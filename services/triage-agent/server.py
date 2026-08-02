"""Triage agent — bare A2A server.

First agent in the SOC testbed (see deployment/base/agents/triage.yaml, which
deploys this as `triage-agent` on A2A port 9101).

DESIGN PRINCIPLE: the protocol machinery is real, the domain logic grows one
step at a time. A task arrives over A2A, moves through the task state machine,
is classified by an LLM that can call SIEM tools over MCP *and* delegate to the
Enrichment agent over A2A, and the model's final text comes back. All four
integrations meet in TriageAgentExecutor._run_tool_loop.

Endpoints are configured, never hardcoded: INFERENCE_ENDPOINT / INFERENCE_MODEL
point at any OpenAI-compatible server (Ollama in dev, vLLM in the reportable
tiers), SIEM_MCP_ENDPOINT points at the tool zone, and ENRICHMENT_A2A_ENDPOINT
points at the peer agent.

Written against a2a-sdk 1.1.2, where:
  * types are protobuf-generated (a2a.types.a2a_pb2), not pydantic;
  * task states are protobuf enums named TASK_STATE_* ;
  * the server app is composed from route factories rather than a prebuilt
    application class.

Run:
    python services/triage-agent/server.py
Endpoints:
    http://127.0.0.1:9101/.well-known/agent-card.json   (Agent Card)
    http://127.0.0.1:9101/                              (A2A JSON-RPC)
"""

from __future__ import annotations

import json
import os
import uuid
from typing import Any

import httpx
import uvicorn
from mcp import Client as MCPClient
from openai import AsyncOpenAI
from starlette.applications import Starlette

from a2a.client import ClientConfig, create_client

from a2a.server.agent_execution import AgentExecutor, RequestContext
from a2a.server.events import EventQueue
from a2a.server.request_handlers import DefaultRequestHandler
from a2a.server.routes import create_agent_card_routes, create_jsonrpc_routes
from a2a.server.tasks import InMemoryTaskStore, TaskUpdater
from a2a.types import (
    AgentCapabilities,
    AgentCard,
    AgentInterface,
    AgentSkill,
    Message,
    Part,
    Role,
    SendMessageRequest,
    Task,
    TaskState,
    TaskStatus,
)
from a2a.utils.constants import (
    DEFAULT_RPC_URL,
    PROTOCOL_VERSION_CURRENT,
    TransportProtocol,
)

# Matches the container env convention in deployment/base/agents/triage.yaml.
HOST = os.environ.get("A2A_LISTEN_HOST", "127.0.0.1")
PORT = int(os.environ.get("A2A_LISTEN_PORT", "9101"))
PUBLIC_URL = os.environ.get("A2A_PUBLIC_URL", f"http://{HOST}:{PORT}/")

# Inference is configured, never hardcoded: dev runs Ollama on the host, the
# reportable tiers run vLLM as a sidecar. Swapping one for the other is an env
# change, not a code change — the defaults below are dev conveniences only.
INFERENCE_ENDPOINT = os.environ.get("INFERENCE_ENDPOINT", "http://127.0.0.1:11434/v1")
INFERENCE_MODEL = os.environ.get("INFERENCE_MODEL", "qwen3.6:35b-mlx")
# Dummy by design: Ollama ignores it, but the OpenAI client requires a value.
# TODO: read from a Secret when the endpoint is one that actually authenticates.
INFERENCE_API_KEY = os.environ.get("INFERENCE_API_KEY", "not-used-by-ollama")
# A 35B model answering cold can take tens of seconds; keep well clear of that.
INFERENCE_TIMEOUT = float(os.environ.get("INFERENCE_TIMEOUT", "300"))

# Tool zone endpoint, also configured rather than hardcoded: agent -> tool
# calls cross a zone boundary, so this address changes per tier and per
# environment. See deployment/base/tools/siem.yaml.
SIEM_MCP_ENDPOINT = os.environ.get("SIEM_MCP_ENDPOINT", "http://127.0.0.1:7001/mcp")

# Peer agent in the agent zone, reached over A2A. Configured, not hardcoded:
# discovery may later come from the platform-zone service registry instead.
ENRICHMENT_A2A_ENDPOINT = os.environ.get(
    "ENRICHMENT_A2A_ENDPOINT", "http://127.0.0.1:9102"
)

# Guards against a model that keeps requesting tools forever. Counts LLM calls,
# so the loop makes at most this many round trips before giving up.
MAX_TOOL_ITERATIONS = int(os.environ.get("MAX_TOOL_ITERATIONS", "5"))

# Name the LLM uses to reach the Enrichment agent. Delegation is presented as
# just another callable action, so the model makes one uniform choice between
# calling a tool, delegating to a peer, and answering.
DELEGATE_ENRICHMENT_ACTION = "delegate_to_enrichment"

# Minimal on purpose — prompt engineering is a later step.
SYSTEM_PROMPT = (
    "You are a SOC triage agent. Given a security alert, assess it briefly and "
    "state a severity and a recommended next action. You have access to SIEM "
    "tools; use them when you need alert data rather than inventing it. You "
    f"can also call {DELEGATE_ENRICHMENT_ACTION} to hand an indicator or asset "
    "to the Enrichment agent when you need reputation or ownership context."
)


def build_agent_card() -> AgentCard:
    """The public Agent Card served at /.well-known/agent-card.json."""
    return AgentCard(
        name="Triage",
        description=(
            "Front-line SOC triage agent. Receives raw security alerts and "
            "classifies them by severity and disposition for downstream "
            "enrichment and correlation."
        ),
        version="0.1.0",
        # 1.x replaces the flat `url` + `preferred_transport` pair with a
        # repeated supported_interfaces list.
        supported_interfaces=[
            AgentInterface(
                url=PUBLIC_URL,
                protocol_binding=TransportProtocol.JSONRPC.value,
                protocol_version=PROTOCOL_VERSION_CURRENT,
            )
        ],
        capabilities=AgentCapabilities(streaming=True, push_notifications=False),
        default_input_modes=["text/plain"],
        default_output_modes=["text/plain"],
        skills=[
            AgentSkill(
                id="triage_alert",
                name="Alert Triage",
                description=(
                    "Classify an incoming security alert and assign an initial "
                    "severity and recommended next action."
                ),
                tags=["soc", "triage", "alerts"],
                examples=["Triage alert-0001: suspicious outbound data transfer"],
                input_modes=["text/plain"],
                output_modes=["text/plain"],
            )
        ],
    )


class TriageAgentExecutor(AgentExecutor):
    """Executor holding what will eventually be the agent's reasoning loop.

    A multi-turn loop in which the model chooses, each iteration, between
    calling an MCP tool, delegating to the Enrichment agent over A2A, and
    answering. The task is walked through submitted -> working -> completed
    with the model's final text as the result.
    """

    def __init__(self) -> None:
        # One client for the process; it is safe to share across requests and
        # holds the connection pool.
        self._llm = AsyncOpenAI(
            base_url=INFERENCE_ENDPOINT,
            api_key=INFERENCE_API_KEY,
            timeout=INFERENCE_TIMEOUT,
        )

    @staticmethod
    def _to_openai_tool(tool: Any) -> dict[str, Any]:
        """Translate one MCP tool declaration into OpenAI function-calling form.

        The MCP `input_schema` is already JSON Schema, which is exactly what
        the `parameters` field expects, so this is a re-wrapping rather than a
        conversion.
        """
        return {
            "type": "function",
            "function": {
                "name": tool.name,
                "description": tool.description or "",
                "parameters": tool.input_schema,
            },
        }

    @staticmethod
    def _tool_result_to_text(result: Any) -> str:
        """Flatten an MCP CallToolResult into something the LLM can read."""
        if result.structured_content is not None:
            return json.dumps(result.structured_content)
        return "\n".join(c.text for c in result.content if c.type == "text")

    @staticmethod
    def _delegation_action() -> dict[str, Any]:
        """Declare the peer agent to the LLM in the same shape as a tool.

        Delegation deliberately looks like every other callable action, so the
        model picks between "call a tool", "delegate", and "answer" in one
        decision rather than through a separate mechanism.
        """
        return {
            "type": "function",
            "function": {
                "name": DELEGATE_ENRICHMENT_ACTION,
                "description": (
                    "Delegate to the Enrichment agent to get IOC reputation "
                    "and asset ownership context for indicators found in an "
                    "alert. Use for IPs, hosts, domains, or hashes."
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "request": {
                            "type": "string",
                            "description": (
                                "What to enrich, e.g. the indicators and any "
                                "context the Enrichment agent needs."
                            ),
                        }
                    },
                    "required": ["request"],
                },
            },
        }

    async def _delegate_to_enrichment(self, request_text: str) -> str:
        """Send a task to the Enrichment agent over A2A and return its answer.

        Triage is an A2A server and, here, also an A2A client. The peer's card
        is resolved per delegation: correct and stateless, but it costs an
        extra HTTP round trip each time — worth caching once discovery moves to
        the service registry.
        """
        async with httpx.AsyncClient(timeout=INFERENCE_TIMEOUT) as http:
            peer = await create_client(
                ENRICHMENT_A2A_ENDPOINT,
                ClientConfig(httpx_client=http, streaming=True),
            )
            request = SendMessageRequest(
                message=Message(
                    message_id=str(uuid.uuid4()),
                    role=Role.ROLE_USER,
                    parts=[Part(text=request_text)],
                )
            )

            answer = ""
            async for response in peer.send_message(request):
                payload = response.WhichOneof("payload")
                # Take the text attached to the peer's terminal state.
                if payload == "status_update":
                    update = response.status_update
                    if update.status.HasField("message"):
                        text = "".join(p.text for p in update.status.message.parts)
                        if text:
                            answer = text
                elif payload == "message":
                    answer = "".join(p.text for p in response.message.parts)
            return answer or "(Enrichment agent returned no content)"

    async def _run_tool_loop(self, alert_text: str, updater: TaskUpdater) -> str:
        """Observe-think-act loop: LLM <-> SIEM tools until a final answer.

        Reproducibility: temperature=0 is the only sampling parameter set. No
        top_p, seed, or max_tokens — everything else is the server default, so
        that the measured behaviour is the endpoint's, not ours.

        The MCP session is opened per task. That costs a connection setup per
        triage, but keeps the agent stateless with respect to the tool zone and
        lets a restarted tool server be picked up without restarting the agent.
        """
        messages: list[dict[str, Any]] = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": alert_text},
        ]

        async with MCPClient(SIEM_MCP_ENDPOINT) as mcp:
            listed = await mcp.list_tools()
            # MCP tools and the A2A peer are offered to the model as one menu.
            tools = [self._to_openai_tool(t) for t in listed.tools]
            tools.append(self._delegation_action())

            for _ in range(MAX_TOOL_ITERATIONS):
                completion = await self._llm.chat.completions.create(
                    model=INFERENCE_MODEL,
                    messages=messages,
                    tools=tools,
                    temperature=0,
                )
                choice = completion.choices[0].message

                # No tool call means the model is done thinking: this is the answer.
                if not choice.tool_calls:
                    return choice.content or ""

                # Record the assistant's tool request explicitly rather than
                # dumping the SDK object, so the wire format stays predictable.
                messages.append(
                    {
                        "role": "assistant",
                        "content": choice.content or "",
                        "tool_calls": [
                            {
                                "id": tc.id,
                                "type": "function",
                                "function": {
                                    "name": tc.function.name,
                                    "arguments": tc.function.arguments,
                                },
                            }
                            for tc in choice.tool_calls
                        ],
                    }
                )

                for tc in choice.tool_calls:
                    arguments = json.loads(tc.function.arguments or "{}")
                    name = tc.function.name

                    # Route by name: the peer agent goes over A2A, everything
                    # else is an MCP tool in the tool zone. Both results come
                    # back into the conversation the same way, so the loop
                    # structure is identical either way.
                    if name == DELEGATE_ENRICHMENT_ACTION:
                        kind = "delegating over A2A"
                        detail = arguments.get("request", "")
                    else:
                        kind = "calling MCP tool"
                        detail = json.dumps(arguments)

                    # Emit each action as an A2A status update so the loop is
                    # observable over the protocol, not just in local logs.
                    await updater.update_status(
                        TaskState.TASK_STATE_WORKING,
                        message=updater.new_agent_message(
                            [Part(text=f"{kind}: {name}({detail})")]
                        ),
                    )

                    if name == DELEGATE_ENRICHMENT_ACTION:
                        content = await self._delegate_to_enrichment(
                            arguments.get("request", "")
                        )
                    else:
                        result = await mcp.call_tool(name, arguments)
                        content = self._tool_result_to_text(result)

                    messages.append(
                        {
                            "role": "tool",
                            "tool_call_id": tc.id,
                            "content": content,
                        }
                    )

        return (
            f"Triage stopped: reached the {MAX_TOOL_ITERATIONS}-iteration tool "
            "limit without the model producing a final answer."
        )

    async def execute(
        self, context: RequestContext, event_queue: EventQueue
    ) -> None:
        # The framework does NOT create the Task for us: emitting a status
        # update first fails with "Agent should enqueue Task before
        # TaskStatusUpdateEvent event". The executor owns task creation, so
        # enqueue the Task in its initial SUBMITTED state before any update.
        if context.current_task is None:
            await event_queue.enqueue_event(
                Task(
                    id=context.task_id,
                    context_id=context.context_id,
                    status=TaskStatus(state=TaskState.TASK_STATE_SUBMITTED),
                    history=[context.message],
                )
            )

        updater = TaskUpdater(event_queue, context.task_id, context.context_id)
        await updater.start_work()

        user_input = context.get_user_input()

        # The task stays in WORKING for the whole loop; each tool call emits an
        # interim status update from inside _run_tool_loop before the terminal
        # transition below.
        try:
            response_text = await self._run_tool_loop(user_input, updater)
        except Exception as exc:  # surface the cause instead of a bare error state
            await updater.failed(
                message=updater.new_agent_message(
                    [Part(text=f"Triage loop failed: {exc}")]
                )
            )
            return

        await updater.complete(
            message=updater.new_agent_message([Part(text=response_text)])
        )

    async def cancel(
        self, context: RequestContext, event_queue: EventQueue
    ) -> None:
        updater = TaskUpdater(event_queue, context.task_id, context.context_id)
        await updater.cancel()


def build_app() -> Starlette:
    agent_card = build_agent_card()
    request_handler = DefaultRequestHandler(
        agent_executor=TriageAgentExecutor(),
        task_store=InMemoryTaskStore(),
        agent_card=agent_card,
    )
    routes = [
        *create_agent_card_routes(agent_card),
        *create_jsonrpc_routes(request_handler, rpc_url=DEFAULT_RPC_URL),
    ]
    return Starlette(routes=routes)


if __name__ == "__main__":
    uvicorn.run(build_app(), host=HOST, port=PORT)
