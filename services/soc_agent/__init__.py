"""Shared base for SOC testbed A2A agents.

Every agent in the testbed has ONE shape — an a2a-sdk server whose executor runs
an observe-think-act loop: the LLM sees a menu of actions (MCP tools, and
optionally A2A delegations to peer agents), calls them until it stops, and the
final text is returned through the A2A task lifecycle. Agents differ only in
role: system prompt, which MCP tool endpoints they connect to, and their Agent
Card. That uniformity is the point (the thesis measures the protocol layer, not
bespoke agent code), so it is enforced here rather than copied per agent.

This module is the template extracted from the Triage agent. Each agent's
server.py is a thin file: config + prompt + card + a call to `build_app`.

Endpoints are configured, never hardcoded: INFERENCE_ENDPOINT / INFERENCE_MODEL
point at any OpenAI-compatible server (Ollama in dev, vLLM in the reportable
tiers); each agent's MCP tool endpoints and any A2A peer endpoints come from its
own env vars.

Written against a2a-sdk 1.1.2 (protobuf-generated types, TASK_STATE_* enums,
route-factory app composition) and MCP Python SDK 2.0.0.

Import convention: agents live at services/<name>/server.py and run as
standalone scripts, so they add services/ to sys.path and `import soc_agent`.
"""

from __future__ import annotations

import contextlib
import json
import os
import pathlib
import time
import uuid
from collections import deque
from dataclasses import dataclass
from typing import Any, Iterable

import httpx
import uvicorn
import yaml
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

# Re-exported so agent files import everything agent-facing from `soc_agent`.
__all__ = [
    "AgentSkill",
    "Delegation",
    "LlmToolLoopExecutor",
    "MAX_TOOL_ITERATIONS",
    "Workflow",
    "WorkflowExecutor",
    "build_agent_card",
    "build_app",
    "listen_config",
    "serve",
]

# ---------------------------------------------------------------------------
# Shared inference + loop config. Read once at import; identical across agents.
# ---------------------------------------------------------------------------
INFERENCE_ENDPOINT = os.environ.get("INFERENCE_ENDPOINT", "http://127.0.0.1:11434/v1")
INFERENCE_MODEL = os.environ.get("INFERENCE_MODEL", "qwen3.6:35b-mlx")
# Dummy by design: Ollama ignores it, but the OpenAI client requires a value.
# TODO: read from a Secret when the endpoint is one that actually authenticates.
INFERENCE_API_KEY = os.environ.get("INFERENCE_API_KEY", "not-used-by-ollama")
# Per-call client timeout. Default is high (900s) on purpose: the deepest chain
# calls receive the largest accumulated prompt AND generate natural (uncapped)
# length output on a slow local reasoning model, so a low timeout would cut off
# legitimate responses and corrupt latency measurements. Config-driven; lower it
# only if the backend is fast (e.g. vLLM on GPU).
INFERENCE_TIMEOUT = float(os.environ.get("INFERENCE_TIMEOUT", "900"))
# Guards against a model that keeps requesting tools forever. Counts LLM calls,
# so the loop makes at most this many round trips before giving up.
MAX_TOOL_ITERATIONS = int(os.environ.get("MAX_TOOL_ITERATIONS", "5"))
# Optional cap on tokens per generation. OFF by default (None => unlimited) so
# reportable runs are not truncated — a cap biases both output content and
# latency measurements. Set it only as a dev convenience to bound a verbose
# reasoning model; never for reportable runs.
_max_tok = os.environ.get("INFERENCE_MAX_TOKENS")
INFERENCE_MAX_TOKENS = int(_max_tok) if _max_tok else None


def listen_config(default_port: int) -> tuple[str, int, str]:
    """Standard A2A listen config for an agent, from env with a per-agent port."""
    host = os.environ.get("A2A_LISTEN_HOST", "127.0.0.1")
    port = int(os.environ.get("A2A_LISTEN_PORT", str(default_port)))
    public_url = os.environ.get("A2A_PUBLIC_URL", f"http://{host}:{port}/")
    return host, port, public_url


@dataclass(frozen=True)
class Delegation:
    """An A2A peer the LLM may hand a sub-task to, offered as a callable action.

    Unused by this batch of agents (they are workers/receivers), but the loop
    supports it so Triage — and the future delegation graph — share one shape.
    """

    action_name: str  # e.g. "delegate_to_enrichment"
    description: str
    endpoint: str


def build_agent_card(
    *, name: str, description: str, public_url: str, skill: AgentSkill
) -> AgentCard:
    """The public Agent Card served at /.well-known/agent-card.json.

    Same shape for every agent; only name/description/skill differ. 1.x uses a
    repeated supported_interfaces list rather than a flat url+transport pair.
    """
    return AgentCard(
        name=name,
        description=description,
        version="0.1.0",
        supported_interfaces=[
            AgentInterface(
                url=public_url,
                protocol_binding=TransportProtocol.JSONRPC.value,
                protocol_version=PROTOCOL_VERSION_CURRENT,
            )
        ],
        capabilities=AgentCapabilities(streaming=True, push_notifications=False),
        default_input_modes=["text/plain"],
        default_output_modes=["text/plain"],
        skills=[skill],
    )


class LlmToolLoopExecutor(AgentExecutor):
    """Generic observe-think-act executor shared by every agent.

    Each iteration the model chooses between calling an MCP tool (from any of the
    configured endpoints), delegating to a peer agent over A2A (if any
    delegations are configured), and answering. The task is walked through
    submitted -> working -> completed with the model's final text as the result.

    Reproducibility: temperature=0 is the only sampling parameter set. No top_p,
    seed, or max_tokens — everything else is the server default, so the measured
    behaviour is the endpoint's, not ours.
    """

    def __init__(
        self,
        *,
        agent_label: str,
        system_prompt: str,
        mcp_endpoints: Iterable[str],
        delegations: Iterable[Delegation] = (),
    ) -> None:
        self._label = agent_label
        self._system_prompt = system_prompt
        self._mcp_endpoints = list(mcp_endpoints)
        self._delegations = {d.action_name: d for d in delegations}
        # One client for the process; safe to share across requests, holds the
        # connection pool.
        self._llm = AsyncOpenAI(
            base_url=INFERENCE_ENDPOINT,
            api_key=INFERENCE_API_KEY,
            timeout=INFERENCE_TIMEOUT,
        )

    # ---- translation helpers -------------------------------------------------

    @staticmethod
    def _to_openai_tool(tool: Any) -> dict[str, Any]:
        """Translate one MCP tool declaration into OpenAI function-calling form.

        The MCP `input_schema` is already JSON Schema, which is exactly what the
        `parameters` field expects, so this is a re-wrapping, not a conversion.
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
    def _delegation_tool(delegation: Delegation) -> dict[str, Any]:
        """Declare a peer agent to the LLM in the same shape as a tool."""
        return {
            "type": "function",
            "function": {
                "name": delegation.action_name,
                "description": delegation.description,
                "parameters": {
                    "type": "object",
                    "properties": {
                        "request": {
                            "type": "string",
                            "description": (
                                "What to ask the peer agent, including any "
                                "context it needs."
                            ),
                        }
                    },
                    "required": ["request"],
                },
            },
        }

    @staticmethod
    def _tool_result_to_text(result: Any) -> str:
        """Flatten an MCP CallToolResult into something the LLM can read."""
        if result.structured_content is not None:
            return json.dumps(result.structured_content)
        return "\n".join(c.text for c in result.content if c.type == "text")

    # ---- gating hooks --------------------------------------------------------
    # Default implementations are inert, so every existing agent is unaffected.
    # They give a subclass a place to make a mid-task delegation result gate a
    # later tool call — the pattern the Response agent needs for verified,
    # correct-by-construction containment. `state` is a per-task dict owned by
    # the loop, so it is safe under concurrent tasks sharing one executor.

    def _on_delegation_result(
        self, state: dict[str, Any], action_name: str, request: str, result: str
    ) -> str:
        """Observe (and optionally transform) a delegation result. Passthrough."""
        return result

    def _guard_tool_call(
        self, state: dict[str, Any], name: str, arguments: dict[str, Any]
    ) -> str | None:
        """Veto an MCP tool call before it runs.

        Return a string to BLOCK the call (the string becomes the tool result
        the model sees, so it can react), or None to allow it. Default allows.
        """
        return None

    async def _delegate(
        self, endpoint: str, request_text: str, updater: TaskUpdater | None = None
    ) -> str:
        """Send a sub-task to a peer agent over A2A and return its answer.

        PROTOCOL-VISIBLE LINEAGE: the delegated message carries
        `reference_task_ids = [parent_task_id]` and the parent's `context_id`.
        The peer creates its sub-task from this message, so the sub-task's
        history records its parent by task id and the whole chain shares one
        context. The delegation depth (RQ2) is then reconstructable from A2A
        task references alone (list_tasks by context_id -> follow
        reference_task_ids), with no custom logs. Parent identity comes from the
        TaskUpdater, which carries this agent's own task_id / context_id.

        The peer's card is resolved per delegation: correct and stateless, but
        it costs an extra HTTP round trip each time — worth caching once
        discovery moves to the service registry.
        """
        message = Message(
            message_id=str(uuid.uuid4()),
            role=Role.ROLE_USER,
            parts=[Part(text=request_text)],
        )
        if updater is not None:
            message.reference_task_ids.append(updater.task_id)
            message.context_id = updater.context_id

        async with httpx.AsyncClient(timeout=INFERENCE_TIMEOUT) as http:
            peer = await create_client(
                endpoint, ClientConfig(httpx_client=http, streaming=True)
            )
            request = SendMessageRequest(message=message)
            answer = ""
            async for response in peer.send_message(request):
                payload = response.WhichOneof("payload")
                if payload == "status_update":
                    update = response.status_update
                    if update.status.HasField("message"):
                        text = "".join(p.text for p in update.status.message.parts)
                        if text:
                            answer = text
                elif payload == "message":
                    answer = "".join(p.text for p in response.message.parts)
            return answer or "(peer agent returned no content)"

    # ---- the loop ------------------------------------------------------------

    async def _run_tool_loop(self, user_text: str, updater: TaskUpdater) -> str:
        """LLM <-> tools/peers until a final answer or the iteration cap.

        MCP sessions are opened per task (one per configured endpoint). That
        costs a connection setup per task but keeps the agent stateless with
        respect to the tool zone and lets a restarted tool server be picked up
        without restarting the agent.
        """
        messages: list[dict[str, Any]] = [
            {"role": "system", "content": self._system_prompt},
            {"role": "user", "content": user_text},
        ]
        # Per-task scratch space for the gating hooks (see _guard_tool_call).
        state: dict[str, Any] = {}

        async with contextlib.AsyncExitStack() as stack:
            # Open every configured MCP endpoint and aggregate their tools into
            # one menu, remembering which client owns each tool name.
            tool_to_client: dict[str, Any] = {}
            tools: list[dict[str, Any]] = []
            for url in self._mcp_endpoints:
                client = await stack.enter_async_context(MCPClient(url))
                listed = await client.list_tools()
                for tool in listed.tools:
                    tool_to_client[tool.name] = client
                    tools.append(self._to_openai_tool(tool))
            for delegation in self._delegations.values():
                tools.append(self._delegation_tool(delegation))

            for _ in range(MAX_TOOL_ITERATIONS):
                completion = await self._llm.chat.completions.create(
                    model=INFERENCE_MODEL,
                    messages=messages,
                    tools=tools,
                    temperature=0,
                    max_tokens=INFERENCE_MAX_TOKENS,
                )
                choice = completion.choices[0].message

                # No tool call means the model is done: this is the answer.
                if not choice.tool_calls:
                    return choice.content or ""

                # Record the assistant's request explicitly rather than dumping
                # the SDK object, so the wire format stays predictable.
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

                    # Route by name: a peer agent goes over A2A, everything else
                    # is an MCP tool. Both results re-enter the conversation the
                    # same way, so the loop structure is identical either way.
                    if name in self._delegations:
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

                    if name in self._delegations:
                        request = arguments.get("request", "")
                        content = await self._delegate(
                            self._delegations[name].endpoint, request, updater
                        )
                        # Let a subclass record the verdict for later gating.
                        content = self._on_delegation_result(
                            state, name, request, content
                        )
                    elif name in tool_to_client:
                        # A subclass may veto the call (e.g. containment without
                        # a matching approval); the veto text becomes the result.
                        veto = self._guard_tool_call(state, name, arguments)
                        if veto is not None:
                            content = veto
                        else:
                            result = await tool_to_client[name].call_tool(
                                name, arguments
                            )
                            content = self._tool_result_to_text(result)
                    else:
                        content = f"error: unknown tool {name!r}"

                    messages.append(
                        {
                            "role": "tool",
                            "tool_call_id": tc.id,
                            "content": content,
                        }
                    )

        return (
            f"{self._label} stopped: reached the {MAX_TOOL_ITERATIONS}-iteration "
            "limit without the model producing a final answer."
        )

    # ---- A2A lifecycle -------------------------------------------------------

    async def _produce_result(self, user_text: str, updater: TaskUpdater) -> str:
        """What this agent returns for a task. Default: just its own LLM loop.

        WorkflowExecutor overrides this to run the loop AND then forward to the
        agent's workflow-defined successor(s), so routing is not baked into the
        loop.
        """
        return await self._run_tool_loop(user_text, updater)

    async def execute(
        self, context: RequestContext, event_queue: EventQueue
    ) -> None:
        # The framework does NOT create the Task for us: emitting a status
        # update first fails with "Agent should enqueue Task before
        # TaskStatusUpdateEvent event". The executor owns task creation.
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

        # The task stays in WORKING for the whole loop; each action emits an
        # interim status update from inside _run_tool_loop.
        try:
            response_text = await self._produce_result(user_input, updater)
        except Exception as exc:  # surface the cause instead of a bare error state
            await updater.failed(
                message=updater.new_agent_message(
                    [Part(text=f"{self._label} loop failed: {exc}")]
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


class Workflow:
    """The declarative delegation graph, loaded from workflows/*.yaml.

    Agents consult this at runtime to resolve their next hop(s); no successor
    identity is baked into agent code. Endpoints resolve from env (config) with
    the file's value as the default, so the graph is editable and the addresses
    are configurable independently.
    """

    def __init__(self, data: dict[str, Any]) -> None:
        self._d = data

    @classmethod
    def load(cls, path: str | None = None) -> "Workflow":
        if path is None:
            path = os.environ.get("WORKFLOW_DEF") or str(
                pathlib.Path(__file__).resolve().parents[2]
                / "workflows"
                / "phishing_triage.yaml"
            )
        with open(path, "r", encoding="utf-8") as fh:
            return cls(yaml.safe_load(fh))

    @property
    def name(self) -> str:
        return self._d["name"]

    @property
    def entry(self) -> str:
        return self._d["entry"]

    @property
    def branch_decider(self) -> str:
        return self._d["branch"]["decider"]

    def node(self, agent: str) -> dict[str, Any]:
        return self._d["agents"][agent]

    def endpoint(self, agent: str) -> str:
        """Resolve an agent's A2A endpoint: env override, else the file default."""
        node = self.node(agent)
        env = node.get("endpoint_env")
        if env and os.environ.get(env):
            return os.environ[env]
        return node["endpoint"]

    def successors(self, agent: str, branch: str) -> list[str]:
        return list(self.node(agent).get("routes", {}).get(branch, []))

    def consult(self, agent: str) -> str | None:
        return self.node(agent).get("consult")

    def depth(self, agent: str) -> int:
        """Nesting depth from the entry (entry = 1), over forward + consult edges."""
        dist = {self.entry: 0}
        queue = deque([self.entry])
        while queue:
            cur = queue.popleft()
            neighbours: set[str] = set()
            for succ_list in self.node(cur).get("routes", {}).values():
                neighbours.update(succ_list)
            consulted = self.consult(cur)
            if consulted:
                neighbours.add(consulted)
            for nxt in neighbours:
                if nxt not in dist:
                    dist[nxt] = dist[cur] + 1
                    queue.append(nxt)
        return dist.get(agent, 0) + 1

    def branch_for_severity(self, severity: str | None) -> str:
        """Map a severity label to 'escalate' or 'benign' via the file threshold."""
        b = self._d["branch"]
        order = [s.lower() for s in b["severity_order"]]
        threshold = order.index(b["escalate_at"].lower())
        if severity is None:
            return "escalate"  # fail toward escalation when the signal is missing
        try:
            rank = order.index(severity.strip().lower())
        except ValueError:
            return "escalate"  # unknown severity -> escalate rather than dismiss
        return "escalate" if rank >= threshold else "benign"


class WorkflowExecutor(LlmToolLoopExecutor):
    """An agent that does its own LLM work, then forwards per the workflow graph.

    The LLM does domain work (reasoning + this agent's tools + any gated
    consult); ROUTING is deterministic and data-driven — the successor comes
    from the Workflow, not the model and not hard-coded edges. This is what makes
    the chain a genuine, reliable depth-N await-and-unwind: each agent blocks on
    `_delegate` to its successor and the result propagates back up.
    """

    def __init__(
        self, *, agent_name: str, workflow: Workflow, **kwargs: Any
    ) -> None:
        super().__init__(**kwargs)
        self._agent_name = agent_name
        self._workflow = workflow

    def _log(self, message: str) -> None:
        ts = f"{time.strftime('%H:%M:%S')}.{int((time.time() % 1) * 1000):03d}"
        print(f"[wf {ts}] {self._agent_name}: {message}", flush=True)

    def _branch(self, own_output: str) -> str:
        """Which route to take. The decider parses its severity marker; the rest
        take the 'default' edge."""
        if self._agent_name != self._workflow.branch_decider:
            return "default"
        severity = None
        for line in own_output.splitlines():
            if line.strip().upper().startswith("SEVERITY:"):
                severity = line.split(":", 1)[1].strip()
                break
        branch = self._workflow.branch_for_severity(severity)
        self._log(f"classified severity={severity!r} -> branch={branch}")
        return branch

    async def _produce_result(self, user_text: str, updater: TaskUpdater) -> str:
        depth = self._workflow.depth(self._agent_name)
        self._log(f"received (depth {depth}); running local work")
        own_output = await self._run_tool_loop(user_text, updater)

        # Accumulate this agent's contribution into the running transcript that
        # flows down the chain (so the successor sees everything upstream).
        transcript = (
            f"{user_text}\n\n===== {self._label} (depth {depth}) =====\n{own_output}"
        )

        branch = self._branch(own_output)
        successors = self._workflow.successors(self._agent_name, branch)
        if not successors:
            self._log(f"terminal on branch '{branch}'; unwinding result up")
            return transcript

        result = transcript
        feed = transcript
        for succ in successors:
            url = self._workflow.endpoint(succ)
            succ_depth = self._workflow.depth(succ)
            await updater.update_status(
                TaskState.TASK_STATE_WORKING,
                message=updater.new_agent_message(
                    [Part(text=(
                        f"[workflow] {self._agent_name}(depth {depth}) "
                        f"delegating to {succ}(depth {succ_depth}); awaiting result"
                    ))]
                ),
            )
            self._log(f"delegating to {succ} (depth {succ_depth}); awaiting")
            result = await self._delegate(url, feed, updater)
            self._log(f"{succ} returned; unwinding")
            feed = result  # the next successor (if any) sees the prior's result
        return result


def build_app(executor: AgentExecutor, agent_card: AgentCard) -> Starlette:
    """Compose the A2A server app: agent-card route + JSON-RPC route."""
    request_handler = DefaultRequestHandler(
        agent_executor=executor,
        task_store=InMemoryTaskStore(),
        agent_card=agent_card,
    )
    routes = [
        *create_agent_card_routes(agent_card),
        *create_jsonrpc_routes(request_handler, rpc_url=DEFAULT_RPC_URL),
    ]
    return Starlette(routes=routes)


def serve(app: Starlette, host: str, port: int) -> None:
    """Run the agent server (blocking)."""
    uvicorn.run(app, host=host, port=port)
