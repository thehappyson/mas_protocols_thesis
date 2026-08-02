"""Enrichment agent — bare A2A server, delegation receiver.

Second agent in the SOC testbed (see deployment/base/agents/enrichment.yaml,
which deploys this as `enrichment-agent` on A2A port 9102).

DESIGN PRINCIPLE: the protocol machinery is real, the domain logic is stubbed.
This agent exists to prove the A2A delegation hop: Triage picks it as an action
inside its reasoning loop, sends a task, and gets a usable answer back. There
is no LLM and no MCP client inside Enrichment — see EnrichmentAgentExecutor.

Written against a2a-sdk 1.1.2; mirrors the structure of the Triage server.

Run:
    python services/enrichment-agent/server.py
Endpoints:
    http://127.0.0.1:9102/.well-known/agent-card.json   (Agent Card)
    http://127.0.0.1:9102/                              (A2A JSON-RPC)
"""

from __future__ import annotations

import os

import uvicorn
from starlette.applications import Starlette

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
    Part,
    Task,
    TaskState,
    TaskStatus,
)
from a2a.utils.constants import (
    DEFAULT_RPC_URL,
    PROTOCOL_VERSION_CURRENT,
    TransportProtocol,
)

# Matches the container env convention in deployment/base/agents/enrichment.yaml.
HOST = os.environ.get("A2A_LISTEN_HOST", "127.0.0.1")
PORT = int(os.environ.get("A2A_LISTEN_PORT", "9102"))
PUBLIC_URL = os.environ.get("A2A_PUBLIC_URL", f"http://{HOST}:{PORT}/")


def build_agent_card() -> AgentCard:
    """The public Agent Card served at /.well-known/agent-card.json."""
    return AgentCard(
        name="Enrichment",
        description=(
            "Enrichment agent. Given an indicator or asset from a security "
            "alert, returns reputation, ownership, and context that triage "
            "needs to decide severity."
        ),
        version="0.1.0",
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
                id="enrich_indicator",
                name="Indicator and Asset Enrichment",
                description=(
                    "Look up IOC reputation and asset ownership for indicators "
                    "found in an alert."
                ),
                tags=["soc", "enrichment", "ioc", "asset"],
                examples=["Enrich 198.51.100.77 and host 10.14.7.32"],
                input_modes=["text/plain"],
                output_modes=["text/plain"],
            )
        ],
    )


class EnrichmentAgentExecutor(AgentExecutor):
    """Canned delegation receiver.

    STUB: no LLM, no threat-intel lookup, no CMDB query. It echoes what it was
    asked about and returns a fixed enrichment verdict, which is enough for the
    delegating agent to continue reasoning. Later steps replace the body of
    `execute` while leaving this state-machine scaffolding intact.
    """

    async def execute(
        self, context: RequestContext, event_queue: EventQueue
    ) -> None:
        # The framework does not create the Task; the executor owns that.
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

        # STUB: the entire enrichment result.
        response_text = (
            f"Enrichment for {user_input}: IOC reputation = suspicious "
            "(known scanning infrastructure, first seen 2026-07-29); "
            "asset owner = finance-workstations; criticality = medium "
            "[stubbed]"
        )

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
        agent_executor=EnrichmentAgentExecutor(),
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
