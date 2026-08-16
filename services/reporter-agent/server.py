"""Reporter agent — A2A server on the shared soc_agent template.

Fourth agent in the SOC testbed (see deployment/base/agents/reporter.yaml,
which deploys this as `reporter-agent` on A2A port 9105).

Role: summarize an incident and file it. Writes a concise incident summary and
creates a ticket via the Ticketing tool (MCP). No delegation — it is a worker.

Note the port: 9105, per the agent-zone convention (triage 9101, enrichment
9102, correlation 9103, response 9104 [not built yet], reporter 9105).

Run:
    python services/reporter-agent/server.py
Endpoints:
    http://127.0.0.1:9105/.well-known/agent-card.json   (Agent Card)
    http://127.0.0.1:9105/                              (A2A JSON-RPC)
"""

from __future__ import annotations

import os
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from soc_agent import (  # noqa: E402
    AgentSkill,
    LlmToolLoopExecutor,
    build_agent_card,
    build_app,
    listen_config,
    serve,
)

HOST, PORT, PUBLIC_URL = listen_config(default_port=9105)

# Tool zone endpoint, configured not hardcoded.
TICKETING_MCP_ENDPOINT = os.environ.get(
    "TICKETING_MCP_ENDPOINT", "http://127.0.0.1:7005/mcp"
)

SYSTEM_PROMPT = (
    "You are a SOC reporter agent. Given an incident and its triage, enrichment, "
    "and correlation findings, write a concise incident summary and file it as a "
    "ticket using your ticketing tool. Create the incident with a clear title, a "
    "summary description, and a severity. Return the incident id and a short "
    "confirmation of what you filed."
)


def build_executor() -> LlmToolLoopExecutor:
    return LlmToolLoopExecutor(
        agent_label="Reporter",
        system_prompt=SYSTEM_PROMPT,
        mcp_endpoints=[TICKETING_MCP_ENDPOINT],
    )


def build_card():
    return build_agent_card(
        name="Reporter",
        description=(
            "Reporter agent. Summarizes an incident and files it as a ticket for "
            "tracking and handoff."
        ),
        public_url=PUBLIC_URL,
        skill=AgentSkill(
            id="report_incident",
            name="Incident Reporting",
            description=(
                "Write an incident summary and create a ticket capturing the "
                "triage, enrichment, and correlation findings."
            ),
            tags=["soc", "reporting", "ticketing"],
            examples=["File an incident for alert-0001 with a summary"],
            input_modes=["text/plain"],
            output_modes=["text/plain"],
        ),
    )


if __name__ == "__main__":
    serve(build_app(build_executor(), build_card()), HOST, PORT)
