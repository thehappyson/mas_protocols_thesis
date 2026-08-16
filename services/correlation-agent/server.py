"""Correlation agent — A2A server on the shared soc_agent template.

Third agent in the SOC testbed (see deployment/base/agents/correlation.yaml,
which deploys this as `correlation-agent` on A2A port 9103).

Role: given an alert plus its enrichment, decide whether it is part of a larger
pattern. Queries the SIEM tool (MCP) for related alerts/events and reasons about
whether they form a campaign or are isolated. No delegation — it is a worker.

Run:
    python services/correlation-agent/server.py
Endpoints:
    http://127.0.0.1:9103/.well-known/agent-card.json   (Agent Card)
    http://127.0.0.1:9103/                              (A2A JSON-RPC)
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

HOST, PORT, PUBLIC_URL = listen_config(default_port=9103)

# Tool zone endpoint, configured not hardcoded.
SIEM_MCP_ENDPOINT = os.environ.get("SIEM_MCP_ENDPOINT", "http://127.0.0.1:7001/mcp")

SYSTEM_PROMPT = (
    "You are a SOC correlation agent. Given an alert and any enrichment context, "
    "determine whether it is part of a larger pattern or campaign, or is "
    "isolated. Use the SIEM tools to query for related alerts and events rather "
    "than inventing them. Return your assessment of how the alert relates to "
    "other activity, citing the related events you found."
)


def build_executor() -> LlmToolLoopExecutor:
    return LlmToolLoopExecutor(
        agent_label="Correlation",
        system_prompt=SYSTEM_PROMPT,
        mcp_endpoints=[SIEM_MCP_ENDPOINT],
    )


def build_card():
    return build_agent_card(
        name="Correlation",
        description=(
            "Correlation agent. Given an alert and its enrichment, determines "
            "whether it is part of a larger pattern by querying related events."
        ),
        public_url=PUBLIC_URL,
        skill=AgentSkill(
            id="correlate_alert",
            name="Alert Correlation",
            description=(
                "Query related alerts and events and determine whether an alert "
                "is part of a larger pattern or campaign."
            ),
            tags=["soc", "correlation", "pattern"],
            examples=["Correlate alert-0001 against recent activity"],
            input_modes=["text/plain"],
            output_modes=["text/plain"],
        ),
    )


if __name__ == "__main__":
    serve(build_app(build_executor(), build_card()), HOST, PORT)
