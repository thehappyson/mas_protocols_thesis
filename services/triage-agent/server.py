"""Triage agent — A2A server on the shared soc_agent template.

First agent in the SOC testbed (see deployment/base/agents/triage.yaml, which
deploys this as `triage-agent` on A2A port 9101).

Role: front-line triage. Reasons over an alert with the SIEM tool (MCP) and can
delegate to the Enrichment agent (A2A) for reputation/ownership context. All the
loop/lifecycle machinery lives in soc_agent; this file is just Triage's config,
prompt, and card.

Run:
    python services/triage-agent/server.py
Endpoints:
    http://127.0.0.1:9101/.well-known/agent-card.json   (Agent Card)
    http://127.0.0.1:9101/                              (A2A JSON-RPC)
"""

from __future__ import annotations

import os
import pathlib
import sys

# services/<name>/server.py runs as a standalone script, so put services/ on the
# path to import the shared base.
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from soc_agent import (  # noqa: E402
    AgentSkill,
    Delegation,
    LlmToolLoopExecutor,
    build_agent_card,
    build_app,
    listen_config,
    serve,
)

HOST, PORT, PUBLIC_URL = listen_config(default_port=9101)

# Tool zone endpoint, configured not hardcoded: agent -> tool calls cross a zone
# boundary, so this address changes per tier and environment.
SIEM_MCP_ENDPOINT = os.environ.get("SIEM_MCP_ENDPOINT", "http://127.0.0.1:7001/mcp")
# Peer agent in the agent zone, reached over A2A. Discovery may later come from
# the platform-zone service registry instead.
ENRICHMENT_A2A_ENDPOINT = os.environ.get(
    "ENRICHMENT_A2A_ENDPOINT", "http://127.0.0.1:9102"
)

DELEGATE_ENRICHMENT_ACTION = "delegate_to_enrichment"

SYSTEM_PROMPT = (
    "You are a SOC triage agent. Given a security alert, assess it briefly and "
    "state a severity and a recommended next action. You have access to SIEM "
    "tools; use them when you need alert data rather than inventing it. You "
    f"can also call {DELEGATE_ENRICHMENT_ACTION} to hand an indicator or asset "
    "to the Enrichment agent when you need reputation or ownership context."
)


def build_executor() -> LlmToolLoopExecutor:
    return LlmToolLoopExecutor(
        agent_label="Triage",
        system_prompt=SYSTEM_PROMPT,
        mcp_endpoints=[SIEM_MCP_ENDPOINT],
        delegations=[
            Delegation(
                action_name=DELEGATE_ENRICHMENT_ACTION,
                description=(
                    "Delegate to the Enrichment agent to get IOC reputation and "
                    "asset ownership context for indicators found in an alert. "
                    "Use for IPs, hosts, domains, or hashes."
                ),
                endpoint=ENRICHMENT_A2A_ENDPOINT,
            )
        ],
    )


def build_card():
    return build_agent_card(
        name="Triage",
        description=(
            "Front-line SOC triage agent. Receives raw security alerts and "
            "classifies them by severity and disposition for downstream "
            "enrichment and correlation."
        ),
        public_url=PUBLIC_URL,
        skill=AgentSkill(
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
        ),
    )


if __name__ == "__main__":
    serve(build_app(build_executor(), build_card()), HOST, PORT)
