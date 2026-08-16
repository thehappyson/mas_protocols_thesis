"""Enrichment agent — A2A server on the shared soc_agent template.

Second agent in the SOC testbed (see deployment/base/agents/enrichment.yaml,
which deploys this as `enrichment-agent` on A2A port 9102).

Role: enrich an alert with context. Looks up IOC reputation via the Threat Intel
tool and asset/user ownership via the CMDB tool (both MCP), then returns a
consolidated enrichment result. No delegation — it is a worker. Promoted from
the earlier canned-ack stub to a full tool-using agent.

Run:
    python services/enrichment-agent/server.py
Endpoints:
    http://127.0.0.1:9102/.well-known/agent-card.json   (Agent Card)
    http://127.0.0.1:9102/                              (A2A JSON-RPC)
"""

from __future__ import annotations

import os
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from soc_agent import (  # noqa: E402
    AgentSkill,
    Workflow,
    WorkflowExecutor,
    build_agent_card,
    build_app,
    listen_config,
    serve,
)

HOST, PORT, PUBLIC_URL = listen_config(default_port=9102)

# Tool zone endpoints, configured not hardcoded.
THREAT_INTEL_MCP_ENDPOINT = os.environ.get(
    "THREAT_INTEL_MCP_ENDPOINT", "http://127.0.0.1:7003/mcp"
)
CMDB_MCP_ENDPOINT = os.environ.get("CMDB_MCP_ENDPOINT", "http://127.0.0.1:7002/mcp")

WORKFLOW = Workflow.load()

SYSTEM_PROMPT = (
    "You are a SOC enrichment agent. Given an alert or set of indicators, gather "
    "context using your tools: look up IOC reputation for IPs, domains, URLs, and "
    "hashes, and look up asset and user ownership and criticality. Use the tools "
    "rather than inventing data. Return a consolidated enrichment result that "
    "summarizes what you found for each indicator and asset."
)


def build_executor() -> WorkflowExecutor:
    return WorkflowExecutor(
        agent_name="enrichment",
        workflow=WORKFLOW,
        agent_label="Enrichment",
        system_prompt=SYSTEM_PROMPT,
        mcp_endpoints=[THREAT_INTEL_MCP_ENDPOINT, CMDB_MCP_ENDPOINT],
    )


def build_card():
    return build_agent_card(
        name="Enrichment",
        description=(
            "Enrichment agent. Given an indicator or asset from a security "
            "alert, returns reputation, ownership, and context that triage "
            "needs to decide severity."
        ),
        public_url=PUBLIC_URL,
        skill=AgentSkill(
            id="enrich_indicator",
            name="Indicator and Asset Enrichment",
            description=(
                "Look up IOC reputation (threat intel) and asset/user ownership "
                "(CMDB) for indicators found in an alert, and return a "
                "consolidated enrichment result."
            ),
            tags=["soc", "enrichment", "ioc", "asset"],
            examples=["Enrich 198.51.100.77 and host 10.14.7.32"],
            input_modes=["text/plain"],
            output_modes=["text/plain"],
        ),
    )


if __name__ == "__main__":
    serve(build_app(build_executor(), build_card()), HOST, PORT)
