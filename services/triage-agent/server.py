"""Triage agent — entry of the declarative delegation graph.

First agent in the SOC testbed (deployment/base/agents/triage.yaml, A2A 9101).

Role: classify the alert and emit a severity. It does NOT choose who to delegate
to — the workflow definition (workflows/phishing_triage.yaml) decides, based on
the severity Triage reports against the file's threshold: at/above the threshold
the alert enters the enrichment->correlation->response chain; below it, Triage
short-circuits to Reporter for a dismissal. After the chain unwinds, Triage
routes (no re-reasoning) to Reporter for the final report. All of that routing
is data-driven in the workflow; this file only defines Triage's reasoning.

Run:
    python services/triage-agent/server.py
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

HOST, PORT, PUBLIC_URL = listen_config(default_port=9101)

# Tool zone endpoint, configured not hardcoded.
SIEM_MCP_ENDPOINT = os.environ.get("SIEM_MCP_ENDPOINT", "http://127.0.0.1:7001/mcp")

WORKFLOW = Workflow.load()

SYSTEM_PROMPT = (
    "You are a SOC triage agent. Assess the alert briefly and classify its "
    "severity. You have SIEM tools; use them when you need alert data rather "
    "than inventing it. Do not decide who handles the alert next — that is "
    "routed for you. End your reply with a line exactly of the form "
    "'SEVERITY: <benign|low|medium|high|critical>' reflecting your assessment."
)


def build_executor() -> WorkflowExecutor:
    return WorkflowExecutor(
        agent_name="triage",
        workflow=WORKFLOW,
        agent_label="Triage",
        system_prompt=SYSTEM_PROMPT,
        mcp_endpoints=[SIEM_MCP_ENDPOINT],
    )


def build_card():
    return build_agent_card(
        name="Triage",
        description=(
            "Front-line SOC triage agent and entry point of the workflow. "
            "Classifies an alert's severity; routing to enrichment or dismissal "
            "is decided by the workflow definition."
        ),
        public_url=PUBLIC_URL,
        skill=AgentSkill(
            id="triage_alert",
            name="Alert Triage",
            description=(
                "Classify an incoming security alert and assign a severity that "
                "drives the workflow's escalate/dismiss branch."
            ),
            tags=["soc", "triage", "alerts"],
            examples=["Triage alert-0001: suspicious outbound data transfer"],
            input_modes=["text/plain"],
            output_modes=["text/plain"],
        ),
    )


if __name__ == "__main__":
    serve(build_app(build_executor(), build_card()), HOST, PORT)
