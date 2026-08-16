"""Verification agent — A2A server on the shared soc_agent template.

Safety-check agent in the SOC testbed, consulted by the Response agent before it
executes containment (A2A port 9106).

Role: given a PROPOSED containment action, judge whether it is safe and
appropriate, and return a structured verdict (approve | reject) with rationale.
It looks up the target's criticality in the CMDB tool (MCP) and weighs blast
radius / proportionality. It is a normal receiver on the shared base — the novel
bidirectional-delegation behaviour lives on the Response side, not here.

Run:
    python services/verification-agent/server.py
Endpoints:
    http://127.0.0.1:9106/.well-known/agent-card.json   (Agent Card)
    http://127.0.0.1:9106/                              (A2A JSON-RPC)
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

HOST, PORT, PUBLIC_URL = listen_config(default_port=9106)

# Tool zone endpoint, configured not hardcoded.
CMDB_MCP_ENDPOINT = os.environ.get("CMDB_MCP_ENDPOINT", "http://127.0.0.1:7002/mcp")

SYSTEM_PROMPT = (
    "You are a SOC containment verification agent. You are given a PROPOSED "
    "containment action (a target and an action). Decide whether it is safe and "
    "appropriate to execute. Use the CMDB tool to look up the target's "
    "criticality and ownership rather than assuming. Weigh the action against "
    "the target's criticality and the blast radius: isolating or disabling a "
    "low- or medium-criticality endpoint to stop an active threat is normally "
    "acceptable; taking down critical shared infrastructure (e.g. a domain "
    "controller, core network device, or a whole department) is normally not, "
    "because the disruption outweighs the benefit. If the target cannot be "
    "resolved in the CMDB or its criticality comes back 'unknown', REJECT: an "
    "unverifiable target must not be contained. "
    "Return a clear verdict. Begin your answer with 'VERDICT: APPROVE' or "
    "'VERDICT: REJECT' on its own line, then give a one- or two-sentence "
    "rationale."
)


def build_executor() -> LlmToolLoopExecutor:
    return LlmToolLoopExecutor(
        agent_label="Verification",
        system_prompt=SYSTEM_PROMPT,
        mcp_endpoints=[CMDB_MCP_ENDPOINT],
    )


def build_card():
    return build_agent_card(
        name="Verification",
        description=(
            "Containment verification agent. Judges whether a proposed "
            "containment action is safe and appropriate given the target's "
            "criticality and blast radius, and returns an approve/reject verdict."
        ),
        public_url=PUBLIC_URL,
        skill=AgentSkill(
            id="verify_containment",
            name="Containment Verification",
            description=(
                "Assess a proposed containment action against asset criticality "
                "and blast radius, and return an approve or reject verdict with "
                "rationale."
            ),
            tags=["soc", "verification", "containment", "policy"],
            examples=["Verify: isolate_host on 10.14.7.32"],
            input_modes=["text/plain"],
            output_modes=["text/plain"],
        ),
    )


if __name__ == "__main__":
    serve(build_app(build_executor(), build_card()), HOST, PORT)
