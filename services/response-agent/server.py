"""Response agent — A2A server on the shared soc_agent template.

The one structurally-different agent: before it contains, it consults the
Verification agent and branches on the verdict (A2A port 9104).

Role: given an alert and context, decide on a containment action; then, BEFORE
executing it, delegate the proposed action to the Verification agent over A2A
and wait for an approve/reject verdict:
  * approved -> call the Containment tool (MCP) and report the outcome;
  * rejected -> do NOT contain; report the rejection and rationale.

This is blocking, bidirectional, mid-task delegation whose result gates the
agent's next action. It needs NO extension to the shared base: the base's
delegation is already blocking (it awaits the peer's terminal response and feeds
it back into the loop), so the verdict simply returns as a tool result and the
LLM branches on it in the next iteration. The verify-before-contain ordering and
the "reject => no containment" rule are enforced by the system prompt below.

  * A2A client to Verification (9106); MCP client to Containment (7006).

Run:
    python services/response-agent/server.py
Endpoints:
    http://127.0.0.1:9104/.well-known/agent-card.json   (Agent Card)
    http://127.0.0.1:9104/                              (A2A JSON-RPC)
"""

from __future__ import annotations

import os
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from typing import Any  # noqa: E402

from soc_agent import (  # noqa: E402
    AgentSkill,
    Delegation,
    LlmToolLoopExecutor,
    build_agent_card,
    build_app,
    listen_config,
    serve,
)

HOST, PORT, PUBLIC_URL = listen_config(default_port=9104)

# Tool zone endpoint (privileged containment), configured not hardcoded.
CONTAINMENT_MCP_ENDPOINT = os.environ.get(
    "CONTAINMENT_MCP_ENDPOINT", "http://127.0.0.1:7006/mcp"
)
# Peer agent consulted before containment, reached over A2A.
VERIFICATION_A2A_ENDPOINT = os.environ.get(
    "VERIFICATION_A2A_ENDPOINT", "http://127.0.0.1:9106"
)

DELEGATE_VERIFICATION_ACTION = "delegate_to_verification"

# The prompt carries the bidirectional protocol. It must enforce (a) verify
# before contain, (b) one step at a time so the verdict is in hand before
# containing, and (c) reject => never contain.
SYSTEM_PROMPT = (
    "You are a SOC response agent. Given an alert and its context, decide on a "
    "single containment action (a target and an action such as isolate_host, "
    "block_ip, disable_account, or quarantine_file). "
    "You MUST follow this procedure and take only ONE action per step:\n"
    f"1. First, call {DELEGATE_VERIFICATION_ACTION} with the proposed target and "
    "action, and WAIT for its verdict. Do not call any other tool in this step.\n"
    "2. Read the verdict. It starts with 'VERDICT: APPROVE' or 'VERDICT: REJECT'.\n"
    "3. If and only if the verdict is APPROVE, call the containment tool to "
    "execute the action, then report the outcome including the audit id.\n"
    "4. If the verdict is REJECT, do NOT call the containment tool at all. "
    "Report that containment was declined and give the rejection rationale.\n"
    "Never execute containment without an APPROVE verdict in hand."
)


CONTAINMENT_TOOL = "contain"


class VerifiedContainmentExecutor(LlmToolLoopExecutor):
    """Response's executor: the LLM branches on the verdict as its primary logic,
    and a structural guard makes the privileged step correct-by-construction.

    The demo showed prompt-only branching is not enough for a privileged action:
    the model occasionally fabricates the target or could contain despite a
    reject. So containment is refused unless THIS task has already received an
    APPROVE verdict whose request names the same target. The LLM still drives
    the flow; the guard only removes the unsafe outcomes.

    Uses the base's gating hooks (`_on_delegation_result`, `_guard_tool_call`)
    with per-task `state` — no duplication of the loop.
    """

    def _on_delegation_result(
        self, state: dict[str, Any], action_name: str, request: str, result: str
    ) -> str:
        if action_name == DELEGATE_VERIFICATION_ACTION:
            approved = state.setdefault("approved_requests", [])
            if "VERDICT: APPROVE" in result.upper():
                approved.append(request)
        return result

    def _guard_tool_call(
        self, state: dict[str, Any], name: str, arguments: dict[str, Any]
    ) -> str | None:
        if name == CONTAINMENT_TOOL:
            target = str(arguments.get("target", "")).strip()
            approved = state.get("approved_requests", [])
            if not target or not any(target in req for req in approved):
                return (
                    f"BLOCKED by Response safety guard: containment of {target!r} "
                    "was refused because no APPROVE verdict naming this exact "
                    "target has been received from the Verification agent in this "
                    "task. Verify this target first, or decline containment."
                )
        return None


def build_executor() -> LlmToolLoopExecutor:
    return VerifiedContainmentExecutor(
        agent_label="Response",
        system_prompt=SYSTEM_PROMPT,
        mcp_endpoints=[CONTAINMENT_MCP_ENDPOINT],
        delegations=[
            Delegation(
                action_name=DELEGATE_VERIFICATION_ACTION,
                description=(
                    "Ask the Verification agent whether a proposed containment "
                    "action is safe to execute. Provide the target and the "
                    "action. Returns a verdict of APPROVE or REJECT with a "
                    "rationale. Always call this before containing."
                ),
                endpoint=VERIFICATION_A2A_ENDPOINT,
            )
        ],
    )


def build_card():
    return build_agent_card(
        name="Response",
        description=(
            "Response agent. Decides on a containment action and, after "
            "verification approves it, executes containment; declines if "
            "verification rejects."
        ),
        public_url=PUBLIC_URL,
        skill=AgentSkill(
            id="respond_containment",
            name="Verified Containment",
            description=(
                "Propose a containment action, verify it with the Verification "
                "agent, and execute it only if approved."
            ),
            tags=["soc", "response", "containment"],
            examples=["Contain host 10.14.7.32 which is exfiltrating data"],
            input_modes=["text/plain"],
            output_modes=["text/plain"],
        ),
    )


if __name__ == "__main__":
    serve(build_app(build_executor(), build_card()), HOST, PORT)
