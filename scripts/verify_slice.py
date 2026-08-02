#!/usr/bin/env python
"""End-to-end check of the SOC testbed vertical slice.

Exercises the whole chain as it stands: an A2A task goes to the Triage agent,
Triage runs an LLM <-> SIEM tool loop, and a final triage report comes back.

The loop itself is checked, not assumed. Seeing one tool call is NOT enough:
an agent that calls the tool, ignores the result, and answers anyway would look
identical at the protocol level. So this script first reads the alert straight
from the SIEM tool, then requires those SIEM-only facts to appear in the
agent's final answer — which can only happen if the tool result was fed back
into a second LLM call.

Run it with the project conda env:

    /opt/miniconda3/envs/masterarbeit/bin/python scripts/verify_slice.py

Optionally pass your own prompt:

    /opt/miniconda3/envs/masterarbeit/bin/python scripts/verify_slice.py "Any new alerts?"

Endpoints come from the same environment variables the services use, so a test
run always targets whatever the services were configured with:

    TRIAGE_A2A_ENDPOINT       default http://127.0.0.1:9101
    ENRICHMENT_A2A_ENDPOINT   default http://127.0.0.1:9102
    SIEM_MCP_ENDPOINT         default http://127.0.0.1:7001/mcp
    INFERENCE_ENDPOINT        default http://127.0.0.1:11434/v1

Exit code is 0 on success, 1 on failure.
"""

from __future__ import annotations

import asyncio
import os
import socket
import sys
import time
from urllib.parse import urlparse

import httpx

from a2a.client import ClientConfig, ClientFactory
from a2a.client.card_resolver import A2ACardResolver
from a2a.types import Message, Part, Role, SendMessageRequest, TaskState
from mcp import Client as MCPClient

TRIAGE_A2A_ENDPOINT = os.environ.get("TRIAGE_A2A_ENDPOINT", "http://127.0.0.1:9101")
ENRICHMENT_A2A_ENDPOINT = os.environ.get(
    "ENRICHMENT_A2A_ENDPOINT", "http://127.0.0.1:9102"
)
SIEM_MCP_ENDPOINT = os.environ.get("SIEM_MCP_ENDPOINT", "http://127.0.0.1:7001/mcp")
INFERENCE_ENDPOINT = os.environ.get("INFERENCE_ENDPOINT", "http://127.0.0.1:11434/v1")

DEFAULT_PROMPT = (
    "Check new alerts, enrich anything suspicious, and give a triage summary."
)

# Facts that appear ONLY in the Enrichment agent's canned answer — never in the
# SIEM payload or the prompt — so any one of them in the final response proves
# the delegated result travelled back into a later LLM call.
#
# Deliberately a set of short facts rather than one verbatim phrase: the model
# paraphrases freely ("known scanning infrastructure" one run, "linked to
# scanning activity" the next), and matching a single exact sentence made this
# check fail intermittently on a perfectly healthy system.
ENRICHMENT_MARKERS = [
    "scanning",
    "finance",
    "2026-07-29",
    "july 29",
    "criticality",
]

# How to bring each dependency up, shown when one is unreachable.
START_HINTS = {
    "inference": "ollama serve   (then: ollama pull <model>)",
    "siem": "python services/mcp-siem/server.py",
    "triage": "python services/triage-agent/server.py",
    "enrichment": "python services/enrichment-agent/server.py",
}


def _hr(title: str = "") -> None:
    print("=" * 72)
    if title:
        print(title)
        print("=" * 72)


def _port_open(url: str) -> bool:
    parsed = urlparse(url)
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    try:
        with socket.create_connection((parsed.hostname, port), timeout=2):
            return True
    except OSError:
        return False


def preflight() -> bool:
    """Check every dependency is listening before trying real traffic."""
    _hr("PREFLIGHT")
    checks = [
        ("inference", INFERENCE_ENDPOINT),
        ("siem", SIEM_MCP_ENDPOINT),
        ("enrichment", ENRICHMENT_A2A_ENDPOINT),
        ("triage", TRIAGE_A2A_ENDPOINT),
    ]
    ok = True
    for name, url in checks:
        up = _port_open(url)
        print(f"  {'up  ' if up else 'DOWN'}  {name:<10} {url}")
        if not up:
            print(f"          start it with: {START_HINTS[name]}")
            ok = False
    return ok


async def check_siem() -> list[str]:
    """Confirm the SIEM tool works, and grab facts only it could supply.

    The returned markers are the heart of the loop check: they are values that
    appear nowhere in the prompt and can only reach the agent's final answer by
    travelling MCP -> conversation -> a *second* LLM call. Fetching them here
    rather than hardcoding them means the check follows the stub's data.
    """
    _hr("SIEM MCP SERVER")
    async with MCPClient(SIEM_MCP_ENDPOINT) as mcp:
        tools = await mcp.list_tools()
        names = [t.name for t in tools.tools]
        print(f"  tools advertised: {names}")
        if "next_alerts" not in names:
            print("  FAIL: next_alerts is missing")
            return []

        result = await mcp.call_tool("next_alerts", {"since": None, "limit": 10})
        alerts = (result.structured_content or {}).get("result", [])
        if not alerts:
            print("  FAIL: next_alerts returned no alerts to ground the check on")
            return []

        alert = alerts[0]
        markers = [
            str(alert[key])
            for key in ("id", "source_ip", "dest_ip")
            if alert.get(key)
        ]
        print(f"  ground-truth markers from SIEM: {markers}")
        return markers


async def run_triage(prompt: str, markers: list[str]) -> bool:
    """Send a real A2A task and print the task lifecycle as it happens."""
    async with httpx.AsyncClient(timeout=600.0) as http:
        _hr("AGENT CARD")
        card = await A2ACardResolver(
            httpx_client=http, base_url=TRIAGE_A2A_ENDPOINT
        ).get_agent_card()
        print(f"  name:    {card.name}")
        print(f"  version: {card.version}")
        print(f"  skills:  {[s.name for s in card.skills]}")

        client = ClientFactory(
            ClientConfig(httpx_client=http, streaming=True)
        ).create(card)

        _hr("TASK")
        print(f"  prompt: {prompt}\n")

        request = SendMessageRequest(
            message=Message(
                message_id=f"verify-{int(time.time())}",
                role=Role.ROLE_USER,
                parts=[Part(text=prompt)],
            )
        )

        states: list[str] = []
        actions: list[str] = []  # every action the agent announced, in order
        final_text: str | None = None
        started = time.time()

        async for response in client.send_message(request):
            payload = response.WhichOneof("payload")
            if payload == "task":
                state = TaskState.Name(response.task.status.state)
                states.append(state)
                print(f"  [{time.time() - started:5.1f}s] {state}")
            elif payload == "status_update":
                update = response.status_update
                state = TaskState.Name(update.status.state)
                states.append(state)
                text = ""
                if update.status.HasField("message"):
                    text = "".join(p.text for p in update.status.message.parts)
                if state == "TASK_STATE_WORKING" and text:
                    actions.append(text)
                    print(f"  [{time.time() - started:5.1f}s] {state}: {text}")
                else:
                    print(f"  [{time.time() - started:5.1f}s] {state}")
                    if text and state != "TASK_STATE_WORKING":
                        final_text = text

        elapsed = time.time() - started

        _hr("FINAL RESPONSE")
        print(final_text or "(none)")

        _hr("RESULT")
        print(f"  elapsed:     {elapsed:.1f}s")
        print(f"  states:      {' -> '.join(states)}")
        print(f"  actions:     {len(actions)}")

        # Which SIEM-only facts made it into the answer. Anything here proves
        # the tool result re-entered the model's context, which is only
        # possible via a further LLM call — i.e. the loop actually closed.
        grounded = [m for m in markers if m and m in (final_text or "")]
        mcp_actions = [a for a in actions if a.startswith("calling MCP tool")]
        a2a_actions = [a for a in actions if a.startswith("delegating over A2A")]
        lowered = (final_text or "").lower()
        enrichment_hits = [m for m in ENRICHMENT_MARKERS if m in lowered]

        _hr("INTEGRATIONS EXERCISED")
        print(f"  1. A2A server  (task accepted)   : {'yes' if states else 'NO'}")
        print(f"  2. LLM         (loop iterations) : {len(actions) + 1} calls (min)")
        print(f"  3. MCP tool    (SIEM)            : {len(mcp_actions)} call(s)")
        print(f"  4. A2A client  (Enrichment)      : {len(a2a_actions)} delegation(s)")
        print()
        print(f"  SIEM data in final answer       : {grounded or 'NONE'}")
        print(f"  Enrichment data in final answer : {enrichment_hits or 'NONE'}")

        failures = []
        if "TASK_STATE_COMPLETED" not in states:
            failures.append("task did not reach TASK_STATE_COMPLETED")
        if not actions:
            failures.append("no action was taken — the LLM loop did not fire")
        if not final_text:
            failures.append("no final response text returned")
        if "reached the" in (final_text or "") and "iteration tool limit" in (
            final_text or ""
        ):
            failures.append(
                "loop hit the iteration cap instead of producing an answer — "
                "results never came back to the LLM"
            )
            return False
        if not mcp_actions:
            failures.append("the SIEM MCP tool was never called")
        elif not grounded:
            failures.append(
                f"final answer contains none of the SIEM markers {markers} — "
                "the tool result did not feed back into a later LLM call"
            )
        if not a2a_actions:
            failures.append(
                "no delegation to Enrichment — the A2A client hop did not fire"
            )
        elif not enrichment_hits:
            failures.append(
                f"final answer contains none of the Enrichment markers "
                f"{ENRICHMENT_MARKERS} — the delegated result did not feed "
                "back into a later LLM call"
            )

        for failure in failures:
            print(f"  FAIL: {failure}")
        return not failures


async def main() -> int:
    prompt = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_PROMPT

    if not preflight():
        _hr()
        print("PREFLIGHT FAILED — start the services listed above and re-run.")
        return 1

    markers = await check_siem()
    if not markers:
        return 1

    ok = await run_triage(prompt, markers)
    _hr()
    print("PASSED" if ok else "FAILED")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
