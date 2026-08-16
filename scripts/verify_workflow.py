"""End-to-end verification of the declarative delegation graph.

Sends one escalate alert and one benign alert to Triage (the workflow entry) and
checks the routing that the workflow definition produces:

  escalate -> Triage -> Enrichment -> Correlation -> Response (-> Verification)
              -> unwind -> Triage routes -> Reporter   (genuine depth-4 chain)
  benign   -> Triage -> Reporter                       (short-circuit dismissal)

The chain is read straight out of the transcript Triage returns: every agent
wraps its output in a "===== <Agent> (depth N) =====" section as the result
accumulates down and unwinds back up, so the section list IS the observed path
with depths. Triage's own streamed status updates show its two-step routing.

Usage: verify_workflow.py [escalate|benign|both]   (default both)
"""

import asyncio
import re
import sys
import time

import httpx

from a2a.client import ClientConfig, ClientFactory
from a2a.client.card_resolver import A2ACardResolver
from a2a.types import Message, Part, Role, SendMessageRequest, TaskState

TRIAGE_URL = "http://127.0.0.1:9101"

ALERTS = {
    "escalate": (
        "Alert alert-7788: user jdoe on host 10.14.7.32 clicked a phishing link "
        "that resolved to 198.51.100.77; the host then made a 4.2 GB outbound "
        "transfer to that IP. Investigate and respond."
    ),
    "benign": (
        "Alert alert-7789: the scheduled nightly backup job on host 10.14.7.32 "
        "completed successfully at 02:00. Routine internal activity, no external "
        "connections, no user impact."
    ),
}

SECTION_RE = re.compile(r"=====\s*(\w+) \(depth (\d+)\)\s*=====")


async def run(branch: str):
    prompt = ALERTS[branch]
    async with httpx.AsyncClient(timeout=1200.0) as http:
        card = await A2ACardResolver(httpx_client=http, base_url=TRIAGE_URL).get_agent_card()
        client = ClientFactory(ClientConfig(httpx_client=http, streaming=True)).create(card)
        req = SendMessageRequest(message=Message(
            message_id=f"wf-{branch}-{int(time.time())}", role=Role.ROLE_USER,
            parts=[Part(text=prompt)]))

        print("=" * 80)
        print(f"{branch.upper()} PATH")
        print(f"  alert: {prompt[:72]}...")
        t0 = time.time()
        final = ""
        async for r in client.send_message(req):
            if r.WhichOneof("payload") == "status_update":
                su = r.status_update
                st = TaskState.Name(su.status.state)
                txt = "".join(p.text for p in su.status.message.parts) if su.status.HasField("message") else ""
                if "[workflow]" in txt:
                    print(f"  [{time.time()-t0:6.1f}s] triage stream: {txt}")
                elif txt and st != "TASK_STATE_WORKING":
                    final = txt
        elapsed = time.time() - t0

        sections = SECTION_RE.findall(final)
        chain = " -> ".join(f"{n}(d{d})" for n, d in sections)
        max_depth = max((int(d) for _, d in sections), default=0)
        print(f"  elapsed {elapsed:.1f}s")
        print(f"  observed chain (from returned transcript): {chain}")
        print(f"  max delegation depth: {max_depth}")
        print(f"  final report (tail): ...{final[-260:].strip()}")
        return [n for n, _ in sections], max_depth


async def main() -> int:
    which = sys.argv[1] if len(sys.argv) > 1 else "both"
    branches = ["escalate", "benign"] if which == "both" else [which]
    ok = True
    for b in branches:
        agents, depth = await run(b)
        if b == "escalate":
            expected = ["Triage", "Enrichment", "Correlation", "Response", "Reporter"]
            if agents != expected:
                ok = False; print(f"  FAIL: chain {agents} != {expected}")
            if depth != 4:
                ok = False; print(f"  FAIL: expected depth-4 chain, got depth {depth}")
        else:
            if agents != ["Triage", "Reporter"]:
                ok = False; print(f"  FAIL: benign path should be Triage->Reporter, got {agents}")
            if any(a in agents for a in ("Enrichment", "Correlation", "Response")):
                ok = False; print("  FAIL: benign path ran the chain (should short-circuit)")
    print("=" * 80)
    print("PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
