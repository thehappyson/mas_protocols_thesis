"""Verify Response's bidirectional delegation on BOTH branches.

Sends Response two tasks — one whose target verification approves (a
workstation), one it rejects (a domain controller) — and shows the full action
sequence Response emits: propose -> delegate_to_verification -> branch. Asserts
the containment tool fires on approve and does NOT fire on reject.
"""

import asyncio
import re
import time

import httpx

from a2a.client import ClientConfig, ClientFactory
from a2a.client.card_resolver import A2ACardResolver
from a2a.types import Message, Part, Role, SendMessageRequest, TaskState

RESPONSE_URL = "http://127.0.0.1:9104"
ACTION_RE = re.compile(r"(?:calling MCP tool|delegating over A2A): (\w+)\(")

CASES = [
    ("APPROVE-EXPECTED (workstation 10.14.7.32)",
     "Alert alert-0001: host 10.14.7.32 is actively exfiltrating 4.2 GB of data "
     "to an external IP. Decide on a containment action and carry out your "
     "verification-then-contain procedure."),
    ("REJECT-EXPECTED (domain controller 10.0.0.10)",
     "Alert alert-0002: suspicious process activity detected on the host at "
     "10.0.0.10. Decide on a containment action and carry out your "
     "verification-then-contain procedure."),
]


async def run_case(label, prompt) -> tuple[list[str], str]:
    async with httpx.AsyncClient(timeout=600.0) as http:
        card = await A2ACardResolver(httpx_client=http, base_url=RESPONSE_URL).get_agent_card()
        client = ClientFactory(ClientConfig(httpx_client=http, streaming=True)).create(card)
        req = SendMessageRequest(message=Message(
            message_id=f"resp-{int(time.time())}", role=Role.ROLE_USER,
            parts=[Part(text=prompt)]))
        print("=" * 76)
        print(label)
        actions, final = [], ""
        t0 = time.time()
        async for r in client.send_message(req):
            p = r.WhichOneof("payload")
            if p == "status_update":
                su = r.status_update
                state = TaskState.Name(su.status.state)
                text = "".join(x.text for x in su.status.message.parts) if su.status.HasField("message") else ""
                m = ACTION_RE.search(text)
                if state == "TASK_STATE_WORKING" and m:
                    actions.append(m.group(1))
                    print(f"  [{time.time()-t0:5.1f}s] {text}")
                elif text and state != "TASK_STATE_WORKING":
                    final = text
        print(f"  final (head): {final[:220]}")
        return actions, final


async def main() -> int:
    approve_actions, approve_final = await run_case(*CASES[0])
    reject_actions, reject_final = await run_case(*CASES[1])

    print("=" * 76)
    print("ASSERTIONS")
    ok = True

    # Approve branch: verification delegated, THEN containment tool fired.
    a_delegated = "delegate_to_verification" in approve_actions
    a_contained = "contain" in approve_actions
    a_order = (a_delegated and a_contained
               and approve_actions.index("delegate_to_verification") < approve_actions.index("contain"))
    print(f"  approve: delegated={a_delegated} contained={a_contained} verify-before-contain={a_order}")
    if not (a_delegated and a_contained and a_order):
        ok = False
        print("  FAIL: approve branch did not verify-then-contain")

    # Reject branch: verification delegated, containment tool NOT fired.
    r_delegated = "delegate_to_verification" in reject_actions
    r_contained = "contain" in reject_actions
    print(f"  reject:  delegated={r_delegated} contained={r_contained} (must be False)")
    if not r_delegated or r_contained:
        ok = False
        print("  FAIL: reject branch either skipped verification or contained anyway")

    print("=" * 76)
    print("PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
