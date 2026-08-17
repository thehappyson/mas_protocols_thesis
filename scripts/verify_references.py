"""Reconstruct the delegation chain from A2A task references ALONE.

Runs one escalate-path workflow, then rebuilds the parent->child tree purely
from the protocol: list_tasks(context_id) on each agent, read each task's
`reference_task_ids` (set by the delegating agent), and derive depth by walking
those references to the root. No custom [wf ...] logs or transcript headers are
used for the reconstruction.

Also checks (on the same run) that transcript accumulation is unchanged (the
section headers are still present) and that Reporter emitted a structured JSON
summary.
"""

import asyncio
import json
import re
import time

import httpx

from a2a.client import ClientConfig, ClientFactory, create_client
from a2a.client.card_resolver import A2ACardResolver
from a2a.types import (
    ListTasksRequest,
    Message,
    Part,
    Role,
    SendMessageRequest,
    TaskState,
)

AGENTS = {
    "Triage": "http://127.0.0.1:9101",
    "Enrichment": "http://127.0.0.1:9102",
    "Correlation": "http://127.0.0.1:9103",
    "Response": "http://127.0.0.1:9104",
    "Reporter": "http://127.0.0.1:9105",
    "Verification": "http://127.0.0.1:9106",
}

ESCALATE = (
    "Alert alert-7788: user jdoe on host 10.14.7.32 clicked a phishing link that "
    "resolved to 198.51.100.77; the host then made a 4.2 GB outbound transfer to "
    "that IP. Investigate and respond."
)


async def run_escalate(http):
    card = await A2ACardResolver(httpx_client=http, base_url=AGENTS["Triage"]).get_agent_card()
    client = ClientFactory(ClientConfig(httpx_client=http, streaming=True)).create(card)
    req = SendMessageRequest(message=Message(
        message_id=f"ref-{int(time.time())}", role=Role.ROLE_USER,
        parts=[Part(text=ESCALATE)]))
    root_task, ctx, final = None, None, ""
    t0 = time.time()
    async for r in client.send_message(req):
        p = r.WhichOneof("payload")
        if p == "task":
            root_task, ctx = r.task.id, r.task.context_id
        elif p == "status_update":
            su = r.status_update
            if su.status.HasField("message") and TaskState.Name(su.status.state) != "TASK_STATE_WORKING":
                final = "".join(x.text for x in su.status.message.parts)
    print(f"  workflow finished in {time.time()-t0:.1f}s")
    return root_task, ctx, final


async def collect_tasks(http, ctx):
    """Gather every task in this run's context from every agent, with its parent
    reference read from the task's own message history."""
    tasks = {}
    for name, url in AGENTS.items():
        c = await create_client(url, ClientConfig(httpx_client=http))
        resp = await c.list_tasks(ListTasksRequest(context_id=ctx, history_length=50))
        for t in resp.tasks:
            if t.context_id != ctx:
                continue
            parent = None
            for m in t.history:          # the incoming (delegated) message carries the ref
                if m.reference_task_ids:
                    parent = list(m.reference_task_ids)[0]
                    break
            tasks[t.id] = {"agent": name, "parent": parent}
    return tasks


def depth_of(tid, tasks):
    d, cur, seen = 1, tid, set()
    while tasks.get(cur, {}).get("parent") and cur not in seen:
        seen.add(cur)
        cur = tasks[cur]["parent"]
        d += 1
    return d


async def main() -> int:
    async with httpx.AsyncClient(timeout=1200.0) as http:
        print("Running escalate workflow ...")
        root, ctx, final = await run_escalate(http)
        print(f"  root task {root[:8]}  context {ctx[:8]}")

        print("\n=== RECONSTRUCTED FROM A2A TASK REFERENCES (list_tasks + reference_task_ids) ===")
        tasks = await collect_tasks(http, ctx)
        rows = []
        for tid, info in tasks.items():
            rows.append((depth_of(tid, tasks), info["agent"], tid, info["parent"]))
        rows.sort()
        by_agent = {}
        for depth, agent, tid, parent in rows:
            by_agent[agent] = depth
            parent_agent = tasks.get(parent, {}).get("agent", "—(root)") if parent else "—(root)"
            print(f"  depth {depth}  {agent:12} task={tid[:8]}  parent={ (parent[:8]+' ('+parent_agent+')') if parent else 'none (root)'}")

        # Derive the forward chain by depth 1..4
        chain = [a for _, a in sorted((d, a) for a, d in by_agent.items() if a != "Reporter")]

        print("\n=== CHECKS ===")
        ok = True
        expected_depth = {"Triage": 1, "Enrichment": 2, "Correlation": 3, "Response": 4, "Verification": 5, "Reporter": 2}
        for agent, exp in expected_depth.items():
            got = by_agent.get(agent)
            mark = "OK" if got == exp else "FAIL"
            if got != exp:
                ok = False
            print(f"  [{mark}] {agent:12} depth={got} (expected {exp})")
        max_forward = max(by_agent.get(a, 0) for a in ("Triage", "Enrichment", "Correlation", "Response"))
        print(f"  derived depth-4 forward chain max depth = {max_forward}")

        # Transcript accumulation unchanged: section headers still present.
        headers = re.findall(r"=====\s*(\w+) \(depth (\d+)\)\s*=====", final)
        print(f"  transcript section headers present: {[h[0] for h in headers]}")
        if [h[0] for h in headers] != ["Triage", "Enrichment", "Correlation", "Response", "Reporter"]:
            ok = False; print("  FAIL: transcript accumulation changed")

        # Reporter emitted structured JSON.
        rep = final.split("===== Reporter")[-1]
        m = re.search(r"\{.*\}", rep, re.DOTALL)
        try:
            obj = json.loads(m.group(0))
            print(f"  Reporter JSON keys: {sorted(obj.keys())}")
            print(f"  Reporter JSON: {json.dumps(obj)[:300]}")
            required = {"disposition", "incident_id", "title", "severity", "asset", "indicators", "action_taken", "summary"}
            if not required.issubset(obj.keys()):
                ok = False; print(f"  FAIL: missing keys {required - set(obj.keys())}")
        except Exception as e:
            ok = False; print(f"  FAIL: Reporter output not parseable JSON: {e}")

        print("\n" + ("PASS" if ok else "FAIL"))
        return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
