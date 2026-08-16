"""Verify the four agents on the shared soc_agent template.

For each: fetch its Agent Card, send a task via the a2a-sdk client, and capture
the tool-call sequence from the interim WORKING status updates the loop emits.
Asserts the loop ran and the agent called at least the tools expected for its
role.
"""

import asyncio
import re
import time

import httpx

from a2a.client import ClientConfig, ClientFactory
from a2a.client.card_resolver import A2ACardResolver
from a2a.types import Message, Part, Role, SendMessageRequest, TaskState

# (label, base_url, prompt, [tool names that MUST appear in the call sequence])
AGENTS = [
    (
        "Triage",
        "http://127.0.0.1:9101",
        "Check for new alerts and triage them.",
        ["next_alerts"],
    ),
    (
        "Enrichment",
        "http://127.0.0.1:9102",
        "Enrich these indicators from an alert: destination IP 198.51.100.77, "
        "internal host 10.14.7.32, user jdoe. Look up reputation and ownership.",
        ["lookup_ioc", "lookup_asset"],  # threat-intel AND cmdb -> multi-MCP
    ),
    (
        "Correlation",
        "http://127.0.0.1:9103",
        "Alert alert-0001 is a suspicious 4.2GB outbound transfer from 10.14.7.32 "
        "to 198.51.100.77. Determine whether it is part of a larger pattern.",
        ["next_alerts"],
    ),
    (
        "Reporter",
        "http://127.0.0.1:9105",
        "File an incident for alert-0001: suspicious 4.2GB outbound transfer from "
        "10.14.7.32 to 198.51.100.77. Severity high. Summarize and create a ticket.",
        ["create_incident"],
    ),
]

# Matches the loop's status text: "calling MCP tool: <name>({...})" or
# "delegating over A2A: <name>(...)".
ACTION_RE = re.compile(r"(?:calling MCP tool|delegating over A2A): (\w+)\(")


async def run_agent(label, base_url, prompt, must_call) -> bool:
    async with httpx.AsyncClient(timeout=600.0) as http:
        card = await A2ACardResolver(httpx_client=http, base_url=base_url).get_agent_card()
        print("=" * 74)
        print(f"{label}  ({base_url})")
        print(f"  card.name={card.name!r}  skill={[s.name for s in card.skills]}")

        client = ClientFactory(ClientConfig(httpx_client=http, streaming=True)).create(card)
        request = SendMessageRequest(
            message=Message(
                message_id=f"verify-{label}-{int(time.time())}",
                role=Role.ROLE_USER,
                parts=[Part(text=prompt)],
            )
        )

        states, called, final = [], [], None
        started = time.time()
        async for response in client.send_message(request):
            payload = response.WhichOneof("payload")
            if payload == "task":
                states.append(TaskState.Name(response.task.status.state))
            elif payload == "status_update":
                su = response.status_update
                state = TaskState.Name(su.status.state)
                states.append(state)
                text = "".join(p.text for p in su.status.message.parts) if su.status.HasField("message") else ""
                m = ACTION_RE.search(text)
                if state == "TASK_STATE_WORKING" and m:
                    called.append(m.group(1))
                    print(f"  [{time.time()-started:5.1f}s] tool-call: {text}")
                elif text and state != "TASK_STATE_WORKING":
                    final = text

        print(f"  states: {' -> '.join(states)}")
        print(f"  tools called (in order): {called}")
        print(f"  final answer (head): {(final or '')[:200]}")

        failures = []
        if "TASK_STATE_COMPLETED" not in states:
            failures.append("did not reach TASK_STATE_COMPLETED")
        if not called:
            failures.append("no tool call fired — loop did not use tools")
        for needed in must_call:
            if needed not in called:
                failures.append(f"expected tool {needed!r} was not called")
        for f in failures:
            print(f"  FAIL: {f}")
        return not failures


async def main() -> int:
    results = {}
    for label, url, prompt, must in AGENTS:
        try:
            results[label] = await run_agent(label, url, prompt, must)
        except Exception as exc:
            print(f"  {label} FAILED: {exc!r}")
            results[label] = False
    print("=" * 74)
    print("SUMMARY")
    for label, ok in results.items():
        print(f"  {'PASS' if ok else 'FAIL'}  {label}")
    return 0 if all(results.values()) else 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
