#!/usr/bin/env python
"""Drive a generated workload through the live SOC pipeline (end-to-end check).

The Workload Generator (services/workload-generator/generator.py) is out-of-band:
it only writes alerts + ground truth to the DB. This harness is the other half —
it takes the generator's manifest (the JSONL it prints for each inserted alert)
and, for each alert, sends the Triage agent a real A2A task describing THAT alert
by its content (no ground-truth label). It records which path the pipeline took
(escalate chain vs benign short-circuit vs needs-review) and the final
disposition, then joins those outcomes back to the manifest's true class.

This demonstrates the methodological point: the branch each alert takes is driven
by the alert's real content (and the seed-linked lookups the agents perform), NOT
by any visible label — the label lives only in the operator's manifest / the
agent-invisible ground-truth table.

Usage (run the generator first, capturing its stdout manifest):
    docker compose run --rm -T workload-generator run --count 20 > /tmp/wl.jsonl
    /opt/miniconda3/envs/masterarbeit/bin/python scripts/run_workload.py \
        --manifest /tmp/wl.jsonl --concurrency 3

Endpoints come from the same env the services use (default localhost mappings):
    TRIAGE_A2A_ENDPOINT   default http://127.0.0.1:9101
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
import time

import httpx

from a2a.client import ClientConfig, ClientFactory
from a2a.client.card_resolver import A2ACardResolver
from a2a.types import Message, Part, Role, SendMessageRequest, TaskState

TRIAGE_A2A_ENDPOINT = os.environ.get("TRIAGE_A2A_ENDPOINT", "http://127.0.0.1:9101")


def _prompt_for(alert: dict) -> str:
    """A content-only triage prompt for one alert. No class label appears."""
    return (
        "A new SIEM alert has arrived. Triage it and classify its severity.\n\n"
        f"Alert {alert['alert_id']}\n"
        f"  source:      {alert['source_ip']} ({alert.get('source_host','')})\n"
        f"  destination: {alert['dest_ip']}\n"
        f"  rule:        {alert['rule_name']}\n"
        f"  detail:      {alert['description']}\n\n"
        "Use your SIEM tools if you need to confirm details. Classify this "
        "alert's severity."
    )


def _classify_path(actions: list[str], final_text: str) -> tuple[str, str]:
    """Infer (path, disposition) from the A2A status updates + final text.

    Path signal is the workflow's own status update emitted by Triage:
      '... delegating to enrichment ...'  -> escalate chain
      '... delegating to reporter ...'    -> benign short-circuit
    Disposition is parsed from the terminal JSON (reporter or needs-review).
    """
    joined = " ".join(actions).lower()
    path = "unknown"
    if "delegating to enrichment" in joined:
        path = "escalate"
    elif "delegating to reporter" in joined:
        path = "benign"

    # The terminal JSON (reporter's disposition object, or the needs-review
    # record) may be wrapped in prose by a small model, so scan for the first
    # parseable {...} rather than requiring the whole text to be JSON.
    disposition = "?"
    obj = _first_json_object(final_text or "")
    if obj is not None and "disposition" in obj:
        disposition = str(obj.get("disposition", "?"))
    if disposition == "needs_review":
        path = "needs_review"
    elif disposition == "?" and "needs_review" in (final_text or "").lower():
        path, disposition = "needs_review", "needs_review"
    return path, disposition


def _first_json_object(text: str) -> dict | None:
    """Return the first JSON object embedded in `text`, or None."""
    decoder = json.JSONDecoder()
    idx = text.find("{")
    while idx != -1:
        try:
            obj, _ = decoder.raw_decode(text[idx:])
            if isinstance(obj, dict):
                return obj
        except ValueError:
            pass
        idx = text.find("{", idx + 1)
    return None


async def _drive_one(client_factory: ClientFactory, http: httpx.AsyncClient,
                     card, alert: dict) -> dict:
    """Send one triage task and collect path + disposition."""
    client = client_factory.create(card)
    request = SendMessageRequest(
        message=Message(
            message_id=f"wl-{alert['alert_id']}-{int(time.time()*1000)}",
            role=Role.ROLE_USER,
            parts=[Part(text=_prompt_for(alert))],
        )
    )
    actions: list[str] = []
    final_text = ""
    started = time.time()
    async for response in client.send_message(request):
        payload = response.WhichOneof("payload")
        if payload == "status_update":
            update = response.status_update
            state = TaskState.Name(update.status.state)
            text = ""
            if update.status.HasField("message"):
                text = "".join(p.text for p in update.status.message.parts)
            if state == "TASK_STATE_WORKING" and text:
                actions.append(text)
            elif text and state != "TASK_STATE_WORKING":
                final_text = text
        elif payload == "message":
            final_text = "".join(p.text for p in response.message.parts)
    path, disposition = _classify_path(actions, final_text)
    return {
        "alert_id": alert["alert_id"],
        "true_class": alert["true_class"],
        "path": path,
        "disposition": disposition,
        "elapsed": time.time() - started,
    }


async def main() -> int:
    ap = argparse.ArgumentParser(description="Drive a workload through the pipeline")
    ap.add_argument("--manifest", help="JSONL manifest path (default: stdin)")
    ap.add_argument("--limit", type=int, help="only drive the first N alerts")
    ap.add_argument("--concurrency", type=int, default=3)
    args = ap.parse_args()

    src = open(args.manifest) if args.manifest else sys.stdin
    alerts = [json.loads(line) for line in src if line.strip()]
    if args.manifest:
        src.close()
    if args.limit:
        alerts = alerts[: args.limit]
    if not alerts:
        print("no alerts in manifest", file=sys.stderr)
        return 1

    print(f"driving {len(alerts)} alert(s) through {TRIAGE_A2A_ENDPOINT} "
          f"(concurrency={args.concurrency})\n")

    results: list[dict] = []
    sem = asyncio.Semaphore(args.concurrency)
    async with httpx.AsyncClient(timeout=900.0) as http:
        card = await A2ACardResolver(
            httpx_client=http, base_url=TRIAGE_A2A_ENDPOINT
        ).get_agent_card()
        # The card advertises Triage's CONTAINER url (A2A_PUBLIC_URL, e.g.
        # http://triage-agent:9101/), which the host cannot resolve. Rewrite the
        # interface(s) to the endpoint we actually reached so the host->triage
        # hop uses the mapped port; every downstream delegation stays
        # container-internal and is unaffected. (On-network this is a no-op.)
        for iface in card.supported_interfaces:
            iface.url = TRIAGE_A2A_ENDPOINT
        factory = ClientFactory(ClientConfig(httpx_client=http, streaming=True))

        async def guarded(alert: dict) -> None:
            async with sem:
                res = await _drive_one(factory, http, card, alert)
                results.append(res)
                print(f"  {res['alert_id']:<24} truth={res['true_class']:<16} "
                      f"path={res['path']:<12} disposition={res['disposition']:<12} "
                      f"{res['elapsed']:5.1f}s", flush=True)

        await asyncio.gather(*(guarded(a) for a in alerts))

    # ---- summary -----------------------------------------------------------
    results.sort(key=lambda r: r["alert_id"])
    by_path: dict[str, int] = {}
    for r in results:
        by_path[r["path"]] = by_path.get(r["path"], 0) + 1

    print("\n" + "=" * 72)
    print("PATHS TAKEN (driven by real content, not by any visible label):")
    for path, n in sorted(by_path.items()):
        print(f"  {path:<14} {n}")

    escalate_paths = by_path.get("escalate", 0)
    benign_paths = by_path.get("benign", 0)
    both = escalate_paths > 0 and benign_paths > 0
    print("\n  both paths occurred:", "YES" if both else "NO")
    print("=" * 72)
    return 0 if both else 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
