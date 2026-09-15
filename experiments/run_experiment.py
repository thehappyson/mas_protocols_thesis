#!/usr/bin/env python
"""run_experiment.py — the experiment EXECUTOR.

Given a workload spec (N alerts, benign/escalate split, seed), drives it through
the live SOC pipeline and captures EVERYTHING for one run into results/<run_id>/:

    config.json     run parameters, condition label, git sha, time window, endpoints
    results.jsonl   per-alert: prompt, ALL status updates, full final text, path,
                    disposition, latency, message count, error (one JSON per line)
    traces/spans.jsonl   Phoenix spans for the run's time window (if reachable)
    network/…       in-cluster network capture (pluggable backend — see design doc)
    summary.json    aggregates + effectiveness vs ground truth

SEPARATION OF CONCERNS: this executor does NOT apply security treatments or
attacks. Those are toggled OUTSIDE it (kubectl apply of overlays, capability-token
config, the attack injector). Pass --condition to LABEL whatever cluster state you
captured; the executor only records the label. See experiments/EXPERIMENT_DESIGN.md.

Usage:
    kubectl -n agent-zone   port-forward svc/triage-agent 9101:9101 &
    kubectl -n platform-zone port-forward svc/phoenix      6006:6006 &   # for traces
    /opt/miniconda3/envs/masterarbeit/bin/python experiments/run_experiment.py \
        --count 20 --escalate-frac 0.3 --condition baseline
"""

from __future__ import annotations

import argparse
import asyncio
import json
import pathlib
import random
import statistics
import subprocess
import sys
import time
from collections import Counter
from datetime import datetime, timezone

import httpx
from a2a.client import ClientConfig, ClientFactory
from a2a.client.card_resolver import A2ACardResolver
from a2a.types import Message, Part, Role, SendMessageRequest, TaskState

# Reuse the exact prompt + path/disposition logic the ad-hoc driver uses, so runs
# are consistent with scripts/run_workload.py.
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "scripts"))
from run_workload import _classify_path, _prompt_for  # noqa: E402

REPO = pathlib.Path(__file__).resolve().parents[1]


# ---------------------------------------------------------------------------
# 1. Workload sampling — N alerts at a benign/escalate split, deterministic
# ---------------------------------------------------------------------------
def sample_workload(manifest: pathlib.Path, count: int, escalate_frac: float,
                    seed: int) -> list[dict]:
    """Pick `count` alerts from the manifest at the requested escalate fraction.
    Deterministic for a given seed; shuffled so the pipeline sees a mix."""
    alerts = [json.loads(l) for l in manifest.open() if l.strip()]
    esc = [a for a in alerts if a.get("true_class") == "escalate"]
    ben = [a for a in alerts if a.get("true_class") == "benign"]
    rng = random.Random(seed)
    n_esc = min(round(count * escalate_frac), len(esc))
    n_ben = min(count - n_esc, len(ben))
    picked = rng.sample(esc, n_esc) + rng.sample(ben, n_ben)
    rng.shuffle(picked)
    return picked


# ---------------------------------------------------------------------------
# 2. Drive the pipeline — full capture per alert
# ---------------------------------------------------------------------------
async def _drive_one(factory: ClientFactory, card, alert: dict, run_id: str) -> dict:
    """Send one triage task and capture the complete exchange."""
    client = factory.create(card)
    prompt = _prompt_for(alert)
    request = SendMessageRequest(message=Message(
        message_id=f"exp-{run_id}-{alert['alert_id']}-{int(time.time()*1000)}",
        role=Role.ROLE_USER, parts=[Part(text=prompt)]))

    updates: list[dict] = []
    final_text = ""
    started = time.time()
    error = None
    try:
        async for response in client.send_message(request):
            payload = response.WhichOneof("payload")
            if payload == "status_update":
                u = response.status_update
                state = TaskState.Name(u.status.state)
                text = ("".join(p.text for p in u.status.message.parts)
                        if u.status.HasField("message") else "")
                updates.append({"state": state, "text": text,
                                "t": round(time.time() - started, 3)})
                if text and state != "TASK_STATE_WORKING":
                    final_text = text
            elif payload == "message":
                final_text = "".join(p.text for p in response.message.parts)
    except Exception as e:  # noqa: BLE001 — record, never abort the whole run
        error = f"{type(e).__name__}: {e}"

    actions = [u["text"] for u in updates
               if u["state"] == "TASK_STATE_WORKING" and u["text"]]
    path, disposition = _classify_path(actions, final_text)
    return {
        "alert_id": alert["alert_id"],
        "true_class": alert.get("true_class"),
        "attack_type": alert.get("attack_type"),
        "prompt": prompt,
        "updates": updates,                 # every status update, full text
        "final_text": final_text,           # full, not truncated
        "path": path,
        "disposition": disposition,
        "latency_s": round(time.time() - started, 3),
        "n_updates": len(updates),          # coarse interaction proxy (real counts from traces)
        "error": error,
    }


async def drive(alerts: list[dict], endpoint: str, concurrency: int,
                run_id: str) -> list[dict]:
    results: list[dict] = []
    sem = asyncio.Semaphore(concurrency)
    async with httpx.AsyncClient(timeout=900.0) as http:
        card = await A2ACardResolver(httpx_client=http, base_url=endpoint).get_agent_card()
        # The card advertises Triage's container URL; rewrite to the endpoint we
        # actually reached (host->triage hop). Downstream delegations are unaffected.
        for iface in card.supported_interfaces:
            iface.url = endpoint
        factory = ClientFactory(ClientConfig(httpx_client=http, streaming=True))

        async def guarded(alert: dict) -> None:
            async with sem:
                res = await _drive_one(factory, card, alert, run_id)
                results.append(res)
                flag = "!" if res["error"] else " "
                print(f" {flag}{res['alert_id']:<24} truth={res['true_class']:<9} "
                      f"path={res['path']:<12} disp={res['disposition']:<12} "
                      f"{res['latency_s']:6.1f}s", flush=True)

        await asyncio.gather(*(guarded(a) for a in alerts))
    return results


# ---------------------------------------------------------------------------
# 3a. Capture — Phoenix traces for the run window
# ---------------------------------------------------------------------------
TRACE_LIMIT = 100_000   # span cap per run (default client limit is only 1000)


def export_traces(endpoint: str, project: str, start: datetime, end: datetime,
                  out_dir: pathlib.Path) -> dict:
    """Export Phoenix spans for [start, end] to traces/spans.jsonl. Best-effort:
    if the client isn't installed or Phoenix is unreachable, record why and move on.
    Uses the phoenix.client API (arize-phoenix >= 20)."""
    try:
        from phoenix.client import Client
    except ImportError:
        return {"captured": False, "reason": "arize-phoenix not installed "
                "(pip install arize-phoenix in the conda env to capture traces)"}
    try:
        client = Client(base_url=endpoint)
        df = client.spans.get_spans_dataframe(
            project_name=project, start_time=start, end_time=end, limit=TRACE_LIMIT)
        td = out_dir / "traces"
        td.mkdir(parents=True, exist_ok=True)
        path = td / "spans.jsonl"
        df.to_json(path, orient="records", lines=True, date_format="iso")
        return {"captured": True, "n_spans": int(len(df)), "path": str(path)}
    except Exception as e:  # noqa: BLE001
        return {"captured": False, "reason": f"{type(e).__name__}: {e}"}


# ---------------------------------------------------------------------------
# 3b. Capture — in-cluster network activity (pluggable; backend TBD)
# ---------------------------------------------------------------------------
def capture_network(net_cmd: str | None, out_dir: pathlib.Path) -> dict:
    """Run an external network-capture command (e.g. dump Kubeshark/Retina/Calico
    flows) and store its output. No backend is wired yet — without --network-cmd
    this writes a marker. See experiments/EXPERIMENT_DESIGN.md for the tool choice."""
    nd = out_dir / "network"
    nd.mkdir(parents=True, exist_ok=True)
    if not net_cmd:
        (nd / "NOT_CAPTURED.txt").write_text(
            "No --network-cmd given. Choose a backend (Kubeshark / Retina / Calico "
            "denied-packet logging) and pass a command that dumps flows for the run "
            "window. See experiments/EXPERIMENT_DESIGN.md.\n")
        return {"captured": False, "reason": "no --network-cmd"}
    proc = subprocess.run(net_cmd, shell=True, capture_output=True, text=True)
    (nd / "capture.log").write_text(proc.stdout)
    if proc.stderr:
        (nd / "capture.err").write_text(proc.stderr)
    return {"captured": proc.returncode == 0, "cmd": net_cmd, "returncode": proc.returncode}


# ---------------------------------------------------------------------------
# 4. Summarise — aggregates + effectiveness vs ground truth
# ---------------------------------------------------------------------------
_PRED = {"incident": "escalate", "dismissed": "benign", "needs_review": "needs_review"}


def summarize(results: list[dict]) -> dict:
    n = len(results)
    preds = [_PRED.get(r["disposition"], "unknown") for r in results]
    correct = sum(1 for r, p in zip(results, preds) if p == r["true_class"])
    lat = sorted(r["latency_s"] for r in results)
    msgs = [r["n_updates"] for r in results]
    return {
        "count": n,
        "errors": sum(1 for r in results if r["error"]),
        "accuracy_vs_ground_truth": round(correct / n, 3) if n else None,
        "by_true_class": dict(Counter(r["true_class"] for r in results)),
        "by_path": dict(Counter(r["path"] for r in results)),
        "by_disposition": dict(Counter(r["disposition"] for r in results)),
        "latency_s": {
            "mean": round(statistics.mean(lat), 2) if lat else None,
            "median": round(statistics.median(lat), 2) if lat else None,
            "p95": round(lat[int(len(lat) * 0.95)], 2) if lat else None,
            "max": max(lat) if lat else None,
        },
        "messages_per_alert": {
            "mean": round(statistics.mean(msgs), 2) if msgs else None,
            "total": sum(msgs),
        },
    }


# ---------------------------------------------------------------------------
def _git_sha() -> str:
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "--short=12", "HEAD"], text=True, cwd=REPO).strip()
    except Exception:  # noqa: BLE001
        return "unknown"


def main() -> int:
    ap = argparse.ArgumentParser(description="Experiment executor: drive a workload + capture everything")
    ap.add_argument("--count", type=int, default=20, help="total alerts to drive")
    ap.add_argument("--escalate-frac", type=float, default=0.3, help="fraction escalate (rest benign)")
    ap.add_argument("--seed", type=int, default=1337)
    ap.add_argument("--concurrency", type=int, default=2)
    ap.add_argument("--condition", default="unlabeled",
                    help="LABEL for the external cluster state (baseline, +captokens, …)")
    ap.add_argument("--manifest", type=pathlib.Path, default=REPO / "raw_data/staged/wl.jsonl")
    ap.add_argument("--out", type=pathlib.Path, default=REPO / "experiments/results")
    ap.add_argument("--triage-endpoint", default="http://127.0.0.1:9101")
    ap.add_argument("--phoenix-endpoint", default="http://127.0.0.1:6006")
    ap.add_argument("--project", default="soc-testbed", help="Phoenix project name")
    ap.add_argument("--network-cmd", default=None, help="shell command to capture in-cluster network flows")
    ap.add_argument("--no-traces", action="store_true", help="skip Phoenix trace export")
    args = ap.parse_args()

    alerts = sample_workload(args.manifest, args.count, args.escalate_frac, args.seed)
    if not alerts:
        print("no alerts sampled (empty manifest?)", file=sys.stderr)
        return 1

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run_id = f"{args.condition}-{stamp}"
    run_dir = args.out / run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    print(f"run_id={run_id}  driving {len(alerts)} alerts "
          f"(escalate_frac={args.escalate_frac}) via {args.triage_endpoint}\n")

    start = datetime.now(timezone.utc)
    results = asyncio.run(drive(alerts, args.triage_endpoint, args.concurrency, run_id))
    end = datetime.now(timezone.utc)

    # --- persist per-alert results ---
    with (run_dir / "results.jsonl").open("w") as fh:
        for r in results:
            fh.write(json.dumps(r) + "\n")

    # --- captures ---
    traces = {"captured": False, "reason": "skipped (--no-traces)"}
    if not args.no_traces:
        traces = export_traces(args.phoenix_endpoint, args.project, start, end, run_dir)
    network = capture_network(args.network_cmd, run_dir)

    # --- config + summary ---
    config = {
        "run_id": run_id,
        "condition": args.condition,
        "git_sha": _git_sha(),
        "params": {"count": args.count, "escalate_frac": args.escalate_frac,
                   "seed": args.seed, "concurrency": args.concurrency},
        "window": {"start": start.isoformat(), "end": end.isoformat()},
        "endpoints": {"triage": args.triage_endpoint, "phoenix": args.phoenix_endpoint,
                      "project": args.project},
        "manifest": str(args.manifest),
        "captures": {"traces": traces, "network": network},
    }
    (run_dir / "config.json").write_text(json.dumps(config, indent=2))
    summary = summarize(results)
    (run_dir / "summary.json").write_text(json.dumps(summary, indent=2))

    # --- console recap ---
    print("\n" + "=" * 60)
    print(f"run_id: {run_id}   condition: {args.condition}")
    print(f"accuracy vs ground truth: {summary['accuracy_vs_ground_truth']}  "
          f"(errors: {summary['errors']})")
    print(f"paths: {summary['by_path']}")
    print(f"dispositions: {summary['by_disposition']}")
    print(f"latency s: {summary['latency_s']}")
    print(f"traces: {'ok' if traces['captured'] else traces.get('reason')}")
    print(f"network: {'ok' if network['captured'] else network.get('reason')}")
    print(f"results dir: {run_dir}")
    print("=" * 60)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
