#!/usr/bin/env python
"""sweep.py — concurrency sweep: find the highest --concurrency that is still clean.

Drives a short workload (default 40 alerts) once per concurrency level through
run_experiment.py and tabulates, per level:

  throughput   alerts/min, vLLM generation tokens/s
  GPU load     peak running / waiting requests, peak KV-cache use, preemptions
               (needs --vllm-metrics; port-forward svc/vllm 8000)
  latency      mean per path taken (benign / escalate)
  non-LLM s    mean per path — the control-overhead metric. If it RISES with
               concurrency, something besides the GPU is saturating (CPU throttling
               of the PDP/tools/agents, Postgres) and would contaminate the overhead
  PDP          DENY count and `expired` DENYs (C2: TTL too short under load)

and suggests the highest level with no errors, no preemptions, no `expired`
DENYs and a flat non-LLM time (≤ +25 % vs the lowest level). You decide; the
chosen value is then FIXED for every condition, like the seed.

Each level uses its own seed (seed-base + level) so later levels don't profit
from earlier levels' alert-specific prefix-cache entries.

Usage (forwards via experiments/portforwards.sh C2 in another terminal):
    $PY experiments/sweep.py --condition C2 --levels 8,16,32,64 \\
        --vllm-metrics http://127.0.0.1:8000/metrics \\
        --pod-logs "platform-zone/capability-verifier"
  Unknown flags are passed through to run_experiment.py. Summarise existing
  sweep runs again without driving:  $PY experiments/sweep.py --runs <dir> <dir> …
"""

from __future__ import annotations

import argparse
import json
import pathlib
import subprocess
import sys
import time
from datetime import datetime, timezone

import numpy as np

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import evaluate as ev  # noqa: E402

FLAT = 1.25     # non-LLM s may grow at most +25 % vs the lowest level


def drive_level(cond: str, level: int, a, passthrough: list[str]) -> pathlib.Path | None:
    cmd = [sys.executable, str(HERE / "run_experiment.py"),
           "--condition", f"{cond}-sweep-c{level}", "--count", str(a.count),
           "--escalate-frac", str(a.escalate_frac), "--seed", str(a.seed_base + level),
           "--concurrency", str(level), *passthrough]
    print(f"\n===== concurrency {level} =====\n$ {' '.join(cmd)}", flush=True)
    run_dir = None
    with subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True) as p:
        for line in p.stdout:                                  # type: ignore[union-attr]
            print(line, end="", flush=True)
            if line.startswith("results dir:"):
                run_dir = pathlib.Path(line.split(":", 1)[1].strip())
    if p.returncode != 0:
        print(f"✗ level {level} exited {p.returncode} — stopping the sweep", file=sys.stderr)
        return None
    return run_dir


def level_row(run_dir: pathlib.Path) -> dict:
    run = ev.load_run(run_dir, None)
    cfg = run["config"]
    A = run["alerts"]
    row = {"run_id": cfg["run_id"], "level": cfg["params"]["concurrency"], "n": len(A),
           "errors": sum(1 for x in A if x["error"]), "alerts_per_min": run["alerts_per_min"],
           "vllm": cfg.get("vllm") or {}}
    for path in ("benign", "escalate"):
        S = ev.seg(A, path)
        row[f"lat_{path}"] = float(np.mean([x["latency_s"] for x in S])) if S else None
        nl = [x["nonllm_s"] for x in S if "nonllm_s" in x]
        row[f"nonllm_{path}"] = float(np.mean(nl)) if nl else None
        row[f"n_{path}"] = len(S)
    pdp = ((cfg.get("captures") or {}).get("pod_logs") or {}).get("pdp") or {}
    reasons = pdp.get("deny_reasons") or {}
    row["deny"] = sum(reasons.values()) if pdp else None
    row["expired"] = sum(v for k, v in reasons.items() if "expire" in k) if pdp else None
    return row


def suggest(rows: list[dict]) -> tuple[int | None, list[str]]:
    rows = sorted(rows, key=lambda r: r["level"])
    ref = rows[0]
    notes, ok = [], []
    for r in rows:
        why = []
        if r["errors"]:
            why.append(f"{r['errors']} errors")
        pre = r["vllm"].get("preemptions_delta")
        if pre:
            why.append(f"{pre:.0f} vLLM preemptions (KV cache full)")
        if r["expired"]:
            why.append(f"{r['expired']} `expired` DENYs")
        for p in ("benign", "escalate"):
            if r[f"nonllm_{p}"] and ref[f"nonllm_{p}"] and r[f"nonllm_{p}"] > FLAT * ref[f"nonllm_{p}"]:
                why.append(f"non-LLM s ({p}) {r[f'nonllm_{p}']:.2f} > {FLAT:.2f}× level {ref['level']}")
        if why:
            notes.append(f"c{r['level']}: " + "; ".join(why))
        else:
            ok.append(r["level"])
    # the highest level such that it and every level below it is clean
    best = None
    for r in rows:
        if r["level"] in ok:
            best = r["level"]
        else:
            break
    if not any(r["vllm"] for r in rows):
        notes.append("no vLLM metrics recorded (pass --vllm-metrics) — preemptions unknown")
    if all(r["deny"] is None for r in rows):
        notes.append("no PDP log captured (at C1/C2 pass --pod-logs platform-zone/capability-verifier)")
    return best, notes


def render(rows: list[dict]) -> str:
    rows = sorted(rows, key=lambda r: r["level"])
    f = ev._f
    L = ["# Concurrency sweep\n",
         "| conc. | run | n | err | alerts/min | gen tok/s | max running | max waiting | max KV | preempt. "
         "| latency benign / escalate (s) | non-LLM benign / escalate (s) | PDP DENY (expired) |",
         "|---|---|---|---|---|---|---|---|---|---|---|---|---|"]
    for r in rows:
        v = r["vllm"]
        kv = v.get("max_kv_usage")
        kv_s = "—" if kv is None else f"{kv * 100:.0f} %"
        deny_s = "—" if r["deny"] is None else f"{r['deny']} ({r['expired']})"
        L.append(f"| {r['level']} | `{r['run_id']}` | {r['n']} | {r['errors']} | {f(r['alerts_per_min'], 2)} | "
                 f"{f(v.get('gen_tokens_per_s'), 0)} | {f(v.get('max_running'), 0)} | {f(v.get('max_waiting'), 0)} | "
                 f"{kv_s} | {f(v.get('preemptions_delta'), 0)} | "
                 f"{f(r['lat_benign'])} / {f(r['lat_escalate'])} | "
                 f"{f(r['nonllm_benign'], 2)} / {f(r['nonllm_escalate'], 2)} | {deny_s} |")
    best, notes = suggest(rows)
    L.append("")
    L.append(f"**Suggested concurrency: {best if best is not None else 'none clean — check the notes'}** "
             f"(highest level that, like every level below it, has no errors, no preemptions, no "
             f"`expired` DENYs and non-LLM time ≤ {FLAT:.2f}× the lowest level).\n")
    if notes:
        L.append("Notes:\n")
        L.extend(f"- {n}" for n in notes)
        L.append("")
    L.append("Latency rises with concurrency by design (batching); what must NOT rise is the non-LLM "
             "time — that is the control-overhead metric. Fix the chosen level for every condition.")
    return "\n".join(L) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser(description="Concurrency sweep over run_experiment.py",
                                 epilog="Unknown flags are passed through to run_experiment.py.")
    ap.add_argument("--condition", help="label of the current cluster state (C0/C1/C2)")
    ap.add_argument("--levels", default="8,16,32,64", help="comma list of concurrency levels")
    ap.add_argument("--count", type=int, default=40, help="alerts per level (default 40)")
    ap.add_argument("--escalate-frac", type=float, default=0.5)
    ap.add_argument("--seed-base", type=int, default=9000, help="level L uses seed seed-base+L")
    ap.add_argument("--pause", type=float, default=20.0, help="seconds between levels (queue drains)")
    ap.add_argument("--report", type=pathlib.Path, default=None, help="markdown output path")
    ap.add_argument("--runs", nargs="+", type=pathlib.Path, default=None,
                    help="don't drive: summarise these existing sweep run dirs")
    a, passthrough = ap.parse_known_args()

    if a.runs:
        dirs = a.runs
        cond = "sweep"
    else:
        if not a.condition:
            ap.error("--condition is required when driving")
        cond = a.condition
        levels = [int(x) for x in a.levels.split(",") if x.strip()]
        dirs = []
        for i, lvl in enumerate(levels):
            if i:
                time.sleep(a.pause)
            d = drive_level(cond, lvl, a, passthrough)
            if d is None:
                break
            dirs.append(d)
    if not dirs:
        print("no runs to summarise", file=sys.stderr)
        return 1

    rows = [level_row(d) for d in dirs]
    md = render(rows)
    out = a.report or (HERE / "results" /
                       f"sweep-{cond}-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}.md")
    out.write_text(md)
    (out.with_suffix(".json")).write_text(json.dumps(rows, indent=2, default=str))
    print("\n" + md)
    print(f"wrote {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
