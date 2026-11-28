#!/usr/bin/env python
"""evaluate.py — multi-condition evaluation of executor + injector runs.

Successor-in-waiting to compare.py (kept separate for traceability). Where
compare.py renders one pairwise table from pre-aggregated summary.json, this
script works from the PER-ALERT records and adds:

  * any number of conditions side by side (C0 · C1 · C2 …), several runs per
    condition pooled (e.g. repeated seeds);
  * a split by the PATH ACTUALLY TAKEN (benign short-circuit vs escalate chain):
    the two have very different latencies (~20-35 s vs ~125-185 s at C0), and the
    capability PDP hops live on the delegation chain, so a pooled mean dilutes the
    control's overhead;
  * per-alert work from the traces (one trace per alert, matched via the alert id
    in the prompt): tokens, LLM calls, LLM time, and NON-LLM time
    (= latency − LLM time: tools, A2A hops and, at C1/C2, the PDP round-trips);
  * 95 % bootstrap confidence intervals, and a PAIRED, path-matched overhead
    estimate: the same seed drives the same alerts in every condition, so each
    alert is compared with itself, taking only alerts that took the same path in
    both conditions (isolates the control's cost from changed LLM decisions);
  * correctness with Wilson intervals, per-class recall, and the number of alerts
    whose verdict flipped vs the baseline;
  * the security matrix (scenario × condition) from injector dirs.

Inputs per run dir (results/<run_id>/): config.json, results.jsonl,
traces/spans.jsonl (optional — work metrics are "n/a" without it).

Usage:
  python experiments/evaluate.py \\
      experiments/results/C0-<ts> experiments/results/C1-<ts> experiments/results/C2-<ts> \\
      --inj C0=experiments/results/injector-<ts0>/injector \\
      --inj C1=experiments/results/injector-<ts1>/injector \\
      --inj C2=experiments/results/injector-<ts2>/injector \\
      --out experiments/results/evaluation.md --json experiments/results/evaluation.json

  A run's condition label comes from its config.json; override with LABEL=path.
  Several dirs with the same label are pooled. --baseline picks the reference for
  deltas (default: first condition in --order, which defaults to sorted labels).
"""

from __future__ import annotations

import argparse
import collections
import datetime as dt
import json
import math
import pathlib
import re

import numpy as np
from scipy import stats as sps

PRED = {"incident": "escalate", "dismissed": "benign", "needs_review": "needs_review"}
BLOCKED = {"token_rejected", "blocked_network", "pin_mismatch",
           "llm_refused", "llm_complied_but_denied"}
SEGMENTS = ("all", "benign", "escalate")        # "all" also holds needs_review/unknown paths
WORK = ("tokens", "llm_calls", "llm_s", "nonllm_s")


# =============================================================================
# loading
# =============================================================================
def _split_label(arg: str) -> tuple[str | None, pathlib.Path]:
    if "=" in arg and not pathlib.Path(arg).exists():
        label, p = arg.split("=", 1)
        return label, pathlib.Path(p)
    return None, pathlib.Path(arg)


def _ts(s: str) -> float:
    return dt.datetime.fromisoformat(s.replace("Z", "+00:00")).timestamp()


def _num(v) -> float:
    return float(v) if isinstance(v, (int, float)) and not (isinstance(v, float) and math.isnan(v)) else 0.0


_ALERT_RE = re.compile(r"\bAlert\s+([A-Za-z0-9_.:-]+)")
_TOKEN_RE = re.compile(r"[A-Za-z0-9_.:-]+")


def span_work(run_dir: pathlib.Path, alert_ids: list[str]) -> tuple[dict, dict]:
    """{alert_id: {tokens, prompt, completion, llm_calls, llm_s}} from the run's
    spans, one trace per alert. A trace is assigned to the alert whose id appears in
    its LLM input (the triage prompt carries `Alert <id>`). Returns (work, stats)."""
    p = run_dir / "traces" / "spans.jsonl"
    if not p.exists():
        return {}, {"spans": False}
    by_trace: dict[str, list[dict]] = collections.defaultdict(list)
    for line in p.open():
        line = line.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        tid = row.get("context.trace_id")
        if tid:
            by_trace[tid].append(row)

    # Match tokens, then look them up in a set — a 1000-way regex alternation over
    # ~26k spans of multi-KB prompts is orders of magnitude slower. The triage
    # prompt says `Alert <id>`; that form is preferred, because tool output (e.g.
    # related_alerts) can mention OTHER alert ids of the same run.
    ids = set(alert_ids)

    def _ids_in(txt: str) -> list[str]:
        found = [m.rstrip(".,:;") for m in _ALERT_RE.findall(txt)]
        found = [m for m in found if m in ids]
        return found or [t for t in (m.rstrip(".,:;") for m in _TOKEN_RE.findall(txt)) if t in ids]

    work: dict[str, dict] = {}
    unmapped = ambiguous = 0
    for spans in by_trace.values():
        hits = collections.Counter()
        for s in spans:
            for k in ("attributes.input.value", "attributes.llm.input_messages"):
                v = s.get(k)
                if v is not None and ids:
                    hits.update(_ids_in(str(v)))
        if not hits:
            unmapped += 1          # e.g. Attack.* spans or a trace from outside the run
            continue
        if len(hits) > 1:
            ambiguous += 1
        aid = hits.most_common(1)[0][0]
        w = work.setdefault(aid, {"tokens": 0.0, "prompt": 0.0, "completion": 0.0,
                                  "llm_calls": 0, "llm_s": 0.0})
        for s in spans:
            if s.get("span_kind") != "LLM" and s.get("attributes.openinference.span.kind") != "LLM":
                continue
            w["llm_calls"] += 1
            pr, co = _num(s.get("attributes.llm.token_count.prompt")), _num(s.get("attributes.llm.token_count.completion"))
            w["tokens"] += _num(s.get("attributes.llm.token_count.total")) or (pr + co)
            w["prompt"] += pr
            w["completion"] += co
            try:
                w["llm_s"] += max(0.0, _ts(s["end_time"]) - _ts(s["start_time"]))
            except (KeyError, TypeError, ValueError):
                pass
    return work, {"spans": True, "traces": len(by_trace), "mapped_alerts": len(work),
                  "unmapped_traces": unmapped, "ambiguous_traces": ambiguous}


def load_run(run_dir: pathlib.Path, label: str | None) -> dict:
    cfg = json.loads((run_dir / "config.json").read_text())
    recs = [json.loads(l) for l in (run_dir / "results.jsonl").open() if l.strip()]
    work, wstats = span_work(run_dir, [r["alert_id"] for r in recs])
    cond = label or cfg.get("condition", run_dir.name)
    alerts = []
    for r in recs:
        pred = PRED.get(r.get("disposition"), "unknown")
        w = work.get(r["alert_id"])
        a = {"alert_id": r["alert_id"], "cond": cond, "run_id": cfg.get("run_id", run_dir.name),
             "true_class": r.get("true_class"), "pred": pred,
             "correct": pred == r.get("true_class"), "path": r.get("path", "unknown"),
             "latency_s": float(r["latency_s"]), "msgs": r.get("n_updates", 0),
             "error": r.get("error"), "retries": r.get("retries", 0)}
        if w:
            a.update(tokens=w["tokens"], llm_calls=w["llm_calls"], llm_s=w["llm_s"],
                     nonllm_s=max(0.0, a["latency_s"] - w["llm_s"]))
        alerts.append(a)
    # wall-clock the alerts were driven in: sum of segments (resumed runs), else window
    segs = [s for s in cfg.get("segments", []) if s.get("start") and s.get("end")]
    if segs:
        duration = sum(_ts(s["end"]) - _ts(s["start"]) for s in segs)
    else:
        w = cfg.get("window", {})
        duration = (_ts(w["end"]) - _ts(w["start"])) if w.get("start") and w.get("end") else None
    return {"dir": str(run_dir), "cond": cond, "config": cfg, "alerts": alerts, "span_stats": wstats,
            "duration_s": duration,
            "alerts_per_min": (len(alerts) / duration * 60) if duration else None,
            "status": cfg.get("status", "complete"),        # runs before `status` existed were one-shot
            "setup": cfg.get("setup") or {}}


def injector_verdicts(inj_dir: pathlib.Path) -> dict[str, list[dict]]:
    out: dict[str, list[dict]] = collections.defaultdict(list)
    for f in sorted(inj_dir.glob("*_V1_*.json")):
        try:
            rec = json.loads(f.read_text())
        except Exception:  # noqa: BLE001
            continue
        out[rec["scenario"]].append({"failure_mode": rec.get("failure_mode"),
                                     "pdp_reason": (rec.get("evidence") or {}).get("pdp_reason"),
                                     "repeat": rec.get("repeat", 1),
                                     "file": str(f)})
    return out


# =============================================================================
# statistics
# =============================================================================
class Stats:
    def __init__(self, n_boot: int, seed: int):
        self.B = n_boot
        self.rng = np.random.default_rng(seed)

    def ci(self, x, fn=np.mean) -> tuple[float, float] | None:
        x = np.asarray(x, float)
        if len(x) < 2:
            return None
        idx = self.rng.integers(0, len(x), (self.B, len(x)))
        b = fn(x[idx], axis=1)
        return float(np.percentile(b, 2.5)), float(np.percentile(b, 97.5))

    def diff_ci(self, a, b, fn=np.mean) -> tuple[float, float] | None:
        """CI of fn(b) − fn(a), independent resampling (unpaired)."""
        a, b = np.asarray(a, float), np.asarray(b, float)
        if len(a) < 2 or len(b) < 2:
            return None
        ia = self.rng.integers(0, len(a), (self.B, len(a)))
        ib = self.rng.integers(0, len(b), (self.B, len(b)))
        d = fn(b[ib], axis=1) - fn(a[ia], axis=1)
        return float(np.percentile(d, 2.5)), float(np.percentile(d, 97.5))


def wilson(k: int, n: int, z: float = 1.96) -> tuple[float, float] | None:
    if n == 0:
        return None
    p = k / n
    den = 1 + z * z / n
    c = (p + z * z / (2 * n)) / den
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / den
    return c - h, c + h


def clopper_pearson(k: int, n: int, alpha: float = 0.05) -> tuple[float, float] | None:
    """Exact two-sided (1−alpha) CI for a binomial proportion."""
    if n == 0:
        return None
    lo = 0.0 if k == 0 else float(sps.beta.ppf(alpha / 2, k, n - k + 1))
    hi = 1.0 if k == n else float(sps.beta.ppf(1 - alpha / 2, k + 1, n - k))
    return lo, hi


def cp_upper(k: int, n: int, alpha: float = 0.05) -> float | None:
    """Exact ONE-sided (1−alpha) upper bound — with k = 0 this is ≈ 3/n
    ("rule of three"), the number a non-inferiority claim rests on."""
    if n == 0:
        return None
    return 1.0 if k == n else float(sps.beta.ppf(1 - alpha, k + 1, n - k))


def mcnemar_exact(b: int, c: int) -> float:
    """Exact two-sided McNemar p: of the b+c discordant pairs, is the split
    'baseline right / condition wrong' vs the reverse different from 50:50?"""
    return 1.0 if b + c == 0 else float(sps.binomtest(min(b, c), b + c, 0.5).pvalue)


def per_alert_pred(alerts: list[dict]) -> tuple[dict[str, str], int]:
    """alert_id -> prediction, over non-error records; alerts whose pooled runs
    disagree are left out (returned as the second value)."""
    acc: dict[str, set] = collections.defaultdict(set)
    for a in alerts:
        if not a["error"]:
            acc[a["alert_id"]].add(a["pred"])
    return {k: next(iter(v)) for k, v in acc.items() if len(v) == 1}, \
        sum(1 for v in acc.values() if len(v) > 1)


def decision_stability(B_all: list[dict], C_all: list[dict]) -> dict:
    """Paired comparison of the FINAL decisions (escalate/benign/…) per alert."""
    bp, b_mixed = per_alert_pred(B_all)
    cp, c_mixed = per_alert_pred(C_all)
    truth = {a["alert_id"]: a["true_class"] for a in B_all + C_all}
    ids = sorted(set(bp) & set(cp))
    changed = [i for i in ids if bp[i] != cp[i]]
    b = sum(1 for i in changed if bp[i] == truth.get(i))       # baseline right, condition wrong
    c = sum(1 for i in changed if cp[i] == truth.get(i))       # condition right, baseline wrong
    n = len(ids)
    return {"pairs": n, "changed": len(changed), "rate": len(changed) / n if n else None,
            "rate_ci": clopper_pearson(len(changed), n), "rate_upper95": cp_upper(len(changed), n),
            "base_right_cond_wrong": b, "cond_right_base_wrong": c,
            "mcnemar_p": mcnemar_exact(b, c),
            "excluded": {"errors_or_missing": len({a["alert_id"] for a in B_all + C_all}) - n
                         - b_mixed - c_mixed, "inconsistent_pooled": b_mixed + c_mixed}}


def process_metrics(A: list[dict]) -> dict:
    """HOW the verdict was reached, not just what it was.

    routing   triage's branch matches the ground truth: an escalate alert must go
              through the investigation chain (enrichment → … → response), a benign
              one takes the short path. A short-pathed escalate alert was never
              investigated or contained, even if the final verdict is "incident".
    consistent  the final disposition matches the path taken (short → dismissed,
              chain → incident). A mismatch means the Reporter overrode the route.
    strict    routed correctly AND the right verdict — the designed end-to-end behaviour.
    Errors count as wrong (the alert was not handled)."""
    n = len(A)
    routed = [a for a in A if not a["error"] and a["path"] == a["true_class"]]
    consistent = [a for a in A if not a["error"] and
                  ((a["path"] == "benign" and a["pred"] == "benign") or
                   (a["path"] == "escalate" and a["pred"] == "escalate"))]
    strict = [a for a in routed if a["correct"]]
    out = {"n": n,
           "routing": len(routed) / n if n else None, "routing_ci": wilson(len(routed), n),
           "consistent": len(consistent) / n if n else None, "consistent_ci": wilson(len(consistent), n),
           "strict": len(strict) / n if n else None, "strict_ci": wilson(len(strict), n),
           "per_class": {}}
    for tc in ("escalate", "benign"):
        T = [a for a in A if a["true_class"] == tc]
        r = sum(1 for a in T if not a["error"] and a["path"] == tc)
        out["per_class"][tc] = {"n": len(T), "routed": r, "rate": r / len(T) if T else None,
                                "ci": wilson(r, len(T))}
    out["short_path_but_incident"] = sum(1 for a in A if not a["error"] and a["path"] == "benign"
                                         and a["pred"] == "escalate")
    out["chain_but_dismissed"] = sum(1 for a in A if not a["error"] and a["path"] == "escalate"
                                     and a["pred"] == "benign")
    return out


def p95(x) -> float | None:
    x = sorted(x)
    return x[min(len(x) - 1, int(len(x) * 0.95))] if x else None


def seg(alerts: list[dict], s: str) -> list[dict]:
    ok = [a for a in alerts if not a["error"]]
    return ok if s == "all" else [a for a in ok if a["path"] == s]


def per_alert_mean(alerts: list[dict], key: str) -> dict[str, float]:
    """alert_id -> mean of `key` over pooled runs (for pairing across conditions)."""
    acc: dict[str, list[float]] = collections.defaultdict(list)
    for a in alerts:
        if key in a:
            acc[a["alert_id"]].append(a[key])
    return {k: float(np.mean(v)) for k, v in acc.items()}


def per_alert_path(alerts: list[dict]) -> dict[str, str]:
    """alert_id -> path, only if every pooled run of that alert took the same path."""
    acc: dict[str, set] = collections.defaultdict(set)
    for a in alerts:
        if not a["error"]:
            acc[a["alert_id"]].add(a["path"])
    return {k: next(iter(v)) for k, v in acc.items() if len(v) == 1}


# =============================================================================
# evaluation
# =============================================================================
def evaluate(conds: dict[str, list[dict]], order: list[str], base: str,
             inj: dict[str, dict], st: Stats, noise: str | None = None) -> dict:
    out: dict = {"order": order, "baseline": base, "noise_floor": noise, "conditions": {},
                 "overhead": {}, "correctness": {}, "security": {}}

    for c in order:
        A = [a for run in conds[c] for a in run["alerts"]]
        durs = [r["duration_s"] for r in conds[c] if r.get("duration_s")]
        cres = {"runs": [r["config"].get("run_id") for r in conds[c]], "n_alerts": len(A),
                "errors": sum(1 for a in A if a["error"]),
                "retried": sum(1 for a in A if a.get("retries")),
                "alerts_per_min": (len(A) / sum(durs) * 60) if durs and len(durs) == len(conds[c]) else None,
                "segments": {}}
        for s in SEGMENTS:
            S = seg(A, s)
            lat = [a["latency_s"] for a in S]
            row = {"n": len(S)}
            if lat:
                row.update(mean=float(np.mean(lat)), mean_ci=st.ci(lat),
                           median=float(np.median(lat)), median_ci=st.ci(lat, np.median),
                           p95=p95(lat), max=max(lat),
                           msgs=float(np.mean([a["msgs"] for a in S])))
            for k in WORK:
                v = [a[k] for a in S if k in a]
                if v:
                    row[k] = float(np.mean(v))
                    row[k + "_ci"] = st.ci(v)
                    row[k + "_n"] = len(v)
            cres["segments"][s] = row
        # correctness (errors count as wrong: the alert was not handled)
        n = len(A)
        k = sum(1 for a in A if a["correct"])
        per_class = {}
        for tc in sorted({a["true_class"] for a in A if a["true_class"]}):
            T = [a for a in A if a["true_class"] == tc]
            kk = sum(1 for a in T if a["correct"])
            per_class[tc] = {"n": len(T), "recall": kk / len(T), "ci": wilson(kk, len(T))}
        conf = collections.Counter((a["true_class"], a["pred"]) for a in A)
        path_mix = collections.Counter(a["path"] for a in A)
        out["correctness"][c] = {"n": n, "accuracy": k / n if n else None, "ci": wilson(k, n),
                                 "per_class": per_class,
                                 "confusion": {f"{t}->{p}": v for (t, p), v in sorted(conf.items())},
                                 "path_mix": dict(path_mix),
                                 "needs_review": sum(1 for a in A if a["pred"] == "needs_review"),
                                 "process": process_metrics(A)}
        out["conditions"][c] = cres

    # --- overhead vs baseline: unpaired (all alerts) + paired, path-matched ---
    B_all = [a for run in conds[base] for a in run["alerts"]]
    b_path = per_alert_path(B_all)
    for c in order:
        if c == base:
            continue
        C_all = [a for run in conds[c] for a in run["alerts"]]
        c_path = per_alert_path(C_all)
        common = sorted(set(b_path) & set(c_path))
        dec = decision_stability(B_all, C_all)
        pc = sum(1 for i in common if b_path[i] != c_path[i])
        dec["path_pairs"], dec["path_changed"] = len(common), pc     # the ROUTE, not the verdict
        dec["path_rate"] = pc / len(common) if common else None
        dec["path_rate_upper95"] = cp_upper(pc, len(common))
        res = {"common_alerts": len(common),
               "path_changed": pc,
               "verdict_changed": dec["changed"],
               "decisions": dec,
               "segments": {}}
        for s in SEGMENTS:
            row = {}
            bl = [a["latency_s"] for a in seg(B_all, s)]
            cl = [a["latency_s"] for a in seg(C_all, s)]
            if bl and cl:
                row["unpaired_mean_delta"] = float(np.mean(cl) - np.mean(bl))
                row["unpaired_mean_ci"] = st.diff_ci(bl, cl)
                row["base_mean"] = float(np.mean(bl))
            ids = [i for i in common if b_path[i] == c_path[i] and (s == "all" or b_path[i] == s)]
            row["pairs"] = len(ids)
            for key in ("latency_s", "nonllm_s", "llm_s", "tokens", "llm_calls"):
                bm = per_alert_mean(seg(B_all, s), key)
                cm = per_alert_mean(seg(C_all, s), key)
                d = [cm[i] - bm[i] for i in ids if i in bm and i in cm]
                if d:
                    row[key] = {"n": len(d), "mean": float(np.mean(d)), "ci": st.ci(d),
                                "median": float(np.median(d)), "median_ci": st.ci(d, np.median),
                                "base_mean": float(np.mean([bm[i] for i in ids if i in bm and i in cm]))}
            res["segments"][s] = row
        out["overhead"][c] = res

    # --- noise floor: is a condition's change rate above the baseline-repeat's? ---
    nf = out["overhead"].get(noise, {}).get("decisions") if noise else None
    if nf and nf["pairs"]:
        for c, o in out["overhead"].items():
            d = o["decisions"]
            if c == noise or not d["pairs"]:
                continue
            table = [[d["changed"], d["pairs"] - d["changed"]],
                     [nf["changed"], nf["pairs"] - nf["changed"]]]
            d["vs_noise_floor_p"] = float(sps.fisher_exact(table, alternative="greater")[1])

    # --- security ---
    scen = sorted({sc for c in inj for sc in inj[c]}, key=lambda s: (s[:2], s))
    for sc in scen:
        out["security"][sc] = {c: inj.get(c, {}).get(sc) for c in order}
    return out


# =============================================================================
# rendering
# =============================================================================
def _f(x, nd=1) -> str:
    return "—" if x is None else f"{x:.{nd}f}"


def _ci(ci, nd=1) -> str:
    return "" if not ci else f" [{ci[0]:.{nd}f}, {ci[1]:.{nd}f}]"


def _pct(x, base) -> str:
    return "" if (x is None or not base) else f" ({x / base * 100:+.0f}%)"


def _sig(ci) -> str:
    return " ✱" if ci and (ci[0] > 0 or ci[1] < 0) else ""


def render(ev: dict, runs: dict[str, list[dict]], warnings: list[str]) -> str:
    order, base = ev["order"], ev["baseline"]
    L = [f"# Evaluation: {' · '.join(order)}  (baseline {base})\n"]

    # inputs
    L.append("## Inputs\n")
    L.append("| condition | runs | status | alerts | errors | retried | alerts/min | git_sha | "
             "count / esc_frac / seed / conc. | traces mapped |")
    L.append("|---|---|---|---|---|---|---|---|---|---|")
    for c in order:
        for r in runs[c]:
            pr = r["config"].get("params", {})
            ss = r["span_stats"]
            tm = (f"{ss['mapped_alerts']}/{len(r['alerts'])}"
                  + (f" ({ss['ambiguous_traces']} ambiguous)" if ss.get("ambiguous_traces") else "")) if ss.get("spans") else "no spans"
            L.append(f"| {c} | `{r['config'].get('run_id')}` | {r['status']} | {len(r['alerts'])} | "
                     f"{sum(1 for a in r['alerts'] if a['error'])} | "
                     f"{sum(1 for a in r['alerts'] if a.get('retries'))} | {_f(r.get('alerts_per_min'), 2)} | "
                     f"{r['config'].get('git_sha', '—')} | "
                     f"{pr.get('count')} / {pr.get('escalate_frac')} / {pr.get('seed')} / {pr.get('concurrency')} | {tm} |")
    L.append("")
    setups = [(c, r) for c in order for r in runs[c] if r["setup"].get("captured")]
    if setups:
        L.append("Setup: " + "; ".join(
            f"`{r['config'].get('run_id')}` GPU {', '.join(r['setup'].get('gpus') or ['?'])}, "
            f"vLLM `{(r['setup'].get('comparable', {}).get('vllm') or {}).get('image')}`"
            for c, r in setups) + "\n")
    for w in warnings:
        L.append(f"> ⚠️ {w}")
    if warnings:
        L.append("")

    # security
    L.append("## Security (attack verdicts)\n")
    if ev["security"]:
        L.append("| scenario | " + " | ".join(order) + " |")
        L.append("|---|" + "---|" * len(order))
        for sc, row in ev["security"].items():
            cells = []
            for c in order:
                v = row.get(c)
                if not v:
                    cells.append("—")
                    continue
                modes = collections.Counter(x["failure_mode"] for x in v)
                reasons = sorted({x["pdp_reason"] for x in v if x["pdp_reason"]})
                parts = []
                for m, k in modes.most_common():
                    name = ("**" + m + "**") if m in BLOCKED else ("⚠️ " + m if m == "harness_error" else m)
                    parts.append(name + (f" {k}/{len(v)}" if len(v) > 1 else ""))
                cell = " · ".join(parts)
                if reasons:
                    cell += f" `{','.join(reasons)}`"
                cells.append(cell)
            L.append(f"| {sc} | " + " | ".join(cells) + " |")
        L.append("\n**Bold** = blocked; `reason` = the PDP's reason where the token was rejected; "
                 "`k/R` = k of R repetitions; ⚠️ harness_error = no verdict (the attack never reached "
                 "the control — usually a dead port-forward), re-run it.\n")
    else:
        L.append("_No injector verdicts — pass `--inj LABEL=<injector dir>`._\n")

    # efficiency per segment
    L.append("## Efficiency per path taken\n")
    L.append("Mean [95 % bootstrap CI]. `all` = every non-error alert; `benign` / `escalate` = "
             "the path the pipeline actually took (not the ground-truth class).\n")
    for s in SEGMENTS:
        L.append(f"### Path: {s}\n")
        L.append("| cond | n | latency mean (s) | median (s) | p95 | msgs/alert | tokens/alert | LLM calls | LLM s | non-LLM s |")
        L.append("|---|---|---|---|---|---|---|---|---|---|")
        for c in order:
            r = ev["conditions"][c]["segments"][s]
            if not r.get("n"):
                L.append(f"| {c} | 0 | — | — | — | — | — | — | — | — |")
                continue
            L.append(f"| {c} | {r['n']} | {_f(r['mean'])}{_ci(r['mean_ci'])} | "
                     f"{_f(r['median'])}{_ci(r['median_ci'])} | {_f(r['p95'])} | {_f(r['msgs'], 2)} | "
                     f"{_f(r.get('tokens'), 0)}{_ci(r.get('tokens_ci'), 0)} | {_f(r.get('llm_calls'), 1)} | "
                     f"{_f(r.get('llm_s'))} | {_f(r.get('nonllm_s'))}{_ci(r.get('nonllm_s_ci'))} |")
        L.append("")

    # overhead
    if ev["overhead"]:
        L.append(f"## Overhead vs {base}\n")
        L.append("**Paired, path-matched:** each alert compared with itself (same seed → same alerts), "
                 "only alerts that took the same path in both conditions. Δ = condition − baseline, "
                 "mean [95 % CI], ✱ = CI excludes 0. Unpaired Δ (all alerts of the segment) for reference.\n")
        for c, o in ev["overhead"].items():
            L.append(f"### {c} vs {base}\n")
            L.append(f"Common alerts: {o['common_alerts']} · path changed: {o['path_changed']} · "
                     f"verdict changed: {o['verdict_changed']}\n")
            L.append("| path | pairs | Δ latency (s) | Δ median latency (s) | Δ non-LLM s | Δ LLM s | Δ tokens | Δ LLM calls | unpaired Δ latency (s) |")
            L.append("|---|---|---|---|---|---|---|---|---|")
            for s in SEGMENTS:
                r = o["segments"].get(s, {})
                def cell(k, nd=1, pct=False):
                    v = r.get(k)
                    if not v:
                        return "—"
                    return (f"{v['mean']:+.{nd}f}{_ci(v['ci'], nd)}{_sig(v['ci'])}"
                            + (_pct(v['mean'], v['base_mean']) if pct else ""))
                lat = r.get("latency_s")
                med = (f"{lat['median']:+.1f}{_ci(lat['median_ci'])}{_sig(lat['median_ci'])}" if lat else "—")
                unp = (f"{r['unpaired_mean_delta']:+.1f}{_ci(r.get('unpaired_mean_ci'))}"
                       f"{_pct(r['unpaired_mean_delta'], r.get('base_mean'))}" if "unpaired_mean_delta" in r else "—")
                L.append(f"| {s} | {r.get('pairs', 0)} | {cell('latency_s', 1, True)} | {med} | "
                         f"{cell('nonllm_s')} | {cell('llm_s')} | {cell('tokens', 0)} | {cell('llm_calls', 2)} | {unp} |")
            L.append("")

    # decision stability
    if ev["overhead"]:
        nf = ev.get("noise_floor")
        L.append(f"## Decision stability vs {base}\n")
        L.append("Per alert, the final decision (escalate / benign / …) in the condition vs the baseline, "
                 "over alerts without errors in both. **changed** = decision differs; rate with exact "
                 "(Clopper-Pearson) 95 % CI and the one-sided 95 % **upper bound** (with 0 changes ≈ 3/n — "
                 "the number a \"the control does not alter decisions\" claim rests on). McNemar p tests "
                 "whether the changes favour one side (baseline right vs condition right)."
                 + (f" **{nf}** is a repeat of the baseline: its rate is the noise floor (vLLM is not "
                    "bit-deterministic across batch mixes, even at temperature 0); `p > floor` = Fisher "
                    "exact, one-sided, rate above the noise floor." if nf else
                    " No noise floor given — pass a baseline repeat with `--noise-floor LABEL`.") + "\n")
        L.append("| cond | pairs | changed | rate [95 % CI] | upper 95 % | base✓ cond✗ | cond✓ base✗ "
                 "| McNemar p | p > floor | route changed (upper 95 %) |")
        L.append("|---|---|---|---|---|---|---|---|---|---|")
        for c, o in ev["overhead"].items():
            d = o["decisions"]
            tag = f"{c} (noise floor)" if c == nf else c
            pf = "—" if c == nf or "vs_noise_floor_p" not in d else f"{d['vs_noise_floor_p']:.3f}"
            route = (f"{d['path_changed']}/{d['path_pairs']} ({_f(d['path_rate_upper95'], 3)})"
                     if d.get("path_pairs") else "—")
            L.append(f"| {tag} | {d['pairs']} | {d['changed']} | {_f(d['rate'], 3)}{_ci(d['rate_ci'], 3)} | "
                     f"{_f(d['rate_upper95'], 3)} | {d['base_right_cond_wrong']} | {d['cond_right_base_wrong']} | "
                     f"{d['mcnemar_p']:.3f} | {pf} | {route} |")
        L.append("")
        L.append("*route changed* = the alert took the other path (chain vs short) than in the baseline — "
                 "a control interfering with the workflow shows up here even when the verdict survives.\n")

    # correctness
    L.append("## Correctness\n")
    classes = sorted({tc for c in order for tc in ev["correctness"][c]["per_class"]})
    L.append("| cond | n | accuracy [Wilson 95 %] | " + " | ".join(f"recall {tc}" for tc in classes)
             + " | needs_review | errors | path mix |")
    L.append("|---|---|---|" + "---|" * len(classes) + "---|---|---|")
    for c in order:
        k = ev["correctness"][c]
        rec = []
        for tc in classes:
            pc = k["per_class"].get(tc)
            rec.append(f"{pc['recall']:.2f}{_ci(pc['ci'], 2)} (n={pc['n']})" if pc else "—")
        mix = ", ".join(f"{p}={v}" for p, v in sorted(k["path_mix"].items()))
        L.append(f"| {c} | {k['n']} | {_f(k['accuracy'], 3)}{_ci(k['ci'], 2)} | " + " | ".join(rec)
                 + f" | {k['needs_review']} | {ev['conditions'][c]['errors']} | {mix} |")
    L.append("")
    L.append("**Process** — *how* the verdict was reached. **routing** = triage sent the alert down the "
             "path its ground truth requires (escalate → investigation chain, benign → short path); "
             "**consistent** = the final disposition matches the path taken; **strict** = routed "
             "correctly *and* the right verdict (the designed behaviour). A short-pathed escalate "
             "alert that still ends as `incident` counts as a correct *verdict* above but was never "
             "investigated or contained.\n")
    L.append("| cond | n | routing [Wilson 95 %] | escalate → chain | benign → short | consistent | "
             "strict | short path → incident | chain → dismissed |")
    L.append("|---|---|---|---|---|---|---|---|---|")
    for c in order:
        p = ev["correctness"][c]["process"]
        pc = p["per_class"]
        L.append(f"| {c} | {p['n']} | {_f(p['routing'], 3)}{_ci(p['routing_ci'], 2)} | "
                 f"{pc['escalate']['routed']}/{pc['escalate']['n']} | {pc['benign']['routed']}/{pc['benign']['n']} | "
                 f"{_f(p['consistent'], 3)}{_ci(p['consistent_ci'], 2)} | {_f(p['strict'], 3)}{_ci(p['strict_ci'], 2)} | "
                 f"{p['short_path_but_incident']} | {p['chain_but_dismissed']} |")
    L.append("")
    L.append("Confusion (true → predicted):\n")
    for c in order:
        L.append(f"- **{c}**: " + ", ".join(f"{k}: {v}" for k, v in ev["correctness"][c]["confusion"].items()))
    L.append("")

    # notes
    L.append("## Notes on reading this\n")
    L.append("- CIs are percentile bootstrap over alerts. Alerts in a run share the vLLM server "
             "(concurrency > 1), so they are not fully independent — treat CIs as indicative, and "
             "prefer repeated runs per condition (pass several dirs with the same label).")
    L.append("- p95 at small n is close to the max; it has no CI here for that reason.")
    L.append("- non-LLM s = end-to-end latency − summed LLM span time of the alert's trace: tool "
             "calls, A2A hops, framework time and — at C1/C2 — the PDP round-trips. It is the "
             "closest proxy for the control's own cost.")
    L.append("- Errors are excluded from efficiency and counted as wrong in correctness.")
    L.append("- A changed path/verdict vs the baseline is LLM non-determinism or the control "
             "interfering with legitimate flow — the noise-floor row separates the two statistically; "
             "the PDP log (`DENY` lines) shows it per alert.")
    L.append("- alerts/min = alerts ÷ wall-clock of the run's segments (a resumed run excludes the gap). "
             "Latency and throughput are only comparable at the same concurrency and setup.")
    L.append("- retried = alerts re-driven after a lost connection to the triage endpoint (the broken "
             "attempt is not recorded). The interrupted attempt may still have finished in-cluster, "
             "adding some load for a moment — a handful of retries is harmless; many are worth a note.")
    return "\n".join(L) + "\n"


# =============================================================================
def main() -> int:
    ap = argparse.ArgumentParser(description="Multi-condition evaluation (per-path, paired, bootstrap CIs)")
    ap.add_argument("runs", nargs="+", help="run dirs; optional LABEL=path to override the condition label")
    ap.add_argument("--inj", action="append", default=[], metavar="LABEL=DIR",
                    help="injector verdict dir for a condition (repeatable); default <run>/injector if present")
    ap.add_argument("--order", default=None, help="condition order, e.g. C0,C1,C2 (default: sorted labels)")
    ap.add_argument("--baseline", default=None, help="reference condition for deltas (default: first in order)")
    ap.add_argument("--noise-floor", default=None, metavar="LABEL",
                    help="condition that is a REPEAT of the baseline (e.g. C0b): its decision-change "
                         "rate and latency deltas are the noise floor the other conditions are tested against")
    ap.add_argument("--boot", type=int, default=10000, help="bootstrap resamples")
    ap.add_argument("--seed", type=int, default=0, help="bootstrap RNG seed (results are reproducible)")
    ap.add_argument("--out", type=pathlib.Path, default=None, help="markdown output (default: stdout)")
    ap.add_argument("--json", type=pathlib.Path, default=None, help="also write all numbers as JSON")
    a = ap.parse_args()

    conds: dict[str, list[dict]] = collections.defaultdict(list)
    for arg in a.runs:
        label, path = _split_label(arg)
        run = load_run(path, label)
        conds[run["cond"]].append(run)

    order = a.order.split(",") if a.order else sorted(conds)
    missing = [c for c in order if c not in conds]
    if missing:
        ap.error(f"--order names conditions without runs: {missing}")
    base = a.baseline or order[0]
    if base not in conds:
        ap.error(f"baseline {base!r} has no runs")

    if a.noise_floor and (a.noise_floor not in conds or a.noise_floor == base):
        ap.error(f"--noise-floor {a.noise_floor!r} must be a condition with runs, other than the baseline")

    # several --inj dirs for one label are pooled (e.g. repeated injector runs)
    inj: dict[str, dict] = {}
    for spec in a.inj:
        label, d = spec.split("=", 1)
        for sc, v in injector_verdicts(pathlib.Path(d)).items():
            inj.setdefault(label, {}).setdefault(sc, []).extend(v)
    for c in order:                                  # co-located verdicts (--run-id)
        if c not in inj:
            for run in conds[c]:
                d = pathlib.Path(run["dir"]) / "injector"
                if d.exists():
                    for sc, v in injector_verdicts(d).items():
                        inj.setdefault(c, {}).setdefault(sc, []).extend(v)

    warnings = []
    params = {json.dumps(r["config"].get("params", {}), sort_keys=True)
              for c in order for r in conds[c]}
    if len(params) > 1:
        warnings.append("Run parameters differ between runs (count/escalate_frac/seed/concurrency) — "
                        "latency and accuracy are NOT comparable across those runs: " + " vs ".join(sorted(params)))
    for c in order:
        for r in conds[c]:
            ss = r["span_stats"]
            if not ss.get("spans"):
                warnings.append(f"{r['config'].get('run_id')}: no traces/spans.jsonl — work metrics n/a.")
            elif ss["mapped_alerts"] < len(r["alerts"]):
                warnings.append(f"{r['config'].get('run_id')}: only {ss['mapped_alerts']}/{len(r['alerts'])} "
                                "alerts matched to a trace — work metrics cover those only.")
            if ss.get("ambiguous_traces"):
                warnings.append(f"{r['config'].get('run_id')}: {ss['ambiguous_traces']} trace(s) mention "
                                "several alert ids (assigned to the most frequent).")
            if r["status"] != "complete":
                warnings.append(f"{r['config'].get('run_id')}: status **{r['status']}** "
                                f"({len(r['alerts'])}/{r['config'].get('params', {}).get('count')} alerts) — "
                                "finish it with `run_experiment.py --resume <dir>`.")
            if r["config"].get("setup_changes"):
                warnings.append(f"{r['config'].get('run_id')}: the setup changed between its segments "
                                "(see config.json `setup_changes`).")

    # the hardware / serving stack must be identical across everything compared
    comparable = {r["config"].get("run_id"): r["setup"].get("comparable")
                  for c in order for r in conds[c] if r["setup"].get("captured")}
    no_setup = [r["config"].get("run_id") for c in order for r in conds[c] if not r["setup"].get("captured")]
    if len({json.dumps(v, sort_keys=True) for v in comparable.values()}) > 1:
        ref_id, ref = next(iter(comparable.items()))
        for rid, v in comparable.items():
            diff = sorted(k for k in set(ref) | set(v) if ref.get(k) != v.get(k))
            if diff:
                warnings.append(f"{rid}: setup differs from {ref_id} in {', '.join(diff)} "
                                "(GPU / vLLM / images / resources) — not comparable.")
    if no_setup and comparable:
        warnings.append("No recorded setup (GPU, vLLM, images) for: " + ", ".join(no_setup)
                        + " — cannot confirm they ran on the same stack.")

    bad_inj = [f"{c} {sc}" for c, d in inj.items() for sc, v in d.items()
               if any(x["failure_mode"] == "harness_error" for x in v)]
    if bad_inj:
        warnings.append("Injector `harness_error` (no verdict, usually a dead port-forward) for: "
                        + ", ".join(sorted(bad_inj)) + " — re-run those before reporting.")

    ev = evaluate(conds, order, base, inj, Stats(a.boot, a.seed), a.noise_floor)
    md = render(ev, conds, warnings)
    if a.out:
        a.out.write_text(md)
        print(f"wrote {a.out}")
    else:
        print(md)
    if a.json:
        a.json.write_text(json.dumps(ev, indent=2, default=str))
        print(f"wrote {a.json}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
