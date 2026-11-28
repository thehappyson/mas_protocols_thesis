#!/usr/bin/env python
"""run_experiment.py — the experiment EXECUTOR.

Given a workload spec (N alerts, benign/escalate split, seed), drives it through
the live SOC pipeline and captures EVERYTHING for one run into results/<run_id>/:

    config.json     run parameters, condition label, git sha, time segments,
                    endpoints, the deployed SETUP (GPU, vLLM image/args, images,
                    resources), capture status, vLLM load summary
    results.jsonl   per-alert: prompt, ALL status updates, full final text, path,
                    disposition, latency, message count, error, retries — appended
                    as each alert finishes, so nothing is lost on a crash
    traces/spans.jsonl   Phoenix spans for the run's segments (chunked export)
    vllm_metrics.jsonl   vLLM /metrics samples during the run (--vllm-metrics)
    network/…       in-cluster network capture (pluggable backend — see design doc)
    pod_logs/…      kubectl logs, STREAMED during the run (PDP [pdp] + PEP [cap])
    summary.json    aggregates + effectiveness vs ground truth + throughput

LONG RUNS (n = 1000):
  * every finished alert is appended to results.jsonl immediately;
  * a broken connection to the triage endpoint (dead port-forward, restarted pod)
    does NOT burn through the remaining alerts as errors: the alert is not
    recorded, the executor waits up to --reconnect-wait s for the endpoint to come
    back (experiments/portforwards.sh restarts dead forwards), then retries it;
  * if it doesn't come back, the run stops cleanly. Continue it with
        run_experiment.py --resume experiments/results/<run_id>
    which re-samples the same alerts (same seed), skips the finished ones, and
    appends a new time SEGMENT. Traces / pod logs / vLLM metrics cover all segments.

SEPARATION OF CONCERNS: this executor does NOT apply security treatments or
attacks. Those are toggled OUTSIDE it (kubectl apply of overlays, capability-token
config, the attack injector). Pass --condition to LABEL whatever cluster state you
captured; the executor only records the label. See experiments/EXPERIMENT_DESIGN.md.

Usage:
    experiments/portforwards.sh C0 &          # or the individual port-forwards
    /opt/miniconda3/envs/masterarbeit/bin/python experiments/run_experiment.py \
        --count 1000 --escalate-frac 0.5 --seed 1337 --concurrency 32 --condition C0 \
        --vllm-metrics http://127.0.0.1:8000/metrics
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import pathlib
import random
import re
import statistics
import subprocess
import sys
import threading
import time
from collections import Counter
from datetime import datetime, timedelta, timezone

import httpx
from a2a.client import ClientConfig, ClientFactory
from a2a.client.card_resolver import A2ACardResolver
from a2a.types import Message, Part, Role, SendMessageRequest, TaskState

# Reuse the exact prompt + path/disposition logic the ad-hoc driver uses, so runs
# are consistent with scripts/run_workload.py.
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "scripts"))
from run_workload import _classify_path, _prompt_for  # noqa: E402

REPO = pathlib.Path(__file__).resolve().parents[1]
DEFAULTS = {"count": 20, "escalate_frac": 0.3, "seed": 1337, "concurrency": 2,
            "condition": "unlabeled"}


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(d: datetime) -> str:
    return d.astimezone(timezone.utc).isoformat()


def _parse(s: str) -> datetime:
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


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
# Errors that mean "our connection to the entry endpoint broke" (port-forward died,
# triage pod replaced) rather than "the pipeline failed on this alert". Such an
# attempt is not a measurement: it is not recorded and the alert is retried.
# ReadTimeout is deliberately NOT here — a 900 s stall is a pipeline result.
TRANSPORT_SIGNS = ("ConnectError", "ConnectTimeout", "RemoteProtocolError", "ReadError",
                   "WriteError", "PoolTimeout", "All connection attempts failed",
                   "Server disconnected", "Connection refused", "Connection reset",
                   "AgentCardResolutionError", "peer closed connection")
MAX_TRANSPORT_RETRIES = 3     # per alert, while the endpoint is otherwise healthy


def _is_transport(err: str | None) -> bool:
    return bool(err) and any(s in err for s in TRANSPORT_SIGNS)


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


async def _resolve_card(http: httpx.AsyncClient, endpoint: str):
    card = await A2ACardResolver(httpx_client=http, base_url=endpoint).get_agent_card()
    # The card advertises Triage's container URL; rewrite to the endpoint we
    # actually reached (host->triage hop). Downstream delegations are unaffected.
    for iface in card.supported_interfaces:
        iface.url = endpoint
    return card


class Progress:
    def __init__(self, total: int, done_before: int):
        self.total, self.done_before, self.done = total, done_before, 0
        self.t0 = time.time()

    def line(self) -> str:
        k = self.done_before + self.done
        el = time.time() - self.t0
        if self.done:
            eta = el / self.done * (self.total - k)
            eta_s = f"ETA {int(eta // 3600)}h{int(eta % 3600 // 60):02d}m"
        else:
            eta_s = "ETA —"
        return f"[{k}/{self.total} {k / self.total * 100:5.1f}% · {eta_s}]"


async def drive(alerts: list[dict], endpoint: str, concurrency: int, run_id: str,
                sink, progress: Progress, reconnect_wait: float,
                segment: int) -> dict:
    """Drive `alerts`; every finished alert goes to `sink(record)` immediately.
    Returns {"aborted": bool, "reason": str|None, "transport_events": int}."""
    sem = asyncio.Semaphore(concurrency)
    healthy = asyncio.Event()
    healthy.set()
    state = {"aborted": False, "reason": None, "transport_events": 0, "probe": None}

    async with httpx.AsyncClient(timeout=900.0) as http:
        card = await _resolve_card(http, endpoint)
        factory = ClientFactory(ClientConfig(httpx_client=http, streaming=True))

        async def probe() -> None:
            """Wait for the endpoint to answer again (watchdog restarts forwards)."""
            deadline = time.time() + reconnect_wait
            print(f"  ⚠ lost connection to {endpoint} — waiting up to {reconnect_wait:.0f}s "
                  "for it to come back (is experiments/portforwards.sh running?)", flush=True)
            while time.time() < deadline:
                await asyncio.sleep(5)
                try:
                    async with httpx.AsyncClient(timeout=10.0) as h:
                        r = await h.get(endpoint.rstrip("/") + "/.well-known/agent-card.json")
                    if r.status_code < 500:
                        print("  ✓ endpoint is back — retrying the interrupted alerts", flush=True)
                        healthy.set()
                        return
                except Exception:  # noqa: BLE001
                    continue
            state["aborted"] = True
            state["reason"] = f"endpoint {endpoint} unreachable for {reconnect_wait:.0f}s"
            healthy.set()                   # release waiters; they see `aborted`

        async def on_transport_error() -> None:
            state["transport_events"] += 1
            if healthy.is_set() and not state["aborted"]:
                healthy.clear()
                state["probe"] = asyncio.create_task(probe())

        async def guarded(alert: dict) -> None:
            async with sem:
                attempts = 0
                while True:
                    await healthy.wait()
                    if state["aborted"]:
                        return
                    res = await _drive_one(factory, card, alert, run_id)
                    if _is_transport(res["error"]) and attempts < MAX_TRANSPORT_RETRIES:
                        attempts += 1
                        await on_transport_error()
                        continue
                    res["retries"] = attempts
                    res["segment"] = segment
                    sink(res)
                    progress.done += 1
                    flag = "!" if res["error"] else " "
                    print(f" {flag}{res['alert_id']:<24} truth={res['true_class']:<9} "
                          f"path={res['path']:<12} disp={res['disposition']:<12} "
                          f"{res['latency_s']:6.1f}s  {progress.line()}", flush=True)
                    return

        await asyncio.gather(*(guarded(a) for a in alerts))
        if state["probe"] is not None and not state["probe"].done():
            state["probe"].cancel()
    return {"aborted": state["aborted"], "reason": state["reason"],
            "transport_events": state["transport_events"]}


# ---------------------------------------------------------------------------
# 3a. Capture — Phoenix traces, chunked per time slice, all segments
# ---------------------------------------------------------------------------
TRACE_LIMIT = 100_000   # span cap per chunk (default client limit is only 1000)
TRACE_GRACE_S = 15      # spans of the last alerts start just before `end`


def export_traces(endpoint: str, project: str, windows: list[tuple[datetime, datetime]],
                  out_dir: pathlib.Path, chunk_min: float) -> dict:
    """Append Phoenix spans for every [start, end] window to traces/spans.jsonl, in
    chunks of `chunk_min` minutes (one huge dataframe for ~26k spans over a
    port-forward is slow and fragile). De-duplicated by span id, so re-exporting an
    overlapping window (resume) is harmless. Best-effort: never fatal."""
    try:
        from phoenix.client import Client
    except ImportError:
        return {"captured": False, "reason": "arize-phoenix not installed "
                "(pip install arize-phoenix in the conda env to capture traces)"}
    td = out_dir / "traces"
    td.mkdir(parents=True, exist_ok=True)
    path = td / "spans.jsonl"
    seen: set[str] = set()
    if path.exists():
        for line in path.open():
            try:
                seen.add(json.loads(line).get("context.span_id"))
            except json.JSONDecodeError:
                continue
    new, truncated, chunks = 0, [], 0
    try:
        client = Client(base_url=endpoint)
        with path.open("a") as fh:
            for start, end in windows:
                t, end = start, end + timedelta(seconds=TRACE_GRACE_S)
                while t < end:
                    u = min(end, t + timedelta(minutes=chunk_min))
                    df = client.spans.get_spans_dataframe(
                        project_name=project, start_time=t, end_time=u, limit=TRACE_LIMIT)
                    chunks += 1
                    if len(df) >= TRACE_LIMIT:
                        truncated.append(f"{_iso(t)}..{_iso(u)}")
                    if len(df):
                        for line in df.to_json(orient="records", lines=True,
                                               date_format="iso").splitlines():
                            sid = json.loads(line).get("context.span_id")
                            if sid in seen:
                                continue
                            seen.add(sid)
                            fh.write(line + "\n")
                            new += 1
                    t = u
    except Exception as e:  # noqa: BLE001
        return {"captured": False, "reason": f"{type(e).__name__}: {e}",
                "n_spans": len(seen), "path": str(path)}
    out = {"captured": True, "n_spans": len(seen), "new_spans": new, "chunks": chunks,
           "path": str(path)}
    if truncated:
        out["truncated_chunks"] = truncated     # lower --trace-chunk-min and re-run --resume
    return out


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
    with (nd / "capture.log").open("a") as fh:
        fh.write(proc.stdout)
    if proc.stderr:
        with (nd / "capture.err").open("a") as fh:
            fh.write(proc.stderr)
    return {"captured": proc.returncode == 0, "cmd": net_cmd, "returncode": proc.returncode}


# ---------------------------------------------------------------------------
# 3c. Capture — pod stdout, STREAMED during the run (the defender-side evidence)
# ---------------------------------------------------------------------------
_TS_RE = re.compile(r"^(\[[^\]]*\]\s+)?(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d+))?Z\s")


def _ts_key(line: str) -> str | None:
    """Fixed-width sortable timestamp of a `kubectl logs --timestamps` line."""
    m = _TS_RE.match(line)
    return f"{m.group(2)}.{(m.group(3) or '').ljust(9, '0')[:9]}" if m else None


class LogStream(threading.Thread):
    """`kubectl logs -f --timestamps --prefix` for one ns/deploy, appended to a file.

    Streaming (instead of one `kubectl logs` at the end) survives log rotation
    (kubelet keeps only the current ~10 MiB file) and resume segments. If the stream
    ends (pod restarted, API hiccup) it reconnects from the last timestamp it saw
    and drops the lines it already wrote. This is the ONLY way the ephemeral
    defender-side evidence survives a cluster teardown: the PDP audit trail
    (`[pdp]`) and the PEP lines (`[cap]`) are container stdout, not traces."""

    def __init__(self, ns: str, deploy: str, path: pathlib.Path, since: datetime):
        super().__init__(daemon=True)
        self.ns, self.deploy, self.path = ns, deploy, path
        self.since = since.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        self.stop_ev = threading.Event()
        self.proc: subprocess.Popen | None = None
        self.lines = 0
        self.reconnects = 0
        self.last_err = ""

    def run(self) -> None:
        last_key, at_last = None, set()
        while not self.stop_ev.is_set():
            cmd = ["kubectl", "-n", self.ns, "logs", "-f", f"deploy/{self.deploy}",
                   "--since-time", self.since, "--timestamps", "--prefix"]
            try:
                self.proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                             stderr=subprocess.PIPE, text=True)
            except Exception as e:  # noqa: BLE001
                self.last_err = f"{type(e).__name__}: {e}"
                return
            with self.path.open("a") as fh:
                for line in self.proc.stdout:              # type: ignore[union-attr]
                    k = _ts_key(line)
                    if k is not None and last_key is not None:
                        if k < last_key or (k == last_key and line in at_last):
                            continue                       # already written before a reconnect
                    if k is not None:
                        if k != last_key:
                            last_key, at_last = k, set()
                        at_last.add(line)
                    fh.write(line)
                    fh.flush()
                    self.lines += 1
            self.proc.wait()
            err = (self.proc.stderr.read() if self.proc.stderr else "") or ""
            if err.strip():
                self.last_err = err.strip()[:300]
            if self.stop_ev.is_set():
                break
            self.reconnects += 1
            if last_key:
                self.since = last_key[:19] + "Z"
            self.stop_ev.wait(5)

    def stop(self) -> None:
        self.stop_ev.set()
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
        self.join(timeout=10)


def start_log_streams(spec: str | None, start: datetime,
                      out_dir: pathlib.Path) -> tuple[list[LogStream], list[dict]]:
    if not spec:
        return [], []
    ld = out_dir / "pod_logs"
    ld.mkdir(parents=True, exist_ok=True)
    streams, bad = [], []
    for t in [t for t in spec.replace(",", " ").split() if t]:
        if "/" not in t:
            bad.append({"target": t, "reason": "expected ns/deploy"})
            continue
        ns, deploy = t.split("/", 1)
        s = LogStream(ns, deploy, ld / f"{ns}_{deploy}.log", start)
        s.start()
        streams.append(s)
    return streams, bad


# reason = the whole detail, minus the t2 binding suffix (" task=… jti=…")
_PDP_RE = re.compile(r"\[pdp\]\s+(/\S+)\s+.*?\s(ISSUE|ALLOW|DENY)\s+(.*?)(?:\s+task=\S*\s+jti=\S*)?\s*$")


def pdp_tally(out_dir: pathlib.Path) -> dict | None:
    """Count the PDP's decisions (and DENY reasons) in the captured audit log."""
    p = out_dir / "pod_logs" / "platform-zone_capability-verifier.log"
    if not p.exists():
        return None
    verdicts, reasons = Counter(), Counter()
    for line in p.open():
        m = _PDP_RE.search(line)
        if not m:
            continue
        verdicts[m.group(2)] += 1
        if m.group(2) == "DENY":
            reasons[m.group(3) or "?"] += 1
    return {"verdicts": dict(verdicts), "deny_reasons": dict(reasons)}


# ---------------------------------------------------------------------------
# 3d. Capture — vLLM load during the run (--vllm-metrics)
# ---------------------------------------------------------------------------
VLLM_METRICS = {   # our key -> candidate Prometheus names (vLLM V1 first), aggregation
    "running": (("vllm:num_requests_running",), "sum"),
    "waiting": (("vllm:num_requests_waiting",), "sum"),
    "kv_usage": (("vllm:kv_cache_usage_perc", "vllm:gpu_cache_usage_perc"), "max"),
    "preemptions": (("vllm:num_preemptions_total", "vllm:num_preemptions"), "sum"),
    "gen_tokens": (("vllm:generation_tokens_total",), "sum"),
    "prompt_tokens": (("vllm:prompt_tokens_total",), "sum"),
    "prefix_hits": (("vllm:prefix_cache_hits_total",), "sum"),
    "prefix_queries": (("vllm:prefix_cache_queries_total",), "sum"),
}
_PROM_RE = re.compile(r"^([a-zA-Z_:][a-zA-Z0-9_:]*)(\{[^}]*\})?\s+([0-9.eE+-]+|NaN)")


def _parse_prom(text: str) -> dict:
    vals: dict[str, list[float]] = {}
    for line in text.splitlines():
        if not line or line[0] == "#":
            continue
        m = _PROM_RE.match(line)
        if m and m.group(3) != "NaN":
            vals.setdefault(m.group(1), []).append(float(m.group(3)))
    out = {}
    for key, (names, agg) in VLLM_METRICS.items():
        for n in names:
            if n in vals:
                out[key] = sum(vals[n]) if agg == "sum" else max(vals[n])
                break
    return out


async def poll_vllm(url: str, path: pathlib.Path, segment: int, stop: asyncio.Event,
                    every_s: float = 5.0) -> None:
    async with httpx.AsyncClient(timeout=5.0) as h:
        while not stop.is_set():
            try:
                r = await h.get(url)
                sample = _parse_prom(r.text) if r.status_code == 200 else {}
            except Exception:  # noqa: BLE001 — a missed sample is fine
                sample = {}
            if sample:
                sample.update(t=_iso(_now()), segment=segment)
                with path.open("a") as fh:
                    fh.write(json.dumps(sample) + "\n")
            try:
                await asyncio.wait_for(stop.wait(), timeout=every_s)
            except asyncio.TimeoutError:
                pass


def summarize_vllm(path: pathlib.Path) -> dict | None:
    """Peaks + per-segment counter deltas (counters reset on a vLLM restart)."""
    if not path.exists():
        return None
    S = [json.loads(l) for l in path.open() if l.strip()]
    if not S:
        return None
    out: dict = {"samples": len(S)}
    for k in ("running", "waiting", "kv_usage"):
        v = [s[k] for s in S if k in s]
        if v:
            out[f"max_{k}"] = max(v)
            out[f"mean_{k}"] = round(statistics.mean(v), 4)
    deltas: Counter = Counter()
    dur = 0.0
    for seg in sorted({s["segment"] for s in S}):
        G = [s for s in S if s["segment"] == seg]
        dur += (_parse(G[-1]["t"]) - _parse(G[0]["t"])).total_seconds()
        for k in ("preemptions", "gen_tokens", "prompt_tokens", "prefix_hits", "prefix_queries"):
            v = [s[k] for s in G if k in s]
            if len(v) >= 2:
                deltas[k] += max(0.0, v[-1] - v[0])
    out.update({f"{k}_delta": v for k, v in deltas.items()})
    if dur > 0 and "gen_tokens" in deltas:
        out["gen_tokens_per_s"] = round(deltas["gen_tokens"] / dur, 1)
    if deltas.get("prefix_queries"):
        out["prefix_hit_rate"] = round(deltas["prefix_hits"] / deltas["prefix_queries"], 3)
    return out


# ---------------------------------------------------------------------------
# 3e. Capture — the deployed setup (what the numbers were measured ON)
# ---------------------------------------------------------------------------
def _kubectl(args: list[str], timeout: float = 20) -> str | None:
    try:
        p = subprocess.run(["kubectl", *args], capture_output=True, text=True, timeout=timeout)
        return p.stdout if p.returncode == 0 else None
    except Exception:  # noqa: BLE001
        return None


def capture_setup() -> dict:
    """GPU, nodes, vLLM image/args, every deployment's images/resources/literal env.
    Best-effort (kubectl from this machine); `comparable` is what evaluate.py checks
    for equality across conditions — env is left out on purpose (C1/C2 differ there
    by design), and so is the PDP (it only exists at C1/C2)."""
    ctx = _kubectl(["config", "current-context"], 5)
    if _kubectl(["get", "ns", "agent-zone", "-o", "name"], 10) is None:
        return {"captured": False, "reason": "kubectl cannot reach the cluster",
                "context": (ctx or "").strip() or None}
    setup: dict = {"captured": True, "context": (ctx or "").strip(), "deployments": {}}
    for ns in ("agent-zone", "tool-zone", "platform-zone"):
        raw = _kubectl(["-n", ns, "get", "deploy", "-o", "json"])
        for d in (json.loads(raw)["items"] if raw else []):
            name = f"{ns}/{d['metadata']['name']}"
            cs = []
            for c in d["spec"]["template"]["spec"].get("containers", []):
                cs.append({"name": c["name"], "image": c.get("image"),
                           "resources": c.get("resources", {}),
                           "env": {e["name"]: e.get("value") for e in c.get("env", [])
                                   if "value" in e},
                           **({"command": c.get("command"), "args": c.get("args")}
                              if d["metadata"]["name"] == "vllm" else {})})
            setup["deployments"][name] = cs
    raw = _kubectl(["get", "nodes", "-o", "json"])
    nodes = []
    for n in (json.loads(raw)["items"] if raw else []):
        lab, alloc = n["metadata"].get("labels", {}), n["status"].get("allocatable", {})
        nodes.append({"name": n["metadata"]["name"],
                      "instance_type": lab.get("node.kubernetes.io/instance-type"),
                      "gpu_product": lab.get("nvidia.com/gpu.product"),
                      "gpus": alloc.get("nvidia.com/gpu"), "cpu": alloc.get("cpu"),
                      "memory": alloc.get("memory")})
    setup["nodes"] = nodes
    smi = _kubectl(["-n", "platform-zone", "exec", "deploy/vllm", "--", "nvidia-smi",
                    "--query-gpu=name,memory.total,driver_version", "--format=csv,noheader"], 30)
    setup["gpus"] = [l.strip() for l in smi.splitlines() if l.strip()] if smi else None
    vl = (setup["deployments"].get("platform-zone/vllm") or [{}])[0]
    setup["comparable"] = {
        "gpus": [g.rsplit(",", 1)[0] for g in setup["gpus"]] if setup["gpus"] else None,
        "vllm": {"image": vl.get("image"), "command": vl.get("command"), "args": vl.get("args")},
        "images": {k: [c["image"] for c in v] for k, v in setup["deployments"].items()
                   if k.split("/")[0] in ("agent-zone", "tool-zone")},
        "resources": {k: [c["resources"] for c in v] for k, v in setup["deployments"].items()
                      if k.split("/")[0] in ("agent-zone", "tool-zone")},
    }
    setup["comparable_hash"] = hashlib.sha256(
        json.dumps(setup["comparable"], sort_keys=True).encode()).hexdigest()[:12]
    return setup


# ---------------------------------------------------------------------------
# 4. Summarise — aggregates + effectiveness vs ground truth
# ---------------------------------------------------------------------------
_PRED = {"incident": "escalate", "dismissed": "benign", "needs_review": "needs_review"}


def summarize(results: list[dict], duration_s: float | None = None) -> dict:
    n = len(results)
    preds = [_PRED.get(r["disposition"], "unknown") for r in results]
    correct = sum(1 for r, p in zip(results, preds) if p == r["true_class"])
    lat = sorted(r["latency_s"] for r in results)
    msgs = [r["n_updates"] for r in results]
    return {
        "count": n,
        "errors": sum(1 for r in results if r["error"]),
        "retried_alerts": sum(1 for r in results if r.get("retries")),
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
        "throughput": {
            "duration_s": round(duration_s, 1) if duration_s else None,
            "alerts_per_min": round(n / duration_s * 60, 2) if duration_s else None,
        },
    }


# ---------------------------------------------------------------------------
def _git_sha() -> str:
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "--short=12", "HEAD"], text=True, cwd=REPO).strip()
    except Exception:  # noqa: BLE001
        return "unknown"


def _reachable(url: str) -> str | None:
    """None if `url` answers HTTP at all (any status), else the error."""
    try:
        httpx.get(url, timeout=10.0)
        return None
    except Exception as e:  # noqa: BLE001
        return f"{type(e).__name__}: {e}"


def _read_results(path: pathlib.Path) -> list[dict]:
    if not path.exists():
        return []
    out = []
    for line in path.open():
        line = line.strip()
        if line:
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:      # a torn last line from a hard crash
                continue
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description="Experiment executor: drive a workload + capture everything")
    ap.add_argument("--count", type=int, default=None, help=f"total alerts to drive (default {DEFAULTS['count']})")
    ap.add_argument("--escalate-frac", type=float, default=None,
                    help=f"fraction escalate, rest benign (default {DEFAULTS['escalate_frac']})")
    ap.add_argument("--seed", type=int, default=None, help=f"workload seed (default {DEFAULTS['seed']})")
    ap.add_argument("--concurrency", type=int, default=None,
                    help=f"alerts in flight (default {DEFAULTS['concurrency']})")
    ap.add_argument("--condition", default=None,
                    help="LABEL for the external cluster state (C0, C1, C2, …)")
    ap.add_argument("--resume", type=pathlib.Path, default=None, metavar="RUN_DIR",
                    help="continue an incomplete run: same params (read from its config.json), "
                         "finished alerts are skipped, a new time segment is appended")
    ap.add_argument("--manifest", type=pathlib.Path, default=REPO / "raw_data/staged/wl.jsonl")
    ap.add_argument("--out", type=pathlib.Path, default=REPO / "experiments/results")
    ap.add_argument("--triage-endpoint", default="http://127.0.0.1:9101")
    ap.add_argument("--phoenix-endpoint", default="http://127.0.0.1:6006")
    ap.add_argument("--project", default="soc-testbed", help="Phoenix project name")
    ap.add_argument("--vllm-metrics", default=None, metavar="URL",
                    help="poll vLLM's Prometheus endpoint during the run, e.g. "
                         "http://127.0.0.1:8000/metrics (port-forward svc/vllm 8000)")
    ap.add_argument("--reconnect-wait", type=float, default=600.0,
                    help="seconds to wait for a lost triage endpoint before stopping (default 600)")
    ap.add_argument("--trace-chunk-min", type=float, default=10.0,
                    help="minutes of spans per Phoenix export request (default 10)")
    ap.add_argument("--network-cmd", default=None, help="shell command to capture in-cluster network flows")
    ap.add_argument("--pod-logs", nargs="?", const="platform-zone/capability-verifier",
                    default=None,
                    help="stream kubectl logs during the run into pod_logs/. Bare flag "
                         "grabs the PDP audit trail; or pass a space/comma list of "
                         "ns/deploy, e.g. 'platform-zone/capability-verifier "
                         "tool-zone/mcp-containment agent-zone/triage-agent'.")
    ap.add_argument("--no-traces", action="store_true", help="skip Phoenix trace export")
    ap.add_argument("--no-setup", action="store_true", help="skip recording the deployed setup via kubectl")
    args = ap.parse_args()
    given = {k: getattr(args, k) for k in DEFAULTS}

    # --- new run or resume ---------------------------------------------------
    if args.resume:
        run_dir = args.resume.resolve()
        cfg_path = run_dir / "config.json"
        if not cfg_path.exists():
            ap.error(f"--resume: no config.json in {run_dir}")
        config = json.loads(cfg_path.read_text())
        if "segments" not in config:               # a run from before segments existed
            config["segments"] = [{"start": config["window"]["start"],
                                   "end": config["window"]["end"], "traces_exported": True}]
        params = dict(config["params"], condition=config["condition"])
        clash = {k: (v, params[k]) for k, v in given.items() if v is not None and v != params[k]}
        if clash:
            ap.error("--resume uses the run's own parameters; these differ: "
                     + ", ".join(f"--{k.replace('_', '-')} {a} (run has {b})" for k, (a, b) in clash.items()))
        manifest = pathlib.Path(config.get("manifest", args.manifest))
        run_id = config["run_id"]
    else:
        params = {k: (v if v is not None else DEFAULTS[k]) for k, v in given.items()}
        manifest = args.manifest
        run_id = f"{params['condition']}-{_now().strftime('%Y%m%dT%H%M%SZ')}"
        run_dir = args.out / run_id
        config = None

    alerts = sample_workload(manifest, params["count"], params["escalate_frac"], params["seed"])
    if not alerts:
        print("no alerts sampled (empty manifest?)", file=sys.stderr)
        return 1
    res_path = run_dir / "results.jsonl"
    done = _read_results(res_path)
    done_ids = {r["alert_id"] for r in done}
    todo = [a for a in alerts if a["alert_id"] not in done_ids]

    # --- preflight: fail in seconds, not after an hour --------------------------
    if todo:
        err = _reachable(args.triage_endpoint.rstrip("/") + "/.well-known/agent-card.json")
        if err:
            print(f"✗ triage endpoint {args.triage_endpoint} unreachable ({err}).\n"
                  "  Start the port-forwards (experiments/portforwards.sh <C0|C1|C2>) and retry.",
                  file=sys.stderr)
            return 2
    if not args.no_traces:
        err = _reachable(args.phoenix_endpoint)
        if err:
            print(f"✗ Phoenix {args.phoenix_endpoint} unreachable ({err}) — traces would be "
                  "lost. Fix the 6006 forward or pass --no-traces.", file=sys.stderr)
            return 2
    if args.vllm_metrics and _reachable(args.vllm_metrics):
        print(f"⚠ vLLM metrics {args.vllm_metrics} unreachable — continuing without load samples.")

    run_dir.mkdir(parents=True, exist_ok=True)
    seg_idx = len(config["segments"]) if config else 0
    start = _now()
    if args.no_setup:
        setup = {"captured": False, "reason": "--no-setup"}
    else:
        try:
            setup = capture_setup()
        except Exception as e:  # noqa: BLE001 — recording the setup must never block a run
            setup = {"captured": False, "reason": f"{type(e).__name__}: {e}"}
    if config is None:
        config = {
            "run_id": run_id,
            "condition": params["condition"],
            "git_sha": _git_sha(),
            "params": {k: params[k] for k in ("count", "escalate_frac", "seed", "concurrency")},
            "status": "running",
            "segments": [],
            "window": {"start": _iso(start), "end": None},
            "endpoints": {"triage": args.triage_endpoint, "phoenix": args.phoenix_endpoint,
                          "project": args.project, "vllm_metrics": args.vllm_metrics},
            "manifest": str(manifest),
            "setup": setup,
            "setup_changes": [],
            "captures": {},
        }
    elif setup.get("captured") and config.get("setup", {}).get("captured") and \
            setup.get("comparable_hash") != config["setup"].get("comparable_hash"):
        config.setdefault("setup_changes", []).append(
            {"segment": seg_idx, "setup": setup})
        print("⚠ the deployed setup differs from the run's first segment "
              "(GPU / vLLM / images / resources) — recorded under setup_changes.")
    segment = {"start": _iso(start), "end": None, "git_sha": _git_sha(),
               "setup_hash": setup.get("comparable_hash"), "traces_exported": False,
               "alerts_before": len(done)}
    config["segments"].append(segment)
    config["status"] = "running"
    cfg_path = run_dir / "config.json"
    cfg_path.write_text(json.dumps(config, indent=2))

    print(f"run_id={run_id}  {'resuming' if args.resume else 'driving'} "
          f"{len(todo)} of {len(alerts)} alerts (escalate_frac={params['escalate_frac']}, "
          f"concurrency={params['concurrency']}) via {args.triage_endpoint}")
    if setup.get("captured"):
        print(f"setup: GPU {setup.get('gpus')}  vLLM {setup['comparable']['vllm']['image']}")
    else:
        print(f"setup: not recorded ({setup.get('reason')})")
    print()

    # --- drive ------------------------------------------------------------------
    streams, bad_streams = start_log_streams(args.pod_logs, start, run_dir)
    fh = res_path.open("a")

    def sink(rec: dict) -> None:
        fh.write(json.dumps(rec) + "\n")
        fh.flush()

    outcome = {"aborted": False, "reason": None, "transport_events": 0}

    async def _run() -> dict:
        stop = asyncio.Event()
        poller = (asyncio.create_task(poll_vllm(args.vllm_metrics, run_dir / "vllm_metrics.jsonl",
                                                seg_idx, stop))
                  if args.vllm_metrics else None)
        try:
            return await drive(todo, args.triage_endpoint, params["concurrency"], run_id, sink,
                               Progress(len(alerts), len(done)), args.reconnect_wait, seg_idx)
        finally:
            stop.set()
            if poller:
                await poller

    interrupted = False
    try:
        if todo:
            outcome = asyncio.run(_run())
    except KeyboardInterrupt:
        interrupted = True
        outcome = {"aborted": True, "reason": "interrupted (Ctrl-C)", "transport_events": 0}
    finally:
        fh.close()
        end = _now()
        segment["end"] = _iso(end)
        config["window"]["end"] = _iso(end)
        for s in streams:
            s.stop()

    results = _read_results(res_path)
    complete = {r["alert_id"] for r in results} >= {a["alert_id"] for a in alerts}
    segment["alerts_after"] = len(results)
    config["status"] = "complete" if complete else ("interrupted" if interrupted else "incomplete")
    if outcome["reason"]:
        segment["stop_reason"] = outcome["reason"]
    segment["transport_events"] = outcome["transport_events"]

    # --- captures (skipped on Ctrl-C: `--resume` exports every unexported segment) --
    caps = config.setdefault("captures", {})
    if not interrupted:
        if args.no_traces:
            caps["traces"] = {"captured": False, "reason": "skipped (--no-traces)"}
        else:
            time.sleep(10)              # let the agents' batch span processors flush
            pending = [s for s in config["segments"] if not s.get("traces_exported") and s.get("end")]
            tr = export_traces(args.phoenix_endpoint, args.project,
                               [(_parse(s["start"]), _parse(s["end"])) for s in pending],
                               run_dir, args.trace_chunk_min)
            # a truncated chunk keeps its segments pending, so `--resume <dir>
            # --trace-chunk-min <smaller>` re-exports them (spans are de-duplicated)
            if tr["captured"] and not tr.get("truncated_chunks"):
                for s in pending:
                    s["traces_exported"] = True
            caps["traces"] = tr
        caps["network"] = capture_network(args.network_cmd, run_dir)
    if args.pod_logs:
        caps["pod_logs"] = {
            "captured": any(s.lines for s in streams),
            "streams": [{"target": f"{s.ns}/{s.deploy}", "lines_this_segment": s.lines,
                         "reconnects": s.reconnects, **({"last_error": s.last_err} if s.last_err else {})}
                        for s in streams],
            "failed": bad_streams, "pdp": pdp_tally(run_dir)}
    elif "pod_logs" not in caps:
        caps["pod_logs"] = {"captured": False, "reason": "not requested (pass --pod-logs)"}
    vsum = summarize_vllm(run_dir / "vllm_metrics.jsonl")
    if vsum:
        config["vllm"] = vsum

    duration = sum((_parse(s["end"]) - _parse(s["start"])).total_seconds()
                   for s in config["segments"] if s.get("end"))
    cfg_path.write_text(json.dumps(config, indent=2))
    summary = summarize(results, duration)
    summary["status"] = config["status"]
    (run_dir / "summary.json").write_text(json.dumps(summary, indent=2))

    # --- console recap ---
    print("\n" + "=" * 60)
    print(f"run_id: {run_id}   condition: {params['condition']}   status: {config['status']}")
    print(f"alerts: {len(results)}/{len(alerts)}   segments: {len(config['segments'])}")
    print(f"accuracy vs ground truth: {summary['accuracy_vs_ground_truth']}  "
          f"(errors: {summary['errors']}, retried: {summary['retried_alerts']})")
    print(f"paths: {summary['by_path']}")
    print(f"dispositions: {summary['by_disposition']}")
    print(f"latency s: {summary['latency_s']}")
    print(f"throughput: {summary['throughput']['alerts_per_min']} alerts/min")
    if vsum:
        print(f"vLLM: max running {vsum.get('max_running')}, max waiting {vsum.get('max_waiting')}, "
              f"max KV {vsum.get('max_kv_usage')}, preemptions {vsum.get('preemptions_delta', 0):.0f}, "
              f"{vsum.get('gen_tokens_per_s')} gen tok/s")
    tr = caps.get("traces", {})
    print(f"traces: {('ok, %s spans' % tr.get('n_spans')) if tr.get('captured') else tr.get('reason')}"
          + (f"  ⚠ truncated chunks: {tr['truncated_chunks']}" if tr.get("truncated_chunks") else ""))
    pl = caps.get("pod_logs", {})
    if pl.get("pdp"):
        print(f"PDP decisions: {pl['pdp']['verdicts']}  DENY reasons: {pl['pdp']['deny_reasons'] or '-'}")
    elif not pl.get("captured"):
        print(f"pod logs: {pl.get('reason', pl.get('failed'))}")
    print(f"results dir: {run_dir}")
    if not complete:
        print(f"\n⚠ INCOMPLETE ({outcome['reason']}). Continue with:\n"
              f"  $PY experiments/run_experiment.py --resume {run_dir}")
    print("=" * 60)
    return 0 if complete else 3


if __name__ == "__main__":
    raise SystemExit(main())
