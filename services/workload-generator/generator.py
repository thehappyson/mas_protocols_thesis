"""Workload Generator — out-of-band labeled-alert source for the SOC testbed.

WHAT IT IS. A standalone component (NOT an agent, no MCP/A2A, no trust or
protocol overhead) that INSERTs alerts into the operational Postgres at a
controllable rate and class mix, and records each alert's constructed TRUE CLASS
in a separate, agent-invisible ground-truth table. It replaces the static seed
alerts as the system's live input: the SIEM tool's `next_alerts` reads the same
`alerts` table, so whatever this writes becomes what the pipeline triages.

WHY OUT-OF-BAND. Ground truth is the methodological core of the evaluation. By
constructing each alert with a known class and writing that class to a side
channel keyed by alert id — never to a column the SIEM tool returns — the later
evaluation can join agent outcomes to truth by alert id, WITHOUT the agents ever
being able to read the answer key. See docker/initdb/operational/02-ground-truth.sql.

SEED-LINKED, NOT DEGENERATE. Every generated alert references rows that already
exist in the seed: its destination is an indicator present in the `iocs` table
and its source is an asset present in the CMDB `assets` table, so enrichment /
correlation lookups actually resolve. The benign vs escalate distinction is
carried by the LINKED INDICATOR'S VERDICT (clean vs malicious/suspicious),
which is only knowable by looking the indicator up — not by the alert's shape.

DETERMINISTIC. All randomness flows from one seeded RNG in a fixed draw order,
so the same seed yields the same sequence of alerts (class, endpoints, rule,
description, inter-arrival delay). `plan` mode prints that sequence without
touching the DB, so two plans with the same seed are byte-identical — the
reproducibility check.

CONFIG (all from env; CLI flags override). See parse_config().
    OPERATIONAL_DB_URL   Postgres DSN (same var the tools use).
    WORKLOAD_RATE        alerts per second (float, default 1.0).
    WORKLOAD_ARRIVAL     'steady' | 'poisson' (default steady).
    WORKLOAD_MIX         'benign:0.6,escalate:0.3,campaign:0.1' (default this).
    WORKLOAD_SEED        RNG seed (int, default 1337).
    WORKLOAD_COUNT       total alerts to emit (int; default 20 if no duration).
    WORKLOAD_DURATION    max seconds to run (float; optional).
    WORKLOAD_CAMPAIGN_SIZE  stages per multi-stage campaign (int, default 3).
    WORKLOAD_RUN_ID      id prefix for this run (default 'wl-<seed>-<base36 time>').

RUN (insert into the DB at the configured rate/mix):
    python services/workload-generator/generator.py run
PLAN (print the deterministic sequence, no DB, for reproducibility diffs):
    python services/workload-generator/generator.py plan --count 20

This reuses the tool image (psycopg2 is already there); it is wired into
compose as a profile-gated `workload-generator` service.
"""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import random
import sys
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any, Iterator

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
from mcp_db import execute, rows  # noqa: E402  (shared DB helper, tool image)

OPERATIONAL_DB_URL = os.environ.get(
    "OPERATIONAL_DB_URL", "postgresql://soc:soc@127.0.0.1:5432/soc_operational"
)

# Canonical class labels. Campaign alerts carry the label 'campaign:<id>'; the
# DB normalizes this into true_class='campaign' + campaign_id (see _insert).
CLASS_BENIGN = "benign"
CLASS_ESCALATE = "escalate"
CLASS_CAMPAIGN = "campaign"


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
@dataclass
class Config:
    rate: float
    arrival: str
    mix: dict[str, float]
    seed: int
    count: int | None
    duration: float | None
    campaign_size: int
    run_id: str
    dsn: str


def _parse_mix(raw: str) -> dict[str, float]:
    """Parse 'benign:0.6,escalate:0.3,campaign:0.1' -> normalized weight dict."""
    out: dict[str, float] = {}
    for part in raw.split(","):
        part = part.strip()
        if not part:
            continue
        key, _, val = part.partition(":")
        key = key.strip().lower()
        if key not in (CLASS_BENIGN, CLASS_ESCALATE, CLASS_CAMPAIGN):
            raise ValueError(f"unknown class in mix: {key!r}")
        out[key] = float(val)
    total = sum(out.values())
    if total <= 0:
        raise ValueError("mix weights must sum to a positive number")
    return {k: v / total for k, v in out.items()}  # normalize to probabilities


def _default_run_id(seed: int) -> str:
    # base36 of the current second keeps physical runs from colliding on the
    # alert-id PK while staying short; content is still seed-deterministic.
    t = int(time.time())
    digits = "0123456789abcdefghijklmnopqrstuvwxyz"
    b36 = ""
    while t:
        t, r = divmod(t, 36)
        b36 = digits[r] + b36
    return f"wl-{seed}-{b36 or '0'}"


def parse_config(argv: list[str]) -> tuple[str, Config, int | None]:
    """Build Config from env, with CLI flags overriding. Returns (mode, cfg, preview)."""
    ap = argparse.ArgumentParser(description="SOC testbed workload generator")
    ap.add_argument("mode", choices=["run", "plan"], help="insert (run) or print plan")
    ap.add_argument("--rate", type=float)
    ap.add_argument("--arrival", choices=["steady", "poisson"])
    ap.add_argument("--mix")
    ap.add_argument("--seed", type=int)
    ap.add_argument("--count", type=int)
    ap.add_argument("--duration", type=float)
    ap.add_argument("--campaign-size", type=int)
    ap.add_argument("--run-id")
    args = ap.parse_args(argv)

    def env(name: str, default: str | None = None) -> str | None:
        return os.environ.get(name, default)

    rate = args.rate if args.rate is not None else float(env("WORKLOAD_RATE", "1.0"))
    arrival = args.arrival or env("WORKLOAD_ARRIVAL", "steady")
    mix = _parse_mix(
        args.mix or env("WORKLOAD_MIX", "benign:0.6,escalate:0.3,campaign:0.1")
    )
    seed = args.seed if args.seed is not None else int(env("WORKLOAD_SEED", "1337"))

    count_env = env("WORKLOAD_COUNT")
    count = args.count if args.count is not None else (int(count_env) if count_env else None)
    dur_env = env("WORKLOAD_DURATION")
    duration = (
        args.duration if args.duration is not None else (float(dur_env) if dur_env else None)
    )
    # Bounded by construction: default to 20 alerts when neither bound is given.
    if count is None and duration is None:
        count = 20

    campaign_size = (
        args.campaign_size
        if args.campaign_size is not None
        else int(env("WORKLOAD_CAMPAIGN_SIZE", "3"))
    )
    run_id = args.run_id or env("WORKLOAD_RUN_ID") or _default_run_id(seed)

    cfg = Config(
        rate=rate,
        arrival=arrival,
        mix=mix,
        seed=seed,
        count=count,
        duration=duration,
        campaign_size=campaign_size,
        run_id=run_id,
        dsn=OPERATIONAL_DB_URL,
    )
    # plan mode preview length: the count, or 20 if only a duration was set.
    preview = count if count is not None else 20
    return args.mode, cfg, preview


# ---------------------------------------------------------------------------
# Seed-linked pools (read the ACTUAL seeded rows, so links always resolve)
# ---------------------------------------------------------------------------
@dataclass
class Pools:
    iocs_by_verdict: dict[str, list[str]]          # verdict -> [indicator, ...]
    assets: list[dict[str, Any]]                   # [{asset_id, hostname, criticality}]
    high_value_assets: list[dict[str, Any]]        # criticality in {high, critical}


def load_pools(dsn: str) -> Pools:
    """Load indicator/asset pools from the operational DB so generated alerts
    reference rows that provably exist (enrichment/correlation will resolve)."""
    iocs_by_verdict: dict[str, list[str]] = {}
    for r in rows(dsn, "SELECT indicator, verdict FROM iocs ORDER BY indicator"):
        iocs_by_verdict.setdefault(r["verdict"], []).append(r["indicator"])
    assets = rows(
        dsn,
        "SELECT asset_id, hostname, criticality FROM assets ORDER BY asset_id",
    )
    if not assets:
        raise SystemExit("no assets seeded — cannot link alerts to CMDB rows")
    if not any(iocs_by_verdict.values()):
        raise SystemExit("no IOCs seeded — cannot link alerts to threat-intel rows")
    high_value = [a for a in assets if a["criticality"] in ("high", "critical")] or assets
    return Pools(iocs_by_verdict=iocs_by_verdict, assets=assets, high_value_assets=high_value)


def _pick_indicator(rng: random.Random, pools: Pools, verdicts: list[str]) -> str:
    """Pick an indicator whose verdict is one of `verdicts`, in preference order,
    falling back across verdicts so a run never fails on a sparse seed."""
    for v in verdicts:
        bucket = pools.iocs_by_verdict.get(v)
        if bucket:
            return rng.choice(bucket)
    # last resort: anything seeded
    everything = [i for bucket in pools.iocs_by_verdict.values() for i in bucket]
    return rng.choice(everything)


# ---------------------------------------------------------------------------
# Alert templates — behavioral, NOT labeled. The class is never named in the
# text; benign and escalate share structure. The distinguishing fact is the
# linked indicator's verdict (resolved by a threat-intel lookup) plus realistic
# behavioral cues (volume, periodicity, timing) — so classifying an alert
# requires actually checking, not pattern-matching the string.
# ---------------------------------------------------------------------------
_BENIGN_TEMPLATES = [
    ("Outbound Connection Observed",
     "Host {src} ({shost}) opened an outbound session to {dst} on port {port}; "
     "{mb} MB transferred over {mins} min, within the asset's normal baseline."),
    ("Scheduled Software Update",
     "Host {src} ({shost}) contacted {dst} on port {port} to check for updates "
     "during the maintenance window; {mb} MB downloaded, no follow-on activity."),
    ("DNS Query To External Host",
     "Host {src} ({shost}) resolved and briefly connected to {dst}; single "
     "short-lived session, {mb} MB, consistent with routine use."),
]
_ESCALATE_TEMPLATES = [
    ("Large Outbound Data Transfer",
     "Host {src} ({shost}) transferred {gb} GB to {dst} on port {port} over "
     "{mins} min, roughly {factor}x this asset's baseline."),
    ("Periodic Outbound Beaconing",
     "Host {src} ({shost}) is contacting {dst} on port {port} every {beacon}s "
     "with small encoded payloads; the regular period is uncharacteristic of "
     "normal traffic."),
    ("Repeated Authentication Failures",
     "Host {src} ({shost}) generated {count} failed logons then one success "
     "against {dst} off-hours; access pattern deviates from the user's norm."),
]
# Campaign stages tell one escalating story on ONE target asset, so correlation
# can link them by shared asset/campaign. Stage index cycles if size > len.
_CAMPAIGN_STAGES = [
    ("Suspicious Inbound Link Delivery",
     "User on {src} ({shost}) received and opened a link resolving to {dst}; "
     "initial-access stage of a suspected multi-step intrusion on this host."),
    ("Post-Access Outbound Beaconing",
     "Host {src} ({shost}) began periodic contact to {dst} every {beacon}s "
     "shortly after the delivery event; likely command-and-control on the same "
     "host."),
    ("Staged Data Collection And Egress",
     "Host {src} ({shost}) moved {gb} GB toward {dst} on port {port} following "
     "the beaconing; consistent with collection and exfiltration on this host."),
]


@dataclass
class PlannedAlert:
    seq: int
    true_class: str            # human label: 'benign' | 'escalate' | 'campaign:<id>'
    class_kind: str            # normalized: benign | escalate | campaign
    campaign_id: str | None
    stage: int | None
    source_ip: str             # a real CMDB asset id
    source_host: str
    dest_ip: str               # a real IOC indicator
    indicator_verdict: str
    target_asset: str
    rule_name: str
    description: str
    severity: str
    delay: float               # seconds to wait AFTER this alert before the next


class _CampaignState:
    """Tracks the in-progress campaign so successive 'campaign' draws extend one
    story (shared id + target asset) until it reaches campaign_size stages."""

    def __init__(self, size: int, seed: int) -> None:
        self._size = size
        self._seed = seed
        self._counter = 0
        self.current: dict[str, Any] | None = None

    def next_stage(self, rng: random.Random, pools: Pools) -> dict[str, Any]:
        if self.current is None or self.current["stage"] >= self._size:
            self._counter += 1
            target = rng.choice(pools.high_value_assets)
            self.current = {
                "id": f"camp-{self._seed}-{self._counter}",
                "target": target,
                "stage": 0,
            }
        self.current["stage"] += 1
        return self.current


def _draw_class(rng: random.Random, mix: dict[str, float]) -> str:
    """Weighted class draw in a fixed key order (determinism)."""
    r = rng.random()
    cumulative = 0.0
    for key in (CLASS_BENIGN, CLASS_ESCALATE, CLASS_CAMPAIGN):
        cumulative += mix.get(key, 0.0)
        if r < cumulative:
            return key
    return CLASS_CAMPAIGN  # rounding guard


def iter_plan(pools: Pools, cfg: Config) -> Iterator[PlannedAlert]:
    """Deterministic, unbounded sequence of planned alerts for `cfg`.

    Draw order per alert is FIXED so the same seed reproduces the same sequence:
    class -> (campaign stage) -> template -> indicator -> source asset ->
    numeric fill -> inter-arrival delay.
    """
    rng = random.Random(cfg.seed)
    campaigns = _CampaignState(cfg.campaign_size, cfg.seed)
    seq = 0
    while True:
        seq += 1
        kind = _draw_class(rng, cfg.mix)

        campaign_id: str | None = None
        stage: int | None = None
        if kind == CLASS_CAMPAIGN:
            camp = campaigns.next_stage(rng, pools)
            campaign_id = camp["id"]
            stage = camp["stage"]
            target = camp["target"]
            rule, desc_t = _CAMPAIGN_STAGES[(stage - 1) % len(_CAMPAIGN_STAGES)]
            # Escalating indicator: later stages skew malicious.
            verdicts = ["suspicious", "malicious", "clean"] if stage == 1 else \
                       ["malicious", "suspicious", "clean"]
            source = target
            severity = "high"
            true_class = f"{CLASS_CAMPAIGN}:{campaign_id}"
        elif kind == CLASS_ESCALATE:
            rule, desc_t = _ESCALATE_TEMPLATES[rng.randrange(len(_ESCALATE_TEMPLATES))]
            verdicts = ["malicious", "suspicious"]
            source = rng.choice(pools.assets)
            severity = rng.choice(["high", "critical"])
            true_class = CLASS_ESCALATE
        else:  # benign
            rule, desc_t = _BENIGN_TEMPLATES[rng.randrange(len(_BENIGN_TEMPLATES))]
            verdicts = ["clean"]
            source = rng.choice(pools.assets)
            severity = "low"
            true_class = CLASS_BENIGN

        indicator = _pick_indicator(rng, pools, verdicts)
        indicator_verdict = next(
            (v for v, bucket in pools.iocs_by_verdict.items() if indicator in bucket),
            "unknown",
        )
        # Avoid a degenerate self-loop where source == dest.
        if indicator == source["asset_id"]:
            indicator = _pick_indicator(rng, pools, verdicts)

        # Numeric fill (drawn regardless of template so the RNG stream is stable).
        port = rng.choice([80, 443, 8080, 53, 22])
        mb = rng.randint(2, 90)
        gb = round(rng.uniform(1.5, 9.0), 1)
        mins = rng.randint(3, 40)
        beacon = rng.choice([30, 45, 60, 90])
        count = rng.randint(8, 60)
        factor = rng.choice([10, 20, 30, 40])
        description = desc_t.format(
            src=source["asset_id"], shost=source["hostname"], dst=indicator,
            port=port, mb=mb, gb=gb, mins=mins, beacon=beacon, count=count,
            factor=factor,
        )

        # Inter-arrival delay drawn here so pacing is part of the deterministic
        # plan. steady -> constant; poisson -> exponential with mean 1/rate.
        if cfg.arrival == "poisson":
            delay = rng.expovariate(cfg.rate) if cfg.rate > 0 else 0.0
        else:
            delay = 1.0 / cfg.rate if cfg.rate > 0 else 0.0

        yield PlannedAlert(
            seq=seq,
            true_class=true_class,
            class_kind=kind,
            campaign_id=campaign_id,
            stage=stage,
            source_ip=source["asset_id"],
            source_host=source["hostname"],
            dest_ip=indicator,
            indicator_verdict=indicator_verdict,
            target_asset=source["asset_id"],
            rule_name=rule,
            description=description,
            severity=severity,
            delay=delay,
        )


# ---------------------------------------------------------------------------
# Schema + insertion
# ---------------------------------------------------------------------------
_GROUND_TRUTH_DDL = """
CREATE TABLE IF NOT EXISTS alert_ground_truth (
    alert_id          text PRIMARY KEY REFERENCES alerts (id) ON DELETE CASCADE,
    true_class        text NOT NULL,
    attack_type       text,
    campaign_id       text,
    stage             integer,
    indicator         text,
    indicator_verdict text,
    target_asset      text,
    run_id            text,
    rng_seed          bigint,
    generated_at      timestamptz DEFAULT now()
)
"""


def ensure_schema(dsn: str) -> None:
    """Idempotently ensure the ground-truth side-channel exists. Lets the
    generator run against an already-seeded volume that never re-ran init.
    (docker/initdb/operational/02-ground-truth.sql documents the same table.)"""
    execute(dsn, _GROUND_TRUTH_DDL)


def _insert(dsn: str, cfg: Config, alert_id: str, ts: str, p: PlannedAlert) -> None:
    """Insert one alert and its ground-truth row. Two statements, one logical
    unit; mcp_db.execute commits each. Ground truth goes ONLY to the side table."""
    execute(
        dsn,
        "INSERT INTO alerts (id, ts, severity, source_ip, dest_ip, rule_name, "
        "description) VALUES (%s,%s,%s,%s,%s,%s,%s)",
        (alert_id, ts, p.severity, p.source_ip, p.dest_ip, p.rule_name, p.description),
    )
    execute(
        dsn,
        "INSERT INTO alert_ground_truth (alert_id, true_class, campaign_id, stage, "
        "indicator, indicator_verdict, target_asset, run_id, rng_seed) "
        "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)",
        (alert_id, p.class_kind, p.campaign_id, p.stage, p.dest_ip,
         p.indicator_verdict, p.target_asset, cfg.run_id, cfg.seed),
    )


# ---------------------------------------------------------------------------
# Modes
# ---------------------------------------------------------------------------
def _manifest_row(alert_id: str | None, p: PlannedAlert) -> dict[str, Any]:
    """Operator-facing record of one generated alert (carries the true class —
    this is the operator's/evaluation's view, never shown to agents)."""
    row = asdict(p)
    row.pop("delay", None)
    if alert_id is not None:
        row = {"alert_id": alert_id, **row}
    return row


def cmd_plan(cfg: Config, preview: int) -> int:
    """Print the deterministic plan (no DB writes, no run_id, no timing) so two
    runs with the same seed produce byte-identical output — the repro check.
    Pools are read from the DB read-only, so the sequence matches `run` exactly."""
    pools = load_pools(cfg.dsn)
    n = 0
    for p in iter_plan(pools, cfg):
        # Omit the run-id-dependent alert id: content determinism is the claim.
        print(json.dumps(_manifest_row(None, p), sort_keys=True))
        n += 1
        if n >= preview:
            break
    return 0


def cmd_run(cfg: Config) -> int:
    """Insert alerts at the configured rate/mix until count or duration is hit.
    Emits a JSONL manifest of inserted alerts to stdout (operator view)."""
    ensure_schema(cfg.dsn)
    pools = load_pools(cfg.dsn)

    print(
        f"[workload] run_id={cfg.run_id} seed={cfg.seed} rate={cfg.rate}/s "
        f"arrival={cfg.arrival} mix={cfg.mix} "
        f"count={cfg.count} duration={cfg.duration} "
        f"campaign_size={cfg.campaign_size}",
        file=sys.stderr, flush=True,
    )

    emitted = 0
    started = time.monotonic()
    for p in iter_plan(pools, cfg):
        if cfg.count is not None and emitted >= cfg.count:
            break
        if cfg.duration is not None and (time.monotonic() - started) >= cfg.duration:
            break

        alert_id = f"{cfg.run_id}-{p.seq:06d}"
        ts = datetime.now(timezone.utc).isoformat()
        _insert(cfg.dsn, cfg, alert_id, ts, p)
        emitted += 1

        # Manifest line (stdout) — machine-readable input for the A2A driver.
        print(json.dumps(_manifest_row(alert_id, p)), flush=True)

        # Pace to the next alert, but do not overrun a duration bound.
        if cfg.duration is not None:
            remaining = cfg.duration - (time.monotonic() - started)
            if remaining <= 0:
                break
            time.sleep(min(p.delay, remaining))
        elif cfg.count is not None and emitted >= cfg.count:
            break  # last alert: no trailing sleep
        else:
            time.sleep(p.delay)

    print(
        f"[workload] done: inserted {emitted} alert(s) (run_id={cfg.run_id})",
        file=sys.stderr, flush=True,
    )
    return 0


def main(argv: list[str] | None = None) -> int:
    mode, cfg, preview = parse_config(argv if argv is not None else sys.argv[1:])
    if mode == "plan":
        return cmd_plan(cfg, preview)
    return cmd_run(cfg)


if __name__ == "__main__":
    raise SystemExit(main())
