"""stage_dbs.py — build the operational-DB seed from the SIEVE log dataset.

Each raw_data/SIEVE_*.csv row is ONE pre-labelled log event: (category, log).
Unlike CSE-CIC-IDS2018 (flows with no IPs, labels recovered by date+attack), here
the CATEGORY IS the ground truth and the `log` is a ready-made alert description.

What we build:
  • category -> (true_class, severity, rule_name)   [classify(), below]
  • a small CONTROLLED substrate the agents look up against, so the escalate/
    benign branch is driven by reasoning, NOT by a single trivial lookup:
      - CMDB (assets): N_ASSETS synthetic internal hosts. EVERY alert's dest is
        rewritten to one of them -> a CMDB hit is UNIVERSAL (asset context that
        modulates severity, never a benign/malicious tell).
      - IOC (iocs):   N_IOCS synthetic known-bad IPs (verdict 'malicious'). Only
        IOC_COVERAGE of ESCALATE alerts get their source from this pool; the rest
        get a novel IP, and benign alerts NEVER do. A hit confirms escalate; its
        absence proves nothing (the threat-intel tool gives unknown IPs a stable
        hash verdict anyway, so "not in the table" != "clean").
    The true_class always comes from the SIEVE category, never from the IP we plant.

Outputs (to --out, default raw_data/staged/):
    seed_iocs.sql  seed_assets.sql  seed_alerts.sql  seed_ground_truth.sql
    wl.jsonl                         # driven by scripts/run_workload.py
Also (re)writes docker/initdb/operational/01-init.sql (schema headers, single source).

Deterministic (SEED). Run:
    /opt/miniconda3/envs/masterarbeit/bin/python scripts/stage_dbs.py --inspect
    /opt/miniconda3/envs/masterarbeit/bin/python scripts/stage_dbs.py [--limit N] [--upload]
"""

from __future__ import annotations

import argparse
import collections
import glob
import json
import pathlib
import random
from dataclasses import dataclass
from datetime import datetime, timedelta

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
REPO = pathlib.Path(__file__).resolve().parents[1]
RAW_DIR = REPO / "raw_data"
OUT_DIR = REPO / "raw_data" / "staged"
SCHEMA_OUT = REPO / "docker" / "initdb" / "operational" / "01-init.sql"
BUCKET_PREFIX = "model-storage/db-seed"        # subfolder in the model bucket

SEED = 1337                # reproducibility
N_ASSETS = 300             # CMDB fleet size
N_IOCS = 60                # known-bad IP pool size
IOC_COVERAGE = 0.40        # fraction of escalate incidents whose source is a known IOC
BASE_TS = datetime(2025, 1, 1)   # synthetic alert timestamps (SIEVE's own are junk)

# AGGREGATION — the routing signal. A single SIEVE line ("one failed login") is
# genuinely low-signal, so triage (correctly) dismisses it and the escalate path
# never runs. We therefore collapse AGG_SIZE same-category attack events into ONE
# loud incident ("47 failed logins from X to Y"), which reliably escalates. This
# is a data-prep choice for PREDICTABLE ROUTING (so both protocol paths fire for
# the measurement), not an attempt at realistic analysis. Benign events stay as
# single lines (clearly benign) — the escalate/benign split is deliberately easy.
AGG_SIZE = 20              # attack events per aggregated incident

# The 4 escalate categories (see raw_data/analysis/categories.txt): category ->
# (severity, rule_name). Rule names reflect the aggregate (repeated/burst) nature.
# Every OTHER category is benign/low (normal ops + noise), emitted one line = one alert.
ESCALATE = {
    "ids-alert":             ("high",   "IDS Alert Burst"),
    "authentication-failed": ("high",   "Repeated Authentication Failures"),
    "network-filtered":      ("medium", "Repeated Firewall Denials"),
    "file-action-failure":   ("medium", "Repeated File Access Denials"),
}


def classify(category: str) -> tuple[str, str, str]:
    """(true_class, severity, rule_name) for a SIEVE category."""
    if category in ESCALATE:
        severity, rule = ESCALATE[category]
        return "escalate", severity, rule
    return "benign", "low", category.replace("-", " ").title()


# ---------------------------------------------------------------------------
# Row shapes (mirror the DB schema)
# ---------------------------------------------------------------------------
@dataclass
class Alert:
    id: str
    ts: str
    severity: str
    source_ip: str
    dest_ip: str
    rule_name: str
    description: str


@dataclass
class GroundTruth:
    alert_id: str
    true_class: str            # benign | escalate
    attack_type: str | None    # the SIEVE category; None for benign
    campaign_id: str | None    # groups alerts from the same known-bad source
    stage: int | None          # unused for SIEVE (no kill-chain staging)
    indicator: str | None      # source IP when it is a seeded IOC, else None
    indicator_verdict: str | None
    target_asset: str | None   # the CMDB asset the alert targets


# ---------------------------------------------------------------------------
# Synthetic substrate (CMDB + IOC pools)
# ---------------------------------------------------------------------------
_ROLES = ["db", "web", "srv", "email", "desktop", "laptop"]
_DEPARTMENTS = ["R&D", "Management", "IT", "Operations", "Finance", "Sales"]
_DOMAINS = ["corp.local", "internal.net", "acme.example"]
_OSES = ["Ubuntu 22.04", "Windows 10", "Windows Server 2019", "RHEL 9", "macOS 14"]
_CITIES = ["Berlin", "London", "Austin", "Toronto", "Singapore"]


def build_assets(rng: random.Random) -> list[dict]:
    """N_ASSETS internal hosts keyed by a unique 10.10.x.y IP (= asset_id, the key
    the CMDB tool and the alert dest_ip both use)."""
    assets = []
    for i in range(N_ASSETS):
        role = _ROLES[i % len(_ROLES)]
        critical = role in ("db", "srv", "web")
        assets.append({
            "asset_id": f"10.10.{i // 254}.{i % 254 + 1}",
            "hostname": f"{role}-{i:03d}.{rng.choice(_DOMAINS)}",
            "owner": f"user{rng.randint(1000, 9999)}",
            "owner_contact": f"user{rng.randint(1000, 9999)}@{rng.choice(_DOMAINS)}",
            "criticality": rng.choice(["critical", "high"]) if critical else rng.choice(["medium", "low"]),
            "location": rng.choice(_CITIES),
            "os": rng.choice(_OSES),
            "department": rng.choice(_DEPARTMENTS),
            "last_seen": (BASE_TS - timedelta(days=rng.randint(0, 30))).isoformat(),
        })
    return assets


def build_iocs(rng: random.Random) -> list[dict]:
    """N_IOCS unique public IPs, all verdict 'malicious' (known-bad infrastructure)."""
    iocs, seen = [], set()
    while len(iocs) < N_IOCS:
        ip = f"185.{rng.randint(1, 254)}.{rng.randint(0, 254)}.{rng.randint(1, 254)}"
        if ip in seen:
            continue
        seen.add(ip)
        iocs.append({"indicator": ip, "verdict": "malicious",
                     "confidence": round(rng.uniform(0.85, 0.99), 2),
                     "source": "synthetic-ti"})
    return iocs


def _novel_public_ip(rng: random.Random) -> str:
    """A random public IPv4 (skips private / reserved ranges)."""
    while True:
        a = rng.randint(1, 223)
        if a in (0, 10, 127):
            continue
        b, c, d = rng.randint(0, 255), rng.randint(0, 255), rng.randint(1, 254)
        if (a == 172 and 16 <= b <= 31) or (a == 192 and b == 168) or (a == 169 and b == 254):
            continue
        return f"{a}.{b}.{c}.{d}"


# ---------------------------------------------------------------------------
# Load + derive
# ---------------------------------------------------------------------------
def load_events(limit: int | None) -> list[tuple[str, str]]:
    """Read every raw_data/SIEVE_*.csv as (category, log) rows. With --limit, take
    a deterministic random sample (keeps category balance).

    The `log` field is UNQUOTED and itself contains commas, so we split on the
    FIRST comma only (the category is always a comma-free slug) — csv.reader would
    wrongly shred the log at every comma.
    """
    rows: list[tuple[str, str]] = []
    for f in sorted(glob.glob(str(RAW_DIR / "SIEVE_*.csv"))):
        with open(f, encoding="utf-8", errors="replace") as fh:
            next(fh, None)                           # header: category,log
            for line in fh:
                category, sep, log = line.rstrip("\n").partition(",")
                if sep and category.strip():
                    rows.append((category.strip(), log.strip()))
    if limit and limit < len(rows):
        rows = random.Random(SEED).sample(rows, limit)
    return rows


def derive(events: list[tuple[str, str]], assets: list[dict], iocs: list[dict],
           ) -> tuple[list[Alert], list[GroundTruth]]:
    """Build alerts + agent-invisible ground truth.

    BENIGN categories -> one alert per event (single line, clearly benign).
    ESCALATE categories -> AGG_SIZE events collapsed into ONE loud incident whose
    description states the volume, so triage reliably escalates and the enrichment
    chain runs. Every alert's dest is a CMDB asset (universal hit); ~IOC_COVERAGE of
    escalate incidents get a known-bad IOC source (downstream corroboration).
    """
    rng = random.Random(SEED + 1)
    alerts: list[Alert] = []
    gts: list[GroundTruth] = []
    n = 0  # running index -> alert id, timestamp, asset pick

    def _emit(severity, source_ip, dest_ip, rule, desc, gt_kwargs):
        nonlocal n
        aid = f"evt-{n:06d}"
        ts = (BASE_TS + timedelta(seconds=n)).isoformat()
        alerts.append(Alert(aid, ts, severity, source_ip, dest_ip, rule, desc))
        gts.append(GroundTruth(alert_id=aid, **gt_kwargs))
        n += 1

    # --- benign: one alert per event -----------------------------------------
    for category, log in events:
        if classify(category)[0] != "benign":
            continue
        _, severity, rule = classify(category)
        dest_ip = assets[n % len(assets)]["asset_id"]
        _emit(severity, _novel_public_ip(rng), dest_ip, rule, log,
              dict(true_class="benign", attack_type=None, campaign_id=None,
                   stage=None, indicator=None, indicator_verdict=None,
                   target_asset=dest_ip))

    # --- escalate: aggregate AGG_SIZE same-category events into one incident ---
    by_cat: dict[str, list[str]] = collections.defaultdict(list)
    for category, log in events:
        if classify(category)[0] == "escalate":
            by_cat[category].append(log)

    for category, logs in by_cat.items():
        severity, rule = ESCALATE[category]
        for i in range(0, len(logs), AGG_SIZE):
            bucket = logs[i:i + AGG_SIZE]
            dest_ip = assets[n % len(assets)]["asset_id"]
            if rng.random() < IOC_COVERAGE:
                source_ip = rng.choice(iocs)["indicator"]
                indicator, verdict, campaign = source_ip, "malicious", f"ti:{source_ip}"
            else:
                source_ip = _novel_public_ip(rng)
                indicator, verdict, campaign = None, None, None
            desc = (f"{len(bucket)} {category} events from {source_ip} to {dest_ip} "
                    f"within a short window (repeated pattern). "
                    f"Sample event: {bucket[0][:160]}")
            _emit(severity, source_ip, dest_ip, rule, desc,
                  dict(true_class="escalate", attack_type=category,
                       campaign_id=campaign, stage=None, indicator=indicator,
                       indicator_verdict=verdict, target_asset=dest_ip))
    return alerts, gts


# ---------------------------------------------------------------------------
# Emit SQL / manifest
# ---------------------------------------------------------------------------
SCHEMA_SQL = """\
-- Operational schema (HEADERS ONLY). Generated by scripts/stage_dbs.py.
-- Bulk data is loaded from S3 by deployment/db-seed-job.yaml (too big for a CM).
-- Columns MUST match what services/mcp-* SELECT.
CREATE TABLE alerts (
    id text PRIMARY KEY, ts timestamptz NOT NULL, severity text,
    source_ip text, dest_ip text, rule_name text, description text);
CREATE TABLE assets (
    asset_id text PRIMARY KEY, hostname text, owner text, owner_contact text,
    criticality text, location text, os text, department text, last_seen timestamptz);
CREATE TABLE users (
    user_id text PRIMARY KEY, display_name text, department text, manager text,
    email text, privileged boolean, mfa_enrolled boolean);
CREATE TABLE iocs (
    indicator text PRIMARY KEY, verdict text, confidence double precision, source text);
CREATE TABLE runbook (
    id serial PRIMARY KEY, title text, steps jsonb, attack_ref text,
    source text, keywords text);
CREATE TABLE incidents (
    incident_id text PRIMARY KEY, status text, title text, description text,
    severity text, assignee text, created_at timestamptz, updated_at timestamptz, note text);
"""


def write_schema_sql() -> None:
    SCHEMA_OUT.write_text(SCHEMA_SQL)
    print(f"wrote {SCHEMA_OUT}")


def _copy_val(v) -> str:
    """One value in COPY text format: \\N for NULL, escape tab/newline/backslash."""
    if v is None:
        return r"\N"
    return (str(v).replace("\\", "\\\\").replace("\t", "\\t")
            .replace("\n", "\\n").replace("\r", "\\r"))


def write_seed_sql(rows: list, table: str, columns: list[str], path: pathlib.Path) -> None:
    """Emit a COPY-format .sql (fast for large tables). `rows` are dicts or dataclasses."""
    def getcol(row, c):
        return getattr(row, c) if hasattr(row, c) else row[c]

    with path.open("w") as fh:
        fh.write(f"COPY {table} ({', '.join(columns)}) FROM stdin;\n")
        for row in rows:
            fh.write("\t".join(_copy_val(getcol(row, c)) for c in columns) + "\n")
        fh.write("\\.\n")
    print(f"wrote {path}  ({len(rows)} rows)")


def write_manifest(alerts: list[Alert], gts: list[GroundTruth], path: pathlib.Path) -> None:
    """One JSONL line per alert for scripts/run_workload.py (+ the true label for
    the eval join). Drive a subset with run_workload.py --limit."""
    gt = {g.alert_id: g for g in gts}
    with path.open("w") as fh:
        for a in alerts:
            g = gt.get(a.id)
            fh.write(json.dumps({
                "alert_id": a.id, "source_ip": a.source_ip, "dest_ip": a.dest_ip,
                "rule_name": a.rule_name, "description": a.description,
                "true_class": g.true_class if g else None,
                "attack_type": g.attack_type if g else None,
            }) + "\n")
    print(f"wrote {path}  ({len(alerts)} lines)")


PART_SIZE = 16 * 1024 * 1024      # 16 MB multipart chunk


def _retry(fn, what: str, tries: int = 5):
    """Call fn(), retrying transient transport errors with exponential backoff.
    Hyperstack intermittently drops a connection mid-upload (e.g. HTTP 499
    'client closed request', or a reset), which botocore does not auto-retry."""
    import time
    for attempt in range(1, tries + 1):
        try:
            return fn()
        except Exception as e:  # noqa: BLE001 — retry any transient transport error
            if attempt == tries:
                raise
            wait = 2 ** attempt
            print(f"  {what}: attempt {attempt} failed ({e.__class__.__name__}); "
                  f"retrying in {wait}s", flush=True)
            time.sleep(wait)


def _put_object(s3, bucket: str, key: str, path: pathlib.Path) -> None:
    """Upload one file to Hyperstack object storage, working around three quirks:
      • it rejects boto3's transfer-manager (streamed aws-chunked, no
        Content-Length) — so we pass each body as BYTES with an explicit length;
      • a single ~140 MB PUT gets the connection dropped — so anything over one
        part is sent as a manual multipart upload (16 MB parts);
      • it intermittently drops a part mid-flight (HTTP 499) — so every S3 call
        is retried with backoff (`_retry`).
    """
    size = path.stat().st_size
    if size <= PART_SIZE:
        data = path.read_bytes()
        _retry(lambda: s3.put_object(Bucket=bucket, Key=key,
                                     Body=data, ContentLength=len(data)),
               f"put {key}")
        return
    upload_id = _retry(
        lambda: s3.create_multipart_upload(Bucket=bucket, Key=key),
        f"create mpu {key}")["UploadId"]
    parts = []
    try:
        with path.open("rb") as fh:
            n = 1
            while (chunk := fh.read(PART_SIZE)):
                r = _retry(
                    lambda c=chunk, pn=n: s3.upload_part(
                        Bucket=bucket, Key=key, UploadId=upload_id,
                        PartNumber=pn, Body=c, ContentLength=len(c)),
                    f"part {n} of {key}")
                parts.append({"ETag": r["ETag"], "PartNumber": n})
                n += 1
        _retry(lambda: s3.complete_multipart_upload(
            Bucket=bucket, Key=key, UploadId=upload_id,
            MultipartUpload={"Parts": parts}), f"complete mpu {key}")
    except Exception:
        s3.abort_multipart_upload(Bucket=bucket, Key=key, UploadId=upload_id)
        raise


def upload_seed(files: list[pathlib.Path]) -> None:
    """Upload seed_*.sql to s3://model-storage/db-seed/ via boto3 (path-style).
    Creds from AWS_ACCESS_KEY_ID/SECRET (or S3_KEY/S3_SECRET); endpoint defaults
    to Hyperstack CANADA-1."""
    import os
    import boto3
    from botocore.config import Config

    endpoint = os.environ.get("AWS_ENDPOINT_URL", "https://ca1.obj.nexgencloud.io")
    key = os.environ.get("AWS_ACCESS_KEY_ID") or os.environ["S3_KEY"]
    secret = os.environ.get("AWS_SECRET_ACCESS_KEY") or os.environ["S3_SECRET"]
    # boto3/botocore >= 1.36 send uploads as aws-chunked with a trailing CRC
    # checksum by DEFAULT (request_checksum_calculation="when_supported"), which
    # drops the Content-Length header. Hyperstack's S3 impl doesn't support that
    # and returns MissingContentLength. "when_required" restores a plain
    # Content-Length body. (Same knob the AWS CLI needs via env var.)
    s3 = boto3.client("s3", endpoint_url=endpoint, aws_access_key_id=key,
                      aws_secret_access_key=secret,
                      config=Config(s3={"addressing_style": "path"},
                                    connect_timeout=30, read_timeout=300,
                                    retries={"max_attempts": 3},
                                    request_checksum_calculation="when_required",
                                    response_checksum_validation="when_required"))
    bucket, prefix = BUCKET_PREFIX.split("/", 1)
    for f in files:
        _put_object(s3, bucket, f"{prefix}/{f.name}", f)
        print(f"uploaded s3://{bucket}/{prefix}/{f.name}  ({f.stat().st_size/1e6:.1f} MB)")


# ---------------------------------------------------------------------------
def inspect() -> None:
    """Print category counts + the benign/escalate split, then exit."""
    import collections
    counts = collections.Counter(cat for cat, _ in load_events(None))
    print(f"{'category':30} {'count':>8}  class")
    for cat, n in counts.most_common():
        tc, _, _ = classify(cat)
        print(f"{cat:30} {n:>8}  {tc}")
    esc = sum(n for c, n in counts.items() if classify(c)[0] == "escalate")
    print(f"\ntotal {sum(counts.values())}  escalate {esc}  benign {sum(counts.values()) - esc}")


def main() -> int:
    ap = argparse.ArgumentParser(description="Stage the operational DB seed from raw_data/SIEVE_*.csv")
    ap.add_argument("--inspect", action="store_true", help="print category counts, then exit")
    ap.add_argument("--limit", type=int, help="stage only a deterministic sample of N alerts")
    ap.add_argument("--out", type=pathlib.Path, default=OUT_DIR)
    ap.add_argument("--upload", action="store_true", help="upload the seed to the S3 bucket subfolder")
    args = ap.parse_args()

    if args.inspect:
        inspect()
        return 0

    args.out.mkdir(parents=True, exist_ok=True)
    assets = build_assets(random.Random(SEED))
    iocs = build_iocs(random.Random(SEED))
    events = load_events(args.limit)
    alerts, gts = derive(events, assets, iocs)

    write_schema_sql()
    write_seed_sql(iocs,   "iocs",   ["indicator", "verdict", "confidence", "source"],
                   args.out / "seed_iocs.sql")
    write_seed_sql(assets, "assets", ["asset_id", "hostname", "owner", "owner_contact",
                   "criticality", "location", "os", "department", "last_seen"],
                   args.out / "seed_assets.sql")
    write_seed_sql(alerts, "alerts", ["id", "ts", "severity", "source_ip", "dest_ip",
                   "rule_name", "description"], args.out / "seed_alerts.sql")
    write_seed_sql(gts, "alert_ground_truth", ["alert_id", "true_class", "attack_type",
                   "campaign_id", "stage", "indicator", "indicator_verdict", "target_asset"],
                   args.out / "seed_ground_truth.sql")
    write_manifest(alerts, gts, args.out / "wl.jsonl")

    if args.upload:
        upload_seed(sorted(args.out.glob("seed_*.sql")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
