"""stage_dbs.py — build the operational-DB seed from CSE-CIC-IDS2018 flow CSVs.

PIPELINE:
    raw_data/*.csv  (one labelled network flow per row; NO IP columns)
        │  load + normalize (Timestamp, Label, a few flow features)
        ▼
    per flow → recover attacker/victim IPs from ATTACK_INFRA by (date, Label)
        ▼
    derive four row-sets → iocs (attackers), assets (victims/CMDB),
                           alerts, alert_ground_truth (agent-invisible labels)
        ▼
    write   docker/initdb/operational/01-init.sql   (schema headers only)
            <out>/seed_iocs.sql  seed_assets.sql  seed_alerts.sql  seed_ground_truth.sql
        ▼
    upload  s3://model-storage/db-seed/…  →  loaded by deployment/db-seed-job.yaml

WHY IPs COME FROM A TABLE, NOT COLUMNS: the 2018 flow CSVs have no Source/Dest IP.
The docs (Table 2 + schedule, https://www.unb.ca/cic/datasets/ids-2018.html) give
the attacker/victim IPs per attack day. Each host has BOTH an internal 172.31.x and
a public "valid" 18.x address; we keep both and seed both into CMDB/IOC so a lookup
resolves whichever form an alert carries.

SCOPE NOW: operational DB only. `users` stub; audit DB empty (runtime-filled).
OUT OF SCOPE (next step): Faker enrichment — see enrich_with_faker() at the bottom.

Run:  /opt/miniconda3/envs/masterarbeit/bin/python scripts/stage_dbs.py --inspect
"""

from __future__ import annotations

import argparse
import glob
import pathlib

import pandas as pd
from dataclasses import dataclass

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
REPO = pathlib.Path(__file__).resolve().parents[1]
RAW_DIR = REPO / "raw_data"
OUT_DIR = REPO / "raw_data" / "staged"                     # generated seed (gitignore)
SCHEMA_OUT = REPO / "docker" / "initdb" / "operational" / "01-init.sql"
BUCKET_PREFIX = "model-storage/db-seed"                      # subfolder in the model bucket

# Which IP form the ALERT rows use for source_ip/dest_ip. Both forms are seeded
# into CMDB/IOC regardless, so lookups resolve either way — this only picks what
# the alert text/flow shows. 'internal' | 'valid'.
ALERT_IP_FORM = "internal"


def host(internal: str | None = None, valid: str | None = None) -> dict:
    """A host with its internal (172.31.x) and/or public 'valid' (18.x) IP."""
    return {"internal": internal, "valid": valid}


# Columns we actually use (the CSV has ~80; we enrich with a handful). No IPs here.
COL = {
    "timestamp": "Timestamp",       # '14/02/2018 08:31:01' — parse dayfirst=True
    "label": "Label",               # 'Benign' or an attack name (LABEL_MAP keys)
    "dst_port": "Dst Port",
    "protocol": "Protocol",         # 6=TCP, 17=UDP, 0=other
    "duration": "Flow Duration",    # microseconds
    "fwd_pkts": "Tot Fwd Pkts",
    "fwd_bytes": "TotLen Fwd Pkts",
    "bytes_s": "Flow Byts/s",
}

# Label → disposition (benign|escalate), alert severity, readable rule name.
# Keys MUST equal the dataset's exact Label strings AND ATTACK_INFRA keys.
# NB: verify with --inspect — releases differ ('Benign'/'BENIGN', the
# 'Infilteration' misspelling, 'Brute Force -Web' spacing).
LABEL_MAP: dict[str, dict] = {
    "Benign":                   {"true_class": "benign",   "severity": "low",      "rule": "Benign Network Flow"},
    "FTP-BruteForce":           {"true_class": "escalate", "severity": "high",     "rule": "FTP Brute-Force"},
    "SSH-Bruteforce":           {"true_class": "escalate", "severity": "high",     "rule": "SSH Brute-Force"},
    "DoS attacks-GoldenEye":    {"true_class": "escalate", "severity": "high",     "rule": "DoS (GoldenEye)"},
    "DoS attacks-Slowloris":    {"true_class": "escalate", "severity": "high",     "rule": "DoS (Slowloris)"},
    "DoS attacks-SlowHTTPTest": {"true_class": "escalate", "severity": "high",     "rule": "DoS (SlowHTTPTest)"},
    "DoS attacks-Hulk":         {"true_class": "escalate", "severity": "high",     "rule": "DoS (Hulk)"},
    "DDoS attacks-LOIC-HTTP":   {"true_class": "escalate", "severity": "critical", "rule": "DDoS (LOIC-HTTP)"},
    "DDOS attack-LOIC-UDP":     {"true_class": "escalate", "severity": "critical", "rule": "DDoS (LOIC-UDP)"},
    "DDOS attack-HOIC":         {"true_class": "escalate", "severity": "critical", "rule": "DDoS (HOIC)"},
    "Brute Force -Web":         {"true_class": "escalate", "severity": "high",     "rule": "Web Brute-Force"},
    "Brute Force -XSS":         {"true_class": "escalate", "severity": "high",     "rule": "Web XSS"},
    "SQL Injection":            {"true_class": "escalate", "severity": "high",     "rule": "SQL Injection"},
    "Infilteration":            {"true_class": "escalate", "severity": "critical", "rule": "Host Infiltration"},
    "Bot":                      {"true_class": "escalate", "severity": "high",     "rule": "Botnet Activity"},
}

# Attack infrastructure (docs Table 2 + schedule). Each attacker/victim is a
# host() with both IP forms. `victims_by_date` handles attacks that ran on
# several days against different victims. TODO: fill the 10-IP DDoS/Bot lists.
ATTACK_INFRA: dict[str, dict] = {
    "FTP-BruteForce":           {"attackers": [host(internal="172.31.70.4")],
                                 "victims":   [host("172.31.69.25", "18.217.21.148")]},
    "SSH-Bruteforce":           {"attackers": [host(internal="172.31.70.6")],
                                 "victims":   [host("172.31.69.25", "18.217.21.148")]},
    "DoS attacks-GoldenEye":    {"attackers": [host(internal="172.31.70.46")],
                                 "victims":   [host("172.31.69.25", "18.217.21.148")]},
    "DoS attacks-Slowloris":    {"attackers": [host(internal="172.31.70.8")],
                                 "victims":   [host("172.31.69.25", "18.217.21.148")]},
    "DoS attacks-SlowHTTPTest": {"attackers": [host(internal="172.31.70.23")],
                                 "victims":   [host("172.31.69.25", "18.217.21.148")]},
    "DoS attacks-Hulk":         {"attackers": [host(internal="172.31.70.16")],
                                 "victims":   [host("172.31.69.25", "18.217.21.148")]},
    "DDoS attacks-LOIC-HTTP":   {"attackers": [host(internal="TODO")],  # 10 IPs (Table 2)
                                 "victims":   [host("172.31.69.25", "18.217.21.148")]},
    "DDOS attack-LOIC-UDP":     {"attackers": [host(internal="TODO")],  # 10 IPs
                                 "victims_by_date": {"2018-02-20": [host("172.31.69.25", "18.217.21.148")],
                                                     "2018-02-21": [host("172.31.69.28", "18.218.83.150")]}},
    "DDOS attack-HOIC":         {"attackers": [host(internal="TODO")],  # 10 IPs
                                 "victims":   [host("172.31.69.28", "18.218.83.150")]},
    "Brute Force -Web":         {"attackers": [host(valid="18.218.115.60")],
                                 "victims":   [host("172.31.69.28", "18.218.83.150")]},
    "Brute Force -XSS":         {"attackers": [host(valid="18.218.115.60")],
                                 "victims":   [host("172.31.69.28", "18.218.83.150")]},
    "SQL Injection":            {"attackers": [host(valid="18.218.115.60")],
                                 "victims":   [host("172.31.69.28", "18.218.83.150")]},
    "Infilteration":            {"attackers": [host(valid="13.58.225.34")],
                                 "victims_by_date": {"2018-02-28": [host("172.31.69.24", "18.221.148.137")],
                                                     "2018-03-01": [host("172.31.69.13", "18.216.254.154")]}},
    "Bot":                      {"attackers": [host(valid="18.219.211.138")],
                                 "victims":   [host(internal="TODO")]},  # 10 victim IPs
}

# Internal victim pool for synthesizing BENIGN flow endpoints (benign flows also
# have no IPs). TODO: extend with the other 172.31.69.x hosts from Table 2.
INTERNAL_POOL = ["172.31.69.25", "172.31.69.28", "172.31.69.24", "172.31.69.13"]

PROTO = {6: "TCP", 17: "UDP", 0: "IP"}


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
    attack_type: str | None    # raw Label; None for benign
    campaign_id: str | None    # one id per attack instance (date+label window)
    stage: int | None
    indicator: str | None      # attacker IP → malicious IOC
    indicator_verdict: str | None
    target_asset: str | None   # victim IP → CMDB asset


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _pick(hosts: list[dict], i: int) -> dict:
    """Deterministically pick one host from a list (stable per row index)."""
    return hosts[i % len(hosts)]


def resolve_endpoints(label: str, date: str, i: int) -> tuple[dict | None, dict]:
    """(attacker_host, victim_host) for an attack flow, from ATTACK_INFRA.

    `date` is 'YYYY-MM-DD' (disambiguates victims_by_date). `i` is the row index,
    used to spread multi-IP attacks deterministically. Attack labels only.
    """
    infra = ATTACK_INFRA[label]
    victims = infra["victims_by_date"][date] if "victims_by_date" in infra else infra["victims"]
    attacker = _pick(infra["attackers"], i)
    victim = _pick(victims, i)
    return attacker, victim


def ip_of(h: dict) -> str:
    """The alert-facing IP for a host, honoring ALERT_IP_FORM, falling back to
    whichever form is present."""
    return h.get(ALERT_IP_FORM) or h.get("valid") or h.get("internal")


def all_ips(h: dict) -> list[str]:
    """Both IP forms of a host that are real (drops None / 'TODO')."""
    return [v for v in (h.get("internal"), h.get("valid")) if v and v != "TODO"]


# ---------------------------------------------------------------------------
# Step 1 — load
# ---------------------------------------------------------------------------
def load_events() -> pd.DataFrame:
    """Load all raw_data/*.csv, keep only COL columns, normalize + parse dates."""
    keep = set(COL.values())
    frames = []
    for f in sorted(glob.glob(str(RAW_DIR / "*.csv"))):
        # Some rows repeat the header / carry junk — coerce and drop later.
        df = pd.read_csv(f, dtype=str)
        df.columns = [c.strip() for c in df.columns]
        df = df[[c for c in df.columns if c in keep]].copy()
        frames.append(df)
    events = pd.concat(frames, ignore_index=True)
    ts = pd.to_datetime(events[COL["timestamp"]], dayfirst=True, errors="coerce")
    # Drop unparseable rows AND stray non-2018 timestamps (a few malformed rows in
    # the CIC CSVs parse to 1970). CSE-CIC-IDS2018 traffic is Feb–Mar 2018.
    mask = ts.notna() & (ts.dt.year == 2018)
    events = events[mask].copy()
    events["_ts"] = ts[mask].values
    events["_date"] = ts[mask].dt.strftime("%Y-%m-%d").values

    return events


# ---------------------------------------------------------------------------
# Step 2 — derive row-sets
# ---------------------------------------------------------------------------
def derive_iocs(events: pd.DataFrame) -> list[dict]:
    """Every attacker IP (both forms) → a malicious IOC row."""
    seen, rows = set(), []
    for label, infra in ATTACK_INFRA.items():
        for h in infra["attackers"]:
            for ip in all_ips(h):
                if ip in seen:
                    continue
                seen.add(ip)
                rows.append({"indicator": ip, "verdict": "malicious",
                             "confidence": 0.95, "source": "cse-cic-ids2018"})
    return rows


def derive_assets(events: pd.DataFrame) -> list[dict]:
    """Every victim IP (both forms) → a CMDB asset row. hostname/owner/etc. are
    placeholders until the Faker step."""
    seen, rows = set(), []
    victim_lists = []
    for infra in ATTACK_INFRA.values():
        victim_lists += infra.get("victims", [])
        for vs in infra.get("victims_by_date", {}).values():
            victim_lists += vs
    for h in victim_lists + [host(internal=ip) for ip in INTERNAL_POOL]:
        for ip in all_ips(h):
            if ip in seen:
                continue
            seen.add(ip)
            rows.append({"asset_id": ip, "hostname": None, "owner": None,
                         "owner_contact": None, "criticality": "unknown",
                         "location": None, "os": None, "department": None,
                         "last_seen": None})
    return rows


WINDOW = "30s"        # SIEM aggregation bucket: 30s of the same label → one alert


def _slug(s: str) -> str:
    return "".join(c if c.isalnum() else "-" for c in s).strip("-").lower()


def _bucket_description(g: pd.DataFrame, proto: str) -> str:
    """Behavioral, NON-label-leaking summary of a (window, label) group of flows."""
    flows = len(g)
    ports = g[COL["dst_port"]].nunique()
    pkts = int(pd.to_numeric(g[COL["fwd_pkts"]], errors="coerce").sum())
    byts = int(pd.to_numeric(g[COL["fwd_bytes"]], errors="coerce").sum())
    return (f"{flows} {proto} flow(s) to {ports} distinct port(s) in 30s: "
            f"{pkts} fwd packets, {byts} bytes.")


def derive_alerts(events: pd.DataFrame) -> tuple[list[Alert], list[GroundTruth]]:
    """Aggregate flows → alerts by (30-second window, Label).

    Every 30s of the SAME label collapses into ONE alert (benign or one attack
    type). Attack alerts get attacker/victim from ATTACK_INFRA; benign get a
    synthesized internal pair. `campaign_id = date:label` links the many 30s
    alerts of one attack instance — the correlation ground truth — WITHOUT
    collapsing them into a single alert. Vectorized via groupby (fast).
    """
    unmapped = set(events[COL["label"]].unique()) - set(LABEL_MAP)
    if unmapped:
        raise SystemExit(f"labels missing from LABEL_MAP: {sorted(unmapped)}")

    ev = events.copy()
    ev["_win"] = pd.to_datetime(ev["_ts"]).dt.floor(WINDOW)
    ev["_proto"] = pd.to_numeric(ev[COL["protocol"]], errors="coerce")

    alerts: list[Alert] = []
    gts: list[GroundTruth] = []
    for (win, label), g in ev.groupby(["_win", COL["label"]], sort=True):
        cfg = LABEL_MAP[label]
        date = win.strftime("%Y-%m-%d")
        proto_num = int(g["_proto"].mode().iloc[0]) if g["_proto"].notna().any() else 0
        proto = PROTO.get(proto_num, "IP")
        aid = f"evt-{win.strftime('%Y%m%dT%H%M%S')}-{_slug(label)}"
        ts = win.isoformat()
        desc = _bucket_description(g, proto)

        if cfg["true_class"] == "benign":
            # Benign flows have no IPs either → synthesize a stable internal pair.
            h = abs(hash(aid))
            src, dst = INTERNAL_POOL[h % len(INTERNAL_POOL)], INTERNAL_POOL[(h + 1) % len(INTERNAL_POOL)]
            alerts.append(Alert(aid, ts, cfg["severity"], src, dst, cfg["rule"], desc))
            gts.append(GroundTruth(aid, "benign", None, None, None, None, None, dst))
        else:
            attacker, victim = resolve_endpoints(label, date, abs(hash(aid)))
            src, dst = ip_of(attacker), ip_of(victim)
            alerts.append(Alert(aid, ts, cfg["severity"], src, dst, cfg["rule"], desc))
            gts.append(GroundTruth(aid, "escalate", label, f"{date}:{label}", None,
                                   src, "malicious", dst))
    return alerts, gts


# ---------------------------------------------------------------------------
# Step 3 — emit SQL
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
    """Write the schema-only 01-init.sql (no bulk INSERTs anymore)."""
    SCHEMA_OUT.write_text(SCHEMA_SQL)
    print(f"wrote {SCHEMA_OUT}")
    # NOTE: alert_ground_truth lives in 02-ground-truth.sql — add an
    # `attack_type text` column there so seed_ground_truth.sql loads.


def _copy_val(v) -> str:
    """One value in COPY text format: \\N for NULL, escape tab/newline/backslash."""
    if v is None or (isinstance(v, float) and pd.isna(v)):
        return r"\N"
    return (str(v).replace("\\", "\\\\").replace("\t", "\\t")
            .replace("\n", "\\n").replace("\r", "\\r"))


def write_seed_sql(rows: list, table: str, columns: list[str], path: pathlib.Path) -> None:
    """Emit a COPY-format .sql (fast for large tables). `rows` are dicts or
    dataclass instances; `columns` selects + orders the fields."""
    def getcol(row, c):
        return getattr(row, c) if hasattr(row, c) else row[c]

    with path.open("w") as fh:
        fh.write(f"COPY {table} ({', '.join(columns)}) FROM stdin;\n")
        for row in rows:
            fh.write("\t".join(_copy_val(getcol(row, c)) for c in columns) + "\n")
        fh.write("\\.\n")
    print(f"wrote {path}  ({len(rows)} rows)")


# ---------------------------------------------------------------------------
# Step 4 — upload
# ---------------------------------------------------------------------------
def upload_seed(files: list[pathlib.Path]) -> None:
    """Upload seed_*.sql to s3://model-storage/db-seed/ via boto3 (path-style).

    Creds from AWS_ACCESS_KEY_ID/SECRET or the runbook's S3_KEY/S3_SECRET;
    endpoint defaults to Hyperstack CANADA-1.
    """
    import os
    import boto3
    from botocore.config import Config

    endpoint = os.environ.get("AWS_ENDPOINT_URL", "https://ca1.obj.nexgencloud.io")
    key = os.environ.get("AWS_ACCESS_KEY_ID") or os.environ["S3_KEY"]
    secret = os.environ.get("AWS_SECRET_ACCESS_KEY") or os.environ["S3_SECRET"]
    s3 = boto3.client(
        "s3", endpoint_url=endpoint, aws_access_key_id=key, aws_secret_access_key=secret,
        config=Config(s3={"addressing_style": "path"}),   # Hyperstack/MinIO-style
    )
    bucket, prefix = BUCKET_PREFIX.split("/", 1)           # 'model-storage', 'db-seed'
    for f in files:
        dest = f"{prefix}/{f.name}"
        s3.upload_file(str(f), bucket, dest)
        print(f"uploaded s3://{bucket}/{dest}")


# ---------------------------------------------------------------------------
# NEXT STEP — Faker enrichment (OUTLINE; wire into main() before write_seed_sql)
# ---------------------------------------------------------------------------
# Goal: make CMDB/IOC lookups realistic in two ways —
#   (A) fill the empty business fields on the REAL victim assets, and
#   (B) PAD both tables with hosts/indicators that appear in NO event (background
#       noise), so "present in the table" is not a giveaway.
# All of it is DETERMINISTIC (seed Faker + random) so a run reproduces.
#
# The 5 victim departments from the docs (business unit / department source):
FAKER_DEPARTMENTS = ["R&D", "Management", "Technician", "Secretary/Operations", "IT"]
#
# SCHEMA NOTE: `assets` currently has no department/business_unit column. Either
# encode department in `owner`/`location`, or add `department text` (and
# `business_unit text`) to assets in SCHEMA_SQL — decide before enriching.


def enrich_assets(assets: list[dict], seed: int = 1337) -> list[dict]:
    """(A) Fill hostname/owner/owner_contact/criticality/location/os (+department)
    on the real victim assets (they come out of derive_assets with None fields).

    OUTLINE:
      • fake = Faker(); fake.seed_instance(seed); rng = random.Random(seed)
      • for each asset: pick a department (rng.choice(FAKER_DEPARTMENTS)); set
        hostname=fake.hostname() or f"{dept-slug}-{fake.word()}-{n}"; owner=
        fake.name(); owner_contact=fake.company_email(); os per the docs (Win 8.1/10
        for depts, Ubuntu for IT, Win Server for the server hosts); criticality by
        role (servers 'critical', IT 'high', else 'medium'); location=fake.city().
      • keep asset_id (the IP) unchanged — it's the real key.
    TODO: implement.
    """
    raise NotImplementedError


def pad_cmdb(assets: list[dict], n: int, seed: int = 1337) -> list[dict]:
    """(B) Add `n` fake internal hosts that appear in NO event — CMDB background.

    OUTLINE: generate random 172.31.69.x IPs NOT already used, each with a full
    synthetic profile (same fields as enrich_assets). Return assets + the padding.
    NOTE: these make an asset lookup on a benign internal IP resolve to a normal
    host, so the agent must actually check rather than infer from presence.
    TODO: implement.
    """
    raise NotImplementedError


def pad_iocs(iocs: list[dict], n: int, seed: int = 1337) -> list[dict]:
    """(B) Add `n` fake indicators with a MIX of verdicts — threat-intel background.

    OUTLINE: generate random public IPs / domains not already present; assign
    verdicts on a distribution (e.g. 20% malicious, 20% suspicious, 60% clean),
    confidence per verdict, source='synthetic-ti'. The CLEAN ones matter most:
    they let benign alerts' destinations resolve to 'clean' so classification
    requires a real lookup, not "in the IOC table = bad".
    TODO: implement.
    """
    raise NotImplementedError


def enrich_with_faker(iocs: list[dict], assets: list[dict],
                      pad_assets_n: int = 400, pad_iocs_n: int = 200,
                      seed: int = 1337) -> tuple[list[dict], list[dict]]:
    """Compose the two steps. Call from main() between derive_* and write_seed_sql:
        assets = enrich_assets(assets, seed)
        assets = pad_cmdb(assets, pad_assets_n, seed)
        iocs   = pad_iocs(iocs, pad_iocs_n, seed)
    (~420 machines + 30 servers in the docs → pad_assets_n≈400 is realistic.)
    TODO: implement once the three helpers above are done.
    """
    raise NotImplementedError


# ---------------------------------------------------------------------------
# Driving manifest for scripts/run_workload.py — replaces the synthetic
# workload-generator: we drive the pipeline over the REAL staged alerts.
# ---------------------------------------------------------------------------
def write_manifest(alerts, gts, path: pathlib.Path) -> None:
    """One JSONL line per alert with the fields run_workload.py needs + the
    ground-truth label for the eval join. Drive a subset with its --limit."""
    import json
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


# ---------------------------------------------------------------------------
def main() -> int:
    ap = argparse.ArgumentParser(description="Stage the operational DB seed from raw_data/*.csv")
    ap.add_argument("--inspect", action="store_true", help="print columns + label counts, then exit")
    ap.add_argument("--out", type=pathlib.Path, default=OUT_DIR)
    ap.add_argument("--upload", action="store_true", help="upload seed to the S3 bucket subfolder")
    args = ap.parse_args()

    if args.inspect:
        inspect_labels()
        return 0

    args.out.mkdir(parents=True, exist_ok=True)
    events = load_events()
    iocs = derive_iocs(events)
    assets = derive_assets(events)
    alerts, gts = derive_alerts(events)      # already aggregated to 30s×label
    # iocs, assets = enrich_with_faker(iocs, assets)   # enable once implemented

    write_schema_sql()
    write_seed_sql(iocs,   "iocs",   ["indicator", "verdict", "confidence", "source"], args.out / "seed_iocs.sql")
    write_seed_sql(assets, "assets", ["asset_id", "hostname", "owner", "owner_contact",
                                      "criticality", "location", "os", "department", "last_seen"], args.out / "seed_assets.sql")
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
