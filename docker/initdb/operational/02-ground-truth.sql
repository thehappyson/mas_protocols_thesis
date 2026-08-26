-- Ground-truth side-channel for the Workload Generator (operational Postgres).
-- Runs once on first container init, AFTER 01-init.sql (lexical order). The
-- Workload Generator ALSO creates this table idempotently at startup
-- (CREATE TABLE IF NOT EXISTS), so it works against an already-seeded volume
-- that never re-ran init — this file documents the table as part of the schema.
--
-- METHODOLOGICAL CORE — AGENT-INVISIBLE GROUND TRUTH.
-- Each generated alert has a constructed TRUE CLASS recorded here, keyed by
-- alert id. This is the evaluation's ground truth; the evaluation (later) joins
-- agent outcomes to it by alert id. Agents must NOT be able to read the true
-- class. Invisibility is STRUCTURAL, not a promise:
--   * No MCP tool queries this table. The tools read only their own tables —
--     SIEM reads `alerts` (a FIXED column allowlist that has no true_class),
--     CMDB reads `assets`/`users`, threat-intel reads `iocs`, runbook reads
--     `runbook`. None of them SELECT from alert_ground_truth.
--   * It is a SEPARATE table from `alerts`, so it cannot leak through the SIEM
--     tool's next_alerts even accidentally. (The `alerts.severity` column is the
--     precedent: it exists but the SIEM seam never selects it.)
--
-- The REVOKE below is dev-grade INTENT (mirroring the audit DB's append-only
-- rules): in a real deployment the tools would connect as a role without SELECT
-- on this table. Here the tools connect as `soc`, a dev superuser that bypasses
-- grants, so the REAL guarantee is the structural one above (no tool issues a
-- query against this table), which the verification demonstrates directly.

CREATE TABLE IF NOT EXISTS alert_ground_truth (
    alert_id         text PRIMARY KEY REFERENCES alerts (id) ON DELETE CASCADE,
    true_class       text NOT NULL,      -- 'benign' | 'escalate' | 'campaign'
    campaign_id      text,               -- set when true_class = 'campaign'
    stage            integer,            -- campaign stage ordinal (1..N), else NULL
    indicator        text,              -- the linked IOC (see iocs table)
    indicator_verdict text,             -- the IOC's seed verdict (the label's basis)
    target_asset     text,              -- the linked CMDB asset id
    run_id           text,              -- which generator run produced this alert
    rng_seed         bigint,            -- the deterministic seed for that run
    generated_at     timestamptz DEFAULT now()
);

-- Intent: tools should never read ground truth. (Toothless against the `soc`
-- dev superuser — see the header — but documents the production posture.)
REVOKE ALL ON alert_ground_truth FROM PUBLIC;
