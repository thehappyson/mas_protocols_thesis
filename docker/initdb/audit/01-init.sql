-- Audit database for the SOC testbed (postgres-audit) — a SEPARATE Postgres
-- instance from operational, on its own port (5433). This is where the
-- Containment tool's audit-write seam records that a containment action was
-- REQUESTED. No real containment is ever performed; the audit record is the
-- point. Operational data never lives here and audit data never lives there.
--
-- Append-only INTENT: a real deployment would grant tools an INSERT-only role
-- and revoke UPDATE/DELETE. For dev we document the intent and enforce it
-- lightly with a rule that blocks UPDATE/DELETE on the table.

CREATE TABLE audit_log (
    audit_id    text PRIMARY KEY,
    tool        text,
    target      text,
    action      text,
    actor       text,
    recorded_at timestamptz,
    note        text
);

-- Append-only guard: reject UPDATE/DELETE (dev-grade enforcement of intent).
CREATE RULE audit_log_no_update AS ON UPDATE TO audit_log DO INSTEAD NOTHING;
CREATE RULE audit_log_no_delete AS ON DELETE TO audit_log DO INSTEAD NOTHING;
