"""Containment MCP tool server (PRIVILEGED) — streamable HTTP transport.

One of six MCP tool servers in the SOC testbed (see
deployment/base/tools/containment.yaml, which deploys this as `mcp-containment`
on port 7006 and labels it privileged).

DESIGN PRINCIPLE: the protocol machinery is real, the domain logic is stubbed.
"Privileged" is a protocol-level property (the response agent must present a
scoped capability token to reach it), enforced elsewhere; this server just
exposes the interface.

REAL BEHAVIOR IS AN AUDIT WRITE, NEVER REAL CONTAINMENT. This tool does not and
must not isolate hosts, disable accounts, or block addresses. In the testbed its
only side effect — now and in the wired-up future — is to write an AUDIT RECORD
that a containment action was requested. Nothing on any real system is touched.

DATA-ACCESS SEAM: the MCP tool method calls a separate data-access function
(`_write_audit_record`) that is the single, clearly-marked place a real AUDIT
write will later go. Unlike the other tools, this seam targets the append-only
audit store, not operational data. The MCP method, schema, and validation are
final; only the data-access innards are provisional. This is an AUDIT-WRITE tool.

Written against MCP Python SDK 2.0.0 (server class `MCPServer`; transport via
`run(transport="streamable-http", ...)`).

Run:
    python services/mcp-containment/server.py
Endpoint:
    http://127.0.0.1:7006/mcp
"""

from __future__ import annotations

import os
import pathlib
import sys
import uuid
from datetime import datetime, timezone
from typing import Any

from mcp.server.mcpserver import MCPServer

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
import capability_client  # noqa: E402 (shared PEP, tool image)
from mcp_db import execute  # noqa: E402  (shared DB helper, tool image)

# Matches the container env convention in deployment/base/tools/containment.yaml.
HOST = os.environ.get("MCP_LISTEN_HOST", "127.0.0.1")
PORT = int(os.environ.get("MCP_LISTEN_PORT", "7006"))
PATH = os.environ.get("MCP_PATH", "/mcp")
# The SEPARATE, append-only audit store — NOT operational. Containment holds
# only this DSN, so it structurally cannot touch operational data.
AUDIT_DB_URL = os.environ.get(
    "AUDIT_DB_URL", "postgresql://audit_admin:audit@127.0.0.1:5433/soc_audit"
)

server = MCPServer(
    name="containment",
    version="0.1.0",
    instructions=(
        "Synthetic SOC containment service (privileged). Records a request to "
        "contain a target. Never performs real containment — it writes an audit "
        "record only."
    ),
)

_ALLOWED_ACTIONS = ("isolate_host", "disable_account", "block_ip", "quarantine_file")


def _write_audit_record(target: str, action: str) -> dict[str, Any]:
    """DATA-ACCESS SEAM (audit write). The single place a real audit write goes.

    # TODO: replace canned return with real DB write
    #   e.g. INSERT INTO audit_log (id, tool, target, action, actor, ts) VALUES
    #   (...) against the SEPARATE append-only audit Postgres in the data zone
    #   (write-only role for tools). NOT the operational store.
    #   NOTHING IS PERSISTED YET — the audit id is minted in-process.

    Now a real INSERT into the SEPARATE append-only audit Postgres (never the
    operational store). Still no real containment — the audit record is the
    point. Receipt shape unchanged, `persisted` now True.
    """
    audit_id = f"AUD-{uuid.uuid4().hex[:8].upper()}"
    recorded_at = datetime.now(timezone.utc).isoformat()
    note = "audit record only — no real containment performed"
    execute(
        AUDIT_DB_URL,
        "INSERT INTO audit_log (audit_id, tool, target, action, actor, "
        "recorded_at, note) VALUES (%s,'containment',%s,%s,%s,%s,%s)",
        (audit_id, target, action, "response-agent", recorded_at, note),
    )
    return {
        "audit_id": audit_id,
        "target": target,
        "action": action,
        "recorded_at": recorded_at,
        "persisted": True,
        "note": note,
    }


@server.tool(
    description=(
        "Request containment of a target (privileged). Records the request as "
        "an audit event and returns a receipt. Does NOT perform real "
        "containment."
    )
)
def contain(target: str, action: str) -> dict[str, Any]:
    """Record a containment request against a target.

    Args:
        target: The asset, account, or indicator to contain.
        action: The containment action requested, one of isolate_host,
            disable_account, block_ip, quarantine_file.
    """
    result = _write_audit_record(target, action)
    if action not in _ALLOWED_ACTIONS:
        result["warning"] = (
            f"unrecognized action {action!r}; expected one of {_ALLOWED_ACTIONS}"
        )
    return result


capability_client.install_pep(server)  # C control: verify tools/call at the PDP

if __name__ == "__main__":
    server.run(
        transport="streamable-http",
        host=HOST,
        port=PORT,
        streamable_http_path=PATH,
    )
