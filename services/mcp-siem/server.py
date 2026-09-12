"""SIEM MCP tool server — streamable HTTP transport.

One of six MCP tool servers in the SOC testbed (see deployment/base/tools/siem.yaml,
which deploys this as `mcp-siem` on port 7001).

DESIGN PRINCIPLE: the protocol machinery is real, the domain logic is stubbed.
The MCP interface below — tool registration, JSON schema, streamable HTTP
transport — is the genuine article, because the protocol layer is what this
thesis measures. Everything behind `next_alerts` is a canned response: there is
no SIEM, no query engine, no alert store.

DATA-ACCESS SEAM: the MCP tool method calls a separate data-access function
(`_fetch_alerts`) that is the single, clearly-marked place where a real DB
query will later go. The MCP method, schema, and validation are final; only the
innards of `_fetch_alerts` are provisional. Wiring real Postgres later means
editing that one function, nothing else. This is a READ tool.

Written against MCP Python SDK 2.0.0, where the ergonomic server class is
`MCPServer` (the 1.x `FastMCP`) and transport is selected via
`run(transport="streamable-http", ...)`.

Run:
    python services/mcp-siem/server.py
Endpoint:
    http://127.0.0.1:7001/mcp
"""

from __future__ import annotations

import os
import pathlib
import sys
from typing import Any

from mcp.server.mcpserver import MCPServer

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
from mcp_db import rows  # noqa: E402  (shared DB helper, tool image)

# Matches the container env convention in deployment/base/tools/siem.yaml.
HOST = os.environ.get("MCP_LISTEN_HOST", "127.0.0.1")
PORT = int(os.environ.get("MCP_LISTEN_PORT", "7001"))
PATH = os.environ.get("MCP_PATH", "/mcp")
# Operational store, from config (container network in compose).
OPERATIONAL_DB_URL = os.environ.get(
    "OPERATIONAL_DB_URL", "postgresql://soc:soc@127.0.0.1:5432/soc_operational"
)

server = MCPServer(
    name="siem",
    version="0.1.0",
    instructions="Synthetic SOC SIEM. Provides access to security alerts for triage.",
)

def _fetch_alerts(since: str | None, limit: int,
                  source_ip: str | None = None) -> list[dict[str, Any]]:
    """DATA-ACCESS SEAM (read) — backed by the operational `alerts` table.

    Return shape is a list of {id, timestamp, source_ip, dest_ip, rule_name,
    description} dicts (no severity key). Newest first. `since` filters by
    timestamp, `source_ip` filters to one source (corroboration lookup), and
    `limit` bounds the rows.
    """
    sql = (
        "SELECT id, "
        "to_char(ts AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"') AS timestamp, "
        "source_ip, dest_ip, rule_name, description FROM alerts"
    )
    clauses: list[str] = []
    params: list[Any] = []
    if since:
        clauses.append("ts > %s")
        params.append(since)
    if source_ip:
        clauses.append("source_ip = %s")
        params.append(source_ip)
    if clauses:
        sql += " WHERE " + " AND ".join(clauses)
    sql += " ORDER BY ts DESC"
    if limit is not None and limit >= 0:
        sql += " LIMIT %s"
        params.append(limit)
    return rows(OPERATIONAL_DB_URL, sql, tuple(params))


@server.tool(
    description=(
        "Fetch recent security alerts from the SIEM, newest first. "
        "Returns a list of alert objects."
    )
)
def next_alerts(since: str | None = None, limit: int = 10) -> list[dict[str, Any]]:
    """Return security alerts newer than `since`.

    Args:
        since: ISO-8601 timestamp; only alerts after this point are returned.
        limit: Maximum number of alerts to return.
    """
    return _fetch_alerts(since, limit)


@server.tool(
    description=(
        "Look up prior alerts from a specific source IP, newest first — to "
        "corroborate whether a source has a history. Returns a list of alert "
        "objects; an empty list means no other alerts from that source."
    )
)
def related_alerts(source_ip: str, limit: int = 20) -> list[dict[str, Any]]:
    """Return alerts sharing `source_ip` (newest first), for corroboration.

    Args:
        source_ip: the source IP to look up a history for.
        limit: maximum number of alerts to return.
    """
    return _fetch_alerts(None, limit, source_ip=source_ip)


if __name__ == "__main__":
    server.run(
        transport="streamable-http",
        host=HOST,
        port=PORT,
        streamable_http_path=PATH,
    )
