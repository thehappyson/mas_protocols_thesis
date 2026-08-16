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
from typing import Any

from mcp.server.mcpserver import MCPServer

# Matches the container env convention in deployment/base/tools/siem.yaml.
HOST = os.environ.get("MCP_LISTEN_HOST", "127.0.0.1")
PORT = int(os.environ.get("MCP_LISTEN_PORT", "7001"))
PATH = os.environ.get("MCP_PATH", "/mcp")

server = MCPServer(
    name="siem",
    version="0.1.0",
    instructions="Synthetic SOC SIEM. Provides access to security alerts for triage.",
)

# One fixed, plausible alert so agents have something structurally realistic to
# reason over. Fields mirror a normalized SIEM alert record.
_CANNED_ALERT: dict[str, Any] = {
    "id": "alert-0001",
    "timestamp": "2026-08-02T14:23:17Z",
   #"severity": "high",
    "source_ip": "10.14.7.32",
    "dest_ip": "198.51.100.77",
    "rule_name": "Suspicious Outbound Data Transfer",
    "description": (
        "Host 10.14.7.32 transferred 4.2 GB to external address 198.51.100.77 "
        "over 11 minutes, exceeding the baseline for this asset by 40x."
    ),
}


def _fetch_alerts(since: str | None, limit: int) -> list[dict[str, Any]]:
    """DATA-ACCESS SEAM (read). The single place a real DB query will go.

    # TODO: replace canned return with real DB query
    #   e.g. SELECT ... FROM alerts WHERE ts > :since ORDER BY ts DESC LIMIT :limit
    #   against the operational Postgres in the data zone.

    STUB: `since` is ignored entirely and the canned alert is returned
    regardless of its timestamp. `limit` truncates the single-element canned
    list, so any limit >= 1 yields the same one alert.
    """
    alerts = [_CANNED_ALERT]
    return alerts[:limit] if limit >= 0 else alerts


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


if __name__ == "__main__":
    server.run(
        transport="streamable-http",
        host=HOST,
        port=PORT,
        streamable_http_path=PATH,
    )
