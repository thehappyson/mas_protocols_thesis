"""CMDB MCP tool server — streamable HTTP transport.

One of six MCP tool servers in the SOC testbed (see deployment/base/tools/cmdb.yaml,
which deploys this as `mcp-cmdb` on port 7002).

DESIGN PRINCIPLE: the protocol machinery is real, the domain logic is stubbed.
The MCP interface below — tool registration, JSON schema, streamable HTTP
transport — is genuine. Behind the tools there is no CMDB and no query engine.

DATA-ACCESS SEAM: each MCP tool method calls a separate data-access function
(`_fetch_asset`, `_fetch_user`) that is the single, clearly-marked place a real
DB query will later go. The MCP methods, schemas, and validation are final;
only the data-access innards are provisional. These are READ tools.

Written against MCP Python SDK 2.0.0 (server class `MCPServer`; transport via
`run(transport="streamable-http", ...)`).

Run:
    python services/mcp-cmdb/server.py
Endpoint:
    http://127.0.0.1:7002/mcp
"""

from __future__ import annotations

import os
from typing import Any

from mcp.server.mcpserver import MCPServer

# Matches the container env convention in deployment/base/tools/cmdb.yaml.
HOST = os.environ.get("MCP_LISTEN_HOST", "127.0.0.1")
PORT = int(os.environ.get("MCP_LISTEN_PORT", "7002"))
PATH = os.environ.get("MCP_PATH", "/mcp")

server = MCPServer(
    name="cmdb",
    version="0.1.0",
    instructions=(
        "Synthetic SOC configuration management database. Resolves assets and "
        "users referenced in alerts to ownership and criticality context."
    ),
)

# Canned records so agents have structurally realistic asset/user data to reason
# over. Fields mirror normalized CMDB records.
_CANNED_ASSET: dict[str, Any] = {
    "asset_id": "10.14.7.32",
    "hostname": "fin-ws-0447",
    "owner": "finance-workstations",
    "owner_contact": "it-finance@example.corp",
    "criticality": "medium",
    "location": "HQ-3F",
    "os": "Windows 11 Pro 23H2",
    "last_seen": "2026-08-02T14:20:00Z",
}

# A few explicitly-known assets so criticality is KEYED on the asset (a lookup,
# not a constant) — mirrors the threat-intel tool's keyed verdicts. This makes
# the field meaningful for consumers like the Verification agent, which judges a
# proposed containment action against the target's criticality: isolating a
# workstation is routine, isolating a domain controller is not.
_KNOWN_ASSETS: dict[str, dict[str, Any]] = {
    "10.14.7.32": {"hostname": "fin-ws-0447", "owner": "finance-workstations",
                   "criticality": "medium"},
    "dc-01": {"hostname": "dc-01", "owner": "core-identity",
              "criticality": "critical", "os": "Windows Server 2022"},
    "10.0.0.10": {"hostname": "dc-01", "owner": "core-identity",
                  "criticality": "critical", "os": "Windows Server 2022"},
}
_CANNED_USER: dict[str, Any] = {
    "user_id": "jdoe",
    "display_name": "Jordan Doe",
    "department": "Finance",
    "manager": "amorgan",
    "email": "jdoe@example.corp",
    "privileged": False,
    "mfa_enrolled": True,
}


def _fetch_asset(asset_id: str) -> dict[str, Any]:
    """DATA-ACCESS SEAM (read). The single place a real DB query will go.

    # TODO: replace canned return with real DB query
    #   e.g. SELECT ... FROM assets WHERE asset_id = :asset_id
    #   against the operational Postgres in the data zone.

    STUB: known assets come from a small table (criticality keyed on the id);
    an unknown id reports criticality "unknown" rather than a default, so
    consumers (e.g. the Verification agent) can treat an unresolved target
    cautiously instead of assuming it is low-risk.
    """
    known = _KNOWN_ASSETS.get(asset_id)
    if known is None:
        return {
            **_CANNED_ASSET,
            "asset_id": asset_id,
            "hostname": "unknown",
            "owner": "unknown",
            "criticality": "unknown",
        }
    return {**_CANNED_ASSET, **known, "asset_id": asset_id}


def _fetch_user(user_id: str) -> dict[str, Any]:
    """DATA-ACCESS SEAM (read). The single place a real DB query will go.

    # TODO: replace canned return with real DB query
    #   e.g. SELECT ... FROM users WHERE user_id = :user_id
    #   against the operational Postgres in the data zone.

    STUB: the lookup is echoed into the canned record; other fields are fixed.
    """
    return {**_CANNED_USER, "user_id": user_id}


@server.tool(
    description=(
        "Look up a configuration item (asset) by id or IP and return its "
        "ownership, criticality, and platform details."
    )
)
def lookup_asset(asset_id: str) -> dict[str, Any]:
    """Resolve an asset to its CMDB record.

    Args:
        asset_id: Asset identifier or IP address to resolve.
    """
    return _fetch_asset(asset_id)


@server.tool(
    description=(
        "Look up a user by id and return their department, manager, and "
        "account posture (privilege, MFA)."
    )
)
def lookup_user(user_id: str) -> dict[str, Any]:
    """Resolve a user to their CMDB record.

    Args:
        user_id: User identifier to resolve.
    """
    return _fetch_user(user_id)


if __name__ == "__main__":
    server.run(
        transport="streamable-http",
        host=HOST,
        port=PORT,
        streamable_http_path=PATH,
    )
