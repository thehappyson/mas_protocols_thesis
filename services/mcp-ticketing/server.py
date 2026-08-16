"""Ticketing MCP tool server — streamable HTTP transport.

One of six MCP tool servers in the SOC testbed (see
deployment/base/tools/ticketing.yaml, which deploys this as `mcp-ticketing` on
port 7005).

DESIGN PRINCIPLE: the protocol machinery is real, the domain logic is stubbed.
The MCP interface below is genuine; behind it there is no ticketing system.

DATA-ACCESS SEAM: each MCP tool method calls a separate data-access function
(`_write_incident`, `_write_incident_update`) that is the single, clearly-marked
place a real DB WRITE will later go. The MCP methods, schemas, and validation
are final; only the data-access innards are provisional. These are WRITE tools:
the seam is shaped as a write (it mints an id and returns a success receipt) but
currently persists nothing.

Written against MCP Python SDK 2.0.0 (server class `MCPServer`; transport via
`run(transport="streamable-http", ...)`).

Run:
    python services/mcp-ticketing/server.py
Endpoint:
    http://127.0.0.1:7005/mcp
"""

from __future__ import annotations

import os
import uuid
from datetime import datetime, timezone
from typing import Any

from mcp.server.mcpserver import MCPServer

# Matches the container env convention in deployment/base/tools/ticketing.yaml.
HOST = os.environ.get("MCP_LISTEN_HOST", "127.0.0.1")
PORT = int(os.environ.get("MCP_LISTEN_PORT", "7005"))
PATH = os.environ.get("MCP_PATH", "/mcp")

server = MCPServer(
    name="ticketing",
    version="0.1.0",
    instructions=(
        "Synthetic SOC ticketing service. Creates and updates incident tickets."
    ),
)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _write_incident(
    title: str, description: str, severity: str | None, assignee: str | None
) -> dict[str, Any]:
    """DATA-ACCESS SEAM (write). The single place a real DB write will go.

    # TODO: replace canned return with real DB write
    #   e.g. INSERT INTO incidents (id, title, description, severity, assignee,
    #   created_at) VALUES (...) RETURNING id  (operational Postgres, data zone).
    #   NOTHING IS PERSISTED YET — the id is minted in-process and forgotten.

    STUB: generates an incident id and returns a success receipt without
    storing anything.
    """
    incident_id = f"INC-{uuid.uuid4().hex[:8].upper()}"
    return {
        "incident_id": incident_id,
        "status": "created",
        "title": title,
        "description": description,
        "severity": severity,
        "assignee": assignee,
        "created_at": _now(),
        "persisted": False,  # honest: no store behind this yet
    }


def _write_incident_update(
    incident_id: str, status: str | None, note: str | None
) -> dict[str, Any]:
    """DATA-ACCESS SEAM (write). The single place a real DB write will go.

    # TODO: replace canned return with real DB write
    #   e.g. UPDATE incidents SET status = :status, updated_at = now() WHERE
    #   id = :incident_id; INSERT INTO incident_notes (...)  (operational Postgres).
    #   NOTHING IS PERSISTED YET.

    STUB: returns a success receipt without storing anything. Does not verify
    that `incident_id` exists.
    """
    return {
        "incident_id": incident_id,
        "status": status or "updated",
        "note": note,
        "updated_at": _now(),
        "persisted": False,  # honest: no store behind this yet
    }


@server.tool(
    description=(
        "Create a new incident ticket. Returns the generated incident id and a "
        "success receipt."
    )
)
def create_incident(
    title: str,
    description: str,
    severity: str | None = None,
    assignee: str | None = None,
) -> dict[str, Any]:
    """Create an incident ticket.

    Args:
        title: Short incident title.
        description: Incident detail.
        severity: Optional severity label.
        assignee: Optional assignee user id.
    """
    return _write_incident(title, description, severity, assignee)


@server.tool(
    description=(
        "Update an existing incident ticket's status or append a note. Returns "
        "a success receipt."
    )
)
def update_incident(
    incident_id: str,
    status: str | None = None,
    note: str | None = None,
) -> dict[str, Any]:
    """Update an incident ticket.

    Args:
        incident_id: The incident to update.
        status: Optional new status.
        note: Optional note to append.
    """
    return _write_incident_update(incident_id, status, note)


if __name__ == "__main__":
    server.run(
        transport="streamable-http",
        host=HOST,
        port=PORT,
        streamable_http_path=PATH,
    )
