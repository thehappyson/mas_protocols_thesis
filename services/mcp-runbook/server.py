"""Runbook MCP tool server — streamable HTTP transport.

One of six MCP tool servers in the SOC testbed (see
deployment/base/tools/runbook.yaml, which deploys this as `mcp-runbook` on
port 7004).

DESIGN PRINCIPLE: the protocol machinery is real, the domain logic is stubbed.
The MCP interface below is genuine; behind it there is no runbook store and no
retrieval engine.

DATA-ACCESS SEAM: the MCP tool method calls a separate data-access function
(`_search_runbook`) that is the single, clearly-marked place a real query will
later go. The MCP method, schema, and validation are final; only the
data-access innards are provisional. This is a READ tool — eventually a RAG or
keyword search over a seeded runbook corpus.

Written against MCP Python SDK 2.0.0 (server class `MCPServer`; transport via
`run(transport="streamable-http", ...)`).

Run:
    python services/mcp-runbook/server.py
Endpoint:
    http://127.0.0.1:7004/mcp
"""

from __future__ import annotations

import os
from typing import Any

from mcp.server.mcpserver import MCPServer

# Matches the container env convention in deployment/base/tools/runbook.yaml.
HOST = os.environ.get("MCP_LISTEN_HOST", "127.0.0.1")
PORT = int(os.environ.get("MCP_LISTEN_PORT", "7004"))
PATH = os.environ.get("MCP_PATH", "/mcp")

server = MCPServer(
    name="runbook",
    version="0.1.0",
    instructions=(
        "Synthetic SOC runbook service. Returns response procedures relevant "
        "to an incident query."
    ),
)

# One fixed, plausible runbook snippet so agents have a structurally realistic
# procedure to reason over. Fields mirror a normalized runbook entry.
_CANNED_RUNBOOK: dict[str, Any] = {
    "title": "Suspected Data Exfiltration — Initial Response",
    "steps": [
        "Confirm the outbound transfer volume and destination against baseline.",
        "Isolate the source host from the network to arrest ongoing transfer.",
        "Preserve volatile evidence (netflow, process list, open handles).",
        "Enrich the destination indicator and check for related alerts.",
        "Open an incident ticket and escalate to IR if exfiltration is confirmed.",
    ],
    "attack_ref": "TA0010 (Exfiltration)",
    "source": "synthetic-runbook (stub)",
}


def _search_runbook(query: str, limit: int) -> list[dict[str, Any]]:
    """DATA-ACCESS SEAM (read). The single place a real query will go.

    # TODO: replace canned return with real DB query
    #   e.g. RAG/keyword search over a seeded runbook corpus in the data zone
    #   (pgvector similarity or full-text search), ranked by relevance to query.

    STUB: `query` is echoed back for traceability but does not steer retrieval;
    the same canned snippet is returned regardless. `limit` truncates the
    single-element result list.
    """
    results = [{**_CANNED_RUNBOOK, "matched_query": query}]
    return results[:limit] if limit >= 0 else results


@server.tool(
    description=(
        "Search the response runbooks for procedures relevant to a query. "
        "Returns matching runbook entries with steps and an ATT&CK reference."
    )
)
def search_runbook(query: str, limit: int = 3) -> list[dict[str, Any]]:
    """Return runbook entries relevant to `query`.

    Args:
        query: Free-text description of the incident or procedure needed.
        limit: Maximum number of runbook entries to return.
    """
    return _search_runbook(query, limit)


if __name__ == "__main__":
    server.run(
        transport="streamable-http",
        host=HOST,
        port=PORT,
        streamable_http_path=PATH,
    )
