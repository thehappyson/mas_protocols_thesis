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
import pathlib
import re
import sys
from typing import Any

from mcp.server.mcpserver import MCPServer

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
from mcp_db import rows  # noqa: E402  (shared DB helper, tool image)

# Matches the container env convention in deployment/base/tools/runbook.yaml.
HOST = os.environ.get("MCP_LISTEN_HOST", "127.0.0.1")
PORT = int(os.environ.get("MCP_LISTEN_PORT", "7004"))
PATH = os.environ.get("MCP_PATH", "/mcp")
OPERATIONAL_DB_URL = os.environ.get(
    "OPERATIONAL_DB_URL", "postgresql://soc:soc@127.0.0.1:5432/soc_operational"
)

server = MCPServer(
    name="runbook",
    version="0.1.0",
    instructions=(
        "Synthetic SOC runbook service. Returns response procedures relevant "
        "to an incident query."
    ),
)

def _search_runbook(query: str, limit: int) -> list[dict[str, Any]]:
    """DATA-ACCESS SEAM (read) — keyword search over the `runbook` table.

    Retrieval is now real: the query terms are matched (ILIKE) against each
    entry's keywords and title; matches are returned newest-first, bounded by
    `limit`, each with `matched_query` echoed in. Chose KEYWORD search (not
    pgvector embeddings) — sufficient for the seeded corpus and dependency-free.
    Return shape unchanged ({title, steps, attack_ref, source, matched_query}).
    Note: with no matching term the result is an empty list (the stub always
    returned one canned entry); no workflow agent uses this tool, so this does
    not affect the escalate/benign paths.
    """
    terms = [t for t in re.findall(r"\w+", query.lower()) if len(t) > 2]
    patterns = [f"%{t}%" for t in terms]
    if not patterns:
        return []
    sql = (
        "SELECT title, steps, attack_ref, source FROM runbook "
        "WHERE keywords ILIKE ANY(%s) OR title ILIKE ANY(%s) ORDER BY id"
    )
    params: list[Any] = [patterns, patterns]
    if limit is not None and limit >= 0:
        sql += " LIMIT %s"
        params.append(limit)
    found = rows(OPERATIONAL_DB_URL, sql, tuple(params))
    return [{**r, "matched_query": query} for r in found]


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
