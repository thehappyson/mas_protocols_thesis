"""Tiny Postgres helper shared by the MCP tool data-access seams.

One connection per call (simple and robust for the testbed's low volume; the MCP
server runs the sync tool functions in a worker thread, so the blocking query
does not stall the event loop). Each tool passes its own DSN — operational tools
use OPERATIONAL_DB_URL, the containment tool uses AUDIT_DB_URL — so the
operational/audit separation is enforced by which DSN a tool holds.
"""

from __future__ import annotations

from typing import Any

import psycopg2
import psycopg2.extras


def rows(dsn: str, sql: str, params: tuple = ()) -> list[dict[str, Any]]:
    """Run a read query and return rows as plain dicts."""
    with psycopg2.connect(dsn) as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(sql, params)
            return [dict(r) for r in cur.fetchall()]


def execute(dsn: str, sql: str, params: tuple = ()) -> None:
    """Run a write statement (commits on success via the connection context)."""
    with psycopg2.connect(dsn) as conn:
        with conn.cursor() as cur:
            cur.execute(sql, params)
