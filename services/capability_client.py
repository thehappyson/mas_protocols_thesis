"""capability_client.py — shared PDP client + tool-server PEP (the C control).

Imported by BOTH the agents (services/soc_agent/capability.py) and the tool servers
(services/mcp-*/server.py). Talks to the capability-verifier (PDP) over HTTP. The
PDP is the ONLY holder of `root` + policy; every component here just asks it.

Gated by CAPABILITY_ENFORCEMENT — off => no-ops, so C0 behaves exactly as before.
"""

from __future__ import annotations

import os

import httpx

KEY = "soc.capability"     # metadata field the capability rides in (A2A + MCP)
ENABLED = os.environ.get("CAPABILITY_ENFORCEMENT", "false").lower() == "true"
PDP = os.environ.get(
    "PDP_ENDPOINT",
    "http://capability-verifier.platform-zone.svc.cluster.local:8080").rstrip("/")


async def _post(path: str, payload: dict) -> dict:
    async with httpx.AsyncClient(timeout=10.0) as client:
        r = await client.post(PDP + path, json=payload)
        return r.json()


async def mint(agent: str) -> dict | None:
    """Entry macaroon for an entry agent -> {token, path}, or None if refused."""
    d = await _post("/mint", {"agent": agent})
    return None if d.get("error") else d


async def attenuate(token: str, path: list, target: str) -> dict | None:
    """Extend the chain one hop -> {token, path}, or None if the edge is illegal."""
    d = await _post("/attenuate", {"token": token, "path": path, "target": target})
    return None if d.get("error") else d


async def verify(token: str, path: list, target: str) -> tuple[bool, str]:
    """(allow, reason) — the incoming capability authorizes reaching `target`."""
    d = await _post("/verify", {"token": token, "path": path, "action": {"target": target}})
    return bool(d.get("allow")), str(d.get("reason", ""))


def install_pep(server) -> None:
    """Append a PEP middleware to a tool server: every `tools/call` is verified with
    the PDP against THIS server (`server.name` = the resource id). A denied call is
    refused with an MCP error the caller sees as a rejection. No-op when disabled."""
    if not ENABLED:
        return
    server_id = server.name

    async def _pep(ctx, call_next):
        if ctx.method == "tools/call":
            cap = (ctx.meta or {}).get(KEY) if ctx.meta else None
            token = (cap or {}).get("token")
            path = (cap or {}).get("path")
            allow, reason = (False, "no_capability")
            if token and path:
                allow, reason = await verify(token, path, server_id)
            if not allow:
                from mcp.shared.exceptions import MCPError
                from mcp.types import ErrorData
                raise MCPError(ErrorData(
                    code=-32001, message=f"capability token rejected: {reason}"))
        return await call_next(ctx)

    server.middleware.append(_pep)
