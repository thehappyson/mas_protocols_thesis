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


# The capability (`cap`) is an OPAQUE dict issued by the PDP — {token, path} at
# C-T1, plus {task, exp, jti} at C-T2. Callers carry it untouched and hand it back;
# only the PDP interprets it, so a new tier changes the PDP alone.
async def mint(agent: str, task: str | None = None) -> dict | None:
    """Entry capability for an entry agent, bound to `task` (C-T2), or None if refused."""
    d = await _post("/mint", {"agent": agent, "task": task})
    return None if d.get("error") else d


async def attenuate(cap: dict, target: str) -> dict | None:
    """Extend the chain one hop -> cap, or None if the edge is illegal/expired."""
    d = await _post("/attenuate", {"cap": cap, "target": target})
    return None if d.get("error") else d


async def verify(cap: dict, target: str, task: str | None = None) -> tuple[bool, str]:
    """(allow, reason) — `cap` authorizes reaching `target` within `task`."""
    d = await _post("/verify", {"cap": cap, "action": {"target": target, "task": task}})
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
            # _meta[KEY] = {"cap": <opaque cap>, "task": <caller's task>}
            entry = (ctx.meta or {}).get(KEY) if ctx.meta else None
            entry = entry if isinstance(entry, dict) else {}
            cap = entry.get("cap") if isinstance(entry.get("cap"), dict) else entry
            path = cap.get("path")
            allow, reason = (False, "no_capability")
            if cap.get("token") and path:
                allow, reason = await verify(cap, server_id, entry.get("task"))
            # Server-side audit line: the ONLY defender-side record of a no-token
            # (edge-denied) call, since those never reach the PDP. Visible in the
            # tool pod's log: `kubectl -n tool-zone logs deploy/mcp-<name>`.
            print(f"[cap] {server_id:<13} tools/call "
                  f"{'ALLOW' if allow else 'DENY':<5} reason={reason} "
                  f"path={'->'.join(path) if path else '-'}", flush=True)
            if not allow:
                from mcp.shared.exceptions import MCPError
                # This SDK's MCPError takes positional (code, message) — NOT an
                # ErrorData object. Passing ErrorData raises a TypeError instead of
                # the rejection, which the caller then sees as a generic harness error.
                raise MCPError(-32001, f"capability token rejected: {reason}")
        return await call_next(ctx)

    server.middleware.append(_pep)
