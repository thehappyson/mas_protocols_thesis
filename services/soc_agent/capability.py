"""capability.py — agent-side capability threading (the C control).

Threads the PDP-minted macaroon through an agent: reads the incoming capability off
the A2A message metadata into a per-task contextvar, asks the PDP to attenuate it
for each downstream delegation / tool call, and carries the new token in the
outgoing metadata (A2A `message.metadata`, MCP `_meta`). Ingress authorization (the
A2A PEP) is `verify_ingress`; the tool-server PEP lives in `capability_client`.

All PDP calls + the on/off flag come from the shared `capability_client`. Off =>
every function is a no-op and the pipeline behaves exactly as at C0.
"""

from __future__ import annotations

import contextvars
import json

import capability_client as cc  # shared PDP client (services/ is on sys.path)

_KEY = cc.KEY
# (token, path) for the current task; None when no capability is present.
_CAP: contextvars.ContextVar[tuple[str, list] | None] = contextvars.ContextVar(
    "soc_capability", default=None)


def enabled() -> bool:
    return cc.ENABLED


# --- ingress ------------------------------------------------------------------
def read_incoming(carrier: dict | None) -> None:
    """Set the task capability from incoming A2A metadata (JSON string under _KEY)."""
    if not cc.ENABLED:
        return
    cap = None
    try:
        raw = (carrier or {}).get(_KEY)
        if raw:
            obj = json.loads(raw)
            cap = (obj["token"], list(obj["path"]))
    except Exception:  # noqa: BLE001 — malformed capability => treat as absent
        cap = None
    _CAP.set(cap)


async def verify_ingress(self_id: str) -> tuple[bool, str]:
    """A2A PEP: does the incoming capability authorize reaching THIS agent?

    No incoming capability is allowed ONLY if this agent is a legitimate ENTRY
    agent — checked by asking the PDP to mint for it (mint succeeds for entries
    only). A non-entry agent called with no token (e.g. a direct A3 delegation)
    is refused. When it is a valid entry, the minted token is seeded for egress."""
    if not cc.ENABLED:
        return True, "disabled"
    cap = _CAP.get()
    if cap is None:
        minted = await cc.mint(self_id)
        if minted is None:
            return False, "no_capability"
        _CAP.set((minted["token"], minted["path"]))
        return True, "entry"
    token, path = cap
    return await cc.verify(token, path, self_id)


# --- egress: PDP-attenuate and carry the new token ----------------------------
async def _cap_for(self_id: str, target_id: str) -> tuple[str, list] | None:
    """PDP-attenuate the current capability for a downstream target. Mints an entry
    token first if this task has none (only works if `self_id` is an entry agent)."""
    cap = _CAP.get()
    if cap is None:
        minted = await cc.mint(self_id)
        if minted is None:
            return None
        cap = (minted["token"], minted["path"])
        _CAP.set(cap)
    token, path = cap
    out = await cc.attenuate(token, path, target_id)
    return None if out is None else (out["token"], out["path"])


async def to_a2a_metadata(self_id: str, target_id: str, message) -> None:
    """Attenuate for a peer agent and write the new token into the outgoing metadata."""
    if not cc.ENABLED:
        return
    c = await _cap_for(self_id, target_id)
    if c is not None:
        message.metadata[_KEY] = json.dumps({"token": c[0], "path": c[1]})


async def to_mcp_meta(self_id: str, tool_server_id: str) -> dict | None:
    """The MCP `_meta` dict carrying the attenuated capability for a tool call."""
    if not cc.ENABLED:
        return None
    c = await _cap_for(self_id, tool_server_id)
    return None if c is None else {_KEY: {"token": c[0], "path": c[1]}}


# --- observability ------------------------------------------------------------
def note(agent_id: str, where: str, target: str = "") -> None:
    if not cc.ENABLED:
        return
    cap = _CAP.get()
    tok = (cap[0][:8] + "…") if cap else "none"
    path = "->".join(cap[1]) if cap else "-"
    print(f"[cap] {agent_id:<13} {where:<11} {target:<13} token={tok} path={path}",
          flush=True)


def annotate_span(span, agent_id: str) -> None:
    if not cc.ENABLED or span is None:
        return
    cap = _CAP.get()
    if cap:
        span.set_attribute("capability.token", cap[0][:16])
        span.set_attribute("capability.path", "->".join(cap[1]))
