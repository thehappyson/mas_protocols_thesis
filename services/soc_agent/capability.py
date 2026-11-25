"""capability.py — agent-side capability threading (the C control).

Threads the PDP-minted macaroon through an agent: reads the incoming capability off
the A2A message metadata into a per-task contextvar, asks the PDP to attenuate it
for each downstream delegation / tool call, and carries the new token in the
outgoing metadata (A2A `message.metadata`, MCP `_meta`). Ingress authorization (the
A2A PEP) is `verify_ingress`; the tool-server PEP lives in `capability_client`.

The capability is an OPAQUE dict from the PDP ({token, path} at C-T1, plus
{task, exp, jti} at C-T2); this module never looks inside beyond logging. The TASK
an agent works in is its A2A `context_id`: `_delegate` propagates the parent's
context_id to every hop, so one alert = one task across the whole chain. A2A
carries it natively; MCP carries it next to the cap in `_meta`.

All PDP calls + the on/off flag come from the shared `capability_client`. Off =>
every function is a no-op and the pipeline behaves exactly as at C0.
"""

from __future__ import annotations

import contextvars
import json

import capability_client as cc  # shared PDP client (services/ is on sys.path)

_KEY = cc.KEY
# Opaque cap for the current task; None when no capability is present.
_CAP: contextvars.ContextVar[dict | None] = contextvars.ContextVar(
    "soc_capability", default=None)
# The task (A2A context_id) this agent is currently working in.
_TASK: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "soc_capability_task", default=None)


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
            obj = json.loads(raw) if isinstance(raw, str) else raw
            if isinstance(obj, dict) and obj.get("token") and obj.get("path"):
                cap = dict(obj)
    except Exception:  # noqa: BLE001 — malformed capability => treat as absent
        cap = None
    _CAP.set(cap)


async def verify_ingress(self_id: str, task: str | None = None) -> tuple[bool, str]:
    """A2A PEP: does the incoming capability authorize reaching THIS agent in `task`?

    No incoming capability is allowed ONLY if this agent is a legitimate ENTRY
    agent — checked by asking the PDP to mint for it (mint succeeds for entries
    only), which also binds the new capability to `task`. A non-entry agent called
    with no token (e.g. a direct A3 delegation) is refused."""
    if not cc.ENABLED:
        return True, "disabled"
    _TASK.set(task)
    cap = _CAP.get()
    if cap is None:
        minted = await cc.mint(self_id, task)
        if minted is None:
            return False, "no_capability"
        _CAP.set(minted)
        return True, "entry"
    return await cc.verify(cap, self_id, task)


# --- egress: PDP-attenuate and carry the new token ----------------------------
async def _cap_for(self_id: str, target_id: str) -> dict | None:
    """PDP-attenuate the current capability for a downstream target. Mints an entry
    capability first if this task has none (only works if `self_id` is an entry)."""
    cap = _CAP.get()
    if cap is None:
        minted = await cc.mint(self_id, _TASK.get())
        if minted is None:
            return None
        cap = minted
        _CAP.set(cap)
    return await cc.attenuate(cap, target_id)


async def to_a2a_metadata(self_id: str, target_id: str, message) -> None:
    """Attenuate for a peer agent and write the new cap into the outgoing metadata.
    The task travels in the message's own context_id (set by `_delegate`)."""
    if not cc.ENABLED:
        return
    c = await _cap_for(self_id, target_id)
    if c is not None:
        message.metadata[_KEY] = json.dumps(c)


async def to_mcp_meta(self_id: str, tool_server_id: str) -> dict | None:
    """The MCP `_meta` dict carrying the attenuated cap + this agent's task."""
    if not cc.ENABLED:
        return None
    c = await _cap_for(self_id, tool_server_id)
    return None if c is None else {_KEY: {"cap": c, "task": _TASK.get()}}


# --- observability ------------------------------------------------------------
def note(agent_id: str, where: str, target: str = "") -> None:
    if not cc.ENABLED:
        return
    cap = _CAP.get()
    tok = (cap["token"][:8] + "…") if cap else "none"
    path = "->".join(cap["path"]) if cap else "-"
    print(f"[cap] {agent_id:<13} {where:<11} {target:<13} token={tok} path={path}",
          flush=True)


def annotate_span(span, agent_id: str) -> None:
    if not cc.ENABLED or span is None:
        return
    cap = _CAP.get()
    if cap:
        span.set_attribute("capability.token", cap["token"][:16])
        span.set_attribute("capability.path", "->".join(cap["path"]))
        if cap.get("task"):
            span.set_attribute("capability.task", str(cap["task"]))
