"""capability.py — capability-token threading (SPIKE for the C-T1 control).

Proves the plumbing the real control needs: a capability token that is minted at
run entry and ATTENUATED (macaroon-style HMAC hash-chain) at each hop, carried in
the PROTOCOL's OWN metadata — A2A `message.metadata` and MCP `_meta`, NOT HTTP
headers — and read back on ingress. It logs the chain at each agent so we can
confirm the token propagates intact end-to-end (triage -> enrichment -> ... ) and
shows up per-hop in the Phoenix spans.

WHAT THIS SPIKE DELIBERATELY DOES NOT DO YET (later steps):
  * No PDP / verification — it only threads + carries the token.
  * No server-side read on the tool servers — that's the PEP middleware (Step 4).

Gated by CAPABILITY_ENFORCEMENT (env). OFF => every function is a no-op and the
pipeline behaves byte-identically to today.

SPIKE SHORTCUTS (replaced in the real build):
  * `root` is a static env value; the entry token is self-seeded by the first agent
    that sees no incoming capability (real: the operator mints it via the PDP).
  * `sig(x)` hashes only the id (real: id + tools/schema + card — the shared C/P hash).
"""

from __future__ import annotations

import contextvars
import hashlib
import hmac
import json
import os

_KEY = "soc.capability"      # the metadata field the token rides in (A2A + MCP)
_ENABLED = os.environ.get("CAPABILITY_ENFORCEMENT", "false").lower() == "true"
_ROOT = os.environ.get("CAPABILITY_ROOT", "spike-root-secret").encode()

# (token_hex, path) for the current task; None when no capability is present.
_CAP: contextvars.ContextVar[tuple[str, list[str]] | None] = contextvars.ContextVar(
    "soc_capability", default=None)


def enabled() -> bool:
    return _ENABLED


def sig(component_id: str) -> str:
    """Canonical component signature (SPIKE: id only; real: id+schema+card)."""
    return hashlib.sha256(component_id.encode()).hexdigest()[:16]


def _extend(token_hex: str | None, component_id: str) -> str:
    """Macaroon attenuation: HMAC the running token with the next component's sig.
    The entry token uses `root` as the key (token_hex=None)."""
    key = bytes.fromhex(token_hex) if token_hex else _ROOT
    return hmac.new(key, sig(component_id).encode(), hashlib.sha256).hexdigest()


# --- ingress: set the task capability from the incoming A2A metadata ----------
def read_incoming(carrier: dict | None) -> None:
    """Set the current task's capability from the incoming message metadata dict.
    Absent => leave None; the entry agent self-seeds on first attenuation (SPIKE)."""
    if not _ENABLED:
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


def _current_or_seed(self_id: str) -> tuple[str, list[str]]:
    """Current capability, seeding an entry token if absent (SPIKE only)."""
    cap = _CAP.get()
    if cap is None:
        cap = (_extend(None, self_id), [self_id])   # T0 = HMAC(root, sig(self))
        _CAP.set(cap)
    return cap


def _attenuate_for(self_id: str, target_id: str) -> tuple[str, list[str]]:
    """Extend the chain for a downstream target (peer agent or tool)."""
    token, path = _current_or_seed(self_id)
    return _extend(token, target_id), path + [target_id]


# --- egress: attach the attenuated capability to the outgoing protocol object -
def to_a2a_metadata(self_id: str, target_id: str, message) -> None:
    """Write the attenuated capability into an outgoing A2A message's metadata."""
    if not _ENABLED:
        return
    token, path = _attenuate_for(self_id, target_id)
    message.metadata[_KEY] = json.dumps({"token": token, "path": path})


def to_mcp_meta(self_id: str, tool_id: str) -> dict | None:
    """The MCP `_meta` dict carrying the attenuated capability for a tool call
    (None when disabled, so `call_tool(..., meta=None)` is a normal call)."""
    if not _ENABLED:
        return None
    token, path = _attenuate_for(self_id, tool_id)
    return {_KEY: {"token": token, "path": path}}


# --- observability: prove the chain in logs + Phoenix spans -------------------
def note(agent_id: str, where: str, target: str = "") -> None:
    if not _ENABLED:
        return
    cap = _CAP.get()
    tok = (cap[0][:8] + "…") if cap else "none"
    path = "->".join(cap[1]) if cap else "-"
    print(f"[cap] {agent_id:<13} {where:<11} {target:<13} token={tok} path={path}",
          flush=True)


def annotate_span(span, agent_id: str) -> None:
    if not _ENABLED or span is None:
        return
    cap = _CAP.get()
    if cap:
        span.set_attribute("capability.token", cap[0][:16])
        span.set_attribute("capability.path", "->".join(cap[1]))
