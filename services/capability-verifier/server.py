"""capability-verifier — the PDP (Policy Decision Point) for the C control.

The central reference monitor. It is the ONLY component that holds `root` and the
policy graph; agents and tool servers (PEPs) call it. Three endpoints, all of which
take/return the capability as an OPAQUE dict (`cap`) that callers pass through:

  POST /mint       {agent, task}      -> cap                entry macaroon
  POST /attenuate  {cap, target}      -> cap                extend one hop (enforces the edge)
  POST /verify     {cap, action}      -> {allow, reason}    authenticate + authorize
                   action = {target, task}

TOKEN CONSTRUCTION — `token = HMAC(root, canonical(cap))`, keyed on `root` over the
WHOLE path. Because every hop needs `root`, only the PDP can mint any token: a
token-holder cannot self-extend to a new hop or forge a different identity. That is
what confines a (possibly compromised) component to its scope. Requiring
`action.target == path[-1]` makes the path's last hop the token's AUDIENCE, so
audience binding is already part of C-T1 (a finding: chained macaroons give `aud`
for free — attack A5a is refused at C-T1 already).

TIERS (env CAPABILITY_TIER; one tier per cluster lifetime):
  t1  C-T1  canonical = path.                       (bearer, no expiry)
  t2  C-T2  canonical = path + task + exp + jti:
        task  bound at mint to the workflow's A2A context_id; verify requires the
              request's task to match                  -> defends A5b (task confusion)
        exp   task-scoped lifetime (CAPABILITY_TTL), INHERITED by every attenuation,
              never extended                           -> defends A5c (temporal reuse)
        jti   fresh per issued token; verify consumes it once (replay cache)
                                                       -> defends A5c (replay)
      Known limits (recorded, not fixed — sender-constraint is C-T3, cut as future
      work): /attenuate from an already-used token is bounded by `exp`, not `jti`;
      the replay cache is in-memory, so a PDP restart clears it.

`sig(x)` here hashes the canonical id only; the real build swaps in the shared
C/P hash (id + schema + card) so a mutated component's sig — and thus its token —
no longer validates. The policy graph mirrors the live wiring (per-agent tools +
the workflow delegation edges), so no legitimate call is ever refused.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import threading
import time
import uuid

# --- policy (canonical ids; mirrors the real wiring) -------------------------
ENTRY = {"triage"}
DELEGATE: dict[str, set[str]] = {
    "triage": {"enrichment", "reporter"},
    "enrichment": {"correlation"},
    "correlation": {"response"},
    "response": {"verification"},
    "reporter": set(),
    "verification": set(),
}
TOOLS: dict[str, set[str]] = {
    "triage": {"siem"},
    "enrichment": {"cmdb", "threat-intel"},
    "correlation": {"siem"},
    "response": {"containment"},
    "reporter": {"ticketing"},
    "verification": {"cmdb"},
}
_ROOT = os.environ.get("CAPABILITY_ROOT", "spike-root-secret").encode()
TIER = os.environ.get("CAPABILITY_TIER", "t1").lower()       # t1 = C-T1, t2 = C-T2
TTL = int(os.environ.get("CAPABILITY_TTL", "600"))            # t2: task-scoped lifetime (s)

# t2 replay cache: jti -> exp. ThreadingHTTPServer serves requests concurrently,
# so check-and-record must be atomic.
_SEEN: dict[str, int] = {}
_SEEN_LOCK = threading.Lock()


def sig(component_id: str) -> str:
    """Canonical component signature (matches soc_agent.capability; real: +schema+card)."""
    return hashlib.sha256(component_id.encode()).hexdigest()[:16]


def _path(cap: dict) -> list[str]:
    p = cap.get("path")
    return p if isinstance(p, list) and p and all(isinstance(x, str) for x in p) else []


def _exp(cap: dict) -> int:
    try:
        return int(cap.get("exp"))
    except (TypeError, ValueError):
        return -1


def _canonical(cap: dict) -> bytes:
    """What the HMAC covers. t1: the path only (unchanged C-T1). t2: path + task +
    exp + jti, so no binding can be altered without invalidating the token. `exp`
    is normalised to int so a JSON float round-trip cannot break authenticity."""
    msg = "->".join(sig(p) for p in _path(cap))
    if TIER == "t2":
        msg += f"|task={cap.get('task')}|exp={_exp(cap)}|jti={cap.get('jti')}"
    return msg.encode()


def _sign(cap: dict) -> dict:
    out = {k: v for k, v in cap.items() if k != "token"}
    out["token"] = hmac.new(_ROOT, _canonical(out), hashlib.sha256).hexdigest()
    return out


def _authentic(cap: dict) -> bool:
    token = cap.get("token")
    if not _path(cap) or not isinstance(token, str):
        return False
    expected = hmac.new(_ROOT, _canonical(cap), hashlib.sha256).hexdigest()
    return hmac.compare_digest(token, expected)


def _expired(cap: dict) -> bool:
    return int(time.time()) > _exp(cap)


def _legal_edge(src: str, dst: str) -> bool:
    """dst is reachable from src as a delegation OR a tool invocation."""
    return dst in DELEGATE.get(src, set()) or dst in TOOLS.get(src, set())


# --- decisions (pure; the HTTP layer is a thin wrapper) ----------------------
def mint(agent: str, task: str | None = None) -> dict:
    if agent not in ENTRY:
        return {"error": f"{agent!r} is not an entry agent"}
    cap: dict = {"path": [agent]}
    if TIER == "t2":
        if not task:
            return {"error": "t2 mint requires a task binding"}
        cap.update(task=str(task), exp=int(time.time()) + TTL, jti=uuid.uuid4().hex)
    return _sign(cap)


def attenuate(cap: dict, target: str) -> dict:
    if not _authentic(cap):
        return {"error": "token does not authenticate for the given path"}
    if TIER == "t2" and _expired(cap):
        return {"error": "token expired"}
    path = _path(cap)
    if not _legal_edge(path[-1], target):
        return {"error": f"illegal edge {path[-1]} -> {target}"}
    child: dict = {"path": path + [target]}
    if TIER == "t2":
        # Attenuation only ever restricts: task and exp are inherited, never reset.
        child.update(task=cap["task"], exp=_exp(cap), jti=uuid.uuid4().hex)
    return _sign(child)


def verify(cap: dict, action: dict) -> dict:
    """The resource being called is path[-1]; the call is legitimate iff the token
    authenticates, every edge is legal, and the action's target is that last hop
    (audience). t2 additionally requires: not expired, the request's task equals the
    bound task, and the jti has not been presented before. Check order fixes which
    reason an attack is attributed to (A5a -> target, A5b -> task, A5c -> jti/exp)."""
    if not _authentic(cap):
        return {"allow": False, "reason": "forged_or_mismatched_token"}
    path = _path(cap)
    for src, dst in zip(path, path[1:]):
        if not _legal_edge(src, dst):
            return {"allow": False, "reason": f"illegal_edge:{src}->{dst}"}
    if action.get("target") and action["target"] != path[-1]:
        return {"allow": False, "reason": "action_target_not_last_hop"}
    if TIER == "t2":
        if _expired(cap):
            return {"allow": False, "reason": "expired"}
        if action.get("task") != cap.get("task"):
            return {"allow": False, "reason": "task_mismatch"}
        now = int(time.time())
        with _SEEN_LOCK:
            for j in [j for j, e in _SEEN.items() if e < now]:   # prune expired
                del _SEEN[j]
            if cap.get("jti") in _SEEN:
                return {"allow": False, "reason": "replayed_jti"}
            _SEEN[cap["jti"]] = _exp(cap)
    return {"allow": True, "reason": "ok"}


# --- HTTP layer (stdlib only, so the PDP runs on a plain public python image) -
def _cap_of(b: dict) -> dict:
    """Request's capability. Accepts the opaque `cap` dict, or the pre-C-T2 flat
    {token, path} shape, so an older client keeps working during a rollout."""
    cap = b.get("cap")
    if isinstance(cap, dict):
        return cap
    return {"token": b.get("token"), "path": b.get("path")}


_ROUTES = {
    "/mint": lambda b: mint(b.get("agent", ""), b.get("task")),
    "/attenuate": lambda b: attenuate(_cap_of(b), b.get("target", "")),
    "/verify": lambda b: verify(_cap_of(b), b.get("action") or {}),
}


def _audit(route: str, body: dict, result: dict) -> None:
    """The reference monitor's audit trail: one line per decision to stdout, so
    `kubectl -n platform-zone logs deploy/capability-verifier` is the authoritative
    record of every capability decision the PDP is asked to make. NOTE: a call that
    presents NO token is denied at the edge PEP and never reaches here — its proof
    is the tool/agent log, not this one."""
    who = body.get("agent") or "->".join(_path(_cap_of(body))) or "?"
    target = body.get("target") or (body.get("action") or {}).get("target") or "-"
    if "allow" in result:                       # /verify
        verdict, detail = ("ALLOW" if result["allow"] else "DENY"), result.get("reason", "")
    elif result.get("error"):                   # /mint or /attenuate refused
        verdict, detail = "DENY", result["error"]
    else:                                        # /mint or /attenuate issued a token
        verdict, detail = "ISSUE", "->".join(result.get("path", []))
    if TIER == "t2":                             # bindings, for tracing a decision
        c = result if result.get("jti") else _cap_of(body)
        detail += f" task={str(c.get('task'))[:12]} jti={str(c.get('jti'))[:8]}"
    print(f"[pdp] {route:<11} {who:<26} target={target:<13} {verdict:<5} {detail}",
          flush=True)


def _serve(port: int) -> None:
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    class Handler(BaseHTTPRequestHandler):
        def _json(self, obj: dict) -> None:
            data = json.dumps(obj).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_POST(self) -> None:
            fn = _ROUTES.get(self.path)
            if fn is None:
                self.send_error(404)
                return
            n = int(self.headers.get("Content-Length", 0) or 0)
            body = json.loads(self.rfile.read(n) or b"{}")
            result = fn(body)
            _audit(self.path, body, result)
            self._json(result)

        def do_GET(self) -> None:
            if self.path == "/health":
                self._json({"ok": True})
            else:
                self.send_error(404)

        def log_message(self, *args) -> None:  # keep the log quiet
            pass

    print(f"[pdp] capability-verifier on :{port}  tier={TIER}"
          + (f" ttl={TTL}s" if TIER == "t2" else ""), flush=True)
    ThreadingHTTPServer(("0.0.0.0", port), Handler).serve_forever()


if __name__ == "__main__":
    _serve(int(os.environ.get("PORT", "8080")))
