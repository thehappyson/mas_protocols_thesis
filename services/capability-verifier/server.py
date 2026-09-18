"""capability-verifier — the PDP (Policy Decision Point) for the C control.

The central reference monitor. It is the ONLY component that holds `root` and the
policy graph; agents and tool servers (PEPs) call it. Three endpoints:

  POST /mint       {agent}                  -> {token, path}      entry macaroon
  POST /attenuate  {token, path, target}    -> {token, path}      extend one hop (enforces the edge)
  POST /verify     {token, path, action}    -> {allow, reason}    authenticate + authorize

TOKEN CONSTRUCTION — `token = HMAC(root, sig(id0) -> sig(id1) -> ...)`, i.e. keyed
on `root` over the WHOLE path. Because every hop needs `root`, only the PDP can mint
any token: a token-holder cannot self-extend to a new hop or forge a different
identity. That is what confines a (possibly compromised) component to its scope.

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


def sig(component_id: str) -> str:
    """Canonical component signature (matches soc_agent.capability; real: +schema+card)."""
    return hashlib.sha256(component_id.encode()).hexdigest()[:16]


def _token(path: list[str]) -> str:
    """token = HMAC(root, sig(id0)->sig(id1)->...). Only a root-holder can compute it."""
    msg = "->".join(sig(p) for p in path).encode()
    return hmac.new(_ROOT, msg, hashlib.sha256).hexdigest()


def _legal_edge(src: str, dst: str) -> bool:
    """dst is reachable from src as a delegation OR a tool invocation."""
    return dst in DELEGATE.get(src, set()) or dst in TOOLS.get(src, set())


def _authentic(token: str, path: list[str]) -> bool:
    return bool(path) and hmac.compare_digest(token, _token(path))


# --- decisions (pure; the HTTP layer is a thin wrapper) ----------------------
def mint(agent: str) -> dict:
    if agent not in ENTRY:
        return {"error": f"{agent!r} is not an entry agent"}
    return {"token": _token([agent]), "path": [agent]}


def attenuate(token: str, path: list[str], target: str) -> dict:
    if not _authentic(token, path):
        return {"error": "token does not authenticate for the given path"}
    if not _legal_edge(path[-1], target):
        return {"error": f"illegal edge {path[-1]} -> {target}"}
    new_path = path + [target]
    return {"token": _token(new_path), "path": new_path}


def verify(token: str, path: list[str], action: dict) -> dict:
    """action = {'kind': 'delegate'|'invoke', 'target': <id>}. The resource being
    called is path[-1]; the call is legitimate iff the token authenticates, every
    edge in the path is legal, and the action's target is that last hop."""
    if not _authentic(token, path):
        return {"allow": False, "reason": "forged_or_mismatched_token"}
    for src, dst in zip(path, path[1:]):
        if not _legal_edge(src, dst):
            return {"allow": False, "reason": f"illegal_edge:{src}->{dst}"}
    if action.get("target") and action["target"] != path[-1]:
        return {"allow": False, "reason": "action_target_not_last_hop"}
    return {"allow": True, "reason": "ok"}


# --- HTTP layer (stdlib only, so the PDP runs on a plain public python image) -
_ROUTES = {
    "/mint": lambda b: mint(b.get("agent", "")),
    "/attenuate": lambda b: attenuate(b.get("token", ""), b.get("path", []), b.get("target", "")),
    "/verify": lambda b: verify(b.get("token", ""), b.get("path", []), b.get("action", {})),
}


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
            self._json(fn(body))

        def do_GET(self) -> None:
            if self.path == "/health":
                self._json({"ok": True})
            else:
                self.send_error(404)

        def log_message(self, *args) -> None:  # keep the log quiet
            pass

    print(f"[pdp] capability-verifier on :{port}", flush=True)
    ThreadingHTTPServer(("0.0.0.0", port), Handler).serve_forever()


if __name__ == "__main__":
    _serve(int(os.environ.get("PORT", "8080")))
