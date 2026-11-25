#!/usr/bin/env python
"""trust_graph.py — offline trust-graph builder from a run's PDP audit trail.

OFFLINE ANALYSIS INSTRUMENT (never in the request path): reads the PDP audit log
captured by `run_experiment.py --pod-logs` and reconstructs the *trust graph* the
capability control actually exercised — which component was authorized to delegate
to / invoke which other, and where the PDP ISSUED, ALLOWED or DENIED. Nodes are
components (agents/tools); edges carry issue/allow/deny counts.

Outputs (always, zero external dependencies):
    <out>/trust_graph.dot      Graphviz source for the report figure
    <out>/trust_graph.cypher   MERGE statements to paste into Memgraph Lab
Optional (`--load`, needs `pip install neo4j` + a Bolt port-forward):
    pushes the same graph into Memgraph over Bolt for interactive exploration.

Source: the PDP log line format from services/capability-verifier/server.py:
    [pdp] /verify     triage->enrichment   target=enrichment  ALLOW ok
This is a C1-only artifact (C0 has no PDP). Denied edges are the interesting ones:
they are exactly the attacks/illegitimate hops the control refused.

Usage:
    python experiments/trust_graph.py results/C1-<ts>
    python experiments/trust_graph.py results/C1-<ts> --load --bolt bolt://127.0.0.1:7687
"""

from __future__ import annotations

import argparse
import pathlib
import re

# Component kinds — used only to label edges (delegate vs invoke) and shape nodes.
TOOLS = {"siem", "cmdb", "threat-intel", "runbook", "ticketing", "containment"}

_LINE = re.compile(
    r"\[pdp\]\s+(?P<route>/\S+)\s+(?P<who>\S+)\s+target=(?P<target>\S+)\s+"
    r"(?P<verdict>ISSUE|ALLOW|DENY)\s*(?P<detail>.*)")


def kind(node: str) -> str:
    return "tool" if node in TOOLS else "agent"


# --- parse + build -----------------------------------------------------------
def parse_pdp_log(path: pathlib.Path) -> list[dict]:
    decisions = []
    for line in path.read_text().splitlines():
        m = _LINE.search(line)
        if m:
            decisions.append(m.groupdict())
    return decisions


def build_graph(decisions: list[dict]) -> tuple[dict, dict]:
    """nodes: {id: {kind, entry, denied_entry}}; edges: {(src,dst): {type, issue, allow, deny}}."""
    nodes: dict[str, dict] = {}
    edges: dict[tuple[str, str], dict] = {}

    def node(n: str) -> dict:
        return nodes.setdefault(n, {"kind": kind(n), "entry": False, "denied_entry": 0})

    def edge(s: str, d: str) -> dict:
        return edges.setdefault((s, d), {
            "type": "invoke" if kind(d) == "tool" else "delegate",
            "issue": 0, "allow": 0, "deny": 0})

    for dc in decisions:
        route, who, verdict = dc["route"], dc["who"], dc["verdict"]
        path = who.split("->") if who and who != "-" else []
        if route == "/mint":
            n = node(path[0] if path else who)
            if verdict == "ISSUE":
                n["entry"] = True
            elif verdict == "DENY":
                n["denied_entry"] += 1
            continue
        # /attenuate and /verify carry a path; the last hop is the edge in question
        if len(path) >= 2:
            for p in path:
                node(p)
            e = edge(path[-2], path[-1])
            if verdict == "ISSUE":
                e["issue"] += 1
            elif verdict == "ALLOW":
                e["allow"] += 1
            elif verdict == "DENY":
                e["deny"] += 1
        elif path:
            node(path[0])
    return nodes, edges


# --- renderers (zero-dependency) ---------------------------------------------
def to_dot(nodes: dict, edges: dict) -> str:
    L = ["digraph trust {", '  rankdir=LR;',
         '  node [fontname="Helvetica"]; edge [fontname="Helvetica"];']
    for n, meta in sorted(nodes.items()):
        shape = "box" if meta["kind"] == "agent" else "ellipse"
        style = ', style=filled, fillcolor="#e8f0fe"' if meta["entry"] else ""
        extra = f'\\n(denied entry x{meta["denied_entry"]})' if meta["denied_entry"] else ""
        L.append(f'  "{n}" [shape={shape}{style}, label="{n}{extra}"];')
    for (s, d), e in sorted(edges.items()):
        # red if the edge was ever denied, else black; label with counts
        color = "red" if e["deny"] else ("black" if e["allow"] or e["issue"] else "gray")
        parts = []
        if e["issue"]:
            parts.append(f'issue={e["issue"]}')
        if e["allow"]:
            parts.append(f'allow={e["allow"]}')
        if e["deny"]:
            parts.append(f'DENY={e["deny"]}')
        lbl = f'{e["type"]}\\n' + " ".join(parts)
        dash = ', style=dashed' if e["deny"] and not (e["allow"] or e["issue"]) else ""
        L.append(f'  "{s}" -> "{d}" [color={color}, label="{lbl}"{dash}];')
    L.append("}")
    return "\n".join(L)


def to_cypher(nodes: dict, edges: dict) -> str:
    L = ["// Trust graph — paste into Memgraph Lab (or run via mgconsole).",
         "MATCH (n) DETACH DELETE n;"]
    for n, meta in sorted(nodes.items()):
        L.append(
            f'MERGE (:Component {{id:"{n}", kind:"{meta["kind"]}", '
            f'entry:{str(meta["entry"]).lower()}, denied_entry:{meta["denied_entry"]}}});')
    for (s, d), e in sorted(edges.items()):
        rel = e["type"].upper()  # DELEGATE / INVOKE
        L.append(
            f'MATCH (a:Component {{id:"{s}"}}), (b:Component {{id:"{d}"}}) '
            f'MERGE (a)-[:{rel} {{issue:{e["issue"]}, allow:{e["allow"]}, deny:{e["deny"]}}}]->(b);')
    return "\n".join(L)


# --- optional live load -------------------------------------------------------
def load_memgraph(bolt: str, nodes: dict, edges: dict) -> dict:
    try:
        from neo4j import GraphDatabase
    except ImportError:
        return {"loaded": False, "reason": "neo4j driver not installed "
                "(pip install neo4j) — use the .cypher file via Memgraph Lab instead"}
    try:
        driver = GraphDatabase.driver(bolt, auth=None)
        with driver.session() as s:
            s.run("MATCH (n) DETACH DELETE n")
            for n, meta in nodes.items():
                s.run("MERGE (c:Component {id:$id}) SET c.kind=$k, c.entry=$e, c.denied_entry=$de",
                      id=n, k=meta["kind"], e=meta["entry"], de=meta["denied_entry"])
            for (src, dst), e in edges.items():
                rel = e["type"].upper()
                s.run(f"MATCH (a:Component {{id:$s}}),(b:Component {{id:$d}}) "
                      f"MERGE (a)-[r:{rel}]->(b) SET r.issue=$i, r.allow=$al, r.deny=$dn",
                      s=src, d=dst, i=e["issue"], al=e["allow"], dn=e["deny"])
        driver.close()
        return {"loaded": True, "bolt": bolt, "nodes": len(nodes), "edges": len(edges)}
    except Exception as e:  # noqa: BLE001
        return {"loaded": False, "reason": f"{type(e).__name__}: {e}"}


def main() -> int:
    ap = argparse.ArgumentParser(description="Build a trust graph from a run's PDP audit log")
    ap.add_argument("run_dir", type=pathlib.Path, help="results/<run_id> (C1; must have pod_logs/)")
    ap.add_argument("--pdp-log", type=pathlib.Path, default=None,
                    help="override PDP log path (default: <run_dir>/pod_logs/platform-zone_capability-verifier.log)")
    ap.add_argument("--out", type=pathlib.Path, default=None, help="output dir (default: <run_dir>/trust_graph)")
    ap.add_argument("--load", action="store_true", help="also push to Memgraph over Bolt")
    ap.add_argument("--bolt", default="bolt://127.0.0.1:7687", help="Bolt endpoint for --load")
    a = ap.parse_args()

    pdp_log = a.pdp_log or a.run_dir / "pod_logs" / "platform-zone_capability-verifier.log"
    if not pdp_log.exists():
        print(f"PDP log not found: {pdp_log}\n"
              f"Run the C1 experiment with --pod-logs so the audit trail is captured.")
        return 1

    decisions = parse_pdp_log(pdp_log)
    nodes, edges = build_graph(decisions)
    if not nodes:
        print(f"No [pdp] decisions parsed from {pdp_log} (is this a C1 run?)")
        return 1

    out = a.out or a.run_dir / "trust_graph"
    out.mkdir(parents=True, exist_ok=True)
    (out / "trust_graph.dot").write_text(to_dot(nodes, edges))
    (out / "trust_graph.cypher").write_text(to_cypher(nodes, edges))
    denied = sum(e["deny"] for e in edges.values())
    print(f"parsed {len(decisions)} decisions -> {len(nodes)} nodes, {len(edges)} edges "
          f"({denied} denied hops)")
    print(f"wrote {out}/trust_graph.dot  and  trust_graph.cypher")
    print("  render figure:  dot -Tpng trust_graph.dot -o trust_graph.png   (or any Graphviz)")
    print("  memgraph:       paste trust_graph.cypher into Memgraph Lab")
    if a.load:
        print("load:", load_memgraph(a.bolt, nodes, edges))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
