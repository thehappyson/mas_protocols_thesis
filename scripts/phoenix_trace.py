"""Print the most recent escalate-workflow trace from self-hosted Phoenix as a
nested tree: the delegation chain, per-span latency, and LLM token counts.

Reads traces straight from Phoenix (the existing OTel sink) over its client API;
no dependency on the agents' custom logs. Run after an escalate workflow.

    python scripts/phoenix_trace.py

Config (from env, with defaults):
    PHOENIX_BASE_URL       default http://127.0.0.1:6006
    PHOENIX_PROJECT_NAME   default soc-testbed
"""

import os

import pandas as pd
from phoenix.client import Client

BASE_URL = os.environ.get("PHOENIX_BASE_URL", "http://127.0.0.1:6006")
PROJECT = os.environ.get("PHOENIX_PROJECT_NAME", "soc-testbed")

ID, TRACE, PARENT = "context.span_id", "context.trace_id", "parent_id"


def _dur_ms(row) -> float | None:
    try:
        return (pd.to_datetime(row["end_time"]) - pd.to_datetime(row["start_time"])).total_seconds() * 1000
    except Exception:
        return None


def main() -> None:
    df = Client(base_url=BASE_URL).spans.get_spans_dataframe(project_name=PROJECT)
    if df.empty or "Triage.task" not in set(df["name"]):
        print("No Triage-rooted trace found. Run an escalate workflow first.")
        return
    trace_id = df[df["name"] == "Triage.task"][TRACE].unique()[-1]
    t = df[df[TRACE] == trace_id]
    rows = {r[ID]: r for _, r in t.iterrows()}
    children: dict = {}
    for _, r in t.iterrows():
        children.setdefault(r[PARENT], []).append(r[ID])
    roots = [r[ID] for _, r in t.iterrows()
             if r[PARENT] is None or str(r[PARENT]) == "nan" or r[PARENT] not in rows]

    print(f"Phoenix trace {trace_id[:12]} — {len(t)} spans (one connected trace)\n")

    def walk(sid: str, depth: int) -> None:
        r = rows[sid]
        d = _dur_ms(r)
        extra = ""
        ptok = r.get("attributes.llm.token_count.prompt")
        ctok = r.get("attributes.llm.token_count.completion")
        if pd.notna(ptok):
            extra += f"  [prompt={int(ptok)} completion={int(ctok)} tok]"
        agent = r.get("attributes.agent.name")
        if pd.notna(agent):
            extra += f"  agent={agent}"
        dur = f"{d:8.0f}ms" if d is not None else "        "
        print(f"  {'  ' * depth}{r['name'][:40]:40} {dur}{extra}")
        for ch in children.get(sid, []):
            walk(ch, depth + 1)

    for rt in roots:
        walk(rt, 0)


if __name__ == "__main__":
    main()
