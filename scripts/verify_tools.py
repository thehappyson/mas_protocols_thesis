"""Verify all six MCP tool servers: connect over streamable HTTP, list tools,
call each method, confirm canned data returns through the data-access seam.
"""

import asyncio
import json

from mcp import Client

# (label, url, [(tool_name, args), ...])
TARGETS = [
    ("siem", "http://127.0.0.1:7001/mcp", [
        ("next_alerts", {"since": None, "limit": 5}),
    ]),
    ("cmdb", "http://127.0.0.1:7002/mcp", [
        ("lookup_asset", {"asset_id": "10.14.7.32"}),
        ("lookup_user", {"user_id": "jdoe"}),
    ]),
    ("threat-intel", "http://127.0.0.1:7003/mcp", [
        ("lookup_ioc", {"indicator": "198.51.100.77"}),
        ("lookup_ioc", {"indicator": "8.8.8.8"}),
        ("lookup_ioc", {"indicator": "evil.example.com"}),
    ]),
    ("runbook", "http://127.0.0.1:7004/mcp", [
        ("search_runbook", {"query": "data exfiltration", "limit": 3}),
    ]),
    ("ticketing", "http://127.0.0.1:7005/mcp", [
        ("create_incident", {"title": "Exfil on fin-ws-0447", "description": "4.2GB out", "severity": "high"}),
        ("update_incident", {"incident_id": "INC-DEADBEEF", "status": "in_progress", "note": "isolating host"}),
    ]),
    ("containment", "http://127.0.0.1:7006/mcp", [
        ("contain", {"target": "10.14.7.32", "action": "isolate_host"}),
        ("contain", {"target": "10.14.7.32", "action": "frobnicate"}),
    ]),
]


async def check(label: str, url: str, calls: list) -> bool:
    ok = True
    print("=" * 74)
    print(f"{label}  ({url})")
    async with Client(url) as c:
        listed = await c.list_tools()
        names = [t.name for t in listed.tools]
        print(f"  tools: {names}")
        for t in listed.tools:
            req = t.input_schema.get("required", [])
            props = list(t.input_schema.get("properties", {}).keys())
            print(f"    - {t.name}: params={props} required={req}")

        called = set()
        for name, args in calls:
            if name not in names:
                print(f"  MISSING TOOL: {name}")
                ok = False
                continue
            res = await c.call_tool(name, args)
            called.add(name)
            if res.is_error:
                print(f"  {name}({args}) -> ERROR")
                ok = False
                continue
            payload = res.structured_content
            print(f"  {name}({json.dumps(args)}) ->")
            print(f"      {json.dumps(payload)}")

        # every advertised tool should have been exercised
        untested = set(names) - called
        if untested:
            print(f"  NOTE: advertised but not called in this run: {untested}")
    return ok


async def main() -> int:
    results = {}
    for label, url, calls in TARGETS:
        try:
            results[label] = await check(label, url, calls)
        except Exception as exc:
            print(f"  {label} FAILED: {exc!r}")
            results[label] = False
    print("=" * 74)
    print("SUMMARY")
    for label, good in results.items():
        print(f"  {'PASS' if good else 'FAIL'}  {label}")
    return 0 if all(results.values()) else 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
