"""Threat Intel MCP tool server — streamable HTTP transport.

One of six MCP tool servers in the SOC testbed (see
deployment/base/tools/threat-intel.yaml, which deploys this as
`mcp-threat-intel` on port 7003).

DESIGN PRINCIPLE: the protocol machinery is real, the domain logic is stubbed.
The MCP interface below is genuine; behind it there is no threat-intel platform
and no reputation feed.

DATA-ACCESS SEAM: the MCP tool method calls a separate data-access function
(`_lookup_ioc`) that is the single, clearly-marked place a real DB (or feed)
query will later go. The MCP method, schema, and validation are final; only the
data-access innards are provisional. This is a READ tool. The seam KEYS the
verdict on the indicator, so it behaves as a lookup rather than a constant.

Written against MCP Python SDK 2.0.0 (server class `MCPServer`; transport via
`run(transport="streamable-http", ...)`).

Run:
    python services/mcp-threat-intel/server.py
Endpoint:
    http://127.0.0.1:7003/mcp
"""

from __future__ import annotations

import hashlib
import os
from typing import Any

from mcp.server.mcpserver import MCPServer

# Matches the container env convention in deployment/base/tools/threat-intel.yaml.
HOST = os.environ.get("MCP_LISTEN_HOST", "127.0.0.1")
PORT = int(os.environ.get("MCP_LISTEN_PORT", "7003"))
PATH = os.environ.get("MCP_PATH", "/mcp")

server = MCPServer(
    name="threat-intel",
    version="0.1.0",
    instructions=(
        "Synthetic SOC threat-intel service. Returns a reputation verdict for "
        "an indicator of compromise (IP, domain, url, or file hash)."
    ),
)

_VERDICTS = ("malicious", "suspicious", "clean")

# A few explicitly-known indicators so the canned data lines up with the rest of
# the testbed (e.g. the SIEM alert's outbound destination).
_KNOWN_INDICATORS: dict[str, dict[str, Any]] = {
    "198.51.100.77": {"verdict": "suspicious", "confidence": 0.72},
    "10.14.7.32": {"verdict": "clean", "confidence": 0.90},
}


def _lookup_ioc(indicator: str) -> dict[str, Any]:
    """DATA-ACCESS SEAM (read). The single place a real DB/feed query will go.

    # TODO: replace canned return with real DB query
    #   e.g. SELECT verdict, confidence, ... FROM ioc_reputation
    #   WHERE indicator = :indicator  (against the operational Postgres / feed).

    STUB: known indicators come from a small table; everything else is mapped
    deterministically from a hash of the indicator so the verdict is KEYED on
    the indicator (a lookup) rather than a fixed constant. No real reputation
    data is consulted.
    """
    known = _KNOWN_INDICATORS.get(indicator)
    if known is not None:
        verdict, confidence = known["verdict"], known["confidence"]
    else:
        digest = hashlib.sha256(indicator.encode()).digest()
        verdict = _VERDICTS[digest[0] % len(_VERDICTS)]
        # 0.50–0.99, stable per indicator.
        confidence = round(0.50 + (digest[1] / 255) * 0.49, 2)

    return {
        "indicator": indicator,
        "verdict": verdict,
        "confidence": confidence,
        "source": "synthetic-ti (stub)",
    }


@server.tool(
    description=(
        "Look up the reputation of an indicator of compromise (IP, domain, "
        "URL, or file hash). Returns a verdict of malicious, suspicious, or "
        "clean with a confidence score."
    )
)
def lookup_ioc(indicator: str) -> dict[str, Any]:
    """Return a reputation verdict for an indicator.

    Args:
        indicator: The IOC to look up (IP, domain, URL, or hash).
    """
    return _lookup_ioc(indicator)


if __name__ == "__main__":
    server.run(
        transport="streamable-http",
        host=HOST,
        port=PORT,
        streamable_http_path=PATH,
    )
