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
import pathlib
import sys
from typing import Any

from mcp.server.mcpserver import MCPServer

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
import capability_client  # noqa: E402 (shared PEP, tool image)
from mcp_db import rows  # noqa: E402  (shared DB helper, tool image)

# Matches the container env convention in deployment/base/tools/threat-intel.yaml.
HOST = os.environ.get("MCP_LISTEN_HOST", "127.0.0.1")
PORT = int(os.environ.get("MCP_LISTEN_PORT", "7003"))
PATH = os.environ.get("MCP_PATH", "/mcp")
OPERATIONAL_DB_URL = os.environ.get(
    "OPERATIONAL_DB_URL", "postgresql://soc:soc@127.0.0.1:5432/soc_operational"
)

server = MCPServer(
    name="threat-intel",
    version="0.1.0",
    instructions=(
        "Synthetic SOC threat-intel service. Returns a reputation verdict for "
        "an indicator of compromise (IP, domain, url, or file hash)."
    ),
)

_VERDICTS = ("malicious", "suspicious", "clean")

# Known indicators now live in the operational `iocs` table (verdict keyed on
# the indicator). Indicators NOT in the table fall back to the deterministic
# hash mapping below, so every indicator still yields a stable verdict.


def _lookup_ioc(indicator: str) -> dict[str, Any]:
    """DATA-ACCESS SEAM (read) — backed by the operational `iocs` table.

    Found -> the real reputation row; not found -> the same deterministic
    hash-keyed verdict as the stub, so unknown indicators remain a stable lookup
    rather than a constant. Return shape unchanged
    ({indicator, verdict, confidence, source}).
    """
    found = rows(
        OPERATIONAL_DB_URL,
        "SELECT indicator, verdict, confidence, source FROM iocs WHERE indicator = %s",
        (indicator,),
    )
    if found:
        return found[0]

    digest = hashlib.sha256(indicator.encode()).digest()
    verdict = _VERDICTS[digest[0] % len(_VERDICTS)]
    confidence = round(0.50 + (digest[1] / 255) * 0.49, 2)  # 0.50–0.99, stable
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


capability_client.install_pep(server)  # C control: verify tools/call at the PDP

if __name__ == "__main__":
    server.run(
        transport="streamable-http",
        host=HOST,
        port=PORT,
        streamable_http_path=PATH,
    )
