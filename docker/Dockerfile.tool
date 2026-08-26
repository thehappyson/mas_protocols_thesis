# MCP tool image — one image for all six tool servers. Each tool runs as its own
# container off this image, started with a different `command` in compose
# (services/mcp-<name>/server.py). Internals are still the canned-data seams; no
# data layer here (that comes next).
FROM python:3.12-slim

WORKDIR /app

COPY docker/requirements-tool.txt /tmp/requirements-tool.txt
RUN pip install --no-cache-dir -r /tmp/requirements-tool.txt

COPY services/ /app/services/

# The concrete tool is chosen per-service via `command:` in compose, e.g.
#   command: ["python", "services/mcp-siem/server.py"]
