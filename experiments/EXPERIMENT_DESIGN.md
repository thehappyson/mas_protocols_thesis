# Experiment design — security/efficiency trade-off of MCP + A2A controls

Working notes for the thesis measurement. This is a living doc; the executor
(`experiments/run_experiment.py`) is deliberately kept **independent of the
decisions below** (see "Separation of concerns").

## Framing (settled)

We do **not** compare protocols (ANP is out of scope). We take the **one system**
(MCP agent→tool + A2A agent→agent) and measure what happens as we **add security
controls** to it. Independent variable = the security hardening; dependent
variables = efficiency cost + security benefit. The thesis question:
**"what does each control cost, and what does it buy?"**

## Treatments (the "toggles" — applied OUTSIDE the executor)

| control | status | what it stops |
|---|---|---|
| **Network zoning** (reportable NetworkPolicies, 5 zones) | **exists** (`deployment/overlays/reportable`) | direct cross-zone access (e.g. agent → data-zone Postgres) |
| **Capability tokens** (scoped per-agent auth on MCP/A2A calls) | **TO BUILD** (scaffold trust-anchor/registry is "FUTURE") | tool misuse / unauthorized delegation |
| (later) message signing, input sanitization, … | TBD | — |

> Sequencing note: **threat model → build missing controls → harness → run.**
> Capability tokens are a treatment we must implement before we can measure it.

## Threat model (backbone — MAESTRO-derived)

Concrete attacks, each designed to be stopped by a specific control (so the
trade-off reads cleanly: control off → attack succeeds + low overhead; on →
blocked + measured cost). Starter set; expand from MAESTRO layers / incident reports.

- **A1 — Lateral movement / data exfiltration:** an agent opens a direct psql
  connection to `postgres-operational`, bypassing the SIEM tool. Control: **network zoning**.
- **A2 — Excessive agency / tool misuse:** the triage agent invokes the
  `containment` MCP tool (only `response` should). Control: **capability tokens**
  (network zoning does not help — all tools sit in tool-zone).
- **A3 — Unauthorized delegation / privilege escalation:** a low agent sends an A2A
  task straight to `response`/`containment`, or replays a delegation. Control: **capability tokens** on A2A.
- **A4 — Indirect prompt injection:** a crafted alert *description* instructs the
  agent to exfiltrate or wrongly contain. Tests whether **least-privilege
  capabilities contain the blast radius even when the LLM is subverted** — a
  property network zoning alone cannot give.

## Conditions matrix

The grid of runs: security config × scenario, each repeated R times.

| config ↓ / scenario → | benign+escalate workload (efficiency) | A1 | A2 | A3 | A4 |
|---|---|---|---|---|---|
| baseline (no controls) | latency/msgs/net | ✗? | ✗? | ✗? | ✗? |
| + network zoning | … | ✓? | | | |
| + capability tokens | … | | ✓? | ✓? | ✓? |
| + both | … | ✓? | ✓? | ✓? | ✓? |

Full factorial = every cell; subset = skip non-interacting cells (e.g. A1 only vs
network zoning). Defining this grid *is* defining the experiment.

## Metrics (dependent variables)

- **Message count** — per-run A2A/MCP calls (from Phoenix spans; the executor also
  records the A2A status-update count as a coarse proxy).
- **Latency** — end-to-end per alert + per-hop (Phoenix spans).
- **Effectiveness** — predicted disposition vs `alert_ground_truth` (accuracy /
  precision / recall), joined by alert id.
- **In-cluster network activity** — DECISION PENDING. Options on Calico (OSS):
  - **Kubeshark** — captures/visualizes all in-cluster traffic, CNI-agnostic (good for "watch interactions").
  - **Microsoft Retina** — eBPF flow metrics, CNI-agnostic (good for volume/overhead).
  - **Calico denied-packet logging** — good specifically for *proving a block* (A1).
  - Hubble is Cilium-only → out.
  The executor has a pluggable network-capture hook; the backend is not yet chosen.

## Separation of concerns (executor contract)

`experiments/run_experiment.py` is the **executor**. It ONLY:
1. samples a workload (N alerts, benign/escalate split, seeded),
2. drives it through the live pipeline,
3. captures everything (agent responses, Phoenix traces, network activity, summary)
   into `results/<run_id>/`.

It does **not** apply treatments or attacks — those are toggled *outside* (kubectl
apply of overlays / capability-token config / attack-injector), so a run is a clean
capture of whatever cluster state exists. The executor records a free-form
`--condition` label (+ git sha, params, time window) so results are attributable.

## Open decisions (discuss later)

- Network-observability backend (Kubeshark / Retina / Calico logs).
- Capability-token design: what is a capability, who issues it, how checked on MCP vs A2A.
- Threat model: top-down from MAESTRO layers vs bottom-up from A1–A4; final attack set.
- Conditions matrix: full factorial vs subset; number of repetitions R; sample size N.
- Whether workload load/rate is a separate efficiency axis.
- Attack-injector implementation (where it lives, how it reports blocked/allowed).
