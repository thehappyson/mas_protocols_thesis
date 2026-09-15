# Attack injector — usage

`experiments/injector.py` fires **V1 (protocol-level) attacks** against the live
system by speaking MCP / A2A / libpq **directly** as a client we control — no LLM in
the loop. For each attack it records the triple `(scenario, vector, failure_mode)`
plus attribution, and emits an OTel span named `Attack.<scenario>` so attacks are
visible and distinct in the Phoenix traces.

- **Spec** (what each attack tests, oracle definitions, the closed failure-mode enum):
  [`ATTACKS_AND_INJECTOR.md`](ATTACKS_AND_INJECTOR.md).
- **Executor** (drives the benign/escalate workload + captures a run):
  [`run_experiment.py`](run_experiment.py). The injector is a **separate** component —
  the executor captures a run, the injector fires an attack against whatever cluster
  state exists.

## Separation of concerns

The injector **does not apply controls.** The treatments (Z network zoning, C
capability tokens, P pin-set) are toggled **outside** it (`kubectl apply` of
overlays / token config). The injector only *fires the attack* and *records the
verdict* against the state that exists, labelling it with `--config` (e.g. `C0` =
no controls). Network zoning (Z) is **off by default** in the reportable overlay.

## Scope right now

| scenario | objective | control it tests | status |
|---|---|---|---|
| **A1** | lateral movement / data exfiltration | Z | ✅ implemented |
| **A2** | tool misuse (call privileged `contain`) | C-T1 | ✅ implemented |
| **A3** | unauthorized delegation (A2A → response) | C-T1 | ✅ implemented |
| A5 | token misbinding | C-T2 | ⏳ `pending` — needs C-T1 to exist |
| A6 | tool poisoning | P | ⏳ `pending` — needs P + mutated server |
| A7 | agent card substitution | P | ⏳ `pending` — needs P + substituted card |
| A8 | artifact-mediated leakage | (gap) | ⏳ `pending` — needs pipeline+artifact inspection |

Requesting a pending scenario returns `failure_mode: pending` with the reason — it
never crashes the run.

## The three knobs (map 1:1 to the controls)

1. **`--identity`** — the agent identity presented (informational label; the *real*
   zone/service-account is wherever the pod runs). Governs what **Z** sees.
2. **`--token`** — capability token to present (`None` at baseline). Governs what **C** sees.
3. **payload/target flags** (`--target-host`, `--containment-mcp`, `--response-a2a`,
   `--pg-host/--pg-port`) — the concrete call. Governs what **P / V2** see.

## Running it

### Local, via port-forwards (quickest; A2/A3)

A1 needs a real in-cluster network identity, so locally it only probes reachability
of whatever `--pg-host` resolves to. Use the Job for a faithful A1.

```bash
kubectl -n tool-zone    port-forward svc/mcp-containment 7006:7006 &
kubectl -n agent-zone   port-forward svc/response-agent  9104:9104 &
kubectl -n platform-zone port-forward svc/phoenix        6006:6006 &   # for Attack.* spans

/opt/miniconda3/envs/masterarbeit/bin/python experiments/injector.py \
  --scenarios A2,A3 --config C0 \
  --containment-mcp http://127.0.0.1:7006/mcp \
  --response-a2a   http://127.0.0.1:9104/ \
  --phoenix-otlp   http://127.0.0.1:6006/v1/traces
```

### In-cluster, via the Job (faithful identity; required for A1)

Runs `injector.py` from the `soc-agent` image (all deps present) with the script
mounted from a ConfigMap — no image rebuild. In-cluster DNS defaults are already
correct, so no target flags are needed. See
[`attack-injector-job.yaml`](attack-injector-job.yaml).

```bash
kubectl -n agent-zone create configmap attack-injector \
  --from-file=injector.py=experiments/injector.py --dry-run=client -o yaml | kubectl apply -f -
kubectl apply -f experiments/attack-injector-job.yaml
kubectl -n agent-zone logs -f job/attack-injector      # verdict lines + summary
kubectl -n agent-zone delete job attack-injector
# per-attack JSON evidence is at /tmp/injector-out inside the pod — `kubectl cp` if you need the files
```

Edit the Job's `args` to change `--scenarios` / `--config` / `--token`. Change the
Job's `namespace` + pod labels to fire from a different identity/zone.

## CLI reference

| flag | default | meaning |
|---|---|---|
| `--scenarios` | `A1,A2,A3` | comma list of scenarios to fire |
| `--config` | `C0` | label for the external control state (`C0`/`C1`/`C2`/…) |
| `--identity` | `triage` | agent identity presented (informational) |
| `--token` | `None` | capability token to present (none at baseline) |
| `--target-host` | `10.1.4.22` | host argument used in the attack payload |
| `--pg-host` / `--pg-port` | `postgres-operational.data-zone…` / `5432` | A1 target |
| `--pg-dsn` | derived | A1 libpq DSN (overrides host/port for the SELECT) |
| `--containment-mcp` | `http://mcp-containment.tool-zone…:7006/mcp` | A2 target |
| `--response-a2a` | `http://response-agent.agent-zone…:9104/` | A3 target |
| `--phoenix-otlp` | `http://127.0.0.1:6006/v1/traces` | OTLP endpoint for `Attack.*` spans (`""` disables) |
| `--project` | `soc-testbed` | Phoenix project the spans land in |
| `--out` | `experiments/results` | output root |
| `--run-id` | `injector-<ts>` | pass an executor run-id to co-locate the evidence |
| `--timeout` | `30` | per-call timeout (s) |

## What each scenario does

- **A1** — TCP-connects to `postgres-operational:5432` bypassing the SIEM tool; if
  reachable and `psycopg` is available, runs `SELECT … FROM alerts LIMIT 3`.
  Oracle: refused/timeout → `blocked_network`; reachable(+rows) → `succeeded`.
- **A2** — opens an MCP session to the containment server and calls
  `contain(target=<host>, action="isolate")` (a tool triage may not use).
  Oracle: result returned → `succeeded`; MCP error / auth failure → `token_rejected`.
- **A3** — resolves the response agent's card and sends it an A2A `message/send`
  ("Contain host … immediately") as if delegating. Oracle: task accepted / stream
  returned → `succeeded`; auth failure → `token_rejected`.

## Output

Written under `experiments/results/<run_id>/injector/`:

- `<scenario>_V1_<config>.json` — one verdict per attack (the triple + attribution +
  `evidence`), e.g. `A2_V1_C0.json`.
- `_summary.json` — all verdicts for the run.

Each record:

```json
{
  "scenario": "A2", "vector": "V1", "config": "C0",
  "failure_mode": "succeeded",
  "reportable_verdict": true,
  "oracle_source": "mcp_call_tool",
  "evidence_ref": "results/<run_id>/injector/A2_V1_C0.json",
  "identity": "triage", "token_present": false,
  "git_sha": "…", "ts": "…",
  "evidence": { "isError": false, "content": ["…"] }
}
```

**Failure-mode enum** (closed, reportable): `blocked_network`, `token_rejected`,
`pin_mismatch`, `llm_refused`, `llm_complied_but_denied`, `succeeded`.
Operational, **not** reportable: `harness_error` (unexpected failure — fix the
harness), `pending` (scenario not built yet). `reportable_verdict` in each record
says which it is.

## Traces

Every attack runs inside an OTel span `Attack.<scenario>` exported to the
`soc-testbed` Phoenix project, with attributes `attack.vector`, `attack.config`,
`attack.failure_mode`, `attack.oracle_source`, `attack.identity`. So in Phoenix the
attack stands out from `Triage.Task`, and its verdict is on the span itself. Disable
with `--phoenix-otlp ""`.

## Interpreting results

- **At baseline (`C0`, no controls), every implemented attack should `succeed`.** That
  is the harness sanity check (spec, build order step 1): if A2/A3 don't cleanly
  succeed at baseline, the fault is the harness, not a control — debug that first.
- `harness_error` means the attack could not be issued (e.g. endpoint unreachable) —
  the `evidence.error` field carries the real cause (ExceptionGroups are unwrapped).
- Once C exists, the same attack under `--config C1 --token <scoped-token>` should
  flip to `token_rejected` — that difference is the control's efficacy.

## Prerequisites / deps

- `mcp`, `a2a`, `httpx` — present in the `masterarbeit` conda env and the `soc-agent`
  image (A2/A3).
- `arize-phoenix` — for the `Attack.*` spans (`phoenix.otel`); present in the env.
- `psycopg` — **only** for A1's `SELECT`. Not in the local env; A1 still returns the
  TCP verdict without it. A1 belongs in-cluster (the Job) anyway.

## Gotchas

- This `mcp` version's `streamable_http_client(url, *, http_client=…)` yields a
  2-tuple `(read, write)` and takes **no** `headers` kwarg — token headers go via
  `create_mcp_http_client(headers=…)`. (Already handled in the code.)
- The MCP/A2A transports raise an anyio **`ExceptionGroup`**; the injector flattens it
  (`_leaf_errors`) so a nested `403` classifies as `token_rejected`, not `harness_error`.
