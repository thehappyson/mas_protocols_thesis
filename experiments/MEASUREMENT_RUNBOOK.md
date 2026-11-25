# Measurement runbook — C0 vs C1 (security–efficiency trade-off)

The end-to-end procedure for one comparison: drive the **same** workload through the
pipeline under **C0** (no capability control) and **C1** (C-T1 capability tokens),
fire the **same** attacks at each, capture everything locally, and render the
trade-off table + trust graph. The apparatus (`run_experiment.py`, `injector.py`,
`compare.py`, `trust_graph.py`) is fixed; this doc is just the drive order.

> One condition per cluster state. Switching C1→C0 on a live cluster is not clean
> (apply only adds), so treat each condition as its own cluster lifetime — matching
> the `--condition` label. See CLUSTER_BOOTSTRAP_reportable.md step 4.

## Fixed parameters (identical across conditions — do not change between C0 and C1)
```
SEED=1337   COUNT=30   ESCALATE_FRAC=0.5   CONCURRENCY=2
```
- `ESCALATE_FRAC=0.5` ensures the full delegation chain (where the PDP hops live) is
  exercised, so C1's overhead is actually measured.
- `CONCURRENCY` **must** match across conditions or latency isn't comparable.
- `COUNT=30` is the dry-run size — confirm the tables populate, then rerun with a
  larger COUNT (100+) for the reportable number.

## Preconditions (both conditions)
- Both images built+pushed at the current commit; tags in `deployment/base/kustomization.yaml` match.
- Dataset seeded: `raw_data/staged/wl.jsonl` exists and the operational DB is loaded
  (CLUSTER_BOOTSTRAP_reportable.md step 7).
- vLLM Ready.

---

## C0 — baseline (cluster on `overlays/reportable`)

**Port-forwards** (each in its own terminal, leave running):
```bash
kubectl -n agent-zone   port-forward svc/triage-agent    9101:9101
kubectl -n platform-zone port-forward svc/phoenix         6006:6006
kubectl -n tool-zone    port-forward svc/mcp-containment  7006:7006
kubectl -n agent-zone   port-forward svc/response-agent   9104:9104
```

**Efficiency + correctness** (executor):
```bash
/opt/miniconda3/envs/masterarbeit/bin/python experiments/run_experiment.py \
  --condition C0 --count 30 --escalate-frac 0.5 --seed 1337 --concurrency 2 \
  --phoenix-endpoint http://127.0.0.1:6006
# note the printed run_id, e.g. C0-2026....
```

**Security** (injector — attacks should SUCCEED at C0):
```bash
/opt/miniconda3/envs/masterarbeit/bin/python experiments/injector.py \
  --config C0 --scenarios A1,A2,A3 \
  --containment-mcp http://127.0.0.1:7006/mcp \
  --response-a2a    http://127.0.0.1:9104/ \
  --phoenix-otlp    http://127.0.0.1:6006
# note the printed run_id, e.g. injector-2026....
```
(A1 needs a Postgres port-forward `kubectl -n data-zone port-forward svc/postgres-operational 5432:5432` and `--pg-host 127.0.0.1`; or run the injector in-cluster for faithful A1.)

---

## C1 — capability tokens (cluster on `overlays/reportable-c1`)

**Extra precondition:** the `capability-root` secret exists (bootstrap step 3b) and
`capability-verifier` is Ready.

Same port-forwards as C0. For the **trust graph**, also forward Memgraph:
```bash
kubectl -n data-zone port-forward svc/memgraph 7687:7687   # only if using --load
```

**Efficiency + correctness** — note the added `--pod-logs` (captures the PDP audit trail):
```bash
/opt/miniconda3/envs/masterarbeit/bin/python experiments/run_experiment.py \
  --condition C1 --count 30 --escalate-frac 0.5 --seed 1337 --concurrency 2 \
  --phoenix-endpoint http://127.0.0.1:6006 \
  --pod-logs "platform-zone/capability-verifier tool-zone/mcp-containment agent-zone/triage-agent"
```

**Security** (injector — A2/A3 BLOCKED at C1; A5 is fired here too so C1→C2 is comparable):
```bash
# A5 needs the PDP (it obtains a legitimate token) and SIEM (a legal read-only hop):
kubectl -n platform-zone port-forward svc/capability-verifier 8080:8080
kubectl -n tool-zone     port-forward svc/mcp-siem            7001:7001
```
```bash
/opt/miniconda3/envs/masterarbeit/bin/python experiments/injector.py \
  --config C1 --scenarios A1,A2,A3,A5 \
  --containment-mcp http://127.0.0.1:7006/mcp \
  --response-a2a    http://127.0.0.1:9104/ \
  --siem-mcp        http://127.0.0.1:7001/mcp \
  --pdp             http://127.0.0.1:8080 \
  --phoenix-otlp    http://127.0.0.1:6006
```
Expected at C1: `A5a → token_rejected` (audience is already bound by the path — a
finding), `A5b → succeeded`, `A5c → succeeded`.

---

## C2 — capability tokens, tier C-T2 (cluster on `overlays/reportable-c2`)

Identical to C1 in every step — same port-forwards, same commands with
`--condition C2` / `--config C2`. Only the PDP's policy differs (task binding,
task-scoped TTL, one-time `jti`); agents and tools are unchanged.

Expected at C2: `A5a → token_rejected` (`action_target_not_last_hop`),
`A5b → token_rejected` (`task_mismatch`), `A5c → token_rejected` (`replayed_jti`).
The PDP's reason is in each injector JSON as `evidence.pdp_reason`.

Optional expiry variant of A5c (replay after the TTL instead of immediately):
`--scenarios A5c --a5c-wait 610` (> `CAPABILITY_TTL`) → `pdp_reason: expired`.

**Watch for:** a correctness drop vs C1 in `compare.py`. If late hops of long
escalations are refused as `expired` in the PDP log, `CAPABILITY_TTL` is shorter
than the slowest legitimate run — itself a measurable cost of "short TTL"; record
it, then raise the TTL in `overlays/reportable-c2` if you want the clean number.

---

## Report

**Trade-off table** (security + efficiency + correctness):
```bash
/opt/miniconda3/envs/masterarbeit/bin/python experiments/compare.py \
  experiments/results/<C0-run> experiments/results/<C1-run> \
  --inj-c0 experiments/results/<C0-injector-run>/injector \
  --inj-c1 experiments/results/<C1-injector-run>/injector \
  --out experiments/results/compare_C0_C1.md
```

The C1→C2 step uses the same tool with labels:
```bash
/opt/miniconda3/envs/masterarbeit/bin/python experiments/compare.py \
  experiments/results/<C1-run> experiments/results/<C2-run> \
  --inj-c0 experiments/results/<C1-injector-run>/injector \
  --inj-c1 experiments/results/<C2-injector-run>/injector \
  --c0-label C1 --c1-label C2 --out experiments/results/compare_C1_C2.md
```

**Trust graph** (C1/C2 — needs the run's `pod_logs/`):
```bash
# zero-dependency: always writes trust_graph.dot + trust_graph.cypher
/opt/miniconda3/envs/masterarbeit/bin/python experiments/trust_graph.py experiments/results/<C1-run>
```
Then either:
- **Report figure:** render `trust_graph.dot` with any Graphviz (`dot -Tpng … -o trust_graph.png`) or an online viewer.
- **Memgraph (interactive):** paste `trust_graph.cypher` into **Memgraph Lab** (no Python deps). *Or* automate the load:
  ```bash
  /opt/miniconda3/envs/masterarbeit/bin/pip install neo4j   # one-time
  /opt/miniconda3/envs/masterarbeit/bin/python experiments/trust_graph.py \
    experiments/results/<C1-run> --load --bolt bolt://127.0.0.1:7687
  ```

---

## What lands where (all durable on the local machine)
```
experiments/results/<condition-run>/
  config.json          params, condition, git_sha, window, capture status
  results.jsonl        per-alert: prompt, updates, final text, path, disposition, latency
  summary.json         latency (mean/median/p95), msgs/alert, accuracy vs ground truth
  traces/spans.jsonl   Phoenix spans for the window (agent + Attack.* spans, token counts)
  pod_logs/*.log       C1: PDP [pdp] audit trail + tool/agent [cap] lines
  trust_graph/         C1: trust_graph.dot + trust_graph.cypher (after trust_graph.py)
experiments/results/<injector-run>/injector/*.json   per-scenario security verdicts
experiments/results/compare_C0_C1.md                 the headline table
```

## Expected result shape (sanity)
- **Security:** C0 `A2/A3 → succeeded`; C1 `A2/A3 → token_rejected`. A1 depends on network
  control (Z, off here) — same verdict both conditions unless Z is toggled.
- **Efficiency:** C1 latency > C0 (PDP round-trips per hop); tokens/msgs ≈ equal.
- **Correctness:** accuracy + dispositions ≈ equal across conditions. If they diverge,
  the control is interfering with legitimate flow — a finding, not just overhead.
