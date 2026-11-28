# Measurement runbook — C0 / C1 / C2 (security–efficiency trade-off)

The measurement design: drive the **same** workload through the pipeline under each
condition, fire the **same** attacks at each, capture everything locally, and render
the evaluation. The apparatus (`run_experiment.py`, `injector.py`, `sweep.py`,
`evaluate.py`, `compare.py`, `trust_graph.py`) is fixed; this doc is the **design and
drive order**. Operator details (all flags, port-forwards, troubleshooting):
[`RUNNING_EXPERIMENTS.md`](RUNNING_EXPERIMENTS.md). Linear copy-paste checklist:
[`RUN_C0_C1_C2_STEPS.md`](RUN_C0_C1_C2_STEPS.md).

| condition | overlay | control |
|---|---|---|
| **C0** | `overlays/reportable` | none (baseline) — no PDP exists |
| **C0b** | `overlays/reportable` | none — a **repeat of C0** (the noise floor, see below) |
| **C1** | `overlays/reportable-c1` | capability tokens, tier t1 (path-bound macaroons) |
| **C2** | `overlays/reportable-c2` | tier t2: C1 + task binding, task-scoped TTL, one-time `jti` |

Comparisons: **C0 → C1** (what capability tokens buy and cost), **C1 → C2** (what the
stronger tier buys and costs), each against the **C0 ↔ C0b** noise floor.

> **The n=30 A100 runs are the pilot.** They validated the apparatus; they are not
> pooled with the H200 series (different GPU → not comparable; `evaluate.py` warns when
> setups differ).

## Fixed parameters (identical across ALL conditions)

| parameter | value | why |
|---|---|---|
| GPU | **1× H200 141 GB** (NVL/PCIe or SXM — same card for every condition) | BF16 leaves ~70 GB KV cache → 32–64 alerts in flight |
| model / serving | Qwen3.8-27B, **BF16, no quantization**, vLLM image + flags as in `base/platform/vllm.yaml` | the system under test stays the real model |
| `COUNT` | **1000** | see "Why n = 1000" |
| `ESCALATE_FRAC` | **0.5** | the full delegation chain (where the PDP hops live) is exercised |
| `SEED` | **1337** | same seed → same 1000 alerts in every condition → paired comparison |
| `CONCURRENCY` | **from the sweep** (`$CONC`, below) | latency/throughput are only comparable at the same value |
| injector | `--scenarios A1,A2,A3,A5 --repeat 10` | 6 verdicts × 10 per condition; A5 is `n/a` at C0, so every table has the same rows |

`run_experiment.py` records the actual setup (GPU, vLLM image/args, all images,
resources) in each run's `config.json`; `evaluate.py` refuses silence when they differ.

### Why n = 1000
- **Decision stability** ("the control does not change decisions") is the claim that
  needs n: with 0 changed decisions the exact one-sided 95 % upper bound on the change
  rate is ≈ 3/n → **0.3 % at n = 1000** (10 % at n = 30).
- **Accuracy**: Wilson ±≈0.02 at n = 1000 (±0.12 at n = 30).
- **Control overhead** (paired Δ non-LLM time) is already tight at n = 30; n = 1000
  makes it per-path robust.
- **Security** verdicts are deterministic → repetitions (`--repeat 10`), not n.

### Why the noise floor (C0b)
vLLM is not bit-deterministic across batch compositions, even at temperature 0, so a
repeat of the *same* condition changes some decisions (the pilot's two C0 runs already
disagreed on 3/30 alerts — on different images, so an upper estimate). C0b measures that
rate; `evaluate.py --noise-floor C0b` tests whether C1/C2 change **more** decisions than
C0b does (Fisher exact, one-sided). The same row is the noise floor for latency deltas.

### Why the sweep (before the series)
Concurrency is chosen once, on **C2** (the most demanding: most PDP load, TTL, one-time
`jti`), by `sweep.py`: the highest level with no errors, no vLLM preemptions, no
`expired` DENYs and **flat non-LLM time** (≤ +25 % vs the lowest level). Rising non-LLM
time means something besides the GPU saturates (CPU throttling of PDP/tools/agents,
Postgres) — that would be *measured as control overhead*, so it must be excluded.
Latency itself rises with concurrency by design (batching).

## Series on one cluster — in place, in this order

```
sweep (C2)  →  downgrade to C0  →  C0  →  C0b  →  C1  →  C2
```

- **Upward in place is clean.** C0 → C1 adds the PDP and flips enforcement on; C1 → C2
  only changes the PDP's env (the PDP restarts, which empties its replay cache).
- **DB carry-over is harmless.** The ticketing tool only creates incidents and updates
  them by their own id; containment's `audit_log` is append-only; nothing reads either
  back. So rows from an earlier condition cannot influence a later one.
- **Downward (C2 → C0, after the sweep) needs a manual cleanup**: `apply` never deletes,
  so the PDP and `CAPABILITY_ENFORCEMENT` would stay behind. Three commands —
  RUNNING_EXPERIMENTS.md §2.
- **Restart vLLM before every condition** (and before the sweep) and wait for Ready:
  it empties the prefix cache. The same seed means the same prompts, so a warm cache
  would make every later condition look faster.

## Order within one condition
1. `kubectl apply` the overlay; verify (C1/C2: `tier=` line of the PDP log).
2. Restart vLLM, wait Ready (≤ 25 min).
3. Port-forwards: `experiments/portforwards.sh <C0|C1|C2>`, left running. It restarts
   any forward whose pod was replaced (apply, vLLM restart) by itself; only switch it
   (Ctrl-C, start with the new label) when going C0 → C1, which adds the PDP/SIEM forwards.
4. Executor (efficiency + correctness), ~0.5–1 h at n = 1000 (estimate; the sweep gives
   the real number). Survives dropped forwards; `--resume` if it stops.
5. **Then** the injector (security). Not concurrently: the executor's `--pod-logs`
   stream would otherwise contain the attack denials, which the trust graph would draw
   as denied legitimate edges. (C0b: no injector — same cluster state as C0.)

## Report

Primary — all conditions in one evaluation, against the noise floor:
```bash
$PY experiments/evaluate.py experiments/results/<C0-run> experiments/results/<C0b-run> experiments/results/<C1-run> experiments/results/<C2-run> --order C0,C0b,C1,C2 --noise-floor C0b --inj C0=experiments/results/<C0-inj>/injector --inj C1=experiments/results/<C1-inj>/injector --inj C2=experiments/results/<C2-inj>/injector --out experiments/results/evaluation.md --json experiments/results/evaluation.json
```
Read: **Security** (k/10 per mode), **Overhead** (paired, path-matched Δ non-LLM s =
the control's cost; C0b's row = the latency noise floor), **Decision stability**
(change rate, its upper 95 % bound, `p > floor`, route changes), **Correctness** and
**Process** (routing vs ground truth, disposition consistent with the path, strict =
both — the verdict alone hides short-pathed escalate alerts that were never investigated).

Optional pairwise trade-off tables (`compare.py`, C0→C1 and C1→C2) and the **trust
graph** of the C1/C2 runs (`trust_graph.py`, needs `pod_logs/`) — RUNNING_EXPERIMENTS.md §6.

## What lands where (all durable on the local machine)
```
experiments/results/<condition-run>/
  config.json          params, condition, status, time SEGMENTS, setup (GPU, vLLM, images,
                       resources), capture status, vLLM load summary
  results.jsonl        per alert (appended live): prompt, updates, final text, path,
                       disposition, latency, retries
  summary.json         latency, msgs/alert, accuracy, throughput (alerts/min)
  traces/spans.jsonl   Phoenix spans of all segments (agent + Attack.* spans, token counts)
  vllm_metrics.jsonl   vLLM load samples every 5 s (running/waiting/KV/preemptions/tokens)
  pod_logs/*.log       streamed during the run — C1/C2: PDP [pdp] audit trail (+ task/jti
                       at C2), tool/agent [cap] lines
  trust_graph/         C1/C2: trust_graph.dot + .cypher (after trust_graph.py)
experiments/results/<injector-run>/injector/*_rNN.json   security verdicts (+ evidence.pdp_reason)
experiments/results/sweep-C2-<ts>.md                     the concurrency decision
experiments/results/evaluation.md / .json                the report
```
Phoenix keeps spans on a PVC (survives a pod restart, not the cluster) — the executor's
export is the durable copy. Capture everything before tearing the cluster down.

## Expected result shape (sanity)
- **Security** (each cell k/10 with k = 10):

  | scenario | C0 | C1 | C2 |
  |---|---|---|---|
  | A1 | `succeeded` (Z off; via port-forward Z is bypassed anyway) | = C0 | = C0 |
  | A2, A3 | `succeeded` | `token_rejected` | `token_rejected` |
  | A5a | `n/a` | `token_rejected` | `token_rejected` (`action_target_not_last_hop`) |
  | A5b | `n/a` | `succeeded` | `token_rejected` (`task_mismatch`) |
  | A5c | `n/a` | `succeeded` | `token_rejected` (`replayed_jti`) |

  If C0 A2/A3 don't cleanly succeed, the fault is the harness — debug that first.
  `harness_error` is never a verdict (INJECTOR.md).
- **Efficiency:** C1 non-LLM time > C0 (PDP round-trips per hop); C2 ≈ C1 (same number
  of PDP calls, slightly more work per call); tokens/LLM calls ≈ equal. The relative
  overhead is larger than on the A100 pilot because LLM time shrinks while the PDP
  cost stays — the honest number.
- **Decision stability:** C1/C2 change rate ≈ the C0b noise floor (`p > floor` not
  small). The PDP log of the executor run should contain **no** `DENY` lines on the
  benign workload; any DENY is a false positive of the control (a finding).
- **C2 `expired` DENYs** on legitimate hops mean the TTL (600 s) is shorter than the
  slowest legitimate run under this load — a measurable cost of "short TTL". Record it;
  raise `CAPABILITY_TTL` in `overlays/reportable-c2` only if you also want the clean number.
