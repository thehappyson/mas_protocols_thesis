# Running the experiments — operator guide

How to take a cluster from "deployed" to "results on disk" for each condition
(C0 / C0b / C1 / C2), what to check after every step, and what to do when something
breaks. This is the **how-to**. The measurement design (why these parameters, the
series order, what each table means) lives in [`MEASUREMENT_RUNBOOK.md`](MEASUREMENT_RUNBOOK.md);
the linear checklist in [`RUN_C0_C1_C2_STEPS.md`](RUN_C0_C1_C2_STEPS.md); attack
semantics in [`ATTACKS_AND_INJECTOR.md`](ATTACKS_AND_INJECTOR.md) and [`INJECTOR.md`](INJECTOR.md).

All commands run from the repo root with the conda env (never a repo `.venv`).
**Run this first in every new terminal** — every `$PY …` command below depends on it:
```bash
export PY=/opt/miniconda3/envs/masterarbeit/bin/python
```
> If you skip it, `$PY` expands to nothing and zsh tries to execute the script
> itself → `zsh: permission denied: experiments/run_experiment.py`.

After the sweep (§4) also set the chosen concurrency in every terminal you drive from:
```bash
export CONC=32
```
(32 is a placeholder — use the sweep's value.)

---

## 0. The shape of one experiment

| step | tool | measures | output |
|---|---|---|---|
| once | `sweep.py` | the concurrency to use for the whole series | `results/sweep-<COND>-<ts>.md` |
| A | `run_experiment.py` (executor) | efficiency + correctness on the benign/escalate workload | `results/<COND>-<ts>/` |
| B | `injector.py` (attacks) | security — 6 verdicts per repetition | `results/injector-<ts>/injector/` |
| C | `evaluate.py` (+ `compare.py`, `trust_graph.py`) | the report | `results/evaluation.md`, `<run>/trust_graph/` |

The tools never toggle controls. The condition is whatever overlay is applied;
`--condition` / `--config` only **label** it. A wrong label gives you a wrong
table, so check the cluster state first (§2).

| condition | overlay | what's on |
|---|---|---|
| **C0** | `deployment/overlays/reportable` | nothing (baseline) |
| **C0b** | `deployment/overlays/reportable` | nothing — repeat of C0 = noise floor |
| **C1** | `deployment/overlays/reportable-c1` | PDP + PEPs, tier **t1** (path-bound macaroons) |
| **C2** | `deployment/overlays/reportable-c2` | C1 + PDP tier **t2** (task binding, TTL 600 s, one-time `jti`) |

---

## 1. Preconditions — check once per cluster

- [ ] **Images match the code.** Both `newTag`s in `deployment/base/kustomization.yaml`
      equal the commit the images were built from. If `services/capability_client.py`
      or anything under `services/soc_agent/` changed, **both** images need a rebuild.
- [ ] **Capability root secret** (C1/C2 and the sweep, bootstrap step 3b):
      ```bash
      kubectl -n platform-zone get secret capability-root
      ```
- [ ] **Dataset staged + DB loaded** (bootstrap step 7): `raw_data/staged/wl.jsonl` exists.
- [ ] **Phoenix volume bound** (traces survive a Phoenix restart):
      ```bash
      kubectl -n platform-zone get pvc phoenix-data
      ```
- [ ] **vLLM Ready**:
      ```bash
      kubectl -n platform-zone get pods
      ```

**Switching conditions in place** (MEASUREMENT_RUNBOOK.md → "Series"):
- Upward (C0 → C1 → C2) is clean.
- DB rows from earlier conditions are harmless: ticketing only creates incidents and
  updates them by their own id, containment's `audit_log` is append-only, nothing reads
  them back.
- Downward (C1/C2 → C0) needs the cleanup in §2 — `apply` never deletes anything.

---

## 2. Apply the condition and verify it

Pick **one**:
```bash
kubectl kustomize --load-restrictor LoadRestrictionsNone deployment/overlays/reportable | kubectl apply -f -
```
```bash
kubectl kustomize --load-restrictor LoadRestrictionsNone deployment/overlays/reportable-c1 | kubectl apply -f -
```
```bash
kubectl kustomize --load-restrictor LoadRestrictionsNone deployment/overlays/reportable-c2 | kubectl apply -f -
```

Wait for the rollouts:
```bash
kubectl -n agent-zone wait --for=condition=Available deploy --all --timeout=10m
```
```bash
kubectl -n tool-zone wait --for=condition=Available deploy --all --timeout=10m
```

**C1/C2: confirm the PDP runs the tier you think it does.** This is the one check
that prevents a mislabeled run:
```bash
kubectl -n platform-zone logs deploy/capability-verifier | grep -m1 "tier="
```
Expect `tier=t1` for C1 and `tier=t2 ttl=600s` for C2.

**Downward to C0 (after the sweep on C2):** after applying `reportable`, remove what
C1/C2 left behind — the PDP and the enforcement setting:
```bash
kubectl -n platform-zone delete deploy/capability-verifier svc/capability-verifier configmap/capability-verifier-src
```
```bash
kubectl -n agent-zone set env deploy --all CAPABILITY_ENFORCEMENT-
```
```bash
kubectl -n tool-zone set env deploy --all CAPABILITY_ENFORCEMENT-
```
Then wait as above, and verify — both counts must be `0`:
```bash
kubectl get deploy -n agent-zone -o yaml | grep -c CAPABILITY_ENFORCEMENT; kubectl get deploy -n tool-zone -o yaml | grep -c CAPABILITY_ENFORCEMENT
```

**Restart vLLM before every condition** (empties the prefix cache — same seed, same
prompts, so a warm cache would flatter every later condition), and wait (≤ 25 min):
```bash
kubectl -n platform-zone rollout restart deploy/vllm
```
```bash
kubectl -n platform-zone rollout status deploy/vllm --timeout=25m
```

**After changing `services/capability-verifier/server.py`:** the PDP code comes
from a configMap with a fixed name, so re-applying updates the configMap but does
**not** restart the pod. Restart it explicitly:
```bash
kubectl -n platform-zone rollout restart deploy/capability-verifier
```
(A restart also clears the t2 replay cache, so a fresh run starts with an empty cache.)

---

## 3. Port-forwards — one self-healing script

One terminal per condition, left running:
```bash
experiments/portforwards.sh C0
```
(`C1` / `C2` add the PDP and SIEM forwards.) Every forward runs in a loop: when
kubectl exits (pod replaced by an apply or a vLLM restart, network blip) it is
restarted after 3 s, and an HTTP health check every 10 s restarts a forward that
hangs without exiting. Logs: `experiments/results/.portforwards/<svc>.log`. Ctrl-C
stops all of them. Switch the script (Ctrl-C, restart with the new label) when going
C0 → C1, since C1 adds forwards.

What it forwards (for reference / manual fallback):

| port | command | needed for | conditions |
|---|---|---|---|
| 9101 | `kubectl -n agent-zone port-forward svc/triage-agent 9101:9101` | executor (drives the workload) | all |
| 6006 | `kubectl -n platform-zone port-forward svc/phoenix 6006:6006` | trace export + `Attack.*` spans | all |
| 8000 | `kubectl -n platform-zone port-forward svc/vllm 8000:8000` | executor `--vllm-metrics` (GPU load) | all |
| 7006 | `kubectl -n tool-zone port-forward svc/mcp-containment 7006:7006` | A2, A5a | all |
| 9104 | `kubectl -n agent-zone port-forward svc/response-agent 9104:9104` | A3 | all |
| 15432 | `kubectl -n data-zone port-forward svc/postgres-operational 15432:5432` | A1 (`--pg-host 127.0.0.1 --pg-port 15432`) | all |
| 8080 | `kubectl -n platform-zone port-forward svc/capability-verifier 8080:8080` | A5 (gets a legit token) | C1, C2 |
| 7001 | `kubectl -n tool-zone port-forward svc/mcp-siem 7001:7001` | A5b, A5c | C1, C2 |
| 7687 | `kubectl -n data-zone port-forward svc/memgraph 7687:7687` | trust graph `--load` (not in the script) | optional |

Local port 15432 avoids clashing with a local Postgres. Phoenix via the public
NodePort (`http://<public-ip>:30606`) works too; the injector appends `/v1/traces`.

**Where to run it from.** The laptop works if it stays awake and online for the
whole run (~0.5–1 h per condition at n = 1000). If you need to move, run the same
commands (forwards + executor + injector) on a small CPU VM in the same Hyperstack
region with the kubeconfig and repo copied there — nothing else changes.

---

## 4. Once per series — the concurrency sweep (on C2)

On a C2 cluster (most PDP load, TTL, one-time `jti`), after a vLLM restart, with
`experiments/portforwards.sh C2` running:
```bash
$PY experiments/sweep.py --condition C2 --levels 8,16,32,64 --count 40 --vllm-metrics http://127.0.0.1:8000/metrics --pod-logs "platform-zone/capability-verifier"
```
~20–30 min. It runs 40 alerts per level (own seed per level, so no level profits from
another's prefix cache) and writes `results/sweep-C2-<ts>.md` with, per level:
alerts/min, gen tokens/s, peak running/waiting requests, peak KV use, preemptions,
latency and **non-LLM time** per path, PDP DENYs (`expired`).

**Suggested concurrency** = the highest level that, like every level below it, has
no errors, no preemptions, no `expired` DENYs and non-LLM time ≤ 1.25× the lowest
level. Non-LLM time is the overhead metric — if it rises, something besides the GPU
saturates (CPU throttling, Postgres) and would be measured as control cost. Pick the
value, `export CONC=<value>`, and use it for **every** condition.

Re-summarise existing sweep runs without driving:
```bash
$PY experiments/sweep.py --runs experiments/results/C2-sweep-c8-<ts> experiments/results/C2-sweep-c16-<ts>
```

---

## 5. Step A — executor (efficiency + correctness)

Fixed parameters, **identical across all conditions**:
```
--count 1000 --escalate-frac 0.5 --seed 1337 --concurrency $CONC
```

**C0** (C0b: the same with `--condition C0b`):
```bash
$PY experiments/run_experiment.py --condition C0 --count 1000 --escalate-frac 0.5 --seed 1337 --concurrency $CONC --phoenix-endpoint http://127.0.0.1:6006 --vllm-metrics http://127.0.0.1:8000/metrics
```
**C1** (C2: same with `--condition C2`). `--pod-logs` streams the PDP audit trail,
which the trust graph needs:
```bash
$PY experiments/run_experiment.py --condition C1 --count 1000 --escalate-frac 0.5 --seed 1337 --concurrency $CONC --phoenix-endpoint http://127.0.0.1:6006 --vllm-metrics http://127.0.0.1:8000/metrics --pod-logs "platform-zone/capability-verifier tool-zone/mcp-containment agent-zone/triage-agent"
```

**Before it starts** it checks the triage endpoint and Phoenix and exits in seconds
(code 2) if either is unreachable, and records the deployed setup (GPU via
`nvidia-smi` in the vLLM pod, vLLM image + args, every image and resource block) —
it prints `setup: GPU [...]  vLLM ...`. Check that line says H200.

**While it runs:** one line per alert with `[k/1000 · ETA …]`. Every finished alert
is appended to `results.jsonl` immediately.

**If a forward drops** (`⚠ lost connection …`): the interrupted alerts are not
recorded; the executor waits up to `--reconnect-wait` (600 s) for the endpoint,
then retries them (`✓ endpoint is back`). With the forward script running this heals
by itself. If the endpoint stays away, the run stops cleanly (`status: incomplete`,
exit code 3). Ctrl-C also stops it cleanly (`interrupted`). Either way, continue with:
```bash
$PY experiments/run_experiment.py --resume experiments/results/<run>
```
Resume reads the parameters from the run's `config.json` (passing different ones is
an error), re-samples the same alerts, skips the finished ones and appends a new time
segment; traces, pod logs and vLLM samples cover every segment.

**Check the recap it prints:**
- `status: complete`, `alerts: 1000/1000`, `errors: 0`. Write down the `run_id`.
- `retried:` small (a few is harmless; see evaluate's notes).
- `throughput: … alerts/min` close to the sweep's value at `$CONC`.
- `vLLM: … preemptions 0` (else the KV cache overflowed — lower `$CONC` for the
  whole series).
- `traces: ok, N spans` (≈ 26 per alert) and no `truncated chunks`.
- C1/C2: `PDP decisions: {...}  DENY reasons: -` on the benign workload. Any DENY is a
  false positive of the control (a finding). `expired` at C2 = TTL shorter than the
  slowest legitimate run under this load (MEASUREMENT_RUNBOOK.md → expected shape).

| flag | default | meaning |
|---|---|---|
| `--count` / `--escalate-frac` / `--seed` / `--concurrency` / `--condition` | 20 / 0.3 / 1337 / 2 / unlabeled | the workload; fixed per series |
| `--resume RUN_DIR` | — | continue an incomplete run (parameters come from its config) |
| `--vllm-metrics URL` | off | poll vLLM `/metrics` every 5 s → `vllm_metrics.jsonl` + summary |
| `--pod-logs "ns/deploy …"` | off | stream `kubectl logs -f` into `pod_logs/` (bare flag = the PDP) |
| `--reconnect-wait S` | 600 | how long to wait for a lost triage endpoint before stopping |
| `--trace-chunk-min M` | 10 | minutes of spans per Phoenix export request |
| `--no-traces` / `--no-setup` | off | skip trace export / setup recording |

---

## 6. Step B — injector (security)

Run it **after** the executor, not at the same time. Otherwise the attack
denials land inside the executor's `pod_logs` stream and show up as red edges in
the trust graph. C0b needs no injector run (same cluster state as C0).

**C0** (A5 is recorded as `n/a` without contacting anything, so the scenario set stays identical):
```bash
$PY experiments/injector.py --config C0 --scenarios A1,A2,A3,A5 --repeat 10 --containment-mcp http://127.0.0.1:7006/mcp --response-a2a http://127.0.0.1:9104/ --pg-host 127.0.0.1 --pg-port 15432 --phoenix-otlp http://127.0.0.1:6006
```
**C1** (C2: `--config C2`):
```bash
$PY experiments/injector.py --config C1 --scenarios A1,A2,A3,A5 --repeat 10 --containment-mcp http://127.0.0.1:7006/mcp --response-a2a http://127.0.0.1:9104/ --siem-mcp http://127.0.0.1:7001/mcp --pdp http://127.0.0.1:8080 --pg-host 127.0.0.1 --pg-port 15432 --phoenix-otlp http://127.0.0.1:6006
```

`A1,A2,A3,A5` = **6 verdicts per repetition** (A1, A2, A3, A5a, A5b, A5c) → it ends
with `wrote 60 verdict(s)` and a tally per scenario. Before each repetition a
**preflight** checks every endpoint; a dead forward stops it with exit code 2 and
names the forward, instead of writing `harness_error` records.

**Expected verdicts** (each 10/10). If these don't match, debug the harness before trusting any table:

| scenario | C0 | C1 | C2 | PDP reason (C2) |
|---|---|---|---|---|
| A1 lateral movement | `succeeded` (Z off) | same as C0 | same as C0 | — |
| A2 tool misuse | `succeeded` | `token_rejected` | `token_rejected` | `no_capability` (edge PEP) |
| A3 unauthorized delegation | `succeeded` | `token_rejected` | `token_rejected` | `no_capability` (edge PEP) |
| A5a audience | `n/a` | `token_rejected` | `token_rejected` | `action_target_not_last_hop` |
| A5b task | `n/a` | `succeeded` | `token_rejected` | `task_mismatch` |
| A5c replay | `n/a` | `succeeded` | `token_rejected` | `replayed_jti` |

- The PDP's reason is in each JSON as `evidence.pdp_reason`.
- A1 through the port-forward only probes reachability, and the tunnel bypasses
  NetworkPolicies — so it cannot test Z. With Z off that's what happens anyway. For a
  faithful A1 from a real in-cluster identity, use the Job (`INJECTOR.md`).
- **Optional expiry variant (C2 only):** replay A5c after the TTL (~10 min):
  ```bash
  $PY experiments/injector.py --config C2 --scenarios A5c --a5c-wait 610 --containment-mcp http://127.0.0.1:7006/mcp --siem-mcp http://127.0.0.1:7001/mcp --pdp http://127.0.0.1:8080 --phoenix-otlp http://127.0.0.1:6006
  ```
  Expected: `token_rejected`, `pdp_reason: expired`.

To keep the verdicts next to the executor run, pass `--run-id <C1-run>`. They then
land in `results/<C1-run>/injector/`, and `evaluate.py`/`compare.py` find them by themselves.

---

## 7. Step C — report

**All conditions in one evaluation** (`evaluate.py`, primary): side by side, split by
the path actually taken, paired per-alert overhead with 95 % bootstrap CIs, decision
stability against the C0b noise floor, Wilson intervals for accuracy, the security
matrix with k/R per mode:
```bash
$PY experiments/evaluate.py experiments/results/<C0-run> experiments/results/<C0b-run> experiments/results/<C1-run> experiments/results/<C2-run> --order C0,C0b,C1,C2 --noise-floor C0b --inj C0=experiments/results/<C0-inj>/injector --inj C1=experiments/results/<C1-inj>/injector --inj C2=experiments/results/<C2-inj>/injector --out experiments/results/evaluation.md --json experiments/results/evaluation.json
```
- **Overhead:** read the paired, path-matched Δ. Δ non-LLM s is the control's cost;
  the C0b row is what "no control change" looks like.
- **Decision stability:** `upper 95 %` is the bound for "the control does not change
  decisions"; `p > floor` small = more changes than the noise floor explains.
- **Process** (under Correctness): *how* the verdict was reached — routing (escalate →
  investigation chain, benign → short path), disposition consistent with the path, and
  strict (routed correctly *and* right verdict). A short-pathed escalate alert ending as
  `incident` is a correct verdict but was never investigated or contained. The decision
  table's *route changed* column shows a control altering the path even when the verdict survives.
- **Warnings at the top** must be empty, or explained: setup differences, incomplete
  runs, unmapped traces, injector `harness_error`s.
- Several `--inj` dirs for one label are pooled (e.g. a second injector run).

**Pairwise trade-off tables** (`compare.py`, optional; C0→C1 and C1→C2):
```bash
$PY experiments/compare.py experiments/results/<C0-run> experiments/results/<C1-run> --inj-c0 experiments/results/<C0-inj>/injector --inj-c1 experiments/results/<C1-inj>/injector --out experiments/results/compare_C0_C1.md
```
```bash
$PY experiments/compare.py experiments/results/<C1-run> experiments/results/<C2-run> --inj-c0 experiments/results/<C1-inj>/injector --inj-c1 experiments/results/<C2-inj>/injector --c0-label C1 --c1-label C2 --out experiments/results/compare_C1_C2.md
```
`control effective?` reads: `✅ yes` = the attack succeeded before and is blocked
now; `— (already blocked)` = blocked in both (e.g. A5a at C1 and C2);
`⚠️ NOT blocked` = still succeeds.

**Trust graph** (C1/C2 runs, needs `pod_logs/`). It always writes `.dot` and `.cypher`:
```bash
$PY experiments/trust_graph.py experiments/results/<C1-run>
```
Render `trust_graph/trust_graph.dot` with Graphviz, or paste `trust_graph.cypher`
into Memgraph Lab. Optional direct load (needs `pip install neo4j` in the env plus the 7687 forward):
```bash
$PY experiments/trust_graph.py experiments/results/<C1-run> --load --bolt bolt://127.0.0.1:7687
```

---

## 8. Where the evidence ends up

**Durable (local disk):**
```
experiments/results/<COND>-<ts>/
  config.json           params, condition, status, segments, setup, capture status, vLLM summary
  results.jsonl         per alert (appended live): prompt, updates, final text, path,
                        disposition, latency, retries, segment
  summary.json          latency mean/median/p95, msgs/alert, accuracy, throughput
  traces/spans.jsonl    Phoenix spans of all segments (incl. capability.* span attrs)
  vllm_metrics.jsonl    vLLM load every 5 s
  pod_logs/*.log        streamed: C1/C2 PDP [pdp] audit lines, PEP [cap] lines (timestamped)
  trust_graph/          after trust_graph.py
experiments/results/injector-<ts>/injector/
  <scenario>_V1_<config>_rNN.json   one verdict per attack and repetition (+ evidence, pdp_reason)
  _summary.json
experiments/results/sweep-<COND>-<ts>.md / .json
experiments/results/evaluation.md / .json, compare_*.md
```
**Ephemeral:** Phoenix keeps spans on a PVC, which survives a pod restart but not the
cluster. Pod stdout is lost on restart (the streamed `pod_logs/` are the copy).
Anything not captured into `results/` is gone with the cluster — capture **before**
tearing down.

---

## 9. Troubleshooting (seen in this project)

| symptom | cause | fix |
|---|---|---|
| `zsh: permission denied: experiments/….py` | `PY` not set in this terminal, so `$PY` expanded to nothing | `export PY=/opt/miniconda3/envs/masterarbeit/bin/python` (top of this doc) |
| executor exits at once: `✗ triage endpoint … unreachable` / `✗ Phoenix … unreachable` | forward not running (yet) | start `experiments/portforwards.sh <COND>`, wait ~5 s, retry |
| injector exits 2: `✗ preflight failed` | a forward the scenarios need is down | the message names it; check the script's terminal / `results/.portforwards/<svc>.log` |
| `harness_error` … `ConnectError` / `Server disconnected` in old injector runs | port-forward missing/dead (both n=30 C0 baselines) | re-run; the preflight now prevents this |
| executor `⚠ lost connection …` then `status: incomplete` (exit 3) | the triage forward stayed down > `--reconnect-wait` | fix the forward, then `--resume <run dir>` |
| executor `--resume`: `these differ: --count …` | resume always uses the run's own parameters | drop the flags; just `--resume <dir>` |
| `⚠ the deployed setup differs from the run's first segment` | something changed between segments (image, GPU, vLLM args, resources) | that run mixes setups: finish it only if the change is irrelevant, else start a new run |
| recap `preemptions` > 0 | KV cache full at this concurrency | lower `$CONC` for the **whole** series (re-run the sweep's lower levels) |
| recap `traces: … truncated chunks` | > 100k spans in one chunk | `--resume <dir> --trace-chunk-min 2` re-exports (spans are de-duplicated) |
| evaluate: `only k/n alerts matched to a trace` | spans dropped or not yet flushed | check Phoenix was up the whole run; agents' span queue is 16384 (`OTEL_BSP_MAX_QUEUE_SIZE`) |
| evaluate: `setup differs … not comparable` | runs from different GPU / vLLM / images / resources | don't compare them (e.g. A100 pilot vs H200 series) |
| `kubectl apply` fails: `spec.strategy.rollingUpdate: Forbidden` (phoenix) | Phoenix changed to `strategy: Recreate` (PVC); an older live Deployment still carries rollingUpdate | once, on that cluster: export traces first, then `kubectl -n platform-zone delete deploy/phoenix` and re-apply. Fresh clusters are unaffected |
| `phoenix-data` PVC `Pending` | no default StorageClass | set `storageClassName` in `base/platform/phoenix.yaml` (same one Postgres uses) |
| A5 `harness_error` with hint "is the PDP reachable" | 8080 forward missing, or PDP not deployed (C0 overlay applied) | check §2 / §3 |
| executor: `InternalError: [Errno -2] Name or service not known` | agents have enforcement on but no PDP (component not applied) | apply the C1/C2 overlay, not a hand-patched one |
| PDP `CreateContainerConfigError` | `capability-root` secret missing | bootstrap step 3b |
| `capability-verifier` NotFound (rollout/logs/port-forward) | cluster is on C0 (`overlays/reportable`), which has no PDP by design | skip the C1/C2-only steps, or apply `reportable-c1`/`-c2` |
| `job/db-seed` not found in data-zone | the cleanup `delete` ran before the Job finished (`logs -f` exits early while the init containers run) | bootstrap step 7: check row counts / TRUNCATE, apply, watch until `Completed`, then delete |
| db-seed `Error` with `duplicate key` in the `loader` log | seed is not idempotent; an earlier attempt loaded part of it | TRUNCATE, delete the Job, re-apply (bootstrap step 7) |
| tool pods `CrashLoopBackOff` right after a rebuild | image dependency missing (e.g. `httpx` once), or tag mismatch | `kubectl -n tool-zone logs deploy/<tool> --previous`; check both `newTag`s |
| Phoenix export `405 Method Not Allowed` | OTLP posted to the UI root | pass `…:6006` or `…/v1/traces`; current code normalizes either |
| PDP behaves like the old code | configMap updated but pod not restarted | `rollout restart deploy/capability-verifier` (§2) |
| C2 legit hops denied `expired` | TTL < slowest legitimate run | finding; raise `CAPABILITY_TTL` for the clean number |
| A5c `harness_error` "legitimate first use did not succeed" | the legit siem call itself failed (tool/DB), so a replay would prove nothing | check `kubectl -n tool-zone logs deploy/mcp-siem` |
