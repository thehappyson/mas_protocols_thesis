# Step by step: H200 series — sweep → C0 → C0b → C1 → C2 (n = 1000)

Starting state: a fresh **H200** cluster, bootstrapped with
[`deployment/CLUSTER_BOOTSTRAP_reportable.md`](../deployment/CLUSTER_BOOTSTRAP_reportable.md)
steps 0–7 **including 3b** (`capability-root`, needed for the sweep on C2), the DB
seeded, vLLM Ready. Why this order and these parameters:
[`MEASUREMENT_RUNBOOK.md`](MEASUREMENT_RUNBOOK.md). Flag details and troubleshooting:
[`RUNNING_EXPERIMENTS.md`](RUNNING_EXPERIMENTS.md).

(This replaces the earlier n=30 A100 restart list; that one is in git history.)

**Three things that will bite otherwise:**
- **Restart vLLM before each condition and wait until it's Ready.** That empties its
  prefix cache (same seed → same prompts → a warm cache would flatter later conditions).
- **Keep `experiments/portforwards.sh` running** in its own terminal. It restarts
  forwards whose pods were replaced (apply, vLLM restart) by itself. Switch it only when
  the label's forward set changes (C2 → C0 and C0 → C1).
- **Executor first, then the injector** — never at the same time.

Rough timing: sweep ~30 min, each condition ~25 min vLLM restart + ~0.5–1 h executor +
~5 min injector. Whole series ≈ 6–8 h.

---

## 0. Once

**0.1** In every terminal you use:
```bash
export PY=/opt/miniconda3/envs/masterarbeit/bin/python
```
**0.2** The images are the ones you mean. It must print only your current tag:
```bash
kubectl kustomize --load-restrictor LoadRestrictionsNone deployment/overlays/reportable | grep "image: ghcr" | sort -u
```
**0.3** The GPU is the H200 and vLLM sees the expected KV cache:
```bash
kubectl -n platform-zone exec deploy/vllm -- nvidia-smi --query-gpu=name,memory.total --format=csv,noheader
```
```bash
kubectl -n platform-zone logs deploy/vllm | grep -iE "KV cache size|Maximum concurrency"
```
**0.4** Phoenix keeps traces on its volume — must say `Bound`:
```bash
kubectl -n platform-zone get pvc phoenix-data
```

---

## 1. Concurrency sweep (on C2)

**1.1** Apply C2 and wait:
```bash
kubectl kustomize --load-restrictor LoadRestrictionsNone deployment/overlays/reportable-c2 | kubectl apply -f -
```
```bash
kubectl -n agent-zone wait --for=condition=Available deploy --all --timeout=10m
```
```bash
kubectl -n tool-zone wait --for=condition=Available deploy --all --timeout=10m
```
```bash
kubectl -n platform-zone rollout status deploy/capability-verifier
```
Must print `tier=t2 ttl=600s`:
```bash
kubectl -n platform-zone logs deploy/capability-verifier | grep -m1 "tier="
```
**1.2** Restart vLLM and wait (up to ~25 min):
```bash
kubectl -n platform-zone rollout restart deploy/vllm
```
```bash
kubectl -n platform-zone rollout status deploy/vllm --timeout=25m
```
**1.3** Port-forwards, in their own terminal, left running:
```bash
experiments/portforwards.sh C2
```
**1.4** Sweep (~20–30 min):
```bash
$PY experiments/sweep.py --condition C2 --levels 8,16,32,64 --count 40 --vllm-metrics http://127.0.0.1:8000/metrics --pod-logs "platform-zone/capability-verifier"
```
**1.5** Read the table it prints (also `experiments/results/sweep-C2-<ts>.md`). Take
the **suggested concurrency** — or a lower one if a column looks off — and set it in
every terminal you drive from:
```bash
export CONC=32
```
(32 is a placeholder.) If you'd like a second opinion, paste the sweep table here before
continuing.

---

## 2. Down to C0

**2.1** Stop the forwards (Ctrl-C in their terminal). Apply C0:
```bash
kubectl kustomize --load-restrictor LoadRestrictionsNone deployment/overlays/reportable | kubectl apply -f -
```
**2.2** Remove what C2 left behind (`apply` never deletes): the PDP, and the
enforcement setting on agents and tools:
```bash
kubectl -n platform-zone delete deploy/capability-verifier svc/capability-verifier configmap/capability-verifier-src
```
```bash
kubectl -n agent-zone set env deploy --all CAPABILITY_ENFORCEMENT-
```
```bash
kubectl -n tool-zone set env deploy --all CAPABILITY_ENFORCEMENT-
```
**2.3** Wait, then verify — both counts must be `0`:
```bash
kubectl -n agent-zone wait --for=condition=Available deploy --all --timeout=10m
```
```bash
kubectl -n tool-zone wait --for=condition=Available deploy --all --timeout=10m
```
```bash
kubectl get deploy -n agent-zone -o yaml | grep -c CAPABILITY_ENFORCEMENT; kubectl get deploy -n tool-zone -o yaml | grep -c CAPABILITY_ENFORCEMENT
```
**2.4** Port-forwards for C0, in their own terminal, left running:
```bash
experiments/portforwards.sh C0
```

---

## 3. C0 run

**3.1** Restart vLLM and wait:
```bash
kubectl -n platform-zone rollout restart deploy/vllm
```
```bash
kubectl -n platform-zone rollout status deploy/vllm --timeout=25m
```
**3.2** Executor. Note the printed `run_id`:
```bash
$PY experiments/run_experiment.py --condition C0 --count 1000 --escalate-frac 0.5 --seed 1337 --concurrency $CONC --phoenix-endpoint http://127.0.0.1:6006 --vllm-metrics http://127.0.0.1:8000/metrics
```
Check the recap: `status: complete`, `alerts: 1000/1000`, `errors: 0`, `preemptions 0`,
`traces: ok`. The `setup:` line at the start must say H200.

If it stops (`status: incomplete` / Ctrl-C), continue it — same command for every condition:
```bash
$PY experiments/run_experiment.py --resume experiments/results/<run_id>
```
**3.3** Injector. Expected (each 10/10): A1/A2/A3 `succeeded`, A5a/b/c `n/a`. Note the `run_id`:
```bash
$PY experiments/injector.py --config C0 --scenarios A1,A2,A3,A5 --repeat 10 --containment-mcp http://127.0.0.1:7006/mcp --response-a2a http://127.0.0.1:9104/ --pg-host 127.0.0.1 --pg-port 15432 --phoenix-otlp http://127.0.0.1:6006
```
It must end with `wrote 60 verdict(s)` (6 per repetition) and no `✗ preflight failed`.

---

## 4. C0b run (the noise floor — a repeat of C0)

**4.1** Restart vLLM and wait (as in 3.1). The forwards heal themselves.

**4.2** Executor, same as 3.2 with `--condition C0b`. No injector run for C0b:
```bash
$PY experiments/run_experiment.py --condition C0b --count 1000 --escalate-frac 0.5 --seed 1337 --concurrency $CONC --phoenix-endpoint http://127.0.0.1:6006 --vllm-metrics http://127.0.0.1:8000/metrics
```

---

## 5. C1 run

**5.1** Apply C1 and wait:
```bash
kubectl kustomize --load-restrictor LoadRestrictionsNone deployment/overlays/reportable-c1 | kubectl apply -f -
```
```bash
kubectl -n agent-zone wait --for=condition=Available deploy --all --timeout=10m
```
```bash
kubectl -n tool-zone wait --for=condition=Available deploy --all --timeout=10m
```
```bash
kubectl -n platform-zone rollout status deploy/capability-verifier
```
Must print `tier=t1`:
```bash
kubectl -n platform-zone logs deploy/capability-verifier | grep -m1 "tier="
```
**5.2** Restart vLLM and wait (as in 3.1).

**5.3** Port-forwards: Ctrl-C the C0 script, start the C1 set (adds PDP + SIEM):
```bash
experiments/portforwards.sh C1
```
**5.4** Executor:
```bash
$PY experiments/run_experiment.py --condition C1 --count 1000 --escalate-frac 0.5 --seed 1337 --concurrency $CONC --phoenix-endpoint http://127.0.0.1:6006 --vllm-metrics http://127.0.0.1:8000/metrics --pod-logs "platform-zone/capability-verifier tool-zone/mcp-containment agent-zone/triage-agent"
```
Check the recap as in 3.2, plus `PDP decisions: …  DENY reasons: -`. Any DENY on this
benign workload is a false positive of the control — a finding, note it.

**5.5** Injector. Expected (each 10/10): A1 `succeeded`, A2/A3/A5a `token_rejected`, A5b/A5c `succeeded`:
```bash
$PY experiments/injector.py --config C1 --scenarios A1,A2,A3,A5 --repeat 10 --containment-mcp http://127.0.0.1:7006/mcp --response-a2a http://127.0.0.1:9104/ --siem-mcp http://127.0.0.1:7001/mcp --pdp http://127.0.0.1:8080 --pg-host 127.0.0.1 --pg-port 15432 --phoenix-otlp http://127.0.0.1:6006
```

---

## 6. C2 run

**6.1** Apply C2. Only the PDP changes and restarts; agents and tools stay as they are:
```bash
kubectl kustomize --load-restrictor LoadRestrictionsNone deployment/overlays/reportable-c2 | kubectl apply -f -
```
```bash
kubectl -n platform-zone rollout status deploy/capability-verifier
```
Must print `tier=t2 ttl=600s`:
```bash
kubectl -n platform-zone logs deploy/capability-verifier | grep -m1 "tier="
```
**6.2** Restart vLLM and wait (as in 3.1). Keep the C1 forward script running — C2
has the same forwards, and it re-attaches the 8080 forward to the new PDP pod by itself.

**6.3** Executor (the same command as 5.4 with `--condition C2`):
```bash
$PY experiments/run_experiment.py --condition C2 --count 1000 --escalate-frac 0.5 --seed 1337 --concurrency $CONC --phoenix-endpoint http://127.0.0.1:6006 --vllm-metrics http://127.0.0.1:8000/metrics --pod-logs "platform-zone/capability-verifier tool-zone/mcp-containment agent-zone/triage-agent"
```
If the recap shows `DENY reasons: {'expired': …}`, the TTL is shorter than the slowest
legitimate run under this load. That's a finding in itself; note it.

**6.4** Injector. Expected (each 10/10): A1 `succeeded`, A2/A3 `token_rejected`,
A5a/A5b/A5c `token_rejected` with `action_target_not_last_hop`, `task_mismatch` and `replayed_jti`:
```bash
$PY experiments/injector.py --config C2 --scenarios A1,A2,A3,A5 --repeat 10 --containment-mcp http://127.0.0.1:7006/mcp --response-a2a http://127.0.0.1:9104/ --siem-mcp http://127.0.0.1:7001/mcp --pdp http://127.0.0.1:8080 --pg-host 127.0.0.1 --pg-port 15432 --phoenix-otlp http://127.0.0.1:6006
```

---

## 7. Evaluation
```bash
$PY experiments/evaluate.py experiments/results/<C0-run> experiments/results/<C0b-run> experiments/results/<C1-run> experiments/results/<C2-run> --order C0,C0b,C1,C2 --noise-floor C0b --inj C0=experiments/results/<C0-inj>/injector --inj C1=experiments/results/<C1-inj>/injector --inj C2=experiments/results/<C2-inj>/injector --out experiments/results/evaluation.md --json experiments/results/evaluation.json
```
The warnings block at the top of `evaluation.md` should be empty. Optional: trust graph
of the C1/C2 runs (`RUNNING_EXPERIMENTS.md` §7).

Everything is now in `experiments/results/` — only then tear the cluster down.
If any run looks off, paste its run_id and I'll look at it before you continue.
