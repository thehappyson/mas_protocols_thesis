# Cluster bootstrap — REPORTABLE tier (5-zone)

Deploys `deployment/overlays/reportable`: the full **5 zones** (agent, tool,
platform, **data**, experiment). This is the comparable tier for measurement runs.
For a quick dev deploy use the **minimal** tier instead → `CLUSTER_BOOTSTRAP_minimal.md`.

**Three standing conditions** sit on top of it (step 4). The measurement series switches between them in place on one cluster (C0b = a repeat of C0):

| condition | overlay | adds |
|---|---|---|
| C0 | `overlays/reportable` | nothing — **no PDP / capability-verifier exists** |
| C1 | `overlays/reportable-c1` | PDP `capability-verifier` + enforcement on every agent/tool (tier t1) |
| C2 | `overlays/reportable-c2` | C1 with the PDP on tier t2 |

Every step marked **C1/C2 only** below fails on a C0 cluster by design — there is no
`capability-verifier` to wait for, restart or port-forward. Skip them for C0.

> **Network zoning (control Z) is OFF by default.** The restrictive NetworkPolicies
> live in `components/network-policies` and are NOT included by the reportable
> overlay (Z is out of scope as a finding; it is only toggled on for the A1 positive
> control — see the overlay header). So by default agents CAN reach the DB directly.
>
> **Key difference from minimal:** minimal folds the DB into platform-zone.
> Reportable keeps **`data-zone` separate**. **You MUST create the `data-zone`
> namespace** (step 1) — if it's missing, `postgres-operational` never schedules,
> and everything that needs the DB (tools, the db-seed loader) fails.

Hyperstack has no cluster hibernate → the cluster is deleted when idle and
recreated. Everything inside is ephemeral; the GHCR images and the `model-storage`
S3 bucket persist. Build + push your own private images before step 4.

> **GPU node.** The n = 1000 measurement series runs on **one H200 141 GB** (NVL/PCIe
> or SXM — same card for the whole series), BF16, no quantization; the n = 30 pilot ran
> on an A100 80 GB. The manifests are GPU-agnostic (`nvidia.com/gpu: 1`); the GPU type
> is a fixed experimental parameter, recorded per run by `run_experiment.py`. Runs from
> different GPUs are not comparable. Drive order: `experiments/RUN_C0_C1_C2_STEPS.md`.

## What is recreated every time
- The GPU worker's container-storage relocation to the big disk (step 2)
- All **5** namespaces
- `ghcr-pull` (agent-zone, tool-zone, experiment-zone) + `vllm-s3-creds` (platform-zone, data-zone)
- C1/C2 (and the sweep): the `capability-root` secret (platform-zone)
- All workloads (via the kustomize apply); the PDP only for C1/C2
- Phoenix's trace volume (`phoenix-data` PVC, default StorageClass)

---

## Per-cluster steps

Run from the repo root.

### 0. Point kubectl at the new cluster + set secrets
```bash
export KUBECONFIG=/absolute/path/to/new-kubeconfig
export GHCR_PAT='ghp_xxx'          # GitHub PAT, read:packages
export S3_KEY='xxx'                # Hyperstack Object Storage access key
export S3_SECRET='xxx'             # Hyperstack Object Storage secret
kubectl get nodes                  # master + GPU worker Ready
```

### 1. Namespaces — FIVE zones (data-zone is the one minimal omits)
```bash
for ns in agent-zone tool-zone platform-zone data-zone experiment-zone; do
  kubectl create namespace "$ns"
done
```

### 2. GPU worker: relocate container storage to the 750 GB disk — REQUIRED, do it FIRST
The worker's ~100 GB root disk can't hold the vLLM image (~30 GB unpacked) alongside
everything else → `DiskPressure` evicts pods. Point containerd at the 750 GB
`/ephemeral` disk before deploying. (Or provision a ≥200 GB root disk and skip this.)
```bash
WORKER=$(kubectl get nodes -o name | sed 's|node/||' | grep -- '-default-' | head -1); echo "$WORKER"
cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata: {name: node-cleaner, namespace: kube-system}
spec:
  nodeName: ${WORKER}
  hostPID: true
  restartPolicy: Never
  tolerations: [{operator: Exists}]
  containers:
    - name: c
      image: busybox
      command: ["sleep","3600"]
      securityContext: {privileged: true}
      volumeMounts: [{name: host, mountPath: /host}]
  volumes: [{name: host, hostPath: {path: /}}]
EOF
kubectl -n kube-system wait --for=condition=Ready pod/node-cleaner --timeout=120s
```
**On a new node flavor (e.g. the first H200 cluster), check the disk layout first** —
the relocation below assumes a big disk mounted at `/ephemeral`:
```bash
kubectl -n kube-system exec node-cleaner -- chroot /host lsblk -o NAME,SIZE,MOUNTPOINT
```
```bash
kubectl -n kube-system exec node-cleaner -- chroot /host df -h / /ephemeral
```
- Root disk ≥ 200 GB → skip the relocation.
- Big disk mounted elsewhere → replace `/ephemeral` in the command below with that mount.
- No `/ephemeral` and a small root → stop and ask; don't run the relocation blind.
```bash
kubectl -n kube-system exec node-cleaner -- chroot /host systemd-run --unit=relocate-containerd \
  /bin/bash -c 'systemctl stop kubelet; systemctl stop containerd; rm -rf /var/lib/containerd; mkdir -p /ephemeral/containerd; ln -sfn /ephemeral/containerd /var/lib/containerd; systemctl start containerd; systemctl start kubelet'
kubectl wait --for=condition=Ready node/${WORKER} --timeout=300s
```
(The helper pod is destroyed when containerd restarts — expected.)

### 3. Secrets (ghcr-pull for private images; vllm-s3-creds in BOTH platform-zone and data-zone)
Secrets are namespace-scoped. `vllm-s3-creds` is needed in **platform-zone** (vLLM streams
the model) **and** in **data-zone** (the Step 7 `db-seed` loader runs there, since reportable
keeps the DB in data-zone). Create both up front — using the same real creds you export:
```bash
for ns in agent-zone tool-zone experiment-zone; do
  kubectl -n "$ns" create secret docker-registry ghcr-pull \
    --docker-server=ghcr.io --docker-username=thehappyson --docker-password="$GHCR_PAT"
done
for ns in platform-zone data-zone; do
  kubectl -n "$ns" create secret generic vllm-s3-creds \
    --from-literal=AWS_ACCESS_KEY_ID="$S3_KEY" --from-literal=AWS_SECRET_ACCESS_KEY="$S3_SECRET"
done
```
> Both must hold REAL, non-empty values — if `$S3_KEY`/`$S3_SECRET` aren't exported in this
> shell, the secret is created with empty strings and the S3 fetch later fails with `Access Denied`.
> Verify: `kubectl -n data-zone get secret vllm-s3-creds -o jsonpath='{.data.AWS_ACCESS_KEY_ID}' | base64 -d; echo`

### 3b. Capability-token root — C1/C2 (always create it for the measurement series: the sweep runs on C2)
The PDP (capability-verifier) needs a `capability-root` secret in **platform-zone** —
the master key it mints/verifies macaroons with. It is NOT committed; create it before
deploying C1/C2 (else the PDP stays `CreateContainerConfigError`). Creating it on a C0
cluster is harmless (nothing reads it), so you may always create it:
```bash
kubectl -n platform-zone create secret generic capability-root \
  --from-literal=root="$(head -c32 /dev/urandom | base64)"
```
> Only the PDP ever reads `root` (agents/tools never see it). Keep it stable across PDP
> restarts — recreating it invalidates any in-flight token. Rotate (C1/C2 cluster only)
> = recreate the secret, then `kubectl -n platform-zone rollout restart deploy/capability-verifier`.

### 4. Deploy the overlay — C0, C1 or C2
**C1 = C0 + the capability-tokens component** (deploys the PDP, mounts its source from
a configMap, flips `CAPABILITY_ENFORCEMENT=true` on every agent + tool). **C2 = C1 with
the PDP on tier t2** (task binding, TTL, one-time jti). C1/C2 require step 3b's secret
**and** images built at a commit that contains the capability code.

C0 — baseline, no capability layer, **no PDP**:
```bash
kubectl kustomize --load-restrictor LoadRestrictionsNone deployment/overlays/reportable | kubectl apply -f -
```
C1 — capability tokens, tier t1 (step 3b first):
```bash
kubectl kustomize --load-restrictor LoadRestrictionsNone deployment/overlays/reportable-c1 | kubectl apply -f -
```
C2 — capability tokens, tier t2 (step 3b first):
```bash
kubectl kustomize --load-restrictor LoadRestrictionsNone deployment/overlays/reportable-c2 | kubectl apply -f -
```

Verify (all conditions):
```bash
kubectl get pods -A
```
```bash
kubectl get networkpolicy -A    # default: "No resources found" (Z is off)
```
```bash
kubectl -n platform-zone get pvc phoenix-data    # Bound (Pending = no default StorageClass)
```
> **Existing cluster, older manifests:** Phoenix now uses `strategy: Recreate` (its PVC
> is ReadWriteOnce). If the live Deployment was created before that change, the apply
> fails with `spec.strategy.rollingUpdate: Forbidden`. Once per such cluster: export
> any traces you still need, then `kubectl -n platform-zone delete deploy/phoenix` and
> re-apply. Fresh clusters are unaffected.
Verify — **C1/C2 only** (on C0 these fail with NotFound, which is correct):
```bash
kubectl -n platform-zone rollout status deploy/capability-verifier
```
```bash
kubectl -n platform-zone logs deploy/capability-verifier | grep -m1 "tier="   # C1: tier=t1   C2: tier=t2 ttl=600s
```

> **PDP code changes** (`services/capability-verifier/server.py`): the source is a
> configMap with a fixed name, so re-applying updates it but does NOT restart the pod.
> After every re-apply with changed PDP code:
> `kubectl -n platform-zone rollout restart deploy/capability-verifier`.
>
> **Switching conditions on a live cluster** — the measurement series does exactly
> this (sweep on C2 → C0 → C0b → C1 → C2 on one cluster). `kubectl apply` only adds/updates:
> - **Upward (C0 → C1 → C2) applies cleanly** (C1→C2 only changes the PDP's env; the
>   PDP restarts, which also empties its replay cache).
> - **DB rows carry over, harmlessly:** ticketing only creates incidents and updates
>   them by their own id, containment's `audit_log` is append-only, and nothing reads
>   either back — earlier rows cannot influence a later condition.
> - **Downward (C1/C2 → C0) needs a manual cleanup** — the PDP and the enforcement env
>   stay behind otherwise. The three commands are in
>   `experiments/RUNNING_EXPERIMENTS.md` §2 ("Downward to C0").
> - **Restart vLLM before every condition** (step 6's first two commands) — it empties
>   the prefix cache, which would otherwise flatter every later condition.

### 5. Seed the model — ONLY if the bucket is empty (unchanged; talks to S3)
```bash
kubectl -n platform-zone run s3check --rm -it --restart=Never --image=public.ecr.aws/aws-cli/aws-cli:2.27.0 \
  --overrides='{"spec":{"containers":[{"name":"s3check","image":"public.ecr.aws/aws-cli/aws-cli:2.27.0","command":["/bin/sh","-c","aws configure set default.s3.addressing_style path && aws s3 ls --endpoint-url $AWS_ENDPOINT_URL s3://model-storage/Qwen3.8-27B/"],"env":[{"name":"AWS_ENDPOINT_URL","value":"https://ca1.obj.nexgencloud.io"},{"name":"AWS_DEFAULT_REGION","value":"us-east-1"},{"name":"AWS_REQUEST_CHECKSUM_CALCULATION","value":"when_required"},{"name":"AWS_RESPONSE_CHECKSUM_VALIDATION","value":"when_required"}],"envFrom":[{"secretRef":{"name":"vllm-s3-creds"}}]}]}}'
```
> Uses the AWS CLI image (pinned): MinIO removed `minio/mc` from Docker Hub, and
> `quay.io/minio/mc` is not anonymously pullable any more.
If empty:
```bash
kubectl apply -f deployment/seed-model-job.yaml
kubectl -n platform-zone logs -f job/seed-model      # wait for "seed complete"
kubectl -n platform-zone delete -f deployment/seed-model-job.yaml
```

### 6. Bring up / verify vLLM
```bash
kubectl -n platform-zone rollout restart deploy/vllm
kubectl -n platform-zone rollout status deploy/vllm --timeout=25m
kubectl -n platform-zone port-forward svc/vllm 8000:8000 &
curl -s localhost:8000/v1/models     # should list Qwen/Qwen3.8-27B
```
How much KV cache the GPU leaves for requests (H200 BF16: far more than the A100's) —
this bounds the concurrency the sweep can reach:
```bash
kubectl -n platform-zone logs deploy/vllm | grep -iE "KV cache size|Maximum concurrency"
```

### 6.5 Network zoning (Z) — ONLY when you toggled Z on (skip by default)
By default the reportable overlay ships **without** NetworkPolicies, so the probe
below prints `CONNECTED` — that is the **expected** default, not an error.

Only for the A1 positive-control run you turn Z on (uncomment the
`components/network-policies` line in `overlays/reportable/kustomization.yaml`, or
`kubectl apply -k deployment/components/network-policies` out-of-band). Then
`kubectl get networkpolicy -A` lists 4 (agent/tool/data/platform zones), and you must
confirm the CNI (Calico here) actually enforces them. The slim agent image has Python
but no `nc`, so probe with Python:
```bash
kubectl -n agent-zone exec deploy/triage-agent -- python -c "import socket; socket.create_connection(('postgres-operational.data-zone.svc.cluster.local',5432),5); print('CONNECTED')"
```
- **Z off (default):** prints `CONNECTED`. ✓
- **Z on (correct):** hangs ~5s then errors — **no `CONNECTED`** (blocked). ✓
- **Z on but prints `CONNECTED`:** the CNI is NOT enforcing — the Z run is invalid; fix the CNI.

With Z on, sanctioned paths are unaffected: tools reach the DB (tool-zone → data-zone
allowed), and agents reach vLLM:8000 / Phoenix:6006 (platform-zone allows all zones).

### 7. Load the real dataset + drive the pipeline
The pipeline is driven over the **real SIEVE log dataset** (`raw_data/SIEVE_*.csv`;
the synthetic workload-generator was dropped). Each row is a pre-labelled log event
whose *category* is the ground truth; `stage_dbs.py` maps it to an alert, rewrites the
victim to a synthetic CMDB asset (universal hit) and ~40% of attack sources to a seeded
IOC (partial hit), so the escalate/benign branch is driven by reasoning, not one lookup.
Build the seed + driving manifest and upload the seed:
```bash
export AWS_ACCESS_KEY_ID=<key>; export AWS_SECRET_ACCESS_KEY=<secret>
/opt/miniconda3/envs/masterarbeit/bin/python scripts/stage_dbs.py --upload   # → raw_data/staged/seed_*.sql + wl.jsonl, uploads seed
```
> Full SIEVE is ~600k alerts (`seed_alerts.sql` ~140 MB). For a smaller SIEM store,
> `stage_dbs.py --limit N` stages a deterministic N-alert sample.
Load it into Postgres. Under reportable the DB is in **`data-zone`**, so the loader runs
there (the overlay pins the namespace — no `sed`). This relies on the `vllm-s3-creds`
secret you created in data-zone in Step 3, and on `postgres-operational` being Running.

**Run these one at a time — do NOT paste them as one block.** The Job spends minutes in
its two init containers (`wait-for-db`, then `fetch-seed` downloading ~140 MB). During
that time `kubectl logs -f job/db-seed` exits immediately with
`container "loader" … is waiting to start: PodInitializing`, and a pasted block would
then run the `delete` and remove the Job before it ever loaded anything — which looks
like "the Job is missing from data-zone".

> **Not idempotent.** The seed is plain `COPY` into primary-keyed tables, committed
> file by file (iocs → assets → alerts → ground_truth). If ANY earlier attempt loaded
> even one file on this cluster, a re-run fails with `duplicate key` (and retries once).
> Check counts first, and TRUNCATE if anything is there (see "Reloading?" below):
> ```bash
> kubectl -n data-zone exec statefulset/postgres-operational -- psql -U soc -d soc_operational -c "SELECT (SELECT count(*) FROM alerts) alerts, (SELECT count(*) FROM iocs) iocs, (SELECT count(*) FROM assets) assets, (SELECT count(*) FROM alert_ground_truth) gt;"
> ```

1. Start the Job:
```bash
kubectl apply -k deployment/db-seed/reportable
```
2. Watch it until `Completed` (Ctrl-C then). Normal path: `Init:0/2` → `Init:1/2` →
   `Running` → `Completed`, a few minutes in total. `Error` / `Init:Error` = failed, go
   to the diagnosis below. (Don't use `kubectl wait --for=condition=complete` here — it
   does not return when the Job FAILS, it just sits until its timeout.)
```bash
kubectl -n data-zone get pods -l job-name=db-seed -w
```
3. Read the result — must end with the row counts and `db-seed complete`:
```bash
kubectl -n data-zone logs job/db-seed
```
4. Only after step 3 shows `db-seed complete`, clean up:
```bash
kubectl delete -k deployment/db-seed/reportable
```
If the pod shows `Init:Error` / `Error`, read the stage that failed (the Job is still
there — don't delete it yet):
```bash
kubectl -n data-zone logs job/db-seed -c wait-for-db
```
```bash
kubectl -n data-zone logs job/db-seed -c fetch-seed
```
```bash
kubectl -n data-zone logs job/db-seed -c loader
```
- `wait-for-db` failing → Postgres not Running in data-zone.
- `fetch-seed` failing with `Access Denied` → the data-zone `vllm-s3-creds` holds
  empty/wrong creds (step 3); "object does not exist" → the seed was never uploaded
  (`stage_dbs.py --upload`).
- `loader` failing with `duplicate key` → an earlier attempt already loaded part of
  the seed: TRUNCATE (below), `kubectl delete -k deployment/db-seed/reportable`, re-apply.
Drive a mixed sample through the live pipeline (needs vLLM Ready; the manifest has
~600k lines, so sample both classes rather than driving all):
```bash
kubectl -n agent-zone port-forward svc/triage-agent 9101:9101 &
grep '"true_class": "escalate"' raw_data/staged/wl.jsonl | head -10  > /tmp/mix.jsonl
grep '"true_class": "benign"'   raw_data/staged/wl.jsonl | head -10 >> /tmp/mix.jsonl
TRIAGE_A2A_ENDPOINT=http://127.0.0.1:9101 \
  /opt/miniconda3/envs/masterarbeit/bin/python scripts/run_workload.py --manifest /tmp/mix.jsonl --concurrency 3
```
Traces (local): `kubectl -n platform-zone port-forward svc/phoenix 6006:6006`.

Traces (public, survives nothing — re-apply after every recreate):
`phoenix-public.yaml` adds a NodePort Service (30606) plus an allow-all NetworkPolicy
for Phoenix. The NodePort is what you need by default; the policy only matters when Z
is on (then the platform-zone policy would drop external ingress). It is NOT part of
the overlay (it exposes the trace UI with no auth), so apply it by hand:
```bash
kubectl apply -f deployment/phoenix-public.yaml
# then, OUTSIDE k8s (resets on recreate): open inbound TCP 30606 to the master in
# the Hyperstack security group, and browse http://<MASTER_PUBLIC_IP>:30606
# tear down when done:  kubectl delete -f deployment/phoenix-public.yaml
```

Inspect the DB:
`kubectl -n data-zone exec statefulset/postgres-operational -- psql -U soc -d soc_operational -c '\dt'`.
> Reloading? `db-seed` COPYs (appends) — TRUNCATE first for a clean reload:
> `… psql … -c "TRUNCATE alerts, iocs, assets, alert_ground_truth CASCADE;"`.

---

## Troubleshooting
- **`phoenix-data` PVC `Pending`** — the cluster has no default StorageClass. Set
  `storageClassName` in `base/platform/phoenix.yaml` (the same class Postgres' volume uses:
  `kubectl get pvc -n data-zone -o wide`).
- **apply fails: `spec.strategy.rollingUpdate: Forbidden`** (phoenix) — an older
  Phoenix Deployment is live; see the note under step 4.
- **`capability-verifier` NotFound** — expected on a **C0** cluster (`overlays/reportable`
  has no PDP). Skip the C1/C2-only steps, or apply `reportable-c1`/`-c2` if you meant C1/C2.
- **`job/db-seed` not found in data-zone** — almost always the Job was deleted by the
  step-7 `delete` before it finished (see the note in step 7). Check the row counts
  (a partial load is likely), TRUNCATE if needed, re-apply, and delete only after
  `Completed`.
- **db-seed "hangs" / `Error` after a previous attempt** — `duplicate key` in the
  `loader` log: the seed is not idempotent. TRUNCATE, delete the Job, re-apply (step 7).
- **db-seed can't reach Postgres / hangs in `wait-for-db`** — the loader uses the
  short host `postgres-operational`, so it must run **in data-zone** (the
  `db-seed/reportable` overlay does that). Confirm all 5 namespaces exist and
  `kubectl -n data-zone get pods` shows Postgres Running. If `fetch-seed` fails with
  `Access Denied`, the data-zone `vllm-s3-creds` secret holds empty/wrong creds —
  recreate it (step 3) with real, non-empty `$S3_KEY`/`$S3_SECRET`.
- **`run_workload` gets no response** — vLLM not Ready, or the manifest is empty;
  check `raw_data/staged/wl.jsonl` exists (from `stage_dbs.py`) and sample it.
- **S3 upload `MissingContentLength`** — boto3/aws-cli ≥ 1.36 default to `aws-chunked`
  uploads with no `Content-Length`, which Hyperstack rejects. `stage_dbs.py` sets
  `request_checksum_calculation="when_required"`; for the `aws` CLI export
  `AWS_REQUEST_CHECKSUM_CALCULATION=when_required` + `AWS_RESPONSE_CHECKSUM_VALIDATION=when_required`.
- **Agent can reach the DB directly (`CONNECTED`)** — expected with Z off (default).
  Only a problem when you turned Z on: then the CNI is not enforcing NetworkPolicy and
  the Z run is invalid until fixed.
- **Inference/tracing broken** — check vLLM is Running; with Z on, also check the
  platform-zone policy admits agent-zone (it admits all zones by design).
- **vLLM + S3 / Service-name / DiskPressure / immutable Job** — same as the minimal doc.
