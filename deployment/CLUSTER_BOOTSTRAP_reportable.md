# Cluster bootstrap — REPORTABLE tier (5-zone, NetworkPolicies ON)

Deploys `deployment/overlays/reportable`: the full **5 zones** (agent, tool,
platform, **data**, experiment) with the restrictive **NetworkPolicies enabled**.
This is the comparable tier for measurement runs. For a quick dev deploy use the
**minimal** tier instead → `CLUSTER_BOOTSTRAP_minimal.md`.

> **Key difference from minimal:** minimal folds the DB into platform-zone and has
> no policies. Reportable keeps **`data-zone` separate** and turns policies on, so
> agents can no longer reach the DB directly (only tools can). **You MUST create
> the `data-zone` namespace** (step 1) — if it's missing, `postgres-operational`
> never schedules, and everything that needs the DB (tools, the db-seed loader)
> fails.

Hyperstack has no cluster hibernate → the cluster is deleted when idle and
recreated. Everything inside is ephemeral; the GHCR images and the `model-storage`
S3 bucket persist. Build + push your own private images before step 4.

## What is recreated every time
- The GPU worker's container-storage relocation to the 750 GB disk (step 2)
- All **5** namespaces
- `ghcr-pull` (agent-zone, tool-zone, experiment-zone) + `vllm-s3-creds` (platform-zone)
- All workloads + the 4 zone NetworkPolicies (via the kustomize apply)

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
```bash
kubectl -n kube-system exec node-cleaner -- chroot /host systemd-run --unit=relocate-containerd \
  /bin/bash -c 'systemctl stop kubelet; systemctl stop containerd; rm -rf /var/lib/containerd; mkdir -p /ephemeral/containerd; ln -sfn /ephemeral/containerd /var/lib/containerd; systemctl start containerd; systemctl start kubelet'
kubectl wait --for=condition=Ready node/${WORKER} --timeout=300s
```
(The helper pod is destroyed when containerd restarts — expected.)

### 3. Secrets (same as minimal — data-zone needs none; Postgres uses its own)
```bash
for ns in agent-zone tool-zone experiment-zone; do
  kubectl -n "$ns" create secret docker-registry ghcr-pull \
    --docker-server=ghcr.io --docker-username=thehappyson --docker-password="$GHCR_PAT"
done
kubectl -n platform-zone create secret generic vllm-s3-creds \
  --from-literal=AWS_ACCESS_KEY_ID="$S3_KEY" --from-literal=AWS_SECRET_ACCESS_KEY="$S3_SECRET"
```

### 4. Deploy the reportable overlay
```bash
kubectl kustomize --load-restrictor LoadRestrictionsNone deployment/overlays/reportable | kubectl apply -f -
kubectl get pods -A
kubectl get networkpolicy -A          # expect 4: agent/tool/data/platform zones
```

### 5. Seed the model — ONLY if the bucket is empty (unchanged; talks to S3)
```bash
kubectl -n platform-zone run s3check --rm -it --restart=Never --image=minio/mc \
  --overrides='{"spec":{"containers":[{"name":"s3check","image":"minio/mc","command":["/bin/sh","-c","mc alias set hs $AWS_ENDPOINT_URL $AWS_ACCESS_KEY_ID $AWS_SECRET_ACCESS_KEY && mc ls hs/model-storage/Qwen3.8-27B"],"env":[{"name":"AWS_ENDPOINT_URL","value":"https://ca1.obj.nexgencloud.io"}],"envFrom":[{"secretRef":{"name":"vllm-s3-creds"}}]}]}}'
```
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

### 6.5 Verify the NetworkPolicies are ENFORCED
Calico (this cluster) enforces NetworkPolicy — but confirm, because an un-enforced
CNI silently invalidates the "policy on" condition. The point: agents can no longer
reach the DB directly. The slim agent image has Python but no `nc`, so probe with Python:
```bash
kubectl -n agent-zone exec deploy/triage-agent -- \
  python -c "import socket; socket.create_connection(('postgres-operational.data-zone.svc.cluster.local',5432),5); print('CONNECTED')"
```
- **Reportable (correct):** hangs ~5s then errors — **no `CONNECTED`** (blocked). ✓
- If it prints `CONNECTED`, the CNI is NOT enforcing — the tier is invalid; fix the CNI.

Sanctioned paths are unaffected: tools reach the DB (tool-zone → data-zone allowed),
and agents reach vLLM:8000 / Phoenix:6006 (platform-zone allows all zones).

### 7. Load the real dataset + drive the pipeline
The pipeline is driven over the **real CSE-CIC-IDS2018 dataset** (the synthetic
workload-generator was dropped). Build the seed + driving manifest and upload the
seed:
```bash
/opt/miniconda3/envs/masterarbeit/bin/python scripts/stage_dbs.py --upload   # → raw_data/staged/seed_*.sql + wl.jsonl, uploads seed
```
Load it into Postgres. Under reportable the DB is in **`data-zone`** and only
tool/experiment/data may reach it, so run the loader **in `data-zone`** — which
means the S3 creds secret must exist there too:
```bash
kubectl -n data-zone create secret generic vllm-s3-creds \
  --from-literal=AWS_ACCESS_KEY_ID="$S3_KEY" --from-literal=AWS_SECRET_ACCESS_KEY="$S3_SECRET"
sed 's/platform-zone/data-zone/g' deployment/db-seed-job.yaml | kubectl apply -f -
kubectl -n data-zone logs -f job/db-seed            # -> "db-seed complete"
kubectl -n data-zone delete job db-seed
```
Drive a mixed sample through the live pipeline (needs vLLM Ready; the real manifest
has ~12k lines, so sample both classes rather than driving all):
```bash
kubectl -n agent-zone port-forward svc/triage-agent 9101:9101 &
grep '"true_class": "escalate"' raw_data/staged/wl.jsonl | head -10  > /tmp/mix.jsonl
grep '"true_class": "benign"'   raw_data/staged/wl.jsonl | head -10 >> /tmp/mix.jsonl
TRIAGE_A2A_ENDPOINT=http://127.0.0.1:9101 \
  /opt/miniconda3/envs/masterarbeit/bin/python scripts/run_workload.py --manifest /tmp/mix.jsonl --concurrency 3
```
Traces: `kubectl -n platform-zone port-forward svc/phoenix 6006:6006`. Inspect the DB:
`kubectl -n data-zone exec statefulset/postgres-operational -- psql -U soc -d soc_operational -c '\dt'`.
> Reloading? `db-seed` COPYs (appends) — TRUNCATE first for a clean reload:
> `… psql … -c "TRUNCATE alerts, iocs, assets, alert_ground_truth CASCADE;"`.

---

## Troubleshooting
- **db-seed can't reach Postgres / hangs** — the DB is in `data-zone` and the
  policy admits only tool/experiment/data, so the loader must run **in data-zone**
  (step 7 does). Also confirm all 5 namespaces exist and `kubectl -n data-zone get
  pods` shows Postgres Running. If the seed pod can't pull the S3 files, the
  `vllm-s3-creds` secret is missing in data-zone (step 7 creates it).
- **`run_workload` gets no response** — vLLM not Ready, or the manifest is empty;
  check `raw_data/staged/wl.jsonl` exists (from `stage_dbs.py`) and sample it.
- **Agent can reach the DB directly (`CONNECTED`)** — CNI not enforcing NetworkPolicy;
  the reportable condition is invalid until fixed.
- **Inference/tracing broken** — check the platform-zone policy admits agent-zone
  (it admits all zones by design) and vLLM is Running.
- **vLLM + S3 / Service-name / DiskPressure / immutable Job** — same as the minimal doc.
