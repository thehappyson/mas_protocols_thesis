# Cluster bootstrap — MINIMAL tier (4-zone, dev/troubleshooting)

Deploys `deployment/overlays/minimal`: 4 zones (data-zone folded into
platform-zone), **no NetworkPolicies**. Best for development. For measurement
runs use the **reportable** tier instead → `CLUSTER_BOOTSTRAP_reportable.md`.

Hyperstack has no cluster hibernate, so the cluster is **deleted when idle and
recreated** to work. Everything *inside* the cluster is ephemeral and must be
recreated each time; a few things persist and are reused. This deployment uses
private images from the GitHub Container Registry built from the repo's source —
build + push your own images (see the Docker build commands) before step 4.

## What persists
- **Container images** on GHCR: `ghcr.io/thehappyson/soc-agent`, `…/soc-tool` (private).
- **The S3 bucket** `model-storage` (CANADA-1) and its contents — the model is
  seeded **once** (step 5) and reused by every future cluster.

## What is recreated every time
- The GPU worker's container-storage relocation to the 750 GB disk (step 2)
- All namespaces (4: agent, tool, platform, experiment)
- The `ghcr-pull` image-pull secret (agent-zone, tool-zone, experiment-zone)
- The `vllm-s3-creds` S3 secret (platform-zone)
- All workloads (via the kustomize apply)

---

## Per-cluster steps

Run these from the repo root every time you recreate the cluster.

### 0. Point kubectl at the new cluster + set your secrets for this session
```bash
export KUBECONFIG=/absolute/path/to/new-kubeconfig
export GHCR_PAT='ghp_xxx'          # GitHub PAT, read:packages
export S3_KEY='xxx'                # Hyperstack Object Storage access key
export S3_SECRET='xxx'             # Hyperstack Object Storage secret
kubectl get nodes                  # sanity: master + GPU worker Ready
```

### 1. Namespaces (minimal = 4 zones)
```bash
kubectl create namespace agent-zone
kubectl create namespace tool-zone
kubectl create namespace platform-zone
kubectl create namespace experiment-zone
```

### 2. GPU worker: relocate container storage to the 750 GB disk — REQUIRED, do it FIRST
The GPU worker's **root disk is only ~100 GB**, and the vLLM image unpacks to
~30 GB — combined with the base OS + other images it fills the disk and the
kubelet evicts everything (`DiskPressure`). The node has a **750 GB disk mounted
at `/ephemeral`** that containerd does not use by default. Point containerd at it
*before* deploying, so image pulls land on the big disk.

> **Preferred alternative:** if you can provision the worker node-pool with a
> **≥200 GB root disk**, do that instead and SKIP this step.

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
The helper pod is destroyed when containerd restarts — that's expected.

### 3. Secrets
```bash
for ns in agent-zone tool-zone experiment-zone; do
  kubectl -n "$ns" create secret docker-registry ghcr-pull \
    --docker-server=ghcr.io --docker-username=thehappyson --docker-password="$GHCR_PAT"
done
kubectl -n platform-zone create secret generic vllm-s3-creds \
  --from-literal=AWS_ACCESS_KEY_ID="$S3_KEY" --from-literal=AWS_SECRET_ACCESS_KEY="$S3_SECRET"
```

### 4. Deploy the minimal overlay
```bash
kubectl kustomize --load-restrictor LoadRestrictionsNone deployment/overlays/minimal | kubectl apply -f -
kubectl get pods -A
```
(`--load-restrictor` is required — init SQL is single-sourced from `docker/initdb/`.)

### 5. Seed the model — **ONLY if the bucket is empty**
```bash
kubectl -n platform-zone run s3check --rm -it --restart=Never --image=minio/mc \
  --overrides='{"spec":{"containers":[{"name":"s3check","image":"minio/mc","command":["/bin/sh","-c","mc alias set hs $AWS_ENDPOINT_URL $AWS_ACCESS_KEY_ID $AWS_SECRET_ACCESS_KEY && mc ls hs/model-storage/Qwen3.8-27B"],"env":[{"name":"AWS_ENDPOINT_URL","value":"https://ca1.obj.nexgencloud.io"}],"envFrom":[{"secretRef":{"name":"vllm-s3-creds"}}]}]}}'
```
If it lists `config.json` + `*.safetensors`, skip to step 6. If empty:
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

### 7. Load the real dataset + drive the pipeline
The pipeline is driven over the **real SIEVE log dataset** (`raw_data/SIEVE_*.csv`;
the synthetic workload-generator was dropped). Each row is a pre-labelled log event
whose *category* is the ground truth; `stage_dbs.py` maps it to an alert, rewrites the
victim to a synthetic CMDB asset (universal hit) and ~40% of attack sources to a seeded
IOC (partial hit), so the escalate/benign branch is driven by reasoning, not one lookup.
Build the seed + driving manifest, upload the seed, and load it into Postgres (minimal
keeps the DB in **platform-zone**, where `vllm-s3-creds` already exists). The loader is
a kustomize overlay that targets the right namespace — no `sed`:
```bash
export AWS_ACCESS_KEY_ID=<key>; export AWS_SECRET_ACCESS_KEY=<secret>
/opt/miniconda3/envs/masterarbeit/bin/python scripts/stage_dbs.py --upload   # → raw_data/staged/seed_*.sql + wl.jsonl, uploads seed
kubectl apply -k deployment/db-seed/minimal
kubectl -n platform-zone logs -f job/db-seed        # -> "db-seed complete"
kubectl delete -k deployment/db-seed/minimal
```
> Full SIEVE is ~600k alerts (`seed_alerts.sql` ~140 MB). For a smaller SIEM store,
> `stage_dbs.py --limit N` stages a deterministic N-alert sample.

Drive a mixed sample through the live pipeline (needs vLLM Ready; the manifest has
~600k lines, so sample both classes rather than driving all):
```bash
kubectl -n agent-zone port-forward svc/triage-agent 9101:9101 &
grep '"true_class": "escalate"' raw_data/staged/wl.jsonl | head -10  > /tmp/mix.jsonl
grep '"true_class": "benign"'   raw_data/staged/wl.jsonl | head -10 >> /tmp/mix.jsonl
TRIAGE_A2A_ENDPOINT=http://127.0.0.1:9101 \
  /opt/miniconda3/envs/masterarbeit/bin/python scripts/run_workload.py --manifest /tmp/mix.jsonl --concurrency 3
```
Traces: `kubectl -n platform-zone port-forward svc/phoenix 6006:6006`. Inspect the DB:
`kubectl -n platform-zone exec statefulset/postgres-operational -- psql -U soc -d soc_operational -c '\dt'`.
> Reloading? `db-seed` COPYs (appends) — TRUNCATE first for a clean reload:
> `… psql … -c "TRUNCATE alerts, iocs, assets, alert_ground_truth CASCADE;"`.

---

## Troubleshooting
- **db-seed can't reach Postgres**: check `postgres-operational` is Running in
  platform-zone (all 4 namespaces created? DB pod scheduled?). `run_workload` gets
  no response → vLLM not Ready or `raw_data/staged/wl.jsonl` empty.
- **S3 upload `MissingContentLength`**: boto3/aws-cli ≥ 1.36 send uploads as
  `aws-chunked` with a trailing checksum by default (no `Content-Length`), which
  Hyperstack rejects. `stage_dbs.py` sets `request_checksum_calculation="when_required"`
  to force a plain body; for the `aws` CLI, export `AWS_REQUEST_CHECKSUM_CALCULATION=when_required`
  (and `AWS_RESPONSE_CHECKSUM_VALIDATION=when_required`). Large files also go as 16 MB
  multipart parts to avoid a dropped single PUT.
- **vLLM + S3 (Run:ai streamer)**: MinIO-style endpoint needs PATH-style addressing —
  both `AWS_S3_ADDRESSING_STYLE=path` (boto3) and
  `RUNAI_STREAMER_S3_USE_VIRTUAL_ADDRESSING=0` (C++ streamer) are set in `vllm.yaml`.
  Symptom if wrong: `libstreamer … File access error`.
- **vLLM Service-name collision**: `enableServiceLinks: false` in `vllm.yaml` (k8s
  injects `VLLM_PORT=tcp://…` which collides with vLLM's own config).
- **DiskPressure**: worker's ~100 GB root fills with images — step 2 relocates
  containerd to `/ephemeral`; clear stragglers with
  `kubectl -n platform-zone delete pods --field-selector=status.phase=Failed`.
- **Immutable Job**: re-run seed/workload jobs with `kubectl -n <ns> delete job <name>` then re-apply.
