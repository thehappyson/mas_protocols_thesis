# Cluster bootstrap runbook (Hyperstack, delete-and-recreate workflow)

Hyperstack has no cluster hibernate, so the cluster is **deleted when idle and
recreated** to work. Everything *inside* the cluster is ephemeral and must be
recreated each time; a few things persist and are reused. This deployment uses private images from the GitHub Container Repository which are built from the repo's source code. If you want to deploy the system as-is you need to build your own images from the source code and push them to a container repository ahead of step 3 for the time being.

## What persists
- **Container images** on GHCR: `ghcr.io/thehappyson/soc-agent`, `…/soc-tool` (private).
- **The S3 bucket** `model-storage` (CANADA-1) and its contents — the model is
  seeded **once** (see step 5) and reused by every future cluster.

## What is recreated every time
- The GPU worker's container-storage relocation to the 750 GB disk (step 2)
- All namespaces
- The `ghcr-pull` image-pull secret (agent-zone, tool-zone, experiment-zone)
- The `vllm-s3-creds` S3 secret (platform-zone)
- All workloads (via the kustomize apply)

---

## Per-cluster steps

Run these from the repo root every time you recreate the cluster.

### 0. Point kubectl at the new cluster + set your secrets for this session
Hyperstack issues a fresh kubeconfig per cluster — download/replace it, then:
```bash
export KUBECONFIG=/absolute/path/to/new-kubeconfig
export GHCR_PAT='ghp_xxx'          # GitHub PAT, read:packages
export S3_KEY='xxx'                # Hyperstack Object Storage access key
export S3_SECRET='xxx'             # Hyperstack Object Storage secret
kubectl get nodes                  # sanity: master + GPU worker Ready
```
### 1. Namespaces (the minimal tier uses 4 zones)
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
> **≥200 GB root disk**, do that instead and SKIP this whole step — no relocation
> needed. The steps below are the fallback for the 100 GB root.

Find the GPU worker's node name (Hyperstack names it `…-default-…`; the master is
`…-master-…`):
```bash
WORKER=$(kubectl get nodes -o name | sed 's|node/||' | grep -- '-default-' | head -1); echo "$WORKER"
```
Launch a privileged helper pod on it (tolerates all taints; busybox is tiny so it
schedules even under early pressure):
```bash
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
Relocate containerd to `/ephemeral` as a **detached host systemd job** (it must
survive the pod being killed when containerd restarts):
```bash
kubectl -n kube-system exec node-cleaner -- chroot /host systemd-run --unit=relocate-containerd \
  /bin/bash -c 'systemctl stop kubelet; systemctl stop containerd; rm -rf /var/lib/containerd; mkdir -p /ephemeral/containerd; ln -sfn /ephemeral/containerd /var/lib/containerd; systemctl start containerd; systemctl start kubelet'
```
The worker resets its container state and comes back in ~1–2 min (the helper pod
is destroyed in the process — that's expected). Wait for it, then verify:
```bash
kubectl wait --for=condition=Ready node/${WORKER} --timeout=300s
# re-create a helper to confirm the symlink + free space:
cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata: {name: node-cleaner, namespace: kube-system}
spec:
  nodeName: ${WORKER}
  restartPolicy: Never
  tolerations: [{operator: Exists}]
  containers: [{name: c, image: busybox, command: ["sleep","120"], securityContext: {privileged: true}, volumeMounts: [{name: host, mountPath: /host}]}]
  volumes: [{name: host, hostPath: {path: /}}]
EOF
kubectl -n kube-system wait --for=condition=Ready pod/node-cleaner --timeout=120s
kubectl -n kube-system exec node-cleaner -- chroot /host bash -c 'ls -l /var/lib/containerd; df -h / /ephemeral'
kubectl -n kube-system delete pod node-cleaner
```
You want `/var/lib/containerd -> /ephemeral/containerd`, `/` well under its
threshold, and `/ephemeral` with hundreds of GB free.

### 3. Secrets
GHCR pull secret — the private agent/tool/generator images (3 namespaces):
```bash
for ns in agent-zone tool-zone experiment-zone; do
  kubectl -n "$ns" create secret docker-registry ghcr-pull \
    --docker-server=ghcr.io \
    --docker-username=thehappyson \
    --docker-password="$GHCR_PAT"
done
```
S3 creds for vLLM model streaming (platform-zone only):
```bash
kubectl -n platform-zone create secret generic vllm-s3-creds \
  --from-literal=AWS_ACCESS_KEY_ID="$S3_KEY" \
  --from-literal=AWS_SECRET_ACCESS_KEY="$S3_SECRET"
```

### 4. Deploy the system (minimal overlay)
```bash
kubectl kustomize --load-restrictor LoadRestrictionsNone deployment/overlays/minimal | kubectl apply -f -
kubectl get pods -A
```
(The `--load-restrictor` flag is required — the init SQL is single-sourced from
`docker/initdb/`, outside the kustomize root.)

### 5. Seed the model — **ONLY if the bucket is empty**
The bucket persists across clusters, so this is normally skipped. Check first:
```bash
kubectl -n platform-zone run s3check --rm -it --restart=Never --image=minio/mc \
  --overrides='{"spec":{"containers":[{"name":"s3check","image":"minio/mc","command":["/bin/sh","-c","mc alias set hs $AWS_ENDPOINT_URL $AWS_ACCESS_KEY_ID $AWS_SECRET_ACCESS_KEY && mc ls hs/model-storage/Qwen3.8-27B"],"env":[{"name":"AWS_ENDPOINT_URL","value":"https://ca1.obj.nexgencloud.io"}],"envFrom":[{"secretRef":{"name":"vllm-s3-creds"}}]}]}}'
```
If it lists `config.json` + `*.safetensors`, you're done — skip to step 6. If empty:
```bash
kubectl apply -f deployment/seed-model-job.yaml
kubectl -n platform-zone logs -f job/seed-model      # wait for "seed complete"
kubectl -n platform-zone delete -f deployment/seed-model-job.yaml
```

### 6. Bring up / verify vLLM
vLLM is deployed by step 4; if it crash-looped before the bucket was seeded,
restart it:
```bash
kubectl -n platform-zone rollout restart deploy/vllm
kubectl -n platform-zone rollout status deploy/vllm --timeout=25m
kubectl -n platform-zone logs deploy/vllm -f          # -> "Application startup complete"
```
Confirm it serves the model:
```bash
kubectl -n platform-zone port-forward svc/vllm 8000:8000 &
curl -s localhost:8000/v1/models     # should list Qwen/Qwen3.8-27B
```

### 7. Interact (via Port forward)
```bash
kubectl -n platform-zone port-forward svc/phoenix 6006:6006     # traces  -> localhost:6006
kubectl -n agent-zone   port-forward svc/triage-agent 9101:9101 # A2A entry -> localhost:9101
```
Drive a workload (once vLLM is Ready). The workload-generator Job runs at apply
time and prints a JSONL manifest on its **`generator`** container's stdout:
```bash
kubectl -n experiment-zone logs job/workload-generator -c generator | grep '^{' > /tmp/wl.jsonl
wc -l /tmp/wl.jsonl                                   # expect ~20 lines
TRIAGE_A2A_ENDPOINT=http://127.0.0.1:9101 \
  /opt/miniconda3/envs/masterarbeit/bin/python scripts/run_workload.py --manifest /tmp/wl.jsonl --concurrency 3
```
If `/tmp/wl.jsonl` is empty (Job hadn't completed, or its pod was GC'd), re-run it:
```bash
kubectl -n experiment-zone delete job workload-generator --ignore-not-found
kubectl kustomize --load-restrictor LoadRestrictionsNone deployment/overlays/minimal | kubectl apply -f -
kubectl -n experiment-zone wait --for=condition=complete job/workload-generator --timeout=180s
kubectl -n experiment-zone logs job/workload-generator -c generator | grep '^{' > /tmp/wl.jsonl
```

---

## Troubleshooting

- **vLLM + S3 (Run:ai streamer)**: Hyperstack's MinIO-style endpoint needs
  PATH-style addressing. Both clients that read the bucket need their own env
  (already set in `vllm.yaml`): boto3 → `AWS_S3_ADDRESSING_STYLE=path`; the C++
  streamer → `RUNAI_STREAMER_S3_USE_VIRTUAL_ADDRESSING=0`. Symptom if wrong:
  `libstreamer … File access error`.
- **vLLM + Service name collision**: the Service is named `vllm`, so k8s injects
  `VLLM_PORT=tcp://…` which collides with vLLM's own config. Fixed with
  `enableServiceLinks: false` in `vllm.yaml`.
- **Immutable Job**: a Job's pod template can't be patched. To re-run the seed or
  workload-generator after changing it: `kubectl -n <ns> delete job <name>` then re-apply.
- **Secrets before apply**: create the secrets (step 3) *before* step 4 so pods
  don't sit in ImagePullBackOff / crash.
- **Docker Hub rate limits**: if `vllm/vllm-openai` fails to pull with
  `toomanyrequests`, mirror it once into GHCR (`docker pull … && docker tag …
  ghcr.io/<REPO>/vllm-openai:v0.28.0 && docker push …`) and point `vllm.yaml`
  at the mirror + add `ghcr-pull` to platform-zone.
```
