#!/usr/bin/env bash
# portforwards.sh — every port-forward a condition needs, self-healing.
#
#   experiments/portforwards.sh C0      # or C1 / C2
#
# One terminal, leave it running, Ctrl-C stops all forwards.
#
# Why: a `kubectl port-forward` dies (or silently stops forwarding) whenever its
# pod is replaced — every overlay apply, image change and vLLM restart — and on
# network blips. A dead forward shows up as `harness_error … ConnectError` in the
# injector and as transport errors in the executor. Here each forward runs in a
# loop that restarts it when kubectl exits, and an HTTP health check (every 10 s,
# two misses in a row) kills and restarts a forward that hangs without exiting.
# The executor waits for the triage endpoint to come back (--reconnect-wait) and
# retries the interrupted alerts, so a run survives a forward restart.
#
# Logs: experiments/results/.portforwards/<svc>.log
# bash 3.2 compatible (macOS /bin/bash): no associative arrays.

set -u
COND="${1:-}"
case "$COND" in
  C0)    WITH_PDP=0 ;;
  C1|C2) WITH_PDP=1 ;;
  *) echo "usage: $0 C0|C1|C2" >&2; exit 64 ;;
esac

REPO="$(cd "$(dirname "$0")/.." && pwd)"
LOG="$REPO/experiments/results/.portforwards"
mkdir -p "$LOG"

# ns  svc  local  remote  health-path ("-" = TCP only, no HTTP check)
FORWARDS="
agent-zone    triage-agent          9101  9101  /.well-known/agent-card.json
agent-zone    response-agent        9104  9104  /.well-known/agent-card.json
tool-zone     mcp-containment       7006  7006  /mcp
platform-zone phoenix               6006  6006  /
platform-zone vllm                  8000  8000  /health
data-zone     postgres-operational  15432 5432  -
"
if [ "$WITH_PDP" = 1 ]; then
  FORWARDS="$FORWARDS
platform-zone capability-verifier   8080  8080  /
tool-zone     mcp-siem              7001  7001  /mcp
"
fi

healthy() {   # any HTTP status = the forward reaches the pod; 000 = it doesn't
  code=$(curl -s -o /dev/null -m 10 -w '%{http_code}' "http://127.0.0.1:$1$2" 2>/dev/null)
  [ "$code" != "000" ]
}

nap() { sleep "$1" & wait $!; }   # interruptible sleep: traps fire at once

forward() {
  ns=$1; svc=$2; lp=$3; rp=$4; hp=$5
  pid=""
  trap 'kill $pid 2>/dev/null; exit 0' TERM INT
  while true; do
    kubectl -n "$ns" port-forward "svc/$svc" "$lp:$rp" >>"$LOG/$svc.log" 2>&1 &
    pid=$!
    nap 3
    misses=0
    while kill -0 "$pid" 2>/dev/null; do
      if [ "$hp" != "-" ]; then
        if healthy "$lp" "$hp"; then
          misses=0
        else
          misses=$((misses + 1))
          if [ "$misses" -ge 2 ]; then
            echo "$(date +%T) $svc:$lp not answering — restarting the forward"
            kill "$pid" 2>/dev/null
            break
          fi
        fi
      fi
      nap 10
    done
    wait "$pid" 2>/dev/null
    echo "$(date +%T) $svc:$lp down — restarting in 3 s (log: $LOG/$svc.log)"
    nap 3
  done
}

# Stop only OUR forward loops (each kills its own kubectl) — never `kill 0`,
# which would also hit whatever shell shares this process group.
stop_all() { trap - INT TERM EXIT; echo; echo "stopping all forwards"; kill $(jobs -p) 2>/dev/null; wait 2>/dev/null; exit 0; }
trap stop_all INT TERM EXIT

echo "$COND port-forwards (Ctrl-C stops all):"
echo "$FORWARDS" | while read -r ns svc lp rp hp; do
  [ -z "${ns:-}" ] && continue
  printf '  %-21s 127.0.0.1:%-5s -> %s/%s:%s\n' "$svc" "$lp" "$ns" "$svc" "$rp"
done

# Here-doc (not a pipe): the loop must run in THIS shell so `wait` owns the jobs.
while read -r ns svc lp rp hp; do
  [ -z "${ns:-}" ] && continue
  forward "$ns" "$svc" "$lp" "$rp" "$hp" &
done <<EOF
$FORWARDS
EOF
wait
