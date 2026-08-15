#!/usr/bin/env bash
# Integration test: exec into a running container
# Requires: Linux, root, rauhad running, alpine image pulled
set -euo pipefail

RAUHA="${RAUHA_BIN:-cargo run --bin rauha --}"
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
AUDIT_POLICY=${RAUHA_TEST_AUDIT_POLICY:-$ROOT/policies/audit.toml}
ZONE_NAME="test-exec-$$"
IMAGE="${TEST_IMAGE:-alpine:latest}"

cleanup() {
    echo "Cleaning up..."
    $RAUHA zone delete "$ZONE_NAME" --force 2>/dev/null || true
}
trap cleanup EXIT

echo "=== Test: exec into container ==="

echo "1. Pulling image (if not present)..."
$RAUHA image pull "$IMAGE" 2>/dev/null || true

echo "2. Creating zone: ${ZONE_NAME}..."
$RAUHA zone create --name "$ZONE_NAME" --policy "$AUDIT_POLICY"

echo "3. Running long-lived container..."
CONTAINER_ID=$($RAUHA run --zone "$ZONE_NAME" "$IMAGE" /bin/sleep 60)
echo "   container ID: $CONTAINER_ID"

sleep 2

echo "4. Exec: run 'echo exec-test' inside container..."
EXEC_OUTPUT=$(echo "" | $RAUHA exec -it "$CONTAINER_ID" /bin/echo exec-test 2>/dev/null || true)
if echo "$EXEC_OUTPUT" | grep -q "exec-test"; then
    echo "   exec output contains expected text (OK)"
else
    echo "   FAIL: exec output did not contain 'exec-test': $EXEC_OUTPUT"
    exit 1
fi

echo "5. Verifying exec joins every container namespace..."
CGROUP="/sys/fs/cgroup/rauha.slice/zone-$ZONE_NAME/cgroup.procs"
BEFORE=$(cat "$CGROUP")
(echo "" | $RAUHA exec -it "$CONTAINER_ID" /bin/sleep 5 >/dev/null 2>&1) &
EXEC_CLIENT_PID=$!
EXEC_PID=""
for _ in $(seq 1 30); do
    while read -r candidate; do
        if ! grep -qx "$candidate" <<<"$BEFORE"; then
            EXEC_PID=$candidate
            break
        fi
    done <"$CGROUP"
    [ -n "$EXEC_PID" ] && break
    sleep 0.1
done
if [ -z "$EXEC_PID" ]; then
    echo "   FAIL: could not identify exec process in zone cgroup"
    wait "$EXEC_CLIENT_PID" 2>/dev/null || true
    exit 1
fi
CONTAINER_PID=$($RAUHA ps --zone "$ZONE_NAME" | awk -v id="$CONTAINER_ID" '$1 == id { print $5 }')
for namespace in net uts ipc mnt pid; do
    CONTAINER_NS=$(stat -Lc '%d:%i' "/proc/$CONTAINER_PID/ns/$namespace")
    EXEC_NS=$(stat -Lc '%d:%i' "/proc/$EXEC_PID/ns/$namespace")
    if [ "$EXEC_NS" != "$CONTAINER_NS" ]; then
        echo "   FAIL: exec $namespace namespace $EXEC_NS differs from container $CONTAINER_NS"
        wait "$EXEC_CLIENT_PID" 2>/dev/null || true
        exit 1
    fi
done
wait "$EXEC_CLIENT_PID" 2>/dev/null || true
echo "   exec namespace membership matches container (OK)"

echo "6. Stopping container..."
$RAUHA stop "$CONTAINER_ID" 2>/dev/null || true
$RAUHA delete "$CONTAINER_ID" --force 2>/dev/null || true

echo "=== PASS: exec into container ==="
