#!/usr/bin/env bash
# Integration test: full container lifecycle
# Requires: Linux, root, rauhad running, alpine image pulled
set -euo pipefail

RAUHA="${RAUHA_BIN:-cargo run --bin rauha --}"
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
AUDIT_POLICY=${RAUHA_TEST_AUDIT_POLICY:-$ROOT/policies/audit.toml}
ZONE_NAME="test-integration-$$"
IMAGE="${TEST_IMAGE:-alpine:latest}"

cleanup() {
    echo "Cleaning up..."
    $RAUHA zone delete "$ZONE_NAME" --force 2>/dev/null || true
}
trap cleanup EXIT

echo "=== Test: container lifecycle ==="

echo "1. Pulling image (if not present)..."
$RAUHA image pull "$IMAGE" 2>/dev/null || true

echo "2. Creating zone: ${ZONE_NAME}..."
$RAUHA zone create --name "$ZONE_NAME" --policy "$AUDIT_POLICY"

echo "3. Verifying zone exists..."
$RAUHA zone list | grep -q "$ZONE_NAME" || {
    echo "FAIL: zone not in list"
    exit 1
}

echo "4. Running container: echo hello..."
CONTAINER_ID=$($RAUHA run --zone "$ZONE_NAME" "$IMAGE" /bin/echo hello)
echo "   container ID: $CONTAINER_ID"

if [ -z "$CONTAINER_ID" ]; then
    echo "FAIL: no container ID returned"
    exit 1
fi

echo "5. Verifying container in ps output..."
sleep 1
$RAUHA ps --zone "$ZONE_NAME"

echo "6. Checking shim socket exists..."
SHIM_SOCK="/run/rauha/shim-${ZONE_NAME}.sock"
if [ -S "$SHIM_SOCK" ]; then
    echo "   shim socket: $SHIM_SOCK (OK)"
else
    echo "   WARN: shim socket not found at $SHIM_SOCK"
fi

echo "7. Checking cgroup enrollment..."
CGROUP_PROCS="/sys/fs/cgroup/rauha.slice/zone-${ZONE_NAME}/cgroup.procs"
if [ -f "$CGROUP_PROCS" ]; then
    procs=$(cat "$CGROUP_PROCS" 2>/dev/null | wc -l)
    echo "   processes in zone cgroup: $procs"
else
    echo "   WARN: cgroup.procs not found at $CGROUP_PROCS"
fi

echo "8. Checking container stdout log..."
LOG_FILE="/run/rauha/containers/${CONTAINER_ID}/stdout.log"
sleep 2
if [ -f "$LOG_FILE" ]; then
    content=$(cat "$LOG_FILE")
    if echo "$content" | grep -q "hello"; then
        echo "   stdout log contains 'hello' (OK)"
    else
        echo "   WARN: stdout log exists but doesn't contain 'hello': $content"
    fi
else
    echo "   WARN: stdout log not found at $LOG_FILE"
fi

echo "9. Stopping container..."
$RAUHA stop "$CONTAINER_ID" || echo "   (may already be exited)"

echo "10. Deleting container..."
$RAUHA delete "$CONTAINER_ID" --force || echo "   (may already be deleted)"

echo "10b. Stopping a sleeping workload (PID 1 of its namespace discards a default-disposition SIGTERM)..."
STOP_CONTAINER_ID=$($RAUHA run --zone "$ZONE_NAME" "$IMAGE" /bin/sleep 120)
sleep 1
STOP_PID=$(head -n 1 "$CGROUP_PROCS")
if [ -z "$STOP_CONTAINER_ID" ] || [ -z "$STOP_PID" ]; then
    echo "FAIL: stop-probe workload was not enrolled in the zone cgroup"
    exit 1
fi
STOP_START=$(awk '{print $22}' "/proc/$STOP_PID/stat")
$RAUHA stop "$STOP_CONTAINER_ID"
if [ -r "/proc/$STOP_PID/stat" ] && [ "$(awk '{print $22}' "/proc/$STOP_PID/stat")" = "$STOP_START" ]; then
    echo "FAIL: stop returned while the workload was still running"
    exit 1
fi
if $RAUHA ps --zone "$ZONE_NAME" | grep "$STOP_CONTAINER_ID" | grep -qi running; then
    echo "FAIL: stopped container still reported as running"
    exit 1
fi
$RAUHA delete "$STOP_CONTAINER_ID" --force

echo "11. Starting a live workload for force-delete drain coverage..."
LIVE_CONTAINER_ID=$($RAUHA run --zone "$ZONE_NAME" "$IMAGE" /bin/sleep 120)
sleep 1
LIVE_PID=$(head -n 1 "$CGROUP_PROCS")
if [ -z "$LIVE_CONTAINER_ID" ] || [ -z "$LIVE_PID" ]; then
    echo "FAIL: live workload was not enrolled in the zone cgroup"
    exit 1
fi
LIVE_START=$(awk '{print $22}' "/proc/$LIVE_PID/stat")

echo "12. Force-deleting zone with a live workload..."
$RAUHA zone delete "$ZONE_NAME" --force

echo "13. Verifying zone and live workload were removed..."
if $RAUHA zone list 2>/dev/null | grep -q "$ZONE_NAME"; then
    echo "FAIL: zone still exists after deletion"
    exit 1
fi
if [ -e "$CGROUP_PROCS" ]; then
    echo "FAIL: force-delete left a cgroup or live workload behind"
    exit 1
fi
if [ -r "/proc/$LIVE_PID/stat" ] && [ "$(awk '{print $22}' "/proc/$LIVE_PID/stat")" = "$LIVE_START" ]; then
    echo "FAIL: force-delete left the live workload behind"
    exit 1
fi

echo "=== PASS: container lifecycle ==="
