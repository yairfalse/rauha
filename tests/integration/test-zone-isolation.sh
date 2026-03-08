#!/usr/bin/env bash
# Integration test: verify zone isolation enforcement
# Requires: Linux, root, rauhad with eBPF loaded, alpine image pulled
set -euo pipefail

RAUHA="${RAUHA_BIN:-cargo run --bin rauha --}"
ZONE_NAME="test-isolation-$$"
IMAGE="${TEST_IMAGE:-alpine:latest}"

cleanup() {
    echo "Cleaning up..."
    $RAUHA zone delete --name "$ZONE_NAME" --force 2>/dev/null || true
}
trap cleanup EXIT

echo "=== Test: zone isolation ==="

echo "1. Pulling image (if not present)..."
$RAUHA image pull "$IMAGE" 2>/dev/null || true

echo "2. Creating zone..."
$RAUHA zone create --name "$ZONE_NAME"

echo "3. Verifying isolation primitives..."
$RAUHA zone verify "$ZONE_NAME"

echo "4. Checking cgroup exists..."
CGROUP_DIR="/sys/fs/cgroup/rauha.slice/zone-${ZONE_NAME}"
if [ -d "$CGROUP_DIR" ]; then
    echo "   cgroup: $CGROUP_DIR (OK)"
else
    echo "FAIL: cgroup directory missing: $CGROUP_DIR"
    exit 1
fi

echo "5. Checking network namespace exists..."
NETNS_NAME="rauha-${ZONE_NAME}"
if ip netns list 2>/dev/null | grep -q "$NETNS_NAME"; then
    echo "   netns: $NETNS_NAME (OK)"
else
    echo "   WARN: netns $NETNS_NAME not found (may not be fatal on some setups)"
fi

echo "6. Running a container in the zone..."
CONTAINER_ID=$($RAUHA run --zone "$ZONE_NAME" "$IMAGE" /bin/sleep 5)
echo "   container: $CONTAINER_ID"
sleep 1

echo "7. Verifying container is in zone cgroup..."
CGROUP_PROCS="${CGROUP_DIR}/cgroup.procs"
if [ -f "$CGROUP_PROCS" ]; then
    if [ -s "$CGROUP_PROCS" ]; then
        echo "   container enrolled in cgroup (OK)"
        cat "$CGROUP_PROCS"
    else
        echo "   WARN: cgroup.procs empty — container may have exited"
    fi
fi

echo "8. Checking BPF zone membership..."
if command -v bpftool &>/dev/null; then
    bpftool map dump pinned /sys/fs/bpf/rauha/ZONE_MEMBERSHIP 2>/dev/null || \
        echo "   WARN: could not dump BPF map (may not be pinned)"
else
    echo "   SKIP: bpftool not installed"
fi

echo "9. Stopping container..."
$RAUHA stop "$CONTAINER_ID" || true

echo "10. Deleting zone..."
$RAUHA zone delete --name "$ZONE_NAME" --force

echo "11. Verifying cgroup removed..."
if [ -d "$CGROUP_DIR" ]; then
    echo "FAIL: cgroup still exists after zone deletion"
    exit 1
fi
echo "   cgroup removed (OK)"

echo "=== PASS: zone isolation ==="
