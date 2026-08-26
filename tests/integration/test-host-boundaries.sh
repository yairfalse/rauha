#!/usr/bin/env bash
# Prove that a strict workload cannot alter or act as the Linux host.
set -euo pipefail

RAUHA=${RAUHA_BIN:-cargo run --bin rauha --}
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
ZONE="test-host-boundaries-$$"
NAME="boundary-$$"
IMAGE=${TEST_IMAGE:-alpine:latest}
HOSTNAME_BEFORE=$(hostname)
POLICY_FILE=$(mktemp /tmp/rauha-host-boundaries-XXXXXX.toml)
HARDENED_POLICY_FILE=$(mktemp /tmp/rauha-hardening-XXXXXX.toml)
HARDENED_ZONE="$ZONE-policy"
CONTAINER_ID=""
HARDENED_CONTAINER_ID=""
SENTINEL_PID=""
FAILURES=0

fail() {
    echo "FAIL: $*" >&2
    FAILURES=$((FAILURES + 1))
}

cleanup() {
    if [ -n "$SENTINEL_PID" ]; then
        kill "$SENTINEL_PID" 2>/dev/null || true
        wait "$SENTINEL_PID" 2>/dev/null || true
    fi
    if [ -n "$CONTAINER_ID" ]; then
        $RAUHA stop "$CONTAINER_ID" 2>/dev/null || true
        $RAUHA delete "$CONTAINER_ID" --force 2>/dev/null || true
    fi
    if [ -n "$HARDENED_CONTAINER_ID" ]; then
        $RAUHA stop "$HARDENED_CONTAINER_ID" 2>/dev/null || true
        $RAUHA delete "$HARDENED_CONTAINER_ID" --force 2>/dev/null || true
    fi
    $RAUHA zone delete "$ZONE" --force 2>/dev/null || true
    $RAUHA zone delete "$HARDENED_ZONE" --force 2>/dev/null || true
    rm -f "$POLICY_FILE" "$HARDENED_POLICY_FILE"
    if [ "$(hostname)" != "$HOSTNAME_BEFORE" ]; then
        hostname "$HOSTNAME_BEFORE"
    fi
}
trap cleanup EXIT

echo "=== Test: strict host boundaries ==="
$RAUHA image pull "$IMAGE" >/dev/null

if STRICT_ERROR=$($RAUHA zone create --name "$ZONE-full" --policy "$ROOT/policies/strict.toml" 2>&1); then
    fail "full strict policy was admitted despite unsupported controls"
    $RAUHA zone delete "$ZONE-full" --force 2>/dev/null || true
elif ! grep -q "strict policy requests unsupported or unavailable Linux controls" <<<"$STRICT_ERROR"; then
    fail "full strict policy failed without an unsupported-control admission result: $STRICT_ERROR"
else
    echo "PASS: unsupported full strict policy rejected"
fi

cat >"$POLICY_FILE" <<TOML
[zone]
name = "host-boundaries"
type = "non-global"

[admission]
mode = "strict"

[capabilities]
allowed = []

[resources]
cpu_shares = 512
memory_limit = "1Gi"
io_weight = 50
pids_max = 128

[network]
mode = "isolated"
allowed_zones = []
allowed_egress = []
allowed_ingress = []
TOML

if CREATE_ERROR=$($RAUHA zone create --name "$ZONE" --policy "$POLICY_FILE" 2>&1); then
    echo "PASS: strict baseline admitted with complete host enforcement"
elif grep -q "lsm\." <<<"$CREATE_ERROR"; then
    echo "PASS: strict baseline rejected on degraded host"
    sed -i 's/mode = "strict"/mode = "audit"/' "$POLICY_FILE"
    $RAUHA zone create --name "$ZONE" --policy "$POLICY_FILE"
else
    echo "FAIL: baseline policy admission failed unexpectedly: $CREATE_ERROR" >&2
    exit 1
fi
CONTAINER_ID=$($RAUHA run --zone "$ZONE" --name "$NAME" "$IMAGE" /bin/sleep 120)

PID=""
for _ in $(seq 1 30); do
    PID=$($RAUHA ps --zone "$ZONE" | awk -v id="$CONTAINER_ID" '$1 == id { print $5 }')
    [ -n "$PID" ] && [ -r "/proc/$PID/status" ] && break
    sleep 1
done
if [ -z "$PID" ] || [ ! -r "/proc/$PID/status" ]; then
    echo "FAIL: could not resolve workload PID" >&2
    exit 1
fi

if [ "$(hostname)" != "$HOSTNAME_BEFORE" ]; then
    fail "workload changed host hostname from $HOSTNAME_BEFORE to $(hostname)"
    hostname "$HOSTNAME_BEFORE"
else
    echo "PASS: host hostname unchanged"
fi

HOST_NET=$(stat -Lc '%d:%i' /proc/self/ns/net)
ZONE_NET=$(stat -Lc '%d:%i' "/var/run/netns/rauha-$ZONE")
WORKLOAD_NET=$(stat -Lc '%d:%i' "/proc/$PID/ns/net")
[ "$WORKLOAD_NET" = "$ZONE_NET" ] || fail "workload netns $WORKLOAD_NET does not match zone $ZONE_NET"
[ "$WORKLOAD_NET" != "$HOST_NET" ] || fail "workload remains in host netns"

HOST_UTS=$(stat -Lc '%d:%i' /proc/self/ns/uts)
WORKLOAD_UTS=$(stat -Lc '%d:%i' "/proc/$PID/ns/uts")
[ "$WORKLOAD_UTS" != "$HOST_UTS" ] || fail "workload remains in host UTS namespace"

HOST_PIDNS=$(stat -Lc '%d:%i' /proc/self/ns/pid)
WORKLOAD_PIDNS=$(stat -Lc '%d:%i' "/proc/$PID/ns/pid")
[ "$WORKLOAD_PIDNS" != "$HOST_PIDNS" ] || fail "workload remains in host PID namespace"

CAPEFF=$(awk '/^CapEff:/ { print $2 }' "/proc/$PID/status")
NO_NEW_PRIVS=$(awk '/^NoNewPrivs:/ { print $2 }' "/proc/$PID/status")
[ "$CAPEFF" = 0000000000000000 ] || fail "strict policy has effective capabilities $CAPEFF"
[ "$NO_NEW_PRIVS" = 1 ] || fail "NoNewPrivs is $NO_NEW_PRIVS, expected 1"

if $RAUHA sandbox --name "$ZONE" --image "$IMAGE" -- /bin/sh -c 'touch /rauha-write-probe' >/dev/null 2>&1; then
    fail "empty writable_paths allowed a rootfs write"
else
    echo "PASS: empty writable_paths makes the rootfs read-only"
fi

if $RAUHA sandbox --name "$ZONE" --image "$IMAGE" -- /bin/sh -c 'test ! -e /run/rauha-zone.procs' >/dev/null 2>&1; then
    echo "PASS: workload has no writable cgroup enrollment handle"
else
    fail "workload can access the zone cgroup enrollment handle"
fi

sed 's/mode = "strict"/mode = "audit"/' "$ROOT/policies/strict.toml" >"$HARDENED_POLICY_FILE"
$RAUHA zone create --name "$HARDENED_ZONE" --policy "$HARDENED_POLICY_FILE" >/dev/null
if $RAUHA sandbox --name "$HARDENED_ZONE" --image "$IMAGE" -- /bin/sh -c '
    touch /tmp/allowed &&
    ! touch /etc/denied &&
    test -c /dev/null && test -c /dev/zero && test -c /dev/urandom &&
    test ! -e /dev/kmsg &&
    grep -Eq "^Seccomp:[[:space:]]+2$" /proc/self/status
' >/dev/null 2>&1; then
    echo "PASS: declared writable path, device allow-list, and seccomp deny profile applied"
else
    fail "OCI mount, device, or seccomp controls were not applied"
fi
HARDENED_CONTAINER_ID=$($RAUHA run --zone "$HARDENED_ZONE" "$IMAGE" /bin/sleep 30)
if echo "" | $RAUHA exec -it "$HARDENED_CONTAINER_ID" /bin/true >/dev/null 2>&1; then
    fail "interactive exec bypassed the container seccomp profile"
else
    echo "PASS: interactive exec fails closed for seccomp-filtered containers"
fi
$RAUHA stop "$HARDENED_CONTAINER_ID" >/dev/null
$RAUHA delete "$HARDENED_CONTAINER_ID" --force >/dev/null
HARDENED_CONTAINER_ID=""

if $RAUHA sandbox --name "$ZONE" --image "$IMAGE" -- /bin/sh -c 'test "$$" -eq 1 && test "$(cat /proc/1/comm)" = sh' >/dev/null 2>&1; then
    echo "PASS: procfs exposes the container PID namespace"
else
    fail "container procfs does not expose its PID 1"
fi

if $RAUHA sandbox --name "$ZONE" --image "$IMAGE" -- /bin/sh -c 'i=0; while [ "$i" -lt 20 ]; do /bin/sh -c "sleep 0.01 &"; i=$((i + 1)); done; sleep 1; ! grep -l "^State:.*Z" /proc/[0-9]*/status >/dev/null 2>&1' >/dev/null 2>&1; then
    echo "PASS: container PID 1 reaps orphaned descendants"
else
    fail "container PID 1 left zombie descendants"
fi

sleep 120 &
SENTINEL_PID=$!
$RAUHA run --zone "$ZONE" --name "signal-$NAME" "$IMAGE" /bin/kill -TERM "$SENTINEL_PID" >/dev/null
sleep 1
if kill -0 "$SENTINEL_PID" 2>/dev/null; then
    echo "PASS: workload could not signal unzoned host sentinel"
else
    fail "workload signaled unzoned host process $SENTINEL_PID"
    SENTINEL_PID=""
fi

if [ "$FAILURES" -ne 0 ]; then
    echo "=== FAIL: $FAILURES strict host boundary violation(s) ===" >&2
    exit 1
fi
echo "=== PASS: strict host boundaries ==="
