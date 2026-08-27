#!/usr/bin/env bash
# Two-phase crash-recovery probe. linux-gate.sh kills and restarts rauhad
# between prepare and verify while the workload remains live.
set -euo pipefail

PHASE=${1:-}
STATE=${2:-}
RAUHA=${RAUHA_BIN:?RAUHA_BIN is required}
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
POLICY=${RAUHA_TEST_AUDIT_POLICY:-$ROOT/policies/audit.toml}
IMAGE=${TEST_IMAGE:-alpine:latest}

inode_check_passes() {
    "$RAUHA" --json zone verify "$1" | jq -e '
        .checks[]
        | select(
            .name == "filesystem:inode_ownership"
            and .passed == true
            and (.detail | test("^[1-9][0-9]* rootfs inodes registered$"))
        )
    ' >/dev/null
}

case "$PHASE" in
    prepare)
        [ -n "$STATE" ] || { echo "recovery state path is required" >&2; exit 2; }
        ZONE="test-recovery-$$"
        cleanup_failed_prepare() {
            "$RAUHA" zone delete "$ZONE" --force >/dev/null 2>&1 || true
        }
        trap cleanup_failed_prepare EXIT

        "$RAUHA" image pull "$IMAGE" >/dev/null
        "$RAUHA" zone create --name "$ZONE" --policy "$POLICY" >/dev/null
        CONTAINER=$($RAUHA run --zone "$ZONE" "$IMAGE" /bin/sleep 300)
        CGROUP="/sys/fs/cgroup/rauha.slice/zone-$ZONE/cgroup.procs"
        PID=""
        for _ in $(seq 1 30); do
            PID=$(head -n 1 "$CGROUP" 2>/dev/null || true)
            [ -n "$PID" ] && break
            sleep 0.1
        done
        [ -n "$PID" ] || { echo "recovery workload never entered its zone cgroup" >&2; exit 1; }
        inode_check_passes "$ZONE" || { echo "inode ownership was incomplete before restart" >&2; exit 1; }
        START=$(awk '{print $22}' "/proc/$PID/stat")
        printf 'zone=%s\ncontainer=%s\npid=%s\nstart=%s\n' \
            "$ZONE" "$CONTAINER" "$PID" "$START" >"$STATE"
        trap - EXIT
        echo "PASS: prepared live recovery workload with verified inode ownership"
        ;;
    verify)
        [ -r "$STATE" ] || { echo "recovery state is missing: $STATE" >&2; exit 2; }
        ZONE=$(sed -n 's/^zone=//p' "$STATE")
        PID=$(sed -n 's/^pid=//p' "$STATE")
        START=$(sed -n 's/^start=//p' "$STATE")
        [ -n "$ZONE" ] && [ -n "$PID" ] && [ -n "$START" ] || {
            echo "recovery state is incomplete" >&2
            exit 2
        }
        cleanup_verify() {
            "$RAUHA" zone delete "$ZONE" --force >/dev/null 2>&1 || true
        }
        trap cleanup_verify EXIT

        "$RAUHA" zone list | grep "$ZONE" >/dev/null || { echo "zone metadata was not recovered" >&2; exit 1; }
        [ -r "/proc/$PID/stat" ] || { echo "live workload was lost during daemon restart" >&2; exit 1; }
        [ "$(awk '{print $22}' "/proc/$PID/stat")" = "$START" ] || {
            echo "recovered PID no longer identifies the original workload" >&2
            exit 1
        }
        inode_check_passes "$ZONE" || { echo "inode ownership was not rebuilt after restart" >&2; exit 1; }
        "$RAUHA" --json zone verify "$ZONE" | jq -e '
            .checks[] | select(.name == "bpf_membership" and .passed == true)
        ' >/dev/null
        echo "PASS: daemon restart rebuilt live cgroup membership and rootfs inode ownership"
        ;;
    *)
        echo "usage: recovery-probe.sh prepare|verify STATE" >&2
        exit 2
        ;;
esac
