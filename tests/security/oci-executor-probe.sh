#!/usr/bin/env bash
# Prove the production handoff: crun creates a blocked init, trusted host code
# enrolls it in the exact zone cgroup, then crun releases the workload.
set -euo pipefail

RAUHA=${RAUHA_BIN:?RAUHA_BIN is required}
RAUHA_ROOT=${RAUHA_ROOT:?RAUHA_ROOT is required}
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
POLICY=${RAUHA_TEST_AUDIT_POLICY:-$ROOT/policies/audit.toml}
IMAGE=${TEST_IMAGE:-alpine:latest}
ZONE="test-oci-executor-$$"
BUNDLE=$(mktemp -d "$RAUHA_ROOT/oci-executor.XXXXXX")
RUNTIME_ROOT="$BUNDLE/runtime"
CGROUP="/sys/fs/cgroup/rauha.slice/zone-$ZONE"
ROOTFS_MOUNTED=false

cleanup() {
    for id in "probe-$ZONE" "probe-$ZONE-1" "probe-$ZONE-2" "probe-$ZONE-3" "probe-$ZONE-4" "probe-$ZONE-5"; do
        crun --root "$RUNTIME_ROOT" --cgroup-manager=disabled delete --force "$id" >/dev/null 2>&1 || true
    done
    if [ "$ROOTFS_MOUNTED" = true ]; then
        umount "$BUNDLE/rootfs" >/dev/null 2>&1 || true
    fi
    "$RAUHA" zone delete "$ZONE" --force >/dev/null 2>&1 || true
    case "$BUNDLE" in
        "$RAUHA_ROOT"/oci-executor.*) rm -rf -- "$BUNDLE" ;;
        *) echo "refusing to remove unexpected bundle path: $BUNDLE" >&2 ;;
    esac
}
trap cleanup EXIT

"$RAUHA" image pull "$IMAGE" >/dev/null
"$RAUHA" zone create --name "$ZONE" --policy "$POLICY" >/dev/null
CONTAINER=$($RAUHA run --zone "$ZONE" "$IMAGE" /bin/true)
CONTAINER_DIR="$RAUHA_ROOT/zones/$ZONE/containers/$CONTAINER"
if [ -d "$CONTAINER_DIR/merged" ]; then
    ROOTFS="$CONTAINER_DIR/merged"
elif [ -d "$CONTAINER_DIR/rootfs" ]; then
    ROOTFS="$CONTAINER_DIR/rootfs"
else
    echo "Rauha did not prepare an OCI rootfs for $CONTAINER" >&2
    exit 1
fi

mkdir -p "$RUNTIME_ROOT"
mkdir "$BUNDLE/rootfs"
mount --bind "$ROOTFS" "$BUNDLE/rootfs"
ROOTFS_MOUNTED=true
HOST_NETNS=$(readlink /proc/self/ns/net)
jq -n \
    --arg hostname "crun-$ZONE" \
    --arg netns "/var/run/netns/rauha-$ZONE" \
    '{
        ociVersion: "1.0.2",
        process: {
            terminal: false,
            user: {uid: 0, gid: 0},
            args: ["/bin/sh", "-c", "hostname; grep -E \"^(CapEff|NoNewPrivs):\" /proc/self/status; readlink /proc/self/ns/net; cat /proc/self/cgroup"],
            env: ["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"],
            cwd: "/",
            capabilities: {bounding: [], effective: [], inheritable: [], permitted: [], ambient: []},
            noNewPrivileges: true
        },
        root: {path: "rootfs", readonly: true},
        hostname: $hostname,
        mounts: [
            {destination: "/proc", type: "proc", source: "proc", options: ["nosuid", "noexec", "nodev"]}
        ],
        linux: {
            namespaces: [
                {type: "pid"},
                {type: "mount"},
                {type: "uts"},
                {type: "ipc"},
                {type: "network", path: $netns}
            ]
        }
    }' >"$BUNDLE/config.json"

run_probe() {
    local id=$1 output=$2 pid status
    : >"$output"
    crun --root "$RUNTIME_ROOT" --cgroup-manager=disabled create --bundle "$BUNDLE" \
        --pid-file "$BUNDLE/$id.pid" "$id" >"$output"
    pid=$(cat "$BUNDLE/$id.pid")
    [ ! -s "$output" ] || { echo "workload ran before cgroup enrollment" >&2; exit 1; }
    printf '%s' "$pid" >"$CGROUP/cgroup.procs"
    grep -Fq "/rauha.slice/zone-$ZONE" "/proc/$pid/cgroup"
    crun --root "$RUNTIME_ROOT" --cgroup-manager=disabled start "$id"
    for _ in $(seq 1 500); do
        status=$(crun --root "$RUNTIME_ROOT" --cgroup-manager=disabled state "$id" 2>/dev/null | jq -r .status || true)
        [ "$status" = stopped ] && break
        sleep 0.01
    done
    [ "$status" = stopped ] || { echo "crun workload did not stop" >&2; exit 1; }
    crun --root "$RUNTIME_ROOT" --cgroup-manager=disabled delete "$id"
}

run_probe "probe-$ZONE" "$BUNDLE/output"
OUTPUT=$(cat "$BUNDLE/output")
printf '%s\n' "$OUTPUT" | grep -qx "crun-$ZONE"
printf '%s\n' "$OUTPUT" | grep -Eq '^CapEff:[[:space:]]+0+$'
printf '%s\n' "$OUTPUT" | grep -Eq '^NoNewPrivs:[[:space:]]+1$'
CONTAINER_NETNS=$(printf '%s\n' "$OUTPUT" | grep '^net:\[')
[ "$CONTAINER_NETNS" != "$HOST_NETNS" ] || { echo "crun workload remained in the host netns" >&2; exit 1; }
printf '%s\n' "$OUTPUT" | grep -Fq "/rauha.slice/zone-$ZONE"
"$RAUHA" --json zone verify "$ZONE" | jq -e '
    .checks[] | select(.name == "bpf_membership" and .passed == true)
' >/dev/null

START=$(date +%s%N)
for iteration in 1 2 3 4 5; do
    run_probe "probe-$ZONE-$iteration" "$BUNDLE/output-$iteration"
done
END=$(date +%s%N)
AVERAGE_MS=$(((END - START) / 5000000))
echo "PASS: crun create/enroll/start preserved Rauha containment; warm bundle launch average ${AVERAGE_MS}ms (n=5)"
