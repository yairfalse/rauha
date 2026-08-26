#!/usr/bin/env bash
# Prove crun can consume a Rauha-prepared rootfs while preserving Rauha's
# exact cgroup and network-namespace boundary used by the production executor.
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
    --arg cgroup_procs "$CGROUP/cgroup.procs" \
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
            {destination: "/proc", type: "proc", source: "proc", options: ["nosuid", "noexec", "nodev"]},
            {destination: "/run/rauha-zone.procs", type: "bind", source: $cgroup_procs, options: ["bind", "rw", "nosuid", "noexec", "nodev"]}
        ],
        hooks: {
            startContainer: [{
                path: "/bin/sh",
                args: ["sh", "-c", "printf 1 > /run/rauha-zone.procs"],
                env: ["PATH=/usr/sbin:/usr/bin:/sbin:/bin"]
            }]
        },
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

OUTPUT=$(crun --root "$RUNTIME_ROOT" --cgroup-manager=disabled run --bundle "$BUNDLE" "probe-$ZONE")
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
    crun --root "$RUNTIME_ROOT" --cgroup-manager=disabled run --bundle "$BUNDLE" \
        "probe-$ZONE-$iteration" >/dev/null
done
END=$(date +%s%N)
AVERAGE_MS=$(((END - START) / 5000000))
echo "PASS: crun preserved Rauha cgroup/netns/security state; warm bundle launch average ${AVERAGE_MS}ms (n=5)"
