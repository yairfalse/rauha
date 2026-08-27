#!/usr/bin/env bash
# Measure crun's existing Wasm handler without adding a runtime to Rauha.
set -euo pipefail

ITERATIONS=${ITERATIONS:-10}
BUNDLE=$(mktemp -d "${TMPDIR:-/tmp}/rauha-wasm-tier.XXXXXX")
RUNTIME_ROOT="$BUNDLE/runtime"
WASM_HEX=0061736d0100000001040160000003020100070a01065f737461727400000a040102000b

cleanup() {
    for iteration in $(seq 1 "$ITERATIONS"); do
        crun --root "$RUNTIME_ROOT" --cgroup-manager=disabled delete --force "rauha-wasm-$iteration" >/dev/null 2>&1 || true
    done
    case "$BUNDLE" in
        "${TMPDIR:-/tmp}"/rauha-wasm-tier.*) rm -rf -- "$BUNDLE" ;;
        *) echo "refusing to remove unexpected bundle: $BUNDLE" >&2 ;;
    esac
}
trap cleanup EXIT

mkdir -p "$BUNDLE/rootfs" "$RUNTIME_ROOT"
python3 -c 'import sys; sys.stdout.buffer.write(bytes.fromhex(sys.argv[1]))' "$WASM_HEX" >"$BUNDLE/rootfs/probe.wasm"
printf '%s\n' '{"ociVersion":"1.0.2","annotations":{"run.oci.handler":"wasm"},"process":{"terminal":false,"user":{"uid":0,"gid":0},"args":["/probe.wasm"],"env":[],"cwd":"/","noNewPrivileges":true},"root":{"path":"rootfs","readonly":true},"mounts":[],"linux":{"namespaces":[{"type":"pid"},{"type":"mount"}]}}' >"$BUNDLE/config.json"

START=$(date +%s%N)
set +e
FIRST_ERROR=$(crun --root "$RUNTIME_ROOT" --cgroup-manager=disabled run --bundle "$BUNDLE" rauha-wasm-1 2>&1)
FIRST_STATUS=$?
set -e
if [ "$FIRST_STATUS" -ne 0 ]; then
    ELAPSED_US=$((($(date +%s%N) - START) / 1000))
    printf 'crun=%s\navailable=false\nprobe_us=%s\nerror=%s\n' \
        "$(crun --version | head -n 1)" "$ELAPSED_US" "$FIRST_ERROR"
    exit 0
fi
for iteration in $(seq 2 "$ITERATIONS"); do
    crun --root "$RUNTIME_ROOT" --cgroup-manager=disabled run --bundle "$BUNDLE" "rauha-wasm-$iteration"
done
END=$(date +%s%N)
AVERAGE_US=$(((END - START) / ITERATIONS / 1000))

printf 'crun=%s\navailable=true\niterations=%s\naverage_us=%s\n' \
    "$(crun --version | head -n 1)" "$ITERATIONS" "$AVERAGE_US"
