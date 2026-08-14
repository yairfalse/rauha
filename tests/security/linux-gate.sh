#!/usr/bin/env bash
# Authoritative privileged Linux gate. The caller supplies a passwordless sudo.
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
cd "$ROOT"

[ "$(uname -s)" = Linux ] || { echo "Linux is required" >&2; exit 2; }
test -r /sys/kernel/btf/vmlinux || { echo "kernel BTF is required" >&2; exit 2; }
grep -qw bpf /sys/kernel/security/lsm || { echo "BPF LSM is required" >&2; exit 2; }
for command in cargo bpf-linker findmnt ip nft pgrep protoc rustup sudo timeout; do
    command -v "$command" >/dev/null || { echo "$command is required" >&2; exit 2; }
done

cargo fmt --all -- --check
cargo clippy --quiet --workspace --all-targets --locked -- -D warnings
cargo test --quiet --workspace --locked
cargo build --quiet --workspace --locked
cargo xtask build-ebpf --release

RUN_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/rauha-security.XXXXXX")
DAEMON_LOG="$ROOT/.sykli/rauhad.log"
HOSTNAME_BEFORE=$(hostname)
mkdir -p "$ROOT/.sykli"
DAEMON_PID=""

cleanup() {
    if [ -n "$DAEMON_PID" ]; then
        sudo kill "$DAEMON_PID" 2>/dev/null || true
        wait "$DAEMON_PID" 2>/dev/null || true
    fi
    while read -r shim_pid; do
        sudo kill "$shim_pid" 2>/dev/null || true
    done < <(pgrep -f -- "--rootfs-root $RUN_ROOT/" || true)
    while read -r mountpoint; do
        sudo umount "$mountpoint" 2>/dev/null || true
    done < <(findmnt -rn -o TARGET | awk -v root="$RUN_ROOT/" 'index($0, root) == 1' | sort -r)
    if [ "$(hostname)" != "$HOSTNAME_BEFORE" ]; then
        sudo hostname "$HOSTNAME_BEFORE"
    fi
    case "$RUN_ROOT" in
        "${TMPDIR:-/tmp}"/rauha-security.*) sudo rm -rf -- "$RUN_ROOT" ;;
        *) echo "refusing to remove unexpected run root: $RUN_ROOT" >&2 ;;
    esac
}
trap cleanup EXIT

sudo env RAUHA_ROOT="$RUN_ROOT" "$ROOT/target/debug/rauhad" >"$DAEMON_LOG" 2>&1 &
DAEMON_PID=$!

for _ in $(seq 1 30); do
    if "$ROOT/target/debug/rauha" zone list >/dev/null 2>&1; then
        break
    fi
    sleep 1
done
if ! "$ROOT/target/debug/rauha" zone list >/dev/null 2>&1; then
    tail -100 "$DAEMON_LOG" >&2
    exit 1
fi

FAILURES=0
TEST_TIMEOUT=${RAUHA_TEST_TIMEOUT_SECONDS:-120}
for test_script in tests/integration/*.sh; do
    if ! sudo env RAUHA_BIN="$ROOT/target/debug/rauha" RAUHA_ROOT="$RUN_ROOT" \
        timeout --foreground --kill-after=5s "$TEST_TIMEOUT" bash "$test_script"; then
        echo "FAILED: $test_script" >&2
        FAILURES=$((FAILURES + 1))
    fi
done

if ! timeout --foreground --kill-after=5s "$TEST_TIMEOUT" env RAUHA_GRPC_ENDPOINT=http://[::1]:9876 \
    cargo test --quiet --manifest-path eval/oracle/Cargo.toml --locked; then
    echo "FAILED: eval/oracle" >&2
    FAILURES=$((FAILURES + 1))
fi

[ "$FAILURES" -eq 0 ] || { echo "$FAILURES security gate(s) failed" >&2; exit 1; }
