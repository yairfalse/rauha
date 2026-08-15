#!/usr/bin/env bash
# Run Rauha's locked Sykli graph against the current Linux host or one Lima VM.
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
RUNTIME="$ROOT/.sykli/runtime"
RECEIPT="$ROOT/.sykli/receipt.json"

running_lima() {
    limactl list --format '{{.Name}} {{.Status}}' | awk '$2 == "Running" { print $1 }'
}

select_lima() {
    local selected=${RAUHA_LIMA_INSTANCE:-}
    if [ -z "$selected" ]; then
        local running count
        running=$(running_lima)
        count=$(printf '%s\n' "$running" | sed '/^$/d' | wc -l | tr -d ' ')
        if [ "$count" -ne 1 ]; then
            echo "expected one running Lima instance, found $count; set RAUHA_LIMA_INSTANCE" >&2
            exit 2
        fi
        selected=$running
    fi
    if [ "$(limactl list --format '{{.Status}}' "$selected")" != Running ]; then
        echo "Lima instance $selected is not running" >&2
        exit 2
    fi
    printf '%s\n' "$selected"
}

fingerprint_linux() {
    printf 'kernel='
    uname -srvm
    printf 'boot_id='
    if [ -r /proc/sys/kernel/random/boot_id ]; then
        cat /proc/sys/kernel/random/boot_id
    else
        printf 'unavailable\n'
    fi
    printf 'lsm='
    if [ -r /sys/kernel/security/lsm ]; then
        cat /sys/kernel/security/lsm
    else
        printf 'unavailable'
    fi
    printf '\n'
    printf 'btf_sha256='
    if [ -r /sys/kernel/btf/vmlinux ] && command -v sha256sum >/dev/null 2>&1; then
        sha256sum /sys/kernel/btf/vmlinux | cut -d' ' -f1
    else
        printf 'unavailable\n'
    fi
}

if [ "${1:-}" = "--gate" ]; then
    [ "$#" -eq 1 ] || { echo "--gate takes no additional arguments" >&2; exit 2; }
    kind=$(sed -n 's/^kind=//p' "$RUNTIME")
    case "$kind" in
        linux)
            exec bash "$ROOT/tests/security/linux-gate.sh"
            ;;
        lima)
            instance=$(sed -n 's/^instance=//p' "$RUNTIME")
            [ -n "$instance" ] || { echo "missing Lima instance in $RUNTIME" >&2; exit 2; }
            exec limactl shell "$instance" -- bash "$ROOT/tests/security/linux-gate.sh"
            ;;
        *)
            echo "invalid or missing security runtime fingerprint; use tests/security/run.sh" >&2
            exit 2
            ;;
    esac
fi
[ "$#" -eq 0 ] || { echo "usage: tests/security/run.sh" >&2; exit 2; }

mkdir -p "$ROOT/.sykli"
# ponytail: live host state is not hermetic; use Sykli --no-cache when it exists.
RUN_ID=$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')
if [ "$(uname -s)" = Linux ]; then
    {
        printf 'run_id=%s\nkind=linux\n' "$RUN_ID"
        fingerprint_linux
    } >"$RUNTIME"
else
    instance=$(select_lima)
    {
        printf 'run_id=%s\nkind=lima\ninstance=%s\n' "$RUN_ID" "$instance"
        limactl shell "$instance" -- bash -c "$(declare -f fingerprint_linux); fingerprint_linux"
    } >"$RUNTIME"
fi

SYKLI_BIN=${RAUHA_SYKLI_BIN:-sykli}
if ! "$SYKLI_BIN" --version 2>/dev/null | grep -Eq '^sykli 0\.1\.'; then
    echo "$SYKLI_BIN is not the Rust-only Sykli 0.1 binary; set RAUHA_SYKLI_BIN" >&2
    exit 2
fi

cd "$ROOT"
run_status=0
"$SYKLI_BIN" run sykli.json --json >"$RECEIPT" || run_status=$?
verify_status=0
"$SYKLI_BIN" verify "$RECEIPT" --contract sykli.json || verify_status=$?
[ "$verify_status" -eq 0 ] || exit "$verify_status"
exit "$run_status"
