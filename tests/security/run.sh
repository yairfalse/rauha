#!/usr/bin/env bash
# Run Rauha's locked Sykli graph against the current Linux host or one Lima VM.
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
RUNTIME="$ROOT/.sykli/runtime"

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
    cat /proc/sys/kernel/random/boot_id
    printf 'lsm='
    cat /sys/kernel/security/lsm
    printf '\n'
    printf 'btf_sha256='
    sha256sum /sys/kernel/btf/vmlinux | cut -d' ' -f1
}

if [ "${1:-}" = "--gate" ]; then
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

mkdir -p "$ROOT/.sykli"
if [ "$(uname -s)" = Linux ]; then
    {
        printf 'kind=linux\n'
        fingerprint_linux
    } >"$RUNTIME"
else
    instance=$(select_lima)
    {
        printf 'kind=lima\ninstance=%s\n' "$instance"
        limactl shell "$instance" -- bash -c "$(declare -f fingerprint_linux); fingerprint_linux"
    } >"$RUNTIME"
fi

SYKLI_BIN=${RAUHA_SYKLI_BIN:-sykli}
if ! "$SYKLI_BIN" --version 2>/dev/null | grep -Eq '^sykli 0\.1\.'; then
    echo "$SYKLI_BIN is not the Rust-only Sykli 0.1 binary; set RAUHA_SYKLI_BIN" >&2
    exit 2
fi

cd "$ROOT"
exec "$SYKLI_BIN" run sykli.json "$@"
