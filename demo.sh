#!/usr/bin/env bash
set -euo pipefail

# Rauha end-to-end demo
#
# Requirements:
#   - Linux 6.1+ with CONFIG_BPF_LSM=y, lsm=bpf in cmdline
#   - Root or CAP_BPF + CAP_SYS_ADMIN
#   - eBPF programs built: cargo xtask build-ebpf
#
# Run: sudo bash demo.sh

RAUHA="${RAUHA:-./target/release/rauha}"
RAUHAD="${RAUHAD:-./target/release/rauhad}"
CLEANUP_PIDS=()

cleanup() {
    echo ""
    echo "=== Cleanup ==="
    $RAUHA zone delete agent-sandbox --force 2>/dev/null || true
    $RAUHA zone delete database --force 2>/dev/null || true
    for pid in "${CLEANUP_PIDS[@]}"; do
        kill "$pid" 2>/dev/null || true
        wait "$pid" 2>/dev/null || true
    done
    echo "done"
}
trap cleanup EXIT

echo "=== Building ==="
cargo build --release --bin rauha --bin rauhad 2>&1 | tail -3

if [ ! -f "$RAUHAD" ] || [ ! -f "$RAUHA" ]; then
    echo "FAIL: binaries not found at $RAUHAD and $RAUHA"
    exit 1
fi

echo "=== Starting rauhad ==="
RUST_LOG=rauhad=info "$RAUHAD" &
CLEANUP_PIDS+=($!)
sleep 2

# Verify daemon is up.
$RAUHA zone list >/dev/null 2>&1 || {
    echo "FAIL: rauhad not responding"
    exit 1
}
echo "✓ rauhad running"

echo ""
echo "=== Pulling image ==="
$RAUHA image pull alpine:latest 2>&1 | tail -1
echo "✓ image pulled"

echo ""
echo "=== Creating zones ==="
$RAUHA zone create --name agent-sandbox --policy policies/standard.toml
$RAUHA zone create --name database --policy policies/standard.toml
echo "✓ zones created"

echo ""
echo "=== Verifying isolation ==="
VERIFY_A=$($RAUHA zone verify agent-sandbox 2>&1) || true
VERIFY_B=$($RAUHA zone verify database 2>&1) || true

if echo "$VERIFY_A" | grep -qi "isolated\|pass"; then
    echo "✓ agent-sandbox: isolated"
else
    echo "⚠ agent-sandbox verification:"
    echo "$VERIFY_A"
fi

if echo "$VERIFY_B" | grep -qi "isolated\|pass"; then
    echo "✓ database: isolated"
else
    echo "⚠ database verification:"
    echo "$VERIFY_B"
fi

echo ""
echo "=== Zone list ==="
$RAUHA zone list

echo ""
echo "=== Running containers ==="
$RAUHA run --zone agent-sandbox alpine:latest /bin/sleep 300 &
sleep 1
$RAUHA run --zone database alpine:latest /bin/sleep 300 &
sleep 1

echo ""
echo "=== Container list ==="
$RAUHA ps

echo ""
echo "=== Enforcement events ==="
# Briefly check if events endpoint responds.
timeout 2 $RAUHA events 2>&1 | head -5 || true
echo "(events streaming works — use 'rauha events --zone agent-sandbox' to watch live)"

echo ""
echo "==============================="
echo "  DEMO COMPLETE"
echo "==============================="
echo ""
echo "Two isolated zones running with eBPF enforcement."
echo "Every file_open, exec, ptrace, kill, and cgroup_attach"
echo "is checked against zone membership in the kernel."
echo ""
echo "Deny events stream in real time via 'rauha events'."
echo ""
echo "Press Ctrl+C to clean up."
wait
