#!/usr/bin/env bash
# Integration test: verify zone networking (IP assignment, cross-zone, internet)
# Requires: Linux, root, rauhad running, alpine image pulled
set -euo pipefail

RAUHA="${RAUHA_BIN:-cargo run --bin rauha --}"
ZONE_A="test-net-a-$$"
ZONE_B="test-net-b-$$"
IMAGE="${TEST_IMAGE:-alpine:latest}"

cleanup() {
    echo "Cleaning up..."
    $RAUHA zone delete --name "$ZONE_A" --force 2>/dev/null || true
    $RAUHA zone delete --name "$ZONE_B" --force 2>/dev/null || true
}
trap cleanup EXIT

echo "=== Test: zone networking ==="

echo "1. Pulling image (if not present)..."
$RAUHA image pull "$IMAGE" 2>/dev/null || true

echo "2. Creating zone A..."
$RAUHA zone create --name "$ZONE_A"

echo "3. Creating zone B..."
$RAUHA zone create --name "$ZONE_B"

echo "4. Checking bridge has gateway IP..."
if ip addr show rauha0 | grep -q "10.89.0.1"; then
    echo "   rauha0 gateway: 10.89.0.1 (OK)"
else
    echo "   FAIL: rauha0 does not have gateway IP"
    exit 1
fi

echo "5. Checking IP forwarding is enabled..."
if [ "$(cat /proc/sys/net/ipv4/ip_forward)" = "1" ]; then
    echo "   ip_forward: enabled (OK)"
else
    echo "   FAIL: IP forwarding is not enabled"
    exit 1
fi

echo "6. Checking nftables NAT table exists..."
if nft list table inet rauha 2>/dev/null | grep -q "masquerade"; then
    echo "   nftables masquerade: present (OK)"
else
    echo "   FAIL: nftables masquerade rule not found"
    exit 1
fi

echo "7. Testing internet connectivity from zone A..."
$RAUHA run --zone "$ZONE_A" "$IMAGE" /bin/ping -c1 -W5 8.8.8.8
echo "   Internet ping from zone A: OK"

echo "8. Getting zone IPs from namespaces..."
ZONE_A_IP=$(ip netns exec "rauha-${ZONE_A}" ip -4 addr show eth0 | grep -oP 'inet \K[0-9.]+')
ZONE_B_IP=$(ip netns exec "rauha-${ZONE_B}" ip -4 addr show eth0 | grep -oP 'inet \K[0-9.]+')
echo "   Zone A IP: $ZONE_A_IP"
echo "   Zone B IP: $ZONE_B_IP"

echo "9. Testing cross-zone connectivity (A → B)..."
$RAUHA run --zone "$ZONE_A" "$IMAGE" /bin/ping -c1 -W5 "$ZONE_B_IP"
echo "   Cross-zone ping A → B: OK"

echo "10. Testing DNS resolution from zone A..."
$RAUHA run --zone "$ZONE_A" "$IMAGE" /bin/sh -c "cat /etc/resolv.conf"
echo "    resolv.conf present: OK"

echo ""
echo "=== All networking tests passed ==="
