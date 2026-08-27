#!/usr/bin/env bash
# Integration test: verify zone networking (IP assignment, cross-zone, internet)
# Requires: Linux, root, rauhad running, alpine image pulled
set -euo pipefail

RAUHA="${RAUHA_BIN:-cargo run --bin rauha --}"
ZONE_A="test-net-a-$$"
ZONE_B="test-net-b-$$"
ZONE_C="test-net-c-$$"
IMAGE="${TEST_IMAGE:-alpine:latest}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
HOST_SERVER_PID=""
HOST_PORT=$((20000 + $$ % 20000))
HOST_LOG=$(mktemp /tmp/rauha-host-http-XXXXXX.log)

# Create a temporary bridged policy that allows cross-zone and internet.
POLICY_FILE=$(mktemp /tmp/rauha-test-net-XXXXXX.toml)
DENY_POLICY_FILE=$(mktemp /tmp/rauha-test-net-deny-XXXXXX.toml)
cat > "$POLICY_FILE" <<TOML
[zone]
name = "placeholder"
type = "non-global"

[admission]
mode = "audit"

[capabilities]
allowed = ["CAP_NET_RAW"]

[network]
mode = "bridged"
allowed_zones = ["$ZONE_A", "$ZONE_B"]
allowed_egress = ["0.0.0.0/0"]
TOML
cat > "$DENY_POLICY_FILE" <<TOML
[zone]
name = "placeholder"
type = "non-global"

[admission]
mode = "audit"

[capabilities]
allowed = ["CAP_NET_RAW"]

[network]
mode = "bridged"
allowed_zones = []
allowed_egress = []
allowed_ingress = []
TOML

cleanup() {
    echo "Cleaning up..."
    [ -z "$HOST_SERVER_PID" ] || kill "$HOST_SERVER_PID" 2>/dev/null || true
    $RAUHA zone delete "$ZONE_A" --force 2>/dev/null || true
    $RAUHA zone delete "$ZONE_B" --force 2>/dev/null || true
    $RAUHA zone delete "$ZONE_C" --force 2>/dev/null || true
    ip -6 addr del fd89::1/64 dev rauha0 2>/dev/null || true
    rm -f "$POLICY_FILE" "$DENY_POLICY_FILE" "$HOST_LOG"
}
trap cleanup EXIT

echo "=== Test: zone networking ==="

echo "1. Pulling image (if not present)..."
$RAUHA image pull "$IMAGE" 2>/dev/null || true

echo "2. Creating zone A (bridged)..."
$RAUHA zone create --name "$ZONE_A" --policy "$POLICY_FILE"

echo "3. Creating zone B (bridged)..."
$RAUHA zone create --name "$ZONE_B" --policy "$POLICY_FILE"

echo "4. Creating zone C (bridged, no peers or egress)..."
$RAUHA zone create --name "$ZONE_C" --policy "$DENY_POLICY_FILE"

echo "5. Checking bridge has gateway IP..."
if ip addr show rauha0 | grep -q "10.89.0.1"; then
    echo "   rauha0 gateway: 10.89.0.1 (OK)"
else
    echo "   FAIL: rauha0 does not have gateway IP"
    exit 1
fi

echo "6. Checking IP forwarding is enabled..."
if [ "$(cat /proc/sys/net/ipv4/ip_forward)" = "1" ]; then
    echo "   ip_forward: enabled (OK)"
else
    echo "   FAIL: IP forwarding is not enabled"
    exit 1
fi

echo "7. Checking inet and bridge nftables boundaries exist..."
if nft list table inet rauha 2>/dev/null | grep "masquerade" >/dev/null; then
    echo "   nftables masquerade: present (OK)"
else
    echo "   FAIL: nftables masquerade rule not found"
    exit 1
fi
if nft list table bridge rauha 2>/dev/null | grep "policy drop" >/dev/null; then
    echo "   bridge default drop: present (OK)"
else
    echo "   FAIL: bridge default-drop boundary not found"
    exit 1
fi

echo "8. Testing internet connectivity from zone A..."
$RAUHA sandbox --name "$ZONE_A" --image "$IMAGE" -- /bin/ping -c1 -W5 8.8.8.8
echo "   Internet ping from zone A: OK"

echo "9. Getting zone IPs from namespaces..."
ZONE_A_IP=$(ip netns exec "rauha-${ZONE_A}" ip -4 addr show eth0 | awk '/inet / {print $2}' | cut -d/ -f1)
ZONE_B_IP=$(ip netns exec "rauha-${ZONE_B}" ip -4 addr show eth0 | awk '/inet / {print $2}' | cut -d/ -f1)
ZONE_C_IP=$(ip netns exec "rauha-${ZONE_C}" ip -4 addr show eth0 | awk '/inet / {print $2}' | cut -d/ -f1)
echo "   Zone A IP: $ZONE_A_IP"
echo "   Zone B IP: $ZONE_B_IP"
echo "   Zone C IP: $ZONE_C_IP"

echo "10. Testing explicitly allowed cross-zone connectivity (A → B)..."
$RAUHA sandbox --name "$ZONE_A" --image "$IMAGE" -- /bin/ping -c1 -W5 "$ZONE_B_IP"
echo "   Cross-zone ping A → B: OK"

echo "11. Testing bridge default-deny connectivity (A → C)..."
if $RAUHA sandbox --name "$ZONE_A" --image "$IMAGE" -- /bin/ping -c1 -W2 "$ZONE_C_IP" >/dev/null 2>&1; then
    echo "   FAIL: undeclared cross-zone IPv4 traffic reached zone C"
    exit 1
else
    echo "   Undeclared cross-zone IPv4 traffic: denied (OK)"
fi

echo "12. Testing zone-to-host service denial..."
python3 -m http.server "$HOST_PORT" --bind 10.89.0.1 >"$HOST_LOG" 2>&1 &
HOST_SERVER_PID=$!
sleep 0.2
if $RAUHA sandbox --name "$ZONE_A" --image "$IMAGE" -- /bin/sh -c \
    "wget -q -T 2 -O- http://10.89.0.1:$HOST_PORT" >/dev/null 2>&1; then
    echo "   FAIL: zone reached an undeclared host-local service"
    exit 1
else
    echo "   Undeclared host-local IPv4 service: denied (OK)"
fi

echo "13. Testing IPv6 host and cross-zone denial..."
ip -6 addr add fd89::1/64 dev rauha0
ip netns exec "rauha-${ZONE_A}" ip -6 addr add fd89::a/64 dev eth0
ip netns exec "rauha-${ZONE_C}" ip -6 addr add fd89::c/64 dev eth0
if $RAUHA sandbox --name "$ZONE_A" --image "$IMAGE" -- /bin/ping -6 -c1 -W2 fd89::1 >/dev/null 2>&1; then
    echo "   FAIL: zone reached the host over IPv6"
    exit 1
fi
if $RAUHA sandbox --name "$ZONE_A" --image "$IMAGE" -- /bin/ping -6 -c1 -W2 fd89::c >/dev/null 2>&1; then
    echo "   FAIL: undeclared cross-zone IPv6 traffic reached zone C"
    exit 1
fi
echo "   Undeclared IPv6 host and cross-zone traffic: denied (OK)"

echo "14. Testing DNS configuration from zone A..."
$RAUHA sandbox --name "$ZONE_A" --image "$IMAGE" -- /bin/sh -c "cat /etc/resolv.conf"
echo "    resolv.conf present: OK"

echo ""
echo "=== All networking tests passed ==="
