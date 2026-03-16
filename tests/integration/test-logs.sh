#!/usr/bin/env bash
# Integration test: container log streaming
# Requires: Linux, root, rauhad running, alpine image pulled
set -euo pipefail

RAUHA="${RAUHA_BIN:-cargo run --bin rauha --}"
ZONE_NAME="test-logs-$$"
IMAGE="${TEST_IMAGE:-alpine:latest}"

cleanup() {
    echo "Cleaning up..."
    $RAUHA zone delete --name "$ZONE_NAME" --force 2>/dev/null || true
}
trap cleanup EXIT

echo "=== Test: container log streaming ==="

echo "1. Pulling image (if not present)..."
$RAUHA image pull "$IMAGE" 2>/dev/null || true

echo "2. Creating zone: ${ZONE_NAME}..."
$RAUHA zone create --name "$ZONE_NAME"

echo "3. Running container that produces output..."
CONTAINER_ID=$($RAUHA run --zone "$ZONE_NAME" "$IMAGE" /bin/sh -c "echo hello-from-logs; echo line2; echo line3")
echo "   container ID: $CONTAINER_ID"

# Wait for container to produce output.
sleep 2

echo "4. Testing one-shot logs (all lines)..."
LOG_OUTPUT=$($RAUHA logs "$CONTAINER_ID" 2>/dev/null || true)
if echo "$LOG_OUTPUT" | grep -q "hello-from-logs"; then
    echo "   one-shot logs contain expected output (OK)"
else
    echo "   FAIL: logs output did not contain 'hello-from-logs': $LOG_OUTPUT"
    exit 1
fi

echo "5. Testing tail mode (last 1 line)..."
TAIL_OUTPUT=$($RAUHA logs "$CONTAINER_ID" --tail 1 2>/dev/null || true)
if echo "$TAIL_OUTPUT" | grep -q "line3"; then
    echo "   tail=1 shows last line (OK)"
else
    echo "   FAIL: tail output did not contain 'line3': $TAIL_OUTPUT"
    exit 1
fi

echo "6. Cleaning up..."
$RAUHA stop "$CONTAINER_ID" 2>/dev/null || true
$RAUHA delete "$CONTAINER_ID" --force 2>/dev/null || true

echo "=== PASS: container log streaming ==="
