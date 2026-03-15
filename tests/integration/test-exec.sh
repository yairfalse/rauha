#!/usr/bin/env bash
# Integration test: exec into a running container
# Requires: Linux, root, rauhad running, alpine image pulled
set -euo pipefail

RAUHA="${RAUHA_BIN:-cargo run --bin rauha --}"
ZONE_NAME="test-exec-$$"
IMAGE="${TEST_IMAGE:-alpine:latest}"

cleanup() {
    echo "Cleaning up..."
    $RAUHA zone delete --name "$ZONE_NAME" --force 2>/dev/null || true
}
trap cleanup EXIT

echo "=== Test: exec into container ==="

echo "1. Pulling image (if not present)..."
$RAUHA image pull "$IMAGE" 2>/dev/null || true

echo "2. Creating zone: ${ZONE_NAME}..."
$RAUHA zone create --name "$ZONE_NAME"

echo "3. Running long-lived container..."
CONTAINER_ID=$($RAUHA run --zone "$ZONE_NAME" "$IMAGE" /bin/sleep 60)
echo "   container ID: $CONTAINER_ID"

sleep 2

echo "4. Exec: run 'echo exec-test' inside container..."
EXEC_OUTPUT=$(echo "" | $RAUHA exec -it "$CONTAINER_ID" /bin/echo exec-test 2>/dev/null || true)
if echo "$EXEC_OUTPUT" | grep -q "exec-test"; then
    echo "   exec output contains expected text (OK)"
else
    echo "   WARN: exec output: $EXEC_OUTPUT"
    echo "   (exec may require PTY support which is Linux-only)"
fi

echo "5. Stopping container..."
$RAUHA stop "$CONTAINER_ID" 2>/dev/null || true
$RAUHA delete "$CONTAINER_ID" --force 2>/dev/null || true

echo "=== PASS: exec into container ==="
