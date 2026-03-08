#!/usr/bin/env bash
# Integration test: image pull from Docker Hub
# Requires: Linux, network access, rauhad running
set -euo pipefail

RAUHA="${RAUHA_BIN:-cargo run --bin rauha --}"
IMAGE="${TEST_IMAGE:-alpine:latest}"

echo "=== Test: image pull ==="

echo "1. Pulling ${IMAGE}..."
$RAUHA image pull "$IMAGE"

echo "2. Listing images..."
$RAUHA image ls

echo "3. Inspecting image..."
$RAUHA image inspect "$IMAGE"

echo "4. Verifying content store..."
RAUHA_ROOT="${RAUHA_ROOT:-/var/lib/rauha}"
BLOBS_DIR="${RAUHA_ROOT}/content/blobs/sha256"
MANIFESTS_DIR="${RAUHA_ROOT}/content/manifests"

blob_count=$(ls "$BLOBS_DIR" 2>/dev/null | wc -l)
if [ "$blob_count" -lt 2 ]; then
    echo "FAIL: expected at least 2 blobs (config + layer), found $blob_count"
    exit 1
fi
echo "   blobs: $blob_count"

manifest_count=$(ls "$MANIFESTS_DIR"/*.json 2>/dev/null | wc -l)
if [ "$manifest_count" -lt 1 ]; then
    echo "FAIL: expected at least 1 manifest reference, found $manifest_count"
    exit 1
fi
echo "   manifest refs: $manifest_count"

echo "5. Removing image..."
$RAUHA image remove "$IMAGE"

echo "6. Verifying removal..."
# Manifest ref should be gone, blobs remain (content-addressable dedup).
manifest_count_after=$(ls "$MANIFESTS_DIR"/*.json 2>/dev/null | wc -l)
if [ "$manifest_count_after" -ge "$manifest_count" ]; then
    echo "FAIL: manifest ref not removed"
    exit 1
fi

echo "=== PASS: image pull ==="
