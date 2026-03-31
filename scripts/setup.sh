#!/bin/bash
# Setup: generate certificates and SEAL keys
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
BUILD_DIR="${PROJECT_DIR}/build"
CONFIG="${PROJECT_DIR}/config.json"

cd "$PROJECT_DIR"

echo "=== Phase 1: Generating X.509 Certificates ==="
"${BUILD_DIR}/cert_generator" "$CONFIG"

echo ""
echo "=== Phase 2: Generating CKKS Keys ==="
"${BUILD_DIR}/key_generator" "$CONFIG"

echo ""
echo "=== Setup Complete ==="
echo "Certificates:"
ls -la certs/ 2>/dev/null || true
echo ""
echo "Keys:"
ls -la keys/ 2>/dev/null || true
