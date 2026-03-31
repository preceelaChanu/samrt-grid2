#!/bin/bash
# Build the Smart Grid Privacy Framework
set -e

BUILD_DIR="${1:-build}"
BUILD_TYPE="${2:-Release}"

echo "=== Building Smart Grid Privacy Framework ==="
echo "Build dir: $BUILD_DIR"
echo "Build type: $BUILD_TYPE"

mkdir -p "$BUILD_DIR"
cd "$BUILD_DIR"

cmake .. -DCMAKE_BUILD_TYPE="$BUILD_TYPE"
make -j$(nproc)

echo "=== Build complete ==="
echo "Executables:"
ls -la cert_generator key_generator kdc smart_meter aggregator control_center 2>/dev/null || true
