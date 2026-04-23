#!/bin/bash
# Run HE scheme comparison benchmark and display results
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
OUTPUT="${1:-${PROJECT_DIR}/output/scheme_comparison.csv}"

echo "=== HE Scheme Comparison ==="
echo "Output: ${OUTPUT}"
echo ""

# Build if needed
if [[ ! -f "${PROJECT_DIR}/build/scheme_comparison" ]]; then
    echo "Building scheme_comparison..."
    cd "${PROJECT_DIR}/build"
    cmake .. -DCMAKE_BUILD_TYPE=Release > /dev/null 2>&1
    make scheme_comparison -j$(nproc) 2>&1
    echo ""
fi

# Run
"${PROJECT_DIR}/build/scheme_comparison" "$OUTPUT"

echo ""
echo "=== CSV Output ==="
cat "$OUTPUT"
