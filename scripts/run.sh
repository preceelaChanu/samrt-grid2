#!/bin/bash
# Run the full Smart Grid system
# Usage: ./run.sh [config.json] [duration_seconds]
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
BUILD_DIR="${PROJECT_DIR}/build"
CONFIG="${1:-${PROJECT_DIR}/config.json}"
DURATION="${2:-7200}"

cd "$PROJECT_DIR"

# Create output directories
mkdir -p output logs

# Determine output directory from config and clear previous metrics
OUTPUT_DIR=$(python3 -c "import json; c=json.load(open('$CONFIG')); print(c.get('metrics',{}).get('output_dir','output'))" 2>/dev/null || echo "output")
mkdir -p "$OUTPUT_DIR"
rm -f "$OUTPUT_DIR"/*.csv "$OUTPUT_DIR"/analytics_report.txt

# Cleanup function
cleanup() {
    echo ""
    echo "=== Stopping all components ==="
    kill $KDC_PID $CC_PID $AGG_PID $SM_PID 2>/dev/null || true
    wait $KDC_PID $CC_PID $AGG_PID $SM_PID 2>/dev/null || true
    echo "=== All components stopped ==="
}
trap cleanup EXIT INT TERM

echo "=== Starting Smart Grid Privacy Framework ==="
echo "Config: $CONFIG"
echo "Duration: ${DURATION}s"
echo ""

# Start KDC
echo "[1/4] Starting Key Distribution Center..."
"${BUILD_DIR}/kdc" "$CONFIG" &
KDC_PID=$!
sleep 2

# Start Control Center
echo "[2/4] Starting Control Center..."
"${BUILD_DIR}/control_center" "$CONFIG" &
CC_PID=$!
sleep 2

# Start Aggregator
echo "[3/4] Starting Aggregator..."
"${BUILD_DIR}/aggregator" "$CONFIG" &
AGG_PID=$!
sleep 2

# Start Smart Meters
echo "[4/4] Starting Smart Meters..."
"${BUILD_DIR}/smart_meter" "$CONFIG" &
SM_PID=$!

echo ""
echo "=== All components running ==="
echo "  KDC PID: $KDC_PID"
echo "  Control Center PID: $CC_PID"
echo "  Aggregator PID: $AGG_PID"
echo "  Smart Meters PID: $SM_PID"
echo ""
echo "Running for ${DURATION} seconds..."
echo "Press Ctrl+C to stop early."
echo ""

sleep "$DURATION"

echo ""
echo "=== Duration elapsed, stopping... ==="
kill -SIGINT $SM_PID 2>/dev/null || true
sleep 3
kill -SIGINT $AGG_PID 2>/dev/null || true
sleep 2
kill -SIGINT $CC_PID 2>/dev/null || true
sleep 1
kill -SIGINT $KDC_PID 2>/dev/null || true
wait 2>/dev/null || true

echo ""
echo "=== Results ==="
echo "Output files:"
ls -la output/ 2>/dev/null || echo "No output files found"
echo ""
echo "Logs:"
ls -la logs/ 2>/dev/null || echo "No log files found"
