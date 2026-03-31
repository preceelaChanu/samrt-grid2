#!/bin/bash
# Scalability benchmark: run with different meter counts
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
CONFIG="${PROJECT_DIR}/config.json"
DURATION="${1:-20}"

METER_COUNTS=(10 50 100 500)

echo "=== Scalability Benchmark ==="
echo "Duration per test: ${DURATION}s"
echo "Meter counts: ${METER_COUNTS[*]}"
echo ""

for count in "${METER_COUNTS[@]}"; do
    echo "=============================="
    echo "Testing with $count meters..."
    echo "=============================="

    # Create temporary config with modified meter count
    TEMP_CONFIG="/tmp/sg_bench_${count}.json"
    python3 -c "
import json
with open('$CONFIG') as f:
    c = json.load(f)
c['smart_meters']['count'] = $count
c['metrics']['output_dir'] = 'output/bench_${count}'
c['control_center']['csv_output_dir'] = 'output/bench_${count}'
c['control_center']['report_file'] = 'output/bench_${count}/analytics_report.txt'
with open('$TEMP_CONFIG', 'w') as f:
    json.dump(c, f, indent=2)
"

    mkdir -p "output/bench_${count}"

    # Run the system
    "${SCRIPT_DIR}/run.sh" "$TEMP_CONFIG" "$DURATION"

    echo ""
    echo "Results for $count meters:"
    ls -la "output/bench_${count}/" 2>/dev/null || true
    echo ""

    # Brief pause between tests
    sleep 5
done

echo "=== Benchmark Complete ==="
echo "Results in output/bench_*/"
