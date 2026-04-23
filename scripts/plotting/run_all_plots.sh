#!/bin/bash
# This script runs all the python plotting scripts in sequence.

# Get the directory of the script
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"

echo "Generating core metrics plots..."
python3 "${SCRIPT_DIR}/plot_core_metrics.py"

echo "Generating security metrics plots..."
python3 "${SCRIPT_DIR}/plot_security_metrics.py"

echo "Generating billing and network plots..."
python3 "${SCRIPT_DIR}/plot_billing_and_network.py"

echo "Generating scalability plots..."
python3 "${SCRIPT_DIR}/plot_scalability.py"

echo "Generating scheme comparison plots..."
python3 "${SCRIPT_DIR}/plot_scheme_comparison.py"

echo "Generating theft deviation plot..."
python3 "${SCRIPT_DIR}/plot_theft_deviation.py"

echo "Generating scheme accuracy plot..."
python3 "${SCRIPT_DIR}/plot_scheme_accuracy.py"

echo "All plots have been generated in the paper/figs/ directory."
