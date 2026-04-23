#!/bin/bash
# CKKS Parameter Sensitivity Benchmark
# Varies poly_modulus_degree, scale_bits, and security_level independently
# Uses 10 smart meters for fast iteration
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
CONFIG="${PROJECT_DIR}/config.json"
DURATION="${1:-60}"
METERS=10
OUTPUT_BASE="${PROJECT_DIR}/output/ckks_params"

mkdir -p "$OUTPUT_BASE"

# Helper: create config with specific CKKS params and run
run_config() {
    local label="$1"
    local poly_deg="$2"
    local scale_bits="$3"
    local sec_level="$4"
    local coeff_bits="$5"
    local out_dir="${OUTPUT_BASE}/${label}"

    echo ""
    echo "============================================"
    echo "  ${label}"
    echo "  poly_degree=${poly_deg} scale=${scale_bits} security=${sec_level}"
    echo "  coeff_modulus=${coeff_bits}"
    echo "============================================"

    mkdir -p "$out_dir"

    local temp_config="/tmp/sg_ckks_${label}.json"
    python3 -c "
import json
with open('${CONFIG}') as f:
    c = json.load(f)
c['seal']['poly_modulus_degree'] = ${poly_deg}
c['seal']['scale_bits'] = ${scale_bits}
c['seal']['security_level'] = ${sec_level}
c['seal']['coeff_modulus_bits'] = ${coeff_bits}
c['smart_meters']['count'] = ${METERS}
c['metrics']['output_dir'] = '${out_dir}'
c['control_center']['csv_output_dir'] = '${out_dir}'
c['control_center']['report_file'] = '${out_dir}/analytics_report.txt'
with open('${temp_config}', 'w') as f:
    json.dump(c, f, indent=2)
"

    # Regenerate keys for new SEAL parameters
    echo "  Regenerating SEAL keys..."
    "${PROJECT_DIR}/build/key_generator" "$temp_config" > /dev/null 2>&1 || {
        echo "  ERROR: key_generator failed for ${label} (invalid parameter combination)"
        echo "${label},FAILED,invalid parameters" >> "${OUTPUT_BASE}/summary.csv"
        return 1
    }

    # Run the system
    "${SCRIPT_DIR}/run.sh" "$temp_config" "$DURATION" || {
        echo "  ERROR: run failed for ${label}"
        echo "${label},FAILED,runtime error" >> "${OUTPUT_BASE}/summary.csv"
        return 1
    }

    echo "  Completed: ${label}"
    sleep 3
}

echo "=== CKKS Parameter Sensitivity Benchmark ==="
echo "Duration per test: ${DURATION}s"
echo "Smart meters: ${METERS}"
echo "Output: ${OUTPUT_BASE}/"
echo ""

# Initialize summary CSV
echo "label,poly_degree,scale_bits,security_level,coeff_modulus,status" > "${OUTPUT_BASE}/summary.csv"

# ============================================================
# Experiment 1: Vary poly_modulus_degree (4096, 8192, 16384)
# Keep scale_bits=40, security_level=128
# ============================================================
echo ""
echo ">>> Experiment 1: Varying poly_modulus_degree <<<"

# 4096: smaller ring -> faster but less capacity
# coeff_modulus for 4096 at 128-bit: max total bits = 109
run_config "poly_4096" 4096 40 128 "[40, 40, 40]" || true

# 8192: default (baseline)
run_config "poly_8192" 8192 40 128 "[60, 40, 40, 60]" || true

# 16384: larger ring -> slower but more capacity
run_config "poly_16384" 16384 40 128 "[60, 40, 40, 40, 40, 60]" || true

# ============================================================
# Experiment 2: Vary scale_bits (20, 30, 40, 50)
# Keep poly_modulus_degree=8192, security_level=128
# ============================================================
echo ""
echo ">>> Experiment 2: Varying scale_bits <<<"

run_config "scale_20" 8192 20 128 "[60, 20, 20, 60]" || true
run_config "scale_30" 8192 30 128 "[60, 30, 30, 60]" || true
run_config "scale_40" 8192 40 128 "[60, 40, 40, 60]" || true
run_config "scale_50" 8192 50 128 "[60, 50, 50]" || true

# ============================================================
# Experiment 3: Vary security_level (128, 192, 256)
# Keep poly_modulus_degree=8192, scale_bits=40
# ============================================================
echo ""
echo ">>> Experiment 3: Varying security_level <<<"

run_config "sec_128" 8192 40 128 "[60, 40, 40, 60]" || true
run_config "sec_192" 8192 40 192 "[60, 40, 40, 60]" || true
run_config "sec_256" 8192 40 256 "[60, 40, 40, 60]" || true

echo ""
echo "=== All CKKS parameter experiments complete ==="
echo ""

# ============================================================
# Analyze results
# ============================================================
echo "=== Generating comparison report ==="
python3 << 'PYEOF'
import csv, statistics, os, json, re

base = os.environ.get("OUTPUT_BASE", "output/ckks_params")
if not os.path.isdir(base):
    base = "output/ckks_params"

results = []

for label in sorted(os.listdir(base)):
    d = os.path.join(base, label)
    if not os.path.isdir(d):
        continue

    row = {"label": label}

    # Parse label for params
    if label.startswith("poly_"):
        row["experiment"] = "poly_modulus_degree"
        row["value"] = label.replace("poly_", "")
    elif label.startswith("scale_"):
        row["experiment"] = "scale_bits"
        row["value"] = label.replace("scale_", "")
    elif label.startswith("sec_"):
        row["experiment"] = "security_level"
        row["value"] = label.replace("sec_", "")

    # Encryption metrics
    try:
        enc = {}
        with open(os.path.join(d, "encryption_metrics.csv")) as f:
            for r in csv.DictReader(f):
                enc.setdefault(r["operation"], []).append(float(r["value"]))
        if "encrypt_vector" in enc:
            vals = [v / 1e6 for v in enc["encrypt_vector"]]
            row["encrypt_ms"] = f"{statistics.mean(vals):.2f}"
            row["encrypt_n"] = len(vals)
        if "decrypt" in enc:
            vals = [v / 1e6 for v in enc["decrypt"]]
            row["decrypt_ms"] = f"{statistics.mean(vals):.2f}"
        if "ciphertext_size" in enc:
            row["ct_bytes"] = f"{enc['ciphertext_size'][0]:.0f}"
            row["ct_kb"] = f"{enc['ciphertext_size'][0]/1024:.1f}"
        if "decryption_error" in enc:
            row["he_error"] = f"{max(enc['decryption_error']):.12f}"
        if "decryption_relative_error" in enc:
            row["he_rel_error"] = f"{max(enc['decryption_relative_error']):.10f}"
    except Exception as e:
        row["encrypt_ms"] = f"ERR: {e}"

    # HE aggregation
    try:
        with open(os.path.join(d, "homomorphic_metrics.csv")) as f:
            he_add = []
            for r in csv.DictReader(f):
                if r["operation"] == "he_add":
                    he_add.append(float(r["value"]) / 1e6)
            if he_add:
                row["he_add_ms"] = f"{statistics.mean(he_add):.3f}"
                row["he_add_n"] = len(he_add)
    except:
        pass

    # Batch analytics
    try:
        with open(os.path.join(d, "batch_analytics.csv")) as f:
            batches = list(csv.DictReader(f))
            row["batches"] = len(batches)
            row["readings"] = sum(int(b["num_readings"]) for b in batches)
    except:
        pass

    # ZKP
    try:
        sec = {}
        with open(os.path.join(d, "security_metrics.csv")) as f:
            for r in csv.DictReader(f):
                sec.setdefault(r["operation"], []).append(float(r["value"]))
        rp = statistics.mean(sec.get("zkp_range_proof_generation", [0]))
        cp = statistics.mean(sec.get("zkp_correctness_proof_generation", [0]))
        row["zkp_gen_ms"] = f"{rp + cp:.4f}"
    except:
        pass

    results.append(row)

# Print comparison table
print("\n" + "=" * 100)
print("CKKS PARAMETER COMPARISON RESULTS")
print("=" * 100)

# Group by experiment
for exp in ["poly_modulus_degree", "scale_bits", "security_level"]:
    group = [r for r in results if r.get("experiment") == exp]
    if not group:
        continue
    print(f"\n--- {exp} ---")
    print(f"{'Value':<10} {'Encrypt(ms)':<14} {'Decrypt(ms)':<14} {'CT(KB)':<10} {'HE Add(ms)':<12} {'Batches':<10} {'Readings':<10} {'HE Error':<18} {'ZKP(ms)':<10}")
    print("-" * 100)
    for r in sorted(group, key=lambda x: int(x.get("value", "0"))):
        print(f"{r.get('value','?'):<10} "
              f"{r.get('encrypt_ms','---'):<14} "
              f"{r.get('decrypt_ms','---'):<14} "
              f"{r.get('ct_kb','---'):<10} "
              f"{r.get('he_add_ms','---'):<12} "
              f"{r.get('batches','---'):<10} "
              f"{r.get('readings','---'):<10} "
              f"{r.get('he_error','---'):<18} "
              f"{r.get('zkp_gen_ms','---'):<10}")

# Write CSV
csv_path = os.path.join(base, "comparison_results.csv")
if results:
    fields = ["label", "experiment", "value", "encrypt_ms", "decrypt_ms",
              "ct_bytes", "ct_kb", "he_add_ms", "he_error", "he_rel_error",
              "batches", "readings", "zkp_gen_ms", "encrypt_n"]
    with open(csv_path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        w.writeheader()
        w.writerows(results)
    print(f"\nResults saved to {csv_path}")

PYEOF

echo ""
echo "=== Done ==="
