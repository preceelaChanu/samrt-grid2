# Privacy-Preserving Smart Grid Analytics Framework

A production-ready, 3-tier privacy-preserving smart grid framework using **CKKS Homomorphic Encryption** (Microsoft SEAL 4.1) for end-to-end encrypted energy consumption analytics, with **malicious-adversary security** (Zero-Knowledge Proofs, Verifiable Computation), **encrypted theft detection**, and **privacy-preserving Time-of-Use billing**.

## Architecture

```
Smart Meters (up to 500) ──[TLS 1.3 + CKKS + ZKP]──> Aggregator ──[TLS 1.3 + VC]──> Control Center
     │  Range proofs                  │  Verifiable aggregation     │  Proof verification
     │  Correctness proofs            │  Theft detection            │  Decryption + analytics
     │  ToU time-slot metadata        │  ToU billing accumulation   │  Security audit
                                      │
Key Distribution Center <──[TLS 1.3]─── All nodes (certificate-authenticated)
```

### Components

| Component | Executable | Description |
|-----------|-----------|-------------|
| Certificate Generator | `cert_generator` | X.509 CA + node certificates (OpenSSL) |
| Key Generator | `key_generator` | CKKS parameters + public/secret/relin keys |
| Key Distribution Center | `kdc` | Serves SEAL keys to authenticated clients |
| Smart Meters | `smart_meter` | Simulates UK household energy + CKKS encryption + ZKP proofs |
| Aggregator | `aggregator` | Homomorphic aggregation + ZKP verification + theft detection + ToU billing |
| Control Center | `control_center` | Decryption, analytics, verifiable computation audit, CSV export |

## Quick Start

### Prerequisites

- Ubuntu/Debian Linux
- GCC 9+ or Clang 10+ (C++17)
- CMake 3.16+
- OpenSSL 3.0+
- Microsoft SEAL 4.1+

### Install Microsoft SEAL

```bash
git clone --depth 1 --branch v4.1.2 https://github.com/microsoft/SEAL.git /tmp/SEAL
cd /tmp/SEAL && cmake -S . -B build -DCMAKE_BUILD_TYPE=Release \
    -DSEAL_BUILD_BENCH=OFF -DSEAL_BUILD_EXAMPLES=OFF -DSEAL_BUILD_TESTS=OFF
cmake --build build -j$(nproc) && sudo cmake --install build
```

### Build

```bash
./scripts/build.sh
```

### Setup (Certificates + Keys)

```bash
./scripts/setup.sh
```

### Run

```bash
# Run with default config (100 meters, 30 seconds)
./scripts/run.sh

# Custom config and duration
./scripts/run.sh config.json 60

# Scalability benchmark (10, 50, 100, 500 meters)
./scripts/benchmark.sh 30
```

## Configuration

All parameters are in `config.json`. No recompilation needed.

| Section | Key Parameters |
|---------|---------------|
| `seal` | `poly_modulus_degree` (8192/16384/32768), `scale_bits` (40), `security_level` (128) |
| `smart_meters` | `count` (1-500), `send_interval_ms`, household type probabilities |
| `aggregator` | `batch_size`, `aggregation_interval_ms`, `max_concurrent_connections` |
| `network` | Hosts, ports, `connection_timeout_ms`, `retry_attempts` |
| `tls` | Certificate/key file paths |
| `metrics` | `enabled`, CSV output filenames |
| `zkp` | `security_bits` (128), enable/disable range/correctness/aggregation/billing proofs |
| `theft_detection` | `history_window` (24), `anomaly_threshold_sigma` (3.0), `spike_multiplier`, `drop_threshold` |
| `tou_billing` | Tariff rates (off-peak/mid-peak/peak/critical pence/kWh), time slot hour mappings |

## Energy Simulation

Realistic UK smart meter data based on actual statistics:

| Household Type | Probability | Base kWh |
|---------------|-------------|----------|
| LOW_CONSUMER | 95.4% | 0.10 |
| MEDIUM_CONSUMER | 4.6% | 0.40 |
| HIGH_CONSUMER | 0.0% | 0.80 |
| VARIABLE_BEHAVIOR | 51% overlap | 2x variance |

- Range: 0.000 – 2.112 kWh, Mean: 0.213 kWh
- 24-hour demand curve (peak at 19:00, trough at 04:00)
- Day-of-week variation (weekends +15%)
- ~2% zero-reading probability

## Cryptography

- **Scheme**: CKKS (Microsoft SEAL 4.1)
- **Security**: ≥128-bit (Ring-LWE, post-quantum assumptions)
- **Operations**: Homomorphic addition, relinearization support
- **Key Management**: KDC distributes keys over TLS 1.3 with mutual X.509 authentication

## Malicious Security & Zero-Knowledge Proofs

The framework defends against **active (malicious) adversaries** who may inject false meter readings, tamper with aggregation, or provide selectively incorrect data.

### ZKP Engine

| Proof Type | Purpose | Protocol |
|-----------|---------|----------|
| **Range Proof** | Proves reading ∈ [0, 2.112] kWh without revealing value | Bulletproofs-style (SHA-256 + Fiat-Shamir) |
| **Correctness Proof** | Proves encrypted value matches committed value | Sigma protocol (Schnorr-like) |
| **Aggregation Proof** | Proves aggregator computed sum honestly | Commit-and-prove with Fiat-Shamir |
| **Billing Compliance Proof** | Proves bill = consumption × rate for correct ToU slot | Sigma protocol |

All proofs use **Pedersen commitments** and are made non-interactive via the **Fiat-Shamir heuristic**.

### Verifiable Computation

- Aggregator records every aggregation with a ZKP proof of correct execution
- Control Center verifies each aggregation proof on receipt
- Full audit log exported to `verification_audit.csv`

### Security Properties

- **Soundness**: Malicious meters cannot forge valid range or correctness proofs
- **Zero-Knowledge**: Proofs reveal nothing about the actual consumption value
- **Robustness**: False data injection is detected via range proof verification at the aggregator
- **Verifiability**: Aggregator honesty is cryptographically verified at the control center

## Theft Detection

Anomaly detection on encrypted consumption data:

- **Z-score analysis**: Detects readings > 3σ from historical mean
- **Spike detection**: Identifies sudden consumption increases (configurable multiplier)
- **Drop detection**: Flags suspicious consumption drops below threshold
- **Zero-pattern fraud**: Detects consecutive zero readings from normally-active meters
- **Peer-group comparison**: Encrypted peer-mean computation via homomorphic addition
- **Historical baseline**: Rolling encrypted history window per meter (default: 24 readings)

All profile tracking uses encrypted ciphertexts; threshold decisions use decrypted statistics at the control center.

## Time-of-Use (ToU) Billing

Privacy-preserving dynamic pricing with verifiable bill generation:

| Slot | Hours | Rate (p/kWh) |
|------|-------|-------------|
| Off-Peak | 00:00–07:00, 23:00–00:00 | 7.5 |
| Mid-Peak | 07:00–16:00, 19:00–23:00 | 15.0 |
| Peak | 16:00–19:00 | 30.0 |
| Critical | Dynamic (grid stress) | 50.0 |

- Readings are classified into ToU slots at the aggregator
- Encrypted cost = encrypted consumption × rate (per slot)
- Bills include a **ZKP compliance proof** verifying correct rate application
- Billing summaries exported to CSV with per-slot breakdowns

## Output

### CSV Metrics (in `output/`)

| File | Contents |
|------|----------|
| `encryption_metrics.csv` | Encrypt/decrypt timing, ciphertext sizes, HE error |
| `network_metrics.csv` | TLS handshakes, connection timing |
| `homomorphic_metrics.csv` | HE operation costs (add, add_many) |
| `scalability_metrics.csv` | Per-batch mean consumption, meter readings |
| `security_metrics.csv` | ZKP proof generation/verification timing, theft detection metrics |
| `batch_analytics.csv` | Decrypted results vs plaintext reference, verification status, anomaly counts |
| `analytics_report.txt` | Human-readable summary report with security section |
| `verification_audit.csv` | Aggregation proof verification log (batch ID, valid/invalid, timing) |
| `theft_detection.csv` | Detected theft anomalies (meter ID, z-score, anomaly type) |
| `tou_billing.csv` | Per-meter ToU bills (slot breakdown, consumption, cost, proof status) |

All CSVs use ISO-8601 timestamps and are compatible with Python/R/MATLAB.

## Project Structure

```
├── CMakeLists.txt
├── config.json
├── include/common/          # Headers
│   ├── config.h
│   ├── logger.h
│   ├── metrics.h
│   ├── tls_context.h
│   ├── certificate_generator.h
│   ├── crypto_engine.h
│   ├── network.h
│   ├── energy_simulator.h
│   ├── zkp_engine.h             # Zero-Knowledge Proof engine
│   ├── verifiable_computation.h # Aggregator honesty verification
│   ├── theft_detection.h        # Encrypted anomaly detection
│   └── tou_billing.h            # Time-of-Use billing engine
├── src/
│   ├── common/              # Shared library
│   ├── key_generator_main.cpp
│   ├── cert_generator_main.cpp
│   ├── kdc_main.cpp
│   ├── smart_meter_main.cpp
│   ├── aggregator_main.cpp
│   └── control_center_main.cpp
├── scripts/
│   ├── build.sh
│   ├── setup.sh
│   ├── run.sh
│   └── benchmark.sh
├── certs/                   # Generated certificates
├── keys/                    # Generated SEAL keys
└── output/                  # Metrics & reports
```

## Research Use

Designed for publication-grade benchmarking:

- **Reproducible**: Deterministic config, seeded RNG, ISO timestamps
- **Scalable**: Test with 10/50/100/500 meters via benchmark script
- **Comparable**: CSV output for cross-scheme comparison (BGV, BFV, TFHE)
- **Measurable**: Nanosecond-precision timing, memory/ciphertext size tracking
- **Security Evaluation**: ZKP proof sizes, generation/verification latency, tamper detection rates
- **Privacy Metrics**: Per-entity information leakage analysis, ToU billing without decryption

## Threat Model

The system assumes **active (malicious) adversaries** who may:

- Inject false or manipulated smart-meter readings
- Tamper with intermediate aggregation computations
- Provide selectively incorrect data while appearing protocol-compliant

**Trust assumptions:**
- The KDC and Control Center are trusted (hold secret keys)
- Smart Meters and Aggregators are potentially compromised
- TLS 1.3 with mutual authentication secures all channels
- ZKPs provide cryptographic guarantees independent of channel security