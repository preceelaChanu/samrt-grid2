# Privacy-Preserving Smart Grid Analytics Framework

A production-ready, 3-tier privacy-preserving smart grid framework using **CKKS Homomorphic Encryption** (Microsoft SEAL 4.1) for end-to-end encrypted energy consumption analytics.

## Architecture

```
Smart Meters (up to 500) ──[TLS 1.3 + CKKS]──> Aggregator ──[TLS 1.3]──> Control Center
                                                     │
Key Distribution Center <──[TLS 1.3]─── All nodes (certificate-authenticated)
```

### Components

| Component | Executable | Description |
|-----------|-----------|-------------|
| Certificate Generator | `cert_generator` | X.509 CA + node certificates (OpenSSL) |
| Key Generator | `key_generator` | CKKS parameters + public/secret/relin keys |
| Key Distribution Center | `kdc` | Serves SEAL keys to authenticated clients |
| Smart Meters | `smart_meter` | Simulates UK household energy + CKKS encryption |
| Aggregator | `aggregator` | Batched homomorphic addition of ciphertexts |
| Control Center | `control_center` | Decryption, analytics, CSV export |

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

## Output

### CSV Metrics (in `output/`)

| File | Contents |
|------|----------|
| `encryption_metrics.csv` | Encrypt/decrypt timing, ciphertext sizes, HE error |
| `network_metrics.csv` | TLS handshakes, connection timing |
| `homomorphic_metrics.csv` | HE operation costs (add, add_many) |
| `scalability_metrics.csv` | Per-batch mean consumption, meter readings |
| `security_metrics.csv` | Key file sizes, security parameters |
| `batch_analytics.csv` | Decrypted results vs plaintext reference |
| `analytics_report.txt` | Human-readable summary report |

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
│   └── energy_simulator.h
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