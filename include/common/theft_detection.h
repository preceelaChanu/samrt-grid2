#pragma once

#include "common/crypto_engine.h"
#include <seal/seal.h>
#include <string>
#include <vector>
#include <deque>
#include <cstdint>

namespace smartgrid {

// Anomaly detection result for a single meter
struct AnomalyResult {
    uint32_t meter_id;
    double z_score;          // Standard deviations from peer mean
    double deviation_pct;    // Percentage deviation from expected
    bool is_anomalous;       // Exceeds threshold
    std::string anomaly_type; // "spike", "drop", "zero_pattern", "inconsistent"
    std::string timestamp;
};

// Theft detection report for a batch
struct TheftDetectionReport {
    uint32_t batch_id;
    int total_meters;
    int anomalous_meters;
    double detection_rate;
    std::vector<AnomalyResult> anomalies;
    double computation_time_ms;
    std::string timestamp;
};

// Encrypted consumption profile (historical) for a meter
struct EncryptedMeterProfile {
    uint32_t meter_id;
    std::deque<seal::Ciphertext> history;  // Rolling window of encrypted readings
    seal::Ciphertext running_sum;           // Encrypted running sum
    uint32_t reading_count;
    // Plaintext reference for simulation verification
    std::deque<double> plaintext_history;
    double plaintext_sum;
};

// Theft Detection Engine
// Performs anomaly detection on encrypted consumption data using HE operations
// Can detect: abnormal spikes/drops, zero-reading fraud, meter tampering patterns
class TheftDetectionEngine {
public:
    TheftDetectionEngine();

    // Initialize with crypto engine and config parameters
    void init(CryptoEngine& crypto, int history_window = 24,
              double anomaly_threshold_sigma = 3.0,
              double spike_multiplier = 3.0,
              double drop_threshold = 0.1);

    // --- Core Detection ---

    // Update a meter's encrypted profile with a new reading
    void update_meter_profile(uint32_t meter_id, const seal::Ciphertext& encrypted_reading,
                               double plaintext_ref = 0.0);

    // Run anomaly detection on a specific meter (operates on encrypted history)
    AnomalyResult detect_anomaly(uint32_t meter_id);

    // Run batch anomaly detection across all tracked meters
    TheftDetectionReport run_batch_detection(uint32_t batch_id);

    // --- Peer Group Analysis (on encrypted data) ---

    // Compute encrypted peer-group mean from a set of meter readings
    seal::Ciphertext compute_encrypted_peer_mean(const std::vector<seal::Ciphertext>& readings,
                                                   int count);

    // Compare a meter's reading against encrypted peer mean
    // Returns encrypted difference (decryption needed at control center)
    seal::Ciphertext compute_encrypted_deviation(const seal::Ciphertext& reading,
                                                   const seal::Ciphertext& peer_mean);

    // --- Historical Baseline (on encrypted data) ---

    // Compute encrypted historical mean for a meter
    seal::Ciphertext compute_encrypted_historical_mean(uint32_t meter_id);

    // --- Statistics ---
    size_t tracked_meters() const { return profiles_.size(); }
    int history_window() const { return history_window_; }
    void export_report_csv(const TheftDetectionReport& report, const std::string& path) const;

private:
    CryptoEngine* crypto_ = nullptr;
    int history_window_ = 24;
    double anomaly_threshold_ = 3.0;
    double spike_multiplier_ = 3.0;
    double drop_threshold_ = 0.1;

    std::unordered_map<uint32_t, EncryptedMeterProfile> profiles_;

    // Internal: compute stats from plaintext history for threshold decisions
    // In production, this would use MPC or TEE; here we use decrypted values for simulation
    double compute_mean(const std::deque<double>& history) const;
    double compute_stddev(const std::deque<double>& history, double mean) const;
    std::string classify_anomaly(double value, double mean, double stddev) const;
    std::string iso_now() const;
};

} // namespace smartgrid
