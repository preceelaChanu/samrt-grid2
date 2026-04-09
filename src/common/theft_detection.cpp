// Theft Detection Engine - Anomaly detection on encrypted consumption data
#include "common/theft_detection.h"
#include "common/logger.h"
#include "common/metrics.h"

#include <chrono>
#include <cmath>
#include <algorithm>
#include <numeric>
#include <fstream>
#include <iomanip>
#include <sstream>

namespace smartgrid {

TheftDetectionEngine::TheftDetectionEngine() = default;

void TheftDetectionEngine::init(CryptoEngine& crypto, int history_window,
                                 double anomaly_threshold_sigma,
                                 double spike_multiplier,
                                 double drop_threshold) {
    crypto_ = &crypto;
    history_window_ = history_window;
    anomaly_threshold_ = anomaly_threshold_sigma;
    spike_multiplier_ = spike_multiplier;
    drop_threshold_ = drop_threshold;

    LOG_INFO("TheftDetection", "Initialized: window=" + std::to_string(history_window) +
             " threshold=" + std::to_string(anomaly_threshold_sigma) + "σ" +
             " spike_mult=" + std::to_string(spike_multiplier) +
             " drop_thresh=" + std::to_string(drop_threshold));
}

void TheftDetectionEngine::update_meter_profile(uint32_t meter_id,
                                                  const seal::Ciphertext& encrypted_reading,
                                                  double plaintext_ref) {
    auto& profile = profiles_[meter_id];

    if (profile.reading_count == 0) {
        profile.meter_id = meter_id;
        profile.running_sum = encrypted_reading;
        profile.plaintext_sum = plaintext_ref;
    } else {
        // Homomorphic addition to running sum
        profile.running_sum = crypto_->add(profile.running_sum, encrypted_reading);
        profile.plaintext_sum += plaintext_ref;
    }

    profile.history.push_back(encrypted_reading);
    profile.plaintext_history.push_back(plaintext_ref);
    profile.reading_count++;

    // Maintain window size
    while (static_cast<int>(profile.history.size()) > history_window_) {
        profile.history.pop_front();
        profile.plaintext_history.pop_front();
    }
}

AnomalyResult TheftDetectionEngine::detect_anomaly(uint32_t meter_id) {
    auto start = std::chrono::high_resolution_clock::now();

    AnomalyResult result;
    result.meter_id = meter_id;
    result.is_anomalous = false;
    result.anomaly_type = "none";
    result.timestamp = iso_now();

    auto it = profiles_.find(meter_id);
    if (it == profiles_.end() || it->second.plaintext_history.size() < 3) {
        result.z_score = 0.0;
        result.deviation_pct = 0.0;
        return result;
    }

    auto& profile = it->second;
    auto& history = profile.plaintext_history;

    // Compute statistics from plaintext history
    // NOTE: In a full production system, these computations would use
    // secure multi-party computation (MPC) or trusted execution environments (TEE).
    // For this simulation, we use decrypted/plaintext values to demonstrate the
    // detection logic that would operate identically on encrypted data via FHE.
    double mean = compute_mean(history);
    double stddev = compute_stddev(history, mean);

    double latest = history.back();

    // Z-score calculation
    if (stddev > 1e-10) {
        result.z_score = (latest - mean) / stddev;
    } else {
        result.z_score = 0.0;
    }

    // Deviation from mean
    if (mean > 1e-10) {
        result.deviation_pct = ((latest - mean) / mean) * 100.0;
    } else {
        result.deviation_pct = (latest > 1e-10) ? 100.0 : 0.0;
    }

    // Classify anomaly
    if (std::abs(result.z_score) > anomaly_threshold_) {
        result.is_anomalous = true;
        result.anomaly_type = classify_anomaly(latest, mean, stddev);
    }

    // Check for zero-reading fraud pattern (consecutive zeros)
    int consecutive_zeros = 0;
    for (auto rit = history.rbegin(); rit != history.rend(); ++rit) {
        if (*rit < 1e-10) consecutive_zeros++;
        else break;
    }
    if (consecutive_zeros >= 3 && mean > 0.05) {
        result.is_anomalous = true;
        result.anomaly_type = "zero_pattern";
    }

    auto end = std::chrono::high_resolution_clock::now();
    double ms = std::chrono::duration<double, std::milli>(end - start).count();

    MetricsCollector::instance().record("security", "theft_detection_single",
        ms, "ms", "meter=" + std::to_string(meter_id) +
        " anomalous=" + std::string(result.is_anomalous ? "true" : "false"));

    return result;
}

TheftDetectionReport TheftDetectionEngine::run_batch_detection(uint32_t batch_id) {
    auto start = std::chrono::high_resolution_clock::now();

    TheftDetectionReport report;
    report.batch_id = batch_id;
    report.total_meters = static_cast<int>(profiles_.size());
    report.anomalous_meters = 0;
    report.timestamp = iso_now();

    for (auto& [meter_id, profile] : profiles_) {
        auto result = detect_anomaly(meter_id);
        if (result.is_anomalous) {
            report.anomalous_meters++;
            report.anomalies.push_back(result);
        }
    }

    report.detection_rate = (report.total_meters > 0) ?
        static_cast<double>(report.anomalous_meters) / report.total_meters : 0.0;

    auto end = std::chrono::high_resolution_clock::now();
    report.computation_time_ms = std::chrono::duration<double, std::milli>(end - start).count();

    MetricsCollector::instance().record("security", "theft_detection_batch",
        report.computation_time_ms, "ms",
        "batch=" + std::to_string(batch_id) +
        " meters=" + std::to_string(report.total_meters) +
        " anomalous=" + std::to_string(report.anomalous_meters));

    LOG_INFO("TheftDetection", "Batch " + std::to_string(batch_id) + ": " +
             std::to_string(report.anomalous_meters) + "/" + std::to_string(report.total_meters) +
             " anomalous (" + std::to_string(report.detection_rate * 100.0) + "%)");

    return report;
}

// --- Peer Group Analysis (on encrypted data) ---

seal::Ciphertext TheftDetectionEngine::compute_encrypted_peer_mean(
    const std::vector<seal::Ciphertext>& readings, int count) {
    if (readings.empty()) throw std::runtime_error("No readings for peer mean");

    // Sum all encrypted readings
    seal::Ciphertext sum = crypto_->add_many(
        const_cast<std::vector<seal::Ciphertext>&>(readings));

    // Division by count is approximated: we encode 1/count as a plaintext
    // and multiply. For CKKS this is accurate.
    // Note: In production you'd use crypto_->multiply_plain() but since
    // the existing API only has add, we return the sum and let the consumer
    // handle the division at decryption time.
    return sum;
}

seal::Ciphertext TheftDetectionEngine::compute_encrypted_deviation(
    const seal::Ciphertext& reading, const seal::Ciphertext& peer_mean) {
    // Compute reading - peer_mean homomorphically
    // We negate peer_mean by encrypting -1 and multiplying (expensive),
    // but since we only have add in the API, we compute reading + (-peer_mean)
    // by returning the sum (the caller must interpret with correct sign at decryption)

    // For now, return the sum (reading + peer_mean). The control center
    // can compute deviation = decrypted_reading - (decrypted_sum / count)
    return crypto_->add(reading, peer_mean);
}

seal::Ciphertext TheftDetectionEngine::compute_encrypted_historical_mean(uint32_t meter_id) {
    auto it = profiles_.find(meter_id);
    if (it == profiles_.end() || it->second.history.empty()) {
        throw std::runtime_error("No history for meter " + std::to_string(meter_id));
    }

    std::vector<seal::Ciphertext> history_vec(it->second.history.begin(),
                                                it->second.history.end());
    return crypto_->add_many(history_vec);
}

void TheftDetectionEngine::export_report_csv(const TheftDetectionReport& report,
                                               const std::string& path) const {
    std::ofstream csv(path, std::ios::app);

    // Header if file is empty
    csv.seekp(0, std::ios::end);
    if (csv.tellp() == 0) {
        csv << "timestamp,batch_id,meter_id,z_score,deviation_pct,is_anomalous,anomaly_type\n";
    }

    for (auto& a : report.anomalies) {
        csv << a.timestamp << ","
            << report.batch_id << ","
            << a.meter_id << ","
            << std::fixed << std::setprecision(4) << a.z_score << ","
            << a.deviation_pct << ","
            << (a.is_anomalous ? "true" : "false") << ","
            << a.anomaly_type << "\n";
    }
}

// --- Internal ---

double TheftDetectionEngine::compute_mean(const std::deque<double>& history) const {
    if (history.empty()) return 0.0;
    double sum = std::accumulate(history.begin(), history.end(), 0.0);
    return sum / static_cast<double>(history.size());
}

double TheftDetectionEngine::compute_stddev(const std::deque<double>& history, double mean) const {
    if (history.size() < 2) return 0.0;
    double sq_sum = 0.0;
    for (double v : history) {
        double diff = v - mean;
        sq_sum += diff * diff;
    }
    return std::sqrt(sq_sum / static_cast<double>(history.size() - 1));
}

std::string TheftDetectionEngine::classify_anomaly(double value, double mean, double stddev) const {
    if (value > mean + spike_multiplier_ * stddev) return "spike";
    if (value < mean * drop_threshold_) return "drop";
    if (std::abs(value - mean) > anomaly_threshold_ * stddev) return "inconsistent";
    return "unknown";
}

std::string TheftDetectionEngine::iso_now() const {
    auto now = std::chrono::system_clock::now();
    auto t = std::chrono::system_clock::to_time_t(now);
    std::tm tm_buf;
    gmtime_r(&t, &tm_buf);
    std::ostringstream oss;
    oss << std::put_time(&tm_buf, "%Y-%m-%dT%H:%M:%SZ");
    return oss.str();
}

} // namespace smartgrid
