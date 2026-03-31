#pragma once

#include <string>
#include <vector>
#include <mutex>
#include <chrono>
#include <fstream>

namespace smartgrid {

struct MetricEntry {
    std::string timestamp;
    std::string category;
    std::string operation;
    double value;
    std::string unit;
    std::string metadata;
};

class MetricsCollector {
public:
    static MetricsCollector& instance();

    void set_output_dir(const std::string& dir);
    void set_enabled(bool enabled);

    // Record a timing metric (nanoseconds)
    void record_timing(const std::string& category, const std::string& operation,
                       std::chrono::nanoseconds duration, const std::string& metadata = "");

    // Record a size metric (bytes)
    void record_size(const std::string& category, const std::string& operation,
                     size_t bytes, const std::string& metadata = "");

    // Record a throughput metric
    void record_throughput(const std::string& category, const std::string& operation,
                          double ops_per_sec, const std::string& metadata = "");

    // Record a generic metric
    void record(const std::string& category, const std::string& operation,
                double value, const std::string& unit, const std::string& metadata = "");

    // Export all metrics to CSV files
    void export_csv() const;

    // Export specific category
    void export_csv(const std::string& category, const std::string& filename) const;

private:
    MetricsCollector() = default;
    std::string output_dir_ = "output";
    bool enabled_ = true;
    mutable std::mutex mtx_;
    std::vector<MetricEntry> entries_;

    std::string iso8601_now() const;
};

// RAII timer
class ScopedTimer {
public:
    ScopedTimer(const std::string& category, const std::string& operation,
                const std::string& metadata = "");
    ~ScopedTimer();

private:
    std::string category_;
    std::string operation_;
    std::string metadata_;
    std::chrono::high_resolution_clock::time_point start_;
};

} // namespace smartgrid
