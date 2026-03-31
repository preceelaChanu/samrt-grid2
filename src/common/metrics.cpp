#include "common/metrics.h"
#include <filesystem>
#include <algorithm>
#include <iomanip>
#include <sstream>
#include <set>

namespace smartgrid {

MetricsCollector& MetricsCollector::instance() {
    static MetricsCollector inst;
    return inst;
}

void MetricsCollector::set_output_dir(const std::string& dir) {
    std::lock_guard<std::mutex> lock(mtx_);
    output_dir_ = dir;
    std::filesystem::create_directories(dir);
}

void MetricsCollector::set_enabled(bool enabled) {
    std::lock_guard<std::mutex> lock(mtx_);
    enabled_ = enabled;
}

void MetricsCollector::record_timing(const std::string& category, const std::string& operation,
                                     std::chrono::nanoseconds duration, const std::string& metadata) {
    record(category, operation, static_cast<double>(duration.count()), "ns", metadata);
}

void MetricsCollector::record_size(const std::string& category, const std::string& operation,
                                   size_t bytes, const std::string& metadata) {
    record(category, operation, static_cast<double>(bytes), "bytes", metadata);
}

void MetricsCollector::record_throughput(const std::string& category, const std::string& operation,
                                         double ops_per_sec, const std::string& metadata) {
    record(category, operation, ops_per_sec, "ops/sec", metadata);
}

void MetricsCollector::record(const std::string& category, const std::string& operation,
                              double value, const std::string& unit, const std::string& metadata) {
    if (!enabled_) return;
    std::lock_guard<std::mutex> lock(mtx_);
    entries_.push_back({iso8601_now(), category, operation, value, unit, metadata});
}

void MetricsCollector::export_csv() const {
    std::lock_guard<std::mutex> lock(mtx_);
    std::filesystem::create_directories(output_dir_);

    // Collect unique categories
    std::set<std::string> categories;
    for (auto& e : entries_) categories.insert(e.category);

    for (auto& cat : categories) {
        std::string filename = cat + "_metrics.csv";
        export_csv(cat, filename);
    }
}

void MetricsCollector::export_csv(const std::string& category, const std::string& filename) const {
    std::string path = output_dir_ + "/" + filename;
    std::ofstream f(path);
    if (!f.is_open()) return;

    f << "timestamp,category,operation,value,unit,metadata\n";
    for (auto& e : entries_) {
        if (e.category == category) {
            f << e.timestamp << ","
              << e.category << ","
              << e.operation << ","
              << std::fixed << std::setprecision(3) << e.value << ","
              << e.unit << ","
              << "\"" << e.metadata << "\"\n";
        }
    }
}

std::string MetricsCollector::iso8601_now() const {
    auto now = std::chrono::system_clock::now();
    auto t = std::chrono::system_clock::to_time_t(now);
    auto us = std::chrono::duration_cast<std::chrono::microseconds>(
        now.time_since_epoch()) % 1000000;
    std::tm tm_buf;
    gmtime_r(&t, &tm_buf);
    std::ostringstream oss;
    oss << std::put_time(&tm_buf, "%Y-%m-%dT%H:%M:%S")
        << '.' << std::setfill('0') << std::setw(6) << us.count() << "Z";
    return oss.str();
}

// ScopedTimer
ScopedTimer::ScopedTimer(const std::string& category, const std::string& operation,
                         const std::string& metadata)
    : category_(category), operation_(operation), metadata_(metadata),
      start_(std::chrono::high_resolution_clock::now()) {}

ScopedTimer::~ScopedTimer() {
    auto end = std::chrono::high_resolution_clock::now();
    auto dur = std::chrono::duration_cast<std::chrono::nanoseconds>(end - start_);
    MetricsCollector::instance().record_timing(category_, operation_, dur, metadata_);
}

} // namespace smartgrid
