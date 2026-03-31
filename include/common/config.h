#pragma once

#include <nlohmann/json.hpp>
#include <string>
#include <mutex>

namespace smartgrid {

class Config {
public:
    static Config& instance();

    void load(const std::string& path);
    const nlohmann::json& get() const { return data_; }

    // Convenience accessors
    size_t poly_modulus_degree() const;
    int scale_bits() const;
    std::vector<int> coeff_modulus_bits() const;
    int security_level() const;

    int smart_meter_count() const;
    int aggregator_batch_size() const;
    int send_interval_ms() const;

    std::string kdc_host() const;
    int kdc_port() const;
    std::string aggregator_host() const;
    int aggregator_port() const;
    std::string control_center_host() const;
    int control_center_port() const;

    int connection_timeout_ms() const;
    int retry_attempts() const;
    int retry_delay_ms() const;

    std::string metrics_output_dir() const;
    bool metrics_enabled() const;

    std::string keys_dir() const;

    std::string tls_ca_cert() const;
    std::string tls_ca_key() const;

    std::string log_level() const;
    std::string log_file() const;
    bool log_to_console() const;

private:
    Config() = default;
    nlohmann::json data_;
    mutable std::mutex mtx_;
};

} // namespace smartgrid
