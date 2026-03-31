#include "common/config.h"
#include <fstream>
#include <stdexcept>

namespace smartgrid {

Config& Config::instance() {
    static Config inst;
    return inst;
}

void Config::load(const std::string& path) {
    std::lock_guard<std::mutex> lock(mtx_);
    std::ifstream f(path);
    if (!f.is_open()) {
        throw std::runtime_error("Cannot open config file: " + path);
    }
    f >> data_;
}

size_t Config::poly_modulus_degree() const {
    return data_["seal"]["poly_modulus_degree"].get<size_t>();
}

int Config::scale_bits() const {
    return data_["seal"]["scale_bits"].get<int>();
}

std::vector<int> Config::coeff_modulus_bits() const {
    return data_["seal"]["coeff_modulus_bits"].get<std::vector<int>>();
}

int Config::security_level() const {
    return data_["seal"]["security_level"].get<int>();
}

int Config::smart_meter_count() const {
    return data_["smart_meters"]["count"].get<int>();
}

int Config::aggregator_batch_size() const {
    return data_["aggregator"]["batch_size"].get<int>();
}

int Config::send_interval_ms() const {
    return data_["smart_meters"]["send_interval_ms"].get<int>();
}

std::string Config::kdc_host() const {
    return data_["network"]["kdc_host"].get<std::string>();
}

int Config::kdc_port() const {
    return data_["network"]["kdc_port"].get<int>();
}

std::string Config::aggregator_host() const {
    return data_["network"]["aggregator_host"].get<std::string>();
}

int Config::aggregator_port() const {
    return data_["network"]["aggregator_port"].get<int>();
}

std::string Config::control_center_host() const {
    return data_["network"]["control_center_host"].get<std::string>();
}

int Config::control_center_port() const {
    return data_["network"]["control_center_port"].get<int>();
}

int Config::connection_timeout_ms() const {
    return data_["network"]["connection_timeout_ms"].get<int>();
}

int Config::retry_attempts() const {
    return data_["network"]["retry_attempts"].get<int>();
}

int Config::retry_delay_ms() const {
    return data_["network"]["retry_delay_ms"].get<int>();
}

std::string Config::metrics_output_dir() const {
    return data_["metrics"]["output_dir"].get<std::string>();
}

bool Config::metrics_enabled() const {
    return data_["metrics"]["enabled"].get<bool>();
}

std::string Config::keys_dir() const {
    return data_["keys"]["output_dir"].get<std::string>();
}

std::string Config::tls_ca_cert() const {
    return data_["tls"]["ca_cert"].get<std::string>();
}

std::string Config::tls_ca_key() const {
    return data_["tls"]["ca_key"].get<std::string>();
}

std::string Config::log_level() const {
    return data_["logging"]["level"].get<std::string>();
}

std::string Config::log_file() const {
    return data_["logging"]["file"].get<std::string>();
}

bool Config::log_to_console() const {
    return data_["logging"]["console"].get<bool>();
}

} // namespace smartgrid
