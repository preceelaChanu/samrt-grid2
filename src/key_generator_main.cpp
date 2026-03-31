// Key Generator - generates CKKS keys and saves them to disk
#include "common/config.h"
#include "common/logger.h"
#include "common/crypto_engine.h"
#include "common/metrics.h"
#include <filesystem>
#include <iostream>

int main(int argc, char* argv[]) {
    std::string config_path = (argc > 1) ? argv[1] : "config.json";

    try {
        auto& cfg = smartgrid::Config::instance();
        cfg.load(config_path);

        auto& logger = smartgrid::Logger::instance();
        logger.init(cfg.log_file(), smartgrid::Logger::parse_level(cfg.log_level()),
                    cfg.log_to_console());

        auto& metrics = smartgrid::MetricsCollector::instance();
        metrics.set_enabled(cfg.metrics_enabled());
        metrics.set_output_dir(cfg.metrics_output_dir());

        LOG_INFO("KeyGen", "Starting CKKS key generation");

        // Create keys directory
        std::string keys_dir = cfg.keys_dir();
        std::filesystem::create_directories(keys_dir);

        // Initialize crypto engine
        smartgrid::CryptoEngine engine;
        engine.init(cfg.poly_modulus_degree(), cfg.coeff_modulus_bits(),
                    cfg.scale_bits(), cfg.security_level());

        // Generate keys
        engine.generate_keys();

        // Save all keys
        auto& json = cfg.get();
        engine.save_params(json["keys"]["seal_params"].get<std::string>());
        engine.save_public_key(json["keys"]["public_key"].get<std::string>());
        engine.save_secret_key(json["keys"]["secret_key"].get<std::string>());
        engine.save_relin_keys(json["keys"]["relin_keys"].get<std::string>());

        LOG_INFO("KeyGen", "All keys saved to " + keys_dir);

        // Record key sizes
        for (auto& entry : std::filesystem::directory_iterator(keys_dir)) {
            metrics.record_size("security", "key_file_size",
                std::filesystem::file_size(entry.path()),
                entry.path().filename().string());
        }

        metrics.export_csv();
        LOG_INFO("KeyGen", "Key generation complete");

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
