// Control Center - receives aggregated ciphertexts, decrypts, performs analytics, exports CSV
#include "common/config.h"
#include "common/logger.h"
#include "common/crypto_engine.h"
#include "common/network.h"
#include "common/tls_context.h"
#include "common/metrics.h"

#include <csignal>
#include <atomic>
#include <iostream>
#include <fstream>
#include <vector>
#include <algorithm>
#include <numeric>
#include <cmath>
#include <filesystem>
#include <iomanip>
#include <sstream>

static std::atomic<bool> g_running{true};

static void signal_handler(int) {
    g_running = false;
}

struct AggregatedBatch {
    uint32_t batch_id;
    uint32_t num_readings;
    double plaintext_sum_ref;
    double decrypted_sum;
    double mean;
    std::string timestamp;
};

static std::string iso_now() {
    auto now = std::chrono::system_clock::now();
    auto t = std::chrono::system_clock::to_time_t(now);
    std::tm tm_buf;
    gmtime_r(&t, &tm_buf);
    std::ostringstream oss;
    oss << std::put_time(&tm_buf, "%Y-%m-%dT%H:%M:%SZ");
    return oss.str();
}

int main(int argc, char* argv[]) {
    std::string config_path = (argc > 1) ? argv[1] : "config.json";

    try {
        std::signal(SIGINT, signal_handler);
        std::signal(SIGTERM, signal_handler);

        smartgrid::TLSContext::init_openssl();

        auto& cfg = smartgrid::Config::instance();
        cfg.load(config_path);

        auto& logger = smartgrid::Logger::instance();
        logger.init(cfg.log_file(), smartgrid::Logger::parse_level(cfg.log_level()),
                    cfg.log_to_console());

        auto& metrics = smartgrid::MetricsCollector::instance();
        metrics.set_enabled(cfg.metrics_enabled());
        metrics.set_output_dir(cfg.metrics_output_dir());

        LOG_INFO("ControlCenter", "Starting Control Center");

        // Load SEAL keys (including secret key for decryption)
        auto& keys_cfg = cfg.get()["keys"];
        smartgrid::CryptoEngine crypto;
        crypto.init_from_files(
            keys_cfg["seal_params"].get<std::string>(),
            keys_cfg["public_key"].get<std::string>(),
            keys_cfg["secret_key"].get<std::string>(),
            keys_cfg["relin_keys"].get<std::string>()
        );

        LOG_INFO("ControlCenter", "CKKS engine initialized with secret key");

        // Setup output directory
        auto& cc_cfg = cfg.get()["control_center"];
        std::string output_dir = cc_cfg["csv_output_dir"].get<std::string>();
        std::string report_file = cc_cfg["report_file"].get<std::string>();
        std::filesystem::create_directories(output_dir);

        // Setup TLS server to receive from aggregator
        auto& tls_cfg = cfg.get()["tls"];
        smartgrid::TLSContext server_tls(smartgrid::TLSContext::Role::SERVER);
        server_tls.load_certificates(
            tls_cfg["control_center_cert"].get<std::string>(),
            tls_cfg["control_center_key"].get<std::string>(),
            tls_cfg["ca_cert"].get<std::string>()
        );

        std::vector<AggregatedBatch> all_batches;
        std::mutex batches_mtx;

        auto agg_handler = [&](SSL* ssl, int /*fd*/) {
            LOG_INFO("ControlCenter", "Aggregator connected");

            while (g_running) {
                uint8_t msg_type;
                std::string msg_data;
                if (!smartgrid::NetworkUtils::recv_typed(ssl, msg_type, msg_data)) {
                    break;
                }

                if (msg_type != static_cast<uint8_t>(smartgrid::MsgType::AGGREGATED_DATA)) {
                    continue;
                }

                if (msg_data.size() < 16) continue;

                uint32_t batch_id, num_readings;
                double plaintext_sum_ref;
                std::memcpy(&batch_id, msg_data.data(), 4);
                std::memcpy(&num_readings, msg_data.data() + 4, 4);
                uint64_t ps_bits;
                std::memcpy(&ps_bits, msg_data.data() + 8, 8);
                std::memcpy(&plaintext_sum_ref, &ps_bits, sizeof(double));

                std::string ct_data = msg_data.substr(16);

                LOG_INFO("ControlCenter", "Received batch " + std::to_string(batch_id) +
                         ": " + std::to_string(num_readings) + " readings, " +
                         std::to_string(ct_data.size()) + " bytes");

                // Decrypt
                smartgrid::ScopedTimer timer("encryption", "batch_decrypt",
                    "batch=" + std::to_string(batch_id));

                try {
                    seal::Ciphertext ct = crypto.deserialize_ciphertext(ct_data);
                    auto decrypted = crypto.decrypt(ct, 1);
                    double sum = decrypted[0];
                    double mean = (num_readings > 0) ? sum / num_readings : 0.0;
                    double error = std::abs(sum - plaintext_sum_ref);
                    double rel_error = (plaintext_sum_ref != 0.0) ?
                        error / std::abs(plaintext_sum_ref) * 100.0 : 0.0;

                    LOG_INFO("ControlCenter",
                             "Batch " + std::to_string(batch_id) + " decrypted:"
                             " sum=" + std::to_string(sum) +
                             " kWh, mean=" + std::to_string(mean) +
                             " kWh, ref_sum=" + std::to_string(plaintext_sum_ref) +
                             " kWh, error=" + std::to_string(rel_error) + "%");

                    AggregatedBatch batch_result{
                        batch_id, num_readings, plaintext_sum_ref,
                        sum, mean, iso_now()
                    };

                    {
                        std::lock_guard<std::mutex> lock(batches_mtx);
                        all_batches.push_back(batch_result);
                    }

                    // Record metrics
                    metrics.record("encryption", "decryption_error", error, "kWh",
                        "batch=" + std::to_string(batch_id));
                    metrics.record("encryption", "decryption_relative_error", rel_error, "%",
                        "batch=" + std::to_string(batch_id));
                    metrics.record("scalability", "batch_mean_consumption", mean, "kWh",
                        "batch=" + std::to_string(batch_id) +
                        " readings=" + std::to_string(num_readings));

                } catch (const std::exception& e) {
                    LOG_ERROR("ControlCenter", "Decryption failed: " + std::string(e.what()));
                }
            }

            LOG_INFO("ControlCenter", "Aggregator disconnected");
        };

        smartgrid::TLSServer server(server_tls, cfg.control_center_port(), agg_handler);
        server.start();

        LOG_INFO("ControlCenter", "Ready on port " + std::to_string(cfg.control_center_port()));

        // Analytics reporting loop
        int analytics_interval = cc_cfg["analytics_interval_ms"].get<int>();

        while (g_running) {
            std::this_thread::sleep_for(std::chrono::milliseconds(analytics_interval));

            std::lock_guard<std::mutex> lock(batches_mtx);
            if (all_batches.empty()) continue;

            // Generate analytics report
            double total_energy = 0.0;
            uint32_t total_readings = 0;
            double max_batch_mean = -1.0;
            double min_batch_mean = 1e9;
            double total_error = 0.0;

            for (auto& b : all_batches) {
                total_energy += b.decrypted_sum;
                total_readings += b.num_readings;
                max_batch_mean = std::max(max_batch_mean, b.mean);
                min_batch_mean = std::min(min_batch_mean, b.mean);
                total_error += std::abs(b.decrypted_sum - b.plaintext_sum_ref);
            }

            double overall_mean = (total_readings > 0) ? total_energy / total_readings : 0.0;
            double avg_error = total_error / static_cast<double>(all_batches.size());

            LOG_INFO("ControlCenter", "=== Analytics Report ===");
            LOG_INFO("ControlCenter", "Batches processed: " + std::to_string(all_batches.size()));
            LOG_INFO("ControlCenter", "Total readings: " + std::to_string(total_readings));
            LOG_INFO("ControlCenter", "Total energy: " + std::to_string(total_energy) + " kWh");
            LOG_INFO("ControlCenter", "Overall mean: " + std::to_string(overall_mean) + " kWh");
            LOG_INFO("ControlCenter", "Batch mean range: [" + std::to_string(min_batch_mean) +
                     ", " + std::to_string(max_batch_mean) + "] kWh");
            LOG_INFO("ControlCenter", "Avg HE error: " + std::to_string(avg_error) + " kWh");

            // Write report file
            {
                std::ofstream report(report_file);
                report << "Smart Grid Privacy-Preserving Analytics Report\n";
                report << "Generated: " << iso_now() << "\n";
                report << "=============================================\n\n";
                report << "Configuration:\n";
                report << "  CKKS Polynomial Degree: " << cfg.poly_modulus_degree() << "\n";
                report << "  Scale: 2^" << cfg.scale_bits() << "\n";
                report << "  Security Level: " << cfg.security_level() << "-bit\n";
                report << "  Smart Meters: " << cfg.smart_meter_count() << "\n\n";
                report << "Results:\n";
                report << "  Batches Processed: " << all_batches.size() << "\n";
                report << "  Total Readings: " << total_readings << "\n";
                report << std::fixed << std::setprecision(6);
                report << "  Total Energy: " << total_energy << " kWh\n";
                report << "  Overall Mean: " << overall_mean << " kWh\n";
                report << "  Min Batch Mean: " << min_batch_mean << " kWh\n";
                report << "  Max Batch Mean: " << max_batch_mean << " kWh\n";
                report << "  Avg HE Abs Error: " << avg_error << " kWh\n\n";
                report << "Batch Details:\n";
                report << "  ID | Readings | Decrypted Sum | Reference Sum | Error | Mean\n";
                report << "  ---|----------|---------------|---------------|-------|-----\n";
                for (auto& b : all_batches) {
                    report << "  " << b.batch_id << " | "
                           << b.num_readings << " | "
                           << b.decrypted_sum << " | "
                           << b.plaintext_sum_ref << " | "
                           << std::abs(b.decrypted_sum - b.plaintext_sum_ref) << " | "
                           << b.mean << "\n";
                }
            }

            // Export batch analytics CSV
            {
                std::string csv_path = output_dir + "/batch_analytics.csv";
                std::ofstream csv(csv_path);
                csv << "timestamp,batch_id,num_readings,decrypted_sum_kwh,reference_sum_kwh,"
                       "absolute_error_kwh,relative_error_pct,mean_kwh\n";
                for (auto& b : all_batches) {
                    double error = std::abs(b.decrypted_sum - b.plaintext_sum_ref);
                    double rel = (b.plaintext_sum_ref != 0.0) ?
                        error / std::abs(b.plaintext_sum_ref) * 100.0 : 0.0;
                    csv << b.timestamp << ","
                        << b.batch_id << ","
                        << b.num_readings << ","
                        << std::fixed << std::setprecision(6)
                        << b.decrypted_sum << ","
                        << b.plaintext_sum_ref << ","
                        << error << ","
                        << rel << ","
                        << b.mean << "\n";
                }
            }
        }

        LOG_INFO("ControlCenter", "Shutting down...");
        server.stop();

        // Final CSV exports
        metrics.export_csv();

        // Export specific CSV files as required
        auto& csv_cfg = cfg.get()["metrics"]["csv_files"];
        metrics.export_csv("encryption", csv_cfg["encryption"].get<std::string>());
        metrics.export_csv("network", csv_cfg["network"].get<std::string>());
        metrics.export_csv("homomorphic", csv_cfg["homomorphic"].get<std::string>());
        metrics.export_csv("scalability", csv_cfg["scalability"].get<std::string>());
        metrics.export_csv("security", csv_cfg["security"].get<std::string>());

        LOG_INFO("ControlCenter", "All metrics exported. Shutdown complete.");

        smartgrid::TLSContext::cleanup_openssl();

    } catch (const std::exception& e) {
        std::cerr << "ControlCenter Error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
