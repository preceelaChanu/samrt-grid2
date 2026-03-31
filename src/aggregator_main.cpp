// Aggregator - receives encrypted meter data, performs homomorphic aggregation, forwards to Control Center
#include "common/config.h"
#include "common/logger.h"
#include "common/crypto_engine.h"
#include "common/network.h"
#include "common/tls_context.h"
#include "common/metrics.h"

#include <csignal>
#include <atomic>
#include <iostream>
#include <thread>
#include <vector>
#include <queue>
#include <condition_variable>

static std::atomic<bool> g_running{true};

static void signal_handler(int) {
    g_running = false;
}

// Thread-safe queue for incoming ciphertexts
struct MeterReading {
    uint32_t meter_id;
    double plaintext_ref; // for verification only
    seal::Ciphertext ciphertext;
};

class ReadingQueue {
public:
    void push(MeterReading&& r) {
        std::lock_guard<std::mutex> lock(mtx_);
        queue_.push(std::move(r));
        cv_.notify_one();
    }

    bool pop_batch(std::vector<MeterReading>& batch, size_t max_size, int timeout_ms) {
        std::unique_lock<std::mutex> lock(mtx_);
        if (queue_.empty()) {
            cv_.wait_for(lock, std::chrono::milliseconds(timeout_ms),
                         [this]{ return !queue_.empty(); });
        }
        if (queue_.empty()) return false;

        size_t count = std::min(max_size, queue_.size());
        batch.reserve(count);
        for (size_t i = 0; i < count; i++) {
            batch.push_back(std::move(queue_.front()));
            queue_.pop();
        }
        return true;
    }

    size_t size() const {
        std::lock_guard<std::mutex> lock(mtx_);
        return queue_.size();
    }

private:
    std::queue<MeterReading> queue_;
    mutable std::mutex mtx_;
    std::condition_variable cv_;
};

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

        LOG_INFO("Aggregator", "Starting Aggregator");

        // Fetch SEAL keys from KDC
        auto& tls_cfg = cfg.get()["tls"];
        smartgrid::TLSContext kdc_tls(smartgrid::TLSContext::Role::CLIENT);
        kdc_tls.load_certificates(
            tls_cfg["client_cert"].get<std::string>(),
            tls_cfg["client_key"].get<std::string>(),
            tls_cfg["ca_cert"].get<std::string>()
        );

        smartgrid::TLSClient kdc_client(kdc_tls);
        if (!kdc_client.connect_with_retry(cfg.kdc_host(), cfg.kdc_port(),
                cfg.retry_attempts(), cfg.retry_delay_ms(), cfg.connection_timeout_ms())) {
            LOG_ERROR("Aggregator", "Cannot connect to KDC");
            return 1;
        }

        // Request keys
        smartgrid::NetworkUtils::send_typed(kdc_client.ssl(),
            static_cast<uint8_t>(smartgrid::MsgType::KEY_REQUEST), "");

        uint8_t type;
        std::string data;
        std::string params_data, pk_data, rk_data;

        smartgrid::NetworkUtils::recv_typed(kdc_client.ssl(), type, data);
        params_data = std::move(data);
        smartgrid::NetworkUtils::recv_typed(kdc_client.ssl(), type, data);
        pk_data = std::move(data);
        smartgrid::NetworkUtils::recv_typed(kdc_client.ssl(), type, data);
        rk_data = std::move(data);
        smartgrid::NetworkUtils::recv_typed(kdc_client.ssl(), type, data); // DONE

        kdc_client.disconnect();
        LOG_INFO("Aggregator", "SEAL keys received from KDC");

        // Initialize crypto
        smartgrid::CryptoEngine crypto;
        {
            auto write_temp = [](const std::string& name, const std::string& data) {
                std::string path = "/tmp/sg_agg_" + name;
                std::ofstream f(path, std::ios::binary);
                f.write(data.data(), static_cast<std::streamsize>(data.size()));
                return path;
            };
            std::string p = write_temp("params.seal", params_data);
            std::string pk = write_temp("pk.seal", pk_data);
            std::string rk = write_temp("rk.seal", rk_data);
            crypto.init_from_files(p, pk, "", rk);
        }

        // Reading queue
        ReadingQueue reading_queue;
        std::atomic<int> total_readings{0};

        // Setup TLS server for smart meters
        smartgrid::TLSContext server_tls(smartgrid::TLSContext::Role::SERVER);
        server_tls.load_certificates(
            tls_cfg["aggregator_cert"].get<std::string>(),
            tls_cfg["aggregator_key"].get<std::string>(),
            tls_cfg["ca_cert"].get<std::string>()
        );

        auto meter_handler = [&](SSL* ssl, int /*fd*/) {
            LOG_DEBUG("Aggregator", "Smart meter connected");

            while (g_running) {
                uint8_t msg_type;
                std::string msg_data;
                if (!smartgrid::NetworkUtils::recv_typed(ssl, msg_type, msg_data)) {
                    break;
                }

                if (msg_type != static_cast<uint8_t>(smartgrid::MsgType::METER_DATA)) {
                    continue;
                }

                if (msg_data.size() < 12) continue; // 4 (id) + 8 (double) + ct

                MeterReading reading;
                std::memcpy(&reading.meter_id, msg_data.data(), 4);
                std::memcpy(&reading.plaintext_ref, msg_data.data() + 4, 8);

                std::string ct_data = msg_data.substr(12);
                try {
                    reading.ciphertext = crypto.deserialize_ciphertext(ct_data);
                    reading_queue.push(std::move(reading));
                    total_readings++;
                } catch (const std::exception& e) {
                    LOG_WARN("Aggregator", "Failed to deserialize ciphertext: " + std::string(e.what()));
                }
            }
        };

        smartgrid::TLSServer meter_server(server_tls, cfg.aggregator_port(), meter_handler);
        meter_server.start();

        // Setup TLS for control center connection
        smartgrid::TLSContext cc_tls(smartgrid::TLSContext::Role::CLIENT);
        cc_tls.load_certificates(
            tls_cfg["client_cert"].get<std::string>(),
            tls_cfg["client_key"].get<std::string>(),
            tls_cfg["ca_cert"].get<std::string>()
        );

        // Connect to control center
        smartgrid::TLSClient cc_client(cc_tls);
        LOG_INFO("Aggregator", "Connecting to Control Center...");
        if (!cc_client.connect_with_retry(cfg.control_center_host(), cfg.control_center_port(),
                cfg.retry_attempts(), cfg.retry_delay_ms(), cfg.connection_timeout_ms())) {
            LOG_ERROR("Aggregator", "Cannot connect to Control Center");
            return 1;
        }
        LOG_INFO("Aggregator", "Connected to Control Center");

        // Aggregation loop
        int batch_size = cfg.aggregator_batch_size();
        int agg_interval = cfg.get()["aggregator"]["aggregation_interval_ms"].get<int>();
        int batch_count = 0;

        LOG_INFO("Aggregator", "Ready. batch_size=" + std::to_string(batch_size) +
                 " interval=" + std::to_string(agg_interval) + "ms");

        while (g_running) {
            std::vector<MeterReading> batch;
            if (!reading_queue.pop_batch(batch, static_cast<size_t>(batch_size), agg_interval)) {
                continue;
            }

            if (batch.empty()) continue;

            LOG_INFO("Aggregator", "Processing batch of " + std::to_string(batch.size()) +
                     " readings (total received: " + std::to_string(total_readings.load()) + ")");

            // Homomorphic aggregation
            smartgrid::ScopedTimer timer("homomorphic", "batch_aggregation",
                "batch_size=" + std::to_string(batch.size()));

            std::vector<seal::Ciphertext> cts;
            cts.reserve(batch.size());
            double plaintext_sum = 0.0;
            for (auto& r : batch) {
                cts.push_back(std::move(r.ciphertext));
                plaintext_sum += r.plaintext_ref;
            }

            seal::Ciphertext aggregated = crypto.add_many(cts);
            batch_count++;

            // Serialize and send to control center
            std::string agg_data = crypto.serialize_ciphertext(aggregated);

            // Include metadata: batch_count, num_readings, plaintext_sum_ref
            std::string payload;
            {
                uint32_t bc = static_cast<uint32_t>(batch_count);
                uint32_t nr = static_cast<uint32_t>(batch.size());
                payload.append(reinterpret_cast<const char*>(&bc), 4);
                payload.append(reinterpret_cast<const char*>(&nr), 4);
                uint64_t ps_bits;
                std::memcpy(&ps_bits, &plaintext_sum, sizeof(double));
                payload.append(reinterpret_cast<const char*>(&ps_bits), 8);
                payload += agg_data;
            }

            if (!smartgrid::NetworkUtils::send_typed(cc_client.ssl(),
                    static_cast<uint8_t>(smartgrid::MsgType::AGGREGATED_DATA), payload)) {
                LOG_WARN("Aggregator", "Failed to send aggregated data to Control Center");
            } else {
                LOG_INFO("Aggregator", "Batch " + std::to_string(batch_count) +
                         " sent: " + std::to_string(batch.size()) + " readings, " +
                         std::to_string(agg_data.size()) + " bytes");
            }

            metrics.record("homomorphic", "aggregation_batch_size",
                static_cast<double>(batch.size()), "readings",
                "batch=" + std::to_string(batch_count));
            metrics.record_size("homomorphic", "aggregated_ciphertext_size",
                agg_data.size(), "batch=" + std::to_string(batch_count));
        }

        LOG_INFO("Aggregator", "Shutting down...");
        meter_server.stop();
        cc_client.disconnect();
        metrics.export_csv();

        smartgrid::TLSContext::cleanup_openssl();

    } catch (const std::exception& e) {
        std::cerr << "Aggregator Error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
