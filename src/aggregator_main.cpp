// Aggregator - receives encrypted meter data, performs homomorphic aggregation, forwards to Control Center
// Extended: ZKP verification, verifiable computation, theft detection profiles, ToU accumulation
#include "common/config.h"
#include "common/logger.h"
#include "common/crypto_engine.h"
#include "common/network.h"
#include "common/tls_context.h"
#include "common/metrics.h"
#include "common/zkp_engine.h"
#include "common/verifiable_computation.h"
#include "common/theft_detection.h"
#include "common/tou_billing.h"

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
    uint8_t tou_hour;     // hour-of-day for ToU classification
    seal::Ciphertext ciphertext;
    smartgrid::RangeProof range_proof;
    smartgrid::CorrectnessProof correctness_proof;
    smartgrid::Commitment commitment;
    bool has_proofs = false;
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
        std::signal(SIGPIPE, SIG_IGN);

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

        // Initialize ZKP engine
        smartgrid::ZKPEngine zkp;
        int zkp_security = cfg.get().value("/zkp/security_bits"_json_pointer, 128);
        zkp.init(zkp_security);

        // Initialize verifiable computation
        smartgrid::VerifiableComputation verifiable;
        verifiable.init(zkp);

        // Initialize theft detection
        smartgrid::TheftDetectionEngine theft_detector;
        int history_window = cfg.get().value("/theft_detection/history_window"_json_pointer, 24);
        double anomaly_threshold = cfg.get().value("/theft_detection/anomaly_threshold_sigma"_json_pointer, 3.0);
        theft_detector.init(crypto, history_window, anomaly_threshold);

        // Initialize ToU billing
        smartgrid::ToUBillingEngine tou_billing;
        tou_billing.init(crypto, zkp);

        // Reading queue
        ReadingQueue reading_queue;
        std::atomic<int> total_readings{0};
        std::atomic<int> zkp_verified{0};
        std::atomic<int> zkp_failed{0};

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

                // New payload format: [meter_id:4][reading:8][tou_hour:1]
                //   [range_proof_len:4][range_proof][correctness_proof_len:4][correctness_proof]
                //   [commitment_data_len:4][commitment_data][commitment_blinding_len:4][commitment_blinding]
                //   [ct_data...]
                if (msg_data.size() < 13) continue; // 4 + 8 + 1 minimum

                MeterReading reading;
                size_t offset = 0;

                std::memcpy(&reading.meter_id, msg_data.data(), 4); offset += 4;
                std::memcpy(&reading.plaintext_ref, msg_data.data() + offset, 8); offset += 8;
                reading.tou_hour = static_cast<uint8_t>(msg_data[offset]); offset += 1;

                // Parse range proof
                if (offset + 4 <= msg_data.size()) {
                    uint32_t rp_len;
                    std::memcpy(&rp_len, msg_data.data() + offset, 4); offset += 4;
                    if (offset + rp_len <= msg_data.size()) {
                        std::string rp_data = msg_data.substr(offset, rp_len); offset += rp_len;
                        try {
                            reading.range_proof = zkp.deserialize_range_proof(rp_data);
                            reading.has_proofs = true;
                        } catch (...) {
                            LOG_WARN("Aggregator", "Failed to parse range proof from meter " +
                                     std::to_string(reading.meter_id));
                        }
                    }
                }

                // Parse correctness proof
                if (offset + 4 <= msg_data.size()) {
                    uint32_t cp_len;
                    std::memcpy(&cp_len, msg_data.data() + offset, 4); offset += 4;
                    if (offset + cp_len <= msg_data.size()) {
                        std::string cp_data = msg_data.substr(offset, cp_len); offset += cp_len;
                        try {
                            reading.correctness_proof = zkp.deserialize_correctness_proof(cp_data);
                        } catch (...) {
                            LOG_WARN("Aggregator", "Failed to parse correctness proof from meter " +
                                     std::to_string(reading.meter_id));
                        }
                    }
                }

                // Parse commitment
                if (offset + 4 <= msg_data.size()) {
                    uint32_t cm_len;
                    std::memcpy(&cm_len, msg_data.data() + offset, 4); offset += 4;
                    if (offset + cm_len <= msg_data.size()) {
                        reading.commitment.data.resize(cm_len);
                        std::memcpy(reading.commitment.data.data(), msg_data.data() + offset, cm_len);
                        offset += cm_len;
                    }
                }
                if (offset + 4 <= msg_data.size()) {
                    uint32_t cb_len;
                    std::memcpy(&cb_len, msg_data.data() + offset, 4); offset += 4;
                    if (offset + cb_len <= msg_data.size()) {
                        reading.commitment.blinding.resize(cb_len);
                        std::memcpy(reading.commitment.blinding.data(), msg_data.data() + offset, cb_len);
                        offset += cb_len;
                    }
                }

                // Remaining is ciphertext data
                std::string ct_data = msg_data.substr(offset);
                try {
                    reading.ciphertext = crypto.deserialize_ciphertext(ct_data);

                    // Verify range proof if present
                    if (reading.has_proofs) {
                        auto rp_result = zkp.verify_range_proof(reading.range_proof, reading.commitment);
                        if (rp_result.valid) {
                            zkp_verified++;
                        } else {
                            zkp_failed++;
                            LOG_WARN("Aggregator", "Range proof FAILED for meter " +
                                     std::to_string(reading.meter_id) + ": " + rp_result.reason);
                        }
                    }

                    // Update theft detection profile
                    theft_detector.update_meter_profile(reading.meter_id, reading.ciphertext,
                                                         reading.plaintext_ref);

                    // Accumulate ToU billing
                    tou_billing.accumulate_reading(reading.meter_id, reading.ciphertext,
                                                     reading.tou_hour, reading.plaintext_ref);

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

        // Connect to control center (with reconnection support)
        smartgrid::TLSClient cc_client(cc_tls);
        std::string cc_host = cfg.control_center_host();
        int cc_port = cfg.control_center_port();
        int cc_retry_attempts = cfg.retry_attempts();
        int cc_retry_delay = cfg.retry_delay_ms();
        int cc_timeout = cfg.connection_timeout_ms();

        auto connect_to_cc = [&]() -> bool {
            if (cc_client.is_connected()) {
                cc_client.disconnect();
            }
            LOG_INFO("Aggregator", "Connecting to Control Center...");
            return cc_client.connect_with_retry(cc_host, cc_port,
                cc_retry_attempts, cc_retry_delay, cc_timeout);
        };

        if (!connect_to_cc()) {
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

        int theft_detection_interval = 5; // Run theft detection every N batches

        while (g_running) {
            std::vector<MeterReading> batch;
            if (!reading_queue.pop_batch(batch, static_cast<size_t>(batch_size), agg_interval)) {
                continue;
            }

            if (batch.empty()) continue;

            LOG_INFO("Aggregator", "Processing batch of " + std::to_string(batch.size()) +
                     " readings (total: " + std::to_string(total_readings.load()) +
                     ", zkp_ok: " + std::to_string(zkp_verified.load()) +
                     ", zkp_fail: " + std::to_string(zkp_failed.load()) + ")");

            // Homomorphic aggregation
            smartgrid::ScopedTimer timer("homomorphic", "batch_aggregation",
                "batch_size=" + std::to_string(batch.size()));

            std::vector<seal::Ciphertext> cts;
            std::vector<std::string> ct_strings; // for verifiable computation
            cts.reserve(batch.size());
            double plaintext_sum = 0.0;
            std::vector<double> plaintext_refs;
            plaintext_refs.reserve(batch.size());
            for (auto& r : batch) {
                cts.push_back(std::move(r.ciphertext));
                plaintext_sum += r.plaintext_ref;
                plaintext_refs.push_back(r.plaintext_ref);
                ct_strings.push_back(crypto.serialize_ciphertext(cts.back()));
            }

            seal::Ciphertext aggregated = crypto.add_many(cts);
            batch_count++;

            // Serialize aggregated result
            std::string agg_data = crypto.serialize_ciphertext(aggregated);

            // --- Verifiable computation: record and prove aggregation ---
            auto agg_record = verifiable.record_aggregation(
                static_cast<uint32_t>(batch_count), ct_strings, agg_data, plaintext_refs);
            std::string vc_data = verifiable.serialize_record(agg_record);

            // --- Periodic theft detection ---
            std::string theft_data;
            if (batch_count % theft_detection_interval == 0) {
                auto report = theft_detector.run_batch_detection(static_cast<uint32_t>(batch_count));
                if (!report.anomalies.empty()) {
                    LOG_WARN("Aggregator", "Theft detection: " +
                             std::to_string(report.anomalous_meters) + " anomalies found");
                }
                // Serialize theft report summary
                uint32_t anom_count = static_cast<uint32_t>(report.anomalies.size());
                theft_data.append(reinterpret_cast<const char*>(&anom_count), 4);
                for (auto& a : report.anomalies) {
                    theft_data.append(reinterpret_cast<const char*>(&a.meter_id), 4);
                    double zs = a.z_score;
                    theft_data.append(reinterpret_cast<const char*>(&zs), 8);
                }
            }

            // Build extended payload: [batch_count:4][num_readings:4][plaintext_sum:8]
            //   [vc_len:4][vc_data][theft_len:4][theft_data][agg_ct_data]
            std::string payload;
            {
                uint32_t bc = static_cast<uint32_t>(batch_count);
                uint32_t nr = static_cast<uint32_t>(batch.size());
                payload.append(reinterpret_cast<const char*>(&bc), 4);
                payload.append(reinterpret_cast<const char*>(&nr), 4);
                uint64_t ps_bits;
                std::memcpy(&ps_bits, &plaintext_sum, sizeof(double));
                payload.append(reinterpret_cast<const char*>(&ps_bits), 8);

                // Verifiable computation proof
                uint32_t vc_len = static_cast<uint32_t>(vc_data.size());
                payload.append(reinterpret_cast<const char*>(&vc_len), 4);
                payload += vc_data;

                // Theft detection data
                uint32_t td_len = static_cast<uint32_t>(theft_data.size());
                payload.append(reinterpret_cast<const char*>(&td_len), 4);
                payload += theft_data;

                // Aggregated ciphertext
                payload += agg_data;
            }

            if (!smartgrid::NetworkUtils::send_typed(cc_client.ssl(),
                    static_cast<uint8_t>(smartgrid::MsgType::AGGREGATED_DATA), payload)) {
                LOG_WARN("Aggregator", "Failed to send batch " + std::to_string(batch_count) +
                         " to Control Center, attempting reconnection...");
                if (connect_to_cc()) {
                    LOG_INFO("Aggregator", "Reconnected to Control Center");
                    // Retry the send once after reconnection
                    if (!smartgrid::NetworkUtils::send_typed(cc_client.ssl(),
                            static_cast<uint8_t>(smartgrid::MsgType::AGGREGATED_DATA), payload)) {
                        LOG_WARN("Aggregator", "Retry send also failed for batch " +
                                 std::to_string(batch_count));
                    } else {
                        LOG_INFO("Aggregator", "Batch " + std::to_string(batch_count) +
                                 " sent after reconnection: " + std::to_string(batch.size()) +
                                 " readings, " + std::to_string(payload.size()) + " bytes");
                    }
                } else {
                    LOG_ERROR("Aggregator", "Reconnection to Control Center failed");
                }
            } else {
                LOG_INFO("Aggregator", "Batch " + std::to_string(batch_count) +
                         " sent: " + std::to_string(batch.size()) + " readings, " +
                         std::to_string(payload.size()) + " bytes (incl. proofs)");
            }

            metrics.record("homomorphic", "aggregation_batch_size",
                static_cast<double>(batch.size()), "readings",
                "batch=" + std::to_string(batch_count));
            metrics.record_size("homomorphic", "aggregated_ciphertext_size",
                agg_data.size(), "batch=" + std::to_string(batch_count));
            metrics.record_size("security", "verifiable_computation_proof_size",
                vc_data.size(), "batch=" + std::to_string(batch_count));
        }

        LOG_INFO("Aggregator", "Shutting down...");
        meter_server.stop();
        cc_client.disconnect();

        // Export security audit logs
        verifiable.export_audit_csv(cfg.metrics_output_dir() + "/verification_audit.csv");
        theft_detector.export_report_csv(
            theft_detector.run_batch_detection(static_cast<uint32_t>(batch_count + 1)),
            cfg.metrics_output_dir() + "/theft_detection.csv");

        // Export ToU billing
        auto bills = tou_billing.generate_all_bills(static_cast<uint32_t>(batch_count));
        tou_billing.export_bills_csv(bills, cfg.metrics_output_dir() + "/tou_billing.csv");

        metrics.export_csv();

        smartgrid::TLSContext::cleanup_openssl();

    } catch (const std::exception& e) {
        std::cerr << "Aggregator Error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
