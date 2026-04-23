// Smart Meter - simulates UK household energy data and sends CKKS-encrypted readings
// Extended: ZKP range proofs, correctness proofs, and ToU time-slot metadata
#include "common/config.h"
#include "common/logger.h"
#include "common/crypto_engine.h"
#include "common/network.h"
#include "common/tls_context.h"
#include "common/energy_simulator.h"
#include "common/metrics.h"
#include "common/zkp_engine.h"
#include "common/tou_billing.h"

#include <openssl/sha.h>
#include <csignal>
#include <atomic>
#include <iostream>
#include <thread>
#include <vector>
#include <sstream>

static std::atomic<bool> g_running{true};

static void signal_handler(int) {
    g_running = false;
}

// Fetch SEAL keys from KDC
static bool fetch_keys_from_kdc(smartgrid::TLSContext& tls_ctx,
                                 const std::string& host, int port,
                                 std::string& params_data,
                                 std::string& pk_data,
                                 std::string& rk_data) {
    auto& cfg = smartgrid::Config::instance();
    smartgrid::TLSClient client(tls_ctx);

    if (!client.connect_with_retry(host, port,
            cfg.retry_attempts(), cfg.retry_delay_ms(), cfg.connection_timeout_ms())) {
        LOG_ERROR("SmartMeter", "Cannot connect to KDC");
        return false;
    }

    // Send key request
    smartgrid::NetworkUtils::send_typed(client.ssl(),
        static_cast<uint8_t>(smartgrid::MsgType::KEY_REQUEST), "");

    // Receive keys
    uint8_t type;
    std::string data;

    // Params
    if (!smartgrid::NetworkUtils::recv_typed(client.ssl(), type, data) ||
        type != static_cast<uint8_t>(smartgrid::MsgType::KEY_PARAMS)) return false;
    params_data = std::move(data);

    // Public key
    if (!smartgrid::NetworkUtils::recv_typed(client.ssl(), type, data) ||
        type != static_cast<uint8_t>(smartgrid::MsgType::KEY_PUBLIC)) return false;
    pk_data = std::move(data);

    // Relin keys
    if (!smartgrid::NetworkUtils::recv_typed(client.ssl(), type, data) ||
        type != static_cast<uint8_t>(smartgrid::MsgType::KEY_RELIN)) return false;
    rk_data = std::move(data);

    // Done
    smartgrid::NetworkUtils::recv_typed(client.ssl(), type, data);

    client.disconnect();
    return true;
}

static void meter_thread(int meter_id, smartgrid::CryptoEngine& crypto,
                          smartgrid::TLSContext& client_tls,
                          smartgrid::ZKPEngine& zkp) {
    auto& cfg = smartgrid::Config::instance();
    smartgrid::EnergySimulator sim;
    sim.init_from_config();

    auto profile = sim.generate_profile();
    std::string type_str;
    switch (profile.type) {
        case smartgrid::HouseholdType::LOW_CONSUMER: type_str = "LOW"; break;
        case smartgrid::HouseholdType::MEDIUM_CONSUMER: type_str = "MEDIUM"; break;
        case smartgrid::HouseholdType::HIGH_CONSUMER: type_str = "HIGH"; break;
        default: type_str = "VARIABLE"; break;
    }

    LOG_INFO("Meter-" + std::to_string(meter_id),
             "Started: type=" + type_str + " variable=" + (profile.is_variable ? "yes" : "no"));

    // Connect to aggregator
    smartgrid::TLSClient agg_client(client_tls);
    if (!agg_client.connect_with_retry(cfg.aggregator_host(), cfg.aggregator_port(),
            cfg.retry_attempts(), cfg.retry_delay_ms(), cfg.connection_timeout_ms())) {
        LOG_ERROR("Meter-" + std::to_string(meter_id), "Cannot connect to Aggregator");
        return;
    }

    int send_interval = cfg.send_interval_ms();
    int readings_sent = 0;

    // Get consumption range from config for ZKP range proofs
    double min_kwh = cfg.get()["smart_meters"]["consumption"]["min_kwh"].get<double>();
    double max_kwh = cfg.get()["smart_meters"]["consumption"]["max_kwh"].get<double>();

    while (g_running) {
        double reading = sim.generate_reading(profile);

        // Encrypt the reading
        auto ct = crypto.encrypt_single(reading);

        // Serialize ciphertext
        std::string ct_data = crypto.serialize_ciphertext(ct);

        // --- ZKP: Generate range proof (value ∈ [min_kwh, max_kwh]) ---
        auto commitment = zkp.commit(reading);
        auto range_proof = zkp.generate_range_proof(reading, min_kwh, max_kwh, commitment);
        std::string range_proof_data = zkp.serialize_range_proof(range_proof);

        // --- ZKP: Generate correctness proof (encrypted value matches commitment) ---
        std::vector<uint8_t> ct_hash(SHA256_DIGEST_LENGTH);
        SHA256(reinterpret_cast<const unsigned char*>(ct_data.data()),
               ct_data.size(), ct_hash.data());
        auto correctness_proof = zkp.generate_correctness_proof(reading, ct_hash);
        std::string correctness_proof_data = zkp.serialize_correctness_proof(correctness_proof);

        // --- ToU: Determine current time slot ---
        int current_hour = sim.current_hour();
        uint8_t tou_slot = static_cast<uint8_t>(current_hour); // Hour info for slot classification

        // Build payload: [meter_id:4][reading:8][tou_hour:1][range_proof_len:4][range_proof]
        //                [correctness_proof_len:4][correctness_proof][commitment_len:4][commitment][ct_data]
        std::string payload;
        {
            uint32_t mid = static_cast<uint32_t>(meter_id);
            payload.append(reinterpret_cast<const char*>(&mid), 4);
            uint64_t reading_bits;
            std::memcpy(&reading_bits, &reading, sizeof(double));
            payload.append(reinterpret_cast<const char*>(&reading_bits), 8);
            payload.push_back(static_cast<char>(tou_slot));

            // Range proof
            uint32_t rp_len = static_cast<uint32_t>(range_proof_data.size());
            payload.append(reinterpret_cast<const char*>(&rp_len), 4);
            payload += range_proof_data;

            // Correctness proof
            uint32_t cp_len = static_cast<uint32_t>(correctness_proof_data.size());
            payload.append(reinterpret_cast<const char*>(&cp_len), 4);
            payload += correctness_proof_data;

            // Commitment
            uint32_t cm_len = static_cast<uint32_t>(commitment.data.size());
            payload.append(reinterpret_cast<const char*>(&cm_len), 4);
            payload.append(reinterpret_cast<const char*>(commitment.data.data()), cm_len);
            uint32_t cb_len = static_cast<uint32_t>(commitment.blinding.size());
            payload.append(reinterpret_cast<const char*>(&cb_len), 4);
            payload.append(reinterpret_cast<const char*>(commitment.blinding.data()), cb_len);

            // Ciphertext
            payload += ct_data;
        }

        if (!smartgrid::NetworkUtils::send_typed(agg_client.ssl(),
                static_cast<uint8_t>(smartgrid::MsgType::METER_DATA), payload)) {
            LOG_WARN("Meter-" + std::to_string(meter_id), "Send failed, reconnecting...");
            agg_client.disconnect();
            if (!agg_client.connect_with_retry(cfg.aggregator_host(), cfg.aggregator_port(),
                    cfg.retry_attempts(), cfg.retry_delay_ms(), cfg.connection_timeout_ms())) {
                LOG_ERROR("Meter-" + std::to_string(meter_id), "Reconnection failed");
                break;
            }
            continue;
        }

        readings_sent++;
        if (readings_sent % 10 == 0) {
            LOG_DEBUG("Meter-" + std::to_string(meter_id),
                      "Sent " + std::to_string(readings_sent) + " readings, last=" +
                      std::to_string(reading) + " kWh");
        }

        smartgrid::MetricsCollector::instance().record("scalability", "meter_reading",
            reading, "kWh", "meter_id=" + std::to_string(meter_id));

        std::this_thread::sleep_for(std::chrono::milliseconds(send_interval));
    }

    agg_client.disconnect();
    LOG_INFO("Meter-" + std::to_string(meter_id),
             "Stopped after " + std::to_string(readings_sent) + " readings");
}

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

        int num_meters = cfg.smart_meter_count();
        LOG_INFO("SmartMeter", "Starting " + std::to_string(num_meters) + " smart meters");

        // Initialize ZKP engine for range + correctness proofs
        smartgrid::ZKPEngine zkp;
        int zkp_security = cfg.get().value("/zkp/security_bits"_json_pointer, 128);
        zkp.init(zkp_security);
        LOG_INFO("SmartMeter", "ZKP engine initialized (" + std::to_string(zkp_security) + "-bit security)");

        // Setup TLS for KDC connection
        auto& tls_cfg = cfg.get()["tls"];
        smartgrid::TLSContext kdc_tls(smartgrid::TLSContext::Role::CLIENT);
        kdc_tls.load_certificates(
            tls_cfg["client_cert"].get<std::string>(),
            tls_cfg["client_key"].get<std::string>(),
            tls_cfg["ca_cert"].get<std::string>()
        );

        // Fetch SEAL keys from KDC
        std::string params_data, pk_data, rk_data;
        LOG_INFO("SmartMeter", "Fetching SEAL keys from KDC...");
        if (!fetch_keys_from_kdc(kdc_tls, cfg.kdc_host(), cfg.kdc_port(),
                params_data, pk_data, rk_data)) {
            LOG_ERROR("SmartMeter", "Failed to fetch keys from KDC");
            return 1;
        }
        LOG_INFO("SmartMeter", "SEAL keys received from KDC");

        // Initialize crypto engine from received keys
        smartgrid::CryptoEngine crypto;
        {
            // Write temp files (for SEAL loading API)
            auto write_temp = [](const std::string& name, const std::string& data) {
                std::string path = "/tmp/sg_" + name;
                std::ofstream f(path, std::ios::binary);
                f.write(data.data(), static_cast<std::streamsize>(data.size()));
                return path;
            };
            std::string p = write_temp("params.seal", params_data);
            std::string pk = write_temp("pk.seal", pk_data);
            std::string rk = write_temp("rk.seal", rk_data);
            crypto.init_from_files(p, pk, "", rk);
        }

        // Setup TLS for aggregator connections
        smartgrid::TLSContext client_tls(smartgrid::TLSContext::Role::CLIENT);
        client_tls.load_certificates(
            tls_cfg["client_cert"].get<std::string>(),
            tls_cfg["client_key"].get<std::string>(),
            tls_cfg["ca_cert"].get<std::string>()
        );

        // Launch meter threads
        std::vector<std::thread> threads;
        threads.reserve(num_meters);
        for (int i = 0; i < num_meters; i++) {
            threads.emplace_back(meter_thread, i, std::ref(crypto), std::ref(client_tls),
                                 std::ref(zkp));
            // Stagger starts to avoid thundering herd
            if (i % 50 == 49) {
                std::this_thread::sleep_for(std::chrono::milliseconds(500));
            }
        }

        // Wait for shutdown
        while (g_running) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }

        LOG_INFO("SmartMeter", "Shutting down all meters...");
        for (auto& t : threads) {
            if (t.joinable()) t.join();
        }

        metrics.export_csv();
        LOG_INFO("SmartMeter", "All meters stopped");

        smartgrid::TLSContext::cleanup_openssl();

    } catch (const std::exception& e) {
        std::cerr << "SmartMeter Error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
