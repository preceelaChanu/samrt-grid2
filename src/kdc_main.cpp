// Key Distribution Center - serves SEAL keys to authenticated clients over TLS
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
#include <sstream>

static std::atomic<bool> g_running{true};

static void signal_handler(int) {
    g_running = false;
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

        LOG_INFO("KDC", "Starting Key Distribution Center");

        // Load SEAL keys
        auto& keys_cfg = cfg.get()["keys"];
        std::string params_file = keys_cfg["seal_params"].get<std::string>();
        std::string pk_file = keys_cfg["public_key"].get<std::string>();
        std::string rk_file = keys_cfg["relin_keys"].get<std::string>();

        // Read files into memory
        auto read_file = [](const std::string& path) -> std::string {
            std::ifstream f(path, std::ios::binary);
            if (!f.is_open()) throw std::runtime_error("Cannot open: " + path);
            std::ostringstream oss;
            oss << f.rdbuf();
            return oss.str();
        };

        std::string params_data = read_file(params_file);
        std::string pk_data = read_file(pk_file);
        std::string rk_data = read_file(rk_file);

        LOG_INFO("KDC", "Loaded SEAL keys: params=" + std::to_string(params_data.size()) +
                 "B, pk=" + std::to_string(pk_data.size()) +
                 "B, rk=" + std::to_string(rk_data.size()) + "B");

        // Setup TLS server
        auto& tls_cfg = cfg.get()["tls"];
        smartgrid::TLSContext tls_ctx(smartgrid::TLSContext::Role::SERVER);
        tls_ctx.load_certificates(
            tls_cfg["kdc_cert"].get<std::string>(),
            tls_cfg["kdc_key"].get<std::string>(),
            tls_cfg["ca_cert"].get<std::string>()
        );

        auto handler = [&](SSL* ssl, int /*fd*/) {
            LOG_INFO("KDC", "Client connected, distributing keys");
            smartgrid::ScopedTimer timer("network", "kdc_key_distribution");

            uint8_t type;
            std::string data;

            if (!smartgrid::NetworkUtils::recv_typed(ssl, type, data)) {
                LOG_ERROR("KDC", "Failed to receive key request");
                return;
            }

            if (type != static_cast<uint8_t>(smartgrid::MsgType::KEY_REQUEST)) {
                LOG_ERROR("KDC", "Unexpected message type: " + std::to_string(type));
                return;
            }

            // Send params
            smartgrid::NetworkUtils::send_typed(ssl,
                static_cast<uint8_t>(smartgrid::MsgType::KEY_PARAMS), params_data);

            // Send public key
            smartgrid::NetworkUtils::send_typed(ssl,
                static_cast<uint8_t>(smartgrid::MsgType::KEY_PUBLIC), pk_data);

            // Send relin keys
            smartgrid::NetworkUtils::send_typed(ssl,
                static_cast<uint8_t>(smartgrid::MsgType::KEY_RELIN), rk_data);

            // Send done
            smartgrid::NetworkUtils::send_typed(ssl,
                static_cast<uint8_t>(smartgrid::MsgType::KEY_DONE), "");

            LOG_INFO("KDC", "Keys distributed successfully");
        };

        smartgrid::TLSServer server(tls_ctx, cfg.kdc_port(), handler);
        server.start();

        LOG_INFO("KDC", "KDC ready on port " + std::to_string(cfg.kdc_port()));

        while (g_running) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }

        LOG_INFO("KDC", "Shutting down...");
        server.stop();
        metrics.export_csv();

        smartgrid::TLSContext::cleanup_openssl();

    } catch (const std::exception& e) {
        std::cerr << "KDC Error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
