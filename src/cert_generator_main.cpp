// Certificate Generator - creates CA + node certificates for all components
#include "common/config.h"
#include "common/logger.h"
#include "common/certificate_generator.h"
#include "common/tls_context.h"
#include <iostream>

int main(int argc, char* argv[]) {
    std::string config_path = (argc > 1) ? argv[1] : "config.json";

    try {
        smartgrid::TLSContext::init_openssl();

        auto& cfg = smartgrid::Config::instance();
        cfg.load(config_path);

        auto& logger = smartgrid::Logger::instance();
        logger.init(cfg.log_file(), smartgrid::Logger::parse_level(cfg.log_level()),
                    cfg.log_to_console());

        LOG_INFO("CertGen", "Generating certificates for all components");

        auto& tls = cfg.get()["tls"];
        std::string ca_cert = tls["ca_cert"].get<std::string>();
        std::string ca_key = tls["ca_key"].get<std::string>();

        // Generate CA
        if (!smartgrid::CertificateGenerator::generate_ca(ca_cert, ca_key, "SmartGrid CA")) {
            LOG_ERROR("CertGen", "Failed to generate CA");
            return 1;
        }

        // Generate component certificates
        struct CertInfo {
            std::string cert;
            std::string key;
            std::string cn;
        };

        std::vector<CertInfo> certs = {
            {tls["kdc_cert"].get<std::string>(), tls["kdc_key"].get<std::string>(), "SmartGrid KDC"},
            {tls["aggregator_cert"].get<std::string>(), tls["aggregator_key"].get<std::string>(), "SmartGrid Aggregator"},
            {tls["control_center_cert"].get<std::string>(), tls["control_center_key"].get<std::string>(), "SmartGrid ControlCenter"},
            {tls["server_cert"].get<std::string>(), tls["server_key"].get<std::string>(), "SmartGrid Server"},
            {tls["client_cert"].get<std::string>(), tls["client_key"].get<std::string>(), "SmartGrid Client"},
        };

        for (auto& ci : certs) {
            if (!smartgrid::CertificateGenerator::generate_signed(ca_cert, ca_key,
                    ci.cert, ci.key, ci.cn)) {
                LOG_ERROR("CertGen", "Failed to generate cert for " + ci.cn);
                return 1;
            }
        }

        LOG_INFO("CertGen", "All certificates generated successfully");

        smartgrid::TLSContext::cleanup_openssl();

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
