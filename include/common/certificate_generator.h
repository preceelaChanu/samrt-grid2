#pragma once

#include <string>

namespace smartgrid {

class CertificateGenerator {
public:
    // Generate a self-signed CA certificate
    static bool generate_ca(const std::string& cert_path, const std::string& key_path,
                            const std::string& cn = "SmartGrid CA", int days = 3650);

    // Generate a signed certificate from the CA
    static bool generate_signed(const std::string& ca_cert_path, const std::string& ca_key_path,
                                const std::string& cert_path, const std::string& key_path,
                                const std::string& cn, int days = 365);
};

} // namespace smartgrid
