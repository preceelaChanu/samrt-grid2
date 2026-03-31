#pragma once

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <string>
#include <memory>

namespace smartgrid {

class TLSContext {
public:
    enum class Role { SERVER, CLIENT };

    TLSContext(Role role);
    ~TLSContext();

    void load_certificates(const std::string& cert_file,
                           const std::string& key_file,
                           const std::string& ca_file);

    SSL_CTX* get() const { return ctx_; }

    // Create an SSL object for a socket fd
    SSL* create_ssl(int fd);

    // Perform handshake (blocking)
    bool handshake(SSL* ssl);

    static void init_openssl();
    static void cleanup_openssl();

private:
    SSL_CTX* ctx_ = nullptr;
    Role role_;
};

// RAII wrapper for SSL*
struct SSLDeleter {
    void operator()(SSL* ssl) const;
};
using SSLPtr = std::unique_ptr<SSL, SSLDeleter>;

} // namespace smartgrid
