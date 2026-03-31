#include "common/tls_context.h"
#include "common/logger.h"
#include <stdexcept>

namespace smartgrid {

void TLSContext::init_openssl() {
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
}

void TLSContext::cleanup_openssl() {
    EVP_cleanup();
}

TLSContext::TLSContext(Role role) : role_(role) {
    const SSL_METHOD* method = (role == Role::SERVER)
        ? TLS_server_method()
        : TLS_client_method();

    ctx_ = SSL_CTX_new(method);
    if (!ctx_) {
        throw std::runtime_error("Failed to create SSL context");
    }

    // Force TLS 1.3
    SSL_CTX_set_min_proto_version(ctx_, TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(ctx_, TLS1_3_VERSION);
}

TLSContext::~TLSContext() {
    if (ctx_) SSL_CTX_free(ctx_);
}

void TLSContext::load_certificates(const std::string& cert_file,
                                    const std::string& key_file,
                                    const std::string& ca_file) {
    if (SSL_CTX_use_certificate_file(ctx_, cert_file.c_str(), SSL_FILETYPE_PEM) <= 0) {
        throw std::runtime_error("Failed to load certificate: " + cert_file);
    }
    if (SSL_CTX_use_PrivateKey_file(ctx_, key_file.c_str(), SSL_FILETYPE_PEM) <= 0) {
        throw std::runtime_error("Failed to load private key: " + key_file);
    }
    if (!SSL_CTX_check_private_key(ctx_)) {
        throw std::runtime_error("Certificate/key mismatch");
    }
    if (SSL_CTX_load_verify_locations(ctx_, ca_file.c_str(), nullptr) <= 0) {
        throw std::runtime_error("Failed to load CA certificate: " + ca_file);
    }

    // Require mutual authentication
    SSL_CTX_set_verify(ctx_, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, nullptr);
}

SSL* TLSContext::create_ssl(int fd) {
    SSL* ssl = SSL_new(ctx_);
    if (!ssl) {
        throw std::runtime_error("Failed to create SSL object");
    }
    SSL_set_fd(ssl, fd);
    return ssl;
}

bool TLSContext::handshake(SSL* ssl) {
    int ret;
    if (role_ == Role::SERVER) {
        ret = SSL_accept(ssl);
    } else {
        ret = SSL_connect(ssl);
    }
    if (ret <= 0) {
        int err = SSL_get_error(ssl, ret);
        LOG_ERROR("TLS", "Handshake failed, SSL error: " + std::to_string(err));
        return false;
    }
    return true;
}

void SSLDeleter::operator()(SSL* ssl) const {
    if (ssl) {
        SSL_shutdown(ssl);
        SSL_free(ssl);
    }
}

} // namespace smartgrid
