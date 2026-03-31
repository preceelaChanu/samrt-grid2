#include "common/certificate_generator.h"
#include "common/logger.h"
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <memory>
#include <filesystem>

namespace smartgrid {

namespace {

struct EVP_PKEY_Deleter { void operator()(EVP_PKEY* p) { EVP_PKEY_free(p); } };
struct X509_Deleter { void operator()(X509* p) { X509_free(p); } };
struct BIO_Deleter { void operator()(BIO* p) { BIO_free_all(p); } };
struct BIGNUM_Deleter { void operator()(BIGNUM* p) { BN_free(p); } };
struct EVP_PKEY_CTX_Deleter { void operator()(EVP_PKEY_CTX* p) { EVP_PKEY_CTX_free(p); } };

using EVP_PKEY_Ptr = std::unique_ptr<EVP_PKEY, EVP_PKEY_Deleter>;
using X509_Ptr = std::unique_ptr<X509, X509_Deleter>;
using BIO_Ptr = std::unique_ptr<BIO, BIO_Deleter>;

EVP_PKEY_Ptr generate_rsa_key(int bits = 2048) {
    std::unique_ptr<EVP_PKEY_CTX, EVP_PKEY_CTX_Deleter> ctx(
        EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr));
    if (!ctx) return nullptr;
    if (EVP_PKEY_keygen_init(ctx.get()) <= 0) return nullptr;
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx.get(), bits) <= 0) return nullptr;
    EVP_PKEY* pkey = nullptr;
    if (EVP_PKEY_keygen(ctx.get(), &pkey) <= 0) return nullptr;
    return EVP_PKEY_Ptr(pkey);
}

bool write_pem_key(EVP_PKEY* key, const std::string& path) {
    BIO_Ptr bio(BIO_new_file(path.c_str(), "w"));
    if (!bio) return false;
    return PEM_write_bio_PrivateKey(bio.get(), key, nullptr, nullptr, 0, nullptr, nullptr) > 0;
}

bool write_pem_cert(X509* cert, const std::string& path) {
    BIO_Ptr bio(BIO_new_file(path.c_str(), "w"));
    if (!bio) return false;
    return PEM_write_bio_X509(bio.get(), cert) > 0;
}

void set_subject(X509* cert, const std::string& cn) {
    X509_NAME* name = X509_get_subject_name(cert);
    X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC,
        reinterpret_cast<const unsigned char*>("GB"), -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC,
        reinterpret_cast<const unsigned char*>("SmartGrid Research"), -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
        reinterpret_cast<const unsigned char*>(cn.c_str()), -1, -1, 0);
}

} // anonymous namespace

bool CertificateGenerator::generate_ca(const std::string& cert_path, const std::string& key_path,
                                        const std::string& cn, int days) {
    std::filesystem::create_directories(std::filesystem::path(cert_path).parent_path());

    auto key = generate_rsa_key(4096);
    if (!key) {
        LOG_ERROR("CertGen", "Failed to generate CA RSA key");
        return false;
    }

    X509_Ptr cert(X509_new());
    if (!cert) return false;

    ASN1_INTEGER_set(X509_get_serialNumber(cert.get()), 1);
    X509_gmtime_adj(X509_getm_notBefore(cert.get()), 0);
    X509_gmtime_adj(X509_getm_notAfter(cert.get()), static_cast<long>(days) * 86400);

    X509_set_pubkey(cert.get(), key.get());

    set_subject(cert.get(), cn);
    X509_set_issuer_name(cert.get(), X509_get_subject_name(cert.get()));

    // Add CA basic constraint
    X509V3_CTX ctx;
    X509V3_set_ctx_nodb(&ctx);
    X509V3_set_ctx(&ctx, cert.get(), cert.get(), nullptr, nullptr, 0);
    X509_EXTENSION* ext = X509V3_EXT_conf_nid(nullptr, &ctx, NID_basic_constraints,
        const_cast<char*>("critical,CA:TRUE"));
    if (ext) {
        X509_add_ext(cert.get(), ext, -1);
        X509_EXTENSION_free(ext);
    }

    // Add SAN for localhost
    ext = X509V3_EXT_conf_nid(nullptr, &ctx, NID_subject_alt_name,
        const_cast<char*>("DNS:localhost,IP:127.0.0.1"));
    if (ext) {
        X509_add_ext(cert.get(), ext, -1);
        X509_EXTENSION_free(ext);
    }

    if (X509_sign(cert.get(), key.get(), EVP_sha256()) == 0) {
        LOG_ERROR("CertGen", "Failed to sign CA certificate");
        return false;
    }

    if (!write_pem_cert(cert.get(), cert_path) || !write_pem_key(key.get(), key_path)) {
        LOG_ERROR("CertGen", "Failed to write CA files");
        return false;
    }

    LOG_INFO("CertGen", "CA certificate generated: " + cert_path);
    return true;
}

bool CertificateGenerator::generate_signed(const std::string& ca_cert_path, const std::string& ca_key_path,
                                            const std::string& cert_path, const std::string& key_path,
                                            const std::string& cn, int days) {
    std::filesystem::create_directories(std::filesystem::path(cert_path).parent_path());

    // Load CA cert and key
    BIO_Ptr ca_cert_bio(BIO_new_file(ca_cert_path.c_str(), "r"));
    BIO_Ptr ca_key_bio(BIO_new_file(ca_key_path.c_str(), "r"));
    if (!ca_cert_bio || !ca_key_bio) {
        LOG_ERROR("CertGen", "Failed to open CA files");
        return false;
    }

    X509* ca_cert_raw = PEM_read_bio_X509(ca_cert_bio.get(), nullptr, nullptr, nullptr);
    EVP_PKEY* ca_key_raw = PEM_read_bio_PrivateKey(ca_key_bio.get(), nullptr, nullptr, nullptr);
    if (!ca_cert_raw || !ca_key_raw) {
        LOG_ERROR("CertGen", "Failed to read CA files");
        if (ca_cert_raw) X509_free(ca_cert_raw);
        if (ca_key_raw) EVP_PKEY_free(ca_key_raw);
        return false;
    }
    X509_Ptr ca_cert(ca_cert_raw);
    EVP_PKEY_Ptr ca_key(ca_key_raw);

    // Generate new key
    auto key = generate_rsa_key(2048);
    if (!key) {
        LOG_ERROR("CertGen", "Failed to generate RSA key for " + cn);
        return false;
    }

    X509_Ptr cert(X509_new());
    if (!cert) return false;

    static int serial = 2;
    ASN1_INTEGER_set(X509_get_serialNumber(cert.get()), serial++);
    X509_gmtime_adj(X509_getm_notBefore(cert.get()), 0);
    X509_gmtime_adj(X509_getm_notAfter(cert.get()), static_cast<long>(days) * 86400);

    X509_set_pubkey(cert.get(), key.get());

    set_subject(cert.get(), cn);
    X509_set_issuer_name(cert.get(), X509_get_subject_name(ca_cert.get()));

    // Add SAN
    X509V3_CTX ctx;
    X509V3_set_ctx_nodb(&ctx);
    X509V3_set_ctx(&ctx, ca_cert.get(), cert.get(), nullptr, nullptr, 0);
    X509_EXTENSION* ext = X509V3_EXT_conf_nid(nullptr, &ctx, NID_subject_alt_name,
        const_cast<char*>("DNS:localhost,IP:127.0.0.1"));
    if (ext) {
        X509_add_ext(cert.get(), ext, -1);
        X509_EXTENSION_free(ext);
    }

    if (X509_sign(cert.get(), ca_key.get(), EVP_sha256()) == 0) {
        LOG_ERROR("CertGen", "Failed to sign certificate for " + cn);
        return false;
    }

    if (!write_pem_cert(cert.get(), cert_path) || !write_pem_key(key.get(), key_path)) {
        LOG_ERROR("CertGen", "Failed to write certificate files for " + cn);
        return false;
    }

    LOG_INFO("CertGen", "Certificate generated for " + cn + ": " + cert_path);
    return true;
}

} // namespace smartgrid
