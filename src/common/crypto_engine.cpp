#include "common/crypto_engine.h"
#include "common/logger.h"
#include "common/metrics.h"
#include <fstream>
#include <sstream>
#include <stdexcept>

namespace smartgrid {

CryptoEngine::CryptoEngine() {}

void CryptoEngine::init(size_t poly_modulus_degree, const std::vector<int>& coeff_modulus_bits,
                         int scale_bits, int security_level) {
    ScopedTimer timer("encryption", "ckks_init");

    params_ = seal::EncryptionParameters(seal::scheme_type::ckks);
    params_.set_poly_modulus_degree(poly_modulus_degree);
    params_.set_coeff_modulus(seal::CoeffModulus::Create(poly_modulus_degree, coeff_modulus_bits));

    seal::sec_level_type sec;
    switch (security_level) {
        case 128: sec = seal::sec_level_type::tc128; break;
        case 192: sec = seal::sec_level_type::tc192; break;
        case 256: sec = seal::sec_level_type::tc256; break;
        default: sec = seal::sec_level_type::tc128; break;
    }

    context_ = std::make_shared<seal::SEALContext>(params_, true, sec);
    scale_ = pow(2.0, scale_bits);

    encoder_ = std::make_unique<seal::CKKSEncoder>(*context_);
    evaluator_ = std::make_unique<seal::Evaluator>(*context_);

    LOG_INFO("CryptoEngine", "CKKS initialized: poly_degree=" + std::to_string(poly_modulus_degree)
             + " scale=2^" + std::to_string(scale_bits)
             + " slots=" + std::to_string(encoder_->slot_count()));
}

void CryptoEngine::init_from_files(const std::string& params_file,
                                    const std::string& public_key_file,
                                    const std::string& secret_key_file,
                                    const std::string& relin_keys_file) {
    // Load params
    {
        std::ifstream f(params_file, std::ios::binary);
        if (!f.is_open()) throw std::runtime_error("Cannot open params file: " + params_file);
        params_ = seal::EncryptionParameters();
        params_.load(f);
    }

    context_ = std::make_shared<seal::SEALContext>(params_);
    encoder_ = std::make_unique<seal::CKKSEncoder>(*context_);
    evaluator_ = std::make_unique<seal::Evaluator>(*context_);

    // Load public key
    {
        std::ifstream f(public_key_file, std::ios::binary);
        if (!f.is_open()) throw std::runtime_error("Cannot open public key file: " + public_key_file);
        public_key_.load(*context_, f);
    }
    encryptor_ = std::make_unique<seal::Encryptor>(*context_, public_key_);

    // Load secret key if provided
    if (!secret_key_file.empty()) {
        std::ifstream f(secret_key_file, std::ios::binary);
        if (f.is_open()) {
            secret_key_.load(*context_, f);
            decryptor_ = std::make_unique<seal::Decryptor>(*context_, secret_key_);
            has_secret_key_ = true;
        }
    }

    // Load relin keys if provided
    if (!relin_keys_file.empty()) {
        std::ifstream f(relin_keys_file, std::ios::binary);
        if (f.is_open()) {
            relin_keys_.load(*context_, f);
            has_relin_keys_ = true;
        }
    }

    // Determine scale from context
    auto ctx_data = context_->first_context_data();
    if (ctx_data) {
        auto& parms = ctx_data->parms();
        auto& coeff = parms.coeff_modulus();
        if (coeff.size() > 1) {
            scale_ = pow(2.0, static_cast<int>(log2(coeff[1].value())));
        }
    }

    LOG_INFO("CryptoEngine", "CKKS loaded from files, slots=" + std::to_string(encoder_->slot_count()));
}

void CryptoEngine::generate_keys() {
    ScopedTimer timer("encryption", "key_generation");

    seal::KeyGenerator keygen(*context_);
    secret_key_ = keygen.secret_key();
    keygen.create_public_key(public_key_);
    keygen.create_relin_keys(relin_keys_);

    encryptor_ = std::make_unique<seal::Encryptor>(*context_, public_key_);
    decryptor_ = std::make_unique<seal::Decryptor>(*context_, secret_key_);
    has_secret_key_ = true;
    has_relin_keys_ = true;

    LOG_INFO("CryptoEngine", "CKKS keys generated");
}

void CryptoEngine::save_params(const std::string& path) const {
    std::ofstream f(path, std::ios::binary);
    params_.save(f);
}

void CryptoEngine::save_public_key(const std::string& path) const {
    std::ofstream f(path, std::ios::binary);
    public_key_.save(f);
}

void CryptoEngine::save_secret_key(const std::string& path) const {
    std::ofstream f(path, std::ios::binary);
    secret_key_.save(f);
}

void CryptoEngine::save_relin_keys(const std::string& path) const {
    std::ofstream f(path, std::ios::binary);
    relin_keys_.save(f);
}

seal::Ciphertext CryptoEngine::encrypt(const std::vector<double>& data) {
    ScopedTimer timer("encryption", "encrypt_vector", "slots=" + std::to_string(data.size()));

    seal::Plaintext plain;
    encoder_->encode(data, scale_, plain);
    seal::Ciphertext ct;
    encryptor_->encrypt(plain, ct);

    MetricsCollector::instance().record_size("encryption", "ciphertext_size",
        ct.save_size(), "slots=" + std::to_string(data.size()));

    return ct;
}

seal::Ciphertext CryptoEngine::encrypt_single(double value) {
    return encrypt({value});
}

std::vector<double> CryptoEngine::decrypt(const seal::Ciphertext& ct, size_t count) {
    if (!has_secret_key_) {
        throw std::runtime_error("Cannot decrypt without secret key");
    }

    ScopedTimer timer("encryption", "decrypt");

    seal::Plaintext plain;
    decryptor_->decrypt(ct, plain);
    std::vector<double> result;
    encoder_->decode(plain, result);

    if (count > 0 && count < result.size()) {
        result.resize(count);
    }
    return result;
}

seal::Ciphertext CryptoEngine::add(const seal::Ciphertext& a, const seal::Ciphertext& b) {
    ScopedTimer timer("homomorphic", "he_add");

    seal::Ciphertext result;
    evaluator_->add(a, b, result);
    return result;
}

seal::Ciphertext CryptoEngine::add_many(const std::vector<seal::Ciphertext>& cts) {
    if (cts.empty()) throw std::runtime_error("Cannot add empty ciphertext vector");
    if (cts.size() == 1) return cts[0];

    ScopedTimer timer("homomorphic", "he_add_many", "count=" + std::to_string(cts.size()));

    seal::Ciphertext result;
    evaluator_->add_many(cts, result);
    return result;
}

std::string CryptoEngine::serialize_ciphertext(const seal::Ciphertext& ct) const {
    std::ostringstream oss;
    ct.save(oss);
    return oss.str();
}

seal::Ciphertext CryptoEngine::deserialize_ciphertext(const std::string& data) const {
    std::istringstream iss(data);
    seal::Ciphertext ct;
    ct.load(*context_, iss);
    return ct;
}

size_t CryptoEngine::slot_count() const {
    return encoder_ ? encoder_->slot_count() : 0;
}

std::string CryptoEngine::serialize_params() const {
    std::ostringstream oss;
    params_.save(oss);
    return oss.str();
}

std::string CryptoEngine::serialize_public_key() const {
    std::ostringstream oss;
    public_key_.save(oss);
    return oss.str();
}

std::string CryptoEngine::serialize_relin_keys() const {
    std::ostringstream oss;
    relin_keys_.save(oss);
    return oss.str();
}

} // namespace smartgrid
