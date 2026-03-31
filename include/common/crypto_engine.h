#pragma once

#include <seal/seal.h>
#include <string>
#include <vector>
#include <memory>

namespace smartgrid {

class CryptoEngine {
public:
    CryptoEngine();

    // Initialize from config parameters
    void init(size_t poly_modulus_degree, const std::vector<int>& coeff_modulus_bits,
              int scale_bits, int security_level);

    // Initialize from serialized parameters + keys
    void init_from_files(const std::string& params_file,
                         const std::string& public_key_file,
                         const std::string& secret_key_file = "",
                         const std::string& relin_keys_file = "");

    // Key generation
    void generate_keys();

    // Serialization
    void save_params(const std::string& path) const;
    void save_public_key(const std::string& path) const;
    void save_secret_key(const std::string& path) const;
    void save_relin_keys(const std::string& path) const;

    // Encryption
    seal::Ciphertext encrypt(const std::vector<double>& data);
    seal::Ciphertext encrypt_single(double value);

    // Decryption
    std::vector<double> decrypt(const seal::Ciphertext& ct, size_t count = 0);

    // Homomorphic operations
    seal::Ciphertext add(const seal::Ciphertext& a, const seal::Ciphertext& b);
    seal::Ciphertext add_many(const std::vector<seal::Ciphertext>& cts);

    // Serialization helpers
    std::string serialize_ciphertext(const seal::Ciphertext& ct) const;
    seal::Ciphertext deserialize_ciphertext(const std::string& data) const;

    // Accessors
    std::shared_ptr<seal::SEALContext> context() const { return context_; }
    double scale() const { return scale_; }
    size_t slot_count() const;

    // Serialize params/keys to string (for network transfer)
    std::string serialize_params() const;
    std::string serialize_public_key() const;
    std::string serialize_relin_keys() const;

private:
    std::shared_ptr<seal::SEALContext> context_;
    seal::PublicKey public_key_;
    seal::SecretKey secret_key_;
    seal::RelinKeys relin_keys_;
    std::unique_ptr<seal::CKKSEncoder> encoder_;
    std::unique_ptr<seal::Encryptor> encryptor_;
    std::unique_ptr<seal::Decryptor> decryptor_;
    std::unique_ptr<seal::Evaluator> evaluator_;
    seal::EncryptionParameters params_{seal::scheme_type::ckks};
    double scale_ = 0;
    bool has_secret_key_ = false;
    bool has_relin_keys_ = false;
};

} // namespace smartgrid
