/**
 * HE Scheme Comparison Benchmark
 * 
 * Compares CKKS, BFV, BGV (via SEAL 4.1) and Paillier (via OpenSSL BN)
 * for smart meter aggregation with 10 meters.
 * 
 * Measures: key generation, encryption, decryption, homomorphic addition,
 *           ciphertext size, and accuracy.
 * 
 * Usage: ./scheme_comparison [output_csv]
 */

#include <seal/seal.h>
#include <openssl/bn.h>
#include <openssl/rand.h>

#include <chrono>
#include <cmath>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <numeric>
#include <random>
#include <sstream>
#include <string>
#include <vector>
#include <functional>
#include <memory>

// ============================================================
// Timing utility
// ============================================================
struct TimingResult {
    double mean_us;
    double std_us;
    double min_us;
    double max_us;
    int n;
};

template <typename Func>
TimingResult benchmark(Func&& fn, int iterations = 1) {
    std::vector<double> times;
    times.reserve(iterations);
    for (int i = 0; i < iterations; i++) {
        auto start = std::chrono::high_resolution_clock::now();
        fn();
        auto end = std::chrono::high_resolution_clock::now();
        double us = std::chrono::duration<double, std::micro>(end - start).count();
        times.push_back(us);
    }
    double sum = std::accumulate(times.begin(), times.end(), 0.0);
    double mean = sum / times.size();
    double sq_sum = 0;
    for (auto t : times) sq_sum += (t - mean) * (t - mean);
    double std_dev = times.size() > 1 ? std::sqrt(sq_sum / (times.size() - 1)) : 0;
    return {mean, std_dev, *std::min_element(times.begin(), times.end()),
            *std::max_element(times.begin(), times.end()), (int)times.size()};
}

// ============================================================
// Paillier implementation using OpenSSL BIGNUM
// ============================================================
struct PaillierKeys {
    BIGNUM* n;       // public key: n = p * q
    BIGNUM* n2;      // n^2
    BIGNUM* g;       // generator (n + 1)
    BIGNUM* lambda;  // private key: lcm(p-1, q-1)
    BIGNUM* mu;      // L(g^lambda mod n^2)^(-1) mod n

    PaillierKeys() : n(nullptr), n2(nullptr), g(nullptr), lambda(nullptr), mu(nullptr) {}

    ~PaillierKeys() {
        if (n) BN_free(n);
        if (n2) BN_free(n2);
        if (g) BN_free(g);
        if (lambda) BN_free(lambda);
        if (mu) BN_free(mu);
    }
};

// L function: L(u) = (u - 1) / n
static BIGNUM* paillier_L(const BIGNUM* u, const BIGNUM* n, BN_CTX* ctx) {
    BIGNUM* result = BN_new();
    BIGNUM* one = BN_new();
    BN_one(one);
    BN_sub(result, u, one);
    BN_div(result, nullptr, result, n, ctx);
    BN_free(one);
    return result;
}

static std::unique_ptr<PaillierKeys> paillier_keygen(int bits = 2048) {
    auto keys = std::make_unique<PaillierKeys>();
    BN_CTX* ctx = BN_CTX_new();

    BIGNUM* p = BN_new();
    BIGNUM* q = BN_new();
    BN_generate_prime_ex(p, bits / 2, 0, nullptr, nullptr, nullptr);
    BN_generate_prime_ex(q, bits / 2, 0, nullptr, nullptr, nullptr);

    keys->n = BN_new();
    BN_mul(keys->n, p, q, ctx);

    keys->n2 = BN_new();
    BN_sqr(keys->n2, keys->n, ctx);

    keys->g = BN_new();
    BIGNUM* one = BN_new();
    BN_one(one);
    BN_add(keys->g, keys->n, one);

    // lambda = lcm(p-1, q-1)
    BIGNUM* p1 = BN_new();
    BIGNUM* q1 = BN_new();
    BN_sub(p1, p, one);
    BN_sub(q1, q, one);

    BIGNUM* pq1 = BN_new();
    BN_mul(pq1, p1, q1, ctx);

    BIGNUM* gcd_pq = BN_new();
    BN_gcd(gcd_pq, p1, q1, ctx);

    keys->lambda = BN_new();
    BN_div(keys->lambda, nullptr, pq1, gcd_pq, ctx);

    // mu = L(g^lambda mod n^2)^(-1) mod n
    BIGNUM* gl = BN_new();
    BN_mod_exp(gl, keys->g, keys->lambda, keys->n2, ctx);

    BIGNUM* l_val = paillier_L(gl, keys->n, ctx);

    keys->mu = BN_new();
    BN_mod_inverse(keys->mu, l_val, keys->n, ctx);

    BN_free(p); BN_free(q); BN_free(one);
    BN_free(p1); BN_free(q1); BN_free(pq1);
    BN_free(gcd_pq); BN_free(gl); BN_free(l_val);
    BN_CTX_free(ctx);

    return keys;
}

static BIGNUM* paillier_encrypt(const BIGNUM* m, const PaillierKeys* keys) {
    BN_CTX* ctx = BN_CTX_new();
    BIGNUM* r = BN_new();

    // r = random in [1, n)
    BN_rand_range(r, keys->n);
    if (BN_is_zero(r)) BN_one(r);

    // c = g^m * r^n mod n^2
    BIGNUM* gm = BN_new();
    BN_mod_exp(gm, keys->g, m, keys->n2, ctx);

    BIGNUM* rn = BN_new();
    BN_mod_exp(rn, r, keys->n, keys->n2, ctx);

    BIGNUM* c = BN_new();
    BN_mod_mul(c, gm, rn, keys->n2, ctx);

    BN_free(r); BN_free(gm); BN_free(rn);
    BN_CTX_free(ctx);
    return c;
}

static BIGNUM* paillier_decrypt(const BIGNUM* c, const PaillierKeys* keys) {
    BN_CTX* ctx = BN_CTX_new();

    BIGNUM* cl = BN_new();
    BN_mod_exp(cl, c, keys->lambda, keys->n2, ctx);

    BIGNUM* l_val = paillier_L(cl, keys->n, ctx);

    BIGNUM* m = BN_new();
    BN_mod_mul(m, l_val, keys->mu, keys->n, ctx);

    BN_free(cl); BN_free(l_val);
    BN_CTX_free(ctx);
    return m;
}

static BIGNUM* paillier_add(const BIGNUM* c1, const BIGNUM* c2, const PaillierKeys* keys) {
    BN_CTX* ctx = BN_CTX_new();
    BIGNUM* result = BN_new();
    BN_mod_mul(result, c1, c2, keys->n2, ctx);
    BN_CTX_free(ctx);
    return result;
}

// ============================================================
// Test data: simulated meter readings (kWh)
// ============================================================
static std::vector<double> generate_readings(int n_meters, unsigned seed = 42) {
    std::mt19937 rng(seed);
    // UK low-consumer profile: mean ~0.10 kWh
    std::normal_distribution<double> dist(0.10, 0.03);
    std::vector<double> readings(n_meters);
    for (auto& r : readings) {
        r = std::max(0.0, dist(rng));
    }
    return readings;
}

// ============================================================
// Result structure
// ============================================================
struct SchemeResult {
    std::string scheme;
    double keygen_ms;
    double encrypt_ms;     // mean per reading
    double decrypt_ms;     // per aggregated result
    double add_ms;         // mean per pairwise addition
    size_t ct_bytes;       // single ciphertext size
    size_t key_bytes;      // total key material
    double accuracy_error; // |decrypted_sum - plaintext_sum|
    double relative_error; // as percentage
    int n_meters;
    std::string params;    // parameter description
};

// ============================================================
// CKKS benchmark
// ============================================================
SchemeResult bench_ckks(const std::vector<double>& readings, int poly_deg = 8192) {
    SchemeResult res;
    res.scheme = "CKKS";
    res.n_meters = readings.size();

    std::vector<int> coeff_bits;
    if (poly_deg == 4096) coeff_bits = {40, 40, 40};
    else if (poly_deg == 8192) coeff_bits = {60, 40, 40, 60};
    else coeff_bits = {60, 40, 40, 40, 40, 60};

    res.params = "poly=" + std::to_string(poly_deg) + " scale=2^40 sec=128";

    double scale = pow(2.0, 40);

    // Key generation
    auto kg_time = benchmark([&]() {
        seal::EncryptionParameters parms(seal::scheme_type::ckks);
        parms.set_poly_modulus_degree(poly_deg);
        parms.set_coeff_modulus(seal::CoeffModulus::Create(poly_deg, coeff_bits));
        seal::SEALContext context(parms);
        seal::KeyGenerator keygen(context);
        auto sk = keygen.secret_key();
        auto pk = keygen.create_public_key();
    }, 3);
    res.keygen_ms = kg_time.mean_us / 1000.0;

    // Setup context
    seal::EncryptionParameters parms(seal::scheme_type::ckks);
    parms.set_poly_modulus_degree(poly_deg);
    parms.set_coeff_modulus(seal::CoeffModulus::Create(poly_deg, coeff_bits));
    seal::SEALContext context(parms);
    seal::KeyGenerator keygen(context);
    auto sk = keygen.secret_key();
    seal::PublicKey pk;
    keygen.create_public_key(pk);
    seal::Encryptor encryptor(context, pk);
    seal::Decryptor decryptor(context, sk);
    seal::CKKSEncoder encoder(context);
    seal::Evaluator evaluator(context);

    // Encrypt each reading
    std::vector<seal::Ciphertext> cts(readings.size());
    auto enc_time = benchmark([&]() {
        for (size_t i = 0; i < readings.size(); i++) {
            seal::Plaintext pt;
            encoder.encode(readings[i], scale, pt);
            encryptor.encrypt(pt, cts[i]);
        }
    }, 5);
    res.encrypt_ms = enc_time.mean_us / 1000.0 / readings.size();

    // Ciphertext size
    std::stringstream ss;
    cts[0].save(ss);
    res.ct_bytes = ss.str().size();

    // Key size
    std::stringstream sk_ss, pk_ss;
    sk.save(sk_ss);
    pk.save(pk_ss);
    res.key_bytes = sk_ss.str().size() + pk_ss.str().size();

    // Homomorphic addition
    seal::Ciphertext agg;
    auto add_time = benchmark([&]() {
        agg = cts[0];
        for (size_t i = 1; i < cts.size(); i++) {
            evaluator.add_inplace(agg, cts[i]);
        }
    }, 10);
    res.add_ms = add_time.mean_us / 1000.0 / (readings.size() - 1);

    // Decrypt
    auto dec_time = benchmark([&]() {
        seal::Plaintext pt_result;
        decryptor.decrypt(agg, pt_result);
        std::vector<double> result;
        encoder.decode(pt_result, result);
    }, 10);
    res.decrypt_ms = dec_time.mean_us / 1000.0;

    // Accuracy
    seal::Plaintext pt_result;
    decryptor.decrypt(agg, pt_result);
    std::vector<double> result;
    encoder.decode(pt_result, result);
    double decrypted_sum = result[0];
    double plaintext_sum = std::accumulate(readings.begin(), readings.end(), 0.0);
    res.accuracy_error = std::abs(decrypted_sum - plaintext_sum);
    res.relative_error = (plaintext_sum != 0) ? (res.accuracy_error / std::abs(plaintext_sum)) * 100.0 : 0;

    return res;
}

// ============================================================
// BFV benchmark
// ============================================================
SchemeResult bench_bfv(const std::vector<double>& readings, int poly_deg = 8192) {
    SchemeResult res;
    res.scheme = "BFV";
    res.n_meters = readings.size();

    // Scale to integers: multiply by 1,000,000 for 6 decimal places
    const uint64_t SCALE = 1000000ULL;
    std::vector<uint64_t> int_readings(readings.size());
    for (size_t i = 0; i < readings.size(); i++) {
        int_readings[i] = static_cast<uint64_t>(std::round(readings[i] * SCALE));
    }

    std::vector<int> coeff_bits;
    if (poly_deg == 4096) coeff_bits = {40, 40, 40};
    else if (poly_deg == 8192) coeff_bits = {60, 40, 40, 60};
    else coeff_bits = {60, 40, 40, 40, 40, 60};

    // Use a plain_modulus large enough
    // For BFV, plain_modulus must be a prime > max possible sum
    uint64_t max_sum = SCALE * readings.size() * 3; // 3 kWh max
    uint64_t plain_mod = 1ULL << 40; // large enough

    res.params = "poly=" + std::to_string(poly_deg) + " plain_mod=2^40 sec=128";

    // Key generation
    auto kg_time = benchmark([&]() {
        seal::EncryptionParameters parms(seal::scheme_type::bfv);
        parms.set_poly_modulus_degree(poly_deg);
        parms.set_coeff_modulus(seal::CoeffModulus::Create(poly_deg, coeff_bits));
        parms.set_plain_modulus(seal::PlainModulus::Batching(poly_deg, 41));
        seal::SEALContext context(parms);
        seal::KeyGenerator keygen(context);
        auto sk = keygen.secret_key();
        auto pk = keygen.create_public_key();
    }, 3);
    res.keygen_ms = kg_time.mean_us / 1000.0;

    // Setup
    seal::EncryptionParameters parms(seal::scheme_type::bfv);
    parms.set_poly_modulus_degree(poly_deg);
    parms.set_coeff_modulus(seal::CoeffModulus::Create(poly_deg, coeff_bits));
    parms.set_plain_modulus(seal::PlainModulus::Batching(poly_deg, 41));
    seal::SEALContext context(parms);
    seal::KeyGenerator keygen(context);
    auto sk = keygen.secret_key();
    seal::PublicKey pk;
    keygen.create_public_key(pk);
    seal::Encryptor encryptor(context, pk);
    seal::Decryptor decryptor(context, sk);
    seal::BatchEncoder encoder(context);
    seal::Evaluator evaluator(context);

    size_t slot_count = encoder.slot_count();

    // Encrypt
    std::vector<seal::Ciphertext> cts(readings.size());
    auto enc_time = benchmark([&]() {
        for (size_t i = 0; i < readings.size(); i++) {
            std::vector<uint64_t> pod(slot_count, 0);
            pod[0] = int_readings[i];
            seal::Plaintext pt;
            encoder.encode(pod, pt);
            encryptor.encrypt(pt, cts[i]);
        }
    }, 5);
    res.encrypt_ms = enc_time.mean_us / 1000.0 / readings.size();

    // CT size
    std::stringstream ss;
    cts[0].save(ss);
    res.ct_bytes = ss.str().size();

    // Key size
    std::stringstream sk_ss, pk_ss;
    sk.save(sk_ss);
    pk.save(pk_ss);
    res.key_bytes = sk_ss.str().size() + pk_ss.str().size();

    // Addition
    seal::Ciphertext agg;
    auto add_time = benchmark([&]() {
        agg = cts[0];
        for (size_t i = 1; i < cts.size(); i++) {
            evaluator.add_inplace(agg, cts[i]);
        }
    }, 10);
    res.add_ms = add_time.mean_us / 1000.0 / (readings.size() - 1);

    // Decrypt
    auto dec_time = benchmark([&]() {
        seal::Plaintext pt_result;
        decryptor.decrypt(agg, pt_result);
        std::vector<uint64_t> result;
        encoder.decode(pt_result, result);
    }, 10);
    res.decrypt_ms = dec_time.mean_us / 1000.0;

    // Accuracy
    seal::Plaintext pt_result;
    decryptor.decrypt(agg, pt_result);
    std::vector<uint64_t> result;
    encoder.decode(pt_result, result);
    double decrypted_sum = static_cast<double>(result[0]) / SCALE;
    double plaintext_sum = std::accumulate(readings.begin(), readings.end(), 0.0);
    res.accuracy_error = std::abs(decrypted_sum - plaintext_sum);
    res.relative_error = (plaintext_sum != 0) ? (res.accuracy_error / std::abs(plaintext_sum)) * 100.0 : 0;

    return res;
}

// ============================================================
// BGV benchmark
// ============================================================
SchemeResult bench_bgv(const std::vector<double>& readings, int poly_deg = 8192) {
    SchemeResult res;
    res.scheme = "BGV";
    res.n_meters = readings.size();

    const uint64_t SCALE = 1000000ULL;
    std::vector<uint64_t> int_readings(readings.size());
    for (size_t i = 0; i < readings.size(); i++) {
        int_readings[i] = static_cast<uint64_t>(std::round(readings[i] * SCALE));
    }

    std::vector<int> coeff_bits;
    if (poly_deg == 4096) coeff_bits = {40, 40, 40};
    else if (poly_deg == 8192) coeff_bits = {60, 40, 40, 60};
    else coeff_bits = {60, 40, 40, 40, 40, 60};

    res.params = "poly=" + std::to_string(poly_deg) + " plain_mod=2^40 sec=128";

    // Key generation
    auto kg_time = benchmark([&]() {
        seal::EncryptionParameters parms(seal::scheme_type::bgv);
        parms.set_poly_modulus_degree(poly_deg);
        parms.set_coeff_modulus(seal::CoeffModulus::Create(poly_deg, coeff_bits));
        parms.set_plain_modulus(seal::PlainModulus::Batching(poly_deg, 41));
        seal::SEALContext context(parms);
        seal::KeyGenerator keygen(context);
        auto sk = keygen.secret_key();
        auto pk = keygen.create_public_key();
    }, 3);
    res.keygen_ms = kg_time.mean_us / 1000.0;

    // Setup
    seal::EncryptionParameters parms(seal::scheme_type::bgv);
    parms.set_poly_modulus_degree(poly_deg);
    parms.set_coeff_modulus(seal::CoeffModulus::Create(poly_deg, coeff_bits));
    parms.set_plain_modulus(seal::PlainModulus::Batching(poly_deg, 41));
    seal::SEALContext context(parms);
    seal::KeyGenerator keygen(context);
    auto sk = keygen.secret_key();
    seal::PublicKey pk;
    keygen.create_public_key(pk);
    seal::Encryptor encryptor(context, pk);
    seal::Decryptor decryptor(context, sk);
    seal::BatchEncoder encoder(context);
    seal::Evaluator evaluator(context);

    size_t slot_count = encoder.slot_count();

    // Encrypt
    std::vector<seal::Ciphertext> cts(readings.size());
    auto enc_time = benchmark([&]() {
        for (size_t i = 0; i < readings.size(); i++) {
            std::vector<uint64_t> pod(slot_count, 0);
            pod[0] = int_readings[i];
            seal::Plaintext pt;
            encoder.encode(pod, pt);
            encryptor.encrypt(pt, cts[i]);
        }
    }, 5);
    res.encrypt_ms = enc_time.mean_us / 1000.0 / readings.size();

    // CT size
    std::stringstream ss;
    cts[0].save(ss);
    res.ct_bytes = ss.str().size();

    // Key size
    std::stringstream sk_ss, pk_ss;
    sk.save(sk_ss);
    pk.save(pk_ss);
    res.key_bytes = sk_ss.str().size() + pk_ss.str().size();

    // Addition
    seal::Ciphertext agg;
    auto add_time = benchmark([&]() {
        agg = cts[0];
        for (size_t i = 1; i < cts.size(); i++) {
            evaluator.add_inplace(agg, cts[i]);
        }
    }, 10);
    res.add_ms = add_time.mean_us / 1000.0 / (readings.size() - 1);

    // Decrypt
    auto dec_time = benchmark([&]() {
        seal::Plaintext pt_result;
        decryptor.decrypt(agg, pt_result);
        std::vector<uint64_t> result;
        encoder.decode(pt_result, result);
    }, 10);
    res.decrypt_ms = dec_time.mean_us / 1000.0;

    // Accuracy
    seal::Plaintext pt_result;
    decryptor.decrypt(agg, pt_result);
    std::vector<uint64_t> result;
    encoder.decode(pt_result, result);
    double decrypted_sum = static_cast<double>(result[0]) / SCALE;
    double plaintext_sum = std::accumulate(readings.begin(), readings.end(), 0.0);
    res.accuracy_error = std::abs(decrypted_sum - plaintext_sum);
    res.relative_error = (plaintext_sum != 0) ? (res.accuracy_error / std::abs(plaintext_sum)) * 100.0 : 0;

    return res;
}

// ============================================================
// Paillier benchmark
// ============================================================
SchemeResult bench_paillier(const std::vector<double>& readings, int key_bits = 2048) {
    SchemeResult res;
    res.scheme = "Paillier";
    res.n_meters = readings.size();
    res.params = "key=" + std::to_string(key_bits) + "bit";

    const uint64_t SCALE = 1000000ULL;

    // Key generation
    std::unique_ptr<PaillierKeys> keys;
    auto kg_time = benchmark([&]() {
        keys = paillier_keygen(key_bits);
    }, 1);  // Paillier keygen is slow, run once
    res.keygen_ms = kg_time.mean_us / 1000.0;

    // Key size: n + lambda + mu (approximation)
    res.key_bytes = (BN_num_bytes(keys->n) * 2) + BN_num_bytes(keys->lambda) + BN_num_bytes(keys->mu);

    // Encrypt
    std::vector<BIGNUM*> cts(readings.size());
    auto enc_time = benchmark([&]() {
        for (size_t i = 0; i < readings.size(); i++) {
            if (cts[i]) BN_free(cts[i]);
            BIGNUM* m = BN_new();
            BN_set_word(m, static_cast<uint64_t>(std::round(readings[i] * SCALE)));
            cts[i] = paillier_encrypt(m, keys.get());
            BN_free(m);
        }
    }, 5);
    res.encrypt_ms = enc_time.mean_us / 1000.0 / readings.size();

    // CT size
    res.ct_bytes = BN_num_bytes(cts[0]);

    // Homomorphic addition (multiplication of ciphertexts mod n^2)
    BIGNUM* agg = nullptr;
    auto add_time = benchmark([&]() {
        if (agg) BN_free(agg);
        agg = BN_dup(cts[0]);
        for (size_t i = 1; i < cts.size(); i++) {
            BIGNUM* tmp = paillier_add(agg, cts[i], keys.get());
            BN_free(agg);
            agg = tmp;
        }
    }, 10);
    res.add_ms = add_time.mean_us / 1000.0 / (readings.size() - 1);

    // Decrypt
    auto dec_time = benchmark([&]() {
        BIGNUM* m = paillier_decrypt(agg, keys.get());
        BN_free(m);
    }, 10);
    res.decrypt_ms = dec_time.mean_us / 1000.0;

    // Accuracy
    BIGNUM* m_result = paillier_decrypt(agg, keys.get());
    char* hex = BN_bn2dec(m_result);
    double decrypted_sum = std::stod(hex) / SCALE;
    OPENSSL_free(hex);
    BN_free(m_result);

    double plaintext_sum = std::accumulate(readings.begin(), readings.end(), 0.0);
    res.accuracy_error = std::abs(decrypted_sum - plaintext_sum);
    res.relative_error = (plaintext_sum != 0) ? (res.accuracy_error / std::abs(plaintext_sum)) * 100.0 : 0;

    // Cleanup
    for (auto& ct : cts) if (ct) BN_free(ct);
    if (agg) BN_free(agg);

    return res;
}

// ============================================================
// Main
// ============================================================
int main(int argc, char* argv[]) {
    std::string csv_path = "output/scheme_comparison.csv";
    if (argc > 1) csv_path = argv[1];

    const int N_METERS = 10;
    auto readings = generate_readings(N_METERS);

    double plaintext_sum = std::accumulate(readings.begin(), readings.end(), 0.0);

    std::cout << "=== HE Scheme Comparison Benchmark ===" << std::endl;
    std::cout << "Meters: " << N_METERS << std::endl;
    std::cout << "Plaintext sum: " << std::fixed << std::setprecision(6) << plaintext_sum << " kWh" << std::endl;
    std::cout << std::endl;

    std::vector<SchemeResult> results;

    // --- CKKS ---
    std::cout << "Benchmarking CKKS..." << std::flush;
    try {
        results.push_back(bench_ckks(readings));
        std::cout << " done" << std::endl;
    } catch (const std::exception& e) {
        std::cout << " FAILED: " << e.what() << std::endl;
    }

    // --- BFV ---
    std::cout << "Benchmarking BFV..." << std::flush;
    try {
        results.push_back(bench_bfv(readings));
        std::cout << " done" << std::endl;
    } catch (const std::exception& e) {
        std::cout << " FAILED: " << e.what() << std::endl;
    }

    // --- BGV ---
    std::cout << "Benchmarking BGV..." << std::flush;
    try {
        results.push_back(bench_bgv(readings));
        std::cout << " done" << std::endl;
    } catch (const std::exception& e) {
        std::cout << " FAILED: " << e.what() << std::endl;
    }

    // --- Paillier ---
    std::cout << "Benchmarking Paillier (2048-bit)..." << std::flush;
    try {
        results.push_back(bench_paillier(readings, 2048));
        std::cout << " done" << std::endl;
    } catch (const std::exception& e) {
        std::cout << " FAILED: " << e.what() << std::endl;
    }

    // Print results table
    std::cout << std::endl;
    std::cout << std::string(120, '=') << std::endl;
    std::cout << std::left
              << std::setw(10) << "Scheme"
              << std::setw(25) << "Parameters"
              << std::right
              << std::setw(12) << "KeyGen(ms)"
              << std::setw(12) << "Enc(ms/r)"
              << std::setw(12) << "Dec(ms)"
              << std::setw(12) << "Add(ms/op)"
              << std::setw(12) << "CT(bytes)"
              << std::setw(12) << "Key(bytes)"
              << std::setw(15) << "Abs Err(kWh)"
              << std::setw(12) << "Rel Err(%)"
              << std::endl;
    std::cout << std::string(120, '-') << std::endl;

    for (const auto& r : results) {
        std::cout << std::left
                  << std::setw(10) << r.scheme
                  << std::setw(25) << r.params
                  << std::right << std::fixed
                  << std::setw(12) << std::setprecision(2) << r.keygen_ms
                  << std::setw(12) << std::setprecision(3) << r.encrypt_ms
                  << std::setw(12) << std::setprecision(3) << r.decrypt_ms
                  << std::setw(12) << std::setprecision(4) << r.add_ms
                  << std::setw(12) << r.ct_bytes
                  << std::setw(12) << r.key_bytes
                  << std::setw(15) << std::setprecision(9) << r.accuracy_error
                  << std::setw(12) << std::setprecision(8) << r.relative_error
                  << std::endl;
    }
    std::cout << std::string(120, '=') << std::endl;

    // Write CSV
    std::ofstream csv(csv_path);
    csv << "scheme,parameters,keygen_ms,encrypt_per_reading_ms,decrypt_ms,"
        << "add_per_op_ms,ciphertext_bytes,key_bytes,absolute_error_kwh,"
        << "relative_error_pct,n_meters" << std::endl;
    for (const auto& r : results) {
        csv << r.scheme << ","
            << "\"" << r.params << "\","
            << std::fixed
            << std::setprecision(3) << r.keygen_ms << ","
            << std::setprecision(4) << r.encrypt_ms << ","
            << std::setprecision(4) << r.decrypt_ms << ","
            << std::setprecision(6) << r.add_ms << ","
            << r.ct_bytes << ","
            << r.key_bytes << ","
            << std::setprecision(12) << r.accuracy_error << ","
            << std::setprecision(10) << r.relative_error << ","
            << r.n_meters << std::endl;
    }
    csv.close();

    std::cout << std::endl << "Results saved to " << csv_path << std::endl;

    return 0;
}
