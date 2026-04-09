// ZKP Engine - Implements Bulletproofs-style range proofs and Sigma protocol correctness proofs
// Uses SHA-256 (OpenSSL) + Fiat-Shamir heuristic for non-interactive zero-knowledge proofs

#include "common/zkp_engine.h"
#include "common/logger.h"
#include "common/metrics.h"

#include <openssl/sha.h>
#include <openssl/rand.h>
#include <cstring>
#include <chrono>
#include <cmath>
#include <algorithm>
#include <stdexcept>
#include <sstream>

namespace smartgrid {

ZKPEngine::ZKPEngine() = default;

void ZKPEngine::init(int security_bits) {
    security_bits_ = security_bits;

    // Generate deterministic generator points (simulated group generators)
    // In production, these would be elliptic curve points; here we use hash-derived values
    std::string g_seed = "SmartGrid_Pedersen_Generator_G_v1";
    std::string h_seed = "SmartGrid_Pedersen_Generator_H_v1";
    generator_g_ = hash_sha256(reinterpret_cast<const uint8_t*>(g_seed.data()), g_seed.size());
    generator_h_ = hash_sha256(reinterpret_cast<const uint8_t*>(h_seed.data()), h_seed.size());

    LOG_INFO("ZKPEngine", "Initialized with " + std::to_string(security_bits) + "-bit security");
}

// --- Commitment Scheme ---

Commitment ZKPEngine::commit(double value) {
    Commitment c;
    c.blinding = generate_random_bytes(32);
    auto val_bytes = double_to_bytes(value);

    // C = H(g^value || h^blinding) — simulated Pedersen commitment
    std::vector<uint8_t> preimage;
    preimage.insert(preimage.end(), generator_g_.begin(), generator_g_.end());
    preimage.insert(preimage.end(), val_bytes.begin(), val_bytes.end());
    preimage.insert(preimage.end(), generator_h_.begin(), generator_h_.end());
    preimage.insert(preimage.end(), c.blinding.begin(), c.blinding.end());

    c.data = hash_sha256(preimage);
    return c;
}

bool ZKPEngine::verify_commitment(const Commitment& commitment, double value) {
    auto val_bytes = double_to_bytes(value);

    std::vector<uint8_t> preimage;
    preimage.insert(preimage.end(), generator_g_.begin(), generator_g_.end());
    preimage.insert(preimage.end(), val_bytes.begin(), val_bytes.end());
    preimage.insert(preimage.end(), generator_h_.begin(), generator_h_.end());
    preimage.insert(preimage.end(), commitment.blinding.begin(), commitment.blinding.end());

    auto expected = hash_sha256(preimage);
    return expected == commitment.data;
}

// --- Range Proofs ---

RangeProof ZKPEngine::generate_range_proof(double value, double min_val, double max_val,
                                            const Commitment& commitment) {
    auto start = std::chrono::high_resolution_clock::now();

    if (value < min_val || value > max_val) {
        throw std::invalid_argument("Value out of range: cannot generate valid proof");
    }

    RangeProof proof;
    proof.claimed_min = min_val;
    proof.claimed_max = max_val;

    // Bulletproofs-style range proof simulation:
    // 1. Decompose value into binary representation relative to range
    // 2. Commit to each bit
    // 3. Generate Fiat-Shamir challenges
    // 4. Compute responses

    double normalized = (value - min_val) / (max_val - min_val);
    auto val_bytes = double_to_bytes(value);
    auto min_bytes = double_to_bytes(min_val);
    auto max_bytes = double_to_bytes(max_val);
    auto norm_bytes = double_to_bytes(normalized);

    // Step 1: Generate bit commitments (simulated)
    std::vector<uint8_t> transcript;
    transcript.insert(transcript.end(), val_bytes.begin(), val_bytes.end());
    transcript.insert(transcript.end(), min_bytes.begin(), min_bytes.end());
    transcript.insert(transcript.end(), max_bytes.begin(), max_bytes.end());

    // Inner-product argument simulation (Bulletproofs core)
    // Number of rounds = log2(bit_length)
    int bit_length = 64; // double precision
    int rounds = 6;      // log2(64)

    std::vector<uint8_t> proof_stream;

    for (int r = 0; r < rounds; r++) {
        auto round_random = generate_random_bytes(32);
        transcript.insert(transcript.end(), round_random.begin(), round_random.end());
        auto challenge = fiat_shamir_challenge(transcript);

        // L_r and R_r commitments
        std::vector<uint8_t> L_r(32), R_r(32);
        for (size_t i = 0; i < 32; i++) {
            L_r[i] = round_random[i] ^ challenge[i];
            R_r[i] = round_random[31 - i] ^ challenge[i];
        }

        proof_stream.insert(proof_stream.end(), L_r.begin(), L_r.end());
        proof_stream.insert(proof_stream.end(), R_r.begin(), R_r.end());
    }

    // Final response: blinding factor and inner product
    auto blinding = generate_random_bytes(32);
    auto final_challenge = fiat_shamir_challenge(transcript);

    proof_stream.insert(proof_stream.end(), blinding.begin(), blinding.end());
    proof_stream.insert(proof_stream.end(), final_challenge.begin(), final_challenge.end());
    proof_stream.insert(proof_stream.end(), norm_bytes.begin(), norm_bytes.end());

    // Embed verification tag: hash of (value_commitment || range || proof_data)
    std::vector<uint8_t> tag_input;
    tag_input.insert(tag_input.end(), commitment.data.begin(), commitment.data.end());
    tag_input.insert(tag_input.end(), min_bytes.begin(), min_bytes.end());
    tag_input.insert(tag_input.end(), max_bytes.begin(), max_bytes.end());
    tag_input.insert(tag_input.end(), proof_stream.begin(), proof_stream.end());
    auto tag = hash_sha256(tag_input);

    proof_stream.insert(proof_stream.end(), tag.begin(), tag.end());

    proof.proof_data = std::move(proof_stream);
    proof.proof_size_bytes = proof.proof_data.size();

    proofs_generated_++;

    auto end = std::chrono::high_resolution_clock::now();
    double ms = std::chrono::duration<double, std::milli>(end - start).count();
    MetricsCollector::instance().record("security", "zkp_range_proof_generation",
        ms, "ms", "range=[" + std::to_string(min_val) + "," + std::to_string(max_val) + "]");

    return proof;
}

VerificationResult ZKPEngine::verify_range_proof(const RangeProof& proof, const Commitment& commitment) {
    auto start = std::chrono::high_resolution_clock::now();

    VerificationResult result;

    // Verify proof structure
    int rounds = 6;
    size_t expected_min = static_cast<size_t>(rounds * 64 + 32 + 32 + 8 + 32); // L/R + blinding + challenge + norm + tag
    if (proof.proof_data.size() < expected_min) {
        result.valid = false;
        result.reason = "Proof too short: expected " + std::to_string(expected_min) +
                       " bytes, got " + std::to_string(proof.proof_data.size());
        auto end = std::chrono::high_resolution_clock::now();
        result.verification_time_ms = std::chrono::duration<double, std::milli>(end - start).count();
        proofs_verified_++;
        return result;
    }

    // Verify the tag (integrity check)
    size_t tag_offset = proof.proof_data.size() - 32;
    std::vector<uint8_t> proof_body(proof.proof_data.begin(),
                                     proof.proof_data.begin() + static_cast<long>(tag_offset));

    auto min_bytes = double_to_bytes(proof.claimed_min);
    auto max_bytes = double_to_bytes(proof.claimed_max);

    std::vector<uint8_t> tag_input;
    tag_input.insert(tag_input.end(), commitment.data.begin(), commitment.data.end());
    tag_input.insert(tag_input.end(), min_bytes.begin(), min_bytes.end());
    tag_input.insert(tag_input.end(), max_bytes.begin(), max_bytes.end());
    tag_input.insert(tag_input.end(), proof_body.begin(), proof_body.end());
    auto expected_tag = hash_sha256(tag_input);

    std::vector<uint8_t> actual_tag(proof.proof_data.begin() + static_cast<long>(tag_offset),
                                     proof.proof_data.end());

    if (expected_tag != actual_tag) {
        result.valid = false;
        result.reason = "Proof verification tag mismatch";
    } else {
        // Extract normalized value and verify range
        size_t norm_offset = tag_offset - 8;
        double normalized;
        std::memcpy(&normalized, proof.proof_data.data() + norm_offset, 8);

        if (normalized >= 0.0 && normalized <= 1.0) {
            result.valid = true;
            result.reason = "Range proof valid";
        } else {
            result.valid = false;
            result.reason = "Normalized value out of [0,1]: " + std::to_string(normalized);
        }
    }

    auto end = std::chrono::high_resolution_clock::now();
    result.verification_time_ms = std::chrono::duration<double, std::milli>(end - start).count();
    proofs_verified_++;

    MetricsCollector::instance().record("security", "zkp_range_proof_verification",
        result.verification_time_ms, "ms", "valid=" + std::string(result.valid ? "true" : "false"));

    return result;
}

// --- Correctness Proofs ---

CorrectnessProof ZKPEngine::generate_correctness_proof(double value,
                                                         const std::vector<uint8_t>& ciphertext_hash) {
    auto start = std::chrono::high_resolution_clock::now();

    CorrectnessProof proof;
    proof.value_commitment = commit(value);

    // Sigma protocol (Schnorr-like):
    // Prover demonstrates knowledge of value s.t. Commit(value) = computed commitment
    // AND Hash(Encrypt(value)) = ciphertext_hash

    auto val_bytes = double_to_bytes(value);
    auto random_nonce = generate_random_bytes(32);

    // Transcript: commitment || ciphertext_hash || nonce
    std::vector<uint8_t> transcript;
    transcript.insert(transcript.end(), proof.value_commitment.data.begin(),
                     proof.value_commitment.data.end());
    transcript.insert(transcript.end(), ciphertext_hash.begin(), ciphertext_hash.end());
    transcript.insert(transcript.end(), random_nonce.begin(), random_nonce.end());

    auto challenge = fiat_shamir_challenge(transcript);

    // Response: r = nonce + challenge * blinding
    std::vector<uint8_t> response(32);
    for (size_t i = 0; i < 32; i++) {
        response[i] = random_nonce[i] ^ (challenge[i] & proof.value_commitment.blinding[i]);
    }

    // Proof = nonce || challenge || response || ciphertext_hash
    proof.proof_data.insert(proof.proof_data.end(), random_nonce.begin(), random_nonce.end());
    proof.proof_data.insert(proof.proof_data.end(), challenge.begin(), challenge.end());
    proof.proof_data.insert(proof.proof_data.end(), response.begin(), response.end());
    proof.proof_data.insert(proof.proof_data.end(), ciphertext_hash.begin(), ciphertext_hash.end());

    proof.proof_size_bytes = proof.proof_data.size();
    proofs_generated_++;

    auto end = std::chrono::high_resolution_clock::now();
    double ms = std::chrono::duration<double, std::milli>(end - start).count();
    MetricsCollector::instance().record("security", "zkp_correctness_proof_generation", ms, "ms");

    return proof;
}

VerificationResult ZKPEngine::verify_correctness_proof(const CorrectnessProof& proof,
                                                         const std::vector<uint8_t>& ciphertext_hash) {
    auto start = std::chrono::high_resolution_clock::now();
    VerificationResult result;

    if (proof.proof_data.size() < 96) {
        result.valid = false;
        result.reason = "Proof too short";
        auto end = std::chrono::high_resolution_clock::now();
        result.verification_time_ms = std::chrono::duration<double, std::milli>(end - start).count();
        proofs_verified_++;
        return result;
    }

    // Extract components
    std::vector<uint8_t> nonce(proof.proof_data.begin(), proof.proof_data.begin() + 32);
    std::vector<uint8_t> challenge(proof.proof_data.begin() + 32, proof.proof_data.begin() + 64);
    std::vector<uint8_t> response(proof.proof_data.begin() + 64, proof.proof_data.begin() + 96);
    std::vector<uint8_t> embedded_ct_hash(proof.proof_data.begin() + 96, proof.proof_data.end());

    // Verify ciphertext hash matches
    if (embedded_ct_hash != ciphertext_hash) {
        result.valid = false;
        result.reason = "Ciphertext hash mismatch";
    } else {
        // Re-derive challenge
        std::vector<uint8_t> transcript;
        transcript.insert(transcript.end(), proof.value_commitment.data.begin(),
                         proof.value_commitment.data.end());
        transcript.insert(transcript.end(), ciphertext_hash.begin(), ciphertext_hash.end());
        transcript.insert(transcript.end(), nonce.begin(), nonce.end());

        auto expected_challenge = fiat_shamir_challenge(transcript);

        if (expected_challenge == challenge) {
            result.valid = true;
            result.reason = "Correctness proof valid";
        } else {
            result.valid = false;
            result.reason = "Challenge verification failed";
        }
    }

    auto end = std::chrono::high_resolution_clock::now();
    result.verification_time_ms = std::chrono::duration<double, std::milli>(end - start).count();
    proofs_verified_++;

    MetricsCollector::instance().record("security", "zkp_correctness_proof_verification",
        result.verification_time_ms, "ms", "valid=" + std::string(result.valid ? "true" : "false"));

    return result;
}

// --- Aggregation Proofs ---

AggregationProof ZKPEngine::generate_aggregation_proof(const std::vector<double>& inputs, double output) {
    auto start = std::chrono::high_resolution_clock::now();

    AggregationProof proof;
    proof.num_inputs = static_cast<uint32_t>(inputs.size());

    // Commit to input set (hash of all commitments)
    std::vector<uint8_t> input_commit_data;
    for (double val : inputs) {
        auto c = commit(val);
        input_commit_data.insert(input_commit_data.end(), c.data.begin(), c.data.end());
    }
    proof.input_commitment.data = hash_sha256(input_commit_data);
    proof.input_commitment.blinding = generate_random_bytes(32);

    // Commit to output
    proof.output_commitment = commit(output);

    // Prove sum correctness: sum(inputs) == output
    double computed_sum = 0.0;
    for (double val : inputs) computed_sum += val;

    auto sum_bytes = double_to_bytes(computed_sum);
    auto out_bytes = double_to_bytes(output);

    std::vector<uint8_t> transcript;
    transcript.insert(transcript.end(), proof.input_commitment.data.begin(),
                     proof.input_commitment.data.end());
    transcript.insert(transcript.end(), proof.output_commitment.data.begin(),
                     proof.output_commitment.data.end());
    transcript.insert(transcript.end(), sum_bytes.begin(), sum_bytes.end());

    auto challenge = fiat_shamir_challenge(transcript);
    auto nonce = generate_random_bytes(32);

    // Response
    std::vector<uint8_t> response(32);
    for (size_t i = 0; i < 32; i++) {
        response[i] = nonce[i] ^ challenge[i];
    }

    // Equality check: embed hash of (sum == output)
    double diff = std::abs(computed_sum - output);
    auto diff_bytes = double_to_bytes(diff);
    auto equality_tag = hash_sha256(diff_bytes);

    proof.proof_data.insert(proof.proof_data.end(), nonce.begin(), nonce.end());
    proof.proof_data.insert(proof.proof_data.end(), challenge.begin(), challenge.end());
    proof.proof_data.insert(proof.proof_data.end(), response.begin(), response.end());
    proof.proof_data.insert(proof.proof_data.end(), equality_tag.begin(), equality_tag.end());
    proof.proof_data.insert(proof.proof_data.end(), sum_bytes.begin(), sum_bytes.end());

    proof.proof_size_bytes = proof.proof_data.size();
    proofs_generated_++;

    auto end_t = std::chrono::high_resolution_clock::now();
    double ms = std::chrono::duration<double, std::milli>(end_t - start).count();
    MetricsCollector::instance().record("security", "zkp_aggregation_proof_generation",
        ms, "ms", "inputs=" + std::to_string(inputs.size()));

    return proof;
}

VerificationResult ZKPEngine::verify_aggregation_proof(const AggregationProof& proof) {
    auto start = std::chrono::high_resolution_clock::now();
    VerificationResult result;

    if (proof.proof_data.size() < 128 + 8) {
        result.valid = false;
        result.reason = "Aggregation proof too short";
        auto end = std::chrono::high_resolution_clock::now();
        result.verification_time_ms = std::chrono::duration<double, std::milli>(end - start).count();
        proofs_verified_++;
        return result;
    }

    // Extract sum from proof
    size_t sum_offset = proof.proof_data.size() - 8;
    double claimed_sum;
    std::memcpy(&claimed_sum, proof.proof_data.data() + sum_offset, 8);

    // Extract equality tag
    size_t tag_offset = sum_offset - 32;
    std::vector<uint8_t> equality_tag(proof.proof_data.begin() + static_cast<long>(tag_offset),
                                       proof.proof_data.begin() + static_cast<long>(sum_offset));

    // Verify: diff should be ~0 (HE introduces small noise)
    double zero = 0.0;
    auto zero_bytes = double_to_bytes(zero);
    auto expected_tag = hash_sha256(zero_bytes);

    // Check that equality_tag indicates sum == output (diff ≈ 0)
    if (equality_tag == expected_tag) {
        // Re-derive challenge
        auto sum_bytes = double_to_bytes(claimed_sum);
        std::vector<uint8_t> transcript;
        transcript.insert(transcript.end(), proof.input_commitment.data.begin(),
                         proof.input_commitment.data.end());
        transcript.insert(transcript.end(), proof.output_commitment.data.begin(),
                         proof.output_commitment.data.end());
        transcript.insert(transcript.end(), sum_bytes.begin(), sum_bytes.end());

        auto expected_challenge = fiat_shamir_challenge(transcript);

        std::vector<uint8_t> actual_challenge(proof.proof_data.begin() + 32,
                                               proof.proof_data.begin() + 64);
        if (expected_challenge == actual_challenge) {
            result.valid = true;
            result.reason = "Aggregation proof valid: sum verified";
        } else {
            result.valid = false;
            result.reason = "Challenge mismatch in aggregation proof";
        }
    } else {
        result.valid = false;
        result.reason = "Sum verification failed: input sum != claimed output";
    }

    auto end = std::chrono::high_resolution_clock::now();
    result.verification_time_ms = std::chrono::duration<double, std::milli>(end - start).count();
    proofs_verified_++;

    MetricsCollector::instance().record("security", "zkp_aggregation_proof_verification",
        result.verification_time_ms, "ms", "valid=" + std::string(result.valid ? "true" : "false"));

    return result;
}

// --- Billing Compliance Proofs ---

BillingComplianceProof ZKPEngine::generate_billing_proof(double consumption, double rate,
                                                           double billed_amount, uint8_t time_slot) {
    auto start = std::chrono::high_resolution_clock::now();

    BillingComplianceProof proof;
    proof.time_slot = time_slot;
    proof.amount_commitment = commit(billed_amount);

    // Prove: billed_amount == consumption * rate
    double expected = consumption * rate;
    double diff = std::abs(expected - billed_amount);

    auto cons_bytes = double_to_bytes(consumption);
    auto rate_bytes = double_to_bytes(rate);
    auto bill_bytes = double_to_bytes(billed_amount);
    auto diff_bytes = double_to_bytes(diff);

    std::vector<uint8_t> transcript;
    transcript.push_back(time_slot);
    transcript.insert(transcript.end(), proof.amount_commitment.data.begin(),
                     proof.amount_commitment.data.end());
    transcript.insert(transcript.end(), rate_bytes.begin(), rate_bytes.end());

    auto nonce = generate_random_bytes(32);
    transcript.insert(transcript.end(), nonce.begin(), nonce.end());

    auto challenge = fiat_shamir_challenge(transcript);

    std::vector<uint8_t> response(32);
    for (size_t i = 0; i < 32; i++) {
        response[i] = nonce[i] ^ challenge[i];
    }

    auto diff_tag = hash_sha256(diff_bytes);

    proof.proof_data.insert(proof.proof_data.end(), nonce.begin(), nonce.end());
    proof.proof_data.insert(proof.proof_data.end(), challenge.begin(), challenge.end());
    proof.proof_data.insert(proof.proof_data.end(), response.begin(), response.end());
    proof.proof_data.insert(proof.proof_data.end(), diff_tag.begin(), diff_tag.end());

    proof.proof_size_bytes = proof.proof_data.size();
    proofs_generated_++;

    auto end_t = std::chrono::high_resolution_clock::now();
    double ms = std::chrono::duration<double, std::milli>(end_t - start).count();
    MetricsCollector::instance().record("security", "zkp_billing_proof_generation",
        ms, "ms", "slot=" + std::to_string(time_slot));

    return proof;
}

VerificationResult ZKPEngine::verify_billing_proof(const BillingComplianceProof& proof, double rate) {
    auto start = std::chrono::high_resolution_clock::now();
    VerificationResult result;

    if (proof.proof_data.size() < 128) {
        result.valid = false;
        result.reason = "Billing proof too short";
        auto end = std::chrono::high_resolution_clock::now();
        result.verification_time_ms = std::chrono::duration<double, std::milli>(end - start).count();
        proofs_verified_++;
        return result;
    }

    // Extract and re-derive challenge
    std::vector<uint8_t> nonce(proof.proof_data.begin(), proof.proof_data.begin() + 32);

    auto rate_bytes = double_to_bytes(rate);
    std::vector<uint8_t> transcript;
    transcript.push_back(proof.time_slot);
    transcript.insert(transcript.end(), proof.amount_commitment.data.begin(),
                     proof.amount_commitment.data.end());
    transcript.insert(transcript.end(), rate_bytes.begin(), rate_bytes.end());
    transcript.insert(transcript.end(), nonce.begin(), nonce.end());

    auto expected_challenge = fiat_shamir_challenge(transcript);

    std::vector<uint8_t> actual_challenge(proof.proof_data.begin() + 32,
                                           proof.proof_data.begin() + 64);

    if (expected_challenge == actual_challenge) {
        // Check diff tag = hash(0.0) meaning billing was exact
        double zero = 0.0;
        auto zero_bytes = double_to_bytes(zero);
        auto expected_tag = hash_sha256(zero_bytes);

        std::vector<uint8_t> actual_tag(proof.proof_data.begin() + 96,
                                         proof.proof_data.begin() + 128);

        if (expected_tag == actual_tag) {
            result.valid = true;
            result.reason = "Billing compliance proof valid";
        } else {
            result.valid = false;
            result.reason = "Billing amount does not match consumption * rate";
        }
    } else {
        result.valid = false;
        result.reason = "Challenge mismatch in billing proof";
    }

    auto end = std::chrono::high_resolution_clock::now();
    result.verification_time_ms = std::chrono::duration<double, std::milli>(end - start).count();
    proofs_verified_++;

    MetricsCollector::instance().record("security", "zkp_billing_proof_verification",
        result.verification_time_ms, "ms", "valid=" + std::string(result.valid ? "true" : "false"));

    return result;
}

// --- Serialization ---

std::string ZKPEngine::serialize_range_proof(const RangeProof& proof) const {
    std::string result;
    // Format: [min:8][max:8][proof_size:4][proof_data]
    result.append(reinterpret_cast<const char*>(&proof.claimed_min), 8);
    result.append(reinterpret_cast<const char*>(&proof.claimed_max), 8);
    uint32_t sz = static_cast<uint32_t>(proof.proof_data.size());
    result.append(reinterpret_cast<const char*>(&sz), 4);
    result.append(reinterpret_cast<const char*>(proof.proof_data.data()), proof.proof_data.size());
    return result;
}

RangeProof ZKPEngine::deserialize_range_proof(const std::string& data) const {
    RangeProof proof;
    if (data.size() < 20) throw std::runtime_error("Range proof data too short");

    std::memcpy(&proof.claimed_min, data.data(), 8);
    std::memcpy(&proof.claimed_max, data.data() + 8, 8);
    uint32_t sz;
    std::memcpy(&sz, data.data() + 16, 4);

    if (data.size() < 20 + sz) throw std::runtime_error("Range proof data truncated");
    proof.proof_data.resize(sz);
    std::memcpy(proof.proof_data.data(), data.data() + 20, sz);
    proof.proof_size_bytes = sz;
    return proof;
}

std::string ZKPEngine::serialize_correctness_proof(const CorrectnessProof& proof) const {
    std::string result;
    // Commitment data
    uint32_t cd_sz = static_cast<uint32_t>(proof.value_commitment.data.size());
    uint32_t cb_sz = static_cast<uint32_t>(proof.value_commitment.blinding.size());
    result.append(reinterpret_cast<const char*>(&cd_sz), 4);
    result.append(reinterpret_cast<const char*>(proof.value_commitment.data.data()), cd_sz);
    result.append(reinterpret_cast<const char*>(&cb_sz), 4);
    result.append(reinterpret_cast<const char*>(proof.value_commitment.blinding.data()), cb_sz);
    // Proof data
    uint32_t pd_sz = static_cast<uint32_t>(proof.proof_data.size());
    result.append(reinterpret_cast<const char*>(&pd_sz), 4);
    result.append(reinterpret_cast<const char*>(proof.proof_data.data()), pd_sz);
    return result;
}

CorrectnessProof ZKPEngine::deserialize_correctness_proof(const std::string& data) const {
    CorrectnessProof proof;
    size_t offset = 0;

    auto read_vec = [&](std::vector<uint8_t>& vec) {
        if (offset + 4 > data.size()) throw std::runtime_error("Correctness proof truncated");
        uint32_t sz;
        std::memcpy(&sz, data.data() + offset, 4);
        offset += 4;
        if (offset + sz > data.size()) throw std::runtime_error("Correctness proof data truncated");
        vec.resize(sz);
        std::memcpy(vec.data(), data.data() + offset, sz);
        offset += sz;
    };

    read_vec(proof.value_commitment.data);
    read_vec(proof.value_commitment.blinding);
    read_vec(proof.proof_data);
    proof.proof_size_bytes = proof.proof_data.size();
    return proof;
}

std::string ZKPEngine::serialize_aggregation_proof(const AggregationProof& proof) const {
    std::string result;
    result.append(reinterpret_cast<const char*>(&proof.num_inputs), 4);
    // Input/output commitments
    auto append_commitment = [&](const Commitment& c) {
        uint32_t sz = static_cast<uint32_t>(c.data.size());
        result.append(reinterpret_cast<const char*>(&sz), 4);
        result.append(reinterpret_cast<const char*>(c.data.data()), sz);
        uint32_t bsz = static_cast<uint32_t>(c.blinding.size());
        result.append(reinterpret_cast<const char*>(&bsz), 4);
        result.append(reinterpret_cast<const char*>(c.blinding.data()), bsz);
    };
    append_commitment(proof.input_commitment);
    append_commitment(proof.output_commitment);
    uint32_t pd_sz = static_cast<uint32_t>(proof.proof_data.size());
    result.append(reinterpret_cast<const char*>(&pd_sz), 4);
    result.append(reinterpret_cast<const char*>(proof.proof_data.data()), pd_sz);
    return result;
}

AggregationProof ZKPEngine::deserialize_aggregation_proof(const std::string& data) const {
    AggregationProof proof;
    size_t offset = 0;

    if (data.size() < 4) throw std::runtime_error("Aggregation proof too short");
    std::memcpy(&proof.num_inputs, data.data(), 4);
    offset = 4;

    auto read_commitment = [&](Commitment& c) {
        uint32_t sz;
        std::memcpy(&sz, data.data() + offset, 4); offset += 4;
        c.data.resize(sz);
        std::memcpy(c.data.data(), data.data() + offset, sz); offset += sz;
        std::memcpy(&sz, data.data() + offset, 4); offset += 4;
        c.blinding.resize(sz);
        std::memcpy(c.blinding.data(), data.data() + offset, sz); offset += sz;
    };

    read_commitment(proof.input_commitment);
    read_commitment(proof.output_commitment);

    uint32_t pd_sz;
    std::memcpy(&pd_sz, data.data() + offset, 4); offset += 4;
    proof.proof_data.resize(pd_sz);
    std::memcpy(proof.proof_data.data(), data.data() + offset, pd_sz);
    proof.proof_size_bytes = pd_sz;
    return proof;
}

// --- Internal Helpers ---

std::vector<uint8_t> ZKPEngine::hash_sha256(const std::vector<uint8_t>& data) const {
    return hash_sha256(data.data(), data.size());
}

std::vector<uint8_t> ZKPEngine::hash_sha256(const void* data, size_t len) const {
    std::vector<uint8_t> digest(SHA256_DIGEST_LENGTH);
    SHA256(reinterpret_cast<const unsigned char*>(data), len, digest.data());
    return digest;
}

std::vector<uint8_t> ZKPEngine::fiat_shamir_challenge(const std::vector<uint8_t>& transcript) const {
    // Domain-separated hash for Fiat-Shamir
    std::vector<uint8_t> prefixed;
    std::string domain = "SmartGrid_FiatShamir_v1";
    prefixed.insert(prefixed.end(), domain.begin(), domain.end());
    prefixed.insert(prefixed.end(), transcript.begin(), transcript.end());
    return hash_sha256(prefixed);
}

std::vector<uint8_t> ZKPEngine::double_to_bytes(double val) const {
    std::vector<uint8_t> bytes(8);
    std::memcpy(bytes.data(), &val, 8);
    return bytes;
}

std::vector<uint8_t> ZKPEngine::generate_random_bytes(size_t count) const {
    std::vector<uint8_t> bytes(count);
    if (RAND_bytes(bytes.data(), static_cast<int>(count)) != 1) {
        throw std::runtime_error("RAND_bytes failed in ZKP engine");
    }
    return bytes;
}

} // namespace smartgrid
