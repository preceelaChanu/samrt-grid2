#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include <cstddef>

namespace smartgrid {

// Commitment structure (Pedersen-style commitment for range proofs)
struct Commitment {
    std::vector<uint8_t> data;  // Serialized commitment
    std::vector<uint8_t> blinding; // Blinding factor (kept secret by prover)
};

// Range proof: proves value is in [min, max] without revealing it
struct RangeProof {
    std::vector<uint8_t> proof_data;
    double claimed_min;
    double claimed_max;
    size_t proof_size_bytes;
};

// Correctness proof: proves encrypted value equals committed value
struct CorrectnessProof {
    std::vector<uint8_t> proof_data;
    Commitment value_commitment;
    size_t proof_size_bytes;
};

// Aggregation proof: proves aggregation was computed correctly
struct AggregationProof {
    std::vector<uint8_t> proof_data;
    Commitment input_commitment;   // Commitment to input set
    Commitment output_commitment;  // Commitment to aggregated output
    uint32_t num_inputs;
    size_t proof_size_bytes;
};

// Billing compliance proof: proves billing rule was applied correctly
struct BillingComplianceProof {
    std::vector<uint8_t> proof_data;
    uint8_t time_slot;            // ToU slot index
    Commitment amount_commitment;  // Commitment to billed amount
    size_t proof_size_bytes;
};

// Verification result
struct VerificationResult {
    bool valid;
    std::string reason;
    double verification_time_ms;
};

// ZKP Engine implementing Bulletproofs-style range proofs and Sigma protocol correctness proofs
// Uses SHA-256 + Fiat-Shamir heuristic for non-interactive proofs
class ZKPEngine {
public:
    ZKPEngine();

    // Initialize with security parameters
    void init(int security_bits = 128);

    // --- Range Proofs ---

    // Generate a range proof that value ∈ [min_val, max_val]
    RangeProof generate_range_proof(double value, double min_val, double max_val,
                                    const Commitment& commitment);

    // Verify a range proof
    VerificationResult verify_range_proof(const RangeProof& proof, const Commitment& commitment);

    // --- Correctness Proofs ---

    // Prove that the encrypted value matches the committed value
    CorrectnessProof generate_correctness_proof(double value, const std::vector<uint8_t>& ciphertext_hash);

    // Verify a correctness proof against a ciphertext hash
    VerificationResult verify_correctness_proof(const CorrectnessProof& proof,
                                                 const std::vector<uint8_t>& ciphertext_hash);

    // --- Aggregation Proofs ---

    // Prove that output = sum(inputs) for committed values
    AggregationProof generate_aggregation_proof(const std::vector<double>& inputs, double output);

    // Verify an aggregation proof
    VerificationResult verify_aggregation_proof(const AggregationProof& proof);

    // --- Billing Compliance Proofs ---

    // Prove that billing was computed correctly for a given time slot
    BillingComplianceProof generate_billing_proof(double consumption, double rate,
                                                   double billed_amount, uint8_t time_slot);

    // Verify billing compliance
    VerificationResult verify_billing_proof(const BillingComplianceProof& proof, double rate);

    // --- Commitment Scheme ---

    // Create a Pedersen commitment to a value
    Commitment commit(double value);

    // Open/verify a commitment
    bool verify_commitment(const Commitment& commitment, double value);

    // --- Serialization ---
    std::string serialize_range_proof(const RangeProof& proof) const;
    RangeProof deserialize_range_proof(const std::string& data) const;

    std::string serialize_correctness_proof(const CorrectnessProof& proof) const;
    CorrectnessProof deserialize_correctness_proof(const std::string& data) const;

    std::string serialize_aggregation_proof(const AggregationProof& proof) const;
    AggregationProof deserialize_aggregation_proof(const std::string& data) const;

    // Performance metrics
    size_t total_proofs_generated() const { return proofs_generated_; }
    size_t total_proofs_verified() const { return proofs_verified_; }

private:
    int security_bits_;
    size_t proofs_generated_ = 0;
    size_t proofs_verified_ = 0;

    // Generator points for Pedersen commitments (simulated as hash-derived)
    std::vector<uint8_t> generator_g_;
    std::vector<uint8_t> generator_h_;

    // Internal helpers
    std::vector<uint8_t> hash_sha256(const std::vector<uint8_t>& data) const;
    std::vector<uint8_t> hash_sha256(const void* data, size_t len) const;
    std::vector<uint8_t> fiat_shamir_challenge(const std::vector<uint8_t>& transcript) const;
    std::vector<uint8_t> double_to_bytes(double val) const;
    std::vector<uint8_t> generate_random_bytes(size_t count) const;
};

} // namespace smartgrid
