#pragma once

#include "common/crypto_engine.h"
#include "common/zkp_engine.h"
#include <seal/seal.h>
#include <string>
#include <vector>
#include <cstdint>

namespace smartgrid {

// Hash of a batch aggregation operation for verification
struct AggregationRecord {
    uint32_t batch_id;
    uint32_t num_inputs;
    std::vector<uint8_t> inputs_hash;   // H(ct1 || ct2 || ... || ctN)
    std::vector<uint8_t> output_hash;   // H(aggregated_ct)
    AggregationProof zkp_proof;         // ZKP that aggregation was honest
    std::string timestamp;
};

// Verification log entry
struct VerificationLogEntry {
    uint32_t batch_id;
    bool aggregation_valid;
    bool all_range_proofs_valid;
    int invalid_proof_count;
    double total_verification_time_ms;
    std::string timestamp;
};

// Verifiable Computation Engine
// Ensures honest behavior of aggregators and other intermediaries
class VerifiableComputation {
public:
    VerifiableComputation();

    // Initialize with a ZKP engine reference
    void init(ZKPEngine& zkp);

    // --- Aggregation Verification ---

    // Record an aggregation operation (called by aggregator)
    AggregationRecord record_aggregation(
        uint32_t batch_id,
        const std::vector<std::string>& input_ciphertexts,  // serialized CTs
        const std::string& output_ciphertext,                // serialized aggregated CT
        const std::vector<double>& plaintext_refs            // for ZKP generation
    );

    // Verify an aggregation record (called by control center or auditor)
    VerificationLogEntry verify_aggregation(const AggregationRecord& record);

    // --- Meter Reading Verification ---

    // Verify a batch of range proofs from meter readings
    VerificationLogEntry verify_meter_batch(
        uint32_t batch_id,
        const std::vector<RangeProof>& proofs,
        const std::vector<Commitment>& commitments,
        double min_kwh, double max_kwh
    );

    // --- Serialization ---
    std::string serialize_record(const AggregationRecord& record) const;
    AggregationRecord deserialize_record(const std::string& data) const;

    // --- Audit Log ---
    const std::vector<VerificationLogEntry>& audit_log() const { return audit_log_; }
    void export_audit_csv(const std::string& path) const;

private:
    ZKPEngine* zkp_ = nullptr;
    std::vector<VerificationLogEntry> audit_log_;

    std::vector<uint8_t> hash_ciphertexts(const std::vector<std::string>& cts) const;
    std::vector<uint8_t> hash_single(const std::string& ct) const;
    std::string iso_now() const;
};

} // namespace smartgrid
