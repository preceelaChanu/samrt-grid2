// Verifiable Computation - Ensures honest behavior of aggregators and intermediaries
#include "common/verifiable_computation.h"
#include "common/logger.h"
#include "common/metrics.h"

#include <openssl/sha.h>
#include <chrono>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <cstring>

namespace smartgrid {

VerifiableComputation::VerifiableComputation() = default;

void VerifiableComputation::init(ZKPEngine& zkp) {
    zkp_ = &zkp;
    LOG_INFO("VerifiableComputation", "Initialized");
}

AggregationRecord VerifiableComputation::record_aggregation(
    uint32_t batch_id,
    const std::vector<std::string>& input_ciphertexts,
    const std::string& output_ciphertext,
    const std::vector<double>& plaintext_refs) {

    auto start = std::chrono::high_resolution_clock::now();

    AggregationRecord record;
    record.batch_id = batch_id;
    record.num_inputs = static_cast<uint32_t>(input_ciphertexts.size());
    record.inputs_hash = hash_ciphertexts(input_ciphertexts);
    record.output_hash = hash_single(output_ciphertext);
    record.timestamp = iso_now();

    // Generate ZKP for aggregation correctness
    double output_sum = 0.0;
    for (double v : plaintext_refs) output_sum += v;

    record.zkp_proof = zkp_->generate_aggregation_proof(plaintext_refs, output_sum);

    auto end = std::chrono::high_resolution_clock::now();
    double ms = std::chrono::duration<double, std::milli>(end - start).count();
    MetricsCollector::instance().record("security", "verifiable_aggregation_record",
        ms, "ms", "batch=" + std::to_string(batch_id) + " inputs=" + std::to_string(input_ciphertexts.size()));

    LOG_DEBUG("VerifiableComputation", "Recorded aggregation batch " + std::to_string(batch_id) +
              ": " + std::to_string(input_ciphertexts.size()) + " inputs");

    return record;
}

VerificationLogEntry VerifiableComputation::verify_aggregation(const AggregationRecord& record) {
    auto start = std::chrono::high_resolution_clock::now();

    VerificationLogEntry entry;
    entry.batch_id = record.batch_id;
    entry.invalid_proof_count = 0;
    entry.timestamp = iso_now();

    // Verify the aggregation ZKP
    auto result = zkp_->verify_aggregation_proof(record.zkp_proof);
    entry.aggregation_valid = result.valid;
    entry.all_range_proofs_valid = true; // Set separately if range proofs provided

    if (!result.valid) {
        entry.invalid_proof_count++;
        LOG_WARN("VerifiableComputation", "Aggregation proof INVALID for batch " +
                 std::to_string(record.batch_id) + ": " + result.reason);
    } else {
        LOG_DEBUG("VerifiableComputation", "Aggregation proof valid for batch " +
                  std::to_string(record.batch_id));
    }

    auto end = std::chrono::high_resolution_clock::now();
    entry.total_verification_time_ms = std::chrono::duration<double, std::milli>(end - start).count();

    audit_log_.push_back(entry);

    MetricsCollector::instance().record("security", "verifiable_aggregation_check",
        entry.total_verification_time_ms, "ms",
        "batch=" + std::to_string(record.batch_id) +
        " valid=" + std::string(entry.aggregation_valid ? "true" : "false"));

    return entry;
}

VerificationLogEntry VerifiableComputation::verify_meter_batch(
    uint32_t batch_id,
    const std::vector<RangeProof>& proofs,
    const std::vector<Commitment>& commitments,
    double min_kwh, double max_kwh) {

    auto start = std::chrono::high_resolution_clock::now();

    VerificationLogEntry entry;
    entry.batch_id = batch_id;
    entry.aggregation_valid = true; // Not checking aggregation here
    entry.all_range_proofs_valid = true;
    entry.invalid_proof_count = 0;
    entry.timestamp = iso_now();

    for (size_t i = 0; i < proofs.size() && i < commitments.size(); i++) {
        auto result = zkp_->verify_range_proof(proofs[i], commitments[i]);
        if (!result.valid) {
            entry.all_range_proofs_valid = false;
            entry.invalid_proof_count++;
            LOG_WARN("VerifiableComputation", "Range proof " + std::to_string(i) +
                     " INVALID in batch " + std::to_string(batch_id) + ": " + result.reason);
        }
    }

    auto end = std::chrono::high_resolution_clock::now();
    entry.total_verification_time_ms = std::chrono::duration<double, std::milli>(end - start).count();

    audit_log_.push_back(entry);

    MetricsCollector::instance().record("security", "verifiable_meter_batch_check",
        entry.total_verification_time_ms, "ms",
        "batch=" + std::to_string(batch_id) +
        " proofs=" + std::to_string(proofs.size()) +
        " invalid=" + std::to_string(entry.invalid_proof_count));

    return entry;
}

// --- Serialization ---

std::string VerifiableComputation::serialize_record(const AggregationRecord& record) const {
    std::string result;
    result.append(reinterpret_cast<const char*>(&record.batch_id), 4);
    result.append(reinterpret_cast<const char*>(&record.num_inputs), 4);

    // Inputs hash
    uint32_t ih_sz = static_cast<uint32_t>(record.inputs_hash.size());
    result.append(reinterpret_cast<const char*>(&ih_sz), 4);
    result.append(reinterpret_cast<const char*>(record.inputs_hash.data()), ih_sz);

    // Output hash
    uint32_t oh_sz = static_cast<uint32_t>(record.output_hash.size());
    result.append(reinterpret_cast<const char*>(&oh_sz), 4);
    result.append(reinterpret_cast<const char*>(record.output_hash.data()), oh_sz);

    // ZKP proof
    std::string zkp_data = zkp_->serialize_aggregation_proof(record.zkp_proof);
    uint32_t zd_sz = static_cast<uint32_t>(zkp_data.size());
    result.append(reinterpret_cast<const char*>(&zd_sz), 4);
    result += zkp_data;

    // Timestamp
    uint32_t ts_sz = static_cast<uint32_t>(record.timestamp.size());
    result.append(reinterpret_cast<const char*>(&ts_sz), 4);
    result += record.timestamp;

    return result;
}

AggregationRecord VerifiableComputation::deserialize_record(const std::string& data) const {
    AggregationRecord record;
    size_t offset = 0;

    std::memcpy(&record.batch_id, data.data() + offset, 4); offset += 4;
    std::memcpy(&record.num_inputs, data.data() + offset, 4); offset += 4;

    auto read_vec = [&](std::vector<uint8_t>& vec) {
        uint32_t sz;
        std::memcpy(&sz, data.data() + offset, 4); offset += 4;
        vec.resize(sz);
        std::memcpy(vec.data(), data.data() + offset, sz); offset += sz;
    };

    read_vec(record.inputs_hash);
    read_vec(record.output_hash);

    // ZKP
    uint32_t zd_sz;
    std::memcpy(&zd_sz, data.data() + offset, 4); offset += 4;
    std::string zkp_data = data.substr(offset, zd_sz); offset += zd_sz;
    record.zkp_proof = zkp_->deserialize_aggregation_proof(zkp_data);

    // Timestamp
    uint32_t ts_sz;
    std::memcpy(&ts_sz, data.data() + offset, 4); offset += 4;
    record.timestamp = data.substr(offset, ts_sz);

    return record;
}

void VerifiableComputation::export_audit_csv(const std::string& path) const {
    std::ofstream csv(path);
    csv << "timestamp,batch_id,aggregation_valid,all_range_proofs_valid,"
           "invalid_proof_count,verification_time_ms\n";
    for (auto& e : audit_log_) {
        csv << e.timestamp << ","
            << e.batch_id << ","
            << (e.aggregation_valid ? "true" : "false") << ","
            << (e.all_range_proofs_valid ? "true" : "false") << ","
            << e.invalid_proof_count << ","
            << std::fixed << std::setprecision(3) << e.total_verification_time_ms << "\n";
    }
    LOG_INFO("VerifiableComputation", "Audit log exported to " + path);
}

// --- Internal ---

std::vector<uint8_t> VerifiableComputation::hash_ciphertexts(const std::vector<std::string>& cts) const {
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    for (auto& ct : cts) {
        SHA256_Update(&ctx, ct.data(), ct.size());
    }
    std::vector<uint8_t> digest(SHA256_DIGEST_LENGTH);
    SHA256_Final(digest.data(), &ctx);
    return digest;
}

std::vector<uint8_t> VerifiableComputation::hash_single(const std::string& ct) const {
    std::vector<uint8_t> digest(SHA256_DIGEST_LENGTH);
    SHA256(reinterpret_cast<const unsigned char*>(ct.data()), ct.size(), digest.data());
    return digest;
}

std::string VerifiableComputation::iso_now() const {
    auto now = std::chrono::system_clock::now();
    auto t = std::chrono::system_clock::to_time_t(now);
    std::tm tm_buf;
    gmtime_r(&t, &tm_buf);
    std::ostringstream oss;
    oss << std::put_time(&tm_buf, "%Y-%m-%dT%H:%M:%SZ");
    return oss.str();
}

} // namespace smartgrid
