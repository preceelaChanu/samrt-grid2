#pragma once

#include "common/crypto_engine.h"
#include "common/zkp_engine.h"
#include <seal/seal.h>
#include <string>
#include <vector>
#include <cstdint>
#include <unordered_map>

namespace smartgrid {

// Time-of-Use tariff slots
enum class ToUSlot : uint8_t {
    OFF_PEAK   = 0,  // 00:00 - 07:00 (cheapest)
    MID_PEAK   = 1,  // 07:00 - 16:00, 19:00 - 23:00
    PEAK       = 2,  // 16:00 - 19:00 (most expensive)
    CRITICAL   = 3   // Dynamic: grid stress events
};

// Tariff rate structure
struct TariffRate {
    ToUSlot slot;
    double rate_per_kwh;  // pence per kWh
    std::string description;
};

// Encrypted bill line item
struct EncryptedBillItem {
    uint8_t time_slot;
    seal::Ciphertext encrypted_consumption;  // Encrypted kWh in this slot
    seal::Ciphertext encrypted_cost;         // Encrypted cost = consumption * rate
    // Plaintext refs for simulation verification
    double plaintext_consumption;
    double plaintext_cost;
};

// Complete encrypted bill for a meter
struct EncryptedBill {
    uint32_t meter_id;
    uint32_t billing_period_id;
    std::vector<EncryptedBillItem> line_items;
    seal::Ciphertext encrypted_total;         // Encrypted total cost
    BillingComplianceProof compliance_proof;   // ZKP that billing was correct
    double plaintext_total;                    // For simulation verification
    std::string timestamp;
};

// Billing summary (decrypted at control center)
struct BillingSummary {
    uint32_t billing_period_id;
    int total_meters;
    double total_revenue;
    double off_peak_total;
    double mid_peak_total;
    double peak_total;
    double critical_total;
    std::string timestamp;
};

// Time-of-Use Billing Engine
// Performs encrypted classification, dynamic pricing, and verifiable bill generation
class ToUBillingEngine {
public:
    ToUBillingEngine();

    // Initialize with crypto engine, ZKP engine, and tariff rates
    void init(CryptoEngine& crypto, ZKPEngine& zkp);

    // --- Tariff Configuration ---
    void set_tariff(ToUSlot slot, double rate_per_kwh, const std::string& description = "");
    double get_tariff(ToUSlot slot) const;
    const std::vector<TariffRate>& tariff_schedule() const { return tariff_schedule_; }

    // --- Time Slot Classification ---

    // Classify an hour (0-23) into a ToU slot
    ToUSlot classify_hour(int hour) const;

    // Encrypt a time-slot indicator vector (one-hot encoding for slot membership)
    std::vector<seal::Ciphertext> encrypt_slot_indicators(int hour);

    // --- Encrypted Billing ---

    // Compute encrypted bill for a single reading
    EncryptedBillItem compute_encrypted_bill_item(
        const seal::Ciphertext& encrypted_reading,
        int hour,
        double plaintext_ref = 0.0  // for simulation
    );

    // Accumulate a reading into a meter's billing period
    void accumulate_reading(uint32_t meter_id, const seal::Ciphertext& encrypted_reading,
                            int hour, double plaintext_ref = 0.0);

    // Generate a complete encrypted bill for a meter
    EncryptedBill generate_bill(uint32_t meter_id, uint32_t billing_period_id);

    // --- Batch Billing ---

    // Generate bills for all tracked meters
    std::vector<EncryptedBill> generate_all_bills(uint32_t billing_period_id);

    // Verify a generated bill's compliance proof
    bool verify_bill(const EncryptedBill& bill);

    // --- Summary & Export ---

    // Generate billing summary from decrypted bills (at control center)
    BillingSummary generate_summary(const std::vector<EncryptedBill>& bills, uint32_t period_id);

    void export_bills_csv(const std::vector<EncryptedBill>& bills, const std::string& path) const;
    void export_summary_csv(const BillingSummary& summary, const std::string& path) const;

    // Reset billing period
    void reset_period();

private:
    CryptoEngine* crypto_ = nullptr;
    ZKPEngine* zkp_ = nullptr;
    std::vector<TariffRate> tariff_schedule_;

    // Per-meter accumulated encrypted costs by slot
    struct MeterBillingState {
        std::unordered_map<uint8_t, std::vector<seal::Ciphertext>> slot_readings;
        std::unordered_map<uint8_t, std::vector<seal::Ciphertext>> slot_costs;
        // Plaintext references for simulation
        std::unordered_map<uint8_t, double> plaintext_consumption;
        std::unordered_map<uint8_t, double> plaintext_cost;
    };

    std::unordered_map<uint32_t, MeterBillingState> meter_states_;

    std::string iso_now() const;
};

} // namespace smartgrid
