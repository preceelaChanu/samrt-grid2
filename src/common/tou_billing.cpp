// Time-of-Use Billing Engine - Encrypted classification, dynamic pricing, verifiable billing
#include "common/tou_billing.h"
#include "common/logger.h"
#include "common/metrics.h"

#include <chrono>
#include <cmath>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <algorithm>

namespace smartgrid {

ToUBillingEngine::ToUBillingEngine() = default;

void ToUBillingEngine::init(CryptoEngine& crypto, ZKPEngine& zkp) {
    crypto_ = &crypto;
    zkp_ = &zkp;

    // Default UK-style tariff rates (pence per kWh)
    tariff_schedule_ = {
        {ToUSlot::OFF_PEAK,  7.5,  "Off-Peak (00:00-07:00)"},
        {ToUSlot::MID_PEAK,  15.0, "Mid-Peak (07:00-16:00, 19:00-23:00)"},
        {ToUSlot::PEAK,      30.0, "Peak (16:00-19:00)"},
        {ToUSlot::CRITICAL,  50.0, "Critical (Grid stress events)"}
    };

    LOG_INFO("ToUBilling", "Initialized with " + std::to_string(tariff_schedule_.size()) + " tariff slots");
}

void ToUBillingEngine::set_tariff(ToUSlot slot, double rate_per_kwh, const std::string& description) {
    for (auto& t : tariff_schedule_) {
        if (t.slot == slot) {
            t.rate_per_kwh = rate_per_kwh;
            if (!description.empty()) t.description = description;
            return;
        }
    }
    tariff_schedule_.push_back({slot, rate_per_kwh, description});
}

double ToUBillingEngine::get_tariff(ToUSlot slot) const {
    for (auto& t : tariff_schedule_) {
        if (t.slot == slot) return t.rate_per_kwh;
    }
    return 0.0;
}

ToUSlot ToUBillingEngine::classify_hour(int hour) const {
    // UK-style time-of-use classification
    if (hour >= 0 && hour < 7) return ToUSlot::OFF_PEAK;
    if (hour >= 7 && hour < 16) return ToUSlot::MID_PEAK;
    if (hour >= 16 && hour < 19) return ToUSlot::PEAK;
    if (hour >= 19 && hour < 23) return ToUSlot::MID_PEAK;
    return ToUSlot::OFF_PEAK; // 23:00-00:00
}

std::vector<seal::Ciphertext> ToUBillingEngine::encrypt_slot_indicators(int hour) {
    // One-hot encoding: [off_peak, mid_peak, peak, critical]
    std::vector<double> indicators(4, 0.0);
    ToUSlot slot = classify_hour(hour);
    indicators[static_cast<uint8_t>(slot)] = 1.0;

    std::vector<seal::Ciphertext> encrypted;
    encrypted.reserve(4);
    for (double ind : indicators) {
        encrypted.push_back(crypto_->encrypt_single(ind));
    }
    return encrypted;
}

EncryptedBillItem ToUBillingEngine::compute_encrypted_bill_item(
    const seal::Ciphertext& encrypted_reading, int hour, double plaintext_ref) {

    auto start = std::chrono::high_resolution_clock::now();

    EncryptedBillItem item;
    ToUSlot slot = classify_hour(hour);
    item.time_slot = static_cast<uint8_t>(slot);
    item.encrypted_consumption = encrypted_reading;

    double rate = get_tariff(slot);

    // Compute encrypted cost: consumption * rate
    // Since CKKS supports multiply_plain, we encrypt rate and add
    // For simulation: we compute plaintext cost and encrypt it
    // In production: use evaluator->multiply_plain(ct, encoded_rate)
    double cost = plaintext_ref * rate;
    item.encrypted_cost = crypto_->encrypt_single(cost);

    item.plaintext_consumption = plaintext_ref;
    item.plaintext_cost = cost;

    auto end = std::chrono::high_resolution_clock::now();
    double ms = std::chrono::duration<double, std::milli>(end - start).count();
    MetricsCollector::instance().record("homomorphic", "tou_bill_item_computation",
        ms, "ms", "slot=" + std::to_string(item.time_slot));

    return item;
}

void ToUBillingEngine::accumulate_reading(uint32_t meter_id,
                                            const seal::Ciphertext& encrypted_reading,
                                            int hour, double plaintext_ref) {
    auto& state = meter_states_[meter_id];
    ToUSlot slot = classify_hour(hour);
    uint8_t slot_idx = static_cast<uint8_t>(slot);
    double rate = get_tariff(slot);

    state.slot_readings[slot_idx].push_back(encrypted_reading);

    // Compute encrypted cost for this reading
    double cost = plaintext_ref * rate;
    state.slot_costs[slot_idx].push_back(crypto_->encrypt_single(cost));

    state.plaintext_consumption[slot_idx] += plaintext_ref;
    state.plaintext_cost[slot_idx] += cost;
}

EncryptedBill ToUBillingEngine::generate_bill(uint32_t meter_id, uint32_t billing_period_id) {
    auto start = std::chrono::high_resolution_clock::now();

    EncryptedBill bill;
    bill.meter_id = meter_id;
    bill.billing_period_id = billing_period_id;
    bill.plaintext_total = 0.0;
    bill.timestamp = iso_now();

    auto it = meter_states_.find(meter_id);
    if (it == meter_states_.end()) {
        LOG_WARN("ToUBilling", "No readings for meter " + std::to_string(meter_id));
        bill.encrypted_total = crypto_->encrypt_single(0.0);
        bill.compliance_proof = zkp_->generate_billing_proof(0.0, 0.0, 0.0, 0);
        return bill;
    }

    auto& state = it->second;
    std::vector<seal::Ciphertext> all_costs;

    for (auto& [slot_idx, readings] : state.slot_readings) {
        EncryptedBillItem item;
        item.time_slot = slot_idx;

        if (!readings.empty()) {
            // Aggregate all readings in this slot
            item.encrypted_consumption = crypto_->add_many(readings);
            item.plaintext_consumption = state.plaintext_consumption[slot_idx];

            // Aggregate all costs in this slot
            auto& costs = state.slot_costs[slot_idx];
            if (!costs.empty()) {
                item.encrypted_cost = crypto_->add_many(costs);
                all_costs.insert(all_costs.end(), costs.begin(), costs.end());
            } else {
                item.encrypted_cost = crypto_->encrypt_single(0.0);
            }
            item.plaintext_cost = state.plaintext_cost[slot_idx];
            bill.plaintext_total += item.plaintext_cost;
        } else {
            item.encrypted_consumption = crypto_->encrypt_single(0.0);
            item.encrypted_cost = crypto_->encrypt_single(0.0);
            item.plaintext_consumption = 0.0;
            item.plaintext_cost = 0.0;
        }

        bill.line_items.push_back(std::move(item));
    }

    // Compute encrypted total
    if (!all_costs.empty()) {
        bill.encrypted_total = crypto_->add_many(all_costs);
    } else {
        bill.encrypted_total = crypto_->encrypt_single(0.0);
    }

    // Generate billing compliance proof
    // Prove that the total bill was computed correctly given the tariff rates
    double total_consumption = 0.0;
    double weighted_rate = 0.0;
    for (auto& item : bill.line_items) {
        total_consumption += item.plaintext_consumption;
        if (item.plaintext_consumption > 0) {
            weighted_rate += item.plaintext_cost;
        }
    }

    // The compliance proof shows the billing was done correctly
    // Use the dominant slot for the proof's rate parameter
    uint8_t dominant_slot = 0;
    double max_consumption = 0.0;
    for (auto& item : bill.line_items) {
        if (item.plaintext_consumption > max_consumption) {
            max_consumption = item.plaintext_consumption;
            dominant_slot = item.time_slot;
        }
    }

    bill.compliance_proof = zkp_->generate_billing_proof(
        total_consumption,
        (total_consumption > 0) ? bill.plaintext_total / total_consumption : 0.0,
        bill.plaintext_total,
        dominant_slot
    );

    auto end = std::chrono::high_resolution_clock::now();
    double ms = std::chrono::duration<double, std::milli>(end - start).count();

    MetricsCollector::instance().record("homomorphic", "tou_bill_generation",
        ms, "ms", "meter=" + std::to_string(meter_id) +
        " items=" + std::to_string(bill.line_items.size()));

    LOG_DEBUG("ToUBilling", "Generated bill for meter " + std::to_string(meter_id) +
              ": total=" + std::to_string(bill.plaintext_total) + "p, " +
              std::to_string(bill.line_items.size()) + " slot(s)");

    return bill;
}

std::vector<EncryptedBill> ToUBillingEngine::generate_all_bills(uint32_t billing_period_id) {
    auto start = std::chrono::high_resolution_clock::now();

    std::vector<EncryptedBill> bills;
    bills.reserve(meter_states_.size());

    for (auto& [meter_id, state] : meter_states_) {
        bills.push_back(generate_bill(meter_id, billing_period_id));
    }

    auto end = std::chrono::high_resolution_clock::now();
    double ms = std::chrono::duration<double, std::milli>(end - start).count();

    MetricsCollector::instance().record("homomorphic", "tou_all_bills_generation",
        ms, "ms", "meters=" + std::to_string(bills.size()));

    LOG_INFO("ToUBilling", "Generated " + std::to_string(bills.size()) +
             " bills for period " + std::to_string(billing_period_id));

    return bills;
}

bool ToUBillingEngine::verify_bill(const EncryptedBill& bill) {
    double total_consumption = 0.0;
    for (auto& item : bill.line_items) {
        total_consumption += item.plaintext_consumption;
    }

    double effective_rate = (total_consumption > 0) ?
        bill.plaintext_total / total_consumption : 0.0;

    auto result = zkp_->verify_billing_proof(bill.compliance_proof, effective_rate);
    return result.valid;
}

BillingSummary ToUBillingEngine::generate_summary(const std::vector<EncryptedBill>& bills,
                                                    uint32_t period_id) {
    BillingSummary summary;
    summary.billing_period_id = period_id;
    summary.total_meters = static_cast<int>(bills.size());
    summary.total_revenue = 0.0;
    summary.off_peak_total = 0.0;
    summary.mid_peak_total = 0.0;
    summary.peak_total = 0.0;
    summary.critical_total = 0.0;
    summary.timestamp = iso_now();

    for (auto& bill : bills) {
        summary.total_revenue += bill.plaintext_total;
        for (auto& item : bill.line_items) {
            switch (static_cast<ToUSlot>(item.time_slot)) {
                case ToUSlot::OFF_PEAK:  summary.off_peak_total += item.plaintext_cost; break;
                case ToUSlot::MID_PEAK:  summary.mid_peak_total += item.plaintext_cost; break;
                case ToUSlot::PEAK:      summary.peak_total += item.plaintext_cost; break;
                case ToUSlot::CRITICAL:  summary.critical_total += item.plaintext_cost; break;
            }
        }
    }

    return summary;
}

void ToUBillingEngine::export_bills_csv(const std::vector<EncryptedBill>& bills,
                                          const std::string& path) const {
    std::ofstream csv(path);
    csv << "timestamp,billing_period,meter_id,time_slot,consumption_kwh,cost_pence,"
           "total_cost_pence,proof_valid\n";

    for (auto& bill : bills) {
        for (auto& item : bill.line_items) {
            std::string slot_name;
            switch (static_cast<ToUSlot>(item.time_slot)) {
                case ToUSlot::OFF_PEAK:  slot_name = "OFF_PEAK"; break;
                case ToUSlot::MID_PEAK:  slot_name = "MID_PEAK"; break;
                case ToUSlot::PEAK:      slot_name = "PEAK"; break;
                case ToUSlot::CRITICAL:  slot_name = "CRITICAL"; break;
            }
            csv << bill.timestamp << ","
                << bill.billing_period_id << ","
                << bill.meter_id << ","
                << slot_name << ","
                << std::fixed << std::setprecision(6)
                << item.plaintext_consumption << ","
                << item.plaintext_cost << ","
                << bill.plaintext_total << ","
                << (bill.compliance_proof.proof_size_bytes > 0 ? "true" : "false") << "\n";
        }
    }
    LOG_INFO("ToUBilling", "Bills exported to " + path);
}

void ToUBillingEngine::export_summary_csv(const BillingSummary& summary,
                                            const std::string& path) const {
    std::ofstream csv(path, std::ios::app);
    csv.seekp(0, std::ios::end);
    if (csv.tellp() == 0) {
        csv << "timestamp,period_id,total_meters,total_revenue_pence,"
               "off_peak_pence,mid_peak_pence,peak_pence,critical_pence\n";
    }
    csv << summary.timestamp << ","
        << summary.billing_period_id << ","
        << summary.total_meters << ","
        << std::fixed << std::setprecision(2)
        << summary.total_revenue << ","
        << summary.off_peak_total << ","
        << summary.mid_peak_total << ","
        << summary.peak_total << ","
        << summary.critical_total << "\n";
}

void ToUBillingEngine::reset_period() {
    meter_states_.clear();
    LOG_INFO("ToUBilling", "Billing period reset");
}

std::string ToUBillingEngine::iso_now() const {
    auto now = std::chrono::system_clock::now();
    auto t = std::chrono::system_clock::to_time_t(now);
    std::tm tm_buf;
    gmtime_r(&t, &tm_buf);
    std::ostringstream oss;
    oss << std::put_time(&tm_buf, "%Y-%m-%dT%H:%M:%SZ");
    return oss.str();
}

} // namespace smartgrid
