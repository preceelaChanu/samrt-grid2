#include "common/energy_simulator.h"
#include "common/config.h"
#include <cmath>
#include <algorithm>

namespace smartgrid {

EnergySimulator::EnergySimulator()
    : rng_(std::random_device{}()) {}

void EnergySimulator::init_from_config() {
    auto& cfg = Config::instance().get();
    auto& sm = cfg["smart_meters"];
    auto& cons = sm["consumption"];

    min_kwh_ = cons["min_kwh"].get<double>();
    max_kwh_ = cons["max_kwh"].get<double>();
    mean_kwh_ = cons["mean_kwh"].get<double>();
    zero_prob_ = cons["zero_reading_probability"].get<double>();
    peak_hour_ = cons["peak_hour"].get<int>();
    low_hour_ = cons["low_hour"].get<int>();

    auto& types = sm["household_types"];
    low_config_ = {
        types["LOW_CONSUMER"]["probability"].get<double>(),
        types["LOW_CONSUMER"]["base_kwh"].get<double>(),
        types["LOW_CONSUMER"]["variance"].get<double>()
    };
    medium_config_ = {
        types["MEDIUM_CONSUMER"]["probability"].get<double>(),
        types["MEDIUM_CONSUMER"]["base_kwh"].get<double>(),
        types["MEDIUM_CONSUMER"]["variance"].get<double>()
    };
    high_config_ = {
        types["HIGH_CONSUMER"]["probability"].get<double>(),
        types["HIGH_CONSUMER"]["base_kwh"].get<double>(),
        types["HIGH_CONSUMER"]["variance"].get<double>()
    };
    variable_overlap_ = types["VARIABLE_BEHAVIOR"]["overlap_probability"].get<double>();
    variable_variance_mult_ = types["VARIABLE_BEHAVIOR"]["variance_multiplier"].get<double>();
}

HouseholdProfile EnergySimulator::generate_profile() {
    std::uniform_real_distribution<double> dist(0.0, 1.0);
    double r = dist(rng_);

    HouseholdProfile profile;
    if (r < low_config_.probability) {
        profile.type = HouseholdType::LOW_CONSUMER;
        profile.base_kwh = low_config_.base_kwh;
        profile.variance = low_config_.variance;
    } else if (r < low_config_.probability + medium_config_.probability) {
        profile.type = HouseholdType::MEDIUM_CONSUMER;
        profile.base_kwh = medium_config_.base_kwh;
        profile.variance = medium_config_.variance;
    } else {
        profile.type = HouseholdType::HIGH_CONSUMER;
        profile.base_kwh = high_config_.base_kwh;
        profile.variance = high_config_.variance;
    }

    // Variable behavior overlap
    profile.is_variable = dist(rng_) < variable_overlap_;
    if (profile.is_variable) {
        profile.variance *= variable_variance_mult_;
    }

    return profile;
}

double EnergySimulator::generate_reading(const HouseholdProfile& profile) {
    std::uniform_real_distribution<double> uniform(0.0, 1.0);

    // Zero reading check
    if (uniform(rng_) < zero_prob_) {
        return 0.0;
    }

    int hour = current_hour();
    double h_factor = hourly_factor(hour);
    double d_factor = day_of_week_factor();

    // Base reading with temporal factors
    double base = profile.base_kwh * h_factor * d_factor;

    // Add gaussian noise
    std::normal_distribution<double> noise(0.0, profile.variance);
    double reading = base + noise(rng_);

    // Clamp to valid range
    reading = std::clamp(reading, min_kwh_, max_kwh_);

    // Round to 3 decimal places
    reading = std::round(reading * 1000.0) / 1000.0;

    return reading;
}

int EnergySimulator::current_hour() const {
    auto now = std::time(nullptr);
    std::tm tm_buf;
    localtime_r(&now, &tm_buf);
    return tm_buf.tm_hour;
}

double EnergySimulator::day_of_week_factor() const {
    auto now = std::time(nullptr);
    std::tm tm_buf;
    localtime_r(&now, &tm_buf);
    int dow = tm_buf.tm_wday; // 0=Sun, 6=Sat

    // Weekend has slightly higher consumption
    if (dow == 0 || dow == 6) return 1.15;
    // Friday slightly higher
    if (dow == 5) return 1.05;
    return 1.0;
}

double EnergySimulator::hourly_factor(int hour) const {
    // Realistic UK demand curve
    // Normalized so peak=1.0 at peak_hour_, trough at low_hour_
    static const double curve[24] = {
        0.30, 0.25, 0.22, 0.20, 0.18, 0.20, 0.25, 0.45,  // 00-07
        0.55, 0.50, 0.48, 0.50, 0.55, 0.52, 0.50, 0.55,  // 08-15
        0.65, 0.80, 0.92, 1.00, 0.95, 0.85, 0.65, 0.45   // 16-23
    };

    // Adjust so peak aligns with configured peak_hour
    int shift = peak_hour_ - 19; // default curve peaks at 19
    int idx = ((hour - shift) % 24 + 24) % 24;
    return curve[idx];
}

} // namespace smartgrid
