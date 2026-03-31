#pragma once

#include <vector>
#include <string>
#include <random>
#include <ctime>

namespace smartgrid {

enum class HouseholdType {
    LOW_CONSUMER,
    MEDIUM_CONSUMER,
    HIGH_CONSUMER,
    VARIABLE_BEHAVIOR
};

struct HouseholdProfile {
    HouseholdType type;
    bool is_variable;
    double base_kwh;
    double variance;
};

class EnergySimulator {
public:
    EnergySimulator();

    // Initialize from config
    void init_from_config();

    // Generate a household profile based on configured probabilities
    HouseholdProfile generate_profile();

    // Generate a single reading for a profile at a given time
    double generate_reading(const HouseholdProfile& profile);

    // Get current simulated hour (0-23)
    int current_hour() const;

    // Get day of week factor (0=Sun..6=Sat)
    double day_of_week_factor() const;

    // Hourly demand curve (normalized)
    double hourly_factor(int hour) const;

private:
    std::mt19937 rng_;

    // Config values
    double min_kwh_ = 0.0;
    double max_kwh_ = 2.112;
    double mean_kwh_ = 0.213;
    double zero_prob_ = 0.02;
    int peak_hour_ = 19;
    int low_hour_ = 4;

    struct TypeConfig {
        double probability;
        double base_kwh;
        double variance;
    };
    TypeConfig low_config_{0.954, 0.10, 0.05};
    TypeConfig medium_config_{0.046, 0.40, 0.15};
    TypeConfig high_config_{0.0, 0.80, 0.30};
    double variable_overlap_ = 0.51;
    double variable_variance_mult_ = 2.0;
};

} // namespace smartgrid
