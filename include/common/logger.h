#pragma once

#include <string>
#include <fstream>
#include <mutex>
#include <iostream>
#include <chrono>
#include <iomanip>
#include <sstream>

namespace smartgrid {

enum class LogLevel { DEBUG, INFO, WARN, ERROR };

class Logger {
public:
    static Logger& instance();

    void init(const std::string& file_path, LogLevel level, bool console);
    void log(LogLevel level, const std::string& component, const std::string& message);
    void debug(const std::string& component, const std::string& msg);
    void info(const std::string& component, const std::string& msg);
    void warn(const std::string& component, const std::string& msg);
    void error(const std::string& component, const std::string& msg);

    static LogLevel parse_level(const std::string& s);

private:
    Logger() = default;
    std::ofstream file_;
    LogLevel level_ = LogLevel::INFO;
    bool console_ = true;
    std::mutex mtx_;

    std::string level_str(LogLevel l) const;
    std::string timestamp() const;
};

#define LOG_DEBUG(comp, msg) smartgrid::Logger::instance().debug(comp, msg)
#define LOG_INFO(comp, msg) smartgrid::Logger::instance().info(comp, msg)
#define LOG_WARN(comp, msg) smartgrid::Logger::instance().warn(comp, msg)
#define LOG_ERROR(comp, msg) smartgrid::Logger::instance().error(comp, msg)

} // namespace smartgrid
