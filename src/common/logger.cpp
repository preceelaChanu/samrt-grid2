#include "common/logger.h"
#include <filesystem>

namespace smartgrid {

Logger& Logger::instance() {
    static Logger inst;
    return inst;
}

void Logger::init(const std::string& file_path, LogLevel level, bool console) {
    std::lock_guard<std::mutex> lock(mtx_);
    level_ = level;
    console_ = console;
    if (!file_path.empty()) {
        std::filesystem::create_directories(std::filesystem::path(file_path).parent_path());
        file_.open(file_path, std::ios::app);
    }
}

void Logger::log(LogLevel level, const std::string& component, const std::string& message) {
    if (level < level_) return;
    std::lock_guard<std::mutex> lock(mtx_);
    std::string line = timestamp() + " [" + level_str(level) + "] [" + component + "] " + message;
    if (console_) {
        std::cout << line << std::endl;
    }
    if (file_.is_open()) {
        file_ << line << std::endl;
    }
}

void Logger::debug(const std::string& component, const std::string& msg) { log(LogLevel::DEBUG, component, msg); }
void Logger::info(const std::string& component, const std::string& msg) { log(LogLevel::INFO, component, msg); }
void Logger::warn(const std::string& component, const std::string& msg) { log(LogLevel::WARN, component, msg); }
void Logger::error(const std::string& component, const std::string& msg) { log(LogLevel::ERROR, component, msg); }

LogLevel Logger::parse_level(const std::string& s) {
    if (s == "DEBUG") return LogLevel::DEBUG;
    if (s == "WARN") return LogLevel::WARN;
    if (s == "ERROR") return LogLevel::ERROR;
    return LogLevel::INFO;
}

std::string Logger::level_str(LogLevel l) const {
    switch (l) {
        case LogLevel::DEBUG: return "DEBUG";
        case LogLevel::INFO:  return "INFO ";
        case LogLevel::WARN:  return "WARN ";
        case LogLevel::ERROR: return "ERROR";
    }
    return "?????";
}

std::string Logger::timestamp() const {
    auto now = std::chrono::system_clock::now();
    auto t = std::chrono::system_clock::to_time_t(now);
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch()) % 1000;
    std::tm tm_buf;
    gmtime_r(&t, &tm_buf);
    std::ostringstream oss;
    oss << std::put_time(&tm_buf, "%Y-%m-%dT%H:%M:%S")
        << '.' << std::setfill('0') << std::setw(3) << ms.count() << "Z";
    return oss.str();
}

} // namespace smartgrid
