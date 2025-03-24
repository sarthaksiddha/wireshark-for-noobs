#include "logging.h"

namespace wireshark_mcp {

std::mutex Log::log_mutex_;
std::ofstream Log::log_file_;
LogLevel Log::min_level_ = LogLevel::INFO;
bool Log::initialized_ = false;

void Log::initialize(const std::string& log_file, LogLevel min_level) {
    std::lock_guard<std::mutex> lock(log_mutex_);
    
    // Close any existing file
    if (log_file_.is_open()) {
        log_file_.close();
    }
    
    // Open new log file
    log_file_.open(log_file, std::ios::out | std::ios::app);
    min_level_ = min_level;
    
    initialized_ = true;
    
    // Log initialization
    info("Logging initialized with minimum level: {}", levelToString(min_level));
}

std::string Log::levelToString(LogLevel level) {
    switch (level) {
        case LogLevel::DEBUG:
            return "DEBUG";
        case LogLevel::INFO:
            return "INFO";
        case LogLevel::WARNING:
            return "WARNING";
        case LogLevel::ERROR:
            return "ERROR";
        case LogLevel::CRITICAL:
            return "CRITICAL";
        default:
            return "UNKNOWN";
    }
}

} // namespace wireshark_mcp