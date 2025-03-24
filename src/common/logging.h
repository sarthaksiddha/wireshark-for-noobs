#ifndef WIRESHARK_MCP_LOGGING_H
#define WIRESHARK_MCP_LOGGING_H

#include <string>
#include <iostream>
#include <fstream>
#include <chrono>
#include <mutex>
#include <sstream>

namespace wireshark_mcp {

enum class LogLevel {
    DEBUG,
    INFO,
    WARNING,
    ERROR,
    CRITICAL
};

class Log {
public:
    static void initialize(const std::string& log_file, LogLevel min_level = LogLevel::INFO);
    
    template<typename... Args>
    static void debug(const std::string& format, Args... args) {
        log(LogLevel::DEBUG, format, args...);
    }
    
    template<typename... Args>
    static void info(const std::string& format, Args... args) {
        log(LogLevel::INFO, format, args...);
    }
    
    template<typename... Args>
    static void warning(const std::string& format, Args... args) {
        log(LogLevel::WARNING, format, args...);
    }
    
    template<typename... Args>
    static void error(const std::string& format, Args... args) {
        log(LogLevel::ERROR, format, args...);
    }
    
    template<typename... Args>
    static void critical(const std::string& format, Args... args) {
        log(LogLevel::CRITICAL, format, args...);
    }

private:
    static std::mutex log_mutex_;
    static std::ofstream log_file_;
    static LogLevel min_level_;
    static bool initialized_;
    
    template<typename... Args>
    static void log(LogLevel level, const std::string& format, Args... args) {
        if (level < min_level_ || !initialized_) return;
        
        std::lock_guard<std::mutex> lock(log_mutex_);
        
        // Get current time
        auto now = std::chrono::system_clock::now();
        auto time = std::chrono::system_clock::to_time_t(now);
        
        std::stringstream message;
        message << std::ctime(&time);
        message << " [" << levelToString(level) << "] ";
        message << formatString(format, args...);
        
        // Output to console and file
        std::cout << message.str() << std::endl;
        if (log_file_.is_open()) {
            log_file_ << message.str() << std::endl;
        }
    }
    
    static std::string levelToString(LogLevel level);
    
    template<typename T, typename... Args>
    static std::string formatString(const std::string& format, T value, Args... args) {
        size_t pos = format.find("{}");
        if (pos == std::string::npos) return format;
        
        std::stringstream ss;
        ss << value;
        
        return format.substr(0, pos) + ss.str() + 
               formatString(format.substr(pos + 2), args...);
    }
    
    static std::string formatString(const std::string& format) {
        return format;
    }
};

} // namespace wireshark_mcp

#endif // WIRESHARK_MCP_LOGGING_H