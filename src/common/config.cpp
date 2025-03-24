#include "config.h"
#include "logging.h"
#include <fstream>
#include <sstream>

namespace wireshark_mcp {

Config::Config() {
    // Set default values
    config_data_["application.name"] = "Wireshark MCP";
    config_data_["application.version"] = "1.0.0";
    config_data_["capture.buffer_size"] = "1048576"; // 1MB
    config_data_["capture.promiscuous_mode"] = "true";
    config_data_["ui.dark_mode"] = "false";
    config_data_["security.encrypt_captures"] = "true";
    config_data_["logging.level"] = "INFO";
    config_data_["logging.file"] = "wireshark_mcp.log";
}

Config::~Config() {
    // Save configuration if it was loaded from a file
    if (!loaded_file_.empty()) {
        save(loaded_file_);
    }
}

Config& Config::getInstance() {
    static Config instance;
    return instance;
}

bool Config::load(const std::string& config_file) {
    std::lock_guard<std::mutex> lock(config_mutex_);
    
    std::ifstream file(config_file);
    if (!file.is_open()) {
        Log::error("Failed to open config file: {}", config_file);
        return false;
    }
    
    // Clear existing configuration
    config_data_.clear();
    
    std::string line;
    while (std::getline(file, line)) {
        // Skip comments and empty lines
        if (line.empty() || line[0] == '#') {
            continue;
        }
        
        // Parse key=value pairs
        size_t pos = line.find('=');
        if (pos != std::string::npos) {
            std::string key = line.substr(0, pos);
            std::string value = line.substr(pos + 1);
            
            // Trim whitespace
            key.erase(0, key.find_first_not_of(" \t"));
            key.erase(key.find_last_not_of(" \t") + 1);
            value.erase(0, value.find_first_not_of(" \t"));
            value.erase(value.find_last_not_of(" \t") + 1);
            
            config_data_[key] = value;
        }
    }
    
    loaded_file_ = config_file;
    Log::info("Loaded configuration from: {}", config_file);
    return true;
}

bool Config::save(const std::string& config_file) {
    std::lock_guard<std::mutex> lock(config_mutex_);
    
    std::string file_to_save = config_file.empty() ? loaded_file_ : config_file;
    if (file_to_save.empty()) {
        Log::error("No file specified for saving configuration");
        return false;
    }
    
    std::ofstream file(file_to_save);
    if (!file.is_open()) {
        Log::error("Failed to open config file for writing: {}", file_to_save);
        return false;
    }
    
    file << "# Wireshark MCP Configuration\n";
    file << "# Generated on " << __DATE__ << " " << __TIME__ << "\n\n";
    
    for (const auto& [key, value] : config_data_) {
        file << key << " = " << value << "\n";
    }
    
    Log::info("Saved configuration to: {}", file_to_save);
    return true;
}

bool Config::hasKey(const std::string& key) const {
    std::lock_guard<std::mutex> lock(config_mutex_);
    return config_data_.find(key) != config_data_.end();
}

std::vector<std::string> Config::getKeys() const {
    std::lock_guard<std::mutex> lock(config_mutex_);
    std::vector<std::string> keys;
    keys.reserve(config_data_.size());
    
    for (const auto& [key, _] : config_data_) {
        keys.push_back(key);
    }
    
    return keys;
}

// Template specializations
template<>
std::string Config::get<std::string>(const std::string& key, const std::string& default_value) const {
    std::lock_guard<std::mutex> lock(config_mutex_);
    auto it = config_data_.find(key);
    return (it != config_data_.end()) ? it->second : default_value;
}

template<>
int Config::get<int>(const std::string& key, const int& default_value) const {
    std::string value = get<std::string>(key, "");
    if (value.empty()) return default_value;
    
    try {
        return std::stoi(value);
    } catch (const std::exception& e) {
        Log::error("Failed to convert config value for key '{}' to int: {}", key, e.what());
        return default_value;
    }
}

template<>
double Config::get<double>(const std::string& key, const double& default_value) const {
    std::string value = get<std::string>(key, "");
    if (value.empty()) return default_value;
    
    try {
        return std::stod(value);
    } catch (const std::exception& e) {
        Log::error("Failed to convert config value for key '{}' to double: {}", key, e.what());
        return default_value;
    }
}

template<>
bool Config::get<bool>(const std::string& key, const bool& default_value) const {
    std::string value = get<std::string>(key, "");
    if (value.empty()) return default_value;
    
    // Convert to lowercase
    std::transform(value.begin(), value.end(), value.begin(), 
                   [](unsigned char c){ return std::tolower(c); });
    
    return (value == "true" || value == "yes" || value == "1");
}

template<>
void Config::set<std::string>(const std::string& key, const std::string& value) {
    std::lock_guard<std::mutex> lock(config_mutex_);
    config_data_[key] = value;
}

template<>
void Config::set<int>(const std::string& key, const int& value) {
    set<std::string>(key, std::to_string(value));
}

template<>
void Config::set<double>(const std::string& key, const double& value) {
    set<std::string>(key, std::to_string(value));
}

template<>
void Config::set<bool>(const std::string& key, const bool& value) {
    set<std::string>(key, value ? "true" : "false");
}

} // namespace wireshark_mcp