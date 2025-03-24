#ifndef WIRESHARK_MCP_CONFIG_H
#define WIRESHARK_MCP_CONFIG_H

#include <string>
#include <map>
#include <mutex>
#include <memory>
#include <vector>

namespace wireshark_mcp {

class Config {
public:
    static Config& getInstance();
    
    // Delete copy constructor and assignment operator
    Config(const Config&) = delete;
    Config& operator=(const Config&) = delete;
    
    bool load(const std::string& config_file);
    bool save(const std::string& config_file = "");
    
    template<typename T>
    T get(const std::string& key, const T& default_value = T()) const;
    
    template<typename T>
    void set(const std::string& key, const T& value);
    
    bool hasKey(const std::string& key) const;
    std::vector<std::string> getKeys() const;

private:
    Config();
    ~Config();
    
    mutable std::mutex config_mutex_;
    std::map<std::string, std::string> config_data_;
    std::string loaded_file_;
};

// Template specialization declarations
template<>
std::string Config::get<std::string>(const std::string& key, const std::string& default_value) const;

template<>
int Config::get<int>(const std::string& key, const int& default_value) const;

template<>
double Config::get<double>(const std::string& key, const double& default_value) const;

template<>
bool Config::get<bool>(const std::string& key, const bool& default_value) const;

template<>
void Config::set<std::string>(const std::string& key, const std::string& value);

template<>
void Config::set<int>(const std::string& key, const int& value);

template<>
void Config::set<double>(const std::string& key, const double& value);

template<>
void Config::set<bool>(const std::string& key, const bool& value);

} // namespace wireshark_mcp

#endif // WIRESHARK_MCP_CONFIG_H