#ifndef WIRESHARK_MCP_SECURITY_MANAGER_H
#define WIRESHARK_MCP_SECURITY_MANAGER_H

#include <string>
#include <vector>
#include <memory>
#include <functional>

namespace wireshark_mcp {

enum class EncryptionLevel {
    NONE,
    BASIC,
    STANDARD,
    HIGH
};

class SecurityManager {
public:
    static SecurityManager& getInstance();
    
    // Delete copy constructor and assignment operator
    SecurityManager(const SecurityManager&) = delete;
    SecurityManager& operator=(const SecurityManager&) = delete;
    
    bool initialize(const std::string& config_path = "");
    
    // Capture permissions
    static bool validate_capture_permissions(const std::string& device_name);
    
    // Encryption methods
    bool encrypt_file(const std::string& input_file, const std::string& output_file, 
                    EncryptionLevel level = EncryptionLevel::STANDARD);
    
    bool decrypt_file(const std::string& input_file, const std::string& output_file);
    
    // Secure temporary files
    std::string create_secure_temp_file(const std::string& prefix = "wireshark_mcp_");
    bool delete_secure_temp_file(const std::string& file_path);
    
    // Security settings
    void set_encryption_level(EncryptionLevel level);
    EncryptionLevel get_encryption_level() const;
    
    // Device permissions
    bool is_device_allowed(const std::string& device_name) const;
    void add_allowed_device(const std::string& device_name);
    
private:
    SecurityManager();
    ~SecurityManager();
    
    // Implementation details
    struct Impl;
    std::unique_ptr<Impl> pimpl_;
    
    // Temporary files to clean up on exit
    std::vector<std::string> temp_files_;
    
    // Current encryption settings
    EncryptionLevel encryption_level_;
    
    // Allowed network devices
    std::vector<std::string> allowed_devices_;
};

} // namespace wireshark_mcp

#endif // WIRESHARK_MCP_SECURITY_MANAGER_H