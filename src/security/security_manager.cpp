#include "security_manager.h"
#include "../common/logging.h"
#include "../common/config.h"
#include <fstream>
#include <random>
#include <filesystem>
#include <algorithm>

namespace wireshark_mcp {

struct SecurityManager::Impl {
    // Crypto implementation details
    
    // Simple XOR encryption (for demonstration only - not secure!)
    // In a real implementation, this would use proper cryptographic libraries
    static bool xor_encrypt_decrypt(const std::string& input_file, 
                                 const std::string& output_file,
                                 const std::string& key) {
        std::ifstream in(input_file, std::ios::binary);
        if (!in) {
            return false;
        }
        
        std::ofstream out(output_file, std::ios::binary);
        if (!out) {
            return false;
        }
        
        char byte;
        size_t key_index = 0;
        
        while (in.get(byte)) {
            // XOR with key (rotating through key bytes)
            char encrypted = byte ^ key[key_index];
            out.put(encrypted);
            
            key_index = (key_index + 1) % key.length();
        }
        
        return true;
    }
    
    // Generate a secure key (in real implementation, this would be more sophisticated)
    static std::string generate_key(size_t length = 32) {
        const std::string chars = 
            "0123456789"
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
            "abcdefghijklmnopqrstuvwxyz"
            "!@#$%^&*()";
        
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dist(0, static_cast<int>(chars.length() - 1));
        
        std::string key;
        key.reserve(length);
        
        for (size_t i = 0; i < length; ++i) {
            key += chars[dist(gen)];
        }
        
        return key;
    }
};

SecurityManager::SecurityManager() 
    : pimpl_(std::make_unique<Impl>()),
      encryption_level_(EncryptionLevel::STANDARD) {
}

SecurityManager::~SecurityManager() {
    // Clean up temp files
    for (const auto& file : temp_files_) {
        if (std::filesystem::exists(file)) {
            try {
                std::filesystem::remove(file);
            } catch (const std::exception& e) {
                Log::warning("Failed to delete temp file: {}, error: {}", file, e.what());
            }
        }
    }
}

SecurityManager& SecurityManager::getInstance() {
    static SecurityManager instance;
    return instance;
}

bool SecurityManager::initialize(const std::string& config_path) {
    Log::info("Initializing security manager");
    
    // Load security configuration
    auto& config = Config::getInstance();
    if (!config_path.empty()) {
        config.load(config_path);
    }
    
    // Set encryption level from config
    std::string level_str = config.get<std::string>("security.encryption_level", "STANDARD");
    if (level_str == "NONE") {
        encryption_level_ = EncryptionLevel::NONE;
    } else if (level_str == "BASIC") {
        encryption_level_ = EncryptionLevel::BASIC;
    } else if (level_str == "HIGH") {
        encryption_level_ = EncryptionLevel::HIGH;
    } else {
        encryption_level_ = EncryptionLevel::STANDARD;
    }
    
    // Load allowed devices
    allowed_devices_.clear();
    std::string devices_str = config.get<std::string>("security.allowed_devices", "");
    if (!devices_str.empty()) {
        size_t pos = 0;
        while ((pos = devices_str.find(',')) != std::string::npos) {
            std::string device = devices_str.substr(0, pos);
            // Trim whitespace
            device.erase(0, device.find_first_not_of(" \t"));
            device.erase(device.find_last_not_of(" \t") + 1);
            
            if (!device.empty()) {
                allowed_devices_.push_back(device);
            }
            
            devices_str.erase(0, pos + 1);
        }
        
        // Add the last device
        if (!devices_str.empty()) {
            devices_str.erase(0, devices_str.find_first_not_of(" \t"));
            devices_str.erase(devices_str.find_last_not_of(" \t") + 1);
            
            if (!devices_str.empty()) {
                allowed_devices_.push_back(devices_str);
            }
        }
    }
    
    Log::info("Security manager initialized with encryption level: {}", level_str);
    return true;
}

bool SecurityManager::validate_capture_permissions(const std::string& device_name) {
    // Check if user has admin/root privileges
    // This is platform-dependent
    
    // For demonstration, we'll just check if the device is allowed
    auto& instance = getInstance();
    return instance.is_device_allowed(device_name);
}

bool SecurityManager::encrypt_file(const std::string& input_file, 
                                 const std::string& output_file,
                                 EncryptionLevel level) {
    if (level == EncryptionLevel::NONE) {
        // Just copy the file
        try {
            std::filesystem::copy_file(
                input_file, output_file, 
                std::filesystem::copy_options::overwrite_existing
            );
            return true;
        } catch (const std::exception& e) {
            Log::error("Failed to copy file: {}", e.what());
            return false;
        }
    }
    
    // For demo purposes, we're using the same algorithm for all levels
    // with different key lengths
    size_t key_length = 16;  // Default for BASIC
    
    if (level == EncryptionLevel::STANDARD) {
        key_length = 32;
    } else if (level == EncryptionLevel::HIGH) {
        key_length = 64;
    }
    
    std::string key = Impl::generate_key(key_length);
    
    // Store the key securely (in a real implementation)
    // For demo, we'll just log it
    Log::debug("Generated encryption key: {}", key);
    
    // Encrypt the file
    bool success = Impl::xor_encrypt_decrypt(input_file, output_file, key);
    
    if (success) {
        Log::info("File encrypted successfully: {}", output_file);
    } else {
        Log::error("Failed to encrypt file: {}", input_file);
    }
    
    return success;
}

bool SecurityManager::decrypt_file(const std::string& input_file, 
                                 const std::string& output_file) {
    // In a real implementation, we would retrieve the key used for encryption
    // For demo, we're using a fixed key
    std::string key = "DefaultKey123!@#";
    
    // Decrypt the file (actually using the same XOR function for demo)
    bool success = Impl::xor_encrypt_decrypt(input_file, output_file, key);
    
    if (success) {
        Log::info("File decrypted successfully: {}", output_file);
    } else {
        Log::error("Failed to decrypt file: {}", input_file);
    }
    
    return success;
}

std::string SecurityManager::create_secure_temp_file(const std::string& prefix) {
    // Create a unique filename
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dist(0, 999999);
    
    std::string temp_dir = std::filesystem::temp_directory_path().string();
    std::string filename = temp_dir + "/" + prefix + std::to_string(dist(gen));
    
    // Create an empty file
    std::ofstream file(filename);
    if (!file) {
        Log::error("Failed to create temporary file: {}", filename);
        return "";
    }
    
    // Add to cleanup list
    temp_files_.push_back(filename);
    
    Log::debug("Created secure temporary file: {}", filename);
    return filename;
}

bool SecurityManager::delete_secure_temp_file(const std::string& file_path) {
    try {
        if (std::filesystem::exists(file_path)) {
            std::filesystem::remove(file_path);
            
            // Remove from cleanup list
            auto it = std::find(temp_files_.begin(), temp_files_.end(), file_path);
            if (it != temp_files_.end()) {
                temp_files_.erase(it);
            }
            
            Log::debug("Deleted temporary file: {}", file_path);
            return true;
        }
    } catch (const std::exception& e) {
        Log::error("Failed to delete temporary file: {}, error: {}", file_path, e.what());
    }
    
    return false;
}

void SecurityManager::set_encryption_level(EncryptionLevel level) {
    encryption_level_ = level;
    
    std::string level_str;
    switch (level) {
        case EncryptionLevel::NONE:
            level_str = "NONE";
            break;
        case EncryptionLevel::BASIC:
            level_str = "BASIC";
            break;
        case EncryptionLevel::STANDARD:
            level_str = "STANDARD";
            break;
        case EncryptionLevel::HIGH:
            level_str = "HIGH";
            break;
    }
    
    Log::info("Encryption level changed to: {}", level_str);
}

EncryptionLevel SecurityManager::get_encryption_level() const {
    return encryption_level_;
}

bool SecurityManager::is_device_allowed(const std::string& device_name) const {
    // If no devices are specified, all are allowed
    if (allowed_devices_.empty()) {
        return true;
    }
    
    return std::find(allowed_devices_.begin(), allowed_devices_.end(), device_name) 
           != allowed_devices_.end();
}

void SecurityManager::add_allowed_device(const std::string& device_name) {
    if (!is_device_allowed(device_name)) {
        allowed_devices_.push_back(device_name);
        Log::info("Added device to allowed list: {}", device_name);
    }
}

} // namespace wireshark_mcp