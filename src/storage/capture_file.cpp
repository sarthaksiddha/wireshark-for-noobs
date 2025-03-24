#include "capture_file.h"
#include "../common/logging.h"
#include "../security/security_manager.h"
#include <fstream>
#include <vector>
#include <stdexcept>
#include <filesystem>

namespace wireshark_mcp {

// Packet structure for storage
struct StoredPacket {
    std::chrono::system_clock::time_point timestamp;
    std::vector<uint8_t> data;
};

// File format constants
constexpr uint32_t FILE_MAGIC = 0x57534D43; // "WSMC" in hex
constexpr uint16_t FILE_VERSION = 0x0100;    // Version 1.0

// File header structure
struct FileHeader {
    uint32_t magic;         // Magic number for file identification
    uint16_t version;       // File format version
    uint16_t flags;         // Flags (encrypted, compressed, etc.)
    uint64_t packet_count;  // Number of packets in the file
    uint64_t reserved;      // Reserved for future use
};

// Implementation class
struct CaptureFile::Impl {
    std::string file_path;
    std::vector<StoredPacket> packets;
    bool modified;
    bool open;
    bool encrypted;
    std::string device_name;
    std::string user_comment;
    
    Impl() : modified(false), open(false), encrypted(false) {}
    
    bool write_to_file(const std::string& path, bool encrypt) {
        // Create a temporary file for writing
        std::string temp_file = path + ".tmp";
        
        std::ofstream file(temp_file, std::ios::binary);
        if (!file) {
            Log::error("Failed to create capture file: {}", temp_file);
            return false;
        }
        
        // Write file header
        FileHeader header;
        header.magic = FILE_MAGIC;
        header.version = FILE_VERSION;
        header.flags = encrypt ? 0x0001 : 0x0000;
        header.packet_count = packets.size();
        header.reserved = 0;
        
        file.write(reinterpret_cast<const char*>(&header), sizeof(header));
        
        // Write metadata
        uint32_t device_name_len = static_cast<uint32_t>(device_name.length());
        file.write(reinterpret_cast<const char*>(&device_name_len), sizeof(device_name_len));
        file.write(device_name.c_str(), device_name.length());
        
        uint32_t comment_len = static_cast<uint32_t>(user_comment.length());
        file.write(reinterpret_cast<const char*>(&comment_len), sizeof(comment_len));
        file.write(user_comment.c_str(), user_comment.length());
        
        // Write packets
        for (const auto& packet : packets) {
            // Write timestamp
            auto timestamp = packet.timestamp.time_since_epoch().count();
            file.write(reinterpret_cast<const char*>(&timestamp), sizeof(timestamp));
            
            // Write packet data length
            uint32_t data_len = static_cast<uint32_t>(packet.data.size());
            file.write(reinterpret_cast<const char*>(&data_len), sizeof(data_len));
            
            // Write packet data
            file.write(reinterpret_cast<const char*>(packet.data.data()), data_len);
        }
        
        file.close();
        
        // Encrypt if requested
        if (encrypt) {
            // Use security manager to encrypt the file
            auto& security_mgr = SecurityManager::getInstance();
            std::string final_file = path + ".enc";
            
            if (!security_mgr.encrypt_file(temp_file, final_file)) {
                Log::error("Failed to encrypt capture file");
                std::filesystem::remove(temp_file);
                return false;
            }
            
            // Remove temp file
            std::filesystem::remove(temp_file);
            
            // Rename encrypted file to final path
            try {
                std::filesystem::rename(final_file, path);
            } catch (const std::exception& e) {
                Log::error("Failed to rename encrypted file: {}", e.what());
                return false;
            }
            
            encrypted = true;
        } else {
            // Rename temp file to final path
            try {
                std::filesystem::rename(temp_file, path);
            } catch (const std::exception& e) {
                Log::error("Failed to rename capture file: {}", e.what());
                return false;
            }
            
            encrypted = false;
        }
        
        file_path = path;
        modified = false;
        open = true;
        
        Log::info("Capture file saved: {}", path);
        return true;
    }
    
    bool read_from_file(const std::string& path) {
        std::string file_to_read = path;
        bool is_encrypted = false;
        
        // Check if file is encrypted (based on extension or content)
        if (path.ends_with(".enc")) {
            // Decrypt to temp file
            auto& security_mgr = SecurityManager::getInstance();
            std::string temp_file = security_mgr.create_secure_temp_file("decrypt_");
            
            if (temp_file.empty() || !security_mgr.decrypt_file(path, temp_file)) {
                Log::error("Failed to decrypt capture file: {}", path);
                return false;
            }
            
            file_to_read = temp_file;
            is_encrypted = true;
        }
        
        // Open file for reading
        std::ifstream file(file_to_read, std::ios::binary);
        if (!file) {
            Log::error("Failed to open capture file: {}", file_to_read);
            return false;
        }
        
        // Read and verify header
        FileHeader header;
        file.read(reinterpret_cast<char*>(&header), sizeof(header));
        
        if (file.fail() || header.magic != FILE_MAGIC) {
            Log::error("Invalid capture file format: {}", file_to_read);
            return false;
        }
        
        // Check file version
        if (header.version > FILE_VERSION) {
            Log::warning("Capture file version newer than supported: {}", header.version);
            // We'll try to read it anyway
        }
        
        // Read metadata
        uint32_t device_name_len;
        file.read(reinterpret_cast<char*>(&device_name_len), sizeof(device_name_len));
        
        if (device_name_len > 0) {
            device_name.resize(device_name_len);
            file.read(&device_name[0], device_name_len);
        } else {
            device_name.clear();
        }
        
        uint32_t comment_len;
        file.read(reinterpret_cast<char*>(&comment_len), sizeof(comment_len));
        
        if (comment_len > 0) {
            user_comment.resize(comment_len);
            file.read(&user_comment[0], comment_len);
        } else {
            user_comment.clear();
        }
        
        // Read packets
        packets.clear();
        packets.reserve(header.packet_count);
        
        for (uint64_t i = 0; i < header.packet_count; ++i) {
            StoredPacket packet;
            
            // Read timestamp
            int64_t timestamp;
            file.read(reinterpret_cast<char*>(&timestamp), sizeof(timestamp));
            packet.timestamp = std::chrono::system_clock::time_point(
                std::chrono::system_clock::duration(timestamp));
            
            // Read packet data length
            uint32_t data_len;
            file.read(reinterpret_cast<char*>(&data_len), sizeof(data_len));
            
            // Read packet data
            packet.data.resize(data_len);
            file.read(reinterpret_cast<char*>(packet.data.data()), data_len);
            
            if (file.fail()) {
                Log::error("Error reading packet data at index {}", i);
                return false;
            }
            
            packets.push_back(std::move(packet));
        }
        
        // Clean up temp file if needed
        if (is_encrypted) {
            auto& security_mgr = SecurityManager::getInstance();
            security_mgr.delete_secure_temp_file(file_to_read);
        }
        
        file_path = path;
        modified = false;
        open = true;
        encrypted = is_encrypted;
        
        Log::info("Loaded capture file with {} packets: {}", packets.size(), path);
        return true;
    }
};

// CaptureFile implementation
CaptureFile::CaptureFile() : pimpl_(std::make_unique<Impl>()) {}

CaptureFile::~CaptureFile() = default;

bool CaptureFile::create(const std::string& file_path, bool encrypt) {
    // Close any existing file
    close();
    
    // Initialize new file
    pimpl_->file_path = file_path;
    pimpl_->packets.clear();
    pimpl_->modified = true;
    pimpl_->open = true;
    pimpl_->encrypted = encrypt;
    
    Log::info("Created new capture file: {}", file_path);
    return true;
}

bool CaptureFile::open(const std::string& file_path) {
    // Close any existing file
    close();
    
    // Open the file
    return pimpl_->read_from_file(file_path);
}

bool CaptureFile::save() {
    if (!pimpl_->open) {
        Log::error("Cannot save: no file is open");
        return false;
    }
    
    if (!pimpl_->modified) {
        Log::info("File not modified, skipping save");
        return true;
    }
    
    return pimpl_->write_to_file(pimpl_->file_path, pimpl_->encrypted);
}

bool CaptureFile::save_as(const std::string& file_path, bool encrypt) {
    if (!pimpl_->open) {
        Log::error("Cannot save: no file is open");
        return false;
    }
    
    return pimpl_->write_to_file(file_path, encrypt);
}

void CaptureFile::close() {
    if (pimpl_->open && pimpl_->modified) {
        Log::warning("Closing modified capture file without saving: {}", pimpl_->file_path);
    }
    
    pimpl_->open = false;
    pimpl_->modified = false;
}

bool CaptureFile::add_packet(const uint8_t* data, size_t data_len,
                           const std::chrono::system_clock::time_point& timestamp) {
    if (!pimpl_->open) {
        Log::error("Cannot add packet: no file is open");
        return false;
    }
    
    StoredPacket packet;
    packet.timestamp = timestamp;
    packet.data.assign(data, data + data_len);
    
    pimpl_->packets.push_back(std::move(packet));
    pimpl_->modified = true;
    
    return true;
}

size_t CaptureFile::get_packet_count() const {
    return pimpl_->packets.size();
}

bool CaptureFile::get_packet(size_t index, std::vector<uint8_t>& data,
                           std::chrono::system_clock::time_point& timestamp) const {
    if (index >= pimpl_->packets.size()) {
        return false;
    }
    
    const auto& packet = pimpl_->packets[index];
    data = packet.data;
    timestamp = packet.timestamp;
    
    return true;
}

bool CaptureFile::is_open() const {
    return pimpl_->open;
}

bool CaptureFile::is_modified() const {
    return pimpl_->modified;
}

std::string CaptureFile::get_file_path() const {
    return pimpl_->file_path;
}

bool CaptureFile::is_encrypted() const {
    return pimpl_->encrypted;
}

CaptureFileStats CaptureFile::get_stats() const {
    CaptureFileStats stats;
    stats.packet_count = pimpl_->packets.size();
    stats.file_size = 0;  // Would need to check the file on disk
    stats.device_name = pimpl_->device_name;
    stats.encrypted = pimpl_->encrypted;
    
    // Calculate first and last packet times
    if (!pimpl_->packets.empty()) {
        stats.first_packet_time = pimpl_->packets.front().timestamp;
        stats.last_packet_time = pimpl_->packets.back().timestamp;
        
        // Calculate file size (estimate)
        for (const auto& packet : pimpl_->packets) {
            stats.file_size += packet.data.size() + 16;  // Data + overhead
        }
        
        // Add header size
        stats.file_size += sizeof(FileHeader) + 
                          pimpl_->device_name.length() + 
                          pimpl_->user_comment.length() + 8;  // +8 for length fields
    }
    
    return stats;
}

void CaptureFile::set_device_name(const std::string& device_name) {
    pimpl_->device_name = device_name;
    pimpl_->modified = true;
}

std::string CaptureFile::get_device_name() const {
    return pimpl_->device_name;
}

void CaptureFile::set_user_comment(const std::string& comment) {
    pimpl_->user_comment = comment;
    pimpl_->modified = true;
}

std::string CaptureFile::get_user_comment() const {
    return pimpl_->user_comment;
}

// Factory function
std::unique_ptr<CaptureFile> create_capture_file() {
    return std::make_unique<CaptureFile>();
}

} // namespace wireshark_mcp