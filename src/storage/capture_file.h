#ifndef WIRESHARK_MCP_CAPTURE_FILE_H
#define WIRESHARK_MCP_CAPTURE_FILE_H

#include <string>
#include <vector>
#include <chrono>
#include <memory>
#include <cstdint>

namespace wireshark_mcp {

struct CaptureFileStats {
    size_t packet_count;
    size_t file_size;
    std::chrono::system_clock::time_point first_packet_time;
    std::chrono::system_clock::time_point last_packet_time;
    std::string device_name;
    bool encrypted;
};

class CaptureFile {
public:
    CaptureFile();
    ~CaptureFile();
    
    // File operations
    bool create(const std::string& file_path, bool encrypt = false);
    bool open(const std::string& file_path);
    bool save();
    bool save_as(const std::string& file_path, bool encrypt = false);
    void close();
    
    // Packet operations
    bool add_packet(const uint8_t* data, size_t data_len, 
                  const std::chrono::system_clock::time_point& timestamp);
    
    size_t get_packet_count() const;
    bool get_packet(size_t index, std::vector<uint8_t>& data, 
                  std::chrono::system_clock::time_point& timestamp) const;
    
    // File info
    bool is_open() const;
    bool is_modified() const;
    std::string get_file_path() const;
    bool is_encrypted() const;
    
    // Statistics
    CaptureFileStats get_stats() const;
    
    // File metadata
    void set_device_name(const std::string& device_name);
    std::string get_device_name() const;
    
    void set_user_comment(const std::string& comment);
    std::string get_user_comment() const;
    
private:
    struct Impl;
    std::unique_ptr<Impl> pimpl_;
};

// Factory function
std::unique_ptr<CaptureFile> create_capture_file();

} // namespace wireshark_mcp

#endif // WIRESHARK_MCP_CAPTURE_FILE_H