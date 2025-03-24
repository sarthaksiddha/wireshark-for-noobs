#pragma once

#include <string>
#include <vector>
#include <pcap.h>
#include <memory>

namespace wireshark_mcp {

// Capture options structure
struct CaptureOptions {
    bool promiscuous_mode = true;
    int snapshot_length = 65535;
    int timeout_ms = 1000;
    bool capture_to_file = false;
    std::string output_file;
    bool enable_encryption = true;
};

// Packet structure
struct Packet {
    uint64_t timestamp;
    std::vector<uint8_t> data;
    size_t actual_length;
    size_t captured_length;
};

class PacketCapture {
public:
    PacketCapture();
    ~PacketCapture();
    
    // Initialize capture device
    bool initialize_device(const std::string& device_name, CaptureOptions options);
    
    // Get list of available devices
    std::vector<std::string> get_available_devices();
    
    // Start capture
    bool start_capture();
    
    // Stop capture
    void stop_capture();
    
    // Get next packet (non-blocking)
    bool get_next_packet(Packet& packet);
    
    // Check if capture is active
    bool is_capturing() const { return m_capturing; }
    
    // Get error message
    std::string get_error() const { return m_error_message; }

private:
    pcap_t* m_pcap_handle;
    bool m_capturing;
    std::string m_error_message;
    CaptureOptions m_options;
    
    // Callback for packet processing
    static void packet_handler(u_char* user, const struct pcap_pkthdr* pkthdr, const u_char* packet);
};

} // namespace wireshark_mcp
