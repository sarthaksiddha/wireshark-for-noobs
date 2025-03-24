#include "packet_capture.h"
#include "../common/logging.h"
#include "../security/auth_manager.h"

namespace wireshark_mcp {

PacketCapture::PacketCapture()
    : m_pcap_handle(nullptr),
      m_capturing(false) {
}

PacketCapture::~PacketCapture() {
    if (m_pcap_handle) {
        pcap_close(m_pcap_handle);
        m_pcap_handle = nullptr;
    }
}

bool PacketCapture::initialize_device(const std::string& device_name, 
                                     CaptureOptions options) {
    Log::info("Initializing capture on device: {}", device_name);
    
    // Store options
    m_options = options;
    
    // Check permissions
    if (!AuthManager::validate_capture_permissions(device_name)) {
        m_error_message = "Insufficient permissions for device: " + device_name;
        Log::error(m_error_message);
        return false;
    }
    
    // Error buffer for pcap
    char errbuf[PCAP_ERRBUF_SIZE];
    
    // Open device for capturing
    m_pcap_handle = pcap_open_live(
        device_name.c_str(),
        options.snapshot_length,
        options.promiscuous_mode ? 1 : 0,
        options.timeout_ms,
        errbuf
    );
    
    if (m_pcap_handle == nullptr) {
        m_error_message = "Failed to open device: " + std::string(errbuf);
        Log::error(m_error_message);
        return false;
    }
    
    Log::info("Successfully initialized capture on device: {}", device_name);
    return true;
}

std::vector<std::string> PacketCapture::get_available_devices() {
    std::vector<std::string> devices;
    pcap_if_t *alldevs;
    char errbuf[PCAP_ERRBUF_SIZE];
    
    // Retrieve the device list
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        Log::error("Error in pcap_findalldevs: {}", errbuf);
        return devices;
    }
    
    // Add devices to the vector
    for (pcap_if_t *d = alldevs; d; d = d->next) {
        devices.push_back(d->name);
    }
    
    // Free the device list
    pcap_freealldevs(alldevs);
    
    return devices;
}

bool PacketCapture::start_capture() {
    if (!m_pcap_handle) {
        m_error_message = "Capture device not initialized";
        Log::error(m_error_message);
        return false;
    }
    
    if (m_capturing) {
        m_error_message = "Capture already in progress";
        Log::warning(m_error_message);
        return false;
    }
    
    // Set filter if needed (example for TCP packets only)
    // struct bpf_program fp;
    // pcap_compile(m_pcap_handle, &fp, "tcp", 0, PCAP_NETMASK_UNKNOWN);
    // pcap_setfilter(m_pcap_handle, &fp);
    
    m_capturing = true;
    Log::info("Packet capture started");
    
    return true;
}

void PacketCapture::stop_capture() {
    if (m_capturing) {
        m_capturing = false;
        Log::info("Packet capture stopped");
    }
}

bool PacketCapture::get_next_packet(Packet& packet) {
    if (!m_capturing || !m_pcap_handle) {
        return false;
    }
    
    struct pcap_pkthdr* header;
    const u_char* packet_data;
    
    int result = pcap_next_ex(m_pcap_handle, &header, &packet_data);
    
    if (result == 1) {
        // Successfully got a packet
        packet.timestamp = header->ts.tv_sec * 1000000 + header->ts.tv_usec;
        packet.actual_length = header->len;
        packet.captured_length = header->caplen;
        packet.data.assign(packet_data, packet_data + header->caplen);
        return true;
    } else if (result == 0) {
        // Timeout elapsed
        return false;
    } else if (result == -1) {
        // Error occurred
        m_error_message = pcap_geterr(m_pcap_handle);
        Log::error("Error reading packet: {}", m_error_message);
        return false;
    } else if (result == -2) {
        // End of capture file reached (when reading from file)
        m_capturing = false;
        return false;
    }
    
    return false;
}

void PacketCapture::packet_handler(u_char* user, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    // This is a static callback function for pcap_loop
    // Implementation if needed
}

} // namespace wireshark_mcp
