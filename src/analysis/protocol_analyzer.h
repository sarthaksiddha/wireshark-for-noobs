#pragma once

#include <string>
#include <memory>
#include <vector>
#include <unordered_map>
#include <functional>
#include "../capture/packet_capture.h"

namespace wireshark_mcp {

// Forward declarations
class ProtocolDecoder;

// Decoded packet field
struct PacketField {
    std::string name;
    std::string value;
    std::string description;
    size_t offset;
    size_t length;
};

// Decoded packet structure
struct DecodedPacket {
    Packet raw_packet;
    std::string highest_protocol;
    std::vector<std::string> protocol_stack;
    std::vector<PacketField> fields;
};

class ProtocolAnalyzer {
public:
    ProtocolAnalyzer();
    ~ProtocolAnalyzer();
    
    // Register a protocol decoder
    void register_decoder(std::shared_ptr<ProtocolDecoder> decoder);
    
    // Analyze a packet
    bool analyze_packet(const Packet& packet, DecodedPacket& decoded);
    
    // Get available protocol decoders
    std::vector<std::string> get_available_decoders() const;
    
    // Enable/disable a protocol decoder
    void set_decoder_enabled(const std::string& protocol_name, bool enabled);
    
private:
    std::unordered_map<std::string, std::shared_ptr<ProtocolDecoder>> m_decoders;
    std::unordered_map<std::string, bool> m_decoder_enabled;
};

// Base class for protocol decoders
class ProtocolDecoder {
public:
    virtual ~ProtocolDecoder() = default;
    
    // Get protocol name
    virtual std::string get_protocol_name() const = 0;
    
    // Check if this decoder can decode the packet
    virtual bool can_decode(const Packet& packet, const std::vector<std::string>& protocol_stack) const = 0;
    
    // Decode the packet
    virtual bool decode(const Packet& packet, DecodedPacket& decoded) = 0;
};

} // namespace wireshark_mcp
