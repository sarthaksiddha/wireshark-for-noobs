#include "protocol_analyzer.h"
#include "../common/logging.h"

namespace wireshark_mcp {

ProtocolAnalyzer::ProtocolAnalyzer() {
    // Initialize with some default decoders
}

ProtocolAnalyzer::~ProtocolAnalyzer() {
    // Clean up resources if needed
}

void ProtocolAnalyzer::register_decoder(std::shared_ptr<ProtocolDecoder> decoder) {
    if (!decoder) {
        Log::warning("Attempted to register null decoder");
        return;
    }
    
    std::string protocol_name = decoder->get_protocol_name();
    m_decoders[protocol_name] = decoder;
    m_decoder_enabled[protocol_name] = true;
    
    Log::info("Registered protocol decoder: {}", protocol_name);
}

bool ProtocolAnalyzer::analyze_packet(const Packet& packet, DecodedPacket& decoded) {
    // Initialize the decoded packet
    decoded.raw_packet = packet;
    decoded.protocol_stack.clear();
    decoded.fields.clear();
    
    // Start with layer 2 protocols (e.g., Ethernet)
    bool decoded_something = false;
    
    // Try each decoder
    for (const auto& decoder_pair : m_decoders) {
        const std::string& protocol_name = decoder_pair.first;
        const auto& decoder = decoder_pair.second;
        
        // Skip disabled decoders
        if (!m_decoder_enabled[protocol_name]) {
            continue;
        }
        
        // Check if this decoder can handle the packet
        if (decoder->can_decode(packet, decoded.protocol_stack)) {
            // Try to decode the packet
            if (decoder->decode(packet, decoded)) {
                decoded_something = true;
                decoded.highest_protocol = protocol_name;
                
                // Protocol stack is updated by the decoder
                break;
            }
        }
    }
    
    if (!decoded_something) {
        Log::warning("Could not decode packet with any registered decoder");
    }
    
    return decoded_something;
}

std::vector<std::string> ProtocolAnalyzer::get_available_decoders() const {
    std::vector<std::string> decoders;
    
    for (const auto& decoder_pair : m_decoders) {
        decoders.push_back(decoder_pair.first);
    }
    
    return decoders;
}

void ProtocolAnalyzer::set_decoder_enabled(const std::string& protocol_name, bool enabled) {
    auto it = m_decoder_enabled.find(protocol_name);
    
    if (it != m_decoder_enabled.end()) {
        it->second = enabled;
        Log::info("Set decoder '{}' enabled: {}", protocol_name, enabled);
    } else {
        Log::warning("Attempted to enable/disable unknown decoder: {}", protocol_name);
    }
}

} // namespace wireshark_mcp
