#include "gtest/gtest.h"
#include "capture/packet_capture.h"
#include "storage/capture_file.h"
#include "security/security_manager.h"
#include <thread>
#include <chrono>
#include <filesystem>

namespace wireshark_mcp {
namespace integration_test {

class CaptureIntegrationTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Initialize security manager
        security_manager_ = &SecurityManager::getInstance();
        security_manager_->initialize();
        
        // Create capture engine
        capture_ = std::make_unique<PacketCapture>();
        
        // Create a new capture file
        capture_file_ = create_capture_file();
        temp_file_path_ = "temp_capture_test.wcap";
    }
    
    void TearDown() override {
        // Stop any ongoing capture
        if (capture_->is_capturing()) {
            capture_->stop_capture();
        }
        
        // Close capture file
        capture_file_->close();
        
        // Remove test file if it exists
        if (std::filesystem::exists(temp_file_path_)) {
            std::filesystem::remove(temp_file_path_);
        }
    }
    
    std::unique_ptr<PacketCapture> capture_;
    std::unique_ptr<CaptureFile> capture_file_;
    SecurityManager* security_manager_;
    std::string temp_file_path_;
    
    // Helper function to perform a simple capture
    bool perform_basic_capture(const std::string& device_name, int duration_seconds = 5) {
        // Configure options
        CaptureOptions options;
        options.promiscuous_mode = true;
        options.buffer_size = 64 * 1024; // 64KB
        
        // Initialize device
        if (!capture_->initialize_device(device_name, options)) {
            return false;
        }
        
        // Create a new capture file
        capture_file_->create(temp_file_path_);
        capture_file_->set_device_name(device_name);
        
        // Setup packet callback to store packets
        capture_->setPacketCallback([this]() {
            // In a real test, we would gather the packet data and add it to the capture file
            // This would need the packet data to be exposed by the capture engine
        });
        
        // Start capture
        if (!capture_->start_capture()) {
            return false;
        }
        
        // Run for some time
        std::this_thread::sleep_for(std::chrono::seconds(duration_seconds));
        
        // Stop capture
        capture_->stop_capture();
        
        // Save capture file
        return capture_file_->save();
    }
};

// This test requires a network interface and is marked as disabled by default
// Enable it when running in an environment with a known working interface
TEST_F(CaptureIntegrationTest, DISABLED_LiveCaptureBasic) {
    // Use a valid interface name for your environment
    std::string test_interface = "eth0";
    
    // Perform a basic capture
    bool capture_success = perform_basic_capture(test_interface, 2);
    EXPECT_TRUE(capture_success);
    
    // Verify capture file has packets (would be more reliable with a controlled test network)
    EXPECT_GT(capture_file_->get_packet_count(), 0);
    
    // Verify file exists on disk
    EXPECT_TRUE(std::filesystem::exists(temp_file_path_));
    
    // File size should be non-zero
    EXPECT_GT(std::filesystem::file_size(temp_file_path_), 0);
}

// Test encryption and decryption of capture files
TEST_F(CaptureIntegrationTest, EncryptDecryptCaptureFile) {
    // Create and populate a test file
    std::string test_content = "TEST_PACKET_DATA_1234567890";
    std::ofstream test_file(temp_file_path_);
    test_file << test_content;
    test_file.close();
    
    // Verify test file exists
    ASSERT_TRUE(std::filesystem::exists(temp_file_path_));
    
    // Encrypted filename
    std::string encrypted_path = temp_file_path_ + ".enc";
    
    // Encrypt the file
    EXPECT_TRUE(security_manager_->encrypt_file(temp_file_path_, encrypted_path));
    
    // Verify encrypted file exists
    EXPECT_TRUE(std::filesystem::exists(encrypted_path));
    
    // Verify content is actually encrypted (different from original)
    std::ifstream encrypted_file(encrypted_path);
    std::string encrypted_content((std::istreambuf_iterator<char>(encrypted_file)),
                                std::istreambuf_iterator<char>());
    encrypted_file.close();
    EXPECT_NE(test_content, encrypted_content);
    
    // Decrypt file
    std::string decrypted_path = temp_file_path_ + ".dec";
    EXPECT_TRUE(security_manager_->decrypt_file(encrypted_path, decrypted_path));
    
    // Verify decrypted content matches original
    std::ifstream decrypted_file(decrypted_path);
    std::string decrypted_content((std::istreambuf_iterator<char>(decrypted_file)),
                                std::istreambuf_iterator<char>());
    decrypted_file.close();
    EXPECT_EQ(test_content, decrypted_content);
    
    // Clean up extra files
    if (std::filesystem::exists(encrypted_path)) {
        std::filesystem::remove(encrypted_path);
    }
    if (std::filesystem::exists(decrypted_path)) {
        std::filesystem::remove(decrypted_path);
    }
}

// End-to-end test with mock packet data
TEST_F(CaptureIntegrationTest, EndToEndWithMockData) {
    // Initialize device with a mock name
    CaptureOptions options;
    ASSERT_TRUE(capture_->initialize_device("mock_device", options));
    
    // Create a new capture file
    ASSERT_TRUE(capture_file_->create(temp_file_path_));
    capture_file_->set_device_name("mock_device");
    
    // Simulate adding some packets
    std::vector<uint8_t> test_packet1 = {0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 0x00, 0x00, 0xc0, 0xa8, 0x00, 0x01, 0xc0, 0xa8, 0x00, 0xc7};
    std::vector<uint8_t> test_packet2 = {0x45, 0x00, 0x00, 0x54, 0x00, 0x00, 0x40, 0x00, 0x40, 0x01, 0x00, 0x00, 0xc0, 0xa8, 0x00, 0x01, 0xc0, 0xa8, 0x00, 0xc7};
    
    auto now = std::chrono::system_clock::now();
    auto later = now + std::chrono::milliseconds(100);
    
    // Add packets to capture file
    EXPECT_TRUE(capture_file_->add_packet(test_packet1.data(), test_packet1.size(), now));
    EXPECT_TRUE(capture_file_->add_packet(test_packet2.data(), test_packet2.size(), later));
    
    // Save the capture file
    EXPECT_TRUE(capture_file_->save());
    
    // Verify file exists
    EXPECT_TRUE(std::filesystem::exists(temp_file_path_));
    
    // Close the original file
    capture_file_->close();
    
    // Create a new capture file and open the saved file
    auto new_capture_file = create_capture_file();
    EXPECT_TRUE(new_capture_file->open(temp_file_path_));
    
    // Verify packet count
    EXPECT_EQ(2, new_capture_file->get_packet_count());
    
    // Verify device name was preserved
    EXPECT_EQ("mock_device", new_capture_file->get_device_name());
    
    // Retrieve and verify packet data
    std::vector<uint8_t> retrieved_packet;
    std::chrono::system_clock::time_point retrieved_time;
    
    EXPECT_TRUE(new_capture_file->get_packet(0, retrieved_packet, retrieved_time));
    EXPECT_EQ(test_packet1.size(), retrieved_packet.size());
    EXPECT_EQ(test_packet1, retrieved_packet);
    
    EXPECT_TRUE(new_capture_file->get_packet(1, retrieved_packet, retrieved_time));
    EXPECT_EQ(test_packet2.size(), retrieved_packet.size());
    EXPECT_EQ(test_packet2, retrieved_packet);
}

} // namespace integration_test
} // namespace wireshark_mcp