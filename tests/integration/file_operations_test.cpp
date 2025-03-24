#include "gtest/gtest.h"
#include "storage/capture_file.h"
#include "security/security_manager.h"
#include <filesystem>
#include <random>
#include <algorithm>

namespace wireshark_mcp {
namespace integration_test {

class FileOperationsTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Create test directory
        test_dir_ = "test_file_ops";
        std::filesystem::create_directory(test_dir_);
        
        // Initialize paths
        test_file_path_ = test_dir_ + "/test.wcap";
        encrypted_file_path_ = test_dir_ + "/test.wcap.enc";
        
        // Create security manager
        security_manager_ = &SecurityManager::getInstance();
        security_manager_->initialize();
        
        // Generate test packet data
        generateRandomPackets(10);
    }
    
    void TearDown() override {
        // Clean up test files
        if (std::filesystem::exists(test_file_path_)) {
            std::filesystem::remove(test_file_path_);
        }
        
        if (std::filesystem::exists(encrypted_file_path_)) {
            std::filesystem::remove(encrypted_file_path_);
        }
        
        // Remove test directory
        if (std::filesystem::exists(test_dir_)) {
            std::filesystem::remove_all(test_dir_);
        }
    }
    
    void generateRandomPackets(size_t count) {
        test_packets_.clear();
        packet_timestamps_.clear();
        
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> size_dist(20, 1500);  // Packet sizes
        std::uniform_int_distribution<> byte_dist(0, 255);    // Byte values
        
        auto base_time = std::chrono::system_clock::now();
        
        for (size_t i = 0; i < count; ++i) {
            // Generate random packet size
            size_t packet_size = size_dist(gen);
            
            // Generate packet data
            std::vector<uint8_t> packet(packet_size);
            std::generate(packet.begin(), packet.end(), [&byte_dist, &gen]() { return static_cast<uint8_t>(byte_dist(gen)); });
            
            // IPv4 header pattern for first few bytes to make it look like valid packets
            if (packet.size() >= 20) {
                packet[0] = 0x45;  // IPv4, header length 20 bytes
                packet[2] = static_cast<uint8_t>((packet_size >> 8) & 0xFF);  // Total length high byte
                packet[3] = static_cast<uint8_t>(packet_size & 0xFF);         // Total length low byte
                packet[8] = 64;    // TTL
            }
            
            test_packets_.push_back(packet);
            
            // Create timestamp with incrementing microseconds
            packet_timestamps_.push_back(base_time + std::chrono::microseconds(i * 1000));
        }
    }
    
    std::string test_dir_;
    std::string test_file_path_;
    std::string encrypted_file_path_;
    SecurityManager* security_manager_;
    std::vector<std::vector<uint8_t>> test_packets_;
    std::vector<std::chrono::system_clock::time_point> packet_timestamps_;
};

TEST_F(FileOperationsTest, CreateAndSaveFile) {
    // Create capture file
    auto capture_file = create_capture_file();
    ASSERT_TRUE(capture_file != nullptr);
    
    // Create new file
    EXPECT_TRUE(capture_file->create(test_file_path_));
    
    // Set metadata
    capture_file->set_device_name("test_device");
    capture_file->set_user_comment("Test capture file");
    
    // Add packets
    for (size_t i = 0; i < test_packets_.size(); ++i) {
        const auto& packet = test_packets_[i];
        EXPECT_TRUE(capture_file->add_packet(packet.data(), packet.size(), packet_timestamps_[i]));
    }
    
    // Save file
    EXPECT_TRUE(capture_file->save());
    
    // Verify file exists
    EXPECT_TRUE(std::filesystem::exists(test_file_path_));
    
    // Verify file size is non-zero
    EXPECT_GT(std::filesystem::file_size(test_file_path_), 0);
    
    // Close file
    capture_file->close();
}

TEST_F(FileOperationsTest, OpenAndReadFile) {
    // First create and save a file
    {
        auto capture_file = create_capture_file();
        ASSERT_TRUE(capture_file->create(test_file_path_));
        
        capture_file->set_device_name("test_device");
        capture_file->set_user_comment("Test read operations");
        
        for (size_t i = 0; i < test_packets_.size(); ++i) {
            const auto& packet = test_packets_[i];
            ASSERT_TRUE(capture_file->add_packet(packet.data(), packet.size(), packet_timestamps_[i]));
        }
        
        ASSERT_TRUE(capture_file->save());
        capture_file->close();
    }
    
    // Now open and read the file
    {
        auto capture_file = create_capture_file();
        ASSERT_TRUE(capture_file->open(test_file_path_));
        
        // Verify metadata
        EXPECT_EQ("test_device", capture_file->get_device_name());
        EXPECT_EQ("Test read operations", capture_file->get_user_comment());
        
        // Verify packet count
        EXPECT_EQ(test_packets_.size(), capture_file->get_packet_count());
        
        // Read and verify each packet
        for (size_t i = 0; i < test_packets_.size(); ++i) {
            const auto& original_packet = test_packets_[i];
            
            std::vector<uint8_t> read_packet;
            std::chrono::system_clock::time_point read_timestamp;
            
            ASSERT_TRUE(capture_file->get_packet(i, read_packet, read_timestamp));
            
            // Verify packet data
            EXPECT_EQ(original_packet.size(), read_packet.size());
            EXPECT_EQ(original_packet, read_packet);
            
            // Verify timestamp (exact comparison might be tricky due to serialization/deserialization)
            // Convert to microseconds to allow for small differences
            auto original_us = std::chrono::time_point_cast<std::chrono::microseconds>(packet_timestamps_[i]).time_since_epoch().count();
            auto read_us = std::chrono::time_point_cast<std::chrono::microseconds>(read_timestamp).time_since_epoch().count();
            
            // Allow for a small tolerance (1ms)
            EXPECT_NEAR(original_us, read_us, 1000);
        }
        
        // Get file stats
        CaptureFileStats stats = capture_file->get_stats();
        EXPECT_EQ(test_packets_.size(), stats.packet_count);
        EXPECT_EQ("test_device", stats.device_name);
        EXPECT_FALSE(stats.encrypted);
        
        capture_file->close();
    }
}

TEST_F(FileOperationsTest, EncryptedFile) {
    // Create and save a file with encryption
    {
        auto capture_file = create_capture_file();
        ASSERT_TRUE(capture_file->create(test_file_path_, true));  // true = encrypt
        
        capture_file->set_device_name("encrypted_device");
        
        // Add some packets
        for (size_t i = 0; i < test_packets_.size(); ++i) {
            const auto& packet = test_packets_[i];
            ASSERT_TRUE(capture_file->add_packet(packet.data(), packet.size(), packet_timestamps_[i]));
        }
        
        ASSERT_TRUE(capture_file->save());
        EXPECT_TRUE(capture_file->is_encrypted());
        
        capture_file->close();
    }
    
    // Verify the file exists
    EXPECT_TRUE(std::filesystem::exists(test_file_path_));
    
    // Try to read the encrypted file
    {
        auto capture_file = create_capture_file();
        ASSERT_TRUE(capture_file->open(test_file_path_));
        
        // Verify it's recognized as encrypted
        EXPECT_TRUE(capture_file->is_encrypted());
        
        // Verify metadata
        EXPECT_EQ("encrypted_device", capture_file->get_device_name());
        
        // Verify packet count
        EXPECT_EQ(test_packets_.size(), capture_file->get_packet_count());
        
        // Read a packet
        std::vector<uint8_t> read_packet;
        std::chrono::system_clock::time_point read_timestamp;
        
        ASSERT_TRUE(capture_file->get_packet(0, read_packet, read_timestamp));
        EXPECT_EQ(test_packets_[0].size(), read_packet.size());
        
        capture_file->close();
    }
}

TEST_F(FileOperationsTest, ModifyAndSaveAs) {
    // Create and save initial file
    {
        auto capture_file = create_capture_file();
        ASSERT_TRUE(capture_file->create(test_file_path_));
        
        // Add some initial packets
        for (size_t i = 0; i < 5; ++i) {
            const auto& packet = test_packets_[i];
            ASSERT_TRUE(capture_file->add_packet(packet.data(), packet.size(), packet_timestamps_[i]));
        }
        
        ASSERT_TRUE(capture_file->save());
        capture_file->close();
    }
    
    // Open, modify, and save as new file
    {
        auto capture_file = create_capture_file();
        ASSERT_TRUE(capture_file->open(test_file_path_));
        
        // Verify initial packet count
        EXPECT_EQ(5, capture_file->get_packet_count());
        
        // Add more packets
        for (size_t i = 5; i < test_packets_.size(); ++i) {
            const auto& packet = test_packets_[i];
            ASSERT_TRUE(capture_file->add_packet(packet.data(), packet.size(), packet_timestamps_[i]));
        }
        
        // Save as new encrypted file
        std::string new_file = test_dir_ + "/modified.wcap";
        ASSERT_TRUE(capture_file->save_as(new_file, true));  // Save as encrypted
        
        capture_file->close();
        
        // Verify new file exists
        EXPECT_TRUE(std::filesystem::exists(new_file));
        
        // Open new file and verify content
        auto new_capture_file = create_capture_file();
        ASSERT_TRUE(new_capture_file->open(new_file));
        
        // Should now have all packets
        EXPECT_EQ(test_packets_.size(), new_capture_file->get_packet_count());
        EXPECT_TRUE(new_capture_file->is_encrypted());
        
        new_capture_file->close();
        
        // Clean up new file
        std::filesystem::remove(new_file);
    }
}

TEST_F(FileOperationsTest, SecurityManagerTempFiles) {
    // Create a secure temporary file
    std::string temp_file = security_manager_->create_secure_temp_file("test_");
    EXPECT_FALSE(temp_file.empty());
    EXPECT_TRUE(std::filesystem::exists(temp_file));
    
    // Write some data to it
    {
        std::ofstream file(temp_file);
        file << "Test secure temporary file data";
    }
    
    // Read data back
    {
        std::ifstream file(temp_file);
        std::string content((std::istreambuf_iterator<char>(file)),
                          std::istreambuf_iterator<char>());
        EXPECT_EQ("Test secure temporary file data", content);
    }
    
    // Delete the temporary file
    EXPECT_TRUE(security_manager_->delete_secure_temp_file(temp_file));
    EXPECT_FALSE(std::filesystem::exists(temp_file));
}

} // namespace integration_test
} // namespace wireshark_mcp