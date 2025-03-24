#include "gtest/gtest.h"
#include "capture/packet_capture.h"
#include "security/security_manager.h"

namespace wireshark_mcp {
namespace test {

class MockSecurityManager : public SecurityManager {
public:
    static bool validateCaptureMock(const std::string& device_name) {
        // Always return true for testing
        return true;
    }
};

// Test fixture for PacketCapture
class PacketCaptureTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Redirect validate_capture_permissions to our mock
        SecurityManager::validate_capture_permissions = 
            MockSecurityManager::validateCaptureMock;
        
        capture = std::make_unique<PacketCapture>();
    }
    
    void TearDown() override {
        if (capture->is_capturing()) {
            capture->stop_capture();
        }
        capture.reset();
    }
    
    std::unique_ptr<PacketCapture> capture;
};

TEST_F(PacketCaptureTest, InitializeValidDevice) {
    // This test checks if a valid device can be initialized
    // Note: Uses a mock device for testing
    CaptureOptions options;
    options.promiscuous_mode = true;
    options.buffer_size = 1024 * 1024;
    
    bool result = capture->initialize_device("test_device", options);
    
    // Should succeed with mock security manager
    EXPECT_TRUE(result);
    EXPECT_EQ("test_device", capture->get_device_name());
    EXPECT_TRUE(options.promiscuous_mode == capture->get_options().promiscuous_mode);
    EXPECT_EQ(options.buffer_size, capture->get_options().buffer_size);
}

TEST_F(PacketCaptureTest, HandleInvalidDevice) {
    CaptureOptions options;
    
    // Test with empty device name
    bool result = capture->initialize_device("", options);
    EXPECT_FALSE(result);
    
    // Test with null options
    result = capture->initialize_device("test_device", {});
    EXPECT_TRUE(result); // Should use default options
}

TEST_F(PacketCaptureTest, StartStopCapture) {
    CaptureOptions options;
    options.promiscuous_mode = false;
    options.buffer_size = 4096;
    
    // Initialize device first
    ASSERT_TRUE(capture->initialize_device("test_device", options));
    
    // Start capture
    EXPECT_TRUE(capture->start_capture());
    EXPECT_TRUE(capture->is_capturing());
    
    // Stop capture
    EXPECT_TRUE(capture->stop_capture());
    EXPECT_FALSE(capture->is_capturing());
}

TEST_F(PacketCaptureTest, StartWithoutInitialize) {
    // Should fail to start capture without initializing a device
    EXPECT_FALSE(capture->start_capture());
    EXPECT_FALSE(capture->is_capturing());
}

TEST_F(PacketCaptureTest, StartTwice) {
    // Initialize device
    CaptureOptions options;
    ASSERT_TRUE(capture->initialize_device("test_device", options));
    
    // Start capture
    EXPECT_TRUE(capture->start_capture());
    EXPECT_TRUE(capture->is_capturing());
    
    // Try to start again (should fail)
    EXPECT_FALSE(capture->start_capture());
    
    // Clean up
    EXPECT_TRUE(capture->stop_capture());
}

TEST_F(PacketCaptureTest, StopTwice) {
    // Initialize device
    CaptureOptions options;
    ASSERT_TRUE(capture->initialize_device("test_device", options));
    
    // Start and stop capture
    EXPECT_TRUE(capture->start_capture());
    EXPECT_TRUE(capture->stop_capture());
    EXPECT_FALSE(capture->is_capturing());
    
    // Try to stop again (should not fail but return false)
    EXPECT_FALSE(capture->stop_capture());
}

TEST_F(PacketCaptureTest, FilterSettings) {
    // Initialize device
    CaptureOptions options;
    options.capture_filter = "port 80";
    ASSERT_TRUE(capture->initialize_device("test_device", options));
    
    // Check filter
    EXPECT_EQ("port 80", capture->get_options().capture_filter);
    
    // Set a new filter
    EXPECT_TRUE(capture->set_capture_filter("port 443"));
    EXPECT_EQ("port 443", capture->get_options().capture_filter);
    
    // Set invalid filter
    EXPECT_FALSE(capture->set_capture_filter("invalid ~!@ filter"));
}

TEST_F(PacketCaptureTest, CallbackRegistration) {
    // Set callbacks
    bool start_called = false;
    bool stop_called = false;
    bool packet_called = false;
    
    capture->setStartCallback([&start_called]() { start_called = true; });
    capture->setStopCallback([&stop_called]() { stop_called = true; });
    capture->setPacketCallback([&packet_called]() { packet_called = true; });
    
    // Initialize and start/stop
    CaptureOptions options;
    ASSERT_TRUE(capture->initialize_device("test_device", options));
    ASSERT_TRUE(capture->start_capture());
    
    // In a real implementation, we'd process some packets here
    // For testing, we'll manually call the packet callback
    capture->onPacketCaptured();
    
    ASSERT_TRUE(capture->stop_capture());
    
    // Check that callbacks were called
    EXPECT_TRUE(start_called);
    EXPECT_TRUE(stop_called);
    EXPECT_TRUE(packet_called);
}

} // namespace test
} // namespace wireshark_mcp