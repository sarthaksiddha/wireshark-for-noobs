#include "gtest/gtest.h"
#include "common/logging.h"
#include <iostream>

int main(int argc, char **argv) {
    std::cout << "Running Wireshark MCP Integration Tests" << std::endl;
    
    // Initialize logging for tests
    wireshark_mcp::Log::initialize("integration_tests.log", wireshark_mcp::LogLevel::DEBUG);
    wireshark_mcp::Log::info("Starting integration tests");
    
    // Initialize Google Test
    testing::InitGoogleTest(&argc, argv);
    
    // Run all tests
    int result = RUN_ALL_TESTS();
    
    wireshark_mcp::Log::info("Finished integration tests with result: {}", result);
    
    return result;
}