#include "gtest/gtest.h"
#include "common/config.h"
#include <filesystem>
#include <fstream>

namespace wireshark_mcp {
namespace test {

class ConfigTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Create test config directory if it doesn't exist
        if (!std::filesystem::exists("test_config")) {
            std::filesystem::create_directory("test_config");
        }
        test_config_file = "test_config/test_config.conf";
    }
    
    void TearDown() override {
        // Clean up test files
        if (std::filesystem::exists(test_config_file)) {
            std::filesystem::remove(test_config_file);
        }
    }
    
    void createTestConfigFile() {
        std::ofstream config_file(test_config_file);
        config_file << "# Test Config File\n";
        config_file << "application.name = Test App\n";
        config_file << "application.version = 2.0.0\n";
        config_file << "logging.level = DEBUG\n";
        config_file << "security.encryption_level = HIGH\n";
        config_file << "ui.dark_mode = true\n";
        config_file.close();
    }
    
    std::string test_config_file;
};

TEST_F(ConfigTest, GetDefaultValues) {
    auto& config = Config::getInstance();
    
    // Test default values
    EXPECT_EQ("Wireshark MCP", config.get<std::string>("application.name"));
    EXPECT_EQ("1.0.0", config.get<std::string>("application.version"));
    EXPECT_EQ("INFO", config.get<std::string>("logging.level"));
    EXPECT_EQ(true, config.get<bool>("security.encrypt_captures"));
}

TEST_F(ConfigTest, SetAndGetValues) {
    auto& config = Config::getInstance();
    
    // Set values
    config.set<std::string>("test.string", "test value");
    config.set<int>("test.int", 42);
    config.set<double>("test.double", 3.14159);
    config.set<bool>("test.bool", true);
    
    // Get values and verify
    EXPECT_EQ("test value", config.get<std::string>("test.string"));
    EXPECT_EQ(42, config.get<int>("test.int"));
    EXPECT_DOUBLE_EQ(3.14159, config.get<double>("test.double"));
    EXPECT_TRUE(config.get<bool>("test.bool"));
    
    // Test default values for keys that don't exist
    EXPECT_EQ("default", config.get<std::string>("nonexistent.key", "default"));
    EXPECT_EQ(100, config.get<int>("nonexistent.key", 100));
    EXPECT_DOUBLE_EQ(2.71828, config.get<double>("nonexistent.key", 2.71828));
    EXPECT_FALSE(config.get<bool>("nonexistent.key", false));
}

TEST_F(ConfigTest, LoadFromFile) {
    createTestConfigFile();
    
    auto& config = Config::getInstance();
    EXPECT_TRUE(config.load(test_config_file));
    
    // Verify loaded values
    EXPECT_EQ("Test App", config.get<std::string>("application.name"));
    EXPECT_EQ("2.0.0", config.get<std::string>("application.version"));
    EXPECT_EQ("DEBUG", config.get<std::string>("logging.level"));
    EXPECT_EQ("HIGH", config.get<std::string>("security.encryption_level"));
    EXPECT_TRUE(config.get<bool>("ui.dark_mode"));
}

TEST_F(ConfigTest, SaveToFile) {
    auto& config = Config::getInstance();
    
    // Set some values
    config.set<std::string>("saved.string", "saved value");
    config.set<int>("saved.int", 123);
    config.set<bool>("saved.bool", true);
    
    // Save to file
    EXPECT_TRUE(config.save(test_config_file));
    
    // Load into a new instance and verify
    Config& config2 = Config::getInstance(); // This will get the same singleton instance
    EXPECT_TRUE(config2.load(test_config_file));
    
    EXPECT_EQ("saved value", config2.get<std::string>("saved.string"));
    EXPECT_EQ(123, config2.get<int>("saved.int"));
    EXPECT_TRUE(config2.get<bool>("saved.bool"));
}

TEST_F(ConfigTest, HasKey) {
    auto& config = Config::getInstance();
    
    // Set a value
    config.set<std::string>("test.key", "test value");
    
    // Check key existence
    EXPECT_TRUE(config.hasKey("test.key"));
    EXPECT_FALSE(config.hasKey("nonexistent.key"));
}

TEST_F(ConfigTest, GetKeys) {
    auto& config = Config::getInstance();
    
    // Clear any existing keys
    // Note: This is not a public API, we just do it for testing
    for (const auto& key : config.getKeys()) {
        config.set<std::string>(key, "");
    }
    
    // Set some test keys
    config.set<std::string>("test.key1", "value1");
    config.set<string>("test.key2", "value2");
    config.set<string>("other.key", "value3");
    
    // Get all keys
    auto keys = config.getKeys();
    
    // Check that our test keys are present
    EXPECT_NE(std::find(keys.begin(), keys.end(), "test.key1"), keys.end());
    EXPECT_NE(std::find(keys.begin(), keys.end(), "test.key2"), keys.end());
    EXPECT_NE(std::find(keys.begin(), keys.end(), "other.key"), keys.end());
}

} // namespace test
} // namespace wireshark_mcp