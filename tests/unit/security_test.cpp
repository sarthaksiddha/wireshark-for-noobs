#include "gtest/gtest.h"
#include "security/auth_manager.h"
#include "security/security_manager.h"
#include <filesystem>
#include <fstream>

namespace wireshark_mcp {
namespace test {

class AuthManagerTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Get auth manager instance
        auth_manager = &AuthManager::getInstance();
        
        // Initialize with default settings
        auth_manager->initialize();
    }
    
    void TearDown() override {
        // Logout if authenticated
        if (auth_manager->isAuthenticated()) {
            auth_manager->logout();
        }
    }
    
    AuthManager* auth_manager;
};

class SecurityManagerTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Create test directory if it doesn't exist
        if (!std::filesystem::exists("test_security")) {
            std::filesystem::create_directory("test_security");
        }
        
        test_file = "test_security/test_file.txt";
        encrypted_file = "test_security/test_file.encrypted";
        decrypted_file = "test_security/test_file.decrypted";
        
        // Create a test file
        std::ofstream file(test_file);
        file << "This is test data that should be encrypted and decrypted.\n";
        file << "It contains some sensitive information: password123\n";
        file.close();
        
        // Get security manager instance
        security_manager = &SecurityManager::getInstance();
        
        // Initialize with default settings
        security_manager->initialize();
    }
    
    void TearDown() override {
        // Clean up test files
        if (std::filesystem::exists(test_file)) {
            std::filesystem::remove(test_file);
        }
        if (std::filesystem::exists(encrypted_file)) {
            std::filesystem::remove(encrypted_file);
        }
        if (std::filesystem::exists(decrypted_file)) {
            std::filesystem::remove(decrypted_file);
        }
    }
    
    std::string test_file;
    std::string encrypted_file;
    std::string decrypted_file;
    SecurityManager* security_manager;
};

// Auth Manager Tests
TEST_F(AuthManagerTest, AuthenticateValidUser) {
    // Test with valid admin credentials
    AuthResult result = auth_manager->authenticate_user("admin", "admin123");
    EXPECT_EQ(AuthResult::SUCCESS, result);
    EXPECT_TRUE(auth_manager->isAuthenticated());
    
    // Check permissions
    EXPECT_TRUE(auth_manager->hasCapturePemission());
    EXPECT_TRUE(auth_manager->hasAdminPermission());
    EXPECT_TRUE(auth_manager->hasPermission("capture"));
    EXPECT_TRUE(auth_manager->hasPermission("admin"));
    
    // Check user info
    UserInfo user = auth_manager->getCurrentUser();
    EXPECT_EQ("admin", user.username);
    EXPECT_EQ("Administrator", user.displayName);
    EXPECT_TRUE(user.isAdmin);
}

TEST_F(AuthManagerTest, AuthenticateRegularUser) {
    // Test with regular user credentials
    AuthResult result = auth_manager->authenticate_user("user", "user123");
    EXPECT_EQ(AuthResult::SUCCESS, result);
    EXPECT_TRUE(auth_manager->isAuthenticated());
    
    // Check permissions
    EXPECT_TRUE(auth_manager->hasCapturePemission());
    EXPECT_FALSE(auth_manager->hasAdminPermission());
    EXPECT_TRUE(auth_manager->hasPermission("capture"));
    EXPECT_FALSE(auth_manager->hasPermission("admin"));
    
    // Check user info
    UserInfo user = auth_manager->getCurrentUser();
    EXPECT_EQ("user", user.username);
    EXPECT_EQ("Regular User", user.displayName);
    EXPECT_FALSE(user.isAdmin);
}

TEST_F(AuthManagerTest, AuthenticateInvalidUser) {
    // Test with invalid username
    AuthResult result = auth_manager->authenticate_user("nonexistent", "password");
    EXPECT_EQ(AuthResult::INVALID_CREDENTIALS, result);
    EXPECT_FALSE(auth_manager->isAuthenticated());
    
    // Test with invalid password
    result = auth_manager->authenticate_user("admin", "wrongpassword");
    EXPECT_EQ(AuthResult::INVALID_CREDENTIALS, result);
    EXPECT_FALSE(auth_manager->isAuthenticated());
}

TEST_F(AuthManagerTest, LogoutTest) {
    // First login
    AuthResult result = auth_manager->authenticate_user("admin", "admin123");
    EXPECT_EQ(AuthResult::SUCCESS, result);
    EXPECT_TRUE(auth_manager->isAuthenticated());
    
    // Then logout
    auth_manager->logout();
    EXPECT_FALSE(auth_manager->isAuthenticated());
    
    // Check permissions after logout
    EXPECT_FALSE(auth_manager->hasCapturePemission());
    EXPECT_FALSE(auth_manager->hasAdminPermission());
    EXPECT_FALSE(auth_manager->hasPermission("capture"));
}

TEST_F(AuthManagerTest, AuthStatusChangeCallback) {
    bool callback_called = false;
    bool auth_status = false;
    
    // Set callback
    auth_manager->setAuthStatusChangeCallback([&](bool authenticated) {
        callback_called = true;
        auth_status = authenticated;
    });
    
    // Login
    auth_manager->authenticate_user("admin", "admin123");
    EXPECT_TRUE(callback_called);
    EXPECT_TRUE(auth_status);
    
    // Reset for testing logout
    callback_called = false;
    auth_status = true;
    
    // Logout
    auth_manager->logout();
    EXPECT_TRUE(callback_called);
    EXPECT_FALSE(auth_status);
}

// Security Manager Tests
TEST_F(SecurityManagerTest, EncryptDecryptFile) {
    // Test encryption
    EXPECT_TRUE(security_manager->encrypt_file(test_file, encrypted_file));
    EXPECT_TRUE(std::filesystem::exists(encrypted_file));
    
    // Check that encrypted file is different from original
    std::ifstream original(test_file);
    std::string original_content((std::istreambuf_iterator<char>(original)),
                             std::istreambuf_iterator<char>());
    original.close();
    
    std::ifstream encrypted(encrypted_file);
    std::string encrypted_content((std::istreambuf_iterator<char>(encrypted)),
                             std::istreambuf_iterator<char>());
    encrypted.close();
    
    EXPECT_NE(original_content, encrypted_content);
    
    // Test decryption
    EXPECT_TRUE(security_manager->decrypt_file(encrypted_file, decrypted_file));
    EXPECT_TRUE(std::filesystem::exists(decrypted_file));
    
    // Check that decrypted file matches original
    std::ifstream decrypted(decrypted_file);
    std::string decrypted_content((std::istreambuf_iterator<char>(decrypted)),
                             std::istreambuf_iterator<char>());
    decrypted.close();
    
    EXPECT_EQ(original_content, decrypted_content);
}

TEST_F(SecurityManagerTest, EncryptionLevels) {
    // Test different encryption levels
    EXPECT_TRUE(security_manager->encrypt_file(test_file, encrypted_file, EncryptionLevel::BASIC));
    EXPECT_TRUE(std::filesystem::exists(encrypted_file));
    std::filesystem::remove(encrypted_file);
    
    EXPECT_TRUE(security_manager->encrypt_file(test_file, encrypted_file, EncryptionLevel::STANDARD));
    EXPECT_TRUE(std::filesystem::exists(encrypted_file));
    std::filesystem::remove(encrypted_file);
    
    EXPECT_TRUE(security_manager->encrypt_file(test_file, encrypted_file, EncryptionLevel::HIGH));
    EXPECT_TRUE(std::filesystem::exists(encrypted_file));
    
    // Test changing encryption level
    EXPECT_EQ(EncryptionLevel::STANDARD, security_manager->get_encryption_level());
    security_manager->set_encryption_level(EncryptionLevel::HIGH);
    EXPECT_EQ(EncryptionLevel::HIGH, security_manager->get_encryption_level());
}

TEST_F(SecurityManagerTest, SecureTempFiles) {
    // Test creating secure temp file
    std::string temp_file = security_manager->create_secure_temp_file("test_");
    EXPECT_FALSE(temp_file.empty());
    EXPECT_TRUE(std::filesystem::exists(temp_file));
    
    // Test writing to temp file
    std::ofstream temp(temp_file);
    temp << "Test data in temporary file";
    temp.close();
    
    // Test deleting temp file
    EXPECT_TRUE(security_manager->delete_secure_temp_file(temp_file));
    EXPECT_FALSE(std::filesystem::exists(temp_file));
}

TEST_F(SecurityManagerTest, DevicePermissions) {
    // Test device permissions
    EXPECT_TRUE(security_manager->is_device_allowed("eth0")); // Default should allow all
    
    // Add a device
    security_manager->add_allowed_device("eth1");
    EXPECT_TRUE(security_manager->is_device_allowed("eth1"));
    
    // Add another device
    security_manager->add_allowed_device("eth2");
    EXPECT_TRUE(security_manager->is_device_allowed("eth2"));
    
    // Check duplicate add
    security_manager->add_allowed_device("eth1");
    EXPECT_TRUE(security_manager->is_device_allowed("eth1"));
}

} // namespace test
} // namespace wireshark_mcp