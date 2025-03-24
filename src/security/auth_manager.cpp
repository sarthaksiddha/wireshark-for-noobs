#include "auth_manager.h"
#include "../common/logging.h"
#include "../common/config.h"
#include <iostream>

namespace wireshark_mcp {

// Base auth provider interface
class AuthProvider {
public:
    virtual ~AuthProvider() = default;
    virtual AuthResult authenticate(const std::string& username, const std::string& password) = 0;
    virtual UserInfo getUserInfo(const std::string& username) = 0;
};

// Local authentication provider
class LocalAuthProvider : public AuthProvider {
public:
    LocalAuthProvider(const std::string& user_db_path) : user_db_path_(user_db_path) {
        // In a real implementation, this would load user data from a secure database
        // For this implementation, we'll just have a few hardcoded users
        
        // Add admin user
        UserInfo admin;
        admin.username = "admin";
        admin.displayName = "Administrator";
        admin.email = "admin@example.com";
        admin.roles = {"admin", "user", "capture"};
        admin.isActive = true;
        admin.isAdmin = true;
        
        // Password would be securely hashed in a real implementation
        // This is just for demonstration
        credentials_["admin"] = "admin123";
        users_["admin"] = admin;
        
        // Add regular user
        UserInfo user;
        user.username = "user";
        user.displayName = "Regular User";
        user.email = "user@example.com";
        user.roles = {"user", "capture"};
        user.isActive = true;
        user.isAdmin = false;
        
        credentials_["user"] = "user123";
        users_["user"] = user;
    }
    
    virtual AuthResult authenticate(const std::string& username, const std::string& password) override {
        // In a real implementation, this would check against properly hashed passwords
        auto it = credentials_.find(username);
        if (it == credentials_.end()) {
            return AuthResult::INVALID_CREDENTIALS;
        }
        
        if (it->second != password) {
            Log::warning("Failed login attempt for user: {}", username);
            return AuthResult::INVALID_CREDENTIALS;
        }
        
        auto user_it = users_.find(username);
        if (user_it == users_.end() || !user_it->second.isActive) {
            return AuthResult::ACCOUNT_LOCKED;
        }
        
        Log::info("User authenticated: {}", username);
        return AuthResult::SUCCESS;
    }
    
    virtual UserInfo getUserInfo(const std::string& username) override {
        auto it = users_.find(username);
        if (it != users_.end()) {
            return it->second;
        }
        
        return UserInfo(); // Empty user info
    }
    
private:
    std::string user_db_path_;
    std::map<std::string, std::string> credentials_;
    std::map<std::string, UserInfo> users_;
};

// LDAP authentication provider (simplified mock)
class LDAPAuthProvider : public AuthProvider {
public:
    LDAPAuthProvider(const std::string& server, int port, const std::string& base_dn) 
        : server_(server), port_(port), base_dn_(base_dn) {
        // This would connect to LDAP server in a real implementation
        Log::info("LDAP Auth Provider initialized with server: {}:{}", server, port);
    }
    
    virtual AuthResult authenticate(const std::string& username, const std::string& password) override {
        // This would actually perform LDAP authentication in a real implementation
        Log::info("LDAP authentication attempt for: {}", username);
        
        // Mock implementation for demonstration
        if (username == "ldap_user" && password == "ldap_pass") {
            return AuthResult::SUCCESS;
        }
        
        return AuthResult::INVALID_CREDENTIALS;
    }
    
    virtual UserInfo getUserInfo(const std::string& username) override {
        // This would query LDAP for user info in a real implementation
        if (username == "ldap_user") {
            UserInfo user;
            user.username = "ldap_user";
            user.displayName = "LDAP User";
            user.email = "ldap_user@example.com";
            user.roles = {"user", "capture"};
            user.isActive = true;
            user.isAdmin = false;
            return user;
        }
        
        return UserInfo(); // Empty user info
    }
    
private:
    std::string server_;
    int port_;
    std::string base_dn_;
};

// AuthManager implementation
AuthManager::AuthManager() 
    : authenticated_(false), 
      current_method_(AuthMethod::LOCAL) {
}

AuthManager::~AuthManager() {
    // Clean up
}

AuthManager& AuthManager::getInstance() {
    static AuthManager instance;
    return instance;
}

bool AuthManager::initialize(const std::string& config_path) {
    Log::info("Initializing authentication manager");
    
    // Load auth configuration
    auto& config = Config::getInstance();
    if (!config_path.empty()) {
        config.load(config_path);
    }
    
    // Initialize authentication providers
    return loadAuthProviders();
}

bool AuthManager::loadAuthProviders() {
    auto& config = Config::getInstance();
    
    // Clear existing providers
    auth_providers_.clear();
    
    // Add local auth provider
    std::string user_db_path = config.get<std::string>("security.local_user_db", "users.db");
    auth_providers_[AuthMethod::LOCAL] = std::make_unique<LocalAuthProvider>(user_db_path);
    
    // Add LDAP auth provider if configured
    if (config.get<bool>("security.ldap.enabled", false)) {
        std::string server = config.get<std::string>("security.ldap.server", "");
        int port = config.get<int>("security.ldap.port", 389);
        std::string base_dn = config.get<std::string>("security.ldap.base_dn", "");
        
        if (!server.empty() && !base_dn.empty()) {
            auth_providers_[AuthMethod::LDAP] = std::make_unique<LDAPAuthProvider>(server, port, base_dn);
            Log::info("LDAP authentication enabled");
        }
    }
    
    // Set default auth method
    std::string default_method = config.get<std::string>("security.default_auth_method", "LOCAL");
    if (default_method == "LDAP" && auth_providers_.find(AuthMethod::LDAP) != auth_providers_.end()) {
        current_method_ = AuthMethod::LDAP;
    } else {
        current_method_ = AuthMethod::LOCAL;
    }
    
    return !auth_providers_.empty();
}

AuthResult AuthManager::authenticate_user(const std::string& username, const std::string& password) {
    // Find the appropriate auth provider
    auto it = auth_providers_.find(current_method_);
    if (it == auth_providers_.end()) {
        Log::error("No authentication provider available for method: {}", 
                  static_cast<int>(current_method_));
        return AuthResult::UNKNOWN_ERROR;
    }
    
    // Attempt authentication
    AuthResult result = it->second->authenticate(username, password);
    
    if (result == AuthResult::SUCCESS) {
        authenticated_ = true;
        current_user_ = it->second->getUserInfo(username);
        
        // Set basic permissions based on roles
        permissions_.clear();
        for (const auto& role : current_user_.roles) {
            if (role == "admin") {
                permissions_["admin"] = true;
                permissions_["capture"] = true;
                permissions_["analyze"] = true;
            } else if (role == "capture") {
                permissions_["capture"] = true;
            } else if (role == "user") {
                permissions_["analyze"] = true;
            }
        }
        
        // Notify any listeners
        if (auth_status_changed_callback_) {
            auth_status_changed_callback_(true);
        }
        
        Log::info("User successfully authenticated: {}", username);
    } else {
        Log::warning("Authentication failed for user: {}, reason: {}", 
                    username, static_cast<int>(result));
    }
    
    return result;
}

bool AuthManager::hasCapturePemission() const {
    if (!authenticated_) return false;
    
    auto it = permissions_.find("capture");
    return (it != permissions_.end() && it->second);
}

bool AuthManager::hasAdminPermission() const {
    if (!authenticated_) return false;
    
    auto it = permissions_.find("admin");
    return (it != permissions_.end() && it->second);
}

bool AuthManager::hasPermission(const std::string& permission) const {
    if (!authenticated_) return false;
    
    auto it = permissions_.find(permission);
    return (it != permissions_.end() && it->second);
}

bool AuthManager::isAuthenticated() const {
    return authenticated_;
}

void AuthManager::logout() {
    authenticated_ = false;
    current_user_ = UserInfo();
    permissions_.clear();
    
    // Notify any listeners
    if (auth_status_changed_callback_) {
        auth_status_changed_callback_(false);
    }
    
    Log::info("User logged out");
}

UserInfo AuthManager::getCurrentUser() const {
    return current_user_;
}

void AuthManager::setAuthStatusChangeCallback(std::function<void(bool)> callback) {
    auth_status_changed_callback_ = callback;
}

} // namespace wireshark_mcp