#ifndef WIRESHARK_MCP_AUTH_MANAGER_H
#define WIRESHARK_MCP_AUTH_MANAGER_H

#include <string>
#include <map>
#include <memory>
#include <vector>
#include <functional>

namespace wireshark_mcp {

enum class AuthMethod {
    LOCAL,
    LDAP,
    OAUTH,
    KERBEROS
};

enum class AuthResult {
    SUCCESS,
    INVALID_CREDENTIALS,
    ACCOUNT_LOCKED,
    ACCOUNT_EXPIRED,
    CONNECTION_ERROR,
    PERMISSION_DENIED,
    UNKNOWN_ERROR
};

struct UserInfo {
    std::string username;
    std::string displayName;
    std::string email;
    std::vector<std::string> roles;
    bool isActive;
    bool isAdmin;
};

// Forward declaration for AuthProvider interface
class AuthProvider;

class AuthManager {
public:
    static AuthManager& getInstance();
    
    // Delete copy constructor and assignment operator
    AuthManager(const AuthManager&) = delete;
    AuthManager& operator=(const AuthManager&) = delete;
    
    bool initialize(const std::string& config_path);
    
    // Main authentication method
    AuthResult authenticate_user(const std::string& username, const std::string& password);
    
    // Permission checks
    bool hasCapturePemission() const;
    bool hasAdminPermission() const;
    bool hasPermission(const std::string& permission) const;
    
    // User session management
    bool isAuthenticated() const;
    void logout();
    
    // User information
    UserInfo getCurrentUser() const;
    
    // For event handling (e.g., UI updates)
    void setAuthStatusChangeCallback(std::function<void(bool)> callback);
    
private:
    AuthManager();
    ~AuthManager();
    
    bool loadAuthProviders();
    
    // Authentication state
    bool authenticated_;
    UserInfo current_user_;
    std::map<std::string, bool> permissions_;
    
    // Authentication providers
    std::map<AuthMethod, std::unique_ptr<AuthProvider>> auth_providers_;
    AuthMethod current_method_;
    
    // Callback for status changes
    std::function<void(bool)> auth_status_changed_callback_;
};

} // namespace wireshark_mcp

#endif // WIRESHARK_MCP_AUTH_MANAGER_H