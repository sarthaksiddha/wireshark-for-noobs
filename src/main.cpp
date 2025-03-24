#include <QApplication>
#include "ui/main_window.h"
#include "common/logging.h"
#include "security/auth_manager.h"

int main(int argc, char *argv[]) {
    // Initialize logging
    wireshark_mcp::Log::initialize("wireshark_mcp.log");
    wireshark_mcp::Log::info("Wireshark MCP starting up...");
    
    // Initialize application
    QApplication app(argc, argv);
    app.setApplicationName("Wireshark MCP");
    app.setOrganizationName("Corporate Network Security");
    
    // Initialize authentication system
    wireshark_mcp::AuthManager authManager;
    if (!authManager.initialize()) {
        wireshark_mcp::Log::error("Failed to initialize authentication system");
        return 1;
    }
    
    // Create and show main window
    wireshark_mcp::MainWindow mainWindow;
    mainWindow.show();
    
    // Run the application
    wireshark_mcp::Log::info("Wireshark MCP UI initialized");
    return app.exec();
}
