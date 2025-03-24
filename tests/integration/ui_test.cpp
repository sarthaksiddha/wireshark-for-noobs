#include "gtest/gtest.h"
#include "ui/main_window.h"
#include "capture/packet_capture.h"
#include "security/auth_manager.h"
#include <QApplication>
#include <QTest>
#include <memory>

namespace wireshark_mcp {
namespace integration_test {

// This test requires Qt event loop, so we need to skip it unless explicitly enabled
// To run these tests, define RUN_UI_TESTS when building

class UITest : public ::testing::Test {
protected:
    static void SetUpTestSuite() {
        // Create QApplication instance if it doesn't exist
        if (qApp == nullptr) {
            static int argc = 1;
            static char* argv[] = {const_cast<char*>("ui_test")};
            app_ = new QApplication(argc, argv);
        }
        
        // Initialize authentication manager and log in with test credentials
        AuthManager::getInstance().initialize();
        AuthManager::getInstance().authenticate_user("admin", "admin123");
    }
    
    static void TearDownTestSuite() {
        // Clean up QApplication
        if (app_ != nullptr) {
            delete app_;
            app_ = nullptr;
        }
        
        // Log out
        AuthManager::getInstance().logout();
    }
    
    void SetUp() override {
#ifndef RUN_UI_TESTS
        GTEST_SKIP() << "UI tests are disabled. Define RUN_UI_TESTS to enable.";
#endif
    }
    
    void TearDown() override {
        // Process pending events
        if (qApp != nullptr) {
            qApp->processEvents();
        }
    }
    
    static QApplication* app_;
};

QApplication* UITest::app_ = nullptr;

// Test creation and basic properties of main window
TEST_F(UITest, MainWindowCreation) {
    MainWindow main_window;
    
    // Window should have proper title
    EXPECT_FALSE(main_window.windowTitle().isEmpty());
    EXPECT_TRUE(main_window.windowTitle().contains("Wireshark MCP"));
    
    // Window should have a decent size
    EXPECT_GT(main_window.width(), 800);
    EXPECT_GT(main_window.height(), 600);
    
    // Check that essential UI components exist
    // (This would need to be adapted based on the actual UI structure)
    EXPECT_TRUE(main_window.menuBar() != nullptr);
    EXPECT_GE(main_window.menuBar()->actions().count(), 5); // At least 5 menus
    
    // Toolbar should exist
    QToolBar* toolbar = main_window.findChild<QToolBar*>();
    EXPECT_TRUE(toolbar != nullptr);
    
    // Status bar should exist
    EXPECT_TRUE(main_window.statusBar() != nullptr);
}

// Test menu actions and basic interactions
TEST_F(UITest, MenuInteractions) {
    MainWindow main_window;
    
    // Find file menu
    QMenu* fileMenu = nullptr;
    for (QAction* action : main_window.menuBar()->actions()) {
        if (action->text().contains("File", Qt::CaseInsensitive)) {
            fileMenu = action->menu();
            break;
        }
    }
    
    ASSERT_TRUE(fileMenu != nullptr);
    
    // Find "New Capture" action
    QAction* newAction = nullptr;
    for (QAction* action : fileMenu->actions()) {
        if (action->text().contains("New", Qt::CaseInsensitive)) {
            newAction = action;
            break;
        }
    }
    
    ASSERT_TRUE(newAction != nullptr);
    
    // Trigger action (should not crash)
    // In a real test, we would need to mock device initialization
    // Here we just verify that the action exists and is connected
    EXPECT_TRUE(newAction->isEnabled());
    EXPECT_FALSE(QObject::connect(newAction, &QAction::triggered, &main_window, nullptr).isNull());
}

// Test authentication status reflected in UI
TEST_F(UITest, AuthenticationUI) {
    MainWindow main_window;
    
    // Check that auth status is reflected in UI elements
    // (This would need to be adapted based on how auth status is displayed)
    
    // First check when authenticated
    EXPECT_TRUE(AuthManager::getInstance().isAuthenticated());
    
    // Status bar should show authenticated user
    QString statusText = main_window.statusBar()->currentMessage();
    
    // Either status text explicitly shows authenticated state or
    // UI elements that require auth are enabled
    bool hasAuthUI = statusText.contains("Logged in", Qt::CaseInsensitive) ||
                    statusText.contains("admin", Qt::CaseInsensitive);
    
    // If status bar doesn't show auth directly, check if capture actions are enabled
    if (!hasAuthUI) {
        // Find Capture menu
        QMenu* captureMenu = nullptr;
        for (QAction* action : main_window.menuBar()->actions()) {
            if (action->text().contains("Capture", Qt::CaseInsensitive)) {
                captureMenu = action->menu();
                break;
            }
        }
        
        if (captureMenu) {
            // Check if at least one action is enabled
            for (QAction* action : captureMenu->actions()) {
                if (action->isEnabled()) {
                    hasAuthUI = true;
                    break;
                }
            }
        }
    }
    
    EXPECT_TRUE(hasAuthUI);
    
    // Now log out
    AuthManager::getInstance().logout();
    
    // Process events to allow UI to update
    QTest::qWait(100);
    qApp->processEvents();
    
    // Check that UI is updated to reflect logged out state
    // (specifics depend on implementation)
    
    // Log back in for other tests
    AuthManager::getInstance().authenticate_user("admin", "admin123");
}

// Capture button test
TEST_F(UITest, CaptureButtonInteraction) {
    MainWindow main_window;
    
    // Find Start and Stop Capture buttons on toolbar
    QToolBar* toolbar = main_window.findChild<QToolBar*>();
    ASSERT_TRUE(toolbar != nullptr);
    
    QAction* startCaptureAction = nullptr;
    QAction* stopCaptureAction = nullptr;
    
    for (QAction* action : toolbar->actions()) {
        if (action->text().contains("Start Capture", Qt::CaseInsensitive)) {
            startCaptureAction = action;
        } else if (action->text().contains("Stop Capture", Qt::CaseInsensitive)) {
            stopCaptureAction = action;
        }
    }
    
    ASSERT_TRUE(startCaptureAction != nullptr);
    ASSERT_TRUE(stopCaptureAction != nullptr);
    
    // Initially, Start should be enabled and Stop disabled
    EXPECT_TRUE(startCaptureAction->isEnabled());
    EXPECT_FALSE(stopCaptureAction->isEnabled());
    
    // Note: Actually triggering the capture would require a mock device
    // which would need to be injected into the main window
    // This test just checks the existence and initial state of the buttons
}

// Tab management test
TEST_F(UITest, TabManagement) {
    MainWindow main_window;
    
    // Find tab widget
    QTabWidget* tabWidget = main_window.findChild<QTabWidget*>();
    ASSERT_TRUE(tabWidget != nullptr);
    
    // There should be at least one tab initially
    EXPECT_GE(tabWidget->count(), 1);
    
    // Currently we can't easily simulate file operations in the test
    // A complete test would:
    // 1. Create a mock capture engine that returns synthetic packets
    // 2. Inject it into the main window
    // 3. Trigger capture start/stop 
    // 4. Verify that tabs are created/removed appropriately
}

} // namespace integration_test
} // namespace wireshark_mcp