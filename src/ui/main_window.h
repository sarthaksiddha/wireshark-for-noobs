#ifndef WIRESHARK_MCP_MAIN_WINDOW_H
#define WIRESHARK_MCP_MAIN_WINDOW_H

#include <QMainWindow>
#include <memory>

class QAction;
class QMenu;
class QToolBar;
class QDockWidget;
class QTabWidget;
class QStatusBar;

namespace wireshark_mcp {

class PacketCapture;
class AuthManager;
class CaptureFile;

class MainWindow : public QMainWindow {
    Q_OBJECT

public:
    explicit MainWindow(QWidget* parent = nullptr);
    ~MainWindow();

private slots:
    // File menu actions
    void on_newCapture_triggered();
    void on_openCapture_triggered();
    void on_saveCapture_triggered();
    void on_saveAsCapture_triggered();
    void on_exportPackets_triggered();
    void on_printCapture_triggered();
    void on_exit_triggered();
    
    // Capture menu actions
    void on_startCapture_clicked();
    void on_stopCapture_clicked();
    void on_captureOptions_triggered();
    void on_captureFilters_triggered();
    
    // View menu actions
    void on_timeFormat_triggered();
    void on_colorRules_triggered();
    void on_fontSettings_triggered();
    void on_preferences_triggered();
    
    // Analysis menu actions
    void on_displayFilters_triggered();
    void on_conversations_triggered();
    void on_endpoints_triggered();
    void on_flowGraph_triggered();
    
    // Statistics menu actions
    void on_protocolHierarchy_triggered();
    void on_conversationList_triggered();
    void on_endpointList_triggered();
    void on_serviceResponseTime_triggered();
    
    // Help menu actions
    void on_about_triggered();
    void on_userGuide_triggered();
    
    // Authentication handler
    void onAuthStatusChanged(bool authenticated);
    
    // Packet capture handlers
    void onCaptureStarted();
    void onCaptureStopped();
    void onPacketCaptured();

private:
    void setupUi();
    void initialize_components();
    void createActions();
    void createMenus();
    void createToolBars();
    void createStatusBar();
    void createDockWidgets();
    
    void showPermissionDeniedDialog();
    void updateUIState();
    
    // Action groups
    QMenu* fileMenu;
    QMenu* editMenu;
    QMenu* viewMenu;
    QMenu* captureMenu;
    QMenu* analysisMenu;
    QMenu* statisticsMenu;
    QMenu* helpMenu;
    
    // Toolbar actions
    QAction* newAction;
    QAction* openAction;
    QAction* saveAction;
    QAction* startCaptureAction;
    QAction* stopCaptureAction;
    QAction* filterAction;
    QAction* preferencesAction;
    
    // Main UI components
    QToolBar* mainToolBar;
    QTabWidget* packetListTabs;
    QDockWidget* packetDetailsDock;
    QDockWidget* packetBytesDock;
    QStatusBar* statusBar;
    
    // Application components
    std::shared_ptr<PacketCapture> captureEngine;
    std::shared_ptr<CaptureFile> currentCaptureFile;
    
    // Manager instances
    AuthManager* m_authManager;
    
    // State
    bool isCapturing;
    bool hasUnsavedChanges;
};

} // namespace wireshark_mcp

#endif // WIRESHARK_MCP_MAIN_WINDOW_H