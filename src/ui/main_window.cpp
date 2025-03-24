#include "main_window.h"
#include "../capture/packet_capture.h"
#include "../security/auth_manager.h"
#include "../storage/capture_file.h"
#include "../common/logging.h"
#include "../common/config.h"

#include <QAction>
#include <QMenu>
#include <QMenuBar>
#include <QToolBar>
#include <QStatusBar>
#include <QDockWidget>
#include <QTabWidget>
#include <QTableView>
#include <QTreeView>
#include <QTextEdit>
#include <QFileDialog>
#include <QMessageBox>
#include <QApplication>
#include <QLabel>
#include <QComboBox>
#include <QPushButton>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QSplitter>
#include <QDateTime>

namespace wireshark_mcp {

MainWindow::MainWindow(QWidget* parent)
    : QMainWindow(parent),
      isCapturing(false),
      hasUnsavedChanges(false) {
    
    // Initialize auth manager
    m_authManager = &AuthManager::getInstance();
    m_authManager->initialize();
    
    // Set up UI
    setupUi();
    initialize_components();
    
    // Connect auth status change
    m_authManager->setAuthStatusChangeCallback(
        [this](bool authenticated) { onAuthStatusChanged(authenticated); }
    );
    
    // Update UI state
    updateUIState();
    
    // Show login dialog if needed
    if (!m_authManager->isAuthenticated()) {
        // In a real implementation, show a login dialog here
        // For demo purposes, we'll auto-login with admin credentials
        m_authManager->authenticate_user("admin", "admin123");
    }
}

MainWindow::~MainWindow() {
    // Clean up
    if (isCapturing) {
        captureEngine->stop_capture();
    }
}

void MainWindow::setupUi() {
    // Set window properties
    setWindowTitle("Wireshark MCP");
    resize(1200, 800);
    
    // Create actions, menus, toolbars, etc.
    createActions();
    createMenus();
    createToolBars();
    createStatusBar();
    
    // Create central widget with tab layout
    packetListTabs = new QTabWidget(this);
    packetListTabs->setTabsClosable(true);
    setCentralWidget(packetListTabs);
    
    // Create packet details dock widget
    packetDetailsDock = new QDockWidget("Packet Details", this);
    packetDetailsDock->setAllowedAreas(Qt::AllDockWidgetAreas);
    
    QTreeView* packetDetailsView = new QTreeView(packetDetailsDock);
    packetDetailsDock->setWidget(packetDetailsView);
    addDockWidget(Qt::BottomDockWidgetArea, packetDetailsDock);
    
    // Create packet bytes dock widget
    packetBytesDock = new QDockWidget("Packet Bytes", this);
    packetBytesDock->setAllowedAreas(Qt::AllDockWidgetAreas);
    
    QTextEdit* packetBytesView = new QTextEdit(packetBytesDock);
    packetBytesView->setReadOnly(true);
    packetBytesView->setFont(QFont("Courier", 10));
    packetBytesDock->setWidget(packetBytesView);
    addDockWidget(Qt::BottomDockWidgetArea, packetBytesDock);
    
    // Set up initial capture tab
    QWidget* initialTab = new QWidget();
    QVBoxLayout* tabLayout = new QVBoxLayout(initialTab);
    
    QLabel* welcomeLabel = new QLabel("Welcome to Wireshark MCP");
    welcomeLabel->setAlignment(Qt::AlignCenter);
    welcomeLabel->setStyleSheet("font-size: 18px; margin: 20px;");
    
    QPushButton* startCaptureBtn = new QPushButton("Start New Capture");
    QPushButton* openCaptureBtn = new QPushButton("Open Existing Capture");
    
    connect(startCaptureBtn, &QPushButton::clicked, this, &MainWindow::on_startCapture_clicked);
    connect(openCaptureBtn, &QPushButton::clicked, this, &MainWindow::on_openCapture_triggered);
    
    tabLayout->addWidget(welcomeLabel);
    tabLayout->addStretch();
    tabLayout->addWidget(startCaptureBtn);
    tabLayout->addWidget(openCaptureBtn);
    tabLayout->addStretch();
    
    packetListTabs->addTab(initialTab, "Start Page");
    packetListTabs->setTabsClosable(false);
}

void MainWindow::initialize_components() {
    // Create capture engine
    captureEngine = std::make_shared<PacketCapture>();
    
    // Connect capture signals (would use signals/slots in real Qt implementation)
    captureEngine->setStartCallback([this]() { onCaptureStarted(); });
    captureEngine->setStopCallback([this]() { onCaptureStopped(); });
    captureEngine->setPacketCallback([this]() { onPacketCaptured(); });
    
    // Create initial capture file
    currentCaptureFile = create_capture_file();
}

void MainWindow::createActions() {
    // File actions
    newAction = new QAction("&New Capture", this);
    newAction->setShortcut(QKeySequence::New);
    connect(newAction, &QAction::triggered, this, &MainWindow::on_newCapture_triggered);
    
    openAction = new QAction("&Open Capture", this);
    openAction->setShortcut(QKeySequence::Open);
    connect(openAction, &QAction::triggered, this, &MainWindow::on_openCapture_triggered);
    
    saveAction = new QAction("&Save Capture", this);
    saveAction->setShortcut(QKeySequence::Save);
    connect(saveAction, &QAction::triggered, this, &MainWindow::on_saveCapture_triggered);
    
    // Capture actions
    startCaptureAction = new QAction("Start Capture", this);
    connect(startCaptureAction, &QAction::triggered, this, &MainWindow::on_startCapture_clicked);
    
    stopCaptureAction = new QAction("Stop Capture", this);
    stopCaptureAction->setEnabled(false);
    connect(stopCaptureAction, &QAction::triggered, this, &MainWindow::on_stopCapture_clicked);
    
    // Other actions
    filterAction = new QAction("Display Filter", this);
    preferencesAction = new QAction("Preferences", this);
    connect(preferencesAction, &QAction::triggered, this, &MainWindow::on_preferences_triggered);
}

void MainWindow::createMenus() {
    // File menu
    fileMenu = menuBar()->addMenu("&File");
    fileMenu->addAction(newAction);
    fileMenu->addAction(openAction);
    fileMenu->addAction(saveAction);
    fileMenu->addSeparator();
    fileMenu->addAction("Export Packets...", this, &MainWindow::on_exportPackets_triggered);
    fileMenu->addAction("Print...", this, &MainWindow::on_printCapture_triggered);
    fileMenu->addSeparator();
    fileMenu->addAction("Exit", this, &MainWindow::on_exit_triggered, QKeySequence::Quit);
    
    // Edit menu
    editMenu = menuBar()->addMenu("&Edit");
    editMenu->addAction("Copy", this, nullptr, QKeySequence::Copy);
    editMenu->addAction("Find Packet...", this, nullptr, QKeySequence::Find);
    
    // View menu
    viewMenu = menuBar()->addMenu("&View");
    viewMenu->addAction("Time Display Format...", this, &MainWindow::on_timeFormat_triggered);
    viewMenu->addAction("Coloring Rules...", this, &MainWindow::on_colorRules_triggered);
    viewMenu->addAction("Font Settings...", this, &MainWindow::on_fontSettings_triggered);
    viewMenu->addSeparator();
    viewMenu->addAction(preferencesAction);
    
    // Capture menu
    captureMenu = menuBar()->addMenu("&Capture");
    captureMenu->addAction(startCaptureAction);
    captureMenu->addAction(stopCaptureAction);
    captureMenu->addSeparator();
    captureMenu->addAction("Options...", this, &MainWindow::on_captureOptions_triggered);
    captureMenu->addAction("Capture Filters...", this, &MainWindow::on_captureFilters_triggered);
    
    // Analysis menu
    analysisMenu = menuBar()->addMenu("&Analysis");
    analysisMenu->addAction("Display Filters...", this, &MainWindow::on_displayFilters_triggered);
    analysisMenu->addAction("Conversations", this, &MainWindow::on_conversations_triggered);
    analysisMenu->addAction("Endpoints", this, &MainWindow::on_endpoints_triggered);
    analysisMenu->addAction("Flow Graph", this, &MainWindow::on_flowGraph_triggered);
    
    // Statistics menu
    statisticsMenu = menuBar()->addMenu("&Statistics");
    statisticsMenu->addAction("Protocol Hierarchy", this, &MainWindow::on_protocolHierarchy_triggered);
    statisticsMenu->addAction("Conversation List", this, &MainWindow::on_conversationList_triggered);
    statisticsMenu->addAction("Endpoint List", this, &MainWindow::on_endpointList_triggered);
    statisticsMenu->addAction("Service Response Time", this, &MainWindow::on_serviceResponseTime_triggered);
    
    // Help menu
    helpMenu = menuBar()->addMenu("&Help");
    helpMenu->addAction("User Guide", this, &MainWindow::on_userGuide_triggered);
    helpMenu->addSeparator();
    helpMenu->addAction("About Wireshark MCP", this, &MainWindow::on_about_triggered);
}

void MainWindow::createToolBars() {
    mainToolBar = addToolBar("Main Toolbar");
    mainToolBar->addAction(newAction);
    mainToolBar->addAction(openAction);
    mainToolBar->addAction(saveAction);
    mainToolBar->addSeparator();
    mainToolBar->addAction(startCaptureAction);
    mainToolBar->addAction(stopCaptureAction);
    mainToolBar->addSeparator();
    
    // Add filter combobox
    QComboBox* filterCombo = new QComboBox(this);
    filterCombo->setEditable(true);
    filterCombo->setMinimumWidth(300);
    filterCombo->setPlaceholderText("Display filter");
    mainToolBar->addWidget(filterCombo);
    
    QPushButton* applyFilterBtn = new QPushButton("Apply", this);
    mainToolBar->addWidget(applyFilterBtn);
    
    mainToolBar->addSeparator();
    mainToolBar->addAction(preferencesAction);
}

void MainWindow::createStatusBar() {
    // Create status bar labels
    QLabel* captureStatusLabel = new QLabel("Ready");
    QLabel* packetCountLabel = new QLabel("Packets: 0");
    QLabel* deviceLabel = new QLabel("No device selected");
    
    // Add to status bar
    statusBar()->addWidget(captureStatusLabel, 1);
    statusBar()->addPermanentWidget(packetCountLabel);
    statusBar()->addPermanentWidget(deviceLabel);
}

// Slot implementations
void MainWindow::onAuthStatusChanged(bool authenticated) {
    updateUIState();
    
    if (authenticated) {
        UserInfo user = m_authManager->getCurrentUser();
        statusBar()->showMessage(QString("Logged in as: %1").arg(user.displayName.c_str()), 5000);
    } else {
        statusBar()->showMessage("Not authenticated", 5000);
    }
}

void MainWindow::on_startCapture_clicked() {
    if (!m_authManager->hasCapturePemission()) {
        showPermissionDeniedDialog();
        return;
    }
    
    // In a real implementation, show a device selection dialog
    // For demo, we'll just use a predefined device
    std::string device = "eth0";
    
    CaptureOptions options;
    options.promiscuous_mode = true;
    options.buffer_size = 1024 * 1024; // 1MB
    
    // Initialize device
    if (!captureEngine->initialize_device(device, options)) {
        QMessageBox::critical(this, "Error", 
                             QString("Failed to initialize capture device: %1").arg(device.c_str()));
        return;
    }
    
    // Create new capture file
    if (currentCaptureFile->is_open() && currentCaptureFile->is_modified()) {
        // Ask user to save current capture
        QMessageBox::StandardButton result = QMessageBox::question(
            this, "Save Current Capture?", 
            "Do you want to save the current capture before starting a new one?",
            QMessageBox::Yes | QMessageBox::No | QMessageBox::Cancel
        );
        
        if (result == QMessageBox::Cancel) {
            return;
        } else if (result == QMessageBox::Yes) {
            on_saveCapture_triggered();
        }
    }
    
    // Create a new capture file
    std::string temp_file = "capture_" + 
                          std::to_string(std::chrono::system_clock::now().time_since_epoch().count()) + 
                          ".wcap";
    
    currentCaptureFile->create(temp_file);
    currentCaptureFile->set_device_name(device);
    
    // Start the capture
    if (!captureEngine->start_capture()) {
        QMessageBox::critical(this, "Error", "Failed to start packet capture");
        return;
    }
}

void MainWindow::on_stopCapture_clicked() {
    if (isCapturing) {
        captureEngine->stop_capture();
    }
}

void MainWindow::onCaptureStarted() {
    isCapturing = true;
    statusBar()->showMessage("Capturing packets...");
    
    // Update UI state
    startCaptureAction->setEnabled(false);
    stopCaptureAction->setEnabled(true);
    
    // Create a new packet list tab
    QTableView* packetListView = new QTableView();
    // In a real implementation, set up the table model here
    
    int tabIndex = packetListTabs->addTab(packetListView, "Capture");
    packetListTabs->setCurrentIndex(tabIndex);
    packetListTabs->setTabsClosable(true);
    
    Log::info("Packet capture started on device: {}", currentCaptureFile->get_device_name());
}

void MainWindow::onCaptureStopped() {
    isCapturing = false;
    statusBar()->showMessage("Capture stopped");
    
    // Update UI state
    startCaptureAction->setEnabled(true);
    stopCaptureAction->setEnabled(false);
    
    // Ask if user wants to save the capture
    QMessageBox::StandardButton result = QMessageBox::question(
        this, "Save Capture", 
        "Do you want to save the captured packets?",
        QMessageBox::Yes | QMessageBox::No
    );
    
    if (result == QMessageBox::Yes) {
        on_saveAsCapture_triggered();
    }
    
    Log::info("Packet capture stopped");
}

void MainWindow::onPacketCaptured() {
    // Update packet count in status bar
    size_t count = currentCaptureFile->get_packet_count();
    QLabel* packetCountLabel = qobject_cast<QLabel*>(statusBar()->children().at(1));
    if (packetCountLabel) {
        packetCountLabel->setText(QString("Packets: %1").arg(count));
    }
    
    // Update the current packet list view
    // In a real implementation, update the table model here
    
    hasUnsavedChanges = true;
}

void MainWindow::on_newCapture_triggered() {
    on_startCapture_clicked();
}

void MainWindow::on_openCapture_triggered() {
    QString fileName = QFileDialog::getOpenFileName(
        this, "Open Capture File", "",
        "Wireshark MCP Captures (*.wcap);;All Files (*)"
    );
    
    if (fileName.isEmpty()) {
        return;
    }
    
    // Check if current capture has unsaved changes
    if (currentCaptureFile->is_open() && currentCaptureFile->is_modified()) {
        QMessageBox::StandardButton result = QMessageBox::question(
            this, "Save Current Capture?", 
            "Do you want to save the current capture before opening a new one?",
            QMessageBox::Yes | QMessageBox::No | QMessageBox::Cancel
        );
        
        if (result == QMessageBox::Cancel) {
            return;
        } else if (result == QMessageBox::Yes) {
            on_saveCapture_triggered();
        }
    }
    
    // Open the selected file
    if (!currentCaptureFile->open(fileName.toStdString())) {
        QMessageBox::critical(this, "Error", "Failed to open capture file");
        return;
    }
    
    // Create a new packet list tab
    QTableView* packetListView = new QTableView();
    // In a real implementation, populate the table with packet data
    
    int tabIndex = packetListTabs->addTab(packetListView, 
                                       QFileInfo(fileName).fileName());
    packetListTabs->setCurrentIndex(tabIndex);
    packetListTabs->setTabsClosable(true);
    
    // Update UI
    statusBar()->showMessage(QString("Opened capture file: %1").arg(fileName));
    hasUnsavedChanges = false;
    
    // Update packet count in status bar
    size_t count = currentCaptureFile->get_packet_count();
    QLabel* packetCountLabel = qobject_cast<QLabel*>(statusBar()->children().at(1));
    if (packetCountLabel) {
        packetCountLabel->setText(QString("Packets: %1").arg(count));
    }
    
    // Update device label in status bar
    std::string device = currentCaptureFile->get_device_name();
    QLabel* deviceLabel = qobject_cast<QLabel*>(statusBar()->children().at(2));
    if (deviceLabel) {
        deviceLabel->setText(QString("Device: %1").arg(device.c_str()));
    }
    
    Log::info("Opened capture file: {}", fileName.toStdString());
}

void MainWindow::on_saveCapture_triggered() {
    if (!currentCaptureFile->is_open()) {
        QMessageBox::warning(this, "Warning", "No capture file is open");
        return;
    }
    
    // If file has a path, save to it, otherwise prompt for a path
    if (currentCaptureFile->get_file_path().empty() || 
        currentCaptureFile->get_file_path().starts_with("capture_")) {
        on_saveAsCapture_triggered();
    } else {
        if (!currentCaptureFile->save()) {
            QMessageBox::critical(this, "Error", "Failed to save capture file");
            return;
        }
        
        statusBar()->showMessage(QString("Saved capture file: %1").arg(
            currentCaptureFile->get_file_path().c_str()
        ));
        
        hasUnsavedChanges = false;
    }
}

void MainWindow::on_saveAsCapture_triggered() {
    if (!currentCaptureFile->is_open()) {
        QMessageBox::warning(this, "Warning", "No capture file is open");
        return;
    }
    
    QString fileName = QFileDialog::getSaveFileName(
        this, "Save Capture File", "",
        "Wireshark MCP Captures (*.wcap);;All Files (*)"
    );
    
    if (fileName.isEmpty()) {
        return;
    }
    
    // Append extension if not provided
    if (!fileName.endsWith(".wcap")) {
        fileName += ".wcap";
    }
    
    // Ask about encryption
    QMessageBox::StandardButton encrypt_result = QMessageBox::question(
        this, "Encrypt Capture?", 
        "Do you want to encrypt the capture file?",
        QMessageBox::Yes | QMessageBox::No
    );
    
    bool encrypt = (encrypt_result == QMessageBox::Yes);
    
    // Save the file
    if (!currentCaptureFile->save_as(fileName.toStdString(), encrypt)) {
        QMessageBox::critical(this, "Error", "Failed to save capture file");
        return;
    }
    
    // Update tab name
    int currentTab = packetListTabs->currentIndex();
    if (currentTab > 0) {  // Skip welcome tab
        packetListTabs->setTabText(currentTab, QFileInfo(fileName).fileName());
    }
    
    statusBar()->showMessage(QString("Saved capture file as: %1").arg(fileName));
    hasUnsavedChanges = false;
    
    Log::info("Saved capture file as: {}", fileName.toStdString());
}

void MainWindow::on_exportPackets_triggered() {
    // Placeholder for export functionality
    QMessageBox::information(this, "Information", "Export functionality not implemented in this demo");
}

void MainWindow::on_printCapture_triggered() {
    // Placeholder for print functionality
    QMessageBox::information(this, "Information", "Print functionality not implemented in this demo");
}

void MainWindow::on_exit_triggered() {
    // Check for unsaved changes
    if (currentCaptureFile->is_open() && currentCaptureFile->is_modified()) {
        QMessageBox::StandardButton result = QMessageBox::question(
            this, "Save Changes?", 
            "Do you want to save changes before exiting?",
            QMessageBox::Yes | QMessageBox::No | QMessageBox::Cancel
        );
        
        if (result == QMessageBox::Cancel) {
            return;
        } else if (result == QMessageBox::Yes) {
            on_saveCapture_triggered();
        }
    }
    
    // Stop any active capture
    if (isCapturing) {
        captureEngine->stop_capture();
    }
    
    // Close application
    QApplication::quit();
}

void MainWindow::on_captureOptions_triggered() {
    // Placeholder for options dialog
    QMessageBox::information(this, "Information", "Capture options dialog not implemented in this demo");
}

void MainWindow::on_captureFilters_triggered() {
    // Placeholder for filters dialog
    QMessageBox::information(this, "Information", "Capture filters dialog not implemented in this demo");
}

void MainWindow::on_timeFormat_triggered() {
    // Placeholder for time format dialog
    QMessageBox::information(this, "Information", "Time format dialog not implemented in this demo");
}

void MainWindow::on_colorRules_triggered() {
    // Placeholder for color rules dialog
    QMessageBox::information(this, "Information", "Color rules dialog not implemented in this demo");
}

void MainWindow::on_fontSettings_triggered() {
    // Placeholder for font settings dialog
    QMessageBox::information(this, "Information", "Font settings dialog not implemented in this demo");
}

void MainWindow::on_preferences_triggered() {
    // Placeholder for preferences dialog
    QMessageBox::information(this, "Information", "Preferences dialog not implemented in this demo");
}

void MainWindow::on_displayFilters_triggered() {
    // Placeholder for display filters dialog
    QMessageBox::information(this, "Information", "Display filters dialog not implemented in this demo");
}

void MainWindow::on_conversations_triggered() {
    // Placeholder for conversations dialog
    QMessageBox::information(this, "Information", "Conversations dialog not implemented in this demo");
}

void MainWindow::on_endpoints_triggered() {
    // Placeholder for endpoints dialog
    QMessageBox::information(this, "Information", "Endpoints dialog not implemented in this demo");
}

void MainWindow::on_flowGraph_triggered() {
    // Placeholder for flow graph dialog
    QMessageBox::information(this, "Information", "Flow graph dialog not implemented in this demo");
}

void MainWindow::on_protocolHierarchy_triggered() {
    // Placeholder for protocol hierarchy dialog
    QMessageBox::information(this, "Information", "Protocol hierarchy dialog not implemented in this demo");
}

void MainWindow::on_conversationList_triggered() {
    // Placeholder for conversation list dialog
    QMessageBox::information(this, "Information", "Conversation list dialog not implemented in this demo");
}

void MainWindow::on_endpointList_triggered() {
    // Placeholder for endpoint list dialog
    QMessageBox::information(this, "Information", "Endpoint list dialog not implemented in this demo");
}

void MainWindow::on_serviceResponseTime_triggered() {
    // Placeholder for service response time dialog
    QMessageBox::information(this, "Information", "Service response time dialog not implemented in this demo");
}

void MainWindow::on_about_triggered() {
    QMessageBox::about(this, "About Wireshark MCP",
                      "Wireshark MCP - Corporate-Grade Network Analysis Tool\n\n"
                      "Version 1.0.0\n"
                      "© 2025 Your Company\n\n"
                      "A secure, enterprise-ready packet capture and analysis tool "
                      "based on the Wireshark protocol analyzer.");
}

void MainWindow::on_userGuide_triggered() {
    // Placeholder for user guide
    QMessageBox::information(this, "Information", "User guide not implemented in this demo");
}

void MainWindow::showPermissionDeniedDialog() {
    QMessageBox::warning(this, "Permission Denied",
                        "You do not have permission to perform this operation.\n\n"
                        "Please contact your system administrator if you require this access.");
}

void MainWindow::updateUIState() {
    bool authenticated = m_authManager->isAuthenticated();
    bool hasCapturePerm = m_authManager->hasCapturePemission();
    bool hasAdminPerm = m_authManager->hasAdminPermission();
    
    // Update menu and toolbar items based on permissions
    startCaptureAction->setEnabled(authenticated && hasCapturePerm && !isCapturing);
    stopCaptureAction->setEnabled(isCapturing);
    
    // Update admin-only features
    captureMenu->actions().at(3)->setEnabled(authenticated && hasAdminPerm); // Options
}

} // namespace wireshark_mcp