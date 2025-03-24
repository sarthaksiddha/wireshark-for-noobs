# Wireshark MCP User Guide

## Introduction

Wireshark MCP (Minimally Capable Product) is a corporate-grade packet capture and network analysis tool based on the foundations of Wireshark. This guide provides instructions for installing, configuring, and using Wireshark MCP in your corporate environment.

## Installation

### System Requirements
- Operating System: Windows 10/11, Ubuntu 20.04+, macOS 12+
- RAM: 4GB minimum, 8GB recommended
- Storage: 500MB for application, additional space for capture files
- Network: Admin privileges for capture interfaces

### Installation Steps

#### Windows
1. Download the Windows installer (`wireshark-mcp-1.0.0-x64.exe`) from the corporate repository
2. Run the installer with administrative privileges
3. Follow the on-screen instructions
4. Select the components you want to install (capture libraries, UI components, etc.)
5. Choose whether to install Npcap/WinPcap drivers if not already installed
6. Complete the installation

#### Linux
1. Add the repository to your sources:
   ```bash
   sudo add-apt-repository ppa:wireshark-mcp/stable
   sudo apt update
   ```
2. Install the package:
   ```bash
   sudo apt install wireshark-mcp
   ```
3. Add your user to the `wireshark` group to capture without root:
   ```bash
   sudo usermod -a -G wireshark $USER
   ```
4. Log out and log back in for the group changes to take effect

#### macOS
1. Download the macOS package (`wireshark-mcp-1.0.0.dmg`) from the corporate repository
2. Open the DMG file and drag the application to your Applications folder
3. When first running the application, you may need to approve system extensions

## Authentication

Wireshark MCP uses corporate authentication to ensure only authorized users can access sensitive network data:

1. When starting the application, you'll be prompted to log in
2. Enter your corporate credentials
3. For LDAP/Active Directory environments, use your domain credentials
4. For local authentication, use your pre-configured username and password

Authentication provides different permission levels:
- **Regular Users**: Can open and analyze existing capture files
- **Capture Users**: Can capture network traffic on authorized interfaces
- **Administrators**: Can configure system-wide settings and manage users

## Basic Usage

### Starting a Capture

1. Launch Wireshark MCP
2. Authenticate with your corporate credentials
3. Click "Start Capture" in the welcome screen or use the toolbar button
4. Select a network interface from the dropdown
5. Optionally set capture options (filters, promiscuous mode, etc.)
6. Click "Start" to begin capturing packets

### Using Display Filters

Display filters allow you to show only packets matching specific criteria:

1. Enter a filter expression in the filter bar (e.g., `http` or `ip.addr == 192.168.1.1`)
2. Click "Apply" or press Enter
3. The packet list will update to show only matching packets
4. Click "Clear" to remove the filter

Common filter examples:
- `http`: Show only HTTP traffic
- `ip.addr == 192.168.1.1`: Show packets to/from a specific IP
- `tcp.port == 443`: Show HTTPS traffic
- `tcp.flags.syn == 1`: Show TCP SYN packets
- `ip.src == 10.0.0.5 && ip.dst == 8.8.8.8`: Show traffic between specific hosts

### Analyzing Packets

1. Click on a packet in the packet list to select it
2. The packet details pane shows the decoded protocol information
3. The packet bytes pane shows the raw data
4. Expand protocol layers in the details pane to see more information
5. Right-click on fields for additional options (filter, copy, etc.)

### Saving Captures

1. Click "Save" in the toolbar or press Ctrl+S
2. Choose a location and filename
3. Select whether to encrypt the capture file
4. Add optional comments about the capture
5. Click "Save" to store the file

### Opening Existing Captures

1. Click "Open" in the toolbar or press Ctrl+O
2. Browse to the capture file location
3. For encrypted files, you'll be prompted for credentials
4. Click "Open" to load the file

## Advanced Features

### Capture Filters

Capture filters reduce the amount of data captured, focusing only on traffic of interest:

1. When starting a capture, click "Capture Options"
2. Enter a capture filter in BPF syntax (e.g., `port 80 or port 443`)
3. Click "Start" to begin capturing with the filter applied

Common capture filter examples:
- `host 192.168.1.1`: Capture traffic to/from a specific host
- `port 80`: Capture HTTP traffic
- `not port 53`: Exclude DNS traffic
- `tcp`: Capture only TCP traffic

### Security Features

Wireshark MCP includes several security enhancements:

1. **Encrypted Storage**: Capture files can be encrypted to protect sensitive data
2. **Audit Logging**: All operations are logged for compliance purposes
3. **Permission Controls**: Network interfaces can be restricted based on user roles
4. **Data Anonymization**: Options to anonymize IP addresses and other sensitive data

To enable encryption:
1. Go to Edit > Preferences > Security
2. Set the encryption level (Standard or High)
3. Choose whether to encrypt captures by default

### Statistical Analysis

Wireshark MCP provides several tools for traffic analysis:

1. **Protocol Hierarchy**: View the distribution of protocols in your capture
   - Statistics > Protocol Hierarchy

2. **Conversation List**: See communications between hosts
   - Statistics > Conversations

3. **Endpoint List**: View statistics for each host
   - Statistics > Endpoints

4. **Service Response Time**: Analyze application performance
   - Statistics > Service Response Time

5. **Flow Graph**: Visualize packet flows between endpoints
   - Analysis > Flow Graph

## Troubleshooting

### Capture Permissions

If you cannot capture packets:
1. Verify you have the "Capture" permission in your user role
2. Check that you're a member of the appropriate system group (e.g., "wireshark")
3. On Windows, ensure WinPcap/Npcap is installed correctly
4. Try running the application with administrator/root privileges

### Performance Issues

If the application is slow with large captures:
1. Use capture filters to reduce the amount of data captured
2. Increase the memory allocation in Edit > Preferences > Advanced
3. Consider using ring buffers for extended captures
4. For post-capture analysis, use display filters to focus on relevant traffic

### Decoding Problems

If packets aren't decoded correctly:
1. Verify you have the latest protocol dissectors installed
2. Check for port mapping issues in Edit > Preferences > Protocols
3. Try manual protocol selection by right-clicking on a packet

## Support and Resources

- Internal Support: Contact the network support team at `network-support@company.com`
- Documentation: Additional guides are available in the Help menu
- Updates: Check for software updates in Help > Check for Updates

## Compliance and Policy

- All network captures must comply with corporate security policies
- Obtain appropriate authorization before capturing traffic
- Handle capture files according to data classification guidelines
- Report any security concerns to your security team immediately