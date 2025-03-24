# Wireshark MCP

Wireshark MCP (Minimally Capable Product) - A corporate-grade network analysis tool

## Overview

Wireshark MCP is a secure, enterprise-ready packet capture and analysis tool based on the foundations of Wireshark. It adds corporate features including:

- **Robust packet capture and analysis** with error handling
- **Security features** (encrypted storage of capture files)
- **User authentication** for sensitive network analysis
- **Logging and audit trails** for compliance
- **Cross-platform compatibility** (Windows, Linux, macOS)

## Features

- Secure packet capture with device permission validation
- Protocol analysis with detailed packet inspection
- Encrypted storage of sensitive capture files
- Corporate authentication integration (LDAP/Local)
- Filter-based packet capture and display
- Comprehensive logging and auditing
- Interactive UI with multiple views
- Extensible plugin architecture

## System Requirements

- **Operating System**: Windows 10/11, Ubuntu 20.04+, macOS 12+
- **RAM**: 4GB minimum, 8GB recommended
- **Storage**: 500MB for application, additional space for capture files
- **Network**: Admin privileges for capture interfaces

## Getting Started

### Installation

See the [User Guide](docs/user/user_guide.md) for detailed installation instructions for your platform.

### Basic Usage

1. Launch Wireshark MCP
2. Authenticate with your corporate credentials
3. Select a network interface from the dropdown
4. Click "Start Capture" to begin capturing packets
5. Use display filters to focus on traffic of interest

## Documentation

- [User Guide](docs/user/user_guide.md) - Comprehensive guide for end users
- [Developer Guide](docs/dev/development_guide.md) - Documentation for developers

## Building from Source

### Prerequisites

- C++17 compatible compiler (GCC 8+, Clang 7+, MSVC 2019+)
- CMake 3.15 or newer
- Qt 5.15.2 or newer
- libpcap/WinPcap development libraries
- Google Test framework (for unit testing)

### Build Instructions

```bash
mkdir build && cd build
cmake ..
cmake --build .
```

For detailed build instructions, see the [Developer Guide](docs/dev/development_guide.md).

## Contributing

We welcome contributions to Wireshark MCP! Please see our [Developer Guide](docs/dev/development_guide.md) for details on how to contribute.

## License

Copyright (c) 2025 Your Company

This software is proprietary and confidential.
Unauthorized copying, distribution, or use is strictly prohibited.