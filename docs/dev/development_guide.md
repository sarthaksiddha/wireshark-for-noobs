# Wireshark MCP Development Guide

## Introduction

This guide provides instructions for developers working on the Wireshark MCP (Minimally Capable Product) project. It covers the development environment setup, architecture overview, coding standards, and contribution workflow.

## Development Environment Setup

### Prerequisites

- C++17 compatible compiler (GCC 8+, Clang 7+, MSVC 2019+)
- CMake 3.15 or newer
- Qt 5.15.2 or newer
- libpcap/WinPcap development libraries
- Google Test framework (for unit testing)
- Git for version control

### Setting Up Your Environment

#### Linux (Ubuntu/Debian)

```bash
# Install dependencies
sudo apt update
sudo apt install -y build-essential cmake libpcap-dev qt5-default libqt5core5a libqt5widgets5 libqt5network5 libgtest-dev git

# Clone the repository
git clone https://github.com/sarthaksiddha/wireshark-mcp.git
cd wireshark-mcp

# Create a build directory
mkdir build && cd build

# Configure and build
cmake ..
cmake --build .
```

#### Windows

1. Install [Visual Studio 2019 or newer](https://visualstudio.microsoft.com/downloads/) with C++ development workload
2. Install [CMake](https://cmake.org/download/)
3. Install [Qt](https://www.qt.io/download-qt-installer) (select Qt 5.15.2 and MSVC components)
4. Install [Npcap SDK](https://nmap.org/npcap/guide/npcap-devguide.html)
5. Install [Git for Windows](https://git-scm.com/download/win)

```bash
# Clone the repository
git clone https://github.com/sarthaksiddha/wireshark-mcp.git
cd wireshark-mcp

# Create a build directory
mkdir build
cd build

# Configure with CMake (adjust paths as needed)
cmake -G "Visual Studio 16 2019" -A x64 -DQt5_DIR=C:/Qt/5.15.2/msvc2019_64/lib/cmake/Qt5 -DPCAP_INCLUDE_DIR=C:/npcap-sdk/Include -DPCAP_LIBRARY=C:/npcap-sdk/Lib/x64/wpcap.lib ..

# Build
cmake --build . --config Release
```

#### macOS

```bash
# Install dependencies using Homebrew
brew install cmake qt@5 libpcap googletest git

# Clone the repository
git clone https://github.com/sarthaksiddha/wireshark-mcp.git
cd wireshark-mcp

# Create a build directory
mkdir build && cd build

# Configure and build
cmake -DQt5_DIR=$(brew --prefix qt@5)/lib/cmake/Qt5 ..
cmake --build .
```

## Project Architecture

The Wireshark MCP codebase is organized as follows:

```
wireshark-mcp/
├── src/
│   ├── capture/       # Packet capture engine
│   ├── analysis/      # Protocol analysis modules
│   ├── ui/            # User interface components
│   ├── security/      # Authentication and encryption
│   ├── storage/       # Capture file management
│   └── common/        # Shared utilities
├── include/           # Public headers
├── tests/
│   ├── unit/          # Unit tests
│   └── integration/   # Integration tests
├── docs/
│   ├── api/           # API documentation
│   ├── user/          # User guides
│   └── dev/           # Developer documentation
├── scripts/           # Build and deployment scripts
├── config/            # Configuration templates
└── third_party/       # Managed external dependencies
```

### Core Components

#### Capture Engine

The capture engine (`src/capture/`) is responsible for interfacing with network devices and capturing packets. It provides an abstraction over libpcap/WinPcap and handles device enumeration, packet capturing, and filtering.

#### Protocol Analysis

The protocol analysis modules (`src/analysis/`) decode captured packets according to various network protocols. These modules parse packet data and provide structured representations for visualization.

#### Security

The security subsystem (`src/security/`) handles authentication, authorization, and encryption. It ensures that only authorized users can access network captures and provides facilities for secure storage of sensitive data.

#### Storage

The storage modules (`src/storage/`) manage capture files, including reading, writing, and indexing packet data. They support the Wireshark MCP file format with optional encryption.

#### User Interface

The UI components (`src/ui/`) provide the graphical interface for packet visualization and analysis. They are built using Qt and follow the Model-View-Controller pattern.

## Coding Standards

### C++ Style Guide

Wireshark MCP follows a modified version of the Google C++ Style Guide:

- Use 4 spaces for indentation (no tabs)
- Line length limit of 100 characters
- Use snake_case for variable and function names
- Use CamelCase for class names
- Use UPPER_CASE for constants and macros
- Always use braces for control structures, even for single-line blocks
- Place opening braces on the same line as the statement
- Prefer `nullptr` over `NULL` or `0`
- Use C++17 features when appropriate
- Avoid C-style casts, use C++ casts instead

### Documentation

All classes, methods, and non-trivial functions should be documented using Doxygen-style comments:

```cpp
/**
 * @brief Short description
 *
 * Longer description with more details
 *
 * @param param1 Description of first parameter
 * @param param2 Description of second parameter
 * @return Description of return value
 */
```

### Testing

- All major functionality should be covered by unit tests
- Use Google Test framework for unit tests
- Mock external dependencies when testing components
- Integration tests should validate end-to-end workflows

## Contribution Workflow

### Branching Strategy

We use a simplified Git Flow model for development:

- `main` - Production-ready code
- `develop` - Integration branch for ongoing development
- `feature/*` - Feature branches for new development
- `bugfix/*` - Bug fix branches
- `release/*` - Release candidate branches

### Pull Request Process

1. Create a new branch from `develop` (for features) or `main` (for hotfixes)
2. Make your changes, following coding standards
3. Write/update tests to cover your changes
4. Ensure all tests pass locally
5. Push your branch and create a pull request against the appropriate base branch
6. Wait for CI checks to pass
7. Address reviewer feedback if needed
8. Once approved, your PR will be merged

### Commit Guidelines

- Use meaningful commit messages that describe what and why (not how)
- Start with a short (50 chars or less) summary line
- Follow with a blank line and a more detailed description if needed
- Reference issue numbers when applicable: "Fix #123: ..."

### Code Review

Code reviews are a critical part of our development process:

- Be respectful and constructive in comments
- Focus on code, not the person
- Explain your reasoning when requesting changes
- Ask questions rather than making demands
- Look for security, performance, and maintainability issues

## Building and Testing

### Building the Project

```bash
mkdir build && cd build
cmake ..
cmake --build .
```

### Running Tests

```bash
# From the build directory
ctest

# Or directly
./tests/unit_tests
```

### Build Options

- `-DBUILD_TESTING=ON/OFF` - Enable/disable building tests (default: ON)
- `-DBUILD_INTEGRATION_TESTS=ON/OFF` - Enable/disable integration tests (default: OFF)
- `-DENABLE_ENCRYPTION=ON/OFF` - Enable/disable encryption features (default: ON)
- `-DENABLE_AUDIT=ON/OFF` - Enable/disable audit logging (default: ON)

## Debugging

### Using Visual Studio

1. Open the generated solution file in Visual Studio
2. Set breakpoints in the code
3. Select the target application and press F5

### Using GDB (Linux/macOS)

```bash
gdb --args ./build/wireshark_mcp
```

### Debug Logging

Use the logging framework to add debug information:

```cpp
Log::debug("Detailed information: {}", variable);
Log::info("General information");
Log::warning("Warning message");
Log::error("Error message");
```

## Performance Considerations

- Avoid deep copies of packet data when possible
- Use move semantics for large objects
- Consider memory usage when dealing with large capture files
- Profile critical sections to identify bottlenecks
- Use paged or streamed file access for large captures

## Security Considerations

- Validate all user input
- Handle sensitive data (passwords, keys) securely
- Use proper encryption libraries, don't implement crypto yourself
- Follow the principle of least privilege
- Regularly update dependencies to address security vulnerabilities

## Release Process

1. Create a release branch from `develop`
2. Perform testing and bug fixes on the release branch
3. Update version numbers and CHANGELOG
4. Merge release branch to `main` and tag with version number
5. Merge back to `develop`
6. Build release packages for distribution

## Additional Resources

- [Qt Documentation](https://doc.qt.io/)
- [libpcap Documentation](https://www.tcpdump.org/manpages/pcap.3pcap.html)
- [Google Test Documentation](https://google.github.io/googletest/)
- [CMake Documentation](https://cmake.org/documentation/)
- [Wireshark Developer's Guide](https://www.wireshark.org/docs/wsdg_html_chunked/) (for reference)