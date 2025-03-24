cmake_minimum_required(VERSION 3.15)
project(WiresharkMCP VERSION 1.0.0)

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Dependencies
find_package(Qt5 COMPONENTS Core Widgets Network REQUIRED)
find_package(PCAP REQUIRED)

# Security options
option(ENABLE_ENCRYPTION "Enable capture file encryption" ON)
option(ENABLE_AUDIT "Enable audit logging" ON)

# Set source files
set(SOURCES
    src/main.cpp
    src/capture/packet_capture.cpp
    src/analysis/protocol_analyzer.cpp
    src/ui/main_window.cpp
    src/security/auth_manager.cpp
    src/storage/capture_manager.cpp
    src/common/logging.cpp
)

# Set header files
set(HEADERS
    src/capture/packet_capture.h
    src/analysis/protocol_analyzer.h
    src/ui/main_window.h
    src/security/auth_manager.h
    src/storage/capture_manager.h
    src/common/logging.h
)

# Create a library target for the core functionality
add_library(wireshark_mcp_lib STATIC ${SOURCES} ${HEADERS})

# Link libraries to the core library
target_link_libraries(wireshark_mcp_lib PRIVATE
    Qt5::Core
    Qt5::Widgets
    Qt5::Network
    ${PCAP_LIBRARIES}
)

# Set include directories
target_include_directories(wireshark_mcp_lib PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/src
)

# Main executable
add_executable(wireshark_mcp src/main.cpp)

# Link the executable with the core library
target_link_libraries(wireshark_mcp PRIVATE
    wireshark_mcp_lib
)

# Installation rules
install(TARGETS wireshark_mcp
        RUNTIME DESTINATION bin)
install(DIRECTORY config/
        DESTINATION etc/wireshark_mcp)

# Testing
enable_testing()
add_subdirectory(tests)
