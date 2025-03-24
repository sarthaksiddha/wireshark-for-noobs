# Integration Tests CMakeLists.txt

# Create test executable
add_executable(integration_tests
    main.cpp
    capture_integration_test.cpp
    file_operations_test.cpp
    ui_test.cpp
)

# Include directories
target_include_directories(integration_tests PRIVATE
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}/include
)

# Link libraries
target_link_libraries(integration_tests PRIVATE
    ${GTEST_LIBRARIES}
    ${GTEST_MAIN_LIBRARIES}
    pthread
    # Add production libraries here
    wireshark_mcp_capture
    wireshark_mcp_analysis
    wireshark_mcp_security
    wireshark_mcp_storage
    wireshark_mcp_common
    # Qt libraries if needed for UI tests
    Qt5::Core
    Qt5::Widgets
    Qt5::Network
)

# Set required C++ standard
set_target_properties(integration_tests PROPERTIES
    CXX_STANDARD 17
    CXX_STANDARD_REQUIRED ON
)

# Add tests to CTest
add_test(NAME IntegrationTests COMMAND integration_tests)