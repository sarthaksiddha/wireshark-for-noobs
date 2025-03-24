# Unit Tests CMakeLists.txt

# Create test executable
add_executable(unit_tests
    capture_test.cpp
    config_test.cpp
    security_test.cpp
    # Add more test files here
)

# Include directories
target_include_directories(unit_tests PRIVATE
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}/include
)

# Link libraries
target_link_libraries(unit_tests PRIVATE
    ${GTEST_LIBRARIES}
    ${GTEST_MAIN_LIBRARIES}
    pthread
    # Add any other libraries needed for testing
)

# Set required C++ standard
set_target_properties(unit_tests PROPERTIES
    CXX_STANDARD 17
    CXX_STANDARD_REQUIRED ON
)

# Add tests to CTest
add_test(NAME UnitTests COMMAND unit_tests)