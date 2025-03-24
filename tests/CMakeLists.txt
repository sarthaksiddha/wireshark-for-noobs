# Tests CMakeLists.txt
cmake_minimum_required(VERSION 3.15)

# Find GTest
find_package(GTest REQUIRED)
include_directories(${GTEST_INCLUDE_DIRS})

# Add unit test directory
add_subdirectory(unit)

# Add integration test directory
if(BUILD_INTEGRATION_TESTS)
    add_subdirectory(integration)
endif()