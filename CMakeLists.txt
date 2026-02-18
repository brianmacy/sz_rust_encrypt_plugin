cmake_minimum_required(VERSION 3.16)
project(sz_rust_encrypt_plugin_examples VERSION 1.0.0 LANGUAGES C)

# Set C standard
set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Build configuration
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

# Set output directories
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

# Rust plugin library paths
set(RUST_TARGET_DIR ${CMAKE_SOURCE_DIR}/target/release)
set(AES_PLUGIN_LIB ${RUST_TARGET_DIR}/libsz_aes_encrypt_plugin.so)
set(DUMMY_PLUGIN_LIB ${RUST_TARGET_DIR}/libsz_dummy_encrypt_plugin.so)

# Custom command to build Rust libraries
add_custom_command(
    OUTPUT ${AES_PLUGIN_LIB} ${DUMMY_PLUGIN_LIB}
    COMMAND cargo build --release --workspace
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    COMMENT "Building Rust encryption plugins..."
)

# Create custom target for Rust builds
add_custom_target(rust_plugins
    DEPENDS ${AES_PLUGIN_LIB} ${DUMMY_PLUGIN_LIB}
)

# Find required libraries (if any)
# Currently we only need standard C libraries

# Shared header for all plugins
include_directories(${CMAKE_SOURCE_DIR}/include)

# AES Plugin Test Executable
add_executable(test_aes
    examples/test_aes_plugin.c
)

# Set properties for AES test
target_link_libraries(test_aes
    ${AES_PLUGIN_LIB}
)

target_link_directories(test_aes PRIVATE ${RUST_TARGET_DIR})

# Set RPATH for AES test so it can find the Rust library at runtime
set_target_properties(test_aes PROPERTIES
    INSTALL_RPATH ${RUST_TARGET_DIR}
    BUILD_WITH_INSTALL_RPATH ON
)

# Add dependency on Rust build
add_dependencies(test_aes rust_plugins)

# Dummy Plugin Test Executable
add_executable(test_dummy
    examples/test_dummy_plugin.c
)

# Set properties for Dummy test
target_link_libraries(test_dummy
    ${DUMMY_PLUGIN_LIB}
)

target_link_directories(test_dummy PRIVATE ${RUST_TARGET_DIR})

# Set RPATH for Dummy test so it can find the Rust library at runtime
set_target_properties(test_dummy PROPERTIES
    INSTALL_RPATH ${RUST_TARGET_DIR}
    BUILD_WITH_INSTALL_RPATH ON
)

# Add dependency on Rust build
add_dependencies(test_dummy rust_plugins)

# Custom targets for running tests
add_custom_target(run_aes_test
    COMMAND $<TARGET_FILE:test_aes>
    DEPENDS test_aes
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    COMMENT "Running AES plugin test..."
)

add_custom_target(run_dummy_test
    COMMAND $<TARGET_FILE:test_dummy>
    DEPENDS test_dummy
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    COMMENT "Running Dummy plugin test..."
)

add_custom_target(run_all_tests
    DEPENDS run_aes_test run_dummy_test
    COMMENT "Running all plugin tests..."
)

# Print build information
message(STATUS "Building C examples for Rust encryption plugins")
message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")
message(STATUS "Rust target directory: ${RUST_TARGET_DIR}")
message(STATUS "Output directory: ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}")

# Installation rules (optional)
install(TARGETS test_aes test_dummy
    RUNTIME DESTINATION bin
)

install(FILES ${AES_PLUGIN_LIB} ${DUMMY_PLUGIN_LIB}
    DESTINATION lib
)