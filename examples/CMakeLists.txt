# CMakeLists.txt for individual examples
# This file can be used to build examples independently

cmake_minimum_required(VERSION 3.16)

# Allow this to be used as a standalone project
if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
    project(sz_encryption_examples VERSION 1.0.0 LANGUAGES C)

    # Set C standard
    set(CMAKE_C_STANDARD 99)
    set(CMAKE_C_STANDARD_REQUIRED ON)

    # Build configuration
    if(NOT CMAKE_BUILD_TYPE)
        set(CMAKE_BUILD_TYPE Release)
    endif()

    # Set paths relative to examples directory
    set(RUST_TARGET_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../target/release)
    set(AES_PLUGIN_LIB ${RUST_TARGET_DIR}/libsz_aes_encrypt_plugin.so)
    set(DUMMY_PLUGIN_LIB ${RUST_TARGET_DIR}/libsz_dummy_encrypt_plugin.so)

    # Custom command to build Rust libraries
    add_custom_command(
        OUTPUT ${AES_PLUGIN_LIB} ${DUMMY_PLUGIN_LIB}
        COMMAND cargo build --release --workspace
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/..
        COMMENT "Building Rust encryption plugins..."
    )

    # Create custom target for Rust builds
    add_custom_target(rust_plugins
        DEPENDS ${AES_PLUGIN_LIB} ${DUMMY_PLUGIN_LIB}
    )
else()
    # When included from parent CMakeLists.txt, use parent's variables
    message(STATUS "Building examples as part of main project")
endif()

# Function to create a plugin test executable
function(add_plugin_test test_name source_file plugin_lib)
    add_executable(${test_name} ${source_file})

    target_link_libraries(${test_name} ${plugin_lib})
    target_link_directories(${test_name} PRIVATE ${RUST_TARGET_DIR})

    # Set RPATH so executable can find the Rust library at runtime
    set_target_properties(${test_name} PROPERTIES
        INSTALL_RPATH ${RUST_TARGET_DIR}
        BUILD_WITH_INSTALL_RPATH ON
    )

    # Add dependency on Rust build (if building standalone)
    if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
        add_dependencies(${test_name} rust_plugins)
    endif()

    # Create run target
    add_custom_target(run_${test_name}
        COMMAND $<TARGET_FILE:${test_name}>
        DEPENDS ${test_name}
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/..
        COMMENT "Running ${test_name}..."
    )
endfunction()

# Create test executables
add_plugin_test(test_aes test_aes_plugin.c ${AES_PLUGIN_LIB})
add_plugin_test(test_dummy test_dummy_plugin.c ${DUMMY_PLUGIN_LIB})

# Target to run all tests
add_custom_target(run_tests
    DEPENDS run_test_aes run_test_dummy
    COMMENT "Running all plugin tests..."
)

# Installation rules (when used standalone)
if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
    install(TARGETS test_aes test_dummy
        RUNTIME DESTINATION bin
    )

    install(FILES ${AES_PLUGIN_LIB} ${DUMMY_PLUGIN_LIB}
        DESTINATION lib
    )
endif()