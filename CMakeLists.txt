cmake_minimum_required(VERSION 3.16)
project(SmartGridPrivacy VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Build type
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

set(CMAKE_CXX_FLAGS_RELEASE "-O2")
set(CMAKE_CXX_FLAGS_DEBUG "-g -O0 -DDEBUG")

# Find dependencies
find_package(SEAL 4.1 REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)

# nlohmann/json - header only
include(FetchContent)
FetchContent_Declare(
    json
    GIT_REPOSITORY https://github.com/nlohmann/json.git
    GIT_TAG v3.11.3
)
FetchContent_MakeAvailable(json)

# Common library
add_library(smartgrid_common STATIC
    src/common/config.cpp
    src/common/logger.cpp
    src/common/metrics.cpp
    src/common/tls_context.cpp
    src/common/certificate_generator.cpp
    src/common/crypto_engine.cpp
    src/common/network.cpp
    src/common/energy_simulator.cpp
    src/common/zkp_engine.cpp
    src/common/verifiable_computation.cpp
    src/common/theft_detection.cpp
    src/common/tou_billing.cpp
)

target_include_directories(smartgrid_common PUBLIC
    ${CMAKE_SOURCE_DIR}/include
)

target_link_libraries(smartgrid_common PUBLIC
    SEAL::seal
    OpenSSL::SSL
    OpenSSL::Crypto
    Threads::Threads
    nlohmann_json::nlohmann_json
)

# Key Generator executable
add_executable(key_generator src/key_generator_main.cpp)
target_link_libraries(key_generator PRIVATE smartgrid_common)

# Certificate Generator executable
add_executable(cert_generator src/cert_generator_main.cpp)
target_link_libraries(cert_generator PRIVATE smartgrid_common)

# Key Distribution Center executable
add_executable(kdc src/kdc_main.cpp)
target_link_libraries(kdc PRIVATE smartgrid_common)

# Smart Meter executable
add_executable(smart_meter src/smart_meter_main.cpp)
target_link_libraries(smart_meter PRIVATE smartgrid_common)

# Aggregator executable
add_executable(aggregator src/aggregator_main.cpp)
target_link_libraries(aggregator PRIVATE smartgrid_common)

# Control Center executable
add_executable(control_center src/control_center_main.cpp)
target_link_libraries(control_center PRIVATE smartgrid_common)

# CKKS from-scratch demonstration (no SEAL dependency)
add_executable(demo demo.cpp)
target_link_libraries(demo PRIVATE Threads::Threads)

# HE Scheme Comparison benchmark (CKKS vs BFV vs BGV vs Paillier)
add_executable(scheme_comparison src/scheme_comparison.cpp)
target_link_libraries(scheme_comparison PRIVATE
    SEAL::seal
    OpenSSL::SSL
    OpenSSL::Crypto
    Threads::Threads
)

# Install
install(TARGETS key_generator cert_generator kdc smart_meter aggregator control_center
    RUNTIME DESTINATION bin
)
