cmake_minimum_required(VERSION 3.16)
project(posix_tls VERSION 1.0.0 LANGUAGES C CXX)

option(POSIX_TLS_QNX "Build for QNX Neutrino 6.6 / BlackBerry 10 ARMv7" OFF)

set(CMAKE_CXX_STANDARD 98)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    add_compile_options(-Wall -Wextra -Wpedantic)
endif()

find_package(Python3 REQUIRED COMPONENTS Interpreter)
execute_process(
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_SOURCE_DIR}/scripts/dependencies.py"
    RESULT_VARIABLE INPUT_RESULT
)
if(NOT INPUT_RESULT EQUAL 0)
    message(FATAL_ERROR "Pinned inputs unavailable or invalid; run scripts/dependencies.py --fetch")
endif()

if(POSIX_TLS_QNX)
    add_definitions(-DPOSIX_TLS_QNX)
    add_compile_options(-fno-use-cxa-atexit)
    set(TARGET_DEPS_DIR "${CMAKE_SOURCE_DIR}/build/qnx-deps")
    set(PLATFORM_LIBS socket m)
    set(OPENSSL_RECIPE build-openssl-qnx.sh)
else()
    set(TARGET_DEPS_DIR "${CMAKE_SOURCE_DIR}/build/host-deps")
    set(PLATFORM_LIBS pthread ${CMAKE_DL_LIBS} m)
    set(OPENSSL_RECIPE build-openssl-host.sh)
endif()

execute_process(
    COMMAND bash "${CMAKE_SOURCE_DIR}/scripts/${OPENSSL_RECIPE}"
    RESULT_VARIABLE OPENSSL_RESULT
)
if(NOT OPENSSL_RESULT EQUAL 0)
    message(FATAL_ERROR "Pinned OpenSSL build failed")
endif()

set(TLS_SOURCES
    src/tls/posix_tls.cpp
    src/tls/posix_tls_crypto.cpp
)

if(POSIX_TLS_QNX)
    list(APPEND TLS_SOURCES src/qnx_compat.cpp)
endif()

add_library(posix_tls STATIC
    ${TLS_SOURCES}
)
target_include_directories(posix_tls
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
)
target_include_directories(posix_tls BEFORE PRIVATE
    ${TARGET_DEPS_DIR}/include
)
target_link_libraries(posix_tls PUBLIC
    ${TARGET_DEPS_DIR}/lib/libssl.a
    ${TARGET_DEPS_DIR}/lib/libcrypto.a
    ${PLATFORM_LIBS}
)
target_link_options(posix_tls INTERFACE "-Wl,--exclude-libs,ALL")

add_executable(posix_tls_probe src/tools/posix_tls_probe.cpp)
target_include_directories(posix_tls_probe BEFORE PRIVATE "${TARGET_DEPS_DIR}/include")
target_link_libraries(posix_tls_probe PRIVATE posix_tls)

include(CTest)
if(BUILD_TESTING)
    add_executable(test_tls tests/tls/test_posix_tls_all.cpp)
    target_include_directories(test_tls BEFORE PRIVATE "${TARGET_DEPS_DIR}/include")
    target_link_libraries(test_tls PRIVATE posix_tls)

    add_executable(test_standalone_consumer tests/standalone_consumer/test_consumer.cpp)
    target_link_libraries(test_standalone_consumer PRIVATE posix_tls)

    if(NOT CMAKE_CROSSCOMPILING)
        add_test(NAME TLSContractSuite COMMAND test_tls)
        add_test(NAME StandaloneExchange COMMAND test_standalone_consumer)
        set_tests_properties(TLSContractSuite StandaloneExchange PROPERTIES
            TIMEOUT 60
            WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
        )
    endif()
endif()

# Relocatable CMake Package Installation Rules
include(CMakePackageConfigHelpers)
set(CONFIG_INSTALL_DIR "lib/cmake/posix_tls")

if(POSIX_TLS_QNX)
    set(POSIX_TLS_IS_QNX 1)
else()
    set(POSIX_TLS_IS_QNX 0)
endif()

configure_package_config_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/cmake/posix_tls-config.cmake.in"
    "${CMAKE_CURRENT_BINARY_DIR}/posix_tls-config.cmake"
    INSTALL_DESTINATION "${CONFIG_INSTALL_DIR}"
    PATH_VARS CMAKE_INSTALL_PREFIX
)

write_basic_package_version_file(
    "${CMAKE_CURRENT_BINARY_DIR}/posix_tls-config-version.cmake"
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY SameMinorVersion
)

install(TARGETS posix_tls
    ARCHIVE DESTINATION lib
    LIBRARY DESTINATION lib
    RUNTIME DESTINATION bin
)

install(DIRECTORY include/posix_tls DESTINATION include)
install(FILES
    "${TARGET_DEPS_DIR}/lib/libssl.a"
    "${TARGET_DEPS_DIR}/lib/libcrypto.a"
    DESTINATION lib
)
install(FILES
    "${CMAKE_CURRENT_BINARY_DIR}/posix_tls-config.cmake"
    "${CMAKE_CURRENT_BINARY_DIR}/posix_tls-config-version.cmake"
    DESTINATION "${CONFIG_INSTALL_DIR}"
)

if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/vendor/sources/cacert.pem")
    install(FILES "${CMAKE_CURRENT_SOURCE_DIR}/vendor/sources/cacert.pem"
        DESTINATION share/posix_tls/certs
    )
endif()

install(TARGETS posix_tls_probe RUNTIME DESTINATION bin)
install(FILES
    share/posix_tls/LICENSE
    share/posix_tls/README.md
    share/posix_tls/BUILDING.md
    share/posix_tls/OpenSSL-LICENSE.txt
    DESTINATION share/posix_tls
)
