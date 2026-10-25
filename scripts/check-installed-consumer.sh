#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
INSTALL_ORIG=$(mktemp -d "${TMPDIR:-/tmp}/posix_tls_install_orig.XXXXXX")
INSTALL_RELOC=$(mktemp -d "${TMPDIR:-/tmp}/posix_tls_install_reloc.XXXXXX")
rm -rf "$INSTALL_RELOC"
WORK_DIR=$(mktemp -d "${TMPDIR:-/tmp}/posix_tls_consumer_test.XXXXXX")
trap 'rm -rf "$INSTALL_ORIG" "$INSTALL_RELOC" "$WORK_DIR"' EXIT

# 1. Install to original prefix
cmake --install "${POSIX_TLS_BUILD_DIR:-$ROOT/build/host}" --prefix "$INSTALL_ORIG" >/dev/null

# Verify contract documentation, CA bundle, and license presence
test -f "$INSTALL_ORIG/share/posix_tls/LICENSE" || { echo "FAIL: missing installed LICENSE" >&2; exit 1; }
test -f "$INSTALL_ORIG/share/posix_tls/README.md" || { echo "FAIL: missing installed README.md contract" >&2; exit 1; }
test -f "$INSTALL_ORIG/share/posix_tls/BUILDING.md" || { echo "FAIL: missing installed BUILDING.md" >&2; exit 1; }
test -f "$INSTALL_ORIG/share/posix_tls/certs/cacert.pem" || { echo "FAIL: missing installed cacert.pem" >&2; exit 1; }

# 2. Relocate installation directory (tests relocatability of CMake configs)
mv "$INSTALL_ORIG" "$INSTALL_RELOC"

# 3. Independent pure C consumer test
mkdir -p "$WORK_DIR/c_consumer"
cat << 'EOF' > "$WORK_DIR/c_consumer/CMakeLists.txt"
cmake_minimum_required(VERSION 3.16)
project(PureCConsumer LANGUAGES C)
find_package(posix_tls REQUIRED PATHS "${POSIX_TLS_PREFIX}" NO_DEFAULT_PATH)

add_executable(consumer_c main.c)
target_link_libraries(consumer_c PRIVATE posix_tls::posix_tls)
target_link_options(consumer_c PRIVATE -rdynamic)
EOF

cat << 'EOF' > "$WORK_DIR/c_consumer/main.c"
#include <posix_tls/posix_tls.h>
#include <stdio.h>

int main(void) {
    posix_tls_context_t* ctx = posix_tls_context_create(POSIX_TLS_POLICY_P2P);
    if (!ctx) return 1;
    posix_tls_context_destroy(ctx);
    return 0;
}
EOF

cmake -S "$WORK_DIR/c_consumer" -B "$WORK_DIR/c_consumer/build" -DPOSIX_TLS_PREFIX="$INSTALL_RELOC" >/dev/null
cmake --build "$WORK_DIR/c_consumer/build" >/dev/null
"$WORK_DIR/c_consumer/build/consumer_c" >/dev/null

# 4. Independent C++03 consumer test
mkdir -p "$WORK_DIR/cpp_consumer"
cat << 'EOF' > "$WORK_DIR/cpp_consumer/CMakeLists.txt"
cmake_minimum_required(VERSION 3.16)
project(PureCppConsumer LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 98)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
find_package(posix_tls REQUIRED PATHS "${POSIX_TLS_PREFIX}" NO_DEFAULT_PATH)

add_executable(consumer_cpp main.cpp)
target_link_libraries(consumer_cpp PRIVATE posix_tls::posix_tls)
target_link_options(consumer_cpp PRIVATE -rdynamic)
EOF

cat << 'EOF' > "$WORK_DIR/cpp_consumer/main.cpp"
#include <posix_tls/posix_tls.hpp>
#include <iostream>

int main() {
    posix_tls::Context ctx(POSIX_TLS_POLICY_P2P);
    if (!ctx.isValid()) return 1;
    return 0;
}
EOF

cmake -S "$WORK_DIR/cpp_consumer" -B "$WORK_DIR/cpp_consumer/build" -DPOSIX_TLS_PREFIX="$INSTALL_RELOC" >/dev/null
cmake --build "$WORK_DIR/cpp_consumer/build" >/dev/null
"$WORK_DIR/cpp_consumer/build/consumer_cpp" >/dev/null

# Exercise the full public-API exchange against only the relocated SDK.
cp "$ROOT/tests/standalone_consumer/test_consumer.cpp" "$WORK_DIR/cpp_consumer/main.cpp"
cmake --build "$WORK_DIR/cpp_consumer/build" >/dev/null
"$WORK_DIR/cpp_consumer/build/consumer_cpp"

# 5. Verify strict symbol isolation on both consumer binaries
python3 "$ROOT/scripts/check-symbol-isolation.py" \
    "$WORK_DIR/c_consumer/build/consumer_c" \
    "$WORK_DIR/cpp_consumer/build/consumer_cpp" >/dev/null

echo "OK: Relocated pure C and C++03 consumers built and verified cleanly from $INSTALL_RELOC"
