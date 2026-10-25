#!/usr/bin/env bash
# QNX ARMv7 cross-compile, relocated consumer compile/link, and ELF symbol isolation.
# Compile/link only; this does not execute ARM binaries on a phone.
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."
mkdir -p build

# 1. Cross-compile and install SDK inside hermetic QNX/BB10 toolchain container
docker run --rm --network none --user "$(id -u):$(id -g)" \
    -v "$PWD:/src:ro" -v "$PWD/build:/src/build" \
    -v "$PWD/vendor/sources:/src/vendor/sources:ro" -w /src \
    "${BB10_NATIVE_IMAGE:-bb10-native-dev:local}" bash -c '
        cmake -S /src -B /src/build/qnx \
            -DCMAKE_TOOLCHAIN_FILE=/opt/bb10-toolchain.cmake -DPOSIX_TLS_QNX=ON &&
        cmake --build /src/build/qnx --parallel "${BUILD_JOBS:-4}" &&
        cmake --install /src/build/qnx --prefix /src/build/sdk-qnx'

python3 scripts/check-symbol-isolation.py build/qnx/posix_tls_probe
file build/qnx/posix_tls_probe

# 2. Verify relocated pure C and C++03 consumers against only the installed QNX SDK
WORK_DIR=$(mktemp -d "${TMPDIR:-/tmp}/posix_tls_qnx_consumer.XXXXXX")
trap 'rm -rf "$WORK_DIR"' EXIT
cp -r build/sdk-qnx "$WORK_DIR/relocated-sdk"

mkdir -p "$WORK_DIR/c_consumer" "$WORK_DIR/cpp_consumer"
cat << 'EOF' > "$WORK_DIR/c_consumer/CMakeLists.txt"
cmake_minimum_required(VERSION 3.16)
project(QnxCConsumer LANGUAGES C CXX)
find_package(posix_tls REQUIRED PATHS "/work/relocated-sdk" NO_DEFAULT_PATH)
add_executable(consumer_c main.c)
target_link_libraries(consumer_c PRIVATE posix_tls::posix_tls)
EOF

cat << 'EOF' > "$WORK_DIR/c_consumer/main.c"
#include <posix_tls/posix_tls.h>
int main(void) {
    posix_tls_context_t* ctx = posix_tls_context_create(POSIX_TLS_POLICY_P2P);
    if (!ctx) return 1;
    posix_tls_context_destroy(ctx);
    return 0;
}
EOF

cat << 'EOF' > "$WORK_DIR/cpp_consumer/CMakeLists.txt"
cmake_minimum_required(VERSION 3.16)
project(QnxCppConsumer LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 98)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
find_package(posix_tls REQUIRED PATHS "/work/relocated-sdk" NO_DEFAULT_PATH)
add_executable(consumer_cpp main.cpp)
target_link_libraries(consumer_cpp PRIVATE posix_tls::posix_tls)
EOF

cp tests/standalone_consumer/test_consumer.cpp "$WORK_DIR/cpp_consumer/main.cpp"

docker run --rm --network none --user "$(id -u):$(id -g)" \
    -v "$WORK_DIR:/work" -w /work \
    "${BB10_NATIVE_IMAGE:-bb10-native-dev:local}" bash -c '
        cmake -S /work/c_consumer -B /work/c_consumer/build \
            -DCMAKE_TOOLCHAIN_FILE=/opt/bb10-toolchain.cmake &&
        cmake --build /work/c_consumer/build &&
        cmake -S /work/cpp_consumer -B /work/cpp_consumer/build \
            -DCMAKE_TOOLCHAIN_FILE=/opt/bb10-toolchain.cmake &&
        cmake --build /work/cpp_consumer/build'

python3 scripts/check-symbol-isolation.py \
    "$WORK_DIR/c_consumer/build/consumer_c" \
    "$WORK_DIR/cpp_consumer/build/consumer_cpp"

echo "OK: QNX ARMv7 SDK and relocated C/C++03 consumers compiled, linked, and symbol-isolated"
