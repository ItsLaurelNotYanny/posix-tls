# Using the Installed posix-tls SDK

Keep the installed SDK prefix intact when relocating it. It contains:
- `include/posix_tls/` (`posix_tls.h`, `posix_tls.hpp`)
- `lib/` (`libposix_tls.a`, `libssl.a`, `libcrypto.a`)
- `lib/cmake/posix_tls/` (`posix_tls-config.cmake`, `posix_tls-config-version.cmake`)
- `bin/posix_tls_probe`
- `share/posix_tls/certs/cacert.pem`

OpenSSL headers are completely encapsulated and are not required by consumers. See [README.md](README.md) for API contracts and [LICENSE](LICENSE) for license notices.

## CMake Consumer Example

Create a separate consumer directory with `main.cpp` and `CMakeLists.txt`:

```cmake
cmake_minimum_required(VERSION 3.16)
project(consumer LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 98)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(posix_tls CONFIG REQUIRED)

add_executable(consumer main.cpp)
target_link_libraries(consumer PRIVATE posix_tls::posix_tls)
```

```cpp
#include <posix_tls/posix_tls.hpp>

int main() {
    posix_tls::Context context(POSIX_TLS_POLICY_P2P);
    return context.isValid() ? 0 : 1;
}
```

Configure and build against the installed SDK prefix:

```sh
cmake -S . -B build -DCMAKE_PREFIX_PATH=/path/to/posix-tls-sdk
cmake --build build
```

Pure C consumers can link the exact same `posix_tls::posix_tls` target and include `<posix_tls/posix_tls.h>`.

For QNX Neutrino / BlackBerry 10 ARMv7 cross-builds, pass your compatible QNX toolchain file during configure (`-DCMAKE_TOOLCHAIN_FILE=...`). Public PKI clients must pass the deployed CA bundle path and target hostname; P2P verifying clients must supply an independently trusted SHA-256 certificate fingerprint.
