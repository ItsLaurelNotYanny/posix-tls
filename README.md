# posix-tls

Minimal, portable TLS 1.2/1.3 stream wrapper over POSIX sockets with an opaque C API and a zero-overhead C++03 RAII wrapper.

`posix-tls` wraps caller-created connected or accepted POSIX stream descriptors (`int fd`) with modern TLS 1.3 security while keeping your event loop, threading model, and application dependencies completely decoupled.

## Key Capabilities

- **Pure POSIX Socket Abstraction**: Bring any connected or accepted stream descriptor (`socket` + `connect` / `accept`). Core requires only standard POSIX C/C++03—no Boost, Qt, libcurl, or modern C++ runtime requirements.
- **Dual Trust Policies**:
  - **Public PKI (`POSIX_TLS_POLICY_PUBLIC_PKI`)**: CA root bundle verification with strict RFC 6125 Subject Alternative Name (SAN) and IP SAN matching.
  - **Peer-to-Peer Pinning (`POSIX_TLS_POLICY_P2P`)**: Ephemeral or persistent EC P-256 self-signed certificate generation and constant-criteria SHA-256 peer certificate fingerprint pinning for LAN/IoT/P2P transfers (such as LocalSend).
- **Hermetic Symbol Isolation**: Statically embeds pinned **OpenSSL 3.5.9 LTS** with `-Wl,--exclude-libs,ALL`, exporting **zero** `SSL_*` / `OPENSSL_*` / `EVP_*` / `CRYPTO_*` symbols into ELF `.dynsym`. Safely coexists inside processes or legacy OS environments that already load older system `libssl.so` (such as OpenSSL 1.0.x).
- **Deterministic `fd` Ownership & Nonblocking I/O**:
  - Failed connection creation leaves `fd` untouched with the caller; successful creation transfers sole ownership and guarantees single `close(fd)` upon destruction.
  - Explicit `POSIX_TLS_ERR_WANT_READ` and `POSIX_TLS_ERR_WANT_WRITE` readiness signaling for `select`, `poll`, `epoll`, `kqueue`, or `QSocketNotifier`.
- **Supported Targets**: Linux (`x86_64` and POSIX hosts) and QNX Neutrino 6.6 / BlackBerry 10 (`ARMv7`).

Project-owned code is licensed under MIT; statically bundled OpenSSL 3.5.9 is licensed under Apache 2.0. See [LICENSE](LICENSE).

---

## Quick Start (Host Build & Install)

Requirements: Linux/POSIX host, C/C++ compiler, CMake 3.16+, Python 3, Perl, Make, Bash, and `openssl` CLI (used only by the end-to-end TCP probe example).

Acquire and hash-verify pinned upstream inputs (`OpenSSL 3.5.9` and Mozilla CA bundle), run the full verification gate, and install the relocatable SDK:

```sh
python3 scripts/dependencies.py --fetch
./check.sh
cmake --install build/host --prefix "$PWD/build/sdk-host"
```

- `./check.sh --fast`: Verifies public tree hygiene, pinned SHA-256 digests, and strict C++03 compilation.
- `./check.sh`: Runs the full gate—20-case TLS contract and regression suite, fragmented nonblocking bidirectional transfer and active cancellation tests, relocated pure C and C++03 consumer builds with ELF `.dynsym` isolation verification, and live local TCP TLS 1.3 client/server exchanges (pinned P2P and Public PKI fullchain).
- Set `SOURCE_CACHE_DIR=/path/to/cache` to reuse pre-downloaded archives without network access, and `BUILD_JOBS` to control OpenSSL build parallelism (default `4`).

---

## Cross-Compiling for QNX Neutrino 6.6 / BlackBerry 10 ARMv7

Using a compatible QNX ARMv7 container toolchain (`bb10-cc`, `bb10-c++`, `/opt/bb10-toolchain.cmake`; default image `bb10-native-dev:local`, configurable via `BB10_NATIVE_IMAGE`):

```sh
./scripts/check-native.sh
```

This builds OpenSSL 3.5.9 and `posix-tls` for ARMv7 (`-DPOSIX_TLS_QNX=ON`), installs the relocatable ARMv7 SDK to `build/sdk-qnx`, compiles standalone relocated C and C++03 ARM consumers, and verifies zero leaked OpenSSL symbols in 32-bit ARM ELF `.dynsym`. (`docker/Dockerfile.bb10` documents the toolchain image recipe; host cross-checks verify compile/link/symbol isolation, distinct from physical device execution.)

---

## Linking from Your Project

Install or copy the SDK directory anywhere—`posix_tls` uses relocatable CMake config packages and requires no OpenSSL headers in consumer code:

```cmake
cmake_minimum_required(VERSION 3.16)
project(example LANGUAGES C CXX)
set(CMAKE_CXX_STANDARD 98)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(posix_tls CONFIG REQUIRED)

add_executable(example main.cpp)
target_link_libraries(example PRIVATE posix_tls::posix_tls)
```

Configure with `-DCMAKE_PREFIX_PATH=/path/to/sdk`. Pure C targets can link `posix_tls::posix_tls` directly and include `<posix_tls/posix_tls.h>`.

> Note: `-Wl,--exclude-libs,ALL` hides static OpenSSL symbols from dynamic ELF exports (`.dynsym`). Avoid statically linking two different OpenSSL archives directly into the same single final executable without linker namespacing.

---

## API Overview & Runnable Examples

- Public headers: [C API (`posix_tls.h`)](include/posix_tls/posix_tls.h) and [C++03 RAII Wrapper (`posix_tls.hpp`)](include/posix_tls/posix_tls.hpp)
- Detailed ownership, lifetime, nonblocking retry, and shutdown contracts: [share/posix_tls/README.md](share/posix_tls/README.md)
- Relocated consumer build guide: [share/posix_tls/BUILDING.md](share/posix_tls/BUILDING.md)

### Minimal C++03 P2P Pinning Client Example

```cpp
#include <posix_tls/posix_tls.hpp>

// Assume connected_fd is a connected POSIX TCP socket (socket + connect)
int run_pinned_client(int connected_fd, const std::string& trusted_sha256_pin) {
    posix_tls::Context ctx(POSIX_TLS_POLICY_P2P);
    if (!ctx.isValid()) return -1;
    if (ctx.setExpectedFingerprint(trusted_sha256_pin) != POSIX_TLS_OK) return -1;

    // Ownership of connected_fd transfers to conn when conn.isValid() is true
    posix_tls::Connection conn(ctx, connected_fd);
    if (!conn.isValid()) {
        ::close(connected_fd);
        return -1;
    }

    if (conn.connect("") != POSIX_TLS_OK) return -1;

    const char req[] = "PING\n";
    size_t written = 0;
    if (conn.write(req, sizeof(req) - 1, written) != POSIX_TLS_OK) return -1;

    conn.shutdown();
    return 0; // conn destructor closes connected_fd exactly once
}
```

### Diagnostic CLI & Automated TCP TLS 1.3 Demo

Run the standalone nonblocking exchange test or the automated TCP TLS 1.3 client/server probe:

```sh
./build/host/test_standalone_consumer
python3 examples/check-probe.py
```

Or run `posix_tls_probe` manually with a disposable local EC P-256 certificate:

```sh
mkdir -p build/example
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -subj /CN=localhost -days 1 \
  -keyout build/example/key.pem -out build/example/cert.pem

pin=$(./build/host/posix_tls_probe fingerprint --cert build/example/cert.pem)

./build/host/posix_tls_probe server --port 18443 --once \
  --cert build/example/cert.pem --key build/example/key.pem \
  --min-tls-version TLSv1.3 &
server_pid=$!

./build/host/posix_tls_probe client --url https://127.0.0.1:18443/ \
  --expected-pin "$pin" --min-tls-version TLSv1.3
wait "$server_pid"
```
