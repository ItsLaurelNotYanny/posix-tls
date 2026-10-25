# posix-tls

Add TLS 1.2 / 1.3 to any POSIX socket. No dependencies, no symbol conflicts.

Hand `posix-tls` a connected `int fd`; it handles the handshake, certificate checks, and cleanup. It offers a plain C API ([`posix_tls.h`](include/posix_tls/posix_tls.h)) and a C++03 RAII wrapper ([`posix_tls.hpp`](include/posix_tls/posix_tls.hpp)), and bundles OpenSSL 3.5 LTS statically, so it works on old and embedded systems where modern TLS is hard to get.

Extracted from [Todoist on BlackBerry Passport](https://github.com/ItsLaurelNotYanny/todoist_on_passport), running on real devices.

## Why `posix-tls`?

Adding modern TLS to portable C/C++98/C++03 code, embedded Linux, or legacy systems such as BlackBerry 10 / QNX 6.6 usually hits two walls:

- **Heavy dependencies.** Most TLS wrappers need C++17, Boost.Asio, Qt, or `libcurl`, and tie you to a specific event loop or HTTP stack.
- **Symbol clashes.** Old system images often preload an ancient `libssl.so` (e.g. OpenSSL 1.0.x) into your process. Linking a newer OpenSSL then breaks at load time.

`posix-tls` avoids both. Its only input is a file descriptor, and its embedded OpenSSL exports zero symbols, so it coexists safely with whatever `libssl` the system already loaded.

## Quick Start

```cpp
#include <posix_tls/posix_tls.hpp>

// `fd` is a connected TCP socket (socket + connect to example.com:443)
posix_tls::Context ctx(POSIX_TLS_POLICY_PUBLIC_PKI);
ctx.setCaPath("share/posix_tls/certs/cacert.pem");

posix_tls::Connection conn(ctx, fd);   // takes ownership of fd on success
if (!conn.isValid()) { /* fd is still yours: close it */ }

conn.connect("example.com");           // handshake + CA chain + hostname check

const char req[] = "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n";
size_t written = 0, nread = 0;
char buf[1024];
conn.write(req, sizeof(req) - 1, written);
conn.read(buf, sizeof(buf), nread);

conn.shutdown();                       // fd is closed when conn is destroyed
```

Return-code checks are trimmed for brevity. See [full examples](docs/examples.md) for production-style error handling, a P2P server, and a fingerprint-pinned client.

## Features

- **Just a file descriptor:** wrap any connected or accepted stream socket. No Boost, Qt, or `libcurl`; builds with `-std=c++98`.
- **No symbol clashes:** statically embedded OpenSSL 3.5 LTS with nothing exported to `.dynsym`.
- **Two trust modes:**
  - **Public PKI:** CA bundle verification with hostname / IP SAN matching and intermediate chain support.
  - **P2P pinning:** self-signed EC P-256 certificates plus SHA-256 fingerprint pinning, ideal for LAN, IoT, and LocalSend-style apps.
- **Clear `fd` ownership:** if create fails, the `fd` is still yours; once it succeeds, it is closed exactly once on destroy.
- **Nonblocking-ready:** returns `POSIX_TLS_ERR_WANT_READ` / `WANT_WRITE` for use with `select`, `poll`, `epoll`, `kqueue`, or `QSocketNotifier`.

## Install

### 1. Download a prebuilt SDK

Grab an archive and `SHA256SUMS` from [GitHub Releases](https://github.com/ItsLaurelNotYanny/posix-tls/releases):

| Platform | Archive |
| :--- | :--- |
| Linux `x86_64` | `posix-tls-1.0.0-linux-x86_64-sdk.tar.gz` |
| QNX Neutrino 6.6 / BlackBerry 10 `ARMv7` | `posix-tls-1.0.0-qnx-armv7-sdk.tar.gz` |

```sh
sha256sum --ignore-missing -c SHA256SUMS   # macOS: shasum -a 256 --ignore-missing -c SHA256SUMS
mkdir -p sdk && tar -xzf posix-tls-1.0.0-linux-x86_64-sdk.tar.gz -C sdk
```

### 2. Link from CMake

```cmake
cmake_minimum_required(VERSION 3.16)
project(my_app LANGUAGES C CXX)
set(CMAKE_CXX_STANDARD 98)

find_package(posix_tls CONFIG REQUIRED)

add_executable(my_app main.cpp)
target_link_libraries(my_app PRIVATE posix_tls::posix_tls)
```

Configure with `-DCMAKE_PREFIX_PATH=/path/to/sdk`. The SDK is relocatable, and your code needs no OpenSSL headers. Pure C projects can link the same target and `#include <posix_tls/posix_tls.h>`.

### Build from source

Prefer to build it yourself, or need to cross-compile for QNX / BlackBerry 10? See [docs/BUILDING.md](docs/BUILDING.md).

## Documentation

- [`posix_tls.h`](include/posix_tls/posix_tls.h): C API
- [`posix_tls.hpp`](include/posix_tls/posix_tls.hpp): C++03 RAII wrapper
- [Full examples](docs/examples.md): error-checked PKI client, P2P server, pinned client, and pure C usage
- [API contracts](share/posix_tls/README.md): `fd` ownership, nonblocking retry, certificate chains, and shutdown rules
- [Consumer build guide](share/posix_tls/BUILDING.md): linking relocated SDKs
- [Design notes](docs/design.md): symbol isolation and static linker caveats
- [`posix_tls_probe` CLI](docs/probe.md): try TLS 1.3 over localhost TCP
- [Changelog](CHANGELOG.md): release history

## License

- **posix-tls:** [MIT](LICENSE)
- **OpenSSL 3.5.9** (statically bundled in SDK builds): Apache 2.0. See [OpenSSL-LICENSE.txt](share/posix_tls/OpenSSL-LICENSE.txt).
- **Mozilla CA bundle** (`share/posix_tls/certs/cacert.pem`, from [curl.se](https://curl.se/docs/caextract.html)): MPL 2.0.

*BlackBerry and QNX are trademarks or registered trademarks of BlackBerry Limited. This project is independent and is not affiliated with or endorsed by BlackBerry Limited.*
