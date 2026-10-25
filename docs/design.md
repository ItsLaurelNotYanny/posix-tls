# Design Notes & Linker Caveats

## 1. Why Bring-Your-Own `int fd`?

`posix-tls` intentionally stops at the connected or accepted POSIX stream descriptor (`int fd`) rather than bundling a custom DNS resolver, socket-connect wrapper, event loop, or HTTP client:

- **Zero framework lock-in:** Callers keep full control over `getaddrinfo`, dual-stack IPv4/IPv6 happy-eyeballs, `SO_RCVTIMEO` / `O_NONBLOCK`, proxies, `socketpair` testing, and event loops (`select`, `poll`, `epoll`, `kqueue`, or `QSocketNotifier`).
- **Local & P2P symmetry:** The exact same `posix_tls_connection_t` handle wraps outbound client sockets (`posix_tls_connect`) and inbound accepted server sockets (`posix_tls_accept`).
- **No `SIGPIPE` surprises:** Outbound socket writes use `MSG_NOSIGNAL` (or `SO_NOSIGPIPE` where available) through a custom OpenSSL `BIO_METHOD`.

---

## 2. Hermetic ELF Symbol Isolation

Legacy POSIX platforms (such as BlackBerry 10 / QNX Neutrino 6.6 or older enterprise/embedded Linux distributions) frequently load an older system `libssl.so` / `libcrypto.so` (e.g. OpenSSL 1.0.1) into every GUI or framework process. Normally, linking OpenSSL 3.x into the same process causes dynamic-symbol interposition crashes at startup or during the first handshake.

`posix-tls` prevents this in three layers:

1. **Opaque public headers:** [`posix_tls.h`](../include/posix_tls/posix_tls.h) and [`posix_tls.hpp`](../include/posix_tls/posix_tls.hpp) include **no** OpenSSL headers and expose only `posix_tls_*` symbols.
2. **Static PIC OpenSSL 3.5.9 + linker hiding:** OpenSSL 3.5.9 is built as static archives (`libssl.a`, `libcrypto.a`) with `-fPIC`, and the `posix_tls::posix_tls` CMake target propagates `-Wl,--exclude-libs,ALL` so static archive symbols are never re-exported into dynamic ELF `.dynsym` tables.
3. **Mechanical ELF verification:** Both `./check.sh` (64-bit Linux ELF) and `./scripts/check-native.sh` (32-bit ARM QNX ELF) inspect linked executables with [`scripts/check-symbol-isolation.py`](../scripts/check-symbol-isolation.py) to verify zero exported `SSL_*`, `OPENSSL_*`, `EVP_*`, `X509_*`, `BIO_*`, `PEM_*`, `RAND_*`, or `CRYPTO_*` dynamic symbols.

### Static Linker Caveat

`-Wl,--exclude-libs,ALL` hides static library symbols from dynamic `.dynsym` exports—allowing safe coexistence with system **shared** libraries (`libssl.so`) loaded in the same process. However, within a single static link step, avoid linking **two different static OpenSSL archives** (`libcrypto.a` / `libssl.a`) directly into the same final binary unless one copy is namespaced or isolated behind its own shared object.

---

## 3. QNX Neutrino 6.6 & Strict C++03 Compatibility

- **Header precedence over legacy sysroots:** QNX 6.6 sysroots ship OpenSSL 1.0.1 headers under `/usr/include/openssl`. During `posix-tls` compilation, `CMakeLists.txt` places the pinned OpenSSL 3.5.9 include directory `BEFORE PRIVATE` so compiler drivers never pick up stale sysroot OpenSSL headers.
- **C++03 ABI compatibility:** Core library and tests compile cleanly under `-std=c++98 -Wall -Wextra -Wpedantic`, with `-fno-use-cxa-atexit` and minimal POSIX shims ([`src/qnx_compat.cpp`](../src/qnx_compat.cpp)) when `POSIX_TLS_QNX=ON`.
