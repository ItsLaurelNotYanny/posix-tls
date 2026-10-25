# Changelog

All notable changes to `posix-tls` are documented in this file.

## [v1.0.0] - 2026-10-25

First public release of `posix-tls`: a minimal TLS 1.2 / 1.3 stream wrapper over POSIX sockets, with a pure C API and a C++03 RAII wrapper. Pass in a connected `int fd`; `posix-tls` handles the handshake, certificate verification, nonblocking readiness, and `fd` cleanup.

Extracted from [Todoist on BlackBerry Passport](https://github.com/ItsLaurelNotYanny/todoist_on_passport).

### Highlights

- Pure C API ([`posix_tls.h`](include/posix_tls/posix_tls.h)) and C++03 RAII wrapper ([`posix_tls.hpp`](include/posix_tls/posix_tls.hpp)); no Boost, Qt, or `libcurl`.
- Two trust policies: **Public PKI** (CA bundle, hostname / IP SAN matching, full-chain server certificates) and **P2P** (self-signed EC P-256 certificates with SHA-256 fingerprint pinning).
- Embedded **OpenSSL 3.5.9 LTS** with zero OpenSSL symbols exported in `.dynsym`, so it can coexist with an older system `libssl.so` in the same process.
- Clear `fd` ownership: on create failure the `fd` stays with the caller; on success it is closed exactly once on destroy.
- Nonblocking I/O with explicit `POSIX_TLS_ERR_WANT_READ` / `POSIX_TLS_ERR_WANT_WRITE` signaling.

### Downloads

| File | Platform |
| :--- | :--- |
| `posix-tls-1.0.0-linux-x86_64-sdk.tar.gz` | Linux `x86_64` |
| `posix-tls-1.0.0-qnx-armv7-sdk.tar.gz` | QNX Neutrino 6.6 / BlackBerry 10 `ARMv7` |
| `posix-tls-1.0.0-source.tar.gz` | Source (no `git` required to build) |
| `SHA256SUMS` | Checksums for all files above |

Verify before extracting:

```sh
sha256sum --ignore-missing -c SHA256SUMS   # macOS: shasum -a 256 --ignore-missing -c SHA256SUMS
mkdir -p sdk && tar -xzf posix-tls-1.0.0-linux-x86_64-sdk.tar.gz -C sdk
```

Then configure your CMake project with `-DCMAKE_PREFIX_PATH=/path/to/sdk`. See [`README.md`](README.md) for a quick start.

### Bundled components

| Component | Version | License |
| :--- | :--- | :--- |
| OpenSSL | 3.5.9 LTS | Apache 2.0 |
| Mozilla CA bundle | `2026-09-25` | MPL 2.0 |

### Verification

Each release is checked by an automated gate covering: a 20-case TLS contract and regression suite, fragmented nonblocking transfers and mid-stream cancellation, relocated C and C++03 consumer builds, ELF `.dynsym` symbol-isolation checks, and live local TCP TLS 1.3 exchanges (pinned P2P and Public PKI full chain).

### Known limitations

- While the underlying statically isolated OpenSSL 3.5.9 + QNX 6.6 runtime runs on a physical BlackBerry Passport (`OS 10.3.3.3216`) in [Todoist on BlackBerry Passport](https://github.com/ItsLaurelNotYanny/todoist_on_passport), automated checks for the standalone `posix-tls` QNX `ARMv7` SDK verify cross-compilation, linking, and ELF symbol isolation on a host machine and do not execute on hardware.
- Both the prebuilt Linux SDK and the bundled host OpenSSL build script (`scripts/build-openssl-host.sh`) target Linux `x86_64`; other POSIX hosts or architectures need a build from source with the matching OpenSSL `Configure` target.
- Avoid statically linking two different OpenSSL `libcrypto.a` / `libssl.a` archives into the same binary.
