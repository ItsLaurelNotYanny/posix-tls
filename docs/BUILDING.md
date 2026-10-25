# Building `posix-tls` from Source

This guide covers building `posix-tls` and its pinned **OpenSSL 3.5.9** static dependency from source, running the verification gates, and cross-compiling the QNX Neutrino 6.6 / BlackBerry 10 `ARMv7` SDK.

If you only want to link `posix-tls` into an application using a prebuilt SDK archive, see [share/posix_tls/BUILDING.md](../share/posix_tls/BUILDING.md) instead.

---

## 1. Host Build & Verification (`Linux x86_64`)

### Prerequisites

- **Host OS:** Linux `x86_64` (the supplied `scripts/build-openssl-host.sh` recipe selects OpenSSL target `linux-x86_64`).
- **Required tools:** Bash, C/C++ compiler (GCC or Clang), CMake 3.16+, Make, Perl, Python 3, `tar`, and `openssl` CLI (used by the end-to-end localhost TCP probe test).
- `git` is required only inside a Git checkout; building and running `./check.sh` from an extracted `posix-tls-1.0.0-source.tar.gz` archive works without `git`.

### Fetch Inputs, Run Gate & Install SDK

1. Fetch and SHA-256-verify pinned upstream inputs (`OpenSSL 3.5.9` and the Mozilla CA certificate bundle, defined in [`dependencies.lock.json`](../dependencies.lock.json)):

   ```sh
   python3 scripts/dependencies.py --fetch
   ```

2. Configure, compile, and run the verification gate:

   ```sh
   ./check.sh
   ```

3. Install a relocatable SDK directory:

   ```sh
   cmake --install build/host --prefix "$PWD/build/sdk-host"
   ```

### Gate Modes & Environment Variables

- `./check.sh --fast`: Runs fast pre-commit checks (source hygiene, Python syntax, pinned dependency SHA-256 verification, CMake configure, and strict `-std=c++98 -Wall -Wextra -Wpedantic` build).
- `./check.sh`: Runs all 9 verification stages, adding:
  - 20-case TLS contract and regression suite (`test_tls`)
  - Fragmented nonblocking bidirectional streaming and mid-stream cancellation (`test_standalone_consumer`)
  - ELF `.dynsym` private-symbol isolation check (`scripts/check-symbol-isolation.py`)
  - Relocated pure C and C++03 external consumer builds (`scripts/check-installed-consumer.sh`)
  - Live localhost TCP TLS 1.3 exchanges covering both P2P pinning and Public PKI fullchain (`examples/check-probe.py`)
- `SOURCE_CACHE_DIR=/path/to/cache`: Copies `openssl-3.5.9.tar.gz` and `cacert.pem` from a local directory instead of downloading over HTTPS (still verifying SHA-256 digests).
- `BUILD_JOBS=N`: Controls parallel build jobs for OpenSSL and CMake (default `4`).

---

## 2. Cross-Compiling for QNX Neutrino 6.6 / BlackBerry 10 (`ARMv7`)

### Prepare the Toolchain Container

The QNX cross-build uses Docker and a local image providing `bb10-cc`, `bb10-c++`, `/opt/bb10-toolchain.cmake`, and the QNX 6.6 `ARMv7` sysroot. Build the image from [`docker/Dockerfile.bb10`](../docker/Dockerfile.bb10):

```sh
docker build -t bb10-native-dev:local -f docker/Dockerfile.bb10 docker
```

*(Override `BB10_NATIVE_IMAGE` if you tag the image under a different name.)*

### Run the Offline QNX Cross-Build & Gate

Ensure `vendor/sources/` has already been populated via `python3 scripts/dependencies.py --fetch`, then run:

```sh
./scripts/check-native.sh
```

`check-native.sh` runs inside the container with networking disabled (`--network none`) and:

1. Cross-compiles OpenSSL 3.5.9 (`linux-armv4` with `-fPIC`, no shared objects or assembly) into `build/qnx-deps`.
2. Configures and builds `posix-tls` with `-DPOSIX_TLS_QNX=ON` into `build/qnx`.
3. Installs the relocatable `ARMv7` SDK into `build/sdk-qnx`.
4. Mounts **only** the relocated `build/sdk-qnx` directory into an isolated workspace to compile and link standalone pure C and C++03 `ARMv7` consumer binaries.
5. Verifies that `posix_tls_probe` and both consumer binaries export **zero** `SSL_*` / `OPENSSL_*` / `EVP_*` / `X509_*` / `CRYPTO_*` symbols in 32-bit ARM ELF `.dynsym`.

> **Verification scope:** Host cross-checks validate compilation, static linking, consumer SDK relocatability, and 32-bit ARM ELF symbol isolation; they do not execute binaries on physical QNX / BlackBerry 10 hardware.
