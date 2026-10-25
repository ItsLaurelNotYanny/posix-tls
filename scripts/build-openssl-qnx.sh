#!/bin/sh
set -eu

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PREFIX="$ROOT/build/qnx-deps"
SRC_DIR="$ROOT/build/dependency-sources-qnx"

KEY=$(cat "$ROOT/dependencies.lock.json" "$ROOT/scripts/build-openssl-qnx.sh" | sha256sum | cut -d ' ' -f 1)
STAMP="$PREFIX/openssl.complete"

if [ -f "$STAMP" ] && [ "$(cat "$STAMP")" = "$KEY" ]; then
    exit 0
fi

rm -rf "$PREFIX" "$SRC_DIR/openssl-3.5.9"
mkdir -p "$SRC_DIR" "$PREFIX"
python3 -c "import inspect, tarfile; tf = tarfile.open('$ROOT/vendor/sources/openssl-3.5.9.tar.gz'); tf.extractall('$SRC_DIR', filter='data') if 'filter' in inspect.signature(tf.extractall).parameters else tf.extractall('$SRC_DIR')"

cd "$SRC_DIR/openssl-3.5.9"
CC=bb10-cc AR=/opt/bb10-toolchain/bin/arm-unknown-nto-qnx6.5.0eabi-ar RANLIB=/opt/bb10-toolchain/bin/arm-unknown-nto-qnx6.5.0eabi-ranlib \
  ./Configure linux-armv4 --prefix="$PREFIX" --libdir=lib \
  no-shared no-tests no-apps no-autoload-config no-dso no-module no-asm \
  no-async no-engine no-legacy no-quic -DOPENSSL_NO_SECURE_MEMORY -DNO_SYSLOG -fPIC

make -j"${BUILD_JOBS:-4}" build_libs
make install_dev

printf '%s\n' "$KEY" > "$STAMP"
echo "OpenSSL 3.5.9 QNX ARMv7 build complete at $PREFIX"
