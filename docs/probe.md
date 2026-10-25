# `posix_tls_probe` Diagnostic CLI

`posix_tls_probe` is a lightweight command-line utility built and installed alongside `posix-tls` (`bin/posix_tls_probe`). It exercises real TCP sockets with `posix-tls` in client, server, and certificate-fingerprint modes.

---

## 1. Automated Localhost TCP Suite

After building on the host (`./check.sh`), you can run the automated Python harness, which tests both P2P SHA-256 fingerprint pinning and a 3-tier Public PKI (`root -> intermediate -> leaf`) fullchain exchange over localhost TCP:

```sh
python3 examples/check-probe.py
```

---

## 2. Manual P2P Fingerprint-Pinned Walkthrough

Generate a disposable EC P-256 certificate, compute its 64-character SHA-256 fingerprint, start a one-shot TLS 1.3 server, and connect with a pinned client:

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

---

## 3. Command Reference

```text
Usage: posix_tls_probe <command> [options]

Commands:
  client       Perform TLS handshake and HTTP GET probe as client
               --url <url>                 Target HTTPS URL (e.g. https://example.com:8443/)
               --ca-bundle <path>          Path to trusted CA bundle (Public PKI mode)
               --expected-pin <pin>        Expected 64-hex SHA-256 fingerprint (P2P mode)
               --min-tls-version <version> TLSv1.2 or TLSv1.3 (default: TLSv1.2)
               --max-tls-version <version> TLSv1.2 or TLSv1.3 (default: TLSv1.3)

  server       Run standalone TLS server probe
               --port <port>               TCP port to listen on (default: 8443)
               --cert <file>               PEM leaf certificate or fullchain file (default: ephemeral self-signed)
               --key <file>                PEM private key file
               --min-tls-version <version> TLSv1.2 or TLSv1.3
               --max-tls-version <version> TLSv1.2 or TLSv1.3
               --once                      Exit after serving one connection

  fingerprint  Calculate 64-hex SHA-256 DER fingerprint of a PEM certificate
               --cert <file>               Certificate file to inspect
```
