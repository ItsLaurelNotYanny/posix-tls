# Full Usage Examples

These examples show complete error handling and socket-descriptor ownership for both **Public PKI** and **Peer-to-Peer (P2P) fingerprint pinning** in C++03 and pure C.

For detailed state-machine, nonblocking `WANT_READ` / `WANT_WRITE` buffer-stability, and shutdown rules, see [share/posix_tls/README.md](../share/posix_tls/README.md).

---

## 1. Public PKI Client (C++03)

Validates the server's certificate chain (including served intermediates) against a trusted CA bundle and enforces RFC 6125 DNS or IP Subject Alternative Name (SAN) matching:

```cpp
#include <posix_tls/posix_tls.hpp>
#include <unistd.h>
#include <string>

// `connected_fd` is a connected TCP socket (e.g. socket + connect to example.com:443)
int https_get_public_pki(int connected_fd,
                         const std::string& hostname,
                         const std::string& ca_bundle_path,
                         std::string& out_response) {
    posix_tls::Context ctx(POSIX_TLS_POLICY_PUBLIC_PKI);
    if (!ctx.isValid() || ctx.setCaPath(ca_bundle_path) != POSIX_TLS_OK) {
        ::close(connected_fd);
        return -1;
    }

    posix_tls::Connection conn(ctx, connected_fd);
    if (!conn.isValid()) {
        ::close(connected_fd); // Creation failed: caller retains ownership of connected_fd
        return -1;
    }
    // From this point on, `conn` owns `connected_fd` and closes it once on destruction.

    int rc = conn.connect(hostname);
    if (rc != POSIX_TLS_OK) {
        return rc;
    }

    std::string req = "GET / HTTP/1.1\r\nHost: " + hostname + "\r\nConnection: close\r\n\r\n";
    size_t written = 0;
    rc = conn.write(req.data(), req.size(), written);
    if (rc != POSIX_TLS_OK) {
        return rc;
    }

    out_response.clear();
    char buf[4096];
    for (;;) {
        size_t nread = 0;
        rc = conn.read(buf, sizeof(buf), nread);
        if (rc == POSIX_TLS_OK && nread > 0) {
            out_response.append(buf, nread);
        } else if (rc == POSIX_TLS_ERR_CLOSED) {
            break; // Peer sent TLS close_notify
        } else {
            return rc;
        }
    }

    conn.shutdown();
    return POSIX_TLS_OK;
}
```

---

## 2. P2P Server & Fingerprint-Pinned Client (C++03)

For LAN discovery, IoT pairing, or LocalSend-style local HTTPS transfers where no public CA exists, generate an EC P-256 self-signed certificate and authenticate the peer by its 64-character SHA-256 DER fingerprint:

```cpp
#include <posix_tls/posix_tls.hpp>
#include <unistd.h>
#include <string>

// Step 1: Generate P2P identity once and compute its 64-hex SHA-256 fingerprint pin
int create_p2p_identity(std::string& cert_pem,
                        std::string& key_pem,
                        std::string& sha256_pin) {
    int rc = posix_tls::generateSelfSignedCert(cert_pem, key_pem);
    if (rc != POSIX_TLS_OK) return rc;
    return posix_tls::calculateCertFingerprint(cert_pem, sha256_pin);
}

// Step 2: Server wraps an accepted socket (`accept()`) and serves TLS 1.2/1.3
int p2p_serve_once(int accepted_fd,
                   const std::string& cert_pem,
                   const std::string& key_pem) {
    posix_tls::Context server_ctx(POSIX_TLS_POLICY_P2P);
    if (!server_ctx.isValid() ||
        server_ctx.setCredentials(cert_pem, key_pem) != POSIX_TLS_OK) {
        ::close(accepted_fd);
        return -1;
    }

    posix_tls::Connection conn(server_ctx, accepted_fd);
    if (!conn.isValid()) {
        ::close(accepted_fd);
        return -1;
    }

    int rc = conn.accept();
    if (rc != POSIX_TLS_OK) return rc;

    const char payload[] = "HELLO_FROM_P2P_SERVER\n";
    size_t written = 0;
    rc = conn.write(payload, sizeof(payload) - 1, written);
    if (rc != POSIX_TLS_OK) return rc;

    conn.shutdown();
    return POSIX_TLS_OK;
}

// Step 3: Client wraps a connected socket and verifies the expected 64-hex pin
int p2p_client_receive(int connected_fd,
                       const std::string& expected_sha256_pin,
                       std::string& out_msg) {
    posix_tls::Context client_ctx(POSIX_TLS_POLICY_P2P);
    if (!client_ctx.isValid() ||
        client_ctx.setExpectedFingerprint(expected_sha256_pin) != POSIX_TLS_OK) {
        ::close(connected_fd);
        return -1;
    }

    posix_tls::Connection conn(client_ctx, connected_fd);
    if (!conn.isValid()) {
        ::close(connected_fd);
        return -1;
    }

    // Rejects with POSIX_TLS_ERR_PIN_MISMATCH if peer certificate hash differs
    int rc = conn.connect("");
    if (rc != POSIX_TLS_OK) return rc;

    char buf[256];
    size_t nread = 0;
    rc = conn.read(buf, sizeof(buf), nread);
    if (rc != POSIX_TLS_OK) return rc;

    out_msg.assign(buf, nread);
    conn.shutdown();
    return POSIX_TLS_OK;
}
```

---

## 3. Pure C API Example (`posix_tls.h`)

```c
#include <posix_tls/posix_tls.h>
#include <string.h>
#include <unistd.h>

int c_pinned_ping(int connected_fd, const char* expected_pin_hex) {
    posix_tls_context_t* ctx = posix_tls_context_create(POSIX_TLS_POLICY_P2P);
    if (!ctx) {
        close(connected_fd);
        return POSIX_TLS_ERR_OUT_OF_MEMORY;
    }

    int rc = posix_tls_context_set_expected_fingerprint(ctx, expected_pin_hex);
    if (rc != POSIX_TLS_OK) {
        posix_tls_context_destroy(ctx);
        close(connected_fd);
        return rc;
    }

    posix_tls_connection_t* conn = posix_tls_connection_create(ctx, connected_fd);
    if (!conn) {
        posix_tls_context_destroy(ctx);
        close(connected_fd);
        return POSIX_TLS_ERR_OUT_OF_MEMORY;
    }

    rc = posix_tls_connect(conn, NULL);
    if (rc == POSIX_TLS_OK) {
        const char msg[] = "PING\n";
        size_t written = 0;
        rc = posix_tls_write(conn, msg, strlen(msg), &written);
        if (rc == POSIX_TLS_OK) {
            posix_tls_shutdown(conn);
        }
    }

    posix_tls_connection_destroy(conn); /* closes connected_fd once */
    posix_tls_context_destroy(ctx);
    return rc;
}
```
