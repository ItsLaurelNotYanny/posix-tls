#ifndef POSIX_TLS_HPP
#define POSIX_TLS_HPP

#include "posix_tls.h"
#include <string>
#include <vector>

namespace posix_tls {

class Context {
public:
    explicit Context(posix_tls_policy_t policy)
        : m_ctx(posix_tls_context_create(policy))
    {
    }

    ~Context() {
        if (m_ctx) {
            posix_tls_context_destroy(m_ctx);
            m_ctx = NULL;
        }
    }

    bool isValid() const {
        return m_ctx != NULL;
    }

    posix_tls_context_t* get() const {
        return m_ctx;
    }

    int setCaPath(const std::string& path) {
        if (!m_ctx) return POSIX_TLS_ERR_INVALID_ARG;
        return posix_tls_context_set_ca_path(m_ctx, path.c_str());
    }

    int setExpectedFingerprint(const std::string& fingerprintHex) {
        if (!m_ctx) return POSIX_TLS_ERR_INVALID_ARG;
        return posix_tls_context_set_expected_fingerprint(m_ctx, fingerprintHex.c_str());
    }

    int setCredentials(const std::string& certPem, const std::string& keyPem) {
        if (!m_ctx) return POSIX_TLS_ERR_INVALID_ARG;
        return posix_tls_context_set_credentials(
            m_ctx, certPem.data(), certPem.size(), keyPem.data(), keyPem.size());
    }

    int setMinTlsVersion(posix_tls_version_t version) {
        if (!m_ctx) return POSIX_TLS_ERR_INVALID_ARG;
        return posix_tls_context_set_min_tls_version(m_ctx, version);
    }

    int setMaxTlsVersion(posix_tls_version_t version) {
        if (!m_ctx) return POSIX_TLS_ERR_INVALID_ARG;
        return posix_tls_context_set_max_tls_version(m_ctx, version);
    }

private:
    Context(const Context&);
    Context& operator=(const Context&);

    posix_tls_context_t* m_ctx;
};

class Connection {
public:
    Connection(Context& ctx, int socketFd)
        : m_conn(posix_tls_connection_create(ctx.get(), socketFd))
    {
    }

    ~Connection() {
        if (m_conn) {
            posix_tls_connection_destroy(m_conn);
            m_conn = NULL;
        }
    }

    bool isValid() const {
        return m_conn != NULL;
    }

    posix_tls_connection_t* get() const {
        return m_conn;
    }

    int connect(const std::string& hostname) {
        if (!m_conn) return POSIX_TLS_ERR_INVALID_ARG;
        return posix_tls_connect(m_conn, hostname.c_str());
    }

    int accept() {
        if (!m_conn) return POSIX_TLS_ERR_INVALID_ARG;
        return posix_tls_accept(m_conn);
    }

    int read(void* buf, size_t count, size_t& bytesRead) {
        if (!m_conn) return POSIX_TLS_ERR_INVALID_ARG;
        return posix_tls_read(m_conn, buf, count, &bytesRead);
    }

    int write(const void* buf, size_t count, size_t& bytesWritten) {
        if (!m_conn) return POSIX_TLS_ERR_INVALID_ARG;
        return posix_tls_write(m_conn, buf, count, &bytesWritten);
    }

    int shutdown() {
        if (!m_conn) return POSIX_TLS_ERR_INVALID_ARG;
        return posix_tls_shutdown(m_conn);
    }

    int getFd() const {
        if (!m_conn) return -1;
        return posix_tls_connection_get_fd(m_conn);
    }

    std::string getNegotiatedVersion() const {
        if (!m_conn) return "";
        char buf[32];
        if (posix_tls_connection_get_negotiated_version(m_conn, buf, sizeof(buf)) == POSIX_TLS_OK) {
            return std::string(buf);
        }
        return "";
    }

    std::string getCipher() const {
        if (!m_conn) return "";
        char buf[64];
        if (posix_tls_connection_get_cipher(m_conn, buf, sizeof(buf)) == POSIX_TLS_OK) {
            return std::string(buf);
        }
        return "";
    }

    std::string getPeerFingerprint() const {
        if (!m_conn) return "";
        char buf[65];
        if (posix_tls_connection_get_peer_fingerprint(m_conn, buf) == POSIX_TLS_OK) {
            return std::string(buf);
        }
        return "";
    }

    std::string getLastError() const {
        if (!m_conn) return "Invalid connection handle";
        const char* err = posix_tls_get_last_error(m_conn);
        return err ? std::string(err) : std::string();
    }

private:
    Connection(const Connection&);
    Connection& operator=(const Connection&);

    posix_tls_connection_t* m_conn;
};

inline int randomBytes(unsigned char* buf, size_t len) {
    return posix_tls_random_bytes(buf, len);
}

inline int sha256(const unsigned char* data, size_t len, unsigned char* outHash32) {
    return posix_tls_sha256(data, len, outHash32);
}

inline int sha256File(const std::string& filepath, std::string& outHex) {
    char hex[65];
    int rc = posix_tls_sha256_file(filepath.c_str(), hex);
    if (rc == POSIX_TLS_OK) {
        outHex = std::string(hex);
    }
    return rc;
}

inline int calculateCertFingerprint(const std::string& certPem, std::string& outFingerprint) {
    char buf[65];
    int rc = posix_tls_calculate_cert_fingerprint(certPem.c_str(), certPem.size(), buf);
    if (rc == POSIX_TLS_OK) {
        outFingerprint = buf;
    }
    return rc;
}

inline int generateSelfSignedCert(std::string& outCertPem, std::string& outKeyPem) {
    char* cert = NULL;
    size_t certLen = 0;
    char* key = NULL;
    size_t keyLen = 0;
    int rc = posix_tls_generate_self_signed_cert(&cert, &certLen, &key, &keyLen);
    if (rc == POSIX_TLS_OK) {
        if (cert) {
            outCertPem.assign(cert, certLen);
            posix_tls_free_string(cert);
        }
        if (key) {
            outKeyPem.assign(key, keyLen);
            posix_tls_free_string(key);
        }
    }
    return rc;
}

} // namespace posix_tls

#endif /* POSIX_TLS_HPP */
