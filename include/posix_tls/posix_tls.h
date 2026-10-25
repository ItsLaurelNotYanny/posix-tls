#ifndef POSIX_TLS_H
#define POSIX_TLS_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Return and error codes */
#define POSIX_TLS_OK                      0
#define POSIX_TLS_ERR_WANT_READ          -1
#define POSIX_TLS_ERR_WANT_WRITE         -2
#define POSIX_TLS_ERR_CLOSED             -3
#define POSIX_TLS_ERR_INVALID_ARG        -4
#define POSIX_TLS_ERR_INVALID_PIN        -5
#define POSIX_TLS_ERR_PIN_MISMATCH       -6
#define POSIX_TLS_ERR_NO_PEER_CERT       -7
#define POSIX_TLS_ERR_CERT_VERIFY        -8
#define POSIX_TLS_ERR_CA_LOAD_FAILED     -9
#define POSIX_TLS_ERR_HANDSHAKE_FAILED  -10
#define POSIX_TLS_ERR_ENTROPY_FAILURE   -11
#define POSIX_TLS_ERR_OUT_OF_MEMORY     -12
#define POSIX_TLS_ERR_IO_FAILED         -13
#define POSIX_TLS_ERR_INTERNAL          -14

/* Verification and usage policies */
typedef enum {
    POSIX_TLS_POLICY_PUBLIC_PKI = 1,
    POSIX_TLS_POLICY_P2P        = 2
} posix_tls_policy_t;

/* TLS protocol versions */
typedef enum {
    POSIX_TLS_VERSION_DEFAULT = 0,
    POSIX_TLS_VERSION_1_2     = 0x0303,
    POSIX_TLS_VERSION_1_3     = 0x0304
} posix_tls_version_t;

/* Opaque context and connection handles */
typedef struct posix_tls_context posix_tls_context_t;
typedef struct posix_tls_connection posix_tls_connection_t;

/* Context management */
posix_tls_context_t* posix_tls_context_create(posix_tls_policy_t policy);
void posix_tls_context_destroy(posix_tls_context_t* ctx);

int posix_tls_context_set_ca_path(posix_tls_context_t* ctx, const char* ca_bundle_path);
int posix_tls_context_set_expected_fingerprint(posix_tls_context_t* ctx, const char* sha256_hex);
int posix_tls_context_set_credentials(posix_tls_context_t* ctx,
                                     const char* cert_pem,
                                     size_t cert_len,
                                     const char* key_pem,
                                     size_t key_len);
int posix_tls_context_set_min_tls_version(posix_tls_context_t* ctx, posix_tls_version_t version);
int posix_tls_context_set_max_tls_version(posix_tls_context_t* ctx, posix_tls_version_t version);

/* Connection management */
posix_tls_connection_t* posix_tls_connection_create(posix_tls_context_t* ctx, int socket_fd);
void posix_tls_connection_destroy(posix_tls_connection_t* conn);

int posix_tls_connect(posix_tls_connection_t* conn, const char* hostname);
int posix_tls_accept(posix_tls_connection_t* conn);

int posix_tls_read(posix_tls_connection_t* conn, void* buf, size_t count, size_t* bytes_read);
int posix_tls_write(posix_tls_connection_t* conn, const void* buf, size_t count, size_t* bytes_written);
int posix_tls_shutdown(posix_tls_connection_t* conn);

int posix_tls_connection_get_fd(const posix_tls_connection_t* conn);
int posix_tls_connection_get_negotiated_version(const posix_tls_connection_t* conn, char* out_buf, size_t buf_len);
int posix_tls_connection_get_cipher(const posix_tls_connection_t* conn, char* out_buf, size_t buf_len);
int posix_tls_connection_get_peer_fingerprint(const posix_tls_connection_t* conn, char* out_hex_65);
const char* posix_tls_get_last_error(const posix_tls_connection_t* conn);

/* Standalone crypto helpers */
int posix_tls_random_bytes(unsigned char* buf, size_t len);
int posix_tls_sha256(const unsigned char* data, size_t len, unsigned char* out_hash_32);
int posix_tls_sha256_file(const char* filepath, char* out_hex_65);
int posix_tls_calculate_cert_fingerprint(const char* cert_pem, size_t cert_len, char* out_hex_65);
int posix_tls_generate_self_signed_cert(char** out_cert_pem,
                                       size_t* out_cert_len,
                                       char** out_key_pem,
                                       size_t* out_key_len);
void posix_tls_free_string(char* str);
const char* posix_tls_strerror(int err);

#ifdef __cplusplus
}
#endif

#endif /* POSIX_TLS_H */
