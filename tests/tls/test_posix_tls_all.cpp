#include "posix_tls/posix_tls.h"
#include "posix_tls/posix_tls.hpp"

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <pthread.h>
#include <signal.h>

#include <iostream>
#include <sstream>
#include <vector>
#include <climits>
#include <cassert>
#include <cstring>
#include <cstdio>
#include <cstdlib>

#if !defined(MAP_ANONYMOUS) && defined(MAP_ANON)
#define MAP_ANONYMOUS MAP_ANON
#endif

#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/rand.h>

#define TEST_ASSERT(cond, msg) \
    do { \
        if (!(cond)) { \
            std::cerr << "Assertion failed at " << __FILE__ << ":" << __LINE__ \
                      << " in " << __FUNCTION__ << ": " << (msg) << std::endl; \
            std::exit(1); \
        } \
    } while (0)

static int g_test_count = 0;

static void run_test(void (*test_fn)(), const char* test_name) {
    std::cout << "[RUNNING] " << test_name << "..." << std::flush;
    test_fn();
    g_test_count++;
    std::cout << " PASSED" << std::endl;
}

// ---------------------------------------------------------------------------
// Test 1: Context Lifecycle & Invalid Policies
// ---------------------------------------------------------------------------
static void test_context_lifecycle() {
    posix_tls_context_t* ctx_pki = posix_tls_context_create(POSIX_TLS_POLICY_PUBLIC_PKI);
    TEST_ASSERT(ctx_pki != NULL, "Public PKI context creation failed");
    posix_tls_context_destroy(ctx_pki);

    posix_tls_context_t* ctx_p2p = posix_tls_context_create(POSIX_TLS_POLICY_P2P);
    TEST_ASSERT(ctx_p2p != NULL, "P2P context creation failed");
    posix_tls_context_destroy(ctx_p2p);

    posix_tls_context_t* ctx_invalid = posix_tls_context_create(static_cast<posix_tls_policy_t>(999));
    TEST_ASSERT(ctx_invalid == NULL, "Invalid policy should return NULL");

    // NULL destroy must not crash
    posix_tls_context_destroy(NULL);
}

// ---------------------------------------------------------------------------
// Test 2: Expected Fingerprint Pin Validation & Normalization
// ---------------------------------------------------------------------------
static void test_fingerprint_pin_validation() {
    posix_tls_context_t* ctx = posix_tls_context_create(POSIX_TLS_POLICY_P2P);
    TEST_ASSERT(ctx != NULL, "Context create failed");

    // Valid standard 64 lowercase hex
    const char* valid_hex = "a1b2c3d4e5f60718293a4b5c6d7e8f90123456789abcdef0123456789abcdef0";
    TEST_ASSERT(posix_tls_context_set_expected_fingerprint(ctx, valid_hex) == POSIX_TLS_OK,
                "Valid hex should succeed");

    // Valid with uppercase letters
    const char* valid_upper = "A1B2C3D4E5F60718293A4B5C6D7E8F90123456789ABCDEF0123456789ABCDEF0";
    TEST_ASSERT(posix_tls_context_set_expected_fingerprint(ctx, valid_upper) == POSIX_TLS_OK,
                "Valid uppercase hex should succeed");

    // Valid with colons (common fingerprint representation)
    const char* valid_colons = "A1:B2:C3:D4:E5:F6:07:18:29:3A:4B:5C:6D:7E:8F:90:"
                              "12:34:56:78:9A:BC:DE:F0:12:34:56:78:9A:BC:DE:F0";
    TEST_ASSERT(posix_tls_context_set_expected_fingerprint(ctx, valid_colons) == POSIX_TLS_OK,
                "Valid hex with colons should succeed");

    // Invalid: Too short (63 chars)
    const char* too_short = "a1b2c3d4e5f60718293a4b5c6d7e8f90123456789abcdef0123456789abcde";
    TEST_ASSERT(posix_tls_context_set_expected_fingerprint(ctx, too_short) == POSIX_TLS_ERR_INVALID_PIN,
                "Too short pin must be rejected");

    // Invalid: Too long (65 chars)
    const char* too_long = "a1b2c3d4e5f60718293a4b5c6d7e8f90123456789abcdef0123456789abcdef00";
    TEST_ASSERT(posix_tls_context_set_expected_fingerprint(ctx, too_long) == POSIX_TLS_ERR_INVALID_PIN,
                "Too long pin must be rejected");

    // Invalid: Illegal non-hex character 'g'
    const char* illegal_char = "g1b2c3d4e5f60718293a4b5c6d7e8f90123456789abcdef0123456789abcdef0";
    TEST_ASSERT(posix_tls_context_set_expected_fingerprint(ctx, illegal_char) == POSIX_TLS_ERR_INVALID_PIN,
                "Non-hex character pin must be rejected");

    // Invalid: Empty string
    TEST_ASSERT(posix_tls_context_set_expected_fingerprint(ctx, "") == POSIX_TLS_ERR_INVALID_PIN,
                "Empty string pin must be rejected");

    // Invalid: NULL pointer
    TEST_ASSERT(posix_tls_context_set_expected_fingerprint(ctx, NULL) == POSIX_TLS_ERR_INVALID_ARG,
                "NULL pin must return INVALID_ARG");

    posix_tls_context_destroy(ctx);
}

// ---------------------------------------------------------------------------
// Test 3: CSPRNG Random Bytes
// ---------------------------------------------------------------------------
static void test_random_bytes() {
    unsigned char buf1[32];
    unsigned char buf2[32];
    std::memset(buf1, 0, sizeof(buf1));
    std::memset(buf2, 0, sizeof(buf2));

    TEST_ASSERT(posix_tls_random_bytes(buf1, sizeof(buf1)) == POSIX_TLS_OK, "Random bytes 1 failed");
    TEST_ASSERT(posix_tls_random_bytes(buf2, sizeof(buf2)) == POSIX_TLS_OK, "Random bytes 2 failed");

    // Verify entropy (not all zeroes and not identical)
    bool non_zero1 = false;
    for (size_t i = 0; i < sizeof(buf1); ++i) {
        if (buf1[i] != 0) non_zero1 = true;
    }
    TEST_ASSERT(non_zero1, "Random bytes buffer 1 should not be all zeroes");
    TEST_ASSERT(std::memcmp(buf1, buf2, sizeof(buf1)) != 0, "Consecutive random byte buffers should differ");

    // Error cases
    TEST_ASSERT(posix_tls_random_bytes(NULL, 16) == POSIX_TLS_ERR_INVALID_ARG, "NULL buffer must fail");
    TEST_ASSERT(posix_tls_random_bytes(buf1, 0) == POSIX_TLS_ERR_INVALID_ARG, "Zero length must fail");
}

// ---------------------------------------------------------------------------
// Test 4: SHA-256 Hashing
// ---------------------------------------------------------------------------
static void test_sha256_hash() {
    // SHA-256 of empty string: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
    const unsigned char empty_str[] = "";
    unsigned char hash[32];
    TEST_ASSERT(posix_tls_sha256(empty_str, 0, hash) == POSIX_TLS_OK, "SHA256 empty string failed");

    char hex[65];
    for (int i = 0; i < 32; ++i) {
        sprintf(hex + (i * 2), "%02x", hash[i]);
    }
    hex[64] = '\0';
    TEST_ASSERT(std::strcmp(hex, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") == 0,
                "Empty string SHA-256 mismatch");

    // Test file hashing
    const char* tmp_file = "/tmp/test_posix_tls_sha.txt";
    FILE* fp = fopen(tmp_file, "wb");
    TEST_ASSERT(fp != NULL, "Failed to create temp file");
    const char* test_data = "The quick brown fox jumps over the lazy dog";
    fwrite(test_data, 1, strlen(test_data), fp);
    fclose(fp);

    char file_hex[65];
    TEST_ASSERT(posix_tls_sha256_file(tmp_file, file_hex) == POSIX_TLS_OK, "SHA256 file failed");
    // Known SHA-256 for "The quick brown fox jumps over the lazy dog":
    // d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592
    TEST_ASSERT(std::strcmp(file_hex, "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592") == 0,
                "File SHA-256 mismatch");
    unlink(tmp_file);

    // Non-existent file
    TEST_ASSERT(posix_tls_sha256_file("/tmp/non_existent_file_posix_tls.bin", file_hex) == POSIX_TLS_ERR_IO_FAILED,
                "Non-existent file should return IO_FAILED");
}

// ---------------------------------------------------------------------------
// Test 5: Self-Signed Certificate and Key Generation
// ---------------------------------------------------------------------------
static void test_self_signed_cert_generation() {
    char* cert_pem = NULL;
    size_t cert_len = 0;
    char* key_pem = NULL;
    size_t key_len = 0;

    int rc = posix_tls_generate_self_signed_cert(&cert_pem, &cert_len, &key_pem, &key_len);
    TEST_ASSERT(rc == POSIX_TLS_OK, "Self signed cert generation failed");
    TEST_ASSERT(cert_pem != NULL && cert_len > 0, "Certificate PEM invalid");
    TEST_ASSERT(key_pem != NULL && key_len > 0, "Key PEM invalid");

    // Verify PEM structure headers
    TEST_ASSERT(std::strstr(cert_pem, "-----BEGIN CERTIFICATE-----") != NULL, "Missing cert PEM header");
    TEST_ASSERT(std::strstr(key_pem, "-----BEGIN PRIVATE KEY-----") != NULL, "Missing key PEM header");

    // Verify it loads cleanly into context
    posix_tls_context_t* ctx = posix_tls_context_create(POSIX_TLS_POLICY_P2P);
    TEST_ASSERT(ctx != NULL, "Context create failed");
    int set_rc = posix_tls_context_set_credentials(ctx, cert_pem, cert_len, key_pem, key_len);
    TEST_ASSERT(set_rc == POSIX_TLS_OK, "Loading generated credentials into context failed");

    posix_tls_context_destroy(ctx);
    posix_tls_free_string(cert_pem);
    posix_tls_free_string(key_pem);
}

// ---------------------------------------------------------------------------
// Test 6: CA Bundle Load & Fail-Closed Behavior
// ---------------------------------------------------------------------------
static const char* find_cacert_path() {
    if (access("vendor/sources/cacert.pem", R_OK) == 0) {
        return "vendor/sources/cacert.pem";
    }
    if (access("../vendor/sources/cacert.pem", R_OK) == 0) {
        return "../vendor/sources/cacert.pem";
    }
    return NULL;
}

static void test_ca_bundle_loading() {
    posix_tls_context_t* ctx = posix_tls_context_create(POSIX_TLS_POLICY_PUBLIC_PKI);
    TEST_ASSERT(ctx != NULL, "Context create failed");

    // Non-existent path fails closed
    int rc_bad = posix_tls_context_set_ca_path(ctx, "/path/does/not/exist/cacert.pem");
    TEST_ASSERT(rc_bad == POSIX_TLS_ERR_CA_LOAD_FAILED, "Non-existent CA bundle must return CA_LOAD_FAILED");

    // Real CA bundle from vendor/sources/cacert.pem
    const char* ca_path = find_cacert_path();
    TEST_ASSERT(ca_path != NULL, "cacert.pem must be present in vendor/sources/");
    int rc_good = posix_tls_context_set_ca_path(ctx, ca_path);
    TEST_ASSERT(rc_good == POSIX_TLS_OK, "Valid vendor CA bundle should load successfully");

    posix_tls_context_destroy(ctx);
}

// ---------------------------------------------------------------------------
// Server thread argument and worker for loopback handshake
// ---------------------------------------------------------------------------
struct ServerThreadArg {
    posix_tls_context_t* ctx;
    int fd;
    int result_rc;
    char negotiated_version[32];
    char negotiated_cipher[64];
    std::string received_msg;
};

static void* p2p_server_worker(void* arg) {
    ServerThreadArg* sarg = static_cast<ServerThreadArg*>(arg);
    posix_tls_connection_t* conn = posix_tls_connection_create(sarg->ctx, sarg->fd);
    if (!conn) {
        sarg->result_rc = POSIX_TLS_ERR_INTERNAL;
        close(sarg->fd);
        return NULL;
    }

    sarg->result_rc = posix_tls_accept(conn);
    if (sarg->result_rc == POSIX_TLS_OK) {
        posix_tls_connection_get_negotiated_version(conn, sarg->negotiated_version, sizeof(sarg->negotiated_version));
        posix_tls_connection_get_cipher(conn, sarg->negotiated_cipher, sizeof(sarg->negotiated_cipher));

        // Read client message
        char buf[128];
        size_t nread = 0;
        int r_rc = posix_tls_read(conn, buf, sizeof(buf) - 1, &nread);
        if (r_rc == POSIX_TLS_OK && nread > 0) {
            buf[nread] = '\0';
            sarg->received_msg = buf;
            // Echo response
            const char* resp = "PONG_FROM_SERVER";
            size_t nwritten = 0;
            posix_tls_write(conn, resp, strlen(resp), &nwritten);
        }
        posix_tls_shutdown(conn);
    }

    posix_tls_connection_destroy(conn);
    return NULL;
}

// ---------------------------------------------------------------------------
// Test 7: Loopback Socketpair TLS 1.3 Handshake & Bi-directional Transfer
// ---------------------------------------------------------------------------
static void test_loopback_p2p_tls13_handshake() {
    // 1. Generate Server credentials
    char* cert_pem = NULL;
    size_t cert_len = 0;
    char* key_pem = NULL;
    size_t key_len = 0;
    TEST_ASSERT(posix_tls_generate_self_signed_cert(&cert_pem, &cert_len, &key_pem, &key_len) == POSIX_TLS_OK,
                "Cert gen failed");

    // Calculate certificate fingerprint
    BIO* cbio = BIO_new_mem_buf(cert_pem, static_cast<int>(cert_len));
    X509* cert = PEM_read_bio_X509(cbio, NULL, NULL, NULL);
    BIO_free(cbio);
    TEST_ASSERT(cert != NULL, "PEM parse failed");

    unsigned char* der = NULL;
    int der_len = i2d_X509(cert, &der);
    TEST_ASSERT(der_len > 0, "DER encode failed");
    unsigned char hash[32];
    TEST_ASSERT(posix_tls_sha256(der, static_cast<size_t>(der_len), hash) == POSIX_TLS_OK, "SHA256 failed");
    OPENSSL_free(der);
    X509_free(cert);

    char server_fingerprint[65];
    for (int i = 0; i < 32; ++i) {
        sprintf(server_fingerprint + (i * 2), "%02x", hash[i]);
    }
    server_fingerprint[64] = '\0';

    // 2. Setup Server Context
    posix_tls_context_t* s_ctx = posix_tls_context_create(POSIX_TLS_POLICY_P2P);
    TEST_ASSERT(s_ctx != NULL, "Server ctx create failed");
    TEST_ASSERT(posix_tls_context_set_credentials(s_ctx, cert_pem, cert_len, key_pem, key_len) == POSIX_TLS_OK,
                "Server set credentials failed");

    // 3. Setup Client Context (Configured with expected server fingerprint)
    posix_tls_context_t* c_ctx = posix_tls_context_create(POSIX_TLS_POLICY_P2P);
    TEST_ASSERT(c_ctx != NULL, "Client ctx create failed");
    TEST_ASSERT(posix_tls_context_set_expected_fingerprint(c_ctx, server_fingerprint) == POSIX_TLS_OK,
                "Client set expected fingerprint failed");

    // 4. Create full-duplex socket pair
    int sv[2];
    TEST_ASSERT(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "socketpair failed");

    ServerThreadArg sarg;
    sarg.ctx = s_ctx;
    sarg.fd = sv[0];
    sarg.result_rc = -999;
    sarg.negotiated_version[0] = '\0';
    sarg.negotiated_cipher[0] = '\0';

    pthread_t sthread;
    TEST_ASSERT(pthread_create(&sthread, NULL, p2p_server_worker, &sarg) == 0, "pthread_create failed");

    // Client connection
    posix_tls_connection_t* c_conn = posix_tls_connection_create(c_ctx, sv[1]);
    TEST_ASSERT(c_conn != NULL, "Client connection create failed");

    int c_rc = posix_tls_connect(c_conn, NULL);
    TEST_ASSERT(c_rc == POSIX_TLS_OK, "Client posix_tls_connect failed");

    // Verify TLS 1.3 negotiated
    char c_ver[32];
    posix_tls_connection_get_negotiated_version(c_conn, c_ver, sizeof(c_ver));
    TEST_ASSERT(std::strcmp(c_ver, "TLSv1.3") == 0, "Negotiated version must be TLSv1.3");

    // Verify peer fingerprint matches
    char c_peer_fp[65];
    TEST_ASSERT(posix_tls_connection_get_peer_fingerprint(c_conn, c_peer_fp) == POSIX_TLS_OK, "Get peer fingerprint failed");
    TEST_ASSERT(std::strcmp(c_peer_fp, server_fingerprint) == 0, "Peer fingerprint does not match expected");

    // Send data to server
    const char* ping_msg = "PING_FROM_CLIENT";
    size_t written = 0;
    TEST_ASSERT(posix_tls_write(c_conn, ping_msg, strlen(ping_msg), &written) == POSIX_TLS_OK, "Client write failed");
    TEST_ASSERT(written == strlen(ping_msg), "Write size mismatch");

    // Read response from server
    char resp_buf[128];
    size_t nread = 0;
    TEST_ASSERT(posix_tls_read(c_conn, resp_buf, sizeof(resp_buf) - 1, &nread) == POSIX_TLS_OK, "Client read failed");
    resp_buf[nread] = '\0';
    TEST_ASSERT(std::strcmp(resp_buf, "PONG_FROM_SERVER") == 0, "Server response content mismatch");

    posix_tls_shutdown(c_conn);
    posix_tls_connection_destroy(c_conn);

    pthread_join(sthread, NULL);
    TEST_ASSERT(sarg.result_rc == POSIX_TLS_OK, "Server accept failed");
    TEST_ASSERT(sarg.received_msg == "PING_FROM_CLIENT", "Server received content mismatch");

    posix_tls_context_destroy(s_ctx);
    posix_tls_context_destroy(c_ctx);
    posix_tls_free_string(cert_pem);
    posix_tls_free_string(key_pem);
}

// ---------------------------------------------------------------------------
// Test 8: P2P Fingerprint Mismatch Rejection
// ---------------------------------------------------------------------------
static void test_p2p_fingerprint_mismatch_rejection() {
    char* cert_pem = NULL;
    size_t cert_len = 0;
    char* key_pem = NULL;
    size_t key_len = 0;
    TEST_ASSERT(posix_tls_generate_self_signed_cert(&cert_pem, &cert_len, &key_pem, &key_len) == POSIX_TLS_OK,
                "Cert gen failed");

    posix_tls_context_t* s_ctx = posix_tls_context_create(POSIX_TLS_POLICY_P2P);
    TEST_ASSERT(posix_tls_context_set_credentials(s_ctx, cert_pem, cert_len, key_pem, key_len) == POSIX_TLS_OK,
                "Server set creds failed");

    // Client has a deliberate wrong fingerprint pin
    const char* wrong_pin = "0000000000000000000000000000000000000000000000000000000000000000";
    posix_tls_context_t* c_ctx = posix_tls_context_create(POSIX_TLS_POLICY_P2P);
    TEST_ASSERT(posix_tls_context_set_expected_fingerprint(c_ctx, wrong_pin) == POSIX_TLS_OK,
                "Client set wrong pin failed");

    int sv[2];
    TEST_ASSERT(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "socketpair failed");

    ServerThreadArg sarg;
    sarg.ctx = s_ctx;
    sarg.fd = sv[0];
    sarg.result_rc = -999;

    pthread_t sthread;
    TEST_ASSERT(pthread_create(&sthread, NULL, p2p_server_worker, &sarg) == 0, "pthread_create failed");

    posix_tls_connection_t* c_conn = posix_tls_connection_create(c_ctx, sv[1]);
    TEST_ASSERT(c_conn != NULL, "Client conn create failed");

    int c_rc = posix_tls_connect(c_conn, NULL);
    TEST_ASSERT(c_rc == POSIX_TLS_ERR_PIN_MISMATCH, "Client must reject with PIN_MISMATCH");

    posix_tls_connection_destroy(c_conn);
    pthread_join(sthread, NULL);

    posix_tls_context_destroy(s_ctx);
    posix_tls_context_destroy(c_ctx);
    posix_tls_free_string(cert_pem);
    posix_tls_free_string(key_pem);
}

// ---------------------------------------------------------------------------
// Test 9: P2P Verifying Client Missing Pin Fails Closed Before Network I/O
// ---------------------------------------------------------------------------
static void test_p2p_missing_pin_fails_closed() {
    posix_tls_context_t* c_ctx = posix_tls_context_create(POSIX_TLS_POLICY_P2P);
    TEST_ASSERT(c_ctx != NULL, "Client ctx create failed");

    // Do NOT set expected fingerprint on client
    int sv[2];
    TEST_ASSERT(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "socketpair failed");

    posix_tls_connection_t* c_conn = posix_tls_connection_create(c_ctx, sv[0]);
    TEST_ASSERT(c_conn != NULL, "Client conn create failed");

    int c_rc = posix_tls_connect(c_conn, NULL);
    TEST_ASSERT(c_rc == POSIX_TLS_ERR_INVALID_PIN, "Client without expected pin must fail with INVALID_PIN");

    posix_tls_connection_destroy(c_conn);
    close(sv[1]);
    posix_tls_context_destroy(c_ctx);
}

// ---------------------------------------------------------------------------
// Test 10: Descriptor Sentinel & Sole Ownership Rules
// ---------------------------------------------------------------------------
static void test_descriptor_sentinel_and_ownership() {
    posix_tls_context_t* ctx = posix_tls_context_create(POSIX_TLS_POLICY_P2P);
    TEST_ASSERT(ctx != NULL, "Context create failed");

    int sv[2];
    TEST_ASSERT(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "socketpair failed");

    int fd0 = sv[0];
    int fd1 = sv[1];

    posix_tls_connection_t* conn = posix_tls_connection_create(ctx, fd0);
    TEST_ASSERT(conn != NULL, "Connection create failed");
    TEST_ASSERT(posix_tls_connection_get_fd(conn) == fd0, "get_fd mismatch");

    // Destroy connection: must close fd0
    posix_tls_connection_destroy(conn);

    // Verify fd0 is now closed (write or close on it fails with EBADF)
    char dummy = 'x';
    ssize_t w = write(fd0, &dummy, 1);
    TEST_ASSERT(w < 0, "Destroyed socket fd should be closed");

    // Sentinel -1 check
    TEST_ASSERT(posix_tls_connection_get_fd(NULL) == -1, "NULL connection get_fd must return -1");

    close(fd1);
    posix_tls_context_destroy(ctx);
}

// ---------------------------------------------------------------------------
// Test 11: Public PKI Verification Fails Closed Against Self-Signed Server
// ---------------------------------------------------------------------------
static void test_public_pki_rejects_untrusted_server() {
    char* cert_pem = NULL;
    size_t cert_len = 0;
    char* key_pem = NULL;
    size_t key_len = 0;
    TEST_ASSERT(posix_tls_generate_self_signed_cert(&cert_pem, &cert_len, &key_pem, &key_len) == POSIX_TLS_OK,
                "Cert gen failed");

    posix_tls_context_t* s_ctx = posix_tls_context_create(POSIX_TLS_POLICY_P2P);
    TEST_ASSERT(posix_tls_context_set_credentials(s_ctx, cert_pem, cert_len, key_pem, key_len) == POSIX_TLS_OK,
                "Server credentials failed");

    // Client uses Public PKI with official Mozilla CA bundle
    posix_tls_context_t* c_ctx = posix_tls_context_create(POSIX_TLS_POLICY_PUBLIC_PKI);
    const char* ca_path = find_cacert_path();
    TEST_ASSERT(ca_path != NULL, "cacert.pem must be present in vendor/sources/");
    TEST_ASSERT(posix_tls_context_set_ca_path(c_ctx, ca_path) == POSIX_TLS_OK,
                "CA path load failed");

    int sv[2];
    TEST_ASSERT(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "socketpair failed");

    ServerThreadArg sarg;
    sarg.ctx = s_ctx;
    sarg.fd = sv[0];
    sarg.result_rc = -999;

    pthread_t sthread;
    TEST_ASSERT(pthread_create(&sthread, NULL, p2p_server_worker, &sarg) == 0, "pthread_create failed");

    posix_tls_connection_t* c_conn = posix_tls_connection_create(c_ctx, sv[1]);
    TEST_ASSERT(c_conn != NULL, "Client conn create failed");

    // Client connects expecting untrusted server; CA chain check must fail
    int c_rc = posix_tls_connect(c_conn, "example.com");
    TEST_ASSERT(c_rc == POSIX_TLS_ERR_CERT_VERIFY || c_rc == POSIX_TLS_ERR_HANDSHAKE_FAILED,
                "Public PKI client must reject untrusted self-signed certificate");

    posix_tls_connection_destroy(c_conn);
    pthread_join(sthread, NULL);

    posix_tls_context_destroy(s_ctx);
    posix_tls_context_destroy(c_ctx);
    posix_tls_free_string(cert_pem);
    posix_tls_free_string(key_pem);
}

// ---------------------------------------------------------------------------
// Test 12: SAN Precedence (RFC 6125) Verification
// ---------------------------------------------------------------------------
static void test_san_precedence_rfc6125() {
    // Generate an EC key
    EVP_PKEY* pkey = EVP_EC_gen("P-256");
    TEST_ASSERT(pkey != NULL, "EVP_EC_gen failed");

    X509* cert = X509_new();
    TEST_ASSERT(cert != NULL, "X509_new failed");
    X509_set_version(cert, 2); // X509 v3
    ASN1_INTEGER_set(X509_get_serialNumber(cert), 12345);
    X509_gmtime_adj(X509_getm_notBefore(cert), 0);
    X509_gmtime_adj(X509_getm_notAfter(cert), 315360000L);

    // Subject Common Name is "legacy-cn.example.com"
    X509_NAME* name = X509_NAME_new();
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                               (const unsigned char*)"legacy-cn.example.com", -1, -1, 0);
    X509_set_subject_name(cert, name);
    X509_set_issuer_name(cert, name);
    X509_NAME_free(name);

    X509_set_pubkey(cert, pkey);

    // Add Subject Alternative Name (SAN): "DNS:san-precedence.example.com"
    X509V3_CTX v3_ctx;
    X509V3_set_ctx_nodb(&v3_ctx);
    X509V3_set_ctx(&v3_ctx, cert, cert, NULL, NULL, 0);
    X509_EXTENSION* ext = X509V3_EXT_conf_nid(NULL, &v3_ctx, NID_subject_alt_name,
                                             const_cast<char*>("DNS:san-precedence.example.com"));
    TEST_ASSERT(ext != NULL, "SAN extension creation failed");
    X509_add_ext(cert, ext, -1);
    X509_EXTENSION_free(ext);

    TEST_ASSERT(X509_sign(cert, pkey, EVP_sha256()) > 0, "X509_sign failed");

    // OpenSSL X509_check_host verification check
    // 1. Check against SAN name -> MUST MATCH (1)
    int san_match = X509_check_host(cert, "san-precedence.example.com", 0, 0, NULL);
    TEST_ASSERT(san_match == 1, "SAN hostname must match");

    // 2. Check against CN name when SAN is present -> MUST FAIL (0) per RFC 6125 (CN is ignored if SAN is present!)
    int cn_match = X509_check_host(cert, "legacy-cn.example.com", 0, 0, NULL);
    TEST_ASSERT(cn_match == 0, "RFC 6125 SAN Precedence: CN must be ignored when SAN is present");

    X509_free(cert);
    EVP_PKEY_free(pkey);
}

// ---------------------------------------------------------------------------
// Test 13: C++03 RAII Wrappers
// ---------------------------------------------------------------------------
static void test_cpp03_raii_wrappers() {
    posix_tls::Context ctx(POSIX_TLS_POLICY_P2P);
    TEST_ASSERT(ctx.isValid(), "Context wrapper isValid failed");
    TEST_ASSERT(ctx.setExpectedFingerprint("a1b2c3d4e5f60718293a4b5c6d7e8f90123456789abcdef0123456789abcdef0") == POSIX_TLS_OK,
                "Context setExpectedFingerprint failed");

    std::string certPem, keyPem;
    TEST_ASSERT(posix_tls::generateSelfSignedCert(certPem, keyPem) == POSIX_TLS_OK,
                "generateSelfSignedCert failed");
    TEST_ASSERT(!certPem.empty() && !keyPem.empty(), "Generated PEMs empty");

    int sv[2];
    TEST_ASSERT(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "socketpair failed");

    {
        posix_tls::Connection conn(ctx, sv[0]);
        TEST_ASSERT(conn.isValid(), "Connection wrapper isValid failed");
        TEST_ASSERT(conn.getFd() == sv[0], "Connection getFd mismatch");
        // conn goes out of scope here and destructor closes sv[0]
    }

    // Verify sv[0] is closed by RAII destructor
    char c = 0;
    TEST_ASSERT(write(sv[0], &c, 1) < 0, "Connection RAII destructor must close fd");
    close(sv[1]);
}

#if defined(__GNUC__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#endif

// ---------------------------------------------------------------------------
// Test 14: Mock Entropy Failure Injection
// ---------------------------------------------------------------------------
static int mock_failing_rand_bytes(unsigned char* /*buf*/, int /*num*/) {
    return 0; // Fail RNG
}

static int mock_failing_rand_status(void) {
    return 0;
}

static void test_entropy_failure_injection() {
    RAND_METHOD failing_meth;
    std::memset(&failing_meth, 0, sizeof(failing_meth));
    failing_meth.bytes = mock_failing_rand_bytes;
    failing_meth.pseudorand = mock_failing_rand_bytes;
    failing_meth.status = mock_failing_rand_status;

    const RAND_METHOD* orig_meth = RAND_get_rand_method();
    RAND_set_rand_method(&failing_meth);

    unsigned char buf[32];
    int r_rc = posix_tls_random_bytes(buf, sizeof(buf));
    TEST_ASSERT(r_rc == POSIX_TLS_ERR_ENTROPY_FAILURE, "posix_tls_random_bytes must fail with ENTROPY_FAILURE");

    char* cert = NULL;
    char* key = NULL;
    size_t clen = 0, klen = 0;
    int g_rc = posix_tls_generate_self_signed_cert(&cert, &clen, &key, &klen);
    TEST_ASSERT(g_rc == POSIX_TLS_ERR_ENTROPY_FAILURE, "posix_tls_generate_self_signed_cert must fail with ENTROPY_FAILURE");

    // Restore original RAND method
    RAND_set_rand_method(orig_meth);

    r_rc = posix_tls_random_bytes(buf, sizeof(buf));
    TEST_ASSERT(r_rc == POSIX_TLS_OK, "posix_tls_random_bytes must succeed after restoring RNG");
}

#if defined(__GNUC__)
#pragma GCC diagnostic pop
#endif

static void calc_cert_fingerprint(const char* cert_pem, size_t cert_len, char* out_hex_65) {
    BIO* cbio = BIO_new_mem_buf(cert_pem, static_cast<int>(cert_len));
    X509* cert = PEM_read_bio_X509(cbio, NULL, NULL, NULL);
    BIO_free(cbio);
    unsigned char* der = NULL;
    int der_len = i2d_X509(cert, &der);
    unsigned char hash[32];
    posix_tls_sha256(der, static_cast<size_t>(der_len), hash);
    OPENSSL_free(der);
    X509_free(cert);
    for (int i = 0; i < 32; ++i) {
        sprintf(out_hex_65 + (i * 2), "%02x", hash[i]);
    }
    out_hex_65[64] = '\0';
}

// ---------------------------------------------------------------------------
// Test 15: Forced TLS Versions and Cross-Version Rejection
// ---------------------------------------------------------------------------
struct VersionServerArg {
    posix_tls_context_t* ctx;
    int fd;
    int result_rc;
    std::string negotiated_ver;
};

static void* version_server_worker(void* ptr) {
    VersionServerArg* arg = static_cast<VersionServerArg*>(ptr);
    posix_tls_connection_t* conn = posix_tls_connection_create(arg->ctx, arg->fd);
    if (!conn) {
        arg->result_rc = -100;
        return NULL;
    }
    arg->result_rc = posix_tls_accept(conn);
    if (arg->result_rc == POSIX_TLS_OK) {
        char ver[32];
        posix_tls_connection_get_negotiated_version(conn, ver, sizeof(ver));
        arg->negotiated_ver = ver;
    }
    posix_tls_connection_destroy(conn);
    return NULL;
}

static void test_forced_tls_versions_and_rejection() {
    char *cert_pem = NULL, *key_pem = NULL;
    size_t cert_len = 0, key_len = 0;
    TEST_ASSERT(posix_tls_generate_self_signed_cert(&cert_pem, &cert_len, &key_pem, &key_len) == 0,
                "Cert generation failed");

    char s_fp[65];
    calc_cert_fingerprint(cert_pem, cert_len, s_fp);

    // Scenario A: Both sides forced to TLS 1.3
    {
        int sv[2];
        TEST_ASSERT(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "socketpair failed");

        posix_tls_context_t* s_ctx = posix_tls_context_create(POSIX_TLS_POLICY_P2P);
        TEST_ASSERT(posix_tls_context_set_credentials(s_ctx, cert_pem, cert_len, key_pem, key_len) == 0, "set creds");
        posix_tls_context_set_min_tls_version(s_ctx, POSIX_TLS_VERSION_1_3);
        posix_tls_context_set_max_tls_version(s_ctx, POSIX_TLS_VERSION_1_3);

        posix_tls_context_t* c_ctx = posix_tls_context_create(POSIX_TLS_POLICY_P2P);
        TEST_ASSERT(posix_tls_context_set_expected_fingerprint(c_ctx, s_fp) == 0, "set fp");
        posix_tls_context_set_min_tls_version(c_ctx, POSIX_TLS_VERSION_1_3);
        posix_tls_context_set_max_tls_version(c_ctx, POSIX_TLS_VERSION_1_3);

        VersionServerArg sarg;
        sarg.ctx = s_ctx;
        sarg.fd = sv[0];
        sarg.result_rc = -999;
        pthread_t st;
        pthread_create(&st, NULL, version_server_worker, &sarg);

        posix_tls_connection_t* c_conn = posix_tls_connection_create(c_ctx, sv[1]);
        int c_rc = posix_tls_connect(c_conn, "localhost");
        TEST_ASSERT(c_rc == POSIX_TLS_OK, "TLS 1.3 client connect failed");
        char c_ver[32];
        posix_tls_connection_get_negotiated_version(c_conn, c_ver, sizeof(c_ver));
        TEST_ASSERT(std::string(c_ver) == "TLSv1.3", "Negotiated version must be TLSv1.3");

        posix_tls_connection_destroy(c_conn);
        pthread_join(st, NULL);
        TEST_ASSERT(sarg.result_rc == POSIX_TLS_OK, "TLS 1.3 server accept failed");
        TEST_ASSERT(sarg.negotiated_ver == "TLSv1.3", "Server negotiated version must be TLSv1.3");

        posix_tls_context_destroy(s_ctx);
        posix_tls_context_destroy(c_ctx);
        close(sv[0]);
        close(sv[1]);
    }

    // Scenario B: Both sides forced to TLS 1.2
    {
        int sv[2];
        TEST_ASSERT(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "socketpair failed");

        posix_tls_context_t* s_ctx = posix_tls_context_create(POSIX_TLS_POLICY_P2P);
        TEST_ASSERT(posix_tls_context_set_credentials(s_ctx, cert_pem, cert_len, key_pem, key_len) == 0, "set creds");
        posix_tls_context_set_min_tls_version(s_ctx, POSIX_TLS_VERSION_1_2);
        posix_tls_context_set_max_tls_version(s_ctx, POSIX_TLS_VERSION_1_2);

        posix_tls_context_t* c_ctx = posix_tls_context_create(POSIX_TLS_POLICY_P2P);
        TEST_ASSERT(posix_tls_context_set_expected_fingerprint(c_ctx, s_fp) == 0, "set fp");
        posix_tls_context_set_min_tls_version(c_ctx, POSIX_TLS_VERSION_1_2);
        posix_tls_context_set_max_tls_version(c_ctx, POSIX_TLS_VERSION_1_2);

        VersionServerArg sarg;
        sarg.ctx = s_ctx;
        sarg.fd = sv[0];
        sarg.result_rc = -999;
        pthread_t st;
        pthread_create(&st, NULL, version_server_worker, &sarg);

        posix_tls_connection_t* c_conn = posix_tls_connection_create(c_ctx, sv[1]);
        int c_rc = posix_tls_connect(c_conn, "localhost");
        TEST_ASSERT(c_rc == POSIX_TLS_OK, "TLS 1.2 client connect failed");
        char c_ver[32];
        posix_tls_connection_get_negotiated_version(c_conn, c_ver, sizeof(c_ver));
        TEST_ASSERT(std::string(c_ver) == "TLSv1.2", "Negotiated version must be TLSv1.2");

        posix_tls_connection_destroy(c_conn);
        pthread_join(st, NULL);
        TEST_ASSERT(sarg.result_rc == POSIX_TLS_OK, "TLS 1.2 server accept failed");
        TEST_ASSERT(sarg.negotiated_ver == "TLSv1.2", "Server negotiated version must be TLSv1.2");

        posix_tls_context_destroy(s_ctx);
        posix_tls_context_destroy(c_ctx);
        close(sv[0]);
        close(sv[1]);
    }

    // Scenario C: Cross-version mismatch (server TLS 1.3 only, client TLS 1.2 only)
    {
        int sv[2];
        TEST_ASSERT(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "socketpair failed");

        posix_tls_context_t* s_ctx = posix_tls_context_create(POSIX_TLS_POLICY_P2P);
        TEST_ASSERT(posix_tls_context_set_credentials(s_ctx, cert_pem, cert_len, key_pem, key_len) == 0, "set creds");
        posix_tls_context_set_min_tls_version(s_ctx, POSIX_TLS_VERSION_1_3);
        posix_tls_context_set_max_tls_version(s_ctx, POSIX_TLS_VERSION_1_3);

        posix_tls_context_t* c_ctx = posix_tls_context_create(POSIX_TLS_POLICY_P2P);
        TEST_ASSERT(posix_tls_context_set_expected_fingerprint(c_ctx, s_fp) == 0, "set fp");
        posix_tls_context_set_min_tls_version(c_ctx, POSIX_TLS_VERSION_1_2);
        posix_tls_context_set_max_tls_version(c_ctx, POSIX_TLS_VERSION_1_2);

        VersionServerArg sarg;
        sarg.ctx = s_ctx;
        sarg.fd = sv[0];
        sarg.result_rc = -999;
        pthread_t st;
        pthread_create(&st, NULL, version_server_worker, &sarg);

        posix_tls_connection_t* c_conn = posix_tls_connection_create(c_ctx, sv[1]);
        int c_rc = posix_tls_connect(c_conn, "localhost");
        TEST_ASSERT(c_rc == POSIX_TLS_ERR_HANDSHAKE_FAILED, "Cross-version mismatch must fail handshake");

        posix_tls_connection_destroy(c_conn);
        pthread_join(st, NULL);
        TEST_ASSERT(sarg.result_rc != POSIX_TLS_OK, "Server must fail on incompatible client version");

        posix_tls_context_destroy(s_ctx);
        posix_tls_context_destroy(c_ctx);
        close(sv[0]);
        close(sv[1]);
    }

    posix_tls_free_string(cert_pem);
    posix_tls_free_string(key_pem);
}

// ---------------------------------------------------------------------------
// Test 16: Real IP SAN Matching and Mismatch Rejection
// ---------------------------------------------------------------------------
static void test_real_ip_san_matching() {
    EVP_PKEY* pkey = EVP_EC_gen("P-256");
    TEST_ASSERT(pkey != NULL, "EVP_EC_gen failed");

    X509* cert = X509_new();
    TEST_ASSERT(cert != NULL, "X509_new failed");
    X509_set_version(cert, 2);
    ASN1_INTEGER_set(X509_get_serialNumber(cert), 99999);
    X509_gmtime_adj(X509_getm_notBefore(cert), 0);
    X509_gmtime_adj(X509_getm_notAfter(cert), 315360000L);

    X509_NAME* name = X509_NAME_new();
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (const unsigned char*)"127.0.0.1", -1, -1, 0);
    X509_set_subject_name(cert, name);
    X509_set_issuer_name(cert, name);
    X509_NAME_free(name);

    X509_set_pubkey(cert, pkey);

    X509V3_CTX v3_ctx;
    X509V3_set_ctx_nodb(&v3_ctx);
    X509V3_set_ctx(&v3_ctx, cert, cert, NULL, NULL, 0);
    X509_EXTENSION* ext = X509V3_EXT_conf_nid(NULL, &v3_ctx, NID_subject_alt_name,
                                              const_cast<char*>("IP:127.0.0.1,IP:192.168.1.50"));
    TEST_ASSERT(ext != NULL, "IP SAN extension creation failed");
    X509_add_ext(cert, ext, -1);
    X509_EXTENSION_free(ext);

    TEST_ASSERT(X509_sign(cert, pkey, EVP_sha256()) > 0, "X509_sign failed");

    // 1. Direct OpenSSL IP SAN checking via X509_check_ip_asc
    TEST_ASSERT(X509_check_ip_asc(cert, "127.0.0.1", 0) == 1, "IP 127.0.0.1 SAN must match");
    TEST_ASSERT(X509_check_ip_asc(cert, "192.168.1.50", 0) == 1, "IP 192.168.1.50 SAN must match");
    TEST_ASSERT(X509_check_ip_asc(cert, "10.0.0.1", 0) == 0, "Mismatched IP 10.0.0.1 must be rejected");

    // 2. Full posix_tls adapter verification with Public PKI trust
    BIO* cert_bio = BIO_new(BIO_s_mem());
    PEM_write_bio_X509(cert_bio, cert);
    char* cert_buf = NULL;
    long cert_len = BIO_get_mem_data(cert_bio, &cert_buf);

    BIO* key_bio = BIO_new(BIO_s_mem());
    PEM_write_bio_PrivateKey(key_bio, pkey, NULL, NULL, 0, NULL, NULL);
    char* key_buf = NULL;
    long key_len = BIO_get_mem_data(key_bio, &key_buf);

    // Save cert as trusted CA file
    const char* tmp_ca_path = "/tmp/test_posix_tls_ip_san_ca.pem";
    FILE* fp = fopen(tmp_ca_path, "wb");
    TEST_ASSERT(fp != NULL, "Failed to create temp CA file");
    fwrite(cert_buf, 1, static_cast<size_t>(cert_len), fp);
    fclose(fp);

    // Server context using these credentials
    posix_tls_context_t* s_ctx = posix_tls_context_create(POSIX_TLS_POLICY_P2P);
    TEST_ASSERT(posix_tls_context_set_credentials(s_ctx, cert_buf, static_cast<size_t>(cert_len),
                                                key_buf, static_cast<size_t>(key_len)) == POSIX_TLS_OK,
                "set_credentials failed");

    // Scenario A: Client with trusted CA connects to matching IP "127.0.0.1" -> MUST SUCCEED
    {
        int sv[2];
        TEST_ASSERT(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "socketpair failed");
        ServerThreadArg sarg;
        sarg.ctx = s_ctx;
        sarg.fd = sv[0];
        sarg.result_rc = -999;
        pthread_t st;
        TEST_ASSERT(pthread_create(&st, NULL, p2p_server_worker, &sarg) == 0, "pthread_create failed");

        posix_tls_context_t* c_ctx = posix_tls_context_create(POSIX_TLS_POLICY_PUBLIC_PKI);
        TEST_ASSERT(posix_tls_context_set_ca_path(c_ctx, tmp_ca_path) == POSIX_TLS_OK, "set_ca_path failed");
        posix_tls_connection_t* c_conn = posix_tls_connection_create(c_ctx, sv[1]);
        TEST_ASSERT(c_conn != NULL, "connection_create failed");

        int c_rc = posix_tls_connect(c_conn, "127.0.0.1");
        TEST_ASSERT(c_rc == POSIX_TLS_OK, "posix_tls_connect to matching IP 127.0.0.1 must succeed");
        posix_tls_connection_destroy(c_conn);
        pthread_join(st, NULL);
        posix_tls_context_destroy(c_ctx);
    }

    // Scenario B: Client with trusted CA connects to mismatched IP "10.0.0.1" -> MUST FAIL WITH CERT_VERIFY
    {
        int sv[2];
        TEST_ASSERT(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "socketpair failed");
        ServerThreadArg sarg;
        sarg.ctx = s_ctx;
        sarg.fd = sv[0];
        sarg.result_rc = -999;
        pthread_t st;
        TEST_ASSERT(pthread_create(&st, NULL, p2p_server_worker, &sarg) == 0, "pthread_create failed");

        posix_tls_context_t* c_ctx = posix_tls_context_create(POSIX_TLS_POLICY_PUBLIC_PKI);
        TEST_ASSERT(posix_tls_context_set_ca_path(c_ctx, tmp_ca_path) == POSIX_TLS_OK, "set_ca_path failed");
        posix_tls_connection_t* c_conn = posix_tls_connection_create(c_ctx, sv[1]);
        TEST_ASSERT(c_conn != NULL, "connection_create failed");

        int c_rc = posix_tls_connect(c_conn, "10.0.0.1");
        TEST_ASSERT(c_rc == POSIX_TLS_ERR_CERT_VERIFY, "posix_tls_connect to mismatched IP 10.0.0.1 must fail with CERT_VERIFY");
        posix_tls_connection_destroy(c_conn);
        pthread_join(st, NULL);
        posix_tls_context_destroy(c_ctx);
    }

    // Scenario C: Client without CA bundle connects to "127.0.0.1" -> MUST FAIL WITH CERT_VERIFY (untrusted CA)
    {
        int sv[2];
        TEST_ASSERT(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "socketpair failed");
        ServerThreadArg sarg;
        sarg.ctx = s_ctx;
        sarg.fd = sv[0];
        sarg.result_rc = -999;
        pthread_t st;
        TEST_ASSERT(pthread_create(&st, NULL, p2p_server_worker, &sarg) == 0, "pthread_create failed");

        posix_tls_context_t* c_ctx = posix_tls_context_create(POSIX_TLS_POLICY_PUBLIC_PKI);
        posix_tls_connection_t* c_conn = posix_tls_connection_create(c_ctx, sv[1]);
        TEST_ASSERT(c_conn != NULL, "connection_create failed");

        int c_rc = posix_tls_connect(c_conn, "127.0.0.1");
        TEST_ASSERT(c_rc == POSIX_TLS_ERR_CERT_VERIFY || c_rc == POSIX_TLS_ERR_HANDSHAKE_FAILED,
                    "posix_tls_connect with untrusted CA must fail with CERT_VERIFY");
        posix_tls_connection_destroy(c_conn);
        pthread_join(st, NULL);
        posix_tls_context_destroy(c_ctx);
    }

    unlink(tmp_ca_path);
    posix_tls_context_destroy(s_ctx);
    BIO_free(cert_bio);
    BIO_free(key_bio);

    X509_free(cert);
    EVP_PKEY_free(pkey);
}

// ---------------------------------------------------------------------------
// Test 17: Length Bounds & Integer Narrowing Guards (R1-01)
// ---------------------------------------------------------------------------
static void test_length_bounds_and_narrowing_guards() {
    // 1. Multi-block CSPRNG fill (> 64 KiB DRBG request block)
    std::vector<unsigned char> multi_buf(131072, 0xa5);
    TEST_ASSERT(posix_tls_random_bytes(&multi_buf[0], multi_buf.size()) == POSIX_TLS_OK,
                "128 KiB random_bytes must succeed");
    bool head_changed = false;
    bool tail_changed = false;
    for (size_t i = 0; i < 32; ++i) {
        if (multi_buf[i] != 0xa5) head_changed = true;
        if (multi_buf[multi_buf.size() - 32 + i] != 0xa5) tail_changed = true;
    }
    TEST_ASSERT(head_changed && tail_changed, "Multi-block random_bytes must populate entire buffer");

    // Prepare valid credentials and an authenticated connection for PEM & stream checks
    std::string valid_cert, valid_key, valid_pin;
    TEST_ASSERT(posix_tls::generateSelfSignedCert(valid_cert, valid_key) == POSIX_TLS_OK,
                "generateSelfSignedCert failed");
    TEST_ASSERT(posix_tls::calculateCertFingerprint(valid_cert, valid_pin) == POSIX_TLS_OK,
                "calculateCertFingerprint failed");

    posix_tls_context_t* s_ctx = posix_tls_context_create(POSIX_TLS_POLICY_P2P);
    posix_tls_context_t* c_ctx = posix_tls_context_create(POSIX_TLS_POLICY_P2P);
    TEST_ASSERT(s_ctx != NULL && c_ctx != NULL, "Context create failed");
    TEST_ASSERT(posix_tls_context_set_credentials(s_ctx, valid_cert.data(), valid_cert.size(),
                                                  valid_key.data(), valid_key.size()) == POSIX_TLS_OK,
                "Server set_credentials failed");
    TEST_ASSERT(posix_tls_context_set_expected_fingerprint(c_ctx, valid_pin.c_str()) == POSIX_TLS_OK,
                "Client set_expected_fingerprint failed");

    int sv[2];
    TEST_ASSERT(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "socketpair failed");
    fcntl(sv[0], F_SETFL, O_NONBLOCK);
    fcntl(sv[1], F_SETFL, O_NONBLOCK);
    posix_tls_connection_t* s_conn = posix_tls_connection_create(s_ctx, sv[0]);
    posix_tls_connection_t* c_conn = posix_tls_connection_create(c_ctx, sv[1]);
    TEST_ASSERT(s_conn != NULL && c_conn != NULL, "Connection create failed");

    int sr = -1, cr = -1;
    for (int i = 0; i < 1000 && (sr != POSIX_TLS_OK || cr != POSIX_TLS_OK); ++i) {
        if (sr != POSIX_TLS_OK) sr = posix_tls_accept(s_conn);
        if (cr != POSIX_TLS_OK) cr = posix_tls_connect(c_conn, NULL);
    }
    TEST_ASSERT(sr == POSIX_TLS_OK && cr == POSIX_TLS_OK, "Nonblocking handshake failed");

    // 2. Zero-length policy across random, PEM, and stream APIs
    char fp_hex[65];
    size_t io_n = 99;
    unsigned char small_buf[64];
    std::memset(small_buf, 0xa5, sizeof(small_buf));
    TEST_ASSERT(posix_tls_random_bytes(small_buf, 0) == POSIX_TLS_ERR_INVALID_ARG,
                "Zero-length random_bytes must fail with INVALID_ARG");
    TEST_ASSERT(posix_tls_calculate_cert_fingerprint(valid_cert.data(), 0, fp_hex) == POSIX_TLS_ERR_INVALID_ARG,
                "Zero-length cert fingerprint must fail with INVALID_ARG");
    TEST_ASSERT(posix_tls_context_set_credentials(s_ctx, valid_cert.data(), 0,
                                                  valid_key.data(), valid_key.size()) == POSIX_TLS_ERR_INVALID_ARG,
                "Zero-length cert_len must fail with INVALID_ARG");
    TEST_ASSERT(posix_tls_context_set_credentials(s_ctx, valid_cert.data(), valid_cert.size(),
                                                  valid_key.data(), 0) == POSIX_TLS_ERR_INVALID_ARG,
                "Zero-length key_len must fail with INVALID_ARG");
    TEST_ASSERT(posix_tls_read(c_conn, small_buf, 0, &io_n) == POSIX_TLS_ERR_INVALID_ARG && io_n == 0,
                "Zero-length read must fail with INVALID_ARG");
    TEST_ASSERT(posix_tls_write(c_conn, small_buf, 0, &io_n) == POSIX_TLS_ERR_INVALID_ARG && io_n == 0,
                "Zero-length write must fail with INVALID_ARG");

    // 3. Maximum-length boundary (INT_MAX + 1 -> negative int if narrowed!) with PROT_NONE guard page
    const size_t over_max = static_cast<size_t>(INT_MAX) + static_cast<size_t>(1);
    void* guard_page = mmap(NULL, 4096, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    unsigned char* unmapped_or_sentinel = (guard_page != MAP_FAILED)
        ? static_cast<unsigned char*>(guard_page) : small_buf;
    const char* unmapped_pem = reinterpret_cast<const char*>(unmapped_or_sentinel);

    TEST_ASSERT(posix_tls_random_bytes(unmapped_or_sentinel, over_max) == POSIX_TLS_ERR_INVALID_ARG,
                "INT_MAX + 1 random_bytes must fail before touching buffer");
    TEST_ASSERT(posix_tls_calculate_cert_fingerprint(unmapped_pem, over_max, fp_hex) == POSIX_TLS_ERR_INVALID_ARG,
                "INT_MAX + 1 cert_len must fail without triggering BIO_new_mem_buf strlen sentinel");
    TEST_ASSERT(posix_tls_context_set_credentials(s_ctx, unmapped_pem, over_max,
                                                  valid_key.data(), valid_key.size()) == POSIX_TLS_ERR_INVALID_ARG,
                "INT_MAX + 1 credential cert_len must fail before touching buffer");
    TEST_ASSERT(posix_tls_context_set_credentials(s_ctx, valid_cert.data(), valid_cert.size(),
                                                  unmapped_pem, over_max) == POSIX_TLS_ERR_INVALID_ARG,
                "INT_MAX + 1 credential key_len must fail before touching buffer");
    io_n = 77;
    TEST_ASSERT(posix_tls_read(c_conn, unmapped_or_sentinel, over_max, &io_n) == POSIX_TLS_ERR_INVALID_ARG && io_n == 0,
                "INT_MAX + 1 read must fail before touching buffer");
    io_n = 77;
    TEST_ASSERT(posix_tls_write(c_conn, unmapped_or_sentinel, over_max, &io_n) == POSIX_TLS_ERR_INVALID_ARG && io_n == 0,
                "INT_MAX + 1 write must fail before touching buffer");

    // 4. 64-bit wrapping length ((1 << 32) + 32 -> narrows to +32 if truncated) without huge physical allocation
    if (sizeof(size_t) > 4) {
        size_t shift = (sizeof(size_t) > 4) ? 32 : 0;
        size_t wrap_len = (static_cast<size_t>(1) << shift) + static_cast<size_t>(32);

        TEST_ASSERT(posix_tls_random_bytes(unmapped_or_sentinel, wrap_len) == POSIX_TLS_ERR_INVALID_ARG,
                    "64-bit wrapping random_bytes must fail before touching PROT_NONE buffer");
        TEST_ASSERT(posix_tls_random_bytes(small_buf, wrap_len) == POSIX_TLS_ERR_INVALID_ARG,
                    "64-bit wrapping random_bytes must return INVALID_ARG");
        for (size_t i = 0; i < sizeof(small_buf); ++i) {
            TEST_ASSERT(small_buf[i] == 0xa5, "Rejected 64-bit wrapping random_bytes must leave buffer untouched");
        }

        size_t wrap_cert_len = (static_cast<size_t>(1) << shift) + valid_cert.size();
        TEST_ASSERT(posix_tls_calculate_cert_fingerprint(valid_cert.data(), wrap_cert_len, fp_hex) == POSIX_TLS_ERR_INVALID_ARG,
                    "64-bit wrapping cert_len must fail instead of truncating to valid_cert.size()");
        TEST_ASSERT(posix_tls_context_set_credentials(s_ctx, valid_cert.data(), wrap_cert_len,
                                                      valid_key.data(), valid_key.size()) == POSIX_TLS_ERR_INVALID_ARG,
                    "64-bit wrapping credential cert_len must fail");
        TEST_ASSERT(posix_tls_read(c_conn, unmapped_or_sentinel, wrap_len, &io_n) == POSIX_TLS_ERR_INVALID_ARG,
                    "64-bit wrapping read length must fail before touching buffer");
        TEST_ASSERT(posix_tls_write(c_conn, unmapped_or_sentinel, wrap_len, &io_n) == POSIX_TLS_ERR_INVALID_ARG,
                    "64-bit wrapping write length must fail before touching buffer");
    }

    if (guard_page != MAP_FAILED) {
        munmap(guard_page, 4096);
    }
    posix_tls_connection_destroy(c_conn);
    posix_tls_connection_destroy(s_conn);
    posix_tls_context_destroy(c_ctx);
    posix_tls_context_destroy(s_ctx);
}

// ---------------------------------------------------------------------------
// Test 18: Stale OpenSSL Error Queue Isolation Across Readiness & Diagnostics (R1-02)
// ---------------------------------------------------------------------------
static void test_stale_openssl_error_queue_isolation() {
    std::string cert, key, pin;
    TEST_ASSERT(posix_tls::generateSelfSignedCert(cert, key) == POSIX_TLS_OK, "Cert gen failed");
    TEST_ASSERT(posix_tls::calculateCertFingerprint(cert, pin) == POSIX_TLS_OK, "Fingerprint failed");

    posix_tls::Context server_ctx(POSIX_TLS_POLICY_P2P);
    posix_tls::Context client_ctx(POSIX_TLS_POLICY_P2P);
    TEST_ASSERT(server_ctx.setCredentials(cert, key) == POSIX_TLS_OK, "Server creds failed");
    TEST_ASSERT(client_ctx.setExpectedFingerprint(pin) == POSIX_TLS_OK, "Client pin failed");

    int sv[2];
    TEST_ASSERT(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "socketpair failed");
    fcntl(sv[0], F_SETFL, O_NONBLOCK);
    fcntl(sv[1], F_SETFL, O_NONBLOCK);

    posix_tls::Connection s(server_ctx, sv[0]);
    posix_tls::Connection c(client_ctx, sv[1]);
    TEST_ASSERT(s.isValid() && c.isValid(), "Connection creation failed");

    // 1. Contaminate error queue via public SDK before every nonblocking handshake step
    char bad_fp[65];
    int sr = -1, cr = -1;
    bool observed_want = false;
    for (int i = 0; i < 1000 && (sr != POSIX_TLS_OK || cr != POSIX_TLS_OK); ++i) {
        if (cr != POSIX_TLS_OK) {
            TEST_ASSERT(posix_tls_calculate_cert_fingerprint("bad", 3, bad_fp) == POSIX_TLS_ERR_INVALID_ARG,
                        "Expected INVALID_ARG on bad PEM");
            cr = c.connect("");
            if (cr == POSIX_TLS_ERR_WANT_READ || cr == POSIX_TLS_ERR_WANT_WRITE) observed_want = true;
            TEST_ASSERT(cr == POSIX_TLS_OK || cr == POSIX_TLS_ERR_WANT_READ || cr == POSIX_TLS_ERR_WANT_WRITE,
                        "Stale error queue must not break nonblocking connect");
        }
        if (sr != POSIX_TLS_OK) {
            TEST_ASSERT(posix_tls_calculate_cert_fingerprint("bad", 3, bad_fp) == POSIX_TLS_ERR_INVALID_ARG,
                        "Expected INVALID_ARG on bad PEM");
            sr = s.accept();
            if (sr == POSIX_TLS_ERR_WANT_READ || sr == POSIX_TLS_ERR_WANT_WRITE) observed_want = true;
            TEST_ASSERT(sr == POSIX_TLS_OK || sr == POSIX_TLS_ERR_WANT_READ || sr == POSIX_TLS_ERR_WANT_WRITE,
                        "Stale error queue must not break nonblocking accept");
        }
    }
    TEST_ASSERT(observed_want && sr == POSIX_TLS_OK && cr == POSIX_TLS_OK,
                "Nonblocking handshake with contaminated queue must complete");

    // 2. Nonblocking WANT_READ preserved after public SDK PEM failure
    size_t n = 0;
    char out[32];
    TEST_ASSERT(c.read(out, sizeof(out), n) == POSIX_TLS_ERR_WANT_READ, "Clean empty read must return WANT_READ");
    TEST_ASSERT(posix_tls_calculate_cert_fingerprint("bad", 3, bad_fp) == POSIX_TLS_ERR_INVALID_ARG,
                "Expected INVALID_ARG on bad PEM");
    TEST_ASSERT(c.read(out, sizeof(out), n) == POSIX_TLS_ERR_WANT_READ,
                "Dirty empty read must still return WANT_READ");

    // 3. Nonblocking WANT_WRITE preserved after public SDK PEM failure
    std::vector<char> chunk(16384, 'W');
    size_t total_sent = 0;
    bool hit_want_write = false;
    for (int i = 0; i < 512; ++i) {
        size_t written = 0;
        int wrc = c.write(&chunk[0], chunk.size(), written);
        if (wrc == POSIX_TLS_OK) {
            total_sent += written;
        } else if (wrc == POSIX_TLS_ERR_WANT_WRITE) {
            hit_want_write = true;
            break;
        } else {
            TEST_ASSERT(false, "Unexpected write error while filling socket buffer");
        }
    }
    TEST_ASSERT(hit_want_write, "Expected nonblocking write backpressure");
    TEST_ASSERT(posix_tls_calculate_cert_fingerprint("bad", 3, bad_fp) == POSIX_TLS_ERR_INVALID_ARG,
                "Expected INVALID_ARG on bad PEM");
    size_t retry_written = 0;
    int dirty_wrc = c.write(&chunk[0], chunk.size(), retry_written);
    TEST_ASSERT(dirty_wrc == POSIX_TLS_ERR_WANT_WRITE,
                "Dirty backpressured write must still return WANT_WRITE");

    // Drain peer so the pending write completes cleanly
    std::vector<char> drain(16384);
    size_t total_rcvd = 0;
    while (dirty_wrc == POSIX_TLS_ERR_WANT_WRITE) {
        size_t nr = 0;
        int rrc = s.read(&drain[0], drain.size(), nr);
        if (rrc == POSIX_TLS_OK) total_rcvd += nr;
        dirty_wrc = c.write(&chunk[0], chunk.size(), retry_written);
    }
    TEST_ASSERT(dirty_wrc == POSIX_TLS_OK, "Pending write must complete once socket drains");
    total_sent += retry_written;
    while (total_rcvd < total_sent) {
        size_t nr = 0;
        int rrc = s.read(&drain[0], drain.size(), nr);
        TEST_ASSERT(rrc == POSIX_TLS_OK, "Server drain read must succeed");
        total_rcvd += nr;
    }

    // 4. Shutdown preserved after public SDK PEM failure
    TEST_ASSERT(posix_tls_calculate_cert_fingerprint("bad", 3, bad_fp) == POSIX_TLS_ERR_INVALID_ARG,
                "Expected INVALID_ARG on bad PEM");
    TEST_ASSERT(c.shutdown() == POSIX_TLS_OK, "Dirty shutdown must succeed");

    // 5. Genuine TLS failure still fails and preserves fresh diagnostic (not stale PEM error)
    int bad_sv[2];
    TEST_ASSERT(socketpair(AF_UNIX, SOCK_STREAM, 0, bad_sv) == 0, "socketpair failed");
    const char raw_garbage[] = "NOT_A_VALID_TLS_RECORD\r\n";
    TEST_ASSERT(write(bad_sv[0], raw_garbage, sizeof(raw_garbage) - 1) > 0, "raw write failed");
    close(bad_sv[0]);

    posix_tls::Connection bad_client(client_ctx, bad_sv[1]);
    TEST_ASSERT(bad_client.isValid(), "bad_client create failed");
    TEST_ASSERT(posix_tls_calculate_cert_fingerprint("bad", 3, bad_fp) == POSIX_TLS_ERR_INVALID_ARG,
                "Expected INVALID_ARG on bad PEM");
    int bad_rc = bad_client.connect("");
    TEST_ASSERT(bad_rc == POSIX_TLS_ERR_HANDSHAKE_FAILED, "Corrupt peer record must fail handshake");
    std::string diag = bad_client.getLastError();
    TEST_ASSERT(!diag.empty() && diag.find("PEM") == std::string::npos,
                "Last error must reflect fresh TLS failure rather than stale PEM error");
}

// ---------------------------------------------------------------------------
// Test 19: CLOSED State Remains Terminal Across Connect and Accept (R1-03)
// ---------------------------------------------------------------------------
static void test_closed_state_terminal_across_handshakes() {
    std::string cert, key, pin;
    TEST_ASSERT(posix_tls::generateSelfSignedCert(cert, key) == POSIX_TLS_OK, "Cert gen failed");
    TEST_ASSERT(posix_tls::calculateCertFingerprint(cert, pin) == POSIX_TLS_OK, "Fingerprint failed");

    posix_tls::Context server_ctx(POSIX_TLS_POLICY_P2P);
    posix_tls::Context client_ctx(POSIX_TLS_POLICY_P2P);
    TEST_ASSERT(server_ctx.setCredentials(cert, key) == POSIX_TLS_OK, "Server creds failed");
    TEST_ASSERT(client_ctx.setExpectedFingerprint(pin) == POSIX_TLS_OK, "Client pin failed");

    // Scenario A: Client shuts down locally while peer bytes are queued
    {
        int sv[2];
        TEST_ASSERT(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "socketpair failed");
        fcntl(sv[0], F_SETFL, O_NONBLOCK);
        fcntl(sv[1], F_SETFL, O_NONBLOCK);

        posix_tls::Connection s(server_ctx, sv[0]);
        posix_tls::Connection c(client_ctx, sv[1]);
        int sr = -1, cr = -1;
        for (int i = 0; i < 1000 && (sr != POSIX_TLS_OK || cr != POSIX_TLS_OK); ++i) {
            if (sr != POSIX_TLS_OK) sr = s.accept();
            if (cr != POSIX_TLS_OK) cr = c.connect("");
        }
        TEST_ASSERT(sr == POSIX_TLS_OK && cr == POSIX_TLS_OK, "Handshake failed");

        // Re-handshaking an already authenticated handle must be rejected without breaking it
        TEST_ASSERT(c.connect("") == POSIX_TLS_ERR_INVALID_ARG, "Authenticated connect must return INVALID_ARG");
        TEST_ASSERT(c.accept() == POSIX_TLS_ERR_INVALID_ARG, "Authenticated accept must return INVALID_ARG");

        size_t n = 0;
        TEST_ASSERT(s.write("hello", 5, n) == POSIX_TLS_OK && n == 5, "Server write failed");
        TEST_ASSERT(c.shutdown() == POSIX_TLS_OK, "Client shutdown failed");

        char buf[16];
        TEST_ASSERT(c.read(buf, sizeof(buf), n) == POSIX_TLS_ERR_IO_FAILED && n == 0,
                    "Post-shutdown client read must return IO_FAILED");
        TEST_ASSERT(c.write("x", 1, n) == POSIX_TLS_ERR_IO_FAILED && n == 0,
                    "Post-shutdown client write must return IO_FAILED");

        TEST_ASSERT(c.connect("") == POSIX_TLS_ERR_CLOSED,
                    "Post-shutdown client connect must return CLOSED");
        TEST_ASSERT(c.accept() == POSIX_TLS_ERR_CLOSED,
                    "Post-shutdown client accept must return CLOSED");

        TEST_ASSERT(c.read(buf, sizeof(buf), n) == POSIX_TLS_ERR_IO_FAILED && n == 0,
                    "Client read after rejected connect/accept must remain IO_FAILED");
        TEST_ASSERT(c.write("x", 1, n) == POSIX_TLS_ERR_IO_FAILED && n == 0,
                    "Client write after rejected connect/accept must remain IO_FAILED");
        TEST_ASSERT(c.shutdown() == POSIX_TLS_ERR_CLOSED,
                    "Repeated client shutdown must remain CLOSED");
    }

    // Scenario B: Server shuts down locally while client bytes are queued
    {
        int sv[2];
        TEST_ASSERT(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "socketpair failed");
        fcntl(sv[0], F_SETFL, O_NONBLOCK);
        fcntl(sv[1], F_SETFL, O_NONBLOCK);

        posix_tls::Connection s(server_ctx, sv[0]);
        posix_tls::Connection c(client_ctx, sv[1]);
        int sr = -1, cr = -1;
        for (int i = 0; i < 1000 && (sr != POSIX_TLS_OK || cr != POSIX_TLS_OK); ++i) {
            if (sr != POSIX_TLS_OK) sr = s.accept();
            if (cr != POSIX_TLS_OK) cr = c.connect("");
        }
        TEST_ASSERT(sr == POSIX_TLS_OK && cr == POSIX_TLS_OK, "Handshake failed");

        size_t n = 0;
        TEST_ASSERT(c.write("world", 5, n) == POSIX_TLS_OK && n == 5, "Client write failed");
        TEST_ASSERT(s.shutdown() == POSIX_TLS_OK, "Server shutdown failed");

        char buf[16];
        TEST_ASSERT(s.read(buf, sizeof(buf), n) == POSIX_TLS_ERR_IO_FAILED && n == 0,
                    "Post-shutdown server read must return IO_FAILED");
        TEST_ASSERT(s.write("y", 1, n) == POSIX_TLS_ERR_IO_FAILED && n == 0,
                    "Post-shutdown server write must return IO_FAILED");

        TEST_ASSERT(s.accept() == POSIX_TLS_ERR_CLOSED,
                    "Post-shutdown server accept must return CLOSED");
        TEST_ASSERT(s.connect("") == POSIX_TLS_ERR_CLOSED,
                    "Post-shutdown server connect must return CLOSED");

        TEST_ASSERT(s.read(buf, sizeof(buf), n) == POSIX_TLS_ERR_IO_FAILED && n == 0,
                    "Server read after rejected accept/connect must remain IO_FAILED");
        TEST_ASSERT(s.write("y", 1, n) == POSIX_TLS_ERR_IO_FAILED && n == 0,
                    "Server write after rejected accept/connect must remain IO_FAILED");
        TEST_ASSERT(s.shutdown() == POSIX_TLS_ERR_CLOSED,
                    "Repeated server shutdown must remain CLOSED");
    }
}

// ---------------------------------------------------------------------------
// Test 20: Intermediate Certificate Chain Loading & Root-Only Verification (R1-04)
// ---------------------------------------------------------------------------
static void add_x509_ext(X509* issuer, X509* subj, int nid, const char* value) {
    X509V3_CTX ctx;
    X509V3_set_ctx_nodb(&ctx);
    X509V3_set_ctx(&ctx, issuer, subj, NULL, NULL, 0);
    X509_EXTENSION* ext = X509V3_EXT_conf_nid(NULL, &ctx, nid, const_cast<char*>(value));
    TEST_ASSERT(ext != NULL, "X509V3_EXT_conf_nid failed");
    TEST_ASSERT(X509_add_ext(subj, ext, -1) == 1, "X509_add_ext failed");
    X509_EXTENSION_free(ext);
}

static X509* build_test_cert(const char* cn,
                             long serial_no,
                             EVP_PKEY* subj_key,
                             X509* issuer_cert,
                             EVP_PKEY* issuer_key,
                             bool is_ca,
                             const char* san_dns) {
    X509* cert = X509_new();
    TEST_ASSERT(cert != NULL, "X509_new failed");
    X509_set_version(cert, 2);
    ASN1_INTEGER_set(X509_get_serialNumber(cert), serial_no);
    X509_gmtime_adj(X509_getm_notBefore(cert), -60);
    X509_gmtime_adj(X509_getm_notAfter(cert), 86400);

    X509_NAME* name = X509_NAME_new();
    TEST_ASSERT(name != NULL, "X509_NAME_new failed");
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                               reinterpret_cast<const unsigned char*>(cn), -1, -1, 0);
    X509_set_subject_name(cert, name);
    X509_set_issuer_name(cert, issuer_cert ? X509_get_subject_name(issuer_cert) : name);
    X509_NAME_free(name);

    X509_set_pubkey(cert, subj_key);

    X509* v3_issuer = issuer_cert ? issuer_cert : cert;
    add_x509_ext(v3_issuer, cert, NID_basic_constraints,
                 is_ca ? "critical,CA:TRUE" : "critical,CA:FALSE");
    add_x509_ext(v3_issuer, cert, NID_key_usage,
                 is_ca ? "critical,keyCertSign,cRLSign" : "critical,digitalSignature");
    add_x509_ext(v3_issuer, cert, NID_subject_key_identifier, "hash");
    add_x509_ext(v3_issuer, cert, NID_authority_key_identifier, "keyid:always");
    if (!is_ca) {
        add_x509_ext(v3_issuer, cert, NID_ext_key_usage, "serverAuth");
    }
    if (san_dns) {
        add_x509_ext(v3_issuer, cert, NID_subject_alt_name, san_dns);
    }

    TEST_ASSERT(X509_sign(cert, issuer_key ? issuer_key : subj_key, EVP_sha256()) > 0,
                "X509_sign failed");
    return cert;
}

static std::string cert_to_pem_string(X509* cert) {
    BIO* bio = BIO_new(BIO_s_mem());
    TEST_ASSERT(bio != NULL && PEM_write_bio_X509(bio, cert) == 1, "PEM_write_bio_X509 failed");
    char* data = NULL;
    long len = BIO_get_mem_data(bio, &data);
    TEST_ASSERT(len > 0 && data != NULL, "BIO_get_mem_data failed");
    std::string out(data, static_cast<size_t>(len));
    BIO_free(bio);
    return out;
}

static std::string key_to_pem_string(EVP_PKEY* key) {
    BIO* bio = BIO_new(BIO_s_mem());
    TEST_ASSERT(bio != NULL && PEM_write_bio_PrivateKey(bio, key, NULL, NULL, 0, NULL, NULL) == 1,
                "PEM_write_bio_PrivateKey failed");
    char* data = NULL;
    long len = BIO_get_mem_data(bio, &data);
    TEST_ASSERT(len > 0 && data != NULL, "BIO_get_mem_data failed");
    std::string out(data, static_cast<size_t>(len));
    BIO_free(bio);
    return out;
}

static void test_fullchain_credentials_and_chain_validation() {
    EVP_PKEY* root_key = EVP_EC_gen("P-256");
    EVP_PKEY* int_key = EVP_EC_gen("P-256");
    EVP_PKEY* leaf_key = EVP_EC_gen("P-256");
    TEST_ASSERT(root_key && int_key && leaf_key, "EVP_EC_gen failed");

    X509* root_cert = build_test_cert("posix-tls Test Root CA", 1, root_key, NULL, NULL, true, NULL);
    X509* int_cert = build_test_cert("posix-tls Test Intermediate CA", 2, int_key, root_cert, root_key, true, NULL);
    X509* leaf_cert = build_test_cert("localhost", 3, leaf_key, int_cert, int_key, false, "DNS:localhost");

    std::string root_pem = cert_to_pem_string(root_cert);
    std::string int_pem = cert_to_pem_string(int_cert);
    std::string leaf_pem = cert_to_pem_string(leaf_cert);
    std::string leaf_key_pem = key_to_pem_string(leaf_key);
    std::string fullchain_pem = leaf_pem + int_pem;

    std::string expected_leaf_fp;
    TEST_ASSERT(posix_tls::calculateCertFingerprint(leaf_pem, expected_leaf_fp) == POSIX_TLS_OK,
                "Leaf fingerprint calculation failed");

    char root_ca_file[] = "/tmp/posix_tls_root_only_XXXXXX";
    int ca_fd = mkstemp(root_ca_file);
    TEST_ASSERT(ca_fd >= 0, "mkstemp failed");
    TEST_ASSERT(write(ca_fd, root_pem.data(), root_pem.size()) == static_cast<ssize_t>(root_pem.size()),
                "Writing root CA file failed");
    close(ca_fd);

    posix_tls_context_t* s_ctx = posix_tls_context_create(POSIX_TLS_POLICY_P2P);
    TEST_ASSERT(s_ctx != NULL, "Server context create failed");

    // 1. Malformed trailing chain PEM block must fail closed
    std::string malformed_chain = leaf_pem +
        "-----BEGIN CERTIFICATE-----\nCORRUPT_PEM_BODY@@@\n-----END CERTIFICATE-----\n";
    TEST_ASSERT(posix_tls_context_set_credentials(s_ctx, malformed_chain.data(), malformed_chain.size(),
                                                  leaf_key_pem.data(), leaf_key_pem.size()) == POSIX_TLS_ERR_INVALID_ARG,
                "Malformed trailing chain certificate must fail with INVALID_ARG");

    // 2. Leaf-only credentials without intermediate must fail verification when client trusts only Root CA
    TEST_ASSERT(posix_tls_context_set_credentials(s_ctx, leaf_pem.data(), leaf_pem.size(),
                                                  leaf_key_pem.data(), leaf_key_pem.size()) == POSIX_TLS_OK,
                "Leaf-only set_credentials failed");
    {
        int sv[2];
        TEST_ASSERT(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "socketpair failed");
        ServerThreadArg sarg;
        sarg.ctx = s_ctx;
        sarg.fd = sv[0];
        sarg.result_rc = -999;
        pthread_t st;
        TEST_ASSERT(pthread_create(&st, NULL, p2p_server_worker, &sarg) == 0, "pthread_create failed");

        posix_tls_context_t* c_ctx = posix_tls_context_create(POSIX_TLS_POLICY_PUBLIC_PKI);
        TEST_ASSERT(posix_tls_context_set_ca_path(c_ctx, root_ca_file) == POSIX_TLS_OK, "set_ca_path failed");
        posix_tls_connection_t* c_conn = posix_tls_connection_create(c_ctx, sv[1]);
        int crc = posix_tls_connect(c_conn, "localhost");
        TEST_ASSERT(crc == POSIX_TLS_ERR_CERT_VERIFY,
                    "Missing intermediate must fail Public PKI verification against root-only trust store");
        posix_tls_connection_destroy(c_conn);
        pthread_join(st, NULL);
        posix_tls_context_destroy(c_ctx);
    }

    // 3. Fullchain credentials (leaf + intermediate) must succeed when client trusts only Root CA
    TEST_ASSERT(posix_tls_context_set_credentials(s_ctx, fullchain_pem.data(), fullchain_pem.size(),
                                                  leaf_key_pem.data(), leaf_key_pem.size()) == POSIX_TLS_OK,
                "Fullchain set_credentials failed");
    {
        int sv[2];
        TEST_ASSERT(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "socketpair failed");
        ServerThreadArg sarg;
        sarg.ctx = s_ctx;
        sarg.fd = sv[0];
        sarg.result_rc = -999;
        pthread_t st;
        TEST_ASSERT(pthread_create(&st, NULL, p2p_server_worker, &sarg) == 0, "pthread_create failed");

        posix_tls_context_t* c_ctx = posix_tls_context_create(POSIX_TLS_POLICY_PUBLIC_PKI);
        TEST_ASSERT(posix_tls_context_set_ca_path(c_ctx, root_ca_file) == POSIX_TLS_OK, "set_ca_path failed");
        posix_tls_connection_t* c_conn = posix_tls_connection_create(c_ctx, sv[1]);
        int crc = posix_tls_connect(c_conn, "localhost");
        TEST_ASSERT(crc == POSIX_TLS_OK,
                    "Fullchain server must verify cleanly against root-only Public PKI client");

        char ver[32];
        char peer_fp[65];
        TEST_ASSERT(posix_tls_connection_get_negotiated_version(c_conn, ver, sizeof(ver)) == POSIX_TLS_OK,
                    "get_negotiated_version failed");
        TEST_ASSERT(std::strcmp(ver, "TLSv1.3") == 0, "Fullchain session must negotiate TLSv1.3");
        TEST_ASSERT(posix_tls_connection_get_peer_fingerprint(c_conn, peer_fp) == POSIX_TLS_OK,
                    "get_peer_fingerprint failed");
        TEST_ASSERT(expected_leaf_fp == peer_fp, "Peer fingerprint must match leaf certificate");

        const char* msg = "FULLCHAIN_PING";
        size_t written = 0;
        TEST_ASSERT(posix_tls_write(c_conn, msg, std::strlen(msg), &written) == POSIX_TLS_OK, "write failed");
        char resp[64];
        size_t nread = 0;
        TEST_ASSERT(posix_tls_read(c_conn, resp, sizeof(resp) - 1, &nread) == POSIX_TLS_OK, "read failed");
        resp[nread] = '\0';
        TEST_ASSERT(std::strcmp(resp, "PONG_FROM_SERVER") == 0, "Fullchain echo mismatch");

        posix_tls_shutdown(c_conn);
        posix_tls_connection_destroy(c_conn);
        pthread_join(st, NULL);
        TEST_ASSERT(sarg.result_rc == POSIX_TLS_OK && sarg.received_msg == "FULLCHAIN_PING",
                    "Server fullchain worker failed");
        posix_tls_context_destroy(c_ctx);
    }

    unlink(root_ca_file);
    posix_tls_context_destroy(s_ctx);
    X509_free(leaf_cert);
    X509_free(int_cert);
    X509_free(root_cert);
    EVP_PKEY_free(leaf_key);
    EVP_PKEY_free(int_key);
    EVP_PKEY_free(root_key);
}

// ---------------------------------------------------------------------------
// Main test entrypoint
// ---------------------------------------------------------------------------
int main() {
    signal(SIGPIPE, SIG_IGN);

    std::cout << "========================================" << std::endl;
    std::cout << " Running posix_tls Core Unit Test Suite  " << std::endl;
    std::cout << "========================================" << std::endl;

    run_test(test_context_lifecycle, "test_context_lifecycle");
    run_test(test_fingerprint_pin_validation, "test_fingerprint_pin_validation");
    run_test(test_random_bytes, "test_random_bytes");
    run_test(test_sha256_hash, "test_sha256_hash");
    run_test(test_self_signed_cert_generation, "test_self_signed_cert_generation");
    run_test(test_ca_bundle_loading, "test_ca_bundle_loading");
    run_test(test_loopback_p2p_tls13_handshake, "test_loopback_p2p_tls13_handshake");
    run_test(test_p2p_fingerprint_mismatch_rejection, "test_p2p_fingerprint_mismatch_rejection");
    run_test(test_p2p_missing_pin_fails_closed, "test_p2p_missing_pin_fails_closed");
    run_test(test_descriptor_sentinel_and_ownership, "test_descriptor_sentinel_and_ownership");
    run_test(test_public_pki_rejects_untrusted_server, "test_public_pki_rejects_untrusted_server");
    run_test(test_san_precedence_rfc6125, "test_san_precedence_rfc6125");
    run_test(test_cpp03_raii_wrappers, "test_cpp03_raii_wrappers");
    run_test(test_entropy_failure_injection, "test_entropy_failure_injection");
    run_test(test_forced_tls_versions_and_rejection, "test_forced_tls_versions_and_rejection");
    run_test(test_real_ip_san_matching, "test_real_ip_san_matching");
    run_test(test_length_bounds_and_narrowing_guards, "test_length_bounds_and_narrowing_guards");
    run_test(test_stale_openssl_error_queue_isolation, "test_stale_openssl_error_queue_isolation");
    run_test(test_closed_state_terminal_across_handshakes, "test_closed_state_terminal_across_handshakes");
    run_test(test_fullchain_credentials_and_chain_validation, "test_fullchain_credentials_and_chain_validation");

    std::cout << "========================================" << std::endl;
    std::cout << " All " << g_test_count << " posix_tls unit tests PASSED!" << std::endl;
    std::cout << "========================================" << std::endl;

    return 0;
}
