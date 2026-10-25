# posix-tls API Contracts

## 1. File Descriptor (`fd`) Ownership Contract

- **Creation Transfer**: When calling `posix_tls_connection_create(ctx, socket_fd)`:
  - If creation **fails** (returns `NULL`), the socket descriptor remains owned by the caller, and the caller is responsible for calling `close(socket_fd)`.
  - If creation **succeeds** (returns a non-NULL `posix_tls_connection_t*`), sole ownership of `socket_fd` transfers unconditionally to the connection object.
- **Destruction Cleanup**: Calling `posix_tls_connection_destroy(conn)` closes the underlying socket file descriptor exactly once and frees all associated connection memory and SSL state.
- **No Follow-up Close**: The caller **MUST NOT** close `socket_fd` after calling `posix_tls_connection_destroy(conn)`. Doing so would close a stale descriptor number that may have already been reallocated by the kernel to another thread's socket or file.

## 2. Handle Lifetime and Thread Safety

- **Context Lifetime**: `posix_tls_context_t*` must outlive all `posix_tls_connection_t*` handles created from it. Destroying a context while connections are still active causes undefined behavior.
- **String Ownership**:
  - `posix_tls_get_last_error(conn)` returns a pointer to internal static or connection-managed storage valid until the next operation on `conn`. The caller must not modify or free this string.
  - `posix_tls_generate_self_signed_cert(cert_out, cert_len, key_out, key_len)` allocates heap buffers for the PEM outputs. The caller must release each allocated string with `posix_tls_free_string()`.
- **Thread Safety**: Distinct `posix_tls_connection_t` handles may be operated concurrently on separate threads. Simultaneous access to a single connection handle across threads requires external synchronization. TLS handshake, stream I/O, and shutdown operations clear stale thread-local OpenSSL errors before invoking OpenSSL I/O primitives so unrelated cryptographic or PEM failures on the same thread cannot corrupt nonblocking readiness signaling.
- **Buffer Length Limits and Fullchain Credentials**:
  - Single-call buffer and PEM length parameters (`posix_tls_random_bytes`, `posix_tls_read`, `posix_tls_write`, `posix_tls_calculate_cert_fingerprint`, and `posix_tls_context_set_credentials`) must be non-zero and at most `INT_MAX` bytes (`1 <= len <= INT_MAX`). Zero or oversized lengths fail immediately with `POSIX_TLS_ERR_INVALID_ARG` before touching caller buffers or narrowing integer sizes.
  - `posix_tls_context_set_credentials` accepts either a single leaf certificate PEM or a concatenated fullchain PEM (leaf certificate first, followed by intermediate CA certificates in chain order). Malformed trailing PEM blocks fail closed with `POSIX_TLS_ERR_INVALID_ARG`.

## 3. Nonblocking I/O and Retry-Buffer Rules

- For nonblocking sockets (e.g. `O_NONBLOCK`), operations (`posix_tls_connect`, `posix_tls_accept`, `posix_tls_read`, `posix_tls_write`, `posix_tls_shutdown`) may return `POSIX_TLS_ERR_WANT_READ` or `POSIX_TLS_ERR_WANT_WRITE`.
- When `POSIX_TLS_ERR_WANT_READ` is returned, wait for readability on the underlying socket (e.g. via `select`, `poll`, `epoll`, `kqueue`, or an event loop) before retrying.
- When `POSIX_TLS_ERR_WANT_WRITE` is returned, wait for writability on the underlying socket before retrying.
- **Buffer Stability Rule**: When retrying an interrupted or nonblocking write (`posix_tls_write`), the caller MUST pass the exact same buffer pointer and length parameter as the previous invocation. Modifying or reallocating the buffer between retries violates TLS record boundaries.

## 4. Shutdown Semantics

- `posix_tls_shutdown(conn)` transmits the local TLS `close_notify` alert.
- Once the local `close_notify` alert is sent (or if the peer closure has already been received), the connection transitions to the closed state and `posix_tls_shutdown` returns `POSIX_TLS_OK` (0).
- Any subsequent call to `posix_tls_shutdown`, `posix_tls_connect`, or `posix_tls_accept` on a connection that has reached the closed state returns `POSIX_TLS_ERR_CLOSED` (-3) without reopening or restoring authentication.
- Any subsequent call to `posix_tls_read` or `posix_tls_write` on a connection that has reached the closed state returns `POSIX_TLS_ERR_IO_FAILED` (-13), distinguishing post-shutdown I/O attempts from a peer closure alert received during active transfer (`POSIX_TLS_ERR_CLOSED` / -3).
- In nonblocking mode, if alert transmission cannot complete immediately, `posix_tls_shutdown` returns `POSIX_TLS_ERR_WANT_WRITE` or `POSIX_TLS_ERR_WANT_READ`. The application must wait for socket readiness and retry until `POSIX_TLS_OK` or an error is returned.

## 5. Building and Examples

See [BUILDING.md](BUILDING.md) for consumer build commands. The installed CMake target is `posix_tls::posix_tls`. Headers, static archives, pinned CA bundle, license, and this contract are installed together. The CA path is supplied explicitly by the application; it is never inferred from the build tree.

The package includes `posix_tls_probe` (TCP client/server/fingerprint CLI) and standalone consumer verification tests (nonblocking bidirectional exchange and cancellation). Project code is MIT; statically bundled OpenSSL 3.5.9 retains Apache 2.0. See [LICENSE](LICENSE).
