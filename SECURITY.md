# Security Policy

`posix-tls` provides a TLS 1.2 / 1.3 stream wrapper for POSIX sockets with statically embedded OpenSSL 3.5 LTS. Because security and cryptographic integrity are critical to any networking stack, this document outlines our supported versions, vulnerability reporting process, and upstream dependency tracking SLA.

---

## Supported Versions

Only the latest patch release on the current stable minor branch receives security updates.

| Version | Supported | Notes |
| :--- | :--- | :--- |
| `1.0.x` | :white_check_mark: | Current stable LTS release series |
| `< 1.0` | :x: | Prerelease / unsupported |

---

## Reporting a Vulnerability

Please do **not** report security vulnerabilities via public GitHub issues, discussions, or pull requests.

### Preferred Method: GitHub Private Vulnerability Reporting

1. Navigate to the repository's security advisory page:
   [Report a vulnerability](https://github.com/ItsLaurelNotYanny/posix-tls/security/advisories/new)
2. Fill out the advisory form with:
   - A clear description of the vulnerability and its potential impact.
   - Affected versions, platforms (e.g. Linux x86_64, QNX Neutrino 6.6 ARMv7), and compiler versions.
   - Minimal proof-of-concept (PoC) code or steps to reproduce.
   - Any proposed remediation or patch, if available.

### Response Timeline

- **Initial acknowledgment:** Within **48 hours** of receiving the report.
- **Triage and assessment:** Within **5 business days**, confirming whether the issue is reproducible and establishing severity.
- **Fix and disclosure:** A patch will be developed in a private branch, verified against the automated test gate, and released as a new patch version (`1.0.x`). Coordinated disclosure will occur simultaneously with or shortly after the release.

---

## Upstream Dependency Tracking & SLA

`posix-tls` bundles two pinned upstream inputs (defined in `dependencies.lock.json`):
1. **OpenSSL 3.5 LTS** (`openssl-3.5.9.tar.gz`)
2. **Mozilla CA root certificate bundle** (`cacert.pem`)

### Upstream OpenSSL Security Advisories

We actively monitor OpenSSL security advisories ([openssl.org/news/vulnerabilities.html](https://www.openssl.org/news/vulnerabilities.html)). When an advisory affects the OpenSSL 3.5 LTS release stream:

- **Critical Vulnerabilities** (e.g. remote code execution or exploitable memory corruption in active handshake):
  - Target release: within **72 hours** of upstream public disclosure.
- **High Severity Vulnerabilities** (e.g. denial of service or cryptographic bypass):
  - Target release: within **7 calendar days** of upstream public disclosure.
- **Moderate / Low Severity Vulnerabilities**:
  - Addressed in the next scheduled maintenance release.

When an OpenSSL update is released, `posix-tls` cuts a new patch release (e.g. `1.0.1`), updates `dependencies.lock.json`, rebuilds the static libraries with full symbol-isolation verification, and publishes updated SDK archives and checksums.

### Mozilla CA Certificate Bundle

- **Routine updates:** Refreshed quarterly or bi-monthly to include newly trusted root CAs and remove expired ones.
- **Emergency updates:** Released within **48 hours** if a major Certificate Authority is distrusted or compromised.

---

## Release Rhythm & Verifiable Builds

- **Patch Releases (`1.0.x`):** Released as needed for security fixes, upstream OpenSSL bumps, or critical bug fixes.
- **Minor Releases (`1.x.0`):** Scheduled quarterly or when backward-compatible features or platform support are added.
- **Verification Gate:** Every release passes an automated 9-stage verification suite covering memory safety, nonblocking stream edge cases, 20-case contract suites, relocatable consumer builds, and ELF `.dynsym` symbol isolation.
- **Integrity:** Every GitHub Release includes `SHA256SUMS` covering all distributed source and SDK tarballs.
