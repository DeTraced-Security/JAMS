# Security Policy

## Supported Versions

JAMS is currently in active pre-release development. Security fixes are applied to the `main` branch only. Once stable releases are tagged, this table will be updated to reflect the support window.

| Version | Supported |
|---------|-----------|
| `main` (pre-release) | ✅ Yes |
| Any tagged release | ✅ Yes (latest only) |
| Older tagged releases | ❌ No |

We strongly recommend always running the latest commit on `main` or the most recent tagged release until a long-term support policy is established.

---

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues, pull requests, or discussions.**

### Private Disclosure

Report vulnerabilities privately via GitHub's built-in security advisory system:

1. Navigate to the [JAMS repository](https://github.com/DeTraced-Security/JAMS)
2. Click **Security** → **Advisories** → **Report a vulnerability**
3. Fill in the details described below

If you are unable to use GitHub's advisory system, contact the maintainers directly via the email address listed in the repository's `CODEOWNERS` file.

### What to Include

A useful report includes as much of the following as possible:

- A clear description of the vulnerability and its potential impact
- The affected component (e.g. SMTP state machine, TLS handshake path, Maildir writer, io_uring loop)
- Steps to reproduce, including any proof-of-concept code or packet captures
- The version or commit hash where the issue was observed
- Any suggested mitigations or fixes

The more detail you provide, the faster we can triage and respond.

### Response Timeline

| Milestone | Target |
|-----------|--------|
| Acknowledgement of report | Within 48 hours |
| Initial triage and severity assessment | Within 7 days |
| Fix developed and reviewed | Within 30 days for critical/high; 90 days for medium/low |
| Public disclosure | Coordinated with reporter; typically after fix is released |

We follow a coordinated disclosure model. We ask that reporters allow us reasonable time to develop and release a fix before publishing details publicly. We will credit reporters in the security advisory unless anonymity is requested.

---

## Scope

The following are considered in scope for security reports:

- **SMTP engine** -> command injection, state machine bypass, envelope spoofing, DoS via malformed input
- **TLS implementation** -> downgrade attacks, certificate validation issues, memory BIO mishandling
- **STARTTLS** -> stripping attacks, premature upgrade, post-upgrade state confusion
- **Maildir storage** -> path traversal, symlink attacks, TOCTOU races on `tmp/` → `new/` rename
- **io_uring event loop** -> use-after-free, SQ overflow handling, user_data confusion between connections
- **Memory safety** -> buffer overflows, use-after-free, double-free in any component
- **Zero-access encryption** (once implemented) -> key leakage, weak key derivation, oracle attacks
- **Authentication** (once implemented) -> SASL bypass, credential exposure, timing attacks
- **Denial of service** -> resource exhaustion, connection floods, malformed packet handling

The following are currently out of scope:

- Vulnerabilities in third-party dependencies (OpenSSL, liburing) -> report these upstream
- Issues requiring physical access to the server
- Social engineering of maintainers
- Vulnerabilities in GitHub Actions CI configuration that do not affect the JAMS binary itself

---

## Security Design Principles

JAMS is built with the following security properties as explicit design goals:

**Memory safety.** All builds enable `-fsanitize=address,undefined` in Debug mode. The codebase avoids raw `new`/`delete` in favour of `std::unique_ptr` and RAII throughout. Buffer bounds are validated at every protocol parsing boundary.

**TLS enforcement.** JAMS enforces a minimum of TLS 1.2 on all encrypted connections. TLS 1.0 and 1.1 are disabled at the `SSL_CTX` level. TLS compression is disabled to prevent CRIME-class attacks. The cipher list prefers ECDHE forward-secrecy suites and explicitly excludes deprecated algorithms.

**No cleartext secrets.** Authentication credentials are never logged. The planned zero-access encryption layer ensures mail bodies are encrypted client-side before reaching disk; the server never holds plaintext message content.

**Least privilege.** JAMS is designed to run without root after initial socket binding. `CAP_NET_BIND_SERVICE` is the only elevated capability required for production deployment on ports 25/587/993.

**Input validation.** The SMTP parser enforces RFC 5321 line length limits (2048 bytes), recipient count limits (100 per envelope), and message size limits (configurable, default 50 MB). The DNS message decoder enforces pointer depth limits to prevent decompression loops.

**Atomic delivery.** Maildir delivery writes to `tmp/` and renames to `new/` atomically. A crash between these two steps leaves an orphan in `tmp/` but never corrupts `new/`, ensuring no partial messages are delivered.

---

## Known Limitations (Current Pre-Release)

The following security features are planned but not yet implemented. Deployments should be aware of these gaps:

- **Zero-access encryption** is not yet implemented. Mail bodies are stored in plaintext on disk.
- **SPF, DKIM, and DMARC** validation is not yet implemented. Inbound mail is not authenticated.
- **SASL authentication** for the submission server is not yet implemented. Port 587 should not be exposed publicly in the current build.
- **Rate limiting and connection throttling** are not yet implemented. The server is susceptible to connection exhaustion under high load.
- **Outbound DKIM signing** is not yet implemented.

We do not recommend exposing a JAMS instance to the public internet until the project is complete and a formal security audit has been conducted.

---

## Static Analysis and CI

JAMS runs GitHub CodeQL analysis on every pull request targeting `main`. The workflow analyses the C++ codebase for memory safety issues, format string vulnerabilities, use-after-free, and other CWE-mapped vulnerability classes. Pull requests that introduce CodeQL findings will not be merged without review and remediation.

Additional static analysis tooling (clang-tidy, cppcheck) is planned for integration in a future CI update.

---

## Acknowledgements

We are grateful to all researchers who responsibly disclose vulnerabilities in JAMS. Contributors who report valid security issues will be credited in the relevant GitHub Security Advisory unless they request otherwise.

---

*This policy is versioned alongside the JAMS codebase. For the current version, see [`SECURITY.md`](./SECURITY.md) on the `main` branch.*
