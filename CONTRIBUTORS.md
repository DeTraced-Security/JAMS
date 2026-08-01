# How to contribute

I'm really glad you're reading this, because we need volunteer developers to help this project come to fruition.

A list of resources will be published shortly for how to contribute to the project.

## Testing

JAMS has a testing suite (JAMS Autotest) that runs dynamic testing of the following vulnerabilities:
- DOS:
- - Denial of Service (Many Connections)
- - Slowloris (Partial Command)
- - Oversized Trickled Lines
- TLS/Authentication:
- - Invalid Base64 to Crash
- - Password Timing Attack
- - SQL Injection (Username)
- Path Traversal:
- - RCPT Dot Traversal
- - Unicode Dot Traversal (Local Name)
- - Absolute Path Traversal (Local Name)
- - Null Byte Traversal (Local Name)
- Buffer Overflow:
- - SMTP Oversized Line (FROM:<>)
- - Integer Overflow (Max RCPT Size)
- SMTP Command Injection:
- - Bad Command Sequence
- - CRLF Injection
- Other:
- - Abrupt Disconnect to Data Leak

It is heavily recommended to rely on manual testing of all implementations, including those covered in the automatic tests to ensure proper security and reduce possible implementations of unintentional attack surfaces.

## Submitting changes

Please send a GitHub Pull Request to opengovernment with a clear list of what you've done (read more about pull requests). Please follow our coding conventions (below) and make sure all of your commits are atomic (one feature per commit).

Always write a clear log message for your commits. One-line messages are fine for small changes, but bigger changes should look like this:

```sh
$ git commit -S -m "A brief summary of the commit
>
> A paragraph describing what changed and its impact."
```

## Coding conventions

Start reading our code and you'll get the hang of it. We optimize for readability and secuity:

- We indent using four spaces (hard or soft tabs)
- All commits must be signed, either over web, SSH, or GPG. Any commits as of `2026-08-01T06:41:54.916Z` that are not signed will not be accepted*. Pull Requests, included.
- We avoid logic in views, putting HTML generators into helpers
- Use correct commenting styles, multi-line should use `/** */`, or Doxygen-styled, comments and should concisely describe why it works. Avoid explaining the what it does unless the method may appear obscure.
- We ALWAYS put spaces after list items and method parameters (`[1, 2, 3]`, not `[1,2,3]`), around operators (`x += 1`, not `x+=1`), and around hash arrows.
- This is open source software. Consider the people who will read your code, and make it look nice for them. It's sort of like driving a car: Perhaps you love doing donuts when you're alone, but with passengers the goal is to make the ride as smooth as possible.
- We use strong typing, so ensure that all variables, functions, etc. are using the correct explicit type (`const std::string = "asdf";`, `auto func = []() -> std::vector<uint64_t> {}`).

\* Setting up commit signing can be found can be under GitHub's [Signing Commits](https://docs.github.com/en/authentication/managing-commit-signature-verification/signing-commits) documentation.

# Practising Secure Coding:

While we acknowledge readability, there are cases where we apply security standards that may lead to obscure code.
In such cases, the standards applied are as followed and may reference OWASP ASVS:

### Threat Matrix
Our current working threat matrix is defined as below, and may be subject to change

| **Threat** | **Risk Description** | **Mitigation/Control** | **Status** | **ASVS Reference** |
| --- | --- | --- | --- | --- |
| **1. Obscured Readability Due to Security Practices** | Security measures may lead to code that is harder to read or understand, increasing the chances of security flaws. | Maintain balance between readability and security standards. | Ongoing | OWASP ASVS: General Practice |
| **2. Unnecessary Supply Chain Dependencies** | Overuse of libraries for simple methods increases the attack surface due to more dependencies and potential vulnerabilities. | Avoid installing external libraries for simple tasks. Current deps: liburing, OpenSSL, SQLite3, tomlc99. | Controlled | OWASP ASVS: General Practice |
| **3. Insufficient Input and Output Handling** | Failure to clearly define how to handle data input and output may lead to unexpected behaviors or vulnerabilities. | Input/output handling defined by type, content, and relevant laws/policies. SMTP/IMAP command parsers validate all input before processing. | Partial | ASVS 4.0.3, 1.5.1 |
| **4. Deserialization Vulnerabilities** | Using serialization with untrusted clients can open the application to attacks like object injection and deserialization flaws. | No serialization with untrusted clients. TOML config parsed at startup only from trusted local filesystem. | Mitigated | ASVS 4.0.3, 1.5.2 |
| **5. Lack of Input Validation on Trusted Service Layer** | Failing to enforce input validation at the service layer may result in improper data processing, leading to injection attacks. | SMTP local-part validated against allowlist of safe characters. Path traversal blocked via `is_safe_local()` and `std::filesystem::weakly_canonical`. IMAP commands validated before dispatch. | Mitigated | ASVS 4.0.3, 1.5.3 |
| **6. Inconsistent or Poor Logging Practices** | Improper or inconsistent logging may obscure security incidents or make them harder to detect. | Structured `[subsystem]` prefixed logging across SMTP, IMAP, TLS, DNS, relay, and DKIM subsystems. Standardized log format not yet enforced programmatically. | Partial | ASVS 4.0.3, 1.7.1 |
| **7. Outdated/Insecure Components in Build Pipeline** | The presence of outdated, insecure, or vulnerable components can introduce new risks to the application. | Build pipeline targets C++23. Dependencies pinned. No automated CVE scanning yet — recommended addition. | Partial | ASVS 4.0.3, 1.14.3 |
| **8. Use of Unsupported or Insecure Client-Side Technologies** | Use of deprecated or insecure client-side technologies can introduce vulnerabilities or make the system incompatible. | JAMS is a server-side only application with no client-side components. Not applicable. | N/A | ASVS 4.0.3, 1.14.6 |
| **9. Path Traversal via Maildir Local-Part** | A malicious `RCPT TO` address containing `../` sequences could write mail outside the maildir root. | `is_safe_local()` allowlist rejects any local-part containing `/`, `..`, or non-alphanumeric characters. Secondary check via `std::filesystem::weakly_canonical` ensures path stays within mail root. | Mitigated | ASVS 4.0.3, 12.3.1 |
| **10. Open Relay / Unauthorized Mail Relay** | Port 25 accepting `RCPT TO` for external domains enables the server to be used as a spam relay, causing reputation damage and blocklisting. | Port 25 (`SMTPSession`) rejects any `RCPT TO` whose domain does not match the configured local hostname with `550 5.7.1 Relaying denied`. External delivery only permitted on port 587 after authentication. | Mitigated | ASVS 4.0.3, 1.5.3 |
| **11. Missing or Weak Email Authentication (SPF/DKIM/DMARC)** | Without SPF, DKIM, and DMARC, outbound mail can be spoofed or rejected by receiving servers, and inbound spoofed mail may be accepted. | SPF and DMARC DNS records published. Outbound DKIM signing implemented via `DKIMSigner` with RSA-SHA256 and configurable canonicalization. Inbound DKIM/SPF/DMARC verification present in `src/auth/`. | Mitigated | ASVS 4.0.3, 1.5.1 |
| **12. TLS Downgrade / Cleartext Credential Exposure** | Clients connecting without TLS could expose credentials or message content in transit. | TLS 1.2 minimum enforced on all listener ports. `AUTH` rejected on port 587 without active TLS (`538 5.7.11 Encryption required`). STARTTLS supported on ports 25, 587, and 143. | Mitigated | ASVS 4.0.3, 9.1.1 |
| **13. BCC Header Leakage** | Delivering a message with the `Bcc:` header intact exposes BCC recipients to other recipients, violating confidentiality. | `Bcc:` header stripped from message body before local delivery and outbound relay in both `SMTPSession` and `SubmissionServer`. | Mitigated | ASVS 4.0.3, 1.5.1 |
| **14. Memory Safety — Misaligned DNS Wire Reads** | Direct pointer casting of DNS wire format data causes undefined behaviour on platforms requiring aligned access. | All multi-byte wire reads replaced with `memcpy` into aligned local variables before `ntohs()`. AddressSanitizer and UBSan enabled in debug builds. | Mitigated | ASVS 4.0.3, 1.14.3 |
| **15. io_uring fd Lifecycle / Use-After-Free** | Closing a file descriptor while io_uring SQEs referencing it are still in-flight causes undefined behaviour or data corruption. | `inflight` counter per connection ensures `::close()` is deferred until all in-flight SQEs drain. `wants_close()` flag prevents use-after-free in session callbacks. | Mitigated | ASVS 4.0.3, 1.14.3 |


## Key Notes for Secure Coding:
- Input Validation: Always validate input on the trusted service layer to prevent attacks like SQL injection, XSS, etc. Input validation must consider the type, content, and specific laws/regulations that apply.
- Serialization Integrity: Avoid using serialization for communication with untrusted clients. If unavoidable, ensure the integrity and confidentiality of serialized data.
- Library Dependency: Use libraries only when necessary, and avoid bloating the application with unnecessary dependencies to minimize the risk of introducing vulnerabilities.
- Logging and Monitoring: Use consistent and structured logging to monitor activities and catch security incidents early.
- Build Pipeline Security: Ensure the build pipeline detects and flags outdated or insecure components before they are deployed into production.
- Client-Side Technologies: Regularly audit client-side technologies to ensure they are up-to-date and secure, and avoid deprecated or insecure components.

Thanks,
DeTraced Staff
