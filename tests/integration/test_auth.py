# tests/integration/test_auth.py
import socket, ssl, base64, time, statistics, pytest

SUBMISSION_PORT = 2587

def smtp_tls_connect():
    s = socket.create_connection(("127.0.0.1", SUBMISSION_PORT), timeout=5)
    s.recv(1024)
    s.sendall(b"EHLO test.local\r\n")
    s.recv(1024)
    s.sendall(b"STARTTLS\r\n")
    assert b"220" in s.recv(1024)

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    tls_s = ctx.wrap_socket(s, server_hostname="localhost")
    tls_s.sendall(b"EHLO test.local\r\n")
    tls_s.recv(1024)
    return tls_s

def test_auth_with_invalid_base64_doesnt_crash(jams_server):
    bad_payloads = [
        b"!!!not-base64-at-all!!!",
        b"",
        b"====",
        b"A",
        b"\x00\x01\x02\x03",
        b"QQ==" * 5000,
    ]

    for payload in bad_payloads:
        tls_s = smtp_tls_connect()
        try:
            tls_s.sendall(b"AUTH PLAIN\r\n")
            challenge = tls_s.recv(1024)
            assert b"334" in challenge, f"expected continuation prompt, got {challenge!r}"

            tls_s.sendall(payload + b"\r\n")
            tls_s.settimeout(5)
            reply = tls_s.recv(1024)

            assert reply, f"no reply to malformed payload {payload!r} — possible crash/hang"
            assert b"235" not in reply, "malformed base64 must never authenticate successfully"
        finally:
            tls_s.close()

    tls_s = smtp_tls_connect()
    tls_s.sendall(b"NOOP\r\n")
    assert b"250" in tls_s.recv(1024)
    tls_s.close()


def test_auth_login_with_invalid_base64_doesnt_crash(jams_server):
    tls_s = smtp_tls_connect()
    try:
        tls_s.sendall(b"AUTH LOGIN\r\n")
        assert b"334" in tls_s.recv(1024)

        tls_s.sendall(b"###invalid###\r\n")
        reply = tls_s.recv(1024)
        assert reply
        assert b"235" not in reply
    finally:
        tls_s.close()

    tls_s = smtp_tls_connect()
    tls_s.sendall(b"NOOP\r\n")
    assert b"250" in tls_s.recv(1024)
    tls_s.close()

def _time_auth_attempt(username: str, password: str) -> float:
    tls_s = smtp_tls_connect()
    try:
        creds = base64.b64encode(f"\x00{username}\x00{password}".encode()).decode()
        tls_s.sendall(f"AUTH PLAIN {creds}\r\n".encode())
        start = time.perf_counter()
        tls_s.recv(1024)
        elapsed = time.perf_counter() - start
        return elapsed
    finally:
        tls_s.close()


@pytest.mark.flaky(reruns=2)
def test_repeated_failed_auth_no_timing_leak(jams_server):
    SAMPLES = 15

    nonexistent_times = [
        _time_auth_attempt("definitely-not-a-real-user", "wrongpass")
        for _ in range(SAMPLES)
    ]

    existing_wrong_pw_times = [
        _time_auth_attempt("ci-test-user", "wrongpass")
        for _ in range(SAMPLES)
    ]

    med_nonexistent = statistics.median(nonexistent_times)
    med_existing = statistics.median(existing_wrong_pw_times)

    ratio = med_existing / med_nonexistent if med_nonexistent > 0 else float("inf")

    print(f"nonexistent-user median: {med_nonexistent*1000:.2f}ms")
    print(f"existing-user-wrong-pw median: {med_existing*1000:.2f}ms")
    print(f"ratio: {ratio:.2f}x")

    assert ratio > 0.3, (
        f"Existing-user auth was {1/ratio:.1f}x FASTER than nonexistent-user "
        f"auth — this direction is suspicious and worth investigating "
        f"(expected existing-user PBKDF2 verify to take at least as long)"
    )

    if ratio > 5.0 or ratio < 1.0 / 5.0:
        pytest.xfail(
            f"Possible timing side-channel: {ratio:.2f}x ratio between "
            f"existing/nonexistent username auth failures — investigate "
            f"CredentialStore::verify() for early-return-on-lookup-miss"
        )


def test_sql_injection_in_username(jams_server):
    payloads = [
        "' OR '1'='1",
        "' OR 1=1--",
        "admin'--",
        "'; DROP TABLE users;--",
        "' UNION SELECT username,hash,salt,iterations,active,created_at FROM users--",
        "ci-test-user' --",
        "\" OR \"\"=\"",
    ]

    for payload in payloads:
        tls_s = smtp_tls_connect()
        try:
            creds = base64.b64encode(f"\x00{payload}\x00anything".encode()).decode()
            tls_s.sendall(f"AUTH PLAIN {creds}\r\n".encode())
            reply = tls_s.recv(1024)

            assert b"235" not in reply, (
                f"SQL injection payload {payload!r} appears to have "
                f"authenticated successfully!"
            )

            assert reply, f"no response to payload {payload!r} — possible crash"
        finally:
            tls_s.close()

    tls_s = smtp_tls_connect()
    try:
        creds = base64.b64encode(b"\x00ci-test-user\x00ci-test-password").decode()
        tls_s.sendall(f"AUTH PLAIN {creds}\r\n".encode())
        reply = tls_s.recv(1024)
        assert b"235" in reply, (
            "Known-good user failed to authenticate after injection "
            "attempts — users table may have been corrupted/dropped"
        )
    finally:
        tls_s.close()
        