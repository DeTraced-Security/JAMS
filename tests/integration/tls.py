import ssl, socket, time

def test_starttls_upgrade():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    with socket.create_connection(("127.0.0.1", 2587), timeout=5) as s:
        s.recv(1024)
        s.sendall(b"EHLO test.local\r\n"); s.recv(1024)
        s.sendall(b"STARTTLS\r\n")
        reply = s.recv(1024)

        assert b"220" in reply

        with ctx.wrap_socket(s, server_hostname="localhost") as tls_s:
            tls_s.sendall(b"EHLO test.local\r\n")
            assert b"250" in tls_s.recv(1024)

def test_plaintext_commands_after_tls_reject():
    with socket.create_connection(("127.0.0.1", 2587), timeout=5) as s:
        s.recv(1024)
        s.sendall(b"EHLO test.local\r\n")
        s.recv(1024)

        injected = b"MAIL FROM:<attacker@evil.test>\r\n"
        s.sendall(b"STARTTLS\r\n" + injected)

        reply = s.recv(1024)
        assert b"220" in reply, "STARTTLS should be accepted"

        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        with ctx.wrap_socket(s, server_hostname="localhost") as tls:
            tls.settimeout(1.0)
            try:
                leaked = tls.recv(1024)
            except socket.timeout:
                leaked = b""

            assert b"250" not in leaked, (
                "Smuggled plaintext command was executed after STARTTLS: "
                f"Got: {leaked!r}"
            )

            tls.sendall(b"EHLO test.local\r\n")
            tls.settimeout(5.0)
            ehlo_reply = tls.recv(1024)

            assert b"250" in ehlo_reply

            tls.sendall(b"RCPT TO:<victim@test.local>\r\n")
            rcpt_reply = tls.recv(1024)

            assert b"503" in rcpt_reply, (
                "Server still has the smuggled MAIL FROM "
                f"State active, expected 503 but got: {rcpt_reply!r}"
            )

def test_starttls_buffer_not_replayed_as_tls():
    with socket.create_connection(("127.0.0.1", 2587), timeout=5) as s:
        s.recv(1024)
        s.sendall(b"EHLO test.local\r\n")
        s.recv(1024)

        junk = b"X" * 512
        s.sendall(b"STARTTLS\r\n" + junk)
        reply = s.recv(1024)
        assert b"220" in reply

        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        try:
            with ctx.wrap_socket(s, server_hostname="localhost") as tls_s:
                tls_s.settimeout(5.0)
                tls_s.sendall(b"EHLO test.local\r\n")
                resp = tls_s.recv(1024)
                assert b"250" in resp
        except ssl.SSLError:
            pass

def test_auth_reject_without_tls():
    with socket.create_connection(("127.0.0.1", 2587), timeout=5) as s:
        s.recv(1024)
        s.sendall(b"EHLO test.local\r\n"); s.recv(1024)
        s.sendall(b"AUTH PLAIN aaaaaaaaaaaaaaaa=\r\n")
        reply = s.recv(1024)

        assert b"538" in reply

def test_weak_tls_rejection():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.minimum_version = ssl.TLSVersion.SSLv3

    ...
