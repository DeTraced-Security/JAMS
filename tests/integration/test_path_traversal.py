import socket, os

MAILROOT = "/tmp/jams/mail"

def send_mail_to(rcpt):
    with socket.create_connection(("127.0.0.1", 2525), timeout=5) as s:
        s.recv(1024)
        s.sendall(b"EHLO test.local\r\n"); s.recv(1024)
        s.sendall(b"MAIL FROM:<attacker@evil.test>\r\n"); s.recv(1024)
        s.sendall(f"RCPT TO:<{rcpt}>\r\n".encode())

        rcpt_reply = s.recv(1024)
        if b"250" not in rcpt_reply:
            return rcpt_reply, None 

        s.sendall(b"DATA\r\n"); s.recv(1024)
        s.sendall(b"Subject: test\r\n\r\nbody\r\n.\r\n")
        return rcpt_reply, s.recv(1024)

def test_dot_traversal_in_rcpt():
    payload = "../../../../etc/passwd"
    rcpt_reply, _ = send_mail_to(f"{payload}@localhost")
    assert b"250" not in rcpt_reply

def test_no_traversed_file_created():
    payload = "..%2f..%2f..%2ftmp%2fpwnd"
    send_mail_to(f"{payload}@localhost")

    for root, dirs, files in os.walk("/tmp"):
        for f in files:
            assert "pwnd" not in f, f"traversal escaped mailroot: {os.path.join(root, f)}"

def test_absolute_path_rejected():
    rcpt_reply, _ = send_mail_to("/etc/cron.d/evil@localhost")
    assert b"250" not in rcpt_reply

def test_null_byte_in_rcpt():
    rcpt_reply, _ = send_mail_to("valid\x00../../etc/passwd@localhost")
    assert b"250" not in rcpt_reply
