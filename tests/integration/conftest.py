import subprocess, socket, time, os, signal, pytest

JAMS_BIN = os.environ["JAMS_BIN"]
JAMS_CONFIG = os.environ["JAMS_CONFIG"]
PORTS = {
    "smtp": 2525, "submission": 2587,
    "imap4": 2143, "imap4s": 2993
}

def wait_for_port(port, timeout=10):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                return True
        except (ConnectionRefusedError, OSError):
            time.sleep(0.1)
    return False

@pytest.fixture(scope="session")
def jams_server():
    proc = subprocess.Popen(
        [JAMS_BIN],
        cwd=os.path.dirname(JAMS_CONFIG),
        stdout=open("/tmp/jams/logs/stdout.log", "w"),
        stderr=open("/tmp/jams/logs/stderr.log", "w")
    )

    for name, port in PORTS.items():
        if not wait_for_port(port):
            proc.terminate()
            raise RuntimeError(f"{name} port {port} never came up, check server logs")

    yield proc

    proc.send_signal(signal.SIGTERM)
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()

@pytest.fixture(scope="session", autouse=True)
def seed_test_user():
    subprocess.run(
        [JAMS_BIN, "--add-user", "ci-test-user", "ci-test-password"],
        check=True,
        cwd=os.path.dirname(JAMS_CONFIG)
    )
