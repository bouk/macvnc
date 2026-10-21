import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import sys
import threading
import uuid

import pytest

from macvnc import _session
from test_macvnc import fake_mac, recv_exact


@pytest.fixture
def session(tmp_path):
    listener = socket.create_server(("127.0.0.1", 0))
    listener.settimeout(10)
    name = "test-" + uuid.uuid4().hex
    received = {"events": [], "screenshots": 0}
    errors = []
    closed = threading.Event()

    def handle(conn):
        conn.settimeout(15)
        while True:
            kind = conn.recv(1)
            if not kind:
                closed.set()
                return
            if kind == b"\x04":
                received["events"].append(kind + recv_exact(conn, 7))
            elif kind == b"\x05":
                received["events"].append(kind + recv_exact(conn, 5))
            elif kind == b"\x03":
                recv_exact(conn, 9)
                received["screenshots"] += 1
                pixels = bytes([0, 0, 255, 0] * 8)
                conn.sendall(struct.pack(">BxHHHHHi", 0, 1, 0, 0, 4, 2, 0) + pixels)
            else:
                raise AssertionError(f"unexpected VNC message {kind!r}")

    def server():
        try:
            fake_mac(listener, received, handle)
        except Exception as exc:
            errors.append(exc)

    thread = threading.Thread(target=server, daemon=True)
    thread.start()
    env = {**os.environ, "PYTHONPATH": str(Path(__file__).resolve().parents[1] / "src")}
    env.pop("MACVNC_PASSWORD", None)
    port = str(listener.getsockname()[1])

    def cli(*actions, host="127.0.0.1", password=None, cwd=tmp_path):
        command_env = dict(env)
        if password is not None:
            command_env["MACVNC_PASSWORD"] = password
        return subprocess.run(
            [sys.executable, "-m", "macvnc", host, "--port", port, "--session", name, *actions],
            env=command_env, cwd=cwd, capture_output=True, text=True, timeout=15,
        )

    yield cli, received, closed, name
    cli("--disconnect")
    listener.close()
    thread.join(timeout=2)
    (_session._directory() / f"{name}.lock").unlink(missing_ok=True)
    assert not errors


def check(result):
    assert result.returncode == 0, result.stderr


def test_persistent_connection(session, tmp_path):
    cli, received, closed, name = session
    # A crashed process can leave its socket behind; startup replaces it.
    path = _session._directory() / f"{name}.sock"
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as stale:
        stale.bind(str(path))
    result = cli("capture:missing.png")
    assert result.returncode == 2
    assert "give -u/--user" in result.stderr
    check(cli("-u", "admin", "password", "key:return", "move:3,1", "capture:first.png", password="secret"))
    assert not closed.is_set()
    assert (received["user"], received["password"]) == (b"admin", b"secret")
    assert path.stat().st_mode & 0o777 == 0o600

    # A separate invocation with no credentials keeps the connection, pointer
    # and password action. Relative screenshot paths belong to this caller.
    other = tmp_path / "other"
    other.mkdir()
    check(cli("click", "password", "capture:second.png", cwd=other))
    assert not closed.is_set()
    assert received["screenshots"] == 2
    assert (tmp_path / "first.png").read_bytes() == (other / "second.png").read_bytes()
    assert struct.pack(">BBHH", 5, 1, 3, 1) in received["events"]
    assert sum(event == struct.pack(">BBxxI", 4, 1, ord("s")) for event in received["events"]) == 2

    # Request mistakes are reported without losing the authenticated session.
    result = cli("key:unknown+return")
    assert result.returncode == 1
    assert "unknown" in result.stderr
    check(cli("capture:after-error.png"))
    assert cli("capture:no.png", host="other.local").returncode == 1
    result = cli("-u", "other", "capture:no.png")
    assert "different account" in result.stderr
    assert not (tmp_path / "no.png").exists()

    check(cli("--disconnect"))
    assert closed.wait(2)
    assert not path.exists()
    result = cli("--disconnect")
    assert result.returncode == 1
    assert "not running" in result.stderr


def test_concurrent_start(session):
    cli, received, closed, _ = session
    results = []
    threads = [threading.Thread(target=lambda: results.append(cli("-u", "admin", password="secret"))) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert len(results) == 2
    for result in results:
        check(result)
    check(cli("capture:screen.png"))
    assert received["screenshots"] == 1
    assert not closed.is_set()


def test_failed_login_cleans_up(tmp_path, monkeypatch):
    def refused(*args):
        raise PermissionError("login refused")

    monkeypatch.setattr(_session, "connect", refused)
    ready = tmp_path / "ready"
    path = _session._directory() / f"test-{uuid.uuid4().hex}.sock"
    with ready.open("w+b") as stream:
        with pytest.raises(PermissionError, match="login refused"):
            _session.serve({"path": str(path), "host": "mac", "user": "admin", "password": "secret", "port": 5900}, stream)
    assert not path.exists()


@pytest.mark.parametrize("name", ["../escape", "", "x" * 41, "/tmp/test"])
def test_invalid_session_names(name):
    from argparse import Namespace

    with pytest.raises(_session.SessionError, match="session name"):
        _session.run(Namespace(session=name), lambda: pytest.fail("password should not be read"))


def test_private_directory(tmp_path, monkeypatch):
    monkeypatch.setattr(_session.os, "getuid", lambda: os.stat(tmp_path).st_uid)
    directory = tmp_path / f"macvnc-{os.getuid()}"
    directory.mkdir(mode=0o755)
    real_path = Path
    monkeypatch.setattr(_session, "Path", lambda path: tmp_path if path == "/tmp" else real_path(path))
    with pytest.raises(_session.SessionError, match="mode 0700"):
        _session._directory()


def test_message_limit():
    import io

    for data in [b"", b"{}", b"x" * (1024 * 1024 + 1) + b"\n"]:
        with pytest.raises(_session.SessionError):
            _session._read(io.BytesIO(data))
    assert _session._read(io.BytesIO(json.dumps({"actions": []}).encode() + b"\n")) == {"actions": []}


@pytest.mark.parametrize("args, error", [
    (["mac", "--disconnect"], "requires --session"),
    (["mac", "--session", "work", "--disconnect", "click"], "requires --session"),
    (["mac"], "give at least one action"),
    (["mac", "capture:screen.png"], "give -u/--user"),
    (["mac", "--session", "", "capture:screen.png"], "session name"),
    (["mac", "--idle-timeout", "10", "click"], "requires --session"),
    (["mac", "--session", "work", "--disconnect", "--idle-timeout", "10"], "without --disconnect"),
    (["mac", "--session", "work", "--idle-timeout", "-1"], "nonnegative"),
    (["mac", "--session", "work", "--idle-timeout", "nan"], "finite"),
    (["mac", "--session", "work", "--idle-timeout", "inf"], "finite"),
    (["mac", "--session", "work", "--idle-timeout", "1e999"], "finite"),
])
def test_cli_validation(args, error, monkeypatch, capsys):
    from macvnc.__main__ import main

    monkeypatch.setattr(sys, "argv", ["macvnc", *args])
    with pytest.raises(SystemExit):
        main()
    assert error in capsys.readouterr().err


def test_one_shot_cli(monkeypatch, tmp_path):
    from macvnc import __main__ as cli

    class Mac:
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            events.append("closed")

        def move(self, *point):
            events.append(point)

        def click(self, *point):
            events.append(point)

        def screenshot(self):
            return b"screenshot"

    events = []
    target = tmp_path / "screen.png"
    monkeypatch.setattr(cli, "connect", lambda *args: Mac())
    monkeypatch.setattr(cli.time, "sleep", lambda seconds: None)
    monkeypatch.setenv("MACVNC_PASSWORD", "secret")
    monkeypatch.setattr(sys, "argv", [
        "macvnc", "mac", "-u", "admin", "move:4,2", "click", f"capture:{target}",
    ])
    cli.main()
    assert events == [(4, 2), (4, 2), "closed"]
    assert target.read_bytes() == b"screenshot"


def test_idle_expiration_resets_after_active_commands(session):
    cli, _, closed, name = session
    check(cli("-u", "admin", "--idle-timeout", "1", password="secret"))
    assert not closed.wait(0.6)
    # This command runs past the old deadline and takes longer than the timeout.
    check(cli("pause:1.1"))
    assert not closed.wait(0.6)
    assert closed.wait(2)
    assert not (_session._directory() / f"{name}.sock").exists()
    result = cli("capture:expired.png")
    assert result.returncode == 2
    assert "give -u/--user" in result.stderr


def test_update_idle_timeout_and_disable_expiration(session):
    cli, _, closed, name = session
    check(cli("-u", "admin", "--idle-timeout", "1.5", password="secret"))
    check(cli("--idle-timeout", "0"))
    assert not closed.wait(1.7)
    check(cli("capture:no-expiration.png"))
    # Updating an existing session needs no credentials, and starts counting
    # after the command's final event delay, which exceeds this timeout.
    check(cli("--idle-timeout", "0.2"))
    assert closed.wait(2)
    assert not (_session._directory() / f"{name}.sock").exists()
