"""Private local IPC for a CLI session that owns one VNC connection."""

import fcntl
import json
import os
from pathlib import Path
import re
import socket
import stat
import subprocess
import sys
import threading
import time

from . import connect
from .__main__ import Actions, DEFAULT_IDLE_TIMEOUT


class SessionError(ValueError):
    pass


def _directory():
    # A short path also fits macOS's 104-byte Unix socket path limit.
    directory = Path("/tmp") / f"macvnc-{os.getuid()}"
    directory.mkdir(mode=0o700, exist_ok=True)
    info = directory.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise SessionError(f"session directory must be owned by you with mode 0700: {directory}")
    return directory


def _read(stream):
    # Each request is one JSON line; bound memory use for incomplete requests.
    line = stream.readline(1024 * 1024 + 1)
    if not line or len(line) > 1024 * 1024 or not line.endswith(b"\n"):
        raise SessionError("incomplete or oversized session message")
    return json.loads(line)


def _write(stream, message):
    stream.write(json.dumps(message).encode() + b"\n")
    stream.flush()


def _open(path):
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        sock.connect(str(path))
    except BaseException:
        sock.close()
        raise
    return sock


def _start(path, args, password):
    # Credentials travel through a pipe, never command-line arguments or files.
    process = subprocess.Popen(
        [sys.executable, "-m", "macvnc._session"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
        env={key: value for key, value in os.environ.items() if key != "MACVNC_PASSWORD"},
    )
    try:
        _write(process.stdin, {
            "path": str(path), "host": args.host, "port": args.port,
            "user": args.user, "password": password,
            "idle_timeout": DEFAULT_IDLE_TIMEOUT if args.idle_timeout is None else args.idle_timeout,
        })
        process.stdin.close()
        response = _read(process.stdout)
        if "error" in response:
            raise SessionError(response["error"])
    except BaseException:
        process.terminate()
        process.wait()
        raise
    finally:
        process.stdin.close()
        process.stdout.close()
    # Reap the child if this CLI is embedded in a longer-lived Python process.
    # The daemon thread lets a normal CLI invocation exit immediately.
    threading.Thread(target=process.wait, daemon=True).start()


def run(args, get_password):
    if not re.fullmatch(r"[A-Za-z0-9_-][A-Za-z0-9_.-]{0,39}", args.session):
        raise SessionError("session name must be 1-40 letters, digits, underscores, hyphens or dots")
    directory = _directory()
    path = directory / f"{args.session}.sock"
    # Serialize startup so simultaneous invocations cannot log in twice.
    with open(directory / f"{args.session}.lock", "a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        try:
            sock = _open(path)
        except (FileNotFoundError, ConnectionRefusedError):
            if args.disconnect:
                raise SessionError(f"session {args.session!r} is not running") from None
            password = get_password()
            path.unlink(missing_ok=True)
            _start(path, args, password)
            sock = _open(path)
    with sock, sock.makefile("rwb") as stream:
        # Resolve paths in the caller, since later commands may use another cwd.
        actions = [
            "capture:" + os.path.abspath(action.partition(":")[2]) if action.startswith("capture:") else action
            for action in args.actions
        ]
        _write(stream, {
            "host": args.host, "port": args.port, "user": args.user,
            "actions": actions, "disconnect": args.disconnect,
            "idle_timeout": args.idle_timeout,
        })
        response = _read(stream)
        if "error" in response:
            raise SessionError(response["error"])


def serve(config, ready):
    path = Path(config["path"])
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
        listener.bind(str(path))
        bound = True
        try:
            os.chmod(path, 0o600)
            listener.listen()
            with connect(config["host"], config["user"], config["password"], config["port"]) as mac:
                actions = Actions(mac, config["password"])
                _write(ready, {})
                ready.close()
                idle_timeout = config.get("idle_timeout", DEFAULT_IDLE_TIMEOUT)
                last_active = time.monotonic()
                while True:
                    if idle_timeout:
                        remaining = last_active + idle_timeout - time.monotonic()
                        if remaining <= 0:
                            path.unlink(missing_ok=True)
                            bound = False
                            return
                        # Bound the socket wait even for very large finite timeouts.
                        listener.settimeout(min(remaining, 3600))
                    else:
                        listener.settimeout(None)
                    try:
                        conn, _ = listener.accept()
                    except TimeoutError:
                        continue
                    with conn, conn.makefile("rwb") as stream:
                        conn.settimeout(30)
                        disconnect = False
                        valid_request = False
                        try:
                            request = _read(stream)
                            if (request["host"], request["port"]) != (config["host"], config["port"]):
                                raise SessionError("session is connected to a different host or port")
                            if request["user"] not in (None, config["user"]):
                                raise SessionError("session is connected with a different account")
                            valid_request = True
                            if request.get("idle_timeout") is not None:
                                idle_timeout = request["idle_timeout"]
                            disconnect = request["disconnect"]
                            if disconnect:
                                mac.close()
                                path.unlink(missing_ok=True)
                                bound = False
                            else:
                                actions.run(request["actions"])
                            response = {}
                        except Exception as exc:
                            response = {"error": str(exc)}
                        # A caller may exit while its actions are still running.
                        try:
                            _write(stream, response)
                        except OSError:
                            pass
                        if disconnect:
                            return
                        if valid_request:
                            # Active commands can exceed the timeout. Start the
                            # idle period after they finish, even on an action error.
                            last_active = time.monotonic()
        finally:
            if bound:
                path.unlink(missing_ok=True)


def main():
    try:
        config = _read(sys.stdin.buffer)
        sys.stdin.close()
        serve(config, sys.stdout.buffer)
    except Exception as exc:
        if not sys.stdout.closed:
            _write(sys.stdout.buffer, {"error": str(exc)})
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
