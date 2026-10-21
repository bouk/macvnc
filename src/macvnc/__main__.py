"""Command-line interface: run actions in a new or persistent session."""

import argparse
import math
import os
import sys
import time

from . import connect

DEFAULT_IDLE_TIMEOUT = 30 * 60

ACTIONS = """actions, run in order:
  type:TEXT       type TEXT
  password        type the password
  key:COMBO       press a key or combination: return, tab, backspace, cmd+space
  click[:X,Y]     left-click at framebuffer pixel X,Y, or where the pointer is
  rightclick[:X,Y]
                  right-click at X,Y, or where the pointer is
  move:X,Y        move the pointer to X,Y
  pause:SECONDS   wait
  capture:FILE    save a screenshot as PNG

example, log in at the login window:
  macvnc mac.local -u admin --password-file pw.txt password key:return

example, keep the connection open between commands:
  macvnc mac.local -u admin --password-file pw.txt --session work password key:return
  macvnc mac.local --session work capture:screen.png
  macvnc mac.local --session work --disconnect
"""


class Actions:
    """Run actions, retaining the pointer position for the next request."""

    def __init__(self, mac, password):
        self.mac = mac
        self.password = password
        self.pointer = (0, 0)

    def run(self, actions):
        for action in actions:
            name, _, arg = action.partition(":")
            if name in ("click", "rightclick", "move") and arg:
                x, y = arg.split(",")
                self.pointer = (int(x), int(y))
            if name == "type":
                self.mac.type(arg)
            elif name == "password":
                self.mac.type(self.password)
            elif name == "key":
                self.mac.press(arg)
            elif name == "click":
                self.mac.click(*self.pointer)
            elif name == "rightclick":
                self.mac.click(*self.pointer, button=3)
            elif name == "move":
                self.mac.move(*self.pointer)
            elif name == "pause":
                time.sleep(float(arg))
            elif name == "capture":
                with open(arg, "wb") as f:
                    f.write(self.mac.screenshot())
            else:
                raise ValueError(f"unknown action: {action}")
        # Let the Mac read the last events before returning or disconnecting.
        time.sleep(0.5)


def _password(args, parser):
    if not args.user:
        parser.error("give -u/--user to start a connection")
    if args.password_file:
        with open(args.password_file) as f:
            return f.read().rstrip("\n")
    if "MACVNC_PASSWORD" in os.environ:
        return os.environ["MACVNC_PASSWORD"]
    parser.error("give --password-file or set MACVNC_PASSWORD")


def _idle_timeout(value):
    seconds = float(value)
    if not math.isfinite(seconds) or seconds < 0:
        raise argparse.ArgumentTypeError("idle timeout must be a finite, nonnegative number of seconds")
    return seconds


def main():
    parser = argparse.ArgumentParser(
        prog="macvnc",
        description="Control a Mac over Apple Screen Sharing.",
        epilog=ACTIONS,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("host")
    parser.add_argument("actions", nargs="*", metavar="action")
    parser.add_argument("-u", "--user", help="Mac account name (required for a new connection)")
    parser.add_argument("--password-file", help="file with the account password (default: $MACVNC_PASSWORD)")
    parser.add_argument("-p", "--port", type=int, default=5900)
    parser.add_argument("--session", help="keep and reuse a named background connection")
    parser.add_argument(
        "--idle-timeout", type=_idle_timeout, metavar="SECONDS",
        help="expire --session after inactivity (default: 1800 seconds; 0 disables); updates existing sessions",
    )
    parser.add_argument("--disconnect", action="store_true", help="close --session instead of running actions")
    args = parser.parse_intermixed_args()
    if args.disconnect and (not args.session or args.actions):
        parser.error("--disconnect requires --session and no actions")
    if args.idle_timeout is not None and (args.session is None or args.disconnect):
        parser.error("--idle-timeout requires --session without --disconnect")
    if not args.actions and args.session is None:
        parser.error("give at least one action or --session")

    try:
        if args.session is not None:
            from ._session import run

            run(args, lambda: _password(args, parser))
        else:
            password = _password(args, parser)
            with connect(args.host, args.user, password, args.port) as mac:
                Actions(mac, password).run(args.actions)
    except (OSError, ValueError, KeyError) as exc:
        parser.exit(1, f"macvnc: {exc}\n")


if __name__ == "__main__":
    sys.exit(main())
