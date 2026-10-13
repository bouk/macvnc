"""Command-line interface: run a sequence of actions in one session."""

import argparse
import os
import sys
import time

from . import connect

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
"""


def main():
    parser = argparse.ArgumentParser(
        prog="macvnc",
        description="Control a Mac over Apple Screen Sharing.",
        epilog=ACTIONS,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("host")
    parser.add_argument("actions", nargs="+", metavar="action")
    parser.add_argument("-u", "--user", required=True, help="Mac account name")
    parser.add_argument("--password-file", help="file with the account password (default: $MACVNC_PASSWORD)")
    parser.add_argument("-p", "--port", type=int, default=5900)
    args = parser.parse_args()

    if args.password_file:
        with open(args.password_file) as f:
            password = f.read().rstrip("\n")
    elif "MACVNC_PASSWORD" in os.environ:
        password = os.environ["MACVNC_PASSWORD"]
    else:
        parser.error("give --password-file or set MACVNC_PASSWORD")

    with connect(args.host, args.user, password, args.port) as mac:
        # Where the last move or click put the pointer.
        pointer = (0, 0)
        for action in args.actions:
            name, _, arg = action.partition(":")
            if name in ("click", "rightclick", "move") and arg:
                x, y = arg.split(",")
                pointer = (int(x), int(y))
            if name == "type":
                mac.type(arg)
            elif name == "password":
                mac.type(password)
            elif name == "key":
                mac.press(arg)
            elif name == "click":
                mac.click(*pointer)
            elif name == "rightclick":
                mac.click(*pointer, button=3)
            elif name == "move":
                mac.move(*pointer)
            elif name == "pause":
                time.sleep(float(arg))
            elif name == "capture":
                with open(arg, "wb") as f:
                    f.write(mac.screenshot())
            else:
                parser.error(f"unknown action: {action}")
        # Let the Mac read the last events before the connection closes.
        time.sleep(0.5)


if __name__ == "__main__":
    sys.exit(main())
