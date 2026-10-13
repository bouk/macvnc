# macvnc

Control a Mac over Apple Screen Sharing (VNC) from Python or the command line:
type, click and take screenshots, also at the login window and the lock screen.

Generic VNC clients such as vncdotool connect to macOS Screen Sharing, but
macOS ignores their keyboard and mouse input. macvnc speaks the parts of
Apple's protocol that give a viewer control.

## Install

```sh
uv tool install git+https://github.com/bouk/macvnc
```

## Command line

```sh
# Log in at the login window, or unlock the lock screen.
macvnc mac.local -u administrator --password-file pw.txt password key:return

# Take a screenshot.
macvnc mac.local -u administrator --password-file pw.txt capture:screen.png
```

The password comes from `--password-file` or `$MACVNC_PASSWORD`, never from
the command line. The actions run in order in one session:

| Action | |
|---|---|
| `type:TEXT` | type text |
| `password` | type the password |
| `key:COMBO` | press a key or combination, for example `return`, `tab`, `backspace`, `cmd+space` |
| `click[:X,Y]`, `rightclick[:X,Y]` | click at a framebuffer pixel, or where the last `move` or click put the pointer |
| `move:X,Y` | move the pointer |
| `pause:SECONDS` | wait |
| `capture:FILE` | save a screenshot as PNG |

Coordinates are framebuffer pixels: on a Retina display, twice the point
coordinates.

A login from the login window stays logged in after macvnc disconnects. A
screen unlocked from the lock screen locks again when the session that
unlocked it ends, so do the work that needs the unlocked screen in the same
session.

## Python

```python
import macvnc

with macvnc.connect("mac.local", "administrator", password) as mac:
    mac.type(password)
    mac.press("return")
    mac.click(400, 300)
    open("screen.png", "wb").write(mac.screenshot())
```

## Requirements on the Mac

Turn on System Settings > General > Sharing > Screen Sharing. The account must
be allowed to control the screen. macvnc logs in with the account name and
password (Apple's security type 30).

## The protocol

Measured on macOS 27.0.1. The main reference for Apple's RFB extensions is the
[remotex documentation](https://github.com/andrewtheguy/remotex/blob/main/docs/apple-vnc-889.md).

1. **Login.** Security type 30 is a Diffie-Hellman exchange. The Mac sends a
   `u16` generator, a `u16` key length, the prime and its public key. The
   viewer sends 128 bytes of credentials (account name at byte 0, password at
   byte 64, each NUL-terminated, random filler), encrypted with AES-128-ECB
   under the MD5 of the shared secret. Then it sends its own public key.
2. **Control.** macOS starts every viewer in observe mode and discards its
   input. The viewer asks for control with Apple's `SetMode` message:
   `0a 00 00 01`. Apple's Screen Sharing app sends it at the start of each
   session. Generic VNC clients do not, so macOS ignores them.
3. **The key guard.** `screensharingd` drops key-down events for two seconds
   after its agent reports the cursor position, which it does when a session
   starts. Key-up events pass, so a client that types at once loses each
   character. The daemon logs `ignore key event`, or `viewer not allowed to
   post key` for Apple's encrypted input event. macvnc waits until the two
   seconds are over before the first key-down.

Things that are not needed, although Apple's viewer sends them: RFB version
`003.889`, the extended ServerInit, `ViewerInfo`, the encrypted record layer,
encrypted input events and `SetKeyboardInputSource`. A secure text field such
as the login password accepts plain RFB key events.

The Mac swaps the RFB mask bits for the middle and right buttons on protocol
versions other than 003.888 and 003.889. macvnc uses 003.008, so the standard
RFB mask works.
