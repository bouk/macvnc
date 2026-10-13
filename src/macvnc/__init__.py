"""Control a Mac over Apple Screen Sharing (VNC) from Python.

macOS Screen Sharing speaks RFB with Apple extensions. A generic VNC client
can watch the screen, but macOS ignores its keyboard and mouse. Two things are
needed to control the Mac, for example to type the password at the login
window:

- ``SetMode(control)`` (message ``0x0a``). macOS starts each viewer in observe
  mode, and only Apple's viewer asks for control.
- A wait of two seconds before the first key-down. ``screensharingd`` drops
  key-down events for two seconds after the session starts.

This module implements the Apple Diffie-Hellman login (security type 30) with
the Mac account name and password, then ``SetMode(control)``, keyboard and
pointer events, and screenshots in Raw encoding.
"""

import hashlib
import secrets
import socket
import struct
import time
import zlib

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

__all__ = ["KEYS", "MODIFIERS", "Client", "connect", "keysym"]

# Apple's Diffie-Hellman login, which carries a Mac account name and password.
SECURITY_APPLE_DH = 30
# screensharingd drops key-down events for two seconds after a session starts.
KEY_GUARD_SECONDS = 2.1

KEYS = {
    "return": 0xFF0D,
    "enter": 0xFF0D,
    "tab": 0xFF09,
    "escape": 0xFF1B,
    "esc": 0xFF1B,
    "backspace": 0xFF08,
    "delete": 0xFFFF,
    "space": 0x20,
    "left": 0xFF51,
    "up": 0xFF52,
    "right": 0xFF53,
    "down": 0xFF54,
    "home": 0xFF50,
    "end": 0xFF57,
    "pageup": 0xFF55,
    "pagedown": 0xFF56,
    **{f"f{n}": 0xFFBD + n for n in range(1, 13)},
}

# The Mac maps Alt and Super to Command, and Meta to Option.
MODIFIERS = {
    "shift": 0xFFE1,
    "ctrl": 0xFFE3,
    "control": 0xFFE3,
    "option": 0xFFE7,
    "alt": 0xFFE7,
    "cmd": 0xFFE9,
    "command": 0xFFE9,
}


def keysym(char):
    """The X11 keysym for one character."""
    code = ord(char)
    if char == "\n":
        return KEYS["return"]
    if char == "\t":
        return KEYS["tab"]
    if 0x20 <= code <= 0x7E or 0xA0 <= code <= 0xFF:
        return code
    return 0x01000000 | code


def _recv_exact(sock, n):
    data = bytearray()
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise ConnectionError("the Mac closed the connection")
        data += chunk
    return bytes(data)


def _aes_ecb_encrypt(key, data):
    encryptor = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    return encryptor.update(data) + encryptor.finalize()


def _png(width, height, rgb):
    """Encode 8-bit RGB pixels as a PNG."""

    def chunk(kind, body):
        return struct.pack(">I", len(body)) + kind + body + struct.pack(">I", zlib.crc32(kind + body))

    stride = width * 3
    rows = b"".join(b"\0" + rgb[y * stride : (y + 1) * stride] for y in range(height))
    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0))
        + chunk(b"IDAT", zlib.compress(rows, 6))
        + chunk(b"IEND", b"")
    )


class Client:
    """A controlling Screen Sharing session. Coordinates are framebuffer
    pixels, which are twice the point coordinates on a Retina display."""

    def __init__(self, host, username, password, port=5900, timeout=30):
        self.sock = socket.create_connection((host, port), timeout=timeout)
        version = _recv_exact(self.sock, 12)
        if not version.startswith(b"RFB 003."):
            raise ConnectionError(f"not an RFB server: {version!r}")
        self.sock.sendall(b"RFB 003.008\n")
        types = _recv_exact(self.sock, _recv_exact(self.sock, 1)[0])
        if SECURITY_APPLE_DH not in types:
            raise ConnectionError(f"the server does not offer Apple's login (security types {list(types)})")
        self.sock.sendall(bytes([SECURITY_APPLE_DH]))
        self._login(username, password)
        self.sock.sendall(b"\x01")  # ClientInit: shared
        self.width, self.height = struct.unpack(">HH", _recv_exact(self.sock, 4))
        _recv_exact(self.sock, 16)  # pixel format
        self.name = _recv_exact(self.sock, struct.unpack(">I", _recv_exact(self.sock, 4))[0])
        # SetPixelFormat: 32 bits, little-endian, red at bit 16, green at 8, blue at 0.
        self.sock.sendall(b"\x00\x00\x00\x00" + struct.pack(">BBBBHHHBBB3x", 32, 24, 0, 1, 255, 255, 255, 16, 8, 0))
        self.sock.sendall(b"\x02\x00" + struct.pack(">Hi", 1, 0))  # SetEncodings: Raw
        self.sock.sendall(b"\x0a\x00\x00\x01")  # SetMode(control)
        self._keys_allowed_at = time.monotonic() + KEY_GUARD_SECONDS

    def _login(self, username, password):
        """Apple Diffie-Hellman login: the server sends a generator, a key
        length, a prime and its public key. The client sends its credentials,
        AES-128-ECB encrypted under MD5 of the shared secret, and its public key."""
        generator, key_len = struct.unpack(">HH", _recv_exact(self.sock, 4))
        prime = int.from_bytes(_recv_exact(self.sock, key_len), "big")
        peer = int.from_bytes(_recv_exact(self.sock, key_len), "big")
        if not 1 < peer < prime - 1:
            raise ConnectionError("the server sent an invalid Diffie-Hellman public key")
        private = int.from_bytes(secrets.token_bytes(2 * key_len), "big")
        public = pow(generator, private, prime).to_bytes(key_len, "big")
        shared = pow(peer, private, prime).to_bytes(key_len, "big")
        credentials = bytearray(secrets.token_bytes(128))
        for offset, field in ((0, username), (64, password)):
            raw = field.encode()
            if len(raw) >= 64:
                raise ValueError("the user name and password must each be shorter than 64 bytes")
            credentials[offset : offset + len(raw) + 1] = raw + b"\0"
        self.sock.sendall(_aes_ecb_encrypt(hashlib.md5(shared).digest(), bytes(credentials)) + public)
        (result,) = struct.unpack(">I", _recv_exact(self.sock, 4))
        if result != 0:
            raise PermissionError("the Mac refused the login")

    def close(self):
        self.sock.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    def key_event(self, keysym, down):
        if down:
            time.sleep(max(0.0, self._keys_allowed_at - time.monotonic()))
        self.sock.sendall(struct.pack(">BBxxI", 4, int(down), keysym))

    def press(self, combo):
        """Press and release a key or a combination such as ``cmd+space``."""
        *mods, key = combo.lower().split("+")
        syms = [MODIFIERS[m] for m in mods]
        syms.append(KEYS[key] if key in KEYS else keysym(key))
        for sym in syms:
            self.key_event(sym, True)
            time.sleep(0.02)
        for sym in reversed(syms):
            self.key_event(sym, False)
            time.sleep(0.02)

    def type(self, text, delay=0.02):
        """Type text. Uppercase letters and symbols bring their own Shift."""
        for char in text:
            sym = keysym(char)
            self.key_event(sym, True)
            time.sleep(delay)
            self.key_event(sym, False)
            time.sleep(delay)

    def pointer_event(self, x, y, buttons=0):
        """Put the pointer at x, y with the buttons in the RFB mask held:
        bit 0 left, bit 1 middle, bit 2 right."""
        self.sock.sendall(struct.pack(">BBHH", 5, buttons, x, y))

    def move(self, x, y):
        self.pointer_event(x, y)

    def click(self, x, y, button=1):
        """Click at x, y. Button 1 is left, 2 middle, 3 right."""
        self.pointer_event(x, y)
        self.pointer_event(x, y, 1 << (button - 1))
        time.sleep(0.05)
        self.pointer_event(x, y)

    def screenshot(self):
        """Request the whole screen and return it as PNG bytes."""
        self.sock.sendall(struct.pack(">BBHHHH", 3, 0, 0, 0, self.width, self.height))
        pixels = bytearray(self.width * self.height * 3)
        while True:
            (kind,) = _recv_exact(self.sock, 1)
            if kind == 0:  # FramebufferUpdate
                (rects,) = struct.unpack(">xH", _recv_exact(self.sock, 3))
                for _ in range(rects):
                    x, y, w, h, encoding = struct.unpack(">HHHHi", _recv_exact(self.sock, 12))
                    if encoding != 0:
                        raise ConnectionError(f"unexpected encoding {encoding}")
                    data = _recv_exact(self.sock, w * h * 4)
                    for row in range(h):
                        src = data[row * w * 4 : (row + 1) * w * 4]
                        start = ((y + row) * self.width + x) * 3
                        line = pixels[start : start + w * 3]
                        line[0::3], line[1::3], line[2::3] = src[2::4], src[1::4], src[0::4]
                        pixels[start : start + w * 3] = line
                return _png(self.width, self.height, bytes(pixels))
            elif kind == 2:  # Bell
                continue
            elif kind == 3:  # ServerCutText
                (length,) = struct.unpack(">3xI", _recv_exact(self.sock, 7))
                _recv_exact(self.sock, length)
            elif kind == 0x14:  # Apple MiscStatus
                (length,) = struct.unpack(">xH", _recv_exact(self.sock, 3))
                _recv_exact(self.sock, length)
            else:
                raise ConnectionError(f"unexpected server message {kind:#x}")


def connect(host, username, password, port=5900, timeout=30):
    """Open a controlling session. Use it as a context manager."""
    return Client(host, username, password, port, timeout)
