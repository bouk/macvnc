import hashlib
import socket
import struct
import threading
import time
import zlib

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

import macvnc

# RFC 5054's 1024-bit group; macOS sends the 4096-bit one.
PRIME = int(
    "EEAF0AB9ADB38DD69C33F80AFA8FC5E86072618775FF3C0B9EA2314C9C256576D674DF7496"
    "EA81D3383B4813D692C6E0E0D5D8E250B98BE48E495C1D6089DAD15DC7D7B46154D6B6CE8E"
    "F4AD69B15D4982559B297BCF1885C529F566660E57EC68EDBC3C05726CC02FD4CBF4976EAA"
    "9AFD5138FE8376435B9FC61D2FC0EB06E3",
    16,
)
KEY_LEN = 128


def recv_exact(sock, n):
    data = b""
    while len(data) < n:
        data += sock.recv(n - len(data))
    return data


def fake_mac(listener, received):
    """Speak the server side of the handshake and record what the client sends."""
    conn, _ = listener.accept()
    conn.sendall(b"RFB 003.889\n")
    received["version"] = recv_exact(conn, 12)
    conn.sendall(bytes([4, 30, 33, 36, 35]))
    received["security"] = recv_exact(conn, 1)
    private = 0x1234567890ABCDEF
    conn.sendall(
        struct.pack(">HH", 2, KEY_LEN)
        + PRIME.to_bytes(KEY_LEN, "big")
        + pow(2, private, PRIME).to_bytes(KEY_LEN, "big")
    )
    encrypted = recv_exact(conn, 128)
    client_public = int.from_bytes(recv_exact(conn, KEY_LEN), "big")
    key = hashlib.md5(pow(client_public, private, PRIME).to_bytes(KEY_LEN, "big")).digest()
    decryptor = Cipher(algorithms.AES(key), modes.ECB()).decryptor()
    credentials = decryptor.update(encrypted) + decryptor.finalize()
    received["user"] = credentials[:64].split(b"\0")[0]
    received["password"] = credentials[64:].split(b"\0")[0]
    conn.sendall(struct.pack(">I", 0))
    received["client_init"] = recv_exact(conn, 1)
    conn.sendall(struct.pack(">HH", 4, 2) + bytes(16) + struct.pack(">I", 3) + b"mac")
    received["set_pixel_format"] = recv_exact(conn, 20)
    received["set_encodings"] = recv_exact(conn, 8)
    received["set_mode"] = recv_exact(conn, 4)
    received["key"] = recv_exact(conn, 8)
    received["key_at"] = time.monotonic()
    received["update_request"] = recv_exact(conn, 10)
    pixels = bytes([0, 0, 255, 0] * 4 + [255, 0, 0, 0] * 4)  # BGRX: red row, blue row
    conn.sendall(bytes([0x14, 0]) + struct.pack(">H", 4) + bytes(4))  # MiscStatus first
    conn.sendall(struct.pack(">BxHHHHHi", 0, 1, 0, 0, 4, 2, 0) + pixels)
    conn.close()


def test_session():
    listener = socket.create_server(("127.0.0.1", 0))
    received = {}
    server = threading.Thread(target=fake_mac, args=(listener, received))
    server.start()
    with macvnc.connect("127.0.0.1", "administrator", "hunter2", port=listener.getsockname()[1]) as mac:
        connected_at = time.monotonic()
        mac.key_event(macvnc.keysym("a"), True)
        png = mac.screenshot()
    server.join()

    assert received["version"] == b"RFB 003.008\n"
    assert received["security"] == bytes([30])
    assert (received["user"], received["password"]) == (b"administrator", b"hunter2")
    assert received["set_mode"] == b"\x0a\x00\x00\x01"
    assert received["key"] == struct.pack(">BBxxI", 4, 1, ord("a"))
    assert received["key_at"] - connected_at >= 2.0
    assert received["update_request"] == struct.pack(">BBHHHH", 3, 0, 0, 0, 4, 2)

    width, height = struct.unpack(">II", png[16:24])
    assert (width, height) == (4, 2)
    idat = png[png.index(b"IDAT") + 4 :]
    rows = zlib.decompressobj().decompress(idat)
    assert rows == b"\0" + bytes([255, 0, 0] * 4) + b"\0" + bytes([0, 0, 255] * 4)


def test_keysym():
    assert macvnc.keysym("a") == 0x61
    assert macvnc.keysym("\n") == 0xFF0D
    assert macvnc.keysym("é") == 0xE9
    assert macvnc.keysym("€") == 0x010020AC
