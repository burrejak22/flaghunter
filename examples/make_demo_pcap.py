"""Generate a demo pcap mimicking the joint task force scenario.

A distribution server speaks a custom binary protocol. The client must present
a 12 character alpha enrollment key, but it is xor obfuscated on the wire.
flaghunter should recover it with zero prior knowledge.
"""
import struct

ENROLLMENT_KEY = b"KxQwErTyUiOp"  # 12 char alpha
XOR_BYTE = 0x42


def xor(data: bytes, k: int) -> bytes:
    return bytes(b ^ k for b in data)


def frame(src_ip, dst_ip, sport, dport, seq, payload):
    eth = b"\xaa\xbb\xcc\xdd\xee\xff" + b"\x11\x22\x33\x44\x55\x66" + struct.pack("!H", 0x0800)
    total = 20 + 20 + len(payload)
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, 0x1234, 0, 64, 6, 0,
                     bytes(map(int, src_ip.split("."))), bytes(map(int, dst_ip.split("."))))
    tcp = struct.pack("!HHIIHHHH", sport, dport, seq, 0, 0x5018, 0x10, 8192, 0)
    return eth + ip + tcp + payload


def main(path="demo.pcap"):
    c, s = "10.0.0.5", "10.0.0.9"
    pkts = [
        # client hello, plaintext
        (c, 1337, s, 9000, 1000, b"\x01\x00HELLO distsrv v1.3"),
        # server challenge, custom framing + xor obfuscation
        (s, 9000, c, 1337, 5000, b"\x02\x10" + xor(b"CHALLENGE:9f8a1c", XOR_BYTE)),
        # client answers with the enrollment key, xor obfuscated
        (c, 1337, s, 9000, 1021, b"\x03\x10" + xor(b"ENROLL:" + ENROLLMENT_KEY, XOR_BYTE)),
        # server accepts, hands over a session blob with a base64 layer inside
        (s, 9000, c, 1337, 5024, b"\x04\x00OK session Zm9vYmFyCg== granted"),
        # client requests the payload
        (c, 1337, s, 9000, 1042, b"\x05\x00GET /payload"),
        # server sends payload, xor obfuscated with a different byte
        (s, 9000, c, 1337, 5052, xor(b"PAYLOAD: the eagle has landed, exfil complete", 0x5A)),
    ]
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for src, sp, dst, dp, seq, payload in pkts:
            p = frame(src, dst, sp, dp, seq, payload)
            f.write(struct.pack("<IIII", 0, 0, len(p), len(p)) + p)
    print(f"wrote {path} with enrollment key {ENROLLMENT_KEY.decode()!r} hidden on the wire")


if __name__ == "__main__":
    main()
