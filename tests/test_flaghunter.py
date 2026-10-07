import base64
import os
import struct
import tempfile

from cryptsmith import xor

from flaghunter import pcaphunt, solver


def _write(path, data: bytes):
    with open(path, "wb") as f:
        f.write(data)


def _build_pcap(path, packets):
    def frame(src_ip, dst_ip, sport, dport, seq, payload):
        eth = b"\x00" * 12 + struct.pack("!H", 0x0800)
        total = 20 + 20 + len(payload)
        ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, 0, 0, 64, 6, 0,
                         bytes(map(int, src_ip.split("."))), bytes(map(int, dst_ip.split("."))))
        tcp = struct.pack("!HHIIHHHH", sport, dport, seq, 0, 0x5000, 0, 0, 0)
        return eth + ip + tcp + payload

    with open(path, "wb") as f:
        f.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for (s, sp, d, dp, seq, payload) in packets:
            p = frame(s, d, sp, dp, seq, payload)
            f.write(struct.pack("<IIII", 0, 0, len(p), len(p)) + p)


def test_solver_breaks_single_byte_xor():
    pt = b"the secret enrollment key is hidden right here in this message"
    ct = xor.xor_bytes(pt, b"\x99")
    with tempfile.NamedTemporaryFile(delete=False) as t:
        _write(t.name, ct)
        path = t.name
    try:
        report = solver.solve_file(path)
        assert any(f.method == "xor" and "hidden right here" in f.plaintext
                   for f in report.findings)
    finally:
        os.unlink(path)


def test_solver_peels_base64_layers():
    inner = base64.b64encode(b"flag{layered_encoding_win}").decode()
    outer = base64.b64encode(inner.encode()).decode()
    with tempfile.NamedTemporaryFile(delete=False, suffix=".txt") as t:
        _write(t.name, outer.encode())
        path = t.name
    try:
        report = solver.solve_file(path)
        assert any(f.method == "encoding" and "flag{layered_encoding_win}" in f.plaintext
                   for f in report.findings)
    finally:
        os.unlink(path)


def test_pcap_hunt_finds_plaintext_enrollment_key():
    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as t:
        path = t.name
    try:
        _build_pcap(path, [
            ("10.0.0.5", 1337, "10.0.0.9", 9000, 1, b"HELLO distsrv v1"),
            ("10.0.0.5", 1337, "10.0.0.9", 9000, 17, b"ENROLL ZxCvBnMkLjHg"),
            ("10.0.0.9", 9000, "10.0.0.5", 1337, 1, b"OK enrolled"),
        ])
        report = pcaphunt.hunt_pcap(path)
        assert report.streams == 1
        tokens = [f.value for f in report.findings if f.kind == "token"]
        assert "ZxCvBnMkLjHg" in tokens
    finally:
        os.unlink(path)


def test_pcap_hunt_breaks_xor_obfuscated_key():
    key = b"QwErTyUiOpAs"
    blob = xor.xor_bytes(b"enrollment key follows: " + key + b" end", b"\x42")
    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as t:
        path = t.name
    try:
        _build_pcap(path, [
            ("10.0.0.5", 1337, "10.0.0.9", 9000, 1, b"\x01\x02hello"),
            ("10.0.0.9", 9000, "10.0.0.5", 1337, 1, blob),
        ])
        report = pcaphunt.hunt_pcap(path)
        values = [f.value for f in report.findings]
        assert any("QwErTyUiOpAs" in v for v in values), values
        kinds = [f.kind for f in report.findings if "QwErTyUiOpAs" in f.value]
        assert "xor-token" in kinds
    finally:
        os.unlink(path)


def test_pcap_hunt_custom_pattern():
    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as t:
        path = t.name
    try:
        _build_pcap(path, [
            ("10.0.0.5", 1337, "10.0.0.9", 9000, 1, b"here is FLAG{you_found_me} bye"),
        ])
        report = pcaphunt.hunt_pcap(path, pattern=r"FLAG\{[^}]+\}")
        assert any(f.value == "FLAG{you_found_me}" for f in report.findings)
    finally:
        os.unlink(path)
