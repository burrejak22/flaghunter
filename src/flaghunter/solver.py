"""Attack battery for crypto challenge files.

Reads a challenge blob and runs every cheap attack, ranking results so the
real answer floats to the top.
"""
from dataclasses import dataclass, field

from cryptsmith import analysis, classical, encoding, hashid, xor


@dataclass
class Finding:
    method: str
    detail: str
    plaintext: str
    score: float


@dataclass
class SolveReport:
    source: str
    findings: list[Finding] = field(default_factory=list)

    def top(self, n: int = 10) -> list[Finding]:
        return sorted(self.findings, key=lambda f: -f.score)[:n]


def _printable(data: bytes) -> str | None:
    try:
        text = data.decode("utf-8")
    except Exception:
        try:
            text = data.decode("latin1")
        except Exception:
            return None
    if not text or sum(32 <= ord(c) < 127 or c in "\n\r\t" for c in text) / len(text) < 0.85:
        return None
    return text


def analyze_blob(data: bytes, max_findings: int = 25) -> list[Finding]:
    """Run the full battery against one blob of bytes."""
    findings: list[Finding] = []

    def add(method: str, detail: str, raw: bytes):
        text = _printable(raw)
        if text is None:
            return
        score = analysis.english_score(text)
        if score == float("-inf"):
            return
        findings.append(Finding(method, detail, text.strip()[:500], score))

    # 1. layered encodings
    for chain, decoded in encoding.smart_decode(data):
        add("encoding", f"decoded via {chain}", decoded)

    text = _printable(data)

    # 2. hash id on standalone hex digests
    if text:
        for token in text.split():
            names = hashid.identify(token.strip())
            if names:
                findings.append(Finding("hashid", f"{token.strip()[:64]} looks like {', '.join(names)}",
                                        token.strip()[:200], 0.0))

    # 3. single byte xor (worth trying on almost anything)
    if len(data) >= 8:
        for key, pt, score in xor.single_byte_xor_break(data, top=2):
            if score > 5:
                findings.append(Finding("xor", f"single byte key 0x{key:02x}", pt.decode("latin1").strip()[:500], score))

    # 4. repeating key xor on longer blobs
    if len(data) >= 60:
        try:
            for key, pt, score in xor.repeating_key_xor_break(data)[:2]:
                if score > 20:
                    findings.append(Finding("xor", f"repeating key {key!r}", pt.decode("latin1").strip()[:500], score))
        except Exception:
            pass

    # 5. classical ciphers on texty input
    if text and sum(c.isalpha() for c in text) / max(len(text), 1) > 0.6 and len(text) >= 20:
        for shift, pt, score in classical.caesar_bruteforce(text, top=1):
            if score > 5:
                findings.append(Finding("caesar", f"shift {shift}", pt.strip()[:500], score))
        for a, b, pt, score in classical.affine_bruteforce(text, top=1):
            if score > 10:
                findings.append(Finding("affine", f"a={a} b={b}", pt.strip()[:500], score))

    # 6. notes on randomness
    entropy = analysis.shannon_entropy(data)
    if entropy > 7.5 and len(data) >= 32:
        findings.append(Finding("note", f"high entropy ({entropy:.2f} bits/byte), likely encrypted or compressed",
                                "", -100.0))

    findings.sort(key=lambda f: -f.score)
    return findings[:max_findings]


def solve_file(path: str) -> SolveReport:
    with open(path, "rb") as f:
        data = f.read()
    return SolveReport(source=path, findings=analyze_blob(data))


def render_markdown(report: SolveReport) -> str:
    lines = [f"# flaghunter solve report", "", f"source: `{report.source}`", ""]
    if not report.findings:
        lines.append("no promising findings. the blob resisted the battery.")
        return "\n".join(lines)
    lines.append(f"## top findings ({len(report.findings)})")
    lines.append("")
    for i, f in enumerate(report.top(), 1):
        lines.append(f"### {i}. {f.method} (score {f.score:.1f})")
        lines.append(f"*{f.detail}*")
        if f.plaintext:
            lines.append("```")
            lines.append(f.plaintext)
            lines.append("```")
        lines.append("")
    return "\n".join(lines)
