"""Pcap hunting: reassemble streams, find tokens, break obfuscated blobs.

The main event for captures with custom protocols and hidden keys, like a
distribution server checking a 12 character alpha enrollment key.
"""
import json
from dataclasses import dataclass, field

from cryptsmith import analysis, pcap, xor
from cryptsmith import encoding as enc

from .solver import analyze_blob


@dataclass
class StreamFinding:
    stream: str
    kind: str
    detail: str
    value: str
    score: float = 0.0


@dataclass
class PcapReport:
    source: str
    streams: int
    packets: int
    findings: list[StreamFinding] = field(default_factory=list)


def _summarize_stream(s: pcap.TCPStream) -> dict:
    return {
        "a_to_b_bytes": len(s.a_to_b),
        "b_to_a_bytes": len(s.b_to_a),
        "a_to_b_entropy": round(analysis.shannon_entropy(s.a_to_b), 2) if s.a_to_b else 0.0,
        "b_to_a_entropy": round(analysis.shannon_entropy(s.b_to_a), 2) if s.b_to_a else 0.0,
    }


# words that suggest the decode is real protocol or challenge text, not luck
_CONTEXT_KEYWORDS = {
    "enroll", "key", "flag", "auth", "login", "password", "passwd", "token",
    "secret", "challenge", "session", "crypto", "decrypt", "encrypt", "admin",
    "server", "client", "hello", "welcome", "granted", "denied", "payload",
}


def _context_score(data: bytes) -> float:
    """Score a decode context, tolerant of binary framing.

    Plain english scoring plus a bonus when the context contains security
    flavored words, which is a strong hint the xor key is right.
    """
    text = "".join(chr(b) for b in data if 32 <= b < 127)
    if len(text) < 8:
        return float("-inf")
    score = analysis.english_score(text)
    low = text.lower()
    if any(w in low for w in _CONTEXT_KEYWORDS):
        score += 50.0
    return score


def hunt_pcap(path: str, key_len: int = 12, pattern: str | None = None,
              min_blob: int = 16) -> PcapReport:
    """Analyze a pcap: token hunt plus attack battery on suspicious blobs."""
    reader = pcap.PcapReader(path)
    packets = sum(1 for _ in reader.packets())
    streams = pcap.reassemble_streams(pcap.PcapReader(path))
    report = PcapReport(source=path, streams=len(streams), packets=packets)

    token_hunter = (lambda d: pcap.hunt_pattern(d, pattern)) if pattern else (
        lambda d: pcap.hunt_alpha_tokens(d, length=key_len))

    for s in streams:
        payload = s.payload

        # 1. token hunt on the raw payload
        for token in token_hunter(payload):
            report.findings.append(StreamFinding(
                stream=s.label, kind="token",
                detail=f"candidate {'custom pattern' if pattern else f'{key_len} char alpha'} token",
                value=token, score=100.0))

        # 2. interesting strings
        strings = pcap.carve_strings(payload, min_len=6)
        for st in strings:
            for token in token_hunter(st.encode("latin1")):
                if not any(f.value == token for f in report.findings):
                    report.findings.append(StreamFinding(
                        stream=s.label, kind="token",
                        detail="token inside carved string", value=token, score=90.0))

        # 3. attack battery per direction: encodings on strings, xor on opaque runs
        for direction, blob in (("a->b", s.a_to_b), ("b->a", s.b_to_a)):
            if len(blob) < min_blob:
                continue
            for st in pcap.carve_strings(blob, min_len=12):
                for chain, decoded in enc.smart_decode(st.encode("latin1")):
                    try:
                        text = decoded.decode("utf-8", errors="strict").strip()
                    except Exception:
                        continue
                    if len(text) >= 4 and all(32 <= ord(c) < 127 or c in " \t" for c in text):
                        for token in token_hunter(text.encode("latin1")):
                            report.findings.append(StreamFinding(
                                stream=s.label, kind="decoded-token",
                                detail=f"token after {chain} decode ({direction})",
                                value=token, score=95.0))
            # xor obfuscated token scan: finds 12+ alpha runs under any single
            # byte xor key, even buried in mixed binary. O(n) bitmask scan.
            # near miss keys cluster at the same offset, so group them into
            # one finding per offset and let the analyst pick.
            groups: dict[int, list[tuple[float, int, str]]] = {}
            for offset, key, token in pcap.xor_token_scan(blob, min_length=key_len):
                ctx = blob[max(0, offset - 24):offset + len(token) + 24]
                ctx_pt = xor.xor_bytes(ctx, bytes([key]))
                score = _context_score(ctx_pt)
                groups.setdefault(offset, []).append((score, key, token))
            for offset, cands in groups.items():
                cands.sort(key=lambda c: -c[0])
                lines = [f"0x{k:02x}: {t}" for _, k, t in cands]
                best = cands[0][0]
                report.findings.append(StreamFinding(
                    stream=s.label, kind="xor-token",
                    detail=(f"{len(cands)} xor keys yield {key_len}+ alpha runs "
                            f"at offset {offset} ({direction})"),
                    value="\n".join(lines), score=max(best, 1.0)))
            # full solver battery as a last resort, strict threshold
            if analysis.shannon_entropy(blob) > 5.5 and len(blob) >= 32:
                for f in analyze_blob(blob, max_findings=3):
                    if f.score > 40 and f.plaintext:
                        report.findings.append(StreamFinding(
                            stream=s.label, kind=f"auto-{f.method}",
                            detail=f"{f.detail} ({direction})",
                            value=f.plaintext[:200], score=min(f.score, 80.0)))

    # dedupe, keep highest score per (stream, kind, value)
    seen: dict[tuple, StreamFinding] = {}
    for f in report.findings:
        k = (f.stream, f.kind, f.value)
        if k not in seen or f.score > seen[k].score:
            seen[k] = f
    report.findings = sorted(seen.values(), key=lambda f: -f.score)
    return report


def render_markdown(report: PcapReport) -> str:
    lines = ["# flaghunter pcap report", "",
             f"source: `{report.source}`",
             f"packets: {report.packets}, tcp streams: {report.streams}", ""]
    if not report.findings:
        lines.append("no tokens or decodable blobs found.")
        return "\n".join(lines)
    lines.append(f"## findings ({len(report.findings)})")
    lines.append("")
    for i, f in enumerate(report.findings, 1):
        lines.append(f"### {i}. [{f.kind}] {f.detail}")
        lines.append(f"stream: `{f.stream}`")
        lines.append("```")
        lines.append(f.value)
        lines.append("```")
        lines.append("")
    return "\n".join(lines)


def render_json(report: PcapReport) -> str:
    return json.dumps({
        "source": report.source,
        "packets": report.packets,
        "streams": report.streams,
        "findings": [
            {"stream": f.stream, "kind": f.kind, "detail": f.detail,
             "value": f.value, "score": round(f.score, 1)}
            for f in report.findings
        ],
    }, indent=2)
