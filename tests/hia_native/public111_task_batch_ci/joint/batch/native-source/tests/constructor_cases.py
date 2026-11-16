"""Ordinary text/result constructor cases; no external services or filesystem effects."""
from dataclasses import dataclass
import struct


@dataclass(frozen=True)
class Case:
    name: str
    text: str
    is_error: int = 0
    policy: int = 0
    retained_typed: bool = True

    def frame(self):
        raw = self.text.encode("utf-8")
        return struct.pack("<8s7Q", b"HRTCRQ01", 1, self.is_error, self.policy, len(raw), 0, 0, 0) + raw


def cases(profile):
    texts = [
        ("empty", ""),
        ("ascii", "ordinary result"),
        ("unicode", "中文 café 😀"),
        ("lines", "first\nsecond\r\nthird\tcolumn"),
        ("quotes", 'quoted "text"; backslash \\ and slash /'),
        ("controls", "".join(chr(i) for i in range(32))),
        ("unicode-separators", "e\u0301 \u2028 \u2029"),
        ("json-looking", '{"answer":42,"text":"raw text"}'),
        ("whitespace", " \n\t\r "),
        ("repeated", "hello 世界\n" * 127),
    ]
    result = [Case(f"{name}-error{error}-policy{policy}", text, error, policy)
              for name, text in texts for error in (0, 1) for policy in (0, 1, 2)]
    result += [Case(f"wire-budget-text-{size}", "x" * size) for size in (65459, 65460, 65461)]
    result += [Case("above-eight-mib", "x" * ((8 << 20) + 123), retained_typed=False)]
    if profile == "quick":
        return result[:6]
    if profile == "ordinary":
        return result
    if profile == "wide":
        return result + [Case("escaped-wire-above-sixty-four-mib", "\n" * ((32 << 20) + 16),
                              retained_typed=False)]
    raise ValueError("unknown case profile")

