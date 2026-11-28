# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Deterministic inputs; general expected semantics execute only in original Rust.

Malformed transport and capacity controls never enter the semantic corpus.
Unix workdir bytes, including non-UTF8 and NUL, remain original semantic inputs.
"""
from __future__ import annotations
from pathlib import Path
import random
import struct

ROOT = Path(__file__).resolve().parents[3]
GATE_MAGIC = b"HSHGATE1"
TERMINAL_KNOWN = [
    ("\x1b[1;32mok\x1b[0m", "ok"),
    ("\x1b[2K\x1b[1Adone", "done"),
    ("\x1b]8;;http://x\x07link\x1b]8;;\x07", "link"),
    ("Downloading 10%\rDownloading 55%\rDone.\n", "Done."),
    ("a\r\nb\r\n", "a\nb"),
    ("abcd\x08\x08X", "abX"),
    ("ding\x07!", "ding!"),
    ("Done.   \t\n\n\n", "Done."),
    ("\n\n  % Total\nbody", "  % Total\nbody"),
    ("same\nsame\nsame\nsame\nnext", "same\n[... last line repeated 3 more times]\nnext"),
    ("dup\ndup\nend", "dup\ndup\nend"),
    ("hello\nworld", "hello\nworld"),
]
GATE_KNOWN = [
    (1, "cargo test", b"/work", struct.pack("<Q", 0)),
    (1, "cargo build 2>&1 | grep error", b"/work", struct.pack("<Q", 0)),
    (1, "echo error >&2", b"/work", struct.pack("<Q", 0)),
    (1, "until test -f /tmp/x; do sleep 2; done", b"/work", struct.pack("<Q", 0)),
    (1, "echo hi > /tmp/x", b"/work", struct.pack("<Q", 2) +
     b"`echo` wrote a file via redirect; text_editor create writes content without shell quoting."),
    (2, "git stash", b"/work", struct.pack("<Q", 1)),
    (2, "git stash pop", b"/work", struct.pack("<Q", 0)),
    (2, "echo git stash", b"/work", struct.pack("<Q", 0)),
    (3, "a;b", None, struct.pack("<QQQQQ", 2, 0, 1, 2, 3)),
    (4, "a 'b c'", None, struct.pack("<QQQQQ", 2, 0, 1, 2, 7)),
    (5, "echo x > /tmp/a", None, struct.pack("<QQQ", 1, 9, 15)),
    (6, "ssh host 'uptime'", None, struct.pack("<QQQ", 1, 10, 16)),
]


def gate_frame(op, command, workdir=b"/work"):
    raw = command.encode() if isinstance(command, str) else command
    directory = b"" if workdir is None else (workdir.encode() if isinstance(workdir, str) else workdir)
    return GATE_MAGIC + struct.pack("<QQQQ", op, int(workdir is not None), len(raw), len(directory)) + raw + directory


def _rust_string(value):
    """Decode Rust literal spelling without translating any tested behavior."""
    output, i = [], 0
    short = {"n": "\n", "r": "\r", "t": "\t", "0": "\0", "\\": "\\", '"': '"', "'": "'"}
    while i < len(value):
        if value[i] != "\\":
            output.append(value[i]); i += 1
            continue
        i += 1
        if i >= len(value):
            raise ValueError("unterminated Rust string escape")
        kind = value[i]; i += 1
        if kind in short:
            output.append(short[kind])
        elif kind == "x":
            output.append(chr(int(value[i:i + 2], 16))); i += 2
        elif kind == "u" and value[i:i + 1] == "{":
            end = value.index("}", i)
            output.append(chr(int(value[i + 1:end].replace("_", ""), 16))); i = end + 1
        elif kind == "\n":
            while i < len(value) and value[i].isspace():
                i += 1
        else:
            raise ValueError(f"unhandled Rust literal escape: {kind!r}")
    return "".join(output)


def original_literals(runtime):
    source = (runtime / "src/mcp/fs/shell_tests.rs").read_text()
    start = source.index("#[test]\nfn stashing_commands_are_recognised")
    end = source.index("#[cfg(unix)]\n#[tokio::test]", start)
    second = source.index("#[test]\nfn test_clean_terminal_noise")
    last = source.index("#[cfg(unix)]\n#[tokio::test]\nasync fn a_scratch_heredoc_and_a_piped_read_run", second)
    selected = source[start:end] + source[second:last]
    # These hash-bound original regions use ordinary strings and line comments.
    strings, i = [], 0
    while i < len(selected):
        if selected.startswith("//", i):
            end = selected.find("\n", i); i = len(selected) if end == -1 else end + 1
        elif selected[i] == '"':
            start = i + 1; i += 1
            while i < len(selected):
                if selected[i] == "\\":
                    i += 2
                elif selected[i] == '"':
                    strings.append(_rust_string(selected[start:i])); i += 1
                    break
                else:
                    i += 1
            else:
                raise ValueError("unterminated original test string")
        else:
            i += 1
    return strings


def _terminal(runtime):
    for raw, expected in TERMINAL_KNOWN:
        yield "original_examples", raw.encode(), expected.encode()
    for literal in original_literals(runtime):
        yield "original_test_literals", literal.encode(), None
    fixed = ["", "\n", "\r", "\r\n", "\r\r\n", "\t\n\t", "\n \n", "a\r\r",
             "one\rtwo\r\nthree\r", "\x08\x08hello", "中\x08文", "e\u0301\x08!",
             "😀\x08x", "a\u2003\u3000", "\u2003a\u3000\n", "\x1b", "\x1b\n",
             "\x1b[", "\x1b]", "\x1b]unfinished\nacross", "\x1b]a\x1bZremaining",
             "\x1b]a\x1b\\remaining", "\x1b]a\x07remaining", "\x1béx", "\x1b😀x",
             "\x1b[123\nremainder", "\x1b\x1b[31mred", "\x1b]title\x1b[31mred"]
    for raw in fixed:
        yield "fixed_boundaries", raw.encode(), None
    points = list(range(256)) + [0x1680, *range(0x2000, 0x200C), 0x2028, 0x2029,
                                0x202F, 0x205F, 0x3000, 0xFEFF, 0x10FFFF]
    for point in points:
        char = chr(point)
        for raw in ("a" + char + "b", "a" + char + "\n", char + "a" + char, "\x1b" + char + "X"):
            yield "unicode_control_and_trim", raw.encode(), None
    parameters = ["", "0", "1;32", "?25", ">", "1234567890;" * 3, " ", "\t", "é", ":<=>?"]
    intermediates = ["", " ", "!", "/", " /", "!\"#$%&'()*+,-./"]
    finals = ["m", "K", "@", "~", "A", "?", " ", "\n", "😀"]
    for parameter in parameters:
        for intermediate in intermediates:
            for final in finals:
                yield "ansi_csi_grammar", ("before\x1b[" + parameter + intermediate + final + "after\n").encode(), None
    for body in ("", "0;title", "8;;https://example.test/中", "a\nb\nc", "a\rpad", "a\x08x"):
        for ending in ("", "\x07", "\x1b\\", "\x1bX", "\x1b\n", "\x1b", "\x1b]tail"):
            yield "ansi_osc_grammar", ("pre\x1b]" + body + ending + "visible").encode(), None
    for line in ("a", "ab", "same", "同", "😀", "\t", "", "x  ", "\x1b[32mx\x1b[0m"):
        for repeats in (1, 2, 3, 4, 9, 10, 11, 99, 100, 101, 1000):
            yield "duplicate_runs", ((line + "\n") * repeats + "end\n").encode(), None
    for size in (255, 256, 257, 4095, 4096, 4097, 16383, 16384, 16385, 65535):
        yield "length_boundaries", ("x" * size + "\n").encode(), None
        yield "progress_boundaries", ("x" * size + "\rfinal\n").encode(), None
    rng = random.Random(0x4853485445524D)
    alphabet = list("abc XYZ[];!?./\\\"'0123") + list("中é😀\u0301\u3000")
    alphabet += [chr(i) for i in range(32)] + [chr(i) for i in range(127, 160)]
    atoms = ["\x1b[31m", "\x1b[0m", "\x1b]8;;x\x07", "\x1b]x\x1b\\", "\r\n", "\n", "\x08"]
    for _ in range(600):
        raw = "".join(rng.choice(alphabet + atoms) for _ in range(rng.randrange(150)))
        yield "seeded_random", raw.encode(), None


def _gate(runtime):
    for op, command, workdir, expected in GATE_KNOWN:
        yield "original_examples", gate_frame(op, command, workdir), expected
    for command in original_literals(runtime):
        for op in range(1, 7):
            yield "original_test_literals", gate_frame(op, command), None
    programs = ["cat", "head", "tail", "less", "more", "grep", "egrep", "fgrep", "rg",
                "find", "ls", "sleep", "watch", "top", "htop", "tee", "sed", "awk",
                "echo", "printf", "git", "ssh", "cargo", "", "中"]
    prefixes = ["", "FOO=bar ", "{ ", "(", "/usr/bin/", "A=B C=D ((("]
    suffixes = ["", " x", " | grep x", "; cargo test", " && cat x", ")", " -i"]
    for program in programs:
        for prefix in prefixes:
            for suffix in suffixes:
                yield "program_and_segment_shape", gate_frame(1, prefix + program + suffix), None
    workdirs = [None, b"", b"/", b"/work", b"/work/", b"//work//", b"/work/.",
                b"/work/..", b"work", b".", b"..", b"./work", b"/work2", b"/tmp",
                "工作".encode(), "/工作".encode(), b"/\xff", b"/work\x00", b"\0", b"/work/\xff/.."]
    targets = ["x", "/", "/work", "/work/x", "/work2/x", "/work/../x", "/work/./x",
               "//work///x", "/work//", "/tmp/x", "./x", "../x", "'x'", "'/tmp/x'",
               '"/work2/x"', '"/work x"', "/工作/文件", "/work\0/x", "/tmp/x\0", "/work/.hidden"]
    for workdir in workdirs:
        for target in targets:
            for program in ("cat", "echo", "printf"):
                yield "unix_path_components", gate_frame(1, f"{program} data > {target}", workdir), None
    for option in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ":
        for spelling in (f"-{option}", f"-v{option}", f"-{option}22", f"-{option}=value"):
            command = f"ssh {spelling} arg host 'grep x /y' | tail -2"
            for op in (1, 6):
                yield "ssh_options", gate_frame(op, command), None
    remotes = ["cat x", "git status", "echo hi > /tmp/x", "sed -i s/a/b/ x", "grep x y",
               "do echo x; sleep 2; done", "bash -lc 'cat x'", "ssh", ""]
    for remote in remotes:
        for quote in ("", "'", '"'):
            for after in ("", " | grep x", " && cat x", "\\|more", " 'tail'"):
                command = "ssh -o StrictHostKeyChecking=no host " + quote + remote + quote + after
                for op in (1, 6):
                    yield "ssh_remote_quotes", gate_frame(op, command), None
    for depth in (1, 2, 3, 8, 16, 31, 32, 63, 64, 127, 128, 255):
        for tail in ("cat x", "cargo test", "echo hi > /tmp/x"):
            yield "ssh_depth", gate_frame(1, "ssh h " * depth + tail), None
    composite = [
        "echo a > /tmp/x; ssh host 'echo ok'; printf b > /tmp/y",
        "echo a > /tmp/x; ssh host 'echo ok'; printf b > /tmp/y; ls",
        "do; ssh h 'sleep 1'; done",
        "do; ssh h 'echo ok'; sleep 1; done",
        "do; ssh h 'do; sleep 1; done'; sleep 1; done; sleep 1",
        "echo hi > /tmp/x; ssh a 'ssh b \"echo ok\"'; printf hi >/tmp/y",
        "ssh h ''", 'ssh h ""', "ssh h '' | x", "ssh -p",
        "ssh -p host echo hi", "ssh -px host echo hi", "ssh -- host echo hi",
        "ssh -vvop22 host 'cat x'", "sed --in-place=backup s/a/b/ x",
        "sed --in-places s/a/b/ x", "sed -in s/a/b/ x",
        "echo >>>foo", "echo >\t/tmp/x", "echo >|x", "echo >''",
        'echo >"/tmp/a b" > /work/z', "echo x > /tmp/z\\",
        "do; do; sleep 1; done; sleep 2; done; echo ok",
    ]
    for command in composite:
        for op in (1, 3, 4, 5, 6):
            yield "priority_and_nested_unwind", gate_frame(op, command), None
    for separator in (";", "&&", "||", "\n", "$(`", "`", "|", "&", "\r", "\u3000"):
        for quoted in ("", "'", '"', "\\"):
            command = f"echo {quoted}a{separator}cat x{quoted}"
            for op in (1, 3, 4, 5, 6):
                yield "quotes_and_separators", gate_frame(op, command), None
    redirects = [">", ">>", ">>>", ">&2", "> &2", ">\t/tmp/x", ">\n/tmp/x", ">/tmp/x>f",
                 ">|x", ">;x", ">&", ">\u3000x", ">é", ">中", ">\x00x", "\\>/tmp/x",
                 "'>' /tmp/x", '"a > b"', ">/tmp/x | cat", ">/work/../tmp/x"]
    for redirect in redirects:
        for prefix in ("echo x ", "cat ", "printf '%s' x ", "tee ", "sed -n "):
            for op in (1, 5):
                yield "redirect_grammar", gate_frame(op, prefix + redirect), None
    for white in (" ", "\t", "\n", "\r", "\v", "\f", "\x85", "\u00a0", "\u1680",
                  "\u2003", "\u2028", "\u2029", "\u202f", "\u3000", "\u200b", "\ufeff"):
        for command in (f"{white}cat{white}x{white}", f"ssh{white}h{white}cat x",
                        f"git{white}stash{white}push", f"echo x >{white}/tmp/x"):
            for op in range(1, 7):
                yield "unicode_vs_ascii_whitespace", gate_frame(op, command), None
    for prefix in ("git", "/usr/bin/git", "FOO=x git", "(git", "{ git", "git -C /work",
                   "git -c a=b", "git --no-pager", "git -C", "git --", "echo git"):
        for sub in ("", "stash", "stash push", "stash save", "stash -q", "stash pop",
                    "stash list", "stash branch", "stash apply", "stash clear", "stash --keep-index",
                    "'stash'", "stash 'push'", "status && git stash"):
            yield "stash_global_options", gate_frame(2, prefix + " " + sub), None
    rng = random.Random(0x48534847415445)
    atoms = programs + [" ", "\t", "\n", "\r", "\u3000", "\0", "é", "😀", "中", "-i", "-C",
                        "'", '"', "\\", ";", "&&", "||", "|", "$(`", "`", "(", ")", "{", "}",
                        ">", ">>", ">&1", "foo=bar", "/tmp/x", "/work/x", "--", "do", "done"]
    for _ in range(500):
        command = "".join(rng.choice(atoms) for _ in range(rng.randrange(35)))
        for op in range(1, 7):
            yield "seeded_random", gate_frame(op, command, rng.choice(workdirs)), None


def iter_cases(mode, runtime=ROOT):
    if mode not in ("terminal", "gate"):
        raise ValueError("unknown shell semantic mode")
    generator = _terminal if mode == "terminal" else _gate
    for index, (category, raw, expected) in enumerate(generator(runtime)):
        yield {"id": f"{mode}-{index:06d}", "category": category,
               "input": raw, "known_expected": expected}


def semantic_cases(mode):
    return list(iter_cases(mode))


def control_specs(mode):
    """Physical ABI refusal controls, explicitly outside original Rust semantics."""
    invalid, capacity = 0xFFFFFFFF, 0xFFFFFFFE
    controls = []
    malformed_utf8 = [b"\x80", b"\xc0\x80", b"\xc2", b"\xe0\x80\x80", b"\xed\xa0\x80",
                      b"\xf0\x80\x80\x80", b"\xf4\x90\x80\x80", b"\xf5\x80\x80\x80",
                      b"\xff", b"ok\xf0\x9f\x98", b"\xe2(\xa1"]
    for index, raw in enumerate(malformed_utf8):
        wire = raw if mode == "terminal" else gate_frame(1, raw)
        controls.append({"id": f"invalid-utf8-{index}", "input": wire,
                         "output_capacity": 1024, "workspace_capacity": 8192,
                         "expected_code": invalid})
    if mode == "terminal":
        for raw, out, work in [(b"abc", 2, 128), (b"a", 1, 0),
                               (b"same\nsame\nsame\n", 1, 512),
                               (b"a\nb\nc", 256, 1)]:
            controls.append({"id": f"capacity-{len(controls)}", "input": raw,
                             "output_capacity": out, "workspace_capacity": work,
                             "expected_code": capacity})
    else:
        good = gate_frame(1, "cargo test")
        malformed = [b"", b"HSHGATE1", good[:39], b"X" + good[1:], good + b"x",
                     gate_frame(0, ""), gate_frame(7, ""), gate_frame((1 << 64) - 1, "")]
        for offset, value in [(16, 2), (24, (1 << 64) - 1), (32, (1 << 64) - 1)]:
            value_wire = bytearray(good); struct.pack_into("<Q", value_wire, offset, value)
            malformed.append(bytes(value_wire))
        absent = bytearray(good); struct.pack_into("<Q", absent, 16, 0)
        malformed.append(bytes(absent))
        for index, wire in enumerate(malformed):
            controls.append({"id": f"malformed-frame-{index}", "input": wire,
                             "output_capacity": 1024, "workspace_capacity": 8192,
                             "expected_code": invalid})
        for op in range(1, 7):
            controls.append({"id": f"output-capacity-op{op}", "input": gate_frame(op, "ssh h cat x"),
                             "output_capacity": 7, "workspace_capacity": 8192,
                             "expected_code": capacity})
            controls.append({"id": f"workspace-capacity-op{op}", "input": gate_frame(op, "cargo test"),
                             "output_capacity": 1024, "workspace_capacity": 127,
                             "expected_code": capacity})
        controls.append({"id": "ssh-recursion-capacity", "input": gate_frame(1, "ssh h " * 32 + "cat x"),
                         "output_capacity": 1024, "workspace_capacity": 128,
                         "expected_code": capacity})
    return controls
