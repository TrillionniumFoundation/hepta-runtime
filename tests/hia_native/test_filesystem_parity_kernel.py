"""Capture every real native filesystem case before original replay."""
from pathlib import Path
import os
import sys

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from filesystem_parity.capture_native import main


def check_trace_pid_padding():
    """Accept strace PID column padding, retaining every record check."""
    from filesystem_parity import native_capture, strict_native, strict_reference
    # CI strace emits two spaces after a four-digit PID; the operator host
    # emits one after its longer PID. This is a parser fixture, not execution.
    line = (r'2887 1794745015.648213 execve("\x2f\x66", [...], '
            r'0x7ffcac630930 /* 269 vars */) = 0' + '\n').encode('ascii')
    readers = (
        lambda raw: native_capture.trace_evidence(raw, [], [], {'events': []}, (0, 0, 0), strict_reference),
        lambda raw: strict_native.trace_evidence(raw, [], [], {'events': []}, (0, 0, 0), '/f'),
        lambda raw: strict_reference.trace_stream(raw, [], [], 0, 0, '/f'),
    )
    for reader in readers:
        expected = reader(line)
        for width in (1, 2, 5):
            assert reader(line.replace(b'2887 ', b'2887' + b' ' * width, 1)) == expected
        invalid = (
            line.replace(b'2887 ', b'2887\t', 1),
            line.replace(b'2887 ', b'2887', 1),
            b' ' + line,
            line[:-1],
            line.replace(b' = 0\n', b' = \n'),
            line.replace(b'1794745015.648213', b'not-a-timestamp'),
            line + b'2888 1794745015.648214 read(0, 0x1000, 0) = 0\n',
            line + b'2887 1794745015.648214 read(0, 0x1000, 1 <unfinished ...>\n',
        )
        for raw in invalid:
            try:
                reader(raw)
            except (AssertionError, ValueError):
                pass
            else:
                raise AssertionError('malformed or foreign-process strace record admitted')

if __name__ == '__main__':
    previous = os.umask(0o077)
    try:
        check_trace_pid_padding()
        main()
    finally:
        os.umask(previous)
