"""Deterministic real-OS inputs for the native shell process owner.

The synchronization prefix is a visible fixture input.  It allows the unchanged
Rust foreground implementation to unlink its own logs while a read-only observer
retains open descriptors.  Both implementations receive exactly this command and
the same controlled environment.  It is not part of the production shell owner.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import struct


SCHEMA = "hepta.runtime.shell-process-cases.v1"
PRODUCTION_TIMEOUT_MS = 10_000
CAPTURE_TOKEN = 1
GATE_ENV = "HIA_FIXTURE_CAPTURE_READY"
GATE_PREFIX = (
    'while [ ! -e "$HIA_FIXTURE_CAPTURE_READY" ]; do /bin/sleep 0.005; done\n'
)
REQUEST_MAGIC = b"HSHPRQ01"
EVENT_MAGIC = b"HSHPRR01"
TRACE_MAGIC = b"HSHPRTR1"
AUDIT_MAGIC = b"HSHPAUD1"


def frame(operation: int, command: bytes = b"", cwd: bytes = b"") -> bytes:
    if operation not in (1, 2, 3, 4):
        raise ValueError("unknown operation")
    if operation != 1 and (command or cwd):
        raise ValueError("control frame cannot borrow a command or cwd")
    body = REQUEST_MAGIC + struct.pack("<4Q", operation, CAPTURE_TOKEN, len(command), len(cwd)) + command + cwd
    return struct.pack("<Q", len(body)) + body


def specs() -> list[dict]:
    """Fresh dictionaries; no random generation, host discovery or hidden cases."""
    rows = [
        {"name": "stdout_and_stderr", "body": "printf 'alpha\\n'; printf 'beta\\n' >&2", "stdout_hex": b"alpha\n".hex(), "stderr_hex": b"beta\n".hex()},
        {"name": "empty_success", "body": ":", "stdout_hex": "", "stderr_hex": ""},
        {"name": "stderr_success", "body": "printf 'warning\\n' >&2", "stdout_hex": "", "stderr_hex": b"warning\n".hex()},
        {"name": "exit_seven", "body": "printf before; printf detail >&2; exit 7", "exit_code": 7, "stdout_hex": b"before".hex(), "stderr_hex": b"detail".hex()},
        {"name": "signal_term", "body": "kill -TERM \"$$\"", "exit_code": -1, "wait_signal": 15, "stdout_hex": "", "stderr_hex": ""},
        {"name": "stdin_eof", "body": "if IFS= read -r line; then printf unexpected; else printf eof; fi", "stdout_hex": b"eof".hex(), "stderr_hex": ""},
        {"name": "stdio_not_tty", "body": "for fd in 0 1 2; do if [ -t \"$fd\" ]; then printf tty; else printf file; fi; done", "stdout_hex": b"filefilefile".hex(), "stderr_hex": ""},
        {"name": "binary_capture", "body": "printf '\\377\\000A\\rB\\n'; printf '\\033[31mred\\033[0m\\n' >&2", "stdout_hex": bytes([255, 0, 65, 13, 66, 10]).hex(), "stderr_hex": b"\x1b[31mred\x1b[0m\n".hex()},
        {"name": "noninteractive_overrides", "body": 'printf "%s|%s|%s|%s|%s" "$GIT_TERMINAL_PROMPT" "$DEBIAN_FRONTEND" "$PAGER" "$GIT_PAGER" "$NO_COLOR"', "env": {"GIT_TERMINAL_PROMPT": "1", "DEBIAN_FRONTEND": "dialog", "PAGER": "less", "GIT_PAGER": "more", "NO_COLOR": "0"}, "stdout_hex": b"0|noninteractive|cat|cat|1".hex(), "stderr_hex": ""},
        {"name": "inherited_environment", "body": 'printf "%s|%s" "$HIA_PROCESS_SENTINEL" "$LANG"', "env": {"HIA_PROCESS_SENTINEL": "kept value = \u03bb"}, "stdout_hex": "kept value = \u03bb|C.UTF-8".encode().hex(), "stderr_hex": ""},
        {"name": "default_path", "body": "printf default-path", "remove_env": ["PATH"], "stdout_hex": b"default-path".hex(), "stderr_hex": ""},
        {"name": "empty_path_current_directory", "body": "printf empty-path", "env": {"PATH": ""}, "setup": "cwd_sh", "stdout_hex": b"empty-path".hex(), "stderr_hex": ""},
        {"name": "empty_path_missing", "body": "printf unreachable", "env": {"PATH": ""}, "spawn_errno": 2},
        {"name": "relative_path", "body": "printf relative-path", "env": {"PATH": "bin"}, "setup": "relative_sh", "stdout_hex": b"relative-path".hex(), "stderr_hex": ""},
        {"name": "empty_path_segment", "body": "printf segment", "env": {"PATH": "missing::other"}, "setup": "cwd_sh", "stdout_hex": b"segment".hex(), "stderr_hex": ""},
        {"name": "permission_then_success", "body": "printf permitted", "env": {"PATH": "denied:/bin"}, "setup": "denied_sh", "stdout_hex": b"permitted".hex(), "stderr_hex": ""},
        {"name": "permission_exhausted", "body": "printf unreachable", "env": {"PATH": "denied:missing"}, "setup": "denied_sh", "spawn_errno": 13},
        {"name": "not_directory_then_success", "body": "printf searched", "env": {"PATH": "plain:/bin"}, "setup": "plain_file", "stdout_hex": b"searched".hex(), "stderr_hex": ""},
        {"name": "overlong_segment_inserts_current_directory_attempt", "body": "printf selected", "env": {"PATH": "x" * 5000 + ":/bin"}, "setup": "cwd_marker_sh", "stdout_hex": b"cwd-search:selected".hex(), "stderr_hex": ""},
        {"name": "overlong_final_preserves_access_denied", "body": "printf unreachable", "env": {"PATH": "denied:" + "x" * 5000}, "setup": "denied_sh", "spawn_errno": 13},
        {"name": "overlong_final_preserves_not_found", "body": "printf unreachable", "env": {"PATH": "missing:" + "x" * 5000}, "spawn_errno": 2},
        {"name": "all_overlong_path_fresh_errno_zero", "body": ":", "env": {"PATH": "x" * 5000}, "gate": False, "spawn_errno": 0, "compatibility_scope": "Observed fresh original fixture process on GNU libc 2.43; arbitrary pre-existing libc errno is not represented by this owner."},
        {"name": "symlink_loop_is_fatal", "body": "printf unreachable", "env": {"PATH": "loop:/bin"}, "setup": "loop_sh", "spawn_errno": 40},
        {"name": "enoexec_script_fallback", "body": "printf requested-command", "env": {"PATH": "text:/bin"}, "setup": "text_sh", "stdout_hex": b"fallback:-c".hex(), "stderr_hex": "", "exit_code": 9},
        {"name": "missing_cwd", "body": "printf unreachable", "cwd": "missing", "spawn_errno": 2},
        {"name": "file_cwd", "body": "printf unreachable", "cwd": "plain", "setup": "plain_file", "spawn_errno": 20},
        {"name": "nul_command", "body": "printf before\u0000printf after", "gate": False, "spawn_invalid_input": True},
        {"name": "nul_cwd", "body": "printf unreachable", "cwd": "nul", "spawn_invalid_input": True},
        {"name": "raw_unix_cwd", "body": "printf raw-cwd", "cwd": "raw", "setup": "raw_cwd", "stdout_hex": b"raw-cwd".hex(), "stderr_hex": ""},
        {"name": "oversized_exec_argument", "body": "#" + "x" * 140_000, "gate": False, "spawn_errno": 7},
        {"name": "short_foreground", "body": "/usr/bin/python3 -c 'import time; time.sleep(0.04)'; printf foreground", "stdout_hex": b"foreground".hex(), "stderr_hex": ""},
        {"name": "capture_two_streams", "body": "i=0; while [ \"$i\" -lt 1024 ]; do printf '0123456789abcdef\\n'; printf 'fedcba9876543210\\n' >&2; i=$((i+1)); done", "stdout_hex": (b"0123456789abcdef\n" * 1024).hex(), "stderr_hex": (b"fedcba9876543210\n" * 1024).hex()},
        {"name": "session_and_process_group", "body": "printf '%s\\n' \"$$\"; /usr/bin/python3 -c 'import json,os; print(json.dumps({\"pid\":os.getpid(),\"ppid\":os.getppid(),\"pgid\":os.getpgid(0),\"sid\":os.getsid(0)}))'; :", "observe_session": True},
        {"name": "foreground_cancel", "body": "printf ready; exec /bin/sleep 30", "control": "cancel_after_ready", "expected_kinds": [5], "stdout_hex": b"ready".hex(), "stderr_hex": ""},
        {"name": "foreground_shutdown", "body": "printf ready; exec /bin/sleep 30", "control": "shutdown_after_ready", "expected_kinds": [6, 2], "exit_code": -1, "wait_signal": 9, "stdout_hex": b"ready".hex(), "stderr_hex": ""},
        {"name": "promotion_completes_same_child", "body": "printf before; /usr/bin/python3 -c 'import time; time.sleep(10.35)'; printf after", "expected_kinds": [3, 4], "stdout_hex": b"beforeafter".hex(), "stderr_hex": ""},
        {"name": "promotion_ignores_caller_cancel", "body": "printf before; /usr/bin/python3 -c 'import time; time.sleep(10.35)'; printf after", "control": "cancel_after_promotion", "expected_kinds": [3, 4], "stdout_hex": b"beforeafter".hex(), "stderr_hex": ""},
        {"name": "background_shutdown", "body": "printf before; exec /bin/sleep 30", "control": "shutdown_after_promotion", "expected_kinds": [3, 6, 4], "exit_code": -1, "wait_signal": 9, "stdout_hex": b"before".hex(), "stderr_hex": ""},
    ]
    for row in rows:
        row.setdefault("gate", True)
        row.setdefault("env", {})
        row.setdefault("remove_env", [])
        row.setdefault("exit_code", 0)
        row.setdefault("expected_kinds", [1] if "spawn_errno" in row or row.get("spawn_invalid_input") else [2])
        row.setdefault("deadline_seconds", 40 if "promotion" in row["name"] or row["name"] == "background_shutdown" else 8)
    if len({row["name"] for row in rows}) != len(rows):
        raise AssertionError("duplicate real-OS case name")
    return rows


def _write(path: Path, data: bytes, mode: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as stream:
        stream.write(data)
    path.chmod(mode)


def prepare(case: dict, directory: Path) -> dict:
    """Create one owned case directory. Reusing a prior attempt is forbidden."""
    directory.mkdir(parents=True, exist_ok=False)
    directory = directory.resolve()
    work = directory / "work"
    work.mkdir()
    ready = directory / "capture.ready"
    setup = case.get("setup")
    wrapper = b'#!/bin/sh\nexec /bin/sh "$@"\n'
    if setup == "cwd_sh":
        _write(work / "sh", wrapper, 0o755)
    elif setup == "cwd_marker_sh":
        _write(work / "sh", ("#!/bin/sh\n" + GATE_PREFIX + 'printf cwd-search:; exec /bin/sh "$@"\n').encode(), 0o755)
    elif setup == "relative_sh":
        _write(work / "bin/sh", wrapper, 0o755)
    elif setup == "denied_sh":
        _write(work / "denied/sh", wrapper, 0o644)
    elif setup == "plain_file":
        _write(work / "plain", b"not a directory\n", 0o644)
    elif setup == "loop_sh":
        (work / "loop").mkdir()
        (work / "loop/sh").symlink_to("sh")
    elif setup == "text_sh":
        _write(work / "text/sh", (GATE_PREFIX + 'printf "fallback:%s" "$1"; exit 9\n').encode(), 0o755)
    elif setup == "raw_cwd":
        os.mkdir(os.fsencode(work) + b"/raw-\xff-\xfe")
    elif setup is not None:
        raise ValueError(f"unknown fixture setup {setup}")

    cwd = os.fsencode(work)
    if case.get("cwd") == "missing":
        cwd += b"/missing"
    elif case.get("cwd") == "plain":
        cwd += b"/plain"
    elif case.get("cwd") == "nul":
        cwd += b"/invalid\0tail"
    elif case.get("cwd") == "raw":
        cwd += b"/raw-\xff-\xfe"
    command = ((GATE_PREFIX if case["gate"] else "") + case["body"]).encode("utf-8")
    temp = directory / "tmp"
    temp.mkdir()
    # Never inherit credentials, loader overrides or unrelated operator state.
    env = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "USER": "hepta-fixture", "HOME": str(work), "TMPDIR": str(temp), GATE_ENV: str(ready)}
    env.update(case["env"])
    for name in case["remove_env"]:
        env.pop(name, None)
    result = {"schema": SCHEMA, "name": case["name"], "definition": case, "command_hex": command.hex(), "cwd_hex": cwd.hex(), "environment": env, "ready_path": str(ready), "directory": str(directory), "timeout_ms": PRODUCTION_TIMEOUT_MS}
    (directory / "input.json").write_text(json.dumps(result, ensure_ascii=True, sort_keys=True, indent=2) + "\n")
    (directory / "native-start.bin").write_bytes(frame(1, command, cwd))
    return result


def decode_event(body: bytes) -> dict:
    if len(body) != 96 or body[:8] != EVENT_MAGIC:
        raise ValueError("not a complete process-owner event")
    words = struct.unpack("<12Q", body)
    result = dict(zip(("magic", "kind", "capture_token", "child_token", "pid", "exit_code", "wait_status", "error_kind", "errno", "sequence", "tracked", "flags"), words))
    result.pop("magic")
    result["exit_code"] = struct.unpack_from("<q", body, 40)[0]
    if result["kind"] not in range(1, 7) or result["capture_token"] != CAPTURE_TOKEN or result["tracked"] not in (0, 1):
        raise ValueError("event violates its typed contract")
    if result["flags"] & ~7:
        raise ValueError("unknown event flag")
    result["raw_hex"] = body.hex()
    return result


def decode_trace(data: bytes, *, complete: bool = True) -> dict:
    if complete and len(data) % 128:
        raise ValueError("truncated native kernel trace")
    records, footer = [], None
    for offset in range(0, len(data) - 127, 128):
        chunk = data[offset:offset + 128]
        words = struct.unpack("<16Q", chunk)
        if chunk[:8] == AUDIT_MAGIC:
            if footer is not None or offset + 128 != len(data):
                raise ValueError("misplaced or duplicate audit footer")
            footer = {"offset": offset, "words": list(words[1:]), "raw_hex": chunk.hex()}
        elif chunk[:8] == TRACE_MAGIC:
            if footer is not None:
                raise ValueError("effect record after audit footer")
            names = ("role", "self_pid", "child_token", "sequence", "action", "arg0", "arg1", "arg2", "result", "errno", "aux", "child_pid", "ownership_flags", "phase", "raw_aux")
            record = dict(zip(names, words[1:]))
            record["offset"] = offset
            record["raw_hex"] = chunk.hex()
            records.append(record)
        else:
            raise ValueError("unknown native trace record")
    if complete and footer is None:
        raise ValueError("missing native audit footer")
    return {"records": records, "footer": footer, "trailing_bytes": len(data) % 128}
