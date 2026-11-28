"""Actual filesystem and ownership controls for the HIA REA file components."""
from pathlib import Path
import argparse
import ctypes
import fcntl
import hashlib
import json
import os
import socket
import struct
import sys
import time
import traceback


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    for name in ("source", "manifest", "engine", "output"):
        ap.add_argument("--" + name, type=Path, required=True)
    ap.add_argument("--engine-sha256", required=True)
    a = ap.parse_args()
    sys.dont_write_bytecode = True
    sys.path.insert(0, str(a.source / "scripts"))
    from hia_native_loader import NativeModule
    from rea_file_native_transport import (
        Capture, Engine, FileActor, PENDING, U64, fd_snapshot, metadata,
        path_request, put, sha, words)
    a.output.mkdir(mode=0o700, exist_ok=False)
    out = a.output
    capture = Capture(out / "capture")
    source_pins = {str(p): p.read_bytes() for p in [
        Path(__file__), Path(__file__).with_name("rea_file_native_transport.py"), a.manifest, a.engine]}
    meta = json.loads(source_pins[str(a.manifest)])
    for key in ("source", "image"):
        p = a.manifest.parent / meta[key]
        source_pins[str(p)] = p.read_bytes()
    module = NativeModule(a.manifest, manifest_sha256=sha(a.manifest.read_bytes()))
    engine = Engine(a.engine, a.engine_sha256)
    start = time.monotonic()
    rows = []
    fixtures = out / "fixtures"
    fixtures.mkdir(mode=0o700)
    serial = 0

    def fixture(data=b"approved"):
        nonlocal serial
        root = fixtures / str(serial)
        serial += 1
        root.mkdir(mode=0o700)
        sub = root / "sub"
        sub.mkdir()
        target = sub / "file"
        target.write_bytes(data)
        target.chmod(0o600)
        return root, target

    def execute(label, path, roots, mode, maximum, expected_error, expected_data=None,
                hook=None, inspect=None):
        before = fd_snapshot()
        actor = FileActor(module, engine, path_request(path, roots), mode=mode,
                          maximum=maximum, capture=capture, label=label)
        try:
            code, raw = actor.run(hook)
            assert 128 <= code <= actor.ocap, (label, code)
            status, error, number = words(raw, 8, 3)
            assert error == expected_error and status == int(bool(error)), (
                label, "terminal", error, expected_error, number)
            if not error:
                assert number == 0
                if expected_data is not None:
                    assert raw[128:] == expected_data, (label, "payload")
                owned = words(ctypes.string_at(actor.context, 128), 56, 4)
                assert owned[0] == 4 and owned[1] == owned[2] == U64
                descriptor = owned[3]
                assert fcntl.fcntl(descriptor, fcntl.F_GETFD) & fcntl.FD_CLOEXEC
                assert words(raw, 32, 11) == metadata(os.fstat(descriptor))
            if inspect is not None:
                inspect(actor, raw)
            rows.append({"label": label, "code": code, "error": error, "errno": number,
                         "native_calls": actor.calls, "native_effects": actor.effects,
                         "response_sha256": sha(raw), "response_bytes": len(raw)})
        finally:
            actor.close()
        assert fd_snapshot() == before, (label, "owned descriptor leak")

    try:
        for size in (0, 1, 8, 255, 4095, 4096, 65535, 65536, 65537):
            data = bytes((j * 31 + 7) & 255 for j in range(size))
            root, target = fixture(data)
            execute("admit-size-" + str(size), target, [root], 0, 0, 0, b"")
            for mode in (1, 2):
                for maximum in sorted({0, max(0, size - 1), size, size + 1}):
                    error = 16 if size > maximum else 0
                    execute("bounded-" + str((size, mode, maximum)), target, [root], mode,
                            maximum, error, data if not error else None)
        root, target = fixture()
        outside, external = fixture(b"outside")
        os.symlink(target, root / "inside-link")
        os.symlink(external, root / "outside-link")
        os.symlink(external.parent, root / "directory-link")
        variants = [
            (target, [root], 0), (str(root) + "/sub/./file", [root], 0),
            (str(root) + "//sub///file/.", [root], 0),
            (str(root) + "/sub/../sub/file", [root], 4),
            (root, [root], 6), ("sub/file", [root], 1),
            (target, [], 2), (target, ["relative", root], 3),
            (target, [root, "relative"], 0), (target, [outside, root], 0),
            (external, [root], 8), (root / "inside-link", [root], 13),
            (root / "outside-link", [root], 13), (root / "directory-link/file", [root], 12),
            (root / "missing/file", [root], 12), (root / "missing", [root], 13),
            (root / "sub", [root], 15), (root / "sub/file/child", [root], 12),
            (bytes(target) + b"\0", [bytes(root)], 5),
            (bytes(root) + b"/" + b"x" * 256, [bytes(root)], 13),
        ]
        for index, (path, roots, error) in enumerate(variants):
            execute("path-and-root-" + str(index), path, roots, 1, 128, error,
                    b"approved" if not error else None)
        badroot = fixtures / "absent"
        execute("missing-configured-root", badroot / "file", [badroot], 0, 0, 11)
        os.symlink(root, fixtures / "admin-link")
        link = fixtures / "admin-link"
        execute("configured-root-final-symlink-refused", link / "sub/file", [link], 0, 0, 11)
        execute("configured-root-ancestor-symlink-admitted", link / "sub/file", [link / "sub"],
                1, 128, 0, b"approved")
        execute("configured-root-dot-spelling-preserved", str(link) + "/./sub/file", [str(link) + "/."],
                1, 128, 0, b"approved")
        execute("first-root-controls-prefix-and-open", target, [target, root], 0, 0, 6)
        execute("valid-second-root-before-invalid-third", target, [outside, root, "relative"], 1, 128, 0, b"approved")
        nonutf = bytes(root) + b"/raw-\xff-\xfe"
        fd = os.open(nonutf, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        os.write(fd, b"raw name"); os.close(fd)
        execute("non-UTF8-component", nonutf, [root], 2, 128, 0, b"raw name")
        os.mkfifo(root / "fifo", 0o600)
        execute("nonblocking-fifo-refused-as-nonregular", root / "fifo", [root], 1, 128, 15)
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            previous_directory = os.getcwd()
            try:
                os.chdir(root)
                sock.bind("socket")
            finally:
                os.chdir(previous_directory)
            execute("unix-socket-open-refused", root / "socket", [root], 1, 128, 13)
        finally:
            sock.close()
        target.chmod(0o644)
        execute("private-world-readable-refused", target, [root], 2, 128, 9)
        execute("ordinary-world-readable-admitted", target, [root], 1, 128, 0, b"approved")
        target.chmod(0o600)
        hardlink = root / "hard-link"
        os.link(target, hardlink)
        execute("private-hardlink-refused", target, [root], 2, 128, 9)
        execute("ordinary-hardlink-admitted", target, [root], 1, 128, 0, b"approved")
        hardlink.unlink()
        execute("private-after-unlink-admitted", target, [root], 2, 128, 0, b"approved")
        for mutation, expected_error in (("same-size", 10), ("shrink", 10),
                                          ("append", 10), ("mode", 10), ("hardlink", 10),
                                          ("grow-past-limit", 16)):
            root, target = fixture()
            mutated = []
            def mutate(actor, event, kind=mutation, target=target, root=root):
                if event == "after" and words(actor.workspace, 8, 1)[0] == 7 and not mutated:
                    time.sleep(0.03)
                    if kind == "same-size":
                        target.write_bytes(b"CHANGED!")
                    elif kind == "shrink":
                        target.write_bytes(b"short")
                    elif kind == "append":
                        with target.open("ab") as stream: stream.write(b" appended")
                    elif kind == "grow-past-limit":
                        target.write_bytes(b"x" * 129)
                    elif kind == "mode":
                        target.chmod(0o400)
                    elif kind == "hardlink":
                        os.link(target, root / "new-link")
                    mutated.append(kind)
            execute("same-fd-mutation-" + mutation, target, [root], 1, 128,
                    expected_error, hook=mutate)
            assert mutated == [mutation]
        for stage in (1, 2, 4):
            root, target = fixture()
            moved = []
            def replace(actor, event, stage=stage, root=root, target=target):
                if event != "after" or words(actor.workspace, 8, 1)[0] != stage or moved:
                    return
                if stage == 1:
                    old = Path(str(root) + "-held")
                    root.rename(old); root.mkdir(); (root / "sub").mkdir()
                elif stage == 2:
                    (root / "sub").rename(root / "held-sub"); (root / "sub").mkdir()
                else:
                    target.rename(root / "held-file")
                target.write_bytes(b"attacker")
                moved.append(stage)
            execute("held-descriptor-replacement-" + str(stage), target, [root], 1, 128,
                    0, b"approved", hook=replace)
            assert moved == [stage]
        root, target = fixture()
        def pread_and_transfer(actor, raw):
            seq = words(actor.workspace, 16, 1)[0] + 1
            action = b"HRFDAC01" + struct.pack("<11Q", seq, 6, 2, 4096, 3, 2, 0, 0, 0, 0, 0)
            ctypes.memmove(ctypes.addressof(actor.workspace) + 256, action, len(action))
            assert actor.step() == 0
            assert words(actor.workspace, 320, 3) == (seq, 3, 0)
            assert bytes(actor.workspace[4096:4099]) == b"pro"
            fd = actor.take()
            assert fd >= 0 and actor.take() == -22
            try:
                assert os.read(fd, 16) == b"approved", "pread must preserve the stream cursor"
            finally:
                os.close(fd)
        execute("held-FD-pread-and-single-transfer", target, [root], 0, 0, 0, b"", inspect=pread_and_transfer)
        for stop_after in range(13):
            root, target = fixture()
            before = fd_snapshot()
            actor = FileActor(module, engine, path_request(target, [root]), mode=2,
                              maximum=128, capture=capture, label="cancel-" + str(stop_after))
            try:
                code = actor.invoke()
                for _ in range(stop_after):
                    if code != PENDING:
                        break
                    assert actor.step() == 0
                    code = actor.invoke()
                rows.append({"label": "cancel-" + str(stop_after), "native_calls": actor.calls,
                             "native_effects": actor.effects, "code": code})
            finally:
                actor.close()
            assert fd_snapshot() == before
        for at, value in ((256, 0), (264, 0), (272, 99), (280, 3), (288, U64),
                          (296, U64), (304, 0), (312, 1), (320, 1), (328, 1), (336, 1), (344, 1)):
            root, target = fixture()
            before = fd_snapshot()
            actor = FileActor(module, engine, path_request(target, [root]), capture=capture,
                              label="bad-action-" + str(at))
            try:
                assert actor.invoke() == PENDING
                put(actor.workspace, at, value)
                original = bytes(actor.workspace[:actor.wcap])
                assert actor.step() == -22
                assert bytes(actor.workspace[:actor.wcap]) == original
                assert words(ctypes.string_at(actor.context, 128), 56, 1) == (0,)
                rows.append({"label": "bad-action-" + str(at), "result": -22})
            finally:
                actor.close()
            assert fd_snapshot() == before
        for at, value in ((320, 0), (328, 1), (336, 4096), (344, 1), (272, 2), (280, 1)):
            root, target = fixture()
            before = fd_snapshot()
            actor = FileActor(module, engine, path_request(target, [root]), capture=capture,
                              label="bad-ack-" + str(at))
            try:
                assert actor.invoke() == PENDING and actor.step() == 0
                put(actor.workspace, at, value)
                assert actor.invoke() == 0xFFFFFFFF
                rows.append({"label": "bad-ack-" + str(at), "result": 0xFFFFFFFF})
            finally:
                actor.close()
            assert fd_snapshot() == before
        for n, raw in source_pins.items():
            assert Path(n).read_bytes() == raw, n
        report = {"status": "PASS", "cases": len(rows), "raw_state_records": len(capture.rows),
                  "image_sha256": meta["image_sha256"], "source_sha256": meta["source_sha256"],
                  "engine_sha256": a.engine_sha256, "source_bytes_unchanged": True,
                  "all_owned_descriptors_released_or_transferred_once": True,
                  "seconds": time.monotonic() - start, "public_route_qualified": False}
    except BaseException as exc:
        report = {"status": "FAILED", "completed_cases": len(rows), "error": repr(exc),
                  "traceback": traceback.format_exc(), "seconds": time.monotonic() - start,
                  "public_route_qualified": False}
        (out / "terminal.json").write_text(json.dumps(report, sort_keys=True, indent=2) + "\n")
        raise
    finally:
        capture.close()
        engine.close()
        module.close()
        (out / "all-cases.json").write_text(json.dumps(rows, sort_keys=True, indent=2) + "\n")
    (out / "terminal.json").write_text(json.dumps(report, sort_keys=True, indent=2) + "\n")
    print(json.dumps(report, sort_keys=True))


if __name__ == "__main__":
    main()
