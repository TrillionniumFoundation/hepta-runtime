"""Compare actual native workdir calls and the unchanged original public method."""
from pathlib import Path
import argparse
import hashlib
import json
import os
import signal
import struct
import subprocess
import time

SHA = lambda raw: hashlib.sha256(raw).hexdigest()


def words(magic, *values):
    return magic + struct.pack("<" + "Q" * len(values), *values)


def encoded(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode()


def framed(rows, variant, mode, legacy):
    result = bytearray()
    for _, params, metadata in rows:
        if variant == "native":
            wire = words(b"HMWDCR01", len(params), int(metadata is not None), len(metadata or b""), 0) + params + (metadata or b"")
        else:
            meta = b"{}" if metadata is None else metadata
            wire = words(b"HMWDRQ01", 1, mode, int(legacy is not None), len(meta), len(legacy or b""), len(params), 0)
            wire += meta + (legacy or b"") + params
        result.extend(struct.pack("<Q", len(wire)) + wire)
    return bytes(result)


def decode(raw, variant):
    result, at = [], 0
    while at < len(raw):
        assert len(raw) - at >= 8
        n = struct.unpack_from("<Q", raw, at)[0]
        assert 0 < n <= 134217792, (variant, at, n)
        at += 8
        frame = raw[at:at + n]
        assert len(frame) == n
        at += n
        if variant == "native":
            assert n >= 96 and frame[:8] == b"HMWDOB01"
            caller_n, latch, state_n = struct.unpack_from("<3Q", frame, 8)
            assert latch <= 1 and n == 32 + caller_n + state_n
            caller = frame[32:32 + caller_n]
            state = frame[32 + caller_n:]
            assert caller[:8] == b"HMWDCS01" and state[:8] == b"HRSWR001"
            tag, zero, text_n = struct.unpack_from("<3Q", caller, 8)
            assert zero == 0 and tag <= 2 and len(caller) == 32 + text_n
            assert struct.unpack_from("<3Q", state, 8) == (1, 0, len(state) - 32)
            current, text = state[32:], caller[32:]
        else:
            assert n >= 56 and frame[:8] == b"HMWDRS01"
            tag, latch, current_n, text_n, normalized_n, zero = struct.unpack_from("<6Q", frame, 8)
            assert tag <= 2 and latch <= 1 and zero == 0
            assert n == 56 + current_n + text_n + normalized_n
            current = frame[56:56 + current_n]
            text = frame[56 + current_n:56 + current_n + text_n]
            frame[56 + current_n + text_n:].decode()
        text.decode()
        result.append((tag, latch, current, text))
    assert at == len(raw)
    return result


def run(variant, executable, root, config, mode, legacy, env, cwd, wire, out):
    argv = [os.fsencode(executable)]
    if config is not None:
        argv += [b"--runtime-config", os.fsencode(config)]
    argv += [b"--session-root", os.fsencode(root)]
    start = time.monotonic()
    snapshot = b""
    if variant == "native":
        read, write = os.pipe2(os.O_CLOEXEC)
        try:
            os.fstat(4)
            reserve = None
        except OSError:
            reserve = os.open("/dev/null", os.O_RDONLY | os.O_CLOEXEC)
            assert reserve == 4
        def arrange():
            os.dup2(read, 4, inheritable=True)
            if read != 4:
                os.close(read)
        try:
            process = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, env=env, cwd=cwd, pass_fds=tuple({read, 4}), preexec_fn=arrange, start_new_session=True)
        except BaseException:
            os.close(write)
            raise
        finally:
            os.close(read)
            if reserve is not None:
                os.close(reserve)
        snapshot = words(b"HMWINIT1", mode, int(legacy is not None), len(legacy or b"")) + (legacy or b"")
        try:
            at = 0
            while at < len(snapshot):
                at += os.write(write, snapshot[at:])
        except BaseException:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGKILL)
            process.wait()
            raise
        finally:
            os.close(write)
    else:
        process = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, env=env, cwd=cwd, start_new_session=True)
    try:
        stdout, stderr = process.communicate(wire, timeout=30)
        timed = False
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGKILL)
        stdout, stderr = process.communicate()
        timed = True
    data = dict(input=wire, stdout=stdout, stderr=stderr, snapshot=snapshot)
    for name, raw in data.items():
        (out / (variant + "." + name)).write_bytes(raw)
    record = dict(variant=variant, pid=process.pid, exit_code=process.returncode, timed_out=timed,
        timeout_seconds=30, elapsed_seconds=time.monotonic() - start, executable_sha256=SHA(Path(executable).read_bytes()),
        argv_hex=[x.hex() for x in argv], root_hex=os.fsencode(root).hex(), cwd_hex=os.fsencode(cwd).hex(),
        streams={name: dict(bytes=len(raw), sha256=SHA(raw)) for name, raw in data.items()})
    (out / (variant + ".json")).write_text(json.dumps(record, sort_keys=True, indent=2) + "\n")
    assert process.returncode == 0 and not timed, (variant, record, stderr[-8000:])
    if variant == "native":
        assert not stderr, stderr
    else:
        bootstrap = json.loads(stderr)
        assert bootstrap["schema"] == "hepta.client-context.actual-sdk-bootstrap.v1", bootstrap
    return decode(stdout, variant), record


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ["native-manifest", "original", "parameter-cases", "output"]:
        parser.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    args.output = args.output.resolve()
    args.output.mkdir(mode=0o700, parents=True, exist_ok=False)
    manifest = args.native_manifest.resolve(strict=True)
    native_info = json.loads(manifest.read_bytes())
    native = manifest.parent / native_info["executable"]
    assert SHA(native.read_bytes()) == native_info["elf_sha256"] and len(native_info["members"]) == 21
    original = args.original.resolve(strict=True)
    fixture = args.output / "fixture"
    fixture.mkdir()
    for name in ["sub", "sub/two", "other", "left|right", " spaced ", 'quote"slash\\line\n\t', "中文🙂"]:
        (fixture / name).mkdir()
    (fixture / "ordinary").write_bytes(b"data")
    (fixture / "link").symlink_to("sub", target_is_directory=True)
    (fixture / "bad-link").symlink_to("missing")
    (fixture / "loop").symlink_to("loop")
    raw_dir = os.fsencode(fixture) + b"/raw-\xff\xed\xa0\x80"
    os.mkdir(raw_dir)
    os.symlink(b"raw-\xff\xed\xa0\x80", os.fsencode(fixture) + b"/link-raw")
    outside = args.output / "outside"
    outside.mkdir()
    allowed = args.output / "allowed.json"
    denied = args.output / "denied.json"
    for path, roots in [(allowed, [str(fixture)]), (denied, [str(outside)])]:
        path.write_bytes(encoded(dict(state_dir=str(args.output / (path.stem + "-state")),
            controller_workspace_roots=roots, hosts={"h": dict(ssh_target="target", remote_state_dir="/remote", allowed_read_path_prefixes=["/work"])})))
        path.chmod(0o600)
    report = dict(schema="hepta.workdir.public-original-comparison.v1", status="FAIL", groups=[], processes=[],
        native_executable_sha256=SHA(native.read_bytes()), original_executable_sha256=SHA(original.read_bytes()),
        native_manifest_sha256=SHA(manifest.read_bytes()), parameter_input_sha256=SHA(args.parameter_cases.read_bytes()),
        actual_original_public_method=True, actual_original_rmcp_context=True, actual_filesystem=True,
        exact_response_bytes_and_raw_session_state=True, remote_execution_qualified=False,
        production_activated=False, whole_runtime_replaced=False, old_stack_removal_qualified=False)
    started = time.monotonic()
    def save():
        (args.output / "result.json").write_text(json.dumps(report, sort_keys=True, indent=2) + "\n")
    def pair(label, rows, *, root=None, config=None, mode=0, legacy=None, user=b"operator", cwd=None):
        directory = args.output / (f"{len(report['groups']):04d}-" + label)
        directory.mkdir(mode=0o700)
        environment = {b"PATH": b""}
        if user is not None:
            environment[b"USER"] = user
        values = {}
        for variant, exe in [("native", native), ("original", original)]:
            wire = framed(rows, variant, mode, legacy)
            values[variant], record = run(variant, exe, fixture if root is None else root, config,
                mode, legacy, environment, fixture if cwd is None else cwd, wire, directory)
            report["processes"].append(record)
            save()
        assert len(values["native"]) == len(values["original"]) == len(rows)
        entries = []
        for (case, params, meta), actual, expected in zip(rows, values["native"], values["original"], strict=True):
            assert actual == expected, (label, case, actual[:3], expected[:3],
                actual[3][:4000], expected[3][:4000])
            tag, latch, current, text = actual
            entries.append(dict(label=case, parameters_bytes=len(params), parameters_sha256=SHA(params),
                metadata_sha256=SHA(meta or b""), tag=tag, latch=latch, current_bytes=len(current),
                current_sha256=SHA(current), text_bytes=len(text), text_sha256=SHA(text), full_bytes_equal=True))
        report["groups"].append(dict(label=label, mode=mode, count=len(rows), directory=directory.name, cases=entries))
        save()
    row = lambda name, value, meta=None: (name, encoded(value), meta)
    reset = row("reset", {"reset": True})
    cap = lambda path: encoded({"experimental": {"session": {"workdir": path}}})
    meta = lambda path: encoded({"io.modelcontextprotocol/clientCapabilities": {"experimental": {"session": {"workdir": path}}}})
    try:
        parameters = json.loads(args.parameter_cases.read_bytes())["cases"]
        pair("complete-typed-public", [(r["label"], r["parameters"].encode(), None) for r in parameters])
        paths = ["sub", "sub/../sub/two", "./sub//two/../", "link", "ordinary", "ordinary/child", "missing", "bad-link", "loop", "x\0y",
            "left|right", " sub ", "   ", "", ".", "..", str(fixture / "sub"), 'quote"slash\\line\n\t', "中文🙂", "link-raw",
            "octofs://blocked", " octofs://blocked ", "sub|other", "|sub", "sub|", "sub||other", " sub | other "]
        for mode in [0, 1]:
            for policy, config in [("absent", None), ("allowed", allowed), ("denied", denied)]:
                rows = []
                for i, path in enumerate(paths):
                    rows += [row("path-" + str(i), {"path": path}), reset]
                rows += [row("reset-null", {"reset": None}), row("reset-false", {"reset": False}),
                    row("reset-path-empty", {"path": "", "reset": True}),
                    row("reset-octofs", {"path": "octofs://blocked", "reset": True}),
                    row("reset-invalid-type", {"path": False, "reset": True})]
                pair("paths-" + policy + "-" + str(mode), rows, mode=mode, config=config)
        whitespace = [9, 10, 11, 12, 13, 32, 0x85, 0xa0, 0x1680, *range(0x2000, 0x200b), 0x2028, 0x2029, 0x202f, 0x205f, 0x3000]
        for config in [None, allowed]:
            rows = []
            for cp in whitespace + [0x180e, 0x200b, 0x2060, 0xfeff]:
                c = chr(cp)
                rows += [row("trim-" + str(cp), {"path": c + "sub" + c}), reset, row("empty-" + str(cp), {"path": c}), reset]
            pair("unicode-trim-" + ("absent" if config is None else "allowed"), rows, config=config)
        current = str(fixture / "sub")
        legacy = cap(current)
        contexts = [
            ("metadata", meta(current), None), ("legacy", None, legacy),
            ("current-empty", b'{"io.modelcontextprotocol/clientCapabilities":{}}', legacy),
            ("current-invalid", b'{"io.modelcontextprotocol/clientCapabilities":false}', legacy),
            ("current-experimental-null", b'{"io.modelcontextprotocol/clientCapabilities":{"experimental":null}}', legacy),
            ("relative", meta("relative"), legacy), ("missing", meta(str(fixture / "missing")), legacy),
            ("file", meta(str(fixture / "ordinary")), legacy),
            ("spelling", meta(str(fixture) + "/sub//two/../"), None),
        ]
        for mode in [0, 1]:
            for policy, config in [("absent", None), ("allowed", allowed), ("denied", denied)]:
                for name, metadata, previous in contexts:
                    rows = [row("invalid-does-not-latch", {"path": False}, metadata),
                        row("valid-context-before-path", {"path": "two"}, metadata),
                        row("reset-retains-root", {"reset": True}, meta(str(outside))),
                        row("later-does-not-change-context", {"path": "sub"}, meta(str(outside)))]
                    pair("context-" + policy + "-" + str(mode) + "-" + name, rows, mode=mode, config=config, legacy=previous)
        for label, root in [("relative-empty", b""), ("relative-dot", b"."), ("relative-sub", b"sub"), ("raw-root", raw_dir)]:
            pair(label, [row("missing", {}), row("same", {"path": "."}), row("parent", {"path": ".."}), reset,
                row("absolute", {"path": str(fixture / "sub")}), reset], root=root)
        for label, user in [("absent", None), ("empty", b""), ("invalid-utf8", b"\xff")]:
            pair("environment-" + label, [row("sub", {"path": "sub"}), reset], user=user)
        # These remote spellings terminate in the actual configured preflight;
        # no remote IO result is simulated or admitted by this local profile.
        remote_rows = [row("remote-" + str(i), {"path": value}) for i, value in enumerate([
            "ssh://unknown/work", "ssh://u@h/work", "ssh://h:22/work", "ssh://h/outside", "sftp://unknown/work", "ssh://h/../outside"])]
        pair("remote-policy-refusals", remote_rows, config=allowed)
        limits = [row("reset", {"reset": True})]
        for n in [255, 256, 4095, 4096, 65535, 1048576, (8 << 20) - len(b'{"path":""}')]:
            limits += [row("long-path-" + str(n), {"path": "x" * n}), reset]
        pair("complete-parameter-domain", limits)
        large_params = b'{"reset":true}' + b" " * ((8 << 20) - len(b'{"reset":true}'))
        large_metadata = b"{}" + b" " * ((8 << 20) - 2)
        large_legacy = b"{}" + b" " * ((8 << 20) - 2)
        for mode in [0, 1]:
            pair("simultaneous-full-domains-" + str(mode), [
                ("full-parameters-metadata-and-legacy", large_params, large_metadata),
                row("following-request-recovers", {"path": "sub"})], mode=mode, legacy=large_legacy)
        report.update(status="PASS", actual_native_processes=sum(p["variant"] == "native" for p in report["processes"]),
            actual_original_processes=sum(p["variant"] == "original" for p in report["processes"]),
            actual_native_requests=sum(g["count"] for g in report["groups"]),
            actual_original_requests=sum(g["count"] for g in report["groups"]), elapsed_seconds=time.monotonic() - started)
    except BaseException as error:
        report["error"] = repr(error)
        raise
    finally:
        save()
    print(json.dumps({k: v for k, v in report.items() if k not in ("groups", "processes")}, sort_keys=True))


if __name__ == "__main__":
    main()
