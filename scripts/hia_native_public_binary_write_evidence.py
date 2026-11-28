#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Compare a real HIA writer with the unmodified current binary helper."""
from pathlib import Path
import argparse
import base64
import hashlib
import itertools
import json
import os
import random
import shutil
import stat
import struct
import subprocess
import sys
import time

sys.dont_write_bytecode = True


def require(value, message):
    if not value:
        raise ValueError(message)


def pin(path):
    raw = path.read_bytes()
    return {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=True) + "\n").encode()


def version(info):
    return ":".join(str(value) for value in (info.st_dev, info.st_ino, info.st_size,
                                           info.st_mtime_ns, info.st_ctime_ns))


def snapshot(root):
    rows, contents = {}, {}
    def visit(folder):
        for path in sorted(folder.iterdir()):
            relative = path.relative_to(root).as_posix()
            info = path.lstat()
            row = {"mode": stat.S_IMODE(info.st_mode), "uid": info.st_uid,
                   "gid": info.st_gid, "nlink": info.st_nlink,
                   "kind": stat.S_IFMT(info.st_mode)}
            if stat.S_ISREG(info.st_mode):
                raw = path.read_bytes()
                contents[relative] = raw
                row.update(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest(),
                           xattrs={name: base64.b64encode(os.getxattr(path, name)).decode()
                                   for name in sorted(os.listxattr(path))})
            elif stat.S_ISLNK(info.st_mode):
                row["target"] = os.readlink(path)
            rows[relative] = row
            if stat.S_ISDIR(info.st_mode):
                visit(path)
    visit(root)
    return rows, contents


CASES = [
    "create_empty", "create_all_bytes", "create_64k", "create_1m",
    "replace", "replace_metadata", "replace_executable", "replace_hardlink",
    "stale_version", "absent_collision", "wrong_missing_version", "empty_version",
    "invalid_base64", "incorrect_padding", "leading_padding", "excess_padding",
    "base64_whitespace", "base64_trailing", "base64_unicode", "base64_nul", "too_large",
    "relative_root", "relative_path", "traversing_root", "traversing_path",
    "outside_root", "root_target", "reserved_target", "nul_name", "nul_parent",
    "missing_parent", "regular_parent", "symlink_parent", "symlink_target",
    "directory_target", "fifo_target", "lock_symlink", "lock_hardlink", "lock_public_mode",
    "unicode_name", "quoted_name", "normalized_path", "name_255", "name_256",
]


def setup(folder, case):
    root = folder / "root"
    root.mkdir(parents=True, mode=0o700)
    destination = root / "output.bin"
    data = b"new\x00bytes\xff\n"
    prior = "absent"
    qroot, qpath = str(root), str(destination)
    if case == "create_empty": data = b""
    if case == "create_all_bytes": data = bytes(range(256))
    if case == "create_64k": data = bytes(range(256)) * 256
    if case == "create_1m": data = bytes(range(256)) * 4096
    if case == "too_large": data = bytes(range(256)) * 4096 + b"!"
    if case.startswith("replace") or case in {"stale_version", "absent_collision"}:
        destination.write_bytes(b"original\x00content\xff")
        destination.chmod(0o640)
        if case == "replace_metadata":
            os.setxattr(destination, "user.hia_native_write", b"value\x00\xff")
            os.setxattr(destination, "user.hia_empty", b"")
        if case == "replace_executable": destination.chmod(0o751)
        if case == "replace_hardlink": os.link(destination, root / "retained-link")
        prior = version(destination.stat())
        if case == "stale_version": prior = "stale"
        if case == "absent_collision": prior = "absent"
    if case == "wrong_missing_version": prior = "stale"
    if case == "empty_version": prior = ""
    if case == "relative_root": qroot = "root"
    if case == "relative_path": qpath = "output.bin"
    if case == "traversing_root": qroot = str(root) + "/../root"
    if case == "traversing_path": qpath = str(root) + "/sub/../output.bin"
    if case == "outside_root": qpath = str(folder / "outside.bin")
    if case == "root_target": qpath = str(root)
    if case == "reserved_target": qpath = str(root / ".hepta-unauthorized")
    if case == "nul_name": qpath = str(root / "nul\x00name")
    if case == "nul_parent": qpath = str(root / "nul\x00parent/output.bin")
    if case == "missing_parent": qpath = str(root / "missing/output.bin")
    if case == "regular_parent":
        (root / "ordinary").write_bytes(b"regular parent")
        qpath = str(root / "ordinary/output.bin")
    if case == "symlink_parent":
        (root / "actual").mkdir()
        (root / "linked").symlink_to("actual", target_is_directory=True)
        qpath = str(root / "linked/output.bin")
    if case == "symlink_target":
        (root / "actual").write_bytes(b"must remain")
        destination.symlink_to("actual")
    if case == "directory_target": destination.mkdir()
    if case == "fifo_target": os.mkfifo(destination, 0o600)
    if case.startswith("lock_"):
        lock = root / (".hepta-lock-" + hashlib.sha256(destination.name.encode()).hexdigest()[:24])
        if case == "lock_symlink":
            (root / "lock-target").write_bytes(b"must remain")
            lock.symlink_to("lock-target")
        elif case == "lock_hardlink":
            lock.write_bytes(b""); lock.chmod(0o600)
            os.link(lock, root / "lock-copy")
        else:
            lock.write_bytes(b""); lock.chmod(0o644)
    if case == "unicode_name": qpath = str(root / "文件-π-😀")
    if case == "quoted_name": qpath = str(root / "quote'\"\\\nend")
    if case == "normalized_path":
        (root / "sub").mkdir()
        qroot = str(root) + "/./"
        qpath = str(root) + "//sub/./output.bin"
    if case == "name_255": qpath = str(root / ("x" * 255))
    if case == "name_256": qpath = str(root / ("x" * 256))
    text = base64.b64encode(data).decode()
    malformed = {"invalid_base64": "%%%", "incorrect_padding": "YQ",
                 "leading_padding": "=YQ==", "excess_padding": "YQ===",
                 "base64_whitespace": "YQ==\n", "base64_trailing": "YQ==AA",
                 "base64_unicode": "你好", "base64_nul": "YQ==\x00"}
    text = malformed.get(case, text)
    q = dict(root=qroot, path=qpath, op="write", expected_version=prior, data_base64=text)
    return q, data


def codec_evidence(source, manifest, python, output):
    sys.path.insert(0, str(source / "scripts"))
    from hia_native_loader import NativeModule
    corpus = ["".join(parts) for size in range(7) for parts in itertools.product("A/=!\n", repeat=size)]
    randomizer = random.Random(0x484941)
    for size in list(range(80)) + [255, 256, 257, 1023, 1024, 1025]:
        valid = base64.b64encode(randomizer.randbytes(size)).decode()
        corpus.extend((valid, valid+"=", valid+"!", valid+"\x00", valid+"A", valid+"é"))
    corpus += ["你好", "😀", "é=", "=é", "A=é", "A=AA", "AAAA=", "AA=A", "AAA=A", "A=!", "AAAAA=!!"]
    payload = json.dumps(corpus, ensure_ascii=True).encode()
    reference = "import base64,json,sys\nout=[]\nfor value in json.load(sys.stdin):\n try:out.append([0,base64.b64encode(base64.b64decode(value,validate=True)).decode()])\n except Exception as exc:out.append([1,type(exc).__name__,str(exc)])\nprint(json.dumps(out))\n"
    result = subprocess.run([str(python), "-I", "-S", "-B", "-c", reference], input=payload,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
    require(result.returncode == 0 and not result.stderr, "original strict-base64 corpus did not complete")
    (output / "codec-input.json").write_bytes(payload)
    (output / "codec-reference.json").write_bytes(result.stdout)
    expected = json.loads(result.stdout)
    observations = []
    require(json.loads(manifest.read_bytes())["source_sha256"] == pin(source/"native/public_binary_base64_decode.hepta")["sha256"],
            "codec manifest does not bind the current HIA source")
    with NativeModule(manifest, manifest_sha256=pin(manifest)["sha256"]) as module:
        for index, (value, wanted) in enumerate(zip(corpus, expected, strict=True)):
            frame = (3549757090987987528).to_bytes(8, "little") + struct.pack("<2Q", 4, 0) + value.encode()
            capacity = 256 + len(frame)
            code, out, work = module.invoke_raw(frame, output_capacity=capacity, workspace_capacity=0,
                                                output_fill=0xb3, workspace_fill=0xc7)
            if wanted[0] == 0:
                data = base64.b64decode(wanted[1])
                header = struct.pack("<8Q", 3544386040927240776, 0, 0, 0, 0, 0, 0, len(data))
            else:
                data = wanted[2].encode()
                header = struct.pack("<8Q", 3544386040927240776, 3, 0,
                                     1 if wanted[1] == "ValueError" else 15, 0, len(data), 0, len(data))
            extent = 64 + len(data)
            same = code == extent and out[:extent] == header+data and out[extent:] == bytes([0xb3])*(capacity-extent) and work == b""
            observations.append(dict(index=index, returncode=code, expected_extent=extent,
                                     output_sha256=hashlib.sha256(out).hexdigest(), pass_=same))
            if not same:
                (output / "codec-mismatch.json").write_bytes(encoded(dict(index=index,input=value,expected=wanted,code=code,
                    actual_base64=base64.b64encode(out).decode())))
                raise ValueError("actual strict-base64 codec differs at corpus index " + str(index))
        short_cases = ["", "YQ==", "YQ===", "YQ==!", "你好"]
        for value in short_cases:
            index = corpus.index(value) if value in corpus else None
            if index is None:
                wanted = [0, "YQ=="] if value == "YQ==" else [1,"Error","Excess padding not allowed"] if value == "YQ===" else [1,"Error","Only base64 data is allowed"]
            else: wanted = expected[index]
            length = len(base64.b64decode(wanted[1])) if wanted[0] == 0 else len(wanted[2].encode())
            capacity = 63 + length
            frame = (3549757090987987528).to_bytes(8, "little") + struct.pack("<2Q",4,0) + value.encode()
            code,out,work = module.invoke_raw(frame,output_capacity=capacity,workspace_capacity=0,output_fill=0xb3)
            require(code == 0xfffffffe and out == bytes([0xb3])*capacity and work == b"", "codec short output mutated or differed")
    (output / "codec-observations.json").write_bytes(encoded(observations))
    report = dict(status="PASS", actual_reference_cases=len(corpus), short_capacity_cases=len(short_cases),
                  all_complete_header_payload_and_tail_bytes_equal=True, manifest=pin(manifest),
                  records={name:pin(output/name) for name in ("codec-input.json","codec-reference.json","codec-observations.json")})
    (output / "CODEC.json").write_bytes(encoded(report))
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("source", "executable", "python", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--codec-manifest", type=Path)
    args = parser.parse_args()
    source = args.source.resolve(strict=True)
    executable = args.executable.resolve(strict=True)
    reference_python = args.python.resolve(strict=True)
    output = args.output.absolute()
    require(not output.exists(), "fresh evidence directory required")
    output.mkdir(parents=True)
    bindings = {name: pin(source / name) for name in (
        "src/mcp/runtime/file_metadata.py", "src/mcp/runtime/inode_patch.py", "src/mcp/runtime/binary_file.py",
        "scripts/hia_native_public_binary_write_evidence.py")}
    identity = subprocess.check_output([str(reference_python), "-I", "-S", "-B", "-c",
        "import json,platform,sys;print(json.dumps(dict(version=list(sys.version_info[:3]),system=platform.system(),machine=platform.machine())))"])
    profile = json.loads(identity)
    require(profile == dict(version=[3, 14, 10], system="Linux", machine="x86_64"),
            "exact current reference Python profile differs")
    program = "\n".join((source / "src/mcp/runtime" / name).read_text()
                          for name in ("file_metadata.py", "inode_patch.py", "binary_file.py"))
    os.umask(0o022)
    executable_before = pin(executable)
    codec = codec_evidence(source,args.codec_manifest.resolve(strict=True),reference_python,output) if args.codec_manifest else None
    cases = []
    for case in CASES:
        folder = output / case
        folder.mkdir()
        runs, after_contents = [], []
        for kind in ("original", "native"):
            lane = folder / kind
            lane.mkdir()
            fixture = lane / "fixture"
            fixture.mkdir()
            q, expected_data = setup(fixture, case)
            before, _ = snapshot(fixture)
            (lane / "request.json").write_bytes(encoded(q))
            if kind == "original":
                payload = json.dumps(q, ensure_ascii=True).encode()
                argv = [str(reference_python), "-I", "-S", "-B", "-c", program]
            else:
                fields = [q[name].encode() for name in ("root", "path", "expected_version", "data_base64")]
                payload = b"HBPWQ001" + struct.pack("<11Q", 1, 0, 1, *map(len, fields), 1, 0, 0, sum(map(len, fields))) + b"".join(fields)
                argv = [str(executable)]
            (lane / "stdin.bin").write_bytes(payload)
            began = time.monotonic()
            completed = subprocess.run(argv, input=payload, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
            elapsed = time.monotonic() - began
            (lane / "stdout").write_bytes(completed.stdout)
            (lane / "stderr").write_bytes(completed.stderr)
            after, files = snapshot(fixture)
            after_contents.append(files)
            row = dict(kind=kind, returncode=completed.returncode, seconds=elapsed,
                       stdin=pin(lane / "stdin.bin"), stdout=pin(lane / "stdout"), stderr=pin(lane / "stderr"),
                       stderr_utf8=completed.stderr.decode("utf-8"), before=before, after=after)
            if completed.returncode == 0:
                result = json.loads(completed.stdout)
                target = Path(q["path"])
                actual = target.read_bytes()
                info = target.stat()
                require(actual == expected_data, case + ": complete successful file bytes differ")
                require(result == dict(written=len(actual), size=len(actual), version=version(info),
                    sha256=hashlib.sha256(actual).hexdigest(), mode=stat.S_IMODE(info.st_mode)),
                    case + ": result differs from actual final file stat/content")
                row.update(result=result, actual_version_verified=True)
            else:
                require(completed.returncode == 1 and completed.stdout == b"", case + ": original error delivery differs")
            require(not any(Path(name).name.startswith(".hepta-write-") for name in after),
                    case + ": unpublished temporary file remains")
            (lane / "RUN.json").write_bytes(encoded(row))
            runs.append(row)
        same_error = (runs[0]["returncode"] == runs[1]["returncode"]
                      and runs[0]["stderr_utf8"] == runs[1]["stderr_utf8"])
        same_result = True
        if runs[0]["returncode"] == 0 and runs[1]["returncode"] == 0:
            same_result = ({k:v for k,v in runs[0]["result"].items() if k != "version"}
                           == {k:v for k,v in runs[1]["result"].items() if k != "version"})
        same_files = runs[0]["before"] == runs[1]["before"] and runs[0]["after"] == runs[1]["after"]
        exact_bytes = after_contents[0] == after_contents[1]
        row = dict(case=case, status="PASS" if same_error and same_result and same_files and exact_bytes else "HOLD",
                   exact_error_bytes=same_error, result_values_equal=same_result,
                   complete_filesystem_equal=same_files, complete_file_bytes_equal=exact_bytes,
                   original_returncode=runs[0]["returncode"], native_returncode=runs[1]["returncode"],
                   original_error=runs[0]["stderr_utf8"], native_error=runs[1]["stderr_utf8"],
                   runs={kind:pin(folder / kind / "RUN.json") for kind in ("original", "native")})
        cases.append(row)
        (output / "CASES.json").write_bytes(encoded(cases))
        print(json.dumps(row, sort_keys=True), flush=True)
        # Retain input, streams and exact inventories; only successful, fully
        # compared disposable fixture contents are removed to bound disk use.
        if row["status"] == "PASS":
            for kind in ("original", "native"):
                shutil.rmtree(folder / kind / "fixture")
    require(bindings == {name:pin(source/name) for name in bindings}, "reference/driver source changed during comparison")
    require(pin(executable) == executable_before, "native executable changed during comparison")
    report = dict(schema="hepta.runtime.public-binary-write.actual-effects.v1",
                  status="PASS" if all(row["status"] == "PASS" for row in cases) else "HOLD",
                  reference_profile=profile, reference_python=pin(reference_python), source=bindings,
                  executable=executable_before, cases=cases, case_count=len(cases),
                  current_base64_codec=codec,
                  actual_helper_executions=2*len(cases), every_success_own_stat_verified=True,
                  complete_file_bytes_compared=True, error_bytes_compared=True,
                  ptrace_fault_campaign_rerun=False, public_mcp_route_executed=False,
                  whole_runtime_replaced=False)
    (output / "EVIDENCE.json").write_bytes(encoded(report))
    require(report["status"] == "PASS", "actual current writer effects differ; complete mismatch evidence retained")


if __name__ == "__main__":
    main()
