#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Export and completely reread ordinary evidence files, including retained failures."""
from __future__ import annotations
from pathlib import Path, PurePosixPath
import argparse
import hashlib
import json
import os
import stat
import sys
import tarfile

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from callable_common import encoded as canonical, decode, pin, require


def verify(archive, index):
    wanted = {row["path"]: row for row in index["files"]}
    require(len(wanted) == len(index["files"]), "duplicate archive index path")
    seen = set()
    dirs=index.get("directories",[])
    require(len({r["path"] for r in dirs})==len(dirs),"duplicate directory index")
    for row in dirs:
        name=PurePosixPath(row["path"])
        require(not name.is_absolute() and ".." not in name.parts and name.as_posix()==row["path"]
            and row["path"] not in wanted and 0<=row["mode"]<=0o777,"directory index path/mode")
    with tarfile.open(archive, "r:gz") as stream:
        for member in stream:
            require(member.isfile() and member.name in wanted and member.name not in seen, "archive member set/type changed")
            name = PurePosixPath(member.name)
            require(not name.is_absolute() and ".." not in name.parts and name.as_posix() == member.name, "archive member path changed")
            seen.add(member.name)
            row = wanted[member.name]
            require(member.size == row["bytes"] and member.mode == row["mode"], "archive size/mode changed")
            file = stream.extractfile(member)
            digest = hashlib.file_digest(file, "sha256").hexdigest()
            require(digest == row["sha256"], "archive complete file bytes changed")
    require(seen == set(wanted), "archive omitted a retained file")
    return dict(status="COMPLETE_ARCHIVE_BYTES_PASS", files=len(wanted), logical_bytes=sum(row["bytes"] for row in wanted.values()), archive=pin(archive))


def pack(source, capture, output, driver_prefix):
    source, capture, output = Path(source).resolve(strict=True), Path(capture).absolute(), Path(output).absolute()
    require(not output.exists(), "archive output must be fresh")
    output.mkdir(parents=True)
    items = []
    directories = []
    roots = [("recipe-source", source)]
    if capture.exists(): roots.append(("capture", capture))
    controls = capture.parent / (capture.name + "-reader-controls")
    if controls.exists(): roots.append(("capture-reader-controls", controls))
    for prefix, root in roots:
        directories.append(dict(path=prefix,mode=root.stat().st_mode&0o777))
        for path in sorted(root.rglob("*")):
            info = path.lstat()
            require(stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode), "non-ordinary evidence file refused")
            if stat.S_ISREG(info.st_mode): items.append((prefix + "/" + path.relative_to(root).as_posix(), path))
            else: directories.append(dict(path=prefix+"/"+path.relative_to(root).as_posix(),mode=info.st_mode&0o777))
    proof = capture.parent / (capture.name + "-readonly.json")
    if proof.exists(): items.append(("capture-readonly.json", proof))
    summary=capture.parent/(capture.name+"-result.json")
    if summary.exists(): items.append(("capture-result.json",summary))
    for suffix in ("stdout", "stderr"):
        path = Path(str(driver_prefix) + "." + suffix)
        if path.exists(): items.append(("driver." + suffix, path))
    require(len({name for name, _ in items}) == len(items), "duplicate export name")
    archive = output / "evidence.tar.gz"
    rows = []
    with tarfile.open(archive, "w:gz", compresslevel=1, format=tarfile.PAX_FORMAT, dereference=True) as stream:
        for name, path in sorted(items):
            before = path.stat()
            require(stat.S_ISREG(before.st_mode), "export input is not a regular file")
            row = dict(path=name, **pin(path), mode=before.st_mode & 0o777, original_mtime_ns=before.st_mtime_ns)
            header = tarfile.TarInfo(name); header.size = row["bytes"]; header.mode = row["mode"]
            header.uid = header.gid = 0
            header.mtime = before.st_mtime_ns // 1000000000
            header.pax_headers = {"mtime": str(before.st_mtime_ns // 1000000000) + "." + f"{before.st_mtime_ns % 1000000000:09d}"}
            with path.open("rb") as file: stream.addfile(header, file)
            after = path.stat()
            require((before.st_dev, before.st_ino, before.st_size, before.st_mode, before.st_mtime_ns, before.st_ctime_ns)
                == (after.st_dev, after.st_ino, after.st_size, after.st_mode, after.st_mtime_ns, after.st_ctime_ns), "export input changed during complete read")
            require(pin(path) == {key: row[key] for key in ("bytes", "sha256")}, "export input changed bytes")
            rows.append(row)
    index = dict(schema="hepta.runtime.text-publisher.archive.v2", files=rows, directories=directories,
                 captured_failure_or_success=True, ordinary_hardlinks_exported_as_complete_files=True)
    (output / "FILES.json").write_bytes(canonical(index))
    result = verify(archive, index)
    (output / "ARCHIVE.json").write_bytes(canonical(result))
    print(json.dumps(result, sort_keys=True))


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("mode", choices=("pack", "verify"))
    p.add_argument("--source", type=Path)
    p.add_argument("--capture", type=Path)
    p.add_argument("--output", required=True, type=Path)
    p.add_argument("--driver-prefix", type=Path)
    a = p.parse_args()
    if a.mode == "pack":
        pack(a.source, a.capture, a.output, a.driver_prefix)
    else:
        value = verify(a.output / "evidence.tar.gz", decode((a.output / "FILES.json").read_bytes()))
        require(value == decode((a.output / "ARCHIVE.json").read_bytes()), "archive receipt changed")
        print(json.dumps(value, sort_keys=True))


if __name__ == "__main__":
    main()
