#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Package only the prepared runtime controls; never install or execute them."""
import hashlib
import io
import json
from pathlib import Path
import stat
import tarfile

HERE = Path(__file__).resolve().parent


def canonical(value):
    return (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()


def identity(raw):
    return {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}


def main():
    paths = [HERE / "materialize_control_inputs.py"]
    for name in ("tools-01", "lifecycle-tools-01", "ci-templates", "input-templates"):
        paths.extend(path for path in (HERE / name).rglob("*") if path.is_file())
    contents = {}
    for path in sorted(paths):
        info = path.lstat()
        assert stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and path.resolve() == path
        name = path.relative_to(HERE).as_posix()
        assert not Path(name).is_absolute() and ".." not in Path(name).parts
        contents[name] = path.read_bytes()
    manifest = {"schema": "hepta-r36-control-package/v1", "workloads_started": 0,
                "qualification_executed": False, "remote_effects": 0,
                "root": "/home/qian/hepta-runtime-optimization-20261106-r36",
                "files": {name: identity(raw) for name, raw in contents.items()}}
    raw = canonical(manifest)
    manifest_path = HERE / "control-package-manifest-01.json"
    manifest_path.write_bytes(raw)
    contents[manifest_path.name] = raw
    archive = HERE.parent / "r36-control-deploy.tar.xz"
    with tarfile.open(archive, "w:xz", preset=6) as stream:
        for name, raw in sorted(contents.items()):
            member = tarfile.TarInfo(name)
            member.mode = 0o600
            member.size = len(raw)
            member.mtime = 0
            stream.addfile(member, io.BytesIO(raw))
    with tarfile.open(archive) as stream:
        members = stream.getmembers()
        assert len(members) == len(contents) and {m.name for m in members} == set(contents)
        for member in members:
            assert member.isfile() and stream.extractfile(member).read() == contents[member.name]
    receipt = {"schema": "hepta-r36-control-package-receipt/v1", "files": len(contents) - 1,
               "manifest": dict(path=str(manifest_path), **identity(raw := manifest_path.read_bytes())),
               "archive": dict(path=str(archive), **identity(archive.read_bytes())),
               "uncompressed_file_bytes": sum(map(len, contents.values())),
               "installed": False, "executed": False}
    (HERE / "package-receipt.json").write_bytes(canonical(receipt))
    print(json.dumps(receipt, sort_keys=True))


if __name__ == "__main__":
    main()
