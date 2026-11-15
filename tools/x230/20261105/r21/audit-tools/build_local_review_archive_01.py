#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Pack one exact, preselected local review inventory after its writers stop."""
import argparse
import gzip
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import stat
import tarfile


def digest(data):
    return hashlib.sha256(data).hexdigest()


def identity(data):
    return {"size": len(data), "sha256": digest(data), "git_blob_sha1":
            hashlib.sha1(("blob " + str(len(data)) + "\0").encode() + data).hexdigest()}


def stable_bytes(path):
    assert path.is_absolute() and path.resolve() == path
    before = path.lstat()
    assert stat.S_ISREG(before.st_mode) and before.st_nlink == 1
    fields = ("st_dev", "st_ino", "st_mode", "st_uid", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns")
    with path.open("rb") as stream:
        assert all(getattr(before, k) == getattr(os.fstat(stream.fileno()), k) for k in fields)
        data = stream.read()
        assert all(getattr(before, k) == getattr(os.fstat(stream.fileno()), k) for k in fields)
    after = path.lstat()
    assert len(data) == before.st_size and all(getattr(before, k) == getattr(after, k) for k in fields)
    return data, before


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inventory", type=Path, required=True)
    parser.add_argument("--expected-inventory-sha256", required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    inventory_bytes, _ = stable_bytes(args.inventory.absolute())
    assert digest(inventory_bytes) == args.expected_inventory_sha256
    inventory = json.loads(inventory_bytes)
    assert inventory["writers_stopped"] is True
    rows = inventory["files"]
    assert rows and len({r["archive_member"] for r in rows}) == len(rows)
    captured = {}
    for row in rows:
        name = PurePosixPath(row["archive_member"])
        assert name.as_posix() == row["archive_member"] and not name.is_absolute()
        assert ".." not in name.parts and str(name) != "_local-review-manifest.json"
        raw, before = stable_bytes(Path(row["source"]))
        assert identity(raw) == row["identity"]
        captured[str(name)] = (raw, stat.S_IMODE(before.st_mode))
    manifest = {"schema": "hepta-r21-exact-local-review-archive/v1",
                "inventory_sha256": args.expected_inventory_sha256,
                "scope": inventory["scope"], "files": rows,
                "exclusions": inventory["exclusions"], "writers_stopped": True}
    manifest_bytes = (json.dumps(manifest, sort_keys=True, indent=2) + "\n").encode()
    output = args.out.absolute()
    assert output.resolve() == output and not os.path.lexists(output)
    os.umask(0o077)
    output.mkdir(mode=0o700)
    archive = output / "local-review-01.tar.gz"
    with archive.open("xb") as raw, gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as zipped:
        with tarfile.open(mode="w|", fileobj=zipped, format=tarfile.PAX_FORMAT) as tar:
            for name, (data, mode) in sorted(captured.items()):
                item = tarfile.TarInfo(name)
                item.size, item.mode, item.mtime = len(data), mode, 0
                tar.addfile(item, io.BytesIO(data))
            item = tarfile.TarInfo("_local-review-manifest.json")
            item.size, item.mode, item.mtime = len(manifest_bytes), 0o600, 0
            tar.addfile(item, io.BytesIO(manifest_bytes))
    with tarfile.open(archive, "r:gz") as tar:
        members = tar.getmembers()
        assert len(members) == len(captured) + 1 and all(m.isfile() for m in members)
        assert len({m.name for m in members}) == len(members)
        assert {m.name for m in members} == set(captured) | {"_local-review-manifest.json"}
        for member in members:
            expected = manifest_bytes if member.name == "_local-review-manifest.json" else captured[member.name][0]
            assert tar.extractfile(member).read() == expected
    for row in rows:
        assert stable_bytes(Path(row["source"]))[0] == captured[row["archive_member"]][0]
    (output / "manifest.json").write_bytes(manifest_bytes)
    archive_bytes, _ = stable_bytes(archive)
    receipt = {"schema": "hepta-r21-local-review-export-receipt/v1", "passed": True,
               "archive": str(archive), "archive_identity": identity(archive_bytes),
               "manifest_identity": identity(manifest_bytes), "payload_files": len(rows),
               "archive_members": len(rows) + 1, "all_members_reopened_and_compared": True,
               "all_source_bytes_unchanged": True, "workloads_executed": False}
    (output / "receipt.json").write_text(json.dumps(receipt, sort_keys=True, indent=2) + "\n")
    print(json.dumps(receipt))


if __name__ == "__main__":
    main()
