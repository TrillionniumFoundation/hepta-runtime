#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Install the exact unsealed D1 C1 preparation once; execute no packaged code."""
import argparse
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import sys
import tarfile

ROOT = Path("/home/qian/hepta-runtime-phase-cost-20261106-d1")
DEST = ROOT / "c1-parent-preparation-05"
RECEIPT = ROOT / "c1-preparation-install-05.json"
ARCHIVE = ROOT / "c1-parent-preparation-05.tar.gz"
MAX_FILE = 4 * 1024 * 1024
MAX_TOTAL = 16 * 1024 * 1024
MAX_FILES = 128
MAX_TAR = MAX_TOTAL + MAX_FILES * 1024 + 10240
EXPECTED_MANIFEST = {"bytes": 13228, "sha256": "40693bc863122eff6c554aa18e4c4394e9a6c17a90753b2761deaa920382c38e"}
EXPECTED_MEMBERS = 43
EXPECTED_PAYLOAD_BYTES = 564059
EXPECTED_ARCHIVE = {'bytes': 158613, 'sha256': 'ad6778f31e7b10caaad3913e8c6368cc09fa6ef6b34c411cdf54a15d8a4e2faf'}


def need(condition, message):
    if not condition:
        raise RuntimeError(message)


def canonical(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + "\n").encode()


def identity(path, raw):
    return {"path": str(path), "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}


def stamp(value):
    return tuple(getattr(value, name) for name in
                 ("st_dev", "st_ino", "st_uid", "st_gid", "st_mode", "st_nlink",
                  "st_size", "st_mtime_ns", "st_ctime_ns"))


def regular(path, maximum=MAX_FILE):
    path = Path(path)
    need(path.is_absolute() and path.resolve() == path, "indirect source path: " + str(path))
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_uid == os.getuid()
             and before.st_nlink == 1 and 0 <= before.st_size <= maximum,
             "unsafe or oversized source: " + str(path))
        chunks, total = [], 0
        while total <= maximum:
            block = os.read(fd, min(1024 * 1024, maximum + 1 - total))
            if not block:
                break
            chunks.append(block)
            total += len(block)
        need(total == before.st_size and total <= maximum
             and stamp(before) == stamp(os.fstat(fd)) == stamp(path.lstat()),
             "source changed while reading: " + str(path))
        return b"".join(chunks)
    finally:
        os.close(fd)


def directory(path, private=False):
    need(path.is_absolute() and path.resolve() == path, "indirect destination directory")
    status = path.lstat()
    need(stat.S_ISDIR(status.st_mode) and status.st_uid == os.getuid()
         and not stat.S_ISLNK(status.st_mode)
         and stat.S_IMODE(status.st_mode) & 0o022 == 0,
         "destination directory is not owned and protected: " + str(path))
    if private:
        need(stat.S_IMODE(status.st_mode) == 0o700, "new destination is not private")
    return status


def sync_directory(path):
    directory(path)
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def write_new(path, raw):
    directory(path.parent)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        view = memoryview(raw)
        while view:
            count = os.write(fd, view)
            need(count > 0, "new file write made no progress")
            view = view[count:]
        os.fsync(fd)
    finally:
        os.close(fd)
    actual = regular(path)
    need(actual == raw, "new file readback differs")
    sync_directory(path.parent)
    return identity(path, actual)


def install(args):
    need(not sys.flags.optimize and sys.platform == "linux" and os.geteuid() == 1000,
         "original non-root x230 operator and normal Python are required")
    need(Path(args.archive) == ARCHIVE, "fixed source archive path is required")
    directory(ROOT)
    archive_raw = regular(ARCHIVE)
    need(len(archive_raw) == EXPECTED_ARCHIVE["bytes"]
         and hashlib.sha256(archive_raw).hexdigest() == EXPECTED_ARCHIVE["sha256"],
         "exact source archive differs")
    with gzip.GzipFile(fileobj=io.BytesIO(archive_raw), mode="rb") as compressed:
        tar_raw = compressed.read(MAX_TAR + 1)
    need(len(tar_raw) <= MAX_TAR, "source archive expansion exceeds the bound")
    members, total = {}, 0
    with tarfile.open(fileobj=io.BytesIO(tar_raw), mode="r:") as archive:
        for item in archive:
            name = item.name
            relative = Path(name)
            need(item.type == tarfile.REGTYPE and not item.pax_headers
                 and not getattr(item, "sparse", None)
                 and not relative.is_absolute() and relative.as_posix() == name
                 and all(part not in {"", ".", ".."} for part in relative.parts)
                 and name not in members and 0 <= item.size <= MAX_FILE,
                 "unsafe, repeated or oversized source member")
            need(len(members) < MAX_FILES, "source member count exceeds the bound")
            stream = archive.extractfile(item)
            need(stream is not None, "regular source member has no body")
            raw = stream.read(item.size + 1)
            need(len(raw) == item.size, "source member length differs")
            total += len(raw)
            need(total <= MAX_TOTAL, "source payload exceeds the total bound")
            members[name] = raw
    need(len(members) == EXPECTED_MEMBERS and total == EXPECTED_PAYLOAD_BYTES,
         "fixed source payload inventory differs")
    manifest_raw = members.get("package-manifest.json", b"")
    need(len(manifest_raw) == EXPECTED_MANIFEST["bytes"]
         and hashlib.sha256(manifest_raw).hexdigest() == EXPECTED_MANIFEST["sha256"],
         "frozen unsealed source manifest differs")
    manifest = json.loads(manifest_raw)
    need(manifest.get("schema") == "hepta-d1-c1-outer-preparation/v1"
         and manifest.get("revision") == "05" and manifest.get("sealed") is False
         and manifest.get("source_only") is True
         and manifest.get("actual_ordinary_result") is None
         and manifest.get("actual_measurement") is None
         and manifest.get("performance_acceptance_claim") is False,
         "only the exact unsealed source preparation may be installed")
    rows = manifest["files"]
    need(type(rows) is list and len(rows) == manifest["file_count"] == EXPECTED_MEMBERS - 1,
         "source manifest count differs")
    expected = {"package-manifest.json"}
    for row in rows:
        name = row["path"]
        need(name not in expected and name in members, "unknown or repeated declared source")
        need(len(members[name]) == row["bytes"]
             and hashlib.sha256(members[name]).hexdigest() == row["sha256"],
             "declared source bytes differ: " + name)
        expected.add(name)
    need(expected == set(members)
         and sum(row["bytes"] for row in rows) == manifest["payload_bytes"],
         "source manifest is incomplete")
    need(not os.path.lexists(DEST) and not os.path.lexists(RECEIPT),
         "source preparation or installation receipt already exists")
    # All source bodies and all destination guards are checked before mutation.
    # Partial failure leaves created originals intact; no cleanup or replay.
    os.umask(0o077)
    DEST.mkdir(mode=0o700)
    directory(DEST, private=True)
    sync_directory(ROOT)
    parents = set()
    for name in members:
        relative = Path(name).parent
        while relative != Path("."):
            parents.add(relative)
            relative = relative.parent
    created = [str(DEST)]
    for relative in sorted(parents, key=lambda path: (len(path.parts), path.as_posix())):
        path = DEST / relative
        path.mkdir(mode=0o700)
        directory(path, private=True)
        sync_directory(path.parent)
        created.append(str(path))
    installed = [write_new(DEST / name, raw) for name, raw in sorted(members.items())]
    need(regular(ARCHIVE) == archive_raw, "source archive changed during installation")
    receipt = {
        "schema": "hepta-d1-c1-source-preparation-install/v1",
        "archive": identity(ARCHIVE, archive_raw),
        "package_manifest": identity(DEST / "package-manifest.json", manifest_raw),
        "destination": str(DEST), "created_directories": created,
        "files": installed, "file_count": len(installed), "payload_bytes": total,
        "installed": True, "actual_source_seal_performed": False,
        "target_imports_or_executions": False, "compiler_or_workload_started": False,
        "ordinary_result_claimed": False, "host_requests": 0, "automatic_retries": 0,
        "existing_ordinary_or_runtime_source_modified": False,
        "partial_failure_policy": "Preserve original native logs and all created paths; do not replay or remove them.",
    }
    receipt_pin = write_new(RECEIPT, canonical(receipt))
    print(json.dumps({"receipt": receipt_pin, "file_count": len(installed),
                      "payload_bytes": total, "source_sealed": False,
                      "compiler_or_workload_started": False}, sort_keys=True), flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", required=True)
    install(parser.parse_args())


if __name__ == "__main__":
    main()
