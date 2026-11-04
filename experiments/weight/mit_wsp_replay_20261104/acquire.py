# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Acquire pinned public replay inputs; never execute a downloaded file here."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import tempfile
import urllib.request

ROOT = Path(__file__).resolve().parent
REPOSITORIES = {"RikiyaT/lm_understand-logs", "TrillionniumFoundation/hepta-runtime"}


def relative_path(value: str) -> Path:
    path = PurePosixPath(value)
    if not value or path.is_absolute() or ".." in path.parts or "\\" in value:
        raise ValueError("unsafe relative source path")
    return Path(*path.parts)


def manifest() -> dict:
    data = (ROOT / "acquire_manifest.json").read_bytes()
    if len(data) > 128 * 1024:
        raise ValueError("manifest exceeds its budget")
    result = json.loads(data)
    if result["schema"] != "hepta.mit-prescription-replay-acquisition.v1":
        raise ValueError("unsupported acquisition manifest")
    files = result["files"]
    if not 1 <= len(files) <= 64:
        raise ValueError("invalid file count")
    destinations = set()
    for row in files:
        if row["repository"] not in REPOSITORIES:
            raise ValueError("unexpected upstream repository")
        for key, size in [("commit", 40), ("git_blob_sha1", 40), ("sha256", 64)]:
            if not re.fullmatch(r"[0-9a-f]{%d}" % size, row[key]):
                raise ValueError("invalid pinned identity")
        if type(row["bytes"]) is not int or not 0 < row["bytes"] <= 2 * 1024 * 1024:
            raise ValueError("source exceeds its byte budget")
        relative_path(row["path"])
        target = relative_path(row["destination"])
        if target.parts[0] not in {"upstream", "hepta_existing"} or target in destinations:
            raise ValueError("unexpected or repeated destination")
        destinations.add(target)
    if sum(row["bytes"] for row in files) > 8 * 1024 * 1024:
        raise ValueError("acquisition exceeds total byte budget")
    return result


def verify_bytes(data: bytes, row: dict) -> None:
    if len(data) != row["bytes"] or hashlib.sha256(data).hexdigest() != row["sha256"]:
        raise ValueError("source size or SHA256 differs: " + row["destination"])
    blob = hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()
    if blob != row["git_blob_sha1"]:
        raise ValueError("Git blob identity differs: " + row["destination"])


def checked_read(path: Path, row: dict) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise ValueError("expected an ordinary input file: " + str(path))
    with path.open("rb") as handle:
        data = handle.read(row["bytes"] + 1)
    verify_bytes(data, row)
    return data


def install(data: bytes, target: Path, row: dict) -> None:
    verify_bytes(data, row)
    target.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=".download-", dir=target.parent)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        try:
            # Exclusive publication: an existing divergent cache is never replaced.
            os.link(temporary, target)
        except FileExistsError:
            checked_read(target, row)
    finally:
        os.unlink(temporary)


def acquire(from_cache: Path | None, verify_only: bool) -> dict:
    files = manifest()["files"]
    downloaded = imported = reused = 0
    for row in files:
        target = ROOT / relative_path(row["destination"])
        if target.exists() or target.is_symlink():
            checked_read(target, row)
            reused += 1
            continue
        if verify_only:
            raise FileNotFoundError(target)
        if from_cache is not None:
            data = checked_read(from_cache / relative_path(row["destination"]), row)
            imported += 1
        else:
            url = "https://raw.githubusercontent.com/{repository}/{commit}/{path}".format(**row)
            request = urllib.request.Request(url, headers={"User-Agent": "hepta-mit-replay/1", "Accept-Encoding": "identity"})
            with urllib.request.urlopen(request, timeout=30) as response:
                data = response.read(row["bytes"] + 1)
            downloaded += 1
        install(data, target, row)
    return {"verified_files": len(files), "verified_bytes": sum(row["bytes"] for row in files),
            "downloaded": downloaded, "imported_from_cache": imported, "reused": reused,
            "validation": "exact byte length, SHA256 and Git blob SHA1"}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group()
    source.add_argument("--from-cache", type=Path, help="import a previously acquired directory, verifying every pinned byte")
    source.add_argument("--verify-only", action="store_true", help="no network or writes; verify every cached input")
    args = parser.parse_args()
    print(json.dumps(acquire(args.from_cache, args.verify_only), indent=2))


if __name__ == "__main__":
    main()
