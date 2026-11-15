"""Preserve complete local view test trees before exporting regular-file evidence."""
from __future__ import annotations
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import struct
from hia_native_result_publication_qualification import decode, exact, require, sha

RECEIPT = "view-call/retired-fixtures.json"
ARCHIVE = "view-call/retired-fixtures.bin.gz"
MAGIC = b"HVFIX001"
FIXTURE = re.compile(r"(?:view-call/caller/files-[0-9]+|view-call/wide/files|"
                     r"view-search/files-(?:100(?:[0-5][0-9]|6[0-3])|20000)|runtime-mcp/files)\Z")
HEX = re.compile(r"(?:[0-9a-f]{2})+\Z")
SHA256 = re.compile(r"[0-9a-f]{64}\Z")


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"),
                       ensure_ascii=True, allow_nan=False) + "\n").encode()


def file_pin(path):
    with path.open("rb") as stream:
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
    return {"sha256": digest, "bytes": path.stat().st_size}


def safe_file(output, name):
    path = output / name
    require(path.resolve() == path.absolute() and not path.is_symlink(),
            "retained fixture artifact crosses a symlink")
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid(),
            "retained fixture artifact is not an owned regular file")
    return path


def fixture_names(fixtures):
    require(type(fixtures) in (tuple, list) and fixtures,
            "fixture retirement requires the exact nonempty directory inventory")
    require(all(type(name) is str and FIXTURE.fullmatch(name) for name in fixtures),
            "fixture retirement path is outside its owned test domain")
    names = list(fixtures)
    exact(names, sorted(set(names)), "fixture retirement directories are duplicated or unordered")
    return names


def record_path(record, fixtures):
    value = record.get("path_hex")
    require(type(value) is str and HEX.fullmatch(value),
            "retained fixture path is not lossless lowercase hex")
    raw = bytes.fromhex(value)
    parts = raw.split(b"/")
    require(not raw.startswith(b"/") and b"\0" not in raw
            and all(part not in (b"", b".", b"..") for part in parts),
            "retained fixture path is not a contained relative path")
    require(any(raw == name.encode() or raw.startswith(name.encode() + b"/") for name in fixtures),
            "retained fixture entry leaves the admitted test trees")
    return Path(os.fsdecode(raw))


def walk_error(error):
    raise error


def snapshot(output, fixtures):
    entries = []
    for name in fixtures:
        top = output / name
        require(top.resolve() == top.absolute() and not top.is_symlink(),
                "fixture retirement root crosses a symlink")
        info = top.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid(),
                "fixture retirement root is not an owned directory")
        paths = [top]
        for base, dirs, files in os.walk(top, followlinks=False, onerror=walk_error):
            paths.extend(Path(base) / child for child in dirs)
            paths.extend(Path(base) / child for child in files)
        for path in paths:
            info = path.lstat()
            require(info.st_uid == os.getuid(), "fixture retirement encountered an unowned entry")
            mode = stat.S_IMODE(info.st_mode)
            require(0 <= mode <= 0o777, "fixture retirement refuses special permission bits")
            entry = {"path_hex": os.fsencode(path.relative_to(output)).hex(), "mode": mode}
            if stat.S_ISDIR(info.st_mode):
                entry["kind"] = "directory"
            elif stat.S_ISLNK(info.st_mode):
                entry.update(kind="symlink", target_hex=os.readlink(os.fsencode(path)).hex())
            elif stat.S_ISREG(info.st_mode):
                entry.update(kind="file", **file_pin(path))
            else:
                raise ValueError("fixture retirement refuses a special file")
            record_path(entry, fixtures)
            entries.append(entry)
    entries.sort(key=lambda entry: entry["path_hex"])
    require(len(entries) == len({entry["path_hex"] for entry in entries}),
            "fixture retirement contains duplicate entries")
    return entries


def exact_read(stream, length):
    raw = stream.read(length)
    require(len(raw) == length, "retained fixture archive is truncated")
    return raw


def verify_archive(output, entries, fixtures, archive):
    require(type(entries) is list and entries, "retained fixture entries are absent")
    require(all(type(entry) is dict for entry in entries), "retained fixture entry is not an object")
    paths = []
    for entry in entries:
        relative = record_path(entry, fixtures)
        paths.append(entry["path_hex"])
        kind = entry.get("kind")
        fields = {"path_hex", "mode", "kind"}
        if kind == "file":
            fields.update(("bytes", "sha256"))
            require(type(entry.get("bytes")) is int and 0 <= entry["bytes"] < 2**64,
                    "retained fixture byte size differs")
            require(type(entry.get("sha256")) is str and SHA256.fullmatch(entry["sha256"]),
                    "retained fixture file digest differs")
        elif kind == "symlink":
            fields.add("target_hex")
            target = entry.get("target_hex")
            require(type(target) is str and HEX.fullmatch(target) and b"\0" not in bytes.fromhex(target),
                    "retained fixture symlink target is not lossless")
        else:
            require(kind == "directory", "retained fixture entry type differs")
        exact(sorted(entry), sorted(fields), "retained fixture entry fields differ")
        require(type(entry["mode"]) is int and 0 <= entry["mode"] <= 0o777,
                "retained fixture permission mode differs")
    exact(paths, sorted(set(paths)), "retained fixture entries are duplicated or unordered")
    directories = {entry["path_hex"] for entry in entries if entry["kind"] == "directory"}
    for name in fixtures:
        require(name.encode().hex() in directories, "retained fixture root is missing")
    roots = {name.encode().hex() for name in fixtures}
    for entry in entries:
        path = record_path(entry, fixtures)
        if entry["path_hex"] not in roots:
            require(os.fsencode(path.parent).hex() in directories,
                    "retained fixture parent directory is missing")
    exact(sorted(archive), ["bytes", "sha256"], "fixture archive identity fields differ")
    require(type(archive["bytes"]) is int and archive["bytes"] >= 0
            and type(archive["sha256"]) is str and SHA256.fullmatch(archive["sha256"]),
            "fixture archive identity types differ")
    archive_path = safe_file(output, ARCHIVE)
    exact(file_pin(archive_path), archive, "complete retained fixture archive bytes differ")
    files = [(index, entry) for index, entry in enumerate(entries) if entry["kind"] == "file"]
    with gzip.open(archive_path, "rb") as stream:
        require(exact_read(stream, len(MAGIC)) == MAGIC, "fixture archive magic differs")
        exact(struct.unpack("<Q", exact_read(stream, 8))[0], len(files),
              "fixture archive file count differs")
        for index, entry in files:
            exact(struct.unpack("<2Q", exact_read(stream, 16)), (index, entry["bytes"]),
                  "fixture archive frame identity differs")
            remaining, digest = entry["bytes"], hashlib.sha256()
            while remaining:
                raw = exact_read(stream, min(remaining, 1 << 20))
                digest.update(raw)
                remaining -= len(raw)
            require(digest.hexdigest() == entry["sha256"],
                    "complete retained fixture file content differs")
        require(stream.read(1) == b"", "fixture archive contains extra payload")
    return {"entries": len(entries), "regular_files": len(files),
            "content_bytes": sum(entry["bytes"] for _, entry in files),
            "symlinks": sum(entry["kind"] == "symlink" for entry in entries)}


def retire_fixtures(output, fixtures, evidence, *, create=False):
    """Retire only suite-owned trees after their complete native evidence passed."""
    output = Path(output).absolute()
    require(output.resolve(strict=True) == output and not output.is_symlink()
            and output.is_dir() and output.stat().st_uid == os.getuid(),
            "fixture evidence root is not an owned real directory")
    fixtures = fixture_names(fixtures)
    expected = {"schema": "hepta.runtime.local-view-fixture-retirement.v1", "status": "PASS",
                "fixture_directories": fixtures,
                "complete_evidence_sha256": sha(encoded(evidence)), "semantic_invocations_added": 0}
    receipt = output / RECEIPT
    require(not receipt.is_symlink() and receipt.parent.resolve() == receipt.parent.absolute(),
            "fixture retirement receipt crosses a symlink")
    if not receipt.exists():
        require(create, "complete fixture retirement receipt is missing")
        require(shutil.rmtree.avoids_symlink_attacks, "fd-bound fixture retirement is unavailable")
        entries = snapshot(output, fixtures)
        receipt.parent.mkdir(parents=True, exist_ok=True)
        archive = output / ARCHIVE
        require(not archive.is_symlink(), "fixture retirement archive is a symlink")
        with archive.open("xb") as raw:
            with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as stream:
                stream.write(MAGIC)
                stream.write(struct.pack("<Q", sum(entry["kind"] == "file" for entry in entries)))
                for index, entry in enumerate(entries):
                    if entry["kind"] != "file":
                        continue
                    stream.write(struct.pack("<2Q", index, entry["bytes"]))
                    path = output / record_path(entry, fixtures)
                    require(path.resolve() == path.absolute() and not path.is_symlink(),
                            "fixture file changed into an alias before retention")
                    with path.open("rb") as content:
                        shutil.copyfileobj(content, stream, length=1 << 20)
            raw.flush()
            os.fsync(raw.fileno())
        archive_pin = file_pin(archive)
        verify_archive(output, entries, fixtures, archive_pin)
        exact(snapshot(output, fixtures), entries, "fixture trees changed before retirement")
        descriptor = os.open(output, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            for name in fixtures:
                shutil.rmtree(name, dir_fd=descriptor)
        finally:
            os.close(descriptor)
        with receipt.open("xb") as stream:
            stream.write(encoded(dict(expected, entries=entries, archive=archive_pin)))
            stream.flush()
            os.fsync(stream.fileno())
    raw = safe_file(output, RECEIPT).read_bytes()
    value = decode(raw)
    require(type(value) is dict, "fixture retirement receipt is not an object")
    exact(sorted(value), sorted((*expected, "entries", "archive")),
          "fixture retirement receipt fields differ")
    exact({key: value[key] for key in expected}, expected,
          "fixture retirement is not bound to the complete admitted execution evidence")
    counts = verify_archive(output, value["entries"], fixtures, value["archive"])
    require(all(not (output / name).exists() and not (output / name).is_symlink() for name in fixtures),
            "retired fixture directory reappeared")
    return dict(expected, **counts, artifact_sha256={
        RECEIPT: sha(raw), ARCHIVE: value["archive"]["sha256"]})
