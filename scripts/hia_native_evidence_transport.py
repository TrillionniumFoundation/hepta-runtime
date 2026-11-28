#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Lossless transport of the already admitted, regular-file native evidence tree.

Every original path remains in both complete inventories. Equal file bytes share
one compressed transport object; unrelated files regain separate inodes. The
producer's quiet physical tree is checked before and after packing. Restoration
uses owned directory descriptors, never tar extraction, and verifies the full
restored inventory before the original qualification readers execute.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import tarfile
import tempfile
import time

SCHEMA = "hepta.runtime.native-evidence-transport.v1"
CHUNK = 1 << 20
EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()
META_KEYS = ("dev", "inode", "mode", "uid", "gid", "nlink", "size", "mtime_ns", "ctime_ns")
ROW_KEYS = {"kind", "mode", "bytes", "sha256", "mtime_ns", "hardlink_to"}


def encode(value):
    return (json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"),
                       allow_nan=False) + "\n").encode()


def unique_json(raw):
    def unique(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError("duplicate JSON field: " + key)
            value[key] = item
        return value
    value = json.loads(raw, object_pairs_hook=unique)
    if encode(value) != raw:
        raise ValueError("noncanonical inventory JSON")
    return value


def metadata(info):
    return {"dev": info.st_dev, "inode": info.st_ino, "mode": info.st_mode,
            "uid": info.st_uid, "gid": info.st_gid, "nlink": info.st_nlink,
            "size": info.st_size, "mtime_ns": info.st_mtime_ns, "ctime_ns": info.st_ctime_ns}


def sha256_stream(stream):
    digest = hashlib.sha256()
    size = 0
    for chunk in iter(lambda: stream.read(CHUNK), b""):
        digest.update(chunk)
        size += len(chunk)
    return size, digest.hexdigest()


def relative_name(name):
    if (not isinstance(name, str) or not name or name.startswith("/")
            or "\0" in name or any(part in ("", ".", "..") for part in name.split("/"))):
        raise ValueError("unsafe evidence member path")
    return name.split("/")


def digest_text(value):
    return isinstance(value, str) and len(value) == 64 and all(c in "0123456789abcdef" for c in value)


def binding(runtime_sha, invocation, native_sha256):
    if (not isinstance(runtime_sha, str) or len(runtime_sha) != 40
            or any(c not in "0123456789abcdef" for c in runtime_sha)
            or not isinstance(invocation, str) or not invocation
            or "\n" in invocation or "\r" in invocation or "\0" in invocation
            or not digest_text(native_sha256)):
        raise ValueError("invalid source, invocation or original native seal binding")
    return {"runtime_sha": runtime_sha, "invocation": invocation, "native_sha256": native_sha256}


@contextmanager
def directory(path):
    path = Path(path).absolute()
    before = path.lstat()
    if (path.resolve(strict=True) != path or not stat.S_ISDIR(before.st_mode)
            or before.st_uid != os.getuid()):
        raise ValueError("evidence directory must be physical and owned")
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        if metadata(os.fstat(descriptor)) != metadata(before):
            raise ValueError("evidence directory changed before open")
        yield descriptor
    finally:
        os.close(descriptor)


@contextmanager
def parent_descriptor(root, name):
    parts = relative_name(name)
    descriptor = os.dup(root)
    try:
        for part in parts[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                            dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        yield descriptor, parts[-1]
    finally:
        os.close(descriptor)


@contextmanager
def regular_file(parent, name, expected=None):
    before = os.stat(name, dir_fd=parent, follow_symlinks=False)
    if not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid():
        raise ValueError("evidence member must be an owned regular file")
    if expected is not None and metadata(before) != expected:
        raise ValueError("captured source identity changed before open")
    descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK,
                         dir_fd=parent)
    with os.fdopen(descriptor, "rb") as stream:
        if metadata(os.fstat(descriptor)) != metadata(before):
            raise ValueError("evidence file changed before open")
        yield stream
        if (metadata(os.fstat(descriptor)) != metadata(before)
                or metadata(os.stat(name, dir_fd=parent, follow_symlinks=False)) != metadata(before)):
            raise ValueError("evidence file changed during capture")


def inventory(root, context):
    entries, captures, links = {}, {}, {}

    def walk(descriptor, prefix):
        before = os.fstat(descriptor)
        key = prefix or "."
        captures[key] = metadata(before)
        entries[key] = {"kind": "directory", "mode": stat.S_IMODE(before.st_mode),
                        "bytes": 0, "sha256": EMPTY_SHA256, "mtime_ns": before.st_mtime_ns,
                        "hardlink_to": None}
        for name in sorted(os.listdir(descriptor), key=os.fsencode):
            relative = prefix + "/" + name if prefix else name
            relative_name(relative)
            info = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
            if info.st_uid != os.getuid():
                raise ValueError("evidence member is not owned: " + relative)
            if stat.S_ISDIR(info.st_mode):
                child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                                dir_fd=descriptor)
                try:
                    if metadata(os.fstat(child)) != metadata(info):
                        raise ValueError("evidence directory changed before descent")
                    walk(child, relative)
                finally:
                    os.close(child)
                if metadata(os.stat(name, dir_fd=descriptor, follow_symlinks=False)) != metadata(info):
                    raise ValueError("evidence directory changed during capture")
            elif stat.S_ISREG(info.st_mode):
                with regular_file(descriptor, name, metadata(info)) as stream:
                    size, digest = sha256_stream(stream)
                if size != info.st_size:
                    raise ValueError("evidence member size changed")
                captures[relative] = metadata(info)
                identity = (info.st_dev, info.st_ino)
                previous = links.setdefault(identity, relative)
                entries[relative] = {"kind": "file", "mode": stat.S_IMODE(info.st_mode),
                                     "bytes": size, "sha256": digest, "mtime_ns": info.st_mtime_ns,
                                     "hardlink_to": None if previous == relative else previous}
            else:
                # The original successful native seal already rejects this domain.
                raise ValueError("evidence member is not a regular file or real directory: " + relative)
        if metadata(os.fstat(descriptor)) != metadata(before):
            raise ValueError("evidence directory changed during inventory")

    with directory(root) as descriptor:
        walk(descriptor, "")
    result = {"schema": SCHEMA, "binding": context, "entries": entries, "capture": captures}
    validate(result, context)
    return result


def validate(value, expected):
    if (not isinstance(value, dict) or set(value) != {"schema", "binding", "entries", "capture"}
            or value["schema"] != SCHEMA or value["binding"] != expected):
        raise ValueError("inventory source or invocation binding differs")
    entries, captures = value["entries"], value["capture"]
    if (not isinstance(entries, dict) or not isinstance(captures, dict)
            or set(entries) != set(captures) or "." not in entries):
        raise ValueError("incomplete evidence inventory")
    objects, groups = {}, {}
    for name, row in entries.items():
        if name != ".":
            relative_name(name)
        if not isinstance(row, dict) or set(row) != ROW_KEYS:
            raise ValueError("invalid evidence inventory row")
        if (row["kind"] not in ("directory", "file") or type(row["mode"]) is not int
                or not 0 <= row["mode"] <= 0o7777 or type(row["bytes"]) is not int
                or row["bytes"] < 0 or type(row["mtime_ns"]) is not int
                or not digest_text(row["sha256"])):
            raise ValueError("invalid evidence inventory identity")
        capture = captures[name]
        if (not isinstance(capture, dict) or set(capture) != set(META_KEYS)
                or any(type(capture[k]) is not int for k in META_KEYS)
                or capture["nlink"] < 1 or capture["size"] < 0
                or capture["mtime_ns"] != row["mtime_ns"]
                or stat.S_IMODE(capture["mode"]) != row["mode"]):
            raise ValueError("invalid physical evidence capture")
        if name != ".":
            parent = name.rpartition("/")[0] or "."
            if parent not in entries or entries[parent].get("kind") != "directory":
                raise ValueError("undeclared or non-directory evidence ancestor")
        if row["kind"] == "directory":
            if (not stat.S_ISDIR(capture["mode"]) or row["bytes"] != 0
                    or row["sha256"] != EMPTY_SHA256 or row["hardlink_to"] is not None):
                raise ValueError("invalid directory inventory")
        else:
            if name == "." or not stat.S_ISREG(capture["mode"]) or capture["size"] != row["bytes"]:
                raise ValueError("invalid file inventory")
            previous = objects.setdefault(row["sha256"], row["bytes"])
            if previous != row["bytes"]:
                raise ValueError("same content digest has conflicting sizes")
            link = row["hardlink_to"]
            if link is not None:
                relative_name(link)
                other = entries.get(link)
                if (other is None or other.get("kind") != "file" or other.get("hardlink_to") is not None
                        or link == name or any(other[k] != row[k] for k in
                                               ("mode", "bytes", "sha256", "mtime_ns"))):
                    raise ValueError("invalid original hardlink relation")
                if (captures[link]["dev"], captures[link]["inode"]) != (capture["dev"], capture["inode"]):
                    raise ValueError("hardlink relation differs from physical source")
            representative = link or name
            groups.setdefault((capture["dev"], capture["inode"]), set()).add(representative)
    if entries["."].get("kind") != "directory" or any(len(v) != 1 for v in groups.values()):
        raise ValueError("incomplete original hardlink relation")
    return objects


class HashedReader:
    def __init__(self, stream):
        self.stream, self.digest, self.size = stream, hashlib.sha256(), 0

    def read(self, size=-1):
        data = self.stream.read(size)
        self.digest.update(data)
        self.size += len(data)
        return data


def add_member(archive, name, size, stream):
    member = tarfile.TarInfo(name)
    member.size, member.mode, member.mtime = size, 0o600, 0
    member.uid = member.gid = 0
    member.uname = member.gname = ""
    archive.addfile(member, stream)


def fresh_destination(path):
    path = Path(path).absolute()
    if path.resolve(strict=False) != path or path.exists() or path.is_symlink():
        raise ValueError("fresh physical transport destination required")
    if not path.parent.is_dir() or path.parent.resolve(strict=True) != path.parent:
        raise ValueError("transport destination needs a physical existing parent")
    return path


def archive_hash(path):
    with directory(path.parent) as descriptor, regular_file(descriptor, path.name) as stream:
        size, digest = sha256_stream(stream)
    return {"bytes": size, "sha256": digest}


def pack(source, output, context):
    source, output = Path(source).absolute(), fresh_destination(output)
    if output.is_relative_to(source) or source.is_relative_to(output):
        raise ValueError("source and transport destination must be separate")
    output.mkdir(mode=0o700)
    started = time.monotonic()
    (output / "initial.json").write_bytes(encode({"schema": SCHEMA, "status": "INCOMPLETE",
                                                "binding": context}))
    before = inventory(source, context)
    first = encode(before)
    objects = validate(before, context)
    representatives = {}
    for name, row in before["entries"].items():
        if row["kind"] == "file":
            representatives.setdefault(row["sha256"], name)
    target = output / "evidence.tar.gz"
    with directory(source) as root, target.open("xb") as raw:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw, compresslevel=1, mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode="w|", format=tarfile.PAX_FORMAT) as archive:
                add_member(archive, "inventory-before.json", len(first), io.BytesIO(first))
                for digest in sorted(objects):
                    name = representatives[digest]
                    with parent_descriptor(root, name) as (parent, leaf):
                        with regular_file(parent, leaf, before["capture"][name]) as stream:
                            observed = HashedReader(stream)
                            add_member(archive, "objects/" + digest, objects[digest], observed)
                            if observed.size != objects[digest] or observed.digest.hexdigest() != digest:
                                raise ValueError("captured object bytes changed during packing")
                after = inventory(source, context)
                if after != before:
                    raise ValueError("complete source inventory changed during packing")
                last = encode(after)
                add_member(archive, "inventory-after.json", len(last), io.BytesIO(last))
    result = {"schema": SCHEMA, "status": "COMPLETE", "binding": context,
              "archive": {"path": target.name, **archive_hash(target)},
              "inventory_before_sha256": hashlib.sha256(first).hexdigest(),
              "inventory_after_sha256": hashlib.sha256(last).hexdigest(),
              "entries": len(before["entries"]),
              "files": sum(row["kind"] == "file" for row in before["entries"].values()),
              "logical_bytes": sum(row["bytes"] for row in before["entries"].values()),
              "unique_objects": len(objects), "unique_bytes": sum(objects.values()),
              "source_unchanged": True, "gzip_level": 1, "seconds": time.monotonic() - started}
    (output / "transport.json").write_bytes(encode(result))
    return result


def next_member(archive, name, size=None):
    member = archive.next()
    if (member is None or member.name != name or member.type != tarfile.REGTYPE
            or member.linkname or member.sparse is not None
            or set(member.pax_headers) - {"size"} or member.size < 0
            or (size is not None and member.size != size)):
        raise ValueError("unexpected, duplicate, unsafe or incomplete archive member: " + name)
    return member


def read_member(archive, member):
    stream = archive.extractfile(member)
    if stream is None:
        raise ValueError("archive member has no regular bytes")
    with stream:
        data = stream.read()
    if len(data) != member.size:
        raise ValueError("incomplete archive member bytes")
    return data


def restore_tree(objects, output, value):
    entries = value["entries"]
    output.mkdir(mode=0o700)
    with directory(output) as root:
        directories = sorted((n for n, r in entries.items() if n != "." and r["kind"] == "directory"),
                             key=lambda n: (n.count("/"), os.fsencode(n)))
        for name in directories:
            with parent_descriptor(root, name) as (parent, leaf):
                os.mkdir(leaf, mode=0o700, dir_fd=parent)
        for name, row in entries.items():
            if row["kind"] != "file" or row["hardlink_to"] is not None:
                continue
            with parent_descriptor(root, name) as (parent, leaf):
                descriptor = os.open(leaf, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                                     | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=parent)
                with os.fdopen(descriptor, "wb") as writer:
                    with (objects / row["sha256"]).open("rb") as reader:
                        for data in iter(lambda: reader.read(CHUNK), b""):
                            writer.write(data)
                    writer.flush()
                    os.fchmod(writer.fileno(), row["mode"])
                    os.utime(writer.fileno(), ns=(row["mtime_ns"], row["mtime_ns"]))
        for name, row in entries.items():
            if row["kind"] != "file" or row["hardlink_to"] is None:
                continue
            with parent_descriptor(root, row["hardlink_to"]) as (source_parent, source_leaf):
                with parent_descriptor(root, name) as (parent, leaf):
                    os.link(source_leaf, leaf, src_dir_fd=source_parent, dst_dir_fd=parent,
                            follow_symlinks=False)
        for name in reversed(directories):
            with parent_descriptor(root, name) as (parent, leaf):
                descriptor = os.open(leaf, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
                                     | os.O_CLOEXEC, dir_fd=parent)
                try:
                    os.fchmod(descriptor, entries[name]["mode"])
                    stamp = entries[name]["mtime_ns"]
                    os.utime(descriptor, ns=(stamp, stamp))
                finally:
                    os.close(descriptor)
        os.fchmod(root, entries["."]["mode"])
        os.utime(root, ns=(entries["."]["mtime_ns"], entries["."]["mtime_ns"]))


def unpack(archive_path, output, context, expected_sha256):
    archive_path, output = Path(archive_path).absolute(), fresh_destination(output)
    if not digest_text(expected_sha256):
        raise ValueError("expected archive SHA256 is required")
    started = time.monotonic()
    with tempfile.TemporaryDirectory(prefix="hia-evidence-objects-", dir=output.parent) as temporary:
        objects_root = Path(temporary)
        with directory(archive_path.parent) as parent, regular_file(parent, archive_path.name) as raw:
            archive_size, actual_sha256 = sha256_stream(raw)
            if actual_sha256 != expected_sha256:
                raise ValueError("archive differs from the independent producer SHA256")
            raw.seek(0)
            with gzip.GzipFile(fileobj=raw, mode="rb") as compressed:
                with tarfile.open(fileobj=compressed, mode="r|") as archive:
                    first = read_member(archive, next_member(archive, "inventory-before.json"))
                    value = unique_json(first)
                    objects = validate(value, context)
                    for digest in sorted(objects):
                        member = next_member(archive, "objects/" + digest, objects[digest])
                        reader = archive.extractfile(member)
                        if reader is None:
                            raise ValueError("object has no bytes")
                        observed, size = hashlib.sha256(), 0
                        with reader, (objects_root / digest).open("xb") as writer:
                            for data in iter(lambda: reader.read(CHUNK), b""):
                                writer.write(data)
                                observed.update(data)
                                size += len(data)
                        if size != objects[digest] or observed.hexdigest() != digest:
                            raise ValueError("archive object content differs from complete inventory")
                    last = read_member(archive, next_member(archive, "inventory-after.json", len(first)))
                    after = unique_json(last)
                    validate(after, context)
                    if after != value:
                        raise ValueError("producer before and after inventories differ")
                    if archive.next() is not None:
                        raise ValueError("unexpected archive member after complete inventory")
                    padding = 0
                    for data in iter(lambda: archive.fileobj.read(CHUNK), b""):
                        padding += len(data)
                        if padding > tarfile.RECORDSIZE or any(data):
                            raise ValueError("unexpected bytes after complete tar archive")
            raw.seek(0)
            final_size, final_sha256 = sha256_stream(raw)
            if (final_size, final_sha256) != (archive_size, actual_sha256):
                raise ValueError("archive changed during restoration")
        restore_tree(objects_root, output, value)
    restored = inventory(output, context)
    if restored["entries"] != value["entries"]:
        raise ValueError("restored complete evidence inventory differs")
    return {"schema": SCHEMA, "status": "RESTORED", "binding": context,
            "archive_sha256": actual_sha256, "inventory_sha256": hashlib.sha256(first).hexdigest(),
            "entries": len(value["entries"]), "files": sum(r["kind"] == "file" for r in value["entries"].values()),
            "logical_bytes": sum(r["bytes"] for r in value["entries"].values()),
            "complete_inventory_verified": True, "seconds": time.monotonic() - started}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("pack", "unpack"))
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--runtime-sha", required=True)
    parser.add_argument("--invocation", required=True)
    parser.add_argument("--native-sha256", required=True)
    parser.add_argument("--archive-sha256")
    parser.add_argument("--github-output", type=Path)
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    context = binding(args.runtime_sha, args.invocation, args.native_sha256)
    if args.operation == "pack":
        result = pack(args.source, args.output, context)
    else:
        result = unpack(args.source, args.output, context, args.archive_sha256)
    if args.report:
        with args.report.open("xb") as stream:
            stream.write(encode(result))
    if args.github_output:
        if args.operation != "pack":
            raise ValueError("only the complete producer may publish an archive SHA")
        with args.github_output.open("a") as stream:
            stream.write("sha256=" + result["archive"]["sha256"] + "\n")
            stream.write("inventory_sha256=" + result["inventory_before_sha256"] + "\n")
    print(json.dumps(result, sort_keys=True), flush=True)


if __name__ == "__main__":
    main()
