#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""R28 fixed evidence transport: reviewed descriptors, exact XZ/USTAR; no extraction."""
import base64
import lzma
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import stat
import tarfile

BLOCK = 1024 * 1024
MAX_FILE_BYTES = 2 * 1024**3
MAX_RETAIN_BYTES = 16 * 1024**2
MAX_TREE_FILES = 50000
PRIVATE_MARKERS = (
    b"-----BEGIN OPENSSH PRIVATE KEY-----",
    b"-----BEGIN RSA PRIVATE KEY-----",
    b"-----BEGIN EC PRIVATE KEY-----",
    b"-----BEGIN DSA PRIVATE KEY-----",
    b"-----BEGIN PRIVATE KEY-----",
    b"-----BEGIN ENCRYPTED PRIVATE KEY-----",
)
STAMP_FIELDS = ("st_dev", "st_ino", "st_uid", "st_mode", "st_nlink", "st_size",
                "st_mtime_ns", "st_ctime_ns")


def need(value, reason):
    if not value:
        raise RuntimeError(reason)


def stamp(value):
    return {key: getattr(value, key) for key in STAMP_FIELDS}


def encode(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + "\n").encode()


def direct(path):
    path = Path(path)
    need(path.is_absolute() and path.resolve(strict=True) == path,
         "direct absolute existing path required: " + str(path))
    return path


def safe_name(name):
    path = PurePosixPath(name)
    need(isinstance(name, str) and name and not path.is_absolute()
         and str(path) == name and ".." not in path.parts and "." not in path.parts
         and "\\" not in name and "\x00" not in name,
         "unsafe or noncanonical archive member")
    return name


def create(path, raw):
    path = Path(path)
    direct(path.parent)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
                 | os.O_CLOEXEC, 0o600)
    try:
        with os.fdopen(os.dup(fd), "wb") as output:
            output.write(raw)
            output.flush()
            os.fsync(output.fileno())
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_uid == os.geteuid()
             and before.st_nlink == 1 and stat.S_IMODE(before.st_mode) == 0o600
             and before.st_size == len(raw) and stamp(before) == stamp(path.lstat()),
             "new file identity changed: " + str(path))
    finally:
        os.close(fd)


class StableReader:
    """A single original fd, streaming SHA and optional secret-marker boundary scan."""
    def __init__(self, path, expected=None, scan_private_markers=False):
        self.path = direct(path)
        self.fd = os.open(self.path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
        try:
            self.before = os.fstat(self.fd)
            need(stat.S_ISREG(self.before.st_mode) and self.before.st_uid == os.geteuid()
                 and self.before.st_nlink == 1
                 and not self.before.st_mode & (stat.S_ISUID | stat.S_ISGID)
                 and 0 <= self.before.st_size <= MAX_FILE_BYTES,
                 "unsafe or oversized regular input: " + str(self.path))
            if expected is not None:
                need(expected["source_path"] == str(self.path)
                     and expected["original_identity"] == stamp(self.before),
                     "original input identity differs: " + str(self.path))
            self.expected = expected
            self.digest = hashlib.sha256()
            self.count = 0
            self.header = b""
            self.tail = b""
            self.scan_private_markers = scan_private_markers
            self.finished = False
        except BaseException:
            os.close(self.fd)
            self.fd = None
            raise

    def read(self, size=-1):
        need(self.fd is not None and not self.finished, "reader already finalized")
        # tarfile supplies bounded blocks; never honor an unbounded allocation.
        size = BLOCK if size < 0 else min(size, BLOCK)
        raw = os.read(self.fd, size)
        self.count += len(raw)
        need(self.count <= self.before.st_size, "input grew during streaming")
        self.digest.update(raw)
        if len(self.header) < 4:
            self.header = (self.header + raw)[:4]
        if self.scan_private_markers and raw:
            combined = self.tail + raw
            need(not any(marker in combined for marker in PRIVATE_MARKERS),
                 "private key marker in evidence stream: " + str(self.path))
            self.tail = combined[-(max(map(len, PRIVATE_MARKERS)) - 1):]
        return raw

    def finish(self):
        need(self.fd is not None and not self.finished, "reader already finalized")
        need(self.count == self.before.st_size, "input was not read completely")
        need(stamp(self.before) == stamp(os.fstat(self.fd)) == stamp(self.path.lstat()),
             "input identity changed while streaming: " + str(self.path))
        value = {"source_path": str(self.path), "bytes": self.count,
                 "sha256": self.digest.hexdigest(), "original_identity": stamp(self.before),
                 "is_elf": self.header == b"\x7fELF"}
        need(self.expected is None or value == self.expected,
             "input contents changed: " + str(self.path))
        self.finished = True
        return value

    def close(self):
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None


def read(path, retain=False, expected=None, scan_private_markers=False):
    stream = StableReader(path, expected, scan_private_markers)
    try:
        need(not retain or stream.before.st_size <= MAX_RETAIN_BYTES,
             "retained metadata exceeds bounded JSON size")
        blocks = []
        while raw := stream.read(BLOCK):
            if retain:
                blocks.append(raw)
        return stream.finish(), b"".join(blocks)
    finally:
        stream.close()


def listing(root):
    root = direct(root)
    before = root.lstat()
    need(stat.S_ISDIR(before.st_mode) and before.st_uid == os.geteuid(), "unsafe input tree")
    files, directories = [], []
    def fail(error):
        raise error
    for current, dirs, names in os.walk(root, followlinks=False, onerror=fail):
        directory = direct(Path(current))
        value = directory.lstat()
        need(stat.S_ISDIR(value.st_mode) and value.st_uid == os.geteuid(), "unsafe directory")
        directories.append(str(directory))
        for name in dirs:
            item = directory / name
            need(not item.is_symlink() and stat.S_ISDIR(item.lstat().st_mode), "unsafe subdirectory")
        for name in names:
            item = directory / name
            need(stat.S_ISREG(item.lstat().st_mode) and not item.is_symlink(), "nonregular evidence file")
            files.append(item)
            need(len(files) <= MAX_TREE_FILES, "file inventory exceeds fixed bound")
    return {"files": sorted(str(path) for path in files), "directories": sorted(directories)}


def expanded_xz(path, expected):
    """One bounded XZ stream with SHA256 check and exact compressed EOF."""
    reader = StableReader(path, expected)
    decoder = lzma.LZMADecompressor(format=lzma.FORMAT_XZ, memlimit=512 * 1024**2)
    pieces, size = [], 0
    try:
        while compressed := reader.read(BLOCK):
            need(not decoder.eof, "trailing or concatenated XZ stream")
            pending = compressed
            while True:
                raw = decoder.decompress(pending, max_length=BLOCK)
                pending = b""
                size += len(raw)
                need(size <= 512 * 1024**2, "expanded fixed evidence archive exceeds bound")
                pieces.append(raw)
                need(not decoder.unused_data, "trailing or concatenated XZ stream")
                if decoder.eof or decoder.needs_input:
                    break
        need(decoder.eof and not decoder.unused_data and decoder.check == lzma.CHECK_SHA256,
             "incomplete XZ end or wrong checksum")
        need(reader.finish() == expected, "compressed archive changed")
    finally:
        reader.close()
    return b"".join(pieces), {"single_xz_stream": True, "sha256_check_verified": True,
                             "exact_compressed_eof": True, "expanded_bytes": size}


def manifest_from_archive(path, manifest_pin):
    expected = read(path)[0]
    expanded, proof = expanded_xz(path, expected)
    with tarfile.open(fileobj=io.BytesIO(expanded), mode="r:") as archive:
        item = archive.next()
        need(item is not None and item.name == "_export-manifest.json"
             and item.type == tarfile.REGTYPE and not item.linkname and not item.pax_headers
             and item.size <= MAX_RETAIN_BYTES, "missing bounded original embedded manifest")
        raw = archive.extractfile(item).read()
    need({"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()} == manifest_pin,
         "original embedded manifest identity differs")
    need(read(path)[0] == expected, "archive changed while reading embedded manifest")
    return raw


def verify_archive(path, manifest_raw, files):
    """Check every canonical regular member and zero tar tail; never extract code."""
    before = read(path)[0]
    expanded, xz_proof = expanded_xz(path, before)
    seen = []
    with tarfile.open(fileobj=io.BytesIO(expanded), mode="r:") as archive:
        for item in archive.getmembers():
            name = safe_name(item.name)
            need(name not in seen and item.type == tarfile.REGTYPE and not item.linkname
                 and not item.pax_headers and item.mode == 0o600
                 and item.uid == item.gid == item.mtime == 0
                 and item.uname == item.gname == "", "noncanonical or duplicate archive member")
            seen.append(name)
            expected = ({"bytes": len(manifest_raw), "sha256": hashlib.sha256(manifest_raw).hexdigest()}
                        if name == "_export-manifest.json" else files[name])
            need(item.size == expected["bytes"], "archive member size differs")
            source = archive.extractfile(item)
            need(source is not None, "missing regular member stream")
            digest, size = hashlib.sha256(), 0
            while raw := source.read(BLOCK):
                digest.update(raw)
                size += len(raw)
                need(size <= expected["bytes"], "oversized archive member")
            need(size == expected["bytes"] and digest.hexdigest() == expected["sha256"],
                 "archive member contents differ: " + name)
        need(seen == ["_export-manifest.json"] + sorted(files), "archive order or inventory differs")
        need(len(expanded[archive.offset:]) >= 1024 and not any(expanded[archive.offset:]),
             "invalid tar end or nonzero trailing body")
    need(read(path)[0] == before, "archive changed during verification")
    return {"verified": True, "regular_members": len(seen), "identity": before,
            "xz_integrity": xz_proof, "archive_code_executed": False, "archive_extracted": False}




def write_archive(path, manifest, files, secret_prefixes=()):
    direct(Path(path).parent)
    manifest_raw = encode(manifest)
    need(len(manifest_raw) <= MAX_RETAIN_BYTES, "manifest exceeds metadata bound")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        with os.fdopen(os.dup(fd), "wb") as destination:
            with lzma.LZMAFile(destination, mode="wb", format=lzma.FORMAT_XZ,
                               check=lzma.CHECK_SHA256, preset=6) as zipped:
                with tarfile.open(fileobj=zipped, mode="w|", format=tarfile.USTAR_FORMAT) as archive:
                    member = tarfile.TarInfo("_export-manifest.json")
                    member.size, member.mode, member.mtime = len(manifest_raw), 0o600, 0
                    archive.addfile(member, io.BytesIO(manifest_raw))
                    for name, expected in sorted(files.items()):
                        safe_name(name)
                        need(name != "_export-manifest.json", "reserved archive member name")
                        reader = StableReader(expected["source_path"], expected, name.startswith(secret_prefixes))
                        try:
                            member = tarfile.TarInfo(name)
                            member.size, member.mode, member.mtime = expected["bytes"], 0o600, 0
                            archive.addfile(member, reader)
                            reader.finish()
                        finally:
                            reader.close()
            destination.flush()
            os.fsync(destination.fileno())
        need(stamp(os.fstat(fd)) == stamp(Path(path).lstat()), "archive destination replaced")
    finally:
        os.close(fd)
    return manifest_raw, verify_archive(path, manifest_raw, files)


def transfer_chunks(archive, output):
    expected = read(archive)[0]
    directory = output / (Path(archive).name + ".chunks")
    directory.mkdir(mode=0o700)
    reader = StableReader(archive, expected)
    rows, offset = [], 0
    try:
        while raw := reader.read(48000):
            text = base64.b64encode(raw)
            need(len(text) <= 64000, "chunk text exceeds transfer bound")
            path = directory / f"chunk-{len(rows):05d}.b64"
            create(path, text)
            rows.append({"path": str(path), "offset": offset, "bytes": len(raw),
                         "sha256": hashlib.sha256(raw).hexdigest(), "base64_bytes": len(text),
                         "base64_sha256": hashlib.sha256(text).hexdigest()})
            offset += len(raw)
        reader.finish()
    finally:
        reader.close()
    value = {"schema": "hepta-r28-lossless-archive-chunks/v1", "archive": expected,
             "encoding": "base64", "maximum_decoded_chunk_bytes": 48000,
             "maximum_text_file_bytes": 64000, "chunks": rows}
    path = directory / "manifest.json"
    create(path, encode(value))
    need(read(archive)[0] == expected, "archive changed during transfer encoding")
    return {"manifest": read(path)[0], "archive": expected, "chunks": len(rows)}
