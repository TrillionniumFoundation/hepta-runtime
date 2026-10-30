#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Pack original X230 evidence without executing, retrying or rewriting a test.

--output accepts a new directory (evidence.tar.gz and manifest.json), or a new
*.tar.gz path (with a sibling *.manifest.json). Only selected regular files are
archived. Reports remain byte-for-byte originals, including failures and paths.
No SSH, subprocess, credential/configuration read, or executable loading occurs.
"""
import argparse
from collections import deque
from contextlib import contextmanager
import datetime
import gzip
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys
import tarfile
import tempfile


CHUNK = 1024 * 1024
MAX_JSON = 64 * CHUNK
MAX_FILES = 100_000
MAX_DIRECTORIES = 10_000
SHA = re.compile(r"[0-9a-f]{64}\Z")
DIRECTORY_FIELDS = {"output", "output_dir", "out", "directory", "evidence", "evidence_dir", "remote_out", "native_output"}
EXCLUDED_CLASSES = {
    "elf": "ELF bodies are excluded; original report paths and SHA256 receipts are retained.",
    "duplicate_state_or_fixture": "State/jobs and fixture trees are not traversed or copied; original manifests retain their hashes.",
    "private_configuration": "Profiles, runtime/SSH configuration, known_hosts and key material are excluded.",
    "build_or_source_tree": "Build targets, dependency caches, source trees and copied executable directories are excluded.",
    "non_evidence_file": "Files outside the raw report/log/observation/input-backup selection are excluded.",
    "special_file": "Sockets, devices, FIFOs and other non-regular files are never opened as evidence.",
    "missing_output_directory": "A declared output directory does not exist; its original report is retained without inventing evidence.",
}


def need(condition, message):
    if not condition:
        raise ValueError(message)


def absolute(value, base=None):
    text = os.fspath(value)
    need("\0" not in text and "\\" not in text and ".." not in text.split("/"),
         "noncanonical source path: " + text)
    path = Path(text)
    if not path.is_absolute():
        path = (base or Path.cwd()) / path
    return Path(os.path.abspath(path))


def identity(info):
    return [info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns]


def open_direct(path, directory=False):
    """Walk every component with openat/O_NOFOLLOW, including parent directories."""
    path = absolute(path)
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_DIRECTORY
    current = os.open("/", flags)
    try:
        if path == Path("/"):
            need(directory, "root is not a regular file")
            result, current = current, None
            return result
        for component in path.parts[1:-1]:
            following = os.open(component, flags, dir_fd=current)
            os.close(current)
            current = following
        before = os.stat(path.name, dir_fd=current, follow_symlinks=False)
        need(not stat.S_ISLNK(before.st_mode), "symlink refused: " + str(path))
        wanted = stat.S_ISDIR if directory else stat.S_ISREG
        need(wanted(before.st_mode), "not a direct " + ("directory: " if directory else "regular file: ") + str(path))
        final_flags = flags if directory else os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
        result = os.open(path.name, final_flags, dir_fd=current)
        try:
            need(identity(before) == identity(os.fstat(result)), "path changed during open: " + str(path))
        except BaseException:
            os.close(result)
            raise
        return result
    finally:
        if current is not None:
            os.close(current)


@contextmanager
def regular(path, expected=None):
    fd = open_direct(path)
    with os.fdopen(fd, "rb", buffering=0) as stream:
        before = identity(os.fstat(stream.fileno()))
        if expected is not None:
            need(before == expected, "original file changed since inventory: " + str(path))
        yield stream, before
        after = identity(os.fstat(stream.fileno()))
        current = open_direct(path)
        try:
            need(before == after == identity(os.fstat(current)), "original file changed during read: " + str(path))
        finally:
            os.close(current)


def read_file(path, body=False, exclude_elf=True):
    with regular(path) as (stream, original):
        prefix = stream.read(4)
        if exclude_elf and prefix == b"\x7fELF":
            return {"path": str(path), "bytes": original[6], "identity": original, "elf": True}, None
        stream.seek(0)
        need(not body or original[6] <= MAX_JSON, "core JSON exceeds 64 MiB: " + str(path))
        digest, count, chunks = hashlib.sha256(), 0, []
        while data := stream.read(CHUNK):
            count += len(data)
            need(count <= original[6], "original file grew while reading: " + str(path))
            digest.update(data)
            if body:
                chunks.append(data)
        need(count == original[6], "original file shrank while reading: " + str(path))
        return {"path": str(path), "bytes": count, "sha256": digest.hexdigest(), "identity": original}, b"".join(chunks) if body else None


def document(raw):
    def pairs(items):
        value = {}
        for key, item in items:
            need(key not in value, "duplicate JSON object key: " + key)
            value[key] = item
        return value
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda value: (_ for _ in ()).throw(ValueError("nonfinite JSON: " + value)))


def excluded_path(path):
    parts = [part.lower().replace("_", "-") for part in path.parts[1:]]
    for part in parts:
        if (part in {"state", "jobs", "fixture", "fixtures"}
                or part.endswith(("-state", "-jobs", "-fixtures"))
                or part.startswith(("state-", "fixtures-"))):
            return "duplicate_state_or_fixture"
        if (part in {"profile", "profiles", ".ssh", "known-hosts", "ssh-config", "sshconfig"}
                or part.startswith(("profile.", "profile-", "known-hosts", "ssh-config", "id-ed25519", "id-rsa"))
                or part in {"runtime.json", "runtime-config.json", "config", "config.json"}
                or part.endswith(("-runtime.json", ".pem", ".key"))):
            return "private_configuration"
        if part in {"target", "test-binaries", "src", "source", "sources", ".git", "node-modules", "__pycache__", "cargo-home", "cargo-cache"}:
            return "build_or_source_tree"
    return None


def evidence_name(path):
    name = path.name.lower()
    return (name.endswith((".json", ".jsonl", ".log", ".log.gz", ".jsonl.gz", ".stdout", ".stderr",
                           ".stdout.gz", ".stderr.gz", ".input", ".txt", ".csv", ".out", ".err"))
            or name in {"stdout", "stderr", "denylog"})


def is_core_name(path):
    name = path.name.lower()
    return name.endswith(".json") and any(part in name for part in ("report", "summary", "manifest", "artifacts", "audit"))


def output_reference(path, pointer):
    # Input pin maps can contain private profiles under arbitrary filenames.
    # Preserve those maps as report bytes, without treating them as copy lists.
    fields = set(pointer.lower().split("/"))
    if fields & {"frozen_inputs", "original_inputs", "tools", "helpers", "pinned", "source_map", "harness_map"}:
        return False
    return evidence_name(path)


def safe_member(name):
    path = PurePosixPath(name)
    need(name and "\\" not in name and not path.is_absolute() and ".." not in path.parts
         and "." not in path.parts and str(path) == name, "unsafe archive member: " + name)
    return name


class Collection:
    def __init__(self, inputs, extra_roots):
        self.inputs = inputs
        self.roots = list(dict.fromkeys([item["root"] for item in inputs] + extra_roots))
        for root in self.roots:
            fd = open_direct(root, directory=True)
            os.close(fd)
        self.files, self.exclusions, self.directories, self.expected = {}, {}, {}, {}
        self.queue, self.parsed, self.visited = deque(), set(), set()
        self.artifact_manifests = set()

    def allowed(self, path):
        if any(path.is_relative_to(root) for root in self.roots):
            return True
        parts = path.parts
        return (len(parts) >= 4 and parts[:3] == ("/", "home", "qian")
                and parts[3].startswith("hepta-runtime-optimization-")
                and len(parts[3]) > len("hepta-runtime-optimization-"))

    def require_allowed(self, path):
        need(self.allowed(path), "report reference is outside authorized input roots: " + str(path))

    def exclude(self, path, reason):
        self.exclusions.setdefault(str(path), {"path": str(path), "class": reason})

    def archive_name(self, path, source):
        if path.is_relative_to(source["root"]):
            return safe_member(source["label"] + "/" + path.relative_to(source["root"]).as_posix())
        for index, root in enumerate(self.roots):
            if path.is_relative_to(root):
                return safe_member(source["label"] + f"/references/input-{index:02d}/" + path.relative_to(root).as_posix())
        self.require_allowed(path)
        return safe_member(source["label"] + "/references/" + Path(*path.parts[3:]).as_posix())

    def add_file(self, path, source, core=False, expected=None):
        path = absolute(path)
        reason = excluded_path(path)
        if reason:
            self.exclude(path, reason)
            return
        self.require_allowed(path)
        if expected is not None:
            self.remember_receipt(path, expected, source["report"], "explicit reference")
        if str(path) not in self.files:
            receipt, _ = read_file(path)
            if receipt.pop("elf", False):
                self.exclude(path, "elf")
                self.exclusions[str(path)].update(bytes=receipt["bytes"], identity=receipt["identity"])
                return
            need(len(self.files) < MAX_FILES, "selected evidence exceeds file inventory bound")
            receipt.update(archive_name=self.archive_name(path, source), groups=[source["label"]])
            self.files[str(path)] = receipt
        elif source["label"] not in self.files[str(path)]["groups"]:
            self.files[str(path)]["groups"].append(source["label"])
        if core or is_core_name(path):
            self.queue.append((path, source))

    def walk(self, root, source, declared=False):
        root = absolute(root)
        reason = excluded_path(root)
        if reason:
            self.exclude(root, reason)
            return
        self.require_allowed(root)
        if declared:
            try:
                fd = open_direct(root, directory=True)
            except FileNotFoundError:
                self.exclude(root, "missing_output_directory")
                return
            else:
                os.close(fd)
        pending = [root]
        while pending:
            directory = pending.pop()
            if str(directory) in self.visited:
                continue
            need(len(self.visited) < MAX_DIRECTORIES, "evidence directory inventory exceeds bound")
            fd = open_direct(directory, directory=True)
            try:
                before = identity(os.fstat(fd))
                with os.scandir(fd) as entries:
                    rows = sorted((entry.name, entry.stat(follow_symlinks=False)) for entry in entries)
                need(before == identity(os.fstat(fd)), "directory changed during enumeration: " + str(directory))
            finally:
                os.close(fd)
            self.visited.add(str(directory))
            self.directories[str(directory)] = {"path": str(directory), "identity": before, "group": source["label"]}
            for name, info in rows:
                path = directory / name
                need(not stat.S_ISLNK(info.st_mode), "symlink in evidence tree refused: " + str(path))
                reason = excluded_path(path)
                if reason:
                    self.exclude(path, reason)
                elif stat.S_ISDIR(info.st_mode):
                    pending.append(path)
                elif not stat.S_ISREG(info.st_mode):
                    self.exclude(path, "special_file")
                elif evidence_name(path):
                    self.add_file(path, source)
                else:
                    # ELF detection reads only its prefix; no executable body is hashed or loaded.
                    with regular(path) as (stream, original):
                        elf = stream.read(4) == b"\x7fELF"
                    self.exclude(path, "elf" if elf else "non_evidence_file")
                    self.exclusions[str(path)].update(bytes=original[6], identity=original)

    def remember_receipt(self, path, receipt, origin, pointer):
        if SHA.fullmatch(str(receipt.get("sha256", ""))):
            row = {"report": str(origin), "pointer": pointer, "sha256": receipt["sha256"]}
            for key in ("bytes", "size"):
                if type(receipt.get(key)) is int and receipt[key] >= 0:
                    row["bytes"] = receipt[key]
                    break
            if row not in self.expected.setdefault(str(path), []):
                self.expected[str(path)].append(row)

    def parse_core(self, path, source):
        if str(path) in self.parsed:
            return
        self.parsed.add(str(path))
        actual, raw = read_file(path, body=True, exclude_elf=False)
        need(actual == {key: self.files[str(path)][key] for key in actual}, "core report changed before parsing: " + str(path))
        value = document(raw)
        log_base = path.parent
        if isinstance(value, dict) and isinstance(value.get("evidence"), str) and value["evidence"].startswith("/"):
            log_base = absolute(value["evidence"])
        artifact_manifest = "artifact" in path.name.lower() and path.suffix == ".json"
        if artifact_manifest:
            self.artifact_manifests.add(str(path))
        pending = [(value, "$")]
        while pending:
            node, pointer = pending.pop()
            if isinstance(node, list):
                pending.extend((item, f"{pointer}[{index}]") for index, item in enumerate(node))
                continue
            if not isinstance(node, dict):
                continue
            raw_path = node.get("path")
            if isinstance(raw_path, str) and SHA.fullmatch(str(node.get("sha256", ""))):
                candidate = absolute(raw_path, path.parent)
                self.remember_receipt(candidate, node, path, pointer)
                # Original artifact manifests prove the omitted tree. They do not
                # authorize copying every fixture/state member listed inside it.
                if not artifact_manifest and output_reference(candidate, pointer):
                    self.add_file(candidate, source, core=is_core_name(candidate))
            for key, item in node.items():
                child = pointer + "/" + key
                if isinstance(item, (dict, list)):
                    pending.append((item, child))
                elif isinstance(item, str) and key in DIRECTORY_FIELDS and item.startswith("/") and not artifact_manifest:
                    candidate = absolute(item)
                    self.walk(candidate, source, declared=True)
                elif (isinstance(item, str) and not artifact_manifest
                      and (key in {"original_report", "native_report", "report", "artifact_manifest", "original_artifacts_manifest",
                                   "stdout", "stderr", "stdout_gzip", "stderr_gzip", "source_manifest_path", "artifacts_path"}
                           or key.startswith("hostload_"))
                      and (item.startswith("/") or Path(item).suffix in {".json", ".jsonl", ".gz", ".stdout", ".stderr", ".input"})):
                    candidate = absolute(item, log_base if key.endswith("_gzip") else path.parent)
                    self.add_file(candidate, source, core=is_core_name(candidate))

    def collect(self):
        for source in self.inputs:
            self.add_file(source["report"], source, core=True)
            self.walk(source["root"], source)
        while self.queue:
            self.parse_core(*self.queue.popleft())
        names = [row["archive_name"] for row in self.files.values()]
        need(len(names) == len(set(names)), "archive name collision")
        for path, row in self.files.items():
            originals = self.expected.get(path, [])
            for original in originals:
                need(row["sha256"] == original["sha256"], "included evidence differs from its original report hash: " + path)
                if "bytes" in original:
                    need(row["bytes"] == original["bytes"], "included evidence differs from its original reported size: " + path)
            row["original_receipts"] = originals
        for path, row in self.exclusions.items():
            row["original_receipts"] = self.expected.get(path, [])
        need(self.files, "no original evidence selected")

    def check_directories(self):
        for row in self.directories.values():
            fd = open_direct(row["path"], directory=True)
            try:
                need(identity(os.fstat(fd)) == row["identity"], "evidence directory changed during packaging: " + row["path"])
            finally:
                os.close(fd)


class HashingReader:
    def __init__(self, stream):
        self.stream, self.digest, self.bytes = stream, hashlib.sha256(), 0

    def read(self, length=-1):
        need(0 <= length <= CHUNK, "unbounded archive read requested")
        data = self.stream.read(length)
        self.digest.update(data)
        self.bytes += len(data)
        return data


def write_archive(path, files):
    with path.open("wb") as raw:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw, compresslevel=6, mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode="w|", format=tarfile.PAX_FORMAT) as archive:
                for row in files:
                    with regular(Path(row["path"]), row["identity"]) as (stream, _):
                        reader = HashingReader(stream)
                        info = tarfile.TarInfo(safe_member(row["archive_name"]))
                        info.size, info.mode, info.mtime = row["bytes"], 0o600, 0
                        archive.addfile(info, reader)
                        need(reader.bytes == row["bytes"] and reader.digest.hexdigest() == row["sha256"]
                             and stream.read(1) == b"", "original evidence changed while archiving: " + row["path"])
        raw.flush()
        os.fsync(raw.fileno())


def verify_archive(path, files):
    expected = {row["archive_name"]: row for row in files}
    seen = set()
    raw_before, _ = read_file(path, exclude_elf=False)
    with regular(path, raw_before["identity"]) as (raw, _):
        with gzip.GzipFile(fileobj=raw, mode="rb") as compressed:
            with tarfile.open(fileobj=compressed, mode="r|") as archive:
                for member in archive:
                    name = safe_member(member.name)
                    need(member.isfile() and not member.islnk() and not member.issym(), "non-regular archive entry")
                    need(name in expected and name not in seen, "extra or duplicate archive entry: " + name)
                    row = expected[name]
                    need(member.size == row["bytes"], "archive member length mismatch: " + name)
                    stream = archive.extractfile(member)
                    need(stream is not None, "archive member cannot be read: " + name)
                    digest, count = hashlib.sha256(), 0
                    with stream:
                        while data := stream.read(CHUNK):
                            digest.update(data)
                            count += len(data)
                    need(count == row["bytes"] and digest.hexdigest() == row["sha256"], "archive member hash mismatch: " + name)
                    seen.add(name)
            # Tar end markers may precede the gzip trailer; consume it to verify CRC.
            while compressed.read(CHUNK):
                pass
    need(seen == set(expected), "archive omitted an original evidence member")
    raw_after, _ = read_file(path, exclude_elf=False)
    need(raw_before == raw_after, "archive bytes changed during verification")
    return {"bytes": raw_after["bytes"], "sha256": raw_after["sha256"],
            "members": len(seen), "all_member_bytes_verified": True, "gzip_read_to_eof": True}


def input_source(label, value):
    path = absolute(value)
    fd = None
    try:
        fd = open_direct(path, directory=True)
    except NotADirectoryError:
        pass
    except ValueError as error:
        if "not a direct directory:" not in str(error):
            raise
    if fd is not None:
        os.close(fd)
        root = path
        report = path / "report.json"
        if not report.exists():
            report = path / "summary.json"
    else:
        root, report = path.parent, path
    return {"label": label, "root": root, "report": report}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--qualification", type=Path, action="append", default=[], help="qualification directory or report; repeat for R1/R2")
    for kind in ("native", "lease", "reuse", "registry"):
        parser.add_argument("--" + kind, type=Path, help=kind + " original report/summary or evidence directory")
    parser.add_argument("--input-root", type=Path, action="append", default=[], help="additional explicitly authorized referenced-input root")
    parser.add_argument("--output", type=Path, required=True, help="new output directory or new .tar.gz pathname")
    args = parser.parse_args()
    inputs = [input_source(f"qualification/{index:02d}", value) for index, value in enumerate(args.qualification, 1)]
    inputs += [input_source(kind, getattr(args, kind)) for kind in ("native", "lease", "reuse", "registry") if getattr(args, kind)]
    need(inputs, "at least one qualification or original experiment report is required")
    output = absolute(args.output)
    create_directory = False
    if output.name.endswith(".tar.gz"):
        archive_path = output
        manifest_path = output.with_name(output.name[:-7] + ".manifest.json")
        directory = output.parent
        fd = open_direct(directory, directory=True)
        os.close(fd)
    else:
        directory = output
        fd = open_direct(directory.parent, directory=True)
        os.close(fd)
        need(not directory.exists() and not directory.is_symlink(), "output directory already exists")
        create_directory = True
        archive_path, manifest_path = directory / "evidence.tar.gz", directory / "manifest.json"
    need(not archive_path.exists() and not archive_path.is_symlink()
         and not manifest_path.exists() and not manifest_path.is_symlink(), "output already exists")
    need(all(not archive_path.is_relative_to(item["root"]) and not manifest_path.is_relative_to(item["root"]) for item in inputs),
         "output must be outside original evidence roots")
    collection = Collection(inputs, [absolute(root) for root in args.input_root])
    collection.collect()
    collection.check_directories()
    original_roots = [Path(path) for path in collection.directories]
    original_roots += [Path(row["path"]) for row in collection.exclusions.values()
                       if row["class"] == "missing_output_directory"]
    need(all(not archive_path.is_relative_to(root) and not manifest_path.is_relative_to(root) for root in original_roots),
         "output overlaps an original referenced evidence directory")
    if create_directory:
        directory.mkdir(mode=0o700)
    files = sorted(collection.files.values(), key=lambda row: row["archive_name"])
    temporary_archive = temporary_manifest = None
    try:
        with tempfile.NamedTemporaryFile(prefix=".hepta-evidence-", suffix=".tar.gz.partial", dir=directory, delete=False) as stream:
            temporary_archive = Path(stream.name)
        write_archive(temporary_archive, files)
        verified = verify_archive(temporary_archive, files)
        collection.check_directories()
        executable_receipts = [{"path": path, "original_receipts": receipts, "archived": False}
                               for path, receipts in sorted(collection.expected.items())
                               if path not in collection.files and any(
                                   re.search(r"/(?:binary|binaries|test_binary|variants)(?:/|\[|$)", row["pointer"])
                                   for row in receipts)]
        report = {"schema": "hepta-x230-original-evidence-package/v1", "complete": True,
                  "created_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                  "packer_sha256": read_file(absolute(__file__), exclude_elf=False)[0]["sha256"],
                  "archive": {"path": str(archive_path), **verified},
                  "inputs": [{key: str(value) for key, value in item.items()} for item in inputs],
                  "authorized_input_roots": [str(root) for root in collection.roots],
                  "additional_reference_root_rule": "/home/qian/hepta-runtime-optimization-*",
                  "original_directories": sorted(collection.directories.values(), key=lambda row: row["path"]),
                  "excluded_classes": EXCLUDED_CLASSES,
                  "excluded": sorted(collection.exclusions.values(), key=lambda row: row["path"]),
                  "excluded_executable_receipts": executable_receipts,
                  "artifact_manifests": [collection.files[path] for path in sorted(collection.artifact_manifests)],
                  "files": files, "file_count": len(files), "raw_bytes": sum(row["bytes"] for row in files),
                  "claims": {"selected_original_bytes_retained": True, "source_files_modified": False,
                             "tests_or_experiments_executed": False, "source_and_archive_streamed": True,
                             "symlinks_followed": False, "excluded_elf_bodies_read": False,
                             "experiment_outcomes_reclassified": False}}
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", prefix=".hepta-manifest-", suffix=".json.partial", dir=directory, delete=False) as stream:
            temporary_manifest = Path(stream.name)
            json.dump(report, stream, indent=2, ensure_ascii=False, allow_nan=False)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        # Link publication is exclusive: neither final pathname can overwrite evidence.
        os.link(temporary_archive, archive_path)
        os.link(temporary_manifest, manifest_path)
        fd = open_direct(directory, directory=True)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
        manifest, raw = read_file(manifest_path, body=True, exclude_elf=False)
        need(document(raw) == report, "published manifest differs from the verified inventory")
        print(json.dumps({"archive": str(archive_path), "archive_bytes": verified["bytes"],
                          "archive_sha256": verified["sha256"], "manifest": str(manifest_path),
                          "manifest_sha256": manifest["sha256"], "files": len(files), "verified": True}), flush=True)
    finally:
        for path in (temporary_archive, temporary_manifest):
            if path is not None:
                path.unlink(missing_ok=True)


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, json.JSONDecodeError, tarfile.TarError) as error:
        print(json.dumps({"verified": False, "error": type(error).__name__ + ": " + str(error)}), file=sys.stderr)
        raise SystemExit(1)
