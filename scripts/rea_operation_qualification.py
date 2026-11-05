#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# Licensed under the Apache License, Version 2.0.
"""Execute frozen REA and native public MCP operations, preserving both wires.

This is deliberately separate from the Rust matrix runner. Passing a finite
comparison never, by itself, qualifies an upstream operation. The independent
receipt consumer requires the complete reviewed profile and every required
lifecycle observation before the compatibility ledger can close that row.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
from pathlib import Path, PurePosixPath
import queue
import select
import signal
import stat
import struct
import subprocess
import sys
import tarfile
import threading
import time


SCHEMA = "hepta.rea.operation-qualification.v1"
PROFILE = "rea-agents-6.8.0/inspect_elf_notes/v1"
PACKAGE_SHA256 = "8d542ec76a9cb350584b60a6c9c088706ff812d5bb5b094c20c95b6dc25698bb"
CATALOG_SHA256 = "d7228cf5da32faf435f9d54a7b8fa84c1081734d7c7dad562f962f221ea8b1e7"
REFERENCE_COMMIT = "93b8b82db70279e40f484114cff9dc1958dc14ee"
PACKAGE_FILES_SHA256 = "8f5a44ea76e5d93b27f8882d902e9449d7f41895e5428c213fe6ed3619592891"
MAX_WIRE_BYTES = 16 * 1024 * 1024
REQUEST_SECONDS = 30.0
EOF_SECONDS = 15.0
TARGET_META = {"provenance": {"untrusted_content": True, "source": "analysis_target"}}
PROVIDER = {"id": "rea-elf-notes", "name": "REA ELF note parser", "version": "1"}
UNIMPLEMENTED_REQUIREMENTS = ["active-cancellation-owner-drain", "deadline-owner-drain",
                            "format-overflow-and-compressed-name-corpus", "build-source-attestation",
                            "oversized-result-retention"]
BUILD_REQUIREMENT = "build-source-attestation"
PRODUCER_FILES = ("scripts/rea_full_qualification.py", "scripts/rea_operation_qualification.py",
                  "scripts/rea_operation_evidence.py", "scripts/rea_build_evidence.py",
                  "tests/rea_operation_qualification_tests.py", "tests/rea_operation_evidence_tests.py",
                  "tests/rea_build_evidence_tests.py")


class QualificationError(ValueError):
    """An unavailable fact or failed comparison, never an implicit pass."""


def require(value, message):
    if not value:
        raise QualificationError(message)


def json_bytes(value):
    return (json.dumps(value, ensure_ascii=True, sort_keys=True, indent=2,
                       allow_nan=False) + "\n").encode()


def digest(value):
    return hashlib.sha256(json.dumps(value, ensure_ascii=True, sort_keys=True,
                                     separators=(",", ":"), allow_nan=False).encode()).hexdigest()


def parse_json(raw):
    require(len(raw) <= MAX_WIRE_BYTES, "JSON exceeds the fixed receive allowance")
    def members(items):
        result = {}
        for key, value in items:
            require(key not in result, "duplicate JSON member: " + key)
            result[key] = value
        return result
    def number(token):
        value = float(token)
        require(math.isfinite(value), "non-finite JSON number")
        return value
    return json.loads(raw, object_pairs_hook=members, parse_float=number,
                      parse_constant=lambda _: (_ for _ in ()).throw(
                          QualificationError("non-finite JSON constant")))


def file_hash(path):
    h = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def identity(path):
    path = Path(path)
    before = path.stat()
    require(stat.S_ISREG(before.st_mode), "not a regular file: " + str(path))
    value = {"path": str(path), "sha256": file_hash(path), "bytes": before.st_size}
    after = path.stat()
    require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns,
             before.st_ctime_ns) == (after.st_dev, after.st_ino, after.st_size,
                                     after.st_mtime_ns, after.st_ctime_ns),
            "file changed while hashing: " + str(path))
    return value


def write_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as handle:
        handle.write(json_bytes(value))
        handle.flush()
        os.fsync(handle.fileno())
    return identity(path)


def artifact_reference(path, output):
    item = identity(path)
    item["path"] = Path(path).relative_to(output).as_posix()
    return item


def artifact_json(output, relative, value):
    write_json(output / relative, value)
    return artifact_reference(output / relative, output)


def process_identity(pid):
    raw = Path("/proc") / str(pid) / "stat"
    value = raw.read_text()
    tail = value[value.rfind(")") + 2:].split()
    return {"pid": pid, "parent_pid": int(tail[1]), "process_group": int(tail[2]),
            "start_time_ticks": int(tail[19])}


def process_group_exists(group):
    try:
        os.killpg(group, 0)
        return True
    except ProcessLookupError:
        return False


def reference_package(package, archive):
    """Authenticate the actual installed package, not its version string.

    Package dependencies are separately identified in the runtime receipt. This
    function claims authentication only for the exact npm tarball's own files.
    No executable code from a package is run before this check succeeds.
    """
    package, archive = Path(package), Path(archive)
    require(archive.is_absolute() and package.is_absolute(), "reference paths must be absolute")
    require(file_hash(archive) == PACKAGE_SHA256, "frozen npm tarball digest mismatch")
    expected = {}
    with tarfile.open(archive, "r:gz") as bundle:
        for member in bundle:
            parts = PurePosixPath(member.name).parts
            require(parts and parts[0] == "package" and ".." not in parts
                    and not member.name.startswith("/"), "unsafe npm archive path")
            if member.isdir():
                continue
            require(member.isfile() and len(parts) > 1, "non-regular npm archive member")
            name = PurePosixPath(*parts[1:]).as_posix()
            require(name not in expected, "duplicate npm archive member")
            require(member.size <= 64 * 1024 * 1024, "oversized npm archive member")
            h = hashlib.sha256()
            with bundle.extractfile(member) as handle:
                for block in iter(lambda: handle.read(1024 * 1024), b""):
                    h.update(block)
            expected[name] = {"path": name, "sha256": h.hexdigest(), "bytes": member.size}
    actual = {}
    for directory, directories, files in os.walk(package, followlinks=False):
        for name in directories:
            require(not (Path(directory) / name).is_symlink(), "symlink in installed npm package")
        for name in files:
            path = Path(directory) / name
            require(not path.is_symlink(), "symlink in installed npm package")
            relative = path.relative_to(package).as_posix()
            item = identity(path)
            actual[relative] = {**item, "path": relative}
    require(actual == expected, "installed npm package differs from the frozen tarball")
    metadata = parse_json((package / "package.json").read_bytes())
    require(metadata["name"] == "rea-agents" and metadata["version"] == "6.8.0",
            "unexpected npm package identity")
    catalog_path = package / "dist/mcp-catalog-full.json"
    require(file_hash(catalog_path) == CATALOG_SHA256, "full catalog digest mismatch")
    return {"name": "rea-agents", "version": "6.8.0", "tarball_sha256": PACKAGE_SHA256,
            "git_source_commit": REFERENCE_COMMIT, "package_root": str(package),
            "file_count": len(expected), "files_sha256": digest(sorted(expected.values(), key=lambda x: x["path"])),
            "catalog_sha256": CATALOG_SHA256,
            "authentication_scope": "all regular files in the published npm package; transitive dependencies remain trusted external inputs"}


class Mcp:
    """A real stdio client with bounded reads and unmodified request/response logs."""

    def __init__(self, argv, directory, environment, output):
        self.output = Path(output)
        self.output.mkdir()
        self.stderr = (self.output / "stderr.log").open("xb")
        self.wire = (self.output / "wire.jsonl").open("xb")
        self.lock = threading.Lock()
        self.responses = queue.Queue()
        self.pending = {}
        self.next_id = 1
        self.closed = False
        self.received_bytes = 0
        self.process = subprocess.Popen(argv, cwd=directory, env=environment,
                                        stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                        stderr=self.stderr, start_new_session=True)
        self.pidfd = os.pidfd_open(self.process.pid)
        self.owner = process_identity(self.process.pid)
        self.started = time.monotonic()
        self.reader = threading.Thread(target=self._read, daemon=True)
        self.reader.start()
        write_json(self.output / "launch.json", {"argv": argv, "cwd": str(directory),
                   "environment": environment, "pid": self.process.pid, "owner": self.owner})

    def _log(self, direction, raw):
        item = {"direction": direction, "monotonic_ns": time.monotonic_ns(),
                "wire_utf8": raw.decode("utf-8", errors="strict")}
        with self.lock:
            self.wire.write(json.dumps(item, ensure_ascii=True).encode() + b"\n")
            self.wire.flush()

    def _read(self):
        try:
            while True:
                raw = self.process.stdout.readline(MAX_WIRE_BYTES + 1)
                if not raw:
                    self.responses.put(QualificationError("MCP stdout closed"))
                    return
                require(len(raw) <= MAX_WIRE_BYTES and raw.endswith(b"\n"), "oversized/unterminated MCP line")
                self.received_bytes += len(raw)
                require(self.received_bytes <= 256 * 1024 * 1024, "MCP session transcript exceeds its fixed allowance")
                self._log("received", raw)
                value = parse_json(raw)
                require(isinstance(value, dict) and value.get("jsonrpc") == "2.0", "invalid MCP message")
                if "id" in value:
                    require("method" not in value, "unexpected server request")
                    self.responses.put(value)
        except BaseException as error:
            self.responses.put(error)

    def send(self, method, params, request_id=None, raw_params=None):
        value = {"jsonrpc": "2.0", "method": method, "params": params}
        if request_id is not None:
            value["id"] = request_id
        if raw_params is None:
            raw = json.dumps(value, ensure_ascii=True, separators=(",", ":"), allow_nan=False).encode() + b"\n"
        else:
            # Preserve reviewed JSON numeric spellings such as 1e0 and 1.0.
            require(parse_json(raw_params) == params, "raw request parameters do not match their parsed facts")
            raw = (b'{"jsonrpc":"2.0","id":' + str(request_id).encode()
                   + b',"method":' + json.dumps(method).encode() + b',"params":' + raw_params + b'}\n')
        self._log("sent", raw)
        self.process.stdin.write(raw)
        self.process.stdin.flush()

    def begin(self, method, params, raw_params=None):
        request_id = self.next_id
        self.next_id += 1
        self.send(method, params, request_id, raw_params)
        return request_id

    def receive(self, request_id, seconds=REQUEST_SECONDS):
        deadline = time.monotonic() + seconds
        while True:
            if request_id in self.pending:
                return self.pending.pop(request_id)
            left = deadline - time.monotonic()
            require(left > 0, "MCP response deadline exceeded")
            try:
                value = self.responses.get(timeout=left)
            except queue.Empty as error:
                raise QualificationError("MCP response deadline exceeded") from error
            if isinstance(value, BaseException):
                raise value
            require(value["id"] not in self.pending, "duplicate MCP response id")
            if value["id"] == request_id:
                return value
            self.pending[value["id"]] = value

    def request(self, method, params, raw_params=None):
        return self.receive(self.begin(method, params, raw_params))

    def initialize(self):
        value = self.request("initialize", {"protocolVersion": "2026-07-28", "capabilities": {},
                             "clientInfo": {"name": "hepta-rea-operation-qualification", "version": "1"}})
        require("result" in value, "MCP initialize failed")
        self.send("notifications/initialized", {})
        return value

    def tools(self):
        rows, cursor, seen = [], None, set()
        while True:
            value = self.request("tools/list", {} if cursor is None else {"cursor": cursor})
            require("result" in value and isinstance(value["result"].get("tools"), list), "tools/list failed")
            rows += value["result"]["tools"]
            cursor = value["result"].get("nextCursor")
            if cursor is None:
                break
            require(isinstance(cursor, str) and cursor not in seen and len(seen) < 32, "invalid tools pagination")
            seen.add(cursor)
        names = [row["name"] for row in rows]
        require(len(names) == len(set(names)), "duplicate tool name")
        return rows

    def call(self, name, arguments, number_spelling=None, omit_arguments=False):
        params = {"name": name}
        if not omit_arguments:
            params["arguments"] = arguments
        raw = None
        if number_spelling:
            raw = json.dumps(params, ensure_ascii=True, separators=(",", ":")).encode()
            field, spelling = number_spelling
            needle = (json.dumps(field) + ":" + json.dumps(arguments[field])).encode()
            require(raw.count(needle) == 1, "ambiguous numeric-spelling request")
            raw = raw.replace(needle, (json.dumps(field) + ":" + spelling).encode())
        return self.request("tools/call", params, raw)

    def close(self):
        if self.closed:
            return self.close_observation
        self.closed = True
        self.process.stdin.close()
        forced = []
        start = time.monotonic()
        try:
            code = self.process.wait(timeout=EOF_SECONDS)
        except subprocess.TimeoutExpired:
            # Cleanup is necessary, but never converts a missed owner cleanup into PASS.
            forced.append("SIGTERM")
            os.killpg(self.process.pid, signal.SIGTERM)
            try:
                code = self.process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                forced.append("SIGKILL")
                os.killpg(self.process.pid, signal.SIGKILL)
                code = self.process.wait(timeout=2)
        if process_group_exists(self.process.pid):
            # An exited parent with a surviving worker is also a failed owner
            # lifecycle. Clean only this runner-created session's process group.
            forced.append("SIGTERM-surviving-process-group")
            os.killpg(self.process.pid, signal.SIGTERM)
            deadline = time.monotonic() + 2
            while process_group_exists(self.process.pid) and time.monotonic() < deadline:
                time.sleep(0.02)
            if process_group_exists(self.process.pid):
                forced.append("SIGKILL-surviving-process-group")
                os.killpg(self.process.pid, signal.SIGKILL)
        self.reader.join(timeout=2)
        owner_exited = bool(select.select([self.pidfd], [], [], 0)[0])
        os.close(self.pidfd)
        self.process.stdout.close()
        self.stderr.close()
        self.wire.close()
        self.close_observation = {"returncode": code, "elapsed_seconds": time.monotonic() - start,
                                  "forced_cleanup": forced, "reader_stopped": not self.reader.is_alive(),
                                  "owner": self.owner, "owner_pidfd_exited": owner_exited,
                                  "process_group_gone": not process_group_exists(self.process.pid)}
        write_json(self.output / "close.json", self.close_observation)
        return self.close_observation


def tool_value(response):
    """Compare JSON value semantics while retaining every MCP envelope member."""
    if "error" in response:
        return {"rpc_error": response["error"]}
    result = response.get("result")
    require(isinstance(result, dict), "MCP result is not an object")
    content = result.get("content")
    require(isinstance(content, list) and len(content) == 1 and content[0].get("type") == "text",
            "expected the original single JSON text representation")
    try:
        text = parse_json(content[0]["text"].encode())
    except json.JSONDecodeError:
        # Some protocol/SDK errors are plain text. Preserve those bytes as a
        # string; never delete text to make an unequal response agree.
        text = content[0]["text"]
    if "structuredContent" in result:
        require(result["structuredContent"] == text, "text/structuredContent disagreement")
    return {**result, "content": [{**content[0], "text": text}]}


def evidence_value(response):
    normalized = tool_value(response)
    require("rpc_error" not in normalized and not normalized.get("isError", False), "expected successful Evidence")
    require("structuredContent" in normalized and normalized.get("_meta") == TARGET_META,
            "Evidence is missing structured content or target provenance")
    return normalized["structuredContent"]


def semantic_evidence_id(value):
    """Independent RFC8785 subset for this profile's integer-only observations.

    Refuse floats, non-ASCII object keys, lone surrogates and unsafe integers;
    this is not a replacement for the production ECMAScript number algorithm.
    """
    fields = ("provider", "analysis_profile", "predicate_type", "operation", "parameters", "raw_result",
              "normalized_result", "confidence", "authority", "environment", "limitations",
              "relationship_coverage", "locations", "evidence_links")
    content = {field: value[field] for field in fields}
    subject = value["subject"]
    content["subject"] = None if subject is None else {field: subject[field] for field in ("digest", "format", "architecture")}
    def visit(item):
        if item is None or isinstance(item, (bool, str)):
            if isinstance(item, str):
                item.encode("utf-8", errors="strict")
            return
        if isinstance(item, int):
            require(abs(item) <= 9007199254740991, "integer outside independent canonicalizer scope")
            return
        if isinstance(item, list):
            for part in item:
                visit(part)
            return
        require(isinstance(item, dict), "value outside independent canonicalizer scope")
        for key, part in item.items():
            require(isinstance(key, str) and key.isascii(), "key outside independent canonicalizer scope")
            visit(part)
    visit(content)
    raw = json.dumps(content, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode()
    return "ev_" + hashlib.sha256(raw).hexdigest()


def align(value, boundary):
    return (value + boundary - 1) // boundary * boundary


def note(owner=b"GNU\0", descriptor=bytes(range(20)), kind=3, order="little", alignment=4):
    prefix = "<" if order == "little" else ">"
    raw = struct.pack(prefix + "III", len(owner), len(descriptor), kind) + owner
    raw += bytes(align(len(raw), alignment) - len(raw))
    raw += descriptor
    return raw + bytes(align(len(raw), alignment) - len(raw))


def elf(notes, bits=64, order="little", program=True, section=False, declared_alignment=4,
        machine=None, file_type=2, osabi=0, version=1):
    prefix = "<" if order == "little" else ">"
    ehsize, phsize, shsize = (64, 56, 64) if bits == 64 else (52, 32, 40)
    offset = align(ehsize + phsize * int(program), 8)
    shoff = align(offset + len(notes), 8) if section else 0
    ident = b"\x7fELF" + bytes([2 if bits == 64 else 1, 1 if order == "little" else 2, 1, osabi]) + bytes(8)
    machine = (62 if bits == 64 else 3) if machine is None else machine
    numbers = (file_type, machine, version, 0, ehsize if program else 0, shoff, 0,
               ehsize, phsize if program else 0, int(program), shsize if section else 0,
               2 if section else 0, 0)
    header = ident + struct.pack(prefix + ("HHIQQQIHHHHHH" if bits == 64 else "HHIIIIIHHHHHH"), *numbers)
    if program:
        values = (4, 0, offset, 0, 0, len(notes), len(notes), declared_alignment) if bits == 64 else (
            4, offset, 0, 0, len(notes), len(notes), 0, declared_alignment)
        header += struct.pack(prefix + ("IIQQQQQQ" if bits == 64 else "IIIIIIII"), *values)
    raw = header + bytes(offset - len(header)) + notes
    if section:
        raw += bytes(shoff - len(raw)) + bytes(shsize)
        values = (0, 7, 0, 0, offset, len(notes), 0, 0, declared_alignment, 0)
        raw += struct.pack(prefix + ("IIQQQQIIQQ" if bits == 64 else "IIIIIIIIII"), *values)
    return raw


def fixture_cases(workspace, write=True):
    """Independent byte encodings; no REA/native parser generates expected facts."""
    workspace = Path(workspace)
    fixtures = {}
    cases = []
    def add(name, raw, entries, tables=1, **facts):
        path = workspace / (name + ".elf")
        if write:
            path.write_bytes(raw)
        fixtures[name] = {"path": str(path), "sha256": hashlib.sha256(raw).hexdigest(),
                          "bytes": len(raw), "entries": entries, "tables": tables, **facts}
        cases.append({"id": name, "kind": "success", "arguments": {"path": str(path)},
                      "facts": fixtures[name]})
    for bits in (32, 64):
        for order in ("little", "big"):
            add("elf%d_%s" % (bits, order), elf(note(order=order), bits=bits, order=order), 1,
                format="elf" + str(bits), byte_order=order, owner="GNU", descriptor_hex=bytes(range(20)).hex())
    add("section_only", elf(note(), program=False, section=True), 1)
    add("aliased_program_section", elf(note(), section=True), 2, tables=2)
    add("no_note_tables", elf(b"", program=False), 0, tables=0)
    add("empty_note_table", elf(b""), 0)
    add("unknown_owner_type", elf(note(b"other\0", b"xyz", 99)), 1, owner="other")
    add("latin1_owner", elf(note(b"\xff\xe9\0tail", b"x", 99)), 1, owner="ÿé")
    add("descriptor_65", elf(note(descriptor=bytes(range(65)))), 1, descriptor_hex=None)
    add("align_8", elf(note(alignment=8), declared_alignment=8), 1)
    add("declared_align_1", elf(note(), declared_alignment=1), 1)
    add("declared_align_16", elf(note(), declared_alignment=16), 1)
    add("zero_tail", elf(note() + bytes(7)), 1)
    add("gnu_abi", elf(note(descriptor=struct.pack("<IIII", 0, 6, 8, 0), kind=1)), 1)
    add("gnu_gold", elf(note(descriptor=b"gold 1.2\0\0", kind=4)), 1)
    add("multiple_notes", elf(note() + note(b"X\0", b"abcd", 99)), 2)
    base = fixtures["elf64_little"]["path"]
    for case_id, args in (
        ("explicit_defaults", {"path": base, "max_file_bytes": 67108864, "max_entries": 32}),
        ("maximum_parameters", {"path": base, "max_file_bytes": 536870912, "max_entries": 256}),
        ("minimum_entries", {"path": base, "max_entries": 1}),
        ("duplicate_record", {"path": base}),
    ):
        cases.append({"id": case_id, "kind": "success", "arguments": args, "facts": fixtures["elf64_little"]})
    for spelling in ("1.0", "1e0"):
        cases.append({"id": "integer_spelling_" + spelling.replace(".", "_"), "kind": "success",
                      "arguments": {"path": base, "max_entries": 1},
                      "number_spelling": ["max_entries", spelling], "facts": fixtures["elf64_little"]})
    invalid = [("missing_path", {}), ("null_path", {"path": None}), ("empty_path", {"path": ""}),
               ("relative_path", {"path": "relative.elf"}), ("nul_path", {"path": base + "\0"}),
               ("unknown_key", {"path": base, "detail": "summary"})]
    for field, values in (("max_file_bytes", [None, True, "67108864", 63, 536870913, 64.5]),
                          ("max_entries", [None, True, "32", 0, 257, 1.5])):
        for index, value in enumerate(values):
            invalid.append((field + "_invalid_" + str(index), {"path": base, field: value}))
    invalid += [("missing_file", {"path": str(workspace / "does-not-exist.elf")}),
                ("directory_path", {"path": str(workspace)}),
                ("file_budget", {"path": base, "max_file_bytes": 64}),
                ("entry_budget", {"path": fixtures["multiple_notes"]["path"], "max_entries": 1})]
    invalid += [("path_number", {"path": 1}), ("path_bool", {"path": True}),
                ("path_array", {"path": []}), ("path_object", {"path": {}}),
                ("multi_unknown_za", {"path": base, "zzz": 1, "aaa": 2}),
                ("multi_unknown_az", {"path": base, "aaa": 2, "zzz": 1}),
                ("multi_errors_reversed_input", {"extra": 1, "max_entries": 0, "max_file_bytes": 63, "path": None})]
    for field in ("max_entries", "max_file_bytes"):
        for index, value in enumerate(([], {}, False, "", -1, 1e30)):
            invalid.append((field + "_extra_type_" + str(index), {"path": base, field: value}))
    for case_id, args in invalid:
        cases.append({"id": case_id, "kind": "error", "arguments": args,
                      "argument_key_order": list(args)})
    for name, value in (("null", None), ("array", []), ("string", "x")):
        cases.append({"id": "arguments_" + name, "kind": "error", "arguments": value})
    cases.append({"id": "arguments_omitted", "kind": "error", "arguments": None, "omit_arguments": True})
    for name, raw in (("nonzero_tail", elf(note() + b"\1")),
                      ("short_header", b"\x7fELF"),
                      ("wrong_magic", bytes(64)),
                      ("truncated_descriptor", elf(note())[:-1])):
        path = workspace / (name + ".elf")
        if write:
            path.write_bytes(raw)
        fixtures[name] = {"path": str(path), "sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw)}
        cases.append({"id": name, "kind": "error", "arguments": {"path": str(path)}})
    return fixtures, cases


def retention_queries(records):
    """Get-bundle behavior necessary for a notes record, not that whole tool."""
    records = sorted(records, key=lambda item: item["evidence_id"])
    first = records[0] if records else None
    queries = [{"id": "complete", "arguments": {}},
               {"id": "summary", "arguments": {"detail": "summary"}},
               {"id": "summary_empty_filters", "arguments": {"detail": "summary", "filters": {}}},
               {"id": "operation_matches", "arguments": {"detail": "summary", "filters": {"operation": "inspect_elf_notes"}}},
               {"id": "operation_misses", "arguments": {"detail": "summary", "filters": {"operation": "not-this-operation"}}},
               {"id": "null_profile_cannot_match", "arguments": {"detail": "summary", "filters": {"analysis_profile_digest": "0" * 64}}},
               {"id": "procedure_cannot_match", "arguments": {"detail": "summary", "filters": {"procedure_address": "0x0"}}},
               {"id": "complete_filters_rejected", "arguments": {"detail": "complete", "filters": {}}, "expect_error": True},
               {"id": "detail_null", "arguments": {"detail": None}, "expect_error": True},
               {"id": "filters_null", "arguments": {"detail": "summary", "filters": None}, "expect_error": True},
               {"id": "bad_evidence_id", "arguments": {"detail": "summary", "filters": {"evidence_id": "ev_" + "A" * 64}}, "expect_error": True},
               {"id": "short_target_digest", "arguments": {"detail": "summary", "filters": {"target_sha256": "0" * 63}}, "expect_error": True},
               {"id": "uppercase_profile_digest", "arguments": {"detail": "summary", "filters": {"analysis_profile_digest": "A" * 64}}, "expect_error": True},
               {"id": "empty_operation", "arguments": {"detail": "summary", "filters": {"operation": ""}}, "expect_error": True},
               {"id": "empty_procedure", "arguments": {"detail": "summary", "filters": {"procedure_address": ""}}, "expect_error": True},
               {"id": "unknown_filter_keys", "arguments": {"detail": "summary", "filters": {"zzz": 1, "aaa": 2}}, "expect_error": True}]
    if first is not None:
        queries += [{"id": "evidence_id_matches", "arguments": {"detail": "summary", "filters": {"evidence_id": first["evidence_id"]}}},
                    {"id": "artifact_matches", "arguments": {"detail": "summary", "filters": {"target_sha256": first["subject"]["digest"]["sha256"]}}},
                    {"id": "and_filter_misses", "arguments": {"detail": "summary", "filters": {"evidence_id": first["evidence_id"], "operation": "not-this-operation"}}}]
    return queries


def check_retention_response(query, response, records):
    value = tool_value(response)
    if query.get("expect_error", False):
        require(value.get("isError") is True, "invalid bundle input unexpectedly succeeded")
        return
    payload = evidence_value(response)["result"]
    records = sorted(records, key=lambda item: item["evidence_id"])
    if query["arguments"].get("detail", "complete") == "complete":
        require(set(payload) == {"artifacts", "providers", "environments", "scenarios", "captures", "unknowns", "records"},
                "complete bundle does not have the seven original manifests")
        require(payload["records"] == records, "retained set/order/content differs from completed observations")
        require(all(payload[key] == [] for key in ("environments", "scenarios", "captures", "unknowns")),
                "notes-only session contains unrelated bundle metadata")
        return
    filters = query["arguments"].get("filters", {})
    expected = []
    for record in records:
        facts = {"evidence_id": record["evidence_id"], "operation": record["operation"],
                 "target_sha256": record["subject"]["digest"]["sha256"],
                 "analysis_profile_digest": None, "procedure_address": None}
        if not all(facts[key] == value for key, value in filters.items()):
            continue
        expected.append({key: record[key] for key in ("evidence_id", "subject", "provider", "operation", "confidence", "authority")}
                        | {"analysis_profile_digest": None, "retention": "complete-record",
                           "limitation_count": len(record["limitations"]),
                           "native_dossier": {"available": False, "reason": "different-operation"}})
    require(payload == {"kind": "evidence-bundle-summary", "filters": filters,
                        "total_retained_records": len(records), "matching_records": len(expected),
                        "unknown_revisions": 0, "records": expected}, "independent summary/filter projection differs")


def check_independent_facts(record, case):
    facts = case["facts"]
    require(record["provider"] == PROVIDER and record["operation"] == "inspect_elf_notes", "provider/operation mismatch")
    require(record["evidence_id"] == semantic_evidence_id(record), "semantic Evidence ID mismatch")
    require(record["relationship_coverage"] is None and record["raw_result"] is None,
            "unexpected notes relationship/raw result")
    value = record["normalized_result"]
    require(value["artifact"] == {key: facts[key] for key in ("path", "sha256", "bytes")}, "artifact identity mismatch")
    require(len(value["entries"]) == facts["entries"] and len(value["tables"]) == facts["tables"], "independent entry/table count mismatch")
    require(value["coverage"] == {"status": "complete", "examined_tables": facts["tables"],
                                  "examined_entries": facts["entries"]}, "coverage does not match independent facts")
    for field in ("format", "byte_order"):
        if field in facts:
            require(value[field] == facts[field], "independent " + field + " mismatch")
    if value["entries"]:
        first = value["entries"][0]
        if "owner" in facts:
            require(first["owner"] == facts["owner"], "independent owner mismatch")
        if "descriptor_hex" in facts:
            require(first["descriptor"]["hex"] == facts["descriptor_hex"], "independent descriptor mismatch")
    defaults = {"max_file_bytes": 67108864, "max_entries": 32, **case["arguments"]}
    require(record["parameters"] == defaults, "defaulted operation parameters mismatch")


def compare_case(case, reference, native):
    left, right = tool_value(reference), tool_value(native)
    require(left == right, "full public MCP result differs from the frozen original")
    if case["kind"] == "success":
        check_independent_facts(evidence_value(reference), case)
    else:
        require("rpc_error" in left or left.get("isError") is True, "invalid case unexpectedly succeeded")
    return {"full_envelope_equal": True, "independent_expectation": case["kind"]}


def compare_registration(reference, native):
    wanted = {"inspect_elf_notes": "rea_inspect_elf_notes", "get_evidence_bundle": "rea_get_evidence_bundle"}
    original, replacement = ({row["name"]: row for row in rows} for rows in (reference, native))
    checks = []
    for upstream, downstream in wanted.items():
        require(upstream in original and downstream in replacement, "missing public MCP route: " + downstream)
        # Only notes itself is being qualified. Bundle schemas describe the
        # original complete bundle, but the surrounding session tool is separate.
        for field in ("inputSchema", "outputSchema", "annotations"):
            require(original[upstream].get(field) == replacement[downstream].get(field),
                    upstream + ": full public " + field + " differs")
            checks.append({"tool": upstream, "field": field, "sha256": digest(original[upstream].get(field))})
    return checks


def arguments(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--operation", choices=("inspect_elf_notes",), required=True)
    parser.add_argument("--repo", type=Path, required=True)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--binary-sha256", required=True)
    parser.add_argument("--reference-package", type=Path, required=True)
    parser.add_argument("--reference-tarball", type=Path, required=True)
    parser.add_argument("--node", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--build-summary", type=Path,
                        help="Original complete Rust matrix receipt with its sibling artifacts; verified before native launch")
    parser.add_argument("--build-summary-sha256",
                        help="Exact original build receipt SHA-256; required together with --build-summary")
    return parser.parse_args(argv)


def main(argv=None):
    args = arguments(argv)
    for name in ("repo", "binary", "reference_package", "reference_tarball", "node", "output_dir"):
        require(getattr(args, name).is_absolute(), "all paths must be absolute")
    require((args.build_summary is None) == (args.build_summary_sha256 is None),
            "--build-summary and --build-summary-sha256 must be supplied together")
    require(not args.output_dir.exists(), "refusing to reuse an evidence directory")
    args.output_dir.mkdir(parents=True, mode=0o700)
    output = args.output_dir
    report = {"schema": SCHEMA, "profile": PROFILE, "operation": args.operation,
              "status": "OPEN", "qualified": False, "cases": [], "errors": [],
              "unimplemented_required_observations": list(UNIMPLEMENTED_REQUIREMENTS),
              "execution": {"repo": str(args.repo), "output": str(output), "python": sys.version,
                            "scope": "Linux local functional profile; not malicious same-UID execution attestation"}}
    reference = native = monitor = producer_monitor = None
    exit_code = 1
    try:
        report["reference_before"] = reference_package(args.reference_package, args.reference_tarball)
        require(report["reference_before"]["files_sha256"] == PACKAGE_FILES_SHA256, "frozen package file inventory mismatch")
        report["native_before"] = identity(args.binary)
        require(report["native_before"]["sha256"] == args.binary_sha256, "native binary digest mismatch")
        report["node_binary"] = identity(args.node.resolve())
        version = subprocess.run([str(args.node), "--version"], capture_output=True, check=True, timeout=10, env={})
        report["node_version"] = version.stdout.decode().strip()
        require(report["node_version"] == "v22.23.4", "this profile requires the independently probed Node 22.23.4")
        workspace = output / "workspace"
        workspace.mkdir(mode=0o700)
        fixtures, cases = fixture_cases(workspace)
        report["workspace"] = str(workspace)
        report["case_manifest"] = artifact_json(output, "cases.json", {"profile": PROFILE, "fixtures": fixtures, "cases": cases})
        producer_repo = Path(__file__).resolve().parents[1]
        report["execution"]["producer_repo"] = str(producer_repo)
        report["producer_files"] = [{**identity(producer_repo / name), "path": name} for name in PRODUCER_FILES]
        report["producer_execution_files"] = []
        for name in PRODUCER_FILES:
            if not name.startswith("scripts/"):
                continue
            actual = Path(__file__).parent / Path(name).name
            executed = identity(actual)
            selected = next(item for item in report["producer_files"] if item["path"] == name)
            require(executed["sha256"] == selected["sha256"] and executed["bytes"] == selected["bytes"],
                    "executing runner/consumer differs from the selected repository: " + name)
            report["producer_execution_files"].append({**executed, "repository_path": name})
        from rea_full_qualification import Selection, SourceMonitor
        selection = Selection(args.repo, output / "unused-target", output)
        monitor = SourceMonitor(selection)
        monitor.start()
        if producer_repo != args.repo.resolve():
            producer_monitor = SourceMonitor(Selection(producer_repo, output / "unused-producer-target", output))
            producer_monitor.start()
        source_before = selection.snapshot()
        report["source_before"] = artifact_json(output, "source-before.json", source_before)
        if args.build_summary is not None:
            from rea_build_evidence import capture_build
            bundle, binding = capture_build(args.build_summary, args.build_summary_sha256,
                                            output, source_before, report["native_before"])
            report["build_evidence"] = bundle
            report["build_summary"] = bundle["summary"]
            # Informational only: the consumer replays the retained originals.
            report["build_binding"] = binding
            report["unimplemented_required_observations"].remove(BUILD_REQUIREMENT)
        config = output / "runtime.json"
        write_json(config, {"controller_workspace_roots": [str(workspace)], "state_dir": str(output / "state"),
                   "hosts": {"never-connect": {"ssh_target": "never-connect-invalid", "remote_state_dir": str(output / "unused-remote"),
                   "allow_execute": False, "allow_pty": False, "allow_write": False, "allow_job_network": False}}})
        environment = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "REA_MCP_INPUT_SCHEMA_PROFILE": "full",
                       "REA_MCP_OUTPUT_SCHEMA_PROFILE": "full"}
        reference = Mcp([str(args.node), str(args.reference_package / "scripts/rea.mjs"), "mcp"],
                        workspace, environment, output / "reference")
        native = Mcp([str(args.binary), "mcp", "--runtime-config", str(config)],
                     workspace, {}, output / "native")
        for client in (reference, native):
            client.initialize()
        original_tools, native_tools = reference.tools(), native.tools()
        report["reference_tools"] = artifact_json(output, "reference-tools.json", original_tools)
        report["native_tools"] = artifact_json(output, "native-tools.json", native_tools)
        try:
            report["registration"] = compare_registration(original_tools, native_tools)
        except Exception as error:
            report["errors"].append({"stage": "registration", "error": str(error)})
        retained = {}
        for case in cases:
            row = {"id": case["id"]}
            try:
                upstream = reference.call("inspect_elf_notes", case["arguments"], case.get("number_spelling"), case.get("omit_arguments", False))
                downstream = native.call("rea_inspect_elf_notes", case["arguments"], case.get("number_spelling"), case.get("omit_arguments", False))
                row["reference"] = artifact_json(output, "cases/" + case["id"] + ".reference.json", upstream)
                row["native"] = artifact_json(output, "cases/" + case["id"] + ".native.json", downstream)
                if case["kind"] == "success":
                    value = evidence_value(upstream)
                    retained.setdefault(value["evidence_id"], value)
                row["comparison"] = compare_case(case, upstream, downstream)
                row["status"] = "PASS"
            except Exception as error:
                row["status"], row["error"] = "FAIL", str(error)
            report["cases"].append(row)
        report["retention_cases"] = []
        for query in retention_queries(list(retained.values())):
            row = {"id": query["id"]}
            try:
                left = reference.call("get_evidence_bundle", query["arguments"])
                right = native.call("rea_get_evidence_bundle", query["arguments"])
                row["reference"] = artifact_json(output, "retention/" + query["id"] + ".reference.json", left)
                row["native"] = artifact_json(output, "retention/" + query["id"] + ".native.json", right)
                require(tool_value(left) == tool_value(right), "retained bundle/summary/filter responses differ")
                check_retention_response(query, left, list(retained.values()))
                row["status"] = "PASS"
            except Exception as error:
                row["status"], row["error"] = "FAIL", str(error)
            report["retention_cases"].append(row)
        # Session ownership is in-memory in the frozen original. A new process
        # must start empty, even when it reuses the same native runtime config.
        report["reference_close"] = reference.close()
        report["native_close"] = native.close()
        report["cold_sessions"] = []
        for label, cold_argv, env, tool in (
                ("reference", [str(args.node), str(args.reference_package / "scripts/rea.mjs"), "mcp"], environment, "get_evidence_bundle"),
                ("native", [str(args.binary), "mcp", "--runtime-config", str(config)], {}, "rea_get_evidence_bundle")):
            cold = Mcp(cold_argv, workspace, env, output / (label + "-cold"))
            row = {"producer": label}
            try:
                cold.initialize()
                value = cold.call(tool, {})
                row["response"] = artifact_json(output, label + "-cold-empty.json", value)
                check_retention_response({"id": "complete", "arguments": {}}, value, [])
                row["status"] = "PASS"
            except Exception as error:
                row["status"], row["error"] = "FAIL", str(error)
            finally:
                row["close"] = cold.close()
                row["wire"] = artifact_reference(cold.output / "wire.jsonl", output)
                row["launch"] = artifact_reference(cold.output / "launch.json", output)
                row["close_artifact"] = artifact_reference(cold.output / "close.json", output)
            report["cold_sessions"].append(row)
        report["reference_after"] = reference_package(args.reference_package, args.reference_tarball)
        report["native_after"] = identity(args.binary)
        report["source_after"] = artifact_json(output, "source-after.json", selection.snapshot())
        report["producer_files_after"] = [{**identity(producer_repo / name), "path": name} for name in PRODUCER_FILES]
        require(report["producer_files_after"] == report["producer_files"], "actual qualification producer changed during execution")
        require(report["reference_before"] == report["reference_after"], "reference changed during execution")
        require(report["native_before"] == report["native_after"], "native binary changed during execution")
        require(parse_json((output / report["source_before"]["path"]).read_bytes()) ==
                parse_json((output / report["source_after"]["path"]).read_bytes()), "source changed during execution")
        cold_closed = all(row["close"]["forced_cleanup"] == [] and row["close"]["returncode"] == 0
                          and row["close"]["reader_stopped"] and row["close"]["owner_pidfd_exited"]
                          and row["close"]["process_group_gone"] for row in report["cold_sessions"])
        exit_code = 0 if not report["errors"] and cold_closed and all(case["status"] == "PASS" for case in
                       report["cases"] + report["retention_cases"] + report["cold_sessions"]) else 1
    except BaseException as error:
        report["errors"].append({"stage": "execution", "error": type(error).__name__ + ": " + str(error)})
    finally:
        for label, client in (("reference", reference), ("native", native)):
            if client is not None:
                try:
                    report[label + "_close"] = client.close()
                    report[label + "_wire"] = artifact_reference(client.output / "wire.jsonl", output)
                    report[label + "_launch"] = artifact_reference(client.output / "launch.json", output)
                    report[label + "_close_artifact"] = artifact_reference(client.output / "close.json", output)
                    if (report[label + "_close"]["forced_cleanup"] or report[label + "_close"]["returncode"] != 0
                            or not report[label + "_close"]["owner_pidfd_exited"]
                            or not report[label + "_close"]["process_group_gone"]):
                        exit_code = 1
                except BaseException as error:
                    report["errors"].append({"stage": label + "_close", "error": str(error)})
                    exit_code = 1
        if monitor is not None:
            observation = monitor.stop()
            report["source_monitor"] = artifact_json(output, "source-monitor.json", observation)
            if observation["event_count"] or observation["errors"]:
                report["errors"].append({"stage": "source_monitor", "error": "source changed or monitor coverage was lost"})
                exit_code = 1
        if producer_monitor is not None:
            observation = producer_monitor.stop()
            report["producer_source_monitor"] = artifact_json(output, "producer-source-monitor.json", observation)
            if observation["event_count"] or observation["errors"]:
                report["errors"].append({"stage": "producer_source_monitor", "error": "producer changed or monitor coverage was lost"})
                exit_code = 1
        report["comparison_exit_code"] = exit_code
        # This initial executable profile exposes its unfinished requirements.
        # A successful comparison is useful evidence but does not close a row.
        report["status"] = "OPEN" if exit_code == 0 else "FAILED"
        receipt = write_json(output / "qualification.json", report)
        print(json.dumps({"qualified": False, "status": report["status"], "receipt": receipt,
                          "cases": len(report["cases"]), "comparison_exit_code": exit_code}, sort_keys=True))
    return exit_code


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        print(json.dumps({"qualified": False, "status": "INVALID", "error": str(error)}), file=sys.stderr)
        raise SystemExit(2)
