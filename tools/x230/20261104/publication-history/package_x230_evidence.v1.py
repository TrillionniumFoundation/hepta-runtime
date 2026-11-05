#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Freeze and package explicitly selected X230 evidence; never run a benchmark.

No remote access, source edits, symlink following, automatic discovery of new
campaigns, or publication. `inventory` reads only a plan's narrow selectors.
`pack` requires that frozen inventory and rechecks every original byte.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import fnmatch
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
import tempfile

SCHEMA = "hepta-x230-evidence-publication/v1"
HOSTS = {"ai395", "mac", "main", "pocket4", "rog", "x230"}
DENIED_COMPONENTS = {".git", ".ssh", "target", "test-binaries", "fixtures",
                     "profile", "profiles", "agent", "agents", "sockets"}
DENIED_NAMES = {"runtime.json", "profile.json", "ssh_config", "known_hosts",
                "authorized_keys", "config", "config.json", ".env"}
TEXT_SUFFIXES = {".json", ".jsonl", ".py", ".rs", ".toml", ".lock", ".md",
                 ".txt", ".log", ".stdout", ".stderr", ".patch", ".diff",
                 ".csv", ".tsv", ".input", ".in", ".sha256", ".sh"}
MAGICS = (b"\x7fELF", b"MZ", b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe",
          b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe")
SECRET_MARKERS = (
    re.compile(rb"(?m)^-----BEGIN (?:OPENSSH |RSA |EC |DSA |ENCRYPTED )?PRIVATE KEY-----\r?$"),
    re.compile(rb"(?mi)^PuTTY-User-Key-File-[0-9]+:"),
    re.compile(rb"(?i)\bBearer\s+[A-Za-z0-9_.-]{32,}"),
    re.compile(rb"(?i)(?:HEPTA_HTTP_TOKEN|AWS_SECRET_ACCESS_KEY|OPENAI_API_KEY)\s*[=:]\s*[\"']?[A-Za-z0-9_./+-]{24,}"),
)


def need(value, message):
    if not value:
        raise ValueError(message)


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=False) + "\n").encode()


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def parts(value):
    need(isinstance(value, str) and value and not value.startswith("/"), "relative path required")
    need("\\" not in value and all(ord(c) >= 32 and ord(c) != 127 for c in value), "unsafe path character")
    result = value.split("/")
    need(all(p not in {"", ".", ".."} for p in result), "non-canonical relative path")
    return result


def basename(value):
    parts(value)
    need("/" not in value, "manifest filename must be a basename")
    return value


def legacy_basename(value):
    need(isinstance(value, str) and "\\" not in value and "\0" not in value, "unsafe legacy path")
    return basename(value.rsplit("/", 1)[-1])


def allowed_path(relative, role):
    components = parts(relative)
    lowered = [p.lower() for p in components]
    need(not any(p in DENIED_COMPONENTS or p.startswith(("cargo-home", "target-"))
                 for p in lowered), "forbidden source subtree: " + relative)
    name = lowered[-1]
    need(name not in DENIED_NAMES and not name.startswith(("id_rsa", "id_ed25519", "id_ecdsa")),
         "credential/config filename: " + relative)
    need(not name.endswith((".pem", ".key", ".p12", ".pfx", ".sock", ".socket")), "credential/socket suffix")
    suffix = Path(name).suffix
    if role == "worker-env":
        need(name == "worker-environment.bin", "only selected worker environment bytes may use .bin")
    elif role == "test-log-gzip":
        need(name.endswith(".gz"), "compressed test log must end in .gz")
    else:
        need(suffix in TEXT_SUFFIXES or name in {"readme", "license", "notice"},
             "unapproved file type: " + relative)


def identity(s):
    return {"dev": s.st_dev, "ino": s.st_ino, "size": s.st_size, "mode": s.st_mode,
            "nlink": s.st_nlink, "mtime_ns": s.st_mtime_ns, "ctime_ns": s.st_ctime_ns}


@contextmanager
def directory_fd(absolute, create=False):
    need(os.name == "posix" and hasattr(os, "O_NOFOLLOW"), "POSIX O_NOFOLLOW is required")
    need(isinstance(absolute, str) and absolute.startswith("/"), "absolute root required")
    components = [] if absolute == "/" else absolute.split("/")[1:]
    need(all(p not in {"", ".", ".."} for p in components), "non-canonical absolute root")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    fd = os.open("/", flags)
    try:
        for component in components:
            if create:
                try:
                    os.mkdir(component, mode=0o700, dir_fd=fd)
                except FileExistsError:
                    pass
            child = os.open(component, flags, dir_fd=fd)
            os.close(fd)
            fd = child
        yield fd
    finally:
        os.close(fd)


@contextmanager
def source_file(root, relative):
    components = parts(relative)
    with directory_fd(root) as root_fd:
        parent = os.dup(root_fd)
        try:
            for component in components[:-1]:
                child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                                dir_fd=parent)
                os.close(parent)
                parent = child
            fd = os.open(components[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                         dir_fd=parent)
            try:
                s = os.fstat(fd)
                need(stat.S_ISREG(s.st_mode) and s.st_nlink == 1, "selected evidence is not an independent regular file")
                with os.fdopen(fd, "rb", closefd=False) as stream:
                    yield stream, identity(s)
            finally:
                os.close(fd)
        finally:
            os.close(parent)


def scan_content(stream, role, size_limit):
    """Scan without changing bytes. This supplements the explicit allowlist."""
    sha = hashlib.sha256()
    total, overlap, first, environment = 0, b"", True, bytearray()
    while True:
        block = stream.read(1024 * 1024)
        if not block:
            break
        if first:
            need(not any(block.startswith(m) for m in MAGICS), "executable/compiled binary signature")
            first = False
        total += len(block)
        need(total <= size_limit, "evidence file exceeds planned size bound")
        sha.update(block)
        sample = overlap + block
        need(not any(pattern.search(sample) for pattern in SECRET_MARKERS), "possible private key or credential content")
        overlap = sample[-4096:]
        if role == "worker-env":
            need(total <= 8192, "selected environment too large")
            environment.extend(block)
    if role == "worker-env":
        raw = bytes(environment)
        need(raw.endswith(b"\0"), "worker environment lacks exact NUL framing")
        entries = [entry.partition(b"=") for entry in raw[:-1].split(b"\0")]
        need(len(entries) == 2 and all(sep == b"=" for _, sep, _ in entries), "worker environment shape differs")
        values = {k: v for k, _, v in entries}
        need(set(values) == {b"TOKIO_WORKER_THREADS", b"MALLOC_ARENA_MAX"}, "unapproved environment key")
        need(values[b"TOKIO_WORKER_THREADS"] in {b"1", b"2", b"4"}
             and values[b"MALLOC_ARENA_MAX"] == b"1", "worker/allocator environment differs")
    return total, sha.hexdigest()


def read_json(collector, root, relative):
    return json.loads(collector.read_small(root, relative))


class Collector:
    def __init__(self, plan, package):
        self.plan, self.package = plan, package
        self.files, self.discovery = {}, []
        self.max_file = plan.get("max_file_bytes", 256 * 1024 * 1024)

    def read_small(self, root, relative):
        allowed_path(relative, "text")
        with source_file(self.plan["roots"][root], relative) as (stream, before):
            raw = stream.read(min(self.max_file, 16 * 1024 * 1024) + 1)
            need(len(raw) <= min(self.max_file, 16 * 1024 * 1024), "JSON metadata too large")
            need(before == identity(os.fstat(stream.fileno())), "metadata changed during read")
            return raw

    def add(self, root, relative, archive, role="text", expected=None, optional=False):
        allowed_path(relative, role)
        parts(archive)
        need(archive.startswith(self.package["bundle_prefix"] + "/"), "member outside package prefix")
        expanded = None
        try:
            with source_file(self.plan["roots"][root], relative) as (stream, before):
                size, sha = scan_content(stream, role, self.max_file)
                need(before == identity(os.fstat(stream.fileno())) and size == before["size"],
                     "selected source changed while hashing")
                if role == "test-log-gzip":
                    stream.seek(0)
                    with gzip.GzipFile(fileobj=stream, mode="rb") as log:
                        expanded_size, expanded_sha = scan_content(log, "raw", self.plan.get("max_expanded_log_bytes", 512 * 1024 * 1024))
                        expanded = {"bytes": expanded_size, "sha256": expanded_sha}
                    need(before == identity(os.fstat(stream.fileno())), "gzip source changed during verification")
        except FileNotFoundError:
            if optional:
                self.discovery.append({"source": relative, "status": "optional-absent"})
                return None
            raise
        if expected:
            if expected.get("sha256") is not None:
                need(sha == expected["sha256"], "original manifest hash differs: " + relative)
            if expected.get("bytes") is not None:
                need(size == expected["bytes"], "original manifest length differs: " + relative)
        entry = {"source_root": root, "source_relative": relative, "archive_path": archive,
                 "role": role, "bytes": size, "sha256": sha, "source_identity": before}
        if expanded is not None:
            entry["expanded_log"] = expanded
        if archive in self.files:
            previous = self.files[archive]
            need({k: v for k, v in previous.items() if k != "role"}
                 == {k: v for k, v in entry.items() if k != "role"}, "conflicting archive member")
            need(previous["role"] == role or {previous["role"], role} <= {"text", "raw"}, "conflicting evidence roles")
            if previous["role"] == "raw":
                entry["role"] = "raw"
        self.files[archive] = entry
        return entry

    def manifest_file(self, root, base, bundle, manifest, role="raw"):
        need(isinstance(manifest, dict), "expected original file manifest")
        name = basename(manifest["file"])
        need(isinstance(manifest.get("bytes"), int) and re.fullmatch("[0-9a-f]{64}", manifest.get("sha256", "")),
             "original file manifest lacks exact size/hash")
        return self.add(root, base + "/" + name, bundle + "/" + name, role, manifest)

    def transport(self, root, base, bundle, shutdown):
        self.manifest_file(root, base, bundle, shutdown["transport_capture"]["raw"])
        self.manifest_file(root, base, bundle, shutdown["transport_capture"]["index"])
        self.manifest_file(root, base, bundle, shutdown["resources"]["trace"])
        self.add(root, base + "/stderr.log", bundle + "/stderr.log", "raw", optional=True)

    def selector(self, selector):
        root, base, bundle = selector["root"], selector.get("base", ""), selector["bundle"]
        for name in selector.get("files", []):
            self.add(root, "/".join(filter(None, [base, name])), bundle + "/" + name,
                     selector.get("role", "text"), expected={"sha256": selector.get("expected_sha256", {}).get(name)})
        for name in selector.get("optional_files", []):
            self.add(root, "/".join(filter(None, [base, name])), bundle + "/" + name,
                     selector.get("role", "text"), optional=True)
        patterns = selector.get("patterns", [])
        if not patterns:
            return
        depth_limit = selector.get("depth", 0)
        need(0 <= depth_limit <= 3, "selector depth outside narrow bound")
        need(base or depth_limit == 0, "root metadata patterns must remain top-level only")
        found = 0
        try:
            with directory_fd(self.plan["roots"][root] + ("/" + base if base else "")) as fd:
                def walk(current, prefix, depth):
                    nonlocal found
                    for name in sorted(os.listdir(current)):
                        basename(name)
                        relative = "/".join(filter(None, [prefix, name]))
                        s = os.stat(name, dir_fd=current, follow_symlinks=False)
                        if stat.S_ISDIR(s.st_mode):
                            if name.lower() in DENIED_COMPONENTS or name.lower().startswith(("cargo-home", "target-")):
                                self.discovery.append({"source": base + "/" + relative, "status": "excluded-subtree"})
                            elif depth < depth_limit:
                                child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                                                dir_fd=current)
                                try:
                                    walk(child, relative, depth + 1)
                                finally:
                                    os.close(child)
                        elif any(fnmatch.fnmatchcase(relative, pattern) for pattern in patterns):
                            need(stat.S_ISREG(s.st_mode) and s.st_nlink == 1, "selected pattern hit symlink/hardlink/special file")
                            self.add(root, "/".join(filter(None, [base, relative])), bundle + "/" + relative,
                                     selector.get("role", "text"))
                            found += 1
                walk(fd, "", 0)
        except FileNotFoundError:
            need(selector.get("optional_base", False), "required selector base missing: " + base)
            self.discovery.append({"source": base, "status": "optional-base-absent"})
        need(found >= selector.get("min_matches", 0), "selector matched too few files: " + base)


def collect_campaign(c):
    p = c.package
    root, base, bundle, kind = p["campaign"]["root"], p["campaign"]["path"], p["campaign"]["bundle"], p["kind"]
    c.add(root, base + "/report.json", bundle + "/report.json",
          expected={"sha256": p.get("expected_report_sha256")})
    report = read_json(c, root, base + "/report.json")
    c.manifest_file(root, base, bundle, report["topology"], "text")
    need(set(report["topology"]["hosts"]) == HOSTS, "campaign topology is not the six declared aliases")
    if kind in {"native", "config"}:
        rounds = report["rounds"]
        need(len(rounds) == 4, "completed ABBA must have four rounds")
        for index, row in enumerate(rounds):
            arm = "ABBA"[index]
            for phase, shutdown, startup in [("first", "shutdown", "startup"), ("restart", "restart_shutdown", "restart_startup")]:
                rel = f"round-{index}-{arm}/{phase}"
                c.transport(root, base + "/" + rel, bundle + "/" + rel, row[shutdown])
                if kind == "config":
                    receipt = row[startup]["worker_configuration"]
                    c.manifest_file(root, base + "/" + rel, bundle + "/" + rel, receipt, "text")
                    snapshot = read_json(c, root, base + "/" + rel + "/" + basename(receipt["file"]))
                    need(snapshot["full_environment_retained"] is False, "whole environment retention is forbidden")
                    c.manifest_file(root, base + "/" + rel, bundle + "/" + rel, snapshot["selected_raw"], "worker-env")
    elif kind == "boundary":
        c.manifest_file(root, base, bundle, report["classification_policy"], "text")
        c.transport(root, base + "/controller/first", bundle + "/controller/first", report["shutdown"])
        c.transport(root, base + "/controller/restart", bundle + "/controller/restart", report["restart_shutdown"])
        originals = report["six_originals"]
        need(len(originals) == 6 and {x["host"] for x in originals} == HOSTS, "boundary original host set differs")
        need(len({x["job_id"] for x in originals}) == 6, "boundary job IDs are not unique")
        for item in originals:
            name = basename(item["job_id"]) + ".json"
            c.add(root, base + "/controller/state/jobs/" + name,
                  bundle + "/controller/state/jobs/" + name, expected={"sha256": item["record_sha256"]})
    elif kind == "recovery":
        for rel, key in [("first-controller", "intentional_crash"), ("after-crash-controller", "after_cancel_shutdown"),
                         ("after-cancel-controller", "shutdown")]:
            c.transport(root, base + "/" + rel, bundle + "/" + rel, report[key])
        for host in sorted(HOSTS):
            c.add(root, f"{base}/{host}-request.json", f"{bundle}/{host}-request.json")
        for row in report["native_calls"]:
            need(row["host"] in HOSTS and row["tool"] in {"start", "status", "read", "cancel"}, "unexpected native recovery call")
            expected = f"native-{row['sequence']:04d}-{row['host']}-{row['tool']}.json"
            need(legacy_basename(row["reply_path"]) == expected, "recovery reply basename differs")
            c.add(root, base + "/" + expected, bundle + "/" + expected, "raw",
                  {"bytes": row["reply_bytes"], "sha256": row["response_sha256"]})
        for row in report["ssh_calls"]:
            need(row["host"] in HOSTS, "unexpected SSH recovery host")
            basename(row["mode"])
            for stream in ["stdout", "stderr"]:
                item = row[stream]
                name = f"ssh-{row['sequence']:04d}-{row['host']}-{row['mode']}.{stream}"
                need(legacy_basename(item["path"]) == name, "recovery SSH stream basename differs")
                c.add(root, base + "/" + name, bundle + "/" + name, "raw", item)
    else:
        raise ValueError("unknown campaign kind")


def within_campaign(reference, absolute_base):
    need(isinstance(reference, str) and "\n" not in reference, "log reference must be a path")
    if reference.startswith("/"):
        need(reference.startswith(absolute_base + "/"), "referenced log is outside qualification")
        reference = reference[len(absolute_base) + 1:]
    parts(reference)
    return reference


def collect_qualification(c):
    """Resolve the actual composed-qualification and isolated-test schemas."""
    p, q = c.package, c.package["qualification"]
    root, base, bundle = q["root"], q["path"], q["bundle"]
    for name in ["report.json", "source-map.json", "cargo-no-run.jsonl", "retained-artifacts.jsonl",
                 "isolated-tests.audit.json", "isolated-tests/tests.jsonl", "isolated-tests/cargo-artifacts.jsonl",
                 "isolated-tests/commands.jsonl", "isolated-tests/source-manifest.input", "isolated-tests/summary.json"]:
        c.add(root, base + "/" + name, bundle + "/" + name,
              expected={"sha256": p.get("expected_report_sha256") if name == "report.json" else None})
    report = read_json(c, root, base + "/report.json")
    absolute = c.plan["roots"][root] + "/" + base
    need(report["schema"] == "hepta-x230-composed-qualification/v1", "qualification schema differs")
    tools = report["harness_before"]
    need(isinstance(tools, dict) and tools and tools == report["harness_after"], "qualification harness changed")
    for key, value in tools.items():
        name = legacy_basename(key)
        need(name.endswith(".py") and isinstance(value, str) and re.fullmatch("[0-9a-f]{64}", value),
             "unknown qualification harness manifest entry")
        c.add(root, "source/tools/x230/20261028/" + name,
              p["bundle_prefix"] + "/qualification-tools/" + name, "text", {"sha256": value})
    rows = report["stages"]
    need(isinstance(rows, list) and rows, "qualification stages missing")
    stage_count = 0
    for stage in rows:
        name = basename(stage["name"])
        for stream in ["stdout", "stderr"]:
            rel = "cargo-no-run.jsonl" if name == "test-build" and stream == "stdout" else name + "." + stream
            c.add(root, base + "/" + rel, bundle + "/" + rel, "raw",
                  {"sha256": stage[stream + "_sha256"]})
            stage_count += 1
    need(stage_count >= 2, "qualification stage-log schema did not resolve logs")
    count = 0
    for index_name in ["tests.jsonl", "commands.jsonl"]:
        for line in c.read_small(root, base + "/isolated-tests/" + index_name).splitlines():
            row = json.loads(line)
            if index_name == "tests.jsonl" and row.get("executed") is False:
                need(row.get("attempt") == 0, "unexecuted test has a nonzero attempt")
                continue  # Ignored rows remain in the unchanged original index.
            for stream in ["stdout", "stderr"]:
                name = basename(row[stream + "_gzip"])
                rel = "isolated-tests/" + name
                entry = c.add(root, base + "/" + rel, bundle + "/" + rel, "test-log-gzip")
                need(entry["expanded_log"]["bytes"] == row[stream + "_bytes"], "expanded test-log length differs")
                if stream + "_sha256" in row:
                    need(entry["expanded_log"]["sha256"] == row[stream + "_sha256"], "expanded test-log hash differs")
                count += 1
    need(count > 0, "no isolated test log references resolved")


def inventory(plan_path, package_id, output, probe_pending=False):
    plan_raw = Path(plan_path).read_bytes()
    plan = json.loads(plan_raw)
    need(plan["schema"] == SCHEMA, "unknown plan schema")
    matches = [p for p in plan["packages"] if p["id"] == package_id]
    need(len(matches) == 1, "package ID must match exactly one plan entry")
    package = matches[0]
    need(package["state"] == "complete" or probe_pending, "pending package needs --probe-pending; it remains un-packable")
    c = Collector(plan, package)
    if package["kind"] in {"native", "config", "boundary", "recovery"}:
        collect_campaign(c)
    elif package["kind"] == "qualification":
        collect_qualification(c)
    else:
        need(package["kind"] == "selectors", "unknown package kind")
    for selector in package.get("selectors", []):
        c.selector(selector)
    entries = [c.files[k] for k in sorted(c.files)]
    need(entries and sum(e["bytes"] for e in entries) <= plan.get("max_package_bytes", 768 * 1024 * 1024),
         "empty or oversized package")
    result = {"schema": SCHEMA, "package": package, "plan_sha256": digest(plan_raw),
              "tool_sha256": digest(Path(__file__).read_bytes()), "roots": plan["roots"],
              "files": entries, "source_bytes": sum(e["bytes"] for e in entries),
              "file_count": len(entries), "discovery": c.discovery,
              "original_bytes_changed": False, "contains_compiled_binaries": False,
              "packable": package["state"] == "complete"}
    with Path(output).open("xb") as stream:
        stream.write(encoded(result))
    return {"inventory": str(output), "sha256": digest(encoded(result)), "file_count": len(entries),
            "source_bytes": result["source_bytes"], "package": package_id}


class HashingReader:
    def __init__(self, stream):
        self.stream, self.sha, self.count = stream, hashlib.sha256(), 0

    def read(self, length=-1):
        raw = self.stream.read(length)
        self.sha.update(raw)
        self.count += len(raw)
        return raw


def tar_bytes(tar, name, raw):
    member = tarfile.TarInfo(name)
    member.size, member.mode, member.mtime = len(raw), 0o644, 0
    member.uid = member.gid = 0
    member.uname = member.gname = ""
    tar.addfile(member, io.BytesIO(raw))


def verify(archive_path, manifest_path=None):
    archive = Path(archive_path)
    with source_file(str(archive.absolute().parent), archive.name) as (raw, _):
        start = identity(os.fstat(raw.fileno()))
        archive_sha = hashlib.file_digest(raw, "sha256").hexdigest()
        raw.seek(0)
        with gzip.GzipFile(fileobj=raw, mode="rb") as gz:
            with tarfile.open(fileobj=gz, mode="r|") as tar:
                iterator = iter(tar)
                first = next(iterator, None)
                need(first is not None and first.isreg() and re.fullmatch(r"_publication/[A-Za-z0-9_.-]+/manifest.json", first.name),
                     "first member must be the package manifest")
                need(not first.pax_headers, "unexpected manifest PAX metadata")
                parts(first.name)
                need(first.size <= 32 * 1024 * 1024, "archive manifest exceeds bound")
                manifest_raw = tar.extractfile(first).read()
                if manifest_path:
                    external = Path(manifest_path).absolute()
                    with source_file(str(external.parent), external.name) as (stream, _):
                        need(manifest_raw == stream.read(32 * 1024 * 1024 + 1), "inside/outside manifests differ")
                manifest = json.loads(manifest_raw)
                need(manifest["schema"] == SCHEMA, "archive schema differs")
                expected = {e["archive_path"]: e for e in manifest["files"]}
                need(len(expected) == len(manifest["files"]), "duplicate manifest path")
                observed = set()
                for member in iterator:
                    parts(member.name)
                    need(member.isreg() and not member.issym() and not member.islnk(), "non-regular tar member")
                    need(set(member.pax_headers) <= {"path"}, "unexpected PAX metadata")
                    need(member.uid == member.gid == 0 and member.uname == member.gname == ""
                         and member.mode == 0o644 and member.mtime == 0, "non-canonical tar metadata")
                    need(member.name in expected and member.name not in observed, "unknown/duplicate tar member")
                    entry = expected[member.name]
                    need(member.size == entry["bytes"], "tar member length differs")
                    stream = tar.extractfile(member)
                    need(hashlib.file_digest(stream, "sha256").hexdigest() == entry["sha256"], "tar member hash differs")
                    observed.add(member.name)
                need(observed == set(expected), "tar is missing manifest members")
                # _Stream may have prefetched the second zero block and later data.
                # Drain that same stream before closing TarFile, never bypass its buffer.
                tail = tar.fileobj.read(1024 * 1024 + 1)
                need(512 <= len(tail) <= 1024 * 1024 and not tail.strip(b"\0"),
                     "missing second tar zero block or unexpected trailing data")
            need(gz.read(1) == b"", "unconsumed compressed payload")
        need(start == identity(os.fstat(raw.fileno())), "archive changed during verification")
    return {"verified": True, "archive_bytes": archive.stat().st_size, "archive_sha256": archive_sha,
            "manifest_sha256": digest(manifest_raw), "member_files": len(expected) + 1,
            "self_manifest_exclusion": "manifest does not hash itself; receipt hashes its exact bytes"}


def pack(inventory_path, output_dir):
    selection_raw = Path(inventory_path).read_bytes()
    selection = json.loads(selection_raw)
    need(selection["schema"] == SCHEMA and selection["package"]["state"] == "complete", "invalid/pending inventory")
    need(selection["tool_sha256"] == digest(Path(__file__).read_bytes()), "packager changed after inventory")
    package_id = selection["package"]["id"]
    need(re.fullmatch("[A-Za-z0-9_.-]+", package_id), "unsafe package ID")
    output = Path(output_dir)
    with directory_fd(str(output.absolute()), create=True):
        pass
    stem = selection["package"].get("archive_stem", package_id)
    need(re.fullmatch("[A-Za-z0-9_.-]+", stem), "unsafe archive stem")
    final = output / (stem + ".tar.gz")
    external = output / (stem + ".manifest.json")
    receipt_path = output / (stem + ".archive.json")
    need(not any(p.exists() or p.is_symlink() for p in [final, external, receipt_path]), "publication output already exists")
    manifest = dict(selection)
    manifest["inventory_sha256"] = digest(selection_raw)
    manifest["manifest_self_hash_policy"] = "Original evidence files only; this manifest is excluded from its own file list."
    manifest_raw = encoded(manifest)
    fd, temp_name = tempfile.mkstemp(prefix=".evidence-", suffix=".tmp", dir=output)
    os.close(fd)
    temporary = Path(temp_name)
    try:
        with temporary.open("wb") as raw:
            with gzip.GzipFile(filename="", fileobj=raw, mode="wb", compresslevel=6, mtime=0) as gz:
                with tarfile.open(fileobj=gz, mode="w|", format=tarfile.PAX_FORMAT) as tar:
                    tar_bytes(tar, f"_publication/{package_id}/manifest.json", manifest_raw)
                    for entry in selection["files"]:
                        relative, role = entry["source_relative"], entry["role"]
                        allowed_path(relative, role)
                        with source_file(selection["roots"][entry["source_root"]], relative) as (stream, before):
                            need(before == entry["source_identity"], "source metadata changed since inventory: " + relative)
                            reader = HashingReader(stream)
                            member = tarfile.TarInfo(entry["archive_path"])
                            parts(member.name)
                            member.size, member.mode, member.mtime = entry["bytes"], 0o644, 0
                            tar.addfile(member, reader)
                            need(stream.read(1) == b"", "source grew while archiving")
                            need(reader.count == entry["bytes"] and reader.sha.hexdigest() == entry["sha256"],
                                 "source bytes changed since inventory: " + relative)
                            need(before == identity(os.fstat(stream.fileno())), "source metadata changed during archive")
            raw.flush()
            os.fsync(raw.fileno())
        result = verify(temporary)
        need(result["manifest_sha256"] == digest(manifest_raw), "archive manifest changed")
        # Link publishes without replacing an existing artifact; unlink leaves nlink=1.
        os.link(temporary, final, follow_symlinks=False)
        temporary.unlink()
        with external.open("xb") as stream:
            stream.write(manifest_raw)
            stream.flush()
            os.fsync(stream.fileno())
        result.update({"package": package_id, "archive": final.name, "manifest": external.name,
                       "repo_dir": selection["package"]["repo_dir"],
                       "inventory_sha256": digest(selection_raw), "plan_sha256": selection["plan_sha256"],
                       "original_bytes_changed": False, "archive_contains_only_regular_files": True,
                       "over_50_mib": result["archive_bytes"] > 50 * 1024 * 1024})
        need(verify(final, external)["verified"], "published pair verification failed")
        with receipt_path.open("xb") as stream:
            stream.write(encoded(result))
            stream.flush()
            os.fsync(stream.fileno())
        with directory_fd(str(output.absolute())) as directory:
            os.fsync(directory)
        return result
    finally:
        if temporary.exists():
            temporary.unlink()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    show = sub.add_parser("show-plan", help="print plan metadata; do not access evidence roots")
    show.add_argument("--plan", required=True)
    collect = sub.add_parser("inventory", help="freeze a complete package's exact selected original files")
    collect.add_argument("--plan", required=True)
    collect.add_argument("--package", required=True)
    collect.add_argument("--output", required=True)
    collect.add_argument("--probe-pending", action="store_true", help="inspect a pending plan after its read window opens; resulting inventory cannot pack")
    archive = sub.add_parser("pack", help="pack one frozen inventory and independently verify the archive")
    archive.add_argument("--inventory", required=True)
    archive.add_argument("--output-dir", required=True)
    check = sub.add_parser("verify", help="stream-verify membership and original file hashes; no extraction")
    check.add_argument("--archive", required=True)
    check.add_argument("--manifest")
    args = parser.parse_args()
    if args.command == "show-plan":
        plan = json.loads(Path(args.plan).read_bytes())
        result = {"schema": plan["schema"], "packages": [{k: p[k] for k in ["id", "kind", "state"]}
                  for p in plan["packages"]], "evidence_roots_accessed": False}
    elif args.command == "inventory":
        result = inventory(args.plan, args.package, args.output, args.probe_pending)
    elif args.command == "pack":
        result = pack(args.inventory, args.output_dir)
    else:
        result = verify(args.archive, args.manifest)
    print(json.dumps(result, sort_keys=True, ensure_ascii=False))


if __name__ == "__main__":
    main()
