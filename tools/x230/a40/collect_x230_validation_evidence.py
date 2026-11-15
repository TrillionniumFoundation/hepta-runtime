#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Collect selected, quiescent X230 validation evidence without changing it.

Example:
  python3 collect_x230_validation_evidence.py --root /abs/devroot \
      --out /abs/new-evidence-directory \
      --include a39-validation/file-pool-soak-r01 \
      --include a39-validation/file-pool-c16-r01 \
      --include small-archive-smoke-r01

Includes are relative files or directories. The output parent must exist; the
output itself must be new and outside every included directory. Failed product
checks are evidence to preserve, not a reason to omit that run. Collection
failure produces an explicit failed receipt, never a successful partial bundle.
No GitHub, SSH, subprocess, runtime configuration, or product API is used.

Archive members keep their original root-relative names and complete bytes.
Tar mtime/uid/gid are zero, names are empty, modes are 0600, members are sorted;
gzip filename is empty and mtime is zero. Reproducibility assumes the same
input bytes/relative names and Python/zlib implementation. Source stat values
are retained separately in manifest.json, not in archive metadata.
"""

import argparse
from collections import Counter, defaultdict
from contextlib import contextmanager
import gzip
import hashlib
import json
import math
import os
from pathlib import Path, PurePosixPath
import re
import stat
import statistics
import sys
import tarfile


BLOCK = 1024 * 1024
EXCLUDED_DIRS = frozenset({"state", "profile", "bin", "target", "source", "__pycache__",
                           ".ssh", ".gnupg", ".aws", "private-keys-v1.d"})
EXCLUDED_FILES = frozenset({"hepta-runtime", "hepta-runtime-tests", "profile.json",
    "runtime.json", "runtime-config.json", "config.json", "ssh_config", "ssh-config",
    "known_hosts", "known-hosts", "authorized_keys", "agent.json", "agent-config.json",
    "credentials", "credentials.json", "credentials.ini", "token", "token.json",
    "private-token", "private-token.json", ".env"})
SECRET_SUFFIXES = (".pem", ".key", ".p12", ".pfx", ".ppk", ".gpg", ".age")
PRIVATE_KEY = re.compile(rb"-----BEGIN (?:[A-Z0-9 ]*PRIVATE KEY|PGP PRIVATE KEY BLOCK)-----"
                         rb"|PuTTY-User-Key-File-[23]:")
TARGET_RUNS = frozenset({"file-pool-soak-r01", "file-pool-c16-r01"})
PHASES = frozenset({"warmup", "measured", "negative"})
CPU_SCOPE = ("RUSAGE_CHILDREN deltas recorded after each original controller wait; "
             "whole rounds including startup, warmup, measured calls, negative cases "
             "and shutdown; remote CPU and the external sampler's CPU excluded")
A39_SCOPE = ("These A39 transport observations are diagnostic evidence. The established "
             "staggered inherited-pipe compatibility regression disqualifies A39 as the "
             "final recovery candidate; no adoption or general recovery claim follows.")


def need(condition, message):
    if not condition:
        raise RuntimeError(message)


def canonical(value):
    return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=True,
                       allow_nan=False) + "\n").encode("utf-8")


def digest(data):
    return hashlib.sha256(data).hexdigest()


def fingerprint(value):
    # atime is intentionally absent: reading evidence may update it.
    return [value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid,
            value.st_nlink, value.st_size, value.st_mtime_ns, value.st_ctime_ns]


def location(value):
    return [value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid]


def relative_path(value):
    need(value and "\\" not in value and "\x00" not in value,
         "include must be a nonempty POSIX relative path")
    path = PurePosixPath(value)
    need(not path.is_absolute() and all(part not in ("", ".", "..")
         for part in value.split("/")), "include has absolute/dot/empty components: " + value)
    need(not any(ord(char) < 32 or ord(char) == 127 for char in value),
         "include contains control characters")
    need(not any(part in EXCLUDED_DIRS for part in path.parts[:-1]),
         "include traverses an excluded directory: " + value)
    return path.as_posix()


def file_exclusion(name):
    lower = name.lower()
    if lower in EXCLUDED_FILES or lower.startswith("id_") or lower.startswith(".env."):
        return "binary_or_credential_configuration_name"
    if lower.endswith(".next"):
        return "temporary_next_file"
    base = lower.removesuffix(".gz")
    if base.endswith(SECRET_SUFFIXES) or "private_key" in base or "private-key" in base:
        return "credential_material_filename"
    if lower.endswith((".pyc", ".pyo")):
        return "python_bytecode"
    return None


def error_record(stage, path, error):
    return {"stage": stage, "path": str(path),
            "error": type(error).__name__ + ": " + str(error)}


class Tree:
    """Descriptor-relative reads: no intermediate or final symlinks are followed."""

    def __init__(self, root):
        self.root = root
        self.fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        self.identity = location(os.fstat(self.fd))

    def close(self):
        os.close(self.fd)

    def check_root(self):
        need(location(self.root.lstat()) == self.identity == location(os.fstat(self.fd)),
             "root directory identity changed")

    @contextmanager
    def parent(self, relative):
        parts = PurePosixPath(relative).parts
        fd = os.dup(self.fd)
        try:
            for part in parts[:-1]:
                next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
                                  | os.O_CLOEXEC, dir_fd=fd)
                os.close(fd)
                fd = next_fd
            yield fd, parts[-1]
        finally:
            os.close(fd)

    @contextmanager
    def opened_file(self, relative, expected):
        with self.parent(relative) as (parent, name):
            before = os.stat(name, dir_fd=parent, follow_symlinks=False)
            need(stat.S_ISREG(before.st_mode) and fingerprint(before) == expected,
                 "input changed or is not regular: " + relative)
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK,
                         dir_fd=parent)
            try:
                need(fingerprint(os.fstat(fd)) == expected, "input changed while opening: " + relative)
                with os.fdopen(os.dup(fd), "rb") as stream:
                    yield stream
                need(fingerprint(os.fstat(fd)) == expected
                     == fingerprint(os.stat(name, dir_fd=parent, follow_symlinks=False)),
                     "input changed while reading: " + relative)
            finally:
                os.close(fd)

    def inventory(self, includes):
        files, directories, excluded, errors = {}, {}, {}, []

        def walk(parent, name, relative):
            try:
                value = os.stat(name, dir_fd=parent, follow_symlinks=False)
                need(not stat.S_ISLNK(value.st_mode), "symlink refused")
                if stat.S_ISDIR(value.st_mode):
                    if name in EXCLUDED_DIRS:
                        excluded[relative] = "excluded_directory"
                        return
                    fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
                                 | os.O_CLOEXEC, dir_fd=parent)
                    try:
                        before = fingerprint(value)
                        need(fingerprint(os.fstat(fd)) == before, "directory changed while opening")
                        directories[relative] = before
                        for child in sorted(os.listdir(fd)):
                            need("\\" not in child and not any(ord(c) < 32 or ord(c) == 127
                                 for c in child), "unsafe archive member filename")
                            walk(fd, child, relative + "/" + child)
                        need(before == fingerprint(os.fstat(fd))
                             == fingerprint(os.stat(name, dir_fd=parent, follow_symlinks=False)),
                             "directory changed while enumerating")
                    finally:
                        os.close(fd)
                elif stat.S_ISREG(value.st_mode):
                    reason = file_exclusion(name)
                    if reason:
                        excluded[relative] = reason
                    else:
                        value = fingerprint(value)
                        need(relative not in files or files[relative] == value,
                             "overlapping include observed a changed file")
                        files[relative] = value
                else:
                    raise RuntimeError("non-regular input refused")
            except Exception as error:
                errors.append(error_record("inventory", relative, error))

        self.check_root()
        for relative in includes:
            try:
                with self.parent(relative) as (parent, name):
                    walk(parent, name, relative)
            except Exception as error:
                errors.append(error_record("include", relative, error))
        self.check_root()
        return {"files": files, "directories": directories, "excluded": excluded}, errors


class HashedReader:
    def __init__(self, source):
        self.source = source
        self.hash = hashlib.sha256()
        self.size = 0
        self.tail = b""

    def read(self, size=-1):
        data = self.source.read(size)
        need(PRIVATE_KEY.search(self.tail + data) is None,
             "private-key material detected; evidence was not redacted or accepted")
        self.tail = (self.tail + data)[-160:]
        self.size += len(data)
        self.hash.update(data)
        return data

    def result(self):
        return {"bytes": self.size, "sha256": self.hash.hexdigest()}


def first_pass(tree, inventory):
    entries, errors = [], []
    for relative, expected in sorted(inventory["files"].items()):
        try:
            with tree.opened_file(relative, expected) as stream:
                reader = HashedReader(stream)
                while reader.read(BLOCK):
                    pass
            need(reader.size == expected[6], "full input length differs")
            # Compressed JSONL/raw evidence must not hide a private-key marker.
            # A malformed gzip remains at the input path and fails collection;
            # it is never silently treated as a checked successful subset.
            if relative.endswith(".gz"):
                with tree.opened_file(relative, expected) as stream:
                    with gzip.GzipFile(fileobj=stream, mode="rb") as uncompressed:
                        scanned = HashedReader(uncompressed)
                        while scanned.read(BLOCK):
                            pass
            entries.append({"path": relative, **reader.result(), "source_stat": expected})
        except Exception as error:
            errors.append(error_record("first_complete_read", relative, error))
    return entries, errors


def make_bundle(tree, inventory, entries, destination):
    with destination.open("xb") as raw:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw, compresslevel=9, mtime=0) as zipped:
            with tarfile.open(fileobj=zipped, mode="w|", format=tarfile.PAX_FORMAT) as archive:
                for entry in entries:
                    relative = entry["path"]
                    with tree.opened_file(relative, inventory["files"][relative]) as stream:
                        reader = HashedReader(stream)
                        member = tarfile.TarInfo(relative)
                        member.size, member.mode = entry["bytes"], 0o600
                        member.uid = member.gid = member.mtime = 0
                        member.uname = member.gname = ""
                        member.pax_headers = {}
                        archive.addfile(member, reader)
                        need(reader.read(1) == b"", "input grew past archived length: " + relative)
                        need(reader.result() == {key: entry[key] for key in ("bytes", "sha256")},
                             "second complete input SHA/length differs: " + relative)
        raw.flush()
        os.fsync(raw.fileno())


def file_receipt(path):
    size, hashed = 0, hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(BLOCK), b""):
            size += len(chunk)
            hashed.update(chunk)
    return {"path": path.name, "bytes": size, "sha256": hashed.hexdigest()}


def row_statistics(rows):
    values = sorted(row["elapsed_ms"] for row in rows)
    good = sum(row["okay"] is True for row in rows)
    return {"count": len(rows), "checks_passed": good, "checks_failed": len(rows) - good,
            "all_okay": bool(rows) and good == len(rows),
            "check_success_rate": good / len(rows) if rows else None,
            "latency_ms_all_attempts": None if not values else {
                "min": values[0], "mean": statistics.mean(values),
                "p50": statistics.median(values),
                "p95": values[math.ceil(.95 * len(values)) - 1],
                "p99": values[math.ceil(.99 * len(values)) - 1], "max": values[-1]}}


def numeric(value):
    return type(value) in (int, float) and math.isfinite(value) and value >= 0


def logical_slot(row):
    base = (row["round"], row["mode"], row["phase"])
    if row["phase"] == "measured":
        for name in ("iteration", "concurrency", "index"):
            need(type(row.get(name)) is int and row[name] >= 0, "invalid measured slot: " + name)
        return base + (row["iteration"], row["concurrency"], row["index"])
    return base + (row["host"], row["tool"], row.get("expected_error"))


def summarize_run(relative, report_raw, call_inputs, entry_by_path):
    report = json.loads(report_raw)
    need(report.get("schema") == "hepta-x230-file-pool-abba/v1", "unexpected file-pool report schema")
    need(call_inputs, "complete calls.jsonl or calls.jsonl.gz is absent from collection")
    decoded = {name: gzip.decompress(data) if name.endswith(".gz") else data
               for name, data in call_inputs.items()}
    hashes = {digest(data) for data in decoded.values()}
    need(len(hashes) == 1 and report.get("calls_sha256") in hashes,
         "raw/gzip calls digest differs from report or from one another")
    calls_raw = next(iter(decoded.values()))
    need(not calls_raw or calls_raw.endswith(b"\n"), "calls JSONL ends with a partial line")
    rows = []
    for number, line in enumerate(calls_raw.splitlines(), 1):
        need(line.strip(), "empty calls JSONL row: " + str(number))
        row = json.loads(line)
        need(isinstance(row, dict) and row.get("phase") in PHASES
             and row.get("mode") in ("off", "on") and type(row.get("round")) is int
             and row["round"] >= 0 and type(row.get("okay")) is bool
             and type(row.get("automatic_retry")) is bool and numeric(row.get("elapsed_ms"))
             and isinstance(row.get("host"), str) and row.get("tool") in ("file_info", "binary_read"),
             "invalid calls JSONL row: " + str(number))
        rows.append(row)
    counts = Counter(logical_slot(row) for row in rows)
    duplicates = [{"slot": list(slot), "count": count} for slot, count in counts.items() if count > 1]
    issues = []
    if duplicates:
        issues.append("duplicate logical request slots")
    groups = defaultdict(list)
    for row in rows:
        groups[(row["phase"], row["mode"])].append(row)
    cells, represented, round_resources, snapshots, cpu = [], set(), [], [], []
    rounds = report.get("rounds", [])
    seen_rounds = set()
    for round_ in rounds:
        index, mode = round_["index"], round_["mode"]
        need((index, mode) not in seen_rounds, "duplicate round in report")
        seen_rounds.add((index, mode))
        for phase in ("warmup", "negative"):
            observed = [row for row in rows if row["round"] == index and row["mode"] == mode
                        and row["phase"] == phase]
            if observed != round_.get(phase, []):
                issues.append(f"round {index} {phase} report/rows differ")
        for cell in round_.get("cells", []):
            key = (index, mode, cell["iteration"], cell["concurrency"])
            need(key not in represented, "duplicate cell in report")
            represented.add(key)
            observed = [row for row in rows if row["phase"] == "measured"
                        and (row["round"], row["mode"], row["iteration"], row["concurrency"]) == key]
            stats = row_statistics(observed)
            consistent = (stats["count"] == cell["calls"] and stats["checks_passed"] == cell["success"]
                          and {row["index"] for row in observed} == set(range(cell["calls"])))
            for field, name in (("p50_ms", "p50"), ("p95_ms", "p95"), ("p99_ms", "p99")):
                actual = (stats["latency_ms_all_attempts"] or {}).get(name)
                consistent = consistent and numeric(actual) and math.isclose(actual, cell[field], rel_tol=1e-10, abs_tol=1e-9)
            wall = cell["seconds"]
            need(numeric(wall) and wall > 0, "invalid measured cell wall time")
            rate = stats["checks_passed"] / wall
            consistent = consistent and math.isclose(rate, cell["successful_calls_per_second"], rel_tol=1e-10, abs_tol=1e-9)
            if not consistent:
                issues.append(f"round {index}, iteration {key[2]}, C{key[3]} report/rows differ")
            cells.append({"round": index, "mode": mode, "iteration": key[2], "concurrency": key[3],
                          **stats, "measured_wall_seconds": wall,
                          "successful_calls_per_second": rate, "report_consistent": consistent,
                          "controller_only_cpu_ms_per_call_reported": cell.get("cpu_ms_per_call")})
            if isinstance(cell.get("resources"), dict):
                snapshots.append(cell["resources"])
        shutdown = round_.get("shutdown")
        waited = round_.get("waited_process_tree_cpu_seconds")
        if waited is not None:
            need(numeric(waited) and isinstance(shutdown, dict), "CPU receipt lacks shutdown/accounting")
            cpu.append({"round": index, "mode": mode, "seconds": waited,
                        "reported_scope": round_.get("waited_cpu_scope"),
                        "shutdown_exit_code": shutdown.get("exit_code"),
                        "shutdown_method": shutdown.get("shutdown_method")})
        if isinstance(shutdown, dict):
            resource = shutdown.get("resources", {})
            snapshots.append(resource)
            round_resources.append({"round": index, "mode": mode,
                "sampled_peaks": resource.get("peaks", {}),
                "samples": resource.get("samples"),
                "sampled_tree_cpu_seconds": resource.get("sampled_tree_cpu_seconds"),
                "observed_descendant_survivors": shutdown.get("observed_descendant_survivors"),
                "unmatched_responses": shutdown.get("unmatched_responses"),
                "reader_error": shutdown.get("reader_error")})
    unrepresented = sum(row["phase"] == "measured" and
        (row["round"], row["mode"], row["iteration"], row["concurrency"]) not in represented for row in rows)
    if unrepresented:
        issues.append(str(unrepresented) + " measured rows have no completed report cell")
    unmapped = sum((row["round"], row["mode"]) not in seen_rounds for row in rows)
    if unmapped:
        issues.append(str(unmapped) + " rows have no report round")
    if report.get("complete") is True:
        if [round_["mode"] for round_ in rounds] != report.get("order"):
            issues.append("complete report round order differs")
        if len(cpu) != len(rounds):
            issues.append("complete report is missing waited CPU receipts")
        if not rows or not all(row["okay"] for row in rows):
            issues.append("complete report contains failed or no check rows")
    peaks, errors = defaultdict(list), Counter()
    error_values = {}
    for snapshot in snapshots:
        need(isinstance(snapshot.get("peaks", {}), dict)
             and isinstance(snapshot.get("errors", []), list), "invalid resource snapshot")
        for name, value in snapshot.get("peaks", {}).items():
            need(numeric(value), "invalid resource peak: " + name)
            peaks[name].append(value)
        for error in snapshot.get("errors", []):
            key = canonical(error).decode()
            errors[key] += 1
            error_values[key] = error
    measured = [row for row in rows if row["phase"] == "measured"]
    wall = sum(cell["measured_wall_seconds"] for cell in cells)
    return {"report_path": relative, "report_sha256": entry_by_path[relative]["sha256"],
        "calls_inputs": [{"path": name, "sha256": entry_by_path[name]["sha256"]} for name in sorted(call_inputs)],
        "uncompressed_calls_sha256": digest(calls_raw), "report_complete": report.get("complete"),
        "report_error": report.get("error"), "candidate_is_final": False, "candidate_scope": A39_SCOPE,
        "consistency_passed": not issues, "consistency_errors": issues,
        "all_rows": row_statistics(rows), "measured_overall": {**row_statistics(measured),
            "sum_recorded_cell_wall_seconds": wall,
            "successful_calls_per_second": sum(row["okay"] for row in measured) / wall
                if wall and not unrepresented else None},
        "phase_mode": [{"phase": phase, "mode": mode, **row_statistics(groups[(phase, mode)])}
                       for phase in sorted(PHASES)
                       for mode in sorted({row["mode"] for row in rows} | set(report.get("order", [])))],
        "negative_success_meaning": "okay means the expected refusal was checked; not a successful file read",
        "automatic_retry_true_rows": sum(row["automatic_retry"] for row in rows),
        "all_rows_report_no_automatic_retry": all(not row["automatic_retry"] for row in rows),
        "request_uniqueness": {"logical_slots_unique": not duplicates, "duplicate_slots": duplicates,
            "wire_request_identity_proven": False,
            "scope": "logical schedule slots only; these call rows have no RPC/native request ID; response hashes are not request identities"},
        "cells": cells, "waited_local_process_tree_cpu": {"scope": CPU_SCOPE, "rounds": cpu,
            "seconds_sum": sum(item["seconds"] for item in cpu),
            "seconds_by_mode": {mode: sum(item["seconds"] for item in cpu if item["mode"] == mode)
                                for mode in sorted({item["mode"] for item in cpu})},
            "all_rounds_accounted": len(cpu) == len(rounds)},
        "resources": {"round_shutdown_observations": round_resources,
            "cumulative_snapshot_peak_ranges": {name: {"min": min(values), "max": max(values)}
                                                for name, values in sorted(peaks.items())},
            "distinct_observation_errors": [{"error": error_values[key], "snapshot_occurrences": errors[key]}
                                            for key in sorted(errors)],
            "error_occurrence_scope": "cells repeat accumulated errors; snapshot occurrences are not independent failures",
            "sampled_peaks_exhaustive": False, "fd_complete": False,
            "survivor_scope": "only descendants the sampler observed; not a universal no-processes proof"}}


def summarize_bundle(bundle, entries):
    by_path = {entry["path"]: entry for entry in entries}
    reports = sorted(path for path in by_path if PurePosixPath(path).name == "report.json"
                     and PurePosixPath(path).parent.name in TARGET_RUNS)
    wanted = set(reports)
    for relative in reports:
        parent = PurePosixPath(relative).parent
        wanted.update(str(parent / name) for name in ("calls.jsonl", "calls.jsonl.gz")
                      if str(parent / name) in by_path)
    blobs = {}
    with tarfile.open(bundle, "r|gz") as archive:
        for member in archive:
            if member.name in wanted:
                stream = archive.extractfile(member)
                need(stream is not None, "selected archive member is not regular")
                data = stream.read()
                need(len(data) == by_path[member.name]["bytes"]
                     and digest(data) == by_path[member.name]["sha256"], "archive member differs from manifest")
                blobs[member.name] = data
    summary = {"schema": "hepta-x230-collected-evidence-summary/v1", "complete": True,
               "candidate_is_final": False, "candidate_scope": A39_SCOPE,
               "other_reports": "preserved complete in bundle; not reclassified or summarized here",
               "target_run_names_not_in_collection": sorted(TARGET_RUNS - {PurePosixPath(p).parent.name for p in reports}),
               "runs": [], "errors": []}
    for relative in reports:
        try:
            parent = PurePosixPath(relative).parent
            calls = {name: data for name, data in blobs.items()
                     if PurePosixPath(name).parent == parent and PurePosixPath(name).name in ("calls.jsonl", "calls.jsonl.gz")}
            result = summarize_run(relative, blobs[relative], calls, by_path)
            summary["runs"].append(result)
            if not result["consistency_passed"]:
                summary["complete"] = False
        except Exception as error:
            summary["errors"].append(error_record("summary", relative, error))
            summary["complete"] = False
    return summary


def write_output(path, value):
    with path.open("xb") as stream:
        stream.write(canonical(value))
        stream.flush()
        os.fsync(stream.fileno())
    return file_receipt(path)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--include", action="append", required=True, dest="includes")
    args = parser.parse_args()
    os.umask(0o077)
    need(os.name == "posix" and hasattr(os, "O_NOFOLLOW"), "POSIX descriptor support is required")
    need(args.root.is_absolute() and args.root.is_dir() and args.root.resolve(strict=True) == args.root,
         "root must be an existing canonical absolute directory")
    need(args.out.is_absolute() and args.out.parent.is_dir()
         and args.out.parent.resolve(strict=True) == args.out.parent
         and not os.path.lexists(args.out), "out must be new with an existing canonical absolute parent")
    # Validate the destination before creating it: even invalid CLI arguments
    # must not create a directory inside an input run.
    includes = sorted({relative_path(value) for value in args.includes})
    for relative in includes:
        selected = args.root / relative
        need(selected != args.out and selected not in args.out.parents,
             "output lies inside an included path: " + relative)
        need(PurePosixPath(relative).name not in EXCLUDED_DIRS
             and file_exclusion(PurePosixPath(relative).name) is None,
             "explicit include is excluded by collection policy: " + relative)
    args.out.mkdir(mode=0o700)
    errors, entries, tree = [], [], None
    inventory = {"files": {}, "directories": {}, "excluded": {}}
    bundle = None
    collected = False
    summary = {"schema": "hepta-x230-collected-evidence-summary/v1", "complete": False,
               "candidate_is_final": False, "candidate_scope": A39_SCOPE,
               "runs": [], "errors": [], "reason": "collection did not complete"}
    try:
        tree = Tree(args.root)
        inventory, found = tree.inventory(includes)
        errors.extend(found)
        need(not errors, "inventory errors; no partial collection accepted")
        need(inventory["files"], "selection contains no collectable regular files")
        entries, found = first_pass(tree, inventory)
        errors.extend(found)
        need(not errors, "full input read errors; no partial collection accepted")
        partial = args.out / "evidence.tar.gz.partial"
        make_bundle(tree, inventory, entries, partial)
        final_inventory, found = tree.inventory(includes)
        errors.extend(found)
        need(not errors and final_inventory == inventory, "selected input tree changed during collection")
        final = args.out / "evidence.tar.gz"
        os.replace(partial, final)
        bundle = file_receipt(final)
        collected = True
        summary = summarize_bundle(final, entries)
    except BaseException as error:
        errors.append(error_record("collection", "", error))
    finally:
        if tree is not None:
            tree.close()
    manifest = {"schema": "hepta-x230-evidence-manifest/v1", "collection_complete": collected,
        "all_requested_files_collected_subject_to_explicit_exclusions": collected,
        "includes": includes, "source_root": str(args.root), "entries": entries,
        "file_count": len(entries), "input_bytes": sum(entry["bytes"] for entry in entries),
        "bundle": bundle, "excluded": [{"path": path, "reason": reason}
                                        for path, reason in sorted(inventory["excluded"].items())],
        "exclusion_policy": {"directories": sorted(EXCLUDED_DIRS), "filenames": sorted(EXCLUDED_FILES),
                             "additional": "*.next; id_*; .env.*; private-key/private_key names; credential suffixes; Python bytecode"},
        "verification": "two complete SHA256/length reads per archived file, descriptor/path stat checks before and after each read, unchanged final selected-tree inventory; atime excluded",
        "archive_metadata": {"member_order": "relative path ascending", "mtime": 0, "uid": 0,
                             "gid": 0, "uname": "", "gname": "", "mode_octal": "0600",
                             "gzip_mtime": 0, "gzip_filename": ""}, "errors": errors}
    manifest_receipt = write_output(args.out / "manifest.json", manifest)
    summary_receipt = write_output(args.out / "summary.json", summary)
    complete = collected and not errors and summary.get("complete") is True
    receipt = {"schema": "hepta-x230-evidence-collection/v1", "complete": complete,
               "collection_complete": collected, "summary_complete": summary.get("complete") is True,
               "product_validation_pass_claimed": False, "candidate_is_final": False,
               "bundle": bundle, "manifest": manifest_receipt, "summary": summary_receipt,
               "failed_partial_bundle": "evidence.tar.gz.partial" if (args.out / "evidence.tar.gz.partial").exists() else None,
               "errors": errors, "scope": "complete raw evidence preservation, including failed product checks"}
    write_output(args.out / "collection.json", receipt)
    fd = os.open(args.out, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
    print(json.dumps(receipt, sort_keys=True), flush=True)
    return 0 if complete else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        print(json.dumps({"schema": "hepta-x230-evidence-collection/v1", "complete": False,
                          "error": type(error).__name__ + ": " + str(error)}, sort_keys=True),
              file=sys.stderr, flush=True)
        raise SystemExit(1)
