#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Read qualified A26/A20 source bytes and create one publication manifest.

Does not build, run, modify, adopt, or publish a runtime. Executable identities
come from the qualification reports; neither executable is rehashed here.
"""

import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys


ROOT = Path("/home/qian/hepta-runtime-optimization-20261023")
A26_REPORT_SHA = "6e8ee71968d883b100dff89b96e4c9878c68b45b215487fefbb60fa08aa9c7cf"
A20_REPORT_SHA = "35ccff9730cf28330e9f3d646f04cd12d0b66ec5d457b9039d8d94b34a359461"
A26_MAP_SHA = "2822cb186ad0d6380a20baa699f5b6e7ed02a9c4cbd0079ca6e50c17a414d2a0"
A26_BINARY_SHA = "52b9a64618b46d04f339e4af2ce91450894d65a57a5ba58bdff7f4fc0ecadb0a"
A20_BINARY_SHA = "727c4661450fdb2a2a44b63f7f9442a5cd20ad854f1c26b043ac710b6fa2ea06"
HEX256 = re.compile(r"[0-9a-f]{64}\Z")
DOCUMENT_LIMIT = 4 * 1024 * 1024
DIRECTORY_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
FILE_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK


def need(value, reason):
    if not value:
        raise ValueError(reason)


def canonical(value):
    # Match qualification's source-map convention: sorted compact JSON, no EOF.
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def signature(value):
    # Reading can update atime; atime is not an input to content identity.
    return (value.st_dev, value.st_ino, value.st_mode, value.st_nlink,
            value.st_uid, value.st_gid, value.st_size, value.st_mtime_ns, value.st_ctime_ns)


def regular(value):
    return stat.S_ISREG(value.st_mode) and value.st_nlink == 1


def read_regular(parent, name, retain=False):
    before_path = os.stat(name, dir_fd=parent, follow_symlinks=False)
    need(regular(before_path), "input is not a single-link regular file: " + name)
    if retain:
        need(before_path.st_size <= DOCUMENT_LIMIT, "document exceeds complete parsing bound")
    descriptor = os.open(name, FILE_FLAGS, dir_fd=parent)
    with os.fdopen(descriptor, "rb") as source:
        before_fd = os.fstat(source.fileno())
        need(signature(before_path) == signature(before_fd), "input changed while opening: " + name)
        digest = hashlib.sha256()
        git = hashlib.sha1(b"blob " + str(before_fd.st_size).encode("ascii") + b"\0")
        content = bytearray() if retain else None
        size = 0
        for block in iter(lambda: source.read(1024 * 1024), b""):
            size += len(block)
            need(size <= before_fd.st_size, "input grew during complete read: " + name)
            digest.update(block)
            git.update(block)
            if retain:
                content.extend(block)
        after_fd = os.fstat(source.fileno())
        after_path = os.stat(name, dir_fd=parent, follow_symlinks=False)
        need(size == before_fd.st_size and signature(before_fd) == signature(after_fd)
             == signature(after_path), "input changed during complete read: " + name)
    return ({"bytes": size, "sha256": digest.hexdigest(), "git_blob_sha1": git.hexdigest(),
             "mode": "100755" if before_fd.st_mode & stat.S_IXUSR else "100644",
             "filesystem_mode": format(stat.S_IMODE(before_fd.st_mode), "04o")},
            signature(after_fd), bytes(content) if retain else None)


def read_document(path):
    need(path.is_absolute() and path.parent.resolve() == path.parent, "indirect document parent refused")
    parent = os.open(path.parent, DIRECTORY_FLAGS)
    try:
        return read_regular(parent, path.name, retain=True)
    finally:
        os.close(parent)


def decode(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            need(key not in result, "duplicate qualification JSON key")
            result[key] = value
        return result
    def nonfinite(_value):
        raise ValueError("non-finite qualification JSON number")
    result = json.loads(raw, object_pairs_hook=unique, parse_constant=nonfinite)
    need(isinstance(result, dict), "qualification must be an object")
    return result


def valid_map(value, count):
    if not isinstance(value, dict) or len(value) != count:
        return False
    for name, digest in value.items():
        if not isinstance(name, str) or not name or "\0" in name or "\\" in name:
            return False
        path = PurePosixPath(name)
        if path.is_absolute() or path.as_posix() != name or any(part in {"", ".", ".."} for part in name.split("/")):
            return False
        if not isinstance(digest, str) or HEX256.fullmatch(digest) is None:
            return False
    return True


def walk_source(root, expected, hash_contents):
    """Anchor every component to fresh directory FDs, refusing symlinks/special files."""
    need(root.is_absolute() and root.resolve() == root, "indirect source root refused")
    root_before = root.lstat()
    need(stat.S_ISDIR(root_before.st_mode), "source root is not a directory")
    descriptor = os.open(root, DIRECTORY_FLAGS)
    files, file_stamps, directory_stamps = {}, {}, {}
    try:
        need(signature(root_before) == signature(os.fstat(descriptor)), "source root changed while opening")
        def walk(parent, prefix):
            before = os.fstat(parent)
            for name in sorted(os.listdir(parent)):
                need(name not in {".", ".."} and "/" not in name, "invalid source directory entry")
                relative = prefix + name
                item = os.stat(name, dir_fd=parent, follow_symlinks=False)
                if stat.S_ISDIR(item.st_mode):
                    child = os.open(name, DIRECTORY_FLAGS, dir_fd=parent)
                    try:
                        need(signature(item) == signature(os.fstat(child)), "source directory changed while opening")
                        walk(child, relative + "/")
                        need(signature(item) == signature(os.stat(name, dir_fd=parent, follow_symlinks=False)),
                             "source directory path changed during traversal")
                    finally:
                        os.close(child)
                else:
                    need(regular(item), "source contains a symlink, special file, or multiply linked file: " + relative)
                    need(relative in expected, "source contains an unqualified extra file: " + relative)
                    if hash_contents:
                        receipt, stamp, _ = read_regular(parent, name)
                        need(receipt["sha256"] == expected[relative], "qualified source content differs: " + relative)
                        files[relative] = {"path": relative, **receipt}
                        file_stamps[relative] = stamp
                    else:
                        file_stamps[relative] = signature(item)
            after = os.fstat(parent)
            need(signature(before) == signature(after), "source directory changed during traversal")
            directory_stamps[prefix] = signature(after)
        walk(descriptor, "")
        need(signature(root_before) == signature(os.fstat(descriptor)) == signature(root.lstat()),
             "source root changed during traversal")
    finally:
        os.close(descriptor)
    need(set(file_stamps) == set(expected), "complete source file set differs from qualification")
    return files, {"files": file_stamps, "directories": directory_stamps}


def qualification(root, label, count, binary_sha):
    source_name = "source-a26-r01" if label == "A26" else "source-a20"
    report_name = "qualification-" + label.lower() + "-r01/report.json"
    path = root / report_name
    receipt, stamp, raw = read_document(path)
    expected_report_sha = A26_REPORT_SHA if label == "A26" else A20_REPORT_SHA
    need(receipt["sha256"] == expected_report_sha, label + " raw qualification SHA differs")
    report = decode(raw)
    expected = report.get("source_tested")
    need(report.get("schema") == "runtime-candidate-qualification/v1"
         and report.get("qualified") is True, label + " qualification is not successful")
    need(valid_map(expected, count) and report.get("source_after") == expected,
         label + " tested/after source maps are not the exact expected equal set")
    need(report.get("source") == str(root / source_name), label + " qualification source path differs")
    need(isinstance(report.get("binary"), dict) and report["binary"].get("sha256") == binary_sha,
         label + " reported executable identity differs")
    map_sha = hashlib.sha256(canonical(expected)).hexdigest()
    if label == "A26":
        need(map_sha == A26_MAP_SHA, "A26 source-map SHA differs")
    summary = {"label": label, "source_directory": source_name,
               "qualification": {"path": report_name, "bytes": receipt["bytes"], "sha256": receipt["sha256"],
                                 "expected_sha256": expected_report_sha, "raw_sha256_pin_matched": True,
                                 "qualified": True, "source_tested_equals_source_after": True},
               "file_count": count, "qualified_source_map_sha256": map_sha,
               "reported_release_binary_sha256": binary_sha,
               "executable_rehashed_by_this_script": False}
    return summary, expected, {"path": path, "stamp": stamp}


def create_only(path, data):
    need(path.parent.is_dir() and path.parent.resolve() == path.parent, "output parent must already be a direct directory")
    parent = os.open(path.parent, DIRECTORY_FLAGS)
    try:
        descriptor = os.open(path.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                             0o600, dir_fd=parent)
        with os.fdopen(descriptor, "wb") as output:
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
        os.fsync(parent)
    finally:
        os.close(parent)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    args = parser.parse_args(argv)
    root = args.root
    need(root == ROOT and root.is_dir() and root.resolve() == root, "original x230 development root required")
    output = root / "publication-a26-r01/source-publication-manifest.json"
    need(not os.path.lexists(output), "publication manifest is create-only and already exists")
    started = datetime.datetime.now(datetime.timezone.utc).isoformat()
    summaries, expected_maps, snapshots, report_inputs = {}, {}, {}, []
    for label, count, binary_sha in (("A26", 156, A26_BINARY_SHA), ("A20", 149, A20_BINARY_SHA)):
        summary, expected, report_input = qualification(root, label, count, binary_sha)
        files, snapshot = walk_source(root / summary["source_directory"], expected, True)
        actual = {name: value["sha256"] for name, value in files.items()}
        need(actual == expected, label + " exact source map check failed")
        summary.update(actual_source_map_sha256=hashlib.sha256(canonical(actual)).hexdigest(),
                       files=[files[name] for name in sorted(files)], all_source_hashes_match_qualification=True,
                       exact_file_set_matches_qualification=True)
        summaries[label], expected_maps[label], snapshots[label] = summary, expected, snapshot
        report_inputs.append(report_input)
    # A final no-follow inventory/stat pass detects changes after an earlier
    # file's complete read; this is still an observation, not a filesystem freeze.
    for label in ("A26", "A20"):
        _, final = walk_source(root / summaries[label]["source_directory"], expected_maps[label], False)
        need(final == snapshots[label], label + " source metadata or file set changed after hashing")
    for item in report_inputs:
        need(signature(item["path"].lstat()) == item["stamp"], "qualification changed before manifest completion")
    candidate = {row["path"]: row for row in summaries["A26"]["files"]}
    baseline = {row["path"]: row for row in summaries["A20"]["files"]}
    categories = {key: [] for key in ("new", "changed", "unchanged", "removed")}
    for path in sorted(set(candidate) | set(baseline)):
        now, old = candidate.get(path), baseline.get(path)
        if now is None:
            state = "removed"
        elif old is None:
            state = "new"
        else:
            state = "changed" if now["sha256"] != old["sha256"] or now["mode"] != old["mode"] else "unchanged"
        categories[state].append(path)
        if now is not None:
            now.update(change_from_A20=state,
                       content_changed=old is None or now["sha256"] != old["sha256"],
                       git_mode_changed=old is None or now["mode"] != old["mode"],
                       filesystem_mode_changed=old is None or now["filesystem_mode"] != old["filesystem_mode"])
    script_receipt, _, _ = read_document(Path(__file__).absolute())
    result = {"schema": "hepta-x230-a26-source-publication-manifest/v1", "started_utc": started,
              "finished_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
              "source_manifest_complete": True, "sources_modified": False, "builds_or_tests_run": False,
              "runtime_executables_read_or_run": False, "source_adopted": False, "repository_tree_checked": False,
              "git_publication_performed": False, "script_sha256": script_receipt["sha256"],
              "script_bytes": script_receipt["bytes"], "candidate": summaries["A26"], "baseline": summaries["A20"],
              "comparison": {"basis": "source content SHA256 and normalized Git regular-file mode",
                             "counts": {key: len(value) for key, value in categories.items()}, "paths": categories},
              "method": {"git_blob_sha1": "SHA1(b'blob ' + decimal byte length + NUL + exact file bytes)",
                         "mode": "Git regular-file mode 100755 when owner execute bit is set; otherwise 100644. Raw permission bits are retained separately.",
                         "stable_read": "Single-link regular files; O_NOFOLLOW; fstat and descriptor-relative path stat before and after complete read; fresh directory-FD walk for every inventory.",
                         "final_fence": "Exact file-set and all file/directory metadata checked again after hashing. No filesystem snapshot or future immutability is asserted.",
                         "source_map_sha256": "SHA256 of compact key-sorted JSON without a trailing newline.",
                         "binary_scope": "Recorded release SHA identities are bound to the qualification reports; previously independent executable verification is not repeated here.",
                         "remaining_publication_gate": "Compare every A20 manifest path/blob/mode with the accepted repository source tree before applying an A26 source update."}}
    raw = canonical(result) + b"\n"
    create_only(output, raw)
    print(json.dumps({"manifest_written": True, "manifest": "publication-a26-r01/source-publication-manifest.json",
                      "sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw),
                      "candidate_files": len(candidate), "baseline_files": len(baseline),
                      "comparison_counts": result["comparison"]["counts"],
                      "source_adopted": False, "repository_tree_checked": False}, sort_keys=True), flush=True)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, TypeError, KeyError) as error:
        reason = ((error.strerror or "filesystem operation failed") if isinstance(error, OSError)
                  else str(error).replace(str(ROOT), "<x230-dev>"))
        print(json.dumps({"manifest_written": False, "error_type": type(error).__name__,
                          "error_errno": getattr(error, "errno", None),
                          "reason": reason, "source_adopted": False}), file=sys.stderr, flush=True)
        raise SystemExit(1)
