#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Losslessly package P/series-r02 into fresh P/series-package-r01.

No workload, network, subprocess or source-publication action is performed.
The original publication remains read-only. Existing partial outputs are never
overwritten or removed. A complete manifest is written only after verification.
"""

import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys

DEFAULT_PUBLICATION_ROOT = Path("/home/qian/hepta-runtime-optimization-20261023/publication-a26-r01")
SOURCE_DIRECTORY = "series-r02"
OUTPUT_DIRECTORY = "series-package-r01"
SUMMARY_NAME = "summary.json"
SERIES_NAME = "series.complete.sanitized.json"
REVIEW_NAME = "review.json"
MANIFEST_NAME = "manifest.json"
REVIEW_KEY = "publication_review_index"
SCHEMA = "hepta-x230-a26-series-public-evidence/v1"
HEX256 = re.compile(r"[0-9a-f]{64}\Z")
SAFE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]*\Z")
BLOCK = 1024 * 1024
JSON_LIMIT = 64 * 1024 * 1024


def need(value, message):
    if not value:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode() + b"\n"


def decode(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            need(key not in result, "duplicate JSON key refused")
            result[key] = value
        return result
    def nonfinite(_value):
        raise ValueError("non-finite JSON value refused")
    return json.loads(raw, object_pairs_hook=unique, parse_constant=nonfinite)


def signature(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_nlink,
            info.st_uid, info.st_gid, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def regular(info):
    return stat.S_ISREG(info.st_mode) and info.st_nlink == 1


def read_file(path, retain=False, destination=None):
    """Read every byte once; optionally retain or copy, keeping FD/path fences."""
    need(path.is_absolute() and path.resolve() == path, "indirect input path refused")
    before_path = path.lstat()
    need(regular(before_path), "input is not a single-link regular file")
    if retain:
        need(before_path.st_size <= JSON_LIMIT, "JSON input exceeds complete parsing limit")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    content = bytearray() if retain else None
    digest, size = hashlib.sha256(), 0
    git = hashlib.sha1(b"blob " + str(before_path.st_size).encode("ascii") + b"\0")
    with os.fdopen(descriptor, "rb") as source:
        before_fd = os.fstat(source.fileno())
        need(signature(before_fd) == signature(before_path), "input changed while opening")
        while True:
            block = source.read(BLOCK)
            if not block:
                break
            size += len(block)
            need(size <= before_fd.st_size, "input grew during complete read")
            digest.update(block)
            git.update(block)
            if retain:
                content.extend(block)
            if destination is not None:
                destination.write(block)
        after_fd = os.fstat(source.fileno())
        after_path = path.lstat()
        need(size == before_fd.st_size and signature(before_fd) == signature(after_fd)
             == signature(after_path), "input changed during complete read")
    return ({"bytes": size, "sha256": digest.hexdigest(), "git_blob_sha1": git.hexdigest()},
            signature(after_path), bytes(content) if retain else None)


def valid_receipt(value, uncompressed=False):
    if not isinstance(value, dict):
        return False
    prefix = "uncompressed_" if uncompressed else ""
    size, digest = value.get(prefix + "bytes"), value.get(prefix + "sha256")
    return type(size) is int and size >= 0 and isinstance(digest, str) and HEX256.fullmatch(digest) is not None


def matches(actual, declared):
    return valid_receipt(declared) and all(actual[key] == declared[key] for key in ("bytes", "sha256"))


def gzip_contents(path, expected_bytes, expected_sha):
    """Hash the complete decompressed stream; do not parse or filter its records."""
    need(type(expected_bytes) is int and expected_bytes >= 0, "invalid decompressed size")
    need(isinstance(expected_sha, str) and HEX256.fullmatch(expected_sha), "invalid decompressed hash")
    before = path.lstat()
    need(regular(before), "compressed publication is not a single-link regular file")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    size, digest = 0, hashlib.sha256()
    with os.fdopen(descriptor, "rb") as source:
        need(signature(before) == signature(os.fstat(source.fileno())), "gzip changed while opening")
        with gzip.GzipFile(fileobj=source, mode="rb") as stream:
            while True:
                block = stream.read(BLOCK)
                if not block:
                    break
                size += len(block)
                need(size <= expected_bytes, "decompressed data exceeds declared complete size")
                digest.update(block)
        need(signature(before) == signature(os.fstat(source.fileno())) == signature(path.lstat()),
             "gzip changed during complete decompression")
    need(size == expected_bytes and digest.hexdigest() == expected_sha,
         "complete decompressed canonical bytes/hash differ")
    return {"uncompressed_bytes": size, "uncompressed_sha256": digest.hexdigest(),
            "complete_decompression_verified": True}


def new_file(path):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    return os.fdopen(descriptor, "wb")


def write_bytes(path, raw):
    with new_file(path) as output:
        output.write(raw)
        output.flush()
        os.fsync(output.fileno())
    receipt, _stamp, _ = read_file(path)
    need(receipt["bytes"] == len(raw) and receipt["sha256"] == sha(raw), "written output readback differs")
    return receipt


def write_gzip(path, raw):
    with new_file(path) as output:
        with gzip.GzipFile(fileobj=output, mode="wb", filename="", mtime=0, compresslevel=9) as stream:
            stream.write(raw)
        output.flush()
        os.fsync(output.fileno())
    receipt, _stamp, _ = read_file(path)
    decoded = gzip_contents(path, len(raw), sha(raw))
    return receipt, decoded


def copy_gzip(source, target, original, expected):
    with new_file(target) as output:
        copied, _stamp, _raw = read_file(source, destination=output)
        output.flush()
        os.fsync(output.fileno())
    need(matches(copied, original), "source bytes changed before exact gzip copy")
    receipt, _stamp, _raw = read_file(target)
    need(matches(receipt, original), "copied gzip bytes differ from original")
    decoded = gzip_contents(target, expected["uncompressed_bytes"], expected["uncompressed_sha256"])
    return receipt, decoded


def published_record(original_name, original, published_name, published, decoded, operation):
    return {"original_name": original_name, "original_bytes": original["bytes"],
            "original_sha256": original["sha256"], "published_name": published_name,
            "published_bytes": published["bytes"], "published_sha256": published["sha256"],
            "git_blob_sha1": published["git_blob_sha1"], "operation": operation, **decoded,
            "original_file_bytes_recoverable": True,
            "recovery": "gzip-decompress to original bytes" if operation == "gzip-original-json" else "published file is the exact original gzip bytes"}


def reduced_review(summary, full_summary):
    """Remove only the explicitly permitted receipt-index paths."""
    need(REVIEW_KEY not in summary, "review provenance key already exists in original summary")
    need(isinstance(summary.get("original_input_receipts"), dict), "original input receipt index missing")
    stages = summary.get("stages")
    need(isinstance(stages, dict) and all(isinstance(row, dict) for row in stages.values()), "stage map malformed")
    removed = []

    def index_receipt(pointer, value):
        need(isinstance(value, dict), "receipt index is not an object")
        encoded = canonical(value)
        return {"json_pointer": pointer, "entries": len(value),
                "canonical_value_bytes": len(encoded), "canonical_value_sha256": sha(encoded)}

    review = dict(summary)
    removed.append(index_receipt("/original_input_receipts", review.pop("original_input_receipts")))
    review["stages"] = {name: dict(row) for name, row in stages.items()}
    for name, row in review["stages"].items():
        if "artifact_receipts" in row:
            pointer = "/stages/" + name.replace("~", "~0").replace("/", "~1") + "/artifact_receipts"
            removed.append(index_receipt(pointer, row.pop("artifact_receipts")))
    # Reinsert precisely those indexes and prove exact canonical reconstruction.
    restored = dict(review)
    restored["original_input_receipts"] = summary["original_input_receipts"]
    restored["stages"] = {name: dict(row) for name, row in review["stages"].items()}
    for name, row in stages.items():
        if "artifact_receipts" in row:
            restored["stages"][name]["artifact_receipts"] = row["artifact_receipts"]
    raw_restored = canonical(restored)
    need(len(raw_restored) == full_summary["original_bytes"] and sha(raw_restored) == full_summary["original_sha256"],
         "review changed fields outside the permitted receipt indexes")
    review[REVIEW_KEY] = {"schema": "hepta-x230-a26-readable-review-index/v1",
        "role": "Readable index only; the complete original summary remains authoritative.",
        "complete_summary": full_summary, "removed_receipt_indexes": removed,
        "removed_receipt_index_entries": sum(row["entries"] for row in removed),
        "every_other_original_field_preserved": True,
        "original_summary_reconstruction_verified": True,
        "all_failure_rows_resources_errors_and_verdicts_preserved": True,
        "no_record_sampling_or_failure_filtering": True}
    return review, removed


def package(publication_root):
    root = publication_root
    need(root.is_absolute() and root.is_dir() and root.resolve() == root, "direct absolute publication root required")
    source, target = root / SOURCE_DIRECTORY, root / OUTPUT_DIRECTORY
    need(source.is_dir() and not source.is_symlink() and source.resolve() == source, "source publication directory unavailable or indirect")
    need(not os.path.lexists(target), "package output must be new; existing or partial attempt is preserved")
    summary_receipt, summary_stamp, summary_raw = read_file(source / SUMMARY_NAME, retain=True)
    summary = decode(summary_raw)
    need(isinstance(summary, dict) and summary.get("schema") == SCHEMA, "unsupported complete summary schema")
    need(canonical(summary) == summary_raw, "summary bytes are not the publisher's complete canonical JSON")
    declared = summary.get("public_artifacts")
    need(isinstance(declared, dict) and len(declared) == 17, "expected exactly seventeen declared original artifacts")
    need(all(isinstance(name, str) and SAFE_NAME.fullmatch(name) for name in declared), "unsafe artifact filename")
    gz_names = sorted(name for name in declared if name.endswith(".gz"))
    need(len(gz_names) == 16 and set(declared) == set(gz_names) | {SERIES_NAME}, "expected sixteen existing gzip files and one series JSON")
    stages = summary.get("stages")
    need(isinstance(stages, dict) and len(stages) == 11, "expected eleven explicit stage records")
    recorded = [name for name, row in stages.items() if isinstance(row, dict) and row.get("recorded") is True]
    need(len(recorded) == 8 and all(SAFE_NAME.fullmatch(name) for name in recorded), "expected eight recorded stages")
    expected_gz = {name + suffix for name in recorded
                   for suffix in (".complete.sanitized.json.gz", ".report.complete.sanitized.json.gz")}
    need(set(gz_names) == expected_gz, "complete stage gzip set differs from recorded stages")
    source_names = {SUMMARY_NAME, SERIES_NAME, *gz_names}
    need({path.name for path in source.iterdir()} == source_names, "source directory has missing or unexpected artifacts")
    originals, stamps, documents = {SUMMARY_NAME: summary_receipt}, {SUMMARY_NAME: summary_stamp}, {SUMMARY_NAME: summary_raw}
    for name in sorted(declared):
        receipt, stamp, raw = read_file(source / name, retain=name == SERIES_NAME)
        need(matches(receipt, declared[name]), "original artifact hash/size differs from complete summary: " + name)
        if name.endswith(".gz"):
            need(valid_receipt(declared[name], True), "complete uncompressed receipt missing: " + name)
        else:
            need(canonical(decode(raw)) == raw, "series bytes are not complete canonical JSON")
            documents[name] = raw
        originals[name], stamps[name] = receipt, stamp
    target.mkdir(mode=0o700)
    records = []
    for name in (SUMMARY_NAME, SERIES_NAME):
        published_name = name + ".gz"
        receipt, decoded = write_gzip(target / published_name, documents[name])
        records.append(published_record(name, originals[name], published_name, receipt, decoded, "gzip-original-json"))
    for name in gz_names:
        receipt, decoded = copy_gzip(source / name, target / name, originals[name], declared[name])
        records.append(published_record(name, originals[name], name, receipt, decoded, "exact-gzip-byte-copy"))
    full_summary = next(row for row in records if row["original_name"] == SUMMARY_NAME)
    review, removed = reduced_review(summary, full_summary)
    review_raw = canonical(review)
    review_receipt = write_bytes(target / REVIEW_NAME, review_raw)
    # Recheck the original inventory and stable file identities after packaging.
    need({path.name for path in source.iterdir()} == source_names, "source artifact set changed during packaging")
    need(all(signature((source / name).lstat()) == stamp for name, stamp in stamps.items()),
         "source publication metadata changed during packaging")
    script_receipt, _stamp, _raw = read_file(Path(__file__).absolute())
    manifest = {"schema": "hepta-x230-a26-lossless-publication-package/v1", "package_complete": True,
        "source_directory_name": SOURCE_DIRECTORY, "package_directory_name": OUTPUT_DIRECTORY,
        "original_files": 18, "preserved_evidence_files": len(records), "published_files_including_review_and_manifest": 20,
        "original_complete_summary": {"name": SUMMARY_NAME, **summary_receipt},
        "reported_verdicts_from_original_summary": {key: summary.get(key) for key in
            ("candidate_validation_passed", "artifact_integrity_passed", "comparison_valid", "performance_adoption")},
        "files": records,
        "readable_index": {"published_name": REVIEW_NAME, "published_bytes": review_receipt["bytes"],
            "published_sha256": review_receipt["sha256"], "git_blob_sha1": review_receipt["git_blob_sha1"],
            "complete_summary_reference": SUMMARY_NAME + ".gz", "complete_summary_original_sha256": summary_receipt["sha256"],
            "removed_receipt_indexes": removed, "review_exceeds_64kib": len(review_raw) > 65536,
            "replaces_complete_summary": False},
        "verification": {"all_original_public_artifact_hashes_and_sizes_match": True,
            "all_sixteen_original_gzip_files_copied_byte_for_byte": True,
            "all_published_gzip_streams_completely_decompressed_and_hash_verified": True,
            "both_original_json_files_recoverable_byte_for_byte": True,
            "every_other_summary_field_and_stage_field_preserved_in_review": True,
            "original_summary_reconstructed_from_review_and_omitted_indexes": True,
            "original_file_metadata_and_set_unchanged_after_packaging": True},
        "method": {"new_json_gzip": "gzip.GzipFile filename='', mtime=0, compresslevel=9; original JSON bytes are not reformatted.",
            "existing_gzip": "Exact full file copy; no decompression/recompression or gzip concatenation during copying.",
            "canonical_receipt": "Full decompressed stream bytes and SHA256 are compared to the frozen publisher receipt; no rows are parsed away or sampled.",
            "git_blob_sha1": "SHA1(b'blob ' + decimal exact file length + NUL + exact published bytes)",
            "review": "Only /original_input_receipts and each existing /stages/<id>/artifact_receipts are removed; their counts/hashes and full-summary reference are added.",
            "manifest_self_receipt": "The manifest file's bytes/SHA256/Git blob SHA1 are printed on stdout after its final write."},
        "script_sha256": script_receipt["sha256"], "script_bytes": script_receipt["bytes"],
        "workloads_reexecuted": False, "original_publication_modified": False,
        "runtime_or_repository_changes_performed": False}
    expected_output = {row["published_name"] for row in records} | {REVIEW_NAME}
    need({path.name for path in target.iterdir()} == expected_output, "unexpected package output set")
    manifest_receipt = write_bytes(target / MANIFEST_NAME, canonical(manifest))
    for directory in (target, root):
        descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    output_receipts = [{"name": row["published_name"], "bytes": row["published_bytes"],
                        "sha256": row["published_sha256"], "git_blob_sha1": row["git_blob_sha1"]} for row in records]
    output_receipts += [{"name": REVIEW_NAME, **review_receipt}, {"name": MANIFEST_NAME, **manifest_receipt}]
    return manifest, output_receipts


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--publication-root", type=Path, default=DEFAULT_PUBLICATION_ROOT)
    args = parser.parse_args(argv)
    try:
        manifest, files = package(args.publication_root)
    except (OSError, ValueError, TypeError, KeyError, EOFError) as error:
        print(json.dumps({"package_complete": False, "error_type": type(error).__name__,
            "errno": getattr(error, "errno", None),
            "reason": "filesystem operation failed; original and partial output preserved" if isinstance(error, OSError) else str(error),
            "workloads_reexecuted": False}), file=sys.stderr, flush=True)
        return 2
    print("file\tbytes\tsha256\tgit_blob_sha1")
    for row in sorted(files, key=lambda item: item["name"]):
        print("\t".join(str(row[key]) for key in ("name", "bytes", "sha256", "git_blob_sha1")))
    print(json.dumps({"package_complete": True, "published_files": len(files),
        "review_bytes": manifest["readable_index"]["published_bytes"],
        "review_exceeds_64kib": manifest["readable_index"]["review_exceeds_64kib"],
        "workloads_reexecuted": False}), flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
