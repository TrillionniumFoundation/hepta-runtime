#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Verify the three actual R22 evidence archives locally, without extraction.

Every payload body is read and hashed. Omitted bodies and original filesystem
identities are remote declarations: only their metadata is checked here. This
program never opens a manifest source_path or follows an archive link.
"""
import argparse
from collections import Counter
from contextlib import contextmanager
import datetime
import gzip
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import tarfile


WORK = Path("/workspace/scratch/806ba5f52f94")
GROUPS = ("qualification", "microbenchmark", "campaign")
MANIFEST_NAME = "_export-manifest.json"
HEX = re.compile(r"[0-9a-f]{64}\Z")
CHUNK = 1024 * 1024
MAX_ARCHIVE_BYTES = 1024 * 1024 * 1024
MAX_MEMBER_BYTES = 1024 * 1024 * 1024
MAX_MANIFEST_BYTES = 64 * 1024 * 1024
MAX_UNCOMPRESSED_BYTES = 16 * 1024 * 1024 * 1024
MAX_MEMBERS = 100000
RECOVERY_SSH = "/home/qian/hepta-runtime-optimization-20261104-r16/r22-cancel-recovery-01/bin/ssh"
PRIVATE_PROFILE_NAMES = {"ssh_config", "known_hosts", "profile.json"}
OMISSION_REASONS = {
    "ELF body omitted; complete actual remote byte identity retained",
    "private transport configuration body omitted; exact identity retained",
    "fixture transport configuration/session wrapper body omitted; exact identity retained",
    "external system/profile input body omitted; exact identity retained",
}
IDENTITY_FIELDS = {"source_path", "bytes", "sha256", "original_identity", "is_elf"}
ORIGINAL_FIELDS = {
    "st_dev", "st_ino", "st_uid", "st_mode", "st_nlink", "st_size",
    "st_mtime_ns", "st_ctime_ns",
}
STAMP_FIELDS = (
    "st_dev", "st_ino", "st_uid", "st_gid", "st_mode", "st_nlink",
    "st_size", "st_mtime_ns", "st_ctime_ns",
)


class QAError(ValueError):
    pass


def need(condition, reason):
    if not condition:
        raise QAError(reason)


def utc():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def stamp(value):
    return tuple(getattr(value, key) for key in STAMP_FIELDS)


def safe_text(value, label):
    need(isinstance(value, str) and value, label + " must be a nonempty string")
    need(not any(ord(char) < 32 or ord(char) == 127 for char in value), label + " contains a control character")
    need("\\" not in value, label + " contains a backslash")
    try:
        value.encode("utf-8", "strict")
    except UnicodeError as error:
        raise QAError(label + " is not valid Unicode") from error
    return value


def archive_path(value):
    safe_text(value, "archive path")
    path = PurePosixPath(value)
    need(not path.is_absolute() and not re.match(r"^[A-Za-z]:", value), "absolute archive path")
    need(all(part not in {"", ".", ".."} for part in value.split("/")), "noncanonical archive path")
    need(path.as_posix() == value, "noncanonical archive path")
    return path


def source_path(value):
    safe_text(value, "source path metadata")
    path = PurePosixPath(value)
    need(value.startswith("/") and not value.startswith("//") and len(path.parts) > 1,
         "source path metadata is not a canonical absolute path")
    need(all(part not in {"", ".", ".."} for part in value[1:].split("/")) and path.as_posix() == value,
         "source path metadata is not canonical")
    return path


def digest_field(value, label):
    need(isinstance(value, str) and HEX.fullmatch(value), label + " is not a SHA-256")


def no_duplicate_keys(pairs):
    value = {}
    for key, item in pairs:
        need(key not in value, "duplicate JSON object key")
        value[key] = item
    return value


def reject_constant(_value):
    raise QAError("nonfinite JSON value")


def decode_json(raw):
    return json.loads(raw.decode("utf-8", "strict"), object_pairs_hook=no_duplicate_keys,
                      parse_constant=reject_constant)


@contextmanager
def stable_reader(path, maximum):
    need(path.is_absolute() and path.resolve() == path, "local input must be a direct absolute path")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and 0 <= before.st_size <= maximum,
             "local input must be a bounded, singly linked regular file")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            try:
                yield stream, before
            finally:
                need(stamp(before) == stamp(os.fstat(fd)) == stamp(path.lstat()),
                     "local input changed during QA")
    finally:
        os.close(fd)


def hash_file(stream, expected_size):
    digest, count = hashlib.sha256(), 0
    while block := stream.read(CHUNK):
        count += len(block)
        need(count <= expected_size, "local file grew during hashing")
        digest.update(block)
    need(count == expected_size, "local file size changed during hashing")
    return {"bytes": count, "sha256": digest.hexdigest()}


def load_receipt(path):
    with stable_reader(path, MAX_MANIFEST_BYTES) as (stream, before):
        raw = stream.read(MAX_MANIFEST_BYTES + 1)
        need(len(raw) == before.st_size, "identity receipt size changed")
        value = decode_json(raw)
    identity = {"path": str(path), "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
    need(isinstance(value, list) and len(value) == len(GROUPS), "exactly three archive identities required")
    by_group = {}
    for row in value:
        need(isinstance(row, dict) and row.get("name") in GROUPS, "unexpected archive identity group")
        group = row["name"]
        need(group not in by_group, "duplicate archive identity group")
        need(type(row.get("size")) is int and 0 < row["size"] <= MAX_ARCHIVE_BYTES, "invalid archive identity size")
        digest_field(row.get("sha256"), "archive identity SHA")
        remote = source_path(row.get("path"))
        need(remote.name == group + "-01.tar.gz", "archive identity filename differs")
        need(isinstance(row.get("version"), str) and row["version"], "archive source version missing")
        by_group[group] = row
    need(set(by_group) == set(GROUPS), "archive identity group set differs")
    return by_group, identity


def validate_identity(value, omitted=False):
    expected_fields = IDENTITY_FIELDS | ({"archive_path", "omission_reason"} if omitted else set())
    need(isinstance(value, dict) and set(value) == expected_fields, "manifest identity fields differ")
    source_path(value["source_path"])
    need(type(value["bytes"]) is int and 0 <= value["bytes"] <= MAX_MEMBER_BYTES, "invalid declared body length")
    digest_field(value["sha256"], "declared body SHA")
    need(type(value["is_elf"]) is bool, "invalid declared ELF flag")
    original = value["original_identity"]
    need(isinstance(original, dict) and set(original) == ORIGINAL_FIELDS, "original identity metadata fields differ")
    need(all(type(item) is int and item >= 0 for item in original.values()), "invalid original identity metadata")
    need(stat.S_ISREG(original["st_mode"]) and not original["st_mode"] & (stat.S_ISUID | stat.S_ISGID)
         and original["st_nlink"] >= 1 and original["st_size"] == value["bytes"],
         "inconsistent original identity metadata")
    if omitted:
        archive_path(value["archive_path"])
        need(value["omission_reason"] in OMISSION_REASONS, "unknown omission reason")
        if value["omission_reason"].startswith("ELF body omitted;"):
            need(value["is_elf"] is True, "ELF omission metadata has a false ELF flag")


def excluded_categories(name, identity):
    archived, original = archive_path(name), source_path(identity["source_path"])
    kinds = []
    if any(path.parent.name == "profile" and path.name in PRIVATE_PROFILE_NAMES for path in (archived, original)):
        kinds.append("private_profile_configuration")
    if any(path.name == "runtime.json" for path in (archived, original)):
        kinds.append("runtime_json")
    if name == "recovery/bin/ssh" or identity["source_path"] == RECOVERY_SSH:
        kinds.append("recovery_ssh_wrapper")
    if identity["is_elf"]:
        kinds.append("remotely_declared_elf")
    return kinds


def validate_inventory(value):
    need(isinstance(value, dict) and value, "source tree inventory metadata missing")
    for root, inventory in value.items():
        parent = source_path(root)
        need(isinstance(inventory, dict) and set(inventory) == {"files", "directories"},
             "source tree inventory metadata fields differ")
        for kind, entries in inventory.items():
            need(isinstance(entries, list) and all(isinstance(item, str) for item in entries),
                 "invalid source tree inventory metadata")
            need(len(entries) == len(set(entries)), "duplicate source tree inventory metadata path")
            need(all(source_path(item).is_relative_to(parent) for item in entries),
                 "source tree inventory path is outside its declared root")
        need(root in inventory["directories"], "source tree inventory root missing")


def validate_manifest(manifest, group, observed):
    fields = {"schema", "group", "files", "omitted_bodies", "source_trees",
              "qualification_report_sha256", "campaign_report_sha256"}
    need(isinstance(manifest, dict) and set(manifest) == fields, "manifest fields differ")
    need(manifest["schema"] == "hepta-r22-archive-manifest/v1" and manifest["group"] == group,
         "manifest schema/group differs")
    files, omitted = manifest["files"], manifest["omitted_bodies"]
    need(isinstance(files, dict) and files, "payload identity map missing")
    need(isinstance(omitted, list), "omitted body metadata must be a list")
    for key in ("qualification_report_sha256", "campaign_report_sha256"):
        digest_field(manifest[key], key)
    need(set(observed) == set(files), "actual payload member set differs from manifest.files")
    for name, expected in files.items():
        archive_path(name)
        need(name != MANIFEST_NAME, "manifest must not list itself as a payload")
        validate_identity(expected)
        actual = observed[name]
        need(actual["bytes"] == expected["bytes"] and actual["sha256"] == expected["sha256"],
             "payload SHA/bytes differ from manifest: " + name)
        need(not actual["is_elf"] and not excluded_categories(name, expected),
             "excluded ELF/private configuration body appears as payload: " + name)
    names, reasons, categories = set(), Counter(), Counter()
    omitted_bytes = 0
    for item in omitted:
        validate_identity(item, omitted=True)
        name = item["archive_path"]
        need(name != MANIFEST_NAME and name not in names and name not in files,
             "omitted body path is duplicate or intersects actual payload")
        names.add(name)
        reasons[item["omission_reason"]] += 1
        categories.update(excluded_categories(name, item))
        omitted_bytes += item["bytes"]
    validate_inventory(manifest["source_trees"])
    return {
        "payload_files": len(files), "payload_bytes": sum(row["bytes"] for row in observed.values()),
        "omitted_bodies": len(omitted), "omitted_declared_bytes": omitted_bytes,
        "omission_reasons": dict(sorted(reasons.items())),
        "omitted_metadata_categories": dict(sorted(categories.items())),
        "payload_member_set_matches_manifest": True,
        "all_payload_sha256_and_bytes_recomputed": True,
        "elf_and_named_private_configuration_payloads_absent": True,
        "omitted_metadata_structure_and_disjointness_verified": True,
        "omitted_body_hashes_locally_recomputed": False,
        "original_identity_and_source_tree_metadata_locally_reverified": False,
    }


def read_member(tar, member, retain=False):
    need(member.type in (tarfile.REGTYPE, tarfile.AREGTYPE) and member.sparse is None and not member.linkname,
         "nonregular/link/sparse semantic tar member: " + member.name)
    need(not any("sparse" in key.lower() or key in {"SCHILY.realsize", "SUN.holesdata"}
                 for key in member.pax_headers), "sparse tar metadata is forbidden")
    if "path" in member.pax_headers:
        archive_path(member.pax_headers["path"])
        need(member.pax_headers["path"] == member.name, "PAX path normalization is forbidden")
    maximum = MAX_MANIFEST_BYTES if retain else MAX_MEMBER_BYTES
    need(type(member.size) is int and 0 <= member.size <= maximum, "tar member size exceeds its bound")
    need(0 <= member.offset_data <= MAX_UNCOMPRESSED_BYTES
         and member.offset_data + member.size <= MAX_UNCOMPRESSED_BYTES, "tar offset exceeds its bound")
    stream = tar.extractfile(member)
    need(stream is not None, "regular tar member is unreadable")
    digest, count, head, parts = hashlib.sha256(), 0, b"", []
    with stream:
        while block := stream.read(CHUNK):
            count += len(block)
            need(count <= member.size, "tar member exceeds declared length")
            digest.update(block)
            if len(head) < 4:
                head = (head + block)[:4]
            if retain:
                parts.append(block)
    need(count == member.size, "truncated tar member")
    return {"bytes": count, "sha256": digest.hexdigest(), "is_elf": head == b"\x7fELF"}, b"".join(parts)


def inspect_archive(path, group, expected, row):
    observed, names, manifest, manifest_identity = {}, set(), None, None
    last_end = 0
    with stable_reader(path, MAX_ARCHIVE_BYTES) as (compressed, before):
        actual = hash_file(compressed, before.st_size)
        row.update(actual)
        need(actual["bytes"] == expected["size"] and actual["sha256"] == expected["sha256"],
             "archive SHA/size differs from transfer identity")
        row["archive_identity_matches_receipt"] = True
        compressed.seek(0)
        with gzip.GzipFile(fileobj=compressed, mode="rb") as unpacked:
            with tarfile.open(fileobj=unpacked, mode="r:", ignore_zeros=False, errorlevel=2) as tar:
                for member in tar:
                    archive_path(member.name)
                    need(member.name not in names, "duplicate semantic tar member name: " + member.name)
                    names.add(member.name)
                    need(len(names) <= MAX_MEMBERS, "too many semantic tar members")
                    identity, raw = read_member(tar, member, retain=member.name == MANIFEST_NAME)
                    if member.name == MANIFEST_NAME:
                        manifest = decode_json(raw)
                        manifest_identity = {"member": MANIFEST_NAME, "bytes": identity["bytes"], "sha256": identity["sha256"]}
                        row["manifest"] = manifest_identity
                    else:
                        observed[member.name] = identity
                    data_end = member.offset_data + member.size
                    padding = (-member.size) % tarfile.BLOCKSIZE
                    unpacked.seek(data_end)
                    block_padding = unpacked.read(padding)
                    need(len(block_padding) == padding and not any(block_padding), "nonzero or truncated tar body padding")
                    last_end = data_end + padding
            # TarFile stops at its first end marker. Read the complete gzip tail
            # independently, so a second tar or hidden nonzero trailer is rejected
            # and gzip CRC/length checks run through the actual end of stream.
            unpacked.seek(last_end)
            tail_bytes = 0
            while block := unpacked.read(CHUNK):
                tail_bytes += len(block)
                need(last_end + tail_bytes <= MAX_UNCOMPRESSED_BYTES, "uncompressed archive exceeds its bound")
                need(not any(block), "nonzero data after the semantic tar members")
            need(tail_bytes >= 2 * tarfile.BLOCKSIZE and tail_bytes % tarfile.BLOCKSIZE == 0,
                 "missing or noncanonical tar end padding")
    need(manifest is not None and manifest_identity is not None, "embedded export manifest missing")
    row.update(validate_manifest(manifest, group, observed))
    row.update(semantic_members=len(names), gzip_read_to_eof=True, gzip_crc_and_length_verified=True,
               only_regular_semantic_members=True, canonical_unique_member_paths=True,
               zero_tar_body_and_end_padding=True, uncompressed_bytes=last_end + tail_bytes, passed=True)
    return {
        "qualification_report_sha256": manifest["qualification_report_sha256"],
        "campaign_report_sha256": manifest["campaign_report_sha256"],
        "qualification_report": observed.get("qualification/report.json"),
        "campaign_report": observed.get("campaign/report.json"),
    }


def verify_cross_archive_reports(details):
    qualification = details["qualification"]["qualification_report"]
    campaign = details["campaign"]["campaign_report"]
    need(qualification is not None and campaign is not None, "actual qualification/campaign report payload missing")
    for value in details.values():
        need(value["qualification_report_sha256"] == qualification["sha256"]
             and value["campaign_report_sha256"] == campaign["sha256"],
             "manifest terminal-report identities disagree across archives")
    return {"verified": True,
            "qualification_report": {key: qualification[key] for key in ("bytes", "sha256")},
            "campaign_report": {key: campaign[key] for key in ("bytes", "sha256")}}


def write_report(path, report):
    need(path.is_absolute() and path.resolve() == path, "report output must be a direct absolute path")
    raw = (json.dumps(report, sort_keys=True, indent=2, allow_nan=False) + "\n").encode()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--identities", type=Path, default=WORK / "transfer/archive-identities.json")
    parser.add_argument("--archives-dir", type=Path, default=WORK / "evidence")
    parser.add_argument("--output", type=Path, default=WORK / "transfer/archive-tar-qa-report.json")
    args = parser.parse_args()
    need(args.output.is_absolute() and args.output.resolve() == args.output and not os.path.lexists(args.output),
         "fresh direct report output required; an existing QA result is never overwritten")
    report = {
        "schema": "hepta-r22-archive-tar-qa/v1", "started_utc": utc(), "passed": False, "archives": [],
        "scope": [
            "Local compressed archive SHA/size matched against the explicit transfer identity receipt.",
            "Every semantic tar member was read fully; payload SHA/bytes and the exact manifest member set were checked.",
            "No filesystem extraction, source_path access, remote operations, workload execution or Git/GitHub operations.",
            "Omitted bodies, original file stat identities and source inventories are remote metadata declarations only.",
            "ELF bodies and named private profile/runtime/recovery-SSH configurations are absent as payload members.",
            "No claim of locally rehashing omitted ELF/private configuration bodies or replaying benchmark correctness.",
        ],
    }
    details = {}
    try:
        identities, receipt_identity = load_receipt(args.identities)
        report["archive_identity_receipt"] = receipt_identity
        for group in GROUPS:
            path = args.archives_dir / (group + "-01.tar.gz")
            row = {"group": group, "path": str(path), "passed": False,
                   "source_archive_version": identities[group]["version"]}
            report["archives"].append(row)
            try:
                details[group] = inspect_archive(path, group, identities[group], row)
            except Exception as error:
                row["error"] = {"type": type(error).__name__, "reason": str(error)[:600]}
        if len(details) == len(GROUPS):
            report["cross_archive_report_bindings"] = verify_cross_archive_reports(details)
            report["passed"] = True
    except Exception as error:
        report["error"] = {"type": type(error).__name__, "reason": str(error)[:600]}
    report["finished_utc"] = utc()
    write_report(args.output, report)
    print(json.dumps({"passed": report["passed"], "report": str(args.output),
                      "archives": [{key: row[key] for key in ("group", "passed", "payload_files", "omitted_bodies", "error")
                                    if key in row} for row in report["archives"]],
                      "error": report.get("error")}, sort_keys=True), flush=True)
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
