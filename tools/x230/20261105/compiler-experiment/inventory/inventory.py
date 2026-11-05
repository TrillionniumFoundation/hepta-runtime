#!/usr/bin/env python3
"""Read-only source/public-registry inventory; an unbound input cannot scan anything.

Only a fresh evidence directory is written. No subprocess, Cargo, Rust, network,
copy, archive decompression, installation, deletion or credential-body access.
"""
import argparse
from contextlib import contextmanager
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import time

SCHEMA = "hepta-compiler-source-cache-inventory-input/v1"
HARNESS_SHA = "e3d3660f26a8a3c8e895434f376564e0f2f17d1cdc922b2de94a73d0b2b4b1ef"
ORIGINAL_QUALIFIER_SHA = "95717717fd5421f2e31dbce24e2f8821696f57d779ce93e988ed66764159552d"
STAGES = ("format", "fmt-check", "harness-tests", "clippy", "test-build",
          "isolated-tests", "audit-isolated-tests", "release")
PUBLIC_SOURCE = "registry+https://github.com/rust-lang/crates.io-index"
PUBLIC_NAMESPACE = re.compile(r"index\.crates\.io-[0-9a-f]{8,64}")
PUBLIC_DOWNLOADS = {"https://static.crates.io/crates", "https://crates.io/api/v1/crates"}
FIELDS = ("st_dev", "st_ino", "st_uid", "st_mode", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns")
MAX_SECONDS = 120
MAX_ENTRIES = 20000
MAX_FILE_BYTES = 64 * 1024**2
MAX_READ_BYTES = 2 * 1024**3
MAX_EVIDENCE_BYTES = 16 * 1024**2
STATE = None


def need(value, reason):
    if not value:
        raise ValueError(reason)


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + "\n").encode()


def stamp(info):
    return {key: getattr(info, key) for key in FIELDS}


def canonical(path):
    path = Path(path)
    need(path.is_absolute() and ".." not in path.parts and str(path) == os.path.normpath(str(path)),
         "selected path must be absolute and normalized")
    return path


def budget():
    need(time.monotonic() - STATE["start"] <= MAX_SECONDS, "inventory time bound exceeded")
    need(STATE["bytes_read"] <= MAX_READ_BYTES, "inventory read-byte bound exceeded")


@contextmanager
def directory(path):
    """Adapt existing R28 descriptor-chain checks; never follow a path symlink."""
    path = canonical(path)
    chain = []
    try:
        for name in path.parts:
            parent = chain[-1][0] if chain else None
            fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                         **({"dir_fd": parent} if parent is not None else {}))
            info = os.fstat(fd)
            chain.append((fd, parent, name, (info.st_dev, info.st_ino, info.st_uid, info.st_mode)))
            need(info.st_uid in (0, os.geteuid()), "directory ancestor owner differs")
        need(os.fstat(chain[-1][0]).st_uid == os.geteuid(), "selected directory owner differs")
        yield chain[-1][0]
        for fd, parent, name, expected in chain:
            linked = os.lstat("/") if parent is None else os.stat(name, dir_fd=parent, follow_symlinks=False)
            current = os.fstat(fd)
            need(stat.S_ISDIR(linked.st_mode)
                 and (current.st_dev, current.st_ino, current.st_uid, current.st_mode) == expected
                 == (linked.st_dev, linked.st_ino, linked.st_uid, linked.st_mode),
                 "directory chain changed")
    finally:
        for fd, _, _, _ in reversed(chain):
            os.close(fd)


def protected(path):
    """Known credential/config/admin/cache locations are metadata-only, not omitted silently."""
    return (any(part in {".git", ".ssh", ".aws", ".cargo", "target", "target-build"} for part in path.parts)
            or any(part.startswith("target-build-") for part in path.parts)
            or path.name in {"credentials", "credentials.toml", ".netrc", ".npmrc", ".pypirc", ".env"}
            or path.name.startswith(".env."))


def file_identity(path, keep=False, limit=MAX_FILE_BYTES, allow_registry=False):
    budget()
    path = canonical(path)
    need(allow_registry or not protected(path), "protected input body was not read")
    with directory(path.parent) as parent:
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=parent)
        try:
            before = os.fstat(fd)
            need(stat.S_ISREG(before.st_mode) and before.st_uid == os.geteuid() and before.st_nlink == 1
                 and not before.st_mode & (stat.S_ISUID | stat.S_ISGID)
                 and 0 <= before.st_size <= limit, "file type/owner/link/size outside inventory bound")
            chunks, digest, count = [], hashlib.sha256(), 0
            while True:
                data = os.read(fd, 262144)
                if not data:
                    break
                count += len(data)
                STATE["bytes_read"] += len(data)
                budget()
                need(count <= before.st_size, "file grew during inventory")
                digest.update(data)
                if keep:
                    chunks.append(data)
            need(count == before.st_size and stamp(before) == stamp(os.fstat(fd))
                 == stamp(os.stat(path.name, dir_fd=parent, follow_symlinks=False)), "file changed while reading")
        finally:
            os.close(fd)
    row = {"path": str(path), "bytes": count, "sha256": digest.hexdigest(),
           "identity": stamp(before), "allocated_bytes": before.st_blocks * 512}
    previous = STATE["files"].setdefault(str(path), row)
    need(previous == row, "same input changed between reads")
    return row, b"".join(chunks)


def bound(ref):
    need(isinstance(ref, dict) and set(ref) == {"path", "bytes", "sha256"}, "invalid bound-file reference")
    need(type(ref["bytes"]) is int and isinstance(ref["sha256"], str)
         and re.fullmatch(r"[0-9a-f]{64}", ref["sha256"]), "unbound file identity")
    row, raw = file_identity(ref["path"], True)
    need({k: row[k] for k in ref} == ref, "bound file bytes/SHA differ")
    return json.loads(raw)


def observe(path):
    """Metadata only, including unknown Cargo configuration; never opens its body."""
    path = canonical(path)
    try:
        with directory(path.parent) as parent:
            info = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
        return {"path": str(path), "state": "present", "identity": stamp(info),
                "allocated_bytes": info.st_blocks * 512, "content_read": False}
    except FileNotFoundError:
        # Missing or dangling parents are not silently called definite absence.
        for ancestor in path.parents:
            try:
                info = ancestor.lstat()
            except FileNotFoundError:
                continue
            if not stat.S_ISDIR(info.st_mode):
                return {"path": str(path), "state": "indeterminate_parent", "content_read": False}
        return {"path": str(path), "state": "absent", "content_read": False}
    except (OSError, ValueError) as exc:
        return {"path": str(path), "state": "indeterminate", "error_type": type(exc).__name__, "content_read": False}


def source_inventory(root):
    files, directories, skipped = {}, {}, []
    root = canonical(root)

    def walk(path, depth):
        budget()
        need(depth <= 64, "source depth bound exceeded")
        with directory(path) as fd:
            before = os.fstat(fd)
            directories[str(path.relative_to(root))] = stamp(before)
            names = sorted(os.listdir(fd))
            STATE["entries"] += len(names)
            need(STATE["entries"] <= MAX_ENTRIES, "source entry bound exceeded")
            for name in names:
                child = path / name
                info = os.stat(name, dir_fd=fd, follow_symlinks=False)
                if protected(child) or info.st_uid != os.geteuid() or info.st_dev != before.st_dev:
                    skipped.append({"path": str(child), "identity": stamp(info), "content_read": False,
                                    "reason": "protected_location_or_foreign_owner_device"})
                elif stat.S_ISDIR(info.st_mode):
                    walk(child, depth + 1)
                elif stat.S_ISREG(info.st_mode):
                    try:
                        files[str(child.relative_to(root))] = file_identity(child)[0]
                    except (OSError, ValueError) as exc:
                        skipped.append({"path": str(child), "identity": stamp(info), "content_read": None,
                                        "read_attempted": True, "body_emitted": False,
                                        "reason": "unreadable_or_disallowed_file", "error_type": type(exc).__name__})
                else:
                    skipped.append({"path": str(child), "identity": stamp(info), "content_read": False,
                                    "reason": "symlink_or_special_file"})
            need(stamp(before) == stamp(os.fstat(fd)), "source directory changed during enumeration")

    walk(root, 0)
    return {"root": str(root), "files": files, "directories": directories, "unread_entries": skipped,
            "content_coverage_complete": not skipped,
            "hashed_file_logical_bytes": sum(v["bytes"] for v in files.values()),
            "hashed_file_allocated_bytes": sum(v["allocated_bytes"] for v in files.values())}


def index_path(name):
    name = name.lower()
    if len(name) <= 2:
        return f"{len(name)}/{name}"
    if len(name) == 3:
        return f"3/{name[0]}/{name}"
    return f"{name[:2]}/{name[2:4]}/{name}"


def optional_identity(path, keep=False, limit=MAX_FILE_BYTES):
    budget()
    meta = observe(path)
    if meta["state"] != "present":
        return meta, None
    try:
        row, raw = file_identity(path, keep, limit, allow_registry=True)
        return {"state": "read", **row}, raw
    except (OSError, ValueError) as exc:
        return {**meta, "state": "unreadable_or_disallowed", "content_read": None,
                "read_attempted": True, "body_emitted": False, "error_type": type(exc).__name__}, None


def registry_inventory(home, lock):
    packages = lock.get("package")
    need(isinstance(packages, list) and len(packages) <= 10000, "unsupported or oversized Cargo.lock package list")
    locked = []
    for p in packages:
        name, version, source = p.get("name"), p.get("version"), p.get("source")
        need(isinstance(name, str) and re.fullmatch(r"[A-Za-z0-9_-]{1,128}", name)
             and isinstance(version, str) and re.fullmatch(r"[0-9A-Za-z.+-]{1,128}", version), "unsafe lock package token")
        kind = "public_crates_io" if source == PUBLIC_SOURCE else "root_workspace_or_path" if source is None else "other_source"
        checksum = p.get("checksum")
        valid_checksum = isinstance(checksum, str) and re.fullmatch(r"[0-9a-f]{64}", checksum) is not None
        locked.append({"name": name, "version": version, "source_kind": kind,
                       "checksum": checksum if valid_checksum else None, "checksum_valid": valid_checksum})
    index_root = home / "registry/index"
    namespaces, found_map, identities = [], {}, {}
    root_observation = observe(index_root)
    if root_observation["state"] != "present":
        return {"index_root": root_observation, "lock_packages": locked, "namespaces": [],
                "observed_registry_map": {}, "file_identities": {}, "actual_target_dependency_closure": None}
    with directory(index_root) as fd:
        before = os.fstat(fd)
        names = sorted(os.listdir(fd))
        need(len(names) <= 64, "registry namespace bound exceeded")
        for name in names:
            item = os.stat(name, dir_fd=fd, follow_symlinks=False)
            ns = {"name": name, "identity": stamp(item), "public_registry_config_verified": False}
            namespaces.append(ns)
            if not PUBLIC_NAMESPACE.fullmatch(name) or not stat.S_ISDIR(item.st_mode):
                ns["state"] = "outside_public_sparse_allowlist_body_not_read"
                continue
            config_path = index_root / name / "config.json"
            config, raw = optional_identity(config_path, True, 8192)
            ns["config"] = config
            try:
                value = json.loads(raw) if raw is not None else None
                safe = (isinstance(value, dict) and set(value) <= {"dl", "api", "auth-required"}
                        and value.get("dl") in PUBLIC_DOWNLOADS
                        and value.get("api", "https://crates.io") == "https://crates.io"
                        and value.get("auth-required", False) is False)
            except (ValueError, TypeError):
                safe = False
            if not safe:
                ns["state"] = "public_config_unverified_no_registry_payload_followup"
                continue
            ns.update(state="observed_public_sparse_candidate", public_registry_config_verified=True,
                      config_structure={"keys": sorted(value), "download_endpoint_allowlisted": True,
                                        "api_endpoint_allowlisted": True, "authentication_required": False}, packages=[])
            # Record only the allowlisted structure and identity, never config text or arbitrary URLs.
            rel = str(config_path.relative_to(home))
            found_map[rel], identities[rel] = config["sha256"], config
            index_entries = {}
            for package in locked:
                budget()
                if package["source_kind"] != "public_crates_io":
                    continue
                package = dict(package)
                pname = package["name"]
                if pname not in index_entries:
                    entry_path = index_root / name / ".cache" / index_path(pname)
                    entry, _ = optional_identity(entry_path)
                    entry["locked_version_cksum"] = None
                    entry["internal_cache_format_interpreted"] = False
                    index_entries[pname] = entry
                    if entry["state"] == "read":
                        rel = str(entry_path.relative_to(home))
                        found_map[rel], identities[rel] = entry["sha256"], entry
                archive_path = home / "registry/cache" / name / f"{pname}-{package['version']}.crate"
                archive, _ = optional_identity(archive_path)
                package["archive"] = archive
                package["index_entry"] = index_entries[pname]
                package["archive_matches_lock_checksum"] = (archive["sha256"] == package["checksum"]
                    if archive["state"] == "read" and package["checksum_valid"] else None)
                if archive["state"] == "read":
                    rel = str(archive_path.relative_to(home))
                    found_map[rel], identities[rel] = archive["sha256"], archive
                ns["packages"].append(package)
        need(stamp(before) == stamp(os.fstat(fd)), "registry namespace directory changed during scan")
    return {"index_root": root_observation, "lock_packages": locked, "namespaces": namespaces,
            "observed_registry_map": found_map, "file_identities": identities,
            "hashed_file_logical_bytes": sum(v["bytes"] for v in identities.values()),
            "hashed_file_allocated_bytes": sum(v["allocated_bytes"] for v in identities.values()),
            "actual_target_dependency_closure": None, "index_version_checksums_verified": None,
            "registry_usable_by_selected_cargo_proven": False, "archive_expanded_bytes": None}


def disk(path):
    with directory(path) as fd:
        info, fs = os.fstat(fd), os.fstatvfs(fd)
        return {"path": str(path), "device": info.st_dev, "block_size": fs.f_frsize,
                "available_bytes": fs.f_bavail * fs.f_frsize, "available_inodes": fs.f_favail,
                "total_bytes": fs.f_blocks * fs.f_frsize}


def validate_selection(plan):
    """Pure in-memory shape validation, before any selected reference/path access."""
    need(set(plan) == {"schema", "selected", "accepted", "metadata_report", "original_harness_map", "paths"},
         "input fields differ")
    accepted = plan["accepted"]
    need(isinstance(accepted, dict) and set(accepted) ==
         {"commit", "source_tree", "source", "publication", "qualification", "source_map"}, "accepted fields differ")
    need(all(isinstance(accepted[k], str) and accepted[k] for k in ("commit", "source_tree", "source")),
         "accepted selection is partially unbound")
    canonical(accepted["source"])
    need(isinstance(plan["paths"], dict) and set(plan["paths"]) == {"cargo_home", "capacity_parent", "output"},
         "selected path fields differ")
    for path in plan["paths"].values():
        need(isinstance(path, str) and path, "selected path is unbound")
        canonical(path)
    for ref in [plan["metadata_report"], plan["original_harness_map"],
                *[accepted[k] for k in ("publication", "qualification", "source_map")]]:
        need(isinstance(ref, dict) and set(ref) == {"path", "bytes", "sha256"}
             and isinstance(ref["path"], str) and ref["path"]
             and type(ref["bytes"]) is int and ref["bytes"] >= 0
             and isinstance(ref["sha256"], str) and re.fullmatch(r"[0-9a-f]{64}", ref["sha256"]),
             "bound reference is incomplete")
        canonical(ref["path"])


def output_key(info):
    return (info.st_dev, info.st_ino, info.st_uid, info.st_mode)


def check_output(path, fd, expected, linked=True):
    need(output_key(os.fstat(fd)) == expected, "held evidence directory identity changed")
    if linked:
        with directory(path.parent) as parent:
            info = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
            need(stat.S_ISDIR(info.st_mode) and output_key(info) == expected,
                 "evidence directory path no longer names held directory")


def write_output(path, fd, expected, name, body, linked=True):
    need(name in {"report.json", "failure.json", "full-source-map.json", "registry-observed-map.json"},
         "unexpected evidence filename")
    check_output(path, fd, expected, linked)
    child = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                    0o600, dir_fd=fd)
    with os.fdopen(child, "wb") as stream:
        stream.write(body)
        stream.flush()
        os.fsync(stream.fileno())
        info = os.fstat(stream.fileno())
        need(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid() and info.st_nlink == 1
             and stat.S_IMODE(info.st_mode) == 0o600 and info.st_size == len(body), "evidence file identity differs")
    os.fsync(fd)
    check_output(path, fd, expected, linked)
    return {"path": str(path / name) if linked else None, "bytes": len(body), "sha256": hashlib.sha256(body).hexdigest()}


def admit(plan):
    need(plan["schema"] == SCHEMA and plan["selected"] is True, "unbound template: selected must be true in a NEW input")
    accepted = plan["accepted"]
    need(all(accepted[k] is not None for k in ("commit", "source_tree", "source")), "accepted binding missing")
    pub, qual, compiled = (bound(accepted[k]) for k in ("publication", "qualification", "source_map"))
    meta, harness = bound(plan["metadata_report"]), bound(plan["original_harness_map"])
    need(pub["verified"] is True and pub["candidate_adopted"] is True and pub["commit"] == accepted["commit"]
         and pub["source_tree"] == accepted["source_tree"]
         and pub["qualification_report_sha256"] == accepted["qualification"]["sha256"], "accepted publication differs")
    need(qual["qualified"] is True and qual["source"] == accepted["source"]
         and qual["source_tested"] == qual["source_after"] == compiled
         and qual["automatic_test_retries"] == 0 and [s["name"] for s in qual["stages"]] == list(STAGES)
         and all(s["returncode"] == 0 for s in qual["stages"]), "accepted qualification differs")
    need(meta["schema"] == "hepta-x230-compiler-metadata-preflight/v1" and meta["passed"] is True
         and meta["metadata_only"] is True and meta["accepted_commit"] == accepted["commit"]
         and meta["runtime"]["sha256"] == pub["runtime_sha256"] == qual["binaries"]["hepta-runtime"]["sha256"],
         "metadata is not successful for this accepted baseline")
    need(plan["original_harness_map"]["sha256"] == HARNESS_SHA and len(harness) == 19
         and harness["qualify.py"] == ORIGINAL_QUALIFIER_SHA
         and qual["harness_before"] == qual["harness_after"] == harness, "original harness binding differs")
    paths = {k: canonical(v) for k, v in plan["paths"].items()}
    need(set(paths) == {"cargo_home", "capacity_parent", "output"}, "selected paths differ")
    source, output = canonical(accepted["source"]), paths["output"]
    need(source != paths["cargo_home"] and not source.is_relative_to(paths["cargo_home"])
         and not paths["cargo_home"].is_relative_to(source), "source and Cargo home overlap")
    need(all(output != p and not output.is_relative_to(p) and not p.is_relative_to(output)
             for p in (source, paths["cargo_home"])), "evidence output overlaps inputs")
    return source, paths, compiled, harness


def main():
    global STATE
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--input-sha256", required=True)
    args = parser.parse_args()
    output = None
    output_fd = None
    output_identity = None
    report = {"schema": "hepta-compiler-source-cache-inventory/v1", "inventory_complete": False,
              "preparation_complete": False, "compiler_variant_qualified": False, "candidate_adopted": False,
              "source_or_cache_copied": False, "archives_decompressed": False, "tools_installed": False,
              "cargo_or_rust_executed": False, "credential_bodies_read": False,
              "clean_build_space_budget_bytes": None, "fresh_build_space_budget_passed": None,
              "sparse_registry_checksums_verified": None,
              "evidence_write_limit_bytes": MAX_EVIDENCE_BYTES}
    try:
        with args.input.open("rb") as stream:
            raw = stream.read(65537)
        need(len(raw) <= 65536 and hashlib.sha256(raw).hexdigest() == args.input_sha256, "input bytes/SHA differ")
        plan = json.loads(raw)
        # This check precedes every selected path, binding read, directory, statvfs or output write.
        need(plan.get("schema") == SCHEMA and plan.get("selected") is True,
             "unbound template: no selected source/cache path was read and no evidence directory was created")
        validate_selection(plan)
        STATE = {"start": time.monotonic(), "bytes_read": 0, "entries": 0, "files": {}}
        source, paths, compiled, harness = admit(plan)
        before_disk = disk(paths["output"].parent)
        need(before_disk["available_bytes"] >= MAX_EVIDENCE_BYTES and before_disk["available_inodes"] >= 8,
             "insufficient space for bounded evidence only; clean-build budget not assessed")
        with directory(paths["output"].parent) as parent:
            os.mkdir(paths["output"].name, mode=0o700, dir_fd=parent)
            output = paths["output"]
            created = os.stat(output.name, dir_fd=parent, follow_symlinks=False)
            output_fd = os.open(output.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                                dir_fd=parent)
            need(output_key(created) == output_key(os.fstat(output_fd))
                 and created.st_uid == os.geteuid() and stat.S_IMODE(created.st_mode) == 0o700,
                 "fresh evidence directory owner/mode/identity differs")
            output_identity = output_key(created)
        report.update(started_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                      input={"path": str(args.input.absolute()), "bytes": len(raw), "sha256": args.input_sha256},
                      bound_selection=plan, evidence_disk_before=before_disk)
        report["source"] = source_inventory(source)
        full = {k: v["sha256"] for k, v in report["source"]["files"].items()}
        current = {k: v for k, v in full.items() if k in ("Cargo.toml", "Cargo.lock", "rustfmt.toml")
                   or k.startswith(("src/", "examples/"))}
        actual_harness = {Path(k).name: v for k, v in full.items()
                          if Path(k).parent.as_posix() == "tools/x230/20261028" and k.endswith(".py")}
        report["source"]["compiled_map_matches_accepted"] = current == compiled
        report["source"]["harness_matches_original"] = actual_harness == harness
        report["source"]["observed_harness_map"] = actual_harness
        config_paths = {base / ".cargo" / name for base in (source, *source.parents) for name in ("config", "config.toml")}
        config_paths.update(paths["cargo_home"] / name for name in ("config", "config.toml"))
        report["cargo_config_metadata_only"] = [observe(p) for p in sorted(config_paths)]
        import tomllib  # Requires existing Python >=3.11; no install or alternate executable.
        _, lock_raw = file_identity(source / "Cargo.lock", True)
        report["registry"] = registry_inventory(paths["cargo_home"], tomllib.loads(lock_raw.decode("utf-8")))
        report["capacity_facts"] = [disk(p) for p in dict.fromkeys((source, paths["cargo_home"], paths["capacity_parent"]))]
        # A later preparation must reread; this is a finite two-point identity check, not a lease.
        for path, row in STATE["files"].items():
            budget()
            observation = observe(path)
            need(observation["state"] == "present" and observation["identity"] == row["identity"],
                 "an inventoried file changed or became indeterminate")
        for relative, expected in report["source"]["directories"].items():
            with directory(source / relative) as fd:
                need(stamp(os.fstat(fd)) == expected, "source tree changed after enumeration")
        report.update(inventory_complete=True, bytes_hashed_or_read=STATE["bytes_read"],
                      evidence_disk_after_scan=disk(output.parent))
        artifacts = {"registry-observed-map.json": report["registry"]["observed_registry_map"]}
        if (report["source"]["content_coverage_complete"] and current == compiled and actual_harness == harness):
            artifacts["full-source-map.json"] = full
        report["maps_are_preparation_receipts"] = False
        report["source_cache_private_copies_verified"] = False
        report["lock_scope"] = "All lock entries observed; no target/features/host-build dependency closure or Cargo usability claimed."
        report["index_scope"] = "Public sparse entry file identity only; internal format/locked version cksum not interpreted."
        report["finished_utc"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        artifacts["report.json"] = report
        bodies = {name: encoded(value) for name, value in artifacts.items()}
        # Leave 4 KiB for an exclusive failure record if a later evidence write fails.
        need(sum(map(len, bodies.values())) + 4096 <= MAX_EVIDENCE_BYTES, "evidence output bound exceeded")
        written = {}
        for name, body in bodies.items():
            written[name] = write_output(output, output_fd, output_identity, name, body)
        check_output(output, output_fd, output_identity)
        print(json.dumps({"inventory_complete": True, "preparation_complete": False,
                          "report": str(output / "report.json"), "report_identity": written["report.json"]}))
        return 0
    except (OSError, ValueError, KeyError, TypeError, ImportError) as exc:
        # Never echo TOML/config contents or an unrecognized registry URL.
        report["inventory_complete"] = False
        report["error_type"] = type(exc).__name__
        report["error"] = str(exc) if isinstance(exc, (ValueError, KeyError)) and type(exc).__name__ not in ("JSONDecodeError", "TOMLDecodeError") else "inventory refused or incomplete"
        report["finished_utc"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        failure_identity = None
        if output_fd is not None and output_identity is not None:
            linked = True
            try:
                check_output(output, output_fd, output_identity)
            except (OSError, ValueError):
                linked = False
            failure = {"schema": report["schema"], "inventory_complete": False, "preparation_complete": False,
                       "error_type": report["error_type"], "error": report["error"][:1500],
                       "finished_utc": report["finished_utc"], "output_path_still_names_held_directory": linked}
            body = encoded(failure)
            try:
                need(len(body) <= 4096, "failure evidence bound exceeded")
                failure_identity = write_output(output, output_fd, output_identity, "failure.json", body, linked=linked)
            except (OSError, ValueError) as failure_error:
                report["failure_evidence_error_type"] = type(failure_error).__name__
        print(json.dumps({"inventory_complete": False, "error_type": report["error_type"],
                          "reason": report["error"], "evidence_directory_created": output is not None,
                          "failure_evidence": failure_identity,
                          "failure_evidence_error_type": report.get("failure_evidence_error_type")}), file=sys.stderr)
        return 2
    finally:
        if output_fd is not None:
            os.close(output_fd)


if __name__ == "__main__":
    raise SystemExit(main())
