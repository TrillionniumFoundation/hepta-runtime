#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Build and qualify the explicit native-local read profile against pinned originals.

Python is used only for source materialization, building and independent tests.
The shipped seven-image ELF requires neither Python nor libc.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
COMPOSITIONS = ("local_service", "multi_read_service", "file_info_service")
SUITES = ("test_local_service", "test_multi_service", "test_info_service")
MEMBERS = ("local_service", "policy", "binary_codec", "io_policy", "stat_version",
           "multi_read_service", "file_info_service")
SUPPORT = ("hia_native_local_read_qualification.py", "hia_native_composition_build.py",
           "hia_native_build.py", "hia_native_loader.py")


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def blob(raw: bytes) -> str:
    return hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()


def git(repository: Path, *args: str) -> bytes:
    return subprocess.check_output(["git", "-C", str(repository), *args],
                                   stderr=subprocess.PIPE)


def file_identity(path: Path) -> dict:
    mode = path.lstat().st_mode
    if not stat.S_ISREG(mode):
        raise ValueError(f"source is not a regular file: {path}")
    raw = path.read_bytes()
    return {"bytes": len(raw), "sha256": digest(raw), "blob": blob(raw),
            "mode": stat.S_IMODE(mode)}


def materialize_reference(repository: Path, destination: Path, commit: str,
                          expected: dict[str, dict]) -> dict:
    """Admit only the declared commit and exact original blobs, never HEAD."""
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ValueError("original commit must be an immutable 40-digit Git object")
    if git(repository, "cat-file", "-t", commit).strip() != b"commit":
        raise ValueError("original object is not a commit")
    destination.mkdir(parents=True, exist_ok=True)
    if destination.is_symlink():
        raise ValueError("original reference destination is a symlink")
    destination = destination.resolve(strict=True)
    result = {}
    for name, identity in sorted(expected.items()):
        relative = PurePosixPath(name)
        if (relative.is_absolute() or ".." in relative.parts or
                str(relative) != name or not name.startswith("src/")):
            raise ValueError(f"invalid original source path: {name}")
        actual_blob = git(repository, "rev-parse", f"{commit}:{name}").decode().strip()
        if actual_blob != identity["blob"]:
            raise ValueError(f"original commit/blob mismatch: {name}")
        raw = git(repository, "cat-file", "blob", actual_blob)
        if blob(raw) != identity["blob"] or digest(raw) != identity["sha256"]:
            raise ValueError(f"original source digest mismatch: {name}")
        target = destination.joinpath(*relative.parts)
        target.parent.mkdir(parents=True, exist_ok=True)
        if not target.parent.resolve(strict=True).is_relative_to(destination):
            raise ValueError(f"original reference escaped destination: {name}")
        if target.is_symlink():
            raise ValueError(f"original reference is a symlink: {name}")
        if target.exists():
            if not target.is_file() or target.read_bytes() != raw:
                raise ValueError(f"existing original reference changed: {name}")
        else:
            with target.open("xb") as stream:
                stream.write(raw)
        result[name] = file_identity(target)
    return result


def reference_spec(source: Path) -> tuple[str, dict]:
    commits = set()
    originals = {}
    for name in COMPOSITIONS:
        proof = json.loads((source / "native" / f"{name}_composition.json").read_bytes())
        actual = source / "native" / f"{name}.hepta"
        source_key = "source_sha256" if name == "local_service" else "native_source_sha256"
        if digest(actual.read_bytes()) != proof[source_key]:
            raise ValueError(f"current HIA composition/source mismatch: {actual}")
        if digest((source / proof["protocol_source"]).read_bytes()) != proof["protocol_source_sha256"]:
            raise ValueError(f"current protocol/source mismatch: {actual}")
        commits.add(proof["original_runtime_commit"])
        for path, identity in proof["original_sources"].items():
            if path in originals and originals[path] != identity:
                raise ValueError(f"original source declarations disagree: {path}")
            originals[path] = identity
    if len(commits) != 1:
        raise ValueError("read components declare different original commits")
    return next(iter(commits)), originals


def freeze(source: Path) -> dict:
    paths = [f"native/{name}.hepta" for name in MEMBERS]
    paths += [f"native/{name}_composition.json" for name in COMPOSITIONS]
    paths += ["native/runtime_protocol.hepta", "native/composition_packer.hepta"]
    paths += [f"scripts/{name}" for name in SUPPORT]
    paths += [f"tests/hia_native/{name}.py" for name in SUITES]
    return {name: file_identity(source / name) for name in sorted(paths)}


def check_unchanged(root: Path, identities: dict) -> None:
    for name, identity in identities.items():
        if file_identity(root / name) != identity:
            raise ValueError(f"source changed during qualification: {name}")


def qualify(source: Path, hepta: Path, build: Path, report: dict) -> None:
    source = source.resolve(strict=True)
    hepta = hepta.resolve(strict=True)
    build.mkdir(parents=True, exist_ok=True)
    build = build.resolve(strict=True)
    report["current_runtime_commit"] = git(source, "rev-parse", "HEAD").decode().strip()
    report["current_sources"] = freeze(source)
    commit, originals = reference_spec(source)
    reference = build / "original-reference" / commit
    report["original_runtime_commit"] = commit
    report["original_sources"] = materialize_reference(source, reference, commit, originals)
    report["original_reference"] = str(reference)
    # Import the builder from the same explicit current source root as the HIA.
    sys.path.insert(0, str(source / "scripts"))
    from hia_native_composition_build import build_local_read
    if Path(sys.modules["hia_native_composition_build"].__file__).resolve() != (
            source / "scripts/hia_native_composition_build.py").resolve():
        raise ValueError("composition builder loaded from a different source root")
    manifest = build_local_read(hepta, build / "native", source_root=source)
    metadata = json.loads(manifest.read_bytes())
    report["manifest"] = str(manifest)
    report["manifest_sha256"] = digest(manifest.read_bytes())
    report["executable_sha256"] = metadata["executable_sha256"]
    report["suites"] = []
    for name in SUITES:
        result_path = build / f"{name}.result.json"
        # A prior result can never satisfy this invocation.
        result_path.unlink(missing_ok=True)
        env = {key: value for key, value in os.environ.items() if not key.startswith("HIA_")}
        env.update(HIA_RUNTIME_REPO=str(source), HIA_RUNTIME_REFERENCE=str(reference),
                   HIA_HEPTA_DIR=str(hepta), HIA_SERVICE_MANIFEST=str(manifest),
                   HIA_SERVICE_RESULT=str(result_path), HIA_MULTI_SERVICE_RESULT=str(result_path),
                   HIA_INFO_SERVICE_RESULT=str(result_path), HIA_INFO_FIXTURE_ROOT=str(build))
        command = [sys.executable, str(source / "tests/hia_native" / f"{name}.py")]
        started = time.monotonic()
        with (build / f"{name}.stdout").open("wb") as out, (
                build / f"{name}.stderr").open("wb") as err:
            done = subprocess.run(command, cwd=source, env=env, stdout=out, stderr=err,
                                  timeout=300, check=False)
        row = {"name": name, "returncode": done.returncode,
               "seconds": round(time.monotonic() - started, 3)}
        if result_path.exists():
            row["result"] = json.loads(result_path.read_bytes())
            row["result_sha256"] = digest(result_path.read_bytes())
        report["suites"].append(row)
        print(json.dumps({"suite": name, "returncode": done.returncode}), flush=True)
        if done.returncode != 0 or row.get("result", {}).get("status") != "pass":
            raise RuntimeError(f"native read qualification failed: {name}; see {build / (name + '.stderr')}")
        if row["result"]["executable_sha256"] != report["executable_sha256"]:
            raise ValueError(f"suite used a different executable: {name}")
        if row["result"]["manifest_sha256"] != report["manifest_sha256"]:
            raise ValueError(f"suite used a different manifest: {name}")
    check_unchanged(source, report["current_sources"])
    check_unchanged(reference, report["original_sources"])
    counts = [row["result"]["counts"] for row in report["suites"]]
    report["actual_elf_responses"] = (counts[0]["elf_requests"] +
                                    counts[1]["all_actual_elf_responses"] +
                                    counts[2]["all_actual_elf_responses"])
    report["original_result_comparisons"] = {
        "binary_read": counts[0]["original_read_comparisons"],
        "read_multiple_files": counts[1]["original_batch_comparisons"],
        "file_info": counts[2]["original_info_comparisons"],
    }
    if any(count == 0 for count in report["original_result_comparisons"].values()):
        raise ValueError("an original-result comparison suite executed no cases")
    report["status"] = "pass"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--hepta", type=Path, required=True)
    parser.add_argument("--build-root", type=Path, required=True)
    parser.add_argument("--source-root", type=Path, default=ROOT)
    args = parser.parse_args()
    args.build_root.mkdir(parents=True, exist_ok=True)
    report = {"schema": "hepta.runtime.native-local-read-qualification.v1",
              "status": "fail", "profile": "explicit-native-local-read",
              "configured_remote_hosts_replaced": False, "default_public_graph_changed": False,
              "whole_runtime_replaced": False, "old_path_removed": False}
    try:
        qualify(args.source_root, args.hepta, args.build_root, report)
    except Exception as exc:
        report["error"] = f"{type(exc).__name__}: {exc}"
        print(report["error"], file=sys.stderr)
    target = args.build_root / "qualification.json"
    target.write_text(json.dumps(report, sort_keys=True, indent=2) + "\n")
    print(json.dumps({"status": report["status"], "report": str(target)}))
    return 0 if report["status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
