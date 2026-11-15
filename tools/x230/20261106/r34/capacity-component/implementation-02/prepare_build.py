#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Materialize component-only A/B workspaces from actual frozen input identities.

This file never calls Cargo, rustc, a component binary, SSH, or a remote API.
It is not run during source preparation. An unsealed template fails before writes.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import stat
import tomllib

ROOT = Path(__file__).resolve().parent
PROFILE = {"lto": True, "codegen-units": 1, "panic": "abort", "strip": True,
           "opt-level": 3, "overflow-checks": False}
CHANGED = {"src/mcp/runtime/jobs.rs", "src/mcp/runtime/ssh.rs", "src/mcp/runtime/ssh_direct.rs",
           "src/mcp/runtime/ssh_direct_tests.rs"}
DIRECT = {"anyhow": "1.0.104", "serde_json": "1.0.151", "tokio": "1.53.1", "libc": "0.2.189"}
STAGES = ["format", "fmt-check", "harness-tests", "clippy", "test-build",
          "isolated-tests", "audit-isolated-tests", "release"]
BASELINE_REPORT_SHA = "bf0c5814d28b163e4a90405026cd4d90e399370d1f910f8ac48cb580af1e4971"
BASELINE_MAP_SHA = "c3415beaf7697b3eb07a763ef24f424138de80af31acfd6c224cf682f3c67cbd"
R34_INPUT_MAP_SHA = "cfbf64a87c37ce988321432f31f12f58e98abf0b2a301ca36a21ecb459573b80"


def need(condition, reason):
    if not condition:
        raise ValueError(reason)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + "\n").encode()


def stamp(info):
    return tuple(getattr(info, key) for key in ("st_dev", "st_ino", "st_uid", "st_gid", "st_mode",
                 "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns"))


def regular(path, limit=16 * 1024 * 1024):
    path = Path(path)
    need(path.is_absolute() and path.resolve(strict=True) == path, "indirect input file")
    before = path.lstat()
    need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_size <= limit,
         "unsafe/oversized component input")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        need(stamp(os.fstat(stream.fileno())) == stamp(before), "input changed before open")
        raw = stream.read(limit + 1)
        need(len(raw) == before.st_size and stamp(os.fstat(stream.fileno())) == stamp(before) == stamp(path.lstat()),
             "input changed during read")
    return raw


def bound_file(row, limit=16 * 1024 * 1024):
    need(isinstance(row, dict) and set(row) == {"path", "bytes", "sha256"}, "actual file binding required")
    raw = regular(Path(row["path"]), limit)
    need(len(raw) == row["bytes"] and sha(raw) == row["sha256"], "actual bound file differs")
    return raw


def full_map(source, mapping):
    source = Path(source)
    need(source.is_absolute() and source.resolve(strict=True) == source, "indirect runtime source")
    need(isinstance(mapping, dict) and mapping, "actual complete source map required")
    result = {}
    for name, expected in sorted(mapping.items()):
        relative = PurePosixPath(name)
        need(not relative.is_absolute() and ".." not in relative.parts and relative.as_posix() == name,
             "invalid source map path")
        raw = regular(source / name)
        need(sha(raw) == expected, "runtime source hash differs: " + name)
        result[name] = expected
    return result


def qualified_arm(arm, row):
    baseline_raw = regular(ROOT / "reference/r24-compile-inputs.json")
    candidate_raw = regular(ROOT / "reference/r34-input-compile-inputs.json")
    need(sha(baseline_raw) == BASELINE_MAP_SHA and sha(candidate_raw) == R34_INPUT_MAP_SHA,
         "original source-map reference changed")
    baseline, candidate = json.loads(baseline_raw), json.loads(candidate_raw)
    raw = bound_file(row["qualification_report"])
    report = json.loads(raw)
    need(report.get("schema") == "hepta-x230-composed-qualification/v1"
         and report.get("qualified") is True and report.get("finished_utc") and not report.get("error"),
         "actual completed successful runtime qualification required")
    need(report.get("service_changes") is False and type(report.get("automatic_test_retries")) is int
         and report["automatic_test_retries"] == 0, "qualification mutation/retry contract differs")
    stages = report.get("stages", [])
    need([stage.get("name") for stage in stages] == STAGES
         and all(type(stage.get("returncode")) is int and stage["returncode"] == 0 for stage in stages),
         "original eight successful qualification stages required")
    need(report.get("source_tested") == report.get("source_after") == row["compile_inputs"],
         "actual formatter-tested runtime map differs from component dependency")
    if arm == "A":
        need(sha(raw) == BASELINE_REPORT_SHA and row["compile_inputs"] == baseline,
             "A is not the accepted R24 qualification/map")
    else:
        need(report.get("source_input") == candidate, "B qualification input is not the frozen R34 candidate")
        need(set(row["compile_inputs"]) == set(baseline)
             and {name for name in baseline if row["compile_inputs"][name] != baseline[name]} == CHANGED,
             "B formatter map escaped the four-file R34 candidate")
    return {"sha256": sha(raw), "bytes": len(raw), "stage_names": STAGES,
            "qualified": True, "actual_tests_count_not_invented": True}


def create(path, raw, mode=0o600):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, mode)
    with os.fdopen(fd, "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def prepare(plan_path):
    plan_raw = regular(plan_path)
    plan = json.loads(plan_raw)
    need(plan.get("schema") == "hepta-r34-capacity-component-build/v1"
         and plan.get("status") == "sealed_actual_inputs", "component build inputs remain unsealed")
    need(plan["baseline_commit"] == "baab4def80be7af015b2e7a594cb302f66c4130e"
         and plan["candidate_patch_sha256"] == "1a73c219fcfd2a273354bcbe0e1eb3f2ba629b1eb9f4969591352c6dd1a4ffc0",
         "different optimization candidate")
    need(set(plan["arms"]) == {"A", "B"} and plan["compiler_jobs"] == 1, "fixed sequential component build required")
    for name in ("cargo", "rustc"):
        need(isinstance(plan[name], str) and Path(plan[name]).is_absolute(), "actual absolute toolchain path required")
    cargo_home = Path(plan["cargo_home"])
    need(cargo_home.is_absolute() and cargo_home.resolve(strict=True) == cargo_home and cargo_home.is_dir(),
         "explicit existing original Cargo cache required; never create or copy a replacement")
    need(isinstance(plan["target_triple"], str) and plan["target_triple"].endswith("-linux-gnu"), "explicit Linux controller target required")
    source_manifest = json.loads(bound_file(plan["component_source_manifest"]))
    need(source_manifest["schema"] == "hepta-r34-capacity-component-source/v1"
         and source_manifest.get("rust_source_state") == "formatted_source_frozen",
         "component source must be a separately formatted and frozen revision before materialization")
    component_files = {}
    for row in source_manifest["files"]:
        name = row["path"]
        need(isinstance(name, str) and not PurePosixPath(name).is_absolute() and ".." not in PurePosixPath(name).parts,
             "invalid component source path")
        raw = regular(ROOT / name)
        need(len(raw) == row["bytes"] and sha(raw) == row["sha256"], "component source changed: " + name)
        component_files[name] = raw
    need("component/src/main.rs" in component_files and "component/Cargo.toml.template" in component_files,
         "component closure incomplete")
    maps, locks = {}, {}
    for arm in ("A", "B"):
        row = plan["arms"][arm]
        maps[arm] = full_map(row["source_root"], row["compile_inputs"])
        need(len(maps[arm]) == 220, "production map must retain its exact 220-input boundary")
        full_map(row["source_root"], row["include_inputs"])
        qualified_arm(arm, row)
        manifest = tomllib.loads(regular(Path(row["source_root"]) / "Cargo.toml").decode())
        need(manifest["package"]["name"] == "hepta-runtime" and manifest["package"]["version"] == "0.1.0"
             and manifest["profile"]["release"] == PROFILE, "runtime package/release profile differs")
        locks[arm] = regular(Path(row["source_root"]) / "Cargo.lock")
    need(set(maps["A"]) == set(maps["B"])
         and {name for name in maps["A"] if maps["A"][name] != maps["B"][name]} == CHANGED,
         "component dependency is not the independent four-file R24 to R34 candidate")
    need(locks["A"] == locks["B"], "runtime dependency locks differ")
    packages = {(row["name"], row["version"]): row for row in tomllib.loads(locks["A"].decode())["package"]}
    for name, version in DIRECT.items():
        need((name, version) in packages, "component direct dependency is not in the accepted lock")
    output = Path(plan["output_directory"])
    need(output.is_absolute() and output.parent.resolve(strict=True) == output.parent
         and not os.path.lexists(output), "create-only component preparation output required")
    # Everything above is read-only; no future identity or missing source triggers a write.
    output.mkdir(mode=0o700)
    receipt = {"schema": "hepta-r34-capacity-component-preparation/v1", "plan_sha256": sha(plan_raw),
               "runtime_sources_read_only": True, "shared_target": str(output / "target-component"),
               "build_order": ["A", "B"], "cargo_invoked": False,
               "cargo_home": str(cargo_home), "cargo_cache_copied_or_moved": False,
               "locks_are_seeds_not_qualified_resolutions": True, "files": {}}
    create(output / "input.json", plan_raw)
    (output / "arms").mkdir(mode=0o700)
    (output / "reference").mkdir(mode=0o700)
    create(output / "reference" / "runtime-Cargo.lock", locks["A"])
    for arm in ("A", "B"):
        package = output / "arms" / arm
        package.mkdir(mode=0o700)
        for name, raw in component_files.items():
            if not name.startswith("component/") or name.endswith("Cargo.toml.template"):
                continue
            relative = PurePosixPath(name).relative_to("component")
            path = package / str(relative)
            path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            create(path, raw)
        template = component_files["component/Cargo.toml.template"].decode()
        need(template.count("@@RUNTIME_PATH_TOML@@") == 1, "component path template differs")
        cargo_raw = template.replace("@@RUNTIME_PATH_TOML@@", json.dumps(plan["arms"][arm]["source_root"])).encode()
        need(tomllib.loads(cargo_raw.decode())["profile"]["release"] == PROFILE, "external root release profile differs")
        create(package / "Cargo.toml", cargo_raw)
        create(package / "Cargo.lock", locks["A"])
        for path in sorted(package.rglob("*")):
            if path.is_file():
                raw = regular(path)
                receipt["files"][path.relative_to(output).as_posix()] = {"bytes": len(raw), "sha256": sha(raw)}
    create(output / "preparation.json", encoded(receipt))
    return receipt


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(prepare(args.input), sort_keys=True))


if __name__ == "__main__":
    main()
