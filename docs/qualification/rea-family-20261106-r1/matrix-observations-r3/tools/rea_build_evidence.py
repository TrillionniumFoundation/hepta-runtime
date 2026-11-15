#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# Licensed under the Apache License, Version 2.0.
"""Archive and independently check a complete source-bound Rust matrix receipt.

Only the reviewed full-qualification format is accepted. Paths and commands in
its original JSON are data, never instructions to execute or arbitrary files to
open. The importer copies a fixed set of sibling artifacts without rewriting the
original receipt; the offline consumer uses only those retained bytes. These are
local provenance checks, not remote attestation of an untrusted build operator,
compiler, dependency cache or filesystem.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import math
import os
from pathlib import Path, PurePosixPath
import re
import stat


MATRIX_SCHEMA = "hepta.rea.full-qualification.v1"
BUNDLE_SCHEMA = "hepta.rea.build-evidence.v1"
PRODUCER_PATH = "scripts/rea_full_qualification.py"
TOOLCHAIN = "1.95.0"
MAX_JSON_BYTES = 16 * 1024 * 1024
MAX_ARTIFACT_BYTES = 256 * 1024 * 1024
MAX_BUNDLE_BYTES = 256 * 1024 * 1024
STAGES = ("cargo-version", "rustc-version", "nextest-version", "fmt-check",
          "clippy-all-features", "clippy-no-default-features",
          "nextest-all-features", "nextest-no-default-features", "build-native-binary")
ARTIFACT_NAMES = ("source-before.json", "source-after.json", "source-events.json") + tuple(
    f"{index:02d}-{name}.{stream}.log"
    for index, name in enumerate(STAGES, 1) for stream in ("stdout", "stderr"))
SHA256 = re.compile(r"[0-9a-f]{64}")
ANSI = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
BUILD_ENVIRONMENT_NAMES = {
    "RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "RUSTC", "RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER",
    "RUSTDOC", "RUSTDOCFLAGS", "CARGO_ENCODED_RUSTDOCFLAGS", "CARGO_INCREMENTAL", "RUSTUP_TOOLCHAIN",
    "CARGO_HOME", "CARGO_NET_OFFLINE", "CARGO_TERM_COLOR", "NEXTEST_TEST_THREADS", "NEXTEST_RETRIES",
}
BUILD_ENVIRONMENT_PREFIXES = ("CARGO_BUILD_", "CARGO_PROFILE_", "CARGO_TARGET_")
BUILD_PROFILE_NAMES = ("CARGO_PROFILE_DEV_DEBUG", "CARGO_PROFILE_TEST_DEBUG")


class BuildEvidenceError(ValueError):
    """The original build cannot be bound to the selected operation execution."""


def require(value, message):
    if not value:
        raise BuildEvidenceError(message)


def parse_json(raw):
    require(len(raw) <= MAX_JSON_BYTES, "build JSON exceeds the receive allowance")

    def members(items):
        value = {}
        for name, item in items:
            require(name not in value, "duplicate build JSON member: " + name)
            value[name] = item
        return value

    def finite_number(token):
        value = float(token)
        require(math.isfinite(value), "non-finite build JSON number")
        return value

    return json.loads(raw, object_pairs_hook=members, parse_float=finite_number,
                      parse_constant=lambda _: (_ for _ in ()).throw(
                          BuildEvidenceError("non-finite build JSON number")))


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=True,
                                     separators=(",", ":"), allow_nan=False).encode()).hexdigest()


def relative_name(value):
    require(isinstance(value, str) and value and "\\" not in value and ":" not in value
            and "\0" not in value, "unsafe build artifact path")
    path = PurePosixPath(value)
    require(not path.is_absolute() and all(part not in {"", ".", ".."} for part in value.split("/")),
            "unsafe build artifact path")
    return path


def absolute_name(value):
    require(isinstance(value, str) and value.startswith("/") and "\0" not in value
            and "\\" not in value and ":" not in value
            and all(part not in {"", ".", ".."} for part in value[1:].split("/")),
            "build path must be canonical and absolute")
    return PurePosixPath(value)


def read_regular(root, name, maximum=MAX_ARTIFACT_BYTES):
    """Keep ancestor descriptors while reading; refuse links and special files."""
    parts = relative_name(name).parts
    parent = os.open(root, os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in parts[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW,
                            dir_fd=parent)
            os.close(parent)
            parent = child
        fd = os.open(parts[-1], os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK,
                     dir_fd=parent)
        with os.fdopen(fd, "rb") as stream:
            before = os.fstat(stream.fileno())
            require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1,
                    "build artifact must be a single-link regular file")
            require(0 <= before.st_size <= maximum, "build artifact exceeds the byte allowance")
            raw = stream.read(maximum + 1)
            after = os.fstat(stream.fileno())
        current = os.stat(parts[-1], dir_fd=parent, follow_symlinks=False)
        fields = ("st_dev", "st_ino", "st_mode", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns")
        require(all(getattr(before, key) == getattr(after, key) == getattr(current, key) for key in fields)
                and len(raw) == before.st_size, "build artifact changed while reading")
        return raw
    finally:
        os.close(parent)


def reference(raw, path):
    return {"path": path, "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}


def check_reference(raw, item, path):
    require(isinstance(item, dict) and isinstance(item.get("sha256"), str)
            and SHA256.fullmatch(item["sha256"]) is not None
            and type(item.get("bytes")) is int, "invalid build artifact reference")
    require({key: item.get(key) for key in ("path", "bytes", "sha256")} == reference(raw, path),
            "build artifact size/path/digest mismatch: " + path)


def check_snapshot(value):
    require(isinstance(value, dict) and value.get("schema") == "hepta.rea.source-snapshot.v1"
            and isinstance(value.get("selection"), dict) and isinstance(value.get("files"), list),
            "invalid build source snapshot")
    rows = value["files"]
    names = []
    for row in rows:
        require(isinstance(row, dict) and set(row) == {"path", "bytes", "mode", "sha256"},
                "invalid build source row")
        relative_name(row["path"])
        require(type(row["bytes"]) is int and row["bytes"] >= 0
                and isinstance(row["sha256"], str) and SHA256.fullmatch(row["sha256"]) is not None
                and isinstance(row["mode"], str) and re.fullmatch(r"0o[0-7]{1,4}", row["mode"]),
                "invalid build source facts")
        names.append(row["path"])
    require(names == sorted(set(names)) and {"Cargo.toml", "Cargo.lock", "src/main.rs", PRODUCER_PATH} <= set(names),
            "build source inventory is incomplete or duplicated")
    require(type(value.get("file_count")) is int and value["file_count"] == len(rows)
            and type(value.get("total_bytes")) is int and value["total_bytes"] == sum(row["bytes"] for row in rows)
            and value.get("tree_sha256") == digest(rows), "build source inventory digest/count mismatch")


def planned_commands(report):
    """Reconstruct the reviewed plan; the receipt cannot choose easier gates."""
    require(report.get("schema") == MATRIX_SCHEMA, "unsupported original build receipt schema")
    inputs = report["inputs"]
    for name in ("repo", "cargo_home", "target_dir", "output_dir"):
        absolute_name(inputs[name])
    relative_name(inputs["binary_relative_path"])
    require(inputs["binary_relative_path"] == "debug/hepta-runtime",
            "build receipt must observe the reviewed debug/hepta-runtime executable")
    require(type(inputs.get("jobs")) is int and 1 <= inputs["jobs"] <= 256
            and inputs.get("toolchain") == TOOLCHAIN and inputs.get("child_launch_umask") == "0022",
            "build toolchain/jobs/umask differs from the reviewed profile")
    for name in ("cargo", "rustc"):
        for key in ("invoked", "resolved"):
            absolute_name(report["executables"][name][key])
    cargo, rustc = (report["executables"][name]["invoked"] for name in ("cargo", "rustc"))
    common = ["--locked", "--offline", "--all-targets"]
    build = ["--jobs", str(inputs["jobs"]), "--target-dir", inputs["target_dir"]]
    nextest = ["--build-jobs", str(inputs["jobs"]), "--target-dir", inputs["target_dir"]]
    controls = ["--test-threads", "1", "--retries", "0", "--no-fail-fast",
                "--profile", "default", "--ignore-default-filter", "--no-tests", "fail"]
    return [
        [cargo, "--version", "--verbose"], [rustc, "--version", "--verbose"],
        [cargo, "nextest", "--version"], [cargo, "fmt", "--all", "--", "--check"],
        *[[cargo, "clippy"] + common + ["--" + features] + build + ["--", "-D", "warnings"]
          for features in ("all-features", "no-default-features")],
        *[[cargo, "nextest", "run"] + common + ["--" + features] + nextest + controls
          for features in ("all-features", "no-default-features")],
        [cargo, "build", "--locked", "--offline", "--all-features", "--bin", "hepta-runtime",
         "--message-format=json-render-diagnostics"] + build,
    ]


def original_artifacts(report):
    commands = planned_commands(report)
    stages = report.get("stages")
    require(isinstance(stages, list) and [row.get("name") for row in stages] == list(STAGES),
            "original build stages are missing, duplicated or reordered")
    output = absolute_name(report["inputs"]["output_dir"])
    values = {name: report[key] for name, key in zip(ARTIFACT_NAMES[:3],
               ("source_before", "source_after", "source_events"), strict=True)}
    for index, (name, row, command) in enumerate(zip(STAGES, stages, commands, strict=True), 1):
        require(row.get("command") == command, "original build command differs: " + name)
        require(set(row["logs"]) == {"stdout", "stderr"}, "original build log pair is incomplete")
        for stream in ("stdout", "stderr"):
            values[f"{index:02d}-{name}.{stream}.log"] = row["logs"][stream]
    for name, item in values.items():
        require(isinstance(item, dict) and item.get("path") == str(output / name),
                "original build reference is not its fixed sibling: " + name)
        require(type(item.get("bytes")) is int and 0 <= item["bytes"] <= (
            MAX_JSON_BYTES if name.endswith(".json") else MAX_ARTIFACT_BYTES),
            "original build artifact size is outside the allowance")
    require(sum(item["bytes"] for item in values.values()) <= MAX_BUNDLE_BYTES,
            "original build artifacts exceed the aggregate allowance")
    return values


def timestamp(value):
    require(isinstance(value, str), "build timestamp is missing")
    result = dt.datetime.fromisoformat(value)
    require(result.tzinfo is not None, "build timestamp has no timezone")
    return result


def check_build_environment(value, expected, inherited):
    require(isinstance(value, dict) and set(value) == {"schema", "selection", "sha256", "profiles"}
            and value["schema"] == "hepta.rea.build-environment.v1"
            and value["selection"] == {"exact_names": sorted(BUILD_ENVIRONMENT_NAMES),
                                        "prefixes": list(BUILD_ENVIRONMENT_PREFIXES)},
            "effective build environment observation is missing or unsupported")
    observed = value["sha256"]
    require(isinstance(observed, dict) and all(
        (name in BUILD_ENVIRONMENT_NAMES or name.startswith(BUILD_ENVIRONMENT_PREFIXES))
        and isinstance(digest_value, str) and SHA256.fullmatch(digest_value)
        for name, digest_value in observed.items()), "invalid effective build override fingerprints")
    for name, setting in expected.items():
        require(observed.get(name) == hashlib.sha256(setting.encode()).hexdigest(),
                "effective build environment differs from the actual stage profile: " + name)
    require(all(observed.get(name) == fingerprint for name, fingerprint in inherited.items()),
            "inherited build override differs from its effective fingerprint")
    profiles = value["profiles"]
    require(isinstance(profiles, dict) and set(profiles) == set(BUILD_PROFILE_NAMES),
            "explicit Cargo debug profile observations are missing")
    for name, setting in profiles.items():
        if setting is None:
            require(name not in observed, "unset Cargo profile has an effective override")
        else:
            require(isinstance(setting, str) and len(setting) <= 1024
                    and observed.get(name) == hashlib.sha256(setting.encode()).hexdigest(),
                    "Cargo debug profile value differs from its fingerprint")


def compiler_artifact(raw, report, binary):
    """A successful nextest run or an existing path is not a binary build receipt."""
    require(raw.endswith(b"\n"), "Cargo compiler artifact stream is incomplete")
    messages = [parse_json(line) for line in raw.splitlines()]
    require(messages and all(isinstance(item, dict) for item in messages), "invalid Cargo compiler artifact stream")
    finished = [item for item in messages if item.get("reason") == "build-finished"]
    require(finished == [{"reason": "build-finished", "success": True}]
            and finished[0].get("success") is True
            and messages[-1] == finished[0], "Cargo did not finish the explicit native binary build")
    selected = [item for item in messages if item.get("reason") == "compiler-artifact"
                and item.get("target", {}).get("name") == "hepta-runtime"]
    require(len(selected) == 1, "Cargo must identify exactly one hepta-runtime binary artifact")
    artifact = selected[0]
    target = artifact.get("target", {})
    repo = absolute_name(report["inputs"]["repo"])
    require(target.get("kind") == ["bin"] and target.get("crate_types") == ["bin"]
            and target.get("src_path") == str(repo / "src/main.rs")
            and artifact.get("manifest_path") == str(repo / "Cargo.toml")
            and artifact.get("executable") == binary["path"]
            and isinstance(artifact.get("filenames"), list) and binary["path"] in artifact["filenames"]
            and isinstance(artifact.get("profile"), dict) and artifact["profile"].get("test") is False
            and type(artifact.get("fresh")) is bool,
            "Cargo artifact does not identify the selected source and native executable")
    features = artifact.get("features")
    require(isinstance(features, list) and all(isinstance(item, str) for item in features)
            and len(features) == len(set(features)) and {"default", "remote-fs"} <= set(features),
            "Cargo artifact lacks the shipping MCP feature set")
    debug = report["build_environment"]["profiles"]["CARGO_PROFILE_DEV_DEBUG"]
    if debug == "0":
        require(type(artifact["profile"].get("debuginfo")) is int and artifact["profile"]["debuginfo"] == 0,
                "Cargo artifact differs from the observed zero-debug dev profile")
    return artifact


def _validate_matrix(raw_summary, read, source, native):
    """`read` receives fixed basenames only, never receipt-provided paths."""
    report = parse_json(raw_summary)
    require(isinstance(report, dict), "original build receipt is not an object")
    refs = original_artifacts(report)
    artifacts = {}
    for name, item in refs.items():
        raw = read(name)
        check_reference(raw, item, item["path"])
        if name.endswith(".log"):
            require(type(item.get("final_bytes")) is int and item["final_bytes"] == item["bytes"]
                    and item.get("sha256_at_stage_exit") == item["sha256"],
                    "original build log changed after stage exit: " + name)
        artifacts[name] = raw
    before, after = (parse_json(artifacts[name]) for name in ARTIFACT_NAMES[:2])
    check_snapshot(before)
    check_snapshot(after)
    check_snapshot(source)
    require(before == after == source, "build source differs from the operation source/fixture/profile tree")
    require(all(report[key].get("tree_sha256") == before["tree_sha256"] for key in ("source_before", "source_after")),
            "build source tree reference mismatch")
    events = parse_json(artifacts["source-events.json"])
    require(isinstance(events, dict) and type(events.get("event_count")) is int
            and events.get("events_truncated") is False and events == {
        "event_count": 0, "retained_events": [], "events_truncated": False, "errors": []},
        "build source changed or monitor coverage was lost")
    require(report.get("invalid_reasons") == [] and report.get("interrupted_by_signal") is None
            and report.get("source_monitor_complete") is True and report.get("source_changed") is False
            and report.get("source_inventory_changed") is False,
            "original build was incomplete, interrupted or invalid")
    selected = next(item for item in before["files"] if item["path"] == PRODUCER_PATH)
    binding = report.get("producer_source")
    require(isinstance(binding, dict) and set(binding) == {"before", "after", "repository_path"}
            and binding["repository_path"] == PRODUCER_PATH and binding["before"] == binding["after"],
            "original build producer binding is missing or changed")
    producer = binding["before"]
    require(isinstance(producer, dict) and set(producer) == {"path", "bytes", "mode", "sha256"},
            "invalid original build producer identity")
    require(producer["path"] == str(absolute_name(report["inputs"]["repo"]) / PRODUCER_PATH)
            and {**producer, "path": PRODUCER_PATH} == selected,
            "original build producer differs from its source snapshot")
    inputs, executables = report["inputs"], report["executables"]
    expected_environment = {
        "CARGO_HOME": inputs["cargo_home"], "CARGO_TARGET_DIR": inputs["target_dir"],
        "CARGO_BUILD_JOBS": str(inputs["jobs"]), "CARGO_NET_OFFLINE": "true", "CARGO_TERM_COLOR": "never",
        "RUSTUP_TOOLCHAIN": TOOLCHAIN, "RUSTC": executables["rustc"]["invoked"],
        "NEXTEST_TEST_THREADS": "1", "NEXTEST_RETRIES": "0",
    }
    require(report.get("environment_overrides") == expected_environment, "build environment profile differs")
    overrides = report.get("ambient_build_override_sha256")
    require(isinstance(overrides, dict) and set(overrides) <= {
        "RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER", "CARGO_BUILD_TARGET"}
        and all(isinstance(value, str) and SHA256.fullmatch(value) for value in overrides.values()),
        "build override fingerprints are missing or invalid")
    check_build_environment(report.get("build_environment"), expected_environment, overrides)
    plan = [{"name": name, "command": command, "child_launch_umask": "0022"}
            for name, command in zip(STAGES[3:8], planned_commands(report)[3:8], strict=True)]
    require(report.get("planned_gates") == plan, "original build plan differs from the reviewed gates")
    end = timestamp(report.get("finished_at"))
    previous = timestamp(report.get("started_at"))
    for index, stage in enumerate(report["stages"], 1):
        name = STAGES[index - 1]
        require(type(stage.get("exit_code")) is int and stage["exit_code"] == 0
                and stage.get("interrupted") is False and stage.get("child_launch_umask") == "0022"
                and stage.get("cwd") == inputs["repo"]
                and stage.get("kind") == ("version" if index <= 3 else "build" if index == 9 else "gate"),
                "original build stage did not complete successfully: " + name)
        start, finish = timestamp(stage.get("started_at")), timestamp(stage.get("finished_at"))
        require(previous <= start <= finish <= end, "original build stage timing/order differs")
        previous = finish
        duration = stage.get("duration_seconds")
        require(type(duration) in (int, float) and math.isfinite(duration) and duration >= 0,
                "invalid original build duration")
        stdout = artifacts[f"{index:02d}-{name}.stdout.log"].decode("utf-8", errors="strict")
        if index <= 2:
            require([line.strip() for line in stdout.splitlines() if line.startswith("release:")]
                    == ["release: " + TOOLCHAIN], "original toolchain version does not match")
        if index == 3:
            require(re.match(r"cargo-nextest \S+", stdout) is not None, "nextest version output is missing")
        if index in (7, 8):
            stderr = artifacts[f"{index:02d}-{name}.stderr.log"].decode("utf-8", errors="strict")
            lines = [ANSI.sub("", line).strip() for line in (stdout + "\n" + stderr).splitlines()]
            summaries = [line for line in lines if line.startswith("Summary [")]
            require(len(summaries) == 1, "original nextest terminal summary is missing or ambiguous")
            counts = re.fullmatch(r"Summary \[[^\]]+\] (\d+) tests run: (\d+) passed"
                                  r"(?: \((\d+) slow\))?(?:, \d+ skipped)?",
                                  summaries[0])
            require(counts is not None and int(counts[1]) > 0 and counts[1] == counts[2]
                    and (counts[3] is None or int(counts[3]) <= int(counts[2])),
                    "original nextest log does not show a successful nonempty run")
    final = report.get("final_binary")
    wanted_path = str(absolute_name(inputs["target_dir"]) / inputs["binary_relative_path"])
    require(isinstance(final, dict) and set(final) == {"path", "exists", "bytes", "mode", "sha256"}
            and final["path"] == wanted_path and final["exists"] is True
            and type(final["bytes"]) is int and final["bytes"] > 0
            and isinstance(final["sha256"], str) and SHA256.fullmatch(final["sha256"])
            and isinstance(final["mode"], str) and re.fullmatch(r"0o[0-7]{1,4}", final["mode"])
            and int(final["mode"], 8) & 0o111, "original build has no identified executable")
    observations = report.get("binaries_after_nextest")
    require(isinstance(observations, list) and len(observations) == 2,
            "both feature-specific executable observations are required")
    for features, observation in zip(("all-features", "no-default-features"), observations, strict=True):
        require(isinstance(observation, dict) and set(observation) == set(final) | {"feature_set", "stage", "stage_exit_code"}
                and observation.get("feature_set") == features and observation.get("stage") == "nextest-" + features
                and type(observation.get("stage_exit_code")) is int and observation["stage_exit_code"] == 0
                and observation.get("path") == wanted_path and observation.get("exists") is True
                and type(observation.get("bytes")) is int and observation["bytes"] > 0
                and isinstance(observation.get("sha256"), str) and SHA256.fullmatch(observation["sha256"])
                and isinstance(observation.get("mode"), str) and re.fullmatch(r"0o[0-7]{1,4}", observation["mode"])
                and int(observation["mode"], 8) & 0o111,
                "feature-specific executable observation is invalid")
    built = report.get("binary_after_build")
    require(isinstance(built, dict) and set(built) == set(final) | {"feature_set", "stage", "stage_exit_code"}
            and built.get("feature_set") == "all-features" and built.get("stage") == "build-native-binary"
            and type(built.get("stage_exit_code")) is int and built["stage_exit_code"] == 0
            and {key: built[key] for key in final} == final,
            "final executable differs from the explicit native binary build")
    compiled = compiler_artifact(artifacts["09-build-native-binary.stdout.log"], report, final)
    require(isinstance(native, dict) and type(native.get("bytes")) is int
            and native.get("sha256") == final["sha256"] and native["bytes"] == final["bytes"],
            "executed native binary differs from the original build output")
    absolute_name(native["path"])
    return {"profile": "hepta.rea.build-source-binding.v1", "source_tree_sha256": before["tree_sha256"],
            "build_summary_sha256": hashlib.sha256(raw_summary).hexdigest(),
            "native_binary_sha256": final["sha256"], "native_binary_bytes": final["bytes"],
            "built_binary_path": final["path"], "executed_binary_path": native["path"],
            "selected_feature_set": "all-features", "verified_stage_names": list(STAGES),
            "compiler_artifact": compiled,
            "build_environment": report["build_environment"],
            "scope": "local original receipt/source/binary binding; trusted producer, toolchain and dependency cache; no operation parity"}


def validate_matrix(raw_summary, read, source, native):
    try:
        return _validate_matrix(raw_summary, read, source, native)
    except (KeyError, TypeError, IndexError, AttributeError, UnicodeError) as error:
        raise BuildEvidenceError("malformed original build receipt: " + type(error).__name__) from error


def validate_bundle(root, bundle, source, native):
    require(isinstance(bundle, dict) and set(bundle) == {"schema", "summary", "artifacts"}
            and bundle["schema"] == BUNDLE_SCHEMA, "invalid retained build evidence bundle")
    require(isinstance(bundle["artifacts"], list), "retained build artifact inventory is not a list")
    refs = [bundle["summary"]] + bundle["artifacts"]
    names = ("summary.json",) + ARTIFACT_NAMES
    require(len(refs) == len(names), "retained build artifacts are incomplete")
    require(all(isinstance(item, dict) and type(item.get("bytes")) is int
                and 0 <= item["bytes"] <= MAX_ARTIFACT_BYTES for item in refs)
            and sum(item["bytes"] for item in refs) <= MAX_BUNDLE_BYTES,
            "retained build artifacts exceed the aggregate allowance")
    retained = {}
    for name, item in zip(names, refs, strict=True):
        path = "build-evidence/" + name
        require(isinstance(item, dict) and set(item) == {"path", "bytes", "sha256"} and item["path"] == path,
                "retained build artifact set/order differs")
        raw = read_regular(root, path, MAX_JSON_BYTES if name.endswith(".json") else MAX_ARTIFACT_BYTES)
        check_reference(raw, item, path)
        retained[name] = raw
    return validate_matrix(retained["summary.json"], retained.__getitem__, source, native)


def capture_build(summary_path, expected_sha256, output, source, native):
    """Preserve original bytes; never retrofit an unsupported/incomplete receipt."""
    summary_path, output = Path(summary_path), Path(output)
    require(summary_path.is_absolute() and isinstance(expected_sha256, str)
            and SHA256.fullmatch(expected_sha256), "original build summary path/digest must be pinned")
    raw = read_regular(summary_path.parent, summary_path.name, MAX_JSON_BYTES)
    require(hashlib.sha256(raw).hexdigest() == expected_sha256, "original build summary digest mismatch")
    validate_matrix(raw, lambda name: read_regular(summary_path.parent, name), source, native)
    destination = output / "build-evidence"
    destination.mkdir(mode=0o700, exist_ok=False)
    references = []
    for name in ("summary.json",) + ARTIFACT_NAMES:
        content = raw if name == "summary.json" else read_regular(summary_path.parent, name)
        with (destination / name).open("xb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        references.append(reference(content, "build-evidence/" + name))
    bundle = {"schema": BUNDLE_SCHEMA, "summary": references[0], "artifacts": references[1:]}
    # Recheck the copied originals to detect source changes during the archive.
    assessment = validate_bundle(output, bundle, source, native)
    return bundle, assessment
