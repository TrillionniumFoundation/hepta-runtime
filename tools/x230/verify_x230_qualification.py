#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Read-only verification of an actual x230 qualification; create one new public receipt.

Rehashes raw logs, the entire source file set, copied executables and the exact
compiler-reported executables. Does not build, run tests, repair or infer passes.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat


STAGES = ("format", "fmt-check", "clippy", "test", "release")
HEX256 = re.compile(r"[0-9a-f]{64}\Z")


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def sha(value):
    return hashlib.sha256(value).hexdigest()


def private_error(error):
    value = str(error)
    return {"type": type(error).__name__, "errno": getattr(error, "errno", None),
            "message": re.sub(r"/[^\s\"'<>;,}\])]+", lambda found: "<path:" + sha(found[0].encode())[:12] + ">", value),
            "original_message_sha256": sha(value.encode())}


def file_hash(path):
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode):
        raise ValueError("verification input is not a regular non-symlink file")
    digest, size = hashlib.sha256(), 0
    with path.open("rb") as source:
        opened = os.fstat(source.fileno())
        while True:
            block = source.read(1024 * 1024)
            if not block:
                break
            digest.update(block)
            size += len(block)
        finished = os.fstat(source.fileno())
    after = path.lstat()
    def identity(info):
        return (info.st_dev, info.st_ino, info.st_mode, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
    if not (identity(before) == identity(opened) == identity(finished) == identity(after)) or size != before.st_size:
        raise ValueError("verification input changed during the complete read")
    return {"sha256": digest.hexdigest(), "bytes": size}


def sources(root):
    result = {}
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            raise ValueError("source manifest contains a symlink")
        if path.is_file():
            result[str(path.relative_to(root))] = file_hash(path)["sha256"]
    return result


def valid_manifest(value):
    return (isinstance(value, dict) and bool(value)
            and all(isinstance(name, str) and name and not Path(name).is_absolute()
                    and ".." not in Path(name).parts and isinstance(digest, str)
                    and HEX256.fullmatch(digest) is not None for name, digest in value.items()))


def read_stage(report_dir, stage):
    name = stage.get("name")
    row = {key: stage.get(key) for key in ("name", "returncode", "seconds", "log_sha256")}
    row["log_hash_verified"] = False
    if name not in STAGES:
        row["error"] = {"type": "UnsupportedStage", "message": "stage name is outside the fixed qualification sequence"}
        return row, None
    log = report_dir / (name + ".log")
    try:
        measured = file_hash(log)
        row.update(log_bytes=measured["bytes"], actual_log_sha256=measured["sha256"],
                   log_hash_verified=measured["sha256"] == stage.get("log_sha256"))
        raw = log.read_bytes()
        if sha(raw) != measured["sha256"]:
            raise ValueError("stage log changed between hashing and independent parsing")
        text = raw.decode("utf-8")
        lines = [line for line in text.splitlines() if line.startswith("test result:")]
        row["test_result_lines"] = lines
        if name == "test":
            row["recorded_test_result_lines_match_raw_log"] = stage.get("results") == lines
        return row, text
    except (OSError, ValueError, UnicodeError) as error:
        row["error"] = private_error(error)
        row["log_hash_verified"] = False
        return row, None


def artifact(log, is_test, reported, source):
    result = {"is_test": is_test, "checks": {}}
    checks = result["checks"]
    found = []
    for line in (log or "").splitlines():
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            continue
        if (isinstance(value, dict) and value.get("reason") == "compiler-artifact"
                and value.get("target", {}).get("name") == "hepta-runtime"
                and value.get("profile", {}).get("test") is is_test):
            found.append(value)
    result["matching_compiler_artifact_count"] = len(found)
    checks["exactly_one_matching_compiler_artifact"] = len(found) == 1
    checks["reported_artifact_present"] = isinstance(reported, dict)
    if not checks["exactly_one_matching_compiler_artifact"] or not checks["reported_artifact_present"]:
        result["verified"] = False
        return result
    record = found[0]
    try:
        expected_source = source / "src/main.rs"
        checks["manifest_matches_candidate"] = Path(record["manifest_path"]) == source / "Cargo.toml"
        checks["compiler_source_matches_main"] = Path(record["target"]["src_path"]) == expected_source
        checks["reported_compiler_source_matches_main"] = Path(reported["compiler_source"]) == expected_source
        copied = file_hash(Path(reported["path"]))
        original = file_hash(Path(record["executable"]))
        result.update(reported_sha256=reported.get("sha256"), copied= copied,
                      current_compiler_executable=original, compiler_artifact_fresh=record.get("fresh"),
                      reported_cached=reported.get("cached"))
        checks["copied_binary_matches_report"] = copied["sha256"] == reported.get("sha256")
        checks["current_compiler_executable_matches_copy"] = original["sha256"] == copied["sha256"]
        checks["cached_metadata_matches_compiler"] = reported.get("cached") is record.get("fresh")
    except (OSError, KeyError, TypeError, ValueError) as error:
        result["error"] = private_error(error)
        checks["all_artifact_inputs_readable"] = False
    result["verified"] = bool(checks) and all(checks.values())
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--qualification", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--candidate", required=True)
    args = parser.parse_args()
    if os.path.lexists(args.output):
        parser.error("create-only output already exists")
    raw = args.qualification.read_bytes()
    report = json.loads(raw)
    if not isinstance(report, dict):
        parser.error("qualification input must be an object")
    success_reported = report.get("qualified") is True
    checks = {"schema_matches": report.get("schema") == "runtime-candidate-qualification/v1",
              "raw_report_qualified": success_reported}
    rows, logs = [], {}
    stages = report.get("stages", [])
    if not isinstance(stages, list):
        stages = []
    for stage in stages:
        if not isinstance(stage, dict):
            rows.append({"name": None, "log_hash_verified": False, "error": {"type": "InvalidStageRecord"}})
            continue
        row, text = read_stage(args.qualification.parent, stage)
        rows.append(row)
        if text is not None:
            logs[stage["name"]] = text
    result = {"schema": "hepta-x230-qualification-independent-receipt/v1", "candidate": args.candidate,
              "raw_report_qualified": report.get("qualified"), "qualified": False,
              "source_report_sha256": sha(raw), "source_report_bytes": len(raw),
              "verifier_sha256": sha(Path(__file__).read_bytes()), "stages": rows,
              "current_stage": report.get("current_stage"), "service_changes": report.get("service_changes"),
              "verification": checks, "success_checks_evaluated": success_reported,
              "test_result_lines_are_not_summed": True,
              "test_count_interpretation": "Every raw test result line is retained; nested one-test helper results are not added to parent suite totals.",
              "private_paths_published": False}
    if "error" in report:
        result["reported_error"] = private_error(RuntimeError(str(report["error"])))
    if not success_reported:
        # Preserve an interrupted current-stage log even if the helper failed
        # before it could append a completed stage result or its return code.
        current = report.get("current_stage")
        if current in STAGES and current not in [row.get("name") for row in rows]:
            partial, _ = read_stage(args.qualification.parent, {"name": current})
            partial["completed_stage_record_present"] = False
            result["unfinished_current_stage"] = partial
        result["success_check_skip_reason"] = "Raw qualification did not report qualified=true; no source or artifact success is asserted."
    else:
        names = [row.get("name") for row in rows]
        checks["exact_five_successful_stages"] = names == list(STAGES) and all(
            type(row.get("returncode")) is int and row["returncode"] == 0 for row in rows)
        checks["all_stage_raw_log_hashes_match"] = len(rows) == 5 and all(row.get("log_hash_verified") is True for row in rows)
        checks["test_result_lines_match_report"] = all(row.get("recorded_test_result_lines_match_raw_log") is True
            for row in rows if row.get("name") == "test") and names.count("test") == 1
        before, after = report.get("source_tested"), report.get("source_after")
        checks["source_tested_and_after_valid_equal"] = valid_manifest(before) and valid_manifest(after) and before == after
        source = Path(report.get("source", ""))
        checks["source_is_absolute_directory"] = source.is_absolute() and source.is_dir() and not source.is_symlink()
        try:
            if not checks["source_is_absolute_directory"]:
                raise ValueError("candidate source root is not an absolute existing directory")
            if args.output.resolve().is_relative_to(source.resolve()):
                parser.error("output must be outside the source tree being verified")
            actual = sources(source)
            checks["actual_source_file_set_and_all_hashes_match"] = bool(actual) and checks["source_tested_and_after_valid_equal"] and actual == before
            result["source"] = {"tested_file_count": len(before) if isinstance(before, dict) else None,
                                "after_file_count": len(after) if isinstance(after, dict) else None,
                                "actual_file_count": len(actual),
                                "tested_map_sha256": sha(canonical(before)) if valid_manifest(before) else None,
                                "after_map_sha256": sha(canonical(after)) if valid_manifest(after) else None,
                                "actual_map_sha256": sha(canonical(actual)),
                                "added_file_count": len(set(actual) - set(before)) if isinstance(before, dict) else None,
                                "missing_file_count": len(set(before) - set(actual)) if isinstance(before, dict) else None,
                                "changed_file_count": sum(actual[name] != digest for name, digest in before.items() if name in actual) if isinstance(before, dict) else None}
            for key, stage, is_test in (("test_binary", "test", True), ("binary", "release", False)):
                result[key] = artifact(logs.get(stage), is_test, report.get(key), source)
                checks[key + "_independently_verified"] = result[key]["verified"]
        except (OSError, KeyError, TypeError, ValueError) as error:
            result["independent_verification_error"] = private_error(error)
            checks["all_success_inputs_readable"] = False
        result["qualified"] = all(checks.values())
    result["unmet_checks"] = [name for name, passed in checks.items() if passed is not True]
    data = canonical(result) + b"\n"
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("xb") as output:
        output.write(data)
        output.flush()
        os.fsync(output.fileno())
    directory = os.open(args.output.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
    print(json.dumps({"qualified": result["qualified"], "raw_report_qualified": report.get("qualified"),
                      "receipt_sha256": sha(data), "receipt_bytes": len(data),
                      "unmet_checks": result["unmet_checks"]}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
