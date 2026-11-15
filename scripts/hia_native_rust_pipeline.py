# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Run every original recipe once in source-bound groups, then admit all bytes.

The workflow supplies the fresh native seal and each successful original seal
through job outputs. A shard is not an aggregate PASS. Shared reference builds
stay ordered in one group; native corpora, process limits and recipes are intact.
"""
from __future__ import annotations

import argparse
import copy
from datetime import datetime, timezone
import json
import math
from pathlib import Path
import shutil
import sys
import time
import traceback

sys.path.insert(0, str(Path(__file__).resolve().parent))
import hia_native_pipeline as p
import qualify_hia_runtime_native as q
import compare_hia_runtime_rust as r

GROUPS = {
    "bytes": ("runtime_bytes", "text_budget", "line_verify", "editable_content", "line_endpoint",
              "delta", "binary_codec", "policy", "view_render"),
    "state": ("view_cache", "history", "session_workdir", "file_locks", "file_lock_service"),
    "services": ("write_chain", "directory_service", "workdir_service", "sdk_connection", "public_registry"),
    "json": ("fence_json", "serde_json", "execution_shadow", "effect_fence",
             "binary32_json", "typed_result_json", "request_result", "serde_error"),
    "config": ("runtime_config",),
    "system": ("operation_kdf", "operation_aead", "operation_nonce", "operation_record", "system_entropy",
               "operation_scope", "operation_scope_os", "caller_authority", "multi_read_service"),
    "batch": ("batch_plan", "batch_apply", "atomic_write", "batch_write"),
}
NATIVE_SEAL = "original-native.json"
NATIVE_REPORT = "original-native-report.json"
SHARD_SEAL = "original-shard.json"
SHARD_REPORT = "original-shard-report.json"
CONTROLS = ("result-values-evidence-controls", "public-registry-evidence-controls")


def groups() -> dict[str, tuple[str, ...]]:
    flat = tuple(key for keys in GROUPS.values() for key in keys)
    if (set(GROUPS) != {"bytes", "state", "services", "json", "config", "system", "batch"}
            or len(flat) != len(set(flat)) or set(flat) != set(r.RECIPES)):
        raise ValueError("every original recipe must belong to exactly one declared group")
    for together in (("fence_json", "serde_json"), tuple(r.result_qualification.KEYS),
                     tuple(r.PARALLEL_RUST_RECIPES), ("write_chain", "workdir_service")):
        if not any(set(together) <= set(keys) for keys in GROUPS.values()):
            raise ValueError("a shared build or evidence lifetime crosses original groups")
    if GROUPS["config"] != ("runtime_config",):
        raise ValueError("configuration and regex require their complete independent recipe")
    return GROUPS


def binding(output: Path, hepta: Path, invocation: str) -> dict:
    return p.context(output, hepta, invocation)


def pending_native(report: dict) -> None:
    if (report.get("schema") != "hepta.runtime.hia-native-qualification.v1"
            or report.get("status") != "NATIVE_COMPONENTS_PASS"
            or report.get("phase") != "awaiting_original_rust_comparison"
            or report.get("native_components_status") != "PASS"
            or report.get("rust_comparison_status") != "PENDING"
            or report.get("original_rust_comparisons") or report.get("rust_compiler")
            or set(report.get("modules", {})) != {m["key"] for m in q.MODULES}
            or report.get("source_sha256") != q.sources()
            or any(report.get(name) is not False for name in
                   ("production_activated", "whole_runtime_replaced", "old_stack_removal_qualified"))):
        raise ValueError("original shards require one complete, unchanged and unqualified native phase")


def prepare(output: Path, hepta: Path, invocation: str) -> dict:
    groups()
    report = p.read_json(p.owned(output, "result.json"))
    pending_native(report)
    r.check_input_pins(output, report)
    for name in (NATIVE_SEAL, NATIVE_REPORT):
        if (output / name).exists():
            raise ValueError("original native admission is create-only")
    q.save_report(output / NATIVE_REPORT, report)
    files, directories = p.inventory(output, {NATIVE_SEAL, "result.json"})
    seal = {"schema": "hepta.runtime.original-native.v1", "context": binding(output, hepta, invocation),
            "files": files, "directories": directories, "groups": {k: list(v) for k, v in groups().items()}}
    q.save_report(output / NATIVE_SEAL, seal)
    return {"status": "ORIGINAL_NATIVE_READY", "native_sha256": p.digest(output / NATIVE_SEAL),
            "recipes": sum(map(len, groups().values())), "whole_runtime_replaced": False}


def admit_native(output: Path, hepta: Path, expected: str, invocation: str, *, exact: bool):
    if (type(expected) is not str or not p.SHA256.fullmatch(expected)
            or p.digest(p.owned(output, NATIVE_SEAL)) != expected):
        raise ValueError("native artifact differs from the workflow-produced original admission SHA256")
    seal = p.read_json(output / NATIVE_SEAL)
    if (set(seal) != {"schema", "context", "files", "directories", "groups"}
            or seal["schema"] != "hepta.runtime.original-native.v1"
            or seal["context"] != binding(output, hepta, invocation)
            or seal["groups"] != {k: list(v) for k, v in groups().items()}
            or NATIVE_REPORT not in seal["files"]):
        raise ValueError("native admission source, location or original recipe registry differs")
    p.verify_files(output, seal["files"], restore_modes=exact)
    p.verify_directories(output, seal["directories"], restore=exact)
    if exact:
        files, directories = p.inventory(output, {NATIVE_SEAL, "result.json"})
        if files != seal["files"] or set(directories) != set(seal["directories"]):
            raise ValueError("native original input artifact has extra or missing members")
    baseline = p.read_json(p.owned(output, NATIVE_REPORT))
    pending_native(baseline)
    if exact and q.json_bytes(p.read_json(output / "result.json")) != q.json_bytes(baseline):
        raise ValueError("mutable report is not the completed native snapshot")
    return seal, baseline


def version_name(group: str) -> str:
    return "original-rust-compiler-version-" + group


def compiler_record(output: Path, report: dict, rustc: Path, group: str) -> dict:
    version = q.record_check(output, report, name=version_name(group),
                             command=[str(rustc), "--version", "--verbose"], timeout=15)
    text = version.stdout.decode("utf-8")
    if (version.stderr or "release: 1.95.0\n" not in text
            or "commit-hash: 59807616e1fa2540724bfbac14d7976d7e4a3860\n" not in text):
        raise ValueError("original shard did not execute the fixed Rust 1.95.0 compiler")
    return {"invocation_path": str(rustc), "resolved_path": str(rustc.resolve()),
            "invocation_executable_sha256": q.sha(rustc), "version": text}


def shard_binding(group: str, expected: str, invocation: str) -> dict:
    return {"group": group, "invocation": invocation, "native_sha256": expected,
            "recipes": list(groups()[group])}


def export(output: Path, destination: Path, native_seal: dict, report: dict) -> str:
    destination.mkdir(mode=0o700, parents=True, exist_ok=False)
    data = destination / "data"
    data.mkdir(mode=0o700)
    # A successful recipe must finish and retire its own transient fixtures.
    # No target/cache exclusion is used for successful evidence transport.
    p.verify_files(output, native_seal["files"])
    files, directories = p.inventory(output, {NATIVE_SEAL, "result.json", *native_seal["files"]})
    for name in directories:
        if name not in native_seal["directories"]:
            (data / p.relative_path(name)).mkdir(mode=0o700, parents=True, exist_ok=True)
    for name, identity in files.items():
        target = data / p.relative_path(name)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(p.owned(output, name), target)
        target.chmod(identity["mode"])
    q.save_report(destination / SHARD_REPORT, report)
    q.save_report(destination / SHARD_SEAL, {"schema": "hepta.runtime.original-shard.v1",
        "binding": report["original_shard"], "files": files, "directories": p.inventory(data)[1],
        "report_sha256": p.digest(destination / SHARD_REPORT)})
    return p.digest(destination / SHARD_SEAL)


def fail(output: Path, report: dict, error: BaseException, phase: str) -> None:
    report.update(status="FAIL", rust_comparison_status="FAIL", phase=phase,
                  error={"type": type(error).__name__, "message": str(error)})
    (output / "rust-comparison-failure.txt").write_text(traceback.format_exc())
    q.save_report(output / "result.json", report)


def shard(output: Path, hepta: Path, expected: str, invocation: str, group: str,
          destination: Path, rustc_name: str) -> dict:
    seal, baseline = admit_native(output, hepta, expected, invocation, exact=True)
    r.check_input_pins(output, baseline)
    report, started = copy.deepcopy(baseline), time.monotonic()
    report.update(status="RUNNING", phase="original_rust_comparison", rust_comparison_status="RUNNING",
                  original_rust_comparisons={}, original_shard=shard_binding(group, expected, invocation))
    q.save_report(output / "result.json", report)
    try:
        rustc = r.executable(rustc_name)
        report["rust_compiler"] = compiler_record(output, report, rustc, group)
        r.run_rust_recipes(output, report, rustc, recipe_keys=groups()[group])
        if set(report["original_rust_comparisons"]) != set(groups()[group]):
            raise ValueError("original shard did not complete every declared recipe")
        if group == "services":
            report["service_original_fixture_retirement"] = r.service_pipeline.original_fixture_transport(
                q.ROOT, output, report, rustc, q.completed_test_summary, create=True)
        r.check_input_pins(output, report)
        admit_native(output, hepta, expected, invocation, exact=False)
        if q.sha(rustc) != report["rust_compiler"]["invocation_executable_sha256"]:
            raise ValueError("Rust compiler changed during its actual original group")
        report.update(status="ORIGINAL_SHARD_PASS", phase="original_shard_complete", rust_comparison_status="PARTIAL",
                      original_shard_elapsed_seconds=time.monotonic() - started,
                      original_shard_finished_at=datetime.now(timezone.utc).isoformat())
        q.save_report(output / "result.json", report)
        digest = export(output, destination, seal, report)
        return {"status": report["status"], "group": group, "recipes": len(groups()[group]),
                "sha256": digest, "whole_runtime_replaced": False}
    except BaseException as error:
        fail(output, report, error, "original_shard")
        raise


def validate_process(data: Path, row: dict) -> None:
    name, command, timeout = row.get("name"), row.get("command"), row.get("timeout_seconds")
    if (type(name) is not str or not name or Path(name).name != name or "\\" in name
            or type(command) is not list or not command or any(type(x) is not str for x in command)
            or type(timeout) is not int or not 0 < timeout <= 180):
        raise ValueError("original completed process framing or unchanged maximum deadline differs")
    # Exact argv/limits are part of the workflow-pinned shard. Owner-specific
    # inspectors independently reconstruct their commands at final admission.
    p.validate_check(data, row, name, command, timeout, "original_rust_comparison")


def admit_shard(data: Path, seal_path: Path, report_path: Path, baseline: dict, native_sha: str,
                invocation: str, group: str, expected_sha: str, *, exact: bool):
    if (type(expected_sha) is not str or not p.SHA256.fullmatch(expected_sha)
            or p.digest(seal_path) != expected_sha):
        raise ValueError("original shard differs from its successful workflow job SHA256")
    seal = p.read_json(seal_path)
    wanted = shard_binding(group, native_sha, invocation)
    if (set(seal) != {"schema", "binding", "files", "directories", "report_sha256"}
            or seal["schema"] != "hepta.runtime.original-shard.v1" or seal["binding"] != wanted
            or p.digest(report_path) != seal["report_sha256"]):
        raise ValueError("original shard report, recipe or native source binding differs")
    p.verify_files(data, seal["files"], restore_modes=exact)
    p.verify_directories(data, seal["directories"], restore=exact)
    if exact:
        files, directories = p.inventory(data)
        if files != seal["files"] or set(directories) != set(seal["directories"]):
            raise ValueError("original shard contains extra or missing evidence members")
    part = p.read_json(report_path)
    changed = {"status", "phase", "rust_comparison_status", "checks"}
    additions = {"rust_compiler", "original_rust_comparisons", "original_shard", "rust_parallel_receipts",
                 "rust_recipe_processes", "original_shard_elapsed_seconds", "original_shard_finished_at"}
    if group == "services":
        additions.add("service_original_fixture_retirement")
    keys = groups()[group]
    if (set(part) != set(baseline) | additions
            or any(q.json_bytes(part.get(k)) != q.json_bytes(v) for k, v in baseline.items() if k not in changed)
            or part.get("status") != "ORIGINAL_SHARD_PASS" or part.get("phase") != "original_shard_complete"
            or part.get("rust_comparison_status") != "PARTIAL" or part.get("original_shard") != wanted
            or set(part.get("original_rust_comparisons", {})) != set(keys)
            or set(part.get("rust_recipe_processes", {})) != set(keys)
            or q.json_bytes(part.get("checks", [])[:len(baseline["checks"])]) != q.json_bytes(baseline["checks"])):
        raise ValueError("original shard is incomplete or changed the completed native phase")
    elapsed = part["original_shard_elapsed_seconds"]
    if type(elapsed) not in (int, float) or not math.isfinite(elapsed) or elapsed < 0:
        raise ValueError("original shard elapsed observation is malformed")
    datetime.fromisoformat(part["original_shard_finished_at"])
    rows = part["checks"][len(baseline["checks"]):]
    process_names = []
    for key in keys:
        names = part["rust_recipe_processes"][key]
        if type(names) is not list or not names or any(type(name) is not str for name in names):
            raise ValueError("original recipe omitted its actual process records")
        process_names.extend(names)
    all_names = [version_name(group), *process_names]
    if (len(set(all_names)) != len(all_names) or [row.get("name") for row in rows] != all_names
            or set(all_names) & {row["name"] for row in baseline["checks"]}):
        raise ValueError("original processes are omitted, duplicated or attributed to another recipe")
    for row in rows:
        validate_process(data, row)
    compiler = part["rust_compiler"]
    if (set(compiler) != {"invocation_path", "resolved_path", "invocation_executable_sha256", "version"}
            or type(compiler["invocation_path"]) is not str or not Path(compiler["invocation_path"]).is_absolute()
            or type(compiler["resolved_path"]) is not str or not Path(compiler["resolved_path"]).is_absolute()
            or not p.SHA256.fullmatch(compiler["invocation_executable_sha256"])
            or rows[0]["command"] != [compiler["invocation_path"], "--version", "--verbose"]
            or rows[0]["timeout_seconds"] != 15
            or p.owned(data, version_name(group) + ".stdout").read_bytes() != compiler["version"].encode()
            or p.owned(data, version_name(group) + ".stderr").read_bytes()
            or "release: 1.95.0\n" not in compiler["version"]
            or "commit-hash: 59807616e1fa2540724bfbac14d7976d7e4a3860\n" not in compiler["version"]):
        raise ValueError("actual original compiler receipt differs")
    selected_parallel = {key: value for key, value in r.PARALLEL_RUST_RECIPES.items() if key in keys}
    if set(part["rust_parallel_receipts"]) != {value[0] for value in selected_parallel.values()}:
        raise ValueError("original shard private worker receipt inventory differs")
    for key, (name, expected) in selected_parallel.items():
        private_path = p.owned(data, name)
        private = p.read_json(private_path)
        actual = [row for row in private.get("checks", []) if row.get("name") in expected]
        if (p.digest(private_path) != part["rust_parallel_receipts"][name]
                or [row["name"] for row in actual] != list(expected)
                or any(row not in rows for row in actual)):
            raise ValueError("original private worker completion changed")
    return seal, part


def expected_shards(values: dict) -> dict:
    if (type(values) is not dict or set(values) != set(groups())
            or any(type(value) is not str or not p.SHA256.fullmatch(value) for value in values.values())):
        raise ValueError("collection requires every successful original workflow SHA256 exactly once")
    return values


def verify_collected_receipts(output: Path, report: dict) -> None:
    pipeline = report["original_qualification_pipeline"]
    if (set(pipeline) != {"schema", "invocation", "native_sha256", "shards", "recipes"}
            or pipeline["schema"] != "hepta.runtime.original-pipeline.v1"
            or pipeline["recipes"] != [key for keys in groups().values() for key in keys]):
        raise ValueError("complete original pipeline registry differs")
    expected = expected_shards(pipeline["shards"])
    _, baseline = admit_native(output, Path(report["compiler_checkout"]), pipeline["native_sha256"],
                               pipeline["invocation"], exact=False)
    rows, comparisons, mapping, parallel, compilers, service = [], {}, {}, {}, [], None
    for group in groups():
        folder = output / "original-qualification-shards" / group
        _, part = admit_shard(output, p.owned(folder, SHARD_SEAL), p.owned(folder, SHARD_REPORT),
            baseline, pipeline["native_sha256"], pipeline["invocation"], group, expected[group], exact=False)
        rows.extend(part["checks"][len(baseline["checks"]):])
        comparisons.update(part["original_rust_comparisons"])
        mapping.update(part["rust_recipe_processes"])
        parallel.update(part["rust_parallel_receipts"])
        compilers.append(part["rust_compiler"])
        if group == "services":
            service = part["service_original_fixture_retirement"]
    prefix = baseline["checks"] + rows
    tail = report.get("checks", [])[len(prefix):]
    if (q.json_bytes(report.get("checks", [])[:len(prefix)]) != q.json_bytes(prefix)
            or [row.get("name") for row in tail] != list(CONTROLS[:len(tail)]) or len(tail) > len(CONTROLS)
            or report.get("original_rust_comparisons") != comparisons
            or report.get("rust_recipe_processes") != mapping or report.get("rust_parallel_receipts") != parallel
            or any(item != compilers[0] for item in compilers)
            or report.get("rust_compiler") != compilers[0]
            or report.get("service_original_fixture_retirement") != service):
        raise ValueError("aggregate differs from all actual original shard completions")
    if report.get("status") == "PASS" and len(tail) != len(CONTROLS):
        raise ValueError("complete original aggregate omitted quiescent evidence controls")


def collect(output: Path, hepta: Path, native_sha: str, invocation: str,
            shards: Path, expected: dict) -> dict:
    expected_shards(expected)
    seal, baseline = admit_native(output, hepta, native_sha, invocation, exact=True)
    report, started = copy.deepcopy(baseline), time.monotonic()
    report.update(status="RUNNING", phase="original_rust_comparison", rust_comparison_status="RUNNING",
                  original_rust_comparisons={}, rust_recipe_processes={}, rust_parallel_receipts={})
    q.save_report(output / "result.json", report)
    try:
        folders = sorted(shards.iterdir())
        if len(folders) != len(groups()) or any(path.is_symlink() or not path.is_dir() for path in folders):
            raise ValueError("collector requires exactly seven complete original shard artifacts")
        parts, files, copies, directories = {}, {}, {}, set()
        for folder in folders:
            if set(path.name for path in folder.iterdir()) != {"data", SHARD_SEAL, SHARD_REPORT}:
                raise ValueError("original shard artifact has undeclared top-level members")
            seal_path, part_path = p.owned(folder, SHARD_SEAL), p.owned(folder, SHARD_REPORT)
            group = p.read_json(seal_path).get("binding", {}).get("group")
            if group not in groups() or group in parts:
                raise ValueError("duplicate or unknown original shard")
            part_seal, part = admit_shard(folder / "data", seal_path, part_path, baseline,
                                          native_sha, invocation, group, expected[group], exact=True)
            parts[group] = (folder, part_seal, part)
            directories.update(part_seal["directories"])
            for name, identity in part_seal["files"].items():
                if (name in seal["files"] or name in {NATIVE_SEAL, "result.json"}
                        or name.startswith("original-qualification-shards/") or name in files):
                    raise ValueError("original shards replace native evidence or duplicate an artifact")
                files[name], copies[name] = identity, folder / "data" / name
        if set(parts) != set(groups()):
            raise ValueError("missing original recipe group")
        p.verify_directories(output, sorted(directories), restore=True)
        for name, source in copies.items():
            target = output / p.relative_path(name)
            if target.exists() or target.is_symlink():
                raise ValueError("original collector would overwrite an existing artifact")
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, target)
            target.chmod(files[name]["mode"])
        compilers = []
        for group in groups():
            folder, _, part = parts[group]
            dest = output / "original-qualification-shards" / group
            dest.mkdir(mode=0o700, parents=True)
            for name in (SHARD_SEAL, SHARD_REPORT):
                shutil.copyfile(folder / name, dest / name)
            report["checks"].extend(part["checks"][len(baseline["checks"]):])
            for field in ("original_rust_comparisons", "rust_recipe_processes", "rust_parallel_receipts"):
                report[field].update(part[field])
            compilers.append(part["rust_compiler"])
            if group == "services":
                report["service_original_fixture_retirement"] = part["service_original_fixture_retirement"]
        if any(item != compilers[0] for item in compilers):
            raise ValueError("original groups executed different compiler bytes or versions")
        report["rust_compiler"] = compilers[0]
        report["original_qualification_pipeline"] = {"schema": "hepta.runtime.original-pipeline.v1",
            "invocation": invocation, "native_sha256": native_sha, "shards": expected,
            "recipes": [key for keys in groups().values() for key in keys]}
        report["original_group_elapsed_seconds"] = {
            group: parts[group][2]["original_shard_elapsed_seconds"] for group in groups()}
        q.save_report(output / "result.json", report)
        verify_collected_receipts(output, report)
        r.check_input_pins(output, report)
        # All original jobs have terminated successfully; no Cargo tree or
        # parallel reference worker is active during these mutation controls.
        r.run_result_values_controls(output, report)
        r.run_public_registry_controls(output, report)
        r.check_input_pins(output, report)
        report.update(status="PASS", phase="complete", rust_comparison_status="PASS",
                      original_collection_elapsed_seconds=time.monotonic() - started,
                      finished_at=datetime.now(timezone.utc).isoformat())
        verify_collected_receipts(output, report)
        q.save_report(output / "result.json", report)
        return {"status": "PASS", "recipes": len(report["original_rust_comparisons"]),
                "checks": len(report["checks"]), "whole_runtime_replaced": False}
    except BaseException as error:
        fail(output, report, error, "original_collect")
        raise


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("phase", choices=("prepare", "shard", "collect"))
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--hepta", required=True, type=Path)
    parser.add_argument("--invocation", required=True)
    parser.add_argument("--native-sha256")
    parser.add_argument("--group", choices=tuple(GROUPS))
    parser.add_argument("--export", type=Path)
    parser.add_argument("--shards", type=Path)
    parser.add_argument("--shard-sha256", action="append", default=[], metavar="GROUP=SHA256")
    parser.add_argument("--rustc", default="rustc")
    parser.add_argument("--github-output", type=Path)
    args = parser.parse_args()
    output, hepta = args.output.resolve(strict=True), args.hepta.resolve(strict=True)
    if args.phase == "prepare":
        result = prepare(output, hepta, args.invocation)
        key = "native_sha256"
    elif args.phase == "shard":
        if args.group is None or args.export is None:
            parser.error("shard requires --group and --export")
        result = shard(output, hepta, args.native_sha256, args.invocation, args.group,
                       args.export.absolute(), args.rustc)
        key = "sha256"
    else:
        if args.shards is None:
            parser.error("collect requires --shards")
        identities = {}
        for value in args.shard_sha256:
            name, separator, digest = value.partition("=")
            if separator != "=" or name in identities:
                parser.error("each original group SHA256 must be supplied exactly once")
            identities[name] = digest
        result = collect(output, hepta, args.native_sha256, args.invocation,
                         args.shards.resolve(strict=True), identities)
        key = None
    if key and args.github_output:
        with args.github_output.open("a") as stream:
            stream.write(key + "=" + result[key] + "\n")
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
