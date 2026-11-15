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
import hia_native_request_context_reference as context_reference
import hia_native_result_publication_reference as publication_reference
import hia_native_request_scope_reference as scope_reference

GROUPS = {
    "storage": tuple(r.storage_pipeline.KEYS),
    'bytes': ('runtime_bytes', 'text_budget', 'line_verify', 'editable_content', 'view_render', 'view_render_growth', 'view_read', 'view_params', 'view_call', 'runtime_mcp', 'line_endpoint', 'delta', 'binary_codec', 'policy', 'filesystem_public', 'text_editor_params'),
    'state': ('terminal_clean', 'shell_gate', 'shell_process', 'shell_background_text', 'shell_outcome', 'shell_output_io', 'shell_foreground', 'shell_capture_path', 'shell_capture_mkdir', 'shell_capture_file', 'shell_capture_prepare', 'view_cache', 'history', 'session_workdir', 'file_locks', 'file_lock_service'),
    'services': ('write_chain', 'directory_service', 'workdir_service', 'sdk_connection', 'public_registry'),
    'json': ('serde_error', 'request_context', 'response_hints', 'result_publication', 'request_scope_lifecycle', 'binary32_json', 'typed_result_json', 'request_result', 'fence_json', 'serde_json', 'execution_shadow', 'effect_fence'),
    'config': ('runtime_config', 'runtime_config_span'),
    'system': ('operation_scope_os', 'multi_read_service', 'operation_kdf', 'operation_aead', 'operation_nonce', 'operation_record', 'system_entropy', 'operation_scope', 'caller_authority', 'bellman_core', 'bellman_commitment', 'local_create_file', 'local_create_spec'),
    'batch': ('batch_write', 'batch_plan', 'batch_apply', 'batch_edit_params', 'batch_plan_input', 'batch_diff', 'atomic_write', 'filesystem_parity'),
}
NATIVE_SEAL = "original-native.json"
NATIVE_REPORT = "original-native-report.json"
SHARD_SEAL = "original-shard.json"
SHARD_REPORT = "original-shard-report.json"
CONTROLS = ("result-values-evidence-controls", "public-registry-evidence-controls", "result-storage-evidence-controls")
REFERENCE_OWNERS = {
    "json_reference_build": ("fence_json", "serde_json"),
    "request_context_reference": ("request_context", "response_hints"),
    "result_publication_reference": ("result_publication",),
    "request_scope_reference": ("request_scope_lifecycle",),
    "view_search_original_comparison": ("view_read", "view_params", "view_call", "runtime_mcp"),
    "view_search_public_original_comparison": ("view_read", "view_params", "view_call", "runtime_mcp"),
    "view_regex_search_original_comparison": ("view_read", "view_params", "view_call", "runtime_mcp"),
    "view_regex_search_public_original_comparison": ("view_read", "view_params", "view_call", "runtime_mcp"),
    "span_raw_value_reference_builds": ("runtime_mcp",),
}


def groups() -> dict[str, tuple[str, ...]]:
    flat = tuple(key for keys in GROUPS.values() for key in keys)
    if (set(GROUPS) != {"bytes", "state", "services", "json", "config", "system", "batch", "storage"}
            or len(flat) != len(set(flat)) or set(flat) != set(r.RECIPES)):
        raise ValueError("every original recipe must belong to exactly one declared group")
    for together in (("fence_json", "serde_json"), tuple(r.result_qualification.KEYS),
                     tuple(r.PARALLEL_RUST_RECIPES), ("write_chain", "workdir_service"),
                     *REFERENCE_OWNERS.values(),
                     *((consumer, *owners) for consumer, owners in r.RUST_RECIPE_DEPENDENCIES.items())):
        if not any(set(together) <= set(keys) for keys in GROUPS.values()):
            raise ValueError("a shared build or evidence lifetime crosses original groups")
    for keys in GROUPS.values():
        if keys != tuple(key for key in r.RECIPES if key in keys):
            raise ValueError("original group differs from its source-declared producer order")
    if GROUPS["config"] != ("runtime_config", "runtime_config_span"):
        raise ValueError("configuration and regex require their complete independent recipe")
    if GROUPS["storage"] != tuple(r.storage_pipeline.KEYS):
        raise ValueError("storage originals require their complete independent group")
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
            or report.get("rust_recipe_processes") or report.get("rust_recipe_shared_processes")
            or report.get("rust_parallel_receipts")
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


def validate_process(data: Path, row: dict, recipe: str | None) -> None:
    name, command, timeout = row.get("name"), row.get("command"), row.get("timeout_seconds")
    exception = r.RUST_PROCESS_DEADLINES.get(name) if type(name) is str else None
    if (type(name) is not str or not name or Path(name).name != name or "\\" in name
            or type(command) is not list or not command or any(type(x) is not str for x in command)
            or type(timeout) is not int or (exception != (recipe, timeout) if exception is not None
                                           else not 0 < timeout <= 180)):
        raise ValueError("original completed process framing or unchanged maximum deadline differs")
    # Exact argv/limits are part of the workflow-pinned shard. Owner-specific
    # inspectors independently reconstruct their commands at final admission.
    p.validate_check(data, row, name, command, timeout, "original_rust_comparison")


def shared_json_build(report: dict) -> dict:
    """Retain the one actual Cargo build used by both complete JSON replays."""
    build = report.get("json_reference_build")
    results = report.get("original_rust_comparisons", {})
    if (type(build) is not dict or build.get("schema") != "hepta.runtime.json-reference-build.v1"
            or any(type(results.get(key)) is not dict
                   or q.json_bytes(results[key].get("reference_build")) != q.json_bytes(build)
                   for key in ("fence_json", "serde_json"))):
        raise ValueError("JSON shared Cargo build differs from its two complete original replays")
    return build


def reference_fields(group: str) -> tuple[str, ...]:
    keys = groups()[group]
    return tuple(name for name, owners in REFERENCE_OWNERS.items() if set(owners) <= set(keys))


def retained_span_references(data: Path, report: dict, files: dict, state: dict) -> None:
    """Carry both fresh span references with their real five-process custody.

    Native files travel in the separately admitted native artifact, so their
    complete verified identities are used here. The full semantic reader runs
    after collection and reads both the native and original bytes again.
    """
    import hia_native_span_raw_value_qualification as span
    import hia_native_runtime_mcp_original as original

    def require(condition: bool, detail: str) -> None:
        if not condition:
            raise ValueError("span original reference " + detail)

    def identity(name: str) -> dict:
        p.relative_path(name)
        require(name in files, "omitted retained bytes: " + name)
        return {key: files[name][key] for key in ("bytes", "sha256")}

    native = report.get("runtime_mcp_evidence", {}).get("span_raw_value")
    comparison = report["original_rust_comparisons"]["runtime_mcp"].get("span_raw_value")
    require(type(native) is dict and type(comparison) is dict and type(state) is dict,
            "omitted its native evidence, comparison or build receipt")
    require(set(state) == {"schema", "source_inputs", "native_evidence_sha256", "cleared_environment",
                          "removed_environment", "rustc", "cargo", "execution", "builds"}
            and state["schema"] == "hepta.runtime.span-raw-value.reference-builds.v1",
            "build receipt schema differs")
    require(comparison.get("schema") == "hepta.runtime.span-raw-value.original-comparison.v1"
            and comparison.get("status") == "PASS"
            and all(type(comparison.get(name)) is int for name in ("actual_fresh_rust_builds", "actual_rust_replays",
                "actual_compiler_version_processes", "native_cases_added_by_replay"))
            and comparison.get("actual_fresh_rust_builds") == 2
            and comparison.get("actual_rust_replays") == 2
            and comparison.get("actual_compiler_version_processes") == 1
            and comparison.get("native_cases_added_by_replay") == 0
            and comparison.get("typed_sdk_handler_fixture") is True
            and all(comparison.get(flag) is False for flag in span.FALSE_FLAGS),
            "comparison scope or completed process counts differ")
    source = native.get("source_inputs")
    require(type(source) is dict and set(source) == {"public_source_binding", "files"}
            and type(source["files"]) is dict and set(source["files"]) == set(span.SOURCE_FILES)
            and state["source_inputs"] == source == comparison.get("source_inputs"),
            "source custody differs from the immutable native phase")
    for name, pin in source["files"].items():
        p.relative_path(name)
        require(type(pin) is dict and set(pin) == {"bytes", "sha256"}
                and type(pin["bytes"]) is int and pin["bytes"] >= 0
                and pin["sha256"] == report["source_sha256"].get(name),
                "source differs from the workflow source inventory")
    require(state["native_evidence_sha256"] == comparison.get("native_evidence_sha256")
            == span.sha(span.compact(native)), "native evidence digest differs")
    require(state["cleared_environment"] == list(original.CLEARED)
            and type(state["removed_environment"]) is list
            and state["removed_environment"] == [key for key in original.CLEARED
                                                  if key in state["removed_environment"]],
            "controlled environment declaration differs")
    origin = state["execution"]
    require(type(origin) is dict and set(origin) == {"runtime_root", "output_root"}
            and all(type(value) is str and Path(value).is_absolute()
                    and str(Path(value)) == value and ".." not in Path(value).parts
                    for value in origin.values()), "execution origin is not canonical")
    rustc, cargo = state["rustc"], state["cargo"]
    require(type(rustc) is dict and set(rustc) == {"invocation", "sha256"}
            and type(cargo) is dict and set(cargo) == {"invocation", "sha256"}
            and rustc["invocation"] == report["rust_compiler"]["invocation_path"]
            and rustc["sha256"] == report["rust_compiler"]["invocation_executable_sha256"] == original.RUSTC_SHA
            and cargo["invocation"] == str(Path(rustc["invocation"]).with_name("cargo"))
            and cargo["sha256"] == original.CARGO_SHA, "selected compiler or Cargo identity differs")
    names = ("span-raw-value-rustc-version", "span-value-rust-compile", "span-value-rust-replay",
             "span-sdk-rust-compile", "span-sdk-rust-replay")
    require([name for name in report["rust_recipe_processes"]["runtime_mcp"] if name in names] == list(names)
            and all(sum(row.get("name") == name for row in report["checks"]) == 1 for name in names),
            "five actual owner processes are absent, repeated or reordered")
    rows = {row["name"]: row for row in report["checks"] if row["name"] in names}

    def process(name: str, command: list[str]) -> dict:
        row = rows[name]
        require(row["command"] == command and type(row["timeout_seconds"]) is int
                and row["timeout_seconds"] == 180, "actual process command or 180-second deadline differs")
        for suffix in ("stdout", "stderr"):
            pin = identity(name + "." + suffix)
            require(pin == {"bytes": row[suffix + "_bytes"], "sha256": row[suffix + "_sha256"]},
                    "actual process stream differs from retained bytes")
        return row

    version = process(names[0], [rustc["invocation"], "--version"])
    require(p.owned(data, names[0] + ".stdout").read_bytes() == original.RUST_VERSION
            and version["stderr_bytes"] == 0, "actual compiler version bytes differ")
    require(type(state["builds"]) is dict and set(state["builds"]) == {"value", "sdk"}
            and type(comparison.get("references")) is dict and set(comparison["references"]) == {"value", "sdk"},
            "two separate original builds are not retained")
    pins = comparison.get("artifact_sha256")
    require(type(pins) is dict and bool(pins), "complete comparison artifact inventory is absent")
    for name, digest in pins.items():
        require(identity(name)["sha256"] == digest, "comparison artifact differs from retained bytes")
    needed = {name + "." + suffix for name in names for suffix in ("stdout", "stderr")}
    for key in ("value", "sdk"):
        base = span.FOLDER + "/original/" + key
        origin_base = str(Path(origin["output_root"]) / base)
        build, reference = state["builds"][key], comparison["references"][key]
        expected_sources = {}
        for name, source_name in span.reference_files(key).items():
            relative = base + "/" + name
            needed.add(relative)
            expected_sources[name] = identity(relative)
            require(expected_sources[name] == source["files"][source_name],
                    "materialized reference source differs from its native source binding")
        require(type(build) is dict and set(build) == {"sources", "executable", "binary",
                "compile_stdout_sha256", "compile_stderr_sha256"} and build["sources"] == expected_sources,
                "materialized build source inventory differs")
        compiled = process("span-" + key + "-rust-compile", [cargo["invocation"], "build", "--locked", "--release",
            "--manifest-path", origin_base + "/Cargo.toml", "--target-dir", origin_base + "/target"])
        executable = base + "/target/release/" + ("hia-serde-json-reference" if key == "value"
                                                 else "hepta-workdir-original-oracle")
        needed.add(executable)
        require(build["executable"] == executable and build["binary"] == identity(executable)
                and all(build["compile_" + stream + "_sha256"] == compiled[stream + "_sha256"]
                        for stream in ("stdout", "stderr")), "compiled executable or actual build streams differ")
        with p.owned(data, executable).open("rb") as binary:
            require(binary.read(4) == b"\x7fELF", "compiled reference is not a retained ELF")
        replayed = process("span-" + key + "-rust-replay", [str(Path(origin["output_root"]) / executable)])
        input_name = span.FOLDER + "/" + ("requests.hex" if key == "value" else "sdk-requests.hex")
        needed.add(input_name)
        output_pin = identity("span-" + key + "-rust-replay.stdout")
        require(reference == {"cases": span.LEAF_CASES if key == "value" else span.SDK_CASES,
            "input": identity(input_name), "output": output_pin, "executable": executable,
            "binary": identity(executable)} and replayed["stderr_bytes"] == 0
            and {"bytes": replayed.get("stdin_bytes"), "sha256": replayed.get("stdin_sha256")} == identity(input_name),
            "actual replay input, output or executable binding differs")
        if key == "value":
            needed.add(span.FOLDER + "/native-output.txt")
            require(output_pin == identity(span.FOLDER + "/native-output.txt"), "complete native and original Value streams differ")
    require(needed <= set(pins), "comparison omitted required source, process or native artifacts")
    require(q.json_bytes(p.read_json(p.owned(data, span.FOLDER + "/rust-comparison.json"))) == q.json_bytes(comparison),
            "stored complete comparison differs from its recipe result")


def retained_reference_fields(data: Path, report: dict, group: str, files: dict) -> dict:
    """Bind each owner receipt to the already verified native/original files.

    Semantic readers still run after complete collection. Here the source-owned
    fields cannot disappear, change groups, cite an unretained artifact, or name
    a different original build from the recipe that actually consumed it.
    """
    fields = {name: report[name] for name in reference_fields(group)}

    def artifacts(value: dict, label: str) -> dict:
        pins = value.get("artifact_sha256")
        if type(pins) is not dict or not pins:
            raise ValueError("original reference omitted complete artifact custody: " + label)
        for name, pin in pins.items():
            p.relative_path(name)
            if (type(pin) is not str or not p.SHA256.fullmatch(pin)
                    or name not in files or files[name]["sha256"] != pin):
                raise ValueError("original reference artifact differs from the retained complete bytes: " + label)
        return pins

    if "json_reference_build" in fields:
        shared_json_build(report)
    if "span_raw_value_reference_builds" in fields:
        retained_span_references(data, report, files, fields["span_raw_value_reference_builds"])
    specs = (
        ("request_context_reference", context_reference, "hepta.runtime.request-context-reference.v1"),
        ("result_publication_reference", publication_reference, "hepta.runtime.result-publication-reference.v1"),
        ("request_scope_reference", scope_reference, "hepta.runtime.request-scope-reference.v1"),
    )
    comparisons = report["original_rust_comparisons"]
    for field, owner, schema in specs:
        if field not in fields:
            continue
        value = fields[field]
        if type(value) is not dict or value.get("schema") != schema or type(value.get("result")) is not dict:
            raise ValueError("required original owner reference is malformed: " + field)
        pins = artifacts(value, field)
        result_path = owner.FOLDER + "/RESULT.json"
        if (result_path not in pins
                or q.json_bytes(p.read_json(p.owned(data, result_path))) != q.json_bytes(value["result"])):
            raise ValueError("original owner reference differs from its completed result bytes: " + field)
        for key in REFERENCE_OWNERS[field]:
            result = comparisons[key]
            if (type(result) is not dict or result.get("shared_fresh_reference") != result_path
                    or result.get("shared_fresh_reference_sha256") != pins[result_path]):
                raise ValueError("original recipe cites another completed owner reference: " + key)
        if field == "request_context_reference":
            for key, result_key in (("request_context", "native_context_to_original"),
                                    ("response_hints", "native_response_to_original")):
                if (result_key not in value["result"]
                        or q.json_bytes(comparisons[key].get("comparison")) != q.json_bytes(value["result"][result_key])):
                    raise ValueError("request context comparison differs from its shared original reference")
        elif q.json_bytes(comparisons[owner.COMPONENT]) != q.json_bytes(owner.comparison_receipt(value)):
            raise ValueError("original owner comparison differs from its completed reference: " + field)
    for stem, checks in (("view_search", r.VIEW_SEARCH_ORIGINAL_CHECKS),
                         ("view_regex_search", r.VIEW_REGEX_SEARCH_ORIGINAL_CHECKS)):
        local_field, public_field = stem + "_original_comparison", stem + "_public_original_comparison"
        if local_field not in fields:
            continue
        local, public = fields[local_field], fields[public_field]
        slug = stem.replace("_", "-")
        folder = slug + "-original"
        if (type(local) is not dict or local.get("schema") != "hepta.runtime." + slug + "-original-comparison.v1"
                or local.get("status") != "PASS" or local.get("original_output") != folder
                or local.get("required_original_checks") != list(checks)
                or any(name not in report["rust_recipe_processes"]["view_read"] for name in checks)
                or type(public) is not dict
                or public.get("schema") != "hepta.runtime." + slug + "-public-original-comparison.v1"
                or public.get("status") != "PASS"):
            raise ValueError("required shared search original receipt or process attribution differs")
        local_pins, public_pins = artifacts(local, local_field), artifacts(public, public_field)
        for name in ("result.json", "process-receipts.json", "input.bin", "original.stdout"):
            relative = folder + "/" + name
            if relative not in local_pins or public_pins.get(relative) != local_pins[relative]:
                raise ValueError("public search comparison cites a different shared original artifact")
    return fields


def admit_shard(data: Path, seal_path: Path, report_path: Path, baseline: dict, native_sha: str,
                invocation: str, group: str, expected_sha: str, *, native_files: dict, exact: bool):
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
                 "rust_recipe_processes", "rust_recipe_shared_processes",
                 "original_shard_elapsed_seconds", "original_shard_finished_at"}
    if group == "services":
        additions.add("service_original_fixture_retirement")
    additions.update(reference_fields(group))
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
    owners = r.original_process_attribution(part, keys)
    all_names = [version_name(group), *owners]
    if (len(set(all_names)) != len(all_names) or [row.get("name") for row in rows] != all_names
            or set(all_names) & {row["name"] for row in baseline["checks"]}):
        raise ValueError("original processes are omitted, duplicated or attributed to another recipe")
    for row in rows:
        validate_process(data, row, owners.get(row["name"]))
    if set(native_files) & set(seal["files"]):
        raise ValueError("original shard would replace native evidence")
    retained_reference_fields(data, part, group, {**native_files, **seal["files"]})
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
    native_seal, baseline = admit_native(output, Path(report["compiler_checkout"]), pipeline["native_sha256"],
                                         pipeline["invocation"], exact=False)
    rows, comparisons, mapping, shared, parallel, compilers, references, service = [], {}, {}, {}, {}, [], {}, None
    for group in groups():
        folder = output / "original-qualification-shards" / group
        _, part = admit_shard(output, p.owned(folder, SHARD_SEAL), p.owned(folder, SHARD_REPORT),
            baseline, pipeline["native_sha256"], pipeline["invocation"], group, expected[group],
            native_files=native_seal["files"], exact=False)
        rows.extend(part["checks"][len(baseline["checks"]):])
        comparisons.update(part["original_rust_comparisons"])
        mapping.update(part["rust_recipe_processes"])
        shared.update(part["rust_recipe_shared_processes"])
        parallel.update(part["rust_parallel_receipts"])
        compilers.append(part["rust_compiler"])
        if group == "services":
            service = part["service_original_fixture_retirement"]
        references.update((field, part[field]) for field in reference_fields(group))
    prefix = baseline["checks"] + rows
    tail = report.get("checks", [])[len(prefix):]
    if (q.json_bytes(report.get("checks", [])[:len(prefix)]) != q.json_bytes(prefix)
            or [row.get("name") for row in tail] != list(CONTROLS[:len(tail)]) or len(tail) > len(CONTROLS)
            or report.get("original_rust_comparisons") != comparisons
            or report.get("rust_recipe_processes") != mapping or report.get("rust_parallel_receipts") != parallel
            or report.get("rust_recipe_shared_processes") != shared
            or any(item != compilers[0] for item in compilers)
            or report.get("rust_compiler") != compilers[0]
            or report.get("service_original_fixture_retirement") != service
            or any(q.json_bytes(report.get(field)) != q.json_bytes(value) for field, value in references.items())):
        raise ValueError("aggregate differs from all actual original shard completions")
    if report.get("status") == "PASS" and len(tail) != len(CONTROLS):
        raise ValueError("complete original aggregate omitted quiescent evidence controls")


def collect(output: Path, hepta: Path, native_sha: str, invocation: str,
            shards: Path, expected: dict) -> dict:
    expected_shards(expected)
    seal, baseline = admit_native(output, hepta, native_sha, invocation, exact=True)
    report, started = copy.deepcopy(baseline), time.monotonic()
    report.update(status="RUNNING", phase="original_rust_comparison", rust_comparison_status="RUNNING",
                  original_rust_comparisons={}, rust_recipe_processes={}, rust_recipe_shared_processes={},
                  rust_parallel_receipts={})
    q.save_report(output / "result.json", report)
    try:
        folders = sorted(shards.iterdir())
        if len(folders) != len(groups()) or any(path.is_symlink() or not path.is_dir() for path in folders):
            raise ValueError("collector requires exactly eight complete original shard artifacts")
        parts, files, copies, directories = {}, {}, {}, set()
        for folder in folders:
            if set(path.name for path in folder.iterdir()) != {"data", SHARD_SEAL, SHARD_REPORT}:
                raise ValueError("original shard artifact has undeclared top-level members")
            seal_path, part_path = p.owned(folder, SHARD_SEAL), p.owned(folder, SHARD_REPORT)
            group = p.read_json(seal_path).get("binding", {}).get("group")
            if group not in groups() or group in parts:
                raise ValueError("duplicate or unknown original shard")
            part_seal, part = admit_shard(folder / "data", seal_path, part_path, baseline,
                                          native_sha, invocation, group, expected[group],
                                          native_files=seal["files"], exact=True)
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
            for field in ("original_rust_comparisons", "rust_recipe_processes", "rust_recipe_shared_processes",
                          "rust_parallel_receipts"):
                report[field].update(part[field])
            compilers.append(part["rust_compiler"])
            if group == "services":
                report["service_original_fixture_retirement"] = part["service_original_fixture_retirement"]
            for field in reference_fields(group):
                report[field] = copy.deepcopy(part[field])
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
        r.run_result_storage_controls(output, report)
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
