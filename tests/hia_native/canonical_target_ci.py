#!/usr/bin/env python3
"""Run the existing complete canonical caller domains in isolated CI groups.

This driver composes the ordinary source-owned runners and readers.  It does
not register a smaller replacement domain, alter a deadline, or qualify the
whole runtime.  Q01 remains the historical wire ABI; its selected policy
function, like Q02's, is the explicitly pinned current-target function.
"""
from __future__ import annotations

import argparse
import copy
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
import sys
import time
import traceback

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
import qualify_hia_runtime_native as q
import hia_native_pipeline as p
import hia_native_rust_pipeline as rp
import compare_hia_runtime_rust as r
import hia_native_canonical_target as canonical
import hia_native_runtime_mcp_evidence as runtime_mcp_evidence
import hia_native_filesystem_public_pipeline as filesystem_public_pipeline

FOCUS = "canonical-target-v1"
PROFILE = "tests/hia_native/canonical_target_ci_sources.json"
CI_SOURCES = (
    "tests/hia_native/canonical_target_ci.py",
    PROFILE,
    "tests/hia_native/test_canonical_target_ci.py",
    ".github/workflows/hia-runtime-canonical-target.yml",
    ".github/workflows/hia-runtime-canonical-group.yml",
)
GROUPS = {
    "directory": ("directory_service",),
    "workdir": ("workdir_service",),
    "configuration": ("runtime_config", "runtime_config_span"),
    "public": ("view_read", "view_params", "view_call", "runtime_mcp", "filesystem_public"),
}
TESTS = {
    "directory": (
        "test_directory_service.py", "directory_service_faults.py",
        "test_directory_service_transport.py", "test_directory_service_build.py",
        "test_directory_service_regex.py",
    ),
    "workdir": (
        "test_workdir_params.py", "test_workdir_caller_controls.py", "test_workdir_service_regex.py",
    ),
    "configuration": (
        "test_config_json.py", "test_config_semantics.py", "test_config_fs.py", "test_config_owner.py",
        "test_config_mcp.py", "test_config_mcp_receipts.py", "test_regex_unicode.py",
        "test_regex_syntax.py", "test_regex_hir.py", "test_regex_nfa_0.py", "test_regex_nfa_1.py",
        "test_regex_match.py", "test_regex_pipeline.py", "test_regex_controls.py", "test_config_regex.py",
        "test_config_span.py", "test_config_span_evidence.py",
    ),
    "public": (
        "test_view_call_read.py", "test_view_call_params.py", "test_view_call_sync.py",
        "test_view_call_wide.py", "test_view_call_resources.py", "test_view_call_evidence.py",
        "test_view_search.py", "test_view_search_native_evidence.py", "test_view_regex_search.py",
        "test_view_regex_search_native_evidence.py", "test_runtime_mcp.py", "test_runtime_mcp_evidence.py",
        "test_view_search_public.py", "test_view_regex_search_public.py",
        "test_view_regex_search_public_evidence.py", "test_runtime_mcp_raw_value.py",
        "test_runtime_mcp_raw_value_evidence.py", "test_filesystem_public.py",
    ),
}
NATIVE_FIELDS = {
    "directory": ("directory_service_evidence",),
    "workdir": ("workdir_service_evidence",),
    "configuration": ("config_evidence", "config_span_evidence", "config_span_fixture_retirement"),
    "public": (
        "view_call_evidence", "view_search_evidence", "view_regex_search_evidence", "view_resource_evidence",
        "runtime_mcp_evidence", "filesystem_public_evidence", "filesystem_public_fixture_retirement",
        "view_search_public_evidence", "view_regex_search_public_evidence", "view_fixture_retirement",
        "runtime_mcp_fixture_retirement",
    ),
}
PUBLIC_REFERENCE_FIELDS = (
    "view_search_original_comparison", "view_search_public_original_comparison",
    "view_regex_search_original_comparison", "view_regex_search_public_original_comparison",
    "span_raw_value_reference_builds", "runtime_mcp_original_fixture_retirement",
)
FALSE_FLAGS = ("whole_runtime_replaced", "production_activated", "old_stack_removal_qualified")
NATIVE_REPORT = "canonical-native-report.json"
NATIVE_TRANSPORT = "canonical-native-transport.json"
NATIVE_SEAL = "canonical-native-baseline.json"
ORIGINAL_REPORT = "canonical-original-report.json"
ORIGINAL_SEAL = "original-shard.json"
ORIGINAL_EXPORT_REPORT = "original-shard-report.json"


def need(condition, message):
    if not condition:
        raise ValueError("canonical focused CI: " + message)


def same(actual, expected, message):
    if isinstance(actual, set) and isinstance(expected, set):
        actual, expected = sorted(actual), sorted(expected)
    need(q.json_bytes(actual) == q.json_bytes(expected), message)


def read_object(path):
    return canonical.document(Path(path).read_bytes())


def source_identity(head=None):
    """Pin the frozen 49-file change and the actual full checkout separately."""
    profile = read_object(ROOT / PROFILE)
    need(set(profile) == {"schema", "base_commit", "target_commit", "files", "graphs", "scope"}
         and profile["schema"] == "hepta.runtime.canonical-focused-source.v1"
         and profile["base_commit"] == "db7593e6228e2c554369c634aaeb307eaafc923a"
         and profile["target_commit"] == canonical.TARGET_COMMIT
         and len(profile["files"]) == 49, "frozen source profile framing differs")
    for name, pin in profile["files"].items():
        raw = canonical.regular(ROOT, name)
        same(canonical.pin(raw), pin, "frozen canonical source differs: " + name)
    policy = canonical.source_evidence(ROOT)
    runtime_mcp_evidence.source_identity(ROOT)
    filesystem_public_pipeline.producer_sources(ROOT)
    current = q.git_head()
    need(type(current) is str and len(current) == 40, "a real exact Git checkout is required")
    if head is not None:
        same(current, head, "checkout differs from the workflow head")
    sources = q.sources()
    return {
        "checkout_head": current,
        "source_index_sha256": hashlib.sha256(q.json_bytes(sources)).hexdigest(),
        "source_count": len(sources),
        "frozen_profile_sha256": q.sha(ROOT / PROFILE),
        "ci_sources": {name: canonical.pin(canonical.regular(ROOT, name)) for name in CI_SOURCES},
        "selected_policy": policy,
        "whole_runtime_replaced": False, "production_activated": False,
        "old_stack_removal_qualified": False,
    }


def registry():
    modules = {item["key"]: item for item in q.MODULES}
    need(len(modules) == len(q.MODULES), "duplicate ordinary component")
    all_tests = []
    for group, keys in GROUPS.items():
        actual = tuple(name for key in keys for name in
                       (modules[key]["test"], *modules[key].get("additional_tests", ())))
        same(actual, TESTS[group], "existing complete native suite inventory differs: " + group)
        need(not set(actual) & set(q.PARALLEL_NATIVE_SUITES), "new shared native scheduler needs review")
        selected = tuple(key for key in r.RECIPES if key in keys)
        same(selected, keys, "ordinary original producer order differs: " + group)
        positions = {key: number for number, key in enumerate(keys)}
        for key in keys:
            need(all(owner in positions and positions[owner] < positions[key]
                     for owner in r.RUST_RECIPE_DEPENDENCIES.get(key, ())),
                 "focused group omits or reorders a shared original producer: " + key)
        all_tests.extend(actual)
    need(len(all_tests) == len(set(all_tests)) == 43, "focused suite ownership differs")
    return {group: {"tests": list(TESTS[group]), "recipes": list(keys)} for group, keys in GROUPS.items()}


def graph_evidence(output, report):
    profile = read_object(ROOT / PROFILE)
    records = {}
    for graph, key, field in (
        ("directory", "directory_service", "executable"),
        ("workdir", "workdir_service", "executable"),
        ("config_span", "runtime_config_span", "binary"),
        ("runtime_mcp", "runtime_mcp", "elf"),
    ):
        item = report["modules"][key]
        manifest = p.owned(output, item["manifest"])
        need(q.sha(manifest) == item["sha256"], "fresh graph manifest differs: " + graph)
        value = read_object(manifest)
        wanted = profile["graphs"][graph]
        need(type(value.get("members")) is list and len(value["members"]) == wanted["members"],
             "fresh graph member count differs: " + graph)
        executable = Path(value[field])
        if not executable.is_absolute():
            executable = manifest.parent / executable
        need(executable.is_relative_to(output), "fresh graph executable escapes its build")
        executable = p.owned(output, executable.relative_to(output).as_posix())
        actual = p.file_identity(executable)
        same({key: actual[key] for key in ("bytes", "sha256")}, wanted["elf"],
             "fresh graph differs from the frozen actual packer output: " + graph)
        records[graph] = {"manifest": item["manifest"], "manifest_sha256": item["sha256"],
                          "executable": executable.relative_to(output).as_posix(), **wanted}
    same(set(profile["graphs"]), set(records), "frozen graph inventory differs")
    return records


def binding(output, hepta, prepared_sha, invocation, group):
    registry()
    return {
        "focus": FOCUS, "group": group, "context": p.context(output, hepta, invocation),
        "prepared_sha256": prepared_sha, "tests": list(TESTS[group]), "recipes": list(GROUPS[group]),
        "source": source_identity(),
    }


def native_evidence(output, report, group, *, create=False):
    """Read the full existing owner domains; retirement follows every consumer."""
    fields = {}
    if group == "directory":
        fields["directory_service_evidence"] = q.directory_service_evidence(output, report)
    elif group == "workdir":
        fields["workdir_service_evidence"] = q.workdir_service_evidence(output, report)
        if create:
            q.service_pipeline.prepare_transport(ROOT, output, report, q.completed_test_summary)
    elif group == "configuration":
        fields["config_evidence"] = q.config_evidence(output, report, create=create)
        fields["config_span_evidence"] = q.config_span_evidence(output, report)
        fields["config_span_fixture_retirement"] = q.config_span_fixture_retirement(
            output, report, create=create, native=fields["config_span_evidence"])
    elif group == "public":
        for name, reader in (
            ("view_call_evidence", q.view_call_evidence),
            ("view_search_evidence", q.view_search_evidence),
            ("view_regex_search_evidence", q.view_regex_search_evidence),
            ("view_resource_evidence", q.view_resource_evidence),
            ("runtime_mcp_evidence", q.runtime_mcp_evidence),
            ("filesystem_public_evidence", q.filesystem_public_evidence),
            ("view_search_public_evidence", q.view_search_public_evidence),
            ("view_regex_search_public_evidence", q.view_regex_search_public_evidence),
        ):
            fields[name] = reader(output, report)
        fields["filesystem_public_fixture_retirement"] = q.filesystem_public_retirement(
            output, report, create=create, native=fields["filesystem_public_evidence"])
        fields["view_fixture_retirement"] = q.view_fixture_retirement(
            output, report, create=create, native=fields["view_call_evidence"],
            public=fields["runtime_mcp_evidence"], search=fields["view_search_evidence"],
            public_search=fields["view_search_public_evidence"], regex_search=fields["view_regex_search_evidence"],
            public_regex_search=fields["view_regex_search_public_evidence"])
        fields["runtime_mcp_fixture_retirement"] = q.runtime_mcp_fixture_retirement(
            output, report, create=create, public=fields["runtime_mcp_evidence"],
            public_search=fields["view_search_public_evidence"],
            public_regex_search=fields["view_regex_search_public_evidence"])
    else:
        raise ValueError("undeclared focused group")
    same(set(fields), set(NATIVE_FIELDS[group]), "complete owner evidence inventory differs")
    return fields


def validate_native_report(output, report, prepared, expected_binding):
    group = expected_binding["group"]
    changed = {"status", "phase", "native_components_status", "checks"}
    additions = {"qualification_shard", "native_parallel_receipts", "shard_elapsed_seconds", "shard_finished_at",
                 *NATIVE_FIELDS[group]}
    need(set(report) == set(prepared) | additions, "native report field inventory differs")
    for key, value in prepared.items():
        if key not in changed:
            same(report.get(key), value, "prepared native field changed: " + key)
    same(report.get("qualification_shard"), expected_binding, "native source or group binding differs")
    need(report.get("status") == "CANONICAL_NATIVE_GROUP_PASS"
         and report.get("phase") == "canonical_native_complete"
         and report.get("native_components_status") == "PARTIAL"
         and all(report.get(flag) is False for flag in FALSE_FLAGS), "native scope or completion differs")
    count = len(prepared["checks"])
    same(report["checks"][:count], prepared["checks"], "cold process receipt changed")
    rows = report["checks"][count:]
    same([row.get("name") for row in rows], TESTS[group], "native process inventory or order differs")
    commands = q.native_commands(output, prepared, TESTS[group])
    for row in rows:
        name = row["name"]
        command = commands.get(name, [sys.executable, "-I", "-B", str(ROOT / "tests/hia_native" / name)])
        p.validate_check(output, row, name, command, 180, "native_components")
    same(report["native_parallel_receipts"], {}, "unexpected separate native process receipts")


def exact_export(destination, seal_name, report_name, expected_sha, schema, expected_binding):
    need(q.sha(p.owned(destination, seal_name)) == expected_sha, "workflow-pinned artifact seal differs")
    seal = read_object(destination / seal_name)
    need(set(seal) == {"schema", "binding", "files", "directories", "report_sha256"}
         and seal["schema"] == schema, "export seal schema differs")
    same(seal["binding"], expected_binding, "export source/group binding differs")
    need(q.sha(p.owned(destination, report_name)) == seal["report_sha256"], "export report bytes differ")
    data = destination / "data"
    p.verify_files(data, seal["files"], restore_modes=True)
    p.verify_directories(data, seal["directories"], restore=True)
    files, directories = p.inventory(data)
    same(files, seal["files"], "export has omitted or undeclared files")
    same(sorted(directories), sorted(seal["directories"]), "export directory inventory differs")
    need(set(path.name for path in destination.iterdir()) == {seal_name, report_name, "data"},
         "export root contains undeclared objects")
    return seal, read_object(destination / report_name)


def import_delta(output, data, files, directories):
    """The complete verified delta may add files but cannot replace a predecessor."""
    for name in files:
        path = output / p.relative_path(name)
        need(not path.exists() and not path.is_symlink(), "artifact overwrites an admitted predecessor: " + name)
    p.verify_directories(output, directories, restore=True)
    for name, identity in files.items():
        target = output / p.relative_path(name)
        target.parent.mkdir(parents=True, exist_ok=True)
        with p.owned(data, name).open("rb") as source, target.open("xb") as sink:
            shutil.copyfileobj(source, sink, 1024 * 1024)
        target.chmod(identity["mode"])
    p.verify_files(output, files)


def native_group(output, hepta, prepared_sha, invocation, group, destination):
    before = binding(output, hepta, prepared_sha, invocation, group)
    seal, prepared, _ = p.admit_prepared(output, hepta, prepared_sha, invocation)
    graph_evidence(output, prepared)
    report, started = copy.deepcopy(prepared), time.monotonic()
    report.update(status="RUNNING", phase="native_components", native_components_status="RUNNING",
                  qualification_shard=before)
    q.save_report(output / "result.json", report)
    try:
        q.run_native_checks(output, report, TESTS[group], q.native_environment(output, hepta, report),
                            timeout=180, commands=q.native_commands(output, report, TESTS[group]))
        report.update(native_evidence(output, report, group, create=True))
        same(native_evidence(output, report, group), {name: report[name] for name in NATIVE_FIELDS[group]},
             "native evidence changed during fixture retirement")
        p.admit_prepared(output, hepta, prepared_sha, invocation, exact=False)
        same(binding(output, hepta, prepared_sha, invocation, group), before, "source changed during native checks")
        report.update(status="CANONICAL_NATIVE_GROUP_PASS", phase="canonical_native_complete",
                      native_components_status="PARTIAL", shard_elapsed_seconds=time.monotonic() - started,
                      shard_finished_at=datetime.now(timezone.utc).isoformat())
        validate_native_report(output, report, prepared, before)
        q.save_report(output / NATIVE_REPORT, report)
        q.save_report(output / "result.json", report)
        p.export_shard(output, destination, seal, report)
        return {"status": report["status"], "group": group, "tests": len(TESTS[group]),
                "sha256": q.sha(destination / "shard.json"), **{flag: False for flag in FALSE_FLAGS}}
    except BaseException as error:
        p.fail(output, report, error, "canonical_native")
        raise


def import_native(output, hepta, prepared_sha, invocation, group, artifact, native_sha):
    build, prepared, _ = p.admit_prepared(output, hepta, prepared_sha, invocation)
    graph_evidence(output, prepared)
    wanted = binding(output, hepta, prepared_sha, invocation, group)
    seal, report = exact_export(artifact, "shard.json", "shard-report.json", native_sha,
                                "hepta.runtime.native-shard.v2", wanted)
    need(not set(build["files"]) & set(seal["files"]), "native delta replaces prepared files")
    import_delta(output, artifact / "data", seal["files"], seal["directories"])
    same(read_object(output / NATIVE_REPORT), report, "complete native report copy differs")
    validate_native_report(output, report, prepared, wanted)
    same(native_evidence(output, report, group), {name: report[name] for name in NATIVE_FIELDS[group]},
         "retained complete native evidence differs")
    shutil.copyfile(p.owned(artifact, "shard.json"), output / NATIVE_TRANSPORT)
    q.save_report(output / "result.json", report)
    files, directories = p.inventory(output, {NATIVE_SEAL, "result.json"})
    q.save_report(output / NATIVE_SEAL, {
        "schema": "hepta.runtime.canonical-native-baseline.v1", "binding": wanted,
        "native_artifact_sha256": native_sha, "files": files, "directories": directories,
        "report_sha256": q.sha(output / NATIVE_REPORT),
    })
    return admit_native(output, hepta, prepared_sha, invocation, group, native_sha, exact=True)


def admit_native(output, hepta, prepared_sha, invocation, group, native_sha, *, exact):
    build, prepared, _ = p.admit_prepared(output, hepta, prepared_sha, invocation, exact=False)
    graph_evidence(output, prepared)
    baseline = read_object(p.owned(output, NATIVE_SEAL))
    wanted = binding(output, hepta, prepared_sha, invocation, group)
    need(set(baseline) == {"schema", "binding", "native_artifact_sha256", "files", "directories", "report_sha256"}
         and baseline["schema"] == "hepta.runtime.canonical-native-baseline.v1", "native predecessor schema differs")
    same(baseline["binding"], wanted, "native predecessor binding differs")
    need(baseline["native_artifact_sha256"] == native_sha
         and q.sha(p.owned(output, NATIVE_TRANSPORT)) == native_sha, "native predecessor export seal differs")
    transport = read_object(output / NATIVE_TRANSPORT)
    need(transport.get("schema") == "hepta.runtime.native-shard.v2", "native predecessor transport schema differs")
    same(transport["binding"], wanted, "native predecessor transport binding differs")
    need(not set(build["files"]) & set(transport["files"]), "native predecessor replaced build bytes")
    expected_files = {**build["files"], **transport["files"],
                      p.BUILD_SEAL: p.file_identity(p.owned(output, p.BUILD_SEAL)),
                      NATIVE_TRANSPORT: p.file_identity(p.owned(output, NATIVE_TRANSPORT))}
    same(baseline["files"], expected_files, "native predecessor complete file set differs")
    same(sorted(baseline["directories"]), sorted(set(build["directories"]) | set(transport["directories"])),
         "native predecessor complete directory set differs")
    p.verify_files(output, baseline["files"])
    p.verify_directories(output, baseline["directories"])
    if exact:
        files, directories = p.inventory(output, {NATIVE_SEAL, "result.json"})
        same(files, baseline["files"], "native predecessor has additional or missing files")
        same(sorted(directories), sorted(baseline["directories"]), "native predecessor directories differ")
    need(q.sha(p.owned(output, NATIVE_REPORT)) == baseline["report_sha256"] == transport["report_sha256"],
         "native predecessor report differs")
    report = read_object(output / NATIVE_REPORT)
    validate_native_report(output, report, prepared, wanted)
    same(native_evidence(output, report, group), {name: report[name] for name in NATIVE_FIELDS[group]},
         "native predecessor semantic evidence differs")
    return baseline, report


def original_binding(native, native_sha, group):
    return {"focus": FOCUS, "group": group, "native_sha256": native_sha,
            "native_binding": native["qualification_shard"], "recipes": list(GROUPS[group])}


def retained_original(output, report, group, *, retire=False):
    """These calls use retained readers only; none may launch a reference."""
    values = {}
    rustc = Path(report["rust_compiler"]["invocation_path"])
    if group in ("directory", "workdir"):
        key = GROUPS[group][0]
        values[key] = q.service_pipeline.retained_original(ROOT, output, report, rustc,
                                                         q.completed_test_summary, key)
        if group == "workdir":
            receipt = q.service_pipeline.retire_fixtures(
                output, q.service_pipeline.WORKDIR_ORIGINAL_FIXTURES,
                output / "workdir-original/retired-fixtures.json", values[key], create=retire)
            if retire:
                report["service_original_fixture_retirement"] = {key: receipt}
            else:
                same(report.get("service_original_fixture_retirement"), {key: receipt},
                     "Workdir original fixture retirement differs")
            same(q.service_pipeline.retained_original(ROOT, output, report, rustc, q.completed_test_summary, key),
                 values[key], "Workdir retirement changed complete original evidence")
    elif group == "configuration":
        import hia_native_config_span_pipeline as span
        values["runtime_config"] = r.retained_config_original(output, report)
        values["runtime_config_span"] = span.retained_original(ROOT, output, report, q.completed_test_summary)
    elif group == "public":
        import hia_native_view_call_qualification as view
        import hia_native_filesystem_public_pipeline as filesystem
        shared = view.compare_original(ROOT, output, report, report["view_call_evidence"])
        for key in ("view_read", "view_params", "view_call"):
            values[key] = shared
        r.compare_view_search(output, report)
        r.compare_view_regex_search(output, report)
        values["runtime_mcp"] = r.compare_runtime_mcp(output, report, None)
        values["filesystem_public"] = filesystem.retained_original(ROOT, output, report, q.completed_test_summary)
        need(all(name in report for name in PUBLIC_REFERENCE_FIELDS), "public original omitted a shared reference receipt")
        files, _ = p.inventory(output, {"result.json"})
        rp.retained_span_references(output, report, files, report["span_raw_value_reference_builds"])
    else:
        raise ValueError("undeclared focused original group")
    same(values, report.get("original_rust_comparisons"), "complete retained original comparisons differ")
    return values


def validate_original_report(output, report, native, native_sha, group):
    changed = {"status", "phase", "rust_comparison_status", "checks"}
    additions = {"original_shard", "original_rust_comparisons", "rust_compiler", "rust_parallel_receipts",
                 "rust_recipe_processes", "rust_recipe_shared_processes", "original_shard_elapsed_seconds",
                 "original_shard_finished_at"}
    if group == "workdir":
        additions.add("service_original_fixture_retirement")
    if group == "public":
        additions.update(PUBLIC_REFERENCE_FIELDS)
    need(set(report) == set(native) | additions, "original report field inventory differs")
    for key, value in native.items():
        if key not in changed:
            same(report.get(key), value, "original recipe changed an admitted native field: " + key)
    same(report.get("original_shard"), original_binding(native, native_sha, group), "original binding differs")
    need(report.get("status") == "CANONICAL_ORIGINAL_GROUP_PASS"
         and report.get("phase") == "canonical_original_complete" and report.get("rust_comparison_status") == "PARTIAL"
         and all(report.get(flag) is False for flag in FALSE_FLAGS), "original scope or completion differs")
    count = len(native["checks"])
    same(report["checks"][:count], native["checks"], "original recipe changed preceding native processes")
    compiler = report["rust_compiler"]
    need(set(compiler) == {"invocation_path", "resolved_path", "invocation_executable_sha256", "version"}
         and "release: 1.95.0\n" in compiler["version"]
         and "commit-hash: 59807616e1fa2540724bfbac14d7976d7e4a3860\n" in compiler["version"],
         "fixed actual Rust compiler record differs")
    rows = report["checks"][count:]
    owners = r.original_process_attribution(report, GROUPS[group])
    version_name = rp.version_name("canonical-" + group)
    same([row.get("name") for row in rows], [version_name, *owners], "actual original process ownership or order differs")
    p.validate_check(output, rows[0], version_name,
                     [compiler["invocation_path"], "--version", "--verbose"], 15, "original_rust_comparison")
    same(p.owned(output, version_name + ".stdout").read_text(), compiler["version"], "actual Rust version stream differs")
    need(p.owned(output, version_name + ".stderr").stat().st_size == 0, "Rust version wrote diagnostics")
    for row in rows[1:]:
        rp.validate_process(output, row, owners[row["name"]])
    same(report["rust_parallel_receipts"], {}, "unexpected additional original execution receipt")
    same(set(report["original_rust_comparisons"]), set(GROUPS[group]), "required original recipe is missing")


def export_original(output, destination, baseline, report):
    p.verify_files(output, baseline["files"])
    files, directories = p.inventory(output, {"result.json", *baseline["files"]})
    destination.mkdir(parents=True, mode=0o700, exist_ok=False)
    data = destination / "data"
    data.mkdir(mode=0o700)
    additions = [name for name in directories if name not in baseline["directories"]]
    import_delta(data, output, files, additions)
    q.save_report(destination / ORIGINAL_EXPORT_REPORT, report)
    q.save_report(destination / ORIGINAL_SEAL, {
        "schema": "hepta.runtime.canonical-original-export.v1", "binding": report["original_shard"],
        "files": files, "directories": p.inventory(data)[1],
        "report_sha256": q.sha(destination / ORIGINAL_EXPORT_REPORT),
    })
    return q.sha(destination / ORIGINAL_SEAL)


def original_group(output, hepta, prepared_sha, invocation, group, native_artifact, native_sha, rustc_name, destination):
    baseline, native = import_native(output, hepta, prepared_sha, invocation, group, native_artifact, native_sha)
    report, started = copy.deepcopy(native), time.monotonic()
    report.update(status="RUNNING", phase="original_rust_comparison", rust_comparison_status="RUNNING",
                  original_rust_comparisons={}, original_shard=original_binding(native, native_sha, group))
    q.save_report(output / "result.json", report)
    try:
        rustc = r.executable(rustc_name)
        report["rust_compiler"] = rp.compiler_record(output, report, rustc, "canonical-" + group)
        r.run_rust_recipes(output, report, rustc, recipe_keys=GROUPS[group])
        retained_original(output, report, group, retire=True)
        admit_native(output, hepta, prepared_sha, invocation, group, native_sha, exact=False)
        need(q.sha(rustc) == report["rust_compiler"]["invocation_executable_sha256"], "Rust compiler changed during the group")
        report.update(status="CANONICAL_ORIGINAL_GROUP_PASS", phase="canonical_original_complete",
                      rust_comparison_status="PARTIAL", original_shard_elapsed_seconds=time.monotonic() - started,
                      original_shard_finished_at=datetime.now(timezone.utc).isoformat())
        validate_original_report(output, report, native, native_sha, group)
        q.save_report(output / ORIGINAL_REPORT, report)
        q.save_report(output / "result.json", report)
        digest = export_original(output, destination, baseline, report)
        return {"status": report["status"], "group": group, "recipes": len(GROUPS[group]),
                "sha256": digest, **{flag: False for flag in FALSE_FLAGS}}
    except BaseException as error:
        rp.fail(output, report, error, "canonical_original")
        raise


def verify_original(output, hepta, prepared_sha, invocation, group, native_sha, artifact, original_sha):
    baseline, native = admit_native(output, hepta, prepared_sha, invocation, group, native_sha, exact=False)
    wanted = original_binding(native, native_sha, group)
    seal, report = exact_export(artifact, ORIGINAL_SEAL, ORIGINAL_EXPORT_REPORT, original_sha,
                                "hepta.runtime.canonical-original-export.v1", wanted)
    need(not set(baseline["files"]) & set(seal["files"]), "original delta replaces native files")
    p.verify_files(output, seal["files"])
    same(read_object(output / ORIGINAL_REPORT), report, "original complete report copy differs")
    before_files, before_dirs = p.inventory(output, {"result.json"})
    same(before_files, {**baseline["files"], **seal["files"]}, "final artifact omits or adds files")
    same(sorted(before_dirs), sorted(set(baseline["directories"]) | set(seal["directories"])),
         "final artifact directory inventory differs")
    validate_original_report(output, report, native, native_sha, group)
    retained_original(output, report, group)
    same(native_evidence(output, report, group), {name: native[name] for name in NATIVE_FIELDS[group]},
         "original replay changed complete native evidence")
    after_files, after_dirs = p.inventory(output, {"result.json"})
    same((after_files, after_dirs), (before_files, before_dirs), "independent admission mutated retained evidence")
    return {
        "schema": "hepta.runtime.canonical-focused-admission.v1", "status": "PASS", "group": group,
        "binding": wanted, "original_sha256": original_sha, "native_sha256": native_sha,
        "full_retained_files": len(after_files), "full_retained_bytes": sum(v["bytes"] for v in after_files.values()),
        "native_tests": list(TESTS[group]), "original_recipes": list(GROUPS[group]),
        "actual_original_processes": len(report["checks"]) - len(native["checks"]),
        "all_existing_owner_readers_rerun": True, "new_native_processes": 0, "new_rust_processes": 0,
        "direct_canonical_abi_suite_qualified": False,
        **{flag: False for flag in FALSE_FLAGS},
    }


def collect_admissions(folder, expected, head, invocation):
    """Join workflow-pinned independent admissions without inventing executions."""
    identity = source_identity(head)
    wanted = {}
    for item in expected:
        group, separator, pins = item.partition("=")
        pair = pins.split(":")
        need(separator and group in GROUPS and group not in wanted and len(pair) == 2
             and all(p.SHA256.fullmatch(value) for value in pair), "final workflow digest input differs")
        wanted[group] = pair
    same(set(wanted), set(GROUPS), "a complete original group has no workflow-produced digest")
    names = {group + ".json" for group in GROUPS}
    need(set(path.name for path in folder.iterdir()) == names, "final admission artifact inventory differs")
    values = {}
    for group, (original_sha, admission_sha) in wanted.items():
        path = p.owned(folder, group + ".json")
        need(q.sha(path) == admission_sha, "independent admission differs from its producing job")
        value = read_object(path)
        need(set(value) == {"schema", "status", "group", "binding", "original_sha256", "native_sha256",
                           "full_retained_files", "full_retained_bytes", "native_tests", "original_recipes",
                           "actual_original_processes", "all_existing_owner_readers_rerun", "new_native_processes",
                           "new_rust_processes", "direct_canonical_abi_suite_qualified", *FALSE_FLAGS}
             and value.get("schema") == "hepta.runtime.canonical-focused-admission.v1"
             and value.get("status") == "PASS" and value.get("group") == group
             and value.get("original_sha256") == original_sha
             and value.get("all_existing_owner_readers_rerun") is True
             and type(value.get("new_native_processes")) is int and type(value.get("new_rust_processes")) is int
             and value.get("new_native_processes") == value.get("new_rust_processes") == 0
             and value.get("direct_canonical_abi_suite_qualified") is False
             and all(value.get(flag) is False for flag in FALSE_FLAGS), "final group is incomplete or overclaims its scope")
        same(value["native_tests"], TESTS[group], "final native domain differs")
        same(value["original_recipes"], GROUPS[group], "final original domain differs")
        native = value["binding"]["native_binding"]
        need(native.get("focus") == FOCUS and native.get("group") == group,
             "native predecessor belongs to a different focused group")
        same(native.get("tests"), TESTS[group], "native predecessor omitted a complete suite")
        same(native.get("recipes"), GROUPS[group], "native predecessor changed its original consumers")
        need(type(value.get("native_sha256")) is str and p.SHA256.fullmatch(value["native_sha256"])
             and type(native.get("prepared_sha256")) is str and p.SHA256.fullmatch(native["prepared_sha256"]),
             "native/build workflow digests are malformed")
        same(native["source"], identity, "group used a different exact source closure")
        need(native["context"]["invocation"] == invocation and native["context"]["checkout_head"] == head,
             "group came from another workflow execution")
        same(value["binding"], {"focus": FOCUS, "group": group, "native_sha256": value["native_sha256"],
                               "native_binding": native, "recipes": list(GROUPS[group])},
             "complete original admission binding differs")
        need(type(value.get("full_retained_files")) is int and value["full_retained_files"] > 0
             and type(value.get("full_retained_bytes")) is int and value["full_retained_bytes"] > 0
             and type(value.get("actual_original_processes")) is int and value["actual_original_processes"] > 0,
             "independent admission omitted its complete evidence counts")
        values[group] = value
    contexts = [value["binding"]["native_binding"]["context"] for value in values.values()]
    need(all(item == contexts[0] for item in contexts), "shared execution origins differ between focused groups")
    prepared = {value["binding"]["native_binding"]["prepared_sha256"] for value in values.values()}
    need(len(prepared) == 1, "groups did not use the same fresh cold/build artifact")
    return {"schema": "hepta.runtime.canonical-focused-complete.v1", "status": "PASS", "source": identity,
            "invocation": invocation, "prepared_sha256": next(iter(prepared)), "groups": values,
            "existing_native_suites": 43, "existing_original_recipes": 9,
            "scope": "complete existing four caller domains with selected current canonical policy",
            "direct_canonical_abi_suite_qualified": False, "whole_sdk_target_qualified": False,
            **{flag: False for flag in FALSE_FLAGS}}


def emit(value, result_path=None):
    if result_path:
        path = Path(result_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("x", encoding="utf-8") as stream:
            json.dump(value, stream, sort_keys=True, indent=2, allow_nan=False)
            stream.write("\n")
    print(json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False))
    if os.environ.get("GITHUB_OUTPUT"):
        with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as stream:
            for key in ("prepared_sha256", "sha256"):
                if key in value:
                    need(type(value[key]) is str and p.SHA256.fullmatch(value[key]), "invalid workflow digest")
                    stream.write(key + "=" + value[key] + "\n")
            if result_path and value.get("schema") == "hepta.runtime.canonical-focused-admission.v1":
                stream.write("admission_sha256=" + q.sha(Path(result_path)) + "\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("phase", choices=("source-check", "prepare", "native", "original", "verify-original", "collect"))
    parser.add_argument("--head", required=True)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--hepta", type=Path)
    parser.add_argument("--invocation")
    parser.add_argument("--prepared-sha256")
    parser.add_argument("--group", choices=tuple(GROUPS))
    parser.add_argument("--destination", type=Path)
    parser.add_argument("--native-artifact", type=Path)
    parser.add_argument("--native-sha256")
    parser.add_argument("--original-sha256")
    parser.add_argument("--rustc")
    parser.add_argument("--result", type=Path)
    parser.add_argument("--admissions", type=Path)
    parser.add_argument("--expected", action="append", default=[])
    args = parser.parse_args()
    identity = source_identity(args.head)
    domains = registry()
    if args.phase == "source-check":
        emit({"status": "SOURCE_CHECK_PASS", "source": identity, "groups": domains,
              "native_processes": 0, "rust_processes": 0}, args.result)
        return
    if args.phase == "collect":
        need(args.admissions is not None and args.invocation, "final admission directory and invocation are required")
        emit(collect_admissions(args.admissions.absolute(), args.expected, args.head, args.invocation), args.result)
        return
    need(args.output is not None and args.hepta is not None and args.invocation,
         "output, compiler and invocation are required")
    output, hepta = args.output.absolute(), args.hepta.resolve(strict=True)
    if args.phase == "prepare":
        value = p.prepare(output, hepta, args.invocation)
        value["canonical_graphs"] = graph_evidence(output, read_object(output / p.BUILD_REPORT))
        same(source_identity(args.head), identity, "source changed during the ordinary cold/native build")
    else:
        need(args.group in GROUPS and args.prepared_sha256 and args.destination is not None,
             "group, prepared digest and artifact destination are required")
        destination = args.destination.absolute()
        if args.phase == "native":
            value = native_group(output, hepta, args.prepared_sha256, args.invocation, args.group, destination)
        elif args.phase == "original":
            need(args.native_artifact is not None and args.native_sha256 and args.rustc,
                 "original group requires its exact native artifact and selected Rust compiler")
            value = original_group(output, hepta, args.prepared_sha256, args.invocation, args.group,
                                   args.native_artifact.absolute(), args.native_sha256, args.rustc, destination)
        else:
            need(args.native_sha256 and args.original_sha256, "independent reader requires both workflow artifact digests")
            value = verify_original(output, hepta, args.prepared_sha256, args.invocation, args.group,
                                    args.native_sha256, destination, args.original_sha256)
    emit(value, args.result)


if __name__ == "__main__":
    main()
