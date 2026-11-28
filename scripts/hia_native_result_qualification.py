# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Admit complete native result-owner corpora and fresh original receipts.

Verification is read-only. Building is the only native-launching operation in
this module; retained original fixtures never count as a fresh Rust execution.
"""
from pathlib import Path
import gzip
import json
import os
import signal
import struct
import subprocess
import sys
import time

from result_value_registry import (COMPILER, COMPILER_IMAGE, MODULES, KEYS, TESTS, CONTROL_TEST,
    DOMAINS, COUNTS, FIXTURES, BINS, REFERENCE, REMOVED_ENVIRONMENT, encoded, regular, require,
    sha, source_pins, sdk_sources)
from hia_native_public_registry_qualification import compile_evidence, completed, confined, keep, duration


def object_at(path):
    value = json.loads(regular(path))
    require(type(value) is dict, "retained result object expected")
    return value


def build_result_values(hepta, build_root, source_root):
    root, build = Path(source_root).resolve(strict=True), Path(build_root).resolve()
    build.mkdir(parents=True, exist_ok=True)
    bundle = build / "result-values-build.json"
    if bundle.exists():
        verify_build(root, bundle)
        return bundle
    pins = source_pins(root)
    command = [sys.executable, "-I", "-B", str(root / "scripts/build_result_values.py"),
        "--hepta", str(Path(hepta).resolve(strict=True)), "--build-root", str(build)]
    env = {k: v for k, v in os.environ.items() if not k.startswith("HIA_")}
    begin = time.monotonic()
    child = subprocess.Popen(command, cwd=root, env=env, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, start_new_session=True)
    timed = False
    try:
        out, err = child.communicate(timeout=180)
    except subprocess.TimeoutExpired:
        timed = True
        os.killpg(child.pid, signal.SIGKILL)
        out, err = child.communicate(timeout=3)
    row = dict(command=command, cwd=str(root), exit_code=child.returncode, timed_out=timed,
        timeout_seconds=180, cleanup_seconds=3, elapsed_seconds=time.monotonic() - begin,
        stdout_sha256=sha(out), stdout_bytes=len(out), stderr_sha256=sha(err), stderr_bytes=len(err),
        sources_before=pins, sources_after=source_pins(root), outer_parent_death_cleanup_qualified=False)
    for suffix, raw in (("stdout", out), ("stderr", err), ("receipt.json", encoded(row))):
        (build / ("result-values-build." + suffix)).write_bytes(raw)
    require(not timed and child.returncode == 0 and not err, "actual native result build failed")
    require(row["sources_after"] == pins, "result sources changed during build")
    require(json.loads(out) == {"manifest": str(bundle), "modules": 5, "actual_static_elfs": 0},
        "actual result build summary differs")
    verify_build(root, bundle)
    return bundle


def verify_build(root, bundle_path):
    root, bundle_path = Path(root).resolve(strict=True), Path(bundle_path).resolve(strict=True)
    build, artifacts = bundle_path.parent, {}
    require(bundle_path.name == "result-values-build.json", "result build name changed")
    bundle = json.loads(keep(build, artifacts, bundle_path))
    pins = source_pins(root)
    require(bundle.get("schema") == "hepta.result-values.native-build.v1" and bundle.get("sources") == pins
        and bundle.get("compiler_commit") == COMPILER and bundle.get("compiler_sha256") == COMPILER_IMAGE
        and set(bundle.get("modules", {})) == set(MODULES)
        and bundle.get("composition") == {"typed_result_json": 29, "request_result": 5,
            "typed_result_json_local_word_helpers": 3, "request_result_local_word_helpers": 3,
            "binary32_exact_bulk_functions": 15, "binary32_local_word_helpers": 3}
        and all(bundle.get(k) is False for k in ("fresh_cold_qualified", "production_activated", "whole_runtime_replaced")),
        "result build closure or scope changed")
    modules = {}
    for name, (source, source_sha, image_sha) in MODULES.items():
        row = dict(source=source, source_sha256=source_sha, image_sha256=image_sha, buffer_profile="serde-json.v1")
        modules[name], _ = compile_evidence(root, build, row, bundle["modules"][name], artifacts)
        require(modules[name]["input_capacity"] == 16 << 20 and modules[name]["output_capacity"] == 64 << 20
            and modules[name]["workspace_capacity"] == 256 << 20, "private native buffer profile changed")
    receipt = json.loads(keep(build, artifacts, build / "result-values-build.receipt.json"))
    command = receipt.get("command", [])
    require(len(command) == 8 and command[:4] == [sys.executable, "-I", "-B", str(root / "scripts/build_result_values.py")]
        and command[4] == "--hepta" and Path(command[5]).is_absolute()
        and command[6:] == ["--build-root", str(build)], "native result build invocation changed")
    out, err = completed(build, "result-values-build", receipt, command, root, 180)
    require(not err and json.loads(out) == {"manifest": str(bundle_path), "modules": 5, "actual_static_elfs": 0}
        and receipt.get("cleanup_seconds") == 3 and receipt.get("sources_before") == receipt.get("sources_after") == pins
        and receipt.get("outer_parent_death_cleanup_qualified") is False, "native result build receipt changed")
    for suffix in ("stdout", "stderr"):
        keep(build, artifacts, build / ("result-values-build." + suffix))
    return dict(bundle=bundle, modules=modules, artifact_sha256=artifacts)


def bundle_for(output, report):
    output = Path(output)
    paths = set()
    for key, domain in KEYS.items():
        row = report["modules"][key]
        require(row["source"] == MODULES[domain][0] and row["builder"] == "result_values", "result registry changed")
        path = confined(output, row["manifest"])
        require(sha(regular(path)) == row["sha256"], "result build manifest changed")
        paths.add(path)
    require(len(paths) == 1, "private result owners lost the shared fixed build")
    return paths.pop()


def test_commands(root, output, report):
    root, output = Path(root), Path(output)
    bundle_path = bundle_for(output, report)
    bundle = object_at(bundle_path)
    module = {key: row["path"] for key, row in bundle["modules"].items()}
    arguments = {
        TESTS[0]: ["--manifest", module["binary32"], "--bulk-manifest", module["bulk"]],
        TESTS[1]: ["--manifest", module["typed"]],
        TESTS[2]: ["--manifest", module["request"], "--value-manifest", module["value"], "--typed-manifest", module["typed"]],
    }
    result = {}
    for name, domain in zip(TESTS, DOMAINS, strict=True):
        result[name] = list(map(str, [sys.executable, "-I", "-B", root / "tests/hia_native" / name,
            *arguments[name], "--runtime", root, "--output", output / "result-values-native" / domain]))
    result[CONTROL_TEST] = list(map(str, [sys.executable, "-I", "-B", root / "tests/hia_native" / CONTROL_TEST,
        "--repo", root, "--build", bundle_path, "--native", output / "result-values-native",
        "--output", output / "result-values-native/controls.json"]))
    return result


def decompressed(path, record=None):
    raw = regular(path)
    value = gzip.decompress(raw)
    if record is not None:
        require(record == dict(bytes=len(value), sha256=sha(value), compressed_bytes=len(raw), compressed_sha256=sha(raw)),
            "complete compressed corpus changed: " + str(path))
    return value


def fixture_receipts(root, folder, domain, result):
    manifest_raw = regular(Path(root) / FIXTURES / "manifest.json")
    manifest = json.loads(manifest_raw)
    require(manifest.get("schema") == "hepta.result-values.retained-original-fixtures.v1"
        and manifest.get("fresh_original_execution") is False
        and {key: {name: r["cases"] for name, r in values.items()}
             for key, values in manifest["domains"].items()} == COUNTS, "original fixture domain changed")
    names = {"binary32": {"main": "original"}, "typed": {"probes": "probes", "cases": "original"},
        "request": {"probes": "original-budget-probes", "cases": "original-cases"}}[domain]
    records, artifacts = [], {}
    for name, relative in names.items():
        path = folder / relative
        receipt = object_at(path / "receipt.json")
        expected = manifest["domains"][domain][name]
        require(receipt.get("schema") == "hepta.result-values.retained-input.v1"
            and receipt.get("domain") == domain and receipt.get("name") == name and receipt.get("cases") == COUNTS[domain][name]
            and receipt.get("observation_kind") == "retained-original-fixture" and receipt.get("actual_original_executions") == 0
            and receipt.get("fixture_manifest_sha256") == sha(manifest_raw)
            and receipt.get("fixture_sha256") == expected["sha256"]
            and receipt.get("original_observation_job") == expected["actual_original_job"], "retained fixture receipt changed")
        for filename, label, size, digest in (("requests.bin.gz", "input", "request_bytes", "request_sha256"),
                                             ("retained.stdout.gz", "stdout", "raw_bytes", "raw_sha256")):
            raw = decompressed(path / filename, receipt[label])
            require((len(raw), sha(raw)) == (expected[size], expected[digest]), "complete retained input/output differs")
            artifacts[str((path / filename).relative_to(folder))] = sha(regular(path / filename))
        artifacts[str((path / "receipt.json").relative_to(folder))] = sha(regular(path / "receipt.json"))
        records.append(receipt)
    observed = [result.get("retained_reference_input")] if domain == "binary32" else result.get("retained_reference_inputs")
    require(records == observed, "native test used another retained domain")
    return artifacts


def framed_rows(path):
    with gzip.open(path, "rb") as stream:
        while header := stream.read(8):
            require(len(header) == 8, "native output length prefix truncated")
            size, = struct.unpack("<Q", header)
            require(size <= 64 << 20, "native result record exceeds declared profile")
            raw = stream.read(size)
            require(len(raw) == size, "native result truncated")
            yield raw


def request_frame(row, body):
    tool, identity, state = (row[k].encode() for k in ("tool", "request_id", "state"))
    return b"HRPRQ001" + struct.pack("<11Q", row["op"], row["tag"], len(tool), len(identity), len(state), len(body),
        row["audit_durable"], row["cancelled"], row["visible"], row["readonly"], 0) + tool + identity + state + body


def request_result(raw):
    require(len(raw) >= 64 and raw[:8] == b"HRPRS001", "native result header differs")
    tag, size, eligible, expose, completion, retain, refused = struct.unpack_from("<7Q", raw, 8)
    require(1 <= tag <= 3 and size == len(raw) - 64 and max(eligible, expose, retain, refused) <= 1
        and completion in (1, 2, 3), "native result fields differ")
    return dict(tag=tag, eligible=bool(eligible), expose=bool(expose), completion=completion,
        retention_candidate=bool(retain), budget_refused=bool(refused), output_body=raw[64:].decode())


def inspect_native_outputs(root, bundle_path, native):
    root, native = Path(root).resolve(strict=True), Path(native).resolve(strict=True)
    built = verify_build(root, bundle_path)
    corpus, results = {}, {}
    for domain in DOMAINS:
        folder = native / domain
        result = object_at(folder / "result.json")
        require(result.get("status") == "PASS" and result.get("actual_original_cases") == 0
            and result.get("whole_runtime_replaced") is False and result.get("production_activated") is False,
            "native test completion or original-execution classification differs")
        fixture = fixture_receipts(root, folder, domain, result)
        for name, digest in fixture.items():
            corpus[str((folder / name).relative_to(native))] = digest
        controls = {"binary32": 6, "typed": 14, "request": 49}[domain]
        require(result.get("controls_passed") == len(result.get("controls", [])) == controls,
            "native refusal domain differs")
        duration(result.get("elapsed_seconds"), 180)
        if domain == "binary32":
            require(result.get("schema") == "hepta.binary32.actual-comparison.v1"
                and result.get("cases") == 541693 and result.get("production_entries") == 1045
                and result.get("bulk_entries") == 1 and result.get("complete_bytes_equal") is True
                and result.get("exhaustive_all_32_bit_patterns") is False
                and result.get("owner_module") == built["modules"]["binary32"]
                and result.get("bulk_module") == built["modules"]["bulk"], "binary32 actual native domain differs")
            actual = decompressed(folder / "native.stdout.jsonl.gz")
            expected = decompressed(folder / "original/retained.stdout.gz")
            require(actual == expected and actual.count(b"\n") == 541693
                and (len(actual), sha(actual)) == (result.get("output_bytes"), result.get("output_sha256")),
                "complete native binary32 output differs")
            inputs = decompressed(folder / "original/requests.bin.gz")
            require((len(inputs), sha(inputs)) == (result.get("input_bytes"), result.get("input_sha256")),
                "binary32 input changed")
            output_file = "native.stdout.jsonl.gz"
        else:
            count = 5249 if domain == "typed" else 1926
            require(result.get("compared_cases") == count and len(result.get("cases", [])) == count
                and result.get("original_probe_cases") == (2 if domain == "typed" else 44)
                and result.get("retained_original_cases") == count + (2 if domain == "typed" else 44),
                "complete result comparison domain differs")
            if domain == "typed":
                require(result.get("schema") == "hepta.typed-json.actual-comparison.v1"
                    and result.get("complete_bytes_equal") is True and result.get("module") == built["modules"]["typed"]
                    and result.get("trusted_typed_canonical_projection_required") is True
                    and result.get("noncomplete_serialization_qualified") is False, "typed serializer scope differs")
                original_folder = folder / "original"
            else:
                require(result.get("schema") == "hepta.request-result.actual-comparison.v1"
                    and result.get("output_bytes_equal") is True and result.get("native_entries") == 4702
                    and result.get("actual_value_child_calls") == 1966 and result.get("actual_typed_child_calls") == 762
                    and result.get("actual_child_calls") == 2728
                    and result.get("modules") == {"owner": built["modules"]["request"],
                        "value": built["modules"]["value"], "typed": built["modules"]["typed"]}
                    and all(result.get(k) is False for k in ("old_stack_removal_qualified", "audit_storage_qualified", "result_storage_qualified"))
                    and result.get("typed_canonical_private_profile") is True, "metadata native call graph or scope differs")
                original_folder = folder / "original-cases"
            output_file = "native-results.bin.gz"
            with gzip.open(original_folder / "requests.bin.gz", "rb") as requests, gzip.open(original_folder / "retained.stdout.gz", "rb") as references:
                for index, (case, line, observation, raw) in enumerate(zip(result["cases"], requests, references,
                        framed_rows(folder / output_file), strict=True)):
                    row, expected = json.loads(line), json.loads(observation)
                    body = expected["body" if domain == "typed" else "input_body"].encode()
                    wire = (b"HRTYP001" + struct.pack("<2Q", expected["tag"], len(body)) + body
                            if domain == "typed" else request_frame(row, body))
                    require(case.get("index" if domain == "typed" else "ordinal") == index
                        and case.get("label") == row["label"]
                        and (case.get("input_bytes"), case.get("input_sha256")) == (len(wire), sha(wire))
                        and (case.get("output_bytes"), case.get("output_sha256")) == (len(raw), sha(raw)),
                        "complete native input/output record changed")
                    if domain == "typed":
                        require(raw == expected["typed_bytes"].encode(), "typed native serialization differs")
                    else:
                        require(request_result(raw) == {k: v for k, v in expected.items() if k not in ("input_body", "output_typed_bytes")}
                            and case.get("original_body_sha256") == sha(expected["output_body"].encode())
                            and case.get("original_typed_body_bytes") == expected["output_typed_bytes"],
                            "native metadata/budget output differs")
                require(index + 1 == count, "complete native corpus was truncated")
        for name in ("result.json", output_file):
            corpus[str((folder / name).relative_to(native))] = sha(regular(folder / name))
        results[domain] = result
    return dict(build=built, results=results, corpus_sha256=corpus)


def native_evidence(root, output, report, completed_test_summary, *, create=False):
    root, output = Path(root), Path(output)
    bundle_path = bundle_for(output, report)
    commands = test_commands(root, output, report)
    checks, summaries = {}, {}
    for name in (*TESTS, CONTROL_TEST):
        row, summary = completed_test_summary(output, report, name)
        out, err = completed(output, name, row, commands[name], root, 180, aggregate=True)
        require(not err and summary == json.loads(out) and row.get("phase") == "native_components",
            "native result suite stdout or phase differs")
        summaries[name] = json.loads(out)
        checks[name] = row
    inspected = inspect_native_outputs(root, bundle_path, output / "result-values-native")
    build_receipt = object_at(bundle_path.parent / "result-values-build.receipt.json")
    require(build_receipt["command"][5] == str(Path(report["compiler_checkout"]).resolve(strict=True)),
        "selected result compiler checkout differs")
    for name, domain in zip(TESTS, DOMAINS, strict=True):
        summary, result = summaries[name], inspected["results"][domain]
        require(summary.get("report_sha256") == sha(regular(output / "result-values-native" / domain / "result.json"))
            and all(result.get(key) == value for key, value in summary.items() if key != "report_sha256"),
            "actual native stdout is not the complete retained test result")
    control = object_at(output / "result-values-native/controls.json")
    require(control == summaries[CONTROL_TEST] and control.get("schema") == "hepta.result-values.native-evidence-controls.v1"
        and control.get("status") == "PASS" and control.get("rejections") == 16 and control.get("restorations") == 17
        and control.get("native_executions_added_by_evidence_admission") == 0,
        "actual native evidence controls did not complete")
    artifacts = {str((bundle_path.parent / name).relative_to(output)): digest
                 for name, digest in inspected["build"]["artifact_sha256"].items()}
    corpus = {"result-values-native/" + name: digest for name, digest in inspected["corpus_sha256"].items()}
    corpus["result-values-native/controls.json"] = sha(regular(output / "result-values-native/controls.json"))
    for name in commands:
        for suffix in ("stdout", "stderr"):
            corpus[name + "." + suffix] = sha(regular(output / (name + "." + suffix)))
    results = inspected["results"]
    native_entries = (results["binary32"]["production_entries"] + results["binary32"]["bulk_entries"]
        + results["typed"]["compared_cases"] + results["typed"]["controls_passed"]
        + results["request"]["native_entries"])
    child_entries = results["request"]["actual_child_calls"]
    return dict(schema="hepta.result-values.native-evidence.v1", status="NATIVE_COMPLETE_RUST_REPLAY_REQUIRED",
        checks=checks, artifact_sha256=artifacts, corpus_sha256=corpus, actual_original_cases=0,
        retained_original_cases=548914, actual_native_entries=native_entries,
        actual_native_child_entries=child_entries, total_actual_native_entries=native_entries + child_entries,
        noncomplete_serialization_qualified=False, audit_storage_qualified=False, result_storage_qualified=False,
        production_activated=False, whole_runtime_replaced=False)


def reference_build_evidence(root, original, *, rustc=None, cargo=None):
    from hia_native_result_reference import reference_inputs, files, archive_files
    root, original = Path(root).resolve(strict=True), Path(original).resolve(strict=True)
    folder, artifacts = original / "build", {}
    report = object_at(folder / "result.json")
    project = folder / "reference"
    proof = reference_inputs(root)
    expected_files = files(root / REFERENCE)
    require(report.get("schema") == "hepta.result-values.original-build.v1" and report.get("status") == "PASS"
        and report.get("sources") == source_pins(root) and report.get("project_files") == files(project) == expected_files
        and report.get("source_projection") == proof and report.get("one_shared_cargo_build") is True
        and report.get("original_sources_unchanged") is True and report.get("intermediate_target_retired") is True
        and report.get("environment_removed") == list(REMOVED_ENVIRONMENT)
        and report.get("clear_target_rustflags") is True
        and type(report.get("outer_process_group")) is int and report["outer_process_group"] > 0
        and all(report.get(k) is False for k in ("inherited_hia_environment", "native_execution_or_fallback",
            "whole_runtime_replaced", "production_activated")), "actual original build completion or source changed")
    duration(report.get("elapsed_seconds"), 180)
    rustc = Path(report["rustc_path"] if rustc is None else rustc).absolute()
    cargo = Path(report["cargo_path"] if cargo is None else cargo).absolute()
    require(str(rustc) == report["rustc_path"] and str(cargo) == report["cargo_path"], "selected original compiler path changed")
    commands = {
        "rust-version": ([rustc, "--version", "--verbose"], 30),
        "metadata": ([cargo, "metadata", "--manifest-path", project / "Cargo.toml", "--format-version", "1", "--locked"], 60),
        "format": ([rustc.with_name("rustfmt"), "--check", "--edition", "2021", "--config", "hard_tabs=true,skip_children=true",
            *[project / name for name in ("binary32.rs", "typed_result.rs", "request_result.rs", "json_size.rs")]], 30),
        "compile": ([cargo, "build", "--manifest-path", project / "Cargo.toml", "--release", "--locked", "--bins"], 180),
    }
    require(set(report.get("checks", {})) == set(commands), "original build process set differs")
    metadata = None
    for name, (command, limit) in commands.items():
        receipt = object_at(folder / (name + ".receipt.json"))
        require(receipt == report["checks"][name] and type(receipt.get("pid")) is int and receipt["pid"] > 0
            and receipt.get("reaped") is True and receipt.get("cleanup_seconds") == 3
            and receipt.get("inherits_outer_process_group") is True and type(receipt.get("process_group")) is int
            and receipt["process_group"] == report["outer_process_group"]
            and receipt.get("outer_parent_death_cleanup_qualified") is False, "actual original build lifecycle differs")
        out, err = completed(folder, name, receipt, list(map(str, command)), root, limit)
        if name == "rust-version":
            require(out.startswith(b"rustc 1.95.0 ") and b"release: 1.95.0\n" in out
                and b"commit-hash: 59807616e1fa2540724bfbac14d7976d7e4a3860\n" in out and not err,
                "fixed actual Rust 1.95 version differs")
        elif name == "format":
            require(not out and not err, "reference formatting gate differs")
        elif name == "metadata":
            metadata = json.loads(out)
        for suffix in ("stdout", "stderr", "receipt.json"):
            keep(original, artifacts, folder / (name + "." + suffix))
    registry = report.get("registry", {})
    fields = ("name", "version", "source", "checksum")
    expected = sorted(({k: p[k] for k in fields} for p in proof["registry_packages"]), key=lambda p: (p["name"], p["version"]))
    require(registry.get("packages") == expected and len(expected) == 100
        and registry.get("actual_sdk_sources") == sdk_sources(root)
        and registry.get("actual_number_sources") == object_at(project / "crate-sources.json")
        and type(registry.get("registry_source_files_verified")) is int,
        "actual original registry or complete serialization sources differ")
    archives = registry.get("archives", {})
    names = {package["name"] + "-" + package["version"] for package in expected}
    require(set(archives) == names
        and {path.name for path in (folder / "registry-archives").iterdir()} == {name + ".crate" for name in names},
        "retained locked registry archive domain differs")
    members = {}
    for package in expected:
        name = package["name"] + "-" + package["version"]
        path = folder / "registry-archives" / (name + ".crate")
        raw = keep(original, artifacts, path)
        require(sha(raw) == package["checksum"], "retained locked registry archive bytes changed")
        members[name] = archive_files(raw, name)
        require(archives[name] == {"path": "registry-archives/" + path.name, "bytes": len(raw), "sha256": sha(raw),
            "files": len(members[name]), "files_sha256": sha(encoded(members[name]))},
            "retained complete registry source inventory differs")
    require(registry["registry_source_files_verified"] == sum(len(value) for value in members.values())
        and members["rmcp-3.4.1"] == sdk_sources(root)
        and {name: members[name] for name in registry["actual_number_sources"]} == registry["actual_number_sources"],
        "complete SDK or numeric source bytes differ from locked retained archives")
    actual_packages = [p for p in metadata["packages"] if p.get("source")]
    require(len(actual_packages) == 100 and {(p["name"], p["version"], p["source"]) for p in actual_packages}
        == {(p["name"], p["version"], p["source"]) for p in expected}, "actual Cargo metadata domain changed")
    require(set(report.get("executables", {})) == set(DOMAINS), "actual original executable set changed")
    for domain, name in BINS.items():
        path = folder / "bin" / name
        raw = keep(original, artifacts, path)
        require(raw.startswith(b"\x7fELF") and path.stat().st_mode & 0o777 == 0o500
            and report["executables"][domain] == {"path": str(path), "bytes": len(raw), "sha256": sha(raw)},
            "actual original executable changed")
    for name in expected_files:
        keep(original, artifacts, project / name)
    keep(original, artifacts, folder / "result.json")
    return dict(result=report, artifact_sha256=artifacts)


def original_command(root, output, report, rustc, cargo, domain):
    root, output = Path(root), Path(output)
    return list(map(str, [sys.executable, "-I", "-B", root / "tests/hia_native/compare_result_values_original.py",
        "--repo", root, "--build", bundle_for(output, report), "--native", output / "result-values-native",
        "--output", output / "result-values-original", "--domain", domain,
        "--rustc", Path(rustc).absolute(), "--cargo", Path(cargo).absolute()]))


def inspect_original_domain(root, original, native, domain, *, rustc=None, cargo=None):
    root, original, native = Path(root), Path(original), Path(native)
    require(domain in DOMAINS, "unknown result reference domain")
    build = reference_build_evidence(root, original, rustc=rustc, cargo=cargo)
    folder, artifacts = original / domain, dict(build["artifact_sha256"])
    report = object_at(folder / "result.json")
    require(report.get("schema") == "hepta.result-values.original-replay.v1" and report.get("status") == "PASS"
        and report.get("domain") == domain and report.get("sources") == source_pins(root)
        and report.get("build_sha256") == sha(regular(original / "build/result.json"))
        and report.get("executable") == build["result"]["executables"][domain]
        and report.get("native_result_sha256") == sha(regular(native / domain / "result.json"))
        and report.get("cases") == sum(COUNTS[domain].values())
        and report.get("actual_original_processes") == len(COUNTS[domain])
        and report.get("actual_native_entries_added") == 0 and report.get("complete_bytes_equal") is True
        and type(report.get("outer_process_group")) is int and report["outer_process_group"] > 0
        and report.get("original_sources_unchanged") is True
        and report.get("whole_runtime_replaced") is False and report.get("production_activated") is False,
        "actual original result completion or scope differs")
    duration(report.get("elapsed_seconds"), 180)
    names = {"binary32": {"main": "original"}, "typed": {"probes": "probes", "cases": "original"},
        "request": {"probes": "original-budget-probes", "cases": "original-cases"}}[domain]
    require(set(report.get("inputs", {})) == set(report.get("checks", {})) == set(names), "complete original replay set changed")
    fixtures = object_at(root / FIXTURES / "manifest.json")["domains"][domain]
    expected_files = {"result.json"}
    for name, source in names.items():
        expected_files.update(name + suffix for suffix in (".stdin.bin.gz", ".stdout.gz", ".stderr", ".receipt.json"))
        wire = decompressed(folder / (name + ".stdin.bin.gz"))
        stdout = decompressed(folder / (name + ".stdout.gz"))
        stderr = regular(folder / (name + ".stderr"))
        receipt = object_at(folder / (name + ".receipt.json"))
        expected, item = fixtures[name], report["inputs"][name]
        require((len(wire), sha(wire)) == (expected["request_bytes"], expected["request_sha256"])
            and (len(stdout), sha(stdout)) == (expected["raw_bytes"], expected["raw_sha256"])
            and stdout.count(b"\n") == COUNTS[domain][name] and not stderr
            and wire == decompressed(native / domain / source / "requests.bin.gz")
            and stdout == decompressed(native / domain / source / "retained.stdout.gz"), "complete fresh original bytes differ")
        require(item == dict(request_bytes=len(wire), request_sha256=sha(wire),
            request_gzip_sha256=sha(regular(folder / (name + ".stdin.bin.gz"))),
            output_bytes=len(stdout), output_sha256=sha(stdout), output_gzip_sha256=sha(regular(folder / (name + ".stdout.gz"))),
            native_fixture_receipt_sha256=sha(regular(native / domain / source / "receipt.json")), complete_bytes_equal=True),
            "fresh original corpus identity changed")
        require(receipt == report["checks"][name] and receipt.get("command") == [report["executable"]["path"]]
            and receipt.get("cwd") == str(root) and type(receipt.get("pid")) is int and receipt["pid"] > 0
            and receipt.get("reaped") is True and receipt.get("exit_code") == 0 and receipt.get("timed_out") is False
            and receipt.get("timeout_seconds") == 180 and receipt.get("cleanup_seconds") == 3
            and receipt.get("inherits_outer_process_group") is True and type(receipt.get("process_group")) is int
            and receipt["process_group"] == report["outer_process_group"]
            and receipt.get("outer_parent_death_cleanup_qualified") is False
            and receipt.get("stdin_bytes") == len(wire) and receipt.get("stdin_sha256") == sha(wire)
            and receipt.get("stdout_bytes") == len(stdout) and receipt.get("stdout_sha256") == sha(stdout)
            and receipt.get("stderr_bytes") == 0 and receipt.get("stderr_sha256") == sha(b"")
            and receipt.get("executable_sha256") == report["executable"]["sha256"]
            and receipt.get("cases") == COUNTS[domain][name], "actual original replay process changed")
        duration(receipt.get("elapsed_seconds"), 180)
    require({p.name for p in folder.iterdir()} == expected_files, "original retained replay file set differs")
    for name in sorted(expected_files):
        keep(original, artifacts, folder / name)
    return dict(result=report, artifact_sha256=artifacts)


def original_evidence(root, output, report, completed_test_summary, domain):
    root, output = Path(root), Path(output)
    original = output / "result-values-original"
    built = reference_build_evidence(root, original)["result"]
    name = "result-" + domain + "-rust-compare"
    row, observed_summary = completed_test_summary(output, report, name)
    command = original_command(root, output, report, built["rustc_path"], built["cargo_path"], domain)
    out, err = completed(output, name, row, command, root, 180, aggregate=True)
    require(not err and observed_summary == json.loads(out) and row.get("phase") == "original_rust_comparison",
        "actual result recipe stdout or phase differs")
    native = native_evidence(root, output, report, completed_test_summary)
    require(native == report.get("result_values_evidence"), "native result evidence changed before original admission")
    checked = inspect_original_domain(root, original, output / "result-values-native", domain)
    summary = json.loads(out)
    value = checked["result"]
    require(summary == {"schema": "hepta.result-values.original-summary.v1", "status": "PASS", "domain": domain,
        "cases": sum(COUNTS[domain].values()), "actual_original_processes": len(COUNTS[domain]),
        "actual_native_entries_added": 0, "complete_bytes_equal": True,
        "result_sha256": sha(regular(original / domain / "result.json")),
        "shared_build_sha256": sha(regular(original / "build/result.json"))}, "actual result recipe stdout differs")
    artifacts = {"result-values-original/" + path: digest for path, digest in checked["artifact_sha256"].items()}
    for suffix in ("stdout", "stderr"):
        artifacts[name + "." + suffix] = sha(regular(output / (name + "." + suffix)))
    return dict(schema="hepta.result-values.original-evidence.v1", status="PASS", domain=domain,
        cases=value["cases"], checks={name: row}, artifact_sha256=artifacts,
        actual_original_processes=value["actual_original_processes"], actual_native_entries_added=0,
        full_original_function_blocks=11, locked_registry_packages=100, one_shared_cargo_build=True,
        production_activated=False, whole_runtime_replaced=False)
