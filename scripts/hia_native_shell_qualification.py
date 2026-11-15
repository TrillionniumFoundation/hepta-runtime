"""Admit complete native shell corpora and fresh original Rust process evidence.

Only the deterministic owners are qualified here. Process creation, background
jobs, production shell routing and removal of the old runtime stay unqualified.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import math
from pathlib import Path
import stat
import struct
import sys

COMPONENTS = {
    "terminal_clean": {"mode": "terminal", "folder": "terminal-clean",
                       "test": "test_shell_native.py", "source": "native/terminal_clean.hepta"},
    "shell_gate": {"mode": "gate", "folder": "shell-gate",
                   "test": "test_shell_gate_native.py", "source": "native/shell_gate.hepta"},
}
CORPUS_FILES = ("input.bin", "native-output.bin", "cases.jsonl", "transport-controls.jsonl")
REFERENCE_FILES = ("Cargo.toml", "Cargo.lock", "source_manifest.json", "src/main.rs", "cases.py", "native_runner.py")
EVIDENCE_REFUSALS = (
    "failed_status", "contradictory_error", "wrong_mode", "invented_rust", "production_claim", "source_digest",
    "manifest_digest", "module_identity", "boolean_count", "category_count", "changed_input",
    "truncated_output", "semantic_row", "control_missing", "control_output_changed",
    "control_return_changed", "missing_file", "symlink_file", "duplicate_json",
)


def require(condition, message):
    if not condition:
        raise ValueError(message)


def encoded(value):
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"),
                      allow_nan=False).encode("ascii")


def exact(actual, expected, message):
    require(encoded(actual) == encoded(expected), message)


def unique(pairs):
    value = {}
    for name, item in pairs:
        require(name not in value, "duplicate shell evidence JSON field")
        value[name] = item
    return value


def decode(raw):
    def invalid(value):
        raise ValueError("non-finite shell evidence number: " + value)
    return json.loads(raw.decode("utf-8"), object_pairs_hook=unique, parse_constant=invalid)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def pin(raw):
    return {"bytes": len(raw), "sha256": sha(raw)}


def owned(root, name):
    require(type(name) is str and bool(name), "shell evidence path is missing")
    rel = Path(name)
    require(not rel.is_absolute() and all(part not in ("", ".", "..") for part in name.split("/"))
            and "\\" not in name and "\x00" not in name, "shell evidence path is not relative")
    path = root / rel
    require(path.resolve(strict=True) == path.absolute() and stat.S_ISREG(path.lstat().st_mode),
            "shell evidence must be an ordinary unsymlinked file")
    return path


def case_owner(root):
    location = owned(root, "tests/hia_native/shell_oracle/cases.py")
    name = "_shell_evidence_cases"
    spec = importlib.util.spec_from_file_location(name, location)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def packets(raw):
    offset = 0
    while offset < len(raw):
        require(len(raw) - offset >= 8, "truncated shell corpus frame")
        length, = struct.unpack_from("<Q", raw, offset)
        offset += 8
        require(length <= len(raw) - offset, "truncated shell corpus payload")
        yield raw[offset:offset + length]
        offset += length


def read_corpus(root, folder, key, manifest):
    """Reconstruct every declared input; verify all outputs and refusal captures."""
    profile = COMPONENTS[key]
    document = decode(owned(folder, "native-corpus.json").read_bytes())
    require(document.get("schema") == "hepta.runtime.shell-native-corpus.v1"
            and document.get("mode") == profile["mode"] and document.get("status") == "PASS"
            and document.get("error") is None,
            "shell native suite is incomplete")
    require(document.get("rust_oracle_executed_by_this_suite") is False,
            "native shell suite cannot substitute for fresh original Rust")
    require(document.get("whole_runtime_replaced") is False
            and document.get("production_shell_execution_qualified") is False
            and document.get("output_tail_unchanged") is True
            and document.get("borrowed_guards_checked") is True,
            "shell native evidence overclaims production scope or drops boundary controls")
    manifest_raw = manifest.read_bytes()
    module = decode(manifest_raw)
    exact(document.get("module"), module, "shell corpus module differs from executed manifest")
    require(document.get("manifest_sha256") == sha(manifest_raw), "shell manifest identity differs")
    require(document.get("manifest_path") == str(manifest)
            and document.get("source_path") == profile["source"], "shell executed source paths differ")
    import hia_native_shell_reference as reference
    source_provenance, _ = reference.original_sources(root, root / "tests/hia_native/shell_oracle")
    exact(document.get("source_provenance"), source_provenance, "shell original source provenance changed")
    source = owned(root, profile["source"]).read_bytes()
    require(document.get("source_sha256") == sha(source)
            and module.get("source_sha256") == sha(source), "shell source changed after execution")
    for field in ("source", "image"):
        raw = owned(manifest.parent, module[field]).read_bytes()
        require(sha(raw) == module[field + "_sha256"], "shell compiled member identity differs")
    files = document.get("files")
    require(type(files) is dict and set(files) == set(CORPUS_FILES), "shell corpus member set differs")
    raw = {name: owned(folder, name).read_bytes() for name in CORPUS_FILES}
    for name, value in raw.items():
        exact(files[name], pin(value), "shell corpus retained bytes differ: " + name)
    rows = [decode(line) for line in raw["cases.jsonl"].splitlines()]
    inputs = iter(packets(raw["input.bin"]))
    outputs = iter(packets(raw["native-output.bin"]))
    owner = case_owner(root)
    categories, count, body_bytes = {}, 0, 0
    for case in owner.iter_cases(profile["mode"], root):
        require(count < len(rows), "shell semantic corpus omitted a source-owned case")
        wire, result = next(inputs, None), next(outputs, None)
        require(wire == case["input"] and result is not None, "shell semantic stream is partial or reordered")
        expected = {"id": case["id"], "category": case["category"], "input_bytes": len(wire),
                    "input_sha256": sha(wire), "native_return": len(result),
                    "output_bytes": len(result), "output_sha256": sha(result),
                    "output_capacity": max(1024, 9 * len(wire) + 128) if profile["mode"] == "terminal"
                                       else max(2048, 16 * len(wire) + 128),
                    "workspace_capacity": max(128, 9 * len(wire) + 128) if profile["mode"] == "terminal"
                                          else max(256, 32 * len(wire) + 128),
                    "literal_expected_checked": case["known_expected"] is not None}
        exact(rows[count], expected, "shell semantic row does not bind its complete byte streams")
        if case["known_expected"] is not None:
            require(result == case["known_expected"], "shell original literal expectation differs")
        require(len(result) < 0xFFFFFFFE, "native refusal was presented as original shell semantics")
        count += 1
        body_bytes += len(result)
        categories[case["category"]] = categories.get(case["category"], 0) + 1
    require(count > 0 and count == len(rows) and next(inputs, None) is None and next(outputs, None) is None,
            "shell semantic corpus has missing or extra records")
    exact(document.get("semantic_case_count"), count, "shell semantic count differs")
    exact(document.get("categories"), categories, "shell semantic categories differ")
    controls = [decode(line) for line in raw["transport-controls.jsonl"].splitlines()]
    exact(document.get("transport_control_count"), len(controls), "shell refusal count differs")
    require(bool(controls), "shell native refusal evidence is missing")
    # The corpus owner reconstructs the input and capacities; this reader checks
    # actual entire output captures, including bytes beyond a returned prefix.
    validate_controls(owner, profile["mode"], controls)
    return {"schema": "hepta.runtime.shell-component-evidence.v1", "status": "PASS",
            "mode": profile["mode"], "semantic_cases": count, "semantic_body_bytes": body_bytes,
            "transport_controls": len(controls), "categories": categories,
            "source_sha256": sha(source), "manifest_sha256": sha(manifest_raw),
            "image_sha256": module["image_sha256"], "module": module,
            "corpus_metadata_sha256": sha(owned(folder, "native-corpus.json").read_bytes()),
            "files": files, "fresh_original_rust_compared": False,
            "whole_runtime_replaced": False, "production_shell_execution_qualified": False}


def validate_controls(owner, mode, controls):
    specs = list(owner.control_specs(mode))
    require(len(specs) == len(controls), "shell refusal case set is incomplete")
    for spec, row in zip(specs, controls):
        out_cap, work_cap = spec["output_capacity"], spec["workspace_capacity"]
        require(type(row) is dict, "shell refusal capture is not an object")
        expected = {"id": spec["id"], "category": "transport_refusal", "input_hex": spec["input"].hex(),
                    "output_capacity": out_cap, "workspace_capacity": work_cap,
                    "output_before_hex": (b"\xa7" * out_cap).hex(),
                    "output_after_hex": (b"\xa7" * out_cap).hex(),
                    "workspace_before_hex": (b"\x5c" * work_cap).hex(),
                    "workspace_after_hex": row.get("workspace_after_hex"),
                    "native_return": spec["expected_code"], "expected_code": spec["expected_code"],
                    "borrowed_guards_checked": True}
        exact(row, expected, "shell refusal captures or expected source-owned request differ")
        require(type(row["workspace_after_hex"]) is str
                and len(row["workspace_after_hex"]) == work_cap * 2,
                "shell refusal workspace capture is incomplete")
        require(bytes.fromhex(row["workspace_after_hex"]).hex() == row["workspace_after_hex"],
                "shell refusal workspace bytes are not canonical")


def check_process(root, report, row, name, *, original=False):
    schemas = {"hepta.runtime.hia-native-qualification.v1": ("native_components", "original_rust_comparison"),
               "hepta.runtime.shell-focused-qualification.v1": ("shell_native_suites", "shell_original_rust")}
    require(report.get("schema") in schemas, "shell qualification report schema is unknown")
    require(row.get("name") == name and row.get("phase") == schemas[report["schema"]][int(original)]
            and type(row.get("exit_code")) is int and row["exit_code"] == 0
            and row.get("timed_out") is False and not row.get("start_error"),
            "shell process scope or completion differs")
    exact(row.get("timeout_seconds"), 180, "shell process deadline differs")
    elapsed = row.get("elapsed_seconds")
    require(type(elapsed) in (int, float) and math.isfinite(elapsed) and 0 <= elapsed <= 183,
            "shell process elapsed duration is invalid")
    if not original:
        exact(row.get("command"), [sys.executable, "-I", "-B", str(root / "tests/hia_native" / name)],
              "shell native process command differs from its source-owned suite")


def qualification_evidence(root, output, report, completed):
    result = {"schema": "hepta.runtime.shell-native-evidence.v1", "status": "PASS",
              "components": {}, "artifact_sha256": {}, "whole_runtime_replaced": False,
              "production_shell_execution_qualified": False}
    for key, profile in COMPONENTS.items():
        built = report["modules"][key]
        manifest = owned(output, built["manifest"])
        require(sha(manifest.read_bytes()) == built["sha256"], "shell build manifest identity changed")
        folder = output / profile["folder"]
        evidence = read_corpus(root, folder, key, manifest)
        check, summary = completed(output, report, profile["test"])
        check_process(root, report, check, profile["test"])
        metadata = decode(owned(folder, "native-corpus.json").read_bytes())
        exact(summary, {"mode": profile["mode"], "status": "PASS", "semantic_cases": evidence["semantic_cases"],
                        "transport_controls": evidence["transport_controls"],
                        "report": str(folder / "native-corpus.json"),
                        "rust_oracle_executed_by_this_suite": False, "error": None},
              "shell test stdout differs from complete corpus metadata")
        result["components"][key] = evidence
        for name in (*CORPUS_FILES, "native-corpus.json"):
            relative = profile["folder"] + "/" + name
            result["artifact_sha256"][relative] = sha(owned(output, relative).read_bytes())
    check, controls = completed(output, report, "test_shell_evidence.py")
    check_process(root, report, check, "test_shell_evidence.py")
    require(controls.get("schema") == "hepta.runtime.shell-evidence-controls.v1"
            and controls.get("status") == "PASS" and type(controls.get("refusals")) is int
            and controls["refusals"] == 2 * len(EVIDENCE_REFUSALS)
            and type(controls.get("native_semantic_calls_added")) is int
            and controls["native_semantic_calls_added"] == 0,
            "shell evidence corruption controls are missing")
    exact(controls.get("cases"), {key: list(EVIDENCE_REFUSALS) for key in COMPONENTS},
          "shell evidence refusal domain differs")
    result["evidence_controls"] = controls
    return result


def reference_command(root, output, key, rustc, cargo):
    profile = COMPONENTS[key]
    return [sys.executable, "-I", "-B", str(root / "scripts/hia_native_shell_reference.py"),
            "--runtime", str(root), "--output", str(output / (profile["folder"] + "-original")),
            "--rustc", str(rustc), "--cargo", str(cargo),
            "--corpus", str(output / profile["folder"]), "--mode", profile["mode"]]


def original_evidence(root, output, report, key, rustc, cargo, completed):
    """Check actual build/test/replay streams, not just a success declaration."""
    import hia_native_shell_reference as reference
    profile = COMPONENTS[key]
    folder = output / (profile["folder"] + "-original")
    name = profile["folder"] + "-rust-compare"
    check, summary = completed(output, report, name)
    check_process(root, report, check, name, original=True)
    exact(check.get("command"), reference_command(root, output, key, rustc, cargo),
          "shell original invocation differs from the declared recipe")
    exact(check.get("timeout_seconds"), 180, "shell original process deadline changed")
    value = decode(owned(folder, "result.json").read_bytes())
    require(value.get("schema") == "hepta.runtime.shell-original-replay.v1"
            and value.get("status") == "PASS" and value.get("mode") == profile["mode"]
            and value.get("error") is None
            and value.get("whole_runtime_replaced") is False
            and value.get("production_shell_execution_qualified") is False,
            "shell original replay is incomplete or overclaims its scope")
    provenance, extracted = reference.original_sources(root, root / "tests/hia_native/shell_oracle")
    provenance["test_transport_sources"] = {
        relative: pin(owned(root, "tests/hia_native/shell_oracle/" + relative).read_bytes())
        for relative in ("Cargo.toml", "Cargo.lock", "src/main.rs")}
    exact(value.get("source_provenance"), provenance, "shell original source closure differs")
    exact(decode(owned(folder, "crate/source-receipt.json").read_bytes()), provenance,
          "shell original materialized source receipt changed")
    tools = {}
    for tool, path in (("rustc", rustc), ("cargo", cargo)):
        resolved = Path(path).resolve(strict=True)
        tools[tool] = {"launch_path": str(path), "resolved_path": str(resolved), **pin(resolved.read_bytes())}
    exact(value.get("build_tools"), tools, "shell original selected build executables changed")
    removed = value.get("removed_build_environment_names")
    require(type(removed) is list and all(type(name) is str for name in removed)
            and removed == sorted(set(removed)), "shell original build environment receipt is malformed")
    for relative, expected in provenance["test_transport_sources"].items():
        exact(pin(owned(folder, "crate/" + relative).read_bytes()), expected, "shell original crate changed")
    for relative, raw in extracted.items():
        require(owned(folder, "crate/fixtures/" + relative).read_bytes() == raw,
                "shell original extracted functions or tests changed")
    crate = folder / "crate"
    executable = folder / "target/release/hepta-shell-original-oracle"
    commands = [
        ("rustc-version", [str(rustc), "--version", "--verbose"], 30),
        ("build", [str(cargo), "build", "--manifest-path", str(crate / "Cargo.toml"), "--locked", "--release"], 180),
        ("original-tests", [str(cargo), "test", "--manifest-path", str(crate / "Cargo.toml"), "--locked", "--release",
                            "--", "--nocapture", "--test-threads=1"], 120),
        ("replay", [str(executable), profile["mode"]], 120),
    ]
    require(type(value.get("processes")) is list and len(value["processes"]) == len(commands),
            "shell original process list is incomplete")
    artifacts = {}
    for row, (label, command, timeout) in zip(value["processes"], commands):
        require(row.get("passed") is True and type(row.get("exit_code")) is int and row["exit_code"] == 0
                and row.get("error") is None, "shell original subprocess failed")
        exact(row.get("command"), command, "shell original subprocess command changed")
        exact(row.get("timeout_seconds"), timeout, "shell original subprocess deadline changed")
        exact(row.get("cwd"), str(crate), "shell original subprocess working directory changed")
        elapsed = row.get("duration_seconds")
        require(type(elapsed) in (int, float) and math.isfinite(elapsed) and 0 <= elapsed <= timeout + 3,
                "shell original subprocess duration is invalid")
        exact(decode(owned(folder, label + ".execution.json").read_bytes()), row,
              "shell original process receipt differs")
        for suffix in ("stdout", "stderr"):
            relative = label + "." + suffix
            raw = owned(folder, relative).read_bytes()
            exact(row.get(suffix), {"path": relative, **pin(raw)}, "shell original process stream differs")
            artifacts[relative] = sha(raw)
    tests = owned(folder, "original-tests.stdout").read_text()
    version = owned(folder, "rustc-version.stdout").read_text()
    require(version.startswith("rustc 1.95.0 ") or version.startswith("rustc 1.95.0\n"),
            "shell original Rust version differs from the declared fixed reference")
    exact(value.get("rustc_version"), version, "shell original compiler version receipt changed")
    require(all("test original::tests::" + name + " ... ok" in tests
                for name in provenance["original_test_names"])
            and "9 passed; 0 failed; 0 ignored" in tests, "shell original tests were not all executed")
    exact(value.get("original_test_count"), 9, "shell original pure test count changed")
    exact(value.get("executable"), {"path": str(executable), **pin(executable.read_bytes())},
          "shell original executable bytes changed")
    native = read_corpus(root, output / profile["folder"], key,
                         owned(output, report["modules"][key]["manifest"]))
    require(owned(folder, "independent-input.bin").read_bytes()
            == owned(output, profile["folder"] + "/input.bin").read_bytes(),
            "shell original input differs from complete source-owned native inputs")
    exact(value.get("input_verification"), {
        "mode": profile["mode"], "semantic_cases": native["semantic_cases"],
        "categories": native["categories"], "all_input_bytes_regenerated_and_equal": True,
        "independent_input": {"path": "independent-input.bin", **pin(owned(folder, "independent-input.bin").read_bytes())},
        "native_corpus_members": native["files"], "native_transport_controls_excluded": native["transport_controls"]},
        "shell original complete input verification receipt differs")
    rows = [decode(line) for line in owned(output, profile["folder"] + "/cases.jsonl").read_bytes().splitlines()]
    comparison = reference.compare_outputs(owned(folder, "replay.stdout"),
                    owned(output, profile["folder"] + "/native-output.bin"), rows)
    exact(value.get("comparison"), comparison, "shell full original byte comparison changed")
    expected_summary = {"status": "PASS", "mode": profile["mode"], "report": str(folder / "result.json"),
                        "processes": 4, "original_test_count": 9, "comparison": comparison, "error": None}
    exact(summary, expected_summary, "shell original outer stdout differs")
    return {"status": "PASS", "mode": profile["mode"], "original_tests": 9,
            "actual_reference_subprocesses": 4, "semantic_cases": native["semantic_cases"],
            "comparison": comparison, "source_provenance": provenance,
            "executable": value["executable"], "process_stream_sha256": artifacts,
            "result_sha256": sha(owned(folder, "result.json").read_bytes()),
            "native_cases_added_by_replay": 0, "production_shell_execution_qualified": False}


def compare_original(root, output, report, key, rustc, cargo, completed, record_check, environment):
    before = read_corpus(root, output / COMPONENTS[key]["folder"], key,
                         owned(output, report["modules"][key]["manifest"]))
    record_check(output, report, name=COMPONENTS[key]["folder"] + "-rust-compare",
                 command=reference_command(root, output, key, rustc, cargo), timeout=180, env=environment())
    result = original_evidence(root, output, report, key, rustc, cargo, completed)
    exact(read_corpus(root, output / COMPONENTS[key]["folder"], key,
          owned(output, report["modules"][key]["manifest"])), before,
          "shell native evidence changed during fresh original replay")
    return result
