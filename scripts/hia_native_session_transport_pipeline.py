# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Bind the four finite session graphs to actual aggregate processes."""
from pathlib import Path
import sys

from hia_native_session_transport_build import read, sha, object_at, require
import hia_native_session_transport_admission as admission
import hia_native_session_transport_capture as capture
import hia_native_session_transport_server as server

TESTS = ("test_session_transport_owned.py", "test_session_transport_server.py",
         "test_session_transport_receipts.py")
NATIVE = "session-transport-native"
SERVER = "session-transport-server"
CONTROLS = "session-transport-compiler-controls"
ORIGINAL = "session-transport-original"
PRIMARY = "native/session_transport/server_message_owner.hepta"
SCRIPTS = (
    "hia_native_session_transport_build.py", "hia_native_session_transport_admission.py",
    "hia_native_session_transport_capture.py", "hia_native_session_transport_server.py",
    "hia_native_session_transport_controls.py", "hia_native_session_transport_pipeline.py",
    "hia_native_session_transport_reference.py",
)


def sources(root):
    root = Path(root)
    names = {"scripts/" + name for name in SCRIPTS}
    names.update(p.relative_to(root).as_posix()
                 for p in (root / "scripts/session_transport").rglob("*") if p.is_file())
    names.update(p.relative_to(root).as_posix()
                 for p in (root / "tests/hia_native/session_transport").rglob("*")
                 if p.is_file() and "__pycache__" not in p.parts and p.suffix != ".pyc")
    return tuple(sorted(names))


def paths(root, output, report):
    root, output = Path(root), Path(output)
    item = report["modules"]["session_transport"]
    manifest = output / item["manifest"]
    require(sha(read(manifest)) == item["sha256"] and item["source"] == PRIMARY
            and item["builder"] == "session_transport", "registered session graph differs")
    return root, output, manifest


def test_commands(root, output, report):
    root, output, manifest = paths(root, output, report)
    common = ["--root", str(root), "--manifest", str(manifest)]
    return {
        TESTS[0]: [sys.executable, "-I", "-B", str(root / "scripts" / SCRIPTS[2]),
                   "run", *common, "--output", str(output / NATIVE)],
        TESTS[1]: [sys.executable, "-I", "-B", str(root / "scripts" / SCRIPTS[3]),
                   "run", *common, "--output", str(output / SERVER)],
        TESTS[2]: [sys.executable, "-I", "-B", str(root / "scripts" / SCRIPTS[4]),
                   *common, "--output", str(output / CONTROLS)],
    }


def complete(output, report, name, command, completed):
    row, summary = completed(output, report, name)
    require(row["command"] == command and row["timeout_seconds"] == 180
            and row["exit_code"] == 0 and row["timed_out"] is False
            and not row.get("start_error") and 0 <= row["elapsed_seconds"] <= 180,
            "actual session transport aggregate process differs")
    require(read(Path(output) / (name + ".stderr")) == b"",
            "actual session transport process emitted stderr")
    return row, summary


def keep(output, items):
    output = Path(output).absolute()
    result = {}
    for path in items:
        path = Path(path).absolute()
        require(path.is_relative_to(output), "session evidence escapes the aggregate")
        result[path.relative_to(output).as_posix()] = sha(read(path))
    return result


def native_evidence(root, output, report, completed):
    root, output, manifest = paths(root, output, report)
    current = admission.verify_build(manifest, root)
    owned = capture.verify(output / NATIVE, manifest, root)
    factory = server.verify(output / SERVER, manifest, root)
    control = object_at(output / CONTROLS / "result.json")
    compiled = object_at(manifest)
    source, selected = sorted(compiled["semantic_modules"].items())[0]
    module = manifest.parent.parent / selected["manifest"]
    compiler = object_at(module.parent / "module.stdout.log")
    mutations = [("remove-stdout-" + name, "remove", name, None) for name in sorted(compiler)]
    mutations.extend([
        ("coordinated-source-digest", "set", "source_sha256", "0" * 64),
        ("unexpected-stdout-field", "set", "invented_workspace_hash", "0" * 64),
        ("loader-action", "set", "loader_operations", "copy; fixed ABI call"),
        ("output-unchanged", "set", "output_unchanged", True),
        ("negative-native-time", "set", "native_elapsed_ns", -1),
        ("boolean-native-time", "set", "native_elapsed_ns", False),
        ("source-header-length", "header", "0", compiler["workspace_header"]["0"] + 1),
        ("image-header-length", "header", "56", compiler["workspace_header"]["56"] + 1),
        ("missing-header-word", "header-remove", "248", None),
        ("extra-header-word", "header", "32", 0),
        ("boolean-header-word", "header", "8", False),
        ("negative-wall-time", "receipt", "wall_elapsed_ns", -1),
    ])
    require(control["schema"] == "hepta.runtime.session-compiler-controls.v1"
            and control["status"] == "PASS"
            and control["build_manifest_sha256"] == current["manifest_sha256"]
            and control["rejections"] == control["complete_restores"] == 27
            and len(control["controls"]) == 27
            and control["module_manifest_sha256"] == sha(read(module))
            and control["source_sha256"] == sha(read(root / source))
            and [(row["name"], row["action"], row["field"], row["value"])
                 for row in control["controls"]] == mutations
            and all(row["rejected"] is row["complete_restore"] is True
                    and isinstance(row["error"], str) and row["error"]
                    for row in control["controls"])
            and control["actual_compilations"] == control["actual_native_executions"] ==
                control["actual_original_executions"] == 0,
            "compiler damage controls are incomplete")
    expected = {
        TESTS[0]: {"status": "PASS", "actual_native_processes": 6,
                   "actual_original_processes": 0, "actual_programs": 504,
                   "domains": owned, "whole_runtime_replaced": False},
        TESTS[1]: {"status": "PASS", "actual_native_processes": 2,
                   "actual_original_processes": 0, "evidence": factory,
                   "whole_runtime_replaced": False},
        TESTS[2]: {"status": "PASS", "rejections": 27, "complete_restores": 27,
                   "actual_compilations": 0, "actual_native_executions": 0,
                   "actual_original_executions": 0},
    }
    receipts = {}
    for name, command in test_commands(root, output, report).items():
        row, summary = complete(output, report, name, command, completed)
        require(summary == expected[name], "complete session process stdout differs")
        receipts[name] = row
    build = manifest.parent.parent
    artifacts = [path for path in manifest.parent.rglob("*") if path.is_file()]
    artifacts.extend(path for path in (build / "bootstrap").rglob("*") if path.is_file())
    compiled = object_at(manifest)
    for row in (*compiled["semantic_modules"].values(), *compiled["packers"].values()):
        artifacts.extend(path for path in (build / row["manifest"]).parent.rglob("*") if path.is_file())
    artifacts.extend(output / (name + suffix) for name in TESTS for suffix in (".stdout", ".stderr"))
    corpus = [p for name in (NATIVE, SERVER, CONTROLS)
              for p in (output / name).rglob("*") if p.is_file()]
    return {"schema": "hepta.runtime.session-transport-pipeline-native.v1", "status": "PASS",
            "semantic_images": 38, "packer_images": 18, "actual_hia_pack_calls": 18,
            "actual_native_processes": 8, "owned_programs": 1120,
            "server_projection_requests": 180, "three_domain_evidence": owned,
            "server_factory_evidence": factory, "compiler_controls": control,
            "completed_processes": receipts,
            "artifact_sha256": keep(output, artifacts), "corpus_sha256": keep(output, corpus),
            "native_cases_added_by_admission": 0, "original_cases_added_by_admission": 0,
            "whole_runtime_replaced": False, "production_activated": False}


def original_commands(root, output, report, rustc):
    root, output, manifest = paths(root, output, report)
    common = [sys.executable, "-I", "-B", str(root / "scripts" / SCRIPTS[6]),
              "--root", str(root), "--manifest", str(manifest),
              "--native-output", str(output / NATIVE), "--server-output", str(output / SERVER),
              "--output", str(output / ORIGINAL)]
    return {"session-transport-rust-build": common + ["build", "--rust-bin", str(Path(rustc).absolute().parent)],
            "session-transport-rust-replay": common + ["replay"]}


def original_evidence(root, output, report, completed):
    import hia_native_session_transport_reference as reference
    root, output, manifest = paths(root, output, report)
    evidence = reference.verify(root, manifest, output / NATIVE, output / SERVER, output / ORIGINAL)
    commands = original_commands(root, output, report, Path(report["rust_compiler"]["invocation_path"]))
    receipts = {}
    for name, command in commands.items():
        row, summary = complete(output, report, name, command, completed)
        wanted = object_at(output / ORIGINAL / ("build-summary.json" if name.endswith("build") else "replay-summary.json"))
        require(summary == wanted, "complete original session process stdout differs")
        receipts[name] = row
    artifacts = [output / ORIGINAL / name for name in evidence["artifact_sha256"]]
    artifacts.extend(output / (name + suffix) for name in commands for suffix in (".stdout", ".stderr"))
    return {"schema": "hepta.runtime.session-transport-pipeline-original.v1", "status": "PASS",
            "owner_evidence": evidence, "completed_processes": receipts,
            "artifact_sha256": keep(output, artifacts),
            "native_cases_added_by_admission": 0, "original_cases_added_by_admission": 0,
            "whole_runtime_replaced": False, "production_activated": False}
