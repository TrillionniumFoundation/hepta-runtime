# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Portable physical execution and complete retained-flow verification.

Frozen child fixtures and physical Machines are imported byte-for-byte. Only
resource paths and the new, explicitly labelled callable build view are supplied
by this driver. The three frame verifiers retain every semantic assertion; their
historical admission preambles are replaced by admission of this actual build
and these actual captured child processes.
"""
from __future__ import annotations
import argparse
import ast
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import time
import types

sys.path.insert(0, str(Path(__file__).resolve().parent))
from hia_native_session_transport_build import read, sha, object_at, require, relative, source_pins
from hia_native_session_transport_admission import verify_build, inventory

DOMAIN = {
    "worker_owners": {
        "fixture": "qualify_worker_transport_owners_native_v2.py",
        "machine": "worker_transport_owners_machine_v2.py",
        "frames": "worker_owners_frames_v1.py",
        "cases": "worker-owner-cases-v1.json", "count": 72,
        "elf": "hia-worker-transport-owners-callable.elf",
        "status": "PASS_FINITE_NATIVE_WORKER_OWNERS",
    },
    "handle_initialize": {
        "fixture": "qualify_session_handle_initialize_native_v1.py",
        "machine": "session_message_machine_v1.py",
        "frames": "handle_initialize_frames_v1.py",
        "cases": "session-handle-initialize-cases-v1.json", "count": 40,
        "elf": "hia-session-message-callable.elf",
        "status": "PASS_FINITE_NATIVE_HANDLE_INITIALIZE",
    },
    "local_worker_error": {
        "fixture": "qualify_local_worker_error_native_v2.py",
        "machine": "local_worker_error_machine_v1.py",
        "frames": "local_worker_error_frames_v3.py",
        "cases": "local-worker-error-cases-v1.json", "count": 140,
        "elf": "hia-local-worker-error-callable.elf",
        "status": "PASS_FINITE_NATIVE_LOCAL_WORKER_ERROR_OWNERS",
    },
}
HERE = Path(__file__).resolve().parents[1]
SOURCES = (
    "scripts/hia_native_session_transport_build.py",
    "scripts/hia_native_session_transport_admission.py",
    "scripts/hia_native_session_transport_capture.py",
    "scripts/hia_native_build.py", "scripts/hia_native_loader.py",
)
ORIGIN = "tests/hia_native/session_transport/origin"
INDEX = "tests/hia_native/session_transport/origin.json"
J = lambda value: (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=False) + "\n").encode()


def save(path, raw, mode=0o600):
    path = Path(path)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, "wb") as handle:
        handle.write(raw)
        handle.flush()
        os.fsync(handle.fileno())


def source_snapshot(root):
    root = Path(root)
    index = object_at(root / INDEX)
    paths = set(SOURCES) | {INDEX}
    for name, want in index.items():
        require("/" not in name and name not in ("", ".", ".."), "invalid frozen helper name")
        path = root / ORIGIN / name
        raw = read(path)
        require(len(raw) == want["bytes"] and sha(raw) == want["sha256"],
                "frozen fixture source changed: " + name)
        paths.add((Path(ORIGIN) / name).as_posix())
    return {name: {"sha256": sha(read(root / name)), "bytes": len(read(root / name))}
            for name in sorted(paths)}


def frozen(root, name, module_name):
    path = Path(root) / ORIGIN / name
    row = object_at(Path(root) / INDEX)[name]
    require(len(read(path)) == row["bytes"] and sha(read(path)) == row["sha256"],
            "frozen helper differs")
    spec = importlib.util.spec_from_file_location(module_name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def new_build_view(build_proof, key, path):
    """This is a new ABI view, not a copy of any historical build receipt."""
    item = build_proof["graphs"][key]
    path.mkdir(mode=0o700)
    artifact = read(item["artifact"])
    save(path / DOMAIN[key]["elf"], artifact, 0o500)
    view = {
        "schema": "hepta.runtime.session-transport-callable-view.v1",
        "status": "BUILT_NOT_SEMANTICALLY_QUALIFIED",
        "source_build_manifest_sha256": build_proof["manifest_sha256"],
        "graph": key, "exports": item["exports"],
        "artifact": {"bytes": len(artifact), "sha256": sha(artifact)},
        "new_compilation": False, "new_semantic_execution": False,
        "historical_build_receipt": False,
    }
    save(path / "result.json", J(view))
    return sha(J(view))


def child(root, key, mode, output, view_sha, sources_sha):
    root, output = Path(root), Path(output)
    spec = DOMAIN[key]
    snapshot = source_snapshot(root)
    require(sha(J(snapshot)) == sources_sha, "child fixture source closure differs")
    view = output / "callable"
    require(sha(read(view / "result.json")) == view_sha, "child callable view differs")
    fixture = frozen(root, spec["fixture"], "session_fixture_" + key)
    load_original = fixture.module
    expected_machine = (root / ORIGIN / spec["machine"]).resolve()
    adaptations = []
    def local_module(path, digest, name):
        result = load_original(path, digest, name)
        if Path(path).resolve() == expected_machine:
            require(digest == object_at(root / INDEX)[spec["machine"]]["sha256"],
                    "fixture asked for another Machine source")
            result.BUILD = view
            adaptations.append({"module": spec["machine"], "binding": "BUILD",
                                "value": str(view), "source_sha256": digest})
        return result
    fixture.D = root / ORIGIN
    fixture.OUT = output
    fixture.BUILD_SHA = view_sha
    fixture.module = local_module
    try:
        fixture.child(mode)
    finally:
        require(source_snapshot(root) == snapshot, "child sources changed")
        require(len(adaptations) == 1, "the physical Machine was not loaded exactly once")
        save(output / ("mode-" + str(mode)) / "portable-invocation.json", J({
            "schema": "hepta.runtime.session-transport-child.v1",
            "pid": os.getpid(), "pgid": os.getpgrp(), "mode": mode, "domain": key,
            "argv": sys.argv, "source_sha256": snapshot, "callable_view_sha256": view_sha,
            "adaptations": adaptations,
            "physical_child_function_unchanged": True,
            "physical_machine_functions_unchanged": True,
        }))


def frames(root, key):
    """Replace only the old external admission preamble, with a full AST inverse."""
    spec = DOMAIN[key]
    path = Path(root) / ORIGIN / spec["frames"]
    raw = read(path)
    want = object_at(Path(root) / INDEX)[spec["frames"]]
    require(sha(raw) == want["sha256"] and len(raw) == want["bytes"], "frozen verifier changed")
    source = raw.decode()
    tree = ast.parse(source)
    function = next(x for x in tree.body if isinstance(x, ast.FunctionDef) and x.name == "native_captures")
    marker = next(i for i, node in enumerate(function.body)
                  if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "canonical"
                                                        for t in node.targets))
    prefix = function.body[:marker]
    preserved = []
    if key == "local_worker_error":
        preserved = [node for node in prefix if isinstance(node, ast.Assign)
                     and any(isinstance(t, ast.Name) and t.id in ("corpus", "decoder")
                             for t in node.targets)]
        require(len(preserved) == 2, "local error decoder/corpus binding changed")
    replacement = ast.parse("pin = base.pin\nroot, result, build = base.admit_domain(cases)\n").body
    function.body = replacement + preserved + function.body[marker:]
    adapted = ast.fix_missing_locations(tree)
    transformed = ast.unparse(adapted) + "\n"
    restored = ast.parse(transformed)
    restored_function = next(x for x in restored.body
                             if isinstance(x, ast.FunctionDef) and x.name == "native_captures")
    restored_function.body = prefix + restored_function.body[len(replacement) + len(preserved):]
    require(ast.dump(restored, include_attributes=False) == ast.dump(ast.parse(source), include_attributes=False),
            "frame verifier transport derivation does not invert")
    module = types.ModuleType("portable_session_frames_" + key)
    module.__file__ = str(path)
    exec(compile(transformed, str(path) + ":portable-admission", "exec"), module.__dict__)
    module.D = Path(root) / ORIGIN
    derivation = {
        "source_sha256": sha(raw), "generated_sha256": sha(transformed.encode()),
        "whole_module_ast_inverse": True,
        "removed_admission_nodes": len(prefix), "retained_decoder_nodes": len(preserved),
        "semantic_verifier_body_unchanged": True,
        "original_capture_function_unchanged": True,
    }
    return module, derivation


class Captures:
    def __init__(self, root, output, key, proof, top):
        self.root, self.output, self.key = Path(root), Path(output), key
        self.proof, self.top = proof, top

    @staticmethod
    def pin(path, digest=None):
        raw = read(path)
        if digest is not None:
            require(sha(raw) == digest, "capture hash differs: " + str(path))
        return raw

    def module(self, path, digest, name):
        path = Path(path)
        require(path.parent == self.root / ORIGIN, "unexpected frozen decoder path")
        require(sha(read(path)) == digest, "decoder source differs")
        return frozen(self.root, path.name, name)

    def admit_domain(self, cases):
        key = self.key
        domain = self.output / key
        result = object_at(domain / "result.json")
        spec = DOMAIN[key]
        require(result["schema"] == "hepta.runtime.session-transport-domain.v1"
                and result["domain"] == key and result["status"] == spec["status"]
                and result["actual_native_processes"] == 2
                and result["actual_original_executions"] == 0,
                "domain process status/accounting differs")
        require(result["source_sha256"] == self.top["source_sha256"]
                and result["source_build_manifest_sha256"] == self.proof["manifest_sha256"],
                "domain source/build binding differs")
        require(object_at(domain / "cases.json") == cases and len(cases) == spec["count"],
                "complete domain corpus differs")
        require(read(domain / "cases.json") == read(self.root / ORIGIN / spec["cases"]),
                "actual corpus bytes differ")
        view = object_at(domain / "callable" / "result.json")
        g = self.proof["graphs"][key]
        require(view == {
            "schema": "hepta.runtime.session-transport-callable-view.v1",
            "status": "BUILT_NOT_SEMANTICALLY_QUALIFIED",
            "source_build_manifest_sha256": self.proof["manifest_sha256"],
            "graph": key, "exports": g["exports"],
            "artifact": {"bytes": g["bytes"], "sha256": g["sha256"]},
            "new_compilation": False, "new_semantic_execution": False,
            "historical_build_receipt": False}, "callable view differs")
        require(read(domain / "callable" / spec["elf"]) == read(g["artifact"]),
                "executed callable bytes differ from this actual build")
        for mode, process in zip((1, 2), result["processes"], strict=True):
            folder = domain / ("mode-" + str(mode))
            invocation = object_at(folder / "portable-invocation.json")
            expected_command = [self.top["python_at_execution"], "-I", "-B",
                str(Path(self.top["root_at_execution"]) / "scripts/hia_native_session_transport_capture.py"),
                "child", "--root", self.top["root_at_execution"], "--key", key,
                "--mode", str(mode), "--output", str(Path(self.top["output_at_execution"]) / key),
                "--view-sha256", sha(read(domain / "callable/result.json")),
                "--sources-sha256", sha(J(self.top["source_sha256"]))]
            require(process["command"] == expected_command and process["mode"] == mode
                    and process["exit_code"] == 0 and process["timed_out"] is False
                    and process["pid"] > 0 and process["pgid"] == self.top["pgid"]
                    and process["timeout_seconds"] == 60,
                    "actual child process identity/completion differs")
            require(invocation["argv"] == expected_command[3:]
                    and invocation["pid"] == process["pid"] and invocation["pgid"] == process["pgid"]
                    and invocation["mode"] == mode and invocation["domain"] == key
                    and invocation["source_sha256"] == self.top["source_sha256"]
                    and invocation["callable_view_sha256"] == sha(read(domain / "callable/result.json"))
                    and invocation["physical_child_function_unchanged"] is True
                    and invocation["physical_machine_functions_unchanged"] is True,
                    "physical child source/invocation receipt differs")
            require(invocation["adaptations"] == [{
                "module": spec["machine"], "binding": "BUILD",
                "value": str(Path(self.top["output_at_execution"]) / key / "callable"),
                "source_sha256": object_at(self.root / INDEX)[spec["machine"]]["sha256"]}],
                "physical Machine resource adaptation differs")
        return domain, result, view


def verify(output, manifest, root, *, captured=False):
    output, root = Path(output), Path(root)
    top = object_at(output / "result.json")
    require(top["schema"] == "hepta.runtime.session-transport-captures.v1"
            and top["status"] == ("CAPTURED_NOT_QUALIFIED" if captured else "PASS"),
            "capture qualification state differs")
    require(top["actual_native_processes"] == 6 and top["actual_original_processes"] == 0
            and top["actual_cases"] == 504
            and top["full_worker"] is False and top["production_activated"] is False
            and top["whole_runtime_replaced"] is False,
            "capture process counts or finite scope differ")
    require(source_snapshot(root) == top["source_sha256"], "fixture source closure changed")
    proof = verify_build(manifest, root)
    require(proof["manifest_sha256"] == top["source_build_manifest_sha256"],
            "capture used another build")
    known = {p.relative_to(output).as_posix() for p in output.rglob("*") if p.is_file()}
    require(known == set(top["files"]) | {"result.json"},
            "complete capture file inventory differs")
    for name, want in top["files"].items():
        p = relative(output, name)
        raw = read(p)
        require(len(raw) == want["bytes"] and sha(raw) == want["sha256"],
                "complete capture file changed")
        require(stat.S_IMODE(p.stat().st_mode) == want["mode"], "capture mode changed")
    expected_dirs = {p.relative_to(output).as_posix() for p in output.rglob("*") if p.is_dir()}
    require(expected_dirs == set(top["directories"]), "complete capture directory inventory differs")
    summary = {}
    for key, spec in DOMAIN.items():
        cases = object_at(root / ORIGIN / spec["cases"])
        frame_module, derivation = frames(root, key)
        canonical, metrics = frame_module.native_captures(cases, Captures(root, output, key, proof, top))
        require(top["derivations"][key] == derivation, "verifier derivation changed")
        summary[key] = {"programs_per_mode": len(cases), "modes": 2,
                        "canonical_sha256": sha(J(canonical)), "metrics": metrics,
                        "verifier_derivation": derivation}
    require(source_snapshot(root) == top["source_sha256"], "fixture source changed during admission")
    return summary


def run(output, manifest, root):
    output, root = Path(output).absolute(), Path(root).absolute()
    require(not output.exists(), "capture directory is create-only")
    output.mkdir(parents=True, mode=0o700)
    snapshot = source_snapshot(root)
    proof = verify_build(manifest, root)
    top = {
        "schema": "hepta.runtime.session-transport-captures.v1", "status": "RUNNING",
        "pid": os.getpid(), "pgid": os.getpgrp(), "root_at_execution": str(root),
        "output_at_execution": str(output), "python_at_execution": sys.executable,
        "source_sha256": snapshot, "source_build_manifest_sha256": proof["manifest_sha256"],
        "actual_native_processes": 0, "actual_original_processes": 0, "actual_cases": 0,
        "derivations": {}, "full_worker": False, "production_activated": False,
        "whole_runtime_replaced": False,
    }
    begun = time.monotonic()
    try:
        for key, spec in DOMAIN.items():
            domain = output / key
            domain.mkdir(mode=0o700)
            save(domain / "cases.json", read(root / ORIGIN / spec["cases"]))
            view_sha = new_build_view(proof, key, domain / "callable")
            _, derivation = frames(root, key)
            top["derivations"][key] = derivation
            result = {"schema": "hepta.runtime.session-transport-domain.v1", "domain": key,
                      "status": "RUNNING", "qualification_status": "CAPTURED_NOT_QUALIFIED",
                      "actual_native_processes": 0, "actual_original_executions": 0,
                      "source_sha256": snapshot,
                      "source_build_manifest_sha256": proof["manifest_sha256"], "processes": []}
            try:
                for mode in (1, 2):
                    command = [sys.executable, "-I", "-B", str(Path(__file__).resolve()),
                               "child", "--root", str(root), "--key", key, "--mode", str(mode),
                               "--output", str(domain), "--view-sha256", view_sha,
                               "--sources-sha256", sha(J(snapshot))]
                    started = time.monotonic()
                    timed = False
                    with (domain / ("mode-" + str(mode) + ".stdout")).open("xb") as stdout, \
                         (domain / ("mode-" + str(mode) + ".stderr")).open("xb") as stderr:
                        process = subprocess.Popen(command, stdin=subprocess.DEVNULL,
                            stdout=stdout, stderr=stderr, cwd=domain,
                            env={"PATH": "", "LANG": "C"})
                        top["actual_native_processes"] += 1
                        result["actual_native_processes"] += 1
                        pgid = os.getpgid(process.pid)
                        try:
                            process.wait(timeout=60)
                        except subprocess.TimeoutExpired:
                            timed = True
                            process.kill()
                            process.wait(timeout=10)
                    out = read(domain / ("mode-" + str(mode) + ".stdout"))
                    err = read(domain / ("mode-" + str(mode) + ".stderr"))
                    observed = {
                        "mode": mode, "pid": process.pid, "pgid": pgid, "command": command,
                        "exit_code": process.returncode, "timed_out": timed, "timeout_seconds": 60,
                        "elapsed_seconds": time.monotonic() - started,
                        "stdout_bytes": len(out), "stdout_sha256": sha(out),
                        "stderr_bytes": len(err), "stderr_sha256": sha(err),
                    }
                    result["processes"].append(observed)
                    require(process.returncode == 0 and not timed and not err,
                            "actual native child failed: " + repr(observed))
                    child_result = object_at(domain / ("mode-" + str(mode)) / "result.json")
                    require(json.loads(out) == child_result and child_result["pid"] == process.pid
                            and child_result["status"] == spec["status"]
                            and child_result["actual_cases"] == spec["count"],
                            "actual native child stdout/result differs")
                    top["actual_cases"] += child_result["actual_cases"]
                result["status"] = spec["status"]
            except BaseException as error:
                result.update(status="FAIL", error=repr(error))
                raise
            finally:
                save(domain / "result.json", J(result))
        require(source_snapshot(root) == snapshot, "fixture sources changed")
        top["status"] = "CAPTURED_NOT_QUALIFIED"
        top["files"] = inventory(output)
        top["directories"] = sorted(p.relative_to(output).as_posix()
                                    for p in output.rglob("*") if p.is_dir())
        save(output / "result.json", J(top))
        summary = verify(output, manifest, root, captured=True)
        top.update(status="PASS", evidence=summary, elapsed_seconds=time.monotonic() - begun)
        # This file belongs only to this invocation. Failed validation never
        # leaves a PASS result or a successful process exit.
        (output / "result.json").write_bytes(J(top))
        print(json.dumps({"status": "PASS", "actual_native_processes": 6,
                          "actual_programs": 504, "actual_original_processes": 0,
                          "domains": summary, "whole_runtime_replaced": False}, sort_keys=True))
        return top
    except BaseException as error:
        top.update(status="FAIL", error=repr(error), elapsed_seconds=time.monotonic() - begun)
        (output / "result.json").write_bytes(J(top))
        raise


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("run", "verify", "child"))
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--key", choices=tuple(DOMAIN))
    parser.add_argument("--mode", type=int)
    parser.add_argument("--view-sha256")
    parser.add_argument("--sources-sha256")
    args = parser.parse_args()
    if args.action == "child":
        child(args.root, args.key, args.mode, args.output, args.view_sha256, args.sources_sha256)
    elif args.action == "run":
        run(args.output, args.manifest, args.root)
    else:
        print(json.dumps(verify(args.output, args.manifest, args.root), sort_keys=True))


if __name__ == "__main__":
    main()
