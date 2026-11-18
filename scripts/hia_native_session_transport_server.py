# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""ServerMessage callable factories on the exact freshly rebuilt 15-image graph.

This native gate uses explicitly retained Original wire fixtures. It starts no
Original process. The separate fresh Original consumer must compare all ninety
requests and full replies before reporting a new Original/Native comparison.
"""
from __future__ import annotations
import argparse
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import time
import types

sys.path.insert(0, str(Path(__file__).resolve().parent))
from hia_native_session_transport_build import read, sha, object_at, require, relative
from hia_native_session_transport_admission import verify_build, inventory
from hia_native_session_transport_capture import source_snapshot, save

ORIGIN = "tests/hia_native/session_transport/server_origin"
INDEX = "tests/hia_native/session_transport/server-origin.json"
SELF = "scripts/hia_native_session_transport_server.py"
J = lambda value: (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=True) + "\n").encode()


def sources(root):
    root = Path(root)
    result = source_snapshot(root)
    index = object_at(root / INDEX)
    for name, want in index.items():
        require("/" not in name and name not in ("", ".", ".."), "invalid Server fixture path")
        raw = read(root / ORIGIN / name)
        require(sha(raw) == want["sha256"] and len(raw) == want["bytes"],
                "Server fixture source/reference bytes changed")
        result[(Path(ORIGIN) / name).as_posix()] = {"bytes": len(raw), "sha256": sha(raw)}
    for name in (SELF, INDEX):
        result[name] = {"bytes": len(read(root / name)), "sha256": sha(read(root / name))}
    return result


def module(root, name, label):
    path = Path(root) / ORIGIN / name
    want = object_at(Path(root) / INDEX)[name]
    require(sha(read(path)) == want["sha256"] and len(read(path)) == want["bytes"],
            "Server frozen source changed")
    spec = importlib.util.spec_from_file_location(label, path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def reference(root):
    root = Path(root)
    snapshot = sources(root)
    frozen = object_at(root / ORIGIN / "factory-fixture.json")
    fixture = module(root, "qualify_server_message_factory_v2.py", "server_factory_assertions")
    cases, answers = frozen["cases"], frozen["answers"]
    require(len(cases) == len(answers) == 90 and len({r["label"] for r in cases}) == 90,
            "Server fixture count differs")
    requests = [fixture.oracle_request(case) for case in cases]
    wire = b"".join((json.dumps(q, separators=(",", ":")) + "\n").encode() for q in requests)
    require(wire == read(root / ORIGIN / "reference-factory.stdin"),
            "complete retained Original input differs")
    response = read(root / ORIGIN / "reference-factory.stdout")
    require(sha(response) == frozen["original_stdout_sha256"]
            and [json.loads(line) for line in response.splitlines()] == answers,
            "complete retained Original output differs")
    for case, answer in zip(cases, answers, strict=True):
        require(answer["status"] in ("OK", "ERROR"), "reference returned unknown status")
        target = "id_hex" if answer.get("target") == "id" else "body_hex"
        require(answer["input_bytes"] == len(bytes.fromhex(case[target])),
                "retained reference input length differs")
        if case["positive"]:
            require(answer["status"] == "OK", "positive fixture was not accepted by Original")
    require(sum(x["status"] == "OK" for x in answers) == 77, "retained typed variants differ")
    return cases, answers, fixture, snapshot


def view(proof, folder):
    graph = proof["graphs"]["server_message"]
    folder.mkdir(mode=0o700)
    raw = read(graph["artifact"])
    save(folder / "hia-server-message-callable.elf", raw, 0o500)
    data = {
        "schema": "hepta.runtime.session-transport-callable-view.v1",
        "status": "BUILT_NOT_SEMANTICALLY_QUALIFIED",
        "source_build_manifest_sha256": proof["manifest_sha256"],
        "graph": "server_message", "exports": graph["exports"],
        "artifact": {"bytes": len(raw), "sha256": sha(raw)},
        "new_compilation": False, "new_semantic_execution": False,
        "historical_build_receipt": False,
    }
    save(folder / "result.json", J(data))
    return sha(J(data))


def child(root, output, mode, expected_sources, expected_fixture):
    root, output = Path(root), Path(output)
    snapshot = sources(root)
    require(sha(J(snapshot)) == expected_sources, "Server child source closure differs")
    require(sha(read(output / "fixture.json")) == expected_fixture, "Server child inputs changed")
    fixture = module(root, "qualify_server_message_factory_v2.py", "server_factory_physical")
    original_loader = fixture.module
    adaptations = []
    def local_module(path, digest, label):
        require(Path(path) == root / ORIGIN / "server_message_machine_v1.py",
                "unexpected Server Machine import")
        result = original_loader(path, digest, label)
        require(digest == object_at(root / INDEX)["server_message_machine_v1.py"]["sha256"],
                "Server Machine source pin differs")
        result.BUILD = output / "callable"
        adaptations.append({"binding": "BUILD", "module": Path(path).name,
                            "source_sha256": digest, "path": str(result.BUILD)})
        return result
    fixture.M = root / ORIGIN
    fixture.OUT = output
    fixture.BUILD = output / "callable"
    fixture.BUILD_SHA = sha(read(output / "callable/result.json"))
    fixture.module = local_module
    try:
        fixture.run_child(mode, expected_fixture)
    finally:
        require(sources(root) == snapshot and len(adaptations) == 1,
                "Server child sources or physical Machine imports differ")
        save(output / ("mode-" + str(mode)) / "portable-invocation.json", J({
            "pid": os.getpid(), "pgid": os.getpgrp(), "mode": mode, "argv": sys.argv,
            "source_sha256": snapshot, "fixture_sha256": expected_fixture,
            "adaptations": adaptations, "physical_fixture_function_unchanged": True,
            "physical_machine_functions_unchanged": True,
            "new_original_processes": 0, "reference_kind": "sealed-historical-full-wire",
        }))


class Reader:
    @staticmethod
    def pin(path, digest=None, size=None):
        raw = read(path)
        if digest is not None:
            require(sha(raw) == digest, "Server capture hash differs")
        if size is not None:
            require(len(raw) == size, "Server capture length differs")
        return raw


def verify(output, manifest, root, *, captured=False):
    root, output = Path(root), Path(output)
    report = object_at(output / "result.json")
    require(report["schema"] == "hepta.runtime.session-server-factory.v1"
            and report["status"] == ("CAPTURED_NOT_QUALIFIED" if captured else "PASS"),
            "Server factory qualification status differs")
    require(report["actual_native_processes"] == 2 and report["actual_original_processes"] == 0
            and report["original_ownership_paired"] is False
            and report["whole_runtime_replaced"] is False
            and report["production_activated"] is False,
            "Server factory scope differs")
    cases, answers, fixture, snapshot = reference(root)
    require(snapshot == report["source_sha256"], "Server capture source closure differs")
    proof = verify_build(manifest, root)
    require(proof["manifest_sha256"] == report["source_build_manifest_sha256"],
            "Server capture build differs")
    expected_files = set(report["files"]) | {"result.json"}
    require(expected_files == {p.relative_to(output).as_posix() for p in output.rglob("*") if p.is_file()},
            "complete Server capture file inventory differs")
    require(set(report["directories"]) == {p.relative_to(output).as_posix()
            for p in output.rglob("*") if p.is_dir()}, "Server capture directory inventory differs")
    for name, want in report["files"].items():
        p = relative(output, name)
        raw = read(p)
        require(len(raw) == want["bytes"] and sha(raw) == want["sha256"]
                and stat.S_IMODE(p.stat().st_mode) == want["mode"],
                "complete Server capture bytes or mode differ")
    build = object_at(output / "callable/result.json")
    graph = proof["graphs"]["server_message"]
    expected_view = {
        "schema": "hepta.runtime.session-transport-callable-view.v1",
        "status": "BUILT_NOT_SEMANTICALLY_QUALIFIED",
        "source_build_manifest_sha256": proof["manifest_sha256"],
        "graph": "server_message", "exports": graph["exports"],
        "artifact": {"bytes": graph["bytes"], "sha256": graph["sha256"]},
        "new_compilation": False, "new_semantic_execution": False,
        "historical_build_receipt": False,
    }
    require(build == expected_view and read(output / "callable/hia-server-message-callable.elf")
            == read(graph["artifact"]), "executed Server callable differs from actual build")
    require(read(output / "original.stdout") == read(root / ORIGIN / "reference-factory.stdout"),
            "retained reference bytes differ")
    expected_fixture = {"build_sha256": sha(read(output / "callable/result.json")),
                        "original_stdout_sha256": sha(read(output / "original.stdout")),
                        "cases": cases, "answers": answers}
    require(read(output / "fixture.json") == fixture.J(expected_fixture),
            "complete Server factory fixture differs")
    retained = module(root, "server_message_factory_retained_v3.py", "server_factory_retained")
    metrics = []
    for mode, process in zip((1, 2), report["processes"], strict=True):
        folder = output / ("mode-" + str(mode))
        command = [report["python_at_execution"], "-I", "-B",
            str(Path(report["root_at_execution"]) / SELF), "child",
            "--root", report["root_at_execution"], "--output", report["output_at_execution"],
            "--mode", str(mode), "--sources-sha256", sha(J(snapshot)),
            "--fixture-sha256", sha(read(output / "fixture.json"))]
        require(process["command"] == command and process["mode"] == mode
                and process["exit_code"] == 0 and process["timed_out"] is False
                and process["pgid"] == report["pgid"] and process["timeout_seconds"] == 60,
                "actual Server child completion differs")
        stdout = read(output / ("mode-" + str(mode) + ".stdout"))
        stderr = read(output / ("mode-" + str(mode) + ".stderr"))
        require(sha(stdout) == process["stdout_sha256"] and len(stdout) == process["stdout_bytes"]
                and not stderr and sha(stderr) == process["stderr_sha256"]
                and process["stderr_bytes"] == 0, "complete Server process output differs")
        value = object_at(folder / "result.json")
        invocation = object_at(folder / "portable-invocation.json")
        require(json.loads(stdout) == value and value["pid"] == value["tid"] == process["pid"]
                and value["mode"] == mode, "actual Server child stdout/result differs")
        require(invocation == {
            "pid": process["pid"], "pgid": process["pgid"], "mode": mode, "argv": command[3:],
            "source_sha256": snapshot, "fixture_sha256": sha(read(output / "fixture.json")),
            "adaptations": [{"binding": "BUILD", "module": "server_message_machine_v1.py",
                "source_sha256": object_at(root / INDEX)["server_message_machine_v1.py"]["sha256"],
                "path": str(Path(report["output_at_execution"]) / "callable")}],
            "physical_fixture_function_unchanged": True,
            "physical_machine_functions_unchanged": True, "new_original_processes": 0,
            "reference_kind": "sealed-historical-full-wire"}, "Server invocation identity differs")
        metrics.append(retained.factory_child(Reader, folder, build, value, fixture, cases, answers, mode))
    require(metrics[0] == metrics[1], "Server factory modes differ")
    require(read(output / "mode-1/canonical.json") == read(output / "mode-2/canonical.json"),
            "Server factory canonical modes differ")
    require(sources(root) == snapshot, "Server sources changed during full admission")
    return {"projection_requests_per_mode": 90, "modes": 2, "owned_cases_per_mode": 308,
            "metrics_per_mode": metrics[0], "fresh_original_processes": 0,
            "retained_reference_requests": 90, "original_ownership_paired": False,
            "raw_physical_and_resource_records_fully_reconstructed": True}


def run(output, manifest, root):
    root, output = Path(root).absolute(), Path(output).absolute()
    require(not output.exists(), "Server capture output is create-only")
    output.mkdir(parents=True, mode=0o700)
    cases, answers, fixture, snapshot = reference(root)
    proof = verify_build(manifest, root)
    view_sha = view(proof, output / "callable")
    save(output / "original.stdout", read(root / ORIGIN / "reference-factory.stdout"))
    frame = fixture.J({"build_sha256": view_sha,
                       "original_stdout_sha256": sha(read(output / "original.stdout")),
                       "cases": cases, "answers": answers})
    save(output / "fixture.json", frame)
    report = {"schema": "hepta.runtime.session-server-factory.v1", "status": "RUNNING",
              "pid": os.getpid(), "pgid": os.getpgrp(), "root_at_execution": str(root),
              "output_at_execution": str(output), "python_at_execution": sys.executable,
              "source_sha256": snapshot, "source_build_manifest_sha256": proof["manifest_sha256"],
              "actual_native_processes": 0, "actual_original_processes": 0,
              "processes": [], "original_ownership_paired": False,
              "production_activated": False, "whole_runtime_replaced": False}
    started = time.monotonic()
    try:
        for mode in (1, 2):
            command = [sys.executable, "-I", "-B", str(Path(__file__).resolve()), "child",
                       "--root", str(root), "--output", str(output), "--mode", str(mode),
                       "--sources-sha256", sha(J(snapshot)), "--fixture-sha256", sha(frame)]
            timed = False
            begin = time.monotonic()
            with (output / ("mode-" + str(mode) + ".stdout")).open("xb") as stdout, \
                 (output / ("mode-" + str(mode) + ".stderr")).open("xb") as stderr:
                process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=stdout,
                    stderr=stderr, cwd=output, env={"PATH": "", "LANG": "C"})
                report["actual_native_processes"] += 1
                pgid = os.getpgid(process.pid)
                try:
                    process.wait(timeout=60)
                except subprocess.TimeoutExpired:
                    timed = True
                    process.kill()
                    process.wait(timeout=10)
            out = read(output / ("mode-" + str(mode) + ".stdout"))
            err = read(output / ("mode-" + str(mode) + ".stderr"))
            row = {"command": command, "pid": process.pid, "pgid": pgid, "mode": mode,
                   "exit_code": process.returncode, "timed_out": timed, "timeout_seconds": 60,
                   "elapsed_seconds": time.monotonic() - begin,
                   "stdout_bytes": len(out), "stdout_sha256": sha(out),
                   "stderr_bytes": len(err), "stderr_sha256": sha(err)}
            report["processes"].append(row)
            require(process.returncode == 0 and not timed and not err,
                    "actual Server factory child failed: " + repr(row))
        report["status"] = "CAPTURED_NOT_QUALIFIED"
        report["files"] = inventory(output)
        report["directories"] = sorted(p.relative_to(output).as_posix()
                                       for p in output.rglob("*") if p.is_dir())
        save(output / "result.json", J(report))
        evidence = verify(output, manifest, root, captured=True)
        report.update(status="PASS", evidence=evidence, elapsed_seconds=time.monotonic() - started)
        (output / "result.json").write_bytes(J(report))
        print(json.dumps({"status": "PASS", "actual_native_processes": 2,
                          "actual_original_processes": 0, "evidence": evidence,
                          "whole_runtime_replaced": False}, sort_keys=True))
    except BaseException as error:
        report.update(status="FAIL", error=repr(error), elapsed_seconds=time.monotonic() - started)
        (output / "result.json").write_bytes(J(report))
        raise
    return report


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("run", "verify", "child"))
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--mode", type=int)
    parser.add_argument("--sources-sha256")
    parser.add_argument("--fixture-sha256")
    args = parser.parse_args()
    if args.action == "child":
        child(args.root, args.output, args.mode, args.sources_sha256, args.fixture_sha256)
    elif args.action == "run":
        run(args.output, args.manifest, args.root)
    else:
        print(json.dumps(verify(args.output, args.manifest, args.root), sort_keys=True))


if __name__ == "__main__":
    main()
