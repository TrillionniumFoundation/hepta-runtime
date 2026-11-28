"""Two owned evidence readers under the unchanged enclosing 180-second budget."""
from pathlib import Path
import gzip
import json
import os
import subprocess
import sys
import time

from read_capture import SHA, file_pin, parse, pin, read, require

NAMES = ("one", "two")


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + "\n").encode()


def command(python, source, capture, output, name, baseline_sha):
    return [str(python), "-I", "-B", str(source / "evidence_controls.py"),
            "--capture", str(capture), "--output", str(output),
            "--worker", name, "--baseline-sha", baseline_sha]


def launch_workers(source, capture, output, baseline_sha, started):
    """Always reap both actual children before attempting final receipt writes."""
    live, records = [], []
    failure = None
    try:
        for name in NAMES:
            argv = command(sys.executable, source, capture, output, name, baseline_sha)
            record = dict(name=name, argv=argv, cwd=str(source), parent_pid=os.getpid(),
                          pgid=os.getpgrp(), enclosing_deadline_seconds=180,
                          started_monotonic_ns=time.monotonic_ns(), pid=None,
                          exit_code=None, completed=False, timed_out=False)
            with (output / (name + ".stdout")).open("xb") as out:
                with (output / (name + ".stderr")).open("xb") as err:
                    process = subprocess.Popen(argv, cwd=source, stdin=subprocess.DEVNULL,
                                               stdout=out, stderr=err, start_new_session=False)
                    # Register the handle before any fallible metadata/receipt work.
                    live.append((process, record))
                    records.append(record)
                    record["pid"] = process.pid
                    require(os.getpgid(process.pid) == record["pgid"],
                            "reader worker escaped the enclosing owned process group")
            (output / "worker-processes.json").write_bytes(encoded(records))
        for process, record in live:
            remaining = 180 - (time.monotonic_ns() - started) / 1e9
            require(remaining > 0, "reader parent exhausted its unchanged deadline")
            try:
                process.wait(timeout=remaining)
            except subprocess.TimeoutExpired:
                record["timed_out"] = True
                raise
            record["finished_monotonic_ns"] = time.monotonic_ns()
            record["exit_code"] = process.returncode
            record["completed"] = True
            require(process.returncode == 0, "reader worker failed: " + record["name"])
    except BaseException as error:
        failure = dict(type=type(error).__name__, message=str(error))
        raise
    finally:
        # A kill/wait or receipt error must never skip the other owned child.
        cleanup = []
        for process, record in live:
            try:
                if process.poll() is None:
                    process.kill()
            except BaseException as error:
                cleanup.append(dict(name=record["name"], phase="kill",
                                    type=type(error).__name__, message=str(error)))
        for process, record in live:
            try:
                process.wait()
                record["exit_code"] = process.returncode
                record["reaped"] = True
                record.setdefault("finished_monotonic_ns", time.monotonic_ns())
            except BaseException as error:
                record["reaped"] = False
                cleanup.append(dict(name=record["name"], phase="wait",
                                    type=type(error).__name__, message=str(error)))
        # All process custody has been resolved before writing these receipts.
        for _, record in live:
            record["elapsed_seconds"] = (
                record["finished_monotonic_ns"] - record["started_monotonic_ns"]) / 1e9
            for kind in ("stdout", "stderr"):
                relative = record["name"] + "." + kind
                record[kind] = dict(file=relative, **file_pin(output / relative))
        (output / "worker-processes.json").write_bytes(encoded(records))
        if failure is not None or cleanup:
            (output / "worker-failure.json").write_bytes(encoded(dict(error=failure, cleanup=cleanup)))
        require(not cleanup, "reader worker cleanup was incomplete")
    return records


def read_workers(output, source_sha, baseline, control_names, *, expected_parent, semantic, expected_files,
                 expected_roots):
    """Read complete child reports, both proof pairs and the exact disjoint union."""
    output = Path(output)
    raw = read(output / "inputs/BASELINE.json")
    data = parse(raw)
    baseline_sha = SHA(raw)
    require(data["schema"] == "hepta.scope-annotation-span.parallel-reader-baseline.v1"
            and data["source_manifest_sha256"] == source_sha and data["baseline"] == baseline,
            "parallel reader baseline differs from the complete admitted capture")
    require({key: bytes.fromhex(value) for key, value in data["semantic_recoveries"].items()} == semantic
            and data["admitted_files"] == expected_files,
            "parallel reader recovery bytes or complete input identity domain differs")
    require({key: data[key] for key in ("source_root", "capture_root", "output_root")} == expected_roots
            and data["source_root"] == expected_parent["cwd"],
            "parallel reader roots differ from the actual enclosing source command")
    require(data["parent_pid"] == expected_parent["pid"]
            and data["parent_pgid"] == expected_parent["pgid"]
            and data["started_monotonic_ns"] == expected_parent["started_monotonic_ns"],
            "parallel reader parent custody differs")
    require(data["partition"] == dict(one=list(control_names[::2]), two=list(control_names[1::2])),
            "parallel reader control partition differs")
    records = parse(read(output / "worker-processes.json"))
    require([row["name"] for row in records] == list(NAMES), "reader worker process domain differs")
    require(len({row["pid"] for row in records}) == 2, "reader worker identities overlap")
    results, all_controls = [], set()
    for row, name in zip(records, NAMES, strict=True):
        require(type(row["pid"]) is int and row["pid"] > 0 and row["pid"] != data["parent_pid"]
                and row["parent_pid"] == data["parent_pid"] and row["pgid"] == data["parent_pgid"],
                "reader worker PID, parent or process group differs")
        require(type(row["enclosing_deadline_seconds"]) is int and row["enclosing_deadline_seconds"] == 180
                and row["completed"] is True and row["timed_out"] is False
                and type(row["exit_code"]) is int and row["exit_code"] == 0 and row["reaped"] is True,
                "reader worker did not complete under the original enclosing deadline")
        require(all(type(value) is int and value > 0 for value in (
                    data["started_monotonic_ns"], row["started_monotonic_ns"], row["finished_monotonic_ns"]))
                and type(row["elapsed_seconds"]) in (int, float),
                "reader worker timing field types differ")
        require(data["started_monotonic_ns"] <= row["started_monotonic_ns"]
                <= row["finished_monotonic_ns"]
                < data["started_monotonic_ns"] + 180_000_000_000
                and row["elapsed_seconds"] ==
                (row["finished_monotonic_ns"] - row["started_monotonic_ns"]) / 1e9,
                "reader worker lifetime escapes the enclosing process deadline")
        source, capture, destination = (Path(data[key]) for key in ("source_root", "capture_root", "output_root"))
        require(row["cwd"] == str(source) and Path(row["argv"][0]).is_absolute()
                and row["argv"] == command(row["argv"][0], source, capture, destination, name, baseline_sha),
                "reader worker actual source command differs")
        for kind in ("stdout", "stderr"):
            identity = row[kind]
            require(identity["file"] == name + "." + kind
                    and file_pin(output / identity["file"]) ==
                    {key: identity[key] for key in ("bytes", "sha256")},
                    "complete reader worker process stream changed")
        require(row["stderr"]["bytes"] == 0, "reader worker stderr is not empty")
        result_raw = read(output / "workers" / name / "result.json")
        result = parse(result_raw)
        summary = parse(read(output / row["stdout"]["file"]))
        require(result["status"] == "READER_WORKER_PASS" and result["name"] == name
                and result["baseline_sha256"] == baseline_sha
                and result["source_manifest_sha256"] == source_sha
                and type(result["native_processes_executed"]) is int
                and type(result["original_processes_executed"]) is int
                and result["native_processes_executed"] == result["original_processes_executed"] == 0,
                "reader worker report source or completion differs")
        observed = result["execution"]
        require(all(type(observed[key]) is int and observed[key] > 0 for key in
                    ("pid", "parent_pid", "pgid", "started_monotonic_ns", "finished_monotonic_ns"))
                and type(result["elapsed_seconds"]) in (int, float),
                "reader worker observation field types differ")
        require(observed["pid"] == row["pid"] and observed["parent_pid"] == row["parent_pid"]
                and observed["pgid"] == row["pgid"] and observed["cwd"] == row["cwd"]
                and row["started_monotonic_ns"] <= observed["started_monotonic_ns"]
                <= observed["finished_monotonic_ns"] <= row["finished_monotonic_ns"]
                and result["elapsed_seconds"] ==
                (observed["finished_monotonic_ns"] - observed["started_monotonic_ns"]) / 1e9,
                "reader worker self-observation differs from its actual process")
        require(summary == dict(status="READER_WORKER_PASS", name=name,
                                controls=len(data["partition"][name]), relocations=1,
                                native_processes_executed=0, original_processes_executed=0,
                                execution=observed, result=pin(result_raw)),
                "actual worker stdout does not bind the complete report")
        require([control["name"] for control in result["controls"]] == data["partition"][name]
                and all(control["status"] == "REFUSED" for control in result["controls"]),
                "reader worker refusal domain differs")
        for control in result["controls"]:
            require(control["name"] not in all_controls, "parallel reader controls overlap")
            all_controls.add(control["name"])
            if control["name"] != "foreign-copy-symlink":
                require(control["guard_refusals"] == 12 and control["unchanged_entries"] > 0
                        and (control["reader_pid"], control["reader_parent_pid"], control["reader_pgid"])
                        == (row["pid"], row["parent_pid"], row["pgid"])
                        and type(control["changed_files"]) is dict and bool(control["changed_files"]),
                        "complete guarded mutation lost its actual worker custody")
        for field, prefix in (("relocations", "relocation"), ("post_refusal", "post-refusal")):
            require(len(result[field]) == 1, "reader worker omitted a complete physical proof")
            proof_row = result[field][0]
            require(proof_row["name"] == name and proof_row["status"] == "PASS"
                    and proof_row["files"] == len(data["admitted_files"])
                    and proof_row["same_complete_source_and_artifact_identity"] is True
                    and proof_row["processes_executed"] == 0
                    and proof_row["proof_file"] == prefix + "-" + name + ".json.gz",
                    "reader worker complete proof domain differs")
            proof_raw = gzip.decompress(read(output / proof_row["proof_file"]))
            require(pin(proof_raw) == proof_row["proof"], "complete worker proof bytes changed")
            proof = parse(proof_raw)
            require(proof["before"] == proof["after"]
                    and len(proof["before"]) == proof_row["unchanged_entries"]
                    and len(proof["probes"]) == proof_row["guard_refusals"] == 12
                    and proof["native_or_rust_executions"] == proof["reader_writes"] == 0
                    and (proof["pid"], proof["ppid"], proof["pgid"])
                    == (row["pid"], row["parent_pid"], row["pgid"])
                    and proof["evidence"] == baseline,
                    "worker complete guarded admission differs")
        results.append(result)
    require(all_controls == set(control_names), "parallel reader union omitted a frozen control")
    return results
