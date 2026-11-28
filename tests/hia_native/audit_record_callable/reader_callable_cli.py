"""Explicit source-bound read-only and physical-control phases for the native callable."""
from pathlib import Path
import argparse
import gzip
import io
import sys
import tarfile
import tomllib
ROOT = Path(__file__).resolve().parent
sys.dont_write_bytecode = True
sys.path.insert(0, str(ROOT))
from common import encoded, loads, read, require
import read_callable_capture
import reader_controls_callable
import read_only_guard


def prepare(retained):
    require(gzip.decompress(gzip.compress(b"ready")) == b"ready", "gzip preload")
    require(tomllib.loads("x=1")["x"] == 1, "TOML preload")
    with tarfile.open(fileobj=io.BytesIO(bytes(10240)), mode="r:") as stream:
        require(list(stream) == [], "TAR preload")
    return read_callable_capture.prepare(retained)


def operation(capture, prepared, controls=None):
    evidence = read_callable_capture.verify(capture, prepared)
    if controls is not None:
        evidence = dict(evidence, physical_controls=reader_controls_callable.verify(capture, prepared, controls, evidence))
    return evidence


def run(phase, capture, retained, controls, report):
    prepared = prepare(retained)
    if phase == "controls":
        value = reader_controls_callable.run(capture, prepared, controls)
        summary = dict(status=value["status"], admissions=value["admissions"], refusals=value["refusals"],
                       native_or_rust_executions=0, mutation_writes_outside_guards=True)
        report.write_bytes(encoded(value))
    else:
        roots = reader_controls_callable.roots(capture, prepared)
        if phase in ("final", "verify"):
            roots.append(controls)
        complete = phase in ("final", "verify")
        value = read_only_guard.guarded(lambda: operation(capture, prepared, controls if complete else None),
            roots=roots, foreign_path=str(report.parent / "foreign-unadmitted-copy/CAPTURE.json"))
        if phase == "verify":
            existing = loads(read(report))
            require(existing["evidence"] == value["evidence"] and existing["before"] == existing["after"] and
                    len(existing["probes"]) == 12 and existing["native_or_rust_executions"] == existing["reader_writes"] == 0,
                    "read-only verification compares the existing complete final proof without rewriting it")
        else:
            report.write_bytes(encoded(value))
        summary = dict(status=value["evidence"]["status"], native_or_rust_executions=0, reader_writes=0,
                       guard_probes=len(value["probes"]), physical_entries=len(value["before"]), evidence=value["evidence"])
        if phase == "verify":
            summary["complete_guard"] = value
    print(encoded(summary).decode(), end="")


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--phase", choices=("semantic", "controls", "final", "verify"), required=True)
    p.add_argument("--capture", type=Path, required=True)
    p.add_argument("--retained", type=Path, required=True)
    p.add_argument("--controls", type=Path, required=True)
    p.add_argument("--report", type=Path, required=True)
    a = p.parse_args()
    run(a.phase, a.capture.resolve(strict=True), a.retained.resolve(strict=True),
        a.controls.absolute(), a.report.absolute())
