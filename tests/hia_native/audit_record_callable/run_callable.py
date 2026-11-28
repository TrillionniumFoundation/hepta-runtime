"""Fresh native callable capture. Completed original Rust is read, never rerun."""
from pathlib import Path
import argparse
import os
import shutil
import sys
ROOT = Path(__file__).resolve().parent
sys.dont_write_bytecode = True
sys.path.insert(0, str(ROOT))
from common import encoded, loads, read, require, source, files, pin
from process import Recorder, environment
from callable_commands import commands


def capture(hepta, output, retained, temporary):
    identity = source()
    output.mkdir(parents=True, exist_ok=False)
    temporary.mkdir(parents=True, exist_ok=False)
    shutil.copytree(ROOT, output / "source")
    old = loads(read(retained / "retained/run/semantic/CAPTURE.json"))
    require(old["schema"] == "hepta.audit-record-io.capture.v1" and old["status"] == "PASS" and
            old["source_manifest_sha256"] == "35b5d7c107e0583ac3a25cdcabf5ec9f547fbb31840079c49b5486230b8281e6" and
            old["uid"] == os.geteuid() and old["gid"] == os.getegid(), "qualified original source and actual operator identity")
    fixture = Path(old["owned_fixture"])
    require(fixture.is_absolute() and fixture.name == "owned-fixture" and
            fixture.parent == Path(old["build_temporary"]) and len(fixture.parts) >= 5 and
            not fixture.exists() and not fixture.is_symlink(), "fresh exact original owned fixture")
    for forbidden in (ROOT, output, retained, hepta):
        require(not fixture.is_relative_to(forbidden) and not forbidden.is_relative_to(fixture),
                "fixture must be independent of all retained evidence and sources")
    fixture.parent.mkdir(parents=True, exist_ok=True)
    require(fixture.parent.resolve() == fixture.parent, "ordinary exact fixture parent")
    env, environment_record = environment(os.environ)
    env.pop("HEPTA_REQUEST_AUDIT_TRACE", None)
    metadata = dict(schema="hepta.audit-record-callable.capture.v1", status="RUNNING",
        source_manifest_sha256=identity, source_root=str(ROOT), producer_root=str(output),
        compiler_root=str(hepta), python=sys.executable, retained_root=str(retained),
        owned_fixture=str(fixture), control_fixture=str(temporary / "transport-fixture"),
        environment=environment_record, audit_trace_environment_absent=True,
        uid=os.geteuid(), gid=os.getegid(), root_pid=os.getpid(), root_pgid=os.getpgrp(),
        original_rust_replay=0, whole_audit_caller_qualified=False,
        public_handler_qualified=False, whole_runtime_replaced=False)
    rows = commands(metadata)
    metadata["commands"] = rows
    (output / "CAPTURE.json").write_bytes(encoded(metadata))
    recorder = Recorder(ROOT, output / "processes", env)
    try:
        for row in rows:
            raw, receipt = recorder.run(row["name"], row["argv"], cwd=row["cwd"], timeout=row["timeout"])
            print(row["name"] + " PASS " + str(receipt["elapsed_seconds"]), flush=True)
        require(source() == identity, "frozen callable source unchanged through all actual processes")
        metadata.update(status="PASS", files=files(output, ("CAPTURE.json",)))
        (output / "CAPTURE.json").write_bytes(encoded(metadata))
    except BaseException as error:
        metadata.update(status="FAIL", exception=repr(error), completed_processes=len(recorder.records))
        (output / "CAPTURE.json").write_bytes(encoded(metadata))
        if recorder.records:
            sys.stderr.write((recorder.directory / (recorder.records[-1]["name"] + ".stderr")).read_text())
        raise
    finally:
        from fixture import snapshot
        for label, owned in (("record", fixture), ("controls", Path(metadata["control_fixture"]))):
            if owned.exists():
                try:
                    value = snapshot(owned)
                    (output / ("FAILED-FILESYSTEM-" + label + ".json")).write_bytes(encoded(value))
                except BaseException as error:
                    (output / ("FAILED-FILESYSTEM-" + label + "-ERROR.json")).write_bytes(encoded(dict(error=repr(error))))


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--hepta", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--retained", type=Path, required=True)
    p.add_argument("--temporary", type=Path, required=True)
    a = p.parse_args()
    capture(a.hepta.resolve(strict=True), a.output.absolute(), a.retained.resolve(strict=True), a.temporary.absolute())
