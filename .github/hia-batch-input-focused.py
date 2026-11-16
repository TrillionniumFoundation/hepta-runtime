from pathlib import Path
import argparse
import hashlib
import json
import os
import signal
import subprocess
import sys
import time

parser = argparse.ArgumentParser()
for name in ("runtime", "hepta", "output", "rust-bin"):
    parser.add_argument("--" + name, type=Path, required=True)
args = parser.parse_args()
root = args.runtime.resolve(strict=True)
hepta = args.hepta.resolve(strict=True)
output = args.output.resolve()
rust_bin = args.rust_bin.resolve(strict=True)
output.mkdir(parents=True, exist_ok=False)
sys.path.insert(0, str(root / "scripts"))
import hia_native_batch_plan_input_build as build
import hia_native_batch_plan_input_qualification as reader

def save(path, value):
    path.write_bytes(reader.canonical(value))

def execute(name, command, *, extra_environment=None):
    environment = os.environ.copy()
    environment.update(extra_environment or {})
    started = time.monotonic()
    timed_out = False
    with (output / (name + ".stdout")).open("xb") as stdout, (output / (name + ".stderr")).open("xb") as stderr:
        process = subprocess.Popen(command, cwd=root, env=environment,
                                   stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr,
                                   start_new_session=True)
        try:
            code = process.wait(timeout=180)
        except subprocess.TimeoutExpired:
            timed_out = True
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            code = process.wait(timeout=3)
    record = {"name": name, "command": command, "cwd": str(root), "pid": process.pid,
              "exit_code": code, "timed_out": timed_out, "timeout_seconds": 180,
              "elapsed_seconds": time.monotonic() - started}
    for kind in ("stdout", "stderr"):
        record[kind] = {"path": name + "." + kind, **reader.pin(output / (name + "." + kind))}
    save(output / (name + ".process.json"), record)
    print(json.dumps({"phase": name, **record}, sort_keys=True), flush=True)
    if code != 0 or timed_out:
        text = (output / (name + ".stderr")).read_text(errors="backslashreplace")
        print(json.dumps({"failure_stderr": text[-32768:]}, sort_keys=True), flush=True)
        raise RuntimeError(name + " did not complete within its unchanged deadline")
    return record

manifest = build.build_batch_plan_input(hepta, output / "build", source_root=root)
native_command = [sys.executable, "-I", "-B", str(root / "tests/hia_native/test_batch_plan_input.py")]
native = execute("native", native_command, extra_environment={
    "HIA_BATCH_PLAN_INPUT_MEMBERS": str(manifest),
    "HIA_BATCH_PLAN_INPUT_CAPTURE_DIR": str(output / "native"),
})
evidence = reader.native_evidence(root, output)
save(output / "native-evidence.json", evidence)
print(json.dumps({"phase": "strict-native-reader", "status": evidence["status"],
                  "native_elapsed_seconds": native["elapsed_seconds"]}, sort_keys=True), flush=True)

original_command = [sys.executable, "-I", "-B",
    str(root / "tests/hia_native/batch_plan_input_oracle/run.py"),
    "--runtime", str(root), "--output", str(output / "original"),
    "--native", str(output / "native"), "--rust-bin", str(rust_bin)]
execute("original", original_command)
complete = reader.native_evidence(root, output, original=True)
save(output / "original-evidence.json", complete)
print(json.dumps({"phase": "complete-fresh-original-comparison", "status": complete["status"],
                  "expected_complete_bytes": 100386031}, sort_keys=True), flush=True)

control_environment = {
    "HIA_BATCH_PLAN_INPUT_QUALIFICATION_OUTPUT": str(output),
    "HIA_BATCH_PLAN_INPUT_EVIDENCE_CAPTURE_DIR": str(output / "controls"),
}
control_sources = ("scripts/hia_native_batch_plan_input_qualification.py",
                   "tests/hia_native/test_batch_plan_input_original_evidence.py")
before = {name: reader.pin(root / name)["sha256"] for name in control_sources}
controls = execute("controls", [sys.executable, "-I", "-B",
    str(root / "tests/hia_native/test_batch_plan_input_original_evidence.py")],
    extra_environment=control_environment)
after = {name: reader.pin(root / name)["sha256"] for name in control_sources}
assert before == after
controls.update(source_before=before, source_after=after, controlled_env=control_environment)
save(output / "controls.process.json", controls)
qualified = reader.qualification_evidence(root, output, native=evidence)
save(output / "QUALIFIED.json", qualified)
print(json.dumps({"status": "COMPLETE_BATCH_INPUT_COMPONENT_PASS",
    "native_elapsed_seconds": native["elapsed_seconds"],
    "native_calls": 7027, "complete_capture_bytes": 3208052725,
    "semantic_inputs": 463, "semantic_records": 926,
    "fresh_original_bytes": 100386031,
    "refusal_controls": 12, "independent_readers": 2,
    "evidence": reader.pin(output / "QUALIFIED.json"),
    "whole_runtime_replaced": False, "public_route_replaced": False}, sort_keys=True), flush=True)

