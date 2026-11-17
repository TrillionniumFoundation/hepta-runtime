"""Retain complete native constructor buffers and compare native typed serialization.

Each HIA invocation has an operating-system 60 second deadline. A case worker
starts no children; the driver adds no outer process-group timeout. Native
component comparison here is separate from actual target Rust qualification.
"""
from pathlib import Path
import argparse
import gzip
import hashlib
import json
import signal
import struct
import subprocess
import sys
import time

sys.dont_write_bytecode = True


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def write_json(path, value):
    path.write_text(json.dumps(value, sort_keys=True, indent=2)+"\n")


def artifact(folder, name, raw):
    path = folder / (name + ".gz")
    with path.open("xb") as handle:
        with gzip.GzipFile(fileobj=handle, mode="wb", filename="", mtime=0) as compressed:
            compressed.write(raw)
    packed = path.read_bytes()
    return dict(path=path.name, bytes=len(raw), sha256=sha(raw),
                compressed_bytes=len(packed), compressed_sha256=sha(packed))


def capture(module, frame, folder, output_capacity, workspace_capacity):
    folder.mkdir()
    inp = artifact(folder, "input", frame)
    started = time.monotonic()
    signal.signal(signal.SIGALRM, signal.SIG_DFL)
    signal.alarm(60)
    try:
        code, output, work = module.invoke_raw(frame, output_capacity=output_capacity,
                                               workspace_capacity=workspace_capacity)
    finally:
        signal.alarm(0)
    elapsed = time.monotonic()-started
    record = dict(return_code=code, output_capacity=output_capacity,
                  workspace_capacity=workspace_capacity, elapsed_seconds=elapsed,
                  deadline_seconds=60, input=inp,
                  output=artifact(folder, "output", output),
                  workspace=artifact(folder, "workspace", work))
    write_json(folder / "CAPTURE.json", record)
    return code, output, record


def run_worker(a):
    source, build = a.source.resolve(), a.build.resolve()
    sys.path.insert(0, str(source / "scripts"))
    sys.path.insert(0, str(source / "tests"))
    from hia_native_loader import NativeModule
    from constructor_cases import cases
    case = cases(a.profile)[a.case]
    folder = a.output.resolve()
    folder.mkdir(parents=True, exist_ok=False)
    receipt = dict(status="RUNNING", case=case.name, index=a.case, profile=a.profile,
                   text_bytes=len(case.text.encode()), is_error=case.is_error, policy=case.policy,
                   actual_target_rust_comparison=False, captures=[])
    write_json(folder / "CASE.json", receipt)
    row = json.loads((build / "BUILD.json").read_bytes())
    if row["status"] != "HIA_COMPILE_PASS":
        raise ValueError("build did not finish")
    c = row["modules"]["text-result-constructor"]
    frame = case.frame()
    output_capacity, workspace_capacity = 32, 16
    try:
        with NativeModule(build / c["manifest"], manifest_sha256=c["manifest_sha256"]) as module:
            for attempt in range(3):
                code, output, record = capture(module, frame, folder / f"constructor-{attempt}",
                                               output_capacity, workspace_capacity)
                receipt["captures"].append(dict(owner="text-result-constructor", folder=f"constructor-{attempt}",
                                                 **record))
                write_json(folder / "CASE.json", receipt)
                if code == 0xffffffd0:
                    magic, kind, required, reserved = struct.unpack("<8s3Q", output[:32])
                    if magic != b"HGRWS002" or reserved != 0:
                        raise ValueError("growth descriptor differs")
                    if kind == 1:
                        if required != 16384 + receipt["text_bytes"] or required <= workspace_capacity:
                            raise ValueError("workspace growth differs")
                        workspace_capacity = required
                    elif kind == 2:
                        if required < 64 or required <= output_capacity:
                            raise ValueError("output growth differs")
                        output_capacity = required
                    else:
                        raise ValueError("unknown growth resource")
                    continue
                if code != 64 or len(output) < 64:
                    raise ValueError(("constructor return differs", code))
                magic, status, error, policy, start, size, zero1, zero2 = struct.unpack("<8s7Q", output[:64])
                if (magic, status, error, policy, start, zero1, zero2) != (
                        b"HRTCRS01", 0, case.is_error, case.policy, 64, 0, 0):
                    raise ValueError("constructor header differs")
                if start + size != len(output):
                    raise ValueError("complete extent differs")
                wire = output[start:start+size]
                value = json.loads(wire)
                expected = dict(content=[dict(type="text", text=case.text)], isError=bool(case.is_error))
                if case.policy != 1:
                    expected["resultType"] = "complete"
                if value != expected:
                    raise ValueError("constructor semantic value differs")
                receipt["wire"] = artifact(folder, "wire", wire)
                receipt["complete_extent"] = len(output)
                break
            else:
                raise ValueError("constructor did not complete after real growth")
        if case.retained_typed:
            typed_json = json.dumps(expected, ensure_ascii=False, separators=(",", ":")).encode()
            typed_frame = struct.pack("<8s2Q", b"HRTYP001", 1, len(typed_json)) + typed_json
            t = row["modules"]["retained-typed-result"]
            with NativeModule(build / t["manifest"], manifest_sha256=t["manifest_sha256"]) as module:
                code, output, record = capture(module, typed_frame, folder / "retained-typed",
                                               len(wire)+64, 96 << 20)
            receipt["captures"].append(dict(owner="retained-typed-result", folder="retained-typed", **record))
            if code != len(wire) or output[:code] != wire:
                raise ValueError(("retained typed wire differs", code, len(wire)))
        receipt.update(status="NATIVE_CONSTRUCTOR_NORMAL_PASS",
                       retained_typed_wire_compared=case.retained_typed,
                       actual_target_rust_comparison=False)
    except BaseException as exc:
        receipt.update(status="FAIL", error=repr(exc))
        raise
    finally:
        write_json(folder / "CASE.json", receipt)


def run_driver(a):
    source, output = a.source.resolve(), a.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    sys.path.insert(0, str(source / "tests"))
    from constructor_cases import cases
    selected = cases(a.profile)
    summary = dict(schema="hepta.text-constructor-native.v2", status="RUNNING",
        profile=a.profile, expected_cases=len(selected), completed_cases=0,
        native_calls=0, retained_typed_comparisons=0, rows=[],
        source=str(source), build=str(a.build.resolve()), actual_target_rust_comparison=False,
        public_publish_qualified=False, full_sdk_qualified=False)
    def save():
        write_json(output / "SUMMARY.json", summary)
    save()
    try:
        for index, case in enumerate(selected):
            case_folder = output / f"case-{index:03d}"
            command = [sys.executable, str(Path(__file__).resolve()),
                "--source", str(source), "--build", str(a.build.resolve()), "--output", str(case_folder),
                "--profile", a.profile, "--case", str(index)]
            started = time.monotonic()
            with (output / f"{index:03d}.stdout").open("xb") as stdout, (output / f"{index:03d}.stderr").open("xb") as stderr:
                proc = subprocess.Popen(command, stdout=stdout, stderr=stderr, start_new_session=True)
                code = proc.wait()
            process = dict(command=command, pid=proc.pid, returncode=code,
                           elapsed_seconds=time.monotonic()-started, native_deadline_seconds=60)
            write_json(output / f"{index:03d}.process.json", process)
            if code != 0 or (output / f"{index:03d}.stderr").stat().st_size:
                raise ValueError(("case process failed", case.name, code))
            receipt = json.loads((case_folder / "CASE.json").read_bytes())
            if receipt["status"] != "NATIVE_CONSTRUCTOR_NORMAL_PASS":
                raise ValueError("case is not complete")
            summary["completed_cases"] += 1
            summary["native_calls"] += len(receipt["captures"])
            summary["retained_typed_comparisons"] += int(receipt["retained_typed_wire_compared"])
            summary["rows"].append(dict(case=case.name, folder=case_folder.name,
                receipt_sha256=sha((case_folder / "CASE.json").read_bytes()),
                wire_sha256=receipt["wire"]["sha256"], wire_bytes=receipt["wire"]["bytes"]))
            save()
        summary["status"] = "NATIVE_CONSTRUCTOR_NORMAL_PASS"
    except BaseException as exc:
        summary.update(status="FAIL", error=repr(exc))
        raise
    finally:
        save()
    print(json.dumps({k:v for k,v in summary.items() if k != "rows"}, sort_keys=True))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--build", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--profile", choices=("quick","ordinary","wide"), default="ordinary")
    parser.add_argument("--case", type=int)
    args = parser.parse_args()
    if args.case is None:
        run_driver(args)
    else:
        run_worker(args)

