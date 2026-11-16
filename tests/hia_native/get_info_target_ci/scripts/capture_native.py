"""Capture the fixed HIA owner for nine retained configuration labels.

No original process stream or expected wire is read. Each real HIA call has a
60 second OS alarm; no additional outer process-group timeout is introduced.
"""
from pathlib import Path
import argparse, hashlib, json, signal, struct, subprocess, sys, time
sys.dont_write_bytecode = True
PROFILES = ["disabled", *map(str, range(8))]
REQUEST = struct.pack("<8s3Q", b"HRTGIQ01", 1, 0, 0)
def sha(raw): return hashlib.sha256(raw).hexdigest()
def save(path, value): path.write_text(json.dumps(value, sort_keys=True, indent=2) + "\n")
def blob(folder, name, raw):
    path = folder / name
    with path.open("xb") as stream: stream.write(raw)
    return dict(path=name, bytes=len(raw), sha256=sha(raw))
def invoke(module, folder, capacity):
    folder.mkdir()
    input_pin = blob(folder, "input.bin", REQUEST)
    started = time.monotonic()
    signal.signal(signal.SIGALRM, signal.SIG_DFL); signal.alarm(60)
    try:
        code, output, workspace = module.invoke_raw(REQUEST, output_capacity=capacity,
            workspace_capacity=64, output_fill=0xa7, workspace_fill=0x5a)
    finally:
        signal.alarm(0)
    record = dict(return_code=code, output_capacity=capacity, workspace_capacity=64,
        output_fill=0xa7, workspace_fill=0x5a, deadline_seconds=60,
        elapsed_seconds=time.monotonic()-started, input=input_pin,
        output=blob(folder, "output.bin", output), workspace=blob(folder, "workspace.bin", workspace))
    save(folder / "CAPTURE.json", record)
    if workspace != b"\x5a" * 64: raise ValueError("stateless owner changed the workspace")
    return code, output, record
def worker(a):
    source, build = a.source.resolve(strict=True), a.build.resolve(strict=True)
    output = a.output.absolute(); output.mkdir(parents=True, exist_ok=False)
    if not 0 <= a.case < len(PROFILES): raise ValueError("ordinary case index")
    receipt = dict(status="RUNNING", profile=PROFILES[a.case], index=a.case, captures=[],
        expected_results_read=False, actual_target_wire_compared=False)
    save(output / "CASE.json", receipt)
    sys.path.insert(0, str(source / "support"))
    from hia_native_loader import NativeModule
    built = json.loads((build / "BUILD.json").read_bytes())
    if built["status"] != "HIA_COMPILE_PASS": raise ValueError("native build incomplete")
    try:
        with NativeModule(build / built["manifest"], manifest_sha256=built["manifest_sha256"]) as module:
            code, raw, record = invoke(module, output / "grow", 32)
            receipt["captures"].append({"folder": "grow", **record})
            save(output / "CASE.json", receipt)
            if code != 0xffffffd0: raise ValueError(("output growth return differs", code))
            magic, kind, extent, zero = struct.unpack("<8s3Q", raw)
            if magic != b"HGRWS002" or kind != 2 or zero or not 64 < extent < 8192:
                raise ValueError("complete output growth descriptor differs")
            code, raw, record = invoke(module, output / "complete", extent)
            receipt["captures"].append({"folder": "complete", **record})
            save(output / "CASE.json", receipt)
            if code != 64: raise ValueError(("descriptor return differs", code))
            magic, status, op, zero1, offset, size, zero2, zero3 = struct.unpack("<8s7Q", raw[:64])
            if (magic,status,op,zero1,offset,zero2,zero3) != (b"HRTGIS01",0,1,0,64,0,0):
                raise ValueError("complete descriptor fields differ")
            if offset + size != len(raw): raise ValueError("complete output extent differs")
            receipt["wire"] = blob(output, "wire.bin", raw[offset:offset+size])
            receipt["complete_extent"] = extent
        receipt["status"] = "NATIVE_CAPTURE_COMPLETE"
    except BaseException as error:
        receipt.update(status="FAIL", error=repr(error)); raise
    finally:
        save(output / "CASE.json", receipt)
def driver(a):
    source, output = a.source.resolve(strict=True), a.output.absolute()
    output.mkdir(parents=True, exist_ok=False)
    result = dict(schema="hepta.current-get-info.native-capture.v1", status="RUNNING",
        expected_cases=9, completed_cases=0, native_calls=0, rows=[],
        expected_results_read=False, actual_target_wire_compared=False, public_frontend_registered=False,
        full_sdk_qualified=False, full_async_runtime_qualified=False, production_activated=False, old_path_removed=False)
    def checkpoint(): save(output / "SUMMARY.json", result)
    checkpoint()
    try:
        for index, profile in enumerate(PROFILES):
            case = output / ("case-" + str(index))
            command = [sys.executable, "-I", "-B", str(Path(__file__).resolve()),
                "--source", str(source), "--build", str(a.build.resolve(strict=True)),
                "--output", str(case), "--case", str(index)]
            started = time.monotonic()
            with (output / f"{index}.stdout").open("xb") as stdout, (output / f"{index}.stderr").open("xb") as stderr:
                process = subprocess.Popen(command, stdout=stdout, stderr=stderr, start_new_session=True)
                code = process.wait()
            record = dict(index=index, profile=profile, command=command, exit_code=code,
                elapsed_seconds=time.monotonic()-started, native_deadline_seconds=60,
                stdout={"bytes":(output/f"{index}.stdout").stat().st_size,"sha256":sha((output/f"{index}.stdout").read_bytes())},
                stderr={"bytes":(output/f"{index}.stderr").stat().st_size,"sha256":sha((output/f"{index}.stderr").read_bytes())})
            save(output / f"{index}.process.json", record)
            if code != 0 or record["stdout"]["bytes"] or record["stderr"]["bytes"]:
                raise ValueError(("native case process failed", profile, code))
            receipt = json.loads((case / "CASE.json").read_bytes())
            if receipt["status"] != "NATIVE_CAPTURE_COMPLETE" or len(receipt["captures"]) != 2:
                raise ValueError("native case capture incomplete")
            result["rows"].append(dict(profile=profile, folder=case.name,
                receipt_sha256=sha((case/"CASE.json").read_bytes()), wire=receipt["wire"]))
            result["completed_cases"] += 1; result["native_calls"] += 2; checkpoint()
        result["status"] = "NATIVE_CAPTURE_COMPLETE"
    except BaseException as error:
        result.update(status="FAIL", error=repr(error)); raise
    finally:
        checkpoint()
    print(json.dumps({key:value for key,value in result.items() if key!="rows"},sort_keys=True))
if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    for name in ("source", "build", "output"): p.add_argument("--"+name,required=True,type=Path)
    p.add_argument("--case",type=int); a=p.parse_args()
    worker(a) if a.case is not None else driver(a)
