"""Actual G1 class-5 projection and the private registry's adjacent enum bound.

The capture path is CI-only. verify() reads every existing complete buffer and
cannot load or execute a native image. These 32 private calls supplement the
unchanged 1394 public records; they do not replace any public-wire comparison.
"""
from pathlib import Path
import argparse
import hashlib
import json
import os
import struct
import sys
import time

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import pin, put, require

NAMES = {"message": "public-task-batch-extract-target-message", "registry": "public-task-batch-extract-request-tasks"}
QUERY = b"HRCJQ001" + struct.pack("<QQ", 1, 4) + b"true"
MODES = tuple((before, after) for before in range(4) for after in range(4))
EPOCH = 17
OUTPUT_CAPACITY, WORKSPACE_CAPACITY = 224, 288


def descriptors(build):
    return {key: {"module": name, "manifest": pin(build / "production/build/modules" / name / "manifest.json")}
            for key, name in NAMES.items()}


def frame(payload, before, after):
    return b"HRTKRQ02" + struct.pack("<7Q", 15, EPOCH, 0, before, after, len(payload), 0) + payload


def capture(package, build):
    require(os.environ.get("GITHUB_ACTIONS") == "true", "native shape controls are CI-only")
    import ctypes
    sys.path.insert(0, str(package / "graph/source/scripts"))
    from hia_native_loader import NativeModule
    require(Path(sys.modules["hia_native_loader"].__file__).resolve()
            == package / "graph/source/scripts/hia_native_loader.py", "foreign native loader")
    out = build / "production/shape-admission"
    out.mkdir(parents=True, exist_ok=False)
    sources = descriptors(build)
    entries = []

    def save(name, body):
        path = out / name
        with path.open("xb") as stream:
            stream.write(body)
        return {"path": name, **pin(path)}

    started = time.monotonic_ns()
    modules = {key: NativeModule(build / "production/build/modules" / row["module"] / "manifest.json",
                                manifest_sha256=row["manifest"]["sha256"])
               for key, row in sources.items()}
    try:
        with modules["message"].session(output_capacity=131072, workspace_capacity=1048576) as session:
            before_o = session._output.raw[:session.output_capacity]
            before_w = session._workspace.raw[:session.workspace_capacity]
            code, output, workspace = session.invoke_raw(QUERY)
            projection = {"return_code": code, "input": save("projection.input", QUERY),
                "before_output": save("projection.before-output", before_o),
                "before_workspace": save("projection.before-workspace", before_w),
                "output": save("projection.output", output), "workspace": save("projection.workspace", workspace)}
            require(code == 256 and output[:16] == b"HRCJR001" + struct.pack("<Q", 5),
                    "actual current G1 did not emit class 5")
            payload = output[:code]
        with modules["registry"].session(output_capacity=OUTPUT_CAPACITY,
                                         workspace_capacity=WORKSPACE_CAPACITY) as session:
            ctypes.memset(session._output, 0xa5, OUTPUT_CAPACITY)
            ctypes.memset(session._workspace, 0, WORKSPACE_CAPACITY)
            ctypes.memset(ctypes.addressof(session._workspace) + 256, 0x5a, WORKSPACE_CAPACITY - 256)
            for before, after in MODES:
                for kind in (5, 6):
                    data = payload if kind == 5 else payload[:8] + struct.pack("<Q", 6) + payload[16:]
                    request = frame(data, before, after)
                    before_o = session._output.raw[:session.output_capacity]
                    before_w = session._workspace.raw[:session.workspace_capacity]
                    code, output, workspace = session.invoke_raw(request)
                    label = "call-" + str(len(entries))
                    entries.append({"class": kind, "mode_before": before, "mode_after": after,
                        "return_code": code, "input": save(label + ".input", request),
                        "before_output": save(label + ".before-output", before_o),
                        "before_workspace": save(label + ".before-workspace", before_w),
                        "output": save(label + ".output", output), "workspace": save(label + ".workspace", workspace)})
    finally:
        for module in modules.values():
            module.close()
    elapsed = time.monotonic_ns() - started
    require(0 <= elapsed <= 60_000_000_000, "shape controls exceeded the retained 60-second bound")
    record = {"schema": "hepta.sdk-task-shape-admission.capture.v1", "modules": sources,
        "projection": projection, "entries": entries, "elapsed_ns": elapsed,
        "complete_mutable_buffers_retained": True, "new_public_inputs": False,
        "native_calls": 33, "public_wire_qualified": False, "async_qualified": False}
    put(out / "CAPTURE.json", record)
    result = verify(package, build)
    put(out / "REPORT.json", result)
    return result


def verify(package, build):
    package, build = Path(package).resolve(strict=True), Path(build).resolve(strict=True)
    out = build / "production/shape-admission"
    record = json.loads((out / "CAPTURE.json").read_bytes())
    require(set(record) == {"schema", "modules", "projection", "entries", "elapsed_ns",
                           "complete_mutable_buffers_retained", "new_public_inputs", "native_calls",
                           "public_wire_qualified", "async_qualified"}, "shape capture fields differ")
    require(record["schema"] == "hepta.sdk-task-shape-admission.capture.v1"
            and record["modules"] == descriptors(build), "actual shape module identity differs")
    require(record["complete_mutable_buffers_retained"] is True and record["new_public_inputs"] is False
            and record["public_wire_qualified"] is False and record["async_qualified"] is False
            and record["native_calls"] == 33, "shape capture scope differs")
    require(type(record["elapsed_ns"]) is int and 0 <= record["elapsed_ns"] <= 60_000_000_000,
            "shape capture timing differs")
    visited = {"CAPTURE.json"}

    def read(row, name):
        require(set(row) == {"path", "bytes", "sha256"} and row["path"] == name,
                "shape buffer source path differs")
        path = out / name
        require(path.is_file() and not path.is_symlink() and pin(path)
                == {key: row[key] for key in ("bytes", "sha256")}, "complete shape buffer changed")
        visited.add(name)
        return path.read_bytes()

    projection = record["projection"]
    require(set(projection) == {"return_code", "input", "before_output", "before_workspace", "output", "workspace"}
            and projection["return_code"] == 256, "G1 projection return differs")
    require(read(projection["input"], "projection.input") == QUERY, "G1 projection input differs")
    before_o = read(projection["before_output"], "projection.before-output")
    before_w = read(projection["before_workspace"], "projection.before-workspace")
    require(before_o == bytes(131072) and before_w == bytes(1048576), "G1 initial buffers differ")
    output = read(projection["output"], "projection.output")
    workspace = read(projection["workspace"], "projection.workspace")
    payload = b"HRCJR001" + struct.pack("<Q", 5) + bytes(240)
    require(output == payload + before_o[256:] and len(workspace) == len(before_w),
            "complete G1 class-5 descriptor or mutable extent differs")
    previous_o = bytes([0xa5]) * OUTPUT_CAPACITY
    previous_w = bytes(256) + bytes([0x5a]) * (WORKSPACE_CAPACITY - 256)
    state = bytearray(previous_w)
    for at, value in ((0, int.from_bytes(b"HRTKST02", "little")), (8, EPOCH), (16, 1), (72, 256), (120, 1)):
        struct.pack_into("<Q", state, at, value)
    expected_o = bytearray(192)
    expected_o[:8] = b"HRTKRS02"
    for at, value in ((8, 16), (16, EPOCH), (96, 256), (168, 1)):
        struct.pack_into("<Q", expected_o, at, value)
    expected_o += previous_o[192:]
    wanted_cases = [(before, after, kind) for before, after in MODES for kind in (5, 6)]
    require(len(record["entries"]) == len(wanted_cases) == 32, "shape private control domain changed")
    for index, (entry, (before, after, kind)) in enumerate(zip(record["entries"], wanted_cases, strict=True)):
        require(set(entry) == {"class", "mode_before", "mode_after", "return_code", "input",
                               "before_output", "before_workspace", "output", "workspace"},
                "registry control fields differ")
        require((entry["mode_before"], entry["mode_after"], entry["class"]) == (before, after, kind),
                "registry control order differs")
        label = "call-" + str(index)
        data = payload if kind == 5 else payload[:8] + struct.pack("<Q", 6) + payload[16:]
        require(read(entry["input"], label + ".input") == frame(data, before, after),
                "registry control frame differs")
        require(read(entry["before_output"], label + ".before-output") == previous_o
                and read(entry["before_workspace"], label + ".before-workspace") == previous_w,
                "complete registry buffer continuation differs")
        actual_o = read(entry["output"], label + ".output")
        actual_w = read(entry["workspace"], label + ".workspace")
        if kind == 5:
            require(entry["return_code"] == 192 and actual_o == expected_o and actual_w == state,
                    "class 5 did not forward with no task/map/generation transition")
        else:
            require(entry["return_code"] == 0xffffffff and actual_o == previous_o and actual_w == previous_w,
                    "class 6 did not reject without changing existing buffers")
        previous_o, previous_w = actual_o, actual_w
    result = {"status": "ACTUAL_G1_SHAPE_ADMISSION_AND_CLASS6_REFUSAL_PASS", "actual_g1_calls": 1,
        "registry_calls": 32, "class5_forwards": 16, "class6_refusals": 16,
        "complete_mutable_buffers_compared": True, "handler_or_map_entries_created": 0,
        "registry_source": pin(package / "graph/source/native/sdk_request_task_registry.hepta"),
        "capture": pin(out / "CAPTURE.json"), "native_or_rust_executed": False,
        "files_written": False, "public_wire_qualified": False, "async_qualified": False}
    if (out / "REPORT.json").exists():
        require(json.loads((out / "REPORT.json").read_bytes()) == result, "shape control report changed")
        visited.add("REPORT.json")
    require({p.name for p in out.iterdir()} == visited and all(p.is_file() for p in out.iterdir()),
            "shape control evidence file set differs")
    return result


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--package", type=Path, required=True)
    p.add_argument("--build", type=Path, required=True)
    args = p.parse_args()
    result = capture(args.package.resolve(strict=True), args.build.resolve(strict=True))
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
