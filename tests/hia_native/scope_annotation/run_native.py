"""Execute the complete bounded annotation corpus on actual pinned HIA images."""
import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path
import struct
import sys
import time

sys.dont_write_bytecode = True
from cases import cases, input_frame, packet, observed_frame
from native_transport import Transport, UNPACK

SHA = lambda raw: hashlib.sha256(raw).hexdigest()
OWNERS = {"scope_annotation": 1, "serde_json": 2, "serde_error": 3, "typed_result_json": 4, "text_result_constructor": 5}


def dump(path, value):
    path.write_text(json.dumps(value, sort_keys=True, indent=2, allow_nan=False)+"\n")


def call_frame(index, step, record):
    request = record["request"]
    output = record.get("output_buffer", record["response"])
    workspace = record.get("state", b"")
    return (b"HSCALL01" + struct.pack("<7Q", index, step, OWNERS[record["owner"]], record["code"],
            len(request), len(output), len(workspace)) + request + output + workspace)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime", type=Path, required=True)
    parser.add_argument("--build", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    runtime = args.runtime.resolve(strict=True)
    build_path = args.build.resolve(strict=True)
    builds = json.loads(build_path.read_bytes())
    if "modules" in builds:
        builds = builds["modules"]
    manifests = {}
    for name, row in builds.items():
        path = Path(row["manifest"])
        path = path if path.is_absolute() else build_path.parent/path
        assert SHA(path.read_bytes()) == row["manifest_sha256"], name
        manifests[name] = path
    assert set(manifests) == set(OWNERS)
    output = args.output.absolute()
    output.mkdir(parents=True, exist_ok=False)
    report = dict(schema="hepta.scope-annotation.actual-native.v1", status="IN_PROGRESS", cases=[],
        execution=dict(pid=os.getpid(), parent_pid=os.getppid(), cwd=str(Path.cwd().resolve())),
        build_sha256=SHA(build_path.read_bytes()), native_calls=0, owner_calls={},
        input_bytes=0, input_sha256=None, output_bytes=0, output_sha256=None,
        call_capture_bytes=0, call_capture_sha256=None, typed_comparisons=0, typed_profile_exclusions=[],
        capture_domain="every complete input; full annotation output capacity and control/action bytes; exact child request/result spans; complete annotated text and actual SDK wire",
        full_child_workspace_capture=False, original_execution_qualified=False,
        production_activated=False, whole_runtime_replaced=False)
    save = lambda: dump(output/"result.json", report)
    save()
    input_hash, result_hash, call_hash = (hashlib.sha256() for _ in range(3))
    started = time.monotonic()
    rows = cases()
    try:
        with Transport(runtime, manifests) as transport, gzip.open(output/"inputs.bin.gz", "wb", compresslevel=1) as inputs, \
             gzip.open(output/"native.bin.gz", "wb", compresslevel=1) as results, \
             gzip.open(output/"calls.bin.gz", "wb", compresslevel=1) as calls_out:
            for row in rows:
                framed = input_frame(row)
                p = packet(framed)
                inputs.write(p); input_hash.update(p); report["input_bytes"] += len(p)
                actual = transport.run(framed)
                assert actual["code"] < 0xffff0000, (row["label"], actual["code"])
                response, annotation, wire = (actual[k] for k in ("response", "annotation", "wire"))
                kind, size, wire_size, category, annotation_size, zero1, zero2 = UNPACK(response[8:64])
                assert wire_size == len(wire) and annotation_size == len(annotation)
                assert (kind, category) in ((0, 0), (1, 1), (1, 2), (1, 3))
                assert category != 0 or response[64:] == annotation
                assert not wire or (kind == int(len(wire)>65536))
                for key, value in (("expected_wire_bytes", len(wire)), ("expected_kind", kind), ("expected_category", category)):
                    if key in row:
                        assert row[key] == value, (row["label"], key, row[key], value)
                if wire:
                    typed = transport.check_typed(annotation, wire)
                    if typed is not None:
                        typed["owner"] = "typed_result_json"
                        actual["calls"].append(typed)
                        report["typed_comparisons"] += 1
                    else:
                        report["typed_profile_exclusions"].append(dict(index=row["index"], label=row["label"],
                            reason="the complete trusted typed projection exceeds the existing 8 MiB typed profile; the unchanged original function remains mandatory"))
                record = packet(observed_frame(response, annotation, wire))
                results.write(record); result_hash.update(record); report["output_bytes"] += len(record)
                first_call = report["native_calls"]
                for step, call in enumerate(actual["calls"]):
                    encoded = packet(call_frame(row["index"], step, call))
                    calls_out.write(encoded); call_hash.update(encoded); report["call_capture_bytes"] += len(encoded)
                    report["native_calls"] += 1
                    report["owner_calls"][call["owner"]] = report["owner_calls"].get(call["owner"], 0)+1
                report["cases"].append(dict(index=row["index"], label=row["label"], input_bytes=len(framed),
                    input_sha256=SHA(framed), response_bytes=len(response), response_sha256=SHA(response),
                    annotation_bytes=len(annotation), annotation_sha256=SHA(annotation), wire_bytes=len(wire), wire_sha256=SHA(wire),
                    kind=kind, category=category, first_call=first_call, call_count=len(actual["calls"])))
                if row["index"] % 64 == 0:
                    save()
        report.update(status="HIA_NATIVE_PASS", input_sha256=input_hash.hexdigest(),
                      output_sha256=result_hash.hexdigest(), call_capture_sha256=call_hash.hexdigest())
    finally:
        report["elapsed_seconds"] = time.monotonic()-started
        save()
    print(json.dumps({k: report[k] for k in ("status", "native_calls", "owner_calls", "typed_comparisons", "input_bytes", "output_bytes", "call_capture_bytes", "elapsed_seconds")}, sort_keys=True))


if __name__ == "__main__":
    main()
