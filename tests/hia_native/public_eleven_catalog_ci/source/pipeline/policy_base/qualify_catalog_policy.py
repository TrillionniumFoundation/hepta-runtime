"""Independent complete-byte comparison against retained actual handler runs.

No part of this program or its expected outputs is an authoring input.
"""
from __future__ import annotations
import argparse
import copy
import gzip
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import sys
import time
sys.dont_write_bytecode = True

TARGET = "d3d75c30719db966b004756f610007a7c723729e"
PROFILES = ("disabled", *(str(i) for i in range(8)))

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def dump(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")

def framed(mode, flags, modern, body):
    return b"HCATCQ01" + struct.pack("<7Q", mode, flags, modern, len(body), 0, 0, 0) + body

def load_module(manifest, runtime):
    sys.path.insert(0, str(runtime / "scripts"))
    from hia_native_loader import NativeModule
    return NativeModule(manifest, manifest_sha256=sha(manifest.read_bytes()))

def policy_call(module, wire, output, label, workspace_capacity=16384, output_capacity=64):
    records = []
    while True:
        code, full_output, full_workspace = module.invoke_raw(wire, output_capacity=output_capacity,
            workspace_capacity=workspace_capacity, output_fill=0xA7, workspace_fill=0x59)
        prefix = output / (label + f"-call-{len(records)}")
        prefix.with_suffix(".input.gz").write_bytes(gzip.compress(wire, mtime=0))
        prefix.with_suffix(".output.gz").write_bytes(gzip.compress(full_output, mtime=0))
        prefix.with_suffix(".workspace.gz").write_bytes(gzip.compress(full_workspace, mtime=0))
        row = {"code": code, "output_capacity": output_capacity, "workspace_capacity": workspace_capacity,
            "input_sha256": sha(wire), "output_sha256": sha(full_output), "workspace_sha256": sha(full_workspace),
            "prefix": prefix.name}
        records.append(row)
        assert full_output[:8] == b"HCATCR01", row
        status, offset, size, count, flags, modern, reserved = struct.unpack_from("<7Q", full_output, 8)
        assert flags == struct.unpack_from("<Q", wire, 16)[0] and modern == struct.unpack_from("<Q", wire, 24)[0] and reserved == 0
        if status == 0:
            assert offset == 64 and code == 64 + size and full_output[code:] == bytes((0xA7,)) * (output_capacity - code)
            return full_output[64:code], count, records
        assert code == 64 and offset == count == 0 and full_output[64:] == bytes((0xA7,)) * (output_capacity - 64)
        assert status in (2, 3), row
        if status == 2:
            assert size > workspace_capacity and size <= module.metadata["workspace_capacity"]
            workspace_capacity = size
        else:
            assert size > output_capacity and size <= module.metadata["output_capacity"]
            output_capacity = size
        assert len(records) < 4

def child_record(output, label, wire, code, out, workspace, output_capacity, workspace_capacity):
    for suffix, raw in (("input", wire), ("output", out), ("workspace", workspace)):
        (output / (label + "." + suffix + ".gz")).write_bytes(gzip.compress(raw, compresslevel=6, mtime=0))
    return {"prefix": label, "code": code, "input_sha256": sha(wire), "output_sha256": sha(out),
        "workspace_sha256": sha(workspace), "output_capacity": output_capacity, "workspace_capacity": workspace_capacity}

def canonical_call(module, body, output, label):
    wire = b"HSJVAL01" + struct.pack("<2Q", 1, len(body)) + body
    code, out, workspace = module.invoke_raw(wire, output_capacity=max(8192, len(body) * 2 + 4096),
        workspace_capacity=32 << 20, output_fill=0xA7, workspace_fill=0x59)
    assert 0 < code <= len(out), (code, out[:64])
    assert out[code:] == bytes((0xA7,)) * (len(out) - code)
    return out[:code], child_record(output, label, wire, code, out, workspace, len(out), len(workspace))

def sdk_call(module, body, output, label):
    wire = b"HRRSP001" + struct.pack("<2Q", 4, len(body)) + body
    code, out, workspace = module.invoke_raw(wire, output_capacity=max(8192, len(body) * 2 + 4096),
        workspace_capacity=96 << 20, output_fill=0xA7, workspace_fill=0x59)
    assert out[:8] == b"HRRPO001", (code, out[:64])
    kind, flags, offset, size, policy, zero_a, zero_b = struct.unpack_from("<7Q", out, 8)
    assert flags == policy == zero_a == zero_b == 0 and offset == 64 and code == 64 + size, (code, out[:64])
    assert kind == 4 and out[code:] == bytes((0xA7,)) * (len(out) - code)
    return out[offset:offset + size], {**child_record(output, label, wire, code, out, workspace, len(out), len(workspace)), "kind": kind}

def run(args):
    root = args.source
    output = args.output
    output.mkdir(parents=True, exist_ok=False)
    policy = load_module(args.build / "modules/catalog-policy/manifest.json", args.runtime)
    serde = load_module(args.build / "modules/serde-json/manifest.json", args.runtime)
    sdk = load_module(args.build / "modules/sdk-catalog-wide/manifest.json", args.runtime)
    spec = importlib.util.spec_from_file_location("original_catalog_reader", args.evidence / "recipe-source/verify.py")
    reference = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(reference)
    asset = json.loads((root / "declarations.json").read_bytes())
    raw_input = (root / "catalog-input.json").read_bytes()
    observations = {profile: json.loads((args.evidence / f"processes/profile-{profile}.stdout").read_bytes()) for profile in PROFILES}
    start = time.monotonic()
    results = []
    calls = 0
    # All 119 ordinary and 17 frozen complete original schema values.
    for index, raw in enumerate(asset["raw_tool_wires"]):
        tool = json.loads(raw)
        frozen = tool["name"] in set(asset["hia_tool_names"]) | reference.FROZEN
        original = tool["inputSchema"]
        expected = copy.deepcopy(original)
        if not frozen:
            for value in expected.values():
                reference.strip_null(value)
            reference.strip_noise(expected)
        body = json.dumps(original, ensure_ascii=False, separators=(",", ":")).encode()
        got, count, rows = policy_call(policy, framed(3 if frozen else 2, 0, 0, body), output, f"schema-{index:03d}")
        assert count == 1 and json.loads(got) == expected, tool["name"]
        expected_raw = json.dumps(expected, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
        (output / f"schema-{index:03d}.expected").write_bytes(expected_raw)
        results.append({"domain": "frozen-schema" if frozen else "ordinary-schema", "index": index, "name": tool["name"], "calls": rows})
        calls += len(rows)
    # Complete input byte equality establishes the 18 equivalence classes.
    # All 216 real handler observations retain their own context and wire.
    shapes = {}
    handler_rows = 0
    for profile in PROFILES:
        observation = observations[profile]
        flags = 0 if profile == "disabled" else 1 | (int(profile) << 1)
        assert observation["target_commit"] == TARGET and len(observation["list_cases"]) == 24
        for index, case in enumerate(observation["list_cases"]):
            modern = int(case["protocol_version"] in ("2026-07-28", "2026-08-01"))
            label = f"catalog-{profile}-{index:02d}"
            wire = framed(1, flags, modern, raw_input)
            if wire not in shapes:
                shape = f"shape-{len(shapes):02d}"
                got, count, rows = policy_call(policy, wire, output, shape)
                canonical, serde_row = canonical_call(serde, got, output, shape + "-serde")
                typed, sdk_row = sdk_call(sdk, canonical, output, shape + "-sdk")
                for suffix, raw in (("policy-json", got), ("canonical-json", canonical), ("typed-json", typed)):
                    (output / (shape + "." + suffix + ".gz")).write_bytes(gzip.compress(raw, mtime=0))
                shapes[wire] = {"name": shape, "count": count, "calls": rows, "serde": serde_row, "sdk": sdk_row,
                    "typed": typed, "flags": flags, "modern": modern, "input_sha256": sha(wire)}
                calls += len(rows) + 2
            shape_row = shapes[wire]
            typed, count = shape_row["typed"], shape_row["count"]
            expected = case["result_wire"].encode()
            (output / (label + ".expected.gz")).write_bytes(gzip.compress(expected, mtime=0))
            assert count == case["tool_count"] and typed == expected, (profile, index, count, case["tool_count"], sha(typed), sha(expected))
            results.append({"domain": "actual-handler", "profile": profile, "case": index,
                "protocol_version": case["protocol_version"], "cursor_case": case["cursor_case"],
                "tool_count": count, "shape": shape_row["name"], "abi_input_sha256": sha(wire),
                "wire_bytes": len(typed), "wire_sha256": sha(typed)})
            handler_rows += 1
    assert len(shapes) == 18 and handler_rows == 216
    result = {"schema": "hepta.runtime.catalog-policy-development.v2", "status": "PASS",
        "actual_handler_cases": 216, "ordinary_schema_cases": 119, "frozen_schema_cases": 17,
        "native_calls": calls, "unique_catalog_abi_shapes": len(shapes),
        "catalog_native_calls": sum(len(row["calls"]) + 2 for row in shapes.values()),
        "shapes": [{key: value for key, value in row.items() if key != "typed"} for row in shapes.values()],
        "rows": results, "elapsed_seconds": time.monotonic() - start,
        "target_commit": TARGET, "fresh_original_build": False, "whole_runtime_replaced": False,
        "production_activated": False, "old_stack_removal_qualified": False}
    dump(output / "result.json", result)
    return result

def main():
    parser = argparse.ArgumentParser()
    for name in ("source", "build", "runtime", "evidence", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    try:
        result = run(args)
    except BaseException as exc:
        if args.output.is_dir():
            dump(args.output / "failure.json", {"type": type(exc).__name__, "message": str(exc)})
        raise
    print(json.dumps({key: value for key, value in result.items() if key != "rows"}, sort_keys=True))

if __name__ == "__main__":
    main()
