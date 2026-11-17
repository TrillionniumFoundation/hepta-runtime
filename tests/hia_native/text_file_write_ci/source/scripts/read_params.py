#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Read every retained native buffer and actual Rust typed response without execution."""
from __future__ import annotations
from pathlib import Path
import gzip
import struct
from common import B3, HEPTA, canonical, decode, owned, pin, require, sha, source_evidence
import params_cases

word = lambda raw, at: struct.unpack_from("<Q", raw, at)[0]


def build_evidence(source, output):
    source, output = Path(source), Path(output)
    bundle = decode(owned(output, "build/typed-params.json").read_bytes())
    require(bundle["schema"] == "hepta.runtime.text-publisher.typed-build.v1", "build schema changed")
    require(set(bundle["members"]) == {"serde_json_span", "text_file_write_params"}, "build member set changed")
    require(bundle["compiler_commit"] == HEPTA and bundle["compiler_sha256"] == B3, "build compiler changed")
    bootstrap = decode(owned(output, "build/bootstrap/bootstrap.json").read_bytes())
    require(bootstrap["generation_sha256"] == B3 and bootstrap["qualification"] == "development_fixed_point", "bootstrap identity changed")
    dependency = bootstrap["dependency"]
    require(dependency["commit"] == HEPTA and dependency["tree"] == "8d8b0fb8d015fb7edab302498bb9ed4c74ab6f49", "compiler source commit/tree changed")
    for path, digest in dependency["files"].items():
        require(pin(owned(output, "compiler-source/" + path))["sha256"] == digest, "compiler dependency file changed: " + path)
    for generation in ("B1", "B2", "B3"):
        require(pin(owned(output, "build/bootstrap/" + generation + ".image.bin"))["sha256"] == B3, "bootstrap generation changed")
    artifacts = {"build/typed-params.json": pin(output / "build/typed-params.json")}
    for name, row in bundle["members"].items():
        path = owned(output, row["manifest"])
        require(pin(path)["sha256"] == row["manifest_sha256"], "member manifest changed")
        metadata = decode(path.read_bytes())
        require(metadata["source_sha256"] == row["source_sha256"] == pin(owned(source, "native/" + name + ".hepta"))["sha256"], "member source changed")
        require(metadata["image_sha256"] == row["image_sha256"], "member image declaration changed")
        require(metadata["compiler_commit"] == HEPTA and metadata["compiler_sha256"] == B3 and metadata["buffer_profile"] == "history.v1" and metadata["standalone"] is None, "member ABI changed")
        require([metadata[k] for k in ("input_capacity", "output_capacity", "workspace_capacity")] == [128 << 20, 128 << 20, 256 << 20], "member capacities changed")
        module_source = owned(path.parent, metadata["source"]).read_bytes()
        image = owned(path.parent, metadata["image"]).read_bytes()
        require(sha(module_source) == metadata["source_sha256"] and sha(image) == metadata["image_sha256"], "actual member bytes changed")
        request = decode(owned(path.parent, "module.request.json").read_bytes())
        receipt = decode(owned(path.parent, "module.receipt.json").read_bytes())
        raw_output = owned(path.parent, "module.output.bin").read_bytes()
        require(owned(path.parent, "module.input.bin").read_bytes() == module_source, "compiled input differs from published source")
        require(receipt["status"] == "returned" and type(receipt["abi_status"]) is int and receipt["abi_status"] == 0 and type(receipt["core_u32"]) is int, "compile did not return cleanly")
        require(receipt["core_u32"] == receipt["result_u64"] == receipt["produced_bytes"] == len(image) and image == raw_output[:len(image)], "compiled complete output/image differs")
        require(receipt["source_unchanged"] is True and receipt["forbidden_compiler_modules_loaded"] == [] and receipt["artifact_sha256"] == B3, "compile custody changed")
        require(receipt["input_bytes"] == len(module_source) and receipt["input_sha256"] == sha(module_source) and receipt["output_sha256"] == sha(raw_output) and receipt["produced_sha256"] == sha(image), "compile complete input/output hash differs")
        require(request["source_sha256"] == sha(module_source) and request["image_sha256"] == B3 and request["format"] == "flat-x86-64", "compile request changed")
        build = decode(owned(path.parent, "build.json").read_bytes())
        require(build["compile_receipt"] == receipt and build["compiler_dependency"] == dependency, "member build source closure changed")
        for artifact in (path, path.parent / metadata["source"], path.parent / metadata["image"]):
            artifacts[artifact.relative_to(output).as_posix()] = pin(artifact)
    return artifacts


def frame(owner, code, out):
    header = 32 if owner == 1 else 128
    require(code == header and out[:8] == (b"HJSVR002" if owner == 1 else b"HTPPRR01"), "native response framing changed")
    status = word(out, 8)
    require(status in ((0, 1, 2, 3, 5) if owner == 1 else (0, 1, 2, 3)), "native response status changed")
    needed = word(out, 24 if owner == 1 else 80)
    if status in (2, 3):
        require(needed > 0, "growth omitted minimum")
        extent = header
    else:
        require(needed == 0, "completion requested growth")
        extent = header + (word(out, 16) if owner == 1 else
            sum(word(out, at) for at in (24, 32, 40)) if status == 0 else word(out, 72))
    require(extent <= len(out) and out[extent:] == b"\xa5" * (len(out) - extent), "native complete output extent/tail changed")
    if owner == 2:
        require(out[48:72] == bytes(24) and out[88:128] == bytes(40), "typed reserved words changed")
        if status:
            require(out[16:72] == bytes(56), "typed error exposes success fields")
        else:
            require(word(out, 16) in (1, 2, 3) and word(out, 72) == 0, "typed mode/error fields changed")
            out[128:extent].decode()
    return status, needed, out[:extent]


def read_capture(source, output):
    source, output = Path(source), Path(output)
    folder = output / "native"
    summary = decode(owned(folder, "capture-result.json").read_bytes())
    require(summary["status"] == "PASS" and summary["original_results_read"] is False and summary["original_handler_executed"] is False and summary["public_route_replaced"] is False, "native capture failed or scope changed")
    require(summary["source_inputs"] == source_evidence(source), "capture source closure changed")
    require(summary["artifacts"] == build_evidence(source, output), "capture did not use the actual fresh build")
    read = lambda name: [decode(line) for line in owned(folder, name).read_bytes().splitlines()]
    index, declared, results, controls = [read(name) for name in ("calls.jsonl", "native-cases.jsonl", "native-results.jsonl", "controls.jsonl")]
    domain = params_cases.cases()
    require(owned(folder, "input.jsonl").read_bytes() == params_cases.encoded(), "fixed input domain changed")
    require(len(domain) == 259 and len(declared) == len(results) == len(domain) == summary["cases"], "typed cases omitted")
    require(len(index) == summary["native_calls"] and len(controls) == summary["controls"] == 34, "native calls/controls omitted")
    semantic = {}
    for case, row, result in zip(domain, declared, results):
        require([row["case_id"], row["name"]] == [result["case_id"], result["name"]] == [case["case_id"], case["name"]], "case order changed")
        require(row["input_sha256"] == sha(case["raw_json"].encode()), "case input changed")
        for owner, key in ((1, "value_calls"), (2, "params_calls")):
            calls = row[key]
            require(type(calls) is list and (calls or owner == 2 and not row["value_admitted"]) and len(calls) <= 12, "call chain changed")
            for position, call in enumerate(calls):
                require(type(call) is int and 1 <= call <= len(index) and call not in semantic, "call duplicate/out of range")
                semantic[call] = (owner, case, row, result["result"], position, len(calls))
    control_calls = set()
    for row in controls:
        calls = ([row["call"]] if "call" in row else row.get("calls", [])) + row.get("resume_calls", [])
        for call in calls:
            require(type(call) is int and 1 <= call <= len(index) and call not in semantic and call not in control_calls, "control call duplicated")
            control_calls.add(call)
    require(set(semantic) | control_calls == set(range(1, len(index) + 1)), "unattributed native calls")
    prior, completed, saved_controls = {}, {}, {}
    offset = 0
    with gzip.open(owned(folder, "calls.bin.gz"), "rb") as stream:
        for ordinal, row in enumerate(index, 1):
            require(type(row["bytes"]) is int and 64 <= row["bytes"] <= 32 << 20, "native record length invalid")
            raw = stream.read(row["bytes"])
            require(len(raw) == row["bytes"] and sha(raw) == row["record_sha256"] and row["call"] == ordinal and row["offset"] == offset, "complete native record changed")
            fields = struct.unpack_from("<8Q", raw)
            require(fields == (ordinal, row["owner"], row["case_id"], row["return_code"], row["input_bytes"], row["output_capacity"], row["workspace_capacity"], 0), "record header changed")
            _, owner, cid, code, inp, ocap, wcap, _ = fields
            cursor, arrays = 64, []
            for size, label in ((inp, "input"), (wcap, "before"), (ocap, "output_before"), (ocap, "output"), (wcap, "after")):
                part = raw[cursor:cursor+size]
                require(len(part) == size and sha(part) == row[label + "_sha256"], "complete buffer changed: " + label)
                arrays.append(part); cursor += size
            require(cursor == len(raw), "unbound record suffix")
            wire, before, old, out, after = arrays
            require(owner in (1, 2) and old == b"\xa5" * ocap, "owner/output initialization changed")
            if ordinal in semantic:
                wanted_owner, case, declaration, result, position, length = semantic[ordinal]
                require(owner == wanted_owner and cid == case["case_id"] and row["label"] == "semantic", "semantic call identity changed")
                if owner == 1:
                    value = case["raw_json"].encode()
                    expected_wire = b"HJSMS002" + struct.pack("<2Q", 1, len(value)) + value
                else:
                    require((cid, 1) in completed, "typed call preceded actual Map result")
                    value = completed[cid, 1][32:]
                    expected_wire = b"HTPPRQ01" + struct.pack("<2Q", len(value), 0) + value
                require(wire == expected_wire, "actual composed input changed")
                if position == 0:
                    require(before == bytes(16512 if owner == 1 else 65536) and ocap == (32 if owner == 1 else 128), "first-call capacity changed")
                else:
                    status0, need0, after0, cap0 = prior[cid, owner]
                    require(status0 in (2, 3), "replayed completed native call")
                    require(before == (after0 + bytes(need0 - len(after0)) if status0 == 2 else after0) and ocap == (cap0 if status0 == 2 else need0), "growth lost or replaced retained state")
                status, needed, final = frame(owner, code, out)
                if status in (2, 3):
                    require(position + 1 < length and needed > (wcap if status == 2 else ocap), "growth missing continuation")
                else:
                    require(position + 1 == length, "native terminal result retried")
                    completed[cid, owner] = final
                    if owner == 1:
                        require(result["value_admitted"] == declaration["value_admitted"] == (status == 0), "Map outcome changed")
                        if status == 0:
                            require(result["canonical"] == final[32:].decode(), "actual canonical bytes changed")
                        else:
                            require(not declaration["params_calls"] and not declaration["typed_success"], "refused Map reached typed parser")
                    else:
                        require(final.hex() == result["frame_hex"] and result["ok"] == declaration["typed_success"] == (status == 0), "typed complete result changed")
                prior[cid, owner] = status, needed, after, ocap
            else:
                saved_controls[ordinal] = (row, wire, before, out, after)
                if code in (0xffffffff, 0xfffffffe):
                    require(before == after and out == old, "private refusal modified caller bytes")
                else:
                    frame(owner, code, out)
            offset += len(raw)
        require(stream.read(1) == b"", "unbound native stream suffix")
    require(offset == summary["full_record_bytes"], "full byte count changed")
    require(sum(r["value_admitted"] for r in declared) == summary["value_admitted"] and sum(r["typed_success"] for r in declared) == summary["typed_successes"], "semantic totals changed")
    control_evidence(controls, saved_controls)
    return dict(status="PASS", cases=len(domain), calls=len(index), controls=len(controls),
                full_record_bytes=offset, value_admitted=summary["value_admitted"], typed_successes=summary["typed_successes"],
                results=results, stream=pin(folder / "calls.bin.gz"))


def control_evidence(controls, records):
    sequence = ["reference"] + ["short-output"] * 3 + ["output-boundary"] * 4 + ["workspace-growth"] * 3 + ["dirty-workspace"] * 3
    require([r["kind"] for r in controls] == sequence * 2 + ["invalid-frame"] * 6, "control sequence changed")
    values = [b'{"content":"a\\nb","expected_sha256":"absent","mode":"create","path":"p"}',
              b'{"content":"x","expected_sha256":"absent","mode":"?","path":"p"}']
    wires = [b"HTPPRQ01" + struct.pack("<2Q", len(value), 0) + value for value in values]
    invalid = [b"", wires[0][:7], wires[0][:24], b"XXXXXXXX" + wires[0][8:],
               wires[0][:8] + struct.pack("<Q", len(values[0]) + 1) + wires[0][16:],
               wires[0][:16] + struct.pack("<Q", 1) + wires[0][24:]]
    refs, dirty = {}, {}
    for number, row in enumerate(controls):
        if row["kind"] == "reference":
            last = records[row["calls"][-1]]
            require(last[1] == wires[number // 14], "control reference input differs from frozen domain")
            status, _, result = frame(2, last[0]["return_code"], last[3])
            require(status in (0, 1) and sha(result) == row["response_sha256"], "control reference changed")
            refs[last[1]] = result
            previous = None
            for call in row["calls"]:
                actual, wire, before, out, after = records[call]
                require(actual["label"] == "control-reference" and wire == last[1], "control reference input changed")
                if previous is not None:
                    ps, pn, pa, po = previous
                    require(ps in (2, 3) and before == (pa + bytes(pn - len(pa)) if ps == 2 else pa) and len(out) == (po if ps == 2 else pn), "control reference growth changed")
                else:
                    require(before == bytes(65536) and len(out) == 128, "control reference initial state changed")
                st, need, _ = frame(2, actual["return_code"], out); previous = st, need, after, len(out)
            continue
        actual, wire, before, out, after = records[row["call"]]
        kind = row["kind"]
        require(actual["owner"] == 2 and actual["label"] == kind, "control label/owner changed")
        if kind == "invalid-frame":
            require(wire == invalid[number - 28] and before == b"\x7b" * 40000 and len(out) == 256, "private refusal domain changed")
            require(actual["return_code"] == 0xffffffff and before == after and out == b"\xa5" * len(out), "invalid private frame accepted")
        elif kind == "short-output":
            require(wire == wires[number // 14] and len(out) == (0, 1, 127)[number % 14 - 1] and before == b"\x7b" * (len(wire) + 65536), "short-output input changed")
            require(actual["return_code"] == 0xfffffffe and before == after and out == b"\xa5" * len(out), "short-output control changed")
        else:
            require(wire in refs, "unbound control wire")
            full = refs[wire]
            status, needed, result = frame(2, actual["return_code"], out)
            if kind == "output-boundary":
                require(len(out) == (128, len(full) - 1, len(full), len(full) + 17)[number % 14 - 4] and before == b"\x7b" * (len(wire) + 65536), "output boundary input changed")
                require(row["required"] == len(full), "output required extent changed")
                require((status == 3 and needed == len(full)) if len(out) < len(full) else result == full, "output boundary changed")
            elif kind == "dirty-workspace":
                expected = b"\x7b" * (len(wire) + 65536) if number % 14 == 11 else dirty[wire]
                require(before == expected, "dirty workspace state was replaced")
                require(result == full and len(out) == len(full) + 7, "dirty reuse changed complete result")
                dirty[wire] = after
            else:
                require(before == b"\x7b" * (0, 1, len(wire) + 65535)[number % 14 - 8] and len(out) == len(full) + 11, "workspace growth input changed")
                require(kind == "workspace-growth" and status == 2 and needed == len(wire) + 65536 and before == after, "workspace refusal changed caller state")
                current = after + bytes(needed - len(after))
                capacity = len(full)
                for call in row["resume_calls"]:
                    rr, rw, rb, ro, ra = records[call]
                    require(rr["owner"] == 2 and rr["label"] == "growth-resume" and rw == wire and rb == current and len(ro) == capacity, "resume did not preserve actual state")
                    st, need, rf = frame(2, rr["return_code"], ro)
                    if st == 2:
                        current = ra + bytes(need - len(ra))
                    elif st == 3:
                        current, capacity = ra, need
                    else:
                        require(call == row["resume_calls"][-1] and rf == full, "resumed complete result changed")


def compare_original(output, capture):
    output = Path(output)
    rows = [decode(line) for line in owned(output, "processes/original.stdout").read_bytes().splitlines()]
    require(len(rows) == len(capture["results"]), "original result count changed")
    for original, native in zip(rows, capture["results"]):
        require(original["case_id"] == native["case_id"] and original["name"] == native["name"], "original case order changed")
        a, b = original["result"], native["result"]
        require(a["value_admitted"] == b["value_admitted"], "original Map admission differs: " + native["name"])
        if a["value_admitted"]:
            require({k: a[k] for k in ("canonical", "ok", "frame_hex")} == {k: b[k] for k in ("canonical", "ok", "frame_hex")}, "original complete canonical/typed wire differs: " + native["name"])
    return dict(status="PASS", cases=len(rows), stdout=pin(output / "processes/original.stdout"), complete_typed_wire=True)
