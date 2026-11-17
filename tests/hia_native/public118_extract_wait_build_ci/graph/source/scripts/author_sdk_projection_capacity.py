#!/usr/bin/env python3
"""Reuse the retired staging slab for the admitted internal SDK projection.

All JSON/type/field parsers are byte-for-byte retained. Parent input and
completed output spans are disjoint throughout the child invocation. After the request child
has completed, the controller reuses TEMP and copies each retired source
forward before dispatch. The leaf keeps its old short-arena refusal;
an otherwise valid wider internal frame can request a larger copy arena.
"""
from pathlib import Path
import argparse
import copy
import hashlib
import json
import re
import sys

BASE = {
    "sdk_public_protocol.hepta": "be0e970f61919906470f4eff2b9a713e293ab26939710e0985501fd541074403",
    "sdk_frontend_bridge_target.hepta": "56f73f52f3ac0df142e2f44ed8555770e29f76623a76d43ac72be05148204635",
}
INTERNAL_MAX = 160 << 20
BRIDGE_START = 176160768
COPY_START = 32 << 20
sha = lambda raw: hashlib.sha256(raw).hexdigest()
encoded = lambda value: (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()


class Edit:
    def __init__(self, function):
        self.function = function
        self.next_value = max(int(x) for x in re.findall(r"\bv(\d+)\b", json.dumps(function))) + 1
        self.next_block = max(int(b["id"][1:]) for b in function["blocks"]) + 1

    def param(self, typ):
        result = {"name": "v" + str(self.next_value), "type": typ}
        self.next_value += 1
        return result

    def op(self, ops, opcode, typ, args=(), **attrs):
        p = self.param(typ)
        ops.append({"op": opcode, "out": [p], "args": list(args), "attrs": attrs})
        return p["name"]

    def const(self, ops, value):
        return self.op(ops, "const", "u64", value=value)

    def block(self, types):
        b = {"id": "b" + str(self.next_block), "params": [self.param(t) for t in types], "ops": []}
        self.next_block += 1
        return b


def block(function, name):
    return next(b for b in function["blocks"] if b["id"] == name)


def set_const(function, bname, out, before, after):
    b = block(function, bname)
    op = next(op for op in b["ops"] if op["out"] == [{"name": out, "type": "u64"}])
    assert op == {"op": "const", "out": [{"name": out, "type": "u64"}], "args": [], "attrs": {"value": before}}
    op["attrs"]["value"] = after


def controller(program):
    f = program["functions"][8]
    set_const(f, "b10", "v84", 32 << 20, INTERNAL_MAX)
    set_const(f, "b12", "v99", 32 << 20, INTERNAL_MAX)
    # TEMP is retired after request completion; the next child consumes this
    # complete packed input; its reply uses the disjoint retired BRIDGE slab.
    # The existing forward copy is overlap-safe for each source: original is
    # disjoint, then destination < MESSAGE, then destination < REQUEST.
    set_const(f, "b16", "v136", BRIDGE_START, 20 << 20)
    e = Edit(f)
    packed = block(f, "b16")
    final = packed["ops"].pop()
    assert final["attrs"] == {"function": "f5"} and final["args"][-2:] == ["v168", "v168"]
    output_start = e.const(packed["ops"], BRIDGE_START)
    final["args"][-2] = output_start
    packed["ops"].append(final)
    # The growth engine forbids overlapping parent input/output spans. Read
    # phase-3 completed output from BRIDGE; historical phase 4 and synthetic
    # phase 6 keep TEMP. A capacity retry leaves that exact phase unchanged.
    finish = program["functions"][9]
    for bname, name, workspace in (("b2", "v24", "v16"),
            ("b4", "v41", "v33"), ("b12", "v131", "v122")):
        op = next(o for o in block(finish, bname)["ops"] if o["out"] == [{"name": name, "type": "u64"}])
        assert op == {"op": "const", "out": [{"name": name, "type": "u64"}], "args": [], "attrs": {"value": 20 << 20}}
        op.update(op="call", args=[workspace], attrs={"function": "f18"})
    assert len(program["functions"]) == 18
    program["functions"].append({"name": "f18", "params": [{"name": "v0", "type": "mutbuf"}],
        "returns": ["u64"], "effects": ["read", "write", "trap"], "entry": "b0", "blocks": [
        {"id": "b0", "params": [{"name": "v0", "type": "mutbuf"}], "ops": [
            {"op": "const", "out": [{"name": "v1", "type": "u64"}], "args": [], "attrs": {"value": 8}},
            {"op": "call", "out": [{"name": "v2", "type": "u64"}], "args": ["v0", "v1"], "attrs": {"function": "f2"}},
            {"op": "const", "out": [{"name": "v3", "type": "u64"}], "args": [], "attrs": {"value": 3}},
            {"op": "compare.eq", "out": [{"name": "v4", "type": "bool"}], "args": ["v2", "v3"], "attrs": {}}],
            "term": {"op": "branch", "cond": "v4", "then": {"target": "b1", "args": []}, "else": {"target": "b2", "args": []}}},
        {"id": "b1", "params": [], "ops": [
            {"op": "const", "out": [{"name": "v5", "type": "u64"}], "args": [], "attrs": {"value": BRIDGE_START}}],
            "term": {"op": "ret", "values": ["v5"]}},
        {"id": "b2", "params": [], "ops": [
            {"op": "const", "out": [{"name": "v6", "type": "u64"}], "args": [], "attrs": {"value": 20 << 20}}],
            "term": {"op": "ret", "values": ["v6"]}}]})


def leaf(program):
    f = program["functions"][0]
    e = Edit(f)
    set_const(f, "b1", "v17", 32 << 20, INTERNAL_MAX)
    old = block(f, "b39")
    assert old["term"] == {"op": "jump", "target": "b40", "args":
        ["v424", "v425", "v426", "v427", "v428", "v431", "v432", "v433", "v449"]}
    original_jump = copy.deepcopy(old["term"])
    check = e.block([p["type"] for p in old["params"]] + ["u64"])
    args = [p["name"] for p in check["params"]]
    inp, out, w, *rest = args
    available = rest[-1]
    ops = check["ops"]
    count = e.op(ops, "buffer.len", "usize", (inp,))
    count = e.op(ops, "int.cast", "u64", (count,), mode="wrap")
    start = e.const(ops, COPY_START)
    need = e.op(ops, "int.add.wrap", "u64", (start, count))
    short = e.op(ops, "compare.lt", "bool", (available, need))
    no = e.op(ops, "const", "bool", value=False)
    growth = e.block(["mutbuf", "u64"])
    gout, gneed = [p["name"] for p in growth["params"]]
    for offset, number in ((0, int.from_bytes(b"HGRWS002", "little")), (8, 1), (16, None), (24, 0)):
        at = e.const(growth["ops"], offset)
        value = gneed if number is None else e.const(growth["ops"], number)
        e.op(growth["ops"], "call", "u64", (gout, at, value), function="f6")
    code = e.const(growth["ops"], 0xFFFFFFD0)
    code = e.op(growth["ops"], "int.cast", "u32", (code,), mode="wrap")
    growth["term"] = {"op": "ret", "values": [code]}
    check["term"] = {"op": "branch", "cond": short,
        "then": {"target": growth["id"], "args": [out, need]},
        "else": {"target": "b40", "args": args[:-1] + [no]}}
    old["term"] = {"op": "branch", "cond": "v449",
        "then": {"target": original_jump["target"], "args": original_jump["args"]},
        "else": {"target": check["id"], "args": [p["name"] for p in old["params"]] + ["v447"]}}
    f["blocks"].extend((check, growth))


def author(hepta, baseline, output):
    sys.dont_write_bytecode = True
    sys.path.insert(0, str(hepta))
    from hepta.hia_agent_assembly import assemble_program, render_assembly
    generated, proofs = {}, {}
    for name, edit, changed in (("sdk_public_protocol.hepta", controller, ("f8", "f9")),
            ("sdk_frontend_bridge_target.hepta", leaf, ("f0",))):
        raw = (baseline / name).read_bytes()
        assert sha(raw) == BASE[name]
        old = assemble_program(raw).as_dict()
        assert render_assembly(old).encode() == raw
        program = copy.deepcopy(old)
        edit(program)
        final = render_assembly(program).encode()
        assert assemble_program(final).as_dict() == program
        actual = [a["name"] for a, b in zip(old["functions"], program["functions"][:len(old["functions"])], strict=True) if a != b]
        assert actual == list(changed)
        proofs[name] = {"baseline_sha256": sha(raw), "source_bytes": len(final), "source_sha256": sha(final),
            "changed_functions": actual, "added_functions": [f["name"] for f in program["functions"][len(old["functions"]):]], "retained_exact_functions": {
                a["name"]: sha(encoded(a)) for a, b in zip(old["functions"], program["functions"][:len(old["functions"])], strict=True) if a == b}}
        generated[name] = final
    max_projection = 40 + ((16 << 20) - 1) + ((64 << 20) - 24) + (64 << 20)
    assert max_projection < INTERNAL_MAX
    assert BRIDGE_START == 109051904 + (64 << 20)
    assert BRIDGE_START + INTERNAL_MAX < 1 << 32
    original_max, message_max, request_max = (16 << 20) - 1, (64 << 20) - 24, 64 << 20
    packed = 20 << 20
    assert 4096 + 32 + original_max < packed + 40
    assert packed + 40 + original_max < 41943040
    assert packed + 40 + original_max + message_max < 109051904
    assert packed + max_projection < BRIDGE_START
    assert packed + INTERNAL_MAX <= 218103808
    assert BRIDGE_START + (20 << 20) <= 218103808
    proof = {"schema": "hepta.runtime.sdk-internal-projection-growth.v1", "sources": proofs,
        "outer_transport_including_lf_limit_unchanged": 16 << 20,
        "maximum_existing_admitted_projection": max_projection, "internal_frame_limit": INTERNAL_MAX,
        "controller_minimum_workspace_unchanged": 218103808,
        "controller_workspace_request": None,
        "controller_reuses_retired_temp_after_completed_request": True,
        "controller_packed_input_start": 20 << 20,
        "controller_child_input_and_completed_output_disjoint": True,
        "controller_completed_output_span": [BRIDGE_START, BRIDGE_START + (20 << 20)],
        "completion_phase3_reads_bridge_phase4_and_phase6_keep_temp": True,
        "capacity_retry_preserves_completion_phase_and_does_not_repeat_child": True,
        "controller_packed_maximum_end": (20 << 20) + max_projection,
        "forward_copy_sources": {"original": [4128, 4128 + original_max],
            "message": [41943040, 41943040 + message_max], "request": [109051904, 109051904 + request_max]},
        "forward_copy_destinations_are_disjoint_or_strictly_below_each_source": True,
        "leaf_minimum_workspace_refusal_unchanged": 96 << 20,
        "leaf_workspace_request": "33554432 + complete_internal_frame_bytes",
        "copy_slab_starts_after_all_retained_control_and_string_storage": COPY_START,
        "connection_reply_32_mib_limit_unchanged": True,
        "all_parser_and_field_validation_functions_unchanged": True,
        "author_sha256": sha(Path(__file__).read_bytes()),
        "native_executed": False, "fresh_original_compared": False, "public_batch_qualified": False}
    output.mkdir(parents=True, exist_ok=False)
    for name, raw in generated.items():
        (output / name).write_bytes(raw)
    (output / "proof.json").write_bytes(encoded(proof))
    return proof


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--hepta", type=Path, required=True)
    p.add_argument("--baseline", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    a = p.parse_args()
    print(json.dumps(author(a.hepta.resolve(strict=True), a.baseline.resolve(strict=True), a.output.absolute()), sort_keys=True))
