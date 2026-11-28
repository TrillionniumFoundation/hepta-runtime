"""Compose the admitted private SessionOwner call before configured tool routing.

The baseline has already completed G1/G2 and request metadata admission. This
author adds only the fixed current-target authority edge and its continuation;
it does not accept an owner or authentication flag from a public request.
"""
from __future__ import annotations
import argparse
import copy
import hashlib
import json
from pathlib import Path
import sys

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from authoring_support import compile_delta, substitute

BASELINE = "311ccb1387c1d9f01e690fcda6b839d0dcd52514e6be6c63cd4a02f9c674c475"
sha = lambda raw: hashlib.sha256(raw).hexdigest()
encoded = lambda obj: (json.dumps(obj, sort_keys=True, indent=2) + "\n").encode()


def literal(name, raw, *, predicate=False):
    lines = [f"def {name}(w:mutbuf, at:u64) -> {'bool' if predicate else 'u64'}:"]
    for i in range(0, len(raw) // 8 * 8, 8):
        number = int.from_bytes(raw[i:i+8], "little")
        if predicate:
            lines += [f"    if get(w, at + {i}) != {number}:", "        return False"]
        else:
            lines.append(f"    put(w, at + {i}, {number})")
    for i in range(len(raw) // 8 * 8, len(raw)):
        if predicate:
            lines += [f"    if byte(w, at + {i}) != {raw[i]}:", "        return False"]
        else:
            lines.append(f"    store(w, at + {i}, {raw[i]})")
    lines.append("    return True" if predicate else f"    return at + {len(raw)}")
    return "\n".join(lines) + "\n"


def author(args):
    sys.path.insert(0, str(args.hepta))
    from hepta.hia_agent_assembly import assemble_program, render_assembly
    old = (args.baseline / "native/runtime_mcp.hepta").read_bytes()
    assert sha(old) == BASELINE
    comp = json.loads((args.baseline / "native/runtime_mcp_composition.json").read_bytes())
    before = assemble_program(old).as_dict()
    assert len(before["functions"]) == 60
    names = {**comp["functions"], "retained_authority_select": "f60", "retained_authority_prepare": "f61"}
    additions = dict(after_authority="f62", after_config_presence="f63", after_owner_projection="f64",
        authority_nibble="f65", authority_unavailable="f66", authority_request="f67",
        config_absent="f68", authority_error="f69")
    absent = b"runtime tools are disabled; start with --runtime-config <file>"
    error = b',"error":{"code":-32603,"message":"request authority unavailable; dispatch refused"}}'
    request = (b"HRAUTR01" + (3).to_bytes(8, "little") + bytes(16)).hex().encode()
    assert len(request) == 64
    constants = dict(CONFIG_QUERY=int.from_bytes(b"HRCFGQ01", "little"),
        CONFIG_RESULT=int.from_bytes(b"HRCFGM01", "little"), OWNER_RESULT=int.from_bytes(b"HROWR001", "little"),
        CONFIG_ABSENT_SIZE=len(absent), AUTHORITY_ERROR_SIZE=len(error), INVALID=0xffffffff)
    text = (Path(__file__).parent / "authority_frontend.txt").read_text()
    text += "\n" + literal("authority_request", request)
    text += "\n" + literal("config_absent", absent, predicate=True)
    text += "\n" + literal("authority_error", error)
    raw, _, retained = compile_delta(args.hepta, old, names, substitute(text, constants),
        {"select_tool": "f3", "prepare": "f8"}, additions,
        (("f3", "f60"), ("f8", "f61")))
    after = assemble_program(raw).as_dict()
    entry = after["functions"][0]
    blocks = {b["id"]: b for b in entry["blocks"]}
    changes = [("b19", "v161", 112, 114), ("b21", "v177", 12, 14)]
    for block, value, previous, current in changes:
        op = next(o for o in blocks[block]["ops"] if o["out"] == [{"name": value, "type": "u64"}])
        assert op["op"] == "const" and op["attrs"]["value"] == previous
        op["attrs"]["value"] = current
    old_term = copy.deepcopy(blocks["b57"]["term"])
    blocks["b57"]["ops"] += [
        dict(op="const", args=[], out=[dict(name="v70000", type="u64")], attrs=dict(value=12)),
        dict(op="compare.gt", args=["v467", "v70000"], out=[dict(name="v70001", type="bool")], attrs={})]
    blocks["b57"]["term"] = dict(op="branch", cond="v70001",
        then=dict(target="b72", args=["v464", "v465", "v466", "v468", "v469", "v467"]),
        **{"else": dict(target="b73", args=["v464", "v465", "v466", "v467", "v468", "v469", "v60001", "v50001", "v476"])})
    entry["blocks"] += [
        dict(id="b72", params=[dict(name="v7001" + str(i), type=t) for i,t in enumerate(["readbuf","mutbuf","mutbuf","u64","u64","u64"])],
            ops=[dict(op="call", args=["v7001"+str(i) for i in range(6)], out=[dict(name="v70016",type="u32")], attrs=dict(function="f62"))],
            term=dict(op="ret",values=["v70016"])),
        dict(id="b73", params=[dict(name="v7002"+str(i),type=t) for i,t in enumerate(["readbuf","mutbuf","mutbuf","u64","u64","u64","bool","bool","bool"])],
            ops=[], term=dict(op="branch", cond="v70026", then=dict(target="b70",args=["v70020","v70021","v70022","v70024","v70025"]),
                **{"else":dict(target="b71",args=["v70020","v70021","v70022","v70023","v70024","v70025","v70027","v70028"])}))]
    inverse = copy.deepcopy(entry)
    ib = {b["id"]: b for b in inverse["blocks"]}
    for block,value,previous,current in changes:
        next(o for o in ib[block]["ops"] if o["out"] == [dict(name=value,type="u64")])["attrs"]["value"] = previous
    ib["b57"]["ops"] = ib["b57"]["ops"][:-2]
    ib["b57"]["term"] = old_term
    inverse["blocks"] = inverse["blocks"][:-2]
    assert inverse == before["functions"][0]
    raw = render_assembly(after).encode()
    assembled = assemble_program(raw).as_dict()
    for index in range(60):
        if index not in (0,3,8):
            assert assembled["functions"][index] == before["functions"][index]
    for index in (3,8):
        shifted = copy.deepcopy(before["functions"][index]); shifted["name"] = "f60" if index==3 else "f61"
        assert shifted == assembled["functions"][60 if index==3 else 61]
    proof = dict(schema="hepta.runtime.public-authority-frontend.v1", source_sha256=sha(raw), source_bytes=len(raw),
        baseline_sha256=BASELINE, functions=len(assembled["functions"]),
        original_functions_unchanged=57, entry_inverse_ast_exact=True,
        relocated_exact={"f3":"f60", "f8":"f61"},
        fields={"current_call_projection_extent":192,"decoded_reply_scratch":[1024,1108],"owned_projection":[1152,1232]},
        fixed_child=12, global_slot=56, configured_presence_child=6, configured_presence_operation=3,
        phase_config_presence=13, phase_owner=14, private_request_bytes=len(request),
        configured_runtime_only=True, raw_owner_result_published=False, peer_info_is_authority=False,
        current_stdio_authenticated_flag=0, public_annotation_integrated=False, request_audit_integrated=False,
        public_http_qualified=False, concurrent_binding_qualified=False, production_activated=False, whole_runtime_replaced=False,
        author_sha256=sha(Path(__file__).read_bytes()), pseudo_sha256=sha((Path(__file__).parent/"authority_frontend.txt").read_bytes()))
    comp.update(source_sha256=sha(raw), source_bytes=len(raw), functions={**names, **additions},
        function_sha256={f["name"]:sha(json.dumps(f,sort_keys=True,separators=(",",":")).encode()) for f in assembled["functions"]},
        target_session_authority=proof)
    outputs={"native/runtime_mcp.hepta":raw,"native/runtime_mcp_authority_composition.json":encoded(proof),
        "native/runtime_mcp_composition.json":encoded(comp)}
    for name, data in outputs.items():
        path=args.source/name
        if args.check:
            assert path.read_bytes()==data,name
        else:
            path.write_bytes(data)
    print(json.dumps(proof,sort_keys=True))


if __name__ == "__main__":
    p=argparse.ArgumentParser()
    for name in ("hepta","baseline","source"):
        p.add_argument("--"+name,required=True,type=Path)
    p.add_argument("--check",action="store_true")
    author(p.parse_args())
