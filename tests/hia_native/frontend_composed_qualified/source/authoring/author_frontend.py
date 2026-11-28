"""Compose fixed Bellman continuations into the public HIA frontend.

This author emits HIA; it does not execute or interpret handlers. Only entry,
prepare and tool-name selection gain wrappers. The retained entry admits three
more phases after its original complete-child validation. Pending is a host
scheduling boundary, never a synchronous wait or a public success response.
"""
from __future__ import annotations
import argparse, copy, hashlib, json, re, sys
from pathlib import Path
sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from authoring_support import compile_delta, substitute
sha = lambda raw: hashlib.sha256(raw).hexdigest()
canon = lambda obj: json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()
encoded = lambda obj: (json.dumps(obj, sort_keys=True, indent=2) + "\n").encode()


def predicate(name, raw):
    lines = [f"def {name}(w:mutbuf, at:u64) -> bool:"]
    for i in range(0, len(raw) // 8 * 8, 8):
        lines += [f"    if get(w, at + {i}) != {int.from_bytes(raw[i:i+8], 'little')}:", "        return False"]
    for i in range(len(raw) // 8 * 8, len(raw)):
        lines += [f"    if byte(w, at + {i}) != {raw[i]}:", "        return False"]
    return "\n".join(lines + ["    return True", ""])


def variables(obj):
    found = []
    def visit(value):
        if isinstance(value, str) and re.fullmatch(r"v[0-9]+", value):
            if value not in found:
                found.append(value)
        elif isinstance(value, list):
            for item in value:
                visit(item)
        elif isinstance(value, dict):
            for item in value.values():
                visit(item)
    visit(obj)
    return found


def rename_values(obj, names):
    if isinstance(obj, str):
        return names.get(obj, obj)
    if isinstance(obj, list):
        return [rename_values(v, names) for v in obj]
    if isinstance(obj, dict):
        return {k: rename_values(v, names) for k, v in obj.items()}
    return obj


def author(args):
    sys.path.insert(0, str(args.hepta.resolve()))
    from hepta.hia_agent_assembly import assemble_program, render_assembly
    raw = (args.baseline / "native/runtime_mcp.hepta").read_bytes()
    assert sha(raw) == args.baseline_sha256, "explicit frozen baseline differs"
    comp = json.loads((args.baseline / "native/runtime_mcp_composition.json").read_bytes())
    assert comp["source_sha256"] == sha(raw)
    assert "bellman_public_extension" not in comp
    before = assemble_program(raw).as_dict()
    original = {f["name"]: copy.deepcopy(f) for f in before["functions"]}
    assert [comp["functions"][n] for n in ("entry","prepare","tool_kind")] == ["f0","f8","f29"]
    first = max(int(n[1:]) for n in original) + 1
    relocated = [("f0", f"f{first}"), ("f8", f"f{first+1}"), ("f29", f"f{first+2}")]
    names = {**comp["functions"], "retained_bellman_entry": relocated[0][1],
             "retained_bellman_prepare": relocated[1][1], "retained_bellman_tool_kind": relocated[2][1]}
    labels = ["prepare_bellman", "after_bellman", "after_bellman_allocate",
              "after_bellman_caller", "after_bellman_retire", "bellman_resume", "bellman_pending", "bellman_name"]
    additions = {name: f"f{first+3+i}" for i, name in enumerate(labels)}
    texts = dict(FRONTEND_STATE=b"HRMCFS02", FRONTEND_RESPONSE=b"HRCMFR02", BELLMAN_STATE=b"HBLFRS01",
                 TAG_REQUEST=b"HBLTAG01", TAG_RESPONSE=b"HBLTGR01", CALLER_REQUEST=b"HBLCLQ01",
                 CALLER_RESPONSE=b"HBLCLR01", RETIRE_REQUEST=b"HBLRET01", RETIRE_RESPONSE=b"HBLRTR01",
                 HOST_REQUEST=b"HBLFRQ01")
    constants = {name:int.from_bytes(value,"little") for name,value in texts.items()}
    constants.update(INVALID=0xffffffff, SHORT_OUTPUT=0xfffffffe, BELLMAN_NAME_SIZE=len(b"weight_bellman_plan"))
    pseudo_path = Path(__file__).with_name("bellman_frontend.pseudo")
    pseudo = pseudo_path.read_text() + "\n" + predicate("bellman_name", b"weight_bellman_plan")
    compiled,_,_ = compile_delta(args.hepta, raw, names, substitute(pseudo,constants),
        {"entry":"f0","prepare":"f8","tool_kind":"f29"}, additions, relocated)
    after = assemble_program(compiled).as_dict()
    by_name = {f["name"]:f for f in after["functions"]}
    entry = by_name[relocated[0][1]]
    original_entry = copy.deepcopy(entry)
    blocks = {b["id"]:b for b in entry["blocks"]}
    changed_constants = []
    for block,variable,candidates,new in [("b19","v161",(112,114),117),("b21","v177",(12,14),17)]:
        op = next(o for o in blocks[block]["ops"] if o["out"] == [dict(name=variable,type="u64")])
        assert op["op"] == "const"
        old = op["attrs"]["value"]
        assert old in candidates, "baseline phase domain differs"
        changed_constants.append((block,variable,old,new))
        op["attrs"]["value"] = new
    types = {}
    for block in entry["blocks"]:
        for item in block["params"]:
            types[item["name"]] = item["type"]
        for op in block["ops"]:
            for item in op["out"]:
                types[item["name"]] = item["type"]
    fixed = ["v464","v465","v466","v468","v469","v467"]
    assert [types[v] for v in fixed] == ["readbuf","mutbuf","mutbuf","u64","u64","u64"]
    branch = blocks["b57"]
    old_term = copy.deepcopy(branch["term"])
    old_ops_count = len(branch["ops"])
    refs = variables(old_term)
    assert len(refs) <= 16
    assert not any(int(v[1:]) >= 900000 for v in types)
    maximum = max(int(b["id"][1:]) for b in entry["blocks"])
    then_id,else_id = f"b{maximum+1}",f"b{maximum+2}"
    branch["ops"] += [dict(op="const",args=[],attrs=dict(value=15),out=[dict(name="v900000",type="u64")]),
                       dict(op="compare.ge",args=["v467","v900000"],attrs={},out=[dict(name="v900001",type="bool")])]
    branch["term"] = dict(op="branch",cond="v900001",then=dict(target=then_id,args=fixed),
                          **{"else":dict(target=else_id,args=refs)})
    params = [dict(name=f"v{900010+i}",type=types[v]) for i,v in enumerate(fixed)]
    yes = dict(id=then_id,params=params,
        ops=[dict(op="call",args=[p["name"] for p in params],attrs=dict(function=additions["after_bellman"]),
                  out=[dict(name="v900016",type="u32")])],term=dict(op="ret",values=["v900016"]))
    remap = {v:f"v{900020+i}" for i,v in enumerate(refs)}
    no = dict(id=else_id,params=[dict(name=remap[v],type=types[v]) for v in refs],ops=[],term=rename_values(old_term,remap))
    entry["blocks"] += [yes,no]
    inverse = copy.deepcopy(entry)
    ib = {b["id"]:b for b in inverse["blocks"]}
    for block,variable,old,new in changed_constants:
        next(o for o in ib[block]["ops"] if o["out"] == [dict(name=variable,type="u64")])["attrs"]["value"] = old
    ib["b57"]["ops"] = ib["b57"]["ops"][:old_ops_count]
    ib["b57"]["term"] = old_term
    inverse["blocks"] = inverse["blocks"][:-2]
    assert inverse == original_entry
    final = render_assembly(after).encode()
    checked = assemble_program(final).as_dict()
    by_name = {f["name"]:f for f in checked["functions"]}
    preserved = {}
    for name,function in original.items():
        if name not in ("f0","f8","f29"):
            assert by_name[name] == function,name
            preserved[name] = sha(canon(function))
    for old,new in relocated[1:]:
        expected = copy.deepcopy(original[old]);expected["name"] = new
        assert by_name[new] == expected
    for function in checked["functions"]:
        assert len(function["blocks"]) <= 256,function["name"]
        assert max(len(b["params"]) for b in function["blocks"]) <= 16,function["name"]
    proof = dict(schema="hepta.runtime.bellman-public-frontend-source.v1",source_sha256=sha(final),source_bytes=len(final),
        baseline_sha256=sha(raw),baseline_functions=len(original),functions=len(by_name),
        blocks=sum(len(f["blocks"]) for f in by_name.values()),
        operations=sum(len(b["ops"]) for f in by_name.values() for b in f["blocks"]),
        retained_exact_functions=preserved,relocated_exact_functions=dict(relocated[1:]),
        retained_entry=relocated[0][1],retained_entry_inverse_ast_exact=True,
        entry_phase_constant_changes=changed_constants,
        entry_completion_dispatch="phases 15-17 after original complete delivery validation",
        new_functions=additions,changed_original_functions=["f0","f8","f29"],
        tool_name="weight_bellman_plan",tool_kind=11,fixed_child=14,global_slot=57,
        phases=dict(allocate=15,caller=16,retire=17,pending=97),pending_kind=4,pending_extent=64,
        pending_header_zero_fields=[16,24,32,40,56],pending_record=dict(offset=1280,bytes=64,magic="HBLFRS01"),
        host_control=dict(offset=1344,bytes=64,magic="HBLFRQ01",commands=[2,3],
                          binds=["private tag","worker job","last completed child sequence"]),
        private_frontend_state=[1280,1408],canonical_parameters_region=4,complete_result_owned_region=5,
        old_constructor_and_json_error_rendering_unchanged=True,public_ids_are_private_tags=False,
        terminal_storage_retired_before_publication=True,status3_returns_to_host=True,status4_emits_public_response=False,
        author_sha256=sha(Path(__file__).read_bytes()),pseudo_sha256=sha(pseudo_path.read_bytes()),
        authoring_support_sha256=sha(Path(__file__).with_name("authoring_support.py").read_bytes()),
        runtime_public_qualified=False,current_sdk_async_qualified=False,full_sdk_qualified=False,
        whole_runtime_replaced=False,production_activated=False,old_path_removed=False,catalog_not_changed=True)
    comp.update(source_bytes=len(final),source_sha256=sha(final),functions={**names,**additions},
        function_sha256={n:sha(canon(f)) for n,f in by_name.items()},bellman_public_extension=proof)
    outputs={"native/runtime_mcp.hepta":final,"native/runtime_mcp_composition.json":encoded(comp),
             "native/runtime_mcp_bellman_composition.json":encoded(proof)}
    for path,data in outputs.items():
        destination = args.output/path
        if args.check:
            assert destination.read_bytes() == data,path
        else:
            destination.parent.mkdir(parents=True,exist_ok=True)
            destination.write_bytes(data)
    print(json.dumps({k:proof[k] for k in ("source_sha256","source_bytes","baseline_functions","functions", "blocks", "operations", "retained_entry_inverse_ast_exact")},sort_keys=True))


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    for name in ("hepta","baseline","output"):
        p.add_argument("--"+name,type=Path,required=True)
    p.add_argument("--baseline-sha256",required=True)
    p.add_argument("--check",action="store_true")
    author(p.parse_args())
