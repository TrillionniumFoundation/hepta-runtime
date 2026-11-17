"""Build the four new HIA owners and a three-function frontend overlay."""
from __future__ import annotations
import copy
import json
from pathlib import Path
from source_support import SHA, CANON, ENCODE, WORD, identity, require, compile_new, compile_delta, renamed

COMMON = {"INVALID": 0xffffffff, "CAPACITY": 0xfffffffe, "RESOURCE": 0xfffffffc,
          "MAXIMUM": (1 << 64) - 1, "CANCELLED": 0xfffffff7,
          "PARAMS_RESULT": WORD("HEXPRR01"), "ENDPOINT": WORD("HIAEP002"),
          "PATH_RESULT": WORD("HRSOLR02"), "PATH_REQUEST": WORD("HRSOLQ02")}
GATEWAY = dict(zip(("entry after_params after_fence after_context after_current after_config policy_next after_resolve after_policy after_caller complete prepare prepare_initial prepare_resolve prepare_policy prepare_caller child finish region region_capacity reply reserve request_grow pending_grow admit_growth delivery_again trim_start trim_end equal space_width literal prepare_client after_client load get put").split(),
                  ("f" + str(i) for i in range(36))))
CALLER = dict(zip(("entry valid_typed after_scope after_resolve after_body prepare prepare_scope prepare_resolve prepare_body install business_error append_hints child finish region region_capacity reply reserve request_grow pending_grow admit_growth delivery_again literal load get put").split(),
                 ("f" + str(i) for i in range(26))))

def params_literals():
    fields = ("from_path", "from_start", "from_end", "append_path", "append_line")
    chunks = ("invalid type: ", ", expected a string", "missing field `", *fields)
    rows = ["def diagnostic_literal(w: mutbuf, o: mutbuf, ident: u64) -> u64:"]
    for index, value in enumerate(chunks):
        rows.append("    if ident == " + str(index) + ":")
        rows += ["        emit(w, o, " + str(b) + ")" for b in value.encode()]
        rows.append("        return 0")
    rows += ["    return 0", "", "def field_key(s: readbuf, start: u64, end: u64) -> u64:"]
    for index, value in enumerate(fields):
        raw = ('"' + value + '"').encode()
        test = ["end - start == " + str(len(raw))]
        test += ["byte(s, start + " + str(i) + ") == " + str(b) for i, b in enumerate(raw)]
        rows += ["    if " + " and ".join(test) + ":", "        return " + str(index)]
    rows += ["    return 5", ""]
    return "\n".join(rows)

def module_proof(name, proof, aliases, **extra):
    return {"schema": "hepta.runtime.public-extract-owner-author.v1", "owner": name,
        "aliases": aliases, **proof, **extra, "native_executed": False, "rust_executed": False,
        "public_handler_qualified": False, "full_async_cancellation_qualified": False,
        "remote_qualified": False, "whole_runtime_replaced": False}

def controllers(api, source, author):
    outputs, proofs = {}, {}
    def save(name, raw, aliases, proof, **extra):
        proofs[name] = module_proof(name, proof, aliases, **extra)
        outputs["native/" + name + ".hepta"] = raw
        outputs["native/" + name + "_composition.json"] = ENCODE(proofs[name])
    raw, names, proof = compile_new(api, source["native/view_params.hepta"],
        {"integer": "f3", "string_info": "f9", "copy_string": "f10", "skip_value": "f11",
         "unexpected": "f13", "load": "f17", "get": "f18", "put": "f19", "emit": "f33"},
        (author / "params.pseudo").read_text() + "\n" + params_literals(),
        {**COMMON, "PARAMS_REQUEST": WORD("HEXPRQ01")}, "runtime_extract_params")
    save("extract_params", raw, names, proof, arguments_domain="canonical object from the actual SDK Value owner",
         optional_from_end_null_is_absent=True, endpoint_validation_owned_by_body=True)
    gateway, changes = renamed(api, source["native/batch_gateway.hepta"],
        dict(zip(("HBAWGQ02", "HBAWGQ03", "HBAWGS01", "HBAWGA01", "HBAPRR01", "HBPRQ002", "HBECQ001"),
                 ("HEXWGQ02", "HEXWGQ03", "HEXWGS01", "HEXWGA01", "HEXPRR01", "HEXPRQ01", "HEXCLQ01"))),
        "runtime_extract_gateway")
    raw, names, proof = compile_delta(api, gateway, GATEWAY,
        (author / "gateway.pseudo").read_text(),
        {**COMMON, "LOCAL_POLICY": WORD("HRLPCQ02"), "CONFIG_REQUEST": WORD("HRCFGQ01")},
        "runtime_extract_gateway")
    save("extract_gateway", raw, names, proof, template=identity(source["native/batch_gateway.hepta"]),
        private_magic_changes=changes, source_policy_write=False, append_policy_write=True,
        child_slots=[60,27,5,6,11,9,7,61,3], typed_before_fence=True)
    caller, changes = renamed(api, source["native/batch_call.hepta"],
        dict(zip(("HBECLI01", "HBECLR01", "HBECQ001", "HBECST01", "HBECCA01", "HBAPRR01"),
                 ("HEXCLI01", "HEXCLR01", "HEXCLQ01", "HEXCST01", "HEXCCA01", "HEXPRR01"))),
        "runtime_extract_call")
    _, _, _, assemble, render = api
    doc = assemble(caller).as_dict()
    scope = next(f for f in doc["functions"] if f["name"] == CALLER["after_scope"])
    block = next(b for b in scope["blocks"] if b["id"] == "b28")
    original_block = copy.deepcopy(block)
    require([p["name"] for p in block["params"]] == ["v278", "v279", "v280", "v284"], "Scope open block parameters changed")
    keep = [i for i, op in enumerate(block["ops"]) if op.get("out") == [{"name": "v301", "type": "u64"}]]
    require(len(keep) == 1 and block["ops"][keep[0]]["op"] == "call"
        and block["ops"][keep[0]]["attrs"]["function"] == CALLER["put"], "Scope active admission changed")
    block["ops"] = block["ops"][:keep[0] + 1]
    for index, offset in enumerate((424,432)):
        first = 900000 + index * 3
        block["ops"] += [
            {"op":"const","args":[],"attrs":{"value":offset},"out":[{"name":"v"+str(first),"type":"u64"}]},
            {"op":"const","args":[],"attrs":{"value":0},"out":[{"name":"v"+str(first+1),"type":"u64"}]},
            {"op":"call","args":["v280","v"+str(first),"v"+str(first+1)],"attrs":{"function":CALLER["put"]},
             "out":[{"name":"v"+str(first+2),"type":"u64"}]}]
    block["term"] = {"op": "jump", "target": "b39", "args": ["v278", "v279", "v280"]}
    by_block = {b["id"]: b for b in scope["blocks"]}
    reachable, queue = set(), [scope["entry"]]
    while queue:
        name = queue.pop()
        if name in reachable:
            continue
        reachable.add(name)
        term = by_block[name]["term"]
        if term["op"] == "jump":
            queue.append(term["target"])
        elif term["op"] == "branch":
            queue.extend([term["then"]["target"],term["else"]["target"]])
        else:
            require(term["op"] in ("ret","trap"), "unexpected Scope terminator")
    removed = {b["id"]: SHA(CANON(b)) for b in scope["blocks"] if b["id"] not in reachable}
    require(set(removed) == {"b29","b30","b31","b32","b33","b35","b36","b37"},
        "Scope text-command-only block inventory differs")
    scope["blocks"] = [b for b in scope["blocks"] if b["id"] in reachable]
    scope_patch = {"function": CALLER["after_scope"], "block":"b28", "removed_text_only_blocks":removed,
        "before": SHA(CANON(original_block)), "after": SHA(CANON(block)),
        "purpose": "after exact Scope open admission, reset two-path state and resolve the source",
        "unchanged_admission_prefix_ops": keep[0] + 1}
    raw, names, proof = compile_delta(api, render(doc).encode(), CALLER,
        (author / "caller.pseudo").read_text(),
        {**COMMON, "BODY_REQUEST": WORD("HEXBDQ01"), "MESSAGE": WORD("HRCFGM01")},
        "runtime_extract_call")
    save("extract_call", raw, names, proof, template=identity(source["native/batch_call.hepta"]),
        private_magic_changes=changes, scope_open_patch=scope_patch, child_slots=[29,9,62],
        uses_same_context_generation_continuation_lease=True, local_body_only=True)
    constants = {**COMMON, "STATE_MAGIC": WORD("HEXADS01"), "REQUEST_MAGIC": WORD("HEXBDQ01"),
        "BODY_REQUEST": WORD("HEXTRQ01"), "BODY_RESULT": WORD("HEXTRP01"),
        "ACTION_MAGIC": WORD("HEXACA01"), "RESULT_MAGIC": WORD("HRCFGM01"),
        "GROW_MAGIC": WORD("HGRWS002"), "PHASE":8, "SEQUENCE":16, "INPUT_LENGTH":24,
        "OUTPUT_LENGTH":32, "WORK_LENGTH":40, "ACTION":256,
        "CALL":0xfffffff0, "GROW":0xffffffd0, "DELIVERY":0xffffffcd, "FIRST_ERROR":0xffff0000}
    raw, names, proof = compile_new(api, source["native/text_budget.hepta"],
        {"load":"f14", "get":"f15", "put":"f16"}, (author / "adapter.pseudo").read_text(),
        constants, "runtime_extract_body_adapter")
    save("extract_body_adapter", raw, names, proof, child_slots=[63],
        owned_parent_delivery_growth_does_not_reexecute_body=True, input_header_bytes=80,
        body_request_header_bytes=128)
    return outputs, proofs

def frontend(api, source, author):
    _, _, _, assemble, render = api
    original = source["native/runtime_mcp.hepta"]
    comp = json.loads(source["native/runtime_mcp_composition.json"])
    before = assemble(original).as_dict()
    old = {f["name"]: f for f in before["functions"]}
    require(comp["source_sha256"] == SHA(original) and comp["source_bytes"] == len(original), "frontend composition source differs")
    require(comp["function_sha256"] == {name: SHA(CANON(f)) for name,f in old.items()}, "frontend AST index differs")
    names = dict(comp["functions"])
    require(len(old) == 84, "pinned source frontend count differs")
    extra = {alias: "f" + str(len(old) + i) for i,alias in enumerate(
        ("retained_extract_tool_kind", "retained_extract_prepare", "prepare_extract"))}
    require(not names.keys() & extra.keys(), "extract already registered")
    names.update(extra)
    seed = copy.deepcopy(before)
    relocated = {names["tool_kind"]: extra["retained_extract_tool_kind"], names["prepare"]: extra["retained_extract_prepare"]}
    for a,b in relocated.items():
        f = copy.deepcopy(old[a]); f["name"] = b; seed["functions"].append(f)
    prepared = copy.deepcopy(old[names["prepare_batch"]])
    prepared["name"] = extra["prepare_extract"]
    changes = []
    for block in prepared["blocks"]:
        for op in block["ops"]:
            if op["op"] != "const":
                continue
            value = op["attrs"]["value"]
            if value == WORD("HBAWGQ02"):
                changes.append([block["id"],op["out"],value,WORD("HEXWGQ02")])
                op["attrs"]["value"] = WORD("HEXWGQ02")
            elif block["id"] == "b16" and op["out"] == [{"name":"v177","type":"u64"}]:
                require(value == 13, "retained Batch frontend target differs")
                changes.append([block["id"],op["out"],13,15])
                op["attrs"]["value"] = 15
    require(len(changes) == 2, "prepared extraction request changes differ")
    seed["functions"].append(prepared)
    raw, aliases, proof = compile_delta(api, render(seed).encode(), names,
        (author / "frontend.pseudo").read_text(), COMMON, "runtime_mcp")
    after = {f["name"]: f for f in assemble(raw).as_dict()["functions"]}
    retained = {}
    for name, f in old.items():
        if name not in relocated:
            require(after[name] == f, "frontend original function changed: " + name)
            retained[name] = SHA(CANON(f))
    for a,b in relocated.items():
        inverse = copy.deepcopy(after[b]); inverse["name"] = a
        require(inverse == old[a], "frontend exact relocation differs")
    inverse = copy.deepcopy(after[extra["prepare_extract"]])
    inverse["name"] = names["prepare_batch"]
    for block_id, out, previous, current in changes:
        op = next(op for block in inverse["blocks"] if block["id"] == block_id for op in block["ops"] if op["out"] == out)
        require(op["attrs"]["value"] == current, "prepared request inverse anchor differs")
        op["attrs"]["value"] = previous
    require(inverse == old[names["prepare_batch"]], "prepared request inverse AST differs")
    proof.update(schema="hepta.runtime.public-extract-frontend.v1", baseline=identity(original),
        exact_relocated_functions=relocated, retained_original_functions=retained,
        entry_ast_exact=True, prepared_request_inverse_ast_exact=True, prepared_request_changes=changes,
        fixed_child=15, global_slot=59, tool_kind=12, phase=6, growth_phase=106,
        native_executed=False, rust_executed=False, public_handler_qualified=False,
        full_async_cancellation_qualified=False, remote_qualified=False, whole_runtime_replaced=False)
    comp.update(source_sha256=SHA(raw), source_bytes=len(raw), functions=aliases,
        function_sha256={name:SHA(CANON(f)) for name,f in after.items()}, extract_public_extension=proof)
    return {"native/runtime_mcp.hepta":raw, "native/runtime_mcp_composition.json":ENCODE(comp),
        "native/runtime_mcp_extract_composition.json":ENCODE(proof)}, proof
