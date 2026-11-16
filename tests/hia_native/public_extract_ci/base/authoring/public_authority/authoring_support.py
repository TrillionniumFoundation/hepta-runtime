"""Compose current G1/G2 admission from pinned implementation sources only."""
from __future__ import annotations
import argparse, ast, copy, hashlib, json, re, sys
from pathlib import Path
sys.dont_write_bytecode = True
sha = lambda raw: hashlib.sha256(raw).hexdigest()
canon = lambda value: json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
CONNECTION = "a3e6353b4d8e98682e6605e711bc19c533d8d524c2eb1b55c788709974a234f2"
PROTOCOL = "ec5ed4c001b7b9446bd700c230751557f2252edaf5009aefc90e6ee6a19ebd64"

def compile_delta(hepta, original, aliases, pseudo, replacements, additions, relocated=()):
    sys.path.insert(0, str(hepta))
    from tools.generate_hia_selfhost import Builder, compact_authoring_cfg, total_scalar_functions
    from hepta.hia_agent_assembly import assemble_program, render_assembly
    class NativeBuilder(Builder):
        def expr(self, node):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "copy_within":
                values = [self.expr(value) for value in node.args]
                return self.op("buffer.move_within", [values[0], *(self.cast(value, "usize") for value in values[1:])])
            return super().expr(node)
    old = assemble_program(original).as_dict()
    before = {f["name"]: copy.deepcopy(f) for f in old["functions"]}
    functions = copy.deepcopy(old["functions"])
    for old_name, new_name in relocated:
        f = copy.deepcopy(before[old_name]); f["name"] = new_name; functions.append(f)
    names = {**aliases, **replacements, **additions}
    by_name = {f["name"]: f for f in functions}
    signatures = {name: ([p["type"] for p in by_name[target]["params"]], by_name[target]["returns"][0])
        for name, target in aliases.items()}
    nodes = ast.parse(pseudo).body
    assert all(isinstance(node, ast.FunctionDef) for node in nodes)
    signatures.update({node.name: ([p.annotation.id for p in node.args.args], node.returns.id) for node in nodes})
    total = total_scalar_functions(nodes)
    generated = {}
    for node in nodes:
        b = NativeBuilder(node, names, signatures, total); b.statements(node.body)
        generated[names[node.name]] = dict(name=names[node.name],
            params=[b.param(p) for p in b.params], returns=[b.returns],
            effects=["read", "write", "trap"], entry="b0", blocks=b.blocks)
    combined = [generated.get(f["name"], f) for f in functions]
    seen = {f["name"] for f in combined}
    combined += [generated[name] for name in sorted(set(generated) - seen, key=lambda n: int(n[1:]))]
    compacted = compact_authoring_cfg(dict(schema="hepta.hia.program.v8", module="public_connection_delta",
        functions=combined))["functions"]
    compacted = {f["name"]: f for f in compacted}
    functions = [compacted[f["name"]] if f["name"] in generated else f for f in combined]
    raw = render_assembly({**old, "functions": functions}).encode()
    after = {f["name"]: f for f in assemble_program(raw).as_dict()["functions"]}
    retained = {}
    for name, function in before.items():
        if name not in replacements.values():
            assert after[name] == function, name
            retained[name] = sha(canon(function))
    for old_name, new_name in relocated:
        f = copy.deepcopy(before[old_name]); f["name"] = new_name
        assert after[new_name] == f
    for f in after.values():
        assert len(f["blocks"]) <= 256, f["name"]
        assert max(len(b["params"]) for b in f["blocks"]) <= 16, f["name"]
    return raw, after, retained

def substitute(text, constants):
    return re.sub(r"\b(" + "|".join(constants) + r")\b", lambda m: str(constants[m[0]]), text)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ("hepta", "baseline", "output", "authoring"):
        p.add_argument("--" + name, required=True, type=Path)
    a = p.parse_args()
    baseline = a.baseline.resolve(strict=True); root = a.output.resolve(strict=True)
    authoring = a.authoring.resolve(strict=True)
    before = json.loads((root.parent / "BASELINE.json").read_bytes())["files"]
    assert all(sha((baseline / path).read_bytes()) == row["sha256"] for path, row in before.items())
    assert sha((root / "native/sdk_connection_target.hepta").read_bytes()) == CONNECTION
    old_protocol = (baseline / "native/sdk_public_protocol.hepta").read_bytes()
    assert sha(old_protocol) == PROTOCOL
    protocol_comp = json.loads((authoring / "protocol_baseline_composition.json").read_bytes())
    constants = dict(protocol_comp["constants"])
    constants.update(CONNECTION_INPUT=int.from_bytes(b"HRCNQ001", "little"),
        CONNECTION_OUTPUT=int.from_bytes(b"HRCNS001", "little"),
        INIT_TAG=int.from_bytes(b"HRCNIN01", "little"),
        DIRECT_TAG=int.from_bytes(b"HRCNDI01", "little"))
    pseudo = (authoring / "connection_protocol.txt").read_text()
    for name, literal in (("response_prefix", b'{"jsonrpc":"2.0","id":'), ("empty_result_suffix", b',"result":{}}')):
        pseudo += "\ndef " + name + "(w:mutbuf, at:u64) -> u64:\n"
        for index in range(0, len(literal) // 8 * 8, 8):
            pseudo += "    put(w,at+" + str(index) + "," + str(int.from_bytes(literal[index:index+8], "little")) + ")\n"
        for index in range(len(literal) // 8 * 8, len(literal)):
            pseudo += "    store(w,at+" + str(index) + "," + str(literal[index]) + ")\n"
        pseudo += "    return at+" + str(len(literal)) + "\n"
    pseudo = substitute(pseudo, constants)
    replacements = {"entry": "f0", "after_message": "f7"}
    additions = dict(after_connection="f11", connection_pair="f12", initialize_frame="f13",
        direct_frame="f14", empty_result="f15", response_prefix="f16", empty_result_suffix="f17")
    raw, after, retained = compile_delta(a.hepta, old_protocol, protocol_comp["aliases"], pseudo, replacements, additions)
    (root / "native/sdk_public_protocol.hepta").write_bytes(raw)
    protocol_note = dict(schema="hepta.runtime.public-connection-controller.v1",
        source_sha256=sha(raw), source_bytes=len(raw), functions=len(after),
        baseline_sha256=PROTOCOL, retained_exact_functions=retained,
        changed_functions=sorted(replacements.values()), added_functions=additions,
        aliases={**protocol_comp["aliases"], **additions}, constants=constants,
        child_order={"0": "target_message42", "1": "target_request43", "2": "target_bridge44",
            "3": "historical_protocol45", "4": "target_connection55"},
        connection_source_sha256=CONNECTION,
        current_typed_initialize_identifier=True, current_ping_context_and_wire=True,
        generic_initialize_response_not_published=True,
        other_admitted_non_call_requests="retained historical projection after real G2; no new whole-SDK claim",
        generic_discover_response_not_published=True, sdk_default_fixture_linked=False,
        full_sdk_qualified=False, full_async_runtime_qualified=False, production_activated=False, old_path_removed=False)
    (root / "native/sdk_public_protocol_composition.json").write_text(json.dumps(protocol_note, sort_keys=True, indent=2) + "\n")
    old_front = (baseline / "native/runtime_mcp.hepta").read_bytes()
    comp = json.loads((baseline / "native/runtime_mcp_composition.json").read_bytes())
    assert len(comp["function_sha256"]) == 58
    names = {**comp["functions"], "retained_connection_protocol": "f58", "retained_connection_initialize": "f59"}
    fp = substitute((authoring / "connection_frontend.txt").read_text(),
        {**constants, "ADMISSION_REQUEST": int.from_bytes(b"HCMADQ02", "little")})
    raw, after, retained = compile_delta(a.hepta, old_front, names, fp,
        {"after_protocol": "f1", "prepare_initialize": "f9"}, {}, (("f1", "f58"), ("f9", "f59")))
    (root / "native/runtime_mcp.hepta").write_bytes(raw)
    front_note = dict(schema="hepta.runtime.public-connection-frontend.v1",
        source_sha256=sha(raw), source_bytes=len(raw), functions=len(after),
        baseline_sha256=sha(old_front), retained_exact_functions=retained,
        changed_functions=["f1", "f9"], relocated_exact_functions={"f1": "f58", "f9": "f59"},
        normalized_json_id_uses_existing_raw_id_tag=3, current_get_info_slot=54,
        get_info_and_constructor_functions_retained_exact=True,
        direct_replies_use_actual_raw_result_publisher=True,
        initialized_capabilities_are_current_G1_typed_object=True,
        full_sdk_qualified=False, production_activated=False, old_path_removed=False)
    comp.update(source_bytes=len(raw), source_sha256=sha(raw))
    comp["functions"] = names
    comp["function_sha256"] = {name: sha(canon(function)) for name, function in after.items()}
    comp["target_connection_extension"] = front_note
    (root / "native/runtime_mcp_composition.json").write_text(json.dumps(comp, sort_keys=True, indent=2) + "\n")
    (root / "native/runtime_mcp_connection_composition.json").write_text(json.dumps(front_note, sort_keys=True, indent=2) + "\n")
    print(json.dumps({"protocol": protocol_note["source_sha256"], "frontend": front_note["source_sha256"],
        "protocol_functions": protocol_note["functions"], "frontend_functions": front_note["functions"]}, sort_keys=True))

if __name__ == "__main__":
    main()
