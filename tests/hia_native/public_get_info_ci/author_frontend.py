"""Compose the fixed current get_info owner into the qualified public frontend.

Authoring reads only pinned implementation sources. No reference response or
native capture supplies implementation bytes. The retained admission owns the
negotiated protocol and session state; the new owner supplies all server fields.
"""
from __future__ import annotations

import argparse
import ast
import copy
import hashlib
import json
from pathlib import Path
import re
import sys

sys.dont_write_bytecode = True
BASELINE = "7921a7fd89d02008baebacf1302b44c927581bb0a3c54d4dbeabbe2f5c1641e1"
OWNER = "e2c4829a305593938202a5bf00e6411c5f4ba095167ff6a0603882e32fc5c89c"
MODEL = "ac438543401b6b9d60021fc044dcf27b446df9539e837c6fecdf16a670091b9a"
SERVICE = "b87a9561d539d44768c90f3b77ae847d0d2f3429d237e9e7c6c2e588b000f595"


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def generate(hepta, baseline, root, reference, pseudo):
    sys.path.insert(0, str(hepta))
    from tools.generate_hia_selfhost import Builder, compact_authoring_cfg, total_scalar_functions
    from hepta.hia_agent_assembly import assemble_program, render_assembly

    class NativeBuilder(Builder):
        def expr(self, node):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "copy_within":
                args = [self.expr(value) for value in node.args]
                return self.op("buffer.move_within", [args[0], *(self.cast(value, "usize") for value in args[1:])])
            return super().expr(node)

    raw = (baseline / "native/runtime_mcp.hepta").read_bytes()
    assert sha(raw) == BASELINE
    assert sha((root / "native/current_get_info.hepta").read_bytes()) == OWNER
    model_raw = (reference / "sdk-model.rs").read_bytes()
    service_raw = (reference / "sdk-service-server.rs").read_bytes()
    assert sha(model_raw) == MODEL and sha(service_raw) == SERVICE
    model = model_raw.decode()
    versions = dict(re.findall(r'pub const (V_\d{4}_\d{2}_\d{2}): Self = Self\(Cow::Borrowed\("([\d-]+)"\)\);', model))
    known_block = re.search(r'pub const KNOWN_VERSIONS:.*?=\s*&\[(.*?)\];', model, re.S)
    assert known_block is not None
    known = [versions[name] for name in re.findall(r'Self::(V_\d{4}_\d{2}_\d{2})', known_block[1])]
    ceiling = versions[re.search(r'pub const NO_INITIALIZE: Self = Self::(V_\d{4}_\d{2}_\d{2});', model)[1]]
    legacy = sorted(version for version in known if version < ceiling)
    assert legacy == ["2024-11-05", "2025-03-26", "2025-06-18", "2025-11-25"]
    assert ceiling == "2026-07-28"
    # These four ids are the source-defined classifier contract of retained
    # admission f5/f7; f16 maps unsupported and no-initialize values to id4.
    admission = assemble_program((baseline / "native/runtime_mcp_admission.hepta").read_bytes()).as_dict()
    admission_by_name = {function["name"]: function for function in admission["functions"]}
    legacy_prefixes = [int.from_bytes(version.encode()[:8], "little") for version in legacy]
    classifier_constants = [operation["attrs"]["value"] for block in admission_by_name["f7"]["blocks"]
        for operation in block["ops"] if operation["op"] == "const"]
    assert all(value in classifier_constants for value in legacy_prefixes)
    assert b"client_requested.has_initialize() && server_supported.contains(client_requested)" in service_raw
    assert b"newest_version_with_initialize(server_supported)" in service_raw

    composition = json.loads((baseline / "native/runtime_mcp_composition.json").read_bytes())
    old = assemble_program(raw).as_dict()
    before = {function["name"]: copy.deepcopy(function) for function in old["functions"]}
    assert len(before) == 52
    functions = copy.deepcopy(old["functions"])
    for old_name, new_name in (("f7", "f52"), ("f8", "f53")):
        retained = copy.deepcopy(before[old_name])
        retained["name"] = new_name
        functions.append(retained)
    aliases = dict(composition["functions"])
    aliases.update(baseline_catalog="f52", baseline_prepare="f53")
    authored = pseudo.read_text()
    prefix = b'{"protocolVersion":"' + ceiling.encode() + b'",'
    assert len(prefix) == 32
    constants = dict(INVALID=0xffffffff,
        INFO_REQUEST=int.from_bytes(b"HRTGIQ01", "little"),
        INFO_RESPONSE=int.from_bytes(b"HRTGIS01", "little"))
    for index in range(4):
        constants["INFO_PREFIX_" + str(index)] = int.from_bytes(prefix[index * 8:index * 8 + 8], "little")
    authored = re.sub(r"\b(" + "|".join(constants) + r")\b", lambda match: str(constants[match[0]]), authored)
    authored += "\ndef negotiated_version(w:mutbuf,at:u64,version:u64) -> u64:\n"
    for number, version in enumerate(legacy, 1):
        data = version.encode()
        authored += (f"    if version=={number}:\n"
            f"        put(w,at,{int.from_bytes(data[:8], 'little')})\n"
            f"        store(w,at+8,{data[8]})\n"
            f"        store(w,at+9,{data[9]})\n"
            "        return at+10\n")
    authored += "    return at\n"
    nodes = ast.parse(authored).body
    names = dict(catalog="f7", prepare="f8", prepare_get_info="f54",
        after_get_info="f55", get_info_envelope="f56", negotiated_version="f57")
    all_names = {**aliases, **names}
    by_name = {function["name"]: function for function in functions}
    signatures = {alias: ([param["type"] for param in by_name[name]["params"]], by_name[name]["returns"][0])
        for alias, name in aliases.items()}
    signatures.update({node.name: ([param.annotation.id for param in node.args.args], node.returns.id) for node in nodes})
    generated = []
    total = total_scalar_functions(nodes)
    for node in nodes:
        builder = NativeBuilder(node, all_names, signatures, total)
        builder.statements(node.body)
        generated.append(dict(name=names[node.name], params=[builder.param(param) for param in builder.params],
            returns=[builder.returns], effects=["read", "write", "trap"], entry="b0", blocks=builder.blocks))
    changes = {function["name"]: function for function in generated}
    functions = [changes.get(function["name"], function) for function in functions]
    functions += [changes["f" + str(index)] for index in range(54, 58)]
    compacted = compact_authoring_cfg(dict(schema="hepta.hia.program.v8",
        module="runtime_mcp_get_info_delta", functions=functions))["functions"]
    compacted = {function["name"]: function for function in compacted}
    functions = [compacted[function["name"]] if function["name"] in changes else function for function in functions]
    entry = functions[0]
    blocks = {block["id"]: block for block in entry["blocks"]}
    assert len(blocks) == 69 and "b69" in blocks and "b70" not in blocks and "b71" not in blocks
    for block, name, previous, current in (("b19", "v161", 111, 112), ("b21", "v177", 11, 12)):
        operation = next(op for op in blocks[block]["ops"] if op["out"] == [dict(name=name, type="u64")])
        assert operation["op"] == "const" and operation["attrs"] == dict(value=previous)
        operation["attrs"]["value"] = current
    dispatch = blocks["b57"]
    assert [param["name"] for param in dispatch["params"]] == ["v464", "v465", "v466", "v467", "v468", "v469"]
    old_term = copy.deepcopy(dispatch["term"])
    assert old_term["cond"] == "v50001"
    dispatch["ops"] += [
        dict(op="const", args=[], attrs=dict(value=12), out=[dict(name="v60000", type="u64")]),
        dict(op="compare.eq", args=["v467", "v60000"], attrs={}, out=[dict(name="v60001", type="bool")])]
    dispatch["term"] = dict(op="branch", cond="v60001",
        then=dict(target="b70", args=["v464", "v465", "v466", "v468", "v469"]),
        **{"else": dict(target="b71", args=["v464", "v465", "v466", "v467", "v468", "v469", "v50001", "v476"])})
    params = [dict(name="v" + str(60020 + index), type=kind)
        for index, kind in enumerate(["readbuf", "mutbuf", "mutbuf", "u64", "u64"])]
    complete = dict(id="b70", params=params, ops=[dict(op="call", args=[param["name"] for param in params],
        attrs=dict(function="f55"), out=[dict(name="v60025", type="u32")])], term=dict(op="ret", values=["v60025"]))
    params = [dict(name="v" + str(60030 + index), type=kind)
        for index, kind in enumerate(["readbuf", "mutbuf", "mutbuf", "u64", "u64", "u64", "bool", "bool"])]
    remap = dict(zip(["v464", "v465", "v466", "v467", "v468", "v469", "v50001", "v476"], [param["name"] for param in params]))
    old_term["cond"] = remap[old_term["cond"]]
    for edge in ("then", "else"):
        old_term[edge]["args"] = [remap[value] for value in old_term[edge]["args"]]
    entry["blocks"] += [complete, dict(id="b71", params=params, ops=[], term=old_term)]
    raw = render_assembly({**old, "functions": functions}).encode()
    checked = assemble_program(raw).as_dict()
    after = {function["name"]: function for function in checked["functions"]}
    retained = {}
    for name, function in before.items():
        if name in {"f0", "f7", "f8"}:
            continue
        assert after[name] == function, name
        retained[name] = sha(encoded(function))
    for old_name, new_name in (("f7", "f52"), ("f8", "f53")):
        expected = copy.deepcopy(before[old_name]); expected["name"] = new_name
        assert after[new_name] == expected
    instructions = sum(len(block["ops"]) + 1 for function in checked["functions"] for block in function["blocks"])
    assert len(after) <= 128 and instructions <= 8192
    for function in checked["functions"]:
        assert len(function["blocks"]) <= 256
        assert max(len(block["params"]) for block in function["blocks"]) <= 16
    output = root / "native/runtime_mcp.hepta"
    output.write_bytes(raw)
    note = dict(schema="hepta.runtime.public-get-info-composition.v1", baseline_sha256=BASELINE,
        source_sha256=sha(raw), source_bytes=len(raw), owner_source_sha256=OWNER,
        functions=len(after), instructions=instructions, retained_exact_functions=retained,
        relocated_exact_functions=dict(f7="f52", f8="f53"), new_functions=names,
        changed_functions=["f0", "f7", "f8"], frontend_child=11, owner_slot=54, phase=12,
        prepare_phase=112, request_magic="HRTGIQ01", response_magic="HRTGIS01",
        wire_offset=64, full_result_extent_checked=True, borrowed_owner_result_modified=False,
        default_supported_versions=known, handshake_versions=legacy, no_initialize=ceiling,
        protocol_selection="retained admission f16; f5/f7 classify; f14 stores negotiated session version",
        arbitrary_server_supported_versions_qualified=False,
        source_primary={"sdk-model.rs":MODEL, "sdk-service-server.rs":SERVICE},
        author_sha256=sha(Path(__file__).read_bytes()), pseudo_sha256=sha(pseudo.read_bytes()),
        actual_public_native_qualified=False, actual_target_handshake_compared=False,
        full_sdk_qualified=False, production_activated=False, old_path_removed=False)
    (root / "native/runtime_mcp_get_info_composition.json").write_text(json.dumps(note, sort_keys=True, indent=2) + "\n")
    composition.update(source_sha256=sha(raw), source_bytes=len(raw))
    composition["function_sha256"] = {name: sha(encoded(function)) for name, function in after.items()}
    composition["functions"].update(names)
    composition["functions"].update(baseline_catalog="f52", baseline_prepare="f53")
    composition["target_get_info_extension"] = note
    (root / "native/runtime_mcp_composition.json").write_text(json.dumps(composition, sort_keys=True, indent=2) + "\n")
    print(json.dumps({key:note[key] for key in ("source_sha256", "source_bytes", "functions", "instructions", "owner_slot", "phase")}, sort_keys=True))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("hepta", "baseline", "root", "reference", "pseudo"):
        parser.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    generate(*(getattr(args, name).resolve() for name in ("hepta", "baseline", "root", "reference", "pseudo")))
