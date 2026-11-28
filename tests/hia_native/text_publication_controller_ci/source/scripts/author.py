#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Author publisher gateway and caller from exact retained HIA controllers."""
from __future__ import annotations
import argparse
import ast
import copy
import hashlib
import json
from pathlib import Path
import sys
sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
import source_support

SHA = lambda raw: hashlib.sha256(raw).hexdigest()
CANON = lambda value: json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
ENCODE = lambda value: (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()
WORD = lambda value: int.from_bytes(value.encode("ascii"), "little")
PINS = {
    "baseline/extract_call.hepta": "a7db249b735c5d8819fb5304bb301c839d84fd097f58e654b767b3cbee7f363a",
    "baseline/text_editor_gateway.hepta": "fc5efb3ef4a4f7679328358764d2b9bd5e3a6d2a5732751c1d53de0533f0c6e8",
}
# SOURCE_MANIFEST binds every original byte; these owner pins also prevent
# accidentally composing another controller template.
COMMON = {
    "INVALID": 0xffffffff, "CAPACITY": 0xfffffffe, "RESOURCE": 0xfffffffc,
    "MAXIMUM": (1 << 64) - 1, "PARAMS_RESULT": WORD("HTPPRR01"),
    "MESSAGE": WORD("HRCFGM01"), "PATH_REQUEST": WORD("HRSOLQ02"),
    "PATH_RESULT": WORD("HRSOLR02"), "CONFIG_REQUEST": WORD("HRCFGQ01"),
    "LOCAL_POLICY_REQUEST": WORD("HRLPCQ02"), "LOCAL_POLICY_RESULT": WORD("HLPCR002"),
    "BODY_REQUEST": WORD("HTPBQ001"), "BODY_RESULT": WORD("HTPBS001"),
    "KEY_REQUEST": WORD("HRLKKEY1"), "KEY_RESULT": WORD("HRLKY001"),
    "SCOPE_REQUEST": WORD("HRSCQ001"), "SCOPE_RESULT": WORD("HRSCR001"),
    "CACHE_REQUEST": WORD("HVCACH01"), "CACHE_RESULT": WORD("HVCAR001"),
}
LITERALS = {
    1: "create needs 'absent'; existing-file modes need exact lowercase SHA256",
    2: "Text input exceeds 64 KiB; use explicit chunked binary tools",
    3: "Plain-text publishing requires an explicit configured controller workspace",
    4: "Plain-text publication supports only controller-local workspace files",
    5: "runtime tools are disabled; start with --runtime-config <file>",
}
CALLER_MAGIC = dict(zip(
    ("HEXCLI01", "HEXCLR01", "HEXCLQ01", "HEXCST01", "HEXCCA01", "HEXPRR01"),
    ("HTPCLI01", "HTPCLR01", "HTPCLQ01", "HTPCST01", "HTPCCA01", "HTPPRR01")))
GATEWAY_MAGIC = dict(zip(
    ("HTEWGQ02", "HTEWGQ03", "HTEWGS03", "HTEWGA02", "HTEPRR02", "HTEPRQ02", "HTECQ002"),
    ("HTPWGQ02", "HTPWGQ03", "HTPWGS03", "HTPWGA01", "HTPPRR01", "HTPPRQ01", "HTPCLQ01")))

def require(value, message):
    if not value:
        raise ValueError(message)

def identity(raw):
    return {"bytes": len(raw), "sha256": SHA(raw)}

def literal_source():
    lines = ["def publisher_literal(w: mutbuf, at: u64, ident: u64) -> u64:"]
    for ident, value in LITERALS.items():
        raw = value.encode()
        lines.append("    if ident == " + str(ident) + ":")
        for index in range(0, len(raw) // 8 * 8, 8):
            lines.append("        put(w, at + " + str(index) + ", " + str(int.from_bytes(raw[index:index + 8], "little")) + ")")
        for index in range(len(raw) // 8 * 8, len(raw)):
            lines.append("        store(w, at + " + str(index) + ", " + str(raw[index]) + ")")
        lines.append("        return " + str(len(raw)))
    return "\n".join(lines + ["    return 0", ""])

def rename(assemble, render, raw, replacements, module):
    original = assemble(raw).as_dict()
    doc = copy.deepcopy(original)
    doc["module"] = module
    numeric = {WORD(a): WORD(b) for a, b in replacements.items()}
    changes = []
    for function in doc["functions"]:
        for block in function["blocks"]:
            for index, op in enumerate(block["ops"]):
                if op["op"] == "const" and type(op["attrs"]["value"]) is int and op["attrs"]["value"] in numeric:
                    old = op["attrs"]["value"]
                    op["attrs"]["value"] = numeric[old]
                    changes.append({"function": function["name"], "block": block["id"],
                        "operation": index, "before": old, "after": numeric[old]})
    require(set(x["before"] for x in changes) == set(numeric), "missing private magic relocation")
    inverse = copy.deepcopy(doc)
    inverse["module"] = original["module"]
    funcs = {f["name"]: f for f in inverse["functions"]}
    for item in changes:
        block = next(b for b in funcs[item["function"]]["blocks"] if b["id"] == item["block"])
        op = block["ops"][item["operation"]]
        require(op["op"] == "const" and op["attrs"]["value"] == item["after"], "private relocation anchor changed")
        op["attrs"]["value"] = item["before"]
    require(inverse == original, "private magic relocation inverse differs")
    return render(doc).encode(), changes


def check_call_graph(document):
    graph = {f["name"]: sorted({op["attrs"]["function"] for b in f["blocks"]
        for op in b["ops"] if op["op"] == "call"}) for f in document["functions"]}
    active, completed, order = [], set(), []
    def visit(name):
        require(name in graph, "call target absent: " + name)
        require(name not in active, "HIA caller graph cycle: " + " -> ".join(active + [name]))
        if name in completed:
            return
        active.append(name)
        for child in graph[name]:
            visit(child)
        require(active.pop() == name, "call graph traversal differs")
        completed.add(name)
        order.append(name)
    for name in graph:
        visit(name)
    return {"acyclic": True, "calls": graph, "leaves_first": order}

def preflight_specialization(seed, aliases, nodes):
    from hepta.hia_agent_assembly import assemble_program
    fs = {f["name"]: f for f in assemble_program(seed).as_dict()["functions"]}
    require(SHA(CANON(fs[aliases["business_error"]])) == "ba66d5d1564cde624c34e1a9733377167890efa1148f2182257887639e0c6188",
        "original business-error body differs")
    require(SHA(CANON(fs[aliases["prepare"]])) == "e7f9464d3502fd6db3980ffff25655cd9e5918a561569e966aa1e5114fbc7218",
        "original phase dispatcher differs")
    wanted = ast.parse("""def preflight_error(s: readbuf, o: mutbuf, w: mutbuf, at: u64, count: u64) -> u32:
    if reserve(w, 4, count) == 0:
        return pending_grow(o, w)
    copy_range(w, w, region(w, 4), at, count)
    put(w, 200, count)
    put(w, 216, 1)
    put(w, 8, 105)
    return prepare_scope(o, w, 5)
""").body[0]
    actual = next(node for node in nodes if node.name == "preflight_error")
    require(ast.dump(actual, include_attributes=False) == ast.dump(wanted, include_attributes=False),
        "preflight close specialization differs")
    return {"original_error": aliases["business_error"], "original_dispatcher": aliases["prepare"],
        "reserved_result_region": 4, "phase_write_offset": 8, "phase_value": 105,
        "actual_close_function": aliases["prepare_scope"], "actual_close_phase": 5,
        "generic_dispatch_recursion_removed": True, "other_error_paths_unchanged": True}

def produce(root, output, hepta, name, template, comp_path, alias_key, pseudo, magic, slots):
    from hepta.hia_agent_assembly import assemble_program, render_assembly
    original = (root / template).read_bytes()
    require(SHA(original) == PINS[template], "template source changed: " + template)
    comp = json.loads((root / comp_path).read_bytes())
    aliases = dict(comp[alias_key])
    require(set(aliases.values()) == set(f["name"] for f in assemble_program(original).as_dict()["functions"]),
        "template alias inventory differs")
    seed, magic_changes = rename(assemble_program, render_assembly, original, magic, "runtime_" + name)
    nodes = ast.parse(pseudo).body
    require(all(isinstance(node, ast.FunctionDef) for node in nodes), "non-function authoring form")
    names = [node.name for node in nodes]
    require(len(names) == len(set(names)), "duplicate authoring function")
    replacements = {n: aliases[n] for n in names if n in aliases}
    next_index = len(aliases)
    additions = {}
    for n in names:
        if n not in aliases:
            additions[n] = "f" + str(next_index)
            next_index += 1
    api = source_support.tools(hepta)
    raw, actual_names, compile_proof = source_support.compile_delta(api, seed, aliases, pseudo, COMMON, "runtime_" + name)
    require(actual_names == {**aliases, **additions}, "actual author function map differs")
    document = assemble_program(raw).as_dict()
    graph_proof = check_call_graph(document)
    preflight_proof = preflight_specialization(seed, aliases, nodes) if name == "text_publication_call" else None
    after = {f["name"]: f for f in document["functions"]}
    retained = compile_proof["retained_exact_functions"]
    concrete = ast.unparse(ast.Module(body=source_support.parsed_nodes(pseudo, COMMON), type_ignores=[])) + "\n"
    source_path = output / "native" / (name + ".hepta")
    source_path.write_bytes(raw)
    (output / "authoring" / (name + ".expanded.py.txt")).write_text(concrete)
    note = {
        "schema": "hepta.runtime.text-publication-controller-author.v1",
        "owner": name, "source": identity(raw), "template_path": template,
        "template": identity(original), "template_commit": (
            "27342064731d701925bfd202cd97d33bdd27bcee" if name == "text_publication_call"
            else "99d107c062a6eb3f226dd82b05283aeecbd3c495"),
        "private_magic_changes": magic_changes, "magic_inverse_ast_exact": True,
        "aliases": {**aliases, **additions}, "changed_functions": replacements,
        "new_functions": additions, "retained_exact_functions": retained,
        "call_graph": graph_proof, "preflight_close_specialization": preflight_proof,
        "function_sha256": {n: SHA(CANON(f)) for n, f in after.items()},
        "functions": len(after), "blocks": sum(len(f["blocks"]) for f in after.values()),
        "operations": sum(len(b["ops"]) for f in after.values() for b in f["blocks"]),
        "child_slots": slots,
        "public_qualified": False, "full_async_qualified": False,
        "production_installed": False, "old_stack_removed": False,
    }
    if name == "text_publication_call":
        require(set(replacements.values()) == {"f1", "f3", "f4", "f7", "f8", "f26"}, "caller retained seam changed")
        note.update(scope_lifecycle_retained_exact=True,
            phase2_substate_offset=424, phase3_substate_offset=440, key_length_offset=448,
            preflight_order=["valid_expectation", "content_limit", "actual_config_presence",
                "actual_path_resolution", "actual_local_path_policy"],
            success_order=["actual_publication_callable", "own_complete_result", "actual_lock_key",
                "actual_active_scope_cache_forget", "actual_hints", "actual_scope_close", "publish_owned_result"],
            no_history_add=True, no_context_from_public_input=True)
    else:
        require(set(replacements.values()) == {"f1"}, "gateway retained seam changed")
        note.update(typed_before_fence=True, fence_before_context=True,
            actual_client_and_session_context_retained=True,
            actual_outer_policy_retained=True, caller_result_owned_before_fence_release=True,
            raw_metadata_frame="HTPWGQ03", resolved_experimental_frame="HTPWGQ02")
    (output / "native" / (name + "_composition.json")).write_bytes(ENCODE(note))
    return note

def main():
    p = argparse.ArgumentParser()
    for name in ("source", "hepta", "output"):
        p.add_argument("--" + name, required=True, type=Path)
    a = p.parse_args()
    root = a.source.resolve(strict=True)
    hepta = a.hepta.resolve(strict=True)
    require(not a.output.exists(), "fresh author output required")
    (a.output / "native").mkdir(parents=True)
    (a.output / "authoring").mkdir()
    sys.path.insert(0, str(hepta))
    target = (root / "target/text_file_write.rs").read_text()
    for ident, value in LITERALS.items():
        if ident != 5:
            require('"' + value + '"' in target, "literal is not present in original target")
    caller = produce(root, a.output, hepta, "text_publication_call",
        "baseline/extract_call.hepta", "baseline/extract_call_composition.json", "aliases",
        (root / "authoring/caller.pseudo").read_text() + "\n" + literal_source(),
        CALLER_MAGIC, [29, 9, 67, 11, 7, 30, 68])
    gateway = produce(root, a.output, hepta, "text_publication_gateway",
        "baseline/text_editor_gateway.hepta", "baseline/text_editor_gateway_composition.json", "functions",
        (root / "authoring/gateway.pseudo").read_text(), GATEWAY_MAGIC, [65, 27, 5, 6, 11, 9, 7, 66, 3])
    (a.output / "AUTHOR.json").write_bytes(ENCODE({"caller": caller, "gateway": gateway}))
    print(json.dumps({"status": "AUTHORED_SOURCE_ONLY", "caller": caller["source"],
        "gateway": gateway["source"], "public_qualified": False}, sort_keys=True))

if __name__ == "__main__":
    main()
