"""Compose exact installed102 and qualified task-pump sources without execution.

The installed graph remains the base. All Batch members, capacity corrections,
the fast constructor and Batch release guards are retained. The separately
qualified task-pump graph supplies its original host, registry and Bellman port.
This source operation does not claim any qualification of the combined graph.
"""
from __future__ import annotations

import argparse
import ast
import copy
import hashlib
import json
from pathlib import Path
import shutil
import stat
import sys

sys.dont_write_bytecode = True
BASE_COMMIT = "0a8f9d6603abaf85f702ff2626dbe75f5d5f841c"
PUMP_COMMIT = "63c366a278a51c1407e5929524b66684747a6e23"
BASE_PIN = "41a42a6247d8b4bf0ccee11e743bad28285273637b9f824fcbf2f0bf9bad0726"
PUMP_PIN = "efb1931eb19d9b6628eced32d1e6b4e2000156fea0b8bbf96d3c612ee95470f0"
PORT_PIN = "2563acb466285cc6d9fbf3f91508b1ea0785904230263bcdea5866c30f801bb1"
PORT_DEST = "runtime_support/bellman_port"
SHA = lambda raw: hashlib.sha256(raw).hexdigest()
ENCODE = lambda value: (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()


def require(value, message):
    if not value:
        raise ValueError(message)


def pin(raw):
    return {"bytes": len(raw), "sha256": SHA(raw)}


def admitted(root, expected):
    root = root.resolve(strict=True)
    raw = (root / "native/runtime_mcp_sources.json").read_bytes()
    require(SHA(raw) == expected, "source closure pin changed")
    manifest = json.loads(raw)
    require(manifest["schema"] == "hepta.runtime.public-source-closure.v2", "source schema changed")
    data = {}
    for name, identity in manifest["sources"].items():
        rel = Path(name)
        require(not rel.is_absolute() and ".." not in rel.parts and rel.as_posix() == name,
                "source path escaped the declared root")
        path = root / rel
        require(path.is_file() and not path.is_symlink(), "source is not an owned regular file")
        value = path.read_bytes()
        require(pin(value) == identity, "source bytes changed: " + name)
        data[name] = value
    data["native/runtime_mcp_sources.json"] = raw
    require(len(data) == 218, "input graph closure count changed")
    return manifest, data


def replace_once(text, previous, current):
    require(previous != current and text.count(previous) == 1,
            "source anchor is not unique: " + previous[:120])
    return text.replace(previous, current, 1)


def assigned(text, name):
    rows = [node for node in ast.parse(text).body if isinstance(node, ast.Assign)
            and any(isinstance(target, ast.Name) and target.id == name for target in node.targets)]
    require(len(rows) == 1, "Python assignment changed: " + name)
    return rows[0], ast.literal_eval(rows[0].value)


def set_list(text, name, value):
    node, _ = assigned(text, name)
    lines = text.splitlines(keepends=True)
    lines[node.lineno - 1:node.end_lineno] = [name + " = [\n"] + ["    " + repr(row) + ",\n" for row in value] + ["]\n"]
    return "".join(lines)


def segment(text, first, after):
    require(text.count(first) == text.count(after) == 1, "assembly segment anchor changed")
    start, end = text.index(first), text.index(after)
    require(start < end, "assembly segment order changed")
    return text[start:end]


def merge_engine(base, pump):
    changes = []

    def change(old, new, purpose):
        nonlocal base
        base = replace_once(base, old, new)
        changes.append({"before": old, "after": new, "purpose": purpose})

    change("57 rows at engine+8192; slots47-52 bind Batch while56 remains Authority.",
           "59 rows at engine+8192; Batch47-52, Authority56, Bellman57 and request registry58.",
           "describe the fixed combined descriptor table")
    change(".equ RG_SLOTS, 57", ".equ RG_SLOTS, 59", "extend only the fixed descriptor count")
    guard = segment(pump, "    /* The process-owned Bellman port must be detached", "    xor ebp, ebp\nruntime_grow_destroy_admit:")
    change("runtime_grow_destroy_fs_admitted:\n    cmp qword ptr [r15 + 416], 0\n    jne runtime_grow_destroy_invalid\n",
           "runtime_grow_destroy_fs_admitted:\n    cmp qword ptr [r15 + 416], 0\n    jne runtime_grow_destroy_invalid\n" + guard,
           "retain Batch destruction guard and add the exact Bellman detached-port guard")
    change("    cmp ebp, 52\n    je runtime_grow_batch_body_dispatch\n",
           "    cmp ebp, 52\n    je runtime_grow_batch_body_dispatch\n    cmp ebp, 57\n    je runtime_grow_bellman_dispatch\n",
           "retain the Batch callable and add the fixed Bellman capability")
    hint = segment(pump, "    /* A new, admitted slot10 call ends", "    cmp ebp, 27\n    jne runtime_grow_resume_filesystem_caller\n")
    change("runtime_grow_resume:\n", "runtime_grow_resume:\n" + hint,
           "copy the qualified bounded Value output-capacity hint")
    change("    mov rdx, 0x323052464d435248 /* HRCMFR02 */\n    cmp [r13], rdx\n    jne runtime_grow_bad\n",
           "    mov rdx, 0x323052464d435248 /* HRCMFR02 */\n    cmp [r13], rdx\n    jne runtime_grow_bad\n    cmp qword ptr [r13 + 8], 4\n    je runtime_grow_frontend_pending\n",
           "recognize only the qualified pending result kind")
    pending = segment(pump, "runtime_grow_frontend_pending:\n", "runtime_grow_connection_result:\n")
    change("runtime_grow_connection_result:\n", pending + "runtime_grow_connection_result:\n",
           "copy the exact 64-byte pending result extent and zero-word checks")
    bellman = segment(pump, "runtime_grow_bellman_dispatch:\n", "runtime_grow_authority_dispatch:\n")
    change("runtime_grow_authority_dispatch:\n", bellman + "runtime_grow_authority_dispatch:\n",
           "copy the fixed owned-export capability call at offset2469")
    change("runtime_grow_target_frontend:\n    cmp rsi, 13\n",
           "runtime_grow_target_frontend:\n    cmp rsi, 14\n", "allow the fixed new frontend child14")
    change("    .zero 48 /* 51..56: no controller action; Authority is a capability. */",
           "    .zero 64 /* 51..58: no controller action; Authority and Bellman are capabilities. */",
           "extend the zero-action table while retaining every Batch action magic")
    change("    .byte 19, 1, 0, 10, 2, 13, 11, 20, 21, 37, 46, 54, 56, 47\n",
           "    .byte 19, 1, 0, 10, 2, 13, 11, 20, 21, 37, 46, 54, 56, 47, 57\n",
           "retain all existing frontend targets and append Bellman57")
    return base, changes


def merge_builder(base, pump):
    _, original_members = assigned(base, "MEMBERS")
    _, pump_members = assigned(pump, "MEMBERS")
    require(len(original_members) == 102 and len(pump_members) == 92, "member count changed")
    require(original_members[-5:] == pump_members[-5:], "fence ordering changed")
    members = original_members[:-5] + [("request_tasks", "sdk_request_task_registry", "history.v1")] + original_members[-5:]
    _, original_edges = assigned(base, "EXTRA")
    require(len(original_edges) == 57, "installed extra table changed")
    require(original_edges[47:53] == ["batch_gateway", "batch_params", "batch_call", "batch_adapter", "batch_input", None],
            "installed Batch bindings changed")
    _, original_boundaries = assigned(base, "BOUNDARIES")
    _, pump_boundaries = assigned(pump, "BOUNDARIES")
    host_boundaries = [name for name in pump_boundaries if name not in original_boundaries]
    require(len(host_boundaries) == 6 and all("runtime_mcp_task_" in name for name in host_boundaries),
            "unexpected new host mechanical source")
    out = set_list(pump, "MEMBERS", members)
    out = set_list(out, "EXTRA", original_edges)
    out = set_list(out, "BOUNDARIES", host_boundaries + original_boundaries)
    out = replace_once(out, "len(MEMBERS) != 92", "len(MEMBERS) != 103")
    authority = "authority_images=[images[n] for n in ('authority','authority_record','authority_kdf','rf_sha','authority_aead','authority_nonce','authority_scope','authority_entropy','authority_loader')])"
    batch = "batch_images=[images[n] for n in ('batch_body','batch_lock','key','tb_history','tb_atomic','cache','lc_read','tb_lock','tb_edit','batch_plan','endpoint','batch_verify','batch_apply','batch_render')])"
    require(batch in base, "installed Batch pack table changed")
    out = replace_once(out, authority, authority[:-1] + ",\n                                    " + batch)
    out = replace_once(out, "'schema': 'hepta.runtime.public-nine-build.v1'",
                       "'schema': 'hepta.runtime.public-task-batch-build.v1'")
    out = replace_once(out, "'target_text_constructor_source_sha256': '3a4c9b40136e0c3dbf3b580e475447e94fb79913f93416a0ec906da6d294996d'",
                       "'target_text_constructor_source_sha256': '785315acd60821313e4683df67e0b83c59c572d798ad3849efaa3108a9e36d58'")
    line = "              'authority_slot': 56, 'authority_context_offset': 432,\n"
    additions = ("              'batch_private_slots': [47,48,49,50,51,52],\n"
                 "              'batch_public_route_registered': True, 'batch_public_route_qualified': False,\n"
                 "              'batch_gateway_caller_qualified': False, 'batch_callable_scope_borrow_maximum': 1048672,\n"
                 "              'advertised_catalog_tools': 9,\n"
                 "              'candidate_extra_registered_tools': ['batch_edit', 'weight_bellman_plan'],\n"
                 "              'combined_installed102_task_pump_qualified': False,\n")
    out = replace_once(out, line, line + additions)
    return out


def prove_frontend(hepta, base, pump):
    sys.path.insert(0, str(hepta.resolve(strict=True)))
    from hepta.hia_agent_assembly import assemble_program
    original = assemble_program(base).as_dict()
    joined = assemble_program(pump).as_dict()
    old, new = original["functions"], joined["functions"]
    require(len(old) == 73 and len(new) == 84, "frontend function count changed")
    kept = {}
    for number, function in enumerate(old):
        if number in (0, 8, 29):
            continue
        require(function == new[number], "retained frontend AST changed: f" + str(number))
        kept["f" + str(number)] = SHA(ENCODE(function))
    for before, after in ((8, 74), (29, 75)):
        restored = copy.deepcopy(new[after])
        restored["name"] = "f" + str(before)
        require(restored == old[before], "relocated frontend AST differs")
    entry = copy.deepcopy(new[73])
    entry["name"] = "f0"
    blocks = {block["id"]: block for block in entry["blocks"]}
    for block, output, current, previous in (("b19", "v161", 117, 114), ("b21", "v177", 17, 14)):
        rows = [op for op in blocks[block]["ops"] if op.get("out") == [{"name": output, "type": "u64"}]]
        require(len(rows) == 1 and rows[0]["op"] == "const" and rows[0]["attrs"]["value"] == current,
                "retained entry phase constant changed")
        rows[0]["attrs"]["value"] = previous
    # The retained entry also dispatches only the new phase range15..17 to
    # after_bellman. Its false branch carries the original predicate and all
    # original arguments unchanged through an otherwise empty block.
    old_blocks = {block["id"]: block for block in old[0]["blocks"]}
    require(blocks["b57"]["params"] == old_blocks["b57"]["params"], "entry dispatch parameters changed")
    require(blocks["b57"]["ops"][:-2] == old_blocks["b57"]["ops"], "entry original predicate changed")
    require(blocks["b57"]["ops"][-2:] == [
        {"args": [], "attrs": {"value": 15}, "op": "const", "out": [{"name": "v900000", "type": "u64"}]},
        {"args": ["v467", "v900000"], "attrs": {}, "op": "compare.ge", "out": [{"name": "v900001", "type": "bool"}]}],
        "new phase dispatch predicate changed")
    require(blocks["b57"]["term"] == {"op": "branch", "cond": "v900001",
        "then": {"target": "b74", "args": old_blocks["b57"]["term"]["then"]["args"]},
        "else": {"target": "b75", "args": ["v70001", *old_blocks["b57"]["term"]["else"]["args"]]}},
        "new phase dispatch edges changed")
    require(blocks["b74"]["ops"] == [{"args": ["v900010", "v900011", "v900012", "v900013", "v900014", "v900015"],
        "attrs": {"function": "f77"}, "op": "call", "out": [{"name": "v900016", "type": "u32"}]}]
        and blocks["b74"]["term"] == {"op": "ret", "values": ["v900016"]}, "new Bellman completion edge changed")
    require(blocks["b75"]["ops"] == [], "original phase relay acquired an operation")
    relay = copy.deepcopy(blocks["b75"]["term"])
    rename = dict(zip([row["name"] for row in blocks["b75"]["params"]], blocks["b57"]["term"]["else"]["args"]))
    relay["cond"] = rename[relay["cond"]]
    for edge in ("then", "else"):
        relay[edge]["args"] = [rename[name] for name in relay[edge]["args"]]
    require(relay == old_blocks["b57"]["term"], "original phase relay does not preserve its edge and arguments")
    blocks["b57"]["ops"] = blocks["b57"]["ops"][:-2]
    blocks["b57"]["term"] = relay
    added_blocks = {name: SHA(ENCODE(blocks[name])) for name in ("b74", "b75")}
    entry["blocks"] = [block for block in entry["blocks"] if block["id"] not in added_blocks]
    require(entry == old[0], "retained entry inverse AST differs")
    return {"schema": "hepta.runtime.installed102-pump-frontend-preservation.v1",
            "before": pin(base), "after": pin(pump), "before_functions": 73, "after_functions": 84,
            "retained_exact_functions": kept, "relocated_exact_functions": {"f8": "f74", "f29": "f75"},
            "entry_inverse_phase_constants": [[117, 114], [17, 14]],
            "added_completion_dispatch_blocks": added_blocks,
            "entry_inverse_ast_exact": True, "native_executed": False, "rust_executed": False}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ("installed-source", "pump-source", "port-package", "hepta", "output"):
        p.add_argument("--" + name, type=Path, required=True)
    a = p.parse_args()
    require(not a.output.exists(), "new composition output already exists")
    base_manifest, base = admitted(a.installed_source, BASE_PIN)
    pump_manifest, pump = admitted(a.pump_source, PUMP_PIN)
    require(SHA((a.port_package / "PACKAGE.json").read_bytes()) == PORT_PIN, "port package changed")
    report = {"schema": "hepta.runtime.installed102-task-pump-source-union.v1",
              "installed_commit": BASE_COMMIT, "qualified_pump_commit": PUMP_COMMIT,
              "installed_binding_sha256": BASE_PIN, "qualified_pump_binding_sha256": PUMP_PIN,
              "native_executed": False, "rust_executed": False,
              "combined_graph_qualified": False, "async_qualified": False,
              "full_sdk_qualified": False, "production_activated": False, "old_path_removed": False}
    data = dict(base)
    additions = sorted(set(pump) - set(base))
    require(len(additions) == 26, "qualified pump-only source set changed")
    data.update({name: pump[name] for name in additions})
    adopted = ["native/runtime_mcp.hepta", "native/runtime_mcp_composition.json",
               "native/sdk_message_target.hepta", "native/serde_json_span.hepta"]
    for name in adopted:
        data[name] = pump[name]
    report["frontend_ast"] = prove_frontend(a.hepta, base["native/runtime_mcp.hepta"], pump["native/runtime_mcp.hepta"])
    engine_name = "scripts/runtime_mcp_extra_engine.S"
    engine, changes = merge_engine(base[engine_name].decode(), pump[engine_name].decode())
    inverse = engine
    for row in reversed(changes):
        inverse = replace_once(inverse, row["after"], row["before"])
    require(inverse.encode() == base[engine_name], "mechanical engine inverse is not byte exact")
    data[engine_name] = engine.encode()
    report["engine_edits"] = changes
    report["engine_inverse_byte_exact"] = True
    transport_name = "scripts/runtime_mcp_transport.S"
    data[transport_name] = replace_once(pump[transport_name].decode(),
        "    /* SDK registry58 has closed transport and drained owned tasks. */\n    call runtime_text_body_release\n",
        "    /* SDK registry58 has closed transport and drained owned tasks. */\n"
        "    call runtime_batch_body_release\n    test rax, rax\n    jnz public_span_fail\n"
        "    call runtime_text_body_release\n").encode()
    report["transport_merge"] = {"qualified_pump_text_retained": True,
        "added_release": "runtime_batch_body_release", "order": ["SDK send/drain/close", "Bellman detach/shutdown/reap", "Batch release", "Text release", "authority release", "shared filesystem hub release", "config lease teardown"]}
    builder_name = "scripts/public_nine_build.py"
    data[builder_name] = merge_builder(base[builder_name].decode(), pump[builder_name].decode()).encode()
    # The actual main builder is an explicit source-only dependency entry, not
    # the older 91-image wrapper retained inside the qualification snapshot.
    wrapper = Path(__file__).with_name("main_default_builder.py").read_bytes()
    compile(wrapper, "main_default_builder.py", "exec")
    data["scripts/hia_native_runtime_mcp_build.py"] = wrapper
    require(data["scripts/text_editor_create_private_pack.py"] == base["scripts/text_editor_create_private_pack.py"],
            "installed Batch packer was replaced")
    retained_special = ["native/sdk_request_target.hepta", "native/sdk_frontend_bridge_target.hepta",
                        "native/sdk_public_protocol.hepta", "native/sdk_public_protocol_composition.json",
                        "native/text_result_constructor.hepta", "native/text_result_constructor.composition.json",
                        "scripts/runtime_mcp_filesystem_fixture.S"]
    for name in retained_special:
        require(data[name] == base[name], "installed capacity/performance source was not retained")
    report["retained_installed_shared_corrections"] = {name: pin(base[name]) for name in retained_special}
    report["adopted_qualified_sources"] = {name: pin(pump[name]) for name in adopted + additions}
    package_manifest = json.loads((a.port_package / "PACKAGE.json").read_bytes())
    declared = {row["path"]: {"bytes": row["bytes"], "sha256": row["sha256"]}
                for row in package_manifest["files"]} if isinstance(package_manifest["files"], list) else package_manifest["files"]
    declared["PACKAGE.json"] = pin((a.port_package / "PACKAGE.json").read_bytes())
    require(len(declared) == 143, "frozen port dependency file count changed")
    for name, identity in declared.items():
        path = a.port_package / name
        require(path.is_file() and not path.is_symlink(), "port source is not a regular file")
        raw = path.read_bytes()
        require(pin(raw) == {key: identity[key] for key in ("bytes", "sha256")}, "port source identity changed")
        data[PORT_DEST + "/" + name] = raw
    report["fixed_dependency"] = {"path": PORT_DEST, "package_sha256": PORT_PIN, "files": 143,
                                  "hia_images": 8, "requires_existing_build": False}
    report["layout"] = {"direct_hia_members": 103, "packed_hia_members": 8,
        "expected_runtime_hia_images": 111, "expected_physical_containers": 104,
        "descriptor_slots": 59, "descriptor_base": 8192, "engine_bytes": 16384,
        "batch_slots": [47, 48, 49, 50, 51, 52], "shutdown_slot": 53, "get_info_slot": 54,
        "connection_slot": 55, "authority_slot": 56, "bellman_slot": 57, "registry_slot": 58,
        "reserved_successor_slots": [59, 60, 61, 62, 63],
        "advertised_catalog_tools": 9, "new_catalog_configuration_not_installed": True}
    report["proof_scope"] = "SOURCE_COMPOSITION_ONLY_FRESH_BUILD_AND_ALL_DOMAINS_REQUIRED"
    data["native/public_task_batch_source_union.json"] = ENCODE(report)
    binding = copy.deepcopy(base_manifest)
    binding["qualification"] = {"all_previous_nested_flags_are_historical_only": True,
        "combined_task_pump_batch": "NOT_RUN", "async": False, "full_sdk": False}
    binding["current_layout"] = report["layout"]
    binding["task_pump_extension"] = {"source_commit": PUMP_COMMIT, "qualified_serial_wire_run": 43916467554,
        "qualified_readonly_run": 43921444127, "qualified_source_binding_sha256": PUMP_PIN,
        "qualification_does_not_transfer_to_combined_graph": True,
        "ordinary_notification_drops_handler_future": False, "source_composition": "native/public_task_batch_source_union.json"}
    binding["sources"] = {name: pin(raw) for name, raw in sorted(data.items()) if name != "native/runtime_mcp_sources.json"}
    data["native/runtime_mcp_sources.json"] = ENCODE(binding)
    a.output.mkdir(parents=True)
    source = a.output / "source"
    for name, raw in sorted(data.items()):
        path = source / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
        original = a.installed_source / name if name in base else a.pump_source / name
        mode = stat.S_IMODE(original.stat().st_mode) if original.is_file() else 0o644
        if name.startswith(PORT_DEST + "/"):
            mode = stat.S_IMODE((a.port_package / name[len(PORT_DEST) + 1:]).stat().st_mode)
        path.chmod(mode)
        if name.endswith(".py"):
            compile(raw, name, "exec")
    changed = []
    for name, raw in sorted(data.items()):
        if name in base and raw == base[name]:
            continue
        changed.append({"path": name, "operation": "change" if name in base else "add",
                        "before": pin(base[name]) if name in base else None, "after": pin(raw),
                        "mode": format(stat.S_IMODE((source / name).stat().st_mode), "04o")})
    install = {"schema": "hepta.runtime.installed102-task-pump-install.v1",
        "base_commit": BASE_COMMIT, "source_binding": pin(data["native/runtime_mcp_sources.json"]),
        "source_files": len(data), "source_bytes": sum(map(len, data.values())), "rows": changed,
        "unchanged_base_files": sum(data.get(name) == raw for name, raw in base.items()),
        "status": "SOURCE_ONLY", "native_executed": False, "rust_executed": False}
    (a.output / "INSTALL.json").write_bytes(ENCODE(install))
    (a.output / "SOURCE_PROOF.json").write_bytes(ENCODE(report))
    print(json.dumps({key: value for key, value in install.items() if key != "rows"}, sort_keys=True))


if __name__ == "__main__":
    main()
