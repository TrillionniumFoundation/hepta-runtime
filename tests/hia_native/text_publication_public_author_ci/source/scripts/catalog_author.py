# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Append one Tool from the retained actual native policy/SDK output."""
from __future__ import annotations
import json

INSTALLED = {"host_list", "effective_config", "execution_shadow_admit", "view", "workdir",
    "directory_create", "file_move", "directory_move", "text_editor", "extract_lines", "text_file_write"}

def literal(name, raw):
    rows = ["def " + name + "(o: mutbuf, at: u64) -> u64:",
            "    position = at", "    stride = 32"]
    wide = len(raw) // 32 * 32
    for offset in range(0, wide, 32):
        words = [int.from_bytes(raw[offset + i:offset + i + 8], "little") for i in (0, 8, 16, 24)]
        rows.append("    publication_literal_4(o, position, " + ", ".join(map(str, words)) + ")")
        rows.append("    position = position + stride")
    at = wide
    while at + 8 <= len(raw):
        rows.append("    put(o, position + " + str(at - wide) + ", "
                    + str(int.from_bytes(raw[at:at + 8], "little")) + ")")
        at += 8
    for offset in range(at, len(raw)):
        rows.append("    store(o, position + " + str(offset - wide) + ", " + str(raw[offset]) + ")")
    return "\n".join(rows + ["    return 0", ""])

def generate(api, source, support, inherited_assets):
    require, identity, SHA, ENCODE = support.require, support.identity, support.SHA, support.ENCODE
    assemble = api[-2]
    chosen, prefixes, provenance = {}, {}, {}
    for label, modern in (("ordinary", False), ("modern", True)):
        name = "authoring/public_extract/catalog_assets/actual/" + label + ".typed.json"
        raw = source[name]
        text, top, items = inherited_assets.exact_tools(raw)
        require(len(items) == 113 and top["resultType"][3] == "complete",
                "retained complete native typed catalog differs")
        selected = [(n, value) for n, value in items if n in INSTALLED]
        require(len(selected) == 11 and {n for n, _ in selected} == INSTALLED,
                "actual native catalog lacks an installed Tool")
        chosen[label] = selected
        if modern:
            require(list(top) == ["resultType", "ttlMs", "cacheScope", "tools"]
                    and top["ttlMs"][3] == 0 and top["cacheScope"][3] == "public",
                    "actual SDK cache-hint constructor differs")
            prefixes[label] = b',"result":' + text[:top["tools"][0]].encode()
        else:
            require(list(top) == ["resultType", "tools"], "ordinary result fields differ")
            prefixes[label] = b',"result":{'
        provenance[label] = {"source_path": name, "whole_source": identity(raw),
                            "selected": [{"name": n, **identity(v)} for n, v in selected]}
    require(chosen["ordinary"] == chosen["modern"], "native Tool bytes depend on policy")
    present = chosen["ordinary"]
    absent_name = "authoring/public_mixed_opener/catalog_assets/actual/ordinary.typed.json"
    _, _, absent_items = inherited_assets.exact_tools(source[absent_name])
    absent = [(n, v) for n, v in absent_items if n in INSTALLED]
    require(len(absent) == 8 and {n for n, _ in absent} == INSTALLED - {
        "host_list", "effective_config", "execution_shadow_admit"}, "actual no-config Tool set differs")
    require(all(dict(present)[n] == v for n, v in absent), "no-config Tool bytes differ")
    common = b'"tools":[' + b",".join(v for _, v in present) + b"]}}"
    filtered = b'"tools":[' + b",".join(v for _, v in absent) + b"]}}"
    offsets, offset = {}, 9
    for name, value in present:
        offsets[name] = (offset, len(value))
        require(common[offset:offset + len(value)] == value, "actual native Tool span differs")
        offset += len(value) + 1
    pieces = [common[:9]]
    for index, (name, value) in enumerate(absent):
        if index: pieces.append(b",")
        start, length = offsets[name]
        pieces.append(common[start:start + length])
    pieces.append(common[-3:])
    require(b"".join(pieces) == filtered, "configured copy spans differ from actual absent catalog")
    old = source["native/runtime_mcp_catalog_ninth.hepta"]
    comp = json.loads(source["native/runtime_mcp_catalog_ninth_composition.json"])
    require(comp["source_sha256"] == SHA(old) and comp["source_bytes"] == len(old),
            "current catalog composition differs")
    ordinary = len(prefixes["ordinary"])
    modern = len(prefixes["modern"])
    nodes = [
        "def publication_literal_4(o: mutbuf, at: u64, a: u64, b: u64, c: u64, d: u64) -> u64:\n"
        "    put(o, at, a)\n    put(o, at + 8, b)\n    put(o, at + 16, c)\n"
        "    put(o, at + 24, d)\n    return 0\n",
        "def target_size(policy: u64) -> u64:\n    return choose(policy == 0, "
        + str(ordinary + len(common)) + ", " + str(modern + len(common)) + ")\n",
        "def target_literal(o: mutbuf, at: u64, policy: u64) -> u64:\n"
        "    if policy == 0:\n        prefix_0(o, at)\n        common_literal(o, at + " + str(ordinary) + ")\n"
        "    elif policy == 1:\n        prefix_1(o, at)\n        common_literal(o, at + " + str(modern) + ")\n"
        "    return 0\n"]
    chunks = [(at, common[at:at + 512]) for at in range(0, len(common), 512)]
    nodes.append("def common_literal(o: mutbuf, at: u64) -> u64:\n"
        + "".join("    common_" + str(at) + "(o, at + " + str(at) + ")\n" for at, _ in chunks)
        + "    return 0\n")
    nodes.extend(literal("common_" + str(at), part) for at, part in chunks)
    lines = [
        "def configured_list(s: readbuf, o: mutbuf, w: mutbuf) -> u32:",
        "    if length(o) < 32:", "        return RESOURCE",
        "    if length(s) != 40:", "        return INVALID",
        "    modern = load(s, 16)", "    present = load(s, 24)",
        "    if modern > 1 or present > 1 or load(s, 32) != 11:", "        return INVALID",
        "    if length(w) < " + str(4096 + len(common)) + ":",
        "        return grow(o, 1, " + str(4096 + len(common)) + ")",
        "    prefix = choose(modern == 0, " + str(ordinary) + ", " + str(modern) + ")",
        "    size = prefix + choose(present == 1, " + str(len(common)) + ", " + str(len(filtered)) + ")",
        "    if length(o) - 32 < size:", "        return grow(o, 2, 32 + size)",
        "    if modern == 0:", "        prefix_0(o, 32)",
        "    else:", "        prefix_1(o, 32)",
        "    at = 32 + prefix", "    if present == 1:", "        common_literal(o, at)",
        "    else:", "        common_literal(w, 4096)",
        "        copy_range(o, w, at, 4096, 9)"]
    used = 9
    for index, (name, value) in enumerate(absent):
        if index:
            lines.append("        store(o, at + " + str(used) + ", 44)")
            used += 1
        start, length = offsets[name]
        lines.append("        copy_range(o, w, at + " + str(used) + ", "
                     + str(4096 + start) + ", " + str(length) + ")")
        used += length
    lines += ["        copy_range(o, w, at + " + str(used) + ", "
              + str(4096 + len(common) - 3) + ", 3)", "    return finish(o, size)", ""]
    require(used + 3 == len(filtered), "complete filtered extent differs")
    nodes.append("\n".join(lines))
    raw, aliases, proof = support.compile_delta(api, old, comp["aliases"], "\n".join(nodes),
        {"INVALID": 0xffffffff, "RESOURCE": 0xfffffffe}, assemble(old).as_dict()["module"])
    after = assemble(raw).as_dict()
    proof.update(schema="hepta.runtime.public-publication.catalog-author.v1",
        baseline=identity(old), actual_native_source_run=43813791993,
        actual_native_source_artifact=14201568537, selected_present=identity(common),
        selected_absent=identity(filtered), tools_present=[n for n, _ in present],
        tools_absent=[n for n, _ in absent], provenance=provenance,
        absent_whole_source=identity(source[absent_name]), absent_copy_offsets=offsets,
        current_installed_profile=11, minimum_configured_workspace=4096 + len(common),
        compact_literal="four ordered calls to the unchanged checked u64 writer",
        expected_original_wire_used_as_implementation=False, old_non_list_functions_exact=True,
        native_executed=False, rust_executed=False, public_qualified=False)
    comp.update(source_bytes=len(raw), source_sha256=SHA(raw), aliases=aliases,
        functions=len(after["functions"]), blocks=proof["blocks"], operations=proof["operations"],
        text_publication_extension=proof)
    return {"native/runtime_mcp_catalog_ninth.hepta": raw,
            "native/runtime_mcp_catalog_ninth_composition.json": ENCODE(comp),
            "native/runtime_mcp_publication_catalog_composition.json": ENCODE(proof)}, proof
