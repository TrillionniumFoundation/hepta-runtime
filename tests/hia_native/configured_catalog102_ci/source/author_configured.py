"""Add a private, source-bound configuration selector to the qualified catalog.

The only declaration bytes come from the previously admitted HIA policy ->
Value -> SDK pipeline.  This author never reads an original expected reply.
The old entry and every old helper are retained exactly; operation 7 selects
whole already-serialized Tool spans according to the target classification
and the caller's fixed installed-capability mask.
"""
from __future__ import annotations

import argparse
import ast
import copy
import hashlib
import json
from pathlib import Path
import sys

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parent
BASE_SHA = "a06073afcfbd748dfcb5bceeec8ed2fff1f44a6cfda3bec2ec0e9af443c0e258"
ASSET_SHAS = (
    "a63aa2d353d4b490fbd2ec9bbb9648a7d7a0a834f9bf3921d9715d3f846598c1",
    "718801779565d7d7932bdd86e0eb3b209614d3e523e23bf66298e378af8217cd",
)
TARGET = "d3d75c30719db966b004756f610007a7c723729e"
SELECTED = (
    "batch_edit", "directory_create", "directory_move", "effective_config",
    "execution_shadow_admit", "file_move", "host_list", "text_editor", "view",
    "weight_bellman_plan", "workdir",
)
FLAGS = (0, 1, 3, 5, 7, 9, 11, 13, 15)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + "\n").encode()


def graph_pin(value):
    return sha(json.dumps(value, sort_keys=True, separators=(",", ":")).encode())


def decoder_access_proof(source, common, data_base, required_workspace):
    """Check every access of the new one-buffer decoder on its fixed input."""
    packed = (source / "retained/native/catalog-common.lzss").read_bytes()
    arena = bytearray([0x59]) * required_workspace
    arena[:len(packed)] = packed
    arena[len(packed):data_base] = bytes(data_base - len(packed))
    at, end, events = 0, data_base, []
    digest = hashlib.sha256()
    def read(offset, source_kind):
        if source_kind == 0:
            assert 0 <= offset < len(packed)
        else:
            assert data_base <= offset < end
        value = arena[offset]
        digest.update(bytes((source_kind, value)) + offset.to_bytes(8, "little"))
        return value
    def write(offset, value):
        assert data_base <= offset < required_workspace
        digest.update(b"\x02" + bytes((value,)) + offset.to_bytes(8, "little"))
        arena[offset] = value
    while at < len(packed):
        token = at
        tag = read(at, 0); at += 1
        start = end
        if tag < 128:
            count, distance = tag + 1, 0
            for _ in range(count):
                write(end, read(at, 0)); at += 1; end += 1
        else:
            distance = read(at, 0) | (read(at + 1, 0) << 8); at += 2
            count = (tag & 127) + 3
            assert 0 < distance <= start - data_base
            for _ in range(count):
                write(end, read(end - distance, 1)); end += 1
        events.append([token, at, start, end, distance])
    assert at == len(packed) and bytes(arena[data_base:end]) == common
    assert end == data_base + len(common)
    assert bytes(arena[end:]) == b"\x59" * (required_workspace - end)
    return {"compressed_sha256": sha(packed), "complete_access_stream_sha256": digest.hexdigest(),
        "token_events": events, "source_range": [0, len(packed)],
        "destination_range": [data_base, end], "padding_bytes_untouched": required_workspace - end,
        "decoded_sha256": sha(common), "all_backreferences_precede_each_written_byte": True,
        "native_execution": False}


def inputs(source):
    retained = source / "retained"
    profile = json.loads((retained / "source-profile.json").read_bytes())
    assert {p.relative_to(retained).as_posix() for p in retained.rglob("*") if p.is_file()} == set(profile["files"]) | {"source-profile.json"}
    for name, pin in profile["files"].items():
        raw = (retained / name).read_bytes()
        assert len(raw) == pin["bytes"] and sha(raw) == pin["sha256"], name
    baseline = (retained / "native/runtime_mcp_catalog_eleven.hepta").read_bytes()
    assert sha(baseline) == BASE_SHA
    proof = json.loads((retained / "native/catalog-eleven-composition.json").read_bytes())
    assert proof["source_sha256"] == BASE_SHA
    assert proof["literal_producer"] == "actual catalog_eleven_policy -> serde Value -> SDK op4"
    assert proof["expected_original_wire_used_as_implementation"] is False
    declarations = json.loads((retained / "pipeline/policy_base/declarations.json").read_bytes())
    assert declarations["target_commit"] == TARGET
    assets = [(retained / f"native/catalog-mode-{mode}.bin").read_bytes() for mode in (0, 1)]
    assert tuple(sha(raw) for raw in assets) == ASSET_SHAS
    positions = [raw.index(b'"tools":[') for raw in assets]
    assert positions == [11, 67]
    common = assets[0][positions[0]:]
    assert assets[1][positions[1]:] == common
    assert common.endswith(b"]}}")
    # Find exact encoded Tool spans, preserving every byte and key order from
    # the native SDK serializer, including escaped Unicode and descriptions.
    spans = []
    at = len(b'"tools":[')
    decoder = json.JSONDecoder()
    for index, name in enumerate(SELECTED):
        tail = common[at:].decode("utf-8")
        tool, chars = decoder.raw_decode(tail)
        raw = tail[:chars].encode("utf-8")
        assert tool["name"] == name and common[at:at + len(raw)] == raw
        spans.append({"index": index, "name": name, "start": at, "bytes": len(raw),
            "sha256": sha(raw), "runtime_only": name in declarations["runtime_tool_names"],
            "hia_worker": name in declarations["hia_tool_names"],
            "weight_worker": name in declarations["weight_tool_names"],
            "rea_static": name.startswith("rea_static_")})
        at += len(raw)
        if index + 1 < len(SELECTED):
            assert common[at:at + 1] == b","; at += 1
    assert common[at:] == b"]}}"
    assert {r["name"] for r in spans if r["runtime_only"]} == {
        "effective_config", "execution_shadow_admit", "host_list", "weight_bellman_plan"}
    assert not any(r["hia_worker"] or r["weight_worker"] or r["rea_static"] for r in spans)
    return baseline, proof, assets, positions, common, spans


def generate(hepta, source, output):
    raw, old_proof, assets, prefixes, common, spans = inputs(source)
    sys.path.insert(0, str(hepta))
    from tools.generate_hia_selfhost import Builder, total_scalar_functions
    from hepta.hia_agent_assembly import assemble_program, render_assembly
    baseline = assemble_program(raw).as_dict()
    assert len(baseline["functions"]) == 55
    assert [f["name"] for f in baseline["functions"]] == [f"f{i}" for i in range(55)]
    data_base = old_proof["workspace_required"]
    assert data_base == 6960 and old_proof["compressed_bytes"] == 6956
    required_workspace = (data_base + len(common) + 7) & ~7
    assert required_workspace == 22152
    access_proof = decoder_access_proof(source, common, data_base, required_workspace)
    lines = [
        "def configured(s: readbuf, o: mutbuf, w: mutbuf) -> u32:",
        "    if length(s) >= 16:",
        "        if read64(s, 8) == 7:",
        "            return select_catalog(s, o, w)",
        "    return retained_entry(s, o, w)",
        "def select_catalog(s: readbuf, o: mutbuf, w: mutbuf) -> u32:",
        "    if length(s) != 40:",
        "        return 4294967295",
        "    if read64(s, 0) != 3616443570523558472 or read64(s, 8) != 7:",
        "        return 4294967295",
        "    mode = read64(s, 16)",
        "    flags = read64(s, 24)",
        "    installed = read64(s, 32)",
        "    if mode > 1 or flags > 15 or installed > 3:",
        "        return 4294967295",
        "    if flags != 0 and (flags & 1) == 0:",
        "        return 4294967295",
        "    if length(o) < 32:",
        "        return 4294967294",
        f"    if length(w) < {required_workspace}:",
        f"        return grow(o, 1, {required_workspace})",
        "    size = selected_size(mode, flags, installed)",
        "    if size > length(o) - 32:",
        "        return grow(o, 2, size + 32)",
        "    expand_workspace(w)",
        "    p = 32",
        "    if mode == 0:",
        "        p = prefix0(o, p)",
        "    else:",
        "        p = prefix1(o, p)",
        f"    p = copy_span(o, p, w, {data_base}, 9)",
        "    index = 0",
        "    emitted = 0",
        "    while index < 11:",
        "        if visible(index, flags, installed) != 0:",
        "            if emitted != 0:",
        "                store(o, p, 44)",
        "                p = p + 1",
        f"            p = copy_span(o, p, w, {data_base} + span_start(index), span_size(index))",
        "            emitted = emitted + 1",
        "        index = index + 1",
        "    store(o, p, 93)",
        "    store(o, p + 1, 125)",
        "    store(o, p + 2, 125)",
        "    return result(o, size)",
        "def visible(index: u64, flags: u64, installed: u64) -> u64:",
        "    if index == 0 and (installed & 1) == 0:",
        "        return 0",
        "    if index == 9 and (installed & 2) == 0:",
        "        return 0",
        "    if (flags & 1) == 0:",
        "        if index == 3 or index == 4 or index == 6 or index == 9:",
        "            return 0",
        "    return 1",
        "def selected_size(mode: u64, flags: u64, installed: u64) -> u64:",
        "    total = 23",
        "    if mode == 1: total = 79",
        "    index = 0",
        "    count = 0",
        "    while index < 11:",
        "        if visible(index, flags, installed) != 0:",
        "            total = total + span_size(index)",
        "            count = count + 1",
        "        index = index + 1",
        "    return total + count - 1",
        "def span_start(index: u64) -> u64:",
    ]
    for row in spans[:-1]:
        lines.append(f"    if index == {row['index']}: return {row['start']}")
    lines.append(f"    return {spans[-1]['start']}")
    lines.append("def span_size(index: u64) -> u64:")
    for row in spans[:-1]:
        lines.append(f"    if index == {row['index']}: return {row['bytes']}")
    lines.extend([
        f"    return {spans[-1]['bytes']}",
        "def copy_span(o: mutbuf, p: u64, w: mutbuf, at: u64, size: u64) -> u64:",
        "    index = 0",
        "    while index < size:",
        "        store(o, p + index, byte(w, at + index))",
        "        index = index + 1",
        "    return p + size",
        "def expand_workspace(w: mutbuf) -> u64:",
        "    load_table(w)",
        f"    p = {data_base}",
        "    i = 0",
        f"    while i < {old_proof['compressed_bytes']}:",
        "        tag = byte(w, i)",
        "        i = i + 1",
        "        if tag < 128:",
        "            count = tag + 1",
        "            j = 0",
        "            while j < count:",
        "                store(w, p, byte(w, i))",
        "                p = p + 1",
        "                i = i + 1",
        "                j = j + 1",
        "        else:",
        "            distance = byte(w, i) | (byte(w, i + 1) << 8)",
        "            i = i + 2",
        "            count = (tag & 127) + 3",
        "            j = 0",
        "            while j < count:",
        "                store(w, p, byte(w, p - distance))",
        "                p = p + 1",
        "                j = j + 1",
        "    return p",
    ])
    pseudo = "\n".join(lines) + "\n"
    nodes = ast.parse(pseudo).body
    mapping = {"configured": "f0", "retained_entry": "f55", "read64": "f4", "grow": "f2",
        "result": "f1", "prefix0": "f38", "prefix1": "f39", "load_table": "f40"}
    mapping.update({node.name: f"f{55 + i}" for i, node in enumerate(nodes) if i})
    signatures = {"retained_entry": (["readbuf", "mutbuf", "mutbuf"], "u32"),
        "read64": (["readbuf", "u64"], "u64"), "grow": (["mutbuf", "u64", "u64"], "u32"),
        "result": (["mutbuf", "u64"], "u32"), "prefix0": (["mutbuf", "u64"], "u64"),
        "prefix1": (["mutbuf", "u64"], "u64"), "load_table": (["mutbuf"], "u64")}
    signatures.update({node.name: ([a.annotation.id for a in node.args.args], node.returns.id) for node in nodes})
    added = []
    for node in nodes:
        builder = Builder(node, mapping, signatures, total_scalar_functions(nodes))
        builder.statements(node.body)
        added.append({"name": mapping[node.name], "params": [builder.param(v) for v in builder.params],
            "returns": [builder.returns], "effects": ["read", "write", "trap"], "entry": "b0", "blocks": builder.blocks})
    document = copy.deepcopy(baseline)
    document["module"] = "runtime_mcp_catalog_configured"
    prior_entry = copy.deepcopy(baseline["functions"][0]); prior_entry["name"] = "f55"
    document["functions"] = [added[0], *document["functions"][1:], prior_entry, *added[1:]]
    assert document["functions"][1:55] == baseline["functions"][1:]
    restored_entry = copy.deepcopy(document["functions"][55]); restored_entry["name"] = "f0"
    assert restored_entry == baseline["functions"][0]
    result = render_assembly(document).encode()
    assert assemble_program(result).as_dict() == document
    stats = {"functions": len(document["functions"]),
        "blocks": sum(len(f["blocks"]) for f in document["functions"]),
        "instructions": sum(len(b["ops"]) for f in document["functions"] for b in f["blocks"])}
    assert stats["functions"] <= 128 and stats["blocks"] <= 1536 and stats["instructions"] <= 8192
    rows = []
    for installed in range(4):
        for flags in FLAGS:
            names = [r["name"] for r in spans if (r["index"] != 0 or installed & 1)
                and (r["index"] != 9 or installed & 2) and (not r["runtime_only"] or flags & 1)]
            rows.append({"installed": installed, "flags": flags, "names": names})
    output.mkdir(parents=True, exist_ok=False)
    (output / "runtime_mcp_catalog_configured.hepta").write_bytes(result)
    (output / "catalog_configured.pseudo").write_text(pseudo)
    proof = {"schema": "hepta.runtime.configured-catalog-author.v1", "target_commit": TARGET,
        "author_sha256": sha(Path(__file__).read_bytes()), "baseline_source_sha256": BASE_SHA,
        "baseline_source_commit": "64fcde73d82ba13e92bf06943432bd11f981be08",
        "source_bytes": len(result), "source_sha256": sha(result), **stats,
        "asset_sha256": list(ASSET_SHAS), "native_asset_producer": old_proof["literal_producer"],
        "expected_original_wire_used_as_implementation": False,
        "all_old_helpers_exact": True, "old_entry_relocated_exactly_as": "f55",
        "retained_function_graphs": {f["name"]: graph_pin(f) for f in baseline["functions"]},
        "compressed_source_range": [0, old_proof["compressed_bytes"]],
        "decompressed_destination_base": data_base, "workspace_required": required_workspace,
        "old_decoder_retained_without_graph_changes": True,
        "configured_decoder": "same immutable LZSS constant in explicitly disjoint single-workspace regions",
        "in_place_workspace_disjoint_regions": True,
        "decoder_access_proof": access_proof,
        "spans": spans, "configuration_installed_domains": rows,
        "public102_installed_mask": 1, "full_eleven_installed_mask": 3,
        "public_handler_admission_qualified": False, "public_async_qualified": False,
        "whole_runtime_replaced": False}
    (output / "catalog_configured_composition.json").write_bytes(encoded(proof))
    return proof


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--hepta", type=Path, required=True)
    parser.add_argument("--source", type=Path, default=ROOT)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = generate(args.hepta.resolve(strict=True), args.source.resolve(strict=True), args.output.absolute())
    print(json.dumps({k: result[k] for k in ("source_sha256", "source_bytes", "functions", "blocks", "instructions", "workspace_required")}, sort_keys=True))
