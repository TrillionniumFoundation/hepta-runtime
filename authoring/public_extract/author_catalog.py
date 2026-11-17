"""Author the installed catalog only from retained actual native pipeline output."""
from __future__ import annotations
import json
from source_support import SHA, ENCODE, identity, require, compile_delta

INSTALLED = {"host_list", "effective_config", "execution_shadow_admit", "view", "workdir",
             "directory_create", "file_move", "directory_move", "text_editor", "extract_lines"}
ASSETS_PIN = "e2620f7a4f34e3eb09c8dc6c5464824fd1d31765f35b93b38d73dddd92c28d0b"
READONLY_PIN = "5595baa619b7f9074b7d0fa6eeb5f879a0f293a46af3d1c4d15b9170fcc2fb4f"


def fields(raw):
    text = raw.decode("utf-8")
    decoder = json.JSONDecoder()
    require(text.startswith("{") and text.endswith("}"), "actual typed catalog object differs")
    at, result = 1, {}
    while text[at] != "}":
        start = at
        key, end = decoder.raw_decode(text, at)
        require(type(key) is str and key not in result and text[end] == ":", "actual typed catalog key differs")
        begin = end + 1
        value, end = decoder.raw_decode(text, begin)
        result[key] = start, begin, end, value
        if text[end] == "}":
            require(end == len(text) - 1, "typed catalog trailing data")
            at = end
        else:
            require(text[end] == ",", "typed catalog separator differs")
            at = end + 1
    return text, result


def exact_tools(raw):
    text, top = fields(raw)
    _, begin, end, items = top["tools"]
    require(type(items) is list and text[begin] == "[" and text[end - 1] == "]", "actual tool array differs")
    at, decoder, parts = begin + 1, json.JSONDecoder(), []
    while at < end - 1:
        item, last = decoder.raw_decode(text, at)
        require(type(item) is dict and type(item.get("name")) is str, "actual Tool object differs")
        parts.append((item["name"], text[at:last].encode()))
        if last == end - 1:
            at = last
        else:
            require(text[last] == ",", "actual Tool separator differs")
            at = last + 1
    require(len({name for name, _ in parts}) == len(parts), "actual native Tool name duplicated")
    return text, top, parts


def literal(name, raw):
    rows = ["def " + name + "(o: mutbuf, at: u64) -> u64:",
            "    stride = 8", "    position = at"]
    words = len(raw) // 8 * 8
    for offset in range(0, words, 8):
        rows.append("    put(o, position, " + str(int.from_bytes(raw[offset:offset + 8], "little")) + ")")
        rows.append("    position = position + stride")
    for offset in range(words, len(raw)):
        rows.append("    store(o, position + " + str(offset - words) + ", " + str(raw[offset]) + ")")
    return "\n".join(rows + ["    return 0", ""])


def catalog(api, source, author):
    assets_root = author / "catalog_assets"
    asset_raw = (assets_root / "ASSETS.json").read_bytes()
    readonly_raw = (assets_root / "READONLY.json").read_bytes()
    require(SHA(asset_raw) == ASSETS_PIN and SHA(readonly_raw) == READONLY_PIN, "actual catalog evidence pin differs")
    assets, readonly = json.loads(asset_raw), json.loads(readonly_raw)
    require(assets["status"] == "RETAINED_NATIVE_ASSETS_ADMITTED" and assets["run"] == 43813791993
            and assets["artifact"] == 14201568537 and assets["declared_input_tools"] == 136, "actual catalog provenance differs")
    require(assets["original_expected_wire_used_as_implementation"] is False and assets["native_reexecutions"] == 0,
            "actual native source/result distinction differs")
    require(readonly["status"] == "PASS" and readonly["before"] == readonly["after"] and len(readonly["probes"]) == 12,
            "complete readonly catalog admission differs")
    require(all(row["denied"] is True for row in readonly["probes"]) and readonly["reader_unexpected_denials"] == 0,
            "readonly reader denial controls differ")
    require(readonly["native_executions"] == readonly["rust_executions"] == readonly["reader_writes"] == 0,
            "retained catalog was reexecuted")
    admitted, prefixes, subsets, details = {}, {}, {}, {}
    for label, modern in (("ordinary", 0), ("modern", 1)):
        shape = assets["shapes"][label]
        require(shape["flags"] == 1 and shape["modern"] == modern, "catalog policy context differs")
        typed_name, subset_name = shape["actual_typed"]["path"], shape["selected_tools"]["path"]
        for name in (typed_name, subset_name):
            value = (assets_root / name).read_bytes()
            require(identity(value) == assets["files"][name], "retained actual asset bytes differ: " + name)
            admitted[name] = value
        raw = admitted[typed_name]
        text, top, items = exact_tools(raw)
        require(top["resultType"][3] == "complete" and len(items) == shape["actual_count"], "actual SDK constructor differs")
        chosen = [(name, value) for name, value in items if name in INSTALLED]
        require(len(chosen) == len(INSTALLED) and {name for name, _ in chosen} == INSTALLED, "installed native Tool set differs")
        subset = b"[" + b",".join(value for _, value in chosen) + b"]"
        require(subset == admitted[subset_name], "selected tools differ from actual native byte spans")
        require([name for name, _ in chosen] == shape["installed_in_original_router_order"], "retained router order differs")
        if modern:
            require(top["ttlMs"][3] == 0 and top["cacheScope"][3] == "public"
                    and set(top) == {"resultType", "ttlMs", "cacheScope", "tools"}, "target modern result metadata differs")
            require(list(top)[-1] == "tools", "actual SDK result field order differs")
            prefixes[label] = b',"result":' + text[:top["tools"][0]].encode()
        else:
            require(set(top) == {"resultType", "tools"}, "ordinary typed result fields differ")
            # The already qualified public legacy projection omits constructor metadata.
            prefixes[label] = b',"result":{'
        subsets[label] = subset
        details[label] = {"shape": shape["shape"], "policy_flags": 1, "modern": modern,
                          "typed_source": identity(raw), "selected_tools": identity(subset),
                          "ordered_names": [name for name, _ in chosen], "prefix": identity(prefixes[label])}
    require(subsets["ordinary"] == subsets["modern"], "Tool objects depend on list protocol projection")
    common = b'"tools":' + subsets["ordinary"] + b'}}'
    fragments = {label: prefix + common for label, prefix in prefixes.items()}
    original = source["native/runtime_mcp_catalog_ninth.hepta"]
    comp = json.loads(source["native/runtime_mcp_catalog_ninth_composition.json"])
    require(comp["source_sha256"] == SHA(original) and comp["source_bytes"] == len(original), "catalog template composition differs")
    nodes = ["def target_size(policy: u64) -> u64:\n    return choose(policy == 0, "
             + str(len(fragments["ordinary"])) + ", " + str(len(fragments["modern"])) + ")\n",
             "def target_literal(o: mutbuf, at: u64, policy: u64) -> u64:\n"
             "    if policy == 0:\n        prefix_0(o, at)\n        common_literal(o, at + " + str(len(prefixes["ordinary"])) + ")\n"
             "    elif policy == 1:\n        prefix_1(o, at)\n        common_literal(o, at + " + str(len(prefixes["modern"])) + ")\n"
             "    return 0\n", literal("prefix_1", prefixes["modern"])]
    chunks = [(offset, common[offset:offset + 512]) for offset in range(0, len(common), 512)]
    nodes.append("def common_literal(o: mutbuf, at: u64) -> u64:\n"
                 + "".join("    common_" + str(offset) + "(o, at + " + str(offset) + ")\n" for offset, _ in chunks)
                 + "    return 0\n")
    nodes.extend(literal("common_" + str(offset), value) for offset, value in chunks)
    raw, names, proof = compile_delta(api, original, comp["aliases"], "\n".join(nodes), {}, "runtime_mcp_catalog_installed")
    proof.update(schema="hepta.runtime.public-extract-catalog-source.v1", baseline=identity(original),
                 declared_tool_count=10, actual_native_asset_manifest_sha256=ASSETS_PIN,
                 complete_retained_reader_sha256=READONLY_PIN, actual_native_assets=details,
                 fragments={label: identity(value) for label, value in fragments.items()},
                 ordinary_projection_retains_legacy_prefix=True, modern_cache_scope="public",
                 old_non_list_entry_and_functions_retained_exactly=True,
                 original_expected_wire_used_as_implementation=False, native_execution_qualified=False,
                 public_route_qualified=False, whole_runtime_replaced=False,
                 literal_data_origin="existing successful full 136-input native policy/serde/SDK pipeline")
    outputs = {"native/runtime_mcp_catalog_ninth.hepta": raw,
               "native/runtime_mcp_catalog_ninth_composition.json": ENCODE({"aliases": names, **proof,
                   "source_bytes": len(raw), "source_sha256": SHA(raw)})}
    for name, value in admitted.items():
        outputs["authoring/public_extract/catalog_assets/" + name] = value
    outputs["authoring/public_extract/catalog_assets/ASSETS.json"] = asset_raw
    outputs["authoring/public_extract/catalog_assets/READONLY.json"] = readonly_raw
    return outputs, proof
