# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Narrow publication route over the admitted current frontend; no engine edits."""
from __future__ import annotations
import copy
import json

def generate(api, source, support, pseudo):
    SHA, CANON, ENCODE = support.SHA, support.CANON, support.ENCODE
    require, identity = support.require, support.identity
    _, _, _, assemble, render = api
    original = source["native/runtime_mcp.hepta"]
    comp = json.loads(source["native/runtime_mcp_composition.json"])
    before = assemble(original).as_dict()
    old = {f["name"]: f for f in before["functions"]}
    require(comp["source_sha256"] == SHA(original) and comp["source_bytes"] == len(original),
            "actual frontend source/composition differs")
    require(comp["function_sha256"] == {n: SHA(CANON(f)) for n, f in old.items()},
            "actual frontend complete AST index differs")
    names = dict(comp["functions"])
    require("prepare_extract" in names and "after_catalog_presence" in names,
            "extract and configured catalog predecessor required")
    require("prepare_publication" not in names, "publication already registered")
    base_count = len(old)
    extra = {name: "f" + str(base_count + i) for i, name in enumerate(
        ("retained_publication_tool_kind", "retained_publication_prepare", "prepare_publication"))}
    require(not set(extra) & set(names), "publication alias collision")
    names.update(extra)
    seed = copy.deepcopy(before)
    relocated = {names["tool_kind"]: extra["retained_publication_tool_kind"],
                 names["prepare"]: extra["retained_publication_prepare"]}
    for previous, destination in relocated.items():
        function = copy.deepcopy(old[previous])
        function["name"] = destination
        seed["functions"].append(function)
    prepared = copy.deepcopy(old[names["prepare_extract"]])
    prepared["name"] = extra["prepare_publication"]
    changes = []
    for block in prepared["blocks"]:
        for op in block["ops"]:
            if op["op"] != "const":
                continue
            value = op["attrs"]["value"]
            if value == support.WORD("HEXWGQ02"):
                changes.append([block["id"], op["out"], value, support.WORD("HTPWGQ02")])
                op["attrs"]["value"] = support.WORD("HTPWGQ02")
            elif block["id"] == "b16" and op["out"] == [{"name": "v177", "type": "u64"}]:
                require(value == 15, "actual extract local child differs")
                changes.append([block["id"], op["out"], 15, 16])
                op["attrs"]["value"] = 16
    require(len(changes) == 2, "only private request magic and local child may differ")
    seed["functions"].append(prepared)
    constants = {"INVALID": 0xffffffff, "PUBLICATION_KIND": 13,
                 "CATALOG_QUERY": support.WORD("HRMCD002"),
                 "PUBLICATION_WORD": support.WORD("text_fil")}
    raw, aliases, proof = support.compile_delta(api, render(seed).encode(), names,
        pseudo, constants, before["module"])
    after = {f["name"]: f for f in assemble(raw).as_dict()["functions"]}
    retained = {}
    for name, function in old.items():
        if name not in relocated:
            require(after[name] == function, "old frontend function changed: " + name)
            retained[name] = SHA(CANON(function))
    for previous, destination in relocated.items():
        restored = copy.deepcopy(after[destination])
        restored["name"] = previous
        require(restored == old[previous], "retained route/prepare inverse differs")
    restored = copy.deepcopy(after[extra["prepare_publication"]])
    restored["name"] = names["prepare_extract"]
    for bid, out, prior, current in changes:
        op = next(op for block in restored["blocks"] if block["id"] == bid
                  for op in block["ops"] if op["out"] == out)
        require(op["attrs"]["value"] == current, "publication request inverse anchor differs")
        op["attrs"]["value"] = prior
    require(restored == old[names["prepare_extract"]], "complete prepared request inverse differs")
    require(after[names["entry"]] == old[names["entry"]]
            and after[names["after_tool"]] == old[names["after_tool"]],
            "actual WAIT/resume/after-tool predecessor must remain exact")
    proof.update(schema="hepta.runtime.public-publication.frontend-author.v1",
        baseline=identity(original), previous_functions=base_count,
        exact_relocated_functions=relocated, retained_original_functions=retained,
        prepared_request_changes=changes, prepared_request_inverse_ast_exact=True,
        entry_and_after_tool_exact=True, local_child=16, global_descriptor=64,
        tool_name="text_file_write", tool_kind=13, phase=6, growth_phase=106,
        public_gateway_magic="HTPWGQ02", actual_resolved_experimental_span=True,
        catalog_installed_profile=11, config_phase=18, config_growth_phase=118,
        inherited_pending_lifecycle_unchanged=True, engine_edited=False,
        native_executed=False, rust_executed=False, public_qualified=False,
        full_async_qualified=False, old_stack_removed=False)
    comp.update(source_sha256=SHA(raw), source_bytes=len(raw), functions=aliases,
        function_sha256={name: SHA(CANON(f)) for name, f in after.items()},
        text_publication_extension=proof)
    return {"native/runtime_mcp.hepta": raw,
            "native/runtime_mcp_composition.json": ENCODE(comp),
            "native/runtime_mcp_publication_composition.json": ENCODE(proof)}, proof
