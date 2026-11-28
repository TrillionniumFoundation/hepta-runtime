#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Compose fixed publisher descriptors; execute no HIA, Rust, or target request."""
from pathlib import Path
import argparse
import hashlib
import json
import shutil
import sys
sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
import layout

SHA = lambda b: hashlib.sha256(b).hexdigest()
ENCODE = lambda x: (json.dumps(x, sort_keys=True, indent=2) + "\n").encode()
def require(x, message):
    if not x: raise ValueError(message)
def pin(raw):
    return dict(bytes=len(raw), sha256=SHA(raw))
def normal(root, name):
    path = Path(name)
    require(not path.is_absolute() and ".." not in path.parts and path.as_posix() == name, "source path differs")
    here = root
    for part in path.parts:
        here = here / part
        require(not here.is_symlink(), "source link")
    require(here.is_file(), "missing ordinary source: " + name)
    return here

def compose(base, package, output):
    require(not output.exists(), "fresh graph composition output required")
    expected_raw = (package / "baseline/runtime_mcp_sources.json").read_bytes()
    require((base / "native/runtime_mcp_sources.json").read_bytes() == expected_raw, "exact installed111 source binding differs")
    before = json.loads(expected_raw)
    require(before["schema"] == "hepta.runtime.public-source-closure.v2" and len(before["sources"]) == 389,
        "installed source inventory differs")
    source = output / "source"
    source.mkdir(parents=True)
    for name, identity in before["sources"].items():
        raw = normal(base, name).read_bytes()
        require(pin(raw) == identity, "base complete source differs: " + name)
        path = source / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
    patches = json.loads((package / "recipe/mechanical_patches.json").read_bytes())
    changed = {}
    for row in patches:
        path = source / row["path"]
        old = path.read_text()
        require(old.count(row["before"]) == 1, "exact mechanical anchor missing: " + row["path"])
        new = old.replace(row["before"], row["after"], 1)
        require(new.count(row["after"]) == 1 and new.replace(row["after"], row["before"], 1) == old,
            "mechanical inverse differs")
        path.write_text(new)
        changed.setdefault(row["path"], []).append(row)
    engine = source / "scripts/runtime_mcp_extra_engine.S"
    before_layout = engine.read_text()
    upgraded = layout.upgrade(before_layout)
    require(layout.undo(upgraded) == before_layout, "qualified layout inverse differs")
    engine.write_text(layout.rebind(upgraded, 68))
    require(layout.layout(68)["descriptor_base"] == 8192 and layout.layout(68)["engine_bytes"] == 16384,
        "installed fixed descriptor/engine displacement changed")
    for name, rows in changed.items():
        raw = (source / name).read_text()
        if name == "scripts/runtime_mcp_extra_engine.S":
            raw = layout.undo(layout.rebind(raw, 59))
        for row in reversed(rows):
            require(raw.count(row["after"]) == 1, "inverse mechanical anchor repeated")
            raw = raw.replace(row["after"], row["before"], 1)
        require(raw.encode() == normal(base, name).read_bytes(), "whole-file mechanical inverse differs: " + name)
    added = []
    for path in sorted((package / "overlay").rglob("*")):
        require(not path.is_symlink(), "overlay link")
        if not path.is_file(): continue
        name = path.relative_to(package / "overlay").as_posix()
        require(name not in before["sources"], "new owner collided with installed source: " + name)
        target = source / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(path.read_bytes())
        added.append(name)
    note = dict(schema="hepta.runtime.text-publication.graph-composition.v1",
        base_commit="99d107c062a6eb3f226dd82b05283aeecbd3c495",
        base_binding=pin(expected_raw), unchanged_sources=len(before["sources"])-len(changed),
        changed_sources=sorted(changed), added_sources=added,
        exact_inverse_mechanical_patches=True, layout_source_commit="7c78115f0d61026d50bab6e2e7043dfb997f1454",
        layout=layout.layout(68), publisher_slots=[64,65,66,67], extract_reserved_slots=[59,60,61,62,63],
        caller_children=[29,9,67,11,7,30], gateway_children=[65,27,5,6,11,9,7,66,3],
        callable_context="descriptor67+8", callable_context_capacity=4096,
        callable_borrow_until_complete_parent_delivery=True, body_syscalls_and_policy_unchanged=True,
        session_cache_forget_owned_by_hia_caller=True, public_route=False, full_async=False,
        production_installed=False, old_stack_removed=False)
    (source / "native/text_publication_graph_composition.json").write_bytes(ENCODE(note))
    identities = {path.relative_to(source).as_posix(): pin(path.read_bytes())
        for path in sorted(source.rglob("*")) if path.is_file()}
    binding = dict(before)
    binding["sources"] = identities
    (source / "native/runtime_mcp_sources.json").write_bytes(ENCODE(binding))
    report = dict(status="COMPLETE_SOURCE_COMPOSITION_PASS", source=str(source), composition=note,
        binding=pin((source / "native/runtime_mcp_sources.json").read_bytes()), source_files=len(identities)+1,
        hia_executed=False, rust_executed=False)
    (output / "COMPOSITION.json").write_bytes(ENCODE(report))
    print(json.dumps(report, sort_keys=True))
    return source

def main():
    p = argparse.ArgumentParser()
    for name in ("base", "package", "output"):
        p.add_argument("--" + name, type=Path, required=True)
    a = p.parse_args()
    compose(a.base.resolve(strict=True), a.package.resolve(strict=True), a.output.absolute())
if __name__ == "__main__": main()
