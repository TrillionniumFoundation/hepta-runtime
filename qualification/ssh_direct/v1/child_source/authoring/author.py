#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Generate private original-child custody HIA from exact target-derived policy."""
from pathlib import Path
import argparse, hashlib, json, sys
sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from source_support import tools, compile_new, WORD
def author(source, hepta, output):
    output.mkdir(parents=True, exist_ok=False)
    original = (source / "retained/publication_worker.hepta").read_bytes()
    pseudo = (source / "authoring/ssh_original_child.pseudo").read_text()
    raw, names, proof = compile_new(tools(hepta), original,
        {"read64": "f10", "get": "f11", "put": "f12"}, pseudo,
        {"REQUEST_MAGIC": WORD("HSDCCQ01"), "STATE_MAGIC": WORD("HSDCST01"),
         "RESULT_MAGIC": WORD("HSDCCR01")}, "ssh_original_child_custody")
    (output / "ssh_original_child.hepta").write_bytes(raw)
    proof.update(status="SOURCE_AUTHOR_PASS", entry=names["child"], names=names,
        pseudo_sha256=hashlib.sha256(pseudo.encode()).hexdigest(),
        target="d3d75c30719db966b004756f610007a7c723729e",
        runtime_semantics_executed=False, public_ssh_qualified=False)
    (output / "AUTHOR.json").write_text(json.dumps(proof, sort_keys=True, indent=2)+"\n")
    return proof
if __name__ == "__main__":
    p = argparse.ArgumentParser()
    for name in ("source", "hepta", "output"):
        p.add_argument("--"+name, type=Path, required=True)
    a = p.parse_args()
    print(json.dumps(author(a.source.resolve(), a.hepta.resolve(), a.output.absolute()), sort_keys=True))
