"""Emit the worker-permit HIA owner, retaining the old byte primitives."""
from __future__ import annotations

import argparse
import ast
import copy
import hashlib
import json
from pathlib import Path
import sys

from pool_source import SOURCE


def author(root, hepta):
    sys.path.insert(0, str(hepta))
    from hepta.hia_agent_assembly import _parse_assembly_document, render_assembly
    from hepta.hia_program import verify_program
    from tools.generate_hia_selfhost import Builder, compact_authoring_cfg, total_scalar_functions
    source = SOURCE
    for name, value in {"REQUEST_MAGIC": b"HBPWRQ01", "STATE_MAGIC": b"HBPWST01",
                        "RESULT_MAGIC": b"HBPWRS01", "GROW_MAGIC": b"HGRWS002"}.items():
        source = source.replace(name, str(int.from_bytes(value, "little")))
    nodes = ast.parse(source).body
    names = {node.name: "f" + str(i) for i, node in enumerate(nodes)}
    signatures = {node.name: ([p.annotation.id for p in node.args.args], node.returns.id) for node in nodes}
    functions = []
    total = total_scalar_functions(nodes)
    for node in nodes:
        builder = Builder(node, names, signatures, total)
        builder.statements(node.body)
        functions.append({"name": names[node.name], "params": [builder.param(v) for v in builder.params],
                          "returns": [builder.returns], "effects": ["read", "write", "trap"],
                          "entry": "b0", "blocks": builder.blocks})
    result = compact_authoring_cfg({"schema": "hepta.hia.program.v8", "module": "blocking_worker_pool", "functions": functions})
    baseline = (root / "native/bellman_core.hepta").read_bytes()
    original = _parse_assembly_document(baseline)
    copies = {"f5": names["read64"], "f6": names["get"], "f7": names["put"]}
    for before, after in copies.items():
        fn = copy.deepcopy(next(x for x in original["functions"] if x["name"] == before))
        fn["name"] = after
        assert all(x["op"] != "call" for b in fn["blocks"] for x in b["ops"])
        result["functions"][int(after[1:])] = fn
    verify_program(result)
    raw = render_assembly(result).encode()
    assert _parse_assembly_document(raw) == result
    path = root / "native/blocking_worker_pool.hepta"
    path.write_bytes(raw)
    digest = lambda b: hashlib.sha256(b).hexdigest()
    proof = {"schema": "hepta.runtime.blocking-worker-pool.source-proof.v1", "status": "SOURCE_ONLY_PASS",
             "source_bytes": len(raw), "source_sha256": digest(raw), "source_author_sha256": digest(Path(__file__).read_bytes()),
             "pseudo_source_sha256": digest((Path(__file__).parent / "pool_source.py").read_bytes()),
             "functions": len(result["functions"]), "blocks": sum(len(x["blocks"]) for x in result["functions"]),
             "imported_byte_primitive_source_sha256": digest(baseline), "relocations_only": copies,
             "native_executed": False, "original_executed": False, "real_worker_boundary_qualified": False,
             "public_handler_qualified": False}
    (root / "native/blocking_worker_pool_source_proof.json").write_text(json.dumps(proof,indent=2,sort_keys=True)+"\n")
    return proof


if __name__ == "__main__":
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--source-root",type=Path,required=True)
    p.add_argument("--hepta",type=Path,required=True)
    a=p.parse_args()
    print(json.dumps(author(a.source_root.resolve(),a.hepta.resolve()),sort_keys=True))
