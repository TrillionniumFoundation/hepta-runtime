#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Author the jobs audit event codec; no runtime I/O or timestamp is simulated."""
import argparse
import importlib.util
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
LITERALS = {
    "literal_action": b'{"action":"native_binary_write","at_unix_ms":',
    "literal_host": b',"host":"',
    "literal_outcome": b'","outcome":{"op":"write"},"subject":"',
}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--hepta", type=Path, required=True)
    args = parser.parse_args()
    path = ROOT / "authoring/public_publication_v1/source_support.py"
    spec = importlib.util.spec_from_file_location("jobs_audit_source_support", path)
    support = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(support)
    api = support.tools(args.hepta)
    pseudo = (HERE / "event.pseudo").read_text()
    for name, literal in LITERALS.items():
        lines = [f"def {name}(o:mutbuf,at:u64) -> u64:"]
        lines += [f"    store(o,at+{i},{byte})" for i, byte in enumerate(literal)]
        lines.append(f"    return at+{len(literal)}")
        pseudo += "\n\n" + "\n".join(lines) + "\n"
    constants = {
        "REQUEST": support.WORD("HJAERQ01"), "MESSAGE": support.WORD("HRCFGM01"),
        "INVALID": 0xffffffff, "SHORT": 0xfffffffe,
        "FIXED_BYTES": sum(map(len, LITERALS.values())) + 3,
    }
    source = (ROOT / "native/response_hints.hepta").read_bytes()
    result, names, proof = support.compile_new(
        api, source, {}, pseudo, constants, "runtime_jobs_audit_event")
    proof.update(schema="hepta.runtime.jobs-audit-event.author.v1", names=names,
                 timestamp_source="supplied only by the enclosing audit owner's real clock effect",
                 public_route_qualified=False, filesystem_qualified=False,
                 author_sources={str(p.relative_to(ROOT)): support.identity(p.read_bytes())
                                 for p in [Path(__file__), HERE / "event.pseudo", path]})
    (ROOT / "native/jobs_audit_event.hepta").write_bytes(result)
    (ROOT / "native/jobs_audit_event_composition.json").write_bytes(support.ENCODE(proof))
    print(json.dumps({"source": proof["source"], "functions": proof["functions"],
                      "operations": proof["operations"]}, sort_keys=True))


if __name__ == "__main__":
    main()
