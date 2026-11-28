#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Author the HIA jobs audit owner; all runtime policy is in the HIA result."""
import argparse
import ast
import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def literal(name, raw):
    lines = [f"def {name}(o:mutbuf,at:u64) -> u64:"]
    lines += [f"    store(o,at+{i},{byte})" for i, byte in enumerate(raw)]
    lines += [f"    return at+{len(raw)}"]
    return "\n".join(lines) + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--hepta", type=Path, required=True)
    args = parser.parse_args()
    support_path = ROOT / "authoring/public_publication_v1/source_support.py"
    support = load("jobs_audit_append_support", support_path)
    event_author = load("jobs_audit_event_author", HERE / "author.py")
    event_raw = (HERE / "event.pseudo").read_text()
    nodes = ast.parse(event_raw).body
    helpers = [node for node in nodes if node.name not in {"event", "admitted", "event_extent"}]
    append_raw = (HERE / "append.pseudo").read_text()
    pieces = [append_raw,
              "\n\n".join(ast.get_source_segment(event_raw, node) for node in helpers)]
    for name, raw in event_author.LITERALS.items():
        pieces.append(literal(name, raw))
    pieces.append(literal("literal_file", b"/audit/events.jsonl"))
    pieces.append(literal("literal_audit", b"/audit"))
    messages = {
        1: b"audit sink is not a regular file: ",
        2: b"audit sink must not be hard-linked: ",
        3: b"audit sink must be owner-private: ",
        4: b"audit target has no parent",
        5: b"audit publication parent is not a directory",
        6: b"audit file binding changed",
        7: b"audit directory publication binding changed",
        8: b"failed to write whole buffer",
    }
    lines = ["def audit_error_literal(o:mutbuf,at:u64,kind:u64) -> u64:"]
    for kind, raw in messages.items():
        lines += [f"    if kind=={kind}:", f"        return error_literal_{kind}(o,at)"]
        pieces.append(literal(f"error_literal_{kind}", raw))
    lines += ["    return at"]
    pieces.append("\n".join(lines) + "\n")
    constants = {
        "OWNER": support.WORD("HJAUW001"),
        "APPEND_REQUEST": support.WORD("HBAUQ001"),
        "MESSAGE": support.WORD("HRCFGM01"),
        "ACTION_MAGIC": support.WORD("HJAUA001"),
        "CANON_REQUEST": support.WORD("HRCNLQ01"),
        "CANON_RESPONSE": support.WORD("HRCNLR01"),
        "CODEC_REQUEST": support.WORD("HRCODEC1"),
        "ERRNO_REQUEST": support.WORD("HMDERQ01"),
        "ERRNO_RESPONSE": support.WORD("HMDERR01"),
        "INVALID": 0xffffffff, "SHORT": 0xfffffffe, "FAULT": 0xfffffff9,
        "CALL": 0xfffffff0, "GROW_WORK": 0xffffffef,
        "GROW_OUTPUT": 0xffffffee, "AGAIN": 0xffffffed,
        "ACTION": 256, "STAT": 384, "TIME": 544,
        "STAMP": 1024, "TEMP_STAMP": 1440, "TOKEN": 1536,
        "SHA_STATE": 1600, "TEMP_WATCH": 1728,
        "FINGERPRINT_FD": 1800, "NAMESPACE_ERROR": 1808,
        "SHA_OUTPUT": 1840, "WATCHES": 2048,
        "FIXED_BYTES": sum(map(len, event_author.LITERALS.values())) + 3,
    }
    api = support.tools(args.hepta)
    source = (ROOT / "native/directory_errno.hepta").read_bytes()
    result, names, proof = support.compile_new(
        api, source, {}, "\n\n".join(pieces), constants,
        "runtime_jobs_audit_append")
    proof.update(schema="hepta.runtime.jobs-audit-append.author.v1", names=names,
                 filesystem_qualified=False, warm_namespace_qualified=False,
                 public_route_qualified=False, old_stack_removal_qualified=False,
                 namespace_original="src/mcp/runtime/namespace_version.rs",
                 append_original="src/mcp/runtime/jobs.rs",
                 author_sources={str(p.relative_to(ROOT)): support.identity(p.read_bytes())
                                 for p in [Path(__file__), HERE / "append.pseudo",
                                           HERE / "namespace.pseudo", HERE / "event.pseudo",
                                           HERE / "author.py", HERE / "APPEND_ABI.md", support_path]})
    (ROOT / "native/jobs_audit_append.hepta").write_bytes(result)
    (ROOT / "native/jobs_audit_append_composition.json").write_bytes(support.ENCODE(proof))
    print(json.dumps({"module": "append", **{key: proof[key] for key in ("source", "functions", "blocks", "operations")}}, sort_keys=True))
    shared = {"cold_binding", "fail", "fail_or_cold", "effect", "io_error", "io_result"}
    shared_nodes = [node for node in ast.parse(append_raw).body if node.name in shared]
    namespace_pieces = [(HERE / "namespace.pseudo").read_text()]
    namespace_pieces += [ast.get_source_segment(append_raw, node) for node in shared_nodes]
    namespace_pieces += [ast.get_source_segment(event_raw, node) for node in helpers if node.name in {"read64", "put"}]
    namespace_raw, names, namespace_proof = support.compile_new(
        api, source, {}, "\n\n".join(namespace_pieces), constants,
        "runtime_jobs_audit_namespace")
    namespace_proof.update(schema="hepta.runtime.jobs-audit-namespace.author.v1", names=names,
                           author_sources=proof["author_sources"],
                           filesystem_qualified=False, warm_namespace_qualified=False,
                           public_route_qualified=False, old_stack_removal_qualified=False)
    (ROOT / "native/jobs_audit_namespace.hepta").write_bytes(namespace_raw)
    (ROOT / "native/jobs_audit_namespace_composition.json").write_bytes(support.ENCODE(namespace_proof))
    print(json.dumps({"module": "namespace", **{key: namespace_proof[key] for key in ("source", "functions", "blocks", "operations")}}, sort_keys=True))


if __name__ == "__main__":
    main()
