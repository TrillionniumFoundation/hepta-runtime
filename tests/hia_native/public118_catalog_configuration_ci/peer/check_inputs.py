"""Reproduce source-only input manifests. No native, Rust, or tool execution."""
# Copyright 2026 Muvon Un Limited
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
import argparse
import ast
from collections import Counter
import hashlib
import json
from pathlib import Path
import sys

sys.dont_write_bytecode = True
PACKAGE = Path(__file__).resolve().parent
CANONICAL_FIXTURE = "/FIXTURE"
PINS = {
    "target/src/mcp/server.rs": (193936, "0957f7d7d56ad76540a42ba82b33fc29a625bb186cece2a207a764ea8c5beb6f", "8167974425e01728432bffd5f0243087647061d6"),
    "batch/public_cases.py": (8883, "cbf635f8e3fa638e5b36ba674cd83f5063b5c52dab92c0fdde8dd09a9b8bef77", "939ccf2d806f4273db05a606e970c1e64ef7657c"),
    "batch/qualify_public.py": (11498, "29609ea5bb026ec9c907db6881cb82af0c9b2e61dae64083edd78affc793dcf2", "40d39a67e927bdee210558faaddb33014f51f1bb"),
    "batch/qualify_stdio.py": (6283, "9d28943b745265e08466d289f55fce65462a09361d55a34ac84e4d9dc11045f0", "fbd14a1ab5cd67c0c2e687d74d4890c833e1eec8"),
    "batch/public_observations.py": (6574, "3300256db5a42ed8c893c938293124a461b1f219d539099cbc08f08ed201f05d", "4d56dfd66d1222764f4d68272513a42b37fcb290"),
    "body/cases.py": (9314, "f4a29524fd53ba5d676ffd0f82884b8df346285cd3d0831316b903f4817e4298", "c87ccee11bb2985b28318f9e49de9a0f6c47c40e"),
    "body/DOMAIN.json": (6058, "ee87ac39894612434e23a6f0324a3a50fb38e8b5b6a5c5ac990a198af49f3a3a", "054691b23be338dc7a966ddb99fb9304f819ef28"),
}


def need(condition, detail):
    if not condition:
        raise ValueError(detail)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def pin(raw):
    return {"bytes": len(raw), "sha256": sha(raw),
        "git_blob": hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()}


def canonical(value):
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False) + "\n").encode()


def functions(raw):
    text = raw.decode()
    tree = ast.parse(text)
    return {node.name: (node, ast.get_source_segment(text, node)) for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))}


def node_pin(node):
    return sha(ast.dump(node, include_attributes=False).encode())


def load_generator():
    path = PACKAGE / "extract_public_inputs.py"
    raw = path.read_bytes()
    tree = ast.parse(raw)
    imports = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.update(item.name for item in node.names)
        elif isinstance(node, ast.ImportFrom):
            imports.add(node.module)
    need(imports == {"pathlib", "copy", "itertools", "json", "os", "argparse", "sys"}, "input generator imports changed")
    denied = {"open", "exec", "eval", "compile", "__import__", "subprocess", "ctypes", "mmap",
        "mkdir", "write_bytes", "write_text", "unlink", "rename", "replace", "chmod", "system", "popen"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            name = node.func.id if isinstance(node.func, ast.Name) else node.func.attr if isinstance(node.func, ast.Attribute) else None
            need(name not in denied, "generator contains an action rather than an input description: " + str(name))
    namespace = {"__file__": str(path), "__name__": "extract_input_source_check"}
    exec(compile(raw, str(path), "exec"), namespace)
    return raw, namespace


def source_proof(baseline, generator_raw):
    originals = {}
    for name, expected in PINS.items():
        raw = (baseline / name).read_bytes()
        actual = pin(raw)
        need((actual["bytes"], actual["sha256"], actual["git_blob"]) == expected, "baseline pin differs: " + name)
        originals[name] = raw
    old, new = functions(originals["batch/public_cases.py"]), functions(generator_raw)
    inverse = {}
    for name in ("encode", "initialize", "inline_meta", "tool_wire"):
        original_node, original_text = old[name]
        new_node, new_text = new[name]
        reverted = new_text.replace("extract-public-corpus", "batch-public-corpus")
        if name == "tool_wire":
            reverted = reverted.replace('name="extract_lines"', 'name="batch_edit"')
        need(reverted == original_text, "framing helper nonliteral difference: " + name)
        need(node_pin(ast.parse(reverted).body[0]) == node_pin(original_node), "framing inverse AST: " + name)
        inverse[name] = {"source": "batch/public_cases.py", "original_text_sha256": sha(original_text.encode()),
            "original_ast_sha256": node_pin(original_node), "current_text_sha256": sha(new_text.encode()),
            "current_ast_sha256": node_pin(new_node), "literal_inverse_text_and_ast_equal": True}
    original_hash = functions(originals["body/cases.py"])["line_hash"]
    need(original_hash[1] == new["line_hash"][1], "line token helper text differs")
    need(node_pin(original_hash[0]) == node_pin(new["line_hash"][0]), "line token helper AST differs")
    inverse["line_hash"] = {"source": "body/cases.py", "text_sha256": sha(original_hash[1].encode()),
        "ast_sha256": node_pin(original_hash[0]), "text_and_ast_equal": True, "purpose": "input line tokens only"}
    server = originals["target/src/mcp/server.rs"]
    spans = {}
    for name, begin, end in (
        ("ExtractLinesParams", b"pub struct ExtractLinesParams {", b"\n}\n"),
        ("TextEditorParams", b"pub struct TextEditorParams {", b"\n}\n"),
        ("TextEditorCommand", b"pub enum TextEditorCommand {", b"\n}\n"),
        ("extract_lines", b"\tasync fn extract_lines(\n", b"\n\t}\n"),
        ("ensure_session_workdir", b"\tfn ensure_session_workdir(&self, context: &RequestContext<RoleServer>) {", b"\n\t}\n"),
    ):
        start = server.index(begin); stop = server.index(end, start) + len(end)
        spans[name] = {"byte_start": start, "byte_end": stop, **pin(server[start:stop])}
    required = (b"pub from_path: String", b"pub from_start: serde_json::Value", b"pub from_end: Option<serde_json::Value>",
        b"pub append_path: String", b"pub append_line: serde_json::Value")
    struct = spans["ExtractLinesParams"]; raw_struct = server[struct["byte_start"]:struct["byte_end"]]
    need(all(item in raw_struct for item in required), "target parameter contract changed")
    need(b"#[serde(default)]" in raw_struct, "target optional-end default changed")
    return {"schema": "hepta.extract-public-input-provenance.v1", "status": "SOURCE_ONLY_PROOF",
        "repository": "TrillionniumFoundation/hepta-runtime", "target_commit": "d3d75c30719db966b004756f610007a7c723729e",
        "graph_commit": "a521066dfa07db38e6a22bd2f03d1dae3c203cc2",
        "aligned_default111_production_commit": "fa2aed97cf22b720d85bd8d08b720aeadba3c4d6",
        "generator": pin(generator_raw), "baseline_inputs": {name: pin(raw) for name, raw in originals.items()},
        "preserved_functions": inverse, "target_source_spans": spans,
        "newly_authored_functions": sorted(set(new) - set(inverse)),
        "transformation": {"corpus_name_literal": ["batch-public-corpus", "extract-public-corpus"],
            "default_tool_literal": ["batch_edit", "extract_lines"], "other_copied_function_changes": 0,
            "body_domain_expected_fields_copied": False, "body153_domain_replaced": False,
            "result_implementation_copied_or_authored": False},
        "runtime_execution": {"native": 0, "rust": 0, "external_target": 0}}


def validate_inputs(namespace, full):
    encode, serial = namespace["encode"], namespace["serial_inputs"]
    need(encode(serial(full)) == encode(serial(namespace["all_inputs"](CANONICAL_FIXTURE))), "nondeterministic generation")
    domains = full["domains"]
    counts = {"typed-legacy": 189, "typed-modern": 189, "session-legacy": 35, "session-modern": 35,
        "context-legacy": 13, "context-modern": 13, "stdio-legacy": 22, "stdio-modern": 20,
        "protocol-legacy": 48, "protocol-modern": 48, "eof-legacy": 5, "eof-modern": 5}
    need(set(domains) == set(counts), "complete input domain set")
    for name, domain in domains.items():
        rows = domain.get("rows", domain.get("scenarios"))
        need(type(rows) is list and len(rows) == counts[name], "input count: " + name)
        need(len({row["name"] for row in rows}) == len(rows), "case names: " + name)
        for row in rows:
            if "raw_arguments" in row:
                need(type(row["raw_arguments"]) is bytes and type(json.loads(row["raw_arguments"])) is dict,
                    "typed tool input must remain an object")
            if "wire" in row:
                need(row["wire"].endswith(b"\n"), "complete ordinary JSON line")
                json.loads(row["wire"])
            if "trial" in row:
                json.loads(row["trial"]["wire"])
                need(row["response_count"] is None and row["requires_real_stdio"] is True,
                    "uncertain SDK shape was assigned a response count")
        for initial in domain.get("initial", []):
            json.loads(initial["wire"])
    typed = domains["typed-legacy"]["rows"]
    need([row["raw_arguments"] for row in typed] == [row["raw_arguments"] for row in domains["typed-modern"]["rows"]],
        "era changes typed argument bytes")
    need(sum(row["name"].startswith("missing-") for row in typed) == 15, "all nonempty required-field subsets")
    for row in typed:
        if row["name"].startswith("duplicate-"):
            field = row["name"][len("duplicate-"):]
            pairs = json.loads(row["raw_arguments"], object_pairs_hook=lambda value: value)
            need(sum(key == field for key, _ in pairs) == 2, "input duplicate key lost")
        if "raw-unsigned-next" in row["name"]:
            need(b"18446744073709551616" in row["raw_arguments"], "exact unsigned JSON token changed")
    for name in ("session-legacy", "session-modern"):
        rows = domains[name]["rows"]
        need({row["session"] for row in rows} == {0, 1}, "both real sessions")
        need({json.loads(row["raw_arguments"])["command"] for row in rows if row["tool"] == "text_editor"} ==
            {"create", "str_replace", "delete", "undo_edit"}, "four text commands")
        need({seed["session"] for row in rows for seed in (row.get("seed") or [])} == {0, 1}, "two cache seeds")
    need(set(full) == {"schema", "target", "graph", "fixture", "budgets", "domains"}, "input root fields")
    def walk(value):
        if isinstance(value, dict):
            for key, item in value.items():
                need(not key.startswith("expected") and key not in ("result", "error", "output", "response_hex", "isError"),
                    "an output expectation was authored")
                if key == "path_hex":
                    path = Path(bytes.fromhex(item).decode())
                    need(path.is_relative_to(Path(CANONICAL_FIXTURE)) and path != Path(CANONICAL_FIXTURE),
                        "fixture action escapes owned child paths")
                walk(item)
        elif isinstance(value, (list, tuple)):
            for item in value:
                walk(item)
    walk(full)
    return counts


def reproduce(baseline):
    generator_raw, namespace = load_generator()
    provenance = source_proof(baseline, generator_raw)
    full = namespace["all_inputs"](CANONICAL_FIXTURE)
    counts = validate_inputs(namespace, full)
    serial, encode = namespace["serial_inputs"], namespace["encode"]
    domains = {}
    for name, value in full["domains"].items():
        rows = value.get("rows", value.get("scenarios"))
        domains[name] = {"units": len(rows), "unit_kind": "scenario" if "scenarios" in value else "input-row",
            "input_object": pin(encode(serial(value))),
            "cases": [{"name": row["name"], "input": pin(encode(serial(row)))} for row in rows]}
        if name.startswith("protocol-"):
            domains[name]["categories"] = dict(sorted(Counter(row["category"] for row in rows).items()))
    domain = {"schema": "hepta.extract-public-domain.v1", "status": "INPUT_ONLY_NOT_EXECUTED",
        "canonical_fixture_root": CANONICAL_FIXTURE, "generator": pin(generator_raw),
        "full_input_object": pin(encode(serial(full))), "target_commit": namespace["TARGET"], "graph_commit": namespace["GRAPH"],
        "domains": domains, "unit_total": sum(counts.values()), "unit_total_is_not_a_response_or_dispatch_count": True,
        "budgets": full["budgets"], "reference_semantics": "actual current SDK and unchanged original handlers only",
        "separate_original_body_domain": {"pairs": 153, "operations": 175, "replaced_by_this_package": False},
        "qualification": {"native": False, "original_rust": False, "public_extract": False, "full_sdk": False,
            "async_cancellation": False, "concurrent_lock_wait": False, "remote": False,
            "all_136_tools": False, "old_stack_removal": False},
        "authoring": {"expected_wire": False, "expected_tool_result": False, "fixture_actions_executed": False,
            "request_shape_collection_booleans_are_not_results": True}}
    report = {"schema": "hepta.extract-input-source-check.v1", "status": "INPUT_SOURCE_CHECK_PASS",
        "generator": pin(generator_raw), "domains": counts, "complete_inputs_deterministic": True,
        "exact_raw_number_tokens": True, "original_source_pins": True, "framing_inverse_text_ast": True,
        "body_hash_text_ast": True, "two_session_inputs": True, "four_text_commands": True, "source_only": True,
        "fixture_actions_executed": 0, "native_execution": 0, "rust_execution": 0,
        "domain_file": pin(canonical(domain)), "provenance_file": pin(canonical(provenance))}
    need(provenance == source_proof(baseline, generator_raw), "baseline bytes changed during source check")
    return {"DOMAIN.json": canonical(domain), "PROVENANCE.json": canonical(provenance), "SOURCE_CHECK.json": canonical(report)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline-root", type=Path, required=True)
    parser.add_argument("--write", action="store_true", help="create manifest files only; default verifies existing bytes")
    args = parser.parse_args()
    values = reproduce(args.baseline_root)
    for name, raw in values.items():
        path = PACKAGE / name
        if args.write:
            with path.open("xb") as output:
                output.write(raw)
        else:
            need(path.read_bytes() == raw, "recorded input source proof differs: " + name)
    print(json.dumps({"status": "INPUT_SOURCE_CHECK_PASS", "source_only": True, "native_execution": 0, "rust_execution": 0,
        "files": {name: pin(raw) for name, raw in values.items()}}, sort_keys=True))


if __name__ == "__main__":
    main()
