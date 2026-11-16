"""Author scope annotation from checked HIA helpers and the exact target contract.

This is authoring-only Python. The generated owner performs all production
transformation in HIA. Final serialization is a mechanical loan to the single
shared target SDK text-result constructor owner.
"""
from pathlib import Path
import argparse
import ast
import copy
import hashlib
import json
import re
import sys

sys.dont_write_bytecode = True

PINS = {
    "native/serde_json.hepta": "ef9dd3a567acf523257c4245c022b8cefa9b3ddb83075e826f129b1a1f341d18",
    "native/typed_result_json.hepta": "a9dfe2fec3f35b2ef2bcfaec56229007c75301cccb06a96a36691dc361aa0bec",
}
TARGET_SHA = "1db8a3f4235339d8a7aef6e247ddc8f42f4791a26efe4dd298490421b8ca1d9a"
TARGET_COMMIT = "d3d75c30719db966b004756f610007a7c723729e"
TARGET_BLOB = "ea360b7627695d212fd4fbe9f7e71d1dc8858591"
KEYS = (
    "authenticated_chatgpt_caller_isolation",
    "credential_metadata_resume",
    "cross_session_resume",
    "metadata_resume_after_restart",
    "ownership_scope",
    "session_resume_after_restart",
    "session_scope",
    "unfinished_search_after_controller_restart",
    "retention",
    "per_owner",
    "per_session",
    "already_terminal", "automatic_retry", "host", "reason", "recovery",
    "scope_annotation_status", "search", "search_id", "state", "stop_requested",
)
METADATA_ERROR = b"metadata response unavailable"
BUDGET_ERROR = b"scoped metadata wire response exceeds 64 KiB; reduce result page limit"


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def literal(name, value, *, reserved=False):
    if reserved:
        text = f"\ndef {name}(w:mutbuf) -> u64:\n    at=reserve(w,{len(value)})\n    if at==0:\n        return 0\n"
    else:
        text = f"\ndef {name}(w:mutbuf,at:u64) -> u64:\n"
    last = len(value) // 8 * 8
    for i in range(0, last, 8):
        text += f"    put(w,at+{i},{int.from_bytes(value[i:i+8], 'little')})\n"
    for i in range(last, len(value)):
        text += f"    store(w,at+{i},{value[i]})\n"
    return text + f"    return at+{len(value)}\n"


def key_source():
    result = "\ndef key_length(key:u64) -> u64:\n"
    for i, key in enumerate(KEYS, 1):
        result += f"    if key=={i}:\n        return {len(key)}\n"
    result += "    return 0\n\ndef key_byte(key:u64,index:u64) -> u64:\n"
    for i, key in enumerate(KEYS, 1):
        value = key.encode()
        result += f"    if key=={i}:\n"
        for at in range(0, len(value), 8):
            part = value[at:at+8]
            result += (f"        if index>={at} and index<{at+len(part)}:\n"
                       f"            return ({int.from_bytes(part, 'little')}>>((index-{at})*8))&255\n")
        result += "        return 0\n"
    return result + "    return 0\n"


def generate(hepta, runtime, target, source, output):
    sys.path.insert(0, str(hepta))
    from tools.generate_hia_selfhost import Builder, compact_authoring_cfg, total_scalar_functions
    from hepta.hia_agent_assembly import assemble_program, render_assembly

    class NativeBuilder(Builder):
        def expr(self, node):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                if node.func.id == "copy_range":
                    args = [self.expr(v) for v in node.args]
                    if args[0] == args[1]:
                        return self.op("buffer.move_within", [args[0], *(self.cast(v, "usize") for v in args[2:])])
                    borrowed = args[1][1] == "mutbuf"
                    loan = self.op("borrow.read", [args[1]], "readbuf") if borrowed else args[1]
                    result = self.op("buffer.copy_range", [args[0], loan, *(self.cast(v, "usize") for v in args[2:])])
                    if borrowed:
                        self.op("loan.end", [loan])
                    return result
                if node.func.id in self.signatures:
                    args = [self.expr(v) for v in node.args]
                    signature = self.signatures[node.func.id]
                    values, loans = [], []
                    for value, kind in zip(args, signature[0]):
                        if value[1] == "mutbuf" and kind == "readbuf":
                            value = self.op("borrow.read", [value], "readbuf")
                            loans.append(value)
                        values.append(self.cast(value, kind) if value[1] != kind else value)
                    result = self.op("call", values, signature[1], function=self.names[node.func.id])
                    for loan in loans:
                        self.op("loan.end", [loan])
                    return result
            return super().expr(node)

    documents = {}
    for path, expected in PINS.items():
        raw = (runtime / path).read_bytes()
        if sha(raw) != expected:
            raise ValueError(("source pin differs", path, sha(raw)))
        documents[path] = {fn["name"]: fn for fn in assemble_program(raw).as_dict()["functions"]}
    original = (target / "src/mcp/runtime/caller_scope.rs").read_bytes()
    if sha(original) != TARGET_SHA:
        raise ValueError("target caller scope source differs")
    selected = {
        "native/serde_json.hepta": {},
        "native/typed_result_json.hepta": {"utf8": "f70"},
    }
    aliases = {}
    imports = []
    closure_proof = {}
    authored = source.read_text() + key_source()
    for name, raw in {
        "literal_false": b"false", "literal_true": b"true",
        "literal_session": b'"native_mcp_session_only"',
        "literal_credential": b'"authenticated_private_operator_credential"',
        "literal_interrupted": b'"interrupted_without_relaunch"',
        "literal_recovery": b'"reconcile the existing search_id; do not relaunch an uncertain search"',
        "literal_unavailable": b'"unavailable_after_effect_identity_retained"',
    }.items():
        authored += literal(name, raw, reserved=True)
    for name, raw in {"error_metadata": METADATA_ERROR, "error_budget": BUDGET_ERROR, "warning_message": b"search scope annotation unavailable; existing identity retained"}.items():
        authored += literal(name, raw)
    constants = dict(INVALID=0xffffffff, CAPACITY=0xfffffffe, CONTRACT=0xfffffff8,
                     CALL=0xffffffe0, GROW=0xffffffd0, RESOURCE=0xfffffffa,
                     METADATA_ERROR_SIZE=len(METADATA_ERROR), BUDGET_ERROR_SIZE=len(BUDGET_ERROR))
    for name, raw in dict(REQUEST=b"HSCANS02", RESPONSE=b"HSCAR002", STATE=b"HSCAWS02", ACTION=b"HSCAA002",
                          VALUE_REQUEST=b"HJSVS002", VALUE_RESPONSE=b"HJSVR002",
                          JSON_ERROR_REQUEST=b"HSJERQ01", JSON_ERROR_RESULT=b"HSJERR01",
                          CONSTRUCTOR_REQUEST=b"HRTCRQ01", CONSTRUCTOR_RESPONSE=b"HRTCRS01",
                          GROW_RESPONSE=b"HGRWS002").items():
        assert len(raw) == 8
        constants[name] = int.from_bytes(raw, "little")
    authored = re.sub(r"\b(" + "|".join(constants) + r")\b", lambda m: str(constants[m[0]]), authored)
    nodes = ast.parse(authored).body
    names = {node.name: "f" + str(i) for i, node in enumerate(nodes)}
    for path, exposed in selected.items():
        old = documents[path]
        pending = list(exposed.values())
        closure = set()
        while pending:
            current = pending.pop()
            if current in closure:
                continue
            closure.add(current)
            pending.extend(op["attrs"]["function"] for block in old[current]["blocks"]
                           for op in block["ops"] if op["op"] == "call")
        relocation = {name: "f" + str(len(nodes)+len(imports)+i)
                      for i, name in enumerate(sorted(closure, key=lambda n: int(n[1:])))}
        closure_proof[path] = dict(source_sha256=PINS[path], relocation=relocation,
                                   functions={n: sha(canonical(old[n])) for n in relocation})
        for alias, old_name in exposed.items():
            aliases[alias] = relocation[old_name]
        for old_name, new_name in relocation.items():
            function = copy.deepcopy(old[old_name])
            function["name"] = new_name
            for block in function["blocks"]:
                for operation in block["ops"]:
                    if operation["op"] == "call":
                        operation["attrs"]["function"] = relocation[operation["attrs"]["function"]]
            imports.append(function)
    names.update(aliases)
    imported_by_name = {f["name"]: f for f in imports}
    signatures = {node.name: ([p.annotation.id for p in node.args.args], node.returns.id) for node in nodes}
    signatures.update({alias: ([p["type"] for p in imported_by_name[name]["params"]], imported_by_name[name]["returns"][0])
                       for alias, name in aliases.items()})
    total = total_scalar_functions(nodes)
    generated = []
    for node in nodes:
        builder = NativeBuilder(node, names, signatures, total)
        builder.statements(node.body)
        generated.append(dict(name=names[node.name], params=[builder.param(v) for v in builder.params],
                              returns=[builder.returns], effects=["read", "write", "trap"], entry="b0", blocks=builder.blocks))
    compacted = compact_authoring_cfg(dict(schema="hepta.hia.program.v8", module="scope_annotation_span", functions=generated+imports))
    compacted["functions"] = [imported_by_name.get(f["name"], f) for f in compacted["functions"]]
    raw = render_assembly(compacted).encode()
    admitted = assemble_program(raw).as_dict()
    for function in admitted["functions"]:
        if function["name"] in imported_by_name:
            assert function == imported_by_name[function["name"]]
        assert len(function["blocks"]) <= 256, function["name"]
        assert max(len(b["params"]) for b in function["blocks"]) <= 16, function["name"]
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(raw)
    proof = dict(schema="hepta.runtime.scope-annotation-span-source.v1", source_sha256=sha(raw), source_bytes=len(raw),
                 operations=["OwnerScope::annotate", "OwnerScope::annotate_search_effect"],
                 semantic_execution=False, request_has_fixed_8mib_limit=False,
                 author_sha256=sha(Path(__file__).read_bytes()), dsl_sha256=sha(source.read_bytes()),
                 functions=len(admitted["functions"]), blocks=sum(len(f["blocks"]) for f in admitted["functions"]),
                 function_names=names, constants=constants, imports=closure_proof,
                 import_changes=["direct function/call relocation only"],
                 constructor_child=dict(path="native/text_result_constructor.hepta",
                    source_sha256="3a4c9b40136e0c3dbf3b580e475447e94fb79913f93416a0ec906da6d294996d",
                    request="HRTCRQ01", response="HRTCRS01", is_error=0, policy=0,
                    actual_complete_wire_budget_bytes=65536),
                 target=dict(commit=TARGET_COMMIT, path="src/mcp/runtime/caller_scope.rs", blob=TARGET_BLOB,
                             bytes=len(original), sha256=TARGET_SHA),
                 original_annotate_qualified=False, public_handler_qualified=False, whole_runtime_replaced=False)
    output.with_suffix(".composition.json").write_text(json.dumps(proof, sort_keys=True, indent=2)+"\n")
    print(json.dumps({k: proof[k] for k in ("source_sha256", "source_bytes", "functions", "blocks")}, sort_keys=True))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--hepta", type=Path, required=True)
    parser.add_argument("--runtime", type=Path, required=True)
    parser.add_argument("--target", type=Path, required=True)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    generate(*(getattr(args, name).resolve() for name in ("hepta", "runtime", "target", "source", "output")))
