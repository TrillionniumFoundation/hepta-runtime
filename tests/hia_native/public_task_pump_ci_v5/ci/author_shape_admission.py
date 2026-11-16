"""Reproduce one registry class-bound change from complete immutable inputs.

The author never reads a Rust response or a captured expected wire. It changes
one HIA constant and the corresponding pseudo-source constant. The old seven
files remain complete in shape-baseline; --check performs no file writes.
"""
from pathlib import Path
import argparse
import copy
import hashlib
import json
import sys

sys.dont_write_bytecode = True
BASELINES = {
    "source/native/sdk_request_task_registry.hepta": "293f0aff888ca980f36223afc02cdf2fd305f7d60884bc1ed827a4d124829f90",
    "source/native/sdk_request_task_admission_source.py.txt": "ab581ba625a34ddefded47a0ee01bd4c1baf84d8c3f97e783d94ee7da7000152",
    "source/native/sdk_request_task_admission_composition.json": "81c21c40c625247b1f3bbb1742da78d2ba16b4fbcd6fc8e61742f2f639d1193d",
    "source/native/sdk_request_task_composition.json": "bed5e574ccbcbe85140dee5d4f960f6ddd0ef164eb0e613cc0051a4e0f5262b5",
    "source/native/sdk_request_task_abi.md": "f1c365febf8716abc07b1c775626718c992068f81994d1d529ab1d39cdbeccda",
    "source/native/runtime_mcp_sources.json": "57f2aceadc6f4b4f51ad9458425f7089a65e6d4d207937245617826b2abdf7d0",
    "SOURCE_MANIFEST.json": "2890aaa874606334de8d58a79e28cf54a344d56f65d9de16de9e0e6b8d6c22a8",
}
OWNER = "source/native/sdk_request_task_registry.hepta"
PSEUDO = "source/native/sdk_request_task_admission_source.py.txt"
PROOF = "source/native/sdk_request_task_admission_composition.json"
COMPOSITION = "source/native/sdk_request_task_composition.json"
ABI = "source/native/sdk_request_task_abi.md"
BINDING = "source/native/runtime_mcp_sources.json"
MANIFEST = "SOURCE_MANIFEST.json"
MESSAGE_SHA = "4346674242b7f00cd97cee2b04e958a7552923623a79a1355d469c251add2968"
OLD = (b'block b5(v31:readbuf,v32:mutbuf,v33:mutbuf,v34:u64)\n'
       b'  v41:u64 = const() {"value":4}\n'
       b'  v42:bool = compare.gt(v34,v41)\n')
NEW = OLD.replace(b'"value":4', b'"value":5')
OLD_PSEUDO = b'if message_header(s, kind) == False or kind > 4:'
NEW_PSEUDO = OLD_PSEUDO.replace(b'kind > 4', b'kind > 5')
ABI_APPEND = b'''

## Revision 3: complete G1 top-level shape projection

Operation 15 accepts the current G1 HRCJR001 class 5, the complete projection
for a JSON value with no JSON-RPC message shape. It returns forward-only 16,
with generation zero and no ID-map, handler, send, queue or sequence mutation.
The existing frontend owns the anonymous error response; this registry does
not construct or replace any public wire. Class 6 remains an invalid private
enumeration value and returns 0xffffffff before any admission transition.

Only f38/b5's unsigned upper-bound constant changes from 4 to 5. All other
38 functions, the entire f38 control flow, and every other operation remain
exactly preserved. The preceding admission proof and all seven baseline files
are retained in the portable CI package. Public 1394 and async qualification
remain pending for this new source until their actual captures pass.
'''


def require(ok, message):
    if not ok:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def pin(raw):
    return {"bytes": len(raw), "sha256": sha(raw)}


def blob(raw):
    return hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + "\n").encode()


def ast_proof(before, after, hepta):
    sys.path.insert(0, str(Path(hepta).resolve(strict=True)))
    from hepta.hia_agent_assembly import assemble_program
    old = assemble_program(before.decode()).as_dict()
    new = assemble_program(after.decode()).as_dict()
    require(len(old["functions"]) == len(new["functions"]) == 39, "function inventory changed")
    old_functions = {f["name"]: f for f in old["functions"]}
    new_functions = {f["name"]: f for f in new["functions"]}
    require(set(old_functions) == set(new_functions) == {"f" + str(n) for n in range(39)},
            "function names changed")
    for name in old_functions:
        if name != "f38":
            require(old_functions[name] == new_functions[name], "retained function changed: " + name)
    before_block = next(b for b in old_functions["f38"]["blocks"] if b["id"] == "b5")
    expected = {"op": "const", "args": [], "attrs": {"value": 4},
                "out": [{"name": "v41", "type": "u64"}]}
    require(before_block["ops"][0] == expected, "exact old f38 constant differs")
    restored = copy.deepcopy(new)
    function = next(f for f in restored["functions"] if f["name"] == "f38")
    block = next(b for b in function["blocks"] if b["id"] == "b5")
    require(block["ops"][0] == {**expected, "attrs": {"value": 5}}, "exact new f38 constant differs")
    block["ops"][0]["attrs"]["value"] = 4
    require(restored == old, "inverse constant substitution does not restore the complete AST")
    return {"retained_exact_functions": {name: sha(encoded(old_functions[name]))
                for name in sorted(old_functions) if name != "f38"},
            "before_f38": sha(encoded(old_functions["f38"])),
            "after_f38": sha(encoded(new_functions["f38"])),
            "complete_inverse_ast_equal": True, "changed_attribute": "f38/b5/ops/0/attrs/value"}


def derive(package, hepta=None):
    package = Path(package).resolve(strict=True)
    baseline = package / "ci/shape-baseline"
    old = {name: (baseline / name).read_bytes() for name in BASELINES}
    for name, digest in BASELINES.items():
        require(sha(old[name]) == digest, "complete immutable baseline differs: " + name)
    require(sha((package / "graph/source/native/sdk_message_target.hepta").read_bytes()) == MESSAGE_SHA,
            "current G1 producer source differs")
    require(old[OWNER].count(OLD) == 1 and old[OWNER].count(NEW) == 0, "HIA replacement is not unique")
    owner = old[OWNER].replace(OLD, NEW)
    require(owner.replace(NEW, OLD) == old[OWNER] and len(owner) == len(old[OWNER])
            and sum(a != b for a, b in zip(owner, old[OWNER], strict=True)) == 1,
            "registry inverse byte proof differs")
    require(old[PSEUDO].count(OLD_PSEUDO) == 1 and old[PSEUDO].count(NEW_PSEUDO) == 0,
            "pseudo replacement is not unique")
    pseudo = old[PSEUDO].replace(OLD_PSEUDO, NEW_PSEUDO)
    require(pseudo.replace(NEW_PSEUDO, OLD_PSEUDO) == old[PSEUDO], "pseudo inverse proof differs")
    if hepta is None:
        # Full byte identity plus the one-byte inverse remains independently
        # checked by readers. CI also re-derives every AST hash with pinned Hepta.
        ast = json.loads((package / "graph" / PROOF).read_bytes())["ast"]
        require(set(ast["retained_exact_functions"]) == {"f" + str(n) for n in range(38)}
                and ast["complete_inverse_ast_equal"] is True
                and ast["changed_attribute"] == "f38/b5/ops/0/attrs/value", "AST proof shape differs")
    else:
        ast = ast_proof(old[OWNER], owner, hepta)
    proof = {"schema": "hepta.sdk-task-public-admission.shape-delta.v2",
        "baseline": pin(old[OWNER]), "output": pin(owner),
        "baseline_admission_proof": pin(old[PROOF]),
        "previous_author_sha256": json.loads(old[PROOF])["author_sha256"],
        "author_sha256": sha(Path(__file__).read_bytes()), "pseudo_sha256": sha(pseudo),
        "operation": 15, "functions": 39, "changed_functions": {"observe_message": "f38"},
        "added_functions": {}, "ast": ast, "changed_source_bytes": 1,
        "old_maximum_class": 4, "new_maximum_class": 5,
        "required_message_source_sha256": MESSAGE_SHA,
        "top_level_shape_disposition": 16, "top_level_shape_generation": 0,
        "unsupported_class_6_rejected": True, "frontend_owns_complete_anonymous_error_wire": True,
        "ordinary_notification_drops_handler_future": False,
        "expected_wire_read_as_implementation": False, "public_async_qualified": False,
        "full_sdk_qualified": False, "production_activated": False,
        "preserved_failure": {"commit": "017bd2101e4bc8f2a9332a66bde25287f39c3ba4",
            "run_id": 43910995397, "case": "legacy/shape-error-and-recover", "sequence": 694,
            "exit_code": 111, "timed_out": False}}
    result = {OWNER: owner, PSEUDO: pseudo, PROOF: encoded(proof), ABI: old[ABI] + ABI_APPEND}
    composition = json.loads(old[COMPOSITION])
    composition.update(schema="hepta.sdk-request-tasks.composition.v3",
        previous_composition_sha256=sha(old[COMPOSITION]),
        previous_author_sha256=composition["author_sha256"], author_sha256=proof["author_sha256"],
        previous_required_message_source_sha256=composition["required_message_source_sha256"],
        required_message_source_sha256=MESSAGE_SHA,
        source_bytes=len(owner), source_sha256=sha(owner), pseudo_sha256=sha(pseudo),
        public_admission_proof_sha256=sha(result[PROOF]),
        accepts_g1_top_level_shape_class_5=True, unsupported_class_6_rejected=True)
    result[COMPOSITION] = encoded(composition)
    binding = json.loads(old[BINDING])
    for name, raw in result.items():
        relative = name.removeprefix("source/")
        require(relative in binding["sources"], "changed source was not previously bound: " + relative)
        binding["sources"][relative] = pin(raw)
    binding["shape_admission_extension"] = {"source_sha256": sha(owner), "operation": 15,
        "previous_source_binding_sha256": sha(old[BINDING]), "proof_sha256": sha(result[PROOF]),
        "source_change_only": "f38/b5 unsigned class upper bound 4 to 5",
        "public_wire_qualified": False, "async_qualified": False, "full_sdk_qualified": False}
    result[BINDING] = encoded(binding)
    manifest = json.loads(old[MANIFEST])
    require(manifest["file_count"] == len(manifest["files"]) == 222, "original graph file count differs")
    for row in manifest["files"]:
        name = row["path"]
        body = result.get(name, (package / "graph" / name).read_bytes())
        if name not in result:
            require(pin(body) == {key: row[key] for key in ("bytes", "sha256")}
                    and blob(body) == row["git_blob"], "unchanged graph source differs: " + name)
        row.update(**pin(body), git_blob=blob(body))
    manifest["total_bytes"] = sum(row["bytes"] for row in manifest["files"])
    manifest["source_revision"] = "class-5-shape-admission-v5"
    manifest["baseline_manifest_sha256"] = sha(old[MANIFEST])
    result[MANIFEST] = encoded(manifest)
    return result, proof


def verify(package, hepta=None):
    expected, proof = derive(package, hepta)
    for name, body in expected.items():
        require((Path(package) / "graph" / name).read_bytes() == body, "derived graph source differs: " + name)
    return {"status": "ONE_CONSTANT_SHAPE_ADMISSION_SOURCE_PASS",
            "changed_files": {name: {**pin(raw), "git_blob": blob(raw)} for name, raw in expected.items()},
            "proof": proof, "native_executed": False, "rust_executed": False}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--package", type=Path, required=True)
    p.add_argument("--hepta", type=Path, required=True)
    p.add_argument("--write", action="store_true")
    args = p.parse_args()
    if args.write:
        result, _ = derive(args.package, args.hepta)
        for name, body in result.items():
            (args.package / "graph" / name).write_bytes(body)
    print(json.dumps(verify(args.package, args.hepta), sort_keys=True, allow_nan=False))


if __name__ == "__main__":
    main()
