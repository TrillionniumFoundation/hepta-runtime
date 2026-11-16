"""Render the actual-effect audit controller as HIA; authoring only."""
from pathlib import Path
import argparse
import ast
import hashlib
import json
import re
import sys

TARGET = "d3d75c30719db966b004756f610007a7c723729e"
TARGET_PATH = "src/mcp/runtime/request_audit.rs"
TARGET_SHA = "b5189f2923153ffa83d0b45a7cdf89873b0f17ebbe6ec1b174c05bab291d73da"
TARGET_BLOB = "984668cfdfcee0a7eb00de14e02086f5ad90bcc0"
COMPILER = "d3e2c90173cf733e42b299d0c4274df4b593a12f"


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def generate(hepta, root):
    sys.dont_write_bytecode = True
    sys.path.insert(0, str(hepta))
    from tools.generate_hia_selfhost import Builder, compact_authoring_cfg, total_scalar_functions
    from hepta.hia_agent_assembly import assemble_program, render_assembly

    original = (root / "reference/target" / TARGET_PATH).read_bytes()
    assert sha(original) == TARGET_SHA
    assert hashlib.sha1(b"blob " + str(len(original)).encode() + b"\0" + original).hexdigest() == TARGET_BLOB
    begin = original.index(b"// Writers and recovery paths retain the original mutex and FIFO reservation.")
    end = original.index(b"\nfn store_lock()", begin)
    exact_owner = original[begin:end]
    (root / "reference/audit_store_lock.rs.txt").write_bytes(exact_owner)
    source = root / "authoring/audit_store_controller.pseudo"
    constants = dict(INVALID=0xffffffff, CAPACITY=0xfffffffe, STATE_ERROR=0xfffffff9,
                     RESOURCE=0xfffffffa, GROW=0xffffffd0, MAXIMUM=(1 << 64) - 1,
                     MAX_ENTRIES=((1 << 64) - 1 - 128) // 16)
    constants.update(U32_MAX=(1 << 32) - 1, I64_MAX=(1 << 63) - 1)
    timeout = ((1 << 63) - 1) * 1000000000 + 999999999
    constants.update(TIMEOUT_LOW=timeout & ((1 << 64) - 1), TIMEOUT_HIGH=timeout >> 64)
    phases = {"PRE_CLOCK":10,"QUEUE_LOCK":11,"QUEUE_CLOCK":12,"POLL_CLOCK":13,"WAIT_CLOCK":14,"WAIT_QUEUE":15,"NOTIFY_ADMIT":16,"UNLOCK_ADMIT":17,"ADMIT_CLOCK":18,"TRY_INNER":19,"INNER_CLOCK":20,"CLEANUP_INNER":21,"CLEANUP_LOCK":22,"CLEANUP_NOTIFY":23,"CLEANUP_UNLOCK":24,"CANCEL_NOTIFY":25,"FAIL_UNLOCK":26,"HELD":30,"FINISH_ID":40,"FINISH_LOCK":41,"FINISH_STATUS":42,"FINISH_CLOCK":43,"FINISH_NOTIFY":44,"FINISH_UNLOCK":45,"FINISH_POISON_UNLOCK":46,"DROP_ID":50,"DROP_INNER":51,"DROP_LOCK":52,"DROP_NOTIFY":53,"DROP_UNLOCK":54,"GROW_QUEUE":60,"DONE":90}
    constants.update(phases)
    for name, value in dict(REQUEST=b"HAUCTL01", ACTOR=b"HAUCOR01", QUEUE=b"HAUQS001",
                            SYNC_REQUEST=b"HASCMD01", SYNC_RESPONSE=b"HASYNR01").items():
        constants[name] = int.from_bytes(value, "little")
    authored = re.sub(r"\b(" + "|".join(constants) + r")\b",
                      lambda m: str(constants[m[0]]), source.read_text())
    nodes = ast.parse(authored).body
    assert all(isinstance(node, ast.FunctionDef) for node in nodes)
    names = {node.name: "f" + str(i) for i, node in enumerate(nodes)}
    signatures = {node.name: ([p.annotation.id for p in node.args.args], node.returns.id)
                  for node in nodes}
    total = total_scalar_functions(nodes)
    functions = []
    for node in nodes:
        builder = Builder(node, names, signatures, total)
        builder.statements(node.body)
        functions.append(dict(name=names[node.name], params=[builder.param(v) for v in builder.params],
                              returns=[builder.returns], effects=["read", "write", "trap"],
                              entry="b0", blocks=builder.blocks))
    program = compact_authoring_cfg(dict(schema="hepta.hia.program.v8",
                                        module="audit_store_controller", functions=functions))
    raw = render_assembly(program).encode()
    actual = assemble_program(raw).as_dict()
    for function in actual["functions"]:
        assert len(function["blocks"]) <= 256, function["name"]
        assert all(len(block["params"]) <= 16 for block in function["blocks"]), function["name"]
    output = root / "native/audit_store_controller.hepta"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(raw)
    proof = dict(schema="hepta.runtime.audit-store-controller.source.v1",
                 target=dict(commit=TARGET, path=TARGET_PATH, git_blob=TARGET_BLOB,
                             bytes=len(original), sha256=TARGET_SHA,
                             exact_owner_bytes=len(exact_owner), exact_owner_sha256=sha(exact_owner)),
                 compiler_commit=COMPILER, source_bytes=len(raw), source_sha256=sha(raw),
                 functions=len(actual["functions"]), blocks=sum(len(f["blocks"]) for f in actual["functions"]),
                 operations=sum(len(b["ops"]) for f in actual["functions"] for b in f["blocks"]),
                 function_names=names, constants=constants,
                 author_sha256=sha(Path(__file__).read_bytes()), dsl_sha256=sha(source.read_bytes()),
                 scope="Private HIA effect controller for actual AuditStoreLock acquire, shared finish and guard release. The controller yields frozen native mutex/condition/clock frames. Shared FIFO bytes are read only while actual queue custody is held. Source checkpoint: no composed semantic or public qualification yet.",
                 time_representation="unsigned 128-bit monotonic epoch-relative nanoseconds, low then high limb",
                 reader_count_cap=None, queue_count_cap=None,
                 runtime_python_required=False, semantic_execution=False,
                 original_lock_qualified=False, concurrent_native_lock_qualified=False,
                 public_audit_qualified=False, whole_runtime_replaced=False)
    output.with_suffix(".composition.json").write_text(json.dumps(proof, sort_keys=True, indent=2) + "\n")
    print(json.dumps({key: proof[key] for key in ("source_bytes", "source_sha256", "functions", "blocks", "operations")}, sort_keys=True))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--hepta", type=Path, required=True)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    generate(args.hepta.resolve(), args.root.resolve())
