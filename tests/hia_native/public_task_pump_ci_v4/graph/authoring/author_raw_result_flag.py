"""Preserve a complete kind-3 result wire when its typed error flag is one.

The fixed HIA frontend has already serialized the complete JSON-RPC result.
Both zero and one are valid HRCMFR02 isError metadata.  The raw publisher must
copy the existing span without interpreting that flag a second time.
"""
import argparse
import hashlib
import json
from pathlib import Path
import shutil


def sha(data):
    return hashlib.sha256(data).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    binding_path = Path("native/runtime_mcp_sources.json")
    old_binding = (args.source / binding_path).read_bytes()
    assert sha(old_binding) == "91aa73a08d479e42eec83852bb341b5b59faa7b62c3a3ddbd634f1243a432fe3"
    relative = Path("scripts/runtime_mcp_task_send.S")
    before = (args.source / relative).read_text()
    old = """pump_send_raw_arguments:
    cmp qword ptr [r13+32],0
    jne public_span_fail
    cmp qword ptr [r13+40],0
    jne public_span_fail
"""
    new = """pump_send_raw_arguments:
    cmp qword ptr [r13+32],0
    jne public_span_fail
    /* Kind3 already contains the complete typed result wire, including its
     * error flag. Admit either boolean; copy the existing wire unchanged. */
    cmp qword ptr [r13+40],1
    ja public_span_fail
"""
    assert before.count(old) == 1
    after = before.replace(old, new, 1)
    assert after.replace(new, old, 1) == before
    shutil.copytree(args.source, args.output)
    (args.output / relative).write_text(after)
    proof = {
        "schema": "hepta.runtime.task-pump.complete-result-error-flag.v1",
        "before_source_binding_sha256": sha(old_binding),
        "path": relative.as_posix(),
        "before_sha256": sha(before.encode()),
        "after_sha256": sha(after.encode()),
        "exact_reversible_change": {"before": old, "after": new},
        "accepted_kind": 3,
        "accepted_is_error_values": [0, 1],
        "body_length_must_remain_zero": True,
        "complete_wire_is_copied_without_new_serialization": True,
        "frontend_boolean_and_extent_checks_unchanged": True,
        "kind_0_1_2_4_and_actual_send_ack_lifetimes_unchanged": True,
        "all_hia_and_external_port_source_bytes_unchanged": True,
        "author_sha256": sha(Path(__file__).read_bytes()),
        "new_source_executed": False,
        "full_public_qualified": False,
        "full_async_qualified": False,
        "fresh_ci_qualified": False,
    }
    proof_path = args.output / "native/runtime_mcp_raw_result_flag.json"
    proof_path.write_text(json.dumps(proof, sort_keys=True, indent=2) + "\n")
    binding = json.loads(old_binding)
    binding["sources"] = {
        p.relative_to(args.output).as_posix(): {"bytes": p.stat().st_size, "sha256": sha(p.read_bytes())}
        for p in sorted(args.output.rglob("*")) if p.is_file() and p != args.output / binding_path
    }
    (args.output / binding_path).write_text(json.dumps(binding, sort_keys=True, indent=2) + "\n")
    changed = []
    for p in sorted(args.output.rglob("*")):
        if p.is_file():
            rel = p.relative_to(args.output)
            old_path = args.source / rel
            if not old_path.is_file() or old_path.read_bytes() != p.read_bytes():
                changed.append(rel.as_posix())
    assert changed == ["native/runtime_mcp_raw_result_flag.json", "native/runtime_mcp_sources.json", relative.as_posix()]
    print(json.dumps({"source": str(args.output), "binding_sha256": sha((args.output / binding_path).read_bytes()),
                      "changed": changed, "direct_hia_sources_changed": 0}, sort_keys=True))


if __name__ == "__main__":
    main()
