#!/usr/bin/env python3
"""Compose a new Batch callable from explicit transport and exact I/O shims."""
from pathlib import Path
import argparse
import hashlib
import json
import re

BASE = "5120f566fe8e4ace6c441d2dd110188663cb29bcc28af26a759b44a6f86b15b6"


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    original = (root / "retained/local_text_body_callable.S").read_bytes()
    assert sha(original) == BASE
    text = original.decode()
    pieces, proof = [], []

    def take(first, last=None):
        assert text.count(first) == 1, first
        start = text.index(first)
        end = len(text) if last is None else text.index(last, start + len(first))
        return text[start:end]

    def replace(part, before, after, count=1):
        assert part.count(before) == count, (before, part.count(before), count)
        return part.replace(before, after)

    def add(name, before, after, adaptations):
        pieces.append(after)
        proof.append({"name": name, "original_bytes": len(before.encode()),
            "original_sha256": sha(before.encode()), "composed_bytes": len(after.encode()),
            "composed_sha256": sha(after.encode()), "adaptations": adaptations})

    first = text[:text.index("/* The exposed suspension")]
    entry = first
    for name, old, new in (("PUBLIC_CTX",1024,1280),("RETURN_STACK",1032,1288),
        ("META_POINTER",1040,1296),("RESULT_PAIR",1048,1304),
        ("WAIT_FLAG",1064,1320),("ABORTING",1072,1328),
        ("CLEAN_FRAME",1088,1344),("CLEAN_OUTPUT",1152,1408)):
        entry = replace(entry, f".equ ltb_{name},{old}\n", f".equ ltb_{name},{new}\n")
    entry = replace(entry, ".equ ltb_MAIN_MAGIC,0x31304d4242544c48", ".equ ltb_MAIN_MAGIC,0x3130434d42424c48")
    entry = replace(entry, ".equ ltb_CONTEXT_MAGIC,0x3130494342544c48", ".equ ltb_CONTEXT_MAGIC,0x3130494342424c48")
    entry = replace(entry, "cmp ecx,12", "cmp ecx,14", 2)
    entry = replace(entry, "mov ebx,3", "mov ebx,7")
    entry = replace(entry, "cmp ebx,3", "cmp ebx,7", 2)
    entry = replace(entry, "mov ebx,6", "mov ebx,3")
    entry = replace(entry, "268435456", "1207959552")
    entry = replace(entry, "134217728", "1073741824", 2)
    entry = replace(entry, "cmp qword ptr [rsp+16],1073741824", "cmp qword ptr [rsp+16],536870912")
    old_generation = "    cmp rax,80\n    jb ltb_body_invoke\n    mov rax,[r15+ltb_INPUT]\n    mov rax,[rax+56]\n    mov [r15+ltb_GENERATION],rax\n"
    entry = replace(entry, old_generation, "")
    add("entry", first, entry, ["14 exact fixed entries", "lock7/history3 borrowed slots", "nonoverlapping control fields1280..1471", "existing Batch buffer declarations", "new capability magic", "Batch input has no Text generation field"])

    control = (root / "authoring/batch_callable_control.S").read_text()
    pieces.append(control)
    proof.append({"name": "new_batch_control", "composed_bytes": len(control.encode()),
        "composed_sha256": sha(control.encode()), "adaptations": ["new explicit Batch effect/footer transport; no inherited semantic claim"]})
    completed = take("ltb_callable_complete:\n", "ltb_callable_shared_growth:\n")
    add("completion_publication", completed, completed, [])
    shared = take("ltb_callable_shared_growth:\n", "ltb_callable_cache:\n")
    adapted = replace(shared, "268435456", "1207959552")
    adapted = replace(adapted, "134217728", "1073741824")
    add("borrowed_shared_growth", shared, adapted, ["existing Batch-plan limits; callback target is actual fixed slot3 or7"])

    abort = take("/* Failure drains owned capabilities", "ltb_callable_drop_lease:\n")
    adapted = replace(abort, "ltb_SLOTS+64+", "ltb_SLOTS+384+", 4)
    add("failure_drain", abort, adapted, ["local-read descriptor moves1->6"])
    drop = take("ltb_callable_drop_lease:\n", "ltb_callable_fault_early:\n")
    adapted = replace(drop, "[rax+168]", "[rax+40]")
    add("failure_lock_drop", drop, adapted, ["Batch owns its lease token at workspace40; drop still invokes actual shared HIA state"])
    fault = take("ltb_callable_fault_early:\n", "/* Release never frees")
    add("early_failure", fault, fault, [])
    release = take("/* Release never frees", "ltb_body_invoke:\n")
    adapted = replace(release, "mov r14d,21", "mov r14d,26")
    mark = "ltb_callable_owned_regions:\n"
    assert adapted.count(mark) == 1
    table = ["ltb_INPUT", "ltb_CALLBACK"]
    for index in range(14):
        if index in (3, 7):
            continue
        table.extend([f"ltb_SLOTS+{index * 64}+8", f"ltb_SLOTS+{index * 64}+24"])
    assert len(table) == 26
    adapted = adapted[:adapted.index(mark)] + mark + "    .quad " + ",".join(table) + "\n\n"
    add("release", release, adapted, ["26 exact owned regions; borrowed lock/history excluded"])

    read = take("ltb_child_read:\n", "ltb_child_key:\n")
    adapted = replace(read, "ltb_SLOTS+64]", "ltb_SLOTS+384]")
    adapted = replace(adapted, "ltb_child_read:\n", "ltb_child_read:\n    push rbp\n")
    adapted = replace(adapted, "    jmp ltb_child_completed", "    pop rbp\n    ret")
    add("read_invocation", read, adapted, ["fixed read slot6", "ordinary internal call return and aligned policy calls"])
    key = take("ltb_child_key:\n", "ltb_child_atomic:\n")
    adapted = replace(key, "ltb_child_key:\n", "ltb_child_key:\n    push rbp\n")
    adapted = replace(adapted, "    jmp ltb_child_completed", "    pop rbp\n    ret")
    add("key_invocation", key, adapted, ["ordinary internal call return and aligned policy calls"])
    atomic = take("ltb_child_atomic:\n", "ltb_atomic_run:\n")
    adapted = replace(atomic, "ltb_SLOTS+448]", "ltb_SLOTS+256]")
    adapted = replace(adapted, "ltb_child_atomic:\n", "ltb_child_atomic:\n    push rbp\n")
    adapted = replace(adapted, "    jmp ltb_child_completed", "    pop rbp\n    ret")
    add("atomic_invocation", atomic, adapted, ["fixed atomic slot4", "ordinary internal call return and aligned policy calls"])
    atomic_policy = take("ltb_atomic_run:\n", "/* The existing file owner")
    add("atomic_syscall_policy_driver", atomic_policy, atomic_policy, [])
    shims = take("/* These complete observations belong only")
    add("allocation_atomic_read_key_syscall_shims", shims, shims, [])
    output = "".join(pieces).replace("local_text_body_", "local_batch_body_").replace("ltb_", "lbb_")
    assert not re.search(r"\bcmp rax,0x[fF]", output)
    assert "ltb_" not in output and "local_text_body_" not in output
    assert output.count("local_batch_body_run:") == 1
    assert output.count("local_batch_body_release:") == 1
    args.output.mkdir(parents=True, exist_ok=False)
    raw = output.encode()
    (args.output / "local_batch_body_callable.S").write_bytes(raw)
    report = {"schema": "hepta.runtime.rebuilt-batch-callable-author.v1", "source_bytes": len(raw),
        "source_sha256": sha(raw), "retained_source_sha256": BASE,
        "author_sha256": sha(Path(__file__).read_bytes()), "sections": proof,
        "uniform_namespace_relocation": "ltb_/local_text_body_ -> lbb_/local_batch_body_",
        "new_version_not_lost_private91": True, "assembly_executed": False,
        "native_executed": False, "fresh_current_original_compared": False,
        "public_batch_qualified": False, "full_async_cancellation_qualified": False,
        "remote_qualified": False, "whole_runtime_replaced": False}
    (args.output / "callable-author-proof.json").write_text(json.dumps(report, sort_keys=True, indent=2) + "\n")
    print(json.dumps({k: report[k] for k in ("source_bytes", "source_sha256", "author_sha256")}, sort_keys=True))


if __name__ == "__main__":
    main()
