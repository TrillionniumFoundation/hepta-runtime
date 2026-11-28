#!/usr/bin/env python3
"""Compose a new serial Batch fixture around the actual callable export.

Only framing, allocation and complete observations are implemented here. Every
filesystem, cache, history, lock, planning and rendering decision remains HIA.
"""
from pathlib import Path
import argparse
import hashlib
import json

SHA = lambda raw: hashlib.sha256(raw).hexdigest()
BASE = "2980ab23ed5b7ee37f449b81542473969b6d02dc0e2a6d15b0948296aec6f010"
EXPORT = "5120f566fe8e4ace6c441d2dd110188663cb29bcc28af26a759b44a6f86b15b6"

PURE = r'''pure_invoke:
    push rbp
    push rbx
    push r12
    push r13
    push r14
    mov r14,rdi
    cmp r14,3
    je pure_admitted
    cmp r14,5
    je pure_admitted
    cmp r14,7
    jne contract
pure_admitted:
    mov r12,rsi
    mov r13,rdx
    cmp r13,536870912
    ja resource
    mov rbx,r14
    shl rbx,6
    lea rbx,[r15+SLOTS+rbx]
    lea rdi,[rbx+8]
    mov esi,4096
    mov edx,1
    call ensure_region
    lea rdi,[rbx+24]
    mov esi,4096
    xor edx,edx
    call ensure_region
pure_again:
    mov rdi,r12
    mov rsi,r13
    mov rdx,[rbx+24]
    mov rcx,[rbx+32]
    mov r8,[rbx+8]
    mov r9,[rbx+16]
    call qword ptr [rbx]
    mov edx,eax
    cmp rax,rdx
    jne contract
    cmp eax,0xfffffffe
    je pure_capacity
    cmp eax,0xffff0000
    jae pure_return
    cmp rax,[rbx+32]
    ja contract
    cmp r14,7
    jne pure_return
    cmp eax,64
    jne pure_return
    mov rcx,[rbx+24]
    cmp qword ptr [rcx+16],2
    jne pure_return
    mov rsi,[rcx+32]
    cmp rsi,[rbx+16]
    jbe contract
    cmp rsi,1207959552
    ja resource
    lea rdi,[rbx+8]
    mov edx,1
    call ensure_region
    jmp pure_again
pure_capacity:
    cmp r14,7
    je resource
    mov rsi,[rbx+16]
    shl rsi,1
    jc resource
    cmp rsi,1207959552
    ja resource
    lea rdi,[rbx+8]
    mov edx,1
    call ensure_region
    mov rsi,[rbx+32]
    shl rsi,1
    jc resource
    cmp rsi,1073741824
    ja resource
    lea rdi,[rbx+24]
    xor edx,edx
    call ensure_region
    jmp pure_again
pure_return:
    mov [rbx+40],rax
    mov rsi,[rbx+24]
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret

'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    old = (root / "retained/local_text_body_callable_fixture.S").read_bytes()
    exported = (root / "retained/local_text_body_callable.S").read_bytes()
    new = (root / "native_boundary/local_batch_body_callable.S").read_bytes()
    assert SHA(old) == BASE and SHA(exported) == EXPORT
    assert old.count(exported) == 1
    before, tail = old.split(exported)
    assert tail == b"\n.balign 16,0\nimage_table:\n.quad 0,0,0,0,0,0,0,0,0,0,0,0\n.balign 16,0\nimages:\n"
    text = before.decode()
    edits = []

    def replace(before, after, count=1):
        nonlocal text
        assert text.count(before) == count, (before, text.count(before), count)
        text = text.replace(before, after)
        edits.append({"before": before, "after": after, "count": count})

    first, last = text.index("pure_invoke:\n"), text.index("observe_states:\n")
    text = text[:first] + PURE + text[last:]
    first, last = text.index("observe_hints:\n"), text.index("round_capacity:\n")
    text = text[:first] + text[last:]
    text = text[:text.index("fixture_hint_callback:\n")] + "fixture_hint_callback:\n    mov eax,0xffffffff\n    ret\n\n"
    replace("cmp ecx,12", "cmp ecx,14", 2)
    replace("    mov edi,3\n    lea rsi,[rip+lock_initial]", "    mov edi,7\n    lea rsi,[rip+lock_initial]")
    replace("cmp qword ptr [r15+INLEN],134217728", "cmp qword ptr [r15+INLEN],536870912")
    replace("0x3130515242544c48", "0x3130305457424648")
    replace("cmp qword ptr [r15+INLEN],80", "cmp qword ptr [r15+INLEN],64")
    replace("    mov rax,[rbx+56]\n    mov [r15+GENERATION],rax\n    mov qword ptr [r15+HINTLEN],0\n    mov qword ptr [r15+HINTCOUNT],0\n", "    inc qword ptr [r15+GENERATION]\n    jz contract\n")
    replace("    call observe_hints\n", "")
    replace("cmp eax,0xffffffdf", "cmp eax,0xffffffe1")
    replace("    cmp [r15+1400],rax\n", "    cmp qword ptr [r15+1440],0\n    jne contract\n    cmp [r15+1400],rax\n")
    replace("    mov edi,8\n", "    mov edi,5\n", 2)
    replace("    mov edi,6\n", "    mov edi,3\n")
    replace("    mov ebx,3\nobserve_one:", "    mov ebx,7\nobserve_one:")
    replace("    cmp ebx,3\n    jne observe_second\n    mov ebx,6\n", "    cmp ebx,7\n    jne observe_second\n    mov ebx,3\n")
    replace("    cmp ebx,6\n    jne observe_done\n    mov ebx,8\n", "    cmp ebx,3\n    jne observe_done\n    mov ebx,5\n")
    replace("0x3130414e42544c48", "0x3130414e42424c48")
    replace("0x3130494342544c48", "0x3130494342424c48")
    replace("lea rax,[r15+SLOTS+192]", "lea rax,[r15+SLOTS+448]")
    replace("lea rax,[r15+SLOTS+384]", "lea rax,[r15+SLOTS+192]")
    replace("    cmp esi,3\n    je fixture_shared_selected\n    cmp esi,6\n", "    cmp esi,7\n    je fixture_shared_selected\n    cmp esi,3\n")
    replace("cmp r12,268435456", "cmp r12,1207959552")
    replace("cmp r13,134217728", "cmp r13,1073741824")
    text = text.replace("local_text_body_", "local_batch_body_")
    result = text.encode() + new + b"\n.balign 16,0\nimage_table:\n.quad " + b",".join([b"0"] * 14) + b"\n.balign 16,0\nimages:\n"
    assert result.count(new) == 1 and b"ltb_" not in result
    args.output.mkdir(parents=True, exist_ok=False)
    (args.output / "local_batch_body_fixture.S").write_bytes(result)
    report = {"schema": "hepta.runtime.rebuilt-batch-fixture-author.v1", "fixture_sha256": SHA(result),
        "fixture_bytes": len(result), "retained_fixture_sha256": BASE, "retained_export_sha256": EXPORT,
        "export_sha256": SHA(new), "export_bytes": len(new), "export_occurrences": 1,
        "fixture_prefix_bytes": len(text.encode()), "fixed_slots": 14, "explicit_edits": edits,
        "replaced_helpers": ["pure_invoke", "fixture_hint_callback"], "removed_helpers": ["observe_hints"],
        "observation_magic": "HLBBNA01", "observed_slots": [7, 3, 5], "serial_fixture_only": True,
        "semantic_qualification": False, "fresh_current_original_compared": False,
        "full_async_cancellation_qualified": False, "public_batch_qualified": False}
    (args.output / "fixture-author-proof.json").write_text(json.dumps(report, sort_keys=True, indent=2) + "\n")
    print(json.dumps({key: report[key] for key in ("fixture_bytes", "fixture_sha256", "export_sha256")}, sort_keys=True))


if __name__ == "__main__":
    main()
