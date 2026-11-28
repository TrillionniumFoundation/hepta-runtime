#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Exact reversible adaptation of the retained private carrier, never policy."""
import argparse
import hashlib
import json
from pathlib import Path

SHA = lambda raw: hashlib.sha256(raw).hexdigest()


def derive(source):
    raw = (source / "dependency/asm/binary_write_body_fixture.S").read_bytes()
    assert SHA(raw)=="38f75708fd2ed642a345240f03998d48eec4bef9fa4e99de2fca3b911df4d97a"
    before = raw.decode()
    value = before
    rows = []

    def edit(old, new, count=1):
        nonlocal value
        assert old and value.count(old) == count, (old, value.count(old), count)
        positions = []
        at = 0
        for _ in range(count):
            at = value.index(old, at)
            positions.append(at)
            at += len(old)
        row = dict(before=old, after=new, count=count, positions=positions,
                   before_sha256=SHA(value.encode()))
        value = value.replace(old, new)
        row["after_positions"] = [pos + i * (len(new) - len(old)) for i, pos in enumerate(positions)]
        row["after_sha256"] = SHA(value.encode())
        rows.append(row)

    edit(" * Private two-context binary write carrier. All parent FDs and the orphan pool belong\n * to this fixed fixture. No public JSON input can select an FD or code address.",
         " * Private two-context parent-owner carrier. The HIA parent owns its FDs;\n * the shared process pool and entropy retain the original fixed primitives.\n * Fixture-only held-parent operations 10/12/14/15/16/19 are unavailable.")
    for suffix in ("create", "invoke", "release", "destroy"):
        old = "binary_write_body_" + suffix
        edit(old, "binary_parent_owner_" + suffix, value.count(old))
    edit("    cmp r14, 10\n    je .Lwbf_hold_parent", "    cmp r14, 10\n    je .Lwbf_no_context")
    for number, label in ((12, "drop_parent"), (14, "parent_stat"), (16, "close_retained"),
                          (15, "child_contexts"), (19, "unowned_refusal")):
        edit("    cmp r14, " + str(number) + "\n    je .Lwbf_" + label,
             "    cmp r14, " + str(number) + "\n    je .Lwbf_no_context")
    edit("    mov rsi, [r15+32+rbx*8]\n    test rsi, rsi\n    jz .Lwbf_no_context\n    dec rsi\n", "")
    edit("    mov rdi, r12\n    lea rdx, [rbp+64]\n    mov rcx, r13\n    call binary_parent_owner_invoke",
         "    mov rdi, r12\n    lea rsi, [rbp+64]\n    mov rdx, r13\n    call binary_parent_owner_invoke")
    edit("    cmp qword ptr [rsi], 5\n    ja .Lwbf_no_context",
         "    cmp qword ptr [rsi], 6\n    ja .Lwbf_no_context")
    edit("    cmp r14, 26\n    ja .Lwbf_fatal", "    cmp r14, 28\n    ja .Lwbf_fatal")
    edit("    cmp r14, 24\n    je .Lwbf_limit_file", "    cmp r14, 24\n    je .Lwbf_limit_file\n"
         "    cmp r14, 27\n    je .Lwbf_arm_parent_actor\n"
         "    cmp r14, 28\n    je .Lwbf_parent_busy_control")
    edit(".Lwbf_limit_file:\n", ".Lwbf_arm_parent_actor:\n"
         "    cmp r13, 8\n    jne .Lwbf_no_context\n"
         "    cmp qword ptr [rbp+64], 1\n    jne .Lwbf_no_context\n"
         "    cmp qword ptr [r15+600], 0\n    jne .Lwbf_no_context\n"
         "    mov qword ptr [r15+600], 1\n    mov qword ptr [r15+608], 0\n"
         "    xor r13d, r13d\n    jmp .Lwbf_empty_reply\n.Lwbf_limit_file:\n")
    edit("    movabs rax, 0x3130494354574248\n    cmp [r12], rax\n    je .Lwbf_journal_write_magic",
         "    movabs rax, 0x3130494357504248\n    cmp [r12], rax\n    je .Lwbf_journal_parent_magic\n"
         "    movabs rax, 0x3130494354574248\n    cmp [r12], rax\n    je .Lwbf_journal_write_magic")
    edit(".Lwbf_journal_write_magic:\n", ".Lwbf_journal_parent_magic:\n"
         "    mov qword ptr [rsp+136], 6\n    movabs rax, 0x3130524a57504248\n"
         "    jmp .Lwbf_journal_magic_ready\n.Lwbf_journal_write_magic:\n")
    edit("    cmp qword ptr [rsp+136], 1\n    je .Lwbf_hook_write_magic",
         "    cmp qword ptr [rsp+136], 6\n    je .Lwbf_hook_parent_magic\n"
         "    cmp qword ptr [rsp+136], 1\n    je .Lwbf_hook_write_magic")
    edit(".Lwbf_hook_write_magic:\n", ".Lwbf_hook_parent_magic:\n"
         "    movabs rax, 0x31304b4857504248\n    jmp .Lwbf_hook_magic_ready\n.Lwbf_hook_write_magic:\n")
    edit("    mov rax, [r14+40]\n    mov [rsp+48], rax\n    mov rax, [r14+48]\n",
         "    mov rax, [r14+40]\n    cmp qword ptr [rsp+136], 6\n"
         "    jne .Lwbf_hook_phase_ready\n    mov rax, [r12+88]\n"
         "    mov rax, [rax+8]\n.Lwbf_hook_phase_ready:\n"
         "    mov [rsp+48], rax\n    mov rax, [r14+48]\n")
    edit("    cmp qword ptr [rbx+88], 0\n    je .Lwbf_journal_hook_ok",
         "    cmp qword ptr [rsp+136], 6\n    jne .Lwbf_no_parent_actor\n"
         "    mov rdi, rbx\n    mov rsi, r12\n    mov rdx, r14\n"
         "    call .Lwbf_parent_actor\n    test rax, rax\n    jnz .Lwbf_journal_return\n"
         ".Lwbf_no_parent_actor:\n    cmp qword ptr [rbx+88], 0\n    je .Lwbf_journal_hook_ok")
    actor = (source / "authoring/parent_actor.S").read_text()
    actor += (source / "authoring/parent_busy_control.S").read_text()
    suffix=value[-128:]
    edit(suffix,suffix+'\n'+actor+'\n')
    restored = value
    for row in reversed(rows):
        assert SHA(restored.encode()) == row["after_sha256"]
        for pos in reversed(row["after_positions"]):
            assert restored[pos:pos + len(row["after"])] == row["after"]
            restored = restored[:pos] + row["before"] + restored[pos + len(row["after"]):]
        assert SHA(restored.encode()) == row["before_sha256"]
    assert restored == before
    return value, dict(schema="hepta.runtime.binary-parent-fixture.author.v1", original_sha256=SHA(raw),
                       source_sha256=SHA(value.encode()), complete_inverse=True, edits=rows,
                       path_policy_added=False, target_result_substitution=False)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        raise ValueError("fresh fixture author output required")
    value, receipt = derive(args.source.resolve(strict=True))
    args.output.mkdir(parents=True)
    (args.output / "binary_parent_owner_fixture.S").write_text(value)
    (args.output / "binary_parent_owner_fixture_edits.json").write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
    print(json.dumps({key: receipt[key] for key in ("schema", "original_sha256", "source_sha256", "complete_inverse")}, sort_keys=True))


if __name__ == "__main__":
    main()
