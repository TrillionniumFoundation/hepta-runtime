/* Copyright 2026 TrillionniumFoundation
 * SPDX-License-Identifier: Apache-2.0
 * Fixed public slot82. The process owns one audit context; engines borrow its
 * cell. A completed HIA result is copied under its lease before publication. */
.intel_syntax noprefix
.section .text

/* Fixed tail entries are patched by the existing native HIA image packer. */
jobs_audit_owner_image:
    .byte 0xe9
jobs_audit_owner_call_displacement:
    .long 0
jobs_audit_canonical_image:
    .byte 0xe9
jobs_audit_canonical_call_displacement:
    .long 0
jobs_audit_sha_image:
    .byte 0xe9
jobs_audit_sha_call_displacement:
    .long 0
jobs_audit_namespace_image:
    .byte 0xe9
jobs_audit_namespace_call_displacement:
    .long 0
jobs_audit_errno_image:
    .byte 0xe9
jobs_audit_errno_call_displacement:
    .long 0

/* rdi trusted process cell, rsi actual installed process AT_SECURE. */
.global runtime_jobs_audit_bind
runtime_jobs_audit_bind:
    JA_SAVE
    mov r12, rdi
    mov r13, rsi
    test r12, r12
    jz jap_bind_invalid
    cmp qword ptr [r12], 0
    jne jap_bound
    lea rdi, [rip + jobs_audit_owner_image]
    lea rsi, [rip + jobs_audit_canonical_image]
    lea rdx, [rip + jobs_audit_sha_image]
    lea rcx, [rip + jobs_audit_namespace_image]
    lea r8, [rip + jobs_audit_errno_image]
    mov r9, r13
    call jobs_audit_create
    cmp rax, -4095
    jae jap_bind_return
    mov rdx, rax
    xor eax, eax
    lock cmpxchg [r12], rdx
    jz jap_bound
    /* A concurrent initializer cannot replace the process's admitted owner. */
    mov rdi, rdx
    call jobs_audit_destroy
    test rax, rax
    jnz jap_bind_return
jap_bound:
    xor eax, eax
    jmp jap_bind_return
jap_bind_invalid:
    mov rax, -22
jap_bind_return:
    JA_RETURN

/* One process close after every service and handler has relinquished its
 * borrow. A failed destroy leaves the cell and its ownership intact. */
.global runtime_jobs_audit_close
runtime_jobs_audit_close:
    push rbx
    mov rbx, rdi
    test rbx, rbx
    jz jap_close_invalid
    mov rdi, [rbx]
    test rdi, rdi
    jz jap_closed
    call jobs_audit_destroy
    test rax, rax
    jnz jap_close_return
    mov qword ptr [rbx], 0
jap_closed:
    xor eax, eax
    jmp jap_close_return
jap_close_invalid:
    mov rax, -22
jap_close_return:
    pop rbx
    ret

/* r15 engine; rdi/rsi the admitted private HBAUQ001 byte span. */
.global runtime_jobs_audit_owned
runtime_jobs_audit_owned:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    sub rsp, 32
    mov [rsp], rdi
    mov [rsp + 8], rsi
    mov rbx, [r15 + 8]
    add rbx, 82 * 64
    lea rbp, [r15 + 512 + 82 * 64]
    mov rax, [rbp]
    or rax, [rbp + 8]
    jnz jap_invalid
    mov qword ptr [rbp], 1
    mov qword ptr [rbx + 48], 0
    mov qword ptr [rbx + 56], 0
    mov r12, [r15 + 488]
    test r12, r12
    jz jap_invalid_active
    mov r13, [r12]
    test r13, r13
    jz jap_invalid_active
    mov rdi, r13
    mov rsi, [rsp]
    mov rdx, [rsp + 8]
    inc qword ptr [r15 + 128]
    call jobs_audit_invoke
    mov edx, eax
    cmp rax, rdx
    jne jap_invalid_active
    cmp eax, 0xffff0000
    jae jap_error_active
    mov r14, rax
    mov rdi, r13
    call jobs_audit_output
    test rax, rax
    jz jap_invalid_release
    mov r12, rax
    mov rax, [rbx + 40]
    mov [rsp + 16], rax
    lea rdi, [rbx + 32]
    mov rsi, r14
    call jobs_audit_grow
    test rax, rax
    jnz jap_resource_release
    bts qword ptr [r15 + RG_OUTPUT_HIGH], 18 /* slot82, engine-owned output */
    mov rax, [rbx + 40]
    cmp [rsp + 16], rax
    je jap_copy
    inc qword ptr [r15 + 144]
jap_copy:
    mov rdi, [rbx + 32]
    mov rsi, r12
    mov rcx, r14
    cld
    rep movsb
    mov rdi, r13
    call jobs_audit_release
    test rax, rax
    jnz jap_invalid_active
    mov [rbx + 48], r14
    mov [rbx + 56], r14
    mov rax, r14
    jmp jap_complete
jap_invalid_release:
    mov r14d, 0xffffffff
    jmp jap_release_error
jap_resource_release:
    mov r14d, 0xfffffffc
jap_release_error:
    mov rdi, r13
    call jobs_audit_release
    test rax, rax
    jnz jap_invalid_active
    mov rax, r14
    jmp jap_error_active
jap_invalid_active:
    mov eax, 0xffffffff
jap_error_active:
    mov [rbx + 48], rax
    mov qword ptr [rbx + 56], 0
jap_complete:
    mov qword ptr [rbp], 0
    jmp jap_owned_return
jap_invalid:
    mov eax, 0xffffffff
jap_owned_return:
    add rsp, 32
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret
