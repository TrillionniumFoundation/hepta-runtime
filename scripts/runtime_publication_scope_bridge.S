/* Copyright 2026 Muvon Un Limited
 * SPDX-License-Identifier: Apache-2.0
 * Fixed publisher child6 / descriptor68. The actual HIA caller chooses Forget
 * and its key. This mechanical capability lends exactly96 output bytes to the
 * existing Scope owner and restores the owning capacity on every return.
 * No cache mutation, application result, path choice or request identity is
 * manufactured here. All cache/lease semantics remain in the installed HIA.
 */
.intel_syntax noprefix
.section .text
.global runtime_publication_forget_owned
runtime_publication_forget_owned:
    push rbp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub rsp, 88
    mov [rsp], rdi
    mov [rsp + 8], rsi
    mov r14, r15
    mov rbx, [r14 + 8]
    add rbx, 68*64
    lea rbp, [r14 + 512 + 68*64]
    cmp qword ptr [rbp], 0
    jne rpf_unowned_invalid
    cmp qword ptr [rbp + 8], 0
    jne rpf_unowned_invalid
    /* Admit only the pending, actual fixed parent CALL. The private fixture
     * has no selector68, and public input has no descriptor selection. */
    mov rdx, [r14 + 8]
    add rdx, 66*64
    cmp qword ptr [rdx + 16], 4096
    jb rpf_unowned_invalid
    mov r12, [rdx + 8]
    test r12, r12
    jz rpf_unowned_invalid
    mov rax, 0x3130545343505448 /* HTPCST01 */
    cmp [r12], rax
    jne rpf_unowned_invalid
    cmp qword ptr [r12 + 8], 3
    jne rpf_unowned_invalid
    cmp qword ptr [r12 + 416], 1
    jne rpf_unowned_invalid
    cmp qword ptr [r12 + 440], 2
    jne rpf_unowned_invalid
    lea r13, [r14 + 512 + 66*64]
    cmp qword ptr [r13], 1
    jne rpf_unowned_invalid
    cmp qword ptr [r13 + 8], 0
    jne rpf_unowned_invalid
    cmp qword ptr [r13 + 24], 68
    jne rpf_unowned_invalid
    mov rax, [r13 + 16]
    test rax, rax
    jz rpf_unowned_invalid
    cmp [r12 + 16], rax
    jne rpf_unowned_invalid
    cmp [rdx + 24], rax
    jne rpf_unowned_invalid
    cmp [r12 + 264], rax
    jne rpf_unowned_invalid
    mov rax, 0x3130414343505448 /* HTPCCA01 */
    cmp [r12 + 256], rax
    jne rpf_unowned_invalid
    cmp qword ptr [r12 + 272], 6
    jne rpf_unowned_invalid
    cmp qword ptr [r12 + 280], 0
    jne rpf_unowned_invalid
    mov rax, [r13 + 32]
    cmp [r12 + 288], rax
    jne rpf_unowned_invalid
    cmp rax, [rdx + 16]
    ja rpf_unowned_invalid
    mov rcx, [rdx + 16]
    sub rcx, rax
    cmp rsi, rcx
    ja rpf_unowned_invalid
    add rax, r12
    jc rpf_unowned_invalid
    cmp rdi, rax
    jne rpf_unowned_invalid
    cmp [r13 + 40], rsi
    jne rpf_unowned_invalid
    cmp [r12 + 296], rsi
    jne rpf_unowned_invalid
    cmp qword ptr [r12 + 312], 96
    jb rpf_unowned_invalid
    cmp rsi, 112
    jb rpf_unowned_invalid
    mov rax, 0x3130305143535248 /* HRSCQ001 */
    cmp [rdi], rax
    jne rpf_unowned_invalid
    cmp qword ptr [rdi + 8], 9
    jne rpf_unowned_invalid
    mov rax, [r12 + 112]
    test rax, rax
    jz rpf_unowned_invalid
    cmp [rdi + 16], rax
    jne rpf_unowned_invalid
    mov rax, [r12 + 120]
    test rax, rax
    jz rpf_unowned_invalid
    cmp [rdi + 24], rax
    jne rpf_unowned_invalid
    mov rax, [rdi + 32]
    or rax, [rdi + 40]
    or rax, [rdi + 56]
    jnz rpf_unowned_invalid
    mov rax, rsi
    sub rax, 64
    cmp [rdi + 48], rax
    jne rpf_unowned_invalid
    mov rax, 0x3130484341435648 /* HVCACH01 */
    cmp [rdi + 64], rax
    jne rpf_unowned_invalid
    cmp qword ptr [rdi + 72], 3
    jne rpf_unowned_invalid
    cmp qword ptr [rdi + 80], 1
    jne rpf_unowned_invalid
    mov rax, rsi
    sub rax, 112
    cmp [rdi + 88], rax
    jne rpf_unowned_invalid
    mov rax, [rdi + 96]
    or rax, [rdi + 104]
    jnz rpf_unowned_invalid
    mov qword ptr [rbp], 1
    mov qword ptr [rbx + 48], 0
    mov qword ptr [rbx + 56], 0
    call runtime_grow_view_ensure
    cmp rax, -4095
    jae rpf_resource
    mov r15, rax
    mov r13, [r15 + 8]
    add r13, 6*64
    mov rax, [r13 + 32]
    cmp rax, 96
    jb rpf_invalid
    cmp qword ptr [r13 + 56], 0
    jne rpf_invalid
    mov [rsp + 24], rax
    mov qword ptr [r13 + 32], 96
    mov rdi, [rsp]
    mov rsi, [rsp + 8]
    mov edx, 6
    inc qword ptr [r14 + 128]
    call view_scope_invoke
    /* Restore before checking status or exposing the complete borrowed span. */
    mov rdx, [rsp + 24]
    mov [r13 + 32], rdx
    mov r15, r14
    mov edx, eax
    cmp rax, rdx
    jne rpf_invalid
    cmp [r13 + 40], rax
    jne rpf_invalid
    mov rcx, [r13 + 8]
    mov [rbx + 8], rcx
    mov rcx, [r13 + 16]
    mov [rbx + 16], rcx
    mov rcx, [r13 + 24]
    mov [rbx + 32], rcx
    mov qword ptr [rbx + 40], 96
    mov [rbx + 48], rax
    cmp eax, 0xffff0000
    jae rpf_trace
    cmp rax, 96
    jne rpf_invalid
    mov [rbx + 56], rax
rpf_trace:
    mov [rsp + 48], rax
    mov [rsp + 56], rbp
    mov ebp, 68
    mov edi, 1
    call runtime_grow_trace
    mov rbp, [rsp + 56]
    mov rax, [rsp + 48]
    jmp rpf_complete
rpf_resource:
    mov eax, 0xfffffffc
    jmp rpf_error
rpf_invalid:
    mov eax, 0xffffffff
rpf_error:
    mov r15, r14
    mov [rbx + 48], rax
    mov qword ptr [rbx + 56], 0
rpf_complete:
    mov qword ptr [rbp], 0
    jmp rpf_done
rpf_unowned_invalid:
    mov eax, 0xffffffff
rpf_done:
    add rsp, 88
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret
.section .note.GNU-stack,"",@progbits
