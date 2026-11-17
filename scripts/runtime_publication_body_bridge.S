/* Copyright 2026 Muvon Un Limited
 * SPDX-License-Identifier: Apache-2.0
 * Fixed synchronous publisher capability. Descriptor67 owns its context,
 * never a normal HIA workspace. HIA alone supplies all filesystem actions.
 * A complete response remains borrowed until the next admitted call or the
 * global engine drain; mechanical delivery growth never reinvokes the body.
 */
.intel_syntax noprefix
.section .text
.global runtime_publication_body_owned
.global runtime_publication_body_destroy
runtime_publication_body_owned:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    sub rsp, 32
    mov [rsp], rdi
    mov [rsp + 8], rsi
    mov rbx, [r15 + 8]
    add rbx, 67 * 64
    lea rbp, [r15 + 512 + 67 * 64]
    cmp qword ptr [rbp], 0
    jne rpb_invalid
    cmp qword ptr [rbp + 8], 0
    jne rpb_invalid
    mov qword ptr [rbp], 1
    mov qword ptr [rbx + 48], 0
    mov qword ptr [rbx + 56], 0
    mov r12, [rbx + 8]
    test r12, r12
    jnz rpb_existing
    cmp qword ptr [rbx + 16], 0
    jne rpb_invalid_active
    xor edi, edi
    xor esi, esi
    call text_publication_create
    cmp rax, -4095
    jae rpb_resource_active
    mov r12, rax
    mov [rbx + 8], rax
    mov qword ptr [rbx + 16], 4096
    jmp rpb_context_ready
rpb_existing:
    cmp qword ptr [rbx + 16], 4096
    jne rpb_invalid_active
    mov rax, 0x3130494343505448 /* HTPCCI01 */
    cmp [r12], rax
    jne rpb_invalid_active
    cmp qword ptr [r12 + 8], 4096
    jne rpb_invalid_active
    mov rax, [r12 + 56]
    test rax, rax
    jz rpb_context_ready
    cmp rax, 2
    jne rpb_invalid_active
    mov rdi, r12
    call text_publication_release
    test eax, eax
    jnz rpb_invalid_active
rpb_context_ready:
    mov rdi, r12
    mov rsi, [rsp]
    mov rdx, [rsp + 8]
    inc qword ptr [r15 + 128]
    call text_publication_invoke
    mov edx, eax
    cmp rax, rdx
    jne rpb_invalid_active
    cmp rax, 64
    jne rpb_returned_error
    cmp [r12 + 176], rax
    jne rpb_invalid_active
    cmp qword ptr [r12 + 56], 2
    jne rpb_invalid_active
    cmp qword ptr [r12 + 184], 0
    jne rpb_invalid_active
    mov r13, [r12 + 104]
    mov r14, [r12 + 112]
    test r13, r13
    jz rpb_invalid_active
    cmp r14, 64
    jb rpb_invalid_active
    mov rcx, [r12 + 168]
    cmp rcx, 64
    jb rpb_invalid_active
    cmp rcx, r14
    ja rpb_invalid_active
    mov rdx, 0x3130305342505448 /* HTPBS001 */
    cmp [r13], rdx
    jne rpb_invalid_active
    mov rdx, [r13 + 8]
    test rdx, rdx
    jz rpb_final_kind
    cmp rdx, 3
    jne rpb_invalid_active
rpb_final_kind:
    mov rdx, [r13 + 24]
    or rdx, [r13 + 32]
    or rdx, [r13 + 40]
    or rdx, [r13 + 48]
    jnz rpb_invalid_active
    mov rdx, rcx
    sub rdx, 64
    cmp [r13 + 56], rdx
    jne rpb_invalid_active
    mov [rbx + 32], r13
    mov [rbx + 40], r14
    mov [rbx + 48], rax
    mov [rbx + 56], rcx
    jmp rpb_complete
rpb_returned_error:
    cmp eax, 0xffff0000
    jb rpb_invalid_active
    jmp rpb_error
rpb_resource_active:
    mov eax, 0xfffffffc
    jmp rpb_error
rpb_invalid_active:
    mov eax, 0xffffffff
rpb_error:
    mov [rbx + 48], rax
    mov qword ptr [rbx + 56], 0
rpb_complete:
    mov qword ptr [rbp], 0
    jmp rpb_done
rpb_invalid:
    mov eax, 0xffffffff
rpb_done:
    add rsp, 32
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

/* Called only after every engine continuation is idle. No descriptor bitmap
 * owns these nested mappings. Successful destroy clears all published aliases;
 * a failure leaves the context attached so cleanup can report or retry it. */
runtime_publication_body_destroy:
    push rbx
    push r12
    sub rsp, 8
    mov rbx, [r15 + 8]
    add rbx, 67 * 64
    mov r12, [rbx + 8]
    test r12, r12
    jz rpb_destroy_empty
    cmp qword ptr [rbx + 16], 4096
    jne rpb_destroy_bad
    mov rax, 0x3130494343505448
    cmp [r12], rax
    jne rpb_destroy_bad
    cmp qword ptr [r12 + 8], 4096
    jne rpb_destroy_bad
    cmp qword ptr [r12 + 56], 2
    jne rpb_destroy_context
    mov rdi, r12
    call text_publication_release
    test eax, eax
    jnz rpb_destroy_done
rpb_destroy_context:
    mov rdi, r12
    call text_publication_destroy
    test rax, rax
    jnz rpb_destroy_done
    mov qword ptr [rbx + 8], 0
    mov qword ptr [rbx + 16], 0
    mov qword ptr [rbx + 32], 0
    mov qword ptr [rbx + 40], 0
    mov qword ptr [rbx + 48], 0
    mov qword ptr [rbx + 56], 0
    jmp rpb_destroy_done
rpb_destroy_empty:
    mov rax, [rbx + 16]
    or rax, [rbx + 32]
    or rax, [rbx + 40]
    jnz rpb_destroy_bad
    xor eax, eax
    jmp rpb_destroy_done
rpb_destroy_bad:
    mov eax, 0xffffffff
rpb_destroy_done:
    add rsp, 8
    pop r12
    pop rbx
    ret
