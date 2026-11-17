/* Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
 * Fixed HIACAL borrowed-span transport; all application semantics are HIA.
 * r15: engine; engine+8: 19 descriptors, each 64 bytes.
 * Descriptor: entry, workspace, workspace length, output, output length,
 * last u32 result, last consumed call sequence, active bridge invocation.
 * The last two fields are bridge-owned only for slots 12 through 18.
 */
.intel_syntax noprefix
.section .text
.global view_regex_invoke
.type view_regex_invoke, @function
/* rdi=input, rsi=length, edx=12..18. Return zero-extended native u32.
 * Fixed actual children: 12 -> {13,14,15,16,18}, {13,14,16} -> 17. No IO effect is granted.
 * Logical regex slots map only through this fixed private table.
 * A single-unit flat adapter calls the local view_regex_invoke_flat alias;
 * this avoids ELF symbol interposition relocations before raw extraction.
 */
view_regex_invoke:
view_regex_invoke_flat:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp, 312
    mov [rsp], rdi
    mov [rsp + 8], rsi
    mov r14d, edx
    cmp edx, 12
    jb .Lvrg_unowned_resource
    cmp edx, 18
    ja .Lvrg_unowned_resource
.Lvrg_slot:
    mov rax, [r15 + 8]
    test rax, rax
    jz .Lvrg_unowned_resource
    mov [rsp + 160], rax
    mov r12, r14
    shl r12, 6
    add r12, rax
    jc .Lvrg_unowned_resource
    cmp qword ptr [r12 + 56], 0
    jne .Lvrg_unowned_resource
    cmp qword ptr [r12], 0
    je .Lvrg_unowned_resource
    mov rax, [r12]
    mov [rsp + 168], rax
    mov rax, [r12 + 24]
    mov [rsp + 16], rax
    add rax, [r12 + 32]
    jc .Lvrg_unowned_resource
    mov rax, [r12 + 32]
    mov [rsp + 24], rax
    mov rax, [r12 + 8]
    test rax, rax
    jz .Lvrg_unowned_resource
    mov [rsp + 32], rax
    add rax, [r12 + 16]
    jc .Lvrg_unowned_resource
    mov rcx, [r12 + 16]
    cmp rcx, 256
    jb .Lvrg_unowned_resource
    mov [rsp + 40], rcx
    sub rax, 256
    mov r13, rax
    mov [rsp + 48], r14
    mov [rsp + 56], r13
    mov rax, [rsp]
    add rax, [rsp + 8]
    jc .Lvrg_unowned_resource
    cmp qword ptr [rsp + 8], 0
    je .Lvrg_input_pointer
    cmp qword ptr [rsp], 0
    je .Lvrg_unowned_resource
.Lvrg_input_pointer:
    cmp qword ptr [rsp + 24], 0
    je .Lvrg_output_pointer
    cmp qword ptr [rsp + 16], 0
    je .Lvrg_unowned_resource
.Lvrg_output_pointer:
    mov rdi, [rsp]
    mov rsi, [rsp + 8]
    mov rdx, [rsp + 16]
    mov rcx, [rsp + 24]
    call .Lvrg_overlap
    test eax, eax
    jnz .Lvrg_unowned_resource
    mov rdi, [rsp]
    mov rsi, [rsp + 8]
    mov rdx, [rsp + 32]
    mov rcx, [rsp + 40]
    call .Lvrg_overlap
    test eax, eax
    jnz .Lvrg_unowned_resource
    mov rdi, [rsp + 16]
    mov rsi, [rsp + 24]
    mov rdx, [rsp + 32]
    mov rcx, [rsp + 40]
    call .Lvrg_overlap
    test eax, eax
    jnz .Lvrg_unowned_resource
    mov qword ptr [rsp + 136], 1
    cmp r14d, 12
    je .Lvrg_activate
    mov qword ptr [rsp + 136], 2
    cmp r14d, 17
    jne .Lvrg_activate
    mov qword ptr [rsp + 136], 3
.Lvrg_activate:
    mov qword ptr [r12 + 56], 1
.Lvrg_again:
    mov qword ptr [r13 + 120], 3
    mov [r13 + 128], r14
    mov rax, [rsp + 136]
    mov [r13 + 136], rax
    mov rdi, [rsp]
    mov rsi, [rsp + 8]
    mov rdx, [rsp + 16]
    mov rcx, [rsp + 24]
    mov r8, [rsp + 32]
    mov r9, [rsp + 40]
    call qword ptr [r12]
    mov rdx, rax
    shr rdx, 32
    jnz .Lvrg_resource
    cmp eax, 0xffffffe0
    je .Lvrg_call
    cmp eax, 0xfffffffc
    je .Lvrg_resource
    cmp eax, 0xffff0000
    jb .Lvrg_normal
    cmp eax, 0xfffffffd
    jb .Lvrg_resource
    jmp .Lvrg_done
.Lvrg_normal:
    cmp rax, [rsp + 24]
    ja .Lvrg_resource
    jmp .Lvrg_done
.Lvrg_call:
    movabs rax, 0x31304c4143414948
    cmp [r13], rax
    jne .Lvrg_resource
    mov rax, [r13 + 8]
    test rax, rax
    jz .Lvrg_resource
    mov rcx, [r12 + 48]
    inc rcx
    jz .Lvrg_resource
    cmp rax, rcx
    jne .Lvrg_resource
    cmp qword ptr [r13 + 72], 0
    jne .Lvrg_resource
    cmp qword ptr [r13 + 80], 0
    jne .Lvrg_resource
    cmp qword ptr [r13 + 88], 0
    jne .Lvrg_resource
    cmp qword ptr [r13 + 96], 0
    jne .Lvrg_resource
    cmp qword ptr [r13 + 104], 0
    jne .Lvrg_resource
    cmp qword ptr [r13 + 112], 0
    jne .Lvrg_resource
    mov [r12 + 48], rax
    mov [rsp + 104], rax
    mov rax, [r13 + 16]
    cmp r14d, 12
    jne .Lvrg_data_target
    cmp rax, 10
    je .Lvrg_syntax_target
    cmp rax, 12
    je .Lvrg_hir_target
    cmp rax, 13
    je .Lvrg_nfa_target
    cmp rax, 14
    je .Lvrg_match_target
    cmp rax, 16
    jne .Lvrg_denied_target
    mov eax, 18
    jmp .Lvrg_target
.Lvrg_syntax_target:
    mov eax, 13
    jmp .Lvrg_target
.Lvrg_hir_target:
    mov eax, 14
    jmp .Lvrg_target
.Lvrg_nfa_target:
    mov eax, 15
    jmp .Lvrg_target
.Lvrg_match_target:
    mov eax, 16
    jmp .Lvrg_target
.Lvrg_data_target:
    cmp rax, 11
    jne .Lvrg_denied_target
    cmp r14d, 13
    je .Lvrg_unicode_target
    cmp r14d, 14
    je .Lvrg_unicode_target
    cmp r14d, 16
    jne .Lvrg_denied_target
.Lvrg_unicode_target:
    mov eax, 17
.Lvrg_target:
    mov [rsp + 64], rax
    shl rax, 6
    add rax, [r15 + 8]
    jc .Lvrg_resource
    mov [rsp + 112], rax
    cmp qword ptr [rax], 0
    je .Lvrg_denied_target
    cmp qword ptr [rax + 56], 0
    jne .Lvrg_denied_active
.Lvrg_input:
    mov rax, [r13 + 24]
    cmp rax, 2
    ja .Lvrg_denied_span
    test rax, rax
    jz .Lvrg_input_zero
    cmp rax, 1
    je .Lvrg_input_one
    mov rdi, [rsp + 32]
    mov rcx, [rsp + 40]
    sub rcx, 256
    jmp .Lvrg_input_span
.Lvrg_input_zero:
    mov rdi, [rsp]
    mov rcx, [rsp + 8]
    jmp .Lvrg_input_span
.Lvrg_input_one:
    mov rdi, [rsp + 16]
    mov rcx, [rsp + 24]
.Lvrg_input_span:
    mov rax, [r13 + 32]
    cmp rax, rcx
    ja .Lvrg_denied_span
    sub rcx, rax
    mov rsi, [r13 + 40]
    cmp rsi, rcx
    ja .Lvrg_denied_span
    cmp rsi, 134217728
    ja .Lvrg_denied_span
    add rdi, rax
    jc .Lvrg_denied_span
    mov [rsp + 72], rdi
    mov [rsp + 80], rsi
    mov rax, rdi
    add rax, rsi
    jc .Lvrg_denied_span
    mov rax, [r13 + 48]
    cmp rax, 1
    je .Lvrg_output_one
    cmp rax, 2
    jne .Lvrg_denied_span
    mov rdx, [rsp + 32]
    mov rcx, [rsp + 40]
    sub rcx, 256
    jmp .Lvrg_output_span
.Lvrg_output_one:
    mov rdx, [rsp + 16]
    mov rcx, [rsp + 24]
.Lvrg_output_span:
    mov rax, [r13 + 56]
    cmp rax, rcx
    ja .Lvrg_denied_span
    sub rcx, rax
    mov rbx, [r13 + 64]
    cmp rbx, rcx
    ja .Lvrg_denied_span
    mov rbp, [rsp + 112]
    cmp rbx, [rbp + 32]
    ja .Lvrg_denied_span
    add rdx, rax
    jc .Lvrg_denied_span
    mov [rsp + 88], rdx
    mov [rsp + 96], rbx
    mov rax, rdx
    add rax, rbx
    jc .Lvrg_denied_span
    mov rcx, rbx
    call .Lvrg_overlap
    test eax, eax
    jnz .Lvrg_denied_overlap
    mov rdi, [rsp + 72]
    mov rsi, [rsp + 80]
    mov rdx, [rbp + 8]
    mov rcx, [rbp + 16]
    test rdx, rdx
    jz .Lvrg_denied_span
    test rcx, rcx
    jz .Lvrg_denied_span
    mov rax, rdx
    add rax, rcx
    jc .Lvrg_denied_span
    call .Lvrg_overlap
    test eax, eax
    jnz .Lvrg_denied_overlap
    mov rdi, [rsp + 88]
    mov rsi, [rsp + 96]
    mov rdx, [rbp + 8]
    mov rcx, [rbp + 16]
    call .Lvrg_overlap
    test eax, eax
    jnz .Lvrg_denied_overlap
    /* The complete pending request must survive before an ACK exists. */
    lea rdi, [rsp + 176]
    mov rsi, r13
    mov ecx, 15
    cld
    rep movsq
    /* Every child sees the exact borrowed bounds while it is active. */
    mov rax, [rbp + 24]
    mov [rsp + 120], rax
    mov rax, [rbp + 32]
    mov [rsp + 128], rax
    mov rax, [rsp + 88]
    mov [rbp + 24], rax
    mov rax, [rsp + 96]
    mov [rbp + 32], rax
    mov rdi, [rsp + 72]
    mov rsi, [rsp + 80]
    mov edx, dword ptr [rsp + 64]
    call view_regex_invoke_flat
.Lvrg_child_return:
    mov rdx, [rsp + 120]
    mov [rbp + 24], rdx
    mov rdx, [rsp + 128]
    mov [rbp + 32], rdx
    mov rdx, rax
    shr rdx, 32
    jnz .Lvrg_resource
    mov [rbp + 40], rax
    cmp eax, 0xfffffffc
    je .Lvrg_resource
    cmp eax, 0xffff0000
    jb .Lvrg_child_length
    cmp eax, 0xfffffffd
    jb .Lvrg_resource
    jmp .Lvrg_child_checked
.Lvrg_child_length:
    cmp rax, [rsp + 96]
    ja .Lvrg_resource
.Lvrg_child_checked:
    mov [rsp + 144], rax
    mov rax, [r15 + 8]
    cmp rax, [rsp + 160]
    jne .Lvrg_resource
    mov rax, [r12]
    cmp rax, [rsp + 168]
    jne .Lvrg_resource
    mov rax, [r12 + 8]
    cmp rax, [rsp + 32]
    jne .Lvrg_resource
    mov rax, [r12 + 16]
    cmp rax, [rsp + 40]
    jne .Lvrg_resource
    mov rax, [r12 + 24]
    cmp rax, [rsp + 16]
    jne .Lvrg_resource
    mov rax, [r12 + 32]
    cmp rax, [rsp + 24]
    jne .Lvrg_resource
    lea rsi, [rsp + 176]
    mov rdi, r13
    mov ecx, 15
    cld
    repe cmpsq
    jne .Lvrg_resource
    xor ecx, ecx
    mov rax, [rsp + 144]
    jmp .Lvrg_ack
.Lvrg_denied_target:
    mov ecx, 1
    jmp .Lvrg_denied
.Lvrg_denied_active:
    mov ecx, 2
    jmp .Lvrg_denied
.Lvrg_denied_span:
    mov ecx, 3
    jmp .Lvrg_denied
.Lvrg_denied_overlap:
    mov ecx, 4
.Lvrg_denied:
    mov eax, 0xffffffff
.Lvrg_ack:
    mov [r13 + 80], rax
    mov rax, [rsp + 104]
    mov [r13 + 88], rax
    mov qword ptr [r13 + 96], 1
    mov [r13 + 104], rcx
    jmp .Lvrg_again
.Lvrg_resource:
    mov eax, 0xfffffffc
.Lvrg_done:
    mov [r12 + 40], rax
    mov qword ptr [r12 + 56], 0
    jmp .Lvrg_exit
.Lvrg_unowned_resource:
    mov eax, 0xfffffffc
.Lvrg_exit:
    add rsp, 312
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret
.size view_regex_invoke, .-view_regex_invoke

/* One for overlapping nonempty spans or wrapped endpoints. */
.Lvrg_overlap:
    xor eax, eax
    test rsi, rsi
    jz .Lvrg_overlap_done
    test rcx, rcx
    jz .Lvrg_overlap_done
    mov r8, rdi
    add r8, rsi
    jc .Lvrg_overlap_yes
    mov r9, rdx
    add r9, rcx
    jc .Lvrg_overlap_yes
    cmp rdi, r9
    jae .Lvrg_overlap_done
    cmp rdx, r8
    jae .Lvrg_overlap_done
.Lvrg_overlap_yes:
    mov eax, 1
.Lvrg_overlap_done:
    ret


/* Root-only output growth after the HIA formatter records its exact extent. */
.global view_regex_dispatch
view_regex_dispatch:
    push rbx
    push r12
    push r13
    push r14
    sub rsp, 8
    mov r12, rdi
    mov r13, rsi
    cmp edx, 12
    jne .Lvrg_dispatch_invalid
    mov rbx, [r15 + 8]
    add rbx, 12*64
.Lvrg_dispatch_again:
    mov rdi, r12
    mov rsi, r13
    mov edx, 12
    call view_regex_invoke_flat
    cmp eax, 0xfffffffe
    jne .Lvrg_dispatch_done
    mov rcx, [rbx + 8]
    cmp qword ptr [rcx + 8], 7
    jne .Lvrg_dispatch_done
    mov rax, [rcx + 176]
    add rax, 32
    jc .Lvrg_dispatch_resource
    cmp rax, 134217728
    ja .Lvrg_dispatch_resource
    cmp rax, [rbx + 32]
    jbe .Lvrg_dispatch_invalid
    mov r14, [rbx + 32]
.Lvrg_dispatch_capacity:
    cmp r14, rax
    jae .Lvrg_dispatch_grow
    shl r14, 1
    jc .Lvrg_dispatch_resource
    jmp .Lvrg_dispatch_capacity
.Lvrg_dispatch_grow:
    mov rdi, [rbx + 24]
    mov rsi, [rbx + 32]
    mov rdx, r14
    call view_resize
    cmp rax, -4095
    jae .Lvrg_dispatch_resource
    mov [rbx + 24], rax
    mov [rbx + 32], r14
    jmp .Lvrg_dispatch_again
.Lvrg_dispatch_invalid:
    mov eax, 0xffffffff
    jmp .Lvrg_dispatch_unbound
.Lvrg_dispatch_resource:
    mov eax, 0xfffffffc
.Lvrg_dispatch_done:
    mov [rbx + 40], rax
.Lvrg_dispatch_unbound:
    add rsp, 8
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

.section .note.GNU-stack,"",@progbits
