/* Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
 * Fixed HIACAL borrowed-span transport; all application semantics are HIA.
 * r15: engine; engine+8: 12 descriptors, each 64 bytes.
 * Descriptor: entry, workspace, workspace length, output, output length,
 * last u32 result, last consumed call sequence, active bridge invocation.
 * The last two fields are bridge-owned only for slots 6 and 7.
 */
.intel_syntax noprefix
.section .text
.global view_scope_invoke
.type view_scope_invoke, @function
/* rdi=input, rsi=length, edx=6/7. Return zero-extended native u32.
 * Fixed children: 6 -> {7,10}, 7 -> 8. No IO effect is granted.
 * Cache slot 8 is looked up afresh after any trusted direct cache growth.
 * A single-unit flat adapter calls the local view_scope_invoke_flat alias;
 * this avoids ELF symbol interposition relocations before raw extraction.
 */
view_scope_invoke:
view_scope_invoke_flat:
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
    cmp edx, 6
    je .Lvsc_slot
    cmp edx, 7
    jne .Lvsc_unowned_resource
.Lvsc_slot:
    mov rax, [r15 + 8]
    test rax, rax
    jz .Lvsc_unowned_resource
    mov [rsp + 160], rax
    mov r12, r14
    shl r12, 6
    add r12, rax
    jc .Lvsc_unowned_resource
    cmp qword ptr [r12 + 56], 0
    jne .Lvsc_unowned_resource
    cmp qword ptr [r12], 0
    je .Lvsc_unowned_resource
    mov rax, [r12]
    mov [rsp + 168], rax
    mov rax, [r12 + 24]
    mov [rsp + 16], rax
    add rax, [r12 + 32]
    jc .Lvsc_unowned_resource
    mov rax, [r12 + 32]
    mov [rsp + 24], rax
    mov rax, [r12 + 8]
    test rax, rax
    jz .Lvsc_unowned_resource
    mov [rsp + 32], rax
    add rax, [r12 + 16]
    jc .Lvsc_unowned_resource
    mov rcx, [r12 + 16]
    cmp rcx, 256
    jb .Lvsc_unowned_resource
    mov [rsp + 40], rcx
    sub rax, 256
    mov r13, rax
    mov [rsp + 48], r14
    mov [rsp + 56], r13
    mov rax, [rsp]
    add rax, [rsp + 8]
    jc .Lvsc_unowned_resource
    cmp qword ptr [rsp + 8], 0
    je .Lvsc_input_pointer
    cmp qword ptr [rsp], 0
    je .Lvsc_unowned_resource
.Lvsc_input_pointer:
    cmp qword ptr [rsp + 24], 0
    je .Lvsc_output_pointer
    cmp qword ptr [rsp + 16], 0
    je .Lvsc_unowned_resource
.Lvsc_output_pointer:
    mov rdi, [rsp]
    mov rsi, [rsp + 8]
    mov rdx, [rsp + 16]
    mov rcx, [rsp + 24]
    call .Lvsc_overlap
    test eax, eax
    jnz .Lvsc_unowned_resource
    mov rdi, [rsp]
    mov rsi, [rsp + 8]
    mov rdx, [rsp + 32]
    mov rcx, [rsp + 40]
    call .Lvsc_overlap
    test eax, eax
    jnz .Lvsc_unowned_resource
    mov rdi, [rsp + 16]
    mov rsi, [rsp + 24]
    mov rdx, [rsp + 32]
    mov rcx, [rsp + 40]
    call .Lvsc_overlap
    test eax, eax
    jnz .Lvsc_unowned_resource
    mov qword ptr [rsp + 136], 1
    cmp r14d, 7
    jne .Lvsc_activate
    mov rax, [r15 + 8]
    cmp qword ptr [rax + 6*64 + 56], 1
    jne .Lvsc_activate
    mov qword ptr [rsp + 136], 2
.Lvsc_activate:
    mov qword ptr [r12 + 56], 1
.Lvsc_again:
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
    jnz .Lvsc_resource
    cmp eax, 0xffffffe0
    je .Lvsc_call
    cmp eax, 0xfffffffc
    je .Lvsc_resource
    cmp eax, 0xffff0000
    jb .Lvsc_normal
    cmp eax, 0xfffffffd
    jb .Lvsc_resource
    jmp .Lvsc_done
.Lvsc_normal:
    cmp rax, [rsp + 24]
    ja .Lvsc_resource
    jmp .Lvsc_done
.Lvsc_call:
    movabs rax, 0x31304c4143414948
    cmp [r13], rax
    jne .Lvsc_resource
    mov rax, [r13 + 8]
    test rax, rax
    jz .Lvsc_resource
    cmp rax, [r12 + 48]
    jbe .Lvsc_resource
    cmp qword ptr [r13 + 72], 0
    jne .Lvsc_resource
    cmp qword ptr [r13 + 80], 0
    jne .Lvsc_resource
    cmp qword ptr [r13 + 88], 0
    jne .Lvsc_resource
    cmp qword ptr [r13 + 96], 0
    jne .Lvsc_resource
    cmp qword ptr [r13 + 104], 0
    jne .Lvsc_resource
    mov [r12 + 48], rax
    mov [rsp + 104], rax
    mov rax, [r13 + 16]
    mov [rsp + 64], rax
    cmp r14d, 6
    jne .Lvsc_lease_target
    cmp rax, 7
    je .Lvsc_target
    cmp rax, 10
    jne .Lvsc_denied_target
    jmp .Lvsc_target
.Lvsc_lease_target:
    cmp rax, 8
    jne .Lvsc_denied_target
.Lvsc_target:
    shl rax, 6
    add rax, [r15 + 8]
    jc .Lvsc_resource
    mov [rsp + 112], rax
    cmp qword ptr [rax], 0
    je .Lvsc_denied_target
    cmp qword ptr [rsp + 64], 7
    jne .Lvsc_input
    cmp qword ptr [rax + 56], 0
    jne .Lvsc_denied_active
.Lvsc_input:
    mov rax, [r13 + 24]
    cmp rax, 2
    ja .Lvsc_denied_span
    test rax, rax
    jz .Lvsc_input_zero
    cmp rax, 1
    je .Lvsc_input_one
    mov rdi, [rsp + 32]
    mov rcx, [rsp + 40]
    jmp .Lvsc_input_span
.Lvsc_input_zero:
    mov rdi, [rsp]
    mov rcx, [rsp + 8]
    jmp .Lvsc_input_span
.Lvsc_input_one:
    mov rdi, [rsp + 16]
    mov rcx, [rsp + 24]
.Lvsc_input_span:
    mov rax, [r13 + 32]
    cmp rax, rcx
    ja .Lvsc_denied_span
    sub rcx, rax
    mov rsi, [r13 + 40]
    cmp rsi, rcx
    ja .Lvsc_denied_span
    cmp rsi, 8388608
    ja .Lvsc_denied_span
    add rdi, rax
    jc .Lvsc_denied_span
    mov [rsp + 72], rdi
    mov [rsp + 80], rsi
    mov rax, rdi
    add rax, rsi
    jc .Lvsc_denied_span
    mov rax, [r13 + 48]
    cmp rax, 1
    je .Lvsc_output_one
    cmp rax, 2
    jne .Lvsc_denied_span
    mov rdx, [rsp + 32]
    mov rcx, [rsp + 40]
    sub rcx, 256
    jmp .Lvsc_output_span
.Lvsc_output_one:
    mov rdx, [rsp + 16]
    mov rcx, [rsp + 24]
.Lvsc_output_span:
    mov rax, [r13 + 56]
    cmp rax, rcx
    ja .Lvsc_denied_span
    sub rcx, rax
    mov rbx, [r13 + 64]
    cmp rbx, rcx
    ja .Lvsc_denied_span
    mov rbp, [rsp + 112]
    cmp rbx, [rbp + 32]
    ja .Lvsc_denied_span
    add rdx, rax
    jc .Lvsc_denied_span
    mov [rsp + 88], rdx
    mov [rsp + 96], rbx
    mov rax, rdx
    add rax, rbx
    jc .Lvsc_denied_span
    mov rcx, rbx
    call .Lvsc_overlap
    test eax, eax
    jnz .Lvsc_denied_overlap
    mov rdi, [rsp + 72]
    mov rsi, [rsp + 80]
    mov rdx, [rbp + 8]
    mov rcx, [rbp + 16]
    test rdx, rdx
    jz .Lvsc_denied_span
    test rcx, rcx
    jz .Lvsc_denied_span
    mov rax, rdx
    add rax, rcx
    jc .Lvsc_denied_span
    call .Lvsc_overlap
    test eax, eax
    jnz .Lvsc_denied_overlap
    mov rdi, [rsp + 88]
    mov rsi, [rsp + 96]
    mov rdx, [rbp + 8]
    mov rcx, [rbp + 16]
    call .Lvsc_overlap
    test eax, eax
    jnz .Lvsc_denied_overlap
    /* The complete pending request must survive before an ACK exists. */
    lea rdi, [rsp + 176]
    mov rsi, r13
    mov ecx, 14
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
    cmp qword ptr [rsp + 64], 7
    jne .Lvsc_leaf
    mov rdi, [rsp + 72]
    mov rsi, [rsp + 80]
    mov edx, 7
    call view_scope_invoke_flat
    jmp .Lvsc_child_return
.Lvsc_leaf:
    /* Cache growth is a separate direct slot-8 operation. Its latest arena
     * is used here, while this parent's borrowed output remains fixed. */
    mov rdi, [rsp + 72]
    mov rsi, [rsp + 80]
    mov rdx, [rsp + 88]
    mov rcx, [rsp + 96]
    mov r8, [rbp + 8]
    mov r9, [rbp + 16]
    call qword ptr [rbp]
.Lvsc_child_return:
    mov rdx, [rsp + 120]
    mov [rbp + 24], rdx
    mov rdx, [rsp + 128]
    mov [rbp + 32], rdx
    mov rdx, rax
    shr rdx, 32
    jnz .Lvsc_resource
    mov [rbp + 40], rax
    cmp eax, 0xfffffffc
    je .Lvsc_resource
    cmp eax, 0xffff0000
    jb .Lvsc_child_length
    cmp eax, 0xfffffffd
    jb .Lvsc_resource
    jmp .Lvsc_child_checked
.Lvsc_child_length:
    cmp rax, [rsp + 96]
    ja .Lvsc_resource
.Lvsc_child_checked:
    mov [rsp + 144], rax
    mov rax, [r15 + 8]
    cmp rax, [rsp + 160]
    jne .Lvsc_resource
    mov rax, [r12]
    cmp rax, [rsp + 168]
    jne .Lvsc_resource
    mov rax, [r12 + 8]
    cmp rax, [rsp + 32]
    jne .Lvsc_resource
    mov rax, [r12 + 16]
    cmp rax, [rsp + 40]
    jne .Lvsc_resource
    mov rax, [r12 + 24]
    cmp rax, [rsp + 16]
    jne .Lvsc_resource
    mov rax, [r12 + 32]
    cmp rax, [rsp + 24]
    jne .Lvsc_resource
    lea rsi, [rsp + 176]
    mov rdi, r13
    mov ecx, 14
    cld
    repe cmpsq
    jne .Lvsc_resource
    xor ecx, ecx
    mov rax, [rsp + 144]
    jmp .Lvsc_ack
.Lvsc_denied_target:
    mov ecx, 1
    jmp .Lvsc_denied
.Lvsc_denied_active:
    mov ecx, 2
    jmp .Lvsc_denied
.Lvsc_denied_span:
    mov ecx, 3
    jmp .Lvsc_denied
.Lvsc_denied_overlap:
    mov ecx, 4
.Lvsc_denied:
    mov eax, 0xffffffff
.Lvsc_ack:
    mov [r13 + 80], rax
    mov rax, [rsp + 104]
    mov [r13 + 88], rax
    mov qword ptr [r13 + 96], 1
    mov [r13 + 104], rcx
    jmp .Lvsc_again
.Lvsc_resource:
    mov eax, 0xfffffffc
.Lvsc_done:
    mov [r12 + 40], rax
    mov qword ptr [r12 + 56], 0
    jmp .Lvsc_exit
.Lvsc_unowned_resource:
    mov eax, 0xfffffffc
.Lvsc_exit:
    add rsp, 312
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret
.size view_scope_invoke, .-view_scope_invoke

/* One for overlapping nonempty spans or wrapped endpoints. */
.Lvsc_overlap:
    xor eax, eax
    test rsi, rsi
    jz .Lvsc_overlap_done
    test rcx, rcx
    jz .Lvsc_overlap_done
    mov r8, rdi
    add r8, rsi
    jc .Lvsc_overlap_yes
    mov r9, rdx
    add r9, rcx
    jc .Lvsc_overlap_yes
    cmp rdi, r9
    jae .Lvsc_overlap_done
    cmp rdx, r8
    jae .Lvsc_overlap_done
.Lvsc_overlap_yes:
    mov eax, 1
.Lvsc_overlap_done:
    ret
.section .note.GNU-stack,"",@progbits
