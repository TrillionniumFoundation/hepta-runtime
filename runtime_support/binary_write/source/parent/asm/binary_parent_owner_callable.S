/* Copyright 2026 TrillionniumFoundation
 * SPDX-License-Identifier: Apache-2.0
 * Fixed private parent capabilities. Path policy, order, retry, cleanup and
 * child/final-close error precedence are exclusively in the HIA controller.
 * The byte-exact retained write boundary supplies mapping helpers and child.
 */
.intel_syntax noprefix
.section .text
.equ P_MAGIC, 0x3130494357504248 /* HBPWCI01 */

/* callback, opaque, the one process orphan pool, the one entropy context. */
.global binary_parent_owner_create
binary_parent_owner_create:
    W_ENTER
    mov r13, rdi
    mov r14, rsi
    mov r15, rdx
    mov rbx, rcx
    /* The unchanged child validates the pool, entropy context and creator PID. */
    call binary_write_body_create
    cmp rax, -4095
    jae .Lbp_create_return
    mov rbp, rax
    mov edi, 4096
    call .Lbw_map
    cmp rax, -4095
    jae .Lbp_create_child_failed
    mov r12, rax
    mov rax, P_MAGIC
    mov [r12], rax
    mov qword ptr [r12+8], 4096
    lea rax, [rip+.Lbp_body]
    mov [r12+16], rax
    mov [r12+40], r13
    mov [r12+48], r14
    mov [r12+376], r15
    mov [r12+384], rbp
    mov [r12+408], rbx
    mov rax, [r15+16]
    mov [r12+480], rax
    mov qword ptr [r12+256], -1 /* current actual opened descriptor */
    mov qword ptr [r12+264], -1 /* opened but not yet assigned child */
    lea rdi, [r12+88]
    mov esi, 4096
    call .Lbw_grow
    test eax, eax
    jnz .Lbp_create_failed
    lea rdi, [r12+104]
    mov esi, 4096
    call .Lbw_grow
    test eax, eax
    jnz .Lbp_create_failed
    lea rdi, [r12+120]
    mov esi, 4096
    call .Lbw_grow
    test eax, eax
    jnz .Lbp_create_failed
    mov rax, r12
    jmp .Lbp_create_return
.Lbp_create_failed:
    mov rdi, r12
    call binary_parent_owner_destroy
    mov rax, -12
    jmp .Lbp_create_return
.Lbp_create_child_failed:
    mov rdi, rbp
    call binary_write_body_destroy
    mov rax, -12
.Lbp_create_return:
    W_LEAVE

.global binary_parent_owner_release
binary_parent_owner_release:
    mov rax, P_MAGIC
    cmp [rdi], rax
    jne .Lbp_release_bad
    cmp qword ptr [rdi+8], 4096
    jne .Lbp_release_bad
    cmp qword ptr [rdi+56], 2
    jne .Lbp_release_bad
    cmp qword ptr [rdi+184], 0
    jne .Lbp_release_bad
    cmp qword ptr [rdi+256], -1
    jne .Lbp_release_bad
    cmp qword ptr [rdi+264], -1
    jne .Lbp_release_bad
    mov rax, [rdi+272]
    or rax, [rdi+280]
    jnz .Lbp_release_bad
    mov qword ptr [rdi+56], 0
    mov qword ptr [rdi+168], 0
    mov qword ptr [rdi+176], 0
    xor eax, eax
    ret
.Lbp_release_bad:
    mov eax, W_INVALID
    ret

.global binary_parent_owner_destroy
binary_parent_owner_destroy:
    W_ENTER
    mov r12, rdi
    test r12, r12
    jz .Lbp_destroy_bad
    mov rax, P_MAGIC
    cmp [r12], rax
    jne .Lbp_destroy_bad
    cmp qword ptr [r12+8], 4096
    jne .Lbp_destroy_bad
    cmp qword ptr [r12+56], 0
    je .Lbp_destroy_state_ok
    cmp qword ptr [r12+56], 3
    jne .Lbp_destroy_busy
.Lbp_destroy_state_ok:
    /* A private failure never invents target cleanup. An unresolved token
     * requires process exit; destroy cannot silently close or reuse it. */
    cmp qword ptr [r12+184], 0
    jne .Lbp_destroy_busy
    cmp qword ptr [r12+256], -1
    jne .Lbp_destroy_busy
    cmp qword ptr [r12+264], -1
    jne .Lbp_destroy_busy
    mov rax, [r12+272]
    or rax, [r12+280]
    jnz .Lbp_destroy_busy
    mov rdi, [r12+384]
    test rdi, rdi
    jz .Lbp_destroy_pairs
    call binary_write_body_destroy
    test rax, rax
    jnz .Lbp_destroy_return
    mov qword ptr [r12+384], 0
.Lbp_destroy_pairs:
    xor ebx, ebx
.Lbp_destroy_pair:
    lea rax, [rip+.Lbp_pairs]
    mov r13, [rax+rbx*8]
    mov rdi, [r12+r13]
    test rdi, rdi
    jz .Lbp_destroy_next
    mov rsi, [r12+r13+8]
    add rsi, 4096
    mov eax, 11
    syscall
    test rax, rax
    jnz .Lbp_destroy_resource
    mov qword ptr [r12+r13], 0
    mov qword ptr [r12+r13+8], 0
.Lbp_destroy_next:
    inc ebx
    cmp ebx, 4
    jb .Lbp_destroy_pair
    mov qword ptr [r12], 0
    mov rdi, r12
    mov esi, 8192
    mov eax, 11
    syscall
    test rax, rax
    jnz .Lbp_destroy_resource
    xor eax, eax
    jmp .Lbp_destroy_return
.Lbp_destroy_bad:
    mov eax, W_INVALID
    jmp .Lbp_destroy_return
.Lbp_destroy_busy:
    mov eax, W_BUSY
    jmp .Lbp_destroy_return
.Lbp_destroy_resource:
    mov eax, W_RESOURCE
.Lbp_destroy_return:
    W_LEAVE
.Lbp_pairs:
    .quad 64,88,104,120

/* HIA output packet is at rbp; r12 is the admitted private context. */
.Lbp_capability:
    W_ENTER
    mov qword ptr [r12+240], 0
    mov rbx, [rbp+24]
    cmp qword ptr [rbp+48], 0
    jne .Lbp_cap_bad
    cmp rbx, 1
    je .Lbp_cap_root
    mov rax, [rbp+32]
    cmp rbx, 4
    je .Lbp_cap_orphan
    cmp rax, [r12+256]
    jne .Lbp_cap_bad
    cmp rax, 2147483647
    ja .Lbp_cap_bad
    cmp rbx, 2
    je .Lbp_cap_child
    cmp rbx, 3
    je .Lbp_cap_close
    jmp .Lbp_cap_bad
.Lbp_cap_root:
    cmp qword ptr [r12+184], 0
    jne .Lbp_cap_bad
    cmp qword ptr [r12+256], -1
    jne .Lbp_cap_bad
    cmp qword ptr [r12+264], -1
    jne .Lbp_cap_bad
    cmp qword ptr [rbp+32], 0
    jne .Lbp_cap_bad
    cmp qword ptr [rbp+40], 720896
    jne .Lbp_cap_bad
    cmp qword ptr [rbp+56], 2
    jne .Lbp_cap_bad
    cmp word ptr [rbp+64], 47
    jne .Lbp_cap_bad
    mov rax, [r12+88]
    cmp qword ptr [rax+8], 2
    jne .Lbp_cap_bad
    mov edi, -100
    lea rsi, [rbp+64]
    mov edx, 720896
    xor r10d, r10d /* actual original glibc openat mode without O_CREAT */
    mov eax, 257
    syscall
    mov [r12+232], rax
    cmp rax, -4095
    jae .Lbp_cap_ok
    cmp rax, 2147483647
    ja .Lbp_cap_bad
    mov [r12+256], rax
    mov qword ptr [r12+184], 1
    jmp .Lbp_cap_ok
.Lbp_cap_child:
    cmp qword ptr [r12+184], 1
    jne .Lbp_cap_bad
    cmp qword ptr [r12+264], -1
    jne .Lbp_cap_bad
    cmp qword ptr [r12+272], 0
    jne .Lbp_cap_bad
    cmp qword ptr [r12+280], 0
    jne .Lbp_cap_bad
    cmp qword ptr [rbp+40], 720896
    jne .Lbp_cap_bad
    mov rax, [r12+88]
    cmp qword ptr [rax+8], 4
    jne .Lbp_cap_bad
    mov rcx, [rax+264]
    test rcx, rcx
    jz .Lbp_cap_bad
    lea rdx, [rcx+1]
    cmp [rbp+56], rdx
    jne .Lbp_cap_bad
    mov rsi, [rax+112]
    add rsi, [rax+256]
    add rsi, rax
    lea rdi, [rbp+64]
    repe cmpsb
    jne .Lbp_cap_bad
    lea rdi, [rbp+64]
    mov rsi, [rbp+56]
    call .Lbw_name
    test eax, eax
    jnz .Lbp_cap_bad
    mov rdi, [r12+256]
    lea rsi, [rbp+64]
    mov edx, 720896
    xor r10d, r10d
    mov eax, 257
    syscall
    mov [r12+232], rax
    cmp rax, -4095
    jae .Lbp_cap_ok
    cmp rax, 2147483647
    ja .Lbp_cap_bad
    mov [r12+264], rax
    mov qword ptr [r12+184], 2
    jmp .Lbp_cap_ok
.Lbp_cap_close:
    cmp qword ptr [rbp+56], 0
    jne .Lbp_cap_bad
    cmp qword ptr [r12+280], 0
    jne .Lbp_cap_bad
    cmp qword ptr [rbp+40], 1
    je .Lbp_cap_second_close
    cmp qword ptr [rbp+40], 0
    jne .Lbp_cap_bad
    cmp qword ptr [r12+272], 0
    jne .Lbp_cap_bad
    mov rax, [r12+88]
    mov rax, [rax+8]
    cmp qword ptr [r12+264], -1
    je .Lbp_cap_final_close
    cmp qword ptr [r12+184], 2
    jne .Lbp_cap_bad
    cmp rax, 5
    jne .Lbp_cap_bad
    mov rdi, [r12+256]
    mov eax, 3
    syscall
    mov [r12+232], rax
    test rax, rax
    jnz .Lbp_cap_close_failed
    mov rax, [r12+264]
    mov [r12+256], rax
    mov qword ptr [r12+264], -1
    dec qword ptr [r12+184]
    jmp .Lbp_cap_ok
.Lbp_cap_close_failed:
    mov qword ptr [r12+272], 1
    jmp .Lbp_cap_ok
.Lbp_cap_final_close:
    cmp qword ptr [r12+184], 1
    jne .Lbp_cap_bad
    cmp rax, 9
    je .Lbp_cap_final_perform
    cmp rax, 91
    jne .Lbp_cap_bad
.Lbp_cap_final_perform:
    mov rdi, [r12+256]
    mov eax, 3
    syscall
    mov [r12+232], rax
    mov qword ptr [r12+256], -1
    mov qword ptr [r12+184], 0
    jmp .Lbp_cap_ok
.Lbp_cap_second_close:
    cmp qword ptr [r12+272], 1
    jne .Lbp_cap_bad
    cmp qword ptr [r12+184], 2
    jne .Lbp_cap_bad
    cmp qword ptr [r12+264], -1
    je .Lbp_cap_bad
    mov rax, [r12+88]
    cmp qword ptr [rax+8], 6
    jne .Lbp_cap_bad
    /* This is exactly the old numeric FD, not the opened unassigned child. */
    mov rdi, [r12+256]
    mov eax, 3
    syscall
    mov [r12+232], rax
    mov qword ptr [r12+256], -1
    mov qword ptr [r12+272], 0
    mov qword ptr [r12+280], 1
    dec qword ptr [r12+184]
    jmp .Lbp_cap_ok
.Lbp_cap_orphan:
    cmp [r12+264], rax
    jne .Lbp_cap_bad
    cmp rax, 2147483647
    ja .Lbp_cap_bad
    cmp qword ptr [r12+256], -1
    jne .Lbp_cap_bad
    cmp qword ptr [r12+272], 0
    jne .Lbp_cap_bad
    cmp qword ptr [r12+280], 1
    jne .Lbp_cap_bad
    cmp qword ptr [r12+184], 1
    jne .Lbp_cap_bad
    mov rdx, [rbp+40]
    or rdx, [rbp+56]
    jnz .Lbp_cap_bad
    mov rdx, [r12+88]
    cmp qword ptr [rdx+8], 7
    jne .Lbp_cap_bad
    cmp qword ptr [r12+400], -1
    je .Lbp_cap_resource
    mov rdi, [r12+376]
    mov rsi, rax
    mov rdx, r12
    mov rcx, [r12+192]
    call hia_process_orphans_append
    test rax, rax
    jnz .Lbp_cap_resource
    mov [r12+232], rax
    mov qword ptr [r12+264], -1
    mov qword ptr [r12+280], 0
    mov qword ptr [r12+184], 0
    inc qword ptr [r12+400]
.Lbp_cap_ok:
    xor eax, eax
    jmp .Lbp_cap_return
.Lbp_cap_bad:
    mov eax, W_INVALID
    jmp .Lbp_cap_return
.Lbp_cap_resource:
    mov eax, W_RESOURCE
.Lbp_cap_return:
    W_LEAVE

/* rdi admitted context, rsi immutable HBPWQ001 request, rdx full extent.
 * No public/request FD or caller-chosen child entry exists. */
.global binary_parent_owner_invoke
binary_parent_owner_invoke:
    W_ENTER
    mov r12, rdi
    mov r13, rsi
    mov r14, rdx
    test r12, r12
    jz .Lbp_invoke_reject
    mov rax, P_MAGIC
    cmp [r12], rax
    jne .Lbp_invoke_reject
    cmp qword ptr [r12+8], 4096
    jne .Lbp_invoke_reject
    cmp qword ptr [r12+56], 0
    jne .Lbp_invoke_busy
    cmp qword ptr [r12+184], 0
    jne .Lbp_invoke_reject
    cmp qword ptr [r12+256], -1
    jne .Lbp_invoke_reject
    cmp qword ptr [r12+264], -1
    jne .Lbp_invoke_reject
    mov rax, [r12+272]
    or rax, [r12+280]
    jnz .Lbp_invoke_reject
    test r13, r13
    jz .Lbp_invoke_reject
    cmp r14, 96
    jb .Lbp_invoke_reject
    cmp r14, W_MAX_INPUT
    ja .Lbp_invoke_reject
    mov rax, 0x3130305157504248 /* HBPWQ001 */
    cmp [r13], rax
    jne .Lbp_invoke_reject
    cmp qword ptr [r13+8], 1
    jne .Lbp_invoke_reject
    cmp qword ptr [r13+24], 1
    jne .Lbp_invoke_reject
    mov rax, [r13+16]
    or rax, [r13+72]
    or rax, [r13+80]
    jnz .Lbp_invoke_reject
    mov rax, r14
    sub rax, 96
    cmp [r13+88], rax
    jne .Lbp_invoke_reject
    cmp [r13+32], rax
    ja .Lbp_invoke_reject
    sub rax, [r13+32]
    cmp [r13+40], rax
    ja .Lbp_invoke_reject
    sub rax, [r13+40]
    cmp [r13+48], rax
    ja .Lbp_invoke_reject
    sub rax, [r13+48]
    cmp [r13+56], rax
    jne .Lbp_invoke_reject
    cmp qword ptr [r13+64], 1
    ja .Lbp_invoke_reject
    cmp qword ptr [r13+64], 0
    jne .Lbp_invoke_prior_ok
    cmp qword ptr [r13+48], 0
    jne .Lbp_invoke_reject
.Lbp_invoke_prior_ok:
    cmp qword ptr [r12+192], -1
    je .Lbp_invoke_reject
    mov eax, 39
    syscall
    cmp [r12+480], rax
    jne .Lbp_invoke_reject
    mov rbx, [r12+384]
    cmp qword ptr [rbx+56], 0
    jne .Lbp_invoke_reject
    mov rbx, [r12+408]
    cmp qword ptr [rbx+56], 0
    jne .Lbp_invoke_reject
    lea rdi, [r12+64]
    mov rsi, r14
    call .Lbw_grow
    test eax, eax
    jnz .Lbp_invoke_return
    mov rdi, [r12+64]
    mov rsi, r13
    mov rcx, r14
    rep movsb
    mov [r12+80], r14
    mov rax, [r12+64]
    mov [r12+200], rax
    mov [r12+208], r14
    inc qword ptr [r12+192]
    mov qword ptr [r12+248], 0
    mov qword ptr [r12+56], 1
    mov qword ptr [r12+168], 0
    mov qword ptr [r12+176], 0
.Lbp_invoke_loop:
    inc qword ptr [r12+248]
    jz .Lbp_invoke_failed
    mov rdi, [r12+104]
    mov rcx, [r12+112]
    shr rcx, 3
    mov rax, 0xa5a5a5a5a5a5a5a5
    rep stosq
    mov edx, 1
    mov rcx, [r12+200]
    mov r8, [r12+208]
    call .Lbw_emit
    test rax, rax
    jnz .Lbp_invoke_failed
    mov edx, 10
    mov rcx, [r12+88]
    mov r8, [r12+96]
    call .Lbw_emit
    test rax, rax
    jnz .Lbp_invoke_failed
    mov edx, 12
    mov rcx, [r12+104]
    mov r8, [r12+112]
    call .Lbw_emit
    test rax, rax
    jnz .Lbp_invoke_failed
    mov rdi, [r12+200]
    mov rsi, [r12+208]
    mov rdx, [r12+104]
    mov rcx, [r12+112]
    mov r8, [r12+88]
    mov r9, [r12+96]
    call qword ptr [r12+16]
    mov [r12+176], rax
    mov edx, 2
    mov rcx, [r12+104]
    mov r8, [r12+112]
    call .Lbw_emit
    test rax, rax
    jnz .Lbp_invoke_failed
    mov edx, 11
    mov rcx, [r12+88]
    mov r8, [r12+96]
    call .Lbw_emit
    test rax, rax
    jnz .Lbp_invoke_failed
    cmp qword ptr [r12+176], 64
    jne .Lbp_invoke_failed
    mov rbp, [r12+104]
    mov rax, 0x3130305257504248 /* HBPWR001 */
    cmp [rbp], rax
    jne .Lbp_invoke_failed
    mov rax, [r12+112]
    sub rax, 64
    cmp [rbp+56], rax
    ja .Lbp_invoke_failed
    mov rbx, [rbp+8]
    cmp rbx, 5
    ja .Lbp_invoke_failed
    test rbx, rbx
    jz .Lbp_invoke_final
    cmp rbx, 3
    je .Lbp_invoke_final
    cmp rbx, 4
    jae .Lbp_invoke_growth
    mov rax, [rbp+16]
    mov [r12+216], rax
    mov rax, [rbp+24]
    mov [r12+224], rax
    cmp rbx, 2
    je .Lbp_invoke_child
    mov edx, 8
    mov rcx, rbp
    mov r8, [rbp+56]
    add r8, 64
    call .Lbw_emit
    test rax, rax
    jnz .Lbp_invoke_failed
    call .Lbp_capability
    cmp eax, W_RESOURCE
    je .Lbp_invoke_resource
    test eax, eax
    jnz .Lbp_invoke_failed
    jmp .Lbp_invoke_reply
.Lbp_invoke_child:
    cmp qword ptr [rbp+24], 1
    jne .Lbp_invoke_failed
    mov rax, [rbp+32]
    cmp rax, [r12+256]
    jne .Lbp_invoke_failed
    cmp rax, 2147483647
    ja .Lbp_invoke_failed
    mov rax, [rbp+40]
    or rax, [rbp+48]
    or rax, [r12+272]
    or rax, [r12+280]
    jnz .Lbp_invoke_failed
    cmp qword ptr [r12+264], -1
    jne .Lbp_invoke_failed
    cmp qword ptr [r12+184], 1
    jne .Lbp_invoke_failed
    mov rax, [r12+88]
    cmp qword ptr [rax+8], 8
    jne .Lbp_invoke_failed
    mov edx, 5
    mov rcx, rbp
    mov r8, [rbp+56]
    add r8, 64
    call .Lbw_emit
    test rax, rax
    jnz .Lbp_invoke_failed
    mov rdi, [r12+384]
    mov rsi, [r12+256]
    lea rdx, [rbp+64]
    mov rcx, [rbp+56]
    call binary_write_body_invoke
    cmp rax, 64
    jne .Lbp_invoke_child_failed
    mov rbx, [r12+384]
    mov r13, [rbx+168]
    cmp r13, 64
    jb .Lbp_invoke_child_failed
    cmp r13, W_MAX_OUT-96
    ja .Lbp_invoke_child_resource
    lea rdi, [r12+120]
    lea rsi, [r13+96]
    call .Lbw_grow
    test eax, eax
    jnz .Lbp_invoke_child_resource
    mov rdi, [r12+120]
    add rdi, 96
    mov rsi, [rbx+104]
    mov rcx, r13
    rep movsb
    mov qword ptr [r12+232], 64
    mov [r12+240], r13
    mov edx, 6
    mov rcx, rbx
    mov r8d, 4096
    call .Lbw_emit
    test rax, rax
    jnz .Lbp_invoke_child_failed
    mov rdi, rbx
    call binary_write_body_release
    test eax, eax
    jnz .Lbp_invoke_failed
    jmp .Lbp_invoke_reply
.Lbp_invoke_child_resource:
    mov r13d, W_RESOURCE
    jmp .Lbp_child_release_failed
.Lbp_invoke_child_failed:
    mov r13d, W_INVALID
.Lbp_child_release_failed:
    mov rdi, [r12+384]
    cmp qword ptr [rdi+56], 2
    jne .Lbp_child_failure_record
    call binary_write_body_release
.Lbp_child_failure_record:
    mov eax, r13d
    jmp .Lbp_invoke_record_failure
.Lbp_invoke_reply:
    mov rbx, [r12+120]
    mov rax, 0x3130305157504248
    mov [rbx], rax
    mov qword ptr [rbx+8], 2
    mov rax, [r12+216]
    mov [rbx+16], rax
    mov rax, [r12+232]
    mov [rbx+24], rax
    mov qword ptr [rbx+32], 0
    mov qword ptr [rbx+40], 0
    mov qword ptr [rbx+48], 0
    mov qword ptr [rbx+56], 0
    mov qword ptr [rbx+64], 0
    mov qword ptr [rbx+72], 0
    mov qword ptr [rbx+80], 0
    mov rax, [r12+240]
    mov [rbx+88], rax
    add rax, 96
    cmp rax, [r12+128]
    ja .Lbp_invoke_failed
    mov [r12+200], rbx
    mov [r12+208], rax
    mov edx, 9
    mov rcx, rbx
    mov r8, rax
    call .Lbw_emit
    test rax, rax
    jnz .Lbp_invoke_failed
    jmp .Lbp_invoke_loop
.Lbp_invoke_growth:
    mov rax, [rbp+16]
    or rax, [rbp+24]
    or rax, [rbp+40]
    or rax, [rbp+48]
    or rax, [rbp+56]
    jnz .Lbp_invoke_failed
    mov r13, [rbp+32]
    cmp rbx, 4
    jne .Lbp_invoke_output_growth
    cmp r13, [r12+96]
    jbe .Lbp_invoke_failed
    cmp r13, W_MAX_WORK
    ja .Lbp_invoke_failed
    mov edx, 3
    mov rcx, [r12+88]
    mov r8, [r12+96]
    call .Lbw_emit
    test rax, rax
    jnz .Lbp_invoke_failed
    lea rdi, [r12+88]
    mov rsi, r13
    call .Lbw_grow
    test eax, eax
    jnz .Lbp_invoke_resource
    mov edx, 4
    mov rcx, [r12+88]
    mov r8, [r12+96]
    call .Lbw_emit
    test rax, rax
    jnz .Lbp_invoke_failed
    jmp .Lbp_invoke_loop
.Lbp_invoke_output_growth:
    cmp r13, [r12+112]
    jbe .Lbp_invoke_failed
    cmp r13, W_MAX_OUT
    ja .Lbp_invoke_failed
    lea rdi, [r12+104]
    mov rsi, r13
    call .Lbw_grow
    test eax, eax
    jnz .Lbp_invoke_resource
    jmp .Lbp_invoke_loop
.Lbp_invoke_final:
    cmp qword ptr [r12+184], 0
    jne .Lbp_invoke_failed
    cmp qword ptr [r12+256], -1
    jne .Lbp_invoke_failed
    cmp qword ptr [r12+264], -1
    jne .Lbp_invoke_failed
    mov rax, [rbp+24]
    or rax, [rbp+32]
    or rax, [rbp+40]
    or rax, [rbp+48]
    or rax, [r12+272]
    or rax, [r12+280]
    jnz .Lbp_invoke_failed
    cmp qword ptr [rbp+8], 3
    jne .Lbp_invoke_borrow
    cmp qword ptr [rbp+56], 64
    jb .Lbp_invoke_failed
    mov rax, 0x3130305344524248
    cmp [rbp+64], rax
    je .Lbp_invoke_error_magic
    mov rax, 0x3130305253444d48
    cmp [rbp+64], rax
    je .Lbp_invoke_error_magic
    mov rax, 0x3130305245534f48
    cmp [rbp+64], rax
    jne .Lbp_invoke_failed
.Lbp_invoke_error_magic:
    cmp qword ptr [rbp+72], 3
    jne .Lbp_invoke_failed
    mov rax, [rbp+56]
    sub rax, 64
    cmp [rbp+120], rax
    jne .Lbp_invoke_failed
.Lbp_invoke_borrow:
    mov rax, [rbp+56]
    add rax, 64
    mov [r12+168], rax
    mov qword ptr [r12+56], 2
    mov eax, 64
    jmp .Lbp_invoke_return
.Lbp_invoke_resource:
    mov eax, W_RESOURCE
    jmp .Lbp_invoke_record_failure
.Lbp_invoke_failed:
    mov eax, W_INVALID
.Lbp_invoke_record_failure:
    mov [r12+176], rax
    mov qword ptr [r12+168], 0
    mov qword ptr [r12+56], 3
    jmp .Lbp_invoke_return
.Lbp_invoke_busy:
    mov eax, W_BUSY
    jmp .Lbp_invoke_return
.Lbp_invoke_reject:
    mov eax, W_INVALID
.Lbp_invoke_return:
    W_LEAVE

.balign 16
.global binary_parent_owner_body_call_displacement
.Lbp_body:
    .byte 0xe9
binary_parent_owner_body_call_displacement:
    .long 0
.section .note.GNU-stack,"",@progbits
