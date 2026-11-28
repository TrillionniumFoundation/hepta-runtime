/* Copyright 2026 TrillionniumFoundation
 * SPDX-License-Identifier: Apache-2.0
 * Fixed adapter -> fixed HIA planner -> real parent connection.
 * Every request decision and file/cleanup decision remains in the HIA owners.
 */
.intel_syntax noprefix
.section .text
.equ C_MAGIC, 0x3130494357434248 /* HBCWCI01 */
.equ C_GROW, 0xffffffd0

/* callback, opaque, one actual process orphan pool, one entropy context. */
.global binary_write_composition_create
binary_write_composition_create:
    W_ENTER
    mov r13, rdi
    mov r14, rsi
    mov r15, rdx
    mov rbx, rcx
    call binary_parent_owner_create
    cmp rax, -4095
    jae .Lbc_create_return
    mov rbp, rax
    mov edi, 4096
    call .Lbw_map
    cmp rax, -4095
    jae .Lbc_create_parent_failed
    mov r12, rax
    mov rax, C_MAGIC
    mov [r12], rax
    mov qword ptr [r12+8], 4096
    lea rax, [rip+.Lbc_adapter]
    mov [r12+16], rax
    lea rax, [rip+.Lbc_planner]
    mov [r12+24], rax
    mov [r12+40], r13
    mov [r12+48], r14
    mov [r12+376], r15
    mov [r12+384], rbp
    mov [r12+408], rbx
    mov rax, [r15+16]
    mov [r12+480], rax
    xor ebx, ebx
.Lbc_create_pair:
    lea rax, [rip+.Lbc_pairs]
    mov rdi, [rax+rbx*8]
    add rdi, r12
    mov esi, 4096
    call .Lbw_grow
    test eax, eax
    jnz .Lbc_create_failed
    inc ebx
    cmp ebx, 7
    jb .Lbc_create_pair
    mov rax, r12
    jmp .Lbc_create_return
.Lbc_create_failed:
    mov rdi, r12
    call binary_write_composition_destroy
    mov rax, -12
    jmp .Lbc_create_return
.Lbc_create_parent_failed:
    mov rdi, rbp
    call binary_parent_owner_destroy
    mov rax, -12
.Lbc_create_return:
    W_LEAVE

/* Private pair offsets: immutable input, adapter workspace, held result,
 * actual-child reply, adapter output, planner workspace, planner output. */
.Lbc_pairs:
    .quad 64,88,104,120,512,528,544

/* A fixed image call with complete before/after journal spans. r12 is the
 * context. Slots 608/616/624 were set only by the two fixed entry labels.
 * Return rax = actual HIA return, rdx = zero or a private infrastructure error.
 * A mapping/observer error is never fabricated as a child HIA result. */
.Lbc_call_adapter:
    mov qword ptr [r12+560], 7
    mov qword ptr [r12+608], 88
    mov qword ptr [r12+616], 512
    mov qword ptr [r12+624], 16
    jmp .Lbc_call_hia
.Lbc_call_planner:
    mov qword ptr [r12+560], 8
    mov qword ptr [r12+608], 528
    mov qword ptr [r12+616], 544
    mov qword ptr [r12+624], 24
.Lbc_call_hia:
    W_ENTER
    mov qword ptr [r12+632], 0
.Lbc_hia_loop:
    inc qword ptr [r12+632]
    cmp qword ptr [r12+632], 12
    ja .Lbc_hia_bad
    inc qword ptr [r12+248]
    jz .Lbc_hia_bad
    mov rbx, [r12+616]
    mov rdi, [r12+rbx]
    mov rcx, [r12+rbx+8]
    shr rcx, 3
    mov rax, 0xa5a5a5a5a5a5a5a5
    rep stosq
    mov edx, 1
    mov rcx, [r12+200]
    mov r8, [r12+208]
    call .Lbw_emit
    test rax, rax
    jnz .Lbc_hia_bad
    mov rbx, [r12+608]
    mov edx, 10
    mov rcx, [r12+rbx]
    mov r8, [r12+rbx+8]
    call .Lbw_emit
    test rax, rax
    jnz .Lbc_hia_bad
    mov rbx, [r12+616]
    mov edx, 12
    mov rcx, [r12+rbx]
    mov r8, [r12+rbx+8]
    call .Lbw_emit
    test rax, rax
    jnz .Lbc_hia_bad
    mov rdi, [r12+200]
    mov rsi, [r12+208]
    mov rbx, [r12+616]
    mov rdx, [r12+rbx]
    mov rcx, [r12+rbx+8]
    mov rbx, [r12+608]
    mov r8, [r12+rbx]
    mov r9, [r12+rbx+8]
    mov rbx, [r12+624]
    call qword ptr [r12+rbx]
    mov [r12+176], rax
    mov rbx, [r12+616]
    mov edx, 2
    mov rcx, [r12+rbx]
    mov r8, [r12+rbx+8]
    call .Lbw_emit
    test rax, rax
    jnz .Lbc_hia_bad
    mov rbx, [r12+608]
    mov edx, 11
    mov rcx, [r12+rbx]
    mov r8, [r12+rbx+8]
    call .Lbw_emit
    test rax, rax
    jnz .Lbc_hia_bad
    mov rax, [r12+176]
    mov rdx, rax
    shr rdx, 32
    jnz .Lbc_hia_bad
    cmp eax, C_GROW
    jne .Lbc_hia_returned
    mov rbx, [r12+616]
    mov rbp, [r12+rbx]
    mov rax, 0x3230305357524748 /* HGRWS002 */
    cmp [rbp], rax
    jne .Lbc_hia_bad
    cmp qword ptr [rbp+24], 0
    jne .Lbc_hia_bad
    mov r13, [rbp+16]
    cmp qword ptr [rbp+8], 1
    je .Lbc_hia_work_growth
    cmp qword ptr [rbp+8], 2
    jne .Lbc_hia_bad
    cmp r13, W_MAX_OUT
    ja .Lbc_hia_bad
    jmp .Lbc_hia_grow
.Lbc_hia_work_growth:
    mov rbx, [r12+608]
    cmp r13, W_MAX_WORK
    ja .Lbc_hia_bad
.Lbc_hia_grow:
    cmp r13, [r12+rbx+8]
    jbe .Lbc_hia_bad
    lea rdi, [r12+rbx]
    mov rsi, r13
    call .Lbw_grow
    test eax, eax
    jnz .Lbc_hia_resource
    jmp .Lbc_hia_loop
.Lbc_hia_returned:
    xor edx, edx
    jmp .Lbc_hia_done
.Lbc_hia_resource:
    mov edx, W_RESOURCE
    mov rax, [r12+176]
    jmp .Lbc_hia_done
.Lbc_hia_bad:
    mov edx, W_INVALID
    mov rax, [r12+176]
.Lbc_hia_done:
    W_LEAVE

/* r12 composition context, rsi complete child bytes, rdx whole extent.
 * The child remains borrowed until the caller's explicit release. */
.Lbc_publish:
    W_ENTER
    mov r13, rsi
    mov r14, rdx
    cmp r14, 64
    jb .Lbc_publish_bad
    cmp r14, W_MAX_OUT
    ja .Lbc_publish_resource
    lea rdi, [r12+104]
    mov rsi, r14
    call .Lbw_grow
    test eax, eax
    jnz .Lbc_publish_resource
    mov rdi, [r12+104]
    mov rsi, r13
    mov rcx, r14
    rep movsb
    mov [r12+168], r14
    mov qword ptr [r12+56], 2
    mov eax, 64
    jmp .Lbc_publish_return
.Lbc_publish_bad:
    mov eax, W_INVALID
    jmp .Lbc_publish_return
.Lbc_publish_resource:
    mov eax, W_RESOURCE
.Lbc_publish_return:
    W_LEAVE

.global binary_write_composition_invoke
binary_write_composition_invoke:
    W_ENTER
    mov r12, rdi
    mov r13, rsi
    mov r14, rdx
    test r12, r12
    jz .Lbc_invoke_reject
    mov rax, C_MAGIC
    cmp [r12], rax
    jne .Lbc_invoke_reject
    cmp qword ptr [r12+8], 4096
    jne .Lbc_invoke_reject
    cmp qword ptr [r12+56], 0
    jne .Lbc_invoke_busy
    mov rax, [r12+568]
    or rax, [r12+576]
    jnz .Lbc_invoke_reject
    test r13, r13
    jz .Lbc_invoke_reject
    cmp r14, W_MAX_INPUT
    ja .Lbc_invoke_reject
    cmp qword ptr [r12+192], -1
    je .Lbc_invoke_reject
    mov eax, 39
    syscall
    cmp [r12+480], rax
    jne .Lbc_invoke_reject
    mov rbx, [r12+384]
    test rbx, rbx
    jz .Lbc_invoke_reject
    cmp [rbx+480], rax
    jne .Lbc_invoke_reject
    mov rax, 0x3130494357504248 /* HBPWCI01 */
    cmp [rbx], rax
    jne .Lbc_invoke_reject
    cmp qword ptr [rbx+8], 4096
    jne .Lbc_invoke_reject
    cmp qword ptr [rbx+56], 0
    jne .Lbc_invoke_busy
    mov rax, [r12+376]
    cmp [rbx+376], rax
    jne .Lbc_invoke_reject
    mov rax, [r12+408]
    cmp [rbx+408], rax
    jne .Lbc_invoke_reject
    cmp r14, [r12+72]
    jbe .Lbc_invoke_copy
    lea rdi, [r12+64]
    mov rsi, r14
    call .Lbw_grow
    test eax, eax
    jnz .Lbc_invoke_return
.Lbc_invoke_copy:
    mov rdi, [r12+64]
    mov rsi, r13
    mov rcx, r14
    rep movsb
    mov [r12+80], r14
    mov rax, [r12+64]
    mov [r12+200], rax
    mov [r12+208], r14
    inc qword ptr [r12+192]
    mov qword ptr [r12+56], 1
    mov qword ptr [r12+168], 0
    mov qword ptr [r12+640], 0
    call .Lbc_call_adapter
    test edx, edx
    jnz .Lbc_invoke_private
    cmp eax, W_INVALID
    je .Lbc_invoke_physical
    cmp eax, 0xfffffffe
    je .Lbc_invoke_physical
    cmp rax, 64
    jb .Lbc_invoke_bad
    cmp rax, [r12+520]
    ja .Lbc_invoke_bad
    mov rbp, [r12+512]
    mov rdx, 0x3130305241574248 /* HBWAR001 */
    cmp [rbp], rdx
    jne .Lbc_invoke_bad
    cmp qword ptr [rbp+8], 1
    jne .Lbc_invoke_bad
    mov rcx, [rbp+24]
    add rcx, 64
    jc .Lbc_invoke_bad
    cmp rcx, rax
    jne .Lbc_invoke_bad
    mov rdx, [rbp+32]
    or rdx, [rbp+40]
    or rdx, [rbp+48]
    or rdx, [rbp+56]
    jnz .Lbc_invoke_bad
    mov rax, [rbp+16]
    test rax, rax
    jz .Lbc_invoke_bad
    mov [r12+216], rax
    lea rax, [rbp+64]
    mov [r12+200], rax
    mov rax, [rbp+24]
    mov [r12+208], rax
    /* Every fixed planner call starts a fresh pure workspace generation. */
    mov rdi, [r12+528]
    mov rcx, [r12+536]
    shr rcx, 3
    xor eax, eax
    rep stosq
    inc qword ptr [r12+592]
    jz .Lbc_invoke_bad
    call .Lbc_call_planner
    test edx, edx
    jnz .Lbc_invoke_private
    mov [r12+232], rax
    xor ecx, ecx
    cmp eax, W_INVALID
    je .Lbc_invoke_planner_extent
    cmp rax, 64
    jb .Lbc_invoke_bad
    cmp rax, [r12+552]
    ja .Lbc_invoke_bad
    cmp rax, W_MAX_OUT
    ja .Lbc_invoke_bad
    mov rcx, rax
.Lbc_invoke_planner_extent:
    mov [r12+240], rcx
    lea rsi, [rcx+48]
    cmp rsi, W_MAX_INPUT
    ja .Lbc_invoke_resource
    lea rdi, [r12+120]
    call .Lbw_grow
    test eax, eax
    jnz .Lbc_invoke_resource
    mov rbp, [r12+120]
    mov rax, 0x3130305141574248 /* HBWAQ001 */
    mov [rbp], rax
    mov qword ptr [rbp+8], 2
    mov rax, [r12+216]
    mov [rbp+16], rax
    mov rax, [r12+232]
    mov [rbp+24], rax
    mov rcx, [r12+240]
    mov [rbp+32], rcx
    mov qword ptr [rbp+40], 0
    lea rdi, [rbp+48]
    mov rsi, [r12+544]
    rep movsb
    mov [r12+200], rbp
    mov rax, [r12+240]
    add rax, 48
    mov [r12+208], rax
    call .Lbc_call_adapter
    test edx, edx
    jnz .Lbc_invoke_private
    cmp rax, 64
    jb .Lbc_invoke_bad
    cmp rax, [r12+520]
    ja .Lbc_invoke_bad
    mov [r12+584], rax
    mov rbp, [r12+512]
    mov rdx, 0x3130305241574248
    cmp [rbp], rdx
    jne .Lbc_invoke_bad
    mov rcx, [rbp+24]
    add rcx, 64
    jc .Lbc_invoke_bad
    cmp rcx, rax
    jne .Lbc_invoke_bad
    mov rdx, [r12+216]
    cmp [rbp+16], rdx
    jne .Lbc_invoke_bad
    mov rdx, [rbp+40]
    or rdx, [rbp+48]
    or rdx, [rbp+56]
    jnz .Lbc_invoke_bad
    cmp qword ptr [rbp+8], 3
    je .Lbc_invoke_adapter_failure
    cmp qword ptr [rbp+8], 2
    jne .Lbc_invoke_bad
    cmp qword ptr [rbp+32], 0
    jne .Lbc_invoke_bad
    mov qword ptr [r12+576], 1
    mov rdi, [r12+384]
    lea rsi, [rbp+64]
    mov rdx, [rbp+24]
    call binary_parent_owner_invoke
    mov [r12+584], rax
    cmp rax, 64
    jne .Lbc_invoke_child_failure
    mov qword ptr [r12+568], 1
    mov rbx, [r12+384]
    cmp qword ptr [rbx+56], 2
    jne .Lbc_invoke_bad
    mov rsi, [rbx+104]
    mov rdx, [rbx+168]
    call .Lbc_publish
    cmp eax, 64
    jne .Lbc_invoke_publish_failure
    jmp .Lbc_invoke_return
.Lbc_invoke_adapter_failure:
    cmp qword ptr [rbp+32], 1
    je .Lbc_invoke_adapter_failure_ready
    cmp qword ptr [rbp+32], 2
    jne .Lbc_invoke_bad
.Lbc_invoke_adapter_failure_ready:
    mov qword ptr [r12+576], 1
    mov rsi, rbp
    mov rdx, [r12+584]
    call .Lbc_publish
    cmp eax, 64
    jne .Lbc_invoke_publish_failure
    jmp .Lbc_invoke_return
.Lbc_invoke_physical:
    mov qword ptr [r12+56], 0
    jmp .Lbc_invoke_return
.Lbc_invoke_child_failure:
.Lbc_invoke_publish_failure:
    mov edx, eax
    jmp .Lbc_invoke_private
.Lbc_invoke_resource:
    mov edx, W_RESOURCE
    jmp .Lbc_invoke_private
.Lbc_invoke_bad:
    mov edx, W_INVALID
.Lbc_invoke_private:
    mov [r12+640], rdx
    mov qword ptr [r12+56], 3
    mov eax, edx
    jmp .Lbc_invoke_return
.Lbc_invoke_busy:
    mov eax, W_BUSY
    jmp .Lbc_invoke_return
.Lbc_invoke_reject:
    mov eax, W_INVALID
.Lbc_invoke_return:
    W_LEAVE

.global binary_write_composition_release
binary_write_composition_release:
    W_ENTER
    mov r12, rdi
    test r12, r12
    jz .Lbc_release_bad
    mov rax, C_MAGIC
    cmp [r12], rax
    jne .Lbc_release_bad
    cmp qword ptr [r12+8], 4096
    jne .Lbc_release_bad
    cmp qword ptr [r12+56], 2
    jne .Lbc_release_bad
    cmp qword ptr [r12+576], 1
    jne .Lbc_release_bad
    mov eax, 39
    syscall
    cmp [r12+480], rax
    jne .Lbc_release_bad
    cmp qword ptr [r12+568], 0
    je .Lbc_release_adapter
    cmp qword ptr [r12+568], 1
    jne .Lbc_release_bad
    mov rdi, [r12+384]
    call binary_parent_owner_release
    test eax, eax
    jnz .Lbc_release_failed
    mov qword ptr [r12+568], 0
.Lbc_release_adapter:
    mov rbp, [r12+120]
    mov rax, 0x3130305141574248
    mov [rbp], rax
    mov qword ptr [rbp+8], 3
    mov rax, [r12+216]
    mov [rbp+16], rax
    mov qword ptr [rbp+24], 0
    mov qword ptr [rbp+32], 0
    mov qword ptr [rbp+40], 0
    mov [r12+200], rbp
    mov qword ptr [r12+208], 48
    call .Lbc_call_adapter
    test edx, edx
    jnz .Lbc_release_private
    cmp rax, 64
    jne .Lbc_release_invalid
    mov rbp, [r12+512]
    mov rax, 0x3130305241574248
    cmp [rbp], rax
    jne .Lbc_release_invalid
    mov rax, [r12+216]
    cmp [rbp+16], rax
    jne .Lbc_release_invalid
    mov rax, [rbp+8]
    or rax, [rbp+24]
    or rax, [rbp+32]
    or rax, [rbp+40]
    or rax, [rbp+48]
    or rax, [rbp+56]
    jnz .Lbc_release_invalid
    mov qword ptr [r12+576], 0
    mov qword ptr [r12+56], 0
    mov qword ptr [r12+168], 0
    mov qword ptr [r12+176], 0
    mov qword ptr [r12+640], 0
    xor eax, eax
    jmp .Lbc_release_return
.Lbc_release_invalid:
    mov edx, W_INVALID
    jmp .Lbc_release_private
.Lbc_release_failed:
    mov edx, eax
.Lbc_release_private:
    mov [r12+640], rdx
    mov qword ptr [r12+56], 3
    mov eax, edx
    jmp .Lbc_release_return
.Lbc_release_bad:
    mov eax, W_INVALID
.Lbc_release_return:
    W_LEAVE

.global binary_write_composition_destroy
binary_write_composition_destroy:
    W_ENTER
    mov r12, rdi
    test r12, r12
    jz .Lbc_destroy_bad
    mov rax, C_MAGIC
    cmp [r12], rax
    jne .Lbc_destroy_bad
    cmp qword ptr [r12+8], 4096
    jne .Lbc_destroy_bad
    mov eax, 39
    syscall
    cmp [r12+480], rax
    jne .Lbc_destroy_bad
    cmp qword ptr [r12+56], 0
    je .Lbc_destroy_state
    cmp qword ptr [r12+56], 3
    jne .Lbc_destroy_busy
.Lbc_destroy_state:
    mov rax, [r12+568]
    or rax, [r12+576]
    jnz .Lbc_destroy_busy
    mov rbx, [r12+88]
    test rbx, rbx
    jz .Lbc_destroy_parent
    cmp qword ptr [rbx], 0
    je .Lbc_destroy_parent
    mov rax, 0x3130305341574248 /* HBWAS001 */
    cmp [rbx], rax
    jne .Lbc_destroy_busy
    cmp qword ptr [rbx+8], 0
    jne .Lbc_destroy_busy
.Lbc_destroy_parent:
    mov rdi, [r12+384]
    test rdi, rdi
    jz .Lbc_destroy_pairs
    /* Parent's real ledger, second-close token and pending orphan decide. */
    call binary_parent_owner_destroy
    test eax, eax
    jnz .Lbc_destroy_return
    mov qword ptr [r12+384], 0
.Lbc_destroy_pairs:
    xor ebx, ebx
.Lbc_destroy_pair:
    lea rax, [rip+.Lbc_pairs]
    mov r13, [rax+rbx*8]
    mov rdi, [r12+r13]
    test rdi, rdi
    jz .Lbc_destroy_next
    mov rsi, [r12+r13+8]
    add rsi, 4096
    mov eax, 11
    syscall
    test rax, rax
    jnz .Lbc_destroy_resource
    mov qword ptr [r12+r13], 0
    mov qword ptr [r12+r13+8], 0
.Lbc_destroy_next:
    inc ebx
    cmp ebx, 7
    jb .Lbc_destroy_pair
    mov qword ptr [r12], 0
    mov rdi, r12
    mov esi, 8192
    mov eax, 11
    syscall
    test rax, rax
    jnz .Lbc_destroy_resource
    xor eax, eax
    jmp .Lbc_destroy_return
.Lbc_destroy_bad:
    mov eax, W_INVALID
    jmp .Lbc_destroy_return
.Lbc_destroy_busy:
    mov eax, W_BUSY
    jmp .Lbc_destroy_return
.Lbc_destroy_resource:
    mov eax, W_RESOURCE
.Lbc_destroy_return:
    W_LEAVE

.global binary_write_composition_adapter_call_displacement
.Lbc_adapter:
    .byte 0xe9
binary_write_composition_adapter_call_displacement:
    .long 0
.global binary_write_composition_planner_call_displacement
.Lbc_planner:
    .byte 0xe9
binary_write_composition_planner_call_displacement:
    .long 0
