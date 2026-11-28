/* Copyright 2026 TrillionniumFoundation
 * SPDX-License-Identifier: Apache-2.0
 * Fixed Linux x86-64 storage/effect boundary for the HIA jobs audit owner.
 * HIA selects all filesystem policy, append ordering, retry and namespace
 * decisions. This boundary admits byte spans, owns descriptors and dispatches
 * only the twenty-two declared effects and five fixed HIA entries. */
.intel_syntax noprefix
.section .text
.equ JA_BYTES, 16384
.equ JA_OWNER, 8
.equ JA_CANONICAL, 16
.equ JA_SHA, 24
.equ JA_NAMESPACE, 32
.equ JA_ERRNO, 40
.equ JA_SECURE, 48
.equ JA_PID, 56
.equ JA_LOCK, 64
.equ JA_TID, 72
.equ JA_INPUT, 80
.equ JA_INPUT_CAP, 88
.equ JA_INPUT_LENGTH, 96
.equ JA_WORK, 104
.equ JA_WORK_CAP, 112
.equ JA_OUTPUT, 120
.equ JA_OUTPUT_CAP, 128
.equ JA_EXTENT, 136
.equ JA_SEQUENCE, 144
.equ JA_NEXT_HANDLE, 152
.equ JA_LIVE, 160
.equ JA_POISON, 168
.equ JA_NATIVE_ERRNO, 176
.equ JA_ACTIVE_ENTRY, 184
.equ JA_CANONICAL_PENDING, 192
.equ JA_SHA_WORK, 200
.equ JA_NAMESPACE_ACTIVE, 216
.equ JA_FRAME_STACK, 224
.equ JA_ERRNO_WORK, 232
.equ JA_PURE_OUTPUT, 248
.equ JA_NATIVE_RETURN, 264
.equ JA_CANONICAL_CONTEXT, 512
.equ JA_REGISTRY, 4096
.equ JA_HANDLES, 512
.equ JA_FAULT, 0xfffffff9
.equ JA_RESOURCE, 0xfffffffc

.macro JA_SAVE
    push rbp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub rsp, 8
.endm
.macro JA_RETURN
    add rsp, 8
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret
.endm
.macro JA_ZEROS offset,count
    lea rax, [r14 + \offset]
    mov ecx, \count
.Lja_zero_\@:
    cmp qword ptr [rax], 0
    jne ja_invoke_bad
    add rax, 8
    dec ecx
    jnz .Lja_zero_\@
.endm
.macro JA_U32 offset
    mov rax, [r14 + \offset]
    mov edx, eax
    cmp rax, rdx
    jne ja_invoke_bad
.endm

/* Guarded anonymous storage. All capacities are checked page multiples. */
jobs_audit_map:
    JA_SAVE
    mov r12, rdi
    test r12, r12
    jz ja_map_invalid
    test r12, 4095
    jnz ja_map_invalid
    lea rsi, [r12 + 4096]
    cmp rsi, r12
    jbe ja_map_invalid
    test rsi, rsi
    js ja_map_invalid
    xor edi, edi
    mov edx, 3
    mov r10d, 0x22
    mov r8, -1
    xor r9d, r9d
    mov eax, 9
    syscall
    cmp rax, -4095
    jae ja_map_done
    mov r13, rax
    lea rdi, [rax + r12]
    mov esi, 4096
    xor edx, edx
    mov eax, 10
    syscall
    test rax, rax
    jnz ja_map_guard_failed
    mov rax, r13
    jmp ja_map_done
ja_map_guard_failed:
    mov rbp, rax
    mov rdi, r13
    lea rsi, [r12 + 4096]
    mov eax, 11
    syscall
    mov rax, rbp
    jmp ja_map_done
ja_map_invalid:
    mov rax, -12
ja_map_done:
    JA_RETURN

/* rdi points to an owned pointer/capacity pair, rsi is the required extent.
 * mremap updates ownership before either protection syscall can fail, so a
 * later fault can still destroy the complete actual mapping. */
jobs_audit_grow:
    JA_SAVE
    mov r12, rdi
    cmp rsi, [r12 + 8]
    jbe ja_grow_ok
    mov r13, rsi
    add r13, 4095
    jc ja_grow_overflow
    and r13, -4096
    test r13, r13
    jle ja_grow_overflow
    mov rax, 0x7fffffffffffe000
    cmp r13, rax
    ja ja_grow_overflow
    mov rdi, [r12]
    test rdi, rdi
    jz ja_grow_first
    mov rsi, [r12 + 8]
    add rsi, 4096
    jc ja_grow_overflow
    /* mremap requires one compatible VMA. Temporarily admit the old guard
     * under the exclusive lease, then restore a guard on either outcome. */
    mov edx, 3
    mov eax, 10
    syscall
    test rax, rax
    jnz ja_grow_done
    mov rdi, [r12]
    mov rsi, [r12 + 8]
    add rsi, 4096
    lea rdx, [r13 + 4096]
    mov r10d, 1
    xor r8d, r8d
    mov eax, 25
    syscall
    cmp rax, -4095
    jae ja_grow_remap_failed
    mov [r12], rax
    mov [r12 + 8], r13
    mov rdi, rax
    mov rsi, r13
    mov edx, 3
    mov eax, 10
    syscall
    test rax, rax
    jnz ja_grow_done
    mov rdi, [r12]
    add rdi, r13
    mov esi, 4096
    xor edx, edx
    mov eax, 10
    syscall
    jmp ja_grow_done
ja_grow_remap_failed:
    mov rbp, rax
    mov rdi, [r12]
    add rdi, [r12 + 8]
    mov esi, 4096
    xor edx, edx
    mov eax, 10
    syscall
    test rax, rax
    cmovz rax, rbp
    jmp ja_grow_done
ja_grow_first:
    cmp qword ptr [r12 + 8], 0
    jne ja_grow_overflow
    mov rdi, r13
    call jobs_audit_map
    cmp rax, -4095
    jae ja_grow_done
    mov [r12], rax
    mov [r12 + 8], r13
ja_grow_ok:
    xor eax, eax
    jmp ja_grow_done
ja_grow_overflow:
    mov rax, -12
ja_grow_done:
    JA_RETURN

/* Validate the process owner without importing any external descriptor. */
ja_context:
    test rdi, rdi
    jz ja_context_invalid
    mov rax, 0x3130544355414a48 /* HJAUCT01 */
    cmp [rdi], rax
    jne ja_context_invalid
    mov eax, 39
    syscall
    cmp [rdi + JA_PID], rax
    jne ja_context_invalid
    xor eax, eax
    ret
ja_context_invalid:
    mov rax, -22
    ret

.global jobs_audit_create
jobs_audit_create:
    JA_SAVE
    sub rsp, 48
    mov [rsp], rdi
    mov [rsp + 8], rsi
    mov [rsp + 16], rdx
    mov [rsp + 24], rcx
    mov [rsp + 32], r8
    mov [rsp + 40], r9
    test rdi, rdi
    jz ja_create_invalid
    test rsi, rsi
    jz ja_create_invalid
    test rdx, rdx
    jz ja_create_invalid
    test rcx, rcx
    jz ja_create_invalid
    test r8, r8
    jz ja_create_invalid
    cmp r9, 1
    ja ja_create_invalid
    mov edi, JA_BYTES
    call jobs_audit_map
    cmp rax, -4095
    jae ja_create_done
    mov r15, rax
    mov rax, 0x3130544355414a48
    mov [r15], rax
    lea rdi, [r15 + JA_OWNER]
    mov rsi, rsp
    mov ecx, 6
    cld
    rep movsq
    mov eax, 39
    syscall
    mov [r15 + JA_PID], rax
    mov rax, [r15 + JA_CANONICAL]
    mov [r15 + JA_CANONICAL_CONTEXT + 128], rax
    mov rax, [r15 + JA_SECURE]
    mov [r15 + JA_CANONICAL_CONTEXT + 64], rax
    mov qword ptr [r15 + JA_CANONICAL_CONTEXT + 72], -1
    mov qword ptr [r15 + JA_CANONICAL_CONTEXT + 80], -1
    mov rax, r15
    jmp ja_create_done
ja_create_invalid:
    mov rax, -22
ja_create_done:
    add rsp, 48
    JA_RETURN

/* A different thread waits for the existing lease. Reentrant invocation by
 * the lease's own thread refuses instead of replacing its borrowed result. */
ja_acquire:
    mov eax, 186
    syscall
    mov rbp, rax
ja_acquire_again:
    xor eax, eax
    mov edx, 1
    lock cmpxchg qword ptr [r15 + JA_LOCK], rdx
    jz ja_acquire_got
    cmp rax, 3
    je ja_acquire_busy
    cmp rax, 4
    ja ja_acquire_busy
    cmp [r15 + JA_TID], rbp
    je ja_acquire_busy
    mov rdx, rax
    lea rdi, [r15 + JA_LOCK]
    mov esi, 128 /* FUTEX_WAIT_PRIVATE */
    xor r10d, r10d
    xor r8d, r8d
    xor r9d, r9d
    mov eax, 202
    syscall
    test rax, rax
    jz ja_acquire_again
    cmp rax, -4
    je ja_acquire_again
    cmp rax, -11
    je ja_acquire_again
    ret
ja_acquire_got:
    mov [r15 + JA_TID], rbp
    xor eax, eax
    ret
ja_acquire_busy:
    mov rax, -16
    ret

ja_wake:
    lea rdi, [r15 + JA_LOCK]
    mov esi, 129 /* FUTEX_WAKE_PRIVATE */
    mov edx, 0x7fffffff
    xor r10d, r10d
    xor r8d, r8d
    xor r9d, r9d
    mov eax, 202
    syscall
    ret

.global jobs_audit_invoke
jobs_audit_invoke:
    JA_SAVE
    sub rsp, 128
    mov r15, rdi
    mov r12, rsi
    mov r13, rdx
    call ja_context
    test rax, rax
    jnz ja_invoke_early_invalid
    call ja_acquire
    test rax, rax
    jnz ja_invoke_early_resource
    mov [r15 + JA_FRAME_STACK], rsp
    cmp qword ptr [r15 + JA_POISON], 0
    jne ja_invoke_poisoned
    mov qword ptr [r15 + JA_EXTENT], 0
    mov qword ptr [r15 + JA_CANONICAL_PENDING], 0
    mov qword ptr [r15 + JA_NAMESPACE_ACTIVE], 0
    mov [r15 + JA_INPUT_LENGTH], r13
    mov rax, [r15 + JA_OWNER]
    mov [r15 + JA_ACTIVE_ENTRY], rax
    lea rdi, [r15 + JA_INPUT]
    mov rsi, r13
    test rsi, rsi
    jnz ja_invoke_input_size
    mov esi, 1
ja_invoke_input_size:
    call jobs_audit_grow
    test rax, rax
    jnz ja_invoke_resource
    mov rdi, [r15 + JA_INPUT]
    mov rsi, [r15 + JA_INPUT_CAP]
    mov edx, 3
    mov eax, 10
    syscall
    test rax, rax
    jnz ja_invoke_resource
    mov rdi, [r15 + JA_INPUT]
    mov rsi, r12
    mov rcx, r13
    cld
    rep movsb
    mov rdi, [r15 + JA_INPUT]
    mov rsi, [r15 + JA_INPUT_CAP]
    mov edx, 1
    mov eax, 10
    syscall
    test rax, rax
    jnz ja_invoke_resource
    lea rdi, [r15 + JA_WORK]
    mov esi, 8192
    call jobs_audit_grow
    test rax, rax
    jnz ja_invoke_resource
    lea rdi, [r15 + JA_OUTPUT]
    mov esi, 16384
    call jobs_audit_grow
    test rax, rax
    jnz ja_invoke_resource
ja_invoke_again:
    mov rdi, [r15 + JA_INPUT]
    mov rsi, [r15 + JA_INPUT_LENGTH]
    mov rdx, [r15 + JA_OUTPUT]
    mov rcx, [r15 + JA_OUTPUT_CAP]
    mov r8, [r15 + JA_WORK]
    mov r9, [r15 + JA_WORK_CAP]
    call qword ptr [r15 + JA_ACTIVE_ENTRY]
    mov edx, eax
    cmp rax, rdx
    jne ja_invoke_bad
    mov rbx, [r15 + JA_WORK]
    lea r14, [rbx + 256]
    cmp eax, 0xfffffff0
    je ja_effect_admit
    cmp eax, 0xffffffed
    je ja_namespace_return
    cmp qword ptr [r15 + JA_NAMESPACE_ACTIVE], 0
    jne ja_invoke_bad
    cmp eax, 0xffffffef
    je ja_owner_grow_work
    cmp eax, 0xffffffee
    je ja_owner_grow_output
    cmp eax, 0xffff0000
    jae ja_invoke_abort
    cmp eax, 32
    jb ja_invoke_bad
    cmp rax, [r15 + JA_OUTPUT_CAP]
    ja ja_invoke_bad
    mov rdx, [r15 + JA_OUTPUT]
    mov rcx, 0x31304d4746435248 /* HRCFGM01 */
    cmp [rdx], rcx
    jne ja_invoke_bad
    cmp qword ptr [rdx + 16], 0
    jne ja_invoke_bad
    lea rcx, [rax - 32]
    cmp [rdx + 24], rcx
    jne ja_invoke_bad
    cmp qword ptr [rdx + 8], 1
    ja ja_invoke_bad
    je ja_result_error
    cmp eax, 32
    jne ja_invoke_bad
    cmp qword ptr [rbx + 128], 1
    jne ja_invoke_bad
    jmp ja_result_ready
ja_result_error:
    mov qword ptr [rbx + 128], 0
ja_result_ready:
    mov [r15 + JA_EXTENT], rax
    mov qword ptr [r15 + JA_LOCK], 2
    jmp ja_invoke_return
ja_namespace_return:
    cmp qword ptr [r15 + JA_NAMESPACE_ACTIVE], 1
    jne ja_invoke_bad
    mov qword ptr [r15 + JA_NAMESPACE_ACTIVE], 0
    mov rax, [r15 + JA_OWNER]
    mov [r15 + JA_ACTIVE_ENTRY], rax
    jmp ja_invoke_again
ja_owner_grow_work:
    mov rsi, [rbx + 208]
    cmp rsi, [r15 + JA_WORK_CAP]
    jbe ja_invoke_bad
    lea rdi, [r15 + JA_WORK]
    call jobs_audit_grow
    test rax, rax
    jnz ja_invoke_resource
    jmp ja_invoke_again
ja_owner_grow_output:
    mov rsi, [rbx + 216]
    cmp rsi, [r15 + JA_OUTPUT_CAP]
    jbe ja_invoke_bad
    lea rdi, [r15 + JA_OUTPUT]
    call jobs_audit_grow
    test rax, rax
    jnz ja_invoke_resource
    jmp ja_invoke_again

ja_effect_admit:
    mov rax, 0x3130304155414a48 /* HJAUA001 */
    cmp [r14], rax
    jne ja_invoke_bad
    mov rax, [r15 + JA_SEQUENCE]
    inc rax
    jz ja_invoke_bad
    cmp [r14 + 8], rax
    jne ja_invoke_bad
    cmp [rbx + 16], rax
    jne ja_invoke_bad
    mov [r15 + JA_SEQUENCE], rax
    JA_ZEROS 64,8
    mov rax, [r14 + 16]
    cmp rax, 1
    jb ja_invoke_bad
    cmp rax, 22
    ja ja_invoke_bad
    lea rdx, [rip + ja_effect_table]
    movsxd rax, dword ptr [rdx + rax * 4 - 4]
    add rax, rdx
    jmp rax

/* Effect helpers only return admitted addresses and context-owned handles. */
ja_span:
    mov rax, [r15 + JA_WORK_CAP]
    cmp rdi, rax
    ja ja_invoke_bad
    sub rax, rdi
    cmp rsi, rax
    ja ja_invoke_bad
    mov rax, [r15 + JA_WORK]
    add rax, rdi
    ret
ja_path:
    mov rdx, rsi
    inc rsi
    jz ja_invoke_bad
    call ja_span
    cmp byte ptr [rax + rdx], 0
    jne ja_invoke_bad
    xor ecx, ecx
ja_path_next:
    cmp rcx, rdx
    je ja_path_done
    cmp byte ptr [rax + rcx], 0
    je ja_invoke_bad
    inc rcx
    jmp ja_path_next
ja_path_done:
    mov rsi, rdx
    ret
ja_handle:
    test rdi, rdi
    jz ja_invoke_bad
    lea rdx, [r15 + JA_REGISTRY]
    mov ecx, JA_HANDLES
ja_handle_next:
    cmp [rdx], rdi
    je ja_handle_found
    add rdx, 16
    dec ecx
    jnz ja_handle_next
    jmp ja_invoke_bad
ja_handle_found:
    mov rax, [rdx + 8]
    cmp rax, 0x7fffffff
    ja ja_invoke_bad
    ret
ja_prepare_fd:
    cmp qword ptr [r15 + JA_LIVE], JA_HANDLES
    jae ja_invoke_registry_full
    mov r13, [r15 + JA_NEXT_HANDLE]
    inc r13
    jz ja_invoke_registry_full
    lea r12, [r15 + JA_REGISTRY]
    mov ecx, JA_HANDLES
ja_prepare_fd_next:
    cmp qword ptr [r12], 0
    je ja_prepare_fd_done
    add r12, 16
    dec ecx
    jnz ja_prepare_fd_next
    jmp ja_invoke_bad
ja_prepare_fd_done:
    ret
ja_fd_return:
    test rax, rax
    js ja_kernel_return
    cmp rax, 0x7fffffff
    ja ja_invoke_bad
    mov [r12], r13
    mov [r12 + 8], rax
    mov [r15 + JA_NEXT_HANDLE], r13
    inc qword ptr [r15 + JA_LIVE]
    mov rax, r13
    jmp ja_acknowledge_success
ja_kernel_count_return:
    test rax, rax
    js ja_kernel_return
    cmp rax, [r14 + 40]
    ja ja_invoke_bad
ja_kernel_return:
    test rax, rax
    jns ja_acknowledge_success
    cmp rax, -4095
    jb ja_invoke_bad
    neg rax
    mov [r14 + 80], rax
    xor eax, eax
ja_acknowledge_success:
    mov [r14 + 72], rax
    mov rax, [r15 + JA_SEQUENCE]
    mov [r14 + 64], rax
    jmp ja_invoke_again

/* Closed effect implementations. No result/error is retried here. */
ja_clock:
    cmp qword ptr [r14 + 32], 16
    jne ja_invoke_bad
    JA_ZEROS 40,3
    mov rdi, [r14 + 24]
    mov esi, 16
    call ja_span
    mov rsi, rax
    xor edi, edi
    mov eax, 228
    syscall
    jmp ja_kernel_return
ja_mkdir:
    JA_ZEROS 48,2
    JA_U32 40
    mov rdi, [r14 + 24]
    mov rsi, [r14 + 32]
    call ja_path
    mov rdi, rax
    mov rsi, [r14 + 40]
    mov eax, 83
    syscall
    jmp ja_kernel_return
ja_stat_path:
    JA_ZEROS 56,1
    JA_U32 48
    mov rdi, [r14 + 24]
    mov rsi, [r14 + 32]
    call ja_path
    mov r12, rax
    mov rdi, [r14 + 40]
    mov esi, 144
    call ja_span
    mov rdx, rax
    mov edi, -100
    mov rsi, r12
    mov r10, [r14 + 48]
    mov eax, 262
    syscall
    jmp ja_kernel_return
ja_open:
    JA_ZEROS 56,1
    JA_U32 40
    JA_U32 48
    mov rdi, [r14 + 24]
    mov rsi, [r14 + 32]
    call ja_path
    mov rbp, rax
    call ja_prepare_fd
    mov edi, -100
    mov rsi, rbp
    mov rdx, [r14 + 40]
    mov r10, [r14 + 48]
    mov eax, 257
    syscall
    jmp ja_fd_return
ja_stat_fd:
    JA_ZEROS 40,3
    mov rdi, [r14 + 24]
    call ja_handle
    mov r12, rax
    mov rdi, [r14 + 32]
    mov esi, 144
    call ja_span
    mov rdi, r12
    mov rsi, rax
    mov eax, 5
    syscall
    jmp ja_kernel_return
ja_uid:
    JA_ZEROS 24,5
    mov eax, 107
    syscall
    jmp ja_kernel_return
ja_chmod:
    JA_ZEROS 40,3
    JA_U32 32
    mov rdi, [r14 + 24]
    call ja_handle
    mov rdi, rax
    mov rsi, [r14 + 32]
    mov eax, 91
    syscall
    jmp ja_kernel_return
ja_write:
    JA_ZEROS 48,2
    mov rdi, [r14 + 24]
    call ja_handle
    mov r12, rax
    mov rdi, [r14 + 32]
    mov rsi, [r14 + 40]
    call ja_span
    mov rdi, r12
    mov rsi, rax
    mov rdx, [r14 + 40]
    mov eax, 1
    syscall
    jmp ja_kernel_count_return
ja_fdatasync:
    JA_ZEROS 32,4
    mov rdi, [r14 + 24]
    call ja_handle
    mov rdi, rax
    mov eax, 75
    syscall
    jmp ja_kernel_return
ja_fsync:
    JA_ZEROS 32,4
    mov rdi, [r14 + 24]
    call ja_handle
    mov rdi, rax
    mov eax, 74
    syscall
    jmp ja_kernel_return
ja_close:
    JA_ZEROS 32,4
    mov rdi, [r14 + 24]
    call ja_handle
    mov qword ptr [rdx], 0
    mov qword ptr [rdx + 8], -1
    cmp qword ptr [r15 + JA_LIVE], 0
    je ja_invoke_bad
    dec qword ptr [r15 + JA_LIVE]
    mov rdi, rax
    mov eax, 3
    syscall
    jmp ja_kernel_return
ja_inotify_init:
    JA_ZEROS 32,4
    JA_U32 24
    call ja_prepare_fd
    mov rdi, [r14 + 24]
    mov eax, 294
    syscall
    jmp ja_fd_return
ja_inotify_add:
    JA_ZEROS 48,2
    JA_U32 40
    mov rdi, [r14 + 24]
    call ja_handle
    mov r12, rax
    mov rdi, [r14 + 32]
    call ja_handle
    mov r13, rax
    mov rdi, rsp
    lea rsi, [rip + ja_proc_fd]
    mov ecx, 14
    cld
    rep movsb
    lea rdi, [rsp + 64]
    mov byte ptr [rdi], 0
    mov rax, r13
    mov r10d, 10
ja_inotify_decimal:
    xor edx, edx
    div r10
    add dl, '0'
    dec rdi
    mov [rdi], dl
    test rax, rax
    jnz ja_inotify_decimal
    mov rsi, rdi
    lea rcx, [rsp + 65]
    sub rcx, rsi
    lea rdi, [rsp + 14]
    rep movsb
    mov rdi, r12
    mov rsi, rsp
    mov rdx, [r14 + 40]
    mov eax, 254
    syscall
    test rax, rax
    js ja_kernel_return
    cmp rax, 0x7fffffff
    ja ja_invoke_bad
    jmp ja_kernel_return
ja_read:
    JA_ZEROS 48,2
    mov rdi, [r14 + 24]
    call ja_handle
    mov r12, rax
    mov rdi, [r14 + 32]
    mov rsi, [r14 + 40]
    call ja_span
    mov rdi, r12
    mov rsi, rax
    mov rdx, [r14 + 40]
    xor eax, eax
    syscall
    jmp ja_kernel_count_return
ja_inotify_remove:
    JA_ZEROS 40,3
    mov rax, [r14 + 32]
    cmp rax, 0x7fffffff
    ja ja_invoke_bad
    mov rdi, [r14 + 24]
    call ja_handle
    mov rdi, rax
    mov rsi, [r14 + 32]
    mov eax, 255
    syscall
    jmp ja_kernel_return
ja_getdents:
    JA_ZEROS 48,2
    JA_U32 40
    mov rdi, [r14 + 24]
    call ja_handle
    mov r12, rax
    mov rdi, [r14 + 32]
    mov rsi, [r14 + 40]
    call ja_span
    mov rdi, r12
    mov rsi, rax
    mov rdx, [r14 + 40]
    mov eax, 217
    syscall
    jmp ja_kernel_count_return
ja_open_dot:
    JA_ZEROS 40,3
    JA_U32 32
    mov rdi, [r14 + 24]
    call ja_handle
    mov rbp, rax
    call ja_prepare_fd
    mov rdi, rbp
    lea rsi, [rip + ja_dot]
    mov rdx, [r14 + 32]
    xor r10d, r10d
    mov eax, 257
    syscall
    jmp ja_fd_return
ja_dup:
    JA_ZEROS 32,4
    mov rdi, [r14 + 24]
    call ja_handle
    mov rbp, rax
    call ja_prepare_fd
    mov rdi, rbp
    mov esi, 1030
    xor edx, edx
    mov eax, 72
    syscall
    jmp ja_fd_return

/* Canonicalization is an effectful fixed child. Preserve a complete result
 * and its input across output-growth retries, rather than reobserve paths. */
ja_canonical:
    JA_ZEROS 56,1
    mov rdi, [r14 + 24]
    mov rsi, [r14 + 32]
    call ja_span
    mov r12, rax
    mov rdi, [r14 + 40]
    mov rsi, [r14 + 48]
    call ja_span
    cmp qword ptr [r15 + JA_CANONICAL_PENDING], 0
    jne ja_canonical_retry
    lea rdi, [r15 + JA_CANONICAL_CONTEXT]
    mov rsi, [r14 + 32]
    test rsi, rsi
    jnz ja_canonical_input_size
    mov esi, 1
ja_canonical_input_size:
    call jobs_audit_grow
    test rax, rax
    jnz ja_invoke_resource
    mov rdi, [r15 + JA_CANONICAL_CONTEXT]
    mov rsi, r12
    mov rcx, [r14 + 32]
    mov [r15 + JA_CANONICAL_CONTEXT + 48], rcx
    cld
    rep movsb
    lea rdi, [r15 + JA_CANONICAL_CONTEXT]
    call jobs_audit_canonical_run
    mov edx, eax
    cmp rax, rdx
    jne ja_invoke_bad
    cmp eax, 0xffff0000
    jae ja_invoke_abort
    cmp rax, 32
    jb ja_invoke_bad
    cmp rax, [r15 + JA_CANONICAL_CONTEXT + 40]
    ja ja_invoke_bad
    mov rdx, [r15 + JA_CANONICAL_CONTEXT + 32]
    mov rcx, 0x3130524c4e435248 /* HRCNLR01 */
    cmp [rdx], rcx
    jne ja_invoke_bad
    lea rcx, [rax - 32]
    cmp [rdx + 16], rcx
    jne ja_invoke_bad
    cmp qword ptr [rdx + 8], 1
    ja ja_invoke_bad
    je ja_canonical_error
    cmp qword ptr [rdx + 24], 0
    jne ja_invoke_bad
    jmp ja_canonical_full
ja_canonical_error:
    mov rcx, [rdx + 24]
    cmp rcx, 65536
    je ja_canonical_full
    dec rcx
    cmp rcx, 4094
    ja ja_invoke_bad
ja_canonical_full:
    mov [r15 + JA_CANONICAL_CONTEXT + 136], rax
    mov qword ptr [r15 + JA_CANONICAL_PENDING], 1
    jmp ja_canonical_deliver
ja_canonical_retry:
    mov rcx, [r14 + 32]
    cmp [r15 + JA_CANONICAL_CONTEXT + 48], rcx
    jne ja_invoke_bad
    mov rdi, [r15 + JA_CANONICAL_CONTEXT]
    mov rsi, r12
    cld
    repe cmpsb
    jne ja_invoke_bad
ja_canonical_deliver:
    mov rax, [r15 + JA_CANONICAL_CONTEXT + 136]
    cmp rax, [r14 + 48]
    ja ja_acknowledge_success
    mov rcx, rax
    mov rsi, [r15 + JA_CANONICAL_CONTEXT + 32]
    mov rdi, [r15 + JA_WORK]
    add rdi, [r14 + 40]
    cld
    rep movsb
    mov qword ptr [r15 + JA_CANONICAL_PENDING], 0
    jmp ja_acknowledge_success

/* Pure children use independent writable arenas. Only a complete admitted
 * response is copied back; output-growth retries cannot emit partial bytes. */
ja_sha:
    JA_ZEROS 56,1
    mov rdi, [r14 + 24]
    mov rsi, [r14 + 32]
    call ja_span
    mov r12, rax
    cmp qword ptr [r14 + 32], 24
    jb ja_invoke_bad
    mov rcx, 0x314345444f435248 /* HRCODEC1 */
    cmp [r12], rcx
    jne ja_invoke_bad
    cmp qword ptr [r12 + 16], 0
    jne ja_invoke_bad
    mov r13, [r12 + 8]
    cmp r13, 3
    jb ja_invoke_bad
    cmp r13, 5
    ja ja_invoke_bad
    mov rdi, [r14 + 40]
    mov rsi, [r14 + 48]
    call ja_span
    lea rdi, [r15 + JA_SHA_WORK]
    mov esi, 4096
    call jobs_audit_grow
    test rax, rax
    jnz ja_invoke_resource
    lea rdi, [r15 + JA_PURE_OUTPUT]
    mov esi, 4096
    call jobs_audit_grow
    test rax, rax
    jnz ja_invoke_resource
    mov rdi, r12
    mov rsi, [r14 + 32]
    mov rdx, [r15 + JA_PURE_OUTPUT]
    mov rcx, [r15 + JA_PURE_OUTPUT + 8]
    mov r8, [r15 + JA_SHA_WORK]
    mov r9, [r15 + JA_SHA_WORK + 8]
    call qword ptr [r15 + JA_SHA]
    mov edx, eax
    cmp rax, rdx
    jne ja_invoke_bad
    cmp eax, 0xffff0000
    jae ja_invoke_abort
    cmp r13, 5
    je ja_sha_digest
    cmp eax, 128
    jne ja_invoke_bad
    mov rdx, [r15 + JA_PURE_OUTPUT]
    mov rcx, 0x3136353241485348 /* HSHA2561 */
    cmp [rdx], rcx
    jne ja_invoke_bad
    jmp ja_pure_deliver
ja_sha_digest:
    cmp eax, 32
    jne ja_invoke_bad
    jmp ja_pure_deliver
ja_errno:
    JA_ZEROS 56,1
    cmp qword ptr [r14 + 32], 16
    jne ja_invoke_bad
    mov rdi, [r14 + 24]
    mov esi, 16
    call ja_span
    mov r12, rax
    mov rcx, 0x3130515245444d48 /* HMDERQ01 */
    cmp [r12], rcx
    jne ja_invoke_bad
    mov r13, [r12 + 8]
    lea rax, [r13 - 1]
    cmp rax, 4094
    ja ja_invoke_bad
    mov rdi, [r14 + 40]
    mov rsi, [r14 + 48]
    call ja_span
    lea rdi, [r15 + JA_ERRNO_WORK]
    mov esi, 4096
    call jobs_audit_grow
    test rax, rax
    jnz ja_invoke_resource
    lea rdi, [r15 + JA_PURE_OUTPUT]
    mov esi, 4096
    call jobs_audit_grow
    test rax, rax
    jnz ja_invoke_resource
    mov rdi, r12
    mov esi, 16
    mov rdx, [r15 + JA_PURE_OUTPUT]
    mov rcx, [r15 + JA_PURE_OUTPUT + 8]
    mov r8, [r15 + JA_ERRNO_WORK]
    mov r9, [r15 + JA_ERRNO_WORK + 8]
    call qword ptr [r15 + JA_ERRNO]
    mov edx, eax
    cmp rax, rdx
    jne ja_invoke_bad
    cmp eax, 0xffff0000
    jae ja_invoke_abort
    cmp eax, 24
    jb ja_invoke_bad
    cmp rax, [r15 + JA_PURE_OUTPUT + 8]
    ja ja_invoke_bad
    mov rdx, [r15 + JA_PURE_OUTPUT]
    mov rcx, 0x3130525245444d48 /* HMDERR01 */
    cmp [rdx], rcx
    jne ja_invoke_bad
    cmp [rdx + 8], r13
    jne ja_invoke_bad
    lea rcx, [rax - 24]
    cmp [rdx + 16], rcx
    jne ja_invoke_bad
ja_pure_deliver:
    cmp rax, [r14 + 48]
    ja ja_acknowledge_success
    mov rcx, rax
    mov rsi, [r15 + JA_PURE_OUTPUT]
    mov rdi, [r15 + JA_WORK]
    add rdi, [r14 + 40]
    cld
    rep movsb
    jmp ja_acknowledge_success

/* Namespace shares the owner's buffers and monotonically increasing effect
 * chain. Its AGAIN return never restores this older outer acknowledgement. */
ja_namespace:
    JA_ZEROS 24,5
    cmp qword ptr [r15 + JA_NAMESPACE_ACTIVE], 0
    jne ja_invoke_bad
    cmp qword ptr [r15 + JA_CANONICAL_PENDING], 0
    jne ja_invoke_bad
    mov rax, [r15 + JA_SEQUENCE]
    mov [r14 + 64], rax
    mov qword ptr [r15 + JA_NAMESPACE_ACTIVE], 1
    mov rax, [r15 + JA_NAMESPACE]
    mov [r15 + JA_ACTIVE_ENTRY], rax
    jmp ja_invoke_again

ja_invoke_registry_full:
    mov rax, -24
ja_invoke_resource:
    mov [r15 + JA_NATIVE_ERRNO], rax
    mov eax, JA_RESOURCE
    jmp ja_invoke_abort
ja_invoke_bad:
    mov eax, JA_FAULT
ja_invoke_abort:
    mov [r15 + JA_NATIVE_RETURN], rax
    mov rsp, [r15 + JA_FRAME_STACK]
    mov rbx, [r15 + JA_WORK]
    test rbx, rbx
    jz ja_abort_no_work
    mov qword ptr [rbx + 128], 0
ja_abort_no_work:
    mov qword ptr [r15 + JA_POISON], 1
    mov qword ptr [r15 + JA_EXTENT], 0
    mov qword ptr [r15 + JA_CANONICAL_PENDING], 0
    call ja_cleanup_descriptors
    jmp ja_invoke_unlock
ja_invoke_poisoned:
    mov eax, JA_RESOURCE
    mov [r15 + JA_NATIVE_RETURN], rax
ja_invoke_unlock:
    mov qword ptr [r15 + JA_TID], 0
    mov qword ptr [r15 + JA_LOCK], 0
    call ja_wake
    mov rax, [r15 + JA_NATIVE_RETURN]
    jmp ja_invoke_return
ja_invoke_early_invalid:
    mov eax, 0xffffffff
    jmp ja_invoke_return
ja_invoke_early_resource:
    mov eax, JA_RESOURCE
ja_invoke_return:
    add rsp, 128
    JA_RETURN

.global jobs_audit_output
jobs_audit_output:
    sub rsp, 8
    call ja_context
    add rsp, 8
    test rax, rax
    jnz ja_output_none
    cmp qword ptr [rdi + JA_LOCK], 2
    jne ja_output_none
    mov rax, [rdi + JA_OUTPUT]
    ret
ja_output_none:
    xor eax, eax
    ret

.global jobs_audit_release
jobs_audit_release:
    JA_SAVE
    mov r15, rdi
    call ja_context
    test rax, rax
    jnz ja_release_done
    mov eax, 2
    mov edx, 4
    lock cmpxchg qword ptr [r15 + JA_LOCK], rdx
    jne ja_release_invalid
    mov qword ptr [r15 + JA_EXTENT], 0
    mov qword ptr [r15 + JA_TID], 0
    mov qword ptr [r15 + JA_LOCK], 0
    call ja_wake
    test rax, rax
    js ja_release_done
    xor eax, eax
    jmp ja_release_done
ja_release_invalid:
    mov rax, -22
ja_release_done:
    JA_RETURN

/* Every close retires its handle first, even on EINTR/EBADF. No close retry. */
ja_cleanup_descriptors:
    JA_SAVE
    xor ebp, ebp
    lea r12, [r15 + JA_REGISTRY]
    mov r13d, JA_HANDLES
ja_cleanup_registry:
    cmp qword ptr [r12], 0
    je ja_cleanup_registry_next
    mov rdi, [r12 + 8]
    mov qword ptr [r12], 0
    mov qword ptr [r12 + 8], -1
    mov eax, 3
    syscall
    test rax, rax
    jz ja_cleanup_registry_next
    test rbp, rbp
    cmovz rbp, rax
ja_cleanup_registry_next:
    add r12, 16
    dec r13d
    jnz ja_cleanup_registry
    mov qword ptr [r15 + JA_LIVE], 0
    lea r12, [r15 + JA_CANONICAL_CONTEXT + 72]
    mov r13d, 2
ja_cleanup_canonical:
    mov rdi, [r12]
    cmp rdi, -1
    je ja_cleanup_canonical_next
    mov qword ptr [r12], -1
    mov eax, 3
    syscall
    test rax, rax
    jz ja_cleanup_canonical_next
    test rbp, rbp
    cmovz rbp, rax
ja_cleanup_canonical_next:
    add r12, 8
    dec r13d
    jnz ja_cleanup_canonical
    mov rax, rbp
    JA_RETURN

.global jobs_audit_destroy
jobs_audit_destroy:
    JA_SAVE
    mov r15, rdi
    call ja_context
    test rax, rax
    jnz ja_destroy_done
    xor eax, eax
    mov edx, 3
    lock cmpxchg qword ptr [r15 + JA_LOCK], rdx
    jne ja_destroy_busy
    call ja_cleanup_descriptors
    mov rbp, rax
    lea r12, [rip + ja_owned_pairs]
    mov r13d, 9
ja_destroy_pair:
    mov rax, [r12]
    lea rbx, [r15 + rax]
    mov rdi, [rbx]
    test rdi, rdi
    jz ja_destroy_pair_next
    mov rsi, [rbx + 8]
    add rsi, 4096
    jc ja_destroy_pair_invalid
    mov eax, 11
    syscall
    test rax, rax
    jnz ja_destroy_pair_failed
    mov qword ptr [rbx], 0
    mov qword ptr [rbx + 8], 0
    jmp ja_destroy_pair_next
ja_destroy_pair_invalid:
    mov rax, -22
ja_destroy_pair_failed:
    test rbp, rbp
    cmovz rbp, rax
ja_destroy_pair_next:
    add r12, 8
    dec r13d
    jnz ja_destroy_pair
    test rbp, rbp
    jnz ja_destroy_retained
    mov rdi, r15
    mov esi, JA_BYTES + 4096
    mov eax, 11
    syscall
    test rax, rax
    jz ja_destroy_done
    mov rbp, rax
ja_destroy_retained:
    mov qword ptr [r15 + JA_POISON], 1
    mov qword ptr [r15 + JA_LOCK], 0
    mov rax, rbp
    jmp ja_destroy_done
ja_destroy_busy:
    mov rax, -16
ja_destroy_done:
    JA_RETURN

.balign 8
ja_owned_pairs:
    .quad JA_INPUT, JA_WORK, JA_OUTPUT, JA_SHA_WORK, JA_ERRNO_WORK, JA_PURE_OUTPUT
    .quad JA_CANONICAL_CONTEXT, JA_CANONICAL_CONTEXT + 16, JA_CANONICAL_CONTEXT + 32
.balign 4
ja_effect_table:
    .long ja_clock - ja_effect_table, ja_mkdir - ja_effect_table
    .long ja_stat_path - ja_effect_table, ja_open - ja_effect_table
    .long ja_stat_fd - ja_effect_table, ja_uid - ja_effect_table
    .long ja_chmod - ja_effect_table, ja_write - ja_effect_table
    .long ja_fdatasync - ja_effect_table, ja_fsync - ja_effect_table
    .long ja_close - ja_effect_table, ja_inotify_init - ja_effect_table
    .long ja_inotify_add - ja_effect_table, ja_read - ja_effect_table
    .long ja_inotify_remove - ja_effect_table, ja_canonical - ja_effect_table
    .long ja_getdents - ja_effect_table, ja_open_dot - ja_effect_table
    .long ja_sha - ja_effect_table, ja_dup - ja_effect_table
    .long ja_namespace - ja_effect_table, ja_errno - ja_effect_table
ja_dot:
    .asciz "."
ja_proc_fd:
    .ascii "/proc/self/fd/"
.section .note.GNU-stack,"",@progbits
