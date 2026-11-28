/* Copyright 2026 Muvon Un Limited
 * Copyright 2026 TrillionniumFoundation
 * SPDX-License-Identifier: Apache-2.0
 * Fixed process-lifetime orphan inventory. It never duplicates or closes an FD.
 * The calling fixed capability adapter must first verify its own opened token.
 */
.intel_syntax noprefix
.section .text
.macro OP_ENTER
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp, 8
.endm
.macro OP_LEAVE
    add rsp, 8
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret
.endm

/* One zeroed RW page followed by an inaccessible page. */
.Lhpo_map:
    push rbx
    xor edi, edi
    mov esi, 8192
    mov edx, 3
    mov r10d, 0x22
    mov r8, -1
    xor r9d, r9d
    mov eax, 9
    syscall
    cmp rax, -4095
    jae .Lhpo_map_return
    mov rbx, rax
    lea rdi, [rax+4096]
    mov esi, 4096
    xor edx, edx
    mov eax, 10
    syscall
    test rax, rax
    jnz .Lhpo_map_guard_failed
    mov rax, rbx
    jmp .Lhpo_map_return
.Lhpo_map_guard_failed:
    mov rdi, rbx
    mov esi, 8192
    mov eax, 11
    syscall
    mov rax, -12
.Lhpo_map_return:
    pop rbx
    ret

/* No arguments. Returns a private pool pointer or raw negative Linux errno.
 * The pool and its records intentionally have no in-process destroy operation. */
.global hia_process_orphans_create
hia_process_orphans_create:
    OP_ENTER
    call .Lhpo_map
    cmp rax, -4095
    jae .Lhpo_create_return
    mov r12, rax
    movabs rax, 0x31303050524f5048 /* HPORP001 */
    mov [r12], rax
    mov qword ptr [r12+8], 4096
    mov eax, 39
    syscall
    mov [r12+16], rax
    mov rax, r12
.Lhpo_create_return:
    OP_LEAVE

/* rdi=trusted pool, rsi=owned FD, rdx=origin context, rcx=origin generation.
 * Success appends exactly one immutable record and returns zero.
 * A negative return appends no record; the caller retains its token.
 * Neither success nor failure invokes close, dup, fcntl, open or an FD callback. */
.global hia_process_orphans_append
hia_process_orphans_append:
    OP_ENTER
    mov r12, rdi
    mov r13, rsi
    mov r14, rdx
    mov r15, rcx
    test r12, r12
    jz .Lhpo_append_bad
    test r12, 4095
    jnz .Lhpo_append_bad
    cmp r13, 2147483647
    ja .Lhpo_append_bad
    test r14, r14
    jz .Lhpo_append_bad
    test r15, r15
    jz .Lhpo_append_bad
    movabs rax, 0x31303050524f5048
    cmp [r12], rax
    jne .Lhpo_append_bad
    cmp qword ptr [r12+8], 4096
    jne .Lhpo_append_bad
    mov eax, 39
    syscall
    cmp [r12+16], rax
    jne .Lhpo_append_bad
.Lhpo_lock:
    xor eax, eax
    mov edx, 1
    lock cmpxchg dword ptr [r12+24], edx
    jz .Lhpo_locked
    lea rdi, [r12+24]
    mov esi, 128 /* FUTEX_WAIT_PRIVATE */
    mov edx, 1
    xor r10d, r10d
    xor r8d, r8d
    xor r9d, r9d
    mov eax, 202
    syscall
    pause
    jmp .Lhpo_lock
.Lhpo_locked:
    cmp qword ptr [r12+48], -1
    je .Lhpo_locked_overflow
    mov rbp, [r12+40]
    test rbp, rbp
    jz .Lhpo_new_page
    movabs rax, 0x3130304c524f5048 /* HPORL001 */
    cmp [rbp], rax
    jne .Lhpo_locked_bad
    cmp [rbp+8], r12
    jne .Lhpo_locked_bad
    cmp qword ptr [rbp+16], 0
    jne .Lhpo_locked_bad
    cmp qword ptr [rbp+24], 126
    ja .Lhpo_locked_bad
    jb .Lhpo_append_record
.Lhpo_new_page:
    call .Lhpo_map
    cmp rax, -4095
    jae .Lhpo_locked_map_failed
    mov rbx, rax
    movabs rax, 0x3130304c524f5048
    mov [rbx], rax
    mov [rbx+8], r12
    mov rax, [r12+48]
    inc rax
    mov [rbx+32], rax
    test rbp, rbp
    jz .Lhpo_first_page
    mov [rbp+16], rbx
    jmp .Lhpo_install_tail
.Lhpo_first_page:
    cmp qword ptr [r12+32], 0
    jne .Lhpo_new_page_bad
    mov [r12+32], rbx
.Lhpo_install_tail:
    mov [r12+40], rbx
    inc qword ptr [r12+56]
    mov rbp, rbx
.Lhpo_append_record:
    mov rcx, [rbp+24]
    shl rcx, 5
    lea rdx, [rbp+rcx+64]
    mov [rdx], r13
    mov [rdx+8], r14
    mov [rdx+16], r15
    mov rax, [r12+48]
    inc rax
    mov [rdx+24], rax
    mov [r12+48], rax
    inc qword ptr [rbp+24]
    xor ebx, ebx
    jmp .Lhpo_unlock
.Lhpo_new_page_bad:
    mov rdi, rbx
    mov esi, 8192
    mov eax, 11
    syscall
.Lhpo_locked_bad:
    mov rbx, -22
    jmp .Lhpo_unlock
.Lhpo_locked_overflow:
    mov rbx, -75
    jmp .Lhpo_unlock
.Lhpo_locked_map_failed:
    mov rbx, rax
    inc qword ptr [r12+64]
.Lhpo_unlock:
    xor eax, eax
    xchg dword ptr [r12+24], eax
    lea rdi, [r12+24]
    mov esi, 129 /* FUTEX_WAKE_PRIVATE */
    mov edx, 1
    xor r10d, r10d
    xor r8d, r8d
    xor r9d, r9d
    mov eax, 202
    syscall
    mov rax, rbx
    jmp .Lhpo_append_return
.Lhpo_append_bad:
    mov rax, -22
.Lhpo_append_return:
    OP_LEAVE

.section .note.GNU-stack,"",@progbits
