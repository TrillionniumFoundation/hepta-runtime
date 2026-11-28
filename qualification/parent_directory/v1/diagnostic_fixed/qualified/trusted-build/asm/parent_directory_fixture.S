/* Copyright 2026 Muvon Un Limited
 * SPDX-License-Identifier: Apache-2.0
 * Private two-context held-directory carrier. No public JSON command selects a native
 * address, fd, syscall, or image. The fixture owns stdin/stdout, FD3 journal,
 * FD4 effect notifications, FD5 acknowledgements and its two parent-directory contexts.
 */
.intel_syntax noprefix
.section .text
.global _start
.type _start, @function
_start:
    and rsp, -16
    cld
    mov edi, 3
    mov esi, 1 /* F_GETFD */
    xor edx, edx
    mov eax, 72
    syscall
    cmp rax, -4095
    jae .Lprf_fatal
    mov edi, 4
    mov esi, 1
    xor edx, edx
    mov eax, 72
    syscall
    cmp rax, -4095
    jae .Lprf_fatal
    mov edi, 5
    mov esi, 1
    xor edx, edx
    mov eax, 72
    syscall
    cmp rax, -4095
    jae .Lprf_fatal
    mov edi, 4096
    call .Lprd_map
    cmp rax, -4095
    jae .Lprf_fatal
    mov r15, rax
.Lprf_loop:
    xor edi, edi
    lea rsi, [r15+64]
    mov edx, 8
    call .Lprf_read_exact
    test rax, rax
    jz .Lprf_eof
    cmp rax, 8
    jne .Lprf_fatal
    mov r13, [r15+64]
    cmp r13, 64
    jb .Lprf_fatal
    cmp r13, 134217792
    ja .Lprf_fatal
    lea rdi, [r15+16]
    mov rsi, r13
    call .Lprd_grow
    test eax, eax
    jnz .Lprf_fatal
    xor edi, edi
    mov rsi, [r15+16]
    mov rdx, r13
    call .Lprf_read_exact
    cmp rax, r13
    jne .Lprf_fatal
    mov rbp, [r15+16]
    mov rax, 0x3130514644525048 /* HPRDFQ01 */
    cmp [rbp], rax
    jne .Lprf_fatal
    mov rbx, [rbp+16]
    cmp rbx, 1
    ja .Lprf_fatal
    mov r14, [rbp+8]
    cmp r14, 1
    jb .Lprf_fatal
    cmp r14, 12
    ja .Lprf_fatal
    mov rax, [rbp+32]
    or rax, [rbp+40]
    or rax, [rbp+48]
    or rax, [rbp+56]
    jnz .Lprf_fatal
    sub r13, 64
    cmp [rbp+24], r13
    jne .Lprf_fatal
    cmp r14, 1
    je .Lprf_invoke
    test r13, r13
    jnz .Lprf_fatal
    cmp r14, 8
    je .Lprf_create_explicit
    cmp r14, 9
    je .Lprf_create_unobserved
    mov r12, [r15+rbx*8]
    test r12, r12
    jz .Lprf_no_context
    cmp r14, 2
    je .Lprf_release
    cmp r14, 3
    je .Lprf_destroy
    cmp r14, 4
    je .Lprf_context
    cmp r14, 5
    je .Lprf_workspace
    cmp r14, 6
    je .Lprf_output
    cmp r14, 7
    je .Lprf_input
    cmp r14, 10
    je .Lprf_close
    cmp r14, 11
    je .Lprf_parent_stat
    cmp r14, 12
    je .Lprf_last_parent_stat
    jmp .Lprf_fatal
.Lprf_invoke:
    mov r12, [r15+rbx*8]
    test r12, r12
    jnz .Lprf_invoke_ready
    lea rdi, [rip+.Lprf_journal]
    mov esi, 3
    call parent_directory_create
    cmp rax, -4095
    jae .Lprf_fatal
    mov r12, rax
    mov [r15+rbx*8], rax
.Lprf_invoke_ready:
    mov rdi, r12
    lea rsi, [rbp+64]
    mov rdx, r13
    call parent_directory_acquire
.Lprf_invocation_returned:
    mov r13, rax
    xor r14d, r14d
    xor ebp, ebp
    cmp rax, 64
    jne .Lprf_reply
    mov r14, [r12+104]
    mov rbp, [r12+168]
    cmp qword ptr [r12+56], 4
    jne .Lprf_reply
    mov rax, [r12+344]
    mov [r15+32+rbx*8], rax
    mov qword ptr [r15+48+rbx*8], 1
    jmp .Lprf_reply

.Lprf_close:
    mov rdi, r12
    call parent_directory_close
    jmp .Lprf_invocation_returned
.Lprf_parent_stat:
    cmp qword ptr [r12+56], 4
    jne .Lprf_no_context
    mov rdi, [r12+344]
    jmp .Lprf_stat_actual
.Lprf_last_parent_stat:
    cmp qword ptr [r15+48+rbx*8], 1
    jne .Lprf_no_context
    mov rdi, [r15+32+rbx*8]
.Lprf_stat_actual:
    push rdi
    lea rdi, [r15+512]
    xor eax, eax
    mov ecx, 18
    rep stosq
    pop rdi
    lea rsi, [r15+512]
    mov eax, 5
    syscall
    mov r13, rax
    xor r14d, r14d
    xor ebp, ebp
    test rax, rax
    jnz .Lprf_reply
    lea r14, [r15+512]
    mov ebp, 144
    jmp .Lprf_reply

.Lprf_release:
    mov rdi, r12
    call parent_directory_release
    mov r13, rax
    xor r14d, r14d
    xor ebp, ebp
    jmp .Lprf_reply
.Lprf_destroy:
    mov rdi, r12
    call parent_directory_destroy
    mov r13, rax
    test eax, eax
    jnz .Lprf_destroy_response
    mov qword ptr [r15+rbx*8], 0
    xor r12d, r12d
.Lprf_destroy_response:
    xor r14d, r14d
    xor ebp, ebp
    jmp .Lprf_reply
.Lprf_create_explicit:
    mov r12, [r15+rbx*8]
    test r12, r12
    jnz .Lprf_create_busy
    lea rdi, [rip+.Lprf_journal]
    mov esi, 3
    call parent_directory_create
    cmp rax, -4095
    jae .Lprf_fatal
    mov r12, rax
    mov [r15+rbx*8], rax
    xor r13d, r13d
    xor r14d, r14d
    xor ebp, ebp
    jmp .Lprf_reply
.Lprf_create_unobserved:
    mov r12, [r15+rbx*8]
    test r12, r12
    jnz .Lprf_create_busy
    xor edi, edi
    xor esi, esi
    call parent_directory_create
    cmp rax, -4095
    jae .Lprf_fatal
    mov r12, rax
    mov [r15+rbx*8], rax
    xor r13d, r13d
    xor r14d, r14d
    xor ebp, ebp
    jmp .Lprf_reply
.Lprf_create_busy:
    mov r13d, 0xfffffffd
    xor r14d, r14d
    xor ebp, ebp
    jmp .Lprf_reply
.Lprf_no_context:
    mov r13d, 0xffffffff
    xor r14d, r14d
    xor ebp, ebp
    jmp .Lprf_reply
.Lprf_context:
    mov r14, r12
    mov ebp, 4096
    xor r13d, r13d
    jmp .Lprf_reply
.Lprf_workspace:
    mov r14, [r12+88]
    mov rbp, [r12+96]
    xor r13d, r13d
    jmp .Lprf_reply
.Lprf_output:
    mov r14, [r12+104]
    mov rbp, [r12+112]
    xor r13d, r13d
    jmp .Lprf_reply
.Lprf_input:
    mov r14, [r12+64]
    mov rbp, [r12+72]
    xor r13d, r13d
.Lprf_reply:
    lea rdi, [r15+128]
    xor eax, eax
    mov ecx, 8
    rep stosq
    mov rax, 0x3130524644525048 /* HPRDFR01 */
    mov [r15+128], rax
    mov [r15+136], r13
    mov [r15+144], rbp
    test r12, r12
    jz .Lprf_reply_header
    mov rax, [r12+56]
    mov [r15+152], rax
    mov rax, [r12+192]
    mov [r15+160], rax
    mov rax, [r12+184]
    mov [r15+168], rax
    mov rax, [r12+112]
    mov [r15+176], rax
    mov rax, [r12+96]
    mov [r15+184], rax
.Lprf_reply_header:
    mov edi, 1
    lea rsi, [r15+128]
    mov edx, 64
    call .Lprf_write_all
    test rax, rax
    jnz .Lprf_fatal
    test rbp, rbp
    jz .Lprf_loop
    mov edi, 1
    mov rsi, r14
    mov rdx, rbp
    call .Lprf_write_all
    test rax, rax
    jnz .Lprf_fatal
    jmp .Lprf_loop
.Lprf_eof:
    xor ebx, ebx
.Lprf_eof_context:
    mov r12, [r15+rbx*8]
    test r12, r12
    jz .Lprf_eof_next
    cmp qword ptr [r12+56], 4
    jne .Lprf_eof_maybe_release
    mov rdi, r12
    call parent_directory_close
    cmp rax, 64
    jne .Lprf_fatal
.Lprf_eof_maybe_release:
    cmp qword ptr [r12+56], 2
    jne .Lprf_eof_destroy
    mov rdi, r12
    call parent_directory_release
    test eax, eax
    jnz .Lprf_fatal
.Lprf_eof_destroy:
    mov rdi, r12
    call parent_directory_destroy
    test eax, eax
    jnz .Lprf_fatal
    mov qword ptr [r15+rbx*8], 0
.Lprf_eof_next:
    inc ebx
    cmp ebx, 2
    jb .Lprf_eof_context
    mov rdi, [r15+16]
    test rdi, rdi
    jz .Lprf_eof_control
    mov rsi, [r15+24]
    add rsi, 4096
    mov eax, 11
    syscall
    test rax, rax
    jnz .Lprf_fatal
.Lprf_eof_control:
    mov rdi, r15
    mov esi, 8192
    mov eax, 11
    syscall
    test rax, rax
    jnz .Lprf_fatal
    xor edi, edi
    mov eax, 60
    syscall
.Lprf_fatal:
    mov edi, 111
    mov eax, 60
    syscall

.Lprf_read_exact:
    push rbx
    push r12
    push r13
    push r14
    mov rbx, rdi
    mov r12, rsi
    mov r13, rdx
    xor r14d, r14d
.Lprf_read_loop:
    mov rdi, rbx
    lea rsi, [r12+r14]
    mov rdx, r13
    sub rdx, r14
    xor eax, eax
    syscall
    test rax, rax
    jz .Lprf_read_eof
    cmp rax, -4
    je .Lprf_read_loop
    cmp rax, -4095
    jae .Lprf_read_done
    add r14, rax
    cmp r14, r13
    jb .Lprf_read_loop
    mov rax, r13
    jmp .Lprf_read_done
.Lprf_read_eof:
    xor eax, eax
    test r14, r14
    jz .Lprf_read_done
    mov rax, -22
.Lprf_read_done:
    pop r14
    pop r13
    pop r12
    pop rbx
    ret
.Lprf_write_all:
    push rbx
    push r12
    push r13
    push r14
    mov rbx, rdi
    mov r12, rsi
    mov r13, rdx
    xor r14d, r14d
.Lprf_write_loop:
    cmp r14, r13
    je .Lprf_write_success
    mov rdi, rbx
    lea rsi, [r12+r14]
    mov rdx, r13
    sub rdx, r14
    mov eax, 1
    syscall
    cmp rax, -4
    je .Lprf_write_loop
    test rax, rax
    jz .Lprf_write_zero
    cmp rax, -4095
    jae .Lprf_write_done
    add r14, rax
    jmp .Lprf_write_loop
.Lprf_write_zero:
    mov rax, -5
    jmp .Lprf_write_done
.Lprf_write_success:
    xor eax, eax
.Lprf_write_done:
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

/* Immutable observer binding: rdi owned FD, rsi context, rdx event,
 * rcx complete owned span, r8 length. Full bytes are written synchronously. */
.Lprf_journal:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp, 136
    mov rbx, rdi
    mov r12, rsi
    mov r13, rdx
    mov r14, rcx
    mov r15, r8
    lea rdi, [rsp]
    xor eax, eax
    mov ecx, 16
    rep stosq
    mov rax, 0x3130524a44525048 /* HPRDJR01 */
    mov [rsp], rax
    mov [rsp+8], r13
    mov rax, [r12+192]
    mov [rsp+16], rax
    mov rax, [r12+248]
    mov [rsp+24], rax
    mov [rsp+32], r15
    mov rax, [r12+56]
    mov [rsp+40], rax
    mov rax, [r12+176]
    mov [rsp+48], rax
    mov rax, [r12+168]
    mov [rsp+56], rax
    mov rax, [r12+96]
    mov [rsp+64], rax
    mov rax, [r12+112]
    mov [rsp+72], rax
    mov rax, [r12+184]
    mov [rsp+80], rax
    mov rax, [r12+208]
    mov [rsp+88], rax
    mov rax, [r12+216]
    mov [rsp+96], rax
    mov rax, [r12+224]
    mov [rsp+104], rax
    mov rax, [r12+232]
    mov [rsp+112], rax
    mov rax, [r12+240]
    mov [rsp+120], rax
    mov rdi, rbx
    mov rsi, rsp
    mov edx, 128
    call .Lprf_write_all
    test rax, rax
    jnz .Lprf_journal_return
    mov rdi, rbx
    mov rsi, r14
    mov rdx, r15
    call .Lprf_write_all
    test rax, rax
    jnz .Lprf_journal_return
    cmp r13, 8
    jne .Lprf_journal_return
    cmp r15, 64
    jb .Lprf_journal_hook_bad
    /* The observer can delay a fixed raw OS request, never replace its result.
     * A separate actual fixture actor performs any frozen filesystem change. */
    mov rax, 0x31304b4844525048 /* HPRDHK01 */
    mov [rsp], rax
    mov rax, [r12+192]
    mov [rsp+8], rax
    mov rax, [r12+248]
    mov [rsp+16], rax
    mov rax, [r14+16]
    mov [rsp+24], rax
    mov rax, [r14+24]
    mov [rsp+32], rax
    mov rax, [r14+32]
    mov [rsp+40], rax
    mov rax, [r14+40]
    mov [rsp+48], rax
    mov rax, [r14+48]
    mov [rsp+56], rax
    mov edi, 4
    mov rsi, rsp
    mov edx, 64
    call .Lprf_write_all
    test rax, rax
    jnz .Lprf_journal_return
    mov edi, 5
    lea rsi, [rsp+128]
    mov edx, 8
    call .Lprf_read_exact
    cmp rax, 8
    jne .Lprf_journal_hook_bad
    cmp qword ptr [rsp+128], 0
    jne .Lprf_journal_hook_bad
    xor eax, eax
    jmp .Lprf_journal_return
.Lprf_journal_hook_bad:
    mov rax, -22
.Lprf_journal_return:
    add rsp, 136
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

.section .note.GNU-stack,"",@progbits
