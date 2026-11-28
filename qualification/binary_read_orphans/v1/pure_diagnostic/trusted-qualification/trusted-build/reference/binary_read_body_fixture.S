/* Copyright 2026 Muvon Un Limited
 * SPDX-License-Identifier: Apache-2.0
 * Private two-context binary carrier. No public JSON command selects a native
 * address, fd, syscall, or image. The fixture owns stdin/stdout, FD3 journal,
 * FD4 effect notifications, FD5 acknowledgements and its two held parents.
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
    jae .Lbrf_fatal
    mov edi, 4
    mov esi, 1
    xor edx, edx
    mov eax, 72
    syscall
    cmp rax, -4095
    jae .Lbrf_fatal
    mov edi, 5
    mov esi, 1
    xor edx, edx
    mov eax, 72
    syscall
    cmp rax, -4095
    jae .Lbrf_fatal
    mov edi, 4096
    call .Lbrd_map
    cmp rax, -4095
    jae .Lbrf_fatal
    mov r15, rax
.Lbrf_loop:
    xor edi, edi
    lea rsi, [r15+64]
    mov edx, 8
    call .Lbrf_read_exact
    test rax, rax
    jz .Lbrf_eof
    cmp rax, 8
    jne .Lbrf_fatal
    mov r13, [r15+64]
    cmp r13, 64
    jb .Lbrf_fatal
    cmp r13, 134217792
    ja .Lbrf_fatal
    lea rdi, [r15+16]
    mov rsi, r13
    call .Lbrd_grow
    test eax, eax
    jnz .Lbrf_fatal
    xor edi, edi
    mov rsi, [r15+16]
    mov rdx, r13
    call .Lbrf_read_exact
    cmp rax, r13
    jne .Lbrf_fatal
    mov rbp, [r15+16]
    mov rax, 0x3130514644524248 /* HBRDFQ01 */
    cmp [rbp], rax
    jne .Lbrf_fatal
    mov rbx, [rbp+16]
    cmp rbx, 1
    ja .Lbrf_fatal
    mov r14, [rbp+8]
    cmp r14, 1
    jb .Lbrf_fatal
    cmp r14, 13
    ja .Lbrf_fatal
    mov rax, [rbp+32]
    or rax, [rbp+40]
    or rax, [rbp+48]
    or rax, [rbp+56]
    jnz .Lbrf_fatal
    sub r13, 64
    cmp [rbp+24], r13
    jne .Lbrf_fatal
    cmp r14, 1
    je .Lbrf_invoke
    cmp r14, 10
    je .Lbrf_hold_parent
    cmp r14, 11
    je .Lbrf_invoke_at
    test r13, r13
    jnz .Lbrf_fatal
    cmp r14, 8
    je .Lbrf_create_explicit
    cmp r14, 9
    je .Lbrf_create_unobserved
    cmp r14, 12
    je .Lbrf_drop_parent
    cmp r14, 13
    je .Lbrf_parent_stat
    mov r12, [r15+rbx*8]
    test r12, r12
    jz .Lbrf_no_context
    cmp r14, 2
    je .Lbrf_release
    cmp r14, 3
    je .Lbrf_destroy
    cmp r14, 4
    je .Lbrf_context
    cmp r14, 5
    je .Lbrf_workspace
    cmp r14, 6
    je .Lbrf_output
    cmp r14, 7
    je .Lbrf_input
    jmp .Lbrf_fatal
.Lbrf_invoke:
    mov r12, [r15+rbx*8]
    test r12, r12
    jnz .Lbrf_invoke_ready
    lea rdi, [rip+.Lbrf_journal]
    mov esi, 3
    call binary_read_body_create
    cmp rax, -4095
    jae .Lbrf_fatal
    mov r12, rax
    mov [r15+rbx*8], rax
.Lbrf_invoke_ready:
    mov rdi, r12
    lea rsi, [rbp+64]
    mov rdx, r13
    call binary_read_body_invoke
.Lbrf_invocation_returned:
    mov r13, rax
    xor r14d, r14d
    xor ebp, ebp
    cmp rax, 64
    jne .Lbrf_reply
    mov r14, [r12+104]
    mov rbp, [r12+168]
    jmp .Lbrf_reply

.Lbrf_hold_parent:
    mov r12, [r15+rbx*8]
    cmp qword ptr [r15+32+rbx*8], 0
    jne .Lbrf_create_busy
    lea rdi, [rbp+64]
    mov rsi, r13
    call .Lbrd_name
    test eax, eax
    jnz .Lbrf_no_context
    lea rdi, [rbp+64]
    mov esi, 0xb0000
    xor edx, edx
    mov eax, 2
    syscall
    mov r13, rax
    xor r14d, r14d
    xor ebp, ebp
    cmp rax, -4095
    jae .Lbrf_reply
    mov [r15+32+rbx*8], rax
    jmp .Lbrf_reply
.Lbrf_invoke_at:
    mov r12, [r15+rbx*8]
    cmp qword ptr [r15+32+rbx*8], 0
    je .Lbrf_no_context
    test r12, r12
    jnz .Lbrf_invoke_at_ready
    lea rdi, [rip+.Lbrf_journal]
    mov esi, 3
    call binary_read_body_create
    cmp rax, -4095
    jae .Lbrf_fatal
    mov r12, rax
    mov [r15+rbx*8], rax
.Lbrf_invoke_at_ready:
    mov rdi, r12
    mov rsi, [r15+32+rbx*8]
    lea rdx, [rbp+64]
    mov rcx, r13
    call binary_read_body_invoke_at
    jmp .Lbrf_invocation_returned
.Lbrf_drop_parent:
    mov r12, [r15+rbx*8]
    mov rdi, [r15+32+rbx*8]
    test rdi, rdi
    jz .Lbrf_no_context
    mov eax, 3
    syscall
    mov qword ptr [r15+32+rbx*8], 0
    mov r13, rax
    xor r14d, r14d
    xor ebp, ebp
    jmp .Lbrf_reply
.Lbrf_parent_stat:
    mov r12, [r15+rbx*8]
    mov rdi, [r15+32+rbx*8]
    test rdi, rdi
    jz .Lbrf_no_context
    lea rsi, [r15+512]
    mov eax, 5
    syscall
    mov r13, rax
    xor r14d, r14d
    xor ebp, ebp
    test rax, rax
    jnz .Lbrf_reply
    lea r14, [r15+512]
    mov ebp, 144
    jmp .Lbrf_reply

.Lbrf_release:
    mov rdi, r12
    call binary_read_body_release
    mov r13, rax
    xor r14d, r14d
    xor ebp, ebp
    jmp .Lbrf_reply
.Lbrf_destroy:
    mov rdi, r12
    call binary_read_body_destroy
    mov r13, rax
    test eax, eax
    jnz .Lbrf_destroy_response
    mov qword ptr [r15+rbx*8], 0
    xor r12d, r12d
.Lbrf_destroy_response:
    xor r14d, r14d
    xor ebp, ebp
    jmp .Lbrf_reply
.Lbrf_create_explicit:
    mov r12, [r15+rbx*8]
    test r12, r12
    jnz .Lbrf_create_busy
    lea rdi, [rip+.Lbrf_journal]
    mov esi, 3
    call binary_read_body_create
    cmp rax, -4095
    jae .Lbrf_fatal
    mov r12, rax
    mov [r15+rbx*8], rax
    xor r13d, r13d
    xor r14d, r14d
    xor ebp, ebp
    jmp .Lbrf_reply
.Lbrf_create_unobserved:
    mov r12, [r15+rbx*8]
    test r12, r12
    jnz .Lbrf_create_busy
    xor edi, edi
    xor esi, esi
    call binary_read_body_create
    cmp rax, -4095
    jae .Lbrf_fatal
    mov r12, rax
    mov [r15+rbx*8], rax
    xor r13d, r13d
    xor r14d, r14d
    xor ebp, ebp
    jmp .Lbrf_reply
.Lbrf_create_busy:
    mov r13d, 0xfffffffd
    xor r14d, r14d
    xor ebp, ebp
    jmp .Lbrf_reply
.Lbrf_no_context:
    mov r13d, 0xffffffff
    xor r14d, r14d
    xor ebp, ebp
    jmp .Lbrf_reply
.Lbrf_context:
    mov r14, r12
    mov ebp, 4096
    xor r13d, r13d
    jmp .Lbrf_reply
.Lbrf_workspace:
    mov r14, [r12+88]
    mov rbp, [r12+96]
    xor r13d, r13d
    jmp .Lbrf_reply
.Lbrf_output:
    mov r14, [r12+104]
    mov rbp, [r12+112]
    xor r13d, r13d
    jmp .Lbrf_reply
.Lbrf_input:
    mov r14, [r12+64]
    mov rbp, [r12+72]
    xor r13d, r13d
.Lbrf_reply:
    lea rdi, [r15+128]
    xor eax, eax
    mov ecx, 8
    rep stosq
    mov rax, 0x3130524644524248 /* HBRDFR01 */
    mov [r15+128], rax
    mov [r15+136], r13
    mov [r15+144], rbp
    test r12, r12
    jz .Lbrf_reply_header
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
.Lbrf_reply_header:
    mov edi, 1
    lea rsi, [r15+128]
    mov edx, 64
    call .Lbrf_write_all
    test rax, rax
    jnz .Lbrf_fatal
    test rbp, rbp
    jz .Lbrf_loop
    mov edi, 1
    mov rsi, r14
    mov rdx, rbp
    call .Lbrf_write_all
    test rax, rax
    jnz .Lbrf_fatal
    jmp .Lbrf_loop
.Lbrf_eof:
    xor ebx, ebx
.Lbrf_eof_context:
    mov r12, [r15+rbx*8]
    test r12, r12
    jz .Lbrf_eof_parent
    cmp qword ptr [r12+56], 2
    jne .Lbrf_eof_destroy
    mov rdi, r12
    call binary_read_body_release
    test eax, eax
    jnz .Lbrf_fatal
.Lbrf_eof_destroy:
    mov rdi, r12
    call binary_read_body_destroy
    test eax, eax
    jnz .Lbrf_fatal
    mov qword ptr [r15+rbx*8], 0
.Lbrf_eof_parent:
    mov rdi, [r15+32+rbx*8]
    test rdi, rdi
    jz .Lbrf_eof_next
    mov eax, 3
    syscall
    test rax, rax
    jnz .Lbrf_fatal
    mov qword ptr [r15+32+rbx*8], 0
.Lbrf_eof_next:
    inc ebx
    cmp ebx, 2
    jb .Lbrf_eof_context
    mov rdi, [r15+16]
    test rdi, rdi
    jz .Lbrf_eof_control
    mov rsi, [r15+24]
    add rsi, 4096
    mov eax, 11
    syscall
    test rax, rax
    jnz .Lbrf_fatal
.Lbrf_eof_control:
    mov rdi, r15
    mov esi, 8192
    mov eax, 11
    syscall
    test rax, rax
    jnz .Lbrf_fatal
    xor edi, edi
    mov eax, 60
    syscall
.Lbrf_fatal:
    mov edi, 111
    mov eax, 60
    syscall

.Lbrf_read_exact:
    push rbx
    push r12
    push r13
    push r14
    mov rbx, rdi
    mov r12, rsi
    mov r13, rdx
    xor r14d, r14d
.Lbrf_read_loop:
    mov rdi, rbx
    lea rsi, [r12+r14]
    mov rdx, r13
    sub rdx, r14
    xor eax, eax
    syscall
    test rax, rax
    jz .Lbrf_read_eof
    cmp rax, -4
    je .Lbrf_read_loop
    cmp rax, -4095
    jae .Lbrf_read_done
    add r14, rax
    cmp r14, r13
    jb .Lbrf_read_loop
    mov rax, r13
    jmp .Lbrf_read_done
.Lbrf_read_eof:
    xor eax, eax
    test r14, r14
    jz .Lbrf_read_done
    mov rax, -22
.Lbrf_read_done:
    pop r14
    pop r13
    pop r12
    pop rbx
    ret
.Lbrf_write_all:
    push rbx
    push r12
    push r13
    push r14
    mov rbx, rdi
    mov r12, rsi
    mov r13, rdx
    xor r14d, r14d
.Lbrf_write_loop:
    cmp r14, r13
    je .Lbrf_write_success
    mov rdi, rbx
    lea rsi, [r12+r14]
    mov rdx, r13
    sub rdx, r14
    mov eax, 1
    syscall
    cmp rax, -4
    je .Lbrf_write_loop
    test rax, rax
    jz .Lbrf_write_zero
    cmp rax, -4095
    jae .Lbrf_write_done
    add r14, rax
    jmp .Lbrf_write_loop
.Lbrf_write_zero:
    mov rax, -5
    jmp .Lbrf_write_done
.Lbrf_write_success:
    xor eax, eax
.Lbrf_write_done:
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

/* Immutable observer binding: rdi owned FD, rsi context, rdx event,
 * rcx complete owned span, r8 length. Full bytes are written synchronously. */
.Lbrf_journal:
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
    mov rax, 0x3130524a44524248 /* HBRDJR01 */
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
    call .Lbrf_write_all
    test rax, rax
    jnz .Lbrf_journal_return
    mov rdi, rbx
    mov rsi, r14
    mov rdx, r15
    call .Lbrf_write_all
    test rax, rax
    jnz .Lbrf_journal_return
    cmp r13, 8
    jne .Lbrf_journal_return
    cmp r15, 64
    jb .Lbrf_journal_hook_bad
    /* The observer can delay a fixed raw OS request, never replace its result.
     * A separate actual fixture actor performs any frozen filesystem change. */
    mov rax, 0x31304b4844524248 /* HBRDHK01 */
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
    call .Lbrf_write_all
    test rax, rax
    jnz .Lbrf_journal_return
    mov edi, 5
    lea rsi, [rsp+128]
    mov edx, 8
    call .Lbrf_read_exact
    cmp rax, 8
    jne .Lbrf_journal_hook_bad
    cmp qword ptr [rsp+128], 0
    jne .Lbrf_journal_hook_bad
    xor eax, eax
    jmp .Lbrf_journal_return
.Lbrf_journal_hook_bad:
    mov rax, -22
.Lbrf_journal_return:
    add rsp, 136
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret
