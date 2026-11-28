/* Copyright 2026 Muvon Un Limited
 * SPDX-License-Identifier: Apache-2.0
 * Private two-context binary carrier. No public JSON command selects a native
 * address, fd, syscall, or image. The fixture alone owns stdin/stdout and FD3.
 */
.intel_syntax noprefix
.section .text
.global _start
_start:
    and rsp, -16
    cld
    mov edi, 3
    mov esi, 1 /* F_GETFD */
    xor edx, edx
    mov eax, 72
    syscall
    cmp rax, -4095
    jae .Lpf_fatal
    mov edi, 4096
    call .Lptp_map
    cmp rax, -4095
    jae .Lpf_fatal
    mov r15, rax
.Lpf_loop:
    xor edi, edi
    lea rsi, [r15+64]
    mov edx, 8
    call .Lpf_read_exact
    test rax, rax
    jz .Lpf_eof
    cmp rax, 8
    jne .Lpf_fatal
    mov r13, [r15+64]
    cmp r13, 64
    jb .Lpf_fatal
    cmp r13, 50331776
    ja .Lpf_fatal
    lea rdi, [r15+16]
    mov rsi, r13
    call .Lptp_grow
    test eax, eax
    jnz .Lpf_fatal
    xor edi, edi
    mov rsi, [r15+16]
    mov rdx, r13
    call .Lpf_read_exact
    cmp rax, r13
    jne .Lpf_fatal
    mov rbp, [r15+16]
    mov rax, 0x3130514643505448 /* HTPCFQ01 */
    cmp [rbp], rax
    jne .Lpf_fatal
    mov rbx, [rbp+16]
    cmp rbx, 1
    ja .Lpf_fatal
    mov r14, [rbp+8]
    cmp r14, 1
    jb .Lpf_fatal
    cmp r14, 8
    ja .Lpf_fatal
    mov rax, [rbp+32]
    or rax, [rbp+40]
    or rax, [rbp+48]
    or rax, [rbp+56]
    jnz .Lpf_fatal
    sub r13, 64
    cmp [rbp+24], r13
    jne .Lpf_fatal
    cmp r14, 1
    je .Lpf_invoke
    test r13, r13
    jnz .Lpf_fatal
    cmp r14, 8
    je .Lpf_create_explicit
    mov r12, [r15+rbx*8]
    test r12, r12
    jz .Lpf_no_context
    cmp r14, 2
    je .Lpf_release
    cmp r14, 3
    je .Lpf_destroy
    cmp r14, 4
    je .Lpf_context
    cmp r14, 5
    je .Lpf_workspace
    cmp r14, 6
    je .Lpf_output
    cmp r14, 7
    je .Lpf_input
    jmp .Lpf_fatal
.Lpf_invoke:
    mov r12, [r15+rbx*8]
    test r12, r12
    jnz .Lpf_invoke_ready
    lea rdi, [rip+.Lpf_journal]
    mov esi, 3
    call text_publication_create
    cmp rax, -4095
    jae .Lpf_fatal
    mov r12, rax
    mov [r15+rbx*8], rax
.Lpf_invoke_ready:
    mov rdi, r12
    lea rsi, [rbp+64]
    mov rdx, r13
    call text_publication_invoke
    mov r13, rax
    xor r14d, r14d
    xor ebp, ebp
    cmp rax, 64
    jne .Lpf_reply
    mov r14, [r12+104]
    mov rbp, [r12+168]
    jmp .Lpf_reply
.Lpf_release:
    mov rdi, r12
    call text_publication_release
    mov r13, rax
    xor r14d, r14d
    xor ebp, ebp
    jmp .Lpf_reply
.Lpf_destroy:
    mov rdi, r12
    call text_publication_destroy
    mov r13, rax
    test eax, eax
    jnz .Lpf_destroy_response
    mov qword ptr [r15+rbx*8], 0
    xor r12d, r12d
.Lpf_destroy_response:
    xor r14d, r14d
    xor ebp, ebp
    jmp .Lpf_reply
.Lpf_create_explicit:
    mov r12, [r15+rbx*8]
    test r12, r12
    jnz .Lpf_create_busy
    lea rdi, [rip+.Lpf_journal]
    mov esi, 3
    call text_publication_create
    cmp rax, -4095
    jae .Lpf_fatal
    mov r12, rax
    mov [r15+rbx*8], rax
    xor r13d, r13d
    xor r14d, r14d
    xor ebp, ebp
    jmp .Lpf_reply
.Lpf_create_busy:
    mov r13d, 0xfffffffd
    xor r14d, r14d
    xor ebp, ebp
    jmp .Lpf_reply
.Lpf_no_context:
    mov r13d, 0xffffffff
    xor r14d, r14d
    xor ebp, ebp
    jmp .Lpf_reply
.Lpf_context:
    mov r14, r12
    mov ebp, 4096
    xor r13d, r13d
    jmp .Lpf_reply
.Lpf_workspace:
    mov r14, [r12+88]
    mov rbp, [r12+96]
    xor r13d, r13d
    jmp .Lpf_reply
.Lpf_output:
    mov r14, [r12+104]
    mov rbp, [r12+112]
    xor r13d, r13d
    jmp .Lpf_reply
.Lpf_input:
    mov r14, [r12+64]
    mov rbp, [r12+72]
    xor r13d, r13d
.Lpf_reply:
    lea rdi, [r15+128]
    xor eax, eax
    mov ecx, 8
    rep stosq
    mov rax, 0x3130524643505448 /* HTPCFR01 */
    mov [r15+128], rax
    mov [r15+136], r13
    mov [r15+144], rbp
    test r12, r12
    jz .Lpf_reply_header
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
.Lpf_reply_header:
    mov edi, 1
    lea rsi, [r15+128]
    mov edx, 64
    call .Lpf_write_all
    test rax, rax
    jnz .Lpf_fatal
    test rbp, rbp
    jz .Lpf_loop
    mov edi, 1
    mov rsi, r14
    mov rdx, rbp
    call .Lpf_write_all
    test rax, rax
    jnz .Lpf_fatal
    jmp .Lpf_loop
.Lpf_eof:
    xor ebx, ebx
.Lpf_eof_context:
    mov r12, [r15+rbx*8]
    test r12, r12
    jz .Lpf_eof_next
    cmp qword ptr [r12+56], 2
    jne .Lpf_eof_destroy
    mov rdi, r12
    call text_publication_release
    test eax, eax
    jnz .Lpf_fatal
.Lpf_eof_destroy:
    mov rdi, r12
    call text_publication_destroy
    test eax, eax
    jnz .Lpf_fatal
    mov qword ptr [r15+rbx*8], 0
.Lpf_eof_next:
    inc ebx
    cmp ebx, 2
    jb .Lpf_eof_context
    mov rdi, [r15+16]
    test rdi, rdi
    jz .Lpf_eof_control
    mov rsi, [r15+24]
    add rsi, 4096
    mov eax, 11
    syscall
    test rax, rax
    jnz .Lpf_fatal
.Lpf_eof_control:
    mov rdi, r15
    mov esi, 8192
    mov eax, 11
    syscall
    test rax, rax
    jnz .Lpf_fatal
    xor edi, edi
    mov eax, 60
    syscall
.Lpf_fatal:
    mov edi, 111
    mov eax, 60
    syscall

.Lpf_read_exact:
    push rbx
    push r12
    push r13
    push r14
    mov rbx, rdi
    mov r12, rsi
    mov r13, rdx
    xor r14d, r14d
.Lpf_read_loop:
    mov rdi, rbx
    lea rsi, [r12+r14]
    mov rdx, r13
    sub rdx, r14
    xor eax, eax
    syscall
    test rax, rax
    jz .Lpf_read_eof
    cmp rax, -4
    je .Lpf_read_loop
    cmp rax, -4095
    jae .Lpf_read_done
    add r14, rax
    cmp r14, r13
    jb .Lpf_read_loop
    mov rax, r13
    jmp .Lpf_read_done
.Lpf_read_eof:
    xor eax, eax
    test r14, r14
    jz .Lpf_read_done
    mov rax, -22
.Lpf_read_done:
    pop r14
    pop r13
    pop r12
    pop rbx
    ret
.Lpf_write_all:
    push rbx
    push r12
    push r13
    push r14
    mov rbx, rdi
    mov r12, rsi
    mov r13, rdx
    xor r14d, r14d
.Lpf_write_loop:
    cmp r14, r13
    je .Lpf_write_success
    mov rdi, rbx
    lea rsi, [r12+r14]
    mov rdx, r13
    sub rdx, r14
    mov eax, 1
    syscall
    cmp rax, -4
    je .Lpf_write_loop
    test rax, rax
    jz .Lpf_write_zero
    cmp rax, -4095
    jae .Lpf_write_done
    add r14, rax
    jmp .Lpf_write_loop
.Lpf_write_zero:
    mov rax, -5
    jmp .Lpf_write_done
.Lpf_write_success:
    xor eax, eax
.Lpf_write_done:
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

/* Immutable observer binding: rdi owned FD, rsi context, rdx event,
 * rcx complete owned span, r8 length. Full bytes are written synchronously. */
.Lpf_journal:
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
    mov rax, 0x3130524a43505448 /* HTPCJR01 */
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
    call .Lpf_write_all
    test rax, rax
    jnz .Lpf_journal_return
    mov rdi, rbx
    mov rsi, r14
    mov rdx, r15
    call .Lpf_write_all
.Lpf_journal_return:
    add rsp, 136
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret
