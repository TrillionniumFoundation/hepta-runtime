/* Copyright 2026 Muvon Un Limited
 * SPDX-License-Identifier: Apache-2.0
 * Private two-context binary carrier. No public JSON command selects a native
 * address, fd, syscall, or image. The fixture owns stdin/stdout, FD3 journal,
 * FD4 effect notifications, FD5 acknowledgements and four held file FDs.
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
    jae .Lmtf_fatal
    mov edi, 4
    mov esi, 1
    xor edx, edx
    mov eax, 72
    syscall
    cmp rax, -4095
    jae .Lmtf_fatal
    mov edi, 5
    mov esi, 1
    xor edx, edx
    mov eax, 72
    syscall
    cmp rax, -4095
    jae .Lmtf_fatal
    mov edi, 4096
    call .Lmdt_map
    cmp rax, -4095
    jae .Lmtf_fatal
    mov r15, rax
.Lmtf_loop:
    xor edi, edi
    lea rsi, [r15+64]
    mov edx, 8
    call .Lmtf_read_exact
    test rax, rax
    jz .Lmtf_eof
    cmp rax, 8
    jne .Lmtf_fatal
    mov r13, [r15+64]
    cmp r13, 64
    jb .Lmtf_fatal
    cmp r13, 134217792
    ja .Lmtf_fatal
    lea rdi, [r15+16]
    mov rsi, r13
    call .Lmdt_grow
    test eax, eax
    jnz .Lmtf_fatal
    xor edi, edi
    mov rsi, [r15+16]
    mov rdx, r13
    call .Lmtf_read_exact
    cmp rax, r13
    jne .Lmtf_fatal
    mov rbp, [r15+16]
    mov rax, 0x3130514654444d48 /* HMDTFQ01 */
    cmp [rbp], rax
    jne .Lmtf_fatal
    mov rbx, [rbp+16]
    cmp rbx, 1
    ja .Lmtf_fatal
    mov r14, [rbp+8]
    cmp r14, 1
    jb .Lmtf_fatal
    cmp r14, 17
    ja .Lmtf_fatal
    mov rax, [rbp+32]
    or rax, [rbp+40]
    or rax, [rbp+48]
    or rax, [rbp+56]
    jnz .Lmtf_fatal
    sub r13, 64
    cmp [rbp+24], r13
    jne .Lmtf_fatal
    cmp r14, 1
    je .Lmtf_invoke
    cmp r14, 10
    je .Lmtf_hold_file
    cmp r14, 11
    je .Lmtf_hold_file
    test r13, r13
    jnz .Lmtf_fatal
    cmp r14, 8
    je .Lmtf_create_explicit
    cmp r14, 9
    je .Lmtf_create_unobserved
    cmp r14, 12
    je .Lmtf_drop_file
    cmp r14, 13
    je .Lmtf_drop_file
    cmp r14, 14
    je .Lmtf_file_stat
    cmp r14, 15
    je .Lmtf_file_stat
    cmp r14, 16
    je .Lmtf_close_retained
    cmp r14, 17
    je .Lmtf_close_retained
    mov r12, [r15+rbx*8]
    test r12, r12
    jz .Lmtf_no_context
    cmp r14, 2
    je .Lmtf_release
    cmp r14, 3
    je .Lmtf_destroy
    cmp r14, 4
    je .Lmtf_context
    cmp r14, 5
    je .Lmtf_workspace
    cmp r14, 6
    je .Lmtf_output
    cmp r14, 7
    je .Lmtf_input
    jmp .Lmtf_fatal
.Lmtf_invoke:
    mov r12, [r15+rbx*8]
    test r12, r12
    jnz .Lmtf_invoke_ready
    lea rdi, [rip+.Lmtf_journal]
    mov esi, 3
    call file_metadata_create
    cmp rax, -4095
    jae .Lmtf_fatal
    mov r12, rax
    mov [r15+rbx*8], rax
.Lmtf_invoke_ready:
    cmp r13, 96
    jb .Lmtf_no_context
    xor esi, esi
    xor edx, edx
    mov rax, [rbp+88]
    cmp rax, 2
    je .Lmtf_invoke_capabilities
    mov rsi, [r15+32+rbx*8]
    test rsi, rsi
    jz .Lmtf_no_context
    cmp rax, 3
    jne .Lmtf_invoke_capabilities
    mov rdx, [r15+48+rbx*8]
    test rdx, rdx
    jz .Lmtf_no_context
.Lmtf_invoke_capabilities:
    mov rdi, r12
    lea rcx, [rbp+64]
    mov r8, r13
    call file_metadata_invoke
.Lmtf_invocation_returned:
    mov r13, rax
    xor r14d, r14d
    xor ebp, ebp
    cmp rax, 64
    jne .Lmtf_reply
    mov r14, [r12+104]
    mov rbp, [r12+168]
    jmp .Lmtf_reply

.Lmtf_hold_file:
    mov r12, [r15+rbx*8]
    mov rax, r14
    sub rax, 10
    shl rax, 4
    add rax, 32
    lea rcx, [r15+rbx*8]
    cmp qword ptr [rcx+rax], 0
    jne .Lmtf_create_busy
    /* The carrier, not the metadata callable, opens this explicitly selected
     * fixture file. A read-only FD allows directories and nonblocking FIFOs
     * to reach the original metadata function's own regular-file checks. */
    lea rdi, [rbp+64]
    mov rsi, r13
    call .Lmdt_name
    test eax, eax
    jnz .Lmtf_no_context
    lea rdi, [rbp+64]
    mov esi, 0xa0800 /* O_RDONLY|O_CLOEXEC|O_NOFOLLOW|O_NONBLOCK */
    xor edx, edx
    mov eax, 2
    syscall
    mov r13, rax
    cmp rax, -4095
    jae .Lmtf_file_response
    mov rcx, r14
    sub rcx, 10
    shl rcx, 4
    add rcx, 32
    lea rdx, [r15+rbx*8]
    mov [rdx+rcx], rax
.Lmtf_file_response:
    xor r14d, r14d
    xor ebp, ebp
    jmp .Lmtf_reply
.Lmtf_drop_file:
    mov r12, [r15+rbx*8]
    sub r14, 12
    shl r14, 4
    add r14, 32
    lea rdx, [r15+rbx*8]
    mov rdi, [rdx+r14]
    test rdi, rdi
    jz .Lmtf_no_context
    mov eax, 3
    syscall
    lea rdx, [r15+rbx*8]
    mov qword ptr [rdx+r14], 0
    mov r13, rax
    jmp .Lmtf_file_response
.Lmtf_close_retained:
    /* Private negative-input fixture only: actually close the held FD while
     * keeping its numeric argument. No replacement FD is opened afterwards. */
    mov r12, [r15+rbx*8]
    sub r14, 16
    shl r14, 4
    add r14, 32
    lea rdx, [r15+rbx*8]
    mov rdi, [rdx+r14]
    test rdi, rdi
    jz .Lmtf_no_context
    mov eax, 3
    syscall
    mov r13, rax
    jmp .Lmtf_file_response
.Lmtf_file_stat:
    mov r12, [r15+rbx*8]
    sub r14, 14
    shl r14, 4
    add r14, 32
    lea rdx, [r15+rbx*8]
    mov rdi, [rdx+r14]
    test rdi, rdi
    jz .Lmtf_no_context
    lea rsi, [r15+512]
    mov eax, 5
    syscall
    mov r13, rax
    xor r14d, r14d
    xor ebp, ebp
    test rax, rax
    jnz .Lmtf_reply
    lea r14, [r15+512]
    mov ebp, 144
    jmp .Lmtf_reply

.Lmtf_release:
    mov rdi, r12
    call file_metadata_release
    mov r13, rax
    xor r14d, r14d
    xor ebp, ebp
    jmp .Lmtf_reply
.Lmtf_destroy:
    mov rdi, r12
    call file_metadata_destroy
    mov r13, rax
    test eax, eax
    jnz .Lmtf_destroy_response
    mov qword ptr [r15+rbx*8], 0
    xor r12d, r12d
.Lmtf_destroy_response:
    xor r14d, r14d
    xor ebp, ebp
    jmp .Lmtf_reply
.Lmtf_create_explicit:
    mov r12, [r15+rbx*8]
    test r12, r12
    jnz .Lmtf_create_busy
    lea rdi, [rip+.Lmtf_journal]
    mov esi, 3
    call file_metadata_create
    cmp rax, -4095
    jae .Lmtf_fatal
    mov r12, rax
    mov [r15+rbx*8], rax
    xor r13d, r13d
    xor r14d, r14d
    xor ebp, ebp
    jmp .Lmtf_reply
.Lmtf_create_unobserved:
    mov r12, [r15+rbx*8]
    test r12, r12
    jnz .Lmtf_create_busy
    xor edi, edi
    xor esi, esi
    call file_metadata_create
    cmp rax, -4095
    jae .Lmtf_fatal
    mov r12, rax
    mov [r15+rbx*8], rax
    xor r13d, r13d
    xor r14d, r14d
    xor ebp, ebp
    jmp .Lmtf_reply
.Lmtf_create_busy:
    mov r13d, 0xfffffffd
    xor r14d, r14d
    xor ebp, ebp
    jmp .Lmtf_reply
.Lmtf_no_context:
    mov r13d, 0xffffffff
    xor r14d, r14d
    xor ebp, ebp
    jmp .Lmtf_reply
.Lmtf_context:
    mov r14, r12
    mov ebp, 4096
    xor r13d, r13d
    jmp .Lmtf_reply
.Lmtf_workspace:
    mov r14, [r12+88]
    mov rbp, [r12+96]
    xor r13d, r13d
    jmp .Lmtf_reply
.Lmtf_output:
    mov r14, [r12+104]
    mov rbp, [r12+112]
    xor r13d, r13d
    jmp .Lmtf_reply
.Lmtf_input:
    mov r14, [r12+64]
    mov rbp, [r12+72]
    xor r13d, r13d
.Lmtf_reply:
    lea rdi, [r15+128]
    xor eax, eax
    mov ecx, 8
    rep stosq
    mov rax, 0x3130524654444d48 /* HMDTFR01 */
    mov [r15+128], rax
    mov [r15+136], r13
    mov [r15+144], rbp
    test r12, r12
    jz .Lmtf_reply_header
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
.Lmtf_reply_header:
    mov edi, 1
    lea rsi, [r15+128]
    mov edx, 64
    call .Lmtf_write_all
    test rax, rax
    jnz .Lmtf_fatal
    test rbp, rbp
    jz .Lmtf_loop
    mov edi, 1
    mov rsi, r14
    mov rdx, rbp
    call .Lmtf_write_all
    test rax, rax
    jnz .Lmtf_fatal
    jmp .Lmtf_loop
.Lmtf_eof:
    xor ebx, ebx
.Lmtf_eof_context:
    mov r12, [r15+rbx*8]
    test r12, r12
    jz .Lmtf_eof_parent
    cmp qword ptr [r12+56], 2
    jne .Lmtf_eof_destroy
    mov rdi, r12
    call file_metadata_release
    test eax, eax
    jnz .Lmtf_fatal
.Lmtf_eof_destroy:
    mov rdi, r12
    call file_metadata_destroy
    test eax, eax
    jnz .Lmtf_fatal
    mov qword ptr [r15+rbx*8], 0
.Lmtf_eof_parent:
    mov r14d, 32
.Lmtf_eof_file:
    lea rdx, [r15+rbx*8]
    mov rdi, [rdx+r14]
    test rdi, rdi
    jz .Lmtf_eof_file_next
    mov eax, 3
    syscall
    test rax, rax
    jz .Lmtf_eof_file_closed
    cmp rax, -9 /* only the explicit close-retained negative fixture */
    jne .Lmtf_fatal
.Lmtf_eof_file_closed:
    lea rdx, [r15+rbx*8]
    mov qword ptr [rdx+r14], 0
.Lmtf_eof_file_next:
    add r14, 16
    cmp r14, 64
    jb .Lmtf_eof_file
.Lmtf_eof_next:
    inc ebx
    cmp ebx, 2
    jb .Lmtf_eof_context
    mov rdi, [r15+16]
    test rdi, rdi
    jz .Lmtf_eof_control
    mov rsi, [r15+24]
    add rsi, 4096
    mov eax, 11
    syscall
    test rax, rax
    jnz .Lmtf_fatal
.Lmtf_eof_control:
    mov rdi, r15
    mov esi, 8192
    mov eax, 11
    syscall
    test rax, rax
    jnz .Lmtf_fatal
    xor edi, edi
    mov eax, 60
    syscall
.Lmtf_fatal:
    mov edi, 111
    mov eax, 60
    syscall

.Lmtf_read_exact:
    push rbx
    push r12
    push r13
    push r14
    mov rbx, rdi
    mov r12, rsi
    mov r13, rdx
    xor r14d, r14d
.Lmtf_read_loop:
    mov rdi, rbx
    lea rsi, [r12+r14]
    mov rdx, r13
    sub rdx, r14
    xor eax, eax
    syscall
    test rax, rax
    jz .Lmtf_read_eof
    cmp rax, -4
    je .Lmtf_read_loop
    cmp rax, -4095
    jae .Lmtf_read_done
    add r14, rax
    cmp r14, r13
    jb .Lmtf_read_loop
    mov rax, r13
    jmp .Lmtf_read_done
.Lmtf_read_eof:
    xor eax, eax
    test r14, r14
    jz .Lmtf_read_done
    mov rax, -22
.Lmtf_read_done:
    pop r14
    pop r13
    pop r12
    pop rbx
    ret
.Lmtf_write_all:
    push rbx
    push r12
    push r13
    push r14
    mov rbx, rdi
    mov r12, rsi
    mov r13, rdx
    xor r14d, r14d
.Lmtf_write_loop:
    cmp r14, r13
    je .Lmtf_write_success
    mov rdi, rbx
    lea rsi, [r12+r14]
    mov rdx, r13
    sub rdx, r14
    mov eax, 1
    syscall
    cmp rax, -4
    je .Lmtf_write_loop
    test rax, rax
    jz .Lmtf_write_zero
    cmp rax, -4095
    jae .Lmtf_write_done
    add r14, rax
    jmp .Lmtf_write_loop
.Lmtf_write_zero:
    mov rax, -5
    jmp .Lmtf_write_done
.Lmtf_write_success:
    xor eax, eax
.Lmtf_write_done:
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

/* Immutable observer binding: rdi owned FD, rsi context, rdx event,
 * rcx complete owned span, r8 length. Full bytes are written synchronously. */
.Lmtf_journal:
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
    mov rax, 0x3130524a54444d48 /* HMDTJR01 */
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
    call .Lmtf_write_all
    test rax, rax
    jnz .Lmtf_journal_return
    mov rdi, rbx
    mov rsi, r14
    mov rdx, r15
    call .Lmtf_write_all
    test rax, rax
    jnz .Lmtf_journal_return
    cmp r13, 8
    jne .Lmtf_journal_return
    cmp r15, 64
    jb .Lmtf_journal_hook_bad
    /* The observer can delay a fixed raw OS request, never replace its result.
     * A separate actual fixture actor performs any frozen filesystem change. */
    mov rax, 0x31304b4854444d48 /* HMDTHK01 */
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
    call .Lmtf_write_all
    test rax, rax
    jnz .Lmtf_journal_return
    mov edi, 5
    lea rsi, [rsp+128]
    mov edx, 8
    call .Lmtf_read_exact
    cmp rax, 8
    jne .Lmtf_journal_hook_bad
    cmp qword ptr [rsp+128], 0
    jne .Lmtf_journal_hook_bad
    xor eax, eax
    jmp .Lmtf_journal_return
.Lmtf_journal_hook_bad:
    mov rax, -22
.Lmtf_journal_return:
    add rsp, 136
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret
