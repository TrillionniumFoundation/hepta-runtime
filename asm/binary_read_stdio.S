/* Copyright 2026 Muvon Un Limited
 * Copyright 2026 TrillionniumFoundation
 * SPDX-License-Identifier: Apache-2.0
 *
 * One-shot byte transport for the fixed HIA binary-read operation.
 * Policy, file handling, encoding and diagnostic text are existing HIA owners.
 * This entry only owns stdin, native buffers, completed response publication
 * and process lifetime. HBRH_OBSERVE is a fixed build-time fixture constant;
 * the production image has no journal entry or descriptor selection path.
 */
.intel_syntax noprefix
.section .text
.global _start
.type _start, @function
_start:
    and rsp, -16
    cld
    /* The fixed bootstrap requires the helper to die with its original parent.
     * Arm before reading stdin and close the getppid/prctl race by rechecking. */
    mov eax, 110
    syscall
    cmp rax, 1
    jbe .Lbrh_fatal
    mov r12, rax
    mov edi, 1
    mov esi, 9
    xor edx, edx
    xor r10d, r10d
    xor r8d, r8d
    mov eax, 157
    syscall
    test rax, rax
    jnz .Lbrh_fatal
    mov eax, 110
    syscall
    cmp rax, r12
    jne .Lbrh_fatal
.if HBRH_OBSERVE
    mov edi, 3
    mov esi, 1
    xor edx, edx
    mov eax, 72
    syscall
    cmp rax, -4095
    jae .Lbrh_fatal
    mov edi, 4
    mov esi, 1
    xor edx, edx
    mov eax, 72
    syscall
    cmp rax, -4095
    jae .Lbrh_fatal
.endif
    mov edi, 4096
    call .Lbrd_map
    cmp rax, -4095
    jae .Lbrh_fatal
    mov r15, rax
    lea rdi, [r15+8]
    mov esi, 65536
    call .Lbrd_grow
    test eax, eax
    jnz .Lbrh_fatal
.Lbrh_input:
    mov rax, [r15+24]
    cmp rax, [r15+16]
    jb .Lbrh_read
    cmp rax, B_MAX_INPUT
    jae .Lbrh_limit
    lea rsi, [rax+rax]
    cmp rsi, B_MAX_INPUT
    jbe .Lbrh_input_grow
    mov esi, B_MAX_INPUT
.Lbrh_input_grow:
    lea rdi, [r15+8]
    call .Lbrd_grow
    test eax, eax
    jnz .Lbrh_fatal
.Lbrh_read:
    xor edi, edi
    mov rsi, [r15+8]
    add rsi, [r15+24]
    mov rdx, [r15+16]
    sub rdx, [r15+24]
    xor eax, eax
    syscall
    cmp rax, -4
    je .Lbrh_read
    cmp rax, -4095
    jae .Lbrh_fatal
    test rax, rax
    jz .Lbrh_eof
    add [r15+24], rax
    jmp .Lbrh_input
.Lbrh_limit:
    xor edi, edi
    lea rsi, [r15+128]
    mov edx, 1
    xor eax, eax
    syscall
    cmp rax, -4
    je .Lbrh_limit
    test rax, rax
    jnz .Lbrh_fatal
.Lbrh_eof:
    cmp qword ptr [r15+24], 96
    jb .Lbrh_fatal
    mov r12, [r15+8]
    mov rax, 0x3130305144524248 /* HBRDQ001 */
    cmp [r12], rax
    jne .Lbrh_fatal
    cmp qword ptr [r12+8], 1
    jne .Lbrh_fatal
    cmp qword ptr [r12+16], 0
    jne .Lbrh_fatal
    cmp qword ptr [r12+24], 1
    jne .Lbrh_fatal
.if HBRH_OBSERVE
    lea rdi, [rip+.Lbrh_body_journal]
    mov esi, 3
.else
    xor edi, edi
    xor esi, esi
.endif
    call binary_read_body_create
    cmp rax, -4095
    jae .Lbrh_fatal
    mov [r15], rax
    mov rdi, rax
    mov rsi, [r15+8]
    mov rdx, [r15+24]
    call binary_read_body_invoke
    cmp rax, 64
    jne .Lbrh_fatal
    mov r12, [r15]
    cmp qword ptr [r12+56], 2
    jne .Lbrh_fatal
    cmp qword ptr [r12+184], 0
    jne .Lbrh_fatal
    mov r13, [r12+104]
    mov r14, [r12+168]
    cmp r14, 64
    jb .Lbrh_fatal
    mov rax, 0x3130305344524248 /* HBRDS001 */
    cmp [r13], rax
    jne .Lbrh_fatal
    mov rax, [r13+56]
    add rax, 64
    jc .Lbrh_fatal
    cmp rax, r14
    jne .Lbrh_fatal
    cmp qword ptr [r13+8], 0
    je .Lbrh_success
    cmp qword ptr [r13+8], 3
    jne .Lbrh_fatal
    lea rdi, [r15+48]
    mov esi, 12288
    call .Lbrd_grow
    test eax, eax
    jnz .Lbrh_fatal
    lea rdi, [r15+32]
    mov esi, 4096
    call .Lbrd_grow
    test eax, eax
    jnz .Lbrh_fatal
.Lbrh_format:
    inc qword ptr [r15+96]
    mov qword ptr [r15+104], 0
.if HBRH_OBSERVE
    mov rdi, r15
    mov esi, 1
    mov rdx, r13
    mov rcx, r14
    call .Lbrh_format_journal
    test rax, rax
    jnz .Lbrh_fatal
    mov rdi, r15
    mov esi, 2
    mov rdx, [r15+48]
    mov rcx, [r15+56]
    call .Lbrh_format_journal
    test rax, rax
    jnz .Lbrh_fatal
    mov rdi, r15
    mov esi, 3
    mov rdx, [r15+32]
    mov rcx, [r15+40]
    call .Lbrh_format_journal
    test rax, rax
    jnz .Lbrh_fatal
.endif
    mov rdi, r13
    mov rsi, r14
    mov rdx, [r15+32]
    mov rcx, [r15+40]
    mov r8, [r15+48]
    mov r9, [r15+56]
    call .Lbrh_error
    mov [r15+104], rax
.if HBRH_OBSERVE
    mov rdi, r15
    mov esi, 4
    mov rdx, [r15+32]
    mov rcx, [r15+40]
    call .Lbrh_format_journal
    test rax, rax
    jnz .Lbrh_fatal
    mov rdi, r15
    mov esi, 5
    mov rdx, [r15+48]
    mov rcx, [r15+56]
    call .Lbrh_format_journal
    test rax, rax
    jnz .Lbrh_fatal
.endif
    mov rax, [r15+104]
    cmp eax, 0xfffffffe
    je .Lbrh_format_grow
    test rax, rax
    jz .Lbrh_fatal
    cmp rax, [r15+40]
    ja .Lbrh_fatal
    mov [r15+88], rax
    mov rax, [r15+32]
    mov [r15+80], rax
    mov qword ptr [r15+64], 2
    mov qword ptr [r15+72], 1
    jmp .Lbrh_publish
.Lbrh_format_grow:
    mov rsi, [r15+40]
    cmp rsi, B_MAX_OUT
    jae .Lbrh_fatal
    add rsi, rsi
    lea rdi, [r15+32]
    call .Lbrd_grow
    test eax, eax
    jnz .Lbrh_fatal
    jmp .Lbrh_format
.Lbrh_success:
    lea rax, [r13+64]
    mov [r15+80], rax
    mov rax, [r13+56]
    mov [r15+88], rax
    mov qword ptr [r15+64], 1
    mov qword ptr [r15+72], 0
.Lbrh_publish:
    mov rdi, [r15+64]
    mov rsi, [r15+80]
    mov rdx, [r15+88]
    call .Lbrh_write_all
    test rax, rax
    jnz .Lbrh_fatal
    mov byte ptr [r15+128], 10
    mov rdi, [r15+64]
    lea rsi, [r15+128]
    mov edx, 1
    call .Lbrh_write_all
    test rax, rax
    jnz .Lbrh_fatal
    mov rdi, [r15]
    call binary_read_body_release
    test eax, eax
    jnz .Lbrh_fatal
    mov rdi, [r15]
    call binary_read_body_destroy
    test eax, eax
    jnz .Lbrh_fatal
    mov qword ptr [r15], 0
    lea rdi, [r15+8]
    call .Lbrh_unmap_pair
    test rax, rax
    jnz .Lbrh_fatal
    lea rdi, [r15+32]
    call .Lbrh_unmap_pair
    test rax, rax
    jnz .Lbrh_fatal
    lea rdi, [r15+48]
    call .Lbrh_unmap_pair
    test rax, rax
    jnz .Lbrh_fatal
    mov r12, [r15+72]
    mov rdi, r15
    mov esi, 8192
    mov eax, 11
    syscall
    test rax, rax
    jnz .Lbrh_fatal
    mov rdi, r12
    mov eax, 60
    syscall
.Lbrh_fatal:
    mov edi, 111
    mov eax, 60
    syscall

.Lbrh_unmap_pair:
    push rbx
    mov rbx, rdi
    mov rdi, [rbx]
    test rdi, rdi
    jz .Lbrh_unmap_zero
    mov rsi, [rbx+8]
    add rsi, 4096
    mov eax, 11
    syscall
    test rax, rax
    jnz .Lbrh_unmap_done
    mov qword ptr [rbx], 0
    mov qword ptr [rbx+8], 0
.Lbrh_unmap_zero:
    xor eax, eax
.Lbrh_unmap_done:
    pop rbx
    ret

.Lbrh_write_all:
    push rbx
    push r12
    push r13
    push r14
    mov rbx, rdi
    mov r12, rsi
    mov r13, rdx
    xor r14d, r14d
.Lbrh_write_loop:
    cmp r14, r13
    je .Lbrh_write_success
    mov rdi, rbx
    lea rsi, [r12+r14]
    mov rdx, r13
    sub rdx, r14
    mov eax, 1
    syscall
    cmp rax, -4
    je .Lbrh_write_loop
    test rax, rax
    jz .Lbrh_write_zero
    cmp rax, -4095
    jae .Lbrh_write_done
    add r14, rax
    jmp .Lbrh_write_loop
.Lbrh_write_zero:
    mov rax, -5
    jmp .Lbrh_write_done
.Lbrh_write_success:
    xor eax, eax
.Lbrh_write_done:
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

.Lbrh_error:
    .byte 0xe9
.global binary_read_helper_error_call_displacement
binary_read_helper_error_call_displacement:
    .long 0

.if HBRH_OBSERVE
/* Exactly the qualified body's full 128-byte journal ABI, without mutation hooks. */
.Lbrh_body_journal:
    B_ENTER
    sub rsp, 128
    mov rbx, rdi
    mov r12, rsi
    mov r13, rdx
    mov r14, rcx
    mov r15, r8
    mov rdi, rsp
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
    call .Lbrh_write_all
    test rax, rax
    jnz .Lbrh_body_journal_return
    mov rdi, rbx
    mov rsi, r14
    mov rdx, r15
    call .Lbrh_write_all
.Lbrh_body_journal_return:
    add rsp, 128
    B_LEAVE

/* HBRFJR01: event, call, returned u64, span bytes, input length, output/work capacity. */
.Lbrh_format_journal:
    B_ENTER
    sub rsp, 64
    mov r12, rdi
    mov r13, rsi
    mov r14, rdx
    mov r15, rcx
    mov rax, 0x3130524a46524248 /* HBRFJR01 */
    mov [rsp], rax
    mov [rsp+8], r13
    mov rax, [r12+96]
    mov [rsp+16], rax
    mov rax, [r12+104]
    mov [rsp+24], rax
    mov [rsp+32], r15
    mov rax, [r12]
    mov rax, [rax+168]
    mov [rsp+40], rax
    mov rax, [r12+40]
    mov [rsp+48], rax
    mov rax, [r12+56]
    mov [rsp+56], rax
    mov edi, 4
    mov rsi, rsp
    mov edx, 64
    call .Lbrh_write_all
    test rax, rax
    jnz .Lbrh_format_journal_return
    mov edi, 4
    mov rsi, r14
    mov rdx, r15
    call .Lbrh_write_all
.Lbrh_format_journal_return:
    add rsp, 64
    B_LEAVE
.endif
