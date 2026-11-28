/* Copyright 2026 Muvon Un Limited
 * Copyright 2026 TrillionniumFoundation
 * SPDX-License-Identifier: Apache-2.0
 *
 * One-shot byte transport for the fixed HIA binary-write parent operation.
 * Policy, file handling, encoding and diagnostic text are existing HIA owners.
 * This entry only owns stdin, native buffers, completed response publication
 * and process lifetime. No observer or request-selected capability is installed.
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
    jbe .Lbwh_fatal
    mov r12, rax
    mov edi, 1
    mov esi, 9
    xor edx, edx
    xor r10d, r10d
    xor r8d, r8d
    mov eax, 157
    syscall
    test rax, rax
    jnz .Lbwh_fatal
    mov eax, 110
    syscall
    cmp rax, r12
    jne .Lbwh_fatal
    mov edi, 4096
    call .Lbrd_map
    cmp rax, -4095
    jae .Lbwh_fatal
    mov r15, rax
    lea rdi, [r15+8]
    mov esi, 65536
    call .Lbrd_grow
    test eax, eax
    jnz .Lbwh_fatal
.Lbwh_input:
    mov rax, [r15+24]
    cmp rax, [r15+16]
    jb .Lbwh_read
    cmp rax, B_MAX_INPUT
    jae .Lbwh_limit
    lea rsi, [rax+rax]
    cmp rsi, B_MAX_INPUT
    jbe .Lbwh_input_grow
    mov esi, B_MAX_INPUT
.Lbwh_input_grow:
    lea rdi, [r15+8]
    call .Lbrd_grow
    test eax, eax
    jnz .Lbwh_fatal
.Lbwh_read:
    xor edi, edi
    mov rsi, [r15+8]
    add rsi, [r15+24]
    mov rdx, [r15+16]
    sub rdx, [r15+24]
    xor eax, eax
    syscall
    cmp rax, -4
    je .Lbwh_read
    cmp rax, -4095
    jae .Lbwh_fatal
    test rax, rax
    jz .Lbwh_eof
    add [r15+24], rax
    jmp .Lbwh_input
.Lbwh_limit:
    xor edi, edi
    lea rsi, [r15+128]
    mov edx, 1
    xor eax, eax
    syscall
    cmp rax, -4
    je .Lbwh_limit
    test rax, rax
    jnz .Lbwh_fatal
.Lbwh_eof:
    cmp qword ptr [r15+24], 96
    jb .Lbwh_fatal
    mov r12, [r15+8]
    mov rax, 0x3130305157504248 /* HBPWQ001 */
    cmp [r12], rax
    jne .Lbwh_fatal
    cmp qword ptr [r12+8], 1
    jne .Lbwh_fatal
    cmp qword ptr [r12+16], 0
    jne .Lbwh_fatal
    cmp qword ptr [r12+24], 1
    jne .Lbwh_fatal
    call hia_process_orphans_create
    cmp rax, -4095
    jae .Lbwh_fatal
    mov [r15+192], rax
    xor edi, edi
    xor esi, esi
    mov rdx, rax
    call binary_entropy_create
    cmp rax, -4095
    jae .Lbwh_fatal
    mov [r15+200], rax
    xor edi, edi
    xor esi, esi
    mov rdx, [r15+192]
    mov rcx, [r15+200]
    call binary_parent_owner_create
    cmp rax, -4095
    jae .Lbwh_fatal
    mov [r15], rax
    mov rdi, rax
    mov rsi, [r15+8]
    mov rdx, [r15+24]
    call binary_parent_owner_invoke
    cmp rax, 64
    jne .Lbwh_fatal
    mov r12, [r15]
    cmp qword ptr [r12+56], 2
    jne .Lbwh_fatal
    cmp qword ptr [r12+184], 0
    jne .Lbwh_fatal
    mov r13, [r12+104]
    mov r14, [r12+168]
    cmp r14, 64
    jb .Lbwh_fatal
    mov rax, 0x3130305257504248 /* HBPWR001 */
    cmp [r13], rax
    jne .Lbwh_fatal
    mov rax, [r13+56]
    add rax, 64
    jc .Lbwh_fatal
    cmp rax, r14
    jne .Lbwh_fatal
    cmp qword ptr [r13+8], 0
    je .Lbwh_success
    cmp qword ptr [r13+8], 3
    jne .Lbwh_fatal
    cmp r14, 128
    jb .Lbwh_fatal
    lea rdi, [r15+48]
    mov esi, 12288
    call .Lbrd_grow
    test eax, eax
    jnz .Lbwh_fatal
    lea rdi, [r15+32]
    mov esi, 4096
    call .Lbrd_grow
    test eax, eax
    jnz .Lbwh_fatal
.Lbwh_format:
    inc qword ptr [r15+96]
    mov qword ptr [r15+104], 0
    lea rdi, [r13+64]
    lea rsi, [r14-64]
    mov rdx, [r15+32]
    mov rcx, [r15+40]
    mov r8, [r15+48]
    mov r9, [r15+56]
    call .Lbwh_error
    mov [r15+104], rax
    mov rax, [r15+104]
    cmp eax, 0xfffffffe
    je .Lbwh_format_grow
    test rax, rax
    jz .Lbwh_fatal
    cmp rax, [r15+40]
    ja .Lbwh_fatal
    mov [r15+88], rax
    mov rax, [r15+32]
    mov [r15+80], rax
    mov qword ptr [r15+64], 2
    mov qword ptr [r15+72], 1
    jmp .Lbwh_publish
.Lbwh_format_grow:
    mov rsi, [r15+40]
    cmp rsi, B_MAX_OUT
    jae .Lbwh_fatal
    add rsi, rsi
    lea rdi, [r15+32]
    call .Lbrd_grow
    test eax, eax
    jnz .Lbwh_fatal
    jmp .Lbwh_format
.Lbwh_success:
    lea rax, [r13+64]
    mov [r15+80], rax
    mov rax, [r13+56]
    mov [r15+88], rax
    mov qword ptr [r15+64], 1
    mov qword ptr [r15+72], 0
.Lbwh_publish:
    mov rdi, [r15+64]
    mov rsi, [r15+80]
    mov rdx, [r15+88]
    call .Lbwh_write_all
    test rax, rax
    jnz .Lbwh_fatal
    mov byte ptr [r15+128], 10
    mov rdi, [r15+64]
    lea rsi, [r15+128]
    mov edx, 1
    call .Lbwh_write_all
    test rax, rax
    jnz .Lbwh_fatal
    mov rdi, [r15]
    call binary_parent_owner_release
    test eax, eax
    jnz .Lbwh_fatal
    mov rdi, [r15]
    call binary_parent_owner_destroy
    test eax, eax
    jnz .Lbwh_fatal
    mov qword ptr [r15], 0
    lea rdi, [r15+8]
    call .Lbwh_unmap_pair
    test rax, rax
    jnz .Lbwh_fatal
    lea rdi, [r15+32]
    call .Lbwh_unmap_pair
    test rax, rax
    jnz .Lbwh_fatal
    lea rdi, [r15+48]
    call .Lbwh_unmap_pair
    test rax, rax
    jnz .Lbwh_fatal
    mov r12, [r15+72]
    mov rdi, r15
    mov esi, 8192
    mov eax, 11
    syscall
    test rax, rax
    jnz .Lbwh_fatal
    mov rdi, r12
    mov eax, 60
    syscall
.Lbwh_fatal:
    mov edi, 111
    mov eax, 60
    syscall

.Lbwh_unmap_pair:
    push rbx
    mov rbx, rdi
    mov rdi, [rbx]
    test rdi, rdi
    jz .Lbwh_unmap_zero
    mov rsi, [rbx+8]
    add rsi, 4096
    mov eax, 11
    syscall
    test rax, rax
    jnz .Lbwh_unmap_done
    mov qword ptr [rbx], 0
    mov qword ptr [rbx+8], 0
.Lbwh_unmap_zero:
    xor eax, eax
.Lbwh_unmap_done:
    pop rbx
    ret

.Lbwh_write_all:
    push rbx
    push r12
    push r13
    push r14
    mov rbx, rdi
    mov r12, rsi
    mov r13, rdx
    xor r14d, r14d
.Lbwh_write_loop:
    cmp r14, r13
    je .Lbwh_write_success
    mov rdi, rbx
    lea rsi, [r12+r14]
    mov rdx, r13
    sub rdx, r14
    mov eax, 1
    syscall
    cmp rax, -4
    je .Lbwh_write_loop
    test rax, rax
    jz .Lbwh_write_zero
    cmp rax, -4095
    jae .Lbwh_write_done
    add r14, rax
    jmp .Lbwh_write_loop
.Lbwh_write_zero:
    mov rax, -5
    jmp .Lbwh_write_done
.Lbwh_write_success:
    xor eax, eax
.Lbwh_write_done:
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

.Lbwh_error:
    .byte 0xe9
.global public_binary_write_error_call_displacement
public_binary_write_error_call_displacement:
    .long 0

