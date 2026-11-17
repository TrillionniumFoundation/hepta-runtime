/* Copyright 2026 Muvon Un Limited
 * Copyright 2026 TrillionniumFoundation
 * SPDX-License-Identifier: Apache-2.0
 * Private two-context multi-read carrier. Each body owns two parent children;
 * both bodies share one process orphan pool. No public route is exposed here.
 */
.intel_syntax noprefix
.section .text
.global _start
.type _start, @function
_start:
    and rsp, -16
    cld
    mov edi, 3
.Lmmf_check_pipes:
    mov esi, 1
    xor edx, edx
    mov eax, 72
    syscall
    cmp rax, -4095
    jae .Lmmf_fatal
    inc edi
    cmp edi, 6
    jb .Lmmf_check_pipes
    mov edi, 4096
    call .Lmrd_map
    cmp rax, -4095
    jae .Lmmf_fatal
    mov r15, rax
    call hia_process_orphans_create
    cmp rax, -4095
    jae .Lmmf_fatal
    mov [r15+80], rax
.Lmmf_loop:
    mov rdi, [r15+72]
    lea rsi, [r15+64]
    mov edx, 8
    call .Lmmf_read_exact
    test rax, rax
    jz .Lmmf_eof
    cmp rax, 8
    jne .Lmmf_fatal
    mov r13, [r15+64]
    cmp r13, 64
    jb .Lmmf_fatal
    cmp r13, 1048640
    ja .Lmmf_fatal
    lea rdi, [r15+16]
    mov rsi, r13
    call .Lmrd_grow
    test eax, eax
    jnz .Lmmf_fatal
    mov rdi, [r15+72]
    mov rsi, [r15+16]
    mov rdx, r13
    call .Lmmf_read_exact
    cmp rax, r13
    jne .Lmmf_fatal
    mov rbp, [r15+16]
    mov rax, 0x3130514644524d48 /* HMRDFQ01 */
    cmp [rbp], rax
    jne .Lmmf_fatal
    mov rbx, [rbp+16]
    cmp rbx, 1
    ja .Lmmf_fatal
    mov r14, [rbp+8]
    cmp r14, 1
    jb .Lmmf_fatal
    cmp r14, 21
    ja .Lmmf_fatal
    mov rax, [rbp+32]
    or rax, [rbp+40]
    or rax, [rbp+48]
    or rax, [rbp+56]
    jnz .Lmmf_fatal
    sub r13, 64
    cmp [rbp+24], r13
    jne .Lmmf_fatal
    mov r12, [r15+rbx*8]
    cmp r14, 1
    je .Lmmf_invoke
    cmp r14, 18
    je .Lmmf_arm_fstat_error
    cmp r14, 21
    je .Lmmf_utf8_direct
    test r13, r13
    jnz .Lmmf_fatal
    cmp r14, 8
    je .Lmmf_create
    cmp r14, 9
    je .Lmmf_create_off
    cmp r14, 11
    je .Lmmf_pool_snapshot
    cmp r14, 17
    je .Lmmf_move_control
    cmp r14, 20
    je .Lmmf_pool_fork_refusal
    test r12, r12
    jz .Lmmf_no_context
    cmp r14, 2
    je .Lmmf_release
    cmp r14, 3
    je .Lmmf_destroy
    cmp r14, 4
    je .Lmmf_context
    cmp r14, 5
    je .Lmmf_workspace
    cmp r14, 6
    je .Lmmf_output
    cmp r14, 7
    je .Lmmf_input
    cmp r14, 13
    je .Lmmf_format
    cmp r14, 15
    je .Lmmf_child_contexts
    cmp r14, 19
    je .Lmmf_unowned_refusal
    jmp .Lmmf_fatal

.Lmmf_invoke:
    test r12, r12
    jnz .Lmmf_invoke_ready
    lea rdi, [rip+.Lmmf_journal]
    mov rsi, r15
    mov rdx, [r15+80]
    call multi_read_body_create
    cmp rax, -4095
    jae .Lmmf_fatal
    mov r12, rax
    mov [r15+rbx*8], rax
.Lmmf_invoke_ready:
    cmp r13, 96
    jb .Lmmf_no_context
    mov [r15+344], r12
    mov rdi, r12
    lea rsi, [rbp+64]
    mov rdx, r13
    call multi_read_body_invoke
    mov r13, rax
    xor r14d, r14d
    xor ebp, ebp
    cmp rax, 64
    jne .Lmmf_reply
    mov r14, [r12+104]
    mov rbp, [r12+168]
    jmp .Lmmf_reply
.Lmmf_create:
    test r12, r12
    jnz .Lmmf_busy
    lea rdi, [rip+.Lmmf_journal]
    mov rsi, r15
    jmp .Lmmf_create_call
.Lmmf_create_off:
    test r12, r12
    jnz .Lmmf_busy
    xor edi, edi
    xor esi, esi
.Lmmf_create_call:
    mov rdx, [r15+80]
    call multi_read_body_create
    cmp rax, -4095
    jae .Lmmf_fatal
    mov r12, rax
    mov [r15+rbx*8], rax
    xor r13d, r13d
    jmp .Lmmf_empty_reply
.Lmmf_release:
    mov rdi, r12
    call multi_read_body_release
    mov r13, rax
    jmp .Lmmf_empty_reply
.Lmmf_destroy:
    mov [r15+344], r12
    mov rdi, r12
    call multi_read_body_destroy
    mov r13, rax
    test rax, rax
    jnz .Lmmf_empty_reply
    mov qword ptr [r15+rbx*8], 0
    xor r12d, r12d
    jmp .Lmmf_empty_reply

/* Move only the control pipe away from FD0, allowing actual parent/file FD0.
 * This never duplicates a target directory or file capability. */
.Lmmf_move_control:
    cmp qword ptr [r15+72], 0
    jne .Lmmf_no_context
    xor edi, edi
    mov eax, 32
    syscall
    cmp rax, -4095
    jae .Lmmf_fatal
    mov [r15+72], rax
    xor edi, edi
    mov eax, 3
    syscall
    test rax, rax
    jnz .Lmmf_fatal
    xor r13d, r13d
    jmp .Lmmf_empty_reply
.Lmmf_arm_fstat_error:
    cmp qword ptr [r15+88], 0
    jne .Lmmf_no_context
    cmp r13, 16
    jne .Lmmf_no_context
    mov rax, [rbp+64]
    cmp rax, 23
    je .Lmmf_arm_phase_ok
    cmp rax, 31
    je .Lmmf_arm_phase_ok
    cmp rax, 41
    je .Lmmf_arm_phase_ok
    cmp rax, 61
    jne .Lmmf_no_context
.Lmmf_arm_phase_ok:
    mov rdx, [rbp+72]
    cmp rdx, 1
    ja .Lmmf_no_context
    mov [r15+320], rax
    mov [r15+328], rdx
    mov qword ptr [r15+88], 1
    xor r13d, r13d
    jmp .Lmmf_empty_reply

.Lmmf_pool_snapshot:
    mov rax, [r15+80]
    mov r13, [rax+56]
    cmp r13, 65533
    ja .Lmmf_fatal
    mov rsi, r13
    shl rsi, 12
    add rsi, 4128
    lea rdi, [r15+208]
    call .Lmrd_grow
    test eax, eax
    jnz .Lmmf_fatal
    mov r14, [r15+208]
    mov rax, 0x3130304e53504f48 /* HOPSN001 */
    mov [r14], rax
    mov rdx, [r15+80]
    mov [r14+8], rdx
    mov rax, [rdx+48]
    mov [r14+16], rax
    mov [r14+24], r13
    lea rdi, [r14+32]
    mov rsi, rdx
    mov ecx, 4096
    rep movsb
    mov rdx, [rdx+32]
    mov rbp, 4128
.Lmmf_pool_copy_page:
    test r13, r13
    jz .Lmmf_pool_copied
    test rdx, rdx
    jz .Lmmf_fatal
    lea rdi, [r14+rbp]
    mov rsi, rdx
    mov ecx, 4096
    rep movsb
    mov rdx, [rdx+16]
    add rbp, 4096
    dec r13
    jmp .Lmmf_pool_copy_page
.Lmmf_pool_copied:
    test rdx, rdx
    jnz .Lmmf_fatal
    xor r13d, r13d
    jmp .Lmmf_reply

.Lmmf_child_contexts:
    lea rdi, [r15+208]
    mov esi, 8192
    call .Lmrd_grow
    test eax, eax
    jnz .Lmmf_fatal
    mov r14, [r15+208]
    mov rdi, r14
    mov rsi, [r12+384]
    mov ecx, 4096
    rep movsb
    mov rsi, [r12+392]
    mov ecx, 4096
    rep movsb
    xor r13d, r13d
    mov ebp, 8192
    jmp .Lmmf_reply
.Lmmf_unowned_refusal:
    cmp qword ptr [r12+56], 0
    jne .Lmmf_no_context
    cmp qword ptr [r12+184], 0
    jne .Lmmf_no_context
    lea rbp, [r15+768]
    mov rdi, rbp
    xor eax, eax
    mov ecx, 8
    rep stosq
    mov qword ptr [rbp+24], 4
    mov qword ptr [rbp+32], 2147483647
    call .Lmrd_capability
    mov r13, rax
    cmp eax, M_INVALID
    jne .Lmmf_fatal
    jmp .Lmmf_empty_reply

/* The root primitive rejects a copied pool in a distinct actual PID. */
.Lmmf_pool_fork_refusal:
    mov eax, 57
    syscall
    test rax, rax
    jz .Lmmf_orphan_child
    cmp rax, -4095
    jae .Lmmf_fatal
    mov [r15+304], rax
.Lmmf_orphan_wait:
    mov rdi, [r15+304]
    lea rsi, [r15+312]
    xor edx, edx
    xor r10d, r10d
    mov eax, 61
    syscall
    cmp rax, -4
    je .Lmmf_orphan_wait
    cmp rax, [r15+304]
    jne .Lmmf_fatal
    cmp dword ptr [r15+312], 0
    jne .Lmmf_fatal
    xor r13d, r13d
    jmp .Lmmf_empty_reply
.Lmmf_orphan_child:
    mov rdi, [r15+80]
    xor esi, esi
    mov rdx, r15
    mov ecx, 1
    call hia_process_orphans_append
    cmp rax, -22
    jne .Lmmf_fatal
    xor edi, edi
    mov eax, 60
    syscall

/* Private direct leaf qualification. Both complete 4 KiB physical arenas are
 * returned before and after invocation, including bytes outside passed caps. */
.Lmmf_utf8_direct:
    cmp r13, 48
    jb .Lmmf_no_context
    mov rax, [rbp+64]
    cmp rax, 4096
    ja .Lmmf_no_context
    mov [r15+280], rax
    mov rax, [rbp+72]
    cmp rax, 4096
    ja .Lmmf_no_context
    mov [r15+288], rax
    cmp qword ptr [rbp+80], 255
    ja .Lmmf_no_context
    cmp qword ptr [rbp+88], 255
    ja .Lmmf_no_context
    lea rax, [rbp+96]
    mov [r15+256], rax
    sub r13, 32
    mov [r15+264], r13
    lea rdi, [r15+224]
    mov esi, 4096
    call .Lmrd_grow
    test eax, eax
    jnz .Lmmf_fatal
    lea rdi, [r15+240]
    mov esi, 4096
    call .Lmrd_grow
    test eax, eax
    jnz .Lmmf_fatal
    lea rdi, [r15+208]
    mov esi, 16416
    call .Lmrd_grow
    test eax, eax
    jnz .Lmmf_fatal
    mov rdi, [r15+224]
    mov rax, [rbp+80]
    mov ecx, 4096
    rep stosb
    mov rdi, [r15+240]
    mov rax, [rbp+88]
    mov ecx, 4096
    rep stosb
    mov r14, [r15+208]
    mov rax, [r15+280]
    mov [r14], rax
    mov rax, [r15+288]
    mov [r14+8], rax
    mov qword ptr [r14+16], 0
    mov rax, [r15+264]
    mov [r14+24], rax
    lea rdi, [r14+32]
    mov rsi, [r15+224]
    mov ecx, 4096
    rep movsb
    mov rsi, [r15+240]
    mov ecx, 4096
    rep movsb
    mov rdi, [r15+256]
    mov rsi, [r15+264]
    mov rdx, [r15+224]
    mov rcx, [r15+280]
    mov r8, [r15+240]
    mov r9, [r15+288]
    call .Lmrd_utf8
    mov r13, rax
    mov [r14+16], rax
    lea rdi, [r14+8224]
    mov rsi, [r15+224]
    mov ecx, 4096
    rep movsb
    mov rsi, [r15+240]
    mov ecx, 4096
    rep movsb
    mov ebp, 16416
    xor r12d, r12d
    jmp .Lmmf_reply

.Lmmf_context:
    mov r14, r12
    mov ebp, 4096
    xor r13d, r13d
    jmp .Lmmf_reply
.Lmmf_workspace:
    mov r14, [r12+88]
    mov rbp, [r12+96]
    xor r13d, r13d
    jmp .Lmmf_reply
.Lmmf_output:
    mov r14, [r12+104]
    mov rbp, [r12+112]
    xor r13d, r13d
    jmp .Lmmf_reply
.Lmmf_input:
    mov r14, [r12+64]
    mov rbp, [r12+72]
    xor r13d, r13d
    jmp .Lmmf_reply
.Lmmf_busy:
    mov r13d, M_BUSY
    jmp .Lmmf_empty_reply
.Lmmf_no_context:
    mov r13d, M_INVALID
.Lmmf_empty_reply:
    xor r14d, r14d
    xor ebp, ebp
.Lmmf_reply:
    lea rdi, [r15+128]
    xor eax, eax
    mov ecx, 8
    rep stosq
    mov rax, 0x3130524644524d48 /* HMRDFR01 */
    mov [r15+128], rax
    mov [r15+136], r13
    mov [r15+144], rbp
    test r12, r12
    jz .Lmmf_reply_header
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
.Lmmf_reply_header:
    mov edi, 1
    lea rsi, [r15+128]
    mov edx, 64
    call .Lmmf_write_all
    test rax, rax
    jnz .Lmmf_fatal
    test rbp, rbp
    jz .Lmmf_loop
    mov edi, 1
    mov rsi, r14
    mov rdx, rbp
    call .Lmmf_write_all
    test rax, rax
    jnz .Lmmf_fatal
    jmp .Lmmf_loop

.Lmmf_eof:
    xor ebx, ebx
.Lmmf_eof_context:
    mov r12, [r15+rbx*8]
    test r12, r12
    jz .Lmmf_eof_next
    mov [r15+344], r12
    cmp qword ptr [r12+56], 2
    jne .Lmmf_eof_destroy
    mov rdi, r12
    call multi_read_body_release
    test eax, eax
    jnz .Lmmf_fatal
.Lmmf_eof_destroy:
    mov rdi, r12
    call multi_read_body_destroy
    test eax, eax
    jnz .Lmmf_fatal
    mov qword ptr [r15+rbx*8], 0
.Lmmf_eof_next:
    inc ebx
    cmp ebx, 2
    jb .Lmmf_eof_context
    mov rdi, [r15+72]
    test rdi, rdi
    jz .Lmmf_eof_witness
    mov eax, 3
    syscall
.Lmmf_eof_witness:
    lea rdi, [r15+512]
    xor eax, eax
    mov ecx, 8
    rep stosq
    movabs rax, 0x31464f4544524d48 /* HMRDEOF1 */
    mov [r15+512], rax
    mov rdx, [r15+80]
    mov rax, [rdx+48]
    mov [r15+520], rax
    mov rax, [rdx+56]
    mov [r15+528], rax
    mov edi, 4
    lea rsi, [r15+512]
    mov edx, 64
    call .Lmmf_write_all
    test rax, rax
    jnz .Lmmf_fatal
    mov edi, 5
    lea rsi, [r15+576]
    mov edx, 8
    call .Lmmf_read_exact
    cmp rax, 8
    jne .Lmmf_fatal
    cmp qword ptr [r15+576], 0
    jne .Lmmf_fatal
    xor edi, edi
    mov eax, 60
    syscall
.Lmmf_fatal:
    mov edi, 111
    mov eax, 60
    syscall

.Lmmf_format:
    cmp qword ptr [r12+56], 2
    jne .Lmmf_no_context
    mov r14, [r12+104]
    cmp qword ptr [r14+8], 3
    jne .Lmmf_no_context
    mov rax, [r14+56]
    cmp rax, 64
    jb .Lmmf_fatal
    lea rdx, [r14+64]
    movabs rcx, 0x3130304446545548 /* HUTFD001 */
    cmp [rdx], rcx
    jne .Lmmf_format_structured
    cmp qword ptr [rdx+8], 3
    jne .Lmmf_fatal
    sub rax, 64
    cmp [rdx+56], rax
    jne .Lmmf_fatal
    cmp [rdx+40], rax
    jne .Lmmf_fatal
    lea r14, [rdx+64]
    mov rbp, rax
    mov r13, rax
    jmp .Lmmf_reply
.Lmmf_format_structured:
    mov [r15+256], rdx
    mov [r15+264], rax
    mov qword ptr [r15+272], 0
    imul rsi, rax, 6
    jo .Lmmf_fatal
    add rsi, 1024
    jc .Lmmf_fatal
    cmp rsi, 134217728
    ja .Lmmf_fatal
    lea rdi, [r15+224]
    call .Lmrd_grow
    test eax, eax
    jnz .Lmmf_fatal
    lea rdi, [r15+240]
    mov esi, 12288
    call .Lmrd_grow
    test eax, eax
    jnz .Lmmf_fatal
    mov rdi, [r15+224]
    mov rcx, [r15+232]
    shr rcx, 3
    mov rax, 0xa5a5a5a5a5a5a5a5
    rep stosq
    mov rdi, [r15+240]
    mov rcx, [r15+248]
    shr rcx, 3
    xor eax, eax
    rep stosq
    mov rdi, r15
    mov esi, 1
    mov rdx, [r15+256]
    mov rcx, [r15+264]
    call .Lmmf_format_journal
    test rax, rax
    jnz .Lmmf_fatal
    mov rdi, r15
    mov esi, 2
    mov rdx, [r15+240]
    mov rcx, [r15+248]
    call .Lmmf_format_journal
    test rax, rax
    jnz .Lmmf_fatal
    mov rdi, r15
    mov esi, 3
    mov rdx, [r15+224]
    mov rcx, [r15+232]
    call .Lmmf_format_journal
    test rax, rax
    jnz .Lmmf_fatal
    mov rdi, [r15+256]
    mov rsi, [r15+264]
    mov rdx, [r15+224]
    mov rcx, [r15+232]
    mov r8, [r15+240]
    mov r9, [r15+248]
    call .Lmmf_error
    mov [r15+272], rax
    mov rdi, r15
    mov esi, 4
    mov rdx, [r15+224]
    mov rcx, [r15+232]
    call .Lmmf_format_journal
    test rax, rax
    jnz .Lmmf_fatal
    mov rdi, r15
    mov esi, 5
    mov rdx, [r15+240]
    mov rcx, [r15+248]
    call .Lmmf_format_journal
    test rax, rax
    jnz .Lmmf_fatal
    mov r13, [r15+272]
    cmp r13, [r15+232]
    ja .Lmmf_fatal
    mov r14, [r15+224]
    mov rbp, r13
    jmp .Lmmf_reply

.Lmmf_format_journal:
    cmp qword ptr [r12+40], 0
    jne .Lmmf_format_journal_observed
    xor eax, eax
    ret
.Lmmf_format_journal_observed:
    M_ENTER
    mov r12, rdi
    mov r13, rsi
    mov r14, rdx
    mov r15, rcx
    sub rsp, 64
    mov rdi, rsp
    xor eax, eax
    mov ecx, 8
    rep stosq
    mov rax, 0x3130305245464d48 /* HMFER001 */
    mov [rsp], rax
    mov [rsp+8], r13
    mov [rsp+16], r15
    mov rax, [r12+272]
    mov [rsp+24], rax
    mov rax, [r12+232]
    mov [rsp+32], rax
    mov rax, [r12+248]
    mov [rsp+40], rax
    mov edi, 3
    mov rsi, rsp
    mov edx, 64
    call .Lmmf_write_all
    test rax, rax
    jnz .Lmmf_format_journal_done
    mov edi, 3
    mov rsi, r14
    mov rdx, r15
    call .Lmmf_write_all
.Lmmf_format_journal_done:
    add rsp, 64
    M_LEAVE

/* Actual seccomp filter, never an observer-provided syscall reply.
 * Only fstat / newfstatat for the just-opened owned FD gets kernel EIO.
 * It remains installed until this OS process exits. */
.Lmmf_install_fstat_error:
    M_ENTER
    mov r13, rdi
    cmp r13, 2147483647
    ja .Lmmf_filter_bad
    sub rsp, 96
    mov rdi, rsp
    xor eax, eax
    mov ecx, 12
    rep stosq
    mov qword ptr [rsp], 0x20
    movabs rax, 0x0000000500010015
    mov [rsp+8], rax
    movabs rax, 0x0000010603000015
    mov [rsp+16], rax
    movabs rax, 0x0000001000000020
    mov [rsp+24], rax
    mov rax, r13
    shl rax, 32
    or rax, 0x01000015
    mov [rsp+32], rax
    movabs rax, 0x0005000500000006
    mov [rsp+40], rax
    movabs rax, 0x7fff000000000006
    mov [rsp+48], rax
    mov word ptr [rsp+64], 7
    lea rax, [rsp]
    mov [rsp+72], rax
    mov edi, 38 /* PR_SET_NO_NEW_PRIVS */
    mov esi, 1
    xor edx, edx
    xor r10d, r10d
    xor r8d, r8d
    mov eax, 157
    syscall
    test rax, rax
    jnz .Lmmf_filter_done
    mov edi, 1 /* SECCOMP_SET_MODE_FILTER */
    xor esi, esi
    lea rdx, [rsp+64]
    mov eax, 317
    syscall
.Lmmf_filter_done:
    add rsp, 96
    jmp .Lmmf_filter_return
.Lmmf_filter_bad:
    mov rax, -22
.Lmmf_filter_return:
    M_LEAVE

.balign 16
.global multi_read_body_error_call_displacement
.Lmmf_error:
    .byte 0xe9
multi_read_body_error_call_displacement:
    .long 0
.Lmmf_read_exact:
    push rbx
    push r12
    push r13
    push r14
    mov rbx, rdi
    mov r12, rsi
    mov r13, rdx
    xor r14d, r14d
.Lmmf_read_loop:
    mov rdi, rbx
    lea rsi, [r12+r14]
    mov rdx, r13
    sub rdx, r14
    xor eax, eax
    syscall
    test rax, rax
    jz .Lmmf_read_eof
    cmp rax, -4
    je .Lmmf_read_loop
    cmp rax, -4095
    jae .Lmmf_read_done
    add r14, rax
    cmp r14, r13
    jb .Lmmf_read_loop
    mov rax, r13
    jmp .Lmmf_read_done
.Lmmf_read_eof:
    xor eax, eax
    test r14, r14
    jz .Lmmf_read_done
    mov rax, -22
.Lmmf_read_done:
    pop r14
    pop r13
    pop r12
    pop rbx
    ret
.Lmmf_write_all:
    push rbx
    push r12
    push r13
    push r14
    mov rbx, rdi
    mov r12, rsi
    mov r13, rdx
    xor r14d, r14d
.Lmmf_write_loop:
    cmp r14, r13
    je .Lmmf_write_success
    mov rdi, rbx
    lea rsi, [r12+r14]
    mov rdx, r13
    sub rdx, r14
    mov eax, 1
    syscall
    cmp rax, -4
    je .Lmmf_write_loop
    test rax, rax
    jz .Lmmf_write_zero
    cmp rax, -4095
    jae .Lmmf_write_done
    add r14, rax
    jmp .Lmmf_write_loop
.Lmmf_write_zero:
    mov rax, -5
    jmp .Lmmf_write_done
.Lmmf_write_success:
    xor eax, eax
.Lmmf_write_done:
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

/* Immutable observer binding: rdi private fixture context, rsi context, rdx event,
 * rcx complete owned span, r8 length. Full bytes are written synchronously. */
.Lmmf_journal:
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
    movabs rax, 0x3130494344524d48 /* HMRDCI01 */
    cmp [r12], rax
    je .Lmmf_journal_body_magic
    movabs rax, 0x3130494352445048 /* exact unchanged parent context magic */
    cmp [r12], rax
    jne .Lmmf_journal_hook_bad
    mov rdx, [rbx+344]
    test rdx, rdx
    jz .Lmmf_journal_hook_bad
    cmp [rdx+384], r12
    je .Lmmf_journal_parent_zero
    cmp [rdx+392], r12
    jne .Lmmf_journal_hook_bad
    movabs rax, 0x3130524a31445048
    jmp .Lmmf_journal_magic_ready
.Lmmf_journal_parent_zero:
    movabs rax, 0x3130524a30445048
    jmp .Lmmf_journal_magic_ready
.Lmmf_journal_body_magic:
    cmp [rbx+344], r12
    jne .Lmmf_journal_hook_bad
    movabs rax, 0x3130524a44524d48
.Lmmf_journal_magic_ready:
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
    mov edi, 3
    mov rsi, rsp
    mov edx, 128
    call .Lmmf_write_all
    test rax, rax
    jnz .Lmmf_journal_return
    mov edi, 3
    mov rsi, r14
    mov rdx, r15
    call .Lmmf_write_all
    test rax, rax
    jnz .Lmmf_journal_return
    cmp r13, 8
    jne .Lmmf_journal_return
    cmp r15, 64
    jb .Lmmf_journal_hook_bad
    /* These barriers never supply a result. The actual OS operation follows. */
    movabs rax, 0x3130494344524d48
    cmp [r12], rax
    je .Lmmf_hook_body_magic
    mov rdx, [rbx+344]
    cmp [rdx+384], r12
    je .Lmmf_hook_parent_zero
    cmp [rdx+392], r12
    jne .Lmmf_journal_hook_bad
    movabs rax, 0x31304b4831445048
    jmp .Lmmf_hook_magic_ready
.Lmmf_hook_parent_zero:
    movabs rax, 0x31304b4830445048
    jmp .Lmmf_hook_magic_ready
.Lmmf_hook_body_magic:
    movabs rax, 0x31304b4844524d48
.Lmmf_hook_magic_ready:
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
    call .Lmmf_write_all
    test rax, rax
    jnz .Lmmf_journal_return
    mov edi, 5
    lea rsi, [rsp+128]
    mov edx, 8
    call .Lmmf_read_exact
    cmp rax, 8
    jne .Lmmf_journal_hook_bad
    cmp qword ptr [rsp+128], 0
    jne .Lmmf_journal_hook_bad
    cmp qword ptr [rbx+88], 1
    jne .Lmmf_journal_hook_ok
    movabs rax, 0x3130494344524d48
    cmp [r12], rax
    jne .Lmmf_journal_hook_ok
    cmp qword ptr [r14+24], 2
    jne .Lmmf_journal_hook_ok
    mov rax, [r12+88]
    mov rdx, [rbx+320]
    cmp [rax+8], rdx
    jne .Lmmf_journal_hook_ok
    mov rdx, [rbx+328]
    cmp [rax+200], rdx
    jne .Lmmf_journal_hook_ok
    mov rdi, [r14+32]
    call .Lmmf_install_fstat_error
    test rax, rax
    jnz .Lmmf_journal_return
    mov qword ptr [rbx+88], 0
    inc qword ptr [rbx+96]
.Lmmf_journal_hook_ok:
    xor eax, eax
    jmp .Lmmf_journal_return
.Lmmf_journal_hook_bad:
    mov rax, -22
.Lmmf_journal_return:
    add rsp, 136
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret
