/* Copyright 2026 Muvon Un Limited
 * Copyright 2026 TrillionniumFoundation
 * SPDX-License-Identifier: Apache-2.0
 * Private two-context info carrier. All parent FDs and the orphan pool belong
 * to this fixed fixture. No public JSON input can select an FD or code address.
 */
.intel_syntax noprefix
.section .text
.global _start
.type _start, @function
_start:
    and rsp, -16
    cld
    mov edi, 3
.Liff_check_pipes:
    mov esi, 1
    xor edx, edx
    mov eax, 72
    syscall
    cmp rax, -4095
    jae .Liff_fatal
    inc edi
    cmp edi, 6
    jb .Liff_check_pipes
    mov edi, 4096
    call .Lifa_map
    cmp rax, -4095
    jae .Liff_fatal
    mov r15, rax
    call hia_process_orphans_create
    cmp rax, -4095
    jae .Liff_fatal
    mov [r15+80], rax
.Liff_loop:
    mov rdi, [r15+72]
    lea rsi, [r15+64]
    mov edx, 8
    call .Liff_read_exact
    test rax, rax
    jz .Liff_eof
    cmp rax, 8
    jne .Liff_fatal
    mov r13, [r15+64]
    cmp r13, 64
    jb .Liff_fatal
    cmp r13, 134217792
    ja .Liff_fatal
    lea rdi, [r15+16]
    mov rsi, r13
    call .Lifa_grow
    test eax, eax
    jnz .Liff_fatal
    mov rdi, [r15+72]
    mov rsi, [r15+16]
    mov rdx, r13
    call .Liff_read_exact
    cmp rax, r13
    jne .Liff_fatal
    mov rbp, [r15+16]
    mov rax, 0x3130514658464948 /* HIFXFQ01 */
    cmp [rbp], rax
    jne .Liff_fatal
    mov rbx, [rbp+16]
    cmp rbx, 1
    ja .Liff_fatal
    mov r14, [rbp+8]
    cmp r14, 1
    jb .Liff_fatal
    cmp r14, 21
    ja .Liff_fatal
    mov rax, [rbp+32]
    or rax, [rbp+40]
    or rax, [rbp+48]
    or rax, [rbp+56]
    jnz .Liff_fatal
    sub r13, 64
    cmp [rbp+24], r13
    jne .Liff_fatal
    mov r12, [r15+rbx*8]
    cmp r14, 1
    je .Liff_invoke
    cmp r14, 10
    je .Liff_hold_parent
    test r13, r13
    jnz .Liff_fatal
    cmp r14, 8
    je .Liff_create
    cmp r14, 9
    je .Liff_create_off
    cmp r14, 11
    je .Liff_pool_snapshot
    cmp r14, 12
    je .Liff_drop_parent
    cmp r14, 14
    je .Liff_parent_stat
    cmp r14, 16
    je .Liff_close_retained
    cmp r14, 17
    je .Liff_move_control
    cmp r14, 18
    je .Liff_arm_fstat_error
    cmp r14, 21
    je .Liff_arm_read_fstat_error
    cmp r14, 20
    je .Liff_pool_fork_refusal
    test r12, r12
    jz .Liff_no_context
    cmp r14, 2
    je .Liff_release
    cmp r14, 3
    je .Liff_destroy
    cmp r14, 4
    je .Liff_context
    cmp r14, 5
    je .Liff_workspace
    cmp r14, 6
    je .Liff_output
    cmp r14, 7
    je .Liff_input
    cmp r14, 13
    je .Liff_format
    cmp r14, 15
    je .Liff_child_contexts
    cmp r14, 19
    je .Liff_unowned_refusal
    jmp .Liff_fatal

.Liff_invoke:
    test r12, r12
    jnz .Liff_invoke_ready
    lea rdi, [rip+.Liff_journal]
    mov rsi, r15
    mov rdx, [r15+80]
    call file_info_at_create
    cmp rax, -4095
    jae .Liff_fatal
    mov r12, rax
    mov [r15+rbx*8], rax
.Liff_invoke_ready:
    cmp r13, 96
    jb .Liff_no_context
    mov rsi, [r15+32+rbx*8]
    test rsi, rsi
    jz .Liff_no_context
    dec rsi
    mov rdi, r12
    lea rdx, [rbp+64]
    mov rcx, r13
    call file_info_at_invoke
    mov r13, rax
    xor r14d, r14d
    xor ebp, ebp
    cmp rax, 64
    jne .Liff_reply
    mov r14, [r12+104]
    mov rbp, [r12+168]
    jmp .Liff_reply
.Liff_create:
    test r12, r12
    jnz .Liff_busy
    lea rdi, [rip+.Liff_journal]
    mov rsi, r15
    jmp .Liff_create_call
.Liff_create_off:
    test r12, r12
    jnz .Liff_busy
    xor edi, edi
    xor esi, esi
.Liff_create_call:
    mov rdx, [r15+80]
    call file_info_at_create
    cmp rax, -4095
    jae .Liff_fatal
    mov r12, rax
    mov [r15+rbx*8], rax
    xor r13d, r13d
    jmp .Liff_empty_reply
.Liff_release:
    mov rdi, r12
    call file_info_at_release
    mov r13, rax
    jmp .Liff_empty_reply
.Liff_destroy:
    mov rdi, r12
    call file_info_at_destroy
    mov r13, rax
    test rax, rax
    jnz .Liff_empty_reply
    mov qword ptr [r15+rbx*8], 0
    xor r12d, r12d
    jmp .Liff_empty_reply

.Liff_hold_parent:
    cmp qword ptr [r15+32+rbx*8], 0
    jne .Liff_busy
    lea rdi, [rbp+64]
    mov rsi, r13
    call .Lifa_name
    test eax, eax
    jnz .Liff_no_context
    lea rdi, [rbp+64]
    mov esi, 0xb0000 /* O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW */
    xor edx, edx
    mov eax, 2
    syscall
    mov r13, rax
    cmp rax, -4095
    jae .Liff_empty_reply
    inc rax
    mov [r15+32+rbx*8], rax
    jmp .Liff_empty_reply
.Liff_drop_parent:
    mov rdi, [r15+32+rbx*8]
    test rdi, rdi
    jz .Liff_no_context
    dec rdi
    mov eax, 3
    syscall
    mov qword ptr [r15+32+rbx*8], 0
    mov r13, rax
    jmp .Liff_empty_reply
.Liff_close_retained:
    mov rdi, [r15+32+rbx*8]
    test rdi, rdi
    jz .Liff_no_context
    dec rdi
    mov eax, 3
    syscall
    mov r13, rax
    jmp .Liff_empty_reply
.Liff_parent_stat:
    mov rdi, [r15+32+rbx*8]
    test rdi, rdi
    jz .Liff_no_context
    dec rdi
    lea rsi, [r15+512]
    mov eax, 5
    syscall
    mov r13, rax
    test rax, rax
    jnz .Liff_empty_reply
    lea r14, [r15+512]
    mov ebp, 144
    jmp .Liff_reply

/* Move only the control pipe away from FD0, allowing actual parent/file FD0.
 * This never duplicates a target directory or file capability. */
.Liff_move_control:
    cmp qword ptr [r15+72], 0
    jne .Liff_no_context
    xor edi, edi
    mov eax, 32
    syscall
    cmp rax, -4095
    jae .Liff_fatal
    mov [r15+72], rax
    xor edi, edi
    mov eax, 3
    syscall
    test rax, rax
    jnz .Liff_fatal
    xor r13d, r13d
    jmp .Liff_empty_reply
.Liff_arm_fstat_error:
    cmp qword ptr [r15+88], 0
    jne .Liff_no_context
    mov qword ptr [r15+88], 1
    xor r13d, r13d
    jmp .Liff_empty_reply

.Liff_arm_read_fstat_error:
    cmp qword ptr [r15+88], 0
    jne .Liff_no_context
    mov qword ptr [r15+88], 2
    xor r13d, r13d
    jmp .Liff_empty_reply

.Liff_pool_snapshot:
    mov rax, [r15+80]
    mov r13, [rax+56]
    cmp r13, 65533
    ja .Liff_fatal
    mov rsi, r13
    shl rsi, 12
    add rsi, 4128
    lea rdi, [r15+208]
    call .Lifa_grow
    test eax, eax
    jnz .Liff_fatal
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
.Liff_pool_copy_page:
    test r13, r13
    jz .Liff_pool_copied
    test rdx, rdx
    jz .Liff_fatal
    lea rdi, [r14+rbp]
    mov rsi, rdx
    mov ecx, 4096
    rep movsb
    mov rdx, [rdx+16]
    add rbp, 4096
    dec r13
    jmp .Liff_pool_copy_page
.Liff_pool_copied:
    test rdx, rdx
    jnz .Liff_fatal
    xor r13d, r13d
    jmp .Liff_reply

.Liff_child_contexts:
    lea rdi, [r15+208]
    mov esi, 8192
    call .Lifa_grow
    test eax, eax
    jnz .Liff_fatal
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
    jmp .Liff_reply
.Liff_unowned_refusal:
    cmp qword ptr [r12+56], 0
    jne .Liff_no_context
    cmp qword ptr [r12+184], 0
    jne .Liff_no_context
    lea rbp, [r15+768]
    mov rdi, rbp
    xor eax, eax
    mov ecx, 8
    rep stosq
    mov qword ptr [rbp+24], 4
    mov qword ptr [rbp+32], 2147483647
    call .Lifa_capability
    mov r13, rax
    cmp eax, I_INVALID
    jne .Liff_fatal
    jmp .Liff_empty_reply

/* The root primitive rejects a copied pool in a distinct actual PID. */
.Liff_pool_fork_refusal:
    mov eax, 57
    syscall
    test rax, rax
    jz .Liff_orphan_child
    cmp rax, -4095
    jae .Liff_fatal
    mov [r15+304], rax
.Liff_orphan_wait:
    mov rdi, [r15+304]
    lea rsi, [r15+312]
    xor edx, edx
    xor r10d, r10d
    mov eax, 61
    syscall
    cmp rax, -4
    je .Liff_orphan_wait
    cmp rax, [r15+304]
    jne .Liff_fatal
    cmp dword ptr [r15+312], 0
    jne .Liff_fatal
    xor r13d, r13d
    jmp .Liff_empty_reply
.Liff_orphan_child:
    mov rdi, [r15+80]
    xor esi, esi
    mov rdx, r15
    mov ecx, 1
    call hia_process_orphans_append
    cmp rax, -22
    jne .Liff_fatal
    xor edi, edi
    mov eax, 60
    syscall

.Liff_context:
    mov r14, r12
    mov ebp, 4096
    xor r13d, r13d
    jmp .Liff_reply
.Liff_workspace:
    mov r14, [r12+88]
    mov rbp, [r12+96]
    xor r13d, r13d
    jmp .Liff_reply
.Liff_output:
    mov r14, [r12+104]
    mov rbp, [r12+112]
    xor r13d, r13d
    jmp .Liff_reply
.Liff_input:
    mov r14, [r12+64]
    mov rbp, [r12+72]
    xor r13d, r13d
    jmp .Liff_reply
.Liff_busy:
    mov r13d, I_BUSY
    jmp .Liff_empty_reply
.Liff_no_context:
    mov r13d, I_INVALID
.Liff_empty_reply:
    xor r14d, r14d
    xor ebp, ebp
.Liff_reply:
    lea rdi, [r15+128]
    xor eax, eax
    mov ecx, 8
    rep stosq
    mov rax, 0x3130524658464948 /* HIFXFR01 */
    mov [r15+128], rax
    mov [r15+136], r13
    mov [r15+144], rbp
    test r12, r12
    jz .Liff_reply_header
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
.Liff_reply_header:
    mov edi, 1
    lea rsi, [r15+128]
    mov edx, 64
    call .Liff_write_all
    test rax, rax
    jnz .Liff_fatal
    test rbp, rbp
    jz .Liff_loop
    mov edi, 1
    mov rsi, r14
    mov rdx, rbp
    call .Liff_write_all
    test rax, rax
    jnz .Liff_fatal
    jmp .Liff_loop

.Liff_eof:
    xor ebx, ebx
.Liff_eof_context:
    mov r12, [r15+rbx*8]
    test r12, r12
    jz .Liff_eof_parent
    cmp qword ptr [r12+56], 2
    jne .Liff_eof_destroy
    mov rdi, r12
    call file_info_at_release
    test eax, eax
    jnz .Liff_fatal
.Liff_eof_destroy:
    mov rdi, r12
    call file_info_at_destroy
    test eax, eax
    jnz .Liff_fatal
    mov qword ptr [r15+rbx*8], 0
.Liff_eof_parent:
    mov rdi, [r15+32+rbx*8]
    test rdi, rdi
    jz .Liff_eof_next
    dec rdi
    mov eax, 3
    syscall
    test rax, rax
    jz .Liff_eof_parent_closed
    cmp rax, -9
    jne .Liff_fatal
.Liff_eof_parent_closed:
    mov qword ptr [r15+32+rbx*8], 0
.Liff_eof_next:
    inc ebx
    cmp ebx, 2
    jb .Liff_eof_context
    mov rdi, [r15+72]
    test rdi, rdi
    jz .Liff_eof_exit
    mov eax, 3
    syscall
.Liff_eof_exit:
    /* The process-lifetime orphan pool and FDs are retired only by OS exit. */
    xor edi, edi
    mov eax, 60
    syscall
.Liff_fatal:
    mov edi, 111
    mov eax, 60
    syscall

.Liff_format:
    cmp qword ptr [r12+56], 2
    jne .Liff_no_context
    mov r14, [r12+104]
    cmp qword ptr [r14+8], 3
    jne .Liff_no_context
    mov rax, [r14+56]
    cmp rax, 64
    jb .Liff_fatal
    lea rdx, [r14+64]
    mov [r15+256], rdx
    mov [r15+264], rax
    mov qword ptr [r15+272], 0
    imul rsi, rax, 6
    jo .Liff_fatal
    add rsi, 1024
    jc .Liff_fatal
    cmp rsi, 134217728
    ja .Liff_fatal
    lea rdi, [r15+224]
    call .Lifa_grow
    test eax, eax
    jnz .Liff_fatal
    lea rdi, [r15+240]
    mov esi, 12288
    call .Lifa_grow
    test eax, eax
    jnz .Liff_fatal
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
    call .Liff_format_journal
    test rax, rax
    jnz .Liff_fatal
    mov rdi, r15
    mov esi, 2
    mov rdx, [r15+240]
    mov rcx, [r15+248]
    call .Liff_format_journal
    test rax, rax
    jnz .Liff_fatal
    mov rdi, r15
    mov esi, 3
    mov rdx, [r15+224]
    mov rcx, [r15+232]
    call .Liff_format_journal
    test rax, rax
    jnz .Liff_fatal
    mov rdi, [r15+256]
    mov rsi, [r15+264]
    mov rdx, [r15+224]
    mov rcx, [r15+232]
    mov r8, [r15+240]
    mov r9, [r15+248]
    call .Liff_error
    mov [r15+272], rax
    mov rdi, r15
    mov esi, 4
    mov rdx, [r15+224]
    mov rcx, [r15+232]
    call .Liff_format_journal
    test rax, rax
    jnz .Liff_fatal
    mov rdi, r15
    mov esi, 5
    mov rdx, [r15+240]
    mov rcx, [r15+248]
    call .Liff_format_journal
    test rax, rax
    jnz .Liff_fatal
    mov r13, [r15+272]
    cmp r13, [r15+232]
    ja .Liff_fatal
    mov r14, [r15+224]
    mov rbp, r13
    jmp .Liff_reply

.Liff_format_journal:
    cmp qword ptr [r12+40], 0
    jne .Liff_format_journal_observed
    xor eax, eax
    ret
.Liff_format_journal_observed:
    I_ENTER
    mov r12, rdi
    mov r13, rsi
    mov r14, rdx
    mov r15, rcx
    sub rsp, 64
    mov rdi, rsp
    xor eax, eax
    mov ecx, 8
    rep stosq
    mov rax, 0x3130305245464948 /* HIFER001 */
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
    call .Liff_write_all
    test rax, rax
    jnz .Liff_format_journal_done
    mov edi, 3
    mov rsi, r14
    mov rdx, r15
    call .Liff_write_all
.Liff_format_journal_done:
    add rsp, 64
    I_LEAVE

/* Actual seccomp filter, never an observer-provided syscall reply.
 * Only fstat / newfstatat for the just-opened owned FD gets kernel EIO.
 * It remains installed until this OS process exits. */
.Liff_install_fstat_error:
    I_ENTER
    mov r13, rdi
    cmp r13, 2147483647
    ja .Liff_filter_bad
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
    jnz .Liff_filter_done
    mov edi, 1 /* SECCOMP_SET_MODE_FILTER */
    xor esi, esi
    lea rdx, [rsp+64]
    mov eax, 317
    syscall
.Liff_filter_done:
    add rsp, 96
    jmp .Liff_filter_return
.Liff_filter_bad:
    mov rax, -22
.Liff_filter_return:
    I_LEAVE

.balign 16
.global file_info_at_error_call_displacement
.Liff_error:
    .byte 0xe9
file_info_at_error_call_displacement:
    .long 0
.Liff_read_exact:
    push rbx
    push r12
    push r13
    push r14
    mov rbx, rdi
    mov r12, rsi
    mov r13, rdx
    xor r14d, r14d
.Liff_read_loop:
    mov rdi, rbx
    lea rsi, [r12+r14]
    mov rdx, r13
    sub rdx, r14
    xor eax, eax
    syscall
    test rax, rax
    jz .Liff_read_eof
    cmp rax, -4
    je .Liff_read_loop
    cmp rax, -4095
    jae .Liff_read_done
    add r14, rax
    cmp r14, r13
    jb .Liff_read_loop
    mov rax, r13
    jmp .Liff_read_done
.Liff_read_eof:
    xor eax, eax
    test r14, r14
    jz .Liff_read_done
    mov rax, -22
.Liff_read_done:
    pop r14
    pop r13
    pop r12
    pop rbx
    ret
.Liff_write_all:
    push rbx
    push r12
    push r13
    push r14
    mov rbx, rdi
    mov r12, rsi
    mov r13, rdx
    xor r14d, r14d
.Liff_write_loop:
    cmp r14, r13
    je .Liff_write_success
    mov rdi, rbx
    lea rsi, [r12+r14]
    mov rdx, r13
    sub rdx, r14
    mov eax, 1
    syscall
    cmp rax, -4
    je .Liff_write_loop
    test rax, rax
    jz .Liff_write_zero
    cmp rax, -4095
    jae .Liff_write_done
    add r14, rax
    jmp .Liff_write_loop
.Liff_write_zero:
    mov rax, -5
    jmp .Liff_write_done
.Liff_write_success:
    xor eax, eax
.Liff_write_done:
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

/* Immutable observer binding: rdi private fixture context, rsi context, rdx event,
 * rcx complete owned span, r8 length. Full bytes are written synchronously. */
.Liff_journal:
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
    movabs rax, 0x31304943464e4948 /* HINFCI01 */
    cmp [r12], rax
    je .Liff_journal_info_magic
    movabs rax, 0x3130494344524248 /* HBRDCI01 */
    cmp [r12], rax
    je .Liff_journal_read_magic
    movabs rax, 0x3130494354444d48 /* HMDTCI01 */
    cmp [r12], rax
    jne .Liff_journal_hook_bad
    movabs rax, 0x3130524a54444d48 /* HMDTJR01 */
    jmp .Liff_journal_magic_ready
.Liff_journal_info_magic:
    movabs rax, 0x3130524a464e4948 /* HINFJR01 */
    jmp .Liff_journal_magic_ready
.Liff_journal_read_magic:
    movabs rax, 0x3130524a44524248 /* HBRDJR01 */
.Liff_journal_magic_ready:
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
    call .Liff_write_all
    test rax, rax
    jnz .Liff_journal_return
    mov edi, 3
    mov rsi, r14
    mov rdx, r15
    call .Liff_write_all
    test rax, rax
    jnz .Liff_journal_return
    cmp r13, 8
    jne .Liff_journal_return
    cmp r15, 64
    jb .Liff_journal_hook_bad
    /* The observer can delay a fixed raw OS request, never replace its result.
     * A separate actual fixture actor performs any frozen filesystem change. */
    movabs rax, 0x31304943464e4948
    cmp [r12], rax
    je .Liff_hook_info_magic
    movabs rax, 0x3130494344524248
    cmp [r12], rax
    je .Liff_hook_read_magic
    movabs rax, 0x31304b4854444d48 /* HMDTHK01 */
    jmp .Liff_hook_magic_ready
.Liff_hook_info_magic:
    movabs rax, 0x31304b48464e4948 /* HINFHK01 */
    jmp .Liff_hook_magic_ready
.Liff_hook_read_magic:
    movabs rax, 0x31304b4844524248 /* HBRDHK01 */
.Liff_hook_magic_ready:
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
    call .Liff_write_all
    test rax, rax
    jnz .Liff_journal_return
    mov edi, 5
    lea rsi, [rsp+128]
    mov edx, 8
    call .Liff_read_exact
    cmp rax, 8
    jne .Liff_journal_hook_bad
    cmp qword ptr [rsp+128], 0
    jne .Liff_journal_hook_bad
    cmp qword ptr [rbx+88], 1
    je .Liff_journal_info_fault
    cmp qword ptr [rbx+88], 2
    jne .Liff_journal_hook_ok
    movabs rax, 0x3130494344524248 /* HBRDCI01 */
    cmp [r12], rax
    jne .Liff_journal_hook_ok
    cmp qword ptr [r14+24], 6
    jne .Liff_journal_hook_ok
    mov rax, [r12+88]
    cmp qword ptr [rax+8], 25
    jne .Liff_journal_hook_ok
    jmp .Liff_journal_install_fault
.Liff_journal_info_fault:
    movabs rax, 0x31304943464e4948
    cmp [r12], rax
    jne .Liff_journal_hook_ok
    cmp qword ptr [r14+24], 2
    jne .Liff_journal_hook_ok
    mov rax, [r12+88]
    cmp qword ptr [rax+8], 13
    jne .Liff_journal_hook_ok
.Liff_journal_install_fault:
    mov rdi, [r14+32]
    call .Liff_install_fstat_error
    test rax, rax
    jnz .Liff_journal_return
    mov qword ptr [rbx+88], 0
    inc qword ptr [rbx+96]
.Liff_journal_hook_ok:
    xor eax, eax
    jmp .Liff_journal_return
.Liff_journal_hook_bad:
    mov rax, -22
.Liff_journal_return:
    add rsp, 136
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret
