/* Copyright 2026 Muvon Un Limited
 * Copyright 2026 TrillionniumFoundation
 * SPDX-License-Identifier: Apache-2.0
 * Private two-context binary write carrier. All parent FDs and the orphan pool belong
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
.Lwbf_check_pipes:
    mov esi, 1
    xor edx, edx
    mov eax, 72
    syscall
    cmp rax, -4095
    jae .Lwbf_fatal
    inc edi
    cmp edi, 6
    jb .Lwbf_check_pipes
    mov edi, 4096
    call .Lbw_map
    cmp rax, -4095
    jae .Lwbf_fatal
    mov r15, rax
    call hia_process_orphans_create
    cmp rax, -4095
    jae .Lwbf_fatal
    mov [r15+80], rax
    lea rdi, [rip+.Lwbf_entropy_journal]
    mov rsi, r15
    mov rdx, rax
    call binary_entropy_create
    cmp rax, -4095
    jae .Lwbf_fatal
    mov [r15+344], rax
    mov qword ptr [r15+448], 1
    mov qword ptr [r15+456], 0
    mov qword ptr [r15+464], 0
    mov qword ptr [r15+472], 0
    mov edi, 13
    lea rsi, [r15+448]
    xor edx, edx
    mov r10d, 8
    mov eax, 13
    syscall
    test rax, rax
    jnz .Lwbf_fatal
    mov edi, 25
    lea rsi, [r15+448]
    xor edx, edx
    mov r10d, 8
    mov eax, 13
    syscall
    test rax, rax
    jnz .Lwbf_fatal
.Lwbf_loop:
    mov rdi, [r15+72]
    lea rsi, [r15+64]
    mov edx, 8
    call .Lwbf_read_exact
    test rax, rax
    jz .Lwbf_eof
    cmp rax, 8
    jne .Lwbf_fatal
    mov r13, [r15+64]
    cmp r13, 64
    jb .Lwbf_fatal
    cmp r13, 134217792
    ja .Lwbf_fatal
    lea rdi, [r15+16]
    mov rsi, r13
    call .Lbw_grow
    test eax, eax
    jnz .Lwbf_fatal
    mov rdi, [r15+72]
    mov rsi, [r15+16]
    mov rdx, r13
    call .Lwbf_read_exact
    cmp rax, r13
    jne .Lwbf_fatal
    mov rbp, [r15+16]
    mov rax, 0x3130514654574248 /* HBWTFQ01 */
    cmp [rbp], rax
    jne .Lwbf_fatal
    mov rbx, [rbp+16]
    cmp rbx, 1
    ja .Lwbf_fatal
    mov r14, [rbp+8]
    cmp r14, 1
    jb .Lwbf_fatal
    cmp r14, 26
    ja .Lwbf_fatal
    mov rax, [rbp+32]
    or rax, [rbp+40]
    or rax, [rbp+48]
    or rax, [rbp+56]
    jnz .Lwbf_fatal
    sub r13, 64
    cmp [rbp+24], r13
    jne .Lwbf_fatal
    mov r12, [r15+rbx*8]
    cmp r14, 1
    je .Lwbf_invoke
    cmp r14, 10
    je .Lwbf_hold_parent
    cmp r14, 18
    je .Lwbf_arm_fault
    cmp r14, 24
    je .Lwbf_limit_file
    test r13, r13
    jnz .Lwbf_fatal
    cmp r14, 8
    je .Lwbf_create
    cmp r14, 9
    je .Lwbf_create_off
    cmp r14, 11
    je .Lwbf_pool_snapshot
    cmp r14, 12
    je .Lwbf_drop_parent
    cmp r14, 14
    je .Lwbf_parent_stat
    cmp r14, 16
    je .Lwbf_close_retained
    cmp r14, 17
    je .Lwbf_move_control
    cmp r14, 20
    je .Lwbf_pool_fork_refusal
    cmp r14, 21
    je .Lwbf_entropy_context
    cmp r14, 22
    je .Lwbf_entropy_workspace
    cmp r14, 23
    je .Lwbf_arm_eof
    cmp r14, 25
    je .Lwbf_null_pool
    cmp r14, 26
    je .Lwbf_null_entropy
    test r12, r12
    jz .Lwbf_no_context
    cmp r14, 2
    je .Lwbf_release
    cmp r14, 3
    je .Lwbf_destroy
    cmp r14, 4
    je .Lwbf_context
    cmp r14, 5
    je .Lwbf_workspace
    cmp r14, 6
    je .Lwbf_output
    cmp r14, 7
    je .Lwbf_input
    cmp r14, 13
    je .Lwbf_format
    cmp r14, 15
    je .Lwbf_child_contexts
    cmp r14, 19
    je .Lwbf_unowned_refusal
    jmp .Lwbf_fatal

.Lwbf_invoke:
    test r12, r12
    jnz .Lwbf_invoke_ready
    lea rdi, [rip+.Lwbf_journal]
    mov rsi, r15
    mov rdx, [r15+80]
    mov rcx, [r15+344]
    call binary_write_body_create
    cmp rax, -4095
    jae .Lwbf_fatal
    mov r12, rax
    mov [r15+rbx*8], rax
.Lwbf_invoke_ready:
    cmp r13, 96
    jb .Lwbf_no_context
    mov rsi, [r15+32+rbx*8]
    test rsi, rsi
    jz .Lwbf_no_context
    dec rsi
    mov qword ptr [r15+352], 0
    cmp qword ptr [r12+40], 0
    je .Lwbf_invoke_observer_ready
    mov qword ptr [r15+352], 1
.Lwbf_invoke_observer_ready:
    mov rdi, r12
    lea rdx, [rbp+64]
    mov rcx, r13
    call binary_write_body_invoke
    mov qword ptr [r15+352], 0
    mov r13, rax
    xor r14d, r14d
    xor ebp, ebp
    cmp rax, 64
    jne .Lwbf_reply
    mov r14, [r12+104]
    mov rbp, [r12+168]
    jmp .Lwbf_reply
.Lwbf_create:
    test r12, r12
    jnz .Lwbf_busy
    lea rdi, [rip+.Lwbf_journal]
    mov rsi, r15
    jmp .Lwbf_create_call
.Lwbf_create_off:
    test r12, r12
    jnz .Lwbf_busy
    xor edi, edi
    xor esi, esi
.Lwbf_create_call:
    mov rdx, [r15+80]
    mov rcx, [r15+344]
    call binary_write_body_create
    cmp rax, -4095
    jae .Lwbf_fatal
    mov r12, rax
    mov [r15+rbx*8], rax
    xor r13d, r13d
    jmp .Lwbf_empty_reply
.Lwbf_release:
    mov rdi, r12
    call binary_write_body_release
    mov r13, rax
    jmp .Lwbf_empty_reply
.Lwbf_destroy:
    mov rdi, r12
    call binary_write_body_destroy
    mov r13, rax
    test rax, rax
    jnz .Lwbf_empty_reply
    mov qword ptr [r15+rbx*8], 0
    xor r12d, r12d
    jmp .Lwbf_empty_reply

.Lwbf_hold_parent:
    cmp qword ptr [r15+32+rbx*8], 0
    jne .Lwbf_busy
    lea rdi, [rbp+64]
    mov rsi, r13
    call .Lbw_name
    test eax, eax
    jnz .Lwbf_no_context
    lea rdi, [rbp+64]
    mov esi, 0xb0000 /* O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW */
    xor edx, edx
    mov eax, 2
    syscall
    mov r13, rax
    cmp rax, -4095
    jae .Lwbf_empty_reply
    inc rax
    mov [r15+32+rbx*8], rax
    jmp .Lwbf_empty_reply
.Lwbf_drop_parent:
    mov rdi, [r15+32+rbx*8]
    test rdi, rdi
    jz .Lwbf_no_context
    dec rdi
    mov eax, 3
    syscall
    mov qword ptr [r15+32+rbx*8], 0
    mov r13, rax
    jmp .Lwbf_empty_reply
.Lwbf_close_retained:
    mov rdi, [r15+32+rbx*8]
    test rdi, rdi
    jz .Lwbf_no_context
    dec rdi
    mov eax, 3
    syscall
    mov r13, rax
    jmp .Lwbf_empty_reply
.Lwbf_parent_stat:
    mov rdi, [r15+32+rbx*8]
    test rdi, rdi
    jz .Lwbf_no_context
    dec rdi
    lea rsi, [r15+512]
    mov eax, 5
    syscall
    mov r13, rax
    test rax, rax
    jnz .Lwbf_empty_reply
    lea r14, [r15+512]
    mov ebp, 144
    jmp .Lwbf_reply

/* Move only the control pipe away from FD0, allowing actual parent/file FD0.
 * This never duplicates a target directory or file capability. */
.Lwbf_move_control:
    cmp qword ptr [r15+72], 0
    jne .Lwbf_no_context
    xor edi, edi
    mov eax, 32
    syscall
    cmp rax, -4095
    jae .Lwbf_fatal
    mov [r15+72], rax
    xor edi, edi
    mov eax, 3
    syscall
    test rax, rax
    jnz .Lwbf_fatal
    xor r13d, r13d
    jmp .Lwbf_empty_reply
.Lwbf_arm_fault:
    cmp r13, 56
    jb .Lwbf_no_context
    cmp r13, 224
    ja .Lwbf_no_context
    cmp qword ptr [r15+88], 0
    jne .Lwbf_no_context
    mov rax, r13
    xor edx, edx
    mov ecx, 56
    div rcx
    test rdx, rdx
    jnz .Lwbf_no_context
    mov r10, rax
    lea rsi, [rbp+64]
    xor r9d, r9d
.Lwbf_arm_validate:
    cmp qword ptr [rsi], 1
    jb .Lwbf_no_context
    cmp qword ptr [rsi], 5
    ja .Lwbf_no_context
    cmp qword ptr [rsi+8], 999
    ja .Lwbf_no_context
    cmp qword ptr [rsi+16], 1
    jb .Lwbf_no_context
    cmp qword ptr [rsi+16], 20
    ja .Lwbf_no_context
    cmp qword ptr [rsi+24], 1
    jb .Lwbf_no_context
    cmp qword ptr [rsi+24], 256
    ja .Lwbf_no_context
    cmp qword ptr [rsi+32], 511
    ja .Lwbf_no_context
    cmp qword ptr [rsi+40], 1
    jb .Lwbf_no_context
    cmp qword ptr [rsi+40], 4095
    ja .Lwbf_no_context
    cmp qword ptr [rsi+48], 1
    ja .Lwbf_no_context
    add rsi, 56
    inc r9
    cmp r9, r10
    jb .Lwbf_arm_validate
    lea rdi, [r15+1024]
    lea rsi, [rbp+64]
    mov rcx, r13
    rep movsb
    mov [r15+88], r10
    mov qword ptr [r15+320], 0
    mov qword ptr [r15+336], 0
    xor r13d, r13d
    jmp .Lwbf_empty_reply

/* Actual process resource bound; pipes carrying evidence remain unbounded. */
.Lwbf_limit_file:
    cmp r13, 8
    jne .Lwbf_no_context
    mov rax, [rbp+64]
    cmp rax, 1048576
    ja .Lwbf_no_context
    mov [r15+448], rax
    mov [r15+456], rax
    mov edi, 1
    lea rsi, [r15+448]
    mov eax, 160
    syscall
    mov r13, rax
    jmp .Lwbf_empty_reply

.Lwbf_pool_snapshot:
    mov rax, [r15+80]
    mov r13, [rax+56]
    cmp r13, 65533
    ja .Lwbf_fatal
    mov rsi, r13
    shl rsi, 12
    add rsi, 4128
    lea rdi, [r15+208]
    call .Lbw_grow
    test eax, eax
    jnz .Lwbf_fatal
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
.Lwbf_pool_copy_page:
    test r13, r13
    jz .Lwbf_pool_copied
    test rdx, rdx
    jz .Lwbf_fatal
    lea rdi, [r14+rbp]
    mov rsi, rdx
    mov ecx, 4096
    rep movsb
    mov rdx, [rdx+16]
    add rbp, 4096
    dec r13
    jmp .Lwbf_pool_copy_page
.Lwbf_pool_copied:
    test rdx, rdx
    jnz .Lwbf_fatal
    xor r13d, r13d
    jmp .Lwbf_reply

.Lwbf_entropy_context:
    mov r14, [r15+344]
    xor r13d, r13d
    mov ebp, 4096
    jmp .Lwbf_reply
.Lwbf_entropy_workspace:
    mov rax, [r15+344]
    mov r14, [rax+88]
    mov rbp, [rax+96]
    xor r13d, r13d
    jmp .Lwbf_reply
.Lwbf_arm_eof:
    mov qword ptr [r15+360], 1
    xor r13d, r13d
    jmp .Lwbf_empty_reply
.Lwbf_null_pool:
    xor edi, edi
    xor esi, esi
    xor edx, edx
    mov rcx, [r15+344]
    call binary_write_body_create
    cmp rax, -22
    jne .Lwbf_fatal
    mov r13, rax
    jmp .Lwbf_empty_reply
.Lwbf_null_entropy:
    xor edi, edi
    xor esi, esi
    mov rdx, [r15+80]
    xor ecx, ecx
    call binary_write_body_create
    cmp rax, -22
    jne .Lwbf_fatal
    mov r13, rax
    jmp .Lwbf_empty_reply

.Lwbf_child_contexts:
    lea rdi, [r15+208]
    mov esi, 16416
    call .Lbw_grow
    test eax, eax
    jnz .Lwbf_fatal
    mov r14, [r15+208]
    movabs rax, 0x3130584354574248
    mov [r14], rax
    mov qword ptr [r14+8], 4
    mov qword ptr [r14+16], 0
    mov qword ptr [r14+24], 0
    lea rdi, [r14+32]
    mov rsi, [r12+384]
    mov ecx, 4096
    rep movsb
    mov rsi, [r12+392]
    mov ecx, 4096
    rep movsb
    mov rsi, [r12+392]
    mov rsi, [rsi+392]
    mov ecx, 4096
    rep movsb
    mov rsi, [r15+344]
    mov ecx, 4096
    rep movsb
    xor r13d, r13d
    mov ebp, 16416
    jmp .Lwbf_reply

/* One process entropy context uses the current invocation's observer mode.
 * Disabling observation does not replace the context, cache, pool or HIA code. */
.Lwbf_entropy_journal:
    cmp qword ptr [rdi+352], 1
    je .Lwbf_journal
    xor eax, eax
    ret

.Lwbf_unowned_refusal:
    cmp qword ptr [r12+56], 0
    jne .Lwbf_no_context
    cmp qword ptr [r12+184], 0
    jne .Lwbf_no_context
    lea rbp, [r15+768]
    mov rdi, rbp
    xor eax, eax
    mov ecx, 8
    rep stosq
    mov qword ptr [rbp+24], 4
    mov qword ptr [rbp+32], 2147483647
    mov rax, [r15+32+rbx*8]
    test rax, rax
    jz .Lwbf_no_context
    dec rax
    mov [r12+344], rax
    mov qword ptr [r12+352], 1
    call .Lbw_capability
    mov qword ptr [r12+344], 0
    mov qword ptr [r12+352], 0
    mov r13, rax
    cmp eax, W_INVALID
    jne .Lwbf_fatal
    jmp .Lwbf_empty_reply

/* The root primitive rejects a copied pool in a distinct actual PID. */
.Lwbf_pool_fork_refusal:
    mov eax, 57
    syscall
    test rax, rax
    jz .Lwbf_orphan_child
    cmp rax, -4095
    jae .Lwbf_fatal
    mov [r15+304], rax
.Lwbf_orphan_wait:
    mov rdi, [r15+304]
    lea rsi, [r15+312]
    xor edx, edx
    xor r10d, r10d
    mov eax, 61
    syscall
    cmp rax, -4
    je .Lwbf_orphan_wait
    cmp rax, [r15+304]
    jne .Lwbf_fatal
    cmp dword ptr [r15+312], 0
    jne .Lwbf_fatal
    xor r13d, r13d
    jmp .Lwbf_empty_reply
.Lwbf_orphan_child:
    mov rdi, [r15+80]
    xor esi, esi
    mov rdx, r15
    mov ecx, 1
    call hia_process_orphans_append
    cmp rax, -22
    jne .Lwbf_fatal
    xor edi, edi
    mov eax, 60
    syscall

.Lwbf_context:
    mov r14, r12
    mov ebp, 4096
    xor r13d, r13d
    jmp .Lwbf_reply
.Lwbf_workspace:
    mov r14, [r12+88]
    mov rbp, [r12+96]
    xor r13d, r13d
    jmp .Lwbf_reply
.Lwbf_output:
    mov r14, [r12+104]
    mov rbp, [r12+112]
    xor r13d, r13d
    jmp .Lwbf_reply
.Lwbf_input:
    mov r14, [r12+64]
    mov rbp, [r12+72]
    xor r13d, r13d
    jmp .Lwbf_reply
.Lwbf_busy:
    mov r13d, W_BUSY
    jmp .Lwbf_empty_reply
.Lwbf_no_context:
    mov r13d, W_INVALID
.Lwbf_empty_reply:
    xor r14d, r14d
    xor ebp, ebp
.Lwbf_reply:
    lea rdi, [r15+128]
    xor eax, eax
    mov ecx, 8
    rep stosq
    mov rax, 0x3130524654574248 /* HBWTFR01 */
    mov [r15+128], rax
    mov [r15+136], r13
    mov [r15+144], rbp
    test r12, r12
    jz .Lwbf_reply_header
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
.Lwbf_reply_header:
    mov edi, 1
    lea rsi, [r15+128]
    mov edx, 64
    call .Lwbf_write_all
    test rax, rax
    jnz .Lwbf_fatal
    test rbp, rbp
    jz .Lwbf_loop
    mov edi, 1
    mov rsi, r14
    mov rdx, rbp
    call .Lwbf_write_all
    test rax, rax
    jnz .Lwbf_fatal
    jmp .Lwbf_loop

.Lwbf_eof:
    xor ebx, ebx
.Lwbf_eof_context:
    mov r12, [r15+rbx*8]
    test r12, r12
    jz .Lwbf_eof_parent
    cmp qword ptr [r12+56], 2
    jne .Lwbf_eof_destroy
    mov rdi, r12
    call binary_write_body_release
    test eax, eax
    jnz .Lwbf_fatal
.Lwbf_eof_destroy:
    mov rdi, r12
    call binary_write_body_destroy
    test eax, eax
    jnz .Lwbf_fatal
    mov qword ptr [r15+rbx*8], 0
.Lwbf_eof_parent:
    mov rdi, [r15+32+rbx*8]
    test rdi, rdi
    jz .Lwbf_eof_next
    dec rdi
    mov eax, 3
    syscall
    test rax, rax
    jz .Lwbf_eof_parent_closed
    cmp rax, -9
    jne .Lwbf_fatal
.Lwbf_eof_parent_closed:
    mov qword ptr [r15+32+rbx*8], 0
.Lwbf_eof_next:
    inc ebx
    cmp ebx, 2
    jb .Lwbf_eof_context
    mov rdi, [r15+72]
    test rdi, rdi
    jz .Lwbf_eof_exit
    mov eax, 3
    syscall
.Lwbf_eof_exit:
    cmp qword ptr [r15+360], 0
    je .Lwbf_eof_process_exit
    lea rdi, [r15+128]
    xor eax, eax
    mov ecx, 8
    rep stosq
    movabs rax, 0x31464f4554574248
    mov [r15+128], rax
    mov rax, [r15+80]
    mov rdx, [rax+48]
    mov [r15+136], rdx
    mov rdx, [rax+56]
    mov [r15+144], rdx
    mov rax, [r15+344]
    mov rdx, [rax+192]
    mov [r15+152], rdx
    mov rdx, [rax+88]
    mov rcx, [rdx]
    mov [r15+160], rcx
    mov rdx, [rdx+72]
    mov [r15+168], rdx
    mov rdx, [rax+184]
    mov [r15+176], rdx
    mov rdx, [rax+400]
    mov [r15+184], rdx
    mov edi, 4
    lea rsi, [r15+128]
    mov edx, 64
    call .Lwbf_write_all
    test rax, rax
    jnz .Lwbf_fatal
    mov edi, 5
    lea rsi, [r15+192]
    mov edx, 8
    call .Lwbf_read_exact
    cmp rax, 8
    jne .Lwbf_fatal
    cmp qword ptr [r15+192], 0
    jne .Lwbf_fatal
.Lwbf_eof_process_exit:
    /* The process-lifetime orphan pool and FDs are retired only by OS exit. */
    xor edi, edi
    mov eax, 60
    syscall
.Lwbf_fatal:
    mov edi, 111
    mov eax, 60
    syscall

.Lwbf_format:
    cmp qword ptr [r12+56], 2
    jne .Lwbf_no_context
    mov r14, [r12+104]
    cmp qword ptr [r14+8], 3
    jne .Lwbf_no_context
    mov rax, [r14+56]
    cmp rax, 64
    jb .Lwbf_fatal
    lea rdx, [r14+64]
    mov [r15+256], rdx
    mov [r15+264], rax
    mov qword ptr [r15+272], 0
    imul rsi, rax, 6
    jo .Lwbf_fatal
    add rsi, 1024
    jc .Lwbf_fatal
    cmp rsi, 134217728
    ja .Lwbf_fatal
    lea rdi, [r15+224]
    call .Lbw_grow
    test eax, eax
    jnz .Lwbf_fatal
    lea rdi, [r15+240]
    mov esi, 12288
    call .Lbw_grow
    test eax, eax
    jnz .Lwbf_fatal
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
    call .Lwbf_format_journal
    test rax, rax
    jnz .Lwbf_fatal
    mov rdi, r15
    mov esi, 2
    mov rdx, [r15+240]
    mov rcx, [r15+248]
    call .Lwbf_format_journal
    test rax, rax
    jnz .Lwbf_fatal
    mov rdi, r15
    mov esi, 3
    mov rdx, [r15+224]
    mov rcx, [r15+232]
    call .Lwbf_format_journal
    test rax, rax
    jnz .Lwbf_fatal
    mov rdi, [r15+256]
    mov rsi, [r15+264]
    mov rdx, [r15+224]
    mov rcx, [r15+232]
    mov r8, [r15+240]
    mov r9, [r15+248]
    call .Lwbf_error
    mov [r15+272], rax
    mov rdi, r15
    mov esi, 4
    mov rdx, [r15+224]
    mov rcx, [r15+232]
    call .Lwbf_format_journal
    test rax, rax
    jnz .Lwbf_fatal
    mov rdi, r15
    mov esi, 5
    mov rdx, [r15+240]
    mov rcx, [r15+248]
    call .Lwbf_format_journal
    test rax, rax
    jnz .Lwbf_fatal
    mov r13, [r15+272]
    cmp r13, [r15+232]
    ja .Lwbf_fatal
    mov r14, [r15+224]
    mov rbp, r13
    jmp .Lwbf_reply

.Lwbf_format_journal:
    cmp qword ptr [r12+40], 0
    jne .Lwbf_format_journal_observed
    xor eax, eax
    ret
.Lwbf_format_journal_observed:
    W_ENTER
    mov r12, rdi
    mov r13, rsi
    mov r14, rdx
    mov r15, rcx
    sub rsp, 64
    mov rdi, rsp
    xor eax, eax
    mov ecx, 8
    rep stosq
    mov rax, 0x3130524554574248 /* HBWTER01 */
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
    call .Lwbf_write_all
    test rax, rax
    jnz .Lwbf_format_journal_done
    mov edi, 3
    mov rsi, r14
    mov rdx, r15
    call .Lwbf_write_all
.Lwbf_format_journal_done:
    add rsp, 64
    W_LEAVE

/* Actual seccomp errno from the kernel. Match only the frozen syscall and,
 * when selected, its real first FD argument. fstat also covers newfstatat.
 * No observer supplies a return value, replacement file bytes or stat bytes. */
.Lwbf_install_fault:
    W_ENTER
    mov r13, rdi
    mov r14, rsi
    mov r15, rdx
    mov rbp, rcx
    cmp rbp, 1
    ja .Lwbf_filter_bad
    test rbp, rbp
    jz .Lwbf_filter_fd_ready
    cmp r13, 2147483647
    ja .Lwbf_filter_bad
.Lwbf_filter_fd_ready:
    cmp r14, 511
    ja .Lwbf_filter_bad
    cmp r15, 1
    jb .Lwbf_filter_bad
    cmp r15, 4095
    ja .Lwbf_filter_bad
    sub rsp, 96
    mov rdi, rsp
    xor eax, eax
    mov ecx, 12
    rep stosq
    mov qword ptr [rsp], 0x20
    mov rax, r14
    shl rax, 32
    or rax, 0x00010015
    test rbp, rbp
    jnz .Lwbf_filter_first
    or rax, 0x00020000
.Lwbf_filter_first:
    mov [rsp+8], rax
    mov rax, r14
    cmp r14, 5
    jne .Lwbf_filter_alias
    mov eax, 262
.Lwbf_filter_alias:
    shl rax, 32
    or rax, 0x03000015
    test rbp, rbp
    jnz .Lwbf_filter_second
    or rax, 0x00020000
.Lwbf_filter_second:
    mov [rsp+16], rax
    movabs rax, 0x0000001000000020
    mov [rsp+24], rax
    mov rax, r13
    shl rax, 32
    or rax, 0x01000015
    mov [rsp+32], rax
    mov rax, r15
    or rax, 0x50000
    shl rax, 32
    or rax, 6
    mov [rsp+40], rax
    movabs rax, 0x7fff000000000006
    mov [rsp+48], rax
    mov word ptr [rsp+64], 7
    lea rax, [rsp]
    mov [rsp+72], rax
    mov edi, 38
    mov esi, 1
    xor edx, edx
    xor r10d, r10d
    xor r8d, r8d
    mov eax, 157
    syscall
    test rax, rax
    jnz .Lwbf_filter_done
    mov edi, 1
    xor esi, esi
    lea rdx, [rsp+64]
    mov eax, 317
    syscall
.Lwbf_filter_done:
    add rsp, 96
    jmp .Lwbf_filter_return
.Lwbf_filter_bad:
    mov rax, -22
.Lwbf_filter_return:
    W_LEAVE

.balign 16
.global binary_write_body_error_call_displacement
.Lwbf_error:
    .byte 0xe9
binary_write_body_error_call_displacement:
    .long 0
.Lwbf_read_exact:
    push rbx
    push r12
    push r13
    push r14
    mov rbx, rdi
    mov r12, rsi
    mov r13, rdx
    xor r14d, r14d
.Lwbf_read_loop:
    mov rdi, rbx
    lea rsi, [r12+r14]
    mov rdx, r13
    sub rdx, r14
    xor eax, eax
    syscall
    test rax, rax
    jz .Lwbf_read_eof
    cmp rax, -4
    je .Lwbf_read_loop
    cmp rax, -4095
    jae .Lwbf_read_done
    add r14, rax
    cmp r14, r13
    jb .Lwbf_read_loop
    mov rax, r13
    jmp .Lwbf_read_done
.Lwbf_read_eof:
    xor eax, eax
    test r14, r14
    jz .Lwbf_read_done
    mov rax, -22
.Lwbf_read_done:
    pop r14
    pop r13
    pop r12
    pop rbx
    ret
.Lwbf_write_all:
    push rbx
    push r12
    push r13
    push r14
    mov rbx, rdi
    mov r12, rsi
    mov r13, rdx
    xor r14d, r14d
.Lwbf_write_loop:
    cmp r14, r13
    je .Lwbf_write_success
    mov rdi, rbx
    lea rsi, [r12+r14]
    mov rdx, r13
    sub rdx, r14
    mov eax, 1
    syscall
    cmp rax, -4
    je .Lwbf_write_loop
    test rax, rax
    jz .Lwbf_write_zero
    cmp rax, -4095
    jae .Lwbf_write_done
    add r14, rax
    jmp .Lwbf_write_loop
.Lwbf_write_zero:
    mov rax, -5
    jmp .Lwbf_write_done
.Lwbf_write_success:
    xor eax, eax
.Lwbf_write_done:
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

/* Immutable observer binding: rdi private fixture context, rsi context, rdx event,
 * rcx complete owned span, r8 length. Full bytes are written synchronously. */
.Lwbf_journal:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp, 152
    mov rbx, rdi
    mov r12, rsi
    mov r13, rdx
    mov r14, rcx
    mov r15, r8
    lea rdi, [rsp]
    xor eax, eax
    mov ecx, 16
    rep stosq
    movabs rax, 0x3130494354574248
    cmp [r12], rax
    je .Lwbf_journal_write_magic
    movabs rax, 0x3130494342555048
    cmp [r12], rax
    je .Lwbf_journal_publish_magic
    movabs rax, 0x3130494344524248
    cmp [r12], rax
    je .Lwbf_journal_read_magic
    movabs rax, 0x31304943544e4548
    cmp [r12], rax
    je .Lwbf_journal_entropy_magic
    movabs rax, 0x3130494354444d48
    cmp [r12], rax
    jne .Lwbf_journal_hook_bad
    mov qword ptr [rsp+136], 5
    movabs rax, 0x3130524a54444d48
    jmp .Lwbf_journal_magic_ready
.Lwbf_journal_write_magic:
    mov qword ptr [rsp+136], 1
    movabs rax, 0x3130524a54574248
    jmp .Lwbf_journal_magic_ready
.Lwbf_journal_publish_magic:
    mov qword ptr [rsp+136], 2
    movabs rax, 0x3130524a42555048
    jmp .Lwbf_journal_magic_ready
.Lwbf_journal_read_magic:
    mov qword ptr [rsp+136], 3
    movabs rax, 0x3130524a44524248
    jmp .Lwbf_journal_magic_ready
.Lwbf_journal_entropy_magic:
    mov qword ptr [rsp+136], 4
    movabs rax, 0x3130524a544e4548

.Lwbf_journal_magic_ready:
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
    call .Lwbf_write_all
    test rax, rax
    jnz .Lwbf_journal_return
    mov edi, 3
    mov rsi, r14
    mov rdx, r15
    call .Lwbf_write_all
    test rax, rax
    jnz .Lwbf_journal_return
    cmp r13, 8
    jne .Lwbf_journal_return
    cmp r15, 64
    jb .Lwbf_journal_hook_bad
    /* The observer can delay a fixed raw OS request, never replace its result.
     * A separate actual fixture actor performs any frozen filesystem change. */
    cmp qword ptr [rsp+136], 1
    je .Lwbf_hook_write_magic
    cmp qword ptr [rsp+136], 2
    je .Lwbf_hook_publish_magic
    cmp qword ptr [rsp+136], 3
    je .Lwbf_hook_read_magic
    cmp qword ptr [rsp+136], 4
    je .Lwbf_hook_entropy_magic
    movabs rax, 0x31304b4854444d48
    jmp .Lwbf_hook_magic_ready
.Lwbf_hook_write_magic:
    movabs rax, 0x31304b4854574248
    jmp .Lwbf_hook_magic_ready
.Lwbf_hook_publish_magic:
    movabs rax, 0x31304b4842555048
    jmp .Lwbf_hook_magic_ready
.Lwbf_hook_read_magic:
    movabs rax, 0x31304b4844524248
    jmp .Lwbf_hook_magic_ready
.Lwbf_hook_entropy_magic:
    movabs rax, 0x31304b48544e4548

.Lwbf_hook_magic_ready:
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
    call .Lwbf_write_all
    test rax, rax
    jnz .Lwbf_journal_return
    mov edi, 5
    lea rsi, [rsp+128]
    mov edx, 8
    call .Lwbf_read_exact
    cmp rax, 8
    jne .Lwbf_journal_hook_bad
    cmp qword ptr [rsp+128], 0
    jne .Lwbf_journal_hook_bad
    cmp qword ptr [rbx+88], 0
    je .Lwbf_journal_hook_ok
    mov rax, [rbx+320]
    imul rax, 56
    lea rbp, [rbx+1024+rax]
    mov rax, [rsp+136]
    cmp [rbp], rax
    jne .Lwbf_journal_hook_ok
    mov rax, [r12+88]
    mov rax, [rax+8]
    cmp [rbp+8], rax
    jne .Lwbf_journal_hook_ok
    mov rax, [r14+24]
    cmp [rbp+16], rax
    jne .Lwbf_journal_hook_ok
    inc qword ptr [rbx+336]
    mov rax, [rbx+336]
    cmp [rbp+24], rax
    jne .Lwbf_journal_hook_ok
    mov rdi, [r14+32]
    mov rsi, [rbp+32]
    mov rdx, [rbp+40]
    mov rcx, [rbp+48]
    call .Lwbf_install_fault
    test rax, rax
    jnz .Lwbf_journal_return
    inc qword ptr [rbx+96]
    inc qword ptr [rbx+320]
    mov qword ptr [rbx+336], 0
    mov rax, [rbx+320]
    cmp rax, [rbx+88]
    jne .Lwbf_journal_hook_ok
    mov qword ptr [rbx+88], 0
.Lwbf_journal_hook_ok:
    xor eax, eax
    jmp .Lwbf_journal_return
.Lwbf_journal_hook_bad:
    mov rax, -22
.Lwbf_journal_return:
    add rsp, 152
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret
