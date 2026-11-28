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
    call hia_process_orphans_create
    cmp rax, -4095
    jae .Lbrf_fatal
    mov [r15+80], rax
.Lbrf_loop:
    mov rdi, [r15+72]
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
    mov rdi, [r15+72]
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
    cmp r14, 25
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
    mov r12, [r15+rbx*8]
    cmp r14, 14
    je .Lbrf_pool_snapshot
    cmp r14, 15
    je .Lbrf_arm_first
    cmp r14, 16
    je .Lbrf_arm_second
    cmp r14, 17
    je .Lbrf_move_control
    cmp r14, 20
    je .Lbrf_pool_fork_refusal
    cmp r14, 21
    je .Lbrf_close_retained
    cmp r14, 22
    je .Lbrf_arm_eof
    cmp r14, 23
    je .Lbrf_arm_last
    cmp r14, 24
    je .Lbrf_null_pool_refusal
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
    cmp r14, 18
    je .Lbrf_unowned_refusal
    cmp r14, 19
    je .Lbrf_borrowed_refusal
    cmp r14, 25
    je .Lbrf_sentinel_refusal
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
    mov rsi, r15
    mov rdx, [r15+80]
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
    inc rax /* Stored FD+1, so an actual held parent FD0 remains representable. */
    mov [r15+32+rbx*8], rax
    jmp .Lbrf_reply
.Lbrf_invoke_at:
    mov r12, [r15+rbx*8]
    cmp qword ptr [r15+32+rbx*8], 0
    je .Lbrf_no_context
    test r12, r12
    jnz .Lbrf_invoke_at_ready
    lea rdi, [rip+.Lbrf_journal]
    mov rsi, r15
    mov rdx, [r15+80]
    call binary_read_body_create
    cmp rax, -4095
    jae .Lbrf_fatal
    mov r12, rax
    mov [r15+rbx*8], rax
.Lbrf_invoke_at_ready:
    mov rdi, r12
    mov rsi, [r15+32+rbx*8]
    dec rsi
    lea rdx, [rbp+64]
    mov rcx, r13
    call binary_read_body_invoke_at
    jmp .Lbrf_invocation_returned
.Lbrf_drop_parent:
    mov r12, [r15+rbx*8]
    mov rdi, [r15+32+rbx*8]
    test rdi, rdi
    jz .Lbrf_no_context
    dec rdi
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
    dec rdi
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
    mov rsi, r15
    mov rdx, [r15+80]
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
    mov rdx, [r15+80]
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
/* Fixed private fixture-only controls. They do not add callable policy. */
.Lbrf_move_control:
    cmp qword ptr [r15+72], 0
    jne .Lbrf_no_context
    xor edi, edi
    mov eax, 32
    syscall
    cmp rax, -4095
    jae .Lbrf_fatal
    mov [r15+72], rax
    xor edi, edi
    mov eax, 3
    syscall
    test rax, rax
    jnz .Lbrf_fatal
    xor r13d, r13d
    jmp .Lbrf_empty_reply
.Lbrf_arm_first:
    mov eax, 25
    jmp .Lbrf_arm_stat
.Lbrf_arm_second:
    mov eax, 29
    jmp .Lbrf_arm_stat
.Lbrf_arm_last:
    mov eax, 255
.Lbrf_arm_stat:
    cmp qword ptr [r15+88], 0
    jne .Lbrf_no_context
    mov [r15+88], rax
    xor r13d, r13d
    jmp .Lbrf_empty_reply
.Lbrf_arm_eof:
    cmp qword ptr [r15+120], 0
    jne .Lbrf_no_context
    mov qword ptr [r15+120], 1
    xor r13d, r13d
    jmp .Lbrf_empty_reply
.Lbrf_close_retained:
    mov rdi, [r15+32+rbx*8]
    test rdi, rdi
    jz .Lbrf_no_context
    dec rdi
    mov eax, 3
    syscall
    mov r13, rax
    jmp .Lbrf_empty_reply
.Lbrf_null_pool_refusal:
    xor edi, edi
    xor esi, esi
    xor edx, edx
    call binary_read_body_create
    cmp rax, -22
    jne .Lbrf_fatal
    mov r13, rax
    jmp .Lbrf_empty_reply
.Lbrf_unowned_refusal:
    mov r13d, 2147483647
    jmp .Lbrf_orphan_refusal
.Lbrf_sentinel_refusal:
    mov r13, -1
    jmp .Lbrf_orphan_refusal
.Lbrf_borrowed_refusal:
    mov r13, [r15+32+rbx*8]
    test r13, r13
    jz .Lbrf_no_context
    dec r13
.Lbrf_orphan_refusal:
    cmp qword ptr [r12+56], 0
    jne .Lbrf_no_context
    cmp qword ptr [r12+184], 0
    jne .Lbrf_no_context
    cmp qword ptr [r12+352], 0
    jne .Lbrf_no_context
    sub rsp, 80
    mov rdi, rsp
    mov rsi, [r12+104]
    mov ecx, 64
    rep movsb
    mov rax, [r12+232]
    mov [rsp+64], rax
    mov rax, [r12+240]
    mov [rsp+72], rax
    mov rdi, [r12+104]
    xor eax, eax
    mov ecx, 8
    rep stosq
    mov rbp, [r12+104]
    mov qword ptr [rbp+24], 4
    mov [rbp+32], r13
    cmp r14, 19
    jne .Lbrf_orphan_refusal_ready
    mov [r12+344], r13
    mov qword ptr [r12+352], 1
.Lbrf_orphan_refusal_ready:
    call .Lbrd_os
    mov r13, rax
    mov qword ptr [r12+344], 0
    mov qword ptr [r12+352], 0
    mov rdi, [r12+104]
    mov rsi, rsp
    mov ecx, 64
    rep movsb
    mov rax, [rsp+64]
    mov [r12+232], rax
    mov rax, [rsp+72]
    mov [r12+240], rax
    add rsp, 80
    cmp r13d, B_INVALID
    jne .Lbrf_fatal
    jmp .Lbrf_empty_reply
.Lbrf_empty_reply:
    xor r14d, r14d
    xor ebp, ebp
    jmp .Lbrf_reply

.Lbrf_pool_snapshot:
    mov rax, [r15+80]
    mov r13, [rax+56]
    cmp r13, 65533
    ja .Lbrf_fatal
    mov rsi, r13
    shl rsi, 12
    add rsi, 4128
    lea rdi, [r15+208]
    call .Lbrd_grow
    test eax, eax
    jnz .Lbrf_fatal
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
.Lbrf_pool_copy_page:
    test r13, r13
    jz .Lbrf_pool_copied
    test rdx, rdx
    jz .Lbrf_fatal
    lea rdi, [r14+rbp]
    mov rsi, rdx
    mov ecx, 4096
    rep movsb
    mov rdx, [rdx+16]
    add rbp, 4096
    dec r13
    jmp .Lbrf_pool_copy_page
.Lbrf_pool_copied:
    test rdx, rdx
    jnz .Lbrf_fatal
    xor r13d, r13d
    jmp .Lbrf_reply

/* The root primitive rejects a copied pool in a distinct actual PID. */
.Lbrf_pool_fork_refusal:
    mov eax, 57
    syscall
    test rax, rax
    jz .Lbrf_orphan_child
    cmp rax, -4095
    jae .Lbrf_fatal
    mov [r15+304], rax
.Lbrf_orphan_wait:
    mov rdi, [r15+304]
    lea rsi, [r15+312]
    xor edx, edx
    xor r10d, r10d
    mov eax, 61
    syscall
    cmp rax, -4
    je .Lbrf_orphan_wait
    cmp rax, [r15+304]
    jne .Lbrf_fatal
    cmp dword ptr [r15+312], 0
    jne .Lbrf_fatal
    xor r13d, r13d
    jmp .Lbrf_empty_reply
.Lbrf_orphan_child:
    mov rdi, [r15+80]
    xor esi, esi
    mov rdx, r15
    mov ecx, 1
    call hia_process_orphans_append
    cmp rax, -22
    jne .Lbrf_fatal
    xor edi, edi
    mov eax, 60
    syscall

/* Actual seccomp filter, never an observer-provided syscall reply.
 * Only fstat / newfstatat for the just-opened owned FD gets kernel EIO.
 * It remains installed until this OS process exits. */
.Lbrf_install_fstat_error:
    B_ENTER
    mov r13, rdi
    cmp r13, 2147483647
    ja .Lbrf_filter_bad
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
    jnz .Lbrf_filter_done
    mov edi, 1 /* SECCOMP_SET_MODE_FILTER */
    xor esi, esi
    lea rdx, [rsp+64]
    mov eax, 317
    syscall
.Lbrf_filter_done:
    add rsp, 96
    jmp .Lbrf_filter_return
.Lbrf_filter_bad:
    mov rax, -22
.Lbrf_filter_return:
    B_LEAVE

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
    dec rdi
    mov eax, 3
    syscall
    test rax, rax
    jz .Lbrf_eof_parent_closed
    cmp rax, -9
    jne .Lbrf_fatal
.Lbrf_eof_parent_closed:
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
    cmp qword ptr [r15+120], 1
    jne .Lbrf_eof_unmap
    lea rdi, [r15+256]
    xor eax, eax
    mov ecx, 8
    rep stosq
    movabs rax, 0x31464f4544524248 /* HBRDEOF1 */
    mov [r15+256], rax
    mov rax, [r15+80]
    mov rcx, [rax+48]
    mov [r15+264], rcx
    mov rcx, [rax+56]
    mov [r15+272], rcx
    mov edi, 4
    lea rsi, [r15+256]
    mov edx, 64
    call .Lbrf_write_all
    test rax, rax
    jnz .Lbrf_fatal
    mov edi, 5
    lea rsi, [r15+320]
    mov edx, 8
    call .Lbrf_read_exact
    cmp rax, 8
    jne .Lbrf_fatal
    cmp qword ptr [r15+320], 0
    jne .Lbrf_fatal
.Lbrf_eof_unmap:
    /* The shared orphan pool and its FDs are left alive until whole-process exit. */
    mov rdi, [r15+72]
    test rdi, rdi
    jz .Lbrf_eof_fixture
    mov eax, 3
    syscall
.Lbrf_eof_fixture:
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

/* Immutable observer binding: rdi private fixture context, rsi context, rdx event,
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
    mov edi, 3
    mov rsi, rsp
    mov edx, 128
    call .Lbrf_write_all
    test rax, rax
    jnz .Lbrf_journal_return
    mov edi, 3
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
    cmp qword ptr [rbx+88], 0
    je .Lbrf_journal_hook_ok
    cmp qword ptr [r14+24], 6
    jne .Lbrf_journal_hook_ok
    mov rax, [r12+88]
    mov rax, [rax+8]
    cmp qword ptr [rbx+88], 255
    je .Lbrf_journal_last_stat
    cmp rax, [rbx+88]
    jne .Lbrf_journal_hook_ok
    jmp .Lbrf_journal_install
.Lbrf_journal_last_stat:
    cmp rax, 39
    je .Lbrf_journal_install
    cmp rax, 49
    jne .Lbrf_journal_hook_ok
.Lbrf_journal_install:
    mov rdi, [r14+32]
    call .Lbrf_install_fstat_error
    test rax, rax
    jnz .Lbrf_journal_return
    mov qword ptr [rbx+88], 0
    inc qword ptr [rbx+96]
.Lbrf_journal_hook_ok:
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
