/* Copyright 2026 Muvon Un Limited
 * SPDX-License-Identifier: Apache-2.0
 * Fixed synchronous binary-read capability. All binary-read policy is HIA.
 * Immutable image entries and the journal callback are trusted graph bindings.
 */
.intel_syntax noprefix
.section .text
.macro B_ENTER
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp, 8
.endm
.macro B_LEAVE
    add rsp, 8
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret
.endm
.equ B_MAGIC, 0x3130494344524248
.equ B_INVALID, 0xffffffff
.equ B_BUSY, 0xfffffffd
.equ B_RESOURCE, 0xfffffffc
.equ B_MAX_WORK, 268435456
.equ B_MAX_OUT, 134217728
.equ B_MAX_INPUT, 134217728
.equ B_REPLY_CAP, 2101248
.equ B_CHILD_OUT, 1400832

/* rdi nonzero page-aligned capacity; return a zeroed RW arena plus an inaccessible
 * final guard page. No input bytes select a mapping or a code entry. */
.Lbrd_map:
    test rdi, rdi
    jz .Lbrd_map_bad
    test rdi, 4095
    jnz .Lbrd_map_bad
    cmp rdi, B_MAX_WORK
    ja .Lbrd_map_bad
    push rbx
    mov rbx, rdi
    lea rsi, [rdi+4096]
    xor edi, edi
    mov edx, 3
    mov r10d, 0x22
    mov r8, -1
    xor r9d, r9d
    mov eax, 9
    syscall
    cmp rax, -4095
    jae .Lbrd_map_done
    push rax
    lea rdi, [rax+rbx]
    mov esi, 4096
    xor edx, edx
    mov eax, 10
    syscall
    test rax, rax
    jnz .Lbrd_map_guard_failed
    pop rax
    jmp .Lbrd_map_done
.Lbrd_map_guard_failed:
    pop rdi
    lea rsi, [rbx+4096]
    mov eax, 11
    syscall
    mov rax, -12
.Lbrd_map_done:
    pop rbx
    ret
.Lbrd_map_bad:
    mov rax, -22
    ret

/* Grow a pointer/capacity pair in a private context. rdi points to the pair,
 * rsi is the required extent. Every old byte is copied, the extension is zero.
 * The old mapping is retired only after allocation and copy are complete. */
.Lbrd_grow:
    B_ENTER
    mov r12, rdi
    mov r13, rsi
    test r13, r13
    jz .Lbrd_grow_bad
    cmp r13, B_MAX_WORK
    ja .Lbrd_grow_bad
    add r13, 4095
    jc .Lbrd_grow_bad
    and r13, -4096
    cmp r13, [r12+8]
    jbe .Lbrd_grow_ok
    mov rdi, r13
    call .Lbrd_map
    cmp rax, -4095
    jae .Lbrd_grow_resource
    mov r14, rax
    mov rdi, rax
    mov rsi, [r12]
    mov rcx, [r12+8]
    test rcx, rcx
    jz .Lbrd_grow_install
    test rsi, rsi
    jz .Lbrd_grow_new_failed
    rep movsb
    mov rdi, [r12]
    mov rsi, [r12+8]
    add rsi, 4096
    mov eax, 11
    syscall
    test rax, rax
    jnz .Lbrd_grow_new_failed
.Lbrd_grow_install:
    mov [r12], r14
    mov [r12+8], r13
.Lbrd_grow_ok:
    xor eax, eax
    jmp .Lbrd_grow_done
.Lbrd_grow_new_failed:
    mov rdi, r14
    lea rsi, [r13+4096]
    mov eax, 11
    syscall
.Lbrd_grow_resource:
    mov eax, B_RESOURCE
    jmp .Lbrd_grow_done
.Lbrd_grow_bad:
    mov eax, B_INVALID
.Lbrd_grow_done:
    B_LEAVE

/* Trusted rdi callback or zero, rsi callback context. */
.global binary_read_body_create
binary_read_body_create:
    B_ENTER
    mov r13, rdi
    mov r14, rsi
    mov edi, 4096
    call .Lbrd_map
    cmp rax, -4095
    jae .Lbrd_create_return
    mov r12, rax
    mov rax, B_MAGIC
    mov [r12], rax
    mov qword ptr [r12+8], 4096
    lea rax, [rip+.Lbrd_body]
    mov [r12+16], rax
    lea rax, [rip+.Lbrd_codec]
    mov [r12+24], rax
    lea rax, [rip+.Lbrd_stat]
    mov [r12+32], rax
    mov [r12+40], r13
    mov [r12+48], r14
    lea rdi, [r12+256]
    mov rax, -1
    mov ecx, 8
    rep stosq
    lea rdi, [r12+88]
    mov esi, 4096
    call .Lbrd_grow
    test eax, eax
    jnz .Lbrd_create_fail
    lea rdi, [r12+104]
    mov esi, 4096
    call .Lbrd_grow
    test eax, eax
    jnz .Lbrd_create_fail
    lea rdi, [r12+120]
    mov esi, B_REPLY_CAP
    call .Lbrd_grow
    test eax, eax
    jnz .Lbrd_create_fail
    mov edi, B_CHILD_OUT
    call .Lbrd_map
    cmp rax, -4095
    jae .Lbrd_create_fail
    mov [r12+136], rax
    mov edi, 4096
    call .Lbrd_map
    cmp rax, -4095
    jae .Lbrd_create_fail
    mov [r12+144], rax
    mov rax, r12
    jmp .Lbrd_create_return
.Lbrd_create_fail:
    mov rdi, r12
    call binary_read_body_destroy
    mov rax, -12
.Lbrd_create_return:
    B_LEAVE

/* An optional journal only observes already owned byte spans. The callback
 * returns zero and cannot replace a syscall or HIA result. r12=context,
 * rdx=event, rcx=span, r8=length. */
.Lbrd_emit:
    B_ENTER
    mov rbx, [r12+40]
    test rbx, rbx
    jz .Lbrd_emit_ok
    mov rdi, [r12+48]
    mov rsi, r12
    call rbx
    jmp .Lbrd_emit_return
.Lbrd_emit_ok:
    xor eax, eax
.Lbrd_emit_return:
    B_LEAVE

/* The graph holds a final response borrow until this explicit release. */
.global binary_read_body_release
binary_read_body_release:
    mov rax, B_MAGIC
    cmp [rdi], rax
    jne .Lbrd_release_bad
    cmp qword ptr [rdi+8], 4096
    jne .Lbrd_release_bad
    cmp qword ptr [rdi+56], 2
    jne .Lbrd_release_bad
    cmp qword ptr [rdi+184], 0
    jne .Lbrd_release_bad
    mov qword ptr [rdi+56], 0
    mov qword ptr [rdi+168], 0
    mov qword ptr [rdi+176], 0
    xor eax, eax
    ret
.Lbrd_release_bad:
    mov eax, B_INVALID
    ret

/* Destruction refuses active or borrowed contexts. Fatal private failures may
 * close still-owned OS descriptors; they never masquerade as body success. */
.global binary_read_body_destroy
binary_read_body_destroy:
    B_ENTER
    mov r12, rdi
    mov rax, B_MAGIC
    cmp [r12], rax
    jne .Lbrd_destroy_bad
    cmp qword ptr [r12+8], 4096
    jne .Lbrd_destroy_bad
    mov rax, [r12+56]
    cmp rax, 1
    je .Lbrd_destroy_busy
    cmp rax, 2
    je .Lbrd_destroy_busy
    cmp rax, 3
    ja .Lbrd_destroy_bad
    xor ebx, ebx
.Lbrd_destroy_fd:
    mov rdi, [r12+256+rbx*8]
    cmp rdi, -1
    je .Lbrd_destroy_fd_next
    mov eax, 3
    syscall
    mov qword ptr [r12+256+rbx*8], -1
.Lbrd_destroy_fd_next:
    inc ebx
    cmp ebx, 8
    jb .Lbrd_destroy_fd
    mov qword ptr [r12+184], 0
    lea r13, [rip+.Lbrd_pairs]
    mov ebx, 4
.Lbrd_destroy_pair:
    mov r14, [r13]
    mov rdi, [r12+r14]
    test rdi, rdi
    jz .Lbrd_destroy_pair_next
    mov rsi, [r12+r14+8]
    add rsi, 4096
    mov eax, 11
    syscall
    test rax, rax
    jnz .Lbrd_destroy_resource
    mov qword ptr [r12+r14], 0
    mov qword ptr [r12+r14+8], 0
.Lbrd_destroy_pair_next:
    add r13, 8
    dec ebx
    jnz .Lbrd_destroy_pair
    mov ebx, 136
.Lbrd_destroy_child:
    mov rdi, [r12+rbx]
    test rdi, rdi
    jz .Lbrd_destroy_child_next
    mov esi, 8192
    cmp ebx, 136
    jne .Lbrd_destroy_child_extent
    mov esi, B_CHILD_OUT+4096
.Lbrd_destroy_child_extent:
    mov eax, 11
    syscall
    test rax, rax
    jnz .Lbrd_destroy_resource
    mov qword ptr [r12+rbx], 0
.Lbrd_destroy_child_next:
    add ebx, 8
    cmp ebx, 152
    jb .Lbrd_destroy_child
    mov rdi, r12
    mov esi, 8192
    mov eax, 11
    syscall
    jmp .Lbrd_destroy_return
.Lbrd_destroy_busy:
    mov eax, B_BUSY
    jmp .Lbrd_destroy_return
.Lbrd_destroy_resource:
    mov eax, B_RESOURCE
    jmp .Lbrd_destroy_return
.Lbrd_destroy_bad:
    mov eax, B_INVALID
.Lbrd_destroy_return:
    B_LEAVE
.balign 8
.Lbrd_pairs:
    .quad 64,88,104,120

/* Only these checked native effects are available to the fixed HIA body. */
.Lbrd_fd_find:
    xor eax, eax
.Lbrd_fd_find_loop:
    cmp [r12+256+rax*8], rdi
    je .Lbrd_fd_find_return
    inc eax
    cmp eax, 8
    jb .Lbrd_fd_find_loop
    mov rax, -1
.Lbrd_fd_find_return:
    ret
.Lbrd_name:
    test rsi, rsi
    jz .Lbrd_name_bad
    mov rcx, rsi
    xor eax, eax
    repne scasb
    jne .Lbrd_name_bad
    test rcx, rcx
    jnz .Lbrd_name_bad
    xor eax, eax
    ret
.Lbrd_name_bad:
    mov eax, B_INVALID
    ret
.Lbrd_os:
    B_ENTER
    mov rbp, [r12+104]
    mov rbx, [rbp+24]
    mov qword ptr [r12+240], 0
    cmp rbx, 1
    je .Lbrd_os_root
    cmp rbx, 9
    je .Lbrd_os_euid
    mov rdi, [rbp+32]
    call .Lbrd_fd_find
    cmp rax, -1
    je .Lbrd_os_bad
    mov r15, rax
    cmp rbx, 2
    je .Lbrd_os_openat
    cmp rbx, 3
    je .Lbrd_os_openat
    cmp rbx, 5
    je .Lbrd_os_close
    cmp rbx, 6
    je .Lbrd_os_fstat
    cmp rbx, 11
    je .Lbrd_os_read
    cmp rbx, 19
    je .Lbrd_os_seek
    jmp .Lbrd_os_bad
.Lbrd_os_root:
    mov rax, [rbp+32]
    or rax, [rbp+40]
    or rax, [rbp+48]
    or rax, [rbp+56]
    jnz .Lbrd_os_bad
    lea rdi, [rip+.Lbrd_root_path]
    mov esi, 0xb0000
    xor edx, edx
    mov eax, 2
    syscall
    jmp .Lbrd_os_opened
.Lbrd_os_openat:
    mov rax, [rbp+40]
    or rax, [rbp+48]
    jnz .Lbrd_os_bad
    lea rdi, [rbp+64]
    mov rsi, [rbp+56]
    call .Lbrd_name
    test eax, eax
    jnz .Lbrd_os_bad
    mov edx, 0xb0000
    cmp rbx, 2
    je .Lbrd_os_openat_call
    mov edx, 0xa0800
.Lbrd_os_openat_call:
    mov rdi, [rbp+32]
    lea rsi, [rbp+64]
    xor r10d, r10d
    mov eax, 257
    syscall
.Lbrd_os_opened:
    mov [r12+232], rax
    cmp rax, -4095
    jae .Lbrd_os_ok
    mov r13, rax
    mov rdi, rax
    call .Lbrd_fd_find
    cmp rax, -1
    jne .Lbrd_os_bad
    xor eax, eax
.Lbrd_os_fd_insert:
    cmp qword ptr [r12+256+rax*8], -1
    je .Lbrd_os_fd_insert_at
    inc eax
    cmp eax, 8
    jb .Lbrd_os_fd_insert
    mov rdi, r13
    mov eax, 3
    syscall
    jmp .Lbrd_os_bad
.Lbrd_os_fd_insert_at:
    mov [r12+256+rax*8], r13
    inc qword ptr [r12+184]
    jmp .Lbrd_os_ok
.Lbrd_os_close:
    mov rax, [rbp+40]
    or rax, [rbp+48]
    or rax, [rbp+56]
    jnz .Lbrd_os_bad
    mov rdi, [rbp+32]
    mov eax, 3
    syscall
    mov [r12+232], rax
    /* Linux close retires this owned descriptor even on a late close error. */
    mov qword ptr [r12+256+r15*8], -1
    dec qword ptr [r12+184]
    jmp .Lbrd_os_ok
.Lbrd_os_fstat:
    mov rax, [rbp+40]
    or rax, [rbp+48]
    or rax, [rbp+56]
    jnz .Lbrd_os_bad
    mov rdi, [r12+120]
    add rdi, 96
    xor eax, eax
    mov ecx, 18
    rep stosq
    mov rdi, [rbp+32]
    mov rsi, [r12+120]
    add rsi, 96
    mov eax, 5
    syscall
    mov [r12+232], rax
    test rax, rax
    jnz .Lbrd_os_ok
    mov qword ptr [r12+240], 144
    jmp .Lbrd_os_ok
.Lbrd_os_euid:
    mov rax, [rbp+32]
    or rax, [rbp+40]
    or rax, [rbp+48]
    or rax, [rbp+56]
    jnz .Lbrd_os_bad
    mov eax, 107
    syscall
    jmp .Lbrd_os_return_raw
.Lbrd_os_read:
    mov rax, [rbp+48]
    or rax, [rbp+56]
    jnz .Lbrd_os_bad
    mov rdx, [rbp+40]
    test rdx, rdx
    jz .Lbrd_os_bad
    cmp rdx, 1048576
    ja .Lbrd_os_bad
    mov rdi, [rbp+32]
    mov rsi, [r12+120]
    add rsi, 96
    xor eax, eax
    syscall
    mov [r12+232], rax
    cmp rax, -4095
    jae .Lbrd_os_ok
    cmp rax, 1048576
    ja .Lbrd_os_bad
    mov [r12+240], rax
    jmp .Lbrd_os_ok
.Lbrd_os_seek:
    mov rax, [rbp+48]
    or rax, [rbp+56]
    jnz .Lbrd_os_bad
    mov rdi, [rbp+32]
    mov rsi, [rbp+40]
    xor edx, edx
    mov eax, 8
    syscall
.Lbrd_os_return_raw:
    mov [r12+232], rax
.Lbrd_os_ok:
    xor eax, eax
    jmp .Lbrd_os_done
.Lbrd_os_bad:
    mov eax, B_INVALID
.Lbrd_os_done:
    B_LEAVE
.Lbrd_root_path:
    .asciz "/"

/* rdi context, rsi immutable complete HBRDQ001 start, rdx length. */
.global binary_read_body_invoke
binary_read_body_invoke:
    B_ENTER
    mov r12, rdi
    mov r13, rsi
    mov r14, rdx
    mov rax, B_MAGIC
    cmp [r12], rax
    jne .Lbrd_invoke_reject
    cmp qword ptr [r12+8], 4096
    jne .Lbrd_invoke_reject
    cmp qword ptr [r12+56], 0
    jne .Lbrd_invoke_busy
    cmp qword ptr [r12+184], 0
    jne .Lbrd_invoke_reject
    cmp r14, 96
    jb .Lbrd_invoke_reject
    cmp r14, B_MAX_INPUT
    ja .Lbrd_invoke_reject
    test r13, r13
    jz .Lbrd_invoke_reject
    mov rax, 0x3130305144524248 /* HBRDQ001 */
    cmp [r13], rax
    jne .Lbrd_invoke_reject
    cmp qword ptr [r13+8], 1
    jne .Lbrd_invoke_reject
    cmp qword ptr [r13+16], 0
    jne .Lbrd_invoke_reject
    cmp qword ptr [r12+192], -1
    je .Lbrd_invoke_reject
    lea rdi, [r12+64]
    mov rsi, r14
    call .Lbrd_grow
    test eax, eax
    jnz .Lbrd_invoke_return
    mov rdi, [r12+64]
    mov rsi, r13
    mov rcx, r14
    rep movsb
    mov [r12+80], r14
    mov rax, [r12+64]
    mov [r12+200], rax
    mov [r12+208], r14
    inc qword ptr [r12+192]
    mov qword ptr [r12+248], 0
    mov qword ptr [r12+56], 1
    mov qword ptr [r12+168], 0
    mov qword ptr [r12+176], 0
.Lbrd_invoke_loop:
    inc qword ptr [r12+248]
    jz .Lbrd_invoke_failed
    mov rdi, [r12+104]
    mov rcx, [r12+112]
    shr rcx, 3
    mov rax, 0xa5a5a5a5a5a5a5a5
    rep stosq
    mov edx, 1
    mov rcx, [r12+200]
    mov r8, [r12+208]
    call .Lbrd_emit
    test rax, rax
    jnz .Lbrd_invoke_failed
    mov edx, 10
    mov rcx, [r12+88]
    mov r8, [r12+96]
    call .Lbrd_emit
    test rax, rax
    jnz .Lbrd_invoke_failed
    mov edx, 12
    mov rcx, [r12+104]
    mov r8, [r12+112]
    call .Lbrd_emit
    test rax, rax
    jnz .Lbrd_invoke_failed
    mov rdi, [r12+200]
    mov rsi, [r12+208]
    mov rdx, [r12+104]
    mov rcx, [r12+112]
    mov r8, [r12+88]
    mov r9, [r12+96]
    call qword ptr [r12+16]
    mov [r12+176], rax
    mov edx, 2
    mov rcx, [r12+104]
    mov r8, [r12+112]
    call .Lbrd_emit
    test rax, rax
    jnz .Lbrd_invoke_failed
    mov edx, 11
    mov rcx, [r12+88]
    mov r8, [r12+96]
    call .Lbrd_emit
    test rax, rax
    jnz .Lbrd_invoke_failed
    cmp qword ptr [r12+176], 64
    jne .Lbrd_invoke_failed
    mov rbp, [r12+104]
    mov rax, 0x3130305344524248 /* HBRDS001 */
    cmp [rbp], rax
    jne .Lbrd_invoke_failed
    mov rax, [r12+112]
    sub rax, 64
    cmp [rbp+56], rax
    ja .Lbrd_invoke_failed
    mov rbx, [rbp+8]
    cmp rbx, 5
    ja .Lbrd_invoke_failed
    test rbx, rbx
    jz .Lbrd_invoke_final
    cmp rbx, 3
    je .Lbrd_invoke_final
    cmp rbx, 4
    jae .Lbrd_invoke_growth
    mov rax, [rbp+16]
    mov [r12+216], rax
    mov rax, [rbp+24]
    mov [r12+224], rax
    cmp rbx, 2
    je .Lbrd_invoke_codec
    mov edx, 8
    mov rcx, rbp
    mov r8, [rbp+56]
    add r8, 64
    call .Lbrd_emit
    test rax, rax
    jnz .Lbrd_invoke_failed
    call .Lbrd_os
    test eax, eax
    jnz .Lbrd_invoke_failed
    jmp .Lbrd_invoke_reply
.Lbrd_invoke_codec:
    mov rax, [rbp+32]
    or rax, [rbp+40]
    or rax, [rbp+48]
    jnz .Lbrd_invoke_failed
    mov rax, [rbp+24]
    cmp rax, 2
    je .Lbrd_child_stat
    cmp rax, 1
    jne .Lbrd_invoke_failed
    mov rax, [r12+24]
    mov [r12+320], rax
    mov qword ptr [r12+328], 1398104
    mov qword ptr [r12+336], 1184
    jmp .Lbrd_child_start
.Lbrd_child_stat:
    mov rax, [r12+32]
    mov [r12+320], rax
    mov qword ptr [r12+328], 128
    mov qword ptr [r12+336], 256
.Lbrd_child_start:
    mov rdi, [r12+136]
    mov rcx, [r12+328]
    shr rcx, 3
    mov rax, 0xa5a5a5a5a5a5a5a5
    rep stosq
    mov rdi, [r12+144]
    mov rcx, [r12+336]
    shr rcx, 3
    xor eax, eax
    rep stosq
    mov edx, 5
    lea rcx, [rbp+64]
    mov r8, [rbp+56]
    call .Lbrd_emit
    test rax, rax
    jnz .Lbrd_invoke_failed
    mov edx, 13
    mov rcx, [r12+136]
    mov r8, [r12+328]
    call .Lbrd_emit
    test rax, rax
    jnz .Lbrd_invoke_failed
    mov edx, 14
    mov rcx, [r12+144]
    mov r8, [r12+336]
    call .Lbrd_emit
    test rax, rax
    jnz .Lbrd_invoke_failed
    lea rdi, [rbp+64]
    mov rsi, [rbp+56]
    mov rdx, [r12+136]
    mov rcx, [r12+328]
    mov r8, [r12+144]
    mov r9, [r12+336]
    call qword ptr [r12+320]
    mov [r12+232], rax
    cmp rax, [r12+328]
    ja .Lbrd_invoke_failed
    mov [r12+240], rax
    mov rdi, [r12+120]
    add rdi, 96
    mov rsi, [r12+136]
    mov rcx, rax
    rep movsb
    mov edx, 6
    mov rcx, [r12+136]
    mov r8, [r12+328]
    call .Lbrd_emit
    test rax, rax
    jnz .Lbrd_invoke_failed
    mov edx, 7
    mov rcx, [r12+144]
    mov r8, [r12+336]
    call .Lbrd_emit
    test rax, rax
    jnz .Lbrd_invoke_failed
.Lbrd_invoke_reply:
    mov rbx, [r12+120]
    mov rax, 0x3130305144524248
    mov [rbx], rax
    mov qword ptr [rbx+8], 2
    mov rax, [r12+216]
    mov [rbx+16], rax
    mov rax, [r12+232]
    mov [rbx+24], rax
    mov qword ptr [rbx+32], 0
    mov qword ptr [rbx+40], 0
    mov qword ptr [rbx+48], 0
    mov qword ptr [rbx+56], 0
    mov qword ptr [rbx+64], 0
    mov qword ptr [rbx+72], 0
    mov qword ptr [rbx+80], 0
    mov rax, [r12+240]
    cmp rax, [r12+128]
    ja .Lbrd_invoke_failed
    mov [rbx+88], rax
    add rax, 96
    cmp rax, [r12+128]
    ja .Lbrd_invoke_failed
    mov [r12+200], rbx
    mov [r12+208], rax
    mov edx, 9
    mov rcx, rbx
    mov r8, rax
    call .Lbrd_emit
    test rax, rax
    jnz .Lbrd_invoke_failed
    jmp .Lbrd_invoke_loop
.Lbrd_invoke_growth:
    mov rax, [rbp+16]
    or rax, [rbp+24]
    or rax, [rbp+40]
    or rax, [rbp+48]
    or rax, [rbp+56]
    jnz .Lbrd_invoke_failed
    mov r13, [rbp+32]
    cmp rbx, 4
    jne .Lbrd_invoke_output_growth
    cmp r13, [r12+96]
    jbe .Lbrd_invoke_failed
    cmp r13, B_MAX_WORK
    ja .Lbrd_invoke_failed
    mov edx, 3
    mov rcx, [r12+88]
    mov r8, [r12+96]
    call .Lbrd_emit
    test rax, rax
    jnz .Lbrd_invoke_failed
    lea rdi, [r12+88]
    mov rsi, r13
    call .Lbrd_grow
    test eax, eax
    jnz .Lbrd_invoke_resource
    mov edx, 4
    mov rcx, [r12+88]
    mov r8, [r12+96]
    call .Lbrd_emit
    test rax, rax
    jnz .Lbrd_invoke_failed
    jmp .Lbrd_invoke_loop
.Lbrd_invoke_output_growth:
    cmp r13, [r12+112]
    jbe .Lbrd_invoke_failed
    cmp r13, B_MAX_OUT
    ja .Lbrd_invoke_failed
    lea rdi, [r12+104]
    mov rsi, r13
    call .Lbrd_grow
    test eax, eax
    jnz .Lbrd_invoke_resource
    jmp .Lbrd_invoke_loop
.Lbrd_invoke_final:
    cmp qword ptr [r12+184], 0
    jne .Lbrd_invoke_failed
    cmp qword ptr [rbp+8], 3
    je .Lbrd_invoke_error
    mov rax, [rbp+24]
    or rax, [rbp+32]
    or rax, [rbp+40]
    or rax, [rbp+48]
    jnz .Lbrd_invoke_failed
    jmp .Lbrd_invoke_borrow
.Lbrd_invoke_error:
    cmp qword ptr [rbp+24], 1
    jb .Lbrd_invoke_failed
    cmp qword ptr [rbp+24], 14
    ja .Lbrd_invoke_failed
    cmp qword ptr [rbp+32], 4095
    ja .Lbrd_invoke_failed
    cmp qword ptr [rbp+48], 1
    ja .Lbrd_invoke_failed
    mov rax, [rbp+40]
    cmp rax, [rbp+56]
    ja .Lbrd_invoke_failed
.Lbrd_invoke_borrow:
    mov rax, [rbp+56]
    add rax, 64
    mov [r12+168], rax
    mov qword ptr [r12+56], 2
    mov eax, 64
    jmp .Lbrd_invoke_return
.Lbrd_invoke_resource:
    mov eax, B_RESOURCE
    jmp .Lbrd_invoke_record_failure
.Lbrd_invoke_failed:
    mov eax, B_INVALID
.Lbrd_invoke_record_failure:
    mov [r12+176], rax
    mov qword ptr [r12+56], 3
    mov qword ptr [r12+168], 0
    jmp .Lbrd_invoke_return
.Lbrd_invoke_busy:
    mov eax, B_BUSY
    jmp .Lbrd_invoke_return
.Lbrd_invoke_reject:
    mov eax, B_INVALID
.Lbrd_invoke_return:
    B_LEAVE

/* Fixed image entries patched only by the actual HIA image packer. */
.balign 16
.global binary_read_body_body_call_displacement
.Lbrd_body:
    .byte 0xe9
binary_read_body_body_call_displacement:
    .long 0
.global binary_read_body_codec_call_displacement
.Lbrd_codec:
    .byte 0xe9
binary_read_body_codec_call_displacement:
    .long 0
.global binary_read_body_stat_call_displacement
.Lbrd_stat:
    .byte 0xe9
binary_read_body_stat_call_displacement:
    .long 0
