/* Copyright 2026 Muvon Un Limited
 * SPDX-License-Identifier: Apache-2.0
 * Fixed synchronous publication capability. All publication policy is HIA.
 * Immutable image entries and the journal callback are trusted graph bindings.
 */
.intel_syntax noprefix
.section .text
.macro P_ENTER
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp, 8
.endm
.macro P_LEAVE
    add rsp, 8
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret
.endm
.equ P_MAGIC, 0x3130494343505448
.equ P_INVALID, 0xffffffff
.equ P_BUSY, 0xfffffffd
.equ P_RESOURCE, 0xfffffffc
.equ P_MAX_WORK, 268435456
.equ P_MAX_OUT, 134217728
.equ P_MAX_INPUT, 50331712
.equ P_REPLY_CAP, 1052672

/* rdi nonzero page-aligned capacity; return a zeroed RW arena plus an inaccessible
 * final guard page. No input bytes select a mapping or a code entry. */
.Lptp_map:
    test rdi, rdi
    jz .Lptp_map_bad
    test rdi, 4095
    jnz .Lptp_map_bad
    cmp rdi, P_MAX_WORK
    ja .Lptp_map_bad
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
    jae .Lptp_map_done
    push rax
    lea rdi, [rax+rbx]
    mov esi, 4096
    xor edx, edx
    mov eax, 10
    syscall
    test rax, rax
    jnz .Lptp_map_guard_failed
    pop rax
    jmp .Lptp_map_done
.Lptp_map_guard_failed:
    pop rdi
    lea rsi, [rbx+4096]
    mov eax, 11
    syscall
    mov rax, -12
.Lptp_map_done:
    pop rbx
    ret
.Lptp_map_bad:
    mov rax, -22
    ret

/* Grow a pointer/capacity pair in a private context. rdi points to the pair,
 * rsi is the required extent. Every old byte is copied, the extension is zero.
 * The old mapping is retired only after allocation and copy are complete. */
.Lptp_grow:
    P_ENTER
    mov r12, rdi
    mov r13, rsi
    test r13, r13
    jz .Lptp_grow_bad
    cmp r13, P_MAX_WORK
    ja .Lptp_grow_bad
    add r13, 4095
    jc .Lptp_grow_bad
    and r13, -4096
    cmp r13, [r12+8]
    jbe .Lptp_grow_ok
    mov rdi, r13
    call .Lptp_map
    cmp rax, -4095
    jae .Lptp_grow_resource
    mov r14, rax
    mov rdi, rax
    mov rsi, [r12]
    mov rcx, [r12+8]
    test rcx, rcx
    jz .Lptp_grow_install
    test rsi, rsi
    jz .Lptp_grow_new_failed
    rep movsb
    mov rdi, [r12]
    mov rsi, [r12+8]
    add rsi, 4096
    mov eax, 11
    syscall
    test rax, rax
    jnz .Lptp_grow_new_failed
.Lptp_grow_install:
    mov [r12], r14
    mov [r12+8], r13
.Lptp_grow_ok:
    xor eax, eax
    jmp .Lptp_grow_done
.Lptp_grow_new_failed:
    mov rdi, r14
    lea rsi, [r13+4096]
    mov eax, 11
    syscall
.Lptp_grow_resource:
    mov eax, P_RESOURCE
    jmp .Lptp_grow_done
.Lptp_grow_bad:
    mov eax, P_INVALID
.Lptp_grow_done:
    P_LEAVE

/* Trusted rdi callback or zero, rsi callback context. */
.global text_publication_create
text_publication_create:
    P_ENTER
    mov r13, rdi
    mov r14, rsi
    mov edi, 4096
    call .Lptp_map
    cmp rax, -4095
    jae .Lptp_create_return
    mov r12, rax
    mov rax, P_MAGIC
    mov [r12], rax
    mov qword ptr [r12+8], 4096
    lea rax, [rip+.Lptp_body]
    mov [r12+16], rax
    lea rax, [rip+.Lptp_codec]
    mov [r12+24], rax
    lea rax, [rip+.Lptp_errno]
    mov [r12+32], rax
    mov [r12+40], r13
    mov [r12+48], r14
    lea rdi, [r12+256]
    mov rax, -1
    mov ecx, 8
    rep stosq
    lea rdi, [r12+88]
    mov esi, 4096
    call .Lptp_grow
    test eax, eax
    jnz .Lptp_create_fail
    lea rdi, [r12+104]
    mov esi, 4096
    call .Lptp_grow
    test eax, eax
    jnz .Lptp_create_fail
    lea rdi, [r12+120]
    mov esi, P_REPLY_CAP
    call .Lptp_grow
    test eax, eax
    jnz .Lptp_create_fail
    mov edi, 4096
    call .Lptp_map
    cmp rax, -4095
    jae .Lptp_create_fail
    mov [r12+136], rax
    mov edi, 4096
    call .Lptp_map
    cmp rax, -4095
    jae .Lptp_create_fail
    mov [r12+144], rax
    mov rax, r12
    jmp .Lptp_create_return
.Lptp_create_fail:
    mov rdi, r12
    call text_publication_destroy
    mov rax, -12
.Lptp_create_return:
    P_LEAVE

/* An optional journal only observes already owned byte spans. The callback
 * returns zero and cannot replace a syscall or HIA result. r12=context,
 * rdx=event, rcx=span, r8=length. */
.Lptp_emit:
    P_ENTER
    mov rbx, [r12+40]
    test rbx, rbx
    jz .Lptp_emit_ok
    mov rdi, [r12+48]
    mov rsi, r12
    call rbx
    jmp .Lptp_emit_return
.Lptp_emit_ok:
    xor eax, eax
.Lptp_emit_return:
    P_LEAVE

/* The graph holds a final response borrow until this explicit release. */
.global text_publication_release
text_publication_release:
    mov rax, P_MAGIC
    cmp [rdi], rax
    jne .Lptp_release_bad
    cmp qword ptr [rdi+8], 4096
    jne .Lptp_release_bad
    cmp qword ptr [rdi+56], 2
    jne .Lptp_release_bad
    cmp qword ptr [rdi+184], 0
    jne .Lptp_release_bad
    mov qword ptr [rdi+56], 0
    mov qword ptr [rdi+168], 0
    mov qword ptr [rdi+176], 0
    xor eax, eax
    ret
.Lptp_release_bad:
    mov eax, P_INVALID
    ret

/* Destruction refuses active or borrowed contexts. Fatal private failures may
 * close still-owned OS descriptors; they never masquerade as body success. */
.global text_publication_destroy
text_publication_destroy:
    P_ENTER
    mov r12, rdi
    mov rax, P_MAGIC
    cmp [r12], rax
    jne .Lptp_destroy_bad
    cmp qword ptr [r12+8], 4096
    jne .Lptp_destroy_bad
    mov rax, [r12+56]
    cmp rax, 1
    je .Lptp_destroy_busy
    cmp rax, 2
    je .Lptp_destroy_busy
    cmp rax, 3
    ja .Lptp_destroy_bad
    xor ebx, ebx
.Lptp_destroy_fd:
    mov rdi, [r12+256+rbx*8]
    cmp rdi, -1
    je .Lptp_destroy_fd_next
    mov eax, 3
    syscall
    mov qword ptr [r12+256+rbx*8], -1
.Lptp_destroy_fd_next:
    inc ebx
    cmp ebx, 8
    jb .Lptp_destroy_fd
    mov qword ptr [r12+184], 0
    lea r13, [rip+.Lptp_pairs]
    mov ebx, 4
.Lptp_destroy_pair:
    mov r14, [r13]
    mov rdi, [r12+r14]
    test rdi, rdi
    jz .Lptp_destroy_pair_next
    mov rsi, [r12+r14+8]
    add rsi, 4096
    mov eax, 11
    syscall
    test rax, rax
    jnz .Lptp_destroy_resource
    mov qword ptr [r12+r14], 0
    mov qword ptr [r12+r14+8], 0
.Lptp_destroy_pair_next:
    add r13, 8
    dec ebx
    jnz .Lptp_destroy_pair
    mov ebx, 136
.Lptp_destroy_child:
    mov rdi, [r12+rbx]
    test rdi, rdi
    jz .Lptp_destroy_child_next
    mov esi, 8192
    mov eax, 11
    syscall
    test rax, rax
    jnz .Lptp_destroy_resource
    mov qword ptr [r12+rbx], 0
.Lptp_destroy_child_next:
    add ebx, 8
    cmp ebx, 152
    jb .Lptp_destroy_child
    mov rdi, r12
    mov esi, 8192
    mov eax, 11
    syscall
    jmp .Lptp_destroy_return
.Lptp_destroy_busy:
    mov eax, P_BUSY
    jmp .Lptp_destroy_return
.Lptp_destroy_resource:
    mov eax, P_RESOURCE
    jmp .Lptp_destroy_return
.Lptp_destroy_bad:
    mov eax, P_INVALID
.Lptp_destroy_return:
    P_LEAVE
.balign 8
.Lptp_pairs:
    .quad 64,88,104,120

/* Only these checked native effects are available to the fixed HIA body. */
.Lptp_fd_find:
    xor eax, eax
.Lptp_fd_find_loop:
    cmp [r12+256+rax*8], rdi
    je .Lptp_fd_find_return
    inc eax
    cmp eax, 8
    jb .Lptp_fd_find_loop
    mov rax, -1
.Lptp_fd_find_return:
    ret
.Lptp_name:
    test rsi, rsi
    jz .Lptp_name_bad
    mov rcx, rsi
    xor eax, eax
    repne scasb
    jne .Lptp_name_bad
    test rcx, rcx
    jnz .Lptp_name_bad
    xor eax, eax
    ret
.Lptp_name_bad:
    mov eax, P_INVALID
    ret
.Lptp_os:
    P_ENTER
    mov rbp, [r12+104]
    mov rbx, [rbp+24]
    cmp rbx, 1
    jb .Lptp_os_bad
    cmp rbx, 18
    ja .Lptp_os_bad
    mov qword ptr [r12+240], 0
    cmp rbx, 1
    je .Lptp_os_root
    cmp rbx, 9
    je .Lptp_os_euid
    cmp rbx, 12
    je .Lptp_os_random
    cmp rbx, 18
    je .Lptp_os_error_text
    mov rdi, [rbp+32]
    call .Lptp_fd_find
    cmp rax, -1
    je .Lptp_os_bad
    mov r15, rax
    cmp rbx, 4
    jbe .Lptp_os_openat
    cmp rbx, 5
    je .Lptp_os_close
    cmp rbx, 6
    je .Lptp_os_fstat
    cmp rbx, 7
    je .Lptp_os_fstatat
    cmp rbx, 8
    je .Lptp_os_flock
    cmp rbx, 10
    je .Lptp_os_xattrs
    cmp rbx, 11
    je .Lptp_os_read
    cmp rbx, 13
    je .Lptp_os_fchmod
    cmp rbx, 14
    je .Lptp_os_write
    cmp rbx, 15
    je .Lptp_os_fsync
    cmp rbx, 16
    je .Lptp_os_rename
    cmp rbx, 17
    je .Lptp_os_unlink
    jmp .Lptp_os_bad
.Lptp_os_root:
    mov rax, [rbp+32]
    or rax, [rbp+40]
    or rax, [rbp+48]
    or rax, [rbp+56]
    jnz .Lptp_os_bad
    lea rdi, [rip+.Lptp_root_path]
    mov esi, 0xb0000 /* O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC */
    xor edx, edx
    mov eax, 2
    syscall
    jmp .Lptp_os_opened
.Lptp_os_openat:
    mov rax, [rbp+40]
    or rax, [rbp+48]
    jnz .Lptp_os_bad
    lea rdi, [rbp+64]
    mov rsi, [rbp+56]
    call .Lptp_name
    test eax, eax
    jnz .Lptp_os_bad
    mov edx, 0xb0000
    xor r10d, r10d
    cmp rbx, 2
    je .Lptp_os_openat_call
    mov edx, 0xa0800 /* RDONLY|NONBLOCK|NOFOLLOW|CLOEXEC */
    cmp rbx, 3
    je .Lptp_os_openat_call
    mov edx, 0xa00c1 /* WRONLY|CREAT|EXCL|NOFOLLOW|CLOEXEC */
    mov r10d, 0x180 /* 0600 */
.Lptp_os_openat_call:
    mov rdi, [rbp+32]
    lea rsi, [rbp+64]
    mov eax, 257
    syscall
.Lptp_os_opened:
    mov [r12+232], rax
    cmp rax, -4095
    jae .Lptp_os_ok
    mov r13, rax
    mov rdi, rax
    call .Lptp_fd_find
    cmp rax, -1
    jne .Lptp_os_bad
    xor eax, eax
.Lptp_os_fd_insert:
    cmp qword ptr [r12+256+rax*8], -1
    je .Lptp_os_fd_insert_at
    inc eax
    cmp eax, 8
    jb .Lptp_os_fd_insert
    mov rdi, r13
    mov eax, 3
    syscall
    jmp .Lptp_os_bad
.Lptp_os_fd_insert_at:
    mov [r12+256+rax*8], r13
    inc qword ptr [r12+184]
    jmp .Lptp_os_ok
.Lptp_os_close:
    mov rax, [rbp+40]
    or rax, [rbp+48]
    or rax, [rbp+56]
    jnz .Lptp_os_bad
    mov rdi, [rbp+32]
    mov eax, 3
    syscall
    mov [r12+232], rax
    test rax, rax
    jnz .Lptp_os_ok
    mov qword ptr [r12+256+r15*8], -1
    dec qword ptr [r12+184]
    jmp .Lptp_os_ok
.Lptp_os_fstat:
    mov rax, [rbp+40]
    or rax, [rbp+48]
    or rax, [rbp+56]
    jnz .Lptp_os_bad
    call .Lptp_stat_zero
    mov rdi, [rbp+32]
    mov rsi, [r12+120]
    add rsi, 64
    mov eax, 5
    syscall
    jmp .Lptp_os_stat_return
.Lptp_os_fstatat:
    mov rax, [rbp+40]
    or rax, [rbp+48]
    jnz .Lptp_os_bad
    lea rdi, [rbp+64]
    mov rsi, [rbp+56]
    call .Lptp_name
    test eax, eax
    jnz .Lptp_os_bad
    call .Lptp_stat_zero
    mov rdi, [rbp+32]
    lea rsi, [rbp+64]
    mov rdx, [r12+120]
    add rdx, 64
    mov r10d, 0x100
    mov eax, 262
    syscall
.Lptp_os_stat_return:
    mov [r12+232], rax
    test rax, rax
    jnz .Lptp_os_ok
    mov qword ptr [r12+240], 144
    jmp .Lptp_os_ok
.Lptp_os_flock:
    call .Lptp_os_empty_bc_payload
    test rax, rax
    jnz .Lptp_os_bad
    mov rdi, [rbp+32]
    mov esi, 2
    mov eax, 73
    syscall
    jmp .Lptp_os_return_raw
.Lptp_os_euid:
    mov rax, [rbp+32]
    or rax, [rbp+40]
    or rax, [rbp+48]
    or rax, [rbp+56]
    jnz .Lptp_os_bad
    mov eax, 107
    syscall
    jmp .Lptp_os_return_raw
.Lptp_os_xattrs:
    call .Lptp_os_empty_bc_payload
    test rax, rax
    jnz .Lptp_os_bad
    mov rdi, [rbp+32]
    xor esi, esi
    xor edx, edx
    mov eax, 196
    syscall
    jmp .Lptp_os_return_raw
.Lptp_os_read:
    mov rax, [rbp+48]
    or rax, [rbp+56]
    jnz .Lptp_os_bad
    mov rdx, [rbp+40]
    test rdx, rdx
    jz .Lptp_os_bad
    cmp rdx, 1048576
    ja .Lptp_os_bad
    mov rdi, [rbp+32]
    mov rsi, [r12+120]
    add rsi, 64
    xor eax, eax
    syscall
    jmp .Lptp_os_bytes_return
.Lptp_os_random:
    call .Lptp_os_empty_bc_payload
    test rax, rax
    jnz .Lptp_os_bad
    mov rsi, [rbp+32]
    test rsi, rsi
    jz .Lptp_os_bad
    cmp rsi, 1048576
    ja .Lptp_os_bad
    mov rdi, [r12+120]
    add rdi, 64
    xor edx, edx
    mov eax, 318
    syscall
.Lptp_os_bytes_return:
    mov [r12+232], rax
    cmp rax, -4095
    jae .Lptp_os_ok
    cmp rax, 1048576
    ja .Lptp_os_bad
    mov [r12+240], rax
    jmp .Lptp_os_ok
.Lptp_os_fchmod:
    mov rax, [rbp+48]
    or rax, [rbp+56]
    jnz .Lptp_os_bad
    cmp qword ptr [rbp+40], 511
    ja .Lptp_os_bad
    mov rdi, [rbp+32]
    mov rsi, [rbp+40]
    mov eax, 91
    syscall
    jmp .Lptp_os_return_raw
.Lptp_os_write:
    cmp qword ptr [rbp+48], 0
    jne .Lptp_os_bad
    mov rdx, [rbp+40]
    test rdx, rdx
    jz .Lptp_os_bad
    cmp rdx, 1048576
    ja .Lptp_os_bad
    cmp rdx, [rbp+56]
    jne .Lptp_os_bad
    mov rdi, [rbp+32]
    lea rsi, [rbp+64]
    mov eax, 1
    syscall
    jmp .Lptp_os_return_raw
.Lptp_os_fsync:
    call .Lptp_os_empty_bc_payload
    test rax, rax
    jnz .Lptp_os_bad
    mov rdi, [rbp+32]
    mov eax, 74
    syscall
    jmp .Lptp_os_return_raw
.Lptp_os_rename:
    cmp qword ptr [rbp+40], 1
    ja .Lptp_os_bad
    mov r13, [rbp+48]
    test r13, r13
    jz .Lptp_os_bad
    cmp r13, [rbp+56]
    jae .Lptp_os_bad
    lea rdi, [rbp+64]
    mov rsi, r13
    call .Lptp_name
    test eax, eax
    jnz .Lptp_os_bad
    lea rdi, [rbp+64+r13]
    mov rsi, [rbp+56]
    sub rsi, r13
    call .Lptp_name
    test eax, eax
    jnz .Lptp_os_bad
    mov rdi, [rbp+32]
    lea rsi, [rbp+64]
    mov rdx, rdi
    lea r10, [rbp+64+r13]
    mov r8, [rbp+40]
    mov eax, 316
    syscall
    jmp .Lptp_os_return_raw
.Lptp_os_unlink:
    mov rax, [rbp+40]
    or rax, [rbp+48]
    jnz .Lptp_os_bad
    lea rdi, [rbp+64]
    mov rsi, [rbp+56]
    call .Lptp_name
    test eax, eax
    jnz .Lptp_os_bad
    mov rdi, [rbp+32]
    lea rsi, [rbp+64]
    xor edx, edx
    mov eax, 263
    syscall
    jmp .Lptp_os_return_raw
.Lptp_os_error_text:
    call .Lptp_os_empty_bc_payload
    test rax, rax
    jnz .Lptp_os_bad
    mov r13, [rbp+32]
    test r13, r13
    jz .Lptp_os_bad
    cmp r13, 4095
    ja .Lptp_os_bad
    mov rax, 0x3130515245444d48 /* HMDERQ01 */
    mov [r12+320], rax
    mov [r12+328], r13
    mov rdi, [r12+136]
    mov ecx, 512
    mov rax, 0xa5a5a5a5a5a5a5a5
    rep stosq
    mov rdi, [r12+144]
    mov qword ptr [rdi], 0
    mov edx, 18
    lea rcx, [r12+320]
    mov r8d, 16
    call .Lptp_emit
    test rax, rax
    jnz .Lptp_os_bad
    lea rdi, [r12+320]
    mov esi, 16
    mov rdx, [r12+136]
    mov ecx, 4096
    mov r8, [r12+144]
    mov r9d, 8
    call qword ptr [r12+32]
    cmp rax, 24
    jb .Lptp_os_bad
    cmp rax, 4096
    ja .Lptp_os_bad
    mov r14, [r12+136]
    mov rdx, 0x3130525245444d48 /* HMDERR01 */
    cmp [r14], rdx
    jne .Lptp_os_bad
    cmp [r14+8], r13
    jne .Lptp_os_bad
    sub rax, 24
    cmp [r14+16], rax
    jne .Lptp_os_bad
    mov [r12+232], rax
    mov [r12+240], rax
    mov rdi, [r12+120]
    add rdi, 64
    lea rsi, [r14+24]
    mov rcx, rax
    rep movsb
    mov edx, 19
    mov rcx, r14
    mov r8d, 4096
    call .Lptp_emit
    test rax, rax
    jnz .Lptp_os_bad
    jmp .Lptp_os_ok
.Lptp_os_return_raw:
    mov [r12+232], rax
.Lptp_os_ok:
    xor eax, eax
    jmp .Lptp_os_done
.Lptp_os_bad:
    mov eax, P_INVALID
.Lptp_os_done:
    P_LEAVE
.Lptp_os_empty_bc_payload:
    mov rax, [rbp+40]
    or rax, [rbp+48]
    or rax, [rbp+56]
    ret
.Lptp_stat_zero:
    mov rdi, [r12+120]
    add rdi, 64
    xor eax, eax
    mov ecx, 18
    rep stosq
    ret
.Lptp_root_path:
    .asciz "/"

/* rdi context, rsi immutable complete HTPBQ001 start, rdx length. */
.global text_publication_invoke
text_publication_invoke:
    P_ENTER
    mov r12, rdi
    mov r13, rsi
    mov r14, rdx
    mov rax, P_MAGIC
    cmp [r12], rax
    jne .Lptp_invoke_reject
    cmp qword ptr [r12+8], 4096
    jne .Lptp_invoke_reject
    cmp qword ptr [r12+56], 0
    jne .Lptp_invoke_busy
    cmp qword ptr [r12+184], 0
    jne .Lptp_invoke_reject
    cmp r14, 64
    jb .Lptp_invoke_reject
    cmp r14, P_MAX_INPUT
    ja .Lptp_invoke_reject
    test r13, r13
    jz .Lptp_invoke_reject
    mov rax, 0x3130305142505448 /* HTPBQ001 */
    cmp [r13], rax
    jne .Lptp_invoke_reject
    cmp qword ptr [r13+8], 1
    jne .Lptp_invoke_reject
    cmp qword ptr [r13+16], 0
    jne .Lptp_invoke_reject
    cmp qword ptr [r12+192], -1
    je .Lptp_invoke_reject
    lea rdi, [r12+64]
    mov rsi, r14
    call .Lptp_grow
    test eax, eax
    jnz .Lptp_invoke_return
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
.Lptp_invoke_loop:
    inc qword ptr [r12+248]
    jz .Lptp_invoke_failed
    mov rdi, [r12+104]
    mov rcx, [r12+112]
    shr rcx, 3
    mov rax, 0xa5a5a5a5a5a5a5a5
    rep stosq
    mov edx, 1
    mov rcx, [r12+200]
    mov r8, [r12+208]
    call .Lptp_emit
    test rax, rax
    jnz .Lptp_invoke_failed
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
    call .Lptp_emit
    test rax, rax
    jnz .Lptp_invoke_failed
    cmp qword ptr [r12+176], 64
    jne .Lptp_invoke_failed
    mov rbp, [r12+104]
    mov rax, 0x3130305342505448 /* HTPBS001 */
    cmp [rbp], rax
    jne .Lptp_invoke_failed
    mov rax, [r12+112]
    sub rax, 64
    cmp [rbp+56], rax
    ja .Lptp_invoke_failed
    mov rbx, [rbp+8]
    cmp rbx, 5
    ja .Lptp_invoke_failed
    test rbx, rbx
    jz .Lptp_invoke_final
    cmp rbx, 3
    je .Lptp_invoke_final
    cmp rbx, 4
    jae .Lptp_invoke_growth
    mov rax, [rbp+16]
    mov [r12+216], rax
    mov rax, [rbp+24]
    mov [r12+224], rax
    cmp rbx, 2
    je .Lptp_invoke_codec
    mov edx, 8
    mov rcx, rbp
    mov r8, [rbp+56]
    add r8, 64
    call .Lptp_emit
    test rax, rax
    jnz .Lptp_invoke_failed
    call .Lptp_os
    test eax, eax
    jnz .Lptp_invoke_failed
    jmp .Lptp_invoke_reply
.Lptp_invoke_codec:
    mov rax, [rbp+32]
    or rax, [rbp+40]
    or rax, [rbp+48]
    jnz .Lptp_invoke_failed
    mov rax, [rbp+24]
    cmp rax, 3
    je .Lptp_codec_start
    cmp rax, 4
    je .Lptp_codec_start
    cmp rax, 6
    jne .Lptp_invoke_failed
.Lptp_codec_start:
    mov rdi, [r12+136]
    mov rcx, 16
    mov rax, 0xa5a5a5a5a5a5a5a5
    rep stosq
    mov rdi, [r12+144]
    mov ecx, 148
    xor eax, eax
    rep stosq
    mov edx, 5
    lea rcx, [rbp+64]
    mov r8, [rbp+56]
    call .Lptp_emit
    test rax, rax
    jnz .Lptp_invoke_failed
    lea rdi, [rbp+64]
    mov rsi, [rbp+56]
    mov rdx, [r12+136]
    mov ecx, 128
    mov r8, [r12+144]
    mov r9d, 1184
    call qword ptr [r12+24]
    mov [r12+232], rax
    cmp rax, 64
    je .Lptp_codec_returned
    cmp rax, 128
    jne .Lptp_invoke_failed
.Lptp_codec_returned:
    mov [r12+240], rax
    mov rdi, [r12+120]
    add rdi, 64
    mov rsi, [r12+136]
    mov rcx, rax
    rep movsb
    mov edx, 6
    mov rcx, [r12+136]
    mov r8d, 128
    call .Lptp_emit
    test rax, rax
    jnz .Lptp_invoke_failed
    mov edx, 7
    mov rcx, [r12+144]
    mov r8d, 1184
    call .Lptp_emit
    test rax, rax
    jnz .Lptp_invoke_failed
.Lptp_invoke_reply:
    mov rbx, [r12+120]
    mov rax, 0x3130305142505448
    mov [rbx], rax
    mov qword ptr [rbx+8], 2
    mov rax, [r12+216]
    mov [rbx+16], rax
    mov rax, [r12+232]
    mov [rbx+24], rax
    mov qword ptr [rbx+32], 0
    mov qword ptr [rbx+40], 0
    mov qword ptr [rbx+48], 0
    mov rax, [r12+240]
    cmp rax, [r12+128]
    ja .Lptp_invoke_failed
    mov [rbx+56], rax
    add rax, 64
    cmp rax, [r12+128]
    ja .Lptp_invoke_failed
    mov [r12+200], rbx
    mov [r12+208], rax
    mov edx, 9
    mov rcx, rbx
    mov r8, rax
    call .Lptp_emit
    test rax, rax
    jnz .Lptp_invoke_failed
    jmp .Lptp_invoke_loop
.Lptp_invoke_growth:
    mov rax, [rbp+16]
    or rax, [rbp+24]
    or rax, [rbp+40]
    or rax, [rbp+48]
    or rax, [rbp+56]
    jnz .Lptp_invoke_failed
    mov r13, [rbp+32]
    cmp rbx, 4
    jne .Lptp_invoke_output_growth
    cmp r13, [r12+96]
    jbe .Lptp_invoke_failed
    cmp r13, P_MAX_WORK
    ja .Lptp_invoke_failed
    mov edx, 3
    mov rcx, [r12+88]
    mov r8, [r12+96]
    call .Lptp_emit
    test rax, rax
    jnz .Lptp_invoke_failed
    lea rdi, [r12+88]
    mov rsi, r13
    call .Lptp_grow
    test eax, eax
    jnz .Lptp_invoke_resource
    mov edx, 4
    mov rcx, [r12+88]
    mov r8, [r12+96]
    call .Lptp_emit
    test rax, rax
    jnz .Lptp_invoke_failed
    jmp .Lptp_invoke_loop
.Lptp_invoke_output_growth:
    cmp r13, [r12+112]
    jbe .Lptp_invoke_failed
    cmp r13, P_MAX_OUT
    ja .Lptp_invoke_failed
    lea rdi, [r12+104]
    mov rsi, r13
    call .Lptp_grow
    test eax, eax
    jnz .Lptp_invoke_resource
    jmp .Lptp_invoke_loop
.Lptp_invoke_final:
    mov rax, [rbp+24]
    or rax, [rbp+32]
    or rax, [rbp+40]
    or rax, [rbp+48]
    or rax, [r12+184]
    jnz .Lptp_invoke_failed
    mov rax, [rbp+56]
    add rax, 64
    mov [r12+168], rax
    mov qword ptr [r12+56], 2
    mov eax, 64
    jmp .Lptp_invoke_return
.Lptp_invoke_resource:
    mov eax, P_RESOURCE
    jmp .Lptp_invoke_record_failure
.Lptp_invoke_failed:
    mov eax, P_INVALID
.Lptp_invoke_record_failure:
    mov [r12+176], rax
    mov qword ptr [r12+56], 3
    mov qword ptr [r12+168], 0
    jmp .Lptp_invoke_return
.Lptp_invoke_busy:
    mov eax, P_BUSY
    jmp .Lptp_invoke_return
.Lptp_invoke_reject:
    mov eax, P_INVALID
.Lptp_invoke_return:
    P_LEAVE

/* Fixed image entries patched only by the actual HIA image packer. */
.balign 16
.global text_publication_body_call_displacement
.Lptp_body:
    .byte 0xe9
text_publication_body_call_displacement:
    .long 0
.global text_publication_codec_call_displacement
.Lptp_codec:
    .byte 0xe9
text_publication_codec_call_displacement:
    .long 0
.global text_publication_errno_call_displacement
.Lptp_errno:
    .byte 0xe9
text_publication_errno_call_displacement:
    .long 0
