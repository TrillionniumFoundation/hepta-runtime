/* Copyright 2026 Muvon Un Limited
 * SPDX-License-Identifier: Apache-2.0
 * Fixed locked binary write capability. All write policy is HIA.
 * Immutable image entries and the journal callback are trusted graph bindings.
 */
.intel_syntax noprefix
.section .text
.macro W_ENTER
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp, 8
.endm
.macro W_LEAVE
    add rsp, 8
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret
.endm
.equ W_MAGIC, 0x3130494354574248 /* HBWTCI01 */
.equ W_INVALID, 0xffffffff
.equ W_BUSY, 0xfffffffd
.equ W_RESOURCE, 0xfffffffc
.equ W_MAX_WORK, 268435456
.equ W_MAX_OUT, 134217728
.equ W_MAX_INPUT, 134217728
.equ W_REPLY_CAP, 4096
.equ W_CHILD_OUT, 4096

/* rdi nonzero page-aligned capacity; return a zeroed RW arena plus an inaccessible
 * final guard page. No input bytes select a mapping or a code entry. */
.Lbw_map:
    test rdi, rdi
    jz .Lbw_map_bad
    test rdi, 4095
    jnz .Lbw_map_bad
    cmp rdi, W_MAX_WORK
    ja .Lbw_map_bad
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
    jae .Lbw_map_done
    push rax
    lea rdi, [rax+rbx]
    mov esi, 4096
    xor edx, edx
    mov eax, 10
    syscall
    test rax, rax
    jnz .Lbw_map_guard_failed
    pop rax
    jmp .Lbw_map_done
.Lbw_map_guard_failed:
    pop rdi
    lea rsi, [rbx+4096]
    mov eax, 11
    syscall
    mov rax, -12
.Lbw_map_done:
    pop rbx
    ret
.Lbw_map_bad:
    mov rax, -22
    ret

/* Grow a pointer/capacity pair in a private context. rdi points to the pair,
 * rsi is the required extent. Every old byte is copied, the extension is zero.
 * The old mapping is retired only after allocation and copy are complete. */
.Lbw_grow:
    W_ENTER
    mov r12, rdi
    mov r13, rsi
    test r13, r13
    jz .Lbw_grow_bad
    cmp r13, W_MAX_WORK
    ja .Lbw_grow_bad
    add r13, 4095
    jc .Lbw_grow_bad
    and r13, -4096
    cmp r13, [r12+8]
    jbe .Lbw_grow_ok
    mov rdi, r13
    call .Lbw_map
    cmp rax, -4095
    jae .Lbw_grow_resource
    mov r14, rax
    mov rdi, rax
    mov rsi, [r12]
    mov rcx, [r12+8]
    test rcx, rcx
    jz .Lbw_grow_install
    test rsi, rsi
    jz .Lbw_grow_new_failed
    rep movsb
    mov rdi, [r12]
    mov rsi, [r12+8]
    add rsi, 4096
    mov eax, 11
    syscall
    test rax, rax
    jnz .Lbw_grow_new_failed
.Lbw_grow_install:
    mov [r12], r14
    mov [r12+8], r13
.Lbw_grow_ok:
    xor eax, eax
    jmp .Lbw_grow_done
.Lbw_grow_new_failed:
    mov rdi, r14
    lea rsi, [r13+4096]
    mov eax, 11
    syscall
.Lbw_grow_resource:
    mov eax, W_RESOURCE
    jmp .Lbw_grow_done
.Lbw_grow_bad:
    mov eax, W_INVALID
.Lbw_grow_done:
    W_LEAVE

/* Fixed graph: callback, callback context, one process orphan pool,
 * and the borrowed process-wide serialized entropy context. */
.global binary_write_body_create
binary_write_body_create:
    W_ENTER
    mov r13, rdi
    mov r14, rsi
    mov r15, rdx
    mov rbx, rcx
    test r15, r15
    jz .Lbw_create_bad
    test r15, 4095
    jnz .Lbw_create_bad
    movabs rax, 0x31303050524f5048
    cmp [r15], rax
    jne .Lbw_create_bad
    cmp qword ptr [r15+8], 4096
    jne .Lbw_create_bad
    test rbx, rbx
    jz .Lbw_create_bad
    test rbx, 4095
    jnz .Lbw_create_bad
    movabs rax, 0x31304943544e4548
    cmp [rbx], rax
    jne .Lbw_create_bad
    cmp qword ptr [rbx+8], 4096
    jne .Lbw_create_bad
    cmp qword ptr [rbx+56], 0
    jne .Lbw_create_bad
    cmp [rbx+376], r15
    jne .Lbw_create_bad
    mov eax, 39
    syscall
    cmp [r15+16], rax
    jne .Lbw_create_bad
    cmp [rbx+384], rax
    jne .Lbw_create_bad
    mov edi, 4096
    call .Lbw_map
    cmp rax, -4095
    jae .Lbw_create_return
    mov r12, rax
    mov rax, W_MAGIC
    mov [r12], rax
    mov qword ptr [r12+8], 4096
    lea rax, [rip+.Lbw_body]
    mov [r12+16], rax
    lea rax, [rip+.Lbw_stat]
    mov [r12+24], rax
    lea rax, [rip+.Lbw_codec]
    mov [r12+416], rax
    lea rax, [rip+.Lbw_base64]
    mov [r12+424], rax
    mov [r12+40], r13
    mov [r12+48], r14
    mov [r12+376], r15
    mov [r12+408], rbx
    mov rax, [r15+16]
    mov [r12+480], rax
    lea rdi, [r12+256]
    mov rax, -1
    mov ecx, 8
    rep stosq
    lea rdi, [r12+88]
    mov esi, 8192
    call .Lbw_grow
    test eax, eax
    jnz .Lbw_create_fail
    lea rdi, [r12+104]
    mov esi, 4096
    call .Lbw_grow
    test eax, eax
    jnz .Lbw_create_fail
    lea rdi, [r12+120]
    mov esi, W_REPLY_CAP
    call .Lbw_grow
    test eax, eax
    jnz .Lbw_create_fail
    lea rdi, [r12+448]
    mov esi, 4096
    call .Lbw_grow
    test eax, eax
    jnz .Lbw_create_fail
    mov rax, [r12+448]
    mov [r12+136], rax
    lea rdi, [r12+464]
    mov esi, 4096
    call .Lbw_grow
    test eax, eax
    jnz .Lbw_create_fail
    mov rax, [r12+464]
    mov [r12+144], rax
    mov rdi, r13
    mov rsi, r14
    mov rdx, r15
    call binary_read_body_create
    cmp rax, -4095
    jae .Lbw_create_fail
    mov [r12+384], rax
    mov rdi, r13
    mov rsi, r14
    mov rdx, r15
    call publish_at_create
    cmp rax, -4095
    jae .Lbw_create_fail
    mov [r12+392], rax
    mov rax, r12
    jmp .Lbw_create_return
.Lbw_create_bad:
    mov rax, -22
    jmp .Lbw_create_return
.Lbw_create_fail:
    mov rdi, r12
    call binary_write_body_destroy
    mov rax, -12
.Lbw_create_return:
    W_LEAVE

/* Callback is observational and cannot replace any effect or child result. */
.Lbw_emit:
    W_ENTER
    mov rbx, [r12+40]
    test rbx, rbx
    jz .Lbw_emit_ok
    mov rdi, [r12+48]
    mov rsi, r12
    call rbx
    jmp .Lbw_emit_return
.Lbw_emit_ok:
    xor eax, eax
.Lbw_emit_return:
    W_LEAVE

.global binary_write_body_release
binary_write_body_release:
    mov rax, W_MAGIC
    cmp [rdi], rax
    jne .Lbw_release_bad
    cmp qword ptr [rdi+8], 4096
    jne .Lbw_release_bad
    cmp qword ptr [rdi+56], 2
    jne .Lbw_release_bad
    mov rax, [rdi+184]
    or rax, [rdi+344]
    or rax, [rdi+352]
    or rax, [rdi+360]
    or rax, [rdi+368]
    jnz .Lbw_release_bad
    mov qword ptr [rdi+56], 0
    mov qword ptr [rdi+168], 0
    mov qword ptr [rdi+176], 0
    xor eax, eax
    ret
.Lbw_release_bad:
    mov eax, W_INVALID
    ret

/* Shared pool and entropy context are never disposed by a write context. */
.global binary_write_body_destroy
binary_write_body_destroy:
    W_ENTER
    mov r12, rdi
    mov rax, W_MAGIC
    cmp [r12], rax
    jne .Lbw_destroy_bad
    cmp qword ptr [r12+8], 4096
    jne .Lbw_destroy_bad
    mov rax, [r12+56]
    cmp rax, 1
    je .Lbw_destroy_busy
    cmp rax, 2
    je .Lbw_destroy_busy
    cmp rax, 3
    ja .Lbw_destroy_bad
    mov rdi, [r12+384]
    test rdi, rdi
    jz .Lbw_destroy_publish
    call binary_read_body_destroy
    test rax, rax
    jnz .Lbw_destroy_resource
    mov qword ptr [r12+384], 0
.Lbw_destroy_publish:
    mov rdi, [r12+392]
    test rdi, rdi
    jz .Lbw_destroy_owned
    call publish_at_destroy
    test rax, rax
    jnz .Lbw_destroy_resource
    mov qword ptr [r12+392], 0
.Lbw_destroy_owned:
    xor ebx, ebx
.Lbw_destroy_fd:
    mov rdi, [r12+256+rbx*8]
    cmp rdi, -1
    je .Lbw_destroy_fd_next
    mov eax, 3
    syscall
    mov qword ptr [r12+256+rbx*8], -1
    mov qword ptr [r12+512+rbx*8], 0
.Lbw_destroy_fd_next:
    inc ebx
    cmp ebx, 8
    jb .Lbw_destroy_fd
    mov qword ptr [r12+184], 0
    lea r13, [rip+.Lbw_pairs]
    mov ebx, 6
.Lbw_destroy_pair:
    mov r14, [r13]
    mov rdi, [r12+r14]
    test rdi, rdi
    jz .Lbw_destroy_pair_next
    mov rsi, [r12+r14+8]
    add rsi, 4096
    mov eax, 11
    syscall
    test rax, rax
    jnz .Lbw_destroy_resource
    mov qword ptr [r12+r14], 0
    mov qword ptr [r12+r14+8], 0
.Lbw_destroy_pair_next:
    add r13, 8
    dec ebx
    jnz .Lbw_destroy_pair
    mov rdi, r12
    mov esi, 8192
    mov eax, 11
    syscall
    jmp .Lbw_destroy_return
.Lbw_destroy_busy:
    mov eax, W_BUSY
    jmp .Lbw_destroy_return
.Lbw_destroy_resource:
    mov eax, W_RESOURCE
    jmp .Lbw_destroy_return
.Lbw_destroy_bad:
    mov eax, W_INVALID
.Lbw_destroy_return:
    W_LEAVE
.balign 8
.Lbw_pairs:
    .quad 64,88,104,120,448,464

/* Only owned slots are returned; the parent is checked separately. */
.Lbw_fd_find:
    cmp rdi, 2147483647
    ja .Lbw_fd_find_bad
    cmp qword ptr [r12+184], 0
    je .Lbw_fd_find_bad
    xor eax, eax
.Lbw_fd_find_loop:
    cmp [r12+256+rax*8], rdi
    je .Lbw_fd_find_return
    inc eax
    cmp eax, 8
    jb .Lbw_fd_find_loop
.Lbw_fd_find_bad:
    mov rax, -1
.Lbw_fd_find_return:
    ret
.Lbw_name:
    test rsi, rsi
    jz .Lbw_name_bad
    mov rcx, rsi
    xor eax, eax
    repne scasb
    jne .Lbw_name_bad
    test rcx, rcx
    jnz .Lbw_name_bad
    xor eax, eax
    ret
.Lbw_name_bad:
    mov eax, W_INVALID
    ret

/* Fixed effects only. The HIA owner determines order, retries and errors. */
.Lbw_capability:
    W_ENTER
    mov qword ptr [r12+232], 0
    mov qword ptr [r12+240], 0
    cmp qword ptr [r12+352], 1
    jne .Lbw_cap_bad
    cmp qword ptr [rbp+48], 0
    jne .Lbw_cap_bad
    mov rbx, [rbp+24]
    cmp rbx, 1
    jb .Lbw_cap_bad
    cmp rbx, 13
    ja .Lbw_cap_bad
    cmp rbx, 8
    je .Lbw_cap_seek_fields
    cmp rbx, 11
    je .Lbw_cap_write_fields
    cmp qword ptr [rbp+40], 0
    jne .Lbw_cap_bad
    cmp rbx, 1
    je .Lbw_cap_open
    cmp rbx, 6
    je .Lbw_cap_open
    cmp rbx, 7
    je .Lbw_cap_open
    cmp rbx, 13
    je .Lbw_cap_unlink
    cmp qword ptr [rbp+56], 0
    jne .Lbw_cap_bad
    cmp rbx, 5
    je .Lbw_cap_geteuid
    jmp .Lbw_cap_owned
.Lbw_cap_seek_fields:
    cmp qword ptr [rbp+56], 0
    jne .Lbw_cap_bad
    mov rax, [rbp+40]
    cmp rax, 1
    jb .Lbw_cap_bad
    cmp rax, 2
    ja .Lbw_cap_bad
    jmp .Lbw_cap_owned
.Lbw_cap_write_fields:
    mov rax, [rbp+40]
    test rax, rax
    jz .Lbw_cap_bad
    cmp rax, [rbp+56]
    jne .Lbw_cap_bad
.Lbw_cap_owned:
    mov rdi, [rbp+32]
    call .Lbw_fd_find
    cmp rax, -1
    je .Lbw_cap_bad
    mov r15, rax
    cmp rbx, 2
    je .Lbw_cap_stat
    cmp rbx, 3
    je .Lbw_cap_close
    cmp rbx, 4
    je .Lbw_cap_orphan
    mov rax, [r12+512+r15*8]
    cmp rbx, 11
    jae .Lbw_cap_temp
    cmp rax, 2
    jne .Lbw_cap_bad
    cmp rbx, 8
    je .Lbw_cap_seek
    cmp rbx, 9
    je .Lbw_cap_isatty
    cmp rbx, 10
    je .Lbw_cap_flock
    jmp .Lbw_cap_bad
.Lbw_cap_temp:
    cmp rax, 3
    jne .Lbw_cap_bad
    cmp rbx, 11
    je .Lbw_cap_write
    cmp rbx, 12
    je .Lbw_cap_fsync
    jmp .Lbw_cap_bad
.Lbw_cap_orphan:
    cmp qword ptr [r12+400], -1
    je .Lbw_cap_resource
    mov rdi, [r12+376]
    mov rsi, [rbp+32]
    mov rdx, r12
    mov rcx, [r12+192]
    call hia_process_orphans_append
    test rax, rax
    jnz .Lbw_cap_resource
    mov qword ptr [r12+256+r15*8], -1
    mov qword ptr [r12+512+r15*8], 0
    dec qword ptr [r12+184]
    inc qword ptr [r12+400]
    jmp .Lbw_cap_ok
.Lbw_cap_open:
    mov rax, [rbp+32]
    cmp rax, [r12+344]
    jne .Lbw_cap_bad
    cmp qword ptr [r12+184], 8
    jae .Lbw_cap_bad
    xor r15d, r15d
.Lbw_cap_free_slot:
    cmp qword ptr [r12+256+r15*8], -1
    je .Lbw_cap_open_slot
    inc r15d
    cmp r15d, 8
    jb .Lbw_cap_free_slot
    jmp .Lbw_cap_bad
.Lbw_cap_open_slot:
    mov rax, [r12+88]
    lea rsi, [rax+8192]
    mov rcx, [rax+64]
    inc rcx
    cmp rbx, 1
    je .Lbw_cap_open_name
    lea rsi, [rax+512]
    mov ecx, 37
    cmp rbx, 6
    je .Lbw_cap_open_name
    lea rsi, [rax+640]
    mov ecx, 46
.Lbw_cap_open_name:
    cmp [rbp+56], rcx
    jne .Lbw_cap_bad
    lea rdi, [rbp+64]
    repe cmpsb
    jne .Lbw_cap_bad
    lea rdi, [rbp+64]
    mov rsi, [rbp+56]
    call .Lbw_name
    test eax, eax
    jnz .Lbw_cap_bad
    mov rdi, [rbp+32]
    lea rsi, [rbp+64]
    mov edx, 657408
    cmp rbx, 1
    je .Lbw_cap_open_flags
    mov edx, 657474
    cmp rbx, 6
    je .Lbw_cap_open_flags
    mov edx, 657601
.Lbw_cap_open_flags:
    mov r10d, 384
    mov eax, 257
    syscall
    mov [r12+232], rax
    cmp rax, -4095
    jae .Lbw_cap_ok
    cmp rax, 2147483647
    ja .Lbw_cap_bad
    mov [r12+256+r15*8], rax
    mov eax, 1
    cmp rbx, 1
    je .Lbw_cap_open_role
    mov eax, 2
    cmp rbx, 6
    je .Lbw_cap_open_role
    mov eax, 3
.Lbw_cap_open_role:
    mov [r12+512+r15*8], rax
    inc qword ptr [r12+184]
    jmp .Lbw_cap_ok
.Lbw_cap_stat:
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
    jnz .Lbw_cap_ok
    mov qword ptr [r12+240], 144
    jmp .Lbw_cap_ok
.Lbw_cap_close:
    mov rdi, [rbp+32]
    mov eax, 3
    syscall
    mov [r12+232], rax
    mov qword ptr [r12+256+r15*8], -1
    mov qword ptr [r12+512+r15*8], 0
    dec qword ptr [r12+184]
    jmp .Lbw_cap_ok
.Lbw_cap_geteuid:
    cmp qword ptr [rbp+32], 0
    jne .Lbw_cap_bad
    mov eax, 107
    syscall
    mov [r12+232], rax
    jmp .Lbw_cap_ok
.Lbw_cap_seek:
    mov rdi, [rbp+32]
    xor esi, esi
    mov rdx, [rbp+40]
    mov eax, 8
    syscall
    mov [r12+232], rax
    jmp .Lbw_cap_ok
.Lbw_cap_isatty:
    mov rdi, [r12+120]
    add rdi, 96
    xor eax, eax
    mov ecx, 8
    rep stosq
    mov rdi, [rbp+32]
    mov esi, 0x5401
    mov rdx, [r12+120]
    add rdx, 96
    mov eax, 16
    syscall
    mov [r12+232], rax
    test rax, rax
    jnz .Lbw_cap_ok
    mov qword ptr [r12+240], 36
    jmp .Lbw_cap_ok
.Lbw_cap_flock:
    mov rdi, [rbp+32]
    mov esi, 2
    mov eax, 73
    syscall
    mov [r12+232], rax
    jmp .Lbw_cap_ok
.Lbw_cap_write:
    mov rdi, [rbp+32]
    lea rsi, [rbp+64]
    mov rdx, [rbp+56]
    mov eax, 1
    syscall
    mov [r12+232], rax
    jmp .Lbw_cap_ok
.Lbw_cap_fsync:
    mov rdi, [rbp+32]
    mov eax, 74
    syscall
    mov [r12+232], rax
    jmp .Lbw_cap_ok
.Lbw_cap_unlink:
    mov rax, [rbp+32]
    cmp rax, [r12+344]
    jne .Lbw_cap_bad
    cmp qword ptr [rbp+56], 46
    jne .Lbw_cap_bad
    mov rsi, [r12+88]
    add rsi, 640
    lea rdi, [rbp+64]
    mov ecx, 46
    repe cmpsb
    jne .Lbw_cap_bad
    lea rdi, [rbp+64]
    mov esi, 46
    call .Lbw_name
    test eax, eax
    jnz .Lbw_cap_bad
    mov rdi, [rbp+32]
    lea rsi, [rbp+64]
    xor edx, edx
    mov eax, 263
    syscall
    mov [r12+232], rax
.Lbw_cap_ok:
    xor eax, eax
    jmp .Lbw_cap_done
.Lbw_cap_resource:
    mov eax, W_RESOURCE
    jmp .Lbw_cap_done
.Lbw_cap_bad:
    mov eax, W_INVALID
.Lbw_cap_done:
    W_LEAVE

/* Fixed graph-only parent capability. Packet FD word is zero externally. */
.global binary_write_body_invoke
binary_write_body_invoke:
    W_ENTER
    mov r12, rdi
    mov r15, rsi
    mov r13, rdx
    mov r14, rcx
    cmp r15, 2147483647
    ja .Lbw_invoke_reject
    mov rax, W_MAGIC
    cmp [r12], rax
    jne .Lbw_invoke_reject
    cmp qword ptr [r12+8], 4096
    jne .Lbw_invoke_reject
    cmp qword ptr [r12+56], 0
    jne .Lbw_invoke_busy
    mov rax, [r12+184]
    or rax, [r12+344]
    or rax, [r12+352]
    or rax, [r12+360]
    or rax, [r12+368]
    jnz .Lbw_invoke_reject
    cmp r14, 96
    jb .Lbw_invoke_reject
    cmp r14, W_MAX_INPUT
    ja .Lbw_invoke_reject
    test r13, r13
    jz .Lbw_invoke_reject
    mov rax, 0x3130305154574248
    cmp [r13], rax
    jne .Lbw_invoke_reject
    cmp qword ptr [r13+8], 1
    jne .Lbw_invoke_reject
    cmp qword ptr [r13+24], 1
    jne .Lbw_invoke_reject
    mov rax, [r13+16]
    or rax, [r13+32]
    or rax, [r13+72]
    or rax, [r13+80]
    jnz .Lbw_invoke_reject
    mov rax, r14
    sub rax, 96
    cmp [r13+88], rax
    jne .Lbw_invoke_reject
    cmp [r13+40], rax
    ja .Lbw_invoke_reject
    sub rax, [r13+40]
    cmp [r13+48], rax
    ja .Lbw_invoke_reject
    sub rax, [r13+48]
    cmp [r13+56], rax
    jne .Lbw_invoke_reject
    cmp qword ptr [r13+64], 1
    ja .Lbw_invoke_reject
    cmp qword ptr [r13+64], 0
    jne .Lbw_invoke_prior_ready
    cmp qword ptr [r13+48], 0
    jne .Lbw_invoke_reject
.Lbw_invoke_prior_ready:
    cmp qword ptr [r12+192], -1
    je .Lbw_invoke_reject
    mov eax, 39
    syscall
    cmp [r12+480], rax
    jne .Lbw_invoke_reject
    mov rbx, [r12+384]
    cmp qword ptr [rbx+56], 0
    jne .Lbw_invoke_reject
    mov rbx, [r12+392]
    cmp qword ptr [rbx+56], 0
    jne .Lbw_invoke_reject
    mov rbx, [r12+408]
    cmp qword ptr [rbx+56], 0
    jne .Lbw_invoke_reject
    lea rdi, [r12+64]
    mov rsi, r14
    call .Lbw_grow
    test eax, eax
    jnz .Lbw_invoke_return
    mov rdi, [r12+64]
    mov rsi, r13
    mov rcx, r14
    rep movsb
    mov rax, [r12+64]
    mov [rax+32], r15
    mov [r12+344], r15
    mov qword ptr [r12+352], 1
    mov [r12+80], r14
    mov rax, [r12+64]
    mov [r12+200], rax
    mov [r12+208], r14
    inc qword ptr [r12+192]
    mov qword ptr [r12+248], 0
    mov qword ptr [r12+56], 1
    mov qword ptr [r12+168], 0
    mov qword ptr [r12+176], 0
.Lbw_invoke_loop:
    inc qword ptr [r12+248]
    jz .Lbw_invoke_failed
    mov rdi, [r12+104]
    mov rcx, [r12+112]
    shr rcx, 3
    mov rax, 0xa5a5a5a5a5a5a5a5
    rep stosq
    mov edx, 1
    mov rcx, [r12+200]
    mov r8, [r12+208]
    call .Lbw_emit
    test rax, rax
    jnz .Lbw_invoke_failed
    mov edx, 10
    mov rcx, [r12+88]
    mov r8, [r12+96]
    call .Lbw_emit
    test rax, rax
    jnz .Lbw_invoke_failed
    mov edx, 12
    mov rcx, [r12+104]
    mov r8, [r12+112]
    call .Lbw_emit
    test rax, rax
    jnz .Lbw_invoke_failed
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
    call .Lbw_emit
    test rax, rax
    jnz .Lbw_invoke_failed
    mov edx, 11
    mov rcx, [r12+88]
    mov r8, [r12+96]
    call .Lbw_emit
    test rax, rax
    jnz .Lbw_invoke_failed
    cmp qword ptr [r12+176], 64
    jne .Lbw_invoke_failed
    mov rbp, [r12+104]
    mov rax, 0x3130305254574248
    cmp [rbp], rax
    jne .Lbw_invoke_failed
    mov rax, [r12+112]
    sub rax, 64
    cmp [rbp+56], rax
    ja .Lbw_invoke_failed
    mov rbx, [rbp+8]
    cmp rbx, 5
    ja .Lbw_invoke_failed
    test rbx, rbx
    jz .Lbw_invoke_final
    cmp rbx, 3
    je .Lbw_invoke_final
    cmp rbx, 4
    jae .Lbw_invoke_growth
    mov rax, [rbp+16]
    mov [r12+216], rax
    mov rax, [rbp+24]
    mov [r12+224], rax
    cmp rbx, 2
    je .Lbw_invoke_child
    mov edx, 8
    mov rcx, rbp
    mov r8, [rbp+56]
    add r8, 64
    call .Lbw_emit
    test rax, rax
    jnz .Lbw_invoke_failed
    call .Lbw_capability
    cmp eax, W_RESOURCE
    je .Lbw_invoke_resource
    test eax, eax
    jnz .Lbw_invoke_failed
    jmp .Lbw_invoke_reply

.Lbw_invoke_child:
    cmp qword ptr [rbp+48], 0
    jne .Lbw_invoke_failed
    mov edx, 5
    lea rcx, [rbp+64]
    mov r8, [rbp+56]
    call .Lbw_emit
    test rax, rax
    jnz .Lbw_invoke_failed
    mov rbx, [rbp+24]
    cmp rbx, 1
    jb .Lbw_invoke_failed
    cmp rbx, 3
    jbe .Lbw_child_direct
    cmp qword ptr [rbp+40], 0
    jne .Lbw_invoke_failed
    cmp qword ptr [rbp+56], 96
    jb .Lbw_invoke_failed
    cmp qword ptr [rbp+72], 1
    jne .Lbw_invoke_failed
    cmp qword ptr [rbp+80], 0
    jne .Lbw_invoke_failed
    cmp qword ptr [rbp+96], 0
    jne .Lbw_invoke_failed
    cmp rbx, 4
    je .Lbw_child_entropy
    mov rax, [rbp+32]
    cmp rax, [r12+344]
    jne .Lbw_invoke_failed
    cmp rbx, 5
    je .Lbw_child_publish
    cmp rbx, 6
    jne .Lbw_invoke_failed
    mov rax, 0x3130444644524248
    cmp [rbp+64], rax
    jne .Lbw_invoke_failed
    cmp qword ptr [rbp+88], 2
    jne .Lbw_invoke_failed
    mov rax, [r12+384]
    mov [r12+360], rax
    mov qword ptr [r12+368], 6
    mov rdi, rax
    mov rsi, [r12+344]
    lea rdx, [rbp+64]
    mov rcx, [rbp+56]
    call binary_read_body_invoke_at
    cmp rax, 64
    jne .Lbw_invoke_failed
    mov rdi, [r12+384]
    mov esi, 6
    jmp .Lbw_child_copied
.Lbw_child_publish:
    mov rax, 0x3130305142555048
    cmp [rbp+64], rax
    jne .Lbw_invoke_failed
    cmp qword ptr [rbp+88], 1
    jne .Lbw_invoke_failed
    mov rax, [r12+392]
    mov [r12+360], rax
    mov qword ptr [r12+368], 5
    mov rdi, rax
    mov rsi, [r12+344]
    lea rdx, [rbp+64]
    mov rcx, [rbp+56]
    call publish_at_invoke
    cmp rax, 64
    jne .Lbw_invoke_failed
    mov rdi, [r12+392]
    mov esi, 5
    jmp .Lbw_child_copied
.Lbw_child_entropy:
    cmp qword ptr [rbp+56], 96
    jne .Lbw_invoke_failed
    mov rax, 0x31303051544e4548
    cmp [rbp+64], rax
    jne .Lbw_invoke_failed
    cmp qword ptr [rbp+88], 2
    jne .Lbw_invoke_failed
    cmp qword ptr [rbp+32], 0
    jne .Lbw_invoke_failed
    mov rax, [r12+408]
    mov [r12+360], rax
    mov qword ptr [r12+368], 4
    mov rdi, rax
    lea rsi, [rbp+64]
    mov rdx, [rbp+56]
    call binary_entropy_invoke
    cmp rax, 64
    jne .Lbw_invoke_failed
    mov rdi, [r12+408]
    mov esi, 4
.Lbw_child_copied:
    call .Lbw_copy_nested
    cmp eax, W_RESOURCE
    je .Lbw_invoke_resource
    test eax, eax
    jnz .Lbw_invoke_failed
    jmp .Lbw_invoke_reply

.Lbw_child_direct:
    mov rax, [rbp+32]
    or rax, [rbp+40]
    jnz .Lbw_invoke_failed
    cmp rbx, 1
    je .Lbw_child_stat
    cmp qword ptr [rbp+56], 24
    jb .Lbw_invoke_failed
    mov rax, 0x314345444f435248
    cmp [rbp+64], rax
    jne .Lbw_invoke_failed
    cmp qword ptr [rbp+80], 0
    jne .Lbw_invoke_failed
    cmp rbx, 3
    je .Lbw_child_base64
    cmp qword ptr [rbp+72], 2
    jne .Lbw_invoke_failed
    mov rax, [r12+416]
    mov [r12+320], rax
    mov qword ptr [r12+328], 64
    mov qword ptr [r12+336], 1184
    jmp .Lbw_child_direct_buffers
.Lbw_child_base64:
    cmp qword ptr [rbp+72], 4
    jne .Lbw_invoke_failed
    mov rax, [r12+424]
    mov [r12+320], rax
    mov rax, [rbp+56]
    add rax, 71
    jc .Lbw_invoke_failed
    and rax, -8
    cmp rax, 512
    jae .Lbw_child_base64_extent
    mov eax, 512
.Lbw_child_base64_extent:
    cmp rax, W_MAX_OUT
    ja .Lbw_invoke_failed
    mov [r12+328], rax
    mov qword ptr [r12+336], 4096
    jmp .Lbw_child_direct_buffers
.Lbw_child_stat:
    cmp qword ptr [rbp+56], 72
    jne .Lbw_invoke_failed
    mov rax, 0x3130524556545348
    cmp [rbp+64], rax
    jne .Lbw_invoke_failed
    mov rax, [r12+24]
    mov [r12+320], rax
    mov qword ptr [r12+328], 128
    mov qword ptr [r12+336], 256
.Lbw_child_direct_buffers:
    lea rdi, [r12+448]
    mov rsi, [r12+328]
    call .Lbw_grow
    test eax, eax
    jnz .Lbw_invoke_resource
    mov rax, [r12+448]
    mov [r12+136], rax
    lea rdi, [r12+464]
    mov rsi, [r12+336]
    call .Lbw_grow
    test eax, eax
    jnz .Lbw_invoke_resource
    mov rax, [r12+464]
    mov [r12+144], rax
    lea rdi, [r12+120]
    mov rsi, [r12+328]
    add rsi, 96
    call .Lbw_grow
    test eax, eax
    jnz .Lbw_invoke_resource
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
    mov edx, 13
    mov rcx, [r12+136]
    mov r8, [r12+328]
    call .Lbw_emit
    test rax, rax
    jnz .Lbw_invoke_failed
    mov edx, 14
    mov rcx, [r12+144]
    mov r8, [r12+336]
    call .Lbw_emit
    test rax, rax
    jnz .Lbw_invoke_failed
    lea rdi, [rbp+64]
    mov rsi, [rbp+56]
    mov rdx, [r12+136]
    mov rcx, [r12+328]
    mov r8, [r12+144]
    mov r9, [r12+336]
    call qword ptr [r12+320]
    mov [r12+232], rax
    cmp rax, [r12+328]
    ja .Lbw_invoke_failed
    mov [r12+240], rax
    mov rdi, [r12+120]
    add rdi, 96
    mov rsi, [r12+136]
    mov rcx, rax
    rep movsb
    mov edx, 6
    mov rcx, [r12+136]
    mov r8, [r12+328]
    call .Lbw_emit
    test rax, rax
    jnz .Lbw_invoke_failed
    mov edx, 7
    mov rcx, [r12+144]
    mov r8, [r12+336]
    call .Lbw_emit
    test rax, rax
    jnz .Lbw_invoke_failed
.Lbw_invoke_reply:
    mov rbx, [r12+120]
    mov rax, 0x3130305154574248
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
    ja .Lbw_invoke_failed
    mov [rbx+88], rax
    add rax, 96
    cmp rax, [r12+128]
    ja .Lbw_invoke_failed
    mov [r12+200], rbx
    mov [r12+208], rax
    mov edx, 9
    mov rcx, rbx
    mov r8, rax
    call .Lbw_emit
    test rax, rax
    jnz .Lbw_invoke_failed
    jmp .Lbw_invoke_loop
.Lbw_invoke_growth:
    mov rax, [rbp+16]
    or rax, [rbp+24]
    or rax, [rbp+40]
    or rax, [rbp+48]
    or rax, [rbp+56]
    jnz .Lbw_invoke_failed
    mov r13, [rbp+32]
    cmp rbx, 4
    jne .Lbw_invoke_output_growth
    cmp r13, [r12+96]
    jbe .Lbw_invoke_failed
    cmp r13, W_MAX_WORK
    ja .Lbw_invoke_failed
    mov edx, 3
    mov rcx, [r12+88]
    mov r8, [r12+96]
    call .Lbw_emit
    test rax, rax
    jnz .Lbw_invoke_failed
    lea rdi, [r12+88]
    mov rsi, r13
    call .Lbw_grow
    test eax, eax
    jnz .Lbw_invoke_resource
    mov edx, 4
    mov rcx, [r12+88]
    mov r8, [r12+96]
    call .Lbw_emit
    test rax, rax
    jnz .Lbw_invoke_failed
    jmp .Lbw_invoke_loop
.Lbw_invoke_output_growth:
    cmp r13, [r12+112]
    jbe .Lbw_invoke_failed
    cmp r13, W_MAX_OUT
    ja .Lbw_invoke_failed
    lea rdi, [r12+104]
    mov rsi, r13
    call .Lbw_grow
    test eax, eax
    jnz .Lbw_invoke_resource
    jmp .Lbw_invoke_loop
.Lbw_invoke_final:
    cmp qword ptr [r12+184], 0
    jne .Lbw_invoke_failed
    mov rax, [r12+360]
    or rax, [r12+368]
    jnz .Lbw_invoke_failed
    mov rax, [rbp+24]
    or rax, [rbp+32]
    or rax, [rbp+40]
    or rax, [rbp+48]
    jnz .Lbw_invoke_failed
    cmp qword ptr [rbp+8], 3
    je .Lbw_invoke_error
    cmp qword ptr [rbp+56], 2
    jb .Lbw_invoke_failed
    jmp .Lbw_invoke_borrow
.Lbw_invoke_error:
    cmp qword ptr [rbp+56], 64
    jb .Lbw_invoke_failed
    mov rax, 0x3130305344524248
    cmp [rbp+64], rax
    je .Lbw_invoke_error_magic
    mov rax, 0x3130305253444d48
    cmp [rbp+64], rax
    je .Lbw_invoke_error_magic
    mov rax, 0x3130305245534f48 /* HOSER001 */
    cmp [rbp+64], rax
    jne .Lbw_invoke_failed
.Lbw_invoke_error_magic:
    cmp qword ptr [rbp+72], 3
    jne .Lbw_invoke_failed
    mov rax, [rbp+56]
    sub rax, 64
    cmp [rbp+120], rax
    jne .Lbw_invoke_failed
.Lbw_invoke_borrow:
    mov qword ptr [r12+344], 0
    mov qword ptr [r12+352], 0
    mov rax, [rbp+56]
    add rax, 64
    mov [r12+168], rax
    mov qword ptr [r12+56], 2
    mov eax, 64
    jmp .Lbw_invoke_return
.Lbw_invoke_resource:
    mov eax, W_RESOURCE
    jmp .Lbw_invoke_record_failure
.Lbw_invoke_failed:
    mov eax, W_INVALID
.Lbw_invoke_record_failure:
    mov [r12+176], rax
    /* A private allocation/observer failure cannot leave a child output loan.
     * Child failures retain their own operable ledger until context teardown. */
    mov rdi, [r12+360]
    test rdi, rdi
    jz .Lbw_failure_recorded
    cmp qword ptr [rdi+56], 2
    jne .Lbw_failure_recorded
    mov rsi, [r12+368]
    call .Lbw_release_child
.Lbw_failure_recorded:
    mov qword ptr [r12+344], 0
    mov qword ptr [r12+352], 0
    mov qword ptr [r12+360], 0
    mov qword ptr [r12+368], 0
    mov qword ptr [r12+56], 3
    mov qword ptr [r12+168], 0
    mov rax, [r12+176]
    jmp .Lbw_invoke_return
.Lbw_invoke_busy:
    mov eax, W_BUSY
    jmp .Lbw_invoke_return
.Lbw_invoke_reject:
    mov eax, W_INVALID
.Lbw_invoke_return:
    W_LEAVE

/* Copy all actual borrowed output before releasing its fixed child.
 * Shared entropy is released but never reset, destroyed or closed. */
.Lbw_copy_nested:
    W_ENTER
    mov r14, rdi
    mov r15, rsi
    cmp qword ptr [r14+56], 2
    jne .Lbw_copy_bad
    mov r13, [r14+168]
    cmp r13, 64
    jb .Lbw_copy_bad
    cmp r13, W_MAX_OUT
    ja .Lbw_copy_bad
    mov rax, [r14+104]
    test rax, rax
    jz .Lbw_copy_bad
    cmp r13, [r14+112]
    ja .Lbw_copy_bad
    mov rbx, [rax+56]
    add rbx, 64
    jc .Lbw_copy_bad
    cmp r13, rbx
    jne .Lbw_copy_bad
    lea rdi, [r12+120]
    lea rsi, [r13+96]
    call .Lbw_grow
    test eax, eax
    jnz .Lbw_copy_resource
    mov edx, 6
    mov rcx, [r14+104]
    mov r8, r13
    call .Lbw_emit
    test rax, rax
    jnz .Lbw_copy_bad
    mov edx, 15
    mov rcx, r14
    mov r8d, 4096
    call .Lbw_emit
    test rax, rax
    jnz .Lbw_copy_bad
    mov rdi, [r12+120]
    add rdi, 96
    mov rsi, [r14+104]
    mov rcx, r13
    rep movsb
    mov [r12+232], r13
    mov [r12+240], r13
    mov rdi, r14
    mov rsi, r15
    call .Lbw_release_child
    test rax, rax
    jnz .Lbw_copy_bad
    mov qword ptr [r12+360], 0
    mov qword ptr [r12+368], 0
    xor eax, eax
    jmp .Lbw_copy_done
.Lbw_copy_resource:
    mov eax, W_RESOURCE
    jmp .Lbw_copy_done
.Lbw_copy_bad:
    mov eax, W_INVALID
.Lbw_copy_done:
    W_LEAVE

.Lbw_release_child:
    cmp rsi, 4
    je .Lbw_release_entropy
    cmp rsi, 5
    je .Lbw_release_publish
    cmp rsi, 6
    je .Lbw_release_read
    mov eax, W_INVALID
    ret
.Lbw_release_entropy:
    jmp binary_entropy_release
.Lbw_release_publish:
    jmp publish_at_release
.Lbw_release_read:
    jmp binary_read_body_release

/* Four direct HIA entries; the fixed opaque callables are statically linked. */
.balign 16
.global binary_write_body_body_call_displacement
.Lbw_body:
    .byte 0xe9
binary_write_body_body_call_displacement:
    .long 0
.global binary_write_body_stat_call_displacement
.Lbw_stat:
    .byte 0xe9
binary_write_body_stat_call_displacement:
    .long 0
.global binary_write_body_codec_call_displacement
.Lbw_codec:
    .byte 0xe9
binary_write_body_codec_call_displacement:
    .long 0
.global binary_write_body_base64_call_displacement
.Lbw_base64:
    .byte 0xe9
binary_write_body_base64_call_displacement:
    .long 0

.section .note.GNU-stack,"",@progbits
