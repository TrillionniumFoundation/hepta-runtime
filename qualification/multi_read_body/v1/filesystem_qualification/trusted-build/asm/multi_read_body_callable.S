/* Copyright 2026 Muvon Un Limited
 * SPDX-License-Identifier: Apache-2.0
 * Fixed bounded multi-file capabilities. All original body policy is HIA.
 * Immutable image entries and the journal callback are trusted graph bindings.
 */
.intel_syntax noprefix
.section .text
.macro M_ENTER
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp, 8
.endm
.macro M_LEAVE
    add rsp, 8
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret
.endm
.equ M_MAGIC, 0x3130494344524d48 /* HMRDCI01 */
.equ M_INVALID, 0xffffffff
.equ M_BUSY, 0xfffffffd
.equ M_RESOURCE, 0xfffffffc
.equ M_MAX_WORK, 268435456
.equ M_MAX_OUT, 134217728
.equ M_MAX_INPUT, 1048576
.equ M_REPLY_CAP, 69632
.equ M_CHILD_OUT, 4096

/* rdi nonzero page-aligned capacity; return a zeroed RW arena plus an inaccessible
 * final guard page. No input bytes select a mapping or a code entry. */
.Lmrd_map:
    test rdi, rdi
    jz .Lmrd_map_bad
    test rdi, 4095
    jnz .Lmrd_map_bad
    cmp rdi, M_MAX_WORK
    ja .Lmrd_map_bad
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
    jae .Lmrd_map_done
    push rax
    lea rdi, [rax+rbx]
    mov esi, 4096
    xor edx, edx
    mov eax, 10
    syscall
    test rax, rax
    jnz .Lmrd_map_guard_failed
    pop rax
    jmp .Lmrd_map_done
.Lmrd_map_guard_failed:
    pop rdi
    lea rsi, [rbx+4096]
    mov eax, 11
    syscall
    mov rax, -12
.Lmrd_map_done:
    pop rbx
    ret
.Lmrd_map_bad:
    mov rax, -22
    ret

/* Grow a pointer/capacity pair in a private context. rdi points to the pair,
 * rsi is the required extent. Every old byte is copied, the extension is zero.
 * The old mapping is retired only after allocation and copy are complete. */
.Lmrd_grow:
    M_ENTER
    mov r12, rdi
    mov r13, rsi
    test r13, r13
    jz .Lmrd_grow_bad
    cmp r13, M_MAX_WORK
    ja .Lmrd_grow_bad
    add r13, 4095
    jc .Lmrd_grow_bad
    and r13, -4096
    cmp r13, [r12+8]
    jbe .Lmrd_grow_ok
    mov rdi, r13
    call .Lmrd_map
    cmp rax, -4095
    jae .Lmrd_grow_resource
    mov r14, rax
    mov rdi, rax
    mov rsi, [r12]
    mov rcx, [r12+8]
    test rcx, rcx
    jz .Lmrd_grow_install
    test rsi, rsi
    jz .Lmrd_grow_new_failed
    rep movsb
    mov rdi, [r12]
    mov rsi, [r12+8]
    add rsi, 4096
    mov eax, 11
    syscall
    test rax, rax
    jnz .Lmrd_grow_new_failed
.Lmrd_grow_install:
    mov [r12], r14
    mov [r12+8], r13
.Lmrd_grow_ok:
    xor eax, eax
    jmp .Lmrd_grow_done
.Lmrd_grow_new_failed:
    mov rdi, r14
    lea rsi, [r13+4096]
    mov eax, 11
    syscall
.Lmrd_grow_resource:
    mov eax, M_RESOURCE
    jmp .Lmrd_grow_done
.Lmrd_grow_bad:
    mov eax, M_INVALID
.Lmrd_grow_done:
    M_LEAVE

/* Fixed graph registers: callback, callback context, shared orphan pool. */
.global multi_read_body_create
multi_read_body_create:
    M_ENTER
    mov r13, rdi
    mov r14, rsi
    mov r15, rdx
    test r15, r15
    jz .Lmrd_create_bad
    test r15, 4095
    jnz .Lmrd_create_bad
    movabs rax, 0x31303050524f5048
    cmp [r15], rax
    jne .Lmrd_create_bad
    cmp qword ptr [r15+8], 4096
    jne .Lmrd_create_bad
    mov eax, 39
    syscall
    cmp [r15+16], rax
    jne .Lmrd_create_bad
    mov edi, 4096
    call .Lmrd_map
    cmp rax, -4095
    jae .Lmrd_create_return
    mov r12, rax
    mov rax, M_MAGIC
    mov [r12], rax
    mov qword ptr [r12+8], 4096
    lea rax, [rip+.Lmrd_body]
    mov [r12+16], rax
    lea rax, [rip+.Lmrd_stat]
    mov [r12+24], rax
    lea rax, [rip+.Lmrd_codec]
    mov [r12+32], rax
    lea rax, [rip+.Lmrd_utf8]
    mov [r12+152], rax
    mov [r12+40], r13
    mov [r12+48], r14
    mov [r12+376], r15
    lea rdi, [r12+256]
    mov rax, -1
    mov ecx, 8
    rep stosq
    lea rdi, [r12+88]
    mov esi, 4096
    call .Lmrd_grow
    test eax, eax
    jnz .Lmrd_create_fail
    lea rdi, [r12+104]
    mov esi, 4096
    call .Lmrd_grow
    test eax, eax
    jnz .Lmrd_create_fail
    lea rdi, [r12+120]
    mov esi, M_REPLY_CAP
    call .Lmrd_grow
    test eax, eax
    jnz .Lmrd_create_fail
    mov edi, M_CHILD_OUT
    call .Lmrd_map
    cmp rax, -4095
    jae .Lmrd_create_fail
    mov [r12+136], rax
    mov edi, 4096
    call .Lmrd_map
    cmp rax, -4095
    jae .Lmrd_create_fail
    mov [r12+144], rax
    mov rdi, r13
    mov rsi, r14
    call parent_directory_create
    cmp rax, -4095
    jae .Lmrd_create_fail
    mov [r12+384], rax
    mov rdi, r13
    mov rsi, r14
    call parent_directory_create
    cmp rax, -4095
    jae .Lmrd_create_fail
    mov [r12+392], rax
    mov rax, r12
    jmp .Lmrd_create_return
.Lmrd_create_bad:
    mov rax, -22
    jmp .Lmrd_create_return
.Lmrd_create_fail:
    mov rdi, r12
    call multi_read_body_destroy
    mov rax, -12
.Lmrd_create_return:
    M_LEAVE

/* Callback is observational and cannot replace any effect or child result. */
.Lmrd_emit:
    M_ENTER
    mov rbx, [r12+40]
    test rbx, rbx
    jz .Lmrd_emit_ok
    mov rdi, [r12+48]
    mov rsi, r12
    call rbx
    jmp .Lmrd_emit_return
.Lmrd_emit_ok:
    xor eax, eax
.Lmrd_emit_return:
    M_LEAVE

.global multi_read_body_release
multi_read_body_release:
    mov rax, M_MAGIC
    cmp [rdi], rax
    jne .Lmrd_release_bad
    cmp qword ptr [rdi+8], 4096
    jne .Lmrd_release_bad
    cmp qword ptr [rdi+56], 2
    jne .Lmrd_release_bad
    mov rax, [rdi+184]
    or rax, [rdi+344]
    or rax, [rdi+352]
    or rax, [rdi+360]
    or rax, [rdi+368]
    jnz .Lmrd_release_bad
    mov rax, [rdi+384]
    cmp qword ptr [rax+56], 0
    jne .Lmrd_release_bad
    mov rax, [rdi+392]
    cmp qword ptr [rax+56], 0
    jne .Lmrd_release_bad
    mov qword ptr [rdi+56], 0
    mov qword ptr [rdi+168], 0
    mov qword ptr [rdi+176], 0
    xor eax, eax
    ret
.Lmrd_release_bad:
    mov eax, M_INVALID
    ret

/* Orphan pool at +376 is never destroyed or traversed for close. */
.global multi_read_body_destroy
multi_read_body_destroy:
    M_ENTER
    mov r12, rdi
    mov rax, M_MAGIC
    cmp [r12], rax
    jne .Lmrd_destroy_bad
    cmp qword ptr [r12+8], 4096
    jne .Lmrd_destroy_bad
    mov rax, [r12+56]
    cmp rax, 1
    je .Lmrd_destroy_busy
    cmp rax, 2
    je .Lmrd_destroy_busy
    cmp rax, 3
    ja .Lmrd_destroy_bad
    mov ebx, 8
.Lmrd_destroy_fd:
    dec ebx
    mov rdi, [r12+256+rbx*8]
    cmp rdi, -1
    je .Lmrd_destroy_fd_next
    mov eax, 3
    syscall
    mov qword ptr [r12+256+rbx*8], -1
.Lmrd_destroy_fd_next:
    test ebx, ebx
    jnz .Lmrd_destroy_fd
    mov qword ptr [r12+184], 0
    mov ebx, 392
.Lmrd_destroy_parent:
    mov r14, [r12+rbx]
    test r14, r14
    jz .Lmrd_destroy_parent_next
    cmp qword ptr [r14+56], 4
    jne .Lmrd_destroy_parent_release
    mov rdi, r14
    call parent_directory_close
    cmp rax, 64
    jne .Lmrd_destroy_resource
.Lmrd_destroy_parent_release:
    cmp qword ptr [r14+56], 2
    jne .Lmrd_destroy_parent_do
    mov rdi, r14
    call parent_directory_release
    test rax, rax
    jnz .Lmrd_destroy_resource
.Lmrd_destroy_parent_do:
    mov rdi, r14
    call parent_directory_destroy
    test rax, rax
    jnz .Lmrd_destroy_resource
    mov qword ptr [r12+rbx], 0
.Lmrd_destroy_parent_next:
    sub ebx, 8
    cmp ebx, 384
    jae .Lmrd_destroy_parent
    lea r13, [rip+.Lmrd_pairs]
    mov ebx, 4
.Lmrd_destroy_pair:
    mov r14, [r13]
    mov rdi, [r12+r14]
    test rdi, rdi
    jz .Lmrd_destroy_pair_next
    mov rsi, [r12+r14+8]
    add rsi, 4096
    mov eax, 11
    syscall
    test rax, rax
    jnz .Lmrd_destroy_resource
    mov qword ptr [r12+r14], 0
    mov qword ptr [r12+r14+8], 0
.Lmrd_destroy_pair_next:
    add r13, 8
    dec ebx
    jnz .Lmrd_destroy_pair
    mov ebx, 136
.Lmrd_destroy_stat_arena:
    mov rdi, [r12+rbx]
    test rdi, rdi
    jz .Lmrd_destroy_stat_next
    mov esi, 8192
    mov eax, 11
    syscall
    test rax, rax
    jnz .Lmrd_destroy_resource
    mov qword ptr [r12+rbx], 0
.Lmrd_destroy_stat_next:
    add ebx, 8
    cmp ebx, 152
    jb .Lmrd_destroy_stat_arena
    mov rdi, r12
    mov esi, 8192
    mov eax, 11
    syscall
    jmp .Lmrd_destroy_return
.Lmrd_destroy_busy:
    mov eax, M_BUSY
    jmp .Lmrd_destroy_return
.Lmrd_destroy_resource:
    mov eax, M_RESOURCE
    jmp .Lmrd_destroy_return
.Lmrd_destroy_bad:
    mov eax, M_INVALID
.Lmrd_destroy_return:
    M_LEAVE
.balign 8
.Lmrd_pairs:
    .quad 64,88,104,120

/* Only owned slots are returned; the parent is checked separately. */
.Lmrd_fd_find:
    cmp rdi, 2147483647
    ja .Lmrd_fd_find_bad
    cmp qword ptr [r12+184], 0
    je .Lmrd_fd_find_bad
    xor eax, eax
.Lmrd_fd_find_loop:
    cmp [r12+256+rax*8], rdi
    je .Lmrd_fd_find_return
    inc eax
    cmp eax, 8
    jb .Lmrd_fd_find_loop
.Lmrd_fd_find_bad:
    mov rax, -1
.Lmrd_fd_find_return:
    ret
.Lmrd_name:
    test rsi, rsi
    jz .Lmrd_name_bad
    mov rcx, rsi
    xor eax, eax
    repne scasb
    jne .Lmrd_name_bad
    test rcx, rcx
    jnz .Lmrd_name_bad
    xor eax, eax
    ret
.Lmrd_name_bad:
    mov eax, M_INVALID
    ret

/* HIA-selected fixed capability operation. All other scalars must be zero.
 * No request may nominate a code pointer or an unowned FD. */
.Lmrd_capability:
    M_ENTER
    mov qword ptr [r12+232], 0
    mov qword ptr [r12+240], 0
    cmp qword ptr [rbp+48], 0
    jne .Lmrd_cap_bad
    mov rbx, [rbp+24]
    cmp rbx, 5
    je .Lmrd_cap_read_check
    cmp qword ptr [rbp+40], 0
    jne .Lmrd_cap_bad
    cmp rbx, 1
    je .Lmrd_cap_open
    cmp rbx, 2
    jb .Lmrd_cap_bad
    cmp rbx, 4
    ja .Lmrd_cap_bad
    jmp .Lmrd_cap_owned
.Lmrd_cap_read_check:
    cmp qword ptr [rbp+40], 1
    jb .Lmrd_cap_bad
    cmp qword ptr [rbp+40], 65537
    ja .Lmrd_cap_bad
.Lmrd_cap_owned:
    cmp qword ptr [rbp+56], 0
    jne .Lmrd_cap_bad
    mov rdi, [rbp+32]
    call .Lmrd_fd_find
    cmp rax, -1
    je .Lmrd_cap_bad
    mov r15, rax
    cmp rbx, 2
    je .Lmrd_cap_stat
    cmp rbx, 3
    je .Lmrd_cap_close
    cmp rbx, 5
    je .Lmrd_cap_read
    mov rdi, [r12+376]
    mov rsi, [rbp+32]
    mov rdx, r12
    mov rcx, [r12+192]
    call hia_process_orphans_append
    test rax, rax
    jnz .Lmrd_cap_resource
    mov qword ptr [r12+256+r15*8], -1
    dec qword ptr [r12+184]
    inc qword ptr [r12+400]
    jmp .Lmrd_cap_ok
.Lmrd_cap_open:
    xor r15d, r15d
.Lmrd_cap_free_slot:
    cmp qword ptr [r12+256+r15*8], -1
    je .Lmrd_cap_parent
    inc r15d
    cmp r15d, 8
    jb .Lmrd_cap_free_slot
    jmp .Lmrd_cap_bad
.Lmrd_cap_parent:
    mov r14, [r12+384]
    mov rax, [rbp+32]
    cmp qword ptr [r14+56], 4
    jne .Lmrd_cap_parent_second
    cmp [r14+344], rax
    je .Lmrd_cap_parent_found
.Lmrd_cap_parent_second:
    mov r14, [r12+392]
    cmp qword ptr [r14+56], 4
    jne .Lmrd_cap_bad
    cmp [r14+344], rax
    jne .Lmrd_cap_bad
.Lmrd_cap_parent_found:
    cmp qword ptr [r14+8], 4096
    jne .Lmrd_cap_bad
    cmp qword ptr [r14+352], 1
    jne .Lmrd_cap_bad
    cmp qword ptr [r14+184], 1
    jne .Lmrd_cap_bad
    cmp rax, 2147483647
    ja .Lmrd_cap_bad
    lea rdi, [rbp+64]
    mov rsi, [rbp+56]
    call .Lmrd_name
    test eax, eax
    jnz .Lmrd_cap_bad
    mov rsi, [r14+104]
    cmp qword ptr [rsi+8], 6
    jne .Lmrd_cap_bad
    mov rcx, [rsi+56]
    lea rax, [rcx+1]
    cmp [rbp+56], rax
    jne .Lmrd_cap_bad
    add rsi, 64
    lea rdi, [rbp+64]
    repe cmpsb
    jne .Lmrd_cap_bad
    mov rdi, [rbp+32]
    lea rsi, [rbp+64]
    mov edx, 657408 /* fixed O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC, O_RDONLY */
    mov r10d, 384
    mov eax, 257
    syscall
    mov [r12+232], rax
    cmp rax, -4095
    jae .Lmrd_cap_ok
    cmp rax, 2147483647
    ja .Lmrd_cap_bad
    mov [r12+256+r15*8], rax
    inc qword ptr [r12+184]
    jmp .Lmrd_cap_ok
.Lmrd_cap_stat:
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
    jnz .Lmrd_cap_ok
    mov qword ptr [r12+240], 144
    jmp .Lmrd_cap_ok
.Lmrd_cap_read:
    mov rdi, [rbp+32]
    mov rsi, [r12+120]
    add rsi, 96
    mov rdx, [rbp+40]
    xor eax, eax
    syscall
    mov [r12+232], rax
    test rax, rax
    js .Lmrd_cap_ok
    mov [r12+240], rax
    jmp .Lmrd_cap_ok
.Lmrd_cap_close:
    mov rdi, [rbp+32]
    mov eax, 3
    syscall
    mov [r12+232], rax
    mov qword ptr [r12+256+r15*8], -1
    dec qword ptr [r12+184]
.Lmrd_cap_ok:
    xor eax, eax
    jmp .Lmrd_cap_done
.Lmrd_cap_resource:
    mov eax, M_RESOURCE
    jmp .Lmrd_cap_done
.Lmrd_cap_bad:
    mov eax, M_INVALID
.Lmrd_cap_done:
    M_LEAVE
/* All paths and policy packets are owned by the HIA body. */
.global multi_read_body_invoke
multi_read_body_invoke:
    M_ENTER
    mov r12, rdi
    mov r13, rsi
    mov r14, rdx
    mov rax, M_MAGIC
    cmp [r12], rax
    jne .Lmrd_invoke_reject
    cmp qword ptr [r12+8], 4096
    jne .Lmrd_invoke_reject
    cmp qword ptr [r12+56], 0
    jne .Lmrd_invoke_busy
    mov rax, [r12+184]
    or rax, [r12+344]
    or rax, [r12+352]
    or rax, [r12+360]
    or rax, [r12+368]
    jnz .Lmrd_invoke_reject
    cmp r14, 96
    jb .Lmrd_invoke_reject
    cmp r14, M_MAX_INPUT
    jae .Lmrd_invoke_reject
    test r13, r13
    jz .Lmrd_invoke_reject
    mov rax, 0x3130305144524d48
    cmp [r13], rax
    jne .Lmrd_invoke_reject
    cmp qword ptr [r13+8], 1
    jne .Lmrd_invoke_reject
    mov rax, [r13+16]
    or rax, [r13+56]
    or rax, [r13+64]
    or rax, [r13+72]
    or rax, [r13+80]
    jnz .Lmrd_invoke_reject
    mov rax, r14
    sub rax, 96
    cmp [r13+88], rax
    jne .Lmrd_invoke_reject
    cmp qword ptr [r12+192], -1
    je .Lmrd_invoke_reject
    mov rbx, [r12+384]
    cmp qword ptr [rbx+56], 0
    jne .Lmrd_invoke_reject
    cmp qword ptr [rbx+184], 0
    jne .Lmrd_invoke_reject
    mov rbx, [r12+392]
    cmp qword ptr [rbx+56], 0
    jne .Lmrd_invoke_reject
    cmp qword ptr [rbx+184], 0
    jne .Lmrd_invoke_reject
    lea rdi, [r12+64]
    mov rsi, r14
    call .Lmrd_grow
    test eax, eax
    jnz .Lmrd_invoke_return
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
.Lmrd_invoke_loop:
    inc qword ptr [r12+248]
    jz .Lmrd_invoke_failed
    mov rdi, [r12+104]
    mov rcx, [r12+112]
    shr rcx, 3
    mov rax, 0xa5a5a5a5a5a5a5a5
    rep stosq
    mov edx, 1
    mov rcx, [r12+200]
    mov r8, [r12+208]
    call .Lmrd_emit
    test rax, rax
    jnz .Lmrd_invoke_failed
    mov edx, 10
    mov rcx, [r12+88]
    mov r8, [r12+96]
    call .Lmrd_emit
    test rax, rax
    jnz .Lmrd_invoke_failed
    mov edx, 12
    mov rcx, [r12+104]
    mov r8, [r12+112]
    call .Lmrd_emit
    test rax, rax
    jnz .Lmrd_invoke_failed
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
    call .Lmrd_emit
    test rax, rax
    jnz .Lmrd_invoke_failed
    mov edx, 11
    mov rcx, [r12+88]
    mov r8, [r12+96]
    call .Lmrd_emit
    test rax, rax
    jnz .Lmrd_invoke_failed
    cmp qword ptr [r12+176], 64
    jne .Lmrd_invoke_failed
    mov rbp, [r12+104]
    mov rax, 0x3130305344524d48
    cmp [rbp], rax
    jne .Lmrd_invoke_failed
    mov rax, [r12+112]
    sub rax, 64
    cmp [rbp+56], rax
    ja .Lmrd_invoke_failed
    mov rbx, [rbp+8]
    cmp rbx, 5
    ja .Lmrd_invoke_failed
    test rbx, rbx
    jz .Lmrd_invoke_final
    cmp rbx, 3
    je .Lmrd_invoke_final
    cmp rbx, 4
    jae .Lmrd_invoke_growth
    mov rax, [rbp+16]
    mov [r12+216], rax
    mov rax, [rbp+24]
    mov [r12+224], rax
    cmp rbx, 2
    je .Lmrd_invoke_child
    mov edx, 8
    mov rcx, rbp
    mov r8, [rbp+56]
    add r8, 64
    call .Lmrd_emit
    test rax, rax
    jnz .Lmrd_invoke_failed
    call .Lmrd_capability
    cmp eax, M_RESOURCE
    je .Lmrd_invoke_resource
    test eax, eax
    jnz .Lmrd_invoke_failed
    jmp .Lmrd_invoke_reply

.Lmrd_invoke_child:
    cmp qword ptr [rbp+48], 0
    jne .Lmrd_invoke_failed
    mov edx, 5
    lea rcx, [rbp+64]
    mov r8, [rbp+56]
    call .Lmrd_emit
    test rax, rax
    jnz .Lmrd_invoke_failed
    mov rbx, [rbp+24]
    cmp rbx, 3
    je .Lmrd_child_parent_acquire
    cmp rbx, 4
    je .Lmrd_child_parent_close
    mov rax, [rbp+32]
    or rax, [rbp+40]
    jnz .Lmrd_invoke_failed
    cmp rbx, 1
    je .Lmrd_child_codec
    cmp rbx, 2
    je .Lmrd_child_stat
    cmp rbx, 5
    je .Lmrd_child_utf8
    jmp .Lmrd_invoke_failed
.Lmrd_child_parent_acquire:
    cmp qword ptr [rbp+40], 0
    jne .Lmrd_invoke_failed
    mov rbx, [rbp+32]
    cmp rbx, 1
    ja .Lmrd_invoke_failed
    cmp qword ptr [rbp+56], 96
    jb .Lmrd_invoke_failed
    cmp qword ptr [rbp+56], 8288
    ja .Lmrd_invoke_failed
    mov r14, [r12+384+rbx*8]
    cmp qword ptr [r14+56], 0
    jne .Lmrd_invoke_failed
    mov [r12+360], r14
    mov qword ptr [r12+368], 3
    mov rdi, r14
    lea rsi, [rbp+64]
    mov rdx, [rbp+56]
    call parent_directory_acquire
    cmp rax, 64
    jne .Lmrd_invoke_failed
    jmp .Lmrd_child_copy_parent
.Lmrd_child_parent_close:
    cmp qword ptr [rbp+40], 0
    jne .Lmrd_invoke_failed
    cmp qword ptr [rbp+56], 0
    jne .Lmrd_invoke_failed
    mov rbx, [rbp+32]
    cmp rbx, 1
    ja .Lmrd_invoke_failed
    mov r14, [r12+384+rbx*8]
    cmp qword ptr [r14+56], 4
    jne .Lmrd_invoke_failed
    mov [r12+360], r14
    mov qword ptr [r12+368], 4
    mov rdi, r14
    call parent_directory_close
    cmp rax, 64
    jne .Lmrd_invoke_failed
.Lmrd_child_copy_parent:
    mov rdi, r14
    call .Lmrd_copy_parent
    cmp eax, M_RESOURCE
    je .Lmrd_invoke_resource
    test eax, eax
    jnz .Lmrd_invoke_failed
    jmp .Lmrd_invoke_reply
.Lmrd_child_codec:
    cmp qword ptr [rbp+56], 24
    jb .Lmrd_invoke_failed
    cmp qword ptr [rbp+56], 65560
    ja .Lmrd_invoke_failed
    movabs rax, 0x314345444f435248
    cmp [rbp+64], rax
    jne .Lmrd_invoke_failed
    cmp qword ptr [rbp+72], 2
    jne .Lmrd_invoke_failed
    cmp qword ptr [rbp+80], 0
    jne .Lmrd_invoke_failed
    mov rax, [r12+32]
    mov [r12+320], rax
    mov qword ptr [r12+328], 64
    mov qword ptr [r12+336], 1184
    jmp .Lmrd_child_direct
.Lmrd_child_stat:
    cmp qword ptr [rbp+56], 72
    jne .Lmrd_invoke_failed
    movabs rax, 0x3130524556545348
    cmp [rbp+64], rax
    jne .Lmrd_invoke_failed
    cmp qword ptr [rbp+72], 1
    jne .Lmrd_invoke_failed
    mov rax, [r12+24]
    mov [r12+320], rax
    mov qword ptr [r12+328], 128
    mov qword ptr [r12+336], 256
    jmp .Lmrd_child_direct
.Lmrd_child_utf8:
    cmp qword ptr [rbp+56], 16
    jb .Lmrd_invoke_failed
    cmp qword ptr [rbp+56], 65552
    ja .Lmrd_invoke_failed
    movabs rax, 0x3130305146545548
    cmp [rbp+64], rax
    jne .Lmrd_invoke_failed
    mov rax, [rbp+56]
    sub rax, 16
    cmp [rbp+72], rax
    jne .Lmrd_invoke_failed
    mov rax, [r12+152]
    mov [r12+320], rax
    mov qword ptr [r12+328], 256
    mov qword ptr [r12+336], 512
.Lmrd_child_direct:
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
    call .Lmrd_emit
    test rax, rax
    jnz .Lmrd_invoke_failed
    mov edx, 14
    mov rcx, [r12+144]
    mov r8, [r12+336]
    call .Lmrd_emit
    test rax, rax
    jnz .Lmrd_invoke_failed
    lea rdi, [rbp+64]
    mov rsi, [rbp+56]
    mov rdx, [r12+136]
    mov rcx, [r12+328]
    mov r8, [r12+144]
    mov r9, [r12+336]
    call qword ptr [r12+320]
    mov [r12+232], rax
    cmp rax, [r12+328]
    ja .Lmrd_invoke_failed
    mov [r12+240], rax
    mov rdi, [r12+120]
    add rdi, 96
    mov rsi, [r12+136]
    mov rcx, rax
    rep movsb
    mov edx, 6
    mov rcx, [r12+136]
    mov r8, [r12+328]
    call .Lmrd_emit
    test rax, rax
    jnz .Lmrd_invoke_failed
    mov edx, 7
    mov rcx, [r12+144]
    mov r8, [r12+336]
    call .Lmrd_emit
    test rax, rax
    jnz .Lmrd_invoke_failed
.Lmrd_invoke_reply:
    mov rbx, [r12+120]
    mov rax, 0x3130305144524d48
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
    ja .Lmrd_invoke_failed
    mov [rbx+88], rax
    add rax, 96
    cmp rax, [r12+128]
    ja .Lmrd_invoke_failed
    mov [r12+200], rbx
    mov [r12+208], rax
    mov edx, 9
    mov rcx, rbx
    mov r8, rax
    call .Lmrd_emit
    test rax, rax
    jnz .Lmrd_invoke_failed
    jmp .Lmrd_invoke_loop
.Lmrd_invoke_growth:
    mov rax, [rbp+16]
    or rax, [rbp+24]
    or rax, [rbp+40]
    or rax, [rbp+48]
    or rax, [rbp+56]
    jnz .Lmrd_invoke_failed
    mov r13, [rbp+32]
    cmp rbx, 4
    jne .Lmrd_invoke_output_growth
    cmp r13, [r12+96]
    jbe .Lmrd_invoke_failed
    cmp r13, M_MAX_WORK
    ja .Lmrd_invoke_failed
    mov edx, 3
    mov rcx, [r12+88]
    mov r8, [r12+96]
    call .Lmrd_emit
    test rax, rax
    jnz .Lmrd_invoke_failed
    lea rdi, [r12+88]
    mov rsi, r13
    call .Lmrd_grow
    test eax, eax
    jnz .Lmrd_invoke_resource
    mov edx, 4
    mov rcx, [r12+88]
    mov r8, [r12+96]
    call .Lmrd_emit
    test rax, rax
    jnz .Lmrd_invoke_failed
    jmp .Lmrd_invoke_loop
.Lmrd_invoke_output_growth:
    cmp r13, [r12+112]
    jbe .Lmrd_invoke_failed
    cmp r13, M_MAX_OUT
    ja .Lmrd_invoke_failed
    lea rdi, [r12+104]
    mov rsi, r13
    call .Lmrd_grow
    test eax, eax
    jnz .Lmrd_invoke_resource
    jmp .Lmrd_invoke_loop
.Lmrd_invoke_final:
    cmp qword ptr [r12+184], 0
    jne .Lmrd_invoke_failed
    mov rax, [r12+360]
    or rax, [r12+368]
    jnz .Lmrd_invoke_failed
    mov rax, [r12+384]
    cmp qword ptr [rax+56], 0
    jne .Lmrd_invoke_failed
    mov rax, [r12+392]
    cmp qword ptr [rax+56], 0
    jne .Lmrd_invoke_failed
    mov rax, [rbp+24]
    or rax, [rbp+32]
    or rax, [rbp+40]
    or rax, [rbp+48]
    jnz .Lmrd_invoke_failed
    cmp qword ptr [rbp+8], 3
    jne .Lmrd_invoke_borrow
    cmp qword ptr [rbp+56], 64
    jb .Lmrd_invoke_failed
    mov rax, 0x3130305344524248
    cmp [rbp+64], rax
    je .Lmrd_invoke_error_magic
    mov rax, 0x3130304446545548
    cmp [rbp+64], rax
    jne .Lmrd_invoke_failed
.Lmrd_invoke_error_magic:
    cmp qword ptr [rbp+72], 3
    jne .Lmrd_invoke_failed
    mov rax, [rbp+56]
    sub rax, 64
    cmp [rbp+120], rax
    jne .Lmrd_invoke_failed
.Lmrd_invoke_borrow:
    mov qword ptr [r12+344], 0
    mov qword ptr [r12+352], 0
    mov rax, [rbp+56]
    add rax, 64
    mov [r12+168], rax
    mov qword ptr [r12+56], 2
    mov eax, 64
    jmp .Lmrd_invoke_return
.Lmrd_invoke_resource:
    mov eax, M_RESOURCE
    jmp .Lmrd_invoke_record_failure
.Lmrd_invoke_failed:
    mov eax, M_INVALID
.Lmrd_invoke_record_failure:
    mov [r12+176], rax
    /* A private allocation/observer failure cannot leave a child output loan.
     * Child failures retain their own operable ledger until context teardown. */
    mov rdi, [r12+384]
    cmp qword ptr [rdi+56], 2
    jne .Lmrd_failure_parent_second
    call parent_directory_release
.Lmrd_failure_parent_second:
    mov rdi, [r12+392]
    cmp qword ptr [rdi+56], 2
    jne .Lmrd_failure_recorded
    call parent_directory_release
.Lmrd_failure_recorded:
    mov qword ptr [r12+344], 0
    mov qword ptr [r12+352], 0
    mov qword ptr [r12+360], 0
    mov qword ptr [r12+368], 0
    mov qword ptr [r12+56], 3
    mov qword ptr [r12+168], 0
    mov rax, [r12+176]
    jmp .Lmrd_invoke_return
.Lmrd_invoke_busy:
    mov eax, M_BUSY
    jmp .Lmrd_invoke_return
.Lmrd_invoke_reject:
    mov eax, M_INVALID
.Lmrd_invoke_return:
    M_LEAVE

/* Copy every actual parent frame. A kind-6 held loan remains held.
 * Only terminal state-2 error/close responses are released here. */
.Lmrd_copy_parent:
    M_ENTER
    mov r14, rdi
    mov r15, [r14+56]
    cmp r15, 2
    je .Lmrd_copy_state
    cmp r15, 4
    jne .Lmrd_copy_bad
.Lmrd_copy_state:
    mov r13, [r14+168]
    cmp r13, 64
    jb .Lmrd_copy_bad
    cmp r13, 4160
    ja .Lmrd_copy_bad
    mov rax, [r14+104]
    test rax, rax
    jz .Lmrd_copy_bad
    cmp r13, [r14+112]
    ja .Lmrd_copy_bad
    mov rbx, [rax+56]
    add rbx, 64
    jc .Lmrd_copy_bad
    cmp r13, rbx
    jne .Lmrd_copy_bad
    cmp r15, 4
    jne .Lmrd_copy_terminal
    cmp qword ptr [rax+8], 6
    jne .Lmrd_copy_bad
    jmp .Lmrd_copy_extent
.Lmrd_copy_terminal:
    cmp qword ptr [rax+8], 0
    je .Lmrd_copy_extent
    cmp qword ptr [rax+8], 3
    jne .Lmrd_copy_bad
.Lmrd_copy_extent:
    lea rdi, [r12+120]
    lea rsi, [r13+96]
    call .Lmrd_grow
    test eax, eax
    jnz .Lmrd_copy_resource
    mov edx, 6
    mov rcx, [r14+104]
    mov r8, r13
    call .Lmrd_emit
    test rax, rax
    jnz .Lmrd_copy_bad
    mov edx, 15
    mov rcx, r14
    mov r8d, 4096
    call .Lmrd_emit
    test rax, rax
    jnz .Lmrd_copy_bad
    mov rdi, [r12+120]
    add rdi, 96
    mov rsi, [r14+104]
    mov rcx, r13
    rep movsb
    mov [r12+232], r13
    mov [r12+240], r13
    cmp r15, 4
    je .Lmrd_copy_held
    mov rdi, r14
    call parent_directory_release
    test rax, rax
    jnz .Lmrd_copy_bad
.Lmrd_copy_held:
    mov qword ptr [r12+360], 0
    mov qword ptr [r12+368], 0
    xor eax, eax
    jmp .Lmrd_copy_done
.Lmrd_copy_resource:
    mov eax, M_RESOURCE
    jmp .Lmrd_copy_done
.Lmrd_copy_bad:
    mov eax, M_INVALID
.Lmrd_copy_done:
    M_LEAVE

/* Four direct HIA entries and one parent image are fixed by the actual packer. */
.balign 16
.global multi_read_body_body_call_displacement
.Lmrd_body:
    .byte 0xe9
multi_read_body_body_call_displacement:
    .long 0
.global multi_read_body_stat_call_displacement
.Lmrd_stat:
    .byte 0xe9
multi_read_body_stat_call_displacement:
    .long 0
.global multi_read_body_codec_call_displacement
.Lmrd_codec:
    .byte 0xe9
multi_read_body_codec_call_displacement:
    .long 0
.global multi_read_body_utf8_call_displacement
.Lmrd_utf8:
    .byte 0xe9
multi_read_body_utf8_call_displacement:
    .long 0

.section .note.GNU-stack,"",@progbits
