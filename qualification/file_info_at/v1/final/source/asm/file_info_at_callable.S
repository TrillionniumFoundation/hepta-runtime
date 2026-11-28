/* Copyright 2026 Muvon Un Limited
 * SPDX-License-Identifier: Apache-2.0
 * Fixed borrowed-parent info capability. All original info policy is HIA.
 * Immutable image entries and the journal callback are trusted graph bindings.
 */
.intel_syntax noprefix
.section .text
.macro I_ENTER
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp, 8
.endm
.macro I_LEAVE
    add rsp, 8
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret
.endm
.equ I_MAGIC, 0x31304943464e4948 /* HINFCI01 */
.equ I_INVALID, 0xffffffff
.equ I_BUSY, 0xfffffffd
.equ I_RESOURCE, 0xfffffffc
.equ I_MAX_WORK, 268435456
.equ I_MAX_OUT, 134217728
.equ I_MAX_INPUT, 134217728
.equ I_REPLY_CAP, 4096
.equ I_CHILD_OUT, 4096

/* rdi nonzero page-aligned capacity; return a zeroed RW arena plus an inaccessible
 * final guard page. No input bytes select a mapping or a code entry. */
.Lifa_map:
    test rdi, rdi
    jz .Lifa_map_bad
    test rdi, 4095
    jnz .Lifa_map_bad
    cmp rdi, I_MAX_WORK
    ja .Lifa_map_bad
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
    jae .Lifa_map_done
    push rax
    lea rdi, [rax+rbx]
    mov esi, 4096
    xor edx, edx
    mov eax, 10
    syscall
    test rax, rax
    jnz .Lifa_map_guard_failed
    pop rax
    jmp .Lifa_map_done
.Lifa_map_guard_failed:
    pop rdi
    lea rsi, [rbx+4096]
    mov eax, 11
    syscall
    mov rax, -12
.Lifa_map_done:
    pop rbx
    ret
.Lifa_map_bad:
    mov rax, -22
    ret

/* Grow a pointer/capacity pair in a private context. rdi points to the pair,
 * rsi is the required extent. Every old byte is copied, the extension is zero.
 * The old mapping is retired only after allocation and copy are complete. */
.Lifa_grow:
    I_ENTER
    mov r12, rdi
    mov r13, rsi
    test r13, r13
    jz .Lifa_grow_bad
    cmp r13, I_MAX_WORK
    ja .Lifa_grow_bad
    add r13, 4095
    jc .Lifa_grow_bad
    and r13, -4096
    cmp r13, [r12+8]
    jbe .Lifa_grow_ok
    mov rdi, r13
    call .Lifa_map
    cmp rax, -4095
    jae .Lifa_grow_resource
    mov r14, rax
    mov rdi, rax
    mov rsi, [r12]
    mov rcx, [r12+8]
    test rcx, rcx
    jz .Lifa_grow_install
    test rsi, rsi
    jz .Lifa_grow_new_failed
    rep movsb
    mov rdi, [r12]
    mov rsi, [r12+8]
    add rsi, 4096
    mov eax, 11
    syscall
    test rax, rax
    jnz .Lifa_grow_new_failed
.Lifa_grow_install:
    mov [r12], r14
    mov [r12+8], r13
.Lifa_grow_ok:
    xor eax, eax
    jmp .Lifa_grow_done
.Lifa_grow_new_failed:
    mov rdi, r14
    lea rsi, [r13+4096]
    mov eax, 11
    syscall
.Lifa_grow_resource:
    mov eax, I_RESOURCE
    jmp .Lifa_grow_done
.Lifa_grow_bad:
    mov eax, I_INVALID
.Lifa_grow_done:
    I_LEAVE

/* Fixed graph registers: callback, callback context, shared orphan pool. */
.global file_info_at_create
file_info_at_create:
    I_ENTER
    mov r13, rdi
    mov r14, rsi
    mov r15, rdx
    test r15, r15
    jz .Lifa_create_bad
    test r15, 4095
    jnz .Lifa_create_bad
    movabs rax, 0x31303050524f5048
    cmp [r15], rax
    jne .Lifa_create_bad
    cmp qword ptr [r15+8], 4096
    jne .Lifa_create_bad
    mov eax, 39
    syscall
    cmp [r15+16], rax
    jne .Lifa_create_bad
    mov edi, 4096
    call .Lifa_map
    cmp rax, -4095
    jae .Lifa_create_return
    mov r12, rax
    mov rax, I_MAGIC
    mov [r12], rax
    mov qword ptr [r12+8], 4096
    lea rax, [rip+.Lifa_body]
    mov [r12+16], rax
    lea rax, [rip+.Lifa_stat]
    mov [r12+24], rax
    mov [r12+40], r13
    mov [r12+48], r14
    mov [r12+376], r15
    lea rdi, [r12+256]
    mov rax, -1
    mov ecx, 8
    rep stosq
    lea rdi, [r12+88]
    mov esi, 4096
    call .Lifa_grow
    test eax, eax
    jnz .Lifa_create_fail
    lea rdi, [r12+104]
    mov esi, 4096
    call .Lifa_grow
    test eax, eax
    jnz .Lifa_create_fail
    lea rdi, [r12+120]
    mov esi, I_REPLY_CAP
    call .Lifa_grow
    test eax, eax
    jnz .Lifa_create_fail
    mov edi, I_CHILD_OUT
    call .Lifa_map
    cmp rax, -4095
    jae .Lifa_create_fail
    mov [r12+136], rax
    mov edi, 4096
    call .Lifa_map
    cmp rax, -4095
    jae .Lifa_create_fail
    mov [r12+144], rax
    mov rdi, r13
    mov rsi, r14
    call binary_read_body_create
    cmp rax, -4095
    jae .Lifa_create_fail
    mov [r12+384], rax
    mov rdi, r13
    mov rsi, r14
    call file_metadata_create
    cmp rax, -4095
    jae .Lifa_create_fail
    mov [r12+392], rax
    mov rax, r12
    jmp .Lifa_create_return
.Lifa_create_bad:
    mov rax, -22
    jmp .Lifa_create_return
.Lifa_create_fail:
    mov rdi, r12
    call file_info_at_destroy
    mov rax, -12
.Lifa_create_return:
    I_LEAVE

/* Callback is observational and cannot replace any effect or child result. */
.Lifa_emit:
    I_ENTER
    mov rbx, [r12+40]
    test rbx, rbx
    jz .Lifa_emit_ok
    mov rdi, [r12+48]
    mov rsi, r12
    call rbx
    jmp .Lifa_emit_return
.Lifa_emit_ok:
    xor eax, eax
.Lifa_emit_return:
    I_LEAVE

.global file_info_at_release
file_info_at_release:
    mov rax, I_MAGIC
    cmp [rdi], rax
    jne .Lifa_release_bad
    cmp qword ptr [rdi+8], 4096
    jne .Lifa_release_bad
    cmp qword ptr [rdi+56], 2
    jne .Lifa_release_bad
    mov rax, [rdi+184]
    or rax, [rdi+344]
    or rax, [rdi+352]
    or rax, [rdi+360]
    or rax, [rdi+368]
    jnz .Lifa_release_bad
    mov qword ptr [rdi+56], 0
    mov qword ptr [rdi+168], 0
    mov qword ptr [rdi+176], 0
    xor eax, eax
    ret
.Lifa_release_bad:
    mov eax, I_INVALID
    ret

/* Orphan pool at +376 is never destroyed or traversed for close. */
.global file_info_at_destroy
file_info_at_destroy:
    I_ENTER
    mov r12, rdi
    mov rax, I_MAGIC
    cmp [r12], rax
    jne .Lifa_destroy_bad
    cmp qword ptr [r12+8], 4096
    jne .Lifa_destroy_bad
    mov rax, [r12+56]
    cmp rax, 1
    je .Lifa_destroy_busy
    cmp rax, 2
    je .Lifa_destroy_busy
    cmp rax, 3
    ja .Lifa_destroy_bad
    mov rdi, [r12+392]
    test rdi, rdi
    jz .Lifa_destroy_read
    call file_metadata_destroy
    test rax, rax
    jnz .Lifa_destroy_resource
    mov qword ptr [r12+392], 0
.Lifa_destroy_read:
    mov rdi, [r12+384]
    test rdi, rdi
    jz .Lifa_destroy_owned
    call binary_read_body_destroy
    test rax, rax
    jnz .Lifa_destroy_resource
    mov qword ptr [r12+384], 0
.Lifa_destroy_owned:
    xor ebx, ebx
.Lifa_destroy_fd:
    mov rdi, [r12+256+rbx*8]
    cmp rdi, -1
    je .Lifa_destroy_fd_next
    mov eax, 3
    syscall
    mov qword ptr [r12+256+rbx*8], -1
.Lifa_destroy_fd_next:
    inc ebx
    cmp ebx, 8
    jb .Lifa_destroy_fd
    mov qword ptr [r12+184], 0
    lea r13, [rip+.Lifa_pairs]
    mov ebx, 4
.Lifa_destroy_pair:
    mov r14, [r13]
    mov rdi, [r12+r14]
    test rdi, rdi
    jz .Lifa_destroy_pair_next
    mov rsi, [r12+r14+8]
    add rsi, 4096
    mov eax, 11
    syscall
    test rax, rax
    jnz .Lifa_destroy_resource
    mov qword ptr [r12+r14], 0
    mov qword ptr [r12+r14+8], 0
.Lifa_destroy_pair_next:
    add r13, 8
    dec ebx
    jnz .Lifa_destroy_pair
    mov ebx, 136
.Lifa_destroy_stat_arena:
    mov rdi, [r12+rbx]
    test rdi, rdi
    jz .Lifa_destroy_stat_next
    mov esi, 8192
    mov eax, 11
    syscall
    test rax, rax
    jnz .Lifa_destroy_resource
    mov qword ptr [r12+rbx], 0
.Lifa_destroy_stat_next:
    add ebx, 8
    cmp ebx, 152
    jb .Lifa_destroy_stat_arena
    mov rdi, r12
    mov esi, 8192
    mov eax, 11
    syscall
    jmp .Lifa_destroy_return
.Lifa_destroy_busy:
    mov eax, I_BUSY
    jmp .Lifa_destroy_return
.Lifa_destroy_resource:
    mov eax, I_RESOURCE
    jmp .Lifa_destroy_return
.Lifa_destroy_bad:
    mov eax, I_INVALID
.Lifa_destroy_return:
    I_LEAVE
.balign 8
.Lifa_pairs:
    .quad 64,88,104,120

/* Only owned slots are returned; the parent is checked separately. */
.Lifa_fd_find:
    cmp rdi, 2147483647
    ja .Lifa_fd_find_bad
    cmp qword ptr [r12+184], 0
    je .Lifa_fd_find_bad
    xor eax, eax
.Lifa_fd_find_loop:
    cmp [r12+256+rax*8], rdi
    je .Lifa_fd_find_return
    inc eax
    cmp eax, 8
    jb .Lifa_fd_find_loop
.Lifa_fd_find_bad:
    mov rax, -1
.Lifa_fd_find_return:
    ret
.Lifa_name:
    test rsi, rsi
    jz .Lifa_name_bad
    mov rcx, rsi
    xor eax, eax
    repne scasb
    jne .Lifa_name_bad
    test rcx, rcx
    jnz .Lifa_name_bad
    xor eax, eax
    ret
.Lifa_name_bad:
    mov eax, I_INVALID
    ret

/* HIA-selected fixed capability operation. All other scalars must be zero.
 * No request may nominate a code pointer or an unowned FD. */
.Lifa_capability:
    I_ENTER
    mov qword ptr [r12+232], 0
    mov qword ptr [r12+240], 0
    mov rax, [rbp+40]
    or rax, [rbp+48]
    jnz .Lifa_cap_bad
    mov rbx, [rbp+24]
    cmp rbx, 1
    je .Lifa_cap_open
    cmp rbx, 2
    jb .Lifa_cap_bad
    cmp rbx, 4
    ja .Lifa_cap_bad
    cmp qword ptr [rbp+56], 0
    jne .Lifa_cap_bad
    mov rdi, [rbp+32]
    call .Lifa_fd_find
    cmp rax, -1
    je .Lifa_cap_bad
    mov r15, rax
    cmp rbx, 2
    je .Lifa_cap_stat
    cmp rbx, 3
    je .Lifa_cap_close
    mov rdi, [r12+376]
    mov rsi, [rbp+32]
    mov rdx, r12
    mov rcx, [r12+192]
    call hia_process_orphans_append
    test rax, rax
    jnz .Lifa_cap_resource
    mov qword ptr [r12+256+r15*8], -1
    dec qword ptr [r12+184]
    inc qword ptr [r12+400]
    jmp .Lifa_cap_ok
.Lifa_cap_open:
    cmp qword ptr [r12+352], 1
    jne .Lifa_cap_bad
    mov rax, [rbp+32]
    cmp rax, [r12+344]
    jne .Lifa_cap_bad
    cmp qword ptr [r12+184], 0
    jne .Lifa_cap_bad
    lea rdi, [rbp+64]
    mov rsi, [rbp+56]
    call .Lifa_name
    test eax, eax
    jnz .Lifa_cap_bad
    mov rdi, [rbp+32]
    lea rsi, [rbp+64]
    mov edx, 657408 /* O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC; O_RDONLY=0 */
    mov r10d, 384
    mov eax, 257
    syscall
    mov [r12+232], rax
    cmp rax, -4095
    jae .Lifa_cap_ok
    cmp rax, 2147483647
    ja .Lifa_cap_bad
    mov [r12+256], rax
    mov qword ptr [r12+184], 1
    jmp .Lifa_cap_ok
.Lifa_cap_stat:
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
    jnz .Lifa_cap_ok
    mov qword ptr [r12+240], 144
    jmp .Lifa_cap_ok
.Lifa_cap_close:
    mov rdi, [rbp+32]
    mov eax, 3
    syscall
    mov [r12+232], rax
    mov qword ptr [r12+256+r15*8], -1
    dec qword ptr [r12+184]
.Lifa_cap_ok:
    xor eax, eax
    jmp .Lifa_cap_done
.Lifa_cap_resource:
    mov eax, I_RESOURCE
    jmp .Lifa_cap_done
.Lifa_cap_bad:
    mov eax, I_INVALID
.Lifa_cap_done:
    I_LEAVE
/* Fixed graph-only parent capability. Packet FD word is zero externally. */
.global file_info_at_invoke
file_info_at_invoke:
    I_ENTER
    mov r12, rdi
    mov r15, rsi
    mov r13, rdx
    mov r14, rcx
    cmp r15, 2147483647
    ja .Lifa_invoke_reject
    mov rax, I_MAGIC
    cmp [r12], rax
    jne .Lifa_invoke_reject
    cmp qword ptr [r12+8], 4096
    jne .Lifa_invoke_reject
    cmp qword ptr [r12+56], 0
    jne .Lifa_invoke_busy
    mov rax, [r12+184]
    or rax, [r12+344]
    or rax, [r12+352]
    or rax, [r12+360]
    or rax, [r12+368]
    jnz .Lifa_invoke_reject
    cmp r14, 96
    jb .Lifa_invoke_reject
    cmp r14, I_MAX_INPUT
    ja .Lifa_invoke_reject
    test r13, r13
    jz .Lifa_invoke_reject
    mov rax, 0x31303051464e4948
    cmp [r13], rax
    jne .Lifa_invoke_reject
    cmp qword ptr [r13+8], 1
    jne .Lifa_invoke_reject
    cmp qword ptr [r13+24], 1
    jne .Lifa_invoke_reject
    mov rax, [r13+16]
    or rax, [r13+32]
    or rax, [r13+56]
    or rax, [r13+64]
    or rax, [r13+72]
    or rax, [r13+80]
    jnz .Lifa_invoke_reject
    mov rax, r14
    sub rax, 96
    cmp [r13+88], rax
    jne .Lifa_invoke_reject
    cmp [r13+40], rax
    ja .Lifa_invoke_reject
    sub rax, [r13+40]
    cmp [r13+48], rax
    jne .Lifa_invoke_reject
    cmp qword ptr [r12+192], -1
    je .Lifa_invoke_reject
    mov rbx, [r12+384]
    cmp qword ptr [rbx+56], 0
    jne .Lifa_invoke_reject
    mov rbx, [r12+392]
    cmp qword ptr [rbx+56], 0
    jne .Lifa_invoke_reject
    lea rdi, [r12+64]
    mov rsi, r14
    call .Lifa_grow
    test eax, eax
    jnz .Lifa_invoke_return
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
.Lifa_invoke_loop:
    inc qword ptr [r12+248]
    jz .Lifa_invoke_failed
    mov rdi, [r12+104]
    mov rcx, [r12+112]
    shr rcx, 3
    mov rax, 0xa5a5a5a5a5a5a5a5
    rep stosq
    mov edx, 1
    mov rcx, [r12+200]
    mov r8, [r12+208]
    call .Lifa_emit
    test rax, rax
    jnz .Lifa_invoke_failed
    mov edx, 10
    mov rcx, [r12+88]
    mov r8, [r12+96]
    call .Lifa_emit
    test rax, rax
    jnz .Lifa_invoke_failed
    mov edx, 12
    mov rcx, [r12+104]
    mov r8, [r12+112]
    call .Lifa_emit
    test rax, rax
    jnz .Lifa_invoke_failed
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
    call .Lifa_emit
    test rax, rax
    jnz .Lifa_invoke_failed
    mov edx, 11
    mov rcx, [r12+88]
    mov r8, [r12+96]
    call .Lifa_emit
    test rax, rax
    jnz .Lifa_invoke_failed
    cmp qword ptr [r12+176], 64
    jne .Lifa_invoke_failed
    mov rbp, [r12+104]
    mov rax, 0x31303052464e4948
    cmp [rbp], rax
    jne .Lifa_invoke_failed
    mov rax, [r12+112]
    sub rax, 64
    cmp [rbp+56], rax
    ja .Lifa_invoke_failed
    mov rbx, [rbp+8]
    cmp rbx, 5
    ja .Lifa_invoke_failed
    test rbx, rbx
    jz .Lifa_invoke_final
    cmp rbx, 3
    je .Lifa_invoke_final
    cmp rbx, 4
    jae .Lifa_invoke_growth
    mov rax, [rbp+16]
    mov [r12+216], rax
    mov rax, [rbp+24]
    mov [r12+224], rax
    cmp rbx, 2
    je .Lifa_invoke_child
    mov edx, 8
    mov rcx, rbp
    mov r8, [rbp+56]
    add r8, 64
    call .Lifa_emit
    test rax, rax
    jnz .Lifa_invoke_failed
    call .Lifa_capability
    cmp eax, I_RESOURCE
    je .Lifa_invoke_resource
    test eax, eax
    jnz .Lifa_invoke_failed
    jmp .Lifa_invoke_reply

.Lifa_invoke_child:
    cmp qword ptr [rbp+48], 0
    jne .Lifa_invoke_failed
    mov edx, 5
    lea rcx, [rbp+64]
    mov r8, [rbp+56]
    call .Lifa_emit
    test rax, rax
    jnz .Lifa_invoke_failed
    mov rbx, [rbp+24]
    cmp rbx, 1
    je .Lifa_child_fingerprint
    cmp rbx, 2
    je .Lifa_child_stat
    cmp rbx, 3
    jne .Lifa_invoke_failed
    cmp qword ptr [rbp+56], 96
    jb .Lifa_invoke_failed
    mov rax, 0x3130305154444d48
    cmp [rbp+64], rax
    jne .Lifa_invoke_failed
    mov rbx, [rbp+40]
    cmp rbx, [rbp+88]
    jne .Lifa_invoke_failed
    cmp rbx, 1
    je .Lifa_child_metadata_capture
    cmp rbx, 2
    jne .Lifa_invoke_failed
    cmp qword ptr [rbp+32], 0
    jne .Lifa_invoke_failed
    jmp .Lifa_child_metadata
.Lifa_child_metadata_capture:
    mov rdi, [rbp+32]
    call .Lifa_fd_find
    cmp rax, -1
    je .Lifa_invoke_failed
.Lifa_child_metadata:
    mov rax, [r12+392]
    mov [r12+360], rax
    mov qword ptr [r12+368], 3
    mov rdi, rax
    mov rsi, [rbp+32]
    xor edx, edx
    lea rcx, [rbp+64]
    mov r8, [rbp+56]
    call file_metadata_invoke
    cmp rax, 64
    jne .Lifa_invoke_failed
    mov rdi, [r12+392]
    mov esi, 3
    call .Lifa_copy_nested
    cmp eax, I_RESOURCE
    je .Lifa_invoke_resource
    test eax, eax
    jnz .Lifa_invoke_failed
    jmp .Lifa_invoke_reply
.Lifa_child_fingerprint:
    cmp qword ptr [rbp+40], 0
    jne .Lifa_invoke_failed
    mov rax, [rbp+32]
    cmp rax, [r12+344]
    jne .Lifa_invoke_failed
    cmp qword ptr [r12+352], 1
    jne .Lifa_invoke_failed
    cmp qword ptr [rbp+56], 96
    jb .Lifa_invoke_failed
    mov rax, 0x3130444644524248
    cmp [rbp+64], rax
    jne .Lifa_invoke_failed
    cmp qword ptr [rbp+88], 2
    jne .Lifa_invoke_failed
    mov rax, [r12+384]
    mov [r12+360], rax
    mov qword ptr [r12+368], 1
    mov rdi, rax
    mov rsi, [rbp+32]
    lea rdx, [rbp+64]
    mov rcx, [rbp+56]
    call binary_read_body_invoke_at
    cmp rax, 64
    jne .Lifa_invoke_failed
    mov rdi, [r12+384]
    mov esi, 1
    call .Lifa_copy_nested
    cmp eax, I_RESOURCE
    je .Lifa_invoke_resource
    test eax, eax
    jnz .Lifa_invoke_failed
    jmp .Lifa_invoke_reply
.Lifa_child_stat:
    mov rax, [rbp+32]
    or rax, [rbp+40]
    jnz .Lifa_invoke_failed
    cmp qword ptr [rbp+56], 72
    jne .Lifa_invoke_failed
    mov rax, [r12+24]
    mov [r12+320], rax
    mov qword ptr [r12+328], 128
    mov qword ptr [r12+336], 256
    mov rdi, [r12+136]
    mov ecx, 16
    mov rax, 0xa5a5a5a5a5a5a5a5
    rep stosq
    mov rdi, [r12+144]
    mov ecx, 32
    xor eax, eax
    rep stosq
    mov edx, 13
    mov rcx, [r12+136]
    mov r8, [r12+328]
    call .Lifa_emit
    test rax, rax
    jnz .Lifa_invoke_failed
    mov edx, 14
    mov rcx, [r12+144]
    mov r8, [r12+336]
    call .Lifa_emit
    test rax, rax
    jnz .Lifa_invoke_failed
    lea rdi, [rbp+64]
    mov rsi, [rbp+56]
    mov rdx, [r12+136]
    mov rcx, [r12+328]
    mov r8, [r12+144]
    mov r9, [r12+336]
    call qword ptr [r12+320]
    mov [r12+232], rax
    cmp rax, [r12+328]
    ja .Lifa_invoke_failed
    mov [r12+240], rax
    mov rdi, [r12+120]
    add rdi, 96
    mov rsi, [r12+136]
    mov rcx, rax
    rep movsb
    mov edx, 6
    mov rcx, [r12+136]
    mov r8, [r12+328]
    call .Lifa_emit
    test rax, rax
    jnz .Lifa_invoke_failed
    mov edx, 7
    mov rcx, [r12+144]
    mov r8, [r12+336]
    call .Lifa_emit
    test rax, rax
    jnz .Lifa_invoke_failed
.Lifa_invoke_reply:
    mov rbx, [r12+120]
    mov rax, 0x31303051464e4948
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
    ja .Lifa_invoke_failed
    mov [rbx+88], rax
    add rax, 96
    cmp rax, [r12+128]
    ja .Lifa_invoke_failed
    mov [r12+200], rbx
    mov [r12+208], rax
    mov edx, 9
    mov rcx, rbx
    mov r8, rax
    call .Lifa_emit
    test rax, rax
    jnz .Lifa_invoke_failed
    jmp .Lifa_invoke_loop
.Lifa_invoke_growth:
    mov rax, [rbp+16]
    or rax, [rbp+24]
    or rax, [rbp+40]
    or rax, [rbp+48]
    or rax, [rbp+56]
    jnz .Lifa_invoke_failed
    mov r13, [rbp+32]
    cmp rbx, 4
    jne .Lifa_invoke_output_growth
    cmp r13, [r12+96]
    jbe .Lifa_invoke_failed
    cmp r13, I_MAX_WORK
    ja .Lifa_invoke_failed
    mov edx, 3
    mov rcx, [r12+88]
    mov r8, [r12+96]
    call .Lifa_emit
    test rax, rax
    jnz .Lifa_invoke_failed
    lea rdi, [r12+88]
    mov rsi, r13
    call .Lifa_grow
    test eax, eax
    jnz .Lifa_invoke_resource
    mov edx, 4
    mov rcx, [r12+88]
    mov r8, [r12+96]
    call .Lifa_emit
    test rax, rax
    jnz .Lifa_invoke_failed
    jmp .Lifa_invoke_loop
.Lifa_invoke_output_growth:
    cmp r13, [r12+112]
    jbe .Lifa_invoke_failed
    cmp r13, I_MAX_OUT
    ja .Lifa_invoke_failed
    lea rdi, [r12+104]
    mov rsi, r13
    call .Lifa_grow
    test eax, eax
    jnz .Lifa_invoke_resource
    jmp .Lifa_invoke_loop
.Lifa_invoke_final:
    cmp qword ptr [r12+184], 0
    jne .Lifa_invoke_failed
    mov rax, [r12+360]
    or rax, [r12+368]
    jnz .Lifa_invoke_failed
    mov rax, [rbp+24]
    or rax, [rbp+32]
    or rax, [rbp+40]
    or rax, [rbp+48]
    jnz .Lifa_invoke_failed
    cmp qword ptr [rbp+8], 3
    jne .Lifa_invoke_borrow
    cmp qword ptr [rbp+56], 64
    jb .Lifa_invoke_failed
    mov rax, 0x3130305344524248
    cmp [rbp+64], rax
    je .Lifa_invoke_error_magic
    mov rax, 0x3130305253444d48
    cmp [rbp+64], rax
    jne .Lifa_invoke_failed
.Lifa_invoke_error_magic:
    cmp qword ptr [rbp+72], 3
    jne .Lifa_invoke_failed
    mov rax, [rbp+56]
    sub rax, 64
    cmp [rbp+120], rax
    jne .Lifa_invoke_failed
.Lifa_invoke_borrow:
    mov qword ptr [r12+344], 0
    mov qword ptr [r12+352], 0
    mov rax, [rbp+56]
    add rax, 64
    mov [r12+168], rax
    mov qword ptr [r12+56], 2
    mov eax, 64
    jmp .Lifa_invoke_return
.Lifa_invoke_resource:
    mov eax, I_RESOURCE
    jmp .Lifa_invoke_record_failure
.Lifa_invoke_failed:
    mov eax, I_INVALID
.Lifa_invoke_record_failure:
    mov [r12+176], rax
    /* A private allocation/observer failure cannot leave a child output loan.
     * Child failures retain their own operable ledger until context teardown. */
    mov rdi, [r12+384]
    cmp qword ptr [rdi+56], 2
    jne .Lifa_failure_metadata
    call binary_read_body_release
.Lifa_failure_metadata:
    mov rdi, [r12+392]
    cmp qword ptr [rdi+56], 2
    jne .Lifa_failure_recorded
    call file_metadata_release
.Lifa_failure_recorded:
    mov qword ptr [r12+344], 0
    mov qword ptr [r12+352], 0
    mov qword ptr [r12+360], 0
    mov qword ptr [r12+368], 0
    mov qword ptr [r12+56], 3
    mov qword ptr [r12+168], 0
    mov rax, [r12+176]
    jmp .Lifa_invoke_return
.Lifa_invoke_busy:
    mov eax, I_BUSY
    jmp .Lifa_invoke_return
.Lifa_invoke_reject:
    mov eax, I_INVALID
.Lifa_invoke_return:
    I_LEAVE

/* Copy the complete actual child output before releasing its borrow.
 * r12 is the caller context; rdi child context; rsi fixed child type 1 or 3.
 * No output bytes are synthesized here. Every child has its own full journal. */
.Lifa_copy_nested:
    I_ENTER
    mov r14, rdi
    mov r15, rsi
    cmp qword ptr [r14+56], 2
    jne .Lifa_copy_bad
    mov r13, [r14+168]
    cmp r13, 64
    jb .Lifa_copy_bad
    cmp r13, I_MAX_OUT
    ja .Lifa_copy_bad
    mov rax, [r14+104]
    test rax, rax
    jz .Lifa_copy_bad
    cmp r13, [r14+112]
    ja .Lifa_copy_bad
    mov rbx, [rax+56]
    add rbx, 64
    jc .Lifa_copy_bad
    cmp r13, rbx
    jne .Lifa_copy_bad
    lea rdi, [r12+120]
    lea rsi, [r13+96]
    call .Lifa_grow
    test eax, eax
    jnz .Lifa_copy_resource
    mov edx, 6
    mov rcx, [r14+104]
    mov r8, r13
    call .Lifa_emit
    test rax, rax
    jnz .Lifa_copy_bad
    mov edx, 15
    mov rcx, r14
    mov r8d, 4096
    call .Lifa_emit
    test rax, rax
    jnz .Lifa_copy_bad
    mov rdi, [r12+120]
    add rdi, 96
    mov rsi, [r14+104]
    mov rcx, r13
    rep movsb
    mov [r12+232], r13
    mov [r12+240], r13
    mov rdi, r14
    cmp r15, 1
    je .Lifa_copy_release_read
    cmp r15, 3
    jne .Lifa_copy_bad
    call file_metadata_release
    jmp .Lifa_copy_released
.Lifa_copy_release_read:
    call binary_read_body_release
.Lifa_copy_released:
    test rax, rax
    jnz .Lifa_copy_bad
    mov qword ptr [r12+360], 0
    mov qword ptr [r12+368], 0
    xor eax, eax
    jmp .Lifa_copy_done
.Lifa_copy_resource:
    mov eax, I_RESOURCE
    jmp .Lifa_copy_done
.Lifa_copy_bad:
    mov eax, I_INVALID
.Lifa_copy_done:
    I_LEAVE

/* Only these two direct HIA entries are supplied by the actual image packer.
 * Fingerprint and metadata opaque callables are statically linked above. */
.balign 16
.global file_info_at_body_call_displacement
.Lifa_body:
    .byte 0xe9
file_info_at_body_call_displacement:
    .long 0
.global file_info_at_stat_call_displacement
.Lifa_stat:
    .byte 0xe9
file_info_at_stat_call_displacement:
    .long 0

.section .note.GNU-stack,"",@progbits
