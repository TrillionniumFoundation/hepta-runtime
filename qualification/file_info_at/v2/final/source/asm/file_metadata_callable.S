/* Copyright 2026 Muvon Un Limited
 * SPDX-License-Identifier: Apache-2.0
 * Fixed borrowed-file metadata capability. All metadata policy is HIA.
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
.equ M_MAGIC, 0x3130494354444d48 /* HMDTCI01 */
.equ M_INVALID, 0xffffffff
.equ M_BUSY, 0xfffffffd
.equ M_RESOURCE, 0xfffffffc
.equ M_MAX_WORK, 268435456
.equ M_MAX_OUT, 134217728
.equ M_MAX_INPUT, 134217728
.equ M_REPLY_CAP, 69632
.equ M_CHILD_OUT, 4096

/* rdi nonzero page-aligned capacity; return a zeroed RW arena plus an inaccessible
 * final guard page. No input bytes select a mapping or a code entry. */
.Lmdt_map:
    test rdi, rdi
    jz .Lmdt_map_bad
    test rdi, 4095
    jnz .Lmdt_map_bad
    cmp rdi, M_MAX_WORK
    ja .Lmdt_map_bad
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
    jae .Lmdt_map_done
    push rax
    lea rdi, [rax+rbx]
    mov esi, 4096
    xor edx, edx
    mov eax, 10
    syscall
    test rax, rax
    jnz .Lmdt_map_guard_failed
    pop rax
    jmp .Lmdt_map_done
.Lmdt_map_guard_failed:
    pop rdi
    lea rsi, [rbx+4096]
    mov eax, 11
    syscall
    mov rax, -12
.Lmdt_map_done:
    pop rbx
    ret
.Lmdt_map_bad:
    mov rax, -22
    ret

/* Grow a pointer/capacity pair in a private context. rdi points to the pair,
 * rsi is the required extent. Every old byte is copied, the extension is zero.
 * The old mapping is retired only after allocation and copy are complete. */
.Lmdt_grow:
    M_ENTER
    mov r12, rdi
    mov r13, rsi
    test r13, r13
    jz .Lmdt_grow_bad
    cmp r13, M_MAX_WORK
    ja .Lmdt_grow_bad
    add r13, 4095
    jc .Lmdt_grow_bad
    and r13, -4096
    cmp r13, [r12+8]
    jbe .Lmdt_grow_ok
    mov rdi, r13
    call .Lmdt_map
    cmp rax, -4095
    jae .Lmdt_grow_resource
    mov r14, rax
    mov rdi, rax
    mov rsi, [r12]
    mov rcx, [r12+8]
    test rcx, rcx
    jz .Lmdt_grow_install
    test rsi, rsi
    jz .Lmdt_grow_new_failed
    rep movsb
    mov rdi, [r12]
    mov rsi, [r12+8]
    add rsi, 4096
    mov eax, 11
    syscall
    test rax, rax
    jnz .Lmdt_grow_new_failed
.Lmdt_grow_install:
    mov [r12], r14
    mov [r12+8], r13
.Lmdt_grow_ok:
    xor eax, eax
    jmp .Lmdt_grow_done
.Lmdt_grow_new_failed:
    mov rdi, r14
    lea rsi, [r13+4096]
    mov eax, 11
    syscall
.Lmdt_grow_resource:
    mov eax, M_RESOURCE
    jmp .Lmdt_grow_done
.Lmdt_grow_bad:
    mov eax, M_INVALID
.Lmdt_grow_done:
    M_LEAVE

/* Trusted rdi callback or zero, rsi callback context. */
.global file_metadata_create
file_metadata_create:
    M_ENTER
    mov r13, rdi
    mov r14, rsi
    mov edi, 4096
    call .Lmdt_map
    cmp rax, -4095
    jae .Lmdt_create_return
    mov r12, rax
    mov rax, M_MAGIC
    mov [r12], rax
    mov qword ptr [r12+8], 4096
    lea rax, [rip+.Lmdt_body]
    mov [r12+16], rax
    lea rax, [rip+.Lmdt_codec]
    mov [r12+24], rax
    mov [r12+40], r13
    mov [r12+48], r14
    lea rdi, [r12+256]
    mov rax, -1
    mov ecx, 8
    rep stosq
    lea rdi, [r12+88]
    mov esi, 4096
    call .Lmdt_grow
    test eax, eax
    jnz .Lmdt_create_fail
    lea rdi, [r12+104]
    mov esi, 4096
    call .Lmdt_grow
    test eax, eax
    jnz .Lmdt_create_fail
    lea rdi, [r12+120]
    mov esi, M_REPLY_CAP
    call .Lmdt_grow
    test eax, eax
    jnz .Lmdt_create_fail
    mov edi, M_CHILD_OUT
    call .Lmdt_map
    cmp rax, -4095
    jae .Lmdt_create_fail
    mov [r12+136], rax
    mov edi, 4096
    call .Lmdt_map
    cmp rax, -4095
    jae .Lmdt_create_fail
    mov [r12+144], rax
    mov rax, r12
    jmp .Lmdt_create_return
.Lmdt_create_fail:
    mov rdi, r12
    call file_metadata_destroy
    mov rax, -12
.Lmdt_create_return:
    M_LEAVE

/* An optional journal only observes already owned byte spans. The callback
 * returns zero and cannot replace a syscall or HIA result. r12=context,
 * rdx=event, rcx=span, r8=length. */
.Lmdt_emit:
    M_ENTER
    mov rbx, [r12+40]
    test rbx, rbx
    jz .Lmdt_emit_ok
    mov rdi, [r12+48]
    mov rsi, r12
    call rbx
    jmp .Lmdt_emit_return
.Lmdt_emit_ok:
    xor eax, eax
.Lmdt_emit_return:
    M_LEAVE

/* The graph holds a final response borrow until this explicit release. */
.global file_metadata_release
file_metadata_release:
    mov rax, M_MAGIC
    cmp [rdi], rax
    jne .Lmdt_release_bad
    cmp qword ptr [rdi+8], 4096
    jne .Lmdt_release_bad
    cmp qword ptr [rdi+56], 2
    jne .Lmdt_release_bad
    cmp qword ptr [rdi+184], 0
    jne .Lmdt_release_bad
    mov qword ptr [rdi+56], 0
    mov qword ptr [rdi+168], 0
    mov qword ptr [rdi+176], 0
    xor eax, eax
    ret
.Lmdt_release_bad:
    mov eax, M_INVALID
    ret

/* Destruction refuses active or borrowed response contexts. File descriptors
 * are borrowed and are never duplicated, closed, reopened or retired here. */
.global file_metadata_destroy
file_metadata_destroy:
    M_ENTER
    mov r12, rdi
    mov rax, M_MAGIC
    cmp [r12], rax
    jne .Lmdt_destroy_bad
    cmp qword ptr [r12+8], 4096
    jne .Lmdt_destroy_bad
    mov rax, [r12+56]
    cmp rax, 1
    je .Lmdt_destroy_busy
    cmp rax, 2
    je .Lmdt_destroy_busy
    cmp rax, 3
    ja .Lmdt_destroy_bad
    /* All file capabilities are borrowed. Destruction never closes an FD. */
    mov qword ptr [r12+184], 0
    lea r13, [rip+.Lmdt_pairs]
    mov ebx, 4
.Lmdt_destroy_pair:
    mov r14, [r13]
    mov rdi, [r12+r14]
    test rdi, rdi
    jz .Lmdt_destroy_pair_next
    mov rsi, [r12+r14+8]
    add rsi, 4096
    mov eax, 11
    syscall
    test rax, rax
    jnz .Lmdt_destroy_resource
    mov qword ptr [r12+r14], 0
    mov qword ptr [r12+r14+8], 0
.Lmdt_destroy_pair_next:
    add r13, 8
    dec ebx
    jnz .Lmdt_destroy_pair
    mov ebx, 136
.Lmdt_destroy_child:
    mov rdi, [r12+rbx]
    test rdi, rdi
    jz .Lmdt_destroy_child_next
    mov esi, 8192
    cmp ebx, 136
    jne .Lmdt_destroy_child_extent
    mov esi, M_CHILD_OUT+4096
.Lmdt_destroy_child_extent:
    mov eax, 11
    syscall
    test rax, rax
    jnz .Lmdt_destroy_resource
    mov qword ptr [r12+rbx], 0
.Lmdt_destroy_child_next:
    add ebx, 8
    cmp ebx, 152
    jb .Lmdt_destroy_child
    mov rdi, r12
    mov esi, 8192
    mov eax, 11
    syscall
    jmp .Lmdt_destroy_return
.Lmdt_destroy_busy:
    mov eax, M_BUSY
    jmp .Lmdt_destroy_return
.Lmdt_destroy_resource:
    mov eax, M_RESOURCE
    jmp .Lmdt_destroy_return
.Lmdt_destroy_bad:
    mov eax, M_INVALID
.Lmdt_destroy_return:
    M_LEAVE
.balign 8
.Lmdt_pairs:
    .quad 64,88,104,120

/* Only these checked native effects are available to the fixed HIA body. */
.Lmdt_name:
    test rsi, rsi
    jz .Lmdt_name_bad
    mov rcx, rsi
    xor eax, eax
    repne scasb
    jne .Lmdt_name_bad
    test rcx, rcx
    jnz .Lmdt_name_bad
    xor eax, eax
    ret
.Lmdt_name_bad:
    mov eax, M_INVALID
    ret
.Lmdt_os:
    M_ENTER
    mov rbp, [r12+104]
    mov rbx, [rbp+24]
    mov qword ptr [r12+240], 0
    cmp qword ptr [r12+368], 1
    jne .Lmdt_os_bad
    cmp qword ptr [r12+360], 2
    je .Lmdt_os_bad
    mov rdi, [rbp+32]
    cmp rdi, [r12+344]
    je .Lmdt_os_read_admitted
    cmp qword ptr [r12+360], 3
    jne .Lmdt_os_bad
    cmp rdi, [r12+352]
    jne .Lmdt_os_bad
.Lmdt_os_read_admitted:
    cmp rbx, 1
    je .Lmdt_os_fstat
    cmp rbx, 2
    je .Lmdt_os_list
    cmp rbx, 3
    je .Lmdt_os_get
    cmp qword ptr [r12+360], 3
    jne .Lmdt_os_bad
    cmp rdi, [r12+352]
    jne .Lmdt_os_bad
    cmp rbx, 4
    je .Lmdt_os_chown
    cmp rbx, 5
    je .Lmdt_os_chmod
    cmp rbx, 6
    je .Lmdt_os_remove
    cmp rbx, 7
    je .Lmdt_os_set
    cmp rbx, 8
    je .Lmdt_os_fsync
    jmp .Lmdt_os_bad
.Lmdt_os_fstat:
    mov rax, [rbp+40]
    or rax, [rbp+48]
    or rax, [rbp+56]
    jnz .Lmdt_os_bad
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
    jnz .Lmdt_os_ok
    mov qword ptr [r12+240], 144
    jmp .Lmdt_os_ok
.Lmdt_os_list:
    mov rax, [rbp+48]
    or rax, [rbp+56]
    jnz .Lmdt_os_bad
    mov rdx, [rbp+40]
    test rdx, rdx
    jz .Lmdt_os_bad
    cmp rdx, 65536
    ja .Lmdt_os_bad
    mov rdi, [rbp+32]
    mov rsi, [r12+120]
    add rsi, 96
    mov eax, 196 /* flistxattr */
    syscall
    jmp .Lmdt_os_read_result
.Lmdt_os_get:
    cmp qword ptr [rbp+48], 0
    jne .Lmdt_os_bad
    mov rax, [rbp+40]
    test rax, rax
    jz .Lmdt_os_bad
    cmp rax, 65536
    ja .Lmdt_os_bad
    mov rsi, [rbp+56]
    cmp rsi, 65536
    ja .Lmdt_os_bad
    lea rdi, [rbp+64]
    call .Lmdt_name
    test eax, eax
    jnz .Lmdt_os_bad
    mov rdi, [rbp+32]
    lea rsi, [rbp+64]
    mov rdx, [r12+120]
    add rdx, 96
    mov r10, [rbp+40]
    mov eax, 193 /* fgetxattr */
    syscall
.Lmdt_os_read_result:
    mov [r12+232], rax
    cmp rax, -4095
    jae .Lmdt_os_ok
    cmp rax, [rbp+40]
    ja .Lmdt_os_bad
    mov [r12+240], rax
    jmp .Lmdt_os_ok
.Lmdt_os_chown:
    cmp qword ptr [rbp+56], 0
    jne .Lmdt_os_bad
    mov rax, [rbp+40]
    or rax, [rbp+48]
    shr rax, 32
    jnz .Lmdt_os_bad
    mov rdi, [rbp+32]
    mov rsi, [rbp+40]
    mov rdx, [rbp+48]
    mov eax, 93 /* fchown */
    syscall
    jmp .Lmdt_os_result
.Lmdt_os_chmod:
    mov rax, [rbp+48]
    or rax, [rbp+56]
    jnz .Lmdt_os_bad
    cmp qword ptr [rbp+40], 4095
    ja .Lmdt_os_bad
    mov rdi, [rbp+32]
    mov rsi, [rbp+40]
    mov eax, 91 /* fchmod */
    syscall
    jmp .Lmdt_os_result
.Lmdt_os_remove:
    mov rax, [rbp+40]
    or rax, [rbp+48]
    jnz .Lmdt_os_bad
    mov rsi, [rbp+56]
    cmp rsi, 65536
    ja .Lmdt_os_bad
    lea rdi, [rbp+64]
    call .Lmdt_name
    test eax, eax
    jnz .Lmdt_os_bad
    mov rdi, [rbp+32]
    lea rsi, [rbp+64]
    mov eax, 199 /* fremovexattr */
    syscall
    jmp .Lmdt_os_result
.Lmdt_os_set:
    mov rsi, [rbp+40]
    cmp rsi, 65535
    ja .Lmdt_os_bad
    cmp qword ptr [rbp+48], 65536
    ja .Lmdt_os_bad
    inc rsi
    mov rax, rsi
    add rax, [rbp+48]
    cmp rax, [rbp+56]
    jne .Lmdt_os_bad
    lea rdi, [rbp+64]
    call .Lmdt_name
    test eax, eax
    jnz .Lmdt_os_bad
    mov rdi, [rbp+32]
    lea rsi, [rbp+64]
    mov rdx, [rbp+40]
    lea rdx, [rsi+rdx+1]
    mov r10, [rbp+48]
    xor r8d, r8d
    mov eax, 190 /* fsetxattr */
    syscall
    jmp .Lmdt_os_result
.Lmdt_os_fsync:
    mov rax, [rbp+40]
    or rax, [rbp+48]
    or rax, [rbp+56]
    jnz .Lmdt_os_bad
    mov rdi, [rbp+32]
    mov eax, 74 /* fsync */
    syscall
.Lmdt_os_result:
    mov [r12+232], rax
.Lmdt_os_ok:
    xor eax, eax
    jmp .Lmdt_os_done
.Lmdt_os_bad:
    mov eax, M_INVALID
.Lmdt_os_done:
    M_LEAVE

/* Trusted graph entry: rdi context, rsi borrowed source FD,
 * rdx borrowed target FD, rcx complete immutable HMDTQ001 packet, r8 length.
 * Both packet FD words must be zero. This entry injects only bound registers. */
.global file_metadata_invoke
file_metadata_invoke:
    M_ENTER
    mov r12, rdi
    mov r15, rsi
    mov rbp, rdx
    mov r13, rcx
    mov r14, r8
    cmp r15, 2147483647
    ja .Lmdt_invoke_reject
    cmp rbp, 2147483647
    ja .Lmdt_invoke_reject
    mov rax, M_MAGIC
    cmp [r12], rax
    jne .Lmdt_invoke_reject
    cmp qword ptr [r12+8], 4096
    jne .Lmdt_invoke_reject
    cmp qword ptr [r12+56], 0
    jne .Lmdt_invoke_busy
    mov rax, [r12+184]
    or rax, [r12+344]
    or rax, [r12+352]
    or rax, [r12+360]
    or rax, [r12+368]
    jnz .Lmdt_invoke_reject
    cmp r14, 96
    jb .Lmdt_invoke_reject
    cmp r14, M_MAX_INPUT
    ja .Lmdt_invoke_reject
    test r13, r13
    jz .Lmdt_invoke_reject
    mov rax, 0x3130305154444d48 /* HMDTQ001 */
    cmp [r13], rax
    jne .Lmdt_invoke_reject
    cmp qword ptr [r13+8], 1
    jne .Lmdt_invoke_reject
    mov rax, [r13+16]
    or rax, [r13+32]
    or rax, [r13+40]
    jnz .Lmdt_invoke_reject
    mov rbx, [r13+24]
    cmp rbx, 1
    jb .Lmdt_invoke_reject
    cmp rbx, 3
    ja .Lmdt_invoke_reject
    cmp rbx, 3
    je .Lmdt_invoke_cap_ready
    test rbp, rbp
    jnz .Lmdt_invoke_reject
    cmp rbx, 1
    je .Lmdt_invoke_cap_ready
    test r15, r15
    jnz .Lmdt_invoke_reject
.Lmdt_invoke_cap_ready:
    cmp qword ptr [r12+192], -1
    je .Lmdt_invoke_reject
    lea rdi, [r12+64]
    mov rsi, r14
    call .Lmdt_grow
    test eax, eax
    jnz .Lmdt_invoke_return
    mov rdi, [r12+64]
    mov rsi, r13
    mov rcx, r14
    rep movsb
    mov rax, [r12+64]
    mov [rax+32], r15
    mov [rax+40], rbp
    mov [r12+344], r15
    mov [r12+352], rbp
    mov [r12+360], rbx
    mov qword ptr [r12+368], 1
    mov [r12+80], r14
    mov rax, [r12+64]
    mov [r12+200], rax
    mov [r12+208], r14
    inc qword ptr [r12+192]
    mov qword ptr [r12+248], 0
    mov qword ptr [r12+56], 1
    mov qword ptr [r12+168], 0
    mov qword ptr [r12+176], 0
.Lmdt_invoke_loop:
    inc qword ptr [r12+248]
    jz .Lmdt_invoke_failed
    mov rdi, [r12+104]
    mov rcx, [r12+112]
    shr rcx, 3
    mov rax, 0xa5a5a5a5a5a5a5a5
    rep stosq
    mov edx, 1
    mov rcx, [r12+200]
    mov r8, [r12+208]
    call .Lmdt_emit
    test rax, rax
    jnz .Lmdt_invoke_failed
    mov edx, 10
    mov rcx, [r12+88]
    mov r8, [r12+96]
    call .Lmdt_emit
    test rax, rax
    jnz .Lmdt_invoke_failed
    mov edx, 12
    mov rcx, [r12+104]
    mov r8, [r12+112]
    call .Lmdt_emit
    test rax, rax
    jnz .Lmdt_invoke_failed
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
    call .Lmdt_emit
    test rax, rax
    jnz .Lmdt_invoke_failed
    mov edx, 11
    mov rcx, [r12+88]
    mov r8, [r12+96]
    call .Lmdt_emit
    test rax, rax
    jnz .Lmdt_invoke_failed
    cmp qword ptr [r12+176], 64
    jne .Lmdt_invoke_failed
    mov rbp, [r12+104]
    mov rax, 0x3130305253444d48 /* HMDSR001 */
    cmp [rbp], rax
    jne .Lmdt_invoke_failed
    mov rax, [r12+112]
    sub rax, 64
    cmp [rbp+56], rax
    ja .Lmdt_invoke_failed
    mov rbx, [rbp+8]
    cmp rbx, 5
    ja .Lmdt_invoke_failed
    test rbx, rbx
    jz .Lmdt_invoke_final
    cmp rbx, 3
    je .Lmdt_invoke_final
    cmp rbx, 4
    jae .Lmdt_invoke_growth
    mov rax, [rbp+16]
    mov [r12+216], rax
    mov rax, [rbp+24]
    mov [r12+224], rax
    cmp rbx, 2
    je .Lmdt_invoke_codec
    mov edx, 8
    mov rcx, rbp
    mov r8, [rbp+56]
    add r8, 64
    call .Lmdt_emit
    test rax, rax
    jnz .Lmdt_invoke_failed
    call .Lmdt_os
    test eax, eax
    jnz .Lmdt_invoke_failed
    jmp .Lmdt_invoke_reply
.Lmdt_invoke_codec:
    mov rax, [rbp+32]
    or rax, [rbp+40]
    or rax, [rbp+48]
    jnz .Lmdt_invoke_failed
    cmp qword ptr [rbp+24], 1
    jne .Lmdt_invoke_failed
    mov rax, [r12+24]
    mov [r12+320], rax
    mov qword ptr [r12+328], 64
    mov qword ptr [r12+336], 1184
.Lmdt_child_start:
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
    call .Lmdt_emit
    test rax, rax
    jnz .Lmdt_invoke_failed
    mov edx, 13
    mov rcx, [r12+136]
    mov r8, [r12+328]
    call .Lmdt_emit
    test rax, rax
    jnz .Lmdt_invoke_failed
    mov edx, 14
    mov rcx, [r12+144]
    mov r8, [r12+336]
    call .Lmdt_emit
    test rax, rax
    jnz .Lmdt_invoke_failed
    lea rdi, [rbp+64]
    mov rsi, [rbp+56]
    mov rdx, [r12+136]
    mov rcx, [r12+328]
    mov r8, [r12+144]
    mov r9, [r12+336]
    call qword ptr [r12+320]
    mov [r12+232], rax
    cmp rax, [r12+328]
    ja .Lmdt_invoke_failed
    mov [r12+240], rax
    mov rdi, [r12+120]
    add rdi, 96
    mov rsi, [r12+136]
    mov rcx, rax
    rep movsb
    mov edx, 6
    mov rcx, [r12+136]
    mov r8, [r12+328]
    call .Lmdt_emit
    test rax, rax
    jnz .Lmdt_invoke_failed
    mov edx, 7
    mov rcx, [r12+144]
    mov r8, [r12+336]
    call .Lmdt_emit
    test rax, rax
    jnz .Lmdt_invoke_failed
.Lmdt_invoke_reply:
    mov rbx, [r12+120]
    mov rax, 0x3130305154444d48 /* HMDTQ001 */
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
    ja .Lmdt_invoke_failed
    mov [rbx+88], rax
    add rax, 96
    cmp rax, [r12+128]
    ja .Lmdt_invoke_failed
    mov [r12+200], rbx
    mov [r12+208], rax
    mov edx, 9
    mov rcx, rbx
    mov r8, rax
    call .Lmdt_emit
    test rax, rax
    jnz .Lmdt_invoke_failed
    jmp .Lmdt_invoke_loop
.Lmdt_invoke_growth:
    mov rax, [rbp+16]
    or rax, [rbp+24]
    or rax, [rbp+40]
    or rax, [rbp+48]
    or rax, [rbp+56]
    jnz .Lmdt_invoke_failed
    mov r13, [rbp+32]
    cmp rbx, 4
    jne .Lmdt_invoke_output_growth
    cmp r13, [r12+96]
    jbe .Lmdt_invoke_failed
    cmp r13, M_MAX_WORK
    ja .Lmdt_invoke_failed
    mov edx, 3
    mov rcx, [r12+88]
    mov r8, [r12+96]
    call .Lmdt_emit
    test rax, rax
    jnz .Lmdt_invoke_failed
    lea rdi, [r12+88]
    mov rsi, r13
    call .Lmdt_grow
    test eax, eax
    jnz .Lmdt_invoke_resource
    mov edx, 4
    mov rcx, [r12+88]
    mov r8, [r12+96]
    call .Lmdt_emit
    test rax, rax
    jnz .Lmdt_invoke_failed
    jmp .Lmdt_invoke_loop
.Lmdt_invoke_output_growth:
    cmp r13, [r12+112]
    jbe .Lmdt_invoke_failed
    cmp r13, M_MAX_OUT
    ja .Lmdt_invoke_failed
    lea rdi, [r12+104]
    mov rsi, r13
    call .Lmdt_grow
    test eax, eax
    jnz .Lmdt_invoke_resource
    jmp .Lmdt_invoke_loop
.Lmdt_invoke_final:
    cmp qword ptr [r12+184], 0
    jne .Lmdt_invoke_failed
    cmp qword ptr [rbp+8], 3
    je .Lmdt_invoke_error
    mov rax, [rbp+24]
    cmp rax, [r12+360]
    jne .Lmdt_invoke_failed
    mov rax, [rbp+32]
    or rax, [rbp+40]
    or rax, [rbp+48]
    jnz .Lmdt_invoke_failed
    jmp .Lmdt_invoke_borrow
.Lmdt_invoke_error:
    cmp qword ptr [rbp+24], 1
    jb .Lmdt_invoke_failed
    cmp qword ptr [rbp+24], 14
    ja .Lmdt_invoke_failed
    cmp qword ptr [rbp+32], 4095
    ja .Lmdt_invoke_failed
    mov rax, [rbp+40]
    cmp qword ptr [rbp+48], 0
    je .Lmdt_invoke_error_extent
    cmp qword ptr [rbp+48], 2
    jne .Lmdt_invoke_failed
    add rax, 8
    jc .Lmdt_invoke_failed
.Lmdt_invoke_error_extent:
    cmp rax, [rbp+56]
    jne .Lmdt_invoke_failed
.Lmdt_invoke_borrow:
    /* Source and target remain owned by the parent. No dup or close occurs. */
    mov qword ptr [r12+344], 0
    mov qword ptr [r12+352], 0
    mov qword ptr [r12+360], 0
    mov qword ptr [r12+368], 0
    mov rax, [rbp+56]
    add rax, 64
    mov [r12+168], rax
    mov qword ptr [r12+56], 2
    mov eax, 64
    jmp .Lmdt_invoke_return
.Lmdt_invoke_resource:
    mov eax, M_RESOURCE
    jmp .Lmdt_invoke_record_failure
.Lmdt_invoke_failed:
    mov eax, M_INVALID
.Lmdt_invoke_record_failure:
    mov qword ptr [r12+344], 0
    mov qword ptr [r12+352], 0
    mov qword ptr [r12+360], 0
    mov qword ptr [r12+368], 0
    mov [r12+176], rax
    mov qword ptr [r12+56], 3
    mov qword ptr [r12+168], 0
    jmp .Lmdt_invoke_return
.Lmdt_invoke_busy:
    mov eax, M_BUSY
    jmp .Lmdt_invoke_return
.Lmdt_invoke_reject:
    mov eax, M_INVALID
.Lmdt_invoke_return:
    M_LEAVE

/* Fixed image entries patched only by the actual HIA image packer. */
.balign 16
.global file_metadata_body_call_displacement
.Lmdt_body:
    .byte 0xe9
file_metadata_body_call_displacement:
    .long 0
.global file_metadata_codec_call_displacement
.Lmdt_codec:
    .byte 0xe9
file_metadata_codec_call_displacement:
    .long 0
