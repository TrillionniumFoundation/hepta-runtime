/* Copyright 2026 Muvon Un Limited
 * SPDX-License-Identifier: Apache-2.0
 * Process-lifetime entropy capability. All random/cache/UUID policy is HIA.
 * Immutable image entries and the journal callback are trusted graph bindings.
 */
.intel_syntax noprefix
.section .text
.macro E_ENTER
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp, 8
.endm
.macro E_LEAVE
    add rsp, 8
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret
.endm
.equ E_MAGIC, 0x31304943544e4548 /* HENTCI01 */
.equ E_INVALID, 0xffffffff
.equ E_BUSY, 0xfffffffd
.equ E_RESOURCE, 0xfffffffc
.equ E_MAX_WORK, 1048576
.equ E_MAX_OUT, 4096
.equ E_MAX_INPUT, 96
.equ E_REPLY_CAP, 4096

/* rdi nonzero page-aligned capacity; return a zeroed RW arena plus an inaccessible
 * final guard page. No input bytes select a mapping or a code entry. */
.Lentropy_map:
    test rdi, rdi
    jz .Lentropy_map_bad
    test rdi, 4095
    jnz .Lentropy_map_bad
    cmp rdi, E_MAX_WORK
    ja .Lentropy_map_bad
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
    jae .Lentropy_map_done
    push rax
    lea rdi, [rax+rbx]
    mov esi, 4096
    xor edx, edx
    mov eax, 10
    syscall
    test rax, rax
    jnz .Lentropy_map_guard_failed
    pop rax
    jmp .Lentropy_map_done
.Lentropy_map_guard_failed:
    pop rdi
    lea rsi, [rbx+4096]
    mov eax, 11
    syscall
    mov rax, -12
.Lentropy_map_done:
    pop rbx
    ret
.Lentropy_map_bad:
    mov rax, -22
    ret

/* Grow a pointer/capacity pair in a private context. rdi points to the pair,
 * rsi is the required extent. Every old byte is copied, the extension is zero.
 * The old mapping is retired only after allocation and copy are complete. */
.Lentropy_grow:
    E_ENTER
    mov r12, rdi
    mov r13, rsi
    test r13, r13
    jz .Lentropy_grow_bad
    cmp r13, E_MAX_WORK
    ja .Lentropy_grow_bad
    add r13, 4095
    jc .Lentropy_grow_bad
    and r13, -4096
    cmp r13, [r12+8]
    jbe .Lentropy_grow_ok
    mov rdi, r13
    call .Lentropy_map
    cmp rax, -4095
    jae .Lentropy_grow_resource
    mov r14, rax
    mov rdi, rax
    mov rsi, [r12]
    mov rcx, [r12+8]
    test rcx, rcx
    jz .Lentropy_grow_install
    test rsi, rsi
    jz .Lentropy_grow_new_failed
    rep movsb
    mov rdi, [r12]
    mov rsi, [r12+8]
    add rsi, 4096
    mov eax, 11
    syscall
    test rax, rax
    jnz .Lentropy_grow_new_failed
.Lentropy_grow_install:
    mov [r12], r14
    mov [r12+8], r13
.Lentropy_grow_ok:
    xor eax, eax
    jmp .Lentropy_grow_done
.Lentropy_grow_new_failed:
    mov rdi, r14
    lea rsi, [r13+4096]
    mov eax, 11
    syscall
.Lentropy_grow_resource:
    mov eax, E_RESOURCE
    jmp .Lentropy_grow_done
.Lentropy_grow_bad:
    mov eax, E_INVALID
.Lentropy_grow_done:
    E_LEAVE


/* Fixed process graph: callback, callback context, shared orphan pool.
 * The returned context and its cache stay alive until process exit. */
.global binary_entropy_create
binary_entropy_create:
    E_ENTER
    mov r13, rdi
    mov r14, rsi
    mov r15, rdx
    test r15, r15
    jz .Lentropy_create_bad
    test r15, 4095
    jnz .Lentropy_create_bad
    movabs rax, 0x31303050524f5048
    cmp [r15], rax
    jne .Lentropy_create_bad
    cmp qword ptr [r15+8], 4096
    jne .Lentropy_create_bad
    mov eax, 39
    syscall
    cmp [r15+16], rax
    jne .Lentropy_create_bad
    mov edi, 4096
    call .Lentropy_map
    cmp rax, -4095
    jae .Lentropy_create_return
    mov r12, rax
    mov rax, E_MAGIC
    mov [r12], rax
    mov qword ptr [r12+8], 4096
    lea rax, [rip+.Lentropy_body]
    mov [r12+16], rax
    mov [r12+40], r13
    mov [r12+48], r14
    mov [r12+376], r15
    mov rax, [r15+16]
    mov [r12+384], rax
    lea rdi, [r12+256]
    mov rax, -1
    mov ecx, 8
    rep stosq
    lea rdi, [r12+64]
    mov esi, 4096
    call .Lentropy_grow
    test eax, eax
    jnz .Lentropy_create_fail
    lea rdi, [r12+88]
    mov esi, 4096
    call .Lentropy_grow
    test eax, eax
    jnz .Lentropy_create_fail
    lea rdi, [r12+104]
    mov esi, 4096
    call .Lentropy_grow
    test eax, eax
    jnz .Lentropy_create_fail
    lea rdi, [r12+120]
    mov esi, E_REPLY_CAP
    call .Lentropy_grow
    test eax, eax
    jnz .Lentropy_create_fail
    mov rax, r12
    jmp .Lentropy_create_return
.Lentropy_create_bad:
    mov rax, -22
    jmp .Lentropy_create_return
.Lentropy_create_fail:
    /* No syscall capability has been exposed at this point. */
    lea r13, [rip+.Lentropy_pairs]
    mov ebx, 4
.Lentropy_create_unmap:
    mov r14, [r13]
    mov rdi, [r12+r14]
    test rdi, rdi
    jz .Lentropy_create_next
    mov rsi, [r12+r14+8]
    add rsi, 4096
    mov eax, 11
    syscall
.Lentropy_create_next:
    add r13, 8
    dec ebx
    jnz .Lentropy_create_unmap
    mov rdi, r12
    mov esi, 8192
    mov eax, 11
    syscall
    mov rax, -12
.Lentropy_create_return:
    E_LEAVE
.balign 8
.Lentropy_pairs:
    .quad 64,88,104,120

/* Full input/output/workspace observations are never substitute results. */
.Lentropy_emit:
    E_ENTER
    mov rbx, [r12+40]
    test rbx, rbx
    jz .Lentropy_emit_ok
    mov rdi, [r12+48]
    mov rsi, r12
    call rbx
    jmp .Lentropy_emit_return
.Lentropy_emit_ok:
    xor eax, eax
.Lentropy_emit_return:
    E_LEAVE

/* The single live descriptor, if any, is exactly the HIA-declared cache.
 * There is no public reset or destroy; a release retires only an output loan. */
.Lentropy_cache_check:
    mov rdx, [r12+88]
    test rdx, rdx
    jz .Lentropy_cache_bad
    movabs rax, 0x31303057544e4548 /* HENTW001 */
    cmp [rdx], rax
    jne .Lentropy_cache_fresh
    cmp qword ptr [rdx+8], 99
    jne .Lentropy_cache_bad
    cmp qword ptr [rdx+96], -1
    jne .Lentropy_cache_bad
    mov rdi, [rdx+72]
    jmp .Lentropy_cache_slots
.Lentropy_cache_fresh:
    cmp qword ptr [r12+192], 0
    jne .Lentropy_cache_bad
    cmp qword ptr [rdx], 0
    jne .Lentropy_cache_bad
    mov rdi, -1
.Lentropy_cache_slots:
    xor ecx, ecx
    xor r8d, r8d
.Lentropy_cache_loop:
    mov rax, [r12+256+rcx*8]
    cmp rax, -1
    je .Lentropy_cache_next
    cmp rax, 2147483647
    ja .Lentropy_cache_bad
    cmp rax, rdi
    jne .Lentropy_cache_bad
    inc r8d
.Lentropy_cache_next:
    inc ecx
    cmp ecx, 8
    jb .Lentropy_cache_loop
    cmp r8, [r12+184]
    jne .Lentropy_cache_bad
    cmp rdi, -1
    je .Lentropy_cache_empty
    cmp r8, 1
    jne .Lentropy_cache_bad
    xor eax, eax
    ret
.Lentropy_cache_empty:
    test r8, r8
    jnz .Lentropy_cache_bad
    xor eax, eax
    ret
.Lentropy_cache_bad:
    mov eax, E_INVALID
    ret

.global binary_entropy_release
binary_entropy_release:
    E_ENTER
    mov r12, rdi
    mov rax, E_MAGIC
    cmp [r12], rax
    jne .Lentropy_release_bad
    cmp qword ptr [r12+8], 4096
    jne .Lentropy_release_bad
    mov eax, 39
    syscall
    cmp [r12+384], rax
    jne .Lentropy_release_bad
    cmp qword ptr [r12+56], 2
    jne .Lentropy_release_bad
    call .Lentropy_cache_check
    test eax, eax
    jnz .Lentropy_release_bad
    mov qword ptr [r12+168], 0
    mov qword ptr [r12+176], 0
    mov qword ptr [r12+56], 0
    xor eax, eax
    jmp .Lentropy_release_return
.Lentropy_release_bad:
    mov eax, E_INVALID
.Lentropy_release_return:
    E_LEAVE

.Lentropy_fd_find:
    cmp rdi, 2147483647
    ja .Lentropy_fd_find_bad
    cmp qword ptr [r12+184], 0
    je .Lentropy_fd_find_bad
    xor eax, eax
.Lentropy_fd_find_loop:
    cmp [r12+256+rax*8], rdi
    je .Lentropy_fd_find_return
    inc eax
    cmp eax, 8
    jb .Lentropy_fd_find_loop
.Lentropy_fd_find_bad:
    mov rax, -1
.Lentropy_fd_find_return:
    ret

/* Six fixed syscalls; there are no retries or cache-policy decisions here. */
.Lentropy_capability:
    E_ENTER
    mov qword ptr [r12+232], 0
    mov qword ptr [r12+240], 0
    cmp qword ptr [rbp+56], 0
    jne .Lentropy_cap_bad
    cmp qword ptr [rbp+48], 0
    jne .Lentropy_cap_bad
    mov rbx, [rbp+24]
    cmp rbx, 1
    je .Lentropy_cap_random
    cmp rbx, 2
    je .Lentropy_cap_open
    cmp rbx, 3
    jb .Lentropy_cap_bad
    cmp rbx, 6
    ja .Lentropy_cap_bad
    mov rdi, [rbp+32]
    call .Lentropy_fd_find
    cmp rax, -1
    je .Lentropy_cap_bad
    mov r15, rax
    cmp rbx, 5
    je .Lentropy_cap_read
    cmp qword ptr [rbp+40], 0
    jne .Lentropy_cap_bad
    cmp rbx, 3
    je .Lentropy_cap_stat
    cmp rbx, 4
    je .Lentropy_cap_close
    mov rax, [r12+88]
    mov rdx, [rbp+32]
    cmp [rax+72], rdx
    jne .Lentropy_cap_bad
    cmp qword ptr [r12+400], -1
    je .Lentropy_cap_resource
    mov rdi, [r12+376]
    mov rsi, [rbp+32]
    mov rdx, r12
    mov rcx, [r12+192]
    call hia_process_orphans_append
    test rax, rax
    jnz .Lentropy_cap_resource
    mov qword ptr [r12+256+r15*8], -1
    dec qword ptr [r12+184]
    inc qword ptr [r12+400]
    jmp .Lentropy_cap_ok
.Lentropy_cap_random:
    cmp qword ptr [rbp+40], 0
    jne .Lentropy_cap_bad
    mov rsi, [rbp+32]
    test rsi, rsi
    jz .Lentropy_cap_bad
    cmp rsi, 16
    ja .Lentropy_cap_bad
    mov rdi, [r12+120]
    add rdi, 96
    xor edx, edx
    mov eax, 318
    syscall
    mov [r12+232], rax
    cmp rax, -4095
    jae .Lentropy_cap_ok
    cmp rax, [rbp+32]
    ja .Lentropy_cap_bad
    mov [r12+240], rax
    jmp .Lentropy_cap_ok
.Lentropy_cap_open:
    mov rax, [rbp+32]
    or rax, [rbp+40]
    jnz .Lentropy_cap_bad
    cmp qword ptr [r12+184], 8
    jae .Lentropy_cap_bad
    xor r15d, r15d
.Lentropy_cap_free_slot:
    cmp qword ptr [r12+256+r15*8], -1
    je .Lentropy_cap_open_slot
    inc r15d
    cmp r15d, 8
    jb .Lentropy_cap_free_slot
    jmp .Lentropy_cap_bad
.Lentropy_cap_open_slot:
    mov rdi, -100
    lea rsi, [rip+.Lentropy_device]
    mov edx, 524288
    xor r10d, r10d
    mov eax, 257
    syscall
    mov [r12+232], rax
    cmp rax, -4095
    jae .Lentropy_cap_ok
    cmp rax, 2147483647
    ja .Lentropy_cap_bad
    mov [r12+256+r15*8], rax
    inc qword ptr [r12+184]
    jmp .Lentropy_cap_ok
.Lentropy_cap_stat:
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
    jnz .Lentropy_cap_ok
    mov qword ptr [r12+240], 144
    jmp .Lentropy_cap_ok
.Lentropy_cap_close:
    mov rax, [r12+88]
    mov rdi, [rbp+32]
    cmp [rax+96], rdi
    jne .Lentropy_cap_bad
    cmp [rax+72], rdi
    je .Lentropy_cap_bad
    mov eax, 3
    syscall
    mov [r12+232], rax
    mov qword ptr [r12+256+r15*8], -1
    dec qword ptr [r12+184]
    jmp .Lentropy_cap_ok
.Lentropy_cap_read:
    mov rax, [r12+88]
    mov rdi, [rbp+32]
    cmp [rax+72], rdi
    jne .Lentropy_cap_bad
    mov rdx, [rbp+40]
    test rdx, rdx
    jz .Lentropy_cap_bad
    cmp rdx, 16
    ja .Lentropy_cap_bad
    mov rsi, [r12+120]
    add rsi, 96
    xor eax, eax
    syscall
    mov [r12+232], rax
    cmp rax, -4095
    jae .Lentropy_cap_ok
    cmp rax, [rbp+40]
    ja .Lentropy_cap_bad
    mov [r12+240], rax
.Lentropy_cap_ok:
    xor eax, eax
    jmp .Lentropy_cap_done
.Lentropy_cap_resource:
    mov eax, E_RESOURCE
    jmp .Lentropy_cap_done
.Lentropy_cap_bad:
    mov eax, E_INVALID
.Lentropy_cap_done:
    E_LEAVE
.Lentropy_device:
    .asciz "/dev/urandom"

/* invoke(context, immutable 96-byte start packet, length).
 * Admission never reads a descriptor or native entry from the packet. */
.global binary_entropy_invoke
binary_entropy_invoke:
    E_ENTER
    mov r12, rdi
    mov r13, rsi
    mov r14, rdx
    mov rax, E_MAGIC
    cmp [r12], rax
    jne .Lentropy_invoke_reject
    cmp qword ptr [r12+8], 4096
    jne .Lentropy_invoke_reject
    mov eax, 39
    syscall
    cmp [r12+384], rax
    jne .Lentropy_invoke_reject
    cmp r14, 96
    jne .Lentropy_invoke_reject
    test r13, r13
    jz .Lentropy_invoke_reject
    movabs rax, 0x31303051544e4548 /* HENTQ001 */
    cmp [r13], rax
    jne .Lentropy_invoke_reject
    cmp qword ptr [r13+8], 1
    jne .Lentropy_invoke_reject
    mov rax, [r13+24]
    cmp rax, 1
    jb .Lentropy_invoke_reject
    cmp rax, 2
    ja .Lentropy_invoke_reject
    mov rax, [r13+16]
    or rax, [r13+32]
    or rax, [r13+40]
    or rax, [r13+48]
    or rax, [r13+56]
    or rax, [r13+64]
    or rax, [r13+72]
    or rax, [r13+80]
    or rax, [r13+88]
    jnz .Lentropy_invoke_reject
    cmp qword ptr [r12+192], -1
    je .Lentropy_invoke_reject
    xor eax, eax
    mov edx, 1
    lock cmpxchg [r12+56], rdx
    jnz .Lentropy_invoke_busy
    call .Lentropy_cache_check
    test eax, eax
    jnz .Lentropy_invoke_unadmit
    mov rdi, [r12+64]
    test rdi, rdi
    jz .Lentropy_invoke_unadmit
    cmp qword ptr [r12+72], 96
    jb .Lentropy_invoke_unadmit
    mov rsi, r13
    mov ecx, 96
    rep movsb
    mov qword ptr [r12+80], 96
    mov rax, [r12+64]
    mov [r12+200], rax
    mov qword ptr [r12+208], 96
    inc qword ptr [r12+192]
    mov qword ptr [r12+248], 0
    mov qword ptr [r12+168], 0
    mov qword ptr [r12+176], 0
    jmp .Lentropy_invoke_loop
.Lentropy_invoke_unadmit:
    mov qword ptr [r12+56], 0
    jmp .Lentropy_invoke_reject

.Lentropy_invoke_loop:
    inc qword ptr [r12+248]
    jz .Lentropy_invoke_failed
    mov rdi, [r12+104]
    mov rcx, [r12+112]
    shr rcx, 3
    mov rax, 0xa5a5a5a5a5a5a5a5
    rep stosq
    mov edx, 1
    mov rcx, [r12+200]
    mov r8, [r12+208]
    call .Lentropy_emit
    test rax, rax
    jnz .Lentropy_invoke_failed
    mov edx, 10
    mov rcx, [r12+88]
    mov r8, [r12+96]
    call .Lentropy_emit
    test rax, rax
    jnz .Lentropy_invoke_failed
    mov edx, 12
    mov rcx, [r12+104]
    mov r8, [r12+112]
    call .Lentropy_emit
    test rax, rax
    jnz .Lentropy_invoke_failed
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
    call .Lentropy_emit
    test rax, rax
    jnz .Lentropy_invoke_failed
    mov edx, 11
    mov rcx, [r12+88]
    mov r8, [r12+96]
    call .Lentropy_emit
    test rax, rax
    jnz .Lentropy_invoke_failed
    cmp qword ptr [r12+176], 64
    jne .Lentropy_invoke_failed
    mov rbp, [r12+104]
    mov rax, 0x31303052544e4548
    cmp [rbp], rax
    jne .Lentropy_invoke_failed
    mov rax, [r12+112]
    sub rax, 64
    cmp [rbp+56], rax
    ja .Lentropy_invoke_failed
    mov rbx, [rbp+8]
    cmp rbx, 5
    ja .Lentropy_invoke_failed
    test rbx, rbx
    jz .Lentropy_invoke_final
    cmp rbx, 3
    je .Lentropy_invoke_final
    cmp rbx, 4
    jae .Lentropy_invoke_growth
    mov rax, [rbp+16]
    mov [r12+216], rax
    mov rax, [rbp+24]
    mov [r12+224], rax
    cmp rbx, 2
    je .Lentropy_invoke_failed
    mov edx, 8
    mov rcx, rbp
    mov r8, [rbp+56]
    add r8, 64
    call .Lentropy_emit
    test rax, rax
    jnz .Lentropy_invoke_failed
    call .Lentropy_capability
    cmp eax, E_RESOURCE
    je .Lentropy_invoke_resource
    test eax, eax
    jnz .Lentropy_invoke_failed
    jmp .Lentropy_invoke_reply
.Lentropy_invoke_reply:
    mov rbx, [r12+120]
    mov rax, 0x31303051544e4548
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
    ja .Lentropy_invoke_failed
    mov [rbx+88], rax
    add rax, 96
    cmp rax, [r12+128]
    ja .Lentropy_invoke_failed
    mov [r12+200], rbx
    mov [r12+208], rax
    mov edx, 9
    mov rcx, rbx
    mov r8, rax
    call .Lentropy_emit
    test rax, rax
    jnz .Lentropy_invoke_failed
    jmp .Lentropy_invoke_loop
.Lentropy_invoke_growth:
    mov rax, [rbp+16]
    or rax, [rbp+24]
    or rax, [rbp+40]
    or rax, [rbp+48]
    or rax, [rbp+56]
    jnz .Lentropy_invoke_failed
    mov r13, [rbp+32]
    cmp rbx, 4
    jne .Lentropy_invoke_output_growth
    cmp r13, [r12+96]
    jbe .Lentropy_invoke_failed
    cmp r13, E_MAX_WORK
    ja .Lentropy_invoke_failed
    mov edx, 3
    mov rcx, [r12+88]
    mov r8, [r12+96]
    call .Lentropy_emit
    test rax, rax
    jnz .Lentropy_invoke_failed
    lea rdi, [r12+88]
    mov rsi, r13
    call .Lentropy_grow
    test eax, eax
    jnz .Lentropy_invoke_resource
    mov edx, 4
    mov rcx, [r12+88]
    mov r8, [r12+96]
    call .Lentropy_emit
    test rax, rax
    jnz .Lentropy_invoke_failed
    jmp .Lentropy_invoke_loop
.Lentropy_invoke_output_growth:
    cmp r13, [r12+112]
    jbe .Lentropy_invoke_failed
    cmp r13, E_MAX_OUT
    ja .Lentropy_invoke_failed
    lea rdi, [r12+104]
    mov rsi, r13
    call .Lentropy_grow
    test eax, eax
    jnz .Lentropy_invoke_resource
    jmp .Lentropy_invoke_loop

.Lentropy_invoke_final:
    call .Lentropy_cache_check
    test eax, eax
    jnz .Lentropy_invoke_failed
    mov rax, [rbp+24]
    or rax, [rbp+32]
    or rax, [rbp+40]
    or rax, [rbp+48]
    jnz .Lentropy_invoke_failed
    cmp qword ptr [rbp+8], 3
    je .Lentropy_invoke_error
    mov rax, [r12+64]
    cmp qword ptr [rax+24], 1
    jne .Lentropy_invoke_uuid
    cmp qword ptr [rbp+56], 16
    jne .Lentropy_invoke_failed
    jmp .Lentropy_invoke_borrow
.Lentropy_invoke_uuid:
    cmp qword ptr [rbp+56], 32
    jne .Lentropy_invoke_failed
    jmp .Lentropy_invoke_borrow
.Lentropy_invoke_error:
    cmp qword ptr [rbp+56], 64
    jb .Lentropy_invoke_failed
    movabs rax, 0x3130305344524248 /* HBRDS001 */
    cmp [rbp+64], rax
    jne .Lentropy_invoke_failed
    cmp qword ptr [rbp+72], 3
    jne .Lentropy_invoke_failed
    mov rax, [rbp+56]
    sub rax, 64
    cmp [rbp+120], rax
    jne .Lentropy_invoke_failed
.Lentropy_invoke_borrow:
    mov rax, [rbp+56]
    add rax, 64
    mov [r12+168], rax
    mov qword ptr [r12+56], 2
    mov eax, 64
    jmp .Lentropy_invoke_return
.Lentropy_invoke_resource:
    mov eax, E_RESOURCE
    jmp .Lentropy_invoke_record_failure
.Lentropy_invoke_failed:
    mov eax, E_INVALID
.Lentropy_invoke_record_failure:
    /* Preserve every cache/candidate FD and all unfinished state. The graph
     * must never replay an application of unknown completion. */
    mov [r12+176], rax
    mov qword ptr [r12+56], 3
    mov qword ptr [r12+168], 0
    jmp .Lentropy_invoke_return
.Lentropy_invoke_busy:
    mov eax, E_BUSY
    jmp .Lentropy_invoke_return
.Lentropy_invoke_reject:
    mov eax, E_INVALID
.Lentropy_invoke_return:
    E_LEAVE

.balign 16
.global binary_entropy_body_call_displacement
.Lentropy_body:
    .byte 0xe9
binary_entropy_body_call_displacement:
    .long 0
.section .note.GNU-stack,"",@progbits
