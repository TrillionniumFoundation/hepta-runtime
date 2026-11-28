/* Copyright 2026 Muvon Un Limited
 * SPDX-License-Identifier: Apache-2.0
 * Fixed held-parent directory capability. All path policy and close order are HIA.
 * Immutable image entries and the journal callback are trusted graph bindings.
 */
.intel_syntax noprefix
.section .text
.macro PD_ENTER
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp, 8
.endm
.macro PD_LEAVE
    add rsp, 8
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret
.endm
.equ PD_MAGIC, 0x3130494352445048
.equ PD_INVALID, 0xffffffff
.equ PD_BUSY, 0xfffffffd
.equ PD_RESOURCE, 0xfffffffc
.equ PD_MAX_WORK, 268435456
.equ PD_MAX_OUT, 134217728
.equ PD_MAX_INPUT, 134217728
.equ PD_REPLY_CAP, 4096

/* rdi nonzero page-aligned capacity; return a zeroed RW arena plus an inaccessible
 * final guard page. No input bytes select a mapping or a code entry. */
.Lprd_map:
    test rdi, rdi
    jz .Lprd_map_bad
    test rdi, 4095
    jnz .Lprd_map_bad
    cmp rdi, PD_MAX_WORK
    ja .Lprd_map_bad
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
    jae .Lprd_map_done
    push rax
    lea rdi, [rax+rbx]
    mov esi, 4096
    xor edx, edx
    mov eax, 10
    syscall
    test rax, rax
    jnz .Lprd_map_guard_failed
    pop rax
    jmp .Lprd_map_done
.Lprd_map_guard_failed:
    pop rdi
    lea rsi, [rbx+4096]
    mov eax, 11
    syscall
    mov rax, -12
.Lprd_map_done:
    pop rbx
    ret
.Lprd_map_bad:
    mov rax, -22
    ret

/* Grow a pointer/capacity pair in a private context. rdi points to the pair,
 * rsi is the required extent. Every old byte is copied, the extension is zero.
 * The old mapping is retired only after allocation and copy are complete. */
.Lprd_grow:
    PD_ENTER
    mov r12, rdi
    mov r13, rsi
    test r13, r13
    jz .Lprd_grow_bad
    cmp r13, PD_MAX_WORK
    ja .Lprd_grow_bad
    add r13, 4095
    jc .Lprd_grow_bad
    and r13, -4096
    cmp r13, [r12+8]
    jbe .Lprd_grow_ok
    mov rdi, r13
    call .Lprd_map
    cmp rax, -4095
    jae .Lprd_grow_resource
    mov r14, rax
    mov rdi, rax
    mov rsi, [r12]
    mov rcx, [r12+8]
    test rcx, rcx
    jz .Lprd_grow_install
    test rsi, rsi
    jz .Lprd_grow_new_failed
    rep movsb
    mov rdi, [r12]
    mov rsi, [r12+8]
    add rsi, 4096
    mov eax, 11
    syscall
    test rax, rax
    jnz .Lprd_grow_new_failed
.Lprd_grow_install:
    mov [r12], r14
    mov [r12+8], r13
.Lprd_grow_ok:
    xor eax, eax
    jmp .Lprd_grow_done
.Lprd_grow_new_failed:
    mov rdi, r14
    lea rsi, [r13+4096]
    mov eax, 11
    syscall
.Lprd_grow_resource:
    mov eax, PD_RESOURCE
    jmp .Lprd_grow_done
.Lprd_grow_bad:
    mov eax, PD_INVALID
.Lprd_grow_done:
    PD_LEAVE

/* Trusted rdi callback or zero, rsi callback context. */
.global parent_directory_create
parent_directory_create:
    PD_ENTER
    mov r13, rdi
    mov r14, rsi
    mov edi, 4096
    call .Lprd_map
    cmp rax, -4095
    jae .Lprd_create_return
    mov r12, rax
    mov rax, PD_MAGIC
    mov [r12], rax
    mov qword ptr [r12+8], 4096
    lea rax, [rip+.Lprd_body]
    mov [r12+16], rax
    mov [r12+40], r13
    mov [r12+48], r14
    lea rdi, [r12+256]
    mov rax, -1
    mov ecx, 8
    rep stosq
    lea rdi, [r12+88]
    mov esi, 4096
    call .Lprd_grow
    test eax, eax
    jnz .Lprd_create_fail
    lea rdi, [r12+104]
    mov esi, 4096
    call .Lprd_grow
    test eax, eax
    jnz .Lprd_create_fail
    lea rdi, [r12+120]
    mov esi, PD_REPLY_CAP
    call .Lprd_grow
    test eax, eax
    jnz .Lprd_create_fail
    mov rax, r12
    jmp .Lprd_create_return
.Lprd_create_fail:
    mov rdi, r12
    call parent_directory_destroy
    mov rax, -12
.Lprd_create_return:
    PD_LEAVE

/* An optional journal only observes already owned byte spans. The callback
 * returns zero and cannot replace a syscall or HIA result. r12=context,
 * rdx=event, rcx=span, r8=length. */
.Lprd_emit:
    PD_ENTER
    mov rbx, [r12+40]
    test rbx, rbx
    jz .Lprd_emit_ok
    mov rdi, [r12+48]
    mov rsi, r12
    call rbx
    jmp .Lprd_emit_return
.Lprd_emit_ok:
    xor eax, eax
.Lprd_emit_return:
    PD_LEAVE

/* The graph holds a final response borrow until this explicit release. */
.global parent_directory_release
parent_directory_release:
    mov rax, PD_MAGIC
    cmp [rdi], rax
    jne .Lprd_release_bad
    cmp qword ptr [rdi+8], 4096
    jne .Lprd_release_bad
    cmp qword ptr [rdi+56], 2
    jne .Lprd_release_bad
    cmp qword ptr [rdi+184], 0
    jne .Lprd_release_bad
    mov qword ptr [rdi+56], 0
    mov qword ptr [rdi+168], 0
    mov qword ptr [rdi+176], 0
    xor eax, eax
    ret
.Lprd_release_bad:
    mov eax, PD_INVALID
    ret

/* Destruction refuses active or borrowed contexts. Fatal private failures may
 * close still-owned OS descriptors; they never masquerade as body success. */
.global parent_directory_destroy
parent_directory_destroy:
    PD_ENTER
    mov r12, rdi
    mov rax, PD_MAGIC
    cmp [r12], rax
    jne .Lprd_destroy_bad
    cmp qword ptr [r12+8], 4096
    jne .Lprd_destroy_bad
    mov rax, [r12+56]
    cmp rax, 1
    je .Lprd_destroy_busy
    cmp rax, 2
    je .Lprd_destroy_busy
    cmp rax, 4
    je .Lprd_destroy_busy
    cmp rax, 3
    ja .Lprd_destroy_bad
    xor ebx, ebx
.Lprd_destroy_fd:
    mov rdi, [r12+256+rbx*8]
    cmp rdi, -1
    je .Lprd_destroy_fd_next
    mov eax, 3
    syscall
    mov qword ptr [r12+256+rbx*8], -1
.Lprd_destroy_fd_next:
    inc ebx
    cmp ebx, 8
    jb .Lprd_destroy_fd
    mov qword ptr [r12+184], 0
    lea r13, [rip+.Lprd_pairs]
    mov ebx, 4
.Lprd_destroy_pair:
    mov r14, [r13]
    mov rdi, [r12+r14]
    test rdi, rdi
    jz .Lprd_destroy_pair_next
    mov rsi, [r12+r14+8]
    add rsi, 4096
    mov eax, 11
    syscall
    test rax, rax
    jnz .Lprd_destroy_resource
    mov qword ptr [r12+r14], 0
    mov qword ptr [r12+r14+8], 0
.Lprd_destroy_pair_next:
    add r13, 8
    dec ebx
    jnz .Lprd_destroy_pair
    mov rdi, r12
    mov esi, 8192
    mov eax, 11
    syscall
    jmp .Lprd_destroy_return
.Lprd_destroy_busy:
    mov eax, PD_BUSY
    jmp .Lprd_destroy_return
.Lprd_destroy_resource:
    mov eax, PD_RESOURCE
    jmp .Lprd_destroy_return
.Lprd_destroy_bad:
    mov eax, PD_INVALID
.Lprd_destroy_return:
    PD_LEAVE
.balign 8
.Lprd_pairs:
    .quad 64,88,104,120

/* Only these checked native effects are available to the fixed HIA body. */
.Lprd_fd_find:
    xor eax, eax
.Lprd_fd_find_loop:
    cmp [r12+256+rax*8], rdi
    je .Lprd_fd_find_return
    inc eax
    cmp eax, 8
    jb .Lprd_fd_find_loop
.Lprd_fd_not_owned:
    mov rax, -1
.Lprd_fd_find_return:
    ret
.Lprd_name:
    test rsi, rsi
    jz .Lprd_name_bad
    mov rcx, rsi
    xor eax, eax
    repne scasb
    jne .Lprd_name_bad
    test rcx, rcx
    jnz .Lprd_name_bad
    xor eax, eax
    ret
.Lprd_name_bad:
    mov eax, PD_INVALID
    ret

.Lprd_os:
    PD_ENTER
    mov rbp, [r12+104]
    mov rbx, [rbp+24]
    mov qword ptr [r12+240], 0
    cmp rbx, 1
    je .Lprd_os_root
    mov rdi, [rbp+32]
    call .Lprd_fd_find
    cmp rax, -1
    je .Lprd_os_bad
    mov r15, rax
    cmp rbx, 2
    je .Lprd_os_openat
    cmp rbx, 5
    je .Lprd_os_close
    jmp .Lprd_os_bad
.Lprd_os_root:
    mov rax, [rbp+32]
    or rax, [rbp+40]
    or rax, [rbp+48]
    or rax, [rbp+56]
    jnz .Lprd_os_bad
    lea rdi, [rip+.Lprd_root_path]
    mov esi, 0xb0000
    xor edx, edx
    mov eax, 2
    syscall
    jmp .Lprd_os_opened
.Lprd_os_openat:
    mov rax, [rbp+40]
    or rax, [rbp+48]
    jnz .Lprd_os_bad
    lea rdi, [rbp+64]
    mov rsi, [rbp+56]
    call .Lprd_name
    test eax, eax
    jnz .Lprd_os_bad
    mov rdi, [rbp+32]
    lea rsi, [rbp+64]
    mov edx, 0xb0000
    xor r10d, r10d
    mov eax, 257
    syscall
.Lprd_os_opened:
    mov [r12+232], rax
    cmp rax, -4095
    jae .Lprd_os_ok
    mov r13, rax
    mov rdi, rax
    call .Lprd_fd_find
    cmp rax, -1
    jne .Lprd_os_bad
    xor eax, eax
.Lprd_os_fd_insert:
    cmp qword ptr [r12+256+rax*8], -1
    je .Lprd_os_fd_insert_at
    inc eax
    cmp eax, 8
    jb .Lprd_os_fd_insert
    mov rdi, r13
    mov eax, 3
    syscall
    jmp .Lprd_os_bad
.Lprd_os_fd_insert_at:
    mov [r12+256+rax*8], r13
    inc qword ptr [r12+184]
    jmp .Lprd_os_ok
.Lprd_os_close:
    mov rax, [rbp+40]
    or rax, [rbp+48]
    or rax, [rbp+56]
    jnz .Lprd_os_bad
    mov rdi, [rbp+32]
    mov eax, 3
    syscall
    mov [r12+232], rax
    mov qword ptr [r12+256+r15*8], -1
    dec qword ptr [r12+184]
.Lprd_os_ok:
    xor eax, eax
    jmp .Lprd_os_done
.Lprd_os_bad:
    mov eax, PD_INVALID
.Lprd_os_done:
    PD_LEAVE
.Lprd_root_path:
    .asciz "/"

/* rdi context, rsi complete HPRDQ001 acquire request, rdx length. */
.global parent_directory_acquire
parent_directory_acquire:
    PD_ENTER
    mov r12, rdi
    mov r13, rsi
    mov r14, rdx
    jmp .Lprd_invoke_validate_context

/* End the held directory borrow. No external bytes can select its FD/sequence.
 * All child users must have completed before the fixed graph calls this entry. */
.global parent_directory_close
parent_directory_close:
    PD_ENTER
    mov r12, rdi
    mov rax, PD_MAGIC
    cmp [r12], rax
    jne .Lprd_invoke_reject
    cmp qword ptr [r12+8], 4096
    jne .Lprd_invoke_reject
    cmp qword ptr [r12+56], 4
    jne .Lprd_invoke_busy
    cmp qword ptr [r12+184], 1
    jne .Lprd_invoke_reject
    cmp qword ptr [r12+352], 1
    jne .Lprd_invoke_reject
    mov rdi, [r12+344]
    call .Lprd_fd_find
    cmp rax, -1
    je .Lprd_invoke_reject
    mov r13, [r12+88]
    cmp qword ptr [r13+8], 20
    jne .Lprd_invoke_reject
    cmp qword ptr [r13+432], 1
    jne .Lprd_invoke_reject
    mov rax, [r12+344]
    cmp [r13+88], rax
    jne .Lprd_invoke_reject
    mov rax, [r12+360]
    cmp [r13+16], rax
    jne .Lprd_invoke_reject
    mov rdi, [r12+64]
    xor eax, eax
    mov ecx, 12
    rep stosq
    mov r13, [r12+64]
    movabs rax, 0x3130305144525048
    mov [r13], rax
    mov qword ptr [r13+8], 3
    mov rax, [r12+360]
    mov [r13+16], rax
    mov qword ptr [r12+80], 96
    mov [r12+200], r13
    mov qword ptr [r12+208], 96
    mov qword ptr [r12+168], 0
    mov qword ptr [r12+176], 0
    mov qword ptr [r12+56], 1
    jmp .Lprd_invoke_loop

.Lprd_invoke_validate_context:
    mov rax, PD_MAGIC
    cmp [r12], rax
    jne .Lprd_invoke_reject
    cmp qword ptr [r12+8], 4096
    jne .Lprd_invoke_reject
    cmp qword ptr [r12+56], 0
    jne .Lprd_invoke_busy
    cmp qword ptr [r12+184], 0
    jne .Lprd_invoke_reject
    cmp qword ptr [r12+352], 0
    jne .Lprd_invoke_reject
    cmp r14, 96
    jb .Lprd_invoke_reject
    cmp r14, PD_MAX_INPUT
    ja .Lprd_invoke_reject
    test r13, r13
    jz .Lprd_invoke_reject
    movabs rax, 0x3130305144525048
    cmp [r13], rax
    jne .Lprd_invoke_reject
    cmp qword ptr [r13+8], 1
    jne .Lprd_invoke_reject
    cmp qword ptr [r13+16], 0
    jne .Lprd_invoke_reject
    cmp qword ptr [r12+192], -1
    je .Lprd_invoke_reject
    lea rdi, [r12+64]
    mov rsi, r14
    call .Lprd_grow
    test eax, eax
    jnz .Lprd_invoke_return
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
.Lprd_invoke_loop:
    inc qword ptr [r12+248]
    jz .Lprd_invoke_failed
    mov rdi, [r12+104]
    mov rcx, [r12+112]
    shr rcx, 3
    mov rax, 0xa5a5a5a5a5a5a5a5
    rep stosq
    mov edx, 1
    mov rcx, [r12+200]
    mov r8, [r12+208]
    call .Lprd_emit
    test rax, rax
    jnz .Lprd_invoke_failed
    mov edx, 10
    mov rcx, [r12+88]
    mov r8, [r12+96]
    call .Lprd_emit
    test rax, rax
    jnz .Lprd_invoke_failed
    mov edx, 12
    mov rcx, [r12+104]
    mov r8, [r12+112]
    call .Lprd_emit
    test rax, rax
    jnz .Lprd_invoke_failed
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
    call .Lprd_emit
    test rax, rax
    jnz .Lprd_invoke_failed
    mov edx, 11
    mov rcx, [r12+88]
    mov r8, [r12+96]
    call .Lprd_emit
    test rax, rax
    jnz .Lprd_invoke_failed
    cmp qword ptr [r12+176], 64
    jne .Lprd_invoke_failed
    mov rbp, [r12+104]
    mov rax, 0x3130305344524248 /* HBRDS001 */
    cmp [rbp], rax
    jne .Lprd_invoke_failed
    mov rax, [r12+112]
    sub rax, 64
    cmp [rbp+56], rax
    ja .Lprd_invoke_failed
    mov rbx, [rbp+8]
    cmp rbx, 6
    ja .Lprd_invoke_failed
    je .Lprd_invoke_parent_loan
    test rbx, rbx
    jz .Lprd_invoke_final
    cmp rbx, 3
    je .Lprd_invoke_final
    cmp rbx, 4
    jae .Lprd_invoke_growth
    mov rax, [rbp+16]
    mov [r12+216], rax
    mov rax, [rbp+24]
    mov [r12+224], rax
    cmp rbx, 2
    je .Lprd_invoke_failed
    mov edx, 8
    mov rcx, rbp
    mov r8, [rbp+56]
    add r8, 64
    call .Lprd_emit
    test rax, rax
    jnz .Lprd_invoke_failed
    call .Lprd_os
    test eax, eax
    jnz .Lprd_invoke_failed
    jmp .Lprd_invoke_reply
.Lprd_invoke_reply:
    mov rbx, [r12+120]
    movabs rax, 0x3130305144525048
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
    ja .Lprd_invoke_failed
    mov [rbx+88], rax
    add rax, 96
    cmp rax, [r12+128]
    ja .Lprd_invoke_failed
    mov [r12+200], rbx
    mov [r12+208], rax
    mov edx, 9
    mov rcx, rbx
    mov r8, rax
    call .Lprd_emit
    test rax, rax
    jnz .Lprd_invoke_failed
    jmp .Lprd_invoke_loop
.Lprd_invoke_growth:
    mov rax, [rbp+16]
    or rax, [rbp+24]
    or rax, [rbp+40]
    or rax, [rbp+48]
    or rax, [rbp+56]
    jnz .Lprd_invoke_failed
    mov r13, [rbp+32]
    cmp rbx, 4
    jne .Lprd_invoke_output_growth
    cmp r13, [r12+96]
    jbe .Lprd_invoke_failed
    cmp r13, PD_MAX_WORK
    ja .Lprd_invoke_failed
    mov edx, 3
    mov rcx, [r12+88]
    mov r8, [r12+96]
    call .Lprd_emit
    test rax, rax
    jnz .Lprd_invoke_failed
    lea rdi, [r12+88]
    mov rsi, r13
    call .Lprd_grow
    test eax, eax
    jnz .Lprd_invoke_resource
    mov edx, 4
    mov rcx, [r12+88]
    mov r8, [r12+96]
    call .Lprd_emit
    test rax, rax
    jnz .Lprd_invoke_failed
    jmp .Lprd_invoke_loop
.Lprd_invoke_output_growth:
    cmp r13, [r12+112]
    jbe .Lprd_invoke_failed
    cmp r13, PD_MAX_OUT
    ja .Lprd_invoke_failed
    lea rdi, [r12+104]
    mov rsi, r13
    call .Lprd_grow
    test eax, eax
    jnz .Lprd_invoke_resource
    jmp .Lprd_invoke_loop
.Lprd_invoke_parent_loan:
    cmp qword ptr [r12+184], 1
    jne .Lprd_invoke_failed
    cmp qword ptr [rbp+24], 2147483647
    ja .Lprd_invoke_failed
    mov rax, [rbp+40]
    or rax, [rbp+48]
    jnz .Lprd_invoke_failed
    mov rax, [rbp+56]
    cmp [rbp+32], rax
    jne .Lprd_invoke_failed
    mov rdi, [rbp+24]
    call .Lprd_fd_find
    cmp rax, -1
    je .Lprd_invoke_failed
    mov r13, [r12+88]
    cmp qword ptr [r13+8], 20
    jne .Lprd_invoke_failed
    cmp qword ptr [r13+432], 1
    jne .Lprd_invoke_failed
    mov rax, [rbp+24]
    cmp [r13+88], rax
    jne .Lprd_invoke_failed
    mov [r12+344], rax
    mov rax, [rbp+16]
    cmp [r13+16], rax
    jne .Lprd_invoke_failed
    mov [r12+360], rax
    mov qword ptr [r12+352], 1
    mov rax, [rbp+56]
    add rax, 64
    mov [r12+168], rax
    mov qword ptr [r12+56], 4
    mov eax, 64
    jmp .Lprd_invoke_return

.Lprd_invoke_final:
    cmp qword ptr [r12+184], 0
    jne .Lprd_invoke_failed
    cmp qword ptr [rbp+8], 3
    je .Lprd_invoke_error
    mov rax, [rbp+24]
    or rax, [rbp+32]
    or rax, [rbp+40]
    or rax, [rbp+48]
    jnz .Lprd_invoke_failed
    jmp .Lprd_invoke_borrow
.Lprd_invoke_error:
    cmp qword ptr [rbp+24], 1
    jb .Lprd_invoke_failed
    cmp qword ptr [rbp+24], 14
    ja .Lprd_invoke_failed
    cmp qword ptr [rbp+32], 4095
    ja .Lprd_invoke_failed
    cmp qword ptr [rbp+48], 1
    ja .Lprd_invoke_failed
    mov rax, [rbp+40]
    cmp rax, [rbp+56]
    ja .Lprd_invoke_failed
.Lprd_invoke_borrow:
    /* Acquisition failure or explicit close has drained every owned directory. */
    mov qword ptr [r12+344], 0
    mov qword ptr [r12+352], 0
    mov qword ptr [r12+360], 0
    mov rax, [rbp+56]
    add rax, 64
    mov [r12+168], rax
    mov qword ptr [r12+56], 2
    mov eax, 64
    jmp .Lprd_invoke_return
.Lprd_invoke_resource:
    mov eax, PD_RESOURCE
    jmp .Lprd_invoke_record_failure
.Lprd_invoke_failed:
    mov eax, PD_INVALID
.Lprd_invoke_record_failure:
    mov [r12+176], rax
    mov qword ptr [r12+56], 3
    mov qword ptr [r12+168], 0
    jmp .Lprd_invoke_return
.Lprd_invoke_busy:
    mov eax, PD_BUSY
    jmp .Lprd_invoke_return
.Lprd_invoke_reject:
    mov eax, PD_INVALID
.Lprd_invoke_return:
    PD_LEAVE

/* Fixed image entries patched only by the actual HIA image packer. */
.balign 16
.global parent_directory_body_call_displacement
.Lprd_body:
    .byte 0xe9
parent_directory_body_call_displacement:
    .long 0

.section .note.GNU-stack,"",@progbits
