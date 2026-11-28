/* Batch fixed callable capability attachment. The existing process hub owns
 * history, locks and the shared statx byte. Engine+416 owns only this session's
 * callable context. A returned WAIT stays owned; no wake is fabricated. */
.intel_syntax noprefix
.section .text
.global runtime_batch_body_owned
.global runtime_batch_body_release
.global runtime_batch_body_shared_grow
.global runtime_batch_body_hint
/* Fixed native slot52, owned result retained until parent delivery completes. */
runtime_batch_body_owned:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    sub rsp, 32
    mov [rsp], rdi
    mov [rsp + 8], rsi
    mov rbx, [r15 + 8]
    add rbx, 52*64
    lea rbp, [r15 + 512 + 52*64]
    cmp qword ptr [rbp], 0
    jne rbb_invalid
    cmp qword ptr [rbp + 8], 0
    jne rbb_invalid
    mov qword ptr [rbp], 1
    mov qword ptr [rbx + 48], 0
    mov qword ptr [rbx + 56], 0
    mov r14, [r15 + 400]
    test r14, r14
    jz rbb_invalid_active
    mov rax, 0x3142554842544c48
    cmp [r14], rax
    jne rbb_invalid_active
    mov r12, [r15 + 416]
    test r12, r12
    jnz rbb_existing
    mov edi, 4096
    call view_allocate
    cmp rax, -4095
    jae rbb_resource_active
    mov r12, rax
    mov [r15 + 416], rax
    mov [r12 + 256 + 168], r15
    jmp rbb_context_ready
rbb_existing:
    cmp qword ptr [r12 + 152], 0
    je rbb_context_ready
    mov rdi, r12
    call local_batch_body_release
    test eax, eax
    jnz rbb_invalid_active
rbb_context_ready:
    mov rdi, r12
    xor eax, eax
    mov ecx, 24
    rep stosq
    mov rax, 0x3130494342424c48 /* HLBBCI01 */
    mov [r12], rax
    mov qword ptr [r12 + 8], 192
    lea rax, [rip + runtime_batch_body_images]
    mov [r12 + 16], rax
    lea rax, [rip + runtime_batch_cache]
    mov [r12 + 24], rax
    lea rax, [r12 + 256]
    mov [r12 + 32], rax
    mov [r12 + 48], rax
    lea rax, [rip + runtime_batch_body_hint]
    mov [r12 + 40], rax
    lea rax, [r14 + 64]
    mov [r12 + 56], rax
    lea rax, [r14 + 128]
    mov [r12 + 64], rax
    lea rax, [rip + runtime_batch_body_shared_grow]
    mov [r12 + 72], rax
    mov [r12 + 80], r14
    lea rax, [r14 + 8]
    mov [r12 + 88], rax
    mov rax, [r15 + 32]
    mov [r12 + 96], rax
    mov rdi, r12
    mov rsi, [rsp]
    mov rdx, [rsp + 8]
    inc qword ptr [r15 + 128]
    call local_batch_body_run
    mov edx, eax
    cmp rax, rdx
    jne rbb_invalid_active
    cmp [r12 + 128], rax
    jne rbb_invalid_active
    /* A scheduling WAIT remains distinct; this serial fixture has no waiter
     * executor. Never spin, fabricate a wake, or release an undrained owner. */
    cmp eax, 0xffffffe1
    je rbb_undrained
    cmp qword ptr [r12 + 136], 1
    jne rbb_invalid_active
    cmp qword ptr [r12 + 144], 1
    jne rbb_invalid_active
    cmp qword ptr [r12 + 160], 0
    jne rbb_invalid_active
    mov [rbx + 48], rax
    mov rcx, [r12 + 112]
    mov [rbx + 32], rcx
    mov rcx, [r12 + 120]
    mov [rbx + 40], rcx
    mov [rbx + 56], rcx
    cmp eax, 0xffff0000
    jae rbb_private
    cmp rax, rcx
    jne rbb_invalid_active
    jmp rbb_complete
rbb_private:
    test rcx, rcx
    jnz rbb_invalid_active
    jmp rbb_complete
rbb_resource_active:
    mov eax, 0xfffffffc
    jmp rbb_error
rbb_invalid_active:
    mov eax, 0xffffffff
rbb_error:
    mov [rbx + 48], rax
    mov qword ptr [rbx + 56], 0
rbb_complete:
    mov qword ptr [rbp], 0
    jmp rbb_done
rbb_undrained:
    mov [rbx + 48], rax
    mov qword ptr [rbx + 56], 0
    jmp rbb_done
rbb_invalid:
    mov eax, 0xffffffff
rbb_done:
    add rsp, 32
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

runtime_batch_body_release:
    push rbx
    mov rbx, [r15 + 416]
    test rbx, rbx
    jz rbbh_release_success
    cmp qword ptr [rbx + 152], 0
    je rbbh_release_frame
    mov rdi, rbx
    call local_batch_body_release
    test eax, eax
    jnz rbbh_release_done
rbbh_release_frame:
    mov rdi, [rbx + 256 + 184]
    test rdi, rdi
    jz rbbh_release_control
    mov rsi, [rbx + 256 + 192]
    add rsi, 4096
    mov eax, 11
    syscall
    test rax, rax
    jnz rbbh_release_done
    mov qword ptr [rbx + 256 + 184], 0
    mov qword ptr [rbx + 256 + 192], 0
rbbh_release_control:
    mov rdi, rbx
    mov esi, 8192
    mov eax, 11
    syscall
    test rax, rax
    jnz rbbh_release_done
    mov qword ptr [r15 + 416], 0
rbbh_release_success:
    xor eax, eax
rbbh_release_done:
    pop rbx
    ret

/* Batch does not publish hints. A call is an invalid capability use. */
runtime_batch_body_hint:
    mov eax, 0xffffffff
    ret

/* Batch owner 7 is the same lock state; Batch owner 3 is the same history.
 * This remaps only table indices, retaining the existing grow implementation. */
runtime_batch_body_shared_grow:
    cmp esi, 7
    je rbb_grow_lock
    cmp esi, 3
    jne rbb_grow_invalid
    mov esi, 6
    jmp runtime_text_body_shared_grow
rbb_grow_lock:
    mov esi, 3
    jmp runtime_text_body_shared_grow
rbb_grow_invalid:
    mov eax, 0xffffffff
    ret
.balign 8
runtime_batch_body_images:
    .zero 112
