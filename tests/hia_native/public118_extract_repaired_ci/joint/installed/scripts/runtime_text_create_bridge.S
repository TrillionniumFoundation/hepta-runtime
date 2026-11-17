/* Private TextEditor Create attachment to the existing session View engine.
 * HIA retains dispatch, path, scope, cache and file semantics. This boundary
 * installs fixed capabilities and retains completed output through delivery.
 * No public route or pre-drain cancellation publication is installed here. */
.intel_syntax noprefix
.section .text
.global runtime_text_create_owned
.global runtime_text_create_release
.global runtime_text_create_cache

/* r15 is the one existing extra engine. Slot 36 is native transport, not a
 * request-selected function. The private control at engine+248 owns its
 * callable context, cancellation word, serial statx byte and cache frame. */
runtime_text_create_owned:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    sub rsp, 32
    mov [rsp], rdi
    mov [rsp + 8], rsi
    mov rbx, [r15 + 8]
    add rbx, 36*64
    lea rbp, [r15 + 512 + 36*64]
    cmp qword ptr [rbp], 0
    jne rtc_invalid
    cmp qword ptr [rbp + 8], 0
    jne rtc_invalid
    mov qword ptr [rbp], 1
    mov qword ptr [rbx + 48], 0
    mov qword ptr [rbx + 56], 0
    mov r12, [r15 + 248]
    test r12, r12
    jnz rtc_existing
    mov edi, 4096
    call view_allocate
    cmp rax, -4095
    jae rtc_resource_active
    mov r12, rax
    mov [r15 + 248], rax
    mov [r12 + 168], r15
    jmp rtc_context_ready
rtc_existing:
    cmp qword ptr [r12 + 120], 0
    je rtc_context_ready
    mov rdi, r12
    call local_create_spec_release
    test eax, eax
    jnz rtc_invalid_active
rtc_context_ready:
    mov rdi, r12
    mov ecx, 20
    xor eax, eax
    rep stosq
    mov qword ptr [r12 + 160], 0
    mov rax, 0x3130304942434c48 /* HLCBI001 */
    mov [r12], rax
    mov qword ptr [r12 + 8], 160
    lea rax, [rip + runtime_text_create_images]
    mov [r12 + 16], rax
    lea rax, [rip + runtime_text_create_cache]
    mov [r12 + 24], rax
    mov [r12 + 32], r12
    lea rax, [r12 + 160]
    mov [r12 + 40], rax
    mov rax, [r15 + 32]
    mov [r12 + 64], rax
    /* Actual process-owned byte shared with Local edit owners, still distinct
     * from View and other metadata callers whose global sharing stays open. */
    mov rax, [r15 + 400]
    test rax, rax
    jz rtc_invalid_active
    add rax, 8
    mov [r12 + 144], rax
    mov rdi, r12
    mov rsi, [rsp]
    mov rdx, [rsp + 8]
    inc qword ptr [r15 + 128]
    call local_create_spec_run
    mov edx, eax
    cmp rax, rdx
    jne rtc_invalid_active
    cmp [r12 + 96], rax
    jne rtc_invalid_active
    cmp qword ptr [r12 + 104], 1
    jne rtc_invalid_active
    cmp qword ptr [r12 + 112], 1
    jne rtc_invalid_active
    cmp qword ptr [r12 + 128], 0
    jne rtc_invalid_active
    mov [rbx + 48], rax
    mov rcx, [r12 + 80]
    mov [rbx + 32], rcx
    mov rcx, [r12 + 88]
    mov [rbx + 40], rcx
    mov [rbx + 56], rcx
    cmp eax, 0xffff0000
    jae rtc_private_result
    cmp rax, rcx
    jne rtc_invalid_active
    jmp rtc_done_active
rtc_private_result:
    test rcx, rcx
    jnz rtc_invalid_active
    jmp rtc_done_active
rtc_resource_active:
    mov eax, 0xfffffffc
    jmp rtc_error_active
rtc_invalid_active:
    mov eax, 0xffffffff
rtc_error_active:
    mov [rbx + 48], rax
    mov qword ptr [rbx + 56], 0
rtc_done_active:
    mov qword ptr [rbp], 0
    jmp rtc_done
rtc_invalid:
    mov eax, 0xffffffff
rtc_done:
    add rsp, 32
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

/* Installed callback: control, complete cache request, length, result pair.
 * The current caller workspace and View scope/lease/cache are acquired here,
 * after actual file flush/close/key. The Create worker receives no binding. */
runtime_text_create_cache:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp, 88
    mov r12, rdi
    mov [rsp], rsi
    mov [rsp + 8], rdx
    mov [rsp + 16], rcx
    mov qword ptr [r12 + 208], 1
    cmp rdx, 48
    jb rtc_cache_invalid
    mov rax, 0x3130484341435648 /* HVCACH01 */
    cmp [rsi], rax
    jne rtc_cache_invalid
    cmp qword ptr [rsi + 8], 6
    je rtc_cache_operation
    cmp qword ptr [rsi + 8], 7
    je rtc_cache_operation
    cmp qword ptr [rsi + 8], 3
    jne rtc_cache_invalid
rtc_cache_operation:
    cmp qword ptr [rsi + 16], 1
    jne rtc_cache_invalid
    mov qword ptr [r12 + 208], 2
    mov r14, [r12 + 168]
    test r14, r14
    jz rtc_cache_invalid
    mov rbx, [r14 + 8]
    mov rbx, [rbx + 35*64 + 8]
    test rbx, rbx
    jz rtc_cache_invalid
    cmp qword ptr [rbx + 416], 1
    jne rtc_cache_invalid
    mov rax, [rbx + 112]
    test rax, rax
    jz rtc_cache_invalid
    mov [rsp + 24], rax
    mov rax, [rbx + 120]
    test rax, rax
    jz rtc_cache_invalid
    mov [rsp + 32], rax
    mov qword ptr [r12 + 208], 3
    add rdx, 64
    jc rtc_cache_resource
    cmp rdx, [r12 + 192]
    jbe rtc_cache_frame_ready
    add rdx, 4095
    jc rtc_cache_resource
    and rdx, -4096
    test rdx, rdx
    jle rtc_cache_resource
    mov r13, rdx
    mov rdi, [r12 + 184]
    test rdi, rdi
    jz rtc_cache_allocate
    mov rsi, [r12 + 192]
    call view_resize
    jmp rtc_cache_allocated
rtc_cache_allocate:
    mov rdi, r13
    call view_allocate
rtc_cache_allocated:
    cmp rax, -4095
    jae rtc_cache_resource
    mov [r12 + 184], rax
    mov [r12 + 192], r13
rtc_cache_frame_ready:
    mov rbp, [r12 + 184]
    mov rdi, rbp
    mov ecx, 8
    xor eax, eax
    rep stosq
    mov rax, 0x3130305143535248 /* HRSCQ001 */
    mov [rbp], rax
    mov qword ptr [rbp + 8], 9
    mov rax, [rsp + 24]
    mov [rbp + 16], rax
    mov rax, [rsp + 32]
    mov [rbp + 24], rax
    mov rax, [rsp + 8]
    mov [rbp + 48], rax
    lea rdi, [rbp + 64]
    mov rsi, [rsp]
    mov rcx, rax
    rep movsb
    mov qword ptr [r12 + 208], 4
    mov r15, [r14 + 16]
    test r15, r15
    jz rtc_cache_invalid
    /* Borrow only the complete fixed result: 64 scope bytes + 32 cache bytes.
     * The original owning descriptor extent is restored before inspecting any
     * child result, including private failures. Nested lease output is then 32. */
rtc_cache_scope_borrow:
    mov r13, [r15 + 8]
    add r13, 6*64
    mov rax, [r13 + 32]
    cmp rax, 96
    jb rtc_cache_invalid
    mov [rsp + 40], rax
    mov rax, [r13 + 48]
    mov [rsp + 56], rax
    mov rax, [r13 + 64 + 48]
    mov [rsp + 64], rax
    mov qword ptr [r13 + 32], 96
    mov rdi, rbp
    mov rsi, [rsp + 8]
    add rsi, 64
    mov edx, 6
    mov qword ptr [r12 + 208], 5
    call view_scope_invoke
    mov rdx, [rsp + 40]
    mov [r13 + 32], rdx
    mov [r12 + 216], rax
    mov qword ptr [r12 + 208], 6
    cmp eax, 0xfffffffe
    je rtc_cache_grow
    cmp rax, 96
    jne rtc_cache_invalid
    mov rdx, [r15 + 8]
    mov rdx, [rdx + 6*64 + 24]
    mov rax, 0x3130305243535248 /* HRSCR001 */
    cmp [rdx], rax
    jne rtc_cache_invalid
    mov rax, [rsp + 24]
    cmp [rdx + 8], rax
    jne rtc_cache_invalid
    mov rax, [rsp + 32]
    cmp [rdx + 16], rax
    jne rtc_cache_invalid
    cmp qword ptr [rdx + 24], 1
    jne rtc_cache_invalid
    cmp qword ptr [rdx + 32], 5
    jne rtc_cache_invalid
    cmp qword ptr [rdx + 56], 32
    jne rtc_cache_invalid
    mov rax, [rbx + 96]
    cmp [rdx + 40], rax
    jne rtc_cache_invalid
    mov rax, [rbx + 128]
    cmp [rdx + 48], rax
    jne rtc_cache_invalid
    mov rcx, [rsp + 16]
    add rdx, 64
    mov [rcx], rdx
    mov qword ptr [rcx + 8], 32
    mov qword ptr [r12 + 208], 7
    inc qword ptr [r12 + 200]
    mov eax, 32
    jmp rtc_cache_done
rtc_cache_grow:
    /* CAPACITY returns before the cache mutation. Scope and lease have both
     * consumed that completed child result. Grow only the same cache arena,
     * preserving every byte, then retry the same pending cache operation.
     * The completed Create file worker is never entered again. */
    mov rdi, [r15 + 8]
    mov rsi, [rsp + 56]
    mov rdx, [rsp + 64]
    call rtc_completed_cache_capacity
    test eax, eax
    jz rtc_cache_resource
    mov r13, [r15 + 8]
    add r13, 8*64
    mov rsi, [r13 + 16]
    test rsi, rsi
    jz rtc_cache_invalid
    mov rdx, rsi
    shl rdx, 1
    jc rtc_cache_resource
    test rdx, rdx
    js rtc_cache_resource
    mov [rsp + 48], rdx
    mov rdi, [r13 + 8]
    call view_resize
    cmp rax, -4095
    jae rtc_cache_resource
    mov [r13 + 8], rax
    mov rax, [rsp + 48]
    mov [r13 + 16], rax
    inc qword ptr [r12 + 224]
    jmp rtc_cache_scope_borrow
rtc_cache_resource:
    mov eax, 0xfffffffc
    jmp rtc_cache_done
rtc_cache_invalid:
    mov eax, 0xffffffff
rtc_cache_done:
    add rsp, 88
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

/* Called after the parent's last result borrow and before session retirement. */
runtime_text_create_release:
    push rbx
    mov rbx, [r15 + 248]
    test rbx, rbx
    jz rtc_release_success
    cmp qword ptr [rbx + 120], 0
    je rtc_release_frame
    mov rdi, rbx
    call local_create_spec_release
    test eax, eax
    jnz rtc_release_done
rtc_release_frame:
    mov rdi, [rbx + 184]
    test rdi, rdi
    jz rtc_release_control
    mov rsi, [rbx + 192]
    add rsi, 4096
    mov eax, 11
    syscall
    test rax, rax
    js rtc_release_done
    mov qword ptr [rbx + 184], 0
    mov qword ptr [rbx + 192], 0
rtc_release_control:
    mov rdi, rbx
    mov esi, 8192
    mov eax, 11
    syscall
    test rax, rax
    js rtc_release_done
    mov qword ptr [r15 + 248], 0
rtc_release_success:
    xor eax, eax
rtc_release_done:
    pop rbx
    ret
.balign 8
runtime_text_create_images:
    .zero 56

/* A capacity result is retryable here only when this invocation completed the
 * fixed Scope -> Lease -> Cache chain. A scope input-window refusal cannot
 * masquerade as cache storage growth. No bytes of any owner are changed. */
rtc_completed_cache_capacity:
    lea r8, [rdi + 6*64]
    lea r9, [rdi + 7*64]
    cmp qword ptr [r8 + 56], 0
    jne rtc_capacity_no
    cmp qword ptr [r9 + 56], 0
    jne rtc_capacity_no
    mov r10, [r8 + 48]
    cmp r10, rsi
    jbe rtc_capacity_no
    mov r11, [r9 + 48]
    cmp r11, rdx
    jbe rtc_capacity_no
    mov rsi, [r8 + 8]
    mov rdx, [r9 + 8]
    cmp qword ptr [rsi + 264], 0
    jne rtc_capacity_no
    cmp qword ptr [rdx + 264], 0
    jne rtc_capacity_no
    add rsi, [r8 + 16]
    sub rsi, 256
    add rdx, [r9 + 16]
    sub rdx, 256
    mov rax, 0x31304c4143414948
    cmp [rsi], rax
    jne rtc_capacity_no
    cmp [rdx], rax
    jne rtc_capacity_no
    cmp [rsi + 8], r10
    jne rtc_capacity_no
    cmp [rsi + 88], r10
    jne rtc_capacity_no
    cmp [rdx + 8], r11
    jne rtc_capacity_no
    cmp [rdx + 88], r11
    jne rtc_capacity_no
    cmp qword ptr [rsi + 16], 7
    jne rtc_capacity_no
    cmp qword ptr [rdx + 16], 8
    jne rtc_capacity_no
    mov eax, 0xfffffffe
    cmp [rsi + 80], rax
    jne rtc_capacity_no
    cmp [rdx + 80], rax
    jne rtc_capacity_no
    cmp qword ptr [rsi + 96], 1
    jne rtc_capacity_no
    cmp qword ptr [rdx + 96], 1
    jne rtc_capacity_no
    cmp qword ptr [rsi + 104], 0
    jne rtc_capacity_no
    cmp qword ptr [rdx + 104], 0
    jne rtc_capacity_no
    mov eax, 1
    ret
rtc_capacity_no:
    xor eax, eax
    ret
