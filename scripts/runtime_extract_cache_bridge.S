.intel_syntax noprefix
.section .text
.global runtime_extract_cache
/* Installed callback: control, complete cache request, length, result pair.
 * The current caller workspace and View scope/lease/cache are acquired here,
 * during the extract_lines cache Get/Set/Forget boundary. Workers receive no binding. */
runtime_extract_cache:
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
    jb rec_cache_invalid
    mov rax, 0x3130484341435648 /* HVCACH01 */
    cmp [rsi], rax
    jne rec_cache_invalid
    cmp qword ptr [rsi + 8], 1
    je rec_cache_operation
    cmp qword ptr [rsi + 8], 2
    je rec_cache_operation
    cmp qword ptr [rsi + 8], 3
    jne rec_cache_invalid
rec_cache_operation:
    cmp qword ptr [rsi + 16], 1
    jne rec_cache_invalid
    mov qword ptr [r12 + 208], 2
    mov r14, [r12 + 168]
    test r14, r14
    jz rec_cache_invalid
    mov rbx, [r14 + 8]
    mov rbx, [rbx + 61*64 + 8]
    test rbx, rbx
    jz rec_cache_invalid
    cmp qword ptr [rbx + 416], 1
    jne rec_cache_invalid
    mov rax, [rbx + 112]
    test rax, rax
    jz rec_cache_invalid
    mov [rsp + 24], rax
    mov rax, [rbx + 120]
    test rax, rax
    jz rec_cache_invalid
    mov [rsp + 32], rax
    mov qword ptr [r12 + 208], 3
    add rdx, 64
    jc rec_cache_resource
    cmp rdx, [r12 + 192]
    jbe rec_cache_frame_ready
    add rdx, 4095
    jc rec_cache_resource
    and rdx, -4096
    test rdx, rdx
    jle rec_cache_resource
    mov r13, rdx
    mov rdi, [r12 + 184]
    test rdi, rdi
    jz rec_cache_allocate
    mov rsi, [r12 + 192]
    call view_resize
    jmp rec_cache_allocated
rec_cache_allocate:
    mov rdi, r13
    call view_allocate
rec_cache_allocated:
    cmp rax, -4095
    jae rec_cache_resource
    mov [r12 + 184], rax
    mov [r12 + 192], r13
rec_cache_frame_ready:
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
    jz rec_cache_invalid
    /* Borrow 64 Scope bytes plus the complete 32-byte cache header and up to
     * 1 MiB of retained cached content. Restore the owning capacity on every
     * return before inspecting the result. The callable copies the complete
     * dynamic Get span before a later callback reuses this borrowed window. */
rec_cache_scope_borrow:
    mov r13, [r15 + 8]
    add r13, 6*64
    mov rax, [r13 + 32]
    cmp rax, 1048672
    jb rec_cache_invalid
    mov [rsp + 40], rax
    mov rax, [r13 + 48]
    mov [rsp + 56], rax
    mov rax, [r13 + 64 + 48]
    mov [rsp + 64], rax
    mov qword ptr [r13 + 32], 1048672
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
    je rec_cache_grow
    cmp rax, 96
    jb rec_cache_invalid
    cmp rax, 1048672
    ja rec_cache_invalid
    sub rax, 64
    mov [rsp + 72], rax
    mov rdx, [r15 + 8]
    mov rdx, [rdx + 6*64 + 24]
    mov rax, 0x3130305243535248 /* HRSCR001 */
    cmp [rdx], rax
    jne rec_cache_invalid
    mov rax, [rsp + 24]
    cmp [rdx + 8], rax
    jne rec_cache_invalid
    mov rax, [rsp + 32]
    cmp [rdx + 16], rax
    jne rec_cache_invalid
    cmp qword ptr [rdx + 24], 1
    jne rec_cache_invalid
    cmp qword ptr [rdx + 32], 5
    jne rec_cache_invalid
    mov rax, [rsp + 72]
    cmp [rdx + 56], rax
    jne rec_cache_invalid
    mov rax, [rbx + 96]
    cmp [rdx + 40], rax
    jne rec_cache_invalid
    mov rax, [rbx + 128]
    cmp [rdx + 48], rax
    jne rec_cache_invalid
    mov rcx, [rsp + 16]
    add rdx, 64
    mov [rcx], rdx
    mov rax, [rsp + 72]
    mov [rcx + 8], rax
    mov qword ptr [r12 + 208], 7
    inc qword ptr [r12 + 200]
    mov rax, [rsp + 72]
    jmp rec_cache_done
rec_cache_grow:
    /* CAPACITY returns before the cache mutation. Scope and lease have both
     * consumed that completed child result. Grow only the same cache arena,
     * preserving every byte, then retry the same pending cache operation.
     * The extract_lines file operation is never entered again. */
    mov rdi, [r15 + 8]
    mov rsi, [rsp + 56]
    mov rdx, [rsp + 64]
    call rtc_completed_cache_capacity
    test eax, eax
    jz rec_cache_resource
    mov r13, [r15 + 8]
    add r13, 8*64
    mov rsi, [r13 + 16]
    test rsi, rsi
    jz rec_cache_invalid
    mov rdx, rsi
    shl rdx, 1
    jc rec_cache_resource
    test rdx, rdx
    js rec_cache_resource
    mov [rsp + 48], rdx
    mov rdi, [r13 + 8]
    call view_resize
    cmp rax, -4095
    jae rec_cache_resource
    mov [r13 + 8], rax
    mov rax, [rsp + 48]
    mov [r13 + 16], rax
    inc qword ptr [r12 + 224]
    jmp rec_cache_scope_borrow
rec_cache_resource:
    mov eax, 0xfffffffc
    jmp rec_cache_done
rec_cache_invalid:
    mov eax, 0xffffffff
rec_cache_done:
    add rsp, 88
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

