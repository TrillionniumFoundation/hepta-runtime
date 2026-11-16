/* Fixed Batch caller borrow. This mechanical boundary does not interpret edits,
 * render diagnostics, select a path, or fabricate a lease/cache state.
 * Extra-engine +3072 owns a separate installation record. The existing process
 * hub +256 owns the never-started Batch primary for History and file locks.
 * Only trusted startup uses these pointers. No JSON field selects an engine.
 * Public asynchronous notification scheduling is a separate unfinished layer;
 * an unresolved lock wait is retained and reported UNOWNED, never a tool error. */
.intel_syntax noprefix
.section .text
.global runtime_grow_batch_owned
.global runtime_grow_batch_release
.global runtime_batch_global_release
.global runtime_batch_ensure

/* r15=Session extra engine. Return installation record or negative errno. */
runtime_batch_ensure:
    push rbp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub rsp, 8
    mov r14, r15
    mov rax, [r14 + 3072]
    test rax, rax
    jz runtime_batch_ensure_new
    cmp qword ptr [rax + 8], 4
    jne runtime_batch_ensure_invalid
    jmp runtime_batch_ensure_done
runtime_batch_ensure_new:
    call runtime_grow_view_ensure
    cmp rax, -4095
    jae runtime_batch_ensure_done
    mov r13, rax
    mov r12, [r14 + 224]
    test r12, r12
    jz runtime_batch_ensure_invalid
    mov rax, 0x3230425548534648 /* HFSHUB02 */
    cmp [r12], rax
    jne runtime_batch_ensure_invalid
    mov rbp, [r12 + 256]
    test rbp, rbp
    jnz runtime_batch_ensure_global_ready
    lea rdi, [rip + runtime_batch_images]
    mov rsi, [r14 + 32]
    call batch_engine_create
    cmp rax, -4095
    jae runtime_batch_ensure_done
    mov [r12 + 256], rax
    mov rbp, rax
runtime_batch_ensure_global_ready:
    mov edi, 4096
    call view_allocate
    cmp rax, -4095
    jae runtime_batch_ensure_done
    mov rbx, rax
    lea rdi, [rip + runtime_batch_images]
    mov rsi, [r14 + 32]
    call batch_engine_create
    cmp rax, -4095
    jae runtime_batch_ensure_create_failed
    mov r15, rax
    mov rdi, rbp
    xor esi, esi
    mov edx, 1
    call batch_engine_bind_shared
    test eax, eax
    jnz runtime_batch_ensure_bind_failed
    mov rdi, rbx
    mov rsi, r15
    mov rdx, r13
    call runtime_batch_view_install
    mov [r14 + 3072], rbx
    test eax, eax
    jnz runtime_batch_ensure_invalid
    /* Read/atomic waits are real child tasks, joined before their arenas can
     * be retired. Fixture control flags remain zero in this public engine. */
    mov qword ptr [r15 + 640], 1
    mov rax, rbx
    jmp runtime_batch_ensure_done
runtime_batch_ensure_bind_failed:
    /* A contract failure is quarantined rather than guessing the disposition
     * of a successful global-owner operation. Keep its actual engine record. */
    mov rcx, 0x3230304250564248
    mov [rbx], rcx
    mov qword ptr [rbx + 8], 6
    mov [rbx + 16], r15
    mov [rbx + 24], r13
    mov [r14 + 3072], rbx
    jmp runtime_batch_ensure_invalid
runtime_batch_ensure_create_failed:
    mov rbp, rax
    mov rdi, rbx
    mov esi, 8192
    mov eax, 11
    syscall
    mov rax, rbp
    jmp runtime_batch_ensure_done
runtime_batch_ensure_invalid:
    mov rax, -22
runtime_batch_ensure_done:
    add rsp, 8
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret

/* rdi/rsi=START borrow; r15=extra. Output aliases Batch slot0 until the
 * gateway copies it. Neither a subsequent caller nor publisher may reuse it. */
runtime_grow_batch_owned:
    push rbp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub rsp, 40
    mov [rsp], rdi
    mov [rsp + 8], rsi
    mov qword ptr [rsp + 24], 0
    mov r14, r15
    lea rbp, [r14 + 512 + 35 * 64]
    mov rbx, [r14 + 8]
    add rbx, 35 * 64
    cmp qword ptr [rbp], 0
    jne runtime_batch_owned_early_invalid
    cmp qword ptr [rbp + 8], 0
    jne runtime_batch_owned_early_invalid
    mov qword ptr [rbp], 1
    mov qword ptr [rsp + 24], 1
    mov qword ptr [rbx + 48], 0
    mov qword ptr [rbx + 56], 0
    call runtime_batch_ensure
    cmp rax, -4095
    jae runtime_batch_owned_resource
    mov r13, rax
    mov r15, [r13 + 16]
    mov rdi, r13
    call runtime_batch_view_refresh
    test eax, eax
    jnz runtime_batch_owned_invalid
    mov rdi, [rsp]
    mov rsi, [rsp + 8]
    call batch_call_run
runtime_batch_owned_completed_call:
    mov r12, rax
    mov rdi, r13
    call runtime_batch_view_store
    test eax, eax
    jnz runtime_batch_owned_invalid
    cmp r12d, 0xfffffff0
    jne runtime_batch_owned_reply
    mov rdi, r13
    call runtime_batch_view_refresh
    test eax, eax
    jnz runtime_batch_owned_invalid
    mov esi, 1
    call batch_call_resume /* Exact wait4 join, not a replay of START. */
    jmp runtime_batch_owned_completed_call
runtime_batch_owned_reply:
    mov eax, r12d
    cmp rax, r12
    jne runtime_batch_owned_invalid
    mov [rbx + 48], rax
    mov rdx, [r15 + 8]
    mov rcx, [rdx + 8]
    mov [rbx + 8], rcx
    mov rcx, [rdx + 16]
    mov [rbx + 16], rcx
    mov rcx, [rdx + 24]
    mov [rbx + 32], rcx
    mov rcx, [rdx + 32]
    mov [rbx + 40], rcx
    cmp eax, 0xffff0000
    jae runtime_batch_owned_native_error
    cmp eax, 64
    jne runtime_batch_owned_invalid
    cmp qword ptr [rdx + 40], 64
    jne runtime_batch_owned_invalid
    mov rdx, [rbx + 32]
    mov rax, 0x3230305241434248 /* HBCAR002 */
    cmp [rdx], rax
    jne runtime_batch_owned_invalid
    cmp qword ptr [rdx + 56], 0
    jne runtime_batch_owned_invalid
    cmp qword ptr [rdx + 8], 2
    je runtime_batch_owned_unowned_wait
    mov rax, [rdx + 40]
    add rax, 64
    jc runtime_batch_owned_invalid
    cmp rax, [rbx + 40]
    ja runtime_batch_owned_invalid
    mov [rbx + 56], rax
    mov eax, 64
    jmp runtime_batch_owned_record
runtime_batch_owned_unowned_wait:
    mov eax, 0xffffffcb
    jmp runtime_batch_owned_error
runtime_batch_owned_native_error:
    mov eax, r12d
    jmp runtime_batch_owned_error
runtime_batch_owned_resource:
    mov eax, 0xfffffffc
    jmp runtime_batch_owned_error
runtime_batch_owned_invalid:
    mov eax, 0xfffffff8
runtime_batch_owned_error:
    mov qword ptr [rbx + 56], 0
runtime_batch_owned_record:
    mov [rbx + 48], rax
    mov [rsp + 16], rax
    mov r15, r14
    mov r12, rbp
    mov ebp, 35
    mov edi, 1
    call runtime_grow_trace
    mov rbp, r12
    cmp qword ptr [rsp + 24], 0
    je runtime_batch_owned_return
    mov qword ptr [rbp], 0
runtime_batch_owned_return:
    mov rax, [rsp + 16]
    jmp runtime_batch_owned_done
runtime_batch_owned_early_invalid:
    mov eax, 0xfffffff8
runtime_batch_owned_done:
    add rsp, 40
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret

/* Caller output is consumed, all workers joined, and no request borrow remains.
 * This precedes View retirement and any process-global History teardown. */
runtime_grow_batch_release:
    push rbx
    push r12
    push r13
    mov r12, r15
    mov rbx, [r15 + 3072]
    test rbx, rbx
    jz runtime_batch_release_empty
    cmp qword ptr [r15 + 512 + 35 * 64], 0
    jne runtime_batch_release_invalid
    cmp qword ptr [r15 + 520 + 35 * 64], 0
    jne runtime_batch_release_invalid
    cmp qword ptr [r15 + 512 + 33 * 64], 0
    jne runtime_batch_release_invalid
    cmp qword ptr [r15 + 520 + 33 * 64], 0
    jne runtime_batch_release_invalid
    mov rdi, rbx
    call runtime_batch_view_retire
    test eax, eax
    jnz runtime_batch_release_done
    mov rdi, rbx
    mov esi, 8192
    mov eax, 11
    syscall
    test rax, rax
    jnz runtime_batch_release_done
    mov qword ptr [r12 + 3072], 0
    mov rdi, [r12 + 8]
    add rdi, 35 * 64 + 8
    xor eax, eax
    mov ecx, 7
    rep stosq
runtime_batch_release_empty:
    xor eax, eax
    jmp runtime_batch_release_done
runtime_batch_release_invalid:
    mov eax, 0xfffffff8
runtime_batch_release_done:
    pop r13
    pop r12
    pop rbx
    ret

/* rdi=process fence hub. Preserve rdi for its existing destroy call. */
runtime_batch_global_release:
    push rbx
    push r12
    push r15
    mov r12, rdi
    cmp qword ptr [r12 + 40], 0
    jne runtime_batch_global_invalid
    mov r15, [r12 + 256]
    test r15, r15
    jz runtime_batch_global_empty
    call batch_engine_retire
    test eax, eax
    jnz runtime_batch_global_done
    call batch_engine_free_maps
    mov qword ptr [r12 + 256], 0
runtime_batch_global_empty:
    xor eax, eax
    jmp runtime_batch_global_done
runtime_batch_global_invalid:
    mov eax, 0xfffffff8
runtime_batch_global_done:
    mov rdi, r12
    pop r15
    pop r12
    pop rbx
    ret

.balign 8
runtime_batch_images:
    .zero 176 /* 22 fixed addresses patched by the executed HIA image packer. */
