/* Trusted installation of process-global history/locks and session-owned
 * cache/lease. The dispatcher serializes owner invocations; only read/atomic
 * workers run concurrently and cannot enter these shared owners. Opaque native
 * engine pointers never come from JSON, protocol request IDs or a tool frame. */
.intel_syntax noprefix
.section .text
.global batch_engine_bind_shared
batch_engine_bind_shared:
    push rbp
    push rbx
    push r12
    push r13
    push r14
    mov r12, rdi
    mov r13, rsi
    mov r14d, edx
    cmp r14d, 1
    ja batch_bind_invalid
    cmp qword ptr [r15 + 800], 0
    jne batch_bind_invalid
    cmp qword ptr [r15 + 808], 0
    jne batch_bind_invalid
    cmp qword ptr [r15 + 840], 0
    jne batch_bind_invalid
    mov rbx, [r15 + 8]
    mov rax, [rbx + 8]
    cmp qword ptr [rax + 8], 0
    jne batch_bind_invalid
    cmp qword ptr [rax + 16], 0
    jne batch_bind_invalid
    test r12, r12
    jz batch_bind_session_check
    cmp r12, r15
    je batch_bind_invalid
    cmp qword ptr [r12 + 800], 0
    jne batch_bind_invalid
    cmp qword ptr [r12 + 840], 0
    jne batch_bind_invalid
    cmp qword ptr [r12 + 816], -1
    je batch_bind_invalid
    mov rax, [r12]
    cmp [r15], rax
    jne batch_bind_invalid
batch_bind_session_check:
    test r13, r13
    jz batch_bind_start
    cmp r13, r15
    je batch_bind_invalid
    cmp qword ptr [r13 + 808], 0
    jne batch_bind_invalid
    cmp qword ptr [r13 + 840], 0
    jne batch_bind_invalid
    cmp qword ptr [r13 + 824], -1
    je batch_bind_invalid
    mov rax, [r13]
    cmp [r15], rax
    jne batch_bind_invalid
batch_bind_start:
    lea rdi, [r15 + 256]
    xor eax, eax
    mov ecx, 8
    rep stosq
    lea rdi, [r15 + 256]
    mov rax, 0x3230514c41434248
    mov [rdi], rax
    mov qword ptr [rdi + 8], 6
    mov esi, 64
    xor edx, edx
    call batch_dispatch
    cmp eax, 64
    jne batch_bind_invalid
    test r12, r12
    jz batch_bind_session
    lea rdi, [r15 + 256]
    mov rax, 0x3130515453494848
    mov [rdi], rax
    mov qword ptr [rdi + 8], 4
    mov esi, 64
    mov edx, 17
    call batch_dispatch
    cmp eax, 64
    jne batch_bind_invalid
    lea rdi, [r15 + 256]
    mov rax, 0x314b434f4c465248
    mov [rdi], rax
    mov qword ptr [rdi + 8], 9
    mov esi, 64
    mov edx, 18
    call batch_dispatch
    cmp eax, 64
    jne batch_bind_invalid
    mov [r15 + 800], r12
    inc qword ptr [r12 + 816]
batch_bind_session:
    test r13, r13
    jz batch_bind_install
    lea rdi, [r15 + 256]
    mov rax, 0x313030514c435248
    mov [rdi], rax
    mov qword ptr [rdi + 8], 3
    mov rax, [r15 + 112]
    mov [rdi + 16], rax
    mov rax, [r15 + 120]
    mov [rdi + 24], rax
    mov esi, 64
    mov edx, 7
    call batch_dispatch
    cmp eax, 64
    jne batch_bind_invalid
    mov rax, [rbx + 7 * 64 + 8]
    mov [r15 + 1024], rax
    mov rax, [rbx + 7 * 64 + 16]
    mov [r15 + 1032], rax
    mov rax, [rbx + 8 * 64 + 8]
    mov [r15 + 1040], rax
    mov rax, [rbx + 8 * 64 + 16]
    mov [r15 + 1048], rax
    mov [r15 + 808], r13
    inc qword ptr [r13 + 824]
    mov rax, [r13 + 112]
    mov [r15 + 112], rax
    mov rax, [r13 + 120]
    mov [r15 + 120], rax
    call batch_shared_load
batch_bind_install:
    lea rdi, [r15 + 256]
    xor eax, eax
    mov ecx, 8
    rep stosq
    lea rdi, [r15 + 256]
    mov rax, 0x3230494e49434248
    mov [rdi], rax
    mov [rdi + 8], r14
    test r14d, r14d
    jz batch_bind_install_fields
    mov rax, [r15 + 112]
    mov [rdi + 16], rax
    mov rax, [r15 + 120]
    mov [rdi + 24], rax
batch_bind_install_fields:
    mov qword ptr [rdi + 32], 10
    mov qword ptr [rdi + 40], 7
    mov esi, 64
    xor edx, edx
    call batch_dispatch
    cmp eax, 64
    jne batch_bind_invalid
    xor eax, eax
    jmp batch_bind_return
batch_bind_invalid:
    mov eax, 0xfffffff8
batch_bind_return:
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret

/* Refresh only the shared workspace fields; borrowed output stays local. */
batch_shared_load:
    mov rax, [r15 + 808]
    test rax, rax
    jz batch_shared_load_done
    mov rax, [rax + 8]
    mov rcx, [r15 + 8]
    mov rdx, [rax + 7 * 64 + 8]
    mov [rcx + 7 * 64 + 8], rdx
    mov rdx, [rax + 7 * 64 + 16]
    mov [rcx + 7 * 64 + 16], rdx
    mov rdx, [rax + 7 * 64 + 48]
    mov [rcx + 7 * 64 + 48], rdx
    mov rdx, [rax + 7 * 64 + 56]
    mov [rcx + 7 * 64 + 56], rdx
    mov rdx, [rax + 8 * 64 + 8]
    mov [rcx + 8 * 64 + 8], rdx
    mov rdx, [rax + 8 * 64 + 16]
    mov [rcx + 8 * 64 + 16], rdx
batch_shared_load_done:
    ret
batch_shared_store:
    mov rax, [r15 + 808]
    test rax, rax
    jz batch_shared_store_done
    mov rax, [rax + 8]
    mov rcx, [r15 + 8]
    mov rdx, [rcx + 7 * 64 + 8]
    mov [rax + 7 * 64 + 8], rdx
    mov rdx, [rcx + 7 * 64 + 16]
    mov [rax + 7 * 64 + 16], rdx
    mov rdx, [rcx + 7 * 64 + 48]
    mov [rax + 7 * 64 + 48], rdx
    mov rdx, [rcx + 7 * 64 + 56]
    mov [rax + 7 * 64 + 56], rdx
    mov rdx, [rcx + 8 * 64 + 8]
    mov [rax + 8 * 64 + 8], rdx
    mov rdx, [rcx + 8 * 64 + 16]
    mov [rax + 8 * 64 + 16], rdx
batch_shared_store_done:
    ret

batch_shared_scope_invoke:
    push rbx
    push r12
    push r13
    mov rbx, rdi
    mov r12, rsi
    mov r13d, edx
    call batch_shared_load
    mov rdi, rbx
    mov rsi, r12
    mov edx, r13d
    cmp edx, 8
    je batch_shared_scope_cache
    call view_scope_invoke
    jmp batch_shared_scope_return
batch_shared_scope_cache:
    call batch_pure_invoke
batch_shared_scope_return:
    mov rbx, rax
    call batch_shared_store
    mov rax, rbx
    pop r13
    pop r12
    pop rbx
    ret

/* Global owner output is copied before the serialized dispatcher can reuse it.
 * A failed delivery reports RESOURCE, preserving an already completed effect. */
batch_shared_global_invoke:
    push rbx
    push r12
    push r13
    push r14
    sub rsp, 8
    mov r12, r15
    mov r14d, edx
    mov r15, [r15 + 800]
    call batch_pure_invoke
    mov r13, rax
    mov rbx, r14
    shl rbx, 6
    add rbx, [r15 + 8]
    mov r15, r12
    mov r12, r14
    shl r12, 6
    add r12, [r15 + 8]
    cmp r13d, 0xffff0000
    jae batch_shared_global_return
    cmp r13, [rbx + 32]
    ja batch_shared_global_invalid
    mov rdi, r12
    mov esi, 2
    mov rdx, r13
    call batch_grow
    test rax, rax
    js batch_shared_global_resource
    mov rdi, [r12 + 24]
    mov rsi, [rbx + 24]
    mov rcx, r13
    rep movsb
batch_shared_global_return:
    mov [r12 + 40], r13
    mov rax, r13
    add rsp, 8
    pop r14
    pop r13
    pop r12
    pop rbx
    ret
batch_shared_global_invalid:
    mov r13d, 0xfffffff8
    jmp batch_shared_global_return
batch_shared_global_resource:
    mov r13d, 0xfffffffc
    jmp batch_shared_global_return
