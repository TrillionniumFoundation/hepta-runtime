/* Fixed trusted view engine binding. Parent outputs borrow its completed result.
 * No request id, tool parameter, or external frame selects an engine instance. */
.intel_syntax noprefix
.section .text
.global runtime_grow_view_owned
.global runtime_grow_view_release
runtime_grow_view_owned:
    push rbp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub rsp, 24
    mov qword ptr [rsp + 16], 0
    mov r12, rdi
    mov r13, rsi
    mov r14, r15
    mov rbx, [r15 + 8]
    add rbx, 12 * 64
    lea rbp, [r15 + 512 + 12 * 64]
    cmp qword ptr [rbp], 0
    jne runtime_grow_view_invalid
    cmp qword ptr [rbp + 8], 0
    jne runtime_grow_view_invalid
    mov qword ptr [rbp], 1
    mov qword ptr [rsp + 16], 1
    mov qword ptr [rbx + 48], 0
    mov qword ptr [rbx + 56], 0
    call runtime_grow_view_ensure
    cmp rax, -4095
    jae runtime_grow_view_resource
runtime_grow_view_ready:
    mov r15, rax
    mov rdi, r12
    mov rsi, r13
    call view_call_run
    mov edx, eax
    cmp rax, rdx
    jne runtime_grow_view_invalid
    mov [rbx + 48], rax
    mov [rsp], rax
    mov rdx, [r15 + 8]
    mov rcx, [rdx + 24]
    mov [rbx + 32], rcx
    mov rcx, [rdx + 32]
    mov [rbx + 40], rcx
    mov rcx, [rdx + 8]
    mov [rbx + 8], rcx
    mov rcx, [rdx + 16]
    mov [rbx + 16], rcx
    cmp rax, [rdx + 40]
    jne runtime_grow_view_invalid
    cmp eax, 0xffff0000
    jae runtime_grow_view_return
    cmp eax, 32
    jne runtime_grow_view_invalid
    mov rdx, [rbx + 32]
    mov rax, 0x31304d4746435248 /* HRCFGM01 */
    cmp [rdx], rax
    jne runtime_grow_view_invalid
    cmp qword ptr [rdx + 8], 1
    ja runtime_grow_view_invalid
    cmp qword ptr [rdx + 16], 0
    jne runtime_grow_view_invalid
    mov rax, [rdx + 24]
    add rax, 32
    jc runtime_grow_view_invalid
    cmp rax, [rbx + 40]
    ja runtime_grow_view_invalid
    mov [rbx + 56], rax
    jmp runtime_grow_view_return
runtime_grow_view_resource:
    mov eax, 0xfffffffc
    jmp runtime_grow_view_error
runtime_grow_view_invalid:
    mov eax, 0xffffffff
runtime_grow_view_error:
    mov [rbx + 48], rax
    mov [rsp], rax
    mov qword ptr [rbx + 56], 0
runtime_grow_view_return:
    cmp qword ptr [rsp + 16], 0
    je runtime_grow_view_stack
    mov qword ptr [rbp], 0
runtime_grow_view_stack:
    mov rax, [rsp]
    add rsp, 24
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret

.global runtime_grow_view_ensure
/* r15 is the exact session extra engine; the caller cannot select a table. */
runtime_grow_view_ensure:
    mov rax, [r15 + 16]
    test rax, rax
    jnz runtime_grow_view_ensure_done
    sub rsp, 8
    lea rdi, [rip + runtime_grow_view_images]
    mov rsi, [r15 + 32]
    call view_engine_create_wide
    add rsp, 8
    cmp rax, -4095
    jae runtime_grow_view_ensure_done
    mov [r15 + 16], rax
    cmp qword ptr [r15 + 80], 0
    je runtime_grow_view_ensure_done
    mov qword ptr [rax + 96], 1
runtime_grow_view_ensure_done:
    ret

/* The trusted caller has consumed the last output borrow before releasing. */
runtime_grow_view_release:
    push rbx
    push r12
    push r15
    mov r12, r15
    cmp qword ptr [r15 + 3072], 0
    jne runtime_grow_view_release_invalid
    mov rax, [r15 + 16]
    test rax, rax
    jz runtime_grow_view_release_empty
    cmp qword ptr [r15 + 512 + 12 * 64], 0
    jne runtime_grow_view_release_invalid
    cmp qword ptr [r15 + 520 + 12 * 64], 0
    jne runtime_grow_view_release_invalid
    cmp qword ptr [r15 + 512 + 23 * 64], 0
    jne runtime_grow_view_release_invalid
    cmp qword ptr [r15 + 520 + 23 * 64], 0
    jne runtime_grow_view_release_invalid
    mov rdx, [r15 + 8]
    mov rdx, [rdx + 23 * 64 + 8]
    test rdx, rdx
    jz runtime_grow_view_release_proxies
    cmp qword ptr [rdx + 8], 0
    jne runtime_grow_view_release_invalid
    cmp qword ptr [rdx + 416], 0
    jne runtime_grow_view_release_invalid
runtime_grow_view_release_proxies:
    mov ecx, 29
runtime_grow_view_release_proxy_admit:
    mov rdx, rcx
    shl rdx, 6
    cmp qword ptr [r15 + rdx + 512], 0
    jne runtime_grow_view_release_invalid
    cmp qword ptr [r15 + rdx + 520], 0
    jne runtime_grow_view_release_invalid
    inc ecx
    cmp ecx, 33
    jb runtime_grow_view_release_proxy_admit
    mov r15, rax
    cmp qword ptr [r15 + 32], 0
    jne runtime_grow_view_release_destroy
    call view_engine_retire
    test rax, rax
    jnz runtime_grow_view_release_done
runtime_grow_view_release_destroy:
    call view_engine_destroy
    test rax, rax
    jnz runtime_grow_view_release_done
    mov qword ptr [r12 + 16], 0
    mov rdi, [r12 + 8]
    add rdi, 12 * 64 + 8
    xor eax, eax
    mov ecx, 7
    rep stosq
    mov qword ptr [r12 + 216], 0
    mov ebx, 29
runtime_grow_view_release_proxy_clear:
    mov rdi, rbx
    shl rdi, 6
    add rdi, [r12 + 8]
    add rdi, 8
    mov ecx, 7
    rep stosq
    inc ebx
    cmp ebx, 33
    jb runtime_grow_view_release_proxy_clear
runtime_grow_view_release_empty:
    xor eax, eax
    jmp runtime_grow_view_release_done
runtime_grow_view_release_invalid:
    mov eax, 0xffffffff
runtime_grow_view_release_done:
    pop r15
    pop r12
    pop rbx
    ret

.balign 8
runtime_grow_view_images:
    .zero 152
