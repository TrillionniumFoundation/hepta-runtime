/* Fixed same-session aliases into the already constructed view engine.
 * These private slots cannot be supplied by MCP ids, arguments or metadata.
 * Source-owned scope/lease/cache functions decide all lifetime and mutations. */
.intel_syntax noprefix
.section .text
.global runtime_filesystem_install_caller
.global runtime_grow_view_proxy_owned
runtime_filesystem_install_caller:
    push rbx
    push r12
    push r13
    push r14
    sub rsp, 56
    mov r14, r15
    mov r12, rbx
    call runtime_grow_view_ensure
    cmp rax, -4095
    jae runtime_filesystem_install_resource
    mov rdx, [rax + 8]
    mov rdx, [rdx + 8] /* Installed view caller's own private workspace. */
    cmp qword ptr [rdx + 16], 1
    jne runtime_filesystem_install_invalid
    cmp qword ptr [rdx + 24], 1
    jne runtime_filesystem_install_invalid
    cmp qword ptr [rdx + 56], 0
    jne runtime_filesystem_install_invalid
    mov rax, [rdx + 40]
    test rax, rax
    jz runtime_filesystem_install_invalid
    mov [rsp + 8], rax
    mov rax, [rdx + 48]
    test rax, rax
    jz runtime_filesystem_install_invalid
    mov [rsp + 16], rax
    mov rax, 0x3230494c43534648 /* HFSCLI02 */
    mov [rsp], rax
    mov qword ptr [rsp + 24], 0
    mov rdi, rsp
    mov esi, 32
    mov rdx, [r12 + 32]
    mov rcx, [r12 + 40]
    mov r8, [r12 + 8]
    mov r9, [r12 + 16]
    inc qword ptr [r14 + 128]
    call qword ptr [r12]
    mov edi, 1
    call runtime_grow_trace
    cmp rax, 32
    jne runtime_filesystem_install_invalid
    mov rdx, [r12 + 32]
    mov rax, 0x3230524c43534648 /* HFSCLR02 */
    cmp [rdx], rax
    jne runtime_filesystem_install_invalid
    mov rax, [rsp + 8]
    cmp [rdx + 8], rax
    jne runtime_filesystem_install_invalid
    mov rax, [rsp + 16]
    cmp [rdx + 16], rax
    jne runtime_filesystem_install_invalid
    cmp qword ptr [rdx + 24], 0
    jne runtime_filesystem_install_invalid
    mov qword ptr [r14 + 216], 1
    xor eax, eax
    jmp runtime_filesystem_install_done
runtime_filesystem_install_resource:
    mov eax, 0xfffffffc
    jmp runtime_filesystem_install_done
runtime_filesystem_install_invalid:
    mov eax, 0xffffffff
runtime_filesystem_install_done:
    add rsp, 56
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

/* r8 is one of four statically selected extra slots 29..32. */
runtime_grow_view_proxy_owned:
    push rbp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub rsp, 56
    mov [rsp], r8
    mov qword ptr [rsp + 16], 0
    mov r12, rdi
    mov r13, rsi
    mov r14, r15
    mov rax, r8
    sub rax, 29
    cmp rax, 3
    ja runtime_grow_proxy_early_invalid
    lea rdx, [rip + runtime_grow_proxy_targets]
    movzx edx, byte ptr [rdx + rax]
    mov [rsp + 8], rdx
    shl r8, 6
    mov rbx, [r14 + 8]
    add rbx, r8
    lea rbp, [r14 + r8 + 512]
    cmp qword ptr [rbp], 0
    jne runtime_grow_proxy_early_invalid
    cmp qword ptr [rbp + 8], 0
    jne runtime_grow_proxy_early_invalid
    mov qword ptr [rbp], 1
    mov qword ptr [rsp + 16], 1
    mov qword ptr [rbx + 48], 0
    mov qword ptr [rbx + 56], 0
    call runtime_grow_view_ensure
    cmp rax, -4095
    jae runtime_grow_proxy_resource
    mov r15, rax
    mov edx, dword ptr [rsp + 8]
    mov rdi, r12
    mov rsi, r13
    inc qword ptr [r14 + 128]
    cmp edx, 5
    je runtime_grow_proxy_key
    cmp edx, 8
    je runtime_grow_proxy_cache
    call view_scope_invoke
    jmp runtime_grow_proxy_completed
runtime_grow_proxy_key:
    call view_key_invoke
    jmp runtime_grow_proxy_completed
runtime_grow_proxy_cache:
    call view_pure_invoke
runtime_grow_proxy_completed:
    mov edx, eax
    cmp rax, rdx
    jne runtime_grow_proxy_invalid
    mov [rsp + 24], rax
    mov rdx, [rsp + 8]
    shl rdx, 6
    add rdx, [r15 + 8]
    cmp rax, [rdx + 40]
    jne runtime_grow_proxy_invalid
    mov rcx, [rdx + 8]
    mov [rbx + 8], rcx
    mov rcx, [rdx + 16]
    mov [rbx + 16], rcx
    mov rcx, [rdx + 24]
    mov [rbx + 32], rcx
    mov rcx, [rdx + 32]
    mov [rbx + 40], rcx
    mov [rbx + 48], rax
    cmp eax, 0xffff0000
    jae runtime_grow_proxy_trace
    cmp rax, rcx
    ja runtime_grow_proxy_invalid
    mov [rbx + 56], rax
runtime_grow_proxy_trace:
    mov r15, r14
    mov [rsp + 32], rbp
    mov rbp, [rsp]
    mov edi, 1
    call runtime_grow_trace
    mov rbp, [rsp + 32]
    jmp runtime_grow_proxy_done
runtime_grow_proxy_resource:
    mov eax, 0xfffffffc
    jmp runtime_grow_proxy_error
runtime_grow_proxy_invalid:
    mov eax, 0xffffffff
runtime_grow_proxy_error:
    mov [rbx + 48], rax
    mov qword ptr [rbx + 56], 0
    mov [rsp + 24], rax
runtime_grow_proxy_done:
    cmp qword ptr [rsp + 16], 0
    je runtime_grow_proxy_return
    mov qword ptr [rbp], 0
runtime_grow_proxy_return:
    mov rax, [rsp + 24]
    jmp runtime_grow_proxy_epilogue
runtime_grow_proxy_early_invalid:
    mov eax, 0xffffffff
runtime_grow_proxy_epilogue:
    add rsp, 56
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret
runtime_grow_proxy_targets:
    .byte 6, 5, 7, 8
