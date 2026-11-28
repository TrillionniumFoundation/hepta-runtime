/* Fixed same-session aliases into the already constructed view engine.
 * These private slots cannot be supplied by MCP ids, arguments or metadata.
 * Source-owned scope/lease/cache functions decide all lifetime and mutations. */
.intel_syntax noprefix
.section .text
.global runtime_text_install_caller
runtime_text_install_caller:
    push rbx
    push r12
    push r13
    push r14
    sub rsp, 56
    mov r14, r15
    mov r12, rbx
    call runtime_grow_view_ensure
    cmp rax, -4095
    jae runtime_text_install_resource
    mov rdx, [rax + 8]
    mov rdx, [rdx + 8] /* Installed view caller's own private workspace. */
    cmp qword ptr [rdx + 16], 1
    jne runtime_text_install_invalid
    cmp qword ptr [rdx + 24], 1
    jne runtime_text_install_invalid
    cmp qword ptr [rdx + 56], 0
    jne runtime_text_install_invalid
    mov rax, [rdx + 40]
    test rax, rax
    jz runtime_text_install_invalid
    mov [rsp + 8], rax
    mov rax, [rdx + 48]
    test rax, rax
    jz runtime_text_install_invalid
    mov [rsp + 16], rax
    mov rax, 0x3230494c43455448 /* HTECLI02 */
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
    jne runtime_text_install_invalid
    mov rdx, [r12 + 32]
    mov rax, 0x3230524c43455448 /* HTECLR02 */
    cmp [rdx], rax
    jne runtime_text_install_invalid
    mov rax, [rsp + 8]
    cmp [rdx + 8], rax
    jne runtime_text_install_invalid
    mov rax, [rsp + 16]
    cmp [rdx + 16], rax
    jne runtime_text_install_invalid
    cmp qword ptr [rdx + 24], 0
    jne runtime_text_install_invalid
    mov qword ptr [r14 + 240], 1
    xor eax, eax
    jmp runtime_text_install_done
runtime_text_install_resource:
    mov eax, 0xfffffffc
    jmp runtime_text_install_done
runtime_text_install_invalid:
    mov eax, 0xffffffff
runtime_text_install_done:
    add rsp, 56
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

