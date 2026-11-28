/* Callable boundary to the existing installed execution controller graph.
 * Its legacy image profile is explicit. Completed results survive output
 * growth; the actual controller is never replayed merely to copy its result. */
.intel_syntax noprefix
.section .text
.global runtime_execution_span
runtime_execution_span:
    push rbp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub rsp, 72
    mov [rsp], rdi
    mov [rsp + 8], rsi
    mov [rsp + 16], rdx
    mov [rsp + 24], rcx
    mov [rsp + 32], r8
    mov [rsp + 40], r9
    mov rbx, r8
    cmp r9, 64
    jb runtime_execution_bad
    cmp rcx, 32
    jb runtime_execution_bad
    mov rax, 0x3230535758455248 /* HREXWS02, private delivery state. */
    cmp qword ptr [rbx], 0
    jne runtime_execution_existing
    mov [rbx], rax
    mov qword ptr [rbx + 8], 0
runtime_execution_existing:
    cmp [rbx], rax
    jne runtime_execution_bad
    mov r15, [r15 + 24]
    test r15, r15
    jz runtime_execution_bad
    cmp qword ptr [rbx + 8], 1
    je runtime_execution_pending
    cmp qword ptr [rbx + 8], 0
    jne runtime_execution_bad
    cmp qword ptr [r15 + 784], 0
    jne runtime_execution_bad
    cmp qword ptr [r15 + 872], 0
    jne runtime_execution_bad
    cmp qword ptr [r15 + 912], 0
    jne runtime_execution_bad
    cmp rsi, 26
    jb runtime_execution_bad
    cmp rsi, 67108864 /* Same retained execution-controller profile. */
    ja runtime_execution_resource
    mov rax, 0x3130514552535848 /* HXSREQ01 */
    cmp [rdi], rax
    jne runtime_execution_bad
    cmp qword ptr [rdi + 8], 1
    jne runtime_execution_bad
    lea rax, [rsi - 24]
    cmp [rdi + 16], rax
    jne runtime_execution_bad
    mov [rbx + 24], rdi
    mov [rbx + 32], rsi
    mov qword ptr [rbx + 8], 2
    mov [r15 + 880], rsi
    mov rcx, rsi
    mov rsi, rdi
    lea rdi, [r15 + MCP_WORK + 33554432]
    rep movsb
    mov qword ptr [r15 + 912], 1
    mov qword ptr [r15 + 872], 1
    jmp execution_resume

/* Entered only from the original execution_completed after it clears 872. */
runtime_execution_completed:
    mov qword ptr [r15 + 912], 0
    mov rbx, [rsp + 32]
    cmp qword ptr [rbx + 8], 2
    jne runtime_execution_bad
    mov [rbx + 16], rax
    mov qword ptr [rbx + 8], 1
    jmp runtime_execution_deliver
runtime_execution_pending:
    cmp [rbx + 24], rdi
    jne runtime_execution_bad
    cmp [rbx + 32], rsi
    jne runtime_execution_bad
runtime_execution_deliver:
    mov rax, [rbx + 16]
    cmp eax, 0xffff0000
    jae runtime_execution_terminal
    cmp rax, 32
    jb runtime_execution_bad
    cmp rax, 67108864
    ja runtime_execution_bad
    lea rsi, [r15 + MCP_WORK + 100667392]
    mov rdx, 0x31304d4746435248 /* HRCFGM01 */
    cmp [rsi], rdx
    jne runtime_execution_bad
    cmp qword ptr [rsi + 8], 3
    ja runtime_execution_bad
    lea rdx, [rax - 32]
    cmp [rsi + 24], rdx
    jne runtime_execution_bad
    cmp rax, [rsp + 24]
    ja runtime_execution_output_growth
    mov rdi, [rsp + 16]
    mov rcx, rax
    rep movsb
runtime_execution_terminal:
    mov qword ptr [rbx + 8], 0
    jmp runtime_execution_restore
runtime_execution_output_growth:
    mov rdx, [rsp + 16]
    mov rcx, 0x3230305357524748 /* HGRWS002 */
    mov [rdx], rcx
    mov qword ptr [rdx + 8], 2
    mov [rdx + 16], rax
    mov qword ptr [rdx + 24], 0
    mov eax, 0xffffffd0
    jmp runtime_execution_restore
runtime_execution_resource:
    mov eax, 0xfffffffc
    jmp runtime_execution_restore
runtime_execution_bad:
    mov eax, 0xffffffff
runtime_execution_restore:
    add rsp, 72
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret
