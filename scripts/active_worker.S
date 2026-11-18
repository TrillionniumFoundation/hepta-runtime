# Fixed transport only: actor routing, immutable request span and result framing.
run_command:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp, 24
    mov r15, rdi
    mov rax, [r15 + 272]
    cmp rax, [r15 + 144]
    jne contract_fail
    mov rsi, [r15 + 280]
    cmp rsi, 64
    jb contract_fail
    cmp rsi, 320
    ja contract_fail
    lea rcx, [rsi + 320]
trailing_zero:
    cmp rcx, 640
    jae request_ready
    cmp byte ptr [r15 + rcx], 0
    jne contract_fail
    inc rcx
    jmp trailing_zero
request_ready:
    lea rdi, [r15 + 320]
    lea rdx, [r15 + 672]
    mov rcx, [r15 + 64]
    call policy_run
    cmp eax, 64
    jne contract_fail
    mov rax, 0x3130304f41415248
    mov [r15 + 640], rax
    mov rax, [r15 + 264]
    mov [r15 + 648], rax
    mov rax, [r15 + 272]
    mov [r15 + 656], rax
    mov qword ptr [r15 + 664], 64
    add rsp, 24
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret
