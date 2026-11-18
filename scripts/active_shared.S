# One native custody gate serializes every lease, registry and arena mutation.
# The HIA owner implements all lifetime, key, pruning and poison decisions.
policy_run:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp, 24
    mov r12, rdi
    mov r13, rsi
    mov r14, rdx
    mov r15, rcx
    mov rdi, r15
    call mutex_lock
policy_invoke:
    mov rdi, r12
    mov rsi, r13
    mov rdx, r14
    mov ecx, 64
    mov r8, [r15 + 8]
    mov r9, [r15 + 16]
    call qword ptr [r15 + 24]
    cmp rax, 64
    jne contract_fail
    mov rax, 0x3130305241415248
    cmp [r14], rax
    jne contract_fail
    cmp qword ptr [r14 + 8], 2
    jne policy_return
    cmp qword ptr [r14 + 24], 0
    jne contract_fail
    mov rdi, [r14 + 16]
    cmp rdi, [r15 + 16]
    jbe contract_fail
    mov rax, [r15 + 16]
    add rax, rax
    jc memory_fail
    cmp rdi, rax
    cmovb rdi, rax
    call round_capacity
    mov rbp, rax
    mov rdi, rax
    call allocate_guarded
    mov rbx, rax
    mov rdi, rax
    mov rsi, [r15 + 8]
    mov rcx, [r15 + 16]
    rep movsb
    mov rdi, [r15 + 8]
    mov rsi, [r15 + 16]
    add rsi, 4096
    mov [r15 + 8], rbx
    mov [r15 + 16], rbp
    mov eax, 11
    syscall
    test rax, rax
    jnz io_fail
    jmp policy_invoke
policy_return:
    mov rdi, r15
    call mutex_unlock
    mov eax, 64
    add rsp, 24
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret
