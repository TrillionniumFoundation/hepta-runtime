# Queue decisions are HIA; this boundary owns clock, mutex, growth and wake.
policy_run:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp, 312
    mov r12, rdi
    mov r13, rsi
    mov r14, rdx
    mov r15, rcx
    cmp r13, 128
    jne contract_fail
    mov edi, 1
    lea rsi, [rsp + 288]
    mov eax, 228
    syscall
    test rax, rax
    jnz io_fail
    mov rax, [rsp + 288]
    mov [r12 + 48], rax
    mov rax, [rsp + 296]
    mov [r12 + 56], rax
    mov rax, [rsp + 288]
    mov [r12 + 64], rax
    mov rax, [rsp + 296]
    mov [r12 + 72], rax
    mov eax, [r15 + 112]
    mov [r12 + 96], rax
    mov rax, [r12 + 8]
    cmp rax, 4
    je policy_private
    cmp rax, 5
    je policy_private
    cmp rax, 12
    je policy_private
    cmp rax, 1
    je policy_preflight
    cmp rax, 2
    jne policy_lock
policy_preflight:
    cmp qword ptr [r12 + 16], 0
    jne contract_fail
    mov [rsp + 8], rax
    mov [r12 + 16], rax
    mov qword ptr [r12 + 8], 13
    mov rdi, r12
    mov esi, 128
    mov rdx, r14
    mov ecx, 64
    lea r8, [rsp + 32]
    mov r9d, 256
    call qword ptr [r15 + 24]
    cmp eax, 64
    jne contract_fail
    mov rax, [rsp + 8]
    mov [r12 + 8], rax
    mov qword ptr [r12 + 16], 0
    cmp qword ptr [r14 + 16], 0
    je policy_lock
    cmp qword ptr [r14 + 16], 6
    jne contract_fail
    mov eax, 64
    jmp policy_return
policy_lock:
    mov rdi, r15
    call mutex_lock
    inc qword ptr [r15 + 40]
    cmp qword ptr [r15 + 40], 1
    jne contract_fail
    mov edi, 1
    lea rsi, [rsp + 288]
    mov eax, 228
    syscall
    test rax, rax
    jnz io_fail
    mov rax, [rsp + 288]
    mov [r12 + 64], rax
    mov rax, [rsp + 296]
    mov [r12 + 72], rax
    mov eax, [r15 + 112]
    mov [r12 + 96], rax
policy_invoke:
    mov edi, 1
    lea rsi, [rsp + 288]
    mov eax, 228
    syscall
    test rax, rax
    jnz io_fail
    mov rax, [rsp + 288]
    mov [r12 + 80], rax
    mov rax, [rsp + 296]
    mov [r12 + 88], rax
    inc qword ptr [r15 + 32]
    jz contract_fail
    mov rdi, r12
    mov rsi, r13
    mov rdx, r14
    mov ecx, 64
    mov r8, qword ptr [r15 + 8]
    mov r9, qword ptr [r15 + 16]
    call qword ptr [r15 + 24]
    mov edx, eax
    cmp rax, rdx
    jne contract_fail
    cmp eax, 64
    jne contract_fail
    mov rax, 0x313030524c415248
    cmp qword ptr [r14], rax
    jne contract_fail
    cmp qword ptr [r14 + 16], 2
    jne policy_success
    mov rax, qword ptr [r14 + 8]
    cmp rax, 1
    je policy_growth
    cmp rax, 2
    jne contract_fail
policy_growth:
    cmp r13, 128
    jb contract_fail
    cmp qword ptr [r12 + 8], rax
    jne contract_fail
    cmp qword ptr [r14 + 24], 0
    jne contract_fail
    mov rdi, qword ptr [r14 + 32]
    cmp rdi, qword ptr [r15 + 16]
    jbe contract_fail
    mov rax, qword ptr [r15 + 16]
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
    mov rsi, qword ptr [r15 + 8]
    mov rcx, qword ptr [r15 + 16]
    rep movsb
    mov rdi, qword ptr [r15 + 8]
    mov rsi, qword ptr [r15 + 16]
    add rsi, 4096
    mov qword ptr [r15 + 8], rbx
    mov qword ptr [r15 + 16], rbp
    mov eax, 11
    syscall
    test rax, rax
    jnz io_fail
    jmp policy_invoke
policy_success:
    mov qword ptr [rsp + 24], 0
    mov eax, [r14 + 56]
    cmp [r15 + 120], eax
    je policy_no_notification
    mov [r15 + 120], eax
    mov qword ptr [rsp + 24], 1
policy_no_notification:
    dec qword ptr [r15 + 40]
    jnz contract_fail
    mov rdi, r15
    call mutex_unlock
    cmp qword ptr [rsp + 24], 0
    je policy_done
    lea rdi, [r15 + 120]
    call wake_all
policy_done:
    mov eax, 64
policy_return:
    add rsp, 312
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret
wake_all:
    mov esi, 129
    mov edx, 0x7fffffff
    xor r10d, r10d
    xor r8d, r8d
    xor r9d, r9d
    mov eax, 202
    syscall
    test rax, rax
    js contract_fail
    ret

policy_private:
    mov rdi, r12
    mov esi, 128
    mov rdx, r14
    mov ecx, 64
    lea r8, [rsp + 32]
    mov r9d, 256
    call qword ptr [r15 + 24]
    cmp eax, 64
    jne contract_fail
    jmp policy_return
