/* Callable boundary around the unchanged original-stage atomic HIA owner. */
.intel_syntax noprefix
.section .text
batch_atomic_invoke:
    push rbp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub rsp, 280
    mov [rsp + 256], rdi
    mov [rsp + 264], rsi
    mov rbx, [r15 + 8]
    add rbx, 19 * 64
    mov rbp, [rbx + 48]
    test rbp, rbp
    jnz batch_atomic_installed
    mov edi, 4096
    call view_allocate
    cmp rax, -4095
    jae batch_atomic_install_resource
    mov rbp, rax
    mov [rbx + 48], rax
batch_atomic_installed:
    mov [rbp], rbx
    mov [rbp + 8], r15
    mov [rbp + 72], rsp
    mov rax, [rsp + 256]
    mov [rbp + 16], rax
    mov rcx, [rsp + 264]
    mov [rbp + 24], rcx
    cmp rcx, 64
    jb batch_atomic_storage_ready
    sub rcx, 64
    mov rdx, [rax + 16]
    cmp rdx, rcx
    ja batch_atomic_storage_ready
    mov [rsp + 272], rdx
    imul rdx, rdx, 5
    jo batch_atomic_install_resource
    add rdx, 4096
    jc batch_atomic_install_resource
    mov rdi, rbx
    mov esi, 1
    call batch_grow
    test rax, rax
    jnz batch_atomic_install_resource
    mov rdx, [rsp + 272]
    imul rdx, rdx, 3
    jo batch_atomic_install_resource
    add rdx, 512
    jc batch_atomic_install_resource
    mov rdi, rbx
    mov esi, 2
    call batch_grow
    test rax, rax
    jnz batch_atomic_install_resource
batch_atomic_storage_ready:
    mov r12, [rbx + 8]
    mov rax, [rbx + 16]
    mov [rbp + 40], rax
    mov rax, [r12 + 8]
    mov [rbp + 48], rax
    mov rdi, r12
    xor eax, eax
    mov ecx, 128
    rep stosq
    mov rax, [rbp + 48]
    mov [r12 + 8], rax
    mov r13, -1
    xor ebx, ebx
    mov qword ptr [rbp + 80], 0
batch_atomic_invoke_policy:
    mov rax, [r15 + 728]
    mov [r12 + 136], rax
    mov rax, [rbp]
    mov rdi, [rbp + 16]
    mov rsi, [rbp + 24]
    mov rdx, [rax + 24]
    mov rcx, [rax + 32]
    mov r8, r12
    mov r9, [rbp + 40]
    call qword ptr [rax]
    mov edx, eax
    cmp rax, rdx
    jne batch_atomic_worker_contract
    cmp eax, 0xfffffff0
    jne batch_atomic_policy_done
    mov rax, 0x3158465441414948
    cmp [r12 + 256], rax
    jne batch_atomic_worker_contract
    inc rbx
    jz batch_atomic_worker_contract
    cmp [r12 + 264], rbx
    jne batch_atomic_worker_contract
    cmp [r12 + 144], rbx
    jne batch_atomic_worker_contract
    mov r14, [r12 + 272]
    cmp [r12], r14
    jne batch_atomic_worker_contract
    cmp r14, 1
    jb batch_atomic_worker_contract
    cmp r14, 11
    ja batch_atomic_worker_contract
    mov rax, [r12 + 304]
    or rax, [r12 + 312]
    or rax, [r12 + 320]
    or rax, [r12 + 328]
    or rax, [r12 + 336]
    or rax, [r12 + 344]
    jnz batch_atomic_worker_contract
    cmp qword ptr [r12 + 56], 1024
    jne batch_atomic_worker_contract
    mov rax, [rbp + 24]
    sub rax, 64
    cmp [r12 + 40], rax
    ja batch_atomic_worker_contract
    mov rax, [r12 + 40]
    add rax, 1025
    jc batch_atomic_worker_contract
    cmp rax, [r12 + 64]
    jne batch_atomic_worker_contract
    add rax, [r12 + 72]
    jc batch_atomic_worker_contract
    cmp rax, [rbp + 40]
    jae batch_atomic_worker_contract
    cmp byte ptr [r12 + rax], 0
    jne batch_atomic_worker_contract
    mov rax, [r12 + 40]
    cmp byte ptr [r12 + rax + 1024], 0
    jne batch_atomic_worker_contract
    call batch_atomic_before_next_effect
    test rax, rax
    js batch_atomic_worker_contract
    cmp r14, 1
    je batch_atomic_stat_path
    cmp r14, 2
    je batch_atomic_stat_probe
    cmp r14, 3
    je batch_atomic_stat_path
    cmp r14, 10
    je batch_atomic_stat_path
    cmp r14, 11
    je batch_atomic_stat_probe_fallback
    cmp r14, 4
    je batch_atomic_open_temp
    cmp r14, 5
    je batch_atomic_write_temp
    cmp r14, 6
    je batch_atomic_close_temp
    cmp r14, 7
    je batch_atomic_chmod_temp
    cmp r14, 8
    je batch_atomic_rename_temp
    jmp batch_atomic_unlink_temp
batch_atomic_policy_done:
    call batch_atomic_observe_terminal
    cmp r13, -1
    jne batch_atomic_worker_contract
    jmp batch_atomic_done
batch_atomic_worker_contract:
    mov rsp, [rbp + 72]
    mov rdi, r13
    mov r13, -1
    test rdi, rdi
    js batch_atomic_contract_closed
    mov eax, 3
    syscall
batch_atomic_contract_closed:
    mov eax, 0xfffffff8
    jmp batch_atomic_done
batch_atomic_install_resource:
    mov eax, 0xfffffffc
batch_atomic_done:
    mov rbx, [r15 + 8]
    mov [rbx + 19 * 64 + 40], rax
    add rsp, 280
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret
