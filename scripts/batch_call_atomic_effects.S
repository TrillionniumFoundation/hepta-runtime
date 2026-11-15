/* Exact original closed atomic syscall handlers, relocated to a callable private arena. */
.intel_syntax noprefix
.section .text
batch_atomic_stat_path:
    cmp r13, -1
    jne batch_atomic_worker_contract
    cmp qword ptr [r12 + 256 + 24], 1024
    jne batch_atomic_worker_contract
    mov rax, qword ptr [r12 + 40]
    cmp qword ptr [r12 + 256 + 32], rax
    jne batch_atomic_worker_contract
    cmp qword ptr [r12 + 256 + 40], 0
    jne batch_atomic_worker_contract
    lea rdi, [r12 + 1024]
    mov rcx, rax
    call batch_atomic_exact_cstring
    mov rdi, rsp
    xor eax, eax
    mov ecx, 32
    rep stosq
    mov edi, -100
    lea rsi, [r12 + 1024]
    cmp r14, 1
    jne batch_atomic_stat_fallback
    xor edx, edx
    mov r10d, 0xfff
    mov r8, rsp
    mov eax, 332
    syscall
    test rax, rax
    js batch_atomic_effect_error
    movzx eax, word ptr [rsp + 28]
    mov qword ptr [r12 + 256 + 72], rax
    jmp batch_atomic_acknowledge
batch_atomic_stat_fallback:
    mov rdx, rsp
    xor r10d, r10d
    mov eax, 262
    syscall
    test rax, rax
    js batch_atomic_effect_error
    mov eax, dword ptr [rsp + 24]
    mov qword ptr [r12 + 256 + 72], rax
    jmp batch_atomic_acknowledge

batch_atomic_stat_probe:
    cmp r13, -1
    jne batch_atomic_worker_contract
    mov rax, qword ptr [r12 + 256 + 24]
    or rax, qword ptr [r12 + 256 + 32]
    or rax, qword ptr [r12 + 256 + 40]
    jnz batch_atomic_worker_contract
    xor edi, edi
    xor esi, esi
    xor edx, edx
    mov r10d, 0xfff
    xor r8d, r8d
    mov eax, 332
    syscall
    test rax, rax
    js batch_atomic_effect_error
    jmp batch_atomic_acknowledge

batch_atomic_stat_probe_fallback:
    cmp r13, -1
    jne batch_atomic_worker_contract
    mov rax, qword ptr [r12 + 256 + 24]
    or rax, qword ptr [r12 + 256 + 32]
    or rax, qword ptr [r12 + 256 + 40]
    jnz batch_atomic_worker_contract
    xor edi, edi
    xor esi, esi
    mov rdx, rsp
    xor r10d, r10d
    mov eax, 262
    syscall
    test rax, rax
    js batch_atomic_effect_error
    jmp batch_atomic_worker_contract

batch_atomic_temp_arguments:
    mov rax, qword ptr [r12 + 64]
    cmp qword ptr [r12 + 256 + 24], rax
    jne batch_atomic_worker_contract
    mov rcx, qword ptr [r12 + 72]
    cmp qword ptr [r12 + 256 + 32], rcx
    jne batch_atomic_worker_contract
    lea rdi, [r12 + rax]
    call batch_atomic_exact_cstring
    mov rax, qword ptr [r12 + 64]
    lea rdi, [r12 + rax]
    ret
batch_atomic_open_temp:
    cmp r13, -1
    jne batch_atomic_worker_contract
    cmp qword ptr [r12 + 256 + 40], 0
    jne batch_atomic_worker_contract
    call batch_atomic_temp_arguments
    mov rsi, rdi
    mov edi, -100
    mov edx, 0x80241
    mov r10d, 0666
    mov eax, 257
    syscall
    test rax, rax
    js batch_atomic_effect_error
    cmp rax, 0x7fffffff
    ja batch_atomic_worker_contract
    mov r13, rax
    mov qword ptr [r12 + 256 + 72], 1
    jmp batch_atomic_acknowledge

batch_atomic_write_temp:
    cmp r13, 0
    jl batch_atomic_worker_contract
    cmp qword ptr [r12 + 256 + 24], 1
    jne batch_atomic_worker_contract
    mov rax, qword ptr [r12 + 40]
    add rax, 64
    add rax, qword ptr [r12 + 112]
    jc batch_atomic_worker_contract
    cmp rax, qword ptr [r12 + 256 + 32]
    jne batch_atomic_worker_contract
    cmp rax, [rbp + 24]
    jae batch_atomic_worker_contract
    mov rdx, [rbp + 24]
    sub rdx, rax
    cmp rdx, qword ptr [r12 + 256 + 40]
    jne batch_atomic_worker_contract
    mov rsi, [rbp + 16]
    add rsi, rax
    mov rdi, r13
    mov eax, 1
    syscall
    test rax, rax
    js batch_atomic_effect_error
    mov qword ptr [r12 + 256 + 56], rax
    jmp batch_atomic_acknowledge

batch_atomic_close_temp:
    cmp r13, 0
    jl batch_atomic_worker_contract
    cmp qword ptr [r12 + 256 + 24], 1
    jne batch_atomic_worker_contract
    mov rax, qword ptr [r12 + 256 + 32]
    or rax, qword ptr [r12 + 256 + 40]
    jnz batch_atomic_worker_contract
    mov rdi, r13
    mov r13, -1
    mov eax, 3
    syscall
    test rax, rax
    js batch_atomic_effect_error
    jmp batch_atomic_acknowledge

batch_atomic_chmod_temp:
    cmp r13, -1
    jne batch_atomic_worker_contract
    mov rax, qword ptr [r12 + 80]
    mov ecx, 0xffffffff
    cmp rax, rcx
    ja batch_atomic_worker_contract
    cmp qword ptr [r12 + 256 + 40], rax
    jne batch_atomic_worker_contract
    call batch_atomic_temp_arguments
    mov esi, dword ptr [r12 + 80]
    mov eax, 90
    syscall
    test rax, rax
    js batch_atomic_effect_error
    jmp batch_atomic_acknowledge

batch_atomic_rename_temp:
    cmp r13, -1
    jne batch_atomic_worker_contract
    mov rax, qword ptr [r12 + 64]
    cmp qword ptr [r12 + 256 + 24], rax
    jne batch_atomic_worker_contract
    cmp qword ptr [r12 + 256 + 32], 1024
    jne batch_atomic_worker_contract
    cmp qword ptr [r12 + 256 + 40], 0
    jne batch_atomic_worker_contract
    lea rdi, [r12 + rax]
    mov rcx, qword ptr [r12 + 72]
    call batch_atomic_exact_cstring
    lea rdi, [r12 + 1024]
    mov rcx, qword ptr [r12 + 40]
    call batch_atomic_exact_cstring
    mov rax, qword ptr [r12 + 64]
    lea rdi, [r12 + rax]
    lea rsi, [r12 + 1024]
    mov eax, 82
    syscall
    test rax, rax
    js batch_atomic_effect_error
    jmp batch_atomic_acknowledge

batch_atomic_unlink_temp:
    cmp r13, -1
    jne batch_atomic_worker_contract
    cmp qword ptr [r12 + 256 + 40], 0
    jne batch_atomic_worker_contract
    call batch_atomic_temp_arguments
    mov eax, 87
    syscall
    test rax, rax
    js batch_atomic_effect_error
    jmp batch_atomic_acknowledge

batch_atomic_effect_error:
    cmp rax, -4095
    jb batch_atomic_worker_contract
    neg rax
    mov qword ptr [r12 + 256 + 64], rax
batch_atomic_acknowledge:
    mov qword ptr [r12 + 256 + 80], 1
    call batch_atomic_after_effect
    test rax, rax
    js batch_atomic_worker_contract
    jmp batch_atomic_invoke_policy

batch_atomic_exact_cstring:
    xor eax, eax
    test rcx, rcx
    jz batch_atomic_exact_end
    repne scasb
    je batch_atomic_worker_contract
batch_atomic_exact_end:
    cmp byte ptr [rdi], 0
    jne batch_atomic_worker_contract
    ret

