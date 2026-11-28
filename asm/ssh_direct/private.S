
/* Explicit private-owner constructor mirrors Proxy::start. The legacy
 * process-global start/freeze/shutdown exports remain byte-for-byte separate.
 * A runtime embeds one selected shared owner; MCP requests cannot create it. */
.intel_syntax noprefix
.section .text
.global ssh_direct_owner_create
ssh_direct_owner_create:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov r14, rdi
    mov r15, rsi
    mov edi, 4096
    call ssh_alloc
    test rax, rax
    js .Lowner_create_remember_error
    mov r12, rax
    mov rax, 0x3130305443535348
    mov QWORD PTR [r12], rax
    mov eax, 39
    syscall
    mov QWORD PTR [r12+C_PID], rax
    mov QWORD PTR [r12+16], 1
    mov QWORD PTR [r12+C_OBSERVER], r14
    mov QWORD PTR [r12+C_OPAQUE], r15
    mov QWORD PTR [r12+C_WAKE], -1
    mov QWORD PTR [r12+C_GENERATION], 1
    mov edi, 4096
    call ssh_alloc
    test rax, rax
    js .Lowner_create_remember_error
    mov rcx, rax
    mov r8, rdx
    lea rdi, [r12+C_CORE]
    mov esi, 3
    lea rdx, [rip+ssh_hia_core]
    lea r9, [r12+C_CORE_OUT]
    mov r10d, 384
    call ssh_policy_init
    mov rdi, r12
    xor esi, esi
    xor edx, edx
    xor ecx, ecx
    xor r8d, r8d
    xor r9d, r9d
    xor r10d, r10d
    xor r11d, r11d
    call ssh_core
    cmp eax, 384
    jne .Lowner_create_internal
    mov rdi, r12
    mov esi, 1
    xor edx, edx
    xor ecx, ecx
    xor r8d, r8d
    xor r9d, r9d
    xor r10d, r10d
    xor r11d, r11d
    call ssh_core
    cmp eax, 384
    jne .Lowner_create_internal
    cmp rdx, 1
    jne .Lowner_create_internal
    mov QWORD PTR [r12+248], r10
    xor edi, edi
    mov esi, 526336
    mov eax, 290
    syscall
    test rax, rax
    js .Lowner_create_receipt_error
    mov QWORD PTR [r12+C_WAKE], rax
    mov rdi, r12
    lea rsi, [rip+ssh_owner_thread]
    lea rdx, [r12+C_TID]
    lea rcx, [r12+C_STACK]
    lea r8, [r12+C_STACK_CAP]
    call ssh_thread_spawn
    test rax, rax
    js .Lowner_create_receipt_error
    mov rdi, r12
    mov esi, 2
    xor edx, edx
    xor ecx, ecx
    xor r8d, r8d
    xor r9d, r9d
    lea r10, [r12+C_TID]
    mov r11, QWORD PTR [r12+248]
    call ssh_core
    cmp eax, 384
    jne .Lowner_create_thread_internal
    test rdx, rdx
    jnz .Lowner_create_thread_internal
.Lowner_create_publish:
    mov DWORD PTR [r12+C_READY], 1
    lea rdi, [r12+C_READY]
    mov esi, 129
    mov edx, 2147483647
    xor r10d, r10d
    xor r8d, r8d
    xor r9d, r9d
    mov eax, 202
    syscall
.Lowner_create_existing:
    mov rdi, r12
    call ssh_identity
    test rax, rax
    js .Lowner_create_return
    cmp QWORD PTR [r12+C_OBSERVER], r14
    jne .Lowner_create_invalid
    cmp QWORD PTR [r12+C_OPAQUE], r15
    jne .Lowner_create_invalid
    cmp QWORD PTR [r12+C_FROZEN], 0
    jne .Lowner_create_frozen
    mov rax, r12
    jmp .Lowner_create_return
.Lowner_create_receipt_error:
    mov r13, rax
    neg rax
    mov r10, rax
    mov rdi, r12
    mov esi, 2
    xor edx, edx
    xor ecx, ecx
    xor r8d, r8d
    mov r9d, 1
    mov r11, QWORD PTR [r12+248]
    call ssh_core
    mov rax, r13
    jmp .Lowner_create_remember_error
.Lowner_create_thread_internal:
    mov QWORD PTR [r12+C_ERROR], 71
    mov QWORD PTR [r12+C_FROZEN], 1
    mov DWORD PTR [r12+C_READY], 1
    lea rdi, [r12+C_READY]
    mov esi, 129
    mov edx, 2147483647
    xor r10d, r10d
    xor r8d, r8d
    xor r9d, r9d
    mov eax, 202
    syscall
    mov rdi, r12
    call ssh_wake
.Lowner_create_internal:
    mov rax, -71
.Lowner_create_remember_error:
    jmp .Lowner_create_return
.Lowner_create_frozen:
    mov rax, -125
    jmp .Lowner_create_return
.Lowner_create_invalid:
    mov rax, -22
.Lowner_create_return:
    mov rbx, rax
    mov rax, rbx
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

.global ssh_direct_owner_freeze
ssh_direct_owner_freeze:
    push r12
    mov r12, rdi
    call ssh_identity
    test rax, rax
    js .Lowner_freeze_done
    mov rdi, r12
    call ssh_core_stop
    xor eax, eax
.Lowner_freeze_done:
    pop r12
    ret

.global ssh_direct_owner_shutdown
ssh_direct_owner_shutdown:
    push r12
    push r13
    sub rsp, 8
    mov r12, rdi
    call ssh_identity
    test rax, rax
    js .Lowner_shutdown_return
    mov rdi, r12
    call ssh_core_stop
    xor eax, eax
    mov edx, 1
    lock cmpxchg QWORD PTR [r12+C_JOIN_START], rdx
    jnz .Lowner_shutdown_result
    mov rdi, r12
    mov esi, 11
    xor edx, edx
    xor ecx, ecx
    xor r8d, r8d
    mov r9d, 1
    xor r10d, r10d
    xor r11d, r11d
    call ssh_core
    cmp eax, 384
    jne .Lowner_shutdown_policy_error
    cmp rdx, 1
    jne .Lowner_shutdown_policy_error
    cmp r8, 2
    jne .Lowner_shutdown_policy_error
    mov QWORD PTR [r12+C_JOIN_SEQUENCE], r10
    mov rdi, r12
    lea rsi, [rip+ssh_join_thread]
    lea rdx, [r12+C_JOIN_TID]
    lea rcx, [r12+C_JOIN_STACK]
    lea r8, [r12+C_JOIN_CAP]
    call ssh_thread_spawn
    test rax, rax
    jns .Lowner_shutdown_result
    neg rax
    mov QWORD PTR [r12+C_JOIN_ERROR], rax
    jmp .Lowner_shutdown_start_failed
.Lowner_shutdown_policy_error:
    mov QWORD PTR [r12+C_JOIN_ERROR], 71
.Lowner_shutdown_start_failed:
    # No actual join occurred. Keep the HIA join pending and the exact owner
    # capability retained; report the native worker-creation error separately.
    mov QWORD PTR [r12+C_JOIN_DONE], 1
    mov rdi, r12
    call ssh_join_notify
.Lowner_shutdown_result:
    mov rdi, r12
    call ssh_direct_join_result
.Lowner_shutdown_return:
    add rsp, 8
    pop r13
    pop r12
    ret


/* Read or hold the exact existing admission gate. The holder may not invoke
 * submit/freeze/shutdown until releasing it. These are trusted embedder calls. */
.global ssh_direct_owner_gate_lock
ssh_direct_owner_gate_lock:
    push r12
    mov r12, rdi
    call ssh_identity
    test rax, rax
    js .Lowner_gate_lock_done
    lea rdi, [r12+C_QUEUE_LOCK]
    call ssh_lock
    mov rax, [r12+C_FROZEN]
.Lowner_gate_lock_done:
    pop r12
    ret
.global ssh_direct_owner_gate_unlock
ssh_direct_owner_gate_unlock:
    lea rdi, [rdi+C_QUEUE_LOCK]
    jmp ssh_unlock

/* Exact held-state observation. The borrow ends at state_unlock; no callback
 * or native owner operation is permitted while this mutex is held. */
.global ssh_direct_owner_state_lock
ssh_direct_owner_state_lock:
    push r12
    mov r12, rdi
    call ssh_identity
    test rax, rax
    js .Lowner_state_lock_done
    lea rdi, [r12+C_CORE]
    call ssh_lock
    mov rax, [r12+C_CORE+24]
    mov rdx, [r12+C_CORE+32]
.Lowner_state_lock_done:
    pop r12
    ret
.global ssh_direct_owner_state_unlock
ssh_direct_owner_state_unlock:
    lea rdi, [rdi+C_CORE]
    jmp ssh_unlock

.global ssh_direct_request_phase
ssh_direct_request_phase:
    push r12
    mov r12, rdi
    lea rdi, [r12+R_ADMISSION]
    call ssh_lock
    mov eax, [r12+R_ADM_WORK+24]
    mov r12, rax
    call ssh_unlock
    mov rax, r12
    pop r12
    ret
