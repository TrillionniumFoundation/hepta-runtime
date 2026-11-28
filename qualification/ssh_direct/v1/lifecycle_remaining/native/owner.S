# Independent owner scheduling and the one persistent original join worker.
# No queue depth, child count, host count, or task count is capped.
.equ C_JOIN_ERROR, 896
.equ C_OWNER_DONE, 904

ssh_owner_thread:
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub rsp, 32
    mov r12, rdi
.Lowner_ready:
    cmp DWORD PTR [r12+C_READY], 1
    je .Lowner_setup
    lea rdi, [r12+C_READY]
    mov esi, 128
    xor edx, edx
    xor r10d, r10d
    xor r8d, r8d
    xor r9d, r9d
    mov eax, 202
    syscall
    jmp .Lowner_ready
.Lowner_setup:
    # A closed child stdin returns EPIPE to the HIA I/O policy. SIGPIPE is
    # blocked on this owner only and the original mask is restored for exec.
    mov QWORD PTR [rsp], 4096
    xor edi, edi
    mov rsi, rsp
    lea rdx, [r12+C_SIGMASK]
    mov r10d, 8
    mov eax, 14
    syscall
    test rax, rax
    js .Lowner_setup_error
    mov edi, 15
    lea rsi, [rip+ssh_owner_name]
    xor edx, edx
    xor r10d, r10d
    xor r8d, r8d
    mov eax, 157
    syscall
.Lowner_loop:
    xor r15d, r15d
    lea rdi, [r12+C_QUEUE_LOCK]
    call ssh_lock
    mov r13, QWORD PTR [r12+C_QUEUE_HEAD]
    mov r14, QWORD PTR [r12+C_FROZEN]
    test r13, r13
    jz .Lowner_queue_unlock
    mov rax, QWORD PTR [r13+R_NEXT_QUEUE]
    mov QWORD PTR [r12+C_QUEUE_HEAD], rax
    test rax, rax
    jnz .Lowner_queue_detached
    mov QWORD PTR [r12+C_QUEUE_TAIL], 0
.Lowner_queue_detached:
    mov QWORD PTR [r13+R_NEXT_QUEUE], 0
.Lowner_queue_unlock:
    lea rdi, [r12+C_QUEUE_LOCK]
    call ssh_unlock
    test r13, r13
    jz .Lowner_active
    mov r15d, 1
    test r14, r14
    jnz .Lowner_drop_queued
    mov rdi, r13
    call ssh_begin_request
    mov rax, QWORD PTR [r12+C_ACTIVE]
    mov QWORD PTR [r13+R_NEXT_ACTIVE], rax
    mov QWORD PTR [r12+C_ACTIVE], r13
    jmp .Lowner_active
.Lowner_drop_queued:
    # Receiver destruction owns and drops a queued Entry without calling it.
    mov QWORD PTR [r13+R_KIND], 1
    mov QWORD PTR [r13+R_REASON], 106
    mov rdi, r13
    call ssh_finish_request
    mov rdi, r13
    call ssh_request_drop
.Lowner_active:
    lea r14, [r12+C_ACTIVE]
.Lowner_active_next:
    mov r13, QWORD PTR [r14]
    test r13, r13
    jz .Lowner_after_active
    mov rax, QWORD PTR [r13+R_PHASE]
    cmp rax, 2
    je .Lowner_drive
    cmp rax, 3
    je .Lowner_cleanup
    cmp rax, 4
    je .Lowner_retained
    cmp rax, 5
    je .Lowner_complete
    mov QWORD PTR [r12+C_ERROR], 71
    mov QWORD PTR [r13+R_KIND], 1
    mov QWORD PTR [r13+R_REASON], 203
    mov QWORD PTR [r13+R_ERRNO], 71
    mov rdi, r13
    call ssh_quarantine
    jmp .Lowner_retained
.Lowner_drive:
    mov rdi, r13
    call ssh_drive_request
    or r15, rax
    jmp .Lowner_after_step
.Lowner_cleanup:
    mov rdi, r13
    call ssh_cleanup_tick
    or r15, rax
.Lowner_after_step:
    cmp QWORD PTR [r13+R_PHASE], 5
    je .Lowner_complete
    cmp QWORD PTR [r13+R_PHASE], 4
    je .Lowner_retained
    lea r14, [r13+R_NEXT_ACTIVE]
    jmp .Lowner_active_next
.Lowner_complete:
    mov rax, QWORD PTR [r13+R_NEXT_ACTIVE]
    mov QWORD PTR [r14], rax
    mov QWORD PTR [r13+R_NEXT_ACTIVE], 0
    mov rdi, r13
    call ssh_request_drop
    mov r15d, 1
    jmp .Lowner_active_next
.Lowner_retained:
    mov rax, QWORD PTR [r13+R_NEXT_ACTIVE]
    mov QWORD PTR [r14], rax
    cmp QWORD PTR [r13+R_DRAIN], 0
    jne .Lowner_permanent
    cmp QWORD PTR [r13+R_REGISTERED], 1
    jne .Lowner_unsafe_drain
    cmp QWORD PTR [r13+R_CHILD_WORK], 0
    je .Lowner_unsafe_drain
    cmp QWORD PTR [r13+R_CHILD_WORK+104], 0
    jne .Lowner_unsafe_drain
    cmp QWORD PTR [r13+R_CHILD_WORK+32], 0
    jne .Lowner_unsafe_drain
    mov rax, QWORD PTR [r12+C_DRAIN]
    mov QWORD PTR [r13+R_NEXT_ACTIVE], rax
    mov QWORD PTR [r12+C_DRAIN], r13
    jmp .Lowner_retained_done
.Lowner_unsafe_drain:
    mov QWORD PTR [r12+C_ERROR], 71
    mov QWORD PTR [r13+R_DRAIN], 1
.Lowner_permanent:
    mov rax, QWORD PTR [r12+C_QUARANTINED]
    mov QWORD PTR [r13+R_NEXT_ACTIVE], rax
    mov QWORD PTR [r12+C_QUARANTINED], r13
.Lowner_retained_done:
    mov r15d, 1
    jmp .Lowner_active_next
.Lowner_after_active:
    cmp QWORD PTR [r12+C_FROZEN], 0
    je .Lowner_wait_if_idle
    cmp QWORD PTR [r12+C_QUEUE_HEAD], 0
    jne .Lowner_loop
    cmp QWORD PTR [r12+C_ACTIVE], 0
    jne .Lowner_wait_if_idle
    mov r13, QWORD PTR [r12+C_DRAIN]
    test r13, r13
    jz .Lowner_exit
    # The original final drain retries only this retained original object.
    # It uses the first cleanup deadline and never replaces a child or owner.
    mov rax, QWORD PTR [r13+R_NEXT_ACTIVE]
    mov QWORD PTR [r12+C_DRAIN], rax
    mov QWORD PTR [r13+R_NEXT_ACTIVE], 0
    mov QWORD PTR [r13+R_DRAIN], 1
    mov QWORD PTR [r12+C_ACTIVE], r13
    mov rdi, r13
    call ssh_cleanup_start
    jmp .Lowner_loop
.Lowner_wait_if_idle:
    test r15, r15
    jnz .Lowner_loop
    mov eax, DWORD PTR [r12+C_WAKE]
    mov DWORD PTR [rsp], eax
    mov WORD PTR [rsp+4], 1
    mov WORD PTR [rsp+6], 0
    mov rdi, rsp
    mov esi, 1
    mov edx, 1
    mov eax, 7
    syscall
    test rax, rax
    js .Lowner_poll_error
    test rax, rax
    jz .Lowner_loop
.Lowner_drain_wake:
    mov edi, DWORD PTR [r12+C_WAKE]
    lea rsi, [rsp+8]
    mov edx, 8
    xor eax, eax
    syscall
    cmp rax, 8
    je .Lowner_drain_wake
    cmp rax, -4
    je .Lowner_drain_wake
    cmp rax, -11
    je .Lowner_loop
    test rax, rax
    js .Lowner_setup_error
    mov rax, -5
    jmp .Lowner_setup_error
.Lowner_poll_error:
    cmp rax, -4
    je .Lowner_loop
.Lowner_setup_error:
    neg rax
    mov QWORD PTR [r12+C_ERROR], rax
    mov rdi, r12
    call ssh_core_stop
    jmp .Lowner_loop
.Lowner_exit:
    mov r14, QWORD PTR [r12+C_ERROR]
    test r14, r14
    jnz .Lowner_exit_result
    cmp QWORD PTR [r12+C_QUARANTINED], 0
    je .Lowner_exit_result
    mov r14d, 5
    mov QWORD PTR [r12+C_ERROR], r14
.Lowner_exit_result:
    mov rdi, r12
    mov esi, 10
    xor edx, edx
    xor ecx, ecx
    xor r8d, r8d
    xor r9d, r9d
    test r14, r14
    setne r9b
    mov r10, r14
    xor r11d, r11d
    call ssh_core
    cmp eax, 384
    jne .Lowner_exit_bad_policy
    test rdx, rdx
    jnz .Lowner_exit_bad_policy
    mov QWORD PTR [r12+C_OWNER_DONE], 1
    jmp .Lowner_return
.Lowner_exit_bad_policy:
    mov QWORD PTR [r12+C_ERROR], 71
.Lowner_return:
    add rsp, 32
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

# Start shutdown without making this caller the join owner. The created
# worker persists and records completion even if every waiter disappears.
.global ssh_direct_shutdown
ssh_direct_shutdown:
    push r12
    push r13
    sub rsp, 8
    mov r12, rdi
    call ssh_identity
    test rax, rax
    js .Lshutdown_return
    mov QWORD PTR [rip+ssh_global_frozen], 1
    mov rdi, r12
    call ssh_core_stop
    xor eax, eax
    mov edx, 1
    lock cmpxchg QWORD PTR [r12+C_JOIN_START], rdx
    jnz .Lshutdown_result
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
    jne .Lshutdown_policy_error
    cmp rdx, 1
    jne .Lshutdown_policy_error
    cmp r8, 2
    jne .Lshutdown_policy_error
    mov QWORD PTR [r12+C_JOIN_SEQUENCE], r10
    mov rdi, r12
    lea rsi, [rip+ssh_join_thread]
    lea rdx, [r12+C_JOIN_TID]
    lea rcx, [r12+C_JOIN_STACK]
    lea r8, [r12+C_JOIN_CAP]
    call ssh_thread_spawn
    test rax, rax
    jns .Lshutdown_result
    neg rax
    mov QWORD PTR [r12+C_JOIN_ERROR], rax
    jmp .Lshutdown_start_failed
.Lshutdown_policy_error:
    mov QWORD PTR [r12+C_JOIN_ERROR], 71
.Lshutdown_start_failed:
    # No actual join occurred. Keep the HIA join pending and the exact owner
    # capability retained; report the native worker-creation error separately.
    mov QWORD PTR [r12+C_JOIN_DONE], 1
    mov rdi, r12
    call ssh_join_notify
.Lshutdown_result:
    mov rdi, r12
    call ssh_direct_join_result
.Lshutdown_return:
    add rsp, 8
    pop r13
    pop r12
    ret

ssh_join_thread:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov r12, rdi
.Ljoin_wait_original:
    mov edx, DWORD PTR [r12+C_TID]
    test edx, edx
    jz .Ljoin_confirmed
    lea rdi, [r12+C_TID]
    xor esi, esi
    xor r10d, r10d
    xor r8d, r8d
    xor r9d, r9d
    mov eax, 202
    syscall
    cmp rax, -4
    je .Ljoin_wait_original
    cmp rax, -11
    je .Ljoin_wait_original
    test rax, rax
    jns .Ljoin_wait_original
    neg rax
    mov QWORD PTR [r12+C_JOIN_ERROR], rax
    jmp .Ljoin_publish
.Ljoin_confirmed:
    # Kernel clear_child_tid has confirmed the one original OS thread exit.
    mov r14, QWORD PTR [r12+C_ERROR]
    cmp QWORD PTR [r12+C_OWNER_DONE], 1
    je .Ljoin_owner_receipt
    mov r14d, 71
    mov QWORD PTR [r12+C_ERROR], r14
.Ljoin_owner_receipt:
    mov rdi, r12
    mov esi, 12
    xor edx, edx
    xor ecx, ecx
    xor r8d, r8d
    xor r9d, r9d
    test r14, r14
    setne r9b
    mov r10, r14
    mov r11, QWORD PTR [r12+C_JOIN_SEQUENCE]
    call ssh_core
    cmp eax, 384
    jne .Ljoin_bad_policy
    test r14, r14
    jz .Ljoin_expect_success
    cmp rdx, 3
    jne .Ljoin_bad_policy
    mov QWORD PTR [r12+C_JOIN_ERROR], r14
    jmp .Ljoin_free_owner_stack
.Ljoin_expect_success:
    test rdx, rdx
    jnz .Ljoin_bad_policy
.Ljoin_free_owner_stack:
    mov rdi, QWORD PTR [r12+C_STACK]
    mov rsi, QWORD PTR [r12+C_STACK_CAP]
    call ssh_free
    mov QWORD PTR [r12+C_STACK], 0
    mov QWORD PTR [r12+C_STACK_CAP], 0
    jmp .Ljoin_publish
.Ljoin_bad_policy:
    mov QWORD PTR [r12+C_JOIN_ERROR], 71
.Ljoin_publish:
    mov QWORD PTR [r12+C_JOIN_DONE], 1
    mov rdi, r12
    call ssh_join_notify
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret
ssh_join_notify:
    lea rdi, [rdi+C_JOIN_DONE]
    mov esi, 129
    mov edx, 2147483647
    xor r10d, r10d
    xor r8d, r8d
    xor r9d, r9d
    mov eax, 202
    syscall
    ret
.global ssh_direct_join_result
ssh_direct_join_result:
    push r12
    mov r12, rdi
    call ssh_identity
    test rax, rax
    js .Ljoin_result_return
    cmp QWORD PTR [r12+C_JOIN_DONE], 1
    jne .Ljoin_result_pending
    mov rax, QWORD PTR [r12+C_JOIN_ERROR]
    test rax, rax
    jnz .Ljoin_result_error
    mov rdi, r12
    mov esi, 13
    call ssh_core_simple
    cmp eax, 384
    jne .Ljoin_result_protocol
    test rdx, rdx
    jnz .Ljoin_result_protocol
    xor eax, eax
    jmp .Ljoin_result_return
.Ljoin_result_protocol:
    mov rax, -71
    jmp .Ljoin_result_return
.Ljoin_result_error:
    neg rax
    jmp .Ljoin_result_return
.Ljoin_result_pending:
    mov eax, 1
.Ljoin_result_return:
    pop r12
    ret

.section .rodata
ssh_dev_null: .asciz "/dev/null"
ssh_owner_name: .asciz "hepta-direct-ssh"
.section .bss
.balign 8
ssh_global_lock: .zero 8
ssh_global_ctx: .zero 8
ssh_global_error: .zero 8
ssh_global_frozen: .zero 8
.section .text
