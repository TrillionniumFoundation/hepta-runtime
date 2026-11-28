# One bounded, nonblocking transport action per live request. Semantic order,
# limits, errors and byte extents come from HIA; the adapter copies actual bytes.
ssh_drive_request:
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub rsp, 16
    mov r13, rdi
    mov r12, QWORD PTR [r13+R_CTX]
    mov QWORD PTR [r13+R_PROGRESS], 0
    xor ebx, ebx
.Ldrive_poll_setup:
    mov eax, DWORD PTR [r13+R_IN+rbx*8]
    mov DWORD PTR [r13+R_POLL+rbx*8], eax
    mov eax, 1
    test rbx, rbx
    jnz .Ldrive_poll_event
    mov eax, 4
.Ldrive_poll_event:
    mov WORD PTR [r13+R_POLL+rbx*8+4], ax
    mov WORD PTR [r13+R_POLL+rbx*8+6], 0
    inc rbx
    cmp rbx, 3
    jb .Ldrive_poll_setup
    lea rdi, [r13+R_POLL]
    mov esi, 3
    xor edx, edx
    mov eax, 7
    syscall
    test rax, rax
    js .Ldrive_poll_error
    mov ebx, 8
    cmp WORD PTR [r13+R_POLL+6], 0
    je .Ldrive_poll_out
    or ebx, 1
.Ldrive_poll_out:
    cmp WORD PTR [r13+R_POLL+14], 0
    je .Ldrive_poll_err
    or ebx, 2
.Ldrive_poll_err:
    cmp WORD PTR [r13+R_POLL+22], 0
    je .Ldrive_tick
    or ebx, 4
.Ldrive_tick:
    mov QWORD PTR [r13+R_READINESS], rbx
    mov rdi, r13
    mov esi, 1
    mov rdx, QWORD PTR [r13+R_ADM_WORK+32]
    mov rcx, QWORD PTR [r12+C_FROZEN]
    cmp QWORD PTR [r13+R_KIND], 0
    je .Ldrive_actual_stop
    mov ecx, 1
.Ldrive_actual_stop:
    mov r8, rbx
    xor r9d, r9d
    call ssh_io
    cmp eax, 320
    jne .Ldrive_protocol
    cmp rdx, 1
    je .Ldrive_effect
    cmp rdx, 2
    je .Ldrive_success
    cmp rdx, 3
    je .Ldrive_failed
    test rdx, rdx
    jnz .Ldrive_protocol
    jmp .Ldrive_return
.Ldrive_effect:
    mov r15, r8
    cmp r15, 1
    je .Ldrive_write
    cmp r15, 4
    je .Ldrive_wait
    cmp r15, 5
    jae .Ldrive_close
    cmp r15, 2
    jb .Ldrive_protocol
    cmp r15, 3
    ja .Ldrive_protocol
    mov rax, r15
    sub rax, 2
    mov rdi, QWORD PTR [r13+R_OUT+rax*8]
    mov rsi, QWORD PTR [r13+R_SCRATCH]
    mov rdx, QWORD PTR [r13+R_IO_WORK+184]
    xor eax, eax
    syscall
    mov r14, rax
    jmp .Ldrive_ack
.Ldrive_write:
    mov rdi, QWORD PTR [r13+R_IN]
    mov rsi, QWORD PTR [r13+R_INPUT]
    add rsi, QWORD PTR [r13+R_IO_WORK+192]
    mov rdx, QWORD PTR [r13+R_IO_WORK+184]
    mov eax, 1
    syscall
    mov r14, rax
    jmp .Ldrive_ack
.Ldrive_close:
    cmp r15, 7
    ja .Ldrive_protocol
    mov rax, r15
    sub rax, 5
    mov rdi, QWORD PTR [r13+R_IN+rax*8]
    test rdi, rdi
    js .Ldrive_protocol
    mov QWORD PTR [r13+R_IN+rax*8], -1
    mov eax, 3
    syscall
    mov r14, rax
    mov QWORD PTR [r13+R_PROGRESS], 1
    jmp .Ldrive_ack
.Ldrive_wait:
    mov rdi, QWORD PTR [r13+R_PID]
    lea rsi, [r13+R_STATUS]
    mov edx, 1
    xor r10d, r10d
    mov eax, 61
    syscall
    mov r14, rax
    test r14, r14
    jz .Ldrive_ack
    cmp r14, -4
    je .Ldrive_ack
    mov edx, 1
    mov rcx, r14
    neg rcx
    test r14, r14
    js .Ldrive_child_wait_ack
    cmp r14, QWORD PTR [r13+R_PID]
    jne .Ldrive_protocol
    lock inc QWORD PTR [r12+C_REAPED]
    mov rdi, r13
    mov rsi, r14
    mov edx, DWORD PTR [r13+R_STATUS]
    call ssh_qa_observe_wait
    mov r14, rax
    mov edx, 1
    mov rcx, rax
    neg rcx
    test rax, rax
    js .Ldrive_child_wait_ack
    xor edx, edx
    mov ecx, DWORD PTR [r13+R_STATUS]
.Ldrive_child_wait_ack:
    mov rdi, r13
    mov esi, 9
    mov r8, QWORD PTR [r13+R_WAIT_SEQ]
    xor r9d, r9d
    xor r10d, r10d
    call ssh_child
    cmp eax, 576
    jne .Ldrive_protocol
    mov QWORD PTR [r13+R_WAIT_SEQ], 0
.Ldrive_ack:
    mov rdi, r13
    mov esi, 2
    mov rdx, r14
    xor ecx, ecx
    xor r8d, r8d
    cmp r15, 4
    je .Ldrive_ack_wait
    cmp r15, 2
    jb .Ldrive_ack_ready
    cmp r15, 3
    ja .Ldrive_ack_ready
    test r14, r14
    jle .Ldrive_ack_ready
    mov rcx, r14
    jmp .Ldrive_ack_ready
.Ldrive_ack_wait:
    mov r8, QWORD PTR [r13+R_PID]
    test r14, r14
    jle .Ldrive_ack_ready
    mov ecx, DWORD PTR [r13+R_STATUS]
.Ldrive_ack_ready:
    mov r9, QWORD PTR [r13+R_IO_WORK+176]
    call ssh_io
    cmp eax, 320
    jne .Ldrive_protocol
    mov rax, QWORD PTR [r13+R_IO_WORK+200]
    test rax, rax
    jz .Ldrive_no_append
    cmp rax, 1
    je .Ldrive_append_out
    cmp rax, 2
    jne .Ldrive_protocol
    mov rdi, QWORD PTR [r13+R_STDERR]
    jmp .Ldrive_append
.Ldrive_append_out:
    mov rdi, QWORD PTR [r13+R_STDOUT]
.Ldrive_append:
    add rdi, QWORD PTR [r13+R_IO_WORK+208]
    mov rsi, QWORD PTR [r13+R_SCRATCH]
    mov rdx, QWORD PTR [r13+R_IO_WORK+216]
    call ssh_copy
    mov rax, QWORD PTR [r13+R_IO_WORK+88]
    mov QWORD PTR [r13+R_STDOUT_LEN], rax
    mov rax, QWORD PTR [r13+R_IO_WORK+96]
    mov QWORD PTR [r13+R_STDERR_LEN], rax
.Ldrive_no_append:
    cmp r14, -4
    je .Ldrive_return
    cmp r14, -11
    je .Ldrive_return
    cmp r15, 4
    jne .Ldrive_progress
    test r14, r14
    jz .Ldrive_return
.Ldrive_progress:
    mov QWORD PTR [r13+R_PROGRESS], 1
    jmp .Ldrive_return
.Ldrive_success:
    mov rax, QWORD PTR [r13+R_IO_WORK+80]
    mov QWORD PTR [r13+R_RAW_STATUS], rax
    mov rdi, r13
    mov esi, 1
    mov rdx, QWORD PTR [r12+C_FROZEN]
    xor ecx, ecx
    xor r8d, r8d
    xor r9d, r9d
    call ssh_admission
    cmp eax, 320
    jne .Ldrive_protocol
    test rdx, rdx
    jz .Ldrive_borrows_finished
    mov QWORD PTR [r13+R_KIND], 1
    add rcx, 100
    mov QWORD PTR [r13+R_REASON], rcx
    jmp .Ldrive_borrows_finished
.Ldrive_failed:
    cmp QWORD PTR [r13+R_KIND], 0
    jne .Ldrive_borrows_finished
    mov QWORD PTR [r13+R_KIND], 1
    mov rax, QWORD PTR [r13+R_IO_WORK+104]
    add rax, 400
    mov QWORD PTR [r13+R_REASON], rax
    mov rax, QWORD PTR [r13+R_IO_WORK+112]
    mov QWORD PTR [r13+R_ERRNO], rax
.Ldrive_borrows_finished:
    cmp QWORD PTR [r13+R_WAIT_SEQ], 0
    je .Ldrive_release_borrow
    mov rdi, r13
    mov esi, 4
    xor edx, edx
    xor ecx, ecx
    mov r8, QWORD PTR [r13+R_WAIT_SEQ]
    xor r9d, r9d
    xor r10d, r10d
    call ssh_child
    cmp eax, 576
    jne .Ldrive_protocol
    mov QWORD PTR [r13+R_WAIT_SEQ], 0
.Ldrive_release_borrow:
    mov rdi, r13
    mov esi, 2
    call ssh_child_simple
    cmp eax, 576
    jne .Ldrive_protocol
    cmp QWORD PTR [r13+R_KIND], 0
    jne .Ldrive_cleanup
    mov rdi, r13
    call ssh_release_child
    jmp .Ldrive_progress
.Ldrive_cleanup:
    mov rdi, r13
    call ssh_cleanup_start
    jmp .Ldrive_progress
.Ldrive_poll_error:
    cmp rax, -4
    je .Ldrive_return
    neg rax
    mov QWORD PTR [r13+R_KIND], 1
    mov QWORD PTR [r13+R_REASON], 206
    mov QWORD PTR [r13+R_ERRNO], rax
    xor ebx, ebx
    jmp .Ldrive_tick
.Ldrive_protocol:
    mov QWORD PTR [r12+C_ERROR], 71
    mov QWORD PTR [r13+R_KIND], 1
    mov QWORD PTR [r13+R_REASON], 203
    mov QWORD PTR [r13+R_ERRNO], 71
    mov rdi, r13
    call ssh_quarantine
.Ldrive_return:
    mov rax, QWORD PTR [r13+R_PROGRESS]
    add rsp, 16
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

ssh_cleanup_start:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov r13, rdi
    mov r12, QWORD PTR [r13+R_CTX]
    mov QWORD PTR [r13+R_PHASE], 3
    mov esi, 5
    call ssh_child_simple
    cmp eax, 576
    jne .Lcleanup_protocol
    test rdx, rdx
    jz .Lcleanup_release
    cmp rdx, 3
    je .Lcleanup_error
    cmp rdx, 1
    jne .Lcleanup_protocol
    cmp r8, 2
    jne .Lcleanup_protocol
    mov QWORD PTR [r13+R_CLEAN_SEQ], r9
.Lcleanup_try_wait:
    mov rdi, QWORD PTR [r13+R_PID]
    lea rsi, [r13+R_STATUS]
    mov edx, 1
    xor r10d, r10d
    mov eax, 61
    syscall
    cmp rax, -4
    je .Lcleanup_try_wait
    mov r14, rax
    test r14, r14
    jz .Lcleanup_alive
    xor r9d, r9d
    xor r10d, r10d
    mov edx, 2
    mov rcx, r14
    neg rcx
    test r14, r14
    js .Lcleanup_try_ack
    cmp r14, QWORD PTR [r13+R_PID]
    jne .Lcleanup_protocol
    lock inc QWORD PTR [r12+C_REAPED]
    mov edx, 1
    mov ecx, DWORD PTR [r13+R_STATUS]
    jmp .Lcleanup_try_ack
.Lcleanup_alive:
    call ssh_now
    cmp rdx, -1
    je .Lcleanup_protocol
    mov r9, rax
    mov r10, rdx
    xor edx, edx
    xor ecx, ecx
.Lcleanup_try_ack:
    mov rdi, r13
    mov esi, 6
    mov r8, QWORD PTR [r13+R_CLEAN_SEQ]
    call ssh_child
    cmp eax, 576
    jne .Lcleanup_protocol
    test rdx, rdx
    jz .Lcleanup_release
    cmp rdx, 3
    je .Lcleanup_error
    cmp rdx, 1
    jne .Lcleanup_protocol
    cmp r8, 3
    jne .Lcleanup_protocol
    mov QWORD PTR [r13+R_CLEAN_SEQ], r9
    mov rdi, QWORD PTR [r13+R_PID]
    mov esi, 9
    mov eax, 62
    syscall
    test rax, rax
    jns .Lcleanup_signal_ok
    neg rax
.Lcleanup_signal_ok:
    mov rdx, rax
    mov rdi, r13
    mov esi, 7
    xor ecx, ecx
    mov r8, QWORD PTR [r13+R_CLEAN_SEQ]
    xor r9d, r9d
    xor r10d, r10d
    call ssh_child
    cmp eax, 576
    jne .Lcleanup_protocol
    cmp rdx, 1
    jne .Lcleanup_protocol
    cmp r8, 4
    jne .Lcleanup_protocol
    mov QWORD PTR [r13+R_CLEAN_SEQ], r9
    jmp .Lcleanup_return
.Lcleanup_release:
    mov rdi, r13
    call ssh_release_child
    jmp .Lcleanup_return
.Lcleanup_error:
    cmp QWORD PTR [r13+R_DONE], 0
    jne .Lcleanup_error_publish
    mov QWORD PTR [r13+R_KIND], 1
    add rcx, 500
    mov QWORD PTR [r13+R_REASON], rcx
    mov QWORD PTR [r13+R_ERRNO], r10
.Lcleanup_error_publish:
    mov rdi, r13
    call ssh_quarantine
    jmp .Lcleanup_return
.Lcleanup_protocol:
    mov QWORD PTR [r12+C_ERROR], 71
    cmp QWORD PTR [r13+R_DONE], 0
    jne .Lcleanup_error_publish
    mov QWORD PTR [r13+R_KIND], 1
    mov QWORD PTR [r13+R_REASON], 203
    mov QWORD PTR [r13+R_ERRNO], 71
    jmp .Lcleanup_error_publish
.Lcleanup_return:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

ssh_cleanup_tick:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov r13, rdi
    mov r12, QWORD PTR [r13+R_CTX]
    mov rdi, QWORD PTR [r13+R_PID]
    lea rsi, [r13+R_STATUS]
    mov edx, 1
    xor r10d, r10d
    mov eax, 61
    syscall
    cmp rax, -4
    je .Lcleanup_tick_idle
    mov r14, rax
    test r14, r14
    jz .Lcleanup_tick_clock
    mov edx, 1
    mov rcx, r14
    neg rcx
    test r14, r14
    js .Lcleanup_tick_ack_zero_clock
    cmp r14, QWORD PTR [r13+R_PID]
    jne .Lcleanup_tick_protocol
    lock inc QWORD PTR [r12+C_REAPED]
    xor edx, edx
    mov ecx, DWORD PTR [r13+R_STATUS]
.Lcleanup_tick_ack_zero_clock:
    xor r9d, r9d
    xor r10d, r10d
    jmp .Lcleanup_tick_ack
.Lcleanup_tick_clock:
    call ssh_now
    cmp rdx, -1
    je .Lcleanup_tick_protocol
    cmp rdx, QWORD PTR [r13+R_CHILD_WORK+80]
    jb .Lcleanup_tick_idle
    ja .Lcleanup_tick_timeout
    cmp rax, QWORD PTR [r13+R_CHILD_WORK+72]
    jb .Lcleanup_tick_idle
.Lcleanup_tick_timeout:
    mov r9, rax
    mov r10, rdx
    mov edx, 2
    xor ecx, ecx
.Lcleanup_tick_ack:
    mov rdi, r13
    mov esi, 8
    mov r8, QWORD PTR [r13+R_CLEAN_SEQ]
    call ssh_child
    cmp eax, 576
    jne .Lcleanup_tick_protocol
    test rdx, rdx
    jnz .Lcleanup_tick_failure
    mov rdi, r13
    call ssh_release_child
    mov eax, 1
    jmp .Lcleanup_tick_return
.Lcleanup_tick_failure:
    cmp QWORD PTR [r13+R_DONE], 0
    jne .Lcleanup_tick_quarantine
    mov QWORD PTR [r13+R_KIND], 1
    add rcx, 500
    mov QWORD PTR [r13+R_REASON], rcx
    mov QWORD PTR [r13+R_ERRNO], r10
.Lcleanup_tick_quarantine:
    mov rdi, r13
    call ssh_quarantine
    mov eax, 1
    jmp .Lcleanup_tick_return
.Lcleanup_tick_protocol:
    mov QWORD PTR [r12+C_ERROR], 71
    cmp QWORD PTR [r13+R_DONE], 0
    jne .Lcleanup_tick_quarantine
    mov QWORD PTR [r13+R_KIND], 1
    mov QWORD PTR [r13+R_REASON], 203
    mov QWORD PTR [r13+R_ERRNO], 71
    jmp .Lcleanup_tick_quarantine
.Lcleanup_tick_idle:
    xor eax, eax
.Lcleanup_tick_return:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret
