/* Each submitted mkdir task owns its process, path snapshot and two FD slots. */
d_launch_mkdir:
    cmp qword ptr [r15 + D_JOB_SEQUENCE], -1
    je d_job_counter_full
    lea rdi, [r15 + D_PIPES]
    mov esi, 0x80800
    mov eax, 293
    syscall
    cmp rax, -4095
    jae d_job_start_errno
    mov eax, [r15 + D_PIPES]
    mov [r15 + D_JOB_R], rax
    mov eax, [r15 + D_PIPES + 4]
    mov [r15 + D_JOB_W], rax
    mov eax, 57
    syscall
    cmp rax, -4095
    jae d_job_fork_error
    test rax, rax
    jz d_mkdir_child
    mov rbx, [r15 + D_CURRENT]
    mov [rbx + T_PID], rax
    mov rax, [r15 + D_JOB_R]
    mov [rbx + T_FD], rax
    mov qword ptr [r15 + D_JOB_R], -1
    mov rax, [r15 + D_JOB_SEQUENCE]
    inc rax
    mov [r15 + D_JOB_SEQUENCE], rax
    mov [rbx + T_JOB], rax
    mov qword ptr [rbx + T_GOT], 0
    mov qword ptr [rbx + T_WSTATUS], 0
    mov qword ptr [rbx + T_PIPE_EOF], 0
    mov qword ptr [rbx + T_PIPE_FAIL], 0
    lea rdi, [r15 + D_JOB_W]
    call d_close_slot
    xor eax, eax
    ret
d_job_fork_error:
    neg rax
    mov [r15 + D_EXEC_ERROR], rax
    lea rdi, [r15 + D_JOB_R]
    call d_close_slot
    lea rdi, [r15 + D_JOB_W]
    call d_close_slot
    mov rax, [r15 + D_EXEC_ERROR]
    ret
d_job_start_errno:
    neg rax
    ret
d_job_counter_full:
    mov eax, 75
    ret

d_mkdir_child:
    mov edi, 1
    mov esi, 9
    mov eax, 157
    syscall
    test rax, rax
    jnz d_worker_bare_fatal
    mov eax, 110
    syscall
    cmp rax, [r15 + D_PARENT_PID]
    jne d_worker_bare_fatal
    mov rbx, [r15 + D_CURRENT]
    mov r12, [rbx + T_WORK]
    add r12, 4096
    mov r13, [r15 + D_CHILD_LEN]
d_worker_preserve_fd:
    mov rdi, [r15 + D_JOB_W]
    mov esi, 1030
    mov edx, 16
    mov eax, 72
    syscall
    cmp rax, -4
    je d_worker_preserve_fd
    cmp rax, -4095
    jae d_worker_bare_fatal
    cmp rax, 16
    jb d_worker_bare_fatal
    mov rdi, rax
d_worker_install_fd:
    mov esi, 3
    mov edx, 0x80000
    mov eax, 292
    syscall
    cmp rax, -4
    je d_worker_install_fd
    cmp rax, 3
    jne d_worker_bare_fatal
    mov edi, 4
    mov esi, -1
    xor edx, edx
    mov eax, 436
    syscall
    test rax, rax
    jnz d_worker_bare_fatal
    xor edi, edi
    mov eax, 3
    syscall
    mov edi, 1
    mov eax, 3
    syscall
    mov edi, 2
    mov eax, 3
    syscall
    xor edi, edi
    mov esi, 33558528
    mov edx, 3
    mov r10d, 34
    mov r8, -1
    xor r9d, r9d
    mov eax, 9
    syscall
    cmp rax, -4095
    jae d_worker_bare_fatal
    mov r15, rax
    mov [r15 + 64], r12
    mov [r15 + 72], r13
d_worker_invoke:
    mov rdi, [r15 + 64]
    mov rsi, [r15 + 72]
    lea rdx, [r15 + 256]
    mov ecx, 40
    lea r8, [r15 + 4096]
    mov r9d, 33554432
    .byte 0xe8
mkdir_call_displacement:
    .long 0
    mov edx, eax
    cmp rax, rdx
    jne d_worker_fatal
    cmp eax, 0xfffffff0
    je d_worker_handle_effect
    cmp eax, 40
    jne d_worker_fatal
    mov rax, [r15 + 24]
    or rax, [r15 + 40]
    jnz d_worker_fatal
    mov edi, 3
    lea rsi, [r15 + 256]
    mov edx, 40
    call write_exact
    test eax, eax
    jnz d_worker_fatal
    mov edi, 3
    mov eax, 3
    syscall
    xor edi, edi
    mov eax, 60
    syscall
d_worker_fatal:
    cmp qword ptr [r15 + 24], 0
    je d_worker_close_second
    mov qword ptr [r15 + 24], 0
    mov rdi, [r15 + 32]
    mov eax, 3
    syscall
d_worker_close_second:
    cmp qword ptr [r15 + 40], 0
    je d_worker_bare_fatal
    mov qword ptr [r15 + 40], 0
    mov rdi, [r15 + 48]
    mov eax, 3
    syscall
d_worker_bare_fatal:
    mov edi, 114
    mov eax, 60
    syscall
d_worker_root_name:
    .asciz "/"
