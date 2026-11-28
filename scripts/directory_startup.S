/* A distinct inherited read-only pipe is the trusted connection snapshot. */
d_read_startup_snapshot:
    mov edi, 4
    mov esi, 3
    mov eax, 72
    syscall
    cmp rax, -4095
    jae fatal
    and eax, 3
    jnz fatal
    mov edi, 4
    lea rsi, [r15 + D_START_STAT]
    mov eax, 5
    syscall
    test rax, rax
    jnz fatal
    mov eax, [r15 + D_START_STAT + 24]
    and eax, 0xf000
    cmp eax, 0x1000
    jne fatal
    mov esi, D_SNAPSHOT_BYTES
    call d_allocate
    mov [r15 + D_SNAPSHOT], rax
    mov rsi, rax
    mov edi, 4
    mov edx, 32
    call read_exact
    test eax, eax
    jnz fatal
    mov r12, [r15 + D_SNAPSHOT]
    movabs rax, 0x3154494e49444d48 /* HMDINIT1 */
    cmp [r12], rax
    jne fatal
    cmp qword ptr [r12 + 8], 1
    ja fatal
    cmp qword ptr [r12 + 16], 1
    ja fatal
    mov rdx, [r12 + 24]
    cmp rdx, 8388608
    ja fatal
    cmp qword ptr [r12 + 16], 0
    jne d_snapshot_length_valid
    test rdx, rdx
    jnz fatal
d_snapshot_length_valid:
    mov edi, 4
    lea rsi, [r12 + 32]
    call read_exact
    test eax, eax
    jnz fatal
    mov edi, 4
    lea rsi, [r15 + D_NOTICE]
    mov edx, 1
    call read_exact
    cmp eax, 1
    jne fatal
    lea rdi, [r15 + D_SNAPSHOT_FD]
    call d_close_slot
    mov rdi, [r15 + D_SNAPSHOT]
    mov esi, D_SNAPSHOT_BYTES
    mov edx, 1
    mov eax, 10
    syscall
    test rax, rax
    jnz fatal
    ret

d_startup:
    mov rax, [r15 + D_ENVP]
    mov [r15 + 648], rax
    lea rdi, [rip + d_env_user]
    call find_environment
    mov [r15 + D_USER_PTR], rax
    mov [r15 + D_USER_LEN], rdx
    test rax, rax
    setnz al
    movzx eax, al
    mov [r15 + D_USER_PRESENT], rax
    mov eax, 39
    syscall
    test rax, rax
    jle fatal
    mov [r15 + D_PARENT_PID], rax
    lea rdi, [r15 + INPUT]
    movabs rax, 0x3130514746435248
    mov [rdi], rax
    mov qword ptr [rdi + 8], 6
    mov qword ptr [rdi + 16], 0
    mov qword ptr [r15 + 24], 24
    mov qword ptr [r15 + 800], 3
    lea rax, [r15 + ROOT_WORK + FOOTER]
    mov qword ptr [rax + 120], 1
    jmp owner_resume

d_startup_config_result:
    cmp rax, 32
    jb fatal
    cmp rax, 131103
    ja fatal
    lea rdx, [r15 + OUTPUT]
    movabs rcx, 0x31304d4746435248
    cmp [rdx], rcx
    jne fatal
    sub rax, 32
    cmp [rdx + 24], rax
    jne fatal
    cmp qword ptr [rdx + 8], 0
    je d_startup_present
    cmp qword ptr [rdx + 8], 1
    jne fatal
    cmp qword ptr [rdx + 16], 9
    jne fatal
    cmp rax, 62
    jne fatal
    lea rdi, [rdx + 32]
    lea rsi, [rip + d_disabled_text]
    mov ecx, 62
    repe cmpsb
    jne fatal
    mov qword ptr [r15 + D_STARTUP_MODE], 0
    jmp d_startup_effects
d_startup_present:
    cmp qword ptr [rdx + 16], 0
    jne fatal
    test rax, rax
    jz fatal
    cmp byte ptr [rdx + 32], 47
    jne fatal
    lea rsi, [rdx + 32]
    lea rdi, [r15 + POLICY_INPUT]
    mov [r15 + D_STATE_PTR], rdi
    mov [r15 + D_STATE_LEN], rax
    mov rcx, rax
d_state_copy:
    lodsb
    test al, al
    jz fatal
    stosb
    loop d_state_copy
    mov byte ptr [rdi], 0
    mov qword ptr [r15 + D_STARTUP_MODE], 1
d_startup_effects:
    mov qword ptr [r15 + 800], 0
    /* Private TLS lets the signal handler find only its own fixed wake pipe. */
    mov edi, 0x1002
    mov rsi, r15
    mov eax, 158
    syscall
    test rax, rax
    jnz fatal
    lea rdi, [r15 + D_PIPES]
    mov esi, 0x80800
    mov eax, 293
    syscall
    test rax, rax
    jnz fatal
    mov eax, [r15 + D_PIPES]
    mov [r15 + D_WAKE_R], rax
    mov eax, [r15 + D_PIPES + 4]
    mov [r15 + D_WAKE_W], rax
    lea rax, [rip + d_sigchld]
    mov [r15 + D_SIGNAL_ACTION], rax
    mov qword ptr [r15 + D_SIGNAL_ACTION + 8], 0x14000000
    lea rax, [rip + d_signal_return]
    mov [r15 + D_SIGNAL_ACTION + 16], rax
    mov qword ptr [r15 + D_SIGNAL_ACTION + 24], 0
    mov edi, 17
    lea rsi, [r15 + D_SIGNAL_ACTION]
    xor edx, edx
    mov r10d, 8
    mov eax, 13
    syscall
    test rax, rax
    jnz fatal
    mov qword ptr [r15 + D_SIGNAL_MASK], 65536
    mov edi, 1 /* SIG_UNBLOCK */
    lea rsi, [r15 + D_SIGNAL_MASK]
    xor edx, edx
    mov r10d, 8
    mov eax, 14
    syscall
    test rax, rax
    jnz fatal
    mov qword ptr [r15 + D_SIGNAL_ACTION], 1 /* SIG_IGN */
    mov edi, 13 /* SIGPIPE */
    lea rsi, [r15 + D_SIGNAL_ACTION]
    xor edx, edx
    mov r10d, 8
    mov eax, 13
    syscall
    test rax, rax
    jnz fatal
    call d_launch_fence
    xor edi, edi
    mov esi, 3
    mov eax, 72
    syscall
    cmp rax, -4095
    jae fatal
    or eax, 2048
    mov edx, eax
    mov esi, 4
    mov eax, 72
    syscall
    test rax, rax
    jnz fatal
    mov esi, 268435456
    call d_allocate
    mov [r15 + D_PATH_WORK], rax
    mov esi, 4096
    call d_allocate
    mov [r15 + D_ERRNO_WORK], rax
    jmp d_main

d_allocate:
    xor edi, edi
    mov edx, 3
    mov r10d, 34
    mov r8, -1
    xor r9d, r9d
    mov eax, 9
    syscall
    cmp rax, -4095
    jae fatal
    ret

d_launch_fence:
    lea rdi, [rip + d_fence_name]
    mov esi, 3
    mov eax, 319
    syscall
    cmp rax, -4095
    jae fatal
    mov [r15 + D_MEMFD], rax
    mov rdi, rax
    /* The HIA linker binds both this RIP target and the exact embedded ELF. */
    .byte 0x48,0x8d,0x35
fence_blob_displacement:
    .long 0
    .byte 0xba
fence_blob_length:
    .long 0
    mov [r15 + D_BLOB_SIZE], rdx
    call write_exact
    test eax, eax
    jnz fatal
    mov rdi, [r15 + D_MEMFD]
    mov esi, 448
    mov eax, 91
    syscall
    test rax, rax
    jnz fatal
    mov rdi, [r15 + D_MEMFD]
    mov esi, 1033
    mov edx, 15
    mov eax, 72
    syscall
    test rax, rax
    jnz fatal
    mov esi, 1034
    mov eax, 72
    syscall
    and eax, 15
    cmp eax, 15
    jne fatal
    lea rdi, [r15 + D_PIPES]
    mov esi, 0x80000
    mov eax, 293
    syscall
    test rax, rax
    jnz fatal
    mov eax, [r15 + D_PIPES]
    mov [r15 + D_IN_R], rax
    mov eax, [r15 + D_PIPES + 4]
    mov [r15 + D_FENCE_IN], rax
    lea rdi, [r15 + D_PIPES]
    mov esi, 0x80000
    mov eax, 293
    syscall
    test rax, rax
    jnz fatal
    mov eax, [r15 + D_PIPES]
    mov [r15 + D_FENCE_OUT], rax
    mov eax, [r15 + D_PIPES + 4]
    mov [r15 + D_OUT_W], rax
    lea rdi, [r15 + D_PIPES]
    mov esi, 0x80000
    mov eax, 293
    syscall
    test rax, rax
    jnz fatal
    mov eax, [r15 + D_PIPES]
    mov [r15 + D_ERR_R], rax
    mov eax, [r15 + D_PIPES + 4]
    mov [r15 + D_ERR_W], rax
    lea rax, [rip + d_fence_name]
    mov [r15 + D_ARGV], rax
    lea rax, [rip + d_fence_absent]
    mov [r15 + D_ARGV + 8], rax
    mov qword ptr [r15 + D_ARGV + 16], 0
    mov qword ptr [r15 + D_ARGV + 24], 0
    cmp qword ptr [r15 + D_STARTUP_MODE], 0
    je d_fence_argv_ready
    lea rax, [rip + d_fence_option]
    mov [r15 + D_ARGV + 8], rax
    mov rax, [r15 + D_STATE_PTR]
    mov [r15 + D_ARGV + 16], rax
d_fence_argv_ready:
    mov eax, 57
    syscall
    cmp rax, -4095
    jae fatal
    test rax, rax
    jz d_fence_child
    mov [r15 + D_FENCE_PID], rax
    lea rdi, [r15 + D_IN_R]
    call d_close_slot
    lea rdi, [r15 + D_OUT_W]
    call d_close_slot
    lea rdi, [r15 + D_ERR_W]
    call d_close_slot
    mov rdi, [r15 + D_ERR_R]
    lea rsi, [r15 + D_EXEC_ERROR]
    mov edx, 8
    call read_exact
    cmp eax, 1
    jne fatal
    lea rdi, [r15 + D_ERR_R]
    call d_close_slot
    lea rdi, [r15 + D_MEMFD]
    call d_close_slot
    ret

d_fence_child:
    mov edi, 1
    mov esi, 9
    mov eax, 157
    syscall
    test rax, rax
    jnz d_fence_child_error
    mov eax, 110
    syscall
    cmp rax, [r15 + D_PARENT_PID]
    jne d_fence_child_parent_gone
    mov rax, [r15 + D_IN_R]
    mov [r15 + D_DUP_FDS], rax
    mov rax, [r15 + D_OUT_W]
    mov [r15 + D_DUP_FDS + 8], rax
    mov rax, [r15 + D_WAKE_W]
    mov [r15 + D_DUP_FDS + 16], rax
    mov rax, [r15 + D_MEMFD]
    mov [r15 + D_DUP_FDS + 24], rax
    mov rax, [r15 + D_ERR_W]
    mov [r15 + D_DUP_FDS + 32], rax
    xor ebx, ebx
d_fence_preserve_fds:
    mov rdi, [r15 + rbx*8 + D_DUP_FDS]
    mov esi, 1030
    mov edx, 16
    mov eax, 72
    syscall
    cmp rax, -4
    je d_fence_preserve_fds
    cmp rax, 16
    jb d_fence_child_error
    cmp rax, -4095
    jae d_fence_child_error
    mov [r15 + rbx*8 + D_DUP_FDS], rax
    inc ebx
    cmp ebx, 5
    jb d_fence_preserve_fds
    xor ebx, ebx
d_fence_normalize_fds:
    mov rdi, [r15 + rbx*8 + D_DUP_FDS]
    mov esi, ebx
    cmp ebx, 2
    jb d_fence_target_ready
    inc esi
d_fence_target_ready:
    xor edx, edx
    cmp ebx, 3
    jb d_fence_dup_ready
    mov edx, 0x80000
d_fence_dup_ready:
    mov eax, 292
    syscall
    cmp rax, -4
    je d_fence_normalize_fds
    cmp rax, -4095
    jae d_fence_child_error
    inc ebx
    cmp ebx, 5
    jb d_fence_normalize_fds
    mov qword ptr [r15 + D_ERR_W], 5
    mov edi, 2
    mov eax, 3
    syscall
    mov edi, 6
    mov esi, -1
    xor edx, edx
    mov eax, 436
    syscall
    test rax, rax
    jnz d_fence_child_error
    mov edi, 4
    lea rsi, [rip + d_empty]
    lea rdx, [r15 + D_ARGV]
    mov r10, [r15 + D_ENVP]
    mov r8d, 4096
    mov eax, 322
    syscall
d_fence_child_error:
    neg rax
    test rax, rax
    jnz d_fence_error_ready
    mov eax, 5
d_fence_error_ready:
    mov [r15 + D_EXEC_ERROR], rax
    mov rdi, [r15 + D_ERR_W]
    lea rsi, [r15 + D_EXEC_ERROR]
    mov edx, 8
    call write_exact
d_fence_child_parent_gone:
    mov edi, 113
    mov eax, 60
    syscall

d_close_slot:
    mov rax, [rdi]
    test rax, rax
    js d_close_done
    mov qword ptr [rdi], -1
    mov rdi, rax
    mov eax, 3
    syscall
d_close_done:
    ret

d_sigchld:
    mov edi, dword ptr fs:D_WAKE_W
    sub rsp, 8
    mov byte ptr [rsp], 1
    mov rsi, rsp
    mov edx, 1
    mov eax, 1
    syscall
    add rsp, 8
    ret
d_signal_return:
    mov eax, 15
    syscall

d_env_user:
    .asciz "USER="
d_disabled_text:
    .ascii "runtime tools are disabled; start with --runtime-config <file>"
d_fence_name:
    .asciz "hia-directory-shared-fence"
d_fence_option:
    .asciz "--state-root"
d_fence_absent:
    .asciz "--runtime-disabled"
d_empty:
    .byte 0
