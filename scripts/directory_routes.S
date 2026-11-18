d_call_caller:
    mov rax, [r15 + D_CURRENT]
    mov r8, [rax + T_WORK]
    mov rdx, [rax + T_OUTPUT]
    mov rcx, [r15 + D_ENTRY_KIND]
    mov [r8 + FOOTER + 120], rcx
    mov rdi, [r15 + D_ENTRY_PTR]
    mov rsi, [r15 + D_ENTRY_LEN]
    mov ecx, ROOT_OUTPUT_CAP
    mov r9d, ROOT_WCAP
    .byte 0xe8
caller_call_displacement:
    .long 0
    mov edx, eax
    cmp rax, rdx
    jne fatal
    ret

d_drive:
    call d_call_caller
    cmp eax, 0xfffffff0
    je d_dispatch
    cmp eax, 0xffffffd2
    je d_pause
    cmp eax, 0xffffffd3
    je d_pause
    mov rbx, [r15 + D_CURRENT]
    mov rdx, [rbx + T_WORK]
    mov rcx, [rdx + 24]
    or rcx, [rdx + 32]
    or rcx, [rdx + 40]
    or rcx, [rdx + 48]
    or rcx, [rdx + 8]
    or rcx, [rbx + T_PID]
    jnz fatal
    cmp eax, ROOT_OUTPUT_CAP
    jbe d_complete_task
    cmp eax, 0xffffffff
    je d_complete_task
    cmp eax, 0xfffffffe
    je d_complete_task
    jmp fatal
d_pause:
    ret

d_dispatch:
    mov rbx, [r15 + D_CURRENT]
    mov r14, [rbx + T_WORK]
    lea r13, [r14 + 256]
    movabs rax, 0x3130414343444d48 /* HMDCCA01 */
    cmp [r13], rax
    jne fatal
    mov rax, [rbx + T_SEQUENCE]
    inc rax
    jz fatal
    cmp [r13 + 8], rax
    jne fatal
    cmp [r14 + 16], rax
    jne fatal
    mov [rbx + T_SEQUENCE], rax
    mov rax, [r13 + 24]
    or rax, [r13 + 64]
    or rax, [r13 + 72]
    or rax, [r13 + 80]
    or rax, [r13 + 88]
    jnz fatal
    cmp qword ptr [r13 + 32], 4096
    jne fatal
    cmp qword ptr [r13 + 48], 67117056
    jne fatal
    mov rax, [r13 + 40]
    cmp rax, 67108864
    ja fatal
    mov [r15 + D_CHILD_LEN], rax
    cmp qword ptr [r13 + 56], ROOT_OUTPUT_CAP
    ja fatal
    mov rcx, [r13 + 16]
    cmp rcx, 1
    je d_fence_request
    cmp rcx, 2
    je d_context_request
    cmp rcx, 3
    je d_session_request
    cmp rcx, 4
    je d_config_request
    cmp rcx, 5
    je d_path_request
    cmp rcx, 6
    je d_policy_request
    cmp rcx, 7
    je d_mkdir_request
    cmp rcx, 8
    je d_errno_request
    jmp fatal

d_child_completed:
    mov edx, eax
    cmp rax, rdx
    jne fatal
    mov rbx, [r15 + D_CURRENT]
    mov r14, [rbx + T_WORK]
    cmp rax, [r14 + 256 + 56]
    jbe d_child_bound
    cmp eax, 0xffffffff
    je d_child_bound
    cmp eax, 0xfffffffe
    jne fatal
d_child_bound:
    mov [r14 + 256 + 72], rax
    mov rax, [rbx + T_SEQUENCE]
    cmp [r14 + 256 + 8], rax
    jne fatal
    mov [r14 + 256 + 64], rax
    mov qword ptr [r15 + D_ENTRY_KIND], 2
    mov qword ptr [r15 + D_ENTRY_LEN], 0
    lea rax, [rip + d_empty]
    mov [r15 + D_ENTRY_PTR], rax
    jmp d_drive

d_fence_request:
    cmp rax, 64
    jne fatal
    cmp qword ptr [r13 + 56], 64
    jne fatal
    lea r12, [r14 + 4096]
    movabs rcx, 0x3130595341464648
    cmp [r12], rcx
    jne fatal
    mov rcx, [r12 + 32]
    or rcx, [r12 + 40]
    or rcx, [r12 + 48]
    or rcx, [r12 + 56]
    jnz fatal
    cmp qword ptr [r14 + 8], 1
    je d_fence_create
    cmp qword ptr [r12 + 24], 0
    jne fatal
    cmp qword ptr [r14 + 8], 2
    je d_fence_poll
    cmp qword ptr [r14 + 8], 90
    je d_fence_release
    cmp qword ptr [r14 + 8], 92
    jne fatal
    cmp qword ptr [r12 + 8], 3
    jne fatal
    jmp d_fence_retire_id
d_fence_release:
    cmp qword ptr [r12 + 8], 5
    jne fatal
d_fence_retire_id:
    mov rcx, [r14 + 168]
    cmp [r12 + 16], rcx
    jne fatal
    jmp d_fence_ipc
d_fence_create:
    cmp qword ptr [r12 + 8], 1
    jne fatal
    cmp qword ptr [r12 + 16], 0
    jne fatal
    cmp qword ptr [r12 + 24], 1
    jne fatal
    jmp d_fence_ipc
d_fence_poll:
    cmp qword ptr [r12 + 8], 8
    jne fatal
    mov rcx, [r14 + 32]
    cmp [r12 + 16], rcx
    jne fatal
d_fence_ipc:
    cmp qword ptr [r15 + D_FENCE_CLOSED], 0
    jne fatal
    mov qword ptr [r15 + D_REPLY], 64
    mov rdi, [r15 + D_FENCE_IN]
    lea rsi, [r15 + D_REPLY]
    mov edx, 8
    call write_exact
    test eax, eax
    jnz fatal
    mov rdi, [r15 + D_FENCE_IN]
    mov rsi, r12
    mov edx, 64
    call write_exact
    test eax, eax
    jnz fatal
    mov rdi, [r15 + D_FENCE_OUT]
    lea rsi, [r15 + D_REPLY]
    mov edx, 8
    call read_exact
    test eax, eax
    jnz fatal
    cmp qword ptr [r15 + D_REPLY], 64
    jne fatal
    mov rdi, [r15 + D_FENCE_OUT]
    lea rsi, [r14 + 67117056]
    mov edx, 64
    call read_exact
    test eax, eax
    jnz fatal
    mov eax, 64
    jmp d_child_completed

d_context_request:
    cmp qword ptr [r14 + 8], 3
    jne fatal
    cmp qword ptr [r13 + 56], 32
    jne fatal
    cmp rax, 40
    jb fatal
    cmp rax, 16777256
    ja fatal
    movabs rcx, 0x3130514343535248 /* HRSCCQ01 */
    cmp [r14 + 4096], rcx
    jne fatal
    mov qword ptr [r15 + D_POLICY_PARENT], 0
    jmp context_resume
d_session_request:
    cmp qword ptr [r14 + 8], 4
    jne fatal
    cmp rax, 32
    jne fatal
    cmp qword ptr [r13 + 56], 16777216
    jne fatal
    movabs rcx, 0x3130305157535248
    cmp [r14 + 4096], rcx
    jne fatal
    cmp qword ptr [r14 + 4104], 2
    jne fatal
    mov rcx, [r14 + 4112]
    or rcx, [r14 + 4120]
    jnz fatal
    mov qword ptr [r15 + 912], 3
    mov qword ptr [r15 + 896], 32
    mov qword ptr [r15 + 904], 16777216
    jmp session_resume
d_config_request:
    cmp qword ptr [r13 + 56], ROOT_OUTPUT_CAP
    jne fatal
    movabs rcx, 0x3130514746435248
    cmp [r14 + 4096], rcx
    jne fatal
    cmp qword ptr [r14 + 8], 5
    je d_config_state_query
    cmp qword ptr [r14 + 8], 8
    jne fatal
    cmp qword ptr [r14 + 4104], 8
    jne fatal
    cmp rax, 64
    jb fatal
    cmp qword ptr [r14 + 4096 + 40], 1
    jne fatal
    jmp d_config_query_ready
d_config_state_query:
    cmp qword ptr [r14 + 4104], 6
    jne fatal
    cmp rax, 24
    jne fatal
d_config_query_ready:
    mov rcx, [r14 + 4112]
    add rcx, 24
    jc fatal
    cmp rcx, rax
    jne fatal
    mov qword ptr [r15 + 800], 2
    lea rax, [r15 + ROOT_WORK + FOOTER]
    mov qword ptr [rax + 120], 1
    jmp owner_resume

d_path_request:
    cmp qword ptr [r14 + 8], 6
    jne fatal
    cmp qword ptr [r13 + 56], 33554432
    jne fatal
    cmp rax, 56
    jb fatal
    cmp rax, 33554432
    ja fatal
    movabs rcx, 0x3130514c4f535248 /* HRSOLQ01 */
    cmp [r14 + 4096], rcx
    jne fatal
    cmp qword ptr [r14 + 4104], 2
    jne fatal
    lea rdi, [r14 + 4096]
    mov rsi, rax
    lea rdx, [r14 + 67117056]
    mov ecx, 33554432
    mov r8, [r15 + D_PATH_WORK]
    mov r9d, ROOT_WCAP
    .byte 0xe8
path_call_displacement:
    .long 0
    jmp d_child_completed

d_policy_request:
    cmp qword ptr [r14 + 8], 7
    je d_local_policy_phase
    cmp qword ptr [r14 + 8], 9
    jne fatal
d_local_policy_phase:
    cmp qword ptr [r13 + 56], ROOT_OUTPUT_CAP
    jne fatal
    cmp rax, 24
    jb fatal
    cmp rax, 33554456
    ja fatal
    movabs rcx, 0x31305143504c5248 /* HRLPCQ01 */
    cmp [r14 + 4096], rcx
    jne fatal
    cmp qword ptr [r14 + 4104], 1
    jne fatal
    mov rcx, [r14 + 4112]
    add rcx, 24
    jc fatal
    cmp rax, rcx
    jne fatal
    mov qword ptr [r15 + D_POLICY_PARENT], 1
    /* A preceding context may have used canonical's is_dir route. This new
       call belongs to policy, including every resumed canonical effect. */
    mov qword ptr [r15 + 920], 0
    jmp policy_resume

d_mkdir_request:
    cmp qword ptr [r14 + 8], 10
    jne fatal
    cmp qword ptr [r13 + 56], 32
    jne fatal
    cmp rax, 24
    jb fatal
    cmp rax, 33554456
    ja fatal
    movabs rcx, 0x3130515249444d48 /* HMDIRQ01 */
    cmp [r14 + 4096], rcx
    jne fatal
    cmp qword ptr [r14 + 4104], 1
    jne fatal
    mov rcx, [r14 + 4112]
    add rcx, 24
    jc fatal
    cmp rax, rcx
    jne fatal
    mov rcx, [rbx + T_PID]
    or rcx, [rbx + T_JOB]
    jnz fatal
    call d_launch_mkdir
    mov rbx, [r15 + D_CURRENT]
    mov r14, [rbx + T_WORK]
    lea rdx, [r14 + 67117056]
    movabs rcx, 0x313053524a444d48 /* HMDJRS01 */
    mov [rdx], rcx
    mov qword ptr [rdx + 8], 0
    mov rcx, [rbx + T_JOB]
    mov [rdx + 16], rcx
    mov [rdx + 24], rax
    test rax, rax
    jz d_mkdir_start_ready
    cmp rax, 4095
    ja fatal
    test rcx, rcx
    jnz fatal
    mov qword ptr [rdx + 8], 1
d_mkdir_start_ready:
    mov eax, 32
    jmp d_child_completed

d_errno_request:
    cmp qword ptr [r14 + 8], 11
    jne fatal
    cmp rax, 16
    jne fatal
    cmp qword ptr [r13 + 56], 4096
    jne fatal
    movabs rcx, 0x3130515245444d48 /* HMDERQ01 */
    cmp [r14 + 4096], rcx
    jne fatal
    lea rdi, [r14 + 4096]
    mov esi, 16
    lea rdx, [r14 + 67117056]
    mov ecx, 4096
    mov r8, [r15 + D_ERRNO_WORK]
    mov r9d, 4096
    .byte 0xe8
errno_call_displacement:
    .long 0
    jmp d_child_completed
