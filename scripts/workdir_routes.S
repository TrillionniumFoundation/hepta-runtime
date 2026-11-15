/* Private, fixed-image byte and syscall dispatch.  All path and tool choices
 * belong to HIA.  The output wrapper observes the same session after a call. */
.global caller_call_displacement
.global params_call_displacement
.global path_call_displacement
.global raw_canonical_call_displacement
.equ WD_CALLER, 960
.equ WD_PARAMS, 968
.equ WD_PATH, 976
.equ WD_RAW, 984
.equ WD_INPUT, 992
.equ WD_LENGTH, 1000
.equ WD_SEQUENCE, 1008
.equ WD_CHILD, 1016
.equ WD_CHILD_LENGTH, 1024
.equ WD_CHILD_CAP, 1032
.equ WD_PARAMS_SEQUENCE, 1040
.equ WD_VALUE_LENGTH, 1048
.equ WD_READY, 1056
.equ WD_START_LENGTH, 1064
.equ WD_STACK, 1072
.equ WD_USER, 1080
.equ WD_USER_LENGTH, 1088
.equ WD_USER_PRESENT, 1096
.equ WD_RESULT_LENGTH, 1104
.equ WD_SNAPSHOT, 1120
.equ WD_OBSERVATION, 1160

wd_mmap:
    mov rsi, rdi
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

wd_initialize:
    mov edi, ROOT_WCAP
    call wd_mmap
    mov [r15 + WD_CALLER], rax
    mov edi, ROOT_WCAP
    call wd_mmap
    mov [r15 + WD_PARAMS], rax
    mov edi, ROOT_WCAP
    call wd_mmap
    mov [r15 + WD_PATH], rax
    mov edi, 4096
    call wd_mmap
    mov [r15 + WD_RAW], rax
    mov qword ptr [rax + 72], -1
    mov qword ptr [rax + 80], -1
    mov edi, 16781312
    call wd_mmap
    mov [r15 + WD_INPUT], rax
    mov rbx, [r15 + WD_STACK]
    mov rax, [rbx]
    lea rsi, [rbx + rax*8 + 16]
    mov [r15 + 648], rsi
wd_environment_end:
    cmp qword ptr [rsi], 0
    lea rsi, [rsi + 8]
    jne wd_environment_end
wd_auxiliary:
    mov rax, [rsi]
    test rax, rax
    jz wd_auxiliary_done
    cmp rax, 23
    jne wd_auxiliary_next
    xor eax, eax
    cmp qword ptr [rsi + 8], 0
    setne al
    mov rdx, [r15 + WD_RAW]
    mov [rdx + 64], rax
wd_auxiliary_next:
    add rsi, 16
    jmp wd_auxiliary
wd_auxiliary_done:
    lea rdi, [rip + wd_user_name]
    call find_environment
    mov [r15 + WD_USER], rax
    mov [r15 + WD_USER_LENGTH], rdx
    cmp rdx, 131071
    ja fatal
    test rax, rax
    setne al
    movzx eax, al
    mov [r15 + WD_USER_PRESENT], rax
    mov edi, 4
    lea rsi, [r15 + WD_SNAPSHOT]
    mov edx, 32
    call read_exact
    test eax, eax
    jnz fatal
    movabs rax, 0x3154494e49574d48 /* HMWINIT1 */
    cmp [r15 + WD_SNAPSHOT], rax
    jne fatal
    cmp qword ptr [r15 + WD_SNAPSHOT + 8], 1
    ja fatal
    cmp qword ptr [r15 + WD_SNAPSHOT + 16], 1
    ja fatal
    cmp qword ptr [r15 + WD_SNAPSHOT + 24], 8388608
    ja fatal
    lea rdi, [r15 + INPUT]
    movabs rax, 0x3130464344574d48 /* HMWDCF01 */
    mov [rdi], rax
    mov rax, [r15 + WD_USER_PRESENT]
    mov [rdi + 8], rax
    mov rax, [r15 + WD_USER_LENGTH]
    mov [rdi + 16], rax
    mov rax, [r15 + WD_SNAPSHOT + 8]
    mov [rdi + 24], rax
    mov rax, [r15 + WD_SNAPSHOT + 16]
    mov [rdi + 32], rax
    mov rax, [r15 + WD_SNAPSHOT + 24]
    mov [rdi + 40], rax
    mov qword ptr [rdi + 48], 0
    add rdi, 56
    mov rsi, [r15 + WD_USER]
    mov rcx, [r15 + WD_USER_LENGTH]
    rep movsb
    mov rsi, rdi
    mov edi, 4
    mov rdx, [r15 + WD_SNAPSHOT + 24]
    call read_exact
    test eax, eax
    jnz fatal
    mov edi, 4
    lea rsi, [r15 + WD_OBSERVATION]
    mov edx, 1
    call read_exact
    cmp eax, 1
    jne fatal
    mov edi, 4
    mov eax, 3
    syscall
    test rax, rax
    jnz fatal
    mov rax, [r15 + WD_USER_LENGTH]
    add rax, [r15 + WD_SNAPSHOT + 24]
    add rax, 56
    mov [r15 + WD_START_LENGTH], rax
    jmp wd_resume

wd_resume:
    mov rdi, [r15 + WD_INPUT]
    mov rsi, [r15 + WD_LENGTH]
    cmp qword ptr [r15 + WD_READY], 1
    je wd_input_selected
    lea rdi, [r15 + INPUT]
    mov rsi, [r15 + WD_START_LENGTH]
wd_input_selected:
    lea rdx, [r15 + OUTPUT]
    mov ecx, ROOT_OUTPUT_CAP
    mov r8, [r15 + WD_CALLER]
    mov r9d, ROOT_WCAP
    .byte 0xe8
caller_call_displacement:
    .long 0
    mov edx, eax
    cmp rax, rdx
    jne fatal
    cmp qword ptr [r15 + WD_READY], 1
    je wd_return
    test eax, eax
    jnz fatal
    mov qword ptr [r15 + WD_READY], 1
    jmp frame_next
wd_return:
    cmp eax, 0xfffffff0
    je wd_dispatch
    cmp eax, ROOT_OUTPUT_CAP
    ja wd_refusal
    cmp eax, 32
    jb fatal
    mov [r15 + WD_RESULT_LENGTH], rax
    mov rdi, [r15 + WD_CALLER]
    add rdi, 67117056
    lea rsi, [r15 + OUTPUT]
    mov rcx, rax
    rep movsb
    lea r13, [r15 + INPUT]
    movabs rax, 0x3130305157535248
    mov [r13], rax
    mov qword ptr [r13 + 8], 2
    mov qword ptr [r13 + 16], 0
    mov qword ptr [r13 + 24], 0
    mov qword ptr [r15 + 896], 32
    mov qword ptr [r15 + 904], 8388640
    mov qword ptr [r15 + 912], 2
    jmp session_resume
wd_refusal:
    cmp eax, 0xffffffff
    je wd_refusal_valid
    cmp eax, 0xfffffffe
    je wd_refusal_valid
    cmp eax, 0xffffffd0
    jne fatal
wd_refusal_valid:
    mov [r15 + 32], rax
    mov edi, 1
    lea rsi, [r15 + 32]
    mov edx, 8
    call write_exact
    test eax, eax
    jnz fatal
    jmp frame_next

wd_publish:
    mov [r15 + 32], rax
    add rax, [r15 + WD_RESULT_LENGTH]
    add rax, 32
    mov [r15 + WD_OBSERVATION], rax
    movabs rax, 0x3130424f44574d48 /* HMWDOB01 */
    mov [r15 + WD_OBSERVATION + 8], rax
    mov rax, [r15 + WD_RESULT_LENGTH]
    mov [r15 + WD_OBSERVATION + 16], rax
    mov rax, [r15 + SESSION_WORK + 40]
    mov [r15 + WD_OBSERVATION + 24], rax
    mov rax, [r15 + 32]
    mov [r15 + WD_OBSERVATION + 32], rax
    mov edi, 1
    lea rsi, [r15 + WD_OBSERVATION]
    mov edx, 40
    call write_exact
    test eax, eax
    jnz fatal
    mov edi, 1
    mov rsi, [r15 + WD_CALLER]
    add rsi, 67117056
    mov rdx, [r15 + WD_RESULT_LENGTH]
    call write_exact
    test eax, eax
    jnz fatal
    mov edi, 1
    lea rsi, [r15 + OUTPUT]
    mov rdx, [r15 + 32]
    call write_exact
    test eax, eax
    jnz fatal
    jmp frame_next

wd_dispatch:
    mov r14, [r15 + WD_CALLER]
    lea rdx, [r14 + 256]
    movabs rax, 0x3130414344574d48 /* HMWDCA01 */
    cmp [rdx], rax
    jne fatal
    mov rax, [r15 + WD_SEQUENCE]
    inc rax
    jz fatal
    cmp [rdx + 8], rax
    jne fatal
    cmp [r14 + 16], rax
    jne fatal
    mov [r15 + WD_SEQUENCE], rax
    mov rax, [rdx + 24]
    or rax, [rdx + 64]
    or rax, [rdx + 72]
    or rax, [rdx + 80]
    or rax, [rdx + 88]
    jnz fatal
    cmp qword ptr [rdx + 32], 4096
    jne fatal
    cmp qword ptr [rdx + 48], 67117056
    jne fatal
    mov rax, [rdx + 40]
    cmp rax, 24
    jb fatal
    cmp rax, 67108864
    ja fatal
    mov [r15 + WD_CHILD_LENGTH], rax
    mov rax, [rdx + 56]
    cmp rax, ROOT_OUTPUT_CAP
    ja fatal
    mov [r15 + WD_CHILD_CAP], rax
    mov rax, [rdx + 16]
    mov [r15 + WD_CHILD], rax
    cmp rax, 1
    je wd_params_resume
    cmp rax, 2
    je wd_context
    cmp rax, 3
    je wd_session
    cmp rax, 4
    je wd_config
    cmp rax, 5
    je wd_path
    cmp rax, 6
    je wd_policy
    cmp rax, 7
    je wd_raw
    cmp rax, 8
    je wd_directory
    jmp fatal

wd_params_resume:
    mov r13, [r15 + WD_CALLER]
    lea rdi, [r13 + 4096]
    mov rsi, [r15 + WD_CHILD_LENGTH]
    lea rdx, [r13 + 67117056]
    mov ecx, ROOT_OUTPUT_CAP
    mov r8, [r15 + WD_PARAMS]
    mov r9d, ROOT_WCAP
    .byte 0xe8
params_call_displacement:
    .long 0
    cmp eax, 0xfffffff0
    jne wd_child_complete
    mov r14, [r15 + WD_PARAMS]
    lea rdx, [r14 + 256]
    movabs rax, 0x3130415044574d48 /* HMWDPA01 */
    cmp [rdx], rax
    jne fatal
    mov rax, [r15 + WD_PARAMS_SEQUENCE]
    inc rax
    jz fatal
    cmp [rdx + 8], rax
    jne fatal
    cmp [r14 + 16], rax
    jne fatal
    mov [r15 + WD_PARAMS_SEQUENCE], rax
    cmp qword ptr [rdx + 16], 1
    jne fatal
    mov rax, [rdx + 24]
    or rax, [rdx + 64]
    or rax, [rdx + 72]
    or rax, [rdx + 80]
    or rax, [rdx + 88]
    jnz fatal
    cmp qword ptr [rdx + 32], 4096
    jne fatal
    cmp qword ptr [rdx + 48], 67117056
    jne fatal
    cmp qword ptr [rdx + 56], 67108864
    jne fatal
    mov rsi, [rdx + 40]
    cmp rsi, 24
    jb fatal
    cmp rsi, 8388632
    ja fatal
    lea rdi, [r14 + 4096]
    movabs rax, 0x31304c41564a5348 /* HSJVAL01 */
    cmp [rdi], rax
    jne fatal
    cmp qword ptr [rdi + 8], 1
    jne fatal
    mov rax, [rdi + 16]
    add rax, 24
    cmp rax, rsi
    jne fatal
    lea rdx, [r14 + 67117056]
    mov ecx, 67108864
    lea r8, [r15 + JSON_WORK]
    mov r9d, ROOT_WCAP
    mov qword ptr [r15 + 80], 13
    jmp shared_value_call
wd_params_value_completed:
    cmp eax, 67108864
    jbe wd_params_value_valid
    cmp eax, 0xffffffff
    je wd_params_value_valid
    cmp eax, 0xfffffffe
    jne fatal
wd_params_value_valid:
    mov rdx, [r15 + WD_PARAMS]
    mov [rdx + 256 + 72], rax
    mov rax, [r15 + WD_PARAMS_SEQUENCE]
    mov [rdx + 256 + 64], rax
    jmp wd_params_resume

wd_context:
    cmp qword ptr [r15 + WD_CHILD_CAP], 32
    jne fatal
    mov rcx, [r15 + WD_CHILD_LENGTH]
    cmp rcx, 16777256
    ja fatal
    mov [r15 + 888], rcx
    lea rsi, [r14 + 4096]
    lea rdi, [r15 + POLICY_INPUT]
    rep movsb
    jmp context_resume
wd_context_completed:
    lea rsi, [r15 + OUTPUT]
    jmp wd_child_copy

wd_session:
    mov rcx, [r15 + WD_CHILD_LENGTH]
    cmp rcx, 8388640
    ja fatal
    mov [r15 + 896], rcx
    mov rax, [r15 + WD_CHILD_CAP]
    mov [r15 + 904], rax
    lea rsi, [r14 + 4096]
    lea rdi, [r15 + INPUT]
    rep movsb
    mov qword ptr [r15 + 912], 3
    jmp session_resume
wd_session_completed:
    lea rsi, [r15 + OUTPUT]
    jmp wd_child_copy

wd_config:
    cmp qword ptr [r15 + WD_CHILD_CAP], ROOT_OUTPUT_CAP
    jne fatal
    mov rcx, [r15 + WD_CHILD_LENGTH]
    cmp rcx, ROOT_INPUT_CAP
    ja fatal
    mov [r15 + 24], rcx
    lea rsi, [r14 + 4096]
    lea rdi, [r15 + INPUT]
    rep movsb
    mov qword ptr [r15 + 800], 2
    lea rax, [r15 + ROOT_WORK + FOOTER]
    mov qword ptr [rax + 120], 1
    jmp owner_resume
wd_config_completed:
    mov qword ptr [r15 + 800], 0
    lea rsi, [r15 + OUTPUT]
    jmp wd_child_copy

wd_path:
    cmp qword ptr [r15 + WD_CHILD_CAP], 33554432
    jne fatal
    lea rdi, [r14 + 4096]
    mov rsi, [r15 + WD_CHILD_LENGTH]
    lea rdx, [r14 + 67117056]
    mov ecx, 33554432
    mov r8, [r15 + WD_PATH]
    mov r9d, ROOT_WCAP
    .byte 0xe8
path_call_displacement:
    .long 0
    jmp wd_child_complete

wd_policy:
    cmp qword ptr [r15 + WD_CHILD_CAP], ROOT_OUTPUT_CAP
    jne fatal
    mov rcx, [r15 + WD_CHILD_LENGTH]
    mov [r15 + 896], rcx
    mov qword ptr [r15 + 904], ROOT_OUTPUT_CAP
    lea rsi, [r14 + 4096]
    lea rdi, [r15 + CONTEXT_WORK + 4096]
    rep movsb
    mov qword ptr [r15 + 920], 0
    jmp policy_resume
wd_directory:
    cmp qword ptr [r15 + WD_CHILD_CAP], ROOT_OUTPUT_CAP
    jne fatal
    mov rcx, [r15 + WD_CHILD_LENGTH]
    mov [r15 + 896], rcx
    mov qword ptr [r15 + 904], ROOT_OUTPUT_CAP
    lea rsi, [r14 + 4096]
    lea rdi, [r15 + CONTEXT_WORK + 4096]
    rep movsb
    mov qword ptr [r15 + 920], 1
    jmp canonical_resume
wd_policy_completed:
    lea rsi, [r15 + CONTEXT_WORK + 67117056]
    jmp wd_child_copy

wd_raw:
    cmp qword ptr [r15 + WD_CHILD_CAP], ROOT_OUTPUT_CAP
    jne fatal
    lea rdi, [r14 + 4096]
    mov rsi, [r15 + WD_CHILD_LENGTH]
    lea rdx, [r14 + 67117056]
    mov ecx, ROOT_OUTPUT_CAP
    mov r8, [r15 + WD_RAW]
    call wd_raw_run
    jmp wd_child_complete

wd_child_copy:
    cmp eax, 0xffffffff
    je wd_child_complete
    cmp eax, 0xfffffffe
    je wd_child_complete
    cmp rax, [r15 + WD_CHILD_CAP]
    ja fatal
    mov rdi, [r15 + WD_CALLER]
    add rdi, 67117056
    mov rcx, rax
    rep movsb
wd_child_complete:
    mov edx, eax
    cmp rax, rdx
    jne fatal
    cmp rax, [r15 + WD_CHILD_CAP]
    jbe wd_child_valid
    cmp eax, 0xffffffff
    je wd_child_valid
    cmp eax, 0xfffffffe
    jne fatal
wd_child_valid:
    mov rdx, [r15 + WD_CALLER]
    mov [rdx + 256 + 72], rax
    mov rax, [r15 + WD_SEQUENCE]
    mov [rdx + 256 + 64], rax
    jmp wd_resume

wd_user_name:
    .asciz "USER"
