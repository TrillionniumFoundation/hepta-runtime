/* Closed Linux x86-64 primitives for ssh_direct_owner.hepta.
 * HIA owns admission, cancellation, errors, timeout, stream limits, and release.
 * This private typed boundary owns only one original child, sealed executable,
 * inherited raw environment snapshot, pipe/pidfd descriptors and exact ACK.
 * No public frame can supply an fd, PID, executable path, or callback pointer.
 */
.intel_syntax noprefix
.section .text
.global ssh_direct_engine
ssh_direct_engine:
    .byte 0xe9
    .long create - . - 4
    .byte 0xe9
    .long step - . - 4
    .byte 0xe9
    .long child_ack - . - 4
    .byte 0xe9
    .long notify - . - 4
    .byte 0xe9
    .long rebind - . - 4
    .byte 0xe9
    .long destroy - . - 4

.equ W, 8
.equ WCAP, 16
.equ ENV, 24
.equ ENV_SIZE, 32
.equ SEQ, 40
.equ DELEGATE, 48
.equ TOKEN, 56
.equ PID, 64
.equ PIDFD, 72
.equ INFD, 80
.equ OUTFD, 88
.equ ERRFD, 96
.equ EXFD, 104
.equ EXWRITE, 112
.equ REAPED, 120
.equ WAIT_STATUS, 128
.equ SIGNAL_SENT, 136
.equ EXEC_STATE, 144
.equ WAIT_UNKNOWN, 152
.equ WAKEFD, 160
.equ ARGV, 168
.equ ARGV_SIZE, 176
.equ SELF_PID, 184
.equ CANCEL_BITS, 192
.equ SHADOW, 200
.equ RESULT, 264
.equ ERROR, 272
.equ AUX, 280
.equ PIPES, 288
.equ EXEC_ERROR, 320
.equ EXEC_HAVE, 328
.equ CLOCKBUF, 336
.equ POLLFDS, 576
.equ POLLTIME, 624
.equ SIGNAL_ACTION, 408
.equ EXEC_ERRNO, 440
.equ GENERATION, 448
.equ STATE, 456
.equ COMMITTED, 472
.equ RELEASED, 480
.equ ATTEMPTED, 488
.equ PROGRAM, 504
.equ CONTRACT, 0xfffffff9

.macro ENTER
    cld
    push rbp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub rsp, 8
.endm
.macro LEAVE
    add rsp, 8
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret
.endm

/* create(owner_workspace, capacity, raw_envp, nonzero_token, sealed_program_fd)
 * The caller supplies only installer-owned private capabilities.
 * Env is copied, including arbitrary bytes, duplicates and any entry count.
 */
create:
    ENTER
    test rdi, rdi
    jz create_bad
    test rdx, rdx
    jz create_bad
    test rcx, rcx
    jz create_bad
    cmp rsi, 24576
    jb create_bad
    mov rax, rdi
    add rax, rsi
    jc create_bad
    movabs rax, 0x3130545348535348
    cmp [rdi], rax
    jne create_bad
    cmp [rdi + 24], rcx
    jne create_bad
    cmp qword ptr [rdi + 8], 1
    jne create_bad
    cmp qword ptr [rdi + 16], 1
    jne create_bad
    test r8, r8
    js create_bad
    mov r12, rdi
    mov r13, rsi
    mov r14, rdx
    mov r15, rcx
    mov rbx, r8
    mov esi, 4096
    call allocate
    test rax, rax
    js create_done
    movabs rcx, 0x3130544348535348
    mov [rax], rcx
    mov [rax + W], r12
    mov [rax + WCAP], r13
    mov [rax + TOKEN], r15
    mov rcx, [r12 + 184]
    mov [rax + GENERATION], rcx
    mov r12, rax
    mov qword ptr [r12 + PIDFD], -1
    mov qword ptr [r12 + INFD], -1
    mov qword ptr [r12 + OUTFD], -1
    mov qword ptr [r12 + ERRFD], -1
    mov qword ptr [r12 + EXFD], -1
    mov qword ptr [r12 + EXWRITE], -1
    mov qword ptr [r12 + WAKEFD], -1
    mov qword ptr [r12 + PROGRAM], -1
    lea rdi, [r12 + PIPES]
    mov ecx, 8
    mov eax, -1
    rep stosd
    mov rdi, rbx
    mov esi, 1034 /* F_GET_SEALS */
    mov eax, 72
    syscall
    test rax, rax
    js create_error
    and eax, 15
    cmp eax, 15
    jne create_unsealed
    mov rdi, rbx
    mov esi, 1030 /* F_DUPFD_CLOEXEC */
    mov edx, 3
    mov eax, 72
    syscall
    test rax, rax
    js create_error
    mov [r12 + PROGRAM], rax
    mov r13, r14
    xor r14d, r14d
    xor r15d, r15d
env_count:
    mov rsi, [r13 + r14*8]
    test rsi, rsi
    jz env_size
    xor ecx, ecx
env_length:
    cmp byte ptr [rsi + rcx], 0
    je env_length_done
    inc rcx
    jz create_overflow
    jmp env_length
env_length_done:
    inc rcx
    jz create_overflow
    add r15, rcx
    jc create_overflow
    inc r14
    mov rax, r14
    shr rax, 60
    jnz create_overflow
    jmp env_count
env_size:
    lea rbx, [r14*8 + 8]
    mov rsi, rbx
    add rsi, r15
    jc create_overflow
    mov [r12 + ENV_SIZE], rsi
    call allocate
    test rax, rax
    js create_error
    mov [r12 + ENV], rax
    mov rbp, rax
    add rbx, rax
    add r15, rbx
    xor r8d, r8d
env_copy:
    cmp r8, r14
    je env_copy_done
    mov rsi, [r13 + r8*8]
    test rsi, rsi
    jz create_environment_changed
    mov [rbp + r8*8], rbx
env_copy_byte:
    cmp rbx, r15
    jae create_environment_changed
    mov al, [rsi]
    mov [rbx], al
    inc rsi
    inc rbx
    test al, al
    jnz env_copy_byte
    inc r8
    jmp env_copy
env_copy_done:
    cmp rbx, r15
    jne create_environment_changed
    cmp qword ptr [r13 + r14*8], 0
    jne create_environment_changed
    mov qword ptr [rbp + r14*8], 0
    xor r8d, r8d
env_recheck:
    cmp r8, r14
    je env_ready
    mov rsi, [r13 + r8*8]
    mov rdi, [rbp + r8*8]
    test rsi, rsi
    jz create_environment_changed
env_compare_byte:
    mov al, [rdi]
    cmp al, [rsi]
    jne create_environment_changed
    inc rsi
    inc rdi
    test al, al
    jnz env_compare_byte
    inc r8
    jmp env_recheck
env_ready:
    xor edi, edi
    mov esi, 0x80800 /* EFD_NONBLOCK|EFD_CLOEXEC */
    mov eax, 290
    syscall
    test rax, rax
    js create_error
    mov rdi, rax
    call normalize_fd
    test rax, rax
    js create_error
    mov [r12 + WAKEFD], rax
    /* Match the original controller's ignored SIGPIPE. The child resets it. */
    mov qword ptr [r12 + SIGNAL_ACTION], 1
    mov edi, 13
    lea rsi, [r12 + SIGNAL_ACTION]
    xor edx, edx
    mov r10d, 8
    mov eax, 13
    syscall
    test rax, rax
    js create_error
    mov qword ptr [r12 + SIGNAL_ACTION], 0
    mov eax, 39
    syscall
    mov [r12 + SELF_PID], rax
    mov qword ptr [r12 + STATE], 1
    mov rax, r12
    jmp create_done
create_unsealed:
    mov rax, -1
    jmp create_error
create_environment_changed:
    mov rax, -116
    jmp create_error
create_overflow:
    mov rax, -75
create_error:
    mov r15, rax
    lea rdi, [r12 + PROGRAM]
    call close_slot
    lea rdi, [r12 + WAKEFD]
    call close_slot
    mov rdi, [r12 + ENV]
    test rdi, rdi
    jz create_free_context
    mov rsi, [r12 + ENV_SIZE]
    mov eax, 11
    syscall
create_free_context:
    mov rdi, r12
    mov esi, 4096
    mov eax, 11
    syscall
    mov rax, r15
    jmp create_done
create_bad:
    mov rax, -22
create_done:
    LEAVE

/* step(ctx): 0 exact ACK stored; 1 delegated HIA admission/release;
 * CONTRACT means the pending identity changed and nothing may be replayed.
 */
step:
    ENTER
    mov r12, rdi
    call check_context
    test eax, eax
    jz step_contract
    cmp qword ptr [r12 + DELEGATE], 0
    jne step_contract
    mov r13, [r12 + W]
    lea r14, [r13 + 256]
    movabs rax, 0x3130304148535348
    cmp [r14], rax
    jne step_contract
    cmp qword ptr [r14 + 56], 0
    jne step_contract
    mov rax, [r12 + SEQ]
    inc rax
    jz step_contract
    cmp [r14 + 8], rax
    jne step_contract
    xor ecx, ecx
step_shadow:
    mov rdx, [r14 + rcx]
    cmp rdx, [r13 + rcx + 512]
    jne step_contract
    mov [r12 + rcx + SHADOW], rdx
    add ecx, 8
    cmp ecx, 64
    jb step_shadow
    mov [r12 + SEQ], rax
    mov qword ptr [r12 + RESULT], 0
    mov qword ptr [r12 + ERROR], 0
    mov qword ptr [r12 + AUX], 0
    mov rax, [r12 + SHADOW + 16]
    cmp rax, 1
    je effect_clock
    cmp rax, 2
    je effect_commit
    cmp rax, 3
    je effect_spawn
    cmp rax, 5
    je effect_write
    cmp rax, 6
    je effect_read
    cmp rax, 7
    je effect_exec
    cmp rax, 8
    je effect_wait
    cmp rax, 9
    je effect_signal
    cmp rax, 10
    je effect_close_stdin
    cmp rax, 11
    je effect_close_pipes
    cmp rax, 12
    je effect_poll
    cmp rax, 13
    je effect_release
    jmp step_contract

effect_clock:
    mov edi, 1
    lea rsi, [r12 + CLOCKBUF]
    mov eax, 228
    syscall
    test rax, rax
    js step_errno
    mov rax, [r12 + CLOCKBUF]
    mov ecx, 1000000000
    mul rcx
    test rdx, rdx
    jnz clock_overflow
    add rax, [r12 + CLOCKBUF + 8]
    jc clock_overflow
    mov [r12 + AUX], rax
    mov rax, [r12 + CANCEL_BITS]
    and eax, 3
    mov [r12 + RESULT], rax
    jmp step_complete
clock_overflow:
    mov eax, 75
    jmp step_positive_errno

effect_commit:
    mov rax, [r12 + SHADOW + 24]
    cmp rax, [r12 + TOKEN]
    jne step_contract
    mov rax, [r12 + SHADOW + 40]
    cmp rax, [r12 + GENERATION]
    jne step_contract
    cmp qword ptr [r12 + COMMITTED], 0
    jne step_contract
    cmp qword ptr [r12 + ATTEMPTED], 0
    jne step_contract
    mov qword ptr [r12 + DELEGATE], 2
    mov eax, 1
    jmp step_done

effect_release:
    mov rax, [r12 + SHADOW + 24]
    cmp rax, [r12 + TOKEN]
    jne step_contract
    cmp qword ptr [r12 + COMMITTED], 1
    jne step_contract
    cmp qword ptr [r12 + RELEASED], 0
    jne step_contract
    cmp qword ptr [r12 + WAIT_UNKNOWN], 0
    jne step_contract
    cmp qword ptr [r12 + PID], 0
    je release_delegate
    cmp qword ptr [r12 + REAPED], 1
    jne step_contract
release_delegate:
    mov qword ptr [r12 + DELEGATE], 13
    mov eax, 1
    jmp step_done

effect_spawn:
    cmp qword ptr [r12 + COMMITTED], 1
    jne step_contract
    cmp qword ptr [r12 + ATTEMPTED], 0
    jne step_contract
    cmp qword ptr [r12 + PID], 0
    jne step_contract
    mov rax, [r12 + SHADOW + 40]
    cmp rax, [r12 + TOKEN]
    jne step_contract
    cmp qword ptr [r12 + SHADOW + 48], 0
    jne step_contract
    mov rbx, [r12 + SHADOW + 24]
    mov rbp, [r12 + SHADOW + 32]
    cmp rbp, 128
    jb step_contract
    cmp rbx, [r12 + WCAP]
    ja step_contract
    mov rax, [r12 + WCAP]
    sub rax, rbx
    cmp rbp, rax
    ja step_contract
    add rbx, r13
    movabs rax, 0x3330504853424648
    cmp [rbx], rax
    jne step_contract
    cmp qword ptr [rbx + 64], 12
    jne step_contract
    mov rax, rbp
    sub rax, 128
    cmp [rbx + 80], rax
    jne step_contract
    mov qword ptr [r12 + ATTEMPTED], 1
    mov rsi, rbp
    add rsi, 128
    jc spawn_overflow
    mov [r12 + ARGV_SIZE], rsi
    call allocate
    test rax, rax
    js spawn_error
    mov [r12 + ARGV], rax
    lea rdi, [rax + 104]
    mov r15, rax
    add r15, [r12 + ARGV_SIZE]
    lea rsi, [rbx + 128]
    add rbp, rbx
    xor r8d, r8d
spawn_args:
    cmp r8, 12
    je spawn_args_done
    mov rax, rbp
    sub rax, rsi
    cmp rax, 8
    jb spawn_invalid
    mov rcx, [rsi]
    add rsi, 8
    test rcx, rcx
    jz spawn_invalid
    mov rax, rbp
    sub rax, rsi
    cmp rcx, rax
    ja spawn_invalid
    mov rax, r15
    sub rax, rdi
    cmp rcx, rax
    jae spawn_invalid
    mov rax, [r12 + ARGV]
    mov [rax + r8*8], rdi
spawn_arg_bytes:
    lodsb
    test al, al
    jz spawn_invalid
    stosb
    dec rcx
    jnz spawn_arg_bytes
    mov byte ptr [rdi], 0
    inc rdi
    inc r8
    jmp spawn_args
spawn_args_done:
    mov rax, [r12 + ARGV]
    mov qword ptr [rax + 96], 0
    sub rbp, rsi
    cmp rbp, [rbx + 72]
    jne spawn_invalid
    xor r15d, r15d
spawn_pipes:
    lea rdi, [r12 + PIPES + r15*8]
    mov esi, 0x80000 /* O_CLOEXEC */
    mov eax, 293
    syscall
    test rax, rax
    js spawn_error
    lea rbp, [r12 + PIPES + r15*8]
    movsxd rdi, dword ptr [rbp]
    mov dword ptr [rbp], -1
    call normalize_fd
    test rax, rax
    js spawn_error
    mov [rbp], eax
    movsxd rdi, dword ptr [rbp + 4]
    mov dword ptr [rbp + 4], -1
    call normalize_fd
    test rax, rax
    js spawn_error
    mov [rbp + 4], eax
    inc r15
    cmp r15, 4
    jb spawn_pipes
    /* Set only parent-facing ends nonblocking; child pipe ends remain blocking. */
    movsxd rdi, dword ptr [r12 + PIPES + 4]
    call nonblocking
    test rax, rax
    js spawn_error
    movsxd rdi, dword ptr [r12 + PIPES + 8]
    call nonblocking
    test rax, rax
    js spawn_error
    movsxd rdi, dword ptr [r12 + PIPES + 16]
    call nonblocking
    test rax, rax
    js spawn_error
    movsxd rdi, dword ptr [r12 + PIPES + 24]
    call nonblocking
    test rax, rax
    js spawn_error
    movsxd rax, dword ptr [r12 + PIPES + 28]
    mov [r12 + EXWRITE], rax
    mov eax, 57
    syscall
    test rax, rax
    js spawn_error
    jz child_exec
    mov [r12 + PID], rax
    movsxd rcx, dword ptr [r12 + PIPES + 4]
    mov [r12 + INFD], rcx
    movsxd rcx, dword ptr [r12 + PIPES + 8]
    mov [r12 + OUTFD], rcx
    movsxd rcx, dword ptr [r12 + PIPES + 16]
    mov [r12 + ERRFD], rcx
    movsxd rcx, dword ptr [r12 + PIPES + 24]
    mov [r12 + EXFD], rcx
    mov dword ptr [r12 + PIPES + 4], -1
    mov dword ptr [r12 + PIPES + 8], -1
    mov dword ptr [r12 + PIPES + 16], -1
    mov dword ptr [r12 + PIPES + 24], -1
    call close_prepared
    mov qword ptr [r12 + EXWRITE], -1
    mov rdi, [r12 + PID]
    xor esi, esi
    mov eax, 434 /* pidfd_open */
    syscall
    test rax, rax
    js spawn_no_pidfd
    mov rdi, rax
    call normalize_fd
    test rax, rax
    js spawn_no_pidfd
    mov [r12 + PIDFD], rax
spawn_no_pidfd:
    mov rax, [r12 + TOKEN]
    mov [r12 + RESULT], rax
    mov rax, [r12 + PID]
    mov [r12 + AUX], rax
    jmp step_complete
spawn_overflow:
    mov rax, -75
    jmp spawn_error
spawn_invalid:
    mov rax, -22
spawn_error:
    mov rbp, rax
    call close_prepared
    mov qword ptr [r12 + EXWRITE], -1
    mov rax, rbp
    jmp step_errno

child_exec:
    mov edi, 1 /* PR_SET_PDEATHSIG */
    mov esi, 9
    xor edx, edx
    xor r10d, r10d
    xor r8d, r8d
    mov eax, 157
    syscall
    test rax, rax
    jnz child_exit
    mov eax, 110
    syscall
    cmp rax, [r12 + SELF_PID]
    jne child_exit
    movsxd rdi, dword ptr [r12 + PIPES]
    xor esi, esi
    mov eax, 33
    syscall
    test rax, rax
    js child_errno
    movsxd rdi, dword ptr [r12 + PIPES + 12]
    mov esi, 1
    mov eax, 33
    syscall
    test rax, rax
    js child_errno
    movsxd rdi, dword ptr [r12 + PIPES + 20]
    mov esi, 2
    mov eax, 33
    syscall
    test rax, rax
    js child_errno
    xor ebx, ebx
child_close_loop:
    movsxd rdi, dword ptr [r12 + PIPES + rbx*4]
    cmp rdi, [r12 + EXWRITE]
    je child_close_next
    test rdi, rdi
    js child_close_next
    mov eax, 3
    syscall
child_close_next:
    inc ebx
    cmp ebx, 8
    jb child_close_loop
    mov rdi, [r12 + WAKEFD]
    mov eax, 3
    syscall
    mov edi, 13
    lea rsi, [r12 + SIGNAL_ACTION]
    xor edx, edx
    mov r10d, 8
    mov eax, 13
    syscall
    test rax, rax
    js child_errno
    mov rdi, [r12 + PROGRAM]
    lea rsi, [rip + empty_string]
    mov rdx, [r12 + ARGV]
    mov r10, [r12 + ENV]
    mov r8d, 0x1000 /* AT_EMPTY_PATH */
    mov eax, 322
    syscall
child_errno:
    neg rax
    mov [r12 + EXEC_ERROR], rax
child_error_write:
    mov rdi, [r12 + EXWRITE]
    lea rsi, [r12 + EXEC_ERROR]
    mov edx, 8
    mov eax, 1
    syscall
    cmp rax, -4
    je child_error_write
child_exit:
    mov edi, 127
    mov eax, 60
    syscall
    ud2

effect_write:
    call require_child
    test eax, eax
    jz step_contract
    mov rdi, [r12 + INFD]
    test rdi, rdi
    js effect_badfd
    mov rsi, [r12 + SHADOW + 32]
    mov rdx, [r12 + SHADOW + 40]
    test rdx, rdx
    jz step_contract
    cmp rsi, [r12 + WCAP]
    ja step_contract
    mov rax, [r12 + WCAP]
    sub rax, rsi
    cmp rdx, rax
    ja step_contract
    add rsi, r13
    mov eax, 1
    syscall
    test rax, rax
    js step_errno
    mov [r12 + RESULT], rax
    jmp step_complete

effect_read:
    call require_child
    test eax, eax
    jz step_contract
    mov rax, [r12 + SHADOW + 32]
    cmp rax, 1
    je read_stdout
    cmp rax, 2
    jne step_contract
    mov rdi, [r12 + ERRFD]
    jmp read_ready
read_stdout:
    mov rdi, [r12 + OUTFD]
read_ready:
    test rdi, rdi
    js effect_badfd
    mov rsi, [r12 + SHADOW + 40]
    mov rdx, [r12 + SHADOW + 48]
    cmp rsi, 8192
    jne step_contract
    cmp rdx, 8192
    jne step_contract
    add rsi, r13
    xor eax, eax
    syscall
    test rax, rax
    js step_errno
    mov [r12 + RESULT], rax
    test rax, rax
    jnz step_complete
    mov rcx, [r12 + SHADOW + 32]
    dec ecx
    mov eax, 1
    shl eax, cl
    or [r12 + 528], rax /* kernel EOF state, retained until explicit close */
    jmp step_complete

effect_exec:
    call require_child
    test eax, eax
    jz step_contract
    cmp qword ptr [r12 + EXEC_STATE], 1
    je exec_success
    cmp qword ptr [r12 + EXEC_STATE], 2
    je exec_failed
    mov rdi, [r12 + EXFD]
    test rdi, rdi
    js effect_badfd
    mov rcx, [r12 + EXEC_HAVE]
    cmp rcx, 8
    jae step_contract
    lea rsi, [r12 + EXEC_ERROR + rcx]
    mov edx, 8
    sub rdx, rcx
    xor eax, eax
    syscall
    cmp rax, -11
    je step_complete
    cmp rax, -4
    je effect_exec
    test rax, rax
    js step_errno
    jz exec_eof
    add [r12 + EXEC_HAVE], rax
    cmp qword ptr [r12 + EXEC_HAVE], 8
    jb step_complete
    mov rax, [r12 + EXEC_ERROR]
    test rax, rax
    jz exec_protocol
    cmp rax, 4095
    ja exec_protocol
    mov [r12 + EXEC_ERRNO], rax
    mov qword ptr [r12 + EXEC_STATE], 2
    lea rdi, [r12 + EXFD]
    call close_slot
exec_failed:
    mov rax, [r12 + EXEC_ERRNO]
    jmp step_positive_errno
exec_eof:
    cmp qword ptr [r12 + EXEC_HAVE], 0
    jne exec_protocol
    lea rdi, [r12 + EXFD]
    call close_slot
    mov qword ptr [r12 + EXEC_STATE], 1
exec_success:
    mov qword ptr [r12 + RESULT], 1
    jmp step_complete
exec_protocol:
    mov qword ptr [r12 + EXEC_ERRNO], 5
    mov qword ptr [r12 + EXEC_STATE], 2
    lea rdi, [r12 + EXFD]
    call close_slot
    mov eax, 5
    jmp step_positive_errno

effect_wait:
    call require_child
    test eax, eax
    jz step_contract
    cmp qword ptr [r12 + WAIT_UNKNOWN], 0
    jne effect_uncertain
    cmp qword ptr [r12 + REAPED], 0
    jne wait_cached
    mov rdi, [r12 + PID]
    lea rsi, [r12 + WAIT_STATUS]
    mov edx, 1 /* WNOHANG */
    xor r10d, r10d
    mov eax, 61
    syscall
    test rax, rax
    js wait_failed
    jz step_complete
    cmp rax, [r12 + PID]
    jne wait_identity_failed
    mov qword ptr [r12 + REAPED], 1
wait_cached:
    mov qword ptr [r12 + RESULT], 1
    mov eax, dword ptr [r12 + WAIT_STATUS]
    mov [r12 + AUX], rax
    jmp step_complete
wait_identity_failed:
    mov rax, -10
wait_failed:
    mov qword ptr [r12 + WAIT_UNKNOWN], 1
    jmp step_errno
effect_uncertain:
    mov eax, 10
    jmp step_positive_errno

effect_signal:
    call require_child
    test eax, eax
    jz step_contract
    cmp qword ptr [r12 + WAIT_UNKNOWN], 0
    jne effect_uncertain
    cmp qword ptr [r12 + REAPED], 0
    jne signal_retired
    cmp qword ptr [r12 + SIGNAL_SENT], 0
    jne step_contract
    cmp qword ptr [r12 + SHADOW + 32], 9
    jne step_contract
    mov qword ptr [r12 + SIGNAL_SENT], 1
    mov rdi, [r12 + PIDFD]
    test rdi, rdi
    js signal_pid
    mov esi, 9
    xor edx, edx
    xor r10d, r10d
    mov eax, 424
    syscall
    test rax, rax
    js step_errno
    jmp step_complete
signal_pid:
    mov rdi, [r12 + PID]
    mov esi, 9
    mov eax, 62
    syscall
    test rax, rax
    js step_errno
    jmp step_complete
signal_retired:
    mov eax, 3
    jmp step_positive_errno

effect_close_stdin:
    call require_child
    test eax, eax
    jz step_contract
    lea rdi, [r12 + INFD]
    call close_slot
    test rax, rax
    js step_errno
    jmp step_complete
effect_close_pipes:
    call require_child
    test eax, eax
    jz step_contract
    call close_parent_pipes
    jmp step_complete
effect_badfd:
    mov eax, 9
    jmp step_positive_errno

effect_poll:
    call require_child
    test eax, eax
    jz step_contract
    xor ebx, ebx
    lea r15, [r12 + POLLFDS]
    mov rdi, [r12 + INFD]
    mov esi, 4 /* POLLOUT */
    call add_pollfd
    test qword ptr [r12 + 528], 1
    jnz poll_skip_stdout
    mov rdi, [r12 + OUTFD]
    mov esi, 1
    call add_pollfd
poll_skip_stdout:
    test qword ptr [r12 + 528], 2
    jnz poll_skip_stderr
    mov rdi, [r12 + ERRFD]
    mov esi, 1
    call add_pollfd
poll_skip_stderr:
    mov rdi, [r12 + EXFD]
    mov esi, 1
    call add_pollfd
    cmp qword ptr [r12 + REAPED], 0
    jne poll_skip_pidfd
    mov rdi, [r12 + PIDFD]
    mov esi, 1
    call add_pollfd
poll_skip_pidfd:
    mov rdi, [r12 + WAKEFD]
    mov esi, 1
    call add_pollfd
    mov rax, [r12 + SHADOW + 32]
    /* Kernels without pidfd still observe only this unreaped original child.
     * A bounded readiness tick schedules WNOHANG; it never replays an unknown
     * wait or signal and never extends either HIA-owned deadline. */
    cmp qword ptr [r12 + REAPED], 0
    jne poll_budget
    cmp qword ptr [r12 + PIDFD], 0
    jge poll_budget
    cmp rax, 1000000
    jbe poll_budget
    mov eax, 1000000
poll_budget:
    xor edx, edx
    mov ecx, 1000000000
    div rcx
    mov [r12 + POLLTIME], rax
    mov [r12 + POLLTIME + 8], rdx
    lea rdi, [r12 + POLLFDS]
    mov rsi, rbx
    lea rdx, [r12 + POLLTIME]
    xor r10d, r10d
    mov r8d, 8
    mov eax, 271
    syscall
    test rax, rax
    js step_errno
poll_drain_wake:
    mov rdi, [r12 + WAKEFD]
    lea rsi, [r12 + 520]
    mov edx, 8
    xor eax, eax
    syscall
    cmp rax, 8
    je poll_drain_wake
    cmp rax, -4
    je poll_drain_wake
    cmp rax, -11
    je step_complete
    test rax, rax
    js step_errno
    mov eax, 5
    jmp step_positive_errno

step_errno:
    neg rax
step_positive_errno:
    mov [r12 + ERROR], rax
step_complete:
    call complete
    jmp step_done
step_contract:
    mov eax, CONTRACT
step_done:
    LEAVE

/* child_ack only resolves the exact pending HIA admission or release.
 * No syscall is replayed; the caller's selected HIA child owns those decisions.
 */
child_ack:
    ENTER
    mov r12, rdi
    mov rbx, rsi
    mov rbp, rdx
    mov r15, rcx
    call check_context
    test eax, eax
    jz ack_bad
    cmp rbp, 4095
    ja ack_bad
    mov rax, [r12 + DELEGATE]
    cmp rax, 2
    je ack_commit
    cmp rax, 13
    jne ack_bad
    test rbx, rbx
    jnz ack_bad
    test r15, r15
    jnz ack_bad
    test rbp, rbp
    jnz ack_fields
    mov qword ptr [r12 + RELEASED], 1
    jmp ack_fields
ack_commit:
    test r15, r15
    jnz ack_bad
    test rbp, rbp
    jnz ack_commit_error
    cmp rbx, 1
    jne ack_bad
    mov qword ptr [r12 + COMMITTED], 1
    jmp ack_fields
ack_commit_error:
    test rbx, rbx
    jnz ack_bad
ack_fields:
    mov [r12 + RESULT], rbx
    mov [r12 + ERROR], rbp
    mov [r12 + AUX], r15
    call complete
    test eax, eax
    jnz ack_done
    mov qword ptr [r12 + DELEGATE], 0
    jmp ack_done
ack_bad:
    mov eax, CONTRACT
ack_done:
    LEAVE

/* notify(ctx, flags 1 caller cancellation / 2 owner stop): wake-only primitive.
 * The HIA owner preserves priority and the original exact cancellation meaning.
 */
notify:
    ENTER
    mov r12, rdi
    mov rbx, rsi
    call check_context
    test eax, eax
    jz notify_bad
    test rbx, rbx
    jz notify_bad
    cmp rbx, 3
    ja notify_bad
    lock or qword ptr [r12 + CANCEL_BITS], rbx
    mov qword ptr [rsp], 1
notify_write:
    mov rdi, [r12 + WAKEFD]
    mov rsi, rsp
    mov edx, 8
    mov eax, 1
    syscall
    cmp rax, -4
    je notify_write
    cmp rax, -11
    je notify_ok
    cmp rax, 8
    jne notify_done
notify_ok:
    xor eax, eax
    jmp notify_done
notify_bad:
    mov rax, -22
notify_done:
    LEAVE

/* Rebind only a byte-for-byte preserved enlarged owned workspace. */
rebind:
    ENTER
    mov r12, rdi
    mov r14, rsi
    mov r15, rdx
    call check_context
    test eax, eax
    jz rebind_bad
    test r14, r14
    jz rebind_bad
    cmp r15, [r12 + WCAP]
    jb rebind_bad
    mov rax, r14
    add rax, r15
    jc rebind_bad
    mov rdi, r14
    mov rsi, [r12 + W]
    mov rcx, [r12 + WCAP]
    repe cmpsb
    jne rebind_bad
    mov [r12 + W], r14
    mov [r12 + WCAP], r15
    xor eax, eax
    jmp rebind_done
rebind_bad:
    mov rax, -22
rebind_done:
    LEAVE

/* Refuse to destroy uncertain or unreaped custody, or a live entry lease. */
destroy:
    ENTER
    mov r12, rdi
    call check_context
    test eax, eax
    jz destroy_bad
    cmp qword ptr [r12 + DELEGATE], 0
    jne destroy_busy
    cmp qword ptr [r12 + WAIT_UNKNOWN], 0
    jne destroy_busy
    cmp qword ptr [r12 + PID], 0
    je destroy_entry
    cmp qword ptr [r12 + REAPED], 1
    jne destroy_busy
destroy_entry:
    cmp qword ptr [r12 + COMMITTED], 0
    je destroy_ready
    cmp qword ptr [r12 + RELEASED], 1
    jne destroy_busy
destroy_ready:
    call close_parent_pipes
    lea rdi, [r12 + PIDFD]
    call close_slot
    lea rdi, [r12 + WAKEFD]
    call close_slot
    lea rdi, [r12 + PROGRAM]
    call close_slot
    mov rdi, [r12 + ENV]
    mov rsi, [r12 + ENV_SIZE]
    test rdi, rdi
    jz destroy_argv
    mov eax, 11
    syscall
destroy_argv:
    mov rdi, [r12 + ARGV]
    mov rsi, [r12 + ARGV_SIZE]
    test rdi, rdi
    jz destroy_context
    mov eax, 11
    syscall
destroy_context:
    mov qword ptr [r12 + STATE], 0
    mov qword ptr [r12], 0
    mov rdi, r12
    mov esi, 4096
    mov eax, 11
    syscall
    jmp destroy_done
destroy_busy:
    mov rax, -16
    jmp destroy_done
destroy_bad:
    mov rax, -22
destroy_done:
    LEAVE

check_context:
    xor eax, eax
    test r12, r12
    jz check_done
    movabs rcx, 0x3130544348535348
    cmp [r12], rcx
    jne check_done
    cmp qword ptr [r12 + STATE], 1
    jne check_done
    mov rdx, [r12 + W]
    mov rcx, [r12 + TOKEN]
    cmp [rdx + 24], rcx
    jne check_done
    mov rcx, [r12 + GENERATION]
    cmp [rdx + 184], rcx
    jne check_done
    mov eax, 1
check_done:
    ret

require_child:
    xor eax, eax
    mov rcx, [r12 + SHADOW + 24]
    cmp rcx, [r12 + TOKEN]
    jne require_done
    cmp qword ptr [r12 + PID], 2
    jb require_done
    mov eax, 1
require_done:
    ret

complete:
    mov rdx, [r12 + W]
    xor ecx, ecx
complete_shadow:
    mov rax, [r12 + SHADOW + rcx]
    cmp rax, [rdx + 256 + rcx]
    jne complete_bad
    add ecx, 8
    cmp ecx, 64
    jb complete_shadow
    mov rax, [r12 + RESULT]
    mov [rdx + 328], rax
    mov rax, [r12 + ERROR]
    mov [rdx + 336], rax
    mov rax, [r12 + AUX]
    mov [rdx + 344], rax
    mov rax, [r12 + SEQ]
    mov [rdx + 320], rax
    xor eax, eax
    ret
complete_bad:
    mov eax, CONTRACT
    ret

add_pollfd:
    test rdi, rdi
    js add_poll_done
    mov [r15 + rbx*8], edi
    mov [r15 + rbx*8 + 4], si
    mov word ptr [r15 + rbx*8 + 6], 0
    inc ebx
add_poll_done:
    ret

close_parent_pipes:
    push rbx
    mov ebx, INFD
close_parent_loop:
    lea rdi, [r12 + rbx]
    call close_slot
    add ebx, 8
    cmp ebx, EXWRITE
    jbe close_parent_loop
    pop rbx
    ret

close_prepared:
    push rbx
    xor ebx, ebx
close_prepared_loop:
    movsxd rdi, dword ptr [r12 + PIPES + rbx*4]
    mov dword ptr [r12 + PIPES + rbx*4], -1
    test rdi, rdi
    js close_prepared_next
    mov eax, 3
    syscall
close_prepared_next:
    inc ebx
    cmp ebx, 8
    jb close_prepared_loop
    pop rbx
    ret

/* Retire before close, never retry a close result whose descriptor may be reused. */
close_slot:
    mov rax, [rdi]
    mov qword ptr [rdi], -1
    test rax, rax
    js close_slot_empty
    mov rdi, rax
    mov eax, 3
    syscall
    ret
close_slot_empty:
    xor eax, eax
    ret

normalize_fd:
    cmp rdi, 3
    jae normalize_original
    push rbx
    mov rbx, rdi
    mov esi, 1030
    mov edx, 3
    mov eax, 72
    syscall
    push rax
    mov rdi, rbx
    mov eax, 3
    syscall
    pop rax
    pop rbx
    ret
normalize_original:
    mov rax, rdi
    ret

nonblocking:
    push rbx
    mov rbx, rdi
    mov esi, 3 /* F_GETFL */
    mov eax, 72
    syscall
    test rax, rax
    js nonblocking_done
    or eax, 0x800
    mov edx, eax
    mov rdi, rbx
    mov esi, 4 /* F_SETFL */
    mov eax, 72
    syscall
nonblocking_done:
    pop rbx
    ret

allocate:
    xor edi, edi
    mov edx, 3
    mov r10d, 34
    mov r8, -1
    xor r9d, r9d
    mov eax, 9
    syscall
    ret

empty_string:
    .byte 0
.section .note.GNU-stack,"",@progbits
