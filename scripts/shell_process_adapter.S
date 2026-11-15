/* Fixed Linux x86-64 boundary for shell_process.hepta.
 *
 * Command/env/PATH selection, spawn sequencing, deadlines, promotion, tracker
 * decisions, cancellation and ordinary cleanup are HIA decisions. This explicit
 * fixture owns capture descriptors and child tokens; frames never supply FDs or
 * PIDs. effects.bin is fixture-only audit IO and is not command stderr.
 */
.intel_syntax noprefix
.section .text
.global _start

.equ EFFECT, 256
.equ PLAN, 512
.equ PENDING, 0xfffffff0
.equ INVALID, 0xffffffff
.equ CAPACITY, 0xfffffffe
.equ CONTRACT, 0xfffffff9
.equ ROLE, 0
.equ ENVIRON, 8
.equ ADMITTED, 16
.equ NULLFD, 24
.equ EXREAD, 32
.equ EXWRITE, 40
.equ CHILD_PID, 48
.equ CHILD_TOKEN, 56
.equ SEQUENCE, 64
.equ FORKED, 72
.equ OWNED, 80
.equ TRACKED, 88
.equ CHILD_STAGE, 96
.equ UNUSED_CLOSED, 104
.equ HANDSHAKE, 112
.equ INPUT_LEN, 120
.equ INPUT_CAP, 128
.equ WORK_CAP, 136
.equ ENV_ARRAY, 144
.equ ENV_ARRAY_BYTES, 152
.equ PIDFD, 160
.equ CONTROL_HAVE, 168
.equ CONTROL_NEED, 176
.equ EOF_SEEN, 184
.equ SETUP_CLOSED, 192
.equ DIRECTORY, 200
.equ OUTLOG, 208
.equ ERRLOG, 216
.equ TRACEFD, 224
.equ AUDIT, 232
.equ ENV_DONE, 240
.equ NULL_DONE, 248
.equ CHANNEL_DONE, 256
.equ ACTION, 264
.equ RESULT, 272
.equ ERROR, 280
.equ AUX, 288
.equ QUEUE, 296
.equ QUEUE_CAP, 304
.equ QUEUE_LEN, 312
.equ QUEUE_POS, 320
.equ IO_ERROR, 328
.equ ABORTING, 336
.equ FINISHED, 344
.equ SELF_PID, 352
.equ EXIT_CODE, 360
.equ WAIT_CACHED, 368
.equ ENV_NEEDED, 376
.equ WAIT_STATUS, 384
.equ RAW_AUX, 392
.equ TIMESPEC, 400
.equ CLOCKBUF, 416
.equ SIGACTION, 448
.equ POLLFDS, 480
.equ PACKET, 512
.equ REPLY, 528
.equ FDPAIR, 544
.equ ARGV, 576
.equ TRACE_RECORD, 640
.equ EXEC_PATH, 784
.equ COMMAND_PTR, 792
.equ SCRIPT_PTR, 800
.equ ENV_COUNT, 808
.equ ENV_TABLE, 816
.equ CONTROL_BUFFER, 1024

_start:
    cld
    mov rbp, rsp
    cmp qword ptr [rbp], 3
    jne usage
    mov rdi, [rbp + 16]
    lea rsi, [rip + fixture_option]
    call equal_string
    test eax, eax
    jz usage
    mov esi, 8192
    call allocate
    cmp rax, -4095
    jae allocation_failure
    mov r12, rax
    mov [r12 + 2048], rbp
    mov rax, [rbp]
    lea rax, [rbp + rax*8 + 16]
    mov [r12 + ENVIRON], rax
    mov qword ptr [r12 + NULLFD], -1
    mov qword ptr [r12 + EXREAD], -1
    mov qword ptr [r12 + EXWRITE], -1
    mov qword ptr [r12 + PIDFD], -2
    mov qword ptr [r12 + DIRECTORY], -1
    mov qword ptr [r12 + OUTLOG], -1
    mov qword ptr [r12 + ERRLOG], -1
    mov qword ptr [r12 + TRACEFD], -1
    mov qword ptr [r12 + CONTROL_NEED], 8
    mov qword ptr [r12 + CHILD_TOKEN], 1
    mov eax, 39
    syscall
    mov [r12 + SELF_PID], rax

    /* Rust's ordinary parent runtime ignores SIGPIPE. The HIA child explicitly
     * requests SIG_DFL before pre_exec(setsid); no mask or SIGCHLD reset occurs. */
    mov qword ptr [r12 + SIGACTION], 1
    mov edi, 13
    lea rsi, [r12 + SIGACTION]
    xor edx, edx
    mov r10d, 8
    mov eax, 13
    syscall
    test rax, rax
    js startup_io_failure
    mov qword ptr [r12 + SIGACTION], 0

    mov esi, 4096
    mov r10d, 33
    call allocate_flags
    cmp rax, -4095
    jae startup_allocation_failure
    mov [r12 + AUDIT], rax
    mov esi, 65536
    call allocate
    cmp rax, -4095
    jae startup_allocation_failure
    mov r13, rax
    mov qword ptr [r12 + INPUT_CAP], 65536
    mov esi, 33554432
    call allocate
    cmp rax, -4095
    jae startup_allocation_failure
    mov r14, rax
    mov qword ptr [r12 + WORK_CAP], 33554432
    mov esi, 4096
    call allocate
    cmp rax, -4095
    jae startup_allocation_failure
    mov r15, rax
    mov esi, 8192
    call allocate
    cmp rax, -4095
    jae startup_allocation_failure
    mov [r12 + QUEUE], rax
    mov qword ptr [r12 + QUEUE_CAP], 8192

    mov rdi, -100
    mov rsi, [rbp + 24]
    mov edx, 0xb0000 /* RDONLY|DIRECTORY|NOFOLLOW|CLOEXEC */
    xor r10d, r10d
    mov eax, 257
    syscall
    call normalize_fd
    test rax, rax
    js startup_io_failure
    mov [r12 + DIRECTORY], rax
    lea rsi, [rip + stdout_name]
    mov edx, 0xa00c1 /* WRONLY|CREAT|EXCL|NOFOLLOW|CLOEXEC */
    call create_capture
    test rax, rax
    js startup_io_failure
    mov [r12 + OUTLOG], rax
    lea rsi, [rip + stderr_name]
    mov edx, 0xa00c1
    call create_capture
    test rax, rax
    js startup_io_failure
    mov [r12 + ERRLOG], rax
    lea rsi, [rip + effects_name]
    mov edx, 0xa04c1 /* audit records append atomically across the fork */
    call create_capture
    test rax, rax
    js startup_io_failure
    mov [r12 + TRACEFD], rax

    xor edi, edi
    lea rsi, [r12 + INPUT_LEN]
    mov edx, 8
    call read_exact
    test eax, eax
    jz finish
    cmp eax, 1
    jne startup_io_failure
    mov rbx, [r12 + INPUT_LEN]
    test rbx, rbx
    js input_capacity
    cmp rbx, [r12 + INPUT_CAP]
    jbe input_mapping_ready
    mov rdx, rbx
    add rdx, 4095
    jc input_capacity
    and rdx, -4096
    mov rbp, rdx
    mov rdi, r13
    mov rsi, [r12 + INPUT_CAP]
    mov r10d, 1
    xor r8d, r8d
    mov eax, 25
    syscall
    cmp rax, -4095
    jae input_capacity
    mov r13, rax
    mov [r12 + INPUT_CAP], rbp
input_mapping_ready:
    mov rdx, rbx
    shl rdx, 1
    jc input_capacity
    add rdx, 33554432
    jc input_capacity
    add rdx, 4095
    jc input_capacity
    and rdx, -4096
    test rdx, rdx
    js input_capacity
    cmp rdx, [r12 + WORK_CAP]
    jbe work_mapping_ready
    mov rbp, rdx
    mov rdi, r14
    mov rsi, [r12 + WORK_CAP]
    mov r10d, 1
    xor r8d, r8d
    mov eax, 25
    syscall
    cmp rax, -4095
    jae input_capacity
    mov r14, rax
    mov [r12 + WORK_CAP], rbp
work_mapping_ready:
    test rbx, rbx
    jz frame_received
    xor edi, edi
    mov rsi, r13
    mov rdx, rbx
    call read_exact
    cmp eax, 1
    jne startup_io_failure
frame_received:
    xor edi, edi
    call nonblocking
    test rax, rax
    js startup_io_failure
    mov edi, 1
    call nonblocking
    test rax, rax
    js startup_io_failure

owner_next:
    cmp qword ptr [r12 + ROLE], 2
    je owner_invoke
    call flush_output
    cmp qword ptr [r12 + FINISHED], 0
    jne drain_output
    cmp qword ptr [r12 + ADMITTED], 0
    je owner_invoke
    call pump_input
owner_invoke:
    mov rdi, r13
    mov rsi, [r12 + INPUT_LEN]
    mov rdx, r15
    mov ecx, 128
    mov r8, r14
    mov r9, [r12 + WORK_CAP]
    call .Lowner_image
    mov rdx, rax
    shr rdx, 32
    jnz boundary_contract
    cmp eax, PENDING
    je effect_pending
    cmp qword ptr [r12 + ROLE], 2
    je child_contract
    cmp eax, 96
    je publish_event
    test eax, eax
    jz retire_owner
    cmp eax, INVALID
    je owner_refusal
    cmp eax, CAPACITY
    je owner_refusal
    cmp eax, CONTRACT
    je owner_refusal
    jmp boundary_contract
effect_pending:
    call effect_dispatch
    jmp owner_next
publish_event:
    mov edx, 96
    call enqueue_reply
    mov edi, 2
    call control_request
    jmp owner_next
retire_owner:
    xor edx, edx
    call enqueue_reply
    mov qword ptr [r12 + FINISHED], 1
    jmp owner_next
owner_refusal:
    mov ebx, eax
    xor edx, edx
    call enqueue_reply
    mov qword ptr [r12 + EXIT_CODE], 2
    cmp ebx, CAPACITY
    jne refusal_not_capacity
    mov qword ptr [r12 + EXIT_CODE], 75
refusal_not_capacity:
    cmp ebx, CONTRACT
    jne refusal_status_ready
    mov qword ptr [r12 + EXIT_CODE], 78
refusal_status_ready:
    cmp qword ptr [r12 + OWNED], 0
    je refusal_finished
    cmp qword ptr [r12 + ABORTING], 0
    jne emergency_containment
    mov qword ptr [r12 + ABORTING], 1
    mov edi, 4
    call control_request
    jmp owner_next
refusal_finished:
    mov qword ptr [r12 + FINISHED], 1
    jmp owner_next
input_capacity:
    mov eax, CAPACITY
    xor edx, edx
    call enqueue_reply
    mov qword ptr [r12 + EXIT_CODE], 75
    mov qword ptr [r12 + FINISHED], 1
    jmp owner_next

/* The controller validates its own issued sequence and capabilities. It does not
 * trust a mutable HIA phase word as authorization to access a kernel object. */
effect_dispatch:
    mov rax, 0x3158465250485348 /* HSHPRFX1 */
    cmp [r14 + EFFECT], rax
    jne boundary_contract
    mov rax, [r12 + SEQUENCE]
    inc rax
    jz boundary_contract
    cmp [r14 + EFFECT + 8], rax
    jne boundary_contract
    mov [r12 + SEQUENCE], rax
    mov rax, [r14 + EFFECT + 48]
    or rax, [r14 + EFFECT + 56]
    or rax, [r14 + EFFECT + 64]
    or rax, [r14 + EFFECT + 72]
    or rax, [r14 + EFFECT + 80]
    or rax, [r14 + EFFECT + 88]
    jnz boundary_contract
    mov rax, [r14 + EFFECT + 16]
    mov [r12 + ACTION], rax
    cmp rax, 1
    jb boundary_contract
    cmp rax, 19
    ja boundary_contract
    mov qword ptr [r12 + RESULT], 0
    mov qword ptr [r12 + ERROR], 0
    mov qword ptr [r12 + AUX], 0
    mov qword ptr [r12 + RAW_AUX], 0
    xor edi, edi
    call trace_effect
    mov rax, [r12 + ACTION]
    cmp rax, 1
    je effect_capture
    cmp qword ptr [r12 + ADMITTED], 1
    jne boundary_contract
    cmp rax, 2
    je effect_environment
    cmp rax, 3
    je effect_null
    cmp rax, 4
    je effect_channel
    cmp rax, 5
    je effect_fork
    cmp rax, 6
    je effect_close_unused
    cmp rax, 7
    je effect_dup_stdio
    cmp rax, 8
    je effect_chdir
    cmp rax, 9
    je effect_sigpipe
    cmp rax, 10
    je effect_setsid
    cmp rax, 11
    je effect_exec
    cmp rax, 12
    je effect_exec_failure
    cmp rax, 13
    je effect_handshake
    cmp rax, 14
    je effect_track
    cmp rax, 15
    je effect_clock
    cmp rax, 16
    je effect_wait
    cmp rax, 17
    je effect_wakeup
    cmp rax, 18
    je effect_signal
    cmp rax, 19
    je effect_close_setup
    jmp boundary_contract

effect_capture:
    call role_before_fork
    cmp qword ptr [r12 + ADMITTED], 0
    jne boundary_contract
    cmp qword ptr [r14 + EFFECT + 24], 1
    jne boundary_contract
    call zero_arg12
    cmp qword ptr [r12 + OUTLOG], 2
    jbe boundary_contract
    cmp qword ptr [r12 + ERRLOG], 2
    jbe boundary_contract
    mov qword ptr [r12 + ADMITTED], 1
    jmp acknowledge

effect_environment:
    call role_before_fork
    cmp qword ptr [r12 + ENV_DONE], 0
    jne boundary_contract
    cmp qword ptr [r14 + EFFECT + 40], 0
    jne boundary_contract
    mov rdi, [r14 + EFFECT + 24]
    mov rsi, [r14 + EFFECT + 32]
    call check_span
    mov rbx, [r12 + ENVIRON]
    xor r8d, r8d
    mov r9d, 8
environment_measure:
    mov rsi, [rbx]
    test rsi, rsi
    jz environment_measured
    xor edx, edx
environment_length:
    cmp byte ptr [rsi + rdx], 0
    je environment_record_length
    inc rdx
    jmp environment_length
environment_record_length:
    add rdx, 9
    jc boundary_contract
    add r9, rdx
    jc boundary_contract
    inc r8
    add rbx, 8
    jmp environment_measure
environment_measured:
    mov [r12 + ENV_NEEDED], r9
    cmp r9, [r14 + EFFECT + 32]
    ja environment_capacity
    mov rdi, [r14 + EFFECT + 24]
    add rdi, r14
    mov [rdi], r8
    add rdi, 8
    mov rbx, [r12 + ENVIRON]
environment_copy:
    mov rsi, [rbx]
    test rsi, rsi
    jz environment_copied
    xor ecx, ecx
environment_copy_length:
    cmp byte ptr [rsi + rcx], 0
    je environment_copy_record
    inc rcx
    jmp environment_copy_length
environment_copy_record:
    mov [rdi], rcx
    add rdi, 8
    inc rcx
    rep movsb
    add rbx, 8
    jmp environment_copy
environment_copied:
    mov qword ptr [r12 + ENV_DONE], 1
    mov rax, [r12 + ENV_NEEDED]
    mov [r12 + RESULT], rax
    jmp acknowledge
environment_capacity:
    mov qword ptr [r12 + ERROR], 105
    mov rax, [r12 + ENV_NEEDED]
    mov [r12 + AUX], rax
    jmp acknowledge

effect_null:
    call role_before_fork
    call zero_args
    cmp qword ptr [r12 + ENV_DONE], 1
    jne boundary_contract
    cmp qword ptr [r12 + NULL_DONE], 0
    jne boundary_contract
    mov rdi, -100
    lea rsi, [rip + devnull]
    mov edx, 0x80000
    xor r10d, r10d
    mov eax, 257
    syscall
    mov [r12 + RAW_AUX], rax
    call normalize_fd
    test rax, rax
    js acknowledge_error
    mov [r12 + NULLFD], rax
    mov qword ptr [r12 + NULL_DONE], 1
    jmp acknowledge

effect_channel:
    call role_before_fork
    call zero_args
    cmp qword ptr [r12 + NULL_DONE], 1
    jne boundary_contract
    cmp qword ptr [r12 + CHANNEL_DONE], 0
    jne boundary_contract
    mov edi, 1
    mov esi, 0x80005 /* AF_UNIX, SOCK_SEQPACKET|SOCK_CLOEXEC */
    xor edx, edx
    lea r10, [r12 + FDPAIR]
    mov eax, 53
    syscall
    mov [r12 + RAW_AUX], rax
    test rax, rax
    js acknowledge_error
    movsxd rax, dword ptr [r12 + FDPAIR]
    call normalize_fd
    test rax, rax
    js channel_first_failed
    mov [r12 + EXREAD], rax
    movsxd rax, dword ptr [r12 + FDPAIR + 4]
    call normalize_fd
    test rax, rax
    js acknowledge_error
    mov [r12 + EXWRITE], rax
    mov qword ptr [r12 + CHANNEL_DONE], 1
    jmp acknowledge
channel_first_failed:
    mov rbx, rax
    mov edi, [r12 + FDPAIR + 4]
    mov eax, 3
    syscall
    mov rax, rbx
    jmp acknowledge_error

effect_fork:
    call role_before_fork
    call zero_args
    cmp qword ptr [r12 + CHANNEL_DONE], 1
    jne boundary_contract
    cmp qword ptr [r12 + FORKED], 0
    jne boundary_contract
    mov qword ptr [r12 + FORKED], 1
    mov eax, 57
    syscall
    mov [r12 + RAW_AUX], rax
    test rax, rax
    js acknowledge_error
    jz fork_child
    mov qword ptr [r12 + ROLE], 1
    mov qword ptr [r12 + OWNED], 1
    mov [r12 + CHILD_PID], rax
    mov [r12 + RESULT], rax
    mov rax, [r12 + CHILD_TOKEN]
    mov [r12 + AUX], rax
    jmp acknowledge
fork_child:
    mov qword ptr [r12 + ROLE], 2
    mov eax, 39
    syscall
    mov [r12 + SELF_PID], rax
    mov [r12 + CHILD_PID], rax
    mov rax, [r12 + CHILD_TOKEN]
    mov [r12 + AUX], rax
    jmp acknowledge

effect_close_unused:
    call zero_arg12
    cmp qword ptr [r12 + UNUSED_CLOSED], 0
    jne boundary_contract
    mov rax, [r14 + EFFECT + 24]
    cmp rax, [r12 + ROLE]
    jne boundary_contract
    cmp rax, 1
    je close_child_endpoint
    cmp rax, 2
    jne boundary_contract
    lea rdi, [r12 + EXREAD]
    jmp close_unused_endpoint
close_child_endpoint:
    lea rdi, [r12 + EXWRITE]
close_unused_endpoint:
    call close_slot
    mov qword ptr [r12 + UNUSED_CLOSED], 1
    jmp acknowledge

effect_dup_stdio:
    call role_child
    call zero_arg12
    cmp qword ptr [r12 + UNUSED_CLOSED], 1
    jne boundary_contract
    mov rsi, [r14 + EFFECT + 24]
    cmp rsi, 2
    ja boundary_contract
    cmp rsi, [r12 + CHILD_STAGE]
    jne boundary_contract
    mov rdi, [r12 + NULLFD]
    test rsi, rsi
    jz dup_descriptor_ready
    mov rdi, [r12 + OUTLOG]
    cmp rsi, 1
    je dup_descriptor_ready
    mov rdi, [r12 + ERRLOG]
dup_descriptor_ready:
    cmp rdi, 2
    jbe boundary_contract
    mov eax, 33
    syscall
    mov [r12 + RAW_AUX], rax
    test rax, rax
    js acknowledge_error
    inc qword ptr [r12 + CHILD_STAGE]
    jmp acknowledge

effect_chdir:
    call role_child
    cmp qword ptr [r12 + CHILD_STAGE], 3
    jne boundary_contract
    cmp qword ptr [r14 + EFFECT + 40], 0
    jne boundary_contract
    mov rdi, [r14 + EFFECT + 24]
    mov rsi, [r14 + EFFECT + 32]
    call check_cstr
    mov eax, 80
    syscall
    mov [r12 + RAW_AUX], rax
    test rax, rax
    js acknowledge_error
    mov qword ptr [r12 + CHILD_STAGE], 4
    jmp acknowledge

effect_sigpipe:
    call role_child
    call zero_args
    cmp qword ptr [r12 + CHILD_STAGE], 4
    jne boundary_contract
    mov edi, 13
    lea rsi, [r12 + SIGACTION]
    xor edx, edx
    mov r10d, 8
    mov eax, 13
    syscall
    mov [r12 + RAW_AUX], rax
    test rax, rax
    js acknowledge_error
    mov qword ptr [r12 + CHILD_STAGE], 5
    jmp acknowledge

effect_setsid:
    call role_child
    call zero_args
    cmp qword ptr [r12 + CHILD_STAGE], 5
    jne boundary_contract
    mov eax, 112
    syscall
    mov [r12 + RAW_AUX], rax
    test rax, rax
    js acknowledge_error
    mov [r12 + RESULT], rax
    mov qword ptr [r12 + CHILD_STAGE], 6
    jmp acknowledge

effect_exec:
    call role_child
    cmp qword ptr [r12 + CHILD_STAGE], 6
    jne boundary_contract
    cmp qword ptr [r14 + EFFECT + 40], PLAN
    jne boundary_contract
    cmp qword ptr [r14 + PLAN + 56], 0
    jne boundary_contract
    cmp qword ptr [r14 + PLAN], 1
    ja boundary_contract
    mov rdi, [r14 + EFFECT + 24]
    mov rsi, [r14 + EFFECT + 32]
    call check_cstr
    mov [r12 + EXEC_PATH], rdi
    mov rdi, [r14 + PLAN + 24]
    mov rsi, [r14 + PLAN + 32]
    call check_cstr
    mov [r12 + COMMAND_PTR], rdi
    cmp qword ptr [r14 + PLAN], 0
    je exec_script_valid
    mov rdi, [r14 + PLAN + 40]
    mov rsi, [r14 + PLAN + 48]
    call check_cstr
    mov [r12 + SCRIPT_PTR], rdi
exec_script_valid:
    mov rax, [r14 + PLAN + 16]
    mov [r12 + ENV_COUNT], rax
    mov rsi, rax
    shl rsi, 5
    shr rsi, 5
    cmp rsi, rax
    jne boundary_contract
    shl rsi, 5
    mov rdi, [r14 + PLAN + 8]
    call check_span
    mov [r12 + ENV_TABLE], rdi
    mov rsi, [r12 + ENV_COUNT]
    inc rsi
    jz boundary_contract
    shl rsi, 3
    cmp rsi, [r12 + ENV_ARRAY_BYTES]
    jbe exec_array_ready
    mov rbp, rsi
    cmp qword ptr [r12 + ENV_ARRAY_BYTES], 0
    jne exec_resize_array
    call allocate
    jmp exec_array_allocated
exec_resize_array:
    mov rdi, [r12 + ENV_ARRAY]
    mov rdx, rsi
    mov rsi, [r12 + ENV_ARRAY_BYTES]
    mov r10d, 1
    xor r8d, r8d
    mov eax, 25
    syscall
exec_array_allocated:
    cmp rax, -4095
    jae acknowledge_error
    mov [r12 + ENV_ARRAY], rax
    mov [r12 + ENV_ARRAY_BYTES], rbp
exec_array_ready:
    mov rbx, [r12 + ENV_TABLE]
    mov rbp, [r12 + ENV_ARRAY]
    mov r10, [r12 + ENV_COUNT]
exec_environment_entry:
    test r10, r10
    jz exec_environment_ready
    mov rdi, [rbx]
    mov rsi, [rbx + 8]
    call check_cstr
    mov [rbp], rdi
    add rbp, 8
    add rbx, 32
    dec r10
    jmp exec_environment_entry
exec_environment_ready:
    mov qword ptr [rbp], 0
    lea rax, [rip + sh_name]
    mov [r12 + ARGV], rax
    lea rax, [rip + dash_c]
    mov [r12 + ARGV + 8], rax
    mov rax, [r12 + COMMAND_PTR]
    mov [r12 + ARGV + 16], rax
    mov qword ptr [r12 + ARGV + 24], 0
    cmp qword ptr [r14 + PLAN], 0
    je exec_arguments_ready
    lea rax, [rip + bin_sh]
    mov [r12 + ARGV], rax
    mov rax, [r12 + SCRIPT_PTR]
    mov [r12 + ARGV + 8], rax
    lea rax, [rip + dash_c]
    mov [r12 + ARGV + 16], rax
    mov rax, [r12 + COMMAND_PTR]
    mov [r12 + ARGV + 24], rax
    mov qword ptr [r12 + ARGV + 32], 0
exec_arguments_ready:
    mov rdi, [r12 + EXEC_PATH]
    lea rsi, [r12 + ARGV]
    mov rdx, [r12 + ENV_ARRAY]
    mov eax, 59
    syscall
    mov [r12 + RAW_AUX], rax
    jmp acknowledge_error

effect_exec_failure:
    call role_child
    call zero_arg12
    mov rax, [r14 + EFFECT + 24]
    /* A NOEX payload of zero remains distinct from a successful channel EOF. */
    cmp rax, 4095
    ja boundary_contract
    bswap eax
    mov [r12 + PACKET], eax
    mov dword ptr [r12 + PACKET + 4], 0x58454f4e
exec_failure_write:
    mov rdi, [r12 + EXWRITE]
    cmp rdi, 2
    jbe boundary_contract
    lea rsi, [r12 + PACKET]
    mov edx, 8
    mov eax, 1
    syscall
    cmp rax, -4
    je exec_failure_write
    mov [r12 + RAW_AUX], rax
    cmp rax, 8
    jne child_contract
    mov edi, 1
    mov eax, 60
    syscall
    ud2

effect_handshake:
    call role_parent
    call zero_args
    cmp qword ptr [r12 + UNUSED_CLOSED], 1
    jne boundary_contract
    cmp qword ptr [r12 + HANDSHAKE], 0
    jne boundary_contract
handshake_read:
    mov rdi, [r12 + EXREAD]
    cmp rdi, 2
    jbe boundary_contract
    lea rsi, [r12 + PACKET]
    mov edx, 8
    xor eax, eax
    syscall
    mov [r12 + RAW_AUX], rax
    cmp rax, -4
    je handshake_read
    test rax, rax
    jz handshake_success
    cmp rax, 8
    jne handshake_contract
    cmp dword ptr [r12 + PACKET + 4], 0x58454f4e
    jne handshake_contract
    mov eax, [r12 + PACKET]
    bswap eax
    mov [r12 + ERROR], rax
    mov qword ptr [r12 + RESULT], 1
    mov qword ptr [r12 + HANDSHAKE], 2
    jmp acknowledge
handshake_success:
    mov qword ptr [r12 + HANDSHAKE], 1
    jmp acknowledge
handshake_contract:
    /* Rust reaps, then panics on a broken or short CLOEXEC channel. */
handshake_contract_reap:
    mov rdi, [r12 + CHILD_PID]
    lea rsi, [r12 + WAIT_STATUS]
    xor edx, edx
    xor r10d, r10d
    mov eax, 61
    syscall
    cmp rax, -4
    je handshake_contract_reap
    cmp rax, [r12 + CHILD_PID]
    je handshake_retire
    cmp rax, -10
    jne boundary_contract
handshake_retire:
    mov qword ptr [r12 + OWNED], 0
    jmp boundary_contract

effect_track:
    call role_parent
    call owned_token
    cmp qword ptr [r14 + EFFECT + 40], 0
    jne boundary_contract
    cmp qword ptr [r12 + HANDSHAKE], 1
    jne boundary_contract
    mov rax, [r14 + EFFECT + 32]
    cmp rax, 1
    ja boundary_contract
    test rax, rax
    jz track_record
    cmp qword ptr [r12 + OWNED], 1
    jne boundary_contract
track_record:
    mov [r12 + TRACKED], rax
    jmp acknowledge

effect_clock:
    call role_parent
    call zero_args
    mov edi, 1
    lea rsi, [r12 + CLOCKBUF]
    mov eax, 228
    syscall
    mov [r12 + RAW_AUX], rax
    test rax, rax
    js acknowledge_error
    mov rax, [r12 + CLOCKBUF]
    mov ecx, 1000000000
    mul rcx
    test rdx, rdx
    jnz boundary_contract
    add rax, [r12 + CLOCKBUF + 8]
    jc boundary_contract
    mov [r12 + RESULT], rax
    jmp acknowledge

effect_wait:
    call role_parent
    call owned_token
    cmp qword ptr [r14 + EFFECT + 40], 0
    jne boundary_contract
    mov rax, [r14 + EFFECT + 32]
    cmp rax, 1
    ja boundary_contract
    cmp qword ptr [r12 + WAIT_CACHED], 1
    je wait_cached
    cmp qword ptr [r12 + OWNED], 1
    jne wait_lost
    mov edx, 1
    sub edx, eax
    mov rdi, [r12 + CHILD_PID]
    lea rsi, [r12 + WAIT_STATUS]
    xor r10d, r10d
    mov eax, 61
    syscall
    mov [r12 + RAW_AUX], rax
    test rax, rax
    jz acknowledge
    js wait_error
    cmp rax, [r12 + CHILD_PID]
    jne boundary_contract
    mov qword ptr [r12 + WAIT_CACHED], 1
    mov qword ptr [r12 + OWNED], 0
    lea rdi, [r12 + PIDFD]
    call close_slot
wait_cached:
    mov qword ptr [r12 + RESULT], 1
    mov eax, [r12 + WAIT_STATUS]
    mov [r12 + AUX], rax
    jmp acknowledge
wait_error:
    cmp rax, -10
    jne acknowledge_error
    mov qword ptr [r12 + OWNED], 0
    mov qword ptr [r12 + WAIT_CACHED], 2
    lea rdi, [r12 + PIDFD]
    call close_slot
wait_lost:
    mov rax, -10
    jmp acknowledge_error

effect_signal:
    call role_parent
    call owned_token
    cmp qword ptr [r14 + EFFECT + 40], 9
    jne boundary_contract
    mov rax, [r14 + EFFECT + 32]
    cmp rax, 1
    je signal_kind_ok
    cmp rax, 2
    jne boundary_contract
signal_kind_ok:
    cmp qword ptr [r12 + OWNED], 1
    jne signal_retired
    mov rdi, [r12 + CHILD_PID]
    cmp rax, 1
    je signal_target_ready
    neg rdi
signal_target_ready:
    mov esi, 9
    mov eax, 62
    syscall
    jmp acknowledge_syscall
signal_retired:
    mov rax, -3
    jmp acknowledge_syscall

effect_wakeup:
    call role_parent
    call owned_token
    cmp qword ptr [r14 + EFFECT + 40], 0
    jne boundary_contract
    cmp qword ptr [r12 + OWNED], 1
    jne acknowledge
    cmp qword ptr [r12 + PIDFD], -2
    jne wake_pidfd_ready
    mov rdi, [r12 + CHILD_PID]
    mov esi, 2048
    mov eax, 434
    syscall
    test rax, rax
    js wake_without_pidfd
    call normalize_fd
    test rax, rax
    js wake_without_pidfd
    mov [r12 + PIDFD], rax
    jmp wake_pidfd_ready
wake_without_pidfd:
    mov qword ptr [r12 + PIDFD], -1
wake_pidfd_ready:
    call make_pollfds
    mov rax, [r14 + EFFECT + 32]
    cmp qword ptr [r12 + PIDFD], 0
    jge wake_duration_ready
    cmp rax, 10000000
    jbe wake_duration_ready
    mov eax, 10000000
wake_duration_ready:
    xor ebp, ebp
    cmp rax, -1
    je wake_poll
    xor edx, edx
    mov ecx, 1000000000
    div rcx
    mov [r12 + TIMESPEC], rax
    mov [r12 + TIMESPEC + 8], rdx
    lea rbp, [r12 + TIMESPEC]
wake_poll:
    lea rdi, [r12 + POLLFDS]
    mov esi, 3
    mov rdx, rbp
    xor r10d, r10d
    mov r8d, 8
    mov eax, 271
    syscall
    mov [r12 + RAW_AUX], rax
    cmp rax, -4
    je wake_received
    test rax, rax
    js acknowledge_error
wake_received:
    call flush_output
    call pump_input
    jmp acknowledge

effect_close_setup:
    cmp qword ptr [r12 + ROLE], 2
    je boundary_contract
    call zero_args
    lea rdi, [r12 + NULLFD]
    call close_slot
    lea rdi, [r12 + EXREAD]
    call close_slot
    lea rdi, [r12 + EXWRITE]
    call close_slot
    mov qword ptr [r12 + SETUP_CLOSED], 1
    jmp acknowledge

acknowledge_syscall:
    mov [r12 + RAW_AUX], rax
    test rax, rax
    js acknowledge_error
    mov [r12 + RESULT], rax
    jmp acknowledge
acknowledge_error:
    cmp rax, -4095
    jb boundary_contract
    neg rax
    mov [r12 + ERROR], rax
acknowledge:
    mov rax, [r12 + RESULT]
    mov [r14 + EFFECT + 56], rax
    mov rax, [r12 + ERROR]
    mov [r14 + EFFECT + 64], rax
    mov rax, [r12 + AUX]
    mov [r14 + EFFECT + 72], rax
    mov qword ptr [r14 + EFFECT + 80], 1
    mov edi, 1
    call trace_effect
    ret

role_before_fork:
    cmp qword ptr [r12 + ROLE], 0
    jne boundary_contract
    ret
role_parent:
    cmp qword ptr [r12 + ROLE], 1
    jne boundary_contract
    ret
role_child:
    cmp qword ptr [r12 + ROLE], 2
    jne boundary_contract
    ret
owned_token:
    mov rax, [r14 + EFFECT + 24]
    cmp rax, [r12 + CHILD_TOKEN]
    jne boundary_contract
    cmp qword ptr [r12 + FORKED], 1
    jne boundary_contract
    ret
zero_args:
    cmp qword ptr [r14 + EFFECT + 24], 0
    jne boundary_contract
zero_arg12:
    mov rax, [r14 + EFFECT + 32]
    or rax, [r14 + EFFECT + 40]
    jnz boundary_contract
    ret
check_span:
    cmp rdi, 4096
    jb boundary_contract
    mov rax, [r12 + WORK_CAP]
    cmp rdi, rax
    ja boundary_contract
    sub rax, rdi
    cmp rsi, rax
    ja boundary_contract
    add rdi, r14
    ret
check_cstr:
    inc rsi
    jz boundary_contract
    call check_span
    dec rsi
    cmp byte ptr [rdi + rsi], 0
    jne boundary_contract
    xor ecx, ecx
cstr_no_embedded_nul:
    cmp rcx, rsi
    je cstr_valid
    cmp byte ptr [rdi + rcx], 0
    je boundary_contract
    inc rcx
    jmp cstr_no_embedded_nul
cstr_valid:
    ret

/* Nonblocking transport does not own process lifecycle policy. Complete control
 * frames replace input only between HIA invocations; partial frames are retained.
 * EOF and a broken reply sink are trusted controller shutdown events. */
control_request:
    mov rax, 0x3130515250485348 /* HSHPRQ01 */
    mov [r13], rax
    mov [r13 + 8], rdi
    mov qword ptr [r13 + 16], 1
    mov qword ptr [r13 + 24], 0
    mov qword ptr [r13 + 32], 0
    mov qword ptr [r12 + INPUT_LEN], 40
    ret
pump_input:
    cmp qword ptr [r12 + EOF_SEEN], 0
    jne pump_done
    cmp qword ptr [r12 + IO_ERROR], 0
    jne pump_shutdown
pump_read:
    xor edi, edi
    mov rsi, [r12 + CONTROL_HAVE]
    lea rsi, [r12 + rsi + CONTROL_BUFFER]
    mov rdx, [r12 + CONTROL_NEED]
    sub rdx, [r12 + CONTROL_HAVE]
    xor eax, eax
    syscall
    cmp rax, -4
    je pump_read
    cmp rax, -11
    je pump_done
    test rax, rax
    js pump_error
    jz pump_eof
    add [r12 + CONTROL_HAVE], rax
    mov rax, [r12 + CONTROL_HAVE]
    cmp rax, [r12 + CONTROL_NEED]
    jb pump_read
    cmp qword ptr [r12 + CONTROL_NEED], 8
    jne pump_complete
    cmp qword ptr [r12 + CONTROL_BUFFER], 40
    jne pump_malformed
    mov qword ptr [r12 + CONTROL_NEED], 48
    jmp pump_read
pump_complete:
    lea rsi, [r12 + CONTROL_BUFFER + 8]
    mov rdi, r13
    mov ecx, 5
    rep movsq
    mov qword ptr [r12 + INPUT_LEN], 40
    mov qword ptr [r12 + CONTROL_HAVE], 0
    mov qword ptr [r12 + CONTROL_NEED], 8
pump_done:
    ret
pump_malformed:
    mov qword ptr [r12 + IO_ERROR], -71
    jmp pump_shutdown
pump_error:
    mov [r12 + IO_ERROR], rax
    jmp pump_shutdown
pump_eof:
    cmp qword ptr [r12 + CONTROL_HAVE], 0
    je pump_shutdown
    mov qword ptr [r12 + IO_ERROR], -71
pump_shutdown:
    mov qword ptr [r12 + EOF_SEEN], 1
    mov edi, 4
    call control_request
    ret

enqueue_reply:
    mov [r12 + REPLY], rax
    mov [r12 + REPLY + 8], rdx
    mov rbp, rdx
    add rbp, 16
    mov rbx, [r12 + QUEUE_LEN]
    add rbx, rbp
    jc boundary_contract
    cmp rbx, [r12 + QUEUE_CAP]
    jbe reply_capacity_ready
    mov rdx, [r12 + QUEUE_CAP]
reply_grow:
    shl rdx, 1
    jc boundary_contract
    test rdx, rdx
    js boundary_contract
    cmp rdx, rbx
    jb reply_grow
    mov rbx, rdx
    mov rdi, [r12 + QUEUE]
    mov rsi, [r12 + QUEUE_CAP]
    mov r10d, 1
    xor r8d, r8d
    mov eax, 25
    syscall
    cmp rax, -4095
    jae boundary_contract
    mov [r12 + QUEUE], rax
    mov [r12 + QUEUE_CAP], rbx
reply_capacity_ready:
    mov rdi, [r12 + QUEUE]
    add rdi, [r12 + QUEUE_LEN]
    lea rsi, [r12 + REPLY]
    mov ecx, 2
    rep movsq
    mov rsi, r15
    mov rcx, [r12 + REPLY + 8]
    rep movsb
    add [r12 + QUEUE_LEN], rbp
    ret
flush_output:
    cmp qword ptr [r12 + IO_ERROR], 0
    jne flush_done
flush_more:
    mov rdx, [r12 + QUEUE_LEN]
    sub rdx, [r12 + QUEUE_POS]
    jz flush_empty
    mov edi, 1
    mov rsi, [r12 + QUEUE]
    add rsi, [r12 + QUEUE_POS]
    mov eax, 1
    syscall
    cmp rax, -4
    je flush_more
    cmp rax, -11
    je flush_done
    test rax, rax
    jle flush_error
    add [r12 + QUEUE_POS], rax
    jmp flush_more
flush_empty:
    mov qword ptr [r12 + QUEUE_LEN], 0
    mov qword ptr [r12 + QUEUE_POS], 0
flush_done:
    ret
flush_error:
    mov [r12 + IO_ERROR], rax
    test rax, rax
    jnz flush_done
    mov qword ptr [r12 + IO_ERROR], -5
    ret
make_pollfds:
    mov qword ptr [r12 + POLLFDS], -1
    mov qword ptr [r12 + POLLFDS + 8], -1
    mov qword ptr [r12 + POLLFDS + 16], -1
    cmp qword ptr [r12 + EOF_SEEN], 0
    jne poll_no_input
    mov dword ptr [r12 + POLLFDS], 0
    mov dword ptr [r12 + POLLFDS + 4], 1
poll_no_input:
    mov rax, [r12 + PIDFD]
    test rax, rax
    js poll_no_pidfd
    mov [r12 + POLLFDS + 8], eax
    mov dword ptr [r12 + POLLFDS + 12], 1
poll_no_pidfd:
    mov rax, [r12 + QUEUE_LEN]
    cmp rax, [r12 + QUEUE_POS]
    je pollfds_ready
    cmp qword ptr [r12 + IO_ERROR], 0
    jne pollfds_ready
    mov dword ptr [r12 + POLLFDS + 16], 1
    mov dword ptr [r12 + POLLFDS + 20], 4
pollfds_ready:
    ret
drain_output:
    cmp qword ptr [r12 + IO_ERROR], 0
    jne finish
    mov rax, [r12 + QUEUE_LEN]
    cmp rax, [r12 + QUEUE_POS]
    je finish
    mov dword ptr [r12 + POLLFDS], 1
    mov dword ptr [r12 + POLLFDS + 4], 4
    lea rdi, [r12 + POLLFDS]
    mov esi, 1
    xor edx, edx
    xor r10d, r10d
    mov r8d, 8
    mov eax, 271
    syscall
    cmp rax, -4
    je owner_next
    test rax, rax
    jns owner_next
    mov [r12 + IO_ERROR], rax
    jmp finish

/* Fixed-size audit observations never enter HIA result bytes. The shared audit
 * page carries failures across fork; short/failed trace writes cannot look like
 * a qualified complete transcript. No global ordering between roles is claimed. */
trace_effect:
    mov [r12 + TRACE_RECORD + 112], rdi
    mov rax, 0x3152545250485348 /* HSHPRTR1 */
    mov [r12 + TRACE_RECORD], rax
    mov rax, [r12 + ROLE]
    mov [r12 + TRACE_RECORD + 8], rax
    mov rax, [r12 + SELF_PID]
    mov [r12 + TRACE_RECORD + 16], rax
    mov rax, [r12 + CHILD_TOKEN]
    mov [r12 + TRACE_RECORD + 24], rax
    mov rax, [r12 + SEQUENCE]
    mov [r12 + TRACE_RECORD + 32], rax
    mov rax, [r12 + ACTION]
    mov [r12 + TRACE_RECORD + 40], rax
    mov rax, [r14 + EFFECT + 24]
    mov [r12 + TRACE_RECORD + 48], rax
    mov rax, [r14 + EFFECT + 32]
    mov [r12 + TRACE_RECORD + 56], rax
    mov rax, [r14 + EFFECT + 40]
    mov [r12 + TRACE_RECORD + 64], rax
    mov rax, [r12 + RESULT]
    mov [r12 + TRACE_RECORD + 72], rax
    mov rax, [r12 + ERROR]
    mov [r12 + TRACE_RECORD + 80], rax
    mov rax, [r12 + AUX]
    mov [r12 + TRACE_RECORD + 88], rax
    mov rax, [r12 + CHILD_PID]
    mov [r12 + TRACE_RECORD + 96], rax
    mov rax, [r12 + OWNED]
    mov rdx, [r12 + TRACKED]
    shl rdx, 1
    or rax, rdx
    mov rdx, [r12 + SETUP_CLOSED]
    shl rdx, 2
    or rax, rdx
    mov rdx, [r12 + HANDSHAKE]
    shl rdx, 3
    or rax, rdx
    mov [r12 + TRACE_RECORD + 104], rax
    mov rax, [r12 + RAW_AUX]
    mov [r12 + TRACE_RECORD + 120], rax
    mov r8, [r12 + AUDIT]
    cmp qword ptr [r12 + ROLE], 2
    jne trace_slot_ready
    add r8, 32
trace_slot_ready:
    inc qword ptr [r8]
    mov rdi, [r12 + TRACEFD]
    lea rsi, [r12 + TRACE_RECORD]
    mov edx, 128
    mov eax, 1
    syscall
    mov [r8 + 16], rax
    cmp rax, 128
    je trace_done
    mov qword ptr [r8 + 8], 1
trace_done:
    ret
audit_footer:
    mov rdi, r12
    add rdi, TRACE_RECORD
    mov ecx, 16
    xor eax, eax
    rep stosq
    mov rax, 0x3144554150485348 /* HSHPAUD1 */
    mov [r12 + TRACE_RECORD], rax
    mov r8, [r12 + AUDIT]
    mov rax, [r8]
    mov [r12 + TRACE_RECORD + 8], rax
    mov rax, [r8 + 32]
    mov [r12 + TRACE_RECORD + 16], rax
    mov rax, [r8 + 8]
    mov [r12 + TRACE_RECORD + 24], rax
    mov rax, [r8 + 40]
    mov [r12 + TRACE_RECORD + 32], rax
    mov rax, [r8 + 16]
    mov [r12 + TRACE_RECORD + 40], rax
    mov rax, [r8 + 48]
    mov [r12 + TRACE_RECORD + 48], rax
    mov rax, [r8 + 24]
    mov [r12 + TRACE_RECORD + 56], rax
    mov rax, [r8 + 56]
    mov [r12 + TRACE_RECORD + 64], rax
    mov rax, [r12 + OWNED]
    mov [r12 + TRACE_RECORD + 72], rax
    mov rax, [r12 + TRACKED]
    mov [r12 + TRACE_RECORD + 80], rax
    mov rax, [r12 + WAIT_CACHED]
    mov [r12 + TRACE_RECORD + 88], rax
    mov rax, [r12 + CHILD_PID]
    mov [r12 + TRACE_RECORD + 96], rax
    mov rax, [r12 + EOF_SEEN]
    mov [r12 + TRACE_RECORD + 104], rax
    mov rax, [r12 + IO_ERROR]
    mov [r12 + TRACE_RECORD + 112], rax
    mov rdi, [r12 + TRACEFD]
    lea rsi, [r12 + TRACE_RECORD]
    mov edx, 128
    mov eax, 1
    syscall
    cmp rax, 128
    je footer_written
    mov qword ptr [r12 + EXIT_CODE], 74
footer_written:
    mov r8, [r12 + AUDIT]
    mov rax, [r8 + 8]
    or rax, [r8 + 40]
    jz footer_no_audit_error
    mov qword ptr [r12 + EXIT_CODE], 74
footer_no_audit_error:
    mov rax, [r8 + 24]
    or rax, [r8 + 56]
    jz footer_done
    mov qword ptr [r12 + EXIT_CODE], 78
footer_done:
    ret

boundary_contract:
    cmp qword ptr [r12 + ROLE], 2
    je child_contract
    mov rax, [r12 + AUDIT]
    test rax, rax
    jz startup_contract_failure
    mov qword ptr [rax + 24], 1
    mov qword ptr [r12 + EXIT_CODE], 78
    /* A corrupted private contract is a failing fixture, never a fallback.
     * Emergency containment is limited to this still-owned unreaped PID. */
emergency_containment:
    cmp qword ptr [r12 + OWNED], 1
    jne containment_finished
    mov rdi, [r12 + CHILD_PID]
    mov esi, 9
    mov eax, 62
    syscall
containment_wait:
    mov rdi, [r12 + CHILD_PID]
    lea rsi, [r12 + WAIT_STATUS]
    xor edx, edx
    xor r10d, r10d
    mov eax, 61
    syscall
    cmp rax, -4
    je containment_wait
    mov qword ptr [r12 + OWNED], 0
containment_finished:
    mov qword ptr [r12 + FINISHED], 1
    /* Invariant failures unwind the private assembly helper stack. */
    mov rsp, [r12 + 2048]
    jmp finish
child_contract:
    mov rax, [r12 + AUDIT]
    mov qword ptr [rax + 56], 1
    mov edi, 78
    mov eax, 60
    syscall
    ud2

finish:
    cmp qword ptr [r12 + TRACEFD], 2
    jle finish_no_trace
    call audit_footer
finish_no_trace:
    cmp qword ptr [r12 + IO_ERROR], 0
    je finish_status
    cmp qword ptr [r12 + EXIT_CODE], 0
    jne finish_status
    mov qword ptr [r12 + EXIT_CODE], 74
finish_status:
    mov rdi, [r12 + EXIT_CODE]
    mov eax, 60
    syscall
    ud2
startup_io_failure:
    mov edi, 74
    jmp exit_now
startup_allocation_failure:
allocation_failure:
    mov edi, 75
    jmp exit_now
startup_contract_failure:
    mov edi, 78
    jmp exit_now
usage:
    mov edi, 64
exit_now:
    mov eax, 60
    syscall
    ud2

create_capture:
    mov rdi, [r12 + DIRECTORY]
    mov r10d, 384
    mov eax, 257
    syscall
    jmp normalize_fd
normalize_fd:
    test rax, rax
    js normalized
    cmp rax, 2
    ja normalized
    mov r8, rax
    mov rdi, rax
    mov esi, 1030 /* F_DUPFD_CLOEXEC */
    mov edx, 3
    mov eax, 72
    syscall
    mov r9, rax
    mov rdi, r8
    mov eax, 3
    syscall
    mov rax, r9
normalized:
    ret
close_slot:
    mov r8, rdi
    mov rdi, [r8]
    mov qword ptr [r8], -1
    test rdi, rdi
    js close_finished
    mov eax, 3
    syscall
close_finished:
    ret
nonblocking:
    mov r8, rdi
    mov esi, 3
    mov eax, 72
    syscall
    test rax, rax
    js nonblocking_done
    or eax, 2048
    mov rdx, rax
    mov rdi, r8
    mov esi, 4
    mov eax, 72
    syscall
nonblocking_done:
    ret
allocate:
    mov r10d, 34
allocate_flags:
    xor edi, edi
    mov edx, 3
    mov r8, -1
    xor r9d, r9d
    mov eax, 9
    syscall
    ret
read_exact:
    xor r8d, r8d
read_more:
    xor eax, eax
    syscall
    cmp rax, -4
    je read_more
    test rax, rax
    js read_failed
    jz read_ended
    add r8, rax
    add rsi, rax
    sub rdx, rax
    jnz read_more
    mov eax, 1
    ret
read_ended:
    test r8, r8
    jnz read_failed
    xor eax, eax
    ret
read_failed:
    mov eax, 2
    ret
equal_string:
    mov al, [rdi]
    cmp al, [rsi]
    jne strings_differ
    inc rdi
    inc rsi
    test al, al
    jnz equal_string
    mov eax, 1
    ret
strings_differ:
    xor eax, eax
    ret

fixture_option: .asciz "--process-fixture"
stdout_name: .asciz "stdout.log"
stderr_name: .asciz "stderr.log"
effects_name: .asciz "effects.bin"
devnull: .asciz "/dev/null"
sh_name: .asciz "sh"
dash_c: .asciz "-c"
bin_sh: .asciz "/bin/sh"
.balign 16, 0
.Lowner_image:
    .byte 0
