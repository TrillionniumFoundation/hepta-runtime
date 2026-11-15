/* Fixed asynchronous bridge for the two original Tokio read_to_string awaits
 * and the original atomic-write await. Each worker owns a separate immutable
 * input span and the selected private reader/atomic arena until wait4 retires
 * it. Cancellation never reuses or frees a live worker's borrowed storage.
 * No public request chooses a worker, PID, descriptor or image slot. */
.intel_syntax noprefix
.section .text
.global batch_worker_start
batch_worker_start:
    push rbp
    push rbx
    push r12
    push r13
    sub rsp, 8
    cmp qword ptr [r15 + 648], 0
    jne batch_worker_invalid
    mov r12, rsi
    mov r13, rdi
    mov ebx, edx
    cmp ebx, 2
    je batch_worker_admitted
    cmp ebx, 3
    je batch_worker_admitted
    cmp ebx, 19
    jne batch_worker_invalid
batch_worker_admitted:
    mov edx, 712
    call batch_buffer
    test rax, rax
    js batch_worker_return
    mov rdi, [r15 + 712]
    mov rsi, r13
    mov rcx, r12
    rep movsb
    mov [r15 + 704], r12
    cmp qword ptr [r15 + 656], 0
    jne batch_worker_stack_ready
    mov edi, 65536
    call view_allocate
    cmp rax, -4095
    jae batch_worker_return
    mov [r15 + 656], rax
    mov qword ptr [r15 + 664], 65536
batch_worker_stack_ready:
    mov [r15 + 680], rbx
    mov rax, [r15 + 176]
    mov [r15 + 688], rax
    mov rax, [r15 + 184]
    mov [r15 + 696], rax
    mov eax, 0xfffffff8
    mov [r15 + 672], rax
    mov qword ptr [r15 + 728], 0
    mov qword ptr [r15 + 736], 0
    mov eax, 39
    syscall
    mov [r15 + 760], rax
    mov rsi, [r15 + 656]
    add rsi, [r15 + 664]
    sub rsi, 16
    mov [rsi], r15
    /* CLONE_VM | SIGCHLD: separate FD table, shared owned mappings. */
    mov edi, 273
    xor edx, edx
    xor r10d, r10d
    xor r8d, r8d
    mov eax, 56
    syscall
    test rax, rax
    jz batch_worker_child
    js batch_worker_return
    mov [r15 + 648], rax
    xor eax, eax
    jmp batch_worker_return
batch_worker_invalid:
    mov rax, -22
batch_worker_return:
    add rsp, 8
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret

batch_worker_child:
    mov r15, [rsp]
    /* A process exit owns all its private workers, including abnormal exits. */
    mov edi, 1
    mov esi, 9
    mov eax, 157
    syscall
    test rax, rax
    js batch_worker_child_failed
    mov eax, 110
    syscall
    cmp rax, [r15 + 760]
    jne batch_worker_child_failed
    mov rdi, [r15 + 712]
    mov rsi, [r15 + 704]
    mov edx, [r15 + 680]
    call batch_dispatch
    mov [r15 + 672], rax
    xor edi, edi
    jmp batch_worker_exit
batch_worker_child_failed:
    mov edi, 70
batch_worker_exit:
    mov eax, 60
    syscall
    ud2

/* eax=0 pending, 1 actual wait, -errno; esi=0 poll / 1 join. */
.global batch_worker_wait
batch_worker_wait:
    mov rdi, [r15 + 648]
    test rdi, rdi
    jle batch_worker_wait_invalid
    mov edx, 1
    test esi, esi
    jz batch_worker_wait_ready
    xor edx, edx
batch_worker_wait_ready:
    lea rsi, [r15 + 736]
    xor r10d, r10d
batch_worker_wait_again:
    mov eax, 61
    syscall
    cmp rax, -4
    je batch_worker_wait_again
    test rax, rax
    jle batch_worker_wait_done
    cmp rax, [r15 + 648]
    jne batch_worker_wait_invalid
    mov qword ptr [r15 + 648], 0
    cmp dword ptr [r15 + 736], 0
    jne batch_worker_wait_failed
    mov eax, 1
    ret
batch_worker_wait_failed:
    mov eax, 0xfffffff8
    mov [r15 + 672], rax
    mov eax, 1
    ret
batch_worker_wait_invalid:
    mov rax, -22
batch_worker_wait_done:
    ret

/* Release caller guard/context now, retain independent worker borrows. */
.global batch_call_cancel
batch_call_cancel:
    sub rsp, 8
    mov rax, [r15 + 8]
    mov rax, [rax + 8]
    mov rdx, [rax + 8]
    cmp rdx, 8
    je batch_cancel_admitted
    cmp rdx, 10
    je batch_cancel_admitted
    cmp rdx, 16
    je batch_cancel_admitted
    cmp rdx, 19
    jne batch_cancel_invalid
batch_cancel_admitted:
    lea rdi, [r15 + 896]
    mov rdx, 0x3230514c41434248
    mov [rdi], rdx
    mov qword ptr [rdi + 8], 3
    mov rdx, [rax + 16]
    mov [rdi + 16], rdx
    mov rdx, [rax + 24]
    mov [rdi + 24], rdx
    mov qword ptr [rdi + 32], 0
    mov qword ptr [rdi + 40], 0
    mov qword ptr [rdi + 48], 0
    mov qword ptr [rdi + 56], 0
    mov qword ptr [r15 + 728], 1
    mov esi, 64
    call batch_call_run
    add rsp, 8
    ret
batch_cancel_invalid:
    mov eax, 0xfffffff8
    add rsp, 8
    ret

.global batch_call_wake
batch_call_wake:
    mov edx, 5
    jmp batch_call_scheduler_frame
.global batch_call_retire_wait
batch_call_retire_wait:
    cmp qword ptr [r15 + 648], 0
    jne batch_scheduler_invalid
    mov rax, [r15 + 8]
    mov rax, [rax + 8]
    cmp qword ptr [rax + 8], 90
    jne batch_scheduler_invalid
    cmp qword ptr [rax + 160], 18
    jne batch_scheduler_invalid
    mov edx, 4
batch_call_scheduler_frame:
    sub rsp, 8
    mov rax, [r15 + 8]
    mov rax, [rax + 8]
    lea rdi, [r15 + 896]
    mov rcx, 0x3230514c41434248
    mov [rdi], rcx
    mov [rdi + 8], rdx
    mov rcx, [rax + 16]
    mov [rdi + 16], rcx
    mov rcx, [rax + 24]
    cmp edx, 4
    jne batch_scheduler_sequence
    mov rcx, [rax + 152]
batch_scheduler_sequence:
    mov [rdi + 24], rcx
    mov qword ptr [rdi + 32], 0
    mov qword ptr [rdi + 40], 0
    mov qword ptr [rdi + 48], 0
    mov qword ptr [rdi + 56], 0
    mov esi, 64
    call batch_call_run
    add rsp, 8
    ret
batch_scheduler_invalid:
    mov eax, 0xfffffff8
    ret
