.intel_syntax noprefix
.section .text
.global _start
_start:
    cld
    cmp qword ptr [rsp], 1
    jne usage
    sub rsp, 128
    mov edi, 4096
    call allocate_guarded
    mov r15, rax
    lea rax, [rip + images]
    mov [r15 + 24], rax
    mov edi, 4096
    call allocate_guarded
    mov [r15 + 8], rax
    mov qword ptr [r15 + 16], 256
    lea rdi, [r15 + 512]
    mov rax, 0x313030514c415248
    mov [rdi], rax
    mov esi, 128
    lea rdx, [r15 + 640]
    mov rcx, r15
    call policy_run
    cmp qword ptr [r15 + 656], 0
    jne contract_fail
    mov qword ptr [rsp], 1
    mov qword ptr [rsp + 8], 0
    mov qword ptr [rsp + 16], 0
    mov qword ptr [rsp + 24], 0
    mov edi, 13
    mov rsi, rsp
    xor edx, edx
    mov r10d, 8
    mov eax, 13
    syscall
    test rax, rax
    jnz io_fail
    xor r12d, r12d
spawn_worker:
    mov edi, 4096
    call allocate_guarded
    mov r13, rax
    mov [r15 + r12 * 8 + 256], rax
    mov [r13 + 64], r15
    mov [r13 + 144], r12
    mov edi, 2101248
    call allocate_guarded
    mov rbx, rax
    mov rdi, rax
    mov esi, 4096
    xor edx, edx
    mov eax, 10
    syscall
    test rax, rax
    jnz memory_fail
    lea rsi, [rbx + 2101248 - 16]
    mov [rsi], r13
    mov edi, 0x350f00
    lea rdx, [r13 + 132]
    mov r10, rdx
    xor r8d, r8d
    mov eax, 56
    syscall
    test rax, rax
    jz worker_start
    js memory_fail
    inc r12
    cmp r12, 4
    jb spawn_worker
next_frame:
    lea rsi, [r15 + 128]
    mov edx, 64
    mov r14d, 1
    call read_exact
    test eax, eax
    jz shutdown
    mov rax, 0x313030434c415248
    cmp [r15 + 128], rax
    jne contract_fail
    mov rax, [r15 + 144]
    cmp rax, 4
    jae contract_fail
    mov r13, [r15 + rax * 8 + 256]
    cmp qword ptr [r15 + 184], 0
    jne contract_fail
wait_actor:
    mov ebp, [r15 + 68]
    cmp dword ptr [r13 + 128], 0
    je dispatch_worker
    lea rdi, [r15 + 68]
    mov esi, 128
    mov edx, ebp
    xor r10d, r10d
    xor r8d, r8d
    xor r9d, r9d
    mov eax, 202
    syscall
    test rax, rax
    jz wait_actor
    cmp rax, -11
    je wait_actor
    cmp rax, -4
    je wait_actor
    jmp contract_fail
dispatch_worker:
    lea rdi, [r13 + 256]
    lea rsi, [r15 + 128]
    mov ecx, 8
    rep movsq
    mov eax, 1
    xchg [r13 + 128], eax
    test eax, eax
    jnz contract_fail
    lea rdi, [r13 + 128]
    call wake_one
    jmp next_frame
worker_start:
    mov r15, [rsp]
    sub rsp, 128
worker_wait:
    mov eax, [r15 + 128]
    cmp eax, 1
    je worker_run
    cmp eax, 3
    je worker_exit
    test eax, eax
    jnz contract_fail
    cmp qword ptr [r15 + 224], 0
    jne worker_exit
    lea rdi, [r15 + 128]
    mov esi, 128
    xor edx, edx
    xor r10d, r10d
    xor r8d, r8d
    xor r9d, r9d
    mov eax, 202
    syscall
    test rax, rax
    jz worker_wait
    cmp rax, -11
    je worker_wait
    cmp rax, -4
    je worker_wait
    jmp contract_fail
worker_run:
    mov rdi, r15
    call run_command
    mov rbx, [r15 + 64]
    lea rdi, [rbx + 64]
    call mutex_lock
    lea rsi, [r15 + 640]
    mov edx, 80
    call write_exact
    lea rdi, [rbx + 64]
    call mutex_unlock
    xor eax, eax
    xchg [r15 + 128], eax
    cmp eax, 1
    jne contract_fail
    lock inc dword ptr [rbx + 68]
    lea rdi, [rbx + 68]
    call wake_one
    jmp worker_wait
worker_exit:
    cmp qword ptr [r15 + 200], 0
    je worker_no_queue
    mov rdi, [r15 + 64]
    call mutex_unlock
    mov qword ptr [r15 + 200], 0
worker_no_queue:
    cmp qword ptr [r15 + 152], 0
    je worker_no_guard
    mov qword ptr [r15 + 280], 4
    mov rdi, r15
    call run_command
worker_no_guard:
    cmp qword ptr [r15 + 216], 0
    je worker_done
    mov rbx, [r15 + 64]
    xor eax, eax
    xchg [rbx + 124], eax
    cmp eax, 1
    jne contract_fail
worker_done:
    xor edi, edi
    mov eax, 60
    syscall
    ud2
shutdown:
    xor r12d, r12d
stop_worker:
    mov r13, [r15 + r12 * 8 + 256]
    mov qword ptr [r13 + 224], 1
    xor eax, eax
    mov edx, 3
    lock cmpxchg [r13 + 128], edx
    jne stop_next
    lea rdi, [r13 + 128]
    call wake_one
stop_next:
    inc r12
    cmp r12, 4
    jb stop_worker
    xor r12d, r12d
join_worker:
    mov r13, [r15 + r12 * 8 + 256]
join_wait:
    mov edx, [r13 + 132]
    test edx, edx
    jz joined_worker
    lea rdi, [r13 + 132]
    xor esi, esi
    xor r10d, r10d
    xor r8d, r8d
    xor r9d, r9d
    mov eax, 202
    syscall
    test rax, rax
    jz join_wait
    cmp rax, -11
    je join_wait
    cmp rax, -4
    je join_wait
    jmp contract_fail
joined_worker:
    inc r12
    cmp r12, 4
    jb join_worker
    lea rdi, [r15 + 512]
    xor eax, eax
    mov ecx, 16
    rep stosq
    lea rdi, [r15 + 512]
    mov rax, 0x313030514c415248
    mov [rdi], rax
    mov qword ptr [rdi + 8], 9
    mov esi, 128
    lea rdx, [r15 + 640]
    mov rcx, r15
    call policy_run
    cmp qword ptr [r15 + 656], 0
    jne contract_fail
    xor edi, edi
    jmp fatal_exit

mutex_lock:
    push rbx
    mov rbx, rdi
mutex_retry:
    xor eax, eax
    mov edx, 1
    lock cmpxchg dword ptr [rbx], edx
    je mutex_locked
    mov rdi, rbx
    mov esi, 128
    mov edx, 1
    xor r10d, r10d
    xor r8d, r8d
    xor r9d, r9d
    mov eax, 202
    syscall
    test rax, rax
    jz mutex_retry
    cmp rax, -11
    je mutex_retry
    cmp rax, -4
    je mutex_retry
    jmp contract_fail
mutex_locked:
    pop rbx
    ret
mutex_unlock:
    xor eax, eax
    xchg dword ptr [rdi], eax
    cmp eax, 1
    jne contract_fail
wake_one:
    mov esi, 129
    mov edx, 1
    xor r10d, r10d
    xor r8d, r8d
    xor r9d, r9d
    mov eax, 202
    syscall
    test rax, rax
    js contract_fail
    ret

round_capacity:
    mov rax, rdi
    add rax, 4095
    jc memory_fail
    and rax, -4096
    test rax, rax
    jz memory_fail
    mov rdx, 0x7ffffffffffff000
    cmp rax, rdx
    jae memory_fail
    ret
allocate_guarded:
    push rbx
    mov rbx, rdi
    lea rsi, [rdi + 4096]
    xor edi, edi
    mov edx, 3
    mov r10d, 0x22
    mov r8, -1
    xor r9d, r9d
    mov eax, 9
    syscall
    cmp rax, -4095
    jae memory_fail
    push rax
    lea rdi, [rax + rbx]
    mov esi, 4096
    xor edx, edx
    mov eax, 10
    syscall
    test rax, rax
    jnz memory_fail
    pop rax
    pop rbx
    ret
read_exact:
    test rdx, rdx
    jz read_done
read_loop:
    xor edi, edi
    xor eax, eax
    syscall
    cmp rax, -4
    je read_loop
    test rax, rax
    js io_fail
    jz read_eof
    xor r14d, r14d
    add rsi, rax
    sub rdx, rax
    jnz read_loop
read_done:
    mov eax, 1
    ret
read_eof:
    test r14, r14
    jz io_fail
    xor eax, eax
    ret
write_exact:
    test rdx, rdx
    jz write_done
write_loop:
    mov edi, 1
    mov eax, 1
    syscall
    cmp rax, -4
    je write_loop
    test rax, rax
    jle io_fail
    add rsi, rax
    sub rdx, rax
    jnz write_loop
write_done:
    ret
usage:
    mov edi, 64
    jmp fatal_exit
contract_fail:
    mov edi, 70
    jmp fatal_exit
memory_fail:
    mov edi, 71
    jmp fatal_exit
io_fail:
    mov edi, 74
fatal_exit:
    mov eax, 231
    syscall
    ud2
