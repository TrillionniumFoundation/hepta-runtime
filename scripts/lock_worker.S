# Each real worker retains its own non-transferable guard token across commands.
run_command:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp, 24
    mov r15, rdi
    mov rbx, [r15 + 64]
    mov r12, [r15 + 280]
    mov rax, [r15 + 272]
    cmp rax, [r15 + 144]
    jne contract_fail
    cmp qword ptr [r15 + 304], 0
    jne contract_fail
    lea rdi, [r15 + 384]
    xor eax, eax
    mov ecx, 16
    rep stosq
    mov rax, 0x313030514c415248
    mov [r15 + 384], rax
    cmp r12, 1
    je command_acquire
    cmp r12, 2
    je command_acquire
    cmp r12, 3
    jb contract_fail
    cmp r12, 5
    jbe command_release
    cmp r12, 6
    je command_snapshot
    cmp r12, 7
    je command_queue_poison
    cmp r12, 8
    je command_inner_poison
    cmp r12, 9
    je command_notify
    cmp r12, 10
    je command_raw_acquire
    cmp r12, 11
    je command_raw_release
    cmp r12, 12
    je command_raw_panic
    cmp r12, 14
    je command_hold_queue
    cmp r12, 15
    je command_release_queue
    cmp r12, 16
    je command_fixture_counter
    cmp r12, 17
    je command_fixture_counter
    jmp contract_fail
command_acquire:
    cmp qword ptr [r15 + 152], 0
    jne contract_fail
    cmp qword ptr [r15 + 208], 0
    jne contract_fail
    mov [r15 + 392], r12
    mov r13, [r15 + 288]
    cmp r13, 2
    ja contract_fail
    test r13, r13
    jnz deadline_present
    cmp r12, 2
    je contract_fail
    cmp qword ptr [r15 + 296], 0
    jne contract_fail
    mov qword ptr [r15 + 168], 0
    mov qword ptr [r15 + 176], 0
    mov qword ptr [r15 + 184], 0
    jmp acquisition_call
deadline_present:
    mov edi, 1
    lea rsi, [r15 + 768]
    mov eax, 228
    syscall
    test rax, rax
    jnz io_fail
    mov rax, [r15 + 768]
    mov [r15 + 176], rax
    mov rax, [r15 + 776]
    mov [r15 + 184], rax
    mov qword ptr [r15 + 168], 1
    cmp r13, 2
    je deadline_ready
    mov rax, [r15 + 296]
    mov rcx, 3600000000000
    cmp rax, rcx
    ja contract_fail
    xor edx, edx
    mov ecx, 1000000000
    div rcx
    add [r15 + 176], rax
    jc contract_fail
    add rdx, [r15 + 184]
    cmp rdx, rcx
    jb deadline_nanos
    sub rdx, rcx
    inc qword ptr [r15 + 176]
    jz contract_fail
deadline_nanos:
    mov [r15 + 184], rdx
deadline_ready:
    mov qword ptr [r15 + 408], 1
    mov rax, [r15 + 176]
    mov [r15 + 416], rax
    mov rax, [r15 + 184]
    mov [r15 + 424], rax
acquisition_call:
    call core_call
    jmp decision
command_release:
    mov rax, [r15 + 152]
    test rax, rax
    jz contract_fail
    mov [r15 + 400], rax
    cmp r12, 3
    je command_finish_shared
    mov qword ptr [r15 + 392], 12
    mov rax, [r15 + 160]
    mov [r15 + 408], rax
    cmp r12, 5
    jne release_call
    mov qword ptr [r15 + 416], 1
    jmp release_call
command_finish_shared:
    cmp qword ptr [r15 + 160], 2
    jne contract_fail
    mov qword ptr [r15 + 392], 6
release_call:
    call core_call
    jmp decision
command_snapshot:
    mov qword ptr [r15 + 392], 8
    call core_call
    jmp decision
command_queue_poison:
    mov qword ptr [r15 + 392], 10
    mov qword ptr [r15 + 408], 1
    call core_call
    jmp decision
command_inner_poison:
    mov dword ptr [rbx + 112], 1
    mov qword ptr [r15 + 392], 10
    mov qword ptr [r15 + 408], 2
    call core_call
    jmp decision
command_notify:
    mov qword ptr [r15 + 392], 11
    call core_call
    jmp decision
command_raw_acquire:
    cmp qword ptr [r15 + 216], 0
    jne contract_fail
    xor eax, eax
    mov edx, 1
    lock cmpxchg [rbx + 124], edx
    jne contract_fail
    mov qword ptr [r15 + 216], 1
    mov qword ptr [r15 + 528], 0
    jmp command_response
command_raw_panic:
    mov dword ptr [rbx + 112], 1
    cmp qword ptr [r15 + 216], 1
    jne contract_fail
    mov qword ptr [r15 + 392], 10
    mov qword ptr [r15 + 408], 2
    call core_call
    cmp qword ptr [r15 + 528], 0
    jne contract_fail
command_raw_release:
    cmp qword ptr [r15 + 216], 1
    jne contract_fail
    xor eax, eax
    xchg [rbx + 124], eax
    cmp eax, 1
    jne contract_fail
    mov qword ptr [r15 + 216], 0
    mov qword ptr [r15 + 528], 0
    jmp command_response
decision:
    mov rax, [r15 + 528]
    cmp rax, 1
    je wait_turn
    cmp rax, 3
    je check_turn
    cmp rax, 4
    je try_inner
    cmp rax, 8
    je release_inner
    cmp rax, 5
    je acquired
    test rax, rax
    jz completed
    cmp rax, 6
    je refused
    cmp rax, 7
    je refused
    jmp contract_fail
wait_turn:
    cmp r12, 2
    ja contract_fail
    mov rax, [r15 + 536]
    mov [r15 + 152], rax
    lea rdi, [rbx + 120]
    mov esi, 137
    mov edx, [r15 + 568]
    xor r10d, r10d
    cmp qword ptr [r15 + 168], 0
    je wait_time_ready
    lea r10, [r15 + 176]
wait_time_ready:
    xor r8d, r8d
    mov r9d, 0xffffffff
    mov eax, 202
    syscall
    test rax, rax
    jz poll_again
    cmp rax, -11
    je poll_again
    cmp rax, -4
    je poll_again
    cmp rax, -110
    jne contract_fail
poll_again:
    call clear_initial
    mov qword ptr [r15 + 392], 3
    call core_call
    jmp decision
check_turn:
    cmp r12, 2
    ja contract_fail
    mov rax, [r15 + 536]
    mov [r15 + 152], rax
    call clear_initial
    mov qword ptr [r15 + 392], 4
    mov [r15 + 408], r12
    call guard_clock_fields
    call core_call
    jmp decision
try_inner:
    cmp r12, 1
    jne contract_fail
    cmp qword ptr [r15 + 208], 0
    jne contract_fail
    call clear_initial
    mov qword ptr [r15 + 392], 5
    call guard_clock_fields
    xor eax, eax
    mov edx, 1
    lock cmpxchg [rbx + 124], edx
    jne inner_busy
    mov qword ptr [r15 + 208], 1
    jmp inner_result
inner_busy:
    mov qword ptr [r15 + 408], 2
inner_result:
    call core_call
    jmp decision
release_inner:
    mov qword ptr [r15 + 232], 0
    mov rax, [r15 + 544]
    mov [r15 + 240], rax
    jmp dispose_guard
dispose_guard:
    cmp qword ptr [r15 + 208], 0
    je disposed_inner
    cmp qword ptr [r15 + 240], 0
    je release_inner_word
    mov dword ptr [rbx + 112], 1
release_inner_word:
    xor eax, eax
    xchg [rbx + 124], eax
    cmp eax, 1
    jne contract_fail
    mov qword ptr [r15 + 208], 0
disposed_inner:
    call clear_initial
    mov qword ptr [r15 + 392], 7
    mov rax, [r15 + 232]
    mov [r15 + 416], rax
    mov rax, [r15 + 240]
    mov [r15 + 408], rax
    call core_call
    jmp decision
acquired:
    cmp r12, 2
    ja contract_fail
    mov rax, [r15 + 536]
    cmp rax, [r15 + 152]
    jne contract_fail
    mov [r15 + 160], r12
    jmp command_response
completed:
    cmp r12, 3
    jb contract_fail
    cmp r12, 5
    ja command_response
    cmp qword ptr [r15 + 392], 12
    je release_inner
    jmp forget_guard
refused:
    cmp r12, 3
    ja contract_fail
    cmp qword ptr [r15 + 392], 4
    je dispose_failed_acquisition
    cmp qword ptr [r15 + 392], 5
    jne forget_guard
dispose_failed_acquisition:
    mov rax, [r15 + 528]
    mov [r15 + 232], rax
    mov qword ptr [r15 + 240], 0
    jmp dispose_guard
forget_guard:
    cmp qword ptr [r15 + 208], 0
    jne contract_fail
    mov qword ptr [r15 + 152], 0
    mov qword ptr [r15 + 160], 0
    mov qword ptr [r15 + 168], 0
command_response:
    lea rdi, [r15 + 640]
    xor eax, eax
    mov ecx, 10
    rep stosq
    mov rax, 0x3130304f4c415248
    mov [r15 + 640], rax
    mov rax, [r15 + 264]
    mov [r15 + 648], rax
    mov rax, [r15 + 144]
    mov [r15 + 656], rax
    mov [r15 + 664], r12
    mov rax, [r15 + 528]
    mov [r15 + 672], rax
    cmp r12, 6
    jne command_done
    mov rax, [r15 + 536]
    mov [r15 + 680], rax
    mov rax, [r15 + 544]
    mov [r15 + 688], rax
    mov rax, [r15 + 552]
    mov [r15 + 696], rax
    mov rax, [r15 + 560]
    mov [r15 + 704], rax
command_done:
    add rsp, 24
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret
clear_initial:
    mov rax, [r15 + 152]
    mov [r15 + 400], rax
    mov qword ptr [r15 + 408], 0
    mov qword ptr [r15 + 416], 0
    mov qword ptr [r15 + 424], 0
    mov qword ptr [r15 + 488], 0
    ret
guard_clock_fields:
    mov rax, [r15 + 168]
    mov [r15 + 488], rax
    mov rax, [r15 + 176]
    mov [r15 + 416], rax
    mov rax, [r15 + 184]
    mov [r15 + 424], rax
    ret
core_call:
    lea rdi, [r15 + 384]
    mov esi, 128
    lea rdx, [r15 + 512]
    mov rcx, [r15 + 64]
    jmp policy_run

command_hold_queue:
    cmp qword ptr [r15 + 200], 0
    jne contract_fail
    mov rdi, rbx
    call mutex_lock
    mov qword ptr [r15 + 200], 1
    mov qword ptr [r15 + 528], 0
    jmp command_response
command_release_queue:
    cmp qword ptr [r15 + 200], 1
    jne contract_fail
    mov qword ptr [r15 + 200], 0
    mov rdi, rbx
    call mutex_unlock
    mov qword ptr [r15 + 528], 0
    jmp command_response

# Qualification-only state faults; actual queue custody protects both writes.
command_fixture_counter:
    cmp qword ptr [r15 + 200], 0
    jne contract_fail
    mov rdi, rbx
    call mutex_lock
    mov rdx, [rbx + 8]
    mov rax, [r15 + 288]
    cmp r12, 16
    jne fixture_readers
    cmp qword ptr [rdx + 104], 0
    jne contract_fail
    mov [rdx + 48], rax
    jmp fixture_counter_done
fixture_readers:
    mov [rdx + 64], rax
fixture_counter_done:
    mov rdi, rbx
    call mutex_unlock
    mov qword ptr [r15 + 528], 0
    jmp command_response
