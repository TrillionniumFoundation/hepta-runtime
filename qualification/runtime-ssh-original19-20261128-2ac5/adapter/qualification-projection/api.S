# Public capability API. Every pointer is an embedding-owner capability,
# never a PID or command selected by JSON.

.global ssh_direct_start
ssh_direct_start:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov r14, rdi
    mov r15, rsi
    lea rdi, [rip+ssh_global_lock]
    call ssh_lock
    cmp QWORD PTR [rip+ssh_global_frozen], 0
    jne .Lstart_frozen
    mov rax, QWORD PTR [rip+ssh_global_error]
    test rax, rax
    jnz .Lstart_return
    mov r12, QWORD PTR [rip+ssh_global_ctx]
    test r12, r12
    jnz .Lstart_existing
    mov edi, 4096
    call ssh_alloc
    test rax, rax
    js .Lstart_remember_error
    mov r12, rax
    mov rax, 0x3130305443535348
    mov QWORD PTR [r12], rax
    mov eax, 39
    syscall
    mov QWORD PTR [r12+C_PID], rax
    mov QWORD PTR [r12+16], 1
    mov QWORD PTR [r12+C_OBSERVER], r14
    mov QWORD PTR [r12+C_OPAQUE], r15
    mov QWORD PTR [r12+C_WAKE], -1
    mov QWORD PTR [r12+C_GENERATION], 1
    mov edi, 4096
    call ssh_alloc
    test rax, rax
    js .Lstart_remember_error
    mov rcx, rax
    mov r8, rdx
    lea rdi, [r12+C_CORE]
    mov esi, 3
    lea rdx, [rip+ssh_hia_core]
    lea r9, [r12+C_CORE_OUT]
    mov r10d, 384
    call ssh_policy_init
    mov rdi, r12
    xor esi, esi
    xor edx, edx
    xor ecx, ecx
    xor r8d, r8d
    xor r9d, r9d
    xor r10d, r10d
    xor r11d, r11d
    call ssh_core
    cmp eax, 384
    jne .Lstart_internal
    mov rdi, r12
    mov esi, 1
    xor edx, edx
    xor ecx, ecx
    xor r8d, r8d
    xor r9d, r9d
    xor r10d, r10d
    xor r11d, r11d
    call ssh_core
    cmp eax, 384
    jne .Lstart_internal
    cmp rdx, 1
    jne .Lstart_internal
    mov QWORD PTR [r12+248], r10
    xor edi, edi
    mov esi, 526336
    mov eax, 290
    syscall
    test rax, rax
    js .Lstart_receipt_error
    mov QWORD PTR [r12+C_WAKE], rax
    mov rdi, r12
    lea rsi, [rip+ssh_owner_thread]
    lea rdx, [r12+C_TID]
    lea rcx, [r12+C_STACK]
    lea r8, [r12+C_STACK_CAP]
    call ssh_thread_spawn
    test rax, rax
    js .Lstart_receipt_error
    mov rdi, r12
    mov esi, 2
    xor edx, edx
    xor ecx, ecx
    xor r8d, r8d
    xor r9d, r9d
    lea r10, [r12+C_TID]
    mov r11, QWORD PTR [r12+248]
    call ssh_core
    cmp eax, 384
    jne .Lstart_thread_internal
    test rdx, rdx
    jnz .Lstart_thread_internal
    cmp QWORD PTR [rip+ssh_global_frozen], 0
    je .Lstart_publish
    mov rdi, r12
    call ssh_core_stop
.Lstart_publish:
    mov QWORD PTR [rip+ssh_global_ctx], r12
    mov DWORD PTR [r12+C_READY], 1
    lea rdi, [r12+C_READY]
    mov esi, 129
    mov edx, 2147483647
    xor r10d, r10d
    xor r8d, r8d
    xor r9d, r9d
    mov eax, 202
    syscall
.Lstart_existing:
    mov rdi, r12
    call ssh_identity
    test rax, rax
    js .Lstart_return
    cmp QWORD PTR [r12+C_OBSERVER], r14
    jne .Lstart_invalid
    cmp QWORD PTR [r12+C_OPAQUE], r15
    jne .Lstart_invalid
    cmp QWORD PTR [r12+C_FROZEN], 0
    jne .Lstart_frozen
    mov rax, r12
    jmp .Lstart_return
.Lstart_receipt_error:
    mov r13, rax
    neg rax
    mov r10, rax
    mov rdi, r12
    mov esi, 2
    xor edx, edx
    xor ecx, ecx
    xor r8d, r8d
    mov r9d, 1
    mov r11, QWORD PTR [r12+248]
    call ssh_core
    mov rax, r13
    jmp .Lstart_remember_error
.Lstart_thread_internal:
    mov QWORD PTR [r12+C_ERROR], 71
    mov QWORD PTR [r12+C_FROZEN], 1
    mov QWORD PTR [rip+ssh_global_ctx], r12
    mov DWORD PTR [r12+C_READY], 1
    lea rdi, [r12+C_READY]
    mov esi, 129
    mov edx, 2147483647
    xor r10d, r10d
    xor r8d, r8d
    xor r9d, r9d
    mov eax, 202
    syscall
    mov rdi, r12
    call ssh_wake
.Lstart_internal:
    mov rax, -71
.Lstart_remember_error:
    mov QWORD PTR [rip+ssh_global_error], rax
    jmp .Lstart_return
.Lstart_frozen:
    mov rax, -125
    jmp .Lstart_return
.Lstart_invalid:
    mov rax, -22
.Lstart_return:
    mov rbx, rax
    lea rdi, [rip+ssh_global_lock]
    call ssh_unlock
    mov rax, rbx
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

ssh_core_stop:
    push r12
    sub rsp, 32
    mov r12, rdi
    lea rdi, [r12+C_QUEUE_LOCK]
    call ssh_lock
    mov QWORD PTR [r12+C_FROZEN], 1
    mov eax, 186
    syscall
    mov DWORD PTR [r12+C_CORE+4], eax
    mov rdi, r12
    mov esi, 4
    xor edx, edx
    xor ecx, ecx
    xor r8d, r8d
    xor r9d, r9d
    xor r10d, r10d
    xor r11d, r11d
    call ssh_core
    lea rdi, [r12+C_CORE]
    call ssh_take_journal
    mov QWORD PTR [rsp], rax
    mov QWORD PTR [rsp+8], rdx
    mov QWORD PTR [rsp+16], rcx
    lea rdi, [r12+C_QUEUE_LOCK]
    call ssh_unlock
    mov rdi, r12
    mov rsi, QWORD PTR [rsp]
    mov rdx, QWORD PTR [rsp+8]
    mov rcx, QWORD PTR [rsp+16]
    call ssh_emit_journal
    mov rdi, r12
    call ssh_wake
    add rsp, 32
    pop r12
    ret
.global ssh_direct_freeze
ssh_direct_freeze:
    push r12
    mov QWORD PTR [rip+ssh_global_frozen], 1
    mov r12, QWORD PTR [rip+ssh_global_ctx]
    test r12, r12
    jz .Lfreeze_no_owner
    mov rdi, r12
    call ssh_identity
    test rax, rax
    js .Lfreeze_return
    mov rdi, r12
    call ssh_core_stop
.Lfreeze_no_owner:
    xor eax, eax
.Lfreeze_return:
    pop r12
    ret

# submit(ctx, fixed_command_bytes, command_extent, input, input_extent,
# options). options = deadline low/high, entry, entry opaque, guard release,
# unused-entry drop, and two zero words.
.global ssh_direct_submit
ssh_direct_submit:
    push rbp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub rsp, 56
    mov r12, rdi
    mov QWORD PTR [rsp], rsi
    mov QWORD PTR [rsp+8], rdx
    mov QWORD PTR [rsp+16], rcx
    mov QWORD PTR [rsp+24], r8
    mov r14, r9
    call ssh_identity
    test rax, rax
    js .Lsubmit_return
    test r14, r14
    jz .Lsubmit_invalid
    cmp QWORD PTR [r14+48], 0
    je .Lsubmit_invalid
    mov rax, 0x3130415144535348
    cmp QWORD PTR [r14+56], rax
    jne .Lsubmit_invalid
    cmp QWORD PTR [rsp+8], 64
    jb .Lsubmit_invalid
    mov rax, QWORD PTR [r14+16]
    test rax, rax
    jz .Lsubmit_no_entry
    cmp QWORD PTR [r14+32], 0
    je .Lsubmit_invalid
    jmp .Lsubmit_allocate
.Lsubmit_no_entry:
    cmp QWORD PTR [r14+32], 0
    jne .Lsubmit_invalid
.Lsubmit_allocate:
    mov edi, R_BYTES
    call ssh_alloc
    test rax, rax
    js .Lsubmit_return
    mov r13, rax
    mov rax, 0x3130514552535348
    mov QWORD PTR [r13], rax
    mov QWORD PTR [r13+R_CTX], r12
    mov rax, [r14+48]
    mov [r13+496], rax
    mov rax, QWORD PTR [r12+C_GENERATION]
.Lsubmit_generation:
    cmp rax, -1
    je .Lsubmit_sequence_failed
    test rax, rax
    jz .Lsubmit_sequence_failed
    lea rdx, [rax+1]
    lock cmpxchg QWORD PTR [r12+C_GENERATION], rdx
    jnz .Lsubmit_generation
    mov QWORD PTR [r13+R_GENERATION], rax
    mov QWORD PTR [r13+R_REFS], 1
    mov QWORD PTR [r13+R_IN], -1
    mov QWORD PTR [r13+R_OUT], -1
    mov QWORD PTR [r13+R_ERR], -1
    mov QWORD PTR [r13+R_EXEC], -1
    lea rdi, [r13+R_PIPES]
    mov eax, -1
    mov ecx, 8
    rep stosd
    mov rax, QWORD PTR [r14]
    mov QWORD PTR [r13+R_DEADLINE_LO], rax
    mov rax, QWORD PTR [r14+8]
    mov QWORD PTR [r13+R_DEADLINE_HI], rax
    mov rax, QWORD PTR [r14+16]
    mov QWORD PTR [r13+R_ENTRY], rax
    mov rax, QWORD PTR [r14+24]
    mov QWORD PTR [r13+R_ENTRY_OPAQUE], rax
    mov rax, QWORD PTR [r14+32]
    mov QWORD PTR [r13+R_RELEASE], rax
    mov rax, QWORD PTR [r14+40]
    mov QWORD PTR [r13+R_ENTRY_DROP], rax
    mov rax, QWORD PTR [rsp+24]
    mov QWORD PTR [r13+R_INPUT_LEN], rax
    mov rax, QWORD PTR [rsp+8]
    mov QWORD PTR [r13+R_COMMAND_LEN], rax
    lea rdi, [r13+R_ADMISSION]
    mov esi, 1
    lea rdx, [rip+ssh_hia_admission]
    lea rcx, [r13+R_ADM_WORK]
    mov r8d, 256
    lea r9, [r13+R_ADM_OUT]
    mov r10d, 320
    call ssh_policy_init
    lea rdi, [r13+R_CHILD]
    mov esi, 2
    lea rdx, [rip+ssh_hia_child]
    lea rcx, [r13+R_CHILD_WORK]
    mov r8d, 512
    lea r9, [r13+R_CHILD_OUT]
    mov r10d, 576
    call ssh_policy_init
    lea rdi, [r13+R_IO]
    mov esi, 4
    lea rdx, [rip+ssh_hia_io]
    lea rcx, [r13+R_IO_WORK]
    mov r8d, 256
    lea r9, [r13+R_IO_OUT]
    mov r10d, 320
    call ssh_policy_init
    lea rdi, [r13+R_FUTURE]
    mov esi, 5
    lea rdx, [rip+ssh_hia_future]
    lea rcx, [r13+R_FUTURE_WORK]
    mov r8d, 128
    lea r9, [r13+R_FUTURE_OUT]
    mov r10d, 192
    call ssh_policy_init
    mov rdi, r13
    xor esi, esi
    call ssh_future
    cmp eax, 192
    jne .Lsubmit_protocol_failed
    mov rdi, r13
    xor esi, esi
    xor edx, edx
    cmp QWORD PTR [r13+R_ENTRY], 0
    setne dl
    xor ecx, ecx
    xor r8d, r8d
    xor r9d, r9d
    call ssh_admission
    cmp eax, 320
    jne .Lsubmit_protocol_failed
    mov rdi, [r13+496]
    mov rsi, r13
    call ssh_qa_prepared
    test rax, rax
    jnz .Lsubmit_protocol_failed
    mov rdi, r13
    mov esi, 1
    mov rdx, QWORD PTR [r12+C_FROZEN]
    xor ecx, ecx
    xor r8d, r8d
    xor r9d, r9d
    call ssh_admission
    cmp eax, 320
    jne .Lsubmit_protocol_failed
    cmp rdx, 0
    jne .Lsubmit_admission_failed
    # Own every command/input byte before publication to the queue.
    mov rdi, QWORD PTR [r13+R_COMMAND_LEN]
    call ssh_alloc
    test rax, rax
    js .Lsubmit_allocation_failed
    mov QWORD PTR [r13+R_COMMAND], rax
    mov QWORD PTR [r13+R_COMMAND_CAP], rdx
    mov rdi, rax
    mov rsi, QWORD PTR [rsp]
    mov rdx, QWORD PTR [r13+R_COMMAND_LEN]
    call ssh_copy
    mov rdi, QWORD PTR [r13+R_COMMAND_LEN]
    add rdi, 64
    jc .Lsubmit_invalid_owned
    call ssh_alloc
    test rax, rax
    js .Lsubmit_allocation_failed
    mov QWORD PTR [r13+R_LAYOUT], rax
    mov QWORD PTR [r13+R_LAYOUT_CAP], rdx
    mov QWORD PTR [r13+R_IO+40], rax
    mov QWORD PTR [r13+R_IO+48], rdx
    mov rdi, r12
    lea rsi, [r13+R_IO]
    mov rdx, QWORD PTR [r13+R_COMMAND]
    mov rcx, QWORD PTR [r13+R_COMMAND_LEN]
    xor r8d, r8d
    call ssh_invoke
    mov r15, rax
    lea rax, [r13+R_IO_OUT]
    mov QWORD PTR [r13+R_IO+40], rax
    mov QWORD PTR [r13+R_IO+48], 320
    cmp r15, 64
    jb .Lsubmit_protocol_failed
    mov eax, 4294901759
    cmp r15, rax
    ja .Lsubmit_invalid_owned
    mov r14, QWORD PTR [r13+R_LAYOUT]
    cmp r15, QWORD PTR [r14+8]
    jne .Lsubmit_protocol_failed
    mov rax, QWORD PTR [r14+40]
    mov QWORD PTR [r13+R_FLAGS], rax
    mov rdi, QWORD PTR [r14+24]
    add rdi, QWORD PTR [r14+32]
    add rdi, 2
    shl rdi, 3
    call ssh_alloc
    test rax, rax
    js .Lsubmit_allocation_failed
    mov QWORD PTR [r13+R_ARGV], rax
    mov QWORD PTR [r13+R_ARGCAP], rdx
    mov rdi, rax
    mov rcx, QWORD PTR [r14+24]
    xor ebx, ebx
.Lsubmit_argv:
    cmp rbx, rcx
    jae .Lsubmit_env_start
    mov rax, QWORD PTR [r14+rbx*8+64]
    add rax, QWORD PTR [r13+R_COMMAND]
    mov QWORD PTR [rdi+rbx*8], rax
    inc rbx
    jmp .Lsubmit_argv
.Lsubmit_env_start:
    mov QWORD PTR [rdi+rbx*8], 0
    lea rdi, [rdi+rbx*8+8]
    mov QWORD PTR [r13+R_ENVP], rdi
    xor ecx, ecx
.Lsubmit_env:
    cmp rcx, QWORD PTR [r14+32]
    jae .Lsubmit_env_end
    mov rax, QWORD PTR [r14+rbx*8+64]
    add rax, QWORD PTR [r13+R_COMMAND]
    mov QWORD PTR [rdi+rcx*8], rax
    inc rcx
    inc rbx
    jmp .Lsubmit_env
.Lsubmit_env_end:
    mov QWORD PTR [rdi+rcx*8], 0
    mov rdi, QWORD PTR [r13+R_INPUT_LEN]
    call ssh_alloc
    test rax, rax
    js .Lsubmit_allocation_failed
    mov QWORD PTR [r13+R_INPUT], rax
    mov QWORD PTR [r13+R_INPUT_CAP], rdx
    mov rdi, rax
    mov rsi, QWORD PTR [rsp+16]
    mov rdx, QWORD PTR [r13+R_INPUT_LEN]
    call ssh_copy
    mov edi, 8388608
    call ssh_alloc
    test rax, rax
    js .Lsubmit_allocation_failed
    mov QWORD PTR [r13+R_STDOUT], rax
    mov QWORD PTR [r13+R_STDOUT_CAP], rdx
    mov edi, 8388608
    call ssh_alloc
    test rax, rax
    js .Lsubmit_allocation_failed
    mov QWORD PTR [r13+R_STDERR], rax
    mov QWORD PTR [r13+R_STDERR_CAP], rdx
    mov edi, 8192
    call ssh_alloc
    test rax, rax
    js .Lsubmit_allocation_failed
    mov QWORD PTR [r13+R_SCRATCH], rax
    mov QWORD PTR [r13+R_SCRATCH_CAP], rdx
    mov rdi, r13
    mov esi, 1
    mov rdx, QWORD PTR [r12+C_FROZEN]
    xor ecx, ecx
    xor r8d, r8d
    xor r9d, r9d
    call ssh_admission
    cmp eax, 320
    jne .Lsubmit_protocol_failed
    cmp rdx, 0
    jne .Lsubmit_admission_failed
    # Queue ownership survives the caller's original future/OS thread.
    lea rdi, [r12+C_QUEUE_LOCK]
    call ssh_lock
    cmp QWORD PTR [r12+C_FROZEN], 0
    jne .Lsubmit_queue_stopped
    # Queue acquires its own reference; the QA cancellation capability
    # already retains the exact request before admission publication.
    lock inc QWORD PTR [r13+R_REFS]
    mov rax, QWORD PTR [r12+C_QUEUE_TAIL]
    test rax, rax
    jz .Lsubmit_first
    mov QWORD PTR [rax+R_NEXT_QUEUE], r13
    jmp .Lsubmit_tail
.Lsubmit_first:
    mov QWORD PTR [r12+C_QUEUE_HEAD], r13
.Lsubmit_tail:
    mov QWORD PTR [r12+C_QUEUE_TAIL], r13
    lea rdi, [r12+C_QUEUE_LOCK]
    call ssh_unlock
    lock inc QWORD PTR [r12+C_ALLOCATED]
    mov rdi, r12
    call ssh_wake
    mov rax, r13
    jmp .Lsubmit_return
.Lsubmit_queue_stopped:
    lea rdi, [r12+C_QUEUE_LOCK]
    call ssh_unlock
    mov QWORD PTR [r13+R_KIND], 1
    mov QWORD PTR [r13+R_REASON], 103
    jmp .Lsubmit_done_owned
.Lsubmit_admission_failed:
    mov QWORD PTR [r13+R_KIND], 1
    mov rax, rcx
    add rax, 100
    mov QWORD PTR [r13+R_REASON], rax
    jmp .Lsubmit_done_owned
.Lsubmit_allocation_failed:
    neg rax
    mov QWORD PTR [r13+R_ERRNO], rax
    mov QWORD PTR [r13+R_KIND], 1
    mov QWORD PTR [r13+R_REASON], 200
    jmp .Lsubmit_done_owned
.Lsubmit_sequence_failed:
    mov rdi, r12
    call ssh_core_stop
    mov QWORD PTR [r13+R_REFS], 1
    mov QWORD PTR [r13+R_KIND], 1
    mov QWORD PTR [r13+R_REASON], 201
    jmp .Lsubmit_done_owned
.Lsubmit_invalid_owned:
    mov QWORD PTR [r13+R_ERRNO], 22
    mov QWORD PTR [r13+R_KIND], 1
    mov QWORD PTR [r13+R_REASON], 202
    jmp .Lsubmit_done_owned
.Lsubmit_protocol_failed:
    mov QWORD PTR [r13+R_ERRNO], 71
    mov QWORD PTR [r13+R_KIND], 1
    mov QWORD PTR [r13+R_REASON], 203
.Lsubmit_done_owned:
    mov rdi, r13
    call ssh_entry_discard
    mov QWORD PTR [r13+R_PHASE], 5
    mov QWORD PTR [r13+R_DONE], 1
    lock inc QWORD PTR [r12+C_ALLOCATED]
    mov rax, r13
    jmp .Lsubmit_return
.Lsubmit_invalid:
    mov rax, -22
.Lsubmit_return:
    add rsp, 56
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret

.global ssh_direct_cancel
ssh_direct_cancel:
    push r12
    mov r12, rdi
    mov esi, 2
    xor edx, edx
    xor ecx, ecx
    xor r8d, r8d
    xor r9d, r9d
    call ssh_admission
    cmp eax, 320
    jne .Lcancel_end
    # This is a separate publication. A commit may occur between the CAS and
    # the token becoming visible, exactly as in the original Cancellation.
    mov rdi, r12
    mov esi, 3
    xor edx, edx
    xor ecx, ecx
    xor r8d, r8d
    xor r9d, r9d
    call ssh_admission
    cmp eax, 320
    jne .Lcancel_end
    mov rdi, QWORD PTR [r12+R_CTX]
    call ssh_wake
    xor eax, eax
.Lcancel_end:
    pop r12
    ret

# Result view: 96 bytes. Success bytes are borrowed until request_release.
.global ssh_direct_result
ssh_direct_result:
    cmp QWORD PTR [rdi+R_DONE], 1
    jne .Lresult_pending
    mov rax, 0x3130534552535348
    mov QWORD PTR [rsi], rax
    mov QWORD PTR [rsi+8], 96
    mov rax, QWORD PTR [rdi+R_KIND]
    mov QWORD PTR [rsi+16], rax
    mov rax, QWORD PTR [rdi+R_REASON]
    mov QWORD PTR [rsi+24], rax
    mov rax, QWORD PTR [rdi+R_ERRNO]
    mov QWORD PTR [rsi+32], rax
    mov rax, QWORD PTR [rdi+R_RAW_STATUS]
    mov QWORD PTR [rsi+40], rax
    mov rax, QWORD PTR [rdi+R_STDOUT]
    mov QWORD PTR [rsi+48], rax
    mov rax, QWORD PTR [rdi+R_STDOUT_LEN]
    mov QWORD PTR [rsi+56], rax
    mov rax, QWORD PTR [rdi+R_STDERR]
    mov QWORD PTR [rsi+64], rax
    mov rax, QWORD PTR [rdi+R_STDERR_LEN]
    mov QWORD PTR [rsi+72], rax
    mov rax, QWORD PTR [rdi+R_GENERATION]
    mov QWORD PTR [rsi+80], rax
    mov QWORD PTR [rsi+88], 0
    xor eax, eax
    ret
.Lresult_pending:
    mov eax, 1
    ret
.global ssh_direct_request_release
ssh_direct_request_release:
    push r12
    mov r12, rdi
    cmp QWORD PTR [r12+R_CALLER_DONE], 1
    je .Lrequest_drop_reference
    cmp QWORD PTR [r12+R_ADM_WORK], 0
    je .Lrequest_drop_reference
    call ssh_direct_cancel
.Lrequest_drop_reference:
    mov rdi, r12
    call ssh_request_drop
    pop r12
    ret
ssh_request_drop:
    lock dec QWORD PTR [rdi+R_REFS]
    jnz .Ldrop_done
    jmp ssh_request_free
.Ldrop_done:
    xor eax, eax
    ret
ssh_request_free:
    push r12
    mov r12, rdi
    call ssh_entry_discard
    mov rdi, QWORD PTR [r12+R_COMMAND]
    mov rsi, QWORD PTR [r12+R_COMMAND_CAP]
    call ssh_free
    mov rdi, QWORD PTR [r12+R_LAYOUT]
    mov rsi, QWORD PTR [r12+R_LAYOUT_CAP]
    call ssh_free
    mov rdi, QWORD PTR [r12+R_ARGV]
    mov rsi, QWORD PTR [r12+R_ARGCAP]
    call ssh_free
    mov rdi, QWORD PTR [r12+R_INPUT]
    mov rsi, QWORD PTR [r12+R_INPUT_CAP]
    call ssh_free
    mov rdi, QWORD PTR [r12+R_STDOUT]
    mov rsi, QWORD PTR [r12+R_STDOUT_CAP]
    call ssh_free
    mov rdi, QWORD PTR [r12+R_STDERR]
    mov rsi, QWORD PTR [r12+R_STDERR_CAP]
    call ssh_free
    mov rdi, QWORD PTR [r12+R_SCRATCH]
    mov rsi, QWORD PTR [r12+R_SCRATCH_CAP]
    call ssh_free
    mov rax, QWORD PTR [r12+R_CTX]
    lock inc QWORD PTR [rax+C_FREED]
    mov rdi, r12
    mov esi, R_BYTES
    call ssh_free
    pop r12
    ret
