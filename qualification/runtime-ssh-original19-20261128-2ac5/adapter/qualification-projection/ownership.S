.equ C_DRAIN, 168
.equ C_QUARANTINED, 176
.equ R_DRAIN, 472
.equ R_ENTRY_DROP, 480

ssh_core_simple:
    xor edx, edx
    xor ecx, ecx
    xor r8d, r8d
    xor r9d, r9d
    xor r10d, r10d
    xor r11d, r11d
    jmp ssh_core
# request, op, id, actual a, b.
ssh_core_request:
    mov r9, rcx
    mov r10, r8
    mov rcx, rdi
    cmp esi, 7
    jne .Lcore_request_cap
    lea rcx, [rdi+R_CHILD_WORK]
.Lcore_request_cap:
    mov r8, QWORD PTR [rdi+R_GENERATION]
    mov rdi, QWORD PTR [rdi+R_CTX]
    xor r11d, r11d
    jmp ssh_core
ssh_child_simple:
    xor edx, edx
    xor ecx, ecx
    xor r8d, r8d
    xor r9d, r9d
    xor r10d, r10d
    jmp ssh_child

# Freeze and commit share only this short gate. Journal delivery occurs after
# the actual gate unlock. Caller cancellation has a separate request CAS lock.
ssh_commit:
    push r12
    push r13
    sub rsp, 104
    mov r13, rdi
    mov r12, QWORD PTR [r13+R_CTX]
    lea rdi, [r12+C_QUEUE_LOCK]
    call ssh_lock
    mov eax, 186
    syscall
    mov DWORD PTR [r13+R_ADMISSION+4], eax
    mov rax, QWORD PTR [r12+C_CORE+24]
    mov rcx, QWORD PTR [rax+40]
    cmp QWORD PTR [rax+200], 0
    je .Lcommit_gate_value
    mov ecx, 2
.Lcommit_gate_value:
    mov rdi, r13
    mov esi, 4
    mov rdx, QWORD PTR [r12+C_FROZEN]
    mov r8, QWORD PTR [r13+R_ID]
    xor r9d, r9d
    call ssh_admission
    mov QWORD PTR [rsp], rax
    mov QWORD PTR [rsp+8], rdx
    mov QWORD PTR [rsp+16], rcx
    mov QWORD PTR [rsp+24], r8
    mov QWORD PTR [rsp+32], r9
    mov QWORD PTR [rsp+40], r10
    lea rdi, [r13+R_ADMISSION]
    call ssh_take_journal
    mov QWORD PTR [rsp+48], rax
    mov QWORD PTR [rsp+56], rdx
    mov QWORD PTR [rsp+64], rcx
    lea rdi, [r12+C_QUEUE_LOCK]
    call ssh_unlock
    mov rdi, r12
    mov rsi, QWORD PTR [rsp+48]
    mov rdx, QWORD PTR [rsp+56]
    mov rcx, QWORD PTR [rsp+64]
    call ssh_emit_journal
    mov rax, QWORD PTR [rsp]
    mov rdx, QWORD PTR [rsp+8]
    mov rcx, QWORD PTR [rsp+16]
    mov r8, QWORD PTR [rsp+24]
    mov r9, QWORD PTR [rsp+32]
    mov r10, QWORD PTR [rsp+40]
    add rsp, 104
    pop r13
    pop r12
    ret
ssh_entry_discard:
    push r12
    mov r12, rdi
    cmp QWORD PTR [r12+R_ENTRY], 0
    je .Lentry_discard_done
    mov QWORD PTR [r12+R_ENTRY], 0
    mov rax, QWORD PTR [r12+R_ENTRY_DROP]
    mov QWORD PTR [r12+R_ENTRY_DROP], 0
    test rax, rax
    jz .Lentry_discard_done
    mov rdi, QWORD PTR [r12+R_ENTRY_OPAQUE]
    call rax
.Lentry_discard_done:
    pop r12
    ret
ssh_guard_drop:
    push r12
    mov r12, rdi
    cmp QWORD PTR [r12+R_GUARD_OWNED], 1
    jne .Lguard_drop_done
    mov QWORD PTR [r12+R_GUARD_OWNED], 0
    mov rdi, QWORD PTR [r12+R_GUARD]
    mov rax, QWORD PTR [r12+R_RELEASE]
    call rax
    mov QWORD PTR [r12+R_GUARD], 0
.Lguard_drop_done:
    pop r12
    ret

ssh_begin_request:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov r13, rdi
    mov r12, QWORD PTR [r13+R_CTX]
    mov QWORD PTR [r13+R_PHASE], 1
    mov esi, 8
    xor edx, edx
    xor ecx, ecx
    xor r8d, r8d
    call ssh_core_request
    cmp eax, 384
    jne .Lbegin_protocol
    cmp rdx, 0
    jne .Lbegin_protocol
    mov QWORD PTR [r13+R_TASK], 1
    mov rdi, r13
    mov esi, 5
    xor edx, edx
    xor ecx, ecx
    xor r8d, r8d
    call ssh_core_request
    cmp eax, 384
    jne .Lbegin_protocol
    test rdx, rdx
    jnz .Lbegin_core_refused
    mov QWORD PTR [r13+R_ID], r9
    mov rdi, r13
    call ssh_qa_spawn_prepared
    test rax, rax
    jnz .Lbegin_abort_protocol
    mov rdi, r13
    call ssh_commit
    cmp eax, 320
    jne .Lbegin_abort_protocol
    test rdx, rdx
    jnz .Lbegin_admission_refused
    mov rdi, r13
    mov esi, 5
    xor edx, edx
    xor ecx, ecx
    xor r8d, r8d
    xor r9d, r9d
    call ssh_admission
    cmp eax, 320
    jne .Lbegin_abort_protocol
    cmp rdx, 1
    jne .Lbegin_abort_protocol
    cmp r8, 1
    jne .Lbegin_spawn_effect
    # Take the one actual Entry before calling it on this independent thread.
    mov r15, QWORD PTR [r13+R_ENTRY]
    mov QWORD PTR [r13+R_ENTRY], 0
    mov QWORD PTR [r13+R_ENTRY_DROP], 0
    mov rdi, QWORD PTR [r13+R_ENTRY_OPAQUE]
    lea rsi, [r13+R_GUARD]
    call r15
    test rax, rax
    jnz .Lbegin_entry_failed
    mov QWORD PTR [r13+R_GUARD_OWNED], 1
    mov rdi, r13
    mov esi, 6
    xor edx, edx
    xor ecx, ecx
    xor r8d, r8d
    mov r9, QWORD PTR [r13+R_ADM_WORK+104]
    call ssh_admission
    cmp eax, 320
    jne .Lbegin_abort_protocol
    cmp rdx, 1
    jne .Lbegin_abort_protocol
.Lbegin_spawn_effect:
    cmp r8, 2
    jne .Lbegin_abort_protocol
    mov rdi, r13
    call ssh_spawn
    test rax, rax
    js .Lbegin_spawn_failed
    test rax, rax
    jz .Lbegin_abort_protocol
    # The unique registry reservation is filled with this actual object.
    mov rdi, r13
    mov esi, 6
    mov rdx, QWORD PTR [r13+R_ID]
    mov ecx, 1
    lea r8, [r13+R_CHILD_WORK]
    call ssh_core_request
    cmp eax, 384
    jne .Lbegin_live_protocol
    test rdx, rdx
    jnz .Lbegin_live_protocol
    mov QWORD PTR [r13+R_REGISTERED], 1
    lock inc QWORD PTR [r12+C_SPAWNED]
    mov rdi, r13
    mov esi, 7
    xor edx, edx
    lea rcx, [r13+R_CHILD_WORK]
    mov r8, QWORD PTR [r13+R_ID]
    mov r9, QWORD PTR [r13+R_ADM_WORK+104]
    call ssh_admission
    cmp eax, 320
    jne .Lbegin_live_protocol
    test rdx, rdx
    jnz .Lbegin_live_protocol
    mov rdi, r13
    xor esi, esi
    mov rdx, QWORD PTR [r13+R_GUARD_OWNED]
    xor ecx, ecx
    xor r8d, r8d
    xor r9d, r9d
    xor r10d, r10d
    call ssh_child
    cmp eax, 576
    jne .Lbegin_live_protocol
    mov rdi, r13
    mov esi, 1
    call ssh_child_simple
    cmp eax, 576
    jne .Lbegin_live_protocol
    mov rdi, r13
    mov esi, 3
    call ssh_child_simple
    cmp eax, 576
    jne .Lbegin_live_protocol
    cmp rdx, 1
    jne .Lbegin_live_protocol
    mov QWORD PTR [r13+R_WAIT_SEQ], r9
    cmp QWORD PTR [r13+R_REASON], 205
    jne .Lbegin_io_init
    mov rdi, r13
    mov esi, 9
    mov edx, 1
    mov rcx, QWORD PTR [r13+R_ERRNO]
    mov r8, QWORD PTR [r13+R_WAIT_SEQ]
    xor r9d, r9d
    xor r10d, r10d
    call ssh_child
    cmp eax, 576
    jne .Lbegin_live_protocol
    mov QWORD PTR [r13+R_WAIT_SEQ], 0
.Lbegin_io_init:
    mov rdi, r13
    xor esi, esi
    mov rdx, QWORD PTR [r13+R_INPUT_LEN]
    mov rcx, QWORD PTR [r13+R_FLAGS]
    and ecx, 7
    xor r8d, r8d
    xor r9d, r9d
    call ssh_io
    cmp eax, 320
    jne .Lbegin_live_protocol
    mov QWORD PTR [r13+R_PHASE], 2
    mov rdi, r13
    call ssh_qa_registered
    test rax, rax
    jz .Lbegin_return
    mov QWORD PTR [r12+C_ERROR], 71
    mov QWORD PTR [r13+R_KIND], 1
    mov QWORD PTR [r13+R_REASON], 203
    mov QWORD PTR [r13+R_ERRNO], 71
    mov rdi, r12
    call ssh_core_stop
    jmp .Lbegin_return
.Lbegin_entry_failed:
    mov r14, rax
    mov rdi, r13
    mov esi, 6
    mov edx, 1
    mov rcx, r14
    xor r8d, r8d
    mov r9, QWORD PTR [r13+R_ADM_WORK+104]
    call ssh_admission
    cmp eax, 320
    jne .Lbegin_abort_protocol
    mov QWORD PTR [r13+R_KIND], 1
    mov QWORD PTR [r13+R_REASON], 104
    mov QWORD PTR [r13+R_ERRNO], r14
    jmp .Lbegin_abort_reservation
.Lbegin_spawn_failed:
    neg rax
    mov r14, rax
    mov rdi, r13
    mov esi, 7
    mov edx, 1
    mov rcx, r14
    xor r8d, r8d
    mov r9, QWORD PTR [r13+R_ADM_WORK+104]
    call ssh_admission
    cmp eax, 320
    jne .Lbegin_abort_protocol
    cmp r8, 3
    jne .Lbegin_spawn_error_record
    mov rdi, r13
    call ssh_guard_drop
    mov rdi, r13
    mov esi, 8
    xor edx, edx
    xor ecx, ecx
    xor r8d, r8d
    mov r9, QWORD PTR [r13+R_ADM_WORK+104]
    call ssh_admission
    cmp eax, 320
    jne .Lbegin_abort_protocol
.Lbegin_spawn_error_record:
    mov QWORD PTR [r13+R_KIND], 1
    mov QWORD PTR [r13+R_REASON], 105
    mov QWORD PTR [r13+R_ERRNO], r14
    jmp .Lbegin_abort_reservation
.Lbegin_admission_refused:
    add rcx, 100
    mov QWORD PTR [r13+R_KIND], 1
    mov QWORD PTR [r13+R_REASON], rcx
    jmp .Lbegin_abort_reservation
.Lbegin_abort_protocol:
    mov QWORD PTR [r13+R_KIND], 1
    mov QWORD PTR [r13+R_REASON], 203
    mov QWORD PTR [r13+R_ERRNO], 71
    mov rdi, r12
    call ssh_core_stop
.Lbegin_abort_reservation:
    mov rdi, r13
    call ssh_guard_drop
    mov rdi, r13
    mov esi, 6
    mov rdx, QWORD PTR [r13+R_ID]
    xor ecx, ecx
    xor r8d, r8d
    call ssh_core_request
    cmp eax, 384
    jne .Lbegin_protocol
    mov rdi, r13
    call ssh_finish_request
    jmp .Lbegin_return
.Lbegin_core_refused:
    add rcx, 300
    mov QWORD PTR [r13+R_KIND], 1
    mov QWORD PTR [r13+R_REASON], rcx
    mov rdi, r12
    call ssh_core_stop
    mov rdi, r13
    call ssh_finish_request
    jmp .Lbegin_return
.Lbegin_protocol:
    mov QWORD PTR [r13+R_KIND], 1
    mov QWORD PTR [r13+R_REASON], 203
    mov QWORD PTR [r13+R_ERRNO], 71
    mov QWORD PTR [r12+C_ERROR], 71
    mov rdi, r12
    call ssh_core_stop
    mov rdi, r13
    call ssh_finish_request
    jmp .Lbegin_return
.Lbegin_live_protocol:
    mov QWORD PTR [r12+C_ERROR], 71
    mov QWORD PTR [r13+R_KIND], 1
    mov QWORD PTR [r13+R_REASON], 203
    mov QWORD PTR [r13+R_ERRNO], 71
    mov rdi, r13
    call ssh_quarantine
.Lbegin_return:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

# Finishes only the received task, never its quarantined original child.
ssh_finish_request:
    push r12
    mov r12, rdi
    call ssh_entry_discard
    cmp QWORD PTR [r12+R_TASK], 0
    je .Lfinish_publish
    mov rdi, r12
    mov esi, 9
    xor edx, edx
    xor ecx, ecx
    xor r8d, r8d
    call ssh_core_request
    cmp eax, 384
    jne .Lfinish_error
    test rdx, rdx
    jnz .Lfinish_error
    mov QWORD PTR [r12+R_TASK], 0
.Lfinish_publish:
    mov QWORD PTR [r12+R_PHASE], 5
.Lfinish_notify:
    mov QWORD PTR [r12+R_DONE], 1
    lea rdi, [r12+R_DONE]
    mov esi, 129
    mov edx, 2147483647
    xor r10d, r10d
    xor r8d, r8d
    xor r9d, r9d
    mov eax, 202
    syscall
    pop r12
    ret
.Lfinish_error:
    mov rdi, QWORD PTR [r12+R_CTX]
    mov QWORD PTR [rdi+C_ERROR], 71
    call ssh_core_stop
    cmp QWORD PTR [r12+R_DONE], 0
    jne .Lfinish_retain
    mov QWORD PTR [r12+R_KIND], 1
    mov QWORD PTR [r12+R_REASON], 203
    mov QWORD PTR [r12+R_ERRNO], 71
.Lfinish_retain:
    # An unremoved task row retains its exact allocation permanently.
    mov QWORD PTR [r12+R_DRAIN], 1
    mov QWORD PTR [r12+R_PHASE], 4
    jmp .Lfinish_notify

# Settle this error waiter without destroying its original child or guard.
ssh_quarantine:
    push r12
    mov r12, rdi
    mov rdi, QWORD PTR [r12+R_CTX]
    call ssh_core_stop
    cmp QWORD PTR [r12+R_TASK], 0
    je .Lquarantine_publish
    mov rdi, r12
    mov esi, 9
    xor edx, edx
    xor ecx, ecx
    xor r8d, r8d
    call ssh_core_request
    cmp eax, 384
    jne .Lquarantine_internal
    test rdx, rdx
    jnz .Lquarantine_internal
    mov QWORD PTR [r12+R_TASK], 0
.Lquarantine_publish:
    mov QWORD PTR [r12+R_PHASE], 4
    mov QWORD PTR [r12+R_DONE], 1
    lea rdi, [r12+R_DONE]
    mov esi, 129
    mov edx, 2147483647
    xor r10d, r10d
    xor r8d, r8d
    xor r9d, r9d
    mov eax, 202
    syscall
    pop r12
    ret
.Lquarantine_internal:
    mov rax, QWORD PTR [r12+R_CTX]
    mov QWORD PTR [rax+C_ERROR], 71
    jmp .Lquarantine_publish

ssh_release_child:
    push r12
    push r13
    sub rsp, 8
    mov r13, rdi
    mov r12, QWORD PTR [r13+R_CTX]
    mov esi, 10
    call ssh_child_simple
    cmp eax, 576
    jne .Lrelease_protocol
    cmp rdx, 1
    jne .Lrelease_protocol
    cmp r8, 5
    jne .Lrelease_protocol
    mov QWORD PTR [r13+R_CLEAN_SEQ], r9
    cmp QWORD PTR [r13+R_REGISTERED], 1
    jne .Lrelease_protocol
    cmp QWORD PTR [r13+R_CHILD_WORK+48], 1
    jne .Lrelease_protocol
    mov rdi, r13
    mov esi, 7
    mov rdx, QWORD PTR [r13+R_ID]
    mov ecx, 1
    xor r8d, r8d
    call ssh_core_request
    cmp eax, 384
    jne .Lrelease_protocol
    test rdx, rdx
    jnz .Lrelease_protocol
    mov QWORD PTR [r13+R_REGISTERED], 0
    mov rdi, r13
    mov esi, 11
    xor edx, edx
    xor ecx, ecx
    mov r8, QWORD PTR [r13+R_CLEAN_SEQ]
    xor r9d, r9d
    xor r10d, r10d
    call ssh_child
    cmp eax, 576
    jne .Lrelease_protocol
    cmp rdx, 1
    jne .Lrelease_protocol
    cmp r8, 6
    jne .Lrelease_protocol
    mov QWORD PTR [r13+R_CLEAN_SEQ], r9
    mov rdi, r13
    call ssh_guard_drop
    mov rdi, r13
    mov esi, 13
    xor edx, edx
    xor ecx, ecx
    mov r8, QWORD PTR [r13+R_CLEAN_SEQ]
    xor r9d, r9d
    xor r10d, r10d
    call ssh_child
    cmp eax, 576
    jne .Lrelease_protocol
    test rdx, rdx
    jnz .Lrelease_protocol
    mov rdi, r13
    call ssh_finish_request
    jmp .Lrelease_done
.Lrelease_protocol:
    mov QWORD PTR [r12+C_ERROR], 71
    cmp QWORD PTR [r13+R_DONE], 0
    jne .Lrelease_quarantine
    mov QWORD PTR [r13+R_KIND], 1
    mov QWORD PTR [r13+R_REASON], 203
    mov QWORD PTR [r13+R_ERRNO], 71
.Lrelease_quarantine:
    mov rdi, r13
    call ssh_quarantine
.Lrelease_done:
    add rsp, 8
    pop r13
    pop r12
    ret
