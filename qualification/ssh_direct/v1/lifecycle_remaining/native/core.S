# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
# Syscall custody for the HIA direct-SSH owners. No libc or caller runtime.
.intel_syntax noprefix
.section .text
.equ C_MAGIC, 0
.equ C_PID, 8
.equ C_OBSERVER, 24
.equ C_OPAQUE, 32
.equ C_WAKE, 40
.equ C_TID, 48
.equ C_STACK, 56
.equ C_STACK_CAP, 64
.equ C_READY, 72
.equ C_QUEUE_HEAD, 80
.equ C_QUEUE_TAIL, 88
.equ C_ACTIVE, 96
.equ C_QUEUE_LOCK, 104
.equ C_ERROR, 112
.equ C_JOIN_TID, 120
.equ C_JOIN_STACK, 128
.equ C_JOIN_CAP, 136
.equ C_JOIN_START, 144
.equ C_JOIN_DONE, 152
.equ C_FROZEN, 160
.equ C_SIGMASK, 184
.equ C_GENERATION, 192
.equ C_ALLOCATED, 200
.equ C_FREED, 208
.equ C_SPAWNED, 216
.equ C_REAPED, 224
.equ C_JOURNAL, 232
.equ C_JOIN_SEQUENCE, 240
.equ C_CORE, 256
.equ C_CORE_OUT, 512

.equ R_CTX, 8
.equ R_GENERATION, 16
.equ R_REFS, 24
.equ R_NEXT_QUEUE, 32
.equ R_NEXT_ACTIVE, 40
.equ R_IN, 48
.equ R_OUT, 56
.equ R_ERR, 64
.equ R_EXEC, 72
.equ R_PID, 80
.equ R_STATUS, 88
.equ R_ENTRY, 96
.equ R_ENTRY_OPAQUE, 104
.equ R_GUARD, 112
.equ R_RELEASE, 120
.equ R_COMMAND, 128
.equ R_COMMAND_CAP, 136
.equ R_COMMAND_LEN, 144
.equ R_INPUT, 152
.equ R_INPUT_CAP, 160
.equ R_INPUT_LEN, 168
.equ R_STDOUT, 176
.equ R_STDOUT_CAP, 184
.equ R_STDOUT_LEN, 192
.equ R_STDERR, 200
.equ R_STDERR_CAP, 208
.equ R_STDERR_LEN, 216
.equ R_DEADLINE_LO, 224
.equ R_DEADLINE_HI, 232
.equ R_DONE, 240
.equ R_KIND, 248
.equ R_REASON, 256
.equ R_ERRNO, 264
.equ R_RAW_STATUS, 272
.equ R_PHASE, 280
.equ R_ID, 288
.equ R_FLAGS, 296
.equ R_WAIT_SEQ, 304
.equ R_CLEAN_SEQ, 312
.equ R_GUARD_OWNED, 320
.equ R_TASK, 328
.equ R_REGISTERED, 336
.equ R_READINESS, 344
.equ R_PIPES, 352
.equ R_LAYOUT, 384
.equ R_LAYOUT_CAP, 392
.equ R_ARGV, 400
.equ R_ENVP, 408
.equ R_SCRATCH, 416
.equ R_SCRATCH_CAP, 424
.equ R_ARGCAP, 432
.equ R_PROGRESS, 440
.equ R_POLL, 448
.equ R_ADMISSION, 512
.equ R_CHILD, 608
.equ R_IO, 704
.equ R_ADM_WORK, 4096
.equ R_CHILD_WORK, 4352
.equ R_IO_WORK, 4864
.equ R_ADM_OUT, 5120
.equ R_CHILD_OUT, 5504
.equ R_IO_OUT, 6144
.equ R_BYTES, 8192

# mmap private RW bytes followed by one inaccessible page.
# rdi requested bytes -> rax pointer, rdx rounded usable extent, or negative errno.
ssh_alloc:
    push rbx
    push r12
    mov r12, rdi
    test r12, r12
    jnz .Lalloc_size
    mov r12d, 1
.Lalloc_size:
    add r12, 4095
    jc .Lalloc_invalid
    and r12, -4096
    mov rbx, r12
    add rbx, 4096
    jc .Lalloc_invalid
    test rbx, rbx
    js .Lalloc_invalid
    xor edi, edi
    mov rsi, rbx
    mov edx, 3
    mov r10d, 34
    mov r8, -1
    xor r9d, r9d
    mov eax, 9
    syscall
    test rax, rax
    js .Lalloc_end
    mov rbx, rax
    lea rdi, [rax+r12]
    mov esi, 4096
    xor edx, edx
    mov eax, 10
    syscall
    test rax, rax
    js .Lalloc_protect_fail
    mov rax, rbx
    mov rdx, r12
    jmp .Lalloc_end
.Lalloc_protect_fail:
    push rax
    mov rdi, rbx
    lea rsi, [r12+4096]
    mov eax, 11
    syscall
    pop rax
    jmp .Lalloc_end
.Lalloc_invalid:
    mov rax, -22
.Lalloc_end:
    pop r12
    pop rbx
    ret
ssh_free:
    test rdi, rdi
    jz .Lfree_done
    add rsi, 4096
    mov eax, 11
    syscall
.Lfree_done:
    ret
ssh_zero:
    mov rcx, rsi
    xor eax, eax
    rep stosb
    ret
ssh_copy:
    mov rcx, rdx
    rep movsb
    ret
ssh_lock:
    xor eax, eax
    mov edx, 1
    lock cmpxchg DWORD PTR [rdi], edx
    jz .Llock_done
.Llock_spin:
    pause
    cmp DWORD PTR [rdi], 0
    jne .Llock_spin
    xor eax, eax
    lock cmpxchg DWORD PTR [rdi], edx
    jnz .Llock_spin
.Llock_done:
    ret
ssh_unlock:
    mov DWORD PTR [rdi], 0
    ret
# Exact monotonic nanoseconds as a 128-bit value in rdx:rax.
ssh_now:
    sub rsp, 24
    mov edi, 1
    mov rsi, rsp
    mov eax, 228
    syscall
    test rax, rax
    js .Lclock_failed
    mov rax, QWORD PTR [rsp]
    mov ecx, 1000000000
    mul rcx
    add rax, QWORD PTR [rsp+8]
    adc rdx, 0
    add rsp, 24
    ret
.Lclock_failed:
    add rsp, 24
    mov rdx, -1
    ret
ssh_wake:
    sub rsp, 8
    mov QWORD PTR [rsp], 1
    mov edi, DWORD PTR [rdi+C_WAKE]
    mov rsi, rsp
    mov edx, 8
    mov eax, 1
    syscall
    add rsp, 8
    ret
ssh_identity:
    test rdi, rdi
    jz .Lidentity_no
    mov rdx, 0x3130305443535348
    cmp QWORD PTR [rdi], rdx
    jne .Lidentity_no
    mov eax, 39
    syscall
    cmp rax, QWORD PTR [rdi+C_PID]
    jne .Lidentity_no
    xor eax, eax
    ret
.Lidentity_no:
    mov rax, -22
    ret
# Each policy owns a short lock. The observer receives immutable complete
# before/after copies after that lock has been released.
# (ctx, metadata, input, input_len) -> exact HIA return.
ssh_invoke:
    push rbp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub rsp, 40
    mov r12, rdi
    mov r13, rsi
    mov r14, rdx
    mov r15, rcx
    test r8, r8
    jnz .Linvoke_output_selected
    mov r8, QWORD PTR [r13+40]
.Linvoke_output_selected:
    mov QWORD PTR [rsp+16], r8
    xor ebx, ebx
    mov QWORD PTR [rsp], 0
    mov rdi, r13
    call ssh_lock
    cmp QWORD PTR [r12+C_OBSERVER], 0
    je .Linvoke_call
    mov rax, QWORD PTR [r13+32]
    add rax, QWORD PTR [r13+48]
    jc .Linvoke_observer_fail
    add rax, r15
    jc .Linvoke_observer_fail
    shl rax, 1
    jc .Linvoke_observer_fail
    add rax, 128
    jc .Linvoke_observer_fail
    mov QWORD PTR [rsp+8], rax
    mov rdi, rax
    call ssh_alloc
    test rax, rax
    js .Linvoke_observer_fail
    mov rbx, rax
    mov QWORD PTR [rsp], rdx
    mov rax, 0x31304e524a535348
    mov QWORD PTR [rbx], rax
    mov rax, QWORD PTR [rsp+8]
    mov QWORD PTR [rbx+8], rax
    mov QWORD PTR [rbx+16], r12
    mov rax, QWORD PTR [r12+C_PID]
    mov QWORD PTR [rbx+24], rax
    mov eax, 186
    syscall
    mov QWORD PTR [rbx+32], rax
    mov eax, 1
    lock xadd QWORD PTR [r12+C_JOURNAL], rax
    inc rax
    mov QWORD PTR [rbx+40], rax
    mov rax, QWORD PTR [r13+8]
    mov QWORD PTR [rbx+48], rax
    mov QWORD PTR [rbx+56], r13
    mov rax, QWORD PTR [r13+56]
    inc rax
    mov QWORD PTR [rbx+64], rax
    mov QWORD PTR [rbx+80], r15
    mov rax, QWORD PTR [r13+32]
    mov QWORD PTR [rbx+88], rax
    mov rax, QWORD PTR [r13+48]
    mov QWORD PTR [rbx+96], rax
    mov rax, QWORD PTR [rsp+16]
    mov QWORD PTR [rbx+104], rax
    mov rax, QWORD PTR [r13+24]
    mov QWORD PTR [rbx+112], rax
    mov QWORD PTR [rbx+120], r14
    lea rdi, [rbx+128]
    mov rsi, r14
    mov rdx, r15
    call ssh_copy
    lea rdi, [rbx+r15+128]
    mov rsi, QWORD PTR [r13+24]
    mov rdx, QWORD PTR [r13+32]
    call ssh_copy
    mov rax, QWORD PTR [r13+32]
    lea rdi, [rbx+r15+128]
    add rdi, rax
    mov rsi, QWORD PTR [rsp+16]
    mov rdx, QWORD PTR [r13+48]
    call ssh_copy
.Linvoke_call:
    mov rdi, r14
    mov rsi, r15
    mov rdx, QWORD PTR [rsp+16]
    mov rcx, QWORD PTR [r13+48]
    mov r8, QWORD PTR [r13+24]
    mov r9, QWORD PTR [r13+32]
    call QWORD PTR [r13+16]
    mov rbp, rax
    mov rsi, QWORD PTR [rsp+16]
    mov rdi, QWORD PTR [r13+40]
    cmp rsi, rdi
    je .Linvoke_output_copied
    mov rdx, QWORD PTR [r13+48]
    call ssh_copy
.Linvoke_output_copied:
    inc QWORD PTR [r13+56]
    test rbx, rbx
    jz .Linvoke_unlock
    mov QWORD PTR [rbx+72], rax
    mov rax, QWORD PTR [r13+32]
    add rax, QWORD PTR [r13+48]
    add rax, r15
    lea rdi, [rbx+rax+128]
    mov rsi, r14
    mov rdx, r15
    call ssh_copy
    mov rax, QWORD PTR [r13+32]
    add rax, QWORD PTR [r13+48]
    lea rdi, [rbx+rax+128]
    add rdi, r15
    add rdi, r15
    mov rsi, QWORD PTR [r13+24]
    mov rdx, QWORD PTR [r13+32]
    call ssh_copy
    mov rax, QWORD PTR [r13+32]
    shl rax, 1
    add rax, QWORD PTR [r13+48]
    lea rdi, [rbx+rax+128]
    add rdi, r15
    add rdi, r15
    mov rsi, QWORD PTR [rsp+16]
    mov rdx, QWORD PTR [r13+48]
    call ssh_copy
.Linvoke_unlock:
    mov rdi, r13
    call ssh_unlock
    test rbx, rbx
    jz .Linvoke_return
    mov eax, DWORD PTR [r13+4]
    cmp eax, DWORD PTR [rbx+32]
    je .Linvoke_defer
    mov rdi, QWORD PTR [r12+C_OPAQUE]
    mov rsi, rbx
    mov rdx, QWORD PTR [rsp+8]
    call QWORD PTR [r12+C_OBSERVER]
    mov rdi, rbx
    mov rsi, QWORD PTR [rsp]
    call ssh_free
.Linvoke_deferred_end:
.Linvoke_return:
    mov rax, rbp
    add rsp, 40
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret
.Linvoke_defer:
    mov QWORD PTR [r13+64], rbx
    mov rax, QWORD PTR [rsp+8]
    mov QWORD PTR [r13+72], rax
    mov rax, QWORD PTR [rsp]
    mov QWORD PTR [r13+80], rax
    jmp .Linvoke_return
.Linvoke_observer_fail:
    mov rdi, r13
    call ssh_unlock
    mov rbp, -12
    jmp .Linvoke_return

# Metadata rows have lock/module/entry/work/work-cap/output/output-cap/calls.
# rdi row, rsi module, rdx entry, rcx work, r8 work-cap, r9 output, r10 output-cap.
ssh_policy_init:
    mov QWORD PTR [rdi+8], rsi
    mov QWORD PTR [rdi+16], rdx
    mov QWORD PTR [rdi+24], rcx
    mov QWORD PTR [rdi+32], r8
    mov QWORD PTR [rdi+40], r9
    mov QWORD PTR [rdi+48], r10
    ret
# rdi request, rsi op, rdx a, rcx b, r8 c, r9 effect sequence.
ssh_admission:
    push r12
    sub rsp, 464
    mov r12, rdi
    mov QWORD PTR [rsp+8], rsi
    mov QWORD PTR [rsp+32], rdx
    mov QWORD PTR [rsp+40], rcx
    mov QWORD PTR [rsp+48], r8
    mov QWORD PTR [rsp+72], r9
    mov rax, 0x3130515241445348
    mov QWORD PTR [rsp], rax
    mov QWORD PTR [rsp+16], r12
    mov rax, QWORD PTR [r12+R_GENERATION]
    mov QWORD PTR [rsp+24], rax
    mov QWORD PTR [rsp+56], 0
    mov QWORD PTR [rsp+64], 0
    lea rdi, [rsp+80]
    mov esi, 48
    call ssh_zero
    mov rax, QWORD PTR [rsp+8]
    test rax, rax
    jz .Ladmission_deadline
    cmp rax, 1
    je .Ladmission_clock
    cmp rax, 4
    jne .Ladmission_invoke
.Ladmission_clock:
    call ssh_now
    cmp rdx, -1
    je .Ladmission_clock_failed
    mov QWORD PTR [rsp+56], rax
    mov QWORD PTR [rsp+64], rdx
    jmp .Ladmission_invoke
.Ladmission_deadline:
    mov rax, QWORD PTR [r12+R_DEADLINE_LO]
    mov QWORD PTR [rsp+56], rax
    mov rax, QWORD PTR [r12+R_DEADLINE_HI]
    mov QWORD PTR [rsp+64], rax
.Ladmission_invoke:
    lea rdi, [rsp+144]
    mov esi, 320
    call ssh_zero
    mov rdi, QWORD PTR [r12+R_CTX]
    lea rsi, [r12+R_ADMISSION]
    mov rdx, rsp
    mov ecx, 128
    lea r8, [rsp+144]
    call ssh_invoke
    mov rdx, QWORD PTR [rsp+168]
    mov rcx, QWORD PTR [rsp+192]
    mov r8, QWORD PTR [rsp+176]
    mov r9, QWORD PTR [rsp+184]
    mov r10, QWORD PTR [rsp+200]
.Ladmission_done:
    add rsp, 464
    pop r12
    ret
.Ladmission_clock_failed:
    mov rax, -5
    jmp .Ladmission_done

# rdi ctx, rsi op, rdx id, rcx request, r8 generation,
# r9 a, r10 b, r11 sequence. Complete registry may grow without consuming op.
ssh_core:
    push r12
    push r13
    sub rsp, 520
    mov r12, rdi
    mov QWORD PTR [rsp+8], rsi
    mov QWORD PTR [rsp+32], rdx
    mov QWORD PTR [rsp+40], rcx
    mov QWORD PTR [rsp+48], r8
    mov QWORD PTR [rsp+56], r9
    mov QWORD PTR [rsp+64], r10
    mov QWORD PTR [rsp+80], r11
    mov rax, 0x3130515043445348
    mov QWORD PTR [rsp], rax
    mov QWORD PTR [rsp+16], r12
    mov QWORD PTR [rsp+24], 1
    mov QWORD PTR [rsp+72], 0
    lea rdi, [rsp+88]
    mov esi, 40
    call ssh_zero
.Lcore_invoke:
    lea rdi, [rsp+136]
    mov esi, 384
    call ssh_zero
    mov rdi, r12
    lea rsi, [r12+C_CORE]
    mov rdx, rsp
    mov ecx, 128
    lea r8, [rsp+136]
    call ssh_invoke
    cmp eax, 4294967248
    jne .Lcore_done
    # The HIA growth result has no state mutation or original id consumption.
    lea rdi, [r12+C_CORE]
    call ssh_lock
    mov rdi, QWORD PTR [r12+C_CORE+32]
    shl rdi, 1
    jc .Lcore_growth_fail
    cmp rdi, QWORD PTR [rsp+152]
    jae .Lcore_allocate
    mov rdi, QWORD PTR [rsp+152]
.Lcore_allocate:
    call ssh_alloc
    test rax, rax
    js .Lcore_growth_fail
    mov r13, rax
    mov QWORD PTR [rsp+128], rdx
    mov rdi, rax
    mov rsi, QWORD PTR [r12+C_CORE+24]
    mov rdx, QWORD PTR [r12+C_CORE+32]
    call ssh_copy
    mov rdi, QWORD PTR [r12+C_CORE+24]
    mov rsi, QWORD PTR [r12+C_CORE+32]
    mov QWORD PTR [r12+C_CORE+24], r13
    mov rax, QWORD PTR [rsp+128]
    mov QWORD PTR [r12+C_CORE+32], rax
    call ssh_free
    lea rdi, [r12+C_CORE]
    call ssh_unlock
    jmp .Lcore_invoke
.Lcore_growth_fail:
    lea rdi, [r12+C_CORE]
    call ssh_unlock
    mov rax, -12
.Lcore_done:
    mov rdx, QWORD PTR [rsp+160]
    mov rcx, QWORD PTR [rsp+168]
    mov r8, QWORD PTR [rsp+176]
    mov r9, QWORD PTR [rsp+184]
    mov r10, QWORD PTR [rsp+192]
    add rsp, 520
    pop r13
    pop r12
    ret

# rdi request, rsi op, rdx a, rcx b, r8 seq, r9 clock low, r10 clock high.
ssh_child:
    push r12
    sub rsp, 704
    mov r12, rdi
    mov QWORD PTR [rsp+8], rsi
    mov rax, QWORD PTR [r12+R_ID]
    mov QWORD PTR [rsp+16], rax
    lea rax, [r12+R_CHILD_WORK]
    mov QWORD PTR [rsp+24], rax
    mov rax, QWORD PTR [r12+R_GENERATION]
    mov QWORD PTR [rsp+32], rax
    mov QWORD PTR [rsp+40], r8
    mov QWORD PTR [rsp+48], rdx
    mov QWORD PTR [rsp+56], rcx
    mov QWORD PTR [rsp+64], r9
    mov QWORD PTR [rsp+72], r10
    mov rax, 0x3130514343445348
    mov QWORD PTR [rsp], rax
    lea rdi, [rsp+80]
    mov esi, 48
    call ssh_zero
    lea rdi, [rsp+128]
    mov esi, 576
    call ssh_zero
    mov rdi, QWORD PTR [r12+R_CTX]
    lea rsi, [r12+R_CHILD]
    mov rdx, rsp
    mov ecx, 128
    lea r8, [rsp+128]
    call ssh_invoke
    mov rdx, QWORD PTR [rsp+152]
    mov rcx, QWORD PTR [rsp+176]
    mov r8, QWORD PTR [rsp+160]
    mov r9, QWORD PTR [rsp+168]
    mov r10, QWORD PTR [rsp+184]
    add rsp, 704
    pop r12
    ret

# rdi request, rsi op, rdx a, rcx b, r8 c, r9 seq.
ssh_io:
    push r12
    sub rsp, 448
    mov r12, rdi
    mov QWORD PTR [rsp+8], rsi
    mov QWORD PTR [rsp+32], rdx
    mov QWORD PTR [rsp+40], rcx
    mov QWORD PTR [rsp+48], r8
    mov QWORD PTR [rsp+72], r9
    mov rax, 0x3130514f49445348
    mov QWORD PTR [rsp], rax
    mov QWORD PTR [rsp+16], r12
    mov rax, QWORD PTR [r12+R_GENERATION]
    mov QWORD PTR [rsp+24], rax
    mov QWORD PTR [rsp+56], 0
    mov QWORD PTR [rsp+64], 0
    lea rdi, [rsp+80]
    mov esi, 48
    call ssh_zero
    cmp QWORD PTR [rsp+8], 0
    je .Lio_deadline
    cmp QWORD PTR [rsp+8], 1
    jne .Lio_invoke
    call ssh_now
    cmp rdx, -1
    je .Lio_clock_failed
    mov QWORD PTR [rsp+56], rax
    mov QWORD PTR [rsp+64], rdx
    jmp .Lio_invoke
.Lio_deadline:
    mov rax, QWORD PTR [r12+R_DEADLINE_LO]
    mov QWORD PTR [rsp+56], rax
    mov rax, QWORD PTR [r12+R_DEADLINE_HI]
    mov QWORD PTR [rsp+64], rax
.Lio_invoke:
    lea rdi, [rsp+128]
    mov esi, 320
    call ssh_zero
    mov rdi, QWORD PTR [r12+R_CTX]
    lea rsi, [r12+R_IO]
    mov rdx, rsp
    mov ecx, 128
    lea r8, [rsp+128]
    call ssh_invoke
    mov rdx, QWORD PTR [rsp+152]
    mov r8, QWORD PTR [rsp+160]
    mov r9, QWORD PTR [rsp+168]
    mov r10, QWORD PTR [rsp+176]
    mov r11, QWORD PTR [rsp+184]
.Lio_done:
    add rsp, 448
    pop r12
    ret
.Lio_clock_failed:
    mov rax, -5
    jmp .Lio_done

# Create a real CLONE_THREAD worker. The two original clear-tid slots are
# never replaced. Stack ownership remains in ctx until confirmed exit.
# ctx, start_fn, tid_word, stack_pointer_slot, stack_capacity_slot.
ssh_thread_spawn:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov r12, rdi
    mov r13, rsi
    mov r14, rdx
    mov r15, rcx
    mov rbx, r8
    mov edi, 1048576
    call ssh_alloc
    test rax, rax
    js .Lthread_return
    mov QWORD PTR [r15], rax
    mov QWORD PTR [rbx], rdx
    lea rsi, [rax+rdx-16]
    mov QWORD PTR [rsi], r12
    mov QWORD PTR [rsi+8], r13
    mov edi, 0x350f00
    mov rdx, r14
    mov r10, r14
    xor r8d, r8d
    mov eax, 56
    syscall
    test rax, rax
    jz .Lthread_child
    jns .Lthread_return
    push rax
    mov rdi, QWORD PTR [r15]
    mov rsi, QWORD PTR [rbx]
    call ssh_free
    mov QWORD PTR [r15], 0
    mov QWORD PTR [rbx], 0
    pop rax
.Lthread_return:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret
.Lthread_child:
    pop rdi
    pop rax
    call rax
    xor edi, edi
    mov eax, 60
    syscall
    ud2

# Detach a journal while its outer gate still excludes a new deferral.
# rdi metadata -> rax pointer, rdx extent, rcx allocation capacity.
ssh_take_journal:
    mov DWORD PTR [rdi+4], 0
    mov rax, QWORD PTR [rdi+64]
    mov rdx, QWORD PTR [rdi+72]
    mov rcx, QWORD PTR [rdi+80]
    mov QWORD PTR [rdi+64], 0
    mov QWORD PTR [rdi+72], 0
    mov QWORD PTR [rdi+80], 0
    ret
# ctx, detached journal pointer, extent, allocation capacity.
ssh_emit_journal:
    test rsi, rsi
    jz .Lemit_done
    push r12
    push r13
    sub rsp, 8
    mov r12, rsi
    mov r13, rcx
    mov rax, QWORD PTR [rdi+C_OBSERVER]
    mov rdi, QWORD PTR [rdi+C_OPAQUE]
    call rax
    mov rdi, r12
    mov rsi, r13
    call ssh_free
    add rsp, 8
    pop r13
    pop r12
.Lemit_done:
    ret
