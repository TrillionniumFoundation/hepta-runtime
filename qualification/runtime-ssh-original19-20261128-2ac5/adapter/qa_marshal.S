/* Qualification callbacks are marshalled to a regular OS thread. No Rust,
 * allocator, TLS, libc lock, or unwind is entered by the native clone owner.
 * Service prefix: head0, wake8, stop12, journal_fd16, events24,
 * observations32, error40, journal_lock48. Event: next/kind/a/b/c/result/
 * done/zero, 64 bytes. A producer retains the stack event until acknowledgement.
 */
.intel_syntax noprefix
.section .text
.global ssh_qa_exchange
ssh_qa_exchange:
    push rbx
    push r12
    push r13
    sub rsp, 64
    mov r12, rdi
    mov r13, rsp
    mov [r13+8], rsi
    mov [r13+16], rdx
    mov [r13+24], rcx
    mov [r13+32], r8
    mov QWORD PTR [r13+40], -71
    mov QWORD PTR [r13+48], 0
    mov QWORD PTR [r13+56], 0
    mov rax, [r12]
.Lqa_push:
    mov [r13], rax
    lock cmpxchg QWORD PTR [r12], r13
    jnz .Lqa_push
    lock inc DWORD PTR [r12+8]
    lock inc QWORD PTR [r12+24]
    lea rdi, [r12+8]
    mov esi, 129
    mov edx, 1
    xor r10d, r10d
    mov eax, 202
    syscall
.Lqa_ack_wait:
    cmp DWORD PTR [r13+48], 1
    je .Lqa_ack_ready
    lea rdi, [r13+48]
    mov esi, 128
    xor edx, edx
    xor r10d, r10d
    xor r8d, r8d
    xor r9d, r9d
    mov eax, 202
    syscall
    jmp .Lqa_ack_wait
.Lqa_ack_ready:
    # ACK producer must not retire this stack before the service has finished
    # its final futex access. This stable service lock closes that interval.
    lea rdi, [r12+56]
    call ssh_lock
    call ssh_unlock
    mov rax, [r13+40]
    add rsp, 64
    pop r13
    pop r12
    pop rbx
    ret

.global ssh_qa_observer
ssh_qa_observer:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov r12, rdi
    mov r13, rsi
    mov r14, rdx
    lock inc QWORD PTR [r12+32]
    lea rdi, [r12+48]
    call ssh_lock
    mov r15, r13
    mov rbx, r14
.Lqa_log_write:
    mov rdi, [r12+16]
    mov rsi, r15
    mov rdx, rbx
    mov eax, 1
    syscall
    cmp rax, -4
    je .Lqa_log_write
    test rax, rax
    jle .Lqa_log_error
    add r15, rax
    sub rbx, rax
    jnz .Lqa_log_write
    jmp .Lqa_log_unlock
.Lqa_log_error:
    mov QWORD PTR [r12+40], 5
.Lqa_log_unlock:
    lea rdi, [r12+48]
    call ssh_unlock
    cmp r14, 256
    jb .Lqa_observer_done
    cmp QWORD PTR [r13+48], 1
    jne .Lqa_observer_child
    cmp QWORD PTR [r13+136], 4
    jne .Lqa_observer_done
    mov rdx, [r13+56]
    sub rdx, R_ADMISSION
    mov esi, 10
    jmp .Lqa_observer_deliver
.Lqa_observer_child:
    cmp QWORD PTR [r13+48], 2
    jne .Lqa_observer_done
    cmp QWORD PTR [r13+136], 7
    jne .Lqa_observer_done
    mov rdx, [r13+56]
    sub rdx, R_CHILD
    mov esi, 11
.Lqa_observer_deliver:
    mov rdi, r12
    mov rcx, r13
    mov r8, r14
    call ssh_qa_exchange
.Lqa_observer_done:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

# ReqState prefix: service0, request8, hide_wait16, real_wait_pid24,
# real_wait_status32, cached_receipt40, cleanup_used48, released56.
.global ssh_qa_prepared
ssh_qa_prepared:
    mov rdx, rsi
    mov rcx, rdi
    mov rdi, [rdi]
    mov esi, 5
    xor r8d, r8d
    jmp ssh_qa_exchange

.global ssh_qa_spawn_prepared
ssh_qa_spawn_prepared:
    mov rdx, rdi
    mov rcx, [rdi+496]
    mov rdi, [rcx]
    mov esi, 7
    xor r8d, r8d
    jmp ssh_qa_exchange

.global ssh_qa_registered
ssh_qa_registered:
    mov rdx, rdi
    mov rcx, [rdi+496]
    mov rdi, [rcx]
    mov esi, 6
    xor r8d, r8d
    jmp ssh_qa_exchange

.global ssh_qa_entry
ssh_qa_entry:
    mov rdx, rdi
    mov rcx, rsi
    mov rdi, [rdi]
    mov esi, 1
    xor r8d, r8d
    jmp ssh_qa_exchange
.global ssh_qa_entry_drop
ssh_qa_entry_drop:
    mov rdx, rdi
    mov rdi, [rdi]
    mov esi, 2
    xor ecx, ecx
    xor r8d, r8d
    jmp ssh_qa_exchange
.global ssh_qa_guard_drop
ssh_qa_guard_drop:
    mov rdx, rdi
    mov rdi, [rdi]
    mov esi, 3
    xor ecx, ecx
    xor r8d, r8d
    jmp ssh_qa_exchange

# Original test fault: hide a completed, successful physical wait. This stores
# the actual pid/status before returning EIO, never fabricates a successful wait.
.global ssh_qa_observe_wait
ssh_qa_observe_wait:
    mov rax, rsi
    mov rcx, [rdi+496]
    cmp QWORD PTR [rcx+16], 1
    jne .Lqa_wait_return
    cmp QWORD PTR [rcx+40], 0
    jne .Lqa_wait_replayed
    mov [rcx+24], rsi
    mov [rcx+32], rdx
    mov QWORD PTR [rcx+40], 1
    mov rax, -5
.Lqa_wait_return:
    ret
.Lqa_wait_replayed:
    mov rax, -71
    ret

.global ssh_qa_request_retain
ssh_qa_request_retain:
    lock inc QWORD PTR [rdi+R_REFS]
    ret
.global ssh_qa_request_drop
ssh_qa_request_drop:
    jmp ssh_request_drop

# The original hidden-wait test explicitly clears only state.wait_failed
# after persistent failed shutdown. Its cached actual Child status is then used
# for cleanup. This mirrors that qualification-only operation; no syscall wait
# is retried and no failed owner/join receipt is replaced.
.global ssh_qa_hidden_cleanup
ssh_qa_hidden_cleanup:
    push r12
    push r13
    sub rsp, 8
    mov r13, rdi
    mov r12, [rdi+496]
    mov rax, [rdi+R_CTX]
    cmp DWORD PTR [rax+C_TID], 0
    jne .Lqa_hidden_bad
    cmp QWORD PTR [rax+C_JOIN_DONE], 1
    jne .Lqa_hidden_bad
    cmp QWORD PTR [rax+C_JOIN_ERROR], 0
    je .Lqa_hidden_bad
    cmp QWORD PTR [r12+40], 1
    jne .Lqa_hidden_bad
    cmp QWORD PTR [r12+48], 0
    jne .Lqa_hidden_bad
    mov rax, [r12+24]
    cmp rax, [r13+R_PID]
    jne .Lqa_hidden_bad
    mov eax, DWORD PTR [r13+R_STATUS]
    cmp rax, [r12+32]
    jne .Lqa_hidden_bad
    cmp QWORD PTR [r13+R_PHASE], 4
    jne .Lqa_hidden_bad
    cmp QWORD PTR [r13+R_REGISTERED], 1
    jne .Lqa_hidden_bad
    cmp QWORD PTR [r13+R_CHILD_WORK+56], 1
    jne .Lqa_hidden_bad
    cmp QWORD PTR [r13+R_CHILD_WORK+48], 0
    jne .Lqa_hidden_bad
    cmp QWORD PTR [r13+R_CHILD_WORK+32], 0
    jne .Lqa_hidden_bad
    cmp QWORD PTR [r13+R_CHILD_WORK+104], 0
    jne .Lqa_hidden_bad
    mov QWORD PTR [r12+48], 1
    mov QWORD PTR [r13+R_CHILD_WORK+56], 0
    mov rdi, r13
    mov esi, 5
    call ssh_child_simple
    cmp eax, 576
    jne .Lqa_hidden_bad
    cmp rdx, 1
    jne .Lqa_hidden_bad
    cmp r8, 2
    jne .Lqa_hidden_bad
    mov r8, r9
    mov rdi, r13
    mov esi, 6
    mov edx, 1
    mov rcx, [r12+32]
    xor r9d, r9d
    xor r10d, r10d
    call ssh_child
    cmp eax, 576
    jne .Lqa_hidden_bad
    test rdx, rdx
    jnz .Lqa_hidden_bad
    cmp QWORD PTR [r13+R_CHILD_WORK+48], 1
    jne .Lqa_hidden_bad
    xor eax, eax
    jmp .Lqa_hidden_done
.Lqa_hidden_bad:
    mov rax, -71
.Lqa_hidden_done:
    add rsp, 8
    pop r13
    pop r12
    ret

.global ssh_qa_hidden_release
ssh_qa_hidden_release:
    push r12
    push r13
    sub rsp, 8
    mov r13, rdi
    mov r12, [rdi+R_CTX]
    cmp DWORD PTR [r12+C_TID], 0
    jne .Lqa_release_bad
    cmp QWORD PTR [r12+C_JOIN_DONE], 1
    jne .Lqa_release_bad
    mov rax, [r13+496]
    cmp QWORD PTR [rax+48], 1
    jne .Lqa_release_bad
    cmp QWORD PTR [rax+56], 0
    jne .Lqa_release_bad
    cmp QWORD PTR [r13+R_REGISTERED], 1
    jne .Lqa_release_bad
    lea rax, [r12+C_QUARANTINED]
.Lqa_release_find:
    mov rcx, [rax]
    test rcx, rcx
    jz .Lqa_release_bad
    cmp rcx, r13
    je .Lqa_release_found
    lea rax, [rcx+R_NEXT_ACTIVE]
    jmp .Lqa_release_find
.Lqa_release_found:
    mov rcx, [r13+R_NEXT_ACTIVE]
    mov [rax], rcx
    mov QWORD PTR [r13+R_NEXT_ACTIVE], 0
    mov rdi, r13
    call ssh_release_child
    cmp QWORD PTR [r13+R_REGISTERED], 0
    jne .Lqa_release_bad
    cmp QWORD PTR [r13+R_PHASE], 5
    jne .Lqa_release_bad
    mov rax, [r13+496]
    mov QWORD PTR [rax+56], 1
    mov rdi, r13
    call ssh_request_drop
    xor eax, eax
    jmp .Lqa_release_done
.Lqa_release_bad:
    mov rax, -71
.Lqa_release_done:
    add rsp, 8
    pop r13
    pop r12
    ret
