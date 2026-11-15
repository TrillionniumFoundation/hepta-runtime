/* Private lifecycle frames schedule real owners; they carry no authority. */
d_main:
    call d_scan_tasks
    call d_reap_fence
    cmp qword ptr [r15 + D_CLOSING], 0
    jne d_closing_loop
    call d_read_input
    test eax, eax
    jnz d_main
    jmp d_wait_events
d_closing_loop:
    call d_close_fence_when_unused
    cmp qword ptr [r15 + D_HEAD], 0
    jne d_wait_events
    cmp qword ptr [r15 + D_FENCE_PID], 0
    jne d_wait_events
    jmp frame_eof

d_wait_events:
    mov dword ptr [r15 + D_POLL], 0
    mov word ptr [r15 + D_POLL + 4], 1
    mov word ptr [r15 + D_POLL + 6], 0
    cmp qword ptr [r15 + D_CLOSING], 0
    je d_poll_stdin_ready
    mov dword ptr [r15 + D_POLL], -1
d_poll_stdin_ready:
    mov eax, [r15 + D_WAKE_R]
    mov [r15 + D_POLL + 8], eax
    mov word ptr [r15 + D_POLL + 12], 1
    mov word ptr [r15 + D_POLL + 14], 0
    lea rdi, [r15 + D_POLL]
    mov esi, 2
    mov edx, -1
    mov eax, 7
    syscall
    cmp rax, -4
    je d_main
    test rax, rax
    jle fatal
    test word ptr [r15 + D_POLL + 6], 0x28
    jnz fatal
    test word ptr [r15 + D_POLL + 14], 0x38
    jnz fatal
d_drain_notices:
    mov rdi, [r15 + D_WAKE_R]
    lea rsi, [r15 + D_NOTICE]
    mov edx, 8
    xor eax, eax
    syscall
    cmp rax, -4
    je d_drain_notices
    cmp rax, -11
    je d_main
    test rax, rax
    jle fatal
    jmp d_drain_notices

/* Returns one when a complete frame or EOF was consumed, zero on EAGAIN. */
d_read_input:
    cmp qword ptr [r15 + D_INPUT_STAGE], 0
    jne d_read_body
    lea rsi, [r15 + D_FRAME_HEADER]
    mov edx, 8
    jmp d_read_selected
d_read_body:
    lea rsi, [r15 + POLICY_INPUT]
    mov rdx, [r15 + D_INPUT_LEN]
d_read_selected:
    mov rcx, [r15 + D_INPUT_USED]
    add rsi, rcx
    sub rdx, rcx
    jz fatal
    xor edi, edi
    xor eax, eax
    syscall
    cmp rax, -4
    je d_read_input
    cmp rax, -11
    je d_read_would_block
    test rax, rax
    js fatal
    jz d_input_eof
    add [r15 + D_INPUT_USED], rax
    cmp qword ptr [r15 + D_INPUT_STAGE], 0
    jne d_body_progress
    cmp qword ptr [r15 + D_INPUT_USED], 8
    jb d_read_input
    jne fatal
    mov rax, [r15 + D_FRAME_HEADER]
    cmp rax, 32
    jb fatal
    cmp rax, 16777288
    ja fatal
    mov [r15 + D_INPUT_LEN], rax
    mov qword ptr [r15 + D_INPUT_STAGE], 1
    mov qword ptr [r15 + D_INPUT_USED], 0
    jmp d_read_input
d_body_progress:
    mov rax, [r15 + D_INPUT_USED]
    cmp rax, [r15 + D_INPUT_LEN]
    jb d_read_input
    jne fatal
    call d_control
    mov qword ptr [r15 + D_INPUT_STAGE], 0
    mov qword ptr [r15 + D_INPUT_USED], 0
    mov qword ptr [r15 + D_INPUT_LEN], 0
    mov eax, 1
    ret
d_read_would_block:
    xor eax, eax
    ret
d_input_eof:
    cmp qword ptr [r15 + D_INPUT_STAGE], 0
    jne fatal
    cmp qword ptr [r15 + D_INPUT_USED], 0
    jne fatal
    mov qword ptr [r15 + D_CLOSING], 1
    mov eax, 1
    ret

d_control:
    lea r12, [r15 + POLICY_INPUT]
    movabs rax, 0x31304c5443444d48 /* HMDCTL01 */
    cmp [r12], rax
    jne fatal
    mov rax, [r15 + D_INPUT_LEN]
    sub rax, 32
    cmp [r12 + 24], rax
    jne fatal
    mov rcx, [r12 + 8]
    mov [r15 + D_CONTROL_CMD], rcx
    mov rdx, [r12 + 16]
    test rdx, rdx
    jz fatal
    mov [r15 + D_CONTROL_ID], rdx
    cmp rcx, 1
    je d_begin_control
    test rax, rax
    jnz fatal
    cmp rcx, 2
    je d_cancel_control
    cmp rcx, 3
    jne fatal
d_cancel_control:
    mov rbx, [r15 + D_HEAD]
d_find_control:
    test rbx, rbx
    jz d_control_missing
    cmp [rbx + T_ID], rdx
    je d_cancel_found
    mov rbx, [rbx + T_NEXT]
    jmp d_find_control
d_cancel_found:
    mov [r15 + D_CURRENT], rbx
    mov rax, [r15 + D_CONTROL_CMD]
    inc rax /* soft cancellation is event 3, outer drop is event 4 */
    mov [r15 + D_ENTRY_KIND], rax
    mov qword ptr [r15 + D_ENTRY_LEN], 0
    lea rax, [rip + d_empty]
    mov [r15 + D_ENTRY_PTR], rax
    call d_drive
    xor edx, edx
    jmp d_emit_control_ack
d_control_missing:
    mov edx, 1
d_emit_control_ack:
    mov rax, [r15 + D_CONTROL_CMD]
    inc rax
    mov [r15 + D_EMIT_EVENT], rax
    mov rax, [r15 + D_CONTROL_ID]
    mov [r15 + D_EMIT_ID], rax
    mov [r15 + D_EMIT_CODE], rdx
    mov qword ptr [r15 + D_EMIT_LEN], 0
    call d_emit
    ret

d_begin_control:
    cmp rdx, [r15 + D_LAST_ID]
    jbe fatal
    mov [r15 + D_LAST_ID], rdx
    mov esi, D_TASK_BYTES
    call d_allocate
    mov rbx, rax
    mov rdx, [r15 + D_HEAD]
    mov [rbx + T_NEXT], rdx
    mov [r15 + D_HEAD], rbx
    mov [r15 + D_CURRENT], rbx
    mov rdx, [r15 + D_CONTROL_ID]
    mov [rbx + T_ID], rdx
    lea rax, [rbx + 4096]
    mov [rbx + T_WORK], rax
    lea rax, [rbx + 268439552]
    mov [rbx + T_OUTPUT], rax
    mov qword ptr [rbx + T_FD], -1
    mov qword ptr [rbx + T_STATUS], 1
    mov rdi, [rbx + T_WORK]
    add rdi, 4096
    mov [r15 + D_ENTRY_PTR], rdi
    movabs rax, 0x3230464343444d48 /* HMDCCF02 */
    mov [rdi], rax
    mov rax, [r15 + D_USER_PRESENT]
    mov [rdi + 8], rax
    mov rcx, [r15 + D_USER_LEN]
    mov [rdi + 16], rcx
    mov r12, [r15 + D_SNAPSHOT]
    mov rax, [r12 + 8]
    mov [rdi + 24], rax
    mov rax, [r12 + 16]
    mov [rdi + 32], rax
    mov rdx, [r12 + 24]
    mov [rdi + 40], rdx
    mov qword ptr [rdi + 48], 0
    lea rax, [rcx + rdx + 56]
    mov [r15 + D_ENTRY_LEN], rax
    mov rsi, [r15 + D_USER_PTR]
    add rdi, 56
    rep movsb
    lea rsi, [r12 + 32]
    mov rcx, [r12 + 24]
    rep movsb
    mov qword ptr [r15 + D_ENTRY_KIND], 0
    call d_call_caller
    test rax, rax
    jnz fatal
    mov qword ptr [r15 + D_EMIT_EVENT], 1
    mov rax, [r15 + D_CONTROL_ID]
    mov [r15 + D_EMIT_ID], rax
    mov qword ptr [r15 + D_EMIT_CODE], 0
    mov qword ptr [r15 + D_EMIT_LEN], 0
    call d_emit
    lea rax, [r15 + POLICY_INPUT + 32]
    mov [r15 + D_ENTRY_PTR], rax
    mov rax, [r15 + D_INPUT_LEN]
    sub rax, 32
    mov [r15 + D_ENTRY_LEN], rax
    mov qword ptr [r15 + D_ENTRY_KIND], 1
    call d_drive
    ret

d_emit:
    mov rax, [r15 + D_EMIT_LEN]
    cmp rax, ROOT_OUTPUT_CAP
    ja fatal
    add rax, 40
    mov [r15 + D_REPLY], rax
    movabs rax, 0x3130525443444d48 /* HMDCTR01 */
    mov [r15 + D_REPLY + 8], rax
    mov rax, [r15 + D_EMIT_EVENT]
    mov [r15 + D_REPLY + 16], rax
    mov rax, [r15 + D_EMIT_ID]
    mov [r15 + D_REPLY + 24], rax
    mov rax, [r15 + D_EMIT_CODE]
    mov [r15 + D_REPLY + 32], rax
    mov rax, [r15 + D_EMIT_LEN]
    mov [r15 + D_REPLY + 40], rax
    mov edi, 1
    lea rsi, [r15 + D_REPLY]
    mov edx, 48
    call write_exact
    test eax, eax
    jnz fatal
    mov edi, 1
    mov rsi, [r15 + D_EMIT_PTR]
    mov rdx, [r15 + D_EMIT_LEN]
    call write_exact
    test eax, eax
    jnz fatal
    ret

d_complete_task:
    mov [r15 + D_RESULT_CODE], rax
    mov qword ptr [r15 + D_EMIT_EVENT], 2
    mov rax, [rbx + T_ID]
    mov [r15 + D_EMIT_ID], rax
    mov rax, [r15 + D_RESULT_CODE]
    mov [r15 + D_EMIT_CODE], rax
    mov qword ptr [r15 + D_EMIT_LEN], 0
    cmp rax, ROOT_OUTPUT_CAP
    ja d_complete_payload_ready
    mov [r15 + D_EMIT_LEN], rax
    mov rax, [rbx + T_OUTPUT]
    mov [r15 + D_EMIT_PTR], rax
d_complete_payload_ready:
    call d_emit
    mov rbx, [r15 + D_CURRENT]
    cmp qword ptr [rbx + T_PID], 0
    jne fatal
    cmp qword ptr [rbx + T_FD], -1
    jne fatal
    lea rdi, [r15 + D_HEAD]
d_unlink_task:
    mov rax, [rdi]
    test rax, rax
    jz fatal
    cmp rax, rbx
    je d_unlink_found
    lea rdi, [rax + T_NEXT]
    jmp d_unlink_task
d_unlink_found:
    mov rax, [rbx + T_NEXT]
    mov [rdi], rax
    mov qword ptr [r15 + D_CURRENT], 0
    mov rdi, rbx
    mov esi, D_TASK_BYTES
    mov eax, 11
    syscall
    test rax, rax
    jnz fatal
    ret

d_scan_tasks:
    mov rax, [r15 + D_HEAD]
    mov [r15 + D_SCAN], rax
d_scan_next:
    mov rbx, [r15 + D_SCAN]
    test rbx, rbx
    jz d_scan_done
    mov [r15 + D_CURRENT], rbx
    mov rax, [rbx + T_NEXT]
    mov [r15 + D_SCAN_NEXT], rax
    cmp qword ptr [r15 + D_CLOSING], 0
    je d_scan_job
    cmp qword ptr [rbx + T_DROP_SENT], 0
    jne d_scan_job
    mov qword ptr [rbx + T_DROP_SENT], 1
    mov qword ptr [r15 + D_ENTRY_KIND], 4
    mov qword ptr [r15 + D_ENTRY_LEN], 0
    lea rax, [rip + d_empty]
    mov [r15 + D_ENTRY_PTR], rax
    call d_drive
    mov rbx, [r15 + D_CURRENT]
    test rbx, rbx
    jz d_scan_advance
d_scan_job:
    cmp qword ptr [rbx + T_PID], 0
    je d_scan_future
    call d_job_progress
    jmp d_scan_advance
d_scan_future:
    mov rdx, [rbx + T_WORK]
    cmp qword ptr [rdx + 32], 0
    je d_scan_advance
    cmp qword ptr [rdx + 64], 0
    jne fatal
    mov qword ptr [r15 + D_ENTRY_KIND], 6
    mov qword ptr [r15 + D_ENTRY_LEN], 0
    lea rax, [rip + d_empty]
    mov [r15 + D_ENTRY_PTR], rax
    call d_drive
d_scan_advance:
    mov rax, [r15 + D_SCAN_NEXT]
    mov [r15 + D_SCAN], rax
    jmp d_scan_next
d_scan_done:
    mov qword ptr [r15 + D_CURRENT], 0
    ret

/* Only waitpid success can turn a submitted task into a HIA completion. */
d_job_progress:
    call d_job_drain
    mov rbx, [r15 + D_CURRENT]
d_job_wait:
    mov rdi, [rbx + T_PID]
    lea rsi, [rbx + T_WSTATUS]
    mov edx, 1 /* WNOHANG */
    xor r10d, r10d
    mov eax, 61
    syscall
    cmp rax, -4
    je d_job_wait
    test rax, rax
    jz d_job_pending
    cmp rax, [rbx + T_PID]
    jne fatal
    mov qword ptr [rbx + T_PID], 0
    call d_job_drain
    mov rbx, [r15 + D_CURRENT]
    lea rdi, [rbx + T_FD]
    call d_close_slot
    mov r14, [rbx + T_WORK]
    mov rax, [rbx + T_JOB]
    test rax, rax
    jz fatal
    cmp [r14 + 48], rax
    jne fatal
    mov [r14 + FOOTER + 128], rax
    mov qword ptr [rbx + T_JOB], 0
    mov qword ptr [r15 + D_ENTRY_KIND], 7
    mov qword ptr [r15 + D_ENTRY_LEN], 0
    lea rax, [rip + d_empty]
    mov [r15 + D_ENTRY_PTR], rax
    mov qword ptr [r14 + FOOTER + 136], 1
    cmp qword ptr [rbx + T_WSTATUS], 0
    jne d_job_deliver
    cmp qword ptr [rbx + T_GOT], 40
    jne d_job_deliver
    cmp qword ptr [rbx + T_PIPE_EOF], 1
    jne d_job_deliver
    cmp qword ptr [rbx + T_PIPE_FAIL], 0
    jne d_job_deliver
    mov qword ptr [r14 + FOOTER + 136], 0
    lea rax, [rbx + T_RESPONSE]
    mov [r15 + D_ENTRY_PTR], rax
    mov qword ptr [r15 + D_ENTRY_LEN], 40
d_job_deliver:
    call d_drive
d_job_pending:
    ret

d_job_drain:
    mov rbx, [r15 + D_CURRENT]
    cmp qword ptr [rbx + T_FD], -1
    je d_job_drain_done
    cmp qword ptr [rbx + T_PIPE_EOF], 0
    jne d_job_drain_done
    mov rcx, [rbx + T_GOT]
    cmp rcx, 40
    ja d_job_drain_done
    mov edx, 41
    sub rdx, rcx
    lea rsi, [rbx + T_RESPONSE]
    add rsi, rcx
    mov rdi, [rbx + T_FD]
    xor eax, eax
    syscall
    cmp rax, -4
    je d_job_drain
    cmp rax, -11
    je d_job_drain_done
    test rax, rax
    js d_job_read_error
    jz d_job_read_eof
    add [rbx + T_GOT], rax
    cmp qword ptr [rbx + T_GOT], 40
    ja d_job_read_error
    jmp d_job_drain
d_job_read_eof:
    mov qword ptr [rbx + T_PIPE_EOF], 1
    ret
d_job_read_error:
    mov qword ptr [rbx + T_PIPE_FAIL], 1
    lea rdi, [rbx + T_FD]
    call d_close_slot
d_job_drain_done:
    ret

d_reap_fence:
    cmp qword ptr [r15 + D_FENCE_PID], 0
    je d_fence_reap_done
d_fence_wait:
    mov rdi, [r15 + D_FENCE_PID]
    lea rsi, [r15 + D_WSTATUS]
    mov edx, 1
    xor r10d, r10d
    mov eax, 61
    syscall
    cmp rax, -4
    je d_fence_wait
    test rax, rax
    jz d_fence_reap_done
    cmp rax, [r15 + D_FENCE_PID]
    jne fatal
    mov qword ptr [r15 + D_FENCE_PID], 0
    cmp qword ptr [r15 + D_FENCE_CLOSED], 1
    jne fatal
    cmp dword ptr [r15 + D_WSTATUS], 0
    jne fatal
    lea rdi, [r15 + D_FENCE_OUT]
    call d_close_slot
d_fence_reap_done:
    ret

d_close_fence_when_unused:
    cmp qword ptr [r15 + D_FENCE_CLOSED], 0
    jne d_fence_close_done
    mov rbx, [r15 + D_HEAD]
d_find_live_permit:
    test rbx, rbx
    jz d_fence_close
    mov rdx, [rbx + T_WORK]
    mov rax, [rdx + 32]
    or rax, [rdx + 40]
    jnz d_fence_close_done
    mov rbx, [rbx + T_NEXT]
    jmp d_find_live_permit
d_fence_close:
    mov qword ptr [r15 + D_FENCE_CLOSED], 1
    lea rdi, [r15 + D_FENCE_IN]
    call d_close_slot
d_fence_close_done:
    ret

/* Fatal paths retire channels and reap only this parent's registered children. */
d_cleanup:
    push rbp
    mov rax, [r15 + D_HEAD]
    mov [r15 + D_SCAN], rax
d_cleanup_kill_tasks:
    mov rbx, [r15 + D_SCAN]
    test rbx, rbx
    jz d_cleanup_kill_fence
    mov rax, [rbx + T_NEXT]
    mov [r15 + D_SCAN], rax
    mov rdi, [rbx + T_PID]
    test rdi, rdi
    jz d_cleanup_kill_tasks
    mov esi, 9
    mov eax, 62
    syscall
    jmp d_cleanup_kill_tasks
d_cleanup_kill_fence:
    mov rdi, [r15 + D_FENCE_PID]
    test rdi, rdi
    jz d_cleanup_join_tasks
    mov esi, 9
    mov eax, 62
    syscall
d_cleanup_join_tasks:
    mov rbx, [r15 + D_HEAD]
    test rbx, rbx
    jz d_cleanup_join_fence
    cmp qword ptr [rbx + T_PID], 0
    je d_cleanup_task_joined
d_cleanup_task_wait:
    mov rdi, [rbx + T_PID]
    lea rsi, [rbx + T_WSTATUS]
    xor edx, edx
    xor r10d, r10d
    mov eax, 61
    syscall
    cmp rax, -4
    je d_cleanup_task_wait
    mov qword ptr [rbx + T_PID], 0
d_cleanup_task_joined:
    lea rdi, [rbx + T_FD]
    call d_close_slot
    mov rax, [rbx + T_NEXT]
    mov [r15 + D_HEAD], rax
    mov rdi, rbx
    mov esi, D_TASK_BYTES
    mov eax, 11
    syscall
    jmp d_cleanup_join_tasks
d_cleanup_join_fence:
    cmp qword ptr [r15 + D_FENCE_PID], 0
    je d_cleanup_channels
d_cleanup_fence_wait:
    mov rdi, [r15 + D_FENCE_PID]
    lea rsi, [r15 + D_WSTATUS]
    xor edx, edx
    xor r10d, r10d
    mov eax, 61
    syscall
    cmp rax, -4
    je d_cleanup_fence_wait
    mov qword ptr [r15 + D_FENCE_PID], 0
d_cleanup_channels:
    lea rdi, [r15 + D_FENCE_IN]
    call d_close_slot
    lea rdi, [r15 + D_FENCE_OUT]
    call d_close_slot
    lea rdi, [r15 + D_MEMFD]
    call d_close_slot
    lea rdi, [r15 + D_ERR_R]
    call d_close_slot
    lea rdi, [r15 + D_ERR_W]
    call d_close_slot
    lea rdi, [r15 + D_IN_R]
    call d_close_slot
    lea rdi, [r15 + D_OUT_W]
    call d_close_slot
    lea rdi, [r15 + D_JOB_R]
    call d_close_slot
    lea rdi, [r15 + D_JOB_W]
    call d_close_slot
    lea rdi, [r15 + D_WAKE_R]
    call d_close_slot
    lea rdi, [r15 + D_WAKE_W]
    call d_close_slot
    mov rdi, [r15 + D_PATH_WORK]
    test rdi, rdi
    jz d_cleanup_errno
    mov esi, ROOT_WCAP
    mov eax, 11
    syscall
d_cleanup_errno:
    mov rdi, [r15 + D_ERRNO_WORK]
    test rdi, rdi
    jz d_cleanup_snapshot
    mov esi, 4096
    mov eax, 11
    syscall
d_cleanup_snapshot:
    lea rdi, [r15 + D_SNAPSHOT_FD]
    call d_close_slot
    mov rdi, [r15 + D_SNAPSHOT]
    test rdi, rdi
    jz d_cleanup_done
    mov esi, D_SNAPSHOT_BYTES
    mov eax, 11
    syscall
d_cleanup_done:
    pop rbp
    ret
