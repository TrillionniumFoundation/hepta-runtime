/* Callable driver: owned response delivery cannot repeat a completed child. */
.intel_syntax noprefix
.section .text
.global batch_call_run
batch_call_run:
    push rbp
    push rbx
    push r12
    push r13
    push r14
    sub rsp, 32
    mov qword ptr [r15 + 776], 0
    mov qword ptr [rsp + 8], 2
    mov [rsp + 24], rdi
    mov r12, rsi
    mov r13, rsi
    mov edx, 128
    call batch_buffer
    test rax, rax
    js batch_run_resource
    mov rdi, [r15 + 128]
    mov rsi, [rsp + 24]
    mov rcx, r13
    rep movsb
    mov [r15 + 144], r13
batch_run_again:
    mov rdi, [r15 + 128]
    mov rsi, [r15 + 144]
    xor edx, edx
    call batch_dispatch
    mov rbx, [r15 + 8]
    cmp eax, 0xfffffffc
    je batch_run_resource
    cmp eax, 64
    jne batch_run_done
    mov rbp, [rbx + 24]
    mov rax, 0x3230305241434248
    cmp [rbp], rax
    jne batch_run_contract
    mov rax, [rbp + 40]
    add rax, 64
    jc batch_run_contract
    cmp rax, [rbx + 32]
    ja batch_run_contract
    cmp qword ptr [rbp + 56], 0
    jne batch_run_contract
    mov rax, [rbp + 8]
    cmp rax, 1
    je batch_run_child
    cmp rax, 8
    je batch_run_redelivery
    cmp rax, 7
    ja batch_run_contract
    cmp rax, 5
    je batch_run_contract
    mov eax, 64
    jmp batch_run_done
batch_run_redelivery:
    mov r13, [rbp + 40]
    cmp r13, 64
    jb batch_run_contract
    mov r12, r13
    mov edx, 128
    call batch_buffer
    test rax, rax
    js batch_run_resource
    mov rdi, [r15 + 128]
    lea rsi, [rbp + 64]
    mov rcx, r13
    rep movsb
    mov [r15 + 144], r13
    jmp batch_run_again
batch_run_child:
    mov r14, [rbp + 32]
    test r14, r14
    jz batch_run_contract
    cmp r14, 22
    jae batch_run_contract
    mov [r15 + 192], r14
    mov rax, [rbp + 16]
    mov [r15 + 176], rax
    mov rax, [rbp + 24]
    mov [r15 + 184], rax
    mov r13, [rbp + 40]
    mov r12, r13
    mov edx, 160
    call batch_buffer
    test rax, rax
    js batch_run_resource
    mov rdi, [r15 + 160]
    lea rsi, [rbp + 64]
    mov rcx, r13
    rep movsb
    mov rdi, [r15 + 160]
    mov rsi, r13
    mov edx, r14d
    cmp qword ptr [r15 + 640], 1
    jne batch_run_synchronous_child
    cmp r14d, 2
    je batch_run_async_child
    cmp r14d, 3
    je batch_run_async_child
    cmp r14d, 19
    je batch_run_async_child
batch_run_synchronous_child:
    call batch_dispatch
    mov [r15 + 200], rax
batch_run_completed_child:
    mov r14, [r15 + 192]
    mov rbx, r14
    shl rbx, 6
    add rbx, [r15 + 8]
    cmp [rbx + 40], rax
    jne batch_run_contract
    xor r13d, r13d
    cmp eax, 0xffff0000
    jae batch_run_extent_ready
    mov r13, rax
    cmp r14, 12
    je batch_run_wide_body
    cmp r14, 16
    je batch_run_wide_body
    cmp r14, 20
    je batch_run_params_body
    jmp batch_run_check_extent
batch_run_wide_body:
    cmp eax, 64
    jne batch_run_contract
    mov rcx, [rbx + 24]
    cmp qword ptr [rcx + 8], 0
    jne batch_run_check_extent
    add r13, [rcx + 16]
    jc batch_run_contract
    jmp batch_run_check_extent
batch_run_params_body:
    cmp eax, 64
    jne batch_run_contract
    mov rcx, [rbx + 24]
    cmp qword ptr [rcx + 8], 0
    jne batch_run_params_error
    add r13, [rcx + 16]
    jc batch_run_contract
    add r13, [rcx + 24]
    jc batch_run_contract
    jmp batch_run_check_extent
batch_run_params_error:
    cmp qword ptr [rcx + 8], 1
    jne batch_run_check_extent
    add r13, [rcx + 40]
    jc batch_run_contract
batch_run_check_extent:
    cmp r13, [rbx + 32]
    ja batch_run_contract
batch_run_extent_ready:
    mov [r15 + 208], r13
    mov qword ptr [rsp], 0
    cmp r14, 1
    jb batch_run_reply_size
    cmp r14, 3
    ja batch_run_reply_size
    cmp qword ptr [r15 + 200], 80
    jne batch_run_reply_size
    mov rcx, [rbx + 24]
    cmp qword ptr [rcx + 16], 2
    jne batch_run_reply_size
    cmp qword ptr [rcx + 24], 0
    jne batch_run_reply_size
    mov rax, [rcx + 64]
    mov [rsp], rax
    add r13, rax
    jc batch_run_contract
batch_run_reply_size:
    add r13, 64
    jc batch_run_contract
    mov r12, r13
    mov edx, 128
    call batch_buffer
    test rax, rax
    js batch_run_resource
    mov rbp, [r15 + 128]
    mov rax, 0x3230514c41434248
    mov [rbp], rax
    mov rax, [rsp + 8]
    mov [rbp + 8], rax
    mov qword ptr [rsp + 8], 2
    mov rax, [r15 + 176]
    mov [rbp + 16], rax
    mov rax, [r15 + 184]
    mov [rbp + 24], rax
    mov rax, [r15 + 200]
    mov [rbp + 32], rax
    lea rax, [r13 - 64]
    mov [rbp + 40], rax
    mov qword ptr [rbp + 48], 0
    mov qword ptr [rbp + 56], 0
    lea rdi, [rbp + 64]
    mov rsi, [rbx + 24]
    mov rcx, [r15 + 208]
    rep movsb
    cmp qword ptr [rsp], 0
    je batch_run_snapshot_copied
    mov rax, [rbx + 24]
    mov rsi, [rax + 56]
    add rsi, [rbx + 8]
    mov rcx, [rsp]
    rep movsb
batch_run_snapshot_copied:
    mov [r15 + 144], r13
    cmp r14, 1
    jb batch_run_child_ready
    cmp r14, 3
    ja batch_run_child_ready
    cmp qword ptr [r15 + 200], 80
    jne batch_run_child_ready
    mov edx, r14d
    call view_reader_retire
    test rax, rax
    jnz batch_run_contract
batch_run_child_ready:
    cmp qword ptr [r15 + 24], 1
    jne batch_run_again
    call batch_fixture_gate
    test rax, rax
    js batch_run_io
    test rax, rax
    jnz batch_run_contract
    jmp batch_run_again
batch_run_async_child:
    call batch_worker_start
    test rax, rax
    js batch_run_resource
    mov eax, 0xfffffff0
    jmp batch_run_done
batch_run_contract:
    mov eax, 0xfffffff8
    jmp batch_run_done
batch_run_resource:
    /* A resource failure remains a native failure, never a tool StringErr.
     * Feed one allocation-free failed child completion so HIA owns release. */
    cmp qword ptr [r15 + 648], 0
    jne batch_run_resource_terminal
    cmp qword ptr [r15 + 776], 0
    jne batch_run_resource_terminal
    mov rax, [r15 + 8]
    mov rdx, [rax + 8]
    cmp qword ptr [rdx + 8], 0
    je batch_run_resource_terminal
    cmp qword ptr [rdx + 8], 8
    je batch_run_resource_terminal
    cmp qword ptr [rdx + 8], 90
    je batch_run_resource_terminal
    cmp qword ptr [rdx + 32], 0
    je batch_run_resource_terminal
    mov rax, [r15 + 128]
    test rax, rax
    jz batch_run_resource_terminal
    mov qword ptr [r15 + 776], 1
    mov rcx, 0x3230514c41434248
    mov [rax], rcx
    mov qword ptr [rax + 8], 2
    mov rcx, [rdx + 16]
    mov [rax + 16], rcx
    mov rcx, [rdx + 24]
    mov [rax + 24], rcx
    mov ecx, 0xfffffffc
    mov [rax + 32], rcx
    mov qword ptr [rax + 40], 0
    mov qword ptr [rax + 48], 0
    mov qword ptr [rax + 56], 0
    mov qword ptr [r15 + 144], 64
    jmp batch_run_again
batch_run_resource_terminal:
    mov eax, 0xfffffffc
    jmp batch_run_done
batch_run_io:
    mov eax, 0xfffffffb
batch_run_done:
    add rsp, 32
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret

/* Resume only a kernel-reaped completion. esi=0 poll, 1 join. */
.global batch_call_resume
batch_call_resume:
    push rbp
    push rbx
    push r12
    push r13
    push r14
    sub rsp, 32
    call batch_worker_wait
    test rax, rax
    js batch_run_contract
    jz batch_run_pending
    mov rax, [r15 + 688]
    mov [r15 + 176], rax
    mov rax, [r15 + 696]
    mov [r15 + 184], rax
    mov rax, [r15 + 680]
    mov [r15 + 192], rax
    mov rax, [r15 + 672]
    mov [r15 + 200], rax
    mov qword ptr [rsp + 8], 2
    cmp qword ptr [r15 + 728], 0
    je batch_run_completed_child
    mov qword ptr [rsp + 8], 4
    jmp batch_run_completed_child
batch_run_pending:
    mov eax, 0xfffffff0
    jmp batch_run_done

/* r12 minimum bytes, edx private engine pointer/cap pair offset. */
batch_buffer:
    push rbx
    push rbp
    sub rsp, 8
    lea rbx, [r15 + rdx]
    test r12, r12
    js batch_buffer_overflow
    cmp qword ptr [rbx], 0
    jne batch_buffer_existing
    mov ebp, 4096
batch_buffer_initial_loop:
    cmp rbp, r12
    jae batch_buffer_initial_ready
    shl rbp, 1
    jc batch_buffer_overflow
    test rbp, rbp
    js batch_buffer_overflow
    jmp batch_buffer_initial_loop
batch_buffer_initial_ready:
    mov rdi, rbp
    call view_allocate
    cmp rax, -4095
    jae batch_buffer_return
    mov [rbx], rax
    mov [rbx + 8], rbp
    jmp batch_buffer_done
batch_buffer_existing:
    cmp r12, [rbx + 8]
    jbe batch_buffer_done
    mov rbp, [rbx + 8]
batch_buffer_grow_loop:
    cmp rbp, r12
    jae batch_buffer_grow_ready
    shl rbp, 1
    jc batch_buffer_overflow
    test rbp, rbp
    js batch_buffer_overflow
    jmp batch_buffer_grow_loop
batch_buffer_grow_ready:
    mov rdi, [rbx]
    mov rsi, [rbx + 8]
    mov rdx, rbp
    call view_resize
    cmp rax, -4095
    jae batch_buffer_return
    mov [rbx], rax
    mov [rbx + 8], rbp
batch_buffer_done:
    xor eax, eax
    jmp batch_buffer_return
batch_buffer_overflow:
    mov rax, -12
batch_buffer_return:
    add rsp, 8
    pop rbp
    pop rbx
    ret

/* An explicit fixture hook only; callable production installation keeps +24=0. */
batch_fixture_gate:
    sub rsp, 88
    mov qword ptr [rsp], 1
    mov rax, [r15 + 144]
    mov [rsp + 8], rax
    mov rax, 0x3230304f49434248
    mov [rsp + 16], rax
    mov rax, [r15 + 176]
    mov [rsp + 24], rax
    mov rax, [r15 + 184]
    mov [rsp + 32], rax
    mov rax, [r15 + 192]
    mov [rsp + 40], rax
    mov rax, [r15 + 200]
    mov [rsp + 48], rax
    mov rax, [r15 + 144]
    sub rax, 64
    mov [rsp + 56], rax
    mov rax, [r15 + 8]
    mov rax, [rax + 8]
    mov rax, [rax + 8]
    mov [rsp + 64], rax
    mov qword ptr [rsp + 72], 0
    mov edi, 1
    mov rsi, rsp
    mov edx, 80
    call view_write_all
    test rax, rax
    js batch_fixture_gate_return
    mov edi, 1
    mov rsi, [r15 + 128]
    add rsi, 64
    mov rdx, [r15 + 144]
    sub rdx, 64
    call view_write_all
    test rax, rax
    js batch_fixture_gate_return
    xor edi, edi
    lea rsi, [rsp + 16]
    mov edx, 32
    call view_read_all
    cmp rax, 1
    jne batch_fixture_gate_failed
    mov rax, 0x32304b4341434248
    cmp [rsp + 16], rax
    jne batch_fixture_gate_failed
    mov rax, [r15 + 176]
    cmp [rsp + 24], rax
    jne batch_fixture_gate_failed
    mov rax, [r15 + 184]
    cmp [rsp + 32], rax
    jne batch_fixture_gate_failed
    cmp qword ptr [rsp + 40], 0
    jne batch_fixture_gate_failed
    xor eax, eax
    jmp batch_fixture_gate_return
batch_fixture_gate_failed:
    mov rax, -22
batch_fixture_gate_return:
    add rsp, 88
    ret
