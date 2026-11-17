/* Copyright 2026 Muvon Un Limited
 * SPDX-License-Identifier: Apache-2.0
 * Fixed private direct futures. No SDK JSON or production selector is added.
 */
.intel_syntax noprefix
.section .text
.equ PD_STATE,280
.equ PD_TAG,288
.equ PD_RAW,296
.equ PD_POLLS,304
.equ PD_BLOCK_JOB,2688
.equ PD_BLOCK_STATE,2696
.equ PD_BLOCK_TAG,0x100000000
.equ PD_BLOCK_OUT,2728
.equ PD_BLOCK_BORROW,3152

/* New fixed private commands6..11 only. The complete ordinary0..5 path is
 * retained by the author. r12/15 already identify the selected real session. */
direct_control:
    cmp rax,6
    je pd_control_start
    cmp rax,7
    je pd_control_drop
    cmp rax,8
    je pd_control_join
    cmp rax,9
    je pd_control_unpolled
    cmp rax,10
    je pd_control_blocker
    cmp rax,11
    je pd_control_release_blocker
    jmp public_span_fail
pd_input_admit:
    cmp qword ptr [r13+DC_ARG0],0
    je public_span_fail
    cmp qword ptr [r13+DC_ARG1],0
    jne public_span_fail
    cmp qword ptr [r13+DC_LENGTH],64
    jb public_span_fail
    cmp qword ptr [r12+DF_DIRECT],0
    jne public_span_fail
    ret
pd_control_start:
    call pd_input_admit
    mov edi,4096
    call view_allocate
    cmp rax,-4095
    jae public_span_fail
    mov rbp,rax
    mov [r12+DF_DIRECT],rax
    mov rax,0x31304e5452505248 /* HRPRTN01 private storage, no SDK generation. */
    mov [rbp],rax
    mov [rbp+PN_ENGINE],r15
    mov rax,[r13+DC_SEQUENCE]
    mov [rbp+PN_HOST_GENERATION],rax
    mov rax,[r13+DC_ARG0]
    mov [rbp+PD_TAG],rax
    mov rdi,[r13+DC_LENGTH]
    mov [rbp+PN_INPUT_LENGTH],rdi
    mov [rbp+PN_INPUT_CAPACITY],rdi
    call view_allocate
    cmp rax,-4095
    jae public_span_fail
    mov [rbp+PN_INPUT],rax
    mov rdi,rax
    mov rsi,[r13+DC_SCRATCH]
    mov rcx,[r13+DC_LENGTH]
    rep movsb
    mov rdi,[rbp+PN_INPUT]
    mov rsi,[rbp+PN_INPUT_LENGTH]
    mov r8d,64
    call runtime_grow_owned
    inc qword ptr [rbp+PD_POLLS]
    call direct_detach_result
    jmp df_control_reply
pd_empty_admit:
    cmp qword ptr [r13+DC_LENGTH],0
    jne public_span_fail
    cmp qword ptr [r13+DC_ARG1],0
    jne public_span_fail
    mov rbp,[r12+DF_DIRECT]
    test rbp,rbp
    jz public_span_fail
    mov rax,[r13+DC_ARG0]
    cmp [rbp+PD_TAG],rax
    jne public_span_fail
    ret
pd_control_drop:
    call pd_empty_admit
    cmp qword ptr [rbp+PD_STATE],1
    jne public_span_fail
    mov r9d,3
    call direct_resume
    cmp qword ptr [rbp+PD_STATE],3
    jne public_span_fail
    call direct_reply_result
    jmp df_control_reply
pd_control_join:
    call pd_empty_admit
pd_join_loop:
    cmp qword ptr [rbp+PD_STATE],2
    je pd_join_ready
    cmp qword ptr [rbp+PD_STATE],1
    jne public_span_fail
    call duplex_drive_all
    mov rdi,[r13+DC_SESSION]
    mov rsi,r13
    call duplex_select
    mov rbp,[r12+DF_DIRECT]
    test rbp,rbp
    jz public_span_fail
    cmp qword ptr [rbp+PD_STATE],1
    jne pd_join_loop
    call duplex_pause
    jmp pd_join_loop
pd_join_ready:
    call direct_reply_result
    jmp df_control_reply
pd_control_unpolled:
    call pd_input_admit
    /* Copy the real future input into owned storage and destroy it without
     * any gateway entry, preserving the unpolled-future boundary. */
    mov rdi,[r13+DC_LENGTH]
    call view_allocate
    cmp rax,-4095
    jae public_span_fail
    mov rbp,rax
    mov rdi,rax
    mov rsi,[r13+DC_SCRATCH]
    mov rcx,[r13+DC_LENGTH]
    rep movsb
    mov rdi,rbp
    mov rsi,[r13+DC_LENGTH]
    add rsi,4096
    jc public_span_fail
    mov eax,11
    syscall
    test rax,rax
    jnz public_span_fail
    jmp df_control_reply

/* Pump each independent real direct future once, with no completion invented. */
direct_tick:
    PM_SAVE
    mov rbp,[r12+DF_DIRECT]
    test rbp,rbp
    jz pd_tick_done
    cmp qword ptr [rbp+PD_STATE],1
    jne pd_tick_done
    mov r9d,2
    call direct_resume
pd_tick_done:
    PM_RETURN

/* r9 is exclusively the private host's actual poll2/drop3 command. */
direct_resume:
    sub rsp,24
    mov [rsp],r9
    cmp qword ptr [rbp+PN_OWNERSHIP],3
    jne public_span_fail
    mov rdi,rbp
    call pump_publication_restore
    mov rdi,rbp
    call pump_fence_restore
    mov rdi,rbp
    call pump_scope_restore
    mov qword ptr [rbp+PN_OWNERSHIP],0
    mov rdi,[rbp+PN_INPUT]
    mov rsi,[rbp+PN_INPUT_LENGTH]
    mov r8d,64
    mov r9,[rsp]
    call runtime_grow_suspended
    inc qword ptr [rbp+PD_POLLS]
    call direct_detach_result
    add rsp,24
    ret

/* Store actual root result before moving all real child/Scope/fence mappings. */
direct_detach_result:
    sub rsp,24
    mov [rsp],rax
    mov rdx,[r15+8]
    add rdx,64*64
    cmp [rdx+48],rax
    jne public_span_fail
    mov [rbp+PD_RAW],rax
    cmp eax,0xffffffdf
    je pd_detach_pending
    cmp eax,32
    jne public_span_fail
    mov qword ptr [rbp+PN_P_ACTIVE],0
    mov rax,[r15+8]
    mov rax,[rax+67*64+8]
    test rax,rax
    jz public_span_fail
    mov rax,[rax+PA_STAGE]
    cmp rax,2
    je pd_detach_returned
    cmp rax,3
    jne public_span_fail
    mov qword ptr [rbp+PD_STATE],3
    jmp pd_detach_copy_root
pd_detach_returned:
    mov qword ptr [rbp+PD_STATE],2
    jmp pd_detach_copy_root
pd_detach_pending:
    mov qword ptr [rbp+PD_STATE],1
    mov qword ptr [rbp+PN_P_ACTIVE],1
pd_detach_copy_root:
    lea rdi,[rbp+PN_DESCRIPTOR]
    mov rsi,rdx
    mov ecx,8
    rep movsq
    lea rdi,[rbp+PN_CONTINUATION]
    lea rsi,[r15+512+64*64]
    mov ecx,8
    rep movsq
    mov rdi,rbp
    call pump_publication_detach
    mov rdi,rbp
    call pump_fence_detach
    mov rdi,rbp
    call pump_scope_detach
    mov qword ptr [rbp+PN_OWNERSHIP],3
    call direct_trace
    mov rdi,rbp
    call duplex_observe_future
    mov rdi,rbp
    call pump_publication_release_scope_loan
    add rsp,24
    ret

/* A separate tag26 says direct-call storage: it is never a public root18
 * admission or SDK request-registry observation. Whole maps follow unchanged. */
direct_trace:
    PM_SAVE
    call pump_trace_clear_tail
    mov rax,[rbp+PN_DESCRIPTOR+32]
    mov [r12+PM_TRACE_C_PTR],rax
    mov rax,[rbp+PN_DESCRIPTOR+56]
    mov [r12+PM_TRACE_C_LEN],rax
    mov edi,26
    mov rsi,rbp
    mov rdx,[rbp+PN_INPUT]
    mov rcx,[rbp+PN_INPUT_LENGTH]
    mov r8,rbp
    mov r9d,4096
    call pump_trace_emit
    mov rdi,rbp
    call pump_trace_publication
    PM_RETURN

direct_reply_result:
    mov rax,[rbp+PN_P_DESCRIPTORS+48]
    cmp rax,32
    jne public_span_fail
    mov rdx,[rbp+PN_P_DESCRIPTORS+32]
    mov rax,0x31304d4746435248
    cmp [rdx],rax
    jne public_span_fail
    cmp qword ptr [rdx+8],2
    ja public_span_fail
    cmp qword ptr [rdx+16],0
    jne public_span_fail
    mov rax,[rdx+24]
    add rax,32
    jc public_span_fail
    cmp [rbp+PN_P_DESCRIPTORS+56],rax
    jne public_span_fail
    cmp rax,[rbp+PN_P_DESCRIPTORS+40]
    ja public_span_fail
    mov [r13+DC_OUTPUT],rdx
    mov [r13+DC_OUTPUT_LENGTH],rax
    ret

/* Invoked only after the entire direct join/drop FD5 output is acknowledged
 * by a successful actual write, before the next private control is read. */
direct_after_reply:
    PM_SAVE
    mov r13,[r12+DF_CO]
    mov rax,[r13+DC_OPERATION]
    cmp rax,7
    je pd_retire
    cmp rax,8
    jne pd_after_done
pd_retire:
    mov rbp,[r12+DF_DIRECT]
    test rbp,rbp
    jz public_span_fail
    cmp qword ptr [rbp+PD_STATE],2
    jb public_span_fail
    cmp qword ptr [rbp+PD_STATE],3
    ja public_span_fail
    call direct_trace
    mov rdi,rbp
    call pump_publication_retire
    mov rdi,[rbp+PN_INPUT]
    mov rsi,[rbp+PN_INPUT_CAPACITY]
    add rsi,4096
    jc public_span_fail
    mov eax,11
    syscall
    test rax,rax
    jnz public_span_fail
    mov rdi,rbp
    mov esi,8192
    mov eax,11
    syscall
    test rax,rax
    jnz public_span_fail
    mov qword ptr [r12+DF_DIRECT],0
pd_after_done:
    PM_RETURN

/* The queue-capacity fixture uses a real auxiliary blocking body. It owns
 * no public handler and is wholly outside both observed application roots. */
pd_control_blocker:
    cmp qword ptr [r13+DC_ARG0],0
    jne public_span_fail
    cmp qword ptr [r13+DC_ARG1],0
    jne public_span_fail
    cmp qword ptr [r13+DC_LENGTH],64
    jb public_span_fail
    cmp qword ptr [r13+PD_BLOCK_STATE],0
    jne public_span_fail
    mov rax,[r13+DC_HUB]
    cmp qword ptr [rax+216],0
    jne public_span_fail
    mov edi,1
    xor esi,esi
    xor edx,edx
    call runtime_publication_worker_create
    cmp rax,-4095
    jae public_span_fail
    test rax,rax
    jz public_span_fail
    mov rdx,[r13+DC_HUB]
    mov [rdx+216],rax
    mov rdi,rax
    mov rsi,[r13+DC_SCRATCH]
    mov rdx,[r13+DC_LENGTH]
    mov rcx,PD_BLOCK_TAG
    lea r8,[r13+PD_BLOCK_OUT]
    call publication_worker_submit
    cmp eax,320
    jne public_span_fail
    cmp qword ptr [r13+PD_BLOCK_OUT+16],0
    jne public_span_fail
    mov rax,[r13+PD_BLOCK_OUT+32]
    test rax,rax
    jz public_span_fail
    mov [r13+PD_BLOCK_JOB],rax
    mov qword ptr [r13+PD_BLOCK_STATE],1
    mov rax,[r13+DC_HUB]
    mov rdi,[rax+216]
    mov rsi,[r13+PD_BLOCK_JOB]
    lea rdx,[r13+PD_BLOCK_OUT]
    call publication_worker_poll
    cmp eax,320
    jne public_span_fail
    cmp qword ptr [r13+PD_BLOCK_OUT+16],2
    jne public_span_fail
    jmp df_control_reply
pd_control_release_blocker:
    mov rax,[r13+DC_ARG0]
    or rax,[r13+DC_ARG1]
    or rax,[r13+DC_LENGTH]
    jnz public_span_fail
    cmp qword ptr [r13+PD_BLOCK_STATE],1
    jne public_span_fail
pd_blocker_wait:
    mov rax,[r13+DC_HUB]
    mov rdi,[rax+216]
    mov rsi,[r13+PD_BLOCK_JOB]
    lea rdx,[r13+PD_BLOCK_OUT]
    call publication_worker_poll
    cmp eax,320
    jne public_span_fail
    cmp qword ptr [r13+PD_BLOCK_OUT+16],0
    je pd_blocker_take
    cmp qword ptr [r13+PD_BLOCK_OUT+16],2
    jne public_span_fail
    call duplex_drive_all
    call duplex_pause
    jmp pd_blocker_wait
pd_blocker_take:
    mov rax,[r13+DC_HUB]
    mov rdi,[rax+216]
    mov rsi,[r13+PD_BLOCK_JOB]
    lea rdx,[r13+PD_BLOCK_OUT]
    lea rcx,[r13+PD_BLOCK_BORROW]
    call publication_worker_take
    cmp eax,320
    jne public_span_fail
    cmp qword ptr [r13+PD_BLOCK_OUT+16],0
    jne public_span_fail
    mov rax,[r13+PD_BLOCK_BORROW+16]
    cmp [r13+PD_BLOCK_JOB],rax
    jne public_span_fail
    mov rax,PD_BLOCK_TAG
    cmp [r13+PD_BLOCK_BORROW+48],rax
    jne public_span_fail
    mov rdx,[r13+PD_BLOCK_BORROW+32]
    mov rax,0x3130305342505448
    cmp [rdx],rax
    jne public_span_fail
    cmp qword ptr [rdx+8],0
    jne public_span_fail
    mov rax,[r13+DC_HUB]
    mov rdi,[rax+216]
    mov rsi,[r13+PD_BLOCK_JOB]
    call publication_worker_release
    test eax,eax
    jnz public_span_fail
    mov qword ptr [r13+PD_BLOCK_STATE],2
    jmp df_control_reply

direct_finalize_admit:
    mov rax,[r13+DC_PM0]
    cmp qword ptr [rax+DF_DIRECT],0
    jne public_span_fail
    mov rax,[r13+DC_PM1]
    cmp qword ptr [rax+DF_DIRECT],0
    jne public_span_fail
    cmp qword ptr [r13+PD_BLOCK_STATE],1
    je public_span_fail
    ret
