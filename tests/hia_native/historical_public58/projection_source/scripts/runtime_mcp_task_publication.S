/* Copyright 2026 Muvon Un Limited
 * SPDX-License-Identifier: Apache-2.0
 * One actual publisher await owns fixed rows64..68. The process hub owns
 * the blocking executor; no worker pointer, operation or job is public input.
 */
.intel_syntax noprefix
.section .text
.equ PP_MASK,31
.equ PP_OWNED,7

/* Return0=settled,1=extract WAIT,2=publisher await; reject mixed ownership. */
pump_waiting_kind:
    mov rax,[rbp+PN_X_ACTIVE]
    cmp rax,1
    ja public_span_fail
    mov rdx,[rbp+PN_P_ACTIVE]
    cmp rdx,1
    ja public_span_fail
    test rax,rax
    jz pp_kind_publisher
    test rdx,rdx
    jnz public_span_fail
    ret
pp_kind_publisher:
    lea rax,[rdx+rdx]
    ret
pump_waiting_context:
    sub rsp,8
    call pump_waiting_kind
    cmp eax,1
    je pp_context_extract
    cmp eax,2
    jne public_span_fail
    mov rax,[rbp+PN_P_CONTEXT]
    jmp pp_context_done
pp_context_extract:
    mov rax,[rbp+PN_X_CONTEXT]
pp_context_done:
    test rax,rax
    jz public_span_fail
    add rsp,8
    ret

pump_publication_detach:
    PM_SAVE
    mov rbp,rdi
    mov rax,[rbp+PN_P_CONTEXT]
    or rax,[rbp+PN_P_WORKMAP]
    or rax,[rbp+PN_P_OUTMAP]
    jnz public_span_fail
    mov r13,[r15+8]
    add r13,64*64
    mov rax,[r13+3*64+8]
    test rax,rax
    jnz pp_detach_context
    cmp qword ptr [rbp+PN_P_ACTIVE],0
    jne public_span_fail
    jmp pp_detach_done
pp_detach_context:
    mov r14,rax
    mov rax,PA_MAGIC
    cmp [r14],rax
    jne public_span_fail
    cmp qword ptr [r14+8],4096
    jne public_span_fail
    cmp [r14+16],r15
    jne public_span_fail
    mov rax,[r15+400]
    cmp [r14+24],rax
    jne public_span_fail
    mov rax,[rax+216]
    cmp [r14+PA_POOL],rax
    jne public_span_fail
    cmp qword ptr [r14+PA_JOB],0
    je public_span_fail
    cmp qword ptr [r14+PA_TAG],0
    je public_span_fail
    cmp qword ptr [rbp+PN_P_ACTIVE],1
    je pp_detach_wait
    cmp qword ptr [rbp+PN_P_ACTIVE],0
    jne public_span_fail
    cmp qword ptr [r14+PA_STAGE],2
    je pp_detach_admitted
    cmp qword ptr [r14+PA_STAGE],3
    jne public_span_fail
    jmp pp_detach_admitted
pp_detach_wait:
    cmp qword ptr [r14+PA_STAGE],1
    jne public_span_fail
pp_detach_admitted:
    mov rax,[r14+PA_NODE]
    test rax,rax
    jz pp_detach_bind
    cmp rax,rbp
    jne public_span_fail
pp_detach_bind:
    mov [r14+PA_NODE],rbp
    mov [rbp+PN_P_CONTEXT],r14
    mov rax,[r14+PA_JOB]
    mov [rbp+PN_P_JOB],rax
    mov rax,[r14+PA_TAG]
    mov [rbp+PN_P_TAG],rax
    mov rax,[r15+RG_WORK_HIGH]
    and eax,PP_MASK
    cmp eax,PP_OWNED
    jne public_span_fail
    mov [rbp+PN_P_WORKMAP],rax
    mov rax,[r15+RG_OUTPUT_HIGH]
    and eax,PP_MASK
    cmp eax,PP_OWNED
    jne public_span_fail
    mov [rbp+PN_P_OUTMAP],rax
    lea r14,[r15+512+64*64]
    xor ebx,ebx
pp_detach_slot:
    cmp qword ptr [rbp+PN_P_ACTIVE],0
    je pp_detach_idle
    cmp ebx,1
    je pp_detach_idle
    cmp ebx,4
    je pp_detach_idle
    cmp qword ptr [r14],1
    jne public_span_fail
    cmp ebx,3
    je pp_detach_body
    cmp qword ptr [r14+8],2
    jne public_span_fail
    mov eax,0xffffffdf
    cmp [r14+48],rax
    jne public_span_fail
    cmp qword ptr [r14+56],0
    jne public_span_fail
    jmp pp_detach_wait_result
pp_detach_body:
    cmp qword ptr [r14+8],0
    jne public_span_fail
pp_detach_wait_result:
    mov eax,0xffffffdf
    cmp [r13+48],rax
    jne public_span_fail
    cmp qword ptr [r13+56],0
    jne public_span_fail
    jmp pp_detach_copy
pp_detach_idle:
    mov rax,[r14]
    or rax,[r14+8]
    jnz public_span_fail
pp_detach_copy:
    mov rax,rbx
    shl rax,6
    lea rdi,[rbp+rax+PN_P_DESCRIPTORS]
    mov rsi,r13
    mov ecx,8
    rep movsq
    mov rax,rbx
    shl rax,6
    lea rdi,[rbp+rax+PN_P_CONTINUATIONS]
    mov rsi,r14
    mov ecx,8
    rep movsq
    lea rdi,[r13+8]
    xor eax,eax
    mov ecx,7
    rep stosq
    mov rdi,r14
    mov ecx,8
    rep stosq
    add r13,64
    add r14,64
    inc ebx
    cmp ebx,5
    jb pp_detach_slot
    and qword ptr [r15+RG_WORK_HIGH],-32
    and qword ptr [r15+RG_OUTPUT_HIGH],-32
pp_detach_done:
    PM_RETURN

/* Retire the completed caller's temporary Scope68 alias after its full
 * detached observation, while the owning Scope6 still exists. The HIA caller
 * has already consumed its reply and closed the Scope. This alias owns no
 * mapping; a later request may legitimately retire that closed Scope6 pair.
 * Pending callers retain their unchanged descriptor/continuation ownership. */
pump_publication_release_scope_loan:
    PM_SAVE
    mov rbp,rdi
    cmp qword ptr [rbp+PN_P_CONTEXT],0
    je pp_loan_done
    cmp qword ptr [rbp+PN_P_ACTIVE],1
    je pp_loan_done
    cmp qword ptr [rbp+PN_P_ACTIVE],0
    jne public_span_fail
    cmp qword ptr [rbp+PN_OWNERSHIP],3
    jne public_span_fail
    mov rax,[rbp+PN_S_OWNERSHIP]
    or rax,[rbp+PN_S_VIEW]
    jnz public_span_fail
    cmp qword ptr [rbp+PN_P_WORKMAP],PP_OWNED
    jne public_span_fail
    cmp qword ptr [rbp+PN_P_OUTMAP],PP_OWNED
    jne public_span_fail
    lea rbx,[rbp+PN_P_DESCRIPTORS+4*64]
    lea rdi,[rbp+PN_P_CONTINUATIONS+4*64]
    xor eax,eax
    mov ecx,8
    repe scasq
    jne public_span_fail
    cmp qword ptr [rbx],0
    jne public_span_fail
    cmp qword ptr [rbx+8],0
    jne pp_loan_present
    lea rdi,[rbx+8]
    mov ecx,7
    repe scasq
    jne public_span_fail
    jmp pp_loan_done
pp_loan_present:
    mov r13,[r15+16]
    test r13,r13
    jz public_span_fail
    cmp qword ptr [r13+32],0
    jne public_span_fail
    mov r13,[r13+8]
    add r13,6*64
    call pump_scope_admit_row_for_loan
    mov rax,[r13+8]
    cmp [rbx+8],rax
    jne public_span_fail
    mov rdx,0x3130545343535248 /* HRSCST01 */
    cmp [rax],rdx
    jne public_span_fail
    cmp qword ptr [rax+8],1
    jne public_span_fail
    mov rdx,[rax+24]
    or rdx,[rax+64]
    jnz public_span_fail
    mov rax,[r13+16]
    cmp [rbx+16],rax
    jne public_span_fail
    cmp qword ptr [rbx+24],0
    jne public_span_fail
    mov rax,[r13+24]
    cmp [rbx+32],rax
    jne public_span_fail
    cmp qword ptr [rbx+40],96
    jne public_span_fail
    cmp qword ptr [r13+32],96
    jb public_span_fail
    mov rax,[rbx+48]
    mov edx,eax
    cmp rax,rdx
    jne public_span_fail
    cmp eax,0xffff0000
    jae pp_loan_error
    cmp eax,96
    jne public_span_fail
    cmp qword ptr [rbx+56],96
    jne public_span_fail
    jmp pp_loan_clear
pp_loan_error:
    cmp qword ptr [rbx+56],0
    jne public_span_fail
pp_loan_clear:
    lea rdi,[rbx+8]
    xor eax,eax
    mov ecx,7
    rep stosq
pp_loan_done:
    PM_RETURN

/* Preserve the existing Scope-row admission with its actual row in rbx. */
pump_scope_admit_row_for_loan:
    push rbx
    mov rbx,r13
    call pump_scope_admit_row
    pop rbx
    ret

/* Only settled, already copied aliases may be cleared for restoration. */
pump_publication_clear_idle:
    PM_SAVE
    mov r13,[r15+8]
    add r13,64*64
    lea r14,[r15+512+64*64]
    xor ebx,ebx
pp_idle_slot:
    mov rax,[r14]
    or rax,[r14+8]
    jnz public_span_fail
    cmp ebx,3
    jne pp_idle_work
    mov rax,[r13+8]
    or rax,[r13+16]
    or rax,[r13+32]
    or rax,[r13+40]
    jnz public_span_fail
pp_idle_work:
    bt qword ptr [r15+RG_WORK_HIGH],rbx
    jnc pp_idle_output
    cmp ebx,3
    jae public_span_fail
    mov rdi,[r13+8]
    test rdi,rdi
    jz public_span_fail
    mov rsi,[r13+16]
    test rsi,rsi
    jz public_span_fail
    add rsi,4096
    jc public_span_fail
    mov eax,11
    syscall
    test rax,rax
    jnz public_span_fail
    btr qword ptr [r15+RG_WORK_HIGH],rbx
pp_idle_output:
    bt qword ptr [r15+RG_OUTPUT_HIGH],rbx
    jnc pp_idle_clear
    cmp ebx,3
    jae public_span_fail
    mov rdi,[r13+32]
    test rdi,rdi
    jz public_span_fail
    mov rsi,[r13+40]
    test rsi,rsi
    jz public_span_fail
    add rsi,4096
    jc public_span_fail
    mov eax,11
    syscall
    test rax,rax
    jnz public_span_fail
    btr qword ptr [r15+RG_OUTPUT_HIGH],rbx
pp_idle_clear:
    lea rdi,[r13+8]
    xor eax,eax
    mov ecx,7
    rep stosq
    mov rdi,r14
    mov ecx,8
    rep stosq
    add r13,64
    add r14,64
    inc ebx
    cmp ebx,5
    jb pp_idle_slot
    PM_RETURN

pump_publication_restore:
    PM_SAVE
    mov rbp,rdi
    mov rax,[rbp+PN_P_CONTEXT]
    test rax,rax
    jnz pp_restore_present
    cmp qword ptr [rbp+PN_P_ACTIVE],0
    jne public_span_fail
    jmp pp_restore_done
pp_restore_present:
    cmp qword ptr [rbp+PN_P_ACTIVE],1
    jne public_span_fail
    cmp [rax+PA_NODE],rbp
    jne public_span_fail
    cmp [rax+16],r15
    jne public_span_fail
    cmp qword ptr [rax+PA_STAGE],1
    jne public_span_fail
    mov rcx,[rbp+PN_P_JOB]
    cmp [rax+PA_JOB],rcx
    jne public_span_fail
    mov rcx,[rbp+PN_P_TAG]
    cmp [rax+PA_TAG],rcx
    jne public_span_fail
    cmp qword ptr [rbp+PN_P_WORKMAP],PP_OWNED
    jne public_span_fail
    cmp qword ptr [rbp+PN_P_OUTMAP],PP_OWNED
    jne public_span_fail
    call pump_publication_clear_idle
    mov r13,[r15+8]
    add r13,64*64
    lea r14,[r15+512+64*64]
    xor ebx,ebx
pp_restore_slot:
    mov rax,rbx
    shl rax,6
    lea rsi,[rbp+rax+PN_P_DESCRIPTORS]
    mov rax,[rsi]
    cmp [r13],rax
    jne public_span_fail
    mov rdi,r13
    mov ecx,8
    rep movsq
    mov rax,rbx
    shl rax,6
    lea rsi,[rbp+rax+PN_P_CONTINUATIONS]
    mov rdi,r14
    mov ecx,8
    rep movsq
    add r13,64
    add r14,64
    inc ebx
    cmp ebx,5
    jb pp_restore_slot
    mov rax,[rbp+PN_P_WORKMAP]
    or [r15+RG_WORK_HIGH],rax
    mov rax,[rbp+PN_P_OUTMAP]
    or [r15+RG_OUTPUT_HIGH],rax
    mov qword ptr [rbp+PN_P_CONTEXT],0
    mov qword ptr [rbp+PN_P_WORKMAP],0
    mov qword ptr [rbp+PN_P_OUTMAP],0
pp_restore_done:
    PM_RETURN

pump_publication_pending:
    PM_SAVE
    mov rbp,rdi
    cmp qword ptr [rbp+PN_P_ACTIVE],1
    jne public_span_fail
    cmp qword ptr [rbp+PN_OWNERSHIP],3
    jne public_span_fail
    cmp qword ptr [rbp+PN_GENERATION],0
    je public_span_fail
    cmp qword ptr [rbp+PN_BOOTSTRAP],0
    jne public_span_fail
    mov rax,[rbp+PN_P_CONTEXT]
    test rax,rax
    jz public_span_fail
    cmp [rax+PA_NODE],rbp
    jne public_span_fail
    cmp qword ptr [rax+PA_STAGE],1
    jne public_span_fail
    cmp qword ptr [rbp+PN_CONTINUATION],1
    jne public_span_fail
    cmp qword ptr [rbp+PN_CONTINUATION+8],2
    jne public_span_fail
    cmp qword ptr [rbp+PN_CONTINUATION+24],64
    jne public_span_fail
    mov eax,0xffffffdf
    cmp [rbp+PN_DESCRIPTOR+48],rax
    jne public_span_fail
    cmp qword ptr [rbp+PN_DESCRIPTOR+56],0
    jne public_span_fail
    mov rax,[rbp+PN_DESCRIPTOR+24]
    test rax,rax
    jz public_span_fail
    cmp [rbp+PN_CONTINUATION+16],rax
    jne public_span_fail
    cmp qword ptr [rbp+PN_STATE],1
    je pp_pending_existing
    cmp qword ptr [rbp+PN_STATE],0
    jne public_span_fail
    mov [rbp+PN_SEQUENCE],rax
    mov qword ptr [rbp+PN_STATE],1
    inc qword ptr [r12+PM_PENDING]
    jz public_span_fail
    jmp pp_pending_done
pp_pending_existing:
    cmp [rbp+PN_SEQUENCE],rax
    jne public_span_fail
pp_pending_done:
    mov qword ptr [rbp+PN_KIND],6 /* Real raw WAIT, never a JSON response. */
    mov qword ptr [rbp+PN_EXTENT],0
    PM_RETURN

pump_resume_publication:
    PM_SAVE
    mov rbp,rdi
    mov r13,rsi
    cmp qword ptr [rbp+PN_P_ACTIVE],1
    jne public_span_fail
    cmp r13,2
    je pp_resume_poll
    cmp r13,3
    jne public_span_fail
    cmp qword ptr [r12+PM_PHASE],3
    jb public_span_fail
    cmp qword ptr [rbp+PN_FUTURE_DROPPED],1
    jne public_span_fail
    jmp pp_resume_install
pp_resume_poll:
    cmp qword ptr [r12+PM_PHASE],3
    jae public_span_fail
pp_resume_install:
    mov rdi,rbp
    call pump_restore_frontend
    mov [r12+PM_CURRENT],rbp
    mov rdi,[rbp+PN_INPUT]
    mov rsi,[rbp+PN_INPUT_LENGTH]
    mov r8d,18
    mov r9,r13
    call runtime_grow_suspended
    cmp eax,0xffffffdf
    je pp_resume_wait
    cmp eax,64
    jne public_span_fail
    mov qword ptr [rbp+PN_P_ACTIVE],0
    cmp qword ptr [r12+PM_PENDING],0
    je public_span_fail
    dec qword ptr [r12+PM_PENDING]
    jmp pp_resume_detach
pp_resume_wait:
    cmp r13,2
    jne public_span_fail
pp_resume_detach:
    mov rdi,rbp
    call pump_detach_frontend
    mov rdi,rbp
    call pump_handle_frontend
    mov qword ptr [r12+PM_CURRENT],0
    PM_RETURN

/* Advance actual clone/reap and poll HIA job completion. A poll timeout never
 * supplies a fabricated completion or advances the caller's await. */
pump_service_publication:
    PM_SAVE
    mov rax,[r15+400]
    test rax,rax
    jz pp_service_done
    mov rdi,[rax+216]
    test rdi,rdi
    jz pp_service_done
    call publication_worker_service
    test eax,eax
    jnz public_span_fail
    cmp qword ptr [r12+PM_PHASE],3
    jae pp_service_done
    mov rbp,[r12+PM_ALL]
pp_service_next:
    test rbp,rbp
    jz pp_service_done
    mov r14,[rbp+PN_NEXT]
    cmp qword ptr [rbp+PN_STATE],1
    jne pp_service_advance
    cmp qword ptr [rbp+PN_P_ACTIVE],1
    jne pp_service_advance
    mov r13,[rbp+PN_P_CONTEXT]
    test r13,r13
    jz public_span_fail
    cmp [r13+PA_NODE],rbp
    jne public_span_fail
    cmp qword ptr [r13+PA_STAGE],1
    jne public_span_fail
    mov rdi,[r13+PA_POOL]
    mov rsi,[r13+PA_JOB]
    lea rdx,[r13+PA_OUT]
    call publication_worker_poll
    cmp eax,320
    jne public_span_fail
    cmp qword ptr [r13+PA_OUT+16],2
    je pp_service_advance
    cmp qword ptr [r13+PA_OUT+16],0
    jne public_span_fail
    mov rdi,rbp
    mov esi,2
    call pump_resume_node
pp_service_advance:
    mov rbp,r14
    jmp pp_service_next
pp_service_done:
    PM_RETURN

pump_publication_retire:
    PM_SAVE
    mov rbp,rdi
    cmp qword ptr [rbp+PN_P_ACTIVE],0
    jne public_span_fail
    mov rdi,[rbp+PN_P_CONTEXT]
    test rdi,rdi
    jz pp_retire_done
    cmp qword ptr [rbp+PN_P_WORKMAP],PP_OWNED
    jne public_span_fail
    cmp qword ptr [rbp+PN_P_OUTMAP],PP_OWNED
    jne public_span_fail
    cmp [rdi+PA_NODE],rbp
    jne public_span_fail
    call runtime_publication_body_release_context
    test eax,eax
    jnz public_span_fail
    mov qword ptr [rbp+PN_P_CONTEXT],0
    xor ebx,ebx
    lea r13,[rbp+PN_P_DESCRIPTORS]
    lea r14,[rbp+PN_P_CONTINUATIONS]
pp_retire_slot:
    mov rax,[r14]
    or rax,[r14+8]
    jnz public_span_fail
    cmp ebx,4
    jne pp_retire_owned_or_context
    /* No stale Scope borrow may survive its completed detach boundary. */
    lea rdi,[r13+8]
    xor eax,eax
    mov ecx,7
    repe scasq
    jne public_span_fail
    jmp pp_retire_advance
pp_retire_owned_or_context:
    cmp ebx,3
    jae pp_retire_advance
    mov rdi,[r13+8]
    test rdi,rdi
    jz public_span_fail
    mov rsi,[r13+16]
    test rsi,rsi
    jz public_span_fail
    add rsi,4096
    jc public_span_fail
    mov eax,11
    syscall
    test rax,rax
    jnz public_span_fail
    mov rdi,[r13+32]
    test rdi,rdi
    jz public_span_fail
    mov rsi,[r13+40]
    test rsi,rsi
    jz public_span_fail
    add rsi,4096
    jc public_span_fail
    mov eax,11
    syscall
    test rax,rax
    jnz public_span_fail
pp_retire_advance:
    add r13,64
    add r14,64
    inc ebx
    cmp ebx,5
    jb pp_retire_slot
    mov qword ptr [rbp+PN_P_WORKMAP],0
    mov qword ptr [rbp+PN_P_OUTMAP],0
pp_retire_done:
    PM_RETURN

pump_publication_close:
    sub rsp,8
    mov rax,[r15+400]
    test rax,rax
    jz pp_close_empty
    mov rdi,[rax+216]
    test rdi,rdi
    jz pp_close_empty
    call publication_worker_close
    test eax,eax
    jnz public_span_fail
pp_close_empty:
    add rsp,8
    ret

/* Return0 after real wait4 and destruction,1 if admitted work still runs.
 * No future or OS process is aborted to make EOF complete early. */
pump_publication_destroy:
    push rbx
    mov rbx,[r15+400]
    test rbx,rbx
    jz pp_destroy_empty
    mov rdi,[rbx+216]
    test rdi,rdi
    jz pp_destroy_empty
    call publication_worker_destroy
    test eax,eax
    jz pp_destroy_done
    cmp eax,0xfffffffd
    jne public_span_fail
    mov eax,1
    pop rbx
    ret
pp_destroy_done:
    mov qword ptr [rbx+216],0
pp_destroy_empty:
    xor eax,eax
    pop rbx
    ret

pump_publication_wake_fd:
    mov rax,[r15+400]
    test rax,rax
    jz pp_wake_absent
    mov rdi,[rax+216]
    test rdi,rdi
    jz pp_wake_absent
    jmp publication_worker_wake_fd
pp_wake_absent:
    mov rax,-1
    ret

/* Full owned HIA buffers, native await descriptor and shared request context.
 * The independent FD6 stream records every worker HIA/body effect unchanged. */
pump_trace_publication:
    PM_SAVE
    mov rbp,rdi
    mov r13,[rbp+PN_P_CONTEXT]
    test r13,r13
    jnz ppt_context
    cmp qword ptr [rbp+PN_P_ACTIVE],1
    jne ppt_done
    cmp qword ptr [rbp+PN_OWNERSHIP],0
    jne public_span_fail
    mov rax,[r15+8]
    mov r13,[rax+67*64+8]
    test r13,r13
    jz public_span_fail
ppt_context:
    call pump_trace_clear_tail
    mov edi,19
    mov rsi,rbp
    mov rdx,rbp
    mov ecx,4096
    mov r8,r13
    mov r9d,4096
    call pump_trace_emit
    call pump_trace_clear_tail
    mov edi,20
    mov rsi,rbp
    mov rdx,[r13+24]
    mov ecx,4096
    mov r8,r15
    mov r9d,OFFSET FLAT:RG_ENGINE
    call pump_trace_emit
    mov rdi,rbp
    call pump_trace_scope
    xor ebx,ebx
ppt_row_next:
    cmp qword ptr [rbp+PN_OWNERSHIP],3
    je ppt_row_saved
    cmp qword ptr [rbp+PN_OWNERSHIP],0
    jne public_span_fail
    lea rax,[rbx+64]
    shl rax,6
    add rax,[r15+8]
    mov rdx,rax
    jmp ppt_row_selected
ppt_row_saved:
    mov rdx,rbx
    shl rdx,6
    add rdx,rbp
    add rdx,PN_P_DESCRIPTORS
ppt_row_selected:
    call pump_trace_clear_tail
    mov rax,[rdx+32]
    mov [r12+PM_TRACE_C_PTR],rax
    mov rax,[rdx+40]
    mov [r12+PM_TRACE_C_LEN],rax
    mov r8,[rdx+8]
    mov r9,[rdx+16]
    lea edi,[rbx+21]
    mov rsi,rbp
    mov ecx,64
    call pump_trace_emit
    inc ebx
    cmp ebx,5
    jb ppt_row_next
ppt_done:
    PM_RETURN
