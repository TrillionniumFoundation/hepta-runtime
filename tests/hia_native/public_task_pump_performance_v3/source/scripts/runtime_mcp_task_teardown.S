/* Current SDK EOF: old sends, queued responses, bounded drain, loop token,
 * transport lock/close, then process-runtime future destruction and worker reap.
 * The registry is the current async shutdown policy owner. Historical slot53
 * remains installed unchanged; this path never feeds it fabricated zero counts. */
.intel_syntax noprefix
.section .text
pump_finish:
    PM_SAVE
    cmp qword ptr [r12+PM_PHASE],0
    jne pump_finish_loop
    call pump_clock
    mov [r12+PM_DRAIN_START],rax
    mov rcx,rax
    mov edi,6
    xor esi,esi
    mov edx,1
    xor r8d,r8d
    xor r9d,r9d
    call pump_registry
    cmp eax,6
    jne public_span_fail
    mov qword ptr [r12+PM_PHASE],1
pump_finish_loop:
    call pump_tick
    cmp qword ptr [r12+PM_PHASE],2
    jb pump_finish_wait
    cmp qword ptr [r12+PM_SEND_HEAD],0
    jne pump_finish_wait
    /* AsyncRwTransport.close takes the writer mutex. Pre-existing main-loop
     * send tasks retain their lock queue after drain timeout; none is dropped
     * merely to make close appear complete. Only drain-owned sends are aborted. */
    mov edi,1
    mov esi,4
    mov rdx,[r12+PM_OUT_FLAGS]
    mov eax,72
    syscall
    test rax,rax
    jnz public_span_fail
    and qword ptr [r12+PM_FLAGS_SET],-3
    mov edi,1
    mov eax,3
    syscall
    cmp rax,-4
    je pump_writer_closed
    test rax,rax
    jnz public_span_fail
pump_writer_closed:
    mov qword ptr [r12+PM_PHASE],3
    call pump_trace_closed
    xor edi,edi
    mov esi,4
    mov rdx,[r12+PM_IN_FLAGS]
    mov eax,72
    syscall
    test rax,rax
    jnz public_span_fail
    and qword ptr [r12+PM_FLAGS_SET],-2
    call pump_deliver_context_cancellation
    call pump_claim_responses
pump_drop_handler_next:
    mov rbp,[r12+PM_ALL]
    test rbp,rbp
    jz pump_handlers_retired
    cmp qword ptr [rbp+PN_STATE],1
    jne public_span_fail
    mov rdi,rbp
    mov esi,3
    call pump_resume_node
    jmp pump_drop_handler_next
pump_handlers_retired:
    cmp qword ptr [r12+PM_PENDING],0
    jne public_span_fail
    mov edi,12
    xor esi,esi
    xor edx,edx
    xor ecx,ecx
    xor r8d,r8d
    xor r9d,r9d
    call pump_registry
    test eax,eax
    jnz public_span_fail
    cmp qword ptr [rdx+56],2
    jne public_span_fail
    mov rax,[rdx+64]
    or rax,[rdx+72]
    or rax,[rdx+80]
    or rax,[rdx+88]
    or rax,[rdx+160]
    jnz public_span_fail
    mov rdi,[r12+PM_PORT]
    mov rsi,r15
    call pump_port_detach
    test rax,rax
    jnz public_span_fail
    mov rdi,[r12+PM_PORT]
    call pump_port_shutdown
    test rax,rax
    jnz public_span_fail
    mov qword ptr [r12+PM_PHASE],4
pump_reap_workers:
    call pump_service_worker
    mov rdi,[r12+PM_PORT]
    call pump_port_destroy
    test rax,rax
    jz pump_port_retired
    cmp eax,0xfffffff8
    jne public_span_fail
    call pump_wait
    jmp pump_reap_workers
pump_port_retired:
    mov qword ptr [r12+PM_PORT],0
    cmp qword ptr [r12+PM_JOURNAL_OWNED],0
    je pump_journal_closed
    mov rdi,[r12+PM_JOURNAL]
    mov eax,3
    syscall
    cmp rax,-4
    je pump_journal_closed
    test rax,rax
    jnz public_span_fail
pump_journal_closed:
    mov qword ptr [r12+PM_JOURNAL],-1
    mov qword ptr [r12+PM_JOURNAL_OWNED],0
    mov qword ptr [r12+PM_WAKE],-1
    mov rdi,[r12+PM_SCRATCH]
    mov rsi,[r12+PM_SCRATCH_CAP]
    add rsi,4096
    mov eax,11
    syscall
    test rax,rax
    jnz public_span_fail
    mov qword ptr [r12+PM_SCRATCH],0
    mov rdi,[r12+PM_READY_COPY]
    test rdi,rdi
    jz pump_storage_retired
    mov rsi,[r12+PM_READY_CAP]
    add rsi,4096
    mov eax,11
    syscall
    test rax,rax
    jnz public_span_fail
    mov qword ptr [r12+PM_READY_COPY],0
pump_storage_retired:
    xor eax,eax
    PM_RETURN
pump_finish_wait:
    call pump_wait
    jmp pump_finish_loop
