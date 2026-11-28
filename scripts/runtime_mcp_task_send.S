/* Exact OS writes complete the SDK send future. The existing HIA publisher
 * acknowledges only positive writes and retains its current loan on EAGAIN. */
.intel_syntax noprefix
.section .text
pump_send_progress:
    PM_SAVE
pump_send_next:
    mov rbp,[r12+PM_SEND_HEAD]
    test rbp,rbp
    jz pump_send_done
    cmp qword ptr [rbp+PN_STATE],3
    jne public_span_fail
    cmp [rbp+PN_ENGINE],r15
    jne public_span_fail
    cmp qword ptr [r12+PM_PHASE],2
    jb pump_send_live
    cmp qword ptr [rbp+PN_SEND_PHASE],1
    je pump_abort_drain_send
pump_send_live:
    cmp qword ptr [rbp+PN_LF],1
    je pump_send_lf
    mov r13,[rbp+PN_DESCRIPTOR+32]
    cmp qword ptr [rbp+PN_KIND],1
    je pump_send_direct
    cmp qword ptr [rbp+PN_KIND],2
    je pump_send_publisher
    cmp qword ptr [rbp+PN_KIND],3
    jne public_span_fail
pump_send_publisher:
    lea rbx,[rbp+PN_PUBLICATION]
    cmp qword ptr [rbx+64],0
    jne pump_send_resume
    mov rax,0x3130434155505248
    mov [rbx+64],rax
    mov qword ptr [rbx+48],2
    cmp qword ptr [rbp+PN_KIND],2
    jne pump_send_raw_arguments
    lea rax,[r13+64]
    mov [rbx],rax
    mov rcx,[r13+24]
    mov [rbx+8],rcx
    add rax,rcx
    mov [rbx+16],rax
    mov rax,[r13+32]
    mov [rbx+24],rax
    mov rax,[r13+40]
    mov [rbx+32],rax
    mov qword ptr [rbx+56],3
    jmp pump_send_start
pump_send_raw_arguments:
    cmp qword ptr [r13+32],0
    jne public_span_fail
    /* Kind3 already contains the complete typed result wire, including its
     * error flag. Admit either boolean; copy the existing wire unchanged. */
    cmp qword ptr [r13+40],1
    ja public_span_fail
    lea rax,[r13+64]
    mov [rbx+16],rax
    mov rax,[r13+24]
    mov [rbx+24],rax
pump_send_start:
    mov rdi,rbx
    call runtime_publication_async_start
    jmp pump_send_published
pump_send_resume:
    cmp qword ptr [rbx+96],1
    jne public_span_fail
    mov rdi,rbx
    call runtime_publication_async_resume
pump_send_published:
    mov [rbp+PN_WRITE_RESULT],rax
    mov qword ptr [rbp+PN_WRITE_KIND],1
    mov rdi,rbp
    call pump_trace_send
    mov rax,[rbp+PN_WRITE_RESULT]
    cmp eax,1
    je pump_send_done
    test eax,eax
    jz pump_send_body_done
    cmp eax,74
    je pump_send_failed
    jmp public_span_fail
pump_send_direct:
    cmp qword ptr [r13+32],0
    jne public_span_fail
    /* Kind1 is the complete JSON-RPC envelope, including a typed decoding
     * error when isError is one. The direct writer preserves its bytes. */
    cmp qword ptr [r13+40],1
    ja public_span_fail
    mov rax,[rbp+PN_SENT]
    mov rdx,[r13+24]
    cmp rax,rdx
    ja public_span_fail
    sub rdx,rax
    jz pump_send_body_done
    lea rsi,[r13+rax+64]
    mov edi,1
    mov eax,1
    syscall
    mov [rbp+PN_WRITE_RESULT],rax
    mov qword ptr [rbp+PN_WRITE_KIND],2
    mov rdi,rbp
    call pump_trace_send
    mov rax,[rbp+PN_WRITE_RESULT]
    cmp rax,-4
    je pump_send_direct
    cmp rax,-11
    je pump_send_done
    test rax,rax
    jle pump_send_failed
    add [rbp+PN_SENT],rax
    jmp pump_send_direct
pump_send_body_done:
    mov qword ptr [rbp+PN_LF],1
pump_send_lf:
    mov edi,1
    lea rsi,[rip+newline]
    mov edx,1
    mov eax,1
    syscall
    mov [rbp+PN_WRITE_RESULT],rax
    mov qword ptr [rbp+PN_WRITE_KIND],3
    mov rdi,rbp
    call pump_trace_send
    mov rax,[rbp+PN_WRITE_RESULT]
    cmp rax,-4
    je pump_send_lf
    cmp rax,-11
    je pump_send_done
    cmp rax,1
    jne pump_send_failed
    mov r13d,1
    jmp pump_send_settled
pump_abort_drain_send:
    /* The timed drain owns this inline send future. Older sends were spawned
     * in the main loop and still hold the AsyncRwTransport lock queue. */
    cmp qword ptr [rbp+PN_PUBLICATION+96],1
    jne pump_send_failed
    lea rdi,[rbp+PN_PUBLICATION]
    call runtime_publication_async_abort
    cmp eax,74
    jne public_span_fail
pump_send_failed:
    xor r13d,r13d
pump_send_settled:
    mov rax,[rbp+PN_SEND_NEXT]
    mov [r12+PM_SEND_HEAD],rax
    test rax,rax
    jnz pump_send_unlinked
    mov qword ptr [r12+PM_SEND_TAIL],0
pump_send_unlinked:
    mov rsi,[rbp+PN_GENERATION]
    test rsi,rsi
    jz pump_send_bootstrap_settled
    mov edi,4
    mov rdx,r13
    xor ecx,ecx
    xor r8d,r8d
    xor r9d,r9d
    call pump_registry
    test eax,eax
    jnz public_span_fail
    jmp pump_send_retire
pump_send_bootstrap_settled:
    cmp qword ptr [rbp+PN_BOOTSTRAP],1
    jne public_span_fail
    mov qword ptr [r12+PM_BARRIER],0
    test r13,r13
    jnz pump_send_retire
    mov qword ptr [r12+40],1
pump_send_retire:
    mov rdi,rbp
    call pump_retire_node
    jmp pump_send_next
pump_send_done:
    xor eax,eax
    PM_RETURN

/* Observe real monotonic nanoseconds; there is no synthesized timeout clock. */
pump_clock:
    mov edi,1
    lea rsi,[r12+PM_TIME]
    mov eax,228
    syscall
    test rax,rax
    jnz public_span_fail
    mov rax,[r12+PM_TIME]
    mov ecx,1000000000
    mul rcx
    test rdx,rdx
    jnz public_span_fail
    add rax,[r12+PM_TIME+8]
    jc public_span_fail
    ret

pump_tick:
    PM_SAVE
    call pump_service_worker
    call pump_service_extract
    call pump_service_publication
    call pump_service_read
    call pump_deliver_context_cancellation
    call pump_claim_responses
    call pump_send_progress
    call pump_claim_responses
    call pump_deliver_context_cancellation
    cmp qword ptr [r12+PM_PHASE],1
    jne pump_tick_done
    call pump_clock
    mov rdx,rax
    mov edi,7
    xor esi,esi
    xor ecx,ecx
    xor r8d,r8d
    xor r9d,r9d
    call pump_registry
    cmp eax,6
    je pump_tick_done
    cmp eax,7
    jne public_span_fail
    mov qword ptr [r12+PM_PHASE],2
pump_tick_done:
    xor eax,eax
    PM_RETURN

/* Input, actual write readiness and the one shared worker wake FD. A finite
 * 10ms poll observes abnormal reap while work exists; no solve is awaited. */
pump_wait:
    PM_SAVE
    mov dword ptr [r12+PM_POLL],-1
    mov dword ptr [r12+PM_POLL+4],1
    cmp qword ptr [r12+PM_PHASE],0
    jne pump_poll_writer
    cmp qword ptr [r12+PM_BARRIER],0
    jne pump_poll_writer
    mov dword ptr [r12+PM_POLL],0
pump_poll_writer:
    mov dword ptr [r12+PM_POLL+8],-1
    mov dword ptr [r12+PM_POLL+12],4
    cmp qword ptr [r12+PM_SEND_HEAD],0
    je pump_poll_worker
    mov dword ptr [r12+PM_POLL+8],1
pump_poll_worker:
    mov eax,[r12+PM_WAKE]
    mov [r12+PM_POLL+16],eax
    mov dword ptr [r12+PM_POLL+20],1
    call pump_publication_wake_fd
    cmp rax,-1
    je pump_poll_publication_ready
    cmp rax,0x7fffffff
    ja public_span_fail
pump_poll_publication_ready:
    mov [r12+PM_POLL+24],eax
    mov dword ptr [r12+PM_POLL+28],1
    mov rdx,-1
    cmp qword ptr [r12+PM_PENDING],0
    jne pump_poll_finite
    cmp qword ptr [r12+PM_PHASE],0
    je pump_poll_ready
pump_poll_finite:
    mov edx,10
pump_poll_ready:
    lea rdi,[r12+PM_POLL]
    mov esi,4
    mov eax,7
    syscall
    cmp rax,-4
    je pump_poll_writer
    test rax,rax
    js public_span_fail
    xor eax,eax
    PM_RETURN
