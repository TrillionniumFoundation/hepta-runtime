/* Consume fixed HIA task decisions and actual frontend results. */
.intel_syntax noprefix
.section .text
pump_accept:
    PM_SAVE
    mov r13,rdi
    mov r14,rsi
    cmp qword ptr [r12+PM_PHASE],0
    jne public_span_fail
    cmp qword ptr [r12+PM_BARRIER],0
    jne public_span_fail
    mov edi,4096
    call view_allocate
    cmp rax,-4095
    jae public_span_fail
    mov rbp,rax
    mov rax,0x31304e5452505248
    mov [rbp],rax
    mov [rbp+PN_ENGINE],r15
    inc qword ptr [r12+PM_NODE_SEQUENCE]
    jz public_span_fail
    mov rax,[r12+PM_NODE_SEQUENCE]
    mov [rbp+PN_HOST_GENERATION],rax
    mov [rbp+PN_INPUT_LENGTH],r14
    lea rdi,[r14+4095]
    and rdi,-4096
    test rdi,rdi
    jz public_span_fail
    mov [rbp+PN_INPUT_CAPACITY],rdi
    call view_allocate
    cmp rax,-4095
    jae public_span_fail
    mov [rbp+PN_INPUT],rax
    mov rdi,rax
    mov rsi,r13
    mov rcx,r14
    rep movsb
    call pump_connection_mode
    mov [rbp+PN_BEFORE_MODE],rax
    mov rax,[r12+PM_ALL]
    mov [rbp+PN_NEXT],rax
    mov [r12+PM_ALL],rbp
    mov [r12+PM_CURRENT],rbp
    mov rdi,[rbp+PN_INPUT]
    mov rsi,[rbp+PN_INPUT_LENGTH]
    mov r8d,18
    call runtime_grow_owned
    cmp eax,64
    jne public_span_fail
    /* Copy the current G1 borrow before another public request replaces it. */
    call pump_connection_mode
    mov rcx,rax
    mov rdx,[rbp+PN_BEFORE_MODE]
    mov rax,[r15+8]
    lea rax,[rax+42*64]
    mov r9,[rax+56]
    cmp r9,256
    jb public_span_fail
    cmp r9,67108864
    ja public_span_fail
    cmp [rax+48],r9
    jne public_span_fail
    mov r8,[rax+32]
    mov edi,15
    xor esi,esi
    call pump_registry
    cmp eax,1
    je pump_accept_registered
    cmp eax,15
    je pump_accept_bootstrap
    cmp eax,2
    je pump_accept_observed
    cmp eax,3
    je pump_accept_observed
    cmp eax,11
    je pump_accept_observed
    cmp eax,16
    jne public_span_fail
    jmp pump_accept_observed
pump_accept_registered:
    mov rax,[rdx+24]
    test rax,rax
    jz public_span_fail
    mov [rbp+PN_GENERATION],rax
    jmp pump_accept_observed
pump_accept_bootstrap:
    mov qword ptr [rbp+PN_BOOTSTRAP],1
pump_accept_observed:
    mov rdi,rbp
    call pump_detach_frontend
    mov rdi,rbp
    call pump_handle_frontend
    mov qword ptr [r12+PM_CURRENT],0
    xor eax,eax
    PM_RETURN

pump_handle_frontend:
    PM_SAVE
    mov rbp,rdi
    mov r13,[rbp+PN_DESCRIPTOR+32]
    mov r14,[rbp+PN_DESCRIPTOR+56]
    mov rax,0x323052464d435248
    cmp [r13],rax
    jne public_span_fail
    cmp qword ptr [r13+56],0
    jne public_span_fail
    cmp qword ptr [r13+16],1
    ja public_span_fail
    mov rax,[r13+16]
    or [r12+40],rax
    mov rax,[r13+8]
    cmp rax,4
    ja public_span_fail
    mov [rbp+PN_KIND],rax
    mov [rbp+PN_EXTENT],r14
    cmp rax,4
    je pump_frontend_pending
    test rax,rax
    jz pump_frontend_silent
    mov rax,[r13+24]
    add rax,[r13+32]
    jc public_span_fail
    add rax,64
    jc public_span_fail
    cmp rax,r14
    jne public_span_fail
    cmp qword ptr [r13+40],1
    ja public_span_fail
    cmp qword ptr [rbp+PN_GENERATION],0
    je pump_frontend_untracked
    mov edi,13
    mov rsi,[rbp+PN_GENERATION]
    xor edx,edx
    xor ecx,ecx
    xor r8d,r8d
    xor r9d,r9d
    call pump_registry
    cmp eax,12
    jne public_span_fail
    mov qword ptr [rbp+PN_STATE],2
    jmp pump_frontend_done
pump_frontend_untracked:
    /* Pre-serve and codec replies are awaited by the actual receive path. */
    mov qword ptr [rbp+PN_BOOTSTRAP],1
    mov qword ptr [r12+PM_BARRIER],1
    mov rdi,rbp
    call pump_enqueue_send
    jmp pump_frontend_done
pump_frontend_silent:
    cmp r14,64
    jne public_span_fail
    mov rax,[r13+24]
    or rax,[r13+32]
    or rax,[r13+40]
    jnz public_span_fail
    cmp qword ptr [rbp+PN_GENERATION],0
    je pump_frontend_silent_free
    cmp qword ptr [rbp+PN_FUTURE_DROPPED],1
    jne public_span_fail
    mov edi,5
    mov rsi,[rbp+PN_GENERATION]
    xor edx,edx
    xor ecx,ecx
    xor r8d,r8d
    xor r9d,r9d
    call pump_registry
    cmp eax,5
    jne public_span_fail
pump_frontend_silent_free:
    mov rdi,rbp
    call pump_retire_node
    jmp pump_frontend_done
pump_frontend_pending:
    cmp r14,64
    jne public_span_fail
    mov rax,[r13+16]
    or rax,[r13+24]
    or rax,[r13+32]
    or rax,[r13+40]
    jnz public_span_fail
    cmp qword ptr [rbp+PN_GENERATION],0
    je public_span_fail
    cmp qword ptr [rbp+PN_BOOTSTRAP],0
    jne public_span_fail
    mov rbx,[rbp+PN_DESCRIPTOR+8]
    cmp qword ptr [rbp+PN_DESCRIPTOR+16],1408
    jb public_span_fail
    cmp qword ptr [rbx+8],97
    jne public_span_fail
    mov rax,0x31305352464c4248
    cmp [rbx+1280],rax
    jne public_span_fail
    mov rax,[rbx+1304]
    or rax,[rbx+1312]
    or rax,[rbx+1328]
    or rax,[rbx+1336]
    jnz public_span_fail
    mov rax,[rbx+1320]
    test rax,rax
    jz public_span_fail
    cmp [r13+48],rax
    jne public_span_fail
    cmp [rbp+PN_DESCRIPTOR+24],rax
    jne public_span_fail
    cmp [rbp+PN_CONTINUATION+16],rax
    jne public_span_fail
    mov [rbp+PN_SEQUENCE],rax
    mov rdx,[rbx+1288]
    mov rcx,[rbx+1296]
    test rdx,rdx
    jz public_span_fail
    test rcx,rcx
    jz public_span_fail
    cmp qword ptr [rbp+PN_STATE],1
    je pump_pending_existing
    mov [rbp+PN_TAG],rdx
    mov [rbp+PN_JOB],rcx
    mov edi,9
    mov rsi,[rbp+PN_GENERATION]
    xor r8d,r8d
    xor r9d,r9d
    call pump_registry
    test eax,eax
    jnz public_span_fail
    mov qword ptr [rbp+PN_STATE],1
    inc qword ptr [r12+PM_PENDING]
    jmp pump_frontend_done
pump_pending_existing:
    cmp [rbp+PN_TAG],rdx
    jne public_span_fail
    cmp [rbp+PN_JOB],rcx
    jne public_span_fail
pump_frontend_done:
    xor eax,eax
    PM_RETURN

pump_enqueue_send:
    mov qword ptr [rdi+PN_STATE],3
    mov qword ptr [rdi+PN_SEND_NEXT],0
    mov rax,[r12+PM_SEND_TAIL]
    test rax,rax
    jz pump_send_first
    mov [rax+PN_SEND_NEXT],rdi
    jmp pump_send_linked
pump_send_first:
    mov [r12+PM_SEND_HEAD],rdi
pump_send_linked:
    mov [r12+PM_SEND_TAIL],rdi
    ret

/* HIA selects the queued response. No host ID lookup decides publication. */
pump_claim_responses:
    PM_SAVE
pump_claim_next:
    cmp qword ptr [r12+PM_BARRIER],0
    jne pump_claim_done
    mov edi,14
    xor esi,esi
    xor edx,edx
    xor ecx,ecx
    xor r8d,r8d
    xor r9d,r9d
    call pump_registry
    cmp eax,13
    je pump_claim_done
    cmp eax,14
    je pump_claim_done
    cmp eax,4
    je pump_claim_publish
    cmp eax,5
    jne public_span_fail
    mov rdi,[rdx+24]
    call pump_find_generation
    cmp qword ptr [rax+PN_STATE],2
    jne public_span_fail
    mov rdi,rax
    call pump_retire_node
    jmp pump_claim_next
pump_claim_publish:
    mov r13,[rdx+56]
    mov rdi,[rdx+24]
    call pump_find_generation
    cmp qword ptr [rax+PN_STATE],2
    jne public_span_fail
    mov [rax+PN_SEND_PHASE],r13
    mov rdi,rax
    call pump_enqueue_send
    jmp pump_claim_next
pump_claim_done:
    xor eax,eax
    PM_RETURN

/* Notification cancellation delivers the context token only. The original
 * Bellman method ignores that token. Keep its future; never issue cmd3 here. */
pump_deliver_context_cancellation:
    PM_SAVE
pump_cancel_next:
    mov edi,10
    xor esi,esi
    xor edx,edx
    xor ecx,ecx
    xor r8d,r8d
    xor r9d,r9d
    call pump_registry
    cmp eax,9
    je pump_cancel_done
    cmp eax,10
    jne public_span_fail
    mov r13,[rdx+24]
    mov rdi,r13
    call pump_find_generation
    mov qword ptr [rax+PN_TOKEN_CANCELLED],1
    mov edi,11
    mov rsi,r13
    xor edx,edx
    xor ecx,ecx
    xor r8d,r8d
    xor r9d,r9d
    call pump_registry
    test eax,eax
    jnz public_span_fail
    jmp pump_cancel_next
pump_cancel_done:
    xor eax,eax
    PM_RETURN
