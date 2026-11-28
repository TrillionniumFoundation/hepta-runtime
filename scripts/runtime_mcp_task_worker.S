/* Actual shared-worker wake/FIFO edge. Copy and release every complete READY
 * borrow before another port call. Delivery resumes the saved current CALL. */
.intel_syntax noprefix
.section .text
pump_service_worker:
    PM_SAVE
    mov rdi,[r12+PM_PORT]
    call pump_port_service
    cmp rax,1
    ja public_span_fail
pump_ready_next:
    mov rdi,[r12+PM_PORT]
    lea rsi,[r12+PM_BORROW]
    mov edx,32
    call pump_port_receive
    test rax,rax
    jz pump_service_done
    cmp rax,32
    jne public_span_fail
    mov rax,0x3130524250524248 /* HBRPBR01 */
    cmp [r12+PM_BORROW],rax
    jne public_span_fail
    mov r13,[r12+PM_BORROW+8]
    mov r14,[r12+PM_BORROW+16]
    test r13,r13
    jz public_span_fail
    cmp r14,192
    jb public_span_fail
    cmp r14,4096-32
    ja public_span_fail
    mov rax,0x313052534d504248 /* HBPMSR01 */
    cmp [r13],rax
    jne public_span_fail
    cmp [r13+8],r14
    jne public_span_fail
    cmp qword ptr [r13+16],2
    jne public_span_fail
    cmp qword ptr [r13+56],0
    jne public_span_fail
    cmp qword ptr [r12+PM_READY_COPY],0
    jne pump_ready_storage
    mov edi,4096
    call view_allocate
    cmp rax,-4095
    jae public_span_fail
    mov [r12+PM_READY_COPY],rax
    mov qword ptr [r12+PM_READY_CAP],4096
pump_ready_storage:
    mov rdi,[r12+PM_READY_COPY]
    mov rsi,r13
    mov rcx,r14
    rep movsb
    mov [r12+PM_READY_LEN],r14
    mov rdi,[r12+PM_PORT]
    mov rsi,[r12+PM_BORROW+24]
    test rsi,rsi
    jz public_span_fail
    call pump_port_release
    test rax,rax
    jnz public_span_fail
    call pump_trace_ready
    lea rdi,[r12+PM_BORROW]
    mov ecx,4
    xor eax,eax
    rep stosq
    mov r13,[r12+PM_READY_COPY]
    mov r14,[r13+24]
    mov rbx,[r13+32]
    mov rbp,[r12+PM_ALL]
pump_ready_find:
    test rbp,rbp
    jz pump_ready_next
    cmp [rbp+PN_TAG],r14
    jne pump_ready_advance
    cmp [rbp+PN_JOB],rbx
    jne public_span_fail
    cmp qword ptr [rbp+PN_STATE],1
    jne pump_ready_next
    cmp qword ptr [r12+PM_PHASE],3
    jae pump_ready_next
    mov rdi,rbp
    mov esi,2
    call pump_resume_node
    jmp pump_ready_next
pump_ready_advance:
    mov rbp,[rbp+PN_NEXT]
    jmp pump_ready_find
pump_service_done:
    xor eax,eax
    PM_RETURN

/* Command3 is reachable only after the transport is actually closed and this
 * host destroys the process runtime's retained handler future. Context-token
 * cancellation while the service lives always continues command2 instead. */
pump_resume_node:
    PM_SAVE
    mov rbp,rdi
    mov r13,rsi
    cmp qword ptr [rbp+PN_STATE],1
    jne public_span_fail
    cmp [rbp+PN_ENGINE],r15
    jne public_span_fail
    cmp r13,2
    je pump_resume_prepare
    cmp r13,3
    jne public_span_fail
    cmp qword ptr [r12+PM_PHASE],3
    jb public_span_fail
    cmp qword ptr [rbp+PN_TOKEN_CANCELLED],1
    jne public_span_fail
    mov qword ptr [rbp+PN_FUTURE_DROPPED],1
pump_resume_prepare:
    call pump_waiting_kind
    test eax,eax
    jz pump_resume_bellman_prepare
    cmp eax,3
    je pump_resume_read_prepare
    cmp eax,2
    je pump_resume_publication_prepare
    mov rdi,rbp
    mov rsi,r13
    call pump_resume_extract
    PM_RETURN
pump_resume_read_prepare:
    mov rdi,rbp
    mov rsi,r13
    call pump_resume_read
    PM_RETURN
pump_resume_publication_prepare:
    mov rdi,rbp
    mov rsi,r13
    call pump_resume_publication
    PM_RETURN
pump_resume_bellman_prepare:
    mov rbx,[rbp+PN_DESCRIPTOR+8]
    cmp qword ptr [rbp+PN_DESCRIPTOR+16],1408
    jb public_span_fail
    cmp qword ptr [rbx+8],97
    jne public_span_fail
    mov rax,0x31305352464c4248
    cmp [rbx+1280],rax
    jne public_span_fail
    mov rax,[rbp+PN_TAG]
    cmp [rbx+1288],rax
    jne public_span_fail
    mov rax,[rbp+PN_JOB]
    cmp [rbx+1296],rax
    jne public_span_fail
    mov rax,[rbp+PN_SEQUENCE]
    cmp [rbx+1320],rax
    jne public_span_fail
    mov rax,[rbx+1344]
    or rax,[rbx+1352]
    or rax,[rbx+1360]
    or rax,[rbx+1368]
    or rax,[rbx+1376]
    or rax,[rbx+1384]
    or rax,[rbx+1392]
    or rax,[rbx+1400]
    jnz public_span_fail
    mov rax,0x31305152464c4248 /* HBLFRQ01 */
    mov [rbx+1344],rax
    mov [rbx+1352],r13
    mov rax,[rbp+PN_TAG]
    mov [rbx+1360],rax
    mov rax,[rbp+PN_JOB]
    mov [rbx+1368],rax
    mov rax,[rbp+PN_SEQUENCE]
    mov [rbx+1376],rax
    mov rdi,rbp
    call pump_restore_frontend
    mov [r12+PM_CURRENT],rbp
    mov rdi,[rbp+PN_INPUT]
    mov rsi,[rbp+PN_INPUT_LENGTH]
    mov r8d,18
    call runtime_grow_owned
    cmp eax,64
    jne public_span_fail
    mov rdi,rbp
    call pump_detach_frontend
    mov rax,[rbp+PN_DESCRIPTOR+32]
    cmp qword ptr [rax+8],4
    je pump_resume_still_pending
    cmp qword ptr [r12+PM_PENDING],0
    je public_span_fail
    dec qword ptr [r12+PM_PENDING]
pump_resume_still_pending:
    mov rdi,rbp
    call pump_handle_frontend
    mov qword ptr [r12+PM_CURRENT],0
    xor eax,eax
    PM_RETURN
