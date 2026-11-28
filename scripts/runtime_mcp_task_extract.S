/* Owned extract future chain at fixed slots59..63. No public bytes select
 * these slots, a context address, or resume/drop commands. Only one chain is
 * installed in the shared engine while its actual synchronous turn runs. */
.intel_syntax noprefix
.section .text
.equ PX_MASK,0xf800000000000000
.equ PX_OWNED,0x7800000000000000

pump_extract_detach:
    PM_SAVE
    mov rbp,rdi
    mov rax,[rbp+PN_X_CONTEXT]
    or rax,[rbp+PN_X_INSTALLED]
    or rax,[rbp+PN_X_WORKMAP]
    or rax,[rbp+PN_X_OUTMAP]
    jnz public_span_fail
    mov rax,[r15+456]
    test rax,rax
    jnz px_detach_context
    cmp qword ptr [rbp+PN_X_ACTIVE],0
    jne public_span_fail
    jmp px_detach_done
px_detach_context:
    mov r13,rax
    cmp [r13+256+168],r15
    jne public_span_fail
    mov rax,[r15+400]
    cmp [r13+80],rax
    jne public_span_fail
    cmp qword ptr [r15+464],1
    jne public_span_fail
    cmp qword ptr [rbp+PN_X_ACTIVE],1
    je px_detach_wait
    cmp qword ptr [r13+XW_LINKED],0
    jne public_span_fail
    cmp qword ptr [r13+136],1
    jne public_span_fail
    cmp qword ptr [r13+144],1
    jne public_span_fail
    jmp px_detach_admitted
px_detach_wait:
    cmp qword ptr [r13+XW_LINKED],1
    jne public_span_fail
    cmp qword ptr [r13+136],0
    jne public_span_fail
    cmp qword ptr [r13+144],0
    jne public_span_fail
    mov rax,[r13+XW_NODE]
    test rax,rax
    jz px_detach_bind
    cmp rax,rbp
    jne public_span_fail
px_detach_bind:
    mov [r13+XW_NODE],rbp
px_detach_admitted:
    cmp qword ptr [r13+160],0
    jne public_span_fail
    mov [rbp+PN_X_CONTEXT],r13
    mov qword ptr [rbp+PN_X_INSTALLED],1
    mov rdx,PX_MASK
    mov rcx,PX_OWNED
    mov rax,[r15+64]
    and rax,rdx
    cmp rax,rcx
    jne public_span_fail
    mov [rbp+PN_X_WORKMAP],rax
    mov rax,[r15+72]
    and rax,rdx
    cmp rax,rcx
    jne public_span_fail
    mov [rbp+PN_X_OUTMAP],rax
    mov r13,[r15+8]
    add r13,59*64
    lea r14,[r15+512+59*64]
    xor ebx,ebx
px_detach_slot:
    cmp qword ptr [rbp+PN_X_ACTIVE],0
    je px_detach_idle
    cmp ebx,1
    je px_detach_idle
    cmp qword ptr [r14],1
    jne public_span_fail
    cmp ebx,4
    je px_detach_body
    cmp qword ptr [r14+8],2
    jne public_span_fail
    mov eax,0xffffffdf
    cmp [r14+48],rax
    jne public_span_fail
    cmp qword ptr [r14+56],0
    jne public_span_fail
    jmp px_detach_wait_result
px_detach_body:
    cmp qword ptr [r14+8],0
    jne public_span_fail
px_detach_wait_result:
    mov eax,0xffffffdf
    cmp [r13+48],rax
    jne public_span_fail
    cmp qword ptr [r13+56],0
    jne public_span_fail
    jmp px_detach_copy
px_detach_idle:
    mov rax,[r14]
    or rax,[r14+8]
    jnz public_span_fail
px_detach_copy:
    mov rax,rbx
    shl rax,6
    lea rdi,[rbp+rax+PN_X_DESCRIPTORS]
    mov rsi,r13
    mov ecx,8
    rep movsq
    mov rax,rbx
    shl rax,6
    lea rdi,[rbp+rax+PN_X_CONTINUATIONS]
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
    jb px_detach_slot
    mov rax,PX_MASK
    not rax
    and [r15+64],rax
    and [r15+72],rax
    mov qword ptr [r15+456],0
    mov qword ptr [r15+464],0
px_detach_done:
    PM_RETURN

/* Failed typed/admission calls can leave idle reusable rows without a body
 * context. Their completed output has already been copied into its owning
 * frontend. Retire only these idle owned mappings before installing a future. */
pump_extract_clear_idle:
    PM_SAVE
    cmp qword ptr [r15+456],0
    jne public_span_fail
    mov ebx,59
    mov r13,[r15+8]
    add r13,59*64
    lea r14,[r15+512+59*64]
px_idle_slot:
    mov rax,[r14]
    or rax,[r14+8]
    jnz public_span_fail
    bt qword ptr [r15+64],rbx
    jnc px_idle_output
    cmp ebx,63
    je public_span_fail
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
    btr qword ptr [r15+64],rbx
px_idle_output:
    bt qword ptr [r15+72],rbx
    jnc px_idle_clear
    cmp ebx,63
    je public_span_fail
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
    btr qword ptr [r15+72],rbx
px_idle_clear:
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
    cmp ebx,64
    jb px_idle_slot
    mov qword ptr [r15+464],0
    PM_RETURN

pump_extract_restore:
    PM_SAVE
    mov rbp,rdi
    mov rax,[rbp+PN_X_CONTEXT]
    test rax,rax
    jnz px_restore_present
    cmp qword ptr [rbp+PN_X_ACTIVE],0
    jne public_span_fail
    jmp px_restore_done
px_restore_present:
    cmp qword ptr [rbp+PN_X_ACTIVE],1
    jne public_span_fail
    cmp qword ptr [rbp+PN_X_INSTALLED],1
    jne public_span_fail
    cmp [rax+XW_NODE],rbp
    jne public_span_fail
    cmp [rax+256+168],r15
    jne public_span_fail
    mov rcx,PX_OWNED
    cmp [rbp+PN_X_WORKMAP],rcx
    jne public_span_fail
    cmp [rbp+PN_X_OUTMAP],rcx
    jne public_span_fail
    call pump_extract_clear_idle
    mov r13,[r15+8]
    add r13,59*64
    lea r14,[r15+512+59*64]
    xor ebx,ebx
px_restore_slot:
    mov rax,rbx
    shl rax,6
    lea rsi,[rbp+rax+PN_X_DESCRIPTORS]
    mov rax,[rsi]
    cmp [r13],rax
    jne public_span_fail
    mov rdi,r13
    mov ecx,8
    rep movsq
    mov rax,rbx
    shl rax,6
    lea rsi,[rbp+rax+PN_X_CONTINUATIONS]
    mov rdi,r14
    mov ecx,8
    rep movsq
    add r13,64
    add r14,64
    inc ebx
    cmp ebx,5
    jb px_restore_slot
    mov rax,[rbp+PN_X_WORKMAP]
    or [r15+64],rax
    mov rax,[rbp+PN_X_OUTMAP]
    or [r15+72],rax
    mov rax,[rbp+PN_X_CONTEXT]
    mov [r15+456],rax
    mov qword ptr [r15+464],1
    mov qword ptr [rbp+PN_X_CONTEXT],0
    mov qword ptr [rbp+PN_X_INSTALLED],0
    mov qword ptr [rbp+PN_X_WORKMAP],0
    mov qword ptr [rbp+PN_X_OUTMAP],0
px_restore_done:
    PM_RETURN

pump_extract_pending:
    PM_SAVE
    mov rbp,rdi
    cmp qword ptr [rbp+PN_X_ACTIVE],1
    jne public_span_fail
    cmp qword ptr [rbp+PN_OWNERSHIP],3
    jne public_span_fail
    cmp qword ptr [rbp+PN_GENERATION],0
    je public_span_fail
    cmp qword ptr [rbp+PN_BOOTSTRAP],0
    jne public_span_fail
    mov rax,[rbp+PN_X_CONTEXT]
    test rax,rax
    jz public_span_fail
    cmp [rax+XW_NODE],rbp
    jne public_span_fail
    cmp qword ptr [rax+XW_LINKED],1
    jne public_span_fail
    cmp qword ptr [rbp+PN_CONTINUATION],1
    jne public_span_fail
    cmp qword ptr [rbp+PN_CONTINUATION+8],2
    jne public_span_fail
    cmp qword ptr [rbp+PN_CONTINUATION+24],59
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
    je px_pending_existing
    cmp qword ptr [rbp+PN_STATE],0
    jne public_span_fail
    mov [rbp+PN_SEQUENCE],rax
    mov qword ptr [rbp+PN_STATE],1
    inc qword ptr [r12+PM_PENDING]
    jz public_span_fail
    jmp px_pending_done
px_pending_existing:
    cmp [rbp+PN_SEQUENCE],rax
    jne public_span_fail
px_pending_done:
    mov qword ptr [rbp+PN_KIND],5 /* Actual raw WAIT; no invented HRCMFR02. */
    mov qword ptr [rbp+PN_EXTENT],0
    PM_RETURN

pump_resume_extract:
    PM_SAVE
    mov rbp,rdi
    mov r13,rsi
    cmp qword ptr [rbp+PN_X_ACTIVE],1
    jne public_span_fail
    cmp r13,2
    je px_resume_wake
    cmp r13,3
    jne public_span_fail
    cmp qword ptr [r12+PM_PHASE],3
    jb public_span_fail
    cmp qword ptr [rbp+PN_FUTURE_DROPPED],1
    jne public_span_fail
    jmp px_resume_install
px_resume_wake:
    cmp qword ptr [r12+PM_PHASE],3
    jae public_span_fail
    mov rax,[rbp+PN_X_CONTEXT]
    test rax,rax
    jz public_span_fail
    cmp qword ptr [rax+XW_READY],1
    jne public_span_fail
px_resume_install:
    mov rdi,rbp
    call pump_restore_frontend
    mov [r12+PM_CURRENT],rbp
    mov rdi,[rbp+PN_INPUT]
    mov rsi,[rbp+PN_INPUT_LENGTH]
    mov r8d,18
    mov r9,r13
    call runtime_grow_suspended
    cmp eax,0xffffffdf
    je px_resume_wait
    cmp eax,64
    jne public_span_fail
    mov qword ptr [rbp+PN_X_ACTIVE],0
    cmp qword ptr [r12+PM_PENDING],0
    je public_span_fail
    dec qword ptr [r12+PM_PENDING]
    jmp px_resume_detach
px_resume_wait:
    cmp r13,2
    jne public_span_fail
px_resume_detach:
    mov rdi,rbp
    call pump_detach_frontend
    mov rdi,rbp
    call pump_handle_frontend
    mov qword ptr [r12+PM_CURRENT],0
    PM_RETURN

/* Ready is written only by an actual HIA reserved-lease completion. Poll
 * timeouts alone never re-enter a handler or advance its HIA phase. */
pump_service_extract:
    PM_SAVE
    cmp qword ptr [r12+PM_PHASE],3
    jae px_service_done
    mov rbp,[r12+PM_ALL]
px_service_next:
    test rbp,rbp
    jz px_service_done
    mov r14,[rbp+PN_NEXT]
    cmp qword ptr [rbp+PN_STATE],1
    jne px_service_advance
    cmp qword ptr [rbp+PN_X_ACTIVE],1
    jne px_service_advance
    mov rax,[rbp+PN_X_CONTEXT]
    test rax,rax
    jz public_span_fail
    cmp [rax+XW_NODE],rbp
    jne public_span_fail
    cmp qword ptr [rax+XW_READY],0
    je px_service_advance
    cmp qword ptr [rax+XW_READY],1
    jne public_span_fail
    mov rdi,rbp
    mov esi,2
    call pump_resume_node
px_service_advance:
    mov rbp,r14
    jmp px_service_next
px_service_done:
    PM_RETURN

pump_extract_retire:
    PM_SAVE
    mov rbp,rdi
    cmp qword ptr [rbp+PN_X_ACTIVE],0
    jne public_span_fail
    mov rdi,[rbp+PN_X_CONTEXT]
    test rdi,rdi
    jz px_retire_done
    mov rax,PX_OWNED
    cmp [rbp+PN_X_WORKMAP],rax
    jne public_span_fail
    cmp [rbp+PN_X_OUTMAP],rax
    jne public_span_fail
    cmp qword ptr [rbp+PN_X_INSTALLED],1
    jne public_span_fail
    call runtime_extract_body_release_context
    test eax,eax
    jnz public_span_fail
    mov qword ptr [rbp+PN_X_CONTEXT],0
    xor ebx,ebx
    lea r13,[rbp+PN_X_DESCRIPTORS]
    lea r14,[rbp+PN_X_CONTINUATIONS]
px_retire_slot:
    mov rax,[r14]
    or rax,[r14+8]
    jnz public_span_fail
    cmp ebx,4
    je px_retire_done_slots
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
    add r13,64
    add r14,64
    inc ebx
    jmp px_retire_slot
px_retire_done_slots:
    mov qword ptr [rbp+PN_X_INSTALLED],0
    mov qword ptr [rbp+PN_X_WORKMAP],0
    mov qword ptr [rbp+PN_X_OUTMAP],0
px_retire_done:
    PM_RETURN
