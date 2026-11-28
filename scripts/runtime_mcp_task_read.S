/* Copyright 2026 Muvon Un Limited
 * Copyright 2026 TrillionniumFoundation
 * SPDX-License-Identifier: Apache-2.0
 * Slots73/74 are detached together with their exact owned SSH caller future.
 * These original remote reads create no local workspace Scope or write fence. */
.intel_syntax noprefix
.section .text
.equ PR_MASK,1536 /* high ownership bits9 and10: slots73 and74 */
.equ PR_OUTPUT,512 /* slot74's capture is borrowed from its owned context */

pump_read_detach:
    PM_SAVE
    mov rbp,rdi
    mov rax,[rbp+PN_R_CONTEXT]
    or rax,[rbp+PN_R_WORKMAP]
    or rax,[rbp+PN_R_OUTMAP]
    jnz public_span_fail
    mov r13,[r15+8]
    add r13,73*64
    mov rax,[r13+64+8]
    test rax,rax
    jnz pr_detach_present
    cmp qword ptr [rbp+PN_R_ACTIVE],0
    jne public_span_fail
    jmp pr_detach_done
pr_detach_present:
    cmp [rax+456],r15
    jne public_span_fail
    mov rdx,[rax+432]
    test rdx,rdx
    jz pr_detach_bind
    cmp rdx,rbp
    jne public_span_fail
pr_detach_bind:
    mov [rax+432],rbp
    cmp qword ptr [rbp+PN_R_ACTIVE],1
    je pr_detach_waiting
    cmp qword ptr [rbp+PN_R_ACTIVE],0
    jne public_span_fail
    cmp qword ptr [rax+8],2
    je pr_detach_state
    cmp qword ptr [rax+8],3
    jne public_span_fail
    jmp pr_detach_state
pr_detach_waiting:
    cmp qword ptr [rax+8],1
    jne public_span_fail
pr_detach_state:
    mov [rbp+PN_R_CONTEXT],rax
    mov rax,[r15+RG_WORK_HIGH]
    and eax,PR_MASK
    cmp eax,PR_MASK
    jne public_span_fail
    mov [rbp+PN_R_WORKMAP],rax
    mov rax,[r15+RG_OUTPUT_HIGH]
    and eax,PR_MASK
    cmp eax,PR_OUTPUT
    jne public_span_fail
    mov [rbp+PN_R_OUTMAP],rax
    lea r14,[r15+512+73*64]
    xor ebx,ebx
pr_detach_slot:
    cmp qword ptr [rbp+PN_R_ACTIVE],0
    je pr_detach_idle
    cmp qword ptr [r14],1
    jne public_span_fail
    test ebx,ebx
    jnz pr_detach_body
    cmp qword ptr [r14+8],2
    jne public_span_fail
    cmp qword ptr [r14+24],74
    jne public_span_fail
    mov eax,0xffffffdf
    cmp [r14+48],rax
    jne public_span_fail
    cmp qword ptr [r14+56],0
    jne public_span_fail
    jmp pr_detach_wait_result
pr_detach_body:
    cmp qword ptr [r14+8],0
    jne public_span_fail
pr_detach_wait_result:
    mov eax,0xffffffdf
    cmp [r13+48],rax
    jne public_span_fail
    cmp qword ptr [r13+56],0
    jne public_span_fail
    jmp pr_detach_copy
pr_detach_idle:
    mov rax,[r14]
    or rax,[r14+8]
    jnz public_span_fail
pr_detach_copy:
    mov rax,rbx
    shl rax,6
    lea rdi,[rbp+rax+PN_R_DESCRIPTORS]
    mov rsi,r13
    mov ecx,8
    rep movsq
    mov rax,rbx
    shl rax,6
    lea rdi,[rbp+rax+PN_R_CONTINUATIONS]
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
    cmp ebx,2
    jb pr_detach_slot
    and qword ptr [r15+RG_WORK_HIGH],-1537
    and qword ptr [r15+RG_OUTPUT_HIGH],-1537
pr_detach_done:
    PM_RETURN

/* Only settled preflight rows can remain in the shared engine. */
pump_read_clear_idle:
    PM_SAVE
    mov r13,[r15+8]
    add r13,73*64
    lea r14,[r15+512+73*64]
    mov rax,[r14]
    or rax,[r14+8]
    or rax,[r14+64]
    or rax,[r14+72]
    jnz public_span_fail
    mov rax,[r13+64+8]
    or rax,[r13+64+16]
    or rax,[r13+64+32]
    or rax,[r13+64+40]
    jnz public_span_fail
    bt qword ptr [r15+RG_WORK_HIGH],10
    jc public_span_fail
    bt qword ptr [r15+RG_OUTPUT_HIGH],10
    jc public_span_fail
    bt qword ptr [r15+RG_WORK_HIGH],9
    jnc pr_idle_output
    mov rdi,[r13+8]
    test rdi,rdi
    jz public_span_fail
    mov rsi,[r13+16]
    add rsi,4096
    jc public_span_fail
    mov eax,11
    syscall
    test rax,rax
    jnz public_span_fail
    btr qword ptr [r15+RG_WORK_HIGH],9
pr_idle_output:
    bt qword ptr [r15+RG_OUTPUT_HIGH],9
    jnc pr_idle_clear
    mov rdi,[r13+32]
    test rdi,rdi
    jz public_span_fail
    mov rsi,[r13+40]
    add rsi,4096
    jc public_span_fail
    mov eax,11
    syscall
    test rax,rax
    jnz public_span_fail
    btr qword ptr [r15+RG_OUTPUT_HIGH],9
pr_idle_clear:
    lea rdi,[r13+8]
    mov ecx,7
    xor eax,eax
    rep stosq
    lea rdi,[r13+64+8]
    mov ecx,7
    rep stosq
    mov rdi,r14
    mov ecx,16
    rep stosq
    PM_RETURN

pump_read_restore:
    PM_SAVE
    mov rbp,rdi
    mov rax,[rbp+PN_R_CONTEXT]
    test rax,rax
    jnz pr_restore_present
    cmp qword ptr [rbp+PN_R_ACTIVE],0
    jne public_span_fail
    jmp pr_restore_done
pr_restore_present:
    cmp qword ptr [rbp+PN_R_ACTIVE],1
    jne public_span_fail
    cmp [rax+432],rbp
    jne public_span_fail
    cmp [rax+456],r15
    jne public_span_fail
    cmp qword ptr [rbp+PN_R_WORKMAP],PR_MASK
    jne public_span_fail
    cmp qword ptr [rbp+PN_R_OUTMAP],PR_OUTPUT
    jne public_span_fail
    call pump_read_clear_idle
    mov r13,[r15+8]
    add r13,73*64
    lea r14,[r15+512+73*64]
    xor ebx,ebx
pr_restore_slot:
    mov rax,rbx
    shl rax,6
    lea rsi,[rbp+rax+PN_R_DESCRIPTORS]
    mov rax,[rsi]
    cmp [r13],rax
    jne public_span_fail
    mov rdi,r13
    mov ecx,8
    rep movsq
    mov rax,rbx
    shl rax,6
    lea rsi,[rbp+rax+PN_R_CONTINUATIONS]
    mov rdi,r14
    mov ecx,8
    rep movsq
    add r13,64
    add r14,64
    inc ebx
    cmp ebx,2
    jb pr_restore_slot
    or qword ptr [r15+RG_WORK_HIGH],PR_MASK
    or qword ptr [r15+RG_OUTPUT_HIGH],PR_OUTPUT
    mov qword ptr [rbp+PN_R_CONTEXT],0
    mov qword ptr [rbp+PN_R_WORKMAP],0
    mov qword ptr [rbp+PN_R_OUTMAP],0
pr_restore_done:
    PM_RETURN

pump_read_pending:
    PM_SAVE
    mov rbp,rdi
    cmp qword ptr [rbp+PN_R_ACTIVE],1
    jne public_span_fail
    cmp qword ptr [rbp+PN_OWNERSHIP],3
    jne public_span_fail
    cmp qword ptr [rbp+PN_GENERATION],0
    je public_span_fail
    cmp qword ptr [rbp+PN_BOOTSTRAP],0
    jne public_span_fail
    mov rax,[rbp+PN_R_CONTEXT]
    test rax,rax
    jz public_span_fail
    cmp [rax+432],rbp
    jne public_span_fail
    cmp [rax+456],r15
    jne public_span_fail
    cmp qword ptr [rax+8],1
    jne public_span_fail
    cmp qword ptr [rbp+PN_CONTINUATION],1
    jne public_span_fail
    cmp qword ptr [rbp+PN_CONTINUATION+8],2
    jne public_span_fail
    cmp qword ptr [rbp+PN_CONTINUATION+24],73
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
    je pr_pending_existing
    cmp qword ptr [rbp+PN_STATE],0
    jne public_span_fail
    mov [rbp+PN_SEQUENCE],rax
    mov qword ptr [rbp+PN_STATE],1
    inc qword ptr [r12+PM_PENDING]
    jz public_span_fail
    jmp pr_pending_done
pr_pending_existing:
    cmp [rbp+PN_SEQUENCE],rax
    jne public_span_fail
pr_pending_done:
    mov qword ptr [rbp+PN_KIND],7 /* Actual owned-read WAIT; no public reply. */
    mov qword ptr [rbp+PN_EXTENT],0
    PM_RETURN

pump_resume_read:
    PM_SAVE
    mov rbp,rdi
    mov r13,rsi
    cmp qword ptr [rbp+PN_R_ACTIVE],1
    jne public_span_fail
    cmp r13,2
    je pr_resume_wake
    cmp r13,3
    jne public_span_fail
    cmp qword ptr [r12+PM_PHASE],3
    jb public_span_fail
    cmp qword ptr [rbp+PN_FUTURE_DROPPED],1
    jne public_span_fail
    jmp pr_resume_install
pr_resume_wake:
    cmp qword ptr [r12+PM_PHASE],3
    jae public_span_fail
    mov rax,[rbp+PN_R_CONTEXT]
    test rax,rax
    jz public_span_fail
    cmp qword ptr [rax+8],2
    jne public_span_fail
pr_resume_install:
    mov rdi,rbp
    call pump_restore_frontend
    mov [r12+PM_CURRENT],rbp
    mov rdi,[rbp+PN_INPUT]
    mov rsi,[rbp+PN_INPUT_LENGTH]
    mov r8d,18
    mov r9,r13
    call runtime_grow_suspended
    cmp eax,0xffffffdf
    je pr_resume_wait
    cmp eax,64
    jne public_span_fail
    mov qword ptr [rbp+PN_R_ACTIVE],0
    cmp qword ptr [r12+PM_PENDING],0
    je public_span_fail
    dec qword ptr [r12+PM_PENDING]
    jmp pr_resume_detach
pr_resume_wait:
    cmp r13,2
    jne public_span_fail
pr_resume_detach:
    mov rdi,rbp
    call pump_detach_frontend
    mov rdi,rbp
    call pump_handle_frontend
    mov qword ptr [r12+PM_CURRENT],0
    PM_RETURN

/* Poll observes the same original caller future. A timer tick alone cannot
 * complete a child, replay submit, or advance its HIA continuation. */
pump_service_read:
    PM_SAVE
    cmp qword ptr [r12+PM_PHASE],3
    jae pr_service_done
    mov rbp,[r12+PM_ALL]
pr_service_next:
    test rbp,rbp
    jz pr_service_done
    mov r14,[rbp+PN_NEXT]
    cmp qword ptr [rbp+PN_STATE],1
    jne pr_service_advance
    cmp qword ptr [rbp+PN_R_ACTIVE],1
    jne pr_service_advance
    mov rdi,[rbp+PN_R_CONTEXT]
    test rdi,rdi
    jz public_span_fail
    cmp [rdi+432],rbp
    jne public_span_fail
    cmp [rdi+456],r15
    jne public_span_fail
    call runtime_read_request_poll
    cmp rax,1
    je pr_service_advance
    test rax,rax
    jnz public_span_fail
    mov rdi,rbp
    mov esi,2
    call pump_resume_node
pr_service_advance:
    mov rbp,r14
    jmp pr_service_next
pr_service_done:
    PM_RETURN

pump_read_retire:
    PM_SAVE
    mov rbp,rdi
    cmp qword ptr [rbp+PN_R_ACTIVE],0
    jne public_span_fail
    mov rdi,[rbp+PN_R_CONTEXT]
    test rdi,rdi
    jz pr_retire_done
    cmp qword ptr [rbp+PN_R_WORKMAP],PR_MASK
    jne public_span_fail
    cmp qword ptr [rbp+PN_R_OUTMAP],PR_OUTPUT
    jne public_span_fail
    cmp [rdi+432],rbp
    jne public_span_fail
    cmp [rdi+456],r15
    jne public_span_fail
    cmp qword ptr [rdi+8],2
    je pr_retire_admitted
    cmp qword ptr [rdi+8],3
    jne public_span_fail
pr_retire_admitted:
    call runtime_read_request_reset
    test rax,rax
    jnz public_span_fail
    lea r13,[rbp+PN_R_DESCRIPTORS]
    lea r14,[rbp+PN_R_CONTINUATIONS]
    xor ebx,ebx
pr_retire_slot:
    mov rax,[r14]
    or rax,[r14+8]
    jnz public_span_fail
    mov rdi,[r13+8]
    test rdi,rdi
    jz public_span_fail
    mov rsi,[r13+16]
    add rsi,4096
    jc public_span_fail
    mov eax,11
    syscall
    test rax,rax
    jnz public_span_fail
    test ebx,ebx
    jnz pr_retire_advance
    mov rdi,[r13+32]
    test rdi,rdi
    jz public_span_fail
    mov rsi,[r13+40]
    add rsi,4096
    jc public_span_fail
    mov eax,11
    syscall
    test rax,rax
    jnz public_span_fail
pr_retire_advance:
    add r13,64
    add r14,64
    inc ebx
    cmp ebx,2
    jb pr_retire_slot
    mov qword ptr [rbp+PN_R_CONTEXT],0
    mov qword ptr [rbp+PN_R_WORKMAP],0
    mov qword ptr [rbp+PN_R_OUTMAP],0
pr_retire_done:
    PM_RETURN

pump_close_read:
    PM_SAVE
pr_close_again:
    lea rdi,[r12+PM_READ_HUB]
    call runtime_read_public_close
    test rax,rax
    jz pr_close_done
    cmp rax,1
    jne public_span_fail
    call pump_wait
    jmp pr_close_again
pr_close_done:
    xor eax,eax
    PM_RETURN
