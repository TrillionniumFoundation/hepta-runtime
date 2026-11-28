/* The process event-loop is the only outer writer of SSH call lifetimes.
 * Seven private rows move with each request. The hub and HIA registry are
 * shared across sessions; a dropped future never owns the child reap. */
.intel_syntax noprefix
.section .text
.equ PH_MASK,0x3f80
.equ PH_WORK,0x1f80

pump_ssh_detach:
    PM_SAVE
    mov rbp,rdi
    mov rax,[rbp+PN_H_PRESENT]
    or rax,[rbp+PN_H_CONTEXT]
    or rax,[rbp+PN_H_WORKMAP]
    or rax,[rbp+PN_H_OUTMAP]
    jnz public_span_fail
    mov rax,[r15+RG_WORK_HIGH]
    and rax,PH_MASK
    mov rdx,rax
    and rdx,PH_WORK
    cmp rdx,rax
    jne public_span_fail
    mov [rbp+PN_H_WORKMAP],rax
    mov rdx,[r15+RG_OUTPUT_HIGH]
    and rdx,PH_MASK
    mov [rbp+PN_H_OUTMAP],rdx
    or rax,rdx
    or rax,[r15+488]
    jnz ph_detach_present
    cmp qword ptr [rbp+PN_H_ACTIVE],0
    jne public_span_fail
    jmp ph_detach_done
ph_detach_present:
    cmp qword ptr [rbp+PN_H_ACTIVE],1
    ja public_span_fail
    jne ph_detach_idle_context
    mov rax,[r15+488]
    test rax,rax
    jz public_span_fail
    mov rdx,[r15+480]
    cmp [rax+8],rdx
    jne public_span_fail
    mov [rbp+PN_H_CONTEXT],rax
    jmp ph_detach_rows
ph_detach_idle_context:
    cmp qword ptr [r15+488],0
    jne public_span_fail
ph_detach_rows:
    mov qword ptr [rbp+PN_H_PRESENT],1
    mov r13,[r15+8]
    add r13,71*64
    lea r14,[r15+512+71*64]
    xor ebx,ebx
ph_detach_slot:
    cmp qword ptr [rbp+PN_H_ACTIVE],0
    je ph_detach_idle
    test ebx,ebx
    jz ph_detach_wait
    cmp ebx,3
    je ph_detach_wait
    cmp ebx,6
    je ph_detach_body
ph_detach_idle:
    mov rax,[r14]
    or rax,[r14+8]
    jnz public_span_fail
    jmp ph_detach_copy
ph_detach_wait:
    cmp qword ptr [r14],1
    jne public_span_fail
    cmp qword ptr [r14+8],2
    jne public_span_fail
    mov eax,0xffffffdf
    cmp [r14+48],rax
    jne public_span_fail
    cmp qword ptr [r14+56],0
    jne public_span_fail
    jmp ph_detach_wait_output
ph_detach_body:
    cmp qword ptr [r14],1
    jne public_span_fail
    cmp qword ptr [r14+8],0
    jne public_span_fail
ph_detach_wait_output:
    mov eax,0xffffffdf
    cmp [r13+48],rax
    jne public_span_fail
    cmp qword ptr [r13+56],0
    jne public_span_fail
ph_detach_copy:
    mov rax,rbx
    shl rax,6
    lea rdi,[rbp+rax+PN_H_DESCRIPTORS]
    mov rsi,r13
    mov ecx,8
    rep movsq
    mov rax,rbx
    shl rax,6
    lea rdi,[rbp+rax+PN_H_CONTINUATIONS]
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
    cmp ebx,7
    jb ph_detach_slot
    and qword ptr [r15+RG_WORK_HIGH],~PH_MASK
    and qword ptr [r15+RG_OUTPUT_HIGH],~PH_MASK
    mov qword ptr [r15+488],0
ph_detach_done:
    PM_RETURN

pump_ssh_restore:
    PM_SAVE
    mov rbp,rdi
    cmp qword ptr [rbp+PN_H_PRESENT],0
    je ph_restore_absent
    cmp qword ptr [rbp+PN_H_PRESENT],1
    jne public_span_fail
    cmp qword ptr [rbp+PN_H_ACTIVE],1
    jne public_span_fail
    cmp qword ptr [r15+488],0
    jne public_span_fail
    mov rax,[r15+RG_WORK_HIGH]
    or rax,[r15+RG_OUTPUT_HIGH]
    and rax,PH_MASK
    jnz public_span_fail
    mov rax,[rbp+PN_H_CONTEXT]
    test rax,rax
    jz public_span_fail
    mov rdx,[r15+480]
    cmp [rax+8],rdx
    jne public_span_fail
    mov r13,[r15+8]
    add r13,71*64
    lea r14,[r15+512+71*64]
    xor ebx,ebx
ph_restore_slot:
    mov rax,[r13+8]
    or rax,[r13+16]
    or rax,[r13+24]
    or rax,[r13+32]
    or rax,[r13+40]
    or rax,[r13+48]
    or rax,[r13+56]
    jnz public_span_fail
    mov rax,[r14]
    or rax,[r14+8]
    jnz public_span_fail
    mov rax,rbx
    shl rax,6
    lea rsi,[rbp+rax+PN_H_DESCRIPTORS]
    mov rax,[rsi]
    cmp [r13],rax
    jne public_span_fail
    mov rdi,r13
    mov ecx,8
    rep movsq
    mov rax,rbx
    shl rax,6
    lea rsi,[rbp+rax+PN_H_CONTINUATIONS]
    mov rdi,r14
    mov ecx,8
    rep movsq
    add r13,64
    add r14,64
    inc ebx
    cmp ebx,7
    jb ph_restore_slot
    mov rax,[rbp+PN_H_WORKMAP]
    or [r15+RG_WORK_HIGH],rax
    mov rax,[rbp+PN_H_OUTMAP]
    or [r15+RG_OUTPUT_HIGH],rax
    mov rax,[rbp+PN_H_CONTEXT]
    mov [r15+488],rax
    mov qword ptr [rbp+PN_H_PRESENT],0
    mov qword ptr [rbp+PN_H_CONTEXT],0
    mov qword ptr [rbp+PN_H_WORKMAP],0
    mov qword ptr [rbp+PN_H_OUTMAP],0
    jmp ph_restore_done
ph_restore_absent:
    cmp qword ptr [rbp+PN_H_ACTIVE],0
    jne public_span_fail
ph_restore_done:
    PM_RETURN

pump_ssh_pending:
    PM_SAVE
    mov rbp,rdi
    cmp qword ptr [rbp+PN_H_ACTIVE],1
    jne public_span_fail
    cmp qword ptr [rbp+PN_H_PRESENT],1
    jne public_span_fail
    cmp qword ptr [rbp+PN_OWNERSHIP],3
    jne public_span_fail
    cmp qword ptr [rbp+PN_GENERATION],0
    je public_span_fail
    cmp qword ptr [rbp+PN_BOOTSTRAP],0
    jne public_span_fail
    mov rax,[rbp+PN_H_CONTEXT]
    test rax,rax
    jz public_span_fail
    mov rdx,[r15+480]
    cmp [rax+8],rdx
    jne public_span_fail
    cmp qword ptr [rbp+PN_CONTINUATION],1
    jne public_span_fail
    cmp qword ptr [rbp+PN_CONTINUATION+8],2
    jne public_span_fail
    cmp qword ptr [rbp+PN_CONTINUATION+24],71
    jne public_span_fail
    cmp qword ptr [rbp+PN_H_CONTINUATIONS+24],74
    jne public_span_fail
    cmp qword ptr [rbp+PN_H_CONTINUATIONS+3*64+24],77
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
    je ph_pending_existing
    cmp qword ptr [rbp+PN_STATE],0
    jne public_span_fail
    mov [rbp+PN_SEQUENCE],rax
    mov qword ptr [rbp+PN_STATE],1
    inc qword ptr [r12+PM_PENDING]
    jz public_span_fail
    jmp ph_pending_done
ph_pending_existing:
    cmp [rbp+PN_SEQUENCE],rax
    jne public_span_fail
ph_pending_done:
    mov qword ptr [rbp+PN_KIND],5
    mov qword ptr [rbp+PN_EXTENT],0
    PM_RETURN

pump_resume_ssh:
    PM_SAVE
    mov rbp,rdi
    mov r13,rsi
    cmp qword ptr [rbp+PN_H_ACTIVE],1
    jne public_span_fail
    cmp r13,2
    je ph_resume_wake
    cmp r13,3
    jne public_span_fail
    cmp qword ptr [r12+PM_PHASE],3
    jb public_span_fail
    cmp qword ptr [rbp+PN_FUTURE_DROPPED],1
    jne public_span_fail
    jmp ph_resume_install
ph_resume_wake:
    cmp qword ptr [r12+PM_PHASE],3
    jae public_span_fail
ph_resume_install:
    mov rdi,rbp
    call pump_restore_frontend
    mov [r12+PM_CURRENT],rbp
    mov rdi,[rbp+PN_INPUT]
    mov rsi,[rbp+PN_INPUT_LENGTH]
    mov r8d,18
    mov r9,r13
    call runtime_grow_suspended
    cmp eax,0xffffffdf
    je ph_resume_wait
    cmp eax,64
    jne public_span_fail
    mov qword ptr [rbp+PN_H_ACTIVE],0
    cmp qword ptr [r12+PM_PENDING],0
    je public_span_fail
    dec qword ptr [r12+PM_PENDING]
    jmp ph_resume_detach
ph_resume_wait:
    cmp r13,2
    jne public_span_fail
ph_resume_detach:
    mov rdi,rbp
    call pump_detach_frontend
    mov rdi,rbp
    call pump_handle_frontend
    mov qword ptr [r12+PM_CURRENT],0
    PM_RETURN

/* A wake only requests a poll. Completion requires the kernel clear-TID plus
 * the original HIA terminal state; time or readable eventfd is never enough. */
pump_service_ssh:
    PM_SAVE
    sub rsp,48
    call pump_ssh_drain_wake
    cmp qword ptr [r12+PM_PHASE],3
    jae ph_service_done
    mov rbp,[r12+PM_ALL]
ph_service_next:
    test rbp,rbp
    jz ph_service_done
    mov r14,[rbp+PN_NEXT]
    cmp qword ptr [rbp+PN_STATE],1
    jne ph_service_advance
    cmp qword ptr [rbp+PN_H_ACTIVE],1
    jne ph_service_advance
    mov rdi,[rbp+PN_H_CONTEXT]
    test rdi,rdi
    jz public_span_fail
    mov rsi,rsp
    call hsw_poll
    cmp eax,0xffffffdf
    je ph_service_advance
    test eax,eax
    jnz public_span_fail
    mov rdi,rbp
    mov esi,2
    call pump_resume_node
ph_service_advance:
    mov rbp,r14
    jmp ph_service_next
ph_service_done:
    add rsp,48
    PM_RETURN

pump_ssh_retire:
    PM_SAVE
    mov rbp,rdi
    mov rax,[rbp+PN_H_ACTIVE]
    or rax,[rbp+PN_H_CONTEXT]
    jnz public_span_fail
    cmp qword ptr [rbp+PN_H_PRESENT],0
    je ph_retire_done
    cmp qword ptr [rbp+PN_H_PRESENT],1
    jne public_span_fail
    xor ebx,ebx
ph_retire_next:
    mov rax,rbx
    shl rax,6
    lea r13,[rbp+rax+PN_H_DESCRIPTORS]
    lea r14,[rbp+rax+PN_H_CONTINUATIONS]
    mov rax,[r14]
    or rax,[r14+8]
    jnz public_span_fail
    lea rcx,[rbx+7]
    bt qword ptr [rbp+PN_H_WORKMAP],rcx
    jnc ph_retire_output
    cmp ebx,6
    je public_span_fail
    mov rdi,[r13+8]
    mov rsi,[r13+16]
    test rdi,rdi
    jz public_span_fail
    test rsi,rsi
    jz public_span_fail
    add rsi,4096
    jc public_span_fail
    mov eax,11
    syscall
    test rax,rax
    jnz public_span_fail
ph_retire_output:
    lea rcx,[rbx+7]
    bt qword ptr [rbp+PN_H_OUTMAP],rcx
    jnc ph_retire_advance
    mov rdi,[r13+32]
    mov rsi,[r13+40]
    test rdi,rdi
    jz public_span_fail
    test rsi,rsi
    jz public_span_fail
    add rsi,4096
    jc public_span_fail
    mov eax,11
    syscall
    test rax,rax
    jnz public_span_fail
ph_retire_advance:
    inc ebx
    cmp ebx,7
    jb ph_retire_next
    mov qword ptr [rbp+PN_H_PRESENT],0
    mov qword ptr [rbp+PN_H_WORKMAP],0
    mov qword ptr [rbp+PN_H_OUTMAP],0
ph_retire_done:
    PM_RETURN

pump_ssh_wake_fd:
    mov rax,[r15+400]
    test rax,rax
    jz ph_wake_absent
    mov rax,[rax+224]
    test rax,rax
    jz ph_wake_absent
    mov rax,[rax+120]
    ret
ph_wake_absent:
    mov rax,-1
    ret
pump_ssh_drain_wake:
    sub rsp,24
    call pump_ssh_wake_fd
    cmp rax,-1
    je ph_drain_done
    mov [rsp+8],rax
ph_drain_next:
    mov rdi,[rsp+8]
    mov rsi,rsp
    mov edx,8
    xor eax,eax
    syscall
    cmp rax,-4
    je ph_drain_next
    cmp rax,-11
    je ph_drain_done
    cmp rax,8
    jne public_span_fail
    jmp ph_drain_next
ph_drain_done:
    add rsp,24
    ret

pump_ssh_close:
    PM_SAVE
    mov rax,[r15+400]
    mov rdi,[rax+224]
    test rdi,rdi
    jz ph_close_done
    call hsw_freeze
    test rax,rax
    jnz public_span_fail
ph_close_done:
    PM_RETURN

/* Return1 only while an actual retained worker has not joined. After all
 * joined calls are released, destroy the same root and its sealed RX inputs. */
pump_ssh_destroy:
    PM_SAVE
    sub rsp,48
    mov rbx,[r15+400]
    mov r13,[rbx+224]
    test r13,r13
    jz ph_destroy_absent
    cmp qword ptr [r13+96],1
    jne public_span_fail
ph_destroy_next:
    mov rdi,[r13+128]
    test rdi,rdi
    jz ph_destroy_root
    mov rbp,rdi
    mov rsi,rsp
    call hsw_poll
    cmp eax,0xffffffdf
    je ph_destroy_pending
    test eax,eax
    jnz public_span_fail
    mov rdi,rbp
    call hsw_release
    test rax,rax
    jnz public_span_fail
    jmp ph_destroy_next
ph_destroy_root:
    mov rdi,r13
    call hsw_destroy
    cmp eax,0xffffffdf
    je ph_destroy_pending
    test rax,rax
    jnz public_span_fail
    mov rax,[rbx+232]
    test rax,rax
    jz public_span_fail
    mov qword ptr [rax+56],0
    mov qword ptr [rbx+224],0
    mov qword ptr [r15+480],0
    mov rdi,rbx
    call runtime_ssh_install_destroy
    test rax,rax
    jnz public_span_fail
ph_destroy_absent:
    xor eax,eax
    jmp ph_destroy_done
ph_destroy_pending:
    mov eax,1
ph_destroy_done:
    add rsp,48
    PM_RETURN
