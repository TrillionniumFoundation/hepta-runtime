/* Process-owned file embedding of the qualified generic direct SSH graph.
 * All public methods are serialized by the existing event-loop. The independent
 * generic owner retains its exact requests, descriptors and child after a
 * handler disappears. This file only captures bytes and forwards HIA receipts.
 */
.intel_syntax noprefix
.section .text
.equ HSW_ROOT,0x31544f4f52475348 /* HSGROOT1 */
.equ HSW_CALL,0x314c4c4143475348 /* HSGCALL1 */
.equ HSW_PENDING,0xffffffdf
.equ HSW_UNCERTAIN,0xfffffff9
.macro HSW_SAVE
    push rbp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub rsp,280
.endm
.macro HSW_RETURN
    add rsp,280
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret
.endm

/* Private table HSGWK001: version1,actual kernel envp,sealed OpenSSH fd,
 * generation,three zeros. Images and all API functions are fixed code labels. */
.global ssh_native_worker
ssh_native_worker:
    HSW_SAVE
    mov r13,rdi
    test r13,r13
    jz hsw_create_bad
    movabs rax,0x3130304b57475348
    cmp [r13],rax
    jne hsw_create_bad
    cmp qword ptr [r13+8],1
    jne hsw_create_bad
    cmp qword ptr [r13+16],0
    je hsw_create_bad
    cmp qword ptr [r13+32],0
    je hsw_create_bad
    mov rax,[r13+40]
    or rax,[r13+48]
    or rax,[r13+56]
    jnz hsw_create_bad
    mov rdi,[r13+24]
    mov esi,1034
    xor edx,edx
    mov eax,72
    syscall
    cmp eax,15
    jne hsw_create_bad
    mov edi,4096
    call ssh_alloc
    test rax,rax
    js hsw_create_return
    mov r12,rax
    movabs rax,HSW_ROOT
    mov [r12],rax
    mov qword ptr [r12+56],-1
    mov qword ptr [r12+120],-1
    mov rax,[r13+32]
    mov [r12+64],rax
    mov rdi,[r13+24]
    mov esi,1030
    mov edx,3
    mov eax,72
    syscall
    test rax,rax
    js hsw_create_fail
    mov [r12+56],rax
    xor edi,edi
    mov esi,0x80800
    mov eax,290
    syscall
    test rax,rax
    js hsw_create_fail
    mov [r12+120],rax
    mov r14,[r13+16]
    xor ebx,ebx
    xor r15d,r15d
hsw_env_measure:
    mov rsi,[r14+rbx*8]
    test rsi,rsi
    jz hsw_env_allocate
    xor ecx,ecx
hsw_env_length:
    cmp byte ptr [rsi+rcx],0
    je hsw_env_measured
    inc rcx
    jnz hsw_env_length
    jmp hsw_create_overflow
hsw_env_measured:
    add r15,8
    jc hsw_create_overflow
    add r15,rcx
    jc hsw_create_overflow
    inc rbx
    jnz hsw_env_measure
    jmp hsw_create_overflow
hsw_env_allocate:
    mov [r12+32],r15
    mov [r12+40],rbx
    mov rdi,r15
    call ssh_alloc
    test rax,rax
    js hsw_create_fail
    mov [r12+16],rax
    mov [r12+24],rdx
    mov rbp,rax
    xor ebx,ebx
hsw_env_copy:
    cmp rbx,[r12+40]
    jae hsw_env_copied
    mov rsi,[r14+rbx*8]
    test rsi,rsi
    jz hsw_create_protocol
    xor ecx,ecx
hsw_env_copy_length:
    cmp byte ptr [rsi+rcx],0
    je hsw_env_copy_bytes
    inc rcx
    jnz hsw_env_copy_length
    jmp hsw_create_overflow
hsw_env_copy_bytes:
    mov rax,rbp
    sub rax,[r12+16]
    add rax,8
    jc hsw_create_overflow
    add rax,rcx
    jc hsw_create_overflow
    cmp rax,[r12+32]
    ja hsw_create_protocol
    mov [rbp],rcx
    lea rdi,[rbp+8]
    rep movsb
    mov rbp,rdi
    inc rbx
    jmp hsw_env_copy
hsw_env_copied:
    sub rbp,[r12+16]
    cmp rbp,[r12+32]
    jne hsw_create_protocol
    cmp qword ptr [r14+rbx*8],0
    jne hsw_create_protocol
    xor edi,edi
    xor esi,esi
    call ssh_direct_owner_create
    test rax,rax
    js hsw_create_fail
    mov [r12+72],rax
    mov rdi,rax
    mov rsi,[r12+120]
    call ssh_direct_owner_set_wake
    test rax,rax
    jnz hsw_create_held
    mov rax,r12
    jmp hsw_create_return
hsw_create_held:
    /* An already-created independent owner is retained on setup uncertainty. */
    mov qword ptr [r12+104],1
    mov rax,r12
    jmp hsw_create_return
hsw_create_overflow:
    mov rax,-75
    jmp hsw_create_fail
hsw_create_protocol:
    mov rax,-71
hsw_create_fail:
    mov [rsp+272],rax
    mov rdi,[r12+16]
    mov rsi,[r12+24]
    call ssh_free
    mov rdi,[r12+56]
    test rdi,rdi
    js hsw_create_close_wake
    mov eax,3
    syscall
hsw_create_close_wake:
    mov rdi,[r12+120]
    test rdi,rdi
    js hsw_create_unmap
    mov eax,3
    syscall
hsw_create_unmap:
    mov rdi,r12
    mov esi,4096
    call ssh_free
    mov rax,[rsp+272]
    jmp hsw_create_return
hsw_create_bad:
    mov rax,-22
hsw_create_return:
    HSW_RETURN

/* Only the captured admitted plan can produce the command; the HIA adapter
 * checks all fixed argv, operation and lengths before generic submit. */
hsw_start:
    HSW_SAVE
    mov r12,rdi
    mov r13,rsi
    mov r14,rdx
    mov [rsp+264],rcx
    call hsw_root_check
    test eax,eax
    jz hsw_start_bad
    cmp qword ptr [r12+96],0
    jne hsw_start_cancelled
    cmp qword ptr [r12+104],0
    jne hsw_start_protocol_no_call
    cmp r14,128
    jb hsw_start_bad
    call hsw_clock
    test rax,rax
    js hsw_start_return
    mov rcx,30000000000
    add rax,rcx
    jc hsw_start_overflow_no_call
    cmp qword ptr [rsp+264],0
    cmovne rax,[rsp+264]
    mov [rsp+256],rax
    mov edi,4096
    call ssh_alloc
    test rax,rax
    js hsw_start_return
    mov rbx,rax
    movabs rax,HSW_CALL
    mov [rbx],rax
    mov [rbx+8],r12
    mov rax,[rsp+256]
    mov [rbx+120],rax
    lea rdi,[r14+64]
    cmp rdi,r14
    jb hsw_start_overflow
    call ssh_alloc
    test rax,rax
    js hsw_start_fail
    mov [rbx+24],rax
    mov [rbx+40],rdx
    lea rcx,[r14+64]
    mov [rbx+32],rcx
    lea rdi,[rax+64]
    mov rsi,r13
    mov rcx,r14
    rep movsb
    lea rdi,[r14+64]
    add rdi,[r12+32]
    jc hsw_start_overflow
    mov [rbx+64],rdi
    call ssh_alloc
    test rax,rax
    js hsw_start_fail
    mov [rbx+48],rax
    mov [rbx+56],rdx
    mov rbp,rax
    movabs rcx,0x3130444d43475348 /* HSGCMD01 */
    mov [rbp],rcx
    mov qword ptr [rbp+8],1
    mov rax,[r12+56]
    mov [rbp+16],rax
    mov [rbp+24],r14
    mov rax,[r12+40]
    mov [rbp+32],rax
    mov rax,[r12+32]
    mov [rbp+40],rax
    lea rdi,[rbp+64]
    mov rsi,[rbx+24]
    add rsi,64
    mov rcx,r14
    rep movsb
    mov rsi,[r12+16]
    mov rcx,[r12+32]
    rep movsb
    mov edi,256
    call ssh_alloc
    test rax,rax
    js hsw_start_fail
    mov [rbx+80],rax
    mov [rbx+88],rdx
hsw_start_frame:
    mov rdi,[rbx+48]
    mov rsi,[rbx+64]
    mov rdx,[rbx+80]
    mov rcx,[rbx+88]
    xor r8d,r8d
    xor r9d,r9d
    call qword ptr [rip+runtime_ssh_images+40]
    cmp eax,0xffffffd0
    je hsw_start_grow
    cmp rax,64
    jb hsw_start_protocol
    mov ecx,0xffff0000
    cmp rax,rcx
    jae hsw_start_protocol
    cmp rax,[rbx+88]
    ja hsw_start_protocol
    mov [rbx+96],rax
    mov rbp,[rbx+80]
    movabs rcx,0x3130524d43475348 /* HSGCMR01 */
    cmp [rbp],rcx
    jne hsw_start_protocol
    cmp [rbp+8],rax
    jne hsw_start_protocol
    mov rdx,[rbp+16]
    add rdx,[rbp+24]
    jc hsw_start_protocol
    add rdx,64
    jc hsw_start_protocol
    cmp rdx,rax
    jne hsw_start_protocol
    mov rdi,rsp
    xor eax,eax
    mov ecx,8
    rep stosq
    mov rax,[rbx+120]
    mov [rsp],rax
    mov rdi,[r12+72]
    lea rsi,[rbp+64]
    mov rdx,[rbp+16]
    lea rcx,[rsi+rdx]
    mov r8,[rbp+24]
    mov r9,rsp
    call ssh_direct_submit
    test rax,rax
    js hsw_start_fail
    mov [rbx+72],rax
    mov rcx,[rax+R_GENERATION]
    mov [rbx+112],rcx
    mov qword ptr [rbx+104],1
    mov rax,[r12+128]
    mov [rbx+16],rax
    mov [r12+128],rbx
    inc qword ptr [r12+88]
    mov rdi,[r12+72]
    call ssh_runtime_owner_notify
    mov rax,rbx
    jmp hsw_start_return
hsw_start_grow:
    mov rbp,[rbx+80]
    movabs rcx,0x3230305357524748
    cmp [rbp],rcx
    jne hsw_start_protocol
    cmp qword ptr [rbp+8],2
    jne hsw_start_protocol
    cmp qword ptr [rbp+24],0
    jne hsw_start_protocol
    mov rdi,[rbp+16]
    cmp rdi,[rbx+88]
    jbe hsw_start_protocol
    call ssh_alloc
    test rax,rax
    js hsw_start_fail
    mov r13,rax
    mov r14,rdx
    mov rdi,[rbx+80]
    mov rsi,[rbx+88]
    call ssh_free
    test rax,rax
    jnz hsw_start_fail
    mov [rbx+80],r13
    mov [rbx+88],r14
    jmp hsw_start_frame
hsw_start_overflow:
    mov rax,-75
    jmp hsw_start_fail
hsw_start_protocol:
    mov rax,-71
hsw_start_fail:
    mov [rsp+272],rax
    mov rdi,rbx
    call hsw_free_buffers
    mov rax,[rsp+272]
    jmp hsw_start_return
hsw_start_overflow_no_call:
    mov rax,-75
    jmp hsw_start_return
hsw_start_protocol_no_call:
    mov rax,-71
    jmp hsw_start_return
hsw_start_cancelled:
    mov rax,-125
    jmp hsw_start_return
hsw_start_bad:
    mov rax,-22
hsw_start_return:
    HSW_RETURN

/* Poll never relinquishes the real generic request. A cached caller error
 * may precede cleanup; retain the call until actual phase5 and no registration. */
hsw_poll:
    HSW_SAVE
    mov rbx,rdi
    mov r13,rsi
    call hsw_call_check
    test eax,eax
    jz hsw_poll_bad
    test r13,r13
    jz hsw_poll_bad
    cmp qword ptr [rbx+104],2
    je hsw_poll_ready
    cmp qword ptr [rbx+104],1
    jne hsw_poll_uncertain
    mov rbp,[rbx+72]
    mov rdi,rbp
    lea rsi,[rbx+256]
    call ssh_direct_capture_result
    cmp eax,1
    je hsw_poll_pending
    test rax,rax
    jnz hsw_poll_broken
    cmp qword ptr [rbp+R_DONE],1
    jne hsw_poll_pending
    cmp qword ptr [rbp+R_PHASE],5
    jne hsw_poll_broken
    mov rax,[rbp+R_REGISTERED]
    or rax,[rbp+R_TASK]
    or rax,[rbp+R_GUARD_OWNED]
    or rax,[rbp+R_ENTRY]
    jnz hsw_poll_broken
    mov r14,[rbx+256+56]
    mov r15,[rbx+256+72]
    cmp r14,8388608
    ja hsw_poll_broken
    cmp r15,8388608
    ja hsw_poll_broken
    lea rdi,[r14+r15+128]
    mov [rbx+144],rdi
    call ssh_alloc
    test rax,rax
    js hsw_poll_broken
    mov [rbx+128],rax
    mov [rbx+136],rdx
    mov r12,rax
    movabs rcx,0x3130505352475348 /* HSGRSP01 */
    mov [r12],rcx
    mov qword ptr [r12+8],1
    mov rax,[rbx+112]
    mov [r12+16],rax
    mov rsi,[rbx+24]
    mov rax,[rsi+80]
    mov [r12+24],rax
    mov rax,[rsi+88]
    mov [r12+32],rax
    mov rax,[rbx+256+16]
    mov [r12+40],rax
    mov rax,[rbx+256+24]
    mov [r12+48],rax
    mov rax,[rbx+256+32]
    mov [r12+56],rax
    mov rax,[rbx+256+40]
    mov [r12+64],rax
    mov [r12+72],r14
    mov [r12+80],r15
    mov rax,[rbp+R_PID]
    mov [r12+88],rax
    mov ecx,8
    cmp qword ptr [rbp+R_ADM_WORK+24],2
    jne hsw_poll_no_commit
    or ecx,1
hsw_poll_no_commit:
    cmp qword ptr [rbp+R_PID],0
    je hsw_poll_no_spawn
    or ecx,2
hsw_poll_no_spawn:
    cmp qword ptr [rbp+R_CHILD_WORK+48],1
    jne hsw_poll_no_reap
    or ecx,4
hsw_poll_no_reap:
    mov [r12+96],rcx
    mov rax,[rbp+R_GENERATION]
    mov [r12+104],rax
    lea rdi,[r12+128]
    mov rsi,[rbx+256+48]
    mov rcx,r14
    rep movsb
    mov rsi,[rbx+256+64]
    mov rcx,r15
    rep movsb
    mov rdi,[rbx+144]
    call ssh_alloc
    test rax,rax
    js hsw_poll_broken
    mov [rbx+152],rax
    mov [rbx+160],rdx
    mov rdi,[rbx+128]
    mov rsi,[rbx+144]
    mov rdx,rax
    mov rcx,[rbx+160]
    xor r8d,r8d
    xor r9d,r9d
    call qword ptr [rip+runtime_ssh_images+40]
    cmp rax,[rbx+144]
    jne hsw_poll_broken
    mov [rbx+168],rax
    mov qword ptr [rbx+104],2
hsw_poll_ready:
    mov rax,[rbx+152]
    mov [r13],rax
    mov rax,[rbx+168]
    mov [r13+8],rax
    mov [r13+16],rax
    mov qword ptr [r13+24],0
    mov qword ptr [r13+32],2
    xor eax,eax
    jmp hsw_poll_return
hsw_poll_broken:
    mov qword ptr [rbx+104],3
    mov rax,[rbx+8]
    mov qword ptr [rax+104],1
hsw_poll_uncertain:
    mov eax,HSW_UNCERTAIN
    jmp hsw_poll_return
hsw_poll_pending:
    mov eax,HSW_PENDING
    jmp hsw_poll_return
hsw_poll_bad:
    mov eax,0xffffffff
hsw_poll_return:
    HSW_RETURN

hsw_cancel:
    HSW_SAVE
    mov rbx,rdi
    mov r13,rsi
    call hsw_call_check
    test eax,eax
    jz hsw_cancel_bad
    test r13,r13
    jz hsw_cancel_bad
    cmp r13,3
    ja hsw_cancel_bad
    cmp qword ptr [rbx+104],1
    jne hsw_cancel_ok
    mov rdi,[rbx+72]
    call ssh_direct_cancel
    jmp hsw_cancel_return
hsw_cancel_ok:
    xor eax,eax
    jmp hsw_cancel_return
hsw_cancel_bad:
    mov rax,-22
hsw_cancel_return:
    HSW_RETURN

hsw_release:
    HSW_SAVE
    mov rbx,rdi
    call hsw_call_check
    test eax,eax
    jz hsw_release_bad
    cmp qword ptr [rbx+104],2
    jne hsw_release_busy
    mov r12,[rbx+8]
    lea rdx,[r12+128]
hsw_release_find:
    mov rax,[rdx]
    test rax,rax
    jz hsw_release_bad
    cmp rax,rbx
    je hsw_release_found
    lea rdx,[rax+16]
    jmp hsw_release_find
hsw_release_found:
    cmp qword ptr [r12+88],0
    je hsw_release_bad
    mov rax,[rbx+16]
    mov [rdx],rax
    dec qword ptr [r12+88]
    mov rdi,[rbx+72]
    mov qword ptr [rbx+72],0
    call ssh_direct_request_release
    mov rdi,rbx
    call hsw_free_buffers
    jmp hsw_release_return
hsw_release_busy:
    mov rax,-16
    jmp hsw_release_return
hsw_release_bad:
    mov rax,-22
hsw_release_return:
    HSW_RETURN

hsw_freeze:
    HSW_SAVE
    mov r12,rdi
    call hsw_root_check
    test eax,eax
    jz hsw_freeze_bad
    mov qword ptr [r12+96],1
    mov rdi,[r12+72]
    call ssh_direct_owner_shutdown
    cmp rax,1
    je hsw_freeze_ok
    test rax,rax
    jnz hsw_freeze_return
hsw_freeze_ok:
    xor eax,eax
    jmp hsw_freeze_return
hsw_freeze_bad:
    mov rax,-22
hsw_freeze_return:
    HSW_RETURN

/* Returns HSW_PENDING until the actual persistent join and all native caller
 * refs are gone. An error never discards retained child or owner custody. */
hsw_destroy:
    HSW_SAVE
    mov r12,rdi
    call hsw_root_check
    test eax,eax
    jz hsw_destroy_bad
    cmp qword ptr [r12+96],1
    jne hsw_destroy_busy
    mov rax,[r12+128]
    or rax,[r12+88]
    jnz hsw_destroy_busy
    cmp qword ptr [r12+104],0
    jne hsw_destroy_failed
    mov rdi,[r12+72]
    call ssh_direct_owner_destroy
    cmp rax,1
    je hsw_destroy_pending
    test rax,rax
    jnz hsw_destroy_return
    mov qword ptr [r12+72],0
    mov rdi,[r12+56]
    mov qword ptr [r12+56],-1
    mov eax,3
    syscall
    test rax,rax
    jnz hsw_destroy_failed
    mov rdi,[r12+120]
    mov qword ptr [r12+120],-1
    mov eax,3
    syscall
    test rax,rax
    jnz hsw_destroy_failed
    mov rdi,[r12+16]
    mov rsi,[r12+24]
    call ssh_free
    test rax,rax
    jnz hsw_destroy_failed
    mov qword ptr [r12+16],0
    mov rdi,r12
    mov esi,4096
    call ssh_free
    jmp hsw_destroy_return
hsw_destroy_failed:
    mov qword ptr [r12+104],1
    mov rax,-71
    jmp hsw_destroy_return
hsw_destroy_pending:
    mov eax,HSW_PENDING
    jmp hsw_destroy_return
hsw_destroy_busy:
    mov rax,-16
    jmp hsw_destroy_return
hsw_destroy_bad:
    mov rax,-22
hsw_destroy_return:
    HSW_RETURN

hsw_free_buffers:
    HSW_SAVE
    mov rbx,rdi
    mov rdi,[rbx+24]
    mov rsi,[rbx+40]
    call ssh_free
    mov rdi,[rbx+48]
    mov rsi,[rbx+56]
    call ssh_free
    mov rdi,[rbx+80]
    mov rsi,[rbx+88]
    call ssh_free
    mov rdi,[rbx+128]
    mov rsi,[rbx+136]
    call ssh_free
    mov rdi,[rbx+152]
    mov rsi,[rbx+160]
    call ssh_free
    mov rdi,rbx
    mov esi,4096
    call ssh_free
    HSW_RETURN
hsw_root_check:
    xor eax,eax
    test r12,r12
    jz hsw_root_checked
    movabs rcx,HSW_ROOT
    cmp [r12],rcx
    jne hsw_root_checked
    mov eax,1
hsw_root_checked:
    ret
hsw_call_check:
    xor eax,eax
    test rbx,rbx
    jz hsw_call_checked
    movabs rcx,HSW_CALL
    cmp [rbx],rcx
    jne hsw_call_checked
    mov rdx,[rbx+8]
    test rdx,rdx
    jz hsw_call_checked
    movabs rcx,HSW_ROOT
    cmp [rdx],rcx
    jne hsw_call_checked
    mov eax,1
hsw_call_checked:
    ret
hsw_clock:
    sub rsp,24
    mov edi,1
    mov rsi,rsp
    mov eax,228
    syscall
    test rax,rax
    js hsw_clock_return
    mov rax,[rsp]
    mov ecx,1000000000
    mul rcx
    test rdx,rdx
    jnz hsw_clock_overflow
    add rax,[rsp+8]
    jc hsw_clock_overflow
    jmp hsw_clock_return
hsw_clock_overflow:
    mov rax,-75
hsw_clock_return:
    add rsp,24
    ret
