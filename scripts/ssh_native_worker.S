/* Native private worker for the HIA-owned foreground SSH capture.
 * No JSON, host policy, queue limit, child outcome or reap is synthesized here.
 * Linux clone creates one syscall-only thread per admitted operation; every
 * thread shares the same actual HIA registry and retains its private buffers.
 * Runtime futures may disappear; the root owner still joins the kernel TID.
 */
.intel_syntax noprefix
.section .text
.global ssh_native_worker
ssh_native_worker:
    .byte 0xe9
    .long hsw_create - . - 4
    .byte 0xe9
    .long hsw_start - . - 4
    .byte 0xe9
    .long hsw_poll - . - 4
    .byte 0xe9
    .long hsw_cancel - . - 4
    .byte 0xe9
    .long hsw_release - . - 4
    .byte 0xe9
    .long hsw_freeze - . - 4
    .byte 0xe9
    .long hsw_destroy - . - 4
/* Root: owner8,cap24,regbase32,binding40,env48,program56,generation64,
 * regctx72,counter80,active88,frozen96,broken104,epoch112,wake120,
 * list128,API lock136. Call records are never public byte-selected pointers. */
.equ HSW_ROOT,0x3130545257535348
.equ HSW_CALL,0x3130434157535348
.equ HSW_INVALID,0xffffffff
.equ HSW_RESOURCE,0xfffffffc
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

/* create(private 96-byte captured installed table) -> root or -errno.
 * HSSHWK01,1,owner,registry,cap,registry_engine,binding,envp,program,gen,0,0 */
hsw_create:
    HSW_SAVE
    mov r13,rdi
    test r13,r13
    jz hsw_create_invalid
    movabs rax,0x31304b5748535348
    cmp [r13],rax
    jne hsw_create_invalid
    cmp qword ptr [r13+8],1
    jne hsw_create_invalid
    mov rax,[r13+80]
    or rax,[r13+88]
    jnz hsw_create_invalid
    cmp qword ptr [r13+72],0
    je hsw_create_invalid
    mov ebx,16
hsw_create_pointer:
    cmp qword ptr [r13+rbx],0
    je hsw_create_invalid
    add ebx,8
    cmp ebx,64
    jb hsw_create_pointer
    mov rdi,[r13+64]
    mov esi,1034 /* F_GET_SEALS */
    xor edx,edx
    mov eax,72
    syscall
    cmp eax,15
    jne hsw_create_invalid
    mov edi,4096
    call hsw_allocate
    test rax,rax
    js hsw_create_return
    mov r12,rax
    movabs rcx,HSW_ROOT
    mov [r12],rcx
    mov rax,[r13+16]
    mov [r12+8],rax
    mov rax,[r13+24]
    mov [r12+16],rax
    mov rax,[r13+32]
    mov [r12+24],rax
    mov rax,[r13+40]
    mov [r12+32],rax
    mov rax,[r13+48]
    mov [r12+40],rax
    mov rax,[r13+56]
    mov [r12+48],rax
    mov rax,[r13+72]
    mov [r12+64],rax
    mov qword ptr [r12+56],-1
    mov qword ptr [r12+120],-1
    mov rdi,[r13+64]
    mov esi,1030 /* F_DUPFD_CLOEXEC */
    mov edx,3
    mov eax,72
    syscall
    test rax,rax
    js hsw_create_unmap
    mov [r12+56],rax
    xor edi,edi
    mov esi,0x80800 /* EFD_CLOEXEC | EFD_NONBLOCK */
    mov eax,290
    syscall
    test rax,rax
    js hsw_create_close
    mov [r12+120],rax
    mov rdi,[r12+16]
    mov rsi,[r12+64]
    call qword ptr [r12+32]
    test rax,rax
    js hsw_create_close_wake
    mov [r12+72],rax
    mov rax,r12
    jmp hsw_create_return
hsw_create_close_wake:
    mov rbx,rax
    mov rdi,[r12+120]
    mov eax,3
    syscall
    mov rax,rbx
hsw_create_close:
    mov rbx,rax
    mov rdi,[r12+56]
    mov eax,3
    syscall
    mov rax,rbx
hsw_create_unmap:
    mov rbx,rax
    mov rdi,r12
    mov esi,4096
    mov eax,11
    syscall
    mov rax,rbx
    jmp hsw_create_return
hsw_create_invalid:
    mov rax,-22
hsw_create_return:
    HSW_RETURN

/* start(root, admitted HFBSHP03, length) -> owned call or -errno.
 * The parent never waits for the network and never performs a HIA child twice.
 * Call: root8,next16,request24/len32,work40/cap48,out56/cap64,result72/len80,
 * binding88,rawcap96,status104,token112,deadline120,stack128/len136,
 * flags144,notify lock152,kernel clear-TID160,diagnostic TID168,queued176.
 */
hsw_start:
    HSW_SAVE
    mov [rsp+248],rcx /* private absolute deadline, or zero for the plan budget */
    mov r12,rdi
    mov r13,rsi
    mov r14,rdx
    call hsw_root_check
    test eax,eax
    jz hsw_start_invalid
    cmp r14,128
    jb hsw_start_invalid
    movabs rax,0x3330504853424648
    cmp [r13],rax
    jne hsw_start_invalid
    mov rax,[r13+8]
    or rax,[r13+32] /* this installed edge is explicitly foreground */
    jnz hsw_start_invalid
    mov rax,r14
    sub rax,128
    cmp [r13+80],rax
    jne hsw_start_invalid
    mov rax,r14
    add rax,64
    jc hsw_start_invalid
    mov edi,4096
    call hsw_allocate
    test rax,rax
    js hsw_start_return
    mov rbx,rax
    movabs rcx,HSW_CALL
    mov [rbx],rcx
    mov [rbx+8],r12
    lea rdi,[r14+64]
    call hsw_allocate
    test rax,rax
    js hsw_start_cleanup
    mov [rbx+24],rax
    lea rcx,[r14+64]
    mov [rbx+32],rcx
    lea rdi,[rax+64]
    mov rsi,r13
    mov rcx,r14
    rep movsb
    mov edi,24576
    call hsw_allocate
    test rax,rax
    js hsw_start_cleanup
    mov [rbx+40],rax
    mov qword ptr [rbx+48],24576
    mov edi,256
    call hsw_allocate
    test rax,rax
    js hsw_start_cleanup
    mov [rbx+56],rax
    mov qword ptr [rbx+64],256
    mov edi,2097152
    call hsw_allocate
    test rax,rax
    js hsw_start_cleanup
    mov [rbx+128],rax
    mov qword ptr [rbx+136],2097152
    lea rdi,[r12+136]
    call hsw_lock
    test eax,eax
    jnz hsw_start_cleanup
    call hsw_clock
    test rax,rax
    js hsw_start_unlock_failure
    mov r15,rax
    mov rcx,30000000000
    add rcx,rax
    jc hsw_start_unlock_overflow
    cmp qword ptr [rsp+248],0
    cmovne rcx,[rsp+248]
    mov [rbx+120],rcx
    lea rdi,[rsp]
    xor eax,eax
    mov ecx,28
    rep stosq
    movabs rax,0x3130515247535348
    mov [rsp],rax
    mov qword ptr [rsp+8],2
    mov rax,[r12+64]
    mov [rsp+16],rax
    mov qword ptr [rsp+24],0
    mov qword ptr [rsp+48],1
    mov [rsp+32],r15
    mov rax,[rbx+120]
    mov [rsp+40],rax
    mov rdi,r12
    mov rsi,rsp
    mov edx,96
    lea rcx,[rsp+128]
    mov r8d,128
    call hsw_registry_invoke
    cmp eax,128
    jne hsw_start_unlock_protocol
    cmp qword ptr [rsp+128+8],0
    jne hsw_start_unlock_cancelled
    mov rax,[rsp+128+24]
    test rax,rax
    jz hsw_start_unlock_protocol
    mov [rbx+112],rax
    mov qword ptr [rbx+176],1
    lea rdi,[r12+136]
    call hsw_unlock
    mov r13,[rbx+24]
    movabs rax,0x3130515248535348
    mov [r13],rax
    mov qword ptr [r13+8],1
    mov rax,[rbx+112]
    mov [r13+16],rax
    mov rax,[rbx+120]
    mov [r13+24],rax
    mov rax,[rbx+32]
    sub rax,64
    mov [r13+32],rax
    mov rax,[r12+64]
    mov [r13+40],rax
    mov rdi,rbx
    mov esi,1
    call hsw_hia
    cmp eax,0xfffffff0
    jne hsw_start_queued_failure
    mov rdi,[rbx+40]
    mov rsi,[rbx+48]
    mov rdx,[r12+48]
    mov rcx,[rbx+112]
    mov r8,[r12+56]
    call qword ptr [r12+24]
    test rax,rax
    js hsw_start_queued_failure
    mov [rbx+96],rax
    movabs rax,0x3130444e42535348
    mov [rsp],rax
    mov qword ptr [rsp+8],1
    lea rax,[rip+hsw_registry_forward]
    mov [rsp+16],rax
    mov [rsp+24],r12
    mov rax,[r12+24]
    mov [rsp+32],rax
    mov rax,[r12+64]
    mov [rsp+40],rax
    mov qword ptr [rsp+48],1
    mov qword ptr [rsp+56],0
    mov rdi,rsp
    mov rsi,[rbx+96]
    call qword ptr [r12+40]
    test rax,rax
    js hsw_start_queued_failure
    mov [rbx+88],rax
    lea rdi,[r12+136]
    call hsw_lock
    test eax,eax
    jnz hsw_start_queued_failure
    mov rax,[r12+128]
    mov [rbx+16],rax
    mov [r12+128],rbx
    inc qword ptr [r12+88]
    lea rdi,[r12+136]
    call hsw_unlock
    mov qword ptr [rbx+104],1
    mov qword ptr [rbx+160],-1
    mov r13,rbx
    mov edi,0x350f00 /* VM,FS,FILES,SIGHAND,THREAD,SYSVSEM,PARENT_SETTID,CLEARTID */
    mov rsi,[rbx+128]
    add rsi,2097152-16
    lea rdx,[rbx+160]
    mov r10,rdx
    xor r8d,r8d
    mov eax,56
    syscall
    test rax,rax
    jz hsw_thread_start
    js hsw_clone_failed
    mov [rbx+168],rax
    mov rax,rbx
    jmp hsw_start_return
hsw_thread_start:
    mov rdi,r13
    call hsw_thread
    ud2
hsw_clone_failed:
    mov qword ptr [rbx+160],0
    mov [rbx+184],rax
    /* No SSH spawn was possible. Keep exact known failure for parent release. */
    mov rdi,rbx
    call hsw_abort_queued
    mov qword ptr [rbx+104],4
    mov rax,rbx
    jmp hsw_start_return
hsw_start_unlock_cancelled:
    mov rax,-125
    jmp hsw_start_unlock_failure
hsw_start_unlock_protocol:
    mov rax,-71
    jmp hsw_start_unlock_failure
hsw_start_unlock_overflow:
    mov rax,-75
hsw_start_unlock_failure:
    mov r15,rax
    lea rdi,[r12+136]
    call hsw_unlock
    mov rax,r15
    jmp hsw_start_cleanup
hsw_start_queued_failure:
    mov [rbx+184],rax
    mov rdi,rbx
    call hsw_abort_queued
    /* A pre-thread capability rejection retains custody for explicit audit. */
    mov qword ptr [rbx+104],3
    mov qword ptr [r12+104],1
    mov rax,-71
    jmp hsw_start_return
hsw_start_cleanup:
    mov r15,rax
    mov rdi,rbx
    call hsw_free_buffers
    mov rax,r15
    jmp hsw_start_return
hsw_start_invalid:
    mov rax,-22
hsw_start_return:
    HSW_RETURN

/* Exact original HIA owner. 1 means initial input; 2 resumes the saved effect.
 * Output/work growth is mechanical; a completed effect is never replayed. */
hsw_hia:
    HSW_SAVE
    mov rbx,rdi
    mov ebp,esi
    mov r12,[rbx+8]
hsw_hia_again:
    cmp ebp,1
    jne hsw_hia_resume
    mov rdi,[rbx+24]
    mov rsi,[rbx+32]
    jmp hsw_hia_enter
hsw_hia_resume:
    mov rdi,rsp
    mov ecx,8
    xor eax,eax
    rep stosq
    movabs rax,0x3130515248535348
    mov [rsp],rax
    mov qword ptr [rsp+8],2
    mov rax,[rbx+112]
    mov [rsp+16],rax
    mov rax,[rbx+120]
    mov [rsp+24],rax
    mov rax,[r12+64]
    mov [rsp+40],rax
    mov rdi,rsp
    mov esi,64
hsw_hia_enter:
    mov rdx,[rbx+56]
    mov rcx,[rbx+64]
    mov r8,[rbx+40]
    mov r9,[rbx+48]
    call qword ptr [r12+8]
    cmp eax,0xffffffd0
    jne hsw_hia_done
    mov r13,[rbx+56]
    movabs rdx,0x3230305357524748
    cmp [r13],rdx
    jne hsw_hia_invalid
    cmp qword ptr [r13+24],0
    jne hsw_hia_invalid
    mov r14,[r13+16]
    cmp qword ptr [r13+8],1
    je hsw_hia_work
    cmp qword ptr [r13+8],2
    jne hsw_hia_invalid
    cmp r14,[rbx+64]
    jbe hsw_hia_invalid
    mov rdi,r14
    call hsw_allocate
    test rax,rax
    js hsw_hia_resource
    mov r15,rax
    mov rdi,[rbx+56]
    mov rsi,[rbx+64]
    mov eax,11
    syscall
    test rax,rax
    jnz hsw_hia_resource
    mov [rbx+56],r15
    mov [rbx+64],r14
    jmp hsw_hia_again
hsw_hia_work:
    cmp r14,[rbx+48]
    jbe hsw_hia_invalid
    mov rdi,r14
    call hsw_allocate
    test rax,rax
    js hsw_hia_resource
    mov r15,rax
    lea rdi,[rbx+152]
    call hsw_lock
    test eax,eax
    jnz hsw_hia_resource
    mov rdi,r15
    mov rsi,[rbx+40]
    mov rcx,[rbx+48]
    rep movsb
    cmp qword ptr [rbx+88],0
    je hsw_hia_rebound
    mov rdi,[rbx+88]
    mov rsi,r15
    mov rdx,r14
    mov rax,[r12+40]
    add rax,15
    call rax
    test rax,rax
    jnz hsw_hia_rebind_failed
hsw_hia_rebound:
    mov rdi,[rbx+40]
    mov rsi,[rbx+48]
    mov eax,11
    syscall
    test rax,rax
    jnz hsw_hia_rebind_failed
    mov [rbx+40],r15
    mov [rbx+48],r14
    lea rdi,[rbx+152]
    call hsw_unlock
    jmp hsw_hia_again
hsw_hia_rebind_failed:
    lea rdi,[rbx+152]
    call hsw_unlock
hsw_hia_resource:
    mov eax,HSW_RESOURCE
    jmp hsw_hia_done
hsw_hia_invalid:
    mov eax,HSW_INVALID
hsw_hia_done:
    HSW_RETURN

/* Thread owns original calls and exact Finish. Kernel clear-TID is the join. */
hsw_thread:
    HSW_SAVE
    mov rbx,rdi
    mov r12,[rbx+8]
hsw_thread_loop:
    mov r14d,[r12+112]
    mov rdi,[rbx+88]
    mov rax,[r12+40]
    add rax,5
    call rax
    cmp eax,2
    je hsw_thread_wait
    test eax,eax
    jnz hsw_thread_failed
    mov rdi,rbx
    mov esi,2
    call hsw_hia
    cmp eax,0xfffffff0
    je hsw_thread_loop
    mov [rbx+72],rax
    cmp eax,0xffff0000
    jae hsw_thread_failed
    cmp eax,128
    jb hsw_thread_failed
    cmp rax,[rbx+64]
    ja hsw_thread_failed
    mov [rbx+80],rax
    mov rdi,[rbx+88]
    mov rax,[r12+40]
    add rax,20
    call rax
    test rax,rax
    jnz hsw_thread_failed
    mov qword ptr [rbx+104],2
    jmp hsw_thread_signal
hsw_thread_wait:
    mov rax,[rbx+120]
    xor edx,edx
    mov ecx,1000000000
    div rcx
    mov [rsp],rax
    mov [rsp+8],rdx
    lea rdi,[r12+112]
    mov esi,9 /* FUTEX_WAIT_BITSET, monotonic absolute original deadline */
    mov edx,r14d
    mov r10,rsp
    xor r8d,r8d
    mov r9d,-1
    mov eax,202
    syscall
    test rax,rax
    jz hsw_thread_loop
    cmp rax,-11
    je hsw_thread_loop
    cmp rax,-4
    je hsw_thread_loop
    cmp rax,-110
    je hsw_thread_loop
hsw_thread_failed:
    mov [rbx+184],rax
    mov qword ptr [r12+104],1
    mov qword ptr [rbx+104],3
    mov rdi,rbx
    call hsw_mark_failure
hsw_thread_signal:
    mov qword ptr [rsp],1
hsw_thread_signal_again:
    mov rdi,[r12+120]
    mov rsi,rsp
    mov edx,8
    mov eax,1
    syscall
    cmp rax,-4
    je hsw_thread_signal_again
    /* EAGAIN is an already pending wake; completion is still held in memory. */
    mov edi,0
    mov eax,60
    syscall
    ud2

/* poll(call, out{pointer,length,actual_return,kernel_tid,status}) -> 0/WAIT/error.
 * No wait result is hidden. A signal is not treated as a completed capture. */
hsw_poll:
    HSW_SAVE
    mov rbx,rdi
    mov r13,rsi
    call hsw_call_check
    test eax,eax
    jz hsw_poll_bad
    test r13,r13
    jz hsw_poll_bad
    cmp dword ptr [rbx+160],0
    jne hsw_poll_pending
    cmp qword ptr [rbx+104],2
    jne hsw_poll_failure
    mov rax,[rbx+56]
    mov [r13],rax
    mov rax,[rbx+80]
    mov [r13+8],rax
    mov rax,[rbx+72]
    mov [r13+16],rax
    mov rax,[rbx+168]
    mov [r13+24],rax
    mov qword ptr [r13+32],2
    xor eax,eax
    jmp hsw_poll_done
hsw_poll_failure:
    mov eax,HSW_UNCERTAIN
    jmp hsw_poll_done
hsw_poll_pending:
    mov eax,HSW_PENDING
    jmp hsw_poll_done
hsw_poll_bad:
    mov eax,HSW_INVALID
hsw_poll_done:
    HSW_RETURN

/* cancel(call,1=caller,2=owner freeze) is actual HIA registry + wake. */
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
    lea rdi,[rbx+152]
    call hsw_lock
    test eax,eax
    jnz hsw_cancel_done
    mov r12,[rbx+8]
    cmp qword ptr [rbx+104],1
    jne hsw_cancel_settled
    mov rdi,[rbx+88]
    mov rsi,r13
    mov rax,[r12+40]
    add rax,10
    call rax
    mov r14,rax
    test rax,rax
    jnz hsw_cancel_unlock
    or [rbx+144],r13
    jmp hsw_cancel_unlock
hsw_cancel_settled:
    xor r14d,r14d
hsw_cancel_unlock:
    lea rdi,[rbx+152]
    call hsw_unlock
    mov rax,r14
    jmp hsw_cancel_done
hsw_cancel_bad:
    mov rax,-22
hsw_cancel_done:
    HSW_RETURN

/* release only after kernel join AND HIA actual child Finish. */
hsw_release:
    HSW_SAVE
    mov rbx,rdi
    call hsw_call_check
    test eax,eax
    jz hsw_release_bad
    cmp dword ptr [rbx+160],0
    jne hsw_release_busy
    cmp qword ptr [rbx+104],2
    jne hsw_release_busy
    mov r12,[rbx+8]
    mov rdi,[rbx+88]
    mov rax,[r12+40]
    add rax,25
    call rax
    test rax,rax
    jnz hsw_release_done
    mov qword ptr [rbx+88],0
    mov qword ptr [rbx+96],0
    lea rdi,[r12+136]
    call hsw_lock
    test eax,eax
    jnz hsw_release_done
    lea rdx,[r12+128]
hsw_release_find:
    mov rax,[rdx]
    test rax,rax
    jz hsw_release_list_error
    cmp rax,rbx
    je hsw_release_unlink
    lea rdx,[rax+16]
    jmp hsw_release_find
hsw_release_unlink:
    mov rax,[rbx+16]
    mov [rdx],rax
    cmp qword ptr [r12+88],0
    je hsw_release_list_error
    dec qword ptr [r12+88]
    lea rdi,[r12+136]
    call hsw_unlock
    mov rdi,rbx
    call hsw_free_buffers
    jmp hsw_release_done
hsw_release_list_error:
    lea rdi,[r12+136]
    call hsw_unlock
hsw_release_bad:
    mov rax,-22
    jmp hsw_release_done
hsw_release_busy:
    mov rax,-16
hsw_release_done:
    HSW_RETURN

/* freeze(root) rejects future commits and wakes every retained original call. */
hsw_freeze:
    HSW_SAVE
    mov r12,rdi
    call hsw_root_check
    test eax,eax
    jz hsw_freeze_bad
    lea rdi,[r12+136]
    call hsw_lock
    test eax,eax
    jnz hsw_freeze_done
    mov rdi,rsp
    xor eax,eax
    mov ecx,28
    rep stosq
    movabs rax,0x3130515247535348
    mov [rsp],rax
    mov qword ptr [rsp+8],8
    mov rax,[r12+64]
    mov [rsp+16],rax
    mov rdi,r12
    mov rsi,rsp
    mov edx,96
    lea rcx,[rsp+128]
    mov r8d,128
    call hsw_registry_invoke
    cmp eax,128
    jne hsw_freeze_locked_bad
    cmp qword ptr [rsp+128+8],0
    jne hsw_freeze_locked_bad
    mov qword ptr [r12+96],1
    mov rbx,[r12+128]
hsw_freeze_next:
    test rbx,rbx
    jz hsw_freeze_unlock
    mov rdi,rbx
    mov esi,2
    call hsw_cancel
    test rax,rax
    jnz hsw_freeze_locked_bad
    mov rbx,[rbx+16]
    jmp hsw_freeze_next
hsw_freeze_unlock:
    lea rdi,[r12+136]
    call hsw_unlock
    xor eax,eax
    jmp hsw_freeze_done
hsw_freeze_locked_bad:
    lea rdi,[r12+136]
    call hsw_unlock
hsw_freeze_bad:
    mov rax,-22
hsw_freeze_done:
    HSW_RETURN

hsw_destroy:
    HSW_SAVE
    mov r12,rdi
    call hsw_root_check
    test eax,eax
    jz hsw_destroy_bad
    mov rax,[r12+88]
    or rax,[r12+128]
    or rax,[r12+104]
    jnz hsw_destroy_busy
    cmp qword ptr [r12+96],1
    jne hsw_destroy_busy
    mov rdi,[r12+72]
    mov rax,[r12+32]
    add rax,10
    call rax
    test rax,rax
    jnz hsw_destroy_done
    mov rdi,[r12+56]
    mov qword ptr [r12+56],-1
    mov eax,3
    syscall
    test rax,rax
    jnz hsw_destroy_done
    mov rdi,[r12+120]
    mov qword ptr [r12+120],-1
    mov eax,3
    syscall
    test rax,rax
    jnz hsw_destroy_done
    mov qword ptr [r12],0
    mov rdi,r12
    mov esi,4096
    mov eax,11
    syscall
    jmp hsw_destroy_done
hsw_destroy_bad:
    mov rax,-22
    jmp hsw_destroy_done
hsw_destroy_busy:
    mov rax,-16
hsw_destroy_done:
    HSW_RETURN

/* Native registry forwarders retain the exact HIA status/response. A real
 * transition increments a futex epoch. WAIT is retried only after this epoch,
 * the original absolute deadline, or an actual kernel interruption. */
.balign 8
hsw_registry_forward:
    .byte 0xe9
    .long hsw_forward_invalid - . - 4
    .byte 0xe9
    .long hsw_registry_invoke - . - 4
    .byte 0xe9
    .long hsw_forward_invalid - . - 4
hsw_forward_invalid:
    mov eax,HSW_INVALID
    ret
hsw_registry_invoke:
    push rbx
    push r12
    push r13
    push r14
    sub rsp,8
    mov r12,rdi
    mov r13,rcx
    mov r14,[rsi+8]
    mov rdi,[r12+72]
    mov rax,[r12+32]
    add rax,5
    call rax
    mov ebx,eax
    cmp eax,128
    jne hsw_registry_return
    cmp r14,12
    je hsw_registry_return
    cmp r14,15
    je hsw_registry_return
    cmp qword ptr [r13+8],2
    je hsw_registry_return
    lock inc dword ptr [r12+112]
    lea rdi,[r12+112]
    mov esi,1
    mov edx,2147483647
    mov eax,202
    syscall
hsw_registry_return:
    mov eax,ebx
    add rsp,8
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

hsw_abort_queued:
    HSW_SAVE
    mov rbx,rdi
    mov r12,[rbx+8]
    mov rdi,rsp
    xor eax,eax
    mov ecx,28
    rep stosq
    movabs rax,0x3130515247535348
    mov [rsp],rax
    mov qword ptr [rsp+8],18
    mov rax,[r12+64]
    mov [rsp+16],rax
    mov rax,[rbx+112]
    mov [rsp+24],rax
    mov qword ptr [rsp+48],5
    mov rdi,r12
    mov rsi,rsp
    mov edx,96
    lea rcx,[rsp+128]
    mov r8d,128
    call hsw_registry_invoke
    cmp eax,128
    jne hsw_abort_failed
    cmp qword ptr [rsp+128+8],0
    jne hsw_abort_failed
    mov qword ptr [rsp+8],13
    mov qword ptr [rsp+48],0
    mov rdi,r12
    mov rsi,rsp
    mov edx,96
    lea rcx,[rsp+128]
    mov r8d,128
    call hsw_registry_invoke
    HSW_RETURN
hsw_abort_failed:
    mov qword ptr [r12+104],1
    HSW_RETURN

hsw_mark_failure:
    HSW_SAVE
    mov rbx,rdi
    mov r12,[rbx+8]
    mov rdi,rsp
    xor eax,eax
    mov ecx,28
    rep stosq
    movabs rax,0x3130515247535348
    mov [rsp],rax
    mov qword ptr [rsp+8],14
    mov rax,[r12+64]
    mov [rsp+16],rax
    mov qword ptr [rsp+48],19
    mov rdi,r12
    mov rsi,rsp
    mov edx,96
    lea rcx,[rsp+128]
    mov r8d,128
    call hsw_registry_invoke
    HSW_RETURN

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

hsw_clock:
    sub rsp,24
    mov edi,1
    mov rsi,rsp
    mov eax,228
    syscall
    test rax,rax
    js hsw_clock_done
    mov rax,[rsp]
    mov ecx,1000000000
    mul rcx
    test rdx,rdx
    jnz hsw_clock_overflow
    add rax,[rsp+8]
    jc hsw_clock_overflow
    jmp hsw_clock_done
hsw_clock_overflow:
    mov rax,-75
hsw_clock_done:
    add rsp,24
    ret
hsw_allocate:
    mov rsi,rdi
    test rsi,rsi
    jle hsw_allocate_bad
    xor edi,edi
    mov edx,3
    mov r10d,34
    mov r8,-1
    xor r9d,r9d
    mov eax,9
    syscall
    ret
hsw_allocate_bad:
    mov rax,-75
    ret
hsw_lock:
    mov rdx,rdi
hsw_lock_again:
    xor eax,eax
    mov ecx,1
    lock cmpxchg dword ptr [rdx],ecx
    jz hsw_lock_acquired
    mov rdi,rdx
    mov esi,0
    mov edx,1
    xor r10d,r10d
    mov eax,202
    syscall
    mov rdx,rdi
    cmp rax,0
    je hsw_lock_again
    cmp rax,-11
    je hsw_lock_again
    cmp rax,-4
    je hsw_lock_again
    ret
hsw_lock_acquired:
    xor eax,eax
    ret
hsw_unlock:
    mov dword ptr [rdi],0
    mov esi,1
    mov edx,1
    mov eax,202
    syscall
    xor eax,eax
    ret

/* Buffers have no live borrows here. Stack unmaps only after clear-TID==0. */
hsw_free_buffers:
    push rbx
    push r12
    sub rsp,8
    mov rbx,rdi
    xor r12d,r12d
hsw_free_next:
    lea rax,[rip+hsw_buffer_pairs]
    movzx ecx,byte ptr [rax+r12]
    movzx edx,byte ptr [rax+r12+1]
    mov rdi,[rbx+rcx]
    test rdi,rdi
    jz hsw_free_advance
    mov rsi,[rbx+rdx]
    mov eax,11
    syscall
    test rax,rax
    jnz hsw_free_done
hsw_free_advance:
    add r12d,2
    cmp r12d,8
    jb hsw_free_next
    mov qword ptr [rbx],0
    mov rdi,rbx
    mov esi,4096
    mov eax,11
    syscall
hsw_free_done:
    add rsp,8
    pop r12
    pop rbx
    ret
hsw_buffer_pairs:
    .byte 24,32,40,48,56,64,128,136
.section .note.GNU-stack,"",@progbits
