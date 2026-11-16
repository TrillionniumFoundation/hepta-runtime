/* Fixed private Linux bridge: HIA owns permits, deadlines, mathematics and JSON. */
.intel_syntax noprefix
.section .text
.global _start
.type _start,@function
.equ bwx_G_MUTEX,0
.equ bwx_G_POOL,8
.equ bwx_G_POOL_BYTES,16
.equ bwx_G_HEAD,24
.equ bwx_G_PID,32
.equ bwx_G_CLOSING,40
.equ bwx_G_WAKE_R,48
.equ bwx_G_WAKE_W,56
.equ bwx_G_INPUT,64
.equ bwx_G_INPUT_LEN,80
.equ bwx_G_INPUT_USED,88
.equ bwx_G_INPUT_STAGE,96
.equ bwx_G_HEADER,104
.equ bwx_G_POLL,112
.equ bwx_G_NOTICE,128
.equ bwx_T_NEXT,0
.equ bwx_T_JOB,8
.equ bwx_T_TAG,16
.equ bwx_T_PID,24
.equ bwx_T_GATE,32
.equ bwx_T_FINISHED,40
.equ bwx_T_REAPED,48
.equ bwx_T_CALLER,56
.equ bwx_T_INPUT,64
.equ bwx_T_INPUT_LEN,72
.equ bwx_T_CORE_OUT,88
.equ bwx_T_CORE_WORK,104
.equ bwx_T_COMMIT_IN,120
.equ bwx_T_COMMIT_IN_LEN,128
.equ bwx_T_COMMIT_OUT,144
.equ bwx_T_COMMIT_WORK,160
.equ bwx_T_RENDER_IN,176
.equ bwx_T_RENDER_IN_LEN,184
.equ bwx_T_RENDER_OUT,200
.equ bwx_T_RENDER_WORK,216
.equ bwx_T_STACK,232
.equ bwx_T_START,248
.equ bwx_T_FINISH,256
.equ bwx_T_ELAPSED,264
.equ bwx_T_RESULT,272
.equ bwx_T_CORE_LEN,280
.equ bwx_T_COMMIT_LEN,288
.equ bwx_T_RENDER_LEN,296
.equ bwx_T_HOLD_MODE,304
.equ bwx_T_HOLD_RELEASED,312
.equ bwx_T_CLOCKS,320
.equ bwx_T_ANNOUNCED,328
.equ bwx_T_STATUS,336
.equ bwx_T_ELAPSED_NS,360
.equ bwx_T_COMPLETE,512
.equ bwx_CORE_OUT_BYTES,295040
.equ bwx_CORE_WORK_BYTES,295552
.equ bwx_COMMIT_OUT_BYTES,8388736
.equ bwx_COMMIT_WORK_BYTES,8405504
.equ bwx_RENDER_BYTES,1069056
.equ bwx_STACK_BYTES,1048576


.equ bwx_G_OUTPUT,160
.equ bwx_G_OUTPUT_CAPACITY,168
.equ bwx_G_OUTPUT_USED,176
.equ bwx_G_OUTPUT_CURSOR,184
.equ bwx_G_BORROW_SEQUENCE,192
.equ bwx_G_BORROWED,200
.equ bwx_G_BORROW_EXTENT,208
.equ bwx_G_JOURNAL_FD,216
.equ bwx_G_API_LOCK,224
.equ bwx_G_MAGIC,232

_start:
    cmp qword ptr [rsp],1
    jne bwx_bare_usage
    and rsp,-16
    sub rsp,4096
    mov r13,rsp
    xor r15d,r15d
    mov qword ptr [r13],1
    mov qword ptr [r13+8],0
    mov qword ptr [r13+16],0
    mov qword ptr [r13+24],0
    mov edi,13
    mov rsi,r13
    xor edx,edx
    mov r10d,8
    mov eax,13
    syscall
    test rax,rax
    jnz bwx_fatal
    mov edi,2
    call bellman_worker_init
    cmp eax,0xffffffff
    je bwx_bare_usage
    test rax,rax
    jz bwx_bare_usage
    mov r15,rax
    xor edi,edi
    mov esi,3
    xor edx,edx
    mov eax,72
    syscall
    test rax,rax
    js bwx_fatal
    mov edx,eax
    or edx,0x800
    xor edi,edi
    mov esi,4
    mov eax,72
    syscall
    test rax,rax
    jnz bwx_fatal
bwx_fixture_loop:
    mov rdi,r15
    call bellman_worker_poll
    cmp rax,1
    ja bwx_fatal
bwx_fixture_receive:
    mov rdi,r15
    lea rsi,[r13+512]
    mov edx,32
    call bellman_worker_receive
    test rax,rax
    jz bwx_fixture_drained
    cmp rax,32
    jne bwx_fatal
    mov rax,[r13+528]
    mov [r13+600],rax
    mov edi,1
    lea rsi,[r13+600]
    mov edx,8
    call bwx_write_all_kernel
    test rax,rax
    jnz bwx_fatal
    mov edi,1
    mov rsi,[r13+520]
    mov rdx,[r13+528]
    call bwx_write_all_kernel
    test rax,rax
    jnz bwx_fatal
    mov rdi,r15
    mov rsi,[r13+536]
    call bellman_worker_release
    test rax,rax
    jnz bwx_fatal
    jmp bwx_fixture_receive
bwx_fixture_drained:
    cmp qword ptr [r15+bwx_G_CLOSING],0
    jne bwx_fixture_closing
    call bwx_read_frame
    test eax,eax
    jnz bwx_fixture_loop
    jmp bwx_fixture_wait
bwx_fixture_closing:
    cmp qword ptr [r15+bwx_G_HEAD],0
    jne bwx_fixture_wait
    mov rdi,r15
    call bellman_worker_destroy
    test rax,rax
    jnz bwx_bare_usage
    xor edi,edi
    mov eax,60
    syscall
    ud2
bwx_fixture_wait:
    mov dword ptr [r13+704],0
    mov dword ptr [r13+708],1
    cmp qword ptr [r15+bwx_G_CLOSING],0
    je bwx_fixture_input_ready
    mov dword ptr [r13+704],-1
bwx_fixture_input_ready:
    mov rdi,r15
    call bellman_worker_wake_fd
    mov [r13+712],eax
    mov dword ptr [r13+716],1
    lea rdi,[r13+704]
    mov esi,2
    mov edx,10
    mov eax,7
    syscall
    cmp rax,-4
    je bwx_fixture_loop
    test rax,rax
    js bwx_fatal
    jmp bwx_fixture_loop

bwx_read_frame:
    cmp qword ptr [r15+bwx_G_INPUT_STAGE],0
    jne bwx_read_body
    lea rsi,[r15+bwx_G_HEADER]
    mov edx,8
    jmp bwx_read_selected
bwx_read_body:
    mov rsi,[r15+bwx_G_INPUT]
    mov rdx,[r15+bwx_G_INPUT_LEN]
bwx_read_selected:
    mov rcx,[r15+bwx_G_INPUT_USED]
    add rsi,rcx
    sub rdx,rcx
    jz bwx_fatal
    xor edi,edi
    xor eax,eax
    syscall
    cmp rax,-4
    je bwx_read_frame
    cmp rax,-11
    je bwx_read_would_block
    test rax,rax
    js bwx_fatal
    jz bwx_input_eof
    add [r15+bwx_G_INPUT_USED],rax
    cmp qword ptr [r15+bwx_G_INPUT_STAGE],0
    jne bwx_body_progress
    cmp qword ptr [r15+bwx_G_INPUT_USED],8
    jb bwx_read_frame
    mov rax,[r15+bwx_G_HEADER]
    cmp rax,64
    jb bwx_fatal
    cmp rax,16777280
    ja bwx_fatal
    mov [r15+bwx_G_INPUT_LEN],rax
    mov qword ptr [r15+bwx_G_INPUT_STAGE],1
    mov qword ptr [r15+bwx_G_INPUT_USED],0
    jmp bwx_read_frame
bwx_body_progress:
    mov rax,[r15+bwx_G_INPUT_USED]
    cmp rax,[r15+bwx_G_INPUT_LEN]
    jb bwx_read_frame
    jne bwx_fatal
    mov rdi,r15
    mov rsi,[r15+bwx_G_INPUT]
    mov rdx,[r15+bwx_G_INPUT_LEN]
    call bellman_worker_control
    test rax,rax
    jnz bwx_fatal
    mov qword ptr [r15+bwx_G_INPUT_STAGE],0
    mov qword ptr [r15+bwx_G_INPUT_USED],0
    mov qword ptr [r15+bwx_G_INPUT_LEN],0
    mov eax,1
    ret
bwx_read_would_block:
    xor eax,eax
    ret
bwx_input_eof:
    cmp qword ptr [r15+bwx_G_INPUT_STAGE],0
    jne bwx_fatal
    cmp qword ptr [r15+bwx_G_INPUT_USED],0
    jne bwx_fatal
    mov rdi,r15
    call bellman_worker_shutdown
    test rax,rax
    jnz bwx_fatal
    mov eax,1
    ret

bwx_control:
    mov r12,[r15+bwx_G_INPUT]
    mov rax,0x313051524b574248 /* HBWKRQ01 */
    cmp [r12],rax
    jne bwx_fatal
    mov rax,[r15+bwx_G_INPUT_LEN]
    sub rax,64
    cmp [r12+40],rax
    jne bwx_fatal
    cmp qword ptr [r12+48],0
    jne bwx_fatal
    cmp qword ptr [r12+56],0
    jne bwx_fatal
    mov rax,[r12+8]
    cmp rax,1
    je bwx_submit
    cmp qword ptr [r12+40],0
    jne bwx_fatal
    cmp qword ptr [r12+32],0
    jne bwx_fatal
    cmp rax,5
    je bwx_stats
    cmp rax,6
    je bwx_shutdown_control
    cmp rax,2
    jb bwx_fatal
    cmp rax,7
    ja bwx_fatal
    mov r14,[r15+bwx_G_HEAD]
bwx_find_control:
    test r14,r14
    jz bwx_missing_control
    mov rax,[r12+24]
    cmp [r14+bwx_T_JOB],rax
    je bwx_found_control
    mov r14,[r14+bwx_T_NEXT]
    jmp bwx_find_control
bwx_found_control:
    mov rax,[r12+8]
    cmp rax,7
    je bwx_release_control
    mov edi,4
    cmp rax,2
    je bwx_selected_control
    mov edi,6
    cmp rax,3
    je bwx_selected_control
    cmp rax,4
    jne bwx_fatal
    mov edi,7
bwx_selected_control:
    mov rsi,[r14+bwx_T_JOB]
    xor edx,edx
    xor ecx,ecx
    lea r8,[r13+128]
    call bwx_pool_command
    mov [r13+400],rax
    cmp eax,128
    jne bwx_control_emit
    cmp qword ptr [r13+144],0
    jne bwx_control_emit
    cmp qword ptr [r12+8],3
    jne bwx_control_maybe_take
    mov qword ptr [r14+bwx_T_CALLER],1
bwx_control_maybe_take:
    cmp qword ptr [r12+8],4
    jne bwx_control_emit
    mov qword ptr [r14+bwx_T_CALLER],2
    mov edi,1
    mov rsi,[r12+16]
    mov rdx,[r14+bwx_T_JOB]
    mov rcx,[r14+bwx_T_RESULT]
    lea r8,[r13+128]
    mov r9,r14
    call bwx_emit
    ret
bwx_control_emit:
    mov edi,1
    mov rsi,[r12+16]
    mov rdx,[r14+bwx_T_JOB]
    mov rcx,[r13+400]
    lea r8,[r13+128]
    xor r9d,r9d
    call bwx_emit
    ret
bwx_release_control:
    mov dword ptr [r14+bwx_T_HOLD_RELEASED],1
    lea rdi,[r14+bwx_T_HOLD_RELEASED]
    call bwx_wake_all
    mov edi,4
    mov rsi,[r14+bwx_T_JOB]
    xor edx,edx
    xor ecx,ecx
    lea r8,[r13+128]
    call bwx_pool_command
    mov [r13+400],rax
    jmp bwx_control_emit
bwx_missing_control:
    lea rdi,[r13+128]
    xor eax,eax
    mov ecx,16
    rep stosq
    mov edi,1
    mov rsi,[r12+16]
    mov rdx,[r12+24]
    mov ecx,0xffffffff
    lea r8,[r13+128]
    xor r9d,r9d
    call bwx_emit
    ret
bwx_stats:
    cmp qword ptr [r12+24],0
    jne bwx_fatal
    mov edi,10
    xor esi,esi
    xor edx,edx
    xor ecx,ecx
    lea r8,[r13+128]
    call bwx_pool_command
    cmp eax,128
    jne bwx_fatal
    mov edi,1
    mov rsi,[r12+16]
    xor edx,edx
    mov ecx,128
    lea r8,[r13+128]
    xor r9d,r9d
    call bwx_emit
    ret
bwx_shutdown_control:
    cmp qword ptr [r12+24],0
    jne bwx_fatal
    call bwx_begin_shutdown
    mov edi,1
    mov rsi,[r12+16]
    xor edx,edx
    mov ecx,128
    lea r8,[r13+128]
    xor r9d,r9d
    call bwx_emit
    ret
bwx_begin_shutdown:
    push rbx
    mov edi,9
    xor esi,esi
    xor edx,edx
    xor ecx,ecx
    lea r8,[r13+128]
    call bwx_pool_command
    cmp eax,128
    jne bwx_fatal
    mov qword ptr [r15+bwx_G_CLOSING],1
    mov rbx,[r15+bwx_G_HEAD]
bwx_shutdown_mark:
    test rbx,rbx
    jz bwx_shutdown_marked
    cmp qword ptr [rbx+bwx_T_CALLER],0
    jne bwx_shutdown_next
    mov qword ptr [rbx+bwx_T_CALLER],1
bwx_shutdown_next:
    mov rbx,[rbx+bwx_T_NEXT]
    jmp bwx_shutdown_mark
bwx_shutdown_marked:
    pop rbx
    ret

bwx_submit:
    cmp qword ptr [r12+24],0
    jne bwx_fatal
    cmp qword ptr [r12+32],4
    ja bwx_fatal
    mov edi,1
    xor esi,esi
    xor edx,edx
    xor ecx,ecx
    lea r8,[r13+128]
    call bwx_pool_command
    cmp eax,128
    jne bwx_fatal
    cmp qword ptr [r13+144],0
    je bwx_submit_admitted
    mov edi,1
    mov rsi,[r12+16]
    xor edx,edx
    mov ecx,128
    lea r8,[r13+128]
    xor r9d,r9d
    call bwx_emit
    ret
bwx_submit_admitted:
    mov edi,4096
    call bwx_map_rw
    mov r14,rax
    mov rax,[r13+160]
    mov [r14+bwx_T_JOB],rax
    mov rax,[r12+16]
    mov [r14+bwx_T_TAG],rax
    mov rax,[r12+32]
    mov [r14+bwx_T_HOLD_MODE],rax
    mov rax,[r15+bwx_G_HEAD]
    mov [r14+bwx_T_NEXT],rax
    mov [r15+bwx_G_HEAD],r14
    mov rdi,[r12+40]
    mov [r14+bwx_T_INPUT_LEN],rdi
    call bwx_map_rw
    mov [r14+bwx_T_INPUT],rax
    mov rdi,rax
    lea rsi,[r12+64]
    mov rcx,[r12+40]
    rep movsb
    mov rdi,[r14+bwx_T_INPUT]
    mov rsi,[r14+bwx_T_INPUT_LEN]
    test rsi,rsi
    jnz bwx_protect_payload
    mov esi,1
bwx_protect_payload:
    mov edx,1
    mov eax,10
    syscall
    test rax,rax
    jnz bwx_fatal
    mov edi,bwx_CORE_OUT_BYTES
    call bwx_map_rw
    mov [r14+bwx_T_CORE_OUT],rax
    mov edi,bwx_CORE_WORK_BYTES
    call bwx_map_rw
    mov [r14+bwx_T_CORE_WORK],rax
    mov edi,bwx_STACK_BYTES
    call bwx_map_rw
    mov [r14+bwx_T_STACK],rax
    lea rsi,[rax+bwx_STACK_BYTES]
    mov edi,0x511 /* CLONE_VM | CLONE_FILES | SIGCHLD; separate private stack. */
    xor edx,edx
    xor r10d,r10d
    xor r8d,r8d
    mov eax,56
    syscall
    test rax,rax
    jz bwx_worker_start
    js bwx_clone_failed
    mov [r14+bwx_T_PID],rax
    mov edi,1
    xor esi,esi
    call bwx_process_event
    mov edi,2
    mov rsi,[r14+bwx_T_JOB]
    xor edx,edx
    xor ecx,ecx
    lea r8,[r13+128]
    call bwx_pool_command
    cmp eax,128
    jne bwx_fatal
    cmp qword ptr [r13+144],0
    jne bwx_fatal
    mov edi,1
    mov rsi,[r12+16]
    mov rdx,[r14+bwx_T_JOB]
    mov ecx,128
    lea r8,[r13+128]
    xor r9d,r9d
    call bwx_emit
    /* Child cannot BEGIN until the successful physical clone is acknowledged. */
    mov dword ptr [r14+bwx_T_GATE],1
    lea rdi,[r14+bwx_T_GATE]
    call bwx_wake_all
    ret
bwx_clone_failed:
    neg rax
    mov [r14+bwx_T_RESULT],rax
    mov rsi,rax
    mov edi,3
    call bwx_process_event
    mov rcx,[r14+bwx_T_RESULT]
    mov edi,11
    mov rsi,[r14+bwx_T_JOB]
    xor edx,edx
    lea r8,[r14+bwx_T_COMPLETE]
    call bwx_pool_command
    cmp eax,128
    jne bwx_fatal
    mov qword ptr [r14+bwx_T_FINISHED],1
    mov qword ptr [r14+bwx_T_REAPED],1
    mov edi,1
    mov rsi,[r12+16]
    mov rdx,[r14+bwx_T_JOB]
    mov ecx,128
    lea r8,[r14+bwx_T_COMPLETE]
    xor r9d,r9d
    call bwx_emit
    ret

/* Receipt-driven cleanup: no mapping is retired before actual reaping AND caller retirement. */
bwx_scan_tasks:
    push rbp
    lea rbp,[r15+bwx_G_HEAD]
bwx_scan_next:
    mov r14,[rbp]
    test r14,r14
    jz bwx_scan_done
    cmp qword ptr [r14+bwx_T_REAPED],0
    jne bwx_scan_ready
    mov rdi,[r14+bwx_T_PID]
    test rdi,rdi
    jz bwx_fatal
    lea rsi,[r14+bwx_T_STATUS]
    mov edx,1
    xor r10d,r10d
    mov eax,61
    syscall
    cmp rax,-4
    je bwx_scan_next
    test rax,rax
    js bwx_fatal
    jz bwx_scan_ready
    cmp rax,[r14+bwx_T_PID]
    jne bwx_fatal
    mov edi,2
    mov esi,[r14+bwx_T_STATUS]
    call bwx_process_event
    /* The worker publishes this mechanical flag only after HIA COMPLETE.
     * A caller POLL is deliberately invalid after that caller was dropped;
     * actual wait4 establishes that the worker can no longer mutate the flag. */
    cmp qword ptr [r14+bwx_T_FINISHED],1
    je bwx_scan_normal_reap
    call bwx_clock_now
    mov rdx,rax
    mov edi,12
    mov rsi,[r14+bwx_T_JOB]
    mov ecx,[r14+bwx_T_STATUS]
    test ecx,ecx
    jnz bwx_scan_abnormal_status
    mov ecx,256
bwx_scan_abnormal_status:
    mov [r14+bwx_T_RESULT],rcx
    mov [r14+bwx_T_FINISH],rdx
    lea r8,[r14+bwx_T_COMPLETE]
    call bwx_pool_command
    cmp eax,128
    jne bwx_fatal
    mov qword ptr [r14+bwx_T_FINISHED],1
    jmp bwx_scan_reaped
bwx_scan_normal_reap:
    mov edi,8
    mov rsi,[r14+bwx_T_JOB]
    xor edx,edx
    xor ecx,ecx
    lea r8,[r13+128]
    call bwx_pool_command
    cmp eax,128
    jne bwx_fatal
    mov qword ptr [r14+bwx_T_FINISHED],1
bwx_scan_reaped:
    mov qword ptr [r14+bwx_T_REAPED],1
bwx_scan_ready:
    cmp qword ptr [r14+bwx_T_FINISHED],0
    je bwx_scan_keep
    cmp qword ptr [r14+bwx_T_ANNOUNCED],0
    jne bwx_scan_maybe_free
    mov edi,2
    mov rsi,[r14+bwx_T_TAG]
    mov rdx,[r14+bwx_T_JOB]
    mov rcx,[r14+bwx_T_RESULT]
    lea r8,[r14+bwx_T_COMPLETE]
    xor r9d,r9d
    call bwx_emit
    mov qword ptr [r14+bwx_T_ANNOUNCED],1
bwx_scan_maybe_free:
    cmp qword ptr [r14+bwx_T_REAPED],0
    je bwx_scan_keep
    cmp qword ptr [r14+bwx_T_CALLER],0
    je bwx_scan_keep
    mov rax,[r14+bwx_T_NEXT]
    mov [rbp],rax
    call bwx_free_task
    jmp bwx_scan_next
bwx_scan_keep:
    lea rbp,[r14+bwx_T_NEXT]
    jmp bwx_scan_next
bwx_scan_done:
    pop rbp
    ret

.include "bellman_worker_callable_api.S"
.include "bellman_worker_common.S"
.include "bellman_worker_run.S"
