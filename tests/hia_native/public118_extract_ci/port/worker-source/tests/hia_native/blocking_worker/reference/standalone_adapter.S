/* Fixed private Linux bridge: HIA owns permits, deadlines, mathematics and JSON. */
.intel_syntax noprefix
.section .text
.global _start
.type _start,@function
.equ G_MUTEX,0
.equ G_POOL,8
.equ G_POOL_BYTES,16
.equ G_HEAD,24
.equ G_PID,32
.equ G_CLOSING,40
.equ G_WAKE_R,48
.equ G_WAKE_W,56
.equ G_INPUT,64
.equ G_INPUT_LEN,80
.equ G_INPUT_USED,88
.equ G_INPUT_STAGE,96
.equ G_HEADER,104
.equ G_POLL,112
.equ G_NOTICE,128
.equ T_NEXT,0
.equ T_JOB,8
.equ T_TAG,16
.equ T_PID,24
.equ T_GATE,32
.equ T_FINISHED,40
.equ T_REAPED,48
.equ T_CALLER,56
.equ T_INPUT,64
.equ T_INPUT_LEN,72
.equ T_CORE_OUT,88
.equ T_CORE_WORK,104
.equ T_COMMIT_IN,120
.equ T_COMMIT_IN_LEN,128
.equ T_COMMIT_OUT,144
.equ T_COMMIT_WORK,160
.equ T_RENDER_IN,176
.equ T_RENDER_IN_LEN,184
.equ T_RENDER_OUT,200
.equ T_RENDER_WORK,216
.equ T_STACK,232
.equ T_START,248
.equ T_FINISH,256
.equ T_ELAPSED,264
.equ T_RESULT,272
.equ T_CORE_LEN,280
.equ T_COMMIT_LEN,288
.equ T_RENDER_LEN,296
.equ T_HOLD_MODE,304
.equ T_HOLD_RELEASED,312
.equ T_CLOCKS,320
.equ T_ANNOUNCED,328
.equ T_STATUS,336
.equ T_ELAPSED_NS,360
.equ T_COMPLETE,512
.equ CORE_OUT_BYTES,295040
.equ CORE_WORK_BYTES,295552
.equ COMMIT_OUT_BYTES,8388736
.equ COMMIT_WORK_BYTES,8405504
.equ RENDER_BYTES,1069056
.equ STACK_BYTES,1048576

_start:
    cmp qword ptr [rsp],1
    jne bare_usage
    and rsp,-16
    sub rsp,4096
    mov r13,rsp
    xor r15d,r15d
    mov edi,4096
    call map_rw
    mov r15,rax
    mov eax,39
    syscall
    mov [r15+G_PID],rax
    /* SIGPIPE is an ordinary failed transport, never an abandoned worker. */
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
    jnz fatal
    mov edi,4096
    call map_rw
    mov [r15+G_POOL],rax
    mov qword ptr [r15+G_POOL_BYTES],4096
    mov edi,16777280
    call map_rw
    mov [r15+G_INPUT],rax
    lea rdi,[r13+32]
    mov esi,0x80800
    mov eax,293
    syscall
    test rax,rax
    jnz fatal
    mov eax,[r13+32]
    mov [r15+G_WAKE_R],rax
    mov eax,[r13+36]
    mov [r15+G_WAKE_W],rax
    xor edi,edi
    mov esi,3
    xor edx,edx
    mov eax,72
    syscall
    test rax,rax
    js fatal
    mov edx,eax
    or edx,0x800
    xor edi,edi
    mov esi,4
    mov eax,72
    syscall
    test rax,rax
    jnz fatal
    xor edi,edi
    xor esi,esi
    xor edx,edx
    xor ecx,ecx
    lea r8,[r13+128]
    call pool_command
    cmp eax,128
    jne fatal
main_loop:
    cmp qword ptr [r15+144],0
    je main_transport_checked
    cmp qword ptr [r15+G_CLOSING],0
    jne main_transport_checked
    call begin_shutdown
main_transport_checked:
    call scan_tasks
    cmp qword ptr [r15+G_CLOSING],0
    jne closing_loop
    call read_frame
    test eax,eax
    jnz main_loop
    jmp wait_events
closing_loop:
    cmp qword ptr [r15+G_HEAD],0
    jne wait_events
    mov edi,10
    xor esi,esi
    xor edx,edx
    xor ecx,ecx
    lea r8,[r13+128]
    call pool_command
    cmp eax,128
    jne fatal
    cmp qword ptr [r13+224],0
    jne fatal
    cmp qword ptr [r13+232],0
    jne fatal
    mov rdi,r13
    xor eax,eax
    mov ecx,8
    rep stosq
    mov rax,0x31444e4550574248 /* HBWPEND1 */
    mov [r13],rax
    mov rax,[r15+G_POOL_BYTES]
    mov [r13+16],rax
    add rax,64
    mov [r13+8],rax
    mov rax,[r15+G_PID]
    mov [r13+24],rax
    mov rax,[r15+152]
    mov [r13+32],rax
    mov edi,2
    mov rsi,r13
    mov edx,64
    call write_all
    mov edi,2
    mov rsi,[r15+G_POOL]
    mov rdx,[r15+G_POOL_BYTES]
    call write_all
    xor edi,edi
    cmp qword ptr [r15+144],0
    je closing_exit
    mov edi,74
closing_exit:
    mov eax,60
    syscall
    ud2
wait_events:
    mov dword ptr [r15+G_POLL],0
    mov dword ptr [r15+G_POLL+4],1
    cmp qword ptr [r15+G_CLOSING],0
    je wait_input_set
    mov dword ptr [r15+G_POLL],-1
wait_input_set:
    mov eax,[r15+G_WAKE_R]
    mov [r15+G_POLL+8],eax
    mov dword ptr [r15+G_POLL+12],1
    lea rdi,[r15+G_POLL]
    mov esi,2
    mov edx,-1
    cmp qword ptr [r15+G_HEAD],0
    je wait_poll
    mov edx,10
wait_poll:
    mov eax,7
    syscall
    cmp rax,-4
    je main_loop
    test rax,rax
    js fatal
drain_notices:
    mov rdi,[r15+G_WAKE_R]
    lea rsi,[r15+G_NOTICE]
    mov edx,8
    xor eax,eax
    syscall
    cmp rax,-4
    je drain_notices
    cmp rax,-11
    je main_loop
    cmp rax,8
    je drain_notices
    jmp fatal

/* Parent uses the existing directory scheduler's partial-frame/nonblocking pattern. */
read_frame:
    cmp qword ptr [r15+G_INPUT_STAGE],0
    jne read_body
    lea rsi,[r15+G_HEADER]
    mov edx,8
    jmp read_selected
read_body:
    mov rsi,[r15+G_INPUT]
    mov rdx,[r15+G_INPUT_LEN]
read_selected:
    mov rcx,[r15+G_INPUT_USED]
    add rsi,rcx
    sub rdx,rcx
    jz fatal
    xor edi,edi
    xor eax,eax
    syscall
    cmp rax,-4
    je read_frame
    cmp rax,-11
    je read_would_block
    test rax,rax
    js fatal
    jz input_eof
    add [r15+G_INPUT_USED],rax
    cmp qword ptr [r15+G_INPUT_STAGE],0
    jne body_progress
    cmp qword ptr [r15+G_INPUT_USED],8
    jb read_frame
    mov rax,[r15+G_HEADER]
    cmp rax,64
    jb fatal
    cmp rax,16777280
    ja fatal
    mov [r15+G_INPUT_LEN],rax
    mov qword ptr [r15+G_INPUT_STAGE],1
    mov qword ptr [r15+G_INPUT_USED],0
    jmp read_frame
body_progress:
    mov rax,[r15+G_INPUT_USED]
    cmp rax,[r15+G_INPUT_LEN]
    jb read_frame
    jne fatal
    call control
    mov qword ptr [r15+G_INPUT_STAGE],0
    mov qword ptr [r15+G_INPUT_USED],0
    mov qword ptr [r15+G_INPUT_LEN],0
    mov eax,1
    ret
read_would_block:
    xor eax,eax
    ret
input_eof:
    cmp qword ptr [r15+G_INPUT_STAGE],0
    jne fatal
    cmp qword ptr [r15+G_INPUT_USED],0
    jne fatal
    call begin_shutdown
    mov eax,1
    ret

control:
    mov r12,[r15+G_INPUT]
    mov rax,0x313051524b574248 /* HBWKRQ01 */
    cmp [r12],rax
    jne fatal
    mov rax,[r15+G_INPUT_LEN]
    sub rax,64
    cmp [r12+40],rax
    jne fatal
    cmp qword ptr [r12+48],0
    jne fatal
    cmp qword ptr [r12+56],0
    jne fatal
    mov rax,[r12+8]
    cmp rax,1
    je submit
    cmp qword ptr [r12+40],0
    jne fatal
    cmp qword ptr [r12+32],0
    jne fatal
    cmp rax,5
    je stats
    cmp rax,6
    je shutdown_control
    cmp rax,2
    jb fatal
    cmp rax,7
    ja fatal
    mov r14,[r15+G_HEAD]
find_control:
    test r14,r14
    jz missing_control
    mov rax,[r12+24]
    cmp [r14+T_JOB],rax
    je found_control
    mov r14,[r14+T_NEXT]
    jmp find_control
found_control:
    mov rax,[r12+8]
    cmp rax,7
    je release_control
    mov edi,4
    cmp rax,2
    je selected_control
    mov edi,6
    cmp rax,3
    je selected_control
    cmp rax,4
    jne fatal
    mov edi,7
selected_control:
    mov rsi,[r14+T_JOB]
    xor edx,edx
    xor ecx,ecx
    lea r8,[r13+128]
    call pool_command
    mov [r13+400],rax
    cmp eax,128
    jne control_emit
    cmp qword ptr [r13+144],0
    jne control_emit
    cmp qword ptr [r12+8],3
    jne control_maybe_take
    mov qword ptr [r14+T_CALLER],1
control_maybe_take:
    cmp qword ptr [r12+8],4
    jne control_emit
    mov qword ptr [r14+T_CALLER],2
    mov edi,1
    mov rsi,[r12+16]
    mov rdx,[r14+T_JOB]
    mov rcx,[r14+T_RESULT]
    lea r8,[r13+128]
    mov r9,r14
    call emit
    ret
control_emit:
    mov edi,1
    mov rsi,[r12+16]
    mov rdx,[r14+T_JOB]
    mov rcx,[r13+400]
    lea r8,[r13+128]
    xor r9d,r9d
    call emit
    ret
release_control:
    mov dword ptr [r14+T_HOLD_RELEASED],1
    lea rdi,[r14+T_HOLD_RELEASED]
    call wake_all
    mov edi,4
    mov rsi,[r14+T_JOB]
    xor edx,edx
    xor ecx,ecx
    lea r8,[r13+128]
    call pool_command
    mov [r13+400],rax
    jmp control_emit
missing_control:
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
    call emit
    ret
stats:
    cmp qword ptr [r12+24],0
    jne fatal
    mov edi,10
    xor esi,esi
    xor edx,edx
    xor ecx,ecx
    lea r8,[r13+128]
    call pool_command
    cmp eax,128
    jne fatal
    mov edi,1
    mov rsi,[r12+16]
    xor edx,edx
    mov ecx,128
    lea r8,[r13+128]
    xor r9d,r9d
    call emit
    ret
shutdown_control:
    cmp qword ptr [r12+24],0
    jne fatal
    call begin_shutdown
    mov edi,1
    mov rsi,[r12+16]
    xor edx,edx
    mov ecx,128
    lea r8,[r13+128]
    xor r9d,r9d
    call emit
    ret
begin_shutdown:
    push rbx
    mov edi,9
    xor esi,esi
    xor edx,edx
    xor ecx,ecx
    lea r8,[r13+128]
    call pool_command
    cmp eax,128
    jne fatal
    mov qword ptr [r15+G_CLOSING],1
    mov rbx,[r15+G_HEAD]
shutdown_mark:
    test rbx,rbx
    jz shutdown_marked
    cmp qword ptr [rbx+T_CALLER],0
    jne shutdown_next
    mov qword ptr [rbx+T_CALLER],1
shutdown_next:
    mov rbx,[rbx+T_NEXT]
    jmp shutdown_mark
shutdown_marked:
    pop rbx
    ret

submit:
    cmp qword ptr [r12+24],0
    jne fatal
    cmp qword ptr [r12+32],4
    ja fatal
    mov edi,1
    xor esi,esi
    xor edx,edx
    xor ecx,ecx
    lea r8,[r13+128]
    call pool_command
    cmp eax,128
    jne fatal
    cmp qword ptr [r13+144],0
    je submit_admitted
    mov edi,1
    mov rsi,[r12+16]
    xor edx,edx
    mov ecx,128
    lea r8,[r13+128]
    xor r9d,r9d
    call emit
    ret
submit_admitted:
    mov edi,4096
    call map_rw
    mov r14,rax
    mov rax,[r13+160]
    mov [r14+T_JOB],rax
    mov rax,[r12+16]
    mov [r14+T_TAG],rax
    mov rax,[r12+32]
    mov [r14+T_HOLD_MODE],rax
    mov rax,[r15+G_HEAD]
    mov [r14+T_NEXT],rax
    mov [r15+G_HEAD],r14
    mov rdi,[r12+40]
    mov [r14+T_INPUT_LEN],rdi
    call map_rw
    mov [r14+T_INPUT],rax
    mov rdi,rax
    lea rsi,[r12+64]
    mov rcx,[r12+40]
    rep movsb
    mov rdi,[r14+T_INPUT]
    mov rsi,[r14+T_INPUT_LEN]
    test rsi,rsi
    jnz protect_payload
    mov esi,1
protect_payload:
    mov edx,1
    mov eax,10
    syscall
    test rax,rax
    jnz fatal
    mov edi,CORE_OUT_BYTES
    call map_rw
    mov [r14+T_CORE_OUT],rax
    mov edi,CORE_WORK_BYTES
    call map_rw
    mov [r14+T_CORE_WORK],rax
    mov edi,STACK_BYTES
    call map_rw
    mov [r14+T_STACK],rax
    lea rsi,[rax+STACK_BYTES]
    mov edi,0x511 /* CLONE_VM | CLONE_FILES | SIGCHLD; separate private stack. */
    xor edx,edx
    xor r10d,r10d
    xor r8d,r8d
    mov eax,56
    syscall
    test rax,rax
    jz worker_start
    js clone_failed
    mov [r14+T_PID],rax
    mov edi,1
    xor esi,esi
    call process_event
    mov edi,2
    mov rsi,[r14+T_JOB]
    xor edx,edx
    xor ecx,ecx
    lea r8,[r13+128]
    call pool_command
    cmp eax,128
    jne fatal
    cmp qword ptr [r13+144],0
    jne fatal
    mov edi,1
    mov rsi,[r12+16]
    mov rdx,[r14+T_JOB]
    mov ecx,128
    lea r8,[r13+128]
    xor r9d,r9d
    call emit
    /* Child cannot BEGIN until the successful physical clone is acknowledged. */
    mov dword ptr [r14+T_GATE],1
    lea rdi,[r14+T_GATE]
    call wake_all
    ret
clone_failed:
    neg rax
    mov [r14+T_RESULT],rax
    mov rsi,rax
    mov edi,3
    call process_event
    mov rcx,[r14+T_RESULT]
    mov edi,11
    mov rsi,[r14+T_JOB]
    xor edx,edx
    lea r8,[r14+T_COMPLETE]
    call pool_command
    cmp eax,128
    jne fatal
    mov qword ptr [r14+T_FINISHED],1
    mov qword ptr [r14+T_REAPED],1
    mov edi,1
    mov rsi,[r12+16]
    mov rdx,[r14+T_JOB]
    mov ecx,128
    lea r8,[r14+T_COMPLETE]
    xor r9d,r9d
    call emit
    ret

/* Receipt-driven cleanup: no mapping is retired before actual reaping AND caller retirement. */
scan_tasks:
    push rbp
    lea rbp,[r15+G_HEAD]
scan_next:
    mov r14,[rbp]
    test r14,r14
    jz scan_done
    cmp qword ptr [r14+T_REAPED],0
    jne scan_ready
    mov rdi,[r14+T_PID]
    test rdi,rdi
    jz fatal
    lea rsi,[r14+T_STATUS]
    mov edx,1
    xor r10d,r10d
    mov eax,61
    syscall
    cmp rax,-4
    je scan_next
    test rax,rax
    js fatal
    jz scan_ready
    cmp rax,[r14+T_PID]
    jne fatal
    mov edi,2
    mov esi,[r14+T_STATUS]
    call process_event
    /* The worker publishes this mechanical flag only after HIA COMPLETE.
     * A caller POLL is deliberately invalid after that caller was dropped;
     * actual wait4 establishes that the worker can no longer mutate the flag. */
    cmp qword ptr [r14+T_FINISHED],1
    je scan_normal_reap
    call clock_now
    mov rdx,rax
    mov edi,12
    mov rsi,[r14+T_JOB]
    mov ecx,[r14+T_STATUS]
    test ecx,ecx
    jnz scan_abnormal_status
    mov ecx,256
scan_abnormal_status:
    mov [r14+T_RESULT],rcx
    mov [r14+T_FINISH],rdx
    lea r8,[r14+T_COMPLETE]
    call pool_command
    cmp eax,128
    jne fatal
    mov qword ptr [r14+T_FINISHED],1
    jmp scan_reaped
scan_normal_reap:
    mov edi,8
    mov rsi,[r14+T_JOB]
    xor edx,edx
    xor ecx,ecx
    lea r8,[r13+128]
    call pool_command
    cmp eax,128
    jne fatal
    mov qword ptr [r14+T_FINISHED],1
scan_reaped:
    mov qword ptr [r14+T_REAPED],1
scan_ready:
    cmp qword ptr [r14+T_FINISHED],0
    je scan_keep
    cmp qword ptr [r14+T_ANNOUNCED],0
    jne scan_maybe_free
    mov edi,2
    mov rsi,[r14+T_TAG]
    mov rdx,[r14+T_JOB]
    mov rcx,[r14+T_RESULT]
    lea r8,[r14+T_COMPLETE]
    xor r9d,r9d
    call emit
    mov qword ptr [r14+T_ANNOUNCED],1
scan_maybe_free:
    cmp qword ptr [r14+T_REAPED],0
    je scan_keep
    cmp qword ptr [r14+T_CALLER],0
    je scan_keep
    mov rax,[r14+T_NEXT]
    mov [rbp],rax
    call free_task
    jmp scan_next
scan_keep:
    lea rbp,[r14+T_NEXT]
    jmp scan_next
scan_done:
    pop rbp
    ret

.include "bellman_worker_common.S"
.include "bellman_worker_run.S"

/* The build author appends fixed HIA images and records every byte offset. */
