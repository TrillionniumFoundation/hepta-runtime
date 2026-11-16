/* Bounded syscall and borrowed-buffer plumbing, no Bellman arithmetic. */
map_rw:
    mov rsi,rdi
    test rsi,rsi
    jnz map_nonempty
    mov esi,4096
map_nonempty:
    xor edi,edi
    mov edx,3
    mov r10d,34
    mov r8,-1
    xor r9d,r9d
    mov eax,9
    syscall
    cmp rax,-4095
    jae fatal
    ret

clock_now:
    push rbp
    mov rbp,rsp
    sub rsp,16
    mov edi,1
    mov rsi,rsp
    mov eax,228
    syscall
    test rax,rax
    jnz fatal
    mov rax,[rsp]
    mov rcx,1000000000
    mul rcx
    test rdx,rdx
    jnz fatal
    mov rcx,[rsp+8]
    cmp rcx,1000000000
    jae fatal
    add rax,rcx
    jc fatal
    leave
    ret

wake_all:
    mov esi,1
    mov edx,2147483647
    xor r10d,r10d
    xor r8d,r8d
    xor r9d,r9d
    mov eax,202
    syscall
    test rax,rax
    js fatal
    ret

mutex_lock:
    push rbp
    mov rbp,rsp
    sub rsp,32
    mov [rbp-8],rdi
    mov eax,39
    syscall
    mov [rbp-16],eax
mutex_retry:
    mov rdi,[rbp-8]
    xor eax,eax
    mov ecx,[rbp-16]
    lock cmpxchg dword ptr [rdi],ecx
    jz mutex_acquired
    mov edx,eax
    mov qword ptr [rbp-32],0
    mov qword ptr [rbp-24],10000000
    xor esi,esi
    lea r10,[rbp-32]
    xor r8d,r8d
    xor r9d,r9d
    mov eax,202
    syscall
    cmp rax,-110
    jne mutex_retry
    /* Unexpected death inside a shared mutation is fail-stop, never repaired
     * into a claimed successful pool transition. A parent can reap its child. */
    mov eax,[rbp-16]
    cmp rax,[r15+G_PID]
    jne mutex_retry
    mov rcx,[rbp-8]
    mov edi,[rcx]
    test edi,edi
    jz mutex_retry
    xor esi,esi
    mov edx,1
    xor r10d,r10d
    mov eax,61
    syscall
    test rax,rax
    jg fatal
    jmp mutex_retry
mutex_acquired:
    leave
    ret

mutex_unlock:
    mov dword ptr [rdi],0
    jmp wake_all

/* cmd,job,now,arg,out -> raw HIA status. Shared state is borrowed under mutex. */
pool_command:
    push rbp
    mov rbp,rsp
    and rsp,-16
    sub rsp,448
    mov [rbp-16],r8
    mov [rbp-440],rdi
    mov [rbp-432],rsi
    mov [rbp-424],rdx
    mov [rbp-416],rcx
    mov rax,0x3130515257504248 /* HBPWRQ01 */
    mov [rbp-448],rax
    mov qword ptr [rbp-408],0
    mov qword ptr [rbp-400],0
    mov qword ptr [rbp-392],0
    lea rdi,[r15+G_MUTEX]
    call mutex_lock
pool_invoke:
    mov rdi,[rbp-16]
    xor eax,eax
    mov ecx,16
    rep stosq
    lea rdi,[rbp-448]
    mov esi,64
    mov rdx,[rbp-16]
    mov ecx,128
    mov r8,[r15+G_POOL]
    mov r9,[r15+G_POOL_BYTES]
    call pool_entry
    mov edx,eax
    cmp rax,rdx
    jne fatal
    mov [rbp-8],rax
    call pool_record
    mov rax,[rbp-8]
    cmp eax,0xffffffd0
    jne pool_returned
    mov r8,[rbp-16]
    mov rax,0x3230305357524748 /* HGRWS002 */
    cmp [r8],rax
    jne fatal
    cmp qword ptr [r8+8],1
    jne fatal
    cmp qword ptr [r8+24],0
    jne fatal
    mov rdx,[r8+16]
    cmp rdx,[r15+G_POOL_BYTES]
    jbe fatal
    add rdx,4095
    jc fatal
    and rdx,-4096
    cmp rdx,268435456
    ja fatal
    mov [rbp-24],rdx
    mov rdi,[r15+G_POOL]
    mov rsi,[r15+G_POOL_BYTES]
    mov r10d,1
    xor r8d,r8d
    mov eax,25
    syscall
    cmp rax,-4095
    jae fatal
    mov [r15+G_POOL],rax
    mov rax,[rbp-24]
    mov [r15+G_POOL_BYTES],rax
    jmp pool_invoke
pool_returned:
    lea rdi,[r15+G_MUTEX]
    call mutex_unlock
    mov rax,[rbp-8]
    leave
    ret
pool_record:
    /* Every actual pool call has its complete request and response retained. */
    lea rdi,[rbp-384]
    xor eax,eax
    mov ecx,32
    rep stosq
    mov rax,0x3130304c50574248 /* HBWPL001 */
    mov [rbp-384],rax
    mov qword ptr [rbp-376],256
    mov eax,39
    syscall
    mov [rbp-368],rax
    mov rax,[rbp-440]
    mov [rbp-360],rax
    lea rsi,[rbp-448]
    lea rdi,[rbp-352]
    mov ecx,64
    rep movsb
    mov rax,[rbp-8]
    mov [rbp-288],rax
    inc qword ptr [r15+152]
    mov rax,[r15+152]
    mov [rbp-280],rax
    mov rsi,[rbp-16]
    lea rdi,[rbp-272]
    mov ecx,128
    rep movsb
    mov edi,2
    lea rsi,[rbp-384]
    mov edx,256
    call write_all
    ret

/* Physical clone and wait4 outcomes, observed only by the owning parent. */
process_event:
    push rbp
    mov rbp,rsp
    sub rsp,64
    mov [rsp+40],rdi
    mov [rsp+48],rsi
    mov rax,0x31434f5250574248 /* HBWPROC1 */
    mov [rsp],rax
    mov qword ptr [rsp+8],64
    mov rax,[r15+G_PID]
    mov [rsp+16],rax
    mov rax,[r14+T_JOB]
    mov [rsp+24],rax
    mov rax,[r14+T_PID]
    mov [rsp+32],rax
    mov qword ptr [rsp+56],0
    mov edi,2
    mov rsi,rsp
    mov edx,64
    call write_all
    test eax,eax
    jnz fatal
    leave
    ret

/* Only the parent publishes stdout, preserving frame boundaries and custody. */
emit:
    cmp qword ptr [r15+144],0
    jne emit_suppressed
    push rbp
    mov rbp,rsp
    sub rsp,256
    mov [rbp-8],r8
    mov [rbp-16],r9
    mov [rbp-232],rdi
    mov [rbp-224],rsi
    mov [rbp-216],rdx
    mov [rbp-208],rcx
    mov qword ptr [rbp-192],0
    mov qword ptr [rbp-200],0
    test r9,r9
    jz emit_lengths
    mov rax,[r9+T_CORE_LEN]
    add rax,[r9+T_COMMIT_LEN]
    jc fatal
    add rax,[r9+T_RENDER_LEN]
    jc fatal
    add rax,96
    jc fatal
    mov [rbp-200],rax
emit_lengths:
    mov rax,[rbp-200]
    add rax,192
    jc fatal
    mov [rbp-256],rax
    mov [rbp-240],rax
    mov rax,0x313052534d504248 /* HBPMSR01 */
    mov [rbp-248],rax
    mov edi,1
    lea rsi,[rbp-256]
    mov edx,72
    call write_all
    test eax,eax
    jnz emit_io_failed
    mov edi,1
    mov rsi,[rbp-8]
    mov edx,128
    call write_all
    test eax,eax
    jnz emit_io_failed
    mov r10,[rbp-16]
    test r10,r10
    jz emit_done
    lea rdi,[rbp-176]
    xor eax,eax
    mov ecx,12
    rep stosq
    mov rax,0x31444f424b574248 /* HBWKBOD1 */
    mov [rbp-176],rax
    mov rax,[rbp-200]
    mov [rbp-168],rax
    mov rax,[r10+T_CORE_LEN]
    mov [rbp-160],rax
    mov rax,[r10+T_COMMIT_LEN]
    mov [rbp-152],rax
    mov rax,[r10+T_RENDER_LEN]
    mov [rbp-144],rax
    mov rax,[r10+T_START]
    mov [rbp-136],rax
    mov rax,[r10+T_FINISH]
    mov [rbp-128],rax
    mov rax,[r10+T_ELAPSED]
    mov [rbp-120],rax
    mov rax,[r10+T_CLOCKS]
    mov [rbp-112],rax
    mov rax,[r10+T_RESULT]
    mov [rbp-104],rax
    mov rax,[r10+T_HOLD_MODE]
    mov [rbp-96],rax
    mov rax,[r10+T_ELAPSED_NS]
    mov [rbp-88],rax
    mov edi,1
    lea rsi,[rbp-176]
    mov edx,96
    call write_all
    test eax,eax
    jnz emit_io_failed
    mov r10,[rbp-16]
    mov edi,1
    mov rsi,[r10+T_CORE_OUT]
    mov rdx,[r10+T_CORE_LEN]
    call write_all
    test eax,eax
    jnz emit_io_failed
    mov r10,[rbp-16]
    mov edi,1
    mov rsi,[r10+T_COMMIT_OUT]
    mov rdx,[r10+T_COMMIT_LEN]
    call write_all
    test eax,eax
    jnz emit_io_failed
    mov r10,[rbp-16]
    mov edi,1
    mov rsi,[r10+T_RENDER_OUT]
    mov rdx,[r10+T_RENDER_LEN]
    call write_all
    test eax,eax
    jnz emit_io_failed
emit_done:
    xor eax,eax
    leave
    ret
emit_io_failed:
    mov qword ptr [r15+144],1
    leave
    ret
emit_suppressed:
    xor eax,eax
    ret

write_all:
    push rbp
    mov rbp,rsp
    sub rsp,32
    mov [rbp-8],rdi
    mov [rbp-16],rsi
    mov [rbp-24],rdx
write_loop:
    cmp qword ptr [rbp-24],0
    je write_done
    mov rdi,[rbp-8]
    mov rsi,[rbp-16]
    mov rdx,[rbp-24]
    mov eax,1
    syscall
    cmp rax,-4
    je write_loop
    test rax,rax
    jle write_failed
    add [rbp-16],rax
    sub [rbp-24],rax
    jmp write_loop
write_done:
    xor eax,eax
write_failed:
    leave
    ret

unmap_if:
    test rdi,rdi
    jz unmap_done
    test rsi,rsi
    jnz unmap_run
    mov esi,4096
unmap_run:
    mov eax,11
    syscall
    test rax,rax
    jnz fatal
unmap_done:
    ret
free_task:
    mov rdi,[r14+T_INPUT]
    mov rsi,[r14+T_INPUT_LEN]
    call unmap_if
    mov rdi,[r14+T_CORE_OUT]
    mov esi,CORE_OUT_BYTES
    call unmap_if
    mov rdi,[r14+T_CORE_WORK]
    mov esi,CORE_WORK_BYTES
    call unmap_if
    mov rdi,[r14+T_COMMIT_IN]
    mov rsi,[r14+T_COMMIT_IN_LEN]
    call unmap_if
    mov rdi,[r14+T_COMMIT_OUT]
    mov esi,COMMIT_OUT_BYTES
    call unmap_if
    mov rdi,[r14+T_COMMIT_WORK]
    mov esi,COMMIT_WORK_BYTES
    call unmap_if
    mov rdi,[r14+T_RENDER_IN]
    mov rsi,[r14+T_RENDER_IN_LEN]
    call unmap_if
    mov rdi,[r14+T_RENDER_OUT]
    mov esi,RENDER_BYTES
    call unmap_if
    mov rdi,[r14+T_RENDER_WORK]
    mov esi,RENDER_BYTES
    call unmap_if
    mov rdi,[r14+T_STACK]
    mov esi,STACK_BYTES
    call unmap_if
    mov rdi,r14
    mov esi,4096
    call unmap_if
    ret

bare_usage:
    mov edi,64
    mov eax,60
    syscall
    ud2
fatal:
    test r15,r15
    jz fatal_exit
    mov eax,39
    syscall
    cmp rax,[r15+G_PID]
    jne fatal_exit
    /* Parent fail-stop always kills and reaps its actual children first. */
    mov rbx,[r15+G_HEAD]
fatal_kill:
    test rbx,rbx
    jz fatal_wait_begin
    mov rdi,[rbx+T_PID]
    test rdi,rdi
    jz fatal_kill_next
    cmp qword ptr [rbx+T_REAPED],0
    jne fatal_kill_next
    mov esi,9
    mov eax,62
    syscall
fatal_kill_next:
    mov rbx,[rbx+T_NEXT]
    jmp fatal_kill
fatal_wait_begin:
    mov rbx,[r15+G_HEAD]
fatal_wait:
    test rbx,rbx
    jz fatal_exit
    mov rdi,[rbx+T_PID]
    test rdi,rdi
    jz fatal_wait_next
    cmp qword ptr [rbx+T_REAPED],0
    jne fatal_wait_next
    xor esi,esi
    xor edx,edx
    xor r10d,r10d
    mov eax,61
    syscall
    cmp rax,-4
    je fatal_wait
fatal_wait_next:
    mov rbx,[rbx+T_NEXT]
    jmp fatal_wait
fatal_exit:
    mov edi,74
    mov eax,60
    syscall
    ud2
