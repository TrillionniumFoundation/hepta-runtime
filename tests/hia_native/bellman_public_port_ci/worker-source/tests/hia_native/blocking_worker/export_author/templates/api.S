/* All exports are SysV functions. No call changes a borrowed result mapping.
 * One serial host owns the persistent instance; actual workers use G_MUTEX. */
.macro API_PROLOGUE
    push rbp
    mov rbp,rsp
    push rbx
    push r12
    push r13
    push r14
    push r15
    and rsp,-16
    sub rsp,4096
    mov r13,rsp
    mov [rbp-48],rsi
    mov [rbp-56],rdx
    mov [rbp-64],rcx
    mov r15,rdi
.endm
.macro API_ENTER
    API_PROLOGUE
    call api_enter
    test rax,rax
    jnz api_return
.endm
.macro REQUIRE_UNBORROWED
    cmp qword ptr [r15+G_BORROWED],0
    jne api_locked_invalid
.endm

.global bellman_worker_init
bellman_worker_init:
    API_PROLOGUE
    mov [rbp-72],rdi
    xor r15d,r15d
    cmp rdi,2
    jb api_invalid
    mov esi,1 /* F_GETFD: caller owns and keeps the actual journal descriptor. */
    xor edx,edx
    mov eax,72
    syscall
    test rax,rax
    js api_invalid
    mov edi,4096
    call map_rw
    mov r15,rax
    mov rax,[rbp-72]
    mov [r15+G_JOURNAL_FD],rax
    mov rax,0x3130545358574248 /* HBWXST01 */
    mov [r15+G_MAGIC],rax
    mov eax,39
    syscall
    mov [r15+G_PID],rax
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
    /* fd 1/2 identify emit/journal calls inside the retained adapter. */
    cmp qword ptr [r15+G_WAKE_R],2
    jbe fatal
    cmp qword ptr [r15+G_WAKE_W],2
    jbe fatal
    xor edi,edi
    xor esi,esi
    xor edx,edx
    xor ecx,ecx
    lea r8,[r13+128]
    call pool_command
    cmp eax,128
    jne fatal
    mov rax,r15
    jmp api_return

api_enter:
    test r15,r15
    jz api_enter_invalid
    mov rax,0x3130545358574248
    cmp [r15+G_MAGIC],rax
    jne api_enter_invalid
    mov eax,39
    syscall
    cmp rax,[r15+G_PID]
    jne api_enter_invalid
    xor eax,eax
    mov ecx,1
    lock cmpxchg qword ptr [r15+G_API_LOCK],rcx
    jnz api_enter_busy
    xor eax,eax
    ret
api_enter_busy:
    mov eax,0xfffffff9
    ret
api_enter_invalid:
    mov eax,0xffffffff
    ret

.global bellman_worker_control
bellman_worker_control:
    API_ENTER
    REQUIRE_UNBORROWED
    mov rsi,[rbp-48]
    mov rdx,[rbp-56]
    cmp rdx,64
    jb api_locked_invalid
    cmp rdx,16777280
    ja api_locked_invalid
    mov rax,0x313051524b574248
    cmp [rsi],rax
    jne api_locked_invalid
    lea rax,[rdx-64]
    cmp [rsi+40],rax
    jne api_locked_invalid
    cmp qword ptr [rsi+48],0
    jne api_locked_invalid
    cmp qword ptr [rsi+56],0
    jne api_locked_invalid
    mov rax,[rsi+8]
    cmp rax,1
    jb api_locked_invalid
    cmp rax,7
    ja api_locked_invalid
    cmp rax,1
    jne api_control_no_payload
    cmp qword ptr [rsi+24],0
    jne api_locked_invalid
    cmp qword ptr [rsi+32],4
    ja api_locked_invalid
    jmp api_control_admitted
api_control_no_payload:
    cmp qword ptr [rsi+32],0
    jne api_locked_invalid
    cmp qword ptr [rsi+40],0
    jne api_locked_invalid
    cmp rax,5
    je api_control_no_job
    cmp rax,6
    jne api_control_admitted
api_control_no_job:
    cmp qword ptr [rsi+24],0
    jne api_locked_invalid
api_control_admitted:
    mov [r15+G_INPUT_LEN],rdx
    mov rdi,[r15+G_INPUT]
    mov rcx,rdx
    rep movsb
    call control
    xor eax,eax
    jmp api_unlock_return

.global bellman_worker_poll
bellman_worker_poll:
    API_ENTER
    REQUIRE_UNBORROWED
    call scan_tasks
api_drain_wake:
    mov rdi,[r15+G_WAKE_R]
    lea rsi,[r13+800]
    mov edx,8
    xor eax,eax
    syscall
    cmp rax,-4
    je api_drain_wake
    cmp rax,8
    je api_drain_wake
    cmp rax,-11
    jne fatal
    xor eax,eax
    mov rcx,[r15+G_OUTPUT_CURSOR]
    cmp rcx,[r15+G_OUTPUT_USED]
    setb al
    jmp api_unlock_return

.global bellman_worker_receive
bellman_worker_receive:
    API_ENTER
    REQUIRE_UNBORROWED
    cmp qword ptr [rbp-56],32
    jb api_locked_capacity
    mov rax,[r15+G_OUTPUT_CURSOR]
    cmp rax,[r15+G_OUTPUT_USED]
    je api_return_pending
    mov rcx,[r15+G_BORROW_SEQUENCE]
    cmp rcx,-1
    je api_locked_capacity
    inc rcx
    mov rdx,[r15+G_OUTPUT]
    add rdx,rax
    mov r8,[rdx]
    cmp r8,192
    jb fatal
    lea rax,[rax+r8+8]
    cmp rax,[r15+G_OUTPUT_USED]
    ja fatal
    mov [r15+G_BORROW_SEQUENCE],rcx
    mov [r15+G_BORROWED],rcx
    mov [r15+G_BORROW_EXTENT],r8
    mov rdi,[rbp-48]
    mov rax,0x3130575242574248 /* HBWBRW01 */
    mov [rdi],rax
    add rdx,8
    mov [rdi+8],rdx
    mov [rdi+16],r8
    mov [rdi+24],rcx
    mov eax,32
    jmp api_unlock_return
api_return_pending:
    xor eax,eax
    jmp api_unlock_return

.global bellman_worker_release
bellman_worker_release:
    API_ENTER
    mov rax,[rbp-48]
    test rax,rax
    jz api_locked_invalid
    cmp rax,[r15+G_BORROWED]
    jne api_locked_invalid
    mov rax,[r15+G_BORROW_EXTENT]
    add rax,8
    add [r15+G_OUTPUT_CURSOR],rax
    mov qword ptr [r15+G_BORROWED],0
    mov qword ptr [r15+G_BORROW_EXTENT],0
    mov rax,[r15+G_OUTPUT_CURSOR]
    cmp rax,[r15+G_OUTPUT_USED]
    jne api_release_done
    mov qword ptr [r15+G_OUTPUT_CURSOR],0
    mov qword ptr [r15+G_OUTPUT_USED],0
api_release_done:
    xor eax,eax
    jmp api_unlock_return

.global bellman_worker_wake_fd
bellman_worker_wake_fd:
    API_ENTER
    mov rax,[r15+G_WAKE_R]
    jmp api_unlock_return

.global bellman_worker_shutdown
bellman_worker_shutdown:
    API_ENTER
    REQUIRE_UNBORROWED
    cmp qword ptr [r15+G_CLOSING],0
    jne api_shutdown_done
    call begin_shutdown
api_shutdown_done:
    xor eax,eax
    jmp api_unlock_return

.global bellman_worker_destroy
bellman_worker_destroy:
    API_ENTER
    REQUIRE_UNBORROWED
    cmp qword ptr [r15+G_CLOSING],1
    jne api_locked_pending
    cmp qword ptr [r15+G_HEAD],0
    jne api_locked_pending
    mov rax,[r15+G_OUTPUT_CURSOR]
    cmp rax,[r15+G_OUTPUT_USED]
    jne api_locked_pending
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
    mov rax,0x31444e4550574248
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
    test rax,rax
    jnz fatal
    mov edi,2
    mov rsi,[r15+G_POOL]
    mov rdx,[r15+G_POOL_BYTES]
    call write_all
    test rax,rax
    jnz fatal
    mov rdi,[r15+G_WAKE_R]
    mov eax,3
    syscall
    test rax,rax
    jnz fatal
    mov rdi,[r15+G_WAKE_W]
    mov eax,3
    syscall
    test rax,rax
    jnz fatal
    mov rdi,[r15+G_INPUT]
    mov esi,16777280
    call unmap_if
    mov rdi,[r15+G_OUTPUT]
    mov rsi,[r15+G_OUTPUT_CAPACITY]
    call unmap_if
    mov rdi,[r15+G_POOL]
    mov rsi,[r15+G_POOL_BYTES]
    call unmap_if
    mov qword ptr [r15+G_MAGIC],0
    mov qword ptr [r15+G_API_LOCK],0
    mov rdi,r15
    mov esi,4096
    call unmap_if
    xor eax,eax
    jmp api_return

api_locked_invalid:
    mov eax,0xffffffff
    jmp api_unlock_return
api_locked_capacity:
    mov eax,0xfffffffe
    jmp api_unlock_return
api_locked_pending:
    mov eax,0xfffffff8
    jmp api_unlock_return
api_invalid:
    mov eax,0xffffffff
    jmp api_return
api_unlock_return:
    mov qword ptr [r15+G_API_LOCK],0
api_return:
    lea rsp,[rbp-40]
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    leave
    ret

/* Parent-only exact immutable stream spool; original emit builds every byte. */
queue_append:
    push rbp
    mov rbp,rsp
    sub rsp,64
    mov [rbp-8],rsi
    mov [rbp-16],rdx
    cmp qword ptr [r15+G_BORROWED],0
    jne fatal
    mov rax,[r15+G_OUTPUT_USED]
    add rax,rdx
    jc fatal
    mov [rbp-24],rax
    cmp rax,[r15+G_OUTPUT_CAPACITY]
    jbe queue_copy
    mov rdx,[r15+G_OUTPUT_CAPACITY]
    test rdx,rdx
    jnz queue_grow_again
    mov edx,4096
queue_grow_again:
    cmp rdx,[rbp-24]
    jae queue_grow_ready
    shl rdx,1
    jc fatal
    jmp queue_grow_again
queue_grow_ready:
    mov [rbp-32],rdx
    mov rdi,[r15+G_OUTPUT]
    test rdi,rdi
    jnz queue_remap
    mov rdi,rdx
    call map_rw
    jmp queue_grown
queue_remap:
    mov rsi,[r15+G_OUTPUT_CAPACITY]
    mov r10d,1
    xor r8d,r8d
    mov eax,25
    syscall
    cmp rax,-4095
    jae fatal
queue_grown:
    mov [r15+G_OUTPUT],rax
    mov rax,[rbp-32]
    mov [r15+G_OUTPUT_CAPACITY],rax
queue_copy:
    mov rdi,[r15+G_OUTPUT]
    add rdi,[r15+G_OUTPUT_USED]
    mov rsi,[rbp-8]
    mov rcx,[rbp-16]
    rep movsb
    mov rax,[rbp-24]
    mov [r15+G_OUTPUT_USED],rax
    xor eax,eax
    leave
    ret
