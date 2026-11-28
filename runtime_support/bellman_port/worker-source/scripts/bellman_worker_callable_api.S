/* All exports are SysV functions. No call changes a borrowed result mapping.
 * One serial host owns the persistent instance; actual workers use bwx_G_MUTEX. */
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
    call bwx_api_enter
    test rax,rax
    jnz bwx_api_return
.endm
.macro REQUIRE_UNBORROWED
    cmp qword ptr [r15+bwx_G_BORROWED],0
    jne bwx_api_locked_invalid
.endm

.global bellman_worker_init
bellman_worker_init:
    API_PROLOGUE
    mov [rbp-72],rdi
    xor r15d,r15d
    cmp rdi,2
    jb bwx_api_invalid
    mov esi,1 /* F_GETFD: caller owns and keeps the actual journal descriptor. */
    xor edx,edx
    mov eax,72
    syscall
    test rax,rax
    js bwx_api_invalid
    mov edi,4096
    call bwx_map_rw
    mov r15,rax
    mov rax,[rbp-72]
    mov [r15+bwx_G_JOURNAL_FD],rax
    mov rax,0x3130545358574248 /* HBWXST01 */
    mov [r15+bwx_G_MAGIC],rax
    mov eax,39
    syscall
    mov [r15+bwx_G_PID],rax
    mov edi,4096
    call bwx_map_rw
    mov [r15+bwx_G_POOL],rax
    mov qword ptr [r15+bwx_G_POOL_BYTES],4096
    mov edi,16777280
    call bwx_map_rw
    mov [r15+bwx_G_INPUT],rax
    lea rdi,[r13+32]
    mov esi,0x80800
    mov eax,293
    syscall
    test rax,rax
    jnz bwx_fatal
    mov eax,[r13+32]
    mov [r15+bwx_G_WAKE_R],rax
    mov eax,[r13+36]
    mov [r15+bwx_G_WAKE_W],rax
    /* fd 1/2 identify bwx_emit/journal calls inside the retained adapter. */
    cmp qword ptr [r15+bwx_G_WAKE_R],2
    jbe bwx_fatal
    cmp qword ptr [r15+bwx_G_WAKE_W],2
    jbe bwx_fatal
    xor edi,edi
    xor esi,esi
    xor edx,edx
    xor ecx,ecx
    lea r8,[r13+128]
    call bwx_pool_command
    cmp eax,128
    jne bwx_fatal
    mov rax,r15
    jmp bwx_api_return

bwx_api_enter:
    test r15,r15
    jz bwx_api_enter_invalid
    mov rax,0x3130545358574248
    cmp [r15+bwx_G_MAGIC],rax
    jne bwx_api_enter_invalid
    mov eax,39
    syscall
    cmp rax,[r15+bwx_G_PID]
    jne bwx_api_enter_invalid
    xor eax,eax
    mov ecx,1
    lock cmpxchg qword ptr [r15+bwx_G_API_LOCK],rcx
    jnz bwx_api_enter_busy
    xor eax,eax
    ret
bwx_api_enter_busy:
    mov eax,0xfffffff9
    ret
bwx_api_enter_invalid:
    mov eax,0xffffffff
    ret

.global bellman_worker_control
bellman_worker_control:
    API_ENTER
    REQUIRE_UNBORROWED
    mov rsi,[rbp-48]
    mov rdx,[rbp-56]
    cmp rdx,64
    jb bwx_api_locked_invalid
    cmp rdx,16777280
    ja bwx_api_locked_invalid
    mov rax,0x313051524b574248
    cmp [rsi],rax
    jne bwx_api_locked_invalid
    lea rax,[rdx-64]
    cmp [rsi+40],rax
    jne bwx_api_locked_invalid
    cmp qword ptr [rsi+48],0
    jne bwx_api_locked_invalid
    cmp qword ptr [rsi+56],0
    jne bwx_api_locked_invalid
    mov rax,[rsi+8]
    cmp rax,1
    jb bwx_api_locked_invalid
    cmp rax,7
    ja bwx_api_locked_invalid
    cmp rax,1
    jne bwx_api_control_no_payload
    cmp qword ptr [rsi+24],0
    jne bwx_api_locked_invalid
    cmp qword ptr [rsi+32],4
    ja bwx_api_locked_invalid
    jmp bwx_api_control_admitted
bwx_api_control_no_payload:
    cmp qword ptr [rsi+32],0
    jne bwx_api_locked_invalid
    cmp qword ptr [rsi+40],0
    jne bwx_api_locked_invalid
    cmp rax,5
    je bwx_api_control_no_job
    cmp rax,6
    jne bwx_api_control_admitted
bwx_api_control_no_job:
    cmp qword ptr [rsi+24],0
    jne bwx_api_locked_invalid
bwx_api_control_admitted:
    mov [r15+bwx_G_INPUT_LEN],rdx
    mov rdi,[r15+bwx_G_INPUT]
    mov rcx,rdx
    rep movsb
    call bwx_control
    xor eax,eax
    jmp bwx_api_unlock_return

.global bellman_worker_poll
bellman_worker_poll:
    API_ENTER
    REQUIRE_UNBORROWED
    call bwx_scan_tasks
bwx_api_drain_wake:
    mov rdi,[r15+bwx_G_WAKE_R]
    lea rsi,[r13+800]
    mov edx,8
    xor eax,eax
    syscall
    cmp rax,-4
    je bwx_api_drain_wake
    cmp rax,8
    je bwx_api_drain_wake
    cmp rax,-11
    jne bwx_fatal
    xor eax,eax
    mov rcx,[r15+bwx_G_OUTPUT_CURSOR]
    cmp rcx,[r15+bwx_G_OUTPUT_USED]
    setb al
    jmp bwx_api_unlock_return

.global bellman_worker_receive
bellman_worker_receive:
    API_ENTER
    REQUIRE_UNBORROWED
    cmp qword ptr [rbp-56],32
    jb bwx_api_locked_capacity
    mov rax,[r15+bwx_G_OUTPUT_CURSOR]
    cmp rax,[r15+bwx_G_OUTPUT_USED]
    je bwx_api_return_pending
    mov rcx,[r15+bwx_G_BORROW_SEQUENCE]
    cmp rcx,-1
    je bwx_api_locked_capacity
    inc rcx
    mov rdx,[r15+bwx_G_OUTPUT]
    add rdx,rax
    mov r8,[rdx]
    cmp r8,192
    jb bwx_fatal
    lea rax,[rax+r8+8]
    cmp rax,[r15+bwx_G_OUTPUT_USED]
    ja bwx_fatal
    mov [r15+bwx_G_BORROW_SEQUENCE],rcx
    mov [r15+bwx_G_BORROWED],rcx
    mov [r15+bwx_G_BORROW_EXTENT],r8
    mov rdi,[rbp-48]
    mov rax,0x3130575242574248 /* HBWBRW01 */
    mov [rdi],rax
    add rdx,8
    mov [rdi+8],rdx
    mov [rdi+16],r8
    mov [rdi+24],rcx
    mov eax,32
    jmp bwx_api_unlock_return
bwx_api_return_pending:
    xor eax,eax
    jmp bwx_api_unlock_return

.global bellman_worker_release
bellman_worker_release:
    API_ENTER
    mov rax,[rbp-48]
    test rax,rax
    jz bwx_api_locked_invalid
    cmp rax,[r15+bwx_G_BORROWED]
    jne bwx_api_locked_invalid
    mov rax,[r15+bwx_G_BORROW_EXTENT]
    add rax,8
    add [r15+bwx_G_OUTPUT_CURSOR],rax
    mov qword ptr [r15+bwx_G_BORROWED],0
    mov qword ptr [r15+bwx_G_BORROW_EXTENT],0
    mov rax,[r15+bwx_G_OUTPUT_CURSOR]
    cmp rax,[r15+bwx_G_OUTPUT_USED]
    jne bwx_api_release_done
    mov qword ptr [r15+bwx_G_OUTPUT_CURSOR],0
    mov qword ptr [r15+bwx_G_OUTPUT_USED],0
bwx_api_release_done:
    xor eax,eax
    jmp bwx_api_unlock_return

.global bellman_worker_wake_fd
bellman_worker_wake_fd:
    API_ENTER
    mov rax,[r15+bwx_G_WAKE_R]
    jmp bwx_api_unlock_return

.global bellman_worker_shutdown
bellman_worker_shutdown:
    API_ENTER
    REQUIRE_UNBORROWED
    cmp qword ptr [r15+bwx_G_CLOSING],0
    jne bwx_api_shutdown_done
    call bwx_begin_shutdown
bwx_api_shutdown_done:
    xor eax,eax
    jmp bwx_api_unlock_return

.global bellman_worker_destroy
bellman_worker_destroy:
    API_ENTER
    REQUIRE_UNBORROWED
    cmp qword ptr [r15+bwx_G_CLOSING],1
    jne bwx_api_locked_pending
    cmp qword ptr [r15+bwx_G_HEAD],0
    jne bwx_api_locked_pending
    mov rax,[r15+bwx_G_OUTPUT_CURSOR]
    cmp rax,[r15+bwx_G_OUTPUT_USED]
    jne bwx_api_locked_pending
    mov edi,10
    xor esi,esi
    xor edx,edx
    xor ecx,ecx
    lea r8,[r13+128]
    call bwx_pool_command
    cmp eax,128
    jne bwx_fatal
    cmp qword ptr [r13+224],0
    jne bwx_fatal
    cmp qword ptr [r13+232],0
    jne bwx_fatal
    mov rdi,r13
    xor eax,eax
    mov ecx,8
    rep stosq
    mov rax,0x31444e4550574248
    mov [r13],rax
    mov rax,[r15+bwx_G_POOL_BYTES]
    mov [r13+16],rax
    add rax,64
    mov [r13+8],rax
    mov rax,[r15+bwx_G_PID]
    mov [r13+24],rax
    mov rax,[r15+152]
    mov [r13+32],rax
    mov edi,2
    mov rsi,r13
    mov edx,64
    call bwx_write_all
    test rax,rax
    jnz bwx_fatal
    mov edi,2
    mov rsi,[r15+bwx_G_POOL]
    mov rdx,[r15+bwx_G_POOL_BYTES]
    call bwx_write_all
    test rax,rax
    jnz bwx_fatal
    mov rdi,[r15+bwx_G_WAKE_R]
    mov eax,3
    syscall
    test rax,rax
    jnz bwx_fatal
    mov rdi,[r15+bwx_G_WAKE_W]
    mov eax,3
    syscall
    test rax,rax
    jnz bwx_fatal
    mov rdi,[r15+bwx_G_INPUT]
    mov esi,16777280
    call bwx_unmap_if
    mov rdi,[r15+bwx_G_OUTPUT]
    mov rsi,[r15+bwx_G_OUTPUT_CAPACITY]
    call bwx_unmap_if
    mov rdi,[r15+bwx_G_POOL]
    mov rsi,[r15+bwx_G_POOL_BYTES]
    call bwx_unmap_if
    mov qword ptr [r15+bwx_G_MAGIC],0
    mov qword ptr [r15+bwx_G_API_LOCK],0
    mov rdi,r15
    mov esi,4096
    call bwx_unmap_if
    xor eax,eax
    jmp bwx_api_return

bwx_api_locked_invalid:
    mov eax,0xffffffff
    jmp bwx_api_unlock_return
bwx_api_locked_capacity:
    mov eax,0xfffffffe
    jmp bwx_api_unlock_return
bwx_api_locked_pending:
    mov eax,0xfffffff8
    jmp bwx_api_unlock_return
bwx_api_invalid:
    mov eax,0xffffffff
    jmp bwx_api_return
bwx_api_unlock_return:
    mov qword ptr [r15+bwx_G_API_LOCK],0
bwx_api_return:
    lea rsp,[rbp-40]
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    leave
    ret

/* Parent-only exact immutable stream spool; original bwx_emit builds every byte. */
bwx_queue_append:
    push rbp
    mov rbp,rsp
    sub rsp,64
    mov [rbp-8],rsi
    mov [rbp-16],rdx
    cmp qword ptr [r15+bwx_G_BORROWED],0
    jne bwx_fatal
    mov rax,[r15+bwx_G_OUTPUT_USED]
    add rax,rdx
    jc bwx_fatal
    mov [rbp-24],rax
    cmp rax,[r15+bwx_G_OUTPUT_CAPACITY]
    jbe bwx_queue_copy
    mov rdx,[r15+bwx_G_OUTPUT_CAPACITY]
    test rdx,rdx
    jnz bwx_queue_grow_again
    mov edx,4096
bwx_queue_grow_again:
    cmp rdx,[rbp-24]
    jae bwx_queue_grow_ready
    shl rdx,1
    jc bwx_fatal
    jmp bwx_queue_grow_again
bwx_queue_grow_ready:
    mov [rbp-32],rdx
    mov rdi,[r15+bwx_G_OUTPUT]
    test rdi,rdi
    jnz bwx_queue_remap
    mov rdi,rdx
    call bwx_map_rw
    jmp bwx_queue_grown
bwx_queue_remap:
    mov rsi,[r15+bwx_G_OUTPUT_CAPACITY]
    mov r10d,1
    xor r8d,r8d
    mov eax,25
    syscall
    cmp rax,-4095
    jae bwx_fatal
bwx_queue_grown:
    mov [r15+bwx_G_OUTPUT],rax
    mov rax,[rbp-32]
    mov [r15+bwx_G_OUTPUT_CAPACITY],rax
bwx_queue_copy:
    mov rdi,[r15+bwx_G_OUTPUT]
    add rdi,[r15+bwx_G_OUTPUT_USED]
    mov rsi,[rbp-8]
    mov rcx,[rbp-16]
    rep movsb
    mov rax,[rbp-24]
    mov [r15+bwx_G_OUTPUT_USED],rax
    xor eax,eax
    leave
    ret
