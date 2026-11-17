/* A real owned worker runs fixed HIA images. Cancellation never branches here. */
bwx_worker_start:
    and rsp,-16
    sub rsp,4096
    mov r13,rsp
    mov edi,1
    mov esi,9
    xor edx,edx
    xor r10d,r10d
    xor r8d,r8d
    mov eax,157
    syscall
    test rax,rax
    jnz bwx_fatal
    mov eax,110
    syscall
    cmp rax,[r15+bwx_G_PID]
    jne bwx_fatal
    lea rdi,[r14+bwx_T_GATE]
    call bwx_wait_word
    cmp qword ptr [r14+bwx_T_HOLD_MODE],1
    jne bwx_worker_begin
    call bwx_held_wait
bwx_worker_begin:
    call bwx_clock_now
    mov [r14+bwx_T_START],rax
    mov rdx,rax
    mov edi,3
    mov rsi,[r14+bwx_T_JOB]
    xor ecx,ecx
    lea r8,[r13+256]
    call bwx_pool_command
    cmp eax,128
    jne bwx_fatal
    cmp qword ptr [r13+272],0
    jne bwx_fatal
    mov rax,0x31304e494d544248 /* HBTMIN01 */
    mov [r13],rax
    mov rax,[r14+bwx_T_JOB]
    mov [r13+8],rax
    mov rax,[r14+bwx_T_START]
    mov [r13+16],rax
    mov qword ptr [r13+24],1
    mov qword ptr [r13+32],0
    mov qword ptr [r13+40],0
    mov qword ptr [r13+48],0
    mov qword ptr [r13+56],0
    mov rdi,r13
    mov esi,64
    lea rdx,[r13+128]
    mov ecx,64
    mov r8,[r14+bwx_T_CORE_WORK]
    mov r9d,bwx_CORE_WORK_BYTES
    call bwx_core_entry
    cmp rax,64
    jne bwx_fatal
bwx_core_loop:
    mov rdi,[r14+bwx_T_INPUT]
    mov rsi,[r14+bwx_T_INPUT_LEN]
    mov rdx,[r14+bwx_T_CORE_OUT]
    mov ecx,bwx_CORE_OUT_BYTES
    mov r8,[r14+bwx_T_CORE_WORK]
    mov r9d,bwx_CORE_WORK_BYTES
    call bwx_core_entry
    mov edx,eax
    cmp rax,rdx
    jne bwx_fatal
    cmp eax,0xffffffe0
    je bwx_core_effect
    cmp eax,0xffff0000
    jae bwx_worker_result
    cmp eax,200
    jb bwx_fatal
    cmp eax,bwx_CORE_OUT_BYTES
    ja bwx_fatal
    mov [r14+bwx_T_CORE_LEN],rax
    jmp bwx_worker_render
bwx_core_effect:
    mov r12,[r14+bwx_T_CORE_WORK]
    add r12,bwx_CORE_WORK_BYTES-256
    mov rax,0x313046454d544248 /* HBTMEF01 */
    cmp [r12],rax
    jne bwx_fatal
    mov rax,[r14+344]
    inc rax
    cmp [r12+8],rax
    jne bwx_fatal
    mov [r14+344],rax
    mov rax,[r14+bwx_T_JOB]
    cmp [r12+24],rax
    jne bwx_fatal
    cmp qword ptr [r12+16],2
    je bwx_core_commitment
    cmp qword ptr [r12+16],1
    jne bwx_fatal
    cmp qword ptr [r14+bwx_T_HOLD_MODE],2
    jne bwx_core_clock
    cmp qword ptr [r12+8],1
    jne bwx_core_clock
    call bwx_held_wait
bwx_core_clock:
    mov edi,1
    mov rsi,r12
    call bwx_clock_effect
    mov rdx,rax
    xor ecx,ecx
    jmp bwx_core_ack
bwx_core_commitment:
    call bwx_run_commitment
    mov ecx,eax
    xor edx,edx
bwx_core_ack:
    mov rdi,[r14+bwx_T_CORE_WORK]
    add rdi,bwx_CORE_WORK_BYTES-128
    mov rax,0x31304b414d544248 /* HBTMAK01 */
    mov [rdi],rax
    mov rax,[r12+8]
    mov [rdi+8],rax
    mov rax,[r12+16]
    mov [rdi+16],rax
    mov rax,[r14+bwx_T_JOB]
    mov [rdi+24],rax
    mov [rdi+32],rdx
    mov [rdi+40],rcx
    mov qword ptr [rdi+48],0
    mov qword ptr [rdi+56],0
    jmp bwx_core_loop

bwx_run_commitment:
    push rbp
    mov rbp,rsp
    push r12
    sub rsp,8
    cmp qword ptr [r14+bwx_T_COMMIT_IN],0
    jne bwx_fatal
    mov rdi,[r14+bwx_T_INPUT_LEN]
    add rdi,40
    jc bwx_fatal
    mov [r14+bwx_T_COMMIT_IN_LEN],rdi
    call bwx_map_rw
    mov [r14+bwx_T_COMMIT_IN],rax
    mov rdi,rax
    mov rax,0x313030544d434248 /* HBCMT001 */
    mov [rdi],rax
    add rdi,8
    lea rsi,[rip+bwx_implementation_digest]
    mov ecx,32
    rep movsb
    mov rsi,[r14+bwx_T_INPUT]
    mov rcx,[r14+bwx_T_INPUT_LEN]
    rep movsb
    mov rdi,[r14+bwx_T_COMMIT_IN]
    mov rsi,[r14+bwx_T_COMMIT_IN_LEN]
    mov edx,1
    mov eax,10
    syscall
    test rax,rax
    jnz bwx_fatal
    mov edi,bwx_COMMIT_OUT_BYTES
    call bwx_map_rw
    mov [r14+bwx_T_COMMIT_OUT],rax
    mov edi,bwx_COMMIT_WORK_BYTES
    call bwx_map_rw
    mov [r14+bwx_T_COMMIT_WORK],rax
    mov rax,0x31304e4943544248 /* HBTCIN01 */
    mov [r13],rax
    mov rax,[r14+bwx_T_JOB]
    mov [r13+8],rax
    mov rax,[r14+bwx_T_START]
    mov [r13+16],rax
    mov qword ptr [r13+24],1
    mov qword ptr [r13+32],0
    mov qword ptr [r13+40],0
    mov qword ptr [r13+48],0
    mov qword ptr [r13+56],0
    mov rdi,r13
    mov esi,64
    lea rdx,[r13+128]
    mov ecx,64
    mov r8,[r14+bwx_T_COMMIT_WORK]
    mov r9d,bwx_COMMIT_WORK_BYTES
    call bwx_commitment_entry
    cmp rax,64
    jne bwx_fatal
bwx_commitment_loop:
    mov rdi,[r14+bwx_T_COMMIT_IN]
    mov rsi,[r14+bwx_T_COMMIT_IN_LEN]
    mov rdx,[r14+bwx_T_COMMIT_OUT]
    mov ecx,bwx_COMMIT_OUT_BYTES
    mov r8,[r14+bwx_T_COMMIT_WORK]
    mov r9d,bwx_COMMIT_WORK_BYTES
    call bwx_commitment_entry
    mov edx,eax
    cmp rax,rdx
    jne bwx_fatal
    cmp eax,0xffffffe0
    je bwx_commitment_effect
    cmp eax,0xffff0000
    jae bwx_commitment_return
    cmp eax,128
    jb bwx_fatal
    cmp eax,bwx_COMMIT_OUT_BYTES
    ja bwx_fatal
    mov [r14+bwx_T_COMMIT_LEN],rax
    xor eax,eax
    jmp bwx_commitment_return
bwx_commitment_effect:
    mov r12,[r14+bwx_T_COMMIT_WORK]
    add r12,bwx_COMMIT_WORK_BYTES-256
    mov rax,0x3130464543544248 /* HBTCEF01 */
    cmp [r12],rax
    jne bwx_fatal
    mov rax,[r14+352]
    inc rax
    cmp [r12+8],rax
    jne bwx_fatal
    mov [r14+352],rax
    mov rax,[r14+bwx_T_JOB]
    cmp [r12+24],rax
    jne bwx_fatal
    cmp qword ptr [r12+16],1
    jne bwx_fatal
    cmp qword ptr [r14+bwx_T_HOLD_MODE],3
    jne bwx_commitment_clock
    cmp qword ptr [r12+8],1
    jne bwx_commitment_clock
    call bwx_held_wait
bwx_commitment_clock:
    mov edi,2
    mov rsi,r12
    call bwx_clock_effect
    mov rdi,[r14+bwx_T_COMMIT_WORK]
    add rdi,bwx_COMMIT_WORK_BYTES-128
    mov [rdi+32],rax
    mov rax,0x31304b4143544248 /* HBTCAK01 */
    mov [rdi],rax
    mov rax,[r12+8]
    mov [rdi+8],rax
    mov qword ptr [rdi+16],1
    mov rax,[r14+bwx_T_JOB]
    mov [rdi+24],rax
    mov qword ptr [rdi+40],0
    mov qword ptr [rdi+48],0
    mov qword ptr [rdi+56],0
    jmp bwx_commitment_loop
bwx_commitment_return:
    add rsp,8
    pop r12
    pop rbp
    ret

bwx_worker_render:
    cmp qword ptr [r14+bwx_T_HOLD_MODE],4
    jne bwx_render_elapsed
    call bwx_held_wait
bwx_render_elapsed:
    call bwx_clock_now
    mov [r14+bwx_T_ELAPSED_NS],rax
    mov [r13+16],rax
    mov rax,0x313051524c454248 /* HBELRQ01 */
    mov [r13],rax
    mov rax,[r14+bwx_T_START]
    mov [r13+8],rax
    mov qword ptr [r13+24],0
    mov rdi,r13
    mov esi,32
    lea rdx,[r13+128]
    mov ecx,24
    lea r8,[r13+192]
    mov r9d,32
    call bwx_elapsed_entry
    cmp rax,24
    jne bwx_fatal
    mov rax,[r13+136]
    mov [r14+bwx_T_ELAPSED],rax
    mov rdi,[r14+bwx_T_CORE_LEN]
    add rdi,[r14+bwx_T_COMMIT_LEN]
    jc bwx_fatal
    add rdi,64
    jc bwx_fatal
    mov [r14+bwx_T_RENDER_IN_LEN],rdi
    call bwx_map_rw
    mov [r14+bwx_T_RENDER_IN],rax
    mov rdi,rax
    mov rax,0x313051524d4c4248 /* HBLMRQ01 */
    mov [rdi],rax
    mov qword ptr [rdi+8],1
    mov rax,[r14+bwx_T_CORE_LEN]
    mov [rdi+16],rax
    mov rax,[r14+bwx_T_COMMIT_LEN]
    mov [rdi+24],rax
    mov rax,[r14+bwx_T_ELAPSED]
    mov [rdi+32],rax
    mov qword ptr [rdi+40],0
    mov qword ptr [rdi+48],0
    mov qword ptr [rdi+56],0
    add rdi,64
    mov rsi,[r14+bwx_T_CORE_OUT]
    mov rcx,[r14+bwx_T_CORE_LEN]
    rep movsb
    mov rsi,[r14+bwx_T_COMMIT_OUT]
    mov rcx,[r14+bwx_T_COMMIT_LEN]
    rep movsb
    mov rdi,[r14+bwx_T_RENDER_IN]
    mov rsi,[r14+bwx_T_RENDER_IN_LEN]
    mov edx,1
    mov eax,10
    syscall
    test rax,rax
    jnz bwx_fatal
    mov edi,bwx_RENDER_BYTES
    call bwx_map_rw
    mov [r14+bwx_T_RENDER_OUT],rax
    mov edi,bwx_RENDER_BYTES
    call bwx_map_rw
    mov [r14+bwx_T_RENDER_WORK],rax
    mov rdi,[r14+bwx_T_RENDER_IN]
    mov rsi,[r14+bwx_T_RENDER_IN_LEN]
    mov rdx,[r14+bwx_T_RENDER_OUT]
    mov ecx,bwx_RENDER_BYTES
    mov r8,[r14+bwx_T_RENDER_WORK]
    mov r9d,bwx_RENDER_BYTES
    call bwx_result_entry
    mov edx,eax
    cmp rax,rdx
    jne bwx_fatal
    cmp eax,0xffff0000
    jae bwx_worker_result
    cmp eax,64
    jbe bwx_fatal
    cmp eax,bwx_RENDER_BYTES
    ja bwx_fatal
    mov [r14+bwx_T_RENDER_LEN],rax
    xor eax,eax
bwx_worker_result:
    mov [r14+bwx_T_RESULT],rax
    call bwx_clock_now
    mov [r14+bwx_T_FINISH],rax
    mov rdx,rax
    mov edi,5
    mov rsi,[r14+bwx_T_JOB]
    mov rcx,[r14+bwx_T_RESULT]
    lea r8,[r14+bwx_T_COMPLETE]
    call bwx_pool_command
    cmp eax,128
    jne bwx_fatal
    cmp qword ptr [r14+bwx_T_COMPLETE+16],0
    jne bwx_fatal
    /* Full serialization has returned. Only now is the HIA permit released. */
    mov qword ptr [r14+bwx_T_FINISHED],1
    mov rdi,[r15+bwx_G_WAKE_W]
    lea rsi,[r14+bwx_T_JOB]
    mov edx,8
    call bwx_write_all
    /* EAGAIN only means a prior notice already makes the parent runnable. */
    xor edi,edi
    mov eax,60
    syscall
    ud2

bwx_wait_word:
    push rbp
    mov rbp,rsp
    sub rsp,16
    mov [rbp-8],rdi
bwx_wait_word_again:
    mov rdi,[rbp-8]
    cmp dword ptr [rdi],1
    je bwx_wait_word_done
    xor esi,esi
    xor edx,edx
    xor r10d,r10d
    xor r8d,r8d
    xor r9d,r9d
    mov eax,202
    syscall
    test rax,rax
    jz bwx_wait_word_again
    cmp rax,-4
    je bwx_wait_word_again
    cmp rax,-11
    je bwx_wait_word_again
    jmp bwx_fatal
bwx_wait_word_done:
    leave
    ret

/* Private qualification hold changes no HIA state and creates no await. */
bwx_held_wait:
    push rbp
    mov rbp,rsp
    sub rsp,64
    mov rax,0x31444c4857504248 /* HBPWHLD1 */
    mov [rsp],rax
    mov qword ptr [rsp+8],64
    mov rax,[r14+bwx_T_JOB]
    mov [rsp+16],rax
    mov eax,39
    syscall
    mov [rsp+24],rax
    mov rax,[r14+bwx_T_HOLD_MODE]
    mov [rsp+32],rax
    mov rax,[r14+bwx_T_CLOCKS]
    mov [rsp+40],rax
    mov qword ptr [rsp+48],0
    mov qword ptr [rsp+56],0
    mov edi,2
    mov rsi,rsp
    mov edx,64
    call bwx_write_all
    lea rdi,[r14+bwx_T_HOLD_RELEASED]
    call bwx_wait_word
    leave
    ret

/* owner, exact effect -> actual CLOCK_MONOTONIC value; all 128 effect bytes retained. */
bwx_clock_effect:
    push rbp
    mov rbp,rsp
    sub rsp,224
    mov [rbp-8],rdi
    mov [rbp-16],rsi
    call bwx_clock_now
    mov [rbp-24],rax
    inc qword ptr [r14+bwx_T_CLOCKS]
    mov rax,0x314b434f4c434248 /* HBCLOCK1 */
    mov [rbp-224],rax
    mov qword ptr [rbp-216],192
    mov rax,[r14+bwx_T_JOB]
    mov [rbp-208],rax
    mov eax,39
    syscall
    mov [rbp-200],rax
    mov rax,[rbp-8]
    mov [rbp-192],rax
    mov rax,[rbp-24]
    mov [rbp-184],rax
    mov qword ptr [rbp-176],0
    mov qword ptr [rbp-168],0
    mov rsi,[rbp-16]
    lea rdi,[rbp-160]
    mov ecx,128
    rep movsb
    mov edi,2
    lea rsi,[rbp-224]
    mov edx,192
    call bwx_write_all
    mov rax,[rbp-24]
    leave
    ret

.p2align 4,0
bwx_implementation_digest:
    .byte 0x25,0x4d,0xe6,0x1b,0x7a,0x16,0x9a,0xb0,0xa0,0x15,0x83,0xfe,0xb9,0x56,0x20,0x51
    .byte 0xfa,0x9d,0x47,0x7d,0x89,0xd9,0x86,0x83,0x26,0x3c,0x52,0xea,0x55,0x45,0xa4,0xa7
