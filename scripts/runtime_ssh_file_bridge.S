/* Fixed slot77 adapts only the admitted HIA SSH plan to the process-owned
 * native worker. It never parses JSON or substitutes a synthetic completion.
 * The event-loop is the sole caller of start/poll/cancel/release; raw worker
 * threads cannot release an outer call record. */
.intel_syntax noprefix
.section .text
.global runtime_ssh_body_owned
.global runtime_ssh_body_resume
.macro RSB_SAVE
    push rbp
    push rbx
    push r12
    push r13
    push r14
    sub rsp,64
.endm
.macro RSB_RETURN
    add rsp,64
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret
.endm
runtime_ssh_body_owned:
    RSB_SAVE
    mov r13,rdi
    mov r14,rsi
    cmp qword ptr [r15+488],0
    jne rsb_bad
    cmp qword ptr [r12],0
    jne rsb_bad
    cmp qword ptr [r12+8],0
    jne rsb_bad
    call runtime_ssh_install_ensure
    test rax,rax
    js rsb_resource
    mov rdi,rax
    mov rsi,r13
    mov rdx,r14
    xor ecx,ecx
    call hsw_start
    test rax,rax
    js rsb_resource
    mov [r15+488],rax
    mov qword ptr [r12],1
    mov qword ptr [r12+8],0
    jmp rsb_wait
runtime_ssh_body_resume:
    RSB_SAVE
    mov r13,rdi
    mov r14,rsi
    mov rbp,rdx
    cmp qword ptr [r12],1
    jne rsb_bad
    cmp qword ptr [r12+8],0
    jne rsb_bad
    mov rdi,[r15+488]
    test rdi,rdi
    jz rsb_bad
    mov rax,[r15+480]
    cmp [rdi+8],rax
    jne rsb_bad
    mov rcx,[rdi+32]
    sub rcx,64
    jc rsb_bad
    cmp rcx,r14
    jne rsb_bad
    mov rsi,[rdi+24]
    add rsi,64
    mov rdi,r13
    repe cmpsb
    jne rsb_bad
    cmp rbp,3
    je rsb_drop
    cmp rbp,2
    jne rsb_bad
    mov rdi,[r15+488]
    mov rsi,rsp
    call hsw_poll
    cmp eax,0xffffffdf
    je rsb_wait
    test eax,eax
    jnz rsb_bad
    cmp qword ptr [rsp+32],2
    jne rsb_bad
    mov r14,[rsp+8]
    cmp r14,128
    jb rsb_bad
    cmp r14,16777344
    ja rsb_bad
    cmp [rsp+16],r14
    jne rsb_bad
    cmp qword ptr [rbx+32],0
    jne rsb_capacity
    lea rdi,[r14+4095]
    and rdi,-4096
    mov [rsp+48],rdi
    call view_allocate
    cmp rax,-4095
    jae rsb_resource
    mov [rbx+32],rax
    mov rax,[rsp+48]
    mov [rbx+40],rax
    bts qword ptr [r15+RG_OUTPUT_HIGH],13
rsb_capacity:
    cmp r14,[rbx+40]
    jbe rsb_copy
    mov rdi,rbx
    mov esi,2
    mov rdx,r14
    call runtime_grow_resize_borrow
    test eax,eax
    jnz rsb_resource
rsb_copy:
    mov rdi,[rbx+32]
    mov rsi,[rsp]
    mov rcx,r14
    rep movsb
    mov rdi,[r15+488]
    call hsw_release
    test rax,rax
    jnz rsb_bad
    mov qword ptr [r15+488],0
    mov qword ptr [r12],0
    mov [rbx+48],r14
    mov [rbx+56],r14
    mov rax,r14
    RSB_RETURN
rsb_drop:
    /* The handler disappears now; the process root keeps the original call,
     * input, pipe ownership and thread stack until its actual joined Finish. */
    mov rdi,[r15+488]
    mov esi,1
    call hsw_cancel
    test rax,rax
    jnz rsb_bad
    mov qword ptr [r15+488],0
    mov qword ptr [r12],0
    mov eax,0xfffffff7
    mov [rbx+48],rax
    mov qword ptr [rbx+56],0
    RSB_RETURN
rsb_wait:
    mov eax,0xffffffdf
    mov [rbx+48],rax
    mov qword ptr [rbx+56],0
    RSB_RETURN
rsb_resource:
    mov eax,0xfffffffc
    RSB_RETURN
rsb_bad:
    mov eax,0xffffffff
    RSB_RETURN
