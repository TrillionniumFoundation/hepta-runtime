_start:
    cmp qword ptr [rsp],1
    jne bare_usage
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
    jnz fatal
    mov edi,2
    call bellman_worker_init
    cmp eax,0xffffffff
    je bare_usage
    test rax,rax
    jz bare_usage
    mov r15,rax
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
fixture_loop:
    mov rdi,r15
    call bellman_worker_poll
    cmp rax,1
    ja fatal
fixture_receive:
    mov rdi,r15
    lea rsi,[r13+512]
    mov edx,32
    call bellman_worker_receive
    test rax,rax
    jz fixture_drained
    cmp rax,32
    jne fatal
    mov rax,[r13+528]
    mov [r13+600],rax
    mov edi,1
    lea rsi,[r13+600]
    mov edx,8
    call write_all_kernel
    test rax,rax
    jnz fatal
    mov edi,1
    mov rsi,[r13+520]
    mov rdx,[r13+528]
    call write_all_kernel
    test rax,rax
    jnz fatal
    mov rdi,r15
    mov rsi,[r13+536]
    call bellman_worker_release
    test rax,rax
    jnz fatal
    jmp fixture_receive
fixture_drained:
    cmp qword ptr [r15+G_CLOSING],0
    jne fixture_closing
    call read_frame
    test eax,eax
    jnz fixture_loop
    jmp fixture_wait
fixture_closing:
    cmp qword ptr [r15+G_HEAD],0
    jne fixture_wait
    mov rdi,r15
    call bellman_worker_destroy
    test rax,rax
    jnz bare_usage
    xor edi,edi
    mov eax,60
    syscall
    ud2
fixture_wait:
    mov dword ptr [r13+704],0
    mov dword ptr [r13+708],1
    cmp qword ptr [r15+G_CLOSING],0
    je fixture_input_ready
    mov dword ptr [r13+704],-1
fixture_input_ready:
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
    je fixture_loop
    test rax,rax
    js fatal
    jmp fixture_loop
