# Physical spawn owns its four pipe pairs from their actual return until each
# exact close. A failed exec is waited on before its failed-spawn receipt.
ssh_close_slot32:
    movsxd rax, DWORD PTR [rdi]
    test eax, eax
    js .Lclose_slot_done
    mov DWORD PTR [rdi], -1
    mov rdi, rax
    mov eax, 3
    syscall
.Lclose_slot_done:
    ret
ssh_close_all_pairs:
    push r12
    push r13
    sub rsp, 8
    mov r12, rdi
    xor r13d, r13d
.Lclose_pairs:
    lea rdi, [r12+R_PIPES+r13*4]
    call ssh_close_slot32
    inc r13
    cmp r13, 8
    jb .Lclose_pairs
    add rsp, 8
    pop r13
    pop r12
    ret
ssh_pipe_pair:
    push r12
    push r13
    mov r12, rdi
    mov esi, 524288
    mov eax, 293
    syscall
    test rax, rax
    js .Lpipe_return
    xor r13d, r13d
.Lpipe_relocate:
    movsxd rdi, DWORD PTR [r12+r13*4]
    cmp edi, 3
    jge .Lpipe_next
    mov esi, 1030
    mov edx, 3
    mov eax, 72
    syscall
    test rax, rax
    js .Lpipe_return
    movsxd rdi, DWORD PTR [r12+r13*4]
    mov DWORD PTR [r12+r13*4], eax
    mov eax, 3
    syscall
.Lpipe_next:
    inc r13
    cmp r13, 2
    jb .Lpipe_relocate
    xor eax, eax
.Lpipe_return:
    pop r13
    pop r12
    ret
ssh_spawn:
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub rsp, 16
    mov r13, rdi
    mov r12, QWORD PTR [r13+R_CTX]
    xor r14d, r14d
.Lspawn_pipes:
    mov rax, QWORD PTR [r13+R_FLAGS]
    bt rax, r14
    jnc .Lspawn_next_pipe
    lea rdi, [r13+R_PIPES+r14*8]
    call ssh_pipe_pair
    test rax, rax
    js .Lspawn_fail_before_fork
.Lspawn_next_pipe:
    inc r14
    cmp r14, 3
    jb .Lspawn_pipes
    lea rdi, [r13+R_PIPES+24]
    call ssh_pipe_pair
    test rax, rax
    js .Lspawn_fail_before_fork
    mov eax, 57
    syscall
    test rax, rax
    jz .Lspawn_child
    js .Lspawn_fail_before_fork
    mov QWORD PTR [r13+R_PID], rax
    mov r15, rax
    lea rdi, [r13+R_PIPES]
    call ssh_close_slot32
    lea rdi, [r13+R_PIPES+12]
    call ssh_close_slot32
    lea rdi, [r13+R_PIPES+20]
    call ssh_close_slot32
    lea rdi, [r13+R_PIPES+28]
    call ssh_close_slot32
.Lspawn_exec_receipt:
    mov edi, DWORD PTR [r13+R_PIPES+24]
    mov rsi, rsp
    mov edx, 8
    xor eax, eax
    syscall
    cmp rax, -4
    je .Lspawn_exec_receipt
    test rax, rax
    jz .Lspawn_exec_success
    cmp rax, 8
    jne .Lspawn_handshake_uncertain
    mov r14, QWORD PTR [rsp]
    test r14, r14
    jz .Lspawn_handshake_uncertain
    cmp r14, 4095
    ja .Lspawn_handshake_uncertain
    mov rdi, r13
    call ssh_close_all_pairs
.Lspawn_exec_reap:
    mov rdi, r15
    lea rsi, [r13+R_STATUS]
    xor edx, edx
    xor r10d, r10d
    mov eax, 61
    syscall
    cmp rax, -4
    je .Lspawn_exec_reap
    cmp rax, r15
    jne .Lspawn_wait_uncertain
    mov QWORD PTR [r13+R_PID], 0
    mov rax, r14
    neg rax
    jmp .Lspawn_return
.Lspawn_exec_success:
    lea rdi, [r13+R_PIPES+24]
    call ssh_close_slot32
    xor r14d, r14d
.Lspawn_nonblock:
    mov ebx, DWORD PTR [r13+R_PIPES+4]
    cmp r14, 0
    je .Lspawn_have_fd
    mov ebx, DWORD PTR [r13+R_PIPES+8]
    cmp r14, 1
    je .Lspawn_have_fd
    mov ebx, DWORD PTR [r13+R_PIPES+16]
.Lspawn_have_fd:
    movsxd rbx, ebx
    mov QWORD PTR [r13+R_IN+r14*8], rbx
    test ebx, ebx
    js .Lspawn_nonblock_next
    mov rdi, rbx
    mov esi, 4
    mov edx, 2048
    mov eax, 72
    syscall
    test rax, rax
    js .Lspawn_handshake_uncertain
.Lspawn_nonblock_next:
    inc r14
    cmp r14, 3
    jb .Lspawn_nonblock
    # The parent fd fields now own these exact ends.
    mov DWORD PTR [r13+R_PIPES+4], -1
    mov DWORD PTR [r13+R_PIPES+8], -1
    mov DWORD PTR [r13+R_PIPES+16], -1
    mov rax, r15
    jmp .Lspawn_return
.Lspawn_handshake_uncertain:
    # There is already an original process. Return its actual capability to
    # registration and error cleanup; never turn it into an unowned PID.
    mov QWORD PTR [r13+R_KIND], 1
    mov QWORD PTR [r13+R_REASON], 204
    mov QWORD PTR [r13+R_ERRNO], 5
    lea rdi, [r13+R_PIPES+24]
    call ssh_close_slot32
    movsxd rax, DWORD PTR [r13+R_PIPES+4]
    mov QWORD PTR [r13+R_IN], rax
    movsxd rax, DWORD PTR [r13+R_PIPES+8]
    mov QWORD PTR [r13+R_OUT], rax
    movsxd rax, DWORD PTR [r13+R_PIPES+16]
    mov QWORD PTR [r13+R_ERR], rax
    mov DWORD PTR [r13+R_PIPES+4], -1
    mov DWORD PTR [r13+R_PIPES+8], -1
    mov DWORD PTR [r13+R_PIPES+16], -1
    mov rax, r15
    jmp .Lspawn_return
.Lspawn_wait_uncertain:
    mov QWORD PTR [r13+R_KIND], 1
    mov QWORD PTR [r13+R_REASON], 205
    neg rax
    mov QWORD PTR [r13+R_ERRNO], rax
    mov QWORD PTR [r13+R_FLAGS], 0
    mov rax, r15
    jmp .Lspawn_return
.Lspawn_fail_before_fork:
    mov r15, rax
    mov rdi, r13
    call ssh_close_all_pairs
    mov rax, r15
.Lspawn_return:
    add rsp, 16
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret
.Lspawn_child:
    mov edi, 1
    mov esi, 9
    xor edx, edx
    xor r10d, r10d
    xor r8d, r8d
    mov eax, 157
    syscall
    test rax, rax
    js .Lexec_errno
    mov eax, 110
    syscall
    cmp rax, QWORD PTR [r12+C_PID]
    jne .Lexec_controller_missing
    xor r14d, r14d
.Lexec_stdio:
    mov rax, QWORD PTR [r13+R_FLAGS]
    bt rax, r14
    jc .Lexec_pipe
    lea rcx, [r14+3]
    bt rax, rcx
    jnc .Lexec_stdio_next
    lea rdi, [rip+ssh_dev_null]
    xor esi, esi
    test r14, r14
    setne sil
    or esi, 524288
    xor edx, edx
    mov eax, 2
    syscall
    test rax, rax
    js .Lexec_errno
    mov r15, rax
    jmp .Lexec_dup
.Lexec_pipe:
    movsxd r15, DWORD PTR [r13+R_PIPES]
    test r14, r14
    jz .Lexec_dup
    movsxd r15, DWORD PTR [r13+R_PIPES+r14*8+4]
.Lexec_dup:
    cmp r15, r14
    je .Lexec_same_fd
    mov rdi, r15
    mov rsi, r14
    xor edx, edx
    mov eax, 292
    syscall
    test rax, rax
    js .Lexec_errno
    jmp .Lexec_close_null
.Lexec_same_fd:
    mov rdi, r14
    mov esi, 2
    xor edx, edx
    mov eax, 72
    syscall
    test rax, rax
    js .Lexec_errno
.Lexec_close_null:
    mov rax, QWORD PTR [r13+R_FLAGS]
    bt rax, r14
    jc .Lexec_stdio_next
    cmp r15, 3
    jl .Lexec_stdio_next
    mov rdi, r15
    mov eax, 3
    syscall
.Lexec_stdio_next:
    inc r14
    cmp r14, 3
    jb .Lexec_stdio
    xor r14d, r14d
.Lexec_close_pairs:
    cmp r14, 7
    je .Lexec_now
    movsxd rdi, DWORD PTR [r13+R_PIPES+r14*4]
    test edi, edi
    js .Lexec_close_next
    mov eax, 3
    syscall
.Lexec_close_next:
    inc r14
    jmp .Lexec_close_pairs
.Lexec_now:
    mov edi, 2
    lea rsi, [r12+C_SIGMASK]
    xor edx, edx
    mov r10d, 8
    mov eax, 14
    syscall
    test rax, rax
    js .Lexec_errno
    mov rdi, QWORD PTR [r13+R_COMMAND]
    add rdi, 64
    mov rsi, QWORD PTR [r13+R_ARGV]
    mov rdx, QWORD PTR [r13+R_ENVP]
    mov eax, 59
    syscall
.Lexec_errno:
    neg rax
    mov QWORD PTR [rsp], rax
    mov edi, DWORD PTR [r13+R_PIPES+28]
    mov rsi, rsp
    mov edx, 8
.Lexec_error_write:
    mov eax, 1
    syscall
    cmp rax, -4
    je .Lexec_error_write
.Lexec_controller_missing:
    mov edi, 127
    mov eax, 60
    syscall
    ud2
