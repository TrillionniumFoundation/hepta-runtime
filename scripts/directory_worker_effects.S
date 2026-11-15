d_worker_handle_effect:
    lea r12, [r15+4096]
    lea r13, [r12+256]
    movabs rax, 0x3130575249444d48
    cmp qword ptr [r12], rax
    jne d_worker_fatal
    movabs rax, 0x3130415249444d48
    cmp qword ptr [r13], rax
    jne d_worker_fatal
    mov rax, qword ptr [r15+8]
    add rax, 1
    jc d_worker_fatal
    cmp qword ptr [r13+8], rax
    jne d_worker_fatal
    cmp qword ptr [r12+16], rax
    jne d_worker_fatal
    mov qword ptr [r15+8], rax
    mov rax, qword ptr [r13+56]
    or rax, qword ptr [r13+64]
    or rax, qword ptr [r13+72]
    or rax, qword ptr [r13+80]
    or rax, qword ptr [r13+88]
    jnz d_worker_fatal
    mov rax, qword ptr [r13+16]
    cmp rax, 1
    je d_worker_effect_root
    cmp rax, 2
    je d_worker_effect_open
    cmp rax, 3
    je d_worker_effect_mkdir
    cmp rax, 4
    je d_worker_effect_close
    jmp d_worker_fatal

d_worker_can_open:
    cmp qword ptr [r15+16], -1
    je d_worker_fatal
    cmp qword ptr [r15+24], 0
    je d_worker_can_open_return
    cmp qword ptr [r15+40], 0
    jne d_worker_fatal
d_worker_can_open_return:
    ret

d_worker_lookup_handle:
    test rdi, rdi
    jz d_worker_fatal
    cmp qword ptr [r15+24], rdi
    je d_worker_found_first
    cmp qword ptr [r15+40], rdi
    jne d_worker_fatal
    lea r14, [r15+40]
    mov rdi, qword ptr [r15+48]
    ret
d_worker_found_first:
    lea r14, [r15+24]
    mov rdi, qword ptr [r15+32]
    ret

d_worker_validate_name:
    cmp qword ptr [r13+32], 4096
    jne d_worker_fatal
    mov rcx, qword ptr [r13+40]
    test rcx, rcx
    jz d_worker_fatal
    cmp rcx, 33554432-4097
    ja d_worker_fatal
    cmp qword ptr [r12+80], rcx
    jne d_worker_fatal
    lea rsi, [r12+4096]
    cmp byte ptr [rsi+rcx], 0
    jne d_worker_fatal
    cmp rcx, 1
    jne d_worker_check_dotdot
    cmp byte ptr [rsi], 46
    je d_worker_fatal
d_worker_check_dotdot:
    cmp rcx, 2
    jne d_worker_scan_name
    cmp word ptr [rsi], 0x2e2e
    je d_worker_fatal
d_worker_scan_name:
    xor edx, edx
d_worker_scan_name_loop:
    cmp byte ptr [rsi+rdx], 0
    je d_worker_fatal
    cmp byte ptr [rsi+rdx], 47
    je d_worker_fatal
    inc rdx
    cmp rdx, rcx
    jb d_worker_scan_name_loop
    mov rdi, qword ptr [r13+24]
    cmp rdi, qword ptr [r12+40]
    jne d_worker_fatal
    call d_worker_lookup_handle
    ret

d_worker_effect_root:
    cmp qword ptr [r12+8], 1
    jne d_worker_fatal
    mov rax, qword ptr [r13+24]
    or rax, qword ptr [r13+32]
    or rax, qword ptr [r13+40]
    or rax, qword ptr [r13+48]
    or rax, qword ptr [r15+24]
    or rax, qword ptr [r15+40]
    jnz d_worker_fatal
    call d_worker_can_open
    mov eax, 257
    mov rdi, -100
    lea rsi, [rip+d_worker_root_name]
    mov edx, 0x2b0000
    xor r10d, r10d
    syscall
    jmp d_worker_opened

d_worker_effect_open:
    cmp qword ptr [r12+8], 2
    je d_worker_open_phase_valid
    cmp qword ptr [r12+8], 5
    jne d_worker_fatal
d_worker_open_phase_valid:
    cmp qword ptr [r13+48], 0
    jne d_worker_fatal
    call d_worker_can_open
    call d_worker_validate_name
    mov eax, 257
    mov edx, 0x2b0000
    xor r10d, r10d
    syscall
d_worker_opened:
    cmp rax, -4095
    jae d_worker_effect_errno
    mov rdx, qword ptr [r15+16]
    inc rdx
    mov qword ptr [r15+16], rdx
    cmp qword ptr [r15+24], 0
    jne d_worker_install_second
    mov qword ptr [r15+24], rdx
    mov qword ptr [r15+32], rax
    jmp d_worker_installed
d_worker_install_second:
    mov qword ptr [r15+40], rdx
    mov qword ptr [r15+48], rax
d_worker_installed:
    mov qword ptr [r13+80], rdx
    jmp d_worker_acknowledge

d_worker_effect_mkdir:
    cmp qword ptr [r12+8], 4
    jne d_worker_fatal
    cmp qword ptr [r13+48], 448
    jne d_worker_fatal
    call d_worker_validate_name
    mov eax, 258
    mov edx, 448
    syscall
    cmp rax, -4095
    jae d_worker_effect_errno
    test rax, rax
    jnz d_worker_fatal
    jmp d_worker_acknowledge

d_worker_effect_close:
    cmp qword ptr [r12+8], 3
    je d_worker_close_phase_valid
    cmp qword ptr [r12+8], 90
    jne d_worker_fatal
d_worker_close_phase_valid:
    mov rax, qword ptr [r13+32]
    or rax, qword ptr [r13+40]
    or rax, qword ptr [r13+48]
    jnz d_worker_fatal
    mov rdi, qword ptr [r13+24]
    cmp rdi, qword ptr [r12+40]
    je d_worker_fatal
    cmp rdi, qword ptr [r12+48]
    je d_worker_fatal
    call d_worker_lookup_handle
    mov qword ptr [r14], 0
    mov eax, 3
    syscall
    cmp rax, -4095
    jae d_worker_effect_errno
    test rax, rax
    jnz d_worker_fatal
    jmp d_worker_acknowledge

d_worker_effect_errno:
    neg rax
    mov qword ptr [r13+72], rax
d_worker_acknowledge:
    mov rax, qword ptr [r13+8]
    mov qword ptr [r13+64], rax
    jmp d_worker_invoke
