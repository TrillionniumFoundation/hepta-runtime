/* Dynamic-borrow version of the frozen canonical effect boundary.
 * No path decisions: validate HIA-owned spans, execute the requested syscall,
 * and write the original result/errno/sequence fields back to that owner. */
.intel_syntax noprefix
.section .text
.global runtime_grow_canonical_effect
/* rdi workspace, rsi full borrow capacity, rdx installed descriptor8. */
runtime_grow_canonical_effect:
    push rbp
    push rbx
    push r12
    push r13
    push r14
    sub rsp, 144
    mov r12, rdi
    mov rbp, rsi
    mov rbx, rdx
    cmp rbp, 4096
    jb rgcan_invalid
    lea r13, [r12 + 256]
    mov rax, 0x3230574e41435248 /* HRCANW02 */
    cmp [r12], rax
    jne rgcan_invalid
    mov rax, 0x3230414e41435248 /* HRCANA02 */
    cmp [r13], rax
    jne rgcan_invalid
    mov rax, [rbx + 24]
    inc rax
    jz rgcan_invalid
    cmp [r13 + 8], rax
    jne rgcan_invalid
    cmp [r12 + 16], rax
    jne rgcan_invalid
    mov [rbx + 24], rax
    mov rax, [r13 + 24]
    or rax, [r13 + 48]
    or rax, [r13 + 56]
    or rax, [r13 + 64]
    or rax, [r13 + 72]
    or rax, [r13 + 80]
    or rax, [r13 + 88]
    jnz rgcan_invalid
    mov r14, [r13 + 16]
    cmp r14, 1
    jb rgcan_invalid
    cmp r14, 8
    ja rgcan_invalid
    cmp r14, 4
    je rgcan_readlink
    cmp r14, 5
    je rgcan_canonical_stat
    cmp [r12 + 8], r14
    jne rgcan_invalid
    cmp r14, 2
    je rgcan_stat_probe
    cmp r14, 7
    je rgcan_stat_probe_fallback
    mov rax, [r12 + 2048]
    cmp [r13 + 32], rax
    jne rgcan_invalid
    mov rcx, [r12 + 2056]
    mov rax, [r12 + 48]
    cmp [r13 + 40], rax
    jne rgcan_invalid
    call rgcan_exact_path
    test eax, eax
    jnz rgcan_invalid
    cmp r14, 8
    je rgcan_lstat
    cmp r14, 1
    je rgcan_statx
    jmp rgcan_stat

/* Dynamic row's capacity in rcx. No read happens before full extent checks. */
rgcan_exact_path:
    mov rdx, [r13 + 32]
    cmp rdx, 4096
    jb rgcan_path_bad
    cmp rdx, rbp
    ja rgcan_path_bad
    mov rax, rbp
    sub rax, rdx
    cmp rcx, rax
    ja rgcan_path_bad
    mov rax, [r13 + 40]
    test rax, rax
    jz rgcan_path_bad
    cmp rax, rcx
    jae rgcan_path_bad
    lea rsi, [r12 + rdx]
    cmp byte ptr [rsi], 47
    jne rgcan_path_bad
    cmp byte ptr [rsi + rax], 0
    jne rgcan_path_bad
    xor edx, edx
rgcan_scan:
    cmp byte ptr [rsi + rdx], 0
    je rgcan_path_bad
    inc rdx
    cmp rdx, rax
    jb rgcan_scan
    xor eax, eax
    ret
rgcan_path_bad:
    mov eax, 1
    ret

rgcan_statx:
    mov edi, -100
    xor edx, edx
    mov r10d, 0xfff
    lea r8, [r12 + 512]
    mov eax, 332
    syscall
    jmp rgcan_zero_result
rgcan_stat:
    mov edi, -100
    lea rdx, [r12 + 512]
    xor r10d, r10d
    mov eax, 262
    syscall
    jmp rgcan_zero_result
rgcan_lstat:
    mov edi, -100
    lea rdx, [r12 + 512]
    mov r10d, 0x100
    mov eax, 262
    syscall
    jmp rgcan_zero_result
rgcan_stat_probe:
    mov rax, [r13 + 32]
    or rax, [r13 + 40]
    jnz rgcan_invalid
    xor edi, edi
    xor esi, esi
    xor edx, edx
    mov r10d, 0xfff
    xor r8d, r8d
    mov eax, 332
    syscall
    jmp rgcan_zero_result
rgcan_stat_probe_fallback:
    mov rax, [r13 + 32]
    or rax, [r13 + 40]
    jnz rgcan_invalid
    xor edi, edi
    xor esi, esi
    lea rdx, [r12 + 512]
    xor r10d, r10d
    mov eax, 262
    syscall
    jmp rgcan_zero_result

rgcan_canonical_path:
    mov rax, [r12 + 2080]
    cmp [r13 + 32], rax
    jne rgcan_path_bad
    mov rcx, [r12 + 2088]
    mov rax, [r12 + 64]
    cmp [r13 + 40], rax
    jne rgcan_path_bad
    jmp rgcan_exact_path
rgcan_readlink:
    cmp qword ptr [r12 + 8], 20
    jne rgcan_invalid
    call rgcan_canonical_path
    test eax, eax
    jnz rgcan_invalid
    mov rdx, [r12 + 2144]
    mov r10, [r12 + 2152]
    cmp rdx, 4096
    jb rgcan_invalid
    cmp rdx, rbp
    ja rgcan_invalid
    mov rax, rbp
    sub rax, rdx
    test r10, r10
    jz rgcan_invalid
    cmp r10, rax
    ja rgcan_invalid
    add rdx, r12
    mov edi, -100
    mov eax, 267
    syscall
    mov [rsp + 128], rax
    cmp rax, -4095
    jae rgcan_error
    cmp rax, [r12 + 2152]
    ja rgcan_invalid
    mov [r13 + 80], rax
    jmp rgcan_ack
rgcan_canonical_stat:
    cmp qword ptr [r12 + 8], 21
    jne rgcan_invalid
    call rgcan_canonical_path
    test eax, eax
    jnz rgcan_invalid
    jmp rgcan_stat
rgcan_zero_result:
    mov [rsp + 128], rax
    cmp rax, -4095
    jae rgcan_error
    test rax, rax
    jnz rgcan_invalid
    jmp rgcan_ack
rgcan_error:
    neg rax
    mov [r13 + 72], rax
rgcan_ack:
    mov rax, [r13 + 8]
    mov [r13 + 64], rax
    cmp qword ptr [r15 + 80], 0
    je rgcan_success
    mov rdx, 0x32304b414e435248 /* HRCNAK02 */
    mov [rsp], rdx
    mov [rsp + 8], rax
    mov rdx, [r12 + 8]
    mov [rsp + 16], rdx
    mov [rsp + 24], r14
    mov rdx, [r13 + 32]
    mov [rsp + 32], rdx
    mov rdx, [r13 + 40]
    mov [rsp + 40], rdx
    mov rdx, [rsp + 128]
    mov [rsp + 48], rdx
    mov rdx, [r13 + 72]
    mov [rsp + 56], rdx
    mov rdx, [r13 + 80]
    mov [rsp + 64], rdx
    mov rdx, [r12 + 2048]
    mov [rsp + 72], rdx
    mov rdx, [r12 + 2080]
    mov [rsp + 80], rdx
    mov rdx, [r12 + 2144]
    mov [rsp + 88], rdx
    mov rdx, [r12 + 2152]
    mov [rsp + 96], rdx
    mov [rsp + 104], rbp
    mov rdx, [r12 + 536]
    mov [rsp + 112], rdx
    mov [rsp + 120], rax
    mov rdi, [r15 + 80]
    dec rdi
    mov rsi, rsp
    mov edx, 128
rgcan_trace_write:
    mov eax, 1
    syscall
    cmp rax, -4
    je rgcan_trace_write
    test rax, rax
    jle rgcan_trace_error
    add rsi, rax
    sub rdx, rax
    jnz rgcan_trace_write
rgcan_success:
    xor eax, eax
    jmp rgcan_return
rgcan_trace_error:
    mov qword ptr [r15 + 88], 1
    jmp rgcan_success
rgcan_invalid:
    mov eax, 0xffffffff
rgcan_return:
    add rsp, 144
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret
