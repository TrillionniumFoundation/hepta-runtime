/* Mechanical canonical-path effect admission from the frozen session context
 * adapter, renamed and made callable; HIA retains path semantics. */
.intel_syntax noprefix
.section .text
.equ CAN_PATH_CAP, 67108864
.equ CAN_NORM, 4096
.equ CAN_CANON, 67117056
.equ CAN_LINK, 201342976
.equ CAN_LINK_CAP, 1048576
runtime_canonical_effect:
    push rbx
    push r12
    push r13
    push r14
    sub rsp, 8
    mov r12, rdi
    lea r13, [r12 + 256]
runtime_canon_handle_effect:
    movabs rax, 0x3130574e41435248
    cmp qword ptr [r12], rax
    jne runtime_boundary_abort
    movabs rax, 0x3130414e41435248
    cmp qword ptr [r13], rax
    jne runtime_boundary_abort
    mov rax, qword ptr [r15+56]
    inc rax
    jz runtime_boundary_abort
    cmp qword ptr [r13+8], rax
    jne runtime_boundary_abort
    cmp qword ptr [r12+16], rax
    jne runtime_boundary_abort
    mov qword ptr [r15+56], rax
    mov rax, qword ptr [r13+24]
    or rax, qword ptr [r13+48]
    or rax, qword ptr [r13+56]
    or rax, qword ptr [r13+64]
    or rax, qword ptr [r13+72]
    or rax, qword ptr [r13+80]
    or rax, qword ptr [r13+88]
    jnz runtime_boundary_abort
    mov r14, qword ptr [r13+16]
    cmp r14, 1
    jb runtime_boundary_abort
    cmp r14, 7
    ja runtime_boundary_abort
    cmp r14, 4
    je runtime_canon_canonical_readlink
    cmp r14, 5
    je runtime_canon_canonical_stat
    cmp qword ptr [r12+8], r14
    jne runtime_boundary_abort
    cmp r14, 2
    je runtime_canon_stat_probe
    cmp r14, 7
    je runtime_canon_stat_probe_fallback
    cmp qword ptr [r13+32], CAN_NORM
    jne runtime_boundary_abort
    mov rax, qword ptr [r12+48]
    cmp qword ptr [r13+40], rax
    jne runtime_boundary_abort
    call runtime_canon_exact_path
    cmp r14, 1
    je runtime_canon_statx_path
    jmp runtime_canon_legacy_stat

runtime_canon_exact_path:
    mov rcx, qword ptr [r13+40]
    test rcx, rcx
    jz runtime_boundary_abort
    cmp rcx, CAN_PATH_CAP
    jae runtime_boundary_abort
    mov rsi, qword ptr [r13+32]
    add rsi, r12
    cmp byte ptr [rsi], 47
    jne runtime_boundary_abort
    cmp byte ptr [rsi+rcx], 0
    jne runtime_boundary_abort
    xor edx, edx
runtime_canon_path_scan:
    cmp byte ptr [rsi+rdx], 0
    je runtime_boundary_abort
    inc rdx
    cmp rdx, rcx
    jb runtime_canon_path_scan
    ret

runtime_canon_statx_path:
    mov edi, -100
    xor edx, edx
    mov r10d, 0xfff
    lea r8, [r12+512]
    mov eax, 332
    syscall
    jmp runtime_canon_zero_result
runtime_canon_legacy_stat:
    mov edi, -100
    lea rdx, [r12+512]
    xor r10d, r10d
    mov eax, 262
    syscall
    jmp runtime_canon_zero_result
runtime_canon_stat_probe:
    mov rax, qword ptr [r13+32]
    or rax, qword ptr [r13+40]
    jnz runtime_boundary_abort
    xor edi, edi
    xor esi, esi
    xor edx, edx
    mov r10d, 0xfff
    xor r8d, r8d
    mov eax, 332
    syscall
    jmp runtime_canon_zero_result
runtime_canon_stat_probe_fallback:
    mov rax, qword ptr [r13+32]
    or rax, qword ptr [r13+40]
    jnz runtime_boundary_abort
    xor edi, edi
    xor esi, esi
    lea rdx, [r12+512]
    xor r10d, r10d
    mov eax, 262
    syscall
    jmp runtime_canon_zero_result

runtime_canon_canonical_path:
    cmp qword ptr [r13+32], CAN_CANON
    jne runtime_boundary_abort
    mov rax, qword ptr [r12+64]
    cmp qword ptr [r13+40], rax
    jne runtime_boundary_abort
    jmp runtime_canon_exact_path
runtime_canon_canonical_readlink:
    cmp qword ptr [r12+8], 20
    jne runtime_boundary_abort
    call runtime_canon_canonical_path
    mov edi, -100
    lea rdx, [r12+CAN_LINK]
    mov r10d, CAN_LINK_CAP
    mov eax, 267
    syscall
    cmp rax, -4095
    jae runtime_canon_effect_error
    cmp rax, CAN_LINK_CAP
    ja runtime_boundary_abort
    mov qword ptr [r13+80], rax
    jmp runtime_canon_acknowledge
runtime_canon_canonical_stat:
    cmp qword ptr [r12+8], 21
    jne runtime_boundary_abort
    call runtime_canon_canonical_path
    jmp runtime_canon_legacy_stat
runtime_canon_zero_result:
    cmp rax, -4095
    jae runtime_canon_effect_error
    test rax, rax
    jnz runtime_boundary_abort
    jmp runtime_canon_acknowledge
runtime_canon_effect_error:
    neg rax
    mov qword ptr [r13+72], rax
runtime_canon_acknowledge:
    mov rax, qword ptr [r13+8]
    mov qword ptr [r13+64], rax
    jmp runtime_canonical_return

runtime_canonical_return:
    add rsp, 8
    pop r14
    pop r13
    pop r12
    pop rbx
    ret
