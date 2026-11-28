/* Copyright 2026 Muvon Un Limited
 * Copyright 2026 TrillionniumFoundation
 * SPDX-License-Identifier: Apache-2.0
 *
 * Fixed Linux execvp boundary for the already-owned argv/environment.
 * It runs only in the original fork child, using syscalls and primitive
 * memory. No public argument selects this capability or an executable.
 */
.intel_syntax noprefix
.section .text
.global ssh_public_execvp
ssh_public_execvp:
    push rbp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub rsp, 4200
    mov rbp, rsp
    mov r12, rdi
    mov r13, rsi
    mov r14, rdx
    /* Preserve the actual empty-errno result when every PATH entry is skipped. */
    mov qword ptr [rbp+4096], 0
    mov qword ptr [rbp+4104], 0
    xor ecx, ecx
.Lpex_program:
    mov al, [r12+rcx]
    test al, al
    jz .Lpex_program_end
    cmp al, 47
    je .Lpex_direct
    inc rcx
    jmp .Lpex_program
.Lpex_program_end:
    test rcx, rcx
    jz .Lpex_missing
    cmp rcx, 255
    ja .Lpex_long
    mov [rbp+4112], rcx
    mov r15, r14
.Lpex_env:
    mov rax, [r15]
    test rax, rax
    jz .Lpex_default
    cmp byte ptr [rax], 80
    jne .Lpex_env_next
    cmp byte ptr [rax+1], 65
    jne .Lpex_env_next
    cmp byte ptr [rax+2], 84
    jne .Lpex_env_next
    cmp byte ptr [rax+3], 72
    jne .Lpex_env_next
    cmp byte ptr [rax+4], 61
    jne .Lpex_env_next
    lea r15, [rax+5]
    jmp .Lpex_component
.Lpex_env_next:
    add r15, 8
    jmp .Lpex_env
.Lpex_default:
    lea r15, [rip+ssh_public_default_path]
.Lpex_component:
    xor ecx, ecx
.Lpex_component_end:
    mov al, [r15+rcx]
    test al, al
    jz .Lpex_component_size
    cmp al, 58
    je .Lpex_component_size
    inc rcx
    jmp .Lpex_component_end
.Lpex_component_size:
    lea rax, [r15+rcx]
    mov [rbp+4120], rax
    mov rax, rcx
    test rcx, rcx
    jz .Lpex_capacity
    inc rax
.Lpex_capacity:
    add rax, [rbp+4112]
    cmp rax, 4095
    ja .Lpex_advance
    mov rdi, rbp
    mov rsi, r15
    test rcx, rcx
    jz .Lpex_basename
    rep movsb
    mov byte ptr [rdi], 47
    inc rdi
.Lpex_basename:
    mov rsi, r12
    mov rcx, [rbp+4112]
    inc rcx
    rep movsb
    mov rdi, rbp
    mov rsi, r13
    mov rdx, r14
    mov eax, 59
    syscall
    cmp rax, -8
    jne .Lpex_failed
    mov rdi, rbp
    mov rsi, r13
    mov rdx, r14
    call ssh_public_exec_shell
    jmp .Lpex_return
.Lpex_failed:
    mov [rbp+4096], rax
    cmp rax, -13
    jne .Lpex_transient
    mov qword ptr [rbp+4104], 1
    jmp .Lpex_advance
.Lpex_transient:
    cmp rax, -2
    je .Lpex_advance
    cmp rax, -20
    je .Lpex_advance
    cmp rax, -116
    je .Lpex_advance
    cmp rax, -19
    je .Lpex_advance
    cmp rax, -110
    jne .Lpex_return
.Lpex_advance:
    mov r15, [rbp+4120]
    cmp byte ptr [r15], 0
    je .Lpex_exhausted
    inc r15
    jmp .Lpex_component
.Lpex_exhausted:
    mov rax, [rbp+4096]
    cmp qword ptr [rbp+4104], 0
    je .Lpex_return
    mov rax, -13
    jmp .Lpex_return
.Lpex_direct:
    mov rdi, r12
    mov rsi, r13
    mov rdx, r14
    mov eax, 59
    syscall
    cmp rax, -8
    jne .Lpex_return
    mov rdi, r12
    mov rsi, r13
    mov rdx, r14
    call ssh_public_exec_shell
    jmp .Lpex_return
.Lpex_missing:
    mov rax, -2
    jmp .Lpex_return
.Lpex_long:
    mov rax, -36
.Lpex_return:
    add rsp, 4200
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret

/* rdi original file, rsi original argv, rdx inherited envp. */
ssh_public_exec_shell:
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub rsp, 16
    mov r13, rdi
    mov r14, rsi
    mov r15, rdx
    xor ebx, ebx
.Lpex_shell_argc:
    cmp qword ptr [r14+rbx*8], 0
    je .Lpex_shell_allocate
    inc rbx
    jmp .Lpex_shell_argc
.Lpex_shell_allocate:
    lea rdi, [rbx*8+16]
    call ssh_alloc
    test rax, rax
    js .Lpex_shell_return
    mov r12, rax
    mov [rsp], rdx
    lea rax, [rip+ssh_public_shell]
    mov [r12], rax
    mov [r12+8], r13
    mov ecx, 1
.Lpex_shell_copy:
    cmp rcx, rbx
    jae .Lpex_shell_exec
    mov rax, [r14+rcx*8]
    mov [r12+rcx*8+8], rax
    inc rcx
    jmp .Lpex_shell_copy
.Lpex_shell_exec:
    mov qword ptr [r12+rbx*8+8], 0
    lea rdi, [rip+ssh_public_shell]
    mov rsi, r12
    mov rdx, r15
    mov eax, 59
    syscall
    mov [rsp+8], rax
    mov rdi, r12
    mov rsi, [rsp]
    call ssh_free
    mov rax, [rsp+8]
.Lpex_shell_return:
    add rsp, 16
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

ssh_public_default_path:
    .asciz "/bin:/usr/bin"
ssh_public_shell:
    .asciz "/bin/sh"
