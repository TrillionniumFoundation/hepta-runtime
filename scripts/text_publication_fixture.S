/* Static framed qualification endpoint. Default callable engine is silent.
 * --trace observes actual completed effects; --sync adds exact observation
 * acknowledgements. Neither is part of the public application protocol. */
.intel_syntax noprefix
.section .text
.global _start
_start:
    xor r12d, r12d
    mov rax, [rsp]
    cmp rax, 1
    je .Ltxt_fixture_args
    cmp rax, 2
    jne .Ltxt_fixture_usage
    mov rdi, [rsp + 16]
    cmp dword ptr [rdi], 0x72742d2d
    je .Ltxt_fixture_trace
    cmp dword ptr [rdi], 0x79732d2d
    jne .Ltxt_fixture_usage
    cmp word ptr [rdi + 4], 0x636e
    jne .Ltxt_fixture_usage
    cmp byte ptr [rdi + 6], 0
    jne .Ltxt_fixture_usage
    mov r12d, 3
    jmp .Ltxt_fixture_args
.Ltxt_fixture_trace:
    cmp dword ptr [rdi + 4], 0x00656361
    jne .Ltxt_fixture_usage
    mov r12d, 1
.Ltxt_fixture_args:
    /* Standalone alone owns this signal policy; callable create does not
     * alter the embedding process's signal dispositions or FD flags. */
    mov edi, 13
    lea rsi, [rip + txt_ignore_action]
    xor edx, edx
    mov r10d, 8
    mov eax, 13
    syscall
    test rax, rax
    js .Ltxt_fixture_usage
    lea rdi, [rip + .Ltxt_image_table]
    call .Ltext_publication_create
    cmp rax, -4095
    jae .Ltxt_fixture_resource_early
    mov r15, rax
    mov [r15 + 144], r12
    sub rsp, 80
.Ltxt_fixture_next:
    xor edi, edi
    mov rsi, rsp
    mov edx, 8
    call txt_read_all
    test rax, rax
    je .Ltxt_fixture_eof
    cmp rax, 1
    jne .Ltxt_fixture_io
    mov r12, [rsp]
    test r12, r12
    js .Ltxt_fixture_resource
    cmp r12, [r15 + 72]
    jbe .Ltxt_fixture_input
    mov rdi, [r15 + 64]
    mov rsi, [r15 + 72]
    mov rdx, r12
    call txt_resize
    cmp rax, -4095
    jae .Ltxt_fixture_resource
    mov [r15 + 64], rax
    mov [r15 + 72], r12
.Ltxt_fixture_input:
    xor edi, edi
    mov rsi, [r15 + 64]
    mov rdx, r12
    call txt_read_all
    cmp rax, 1
    jne .Ltxt_fixture_io
    mov rdi, r15
    mov rsi, [r15 + 64]
    mov rdx, r12
    call .Ltext_publication_call
    mov r13, rdx
    mov r14, rcx
    mov [rsp + 16], rax
    mov rax, rcx
    add rax, 64
    jc .Ltxt_fixture_contract
    mov [rsp], rax
    mov rax, 0x3130524554585448
    mov [rsp + 8], rax
    mov rbx, [r15 + 32]
    mov rax, [rbx + 64]
    mov [rsp + 24], rax
    mov rax, [rbx + 56]
    mov [rsp + 32], rax
    mov [rsp + 40], r14
    mov rax, [r15 + 136]
    xor ecx, ecx
.Ltxt_fixture_count_fd:
    test rax, rax
    jz .Ltxt_fixture_count_done
    lea rdx, [rax - 1]
    and rax, rdx
    inc rcx
    jmp .Ltxt_fixture_count_fd
.Ltxt_fixture_count_done:
    mov [rsp + 48], rcx
    mov rax, [rbx]
    mov [rsp + 56], rax
    mov qword ptr [rsp + 64], 0
    mov edi, 1
    mov rsi, rsp
    mov edx, 72
    call txt_write_all
    test rax, rax
    js .Ltxt_fixture_io
    mov edi, 1
    mov rsi, r13
    mov rdx, r14
    call txt_write_all
    test rax, rax
    js .Ltxt_fixture_io
    cmp qword ptr [r15 + 264], 0
    jne .Ltxt_fixture_contract
    jmp .Ltxt_fixture_next
.Ltxt_fixture_eof:
    xor r14d, r14d
    jmp .Ltxt_fixture_destroy
.Ltxt_fixture_io:
    mov r14d, 74
    jmp .Ltxt_fixture_destroy
.Ltxt_fixture_contract:
    mov r14d, 70
    jmp .Ltxt_fixture_destroy
.Ltxt_fixture_resource:
    mov r14d, 71
.Ltxt_fixture_destroy:
    mov rdi, r15
    call .Ltext_publication_destroy
    test rax, rax
    jz .Ltxt_fixture_exit_ready
    test r14, r14
    jnz .Ltxt_fixture_exit_ready
    mov r14d, 70
.Ltxt_fixture_exit_ready:
    mov rdi, r14
    jmp .Ltxt_fixture_exit
.Ltxt_fixture_usage:
    mov edi, 64
    jmp .Ltxt_fixture_exit
.Ltxt_fixture_resource_early:
    mov edi, 71
.Ltxt_fixture_exit:
    mov eax, 60
    syscall
    ud2
.balign 8
txt_ignore_action:
    .quad 1,0,0,0
.global text_publication_image_table
text_publication_image_table:
.Ltxt_image_table:
    .zero 24
