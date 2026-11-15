/* Terminal native owner retirement, after all borrowed requests have ended. */
.intel_syntax noprefix
.section .text
.global batch_engine_retire
batch_engine_retire:
    push rbx
    push r12
    sub rsp, 8
    cmp qword ptr [r15 + 648], 0
    jne batch_retire_invalid
    cmp qword ptr [r15 + 816], 0
    jne batch_retire_invalid
    cmp qword ptr [r15 + 824], 0
    jne batch_retire_invalid
    cmp qword ptr [r15 + 840], 0
    jne batch_retire_invalid
    mov rbx, [r15 + 8]
    mov rax, [rbx + 8]
    cmp qword ptr [rax + 8], 0
    jne batch_retire_invalid
    cmp qword ptr [rax + 168], 0
    jne batch_retire_invalid
    lea rdi, [r15 + 256]
    xor eax, eax
    mov ecx, 8
    rep stosq
    lea rdi, [r15 + 256]
    mov rax, 0x3230514c41434248
    mov [rdi], rax
    mov qword ptr [rdi + 8], 6
    mov esi, 64
    xor edx, edx
    call batch_dispatch
    cmp eax, 64
    jne batch_retire_invalid
    cmp qword ptr [r15 + 808], 0
    jne batch_retire_history
    lea rdi, [r15 + 256]
    mov rax, 0x313030514c435248
    mov [rdi], rax
    mov qword ptr [rdi + 8], 3
    mov rax, [r15 + 112]
    mov [rdi + 16], rax
    mov rax, [r15 + 120]
    mov [rdi + 24], rax
    mov esi, 64
    mov edx, 7
    call batch_dispatch
    cmp eax, 64
    jne batch_retire_invalid
batch_retire_history:
    cmp qword ptr [r15 + 800], 0
    jne batch_retire_shared
    lea rdi, [r15 + 256]
    xor eax, eax
    mov ecx, 8
    rep stosq
    lea rdi, [r15 + 256]
    mov rax, 0x3130515453494848
    mov [rdi], rax
    mov qword ptr [rdi + 8], 4
    mov esi, 64
    mov edx, 17
    call batch_dispatch
    cmp eax, 64
    jne batch_retire_invalid
    lea rdi, [r15 + 256]
    mov rax, 0x314b434f4c465248
    mov [rdi], rax
    mov qword ptr [rdi + 8], 9
    mov esi, 64
    mov edx, 18
    call batch_dispatch
    cmp eax, 64
    jne batch_retire_invalid
batch_retire_shared:
    mov rax, [r15 + 800]
    test rax, rax
    jz batch_retire_session_ref
    cmp qword ptr [rax + 816], 0
    je batch_retire_invalid
    dec qword ptr [rax + 816]
batch_retire_session_ref:
    mov rax, [r15 + 808]
    test rax, rax
    jz batch_retire_complete
    cmp qword ptr [rax + 824], 0
    je batch_retire_invalid
    dec qword ptr [rax + 824]
batch_retire_complete:
    mov qword ptr [r15 + 840], 1
    xor eax, eax
    jmp batch_retire_done
batch_retire_invalid:
    mov eax, 0xfffffff8
batch_retire_done:
    add rsp, 8
    pop r12
    pop rbx
    ret
