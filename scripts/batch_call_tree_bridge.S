/* Retained fixed HIACAL planner/apply graphs, with exact borrowed spans. */
.intel_syntax noprefix
.section .text
batch_tree_invoke:
    push rbp
    push rbx
    push r12
    push r13
    push r14
    sub rsp, 48
    mov r12, rdi
    mov r13, rsi
    mov r14d, edx
    mov ebx, edx
    shl rbx, 6
    add rbx, [r15 + 8]
    cmp r14d, 14
    jne batch_tree_attempt
    /* The ordinary successful result includes both normalized and rendered
     * text. A request-sized capacity hint avoids reapplying the entire plan
     * once per power of two. This is not an admission bound: CRLF expansion
     * and all other short-output cases still use the original growth loop. */
    mov rdx, r13
    shl rdx, 1
    jc batch_tree_resource
    add rdx, 4096
    jc batch_tree_resource
    mov rdi, rbx
    mov esi, 2
    call batch_grow
    test rax, rax
    jnz batch_tree_resource
batch_tree_attempt:
    mov rdx, r13
    shl rdx, 2
    jc batch_tree_resource
    mov rax, [rbx + 32]
    imul rax, rax, 3
    jo batch_tree_resource
    add rdx, rax
    jc batch_tree_resource
    add rdx, 32768
    jc batch_tree_resource
    mov rdi, rbx
    mov esi, 1
    call batch_grow
    test rax, rax
    jnz batch_tree_resource
    mov rbp, [rbx + 8]
    mov qword ptr [rbp], 0
    add rbp, [rbx + 16]
    sub rbp, 256
    mov rdi, rbp
    xor eax, eax
    mov ecx, 32
    rep stosq
    mov qword ptr [rbp + 120], 3
    mov eax, 1
    cmp r14d, 13
    je batch_tree_id_ready
    cmp r14d, 14
    jne batch_tree_contract
    mov eax, 4
batch_tree_id_ready:
    mov [rbp + 128], rax
    mov qword ptr [rbp + 136], 1
    mov qword ptr [rsp], 0
batch_tree_again:
    mov rdi, r12
    mov rsi, r13
    mov rdx, [rbx + 24]
    mov rcx, [rbx + 32]
    mov r8, [rbx + 8]
    mov r9, [rbx + 16]
    call qword ptr [rbx]
    mov edx, eax
    cmp rax, rdx
    jne batch_tree_contract
    cmp eax, 0xffffffe0
    jne batch_tree_completed
    mov rax, 0x31304c4143414948
    cmp [rbp], rax
    jne batch_tree_contract
    mov rax, [rsp]
    inc rax
    jz batch_tree_resource
    cmp [rbp + 8], rax
    jne batch_tree_contract
    mov [rsp], rax
    cmp qword ptr [rbp + 24], 2
    jne batch_tree_contract
    cmp qword ptr [rbp + 48], 2
    jne batch_tree_contract
    mov rax, [rbp + 72]
    or rax, [rbp + 80]
    or rax, [rbp + 88]
    or rax, [rbp + 96]
    or rax, [rbp + 104]
    or rax, [rbp + 112]
    jnz batch_tree_contract
    cmp qword ptr [rbp + 120], 3
    jne batch_tree_contract
    cmp qword ptr [rbp + 136], 1
    jne batch_tree_contract
    mov rax, [rbp + 16]
    cmp r14d, 13
    jne batch_tree_apply_child
    cmp qword ptr [rbp + 128], 1
    jne batch_tree_contract
    mov edx, 4
    cmp rax, 2
    je batch_tree_child_ready
    mov edx, 9
    cmp rax, 3
    je batch_tree_child_ready
    jmp batch_tree_contract
batch_tree_apply_child:
    cmp qword ptr [rbp + 128], 4
    jne batch_tree_contract
    cmp rax, 5
    jne batch_tree_contract
    mov edx, 15
batch_tree_child_ready:
    shl rdx, 6
    add rdx, [r15 + 8]
    mov [rsp + 40], rdx
    mov rcx, [rbx + 16]
    sub rcx, 256
    mov rax, [rbp + 32]
    cmp rax, rcx
    ja batch_tree_contract
    mov [rsp + 8], rax
    sub rcx, rax
    mov rax, [rbp + 40]
    cmp rax, rcx
    ja batch_tree_contract
    mov [rsp + 16], rax
    mov rcx, [rbx + 16]
    sub rcx, 256
    mov rax, [rbp + 56]
    cmp rax, rcx
    ja batch_tree_contract
    mov [rsp + 24], rax
    sub rcx, rax
    mov rax, [rbp + 64]
    cmp rax, rcx
    ja batch_tree_contract
    mov [rsp + 32], rax
    add rax, [rsp + 24]
    cmp rax, [rsp + 8]
    jbe batch_tree_spans_ready
    mov rax, [rsp + 8]
    add rax, [rsp + 16]
    cmp rax, [rsp + 24]
    ja batch_tree_contract
batch_tree_spans_ready:
    cmp r14d, 14
    jne batch_tree_leaf_call
    mov rdx, [rsp + 16]
    add rdx, [rsp + 32]
    jc batch_tree_resource
    shl rdx, 2
    jc batch_tree_resource
    add rdx, 4096
    jc batch_tree_resource
    mov rdi, [rsp + 40]
    mov esi, 1
    call batch_grow
    test rax, rax
    jnz batch_tree_resource
batch_tree_leaf_call:
    mov rax, [rsp + 40]
    mov rdi, [rbx + 8]
    add rdi, [rsp + 8]
    mov rsi, [rsp + 16]
    mov rdx, [rbx + 8]
    add rdx, [rsp + 24]
    mov rcx, [rsp + 32]
    mov r8, [rax + 8]
    mov r9, [rax + 16]
    call qword ptr [rax]
    mov edx, eax
    cmp rax, rdx
    jne batch_tree_contract
    cmp eax, 0xffff0000
    jae batch_tree_leaf_return_ready
    cmp rax, [rsp + 32]
    ja batch_tree_contract
batch_tree_leaf_return_ready:
    mov [rbp + 80], rax
    mov rdx, [rsp]
    mov [rbp + 88], rdx
    mov qword ptr [rbp + 96], 1
    jmp batch_tree_again
batch_tree_completed:
    cmp eax, 0xfffffffe
    jne batch_tree_done
    mov rdx, [rbx + 32]
    shl rdx, 1
    jc batch_tree_resource
    mov rdi, rbx
    mov esi, 2
    call batch_grow
    test rax, rax
    jnz batch_tree_resource
    jmp batch_tree_attempt
batch_tree_contract:
    mov eax, 0xfffffff8
    jmp batch_tree_done
batch_tree_resource:
    mov eax, 0xfffffffc
batch_tree_done:
    mov [rbx + 40], rax
    add rsp, 48
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret
