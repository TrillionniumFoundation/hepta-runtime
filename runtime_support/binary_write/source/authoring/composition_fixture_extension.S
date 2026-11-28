/* Qualification-only full context and whole buffer observations. */
.Lbcf_context:
    mov r14, r12
    mov ebp, 4096
    xor r13d, r13d
    jmp .Lwbf_reply
.Lbcf_adapter_workspace:
    mov r14, [r12+88]
    mov rbp, [r12+96]
    xor r13d, r13d
    jmp .Lwbf_reply
.Lbcf_planner_workspace:
    mov r14, [r12+528]
    mov rbp, [r12+536]
    xor r13d, r13d
    jmp .Lwbf_reply
.Lbcf_adapter_output:
    mov r14, [r12+512]
    mov rbp, [r12+520]
    xor r13d, r13d
    jmp .Lwbf_reply
.Lbcf_planner_output:
    mov r14, [r12+544]
    mov rbp, [r12+552]
    xor r13d, r13d
    jmp .Lwbf_reply
.Lbcf_input:
    mov r14, [r12+64]
    mov rbp, [r12+72]
    xor r13d, r13d
    jmp .Lwbf_reply

/* Route actual parent/body/entropy observations to the unchanged full journal.
 * The composition owner has exactly two fixed pure HIA children and no effect
 * hooks. Its five full spans use the existing FD3, preserving FD0..FD5 limits. */
.Lbcf_journal:
    mov rax, C_MAGIC
    cmp [rsi], rax
    jne .Lwbf_journal
    W_ENTER
    sub rsp, 128
    mov r12, rsi
    mov r13, rdx
    mov r14, rcx
    mov r15, r8
    mov rax, 0x3130524a57434248 /* HBCWJR01 */
    mov [rsp], rax
    mov [rsp+8], r13
    mov rax, [r12+560]
    mov [rsp+16], rax
    mov rax, [r12+192]
    mov [rsp+24], rax
    mov [rsp+32], r15
    mov rax, [r12+56]
    mov [rsp+40], rax
    mov rax, [r12+176]
    mov [rsp+48], rax
    mov rax, [r12+248]
    mov [rsp+56], rax
    mov rax, [r12+608]
    mov rdx, [r12+rax+8]
    mov [rsp+64], rdx
    mov rax, [r12+616]
    mov rdx, [r12+rax+8]
    mov [rsp+72], rdx
    mov [rsp+80], r12
    mov rax, [r12+208]
    mov [rsp+88], rax
    mov rax, [r12+216]
    mov [rsp+96], rax
    mov rax, [r12+592]
    mov [rsp+104], rax
    mov rax, [r12+568]
    mov [rsp+112], rax
    mov rax, [r12+576]
    mov [rsp+120], rax
    mov edi, 3
    mov rsi, rsp
    mov edx, 128
    call .Lwbf_write_all
    test rax, rax
    jnz .Lbcf_journal_done
    mov edi, 3
    mov rsi, r14
    mov rdx, r15
    call .Lwbf_write_all
.Lbcf_journal_done:
    add rsp, 128
    W_LEAVE
