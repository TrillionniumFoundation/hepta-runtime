/* Actual native child invocations. The one-MiB SHA transfer window is not a
 * cumulative result quota. Child output/workspace are zeroed for every call,
 * matching separate fresh borrowed sessions in the qualification carrier. */
.intel_syntax noprefix
.section .text
txt_codec_invoke:
    TXT_ENTER
    mov r12, rsi
    mov r13, rcx
    mov rbx, [r15 + 224]
    lea rdi, [rbx + 1048832]
    xor eax, eax
    mov rcx, r13
    rep stosb
    lea rdi, [rbx + 1049344]
    mov ecx, 1184
    rep stosb
    mov rdi, rbx
    mov rsi, r12
    lea rdx, [rbx + 1048832]
    mov rcx, r13
    lea r8, [rbx + 1049344]
    mov r9d, 1184
    call qword ptr [r15 + 16]
    mov eax, eax
    TXT_LEAVE

txt_sha256:
    TXT_ENTER
    mov rbx, [r15 + 32]
    mov r12, [rbx + 544]
    add r12, rbx
    mov r13, [rbx + 552]
    mov r14, [rbx + 560]
    add r14, rbx
    mov rbx, [r15 + 224]
    mov rax, 0x314345444f435248
    mov [rbx], rax
    mov qword ptr [rbx + 8], 3
    mov qword ptr [rbx + 16], 0
    mov esi, 24
    mov ecx, 128
    call txt_codec_invoke
    cmp eax, 128
    jne .Ltxt_sha_bad
.Ltxt_sha_save:
    lea rdi, [r15 + 640]
    lea rsi, [rbx + 1048832]
    mov ecx, 128
    rep movsb
    test r13, r13
    jz .Ltxt_sha_finish
    mov rax, 1048576
    cmp r13, rax
    cmovb rax, r13
    mov [r15 + 320], rax
    mov qword ptr [rbx + 8], 4
    lea rdi, [rbx + 24]
    lea rsi, [r15 + 640]
    mov ecx, 128
    rep movsb
    lea rdi, [rbx + 152]
    mov rsi, r12
    mov rcx, rax
    rep movsb
    lea rsi, [rax + 152]
    mov ecx, 128
    call txt_codec_invoke
    cmp eax, 128
    jne .Ltxt_sha_bad
    mov rax, [r15 + 320]
    add r12, rax
    sub r13, rax
    jmp .Ltxt_sha_save
.Ltxt_sha_finish:
    mov qword ptr [rbx + 8], 5
    lea rdi, [rbx + 24]
    lea rsi, [r15 + 640]
    mov ecx, 128
    rep movsb
    mov esi, 152
    mov ecx, 32
    call txt_codec_invoke
    cmp eax, 32
    jne .Ltxt_sha_bad
    mov rdi, r14
    lea rsi, [rbx + 1048832]
    mov ecx, 32
    rep movsb
    xor eax, eax
    TXT_LEAVE
.Ltxt_sha_bad:
    mov rax, -22
    TXT_LEAVE

txt_errno_child:
    TXT_ENTER
    mov rbx, [r15 + 224]
    mov r12, [r15 + 32]
    mov rax, 3544386032571340360
    mov [rbx], rax
    mov rax, [r12 + 544]
    mov [rbx + 8], rax
    lea rdi, [rbx + 1048832]
    mov ecx, 512
    xor eax, eax
    rep stosb
    lea rdi, [rbx + 1049344]
    mov ecx, 16
    rep stosb
    mov rdi, rbx
    mov esi, 16
    lea rdx, [rbx + 1048832]
    mov ecx, 512
    lea r8, [rbx + 1049344]
    mov r9d, 16
    call qword ptr [r15 + 24]
    mov eax, eax
    test eax, eax
    jz .Ltxt_errno_bad
    cmp eax, 512
    ja .Ltxt_errno_bad
    mov r13, rax
    lea rdi, [r12 + 1536]
    lea rsi, [rbx + 1048832]
    mov rcx, rax
    rep movsb
    mov rax, r13
    TXT_LEAVE
.Ltxt_errno_bad:
    mov rax, -22
    TXT_LEAVE
