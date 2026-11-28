/* Qualification-only private ABI rejection. No public operation can select an
 * address or write a context. The one payload is exactly offset 272 or 280;
 * the fixture temporarily marks an inconsistent idle ownership state, calls
 * the real exported destroy, verifies busy, and restores that same word. */
.Lwbf_parent_busy_control:
    cmp r13, 8
    jne .Lwbf_no_context
    test r12, r12
    jz .Lwbf_no_context
    cmp qword ptr [r12+56], 0
    jne .Lwbf_no_context
    mov rax, [rbp+64]
    cmp rax, 272
    je .Lwbf_parent_busy_offset
    cmp rax, 280
    jne .Lwbf_no_context
.Lwbf_parent_busy_offset:
    cmp qword ptr [r12+rax], 0
    jne .Lwbf_no_context
    push rax
    mov qword ptr [r12+rax], 1
    mov rdi, r12
    call binary_parent_owner_destroy
    mov edx, 0xfffffffd
    cmp rax, rdx
    jne .Lwbf_fatal
    pop rdx
    mov qword ptr [r12+rdx], 0
    mov r13, rax
    jmp .Lwbf_empty_reply
