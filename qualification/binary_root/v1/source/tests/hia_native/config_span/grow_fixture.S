/* Development-only private wire. No public MCP selector is exposed. */
.intel_syntax noprefix
.section .text
.global _start
.type _start, @function
_start:
    add rsp, 8
    cld
    sub rsp, 256
    mov r12, rsp
    xor ebx, ebx
    xor ebp, ebp
    lea rdi, [rip + grow_fixture_images]
    xor esi, esi
    call runtime_grow_create
    cmp rax, -4095
    jae grow_fixture_fatal
    mov r15, rax
    mov qword ptr [r15 + 80], 3 /* Only fixture: receipts to fd 2. */
grow_fixture_next:
    xor edi, edi
    mov rsi, r12
    mov edx, 16
    call grow_fixture_read
    test rax, rax
    jz grow_fixture_finish
    js grow_fixture_fatal
    mov r14, [r12]
    cmp r14, RG_SLOTS
    jae grow_fixture_fatal
    mov r13, [r12 + 8]
    cmp r13, rbp
    jbe grow_fixture_read_body
    mov rdx, r13
    add rdx, 4095
    jc grow_fixture_fatal
    and rdx, -4096
    test rdx, rdx
    jle grow_fixture_fatal
    mov [r12 + 16], rdx
    test rbx, rbx
    jnz grow_fixture_resize
    mov rdi, rdx
    call view_allocate
    jmp grow_fixture_resized
grow_fixture_resize:
    mov rdi, rbx
    mov rsi, rbp
    call view_resize
grow_fixture_resized:
    cmp rax, -4095
    jae grow_fixture_fatal
    mov rbx, rax
    mov rbp, [r12 + 16]
grow_fixture_read_body:
    xor edi, edi
    mov rsi, rbx
    mov rdx, r13
    call grow_fixture_read
    cmp rax, 1
    jne grow_fixture_fatal
    lea rsi, [r15 + 128]
    lea rdi, [r12 + 64]
    mov ecx, 48
    rep movsb
    mov rdi, rbx
    mov rsi, r13
    mov r8, r14
    call runtime_grow_owned
    mov [r12 + 144], rax
    mov rdx, r14
    shl rdx, 6
    add rdx, [r15 + 8]
    mov rax, 0x3230305246475248 /* HRGFR002 */
    mov [r12 + 128], rax
    mov [r12 + 136], r14
    mov rax, [rdx + 56]
    mov [r12 + 152], rax
    xor ecx, ecx
grow_fixture_counter:
    mov rax, [r15 + rcx * 8 + 128]
    sub rax, [r12 + rcx * 8 + 64]
    mov [r12 + rcx * 8 + 160], rax
    inc ecx
    cmp ecx, 6
    jb grow_fixture_counter
    mov rax, [rdx + 16]
    mov [r12 + 208], rax
    mov rax, [rdx + 40]
    mov [r12 + 216], rax
    mov rax, [rdx + 32]
    mov [r12 + 224], rax
    mov edi, 1
    lea rsi, [r12 + 128]
    mov edx, 96
    call grow_fixture_write
    test rax, rax
    jnz grow_fixture_fatal
    mov edi, 1
    mov rsi, [r12 + 224]
    mov rdx, [r12 + 152]
    call grow_fixture_write
    test rax, rax
    jnz grow_fixture_fatal
    cmp qword ptr [r15 + 88], 0
    jne grow_fixture_fatal
    jmp grow_fixture_next
grow_fixture_finish:
    call runtime_grow_destroy
    test rax, rax
    jnz grow_fixture_fatal
    test rbx, rbx
    jz grow_fixture_success
    mov rdi, rbx
    lea rsi, [rbp + 4096]
    mov eax, 11
    syscall
    test rax, rax
    jnz grow_fixture_fatal
grow_fixture_success:
    xor edi, edi
    mov eax, 60
    syscall
    ud2
grow_fixture_fatal:
    mov edi, 111
    mov eax, 60
    syscall
    ud2

/* Actual byte streams. read returns 1 / clean EOF 0 / error -1. */
grow_fixture_read:
    mov r8, rdx
    test rdx, rdx
    jz grow_fixture_read_ok
grow_fixture_read_more:
    xor eax, eax
    syscall
    cmp rax, -4
    je grow_fixture_read_more
    test rax, rax
    js grow_fixture_read_bad
    jz grow_fixture_read_end
    add rsi, rax
    sub rdx, rax
    jnz grow_fixture_read_more
grow_fixture_read_ok:
    mov eax, 1
    ret
grow_fixture_read_end:
    cmp rdx, r8
    jne grow_fixture_read_bad
    xor eax, eax
    ret
grow_fixture_read_bad:
    mov rax, -1
    ret
grow_fixture_write:
    test rdx, rdx
    jz grow_fixture_write_ok
grow_fixture_write_more:
    mov eax, 1
    syscall
    cmp rax, -4
    je grow_fixture_write_more
    test rax, rax
    jle grow_fixture_write_bad
    add rsi, rax
    sub rdx, rax
    jnz grow_fixture_write_more
grow_fixture_write_ok:
    xor eax, eax
    ret
grow_fixture_write_bad:
    mov rax, -1
    ret

/* Uninstalled fixture branch, not a replacement for public view. */
runtime_grow_view_owned:
    mov eax, RG_RESOURCE
    ret
.balign 8
grow_fixture_images:
    .zero 144
