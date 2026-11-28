/* Private two-session wire carrier. Both sessions invoke the same production
 * frontend and real publisher. Session choice exists only in this fixture. */
.intel_syntax noprefix
.section .text
fs_fixture_public_request:
    mov rcx, [r12 + 72]
    bt qword ptr [r12 + 488], rcx
    jc fs_fixture_public_closed
    lea rsi, [r15 + 128]
    lea rdi, [r12 + 128]
    mov ecx, 6
    rep movsq
    mov rdi, [r12 + 24]
    mov rsi, [r12 + 88]
    mov r8d, 18
    call runtime_grow_owned
    cmp rax, 64
    jne fs_fixture_failure
    mov rdx, [r15 + 8]
    add rdx, 18 * 64
    mov r13, [rdx + 32]
    mov rax, [r13 + 8]
    cmp rax, 3
    ja fs_fixture_failure
    mov [r12 + 208], rax
    mov rax, [r13 + 16]
    cmp rax, 1
    ja fs_fixture_failure
    mov [r12 + 216], rax
    test rax, rax
    jz fs_fixture_public_open
    mov rcx, [r12 + 72]
    bts qword ptr [r12 + 488], rcx
fs_fixture_public_open:
    xor ecx, ecx
fs_fixture_public_counter:
    mov rax, [r15 + rcx * 8 + 128]
    sub rax, [r12 + rcx * 8 + 128]
    jc fs_fixture_failure
    mov [r12 + rcx * 8 + 224], rax
    inc ecx
    cmp ecx, 6
    jb fs_fixture_public_counter
    call fs_fixture_public_header
    cmp qword ptr [r12 + 208], 0
    je fs_fixture_next
    cmp qword ptr [r12 + 208], 2
    je fs_fixture_public_publish
    cmp qword ptr [r12 + 208], 3
    je fs_fixture_public_publish_raw
    cmp qword ptr [r13 + 32], 0
    jne fs_fixture_failure
    mov edi, 1
    lea rsi, [r13 + 64]
    mov rdx, [r13 + 24]
    call view_write_all
    test rax, rax
    jnz fs_fixture_failure
    jmp fs_fixture_public_newline
fs_fixture_public_publish_raw:
    cmp qword ptr [r13 + 32], 0
    jne fs_fixture_failure
    lea rdi, [r13 + 64]
    mov rsi, [r13 + 24]
    call runtime_publication_raw_span
    test eax, eax
    jnz fs_fixture_failure
    jmp fs_fixture_public_newline
fs_fixture_public_publish:
    lea rdi, [r13 + 64]
    mov rsi, [r13 + 24]
    lea rdx, [rdi + rsi]
    mov rcx, [r13 + 32]
    mov r8, [r13 + 40]
    call runtime_publication_span
    test rax, rax
    jnz fs_fixture_failure
fs_fixture_public_newline:
    mov edi, 1
    lea rsi, [rip + newline]
    mov edx, 1
    call view_write_all
    test rax, rax
    jnz fs_fixture_failure
    jmp fs_fixture_next
fs_fixture_public_closed:
    mov qword ptr [r12 + 208], 4
    mov qword ptr [r12 + 216], 1
    lea rdi, [r12 + 224]
    mov ecx, 6
    xor eax, eax
    rep stosq
    call fs_fixture_public_header
    jmp fs_fixture_next
fs_fixture_public_header:
    mov rax, 0x333052504a534648 /* HFSJPR03 */
    mov [r12 + 192], rax
    mov rax, [r12 + 72]
    mov [r12 + 200], rax
    mov qword ptr [r12 + 272], 0
    mov qword ptr [r12 + 280], 0
    mov edi, 1
    lea rsi, [r12 + 192]
    mov edx, 96
    call view_write_all
    test rax, rax
    jnz fs_fixture_failure
    ret
