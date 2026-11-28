/* Private qualification observation. These actions never enter stdio JSON. */
fs_fixture_authority_release:
    cmp qword ptr [r12 + 88], 0
    jne fs_fixture_failure
    call runtime_authority_release
    test rax, rax
    jnz fs_fixture_failure
fs_fixture_authority_snapshot:
    cmp qword ptr [r12 + 88], 0
    jne fs_fixture_failure
    mov rax, 0x323053424f415248 /* HRAOBS02 */
    mov [r12 + 192], rax
    mov rax, [r12 + 72]
    mov [r12 + 200], rax
    mov [r12 + 208], r15
    mov qword ptr [r12 + 216], RG_ENGINE
    mov r13, [r15 + 432]
    mov [r12 + 224], r13
    xor eax, eax
    test r13, r13
    jz fs_fixture_authority_absent
    mov eax, RA_BYTES
fs_fixture_authority_absent:
    mov [r12 + 232], rax
    mov rdx, [r15 + 8]
    mov rax, [rdx + 18 * 64 + 8]
    mov [r12 + 240], rax
    mov rax, [rdx + 18 * 64 + 16]
    mov [r12 + 248], rax
    mov edi, 1
    lea rsi, [r12 + 192]
    mov edx, 64
    call view_write_all
    test rax, rax
    jnz fs_fixture_failure
    mov edi, 1
    mov rsi, r15
    mov edx, RG_ENGINE
    call view_write_all
    test rax, rax
    jnz fs_fixture_failure
    mov edi, 1
    mov rsi, [r12 + 224]
    mov rdx, [r12 + 232]
    call view_write_all
    test rax, rax
    jnz fs_fixture_failure
    mov edi, 1
    mov rsi, [r12 + 240]
    mov rdx, [r12 + 248]
    call view_write_all
    test rax, rax
    jnz fs_fixture_failure
    jmp fs_fixture_next
