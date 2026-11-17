/* Private complete immutable-after-call capture of both process-shared arenas.
 * No cache/history/lock state is constructed by the observer. */
.intel_syntax noprefix
.section .text
fs_fixture_text_snapshot:
    cmp qword ptr [r12 + 88], 0
    jne fs_fixture_failure
    mov rbx, [r15 + 400]
    test rbx, rbx
    jz fs_fixture_failure
    mov rax, 0x3142554842544c48
    cmp [rbx], rax
    jne fs_fixture_failure
    mov rax, [rbx + 64 + 16]
    mov [r12 + 328], rax
    add rax, [rbx + 128 + 16]
    jc fs_fixture_failure
    add rax, 32
    jc fs_fixture_failure
    mov [r12 + 224], rax
    mov rax, 0x3230525846534648
    mov [r12 + 192], rax
    mov rax, [r12 + 72]
    mov [r12 + 200], rax
    mov qword ptr [r12 + 208], 41
    mov qword ptr [r12 + 216], 0
    lea rdi, [r12 + 232]
    xor eax, eax
    mov ecx, 8
    rep stosq
    mov rax, 0x3130485342544c48 /* HLTBSH01 */
    mov [r12 + 320], rax
    mov rax, [rbx + 128 + 16]
    mov [r12 + 336], rax
    movzx eax, byte ptr [rbx + 8]
    mov [r12 + 344], rax
    cmp eax, 2
    ja fs_fixture_failure
    mov edi, 1
    lea rsi, [r12 + 192]
    mov edx, 104
    call view_write_all
    test rax, rax
    jnz fs_fixture_failure
    mov edi, 1
    lea rsi, [r12 + 320]
    mov edx, 32
    call view_write_all
    test rax, rax
    jnz fs_fixture_failure
    mov edi, 1
    mov rsi, [rbx + 64 + 8]
    mov rdx, [rbx + 64 + 16]
    call view_write_all
    test rax, rax
    jnz fs_fixture_failure
    mov edi, 1
    mov rsi, [rbx + 128 + 8]
    mov rdx, [rbx + 128 + 16]
    call view_write_all
    test rax, rax
    jnz fs_fixture_failure
    jmp fs_fixture_next
