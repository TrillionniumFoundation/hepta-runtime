/* Private read-only capture of exact Session and full Cache bytes. */
.intel_syntax noprefix
.section .text
fs_fixture_snapshot:
    cmp qword ptr [r12 + 88], 0
    jne fs_fixture_failure
    mov rdx, [r15 + 8]
    mov rbx, [rdx + 6 * 64 + 8]
    mov rcx, [rdx + 6 * 64 + 16]
    cmp rcx, 64
    jb fs_fixture_failure
    mov rax, 0x3230545357535248
    cmp [rbx], rax
    jne fs_fixture_failure
    mov rax, [rbx + 8]
    add rax, [rbx + 16]
    jc fs_fixture_failure
    add rax, 64
    jc fs_fixture_failure
    cmp rax, rcx
    ja fs_fixture_failure
    mov [r12 + 384], rbx
    mov [r12 + 392], rax
    mov rdx, [r15 + 16]
    test rdx, rdx
    jz fs_fixture_failure
    mov rdx, [rdx + 8]
    mov rbx, [rdx + 8 * 64 + 8]
    mov rcx, [rdx + 8 * 64 + 16]
    cmp rcx, 64
    jb fs_fixture_failure
    mov rax, 0x3130415453435648
    cmp [rbx], rax
    jne fs_fixture_failure
    cmp qword ptr [rbx + 8], 1
    jne fs_fixture_failure
    mov rax, [rbx + 16]
    cmp rax, 64
    jb fs_fixture_failure
    cmp rax, rcx
    ja fs_fixture_failure
    mov [r12 + 400], rbx
    mov [r12 + 408], rax
    mov rax, [rdx + 10 * 64 + 8]
    cmp qword ptr [rdx + 10 * 64 + 16], 64
    jb fs_fixture_failure
    mov [r12 + 416], rax
    mov rax, [rdx + 6 * 64 + 8]
    cmp qword ptr [rdx + 6 * 64 + 16], 256
    jb fs_fixture_failure
    mov [r12 + 424], rax
    mov rax, [rdx + 7 * 64 + 8]
    cmp qword ptr [rdx + 7 * 64 + 16], 256
    jb fs_fixture_failure
    mov [r12 + 432], rax
    mov rax, [r12 + 392]
    add rax, [r12 + 408]
    jc fs_fixture_failure
    add rax, 640
    jc fs_fixture_failure
    mov [r12 + 224], rax
    mov rax, 0x3230525846534648
    mov [r12 + 192], rax
    mov rax, [r12 + 72]
    mov [r12 + 200], rax
    mov qword ptr [r12 + 208], 33
    mov qword ptr [r12 + 216], 0
    lea rdi, [r12 + 232]
    xor eax, eax
    mov ecx, 8
    rep stosq
    mov rax, 0x323053424f534648
    mov [r12 + 320], rax
    mov rax, [r12 + 392]
    mov [r12 + 328], rax
    mov rax, [r12 + 408]
    mov [r12 + 336], rax
    mov qword ptr [r12 + 344], 64
    mov qword ptr [r12 + 352], 256
    mov qword ptr [r12 + 360], 256
    mov qword ptr [r12 + 368], 0
    mov qword ptr [r12 + 376], 0
    mov edi, 1
    lea rsi, [r12 + 192]
    mov edx, 104
    call view_write_all
    test rax, rax
    jnz fs_fixture_failure
    mov edi, 1
    lea rsi, [r12 + 320]
    mov edx, 64
    call view_write_all
    test rax, rax
    jnz fs_fixture_failure
    mov edi, 1
    mov rsi, [r12 + 384]
    mov rdx, [r12 + 392]
    call view_write_all
    test rax, rax
    jnz fs_fixture_failure
    mov edi, 1
    mov rsi, [r12 + 400]
    mov rdx, [r12 + 408]
    call view_write_all
    test rax, rax
    jnz fs_fixture_failure
    mov edi, 1
    mov rsi, [r12 + 416]
    mov edx, 64
    call view_write_all
    test rax, rax
    jnz fs_fixture_failure
    mov edi, 1
    mov rsi, [r12 + 424]
    mov edx, 256
    call view_write_all
    test rax, rax
    jnz fs_fixture_failure
    mov edi, 1
    mov rsi, [r12 + 432]
    mov edx, 256
    call view_write_all
    test rax, rax
    jnz fs_fixture_failure
    jmp fs_fixture_next
