/* Four fixed qualification contexts. Native engine binding is callable; this
 * ordinal selector is fixture-only and never a protocol session capability. */
.intel_syntax noprefix
.section .text
batch_fixture_select:
    push rbx
    push r12
    push r13
    push r14
    sub rsp, 8
    cmp rdi, 3
    ja batch_fixture_select_invalid
    mov r14, r15
    mov rbx, rdi
    mov r12, [r15 + 1080]
    mov rax, [r12 + rbx * 8 + 1088]
    test rax, rax
    jnz batch_fixture_select_return
    mov rdi, [r12]
    mov rsi, [r12 + 16]
    call batch_engine_create
    cmp rax, -4095
    jae batch_fixture_select_return
    mov r13, rax
    mov r15, rax
    mov rdi, r12
    mov rsi, r12
    cmp ebx, 2
    jne batch_fixture_select_session
    xor esi, esi
batch_fixture_select_session:
    mov edx, 1
    cmp ebx, 3
    jne batch_fixture_select_bind
    xor edx, edx
batch_fixture_select_bind:
    call batch_engine_bind_shared
    test rax, rax
    jnz batch_fixture_select_failed
    mov [r12 + rbx * 8 + 1088], r13
    mov [r13 + 1080], r12
    mov rax, [r12 + 24]
    mov [r13 + 24], rax
    mov rax, [r12 + 640]
    mov [r13 + 640], rax
    mov rax, r13
    jmp batch_fixture_select_return
batch_fixture_select_failed:
    /* A failed install remains owned; process shutdown is the fixture's
     * contract-failure boundary. No primary owner is freed here. */
batch_fixture_select_invalid:
    mov rax, -22
batch_fixture_select_return:
    mov r15, r14
    add rsp, 8
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

batch_fixture_retire_all:
    push rbx
    push r12
    push r13
    mov r12, [r15 + 1080]
    mov ebx, 1
batch_fixture_retire_follower:
    mov r15, [r12 + rbx * 8 + 1088]
    test r15, r15
    jz batch_fixture_retire_next
    call batch_engine_retire
    test rax, rax
    jnz batch_fixture_retire_return
    call batch_engine_free_maps
    mov qword ptr [r12 + rbx * 8 + 1088], 0
batch_fixture_retire_next:
    inc ebx
    cmp ebx, 4
    jb batch_fixture_retire_follower
    mov r15, r12
    call batch_engine_retire
    test rax, rax
    jnz batch_fixture_retire_return
    call batch_engine_free_maps
    xor eax, eax
batch_fixture_retire_return:
    pop r13
    pop r12
    pop rbx
    ret
