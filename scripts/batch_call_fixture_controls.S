/* Qualification-only owner observations. Not linked into a public route.
 * HBCFXQ02 + slot:u64 + payload_length:u64 + reserved:0 + native request.
 * Fixed slots 5/8/17/18; zero length snapshots only 8/17/18 workspaces. */
.intel_syntax noprefix
.section .text
batch_fixture_control:
    push rbp
    push rbx
    push r12
    push r13
    sub rsp, 56
    cmp rsi, 32
    jb batch_fixture_control_invalid
    cmp qword ptr [rdi + 24], 0
    jne batch_fixture_control_invalid
    mov r12, [rdi + 16]
    sub rsi, 32
    cmp r12, rsi
    jne batch_fixture_control_invalid
    mov r13, [rdi + 8]
    cmp r13, 5
    je batch_fixture_control_slot
    cmp r13, 8
    je batch_fixture_control_slot
    cmp r13, 17
    je batch_fixture_control_slot
    cmp r13, 18
    jne batch_fixture_control_invalid
batch_fixture_control_slot:
    mov rbx, r13
    shl rbx, 6
    add rbx, [r15 + 8]
    test r12, r12
    jz batch_fixture_control_snapshot
    add rdi, 32
    mov rsi, r12
    mov edx, r13d
    call batch_dispatch
    mov [rsp + 32], rax
    xor r12d, r12d
    cmp eax, 0xffff0000
    jae batch_fixture_control_result
    mov r12, rax
    cmp r12, [rbx + 32]
    ja batch_fixture_control_invalid
    mov rbp, [rbx + 24]
    jmp batch_fixture_control_result
batch_fixture_control_snapshot:
    cmp r13, 17
    je batch_fixture_control_global_snapshot
    cmp r13, 18
    jne batch_fixture_control_snapshot_ready
batch_fixture_control_global_snapshot:
    mov rax, [r15 + 800]
    test rax, rax
    jz batch_fixture_control_snapshot_ready
    mov rbx, r13
    shl rbx, 6
    add rbx, [rax + 8]
batch_fixture_control_snapshot_ready:
    cmp r13, 5
    je batch_fixture_control_invalid
    mov qword ptr [rsp + 32], 0
    mov rbp, [rbx + 8]
    mov r12, [rbx + 16]
batch_fixture_control_result:
    mov qword ptr [rsp], 4
    lea rax, [r12 + 32]
    mov [rsp + 8], rax
    mov rax, 0x3230525846434248
    mov [rsp + 16], rax
    mov [rsp + 24], r13
    mov [rsp + 40], r12
    mov edi, 1
    mov rsi, rsp
    mov edx, 48
    call view_write_all
    test rax, rax
    js batch_fixture_control_return
    mov edi, 1
    mov rsi, rbp
    mov rdx, r12
    call view_write_all
    jmp batch_fixture_control_return
batch_fixture_control_invalid:
    mov rax, -22
batch_fixture_control_return:
    add rsp, 56
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret
