/* Private qualification observer. It never creates, calls or mutates an owner.
 * HFSFXQ02 selector35, empty payload -> HFSFXR02 + HBCOBS03 + complete arenas and actual Batch owner prefixes.
 * The public transport does not link this file or expose the selector. */
.intel_syntax noprefix
.section .text
.global runtime_batch_fixture_observe
/* r15 extra engine, rdi fixed fixture Session index. */
runtime_batch_fixture_observe:
    push rbp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub rsp, 408
    mov rbp, rdi
    mov r12, r15
    mov rbx, rsp
    xor eax, eax
    mov rdi, rsp
    mov ecx, 51
    rep stosq
    mov rax, 0x3230525846534648 /* HFSFXR02 */
    mov [rbx], rax
    mov [rbx + 8], rbp
    mov qword ptr [rbx + 16], 35
    mov rax, 0x333053424f434248 /* HBCOBS03 */
    mov [rbx + 112], rax
    mov rdx, [r12 + 16]
    test rdx, rdx
    jz batch_fixture_observe_invalid
    mov rax, [rdx + 112]
    mov [rbx + 232], rax
    mov rax, [rdx + 120]
    mov [rbx + 240], rax
    mov r13, [r12 + 224]
    test r13, r13
    jz batch_fixture_observe_invalid
    mov rax, 0x3230425548534648 /* HFSHUB02 */
    cmp [r13], rax
    jne batch_fixture_observe_invalid
    mov r13, [r13 + 256]
    test r13, r13
    jz batch_fixture_observe_binding
    or qword ptr [rbx + 120], 1
    mov rax, [r13 + 816]
    mov [rbx + 152], rax
    mov rdx, [r13 + 8]
    lea rsi, [rdx + 17 * 64]
    mov rdi, [rsi + 8]
    mov rcx, [rsi + 16]
    cmp rcx, 64
    jb batch_fixture_observe_invalid
    mov rax, 0x3130415453494848 /* HHISTA01 */
    cmp [rdi], rax
    jne batch_fixture_observe_invalid
    cmp qword ptr [rdi + 8], 1
    jne batch_fixture_observe_invalid
    mov rax, [rdi + 16]
    cmp rax, 64
    jb batch_fixture_observe_invalid
    cmp rax, rcx
    ja batch_fixture_observe_invalid
    mov rsi, [rdi + 56]
    cmp rsi, 64
    jb batch_fixture_observe_invalid
    cmp rsi, rax
    ja batch_fixture_observe_invalid
    mov [rbx + 328], rdi
    mov [rbx + 176], rcx
    mov [rbx + 200], rax
    lea rsi, [rdx + 18 * 64]
    mov rdi, [rsi + 8]
    mov rcx, [rsi + 16]
    cmp rcx, 256
    jb batch_fixture_observe_invalid
    mov rax, 0x45544154534c4648 /* HFLSTATE */
    cmp [rdi], rax
    jne batch_fixture_observe_invalid
    cmp qword ptr [rdi + 8], 1
    jne batch_fixture_observe_invalid
    mov rax, [rdi + 16]
    cmp rax, 256
    jb batch_fixture_observe_invalid
    cmp rax, rcx
    ja batch_fixture_observe_invalid
    test rax, 15
    jnz batch_fixture_observe_invalid
    mov [rbx + 336], rdi
    mov [rbx + 184], rcx
    mov [rbx + 208], rax
batch_fixture_observe_binding:
    mov rdx, [r12 + 3072]
    test rdx, rdx
    jz batch_fixture_observe_emit
    mov rax, 0x3230304250564248 /* HBVPB002 */
    cmp [rdx], rax
    jne batch_fixture_observe_invalid
    mov rax, [r12 + 16]
    cmp [rdx + 24], rax
    jne batch_fixture_observe_invalid
    mov rax, [rdx + 8]
    mov [rbx + 128], rax
    cmp rax, 4
    jne batch_fixture_observe_invalid
    or qword ptr [rbx + 120], 2
    mov r14, [rdx + 16]
    test r14, r14
    jz batch_fixture_observe_invalid
    cmp [r14 + 800], r13
    jne batch_fixture_observe_invalid
    mov rax, [r14 + 840]
    mov [rbx + 136], rax
    mov rax, [r14 + 648]
    mov [rbx + 144], rax
    mov rax, [r14 + 824]
    mov [rbx + 160], rax
    mov rax, [r14 + 112]
    cmp [rdx + 80], rax
    jne batch_fixture_observe_invalid
    mov [rbx + 216], rax
    mov rax, [r14 + 120]
    cmp [rdx + 88], rax
    jne batch_fixture_observe_invalid
    mov [rbx + 224], rax
    mov rdx, [r14 + 8]
    mov rdi, [rdx + 8]
    mov rcx, [rdx + 16]
    cmp rcx, 4096
    jb batch_fixture_observe_invalid
    mov rax, 0x3230305357434248 /* HBCWS002 */
    cmp [rdi], rax
    jne batch_fixture_observe_invalid
    mov rax, [rdi + 48]
    cmp rax, [rdi + 512]
    ja batch_fixture_observe_invalid
    cmp qword ptr [rdi + 512], 4096
    jb batch_fixture_observe_invalid
    mov rsi, [rdi + 512]
    cmp rsi, rcx
    ja batch_fixture_observe_invalid
    mov [rbx + 320], rdi
    mov [rbx + 168], rcx
    mov [rbx + 192], rax
    mov rax, [rdi + 32]
    mov [rbx + 248], rax
    mov rax, [rdi + 8]
    mov [rbx + 256], rax
    mov rax, [rdx + 10 * 64 + 8]
    test rax, rax
    jz batch_fixture_observe_invalid
    cmp qword ptr [rdx + 10 * 64 + 16], 64
    jb batch_fixture_observe_invalid
    mov [rbx + 344], rax
    mov qword ptr [rbx + 272], 64
    mov rax, [rdx + 6 * 64 + 8]
    test rax, rax
    jz batch_fixture_observe_invalid
    cmp qword ptr [rdx + 6 * 64 + 16], 256
    jb batch_fixture_observe_invalid
    mov [rbx + 352], rax
    mov qword ptr [rbx + 280], 256
    mov rax, [rdx + 7 * 64 + 8]
    test rax, rax
    jz batch_fixture_observe_invalid
    cmp qword ptr [rdx + 7 * 64 + 16], 256
    jb batch_fixture_observe_invalid
    mov [rbx + 360], rax
    mov qword ptr [rbx + 288], 256
    mov rsi, [r12 + 16]
    mov rsi, [rsi + 8]
    mov rax, [rdx + 8 * 64 + 8]
    cmp [rsi + 8 * 64 + 8], rax
    jne batch_fixture_observe_lease
    mov rax, [rdx + 8 * 64 + 16]
    cmp [rsi + 8 * 64 + 16], rax
    jne batch_fixture_observe_lease
    or qword ptr [rbx + 120], 4
batch_fixture_observe_lease:
    mov rax, [rdx + 7 * 64 + 8]
    cmp [rsi + 7 * 64 + 8], rax
    jne batch_fixture_observe_emit
    mov rax, [rdx + 7 * 64 + 16]
    cmp [rsi + 7 * 64 + 16], rax
    jne batch_fixture_observe_emit
    mov rax, [rdx + 7 * 64 + 48]
    cmp [rsi + 7 * 64 + 48], rax
    jne batch_fixture_observe_emit
    mov rax, [rdx + 7 * 64 + 56]
    cmp [rsi + 7 * 64 + 56], rax
    jne batch_fixture_observe_emit
    or qword ptr [rbx + 120], 8
batch_fixture_observe_emit:
    mov rax, [rbx + 168]
    add rax, [rbx + 176]
    jc batch_fixture_observe_invalid
    add rax, [rbx + 184]
    jc batch_fixture_observe_invalid
    add rax, [rbx + 272]
    jc batch_fixture_observe_invalid
    add rax, [rbx + 280]
    jc batch_fixture_observe_invalid
    add rax, [rbx + 288]
    jc batch_fixture_observe_invalid
    add rax, 192
    jc batch_fixture_observe_invalid
    mov [rbx + 32], rax
    mov edi, 1
    mov rsi, rbx
    mov edx, 104
    call view_write_all
    test rax, rax
    jnz batch_fixture_observe_return
    mov edi, 1
    lea rsi, [rbx + 112]
    mov edx, 192
    call view_write_all
    test rax, rax
    jnz batch_fixture_observe_return
    mov edi, 1
    mov rsi, [rbx + 320]
    mov rdx, [rbx + 168]
    call view_write_all
    test rax, rax
    jnz batch_fixture_observe_return
    mov edi, 1
    mov rsi, [rbx + 328]
    mov rdx, [rbx + 176]
    call view_write_all
    test rax, rax
    jnz batch_fixture_observe_return
    mov edi, 1
    mov rsi, [rbx + 336]
    mov rdx, [rbx + 184]
    call view_write_all
    test rax, rax
    jnz batch_fixture_observe_return
    mov edi, 1
    mov rsi, [rbx + 344]
    mov rdx, [rbx + 272]
    call view_write_all
    test rax, rax
    jnz batch_fixture_observe_return
    mov edi, 1
    mov rsi, [rbx + 352]
    mov rdx, [rbx + 280]
    call view_write_all
    test rax, rax
    jnz batch_fixture_observe_return
    mov edi, 1
    mov rsi, [rbx + 360]
    mov rdx, [rbx + 288]
    call view_write_all
    jmp batch_fixture_observe_return
batch_fixture_observe_invalid:
    mov rax, -22
batch_fixture_observe_return:
    add rsp, 408
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret
