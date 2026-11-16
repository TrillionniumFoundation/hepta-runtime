/* Private graph fixture only. Two fixed session engines share the installed
 * configuration and fence hub. No selector appears in the public transport. */
.intel_syntax noprefix
.section .text
.type public_span_start,@function
public_span_start:
    cld
    mov rax, [rsp]
    lea rdi, [rsp + rax * 8 + 16]
    sub rsp, 512
    mov r12, rsp
    mov [r12 + 504], r15
    mov [r12 + 496], rdi
    xor eax, eax
    mov rdi, r12
    mov ecx, 496
    rep stosb
    mov rdi, [r12 + 496]
    call runtime_filesystem_hub_create
    cmp rax, -4095
    jae fs_fixture_failure
    mov [r12 + 16], rax
    call runtime_text_body_hub_create
    cmp rax, -4095
    jae fs_fixture_failure
    mov [r12 + 56], rax
    mov edi, 4096
    call view_allocate
    cmp rax, -4095
    jae fs_fixture_failure
    mov [r12 + 24], rax
    mov qword ptr [r12 + 32], 4096
fs_fixture_getcwd:
    mov rdi, [r12 + 24]
    add rdi, 32
    mov rsi, [r12 + 32]
    sub rsi, 32
    mov eax, 79
    syscall
    cmp rax, -34
    je fs_fixture_grow_cwd
    cmp rax, -4095
    jae fs_fixture_failure
    cmp rax, 2
    jb fs_fixture_failure
    dec rax
    mov rdx, [r12 + 24]
    mov [rdx + 16], rax
    add rax, 32
    mov [r12 + 40], rax
    mov rax, 0x3230305157535248 /* HRSWQ002 */
    mov [rdx], rax
    mov qword ptr [rdx + 8], 1
    mov qword ptr [rdx + 24], 0
    xor r13d, r13d
fs_fixture_create_session:
    lea rdi, [rip + grow_fixture_images]
    mov rsi, [r12 + 504]
    call runtime_grow_create
    cmp rax, -4095
    jae fs_fixture_failure
    mov [r12 + r13 * 8], rax
    mov r15, rax
    mov rax, [r12 + 56]
    mov [r15 + 400], rax
    mov qword ptr [r15 + 80], 3 /* private stderr trace, fd+1 */
    mov rdi, [r12 + 16]
    call runtime_filesystem_hub_bind
    test rax, rax
    jnz fs_fixture_failure
    mov rdi, [r12 + 24]
    mov rsi, [r12 + 40]
    mov r8d, 6
    call runtime_grow_owned
    cmp rax, 32
    jne fs_fixture_failure
    mov rdx, [r15 + 8]
    cmp qword ptr [rdx + 6 * 64 + 56], 32
    jne fs_fixture_failure
    mov rdx, [rdx + 6 * 64 + 32]
    mov rax, 0x3230305257535248
    cmp [rdx], rax
    jne fs_fixture_failure
    mov rax, [rdx + 8]
    or rax, [rdx + 16]
    or rax, [rdx + 24]
    jnz fs_fixture_failure
    call runtime_grow_view_ensure
    cmp rax, -4095
    jae fs_fixture_failure
    inc r13d
    cmp r13d, 2
    jb fs_fixture_create_session
    jmp fs_fixture_next
fs_fixture_grow_cwd:
    mov rdx, [r12 + 32]
    add rdx, rdx
    jc fs_fixture_failure
    call fs_fixture_grow
    jmp fs_fixture_getcwd
fs_fixture_next:
    xor edi, edi
    lea rsi, [r12 + 64]
    mov edx, 32
    call view_read_all
    test rax, rax
    jz fs_fixture_finish
    cmp rax, 1
    jne fs_fixture_failure
    mov rax, 0x3230515846534648 /* HFSFXQ02 */
    cmp [r12 + 64], rax
    jne fs_fixture_failure
    cmp qword ptr [r12 + 72], 1
    ja fs_fixture_failure
    cmp qword ptr [r12 + 80], 41
    ja fs_fixture_failure
    mov rdx, [r12 + 88]
    cmp rdx, [r12 + 32]
    jbe fs_fixture_input_ready
    add rdx, 4095
    jc fs_fixture_failure
    and rdx, -4096
    call fs_fixture_grow
fs_fixture_input_ready:
    xor edi, edi
    mov rsi, [r12 + 24]
    mov rdx, [r12 + 88]
    call view_read_all
    cmp rax, 1
    jne fs_fixture_failure
    mov rax, [r12 + 72]
    mov r15, [r12 + rax * 8]
    cmp qword ptr [r12 + 80], 41
    je fs_fixture_text_snapshot
    cmp qword ptr [r12 + 80], 33
    je fs_fixture_snapshot
    cmp qword ptr [r12 + 80], 34
    je fs_fixture_public_request
    lea rsi, [r15 + 128]
    lea rdi, [r12 + 128]
    mov ecx, 6
    rep movsq
    mov rdi, [r12 + 24]
    mov rsi, [r12 + 88]
    mov r8, [r12 + 80]
    call runtime_grow_owned
    mov [r12 + 216], rax
    mov rbx, [r12 + 80]
    shl rbx, 6
    add rbx, [r15 + 8]
    cmp rax, [rbx + 48]
    jne fs_fixture_failure
    mov rax, [rbx + 56]
    cmp rax, [rbx + 40]
    ja fs_fixture_failure
    mov [r12 + 224], rax
    mov rax, 0x3230525846534648 /* HFSFXR02 */
    mov [r12 + 192], rax
    mov rax, [r12 + 72]
    mov [r12 + 200], rax
    mov rax, [r12 + 80]
    mov [r12 + 208], rax
    xor ecx, ecx
fs_fixture_counter:
    mov rax, [r15 + rcx * 8 + 128]
    sub rax, [r12 + rcx * 8 + 128]
    jc fs_fixture_failure
    mov [r12 + rcx * 8 + 232], rax
    inc ecx
    cmp ecx, 6
    jb fs_fixture_counter
    mov rax, [rbx + 16]
    mov [r12 + 280], rax
    mov rax, [rbx + 40]
    mov [r12 + 288], rax
    mov edi, 1
    lea rsi, [r12 + 192]
    mov edx, 104
    call view_write_all
    test rax, rax
    jnz fs_fixture_failure
    mov edi, 1
    mov rsi, [rbx + 32]
    mov rdx, [rbx + 56]
    call view_write_all
    test rax, rax
    jnz fs_fixture_failure
    jmp fs_fixture_next
fs_fixture_finish:
    xor r13d, r13d
fs_fixture_finish_session:
    mov r15, [r12 + r13 * 8]
    call runtime_text_body_release
    test rax, rax
    jnz fs_fixture_failure
    call runtime_text_create_release
    test rax, rax
    jnz fs_fixture_failure
    call runtime_grow_fence_release
    test rax, rax
    jnz fs_fixture_failure
    call runtime_grow_view_release
    test rax, rax
    jnz fs_fixture_failure
    call runtime_grow_destroy
    test rax, rax
    jnz fs_fixture_failure
    mov qword ptr [r12 + r13 * 8], 0
    inc r13d
    cmp r13d, 2
    jb fs_fixture_finish_session
    mov rdi, [r12 + 56]
    call runtime_text_body_hub_destroy
    test rax, rax
    jnz fs_fixture_failure
    mov rdi, [r12 + 16]
    call runtime_filesystem_hub_destroy
    test rax, rax
    jnz fs_fixture_failure
    mov rdi, [r12 + 24]
    mov rsi, [r12 + 32]
    add rsi, 4096
    mov eax, 11
    syscall
    test rax, rax
    jnz fs_fixture_failure
    mov r15, [r12 + 504]
    jmp frame_eof
fs_fixture_grow:
    test rdx, rdx
    jle fs_fixture_failure
    mov [r12 + 48], rdx
    mov rdi, [r12 + 24]
    mov rsi, [r12 + 32]
    call view_resize
    cmp rax, -4095
    jae fs_fixture_failure
    mov [r12 + 24], rax
    mov rax, [r12 + 48]
    mov [r12 + 32], rax
    ret
fs_fixture_failure:
    mov r15, [r12 + 504]
    jmp fatal
.balign 8
grow_fixture_images:
    .zero 440
