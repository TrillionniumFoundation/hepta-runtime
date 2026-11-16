/* Public newline JSON-RPC transport. HIA slot18 owns routing and responses.
 * No input byte chooses a child slot, pointer, session or publisher instance. */
.intel_syntax noprefix
.section .text
.type public_span_start, @function
public_span_start:
    cld
    mov rax, [rsp]
    lea r14, [rsp + rax * 8 + 16]
    sub rsp, 256
    mov r12, rsp
    mov [r12 + 248], r15
    xor eax, eax
    mov rdi, r12
    mov ecx, 240
    rep stosb
    mov rdi, r14
    call runtime_filesystem_hub_create
    cmp rax, -4095
    jae public_span_fail
    mov [r12 + 232], rax
    call runtime_text_body_hub_create
    cmp rax, -4095
    jae public_span_fail
    mov [r12 + 224], rax
    xor ebx, ebx
    xor ebp, ebp
    lea rdi, [rip + grow_fixture_images]
    mov rsi, r15
    call runtime_grow_create
    cmp rax, -4095
    jae public_span_fail
    mov r15, rax
    mov [r12 + 240], rax
    mov rax, [r12 + 224]
    mov [r15 + 400], rax
    mov rdi, [r12 + 232]
    call runtime_filesystem_hub_bind
    test rax, rax
    jnz public_span_fail
    /* SIGPIPE is an I/O result, including before the first publication. */
    mov qword ptr [r12 + 160], 1
    mov edi, 13
    lea rsi, [r12 + 160]
    xor edx, edx
    mov r10d, 8
    mov eax, 13
    syscall
    test rax, rax
    js public_span_fail
    mov edi, 4096
    call view_allocate
    cmp rax, -4095
    jae public_span_fail
    mov rbx, rax
    mov ebp, 4096
public_span_getcwd:
    lea rdi, [rbx + 32]
    lea rsi, [rbp - 32]
    mov eax, 79
    syscall
    cmp rax, -34
    je public_span_getcwd_grow
    cmp rax, -4095
    jae public_span_fail
    cmp rax, 2
    jb public_span_fail
    cmp rax, rbp
    ja public_span_fail
    dec rax /* Kernel getcwd includes its terminator. */
    mov [rbx + 16], rax
    lea rsi, [rax + 32]
    mov rdx, 0x3230305157535248 /* HRSWQ002 */
    mov [rbx], rdx
    mov qword ptr [rbx + 8], 1
    mov qword ptr [rbx + 24], 0
    mov rdi, rbx
    mov r8d, 6
    call runtime_grow_owned
    cmp eax, 32
    jne public_span_fail
    mov rdx, [r15 + 8]
    add rdx, 6 * 64
    cmp qword ptr [rdx + 56], 32
    jne public_span_fail
    mov rdx, [rdx + 32]
    mov rax, 0x3230305257535248 /* HRSWR002 */
    cmp [rdx], rax
    jne public_span_fail
    mov rax, [rdx + 8]
    or rax, [rdx + 16]
    or rax, [rdx + 24]
    jnz public_span_fail
    jmp public_span_scan
public_span_getcwd_grow:
    call public_span_grow_input
    test eax, eax
    jnz public_span_fail
    jmp public_span_getcwd
public_span_next:
    cmp qword ptr [r12 + 40], 0
    jne public_span_finish
    mov rcx, [r12 + 16]
    mov rdx, [r12]
    cmp rcx, rdx
    ja public_span_fail
    sub rdx, rcx
    mov rdi, rbx
    lea rsi, [rbx + rcx]
    mov rcx, rdx
    rep movsb
    mov [r12], rdx
    mov qword ptr [r12 + 8], 0
    mov qword ptr [r12 + 16], 0
public_span_scan:
    mov rcx, [r12 + 8]
    mov rdx, [r12]
    cmp rdx, rbp
    ja public_span_fail
public_span_scan_byte:
    cmp rcx, rdx
    jae public_span_need_input
    cmp byte ptr [rbx + rcx], 10
    je public_span_line
    inc rcx
    jmp public_span_scan_byte
public_span_line:
    mov rsi, rcx
    inc rcx
    mov [r12 + 16], rcx
    jmp public_span_request
public_span_need_input:
    mov [r12 + 8], rcx
    cmp qword ptr [r12 + 24], 0
    jne public_span_final_line
    cmp rdx, rbp
    jne public_span_read
    call public_span_grow_input
    test eax, eax
    jnz public_span_fail
    mov rdx, [r12]
public_span_read:
    lea rsi, [rbx + rdx]
    mov rcx, rbp
    sub rcx, rdx
    cmp rcx, 65536
    jbe public_span_read_size
    mov ecx, 65536
public_span_read_size:
    mov rdx, rcx
    xor edi, edi
    xor eax, eax
    syscall
    cmp rax, -4
    je public_span_scan
    cmp rax, -11
    je public_span_wait_input
    test rax, rax
    js public_span_fail
    jz public_span_input_eof
    add [r12], rax
    jc public_span_fail
    jmp public_span_scan
public_span_wait_input:
    mov dword ptr [r12 + 192], 0
    mov dword ptr [r12 + 196], 1
    lea rdi, [r12 + 192]
    mov esi, 1
    mov rdx, -1
    mov eax, 7
    syscall
    cmp rax, -4
    je public_span_wait_input
    cmp rax, 1
    jne public_span_fail
    jmp public_span_scan
public_span_input_eof:
    mov qword ptr [r12 + 24], 1
    jmp public_span_scan
public_span_final_line:
    test rdx, rdx
    jz public_span_finish
    mov [r12 + 16], rdx
    mov rsi, rdx
public_span_request:
    mov rdi, rbx
    mov r8d, 18
    call runtime_grow_owned
    cmp eax, 64
    jne public_span_fail
    mov rdx, [r15 + 8]
    add rdx, 18 * 64
    mov r13, [rdx + 32]
    mov rax, [r13 + 16]
    mov [r12 + 40], rax
    cmp qword ptr [r13 + 8], 0
    je public_span_silent
    cmp qword ptr [r13 + 8], 2
    je public_span_publish
    cmp qword ptr [r13 + 8], 1
    jne public_span_fail
    cmp qword ptr [r13 + 32], 0
    jne public_span_fail
    mov edi, 1
    lea rsi, [r13 + 64]
    mov rdx, [r13 + 24]
    call public_span_write
    test eax, eax
    jnz public_span_fail
    jmp public_span_newline
public_span_publish:
    lea rdi, [r13 + 64]
    mov rsi, [r13 + 24]
    lea rdx, [rdi + rsi]
    mov rcx, [r13 + 32]
    mov r8, [r13 + 40]
    call runtime_publication_span
    test eax, eax
    jnz public_span_fail
public_span_newline:
    mov edi, 1
    lea rsi, [rip + newline]
    mov edx, 1
    call public_span_write
    test eax, eax
    jnz public_span_fail
    jmp public_span_next
public_span_silent:
    mov rax, [r13 + 24]
    or rax, [r13 + 32]
    or rax, [r13 + 40]
    jnz public_span_fail
    jmp public_span_next
public_span_finish:
    call runtime_text_body_release
    test rax, rax
    jnz public_span_fail
    call runtime_text_create_release
    test rax, rax
    jnz public_span_fail
    call runtime_grow_fence_release
    test rax, rax
    jnz public_span_fail
    call runtime_grow_view_release
    test rax, rax
    jnz public_span_fail
    call runtime_grow_destroy
    test rax, rax
    jnz public_span_fail
    mov qword ptr [r12 + 240], 0
    mov rdi, [r12 + 224]
    call runtime_text_body_hub_destroy
    test rax, rax
    jnz public_span_fail
    mov qword ptr [r12 + 224], 0
    mov rdi, [r12 + 232]
    call runtime_filesystem_hub_destroy
    test rax, rax
    jnz public_span_fail
    mov qword ptr [r12 + 232], 0
    mov rdi, rbx
    lea rsi, [rbp + 4096]
    mov eax, 11
    syscall
    test rax, rax
    jnz public_span_fail
    mov r15, [r12 + 248]
    jmp frame_eof /* Existing HIA config lease/lock teardown. */
public_span_fail:
    mov r15, [r12 + 248]
    jmp fatal /* Never convert resource/invariant failure to business text. */
/* Physical capacity grows by checked pages, without an application quota. */
public_span_grow_input:
    mov rdx, rbp
    add rdx, rdx
    jc public_span_grow_failed
    test rdx, rdx
    jle public_span_grow_failed
    mov [r12 + 32], rdx
    mov rdi, rbx
    mov rsi, rbp
    call view_resize
    cmp rax, -4095
    jae public_span_grow_failed
    mov rbx, rax
    mov rbp, [r12 + 32]
    xor eax, eax
    ret
public_span_grow_failed:
    mov eax, 75
    ret
/* Complete writes preserve the same byte span across EINTR/EAGAIN. */
public_span_write:
    test rdx, rdx
    jz public_span_write_ok
public_span_write_more:
    mov eax, 1
    syscall
    cmp rax, -4
    je public_span_write_more
    cmp rax, -11
    je public_span_write_wait
    test rax, rax
    jle public_span_write_failed
    add rsi, rax
    sub rdx, rax
    jnz public_span_write_more
public_span_write_ok:
    xor eax, eax
    ret
public_span_write_wait:
    push rsi
    push rdx
    sub rsp, 16
    mov dword ptr [rsp], 1
    mov dword ptr [rsp + 4], 4
public_span_write_poll:
    mov rdi, rsp
    mov esi, 1
    mov rdx, -1
    mov eax, 7
    syscall
    cmp rax, -4
    je public_span_write_poll
    add rsp, 16
    pop rdx
    pop rsi
    mov edi, 1
    cmp rax, 1
    je public_span_write_more
public_span_write_failed:
    mov eax, 74
    ret
.balign 8
grow_fixture_images:
    .zero 368
