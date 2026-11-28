/* Persistent closed composition fixture. Production links the same callable
 * engine; the explicit --sync mode is solely deterministic I/O qualification. */
.intel_syntax noprefix
.section .text
.global _start
.global view_image_table
_start:
    xor r12d, r12d
    mov rax, [rsp]
    cmp rax, 1
    je view_fixture_arguments_done
    cmp rax, 2
    jne view_fixture_usage
    mov rdx, [rsp + 16]
    cmp word ptr [rdx], 0x2d2d
    jne view_fixture_usage
    cmp dword ptr [rdx + 2], 0x636e7973
    jne view_fixture_usage
    cmp byte ptr [rdx + 6], 0
    jne view_fixture_usage
    mov r12d, 1
view_fixture_arguments_done:
    lea rsi, [rsp + rax * 8 + 16]
view_fixture_environment:
    cmp qword ptr [rsi], 0
    lea rsi, [rsi + 8]
    jne view_fixture_environment
    xor ebp, ebp
view_fixture_auxiliary:
    mov rax, [rsi]
    test rax, rax
    jz view_fixture_install
    cmp rax, 23
    jne view_fixture_aux_next
    cmp qword ptr [rsi + 8], 0
    setne bpl
view_fixture_aux_next:
    add rsi, 16
    jmp view_fixture_auxiliary
view_fixture_install:
    lea rdi, [rip + view_image_table]
    mov rsi, rbp
    call view_engine_create
    cmp rax, -4095
    jae view_fixture_resource
    mov r15, rax
    mov [r15 + 24], r12
    mov qword ptr [r15 + 40], 1
    mov qword ptr [r15 + 96], 1
    mov edi, 4096
    call view_allocate
    cmp rax, -4095
    jae view_fixture_resource
    mov [r15 + 48], rax
    mov qword ptr [r15 + 56], 4096
    mov qword ptr [r15 + 1024], 1
    mov edi, 13
    lea rsi, [r15 + 1024]
    xor edx, edx
    mov r10d, 8
    mov eax, 13
    syscall
    test rax, rax
    js view_fixture_io
    cmp qword ptr [r15 + 24], 0
    je view_fixture_next
    call view_fixture_install_alternate
    test rax, rax
    jnz view_fixture_invalid
view_fixture_next:
    xor edi, edi
    lea rsi, [r15 + 64]
    mov edx, 8
    call view_read_all
    test rax, rax
    jz view_fixture_success
    cmp rax, 1
    jne view_fixture_io
    mov rax, [r15 + 64]
    cmp rax, 16
    jb view_fixture_invalid
    test rax, rax
    js view_fixture_resource
    cmp rax, [r15 + 56]
    jbe view_fixture_read
    mov rdx, [r15 + 56]
view_fixture_grow_loop:
    cmp rdx, rax
    jae view_fixture_grow_ready
    shl rdx, 1
    jc view_fixture_resource
    test rdx, rdx
    js view_fixture_resource
    jmp view_fixture_grow_loop
view_fixture_grow_ready:
    mov [r15 + 88], rdx
    mov rdi, [r15 + 48]
    mov rsi, [r15 + 56]
    call view_resize
    cmp rax, -4095
    jae view_fixture_resource
    mov [r15 + 48], rax
    mov rdx, [r15 + 88]
    mov [r15 + 56], rdx
view_fixture_read:
    xor edi, edi
    mov rsi, [r15 + 48]
    mov rdx, [r15 + 64]
    call view_read_all
    cmp rax, 1
    jne view_fixture_io
    mov rdi, [r15 + 48]
    mov rsi, [r15 + 64]
    mov rax, 0x3130584946435648
    cmp [rdi], rax
    je view_fixture_command
    call view_call_run
    mov [r15 + 1032], rax
    xor edx, edx
    cmp eax, 0xffff0000
    jae view_fixture_result
    mov rdx, rax
view_fixture_result:
    mov [r15 + 1040], rdx
    mov qword ptr [r15 + 1048], 0
    add rdx, 32
    mov [r15 + 1016], rdx
    mov rax, 0x3130524f4c435648
    mov [r15 + 1024], rax
    mov edi, 1
    lea rsi, [r15 + 1016]
    mov edx, 40
    call view_write_all
    test rax, rax
    js view_fixture_io
    mov rax, [r15 + 8]
    mov rsi, [rax + 24]
    mov rdx, [r15 + 1040]
    cmp rdx, [rax + 32]
    ja view_fixture_invalid
    mov edi, 1
    call view_write_all
    test rax, rax
    js view_fixture_io
    jmp view_fixture_next
view_fixture_command:
    cmp qword ptr [r15 + 24], 1
    jne view_fixture_invalid
    call view_fixture_control
    test rax, rax
    jnz view_fixture_invalid
    jmp view_fixture_next
view_fixture_success:
    cmp qword ptr [r15 + 40], 1
    je view_fixture_bound_exit
    call view_fixture_swap
view_fixture_bound_exit:
    call view_engine_retire
    test rax, rax
    jnz view_fixture_invalid
    call view_engine_destroy
    test rax, rax
    jnz view_fixture_invalid
    xor edi, edi
    jmp view_fixture_exit
view_fixture_usage:
    mov edi, 64
    jmp view_fixture_exit
view_fixture_invalid:
    mov edi, 70
    jmp view_fixture_exit
view_fixture_resource:
    mov edi, 71
    jmp view_fixture_exit
view_fixture_io:
    mov edi, 74
view_fixture_exit:
    mov eax, 231
    syscall
    ud2
.balign 8
view_image_table:
    .zero 152
