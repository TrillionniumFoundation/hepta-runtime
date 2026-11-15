/* Test-only controls for actual filesystem scheduling and cache observations.
 * They are accepted by the composition fixture's --sync entry only. */
.intel_syntax noprefix
.section .text
view_fixture_install_alternate:
    push rbx
    mov rbx, [r15 + 8]
    mov rax, [rbx]
    mov [r15 + 128], rax
    mov qword ptr [r15 + 144], 131072
    mov edi, 131072
    call view_allocate
    cmp rax, -4095
    jae view_fixture_alternate_done
    mov [r15 + 136], rax
    mov qword ptr [r15 + 160], 16777216
    mov edi, 16777216
    call view_allocate
    cmp rax, -4095
    jae view_fixture_alternate_done
    mov [r15 + 152], rax
    call view_fixture_swap
    lea rdi, [rip + view_fixture_unbound_init]
    mov esi, 16
    call view_call_run
    cmp rax, 32
    jne view_fixture_alternate_invalid
    call view_fixture_swap
    xor eax, eax
    jmp view_fixture_alternate_done
view_fixture_alternate_invalid:
    mov rax, -22
view_fixture_alternate_done:
    pop rbx
    ret
view_fixture_swap:
    mov rdi, [r15 + 8]
    lea rsi, [r15 + 128]
    mov ecx, 8
view_fixture_swap_loop:
    mov rax, [rdi]
    xchg rax, [rsi]
    mov [rdi], rax
    add rdi, 8
    add rsi, 8
    loop view_fixture_swap_loop
    xor qword ptr [r15 + 40], 1
    ret
view_fixture_scratch:
    push rbx
    mov rbx, rax
    mov rdx, [r15 + 80]
    test rdx, rdx
    jnz view_fixture_scratch_loop
    mov edx, 4096
view_fixture_scratch_loop:
    cmp rdx, rbx
    jae view_fixture_scratch_ready
    shl rdx, 1
    jc view_fixture_scratch_resource
    test rdx, rdx
    js view_fixture_scratch_resource
    jmp view_fixture_scratch_loop
view_fixture_scratch_ready:
    cmp rdx, [r15 + 80]
    je view_fixture_scratch_existing
    mov rbx, rdx
    mov rdi, [r15 + 72]
    test rdi, rdi
    jz view_fixture_scratch_initial
    mov rsi, [r15 + 80]
    call view_resize
    jmp view_fixture_scratch_allocated
view_fixture_scratch_initial:
    mov rdi, rdx
    call view_allocate
view_fixture_scratch_allocated:
    cmp rax, -4095
    jae view_fixture_scratch_done
    mov [r15 + 72], rax
    mov [r15 + 80], rbx
view_fixture_scratch_existing:
    mov rax, [r15 + 72]
    jmp view_fixture_scratch_done
view_fixture_scratch_resource:
    mov rax, -12
view_fixture_scratch_done:
    pop rbx
    ret

view_fixture_control:
    push rbx
    push r12
    push r13
    push r14
    sub rsp, 8
    cmp rsi, 32
    jb view_fixture_control_invalid
    mov rbx, rdi
    mov r12, [rbx + 8]
    mov r13, [rbx + 16]
    mov r14, [rbx + 24]
    sub rsi, 32
    cmp r14, rsi
    jne view_fixture_control_invalid
    mov rax, [r15 + 8]
    mov rax, [rax + 8]
    cmp qword ptr [rax + 16], 1
    jne view_fixture_control_invalid
    cmp r12, 1
    je view_fixture_control_select
    test r13, r13
    jnz view_fixture_control_invalid
    cmp r12, 2
    je view_fixture_control_forget
    cmp r12, 3
    je view_fixture_control_probe
    jmp view_fixture_control_invalid
view_fixture_control_select:
    test r14, r14
    jnz view_fixture_control_invalid
    cmp r13, 1
    ja view_fixture_control_invalid
    cmp [r15 + 40], r13
    je view_fixture_control_empty
    call view_fixture_swap
    jmp view_fixture_control_empty
view_fixture_control_forget:
    test r14, r14
    jnz view_fixture_control_invalid
    mov eax, 48
    call view_fixture_scratch
    cmp rax, -4095
    jae view_fixture_control_done
    mov rdi, rax
    mov ecx, 6
    xor eax, eax
    rep stosq
    mov rdi, [r15 + 72]
    mov rax, 0x3130484341435648
    mov [rdi], rax
    mov qword ptr [rdi + 8], 5
    mov esi, 48
    mov edx, 8
    call view_pure_invoke
    cmp rax, 32
    jne view_fixture_control_invalid
    jmp view_fixture_control_empty
view_fixture_control_probe:
    mov rax, r14
    add rax, 64
    jc view_fixture_control_invalid
    call view_fixture_scratch
    cmp rax, -4095
    jae view_fixture_control_done
    mov rdi, rax
    mov ecx, 8
    xor eax, eax
    rep stosq
    mov rdi, [r15 + 72]
    mov rax, 0x3159454b4b4c5248
    mov [rdi], rax
    mov qword ptr [rdi + 8], 1
    mov [rdi + 16], r14
    add rdi, 64
    lea rsi, [rbx + 32]
    mov rcx, r14
    rep movsb
    mov rdi, [r15 + 72]
    lea rsi, [r14 + 64]
    mov edx, 5
    call view_key_invoke
    cmp eax, 0xffff0000
    jae view_fixture_control_invalid
    cmp rax, 32
    jb view_fixture_control_invalid
    mov r13, rax
    mov rbx, [r15 + 8]
    mov rbx, [rbx + 344]
    mov rax, 0x313030594b4c5248
    cmp [rbx], rax
    jne view_fixture_control_invalid
    mov r14, [rbx + 16]
    lea rax, [r14 + 48]
    call view_fixture_scratch
    cmp rax, -4095
    jae view_fixture_control_done
    mov rdi, rax
    mov ecx, 6
    xor eax, eax
    rep stosq
    mov rdi, [r15 + 72]
    mov rax, 0x3130484341435648
    mov [rdi], rax
    mov qword ptr [rdi + 8], 1
    mov [rdi + 24], r14
    add rdi, 48
    lea rsi, [rbx + 32]
    mov rcx, r14
    rep movsb
    mov rdi, [r15 + 72]
    lea rsi, [r14 + 48]
    mov edx, 8
    call view_pure_invoke
    cmp eax, 0xffff0000
    jae view_fixture_control_invalid
    cmp rax, 32
    jb view_fixture_control_invalid
    mov r14, rax
    add rax, r13
    jc view_fixture_control_invalid
    mov [rsp], rax
    jmp view_fixture_control_write
view_fixture_control_empty:
    mov qword ptr [rsp], 0
view_fixture_control_write:
    mov rax, 0x3130525846435648
    mov [r15 + 1024], rax
    mov [r15 + 1032], r12
    mov qword ptr [r15 + 1040], 0
    mov rax, [rsp]
    mov [r15 + 1048], rax
    add rax, 32
    mov [r15 + 1016], rax
    mov edi, 1
    lea rsi, [r15 + 1016]
    mov edx, 40
    call view_write_all
    test rax, rax
    js view_fixture_control_done
    cmp qword ptr [rsp], 0
    je view_fixture_control_done
    mov edi, 1
    mov rsi, rbx
    mov rdx, r13
    call view_write_all
    test rax, rax
    js view_fixture_control_done
    mov rax, [r15 + 8]
    mov rsi, [rax + 536]
    mov edi, 1
    mov rdx, r14
    call view_write_all
    jmp view_fixture_control_done
view_fixture_control_invalid:
    mov rax, -22
view_fixture_control_done:
    add rsp, 8
    pop r14
    pop r13
    pop r12
    pop rbx
    ret
.balign 8
view_fixture_unbound_init:
    .ascii "HVCLI001"
    .quad 0
