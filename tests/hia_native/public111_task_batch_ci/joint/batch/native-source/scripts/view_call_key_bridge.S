/* Fixed slot 5 callable canonical-key boundary. */
.intel_syntax noprefix
.section .text
.global view_key_invoke
view_key_invoke:
    push rbp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub rsp, 24
    mov [rsp], r15
    mov [rsp + 8], rdi
    mov [rsp + 16], rsi
    mov rbx, [r15 + 8]
    add rbx, 320
    mov rax, [rbx + 48]
    test rax, rax
    jnz view_key_installed
    mov edi, 4096
    call view_allocate
    cmp rax, -4095
    jae view_key_install_failed
    mov [rbx + 48], rax
view_key_installed:
    mov r15, rax
    mov rax, [rsp + 8]
    mov [r15], rax
    mov rax, [rsp + 16]
    mov [r15 + 8], rax
    mov [r15 + 48], rax
    mov rax, [rbx + 8]
    mov [r15 + 16], rax
    mov rax, [rbx + 16]
    mov [r15 + 24], rax
    mov rax, [rbx + 24]
    mov [r15 + 32], rax
    mov rax, [rbx + 32]
    mov [r15 + 40], rax
    mov rax, [rsp]
    mov [r15 + 104], rax
    mov rax, [rax + 16]
    mov [r15 + 64], rax
    mov qword ptr [r15 + 72], -1
    mov qword ptr [r15 + 80], -1
    mov qword ptr [r15 + 88], 0
    mov [r15 + 96], rbx
    mov rax, [rbx]
    mov [r15 + 112], rax
    mov [r15 + 120], rsp
    mov rdi, [r15 + 16]
    mov ecx, 128
    xor eax, eax
    rep stosq
    mov rbx, [r15 + 16]
    mov rax, [r15 + 64]
    mov [rbx + 176], rax
    jmp view_key_native_invoke
view_key_install_failed:
    mov eax, 0xfffffffc
    mov [rbx + 40], rax
    add rsp, 24
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret
view_key_native_invoke:
    mov rdi, qword ptr [r15]
    mov rsi, qword ptr [r15 + 48]
    mov rdx, qword ptr [r15 + 32]
    mov rcx, qword ptr [r15 + 40]
    mov r8, qword ptr [r15 + 16]
    mov r9, qword ptr [r15 + 24]
    call qword ptr [r15 + 112]
    mov edx, eax
    cmp rax, rdx
    jne view_key_native_contract_fail
    mov rbx, qword ptr [r15 + 16]
    cmp eax, 0xffffffef
    je view_key_native_grow_workspace
    cmp eax, 0xffffffee
    je view_key_native_grow_output
    cmp eax, 0xfffffff0
    je view_key_native_admit_effect
    cmp eax, 0xffffffff
    je view_key_native_refusal
    cmp eax, 0xfffffffe
    je view_key_native_refusal
    cmp eax, 0xfffffff9
    je view_key_native_contract_fail
    cmp eax, 32
    jb view_key_native_contract_fail
    cmp rax, qword ptr [r15 + 40]
    ja view_key_native_contract_fail
    cmp qword ptr [rbx], 100
    jne view_key_native_contract_fail
    mov rdx, qword ptr [r15 + 32]
    mov rcx, 0x313030594b4c5248
    cmp qword ptr [rdx], rcx
    jne view_key_native_contract_fail
    lea rcx, [rax - 32]
    cmp qword ptr [rdx + 16], rcx
    jne view_key_native_contract_fail
    cmp qword ptr [rdx + 24], 0
    jne view_key_native_contract_fail
    cmp qword ptr [r15 + 72], -1
    jne view_key_native_contract_fail
    cmp qword ptr [r15 + 80], -1
    jne view_key_native_contract_fail
    jmp view_key_native_done
view_key_native_refusal:
    jmp view_key_native_done

view_key_native_grow_workspace:
    mov rdi, qword ptr [rbx + 40]
    cmp rdi, qword ptr [rbx + 32]
    jbe view_key_native_contract_fail
    mov rax, 0x1ffffffffffbfeff
    cmp rdi, rax
    ja view_key_native_memory_fail
    shl rdi, 2
    add rdi, 1049600
    jc view_key_native_memory_fail
    call view_key_native_round_capacity
    mov r12, rax
    cmp r12, qword ptr [r15 + 24]
    jbe view_key_native_invoke
    mov rdi, r12
    call view_key_native_allocate_guarded
    mov r13, rax
    mov rdi, rax
    mov rsi, qword ptr [r15 + 16]
    mov rcx, qword ptr [r15 + 24]
    rep movsb
    mov rdi, qword ptr [r15 + 16]
    mov rsi, qword ptr [r15 + 24]
    add rsi, 4096
    mov qword ptr [r15 + 16], r13
    mov qword ptr [r15 + 24], r12
    mov eax, 11
    syscall
    test rax, rax
    jnz view_key_native_io_fail
    jmp view_key_native_invoke
view_key_native_grow_output:
    mov rdi, qword ptr [rbx + 48]
    cmp rdi, qword ptr [r15 + 40]
    jbe view_key_native_contract_fail
    mov rax, 0xffffffef
    cmp rdi, rax
    ja view_key_native_contract_fail
    call view_key_native_round_capacity
    mov r12, rax
    mov rdi, r12
    call view_key_native_allocate_guarded
    mov r13, rax
    mov rdi, qword ptr [r15 + 32]
    mov rsi, qword ptr [r15 + 40]
    add rsi, 4096
    mov qword ptr [r15 + 32], r13
    mov qword ptr [r15 + 40], r12
    mov eax, 11
    syscall
    test rax, rax
    jnz view_key_native_io_fail
    jmp view_key_native_invoke

view_key_native_admit_effect:
    mov rax, qword ptr [r15 + 48]
    cmp qword ptr [rbx + 8], rax
    jne view_key_native_contract_fail
    mov rax, qword ptr [r15 + 40]
    cmp qword ptr [rbx + 16], rax
    jne view_key_native_contract_fail
    mov rax, qword ptr [r15 + 24]
    cmp qword ptr [rbx + 24], rax
    jne view_key_native_contract_fail
    mov rax, qword ptr [rbx + 40]
    or rax, qword ptr [rbx + 48]
    jnz view_key_native_contract_fail
    mov rax, qword ptr [rbx + 32]
    cmp rax, 1024
    jb view_key_native_contract_fail
    lea rcx, [rax - 1]
    test rcx, rax
    jnz view_key_native_contract_fail
    cmp qword ptr [rbx + 96], rax
    jae view_key_native_contract_fail
    mov rcx, 0x1ffffffffffbfeff
    cmp rax, rcx
    ja view_key_native_contract_fail
    shl rax, 2
    add rax, 1049600
    jc view_key_native_contract_fail
    cmp rax, qword ptr [r15 + 24]
    ja view_key_native_contract_fail
    mov rax, 0x584659454b4c4648
    cmp qword ptr [rbx + 512], rax
    jne view_key_native_contract_fail
    inc qword ptr [r15 + 88]
    jz view_key_native_contract_fail
    mov rax, qword ptr [r15 + 88]
    cmp qword ptr [rbx + 520], rax
    jne view_key_native_contract_fail
    cmp qword ptr [rbx + 56], rax
    jne view_key_native_contract_fail
    mov rax, qword ptr [rbx + 568]
    or rax, qword ptr [rbx + 576]
    or rax, qword ptr [rbx + 584]
    or rax, qword ptr [rbx + 592]
    or rax, qword ptr [rbx + 600]
    or rax, qword ptr [rbx + 608]
    or rax, qword ptr [rbx + 616]
    or rax, qword ptr [rbx + 624]
    or rax, qword ptr [rbx + 632]
    jnz view_key_native_contract_fail
    mov r14, qword ptr [rbx + 528]
    cmp r14, 1
    je view_key_native_get_current
    cmp r14, 2
    je view_key_native_read_link
    cmp r14, 3
    je view_key_native_access_path
    cmp r14, 4
    je view_key_native_access_path
    cmp r14, 5
    je view_key_native_lstat_path
    cmp r14, 6
    je view_key_native_access_path
    cmp r14, 7
    je view_key_native_open_parent
    cmp r14, 8
    je view_key_native_stat_descriptor
    cmp r14, 9
    je view_key_native_close_descriptor
    cmp r14, 10
    je view_key_native_get_flags
    cmp r14, 11
    je view_key_native_set_cloexec
    cmp r14, 12
    je view_key_native_directory_entries
    cmp r14, 13
    je view_key_native_rewind_directory
    jmp view_key_native_contract_fail

view_key_native_get_current:
    cmp qword ptr [rbx], 10
    jne view_key_native_contract_fail
    call view_key_native_resolved_argument
    mov rdx, qword ptr [rbx + 552]
    or rdx, qword ptr [rbx + 560]
    jnz view_key_native_contract_fail
    mov rsi, qword ptr [rbx + 544]
    cmp rsi, qword ptr [rbx + 152]
    jne view_key_native_contract_fail
    cmp rsi, 1024
    jb view_key_native_contract_fail
    cmp rsi, qword ptr [rbx + 32]
    ja view_key_native_contract_fail
    mov eax, 79
    syscall
    jmp view_key_native_value_completion

view_key_native_read_link:
    cmp qword ptr [rbx], 3
    jne view_key_native_contract_fail
    call view_key_native_resolved_argument
    mov rcx, qword ptr [rbx + 544]
    cmp rcx, qword ptr [rbx + 96]
    jne view_key_native_contract_fail
    call view_key_native_cstring
    mov rax, qword ptr [rbx + 32]
    lea rax, [rax + rax + 1024]
    cmp qword ptr [rbx + 552], rax
    jne view_key_native_contract_fail
    lea rsi, [rbx + rax]
    mov rdx, qword ptr [rbx + 144]
    cmp rdx, 1024
    jb view_key_native_contract_fail
    dec rdx
    cmp rdx, qword ptr [rbx + 560]
    jne view_key_native_contract_fail
    cmp rdx, qword ptr [rbx + 32]
    jae view_key_native_contract_fail
    mov eax, 89
    syscall
    jmp view_key_native_value_completion

view_key_native_access_path:
    cmp qword ptr [rbx], 4
    jne view_key_native_contract_fail
    call view_key_native_resolved_argument
    mov rcx, qword ptr [rbx + 96]
    inc rcx
    cmp rcx, qword ptr [rbx + 32]
    jae view_key_native_contract_fail
    cmp rcx, qword ptr [rbx + 544]
    jne view_key_native_contract_fail
    call view_key_native_cstring
    mov rax, qword ptr [rbx + 552]
    or rax, qword ptr [rbx + 560]
    jnz view_key_native_contract_fail
    mov rsi, rdi
    mov edi, -100
    xor edx, edx
    mov r10d, 512
    mov eax, 439
    cmp r14, 3
    je view_key_native_access_go
    cmp r14, 4
    jne view_key_native_stat_access
    cmp qword ptr [r15 + 64], 0
    jne view_key_native_contract_fail
    mov eax, 269
view_key_native_access_go:
    syscall
    jmp view_key_native_zero_completion
view_key_native_stat_access:
    cmp qword ptr [r15 + 64], 1
    jne view_key_native_contract_fail
    xor r10d, r10d
    jmp view_key_native_stat_at

view_key_native_lstat_path:
    mov rax, qword ptr [rbx]
    cmp rax, 12
    je view_key_native_lstat_fixed
    cmp rax, 13
    je view_key_native_lstat_fixed
    cmp rax, 24
    jne view_key_native_contract_fail
    mov rax, qword ptr [rbx + 32]
    lea rax, [rax * 4 + 1024]
    add rax, qword ptr [rbx + 368]
    jc view_key_native_contract_fail
    cmp rax, qword ptr [rbx + 536]
    jne view_key_native_contract_fail
    mov rcx, qword ptr [rbx + 376]
    cmp rcx, qword ptr [rbx + 544]
    jne view_key_native_contract_fail
    mov rdx, qword ptr [rbx + 552]
    cmp rdx, qword ptr [rbx + 160]
    jne view_key_native_contract_fail
    jmp view_key_native_lstat_arguments
view_key_native_lstat_fixed:
    mov rax, qword ptr [rbx + 32]
    lea rax, [rax + rax + 1024]
    cmp rax, qword ptr [rbx + 536]
    jne view_key_native_contract_fail
    mov ecx, 1
    cmp qword ptr [rbx + 544], 1
    jne view_key_native_contract_fail
    cmp qword ptr [rbx + 552], 0
    jne view_key_native_contract_fail
    xor edx, edx
    cmp qword ptr [rbx], 12
    jne view_key_native_lstat_root
    cmp byte ptr [rbx + rax], 46
    jne view_key_native_contract_fail
    jmp view_key_native_lstat_arguments
view_key_native_lstat_root:
    cmp byte ptr [rbx + rax], 47
    jne view_key_native_contract_fail
view_key_native_lstat_arguments:
    cmp qword ptr [rbx + 560], 0
    jne view_key_native_contract_fail
    lea rdi, [rbx + rax]
    call view_key_native_cstring
    mov rsi, rdi
    mov edi, -100
    test rdx, rdx
    jz view_key_native_lstat_cwd
    call view_key_native_descriptor
view_key_native_lstat_cwd:
    mov r10d, 256
view_key_native_stat_at:
    mov r12, rsi
    mov r13, rdi
    mov rdi, rsp
    xor eax, eax
    mov ecx, 32
    rep stosq
    mov rdi, r13
    mov rsi, r12
    mov rdx, rsp
    mov eax, 262
    syscall
    jmp view_key_native_stat_completion

view_key_native_open_parent:
    cmp qword ptr [rbx], 15
    jne view_key_native_contract_fail
    mov rax, qword ptr [rbx + 552]
    or rax, qword ptr [rbx + 560]
    jnz view_key_native_contract_fail
    mov r12, qword ptr [rbx + 536]
    cmp r12, 1
    jb view_key_native_contract_fail
    cmp r12, 2
    ja view_key_native_contract_fail
    cmp qword ptr [r15 + r12 * 8 + 64], -1
    jne view_key_native_contract_fail
    mov rdx, qword ptr [rbx + 544]
    cmp rdx, qword ptr [rbx + 160]
    jne view_key_native_contract_fail
    cmp rdx, r12
    je view_key_native_contract_fail
    mov edi, -100
    test rdx, rdx
    jz view_key_native_open_parent_cwd
    call view_key_native_descriptor
view_key_native_open_parent_cwd:
    lea rsi, [rip + view_key_native_parent_name]
    xor edx, edx
    xor r10d, r10d
    mov eax, 257
    syscall
    test rax, rax
    js view_key_native_error_completion
    cmp rax, 0x7fffffff
    ja view_key_native_contract_fail
    mov qword ptr [r15 + r12 * 8 + 64], rax
    mov rax, r12
    jmp view_key_native_value_completion

view_key_native_stat_descriptor:
    mov rax, qword ptr [rbx]
    cmp rax, 16
    je view_key_native_stat_descriptor_phase
    cmp rax, 18
    jne view_key_native_contract_fail
view_key_native_stat_descriptor_phase:
    call view_key_native_zero_trailing_args
    mov rdx, qword ptr [rbx + 536]
    cmp rdx, qword ptr [rbx + 168]
    jne view_key_native_contract_fail
    call view_key_native_descriptor
    mov r13, rdi
    mov rdi, rsp
    xor eax, eax
    mov ecx, 32
    rep stosq
    mov rdi, r13
    mov rsi, rsp
    mov eax, 5
    syscall
view_key_native_stat_completion:
    test rax, rax
    js view_key_native_error_completion
    test rax, rax
    jnz view_key_native_contract_fail
    mov rax, qword ptr [rsp]
    mov qword ptr [rbx + 584], rax
    mov rax, qword ptr [rsp + 8]
    mov qword ptr [rbx + 592], rax
    mov eax, dword ptr [rsp + 24]
    mov qword ptr [rbx + 600], rax
    mov rax, qword ptr [rsp + 56]
    mov qword ptr [rbx + 616], rax
    jmp view_key_native_acknowledge

view_key_native_close_descriptor:
    mov rax, qword ptr [rbx]
    cmp rax, 17
    je view_key_native_close_phase
    cmp rax, 27
    je view_key_native_close_phase
    cmp rax, 29
    jne view_key_native_contract_fail
view_key_native_close_phase:
    call view_key_native_zero_trailing_args
    mov rdx, qword ptr [rbx + 536]
    call view_key_native_descriptor
    mov qword ptr [r15 + rdx * 8 + 64], -1
    mov eax, 3
    syscall
    jmp view_key_native_zero_completion

view_key_native_get_flags:
    cmp qword ptr [rbx], 19
    jne view_key_native_contract_fail
    call view_key_native_zero_trailing_args
    mov rdx, qword ptr [rbx + 536]
    cmp rdx, qword ptr [rbx + 168]
    jne view_key_native_contract_fail
    call view_key_native_descriptor
    mov esi, 3
    xor edx, edx
    mov eax, 72
    syscall
    jmp view_key_native_value_completion
view_key_native_set_cloexec:
    cmp qword ptr [rbx], 20
    jne view_key_native_contract_fail
    call view_key_native_zero_trailing_args
    mov rdx, qword ptr [rbx + 536]
    cmp rdx, qword ptr [rbx + 168]
    jne view_key_native_contract_fail
    call view_key_native_descriptor
    mov esi, 2
    mov edx, 1
    mov eax, 72
    syscall
    jmp view_key_native_zero_completion

view_key_native_directory_entries:
    cmp qword ptr [rbx], 22
    jne view_key_native_contract_fail
    cmp qword ptr [rbx + 560], 0
    jne view_key_native_contract_fail
    mov rax, qword ptr [rbx + 32]
    lea rax, [rax * 4 + 1024]
    cmp rax, qword ptr [rbx + 544]
    jne view_key_native_contract_fail
    mov r12, qword ptr [rbx + 552]
    cmp r12, 32768
    jb view_key_native_contract_fail
    cmp r12, 1048576
    ja view_key_native_contract_fail
    cmp r12, qword ptr [rbx + 336]
    jne view_key_native_contract_fail
    lea rsi, [rbx + rax]
    mov rdx, qword ptr [rbx + 536]
    cmp rdx, qword ptr [rbx + 160]
    jne view_key_native_contract_fail
    call view_key_native_descriptor
    mov rdx, r12
    mov eax, 217
    syscall
    jmp view_key_native_value_completion
view_key_native_rewind_directory:
    cmp qword ptr [rbx], 23
    jne view_key_native_contract_fail
    call view_key_native_zero_trailing_args
    mov rdx, qword ptr [rbx + 536]
    cmp rdx, qword ptr [rbx + 160]
    jne view_key_native_contract_fail
    call view_key_native_descriptor
    xor esi, esi
    xor edx, edx
    mov eax, 8
    syscall
    jmp view_key_native_value_completion

view_key_native_resolved_argument:
    mov rax, qword ptr [rbx + 32]
    add rax, 1024
    cmp qword ptr [rbx + 536], rax
    jne view_key_native_contract_fail
    lea rdi, [rbx + rax]
    ret
view_key_native_zero_trailing_args:
    mov rax, qword ptr [rbx + 544]
    or rax, qword ptr [rbx + 552]
    or rax, qword ptr [rbx + 560]
    jnz view_key_native_contract_fail
    ret
# logical slot in rdx -> real view_key_native_descriptor in rdi, preserving other arguments.
view_key_native_descriptor:
    cmp rdx, 1
    jb view_key_native_contract_fail
    cmp rdx, 2
    ja view_key_native_contract_fail
    mov rdi, qword ptr [r15 + rdx * 8 + 64]
    test rdi, rdi
    js view_key_native_contract_fail
    ret
# Exact span containment and unique final NUL.  rdx is preserved for dirfd.
view_key_native_cstring:
    mov rax, rdi
    sub rax, rbx
    jc view_key_native_contract_fail
    cmp rax, qword ptr [r15 + 24]
    jae view_key_native_contract_fail
    mov r11, qword ptr [r15 + 24]
    sub r11, rax
    cmp rcx, r11
    jae view_key_native_contract_fail
    cmp byte ptr [rdi + rcx], 0
    jne view_key_native_contract_fail
    xor eax, eax
view_key_native_cstring_loop:
    cmp rax, rcx
    je view_key_native_cstring_done
    cmp byte ptr [rdi + rax], 0
    je view_key_native_contract_fail
    inc rax
    jmp view_key_native_cstring_loop
view_key_native_cstring_done:
    ret
view_key_native_value_completion:
    test rax, rax
    js view_key_native_error_completion
    mov qword ptr [rbx + 568], rax
    jmp view_key_native_acknowledge
view_key_native_zero_completion:
    test rax, rax
    js view_key_native_error_completion
    test rax, rax
    jnz view_key_native_contract_fail
    jmp view_key_native_acknowledge
view_key_native_error_completion:
    neg rax
    cmp rax, 4095
    ja view_key_native_contract_fail
    mov qword ptr [rbx + 576], rax
view_key_native_acknowledge:
    mov qword ptr [rbx + 608], 1
    mov rax, [r15 + 104]
    cmp qword ptr [rax + 96], 1
    jne view_key_native_invoke
    mov edi, 2
    lea rsi, [rbx + 512]
    mov edx, 128
    call view_write_all
    test rax, rax
    js view_key_native_io_fail
    jmp view_key_native_invoke

view_key_native_round_capacity:
    mov rax, rdi
    add rax, 4095
    jc view_key_native_memory_fail
    and rax, -4096
    test rax, rax
    jz view_key_native_memory_fail
    mov rdx, 0x7ffffffffffff000
    cmp rax, rdx
    jae view_key_native_memory_fail
    ret
view_key_native_allocate_guarded:
    push rbx
    mov rbx, rdi
    lea rsi, [rdi + 4096]
    xor edi, edi
    mov edx, 3
    mov r10d, 0x22
    mov r8, -1
    xor r9d, r9d
    mov eax, 9
    syscall
    cmp rax, -4095
    jae view_key_native_memory_fail
    push rax
    lea rdi, [rax + rbx]
    mov esi, 4096
    xor edx, edx
    mov eax, 10
    syscall
    test rax, rax
    jnz view_key_native_memory_fail
    pop rax
    pop rbx
    ret
view_key_native_cleanup:
    mov rdi, qword ptr [r15 + 72]
    mov qword ptr [r15 + 72], -1
    test rdi, rdi
    js view_key_native_cleanup_second
    mov eax, 3
    syscall
view_key_native_cleanup_second:
    mov rdi, qword ptr [r15 + 80]
    mov qword ptr [r15 + 80], -1
    test rdi, rdi
    js view_key_native_cleanup_done
    mov eax, 3
    syscall
view_key_native_cleanup_done:
    ret
view_key_native_contract_fail:
    mov eax, 0xffffffff
    jmp view_key_native_done
view_key_native_memory_fail:
    mov eax, 0xfffffffc
    jmp view_key_native_done
view_key_native_io_fail:
    mov eax, 0xfffffffb
view_key_native_done:
    mov [r15 + 128], eax
    call view_key_native_cleanup
    mov rbx, [r15 + 96]
    mov rax, [r15 + 16]
    mov [rbx + 8], rax
    mov rax, [r15 + 24]
    mov [rbx + 16], rax
    mov rax, [r15 + 32]
    mov [rbx + 24], rax
    mov rax, [r15 + 40]
    mov [rbx + 32], rax
    mov eax, [r15 + 128]
    mov [rbx + 40], rax
    mov rsp, [r15 + 120]
    add rsp, 24
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret
view_key_native_parent_name:
    .asciz ".."
