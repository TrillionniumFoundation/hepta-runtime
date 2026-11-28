/* Callable storage. The effect closure is imported with private label names. */
.intel_syntax noprefix
.section .text
.global runtime_grow_io_owned
runtime_grow_io_owned:
    push rbp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub rsp, 552
    mov [rsp + 512], rdi
    mov [rsp + 520], rsi
    mov [rsp + 528], r15
    mov rax, [r15 + 8]
    lea rax, [rax + 15 * 64]
    mov [rsp + 536], rax
    mov qword ptr [r15 + 512 + 15 * 64], 1
    mov rax, [r15 + 192]
    test rax, rax
    jnz rgio_control_ready
    mov edi, 4096
    call view_allocate
    cmp rax, -4095
    jae rgio_allocation_failed_early
    mov [r15 + 192], rax
    mov [rax + 120], r15
    mov qword ptr [rax + 72], -1
    mov qword ptr [rax + 80], -1
    mov rdx, [r15 + 32]
    test rdx, rdx
    setne dl
    movzx edx, dl
    mov [rax + 64], rdx
rgio_control_ready:
    mov rdx, [r15 + 80]
    mov [rax + 112], rdx
    mov r15, rax
    mov [r15 + 152], rsp
    mov rbx, [rsp + 536]
    mov rax, [rbx]
    test rax, rax
    jz rgio_memory_fail
    mov [r15 + 128], rax
    mov rax, [rsp + 512]
    mov [r15], rax
    mov rax, [rsp + 520]
    mov [r15 + 8], rax
    mov [r15 + 48], rax
    cmp qword ptr [r15 + 16], 0
    jne rgio_output_allocate
    mov edi, 1056768
    call view_allocate
    cmp rax, -4095
    jae rgio_memory_fail
    mov [r15 + 16], rax
    mov qword ptr [r15 + 24], 1056768
    mov rdx, [r15 + 64]
    mov [rax + 176], rdx
    mov rdx, [rsp + 528]
    bts qword ptr [rdx + 64], 15
rgio_output_allocate:
    cmp qword ptr [r15 + 32], 0
    jne rgio_storage_ready
    mov edi, 4096
    call view_allocate
    cmp rax, -4095
    jae rgio_memory_fail
    mov [r15 + 32], rax
    mov qword ptr [r15 + 40], 4096
    mov rdx, [rsp + 528]
    bts qword ptr [rdx + 72], 15
rgio_storage_ready:
    call rgio_sync_descriptor
    jmp rgio_invoke

rgio_invoke:
    mov rax, [r15 + 120]
    inc qword ptr [rax + 128]
    mov rdi, qword ptr [r15]
    mov rsi, qword ptr [r15 + 48]
    mov rdx, qword ptr [r15 + 32]
    mov rcx, qword ptr [r15 + 40]
    mov r8, qword ptr [r15 + 16]
    mov r9, qword ptr [r15 + 24]
    call qword ptr [r15 + 128]
    mov edi, 1
    call rgio_trace
    mov edx, eax
    cmp rax, rdx
    jne rgio_contract_fail
    mov rbx, qword ptr [r15 + 16]
    cmp eax, 0xffffffef
    je rgio_grow_workspace
    cmp eax, 0xffffffee
    je rgio_grow_output
    cmp eax, 0xfffffff0
    je rgio_admit_effect
    cmp eax, 0xffffffff
    je rgio_refusal
    cmp eax, 0xfffffffe
    je rgio_refusal
    cmp eax, 0xfffffff9
    je rgio_contract_fail
    cmp eax, 64
    jne rgio_contract_fail
    mov rdx, qword ptr [r15 + 32]
    mov rcx, 0x3230524f49445748
    cmp qword ptr [rdx], rcx
    jne rgio_contract_fail
    mov rcx, qword ptr [rdx + 48]
    cmp rcx, qword ptr [rbx + 640]
    jne rgio_contract_fail
    mov rcx, qword ptr [rdx + 56]
    cmp rcx, qword ptr [rbx + 56]
    jne rgio_contract_fail
    cmp rcx, qword ptr [r15 + 88]
    jne rgio_contract_fail
    mov rcx, qword ptr [rdx + 8]
    cmp rcx, 3
    ja rgio_contract_fail
    cmp rcx, 3
    je rgio_dropped_result
    cmp qword ptr [rbx], 100
    jne rgio_contract_fail
    jmp rgio_result_extent
rgio_dropped_result:
    cmp qword ptr [rbx], 0
    jne rgio_contract_fail
    mov rcx, qword ptr [rdx + 16]
    or rcx, qword ptr [rdx + 24]
    or rcx, qword ptr [rdx + 32]
    or rcx, qword ptr [rdx + 40]
    jnz rgio_contract_fail
rgio_result_extent:
    mov rcx, qword ptr [rdx + 32]
    add rcx, qword ptr [rdx + 40]
    jc rgio_contract_fail
    add rcx, 64
    jc rgio_contract_fail
    cmp rcx, qword ptr [r15 + 40]
    ja rgio_contract_fail
    cmp qword ptr [r15 + 72], -1
    jne rgio_contract_fail
    cmp qword ptr [r15 + 80], -1
    jne rgio_contract_fail
    mov qword ptr [r15 + 136], 64
    mov qword ptr [r15 + 144], rcx
    jmp rgio_returned

rgio_admit_effect:
    mov rax, qword ptr [r15 + 48]
    cmp qword ptr [rbx + 8], rax
    jne rgio_contract_fail
    mov rax, qword ptr [r15 + 40]
    cmp qword ptr [rbx + 16], rax
    jne rgio_contract_fail
    mov rax, qword ptr [r15 + 24]
    cmp qword ptr [rbx + 24], rax
    jne rgio_contract_fail
    mov rax, qword ptr [rbx + 40]
    or rax, qword ptr [rbx + 48]
    jnz rgio_contract_fail
    mov rax, qword ptr [rbx + 32]
    cmp rax, 1024
    jb rgio_contract_fail
    lea rcx, [rax - 1]
    test rcx, rax
    jnz rgio_contract_fail
    cmp qword ptr [rbx + 96], rax
    jae rgio_contract_fail
    mov rcx, 3689348814741700403
    cmp rax, rcx
    ja rgio_contract_fail
    lea rax, [rax + rax * 4]
    add rax, 1049600
    jc rgio_contract_fail
    cmp rax, qword ptr [r15 + 24]
    ja rgio_contract_fail
    mov rax, 0x3258464f49445748
    cmp qword ptr [rbx + 512], rax
    jne rgio_contract_fail
    inc qword ptr [r15 + 88]
    jz rgio_contract_fail
    mov rax, qword ptr [r15 + 88]
    cmp qword ptr [rbx + 520], rax
    jne rgio_contract_fail
    cmp qword ptr [rbx + 56], rax
    jne rgio_contract_fail
    mov rax, qword ptr [rbx + 568]
    or rax, qword ptr [rbx + 576]
    or rax, qword ptr [rbx + 584]
    or rax, qword ptr [rbx + 592]
    or rax, qword ptr [rbx + 600]
    or rax, qword ptr [rbx + 608]
    or rax, qword ptr [rbx + 616]
    or rax, qword ptr [rbx + 632]
    jnz rgio_contract_fail
    mov rax, qword ptr [rbx + 624]
    test rax, rax
    jz rgio_contract_fail
    cmp rax, qword ptr [rbx + 640]
    jne rgio_contract_fail
    mov r14, qword ptr [rbx + 528]
    cmp r14, 1
    je rgio_get_current
    cmp r14, 2
    je rgio_read_link
    cmp r14, 3
    je rgio_access_path
    cmp r14, 4
    je rgio_access_path
    cmp r14, 5
    je rgio_lstat_path
    cmp r14, 6
    je rgio_access_path
    cmp r14, 7
    je rgio_open_parent
    cmp r14, 8
    je rgio_stat_descriptor
    cmp r14, 9
    je rgio_close_descriptor
    cmp r14, 10
    je rgio_get_flags
    cmp r14, 11
    je rgio_set_cloexec
    cmp r14, 12
    je rgio_directory_entries
    cmp r14, 13
    je rgio_rewind_directory
    cmp r14, 14
    je rgio_final_stat
    jmp rgio_contract_fail

rgio_get_current:
    cmp qword ptr [rbx], 10
    jne rgio_contract_fail
    call rgio_resolved_argument
    mov rdx, qword ptr [rbx + 552]
    or rdx, qword ptr [rbx + 560]
    jnz rgio_contract_fail
    mov rsi, qword ptr [rbx + 544]
    cmp rsi, qword ptr [rbx + 152]
    jne rgio_contract_fail
    cmp rsi, 1024
    jb rgio_contract_fail
    cmp rsi, qword ptr [rbx + 32]
    ja rgio_contract_fail
    mov eax, 79
    syscall
    jmp rgio_value_completion

rgio_read_link:
    cmp qword ptr [rbx], 3
    jne rgio_contract_fail
    call rgio_resolved_argument
    mov rcx, qword ptr [rbx + 544]
    cmp rcx, qword ptr [rbx + 96]
    jne rgio_contract_fail
    call rgio_cstring
    mov rax, qword ptr [rbx + 32]
    lea rax, [rax + rax + 1024]
    cmp qword ptr [rbx + 552], rax
    jne rgio_contract_fail
    lea rsi, [rbx + rax]
    mov rdx, qword ptr [rbx + 144]
    cmp rdx, 1024
    jb rgio_contract_fail
    dec rdx
    cmp rdx, qword ptr [rbx + 560]
    jne rgio_contract_fail
    cmp rdx, qword ptr [rbx + 32]
    jae rgio_contract_fail
    mov eax, 89
    syscall
    jmp rgio_value_completion

rgio_access_path:
    cmp qword ptr [rbx], 4
    jne rgio_contract_fail
    call rgio_resolved_argument
    mov rcx, qword ptr [rbx + 96]
    inc rcx
    cmp rcx, qword ptr [rbx + 32]
    jae rgio_contract_fail
    cmp rcx, qword ptr [rbx + 544]
    jne rgio_contract_fail
    call rgio_cstring
    mov rax, qword ptr [rbx + 552]
    or rax, qword ptr [rbx + 560]
    jnz rgio_contract_fail
    mov rsi, rdi
    mov edi, -100
    xor edx, edx
    mov r10d, 512
    mov eax, 439
    cmp r14, 3
    je rgio_access_go
    cmp r14, 4
    jne rgio_stat_access
    cmp qword ptr [r15 + 64], 0
    jne rgio_contract_fail
    mov eax, 269
rgio_access_go:
    syscall
    jmp rgio_zero_completion
rgio_stat_access:
    cmp qword ptr [r15 + 64], 1
    jne rgio_contract_fail
    xor r10d, r10d
    jmp rgio_stat_at

rgio_final_stat:
    cmp qword ptr [rbx], 41
    jne rgio_contract_fail
    call rgio_resolved_argument
    mov rcx, qword ptr [rbx + 96]
    cmp rcx, qword ptr [rbx + 544]
    jne rgio_contract_fail
    call rgio_cstring
    mov rax, qword ptr [rbx + 552]
    or rax, qword ptr [rbx + 560]
    jnz rgio_contract_fail
    mov rsi, rdi
    mov edi, -100
    xor r10d, r10d
    jmp rgio_stat_at

rgio_lstat_path:
    mov rax, qword ptr [rbx]
    cmp rax, 12
    je rgio_lstat_fixed
    cmp rax, 13
    je rgio_lstat_fixed
    cmp rax, 24
    jne rgio_contract_fail
    mov rax, qword ptr [rbx + 32]
    lea rax, [rax + rax * 4 + 1024]
    add rax, qword ptr [rbx + 368]
    jc rgio_contract_fail
    cmp rax, qword ptr [rbx + 536]
    jne rgio_contract_fail
    mov rcx, qword ptr [rbx + 376]
    cmp rcx, qword ptr [rbx + 544]
    jne rgio_contract_fail
    mov rdx, qword ptr [rbx + 552]
    cmp rdx, qword ptr [rbx + 160]
    jne rgio_contract_fail
    jmp rgio_lstat_arguments
rgio_lstat_fixed:
    mov rax, qword ptr [rbx + 32]
    lea rax, [rax + rax + 1024]
    cmp rax, qword ptr [rbx + 536]
    jne rgio_contract_fail
    mov ecx, 1
    cmp qword ptr [rbx + 544], 1
    jne rgio_contract_fail
    cmp qword ptr [rbx + 552], 0
    jne rgio_contract_fail
    xor edx, edx
    cmp qword ptr [rbx], 12
    jne rgio_lstat_root
    cmp byte ptr [rbx + rax], 46
    jne rgio_contract_fail
    jmp rgio_lstat_arguments
rgio_lstat_root:
    cmp byte ptr [rbx + rax], 47
    jne rgio_contract_fail
rgio_lstat_arguments:
    cmp qword ptr [rbx + 560], 0
    jne rgio_contract_fail
    lea rdi, [rbx + rax]
    call rgio_cstring
    mov rsi, rdi
    mov edi, -100
    test rdx, rdx
    jz rgio_lstat_cwd
    call rgio_descriptor
rgio_lstat_cwd:
    mov r10d, 256
rgio_stat_at:
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
    jmp rgio_stat_completion

rgio_open_parent:
    cmp qword ptr [rbx], 15
    jne rgio_contract_fail
    mov rax, qword ptr [rbx + 552]
    or rax, qword ptr [rbx + 560]
    jnz rgio_contract_fail
    mov r12, qword ptr [rbx + 536]
    cmp r12, 1
    jb rgio_contract_fail
    cmp r12, 2
    ja rgio_contract_fail
    cmp qword ptr [r15 + r12 * 8 + 64], -1
    jne rgio_contract_fail
    mov rdx, qword ptr [rbx + 544]
    cmp rdx, qword ptr [rbx + 160]
    jne rgio_contract_fail
    cmp rdx, r12
    je rgio_contract_fail
    mov edi, -100
    test rdx, rdx
    jz rgio_open_parent_cwd
    call rgio_descriptor
rgio_open_parent_cwd:
    lea rsi, [rip + rgio_parent_name]
    xor edx, edx
    xor r10d, r10d
    mov eax, 257
    syscall
    mov qword ptr [r15 + 96], rax
    test rax, rax
    js rgio_error_completion
    cmp rax, 0x7fffffff
    ja rgio_contract_fail
    mov qword ptr [r15 + r12 * 8 + 64], rax
    mov rax, r12
    jmp rgio_stored_value_completion

rgio_stat_descriptor:
    mov rax, qword ptr [rbx]
    cmp rax, 16
    je rgio_stat_descriptor_phase
    cmp rax, 18
    jne rgio_contract_fail
rgio_stat_descriptor_phase:
    call rgio_zero_trailing_args
    mov rdx, qword ptr [rbx + 536]
    cmp rdx, qword ptr [rbx + 168]
    jne rgio_contract_fail
    call rgio_descriptor
    mov r13, rdi
    mov rdi, rsp
    xor eax, eax
    mov ecx, 32
    rep stosq
    mov rdi, r13
    mov rsi, rsp
    mov eax, 5
    syscall
rgio_stat_completion:
    mov qword ptr [r15 + 96], rax
    test rax, rax
    js rgio_error_completion
    test rax, rax
    jnz rgio_contract_fail
    mov rax, qword ptr [rsp]
    mov qword ptr [rbx + 584], rax
    mov rax, qword ptr [rsp + 8]
    mov qword ptr [rbx + 592], rax
    mov eax, dword ptr [rsp + 24]
    mov qword ptr [rbx + 600], rax
    mov rax, qword ptr [rsp + 56]
    mov qword ptr [rbx + 616], rax
    jmp rgio_acknowledge

rgio_close_descriptor:
    mov rax, qword ptr [rbx]
    cmp rax, 17
    je rgio_close_phase
    cmp rax, 27
    je rgio_close_phase
    cmp rax, 29
    jne rgio_contract_fail
rgio_close_phase:
    call rgio_zero_trailing_args
    mov rdx, qword ptr [rbx + 536]
    call rgio_descriptor
    mov qword ptr [r15 + rdx * 8 + 64], -1
    mov eax, 3
    syscall
    jmp rgio_zero_completion

rgio_get_flags:
    cmp qword ptr [rbx], 19
    jne rgio_contract_fail
    call rgio_zero_trailing_args
    mov rdx, qword ptr [rbx + 536]
    cmp rdx, qword ptr [rbx + 168]
    jne rgio_contract_fail
    call rgio_descriptor
    mov esi, 3
    xor edx, edx
    mov eax, 72
    syscall
    jmp rgio_value_completion
rgio_set_cloexec:
    cmp qword ptr [rbx], 20
    jne rgio_contract_fail
    call rgio_zero_trailing_args
    mov rdx, qword ptr [rbx + 536]
    cmp rdx, qword ptr [rbx + 168]
    jne rgio_contract_fail
    call rgio_descriptor
    mov esi, 2
    mov edx, 1
    mov eax, 72
    syscall
    jmp rgio_zero_completion

rgio_directory_entries:
    cmp qword ptr [rbx], 22
    jne rgio_contract_fail
    cmp qword ptr [rbx + 560], 0
    jne rgio_contract_fail
    mov rax, qword ptr [rbx + 32]
    lea rax, [rax + rax * 4 + 1024]
    cmp rax, qword ptr [rbx + 544]
    jne rgio_contract_fail
    mov r12, qword ptr [rbx + 552]
    cmp r12, 32768
    jb rgio_contract_fail
    cmp r12, 1048576
    ja rgio_contract_fail
    cmp r12, qword ptr [rbx + 336]
    jne rgio_contract_fail
    lea rsi, [rbx + rax]
    mov rdx, qword ptr [rbx + 536]
    cmp rdx, qword ptr [rbx + 160]
    jne rgio_contract_fail
    call rgio_descriptor
    mov rdx, r12
    mov eax, 217
    syscall
    jmp rgio_value_completion
rgio_rewind_directory:
    cmp qword ptr [rbx], 23
    jne rgio_contract_fail
    call rgio_zero_trailing_args
    mov rdx, qword ptr [rbx + 536]
    cmp rdx, qword ptr [rbx + 160]
    jne rgio_contract_fail
    call rgio_descriptor
    xor esi, esi
    xor edx, edx
    mov eax, 8
    syscall
    jmp rgio_value_completion

rgio_resolved_argument:
    mov rax, qword ptr [rbx + 32]
    add rax, 1024
    cmp qword ptr [rbx + 536], rax
    jne rgio_contract_fail
    lea rdi, [rbx + rax]
    ret
rgio_zero_trailing_args:
    mov rax, qword ptr [rbx + 544]
    or rax, qword ptr [rbx + 552]
    or rax, qword ptr [rbx + 560]
    jnz rgio_contract_fail
    ret
# logical slot in rdx -> real rgio_descriptor in rdi, preserving other arguments.
rgio_descriptor:
    cmp rdx, 1
    jb rgio_contract_fail
    cmp rdx, 2
    ja rgio_contract_fail
    mov rdi, qword ptr [r15 + rdx * 8 + 64]
    test rdi, rdi
    js rgio_contract_fail
    ret
# Exact span containment and unique final NUL.  rdx is preserved for dirfd.
rgio_cstring:
    mov rax, rdi
    sub rax, rbx
    jc rgio_contract_fail
    cmp rax, qword ptr [r15 + 24]
    jae rgio_contract_fail
    mov r11, qword ptr [r15 + 24]
    sub r11, rax
    cmp rcx, r11
    jae rgio_contract_fail
    cmp byte ptr [rdi + rcx], 0
    jne rgio_contract_fail
    xor eax, eax
rgio_cstring_loop:
    cmp rax, rcx
    je rgio_cstring_done
    cmp byte ptr [rdi + rax], 0
    je rgio_contract_fail
    inc rax
    jmp rgio_cstring_loop
rgio_cstring_done:
    ret
rgio_value_completion:
    mov qword ptr [r15 + 96], rax
    test rax, rax
    js rgio_error_completion
rgio_stored_value_completion:
    mov qword ptr [rbx + 568], rax
    jmp rgio_acknowledge
rgio_zero_completion:
    mov qword ptr [r15 + 96], rax
    test rax, rax
    js rgio_error_completion
    test rax, rax
    jnz rgio_contract_fail
    jmp rgio_acknowledge
rgio_error_completion:
    mov qword ptr [r15 + 96], rax
    neg rax
    cmp rax, 4095
    ja rgio_contract_fail
    mov qword ptr [rbx + 576], rax
rgio_acknowledge:
    mov qword ptr [rbx + 608], 1
    mov rax, 0x324b414f49445748
    mov qword ptr [rsp + 256], rax
    mov rax, qword ptr [rbx + 520]
    mov qword ptr [rsp + 264], rax
    mov qword ptr [rsp + 400], rax
    mov rax, qword ptr [rbx + 640]
    mov qword ptr [rsp + 272], rax
    mov rax, qword ptr [rbx]
    mov qword ptr [rsp + 280], rax
    mov rax, qword ptr [rbx + 528]
    mov qword ptr [rsp + 288], rax
    mov rax, qword ptr [rbx + 536]
    mov qword ptr [rsp + 296], rax
    mov rax, qword ptr [rbx + 544]
    mov qword ptr [rsp + 304], rax
    mov rax, qword ptr [rbx + 552]
    mov qword ptr [rsp + 312], rax
    mov rax, qword ptr [rbx + 560]
    mov qword ptr [rsp + 320], rax
    mov rax, qword ptr [r15 + 96]
    mov qword ptr [rsp + 328], rax
    mov rax, qword ptr [rbx + 568]
    mov qword ptr [rsp + 336], rax
    mov rax, qword ptr [rbx + 576]
    mov qword ptr [rsp + 344], rax
    mov rax, qword ptr [rbx + 584]
    mov qword ptr [rsp + 352], rax
    mov rax, qword ptr [rbx + 592]
    mov qword ptr [rsp + 360], rax
    mov rax, qword ptr [rbx + 600]
    mov qword ptr [rsp + 368], rax
    mov rax, qword ptr [rbx + 616]
    mov qword ptr [rsp + 376], rax
    mov rax, qword ptr [r15 + 72]
    mov qword ptr [rsp + 384], rax
    mov rax, qword ptr [r15 + 80]
    mov qword ptr [rsp + 392], rax
    mov qword ptr [rsp + 408], 0
    lea rsi, [rsp + 256]
    mov edx, 160
    call rgio_write_receipt
    jmp rgio_invoke


rgio_grow_workspace:
    mov rdi, [rbx + 40]
    cmp rdi, [rbx + 32]
    jbe rgio_contract_fail
    mov rax, 3689348814741700403
    cmp rdi, rax
    ja rgio_memory_fail
    lea rdi, [rdi + rdi * 4]
    add rdi, 1049600
    jc rgio_memory_fail
    call rgio_round_capacity
    cmp rax, [r15 + 24]
    jbe rgio_invoke
    mov r12, rax
    mov rdi, [r15 + 16]
    mov rsi, [r15 + 24]
    mov rdx, r12
    call view_resize
    cmp rax, -4095
    jae rgio_memory_fail
    mov [r15 + 16], rax
    mov [r15 + 24], r12
    mov rdx, [r15 + 120]
    inc qword ptr [rdx + 136]
    call rgio_sync_descriptor
    mov edi, 2
    call rgio_trace
    jmp rgio_invoke
rgio_grow_output:
    mov rdi, [rbx + 48]
    cmp rdi, [r15 + 40]
    jbe rgio_contract_fail
    call rgio_round_capacity
    mov r12, rax
    mov rdi, [r15 + 32]
    mov rsi, [r15 + 40]
    mov rdx, r12
    call view_resize
    cmp rax, -4095
    jae rgio_memory_fail
    mov [r15 + 32], rax
    mov [r15 + 40], r12
    mov rdx, [r15 + 120]
    inc qword ptr [rdx + 144]
    call rgio_sync_descriptor
    mov edi, 2
    call rgio_trace
    jmp rgio_invoke
rgio_sync_descriptor:
    mov rdx, [r15 + 120]
    mov rdx, [rdx + 8]
    add rdx, 15 * 64
    mov rax, [r15 + 16]
    mov [rdx + 8], rax
    mov rax, [r15 + 24]
    mov [rdx + 16], rax
    mov rax, [r15 + 32]
    mov [rdx + 32], rax
    mov rax, [r15 + 40]
    mov [rdx + 40], rax
    ret
rgio_trace:
    push rbx
    push rbp
    push r15
    mov r15, [r15 + 120]
    mov rbx, [r15 + 8]
    add rbx, 15 * 64
    mov ebp, 15
    call runtime_grow_trace
    pop r15
    pop rbp
    pop rbx
    ret

rgio_refusal:
    mov [r15 + 136], rax
    mov qword ptr [r15 + 144], 0
    mov rsp, [r15 + 152]
    call rgio_cleanup
    jmp rgio_returned
rgio_contract_fail:
    mov eax, 0xfffffff9
    jmp rgio_refusal
rgio_memory_fail:
    mov eax, 0xfffffffc
    jmp rgio_refusal
rgio_io_fail:
    mov eax, 0xfffffffc
    jmp rgio_refusal
rgio_returned:
    call rgio_sync_descriptor
    mov rax, [r15 + 136]
    mov [rdx + 48], rax
    mov rcx, [r15 + 144]
    mov [rdx + 56], rcx
    mov rdx, [r15 + 120]
    mov qword ptr [rdx + 512 + 15 * 64], 0
    jmp rgio_epilogue
rgio_allocation_failed_early:
    mov rdx, [rsp + 536]
    mov eax, 0xfffffffc
    mov [rdx + 48], rax
    mov qword ptr [rdx + 56], 0
    mov qword ptr [r15 + 512 + 15 * 64], 0
rgio_epilogue:
    add rsp, 552
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret

/* Fixture-only receipt sink: default engine creation leaves fd+1 zero. */
rgio_write_receipt:
    cmp qword ptr [r15 + 112], 0
    je rgio_receipt_done
rgio_receipt_more:
    test rdx, rdx
    jz rgio_receipt_done
    mov rdi, [r15 + 112]
    dec rdi
    mov eax, 1
    syscall
    cmp rax, -4
    je rgio_receipt_more
    test rax, rax
    jle rgio_receipt_error
    add rsi, rax
    sub rdx, rax
    jmp rgio_receipt_more
rgio_receipt_error:
    test rax, rax
    jnz rgio_receipt_store
    mov rax, -5
rgio_receipt_store:
    mov rdx, [r15 + 120]
    mov [rdx + 88], rax
rgio_receipt_done:
    ret
rgio_parent_name:
    .asciz ".."

rgio_round_capacity:
    mov rax, rdi
    add rax, 4095
    jc rgio_memory_fail
    and rax, -4096
    test rax, rax
    jz rgio_memory_fail
    mov rdx, 0x7ffffffffffff000
    cmp rax, rdx
    jae rgio_memory_fail
    ret

rgio_cleanup:
    mov rdi, qword ptr [r15 + 72]
    mov qword ptr [r15 + 72], -1
    test rdi, rdi
    js rgio_cleanup_second
    mov eax, 3
    syscall
rgio_cleanup_second:
    mov rdi, qword ptr [r15 + 80]
    mov qword ptr [r15 + 80], -1
    test rdi, rdi
    js rgio_cleanup_done
    mov eax, 3
    syscall
rgio_cleanup_done:
    ret
