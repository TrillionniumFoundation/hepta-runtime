/* Exact ordinary-file reader HIA with fixed private native FD storage. */
.intel_syntax noprefix
.section .text
.global view_read_invoke
view_read_invoke:
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
    cmp edx, 1
    jb view_reader_install_invalid
    cmp edx, 3
    ja view_reader_install_invalid
    mov ebx, edx
    shl rbx, 6
    add rbx, [r15 + 8]
    mov r12, [rbx + 48]
    test r12, r12
    jnz view_reader_installed
    mov edi, 4096
    call view_allocate
    cmp rax, -4095
    jae view_reader_install_failed
    mov r12, rax
    mov [rbx + 48], rax
    mov qword ptr [r12], -1
view_reader_installed:
    mov rax, [rsp + 8]
    mov [r12 + 40], rax
    mov rax, [rsp + 16]
    mov [r12 + 24], rax
    mov rax, [rbx]
    mov [r12 + 1024], rax
    mov [r12 + 1032], rbx
    mov rax, [rsp]
    mov [r12 + 1040], rax
    mov [r12 + 1048], rsp
    mov r14, [rbx + 8]
    mov r15, [rbx + 16]
    jmp view_reader_native_invoke
view_reader_install_invalid:
    mov eax, 0xffffffff
    jmp view_reader_install_return
view_reader_install_failed:
    mov eax, 0xfffffffc
view_reader_install_return:
    add rsp, 24
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret
view_reader_native_invoke:
    mov rdi, [r12 + 40]
    mov rsi, [r12 + 24]
    lea rdx, [r12 + 256]
    mov ecx, 80
    mov r8, r14
    mov r9, r15
    call qword ptr [r12 + 1024]
    mov edx, eax
    cmp rax, rdx
    jne view_reader_native_invalid
    cmp eax, 0xffffffd0
    je view_reader_native_grow_workspace
    cmp eax, 0xfffffff0
    je view_reader_native_dispatch
    cmp eax, 80
    jne view_reader_native_done
    cmp qword ptr [r12], -1
    jne view_reader_native_invalid
    mov rax, 0x3130305244525648
    cmp [r12 + 256], rax
    jne view_reader_native_invalid
    mov rax, [r12 + 312]
    cmp rax, r15
    ja view_reader_native_invalid
    mov rcx, r15
    sub rcx, rax
    cmp [r12 + 320], rcx
    ja view_reader_native_invalid
    mov eax, 80
    jmp view_reader_native_done
view_reader_native_grow_workspace:
    mov rax, 0x3130304744525648
    cmp [r14 + 640], rax
    jne view_reader_native_invalid
    mov rax, [r12 + 16]
    inc rax
    jz view_reader_native_resource_failure
    cmp [r14 + 648], rax
    jne view_reader_native_invalid
    cmp [r14 + 136], rax
    jne view_reader_native_invalid
    mov [r12 + 16], rax
    mov rax, [r14 + 656]
    cmp rax, r15
    jbe view_reader_native_invalid
    test rax, rax
    js view_reader_native_resource_failure
    mov rdx, r15
view_reader_native_workspace_grow:
    cmp rdx, rax
    jae view_reader_native_workspace_grow_ready
    shl rdx, 1
    jc view_reader_native_resource_failure
    test rdx, rdx
    js view_reader_native_resource_failure
    jmp view_reader_native_workspace_grow
view_reader_native_workspace_grow_ready:
    mov [r12 + 48], rdx
    mov rdi, r14
    mov rsi, r15
    call view_resize
    cmp rax, -4095
    jae view_reader_native_resource_failure
    mov r14, rax
    mov r15, [r12 + 48]
    jmp view_reader_native_invoke

view_reader_native_dispatch:
    cmp qword ptr [r14 + 16], 1
    jne view_reader_native_invalid
    mov rax, 0x3130584644525648
    cmp [r14 + 512], rax
    jne view_reader_native_invalid
    mov rax, [r12 + 8]
    inc rax
    jz view_reader_native_resource_failure
    cmp [r14 + 520], rax
    jne view_reader_native_invalid
    cmp [r14 + 32], rax
    jne view_reader_native_invalid
    mov [r12 + 8], rax
    mov rax, [r14 + 8]
    test rax, rax
    jz view_reader_native_invalid
    cmp [r14 + 528], rax
    jne view_reader_native_invalid
    lea rsi, [r14 + 576]
    mov ecx, 8
view_reader_native_check_completion_zero:
    cmp qword ptr [rsi], 0
    jne view_reader_native_invalid
    add rsi, 8
    loop view_reader_native_check_completion_zero
    mov rax, [r12]
    mov [r12 + 64], rax
    mov rax, [r14 + 536]
    cmp rax, 1
    je view_reader_native_stat_effect
    cmp rax, 2
    je view_reader_native_open_effect
    cmp rax, 3
    je view_reader_native_read_effect
    cmp rax, 4
    je view_reader_native_close_effect
    jmp view_reader_native_invalid
view_reader_native_check_path:
    cmp qword ptr [r14 + 544], 4096
    jne view_reader_native_invalid
    mov rax, [r14 + 552]
    cmp [r14 + 40], rax
    jne view_reader_native_invalid
    mov rcx, r15
    sub rcx, 4097
    cmp rax, rcx
    ja view_reader_native_invalid
    cmp byte ptr [r14 + rax + 4096], 0
    jne view_reader_native_invalid
    ret
view_reader_native_stat_effect:
    cmp qword ptr [r14 + 120], 11
    jne view_reader_native_invalid
    cmp qword ptr [r12], -1
    jne view_reader_native_invalid
    call view_reader_native_check_path
    cmp qword ptr [r14 + 560], 1024
    jne view_reader_native_invalid
    cmp qword ptr [r14 + 568], 144
    jne view_reader_native_invalid
    mov rdi, -100
    lea rsi, [r14 + 4096]
    lea rdx, [r14 + 1024]
    xor r10d, r10d
    mov eax, 262
    syscall
    mov [r12 + 72], rax
    test rax, rax
    js view_reader_native_effect_error
    jnz view_reader_native_invalid
    mov eax, dword ptr [r14 + 1048]
    mov [r14 + 608], rax
    mov rax, [r14 + 1072]
    mov [r14 + 616], rax
    xor eax, eax
    jmp view_reader_native_effect_complete
view_reader_native_open_effect:
    cmp qword ptr [r14 + 120], 21
    jne view_reader_native_invalid
    cmp qword ptr [r12], -1
    jne view_reader_native_invalid
    call view_reader_native_check_path
    cmp qword ptr [r14 + 560], 524288
    jne view_reader_native_invalid
    cmp qword ptr [r14 + 568], 0
    jne view_reader_native_invalid
    mov rdi, -100
    lea rsi, [r14 + 4096]
    mov edx, 524288
    xor r10d, r10d
    mov eax, 257
    syscall
    mov [r12 + 72], rax
    test rax, rax
    js view_reader_native_effect_error
    mov [r12], rax
    xor eax, eax
    jmp view_reader_native_effect_complete
view_reader_native_read_effect:
    cmp qword ptr [r14 + 120], 31
    jne view_reader_native_invalid
    cmp qword ptr [r14 + 104], 1
    jne view_reader_native_invalid
    cmp qword ptr [r14 + 544], 0
    jne view_reader_native_invalid
    cmp qword ptr [r14 + 560], 65536
    jne view_reader_native_invalid
    cmp qword ptr [r14 + 568], 0
    jne view_reader_native_invalid
    mov rsi, [r14 + 48]
    add rsi, [r14 + 56]
    jc view_reader_native_invalid
    cmp [r14 + 552], rsi
    jne view_reader_native_invalid
    mov rax, r15
    sub rax, 65536
    cmp rsi, rax
    ja view_reader_native_invalid
    add rsi, r14
    mov rdi, [r12]
    test rdi, rdi
    js view_reader_native_invalid
    mov edx, 65536
    xor eax, eax
    syscall
    mov [r12 + 72], rax
    test rax, rax
    js view_reader_native_effect_error
    cmp rax, 65536
    ja view_reader_native_invalid
    jmp view_reader_native_effect_complete
view_reader_native_close_effect:
    cmp qword ptr [r14 + 120], 41
    jne view_reader_native_invalid
    cmp qword ptr [r14 + 104], 1
    jne view_reader_native_invalid
    lea rsi, [r14 + 544]
    mov ecx, 4
view_reader_native_check_close_args:
    cmp qword ptr [rsi], 0
    jne view_reader_native_invalid
    add rsi, 8
    loop view_reader_native_check_close_args
    mov rdi, [r12]
    test rdi, rdi
    js view_reader_native_invalid
    mov qword ptr [r12], -1
    mov eax, 3
    syscall
    mov [r12 + 72], rax
    test rax, rax
    js view_reader_native_effect_error
    jnz view_reader_native_invalid
    jmp view_reader_native_effect_complete
view_reader_native_effect_error:
    cmp rax, -4095
    jb view_reader_native_invalid
    mov rdx, rax
    neg rdx
    mov [r14 + 600], rdx
view_reader_native_effect_complete:
    mov [r14 + 592], rax
    mov rax, [r14 + 520]
    mov [r14 + 576], rax
    mov rax, [r14 + 528]
    mov [r14 + 584], rax
    call view_reader_native_receipt
    jmp view_reader_native_invoke

view_reader_native_receipt:
    mov rax, [r12 + 1040]
    cmp qword ptr [rax + 96], 1
    jne view_reader_native_receipt_disabled
    lea rdi, [r12 + 768]
    mov rax, 0x314b434144525648
    mov [rdi], rax
    lea rsi, [r14 + 520]
    add rdi, 8
    mov ecx, 7
    cld
    rep movsq
    mov rax, [r12 + 72]
    mov [r12 + 832], rax
    lea rsi, [r14 + 592]
    lea rdi, [r12 + 840]
    mov ecx, 4
    rep movsq
    mov rax, [r12 + 64]
    mov [r12 + 872], rax
    mov rax, [r12]
    mov [r12 + 880], rax
    mov rax, [r14 + 520]
    mov [r12 + 888], rax
    mov edi, 2
    lea rsi, [r12 + 768]
    mov edx, 128
    call view_write_all
    test rax, rax
    js view_reader_native_io_failure
view_reader_native_receipt_disabled:
    ret

view_reader_native_invalid:
    mov eax, 0xffffffff
    jmp view_reader_native_done
view_reader_native_resource_failure:
    mov eax, 0xfffffffc
    jmp view_reader_native_done
view_reader_native_io_failure:
    mov eax, 0xfffffffb
view_reader_native_done:
    mov [r12 + 1056], eax
    cmp eax, 80
    je view_reader_native_retain
    mov rdi, [r12]
    mov qword ptr [r12], -1
    test rdi, rdi
    js view_reader_native_retain
    mov eax, 3
    syscall
view_reader_native_retain:
    mov rbx, [r12 + 1032]
    mov [rbx + 8], r14
    mov [rbx + 16], r15
    cmp dword ptr [r12 + 1056], 80
    jne view_reader_native_retained
    mov rdi, [rbx + 24]
    lea rsi, [r12 + 256]
    mov ecx, 10
    rep movsq
view_reader_native_retained:
    mov eax, [r12 + 1056]
    mov [rbx + 40], rax
    mov rsp, [r12 + 1048]
    add rsp, 24
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret
