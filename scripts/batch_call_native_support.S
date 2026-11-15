/* Fixed native boundary for the HIA ordinary view caller. All tool decisions,
 * scope ownership, cache actions, UTF-8 and rendering remain source-owned HIA.
 * This callable engine does not select public sessions or parse JSON-RPC. */
.intel_syntax noprefix
.section .text
.global view_allocate
.global view_resize
.global view_write_all
.global view_read_all
.global view_pure_invoke
.global view_dispatch
.global view_call_run
.global view_engine_create

/* rdi = page-aligned capacity; return guarded zeroed RW mapping or -errno. */
view_allocate:
    push rbx
    mov rbx, rdi
    test rbx, rbx
    jz view_allocate_invalid
    test rbx, 4095
    jnz view_allocate_invalid
    test rbx, rbx
    js view_allocate_invalid
    lea rsi, [rbx + 4096]
    cmp rsi, rbx
    jb view_allocate_invalid
    xor edi, edi
    mov edx, 3
    mov r10d, 34
    mov r8, -1
    xor r9d, r9d
    mov eax, 9
    syscall
    cmp rax, -4095
    jae view_allocate_done
    push rax
    lea rdi, [rax + rbx]
    mov esi, 4096
    xor edx, edx
    mov eax, 10
    syscall
    test rax, rax
    js view_allocate_protection_failed
    pop rax
    jmp view_allocate_done
view_allocate_protection_failed:
    mov r8, rax
    pop rdi
    lea rsi, [rbx + 4096]
    mov eax, 11
    syscall
    mov rax, r8
    jmp view_allocate_done
view_allocate_invalid:
    mov rax, -12
view_allocate_done:
    pop rbx
    ret

/* rdi old mapping, rsi old capacity, rdx larger page-aligned capacity.
 * The old mapping remains intact if allocation fails. No alias crosses call. */
view_resize:
    push rbx
    push r12
    push r13
    push r14
    sub rsp, 8
    mov r12, rdi
    mov r13, rsi
    mov r14, rdx
    cmp r14, r13
    jbe view_resize_invalid
    mov rdi, r14
    call view_allocate
    cmp rax, -4095
    jae view_resize_done
    mov rbx, rax
    mov rdi, rax
    mov rsi, r12
    mov rcx, r13
    cld
    rep movsb
    mov rdi, r12
    lea rsi, [r13 + 4096]
    mov eax, 11
    syscall
    test rax, rax
    js view_resize_unmap_failed
    mov rax, rbx
    jmp view_resize_done
view_resize_unmap_failed:
    mov [rsp], rax
    mov rdi, rbx
    lea rsi, [r14 + 4096]
    mov eax, 11
    syscall
    mov rax, [rsp]
    jmp view_resize_done
view_resize_invalid:
    mov rax, -12
view_resize_done:
    add rsp, 8
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

/* Actual partial writes. Never changes externally shared OFD flags. */
view_write_all:
    sub rsp, 24
    mov [rsp], rdi
view_write_more:
    test rdx, rdx
    jz view_write_done
    mov eax, 1
    syscall
    cmp rax, -4
    je view_write_more
    cmp rax, -11
    je view_write_poll
    test rax, rax
    js view_write_return
    jz view_write_broken
    add rsi, rax
    sub rdx, rax
    jmp view_write_more
view_write_poll:
    mov [rsp + 8], rsi
    mov [rsp + 16], rdx
    shl qword ptr [rsp], 32
    shr qword ptr [rsp], 32
    mov dword ptr [rsp + 4], 4
view_write_poll_again:
    mov rdi, rsp
    mov esi, 1
    mov rdx, -1
    mov eax, 7
    syscall
    cmp rax, -4
    je view_write_poll_again
    test rax, rax
    jle view_write_broken
    mov edi, dword ptr [rsp]
    mov rsi, [rsp + 8]
    mov rdx, [rsp + 16]
    jmp view_write_more
view_write_done:
    xor eax, eax
    jmp view_write_return
view_write_broken:
    mov rax, -5
view_write_return:
    add rsp, 24
    ret

/* Return 1 complete, 0 clean initial EOF, or -errno/truncated frame. */
view_read_all:
    push rbx
    mov rbx, rdx
view_read_more:
    test rdx, rdx
    jz view_read_done
    xor eax, eax
    syscall
    cmp rax, -4
    je view_read_more
    test rax, rax
    js view_read_return
    jz view_read_eof
    add rsi, rax
    sub rdx, rax
    jmp view_read_more
view_read_eof:
    cmp rdx, rbx
    je view_read_return
    mov rax, -5
    jmp view_read_return
view_read_done:
    mov eax, 1
view_read_return:
    pop rbx
    ret

/* Retire through actual reader HIA, retaining the original parent's summary. */
view_reader_retire:
    push rbx
    push r12
    sub rsp, 8
    cmp edx, 1
    jb view_reader_retire_invalid
    cmp edx, 3
    ja view_reader_retire_invalid
    mov ebx, edx
    shl rbx, 6
    add rbx, [r15 + 8]
    mov r12, [rbx + 48]
    test r12, r12
    jz view_reader_retire_invalid
    mov rdi, [rbx + 8]
    cmp qword ptr [rdi + 16], 2
    jne view_reader_retire_invalid
    cmp qword ptr [rdi + 104], 0
    jne view_reader_retire_invalid
    mov rax, [rdi + 8]
    mov [rsp], rax
    lea rdi, [r12 + 1088]
    mov ecx, 8
    xor eax, eax
    rep stosq
    mov rax, 0x3130305144525648
    mov [r12 + 1088], rax
    mov qword ptr [r12 + 1096], 4
    mov rax, [rsp]
    mov [r12 + 1104], rax
    lea rdi, [r12 + 1088]
    mov esi, 64
    lea rdx, [r12 + 1152]
    mov ecx, 80
    mov r8, [rbx + 8]
    mov r9, [rbx + 16]
    call qword ptr [rbx]
    cmp rax, 80
    jne view_reader_retire_invalid
    mov rax, 0x3130305244525648
    cmp [r12 + 1152], rax
    jne view_reader_retire_invalid
    mov rax, [rsp]
    cmp [r12 + 1160], rax
    jne view_reader_retire_invalid
    cmp qword ptr [r12 + 1168], 4
    jne view_reader_retire_invalid
    cmp qword ptr [r12 + 1176], 5
    jne view_reader_retire_invalid
    xor eax, eax
    jmp view_reader_retire_done
view_reader_retire_invalid:
    mov eax, 0xffffffff
view_reader_retire_done:
    add rsp, 8
    pop r12
    pop rbx
    ret

