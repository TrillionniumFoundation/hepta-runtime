/* Fixture-only complete atomic-effect receipts and logical await barriers.
 * HIA has already chosen the next effect before a barrier is exposed. Every
 * production installation keeps engine+24=0, with no fixture IO. */
.intel_syntax noprefix
.section .text
batch_atomic_observe_effect:
    cmp qword ptr [r15 + 24], 1
    jne batch_atomic_observe_return
    sub rsp, 184
    mov qword ptr [rsp], 7
    mov qword ptr [rsp + 8], 160
    mov rax, 0x3230455441434248
    mov [rsp + 16], rax
    mov rax, [r15 + 176]
    mov [rsp + 24], rax
    mov rax, [r15 + 184]
    mov [rsp + 32], rax
    mov [rsp + 40], rbx
    mov [rsp + 48], r14
    mov [rsp + 56], r13
    mov qword ptr [rsp + 64], 0
    mov qword ptr [rsp + 72], 0
    lea rdi, [rsp + 80]
    lea rsi, [r12 + 256]
    mov ecx, 96
    rep movsb
    mov edi, 1
    mov rsi, rsp
    mov edx, 176
    call view_write_all
    add rsp, 184
    ret
batch_atomic_observe_return:
    xor eax, eax
    ret

/* edx logical stage: 1 metadata, 2 write closure, 3 chmod, 4 rename, 5 unlink. */
batch_atomic_observe_boundary:
    cmp qword ptr [r15 + 24], 1
    jne batch_atomic_observe_return
    sub rsp, 184
    mov [rsp + 176], rdx
    mov qword ptr [rsp], 8
    mov qword ptr [rsp + 8], 160
    mov rax, 0x3230425441434248
    mov [rsp + 16], rax
    mov rax, [r15 + 176]
    mov [rsp + 24], rax
    mov rax, [r15 + 184]
    mov [rsp + 32], rax
    mov [rsp + 40], rdx
    mov rax, [rbp + 136]
    mov [rsp + 48], rax
    mov qword ptr [rsp + 56], 0
    mov qword ptr [rsp + 64], 0
    mov qword ptr [rsp + 72], 0
    lea rdi, [rsp + 80]
    lea rsi, [rbp + 128]
    mov ecx, 96
    rep movsb
    mov edi, 1
    mov rsi, rsp
    mov edx, 176
    call view_write_all
    test rax, rax
    js batch_atomic_observe_boundary_return
    xor edi, edi
    mov rsi, rsp
    mov edx, 32
    call view_read_all
    cmp rax, 1
    jne batch_atomic_observe_boundary_invalid
    mov rax, 0x3230415441434248
    cmp [rsp], rax
    jne batch_atomic_observe_boundary_invalid
    mov rax, [r15 + 176]
    cmp [rsp + 8], rax
    jne batch_atomic_observe_boundary_invalid
    mov rax, [r15 + 184]
    cmp [rsp + 16], rax
    jne batch_atomic_observe_boundary_invalid
    mov rax, [rsp + 176]
    cmp [rsp + 24], rax
    jne batch_atomic_observe_boundary_invalid
    xor eax, eax
    jmp batch_atomic_observe_boundary_return
batch_atomic_observe_boundary_invalid:
    mov rax, -22
batch_atomic_observe_boundary_return:
    add rsp, 184
    ret

batch_atomic_before_next_effect:
    cmp r14, 4
    je batch_atomic_boundary_metadata
    cmp r14, 7
    je batch_atomic_boundary_write
    cmp r14, 8
    je batch_atomic_boundary_write
    xor eax, eax
    ret
batch_atomic_boundary_metadata:
    cmp qword ptr [rbp + 80], 0
    jne batch_atomic_observe_return
    mov qword ptr [rbp + 80], 1
    mov edx, 1
    jmp batch_atomic_observe_boundary
batch_atomic_boundary_write:
    cmp qword ptr [rbp + 80], 1
    jne batch_atomic_observe_return
    mov qword ptr [rbp + 80], 2
    mov edx, 2
    jmp batch_atomic_observe_boundary

batch_atomic_after_effect:
    sub rsp, 8
    lea rdi, [rbp + 128]
    lea rsi, [r12 + 256]
    mov ecx, 96
    rep movsb
    call batch_atomic_observe_effect
    test rax, rax
    js batch_atomic_after_return
    cmp r14, 7
    je batch_atomic_after_permissions
    cmp r14, 8
    je batch_atomic_after_rename
    cmp r14, 9
    je batch_atomic_after_unlink
    xor eax, eax
    add rsp, 8
    ret
batch_atomic_after_permissions:
    add rsp, 8
    mov edx, 3
    jmp batch_atomic_observe_boundary
batch_atomic_after_rename:
    add rsp, 8
    mov edx, 4
    jmp batch_atomic_observe_boundary
batch_atomic_after_unlink:
    add rsp, 8
    mov edx, 5
    jmp batch_atomic_observe_boundary
batch_atomic_after_return:
    add rsp, 8
    ret

batch_atomic_observe_terminal:
    /* Preserve the original owner return across fixture IO. */
    push rax
    cmp eax, 32
    jb batch_atomic_terminal_done
    cmp eax, 0xffff0000
    jae batch_atomic_terminal_done
    mov rax, [rbp]
    mov rax, [rax + 24]
    mov rdx, 0x3130305257415248
    cmp [rax], rdx
    jne batch_atomic_terminal_done
    cmp qword ptr [rax + 8], 1
    jne batch_atomic_terminal_done
    cmp qword ptr [rax + 16], 1
    je batch_atomic_terminal_metadata
    cmp qword ptr [rax + 16], 2
    jne batch_atomic_terminal_done
    call batch_atomic_boundary_write
    jmp batch_atomic_terminal_checked
batch_atomic_terminal_metadata:
    call batch_atomic_boundary_metadata
batch_atomic_terminal_checked:
    test rax, rax
    jns batch_atomic_terminal_done
    pop rax
    jmp batch_atomic_worker_contract
batch_atomic_terminal_done:
    pop rax
    ret
