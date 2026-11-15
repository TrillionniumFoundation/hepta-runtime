/* Fixed three-image Linux boundary. No result, path, policy or checksum
 * semantics are implemented here. The HIA owner retains every decision.
 * SysV create(table[3]) -> engine or -errno; call(engine, borrowed, length)
 * -> eax native return, rdx complete output, rcx extent; destroy(engine).
 * The output borrow lasts until the next call/destroy. One caller at a time. */
.intel_syntax noprefix
.section .text
.macro TXT_ENTER
    push rbp
    mov rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub rsp, 8
.endm
.macro TXT_LEAVE
    add rsp, 8
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret
.endm

/* A successful mapping is owned until explicit munmap. Error returns are
 * Linux negative errno; no fabricated successful allocation. */
txt_map:
    mov rsi, rdi
    xor edi, edi
    mov edx, 3
    mov r10d, 34
    mov r8, -1
    xor r9d, r9d
    mov eax, 9
    syscall
    ret

/* rdi old, rsi exact old capacity, rdx new capacity. Preserve every old byte
 * and the kernel-zeroed new tail. Failed unmap keeps old ownership and frees
 * the new map, retaining the original errno. No saved interior pointers. */
txt_resize:
    TXT_ENTER
    mov r12, rdi
    mov r13, rsi
    mov r14, rdx
    cmp r14, r13
    jbe .Ltxt_resize_invalid
    test r14, r14
    js .Ltxt_resize_resource
    mov rdi, r14
    call txt_map
    cmp rax, -4095
    jae .Ltxt_resize_return
    mov rbx, rax
    mov rdi, rax
    mov rsi, r12
    mov rcx, r13
    rep movsb
    mov rdi, r12
    mov rsi, r13
    mov eax, 11
    syscall
    test rax, rax
    js .Ltxt_resize_unmap_failed
    mov rax, rbx
    jmp .Ltxt_resize_return
.Ltxt_resize_unmap_failed:
    mov r12, rax
    mov rdi, rbx
    mov rsi, r14
    mov eax, 11
    syscall
    mov rax, r12
    jmp .Ltxt_resize_return
.Ltxt_resize_resource:
    mov rax, -12
    jmp .Ltxt_resize_return
.Ltxt_resize_invalid:
    mov rax, -22
.Ltxt_resize_return:
    TXT_LEAVE

.global text_publication_create
text_publication_create:
.Ltext_publication_create:
    TXT_ENTER
    mov r12, rdi
    test r12, r12
    jz .Ltxt_create_invalid
    cmp qword ptr [r12], 0
    je .Ltxt_create_invalid
    cmp qword ptr [r12 + 8], 0
    je .Ltxt_create_invalid
    cmp qword ptr [r12 + 16], 0
    je .Ltxt_create_invalid
    mov edi, 4096
    call txt_map
    cmp rax, -4095
    jae .Ltxt_create_return
    mov r15, rax
    mov rax, 0x32304e4554585448
    mov [r15], rax
    mov rax, [r12]
    mov [r15 + 8], rax
    mov rax, [r12 + 8]
    mov [r15 + 16], rax
    mov rax, [r12 + 16]
    mov [r15 + 24], rax
    mov qword ptr [r15 + 160], -1
    mov qword ptr [r15 + 176], -1
    mov qword ptr [r15 + 192], -1
    mov qword ptr [r15 + 208], -1
    mov edi, 4096
    call txt_map
    cmp rax, -4095
    jae .Ltxt_create_failed
    mov [r15 + 32], rax
    mov qword ptr [r15 + 40], 4096
    mov edi, 64
    call txt_map
    cmp rax, -4095
    jae .Ltxt_create_failed
    mov [r15 + 48], rax
    mov qword ptr [r15 + 56], 64
    mov edi, 64
    call txt_map
    cmp rax, -4095
    jae .Ltxt_create_failed
    mov [r15 + 64], rax
    mov qword ptr [r15 + 72], 64
    mov edi, 1052672
    call txt_map
    cmp rax, -4095
    jae .Ltxt_create_failed
    mov [r15 + 224], rax
    mov qword ptr [r15 + 232], 1052672
    mov rax, r15
    jmp .Ltxt_create_return
.Ltxt_create_failed:
    mov r14, rax
    mov rdi, r15
    call .Ltext_publication_destroy
    mov rax, r14
    jmp .Ltxt_create_return
.Ltxt_create_invalid:
    mov rax, -22
.Ltxt_create_return:
    TXT_LEAVE

.global text_publication_call
text_publication_call:
.Ltext_publication_call:
    TXT_ENTER
    mov r15, rdi
    mov r12, rsi
    mov r13, rdx
    test r15, r15
    jz .Ltxt_call_invalid_pointer
    mov rax, 0x32304e4554585448
    cmp [r15], rax
    jne .Ltxt_call_invalid_pointer
    cmp qword ptr [r15 + 88], 0
    jne .Ltxt_call_invalid_pointer
    cmp qword ptr [r15 + 264], 0
    jne .Ltxt_call_state
    test r13, r13
    js .Ltxt_call_resource
    jz .Ltxt_call_input_ready
    test r12, r12
    jz .Ltxt_call_state
    mov rax, r12
    add rax, r13
    jc .Ltxt_call_state
    cmp r13, [r15 + 72]
    jbe .Ltxt_call_input_ready
    mov rdi, [r15 + 64]
    mov rsi, [r15 + 72]
    mov rdx, r13
    call txt_resize
    cmp rax, -4095
    jae .Ltxt_call_resource
    mov [r15 + 64], rax
    mov [r15 + 72], r13
.Ltxt_call_input_ready:
    mov rdi, [r15 + 64]
    mov rsi, r12
    mov rcx, r13
    rep movsb
    mov [r15 + 80], r13
    mov qword ptr [r15 + 88], 1
    /* Retire an already requested output growth before resuming the identical
     * completed request. HIA rejects its former short output span. Different
     * input, including terminal DROP, still goes through HIA admission. */
    mov r14, [r15 + 256]
    test r14, r14
    jz .Ltxt_call_again
    mov rbx, [r15 + 32]
    cmp qword ptr [rbx], 100
    jne .Ltxt_call_poison
    cmp [rbx + 48], r14
    jne .Ltxt_call_poison
    cmp r13, [rbx + 8]
    jne .Ltxt_call_again
    mov rax, [r15 + 40]
    sub rax, 4096
    jc .Ltxt_call_poison
    cmp r13, rax
    ja .Ltxt_call_poison
    mov rdi, [r15 + 64]
    lea rsi, [rbx + 4096]
    mov rcx, r13
    repe cmpsb
    jne .Ltxt_call_again
    jmp .Ltxt_call_output_grow
.Ltxt_call_again:
    mov rdi, [r15 + 64]
    mov rsi, [r15 + 80]
    mov rdx, [r15 + 48]
    mov rcx, [r15 + 56]
    mov r8, [r15 + 32]
    mov r9, [r15 + 40]
    call qword ptr [r15 + 8]
    mov eax, eax
    mov [r15 + 112], rax
    cmp eax, 0xffffffef
    je .Ltxt_call_grow
    cmp eax, 0xffffffee
    je .Ltxt_call_output_grow
    cmp eax, 0xfffffff0
    je .Ltxt_call_effect
    mov rbx, [r15 + 32]
    cmp qword ptr [rbx + 48], 0
    jne .Ltxt_call_pending_kept
    mov qword ptr [r15 + 256], 0
.Ltxt_call_pending_kept:
    cmp qword ptr [r15 + 136], 0
    jne .Ltxt_call_poison
    cmp eax, 0xffff0000
    jae .Ltxt_call_no_body
    cmp rax, [r15 + 56]
    ja .Ltxt_call_poison
    mov [r15 + 120], rax
    jmp .Ltxt_call_done
.Ltxt_call_no_body:
    mov qword ptr [r15 + 120], 0
    jmp .Ltxt_call_done
.Ltxt_call_grow:
    cmp qword ptr [r15 + 136], 0
    jne .Ltxt_call_poison
    mov rbx, [r15 + 32]
    cmp qword ptr [rbx], 0
    jne .Ltxt_call_poison
    mov r14, [rbx + 40]
    cmp r14, [r15 + 40]
    jbe .Ltxt_call_poison
    mov rdi, rbx
    mov rsi, [r15 + 40]
    mov rdx, r14
    call txt_resize
    cmp rax, -4095
    jae .Ltxt_call_resource
    mov [r15 + 32], rax
    mov [r15 + 40], r14
    jmp .Ltxt_call_again
.Ltxt_call_output_grow:
    cmp qword ptr [r15 + 136], 0
    jne .Ltxt_call_poison
    mov rbx, [r15 + 32]
    cmp qword ptr [rbx], 100
    jne .Ltxt_call_poison
    mov r14, [rbx + 48]
    cmp r14, [r15 + 56]
    jbe .Ltxt_call_poison
    mov [r15 + 256], r14
    mov rdi, [r15 + 48]
    mov rsi, [r15 + 56]
    mov rdx, r14
    call txt_resize
    cmp rax, -4095
    jae .Ltxt_call_resource
    mov [r15 + 48], rax
    mov [r15 + 56], r14
    mov qword ptr [r15 + 256], 0
    jmp .Ltxt_call_again
.Ltxt_call_effect:
    call txt_dispatch_effect
    test rax, rax
    jnz .Ltxt_call_poison
    call txt_effect_trace
    test rax, rax
    jnz .Ltxt_call_poison
    jmp .Ltxt_call_again
.Ltxt_call_poison:
    mov qword ptr [r15 + 264], 1
    call txt_close_owned
.Ltxt_call_state:
    mov eax, 0xfffffff9
    mov [r15 + 112], rax
    mov qword ptr [r15 + 120], 0
    jmp .Ltxt_call_done
.Ltxt_call_resource:
    mov eax, 0xfffffffc
    mov [r15 + 112], rax
    mov qword ptr [r15 + 120], 0
.Ltxt_call_done:
    mov qword ptr [r15 + 88], 0
    mov eax, [r15 + 112]
    mov rdx, [r15 + 48]
    mov rcx, [r15 + 120]
    TXT_LEAVE
.Ltxt_call_invalid_pointer:
    mov eax, 0xfffffff9
    xor edx, edx
    xor ecx, ecx
    TXT_LEAVE

/* Closing does not retry EINTR and cannot close an FD from another engine.
 * The Linux descriptor is consumed exactly once before the syscall. */
txt_close_owned:
    TXT_ENTER
    xor r12d, r12d
    xor r13d, r13d
.Ltxt_close_next:
    mov rbx, r12
    shl rbx, 4
    mov rdi, [r15 + rbx + 160]
    test rdi, rdi
    js .Ltxt_close_skip
    mov qword ptr [r15 + rbx + 160], -1
    mov qword ptr [r15 + rbx + 168], 0
    mov eax, 3
    syscall
    test rax, rax
    jns .Ltxt_close_skip
    test r13, r13
    cmovz r13, rax
.Ltxt_close_skip:
    inc r12
    cmp r12, 4
    jb .Ltxt_close_next
    mov qword ptr [r15 + 136], 0
    mov rax, r13
    TXT_LEAVE

.global text_publication_destroy
text_publication_destroy:
.Ltext_publication_destroy:
    TXT_ENTER
    mov r15, rdi
    test r15, r15
    jz .Ltxt_destroy_invalid
    mov rax, 0x32304e4554585448
    cmp [r15], rax
    jne .Ltxt_destroy_invalid
    cmp qword ptr [r15 + 88], 0
    jne .Ltxt_destroy_busy
    call txt_close_owned
    mov r14, rax
    mov r12d, 32
.Ltxt_destroy_map:
    mov rdi, [r15 + r12]
    test rdi, rdi
    jz .Ltxt_destroy_advance
    mov rsi, [r15 + r12 + 8]
    mov eax, 11
    syscall
    test rax, rax
    jns .Ltxt_destroy_advance
    test r14, r14
    cmovz r14, rax
.Ltxt_destroy_advance:
    add r12, 16
    cmp r12, 80
    jb .Ltxt_destroy_map
    cmp r12, 80
    jne .Ltxt_destroy_engine
    mov r12d, 224
    jmp .Ltxt_destroy_map
.Ltxt_destroy_engine:
    mov rdi, r15
    mov esi, 4096
    mov eax, 11
    syscall
    test r14, r14
    cmovnz rax, r14
    TXT_LEAVE
.Ltxt_destroy_invalid:
    mov rax, -22
    TXT_LEAVE
.Ltxt_destroy_busy:
    mov rax, -16
    TXT_LEAVE
