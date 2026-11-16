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

view_dispatch:
    cmp edx, 1
    jb view_dispatch_invalid
    cmp edx, 3
    jbe view_read_invoke
    cmp edx, 5
    je view_key_invoke
    cmp edx, 6
    je view_scope_invoke
    cmp edx, 7
    je view_scope_invoke
    cmp edx, 12
    je view_regex_dispatch
    jmp view_pure_invoke
view_dispatch_invalid:
    mov eax, 0xffffffff
    ret

view_pure_invoke:
    push rbx
    push r12
    push r13
    push r14
    sub rsp, 8
    mov r12, rdi
    mov r13, rsi
    mov r14d, edx
    cmp edx, 4
    je view_pure_admitted
    cmp edx, 8
    jb view_pure_invalid
    cmp edx, 11
    ja view_pure_invalid
view_pure_admitted:
    mov ebx, r14d
    shl rbx, 6
    add rbx, [r15 + 8]
view_pure_retry:
    mov rdi, r12
    mov rsi, r13
    mov rdx, [rbx + 24]
    mov rcx, [rbx + 32]
    mov r8, [rbx + 8]
    mov r9, [rbx + 16]
    call qword ptr [rbx]
    mov edx, eax
    cmp rax, rdx
    jne view_pure_invalid
    cmp eax, 0xffffffd0
    je view_pure_exact_output
    cmp eax, 0xfffffffe
    jne view_pure_return
    cmp r14d, 4
    je view_pure_grow_output
    cmp r14d, 8
    je view_pure_grow_workspace
    cmp r14d, 9
    jne view_pure_return
view_pure_grow_workspace:
    mov rsi, [rbx + 16]
    mov rdx, rsi
    shl rdx, 1
    jc view_pure_resource
    test rdx, rdx
    js view_pure_resource
    mov [rsp], rdx
    mov rdi, [rbx + 8]
    call view_resize
    cmp rax, -4095
    jae view_pure_resource
    mov [rbx + 8], rax
    mov rax, [rsp]
    mov [rbx + 16], rax
    jmp view_pure_retry
/* A pure wide endpoint reports its exact required result extent.  Allocate
 * once before retrying the same input; no completed child or I/O is replayed. */
view_pure_exact_output:
    cmp r14d, 4
    jne view_pure_invalid
    cmp r13, 32
    jb view_pure_invalid
    mov rax, 0x3230305045414948 /* HIAEP002 */
    cmp [r12], rax
    jne view_pure_invalid
    cmp qword ptr [rbx + 32], 32
    jb view_pure_invalid
    mov rcx, [rbx + 24]
    mov rax, 0x3230305357524748 /* HGRWS002 */
    cmp [rcx], rax
    jne view_pure_invalid
    cmp qword ptr [rcx + 8], 2
    jne view_pure_invalid
    cmp qword ptr [rcx + 24], 0
    jne view_pure_invalid
    mov rax, [rcx + 16]
    cmp rax, [rbx + 32]
    jbe view_pure_invalid
    test rax, rax
    js view_pure_resource
    mov rdx, [rbx + 32]
view_pure_exact_output_loop:
    cmp rdx, rax
    jae view_pure_output_ready
    shl rdx, 1
    jc view_pure_resource
    test rdx, rdx
    js view_pure_resource
    jmp view_pure_exact_output_loop
view_pure_grow_output:
    mov rsi, [rbx + 32]
    mov rdx, rsi
    shl rdx, 1
    jc view_pure_resource
    test rdx, rdx
    js view_pure_resource
view_pure_output_ready:
    mov rsi, [rbx + 32]
    mov [rsp], rdx
    mov rdi, [rbx + 24]
    call view_resize
    cmp rax, -4095
    jae view_pure_resource
    mov [rbx + 24], rax
    mov rax, [rsp]
    mov [rbx + 32], rax
    jmp view_pure_retry
view_pure_resource:
    mov eax, 0xfffffffc
    jmp view_pure_return
view_pure_invalid:
    mov eax, 0xffffffff
view_pure_return:
    cmp r14d, 12
    jae view_pure_return_unbound
    mov edx, r14d
    shl rdx, 6
    add rdx, [r15 + 8]
    mov [rdx + 40], rax
view_pure_return_unbound:
    add rsp, 8
    pop r14
    pop r13
    pop r12
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

view_call_run:
    push rbp
    push rbx
    push r12
    push r13
    push r14
    sub rsp, 32
    mov r12, rdi
    mov r13, rsi
    mov rbx, [r15 + 8]
    cmp qword ptr [r15 + 32], 0
    jne view_run_invalid
view_run_again:
    mov r14, [rbx + 8]
    mov rdi, r12
    mov rsi, r13
    mov rdx, [rbx + 24]
    mov rcx, [rbx + 32]
    mov r8, r14
    mov r9, [rbx + 16]
    call qword ptr [rbx]
    mov edx, eax
    cmp rax, rdx
    jne view_run_invalid
    cmp eax, 0xffffffd0
    je view_run_grow
    cmp eax, 0xffffffe0
    je view_run_action
    cmp eax, 0xfffffffe
    je view_run_output_capacity
    jmp view_run_done
view_run_grow:
    mov rax, 0x313030474c435648
    cmp [r14 + 640], rax
    jne view_run_invalid
    mov rax, [rbx + 48]
    inc rax
    jz view_run_resource
    cmp [r14 + 648], rax
    jne view_run_invalid
    cmp [r14 + 264], rax
    jne view_run_invalid
    mov [rbx + 48], rax
    mov rax, [r14 + 656]
    cmp rax, [rbx + 16]
    jbe view_run_invalid
    test rax, rax
    js view_run_resource
    mov rdx, [rbx + 16]
view_run_grow_loop:
    cmp rdx, rax
    jae view_run_grow_ready
    shl rdx, 1
    jc view_run_resource
    test rdx, rdx
    js view_run_resource
    jmp view_run_grow_loop
view_run_grow_ready:
    mov [rsp], rdx
    mov rdi, r14
    mov rsi, [rbx + 16]
    call view_resize
    cmp rax, -4095
    jae view_run_resource
    mov [rbx + 8], rax
    mov rdx, [rsp]
    mov [rbx + 16], rdx
    jmp view_run_again
view_run_output_capacity:
    cmp qword ptr [r14 + 16], 92
    jne view_run_done
    mov rax, [r14 + 192]
    add rax, 32
    jc view_run_resource
    cmp rax, [rbx + 32]
    jbe view_run_done
    cmp qword ptr [r14 + 680], 1
    je view_run_output_wide
    mov ecx, 0xffff0000
    cmp rax, rcx
    jae view_run_resource
view_run_output_wide:
    mov rdx, [rbx + 32]
view_run_output_loop:
    cmp rdx, rax
    jae view_run_output_ready
    shl rdx, 1
    jc view_run_resource
    test rdx, rdx
    js view_run_resource
    jmp view_run_output_loop
view_run_output_ready:
    mov [rsp], rdx
    mov rdi, [rbx + 24]
    mov rsi, [rbx + 32]
    call view_resize
    cmp rax, -4095
    jae view_run_resource
    mov [rbx + 24], rax
    mov rdx, [rsp]
    mov [rbx + 32], rdx
    jmp view_run_again
view_run_action:
    mov rax, 0x313058464c435648
    cmp [r14 + 512], rax
    jne view_run_invalid
    mov rax, [rbx + 56]
    inc rax
    jz view_run_resource
    cmp [r14 + 520], rax
    jne view_run_invalid
    cmp [r14 + 32], rax
    jne view_run_invalid
    mov rdx, [r14 + 8]
    cmp [r14 + 528], rdx
    jne view_run_invalid
    mov rcx, [r14 + 576]
    or rcx, [r14 + 584]
    or rcx, [r14 + 592]
    or rcx, [r14 + 600]
    or rcx, [r14 + 624]
    or rcx, [r14 + 632]
    jnz view_run_invalid
    mov [rbx + 56], rax
    mov rax, [r14 + 536]
    cmp rax, 1
    je view_run_child
    cmp rax, 2
    je view_run_copy
    cmp rax, 3
    je view_run_barrier
    jmp view_run_invalid
view_run_child:
    mov rdx, [r14 + 544]
    cmp rdx, 1
    jb view_run_invalid
    cmp rdx, 12
    ja view_run_invalid
    cmp qword ptr [r14 + 568], 1024
    jne view_run_invalid
    cmp qword ptr [r14 + 616], 0
    jne view_run_invalid
    mov rdi, [r14 + 552]
    cmp rdi, [rbx + 16]
    ja view_run_invalid
    mov rax, [rbx + 16]
    sub rax, rdi
    mov rsi, [r14 + 560]
    cmp rsi, rax
    ja view_run_invalid
    add rdi, r14
    call view_dispatch
    cmp eax, 0xfffffffc
    je view_run_done
    cmp eax, 0xfffffffb
    je view_run_done
    mov [rsp], rax
    mov rbp, [r14 + 544]
    shl rbp, 6
    add rbp, [r15 + 8]
    cmp [rbp + 40], rax
    jne view_run_invalid
    lea rdi, [r14 + 2048]
    xor eax, eax
    mov ecx, 128
    rep stosq
    mov rax, [rsp]
    mov qword ptr [rsp + 8], 0
    cmp eax, 0xffff0000
    jae view_run_child_summary_done
    cmp rax, [rbp + 32]
    ja view_run_invalid
    mov ecx, 1024
    cmp rax, rcx
    cmovb rcx, rax
    mov [rsp + 8], rcx
    mov rsi, [rbp + 24]
    lea rdi, [r14 + 2048]
    rep movsb
view_run_child_summary_done:
    cmp qword ptr [r14 + 608], 0
    je view_run_child_retire
    mov rdi, r14
    call view_logical_gate
    test rax, rax
    js view_run_io
    jnz view_run_invalid
view_run_child_retire:
    mov rdx, [r14 + 544]
    cmp rdx, 3
    ja view_run_child_complete
    cmp qword ptr [rsp], 80
    jne view_run_child_complete
    cmp rdx, 1
    je view_run_retire_now
    mov rax, [rbp + 24]
    cmp qword ptr [rax + 24], 0
    je view_run_child_complete
view_run_retire_now:
    call view_reader_retire
    test rax, rax
    jnz view_run_invalid
view_run_child_complete:
    mov rax, [rsp]
    mov rdx, [rsp + 8]
    jmp view_run_complete

view_run_copy:
    mov rbp, [r14 + 544]
    cmp rbp, 1
    jb view_run_invalid
    cmp rbp, 12
    ja view_run_invalid
    shl rbp, 6
    add rbp, [r15 + 8]
    mov rdi, [r14 + 568]
    cmp rdi, [rbx + 16]
    ja view_run_invalid
    mov rax, [rbx + 16]
    sub rax, rdi
    mov rcx, [r14 + 560]
    cmp rcx, rax
    ja view_run_invalid
    add rdi, r14
    mov rsi, [r14 + 552]
    cmp qword ptr [r14 + 616], 0
    je view_run_output_copy
    cmp qword ptr [r14 + 616], 1
    jne view_run_invalid
    cmp qword ptr [r14 + 544], 2
    jb view_run_invalid
    cmp qword ptr [r14 + 544], 3
    ja view_run_invalid
    cmp qword ptr [rbp + 40], 80
    jne view_run_invalid
    mov rax, [rbp + 24]
    cmp qword ptr [rax + 24], 0
    jne view_run_invalid
    mov rdx, [r14 + 608]
    cmp [rax + 8], rdx
    jne view_run_invalid
    cmp [rax + 56], rsi
    jne view_run_invalid
    cmp [rax + 64], rcx
    jne view_run_invalid
    mov rax, [rbp + 8]
    cmp qword ptr [rax + 16], 2
    jne view_run_invalid
    cmp [rax + 8], rdx
    jne view_run_invalid
    mov rdx, [rbp + 16]
    cmp rsi, rdx
    ja view_run_invalid
    sub rdx, rsi
    cmp rcx, rdx
    ja view_run_invalid
    add rsi, rax
    jmp view_run_copy_ready
view_run_output_copy:
    cmp qword ptr [r14 + 608], 0
    jne view_run_invalid
    mov rax, [rbp + 40]
    cmp eax, 0xffff0000
    jae view_run_invalid
    cmp qword ptr [r14 + 544], 4
    jne view_run_copy_extent
    cmp eax, 32
    jne view_run_copy_extent
    mov rdx, [rbp + 24]
    mov r8, 0x3230525045414948 /* HIAEPR02 */
    cmp [rdx], r8
    jne view_run_copy_extent
    cmp qword ptr [r14 + 680], 1
    jne view_run_invalid
    cmp qword ptr [rdx + 8], 0
    jne view_run_copy_extent
    add rax, [rdx + 24]
    jc view_run_invalid
view_run_copy_extent:
    cmp rax, [rbp + 32]
    ja view_run_invalid
    cmp rsi, rax
    ja view_run_invalid
    sub rax, rsi
    cmp rcx, rax
    ja view_run_invalid
    add rsi, [rbp + 24]
view_run_copy_ready:
    mov [rsp + 8], rcx
    rep movsb
    cmp qword ptr [r14 + 616], 1
    jne view_run_copy_complete
    mov rdx, [r14 + 544]
    call view_reader_retire
    test rax, rax
    jnz view_run_invalid
view_run_copy_complete:
    xor eax, eax
    mov rdx, [rsp + 8]
    jmp view_run_complete

view_run_barrier:
    cmp qword ptr [r14 + 544], 0
    jne view_run_invalid
    cmp qword ptr [r14 + 552], 1
    ja view_run_invalid
    cmp qword ptr [r14 + 608], 6
    jne view_run_invalid
    cmp qword ptr [r14 + 616], 0
    jne view_run_invalid
    mov rdi, r14
    call view_logical_gate
    test rax, rax
    js view_run_io
    cmp rax, 1
    ja view_run_invalid
    xor edx, edx
view_run_complete:
    mov [r14 + 592], rax
    mov [r14 + 600], rdx
    mov rax, [r14 + 520]
    mov [r14 + 576], rax
    mov rax, [r14 + 528]
    mov [r14 + 584], rax
    jmp view_run_again
view_run_invalid:
    mov eax, 0xffffffff
    jmp view_run_done
view_run_resource:
    mov eax, 0xfffffffc
    jmp view_run_done
view_run_io:
    mov eax, 0xfffffffb
view_run_done:
    mov [rbx + 40], rax
    add rsp, 32
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret

/* rdi = fixed image address table, rsi = AT_SECURE. Returns private engine. */
view_engine_create:
    xor edx, edx
    jmp view_engine_create_format
.global view_engine_create_wide
view_engine_create_wide:
    mov edx, 1
view_engine_create_format:
    push rbp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub rsp, 24
    mov [rsp + 8], rdx
    mov r12, rdi
    mov r13, rsi
    mov qword ptr [rsp], 0
    mov edi, 4096
    call view_allocate
    cmp rax, -4095
    jae view_engine_create_cleanup
    mov r15, rax
    mov [rsp], rax
    mov [r15], r12
    mov [r15 + 16], r13
    mov edi, 4096
    call view_allocate
    cmp rax, -4095
    jae view_engine_create_cleanup
    mov [r15 + 8], rax
    mov r14, rax
    xor ebp, ebp
view_engine_create_slot:
    mov rax, [r12 + rbp * 8]
    mov [r14], rax
    lea rbx, [rip + view_initial_capacities]
    mov rax, rbp
    shl rax, 4
    add rbx, rax
    mov rdi, [rbx]
    mov [r14 + 16], rdi
    call view_allocate
    cmp rax, -4095
    jae view_engine_create_cleanup
    mov [r14 + 8], rax
    mov rdi, [rbx + 8]
    mov [r14 + 32], rdi
    call view_allocate
    cmp rax, -4095
    jae view_engine_create_cleanup
    mov [r14 + 24], rax
    add r14, 64
    inc rbp
    cmp rbp, 19
    jb view_engine_create_slot
    lea rdi, [rip + view_bound_init_frame]
    cmp qword ptr [rsp + 8], 0
    je view_engine_create_init_ready
    lea rdi, [rip + view_bound_wide_init_frame]
view_engine_create_init_ready:
    mov esi, 16
    call view_call_run
    cmp rax, 32
    jne view_engine_create_failed
    mov rax, r15
    jmp view_engine_create_return
view_engine_create_failed:
    mov rax, -22
view_engine_create_cleanup:
    mov r13, rax
    mov r15, [rsp]
    test r15, r15
    jz view_engine_create_cleanup_done
    call view_engine_free_maps
view_engine_create_cleanup_done:
    mov rax, r13
view_engine_create_return:
    add rsp, 24
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret
.balign 8
view_bound_init_frame:
    .ascii "HVCLI001"
    .quad 1
view_bound_wide_init_frame:
    .ascii "HVCLI002"
    .quad 1
view_initial_capacities:
    .quad 131072, 16777216
    .quad 131072, 4096
    .quad 131072, 4096
    .quad 131072, 4096
    .quad 4096, 4096
    .quad 1056768, 4096
    .quad 33554432, 8388608
    .quad 33554432, 8388608
    .quad 131072, 1052672
    .quad 131072, 16777216
    .quad 33554432, 8388608
    .quad 4096, 4096
    .quad 268435456, 1048576
    .quad 268435456, 134217728
    .quad 268435456, 134217728
    .quad 268435456, 134217728
    .quad 33554432, 4096
    .quad 65536, 172032
    .quad 4096, 134217728

/* Explicit fixture-only scheduler gate. Production installation keeps +24=0.
 * Observed bytes here are qualification output, not public tool publication. */
view_logical_gate:
    cmp qword ptr [r15 + 24], 0
    jne view_logical_enabled
    xor eax, eax
    ret
view_logical_enabled:
    push rbx
    push r12
    push r13
    push r14
    sub rsp, 168
    mov r12, rdi
    mov rax, 0x31304f494c435648
    mov [rsp + 8], rax
    mov rax, [r12 + 528]
    mov [rsp + 16], rax
    mov rax, [r12 + 520]
    mov [rsp + 24], rax
    mov rax, [r12 + 608]
    mov [rsp + 32], rax
    mov rax, [r12 + 544]
    mov [rsp + 40], rax
    mov qword ptr [rsp + 64], 0
    mov qword ptr [rsp + 112], 0
    mov qword ptr [rsp + 120], 0
    cmp qword ptr [r12 + 536], 3
    je view_logical_render
    cmp qword ptr [rsp + 32], 1
    jb view_logical_invalid
    cmp qword ptr [rsp + 32], 5
    ja view_logical_invalid
    cmp rax, 1
    jb view_logical_invalid
    cmp rax, 3
    ja view_logical_invalid
    mov rbx, rax
    shl rbx, 6
    add rbx, [r15 + 8]
    cmp qword ptr [rbx + 40], 80
    jne view_logical_invalid
    mov qword ptr [rsp + 48], 80
    mov r13, [rbx + 24]
    mov r14d, 80
    cmp qword ptr [r13 + 16], 2
    je view_logical_snapshot
    cmp qword ptr [r13 + 16], 5
    jne view_logical_header
view_logical_snapshot:
    cmp qword ptr [r13 + 24], 0
    jne view_logical_header
    mov rax, [r13 + 56]
    cmp rax, [rbx + 16]
    ja view_logical_invalid
    mov rcx, [rbx + 16]
    sub rcx, rax
    mov rdx, [r13 + 64]
    cmp rdx, rcx
    ja view_logical_invalid
    add rax, [rbx + 8]
    mov [rsp + 112], rax
    mov [rsp + 120], rdx
    jmp view_logical_header
view_logical_render:
    mov rbx, [r15 + 8]
    mov r13, [r12 + 560]
    cmp r13, [rbx + 16]
    ja view_logical_invalid
    mov rax, [rbx + 16]
    sub rax, r13
    mov r14, [r12 + 568]
    cmp r14, rax
    ja view_logical_invalid
    add r13, r12
    mov rax, [r12 + 552]
    mov [rsp + 48], rax
view_logical_header:
    mov rax, r14
    add rax, [rsp + 120]
    jc view_logical_invalid
    mov [rsp + 56], rax
    add rax, 64
    jc view_logical_invalid
    mov [rsp], rax
    mov edi, 1
    mov rsi, rsp
    mov edx, 72
    call view_write_all
    test rax, rax
    js view_logical_done
    mov edi, 1
    mov rsi, r13
    mov rdx, r14
    call view_write_all
    test rax, rax
    js view_logical_done
    mov edi, 1
    mov rsi, [rsp + 112]
    mov rdx, [rsp + 120]
    call view_write_all
    test rax, rax
    js view_logical_done
    xor edi, edi
    lea rsi, [rsp + 80]
    mov edx, 32
    call view_read_all
    cmp rax, 1
    jne view_logical_invalid
    mov rax, 0x314b43414c435648
    cmp [rsp + 80], rax
    jne view_logical_invalid
    mov rax, [rsp + 16]
    cmp [rsp + 88], rax
    jne view_logical_invalid
    mov rax, [rsp + 24]
    cmp [rsp + 96], rax
    jne view_logical_invalid
    mov rax, [rsp + 104]
    cmp rax, 1
    ja view_logical_invalid
    test rax, rax
    jz view_logical_done
    cmp qword ptr [rsp + 32], 6
    je view_logical_done
view_logical_invalid:
    mov rax, -22
view_logical_done:
    add rsp, 168
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

/* Release the actual session lease; output mappings keep their own borrow. */
.global view_engine_retire
view_engine_retire:
    push rbx
    mov rbx, [r15 + 8]
    mov rbx, [rbx + 8]
    cmp qword ptr [r15 + 32], 0
    jne view_engine_retire_invalid
    cmp qword ptr [rbx + 16], 1
    jne view_engine_retire_invalid
    cmp qword ptr [rbx + 56], 0
    jne view_engine_retire_invalid
    lea rdi, [r15 + 512]
    xor eax, eax
    mov ecx, 8
    rep stosq
    mov rax, 0x313030514c435248
    mov [r15 + 512], rax
    mov qword ptr [r15 + 520], 3
    mov rax, [rbx + 40]
    mov [r15 + 528], rax
    mov rax, [rbx + 48]
    mov [r15 + 536], rax
    lea rdi, [r15 + 512]
    mov esi, 64
    mov edx, 7
    call view_scope_invoke
    cmp rax, 64
    jne view_engine_retire_invalid
    mov qword ptr [r15 + 32], 1
    xor eax, eax
    pop rbx
    ret
view_engine_retire_invalid:
    mov eax, 0xffffffff
    pop rbx
    ret

/* The trusted parent ends its last output borrow before calling destroy. */
.global view_engine_destroy
view_engine_destroy:
    cmp qword ptr [r15 + 32], 1
    jne view_engine_destroy_invalid
    jmp view_engine_free_maps
view_engine_destroy_invalid:
    mov eax, 0xffffffff
    ret
view_engine_free_maps:
    push rbx
    push rbp
    push r12
    mov r12, [r15 + 8]
    test r12, r12
    jz view_engine_free_private
    mov rbx, r12
    xor ebp, ebp
view_engine_free_slot:
    mov rdi, [rbx + 8]
    mov rsi, [rbx + 16]
    call view_engine_unmap
    mov rdi, [rbx + 24]
    mov rsi, [rbx + 32]
    call view_engine_unmap
    cmp rbp, 1
    jb view_engine_free_slot_next
    cmp rbp, 3
    jbe view_engine_free_slot_control
    cmp rbp, 5
    jne view_engine_free_slot_next
view_engine_free_slot_control:
    mov rdi, [rbx + 48]
    mov esi, 4096
    call view_engine_unmap
view_engine_free_slot_next:
    add rbx, 64
    inc rbp
    cmp rbp, 19
    jb view_engine_free_slot
    mov rdi, r12
    mov esi, 4096
    call view_engine_unmap
view_engine_free_private:
    mov rdi, [r15 + 48]
    mov rsi, [r15 + 56]
    call view_engine_unmap
    mov rdi, [r15 + 72]
    mov rsi, [r15 + 80]
    call view_engine_unmap
    mov rdi, [r15 + 136]
    mov rsi, [r15 + 144]
    call view_engine_unmap
    mov rdi, [r15 + 152]
    mov rsi, [r15 + 160]
    call view_engine_unmap
    mov rdi, r15
    mov esi, 4096
    call view_engine_unmap
    xor eax, eax
    pop r12
    pop rbp
    pop rbx
    ret
view_engine_unmap:
    test rdi, rdi
    jz view_engine_unmap_done
    add rsi, 4096
    mov eax, 11
    syscall
view_engine_unmap_done:
    ret
