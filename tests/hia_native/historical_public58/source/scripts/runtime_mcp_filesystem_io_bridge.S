/* Callable boundary for the unchanged filesystem_parity HIA owner.
 * Actual syscall admission/ACK closure below is imported with label renaming.
 * Extra slot 24 owns its buffers; engine+200 owns only this guarded control.
 * Input is borrowed for this synchronous call. No public descriptor selectors. */
.intel_syntax noprefix
.section .text
.global runtime_grow_fs_io_owned
.equ RGFS_SLOT, 24
runtime_grow_fs_io_owned:
    push rbp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub rsp, 40
    mov [rsp], rdi
    mov [rsp + 8], rsi
    mov [rsp + 16], r15
    mov rax, [r15 + 8]
    lea rax, [rax + RGFS_SLOT * 64]
    mov [rsp + 24], rax
    mov qword ptr [r15 + 512 + RGFS_SLOT * 64], 1
    mov rax, [r15 + 200]
    test rax, rax
    jnz rgfs_control_ready
    mov edi, 4096
    call view_allocate
    cmp rax, -4095
    jae rgfs_allocation_failed_early
    mov [r15 + 200], rax
    mov [rax + 168], r15
    mov qword ptr [rax + 72], -1
    mov qword ptr [rax + 80], -1
    mov qword ptr [rax + 88], -1
rgfs_control_ready:
    mov rdx, [r15 + 80]
    mov [rax + 192], rdx
    mov r15, rax
    mov [r15 + 184], rsp
    cmp qword ptr [r15 + 200], 0
    jne rgfs_contract_fail
    cmp qword ptr [r15 + 72], -1
    jne rgfs_contract_fail
    cmp qword ptr [r15 + 80], -1
    jne rgfs_contract_fail
    cmp qword ptr [r15 + 88], -1
    jne rgfs_contract_fail
    mov rbx, [rsp + 24]
    mov rax, [rbx]
    test rax, rax
    jz rgfs_memory_fail
    mov [r15 + 176], rax
    mov rax, [rsp]
    mov [r15], rax
    mov rax, [rsp + 8]
    mov [r15 + 8], rax
    mov [r15 + 48], rax
    cmp qword ptr [r15 + 16], 0
    jne rgfs_allocate_output
    mov edi, 8192
    call view_allocate
    cmp rax, -4095
    jae rgfs_memory_fail
    mov [r15 + 16], rax
    mov qword ptr [r15 + 24], 8192
    mov rdx, [r15 + 168]
    bts qword ptr [rdx + 64], RGFS_SLOT
rgfs_allocate_output:
    cmp qword ptr [r15 + 32], 0
    jne rgfs_storage_ready
    mov edi, 4096
    call view_allocate
    cmp rax, -4095
    jae rgfs_memory_fail
    mov [r15 + 32], rax
    mov qword ptr [r15 + 40], 4096
    mov rdx, [r15 + 168]
    bts qword ptr [rdx + 72], RGFS_SLOT
rgfs_storage_ready:
    call rgfs_sync_descriptor
rgfs_invoke:
    mov rax, [r15 + 168]
    inc qword ptr [rax + 128]
    jz rgfs_contract_fail
    inc qword ptr [r15 + 112]
    jz rgfs_contract_fail
    mov rdi, [r15]
    mov rsi, [r15 + 48]
    mov rdx, [r15 + 32]
    mov rcx, [r15 + 40]
    mov r8, [r15 + 16]
    mov r9, [r15 + 24]
    call qword ptr [r15 + 176]
    mov edx, eax
    cmp rax, rdx
    jne rgfs_contract_fail
    mov [r15 + 120], rax
    mov edi, 1
    call rgfs_trace
    mov rbx, [r15 + 16]
    call rgfs_native_receipt
    mov rax, [r15 + 120]
    cmp eax, 0xffffffef
    je rgfs_grow_workspace
    cmp eax, 0xffffffee
    je rgfs_grow_output
    cmp eax, 0xfffffff0
    je rgfs_admit_effect
    cmp eax, 0xffffffff
    je rgfs_native_refusal
    cmp eax, 0xfffffffe
    je rgfs_native_refusal
    cmp eax, 0xfffffff9
    je rgfs_native_refusal
    cmp eax, 80
    jne rgfs_contract_fail
    mov rdx, [r15 + 32]
    mov rcx, 0x3230304f50534648
    cmp [rdx], rcx
    jne rgfs_contract_fail
    mov rcx, [rdx + 64]
    cmp rcx, [rbx + 64]
    jne rgfs_contract_fail
    mov rcx, [rdx + 72]
    cmp rcx, [rbx + 56]
    jne rgfs_contract_fail
    cmp rcx, [r15 + 64]
    jne rgfs_contract_fail
    cmp qword ptr [rbx + 280], 0
    jne rgfs_contract_fail
    cmp qword ptr [r15 + 72], -1
    jne rgfs_contract_fail
    cmp qword ptr [r15 + 80], -1
    jne rgfs_contract_fail
    cmp qword ptr [r15 + 88], -1
    jne rgfs_contract_fail
    mov rcx, [rdx + 8]
    cmp rcx, 2
    ja rgfs_contract_fail
    je rgfs_dropped_result
    cmp qword ptr [rbx], 100
    jne rgfs_contract_fail
    mov rcx, [rdx + 16]
    cmp rcx, [rbx + 80]
    jne rgfs_contract_fail
    jmp rgfs_result_extent
rgfs_dropped_result:
    cmp qword ptr [rbx], 0
    jne rgfs_contract_fail
    cmp qword ptr [rdx + 16], 4
    jne rgfs_contract_fail
    mov rcx, [rdx + 24]
    or rcx, [rdx + 32]
    or rcx, [rdx + 40]
    or rcx, [rdx + 48]
    or rcx, [rdx + 56]
    jnz rgfs_contract_fail
rgfs_result_extent:
    mov rcx, [rdx + 48]
    add rcx, [rdx + 56]
    jc rgfs_contract_fail
    add rcx, 80
    jc rgfs_contract_fail
    cmp rcx, [r15 + 40]
    ja rgfs_contract_fail
    mov qword ptr [r15 + 128], 80
    mov [r15 + 136], rcx
    jmp rgfs_returned
rgfs_native_refusal:
    cmp qword ptr [r15 + 72], -1
    jne rgfs_contract_fail
    cmp qword ptr [r15 + 80], -1
    jne rgfs_contract_fail
    cmp qword ptr [r15 + 88], -1
    jne rgfs_contract_fail
    mov [r15 + 128], rax
    mov qword ptr [r15 + 136], 0
    jmp rgfs_returned

rgfs_grow_workspace:
    cmp qword ptr [rbx], 0
    jne rgfs_contract_fail
    cmp qword ptr [r15 + 72], -1
    jne rgfs_contract_fail
    cmp qword ptr [r15 + 80], -1
    jne rgfs_contract_fail
    cmp qword ptr [r15 + 88], -1
    jne rgfs_contract_fail
    mov rdi, [rbx + 40]
    cmp rdi, 1024
    jb rgfs_contract_fail
    lea rax, [rdi - 1]
    test rax, rdi
    jnz rgfs_contract_fail
    mov rax, 4611686018427387391
    cmp rdi, rax
    ja rgfs_memory_fail
    shl rdi, 2
    add rdi, 2048
    jc rgfs_memory_fail
    call rgfs_round_capacity
    cmp rax, [r15 + 24]
    jbe rgfs_contract_fail
    mov r12, rax
    mov rdi, [r15 + 16]
    mov rsi, [r15 + 24]
    mov rdx, r12
    call view_resize
    cmp rax, -4095
    jae rgfs_memory_fail
    mov [r15 + 16], rax
    mov [r15 + 24], r12
    mov rdx, [r15 + 168]
    inc qword ptr [rdx + 136]
    call rgfs_sync_descriptor
    mov edi, 2
    call rgfs_trace
    jmp rgfs_invoke
rgfs_grow_output:
    cmp qword ptr [rbx], 100
    jne rgfs_contract_fail
    cmp qword ptr [rbx + 280], 0
    jne rgfs_contract_fail
    mov rdi, [rbx + 48]
    cmp rdi, [r15 + 40]
    jbe rgfs_contract_fail
    call rgfs_round_capacity
    mov r12, rax
    mov rdi, [r15 + 32]
    mov rsi, [r15 + 40]
    mov rdx, r12
    call view_resize
    cmp rax, -4095
    jae rgfs_memory_fail
    mov [r15 + 32], rax
    mov [r15 + 40], r12
    mov rdx, [r15 + 168]
    inc qword ptr [rdx + 144]
    call rgfs_sync_descriptor
    mov edi, 2
    call rgfs_trace
    jmp rgfs_invoke

rgfs_admit_effect:
    mov rax, qword ptr [r15 + 48]
    cmp qword ptr [rbx + 8], rax
    jne rgfs_contract_fail
    mov rax, qword ptr [r15 + 40]
    cmp qword ptr [rbx + 16], rax
    jne rgfs_contract_fail
    mov rax, qword ptr [r15 + 24]
    cmp qword ptr [rbx + 24], rax
    jne rgfs_contract_fail
    mov rax, qword ptr [rbx + 40]
    or rax, qword ptr [rbx + 48]
    jnz rgfs_contract_fail
    mov rax, 0x3230584650534648
    cmp qword ptr [rbx + 512], rax
    jne rgfs_contract_fail
    mov rax, qword ptr [r15 + 64]
    inc rax
    jz rgfs_contract_fail
    cmp qword ptr [rbx + 520], rax
    jne rgfs_contract_fail
    cmp qword ptr [rbx + 56], rax
    jne rgfs_contract_fail
    mov qword ptr [r15 + 64], rax
    mov rax, qword ptr [rbx + 64]
    test rax, rax
    jz rgfs_contract_fail
    cmp qword ptr [rbx + 528], rax
    jne rgfs_contract_fail
    mov rax, qword ptr [rbx]
    cmp qword ptr [rbx + 376], rax
    jne rgfs_contract_fail
    xor ecx, ecx
rgfs_effect_request_words:
    mov rax, qword ptr [rbx + rcx + 536]
    cmp qword ptr [rbx + rcx + 320], rax
    jne rgfs_contract_fail
    add rcx, 8
    cmp rcx, 56
    jne rgfs_effect_request_words
    mov rax, qword ptr [rbx + 592]
    or rax, qword ptr [rbx + 600]
    or rax, qword ptr [rbx + 608]
    or rax, qword ptr [rbx + 616]
    or rax, qword ptr [rbx + 632]
    jnz rgfs_contract_fail
    mov r14, qword ptr [rbx + 536]
    mov eax, 0
    cmp r14, 5
    sete al
    cmp qword ptr [rbx + 624], rax
    jne rgfs_contract_fail
    call rgfs_physical_mask
    mov rdx, qword ptr [rbx + 280]
    cmp r14, 6
    jne rgfs_effect_mask_ready
    mov rcx, qword ptr [rbx + 544]
    dec rcx
    cmp rcx, 2
    ja rgfs_contract_fail
    mov esi, 1
    shl rsi, cl
    test rdx, rsi
    jnz rgfs_contract_fail
    or rdx, rsi
rgfs_effect_mask_ready:
    cmp rax, rdx
    jne rgfs_contract_fail
    cmp r14, 1
    je rgfs_open_root
    cmp r14, 2
    je rgfs_open_component
    cmp r14, 3
    je rgfs_make_directory
    cmp r14, 4
    je rgfs_stat_source
    cmp r14, 5
    je rgfs_rename_source
    cmp r14, 6
    je rgfs_close_descriptor
    jmp rgfs_contract_fail

rgfs_open_root:
    cmp qword ptr [rbx], 11
    jne rgfs_contract_fail
    mov rax, qword ptr [rbx + 544]
    cmp rax, qword ptr [rbx + 144]
    jne rgfs_contract_fail
    call rgfs_empty_slot
    mov qword ptr [r15 + 104], rax
    cmp qword ptr [rbx + 552], 0x2b0000
    jne rgfs_contract_fail
    mov rax, qword ptr [rbx + 560]
    or rax, qword ptr [rbx + 568]
    or rax, qword ptr [rbx + 576]
    or rax, qword ptr [rbx + 584]
    jnz rgfs_contract_fail
    mov edi, -100
    lea rsi, [rip + rgfs_root_name]
    mov edx, 0x2b0000
    xor r10d, r10d
    mov eax, 257
    syscall
    jmp rgfs_open_completion

rgfs_open_component:
    cmp qword ptr [rbx], 13
    je rgfs_open_component_phase
    cmp qword ptr [rbx], 16
    jne rgfs_contract_fail
rgfs_open_component_phase:
    call rgfs_current_name
    mov qword ptr [r15 + 144], rsi
    mov rax, qword ptr [rbx + 568]
    cmp rax, qword ptr [rbx + 152]
    jne rgfs_contract_fail
    call rgfs_empty_slot
    mov qword ptr [r15 + 104], rax
    cmp qword ptr [rbx + 576], 0x2b0000
    jne rgfs_contract_fail
    cmp qword ptr [rbx + 584], 0
    jne rgfs_contract_fail
    mov rax, qword ptr [rbx + 544]
    call rgfs_slot_fd
    mov rsi, qword ptr [r15 + 144]
    mov edx, 0x2b0000
    xor r10d, r10d
    mov eax, 257
    syscall
    jmp rgfs_open_completion

rgfs_make_directory:
    cmp qword ptr [rbx], 15
    jne rgfs_contract_fail
    cmp qword ptr [rbx + 80], 1
    jne rgfs_contract_fail
    call rgfs_current_name
    mov qword ptr [r15 + 144], rsi
    cmp qword ptr [rbx + 568], 448
    jne rgfs_contract_fail
    mov rax, qword ptr [rbx + 576]
    or rax, qword ptr [rbx + 584]
    jnz rgfs_contract_fail
    mov rax, qword ptr [rbx + 544]
    call rgfs_slot_fd
    mov rsi, qword ptr [r15 + 144]
    mov edx, 448
    mov eax, 258
    syscall
    jmp rgfs_zero_completion

rgfs_stat_source:
    cmp qword ptr [rbx], 31
    jne rgfs_contract_fail
    mov rax, qword ptr [rbx + 544]
    cmp rax, qword ptr [rbx + 160]
    jne rgfs_contract_fail
    mov rax, qword ptr [rbx + 32]
    shl rax, 1
    add rax, 2048
    add rax, qword ptr [rbx + 208]
    cmp rax, qword ptr [rbx + 552]
    jne rgfs_contract_fail
    mov rcx, qword ptr [rbx + 216]
    cmp rcx, qword ptr [rbx + 560]
    jne rgfs_contract_fail
    call rgfs_component_span
    mov qword ptr [r15 + 144], rsi
    cmp qword ptr [rbx + 568], 256
    jne rgfs_contract_fail
    mov rax, qword ptr [rbx + 576]
    or rax, qword ptr [rbx + 584]
    jnz rgfs_contract_fail
    lea rdi, [r15 + 512]
    xor eax, eax
    mov ecx, 18
    rep stosq
    mov rax, qword ptr [rbx + 544]
    call rgfs_slot_fd
    mov rsi, qword ptr [r15 + 144]
    lea rdx, [r15 + 512]
    mov r10d, 256
    mov eax, 262
    syscall
    mov qword ptr [r15 + 96], rax
    test rax, rax
    js rgfs_error_completion
    jnz rgfs_contract_fail
    mov eax, dword ptr [r15 + 536]
    mov qword ptr [rbx + 608], rax
    jmp rgfs_completed

rgfs_rename_source:
    cmp qword ptr [rbx], 33
    jne rgfs_contract_fail
    mov rax, qword ptr [rbx + 544]
    cmp rax, qword ptr [rbx + 160]
    jne rgfs_contract_fail
    mov rax, qword ptr [rbx + 568]
    cmp rax, qword ptr [rbx + 168]
    jne rgfs_contract_fail
    mov rax, qword ptr [rbx + 32]
    shl rax, 1
    add rax, 2048
    add rax, qword ptr [rbx + 208]
    cmp rax, qword ptr [rbx + 552]
    jne rgfs_contract_fail
    mov rcx, qword ptr [rbx + 216]
    cmp rcx, qword ptr [rbx + 560]
    jne rgfs_contract_fail
    call rgfs_component_span
    mov qword ptr [r15 + 144], rsi
    mov rax, qword ptr [rbx + 32]
    lea rax, [rax + rax*2 + 2048]
    add rax, qword ptr [rbx + 224]
    cmp rax, qword ptr [rbx + 576]
    jne rgfs_contract_fail
    mov rcx, qword ptr [rbx + 232]
    cmp rcx, qword ptr [rbx + 584]
    jne rgfs_contract_fail
    call rgfs_component_span
    mov qword ptr [r15 + 152], rsi
    mov rax, qword ptr [rbx + 544]
    call rgfs_slot_fd
    mov qword ptr [r15 + 160], rdi
    mov rax, qword ptr [rbx + 568]
    call rgfs_slot_fd
    mov rdx, rdi
    mov rdi, qword ptr [r15 + 160]
    mov rsi, qword ptr [r15 + 144]
    mov r10, qword ptr [r15 + 152]
    mov r8d, 1
    mov eax, 316
    syscall
    jmp rgfs_zero_completion

rgfs_close_descriptor:
    cmp qword ptr [rbx], 14
    je rgfs_close_phase_ready
    cmp qword ptr [rbx], 91
    jne rgfs_contract_fail
rgfs_close_phase_ready:
    mov rax, qword ptr [rbx + 552]
    or rax, qword ptr [rbx + 560]
    or rax, qword ptr [rbx + 568]
    or rax, qword ptr [rbx + 576]
    or rax, qword ptr [rbx + 584]
    jnz rgfs_contract_fail
    mov rax, qword ptr [rbx + 544]
    call rgfs_slot_fd
    mov qword ptr [r15 + rax*8 + 72], -1
    mov eax, 3
    syscall
    jmp rgfs_zero_completion

rgfs_open_completion:
    mov qword ptr [r15 + 96], rax
    test rax, rax
    js rgfs_error_completion
    cmp rax, 2147483647
    ja rgfs_contract_fail
    cmp rax, qword ptr [r15 + 72]
    je rgfs_contract_fail
    cmp rax, qword ptr [r15 + 80]
    je rgfs_contract_fail
    cmp rax, qword ptr [r15 + 88]
    je rgfs_contract_fail
    mov rcx, qword ptr [r15 + 104]
    cmp rcx, 2
    ja rgfs_contract_fail
    cmp qword ptr [r15 + rcx*8 + 72], -1
    jne rgfs_contract_fail
    mov qword ptr [r15 + rcx*8 + 72], rax
    mov qword ptr [rbx + 592], 1
    jmp rgfs_completed
rgfs_zero_completion:
    mov qword ptr [r15 + 96], rax
    test rax, rax
    js rgfs_error_completion
    jnz rgfs_contract_fail
    jmp rgfs_completed
rgfs_error_completion:
    cmp rax, -4095
    jb rgfs_contract_fail
    neg rax
    mov qword ptr [rbx + 600], rax
rgfs_completed:
    mov qword ptr [rbx + 616], 1
    call rgfs_effect_receipt
    jmp rgfs_invoke

rgfs_current_name:
    mov rax, qword ptr [rbx + 544]
    cmp rax, qword ptr [rbx + 144]
    jne rgfs_contract_fail
    mov rax, qword ptr [rbx + 552]
    cmp rax, qword ptr [rbx + 192]
    jne rgfs_contract_fail
    mov rcx, qword ptr [rbx + 560]
    cmp rcx, qword ptr [rbx + 200]
    jne rgfs_contract_fail
    mov rdx, qword ptr [rbx + 32]
    shl rdx, 1
    add rdx, 2048
    mov r8, qword ptr [rbx + 104]
    cmp qword ptr [rbx + 136], 1
    je rgfs_current_region_ready
    cmp qword ptr [rbx + 136], 2
    jne rgfs_contract_fail
    add rdx, qword ptr [rbx + 32]
    mov r8, qword ptr [rbx + 112]
rgfs_current_region_ready:
    add rdx, qword ptr [rbx + 176]
    jc rgfs_contract_fail
    cmp rax, rdx
    jne rgfs_contract_fail
    mov rdx, qword ptr [rbx + 176]
    add rdx, rcx
    jc rgfs_contract_fail
    inc rdx
    jz rgfs_contract_fail
    cmp rdx, qword ptr [rbx + 184]
    jne rgfs_contract_fail
    cmp rdx, r8
    ja rgfs_contract_fail
    jmp rgfs_component_span

# rax = workspace-relative CString start; rcx = exact non-NUL length.
# Return rsi = real CString pointer. Every component stays inside a parsed
# path region, has a preceding delimiter, and contains neither slash nor NUL.
rgfs_component_span:
    test rcx, rcx
    jz rgfs_contract_fail
    mov r8, qword ptr [rbx + 32]
    cmp r8, 1024
    jb rgfs_contract_fail
    lea r9, [r8 - 1]
    test r9, r8
    jnz rgfs_contract_fail
    mov r9, 4611686018427387391
    cmp r8, r9
    ja rgfs_contract_fail
    lea r9, [r8*4 + 2048]
    cmp r9, qword ptr [r15 + 24]
    ja rgfs_contract_fail
    lea r9, [r8*2 + 2048]
    cmp rax, r9
    jb rgfs_contract_fail
    lea r10, [r9 + r8]
    cmp rax, r10
    jae rgfs_destination_span
    mov rdx, qword ptr [rbx + 104]
    jmp rgfs_span_region_ready
rgfs_destination_span:
    mov r9, r10
    mov rdx, qword ptr [rbx + 112]
rgfs_span_region_ready:
    cmp rdx, r8
    ja rgfs_contract_fail
    add rdx, r9
    jc rgfs_contract_fail
    mov r10, rax
    add r10, rcx
    jc rgfs_contract_fail
    cmp r10, rdx
    jae rgfs_contract_fail
    cmp byte ptr [rbx + r10], 0
    jne rgfs_contract_fail
    cmp rax, r9
    je rgfs_span_start_ready
    cmp byte ptr [rbx + rax - 1], 0
    jne rgfs_contract_fail
rgfs_span_start_ready:
    lea rsi, [rbx + rax]
    xor edx, edx
rgfs_span_bytes:
    movzx eax, byte ptr [rsi + rdx]
    test eax, eax
    jz rgfs_contract_fail
    cmp eax, 47
    je rgfs_contract_fail
    inc rdx
    cmp rdx, rcx
    jb rgfs_span_bytes
    cmp byte ptr [rsi], 46
    jne rgfs_span_valid
    cmp rcx, 1
    je rgfs_contract_fail
    cmp rcx, 2
    jne rgfs_span_valid
    cmp byte ptr [rsi + 1], 46
    je rgfs_contract_fail
rgfs_span_valid:
    ret

rgfs_slot_fd:
    dec rax
    cmp rax, 2
    ja rgfs_contract_fail
    mov rdi, qword ptr [r15 + rax*8 + 72]
    cmp rdi, 2147483647
    ja rgfs_contract_fail
    ret
rgfs_empty_slot:
    dec rax
    cmp rax, 2
    ja rgfs_contract_fail
    cmp qword ptr [r15 + rax*8 + 72], -1
    jne rgfs_contract_fail
    ret
rgfs_physical_mask:
    xor eax, eax
    xor ecx, ecx
rgfs_physical_mask_loop:
    cmp qword ptr [r15 + rcx*8 + 72], -1
    je rgfs_physical_mask_next
    mov edx, 1
    shl rdx, cl
    or rax, rdx
rgfs_physical_mask_next:
    inc rcx
    cmp rcx, 3
    jne rgfs_physical_mask_loop
    ret

rgfs_native_receipt:
    mov rax, 0x32304c4350534648
    mov qword ptr [r15 + 256], rax
    mov rax, qword ptr [r15 + 112]
    mov qword ptr [r15 + 264], rax
    mov rax, qword ptr [r15 + 120]
    mov qword ptr [r15 + 272], rax
    mov rax, qword ptr [rbx]
    mov qword ptr [r15 + 280], rax
    mov rax, qword ptr [rbx + 64]
    mov qword ptr [r15 + 288], rax
    mov rax, qword ptr [rbx + 56]
    mov qword ptr [r15 + 296], rax
    mov rax, qword ptr [r15 + 48]
    mov qword ptr [r15 + 304], rax
    mov rax, qword ptr [r15 + 40]
    mov qword ptr [r15 + 312], rax
    mov rax, qword ptr [r15 + 24]
    mov qword ptr [r15 + 320], rax
    mov rax, qword ptr [rbx + 280]
    mov qword ptr [r15 + 328], rax
    lea rsi, [r15 + 256]
    mov edx, 80
    mov edi, 2
    jmp rgfs_write_fd_exact
rgfs_effect_receipt:
    mov rax, 0x32304b4150534648
    mov qword ptr [r15 + 256], rax
    mov rax, qword ptr [r15 + 96]
    mov qword ptr [r15 + 264], rax
    mov rax, qword ptr [r15 + 112]
    mov qword ptr [r15 + 272], rax
    mov rax, qword ptr [rbx]
    mov qword ptr [r15 + 280], rax
    mov rax, qword ptr [r15 + 72]
    mov qword ptr [r15 + 288], rax
    mov rax, qword ptr [r15 + 80]
    mov qword ptr [r15 + 296], rax
    mov rax, qword ptr [r15 + 88]
    mov qword ptr [r15 + 304], rax
    mov rax, qword ptr [rbx + 280]
    mov qword ptr [r15 + 312], rax
    lea rdi, [r15 + 320]
    lea rsi, [rbx + 512]
    mov ecx, 16
    rep movsq
    lea rsi, [r15 + 256]
    mov edx, 192
    mov edi, 2
    jmp rgfs_write_fd_exact

rgfs_sync_descriptor:
    mov rdx, [r15 + 168]
    mov rdx, [rdx + 8]
    add rdx, RGFS_SLOT * 64
    mov rax, [r15 + 16]
    mov [rdx + 8], rax
    mov rax, [r15 + 24]
    mov [rdx + 16], rax
    mov rax, [r15 + 32]
    mov [rdx + 32], rax
    mov rax, [r15 + 40]
    mov [rdx + 40], rax
    ret
rgfs_trace:
    push rbx
    push rbp
    push r15
    mov r15, [r15 + 168]
    mov rbx, [r15 + 8]
    add rbx, RGFS_SLOT * 64
    mov ebp, RGFS_SLOT
    call runtime_grow_trace
    pop r15
    pop rbp
    pop rbx
    ret
rgfs_contract_fail:
    mov eax, 0xfffffff9
    jmp rgfs_boundary_failure
rgfs_memory_fail:
    mov eax, 0xfffffffc
    jmp rgfs_boundary_failure
rgfs_io_fail:
    mov eax, 0xfffffffc
rgfs_boundary_failure:
    mov [r15 + 128], rax
    mov qword ptr [r15 + 136], 0
    mov qword ptr [r15 + 200], 1 /* A failed mechanical continuation is retired. */
    mov rsp, [r15 + 184]
    call rgfs_cleanup
rgfs_returned:
    call rgfs_sync_descriptor
    mov rax, [r15 + 128]
    mov [rdx + 48], rax
    mov rcx, [r15 + 136]
    mov [rdx + 56], rcx
    mov rdx, [r15 + 168]
    mov qword ptr [rdx + 512 + RGFS_SLOT * 64], 0
    jmp rgfs_epilogue
rgfs_allocation_failed_early:
    mov rdx, [rsp + 24]
    mov eax, 0xfffffffc
    mov [rdx + 48], rax
    mov qword ptr [rdx + 56], 0
    mov qword ptr [r15 + 512 + RGFS_SLOT * 64], 0
rgfs_epilogue:
    add rsp, 40
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret
rgfs_cleanup:
    push r13
    xor r13d, r13d
rgfs_cleanup_next:
    mov rdi, [r15 + r13 * 8 + 72]
    mov qword ptr [r15 + r13 * 8 + 72], -1
    test rdi, rdi
    js rgfs_cleanup_closed
    mov eax, 3
    syscall
rgfs_cleanup_closed:
    inc r13
    cmp r13, 3
    jb rgfs_cleanup_next
    pop r13
    ret
rgfs_round_capacity:
    mov rax, rdi
    add rax, 4095
    jc rgfs_memory_fail
    and rax, -4096
    test rax, rax
    jz rgfs_memory_fail
    mov rdx, 0x7ffffffffffff000
    cmp rax, rdx
    jae rgfs_memory_fail
    ret
/* The engine's private fixture fd is never selected by the MCP input. */
rgfs_write_fd_exact:
    cmp qword ptr [r15 + 192], 0
    je rgfs_write_done
rgfs_write_more:
    test rdx, rdx
    jz rgfs_write_done
    mov rdi, [r15 + 192]
    dec rdi
    mov eax, 1
    syscall
    cmp rax, -4
    je rgfs_write_more
    test rax, rax
    jle rgfs_write_failure
    add rsi, rax
    sub rdx, rax
    jmp rgfs_write_more
rgfs_write_failure:
    test rax, rax
    jnz rgfs_write_store
    mov rax, -5
rgfs_write_store:
    mov rdx, [r15 + 168]
    mov [rdx + 88], rax
rgfs_write_done:
    ret
rgfs_root_name:
    .asciz "/"
