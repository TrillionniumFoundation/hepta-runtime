/* Private storage/continuation boundary. HIA owns all application decisions.
 * Fixed extra descriptors: entry, work_ptr, work_cap, sequence,
 * out_ptr, out_cap, return_u32, full_extent. 59 rows at engine+8192; Batch47-52, Authority56, Bellman57 and request registry58.
 * Mechanical records at +512: busy,pending,sequence,child,input_offset,
 * input_len,actual_return,actual_extent. Completed children are not replayed.
 * The separate view engine retains its existing descriptor ABI. */
.intel_syntax noprefix
.section .text
.global runtime_grow_create
.global runtime_grow_destroy
.global runtime_grow_owned
.global runtime_grow_target
.equ RG_SLOTS, 128
.equ RG_ENGINE, 24576
.equ RG_TABLE, 12288
.equ RG_WORK_HIGH, 20480
.equ RG_OUTPUT_HIGH, 20488
.equ RG_HIGH_BYTES, 8
.equ RG_INVALID, 0xffffffff
.equ RG_RESOURCE, 0xfffffffc
.equ RG_CALL, 0xfffffff0
.equ RG_GROW, 0xffffffd0
.equ RG_DELIVERY, 0xffffffcd

/* rdi fixed image table, rsi existing config control or zero. */
runtime_grow_create:
    push rbx
    push r12
    push r13
    mov r12, rdi
    mov r13, rsi
    mov edi, RG_ENGINE
    call view_allocate
    cmp rax, -4095
    jae runtime_grow_create_done
    mov rbx, rax
    mov [rbx], r12
    lea rdx, [rbx + RG_TABLE]
    mov [rbx + 8], rdx
    mov [rbx + 24], r13
    mov rcx, 0x3230474e45475248 /* HRGENG02 */
    mov [rbx + 40], rcx
    test r13, r13
    jz runtime_grow_create_unshared
    mov rcx, [r13 + 904]
    mov [rbx + 32], rcx
    mov rcx, [r13 + 1024] /* The single installed span owner's current borrow. */
    mov [rdx + 11 * 64 + 8], rcx
    mov rcx, [r13 + 1032]
    mov [rdx + 11 * 64 + 16], rcx
runtime_grow_create_unshared:
    xor ecx, ecx
runtime_grow_create_member:
    mov rsi, [r12 + rcx * 8]
    mov [rdx], rsi
    add rdx, 64
    inc ecx
    cmp ecx, RG_SLOTS
    jb runtime_grow_create_member
    mov rdi, rbx
    call runtime_authority_create
    test rax, rax
    jnz runtime_grow_create_authority_failed
    mov rax, rbx
    jmp runtime_grow_create_done
runtime_grow_create_authority_failed:
    mov r13, rax
    mov rdi, rbx
    mov esi, RG_ENGINE + 4096
    mov eax, 11
    syscall
    mov rax, r13
runtime_grow_create_done:
    pop r13
    pop r12
    pop rbx
    ret

/* r15 engine; separately owned view/IO lifetimes must already be retired.
 * Clear allocation bitmap bits denote shared borrows: never unmap those.
 * Failed munmap retains its descriptor for reporting/retrying cleanup. */
runtime_grow_destroy:
    push rbp
    push rbx
    push r12
    push r13
    sub rsp, 8
    mov rax, 0x3230474e45475248
    cmp [r15 + 40], rax
    jne runtime_grow_destroy_invalid
    cmp qword ptr [r15 + 16], 0
    jne runtime_grow_destroy_invalid
    mov rax, [r15 + 208]
    or rax, [r15 + 224]
    jnz runtime_grow_destroy_invalid
    mov rax, [r15 + 192]
    test rax, rax
    jz runtime_grow_destroy_io_admitted
    cmp qword ptr [rax + 72], -1
    jne runtime_grow_destroy_invalid
    cmp qword ptr [rax + 80], -1
    jne runtime_grow_destroy_invalid
runtime_grow_destroy_io_admitted:
    mov rax, [r15 + 200]
    test rax, rax
    jz runtime_grow_destroy_fs_admitted
    cmp qword ptr [rax + 72], -1
    jne runtime_grow_destroy_invalid
    cmp qword ptr [rax + 80], -1
    jne runtime_grow_destroy_invalid
    cmp qword ptr [rax + 88], -1
    jne runtime_grow_destroy_invalid
runtime_grow_destroy_fs_admitted:
    cmp qword ptr [r15 + 416], 0
    jne runtime_grow_destroy_invalid
    /* The process-owned Bellman port must be detached before freeing an engine. */
    mov rax, [r15 + 440]
    or rax, [r15 + 448]
    jnz runtime_grow_destroy_invalid
    xor ebp, ebp
runtime_grow_destroy_admit:
    mov rax, rbp
    shl rax, 6
    cmp qword ptr [r15 + rax + 512], 0
    jne runtime_grow_destroy_invalid
    cmp qword ptr [r15 + rax + 520], 0
    jne runtime_grow_destroy_invalid
    inc ebp
    cmp ebp, RG_SLOTS
    jb runtime_grow_destroy_admit
    call runtime_authority_release
    test rax, rax
    jnz runtime_grow_destroy_done
    xor ebp, ebp
    xor r12d, r12d
    mov rbx, [r15 + 8]
runtime_grow_destroy_slot:
    lea rax, [r15 + 64]
    lea rdx, [r15 + RG_WORK_HIGH - 8]
    cmp rbp, 64
    cmovae rax, rdx
    bt qword ptr [rax], rbp
    jnc runtime_grow_destroy_output
    mov rdi, [rbx + 8]
    mov rsi, [rbx + 16]
    add rsi, 4096
    mov eax, 11
    syscall
    test rax, rax
    js runtime_grow_destroy_work_error
    mov qword ptr [rbx + 8], 0
    mov qword ptr [rbx + 16], 0
    lea rax, [r15 + 64]
    lea rdx, [r15 + RG_WORK_HIGH - 8]
    cmp rbp, 64
    cmovae rax, rdx
    btr qword ptr [rax], rbp
    jmp runtime_grow_destroy_output
runtime_grow_destroy_work_error:
    test r12, r12
    cmovz r12, rax
runtime_grow_destroy_output:
    lea rax, [r15 + 72]
    lea rdx, [r15 + RG_OUTPUT_HIGH - 8]
    cmp rbp, 64
    cmovae rax, rdx
    bt qword ptr [rax], rbp
    jnc runtime_grow_destroy_next
    mov rdi, [rbx + 32]
    mov rsi, [rbx + 40]
    add rsi, 4096
    mov eax, 11
    syscall
    test rax, rax
    js runtime_grow_destroy_output_error
    mov qword ptr [rbx + 32], 0
    mov qword ptr [rbx + 40], 0
    lea rax, [r15 + 72]
    lea rdx, [r15 + RG_OUTPUT_HIGH - 8]
    cmp rbp, 64
    cmovae rax, rdx
    btr qword ptr [rax], rbp
    jmp runtime_grow_destroy_next
runtime_grow_destroy_output_error:
    test r12, r12
    cmovz r12, rax
runtime_grow_destroy_next:
    inc ebp
    add rbx, 64
    cmp ebp, RG_SLOTS
    jb runtime_grow_destroy_slot
    test r12, r12
    jnz runtime_grow_destroy_error
    mov rdi, [r15 + 192]
    test rdi, rdi
    jz runtime_grow_destroy_control
    mov esi, 8192
    mov eax, 11
    syscall
    test rax, rax
    jnz runtime_grow_destroy_done
    mov qword ptr [r15 + 192], 0
runtime_grow_destroy_control:
    mov rdi, [r15 + 200]
    test rdi, rdi
    jz runtime_grow_destroy_engine
    mov esi, 8192
    mov eax, 11
    syscall
    test rax, rax
    jnz runtime_grow_destroy_done
    mov qword ptr [r15 + 200], 0
runtime_grow_destroy_engine:
    mov rdi, r15
    mov esi, RG_ENGINE + 4096
    mov eax, 11
    syscall
    jmp runtime_grow_destroy_done
runtime_grow_destroy_error:
    mov rax, r12
    jmp runtime_grow_destroy_done
runtime_grow_destroy_invalid:
    mov rax, -22
runtime_grow_destroy_done:
    add rsp, 8
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret

/* r15 engine; rdi/rsi input borrow; r8 installed slot. Returns full u32.
 * Output remains owned by descriptor +32; full u64 length is descriptor +56. */
runtime_grow_owned:
    push rbp
    push rbx
    push r12
    push r13
    push r14
    sub rsp, 96
    mov [rsp], rdi
    mov [rsp + 8], rsi
    mov rbp, r8
    cmp rbp, RG_SLOTS
    jae runtime_grow_bad_early
    mov rax, 0x3230474e45475248
    cmp [r15 + 40], rax
    jne runtime_grow_bad_early
    mov rax, rbp
    shl rax, 6
    mov rbx, [r15 + 8]
    add rbx, rax
    lea r12, [r15 + rax + 512]
    cmp qword ptr [r12], 0
    jne runtime_grow_bad_early
    cmp qword ptr [r12 + 8], 0
    jne runtime_grow_bad_early
    cmp ebp, 52
    je runtime_grow_batch_body_dispatch
    cmp ebp, 57
    je runtime_grow_bellman_dispatch
    cmp ebp, 56
    je runtime_grow_authority_dispatch
    cmp ebp, 40
    je runtime_grow_text_body_dispatch
    cmp ebp, 36
    je runtime_grow_text_create_dispatch
    cmp ebp, 12
    je runtime_grow_view_dispatch
    cmp ebp, 15
    je runtime_grow_io_dispatch
    cmp ebp, 24
    je runtime_grow_fs_io_dispatch
    cmp ebp, 28
    je runtime_grow_fence_dispatch
    cmp ebp, 29
    jb runtime_grow_regular_dispatch
    cmp ebp, 32
    jbe runtime_grow_view_proxy_dispatch
runtime_grow_regular_dispatch:
    cmp qword ptr [rbx], 0
    je runtime_grow_resource_early
    mov qword ptr [r12], 1
    mov qword ptr [rbx + 48], 0
    mov qword ptr [rbx + 56], 0
    cmp qword ptr [rbx + 8], 0
    jne runtime_grow_allocate_output
    mov edi, 67108864
    cmp ebp, 55
    je runtime_grow_allocate_work
    mov edi, 100663296
    cmp ebp, 42
    jb runtime_grow_allocate_ordinary_work
    cmp ebp, 44
    jbe runtime_grow_allocate_work
runtime_grow_allocate_ordinary_work:
    mov edi, 4096
    cmp ebp, 4
    jne runtime_grow_allocate_work
    mov edi, 32768
runtime_grow_allocate_work:
    mov [rsp + 24], rdi
    call view_allocate
    cmp rax, -4095
    jae runtime_grow_resource
    mov [rbx + 8], rax
    mov rax, [rsp + 24]
    mov [rbx + 16], rax
    lea rax, [r15 + 64]
    lea rdx, [r15 + RG_WORK_HIGH - 8]
    cmp rbp, 64
    cmovae rax, rdx
    bts qword ptr [rax], rbp
runtime_grow_allocate_output:
    cmp qword ptr [rbx + 32], 0
    jne runtime_grow_resume
    mov edi, 33554432
    cmp ebp, 55
    je runtime_grow_allocate_output_ready
    mov edi, 4096
    cmp ebp, 42
    jb runtime_grow_allocate_output_ready
    cmp ebp, 44
    ja runtime_grow_allocate_output_ready
    mov edi, 67108864
runtime_grow_allocate_output_ready:
    mov [rsp + 24], rdi
    call view_allocate
    cmp rax, -4095
    jae runtime_grow_resource
    mov [rbx + 32], rax
    mov rcx, [rsp + 24]
    mov [rbx + 40], rcx
    lea rax, [r15 + 72]
    lea rdx, [r15 + RG_OUTPUT_HIGH - 8]
    cmp rbp, 64
    cmovae rax, rdx
    bts qword ptr [rax], rbp
runtime_grow_resume:
    /* A new, admitted slot10 call ends the prior output loan. Reserve an
     * input-sized output before the first parse to avoid a known full reparse
     * on ordinary canonical output. This is only a mechanical hint: it is
     * capped at64 MiB, never shrinks, and leaves all HIA-required growth and
     * refusals below/above the hint to the original exact protocol. */
    cmp ebp, 10
    jne runtime_grow_value_hint_done
    mov rdx, [rsp + 8]
    add rdx, 64
    jc runtime_grow_value_hint_done
    cmp rdx, 67108864
    ja runtime_grow_value_hint_done
    cmp rdx, [rbx + 40]
    jbe runtime_grow_value_hint_done
    mov rdi, rbx
    mov esi, 2
    call runtime_grow_resize_borrow
    test eax, eax
    jnz runtime_grow_error
runtime_grow_value_hint_done:
    cmp ebp, 27
    jne runtime_grow_resume_filesystem_caller
    cmp qword ptr [r15 + 232], 0
    jne runtime_grow_resume_installed
    call runtime_filesystem_install_fence
    test eax, eax
    jnz runtime_grow_classify_return
    jmp runtime_grow_resume_installed
runtime_grow_resume_filesystem_caller:
    cmp ebp, 23
    jne runtime_grow_resume_installed
    cmp qword ptr [r15 + 216], 0
    jne runtime_grow_resume_installed
    call runtime_filesystem_install_caller
    test eax, eax
    jnz runtime_grow_error
runtime_grow_resume_installed:
    cmp ebp, 35
    jne runtime_grow_text_installed
    cmp qword ptr [r15 + 240], 0
    jne runtime_grow_text_installed
    call runtime_text_install_caller
    test eax, eax
    jnz runtime_grow_error
runtime_grow_text_installed:
    cmp ebp, 49
    jne runtime_grow_batch_installed
    cmp qword ptr [r15 + 424], 0
    jne runtime_grow_batch_installed
    call runtime_batch_install_caller
    test eax, eax
    jnz runtime_grow_error
runtime_grow_batch_installed:
    cmp ebp, 11
    jne runtime_grow_enter_native
    cmp qword ptr [r15 + 24], 0
    je runtime_grow_bad
    cmp qword ptr [rsp + 8], 24
    jb runtime_grow_bad
    mov rdx, [rsp]
    mov rax, 0x3130514746435248 /* HRCFGQ01 installed read query. */
    cmp [rdx], rax
    jne runtime_grow_bad
    mov rax, [rdx + 8]
    cmp rax, 1
    je runtime_grow_config_query_admitted
    cmp rax, 2
    je runtime_grow_config_query_admitted
    cmp rax, 3
    je runtime_grow_config_query_admitted
    cmp rax, 6
    je runtime_grow_config_query_admitted
    cmp rax, 7
    jb runtime_grow_bad
    cmp rax, 8
    ja runtime_grow_bad
runtime_grow_config_query_admitted:
    mov rcx, [rsp + 8]
    sub rcx, 24
    cmp [rdx + 16], rcx
    jne runtime_grow_bad
    mov rdx, [r15 + 24]
    mov rcx, [rdx + 1032]
    mov rdx, [rdx + 1024]
    test rdx, rdx
    jz runtime_grow_bad
    cmp rcx, 256
    jb runtime_grow_bad
    mov [rbx + 8], rdx
    mov [rbx + 16], rcx
    lea rdx, [rdx + rcx - 256]
    mov qword ptr [rdx + 120], 1
runtime_grow_enter_native:
    mov rdi, [rsp]
    mov rsi, [rsp + 8]
    mov rdx, [rbx + 32]
    mov rcx, [rbx + 40]
    mov r8, [rbx + 8]
    mov r9, [rbx + 16]
    inc qword ptr [r15 + 128]
    cmp ebp, 11
    je runtime_grow_call_config
    cmp ebp, 20
    jne runtime_grow_call_leaf
    call runtime_execution_span
    jmp runtime_grow_called
runtime_grow_call_config:
    call runtime_config_query
    /* Configuration workspace growth is owned by its existing dispatcher.
     * Refresh the shared descriptor before reading state or emitting trace;
     * another session may have moved this same mapping since our last call. */
    mov rdx, [r15 + 24]
    mov rcx, [rdx + 1024]
    mov [rbx + 8], rcx
    mov rcx, [rdx + 1032]
    mov [rbx + 16], rcx
    jmp runtime_grow_called
runtime_grow_call_leaf:
    call qword ptr [rbx]
runtime_grow_called:
    mov edi, 1
    call runtime_grow_trace
runtime_grow_classify_return:
    mov edx, eax
    cmp rax, rdx
    jne runtime_grow_bad
    mov [rbx + 48], rax
    mov qword ptr [rbx + 56], 0
    cmp eax, 0xfffffffe
    jne runtime_grow_classify_result
    cmp ebp, 11
    jne runtime_grow_classify_result
    /* op1/2/7 are installed-state reads without state-setting effects.
     * A short output is retried only for these exact operations. */
    mov rdx, [rsp]
    cmp qword ptr [rdx + 8], 1
    je runtime_grow_config_empty_query
    cmp qword ptr [rdx + 8], 2
    je runtime_grow_config_empty_query
    cmp qword ptr [rdx + 8], 6
    je runtime_grow_config_empty_query
    cmp qword ptr [rdx + 8], 7
    jne runtime_grow_resource
    mov rax, [rdx + 16]
    test rax, rax
    jz runtime_grow_config_output
    cmp rax, 8
    jne runtime_grow_bad
    jmp runtime_grow_config_output
runtime_grow_config_empty_query:
    cmp qword ptr [rdx + 16], 0
    jne runtime_grow_bad
runtime_grow_config_output:
    mov rdx, [rbx + 40]
    inc rdx
    jz runtime_grow_resource
    mov esi, 2
    jmp runtime_grow_resize_requested
runtime_grow_classify_result:
    cmp ebp, 47
    je runtime_grow_text_gateway_result
    cmp ebp, 49
    je runtime_grow_text_gateway_result
    cmp ebp, 50
    je runtime_grow_batch_adapter_result
    cmp ebp, 39
    je runtime_grow_text_gateway_result
    cmp ebp, 37
    je runtime_grow_text_gateway_result
    cmp ebp, 35
    jne runtime_grow_text_classified
runtime_grow_text_gateway_result:
    cmp eax, RG_CALL
    je runtime_grow_action
    cmp eax, RG_GROW
    je runtime_grow_controller_growth
    cmp eax, 0xffff0000
    jae runtime_grow_error
    mov [rbx + 48], rax
    mov r13, [rbx + 32]
    jmp runtime_grow_gateway_result
runtime_grow_text_classified:
    cmp eax, RG_CALL
    je runtime_grow_action
    cmp eax, RG_GROW
    je runtime_grow_controller_growth
    cmp eax, 0xffff0000
    jae runtime_grow_error
    mov r13, [rbx + 32]
    cmp ebp, 0
    je runtime_grow_catalog_result
    cmp ebp, 18
    je runtime_grow_frontend_result
    cmp ebp, 46
    je runtime_grow_text_constructor_result
    cmp ebp, 54
    je runtime_grow_get_info_result
    cmp ebp, 55
    je runtime_grow_connection_result
    cmp ebp, 19
    je runtime_grow_protocol_result
    cmp ebp, 44
    je runtime_grow_protocol_result
    cmp ebp, 45
    je runtime_grow_protocol_result
    cmp ebp, 1
    je runtime_grow_admission_result
    cmp ebp, 10
    je runtime_grow_value_result
    cmp ebp, 48
    je runtime_grow_batch_params_result
    cmp ebp, 51
    je runtime_grow_batch_input_result
    cmp ebp, 38
    je runtime_grow_text_params_result
    cmp ebp, 4
    je runtime_grow_params_result
    cmp ebp, 6
    je runtime_grow_session_result
    cmp ebp, 3
    je runtime_grow_client_result
    cmp ebp, 5
    je runtime_grow_context_result
    cmp ebp, 2
    je runtime_grow_gateway_result
    cmp ebp, 13
    je runtime_grow_gateway_result
    cmp ebp, 21
    je runtime_grow_gateway_result
    cmp ebp, 23
    je runtime_grow_gateway_result
    cmp ebp, 22
    je runtime_grow_filesystem_params_result
    cmp ebp, 25
    je runtime_grow_filesystem_render_result
    cmp ebp, 26
    je runtime_grow_directory_guard_result
    cmp ebp, 27
    je runtime_grow_fence_result
    cmp ebp, 14
    je runtime_grow_workdir_params_result
    cmp ebp, 16
    je runtime_grow_workdir_render_result
    cmp ebp, 15
    je runtime_grow_workdir_io_result
    cmp ebp, 8
    je runtime_grow_canonical_result
    cmp ebp, 7
    je runtime_grow_policy_result
    cmp ebp, 9
    je runtime_grow_path_result
    /* Legacy leaves retain exact u32 output and are never blindly retried. */
    jmp runtime_grow_extent_ready

/* The Batch adapter returns the complete HBBSPR01 extent, not the common
 * gateway's 32-byte header. Keep the exact owner return and validate its own
 * result ABI before making the retained child span available to the caller. */
runtime_grow_batch_adapter_result:
    cmp eax, RG_CALL
    je runtime_grow_action
    cmp eax, RG_GROW
    je runtime_grow_controller_growth
    cmp eax, 0xffff0000
    jae runtime_grow_error
    cmp rax, 32
    jb runtime_grow_bad
    mov [rbx + 48], rax
    mov r13, [rbx + 32]
    mov rdx, 0x3130525053424248
    cmp [r13], rdx
    jne runtime_grow_bad
    cmp qword ptr [r13 + 8], 1
    jne runtime_grow_bad
    cmp qword ptr [r13 + 16], 1
    ja runtime_grow_bad
    mov rdx, rax
    sub rdx, 32
    cmp [r13 + 24], rdx
    jne runtime_grow_bad
    jmp runtime_grow_extent_ready

runtime_grow_filesystem_params_result:
    cmp eax, 64
    jne runtime_grow_bad
    mov rdx, 0x3230525250504648 /* HFPPRR02 */
    cmp [r13], rdx
    jne runtime_grow_bad
    cmp qword ptr [r13 + 56], 0
    jne runtime_grow_bad
    mov rax, [r13 + 8]
    cmp rax, 4
    ja runtime_grow_bad
    je runtime_grow_resource
    cmp rax, 2
    jae runtime_grow_filesystem_params_growth
    cmp qword ptr [r13 + 48], 0
    jne runtime_grow_bad
    mov rax, [r13 + 16]
    dec rax
    cmp rax, 2
    ja runtime_grow_bad
    mov rax, [r13 + 24]
    add rax, [r13 + 32]
    jc runtime_grow_bad
    add rax, [r13 + 40]
    jc runtime_grow_bad
    add rax, 64
    jc runtime_grow_bad
    jmp runtime_grow_extent_ready
runtime_grow_filesystem_params_growth:
    mov rdx, [r13 + 48]
    lea rsi, [rax - 1]
    mov rax, [r13 + 24]
    or rax, [r13 + 32]
    or rax, [r13 + 40]
    jnz runtime_grow_bad
    jmp runtime_grow_resize_requested
runtime_grow_filesystem_render_result:
    cmp eax, 32
    jne runtime_grow_bad
    mov rdx, 0x323052524a504648 /* HFPJRR02 */
    cmp [r13], rdx
    jne runtime_grow_bad
    jmp runtime_grow_status32
runtime_grow_directory_guard_result:
    cmp eax, 48
    jne runtime_grow_bad
    mov rdx, 0x323052474d444648 /* HFDMGR02 */
    cmp [r13], rdx
    jne runtime_grow_bad
    cmp qword ptr [r13 + 8], 1
    ja runtime_grow_bad
    cmp qword ptr [r13 + 40], 0
    jne runtime_grow_bad
    mov rax, [r13 + 24]
    add rax, [r13 + 32]
    jc runtime_grow_bad
    add rax, 48
    jc runtime_grow_bad
    jmp runtime_grow_extent_ready
runtime_grow_fence_result:
    cmp eax, 48
    jne runtime_grow_bad
    mov rdx, 0x3230524546534648 /* HFSFER02 */
    cmp [r13], rdx
    jne runtime_grow_bad
    cmp qword ptr [r13 + 8], 2
    ja runtime_grow_bad
    cmp qword ptr [r13 + 40], 0
    jne runtime_grow_bad
    mov rax, [r13 + 24]
    add rax, 48
    jc runtime_grow_bad
    jmp runtime_grow_extent_ready

runtime_grow_catalog_result:
    cmp eax, 32
    jne runtime_grow_bad
    mov rdx, 0x3230525441435248 /* HRCATR02 */
    cmp [r13], rdx
    jne runtime_grow_bad
    mov rax, [r13 + 8]
    or rax, [r13 + 24]
    jnz runtime_grow_bad
    mov rax, [r13 + 16]
    add rax, 32
    jc runtime_grow_bad
    jmp runtime_grow_extent_ready
runtime_grow_text_constructor_result:
    cmp eax, 64
    jne runtime_grow_bad
    mov rdx, 0x3130535243545248 /* HRTCRS01 */
    cmp [r13], rdx
    jne runtime_grow_bad
    cmp qword ptr [r13 + 8], 0
    jne runtime_grow_bad
    cmp qword ptr [r13 + 16], 1
    ja runtime_grow_bad
    cmp qword ptr [r13 + 24], 2
    ja runtime_grow_bad
    cmp qword ptr [r13 + 32], 64
    jne runtime_grow_bad
    mov rax, [r13 + 48]
    or rax, [r13 + 56]
    jnz runtime_grow_bad
    mov rax, [r13 + 40]
    add rax, 64
    jc runtime_grow_bad
    jmp runtime_grow_extent_ready
runtime_grow_get_info_result:
    cmp eax, 64
    jne runtime_grow_bad
    mov rdx, 0x3130534947545248 /* HRTGIS01 */
    cmp [r13], rdx
    jne runtime_grow_bad
    cmp qword ptr [r13 + 8], 0
    jne runtime_grow_bad
    cmp qword ptr [r13 + 16], 1
    jne runtime_grow_bad
    cmp qword ptr [r13 + 24], 0
    jne runtime_grow_bad
    cmp qword ptr [r13 + 32], 64
    jne runtime_grow_bad
    mov rax, [r13 + 48]
    or rax, [r13 + 56]
    jnz runtime_grow_bad
    mov rax, [r13 + 40]
    add rax, 64
    jc runtime_grow_bad
    jmp runtime_grow_extent_ready
runtime_grow_frontend_result:
    cmp eax, 64
    jne runtime_grow_bad
    mov rdx, 0x323052464d435248 /* HRCMFR02 */
    cmp [r13], rdx
    jne runtime_grow_bad
    cmp qword ptr [r13 + 8], 4
    je runtime_grow_frontend_pending
    cmp qword ptr [r13 + 8], 3
    ja runtime_grow_bad
    cmp qword ptr [r13 + 8], 3
    jne runtime_grow_frontend_common
    cmp qword ptr [r13 + 32], 0
    jne runtime_grow_bad
runtime_grow_frontend_common:
    cmp qword ptr [r13 + 16], 1
    ja runtime_grow_bad
    cmp qword ptr [r13 + 40], 1
    ja runtime_grow_bad
    cmp qword ptr [r13 + 56], 0
    jne runtime_grow_bad
    mov rax, [r13 + 24]
    add rax, [r13 + 32]
    jc runtime_grow_bad
    add rax, 64
    jc runtime_grow_bad
    jmp runtime_grow_extent_ready
runtime_grow_frontend_pending:
    /* A pending host result is exactly 64 bytes, with no public payload. */
    mov rax, [r13 + 16]
    or rax, [r13 + 24]
    or rax, [r13 + 32]
    or rax, [r13 + 40]
    or rax, [r13 + 56]
    jnz runtime_grow_bad
    mov eax, 64
    jmp runtime_grow_extent_ready
runtime_grow_connection_result:
    cmp eax, 256
    jb runtime_grow_bad
    mov rdx, 0x313030534e435248 /* HRCNS001: the u32 is the complete extent. */
    cmp [r13], rdx
    jne runtime_grow_bad
    cmp qword ptr [r13 + 8], 6
    ja runtime_grow_bad
    cmp qword ptr [r13 + 16], 1
    ja runtime_grow_bad
    cmp qword ptr [r13 + 24], 1
    ja runtime_grow_bad
    cmp qword ptr [r13 + 48], 1
    ja runtime_grow_bad
    jmp runtime_grow_extent_ready
runtime_grow_protocol_result:
    cmp eax, 192
    jne runtime_grow_bad
    mov rdx, 0x32305252504a5248 /* HRJPRR02 */
    cmp [r13], rdx
    jne runtime_grow_bad
    cmp qword ptr [r13 + 8], 4
    ja runtime_grow_bad
    cmp ebp, 19
    jne runtime_grow_historical_protocol_kind
    cmp qword ptr [r13 + 16], 6
    ja runtime_grow_bad
    jmp runtime_grow_protocol_kind_ready
runtime_grow_historical_protocol_kind:
    cmp qword ptr [r13 + 16], 5
    ja runtime_grow_bad
runtime_grow_protocol_kind_ready:
    cmp qword ptr [r13 + 24], 8
    ja runtime_grow_bad
    cmp qword ptr [r13 + 32], 2
    ja runtime_grow_bad
    mov rax, [r13 + 152]
    or rax, [r13 + 160]
    or rax, [r13 + 168]
    or rax, [r13 + 176]
    or rax, [r13 + 184]
    jnz runtime_grow_bad
    mov rax, [r13 + 48]
    add rax, [r13 + 56]
    jc runtime_grow_bad
    add rax, [r13 + 64]
    jc runtime_grow_bad
    add rax, 192
    jc runtime_grow_bad
    jmp runtime_grow_extent_ready

runtime_grow_admission_result:
    cmp eax, 48
    jne runtime_grow_bad
    mov rdx, 0x32305244414d4348 /* HCMADR02 */
    cmp [r13], rdx
    jne runtime_grow_bad
    cmp qword ptr [r13 + 8], 4
    ja runtime_grow_bad
    cmp qword ptr [r13 + 16], 2
    ja runtime_grow_bad
    cmp qword ptr [r13 + 24], 1
    ja runtime_grow_bad
    cmp qword ptr [r13 + 40], 6
    ja runtime_grow_bad
    mov rax, [r13 + 32]
    add rax, 48
    jc runtime_grow_bad
    jmp runtime_grow_extent_ready

runtime_grow_value_result:
    cmp eax, 32
    jne runtime_grow_bad
    mov rdx, 0x3230305256534a48 /* HJSVR002 */
    cmp [r13], rdx
    jne runtime_grow_bad
    cmp qword ptr [r13 + 8], 5
    jne runtime_grow_status32
    /* Typed Map RawValue failure is an ordinary completed reply only for
     * the exact new input mode; existing Value/status and other leaf
     * domains keep their original guards. No body or growth extent exists. */
    cmp qword ptr [rsp + 8], 24
    jb runtime_grow_bad
    mov rdx, [rsp]
    mov rax, 0x323030534d534a48 /* HJSMS002 */
    cmp [rdx], rax
    jne runtime_grow_bad
    cmp qword ptr [rdx + 8], 1
    jne runtime_grow_bad
    mov rax, [r13 + 16]
    or rax, [r13 + 24]
    jnz runtime_grow_bad
    mov eax, 32
    jmp runtime_grow_extent_ready
runtime_grow_workdir_params_result:
    cmp eax, 32
    jne runtime_grow_bad
    mov rdx, 0x3230525250445748 /* HWDPRR02 */
    cmp [r13], rdx
    jne runtime_grow_bad
    jmp runtime_grow_status32
runtime_grow_workdir_render_result:
    cmp eax, 32
    jne runtime_grow_bad
    mov rdx, 0x323052524a445748 /* HWDJRR02 */
    cmp [r13], rdx
    jne runtime_grow_bad
runtime_grow_status32:
    mov rax, [r13 + 8]
    cmp rax, 4
    ja runtime_grow_bad
    je runtime_grow_resource
    cmp rax, 2
    jae runtime_grow_status32_growth
    cmp qword ptr [r13 + 24], 0
    jne runtime_grow_bad
    mov rax, [r13 + 16]
    add rax, 32
    jc runtime_grow_bad
    jmp runtime_grow_extent_ready
runtime_grow_status32_growth:
    cmp qword ptr [r13 + 16], 0
    jne runtime_grow_bad
    mov rdx, [r13 + 24]
    lea rsi, [rax - 1]
    jmp runtime_grow_resize_requested

runtime_grow_batch_params_result:
    cmp eax, 128
    jne runtime_grow_bad
    mov rdx, 0x3130525250414248
    cmp [r13], rdx
    jne runtime_grow_bad
    jmp runtime_grow_typed_params_fields
runtime_grow_text_params_result:
    cmp eax, 128
    jne runtime_grow_bad
    mov rdx, 0x3230525250455448 /* HTEPRR02 */
    cmp [r13], rdx
    jne runtime_grow_bad
runtime_grow_typed_params_fields:
    mov rdx, [r13 + 88]
    or rdx, [r13 + 96]
    or rdx, [r13 + 104]
    or rdx, [r13 + 112]
    or rdx, [r13 + 120]
    jnz runtime_grow_bad
    mov rax, [r13 + 8]
    cmp rax, 4
    ja runtime_grow_bad
    je runtime_grow_resource
    cmp rax, 2
    jae runtime_grow_text_params_growth
    cmp qword ptr [r13 + 80], 0
    jne runtime_grow_bad
    test rax, rax
    jnz runtime_grow_text_params_error
    mov rax, [r13 + 24]
    add rax, [r13 + 40]
    jc runtime_grow_bad
    add rax, [r13 + 48]
    jc runtime_grow_bad
    add rax, [r13 + 56]
    jc runtime_grow_bad
    add rax, 128
    jc runtime_grow_bad
    jmp runtime_grow_extent_ready
runtime_grow_text_params_error:
    mov rax, [r13 + 72]
    add rax, 128
    jc runtime_grow_bad
    jmp runtime_grow_extent_ready
runtime_grow_text_params_growth:
    mov rdx, [r13 + 80]
    lea rsi, [rax - 1]
    jmp runtime_grow_resize_requested

runtime_grow_batch_input_result:
    cmp eax, 64
    jne runtime_grow_bad
    mov rdx, 0x3230305249504248
    cmp [r13], rdx
    jne runtime_grow_bad
    mov rax, [r13 + 48]
    or rax, [r13 + 56]
    jnz runtime_grow_bad
    mov rax, [r13 + 8]
    cmp rax, 4
    ja runtime_grow_bad
    je runtime_grow_resource
    cmp rax, 1
    je runtime_grow_bad
    cmp rax, 2
    jae runtime_grow_batch_input_growth
    cmp qword ptr [r13 + 40], 0
    jne runtime_grow_bad
    mov rax, [r13 + 16]
    add rax, 64
    jc runtime_grow_bad
    jmp runtime_grow_extent_ready
runtime_grow_batch_input_growth:
    mov rdx, [r13 + 40]
    lea rsi, [rax - 1]
    mov rax, [r13 + 16]
    or rax, [r13 + 24]
    or rax, [r13 + 32]
    jnz runtime_grow_bad
    jmp runtime_grow_resize_requested

runtime_grow_params_result:
    cmp eax, 96
    jne runtime_grow_bad
    mov rdx, 0x3230305252505648 /* HVPRR002 */
    cmp [r13], rdx
    jne runtime_grow_bad
    mov rax, [r13 + 8]
    cmp rax, 4
    ja runtime_grow_bad
    je runtime_grow_resource
    cmp rax, 2
    jae runtime_grow_params_growth
    test rax, rax
    jnz runtime_grow_params_error_text
    mov eax, 96
    xor ecx, ecx
runtime_grow_params_span:
    add rax, [r13 + rcx * 8 + 24]
    jc runtime_grow_bad
    inc ecx
    cmp ecx, 5
    jb runtime_grow_params_span
    jmp runtime_grow_extent_ready
runtime_grow_params_error_text:
    mov rax, [r13 + 88]
    add rax, 96
    jc runtime_grow_bad
    jmp runtime_grow_extent_ready
runtime_grow_params_growth:
    mov rdx, [r13 + 88]
    lea rsi, [rax - 1]
    jmp runtime_grow_resize_requested

runtime_grow_session_result:
    cmp eax, 32
    jne runtime_grow_bad
    mov rdx, 0x3230305257535248 /* HRSWR002 */
    cmp [r13], rdx
    jne runtime_grow_bad
    mov rax, [r13 + 8]
    cmp rax, 5
    ja runtime_grow_bad
    je runtime_grow_resource
    cmp rax, 3
    jae runtime_grow_session_growth
    mov rax, [r13 + 24]
    add rax, 32
    jc runtime_grow_bad
    jmp runtime_grow_extent_ready
runtime_grow_session_growth:
    cmp qword ptr [r13 + 24], 0
    jne runtime_grow_bad
    mov rdx, [r13 + 16]
    lea rsi, [rax - 2]
    jmp runtime_grow_resize_requested
runtime_grow_client_result:
    cmp eax, 32
    jne runtime_grow_bad
    mov rdx, 0x323052504d435248 /* HRCMPR02 */
    cmp [r13], rdx
    jne runtime_grow_bad
    cmp qword ptr [r13 + 8], 1
    ja runtime_grow_bad
    mov rax, [r13 + 16]
    cmp rax, [r13 + 8]
    ja runtime_grow_bad
    jmp runtime_grow_length24
runtime_grow_context_result:
    cmp eax, 32
    jne runtime_grow_bad
    mov rdx, 0x3230525043535248 /* HRSCPR02 */
    cmp [r13], rdx
    jne runtime_grow_bad
    mov rax, [r13 + 8]
    or rax, [r13 + 16]
    or rax, [r13 + 24]
    jnz runtime_grow_bad
    mov eax, 32
    jmp runtime_grow_extent_ready
runtime_grow_gateway_result:
    cmp eax, 32
    jne runtime_grow_bad
    mov rdx, 0x31304d4746435248 /* HRCFGM01 */
    cmp [r13], rdx
    jne runtime_grow_bad
    cmp qword ptr [r13 + 8], 2
    ja runtime_grow_bad
    cmp qword ptr [r13 + 16], 0
    jne runtime_grow_bad
runtime_grow_length24:
    mov rax, [r13 + 24]
    add rax, 32
    jc runtime_grow_bad
    jmp runtime_grow_extent_ready
runtime_grow_workdir_io_result:
    cmp eax, 64
    jne runtime_grow_bad
    mov rdx, 0x3230524f49445748 /* HWDIOR02 */
    cmp [r13], rdx
    jne runtime_grow_bad
    cmp qword ptr [r13 + 8], 3
    ja runtime_grow_bad
    mov rax, [r13 + 32]
    add rax, [r13 + 40]
    jc runtime_grow_bad
    add rax, 64
    jc runtime_grow_bad
    jmp runtime_grow_extent_ready
runtime_grow_canonical_result:
    cmp eax, 40
    jne runtime_grow_bad
    mov rdx, 0x3230524e41435248 /* HRCANR02 */
    cmp [r13], rdx
    jne runtime_grow_bad
    cmp qword ptr [r13 + 8], 2
    ja runtime_grow_bad
    mov rax, [r13 + 32]
    add rax, 40
    jc runtime_grow_bad
    jmp runtime_grow_extent_ready
runtime_grow_policy_result:
    cmp eax, 32
    jne runtime_grow_bad
    mov rdx, 0x3230305243504c48 /* HLPCR002 */
    cmp [r13], rdx
    jne runtime_grow_bad
    cmp qword ptr [r13 + 8], 1
    ja runtime_grow_bad
    jmp runtime_grow_length24
runtime_grow_path_result:
    cmp eax, 96
    jne runtime_grow_bad
    mov rdx, 0x3230524c4f535248 /* HRSOLR02 */
    cmp [r13], rdx
    jne runtime_grow_bad
    cmp qword ptr [r13 + 8], 1
    ja runtime_grow_bad
    mov rax, [r13 + 40]
    add rax, [r13 + 48]
    jc runtime_grow_bad
    add rax, [r13 + 56]
    jc runtime_grow_bad
    add rax, 96
    jc runtime_grow_bad
runtime_grow_extent_ready:
    cmp rax, [rbx + 40]
    ja runtime_grow_bad
    cmp qword ptr [r12 + 8], 0
    jne runtime_grow_bad
    mov [rbx + 56], rax
    mov rax, [rbx + 48]
    jmp runtime_grow_finish
runtime_grow_controller_growth:
    cmp qword ptr [rbx + 40], 32
    jb runtime_grow_bad
    mov r13, [rbx + 32]
    mov rdx, 0x3230305357524748 /* HGRWS002 */
    cmp [r13], rdx
    jne runtime_grow_bad
    cmp qword ptr [r13 + 24], 0
    jne runtime_grow_bad
    mov rsi, [r13 + 8]
    cmp rsi, 3
    ja runtime_grow_bad
    je runtime_grow_resource
    test rsi, rsi
    jz runtime_grow_bad
    mov rdx, [r13 + 16]
runtime_grow_resize_requested:
    cmp ebp, 11
    jne runtime_grow_resize_owned
    cmp esi, 2
    jne runtime_grow_bad /* Shared owner growth stays in its owning boundary. */
runtime_grow_resize_owned:
    mov rdi, rbx
    call runtime_grow_resize_borrow
    test eax, eax
    jnz runtime_grow_error
    mov edi, 2
    call runtime_grow_trace
    jmp runtime_grow_resume

runtime_grow_canonical_action:
    mov rdi, [rbx + 8]
    mov rsi, [rbx + 16]
    mov rdx, rbx
    call runtime_grow_canonical_effect
    test eax, eax
    jnz runtime_grow_bad
    jmp runtime_grow_resume

runtime_grow_action:
    cmp ebp, 8
    je runtime_grow_canonical_action
    cmp qword ptr [rbx + 16], 4096
    jb runtime_grow_bad
    mov r14, [rbx + 8]
    lea r13, [r14 + 256]
    lea rdx, [rip + runtime_grow_action_magics]
    mov rax, [rdx + rbp * 8]
    test rax, rax
    jz runtime_grow_bad
    cmp [r13], rax
    jne runtime_grow_bad
    mov rax, [r13 + 8]
    test rax, rax
    jz runtime_grow_bad
    cmp [r14 + 16], rax
    jne runtime_grow_bad
    mov rax, [r13 + 64]
    or rax, [r13 + 72]
    or rax, [r13 + 80]
    or rax, [r13 + 88]
    or rax, [r13 + 96]
    or rax, [r13 + 104]
    jnz runtime_grow_bad
    cmp qword ptr [r13 + 24], 1
    ja runtime_grow_bad
    mov rax, [r13 + 32]
    cmp rax, 4096
    jb runtime_grow_bad
    cmp rax, [rbx + 16]
    ja runtime_grow_bad
    mov rdx, [rbx + 16]
    sub rdx, rax
    cmp [r13 + 40], rdx
    ja runtime_grow_bad
    add rax, [r13 + 40]
    mov rdx, [r13 + 48]
    cmp rdx, 4096
    jb runtime_grow_bad
    cmp rdx, [rbx + 16]
    ja runtime_grow_bad
    mov rcx, [rbx + 16]
    sub rcx, rdx
    cmp [r13 + 56], rcx
    ja runtime_grow_bad
    cmp qword ptr [r13 + 56], 32
    jb runtime_grow_bad
    add rdx, [r13 + 56]
    cmp rdx, [r13 + 32]
    jbe runtime_grow_action_disjoint
    cmp rax, [r13 + 48]
    ja runtime_grow_bad
runtime_grow_action_disjoint:
    mov rdi, rbp
    mov rsi, [r13 + 16]
    call runtime_grow_target
    cmp rax, RG_SLOTS
    jae runtime_grow_bad
    mov [rsp + 16], rax
    cmp qword ptr [r13 + 24], 1
    je runtime_grow_deliver_again
    cmp qword ptr [r12 + 8], 0
    jne runtime_grow_bad
    mov rdx, [rbx + 24]
    inc rdx
    jz runtime_grow_bad
    cmp [r13 + 8], rdx
    jne runtime_grow_bad
    mov [rbx + 24], rdx
    mov [r12 + 16], rdx
    mov [r12 + 24], rax
    mov rax, [r13 + 32]
    mov [r12 + 32], rax
    mov rax, [r13 + 40]
    mov [r12 + 40], rax
    mov rdi, r14
    add rdi, [r13 + 32]
    mov rsi, [r13 + 40]
    mov r8, [rsp + 16]
    inc qword ptr [r15 + 152]
    mov edi, 3
    call runtime_grow_trace
    mov rdi, r14
    add rdi, [r13 + 32]
    call runtime_grow_owned
    mov [r12 + 48], rax
    cmp eax, 0xffff0000
    jae runtime_grow_child_error
    mov rcx, [rsp + 16]
    shl rcx, 6
    add rcx, [r15 + 8]
    mov rax, [rcx + 56]
    mov [r12 + 56], rax
    jmp runtime_grow_child_completed
runtime_grow_child_error:
    mov qword ptr [r12 + 56], 0
runtime_grow_child_completed:
    mov qword ptr [r12 + 8], 1
    jmp runtime_grow_deliver
runtime_grow_deliver_again:
    cmp qword ptr [r12 + 8], 1
    jne runtime_grow_bad
    cmp [r12 + 24], rax
    jne runtime_grow_bad
    mov rax, [r13 + 8]
    cmp [rbx + 24], rax
    jne runtime_grow_bad
    cmp [r12 + 16], rax
    jne runtime_grow_bad
    mov rax, [r13 + 32]
    cmp [r12 + 32], rax
    jne runtime_grow_bad
    mov rax, [r13 + 40]
    cmp [r12 + 40], rax
    jne runtime_grow_bad
    inc qword ptr [r15 + 160]
runtime_grow_deliver:
    mov eax, 0xffff0000
    cmp [r12 + 48], rax
    jae runtime_grow_deliver_error
    mov rcx, [r12 + 56]
    cmp rcx, [r13 + 56]
    ja runtime_grow_delivery_short
    mov rax, [r12 + 24]
    shl rax, 6
    add rax, [r15 + 8]
    cmp rcx, [rax + 56]
    jne runtime_grow_bad
    mov rdx, [r12 + 48]
    cmp [rax + 48], rdx
    jne runtime_grow_bad
    mov rsi, [rax + 32]
    mov rdi, [rbx + 8]
    add rdi, [r13 + 48]
    cld
    rep movsb
runtime_grow_deliver_error:
    mov qword ptr [r12 + 8], 0
    mov rax, [r12 + 48]
    jmp runtime_grow_complete_action
runtime_grow_delivery_short:
    inc qword ptr [r15 + 168]
    mov eax, RG_DELIVERY
runtime_grow_complete_action:
    mov [r13 + 72], rax
    mov rax, [r12 + 16]
    mov [r13 + 64], rax
    mov rax, [r12 + 56]
    mov [r13 + 96], rax
    mov edi, 4
    call runtime_grow_trace
    jmp runtime_grow_resume

runtime_grow_batch_body_dispatch:
    call runtime_batch_body_owned
    jmp runtime_grow_done

runtime_grow_bellman_dispatch:
    /* The installed fixed packed port is a private capability, not an HIA
     * child selector supplied by input. Its SysV owned entry preserves r15. */
    mov rax, [rbx]
    test rax, rax
    jz runtime_grow_resource_early
    add rax, 2469 /* fixed runtime_bellman_owned export, component identity-bound */
    call rax
    jmp runtime_grow_done
runtime_grow_authority_dispatch:
    call runtime_authority_owned
    jmp runtime_grow_done
runtime_grow_text_body_dispatch:
    call runtime_text_body_owned
    jmp runtime_grow_done
runtime_grow_text_create_dispatch:
    call runtime_text_create_owned
    jmp runtime_grow_done
runtime_grow_view_dispatch:
    call runtime_grow_view_owned
    jmp runtime_grow_done
runtime_grow_io_dispatch:
    call runtime_grow_io_owned
    jmp runtime_grow_done
runtime_grow_fs_io_dispatch:
    call runtime_grow_fs_io_owned
    jmp runtime_grow_done
runtime_grow_fence_dispatch:
    call runtime_grow_fence_owned
    jmp runtime_grow_done
runtime_grow_view_proxy_dispatch:
    mov r8, rbp
    call runtime_grow_view_proxy_owned
    jmp runtime_grow_done
runtime_grow_bad:
    mov eax, RG_INVALID
    jmp runtime_grow_error
runtime_grow_resource:
    mov eax, RG_RESOURCE
runtime_grow_error:
    mov [rbx + 48], rax
    mov qword ptr [rbx + 56], 0
    mov qword ptr [r12 + 8], 0
runtime_grow_finish:
    mov qword ptr [r12], 0
    jmp runtime_grow_done
runtime_grow_bad_early:
    mov eax, RG_INVALID
    jmp runtime_grow_done
runtime_grow_resource_early:
    mov eax, RG_RESOURCE
runtime_grow_done:
    add rsp, 96
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret

/* rdi descriptor, rsi 1=work/2=output, rdx exact required capacity.
 * Page/usize/OS failures are resource failures, never application error text. */
runtime_grow_resize_borrow:
    push rbp
    push rbx
    push r12
    push r13
    sub rsp, 8
    mov rbx, rdi
    mov rbp, rsi
    cmp rbp, 1
    je runtime_grow_resize_work
    cmp rbp, 2
    jne runtime_grow_resize_invalid
    lea rbx, [rbx + 24]
runtime_grow_resize_work:
    mov r12, [rbx + 16]
    cmp rdx, r12
    jbe runtime_grow_resize_invalid
    mov r13, rdx
    mov rax, r12
    add rax, rax
    jc runtime_grow_resize_exact
    cmp rax, r13
    cmova r13, rax
runtime_grow_resize_exact:
    add r13, 4095
    jc runtime_grow_resize_resource
    and r13, -4096
    test r13, r13
    jz runtime_grow_resize_resource
    js runtime_grow_resize_resource
    mov rdi, [rbx + 8]
    mov rsi, r12
    mov rdx, r13
    call view_resize
    cmp rax, -4095
    jae runtime_grow_resize_resource
    mov [rbx + 8], rax
    mov [rbx + 16], r13
    cmp ebp, 1
    jne runtime_grow_resize_output_count
    inc qword ptr [r15 + 136]
    jmp runtime_grow_resize_success
runtime_grow_resize_output_count:
    inc qword ptr [r15 + 144]
runtime_grow_resize_success:
    xor eax, eax
    jmp runtime_grow_resize_done
runtime_grow_resize_invalid:
    mov eax, RG_INVALID
    jmp runtime_grow_resize_done
runtime_grow_resize_resource:
    mov eax, RG_RESOURCE
runtime_grow_resize_done:
    add rsp, 8
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret

/* Optional fixture receipt sink. Create leaves +80 zero, so production emits
 * nothing. Fixture sets fd+1. All input registers and flags survive the hook.
 * Record224: magic,event-seq,slot,event,rax,wcap,ocap,phase,sequence,extent,
 * followed by the exact 112-byte private action and 32-byte output header. */
runtime_grow_trace:
    pushfq
    push rax
    push rcx
    push rdx
    push rsi
    push rdi
    push r8
    push r9
    push r10
    push r11
    cmp qword ptr [r15 + 80], 0
    je runtime_grow_trace_restore
    sub rsp, 224
    mov rax, 0x3230305254475248 /* HRGTR002 */
    mov [rsp], rax
    inc qword ptr [r15 + 184]
    mov rax, [r15 + 184]
    mov [rsp + 8], rax
    mov [rsp + 16], rbp
    mov [rsp + 24], rdi
    mov rax, [rsp + 224 + 64]
    mov [rsp + 32], rax
    mov rax, [rbx + 16]
    mov [rsp + 40], rax
    mov rax, [rbx + 40]
    mov [rsp + 48], rax
    mov rsi, [rbx + 8]
    mov rax, [rsi + 8]
    mov [rsp + 56], rax
    mov rax, [rsi + 16]
    mov [rsp + 64], rax
    mov rax, [rbx + 56]
    mov [rsp + 72], rax
    lea rdi, [rsp + 80]
    add rsi, 256
    mov ecx, 112
    cld
    rep movsb
    mov rsi, [rbx + 32]
    mov ecx, 32
    rep movsb
    mov rsi, rsp
    mov edx, 224
runtime_grow_trace_write:
    mov rdi, [r15 + 80]
    dec rdi
    mov eax, 1
    syscall
    cmp rax, -4
    je runtime_grow_trace_write
    test rax, rax
    jle runtime_grow_trace_failure
    add rsi, rax
    sub rdx, rax
    jnz runtime_grow_trace_write
    jmp runtime_grow_trace_finish
runtime_grow_trace_failure:
    mov [r15 + 88], rax
runtime_grow_trace_finish:
    add rsp, 224
runtime_grow_trace_restore:
    pop r11
    pop r10
    pop r9
    pop r8
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rax
    popfq
    ret

/* Exact private graph: rdi parent slot, rsi local selector. */
runtime_grow_target:
    cmp edi, 47
    je runtime_grow_target_batch_gateway
    cmp edi, 49
    je runtime_grow_target_batch_caller
    cmp edi, 50
    je runtime_grow_target_batch_body
    cmp edi, 19
    je runtime_grow_target_sdk_protocol
    cmp edi, 39
    je runtime_grow_target_local_body
    cmp edi, 37
    je runtime_grow_target_text_gateway
    cmp edi, 35
    je runtime_grow_target_text_create
    cmp edi, 18
    je runtime_grow_target_frontend
    cmp edi, 3
    je runtime_grow_target_client
    cmp edi, 5
    je runtime_grow_target_context
    cmp edi, 13
    je runtime_grow_target_workdir
    cmp edi, 1
    je runtime_grow_target_admission
    cmp edi, 2
    je runtime_grow_target_gateway
    cmp edi, 7
    je runtime_grow_target_policy
    cmp edi, 21
    je runtime_grow_target_filesystem_gateway
    cmp edi, 23
    je runtime_grow_target_filesystem_caller
    cmp edi, 26
    je runtime_grow_target_policy
    cmp edi, 27
    je runtime_grow_target_fence
    jmp runtime_grow_target_invalid
runtime_grow_target_batch_gateway:
    cmp rsi, 8
    ja runtime_grow_target_invalid
    lea rdx, [rip + runtime_grow_batch_gateway_targets]
    jmp runtime_grow_target_byte
runtime_grow_target_batch_caller:
    cmp rsi, 5
    ja runtime_grow_target_invalid
    lea rdx, [rip + runtime_grow_batch_caller_targets]
    jmp runtime_grow_target_byte
runtime_grow_target_batch_body:
    cmp rsi, 1
    ja runtime_grow_target_invalid
    lea rdx, [rip + runtime_grow_batch_body_targets]
    jmp runtime_grow_target_byte
runtime_grow_target_local_body:
    test rsi, rsi
    jnz runtime_grow_target_invalid
    mov eax, 40
    ret
runtime_grow_target_text_gateway:
    cmp rsi, 8
    ja runtime_grow_target_invalid
    lea rdx, [rip + runtime_grow_text_gateway_targets]
    jmp runtime_grow_target_byte
runtime_grow_target_text_create:
    cmp rsi, 5
    ja runtime_grow_target_invalid
    lea rdx, [rip + runtime_grow_text_create_targets]
    jmp runtime_grow_target_byte
runtime_grow_target_filesystem_gateway:
    cmp rsi, 7
    ja runtime_grow_target_invalid
    lea rdx, [rip + runtime_grow_filesystem_gateway_targets]
    jmp runtime_grow_target_byte
runtime_grow_target_filesystem_caller:
    cmp rsi, 9
    ja runtime_grow_target_invalid
    lea rdx, [rip + runtime_grow_filesystem_caller_targets]
    jmp runtime_grow_target_byte
runtime_grow_target_fence:
    cmp rsi, 2
    ja runtime_grow_target_invalid
    lea rdx, [rip + runtime_grow_fence_targets]
    jmp runtime_grow_target_byte
runtime_grow_target_sdk_protocol:
    cmp rsi, 4
    ja runtime_grow_target_invalid
    lea rdx, [rip + runtime_grow_sdk_protocol_targets]
    jmp runtime_grow_target_byte
runtime_grow_target_frontend:
    cmp rsi, 14
    ja runtime_grow_target_invalid
    lea rdx, [rip + runtime_grow_frontend_targets]
    jmp runtime_grow_target_byte
runtime_grow_target_client:
    cmp rsi, 1
    jne runtime_grow_target_invalid
    mov eax, 10
    ret
runtime_grow_target_context:
    cmp rsi, 1
    jb runtime_grow_target_invalid
    cmp rsi, 4
    ja runtime_grow_target_invalid
    lea rdx, [rip + runtime_grow_context_targets - 1]
    jmp runtime_grow_target_byte
runtime_grow_target_workdir:
    cmp rsi, 8
    ja runtime_grow_target_invalid
    lea rdx, [rip + runtime_grow_workdir_targets]
    jmp runtime_grow_target_byte
runtime_grow_target_admission:
    cmp rsi, 1
    ja runtime_grow_target_invalid
    lea rdx, [rip + runtime_grow_admission_targets]
    jmp runtime_grow_target_byte
runtime_grow_target_gateway:
    cmp rsi, 6
    ja runtime_grow_target_invalid
    lea rdx, [rip + runtime_grow_gateway_targets]
    jmp runtime_grow_target_byte
runtime_grow_target_policy:
    cmp rsi, 1
    jb runtime_grow_target_invalid
    cmp rsi, 2
    ja runtime_grow_target_invalid
    lea rdx, [rip + runtime_grow_policy_targets - 1]
runtime_grow_target_byte:
    movzx eax, byte ptr [rdx + rsi]
    ret
runtime_grow_target_invalid:
    mov rax, -1
    ret

.balign 8
runtime_grow_action_magics:
    .quad 0
    .ascii "HRCADA02"
    .ascii "HVGWCA02"
    .ascii "HRCMCA02"
    .quad 0
    .ascii "HRSCPA02"
    .quad 0
    .ascii "HLPCA002"
    .quad 0, 0, 0, 0, 0
    .ascii "HWDGWA02"
    .quad 0, 0, 0, 0
    .ascii "HRMCFA02"
    .ascii "HRQPCA01"
    .quad 0
    .ascii "HFSWGA02"
    .quad 0
    .ascii "HFSCCA02"
    .quad 0, 0
    .ascii "HFDMGA02"
    .ascii "HFSFEA02"
    .quad 0, 0, 0, 0, 0
    .quad 0, 0
    .ascii "HTECCA02"
    .quad 0
    .ascii "HTEWGA02"
    .quad 0
    .ascii "HTLBCA01"
    .quad 0
    .zero 48 /* 41..46: no controller action. */
    .ascii "HBAWGA01" /* 47 */
    .quad 0 /* 48 typed params */
    .ascii "HBECCA01" /* 49 caller */
    .ascii "HBBACA01" /* 50 adapter */
    .zero 64 /* 51..58: no controller action; Authority and Bellman are capabilities. */
runtime_grow_sdk_protocol_targets:
    .byte 42, 43, 44, 45, 55
runtime_grow_text_gateway_targets:
    .byte 38, 27, 5, 6, 11, 9, 7, 35, 3
runtime_grow_text_create_targets:
    .byte 29, 9, 36, 39, 39, 39
runtime_grow_filesystem_gateway_targets:
    .byte 22, 27, 5, 6, 11, 9, 7, 23
runtime_grow_filesystem_caller_targets:
    .byte 29, 11, 9, 7, 26, 24, 30, 31, 32, 25
runtime_grow_fence_targets:
    .byte 11, 28, 17
runtime_grow_frontend_targets:
    .byte 19, 1, 0, 10, 2, 13, 11, 20, 21, 37, 46, 54, 56, 47, 57
runtime_grow_context_targets:
    .byte 6, 10, 7, 8
runtime_grow_workdir_targets:
    .byte 14, 5, 6, 11, 9, 7, 15, 16, 17
runtime_grow_admission_targets:
    .byte 10, 3
runtime_grow_gateway_targets:
    .byte 4, 5, 6, 11, 9, 7, 12
runtime_grow_policy_targets:
    .byte 11, 8

runtime_grow_batch_gateway_targets:
    .byte 48, 27, 5, 6, 11, 9, 7, 49, 3
runtime_grow_batch_caller_targets:
    .byte 29, 9, 50, 50, 50, 50
runtime_grow_batch_body_targets:
    .byte 51, 52
