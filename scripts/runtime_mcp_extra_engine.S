/* Private, fixed-image continuation transport. JSON, capability selection,
 * session latch, policy, parameter projection, view and publication decisions
 * remain in their HIA owners. No public frame can select this table. */
.intel_syntax noprefix
.section .text
.global runtime_extra_invoke
.global runtime_extra_create
.global runtime_extra_image_table
.global runtime_view_image_table

/* Private main-control words: +896 engine, +904 AT_SECURE, +912 root pointer,
 * +920 root length, +928 configured. These do not overlap existing config
 * descriptor or protocol transport words. */
runtime_arguments_start:
    cmp qword ptr [rbx], 3
    je runtime_arguments_three
    cmp qword ptr [rbx], 5
    jne argv_fatal
    mov rdi, [rbx + 32]
    lea rsi, [rip + runtime_session_option]
    call cstr_equal
    test eax, eax
    jz argv_fatal
    mov rdi, [rbx + 40]
    mov [r15 + 912], rdi
    call cstr_length
    mov [r15 + 920], rax
    jmp runtime_arguments_configured
runtime_arguments_three:
    mov rdi, [rbx + 16]
    lea rsi, [rip + runtime_session_option]
    call cstr_equal
    test eax, eax
    jz runtime_arguments_configured
    mov rdi, [rbx + 24]
    mov [r15 + 912], rdi
    call cstr_length
    mov [r15 + 920], rax
    lea rax, [rbx + 40]
    mov [r15 + 648], rax
    call runtime_admit_auxv
    mov qword ptr [r15 + 24], 0
    lea rax, [r15 + ROOT_WORK + FOOTER]
    mov qword ptr [rax + 120], 4
    jmp owner_resume
runtime_arguments_configured:
    mov qword ptr [r15 + 928], 1
    jmp runtime_arguments_done

runtime_admit_auxv:
    mov rax, [r15 + 648]
runtime_environment_end:
    cmp qword ptr [rax], 0
    lea rax, [rax + 8]
    jne runtime_environment_end
runtime_auxv_next:
    mov rcx, [rax]
    test rcx, rcx
    jz runtime_auxv_done
    cmp rcx, 23
    jne runtime_auxv_advance
    mov rcx, [rax + 8]
    mov [r15 + 904], rcx
runtime_auxv_advance:
    add rax, 16
    jmp runtime_auxv_next
runtime_auxv_done:
    ret

runtime_install_private:
    lea rdi, [rip + runtime_extra_image_table]
    mov rsi, r15
    call runtime_extra_create
    cmp rax, -4095
    jae fatal
    mov [r15 + 896], rax
    jmp frame_next

runtime_mcp_extra_call:
    /* rdx is the already admitted frontend footer. */
    mov rax, [rdx + 16]
    cmp rax, 11
    jb fatal
    cmp rax, 13
    ja fatal
    sub rax, 11
    mov r8, rax
    cmp qword ptr [rdx + 56], 100667392
    jne fatal
    mov rax, [rdx + 32]
    cmp rax, 33550336
    je runtime_extra_short_request
    cmp rax, 167780352
    jne fatal
    mov rsi, [rdx + 40]
    cmp rsi, 75497512
    ja fatal
    jmp runtime_extra_request_ready
runtime_extra_short_request:
    cmp qword ptr [rdx + 16], 11
    jne fatal
    cmp qword ptr [rdx + 40], 24
    jne fatal
    mov esi, 24
runtime_extra_request_ready:
    lea rdi, [r15 + MCP_WORK]
    add rdi, rax
    lea rdx, [r15 + MCP_WORK + 100667392]
    mov ecx, 67108864
    sub rsp, 16
    mov [rsp], r15
    mov r15, [r15 + 896]
    test r15, r15
    jz runtime_boundary_abort
    call runtime_extra_invoke
    mov r15, [rsp]
    add rsp, 16
    cmp rax, 67108864
    jbe runtime_extra_front_result
    cmp eax, 0xffff0000
    jb fatal
runtime_extra_front_result:
    lea rdx, [r15 + MCP_WORK + FOOTER]
    mov [rdx + 80], rax
    mov rax, [r15 + 792]
    mov [rdx + 88], rax
    mov qword ptr [rdx + 96], 1
    jmp mcp_resume

runtime_finish_private:
    mov rax, [r15 + 896]
    test rax, rax
    jz runtime_finish_private_done
    mov rax, [rax + 16]
    test rax, rax
    jz runtime_finish_private_done
    push r15
    mov r15, rax
    call view_engine_retire
    test rax, rax
    jnz runtime_boundary_abort
    call view_engine_destroy
    test rax, rax
    jnz runtime_boundary_abort
    pop r15
    mov rax, [r15 + 896]
    mov qword ptr [rax + 16], 0
runtime_finish_private_done:
    ret

/* rdi constant table, rsi existing config-private control. */
runtime_extra_create:
    push rbp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub rsp, 8
    mov r12, rdi
    mov r13, rsi
    mov edi, 8192
    call view_allocate
    cmp rax, -4095
    jae runtime_extra_create_done
    mov r15, rax
    mov [r15], r12
    lea r14, [r15 + 4096]
    mov [r15 + 8], r14
    mov [r15 + 24], r13
    mov rax, [r13 + 904]
    mov [r15 + 32], rax
    xor ebp, ebp
runtime_extra_create_slot:
    mov rax, [r12 + rbp * 8]
    mov [r14], rax
    mov edi, 268435456
    test ebp, ebp
    jnz runtime_extra_not_catalog
    mov edi, 4096
runtime_extra_not_catalog:
    cmp ebp, 4
    jne runtime_extra_not_params
    mov edi, 65536
runtime_extra_not_params:
    cmp ebp, 6
    jne runtime_extra_not_state
    mov edi, 16781312
runtime_extra_not_state:
    mov [r14 + 16], rdi
    cmp ebp, 10
    je runtime_extra_shared_value
    cmp ebp, 11
    je runtime_extra_shared_config
    call view_allocate
    cmp rax, -4095
    jae runtime_boundary_abort
    jmp runtime_extra_slot_mapped
runtime_extra_shared_value:
    lea rax, [r13 + VALUE_WORK]
    jmp runtime_extra_slot_mapped
runtime_extra_shared_config:
    lea rax, [r13 + ROOT_WORK]
runtime_extra_slot_mapped:
    mov [r14 + 8], rax
    add r14, 64
    inc ebp
    cmp ebp, 12
    jb runtime_extra_create_slot
    /* Install the sole private SessionWorkdir from argv or actual getcwd. */
    mov rbx, [r15 + 8]
    mov rbx, [rbx + 2 * 64 + 8]
    add rbx, 4096
    mov rax, 0x3130305157535248
    mov [rbx], rax
    mov qword ptr [rbx + 8], 1
    mov qword ptr [rbx + 24], 0
    mov rsi, [r13 + 912]
    test rsi, rsi
    jz runtime_extra_current_directory
    mov rcx, [r13 + 920]
    cmp rcx, 8388608
    ja runtime_boundary_abort
    mov [rbx + 16], rcx
    lea rdi, [rbx + 32]
    cld
    rep movsb
    jmp runtime_extra_initial_root_ready
runtime_extra_current_directory:
    lea rdi, [rbx + 32]
    mov esi, 8388608
    mov eax, 79
    syscall
    cmp rax, -4095
    jae runtime_boundary_abort
    test rax, rax
    jz runtime_boundary_abort
    dec rax
    mov [rbx + 16], rax
runtime_extra_initial_root_ready:
    mov rdi, rbx
    mov rsi, [rbx + 16]
    add rsi, 32
    lea rdx, [r15 + 1024]
    mov ecx, 32
    mov r8d, 6
    call runtime_extra_invoke
    cmp rax, 32
    jne runtime_boundary_abort
    mov rax, r15
runtime_extra_create_done:
    add rsp, 8
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret

/* r15 private engine; rdi/rsi borrowed input, rdx/rcx borrowed output;
 * r8 is a locally installed descriptor index. Output borrow never escapes. */
runtime_extra_invoke:
    push rbp
    push rbx
    push r12
    push r13
    push r14
    sub rsp, 64
    mov [rsp], rdi
    mov [rsp + 8], rsi
    mov [rsp + 16], rdx
    mov [rsp + 24], rcx
    mov rbp, r8
    cmp rbp, 12
    ja runtime_extra_invalid
    je runtime_extra_view
    mov rbx, rbp
    shl rbx, 6
    add rbx, [r15 + 8]
    mov r12, [rbx + 8]
runtime_extra_resume:
    cmp rbp, 11
    jne runtime_extra_native
    /* Only exact installed-state read queries are admitted here. */
    mov rax, [rsp + 8]
    cmp rax, 24
    jb runtime_extra_invalid
    mov rdx, [rsp]
    mov rcx, 0x3130514746435248
    cmp [rdx], rcx
    jne runtime_extra_invalid
    mov rcx, [rdx + 8]
    cmp rcx, 7
    jb runtime_extra_invalid
    cmp rcx, 8
    ja runtime_extra_invalid
    sub rax, 24
    cmp [rdx + 16], rax
    jne runtime_extra_invalid
    mov qword ptr [r12 + FOOTER + 120], 1
runtime_extra_native:
    mov rdi, [rsp]
    mov rsi, [rsp + 8]
    mov rdx, [rsp + 16]
    mov rcx, [rsp + 24]
    mov r8, r12
    mov r9, [rbx + 16]
    call qword ptr [rbx]
    mov edx, eax
    cmp rax, rdx
    jne runtime_extra_invalid
    cmp eax, 0xffffffe0
    je runtime_extra_standard_call
    cmp eax, 0xfffffff0
    je runtime_extra_custom_call
    cmp rax, [rsp + 24]
    jbe runtime_extra_done
    cmp eax, 0xffff0000
    jae runtime_extra_done
    jmp runtime_extra_invalid

runtime_extra_standard_call:
    cmp ebp, 1
    je runtime_extra_standard_owner
    cmp ebp, 2
    jne runtime_extra_invalid
runtime_extra_standard_owner:
    mov r13, [rbx + 16]
    lea r13, [r12 + r13 - 256]
    mov rax, 0x31304c4143414948
    cmp [r13], rax
    jne runtime_extra_invalid
    mov rax, [rbx + 24]
    inc rax
    jz runtime_extra_invalid
    cmp [r13 + 8], rax
    jne runtime_extra_invalid
    mov [rbx + 24], rax
    cmp qword ptr [r13 + 24], 2
    jne runtime_extra_invalid
    cmp qword ptr [r13 + 32], 4096
    jne runtime_extra_invalid
    cmp qword ptr [r13 + 48], 2
    jne runtime_extra_invalid
    cmp qword ptr [r13 + 56], 67117056
    jne runtime_extra_invalid
    cmp qword ptr [r13 + 64], 67108864
    jne runtime_extra_invalid
    mov rax, [r13 + 72]
    or rax, [r13 + 80]
    or rax, [r13 + 88]
    or rax, [r13 + 96]
    or rax, [r13 + 104]
    jnz runtime_extra_invalid
    mov rsi, [r13 + 40]
    cmp rsi, 67108864
    ja runtime_extra_invalid
    mov rax, [r13 + 16]
    cmp ebp, 2
    je runtime_extra_gateway_child
    cmp rax, 1
    ja runtime_extra_invalid
    mov r8d, 10
    test rax, rax
    jz runtime_extra_standard_child_ready
    mov r8d, 3
    jmp runtime_extra_standard_child_ready
runtime_extra_gateway_child:
    cmp rax, 6
    ja runtime_extra_invalid
    lea rdx, [rip + runtime_gateway_slots]
    movzx r8d, byte ptr [rdx + rax]
runtime_extra_standard_child_ready:
    lea rdi, [r12 + 4096]
    lea rdx, [r12 + 67117056]
    mov ecx, 67108864
    call runtime_extra_invoke
    mov [r13 + 80], rax
    mov rax, [r13 + 8]
    mov [r13 + 88], rax
    mov qword ptr [r13 + 96], 1
    jmp runtime_extra_resume

runtime_extra_custom_call:
    cmp ebp, 8
    je runtime_extra_canonical_effect
    lea r13, [r12 + 256]
    cmp ebp, 3
    je runtime_extra_client_record
    cmp ebp, 5
    je runtime_extra_session_record
    cmp ebp, 7
    jne runtime_extra_invalid
    mov rax, 0x3130304143504c48
    jmp runtime_extra_custom_record
runtime_extra_client_record:
    mov rax, 0x313041434d435248
    jmp runtime_extra_custom_record
runtime_extra_session_record:
    mov rax, 0x3130415043535248
runtime_extra_custom_record:
    cmp [r13], rax
    jne runtime_extra_invalid
    mov rax, [rbx + 24]
    inc rax
    jz runtime_extra_invalid
    cmp [r13 + 8], rax
    jne runtime_extra_invalid
    cmp [r12 + 16], rax
    jne runtime_extra_invalid
    mov [rbx + 24], rax
    mov rax, [r13 + 24]
    or rax, [r13 + 64]
    or rax, [r13 + 72]
    or rax, [r13 + 80]
    or rax, [r13 + 88]
    jnz runtime_extra_invalid
    cmp qword ptr [r13 + 32], 4096
    jne runtime_extra_invalid
    cmp qword ptr [r13 + 48], 67117056
    jne runtime_extra_invalid
    mov rsi, [r13 + 40]
    cmp rsi, 67108864
    ja runtime_extra_invalid
    mov rax, [r13 + 16]
    mov rcx, [r13 + 56]
    cmp ebp, 3
    je runtime_extra_client_child
    cmp ebp, 5
    je runtime_extra_session_child
    cmp rcx, 134217728
    jne runtime_extra_invalid
    cmp rax, 1
    je runtime_extra_policy_config
    cmp rax, 2
    jne runtime_extra_invalid
    mov r8d, 8
    jmp runtime_extra_custom_child_ready
runtime_extra_policy_config:
    mov r8d, 11
    jmp runtime_extra_custom_child_ready
runtime_extra_client_child:
    cmp rax, 1
    jne runtime_extra_invalid
    cmp rcx, 67108864
    jne runtime_extra_invalid
    mov r8d, 10
    jmp runtime_extra_custom_child_ready
runtime_extra_session_child:
    cmp rax, 1
    jb runtime_extra_invalid
    cmp rax, 4
    ja runtime_extra_invalid
    cmp rax, 1
    jne runtime_extra_session_not_state
    cmp rcx, 32
    jne runtime_extra_invalid
    mov r8d, 6
    jmp runtime_extra_custom_child_ready
runtime_extra_session_not_state:
    cmp rax, 2
    jne runtime_extra_session_not_value
    cmp rcx, 67108864
    jne runtime_extra_invalid
    mov r8d, 10
    jmp runtime_extra_custom_child_ready
runtime_extra_session_not_value:
    cmp rcx, 134217728
    jne runtime_extra_invalid
    mov r8d, 7
    cmp rax, 3
    je runtime_extra_custom_child_ready
    mov r8d, 8
runtime_extra_custom_child_ready:
    lea rdi, [r12 + 4096]
    lea rdx, [r12 + 67117056]
    call runtime_extra_invoke
    mov [r13 + 72], rax
    mov rax, [r13 + 8]
    mov [r13 + 64], rax
    jmp runtime_extra_resume
runtime_extra_canonical_effect:
    mov rdi, r12
    call runtime_canonical_effect
    jmp runtime_extra_resume

runtime_extra_view:
    mov rax, [r15 + 16]
    test rax, rax
    jnz runtime_extra_view_installed
    lea rdi, [rip + runtime_view_image_table]
    mov rsi, [r15 + 32]
    call view_engine_create
    cmp rax, -4095
    jae runtime_extra_resource
    mov [r15 + 16], rax
runtime_extra_view_installed:
    mov [rsp + 56], r15
    mov r15, rax
    mov rdi, [rsp]
    mov rsi, [rsp + 8]
    call view_call_run
    mov rbx, [r15 + 8]
    mov rsi, [rbx + 24]
    mov r15, [rsp + 56]
    cmp eax, 0xffff0000
    jae runtime_extra_done
    cmp rax, [rsp + 24]
    ja runtime_extra_capacity
    mov rdi, [rsp + 16]
    mov rcx, rax
    cld
    rep movsb
    jmp runtime_extra_done
runtime_extra_capacity:
    mov eax, 0xfffffffe
    jmp runtime_extra_done
runtime_extra_resource:
    mov eax, 0xfffffffc
    jmp runtime_extra_done
runtime_extra_invalid:
    mov eax, 0xffffffff
runtime_extra_done:
    add rsp, 64
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret

runtime_boundary_abort:
    mov edi, 111
    mov eax, 60
    syscall
    ud2
runtime_session_option:
    .asciz "--session-root"
runtime_gateway_slots:
    .byte 4, 5, 6, 11, 9, 7, 12
.balign 8
runtime_extra_image_table:
    .zero 96
runtime_view_image_table:
    .zero 96
