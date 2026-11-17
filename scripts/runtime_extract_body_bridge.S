/* Extract callable attachment. The process hub owns shared locks/history.
 * Engine+456 is transferred with its actual caller chain while lock WAIT
 * suspends. Only an HIA-selected wake or actual future Drop resumes it. */
.intel_syntax noprefix
.section .text
.global runtime_extract_body_owned
.global runtime_extract_body_resume
.global runtime_extract_body_release
.global runtime_extract_body_release_context
.global runtime_extract_body_hint
runtime_extract_body_owned:
    xor edx,edx
    jmp rex_body_entry
/* rdx 2=actual lock wake; 3=actual future destruction after transport close. */
runtime_extract_body_resume:
    cmp rdx,2
    je rex_body_entry
    cmp rdx,3
    je rex_body_entry
    mov eax,0xffffffff
    ret
rex_body_entry:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    sub rsp,32
    mov [rsp],rdi
    mov [rsp+8],rsi
    mov [rsp+16],rdx
    mov rbx,[r15+8]
    add rbx,63*64
    lea rbp,[r15+512+63*64]
    cmp qword ptr [rbp+8],0
    jne rex_invalid
    test rdx,rdx
    jnz rex_resume_admit
    cmp qword ptr [rbp],0
    jne rex_invalid
    mov qword ptr [rbp],1
    mov qword ptr [rbx+48],0
    mov qword ptr [rbx+56],0
    mov r14,[r15+400]
    test r14,r14
    jz rex_invalid_active
    mov rax,0x3142554842544c48
    cmp [r14],rax
    jne rex_invalid_active
    mov r12,[r15+456]
    test r12,r12
    jnz rex_existing
    mov edi,4096
    call view_allocate
    cmp rax,-4095
    jae rex_resource_active
    mov r12,rax
    mov [r15+456],rax
    mov [r12+256+168],r15
    jmp rex_context_ready
rex_existing:
    mov rdi,r12
    call runtime_extract_wait_unlink
    test eax,eax
    jnz rex_invalid_active
    cmp qword ptr [r12+152],0
    je rex_context_ready
    mov rdi,r12
    call local_extract_lines_release
    test eax,eax
    jnz rex_invalid_active
rex_context_ready:
    mov rdi,r12
    xor eax,eax
    mov ecx,24
    rep stosq
    mov rax,0x3130494354584548
    mov [r12],rax
    mov qword ptr [r12+8],192
    lea rax,[rip+runtime_extract_body_images]
    mov [r12+16],rax
    lea rax,[rip + runtime_extract_cache]
    mov [r12+24],rax
    lea rax,[r12+256]
    mov [r12+32],rax
    mov [r12+48],rax
    lea rax,[rip + runtime_extract_body_hint]
    mov [r12+40],rax
    lea rax,[r14+64]
    mov [r12+56],rax
    lea rax,[r14+128]
    mov [r12+64],rax
    lea rax,[rip + runtime_text_body_shared_grow]
    mov [r12+72],rax
    mov [r12+80],r14
    lea rax,[r14+8]
    mov [r12+88],rax
    mov rax,[r15+32]
    mov [r12+96],rax
    mov rdi,r12
    mov rsi,[rsp]
    mov rdx,[rsp+8]
    inc qword ptr [r15+128]
    call local_extract_lines_run
    jmp rex_actual_return
rex_resume_admit:
    cmp qword ptr [rbp],1
    jne rex_invalid
    mov eax,0xffffffdf
    cmp [rbx+48],rax
    jne rex_invalid
    cmp qword ptr [rbx+56],0
    jne rex_invalid
    mov r12,[r15+456]
    test r12,r12
    jz rex_invalid
    mov rax,[r15+400]
    cmp [r12+80],rax
    jne rex_invalid
    cmp [r12+256+168],r15
    jne rex_invalid
    cmp qword ptr [r12+XW_LINKED],1
    jne rex_invalid
    cmp qword ptr [rsp+16],3
    je rex_resume_drop
    cmp qword ptr [r12+XW_READY],1
    jne rex_invalid
    mov qword ptr [r12+XW_READY],0
    mov rdi,r12
    inc qword ptr [r15+128]
    call local_extract_lines_resume
    jmp rex_actual_return
rex_resume_drop:
    mov rdi,r12
    inc qword ptr [r15+128]
    call local_extract_lines_cancel_wait
rex_actual_return:
    mov edx,eax
    cmp rax,rdx
    jne rex_invalid_active
    cmp [r12+128],rax
    jne rex_invalid_active
    cmp eax,0xffffffdf
    je rex_undrained
    cmp qword ptr [r12+136],1
    jne rex_invalid_active
    cmp qword ptr [r12+144],1
    jne rex_invalid_active
    cmp qword ptr [r12+160],0
    jne rex_invalid_active
    mov [rsp+24],rax
    mov rdi,r12
    call runtime_extract_wait_unlink
    test eax,eax
    jnz rex_invalid_active
    mov rax,[rsp+24]
    mov [rbx+48],rax
    mov rcx,[r12+112]
    mov [rbx+32],rcx
    mov rcx,[r12+120]
    mov [rbx+40],rcx
    mov [rbx+56],rcx
    cmp eax,0xffff0000
    jae rex_private
    cmp rax,rcx
    jne rex_invalid_active
    jmp rex_complete
rex_private:
    test rcx,rcx
    jnz rex_invalid_active
    jmp rex_complete
rex_resource_active:
    mov eax,0xfffffffc
    jmp rex_error
rex_invalid_active:
    mov eax,0xffffffff
rex_error:
    mov [rbx+48],rax
    mov qword ptr [rbx+56],0
rex_complete:
    mov qword ptr [rbp],0
    jmp rex_done
rex_undrained:
    mov rdi,r12
    call runtime_extract_wait_link
    test eax,eax
    jnz rex_invalid_active
    mov eax,0xffffffdf
    mov [rbx+48],rax
    mov qword ptr [rbx+56],0
    jmp rex_done
rex_invalid:
    mov eax,0xffffffff
rex_done:
    add rsp,32
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

/* Same request Scope receives each actual HIA hint before caller DRAIN. */
runtime_extract_body_hint:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp, 72
    mov r12, rdi
    mov [rsp], rsi
    mov [rsp + 8], rdx
    mov [rsp + 16], rcx
    cmp rdx, 32
    jb rexh_hint_invalid
    mov rax, 0x3130514842544c48 /* HLTBHQ01 */
    cmp [rsi], rax
    jne rexh_hint_invalid
    cmp qword ptr [rsi + 8], 1
    jne rexh_hint_invalid
    cmp qword ptr [rsi + 24], 0
    jne rexh_hint_invalid
    sub rdx, 32
    cmp [rsi + 16], rdx
    jne rexh_hint_invalid
    mov r14, [r12 + 168]
    test r14, r14
    jz rexh_hint_invalid
    mov rbx, [r14 + 8]
    mov rbx, [rbx + 61*64 + 8]
    test rbx, rbx
    jz rexh_hint_invalid
    cmp qword ptr [rbx + 416], 1
    jne rexh_hint_invalid
    mov rax, [rbx + 112]
    test rax, rax
    jz rexh_hint_invalid
    mov [rsp + 24], rax
    mov rax, [rbx + 120]
    test rax, rax
    jz rexh_hint_invalid
    mov [rsp + 32], rax
    add rdx, 64
    jc rexh_hint_resource
    cmp rdx, [r12 + 192]
    jbe rexh_hint_frame
    add rdx, 4095
    jc rexh_hint_resource
    and rdx, -4096
    test rdx, rdx
    jle rexh_hint_resource
    mov r13, rdx
    mov rdi, [r12 + 184]
    test rdi, rdi
    jz rexh_hint_allocate
    mov rsi, [r12 + 192]
    call view_resize
    jmp rexh_hint_allocated
rexh_hint_allocate:
    mov rdi, r13
    call view_allocate
rexh_hint_allocated:
    cmp rax, -4095
    jae rexh_hint_resource
    mov [r12 + 184], rax
    mov [r12 + 192], r13
rexh_hint_frame:
    mov rbp, [r12 + 184]
    mov rdi, rbp
    xor eax, eax
    mov ecx, 8
    rep stosq
    mov rax, 0x3130305143535248 /* HRSCQ001 */
    mov [rbp], rax
    mov qword ptr [rbp + 8], 3
    mov rax, [rsp + 24]
    mov [rbp + 16], rax
    mov rax, [rsp + 32]
    mov [rbp + 24], rax
    mov rcx, [rsp + 8]
    sub rcx, 32
    mov [rbp + 48], rcx
    lea rdi, [rbp + 64]
    mov rsi, [rsp]
    add rsi, 32
    rep movsb
    mov r15, [r14 + 16]
    test r15, r15
    jz rexh_hint_invalid
    mov r13, [r15 + 8]
    add r13, 6*64
    mov rax, [r13 + 32]
    cmp rax, 64
    jb rexh_hint_invalid
    mov [rsp + 40], rax
    mov qword ptr [r13 + 32], 64
    mov rdi, rbp
    mov rsi, [rsp + 8]
    add rsi, 32
    mov edx, 6
    call view_scope_invoke
    mov rdx, [rsp + 40]
    mov [r13 + 32], rdx
    cmp rax, 64
    jne rexh_hint_invalid
    mov rdx, [r13 + 24]
    mov rax, 0x3130305243535248 /* HRSCR001 */
    cmp [rdx], rax
    jne rexh_hint_invalid
    mov rax, [rsp + 24]
    cmp [rdx + 8], rax
    jne rexh_hint_invalid
    mov rax, [rsp + 32]
    cmp [rdx + 16], rax
    jne rexh_hint_invalid
    cmp qword ptr [rdx + 24], 1
    jne rexh_hint_invalid
    mov rax, [rdx + 32]
    or rax, [rdx + 56]
    jnz rexh_hint_invalid
    mov rax, [rbx + 96]
    cmp [rdx + 40], rax
    jne rexh_hint_invalid
    mov rax, [rbx + 128]
    cmp [rdx + 48], rax
    jne rexh_hint_invalid
    mov rcx, [rsp + 16]
    lea rax, [rip + rexh_hint_reply]
    mov [rcx], rax
    mov qword ptr [rcx + 8], 32
    mov eax, 32
    jmp rexh_hint_done
rexh_hint_resource:
    mov eax, 0xfffffffc
    jmp rexh_hint_done
rexh_hint_invalid:
    mov eax, 0xffffffff
rexh_hint_done:
    add rsp, 72
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

runtime_extract_body_release:
    sub rsp,8
    mov rdi,[r15+456]
    call runtime_extract_body_release_context
    test eax,eax
    jnz rexh_release_engine_done
    mov qword ptr [r15+456],0
rexh_release_engine_done:
    add rsp,8
    ret

/* Release the exact detached node's context, never another engine borrow. */
runtime_extract_body_release_context:
    push rbx
    mov rbx,rdi
    test rbx,rbx
    jz rexh_release_success
    mov rdi,rbx
    call runtime_extract_wait_unlink
    test eax,eax
    jnz rexh_release_done
    cmp qword ptr [rbx+XW_LINKED],0
    jne rexh_release_invalid
    cmp qword ptr [rbx+152],0
    je rexh_release_frame
    mov rdi,rbx
    call local_extract_lines_release
    test eax,eax
    jnz rexh_release_done
rexh_release_frame:
    mov rdi,[rbx+256+184]
    test rdi,rdi
    jz rexh_release_control
    mov rsi,[rbx+256+192]
    add rsi,4096
    jc rexh_release_invalid
    mov eax,11
    syscall
    test rax,rax
    jnz rexh_release_done
    mov qword ptr [rbx+256+184],0
    mov qword ptr [rbx+256+192],0
rexh_release_control:
    mov rdi,rbx
    mov esi,8192
    mov eax,11
    syscall
    test rax,rax
    jnz rexh_release_done
rexh_release_success:
    xor eax,eax
    jmp rexh_release_done
rexh_release_invalid:
    mov eax,0xffffffff
rexh_release_done:
    pop rbx
    ret
.balign 8
rexh_hint_reply:
    .ascii "HLTBHP01"
    .zero 24
runtime_extract_body_images:
    .zero 112
