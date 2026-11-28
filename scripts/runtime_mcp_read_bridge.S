/* Copyright 2026 Muvon Un Limited
 * Copyright 2026 TrillionniumFoundation
 * SPDX-License-Identifier: Apache-2.0
 * Fixed slot74: one owned SSH caller future. HIA owns the argv, payload,
 * protocol and result; this bridge owns the request's physical mappings. */
.intel_syntax noprefix
.section .text
.global runtime_read_public_owned
runtime_read_public_owned:
    xor edx,edx
    jmp rrp_entry
.global runtime_read_public_resume
runtime_read_public_resume:
    cmp rdx,2
    je rrp_entry
    cmp rdx,3
    je rrp_entry
    mov eax,0xffffffff
    ret
rrp_entry:
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
    add rbx,74*64
    lea rbp,[r15+512+74*64]
    cmp qword ptr [rbp+8],0
    jne rrp_invalid
    test rdx,rdx
    jnz rrp_resume
    cmp qword ptr [rbp],0
    jne rrp_invalid
    mov qword ptr [rbp],1
    mov qword ptr [rbx+48],0
    mov qword ptr [rbx+56],0
    mov r14,[r15+472]
    test r14,r14
    jz rrp_invalid_active
    mov r13,[r14]
    test r13,r13
    jnz rrp_hub
    mov rdi,[r15+480] /* Original process envp, supplied only by the host. */
    test rdi,rdi
    jz rrp_invalid_active
    mov rax,[r15]
    mov rsi,[rax+74*8]
    mov rdx,[rax+79*8]
    mov rcx,[rax+78*8]
    mov r8,[rax+80*8]
    call runtime_read_hub_create
    cmp rax,-4095
    jae rrp_resource_active
    test rax,rax
    jz rrp_invalid_active
    mov r13,rax
    mov [r14],rax
rrp_hub:
    mov r12,[rbx+8]
    test r12,r12
    jnz rrp_reset
    mov edi,4096
    call view_allocate
    cmp rax,-4095
    jae rrp_resource_active
    mov r12,rax
    mov [rbx+8],rax
    mov qword ptr [rbx+16],4096
    bts qword ptr [r15+RG_WORK_HIGH],10
    jmp rrp_start
rrp_reset:
    cmp qword ptr [rbx+16],4096
    jne rrp_invalid_active
    cmp qword ptr [r12+8],1
    je rrp_invalid_active
    mov rdi,r12
    call runtime_read_request_reset
    test rax,rax
    jnz rrp_invalid_active
rrp_start:
    mov qword ptr [rbx+32],0
    mov qword ptr [rbx+40],0
    mov rdi,r12
    mov rsi,r13
    mov rdx,[rsp]
    mov rcx,[rsp+8]
    inc qword ptr [r15+128]
    call runtime_read_request_start
    test rax,rax
    jnz rrp_resource_active
    mov [r12+456],r15
    jmp rrp_poll
rrp_resume:
    cmp qword ptr [rbp],1
    jne rrp_invalid
    mov eax,0xffffffdf
    cmp [rbx+48],rax
    jne rrp_invalid
    cmp qword ptr [rbx+56],0
    jne rrp_invalid
    mov r12,[rbx+8]
    test r12,r12
    jz rrp_invalid
    cmp qword ptr [rbx+16],4096
    jne rrp_invalid
    cmp [r12+456],r15
    jne rrp_invalid
    mov rax,[rsp]
    cmp [r12+48],rax
    jne rrp_invalid
    mov rax,[rsp+8]
    cmp [r12+56],rax
    jne rrp_invalid
    cmp qword ptr [rsp+16],3
    je rrp_drop
rrp_poll:
    mov rdi,r12
    call runtime_read_request_poll
    cmp rax,1
    je rrp_wait
    test rax,rax
    jnz rrp_resource_active
    cmp qword ptr [r12+8],2
    jne rrp_invalid_active
    mov rax,[r12+224]
    test rax,rax
    jz rrp_invalid_active
    mov [rbx+32],rax
    mov rax,[r12+232]
    mov [rbx+40],rax
    mov rcx,[r12+448]
    cmp rcx,128
    jb rrp_invalid_active
    cmp rcx,rax
    ja rrp_invalid_active
    mov [rbx+56],rcx
    mov eax,128
    mov [rbx+48],rax
    jmp rrp_complete
rrp_drop:
    mov rdi,r12
    call runtime_read_request_drop
    test rax,rax
    jnz rrp_invalid_active
    mov qword ptr [rbx+32],0
    mov qword ptr [rbx+40],0
    mov eax,0xfffffff7 /* Original private handler-future destruction. */
    mov [rbx+48],rax
    mov qword ptr [rbx+56],0
    jmp rrp_complete
rrp_wait:
    mov eax,0xffffffdf
    mov [rbx+48],rax
    mov qword ptr [rbx+56],0
    jmp rrp_done
rrp_resource_active:
    mov eax,0xfffffffc
    jmp rrp_error
rrp_invalid_active:
    mov eax,0xffffffff
rrp_error:
    mov [rbx+48],rax
    mov qword ptr [rbx+56],0
rrp_complete:
    mov qword ptr [rbp],0
    jmp rrp_done
rrp_invalid:
    mov eax,0xffffffff
rrp_done:
    add rsp,32
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

/* Original process singleton lives until process exit, like its source owner.
 * This entry is called only after every service has dropped its handlers. */
runtime_read_public_close:
    mov rdi,[rdi] /* Trusted process-owned singleton cell. */
    test rdi,rdi
    jz rrp_closed
    jmp runtime_read_hub_shutdown
rrp_closed:
    xor eax,eax
    ret

/* Engine destruction settles every local mapping before the control arena. */
runtime_read_public_destroy:
    push rbx
    mov rbx,[r15+8]
    add rbx,74*64
    mov rdi,[rbx+8]
    test rdi,rdi
    jz rrp_destroyed
    cmp qword ptr [rdi+8],1
    je rrp_destroy_invalid
    call runtime_read_request_reset
    test rax,rax
    jnz rrp_destroy_return
    mov qword ptr [rbx+32],0
    mov qword ptr [rbx+40],0
    mov qword ptr [rbx+48],0
    mov qword ptr [rbx+56],0
rrp_destroyed:
    xor eax,eax
    jmp rrp_destroy_return
rrp_destroy_invalid:
    mov rax,-22
rrp_destroy_return:
    pop rbx
    ret

