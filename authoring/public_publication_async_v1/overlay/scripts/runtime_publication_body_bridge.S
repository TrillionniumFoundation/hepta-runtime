/* Copyright 2026 Muvon Un Limited
 * SPDX-License-Identifier: Apache-2.0
 * Fixed descriptor67 future for the qualified publication worker. A worker
 * owns its complete input and body mappings. This request owns only the
 * native capability below and the HIA caller's unfinished await.
 */
.intel_syntax noprefix
.section .text
.equ PA_MAGIC,0x3130435741505448 /* HTPAWC01 */
.equ PA_POOL,32
.equ PA_JOB,40
.equ PA_TAG,48
.equ PA_STAGE,56
.equ PA_NODE,64
.equ PA_OUT,128
.equ PA_BORROW,448
.global runtime_publication_body_owned
.global runtime_publication_body_resume
.global runtime_publication_body_destroy
.global runtime_publication_body_release_context

runtime_publication_body_owned:
    xor edx,edx
    jmp rpa_entry
/* Private command2 polls the real job. Command3 destroys this handler future,
 * never its blocking body and never in response to notifications/cancelled. */
runtime_publication_body_resume:
    cmp rdx,2
    je rpa_entry
    cmp rdx,3
    je rpa_entry
    mov eax,0xffffffff
    ret
rpa_entry:
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
    add rbx,67*64
    lea rbp,[r15+512+67*64]
    cmp qword ptr [rbp+8],0
    jne rpa_invalid
    /* The input is the actual child2 loan of the installed caller66. */
    mov r13,[r15+8]
    add r13,66*64
    cmp qword ptr [r13+16],4096
    jb rpa_invalid
    mov r14,[r13+8]
    test r14,r14
    jz rpa_invalid
    cmp qword ptr [r14+8],3
    jne rpa_invalid
    cmp qword ptr [r14+48],2
    jne rpa_invalid
    cmp qword ptr [r14+440],0
    jne rpa_invalid
    cmp qword ptr [r14+416],1
    jne rpa_invalid
    cmp qword ptr [r15+512+66*64],1
    jne rpa_invalid
    cmp qword ptr [r15+512+66*64+24],67
    jne rpa_invalid
    mov rcx,[r13+24]
    test rcx,rcx
    jz rpa_invalid
    cmp [r14+16],rcx
    jne rpa_invalid
    cmp [r14+264],rcx
    jne rpa_invalid
    cmp [r15+512+66*64+16],rcx
    jne rpa_invalid
    mov rax,[r14+288]
    cmp rax,4096
    jb rpa_invalid
    cmp rax,[r13+16]
    ja rpa_invalid
    mov rdx,[r13+16]
    sub rdx,rax
    cmp [rsp+8],rdx
    ja rpa_invalid
    add rax,r14
    cmp [rsp],rax
    jne rpa_invalid
    mov rax,[rsp+8]
    cmp [r14+296],rax
    jne rpa_invalid
    cmp [r15+512+66*64+40],rax
    jne rpa_invalid
    mov rax,[r14+288]
    cmp [r15+512+66*64+32],rax
    jne rpa_invalid
    cmp qword ptr [rsp+16],0
    jne rpa_resume_admit
    cmp qword ptr [rbp],0
    jne rpa_invalid
    cmp qword ptr [rbx+8],0
    je rpa_new_context
    /* An ordinary private serial carrier may consume the prior settled loan
     * before its next real call. Public tasks detach that loan instead. */
    mov rdi,[rbx+8]
    call runtime_publication_body_release_context
    test eax,eax
    jnz rpa_invalid
    lea rdi,[rbx+8]
    xor eax,eax
    mov ecx,7
    rep stosq
rpa_new_context:
    cmp qword ptr [rbx+16],0
    jne rpa_invalid
    mov r14,[r15+400]
    test r14,r14
    jz rpa_invalid
    mov rax,0x3142554842544c48 /* HLTBHUB1 */
    cmp [r14],rax
    jne rpa_invalid
    cmp qword ptr [r14+216],0
    jne rpa_pool_present
    mov edi,512
    xor esi,esi
    xor edx,edx
    call runtime_publication_worker_create
    cmp rax,-4095
    jae rpa_resource
    test rax,rax
    jz rpa_resource
    mov [r14+216],rax
rpa_pool_present:
    mov edi,4096
    call view_allocate
    cmp rax,-4095
    jae rpa_resource
    mov r12,rax
    mov [rbx+8],rax
    mov qword ptr [rbx+16],4096
    mov rax,PA_MAGIC
    mov [r12],rax
    mov qword ptr [r12+8],4096
    mov [r12+16],r15
    mov [r12+24],r14
    mov rax,[r14+216]
    mov [r12+PA_POOL],rax
    mov rax,[r13+24]
    mov [r12+PA_TAG],rax
    mov qword ptr [rbp],1
    mov qword ptr [rbx+48],0
    mov qword ptr [rbx+56],0
    mov rdi,[r12+PA_POOL]
    mov rsi,[rsp]
    mov rdx,[rsp+8]
    mov rcx,[r12+PA_TAG]
    lea r8,[r12+PA_OUT]
    call publication_worker_submit
    cmp eax,320
    jne rpa_invalid_active
    cmp qword ptr [r12+PA_OUT+16],0
    jne rpa_invalid_active
    mov rax,[r12+PA_OUT+32]
    test rax,rax
    jz rpa_invalid_active
    mov [r12+PA_JOB],rax
    mov qword ptr [r12+PA_STAGE],1
    jmp rpa_poll
rpa_resume_admit:
    cmp qword ptr [rbp],1
    jne rpa_invalid
    mov eax,0xffffffdf
    cmp [rbx+48],rax
    jne rpa_invalid
    cmp qword ptr [rbx+56],0
    jne rpa_invalid
    mov r12,[rbx+8]
    test r12,r12
    jz rpa_invalid
    cmp qword ptr [rbx+16],4096
    jne rpa_invalid
    mov rax,PA_MAGIC
    cmp [r12],rax
    jne rpa_invalid
    cmp qword ptr [r12+8],4096
    jne rpa_invalid
    cmp [r12+16],r15
    jne rpa_invalid
    mov rax,[r15+400]
    cmp [r12+24],rax
    jne rpa_invalid
    mov rax,[rax+216]
    cmp [r12+PA_POOL],rax
    jne rpa_invalid
    mov rax,[r13+24]
    cmp [r12+PA_TAG],rax
    jne rpa_invalid
    cmp qword ptr [r12+PA_STAGE],1
    jne rpa_invalid
    cmp qword ptr [r12+PA_JOB],0
    je rpa_invalid
    cmp qword ptr [rsp+16],3
    je rpa_drop
rpa_poll:
    mov rdi,[r12+PA_POOL]
    mov rsi,[r12+PA_JOB]
    lea rdx,[r12+PA_OUT]
    call publication_worker_poll
    cmp eax,320
    jne rpa_invalid_active
    cmp qword ptr [r12+PA_OUT+16],2
    je rpa_wait
    cmp qword ptr [r12+PA_OUT+16],0
    jne rpa_invalid_active
    mov rdi,[r12+PA_POOL]
    mov rsi,[r12+PA_JOB]
    lea rdx,[r12+PA_OUT]
    lea rcx,[r12+PA_BORROW]
    call publication_worker_take
    cmp eax,320
    jne rpa_invalid_active
    cmp qword ptr [r12+PA_OUT+16],0
    jne rpa_invalid_active
    mov qword ptr [r12+PA_STAGE],2
    mov rax,0x3130304257545048 /* HPTWB001 */
    cmp [r12+PA_BORROW],rax
    jne rpa_invalid_active
    cmp qword ptr [r12+PA_BORROW+8],64
    jne rpa_invalid_active
    mov rax,[r12+PA_JOB]
    cmp [r12+PA_BORROW+16],rax
    jne rpa_invalid_active
    mov rax,[r12+PA_TAG]
    cmp [r12+PA_BORROW+48],rax
    jne rpa_invalid_active
    cmp qword ptr [r12+PA_BORROW+56],0
    jne rpa_invalid_active
    cmp qword ptr [r12+PA_BORROW+24],64
    jne rpa_invalid_active
    mov r13,[r12+PA_BORROW+32]
    mov r14,[r12+PA_BORROW+40]
    test r13,r13
    jz rpa_invalid_active
    cmp r14,64
    jb rpa_invalid_active
    mov rax,0x3130305342505448 /* HTPBS001 */
    cmp [r13],rax
    jne rpa_invalid_active
    mov rax,[r13+8]
    test rax,rax
    jz rpa_body_header
    cmp rax,3
    jne rpa_invalid_active
rpa_body_header:
    mov rax,[r13+24]
    or rax,[r13+32]
    or rax,[r13+40]
    or rax,[r13+48]
    jnz rpa_invalid_active
    mov rax,r14
    sub rax,64
    cmp [r13+56],rax
    jne rpa_invalid_active
    mov [rbx+32],r13
    mov [rbx+40],r14
    mov qword ptr [rbx+48],64
    mov [rbx+56],r14
    mov qword ptr [rbp],0
    mov eax,64
    jmp rpa_done
rpa_wait:
    mov eax,0xffffffdf
    mov [rbx+48],rax
    mov qword ptr [rbx+56],0
    jmp rpa_done
rpa_drop:
    mov rdi,[r12+PA_POOL]
    mov rsi,[r12+PA_JOB]
    call publication_worker_drop
    test eax,eax
    jnz rpa_invalid_active
    mov qword ptr [r12+PA_STAGE],3
    mov eax,0xfffffff7
    mov [rbx+48],rax
    mov qword ptr [rbx+56],0
    mov qword ptr [rbp],0
    jmp rpa_done
rpa_invalid_active:
    mov eax,0xffffffff
    mov [rbx+48],rax
    mov qword ptr [rbx+56],0
    mov qword ptr [rbp],0
    jmp rpa_done
rpa_resource:
    mov eax,0xfffffffc
    jmp rpa_done
rpa_invalid:
    mov eax,0xffffffff
rpa_done:
    add rsp,32
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

/* Default production is observer-off; a separate frozen fixture may wrap this
 * exact call site. Public arguments never select an observer or worker limit. */
runtime_publication_worker_create:
.if PM_FIXED_PUBLICATION_TRACE
    lea rsi,[rip+runtime_publication_worker_journal]
    mov edx,6
.endif
    jmp publication_worker_create

/* The parent has copied the complete body result before releasing this loan.
 * Dropped futures do not release/cancel a worker's still-running body. */
runtime_publication_body_release_context:
    push rbx
    mov rbx,rdi
    test rbx,rbx
    jz rpa_release_ok
    mov rax,PA_MAGIC
    cmp [rbx],rax
    jne rpa_release_invalid
    cmp qword ptr [rbx+8],4096
    jne rpa_release_invalid
    cmp qword ptr [rbx+PA_STAGE],3
    je rpa_release_mapping
    cmp qword ptr [rbx+PA_STAGE],2
    jne rpa_release_invalid
    mov rdi,[rbx+PA_POOL]
    mov rsi,[rbx+PA_JOB]
    call publication_worker_release
    test eax,eax
    jnz rpa_release_done
rpa_release_mapping:
    mov rdi,rbx
    mov esi,8192
    mov eax,11
    syscall
    test rax,rax
    jnz rpa_release_done
rpa_release_ok:
    xor eax,eax
    jmp rpa_release_done
rpa_release_invalid:
    mov eax,0xffffffff
rpa_release_done:
    pop rbx
    ret

runtime_publication_body_destroy:
    push rbx
    mov rbx,[r15+8]
    add rbx,67*64
    mov rax,[r15+512+67*64]
    or rax,[r15+512+67*64+8]
    jnz rpa_destroy_invalid
    mov rdi,[rbx+8]
    test rdi,rdi
    jz rpa_destroy_absent
    cmp qword ptr [rbx+16],4096
    jne rpa_destroy_invalid
    call runtime_publication_body_release_context
    test eax,eax
    jnz rpa_destroy_done
    lea rdi,[rbx+8]
    xor eax,eax
    mov ecx,7
    rep stosq
    jmp rpa_destroy_done
rpa_destroy_absent:
    mov rax,[rbx+16]
    or rax,[rbx+32]
    or rax,[rbx+40]
    jnz rpa_destroy_invalid
    xor eax,eax
    jmp rpa_destroy_done
rpa_destroy_invalid:
    mov eax,0xffffffff
rpa_destroy_done:
    pop rbx
    ret

/* Exact qualified observer, private FD6 selected only at compile time. */
runtime_publication_worker_journal:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp,72
    mov rbx,rdi
    mov r12,rsi
    mov r13,rdx
    mov r14,rcx
    mov r15,r8
    mov rdi,rsp
    xor eax,eax
    mov ecx,8
    rep stosq
    mov rax,0x3130524a57545048 /* HPTWJR01 */
    mov [rsp],rax
    mov [rsp+8],r13
    mov rax,[r12+96]
    mov [rsp+16],rax
    mov [rsp+24],r15
    mov [rsp+32],r12
    mov rax,[r12+8]
    mov [rsp+40],rax
    mov eax,39
    syscall
    mov [rsp+48],rax
    mov rdi,rbx
    mov rsi,rsp
    mov edx,64
    call .Lpa_write_all
    test rax,rax
    jnz runtime_publication_worker_journal_done
    mov rdi,rbx
    mov rsi,r14
    mov rdx,r15
    call .Lpa_write_all
runtime_publication_worker_journal_done:
    add rsp,72
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

.Lpa_write_all:
    push rbx
    push r12
    push r13
    push r14
    mov rbx, rdi
    mov r12, rsi
    mov r13, rdx
    xor r14d, r14d
.Lpa_write_loop:
    cmp r14, r13
    je .Lpa_write_success
    mov rdi, rbx
    lea rsi, [r12+r14]
    mov rdx, r13
    sub rdx, r14
    mov eax, 1
    syscall
    cmp rax, -4
    je .Lpa_write_loop
    test rax, rax
    jz .Lpa_write_zero
    cmp rax, -4095
    jae .Lpa_write_done
    add r14, rax
    jmp .Lpa_write_loop
.Lpa_write_zero:
    mov rax, -5
    jmp .Lpa_write_done
.Lpa_write_success:
    xor eax, eax
.Lpa_write_done:
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

