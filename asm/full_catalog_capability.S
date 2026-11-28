/* Copyright 2026 TrillionniumFoundation
 * SPDX-License-Identifier: Apache-2.0
 * Fixed three-buffer boundary for the HIA catalog pipeline.
 * HIA selects every policy step and owns every JSON byte. This boundary
 * supplies immutable declaration bytes and performs bounded fixed image calls.
 */
.intel_syntax noprefix
.section .text
.global _start
.type _start,@function
_start:
    push rbp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub rsp,104
    mov [rsp],rdi
    mov [rsp+8],rsi
    mov [rsp+16],rdx
    mov [rsp+24],rcx
    mov [rsp+32],r8
    mov [rsp+40],r9
    mov qword ptr [rsp+48],0
    mov qword ptr [rsp+72],0
    add rsi,32
    jc .Lfc_resource_unmapped
    mov [rsp+56],rsi
    xor edi,edi
    mov edx,3
    mov r10d,34
    mov r8,-1
    xor r9d,r9d
    mov eax,9
    syscall
    cmp rax,-4095
    jae .Lfc_resource_unmapped
    mov [rsp+48],rax
    mov r12,rax
    mov r13,[rsp+32]
    mov r14,[rsp+40]
    mov rax,FC_FRAME
    mov [r12],rax
    mov qword ptr [r12+8],0
    mov rax,[rsp+8]
    mov [r12+16],rax
    mov qword ptr [r12+24],0
    lea rdi,[r12+32]
    mov rsi,[rsp]
    mov rcx,[rsp+8]
    cld
    rep movsb
.Lfc_owner:
    mov rdi,r12
    mov rsi,[rsp+56]
    mov rdx,[rsp+16]
    mov rcx,[rsp+24]
    mov r8,r13
    mov r9,r14
    call full_catalog_owner
    cmp eax,0xffffffb1
    je .Lfc_action
    cmp eax,0xffffffb2
    je .Lfc_old
    jmp .Lfc_return
.Lfc_action:
    inc qword ptr [rsp+72]
    cmp qword ptr [rsp+72],4
    ja .Lfc_invalid
    cmp r14,FC_TOTAL
    jb .Lfc_invalid
    mov rax,[r13+8]
    cmp rax,1
    je .Lfc_data
    cmp rax,2
    jne .Lfc_invalid
    cmp qword ptr [r13+16],2
    ja .Lfc_invalid
    cmp qword ptr [r13+24],FC_REQUEST
    jne .Lfc_invalid
    cmp qword ptr [r13+32],FC_FRAME_CAP
    ja .Lfc_invalid
    cmp qword ptr [r13+40],FC_REPLY
    jne .Lfc_invalid
    cmp qword ptr [r13+48],FC_FRAME_CAP
    jne .Lfc_invalid
    cmp qword ptr [r13+56],FC_WORK
    jne .Lfc_invalid
    cmp qword ptr [r13+64],FC_SDK_WORK
    ja .Lfc_invalid
    lea rdi,[r13+FC_REQUEST]
    mov rsi,[r13+32]
    lea rdx,[r13+FC_REPLY]
    mov ecx,FC_FRAME_CAP
    lea r8,[r13+FC_WORK]
    mov r9,[r13+64]
    mov rax,[r13+16]
    test rax,rax
    jz .Lfc_policy
    cmp rax,1
    je .Lfc_value
    call full_catalog_sdk
    jmp .Lfc_resume
.Lfc_policy:
    call full_catalog_policy
    jmp .Lfc_resume
.Lfc_value:
    call full_catalog_value
.Lfc_resume:
    mov eax,eax
    mov [r12+24],rax
    mov qword ptr [r12+8],1
    jmp .Lfc_owner
.Lfc_data:
    lea rdi,[r13+FC_REQUEST+64]
    lea rsi,[rip+.Lfc_declarations]
    mov ecx,FC_DECLARATION_BYTES
    cld
    rep movsb
    xor eax,eax
    jmp .Lfc_resume
.Lfc_old:
    mov rdi,[rsp]
    mov rsi,[rsp+8]
    mov rdx,[rsp+16]
    mov rcx,[rsp+24]
    mov r8,[rsp+32]
    mov r9,[rsp+40]
    call full_catalog_retained
    jmp .Lfc_return
.Lfc_invalid:
    mov eax,0xffffffff
.Lfc_return:
    mov [rsp+64],eax
    mov rdi,[rsp+48]
    mov rsi,[rsp+56]
    mov eax,11
    syscall
    test rax,rax
    jnz .Lfc_resource_unmapped
    mov eax,[rsp+64]
    jmp .Lfc_exit
.Lfc_resource_unmapped:
    mov eax,0xfffffffe
.Lfc_exit:
    add rsp,104
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret
.size _start,.-_start

full_catalog_owner:
    .byte 0xe9
.global full_catalog_owner_displacement
full_catalog_owner_displacement:
    .long 0
full_catalog_policy:
    .byte 0xe9
.global full_catalog_policy_displacement
full_catalog_policy_displacement:
    .long 0
full_catalog_value:
    .byte 0xe9
.global full_catalog_value_displacement
full_catalog_value_displacement:
    .long 0
full_catalog_sdk:
    .byte 0xe9
.global full_catalog_sdk_displacement
full_catalog_sdk_displacement:
    .long 0
full_catalog_retained:
    .byte 0xe9
.global full_catalog_retained_displacement
full_catalog_retained_displacement:
    .long 0
.p2align 3
.Lfc_declarations:
    .incbin "__DECLARATIONS__"
.Lfc_declarations_end:
.if .Lfc_declarations_end-.Lfc_declarations != FC_DECLARATION_BYTES
.error "complete declaration byte extent differs"
.endif
