/* Copyright 2026 Muvon Un Limited
 * Copyright 2026 TrillionniumFoundation
 * SPDX-License-Identifier: Apache-2.0
 *
 * Fixed Linux x86-64 v12 metadata publication effects. The HIA actor owns
 * typed admission, canonical serialization, write ordering and cleanup.
 * Slot 0 borrows one retained audit-root capability; slot 1 owns only this
 * call's create-new temporary file. Names and operations form a closed domain.
 * Caller serializes create/step/child_ack/destroy; no concurrent free contract.
 * create(0,w,wcap,rootfd), step(ctx), child_ack(ctx,size,errno),
 * take(ctx,slot) always EPERM, destroy(ctx). System V position-independent ABI.
 */
.intel_syntax noprefix
.section .text
.macro SAVE
 push rbp
 push rbx
 push r12
 push r13
 push r14
 push r15
 sub rsp, 8
.endm
.macro RESTORE
 add rsp, 8
 pop r15
 pop r14
 pop r13
 pop r12
 pop rbx
 pop rbp
 ret
.endm
.equ PUB_MAGIC, 0x3130475741415248
.equ PUB_ACTION, 0x3130415741415248
.global durable_audit_archive_publication_create
.global durable_audit_archive_publication_step
.global durable_audit_archive_publication_child_ack
.global durable_audit_archive_publication_take
.global durable_audit_archive_publication_destroy

durable_audit_archive_publication_create:
 SAVE
 mov r12, rdi
 mov r13, rsi
 mov r14, rdx
 mov r15, rcx
 test r12, r12
 jnz .Lcreate_invalid
 test r13, r13
 jz .Lcreate_invalid
 cmp r14, 1048576
 jb .Lcreate_invalid
 test r15, r15
 js .Lcreate_invalid
 cmp r15, 0x7fffffff
 ja .Lcreate_invalid
 mov rbp, r14
 add rbp, 8192
 jc .Lcreate_invalid
 xor edi, edi
 mov rsi, rbp
 mov edx, 3
 mov r10d, 0x22
 mov r8, -1
 xor r9d, r9d
 mov eax, 9
 syscall
 cmp rax, -4095
 jae .Lcreate_done
 mov rbx, rax
 mov rdx, PUB_MAGIC
 mov [rbx], rdx
 mov [rbx+16], r13
 mov [rbx+24], r14
 mov [rbx+48], rbp
 mov [rbx+64], r15
 mov qword ptr [rbx+72], -1
 jmp .Lcreate_done
.Lcreate_invalid:
 mov rax, -22
.Lcreate_done:
 RESTORE

durable_audit_archive_publication_step:
 SAVE
 mov r12, rdi
 mov rax, PUB_MAGIC
 cmp [r12], rax
 jne .Linvalid
 cmp qword ptr [r12+8], 0
 jne .Linvalid
 cmp qword ptr [r12+40], 0
 jne .Lbusy
 mov r13, [r12+16]
 lea r14, [r13+256]
 call .Lrequest
 test eax, eax
 jnz .Linvalid
 mov rax, PUB_ACTION
 cmp [r14], rax
 jne .Linvalid
 mov rax, [r12+32]
 add rax, 1
 jc .Linvalid
 cmp [r14+8], rax
 jne .Linvalid
 mov rax, [r14+64]
 or rax, [r14+72]
 or rax, [r14+80]
 or rax, [r14+88]
 jnz .Linvalid
 mov r15, [r14+24]
 cmp r15, 1
 ja .Linvalid
 mov rax, [r14+32]
 cmp rax, [r12+24]
 ja .Linvalid
 add rax, [r14+40]
 jc .Linvalid
 cmp rax, [r12+24]
 ja .Linvalid
 mov rax, [r14+16]
 cmp rax, 1
 je .Lopen
 cmp rax, 7
 je .Lclose
 cmp rax, 10
 je .Lunlink
 cmp rax, 11
 je .Lsync
 cmp rax, 12
 je .Lrandom
 cmp rax, 13
 je .Lwrite
 cmp rax, 14
 je .Llink
 cmp rax, 15
 je .Lrename
 cmp rax, 100
 je .Lchild
 jmp .Linvalid

.Lopen:
 cmp r15, 1
 jne .Linvalid
 cmp qword ptr [r12+72], -1
 jne .Linvalid
 cmp qword ptr [r12+80], 0
 jne .Linvalid
 cmp qword ptr [r14+48], 0xa00c1
 jne .Linvalid
 cmp qword ptr [r14+56], 384
 jne .Linvalid
 call .Ltemporary
 test eax, eax
 jnz .Linvalid
 call .Lbegin
 mov rdi, [r12+64]
 lea rsi, [r12+416]
 mov edx, 0xa00c1
 mov r10d, 384
 mov eax, 257
 syscall
 cmp rax, -4095
 jae .Lcomplete
 cmp rax, 0x7fffffff
 ja .Linvalid_owned
 mov [r12+72], rax
 mov qword ptr [r12+56], 2
 xor eax, eax
 jmp .Lcomplete

.Lrandom:
 test r15, r15
 jnz .Linvalid
 cmp qword ptr [r12+72], -1
 jne .Linvalid
 cmp qword ptr [r12+80], 0
 jne .Linvalid
 mov rax, [r14+48]
 or rax, [r14+56]
 jnz .Linvalid
 cmp qword ptr [r14+32], 512
 jb .Linvalid
 cmp qword ptr [r14+40], 0
 je .Linvalid
 mov rax, [r14+32]
 add rax, [r14+40]
 cmp rax, 544
 ja .Linvalid
 call .Lbegin
 mov rdi, [r14+32]
 add rdi, r13
 mov rsi, [r14+40]
 xor edx, edx
 mov eax, 318
 syscall
 jmp .Lcomplete

.Lwrite:
 cmp r15, 1
 jne .Linvalid
 cmp qword ptr [r12+72], 0
 jl .Linvalid
 mov rax, [r14+48]
 or rax, [r14+56]
 jnz .Linvalid
 cmp qword ptr [r14+32], 278528
 jb .Linvalid
 cmp qword ptr [r14+40], 0
 je .Linvalid
 mov rax, [r14+32]
 add rax, [r14+40]
 cmp rax, 344064
 ja .Linvalid
 call .Lbegin
 mov rdi, [r12+72]
 mov rsi, [r14+32]
 add rsi, r13
 mov rdx, [r14+40]
 mov eax, 1
 syscall
 jmp .Lcomplete

.Llink:
 test r15, r15
 jnz .Linvalid
 cmp qword ptr [r12+8200], 2
 je .Linvalid
 cmp qword ptr [r12+72], 0
 jl .Linvalid
 call .Ltemporary
 test eax, eax
 jnz .Linvalid
 call .Ltarget
 test eax, eax
 jnz .Linvalid
 call .Lbegin
 mov rdi, [r12+64]
 lea rsi, [r12+416]
 mov rdx, rdi
 mov r10, rbx
 xor r8d, r8d
 mov eax, 265
 syscall
 jmp .Lcomplete

.Lrename:
 test r15, r15
 jnz .Linvalid
 cmp qword ptr [r12+8200], 2
 jne .Linvalid
 cmp qword ptr [r12+72], 0
 jl .Linvalid
 call .Ltemporary
 test eax, eax
 jnz .Linvalid
 call .Ltarget
 test eax, eax
 jnz .Linvalid
 call .Lbegin
 mov rdi, [r12+64]
 lea rsi, [r12+416]
 mov rdx, rdi
 mov r10, rbx
 mov eax, 264
 syscall
 jmp .Lcomplete

.Lunlink:
 test r15, r15
 jnz .Linvalid
 cmp qword ptr [r12+72], 0
 jl .Linvalid
 mov rax, [r14+48]
 or rax, [r14+56]
 jnz .Linvalid
 call .Ltemporary
 test eax, eax
 jnz .Linvalid
 call .Lbegin
 mov rdi, [r12+64]
 lea rsi, [r12+416]
 xor edx, edx
 mov eax, 263
 syscall
 jmp .Lcomplete

.Lsync:
 cmp qword ptr [r12+64+r15*8], 0
 jl .Linvalid
 call .Lzero_args
 test rax, rax
 jnz .Linvalid
 call .Lbegin
 mov rdi, [r12+64+r15*8]
 mov eax, 74
 syscall
 jmp .Lcomplete

.Lclose:
 cmp r15, 1
 jne .Linvalid
 cmp qword ptr [r12+72], 0
 jl .Linvalid
 cmp qword ptr [r12+56], 2
 jne .Linvalid
 call .Lzero_args
 test rax, rax
 jnz .Linvalid
 call .Lbegin
 mov rdi, [r12+72]
 mov qword ptr [r12+72], -1
 mov qword ptr [r12+56], 0
 mov eax, 3
 syscall
 jmp .Lcomplete

.Lchild:
 test r15, r15
 jnz .Linvalid
 cmp qword ptr [r12+8200], 2
 jne .Linvalid
 cmp qword ptr [r12+32], 0
 jne .Linvalid
 cmp qword ptr [r14+32], 1536
 jne .Linvalid
 cmp qword ptr [r14+40], 32
 jne .Linvalid
 cmp qword ptr [r14+48], 270336
 jne .Linvalid
 cmp qword ptr [r14+56], 4384
 jne .Linvalid
 mov rax, 0x3130514d41415248
 cmp [r13+1536], rax
 jne .Linvalid
 cmp qword ptr [r13+1544], 1
 jne .Linvalid
 mov rax, [r13+1552]
 or rax, [r13+1560]
 jnz .Linvalid
 call .Lbegin
 lea rsi, [r13+1536]
 lea rdi, [r12+512]
 mov ecx, 32
 cld
 rep movsb
 mov qword ptr [r12+40], 2
 mov eax, 1
 jmp .Ldone

.Lrequest:
 mov rax, 0x3130575741415248
 cmp [r13+232], rax
 jne .Lrequest_bad
 mov rax, [r12+24]
 cmp [r13+40], rax
 jne .Lrequest_bad
 mov rdx, [r13+16]
 cmp rdx, 160
 jb .Lrequest_bad
 mov rax, [r12+24]
 sub rax, 524288
 jc .Lrequest_bad
 cmp rdx, rax
 ja .Lrequest_bad
 cmp qword ptr [r12+112], 0
 jne .Lrequest_existing
 mov rax, 0x3130515741415248
 cmp [r13+524288], rax
 jne .Lrequest_bad
 mov rax, [r13+524296]
 cmp rax, 1
 jb .Lrequest_bad
 cmp rax, 3
 ja .Lrequest_bad
 cmp [r13+24], rax
 jne .Lrequest_bad
 mov rax, [r13+524304]
 add rax, 32
 jc .Lrequest_bad
 cmp rax, rdx
 jne .Lrequest_bad
 cmp qword ptr [r13+524312], 0
 jne .Lrequest_bad
 mov [r12+112], rdx
 mov rcx, rdx
 lea rsi, [r13+524288]
 lea rdi, [r12+8192]
 cld
 rep movsb
 xor eax, eax
 ret
.Lrequest_existing:
 cmp [r12+112], rdx
 jne .Lrequest_bad
 mov rax, [r12+8200]
 cmp [r13+24], rax
 jne .Lrequest_bad
 mov rcx, rdx
 lea rsi, [r13+524288]
 lea rdi, [r12+8192]
 cld
 repe cmpsb
 jne .Lrequest_bad
 xor eax, eax
 ret
.Lrequest_bad:
 mov eax, 1
 ret

.Ltemporary:
 cmp qword ptr [r14+32], 1024
 jne .Ltemp_bad
 cmp qword ptr [r12+8200], 3
 je .Ltemp_anchor
 cmp qword ptr [r14+40], 86
 jne .Ltemp_bad
 lea rdi, [rip+.Lintent_prefix]
 mov ecx, 18
 jmp .Ltemp_prefix
.Ltemp_anchor:
 cmp qword ptr [r14+40], 88
 jne .Ltemp_bad
 lea rdi, [rip+.Lanchor_prefix]
 mov ecx, 20
.Ltemp_prefix:
 lea rsi, [r13+1024]
 cld
 repe cmpsb
 jne .Ltemp_bad
 mov ecx, 64
.Ltemp_hex:
 lodsb
 cmp al, '0'
 jb .Ltemp_bad
 cmp al, '9'
 jbe .Ltemp_next
 cmp al, 'a'
 jb .Ltemp_bad
 cmp al, 'f'
 ja .Ltemp_bad
.Ltemp_next:
 dec ecx
 jnz .Ltemp_hex
 cmp dword ptr [rsi], 0x706d742e
 jne .Ltemp_bad
 cmp byte ptr [rsi+4], 0
 jne .Ltemp_bad
 mov rcx, [r14+40]
 cmp qword ptr [r12+80], 0
 jne .Ltemp_existing
 mov [r12+80], rcx
 inc rcx
 lea rsi, [r13+1024]
 lea rdi, [r12+416]
 rep movsb
 xor eax, eax
 ret
.Ltemp_existing:
 cmp [r12+80], rcx
 jne .Ltemp_bad
 inc rcx
 lea rsi, [r13+1024]
 lea rdi, [r12+416]
 repe cmpsb
 jne .Ltemp_bad
 xor eax, eax
 ret
.Ltemp_bad:
 mov eax, 1
 ret

.Ltarget:
 cmp qword ptr [r14+48], 1152
 jne .Ltarget_bad
 cmp qword ptr [r12+8200], 3
 je .Ltarget_anchor
 cmp qword ptr [r14+56], 30
 jne .Ltarget_bad
 lea rbx, [rip+.Lintent]
 mov ecx, 31
 jmp .Ltarget_compare
.Ltarget_anchor:
 cmp qword ptr [r14+56], 32
 jne .Ltarget_bad
 lea rbx, [rip+.Lanchor]
 mov ecx, 33
.Ltarget_compare:
 lea rsi, [r13+1152]
 mov rdi, rbx
 cld
 repe cmpsb
 jne .Ltarget_bad
 xor eax, eax
 ret
.Ltarget_bad:
 mov eax, 1
 ret

.Lzero_args:
 mov rax, [r14+32]
 or rax, [r14+40]
 or rax, [r14+48]
 or rax, [r14+56]
 ret
.Lbegin:
 mov rax, [r14+8]
 mov [r12+32], rax
 mov qword ptr [r12+40], 1
 xor ecx, ecx
.Lcapture:
 mov rax, [r14+rcx]
 mov [r12+rcx+160], rax
 add ecx, 8
 cmp ecx, 64
 jb .Lcapture
 ret
.Lcomplete:
 mov rdx, [r12+32]
 mov [r14+64], rdx
 cmp rax, -4095
 jae .Leffect_errno
 mov [r14+72], rax
 jmp .Lcompleted
.Leffect_errno:
 neg rax
 mov [r14+80], rax
.Lcompleted:
 mov qword ptr [r12+40], 0
 xor eax, eax
 jmp .Ldone
.Linvalid_owned:
 mov rdi, rax
 mov eax, 3
 syscall
 mov rax, -75
 jmp .Lcomplete
.Lbusy:
 mov rax, -16
 jmp .Ldone
.Linvalid:
 mov rax, -22
.Ldone:
 RESTORE

durable_audit_archive_publication_child_ack:
 SAVE
 mov r12, rdi
 mov rbx, rsi
 mov rbp, rdx
 mov rax, PUB_MAGIC
 cmp [r12], rax
 jne .Linvalid
 cmp qword ptr [r12+40], 2
 jne .Linvalid
 mov r13, [r12+16]
 lea r14, [r13+256]
 call .Lrequest
 test eax, eax
 jnz .Linvalid
 xor ecx, ecx
.Lcheck_child_action:
 mov rax, [r14+rcx]
 cmp rax, [r12+rcx+160]
 jne .Linvalid
 add ecx, 8
 cmp ecx, 64
 jb .Lcheck_child_action
 mov rax, [r14+64]
 or rax, [r14+72]
 or rax, [r14+80]
 or rax, [r14+88]
 jnz .Linvalid
 mov rax, [r12+32]
 cmp rax, [r14+8]
 jne .Linvalid
 cmp qword ptr [r14+16], 100
 jne .Linvalid
 cmp rbp, 4095
 ja .Linvalid
 cmp rbx, 4384
 ja .Linvalid
 test rbp, rbp
 jz .Lchild_check_payload
 test rbx, rbx
 jnz .Linvalid
.Lchild_check_payload:
 lea rsi, [r13+1536]
 lea rdi, [r12+512]
 mov ecx, 32
 cld
 repe cmpsb
 jne .Linvalid
 mov rax, [r12+32]
 mov [r14+64], rax
 mov [r14+72], rbx
 mov [r14+80], rbp
 mov qword ptr [r12+40], 0
 xor eax, eax
 jmp .Ldone

durable_audit_archive_publication_take:
 mov rax, -1
 ret

durable_audit_archive_publication_destroy:
 SAVE
 mov r12, rdi
 mov rax, PUB_MAGIC
 cmp [r12], rax
 jne .Linvalid
 cmp qword ptr [r12+40], 0
 jne .Lbusy
 xor ebx, ebx
 cmp qword ptr [r12+56], 0
 je .Ldestroy_unmap
 mov rdi, [r12+72]
 mov qword ptr [r12+72], -1
 mov qword ptr [r12+56], 0
 mov eax, 3
 syscall
 mov rbx, rax
.Ldestroy_unmap:
 mov qword ptr [r12], 0
 mov rdi, r12
 mov rsi, [r12+48]
 mov eax, 11
 syscall
 test rax, rax
 jnz .Lretained
 mov rax, rbx
 jmp .Ldone
.Lretained:
 mov rdx, PUB_MAGIC
 mov [r12], rdx
 jmp .Ldone

.Lintent:
 .asciz ".request-archive-v12-init.json"
.Lanchor:
 .asciz ".request-archive-v12-anchor.json"
.Lintent_prefix:
 .ascii ".archive-v12-init-"
.Lanchor_prefix:
 .ascii ".archive-v12-anchor-"
.section .note.GNU-stack,"",@progbits
