/* Copyright 2026 Muvon Un Limited
 * Copyright 2026 TrillionniumFoundation
 * SPDX-License-Identifier: Apache-2.0
 *
 * Closed Linux x86-64 effects for HIA PinnedAnchor. The HIA actor owns all
 * policy, comparisons, ordering, read limits and retry decisions. Slot zero
 * borrows one retained private root; slot one owns only the fixed legacy
 * anchor. There is no public FD, path, general syscall or subprocess input.
 * create(0,w,wcap,rootfd), step(ctx), child_ack(ctx,result,errno), take(ctx,slot)
 * (always refused), destroy(ctx). Ordinary System V ABI; flat PIC code.
 * Private context: magic0, mode8, workspace16, capacity24, seq32,pending40,
 * owned56, borrowed64, owned72, frozen-action160..223, stat256..399.
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
.equ ANCHOR_MAGIC, 0x3130474e41415248
.equ ANCHOR_ACTION, 0x3130414e41415248
.global durable_audit_anchor_create
.global durable_audit_anchor_step
.global durable_audit_anchor_child_ack
.global durable_audit_anchor_take
.global durable_audit_anchor_destroy

durable_audit_anchor_create:
 SAVE
 mov r12, rdi
 mov r13, rsi
 mov r14, rdx
 mov r15, rcx
 test r12, r12
 jnz .Lcreate_invalid
 test r13, r13
 jz .Lcreate_invalid
 cmp r14, 16384
 jb .Lcreate_invalid
 test r15, r15
 js .Lcreate_invalid
 cmp r15, 0x7fffffff
 ja .Lcreate_invalid
 xor edi, edi
 mov esi, 4096
 mov edx, 3
 mov r10d, 0x22
 mov r8, -1
 xor r9d, r9d
 mov eax, 9
 syscall
 cmp rax, -4095
 jae .Lcreate_done
 mov rbx, rax
 mov rdx, ANCHOR_MAGIC
 mov [rbx], rdx
 mov [rbx+16], r13
 mov [rbx+24], r14
 mov [rbx+64], r15
 mov qword ptr [rbx+72], -1
 jmp .Lcreate_done
.Lcreate_invalid:
 mov rax, -22
.Lcreate_done:
 RESTORE

durable_audit_anchor_step:
 SAVE
 mov r12, rdi
 mov rax, ANCHOR_MAGIC
 cmp [r12], rax
 jne .Linvalid
 cmp qword ptr [r12+8], 0
 jne .Linvalid
 cmp qword ptr [r12+40], 0
 jne .Lbusy
 mov r13, [r12+16]
 lea r14, [r13+256]
 mov rax, ANCHOR_ACTION
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
 cmp rax, 2
 je .Lfstat
 cmp rax, 3
 je .Luid
 cmp rax, 4
 je .Lnamed
 cmp rax, 5
 je .Lread
 cmp rax, 6
 je .Lpread
 cmp rax, 7
 je .Lclose
 cmp rax, 100
 je .Lchild
 jmp .Linvalid

.Lopen:
 cmp r15, 1
 jne .Linvalid
 cmp qword ptr [r12+72], -1
 jne .Linvalid
 cmp qword ptr [r14+32], 896
 jne .Linvalid
 cmp qword ptr [r14+40], 32
 jne .Linvalid
 cmp qword ptr [r14+48], 0xa0800
 jne .Linvalid
 cmp qword ptr [r14+56], 0
 jne .Linvalid
 call .Lname
 test eax, eax
 jnz .Linvalid
 call .Lbegin
 mov rdi, [r12+64]
 lea rsi, [rip+.Lfilename]
 mov edx, 0xa0800
 xor r10d, r10d
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

.Lfstat:
 cmp r15, 1
 jne .Linvalid
 cmp qword ptr [r12+72], 0
 jl .Linvalid
 cmp qword ptr [r14+32], 512
 jne .Linvalid
 cmp qword ptr [r14+40], 88
 jne .Linvalid
 mov rax, [r14+48]
 or rax, [r14+56]
 jnz .Linvalid
 call .Lbegin
 mov rdi, [r12+72]
 lea rsi, [r12+256]
 mov eax, 5
 syscall
 jmp .Lstat_result

.Luid:
 test r15, r15
 jnz .Linvalid
 call .Lzero_args
 test rax, rax
 jnz .Linvalid
 call .Lbegin
 mov eax, 107
 syscall
 jmp .Lcomplete

.Lnamed:
 test r15, r15
 jnz .Linvalid
 cmp qword ptr [r14+32], 512
 jne .Linvalid
 cmp qword ptr [r14+40], 88
 jne .Linvalid
 cmp qword ptr [r14+48], 896
 jne .Linvalid
 cmp qword ptr [r14+56], 32
 jne .Linvalid
 call .Lname
 test eax, eax
 jnz .Linvalid
 call .Lbegin
 mov rdi, [r12+64]
 lea rsi, [rip+.Lfilename]
 lea rdx, [r12+256]
 mov r10d, 0x100
 mov eax, 262
 syscall
.Lstat_result:
 test rax, rax
 jnz .Lcomplete
 mov rax, [r12+256]
 mov [r13+512], rax
 mov rax, [r12+264]
 mov [r13+520], rax
 mov eax, dword ptr [r12+280]
 mov [r13+528], rax
 mov eax, dword ptr [r12+284]
 mov [r13+536], rax
 mov eax, dword ptr [r12+288]
 mov [r13+544], rax
 mov rax, [r12+272]
 mov [r13+552], rax
 mov rax, [r12+304]
 mov [r13+560], rax
 mov rax, [r12+344]
 mov [r13+568], rax
 mov rax, [r12+352]
 mov [r13+576], rax
 mov rax, [r12+360]
 mov [r13+584], rax
 mov rax, [r12+368]
 mov [r13+592], rax
 xor eax, eax
 jmp .Lcomplete

.Lread:
 cmp r15, 1
 jne .Linvalid
 cmp qword ptr [r12+72], 0
 jl .Linvalid
 mov rax, [r14+48]
 or rax, [r14+56]
 jnz .Linvalid
 cmp qword ptr [r14+32], 4096
 jb .Linvalid
 cmp qword ptr [r14+40], 0
 je .Linvalid
 cmp qword ptr [r14+40], 2049
 ja .Linvalid
 mov rax, [r14+32]
 add rax, [r14+40]
 cmp rax, 6145
 ja .Linvalid
 call .Lbegin
 mov rdi, [r12+72]
 mov rsi, [r14+32]
 add rsi, r13
 mov rdx, [r14+40]
 xor eax, eax
 syscall
 jmp .Lcomplete

.Lpread:
 cmp r15, 1
 jne .Linvalid
 cmp qword ptr [r12+72], 0
 jl .Linvalid
 cmp qword ptr [r14+56], 0
 jne .Linvalid
 cmp qword ptr [r14+32], 4096
 jb .Linvalid
 cmp qword ptr [r14+40], 0
 je .Linvalid
 cmp qword ptr [r14+40], 2048
 ja .Linvalid
 mov rax, [r14+32]
 add rax, [r14+40]
 cmp rax, 6144
 ja .Linvalid
 mov rax, [r14+32]
 sub rax, 4096
 cmp rax, [r14+48]
 jne .Linvalid
 call .Lbegin
 mov rdi, [r12+72]
 mov rsi, [r14+32]
 add rsi, r13
 mov rdx, [r14+40]
 mov r10, [r14+48]
 mov eax, 17
 syscall
 jmp .Lcomplete

.Lclose:
 cmp r15, 1
 jne .Linvalid
 cmp qword ptr [r12+56], 2
 jne .Linvalid
 cmp qword ptr [r12+72], 0
 jl .Linvalid
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
 cmp qword ptr [r12+56], 2
 jne .Linvalid
 cmp qword ptr [r12+72], 0
 jl .Linvalid
 cmp qword ptr [r14+32], 8192
 jne .Linvalid
 cmp qword ptr [r14+40], 32
 jb .Linvalid
 cmp qword ptr [r14+40], 2080
 ja .Linvalid
 cmp qword ptr [r14+48], 10496
 jne .Linvalid
 cmp qword ptr [r14+56], 128
 jne .Linvalid
 mov rax, 0x3130515441415248 /* HRAATQ01 */
 cmp [r13+8192], rax
 jne .Linvalid
 cmp qword ptr [r13+8200], 1
 jne .Linvalid
 cmp qword ptr [r13+8216], 0
 jne .Linvalid
 mov rax, [r14+40]
 sub rax, 32
 cmp [r13+8208], rax
 jne .Linvalid
 call .Lbegin
 mov qword ptr [r12+40], 2
 mov eax, 1
 jmp .Ldone

.Lname:
 lea rsi, [r13+896]
 lea rdi, [rip+.Lfilename]
 mov ecx, 33
 cld
 repe cmpsb
 setne al
 movzx eax, al
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

durable_audit_anchor_child_ack:
 SAVE
 mov r12, rdi
 mov rbx, rsi
 mov rbp, rdx
 mov rax, ANCHOR_MAGIC
 cmp [r12], rax
 jne .Linvalid
 cmp qword ptr [r12+40], 2
 jne .Linvalid
 mov r13, [r12+16]
 lea r14, [r13+256]
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
 cmp rbx, [r14+56]
 ja .Linvalid
 test rbp, rbp
 jz .Lchild_ready
 test rbx, rbx
 jnz .Linvalid
.Lchild_ready:
 mov [r14+64], rax
 mov [r14+72], rbx
 mov [r14+80], rbp
 mov qword ptr [r12+40], 0
 xor eax, eax
 jmp .Ldone

durable_audit_anchor_take:
 mov rax, -1 /* EPERM: this owner never exports a raw descriptor. */
 ret

durable_audit_anchor_destroy:
 SAVE
 mov r12, rdi
 mov rax, ANCHOR_MAGIC
 cmp [r12], rax
 jne .Linvalid
 cmp qword ptr [r12+40], 0
 jne .Lbusy
 xor ebx, ebx
 cmp qword ptr [r12+56], 0
 je .Ldestroy_control
 cmp qword ptr [r12+56], 2
 jne .Linvalid
 mov rdi, [r12+72]
 mov qword ptr [r12+72], -1
 mov qword ptr [r12+56], 0
 mov eax, 3
 syscall
 mov rbx, rax
.Ldestroy_control:
 mov qword ptr [r12], 0
 mov rdi, r12
 mov esi, 4096
 mov eax, 11
 syscall
 test rax, rax
 jnz .Lretained
 mov rax, rbx
 jmp .Ldone
.Lretained:
 mov rdx, ANCHOR_MAGIC
 mov [r12], rdx
 jmp .Ldone

.Lfilename:
 .asciz ".request-archive-v11-anchor.json"
.section .note.GNU-stack,"",@progbits
