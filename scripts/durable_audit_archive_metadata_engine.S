/* Copyright 2026 Muvon Un Limited
 * Copyright 2026 TrillionniumFoundation
 * SPDX-License-Identifier: Apache-2.0
 *
 * Closed Linux x86-64 v12 audit metadata effects. Policy, parsing, UTF-8,
 * alias recognition, ordering and every bound remain in the HIA actor.
 * Slot 0 borrows the audit root. Slots 1 metadata, 2 legacy, 3 fresh scan,
 * 4 CLOEXEC scan duplicate and 5 recognized temporary alias are owned.
 * No public descriptors, arbitrary paths, general syscalls or subprocesses.
 * create(0,w,wcap,rootfd), step(ctx), child_ack(ctx,result,errno),
 * take(ctx,slot) always EPERM, destroy(ctx). Ordinary System V PIC ABI.
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
.equ META_MAGIC, 0x3130474d41415248
.equ META_ACTION, 0x3130414d41415248
.global durable_audit_archive_metadata_create
.global durable_audit_archive_metadata_step
.global durable_audit_archive_metadata_child_ack
.global durable_audit_archive_metadata_take
.global durable_audit_archive_metadata_destroy

durable_audit_archive_metadata_create:
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
 xor edi, edi
 mov esi, 131072
 mov edx, 3
 mov r10d, 0x22
 mov r8, -1
 xor r9d, r9d
 mov eax, 9
 syscall
 cmp rax, -4095
 jae .Lcreate_done
 mov rbx, rax
 mov rdx, META_MAGIC
 mov [rbx], rdx
 mov [rbx+16], r13
 mov [rbx+24], r14
 mov [rbx+64], r15
 mov ecx, 1
.Lcreate_slots:
 mov qword ptr [rbx+64+rcx*8], -1
 inc ecx
 cmp ecx, 6
 jb .Lcreate_slots
 jmp .Lcreate_done
.Lcreate_invalid:
 mov rax, -22
.Lcreate_done:
 RESTORE

durable_audit_archive_metadata_step:
 SAVE
 mov r12, rdi
 mov rax, META_MAGIC
 cmp [r12], rax
 jne .Linvalid
 cmp qword ptr [r12+8], 0
 jne .Linvalid
 cmp qword ptr [r12+40], 0
 jne .Lbusy
 mov r13, [r12+16]
 lea r14, [r13+256]
 mov rax, META_ACTION
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
 cmp r15, 5
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
 cmp rax, 5
 je .Lread
 cmp rax, 7
 je .Lclose
 cmp rax, 8
 je .Lduplicate
 cmp rax, 9
 je .Lgetdents
 cmp rax, 10
 je .Lunlink
 cmp rax, 11
 je .Lsync
 cmp rax, 100
 je .Lchild
 jmp .Linvalid

.Lopen:
 test r15, r15
 jz .Linvalid
 cmp r15, 4
 je .Linvalid
 cmp qword ptr [r12+64+r15*8], -1
 jne .Linvalid
 cmp qword ptr [r14+56], 0
 jne .Linvalid
 cmp r15, 1
 je .Lopen_metadata
 cmp r15, 2
 je .Lopen_legacy
 cmp r15, 3
 je .Lopen_scan
 cmp r15, 5
 jne .Linvalid
 call .Lalias
 test eax, eax
 jnz .Linvalid
 cmp qword ptr [r14+48], 0xa0800
 jne .Linvalid
 lea rbx, [r12+416]
 jmp .Lopen_do
.Lopen_metadata:
 cmp qword ptr [r14+32], 2048
 jne .Linvalid
 cmp qword ptr [r14+48], 0xa0800
 jne .Linvalid
 mov rax, [r13+1544]
 cmp rax, 1
 je .Lopen_intent
 cmp rax, 2
 jne .Linvalid
 cmp qword ptr [r14+40], 32
 jne .Linvalid
 lea rbx, [rip+.Lanchor]
 mov ecx, 33
 jmp .Lopen_compare
.Lopen_intent:
 cmp qword ptr [r14+40], 30
 jne .Linvalid
 lea rbx, [rip+.Lintent]
 mov ecx, 31
 jmp .Lopen_compare
.Lopen_legacy:
 cmp qword ptr [r14+32], 2112
 jne .Linvalid
 cmp qword ptr [r14+40], 32
 jne .Linvalid
 cmp qword ptr [r14+48], 0xa0800
 jne .Linvalid
 lea rbx, [rip+.Llegacy]
 mov ecx, 33
 jmp .Lopen_compare
.Lopen_scan:
 cmp qword ptr [r14+32], 2176
 jne .Linvalid
 cmp qword ptr [r14+40], 1
 jne .Linvalid
 cmp qword ptr [r14+48], 0xb0000
 jne .Linvalid
 lea rbx, [rip+.Ldot]
 mov ecx, 2
.Lopen_compare:
 mov rsi, [r14+32]
 add rsi, r13
 mov rdi, rbx
 cld
 repe cmpsb
 jne .Linvalid
.Lopen_do:
 call .Lbegin
 mov rdi, [r12+64]
 mov rsi, rbx
 mov rdx, [r14+48]
 xor r10d, r10d
 mov eax, 257
 syscall
 jmp .Lassign

.Lfstat:
 cmp qword ptr [r12+64+r15*8], 0
 jl .Linvalid
 cmp qword ptr [r14+32], 512
 jne .Linvalid
 cmp qword ptr [r14+40], 88
 jne .Linvalid
 mov rax, [r14+48]
 or rax, [r14+56]
 jnz .Linvalid
 call .Lbegin
 mov rdi, [r12+64+r15*8]
 lea rsi, [r12+256]
 mov eax, 5
 syscall
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

.Lread:
 cmp r15, 1
 je .Lread_metadata
 cmp r15, 2
 jne .Linvalid
 mov ebx, 69664
 mov ebp, 71713
 jmp .Lread_bounds
.Lread_metadata:
 mov ebx, 4096
 mov ebp, 69633
.Lread_bounds:
 cmp qword ptr [r12+64+r15*8], 0
 jl .Linvalid
 mov rax, [r14+48]
 or rax, [r14+56]
 jnz .Linvalid
 cmp [r14+32], rbx
 jb .Linvalid
 cmp qword ptr [r14+40], 0
 je .Linvalid
 mov rax, [r14+32]
 add rax, [r14+40]
 cmp rax, rbp
 ja .Linvalid
 call .Lbegin
 mov rdi, [r12+64+r15*8]
 mov rsi, [r14+32]
 add rsi, r13
 mov rdx, [r14+40]
 xor eax, eax
 syscall
 jmp .Lcomplete

.Lclose:
 test r15, r15
 jz .Linvalid
 cmp qword ptr [r12+64+r15*8], 0
 jl .Linvalid
 bt qword ptr [r12+56], r15
 jnc .Linvalid
 call .Lzero_args
 test rax, rax
 jnz .Linvalid
 call .Lbegin
 mov rdi, [r12+64+r15*8]
 mov qword ptr [r12+64+r15*8], -1
 btr qword ptr [r12+56], r15
 mov eax, 3
 syscall
 jmp .Lcomplete

.Lduplicate:
 cmp r15, 4
 jne .Linvalid
 cmp qword ptr [r12+96], -1
 jne .Linvalid
 cmp qword ptr [r12+88], 0
 jl .Linvalid
 mov rax, [r14+32]
 or rax, [r14+40]
 or rax, [r14+56]
 jnz .Linvalid
 cmp qword ptr [r14+48], 3
 jne .Linvalid
 call .Lbegin
 mov rdi, [r12+88]
 mov esi, 1030
 xor edx, edx
 mov eax, 72
 syscall
.Lassign:
 cmp rax, -4095
 jae .Lcomplete
 cmp rax, 0x7fffffff
 ja .Linvalid_owned
 mov [r12+64+r15*8], rax
 bts qword ptr [r12+56], r15
 xor eax, eax
 jmp .Lcomplete

.Lgetdents:
 cmp r15, 4
 jne .Linvalid
 cmp qword ptr [r12+96], 0
 jl .Linvalid
 cmp qword ptr [r14+32], 675840
 jne .Linvalid
 cmp qword ptr [r14+40], 32768
 jne .Linvalid
 mov rax, [r14+48]
 or rax, [r14+56]
 jnz .Linvalid
 call .Lbegin
 mov rdi, [r12+96]
 lea rsi, [r13+675840]
 mov edx, 32768
 mov eax, 217
 syscall
 jmp .Lcomplete

.Lunlink:
 test r15, r15
 jnz .Linvalid
 mov rax, [r14+48]
 or rax, [r14+56]
 jnz .Linvalid
 call .Lalias
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
 test r15, r15
 jnz .Linvalid
 call .Lzero_args
 test rax, rax
 jnz .Linvalid
 call .Lbegin
 mov rdi, [r12+64]
 mov eax, 74
 syscall
 jmp .Lcomplete

.Lchild:
 test r15, r15
 jnz .Linvalid
 cmp qword ptr [r14+32], 73728
 jne .Linvalid
 cmp qword ptr [r14+40], 32
 jb .Linvalid
 cmp qword ptr [r14+40], 65568
 ja .Linvalid
 cmp qword ptr [r14+48], 143360
 jne .Linvalid
 cmp qword ptr [r14+56], 262272
 jne .Linvalid
 mov rax, 0x3130515441415248
 cmp [r13+73728], rax
 jne .Linvalid
 cmp qword ptr [r13+73752], 0
 jne .Linvalid
 mov rax, [r14+40]
 sub rax, 32
 cmp [r13+73744], rax
 jne .Linvalid
 mov rax, [r13+73736]
 cmp rax, 1
 je .Lchild_legacy
 cmp rax, 3
 ja .Linvalid
 cmp rax, 2
 jb .Linvalid
 cmp qword ptr [r12+72], 0
 jl .Linvalid
 jmp .Lchild_begin
.Lchild_legacy:
 cmp qword ptr [r14+40], 2080
 ja .Linvalid
 cmp qword ptr [r12+80], 0
 jl .Linvalid
.Lchild_begin:
 call .Lbegin
 mov rcx, [r14+40]
 mov [r12+112], rcx
 lea rsi, [r13+73728]
 lea rdi, [r12+512]
 cld
 rep movsb
 mov qword ptr [r12+40], 2
 mov eax, 1
 jmp .Ldone

.Lalias:
 cmp qword ptr [r14+32], 2304
 jne .Lalias_bad
 mov rax, [r13+1544]
 cmp rax, 1
 je .Lalias_intent
 cmp rax, 2
 jne .Lalias_bad
 cmp qword ptr [r14+40], 88
 jne .Lalias_bad
 lea rdi, [rip+.Lanchor_prefix]
 mov ecx, 20
 jmp .Lalias_prefix
.Lalias_intent:
 cmp qword ptr [r14+40], 86
 jne .Lalias_bad
 lea rdi, [rip+.Lintent_prefix]
 mov ecx, 18
.Lalias_prefix:
 lea rsi, [r13+2304]
 cld
 repe cmpsb
 jne .Lalias_bad
 mov ecx, 64
.Lalias_hex:
 lodsb
 cmp al, '0'
 jb .Lalias_bad
 cmp al, '9'
 jbe .Lalias_next
 cmp al, 'a'
 jb .Lalias_bad
 cmp al, 'f'
 ja .Lalias_bad
.Lalias_next:
 dec ecx
 jnz .Lalias_hex
 cmp dword ptr [rsi], 0x706d742e
 jne .Lalias_bad
 cmp byte ptr [rsi+4], 0
 jne .Lalias_bad
 mov rcx, [r14+40]
 inc rcx
 lea rsi, [r13+2304]
 lea rdi, [r12+416]
 rep movsb
 xor eax, eax
 ret
.Lalias_bad:
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
 xor ecx, ecx
.Lcapture_request:
 mov rax, [r13+1536+rcx]
 mov [r12+128+rcx], rax
 add ecx, 8
 cmp ecx, 32
 jb .Lcapture_request
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

durable_audit_archive_metadata_child_ack:
 SAVE
 mov r12, rdi
 mov rbx, rsi
 mov rbp, rdx
 mov rax, META_MAGIC
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
 xor ecx, ecx
.Lcheck_child_request:
 mov rax, [r13+1536+rcx]
 cmp rax, [r12+128+rcx]
 jne .Linvalid
 add ecx, 8
 cmp ecx, 32
 jb .Lcheck_child_request
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
 jz .Lchild_check_payload
 test rbx, rbx
 jnz .Linvalid
.Lchild_check_payload:
 mov rcx, [r14+40]
 cmp rcx, [r12+112]
 jne .Linvalid
 lea rsi, [r13+73728]
 lea rdi, [r12+512]
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

durable_audit_archive_metadata_take:
 mov rax, -1
 ret

durable_audit_archive_metadata_destroy:
 SAVE
 mov r12, rdi
 mov rax, META_MAGIC
 cmp [r12], rax
 jne .Linvalid
 cmp qword ptr [r12+40], 0
 jne .Lbusy
 xor ebx, ebx
 mov r15d, 5
.Ldestroy_slot:
 bt qword ptr [r12+56], r15
 jnc .Ldestroy_next
 mov rdi, [r12+64+r15*8]
 mov qword ptr [r12+64+r15*8], -1
 btr qword ptr [r12+56], r15
 mov eax, 3
 syscall
 test rbx, rbx
 cmovz rbx, rax
.Ldestroy_next:
 dec r15d
 jnz .Ldestroy_slot
 mov qword ptr [r12], 0
 mov rdi, r12
 mov esi, 131072
 mov eax, 11
 syscall
 test rax, rax
 jnz .Lretained
 mov rax, rbx
 jmp .Ldone
.Lretained:
 mov rdx, META_MAGIC
 mov [r12], rdx
 jmp .Ldone

.Lintent:
 .asciz ".request-archive-v12-init.json"
.Lanchor:
 .asciz ".request-archive-v12-anchor.json"
.Llegacy:
 .asciz ".request-archive-v11-anchor.json"
.Ldot:
 .asciz "."
.Lintent_prefix:
 .ascii ".archive-v12-init-"
.Lanchor_prefix:
 .ascii ".archive-v12-anchor-"
.section .note.GNU-stack,"",@progbits
