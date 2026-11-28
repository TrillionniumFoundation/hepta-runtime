/* Copyright 2026 Muvon Un Limited
 * Copyright 2026 TrillionniumFoundation
 * SPDX-License-Identifier: Apache-2.0
 * Private Linux x86-64 v12 layout effects. The HIA actor owns all policy.
 * Slots 0/1 borrow the retained audit root/legacy; 2 is the owned shard root,
 * 3 a transient file/directory, 4/5 and 6/7 fresh nested scans, 8..263 pinned
 * shards. Single-owner serialized API; no public descriptor or path input.
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
.equ MAGIC, 0x3130474c41415248
.equ ACTION, 0x3130414c41415248
.equ REQUEST, 0x3130514c41415248
.global durable_audit_archive_layout_create
.global durable_audit_archive_layout_step
.global durable_audit_archive_layout_child_ack
.global durable_audit_archive_layout_take
.global durable_audit_archive_layout_destroy

durable_audit_archive_layout_create:
 SAVE
 mov r12, rdi
 mov r13, rsi
 mov r14, rdx
 mov r15, rcx
 mov rbp, r8
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
 test rbp, rbp
 js .Lcreate_invalid
 cmp rbp, 0x7fffffff
 ja .Lcreate_invalid
 xor edi, edi
 mov esi, 65536
 mov edx, 3
 mov r10d, 0x22
 mov r8, -1
 xor r9d, r9d
 mov eax, 9
 syscall
 cmp rax, -4095
 jae .Lcreate_done
 mov rbx, rax
 mov rdx, MAGIC
 mov [rbx], rdx
 mov [rbx+16], r13
 mov [rbx+24], r14
 mov [rbx+64], r15
 mov [rbx+72], rbp
 mov ecx, 2
.Lcreate_slots:
 mov qword ptr [rbx+64+rcx*8], -1
 inc ecx
 cmp ecx, 264
 jb .Lcreate_slots
 jmp .Lcreate_done
.Lcreate_invalid:
 mov rax, -22
.Lcreate_done:
 RESTORE

durable_audit_archive_layout_step:
 SAVE
 mov r12, rdi
 mov rax, MAGIC
 cmp [r12], rax
 jne .Linvalid
 cmp qword ptr [r12+8], 0
 jne .Linvalid
 cmp qword ptr [r12+40], 0
 jne .Lbusy
 mov r13, [r12+16]
 lea r14, [r13+256]
 mov rax, ACTION
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
 mov rax, REQUEST
 cmp [r13+1536], rax
 jne .Linvalid
 cmp qword ptr [r13+1544], 1
 jb .Linvalid
 cmp qword ptr [r13+1544], 5
 ja .Linvalid
 cmp qword ptr [r13+1552], 0
 je .Linvalid
 cmp qword ptr [r13+1560], 0
 jne .Linvalid
 mov r15, [r14+24]
 cmp r15, 263
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
 cmp rax, 16
 je .Lmkdir
 cmp rax, 21
 je .Lcheckpoint
 cmp rax, 100
 jb .Linvalid
 cmp rax, 102
 jbe .Lchild
 jmp .Linvalid

.Lopen:
 cmp r15, 2
 jb .Linvalid
 cmp qword ptr [r12+64+r15*8], -1
 jne .Linvalid
 cmp r15, 2
 je .Lopen_root
 cmp r15, 3
 je .Lopen_work
 cmp r15, 4
 je .Lopen_scan
 cmp r15, 6
 je .Lopen_nested
 cmp r15, 8
 jb .Linvalid
 cmp qword ptr [r14+48], 2
 jne .Linvalid
 cmp qword ptr [r14+56], 0xb0000
 jne .Linvalid
 cmp qword ptr [r14+32], 2304
 jne .Linvalid
 call .Lname
 test eax, eax
 jnz .Linvalid
 mov rax, r15
 sub rax, 8
 mov rdx, rax
 shr rdx, 4
 call .Lhex
 cmp [rbx], dl
 jne .Linvalid
 mov rdx, rax
 and rdx, 15
 call .Lhex
 cmp [rbx+1], dl
 jne .Linvalid
 jmp .Lopen_do
.Lopen_root:
 cmp qword ptr [r14+32], 2048
 jne .Linvalid
 cmp qword ptr [r14+48], 0
 jne .Linvalid
 cmp qword ptr [r14+56], 0xb0000
 jne .Linvalid
 jmp .Lopen_name
.Lopen_work:
 cmp qword ptr [r14+32], 2112
 je .Lopen_anchor
 cmp qword ptr [r14+32], 2304
 jne .Linvalid
 cmp qword ptr [r14+48], 2
 jne .Linvalid
 cmp qword ptr [r14+56], 0xb0000
 jne .Linvalid
 jmp .Lopen_name
.Lopen_anchor:
 cmp qword ptr [r14+48], 0
 jne .Linvalid
 cmp qword ptr [r14+56], 0xa0800
 jne .Linvalid
 jmp .Lopen_name
.Lopen_scan:
 mov rax, [r14+48]
 cmp rax, 2
 je .Lopen_scan_common
 cmp rax, 3
 jne .Linvalid
 jmp .Lopen_scan_common
.Lopen_nested:
 cmp qword ptr [r14+48], 3
 jne .Linvalid
.Lopen_scan_common:
 cmp qword ptr [r14+32], 2368
 jne .Linvalid
 cmp qword ptr [r14+56], 0xb0000
 jne .Linvalid
.Lopen_name:
 call .Lname
 test eax, eax
 jnz .Linvalid
.Lopen_do:
 mov rax, [r14+48]
 cmp qword ptr [r12+64+rax*8], 0
 jl .Linvalid
 call .Lbegin
 mov rax, [r14+48]
 mov rdi, [r12+64+rax*8]
 mov rsi, rbx
 mov rdx, [r14+56]
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
 lea rsi, [r12+2560]
 mov eax, 5
 syscall
 test rax, rax
 jnz .Lcomplete
 call .Lstat_output
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

.Lnamed:
 cmp r15, 0
 je .Lnamed_root
 cmp r15, 2
 jne .Linvalid
 cmp qword ptr [r14+32], 2304
 jne .Linvalid
 jmp .Lnamed_common
.Lnamed_root:
 mov rax, [r14+32]
 cmp rax, 2048
 je .Lnamed_common
 cmp rax, 2112
 je .Lnamed_common
 cmp rax, 2176
 je .Lnamed_common
 cmp rax, 2240
 jne .Linvalid
.Lnamed_common:
 cmp qword ptr [r12+64+r15*8], 0
 jl .Linvalid
 cmp qword ptr [r14+48], 512
 jne .Linvalid
 cmp qword ptr [r14+56], 88
 jne .Linvalid
 call .Lname
 test eax, eax
 jnz .Linvalid
 call .Lbegin
 mov rdi, [r12+64+r15*8]
 mov rsi, rbx
 lea rdx, [r12+2560]
 mov r10d, 256
 mov eax, 262
 syscall
 test rax, rax
 jnz .Lcomplete
 call .Lstat_output
 xor eax, eax
 jmp .Lcomplete

.Lclose:
 cmp r15, 2
 jb .Linvalid
 cmp qword ptr [r12+64+r15*8], 0
 jl .Linvalid
 cmp byte ptr [r12+4096+r15], 1
 jne .Linvalid
 call .Lzero_args
 test rax, rax
 jnz .Linvalid
 call .Lbegin
 mov rdi, [r12+64+r15*8]
 mov qword ptr [r12+64+r15*8], -1
 mov byte ptr [r12+4096+r15], 0
 mov eax, 3
 syscall
 jmp .Lcomplete

.Lduplicate:
 cmp r15, 5
 je .Lduplicate_outer
 cmp r15, 7
 jne .Linvalid
 cmp qword ptr [r14+48], 6
 jne .Linvalid
 jmp .Lduplicate_common
.Lduplicate_outer:
 cmp qword ptr [r14+48], 4
 jne .Linvalid
.Lduplicate_common:
 cmp qword ptr [r12+64+r15*8], -1
 jne .Linvalid
 mov rax, [r14+48]
 cmp qword ptr [r12+64+rax*8], 0
 jl .Linvalid
 mov rax, [r14+32]
 or rax, [r14+40]
 or rax, [r14+56]
 jnz .Linvalid
 call .Lbegin
 mov rax, [r14+48]
 mov rdi, [r12+64+rax*8]
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
 mov byte ptr [r12+4096+r15], 1
 xor eax, eax
 jmp .Lcomplete

.Lgetdents:
 cmp r15, 5
 je .Lgetdents_outer
 cmp r15, 7
 jne .Linvalid
 cmp qword ptr [r14+32], 98304
 jne .Linvalid
 jmp .Lgetdents_common
.Lgetdents_outer:
 cmp qword ptr [r14+32], 65536
 jne .Linvalid
.Lgetdents_common:
 cmp qword ptr [r12+64+r15*8], 0
 jl .Linvalid
 cmp qword ptr [r14+40], 32768
 jne .Linvalid
 mov rax, [r14+48]
 or rax, [r14+56]
 jnz .Linvalid
 call .Lbegin
 mov rdi, [r12+64+r15*8]
 mov rsi, [r14+32]
 add rsi, r13
 mov edx, 32768
 mov eax, 217
 syscall
 jmp .Lcomplete

.Lunlink:
 test r15, r15
 jnz .Linvalid
 cmp qword ptr [r14+32], 2176
 jne .Linvalid
 mov rax, [r14+48]
 or rax, [r14+56]
 jnz .Linvalid
 call .Lname
 test eax, eax
 jnz .Linvalid
 call .Lbegin
 mov rdi, [r12+64]
 mov rsi, rbx
 xor edx, edx
 mov eax, 263
 syscall
 jmp .Lcomplete

.Lsync:
 test r15, r15
 jz .Lsync_common
 cmp r15, 2
 je .Lsync_common
 cmp r15, 3
 jne .Linvalid
.Lsync_common:
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

.Lmkdir:
 test r15, r15
 jz .Lmkdir_root
 cmp r15, 2
 jne .Linvalid
 cmp qword ptr [r14+32], 2304
 jne .Linvalid
 jmp .Lmkdir_common
.Lmkdir_root:
 cmp qword ptr [r14+32], 2048
 jne .Linvalid
.Lmkdir_common:
 cmp qword ptr [r12+64+r15*8], 0
 jl .Linvalid
 cmp qword ptr [r14+48], 448
 jne .Linvalid
 cmp qword ptr [r14+56], 0
 jne .Linvalid
 call .Lname
 test eax, eax
 jnz .Linvalid
 call .Lbegin
 mov rdi, [r12+64+r15*8]
 mov rsi, rbx
 mov edx, 448
 mov eax, 258
 syscall
 jmp .Lcomplete

.Lcheckpoint:
 test r15, r15
 jnz .Linvalid
 mov rax, [r14+32]
 or rax, [r14+40]
 jnz .Linvalid
 mov rax, [r14+48]
 cmp rax, 1
 jb .Linvalid
 cmp rax, 7
 ja .Linvalid
 cmp rax, 4
 je .Lcheckpoint_shard
 cmp rax, 5
 je .Lcheckpoint_shard
 cmp qword ptr [r14+56], 0
 jne .Linvalid
 jmp .Lcheckpoint_ready
.Lcheckpoint_shard:
 cmp qword ptr [r14+56], 255
 ja .Linvalid
.Lcheckpoint_ready:
 call .Lbegin
 xor eax, eax
 jmp .Lcomplete

.Lchild:
 test r15, r15
 jnz .Linvalid
 cmp qword ptr [r14+32], 131072
 jne .Linvalid
 cmp qword ptr [r14+48], 262144
 jne .Linvalid
 mov rax, [r14+16]
 cmp rax, 102
 je .Lchild_publication
 cmp qword ptr [r14+40], 32
 jne .Linvalid
 cmp qword ptr [r13+131088], 0
 jne .Linvalid
 cmp qword ptr [r13+131096], 0
 jne .Linvalid
 cmp rax, 101
 je .Lchild_pin
 cmp qword ptr [r14+56], 4384
 jne .Linvalid
 mov rax, 0x3130514d41415248
 cmp [r13+131072], rax
 jne .Linvalid
 cmp qword ptr [r13+131080], 1
 jb .Linvalid
 cmp qword ptr [r13+131080], 2
 ja .Linvalid
 jmp .Lchild_begin
.Lchild_pin:
 cmp qword ptr [r14+56], 192
 jne .Linvalid
 mov rax, 0x3130514e41415248
 cmp [r13+131072], rax
 jne .Linvalid
 cmp qword ptr [r13+131080], 2
 jne .Linvalid
 jmp .Lchild_begin
.Lchild_publication:
 cmp qword ptr [r14+56], 128
 jne .Linvalid
 cmp qword ptr [r14+40], 160
 jb .Linvalid
 cmp qword ptr [r14+40], 4256
 ja .Linvalid
 mov rax, 0x3130515741415248
 cmp [r13+131072], rax
 jne .Linvalid
 cmp qword ptr [r13+131080], 1
 jb .Linvalid
 cmp qword ptr [r13+131080], 3
 ja .Linvalid
 cmp qword ptr [r13+131096], 0
 jne .Linvalid
 mov rax, [r14+40]
 sub rax, 32
 cmp [r13+131088], rax
 jne .Linvalid
 cmp [r13+131128], rax
 jne .Linvalid
 mov rdx, 0x3130525441415248
 cmp [r13+131104], rdx
 jne .Linvalid
 cmp qword ptr [r13+131112], 0
 jne .Linvalid
 mov rdx, [r13+131200]
 cmp rdx, 256
 ja .Linvalid
 shl rdx, 4
 add rdx, 128
 cmp rdx, rax
 jne .Linvalid
.Lchild_begin:
 call .Lbegin
 mov rcx, [r14+40]
 mov [r12+48], rcx
 lea rsi, [r13+131072]
 lea rdi, [r12+12288]
 cld
 rep movsb
 mov qword ptr [r12+40], 1
 mov eax, 1
 jmp .Ldone

.Lname:
 mov rax, [r14+32]
 cmp rax, 2048
 je .Lname_root
 cmp rax, 2112
 je .Lname_anchor
 cmp rax, 2176
 je .Lname_intent
 cmp rax, 2240
 je .Lname_legacy
 cmp rax, 2304
 je .Lname_shard
 cmp rax, 2368
 je .Lname_dot
 jmp .Lname_bad
.Lname_root:
 cmp qword ptr [r14+40], 19
 jne .Lname_bad
 lea rbx, [rip+.Lroot]
 mov ecx, 20
 jmp .Lname_compare
.Lname_anchor:
 cmp qword ptr [r14+40], 32
 jne .Lname_bad
 lea rbx, [rip+.Lanchor]
 mov ecx, 33
 jmp .Lname_compare
.Lname_intent:
 cmp qword ptr [r14+40], 30
 jne .Lname_bad
 lea rbx, [rip+.Lintent]
 mov ecx, 31
 jmp .Lname_compare
.Lname_legacy:
 cmp qword ptr [r14+40], 19
 jne .Lname_bad
 lea rbx, [rip+.Llegacy]
 mov ecx, 20
 jmp .Lname_compare
.Lname_dot:
 cmp qword ptr [r14+40], 1
 jne .Lname_bad
 lea rbx, [rip+.Ldot]
 mov ecx, 2
.Lname_compare:
 lea rsi, [r13+rax]
 mov rdi, rbx
 cld
 repe cmpsb
 jne .Lname_bad
 xor eax, eax
 ret
.Lname_shard:
 cmp qword ptr [r14+40], 2
 jne .Lname_bad
 cmp byte ptr [r13+2306], 0
 jne .Lname_bad
 xor ecx, ecx
.Lname_digit:
 movzx edx, byte ptr [r13+2304+rcx]
 cmp edx, 48
 jb .Lname_bad
 cmp edx, 57
 jbe .Lname_digit_good
 cmp edx, 97
 jb .Lname_bad
 cmp edx, 102
 ja .Lname_bad
.Lname_digit_good:
 mov [r12+3072+rcx], dl
 inc ecx
 cmp ecx, 2
 jb .Lname_digit
 mov byte ptr [r12+3074], 0
 lea rbx, [r12+3072]
 xor eax, eax
 ret
.Lname_bad:
 mov eax, 1
 ret

.Lhex:
 cmp dl, 10
 jb .Lhex_low
 add dl, 87
 ret
.Lhex_low:
 add dl, 48
 ret

.Lstat_output:
 mov rax, [r12+2560]
 mov [r13+512], rax
 mov rax, [r12+2568]
 mov [r13+520], rax
 mov eax, dword ptr [r12+2584]
 mov [r13+528], rax
 mov eax, dword ptr [r12+2588]
 mov [r13+536], rax
 mov eax, dword ptr [r12+2592]
 mov [r13+544], rax
 mov rax, [r12+2576]
 mov [r13+552], rax
 mov rax, [r12+2608]
 mov [r13+560], rax
 mov rax, [r12+2648]
 mov [r13+568], rax
 mov rax, [r12+2656]
 mov [r13+576], rax
 mov rax, [r12+2664]
 mov [r13+584], rax
 mov rax, [r12+2672]
 mov [r13+592], rax
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
 lea rsi, [r13+256]
 lea rdi, [r12+2304]
 mov ecx, 64
 cld
 rep movsb
 lea rsi, [r13+1536]
 lea rdi, [r12+2368]
 mov ecx, 32
 rep movsb
 ret

.Lcomplete:
 cmp rax, -4095
 jae .Leffect_errno
 mov [r14+72], rax
 mov qword ptr [r14+80], 0
 jmp .Lcompleted
.Leffect_errno:
 neg rax
 mov [r14+80], rax
 mov qword ptr [r14+72], 0
.Lcompleted:
 mov rax, [r12+32]
 mov [r14+64], rax
 xor eax, eax
 jmp .Ldone

.Linvalid_owned:
 mov rdi, rax
 mov eax, 3
 syscall
 mov rax, -22
 jmp .Lcomplete
.Lbusy:
 mov rax, -16
 jmp .Ldone
.Linvalid:
 mov rax, -22
.Ldone:
 RESTORE

durable_audit_archive_layout_child_ack:
 SAVE
 mov r12, rdi
 mov r15, rsi
 mov rbp, rdx
 mov rax, MAGIC
 cmp [r12], rax
 jne .Linvalid
 cmp qword ptr [r12+8], 0
 jne .Linvalid
 cmp qword ptr [r12+40], 1
 jne .Linvalid
 mov r13, [r12+16]
 lea r14, [r13+256]
 lea rsi, [r12+2304]
 mov rdi, r14
 mov ecx, 64
 cld
 repe cmpsb
 jne .Linvalid
 mov rax, [r14+64]
 or rax, [r14+72]
 or rax, [r14+80]
 or rax, [r14+88]
 jnz .Linvalid
 lea rsi, [r12+2368]
 lea rdi, [r13+1536]
 mov ecx, 32
 repe cmpsb
 jne .Linvalid
 mov rcx, [r12+48]
 lea rsi, [r12+12288]
 lea rdi, [r13+131072]
 repe cmpsb
 jne .Linvalid
 cmp rbp, 4095
 ja .Linvalid
 test rbp, rbp
 jnz .Lack_error
 cmp r15, [r14+56]
 ja .Linvalid
 jmp .Lack_ready
.Lack_error:
 test r15, r15
 jnz .Linvalid
.Lack_ready:
 mov qword ptr [r12+40], 0
 mov [r14+72], r15
 mov [r14+80], rbp
 mov rax, [r12+32]
 mov [r14+64], rax
 xor eax, eax
 jmp .Ldone

durable_audit_archive_layout_take:
 mov rax, -1
 ret

durable_audit_archive_layout_destroy:
 SAVE
 mov r12, rdi
 mov rax, MAGIC
 cmp [r12], rax
 jne .Linvalid
 cmp qword ptr [r12+8], 0
 jne .Linvalid
 cmp qword ptr [r12+40], 0
 jne .Lbusy
 mov qword ptr [r12+8], 1
 mov r15d, 2
.Ldestroy_loop:
 cmp byte ptr [r12+4096+r15], 1
 jne .Ldestroy_next
 mov rdi, [r12+64+r15*8]
 mov qword ptr [r12+64+r15*8], -1
 mov byte ptr [r12+4096+r15], 0
 mov eax, 3
 syscall
.Ldestroy_next:
 inc r15
 cmp r15, 264
 jb .Ldestroy_loop
 mov rdi, r12
 mov esi, 65536
 mov eax, 11
 syscall
 jmp .Ldone

.Lroot: .asciz "request-archive-v12"
.Lanchor: .asciz ".request-archive-v12-anchor.json"
.Lintent: .asciz ".request-archive-v12-init.json"
.Llegacy: .asciz "request-archive-v11"
.Ldot: .asciz "."
.section .note.GNU-stack,"",@progbits
