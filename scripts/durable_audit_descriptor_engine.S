/* Copyright 2026 Muvon Un Limited
 * Copyright 2026 TrillionniumFoundation
 * SPDX-License-Identifier: Apache-2.0
 *
 * Private Linux x86-64 audit descriptor effects. All policy and ordering are
 * owned by the fixed HIA Root/Record-I/O/Hot actors. No path, descriptor or
 * context pointer in this interface is a public MCP parameter.
 *
 * create(mode, workspace, capacity, borrowed_directory):
 *   modes 0 Root, 1 Record I/O, 2 Hot. Root requires -1, others a held private
 *   directory capability. Returned context owns only slots 1..5.
 * step(context): 0 completed effect, 1 exact child call pending, negative
 *   private-protocol/resource failure. Effects are consumed once.
 * child_ack(context, result, errno): completes only the pending child.
 * take(context, slot): transfers an actual owned descriptor after HIA terminal
 *   output has been validated by the private caller.
 * destroy(context): requires no pending child/effect, closes owned slots once.
 *
 * Context: magic0, mode8, workspace16, capacity24, sequence32, pending40,
 * owned-mask56, descriptors64..111, temporary path120/128, private action160..223, stat256..399.
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
.equ AUDIT_MAGIC, 0x3130474e45415248
.global durable_audit_descriptor_create
.global durable_audit_descriptor_step
.global durable_audit_descriptor_child_ack
.global durable_audit_descriptor_take
.global durable_audit_descriptor_destroy

durable_audit_descriptor_create:
 SAVE
 mov r12, rdi
 mov r13, rsi
 mov r14, rdx
 mov r15, rcx
 cmp r12, 2
 ja .Lcreate_invalid
 test r13, r13
 jz .Lcreate_invalid
 mov eax, 1056
 test r12, r12
 jz .Lcreate_root
 mov eax, 65536
 cmp r12, 1
 je .Lcreate_borrow
 mov eax, 532480
.Lcreate_borrow:
 test r15, r15
 js .Lcreate_invalid
 cmp r15, 0x7fffffff
 ja .Lcreate_invalid
 jmp .Lcreate_capacity
.Lcreate_root:
 cmp r15, -1
 jne .Lcreate_invalid
.Lcreate_capacity:
 cmp r14, rax
 jb .Lcreate_invalid
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
 mov rdx, AUDIT_MAGIC
 mov [rbx], rdx
 mov [rbx+8], r12
 mov [rbx+16], r13
 mov [rbx+24], r14
 mov [rbx+64], r15
 mov qword ptr [rbx+72], -1
 mov qword ptr [rbx+80], -1
 mov qword ptr [rbx+88], -1
 mov qword ptr [rbx+96], -1
 mov qword ptr [rbx+104], -1
 jmp .Lcreate_done
.Lcreate_invalid:
 mov rax, -22
.Lcreate_done:
 RESTORE

durable_audit_descriptor_step:
 SAVE
 mov r12, rdi
 mov rax, AUDIT_MAGIC
 cmp [r12], rax
 jne .Linvalid
 cmp qword ptr [r12+40], 0
 jne .Lbusy
 cmp qword ptr [r12+120], 0
 jne .Lbusy
 mov r13, [r12+16]
 lea r14, [r13+256]
 mov rax, 0x3130534452415248 /* HRARDS01 */
 cmp qword ptr [r12+8], 0
 je .Lmagic
 mov rax, 0x3130534144415248 /* HRADAS01 */
 cmp qword ptr [r12+8], 1
 je .Lmagic
 mov rax, 0x3130534148415248 /* HRAHAS01 */
.Lmagic:
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
 je .Lopenat
 cmp rax, 2
 je .Lfstat
 cmp rax, 3
 je .Lread
 cmp rax, 4
 je .Lunlink
 cmp rax, 5
 je .Lsync
 cmp rax, 6
 je .Lclose
 cmp rax, 7
 je .Ldup
 cmp rax, 8
 je .Lgetdents
 cmp rax, 9
 je .Lgetfl
 cmp rax, 10
 je .Lsetfd
 cmp rax, 11
 je .Lroot
 cmp rax, 12
 je .Lmkdir
 cmp rax, 100
 je .Lchild
 jmp .Linvalid

.Lopenat:
 test r15, r15
 jz .Linvalid
 cmp qword ptr [r12+r15*8+64], -1
 jne .Linvalid
 mov rbx, [r14+56]
 cmp qword ptr [r12+8], 0
 jne .Lopen_nonroot
 cmp r15, 3
 ja .Linvalid
 cmp rbx, 3
 ja .Linvalid
 test rbx, rbx
 jz .Linvalid
 mov rax, [r14+48]
 cmp rax, 0x2b0000
 je .Lopen_flags
 cmp rax, 0xb0000
 jne .Linvalid
 jmp .Lopen_flags
.Lopen_nonroot:
 test rbx, rbx
 jnz .Linvalid
 cmp qword ptr [r14+40], 255
 ja .Linvalid
 mov rax, [r14+48]
 cmp rax, 0xa0800
 je .Lopen_io_flag
 cmp rax, 0xb0000
 jne .Linvalid
 jmp .Lopen_hot_check
.Lopen_io_flag:
 cmp qword ptr [r12+8], 1
 jne .Linvalid
.Lopen_hot_check:
 cmp qword ptr [r12+8], 2
 jne .Lopen_flags
 cmp r15, 4
 jne .Linvalid
 cmp qword ptr [r14+32], 640
 jne .Linvalid
 cmp qword ptr [r14+40], 1
 jne .Linvalid
 cmp byte ptr [r13+640], '.'
 jne .Linvalid
.Lopen_flags:
 cmp qword ptr [r12+rbx*8+64], 0
 jl .Linvalid
 call .Lpath_validate
 test eax, eax
 jnz .Linvalid
 call .Lbegin
 call .Lpath_allocate
 cmp rax, -4095
 jae .Lcomplete
 mov rdi, [r12+rbx*8+64]
 mov rsi, [r12+120]
 mov rdx, [r14+48]
 xor r10d, r10d
 mov eax, 257
 syscall
 jmp .Lopened

.Lroot:
 cmp qword ptr [r12+8], 0
 jne .Linvalid
 cmp r15, 1
 jne .Linvalid
 cmp qword ptr [r12+72], -1
 jne .Linvalid
 cmp qword ptr [r14+32], 768
 jne .Linvalid
 cmp qword ptr [r14+40], 1
 jne .Linvalid
 cmp qword ptr [r14+48], 0x2b0000
 jne .Linvalid
 cmp qword ptr [r14+56], 0
 jne .Linvalid
 cmp byte ptr [r13+768], '/'
 jne .Linvalid
 call .Lbegin
 lea rdi, [rip+.Lslash]
 mov esi, 0x2b0000
 xor edx, edx
 mov eax, 2
 syscall
.Lopened:
 cmp rax, -4095
 jae .Lcomplete
 cmp rax, 0x7fffffff
 ja .Linvalid_owned
 mov [r12+r15*8+64], rax
 bts qword ptr [r12+56], r15
 xor eax, eax
 jmp .Lcomplete

.Lfstat:
 cmp qword ptr [r12+8], 2
 jne .Lfstat_not_hot
 cmp r15, 5
 jne .Linvalid
.Lfstat_not_hot:
 cmp qword ptr [r12+8], 0
 jne .Lfstat_role_valid
 test r15, r15
 jz .Linvalid
 cmp r15, 3
 ja .Linvalid
.Lfstat_role_valid:
 cmp qword ptr [r14+32], 512
 jne .Linvalid
 cmp qword ptr [r14+40], 88
 jne .Linvalid
 mov rax, [r14+48]
 or rax, [r14+56]
 jnz .Linvalid
 cmp qword ptr [r12+r15*8+64], 0
 jl .Linvalid
 call .Lbegin
 mov rdi, [r12+r15*8+64]
 lea rsi, [r12+256]
 mov eax, 5
 syscall
 test rax, rax
 jnz .Lcomplete
 mov eax, dword ptr [r12+280]
 mov [r13+512], rax
 mov eax, dword ptr [r12+284]
 mov [r13+520], rax
 mov eax, 107
 syscall
 mov [r13+528], rax
 mov rax, [r12+272]
 mov [r13+536], rax
 mov rax, [r12+304]
 mov [r13+544], rax
 mov rax, [r12+256]
 mov [r13+552], rax
 mov rax, [r12+264]
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
 cmp qword ptr [r12+8], 1
 jne .Linvalid
 cmp r15, 1
 jne .Linvalid
 cmp qword ptr [r12+72], 0
 jl .Linvalid
 mov rax, [r14+48]
 or rax, [r14+56]
 jnz .Linvalid
 cmp qword ptr [r14+32], 40000
 jb .Linvalid
 mov rax, [r14+32]
 add rax, [r14+40]
 cmp rax, 42049
 ja .Linvalid
 cmp qword ptr [r14+40], 0
 je .Linvalid
 cmp qword ptr [r14+40], 2049
 ja .Linvalid
 call .Lbegin
 mov rdi, [r12+72]
 mov rsi, [r14+32]
 add rsi, r13
 mov rdx, [r14+40]
 xor eax, eax
 syscall
 jmp .Lcomplete

.Lunlink:
 cmp qword ptr [r12+8], 1
 jne .Linvalid
 test r15, r15
 jnz .Linvalid
 cmp qword ptr [r12+64], 0
 jl .Linvalid
 mov rax, [r14+48]
 or rax, [r14+56]
 jnz .Linvalid
 cmp qword ptr [r14+40], 255
 ja .Linvalid
 call .Lpath_validate
 test eax, eax
 jnz .Linvalid
 call .Lbegin
 call .Lpath_allocate
 cmp rax, -4095
 jae .Lcomplete
 mov rdi, [r12+64]
 mov rsi, [r12+120]
 xor edx, edx
 mov eax, 263
 syscall
 jmp .Lcomplete

.Lsync:
 cmp qword ptr [r12+8], 2
 je .Linvalid
 cmp qword ptr [r12+8], 1
 jne .Lsync_role
 test r15, r15
 jnz .Linvalid
.Lsync_role:
 call .Lzero_args
 test eax, eax
 jnz .Linvalid
 cmp qword ptr [r12+r15*8+64], 0
 jl .Linvalid
 call .Lbegin
 mov rdi, [r12+r15*8+64]
 mov eax, 74
 syscall
 jmp .Lcomplete

.Lclose:
 test r15, r15
 jz .Linvalid
 call .Lzero_args
 test eax, eax
 jnz .Linvalid
 bt qword ptr [r12+56], r15
 jnc .Linvalid
 cmp qword ptr [r12+r15*8+64], 0
 jl .Linvalid
 call .Lbegin
 mov rdi, [r12+r15*8+64]
 mov qword ptr [r12+r15*8+64], -1
 btr qword ptr [r12+56], r15
 mov eax, 3
 syscall
 jmp .Lcomplete

.Ldup:
 cmp qword ptr [r12+8], 0
 je .Linvalid
 cmp r15, 5
 jne .Linvalid
 cmp qword ptr [r14+48], 4
 jne .Linvalid
 mov rax, [r14+32]
 or rax, [r14+40]
 or rax, [r14+56]
 jnz .Linvalid
 cmp qword ptr [r12+104], -1
 jne .Linvalid
 cmp qword ptr [r12+96], 0
 jl .Linvalid
 call .Lbegin
 mov rdi, [r12+96]
 mov esi, 1030
 xor edx, edx
 mov eax, 72
 syscall
 jmp .Lopened

.Lgetdents:
 cmp qword ptr [r12+8], 0
 je .Linvalid
 cmp r15, 5
 jne .Linvalid
 cmp qword ptr [r14+32], 4096
 jne .Linvalid
 cmp qword ptr [r14+40], 32768
 jne .Linvalid
 mov rax, [r14+48]
 or rax, [r14+56]
 jnz .Linvalid
 cmp qword ptr [r12+104], 0
 jl .Linvalid
 call .Lbegin
 mov rdi, [r12+104]
 lea rsi, [r13+4096]
 mov edx, 32768
 mov eax, 217
 syscall
 jmp .Lcomplete

.Lgetfl:
 cmp qword ptr [r12+8], 0
 je .Linvalid
 cmp r15, 5
 jne .Linvalid
 call .Lzero_args
 test eax, eax
 jnz .Linvalid
 cmp qword ptr [r12+104], 0
 jl .Linvalid
 call .Lbegin
 mov rdi, [r12+104]
 mov esi, 3
 xor edx, edx
 mov eax, 72
 syscall
 jmp .Lcomplete

.Lsetfd:
 cmp qword ptr [r12+8], 0
 je .Linvalid
 cmp r15, 5
 jne .Linvalid
 mov rax, [r14+32]
 or rax, [r14+40]
 or rax, [r14+56]
 jnz .Linvalid
 cmp qword ptr [r14+48], 1
 jne .Linvalid
 cmp qword ptr [r12+104], 0
 jl .Linvalid
 call .Lbegin
 mov rdi, [r12+104]
 mov esi, 2
 mov edx, 1
 mov eax, 72
 syscall
 jmp .Lcomplete

.Lmkdir:
 cmp qword ptr [r12+8], 0
 jne .Linvalid
 test r15, r15
 jz .Linvalid
 cmp r15, 3
 ja .Linvalid
 cmp qword ptr [r12+r15*8+64], 0
 jl .Linvalid
 cmp qword ptr [r14+32], 800
 jne .Linvalid
 cmp qword ptr [r14+40], 13
 jne .Linvalid
 cmp qword ptr [r14+48], 448
 jne .Linvalid
 cmp qword ptr [r14+56], 0
 jne .Linvalid
 lea rsi, [r13+800]
 lea rdi, [rip+.Lhot_name]
 mov ecx, 13
 cld
 repe cmpsb
 jne .Linvalid
 call .Lbegin
 mov rdi, [r12+r15*8+64]
 lea rsi, [rip+.Lhot_name]
 mov edx, 448
 mov eax, 258
 syscall
 jmp .Lcomplete

.Lchild:
 cmp qword ptr [r12+8], 0
 je .Linvalid
 test r15, r15
 jnz .Linvalid
 cmp qword ptr [r14+56], 4096
 jne .Linvalid
 cmp qword ptr [r12+8], 1
 jne .Lhot_child
 cmp qword ptr [r14+32], 44000
 jne .Linvalid
 cmp qword ptr [r14+40], 101
 jb .Linvalid
 cmp qword ptr [r14+40], 2149
 ja .Linvalid
 cmp qword ptr [r14+48], 48000
 jne .Linvalid
 jmp .Lchild_ready
.Lhot_child:
 cmp qword ptr [r12+56], 0
 jne .Linvalid
 cmp qword ptr [r14+32], 524288
 jne .Linvalid
 cmp qword ptr [r14+40], 32
 jb .Linvalid
 cmp qword ptr [r14+40], 287
 ja .Linvalid
 cmp qword ptr [r14+48], 525312
 jne .Linvalid
.Lchild_ready:
 mov rax, [r14+48]
 add rax, [r14+56]
 jc .Linvalid
 cmp rax, [r12+24]
 ja .Linvalid
 call .Lbegin
 mov qword ptr [r12+40], 2
 mov eax, 1
 jmp .Ldone

.Lpath_validate:
 mov rcx, [r14+40]
 test rcx, rcx
 jz .Lhelper_invalid
 mov rsi, [r14+32]
 add rsi, r13
.Lpath_char:
 mov al, [rsi]
 test al, al
 jz .Lhelper_invalid
 cmp al, '/'
 je .Lhelper_invalid
 inc rsi
 dec rcx
 jnz .Lpath_char
 xor eax, eax
 ret
.Lzero_args:
 mov rax, [r14+32]
 or rax, [r14+40]
 or rax, [r14+48]
 or rax, [r14+56]
 ret
.Lhelper_invalid:
 mov eax, 1
 ret
.Lbegin:
 mov rax, [r14+8]
 mov [r12+32], rax
 mov qword ptr [r12+40], 1
 xor ecx, ecx
.Lcapture_action:
 mov rax, [r14+rcx]
 mov [r12+rcx+160], rax
 add ecx, 8
 cmp ecx, 64
 jb .Lcapture_action
 ret
.Lpath_allocate:
 mov rsi, [r14+40]
 add rsi, 1
 jc .Lallocation_failed
 mov [r12+128], rsi
 xor edi, edi
 mov edx, 3
 mov r10d, 0x22
 mov r8, -1
 xor r9d, r9d
 mov eax, 9
 syscall
 cmp rax, -4095
 jae .Lallocation_return
 mov [r12+120], rax
 mov rdi, rax
 mov rsi, [r14+32]
 add rsi, r13
 mov rcx, [r14+40]
 cld
 rep movsb
 mov byte ptr [rdi], 0
 xor eax, eax
.Lallocation_return:
 ret
.Lallocation_failed:
 mov rax, -12
 ret

.Lcomplete:
 mov rbp, rax
 mov rdi, [r12+120]
 test rdi, rdi
 jz .Lcompletion_payload
 mov rsi, [r12+128]
 mov eax, 11
 syscall
 test rax, rax
 jz .Lpath_released
 /* A known failed unmap retains the exact mapping for destroy. The actual
    filesystem result is acknowledged once; step cannot start another effect. */
 mov [r12+136], rax
 jmp .Lcompletion_payload
.Lpath_released:
 mov qword ptr [r12+120], 0
 mov qword ptr [r12+128], 0
.Lcompletion_payload:
 mov rax, [r12+32]
 mov [r14+64], rax
 cmp rbp, -4095
 jae .Leffect_errno
 mov [r14+72], rbp
 jmp .Lcompleted
.Leffect_errno:
 neg rbp
 mov [r14+80], rbp
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

durable_audit_descriptor_child_ack:
 SAVE
 mov r12, rdi
 mov rbx, rsi
 mov rbp, rdx
 mov rax, AUDIT_MAGIC
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
 jz .Lchild_ack_ready
 test rbx, rbx
 jnz .Linvalid
.Lchild_ack_ready:
 mov [r14+64], rax
 mov [r14+72], rbx
 mov [r14+80], rbp
 mov qword ptr [r12+40], 0
 xor eax, eax
 jmp .Ldone

durable_audit_descriptor_take:
 SAVE
 mov r12, rdi
 mov r15, rsi
 mov rax, AUDIT_MAGIC
 cmp [r12], rax
 jne .Linvalid
 cmp qword ptr [r12+40], 0
 jne .Lbusy
 cmp r15, 1
 jb .Linvalid
 cmp r15, 5
 ja .Linvalid
 bt qword ptr [r12+56], r15
 jnc .Linvalid
 mov rax, [r12+r15*8+64]
 test rax, rax
 js .Linvalid
 mov qword ptr [r12+r15*8+64], -1
 btr qword ptr [r12+56], r15
 jmp .Ldone

durable_audit_descriptor_destroy:
 SAVE
 mov r12, rdi
 mov rax, AUDIT_MAGIC
 cmp [r12], rax
 jne .Linvalid
 cmp qword ptr [r12+40], 0
 jne .Lbusy
 xor ebx, ebx
 mov r15d, 1
.Ldestroy_next:
 bt qword ptr [r12+56], r15
 jnc .Ldestroy_continue
 mov rdi, [r12+r15*8+64]
 mov qword ptr [r12+r15*8+64], -1
 btr qword ptr [r12+56], r15
 mov eax, 3
 syscall
 test rax, rax
 jz .Ldestroy_continue
 test rbx, rbx
 cmovz rbx, rax
.Ldestroy_continue:
 inc r15
 cmp r15, 6
 jb .Ldestroy_next
 mov rdi, [r12+120]
 test rdi, rdi
 jz .Ldestroy_control
 mov rsi, [r12+128]
 mov eax, 11
 syscall
 test rax, rax
 jnz .Ldone
 mov qword ptr [r12+120], 0
 mov qword ptr [r12+128], 0
.Ldestroy_control:
 mov qword ptr [r12], 0
 mov rdi, r12
 mov esi, 4096
 mov eax, 11
 syscall
 test rax, rax
 jnz .Ldestroy_mapping_retained
 mov rax, rbx
 jmp .Ldone
.Ldestroy_mapping_retained:
 /* A failed control unmap leaves the exact context available for cleanup.
    All descriptor closes above remain consumed and cannot be repeated. */
 mov rdx, AUDIT_MAGIC
 mov [r12], rdx
 jmp .Ldone

.Lslash:
 .asciz "/"
.Lhot_name:
 .asciz "request-audit"
.section .note.GNU-stack,"",@progbits
