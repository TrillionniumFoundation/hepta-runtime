/* Copyright 2026 Muvon Un Limited
 * Copyright 2026 TrillionniumFoundation
 * SPDX-License-Identifier: Apache-2.0
 *
 * Independent mechanical REA descriptor effects for a closed HIA actor.
 * Development assembly is an oracle for the HIA emitter, never a runtime
 * dependency. The private caller owns an exclusive workspace throughout a
 * call. No pointer, slot, descriptor or context is a public request value.
 *
 * create(workspace, capacity) -> context
 * step(context) -> 0 for an acknowledged actual syscall, negative protocol error
 * take(context) -> file fd only when both parent slots have been released
 * destroy(context) -> closes owned file before parents and releases mappings
 *
 * The twelve-u64 action is at workspace+256:
 * HRFDAC01, sequence, operation, slot, span, length, argument, parent,
 * ack_sequence, result, errno, reserved.
 * Operations: 1 root open, 2 directory openat, 3 file openat, 4 fstat,
 * 5 geteuid, 6 pread, 7 read, 8 close.
 *
 * Context layout follows the explicit owned table: magic0, workspace16,
 * capacity24, sequence32, in-flight40, owned-mask56, descriptors64/72/80,
 * temporary path120/128, unmap error136, immutable action160..223, stat256.
 */
.intel_syntax noprefix
.section .text
.equ REA_CONTEXT, 0x31304e4544465248
.equ REA_ACTION, 0x3130434144465248
.macro SAVE
 push rbp
 push rbx
 push r12
 push r13
 push r14
 push r15
 sub rsp, 8
.endm
.macro RETURN
 add rsp, 8
 pop r15
 pop r14
 pop r13
 pop r12
 pop rbx
 pop rbp
 ret
.endm
.global rea_descriptor_create
.global rea_descriptor_step
.global rea_descriptor_take
.global rea_descriptor_destroy

rea_descriptor_create:
 SAVE
 mov r12, rdi
 mov r13, rsi
 test r12, r12
 jz .Lcreate_invalid
 cmp r13, 4096
 jb .Lcreate_invalid
 mov rax, r12
 add rax, r13
 jc .Lcreate_invalid
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
 mov rdx, REA_CONTEXT
 mov [rax], rdx
 mov [rax+16], r12
 mov [rax+24], r13
 mov qword ptr [rax+64], -1
 mov qword ptr [rax+72], -1
 mov qword ptr [rax+80], -1
 jmp .Lcreate_done
.Lcreate_invalid:
 mov rax, -22
.Lcreate_done:
 RETURN

rea_descriptor_step:
 SAVE
 mov r12, rdi
 mov rax, REA_CONTEXT
 cmp [r12], rax
 jne .Linvalid
 cmp qword ptr [r12+40], 0
 jne .Lbusy
 cmp qword ptr [r12+120], 0
 jne .Lbusy
 mov r13, [r12+16]
 lea rsi, [r13+256]
 lea rdi, [r12+160]
 mov ecx, 8
 cld
 rep movsq
 lea r14, [r12+160]
 mov rax, REA_ACTION
 cmp [r14], rax
 jne .Linvalid
 mov rax, [r12+32]
 add rax, 1
 jc .Linvalid
 cmp [r14+8], rax
 jne .Linvalid
 mov rax, [r13+320]
 or rax, [r13+328]
 or rax, [r13+336]
 or rax, [r13+344]
 jnz .Linvalid
 mov r15, [r14+24]
 cmp r15, 2
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
 je .Lroot
 cmp rax, 2
 je .Ldirectory
 cmp rax, 3
 je .Lfile
 cmp rax, 4
 je .Lfstat
 cmp rax, 5
 je .Lgeteuid
 cmp rax, 6
 je .Lpread
 cmp rax, 7
 je .Lread
 cmp rax, 8
 je .Lclose
 jmp .Linvalid

.Lroot:
 test r15, r15
 jnz .Linvalid
 cmp qword ptr [r12+56], 0
 jne .Linvalid
 cmp qword ptr [r14+48], 0xb0000
 jne .Linvalid
 cmp qword ptr [r14+56], 0
 jne .Linvalid
 cmp qword ptr [r14+32], 1024
 jb .Linvalid
 mov eax, 1
 call .Lpath_valid
 test eax, eax
 jnz .Linvalid
 mov rax, [r14+32]
 cmp byte ptr [r13+rax], '/'
 jne .Linvalid
 call .Lbegin
 call .Lpath_allocate
 cmp rax, -4095
 jae .Lcomplete
 mov rdi, [r12+120]
 mov esi, 0xb0000
 xor edx, edx
 mov eax, 2
 syscall
 jmp .Lopened

.Ldirectory:
 cmp r15, 1
 ja .Linvalid
 cmp qword ptr [r14+48], 0xb0000
 jne .Linvalid
 jmp .Lrelative
.Lfile:
 cmp r15, 2
 jne .Linvalid
 cmp qword ptr [r14+48], 0xa0800
 jne .Linvalid
.Lrelative:
 cmp qword ptr [r12+r15*8+64], -1
 jne .Linvalid
 bt qword ptr [r12+56], r15
 jc .Linvalid
 mov rbx, [r14+56]
 cmp rbx, 1
 ja .Linvalid
 cmp rbx, r15
 je .Linvalid
 bt qword ptr [r12+56], rbx
 jnc .Linvalid
 cmp qword ptr [r12+rbx*8+64], 0
 jl .Linvalid
 cmp qword ptr [r14+32], 1024
 jb .Linvalid
 xor eax, eax
 call .Lpath_valid
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
.Lopened:
 cmp rax, -4095
 jae .Lcomplete
 cmp rax, 0x7fffffff
 ja .Lopened_invalid
 mov [r12+r15*8+64], rax
 bts qword ptr [r12+56], r15
 xor eax, eax
 jmp .Lcomplete
.Lopened_invalid:
 mov rdi, rax
 mov eax, 3
 syscall
 mov rax, -75
 jmp .Lcomplete

.Lfstat:
 cmp r15, 2
 jne .Linvalid
 bt qword ptr [r12+56], 2
 jnc .Linvalid
 cmp qword ptr [r12+80], 0
 jl .Linvalid
 cmp qword ptr [r14+32], 512
 jne .Linvalid
 cmp qword ptr [r14+40], 88
 jne .Linvalid
 mov rax, [r14+48]
 or rax, [r14+56]
 jnz .Linvalid
 call .Lbegin
 mov rdi, [r12+80]
 lea rsi, [r12+256]
 mov eax, 5
 syscall
 test rax, rax
 jnz .Lcomplete
 mov rax, [r12+256]
 mov [r13+512], rax
 mov rax, [r12+264]
 mov [r13+520], rax
 mov rax, [r12+304]
 mov [r13+528], rax
 mov eax, dword ptr [r12+280]
 mov [r13+536], rax
 mov eax, dword ptr [r12+284]
 mov [r13+544], rax
 mov eax, dword ptr [r12+288]
 mov [r13+552], rax
 mov rax, [r12+272]
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

.Lgeteuid:
 cmp r15, 2
 jne .Linvalid
 bt qword ptr [r12+56], 2
 jnc .Linvalid
 call .Lzero_args
 test rax, rax
 jnz .Linvalid
 call .Lbegin
 mov eax, 107
 syscall
 jmp .Lcomplete

.Lpread:
 cmp qword ptr [r14+56], 0
 jne .Linvalid
 jmp .Lread_common
.Lread:
 mov rax, [r14+48]
 or rax, [r14+56]
 jnz .Linvalid
.Lread_common:
 cmp r15, 2
 jne .Linvalid
 bt qword ptr [r12+56], 2
 jnc .Linvalid
 cmp qword ptr [r12+80], 0
 jl .Linvalid
 cmp qword ptr [r14+32], 4096
 jb .Linvalid
 call .Lbegin
 mov rdi, [r12+80]
 mov rsi, [r14+32]
 add rsi, r13
 mov rdx, [r14+40]
 mov r10, [r14+48]
 xor eax, eax
 cmp qword ptr [r14+16], 7
 je .Lread_syscall
 mov eax, 17
.Lread_syscall:
 syscall
 jmp .Lcomplete

.Lclose:
 call .Lzero_args
 test rax, rax
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

/* eax=1 admits the original absolute configured-root spelling. eax=0
   admits one nonempty Normal component, with no slash, NUL, "." or "..". */
.Lpath_valid:
 mov edx, eax
 mov rcx, [r14+40]
 test rcx, rcx
 jz .Lhelper_invalid
 mov rsi, [r14+32]
 add rsi, r13
 test edx, edx
 jnz .Lpath_loop
 cmp byte ptr [rsi], '.'
 jne .Lpath_loop
 cmp rcx, 1
 je .Lhelper_invalid
 cmp rcx, 2
 jne .Lpath_loop
 cmp byte ptr [rsi+1], '.'
 je .Lhelper_invalid
.Lpath_loop:
 mov al, [rsi]
 test al, al
 jz .Lhelper_invalid
 test edx, edx
 jnz .Lpath_next
 cmp al, '/'
 je .Lhelper_invalid
.Lpath_next:
 inc rsi
 dec rcx
 jnz .Lpath_loop
 xor eax, eax
 ret
.Lhelper_invalid:
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
 jz .Lack
 mov rsi, [r12+128]
 mov eax, 11
 syscall
 test rax, rax
 jnz .Lunmap_failed
 mov qword ptr [r12+120], 0
 mov qword ptr [r12+128], 0
 jmp .Lack
.Lunmap_failed:
 mov [r12+136], rax
.Lack:
 mov rax, [r12+32]
 mov [r13+320], rax
 cmp rbp, -4095
 jae .Lerrno
 mov [r13+328], rbp
 jmp .Lack_done
.Lerrno:
 neg rbp
 mov [r13+336], rbp
.Lack_done:
 mov qword ptr [r12+40], 0
 xor eax, eax
 jmp .Ldone
.Lbusy:
 mov rax, -16
 jmp .Ldone
.Linvalid:
 mov rax, -22
.Ldone:
 RETURN

rea_descriptor_take:
 SAVE
 mov r12, rdi
 mov rax, REA_CONTEXT
 cmp [r12], rax
 jne .Linvalid
 cmp qword ptr [r12+40], 0
 jne .Lbusy
 cmp qword ptr [r12+120], 0
 jne .Lbusy
 cmp qword ptr [r12+56], 4
 jne .Linvalid
 mov rax, [r12+80]
 test rax, rax
 js .Linvalid
 mov qword ptr [r12+80], -1
 mov qword ptr [r12+56], 0
 jmp .Ldone

rea_descriptor_destroy:
 SAVE
 mov r12, rdi
 mov rax, REA_CONTEXT
 cmp [r12], rax
 jne .Linvalid
 cmp qword ptr [r12+40], 0
 jne .Lbusy
 xor ebx, ebx
 mov r15d, 2
.Ldestroy_slot:
 bt qword ptr [r12+56], r15
 jnc .Ldestroy_next
 mov rdi, [r12+r15*8+64]
 mov qword ptr [r12+r15*8+64], -1
 btr qword ptr [r12+56], r15
 mov eax, 3
 syscall
 test rax, rax
 jz .Ldestroy_next
 test rbx, rbx
 cmovz rbx, rax
.Ldestroy_next:
 sub r15, 1
 jnc .Ldestroy_slot
 mov rdi, [r12+120]
 test rdi, rdi
 jz .Ldestroy_context
 mov rsi, [r12+128]
 mov eax, 11
 syscall
 test rax, rax
 jnz .Ldone
 mov qword ptr [r12+120], 0
 mov qword ptr [r12+128], 0
.Ldestroy_context:
 mov qword ptr [r12], 0
 mov rdi, r12
 mov esi, 4096
 mov eax, 11
 syscall
 test rax, rax
 jnz .Ldestroy_retained
 mov rax, rbx
 jmp .Ldone
.Ldestroy_retained:
 mov rdx, REA_CONTEXT
 mov [r12], rdx
 jmp .Ldone
.section .note.GNU-stack,"",@progbits

