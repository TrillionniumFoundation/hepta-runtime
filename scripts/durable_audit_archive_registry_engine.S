/* Copyright 2026 Muvon Un Limited
 * Copyright 2026 TrillionniumFoundation
 * SPDX-License-Identifier: Apache-2.0
 * Private shared registry storage. The actual HIA image owns identities,
 * reference counts, pruning, reservations and poison/fatal classification.
 * Entry is a retained, verified HIA image; only private runtime callers use
 * these pointers. Destroy requires exclusive outer ownership and all callers
 * joined. A context is shared by all sessions of one runtime instance.
 */
.intel_syntax noprefix
.section .text
.equ R_MAGIC, 0x3130475241415248
.equ REQUEST, 0x3130515241415248
.equ RESPONSE, 0x3130525241415248
.equ C_MAGIC, 0
.equ C_PID, 8
.equ C_ENTRY, 16
.equ C_LOCK, 24
.equ C_GENERATION, 28
.equ C_WORK, 32
.equ C_CAP, 40
.equ C_ERROR, 48
.equ C_INPUT, 64
.equ C_OUTPUT, 160
.equ C_EXTRA, 288
.equ C_EXTRA_CAP, 296
.macro SAVE
 push rbp
 push rbx
 push r12
 push r13
 push r14
 push r15
 sub rsp,40
.endm
.macro RETURN
 add rsp,40
 pop r15
 pop r14
 pop r13
 pop r12
 pop rbx
 pop rbp
 ret
.endm
.global durable_audit_archive_registry_create
.global durable_audit_archive_registry_apply
.global durable_audit_archive_registry_sequence
.global durable_audit_archive_registry_wait
.global durable_audit_archive_registry_destroy

/* create(verified_policy_entry, initial_storage_bytes) -> owned context. */
durable_audit_archive_registry_create:
 SAVE
 mov r13,rdi
 mov r14,rsi
 test r13,r13
 jz .Linvalid
 cmp r14,128
 jb .Linvalid
 test r14,63
 jnz .Linvalid
 test r14,r14
 js .Linvalid
 xor edi,edi
 mov esi,4096
 mov edx,3
 mov r10d,0x22
 mov r8,-1
 xor r9d,r9d
 mov eax,9
 syscall
 cmp rax,-4095
 jae .Lreturn
 mov r12,rax
 mov rdx,R_MAGIC
 mov [r12+C_MAGIC],rdx
 mov [r12+C_ENTRY],r13
 mov [r12+C_CAP],r14
 mov eax,39
 syscall
 mov [r12+C_PID],rax
 xor edi,edi
 mov rsi,r14
 mov edx,3
 mov r10d,0x22
 mov r8,-1
 xor r9d,r9d
 mov eax,9
 syscall
 cmp rax,-4095
 jae .Lcreate_unmap_context
 mov [r12+C_WORK],rax
 mov rax,REQUEST
 mov [r12+C_INPUT],rax
 lea rdi,[r12+C_INPUT]
 mov esi,96
 lea rdx,[r12+C_OUTPUT]
 mov ecx,112
 mov r8,[r12+C_WORK]
 mov r9,[r12+C_CAP]
 call [r12+C_ENTRY]
 cmp rax,112
 jne .Lcreate_bad_policy
 mov rdx,RESPONSE
 cmp [r12+C_OUTPUT],rdx
 jne .Lcreate_bad_policy
 cmp qword ptr [r12+C_OUTPUT+8],0
 jne .Lcreate_bad_policy
 mov rax,r12
 jmp .Lreturn
.Lcreate_bad_policy:
 mov rbx,-71
 mov rdi,[r12+C_WORK]
 mov rsi,[r12+C_CAP]
 mov eax,11
 syscall
 mov rax,rbx
.Lcreate_unmap_context:
 mov rbx,rax
 mov rdi,r12
 mov esi,4096
 mov eax,11
 syscall
 mov rax,rbx
 jmp .Lreturn

/* apply(context, captured_request, 96, output, output_capacity) -> HIA u32
 * or a negative mechanical errno. Calls from actual OS threads are serialized.
 */
durable_audit_archive_registry_apply:
 SAVE
 mov r12,rdi
 mov r13,rsi
 mov r14,rcx
 cmp rdx,96
 jne .Linvalid
 cmp r8,112
 jb .Linvalid
 test r13,r13
 jz .Linvalid
 test r14,r14
 jz .Linvalid
 call .Lidentity
 test rax,rax
 jnz .Lreturn
 lea rdi,[r12+C_LOCK]
 call .Llock
 test rax,rax
 jnz .Lreturn
 mov rax,[r12+C_ERROR]
 test rax,rax
 jnz .Lapply_release
 /* Neither call buffer may alias the owned context or mutable HIA storage. */
 mov rdi,r13
 mov esi,96
 call .Lexternal
 test eax,eax
 jnz .Lapply_invalid
 mov rdi,r14
 mov esi,112
 call .Lexternal
 test eax,eax
 jnz .Lapply_invalid
 lea rdi,[r12+C_INPUT]
 mov rsi,r13
 mov ecx,96
 cld
 rep movsb
.Lapply_call:
 lea rdi,[r12+C_OUTPUT]
 xor eax,eax
 mov ecx,112
 rep stosb
 lea rdi,[r12+C_INPUT]
 mov esi,96
 lea rdx,[r12+C_OUTPUT]
 mov ecx,112
 mov r8,[r12+C_WORK]
 mov r9,[r12+C_CAP]
 call [r12+C_ENTRY]
 mov rbx,rax
 cmp rax,112
 jne .Lapply_result
 mov rdx,RESPONSE
 cmp [r12+C_OUTPUT],rdx
 jne .Lapply_broken
 cmp qword ptr [r12+C_OUTPUT+8],7
 jne .Lapply_result
 cmp qword ptr [r12+C_INPUT+8],1
 jne .Lapply_broken
 mov r15,[r12+C_OUTPUT+48]
 cmp r15,[r12+C_CAP]
 jbe .Lapply_broken
 test r15,63
 jnz .Lapply_broken
 add r15,4095
 jc .Lapply_broken
 and r15,-4096
 test r15,r15
 js .Lapply_broken
 xor edi,edi
 mov rsi,r15
 mov edx,3
 mov r10d,0x22
 mov r8,-1
 xor r9d,r9d
 mov eax,9
 syscall
 cmp rax,-4095
 jae .Lapply_release
 mov rbp,rax
 mov rdi,rbp
 mov rsi,[r12+C_WORK]
 mov rcx,[r12+C_CAP]
 cld
 rep movsb
 mov rdi,[r12+C_WORK]
 mov rsi,[r12+C_CAP]
 mov eax,11
 syscall
 test rax,rax
 jnz .Lapply_growth_quarantine
 mov [r12+C_WORK],rbp
 mov [r12+C_CAP],r15
 jmp .Lapply_call
.Lapply_growth_quarantine:
 mov [r12+C_EXTRA],rbp
 mov [r12+C_EXTRA_CAP],r15
 mov [r12+C_ERROR],rax
 jmp .Lapply_release
.Lapply_broken:
 mov rbx,-71
 mov [r12+C_ERROR],rbx
.Lapply_result:
 mov eax,0xfffffffd
 cmp rbx,rax
 jne .Lapply_copy_result
 mov [r12+C_ERROR],rbx
.Lapply_copy_result:
 mov rdi,r14
 lea rsi,[r12+C_OUTPUT]
 mov ecx,112
 cld
 rep movsb
 /* Generation is only a mechanical wake sequence. The actual policy state
  * remains the authority for whether a pending open is allowed to proceed. */
 cmp rbx,112
 jne .Lapply_done
 mov rax,[r12+C_INPUT+8]
 cmp rax,2
 je .Lapply_notify
 cmp rax,6
 jne .Lapply_done
.Lapply_notify:
 lock inc dword ptr [r12+C_GENERATION]
 lea rdi,[r12+C_GENERATION]
 mov esi,129
 mov edx,2147483647
 xor r10d,r10d
 xor r8d,r8d
 xor r9d,r9d
 mov eax,202
 syscall
.Lapply_done:
 mov rax,rbx
 jmp .Lapply_release
.Lapply_invalid:
 mov rax,-22
.Lapply_release:
 mov rbx,rax
 lea rdi,[r12+C_LOCK]
 call .Lunlock
 mov rax,rbx
 jmp .Lreturn

/* sequence(context) and wait(context, observed_u32, relative_ns).
 * Waiting never invents an open result; caller repeats the untouched policy
 * request after a wake and still must obtain the real open reservation.
 */
durable_audit_archive_registry_sequence:
 SAVE
 mov r12,rdi
 call .Lidentity
 test rax,rax
 jnz .Lreturn
 mov eax,[r12+C_GENERATION]
 jmp .Lreturn

durable_audit_archive_registry_wait:
 SAVE
 mov r12,rdi
 mov r13,rsi
 mov r14,rdx
 call .Lidentity
 test rax,rax
 jnz .Lreturn
 mov eax,r13d
 cmp rax,r13
 jne .Linvalid
 test r14,r14
 js .Linvalid
 mov rax,r14
 xor edx,edx
 mov ecx,1000000000
 div rcx
 mov [rsp],rax
 mov [rsp+8],rdx
 lea rdi,[r12+C_GENERATION]
 mov esi,128
 mov edx,r13d
 mov r10,rsp
 xor r8d,r8d
 xor r9d,r9d
 mov eax,202
 syscall
 jmp .Lreturn

/* The private runtime has already stopped new users and joined every caller.
 * Live strong references or an unfinished open keep all storage retained. */
durable_audit_archive_registry_destroy:
 SAVE
 mov r12,rdi
 call .Lidentity
 test rax,rax
 jnz .Lreturn
 xor eax,eax
 mov edx,1
 lock cmpxchg dword ptr [r12+C_LOCK],edx
 jne .Lbusy
 mov rax,[r12+C_ERROR]
 test rax,rax
 jnz .Lapply_release
 lea rdi,[r12+C_INPUT]
 xor eax,eax
 mov ecx,96
 cld
 rep stosb
 mov rax,REQUEST
 mov [r12+C_INPUT],rax
 mov qword ptr [r12+C_INPUT+8],5
 lea rdi,[r12+C_INPUT]
 mov esi,96
 lea rdx,[r12+C_OUTPUT]
 mov ecx,112
 mov r8,[r12+C_WORK]
 mov r9,[r12+C_CAP]
 call [r12+C_ENTRY]
 cmp rax,112
 jne .Ldestroy_broken
 mov rdx,RESPONSE
 cmp [r12+C_OUTPUT],rdx
 jne .Ldestroy_broken
 mov rax,[r12+C_OUTPUT+56]
 or rax,[r12+C_OUTPUT+72]
 jnz .Ldestroy_busy
 mov rdi,[r12+C_WORK]
 mov rsi,[r12+C_CAP]
 mov eax,11
 syscall
 test rax,rax
 jnz .Ldestroy_broken_errno
 mov qword ptr [r12+C_WORK],0
 mov qword ptr [r12+C_CAP],0
 mov rdi,r12
 mov esi,4096
 mov eax,11
 syscall
 test rax,rax
 jnz .Ldestroy_broken_errno
 jmp .Lreturn
.Ldestroy_broken:
 mov rax,-71
.Ldestroy_broken_errno:
 mov [r12+C_ERROR],rax
 jmp .Lapply_release
.Ldestroy_busy:
 mov rax,-16
 jmp .Lapply_release
.Lbusy:
 mov rax,-16
 jmp .Lreturn

.Lidentity:
 test r12,r12
 jz .Lbad_identity
 mov rax,R_MAGIC
 cmp [r12+C_MAGIC],rax
 jne .Lbad_identity
 mov eax,39
 syscall
 cmp rax,[r12+C_PID]
 jne .Lbad_identity
 xor eax,eax
 ret
.Lbad_identity:
 mov rax,-22
 ret

/* (pointer,length) must not overlap either owned mutable mapping.
 * r12 retains the private context; unsigned wrap is rejected. */
.Lexternal:
 mov rdx,rdi
 add rdx,rsi
 jc .Lexternal_bad
 lea rcx,[r12+4096]
 cmp rdi,rcx
 jae .Lexternal_workspace
 cmp rdx,r12
 ja .Lexternal_bad
.Lexternal_workspace:
 mov rcx,[r12+C_WORK]
 mov rax,rcx
 add rax,[r12+C_CAP]
 jc .Lexternal_bad
 cmp rdi,rax
 jae .Lexternal_good
 cmp rdx,rcx
 ja .Lexternal_bad
.Lexternal_good:
 xor eax,eax
 ret
.Lexternal_bad:
 mov eax,1
 ret

/* Three-state process-private futex mutex; EINTR/EAGAIN cannot grant a lock. */
.Llock:
 xor eax,eax
 mov edx,1
 lock cmpxchg dword ptr [rdi],edx
 jz .Llock_ok
.Llock_contended:
 mov eax,2
 xchg eax,dword ptr [rdi]
 test eax,eax
 jz .Llock_ok
 mov esi,128
 mov edx,2
 xor r10d,r10d
 xor r8d,r8d
 xor r9d,r9d
 mov eax,202
 syscall
 cmp rax,-4
 je .Llock_contended
 cmp rax,-11
 je .Llock_contended
 test rax,rax
 jz .Llock_contended
 ret
.Llock_ok:
 xor eax,eax
 ret
.Lunlock:
 xor eax,eax
 xchg eax,dword ptr [rdi]
 cmp eax,2
 jne .Lunlock_done
 mov esi,129
 mov edx,1
 xor r10d,r10d
 xor r8d,r8d
 xor r9d,r9d
 mov eax,202
 syscall
.Lunlock_done:
 ret
.Linvalid:
 mov rax,-22
.Lreturn:
 RETURN
.section .note.GNU-stack,"",@progbits
