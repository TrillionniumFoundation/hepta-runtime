/* Copyright 2026 TrillionniumFoundation
 * SPDX-License-Identifier: Apache-2.0
 * Mechanical strong/weak reference storage for the HIA audit lifetime owner.
 * Each reference owns its pointer for the entire call. Invalid or dangling
 * host pointers are outside this private ABI, as for Arc raw pointers.
 * HIA owns map membership, pruning, publication and query ordering.
 */
.text
.globl audit_refs_entry
.type audit_refs_entry,@function
audit_refs_entry:
    push %rbp
    push %rbx
    push %r12
    push %r13
    push %r14
    push %r15
    sub $88,%rsp
    mov %rdi,%r12
    mov %rdx,%r13
    cmp $64,%rsi
    jne .LRinvalid
    cmp $64,%rcx
    jb .LRcapacity
    test %r9,%r9
    jnz .LRinvalid
    lea 64(%r12),%rax
    cmp %r12,%rax
    jb .LRinvalid
    lea 64(%r13),%rdx
    cmp %r13,%rdx
    jb .LRinvalid
    cmp %rdx,%r12
    jae .LRframe
    cmp %rax,%r13
    jb .LRinvalid
.LRframe:
    movabs $0x3130464552524148,%rax
    cmp %rax,(%r12)
    jne .LRinvalid
    mov 8(%r12),%r15
    cmp $9,%r15
    ja .LRinvalid
    mov 16(%r12),%rbx
    cmp $1,%rbx
    jb .LRinvalid
    cmp $2,%rbx
    ja .LRinvalid
    mov 32(%r12),%rax
    or 40(%r12),%rax
    or 48(%r12),%rax
    or 56(%r12),%rax
    jnz .LRinvalid
    mov 24(%r12),%r14
    cmp $2,%r15
    jb .LRnew
    test %r14,%r14
    jz .LRinvalid
    test $7,%r14
    jnz .LRinvalid
    movabs $0x31304a424f524148,%rax
    cmp %rax,(%r14)
    jne .LRstate
    cmp %rbx,24(%r14)
    jne .LRstate
    mov 40(%r14),%rax
    or 48(%r14),%rax
    or 56(%r14),%rax
    jnz .LRstate
    cmp $8,%r15
    jb .LRlive
    cmp $1,%rbx
    jne .LRinvalid
.LRlive:
    cmpq $0,16(%r14)
    je .LRstate
    cmp $4,%r15
    jb .LRstrong
    cmp $8,%r15
    jae .LRstrong
    jmp .LRsnapshot
.LRstrong:
    cmpq $0,8(%r14)
    je .LRstate
.LRsnapshot:
    movabs $0x3130534552524148,%rax
    mov %rax,(%rsp)
    mov %r15,8(%rsp)
    movq $1,16(%rsp)
    mov %r14,24(%rsp)
    mov 8(%r14),%rax
    mov %rax,32(%rsp)
    mov 16(%r14),%rax
    mov %rax,40(%rsp)
    mov %rbx,48(%rsp)
    mov 32(%r14),%rax
    mov %rax,56(%rsp)
    cmp $2,%r15
    je .LRclone
    cmp $3,%r15
    je .LRdrop
    cmp $4,%r15
    je .LRweak
    cmp $5,%r15
    je .LRweak_drop
    cmp $6,%r15
    je .LRcount
    cmp $7,%r15
    je .LRupgrade
    cmp $8,%r15
    je .LRreturn_buffer
    movq $0,32(%r14)
    movq $0,56(%rsp)
    jmp .LRreturn_buffer
.LRnew:
    test %r14,%r14
    jnz .LRinvalid
    mov %r15,%rax
    inc %rax
    cmp %rbx,%rax
    jne .LRinvalid
    mov $9,%eax
    xor %edi,%edi
    mov $4096,%esi
    mov $3,%edx
    mov $0x22,%r10d
    mov $-1,%r8
    xor %r9d,%r9d
    syscall
    cmp $-4095,%rax
    jae .LRfatal
    mov %rax,%r14
    movabs $0x31304a424f524148,%rax
    mov %rax,(%r14)
    movq $1,8(%r14)
    movq $1,16(%r14)
    mov %rbx,24(%r14)
    xor %eax,%eax
    cmp $1,%rbx
    sete %al
    mov %rax,32(%r14)
    movabs $0x3130534552524148,%rax
    mov %rax,(%rsp)
    mov %r15,8(%rsp)
    movq $1,16(%rsp)
    mov %r14,24(%rsp)
    movq $1,32(%rsp)
    movq $1,40(%rsp)
    mov %rbx,48(%rsp)
    mov 32(%r14),%rax
    mov %rax,56(%rsp)
    jmp .LRreturn_buffer
.LRclone:
    mov $1,%eax
    lock xadd %rax,8(%r14)
    test %rax,%rax
    jle .LRfatal
    inc %rax
    js .LRfatal
    mov %rax,32(%rsp)
    jmp .LRreturn_buffer
.LRdrop:
    mov $-1,%rax
    lock xadd %rax,8(%r14)
    test %rax,%rax
    jle .LRfatal
    dec %rax
    mov %rax,32(%rsp)
    movq $0,16(%rsp)
    jnz .LRreturn_buffer
    mov $-1,%rax
    lock xadd %rax,16(%r14)
    test %rax,%rax
    jle .LRfatal
    dec %rax
    mov %rax,40(%rsp)
    jz .LRdispose
    jmp .LRreturn_buffer
.LRweak:
    mov $1,%eax
    lock xadd %rax,16(%r14)
    test %rax,%rax
    jle .LRfatal
    inc %rax
    js .LRfatal
    mov %rax,40(%rsp)
    jmp .LRreturn_buffer
.LRweak_drop:
    mov $-1,%rax
    lock xadd %rax,16(%r14)
    test %rax,%rax
    jle .LRfatal
    dec %rax
    mov %rax,40(%rsp)
    movq $0,16(%rsp)
    jnz .LRreturn_buffer
    cmpq $0,8(%r14)
    jne .LRfatal
    movq $0,32(%rsp)
    jmp .LRdispose
.LRcount:
    movq $0,16(%rsp)
    jmp .LRreturn_buffer
.LRupgrade:
    mov 8(%r14),%rax
.LRupgrade_retry:
    test %rax,%rax
    jz .LRupgrade_empty
    js .LRfatal
    mov %rax,%rdx
    inc %rdx
    js .LRfatal
    lock cmpxchg %rdx,8(%r14)
    jne .LRupgrade_retry
    mov %rdx,32(%rsp)
    jmp .LRreturn_buffer
.LRupgrade_empty:
    movq $0,16(%rsp)
    movq $0,32(%rsp)
    jmp .LRreturn_buffer
.LRdispose:
    movq $2,16(%rsp)
    mov $11,%eax
    mov %r14,%rdi
    mov $4096,%esi
    syscall
    test %rax,%rax
    jne .LRfatal
.LRreturn_buffer:
    mov %r13,%rdi
    mov %rsp,%rsi
    mov $8,%ecx
    rep movsq
    mov $64,%eax
    jmp .LRreturn
.LRinvalid:
    mov $0xffffffff,%eax
    jmp .LRreturn
.LRcapacity:
    mov $0xfffffffe,%eax
    jmp .LRreturn
.LRstate:
    mov $0xfffffff9,%eax
    jmp .LRreturn
.LRfatal:
    mov $231,%eax
    mov $134,%edi
    syscall
    ud2
.LRreturn:
    add $88,%rsp
    pop %r15
    pop %r14
    pop %r13
    pop %r12
    pop %rbx
    pop %rbp
    ret
.size audit_refs_entry,.-audit_refs_entry
.globl audit_refs_end
audit_refs_end:
.section .note.GNU-stack,"",@progbits
