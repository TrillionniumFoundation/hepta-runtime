/* Copyright 2026 TrillionniumFoundation
 * SPDX-License-Identifier: Apache-2.0
 * Mechanical Linux x86-64 mutex/condition/clock boundary. No queue policy.
 */
.text
.globl audit_sync_entry
.type audit_sync_entry,@function
audit_sync_entry:
    push %rbp
    push %rbx
    push %r12
    push %r13
    push %r14
    push %r15
    sub $88,%rsp
    mov %rdi,%r12
    mov %rdx,%r13
    mov %r8,%r14
    cmp $128,%rsi
    jne .Linvalid
    cmp $128,%rcx
    jb .Lcapacity
    cmp $64,%r9
    jb .Lcapacity
    test $7,%r8
    jnz .Linvalid
    movabs $0x3130444d43534148,%rax
    cmp %rax,(%r12)
    jne .Linvalid
    mov 8(%r12),%r15
    cmp $7,%r15
    ja .Linvalid
    mov 16(%r12),%rbp
    cmp $1,%rbp
    ja .Linvalid
    cmpq $0,24(%r12)
    je .Linvalid
    cmpq $1,40(%r12)
    ja .Linvalid
    mov $72,%ecx
.Lreserved:
    cmpq $0,(%r12,%rcx)
    jne .Linvalid
    add $8,%ecx
    cmp $128,%ecx
    jb .Lreserved
    cmp $4,%r15
    je .Lwait_frame
    cmpq $0,32(%r12)
    jne .Linvalid
    cmpq $0,48(%r12)
    jne .Linvalid
    cmpq $0,56(%r12)
    jne .Linvalid
    cmpq $0,64(%r12)
    jne .Linvalid
    cmp $1,%r15
    jb .Lnon_mutex_frame
    cmp $3,%r15
    jbe .Lranges
.Lnon_mutex_frame:
    test %rbp,%rbp
    jnz .Linvalid
    cmpq $0,40(%r12)
    jne .Linvalid
    jmp .Lranges
.Lwait_frame:
    test %rbp,%rbp
    jnz .Linvalid
    cmpq $0,40(%r12)
    jne .Linvalid
    mov 32(%r12),%rax
    shr $32,%rax
    jnz .Linvalid
    cmpq $1,48(%r12)
    ja .Linvalid
    cmpq $0,56(%r12)
    js .Linvalid
    cmpq $1000000000,64(%r12)
    jae .Linvalid
    cmpq $0,48(%r12)
    jne .Lranges
    mov 56(%r12),%rax
    or 64(%r12),%rax
    jnz .Linvalid
.Lranges:
    mov %r12,%rax
    add $128,%rax
    jc .Linvalid
    mov %r13,%rdx
    add $128,%rdx
    jc .Linvalid
    mov %r14,%rcx
    add $64,%rcx
    jc .Linvalid
    cmp %rdx,%r12
    jae .Lrange_sw
    cmp %rax,%r13
    jb .Linvalid
.Lrange_sw:
    cmp %rcx,%r12
    jae .Lrange_ow
    cmp %rax,%r14
    jb .Linvalid
.Lrange_ow:
    cmp %rcx,%r13
    jae .Lframe_valid
    cmp %rdx,%r14
    jb .Linvalid
.Lframe_valid:
    movq $0,24(%rsp)
    movq $0,32(%rsp)
    movq $0,40(%rsp)
    movq $0,48(%rsp)
    movq $0,56(%rsp)
    movq $0,64(%rsp)
    movq $0,72(%rsp)
    test %r15,%r15
    jz .Linitialize
    movabs $0x3130434e59534148,%rax
    cmp %rax,(%r14)
    jne .Lstate
    mov 24(%r12),%rax
    cmp %rax,48(%r14)
    jne .Lstate
    cmpl $0,28(%r14)
    jne .Lstate
    cmpl $1,8(%r14)
    ja .Lstate
    cmpl $1,12(%r14)
    ja .Lstate
    cmpl $1,16(%r14)
    ja .Lstate
    cmpl $1,20(%r14)
    ja .Lstate
    cmpl $1,56(%r14)
    ja .Lstate
    cmpl $1,60(%r14)
    ja .Lstate
    mov $186,%eax
    syscall
    test %rax,%rax
    jle .Lstate
    mov %rax,16(%rsp)
    lea 8(%r14,%rbp,8),%rbx
    cmp $3,%r15
    jb .Llock_start
    je .Lunlock_start
    cmp $4,%r15
    je .Lcondition_wait
    cmp $5,%r15
    je .Lnotify
    cmp $6,%r15
    je .Lclock
    jmp .Lresponse
.Linitialize:
    xor %ecx,%ecx
.Linitial_zero:
    cmpq $0,(%r14,%rcx)
    jne .Lstate
    add $8,%ecx
    cmp $64,%ecx
    jb .Linitial_zero
    mov $186,%eax
    syscall
    test %rax,%rax
    jle .Lstate
    mov %rax,16(%rsp)
    movabs $0x3130434e59534148,%rax
    mov %rax,(%r14)
    mov 24(%r12),%rax
    mov %rax,48(%r14)
    jmp .Lresponse
.Llock_start:
    cmp $2,%r15
    je .Lacquire
    mov 16(%rsp),%rax
    cmp %rax,32(%r14,%rbp,8)
    je .Lstate
.Lacquire:
    xor %eax,%eax
    mov $1,%edx
    lock cmpxchg %edx,(%rbx)
    je .Lacquired
    cmp $2,%r15
    je .Lwould_block
    mov $202,%eax
    mov %rbx,%rdi
    mov $128,%esi
    mov $1,%edx
    xor %r10d,%r10d
    xor %r8d,%r8d
    xor %r9d,%r9d
    syscall
    test %rax,%rax
    jns .Lacquire
    cmp $-11,%rax
    je .Lacquire
    cmp $-4,%rax
    je .Lacquire
    jmp .Lkernel_error
.Lacquired:
    mov 16(%rsp),%rax
    mov %rax,32(%r14,%rbp,8)
    mov 40(%r12),%eax
    cmpq $0,64(%rsp)
    je .Lstore_entry_panic
    mov 56(%rsp),%eax
.Lstore_entry_panic:
    mov %eax,56(%r14,%rbp,4)
    mov 4(%rbx),%eax
    mov %rax,24(%rsp)
    cmpq $0,72(%rsp)
    je .Lresponse
    movq $6,24(%rsp)
    jmp .Lresponse
.Lwould_block:
    movq $2,24(%rsp)
    jmp .Lresponse
.Lunlock_start:
    cmpl $1,(%rbx)
    jne .Lstate
    mov 16(%rsp),%rax
    cmp %rax,32(%r14,%rbp,8)
    jne .Lstate
    cmpq $0,40(%r12)
    je .Lunlock_clean
    cmpl $0,56(%r14,%rbp,4)
    jne .Lunlock_clean
    movl $1,4(%rbx)
.Lunlock_clean:
    movq $0,32(%r14,%rbp,8)
    movl $0,56(%r14,%rbp,4)
    xor %eax,%eax
    xchg %eax,(%rbx)
    mov $202,%eax
    mov %rbx,%rdi
    mov $129,%esi
    mov $1,%edx
    xor %r10d,%r10d
    xor %r8d,%r8d
    xor %r9d,%r9d
    syscall
    test %rax,%rax
    js .Lkernel_error
    jmp .Lresponse
.Lcondition_wait:
    cmpl $1,8(%r14)
    jne .Lstate
    mov 16(%rsp),%rax
    cmp %rax,32(%r14)
    jne .Lstate
    mov 56(%r14),%eax
    mov %rax,56(%rsp)
    movq $1,64(%rsp)
    movq $0,32(%r14)
    movl $0,56(%r14)
    xor %eax,%eax
    xchg %eax,8(%r14)
    mov $202,%eax
    lea 8(%r14),%rdi
    mov $129,%esi
    mov $1,%edx
    xor %r10d,%r10d
    xor %r8d,%r8d
    xor %r9d,%r9d
    syscall
    test %rax,%rax
    js .Lwait_kernel_error
    xor %r10d,%r10d
    cmpq $0,48(%r12)
    je .Lwait_syscall
    mov 56(%r12),%rax
    mov %rax,(%rsp)
    mov 64(%r12),%rax
    mov %rax,8(%rsp)
    mov %rsp,%r10
.Lwait_syscall:
    mov $202,%eax
    lea 24(%r14),%rdi
    mov $128,%esi
    mov 32(%r12),%edx
    xor %r8d,%r8d
    xor %r9d,%r9d
    syscall
    test %rax,%rax
    jns .Lacquire
    neg %rax
    mov %rax,32(%rsp)
    cmp $11,%rax
    je .Lacquire
    cmp $4,%rax
    je .Lacquire
    cmp $110,%rax
    je .Lacquire
    neg %rax
.Lwait_kernel_error:
    neg %rax
    mov %rax,32(%rsp)
    movq $1,72(%rsp)
    jmp .Lacquire
.Lnotify:
    cmpl $1,8(%r14)
    jne .Lstate
    mov 16(%rsp),%rax
    cmp %rax,32(%r14)
    jne .Lstate
    lock incl 24(%r14)
    mov $202,%eax
    lea 24(%r14),%rdi
    mov $129,%esi
    mov $0x7fffffff,%edx
    xor %r10d,%r10d
    xor %r8d,%r8d
    xor %r9d,%r9d
    syscall
    test %rax,%rax
    js .Lkernel_error
    jmp .Lresponse
.Lclock:
    mov $228,%eax
    mov $1,%edi
    mov %rsp,%rsi
    syscall
    test %rax,%rax
    js .Lkernel_error
    mov (%rsp),%rax
    test %rax,%rax
    js .Lclock_value_error
    mov 8(%rsp),%rdx
    cmp $1000000000,%rdx
    jae .Lclock_value_error
    mov $1000000000,%ecx
    mul %rcx
    add 8(%rsp),%rax
    adc $0,%rdx
    mov %rax,40(%rsp)
    mov %rdx,48(%rsp)
    jmp .Lresponse
.Lclock_value_error:
    mov $-75,%rax
.Lkernel_error:
    neg %rax
    mov %rax,32(%rsp)
    movq $6,24(%rsp)
.Lresponse:
    mov %r13,%rdi
    xor %eax,%eax
    mov $16,%ecx
    rep stosq
    movabs $0x3130524e59534148,%rax
    mov %rax,(%r13)
    mov %r15,8(%r13)
    mov 24(%rsp),%rax
    mov %rax,16(%r13)
    mov 16(%rsp),%rax
    mov %rax,24(%r13)
    mov 32(%rsp),%rax
    mov %rax,32(%r13)
    mov 24(%r14),%eax
    mov %rax,40(%r13)
    mov 12(%r14),%eax
    mov %rax,48(%r13)
    mov 20(%r14),%eax
    mov %rax,56(%r13)
    mov 40(%rsp),%rax
    mov %rax,64(%r13)
    mov 48(%rsp),%rax
    mov %rax,72(%r13)
    mov 48(%r14),%rax
    mov %rax,80(%r13)
    mov 32(%r14),%rax
    mov %rax,88(%r13)
    mov 40(%r14),%rax
    mov %rax,96(%r13)
    mov 8(%r14),%eax
    mov %rax,104(%r13)
    mov 16(%r14),%eax
    mov %rax,112(%r13)
    mov $128,%eax
    jmp .Lreturn
.Linvalid:
    mov $0xffffffff,%eax
    jmp .Lreturn
.Lcapacity:
    mov $0xfffffffe,%eax
    jmp .Lreturn
.Lstate:
    mov $0xfffffff9,%eax
.Lreturn:
    add $88,%rsp
    pop %r15
    pop %r14
    pop %r13
    pop %r12
    pop %rbx
    pop %rbp
    ret
.size audit_sync_entry,.-audit_sync_entry
.section .note.GNU-stack,"",@progbits
