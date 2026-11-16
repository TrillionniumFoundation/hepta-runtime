/* Copyright 2026 TrillionniumFoundation
 * SPDX-License-Identifier: Apache-2.0
 * Mechanical callable composition. Queue policy remains in the HIA controller.
 * Context: magic, generation, kernel pointer/capacity, queue pointer/capacity,
 * mapping length, optional observation function/user pointer, seven zero words.
 * Caller owns context lifetime, initializes before publication and destroys only
 * after the final actor. Observations do not implement any runtime decision.
 */
.text
.globl audit_callable_entry
.type audit_callable_entry,@function
audit_callable_entry:
    push %rbp
    push %rbx
    push %r12
    push %r13
    push %r14
    push %r15
    sub $584,%rsp
    mov %r8,%r12
    mov %rdx,%r13
    mov %rdi,%rbx
    mov %rsp,%r14
    lea 416(%rsp),%r15
    cmp $256,%rsi
    jne .Linvalid
    cmp $512,%rcx
    jb .Lcapacity
    cmp $128,%r9
    jb .Lcapacity
    test $7,%r12
    jnz .Linvalid
    movabs $0x31304c5443554148,%rax
    cmp %rax,(%rbx)
    jne .Linvalid
    mov 8(%rbx),%rax
    cmp $6,%rax
    ja .Linvalid
    cmp $3,%rax
    je .Linvalid
    mov %rax,576(%rsp)
    mov %rbx,%rax
    add $256,%rax
    jc .Linvalid
    mov %r13,%rdx
    add $512,%rdx
    jc .Linvalid
    mov %r12,%rcx
    add $128,%rcx
    jc .Linvalid
    cmp %rdx,%rbx
    jae .Linput_context
    cmp %rax,%r13
    jb .Linvalid
.Linput_context:
    cmp %rcx,%rbx
    jae .Loutput_context
    cmp %rax,%r12
    jb .Linvalid
.Loutput_context:
    cmp %rcx,%r13
    jae .Lcontext_valid
    cmp %rdx,%r12
    jb .Linvalid
.Lcontext_valid:
    cmpq $64,24(%r12)
    jne .Linvalid
    mov 16(%r12),%rax
    test %rax,%rax
    jz .Linvalid
    test $7,%rax
    jnz .Linvalid
    mov $72,%ecx
.Lreserved:
    cmpq $0,(%r12,%rcx)
    jne .Linvalid
    add $8,%ecx
    cmp $128,%ecx
    jb .Lreserved
    mov %r14,%rdi
    mov %rbx,%rsi
    mov $32,%ecx
    rep movsq
    lea 400(%rsp),%rdi
    movabs $0xa5a5a5a5a5a5a5a5,%rax
    mov $2,%ecx
    rep stosq
    movq $0,552(%rsp)
    movq $0,560(%rsp)
    mov $186,%eax
    syscall
    test %rax,%rax
    jle .Lfatal
    mov %rax,544(%rsp)
    cmpq $0,576(%rsp)
    je .Linitialize
    movabs $0x3130585443504148,%rax
    cmp %rax,(%r12)
    jne .Lstate
    mov 8(%r12),%rax
    cmp %rax,32(%r14)
    jne .Lstate
    cmpq $6,576(%rsp)
    je .Ldestroy
    jmp .Lcontroller
.Linitialize:
    mov (%r12),%rax
    or 8(%r12),%rax
    or 32(%r12),%rax
    or 40(%r12),%rax
    or 48(%r12),%rax
    jnz .Lstate
    cmpq $0,32(%r14)
    je .Linvalid
    mov $16,%ecx
.Linitial_request:
    cmp $32,%ecx
    je .Linitial_next
    cmpq $0,(%r14,%rcx)
    jne .Linvalid
.Linitial_next:
    add $8,%ecx
    cmp $256,%ecx
    jb .Linitial_request
    mov $9,%eax
    xor %edi,%edi
    mov $4096,%esi
    mov $3,%edx
    mov $0x22,%r10d
    mov $-1,%r8
    xor %r9d,%r9d
    syscall
    cmp $-4095,%rax
    jae .Lresource
    mov %rax,32(%r12)
    movq $128,40(%r12)
    movq $4096,48(%r12)
    lea 128(%rax),%rdi
    movabs $0xa5a5a5a5a5a5a5a5,%rax
    mov $2,%ecx
    rep stosq
    mov 32(%r14),%rax
    mov %rax,8(%r12)
    movabs $0x3130585443504148,%rax
    mov %rax,(%r12)
    lea 128(%r14),%rbx
    movabs $0x3130444d43534148,%rax
    mov %rax,(%rbx)
    mov 8(%r12),%rax
    mov %rax,24(%rbx)
    call .Lboundary
    lea 128(%r14),%rdi
    xor %eax,%eax
    mov $16,%ecx
    rep stosq
    movq $1,552(%rsp)
    movq $1,560(%rsp)
    jmp .Lcontroller
.Lcontroller:
    mov %r15,%rdi
    xor %eax,%eax
    mov $16,%ecx
    rep stosq
    movq $1,(%r15)
    mov %r14,24(%r15)
    movq $256,32(%r15)
    mov %r13,40(%r15)
    lea 400(%rsp),%rax
    mov %rax,48(%r15)
    mov 552(%rsp),%rax
    mov %rax,64(%r15)
    test %rax,%rax
    jz .Lcontroller_observe
    mov 32(%r12),%rax
    mov %rax,48(%r15)
    mov 40(%r12),%rax
    mov %rax,56(%r15)
.Lcontroller_observe:
    mov 560(%rsp),%rax
    mov %rax,72(%r15)
    call .Lobserve
    mov %r14,%rdi
    mov $256,%esi
    mov %r13,%rdx
    mov $512,%ecx
    mov 48(%r15),%r8
    mov 56(%r15),%r9
    call .Lcontroller_image
    mov %eax,568(%rsp)
    mov %rax,16(%r15)
    movq $1,8(%r15)
    call .Lobserve
    cmpl $512,568(%rsp)
    jne .Lfatal
    movq $0,560(%rsp)
    mov 8(%r13),%rax
    test %rax,%rax
    jz .Lcomplete
    cmp $1,%rax
    je .Leffect
    cmp $2,%rax
    je .Lgrowth
    jmp .Lfatal
.Leffect:
    lea 256(%r13),%rbx
    call .Lboundary
    movq $0,552(%rsp)
    mov 544(%rsp),%rax
    cmp %rax,344(%rsp)
    jne .Lresponse_ready
    cmpq $1,360(%rsp)
    jne .Lresponse_ready
    movq $1,552(%rsp)
.Lresponse_ready:
    mov %r14,%rdi
    xor %eax,%eax
    mov $16,%ecx
    rep stosq
    movabs $0x31304c5443554148,%rax
    mov %rax,(%r14)
    movq $3,8(%r14)
    mov 24(%r13),%rax
    mov %rax,16(%r14)
    movq $128,24(%r14)
    lea 128(%r14),%rdi
    lea 256(%rsp),%rsi
    mov $16,%ecx
    rep movsq
    jmp .Lcontroller
.Lgrowth:
    cmpq $1,552(%rsp)
    jne .Lfatal
    cmpq $1,88(%r13)
    jne .Lfatal
    mov 40(%r12),%rbx
    mov 192(%r13),%rbp
    cmp %rbx,%rbp
    jbe .Lfatal
    test $15,%rbp
    jnz .Lfatal
    mov %r15,%rdi
    xor %eax,%eax
    mov $16,%ecx
    rep stosq
    movq $3,(%r15)
    mov %r13,40(%r15)
    mov 32(%r12),%rax
    mov %rax,48(%r15)
    mov %rbx,56(%r15)
    movq $1,64(%r15)
    mov %rbx,80(%r15)
    mov %rbp,88(%r15)
    call .Lobserve
    mov %rbp,%rdx
    add $4111,%rdx
    jc .Lresource
    and $-4096,%rdx
    mov $25,%eax
    mov 32(%r12),%rdi
    mov 48(%r12),%rsi
    mov $1,%r10d
    xor %r8d,%r8d
    xor %r9d,%r9d
    syscall
    cmp $-4095,%rax
    jae .Lresource
    mov %rax,32(%r12)
    mov %rbp,40(%r12)
    mov %rdx,48(%r12)
    lea (%rax,%rbx),%rdi
    mov %rbp,%rcx
    sub %rbx,%rcx
    xor %eax,%eax
    rep stosb
    movabs $0xa5a5a5a5a5a5a5a5,%rax
    mov $2,%ecx
    rep stosq
    mov 32(%r12),%rax
    mov %rax,48(%r15)
    mov %rbp,56(%r15)
    movq $1,8(%r15)
    call .Lobserve
    mov %r14,%rdi
    xor %eax,%eax
    mov $32,%ecx
    rep stosq
    movabs $0x31304c5443554148,%rax
    mov %rax,(%r14)
    movq $3,8(%r14)
    mov 24(%r13),%rax
    mov %rax,16(%r14)
    jmp .Lcontroller
.Lboundary:
    sub $8,%rsp
    lea 256(%r14),%rdi
    movabs $0xa5a5a5a5a5a5a5a5,%rax
    mov $18,%ecx
    rep stosq
    mov %r15,%rdi
    xor %eax,%eax
    mov $16,%ecx
    rep stosq
    movq $2,(%r15)
    mov %rbx,24(%r15)
    movq $128,32(%r15)
    lea 256(%r14),%rax
    mov %rax,40(%r15)
    mov 24(%r13),%rax
    mov %rax,96(%r15)
    call .Lobserve
    mov %rbx,%rdi
    mov $128,%esi
    lea 256(%r14),%rdx
    mov $128,%ecx
    mov 16(%r12),%r8
    mov $64,%r9d
    call .Lsync_image
    mov %eax,568(%r14)
    mov %rax,16(%r15)
    movq $1,8(%r15)
    call .Lobserve
    cmpl $128,568(%r14)
    jne .Lfatal_boundary
    cmpq $2,272(%r14)
    ja .Lfatal_boundary
    mov 544(%r14),%rax
    cmp %rax,280(%r14)
    jne .Lfatal_boundary
    add $8,%rsp
    ret
.Lfatal_boundary:
    jmp .Lfatal
.Lobserve:
    mov 56(%r12),%rax
    test %rax,%rax
    jz .Lobserve_done
    sub $8,%rsp
    mov %r15,%rdi
    mov 64(%r12),%rsi
    call *%rax
    add $8,%rsp
.Lobserve_done:
    ret
.Ldestroy:
    mov $11,%eax
    mov 32(%r12),%rdi
    mov 48(%r12),%rsi
    syscall
    test %rax,%rax
    jne .Lfatal
    movq $0,(%r12)
    movq $0,8(%r12)
    movq $0,32(%r12)
    movq $0,40(%r12)
    movq $0,48(%r12)
    xor %eax,%eax
    jmp .Lreturn
.Lcomplete:
    mov $512,%eax
    jmp .Lreturn
.Linvalid:
    mov $0xffffffff,%eax
    jmp .Lreturn
.Lcapacity:
    mov $0xfffffffe,%eax
    jmp .Lreturn
.Lstate:
    mov $0xfffffffd,%eax
    jmp .Lreturn
.Lresource:
.Lfatal:
    mov $231,%eax
    mov $134,%edi
    syscall
    ud2
.Lreturn:
    add $584,%rsp
    pop %r15
    pop %r14
    pop %r13
    pop %r12
    pop %rbx
    pop %rbp
    ret
.size audit_callable_entry,.-audit_callable_entry
.balign 16,0x90
.globl audit_callable_controller
audit_callable_controller:
.Lcontroller_image:
    .zero 160544
.globl audit_callable_sync
audit_callable_sync:
.Lsync_image:
    .zero 1635
.globl audit_callable_end
audit_callable_end:
.section .note.GNU-stack,"",@progbits
