/* Private qualification actor, never linked into the parent capability owner.
 * It makes actual descriptor-table changes at two fixed before-effect barriers:
 * close the old FD, then reopen literal / into that same free numeric slot.
 * The target subsequently observes real EBADF followed by a real close success.
 * No syscall return, application reply or application memory is substituted. */
.Lwbf_parent_actor:
    W_ENTER
    mov r13, rdi
    mov r12, rsi
    mov rbp, rdx
    cmp qword ptr [r13+600], 1
    jne .Lwbf_parent_actor_noop
    cmp qword ptr [rbp+24], 3
    jne .Lwbf_parent_actor_noop
    mov rax, [r12+88]
    mov r14, [rax+8]
    mov r15, [rbp+32]
    cmp qword ptr [r13+608], 0
    je .Lwbf_parent_actor_first
    cmp qword ptr [r13+608], 1
    jne .Lwbf_parent_actor_noop
    cmp r14, 6
    jne .Lwbf_parent_actor_noop
    mov edi, -100
    lea rsi, [rip+.Lwbf_parent_actor_root]
    mov edx, 720896
    xor r10d, r10d
    mov eax, 257
    syscall
    cmp rax, r15
    jne .Lwbf_parent_actor_failed
    mov ebx, 2
    jmp .Lwbf_parent_actor_record
.Lwbf_parent_actor_first:
    cmp r14, 5
    jne .Lwbf_parent_actor_noop
    mov rdi, r15
    mov eax, 3
    syscall
    test rax, rax
    jnz .Lwbf_parent_actor_failed
    mov ebx, 1
.Lwbf_parent_actor_record:
    inc qword ptr [r13+608]
    sub rsp, 64
    mov [rsp+32], rax
    movabs rax, 0x3130434157504248 /* HBPWAC01 */
    mov [rsp], rax
    mov [rsp+8], rbx
    mov [rsp+16], r14
    mov [rsp+24], r15
    mov rax, [r12+192]
    mov [rsp+40], rax
    mov rax, [r12+248]
    mov [rsp+48], rax
    mov qword ptr [rsp+56], 0
    mov edi, 3
    mov rsi, rsp
    mov edx, 64
    call .Lwbf_write_all
    add rsp, 64
    jmp .Lwbf_parent_actor_return
.Lwbf_parent_actor_noop:
    xor eax, eax
    jmp .Lwbf_parent_actor_return
.Lwbf_parent_actor_failed:
    mov rax, -22
.Lwbf_parent_actor_return:
    W_LEAVE
.Lwbf_parent_actor_root:
    .asciz "/"
