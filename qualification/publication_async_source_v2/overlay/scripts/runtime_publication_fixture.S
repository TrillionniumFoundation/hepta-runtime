/* Copyright 2026 Muvon Un Limited
 * SPDX-License-Identifier: Apache-2.0
 * Private serial carrier only. It waits for the actual worker wake and enters
 * the same retained HIA await; it neither fabricates a result nor detaches a
 * public request. The normal stdio entry uses the asynchronous task pump.
 */
.intel_syntax noprefix
.section .text
runtime_publication_fixture_owned:
    push rbx
    push rbp
    push r12
    push r13
    sub rsp,24
    mov r12,rdi
    mov r13,rsi
    mov rbp,r8
    call runtime_grow_owned
    cmp eax,0xffffffdf
    jne rpf_done
    cmp ebp,64
    je rpf_wait
    cmp ebp,18
    jne rpf_done
    cmp qword ptr [r15+512+18*64+24],64
    jne rpf_done
rpf_wait:
    mov rax,[r15+400]
    test rax,rax
    jz rpf_invalid
    mov rdi,[rax+216]
    test rdi,rdi
    jz rpf_invalid
    call publication_worker_wake_fd
    cmp rax,0x7fffffff
    ja rpf_invalid
    mov [rsp],eax
    mov dword ptr [rsp+4],1
    mov rdi,rsp
    mov esi,1
    mov edx,10
    mov eax,7
    syscall
    cmp rax,-4
    je rpf_wait
    test rax,rax
    js rpf_invalid
    mov rdi,r12
    mov rsi,r13
    mov r8,rbp
    mov r9d,2
    call runtime_grow_suspended
    cmp eax,0xffffffdf
    je rpf_wait
    jmp rpf_done
rpf_invalid:
    mov eax,0xffffffff
rpf_done:
    add rsp,24
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

/* All session descriptors are destroyed before this one process pool drains. */
runtime_publication_fixture_pool_finish:
    push rbx
    push rbp
    sub rsp,24
    mov rbp,rdi
    mov rbx,[rbp+216]
    test rbx,rbx
    jz rpf_pool_empty
    mov rdi,rbx
    call publication_worker_close
    test eax,eax
    jnz rpf_pool_done
rpf_pool_again:
    mov rdi,rbx
    call publication_worker_destroy
    test eax,eax
    jz rpf_pool_retired
    cmp eax,0xfffffffd
    jne rpf_pool_done
    mov rdi,rbx
    call publication_worker_wake_fd
    cmp rax,0x7fffffff
    ja rpf_pool_invalid
    mov [rsp],eax
    mov dword ptr [rsp+4],1
    mov rdi,rsp
    mov esi,1
    mov edx,10
    mov eax,7
    syscall
    cmp rax,-4
    je rpf_pool_again
    test rax,rax
    js rpf_pool_invalid
    jmp rpf_pool_again
rpf_pool_retired:
    mov qword ptr [rbp+216],0
rpf_pool_empty:
    xor eax,eax
    jmp rpf_pool_done
rpf_pool_invalid:
    mov eax,0xffffffff
rpf_pool_done:
    add rsp,24
    pop rbp
    pop rbx
    ret
