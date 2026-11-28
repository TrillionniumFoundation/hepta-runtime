/* Copyright 2026 TrillionniumFoundation
 * SPDX-License-Identifier: Apache-2.0
 * Fixed Linux x86-64 metadata effects. All policy and stat conversion are HIA.
 * Six arguments: request, length, output, capacity, shared AtomicU8, capacity.
 */
.intel_syntax noprefix
.section .text
.global _start
.type _start,@function
.global namespace_metadata_entry
.type namespace_metadata_entry,@function
_start:
namespace_metadata_entry:
    push rbp
    mov rbp,rsp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub rsp,1608
    mov rbx,rsp
    mov [rbx],rdi
    mov [rbx+8],rsi
    mov [rbx+16],rdx
    mov [rbx+24],rcx
    mov [rbx+32],r8
    mov qword ptr [rbx+40],0
    mov qword ptr [rbx+48],0
    mov r12,rdi
    mov r13,rsi
    mov r14,rdx
    mov r15,r8
    test rdi,rdi
    jz .invalid
    test rdx,rdx
    jz .invalid
    test r8,r8
    jz .invalid
    cmp rsi,96
    jb .invalid
    cmp rcx,176
    jb .resource
    cmp r9,1
    jb .resource
    mov rax,rdi
    add rax,rsi
    jc .invalid
    mov r10,rdx
    add r10,rcx
    jc .invalid
    cmp rdi,r10
    jae .request_output_disjoint
    cmp rdx,rax
    jb .invalid
.request_output_disjoint:
    cmp r8,rdi
    jb .cache_request_disjoint
    cmp r8,rax
    jb .invalid
.cache_request_disjoint:
    cmp r8,rdx
    jb .cache_output_disjoint
    cmp r8,r10
    jb .invalid
.cache_output_disjoint:
    mov rax,r8
    add rax,1
    jc .invalid
    mov rsi,r13
    add rsi,1
    jc .invalid
    mov [rbx+48],rsi
    xor edi,edi
    mov edx,3
    mov r10d,34
    mov r8,-1
    xor r9d,r9d
    mov eax,9
    syscall
    cmp rax,-4095
    jae .resource
    mov [rbx+40],rax
    mov rdi,rax
    mov rsi,r12
    mov rcx,r13
    cld
    rep movsb
    mov byte ptr [rdi],0
    mov r12,rax
    lea rdi,[rbx+128]
    xor eax,eax
    mov ecx,184
    rep stosq
.invoke:
    mov rdi,r12
    mov rsi,r13
    lea rdx,[rbx+128]
    mov ecx,256
    lea r8,[rbx+1024]
    mov r9d,512
    call namespace_metadata_policy
    cmp eax,0xffffffb1
    je .effect
    cmp eax,32
    je .terminal
    cmp eax,0xffffffff
    je .finish
    cmp eax,0xfffffffe
    je .finish
    jmp .mechanical
.effect:
    movabs rax,0x313030454d534e48
    cmp [rbx+128],rax
    jne .mechanical
    mov rax,[rbx+160]
    or rax,[rbx+168]
    or rax,[rbx+176]
    or rax,[rbx+184]
    jnz .mechanical
    mov rax,[rbx+136]
    cmp rax,1
    jb .mechanical
    cmp rax,9
    ja .mechanical
    lea rdi,[rbx+512]
    xor eax,eax
    mov ecx,36
    rep stosq
    movabs rax,0x313030414d534e48
    mov [rbx+512],rax
    mov rax,[rbx+136]
    mov [rbx+520],rax
    cmp eax,1
    je .load_cache
    cmp eax,2
    je .store_cache
    cmp eax,3
    je .path_statx
    cmp eax,4
    je .fd_statx
    cmp eax,5
    je .probe_statx
    cmp eax,6
    je .path_fallback
    cmp eax,7
    je .fd_fallback
    cmp eax,8
    je .fd_statat
    jmp .probe_statat
.load_cache:
    mov rax,[rbx+144]
    or rax,[rbx+152]
    jnz .mechanical
    movzx eax,byte ptr [r15]
    jmp .ack
.store_cache:
    cmp qword ptr [rbx+152],0
    jne .mechanical
    mov rax,[rbx+144]
    cmp rax,1
    jb .mechanical
    cmp rax,2
    ja .mechanical
    mov byte ptr [r15],al
    xor eax,eax
    jmp .ack
.path_statx:
    call .check_path
    test eax,eax
    jnz .mechanical
    mov rdi,-100
    mov rsi,[rbx+40]
    add rsi,96
    xor edx,edx
    mov r10d,4095
    lea r8,[rbx+544]
    mov eax,332
    syscall
    jmp .ack
.fd_statx:
    call .check_fd
    test eax,eax
    jnz .mechanical
    mov rdi,[rbx+144]
    lea rsi,[rip+.empty]
    mov edx,4096
    mov r10d,4095
    lea r8,[rbx+544]
    mov eax,332
    syscall
    jmp .ack
.probe_statx:
    mov rax,[rbx+144]
    or rax,[rbx+152]
    jnz .mechanical
    xor edi,edi
    xor esi,esi
    xor edx,edx
    mov r10d,4095
    xor r8d,r8d
    mov eax,332
    syscall
    jmp .ack
.path_fallback:
    call .check_path
    test eax,eax
    jnz .mechanical
    mov rdi,-100
    mov rsi,[rbx+40]
    add rsi,96
    lea rdx,[rbx+544]
    xor r10d,r10d
    mov eax,262
    syscall
    jmp .ack
.fd_statat:
    call .check_fd
    test eax,eax
    jnz .mechanical
    mov rdi,[rbx+144]
    lea rsi,[rip+.empty]
    lea rdx,[rbx+544]
    mov r10d,4096
    mov eax,262
    syscall
    jmp .ack
.probe_statat:
    mov rax,[rbx+144]
    or rax,[rbx+152]
    jnz .mechanical
    xor edi,edi
    xor esi,esi
    lea rdx,[rbx+544]
    xor r10d,r10d
    mov eax,262
    syscall
    jmp .ack
.fd_fallback:
    call .check_fd
    test eax,eax
    jnz .mechanical
    mov rdi,[rbx+144]
    lea rsi,[rbx+544]
    mov eax,5
    syscall
.ack:
    mov [rbx+528],rax
    lea r12,[rbx+512]
    mov r13d,288
    jmp .invoke
.check_path:
    mov rax,[rbx+40]
    cmp qword ptr [rax+8],2
    jne .check_bad
    cmp qword ptr [rbx+144],0
    jne .check_bad
    mov rax,[rax+24]
    cmp [rbx+152],rax
    jne .check_bad
    xor eax,eax
    ret
.check_fd:
    mov rax,[rbx+40]
    cmp qword ptr [rax+8],1
    jne .check_bad
    cmp qword ptr [rbx+152],0
    jne .check_bad
    mov rax,[rax+16]
    cmp [rbx+144],rax
    jne .check_bad
    xor eax,eax
    ret
.check_bad:
    mov eax,1
    ret
.terminal:
    mov [rbx+56],rax
    movabs rax,0x313030524d534e48
    cmp [rbx+128],rax
    jne .mechanical
    cmp qword ptr [rbx+136],0
    jne .terminal_error
    cmp qword ptr [rbx+144],0
    jne .mechanical
    cmp qword ptr [rbx+152],144
    jne .mechanical
    mov qword ptr [rbx+64],176
    jmp .copy_terminal
.terminal_error:
    mov qword ptr [rbx+64],32
    cmp qword ptr [rbx+152],0
    jne .mechanical
    mov rax,[rbx+136]
    cmp rax,1
    je .terminal_os
    cmp rax,2
    jne .mechanical
    cmp qword ptr [rbx+144],0
    jne .mechanical
    jmp .copy_terminal
.terminal_os:
    cmp qword ptr [rbx+144],1
    jb .mechanical
    cmp qword ptr [rbx+144],4095
    ja .mechanical
.copy_terminal:
    mov rdi,r14
    lea rsi,[rbx+128]
    mov rcx,[rbx+64]
    rep movsb
    mov eax,[rbx+56]
    jmp .finish
.invalid:
    mov eax,0xffffffff
    jmp .finish
.resource:
    mov eax,0xfffffffe
    jmp .finish
.mechanical:
    mov eax,0xfffffffc
.finish:
    mov [rbx+56],rax
    cmp qword ptr [rbx+40],0
    je .return
    mov rdi,[rbx+40]
    mov rsi,[rbx+48]
    mov eax,11
    syscall
.return:
    mov eax,[rbx+56]
    add rsp,1608
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret
.empty:
    .byte 0
.balign 16,0x90
namespace_metadata_policy:
    .incbin "namespace-metadata-policy.bin"
namespace_metadata_end:
.size namespace_metadata_entry,.-namespace_metadata_entry
.size _start,.-_start
.section .note.GNU-stack,"",@progbits
