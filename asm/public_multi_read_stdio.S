/* Copyright 2026 TrillionniumFoundation
 * SPDX-License-Identifier: Apache-2.0
 * One-shot stdio boundary around the unchanged qualified multi-read callable.
 * HIA owns all filesystem policy and complete success/error text.
 * The boundary owns fixed image calls, guarded arenas, pipes and process lifetime.
 * PMR_* constants are fixed at build time. Production has no journal path.
 */
.intel_syntax noprefix
.section .text
.global _start
.type _start,@function
_start:
    and rsp,-16
    cld
    mov eax,110
    syscall
    cmp rax,1
    jbe .Lpmr_fatal
    mov r12,rax
    mov edi,1
    mov esi,9
    xor edx,edx
    xor r10d,r10d
    xor r8d,r8d
    mov eax,157
    syscall
    test rax,rax
    jnz .Lpmr_fatal
    mov eax,110
    syscall
    cmp rax,r12
    jne .Lpmr_fatal
.if PMR_OBSERVE
    mov edi,3
    mov esi,1
    xor edx,edx
    mov eax,72
    syscall
    cmp rax,-4095
    jae .Lpmr_fatal
.endif
    mov edi,4096
    call .Lmrd_map
    cmp rax,-4095
    jae .Lpmr_fatal
    mov r15,rax
    lea rdi,[r15]
    mov esi,65536
    call .Lmrd_grow
    test eax,eax
    jnz .Lpmr_fatal
.Lpmr_input:
    mov rax,[r15+16]
    cmp rax,[r15+8]
    jb .Lpmr_read
    cmp rax,M_MAX_INPUT
    jae .Lpmr_limit
    lea rsi,[rax+rax]
    cmp rsi,M_MAX_INPUT
    jbe .Lpmr_input_grow
    mov esi,M_MAX_INPUT
.Lpmr_input_grow:
    lea rdi,[r15]
    call .Lmrd_grow
    test eax,eax
    jnz .Lpmr_fatal
.Lpmr_read:
    xor edi,edi
    mov rsi,[r15]
    add rsi,[r15+16]
    mov rdx,[r15+8]
    sub rdx,[r15+16]
    xor eax,eax
    syscall
    cmp rax,-4
    je .Lpmr_read
    cmp rax,-4095
    jae .Lpmr_fatal
    test rax,rax
    jz .Lpmr_eof
    add [r15+16],rax
    jmp .Lpmr_input
.Lpmr_limit:
    xor edi,edi
    lea rsi,[r15+152]
    mov edx,1
    xor eax,eax
    syscall
    cmp rax,-4
    je .Lpmr_limit
    test rax,rax
    jnz .Lpmr_fatal
.Lpmr_eof:
    cmp qword ptr [r15+16],96
    jb .Lpmr_fatal
    cmp qword ptr [r15+16],M_MAX_INPUT
    jae .Lpmr_fatal
.if PMR_CLOSE_STDIN
    xor edi,edi
    mov eax,3
    syscall
    test rax,rax
    jnz .Lpmr_fatal
.endif
    call hia_process_orphans_create
    cmp rax,-4095
    jae .Lpmr_fatal
    mov [r15+32],rax
.if PMR_OBSERVE
    lea rdi,[rip+.Lpmr_journal]
    mov rsi,r15
.else
    xor edi,edi
    xor esi,esi
.endif
    mov rdx,rax
    call multi_read_body_create
    cmp rax,-4095
    jae .Lpmr_fatal
    mov [r15+24],rax
    mov rdi,rax
    mov rsi,[r15]
    mov rdx,[r15+16]
    call multi_read_body_invoke
    cmp rax,64
    jne .Lpmr_fatal
    mov r12,[r15+24]
    cmp qword ptr [r12+56],2
    jne .Lpmr_fatal
    mov r14,[r12+104]
    mov rax,0x3130305344524d48 /* HMRDS001 */
    cmp [r14],rax
    jne .Lpmr_fatal
    mov r13,[r12+168]
    cmp r13,64
    jb .Lpmr_fatal
    cmp r13,[r12+112]
    ja .Lpmr_fatal
    sub r13,64
    cmp [r14+56],r13
    jne .Lpmr_fatal
    cmp qword ptr [r14+8],3
    je .Lpmr_error
    cmp qword ptr [r14+8],0
    jne .Lpmr_fatal
    mov qword ptr [r15+104],0
    lea rax,[r14+64]
    mov [r15+112],rax
    mov [r15+120],r13
    jmp .Lpmr_envelope
.Lpmr_error:
    mov qword ptr [r15+104],1
    cmp r13,64
    jb .Lpmr_fatal
    add r14,64
    movabs rax,0x3130304446545548 /* HUTFD001 */
    cmp [r14],rax
    jne .Lpmr_structured
    cmp qword ptr [r14+8],3
    jne .Lpmr_fatal
    sub r13,64
    cmp [r14+40],r13
    jne .Lpmr_fatal
    cmp [r14+56],r13
    jne .Lpmr_fatal
    lea rax,[r14+64]
    mov [r15+112],rax
    mov [r15+120],r13
    jmp .Lpmr_envelope
.Lpmr_structured:
    movabs rax,0x3130305344524248 /* HBRDS001 */
    cmp [r14],rax
    jne .Lpmr_fatal
    mov [r15+112],r14
    mov [r15+120],r13
    imul rsi,r13,6
    jo .Lpmr_fatal
    add rsi,1024
    jc .Lpmr_fatal
    cmp rsi,M_MAX_OUT
    ja .Lpmr_fatal
    lea rdi,[r15+40]
    call .Lmrd_grow
    test eax,eax
    jnz .Lpmr_fatal
    lea rdi,[r15+56]
    mov esi,12288
    call .Lmrd_grow
    test eax,eax
    jnz .Lpmr_fatal
    mov rdi,[r15+40]
    mov rcx,[r15+48]
    shr rcx,3
    mov rax,0xa5a5a5a5a5a5a5a5
    rep stosq
.if PMR_OBSERVE
    mov rdi,r15
    mov rsi,[r15+24]
    mov edx,90
    mov rcx,[r15+112]
    mov r8,[r15+120]
    call .Lpmr_journal
    test rax,rax
    jnz .Lpmr_fatal
.endif
    mov rdi,[r15+112]
    mov rsi,[r15+120]
    mov rdx,[r15+40]
    mov rcx,[r15+48]
    mov r8,[r15+56]
    mov r9,[r15+64]
    call .Lpmr_error_image
    cmp rax,[r15+48]
    ja .Lpmr_fatal
    mov [r15+120],rax
    mov rax,[r15+40]
    mov [r15+112],rax
.if PMR_OBSERVE
    mov rdi,r15
    mov rsi,[r15+24]
    mov edx,91
    mov rcx,[r15+40]
    mov r8,[r15+48]
    call .Lpmr_journal
    test rax,rax
    jnz .Lpmr_fatal
    mov rdi,r15
    mov rsi,[r15+24]
    mov edx,92
    mov rcx,[r15+56]
    mov r8,[r15+64]
    call .Lpmr_journal
    test rax,rax
    jnz .Lpmr_fatal
.endif
.Lpmr_envelope:
    mov rsi,[r15+120]
    add rsi,24
    jc .Lpmr_fatal
    cmp rsi,M_MAX_OUT
    ja .Lpmr_fatal
    mov [r15+144],rsi
    lea rdi,[r15+72]
    call .Lmrd_grow
    test eax,eax
    jnz .Lpmr_fatal
    mov rdi,[r15+72]
    movabs rax,0x3130305146524d48 /* HMRFQ001 */
    mov [rdi],rax
    mov rax,[r15+104]
    mov [rdi+8],rax
    mov rcx,[r15+120]
    mov [rdi+16],rcx
    add rdi,24
    mov rsi,[r15+112]
    rep movsb
    mov rsi,[r15+120]
    add rsi,128
    jc .Lpmr_fatal
    cmp rsi,M_MAX_OUT
    ja .Lpmr_fatal
    lea rdi,[r15+88]
    call .Lmrd_grow
    test eax,eax
    jnz .Lpmr_fatal
    mov rdi,[r15+88]
    mov rcx,[r15+96]
    shr rcx,3
    mov rax,0xa5a5a5a5a5a5a5a5
    rep stosq
.if PMR_OBSERVE
    mov rdi,r15
    mov rsi,[r15+24]
    mov edx,80
    mov rcx,[r15+72]
    mov r8,[r15+144]
    call .Lpmr_journal
    test rax,rax
    jnz .Lpmr_fatal
.endif
    mov rdi,[r15+72]
    mov rsi,[r15+144]
    mov rdx,[r15+88]
    mov rcx,[r15+96]
    xor r8d,r8d
    xor r9d,r9d
    call .Lpmr_result_image
    cmp rax,32
    jne .Lpmr_fatal
.if PMR_OBSERVE
    mov rdi,r15
    mov rsi,[r15+24]
    mov edx,81
    mov rcx,[r15+88]
    mov r8,[r15+96]
    call .Lpmr_journal
    test rax,rax
    jnz .Lpmr_fatal
.endif
    mov r14,[r15+88]
    movabs rax,0x3130305246524d48 /* HMRFR001 */
    cmp [r14],rax
    jne .Lpmr_fatal
    mov rax,[r14+8]
    cmp rax,[r15+104]
    jne .Lpmr_fatal
    cmp qword ptr [r14+24],0
    jne .Lpmr_fatal
    mov rax,[r15+96]
    sub rax,32
    cmp [r14+16],rax
    ja .Lpmr_fatal
    mov rdi,[r15+24]
    call multi_read_body_release
    test rax,rax
    jnz .Lpmr_fatal
.if PMR_OBSERVE
    mov rdi,r15
    mov rsi,[r15+24]
    mov edx,95
    mov rcx,[r15+32]
    mov r8d,4096
    call .Lpmr_journal
    test rax,rax
    jnz .Lpmr_fatal
    mov rdi,r15
    mov rsi,[r15+24]
    mov edx,96
    mov rcx,[r15+24]
    mov r8d,4096
    call .Lpmr_journal
    test rax,rax
    jnz .Lpmr_fatal
.endif
    mov rdi,[r15+24]
    call multi_read_body_destroy
    test rax,rax
    jnz .Lpmr_fatal
    mov qword ptr [r15+24],0
    mov rdi,[r15+104]
    inc rdi
    lea rsi,[r14+32]
    mov rdx,[r14+16]
    call .Lpmr_write
    test rax,rax
    jnz .Lpmr_fatal
    mov rdi,[r15+104]
    mov eax,60
    syscall
.Lpmr_fatal:
    mov edi,111
    mov eax,60
    syscall
.Lpmr_write:
    M_ENTER
    mov rbx,rdi
    mov r12,rsi
    mov r13,rdx
.Lpmr_write_loop:
    test r13,r13
    jz .Lpmr_write_ok
    mov rdi,rbx
    mov rsi,r12
    mov rdx,r13
    mov eax,1
    syscall
    cmp rax,-4
    je .Lpmr_write_loop
    cmp rax,-4095
    jae .Lpmr_write_done
    test rax,rax
    jz .Lpmr_write_zero
    add r12,rax
    sub r13,rax
    jmp .Lpmr_write_loop
.Lpmr_write_zero:
    mov rax,-5
    jmp .Lpmr_write_done
.Lpmr_write_ok:
    xor eax,eax
.Lpmr_write_done:
    M_LEAVE

.balign 16
.global public_multi_read_error_call_displacement
.Lpmr_error_image:
    .byte 0xe9
public_multi_read_error_call_displacement:
    .long 0
.global public_multi_read_result_call_displacement
.Lpmr_result_image:
    .byte 0xe9
public_multi_read_result_call_displacement:
    .long 0

.if PMR_OBSERVE
/* Observation only: all complete passed spans, with distinct body/parent owners.
 * No callback-supplied syscall result and no callback-selected image or FD. */
.Lpmr_journal:
    M_ENTER
    mov r12,rdi
    mov r13,rsi
    mov ebx,edx
    mov r14,rcx
    mov r15,r8
    sub rsp,64
    mov rdi,rsp
    xor eax,eax
    mov ecx,8
    rep stosq
    movabs rax,0x3130304a524d5048 /* HPMRJ001 */
    mov [rsp],rax
    mov eax,1
    mov rdx,[r12+24]
    cmp r13,rdx
    je .Lpmr_journal_owner
    mov eax,2
    cmp r13,[rdx+384]
    je .Lpmr_journal_owner
    mov eax,3
    cmp r13,[rdx+392]
    jne .Lpmr_fatal
.Lpmr_journal_owner:
    mov [rsp+8],rax
    mov [rsp+16],rbx
    mov [rsp+24],r15
    mov rax,[r13+56]
    mov [rsp+32],rax
    mov rax,[r13+192]
    mov [rsp+40],rax
    mov rax,[r13+184]
    mov [rsp+48],rax
    inc qword ptr [r12+136]
    jz .Lpmr_fatal
    mov rax,[r12+136]
    mov [rsp+56],rax
    mov edi,3
    mov rsi,rsp
    mov edx,64
    call .Lpmr_write
    test rax,rax
    jnz .Lpmr_journal_done
    mov edi,3
    mov rsi,r14
    mov rdx,r15
    call .Lpmr_write
.Lpmr_journal_done:
    add rsp,64
    M_LEAVE
.endif
.section .note.GNU-stack,"",@progbits
