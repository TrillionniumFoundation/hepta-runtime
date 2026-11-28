/* Copyright 2026 TrillionniumFoundation
 * SPDX-License-Identifier: Apache-2.0
 * Fixed one-shot stdio transport for the HIA public binary-write parent walk.
 * HIA owns normalization, path decisions, error order and the nested call plan.
 * This adapter owns guarded buffers, fixed syscalls and exact capability tokens.
 * PBWR_* constants are fixed by the build; production has no observation/fault path.
 */
.intel_syntax noprefix
.section .text
.global _start
.type _start,@function
_start:
    and rsp,-16
    cld
    /* Match the original interpreter's process-level ignored SIGPIPE/SIGXFSZ. */
    mov edi,13
    lea rsi,[rip+.Lpbw_ignore_signal]
    xor edx,edx
    mov r10d,8
    mov eax,13
    syscall
    test rax,rax
    jnz .Lpbw_fatal
    mov edi,25
    lea rsi,[rip+.Lpbw_ignore_signal]
    xor edx,edx
    mov r10d,8
    mov eax,13
    syscall
    test rax,rax
    jnz .Lpbw_fatal
    mov eax,110
    syscall
    cmp rax,1
    jbe .Lpbw_fatal
    mov r12,rax
    mov edi,1
    mov esi,9
    xor edx,edx
    xor r10d,r10d
    xor r8d,r8d
    mov eax,157
    syscall
    test rax,rax
    jnz .Lpbw_fatal
    mov eax,110
    syscall
    cmp rax,r12
    jne .Lpbw_fatal
.if PBWR_OBSERVE
    mov edi,3
    mov esi,1
    xor edx,edx
    mov eax,72
    syscall
    cmp rax,-4095
    jae .Lpbw_fatal
.endif
    mov edi,4096
    call .Lbw_map
    cmp rax,-4095
    jae .Lpbw_fatal
    mov r15,rax
    lea rdi,[r15]
    mov esi,65536
    call .Lbw_grow
    test eax,eax
    jnz .Lpbw_fatal
.Lpbw_input:
    mov rax,[r15+16]
    cmp rax,[r15+8]
    jb .Lpbw_read
    cmp rax,W_MAX_INPUT
    jae .Lpbw_limit
    lea rsi,[rax+rax]
    cmp rsi,W_MAX_INPUT
    jbe .Lpbw_input_grow
    mov esi,W_MAX_INPUT
.Lpbw_input_grow:
    lea rdi,[r15]
    call .Lbw_grow
    test eax,eax
    jnz .Lpbw_fatal
.Lpbw_read:
    xor edi,edi
    mov rsi,[r15]
    add rsi,[r15+16]
    mov rdx,[r15+8]
    sub rdx,[r15+16]
    xor eax,eax
    syscall
    cmp rax,-4
    je .Lpbw_read
    cmp rax,-4095
    jae .Lpbw_fatal
    test rax,rax
    jz .Lpbw_eof
    add [r15+16],rax
    jmp .Lpbw_input
.Lpbw_limit:
    xor edi,edi
    lea rsi,[r15+280]
    mov edx,1
    xor eax,eax
    syscall
    cmp rax,-4
    je .Lpbw_limit
    test rax,rax
    jnz .Lpbw_fatal
.Lpbw_eof:
    cmp qword ptr [r15+16],96
    jb .Lpbw_fatal
.if PBWR_CLOSE_STDIN
    xor edi,edi
    mov eax,3
    syscall
    test rax,rax
    jnz .Lpbw_fatal
.endif
    lea rdi,[r15+24]
    mov esi,4096
    call .Lbw_grow
    test eax,eax
    jnz .Lpbw_fatal
    lea rdi,[r15+40]
    mov esi,4096
    call .Lbw_grow
    test eax,eax
    jnz .Lpbw_fatal
    lea rdi,[r15+56]
    mov esi,4096
    call .Lbw_grow
    test eax,eax
    jnz .Lpbw_fatal
    call hia_process_orphans_create
    cmp rax,-4095
    jae .Lpbw_fatal
    mov [r15+96],rax
.if PBWR_OBSERVE
    lea rdi,[rip+.Lpbw_child_journal]
    mov rsi,r15
.else
    xor edi,edi
    xor esi,esi
.endif
    mov rdx,[r15+96]
    call binary_entropy_create
    cmp rax,-4095
    jae .Lpbw_fatal
    mov [r15+288],rax
.if PBWR_OBSERVE
    lea rdi,[rip+.Lpbw_child_journal]
    mov rsi,r15
.else
    xor edi,edi
    xor esi,esi
.endif
    mov rdx,[r15+96]
    mov rcx,[r15+288]
    call binary_write_body_create
    cmp rax,-4095
    jae .Lpbw_fatal
    mov [r15+88],rax
    mov rax,[r15]
    mov [r15+72],rax
    mov rax,[r15+16]
    mov [r15+80],rax
.Lpbw_loop:
    inc qword ptr [r15+144]
    jz .Lpbw_fatal
    mov rdi,[r15+24]
    mov rcx,[r15+32]
    shr rcx,3
    mov rax,0xa5a5a5a5a5a5a5a5
    rep stosq
.if PBWR_OBSERVE
    mov rdi,r15
    mov esi,1
    mov edx,1
    mov rcx,[r15+72]
    mov r8,[r15+80]
    call .Lpbw_journal
    test rax,rax
    jnz .Lpbw_fatal
    mov rdi,r15
    mov esi,1
    mov edx,2
    mov rcx,[r15+40]
    mov r8,[r15+48]
    call .Lpbw_journal
    test rax,rax
    jnz .Lpbw_fatal
    mov rdi,r15
    mov esi,1
    mov edx,3
    mov rcx,[r15+24]
    mov r8,[r15+32]
    call .Lpbw_journal
    test rax,rax
    jnz .Lpbw_fatal
.endif
    mov rdi,[r15+72]
    mov rsi,[r15+80]
    mov rdx,[r15+24]
    mov rcx,[r15+32]
    mov r8,[r15+40]
    mov r9,[r15+48]
    call .Lpbw_owner
    mov [r15+136],rax
.if PBWR_OBSERVE
    mov rdi,r15
    mov esi,1
    mov edx,4
    mov rcx,[r15+24]
    mov r8,[r15+32]
    call .Lpbw_journal
    test rax,rax
    jnz .Lpbw_fatal
    mov rdi,r15
    mov esi,1
    mov edx,5
    mov rcx,[r15+40]
    mov r8,[r15+48]
    call .Lpbw_journal
    test rax,rax
    jnz .Lpbw_fatal
.endif
    cmp qword ptr [r15+136],64
    jne .Lpbw_fatal
    mov rbp,[r15+24]
    mov rax,0x3130305252574248 /* HBWRR001 */
    cmp [rbp],rax
    jne .Lpbw_fatal
    mov rax,[r15+32]
    sub rax,64
    cmp [rbp+56],rax
    ja .Lpbw_fatal
    mov rbx,[rbp+8]
    cmp rbx,5
    ja .Lpbw_fatal
    test rbx,rbx
    jz .Lpbw_final
    cmp rbx,3
    je .Lpbw_final
    cmp rbx,4
    jae .Lpbw_growth
    mov rax,[rbp+16]
    test rax,rax
    jz .Lpbw_fatal
    cmp rax,[r15+128]
    jbe .Lpbw_fatal
    mov [r15+128],rax
    mov qword ptr [r15+184],0
    mov qword ptr [r15+192],0
    cmp rbx,2
    je .Lpbw_child
.if PBWR_OBSERVE
    mov rdi,r15
    mov esi,1
    mov edx,8
    mov rcx,rbp
    mov r8,[rbp+56]
    add r8,64
    call .Lpbw_journal
    test rax,rax
    jnz .Lpbw_fatal
.endif
    call .Lpbw_effect
    test rax,rax
    jnz .Lpbw_fatal
    jmp .Lpbw_resume
.Lpbw_child:
    cmp qword ptr [rbp+24],1
    jne .Lpbw_fatal
    mov rax,[rbp+40]
    or rax,[rbp+48]
    jnz .Lpbw_fatal
    mov rdi,[rbp+32]
    call .Lpbw_owned
    test rax,rax
    jz .Lpbw_fatal
    /* Reserve the complete nested request before first admission in write,
     * fingerprint and publication contexts. The immutable child starts cannot
     * be replayed as fresh commands after their first output growth. */
    mov r12,[r15+88]
    cmp qword ptr [r12+56],0
    jne .Lpbw_fatal
    mov r13,[rbp+56]
    add r13,256
    jc .Lpbw_fatal
    cmp r13,W_MAX_OUT
    ja .Lpbw_fatal
    lea rdi,[r12+104]
    mov rsi,r13
    call .Lbw_grow
    test eax,eax
    jnz .Lpbw_fatal
    mov r14,[r12+384]
    cmp qword ptr [r14+56],0
    jne .Lpbw_fatal
    lea rdi,[r14+104]
    mov rsi,r13
    call .Lbw_grow
    test eax,eax
    jnz .Lpbw_fatal
    mov r14,[r12+392]
    cmp qword ptr [r14+56],0
    jne .Lpbw_fatal
    lea rdi,[r14+104]
    mov rsi,r13
    call .Lbw_grow
    test eax,eax
    jnz .Lpbw_fatal
    mov rdi,r12
    mov rsi,[rbp+32]
    lea rdx,[rbp+64]
    mov rcx,[rbp+56]
    call binary_write_body_invoke
    cmp rax,64
    jne .Lpbw_fatal
    mov r12,[r15+88]
    cmp qword ptr [r12+56],2
    jne .Lpbw_fatal
    mov r13,[r12+168]
    cmp r13,64
    jb .Lpbw_fatal
    cmp r13,W_MAX_OUT
    ja .Lpbw_fatal
    cmp r13,[r12+112]
    ja .Lpbw_fatal
    lea rdi,[r15+56]
    lea rsi,[r13+96]
    call .Lbw_grow
    test eax,eax
    jnz .Lpbw_fatal
.if PBWR_OBSERVE
    mov rdi,r15
    mov esi,1
    mov edx,10
    mov rcx,[r12+104]
    mov r8,r13
    call .Lpbw_journal
    test rax,rax
    jnz .Lpbw_fatal
    mov rdi,r15
    mov esi,1
    mov edx,11
    mov rcx,r12
    mov r8d,4096
    call .Lpbw_journal
    test rax,rax
    jnz .Lpbw_fatal
.endif
    mov rdi,[r15+56]
    add rdi,96
    mov rsi,[r12+104]
    mov rcx,r13
    rep movsb
    mov [r15+184],r13
    mov [r15+192],r13
    mov rdi,r12
    call binary_write_body_release
    test eax,eax
    jnz .Lpbw_fatal
.Lpbw_resume:
    mov rbx,[r15+56]
    mov rax,0x3130305152574248 /* HBWRQ001 */
    mov [rbx],rax
    mov qword ptr [rbx+8],2
    mov rax,[r15+128]
    mov [rbx+16],rax
    mov rax,[r15+184]
    mov [rbx+24],rax
    lea rdi,[rbx+32]
    mov ecx,7
    xor eax,eax
    rep stosq
    mov rax,[r15+192]
    mov [rbx+88],rax
    add rax,96
    jc .Lpbw_fatal
    cmp rax,[r15+64]
    ja .Lpbw_fatal
    mov [r15+72],rbx
    mov [r15+80],rax
.if PBWR_OBSERVE
    mov rdi,r15
    mov esi,1
    mov edx,9
    mov rcx,rbx
    mov r8,rax
    call .Lpbw_journal
    test rax,rax
    jnz .Lpbw_fatal
.endif
    jmp .Lpbw_loop
.Lpbw_growth:
    mov rax,[rbp+16]
    or rax,[rbp+24]
    or rax,[rbp+40]
    or rax,[rbp+48]
    or rax,[rbp+56]
    jnz .Lpbw_fatal
    mov r13,[rbp+32]
    cmp rbx,4
    jne .Lpbw_output_growth
    cmp r13,[r15+48]
    jbe .Lpbw_fatal
    cmp r13,W_MAX_WORK
    ja .Lpbw_fatal
.if PBWR_OBSERVE
    mov rdi,r15
    mov esi,1
    mov edx,6
    mov rcx,[r15+40]
    mov r8,[r15+48]
    call .Lpbw_journal
    test rax,rax
    jnz .Lpbw_fatal
.endif
    lea rdi,[r15+40]
    mov rsi,r13
    call .Lbw_grow
    test eax,eax
    jnz .Lpbw_fatal
.if PBWR_OBSERVE
    mov rdi,r15
    mov esi,1
    mov edx,7
    mov rcx,[r15+40]
    mov r8,[r15+48]
    call .Lpbw_journal
    test rax,rax
    jnz .Lpbw_fatal
.endif
    jmp .Lpbw_loop
.Lpbw_output_growth:
    cmp r13,[r15+32]
    jbe .Lpbw_fatal
    cmp r13,W_MAX_OUT
    ja .Lpbw_fatal
    lea rdi,[r15+24]
    mov rsi,r13
    call .Lbw_grow
    test eax,eax
    jnz .Lpbw_fatal
    jmp .Lpbw_loop
.Lpbw_final:
    mov rax,[r15+104]
    or rax,[r15+112]
    jnz .Lpbw_fatal
    mov rax,[rbp+24]
    or rax,[rbp+32]
    or rax,[rbp+40]
    or rax,[rbp+48]
    jnz .Lpbw_fatal
    lea rax,[rbp+64]
    mov [r15+216],rax
    mov rax,[rbp+56]
    mov [r15+224],rax
    mov qword ptr [r15+200],1
    mov qword ptr [r15+208],0
.if PBWR_OBSERVE
    mov rdi,r15
    mov esi,1
    mov edx,12
    mov rcx,r15
    mov r8d,4096
    call .Lpbw_journal
    test rax,rax
    jnz .Lpbw_fatal
    mov rdi,r15
    mov esi,1
    mov edx,13
    mov rcx,[r15+96]
    mov r8d,4096
    call .Lpbw_journal
    test rax,rax
    jnz .Lpbw_fatal
    mov r12,[r15+96]
    mov r12,[r12+32]
.Lpbw_orphan_journal:
    test r12,r12
    jz .Lpbw_orphan_journal_done
    mov rdi,r15
    mov esi,1
    mov edx,14
    mov rcx,r12
    mov r8d,4096
    call .Lpbw_journal
    test rax,rax
    jnz .Lpbw_fatal
    mov r12,[r12+16]
    jmp .Lpbw_orphan_journal
.Lpbw_orphan_journal_done:
.endif
    cmp qword ptr [rbp+8],0
    je .Lpbw_publish
    mov rax,[r15+216]
    mov [r15+232],rax
    mov rax,[r15+224]
    mov [r15+240],rax
    lea rdi,[r15+152]
    mov esi,4096
    call .Lbw_grow
    test eax,eax
    jnz .Lpbw_fatal
    lea rdi,[r15+168]
    mov esi,12288
    call .Lbw_grow
    test eax,eax
    jnz .Lpbw_fatal
.Lpbw_format:
.if PBWR_OBSERVE
    mov rdi,r15
    mov esi,3
    mov edx,1
    mov rcx,[r15+232]
    mov r8,[r15+240]
    call .Lpbw_journal
    test rax,rax
    jnz .Lpbw_fatal
    mov rdi,r15
    mov esi,3
    mov edx,2
    mov rcx,[r15+168]
    mov r8,[r15+176]
    call .Lpbw_journal
    test rax,rax
    jnz .Lpbw_fatal
    mov rdi,r15
    mov esi,3
    mov edx,3
    mov rcx,[r15+152]
    mov r8,[r15+160]
    call .Lpbw_journal
    test rax,rax
    jnz .Lpbw_fatal
.endif
    mov rdi,[r15+232]
    mov rsi,[r15+240]
    mov rdx,[r15+152]
    mov rcx,[r15+160]
    mov r8,[r15+168]
    mov r9,[r15+176]
    call .Lpbw_error
    mov [r15+136],rax
.if PBWR_OBSERVE
    mov rdi,r15
    mov esi,3
    mov edx,4
    mov rcx,[r15+152]
    mov r8,[r15+160]
    call .Lpbw_journal
    test rax,rax
    jnz .Lpbw_fatal
    mov rdi,r15
    mov esi,3
    mov edx,5
    mov rcx,[r15+168]
    mov r8,[r15+176]
    call .Lpbw_journal
    test rax,rax
    jnz .Lpbw_fatal
.endif
    mov rax,[r15+136]
    cmp eax,0xfffffffe
    je .Lpbw_format_growth
    test rax,rax
    jz .Lpbw_fatal
    cmp rax,[r15+160]
    ja .Lpbw_fatal
    mov [r15+224],rax
    mov rax,[r15+152]
    mov [r15+216],rax
    mov qword ptr [r15+200],2
    mov qword ptr [r15+208],1
    jmp .Lpbw_publish
.Lpbw_format_growth:
    mov rsi,[r15+160]
    cmp rsi,W_MAX_OUT
    jae .Lpbw_fatal
    add rsi,rsi
    lea rdi,[r15+152]
    call .Lbw_grow
    test eax,eax
    jnz .Lpbw_fatal
    jmp .Lpbw_format
.Lpbw_publish:
    mov rdi,[r15+88]
    call binary_write_body_destroy
    test eax,eax
    jnz .Lpbw_fatal
    mov qword ptr [r15+88],0
    mov rdi,[r15+200]
    mov rsi,[r15+216]
    mov rdx,[r15+224]
    call .Lpbw_write
    test rax,rax
    jnz .Lpbw_fatal
    mov byte ptr [r15+280],10
    mov rdi,[r15+200]
    lea rsi,[r15+280]
    mov edx,1
    call .Lpbw_write
    test rax,rax
    jnz .Lpbw_fatal
    mov rdi,[r15+208]
    mov eax,60
    syscall
.Lpbw_fatal:
    mov edi,111
    mov eax,60
    syscall

/* Return the address of one live native-owned FD+1 token, or zero. */
.Lpbw_owned:
    cmp rdi,2147483647
    ja .Lpbw_owned_bad
    lea rax,[rdi+1]
    cmp [r15+104],rax
    je .Lpbw_owned_first
    cmp [r15+112],rax
    je .Lpbw_owned_second
.Lpbw_owned_bad:
    xor eax,eax
    ret
.Lpbw_owned_first:
    lea rax,[r15+104]
    ret
.Lpbw_owned_second:
    lea rax,[r15+112]
    ret

/* Fixed root open/openat/close/orphan/repeated failed close only. */
.Lpbw_effect:
    W_ENTER
    mov r13,rbp
    mov rax,[r13+40]
    or rax,[r13+48]
    jnz .Lpbw_effect_bad
    mov rbx,[r13+24]
    cmp rbx,1
    je .Lpbw_open_root
    cmp rbx,2
    je .Lpbw_open_component
    cmp rbx,3
    jb .Lpbw_effect_bad
    cmp rbx,5
    ja .Lpbw_effect_bad
    cmp qword ptr [r13+56],0
    jne .Lpbw_effect_bad
    cmp rbx,5
    je .Lpbw_repeat_close
    mov rdi,[r13+32]
    call .Lpbw_owned
    test rax,rax
    jz .Lpbw_effect_bad
    mov r12,rax
    cmp rbx,4
    je .Lpbw_orphan
.if PBWR_FAIL_CLOSE
    cmp qword ptr [r15+272],0
    jne .Lpbw_close
    mov rdi,[r13+32]
    call .Lpbw_fault_close
    test rax,rax
    jnz .Lpbw_effect_bad
    mov qword ptr [r15+272],1
.endif
.Lpbw_close:
    mov rdi,[r13+32]
    mov eax,3
    syscall
    mov [r15+184],rax
    mov qword ptr [r12],0
    mov qword ptr [r15+120],0
    cmp rax,-4095
    jb .Lpbw_effect_ok
    mov rax,[r13+32]
    inc rax
    mov [r15+120],rax
    jmp .Lpbw_effect_ok
.Lpbw_orphan:
    mov rdi,[r15+96]
    mov rsi,[r13+32]
    mov rdx,r15
    mov ecx,1
    call hia_process_orphans_append
    test rax,rax
    jnz .Lpbw_effect_bad
    mov qword ptr [r12],0
    jmp .Lpbw_effect_ok
.Lpbw_repeat_close:
    mov rdi,[r13+32]
    cmp rdi,2147483647
    ja .Lpbw_effect_bad
    lea rax,[rdi+1]
    cmp rax,[r15+120]
    jne .Lpbw_effect_bad
    mov qword ptr [r15+120],0
    mov eax,3
    syscall
    mov [r15+184],rax
    jmp .Lpbw_effect_ok
.Lpbw_open_root:
    mov rax,[r13+32]
    or rax,[r13+56]
    or rax,[r15+104]
    or rax,[r15+112]
    jnz .Lpbw_effect_bad
    mov rdi,-100
    lea rsi,[rip+.Lpbw_root]
    jmp .Lpbw_open
.Lpbw_open_component:
    mov rdi,[r13+32]
    call .Lpbw_owned
    test rax,rax
    jz .Lpbw_effect_bad
    mov rcx,[r13+56]
    cmp rcx,2
    jb .Lpbw_effect_bad
    lea rsi,[r13+64]
    xor edx,edx
.Lpbw_name:
    cmp rdx,rcx
    jae .Lpbw_effect_bad
    mov al,[rsi+rdx]
    inc rdx
    test al,al
    jz .Lpbw_name_end
    cmp al,47
    je .Lpbw_effect_bad
    jmp .Lpbw_name
.Lpbw_name_end:
    cmp rdx,rcx
    jne .Lpbw_effect_bad
    mov rdi,[r13+32]
.Lpbw_open:
    cmp qword ptr [r15+104],0
    je .Lpbw_open_slot_first
    cmp qword ptr [r15+112],0
    jne .Lpbw_effect_bad
    lea r12,[r15+112]
    jmp .Lpbw_open_actual
.Lpbw_open_slot_first:
    lea r12,[r15+104]
.Lpbw_open_actual:
    mov edx,720896 /* O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC; O_RDONLY=0 */
    xor r10d,r10d
    mov eax,257
    syscall
    mov [r15+184],rax
    cmp rax,-4095
    jae .Lpbw_effect_ok
    cmp rax,2147483647
    ja .Lpbw_effect_bad
    inc rax
    mov [r12],rax
.Lpbw_effect_ok:
    xor eax,eax
    jmp .Lpbw_effect_done
.Lpbw_effect_bad:
    mov eax,1
.Lpbw_effect_done:
    W_LEAVE
.Lpbw_root:
    .byte 47,0
.balign 8
.Lpbw_ignore_signal:
    .quad 1,0,0,0

.Lpbw_write:
    push rbx
    push r12
    push r13
    push r14
    mov rbx,rdi
    mov r12,rsi
    mov r13,rdx
    xor r14d,r14d
.Lpbw_write_loop:
    cmp r14,r13
    je .Lpbw_write_ok
    mov rdi,rbx
    lea rsi,[r12+r14]
    mov rdx,r13
    sub rdx,r14
    mov eax,1
    syscall
    cmp rax,-4
    je .Lpbw_write_loop
    cmp rax,-4095
    jae .Lpbw_write_done
    test rax,rax
    jz .Lpbw_write_zero
    add r14,rax
    jmp .Lpbw_write_loop
.Lpbw_write_zero:
    mov rax,-5
    jmp .Lpbw_write_done
.Lpbw_write_ok:
    xor eax,eax
.Lpbw_write_done:
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

.Lpbw_owner:
    .byte 0xe9
.global public_binary_write_body_call_displacement
public_binary_write_body_call_displacement:
    .long 0
.Lpbw_error:
    .byte 0xe9
.global public_binary_write_error_call_displacement
public_binary_write_error_call_displacement:
    .long 0

.if PBWR_OBSERVE
/* Original opaque child callback: only records, always returns actual I/O ACK. */
.Lpbw_child_journal:
    mov rdi,rsi
    mov esi,2
    jmp .Lpbw_journal

/* Full spans, including untouched capacities. No result substitution.
 * HBWLJR01: family, event, producer identity, reserved, reserved, extent, reserved. */
.Lpbw_journal:
    W_ENTER
    sub rsp,64
    mov r12,rdi
    mov r13,rcx
    mov r14,r8
    mov rax,0x3130524a4c574248 /* HBWLJR01 */
    mov [rsp],rax
    mov [rsp+8],rsi
    mov [rsp+16],rdx
    mov [rsp+24],r12
    mov qword ptr [rsp+32],0
    mov qword ptr [rsp+40],0
    mov [rsp+48],r14
    mov qword ptr [rsp+56],0
    mov edi,3
    mov rsi,rsp
    mov edx,64
    call .Lpbw_write
    test rax,rax
    jnz .Lpbw_journal_done
    mov edi,3
    mov rsi,r13
    mov rdx,r14
    call .Lpbw_write
.Lpbw_journal_done:
    add rsp,64
    W_LEAVE
.endif

.if PBWR_FAIL_CLOSE
/* Fixture only: install actual kernel EIO for close of this exact runtime FD.
 * The real syscall executes and is refused by seccomp; no reply bytes are forged. */
.Lpbw_fault_close:
    W_ENTER
    sub rsp,80
    mov r12,rdi
    mov edi,38
    mov esi,1
    xor edx,edx
    xor r10d,r10d
    xor r8d,r8d
    mov eax,157
    syscall
    test rax,rax
    jnz .Lpbw_fault_done
    mov word ptr [rsp],6
    lea rax,[rsp+16]
    mov [rsp+8],rax
    mov qword ptr [rsp+16],0x20
    mov dword ptr [rsp+24],0x03000015
    mov dword ptr [rsp+28],3
    mov dword ptr [rsp+32],0x20
    mov dword ptr [rsp+36],16
    mov dword ptr [rsp+40],0x01000015
    mov [rsp+44],r12d
    mov dword ptr [rsp+48],6
    mov dword ptr [rsp+52],0x00050005
    mov dword ptr [rsp+56],6
    mov dword ptr [rsp+60],0x7fff0000
    mov edi,1
    xor esi,esi
    mov rdx,rsp
    mov eax,317
    syscall
.Lpbw_fault_done:
    add rsp,80
    W_LEAVE
.endif
.section .note.GNU-stack,"",@progbits
