/* Copyright 2026 TrillionniumFoundation
 * SPDX-License-Identifier: Apache-2.0
 * Fixed one-shot stdio transport for the HIA public file-info parent walk.
 * HIA owns normalization, path decisions, error order and the nested call plan.
 * This adapter owns guarded buffers, fixed syscalls and exact capability tokens.
 * PFIW_* constants are fixed by the build; production has no observation/fault path.
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
    jbe .Lpfw_fatal
    mov r12,rax
    mov edi,1
    mov esi,9
    xor edx,edx
    xor r10d,r10d
    xor r8d,r8d
    mov eax,157
    syscall
    test rax,rax
    jnz .Lpfw_fatal
    mov eax,110
    syscall
    cmp rax,r12
    jne .Lpfw_fatal
.if PFIW_OBSERVE
    mov edi,3
    mov esi,1
    xor edx,edx
    mov eax,72
    syscall
    cmp rax,-4095
    jae .Lpfw_fatal
.endif
    mov edi,4096
    call .Lifa_map
    cmp rax,-4095
    jae .Lpfw_fatal
    mov r15,rax
    lea rdi,[r15]
    mov esi,65536
    call .Lifa_grow
    test eax,eax
    jnz .Lpfw_fatal
.Lpfw_input:
    mov rax,[r15+16]
    cmp rax,[r15+8]
    jb .Lpfw_read
    cmp rax,I_MAX_INPUT
    jae .Lpfw_limit
    lea rsi,[rax+rax]
    cmp rsi,I_MAX_INPUT
    jbe .Lpfw_input_grow
    mov esi,I_MAX_INPUT
.Lpfw_input_grow:
    lea rdi,[r15]
    call .Lifa_grow
    test eax,eax
    jnz .Lpfw_fatal
.Lpfw_read:
    xor edi,edi
    mov rsi,[r15]
    add rsi,[r15+16]
    mov rdx,[r15+8]
    sub rdx,[r15+16]
    xor eax,eax
    syscall
    cmp rax,-4
    je .Lpfw_read
    cmp rax,-4095
    jae .Lpfw_fatal
    test rax,rax
    jz .Lpfw_eof
    add [r15+16],rax
    jmp .Lpfw_input
.Lpfw_limit:
    xor edi,edi
    lea rsi,[r15+280]
    mov edx,1
    xor eax,eax
    syscall
    cmp rax,-4
    je .Lpfw_limit
    test rax,rax
    jnz .Lpfw_fatal
.Lpfw_eof:
    cmp qword ptr [r15+16],96
    jb .Lpfw_fatal
.if PFIW_CLOSE_STDIN
    xor edi,edi
    mov eax,3
    syscall
    test rax,rax
    jnz .Lpfw_fatal
.endif
    lea rdi,[r15+24]
    mov esi,4096
    call .Lifa_grow
    test eax,eax
    jnz .Lpfw_fatal
    lea rdi,[r15+40]
    mov esi,4096
    call .Lifa_grow
    test eax,eax
    jnz .Lpfw_fatal
    lea rdi,[r15+56]
    mov esi,4096
    call .Lifa_grow
    test eax,eax
    jnz .Lpfw_fatal
    call hia_process_orphans_create
    cmp rax,-4095
    jae .Lpfw_fatal
    mov [r15+96],rax
.if PFIW_OBSERVE
    lea rdi,[rip+.Lpfw_child_journal]
    mov rsi,r15
.else
    xor edi,edi
    xor esi,esi
.endif
    mov rdx,rax
    call file_info_at_create
    cmp rax,-4095
    jae .Lpfw_fatal
    mov [r15+88],rax
    mov rax,[r15]
    mov [r15+72],rax
    mov rax,[r15+16]
    mov [r15+80],rax
.Lpfw_loop:
    inc qword ptr [r15+144]
    jz .Lpfw_fatal
    mov rdi,[r15+24]
    mov rcx,[r15+32]
    shr rcx,3
    mov rax,0xa5a5a5a5a5a5a5a5
    rep stosq
.if PFIW_OBSERVE
    mov rdi,r15
    mov esi,1
    mov edx,1
    mov rcx,[r15+72]
    mov r8,[r15+80]
    call .Lpfw_journal
    test rax,rax
    jnz .Lpfw_fatal
    mov rdi,r15
    mov esi,1
    mov edx,2
    mov rcx,[r15+40]
    mov r8,[r15+48]
    call .Lpfw_journal
    test rax,rax
    jnz .Lpfw_fatal
    mov rdi,r15
    mov esi,1
    mov edx,3
    mov rcx,[r15+24]
    mov r8,[r15+32]
    call .Lpfw_journal
    test rax,rax
    jnz .Lpfw_fatal
.endif
    mov rdi,[r15+72]
    mov rsi,[r15+80]
    mov rdx,[r15+24]
    mov rcx,[r15+32]
    mov r8,[r15+40]
    mov r9,[r15+48]
    call .Lpfw_owner
    mov [r15+136],rax
.if PFIW_OBSERVE
    mov rdi,r15
    mov esi,1
    mov edx,4
    mov rcx,[r15+24]
    mov r8,[r15+32]
    call .Lpfw_journal
    test rax,rax
    jnz .Lpfw_fatal
    mov rdi,r15
    mov esi,1
    mov edx,5
    mov rcx,[r15+40]
    mov r8,[r15+48]
    call .Lpfw_journal
    test rax,rax
    jnz .Lpfw_fatal
.endif
    cmp qword ptr [r15+136],64
    jne .Lpfw_fatal
    mov rbp,[r15+24]
    mov rax,0x3130305244524648 /* HFRDR001 */
    cmp [rbp],rax
    jne .Lpfw_fatal
    mov rax,[r15+32]
    sub rax,64
    cmp [rbp+56],rax
    ja .Lpfw_fatal
    mov rbx,[rbp+8]
    cmp rbx,5
    ja .Lpfw_fatal
    test rbx,rbx
    jz .Lpfw_final
    cmp rbx,3
    je .Lpfw_final
    cmp rbx,4
    jae .Lpfw_growth
    mov rax,[rbp+16]
    test rax,rax
    jz .Lpfw_fatal
    cmp rax,[r15+128]
    jbe .Lpfw_fatal
    mov [r15+128],rax
    mov qword ptr [r15+184],0
    mov qword ptr [r15+192],0
    cmp rbx,2
    je .Lpfw_child
.if PFIW_OBSERVE
    mov rdi,r15
    mov esi,1
    mov edx,8
    mov rcx,rbp
    mov r8,[rbp+56]
    add r8,64
    call .Lpfw_journal
    test rax,rax
    jnz .Lpfw_fatal
.endif
    call .Lpfw_effect
    test rax,rax
    jnz .Lpfw_fatal
    jmp .Lpfw_resume
.Lpfw_child:
    cmp qword ptr [rbp+24],1
    jne .Lpfw_fatal
    mov rax,[rbp+40]
    or rax,[rbp+48]
    jnz .Lpfw_fatal
    mov rdi,[rbp+32]
    call .Lpfw_owned
    test rax,rax
    jz .Lpfw_fatal
    /* Both frozen children start by emitting a complete request containing
     * input bytes. Reserve the complete framed input extent before mutation;
     * growth after a started command is not a second start admission. */
    mov r12,[r15+88]
    cmp qword ptr [r12+56],0
    jne .Lpfw_fatal
    mov r13,[rbp+56]
    add r13,64
    jc .Lpfw_fatal
    cmp r13,I_MAX_OUT
    ja .Lpfw_fatal
    lea rdi,[r12+104]
    mov rsi,r13
    call .Lifa_grow
    test eax,eax
    jnz .Lpfw_fatal
    mov r14,[r12+384]
    cmp qword ptr [r14+56],0
    jne .Lpfw_fatal
    lea rdi,[r14+104]
    mov rsi,r13
    call .Lifa_grow
    test eax,eax
    jnz .Lpfw_fatal
    mov rdi,r12
    mov rsi,[rbp+32]
    lea rdx,[rbp+64]
    mov rcx,[rbp+56]
    call file_info_at_invoke
    cmp rax,64
    jne .Lpfw_fatal
    mov r12,[r15+88]
    cmp qword ptr [r12+56],2
    jne .Lpfw_fatal
    mov r13,[r12+168]
    cmp r13,64
    jb .Lpfw_fatal
    cmp r13,I_MAX_OUT
    ja .Lpfw_fatal
    cmp r13,[r12+112]
    ja .Lpfw_fatal
    lea rdi,[r15+56]
    lea rsi,[r13+96]
    call .Lifa_grow
    test eax,eax
    jnz .Lpfw_fatal
.if PFIW_OBSERVE
    mov rdi,r15
    mov esi,1
    mov edx,10
    mov rcx,[r12+104]
    mov r8,r13
    call .Lpfw_journal
    test rax,rax
    jnz .Lpfw_fatal
    mov rdi,r15
    mov esi,1
    mov edx,11
    mov rcx,r12
    mov r8d,4096
    call .Lpfw_journal
    test rax,rax
    jnz .Lpfw_fatal
.endif
    mov rdi,[r15+56]
    add rdi,96
    mov rsi,[r12+104]
    mov rcx,r13
    rep movsb
    mov [r15+184],r13
    mov [r15+192],r13
    mov rdi,r12
    call file_info_at_release
    test eax,eax
    jnz .Lpfw_fatal
.Lpfw_resume:
    mov rbx,[r15+56]
    mov rax,0x3130305144524648 /* HFRDQ001 */
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
    jc .Lpfw_fatal
    cmp rax,[r15+64]
    ja .Lpfw_fatal
    mov [r15+72],rbx
    mov [r15+80],rax
.if PFIW_OBSERVE
    mov rdi,r15
    mov esi,1
    mov edx,9
    mov rcx,rbx
    mov r8,rax
    call .Lpfw_journal
    test rax,rax
    jnz .Lpfw_fatal
.endif
    jmp .Lpfw_loop
.Lpfw_growth:
    mov rax,[rbp+16]
    or rax,[rbp+24]
    or rax,[rbp+40]
    or rax,[rbp+48]
    or rax,[rbp+56]
    jnz .Lpfw_fatal
    mov r13,[rbp+32]
    cmp rbx,4
    jne .Lpfw_output_growth
    cmp r13,[r15+48]
    jbe .Lpfw_fatal
    cmp r13,I_MAX_WORK
    ja .Lpfw_fatal
.if PFIW_OBSERVE
    mov rdi,r15
    mov esi,1
    mov edx,6
    mov rcx,[r15+40]
    mov r8,[r15+48]
    call .Lpfw_journal
    test rax,rax
    jnz .Lpfw_fatal
.endif
    lea rdi,[r15+40]
    mov rsi,r13
    call .Lifa_grow
    test eax,eax
    jnz .Lpfw_fatal
.if PFIW_OBSERVE
    mov rdi,r15
    mov esi,1
    mov edx,7
    mov rcx,[r15+40]
    mov r8,[r15+48]
    call .Lpfw_journal
    test rax,rax
    jnz .Lpfw_fatal
.endif
    jmp .Lpfw_loop
.Lpfw_output_growth:
    cmp r13,[r15+32]
    jbe .Lpfw_fatal
    cmp r13,I_MAX_OUT
    ja .Lpfw_fatal
    lea rdi,[r15+24]
    mov rsi,r13
    call .Lifa_grow
    test eax,eax
    jnz .Lpfw_fatal
    jmp .Lpfw_loop
.Lpfw_final:
    mov rax,[r15+104]
    or rax,[r15+112]
    jnz .Lpfw_fatal
    mov rax,[rbp+24]
    or rax,[rbp+32]
    or rax,[rbp+40]
    or rax,[rbp+48]
    jnz .Lpfw_fatal
    lea rax,[rbp+64]
    mov [r15+216],rax
    mov rax,[rbp+56]
    mov [r15+224],rax
    mov qword ptr [r15+200],1
    mov qword ptr [r15+208],0
.if PFIW_OBSERVE
    mov rdi,r15
    mov esi,1
    mov edx,12
    mov rcx,r15
    mov r8d,4096
    call .Lpfw_journal
    test rax,rax
    jnz .Lpfw_fatal
    mov rdi,r15
    mov esi,1
    mov edx,13
    mov rcx,[r15+96]
    mov r8d,4096
    call .Lpfw_journal
    test rax,rax
    jnz .Lpfw_fatal
    mov r12,[r15+96]
    mov r12,[r12+32]
.Lpfw_orphan_journal:
    test r12,r12
    jz .Lpfw_orphan_journal_done
    mov rdi,r15
    mov esi,1
    mov edx,14
    mov rcx,r12
    mov r8d,4096
    call .Lpfw_journal
    test rax,rax
    jnz .Lpfw_fatal
    mov r12,[r12+16]
    jmp .Lpfw_orphan_journal
.Lpfw_orphan_journal_done:
.endif
    cmp qword ptr [rbp+8],0
    je .Lpfw_publish
    mov rax,[r15+216]
    mov [r15+232],rax
    mov rax,[r15+224]
    mov [r15+240],rax
    lea rdi,[r15+152]
    mov esi,4096
    call .Lifa_grow
    test eax,eax
    jnz .Lpfw_fatal
    lea rdi,[r15+168]
    mov esi,12288
    call .Lifa_grow
    test eax,eax
    jnz .Lpfw_fatal
.Lpfw_format:
.if PFIW_OBSERVE
    mov rdi,r15
    mov esi,3
    mov edx,1
    mov rcx,[r15+232]
    mov r8,[r15+240]
    call .Lpfw_journal
    test rax,rax
    jnz .Lpfw_fatal
    mov rdi,r15
    mov esi,3
    mov edx,2
    mov rcx,[r15+168]
    mov r8,[r15+176]
    call .Lpfw_journal
    test rax,rax
    jnz .Lpfw_fatal
    mov rdi,r15
    mov esi,3
    mov edx,3
    mov rcx,[r15+152]
    mov r8,[r15+160]
    call .Lpfw_journal
    test rax,rax
    jnz .Lpfw_fatal
.endif
    mov rdi,[r15+232]
    mov rsi,[r15+240]
    mov rdx,[r15+152]
    mov rcx,[r15+160]
    mov r8,[r15+168]
    mov r9,[r15+176]
    call .Lpfw_error
    mov [r15+136],rax
.if PFIW_OBSERVE
    mov rdi,r15
    mov esi,3
    mov edx,4
    mov rcx,[r15+152]
    mov r8,[r15+160]
    call .Lpfw_journal
    test rax,rax
    jnz .Lpfw_fatal
    mov rdi,r15
    mov esi,3
    mov edx,5
    mov rcx,[r15+168]
    mov r8,[r15+176]
    call .Lpfw_journal
    test rax,rax
    jnz .Lpfw_fatal
.endif
    mov rax,[r15+136]
    cmp eax,0xfffffffe
    je .Lpfw_format_growth
    test rax,rax
    jz .Lpfw_fatal
    cmp rax,[r15+160]
    ja .Lpfw_fatal
    mov [r15+224],rax
    mov rax,[r15+152]
    mov [r15+216],rax
    mov qword ptr [r15+200],2
    mov qword ptr [r15+208],1
    jmp .Lpfw_publish
.Lpfw_format_growth:
    mov rsi,[r15+160]
    cmp rsi,I_MAX_OUT
    jae .Lpfw_fatal
    add rsi,rsi
    lea rdi,[r15+152]
    call .Lifa_grow
    test eax,eax
    jnz .Lpfw_fatal
    jmp .Lpfw_format
.Lpfw_publish:
    mov rdi,[r15+88]
    call file_info_at_destroy
    test eax,eax
    jnz .Lpfw_fatal
    mov qword ptr [r15+88],0
    mov rdi,[r15+200]
    mov rsi,[r15+216]
    mov rdx,[r15+224]
    call .Lpfw_write
    test rax,rax
    jnz .Lpfw_fatal
    mov byte ptr [r15+280],10
    mov rdi,[r15+200]
    lea rsi,[r15+280]
    mov edx,1
    call .Lpfw_write
    test rax,rax
    jnz .Lpfw_fatal
    mov rdi,[r15+208]
    mov eax,60
    syscall
.Lpfw_fatal:
    mov edi,111
    mov eax,60
    syscall

/* Return the address of one live native-owned FD+1 token, or zero. */
.Lpfw_owned:
    cmp rdi,2147483647
    ja .Lpfw_owned_bad
    lea rax,[rdi+1]
    cmp [r15+104],rax
    je .Lpfw_owned_first
    cmp [r15+112],rax
    je .Lpfw_owned_second
.Lpfw_owned_bad:
    xor eax,eax
    ret
.Lpfw_owned_first:
    lea rax,[r15+104]
    ret
.Lpfw_owned_second:
    lea rax,[r15+112]
    ret

/* Fixed root open/openat/close/orphan/repeated failed close only. */
.Lpfw_effect:
    I_ENTER
    mov r13,rbp
    mov rax,[r13+40]
    or rax,[r13+48]
    jnz .Lpfw_effect_bad
    mov rbx,[r13+24]
    cmp rbx,1
    je .Lpfw_open_root
    cmp rbx,2
    je .Lpfw_open_component
    cmp rbx,3
    jb .Lpfw_effect_bad
    cmp rbx,5
    ja .Lpfw_effect_bad
    cmp qword ptr [r13+56],0
    jne .Lpfw_effect_bad
    cmp rbx,5
    je .Lpfw_repeat_close
    mov rdi,[r13+32]
    call .Lpfw_owned
    test rax,rax
    jz .Lpfw_effect_bad
    mov r12,rax
    cmp rbx,4
    je .Lpfw_orphan
.if PFIW_FAIL_CLOSE
    cmp qword ptr [r15+272],0
    jne .Lpfw_close
    mov rdi,[r13+32]
    call .Lpfw_fault_close
    test rax,rax
    jnz .Lpfw_effect_bad
    mov qword ptr [r15+272],1
.endif
.Lpfw_close:
    mov rdi,[r13+32]
    mov eax,3
    syscall
    mov [r15+184],rax
    mov qword ptr [r12],0
    mov qword ptr [r15+120],0
    cmp rax,-4095
    jb .Lpfw_effect_ok
    mov rax,[r13+32]
    inc rax
    mov [r15+120],rax
    jmp .Lpfw_effect_ok
.Lpfw_orphan:
    mov rdi,[r15+96]
    mov rsi,[r13+32]
    mov rdx,r15
    mov ecx,1
    call hia_process_orphans_append
    test rax,rax
    jnz .Lpfw_effect_bad
    mov qword ptr [r12],0
    jmp .Lpfw_effect_ok
.Lpfw_repeat_close:
    mov rdi,[r13+32]
    cmp rdi,2147483647
    ja .Lpfw_effect_bad
    lea rax,[rdi+1]
    cmp rax,[r15+120]
    jne .Lpfw_effect_bad
    mov qword ptr [r15+120],0
    mov eax,3
    syscall
    mov [r15+184],rax
    jmp .Lpfw_effect_ok
.Lpfw_open_root:
    mov rax,[r13+32]
    or rax,[r13+56]
    or rax,[r15+104]
    or rax,[r15+112]
    jnz .Lpfw_effect_bad
    mov rdi,-100
    lea rsi,[rip+.Lpfw_root]
    jmp .Lpfw_open
.Lpfw_open_component:
    mov rdi,[r13+32]
    call .Lpfw_owned
    test rax,rax
    jz .Lpfw_effect_bad
    mov rcx,[r13+56]
    cmp rcx,2
    jb .Lpfw_effect_bad
    lea rsi,[r13+64]
    xor edx,edx
.Lpfw_name:
    cmp rdx,rcx
    jae .Lpfw_effect_bad
    mov al,[rsi+rdx]
    inc rdx
    test al,al
    jz .Lpfw_name_end
    cmp al,47
    je .Lpfw_effect_bad
    jmp .Lpfw_name
.Lpfw_name_end:
    cmp rdx,rcx
    jne .Lpfw_effect_bad
    mov rdi,[r13+32]
.Lpfw_open:
    cmp qword ptr [r15+104],0
    je .Lpfw_open_slot_first
    cmp qword ptr [r15+112],0
    jne .Lpfw_effect_bad
    lea r12,[r15+112]
    jmp .Lpfw_open_actual
.Lpfw_open_slot_first:
    lea r12,[r15+104]
.Lpfw_open_actual:
    mov edx,720896 /* O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC; O_RDONLY=0 */
    xor r10d,r10d
    mov eax,257
    syscall
    mov [r15+184],rax
    cmp rax,-4095
    jae .Lpfw_effect_ok
    cmp rax,2147483647
    ja .Lpfw_effect_bad
    inc rax
    mov [r12],rax
.Lpfw_effect_ok:
    xor eax,eax
    jmp .Lpfw_effect_done
.Lpfw_effect_bad:
    mov eax,1
.Lpfw_effect_done:
    I_LEAVE
.Lpfw_root:
    .byte 47,0

.Lpfw_write:
    push rbx
    push r12
    push r13
    push r14
    mov rbx,rdi
    mov r12,rsi
    mov r13,rdx
    xor r14d,r14d
.Lpfw_write_loop:
    cmp r14,r13
    je .Lpfw_write_ok
    mov rdi,rbx
    lea rsi,[r12+r14]
    mov rdx,r13
    sub rdx,r14
    mov eax,1
    syscall
    cmp rax,-4
    je .Lpfw_write_loop
    cmp rax,-4095
    jae .Lpfw_write_done
    test rax,rax
    jz .Lpfw_write_zero
    add r14,rax
    jmp .Lpfw_write_loop
.Lpfw_write_zero:
    mov rax,-5
    jmp .Lpfw_write_done
.Lpfw_write_ok:
    xor eax,eax
.Lpfw_write_done:
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

.Lpfw_owner:
    .byte 0xe9
.global public_file_info_walk_body_call_displacement
public_file_info_walk_body_call_displacement:
    .long 0
.Lpfw_error:
    .byte 0xe9
.global public_file_info_walk_error_call_displacement
public_file_info_walk_error_call_displacement:
    .long 0

.if PFIW_OBSERVE
/* Original opaque child callback: only records, always returns actual I/O ACK. */
.Lpfw_child_journal:
    mov rdi,rsi
    mov esi,2
    jmp .Lpfw_journal

/* Full spans, including untouched capacities. No result substitution.
 * HFWLJR01: family, event, producer identity, reserved, reserved, extent, reserved. */
.Lpfw_journal:
    I_ENTER
    sub rsp,64
    mov r12,rdi
    mov r13,rcx
    mov r14,r8
    mov rax,0x3130524a4c574648 /* HFWLJR01 */
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
    call .Lpfw_write
    test rax,rax
    jnz .Lpfw_journal_done
    mov edi,3
    mov rsi,r13
    mov rdx,r14
    call .Lpfw_write
.Lpfw_journal_done:
    add rsp,64
    I_LEAVE
.endif

.if PFIW_FAIL_CLOSE
/* Fixture only: install actual kernel EIO for close of this exact runtime FD.
 * The real syscall executes and is refused by seccomp; no reply bytes are forged. */
.Lpfw_fault_close:
    I_ENTER
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
    jnz .Lpfw_fault_done
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
.Lpfw_fault_done:
    add rsp,80
    I_LEAVE
.endif
.section .note.GNU-stack,"",@progbits
