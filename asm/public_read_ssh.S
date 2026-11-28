/* Copyright 2026 Muvon Un Limited
 * Copyright 2026 TrillionniumFoundation
 * SPDX-License-Identifier: Apache-2.0
 * Fixed Linux storage boundary for the HIA-configured public read transport.
 * Command, bootstrap, packet, deadline/cancellation and result decisions are
 * HIA-owned. This boundary copies owned spans and calls the fixed SSH actor.
 * RS_* library constants are generated from the admitted complete ELF.
 */
.intel_syntax noprefix
.section .text
.macro RSH_SAVE
    push rbp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub rsp,8
.endm
.macro RSH_RETURN
    add rsp,8
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret
.endm

/* rdi=pointer/capacity pair, rsi=required bytes. Both mappings have a guard. */
rsh_grow:
    RSH_SAVE
    mov r12,rdi
    cmp rsi,[r12+8]
    jbe .Lrsh_grow_ok
    mov r13,rsi
    add r13,4095
    jc .Lrsh_grow_overflow
    and r13,-4096
    test r13,r13
    jle .Lrsh_grow_overflow
    mov rdi,[r12]
    test rdi,rdi
    jz .Lrsh_grow_first
    mov rsi,[r12+8]
    mov rdx,r13
    call view_resize
    jmp .Lrsh_grow_observe
.Lrsh_grow_first:
    mov rdi,r13
    call view_allocate
.Lrsh_grow_observe:
    cmp rax,-4095
    jae .Lrsh_grow_done
    mov [r12],rax
    mov [r12+8],r13
.Lrsh_grow_ok:
    xor eax,eax
    jmp .Lrsh_grow_done
.Lrsh_grow_overflow:
    mov rax,-75
.Lrsh_grow_done:
    RSH_RETURN

/* rdi=owned pair. Failed release preserves the descriptor. */
rsh_unmap:
    RSH_SAVE
    mov r12,rdi
    mov rdi,[r12]
    test rdi,rdi
    jz .Lrsh_unmap_ok
    mov rsi,[r12+8]
    add rsi,4096
    jc .Lrsh_unmap_bad
    mov eax,11
    syscall
    test rax,rax
    jnz .Lrsh_unmap_done
    mov qword ptr [r12],0
    mov qword ptr [r12+8],0
.Lrsh_unmap_ok:
    xor eax,eax
    jmp .Lrsh_unmap_done
.Lrsh_unmap_bad:
    mov rax,-75
.Lrsh_unmap_done:
    RSH_RETURN

/* envp, fixed complete ELF, bootstrap HIA, wire HIA, fixed helper bundle.
 * Library BSS and the actor's join-worker context remain process-owned. */
.global runtime_read_hub_create
runtime_read_hub_create:
    RSH_SAVE
    mov rbp,rdi
    mov r12,rsi
    mov r13,rdx
    mov r14,rcx
    mov r15,r8
    mov edi,4096
    call view_allocate
    cmp rax,-4095
    jae .Lrsh_hub_return
    mov rbx,rax
    mov rax,0x3142554848535248 /* HRSHHUB1 */
    mov [rbx],rax
    mov [rbx+32],rbp
    mov [rbx+40],r15
    mov [rbx+48],r13
    mov [rbx+56],r14
    mov eax,39
    syscall
    mov [rbx+72],rax
    /* Preserve every original environment byte, including non-UTF-8. */
    xor r13d,r13d
    xor r14d,r14d
.Lrsh_env_size:
    mov rdi,[rbp+r14*8]
    test rdi,rdi
    jz .Lrsh_env_allocate
    xor ecx,ecx
.Lrsh_env_length:
    cmp byte ptr [rdi+rcx],0
    je .Lrsh_env_add
    inc rcx
    jnz .Lrsh_env_length
    jmp .Lrsh_hub_overflow
.Lrsh_env_add:
    add r13,rcx
    jc .Lrsh_hub_overflow
    add r13,9
    jc .Lrsh_hub_overflow
    inc r14
    jmp .Lrsh_env_size
.Lrsh_env_allocate:
    mov [rbx+112],r13
    mov [rbx+120],r14
    lea rdi,[rbx+96]
    mov rsi,r13
    inc rsi
    jc .Lrsh_hub_overflow
    call rsh_grow
    test rax,rax
    jnz .Lrsh_hub_return
    mov rdi,[rbx+96]
    xor r14d,r14d
.Lrsh_env_copy:
    mov rsi,[rbp+r14*8]
    test rsi,rsi
    jz .Lrsh_hub_map
    xor ecx,ecx
.Lrsh_env_copy_length:
    cmp byte ptr [rsi+rcx],0
    je .Lrsh_env_record
    inc rcx
    jmp .Lrsh_env_copy_length
.Lrsh_env_record:
    mov [rdi],rcx
    add rdi,8
    inc rcx
    cld
    rep movsb
    inc r14
    jmp .Lrsh_env_copy

.Lrsh_hub_map:
    mov edi,RS_LIBRARY_MEMORY
    call view_allocate
    cmp rax,-4095
    jae .Lrsh_hub_return
    mov r13,rax
    mov [rbx+8],rax
    mov qword ptr [rbx+16],RS_LIBRARY_MEMORY
    /* Trusted ELF LOADs are source/identity-bound by the builder. */
    xor r14d,r14d
    mov r15,[r12+32]
    add r15,r12
.Lrsh_map_segments:
    cmp r14w,[r12+56]
    jae .Lrsh_map_protect
    cmp dword ptr [r15],1
    jne .Lrsh_map_next
    mov rdi,[r15+16]
    sub rdi,RS_LIBRARY_ORIGIN
    add rdi,r13
    mov rsi,[r15+8]
    add rsi,r12
    mov rcx,[r15+32]
    cld
    rep movsb
.Lrsh_map_next:
    add r15,56
    inc r14
    jmp .Lrsh_map_segments
.Lrsh_map_protect:
    mov rdi,r13
    mov esi,RS_LIBRARY_MEMORY
    xor edx,edx
    mov eax,10
    syscall
    test rax,rax
    jnz .Lrsh_hub_return
    xor r14d,r14d
    mov r15,[r12+32]
    add r15,r12
.Lrsh_protect_segment:
    cmp r14w,[r12+56]
    jae .Lrsh_hub_start
    cmp dword ptr [r15],1
    jne .Lrsh_protect_next
    mov rdi,[r15+16]
    sub rdi,RS_LIBRARY_ORIGIN
    mov rsi,rdi
    add rsi,[r15+40]
    add rsi,4095
    and rsi,-4096
    and rdi,-4096
    sub rsi,rdi
    add rdi,r13
    mov edx,[r15+4]
    mov ecx,edx
    and edx,4
    shr edx,2
    and ecx,3
    test ecx,1
    jz .Lrsh_protect_no_exec
    or edx,4
.Lrsh_protect_no_exec:
    and ecx,2
    or edx,ecx
    mov eax,10
    syscall
    test rax,rax
    jnz .Lrsh_hub_return
.Lrsh_protect_next:
    add r15,56
    inc r14
    jmp .Lrsh_protect_segment
.Lrsh_hub_start:
    xor edi,edi
    xor esi,esi
    lea rax,[r13+RS_START]
    call rax
    test rax,rax
    js .Lrsh_hub_return
    mov [rbx+24],rax
    mov rax,rbx
    jmp .Lrsh_hub_return
.Lrsh_hub_overflow:
    mov rax,-75
.Lrsh_hub_return:
    RSH_RETURN

/* Reset one request-owned context after the parent's output loan has ended.
 * No reset can cancel or wait on a different request or a selected OS PID. */
.global runtime_read_request_reset
runtime_read_request_reset:
    RSH_SAVE
    mov r12,rdi
    mov rdi,[r12+24]
    test rdi,rdi
    jz .Lrsh_reset_mappings
    mov rax,[r12+16]
    mov rax,[rax+8]
    add rax,RS_RELEASE
    call rax
    mov qword ptr [r12+24],0
.Lrsh_reset_mappings:
    xor ebx,ebx
    lea r13,[rip+.Lrsh_pairs]
.Lrsh_reset_pair:
    movzx eax,byte ptr [r13+rbx]
    lea rdi,[r12+rax]
    call rsh_unmap
    test rax,rax
    jnz .Lrsh_reset_return
    inc ebx
    cmp ebx,7
    jb .Lrsh_reset_pair
    mov rdi,r12
    mov ecx,512
    xor eax,eax
    rep stosq
.Lrsh_reset_return:
    RSH_RETURN
.Lrsh_pairs:
    .byte 64,88,104,120,160,184,224

/* rdi=request-owned 4096-byte zeroed context, rsi=shared hub,
 * rdx=complete borrowed HRSSQ001 request, rcx=extent.
 * Result 0 means an original future now exists; poll observes that same one. */
.global runtime_read_request_start
runtime_read_request_start:
    RSH_SAVE
    mov r12,rdi
    mov r13,rsi
    mov r14,rdx
    mov r15,rcx
    cmp r15,64
    jb .Lrsh_start_invalid
    mov rax,0x3130305153535248
    cmp [r14],rax
    jne .Lrsh_start_invalid
    cmp qword ptr [r12],0
    jne .Lrsh_start_invalid
    mov rax,0x3154534853535248 /* HRSSHST1 */
    mov [r12],rax
    mov [r12+16],r13
    mov [r12+48],r14
    mov [r12+56],r15
    mov edi,1
    lea rsi,[r12+576]
    mov eax,228
    syscall
    test rax,rax
    jnz .Lrsh_start_return
    mov rax,[r12+576]
    mov ecx,1000000000
    mul rcx
    add rax,[r12+584]
    adc rdx,0
    jc .Lrsh_start_overflow
    mov rcx,30000000000
    add rax,rcx
    adc rdx,0
    jc .Lrsh_start_overflow
    mov [r12+32],rax
    mov [r12+40],rdx
    mov [r12+336],rax
    mov [r12+344],rdx
    /* Fixed helper images are never selected by a path or executable string. */
    mov rbx,[r13+40]
    mov rax,[r14+8]
    cmp rax,1
    jb .Lrsh_start_invalid
    cmp rax,3
    ja .Lrsh_start_invalid
    lea rdi,[rbx+64]
    mov edx,1
.Lrsh_helper_select:
    cmp rdx,rax
    je .Lrsh_helper_selected
    add rdi,[rbx+rdx*8]
    inc rdx
    jmp .Lrsh_helper_select
.Lrsh_helper_selected:
    mov rcx,[rbx+rax*8]
    test rcx,rcx
    jz .Lrsh_start_missing
    mov [r12+200],rdi
    mov [r12+208],rcx
    mov rax,0x3130305142535348 /* HSSBQ001 */
    mov [r12+512],rax
    mov [r12+520],rcx
    lea rdi,[r12+160]
    mov esi,4096
    call rsh_grow
    test rax,rax
    jnz .Lrsh_start_return
    lea rdi,[r12+184]
    mov esi,4096
    call rsh_grow
    test rax,rax
    jnz .Lrsh_start_return
    lea rdi,[r12+512]
    mov esi,64
    mov rdx,[r12+160]
    mov rcx,[r12+168]
    mov r8,[r12+184]
    mov r9,[r12+192]
    call qword ptr [r13+48]
    cmp rax,64
    jb .Lrsh_start_invalid
    cmp rax,[r12+168]
    ja .Lrsh_start_invalid
    mov [r12+176],rax
    add rax,r15
    jc .Lrsh_start_overflow
    add rax,[r13+112]
    jc .Lrsh_start_overflow
    add rax,64
    jc .Lrsh_start_overflow
    mov [r12+80],rax
    lea rdi,[r12+64]
    mov rsi,rax
    call rsh_grow
    test rax,rax
    jnz .Lrsh_start_return
    mov rbx,[r12+64]
    mov rax,0x3130305152575248 /* HRWRQ001 */
    mov [rbx],rax
    mov rax,[r14+8]
    mov [rbx+8],rax
    mov [rbx+16],r15
    mov rax,[r12+176]
    mov [rbx+24],rax
    mov rax,[r13+112]
    mov [rbx+32],rax
    mov rax,[r13+120]
    mov [rbx+40],rax
    mov rax,[r12+208]
    mov [rbx+48],rax
    lea rdi,[rbx+64]
    mov rsi,r14
    mov rcx,r15
    cld
    rep movsb
    mov rsi,[r12+160]
    mov rcx,[r12+176]
    rep movsb
    mov rsi,[r13+96]
    mov rcx,[r13+112]
    rep movsb
    lea rdi,[r12+88]
    mov esi,4096
    call rsh_grow
    test rax,rax
    jnz .Lrsh_start_return
    lea rdi,[r12+104]
    mov esi,4096
    call rsh_grow
    test rax,rax
    jnz .Lrsh_start_return
.Lrsh_wire_call:
    mov rdi,[r12+64]
    mov rsi,[r12+80]
    mov rdx,[r12+88]
    mov rcx,[r12+96]
    mov r8,[r12+104]
    mov r9,[r12+112]
    call qword ptr [r13+56]
    cmp eax,0xffffffd0
    je .Lrsh_wire_grow
    cmp rax,64
    jne .Lrsh_start_invalid
    mov rbx,[r12+88]
    mov rax,0x3130305252575248 /* HRWRR001 */
    cmp [rbx],rax
    jne .Lrsh_start_invalid
    cmp qword ptr [rbx+8],1
    je .Lrsh_wire_early_error
    cmp qword ptr [rbx+8],0
    jne .Lrsh_start_invalid
    mov rax,[rbx+16]
    mov [r12+144],rax
    add rax,[rbx+24]
    jc .Lrsh_start_invalid
    add rax,64
    jc .Lrsh_start_invalid
    cmp rax,[r12+96]
    ja .Lrsh_start_invalid
    mov rax,[rbx+24]
    mov [r12+152],rax
    add rax,[r12+208]
    jc .Lrsh_start_overflow
    mov [r12+136],rax
    lea rdi,[r12+120]
    mov rsi,rax
    call rsh_grow
    test rax,rax
    jnz .Lrsh_start_return
    mov rdi,[r12+120]
    mov rsi,[r12+200]
    mov rcx,[r12+208]
    cld
    rep movsb
    mov rsi,[r12+88]
    add rsi,64
    add rsi,[r12+144]
    mov rcx,[r12+152]
    rep movsb
    mov rdi,[r13+24]
    mov rsi,[r12+88]
    add rsi,64
    mov rdx,[r12+144]
    mov rcx,[r12+120]
    mov r8,[r12+136]
    lea r9,[r12+336]
    mov rax,[r13+8]
    add rax,RS_SUBMIT
    call rax
    test rax,rax
    js .Lrsh_start_return
    mov [r12+24],rax
    mov qword ptr [r12+8],1
    xor eax,eax
    jmp .Lrsh_start_return
.Lrsh_wire_grow:
    mov rbx,[r12+88]
    mov rax,0x3230305357524748
    cmp [rbx],rax
    jne .Lrsh_start_invalid
    mov rax,[rbx+8]
    lea rdi,[r12+104]
    cmp rax,1
    je .Lrsh_wire_resize
    lea rdi,[r12+88]
    cmp rax,2
    jne .Lrsh_start_overflow
.Lrsh_wire_resize:
    mov rsi,[rbx+16]
    cmp rsi,[rdi+8]
    jbe .Lrsh_start_invalid
    call rsh_grow
    test rax,rax
    jnz .Lrsh_start_return
    jmp .Lrsh_wire_call
.Lrsh_wire_early_error:
    mov rax,0x3130534552535348 /* HSSRES01 */
    mov [r12+240],rax
    mov qword ptr [r12+248],96
    mov qword ptr [r12+256],1
    mov rax,[rbx+16]
    mov [r12+264],rax
    mov rax,[rbx+24]
    mov [r12+272],rax
    mov qword ptr [r12+8],1
    mov qword ptr [r12+440],1
    xor eax,eax
    jmp .Lrsh_start_return
.Lrsh_start_overflow:
    mov rax,-75
    jmp .Lrsh_start_return
.Lrsh_start_missing:
    mov rax,-38
    jmp .Lrsh_start_return
.Lrsh_start_invalid:
    mov rax,-22
.Lrsh_start_return:
    RSH_RETURN

/* 1 pending; 0 complete with owned HRSCAP01 at context+224/+232.
 * The library's original caller future determines all cancellation/timeout. */
.global runtime_read_request_poll
runtime_read_request_poll:
    RSH_SAVE
    mov r12,rdi
    cmp qword ptr [r12+8],2
    je .Lrsh_poll_complete
    cmp qword ptr [r12+8],1
    jne .Lrsh_poll_invalid
    cmp qword ptr [r12+440],1
    je .Lrsh_poll_capture
    mov rdi,[r12+24]
    test rdi,rdi
    jz .Lrsh_poll_invalid
    lea rsi,[r12+240]
    mov rax,[r12+16]
    mov rax,[rax+8]
    add rax,RS_CAPTURE
    call rax
    test rax,rax
    jnz .Lrsh_poll_return
    mov qword ptr [r12+440],1
.Lrsh_poll_capture:
    lea r13,[r12+240]
    mov rax,0x3130534552535348
    cmp [r13],rax
    jne .Lrsh_poll_invalid
    cmp qword ptr [r13+8],96
    jne .Lrsh_poll_invalid
    cmp qword ptr [r13+16],1
    ja .Lrsh_poll_invalid
    cmp qword ptr [r13+56],8388608
    ja .Lrsh_poll_invalid
    cmp qword ptr [r13+72],8388608
    ja .Lrsh_poll_invalid
    mov r14,[r13+56]
    add r14,[r13+72]
    add r14,128
    lea rdi,[r12+224]
    mov rsi,r14
    call rsh_grow
    test rax,rax
    jnz .Lrsh_poll_return
    mov rbx,[r12+224]
    mov rdi,rbx
    xor eax,eax
    mov ecx,16
    cld
    rep stosq
    mov rax,0x3130504143535248 /* HRSCAP01 */
    mov [rbx],rax
    mov rax,[r13+16]
    mov [rbx+8],rax
    mov rax,[r13+24]
    mov [rbx+16],rax
    mov rax,[r13+32]
    mov [rbx+24],rax
    mov rax,[r13+40]
    mov [rbx+32],rax
    mov rax,[r13+56]
    mov [rbx+40],rax
    mov rax,[r13+72]
    mov [rbx+48],rax
    mov rax,[r13+80]
    mov [rbx+56],rax
    lea rdi,[rbx+128]
    mov rsi,[r13+48]
    mov rcx,[r13+56]
    rep movsb
    mov rsi,[r13+64]
    mov rcx,[r13+72]
    rep movsb
    mov [r12+448],r14
    mov qword ptr [r12+8],2
    mov rdi,[r12+24]
    test rdi,rdi
    jz .Lrsh_poll_complete
    mov rax,[r12+16]
    mov rax,[rax+8]
    add rax,RS_RELEASE
    call rax
    mov qword ptr [r12+24],0
.Lrsh_poll_complete:
    xor eax,eax
    jmp .Lrsh_poll_return
.Lrsh_poll_invalid:
    mov rax,-22
.Lrsh_poll_return:
    RSH_RETURN

/* Original global freeze/join. A pending receipt belongs to this same actor. */
.global runtime_read_hub_shutdown
runtime_read_hub_shutdown:
    RSH_SAVE
    mov r12,rdi
    cmp qword ptr [r12+64],0
    jne .Lrsh_hub_join
    mov qword ptr [r12+64],1
    mov rdi,[r12+24]
    mov rax,[r12+8]
    add rax,RS_SHUTDOWN
    call rax
    jmp .Lrsh_shutdown_return
.Lrsh_hub_join:
    mov rdi,[r12+24]
    mov rax,[r12+8]
    add rax,RS_JOIN
    call rax
.Lrsh_shutdown_return:
    RSH_RETURN

/* Destruction releases exactly this caller reference. The original actor owns
 * any in-flight reap; no alternate PID or wait operation is introduced. */
.global runtime_read_request_drop
runtime_read_request_drop:
    RSH_SAVE
    mov r12,rdi
    cmp qword ptr [r12+8],1
    je .Lrsh_drop_admitted
    cmp qword ptr [r12+8],2
    jne .Lrsh_drop_invalid
.Lrsh_drop_admitted:
    mov rdi,[r12+24]
    test rdi,rdi
    jz .Lrsh_drop_complete
    mov rax,[r12+16]
    mov rax,[rax+8]
    add rax,RS_RELEASE
    call rax
    test rax,rax
    jnz .Lrsh_drop_done
    mov qword ptr [r12+24],0
.Lrsh_drop_complete:
    mov qword ptr [r12+8],3
    xor eax,eax
    jmp .Lrsh_drop_done
.Lrsh_drop_invalid:
    mov rax,-22
.Lrsh_drop_done:
    RSH_RETURN
