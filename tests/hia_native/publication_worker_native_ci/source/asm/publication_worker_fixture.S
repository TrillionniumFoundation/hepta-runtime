/* Copyright 2026 Muvon Un Limited
 * SPDX-License-Identifier: Apache-2.0
 * Private binary observer for the fixed publication executor. FD3 is an owned
 * journal. No public request can choose an address, syscall, image or descriptor.
 * EOF requires explicit complete pool destruction; it does not invent a Drop.
 */
.intel_syntax noprefix
.section .text
.global _start
.type _start,@function
_start:
    and rsp,-16
    cld
    mov edi,3
    mov esi,1
    xor edx,edx
    mov eax,72
    syscall
    test rax,rax
    js pf_fatal_early
    mov edi,4096
    call .Lptp_map
    cmp rax,-4095
    jae pf_fatal_early
    mov r15,rax
pf_loop:
    xor edi,edi
    lea rsi,[r15+120]
    mov edx,8
    call .Lpf_read_exact
    test rax,rax
    jz pf_eof
    cmp rax,8
    jne pf_fatal
    mov r14,[r15+120]
    cmp r14,64
    jb pf_fatal
    cmp r14,50331776
    ja pf_fatal
    lea rdi,[r15+8]
    mov rsi,r14
    call .Lptp_grow
    test eax,eax
    jnz pf_fatal
    xor edi,edi
    mov rsi,[r15+8]
    mov rdx,r14
    call .Lpf_read_exact
    cmp rax,r14
    jne pf_fatal
    mov rbp,[r15+8]
    mov rax,0x3130514657545048 /* HPTWFQ01 */
    cmp [rbp],rax
    jne pf_fatal
    cmp qword ptr [rbp+56],0
    jne pf_fatal
    mov rax,[rbp+8]
    cmp rax,17
    ja pf_fatal
    mov [r15+32],rax
    mov rcx,[rbp+16]
    mov [r15+40],rcx
    mov rcx,[rbp+24]
    mov [r15+48],rcx
    mov rcx,[rbp+40]
    mov [r15+56],rcx
    mov rcx,[rbp+48]
    mov [r15+64],rcx
    sub r14,64
    cmp [rbp+32],r14
    jne pf_fatal
    mov [r15+24],r14
    cmp rax,1
    je pf_submit_header
    test r14,r14
    jnz pf_fatal
    cmp qword ptr [r15+48],0
    jne pf_fatal
    cmp rax,0
    je pf_create_header
    cmp qword ptr [r15+56],0
    jne pf_fatal
    cmp qword ptr [r15+64],0
    jne pf_fatal
    cmp rax,3
    je pf_job_header
    cmp rax,4
    je pf_job_header
    cmp rax,5
    je pf_job_header
    cmp rax,6
    je pf_job_header
    cmp rax,12
    jae pf_job_header
    cmp qword ptr [r15+40],0
    jne pf_fatal
    jmp pf_header_ready
pf_submit_header:
    cmp qword ptr [r15+40],0
    jne pf_fatal
    cmp qword ptr [r15+48],0
    je pf_fatal
    mov rcx,[r15+56]
    or rcx,[r15+64]
    jnz pf_fatal
    jmp pf_header_ready
pf_create_header:
    cmp qword ptr [r15+40],0
    jne pf_fatal
    cmp qword ptr [r15+56],0
    je pf_fatal
    cmp qword ptr [r15+64],1
    ja pf_fatal
    jmp pf_header_ready
pf_job_header:
    cmp qword ptr [r15+40],0
    je pf_fatal
pf_header_ready:
    inc qword ptr [r15+600]
    jz pf_fatal
    mov qword ptr [r15+72],0
    mov qword ptr [r15+80],0
    mov qword ptr [r15+88],0
    mov qword ptr [r15+96],0
    mov qword ptr [r15+104],0
    mov qword ptr [r15+112],0
    lea rdi,[r15+192]
    mov ecx,48
    xor eax,eax
    rep stosq
    mov rax,[r15+32]
    test rax,rax
    jz pf_create
    cmp qword ptr [r15],0
    je pf_invalid
    cmp rax,1
    je pf_submit
    cmp rax,2
    je pf_service
    cmp rax,3
    je pf_poll
    cmp rax,4
    je pf_take
    cmp rax,5
    je pf_release
    cmp rax,6
    je pf_drop
    cmp rax,7
    je pf_close
    cmp rax,8
    je pf_destroy
    cmp rax,9
    je pf_observe
    cmp rax,11
    jbe pf_pool_snapshot
    jmp pf_task_snapshot
pf_create:
    cmp qword ptr [r15],0
    jne pf_busy
    mov rdi,[r15+56]
    lea rsi,[rip+pf_journal]
    mov edx,3
    cmp qword ptr [r15+64],0
    je pf_create_go
    xor esi,esi
    xor edx,edx
pf_create_go:
    call publication_worker_create
    cmp rax,-4095
    jae pf_raw
    mov [r15],rax
    xor eax,eax
    jmp pf_raw
pf_submit:
    mov rdi,[r15]
    lea rsi,[rbp+64]
    mov rdx,[r15+24]
    mov rcx,[r15+48]
    lea r8,[r15+192]
    call publication_worker_submit
    jmp pf_pool_result
pf_service:
    mov rdi,[r15]
    call publication_worker_service
    jmp pf_raw
pf_poll:
    mov rdi,[r15]
    mov rsi,[r15+40]
    lea rdx,[r15+192]
    call publication_worker_poll
    jmp pf_pool_result
pf_take:
    mov rdi,[r15]
    mov rsi,[r15+40]
    lea rdx,[r15+192]
    lea rcx,[r15+512]
    call publication_worker_take
    cmp eax,320
    jne pf_raw
    cmp qword ptr [r15+208],0
    jne pf_pool_result
    cmp qword ptr [r15+520],64
    jne pf_fatal
    mov rcx,[r15+552]
    cmp rcx,134217728
    ja pf_fatal
    mov [r15+104],rcx
    mov rdx,[r15+544]
    mov [r15+96],rdx
    test rcx,rcx
    jz pf_take_empty
    test rdx,rdx
    jz pf_fatal
pf_take_empty:
    mov qword ptr [r15+112],1
pf_pool_result:
    mov edx,eax
    cmp rax,rdx
    jne pf_fatal
    mov [r15+72],rax
    cmp eax,320
    jne pf_reply
    lea rax,[r15+192]
    mov [r15+80],rax
    mov qword ptr [r15+88],320
    cmp qword ptr [r15+112],1
    jne pf_reply
    mov qword ptr [r15+88],384
    jmp pf_reply
pf_release:
    mov rdi,[r15]
    mov rsi,[r15+40]
    call publication_worker_release
    jmp pf_raw
pf_drop:
    mov rdi,[r15]
    mov rsi,[r15+40]
    call publication_worker_drop
    jmp pf_raw
pf_close:
    mov rdi,[r15]
    call publication_worker_close
    jmp pf_raw
pf_destroy:
    mov rdi,[r15]
    call publication_worker_destroy
    test eax,eax
    jnz pf_raw
    mov qword ptr [r15],0
    jmp pf_raw
pf_observe:
    mov rdi,[r15]
    lea rsi,[r15+192]
    call publication_worker_observe
    jmp pf_pool_result
pf_pool_snapshot:
    mov rbx,r15
    mov r15,[rbx]
    lea rdi,[r15+16]
    call pw_mutex_lock
    mov r13,r15
    mov r14d,4096
    cmp qword ptr [rbx+32],10
    je pf_pool_snapshot_copy
    mov r13,[r15+32]
    mov r14,[r15+40]
pf_pool_snapshot_copy:
    lea rdi,[rbx+576]
    mov rsi,r14
    call .Lptp_grow
    test eax,eax
    jnz pf_fatal_pool
    mov rdi,[rbx+576]
    mov rsi,r13
    mov rcx,r14
    rep movsb
    lea rdi,[r15+16]
    call pw_mutex_unlock
    mov r15,rbx
    mov rax,[r15+576]
    mov [r15+80],rax
    mov [r15+88],r14
    xor eax,eax
    jmp pf_raw
pf_task_snapshot:
    mov rbx,r15
    mov r15,[rbx]
    mov rsi,[rbx+40]
    call pw_find_task
    mov r15,rbx
    test rax,rax
    jz pf_invalid
    cmp qword ptr [rax+80],0
    je pf_task_quiescent
    cmp qword ptr [rax+96],1
    jne pf_busy
pf_task_quiescent:
    mov r13,rax
    mov r14d,4096
    mov rdx,[r15+32]
    cmp rdx,12
    je pf_task_copy
    cmp rdx,17
    je pf_task_input
    mov r13,[rax+40]
    test r13,r13
    jz pf_invalid
    cmp rdx,13
    je pf_task_copy
    cmp rdx,14
    je pf_task_workspace
    cmp rdx,15
    je pf_task_output
    cmp rdx,16
    jne pf_fatal
    mov r14,[r13+72]
    mov r13,[r13+64]
    jmp pf_task_copy
pf_task_workspace:
    mov r14,[r13+96]
    mov r13,[r13+88]
    jmp pf_task_copy
pf_task_output:
    mov r14,[r13+112]
    mov r13,[r13+104]
    jmp pf_task_copy
pf_task_input:
    mov r14,[r13+56]
    mov r13,[r13+48]
pf_task_copy:
    test r14,r14
    jz pf_task_empty
    test r13,r13
    jz pf_fatal
    lea rdi,[r15+576]
    mov rsi,r14
    call .Lptp_grow
    test eax,eax
    jnz pf_fatal
    mov rdi,[r15+576]
    mov rsi,r13
    mov rcx,r14
    rep movsb
    mov rax,[r15+576]
    mov [r15+80],rax
pf_task_empty:
    mov [r15+88],r14
    xor eax,eax
    jmp pf_raw
pf_busy:
    mov eax,0xfffffffd
    jmp pf_raw
pf_invalid:
    mov eax,0xffffffff
pf_raw:
    mov [r15+72],rax
pf_reply:
    lea rdi,[r15+128]
    xor eax,eax
    mov ecx,8
    rep stosq
    mov rax,0x3130524657545048 /* HPTWFR01 */
    mov [r15+128],rax
    mov rax,[r15+72]
    mov [r15+136],rax
    mov rax,[r15+88]
    add rax,[r15+104]
    jc pf_fatal
    mov [r15+144],rax
    mov rax,[r15+32]
    mov [r15+152],rax
    mov rax,[r15+40]
    mov [r15+160],rax
    mov rax,[r15]
    mov [r15+168],rax
    mov rax,[r15+600]
    mov [r15+176],rax
    mov edi,1
    lea rsi,[r15+128]
    mov edx,64
    call .Lpf_write_all
    test rax,rax
    jnz pf_fatal
    mov edi,1
    mov rsi,[r15+80]
    mov rdx,[r15+88]
    call .Lpf_write_all
    test rax,rax
    jnz pf_fatal
    mov edi,1
    mov rsi,[r15+96]
    mov rdx,[r15+104]
    call .Lpf_write_all
    test rax,rax
    jnz pf_fatal
    jmp pf_loop
pf_eof:
    cmp qword ptr [r15],0
    jne pf_fatal
    mov rdi,[r15+8]
    test rdi,rdi
    jz pf_eof_snapshot
    mov rsi,[r15+16]
    add rsi,4096
    mov eax,11
    syscall
    test rax,rax
    jnz pf_fatal
pf_eof_snapshot:
    mov rdi,[r15+576]
    test rdi,rdi
    jz pf_eof_control
    mov rsi,[r15+584]
    add rsi,4096
    mov eax,11
    syscall
    test rax,rax
    jnz pf_fatal
pf_eof_control:
    mov rdi,r15
    mov esi,8192
    mov eax,11
    syscall
    test rax,rax
    jnz pf_fatal_early
    xor edi,edi
    mov eax,60
    syscall
    ud2
pf_fatal:
    mov rax,[r15]
    test rax,rax
    jz pf_fatal_early
    mov r15,rax
pf_fatal_pool:
    jmp pw_fatal
pf_fatal_early:
    mov edi,111
    mov eax,60
    syscall
    ud2

/* Immutable callback observes full spans under the actual pool journal lock.
 * Header64: magic,event,sequence,extent,pool_address,creator_pid,callback_pid,0. */
pf_journal:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp,72
    mov rbx,rdi
    mov r12,rsi
    mov r13,rdx
    mov r14,rcx
    mov r15,r8
    mov rdi,rsp
    xor eax,eax
    mov ecx,8
    rep stosq
    mov rax,0x3130524a57545048 /* HPTWJR01 */
    mov [rsp],rax
    mov [rsp+8],r13
    mov rax,[r12+96]
    mov [rsp+16],rax
    mov [rsp+24],r15
    mov [rsp+32],r12
    mov rax,[r12+8]
    mov [rsp+40],rax
    mov eax,39
    syscall
    mov [rsp+48],rax
    mov rdi,rbx
    mov rsi,rsp
    mov edx,64
    call .Lpf_write_all
    test rax,rax
    jnz pf_journal_done
    mov rdi,rbx
    mov rsi,r14
    mov rdx,r15
    call .Lpf_write_all
pf_journal_done:
    add rsp,72
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

.Lpf_read_exact:
    push rbx
    push r12
    push r13
    push r14
    mov rbx, rdi
    mov r12, rsi
    mov r13, rdx
    xor r14d, r14d
.Lpf_read_loop:
    mov rdi, rbx
    lea rsi, [r12+r14]
    mov rdx, r13
    sub rdx, r14
    xor eax, eax
    syscall
    test rax, rax
    jz .Lpf_read_eof
    cmp rax, -4
    je .Lpf_read_loop
    cmp rax, -4095
    jae .Lpf_read_done
    add r14, rax
    cmp r14, r13
    jb .Lpf_read_loop
    mov rax, r13
    jmp .Lpf_read_done
.Lpf_read_eof:
    xor eax, eax
    test r14, r14
    jz .Lpf_read_done
    mov rax, -22
.Lpf_read_done:
    pop r14
    pop r13
    pop r12
    pop rbx
    ret
.Lpf_write_all:
    push rbx
    push r12
    push r13
    push r14
    mov rbx, rdi
    mov r12, rsi
    mov r13, rdx
    xor r14d, r14d
.Lpf_write_loop:
    cmp r14, r13
    je .Lpf_write_success
    mov rdi, rbx
    lea rsi, [r12+r14]
    mov rdx, r13
    sub rdx, r14
    mov eax, 1
    syscall
    cmp rax, -4
    je .Lpf_write_loop
    test rax, rax
    jz .Lpf_write_zero
    cmp rax, -4095
    jae .Lpf_write_done
    add r14, rax
    jmp .Lpf_write_loop
.Lpf_write_zero:
    mov rax, -5
    jmp .Lpf_write_done
.Lpf_write_success:
    xor eax, eax
.Lpf_write_done:
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

