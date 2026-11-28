/* The default foreground file transport uses one process-owned SSH root.
 * Its three fixed syscall capabilities are emitted by captured HIA images.
 * This installer only captures the fixed external OpenSSH executable, checks
 * its held inode before/after copying, seals the bytes, and owns RX mappings.
 * All calls are serialized by the process event-loop owner. */
.intel_syntax noprefix
.section .text
.global runtime_ssh_install_ensure
.global runtime_ssh_install_destroy
.macro RSI_SAVE
    push rbp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub rsp,536
.endm
.macro RSI_RETURN
    add rsp,536
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret
.endm

/* r15 actual engine. Return root or negative errno. Hub is shared by every
 * session and request in this process; a public JSON value cannot select it. */
runtime_ssh_install_ensure:
    RSI_SAVE
    mov rbx,[r15+400]
    test rbx,rbx
    jz rsi_invalid
    movabs rax,0x3142554842544c48
    cmp [rbx],rax
    jne rsi_invalid
    cmp qword ptr [rbx+224],0
    je rsi_create
    mov rax,[rbx+232]
    test rax,rax
    jz rsi_invalid
    movabs rcx,0x3154534e49535348 /* HSSINST1 */
    cmp [rax],rcx
    jne rsi_invalid
    mov rcx,[rbx+224]
    cmp [rax+56],rcx
    jne rsi_invalid
    mov [r15+480],rcx
    mov rax,rcx
    RSI_RETURN
rsi_create:
    cmp qword ptr [rbx+232],0
    jne rsi_invalid
    /* Hub+240 borrows the original kernel envp for this process lifetime. */
    cmp qword ptr [rbx+240],0
    je rsi_invalid
    mov edi,4096
    call view_allocate
    cmp rax,-4095
    jae rsi_return
    mov r12,rax
    movabs rcx,0x3154534e49535348
    mov [r12],rcx
    mov qword ptr [r12+64],-1
    mov rax,[rbx+240]
    mov [r12+72],rax
    mov edi,4096
    call view_allocate
    cmp rax,-4095
    jae rsi_fail_context
    mov r13,rax
    xor r14d,r14d
rsi_emit_next:
    mov edi,8192
    call view_allocate
    cmp rax,-4095
    jae rsi_fail_work
    mov rbp,rax
    mov rdx,r14
    shl rdx,4
    mov [r12+rdx+8],rax
    mov rax,r14
    imul rax,56
    lea rdx,[rip+rsi_cap_specs]
    add rdx,rax
    mov [rsp+96],rdx
    mov rax,[rdx]
    mov [rsp],rax
    mov qword ptr [rsp+8],1
    mov qword ptr [rsp+16],0
    mov rdi,r13
    xor eax,eax
    mov ecx,512
    rep stosq
    mov rdi,rsp
    mov esi,24
    mov rdx,rbp
    mov ecx,8192
    mov r8,r13
    mov r9d,4096
    lea rax,[rip+runtime_ssh_images]
    call qword ptr [rax+r14*8+16]
    mov rdx,[rsp+96]
    cmp rax,[rdx+16]
    jne rsi_fail_protocol
    mov rcx,[rdx+8]
    cmp [rbp],rcx
    jne rsi_fail_protocol
    cmp qword ptr [rbp+8],1
    jne rsi_fail_protocol
    mov rcx,[rdx+24]
    cmp [rbp+16],rcx
    jne rsi_fail_protocol
    mov rcx,[rdx+40]
    cmp [rbp+24],rcx
    jne rsi_fail_protocol
    xor esi,esi
rsi_emit_exports:
    lea rax,[rsi+rsi*4]
    cmp [rbp+rsi*8+32],rax
    jne rsi_fail_protocol
    inc esi
    cmp rsi,rcx
    jb rsi_emit_exports
    lea rsi,[rsi*8+32]
rsi_emit_padding:
    cmp rsi,[rdx+32]
    jae rsi_emit_checked
    cmp qword ptr [rbp+rsi],0
    jne rsi_fail_protocol
    add rsi,8
    jmp rsi_emit_padding
rsi_emit_checked:
    mov rcx,[rdx+32]
    add rcx,rbp
    mov rax,r14
    shl rax,4
    mov [r12+rax+16],rcx
    mov rdi,rbp
    mov esi,8192
    mov edx,5 /* RX, never RWX */
    mov eax,10
    syscall
    test rax,rax
    jnz rsi_fail_work
    inc r14d
    cmp r14d,3
    jb rsi_emit_next
    call rsi_capture_program
    test rax,rax
    js rsi_fail_work
    mov [r12+64],rax
    movabs rcx,0x31304b5748535348
    mov [rsp],rcx
    mov qword ptr [rsp+8],1
    lea rdx,[rip+runtime_ssh_images]
    mov rcx,[rdx]
    mov [rsp+16],rcx
    mov rcx,[rdx+8]
    mov [rsp+24],rcx
    mov rcx,[r12+16]
    mov [rsp+32],rcx
    mov rcx,[r12+32]
    mov [rsp+40],rcx
    mov rcx,[r12+48]
    mov [rsp+48],rcx
    mov rcx,[r12+72]
    mov [rsp+56],rcx
    mov [rsp+64],rax
    mov qword ptr [rsp+72],1
    mov qword ptr [rsp+80],0
    mov qword ptr [rsp+88],0
    mov rdi,rsp
    call ssh_native_worker
    test rax,rax
    js rsi_fail_work
    mov [r12+56],rax
    mov rdi,[r12+64]
    mov eax,3
    syscall
    mov qword ptr [r12+64],-1 /* Linux close is never replayed. */
    test rax,rax
    jnz rsi_created_broken
    mov rdi,r13
    mov esi,8192
    mov eax,11
    syscall
    test rax,rax
    jnz rsi_created_broken
    mov rax,[r12+56]
    mov [rbx+232],r12
    mov [rbx+224],rax
    mov [r15+480],rax
    RSI_RETURN
rsi_created_broken:
    /* Keep the successfully created root and all capabilities owned. */
    mov rcx,[r12+56]
    mov [rbx+232],r12
    mov [rbx+224],rcx
    mov [r15+480],rcx
    mov qword ptr [rcx+104],1
    mov rax,-5
    RSI_RETURN
rsi_fail_protocol:
    mov rax,-22
rsi_fail_work:
    mov [rsp+104],rax
    mov rdi,[r12+64]
    test rdi,rdi
    js rsi_fail_caps
    mov eax,3
    syscall
    mov qword ptr [r12+64],-1
rsi_fail_caps:
    xor r14d,r14d
rsi_fail_cap_next:
    mov rax,r14
    shl rax,4
    mov rdi,[r12+rax+8]
    test rdi,rdi
    jz rsi_fail_cap_skip
    mov esi,12288
    mov eax,11
    syscall
rsi_fail_cap_skip:
    inc r14d
    cmp r14d,3
    jb rsi_fail_cap_next
    mov rdi,r13
    mov esi,8192
    mov eax,11
    syscall
    mov rax,[rsp+104]
rsi_fail_context:
    mov [rsp+104],rax
    mov rdi,r12
    mov esi,8192
    mov eax,11
    syscall
    mov rax,[rsp+104]
    RSI_RETURN
rsi_invalid:
    mov rax,-22
rsi_return:
    RSI_RETURN

/* Copy the fixed installed OpenSSH program through one held ordinary inode.
 * Neither a public alias nor an operation frame can replace this path. */
rsi_capture_program:
    RSI_SAVE
    mov qword ptr [rsp+432],-1
    mov qword ptr [rsp+440],-1
    mov qword ptr [rsp+416],0
    mov edi,-100
    lea rsi,[rip+rsi_program_path]
    mov edx,0xa0000 /* O_RDONLY | O_NOFOLLOW | O_CLOEXEC */
    xor r10d,r10d
    mov eax,257
    syscall
    test rax,rax
    js rsi_capture_done
    mov [rsp+440],rax
    mov rdi,rax
    lea rsi,[rsp+128]
    mov eax,5
    syscall
    test rax,rax
    jnz rsi_capture_fail
    mov eax,[rsp+128+24]
    and eax,0xf000
    cmp eax,0x8000
    jne rsi_capture_bad
    mov rax,[rsp+128+48]
    test rax,rax
    jle rsi_capture_bad
    mov [rsp+472],rax
    lea rdi,[rip+rsi_program_name]
    mov esi,3 /* MFD_CLOEXEC | MFD_ALLOW_SEALING */
    mov eax,319
    syscall
    test rax,rax
    js rsi_capture_fail
    mov [rsp+432],rax
    mov edi,65536
    call view_allocate
    cmp rax,-4095
    jae rsi_capture_fail
    mov [rsp+416],rax
rsi_capture_read:
    mov rdx,[rsp+472]
    test rdx,rdx
    jz rsi_capture_eof
    cmp rdx,65536
    jbe rsi_capture_read_size
    mov edx,65536
rsi_capture_read_size:
    mov rdi,[rsp+440]
    mov rsi,[rsp+416]
    xor eax,eax
    syscall
    cmp rax,-4
    je rsi_capture_read
    test rax,rax
    jle rsi_capture_bad
    sub [rsp+472],rax
    mov r13,rax
    xor r14d,r14d
rsi_capture_write:
    mov rdi,[rsp+432]
    mov rsi,[rsp+416]
    add rsi,r14
    mov rdx,r13
    sub rdx,r14
    mov eax,1
    syscall
    cmp rax,-4
    je rsi_capture_write
    test rax,rax
    jle rsi_capture_bad
    add r14,rax
    cmp r14,r13
    jb rsi_capture_write
    jne rsi_capture_bad
    jmp rsi_capture_read
rsi_capture_eof:
    mov rdi,[rsp+440]
    mov rsi,[rsp+416]
    mov edx,1
    xor eax,eax
    syscall
    cmp rax,-4
    je rsi_capture_eof
    test rax,rax
    jnz rsi_capture_bad
    mov rdi,[rsp+440]
    lea rsi,[rsp+272]
    mov eax,5
    syscall
    test rax,rax
    jnz rsi_capture_fail
    /* Exact dev,ino,nlink,mode,uid,gid,size,mtime and ctime; access time can
     * legitimately change because this routine has just read the inode. */
    xor ecx,ecx
rsi_capture_stat_prefix:
    mov rax,[rsp+rcx+128]
    cmp rax,[rsp+rcx+272]
    jne rsi_capture_bad
    add ecx,8
    cmp ecx,40
    jb rsi_capture_stat_prefix
    mov rax,[rsp+128+48]
    cmp rax,[rsp+272+48]
    jne rsi_capture_bad
    mov ecx,88
rsi_capture_stat_times:
    mov rax,[rsp+rcx+128]
    cmp rax,[rsp+rcx+272]
    jne rsi_capture_bad
    add ecx,8
    cmp ecx,120
    jb rsi_capture_stat_times
    mov rdi,[rsp+432]
    mov esi,1033 /* F_ADD_SEALS */
    mov edx,15
    mov eax,72
    syscall
    test rax,rax
    jnz rsi_capture_fail
    mov rdi,[rsp+432]
    mov esi,1034
    xor edx,edx
    mov eax,72
    syscall
    cmp eax,15
    jne rsi_capture_bad
    mov rdi,[rsp+440]
    mov eax,3
    syscall
    mov qword ptr [rsp+440],-1
    test rax,rax
    jnz rsi_capture_fail
    mov rdi,[rsp+416]
    mov esi,69632
    mov eax,11
    syscall
    mov qword ptr [rsp+416],0
    test rax,rax
    jnz rsi_capture_fail
    mov rax,[rsp+432]
    RSI_RETURN
rsi_capture_bad:
    mov rax,-5
rsi_capture_fail:
    mov [rsp+464],rax
    mov rdi,[rsp+416]
    test rdi,rdi
    jz rsi_capture_close_memfd
    mov esi,69632
    mov eax,11
    syscall
rsi_capture_close_memfd:
    mov rdi,[rsp+432]
    test rdi,rdi
    js rsi_capture_close_source
    mov eax,3
    syscall
rsi_capture_close_source:
    mov rdi,[rsp+440]
    test rdi,rdi
    js rsi_capture_failed
    mov eax,3
    syscall
rsi_capture_failed:
    mov rax,[rsp+464]
rsi_capture_done:
    RSI_RETURN

/* Only after the shared root has been frozen, all calls reaped/released and
 * root destroyed. rdi is the actual hub, never a request-provided pointer. */
runtime_ssh_install_destroy:
    RSI_SAVE
    mov rbx,rdi
    cmp qword ptr [rbx+224],0
    jne rsi_destroy_invalid
    mov r12,[rbx+232]
    test r12,r12
    jz rsi_destroy_ok
    movabs rax,0x3154534e49535348
    cmp [r12],rax
    jne rsi_destroy_invalid
    cmp qword ptr [r12+56],0
    jne rsi_destroy_invalid
    xor r14d,r14d
rsi_destroy_next:
    mov rax,r14
    shl rax,4
    mov rdi,[r12+rax+8]
    test rdi,rdi
    jz rsi_destroy_invalid
    mov esi,12288
    mov eax,11
    syscall
    test rax,rax
    jnz rsi_destroy_return
    mov rax,r14
    shl rax,4
    mov qword ptr [r12+rax+8],0
    mov qword ptr [r12+rax+16],0
    inc r14d
    cmp r14d,3
    jb rsi_destroy_next
    mov rdi,r12
    mov esi,8192
    mov eax,11
    syscall
    test rax,rax
    jnz rsi_destroy_return
    mov qword ptr [rbx+232],0
rsi_destroy_ok:
    xor eax,eax
rsi_destroy_return:
    RSI_RETURN
rsi_destroy_invalid:
    mov rax,-22
    RSI_RETURN
.balign 8
runtime_ssh_images:
    .zero 40
rsi_cap_specs:
    .quad 0x3130514548535348,0x3130504548535348,5231,5151,80,6,0
    .quad 0x3130514547535348,0x3130504547535348,1544,1480,64,3,0
    .quad 0x3130514542535348,0x3130504542535348,2814,2734,80,6,0
rsi_program_path:
    .asciz "/usr/bin/ssh"
rsi_program_name:
    .asciz "runtime-installed-openssh"
