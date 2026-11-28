/* Default private generic owner embedding. The six HIA image addresses are
 * fixed by the actual native packer. The complete retained program capture
 * below binds the same ordinary installed OpenSSH inode and seals its bytes.
 * Only the single process event-loop owns creation and final destruction. */
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


/* Actual engine r15, process hub+224 root, hub+232 owned installer. */
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
    movabs rcx,0x3154534e49535348
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
    call rsi_capture_program
    test rax,rax
    js rsi_fail_context
    mov [r12+64],rax
    movabs rcx,0x3130304b57475348 /* HSGWK001 */
    mov [rsp],rcx
    mov qword ptr [rsp+8],1
    mov rcx,[r12+72]
    mov [rsp+16],rcx
    mov [rsp+24],rax
    mov qword ptr [rsp+32],1
    mov qword ptr [rsp+40],0
    mov qword ptr [rsp+48],0
    mov qword ptr [rsp+56],0
    mov rdi,rsp
    call ssh_native_worker
    test rax,rax
    js rsi_fail_capture
    mov [r12+56],rax
    mov [rbx+232],r12
    mov [rbx+224],rax
    mov [r15+480],rax
    mov rdi,[r12+64]
    mov qword ptr [r12+64],-1
    mov eax,3
    syscall
    test rax,rax
    jnz rsi_created_broken
    mov rax,[r12+56]
    RSI_RETURN
rsi_created_broken:
    mov rcx,[r12+56]
    mov qword ptr [rcx+104],1
    mov rax,-5
    RSI_RETURN
rsi_fail_capture:
    mov [rsp+104],rax
    mov rdi,[r12+64]
    mov qword ptr [r12+64],-1
    mov eax,3
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

/* Root must already have completed its real persistent join and destruction. */
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
    cmp qword ptr [r12+64],-1
    jne rsi_destroy_invalid
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
    .zero 48
rsi_program_path:
    .asciz "/usr/bin/ssh"
rsi_program_name:
    .asciz "runtime-installed-openssh"
