/* The only filesystem entry points for this fixed owner. Every effect is
 * validated against the source-owned operation, span and descriptor schema.
 * FD slots are private 1..4 and carry their actual opening sequence. */
.intel_syntax noprefix
.section .text
.macro TXT_ZERO offset
    cmp qword ptr [rbx + \offset], 0
    jne .Ltxt_effect_bad
.endm
.macro TXT_EQ offset, value
    cmp qword ptr [rbx + \offset], \value
    jne .Ltxt_effect_bad
.endm

txt_getfd:
    cmp rdi, 1
    jb .Ltxt_getfd_bad
    cmp rdi, 4
    ja .Ltxt_getfd_bad
    dec rdi
    shl rdi, 4
    cmp qword ptr [r15 + rdi + 168], 0
    je .Ltxt_getfd_bad
    mov rax, [r15 + rdi + 160]
    test rax, rax
    js .Ltxt_getfd_bad
    ret
.Ltxt_getfd_bad:
    mov rax, -22
    ret

/* rdi offset/rsi byte length, exact terminated HIA name region. */
txt_name:
    mov r8, [r15 + 32]
    mov rax, [r8 + 32]
    add rax, 4096
    jc .Ltxt_name_bad
    cmp rdi, rax
    je .Ltxt_name_region
    cmp rdi, 1440
    jne .Ltxt_name_bad
.Ltxt_name_region:
    mov rax, [r15 + 40]
    cmp rdi, rax
    jae .Ltxt_name_bad
    sub rax, rdi
    cmp rsi, rax
    jae .Ltxt_name_bad
    lea r8, [r8 + rdi]
    cmp byte ptr [r8 + rsi], 0
    jne .Ltxt_name_bad
    mov rdi, r8
    mov rcx, rsi
    xor eax, eax
    test rcx, rcx
    jz .Ltxt_name_good
    repne scasb
    je .Ltxt_name_bad
.Ltxt_name_good:
    mov rax, r8
    ret
.Ltxt_name_bad:
    mov rax, -22
    ret

/* Exact original result area; rdi offset/rsi length. */
txt_data_span:
    mov r8, [r15 + 32]
    cmp rsi, 4259840
    ja .Ltxt_span_bad
    mov rax, [r8 + 112]
    cmp rdi, rax
    jb .Ltxt_span_bad
    mov rcx, rdi
    sub rcx, rax
    mov rax, 4259840
    sub rax, rsi
    cmp rcx, rax
    ja .Ltxt_span_bad
    mov rax, [r15 + 40]
    cmp rdi, rax
    ja .Ltxt_span_bad
    sub rax, rdi
    cmp rsi, rax
    ja .Ltxt_span_bad
    lea rax, [r8 + rdi]
    ret
.Ltxt_span_bad:
    mov rax, -22
    ret

txt_dispatch_effect:
    TXT_ENTER
    mov r12, [r15 + 32]
    lea rbx, [r12 + 512]
    mov rax, 0x3130584654585448
    cmp [rbx], rax
    jne .Ltxt_effect_bad
    mov rax, [r15 + 96]
    cmp rax, -1
    je .Ltxt_effect_bad
    inc rax
    cmp rax, [rbx + 8]
    jne .Ltxt_effect_bad
    cmp rax, [r12 + 56]
    jne .Ltxt_effect_bad
    mov rax, [rbx + 16]
    test rax, rax
    jz .Ltxt_effect_bad
    cmp rax, [r15 + 104]
    jb .Ltxt_effect_bad
    cmp rax, [r12 + 64]
    jne .Ltxt_effect_bad
    TXT_ZERO 80
    TXT_ZERO 88
    TXT_ZERO 96
    TXT_ZERO 104
    TXT_ZERO 112
    TXT_ZERO 120
    mov r13, [rbx + 24]
    cmp r13, 1
    je .Ltxt_effect_root
    cmp r13, 2
    je .Ltxt_effect_parent
    cmp r13, 3
    je .Ltxt_effect_close
    cmp r13, 4
    je .Ltxt_effect_flock
    cmp r13, 5
    je .Ltxt_effect_path_stat
    cmp r13, 6
    je .Ltxt_effect_source
    cmp r13, 7
    je .Ltxt_effect_fd_stat
    cmp r13, 8
    je .Ltxt_effect_uid
    cmp r13, 9
    je .Ltxt_effect_xattr
    cmp r13, 10
    je .Ltxt_effect_read
    cmp r13, 11
    je .Ltxt_effect_hash
    cmp r13, 12
    je .Ltxt_effect_entropy
    cmp r13, 13
    je .Ltxt_effect_stage
    cmp r13, 14
    je .Ltxt_effect_chmod
    cmp r13, 15
    je .Ltxt_effect_write
    cmp r13, 16
    je .Ltxt_effect_sync
    cmp r13, 17
    je .Ltxt_effect_rename
    cmp r13, 18
    je .Ltxt_effect_unlink
    cmp r13, 19
    je .Ltxt_effect_errno
    jmp .Ltxt_effect_bad
.Ltxt_effect_root:
    TXT_EQ 32, 1
    TXT_EQ 40, 720896
    TXT_ZERO 48
    TXT_ZERO 56
    TXT_ZERO 64
    TXT_ZERO 72
    cmp qword ptr [r15 + 160], -1
    jne .Ltxt_effect_bad
    mov r14d, 1
    lea rdi, [rip + txt_root_name]
    mov esi, 720896
    xor edx, edx
    mov eax, 2
    syscall
    jmp .Ltxt_effect_opened
.Ltxt_effect_parent:
    TXT_EQ 64, 720896
    TXT_ZERO 72
    mov rdi, [rbx + 32]
    cmp rdi, 1
    jb .Ltxt_effect_bad
    cmp rdi, 2
    ja .Ltxt_effect_bad
    mov r14, [rbx + 40]
    cmp r14, 1
    jb .Ltxt_effect_bad
    cmp r14, 2
    ja .Ltxt_effect_bad
    cmp r14, rdi
    je .Ltxt_effect_bad
    jmp .Ltxt_effect_open_at
.Ltxt_effect_source:
    TXT_EQ 40, 3
    TXT_EQ 64, 657408
    TXT_ZERO 72
    mov rdi, [rbx + 32]
    cmp rdi, 1
    jb .Ltxt_effect_bad
    cmp rdi, 2
    ja .Ltxt_effect_bad
    mov r14d, 3
    jmp .Ltxt_effect_open_at
.Ltxt_effect_stage:
    TXT_EQ 40, 4
    TXT_EQ 48, 1440
    TXT_EQ 56, 44
    TXT_EQ 64, 655553
    TXT_EQ 72, 384
    mov rdi, [rbx + 32]
    cmp rdi, 1
    jb .Ltxt_effect_bad
    cmp rdi, 2
    ja .Ltxt_effect_bad
    mov r14d, 4
.Ltxt_effect_open_at:
    mov rax, r14
    dec rax
    shl rax, 4
    cmp qword ptr [r15 + rax + 160], -1
    jne .Ltxt_effect_bad
    cmp qword ptr [r15 + rax + 168], 0
    jne .Ltxt_effect_bad
    call txt_getfd
    test rax, rax
    js .Ltxt_effect_bad
    mov [r15 + 304], rax
    mov rdi, [rbx + 48]
    mov rsi, [rbx + 56]
    call txt_name
    test rax, rax
    js .Ltxt_effect_bad
    mov rsi, rax
    mov rdi, [r15 + 304]
    mov rdx, [rbx + 64]
    mov r10, [rbx + 72]
    mov eax, 257
    syscall
.Ltxt_effect_opened:
    mov [r15 + 128], rax
    test rax, rax
    js .Ltxt_effect_normalize
    cmp rax, 2147483647
    ja .Ltxt_effect_bad
    mov rcx, r14
    dec rcx
    bts qword ptr [r15 + 136], rcx
    shl rcx, 4
    mov [r15 + rcx + 160], rax
    mov rax, [rbx + 8]
    mov [r15 + rcx + 168], rax
    mov eax, 1
    jmp .Ltxt_effect_success
.Ltxt_effect_close:
    TXT_ZERO 48
    TXT_ZERO 56
    TXT_ZERO 64
    TXT_ZERO 72
    mov rdi, [rbx + 32]
    mov r14, rdi
    call txt_getfd
    test rax, rax
    js .Ltxt_effect_bad
    mov rdi, rax
    dec r14
    mov rcx, r14
    shl r14, 4
    mov rax, [rbx + 40]
    cmp rax, [r15 + r14 + 168]
    jne .Ltxt_effect_bad
    mov qword ptr [r15 + r14 + 160], -1
    mov qword ptr [r15 + r14 + 168], 0
    btr qword ptr [r15 + 136], rcx
    mov eax, 3
    syscall
    jmp .Ltxt_effect_syscall_done
.Ltxt_effect_flock:
    TXT_EQ 40, 2
    TXT_ZERO 48
    TXT_ZERO 56
    TXT_ZERO 64
    TXT_ZERO 72
    mov rdi, [rbx + 32]
    cmp rdi, 2
    ja .Ltxt_effect_bad
    call txt_getfd
    test rax, rax
    js .Ltxt_effect_bad
    mov rdi, rax
    mov esi, 2
    mov eax, 73
    syscall
    jmp .Ltxt_effect_syscall_done
.Ltxt_effect_path_stat:
    TXT_EQ 64, 256
    TXT_ZERO 72
    mov r14, [rbx + 56]
    cmp r14, 912
    je .Ltxt_path_stat_ready
    cmp r14, 1200
    jne .Ltxt_effect_bad
.Ltxt_path_stat_ready:
    mov rdi, [rbx + 32]
    cmp rdi, 2
    ja .Ltxt_effect_bad
    call txt_getfd
    test rax, rax
    js .Ltxt_effect_bad
    mov [r15 + 304], rax
    mov rdi, [rbx + 40]
    mov rsi, [rbx + 48]
    call txt_name
    test rax, rax
    js .Ltxt_effect_bad
    mov rsi, rax
    mov rdi, [r15 + 304]
    lea rdx, [r12 + r14]
    mov r10d, 256
    mov eax, 262
    syscall
    jmp .Ltxt_effect_syscall_done
.Ltxt_effect_fd_stat:
    TXT_ZERO 48
    TXT_ZERO 56
    TXT_ZERO 64
    TXT_ZERO 72
    mov rdi, [rbx + 32]
    cmp rdi, 3
    jb .Ltxt_effect_bad
    cmp rdi, 4
    ja .Ltxt_effect_bad
    mov r14, [rbx + 40]
    cmp r14, 768
    je .Ltxt_fd_stat_ready
    cmp r14, 912
    je .Ltxt_fd_stat_ready
    cmp r14, 1056
    jne .Ltxt_effect_bad
.Ltxt_fd_stat_ready:
    call txt_getfd
    test rax, rax
    js .Ltxt_effect_bad
    mov rdi, rax
    lea rsi, [r12 + r14]
    mov eax, 5
    syscall
    jmp .Ltxt_effect_syscall_done
.Ltxt_effect_uid:
    TXT_ZERO 32
    TXT_ZERO 40
    TXT_ZERO 48
    TXT_ZERO 56
    TXT_ZERO 64
    TXT_ZERO 72
    mov eax, 107
    syscall
    jmp .Ltxt_effect_syscall_done
.Ltxt_effect_xattr:
    TXT_EQ 32, 3
    TXT_ZERO 40
    TXT_ZERO 48
    TXT_ZERO 56
    TXT_ZERO 64
    TXT_ZERO 72
    mov edi, 3
    call txt_getfd
    test rax, rax
    js .Ltxt_effect_bad
    mov rdi, rax
    xor esi, esi
    xor edx, edx
    mov eax, 196
    syscall
    jmp .Ltxt_effect_syscall_done
.Ltxt_effect_read:
    TXT_EQ 32, 3
    cmp qword ptr [rbx + 48], 65536
    ja .Ltxt_effect_bad
    jmp .Ltxt_effect_transfer
.Ltxt_effect_write:
    TXT_EQ 32, 4
.Ltxt_effect_transfer:
    TXT_ZERO 56
    TXT_ZERO 64
    TXT_ZERO 72
    mov rdi, [rbx + 40]
    mov rsi, [rbx + 48]
    call txt_data_span
    test rax, rax
    js .Ltxt_effect_bad
    mov r14, rax
    mov rdi, [rbx + 32]
    call txt_getfd
    test rax, rax
    js .Ltxt_effect_bad
    mov rdi, rax
    mov rsi, r14
    mov rdx, [rbx + 48]
    xor eax, eax
    cmp r13, 10
    je .Ltxt_transfer_ready
    mov eax, 1
.Ltxt_transfer_ready:
    syscall
    jmp .Ltxt_effect_syscall_done
.Ltxt_effect_hash:
    TXT_ZERO 56
    TXT_ZERO 64
    TXT_ZERO 72
    mov rdi, [rbx + 32]
    cmp rdi, [r12 + 112]
    jne .Ltxt_effect_bad
    mov rsi, [rbx + 40]
    call txt_data_span
    test rax, rax
    js .Ltxt_effect_bad
    mov rdi, [rbx + 48]
    cmp rdi, 1344
    je .Ltxt_hash_ready
    cmp rdi, 1376
    jne .Ltxt_effect_bad
.Ltxt_hash_ready:
    call txt_sha256
    test rax, rax
    jnz .Ltxt_effect_bad
    mov eax, 32
    jmp .Ltxt_effect_syscall_done
.Ltxt_effect_entropy:
    TXT_EQ 32, 1408
    TXT_EQ 40, 16
    TXT_ZERO 48
    TXT_ZERO 56
    TXT_ZERO 64
    TXT_ZERO 72
    lea rdi, [r12 + 1408]
    mov esi, 16
    xor edx, edx
    mov eax, 318
    syscall
    jmp .Ltxt_effect_syscall_done
.Ltxt_effect_chmod:
    TXT_EQ 32, 4
    cmp qword ptr [rbx + 40], 511
    ja .Ltxt_effect_bad
    TXT_ZERO 48
    TXT_ZERO 56
    TXT_ZERO 64
    TXT_ZERO 72
    mov edi, 4
    call txt_getfd
    test rax, rax
    js .Ltxt_effect_bad
    mov rdi, rax
    mov rsi, [rbx + 40]
    mov eax, 91
    syscall
    jmp .Ltxt_effect_syscall_done
.Ltxt_effect_sync:
    TXT_ZERO 40
    TXT_ZERO 48
    TXT_ZERO 56
    TXT_ZERO 64
    TXT_ZERO 72
    mov rdi, [rbx + 32]
    cmp rdi, 3
    je .Ltxt_effect_bad
    call txt_getfd
    test rax, rax
    js .Ltxt_effect_bad
    mov rdi, rax
    mov eax, 74
    syscall
    jmp .Ltxt_effect_syscall_done
.Ltxt_effect_rename:
    TXT_EQ 40, 1440
    TXT_EQ 64, 44
    cmp qword ptr [rbx + 56], 1
    ja .Ltxt_effect_bad
    mov rdi, [rbx + 32]
    cmp rdi, 2
    ja .Ltxt_effect_bad
    call txt_getfd
    test rax, rax
    js .Ltxt_effect_bad
    mov [r15 + 304], rax
    mov edi, 1440
    mov esi, 44
    call txt_name
    test rax, rax
    js .Ltxt_effect_bad
    mov r14, rax
    mov rdi, [rbx + 48]
    mov rsi, [rbx + 72]
    call txt_name
    test rax, rax
    js .Ltxt_effect_bad
    mov r10, rax
    mov rsi, r14
    mov rdi, [r15 + 304]
    mov rdx, rdi
    mov r8, [rbx + 56]
    mov eax, 316
    syscall
    jmp .Ltxt_effect_syscall_done
.Ltxt_effect_unlink:
    TXT_EQ 40, 1440
    TXT_EQ 48, 44
    TXT_ZERO 56
    TXT_ZERO 64
    TXT_ZERO 72
    mov rdi, [rbx + 32]
    cmp rdi, 2
    ja .Ltxt_effect_bad
    call txt_getfd
    test rax, rax
    js .Ltxt_effect_bad
    mov r14, rax
    mov edi, 1440
    mov esi, 44
    call txt_name
    test rax, rax
    js .Ltxt_effect_bad
    mov rsi, rax
    mov rdi, r14
    xor edx, edx
    mov eax, 263
    syscall
    jmp .Ltxt_effect_syscall_done
.Ltxt_effect_errno:
    TXT_EQ 40, 1536
    TXT_EQ 48, 512
    TXT_ZERO 56
    TXT_ZERO 64
    TXT_ZERO 72
    cmp qword ptr [r15 + 136], 0
    jne .Ltxt_effect_bad
    cmp qword ptr [rbx + 32], 1
    jb .Ltxt_effect_bad
    cmp qword ptr [rbx + 32], 4095
    ja .Ltxt_effect_bad
    call txt_errno_child
    test rax, rax
    js .Ltxt_effect_bad
.Ltxt_effect_syscall_done:
    mov [r15 + 128], rax
.Ltxt_effect_normalize:
    test rax, rax
    jns .Ltxt_effect_success
    cmp rax, -4095
    jb .Ltxt_effect_bad
    neg rax
    mov [rbx + 88], rax
    xor eax, eax
.Ltxt_effect_success:
    mov [rbx + 80], rax
    mov qword ptr [rbx + 104], 1
    mov rax, [rbx + 8]
    mov [r15 + 96], rax
    mov rax, [rbx + 16]
    mov [r15 + 104], rax
    xor eax, eax
    TXT_LEAVE
.Ltxt_effect_bad:
    mov rax, -22
    TXT_LEAVE
txt_root_name:
    .asciz "/"
