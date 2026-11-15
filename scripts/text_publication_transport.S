/* Bounded individual Linux transfers, complete unbounded framed stream.
 * Existing FD flags are never changed. EINTR is retried for transport only;
 * filesystem EINTR is delivered verbatim to the HIA state machine. */
.intel_syntax noprefix
.section .text
txt_wait_fd:
    sub rsp, 16
    mov [rsp], edi
    mov [rsp + 4], si
    mov word ptr [rsp + 6], 0
.Ltxt_poll_again:
    mov rdi, rsp
    mov esi, 1
    mov rdx, -1
    mov eax, 7
    syscall
    cmp rax, -4
    je .Ltxt_poll_again
    add rsp, 16
    ret

/* read_all(fd,p,n):1 exact;0 clean EOF before any byte;-errno otherwise. */
txt_read_all:
    TXT_ENTER
    mov r12, rdi
    mov r13, rsi
    mov r14, rdx
    xor ebx, ebx
.Ltxt_read_again:
    cmp rbx, r14
    je .Ltxt_read_done
    mov rdi, r12
    lea rsi, [r13 + rbx]
    mov rdx, r14
    sub rdx, rbx
    cmp rdx, 1048576
    jbe .Ltxt_read_count
    mov edx, 1048576
.Ltxt_read_count:
    xor eax, eax
    syscall
    cmp rax, -4
    je .Ltxt_read_again
    cmp rax, -11
    je .Ltxt_read_wait
    test rax, rax
    js .Ltxt_read_return
    jz .Ltxt_read_eof
    add rbx, rax
    jc .Ltxt_read_invalid
    jmp .Ltxt_read_again
.Ltxt_read_wait:
    mov rdi, r12
    mov esi, 1
    call txt_wait_fd
    test rax, rax
    js .Ltxt_read_return
    jmp .Ltxt_read_again
.Ltxt_read_eof:
    test rbx, rbx
    jz .Ltxt_read_return
.Ltxt_read_invalid:
    mov rax, -5
    jmp .Ltxt_read_return
.Ltxt_read_done:
    mov eax, 1
.Ltxt_read_return:
    TXT_LEAVE

txt_write_all:
    TXT_ENTER
    mov r12, rdi
    mov r13, rsi
    mov r14, rdx
    xor ebx, ebx
.Ltxt_write_again:
    cmp rbx, r14
    je .Ltxt_write_done
    mov rdi, r12
    lea rsi, [r13 + rbx]
    mov rdx, r14
    sub rdx, rbx
    cmp rdx, 1048576
    jbe .Ltxt_write_count
    mov edx, 1048576
.Ltxt_write_count:
    mov eax, 1
    syscall
    cmp rax, -4
    je .Ltxt_write_again
    cmp rax, -11
    je .Ltxt_write_wait
    test rax, rax
    js .Ltxt_write_return
    jz .Ltxt_write_invalid
    add rbx, rax
    jc .Ltxt_write_invalid
    jmp .Ltxt_write_again
.Ltxt_write_wait:
    mov rdi, r12
    mov esi, 4
    call txt_wait_fd
    test rax, rax
    js .Ltxt_write_return
    jmp .Ltxt_write_again
.Ltxt_write_invalid:
    mov rax, -5
    jmp .Ltxt_write_return
.Ltxt_write_done:
    xor eax, eax
.Ltxt_write_return:
    TXT_LEAVE

/* Qualification-only flag at engine+144. Zero in all callable production
 * engines. A receipt is 256 bytes: HTXTEF01 +7Q(gen,seq,kind,phase,raw,
 * workcap,0), exact completed128B HIA effect,4(fd,opening_seq) pairs.
 * --sync waits for HTXTACK1+2Q(gen,seq); the ACK cannot alter a result. */
txt_effect_trace:
    test qword ptr [r15 + 144], 1
    jz .Ltxt_trace_quiet
    TXT_ENTER
    mov r12, [r15 + 32]
    lea rbx, [r15 + 1280]
    mov rax, 0x3130464554585448
    mov [rbx], rax
    mov rax, [r12 + 528]
    mov [rbx + 8], rax
    mov rax, [r12 + 520]
    mov [rbx + 16], rax
    mov rax, [r12 + 536]
    mov [rbx + 24], rax
    mov rax, [r12]
    mov [rbx + 32], rax
    mov rax, [r15 + 128]
    mov [rbx + 40], rax
    mov rax, [r15 + 40]
    mov [rbx + 48], rax
    mov qword ptr [rbx + 56], 0
    lea rdi, [rbx + 64]
    lea rsi, [r12 + 512]
    mov ecx, 128
    rep movsb
    lea rdi, [rbx + 192]
    lea rsi, [r15 + 160]
    mov ecx, 64
    rep movsb
    mov edi, 2
    mov rsi, rbx
    mov edx, 256
    call txt_write_all
    test rax, rax
    js .Ltxt_trace_return
    test qword ptr [r15 + 144], 2
    jz .Ltxt_trace_return
    xor edi, edi
    lea rsi, [r15 + 1536]
    mov edx, 24
    call txt_read_all
    cmp rax, 1
    jne .Ltxt_trace_bad
    mov rax, 0x314b434154585448
    cmp [r15 + 1536], rax
    jne .Ltxt_trace_bad
    mov rax, [rbx + 8]
    cmp [r15 + 1544], rax
    jne .Ltxt_trace_bad
    mov rax, [rbx + 16]
    cmp [r15 + 1552], rax
    jne .Ltxt_trace_bad
    xor eax, eax
.Ltxt_trace_return:
    TXT_LEAVE
.Ltxt_trace_bad:
    mov rax, -5
    TXT_LEAVE
.Ltxt_trace_quiet:
    xor eax, eax
    ret
