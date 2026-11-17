/* G2 selects the actual final SDK initialization outcome. This fixed boundary
 * writes its admitted stderr span and retains its exit across config teardown. */
.equ CG_PUBLIC_EOF_EXIT,920
public_span_connection_eof:
    PM_SAVE
    mov rax,0x313030514e435248 /* HRCNQ001 */
    mov [r12+64],rax
    mov qword ptr [r12+72],3
    mov qword ptr [r12+80],0
    lea rdi,[r12+64]
    mov esi,24
    mov r8d,55
    call runtime_grow_owned
    cmp eax,32
    jb public_span_fail
    mov r13,[r15+8]
    lea r13,[r13+55*64]
    cmp [r13+56],rax
    jne public_span_fail
    cmp [r13+48],rax
    jne public_span_fail
    cmp [r13+40],rax
    jb public_span_fail
    mov r13,[r13+32]
    test r13,r13
    jz public_span_fail
    mov r14,rax
    mov rax,0x3130464f45435248 /* HRCEOF01 */
    cmp [r13],rax
    jne public_span_fail
    mov rbp,[r13+8]
    cmp rbp,1
    ja public_span_fail
    mov rax,[r13+24]
    add rax,32
    jc public_span_fail
    cmp rax,r14
    jne public_span_fail
    test rbp,rbp
    jnz public_span_connection_error
    mov rax,[r13+16]
    or rax,[r13+24]
    jnz public_span_fail
    jmp public_span_connection_outcome
public_span_connection_error:
    cmp qword ptr [r13+16],32
    jne public_span_fail
    cmp qword ptr [r13+24],0
    je public_span_fail
    mov edi,2
    lea rsi,[r13+32]
    mov rdx,[r13+24]
    call public_span_error_write
    test eax,eax
    jnz public_span_fail
public_span_connection_outcome:
    mov rax,[r12+248]
    mov [rax+CG_PUBLIC_EOF_EXIT],rbp
    xor eax,eax
    PM_RETURN
/* Complete stderr writes retain their span across EINTR/EAGAIN. */
public_span_error_write:
    test rdx,rdx
    jz public_span_error_write_ok
public_span_error_write_more:
    mov eax,1
    syscall
    cmp rax,-4
    je public_span_error_write_more
    cmp rax,-11
    je public_span_error_write_wait
    test rax,rax
    jle public_span_error_write_failed
    add rsi,rax
    sub rdx,rax
    jnz public_span_error_write_more
public_span_error_write_ok:
    xor eax,eax
    ret
public_span_error_write_wait:
    push rsi
    push rdx
    sub rsp,16
    mov dword ptr [rsp],2
    mov dword ptr [rsp+4],4
public_span_error_write_poll:
    mov rdi,rsp
    mov esi,1
    mov rdx,-1
    mov eax,7
    syscall
    cmp rax,-4
    je public_span_error_write_poll
    add rsp,16
    pop rdx
    pop rsi
    mov edi,2
    cmp rax,1
    je public_span_error_write_more
public_span_error_write_failed:
    mov eax,74
    ret
