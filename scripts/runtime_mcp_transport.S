/* Public newline JSON-RPC transport. HIA slot18 owns routing and responses.
 * No input byte chooses a child slot, pointer, session or publisher instance. */
.intel_syntax noprefix
.section .text
.type public_span_start, @function
public_span_start:
    cld
    mov rax, [rsp]
    lea r14, [rsp + rax * 8 + 16]
    sub rsp, 4096
    mov r12, rsp
    xor eax, eax
    mov rdi, r12
    mov ecx, 4096
    rep stosb
    mov [r12 + 248], r15
    mov rdi, r14
    call runtime_filesystem_hub_create
    cmp rax, -4095
    jae public_span_fail
    mov [r12 + 232], rax
    call runtime_text_body_hub_create
    cmp rax, -4095
    jae public_span_fail
    mov [r12 + 224], rax
    xor ebx, ebx
    xor ebp, ebp
    lea rdi, [rip + grow_fixture_images]
    mov rsi, r15
    call runtime_grow_create
    cmp rax, -4095
    jae public_span_fail
    mov r15, rax
    mov [r12 + 240], rax
    mov rax, [r12 + 224]
    mov [r15 + 400], rax
    mov rdi, [r12 + 232]
    call runtime_filesystem_hub_bind
    test rax, rax
    jnz public_span_fail
    /* SIGPIPE is an I/O result, including before the first publication. */
    mov qword ptr [r12 + 160], 1
    mov edi, 13
    lea rsi, [r12 + 160]
    xor edx, edx
    mov r10d, 8
    mov eax, 13
    syscall
    test rax, rax
    js public_span_fail
    call pump_initialize
    mov edi, 4096
    call view_allocate
    cmp rax, -4095
    jae public_span_fail
    mov rbx, rax
    mov ebp, 4096
public_span_getcwd:
    lea rdi, [rbx + 32]
    lea rsi, [rbp - 32]
    mov eax, 79
    syscall
    cmp rax, -34
    je public_span_getcwd_grow
    cmp rax, -4095
    jae public_span_fail
    cmp rax, 2
    jb public_span_fail
    cmp rax, rbp
    ja public_span_fail
    dec rax /* Kernel getcwd includes its terminator. */
    mov [rbx + 16], rax
    lea rsi, [rax + 32]
    mov rdx, 0x3230305157535248 /* HRSWQ002 */
    mov [rbx], rdx
    mov qword ptr [rbx + 8], 1
    mov qword ptr [rbx + 24], 0
    mov rdi, rbx
    mov r8d, 6
    call runtime_grow_owned
    cmp eax, 32
    jne public_span_fail
    mov rdx, [r15 + 8]
    add rdx, 6 * 64
    cmp qword ptr [rdx + 56], 32
    jne public_span_fail
    mov rdx, [rdx + 32]
    mov rax, 0x3230305257535248 /* HRSWR002 */
    cmp [rdx], rax
    jne public_span_fail
    mov rax, [rdx + 8]
    or rax, [rdx + 16]
    or rax, [rdx + 24]
    jnz public_span_fail
    jmp public_span_scan
public_span_getcwd_grow:
    call public_span_grow_input
    test eax, eax
    jnz public_span_fail
    jmp public_span_getcwd
public_span_next:
    cmp qword ptr [r12 + 40], 0
    jne public_span_finish
    mov rcx, [r12 + 16]
    mov rdx, [r12]
    cmp rcx, rdx
    ja public_span_fail
    sub rdx, rcx
    mov rdi, rbx
    lea rsi, [rbx + rcx]
    mov rcx, rdx
    rep movsb
    mov [r12], rdx
    mov qword ptr [r12 + 8], 0
    mov qword ptr [r12 + 16], 0
public_span_scan:
    call pump_tick
    cmp qword ptr [r12 + PM_BARRIER], 0
    jne public_span_wait_input
    mov rcx, [r12 + 8]
    mov rdx, [r12]
    cmp rdx, rbp
    ja public_span_fail
public_span_scan_byte:
    cmp rcx, rdx
    jae public_span_need_input
    cmp byte ptr [rbx + rcx], 10
    je public_span_line
    inc rcx
    jmp public_span_scan_byte
public_span_line:
    mov rsi, rcx
    inc rcx
    mov [r12 + 16], rcx
    cmp qword ptr [r12 + 48], 0
    jne public_span_discard_end
    cmp rcx, 16777216 /* The target limit includes the terminating LF. */
    ja public_span_discard_end
    test rsi, rsi
    jz public_span_next
    cmp byte ptr [rbx + rsi - 1], 13
    jne public_span_line_ready
    dec rsi
public_span_line_ready:
    test rsi, rsi
    jz public_span_next
    jmp public_span_request
public_span_discard_end:
    mov qword ptr [r12 + 48], 0
    jmp public_span_next
public_span_need_input:
    mov [r12 + 8], rcx
    cmp qword ptr [r12 + 24], 0
    jne public_span_final_line
    cmp qword ptr [r12 + 48], 0
    jne public_span_discard_buffer
    cmp rdx, 16777216
    jae public_span_begin_discard
    cmp rdx, rbp
    jne public_span_read
    call public_span_grow_input
    test eax, eax
    jnz public_span_fail
    mov rdx, [r12]
public_span_read:
    lea rsi, [rbx + rdx]
    mov rcx, rbp
    sub rcx, rdx
    cmp rcx, 65536
    jbe public_span_read_size
    mov ecx, 65536
public_span_read_size:
    mov rdx, rcx
    xor edi, edi
    xor eax, eax
    syscall
    cmp rax, -4
    je public_span_scan
    cmp rax, -11
    je public_span_wait_input
    test rax, rax
    js public_span_fail
    jz public_span_input_eof
    add [r12], rax
    jc public_span_fail
    jmp public_span_scan
public_span_wait_input:
    call pump_wait
    jmp public_span_scan
public_span_begin_discard:
    mov qword ptr [r12 + 48], 1
public_span_discard_buffer:
    /* A rejected frame is consumed through its LF without retaining its tail. */
    mov qword ptr [r12], 0
    mov qword ptr [r12 + 8], 0
    mov qword ptr [r12 + 16], 0
    xor edx, edx
    jmp public_span_read
public_span_input_eof:
    mov qword ptr [r12 + 24], 1
    jmp public_span_scan
public_span_final_line:
    /* AsyncRwTransport discards an unterminated trailing message.
     * JsonRpcMessageCodec.decode_eof is a separate contract. */
    jmp public_span_finish
public_span_request:
    mov rdi, rbx
    /* Target compatibility removes one leading UTF-8 BOM from a complete
     * frame. The limit above already counted these bytes and the final LF. */
    cmp rsi, 3
    jb public_span_request_ready
    cmp byte ptr [rdi], 239
    jne public_span_request_ready
    cmp byte ptr [rdi + 1], 187
    jne public_span_request_ready
    cmp byte ptr [rdi + 2], 191
    jne public_span_request_ready
    add rdi, 3
    sub rsi, 3
    jz public_span_next
public_span_request_ready:
    call pump_accept
    jmp public_span_next
public_span_finish:
    call pump_finish
    call public_span_connection_eof
    test eax,eax
    jnz public_span_fail
    /* SDK registry58 has closed transport and drained owned tasks. */
    call runtime_extract_body_release
    test rax, rax
    jnz public_span_fail
    call runtime_batch_body_release
    test rax, rax
    jnz public_span_fail
    call runtime_text_body_release
    test rax, rax
    jnz public_span_fail
    call runtime_text_create_release
    test rax, rax
    jnz public_span_fail
    call runtime_grow_fence_release
    test rax, rax
    jnz public_span_fail
    call runtime_grow_view_release
    test rax, rax
    jnz public_span_fail
    call runtime_grow_destroy
    test rax, rax
    jnz public_span_fail
    mov qword ptr [r12 + 240], 0
    mov rdi, [r12 + 224]
    call runtime_text_body_hub_destroy
    test rax, rax
    jnz public_span_fail
    mov qword ptr [r12 + 224], 0
    mov rdi, [r12 + 232]
    call runtime_filesystem_hub_destroy
    test rax, rax
    jnz public_span_fail
    mov qword ptr [r12 + 232], 0
    mov rdi, rbx
    lea rsi, [rbp + 4096]
    mov eax, 11
    syscall
    test rax, rax
    jnz public_span_fail
    mov r15, [r12 + 248]
    jmp frame_eof /* Existing HIA config lease/lock teardown. */
public_span_fail:
    call pump_restore_fd_flags
    mov r15, [r12 + 248]
    jmp fatal /* Never convert resource/invariant failure to business text. */
/* HIA decides the shutdown action. The native boundary verifies the complete
 * descriptor and reports only actual synchronous completion to that owner. */
public_span_shutdown_step:
    mov [r12 + 56], rcx
    mov rdx, 0x3130303051535248 /* HRSQ0001 */
    mov [r12 + 64], rdx
    mov [r12 + 72], rax
    xor eax, eax
    mov [r12 + 80], rax
    mov [r12 + 88], rax
    mov [r12 + 96], rax
    mov [r12 + 104], rax
    mov [r12 + 112], rax
    mov [r12 + 120], rax
    lea rdi, [r12 + 64]
    mov esi, 64
    mov r8d, 53
    sub rsp, 8 /* Preserve the nested native SysV call alignment. */
    call runtime_grow_owned
    add rsp, 8
    cmp eax, 96
    jne public_span_shutdown_invalid
    mov rdx, [r15 + 8]
    add rdx, 53 * 64
    cmp qword ptr [rdx + 56], 96
    jne public_span_shutdown_invalid
    mov rdx, [rdx + 32]
    mov rax, 0x3130303053535248 /* HRSS0001 */
    cmp [rdx], rax
    jne public_span_shutdown_invalid
    mov rcx, [r12 + 56]
    cmp [rdx + 8], rcx
    jne public_span_shutdown_invalid
    cmp [rdx + 16], rcx
    jne public_span_shutdown_invalid
    xor eax, eax
    cmp ecx, 3
    setae al
    cmp [rdx + 24], rax
    jne public_span_shutdown_invalid
    xor eax, eax
    cmp ecx, 4
    sete al
    cmp [rdx + 40], rax
    jne public_span_shutdown_invalid
    cmp qword ptr [rdx + 48], 5000
    jne public_span_shutdown_invalid
    mov rax, [rdx + 32]
    or rax, [rdx + 56]
    or rax, [rdx + 64]
    or rax, [rdx + 72]
    or rax, [rdx + 80]
    or rax, [rdx + 88]
    jnz public_span_shutdown_invalid
    xor eax, eax
    ret
public_span_shutdown_invalid:
    mov eax, 0xffffffff
    ret
/* Physical pages grow only as needed. Input framing has its separate
 * 16 MiB SDK line limit; no new result-output limit is introduced. */
public_span_grow_input:
    mov rdx, rbp
    add rdx, rdx
    jc public_span_grow_failed
    test rdx, rdx
    jle public_span_grow_failed
    mov [r12 + 32], rdx
    mov rdi, rbx
    mov rsi, rbp
    call view_resize
    cmp rax, -4095
    jae public_span_grow_failed
    mov rbx, rax
    mov rbp, [r12 + 32]
    xor eax, eax
    ret
public_span_grow_failed:
    mov eax, 75
    ret
/* Complete writes preserve the same byte span across EINTR/EAGAIN. */
public_span_write:
    test rdx, rdx
    jz public_span_write_ok
public_span_write_more:
    mov eax, 1
    syscall
    cmp rax, -4
    je public_span_write_more
    cmp rax, -11
    je public_span_write_wait
    test rax, rax
    jle public_span_write_failed
    add rsi, rax
    sub rdx, rax
    jnz public_span_write_more
public_span_write_ok:
    xor eax, eax
    ret
public_span_write_wait:
    push rsi
    push rdx
    sub rsp, 16
    mov dword ptr [rsp], 1
    mov dword ptr [rsp + 4], 4
public_span_write_poll:
    mov rdi, rsp
    mov esi, 1
    mov rdx, -1
    mov eax, 7
    syscall
    cmp rax, -4
    je public_span_write_poll
    add rsp, 16
    pop rdx
    pop rsi
    mov edi, 1
    cmp rax, 1
    je public_span_write_more
public_span_write_failed:
    mov eax, 74
    ret
.balign 8
grow_fixture_images:
    .zero 568 /* 71 fixed slots; existing routes plus binary owners69..70. */

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
