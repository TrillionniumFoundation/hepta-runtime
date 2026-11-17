/* Fixed private FD4 observations. Production leaves FD4 unselected. These
 * copies never choose policy, acknowledge an OS write, or release a borrow. */
.intel_syntax noprefix
.section .text

/* Event128 header followed by three exact spans. Inputs are event, node,
 * A pointer/length, B pointer/length. C and committed-state capacity are set
 * by the fixed wrapper. The header distinguishes bounded diagnostic prefixes
 * from the registry's complete committed extent and complete result frames. */
pump_trace_emit:
    PM_SAVE
    cmp qword ptr [r12+PM_TRACE_FD],0
    jl pump_trace_emit_done
    mov rbp,rsi
    mov [r12+PM_TRACE_A_PTR],rdx
    mov [r12+PM_TRACE_B_PTR],r8
    mov [r12+PM_TRACE_HEADER+24],rdi
    mov [r12+PM_TRACE_HEADER+72],rcx
    mov [r12+PM_TRACE_HEADER+80],r9
    mov rax,[r12+PM_TRACE_C_LEN]
    mov [r12+PM_TRACE_HEADER+88],rax
    add rax,rcx
    jc public_span_fail
    add rax,r9
    jc public_span_fail
    add rax,128
    jc public_span_fail
    mov [r12+PM_TRACE_HEADER+8],rax
    mov rax,0x3130564552545048 /* HPTREV01 */
    mov [r12+PM_TRACE_HEADER],rax
    inc qword ptr [r12+PM_TRACE_SEQUENCE]
    jz public_span_fail
    mov rax,[r12+PM_TRACE_SEQUENCE]
    mov [r12+PM_TRACE_HEADER+16],rax
    mov qword ptr [r12+PM_TRACE_HEADER+32],0
    mov qword ptr [r12+PM_TRACE_HEADER+40],0
    mov [r12+PM_TRACE_HEADER+48],rbp
    mov [r12+PM_TRACE_HEADER+56],r15
    mov qword ptr [r12+PM_TRACE_HEADER+104],0
    test rbp,rbp
    jz pump_trace_header_state
    mov rax,[rbp+PN_HOST_GENERATION]
    mov [r12+PM_TRACE_HEADER+32],rax
    mov rax,[rbp+PN_GENERATION]
    mov [r12+PM_TRACE_HEADER+40],rax
    mov rax,[rbp+PN_WRITE_RESULT]
    mov [r12+PM_TRACE_HEADER+104],rax
pump_trace_header_state:
    mov rax,[r12+PM_PHASE]
    mov [r12+PM_TRACE_HEADER+96],rax
    mov rax,[r12+PM_TRACE_STATE_CAP]
    mov [r12+PM_TRACE_HEADER+112],rax
    mov qword ptr [r12+PM_TRACE_HEADER+120],0
    call pump_clock
    mov [r12+PM_TRACE_HEADER+64],rax
    mov rdi,[r12+PM_TRACE_FD]
    lea rsi,[r12+PM_TRACE_HEADER]
    mov edx,128
    call view_write_all
    test rax,rax
    jnz public_span_fail
    mov rdi,[r12+PM_TRACE_FD]
    mov rsi,[r12+PM_TRACE_A_PTR]
    mov rdx,[r12+PM_TRACE_HEADER+72]
    call view_write_all
    test rax,rax
    jnz public_span_fail
    mov rdi,[r12+PM_TRACE_FD]
    mov rsi,[r12+PM_TRACE_B_PTR]
    mov rdx,[r12+PM_TRACE_HEADER+80]
    call view_write_all
    test rax,rax
    jnz public_span_fail
    mov rdi,[r12+PM_TRACE_FD]
    mov rsi,[r12+PM_TRACE_C_PTR]
    mov rdx,[r12+PM_TRACE_HEADER+88]
    call view_write_all
    test rax,rax
    jnz public_span_fail
pump_trace_emit_done:
    PM_RETURN

pump_trace_clear_tail:
    mov qword ptr [r12+PM_TRACE_C_PTR],0
    mov qword ptr [r12+PM_TRACE_C_LEN],0
    mov qword ptr [r12+PM_TRACE_STATE_CAP],0
    ret

pump_trace_accept:
    PM_SAVE
    cmp qword ptr [r12+PM_TRACE_FD],0
    jl pump_trace_accept_done
    mov rbp,rdi
    call pump_trace_clear_tail
    mov edi,1
    mov rsi,rbp
    mov rdx,[rbp+PN_INPUT]
    mov rcx,[rbp+PN_INPUT_LENGTH]
    mov r8,rbp
    mov r9d,512
    call pump_trace_emit
pump_trace_accept_done:
    PM_RETURN

/* Full registry input and reply, then every byte of its committed state.
 * Unused allocated arena capacity is reported separately, never called a
 * captured state extent. The actual HIA response supplies the used extent. */
pump_trace_registry:
    PM_SAVE
    cmp qword ptr [r12+PM_TRACE_FD],0
    jl pump_trace_registry_done
    mov rax,[r15+8]
    add rax,58*64
    mov rdx,[rax+8]
    mov rcx,[rax+16]
    mov [r12+PM_TRACE_STATE_CAP],rcx
    mov rbx,[r12+PM_REG_REPLY+96]
    cmp rbx,256
    jb public_span_fail
    cmp rbx,rcx
    ja public_span_fail
    cmp [rdx+72],rbx
    jne public_span_fail
    mov [r12+PM_TRACE_C_PTR],rdx
    mov [r12+PM_TRACE_C_LEN],rbx
    mov edi,2
    mov rsi,[r12+PM_CURRENT]
    mov rdx,[r12+PM_SCRATCH]
    mov rcx,[rdx+48]
    add rcx,64
    lea r8,[r12+PM_REG_REPLY]
    mov r9d,192
    call pump_trace_emit
pump_trace_registry_done:
    PM_RETURN

pump_trace_detached:
    mov rsi,rdi
    mov edi,3
    jmp pump_trace_frontend
pump_trace_restored:
    mov rsi,rdi
    mov edi,4
    jmp pump_trace_frontend
pump_trace_retired:
    mov rsi,rdi
    mov edi,7
    jmp pump_trace_frontend
pump_trace_frontend:
    PM_SAVE
    cmp qword ptr [r12+PM_TRACE_FD],0
    jl pump_trace_frontend_done
    mov rbp,rsi
    call pump_trace_clear_tail
    cmp qword ptr [rbp+PN_DESCRIPTOR+16],1408
    jb public_span_fail
    mov rax,[rbp+PN_DESCRIPTOR+56]
    cmp rax,64
    jb public_span_fail
    cmp rax,[rbp+PN_DESCRIPTOR+40]
    ja public_span_fail
    mov [r12+PM_TRACE_C_LEN],rax
    mov rax,[rbp+PN_DESCRIPTOR+32]
    mov [r12+PM_TRACE_C_PTR],rax
    mov rsi,rbp
    mov rdx,rbp
    mov ecx,512
    mov r8,[rbp+PN_DESCRIPTOR+8]
    mov r9d,1408
    call pump_trace_emit
pump_trace_frontend_done:
    PM_RETURN

/* The complete READY frame and original borrow descriptor are observed only
 * after actual token release, before the descriptor is cleared. */
pump_trace_ready:
    PM_SAVE
    cmp qword ptr [r12+PM_TRACE_FD],0
    jl pump_trace_ready_done
    call pump_trace_clear_tail
    mov edi,5
    xor esi,esi
    mov rdx,[r12+PM_READY_COPY]
    mov rcx,[r12+PM_READY_LEN]
    lea r8,[r12+PM_BORROW]
    mov r9d,32
    call pump_trace_emit
pump_trace_ready_done:
    PM_RETURN

/* A send turn records the actual syscall result for direct bytes/LF, or the
 * publisher return code. Suspended publishers retain their actual 256/640
 * header prefixes and complete private context; these are not full arenas. */
pump_trace_send:
    PM_SAVE
    cmp qword ptr [r12+PM_TRACE_FD],0
    jl pump_trace_send_done
    mov rbp,rdi
    call pump_trace_clear_tail
    xor r8d,r8d
    xor r9d,r9d
    cmp qword ptr [rbp+PN_PUBLICATION+96],1
    jne pump_trace_send_ready
    mov r8,[rbp+PN_PUBLICATION+72]
    mov r9d,256
    mov rax,[rbp+PN_PUBLICATION+80]
    mov [r12+PM_TRACE_C_PTR],rax
    mov qword ptr [r12+PM_TRACE_C_LEN],640
    mov rax,[rbp+PN_PUBLICATION+88]
    cmp rax,640
    jb public_span_fail
    mov [r12+PM_TRACE_STATE_CAP],rax
pump_trace_send_ready:
    mov edi,6
    mov rsi,rbp
    mov rdx,rbp
    mov ecx,512
    call pump_trace_emit
pump_trace_send_done:
    PM_RETURN

pump_trace_closed:
    PM_SAVE
    cmp qword ptr [r12+PM_TRACE_FD],0
    jl pump_trace_closed_done
    call pump_trace_clear_tail
    mov edi,8
    xor esi,esi
    lea rdx,[r12+PM_REG_REPLY]
    mov ecx,192
    xor r8d,r8d
    xor r9d,r9d
    call pump_trace_emit
pump_trace_closed_done:
    PM_RETURN
