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
    mov r14,rdi
    call pump_trace_clear_tail
    cmp qword ptr [rbp+PN_DESCRIPTOR+16],1408
    jb public_span_fail
    mov rax,[rbp+PN_DESCRIPTOR+56]
    cmp qword ptr [rbp+PN_X_ACTIVE],0
    je pump_trace_settled_extent
    cmp qword ptr [rbp+PN_X_ACTIVE],1
    jne public_span_fail
    test rax,rax
    jnz public_span_fail
    mov edx,0xffffffdf
    cmp [rbp+PN_DESCRIPTOR+48],rdx
    jne public_span_fail
    jmp pump_trace_admitted_extent
pump_trace_settled_extent:
    cmp rax,64
    jb public_span_fail
pump_trace_admitted_extent:
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
    mov rdi,rbp
    mov rsi,r14
    call pump_trace_extract
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

/* Complete retained extract mappings at detach/restore/retire boundaries.
 * Events9/15 contain full node/context/control/hub/engine bytes. Events10
 * observe root18 then59..63; events11 all14 callable rows; events12 the two
 * actual shared rows; events13 five independent owned regions; event14 the
 * cache/hint frame. Every allocated byte of these mappings is copied. These
 * observations do not execute an owner or acknowledge a completion. */
pump_trace_extract:
    PM_SAVE
    mov rbp,rdi
    mov r13,[rbp+PN_X_CONTEXT]
    test r13,r13
    jnz pxt_context
    cmp qword ptr [rbp+PN_X_ACTIVE],1
    jne pxt_done
    cmp qword ptr [rbp+PN_OWNERSHIP],0
    jne public_span_fail
    mov r13,[r15+456]
    test r13,r13
    jz public_span_fail
pxt_context:
    mov r14,[r13+152]
    test r14,r14
    jz public_span_fail
    call pump_trace_clear_tail
    mov [r12+PM_TRACE_C_PTR],r14
    mov qword ptr [r12+PM_TRACE_C_LEN],4096
    mov edi,9
    mov rsi,rbp
    mov rdx,rbp
    mov ecx,4096
    mov r8,r13
    mov r9d,4096
    call pump_trace_emit
    call pump_trace_clear_tail
    mov edi,15
    mov rsi,rbp
    mov rdx,[r13+80]
    mov ecx,4096
    mov r8,r15
    mov r9d,16384
    call pump_trace_emit
    xor ebx,ebx
pxt_extra:
    lea rdx,[rbp+PN_DESCRIPTOR]
    test ebx,ebx
    jz pxt_extra_row
    lea rax,[rbx-1]
    shl rax,6
    lea rdx,[rbp+rax+PN_X_DESCRIPTORS]
pxt_extra_row:
    mov rax,[rdx+32]
    mov [r12+PM_TRACE_C_PTR],rax
    mov rax,[rdx+40]
    mov [r12+PM_TRACE_C_LEN],rax
    mov r8,[rdx+8]
    mov r9,[rdx+16]
    mov edi,10
    mov rsi,rbp
    mov ecx,64
    call pump_trace_emit
    inc ebx
    cmp ebx,6
    jb pxt_extra
    xor ebx,ebx
pxt_callable:
    mov rax,rbx
    shl rax,6
    lea rdx,[r14+rax+256]
    mov rax,[rdx+24]
    mov [r12+PM_TRACE_C_PTR],rax
    mov rax,[rdx+32]
    mov [r12+PM_TRACE_C_LEN],rax
    mov r8,[rdx+8]
    mov r9,[rdx+16]
    mov edi,11
    mov rsi,rbp
    mov ecx,64
    call pump_trace_emit
    inc ebx
    cmp ebx,14
    jb pxt_callable
    xor ebx,ebx
pxt_shared:
    mov rax,rbx
    shl rax,6
    mov rdx,[r13+80]
    lea rdx,[rdx+rax+64]
    mov rax,[rdx+24]
    mov [r12+PM_TRACE_C_PTR],rax
    mov rax,[rdx+32]
    mov [r12+PM_TRACE_C_LEN],rax
    mov r8,[rdx+8]
    mov r9,[rdx+16]
    mov edi,12
    mov rsi,rbp
    mov ecx,64
    call pump_trace_emit
    inc ebx
    cmp ebx,2
    jb pxt_shared
    xor ebx,ebx
pxt_region:
    call pump_trace_clear_tail
    lea rax,[rip+pxt_regions]
    mov rdx,[rax+rbx*8]
    add rdx,r14
    mov r8,[rdx]
    mov r9,[rdx+8]
    mov edi,13
    mov rsi,rbp
    mov ecx,16
    call pump_trace_emit
    inc ebx
    cmp ebx,5
    jb pxt_region
    call pump_trace_clear_tail
    lea rdx,[r13+256+184]
    mov r8,[rdx]
    mov r9,[rdx+8]
    mov edi,14
    mov rsi,rbp
    mov ecx,16
    call pump_trace_emit
pxt_done:
    PM_RETURN
.balign 8
pxt_regions:
    .quad 0,24,160,1536,1584
