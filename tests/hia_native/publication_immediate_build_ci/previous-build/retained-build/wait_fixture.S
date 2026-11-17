/* Fixed inherited FD5 test capability. This file is absent from every
 * production boundary. The fixture holds actual FileLockState leases and
 * observes bytes; it never fabricates a public WAIT, wake, response or drop. */
.intel_syntax noprefix
.section .text
.equ PM_WAIT_FIXTURE,1200
.equ XF_SEQUENCE,8
.equ XF_CLOSED,16
.equ XF_FD,24
.equ XF_OPERATION,32
.equ XF_SLOT,40
.equ XF_PAYLOAD_LENGTH,48
.equ XF_OUTPUT,56
.equ XF_OUTPUT_LENGTH,64
.equ XF_PHASE,72
.equ XF_COUNT,80
.equ XF_SNAPSHOT_LENGTH,88
.equ XF_REPLY,96
.equ XF_SNAPSHOT_HEADER,160
.equ XF_POLL,224
.equ XF_LEASES,256
.equ XF_LOCK_REQUEST,288
.equ XF_LOCK_RESULTS,352
.equ XF_INPUT,512
.equ XF_PAYLOAD,576
.equ XF_ROWS,4096

wait_fixture_preflight:
    sub rsp,24
    mov edi,5
    mov esi,3
    mov eax,72
    syscall
    test rax,rax
    js bare_fatal
    mov ecx,eax
    and eax,3
    cmp eax,2
    jne bare_fatal
    test ecx,2048
    jnz bare_fatal
    mov dword ptr [rsp+8],4
    mov edi,5
    mov esi,1
    mov edx,3
    mov r10,rsp
    lea r8,[rsp+8]
    mov eax,55
    syscall
    test rax,rax
    jnz bare_fatal
    cmp dword ptr [rsp],1
    jne bare_fatal
    cmp dword ptr [rsp+8],4
    jne bare_fatal
    add rsp,24
    ret

wait_fixture_initialize:
    PM_SAVE
    cmp qword ptr [r12+PM_WAIT_FIXTURE],0
    jne public_span_fail
    mov edi,8192
    call view_allocate
    cmp rax,-4095
    jae public_span_fail
    mov [r12+PM_WAIT_FIXTURE],rax
    mov rdx,0x31303043544c5848 /* HXLTC001 */
    mov [rax],rdx
    mov qword ptr [rax+XF_FD],5
    mov qword ptr [r15+80],5 /* Diagnostic: existing engine trace to fixed FD4. */
    PM_RETURN

/* One fully framed trusted test command per event-loop turn. FD5 is a
 * blocking socket checked before startup; only poll-readable input is read.
 * The producer sends each complete <=3136-byte frame before awaiting reply. */
wait_fixture_tick:
    PM_SAVE
    mov rbp,[r12+PM_WAIT_FIXTURE]
    test rbp,rbp
    jz public_span_fail
    cmp qword ptr [rbp+XF_CLOSED],0
    jne xwf_tick_done
    cmp qword ptr [r12+PM_PHASE],3
    jae xwf_tick_done
    mov dword ptr [rbp+XF_POLL],5
    mov dword ptr [rbp+XF_POLL+4],1
xwf_poll_retry:
    lea rdi,[rbp+XF_POLL]
    mov esi,1
    xor edx,edx
    mov eax,7
    syscall
    cmp rax,-4
    je xwf_poll_retry
    test rax,rax
    js public_span_fail
    jz xwf_tick_done
    mov edi,5
    lea rsi,[rbp+XF_INPUT]
    mov edx,64
    call view_read_all
    test rax,rax
    jz xwf_control_closed
    cmp rax,1
    jne public_span_fail
    mov rax,0x31303051544c5848 /* HXLTQ001 */
    cmp [rbp+XF_INPUT],rax
    jne public_span_fail
    mov rax,[rbp+XF_SEQUENCE]
    inc rax
    jz public_span_fail
    cmp [rbp+XF_INPUT+8],rax
    jne public_span_fail
    mov [rbp+XF_SEQUENCE],rax
    mov rax,[rbp+XF_INPUT+16]
    cmp rax,1
    jb public_span_fail
    cmp rax,4
    ja public_span_fail
    mov [rbp+XF_OPERATION],rax
    mov rax,[rbp+XF_INPUT+24]
    cmp rax,3
    ja public_span_fail
    mov [rbp+XF_SLOT],rax
    mov rdx,[rbp+XF_INPUT+32]
    cmp rdx,3072
    ja public_span_fail
    mov [rbp+XF_PAYLOAD_LENGTH],rdx
    mov rax,[rbp+XF_INPUT+40]
    or rax,[rbp+XF_INPUT+48]
    or rax,[rbp+XF_INPUT+56]
    jnz public_span_fail
    mov edi,5
    lea rsi,[rbp+XF_PAYLOAD]
    call view_read_all
    cmp rax,1
    jne public_span_fail
    mov qword ptr [rbp+XF_OUTPUT],0
    mov qword ptr [rbp+XF_OUTPUT_LENGTH],0
    mov qword ptr [rbp+XF_PHASE],0
    mov rax,[rbp+XF_OPERATION]
    cmp rax,1
    je xwf_hold
    cmp rax,2
    je xwf_release
    cmp qword ptr [rbp+XF_SLOT],0
    jne public_span_fail
    cmp rax,4
    je xwf_cache
    cmp qword ptr [rbp+XF_PAYLOAD_LENGTH],0
    jne public_span_fail
    jmp xwf_reply
xwf_hold:
    mov rbx,[rbp+XF_SLOT]
    cmp qword ptr [rbp+rbx*8+XF_LEASES],0
    jne public_span_fail
    cmp qword ptr [rbp+XF_PAYLOAD_LENGTH],0
    je public_span_fail
    /* Exact canonical-key bytes come from the frozen local fixture inputs.
     * The actual HIA request and full state are retained on FD4. */
    lea rdi,[rbp+XF_INPUT]
    xor eax,eax
    mov ecx,8
    rep stosq
    mov rax,0x314b434f4c465248
    mov [rbp+XF_INPUT],rax
    mov qword ptr [rbp+XF_INPUT+8],1
    mov rax,[rbp+XF_PAYLOAD_LENGTH]
    mov [rbp+XF_INPUT+24],rax
    lea rdi,[rbp+XF_INPUT]
    lea rsi,[rax+64]
    call wait_fixture_lock_call
    cmp qword ptr [rdx+16],0
    jne public_span_fail
    mov rax,[rdx+24]
    test rax,rax
    jz public_span_fail
    mov [rbp+rbx*8+XF_LEASES],rax
    lea rdi,[rbp+XF_LOCK_RESULTS]
    mov rsi,rdx
    mov ecx,8
    rep movsq
    call wait_fixture_clear_lock_request
    mov qword ptr [rbp+XF_LOCK_REQUEST+8],3
    mov rax,[rbp+rbx*8+XF_LEASES]
    mov [rbp+XF_LOCK_REQUEST+16],rax
    lea rdi,[rbp+XF_LOCK_REQUEST]
    mov esi,64
    call wait_fixture_lock_call
    cmp qword ptr [rdx+16],0
    jne public_span_fail
    mov rax,[rbp+rbx*8+XF_LEASES]
    cmp [rdx+24],rax
    jne public_span_fail
    lea rdi,[rbp+XF_LOCK_RESULTS+64]
    mov rsi,rdx
    mov ecx,8
    rep movsq
    lea rax,[rbp+XF_LOCK_RESULTS]
    mov [rbp+XF_OUTPUT],rax
    mov qword ptr [rbp+XF_OUTPUT_LENGTH],128
    jmp xwf_reply
xwf_release:
    cmp qword ptr [rbp+XF_PAYLOAD_LENGTH],0
    jne public_span_fail
    mov rbx,[rbp+XF_SLOT]
    cmp qword ptr [rbp+rbx*8+XF_LEASES],0
    je public_span_fail
    call wait_fixture_drop_slot
    lea rdi,[rbp+XF_LOCK_RESULTS]
    mov rsi,rdx
    mov ecx,8
    rep movsq
    lea rax,[rbp+XF_LOCK_RESULTS]
    mov [rbp+XF_OUTPUT],rax
    mov qword ptr [rbp+XF_OUTPUT_LENGTH],64
    jmp xwf_reply
xwf_cache:
    cmp qword ptr [rbp+XF_PAYLOAD_LENGTH],48
    jb public_span_fail
    mov rax,0x3130484341435648
    cmp [rbp+XF_PAYLOAD],rax
    jne public_span_fail
    mov rax,[rbp+XF_PAYLOAD+8]
    cmp rax,1
    jb public_span_fail
    cmp rax,2
    ja public_span_fail
    lea rdi,[rbp+XF_PAYLOAD]
    mov rsi,[rbp+XF_PAYLOAD_LENGTH]
    mov r8d,32
    call runtime_grow_owned
    mov edx,eax
    cmp rax,rdx
    jne public_span_fail
    cmp eax,0xffff0000
    jae public_span_fail
    mov rdx,[r15+8]
    add rdx,32*64
    cmp [rdx+48],rax
    jne public_span_fail
    cmp [rdx+56],rax
    jne public_span_fail
    mov [rbp+XF_OUTPUT_LENGTH],rax
    mov rax,[rdx+32]
    mov [rbp+XF_OUTPUT],rax
xwf_reply:
    call wait_fixture_snapshot
    call wait_fixture_write_reply
    jmp xwf_tick_done
xwf_control_closed:
    mov qword ptr [rbp+XF_CLOSED],1
xwf_tick_done:
    xor eax,eax
    PM_RETURN

wait_fixture_clear_lock_request:
    lea rdi,[rbp+XF_LOCK_REQUEST]
    xor eax,eax
    mov ecx,8
    rep stosq
    mov rax,0x314b434f4c465248
    mov [rbp+XF_LOCK_REQUEST],rax
    ret

/* Actual Drop of the fixture-owned held lease. Shared owner operation6 performs the
 * release/reservation; the common wake hook observes its actual reply only. */
wait_fixture_drop_slot:
    sub rsp,8
    call wait_fixture_clear_lock_request
    mov qword ptr [rbp+XF_LOCK_REQUEST+8],6
    mov rax,[rbp+rbx*8+XF_LEASES]
    test rax,rax
    jz public_span_fail
    mov [rbp+XF_LOCK_REQUEST+16],rax
    lea rdi,[rbp+XF_LOCK_REQUEST]
    mov esi,64
    call wait_fixture_lock_call
    cmp qword ptr [rdx+16],0
    jne public_span_fail
    mov qword ptr [rbp+rbx*8+XF_LEASES],0
    add rsp,8
    ret

/* Fixed shared FileLockState invocation; only genuine unchanged-state growth
 * retries. FD4 event16 preserves complete request/reply/workspace for each
 * actual HIA call, including every resource continuation. */
wait_fixture_lock_call:
    PM_SAVE
    mov r13,rdi
    mov r14,rsi
    mov rbp,[r15+400]
    test rbp,rbp
    jz public_span_fail
    lea rbx,[rbp+64]
xwf_lock_retry:
    mov rdi,r13
    mov rsi,r14
    mov rdx,[rbx+24]
    mov rcx,[rbx+32]
    mov r8,[rbx+8]
    mov r9,[rbx+16]
    call qword ptr [rbx]
    mov [rbx+40],rax
    cmp rax,64
    jne public_span_fail
    mov rdx,[rbx+24]
    mov rax,0x3130524b4c465248
    cmp [rdx],rax
    jne public_span_fail
    mov rax,[r13+8]
    cmp [rdx+8],rax
    jne public_span_fail
    call pump_trace_clear_tail
    mov rax,[rbx+8]
    mov [r12+PM_TRACE_C_PTR],rax
    mov rax,[rbx+16]
    mov [r12+PM_TRACE_C_LEN],rax
    mov [r12+PM_TRACE_STATE_CAP],rax
    mov edi,16
    xor esi,esi
    mov rdx,r13
    mov rcx,r14
    mov r8,[rbx+24]
    mov r9d,64
    call pump_trace_emit
    mov rdx,[rbx+24]
    cmp qword ptr [rdx+16],2
    jne xwf_lock_done
    mov rdx,[rdx+32]
    cmp rdx,[rbx+16]
    jbe public_span_fail
    mov rdi,rbp
    mov esi,3
    mov rcx,[rbx+32]
    call runtime_text_body_shared_grow
    test eax,eax
    jnz public_span_fail
    jmp xwf_lock_retry
xwf_lock_done:
    mov rdi,rbp
    mov rsi,rdx
    call runtime_lock_wake_record
    test eax,eax
    jnz public_span_fail
    mov rdx,[rbx+24]
    mov eax,64
    PM_RETURN

/* Fixed inventory of complete mappings. A missing lazy View is represented
 * by twelve zero spans; observation never constructs it. Each record is
 * kind/slot/address/extent followed by every byte of that retained mapping. */
wait_fixture_add:
    mov rax,[rbp+XF_COUNT]
    cmp rax,32
    jae public_span_fail
    test rdx,rdx
    jz xwf_add_absent
    test rcx,rcx
    jz public_span_fail
    cmp rcx,268435456
    ja public_span_fail
    jmp xwf_add_present
xwf_add_absent:
    test rcx,rcx
    jnz public_span_fail
xwf_add_present:
    mov r8,rax
    shl r8,5
    lea r8,[rbp+r8+XF_ROWS]
    mov [r8],rdi
    mov [r8+8],rsi
    mov [r8+16],rdx
    mov [r8+24],rcx
    inc rax
    mov [rbp+XF_COUNT],rax
    add rcx,32
    jc public_span_fail
    add [rbp+XF_SNAPSHOT_LENGTH],rcx
    jc public_span_fail
    ret

wait_fixture_snapshot:
    PM_SAVE
    mov rbp,[r12+PM_WAIT_FIXTURE]
    mov qword ptr [rbp+XF_COUNT],0
    mov qword ptr [rbp+XF_SNAPSHOT_LENGTH],32
    mov edi,1
    xor esi,esi
    mov rdx,[r15+400]
    mov ecx,4096
    call wait_fixture_add
    mov edi,2
    xor esi,esi
    mov rdx,r15
    mov ecx,RG_ENGINE
    call wait_fixture_add

    mov r13,[r15+8]
    add r13,6*64
    mov edi,3
    mov esi,6
    mov rdx,r13
    mov ecx,64
    call wait_fixture_add
    mov edi,4
    mov esi,6
    mov rdx,[r13+8]
    mov rcx,[r13+16]
    call wait_fixture_add
    mov edi,5
    mov esi,6
    mov rdx,[r13+32]
    mov rcx,[r13+40]
    call wait_fixture_add

    mov r13,[r15+8]
    add r13,58*64
    mov edi,3
    mov esi,58
    mov rdx,r13
    mov ecx,64
    call wait_fixture_add
    mov edi,4
    mov esi,58
    mov rdx,[r13+8]
    mov rcx,[r13+16]
    call wait_fixture_add
    mov edi,5
    mov esi,58
    mov rdx,[r13+32]
    mov rcx,[r13+40]
    call wait_fixture_add

    mov r13,[r15+400]
    add r13,64
    mov edi,6
    mov esi,3
    mov rdx,r13
    mov ecx,64
    call wait_fixture_add
    mov edi,7
    mov esi,3
    mov rdx,[r13+8]
    mov rcx,[r13+16]
    call wait_fixture_add
    mov edi,8
    mov esi,3
    mov rdx,[r13+24]
    mov rcx,[r13+32]
    call wait_fixture_add

    mov r13,[r15+400]
    add r13,128
    mov edi,6
    mov esi,6
    mov rdx,r13
    mov ecx,64
    call wait_fixture_add
    mov edi,7
    mov esi,6
    mov rdx,[r13+8]
    mov rcx,[r13+16]
    call wait_fixture_add
    mov edi,8
    mov esi,6
    mov rdx,[r13+24]
    mov rcx,[r13+32]
    call wait_fixture_add

    mov r14,[r15+16]
    test r14,r14
    jz xwf_view_absent
    mov edi,9
    xor esi,esi
    mov rdx,r14
    mov ecx,4096
    call wait_fixture_add
    mov edi,10
    xor esi,esi
    mov rdx,[r14+8]
    mov ecx,4096
    call wait_fixture_add

    mov r13,[r14+8]
    add r13,5*64
    mov edi,11
    mov esi,5
    mov rdx,[r13+8]
    mov rcx,[r13+16]
    call wait_fixture_add
    mov edi,12
    mov esi,5
    mov rdx,[r13+24]
    mov rcx,[r13+32]
    call wait_fixture_add

    mov r13,[r14+8]
    add r13,6*64
    mov edi,11
    mov esi,6
    mov rdx,[r13+8]
    mov rcx,[r13+16]
    call wait_fixture_add
    mov edi,12
    mov esi,6
    mov rdx,[r13+24]
    mov rcx,[r13+32]
    call wait_fixture_add

    mov r13,[r14+8]
    add r13,7*64
    mov edi,11
    mov esi,7
    mov rdx,[r13+8]
    mov rcx,[r13+16]
    call wait_fixture_add
    mov edi,12
    mov esi,7
    mov rdx,[r13+24]
    mov rcx,[r13+32]
    call wait_fixture_add

    mov r13,[r14+8]
    add r13,8*64
    mov edi,11
    mov esi,8
    mov rdx,[r13+8]
    mov rcx,[r13+16]
    call wait_fixture_add
    mov edi,12
    mov esi,8
    mov rdx,[r13+24]
    mov rcx,[r13+32]
    call wait_fixture_add

    mov r13,[r14+8]
    add r13,10*64
    mov edi,11
    mov esi,10
    mov rdx,[r13+8]
    mov rcx,[r13+16]
    call wait_fixture_add
    mov edi,12
    mov esi,10
    mov rdx,[r13+24]
    mov rcx,[r13+32]
    call wait_fixture_add

    jmp xwf_view_observed
xwf_view_absent:
    mov edi,9
    xor esi,esi
    xor edx,edx
    xor ecx,ecx
    call wait_fixture_add
    mov edi,10
    xor esi,esi
    xor edx,edx
    xor ecx,ecx
    call wait_fixture_add

    mov edi,11
    mov esi,5
    xor edx,edx
    xor ecx,ecx
    call wait_fixture_add
    mov edi,12
    mov esi,5
    xor edx,edx
    xor ecx,ecx
    call wait_fixture_add

    mov edi,11
    mov esi,6
    xor edx,edx
    xor ecx,ecx
    call wait_fixture_add
    mov edi,12
    mov esi,6
    xor edx,edx
    xor ecx,ecx
    call wait_fixture_add

    mov edi,11
    mov esi,7
    xor edx,edx
    xor ecx,ecx
    call wait_fixture_add
    mov edi,12
    mov esi,7
    xor edx,edx
    xor ecx,ecx
    call wait_fixture_add

    mov edi,11
    mov esi,8
    xor edx,edx
    xor ecx,ecx
    call wait_fixture_add
    mov edi,12
    mov esi,8
    xor edx,edx
    xor ecx,ecx
    call wait_fixture_add

    mov edi,11
    mov esi,10
    xor edx,edx
    xor ecx,ecx
    call wait_fixture_add
    mov edi,12
    mov esi,10
    xor edx,edx
    xor ecx,ecx
    call wait_fixture_add

xwf_view_observed:
    mov edi,13
    xor esi,esi
    mov rdx,rbp
    mov ecx,8192
    call wait_fixture_add
    cmp qword ptr [rbp+XF_COUNT],27
    jne public_span_fail
    mov rax,0x31303053544c5848 /* HXLTS001 */
    mov [rbp+XF_SNAPSHOT_HEADER],rax
    mov qword ptr [rbp+XF_SNAPSHOT_HEADER+8],0 /* native complete mappings */
    mov qword ptr [rbp+XF_SNAPSHOT_HEADER+16],27
    xor eax,eax
    test r14,r14
    setnz al
    mov [rbp+XF_SNAPSHOT_HEADER+24],rax
    PM_RETURN

wait_fixture_write_reply:
    PM_SAVE
    mov rbp,[r12+PM_WAIT_FIXTURE]
    mov rax,0x31303052544c5848 /* HXLTR001 */
    mov [rbp+XF_REPLY],rax
    mov rax,[rbp+XF_SEQUENCE]
    mov [rbp+XF_REPLY+8],rax
    mov rax,[rbp+XF_OPERATION]
    mov [rbp+XF_REPLY+16],rax
    mov rax,[rbp+XF_SLOT]
    mov [rbp+XF_REPLY+24],rax
    mov qword ptr [rbp+XF_REPLY+32],0
    mov rax,[rbp+XF_OUTPUT_LENGTH]
    mov [rbp+XF_REPLY+40],rax
    mov rax,[rbp+XF_SNAPSHOT_LENGTH]
    mov [rbp+XF_REPLY+48],rax
    mov rax,[rbp+XF_PHASE]
    mov [rbp+XF_REPLY+56],rax
    mov rdi,[rbp+XF_FD]
    lea rsi,[rbp+XF_REPLY]
    mov edx,64
    call view_write_all
    test rax,rax
    jnz public_span_fail
    mov rdi,[rbp+XF_FD]
    mov rsi,[rbp+XF_OUTPUT]
    mov rdx,[rbp+XF_OUTPUT_LENGTH]
    call view_write_all
    test rax,rax
    jnz public_span_fail
    mov rdi,[rbp+XF_FD]
    lea rsi,[rbp+XF_SNAPSHOT_HEADER]
    mov edx,32
    call view_write_all
    test rax,rax
    jnz public_span_fail
    xor ebx,ebx
xwf_write_row:
    mov r13,rbx
    shl r13,5
    add r13,rbp
    add r13,XF_ROWS
    mov rdi,[rbp+XF_FD]
    mov rsi,r13
    mov edx,32
    call view_write_all
    test rax,rax
    jnz public_span_fail
    mov rdi,[rbp+XF_FD]
    mov rsi,[r13+16]
    mov rdx,[r13+24]
    call view_write_all
    test rax,rax
    jnz public_span_fail
    inc rbx
    cmp rbx,[rbp+XF_COUNT]
    jb xwf_write_row
    PM_RETURN

/* The public registry has really closed the writer and destroyed all handler
 * futures before this fixture-owned guard is released. Both boundaries have
 * full snapshots, with genuine owner Drop calls retained between them. */
wait_fixture_finish:
    PM_SAVE
    mov rbp,[r12+PM_WAIT_FIXTURE]
    test rbp,rbp
    jz public_span_fail
    cmp qword ptr [r12+PM_PHASE],4
    jne public_span_fail
    mov rax,[r15+400]
    cmp qword ptr [rax+XW_HUB_HEAD],0
    jne public_span_fail
    cmp qword ptr [rax+XW_HUB_COUNT],0
    jne public_span_fail
    mov qword ptr [rbp+XF_FD],4
    mov qword ptr [rbp+XF_OPERATION],90
    mov qword ptr [rbp+XF_SLOT],0
    mov qword ptr [rbp+XF_PHASE],90
    mov qword ptr [rbp+XF_OUTPUT],0
    mov qword ptr [rbp+XF_OUTPUT_LENGTH],0
    call wait_fixture_snapshot
    call wait_fixture_write_reply
    xor ebx,ebx
xwf_drop_holder:
    cmp qword ptr [rbp+rbx*8+XF_LEASES],0
    je xwf_drop_holder_next
    call wait_fixture_drop_slot
    cmp qword ptr [rdx+56],0
    jne public_span_fail
xwf_drop_holder_next:
    inc ebx
    cmp ebx,4
    jb xwf_drop_holder
    mov qword ptr [rbp+XF_OPERATION],91
    mov qword ptr [rbp+XF_PHASE],91
    call wait_fixture_snapshot
    call wait_fixture_write_reply
    mov rdi,rbp
    mov esi,12288
    mov eax,11
    syscall
    test rax,rax
    jnz public_span_fail
    mov qword ptr [r12+PM_WAIT_FIXTURE],0
    PM_RETURN
