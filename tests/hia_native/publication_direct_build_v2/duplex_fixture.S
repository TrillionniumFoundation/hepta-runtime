/* Copyright 2026 Muvon Un Limited
 * SPDX-License-Identifier: Apache-2.0
 * Fixed private two-session observer. Actual public bytes travel only through
 * owned pipes7/9. Actual publication writes use pipes8/10 via descriptors0/1.
 * FD5 selects only fixture operations; it never chooses a public child slot.
 */
.intel_syntax noprefix
.section .text
.equ DF_CO,1216
.equ DF_SID,1224
.equ DF_READ,1232
.equ DF_BUFFER,1240
.equ DF_CAP,1248
.equ DF_CLOSED,1256
.equ DF_EOF_RESULT,1264
.equ DF_DIRECT,1272
.equ DC_CONFIG,16
.equ DC_FS,24
.equ DC_HUB,32
.equ DC_PM0,40
.equ DC_PM1,48
.equ DC_PORT,56
.equ DC_SEQUENCE,64
.equ DC_OPERATION,72
.equ DC_SESSION,80
.equ DC_LENGTH,88
.equ DC_ARG0,96
.equ DC_ARG1,104
.equ DC_OUTPUT,112
.equ DC_OUTPUT_LENGTH,120
.equ DC_MODE,128
.equ DC_FINAL,136
.equ DC_SCRATCH,160
.equ DC_SCRATCH_CAP,168
.equ DC_START_TIME,176
.equ DC_INPUT,256
.equ DC_REPLY,320
.equ DC_EVENT_COUNT,448
.equ DC_EVENTS,512
.equ DC_EVENT_BYTES,64
.equ DC_EVENT_LIMIT,32

duplex_fixture_preflight:
    PM_SAVE
    call wait_fixture_preflight
    mov ebx,7
df_preflight_pipe:
    mov edi,ebx
    mov esi,3
    mov eax,72
    syscall
    test rax,rax
    js bare_fatal
    and eax,3
    mov edx,ebx
    and edx,1
    xor edx,1
    cmp eax,edx
    jne bare_fatal
    sub rsp,144
    mov edi,ebx
    mov rsi,rsp
    mov eax,5
    syscall
    test rax,rax
    jnz bare_fatal
    mov eax,[rsp+24]
    and eax,61440
    cmp eax,4096
    jne bare_fatal
    add rsp,144
    inc ebx
    cmp ebx,11
    jb df_preflight_pipe
    PM_RETURN

/* Raw process entry: the original configuration owner has already returned. */
public_span_start:
    cld
    mov rax,[rsp]
    lea r14,[rsp+rax*8+16]
    mov rbx,r15
    mov edi,4096
    call view_allocate
    cmp rax,-4095
    jae bare_fatal
    mov r13,rax
    mov rax,0x3130304346504148 /* HAPFC001 */
    mov [r13],rax
    mov qword ptr [r13+8],4096
    mov [r13+DC_CONFIG],rbx
    mov rdi,r14
    call runtime_filesystem_hub_create
    cmp rax,-4095
    jae bare_fatal
    mov [r13+DC_FS],rax
    call runtime_text_body_hub_create
    cmp rax,-4095
    jae bare_fatal
    mov [r13+DC_HUB],rax
    /* Ignore SIGPIPE exactly as the ordinary transport does. */
    mov qword ptr [r13+3072],1
    mov edi,13
    lea rsi,[r13+3072]
    xor edx,edx
    mov r10d,8
    mov eax,13
    syscall
    test rax,rax
    jnz bare_fatal
    xor ebx,ebx
df_create_session:
    mov edi,4096
    call view_allocate
    cmp rax,-4095
    jae bare_fatal
    mov r12,rax
    mov [r13+rbx*8+DC_PM0],rax
    mov [r12+DF_CO],r13
    mov [r12+DF_SID],rbx
    mov rax,[r13+DC_CONFIG]
    mov [r12+248],rax
    mov rax,[r13+DC_FS]
    mov [r12+232],rax
    mov rax,[r13+DC_HUB]
    mov [r12+224],rax
    lea rdi,[rip+grow_fixture_images]
    mov rsi,[r13+DC_CONFIG]
    call runtime_grow_create
    cmp rax,-4095
    jae public_span_fail
    mov r15,rax
    mov [r12+240],rax
    mov rax,[r13+DC_HUB]
    mov [r15+400],rax
    mov rdi,[r13+DC_FS]
    call runtime_filesystem_hub_bind
    test rax,rax
    jnz public_span_fail
    mov rdi,rbx
    mov rsi,r13
    call duplex_select
    mov rdi,[r13+DC_PORT]
    call pump_initialize_shared
    mov rax,[r12+PM_PORT]
    cmp qword ptr [r13+DC_PORT],0
    jne df_port_compare
    mov [r13+DC_PORT],rax
df_port_compare:
    cmp [r13+DC_PORT],rax
    jne public_span_fail
    call duplex_cwd_initialize
    call runtime_grow_view_ensure
    cmp rax,-4095
    jae public_span_fail
    call wait_fixture_initialize
    inc ebx
    cmp ebx,2
    jb df_create_session
    jmp duplex_control_next

/* Select one actual transport. Closed sessions retain state for observation. */
duplex_select:
    cmp rdi,1
    ja bare_fatal
    mov r12,[rsi+rdi*8+DC_PM0]
    test r12,r12
    jz bare_fatal
    cmp [r12+DF_SID],rdi
    jne public_span_fail
    cmp [r12+DF_CO],rsi
    jne public_span_fail
    mov r15,[r12+240]
    cmp qword ptr [r12+DF_CLOSED],0
    jne df_select_done
    lea r8,[rdi*2+7]
    mov rdi,r8
    xor esi,esi
    mov eax,33
    syscall
    test rax,rax
    jnz public_span_fail
    lea rdi,[r8+1]
    mov esi,1
    mov eax,33
    syscall
    cmp rax,1
    jne public_span_fail
df_select_done:
    ret

duplex_cwd_initialize:
    PM_SAVE
    mov edi,4096
    call view_allocate
    cmp rax,-4095
    jae public_span_fail
    mov rbx,rax
    mov ebp,4096
df_cwd_retry:
    lea rdi,[rbx+32]
    lea rsi,[rbp-32]
    mov eax,79
    syscall
    cmp rax,-34
    je df_cwd_grow
    cmp rax,-4095
    jae public_span_fail
    cmp rax,2
    jb public_span_fail
    cmp rax,rbp
    ja public_span_fail
    dec rax
    mov [rbx+16],rax
    lea rsi,[rax+32]
    mov rdx,0x3230305157535248
    mov [rbx],rdx
    mov qword ptr [rbx+8],1
    mov qword ptr [rbx+24],0
    mov rdi,rbx
    mov r8d,6
    call runtime_grow_owned
    cmp eax,32
    jne public_span_fail
    mov rdx,[r15+8]
    add rdx,6*64
    cmp qword ptr [rdx+56],32
    jne public_span_fail
    mov rdx,[rdx+32]
    mov rax,0x3230305257535248
    cmp [rdx],rax
    jne public_span_fail
    mov rax,[rdx+8]
    or rax,[rdx+16]
    or rax,[rdx+24]
    jnz public_span_fail
    mov [r12+DF_BUFFER],rbx
    mov [r12+DF_CAP],rbp
    PM_RETURN
df_cwd_grow:
    call public_span_grow_input
    test eax,eax
    jnz public_span_fail
    jmp df_cwd_retry

duplex_control_next:
    mov r13,[r12+DF_CO]
    mov edi,5
    lea rsi,[r13+DC_INPUT]
    mov edx,64
    call view_read_all
    cmp rax,1
    jne public_span_fail
    mov rax,0x3130305146504148 /* HAPFQ001 */
    cmp [r13+DC_INPUT],rax
    jne public_span_fail
    mov rax,[r13+DC_SEQUENCE]
    inc rax
    jz public_span_fail
    cmp [r13+DC_INPUT+8],rax
    jne public_span_fail
    mov [r13+DC_SEQUENCE],rax
    mov rax,[r13+DC_INPUT+16]
    cmp rax,1
    jb public_span_fail
    cmp rax,11
    ja public_span_fail
    mov [r13+DC_OPERATION],rax
    mov rax,[r13+DC_INPUT+24]
    cmp rax,1
    ja public_span_fail
    mov [r13+DC_SESSION],rax
    mov rdi,rax
    mov rsi,r13
    call duplex_select
    mov rax,[r13+DC_INPUT+32]
    cmp rax,16777216
    ja public_span_fail
    mov [r13+DC_LENGTH],rax
    mov rax,[r13+DC_INPUT+40]
    mov [r13+DC_ARG0],rax
    mov rax,[r13+DC_INPUT+48]
    mov [r13+DC_ARG1],rax
    cmp qword ptr [r13+DC_INPUT+56],0
    jne public_span_fail
    mov qword ptr [r13+DC_OUTPUT],0
    mov qword ptr [r13+DC_OUTPUT_LENGTH],0
    cmp qword ptr [r13+DC_LENGTH],0
    je df_control_payload_ready
    mov rdx,[r13+DC_LENGTH]
    cmp [r13+DC_SCRATCH_CAP],rdx
    jae df_control_read_payload
    add rdx,4095
    jc public_span_fail
    and rdx,-4096
    mov [r13+DC_START_TIME],rdx
    mov rdi,[r13+DC_SCRATCH]
    test rdi,rdi
    jnz df_control_grow_payload
    mov rdi,rdx
    call view_allocate
    jmp df_control_payload_allocated
df_control_grow_payload:
    mov rsi,[r13+DC_SCRATCH_CAP]
    call view_resize
df_control_payload_allocated:
    cmp rax,-4095
    jae public_span_fail
    mov [r13+DC_SCRATCH],rax
    mov rax,[r13+DC_START_TIME]
    mov [r13+DC_SCRATCH_CAP],rax
df_control_read_payload:
    mov edi,5
    mov rsi,[r13+DC_SCRATCH]
    mov rdx,[r13+DC_LENGTH]
    call view_read_all
    cmp rax,1
    jne public_span_fail
df_control_payload_ready:
    mov rax,[r13+DC_OPERATION]
    cmp rax,6
    jae direct_control
    cmp rax,2
    je df_control_cache
    cmp qword ptr [r13+DC_LENGTH],0
    jne public_span_fail
    cmp qword ptr [r13+DC_ARG1],0
    jne public_span_fail
    cmp rax,1
    je df_control_drive
    cmp qword ptr [r13+DC_ARG0],0
    jne public_span_fail
    cmp rax,3
    je df_control_snapshot
    cmp rax,4
    je df_control_drain
    cmp rax,5
    jne public_span_fail
    jmp df_control_finalize
df_control_cache:
    mov rax,[r13+DC_ARG0]
    or rax,[r13+DC_ARG1]
    jnz public_span_fail
    cmp qword ptr [r13+DC_LENGTH],48
    jb public_span_fail
    mov rdi,[r13+DC_SCRATCH]
    mov rax,0x3130484341435648
    cmp [rdi],rax
    jne public_span_fail
    mov rax,[rdi+8]
    cmp rax,1
    jb public_span_fail
    cmp rax,2
    ja public_span_fail
    mov rsi,[r13+DC_LENGTH]
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
    mov [r13+DC_OUTPUT_LENGTH],rax
    mov rax,[rdx+32]
    mov [r13+DC_OUTPUT],rax
    jmp df_control_reply
df_control_drive:
    cmp qword ptr [r13+DC_ARG0],1000
    ja public_span_fail
    call pump_clock
    mov [r13+DC_START_TIME],rax
df_control_drive_loop:
    call duplex_drive_all
    cmp qword ptr [r13+DC_ARG0],0
    je df_control_reply
    call pump_clock
    sub rax,[r13+DC_START_TIME]
    mov rcx,[r13+DC_ARG0]
    imul rcx,rcx,1000000
    cmp rax,rcx
    jae df_control_reply
    call duplex_pause
    jmp df_control_drive_loop
df_control_drain:
    call duplex_drive_all
    mov rax,[r13+DC_SESSION]
    mov rax,[r13+rax*8+DC_PM0]
    cmp qword ptr [rax+PM_PHASE],4
    je df_control_reply
    call duplex_pause
    jmp df_control_drain
df_control_snapshot:
    jmp df_control_reply
df_control_finalize:
    call direct_finalize_admit
    mov rax,[r13+DC_PM0]
    cmp qword ptr [rax+PM_PHASE],4
    jne public_span_fail
    mov rax,[r13+DC_PM1]
    cmp qword ptr [rax+PM_PHASE],4
    jne public_span_fail
    cmp qword ptr [r13+DC_FINAL],0
    jne public_span_fail
    xor edi,edi
    mov rsi,r13
    call duplex_select
    call pump_finish_runtime
    mov rax,[r13+DC_PM1]
    mov qword ptr [rax+PM_PORT],0
    mov qword ptr [rax+PM_WAKE],-1
    mov qword ptr [r13+DC_PORT],0
    mov qword ptr [r13+DC_FINAL],1
df_control_reply:
    mov rdi,[r13+DC_SESSION]
    mov rsi,r13
    call duplex_select
    call duplex_write_reply
    call direct_after_reply
    cmp qword ptr [r13+DC_FINAL],1
    je duplex_destroy
    jmp duplex_control_next

/* A bounded host turn never awaits one session while starving the other. */
duplex_drive_all:
    PM_SAVE
    mov r13,[r12+DF_CO]
    xor ebx,ebx
df_drive_next:
    mov rdi,rbx
    mov rsi,r13
    call duplex_select
    call duplex_service_current
    call direct_tick
    inc ebx
    cmp ebx,2
    jb df_drive_next
    PM_RETURN
duplex_pause:
    xor edi,edi
    xor esi,esi
    mov edx,1
    mov eax,7
    syscall
    cmp rax,-4
    je duplex_pause
    test rax,rax
    jnz public_span_fail
    ret

/* The complete ordinary framing loop below is mechanically retained. Its
 * blocking wait returns to the two-session coordinator; EOF starts the same
 * registry transition and remains pending until actual writer/service close. */
duplex_service_current:
    PM_SAVE
    mov rbx,[r12+DF_BUFFER]
    mov rbp,[r12+DF_CAP]
    cmp qword ptr [r12+PM_PHASE],4
    je df_service_return
    cmp qword ptr [r12+PM_PHASE],0
    jne df_service_drain
    jmp df_span_scan
df_span_next:
    cmp qword ptr [r12 + 40], 0
    jne df_span_finish
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
df_span_scan:
    call pump_tick
    cmp qword ptr [r12 + PM_BARRIER], 0
    jne df_span_wait_input
    mov rcx, [r12 + 8]
    mov rdx, [r12]
    cmp rdx, rbp
    ja public_span_fail
df_span_scan_byte:
    cmp rcx, rdx
    jae df_span_need_input
    cmp byte ptr [rbx + rcx], 10
    je df_span_line
    inc rcx
    jmp df_span_scan_byte
df_span_line:
    mov rsi, rcx
    inc rcx
    mov [r12 + 16], rcx
    cmp qword ptr [r12 + 48], 0
    jne df_span_discard_end
    cmp rcx, 16777216 /* The target limit includes the terminating LF. */
    ja df_span_discard_end
    test rsi, rsi
    jz df_span_next
    cmp byte ptr [rbx + rsi - 1], 13
    jne df_span_line_ready
    dec rsi
df_span_line_ready:
    test rsi, rsi
    jz df_span_next
    jmp df_span_request
df_span_discard_end:
    mov qword ptr [r12 + 48], 0
    jmp df_span_next
df_span_need_input:
    mov [r12 + 8], rcx
    cmp qword ptr [r12 + 24], 0
    jne df_span_final_line
    cmp qword ptr [r12 + 48], 0
    jne df_span_discard_buffer
    cmp rdx, 16777216
    jae df_span_begin_discard
    cmp rdx, rbp
    jne df_span_read
    call public_span_grow_input
    test eax, eax
    jnz public_span_fail
    mov rdx, [r12]
df_span_read:
    lea rsi, [rbx + rdx]
    mov rcx, rbp
    sub rcx, rdx
    cmp rcx, 65536
    jbe df_span_read_size
    mov ecx, 65536
df_span_read_size:
    mov rdx, rcx
    xor edi, edi
    xor eax, eax
    syscall
    cmp rax, -4
    je df_span_scan
    cmp rax, -11
    je df_span_wait_input
    test rax, rax
    js public_span_fail
    jz df_span_input_eof
    add [r12+DF_READ],rax
    jc public_span_fail
    add [r12], rax
    jc public_span_fail
    jmp df_span_scan
df_span_wait_input:
    jmp df_service_return
df_span_begin_discard:
    mov qword ptr [r12 + 48], 1
df_span_discard_buffer:
    /* A rejected frame is consumed through its LF without retaining its tail. */
    mov qword ptr [r12], 0
    mov qword ptr [r12 + 8], 0
    mov qword ptr [r12 + 16], 0
    xor edx, edx
    jmp df_span_read
df_span_input_eof:
    mov qword ptr [r12 + 24], 1
    jmp df_span_scan
df_span_final_line:
    /* AsyncRwTransport discards an unterminated trailing message.
     * JsonRpcMessageCodec.decode_eof is a separate contract. */
    jmp df_span_finish
df_span_request:
    mov rdi, rbx
    /* Target compatibility removes one leading UTF-8 BOM from a complete
     * frame. The limit above already counted these bytes and the final LF. */
    cmp rsi, 3
    jb df_span_request_ready
    cmp byte ptr [rdi], 239
    jne df_span_request_ready
    cmp byte ptr [rdi + 1], 187
    jne df_span_request_ready
    cmp byte ptr [rdi + 2], 191
    jne df_span_request_ready
    add rdi, 3
    sub rsi, 3
    jz df_span_next
df_span_request_ready:
    call pump_accept
    jmp df_span_next

df_span_finish:
    call pump_begin_finish
df_service_drain:
    call pump_tick
    cmp qword ptr [r12+PM_PHASE],2
    jb df_service_return
    cmp qword ptr [r12+PM_SEND_HEAD],0
    jne df_service_return
    call pump_finish_service
    cmp qword ptr [r12+PM_PHASE],4
    jne public_span_fail
    call public_span_connection_eof
    test eax,eax
    jnz public_span_fail
    mov rax,[r12+248]
    mov rax,[rax+CG_PUBLIC_EOF_EXIT]
    mov [r12+DF_EOF_RESULT],rax
    mov rax,[r12+DF_SID]
    lea rdi,[rax*2+8]
    mov eax,3
    syscall
    cmp rax,-4
    je df_service_output_closed
    test rax,rax
    jnz public_span_fail
df_service_output_closed:
    xor edi,edi
    mov eax,3
    syscall
    cmp rax,-4
    je df_service_input_duplicate_closed
    test rax,rax
    jnz public_span_fail
df_service_input_duplicate_closed:
    mov rax,[r12+DF_SID]
    lea rdi,[rax*2+7]
    mov eax,3
    syscall
    cmp rax,-4
    je df_service_input_closed
    test rax,rax
    jnz public_span_fail
df_service_input_closed:
    mov qword ptr [r12+DF_CLOSED],1
df_service_return:
    mov [r12+DF_BUFFER],rbx
    mov [r12+DF_CAP],rbp
    xor eax,eax
    PM_RETURN

/* Append-only observations come from the actual admitted await context after
 * full HIA completion/detach. No count can complete or cancel a future. */
duplex_observe_future:
    PM_SAVE
    mov rbp,rdi
    mov r14,[rbp+PN_P_CONTEXT]
    test r14,r14
    jz df_observe_done
    mov rax,PA_MAGIC
    cmp [r14],rax
    jne public_span_fail
    cmp [r14+PA_NODE],rbp
    jne public_span_fail
    cmp [r14+16],r15
    jne public_span_fail
    mov r13,[r12+DF_CO]
    mov rcx,[r13+DC_EVENT_COUNT]
    cmp rcx,DC_EVENT_LIMIT
    ja public_span_fail
    xor ebx,ebx
df_observe_find:
    cmp rbx,rcx
    jae df_observe_new
    mov rax,rbx
    shl rax,6
    lea rdx,[r13+rax+DC_EVENTS]
    mov rax,[r14+PA_POOL]
    cmp [rdx],rax
    jne df_observe_next
    mov rax,[r14+PA_JOB]
    cmp [rdx+8],rax
    jne df_observe_next
    cmp [rdx+16],r15
    jne public_span_fail
    mov rax,[r14+PA_TAG]
    cmp [rdx+24],rax
    jne public_span_fail
    jmp df_observe_stage
df_observe_next:
    inc rbx
    jmp df_observe_find
df_observe_new:
    cmp rbx,DC_EVENT_LIMIT
    jae public_span_fail
    mov rax,rbx
    shl rax,6
    lea rdx,[r13+rax+DC_EVENTS]
    mov rax,[r14+PA_POOL]
    mov [rdx],rax
    mov rax,[r14+PA_JOB]
    mov [rdx+8],rax
    mov [rdx+16],r15
    mov rax,[r14+PA_TAG]
    mov [rdx+24],rax
    mov rax,[r12+PM_TRACE_SEQUENCE]
    mov [rdx+40],rax
    inc qword ptr [r13+DC_EVENT_COUNT]
df_observe_stage:
    mov rax,[r14+PA_STAGE]
    cmp rax,1
    jb public_span_fail
    cmp rax,3
    ja public_span_fail
    cmp [rdx+32],rax
    je df_observe_done
    cmp qword ptr [rdx+32],1
    ja public_span_fail
    mov [rdx+32],rax
    cmp rax,1
    je df_observe_done
    mov rcx,[r12+PM_TRACE_SEQUENCE]
    cmp rax,2
    jne df_observe_drop
    mov [rdx+48],rcx
    jmp df_observe_done
df_observe_drop:
    mov [rdx+56],rcx
df_observe_done:
    PM_RETURN

/* Header, borrowed result, complete coordinator and both complete PM pages.
 * Observe/finalize additionally retain both complete existing27-mapping
 * snapshots. Nothing is read from already retired owner mappings. */
duplex_write_reply:
    PM_SAVE
    mov r13,[r12+DF_CO]
    mov qword ptr [r13+DC_REPLY+48],0
    cmp qword ptr [r13+DC_OPERATION],3
    je df_reply_snapshots
    cmp qword ptr [r13+DC_OPERATION],5
    jne df_reply_header
df_reply_snapshots:
    xor ebx,ebx
df_reply_snapshot_prepare:
    mov rdi,rbx
    mov rsi,r13
    call duplex_select
    mov r14,[r12+PM_WAIT_FIXTURE]
    mov rax,[r13+DC_SEQUENCE]
    mov [r14+XF_SEQUENCE],rax
    mov rax,[r13+DC_OPERATION]
    mov [r14+XF_OPERATION],rax
    mov [r14+XF_SLOT],rbx
    mov rax,[r12+PM_PHASE]
    mov [r14+XF_PHASE],rax
    mov qword ptr [r14+XF_OUTPUT],0
    mov qword ptr [r14+XF_OUTPUT_LENGTH],0
    call wait_fixture_snapshot
    mov rax,[r14+XF_SNAPSHOT_LENGTH]
    add rax,64
    jc public_span_fail
    add [r13+DC_REPLY+48],rax
    jc public_span_fail
    inc ebx
    cmp ebx,2
    jb df_reply_snapshot_prepare
df_reply_header:
    mov rdi,[r13+DC_SESSION]
    mov rsi,r13
    call duplex_select
    mov rax,0x3130305246504148 /* HAPFR001 */
    mov [r13+DC_REPLY],rax
    mov rax,[r13+DC_SEQUENCE]
    mov [r13+DC_REPLY+8],rax
    mov rax,[r13+DC_OPERATION]
    mov [r13+DC_REPLY+16],rax
    mov rax,[r13+DC_SESSION]
    mov [r13+DC_REPLY+24],rax
    mov qword ptr [r13+DC_REPLY+32],0
    mov rax,[r13+DC_OUTPUT_LENGTH]
    mov [r13+DC_REPLY+40],rax
    mov rax,[r13+DC_EVENT_COUNT]
    mov [r13+DC_REPLY+56],rax
    mov rax,[r13+DC_PM0]
    mov rdx,[rax+PM_PHASE]
    mov [r13+DC_REPLY+64],rdx
    mov rdx,[rax+PM_PENDING]
    mov [r13+DC_REPLY+80],rdx
    mov rdx,[rax+DF_READ]
    mov [r13+DC_REPLY+96],rdx
    mov rax,[r13+DC_PM1]
    mov rdx,[rax+PM_PHASE]
    mov [r13+DC_REPLY+72],rdx
    mov rdx,[rax+PM_PENDING]
    mov [r13+DC_REPLY+88],rdx
    mov rdx,[rax+DF_READ]
    mov [r13+DC_REPLY+104],rdx
    mov rax,[r13+DC_FINAL]
    mov [r13+DC_REPLY+112],rax
    mov qword ptr [r13+DC_REPLY+120],12288
    mov edi,5
    lea rsi,[r13+DC_REPLY]
    mov edx,128
    call view_write_all
    test rax,rax
    jnz public_span_fail
    mov edi,5
    mov rsi,[r13+DC_OUTPUT]
    mov rdx,[r13+DC_OUTPUT_LENGTH]
    call view_write_all
    test rax,rax
    jnz public_span_fail
    mov edi,5
    mov rsi,r13
    mov edx,4096
    call view_write_all
    test rax,rax
    jnz public_span_fail
    xor ebx,ebx
df_reply_pm:
    mov edi,5
    mov rsi,[r13+rbx*8+DC_PM0]
    mov edx,4096
    call view_write_all
    test rax,rax
    jnz public_span_fail
    inc ebx
    cmp ebx,2
    jb df_reply_pm
    cmp qword ptr [r13+DC_REPLY+48],0
    je df_reply_done
    xor ebx,ebx
df_reply_snapshot_write:
    mov rdi,rbx
    mov rsi,r13
    call duplex_select
    call wait_fixture_write_reply
    inc ebx
    cmp ebx,2
    jb df_reply_snapshot_write
df_reply_done:
    mov rdi,[r13+DC_SESSION]
    mov rsi,r13
    call duplex_select
    PM_RETURN

/* Release only after both services and the actual process runtime have ended.
 * The original configuration EOF still owns its own complete finalization. */
duplex_destroy:
    mov r13,[r12+DF_CO]
    cmp qword ptr [r13+DC_FINAL],1
    jne public_span_fail
    xor ebx,ebx
df_destroy_session:
    mov rdi,rbx
    mov rsi,r13
    call duplex_select
    cmp qword ptr [r12+PM_PHASE],4
    jne public_span_fail
    cmp qword ptr [r12+DF_CLOSED],1
    jne public_span_fail
    call pump_finish_storage
    call runtime_extract_body_release
    test rax,rax
    jnz public_span_fail
    call runtime_batch_body_release
    test rax,rax
    jnz public_span_fail
    call runtime_text_body_release
    test rax,rax
    jnz public_span_fail
    call runtime_text_create_release
    test rax,rax
    jnz public_span_fail
    call runtime_grow_fence_release
    test rax,rax
    jnz public_span_fail
    call runtime_grow_view_release
    test rax,rax
    jnz public_span_fail
    call runtime_grow_destroy
    test rax,rax
    jnz public_span_fail
    mov qword ptr [r12+240],0
    mov rdi,[r12+PM_WAIT_FIXTURE]
    mov esi,12288
    mov eax,11
    syscall
    test rax,rax
    jnz bare_fatal
    mov rdi,[r12+DF_BUFFER]
    mov rsi,[r12+DF_CAP]
    add rsi,4096
    jc bare_fatal
    mov eax,11
    syscall
    test rax,rax
    jnz bare_fatal
    mov rax,[r12+DF_EOF_RESULT]
    or [r13+248],rax
    mov rdi,r12
    mov esi,8192
    mov eax,11
    syscall
    test rax,rax
    jnz bare_fatal
    inc ebx
    cmp ebx,2
    jb df_destroy_session
    mov rdi,[r13+DC_HUB]
    call runtime_text_body_hub_destroy
    test rax,rax
    jnz bare_fatal
    mov rdi,[r13+DC_FS]
    call runtime_filesystem_hub_destroy
    test rax,rax
    jnz bare_fatal
    mov rdi,[r13+DC_SCRATCH]
    test rdi,rdi
    jz df_destroy_scratch_done
    mov rsi,[r13+DC_SCRATCH_CAP]
    add rsi,4096
    jc bare_fatal
    mov eax,11
    syscall
    test rax,rax
    jnz bare_fatal
df_destroy_scratch_done:
    mov r15,[r13+DC_CONFIG]
    mov rax,[r13+248]
    mov [r15+CG_PUBLIC_EOF_EXIT],rax
    mov rdi,r13
    mov esi,8192
    mov eax,11
    syscall
    test rax,rax
    jnz bare_fatal
    jmp frame_eof
