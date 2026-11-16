/* Private task mappings and fixed current-SDK registry boundary. HIA owns
 * typed-ID policy; public input cannot select operations, tags or addresses. */
.intel_syntax noprefix
.section .text
.equ PM_SCRATCH,256
.equ PM_SCRATCH_CAP,264
.equ PM_PORT,272
.equ PM_JOURNAL,280
.equ PM_WAKE,288
.equ PM_ALL,296
.equ PM_SEND_HEAD,304
.equ PM_SEND_TAIL,312
.equ PM_CURRENT,320
.equ PM_PHASE,328
.equ PM_EPOCH,336
.equ PM_BARRIER,344
.equ PM_IN_FLAGS,352
.equ PM_OUT_FLAGS,360
.equ PM_TIME,368
.equ PM_BORROW,384
.equ PM_READY_COPY,416
.equ PM_READY_CAP,424
.equ PM_READY_LEN,432
.equ PM_NODE_SEQUENCE,440
.equ PM_REG_REPLY,512
.equ PM_TRACE_FD,712
.equ PM_TRACE_SEQUENCE,720
.equ PM_POLL,768
.equ PM_PENDING,816
.equ PM_FLAGS_SET,832
.equ PM_JOURNAL_OWNED,848
.equ PM_DRAIN_START,880
.equ PM_TRACE_HEADER,1024
.equ PM_TRACE_A_PTR,1152
.equ PM_TRACE_B_PTR,1160
.equ PM_TRACE_C_PTR,1168
.equ PM_TRACE_C_LEN,1176
.equ PM_TRACE_STATE_CAP,1184
.equ PN_NEXT,8
.equ PN_SEND_NEXT,16
.equ PN_STATE,24
.equ PN_GENERATION,32
.equ PN_TAG,40
.equ PN_JOB,48
.equ PN_SEQUENCE,56
.equ PN_INPUT,64
.equ PN_INPUT_LENGTH,72
.equ PN_INPUT_CAPACITY,80
.equ PN_DESCRIPTOR,88
.equ PN_CONTINUATION,152
.equ PN_OWNERSHIP,216
.equ PN_SENT,224
.equ PN_KIND,232
.equ PN_EXTENT,240
.equ PN_LF,248
.equ PN_PUBLICATION,256
.equ PN_BOOTSTRAP,384
.equ PN_ENGINE,392
.equ PN_HOST_GENERATION,400
.equ PN_BEFORE_MODE,408
.equ PN_TOKEN_CANCELLED,416
.equ PN_FUTURE_DROPPED,424
.equ PN_SEND_PHASE,448
.equ PN_WRITE_RESULT,456
.equ PN_WRITE_KIND,464
.macro PM_SAVE
    push rbp
    push rbx
    push r13
    push r14
    sub rsp,8
.endm
.macro PM_RETURN
    add rsp,8
    pop r14
    pop r13
    pop rbx
    pop rbp
    ret
.endm

/* Validate inherited fixture capabilities at the raw process entry, before
 * configuration or any owner can open a different object on an absent FD. */
pump_fixture_preflight:
    mov edi,3
    mov esi,1
    mov eax,72
    syscall
    test rax,rax
    js bare_fatal
    mov edi,3
    mov esi,3
    mov eax,72
    syscall
    test rax,rax
    js bare_fatal
    and eax,3
    test eax,eax
    jz bare_fatal
.if PM_FIXED_TRACE_FD
    mov edi,4
    mov esi,1
    mov eax,72
    syscall
    test rax,rax
    js bare_fatal
    mov edi,4
    mov esi,3
    mov eax,72
    syscall
    test rax,rax
    js bare_fatal
    and eax,3
    test eax,eax
    jz bare_fatal
.endif
    ret

/* One process-owned fixed port. All future sessions must share this handle. */
pump_initialize:
    PM_SAVE
    mov qword ptr [r12+PM_EPOCH],1
    mov qword ptr [r12+PM_TRACE_FD],-1
    mov qword ptr [r12+PM_JOURNAL],-1
    mov qword ptr [r12+PM_WAKE],-1
    xor edi,edi
    mov esi,3
    mov eax,72
    syscall
    test rax,rax
    js public_span_fail
    mov [r12+PM_IN_FLAGS],rax
    mov edx,eax
    or edx,2048
    xor edi,edi
    mov esi,4
    mov eax,72
    syscall
    test rax,rax
    jnz public_span_fail
    or qword ptr [r12+PM_FLAGS_SET],1
    mov edi,1
    mov esi,3
    mov eax,72
    syscall
    test rax,rax
    js public_span_fail
    mov [r12+PM_OUT_FLAGS],rax
    mov edx,eax
    or edx,2048
    mov edi,1
    mov esi,4
    mov eax,72
    syscall
    test rax,rax
    jnz public_span_fail
    or qword ptr [r12+PM_FLAGS_SET],2
.if PM_FIXED_FIXTURE_FDS
    mov edi,3
    mov esi,1
    mov eax,72
    syscall
    test rax,rax
    js public_span_fail
    mov edi,3
    mov esi,3
    mov eax,72
    syscall
    test rax,rax
    js public_span_fail
    and eax,3
    test eax,eax
    jz public_span_fail
    mov qword ptr [r12+PM_JOURNAL],3
    /* The separate trace fixture requires fixed inherited FD4. The journal
     * fixture never probes FD4 after owners have started opening files. */
.if PM_FIXED_TRACE_FD
    mov edi,4
    mov esi,1
    mov eax,72
    syscall
    test rax,rax
    js public_span_fail
    mov edi,4
    mov esi,3
    mov eax,72
    syscall
    test rax,rax
    js public_span_fail
    and eax,3
    test eax,eax
    jz public_span_fail
    mov qword ptr [r12+PM_TRACE_FD],4
.endif
.else
    mov edi,-100
    lea rsi,[rip+pump_null_path]
    mov edx,524289
    xor r10d,r10d
    mov eax,257
    syscall
    cmp rax,-4095
    jae public_span_fail
    cmp rax,2
    jb public_span_fail
    mov [r12+PM_JOURNAL],rax
    mov qword ptr [r12+PM_JOURNAL_OWNED],1
.endif
    mov rdi,[r12+PM_JOURNAL]
    call pump_port_create
    mov rdx,rax
    shr rdx,32
    jnz pump_port_created
    cmp eax,0xffff0000
    jae public_span_fail
pump_port_created:
    test rax,rax
    jz public_span_fail
    mov [r12+PM_PORT],rax
    mov rdi,rax
    mov rsi,r15
    call pump_port_attach
    test rax,rax
    jnz public_span_fail
    mov rdi,[r12+PM_PORT]
    call pump_port_wake_fd
    cmp rax,0x7fffffff
    ja public_span_fail
    mov [r12+PM_WAKE],rax
    mov edi,12
    xor esi,esi
    xor edx,edx
    xor ecx,ecx
    xor r8d,r8d
    xor r9d,r9d
    call pump_registry
    test eax,eax
    jnz public_span_fail
    xor eax,eax
    PM_RETURN

/* Fixed op/gen/arg0/arg1/payload/extent arguments. Copy the complete current
 * child borrow before entering the registry and retain its complete reply. */
pump_registry:
    PM_SAVE
    sub rsp,64
    mov [rsp],rdi
    mov [rsp+8],rsi
    mov [rsp+16],rdx
    mov [rsp+24],rcx
    mov [rsp+32],r8
    mov [rsp+40],r9
    lea rbx,[r9+64]
    cmp rbx,r9
    jb public_span_fail
    cmp rbx,67108928
    ja public_span_fail
    mov rdi,[r12+PM_SCRATCH]
    mov rsi,[r12+PM_SCRATCH_CAP]
    cmp rbx,rsi
    jbe pump_registry_capacity
    lea rdx,[rbx+4095]
    and rdx,-4096
    mov [rsp+48],rdx
    test rdi,rdi
    jnz pump_registry_grow
    mov rdi,rdx
    call view_allocate
    jmp pump_registry_grown
pump_registry_grow:
    call view_resize
pump_registry_grown:
    cmp rax,-4095
    jae public_span_fail
    mov [r12+PM_SCRATCH],rax
    mov rdx,[rsp+48]
    mov [r12+PM_SCRATCH_CAP],rdx
pump_registry_capacity:
    mov r14,[r12+PM_SCRATCH]
    mov rax,0x323051524b545248
    mov [r14],rax
    mov rax,[rsp]
    mov [r14+8],rax
    mov rax,[r12+PM_EPOCH]
    mov [r14+16],rax
    mov rax,[rsp+8]
    mov [r14+24],rax
    mov rax,[rsp+16]
    mov [r14+32],rax
    mov rax,[rsp+24]
    mov [r14+40],rax
    mov rcx,[rsp+40]
    mov [r14+48],rcx
    mov qword ptr [r14+56],0
    mov rsi,[rsp+32]
    lea rdi,[r14+64]
    rep movsb
    mov rdi,r14
    mov rsi,rbx
    mov r8d,58
    call runtime_grow_owned
    cmp eax,192
    jne public_span_fail
    mov rdx,[r15+8]
    add rdx,58*64
    cmp qword ptr [rdx+56],192
    jne public_span_fail
    mov rsi,[rdx+32]
    mov rax,0x323053524b545248
    cmp [rsi],rax
    jne public_span_fail
    mov rax,[r12+PM_EPOCH]
    cmp [rsi+16],rax
    jne public_span_fail
    mov rax,[rsi+144]
    or rax,[rsi+152]
    or rax,[rsi+184]
    jnz public_span_fail
    lea rdi,[r12+PM_REG_REPLY]
    mov ecx,24
    rep movsq
    call pump_trace_registry
    lea rdx,[r12+PM_REG_REPLY]
    mov rax,[rdx+8]
    add rsp,64
    PM_RETURN

pump_connection_mode:
    mov rax,[r15+8]
    mov rax,[rax+55*64+8]
    test rax,rax
    jz pump_connection_absent
    mov rax,[rax+8]
    cmp rax,3
    ja public_span_fail
    ret
pump_connection_absent:
    xor eax,eax
    ret

/* Move the complete slot18 descriptor and continuation as a single lifetime.
 * All child borrows are settled before the frontend can return HRCMFR02. */
pump_detach_frontend:
    PM_SAVE
    mov rbp,rdi
    cmp [rbp+PN_ENGINE],r15
    jne public_span_fail
    mov rbx,[r15+8]
    add rbx,18*64
    lea r14,[r15+512+18*64]
    mov rax,[r14]
    or rax,[r14+8]
    jnz public_span_fail
    cmp qword ptr [rbx+48],64
    jne public_span_fail
    cmp qword ptr [rbx+56],64
    jb public_span_fail
    lea rdi,[rbp+PN_DESCRIPTOR]
    mov rsi,rbx
    mov ecx,8
    rep movsq
    lea rdi,[rbp+PN_CONTINUATION]
    mov rsi,r14
    mov ecx,8
    rep movsq
    xor eax,eax
    bt qword ptr [r15+64],18
    setc al
    xor edx,edx
    bt qword ptr [r15+72],18
    setc dl
    shl edx,1
    or eax,edx
    cmp eax,3
    jne public_span_fail
    mov [rbp+PN_OWNERSHIP],rax
    btr qword ptr [r15+64],18
    btr qword ptr [r15+72],18
    lea rdi,[rbx+8]
    mov ecx,7
    xor eax,eax
    rep stosq
    mov rdi,r14
    mov ecx,8
    rep stosq
    mov rdi,rbp
    call pump_trace_detached
    PM_RETURN

pump_restore_frontend:
    PM_SAVE
    mov rbp,rdi
    cmp [rbp+PN_ENGINE],r15
    jne public_span_fail
    cmp qword ptr [rbp+PN_OWNERSHIP],3
    jne public_span_fail
    mov rbx,[r15+8]
    add rbx,18*64
    mov rax,[rbp+PN_DESCRIPTOR]
    cmp [rbx],rax
    jne public_span_fail
    mov rax,[rbx+8]
    or rax,[rbx+16]
    or rax,[rbx+24]
    or rax,[rbx+32]
    or rax,[rbx+40]
    or rax,[rbx+48]
    or rax,[rbx+56]
    jnz public_span_fail
    lea r14,[r15+512+18*64]
    mov rax,[r14]
    or rax,[r14+8]
    or rax,[r14+16]
    or rax,[r14+24]
    or rax,[r14+32]
    or rax,[r14+40]
    or rax,[r14+48]
    or rax,[r14+56]
    jnz public_span_fail
    bt qword ptr [r15+64],18
    jc public_span_fail
    bt qword ptr [r15+72],18
    jc public_span_fail
    mov rdi,rbx
    lea rsi,[rbp+PN_DESCRIPTOR]
    mov ecx,8
    rep movsq
    mov rdi,r14
    lea rsi,[rbp+PN_CONTINUATION]
    mov ecx,8
    rep movsq
    bts qword ptr [r15+64],18
    bts qword ptr [r15+72],18
    mov qword ptr [rbp+PN_OWNERSHIP],0
    mov rdi,rbp
    call pump_trace_restored
    PM_RETURN

pump_find_generation:
    mov rax,[r12+PM_ALL]
pump_find_generation_loop:
    test rax,rax
    jz public_span_fail
    cmp [rax+PN_GENERATION],rdi
    je pump_find_generation_done
    mov rax,[rax+PN_NEXT]
    jmp pump_find_generation_loop
pump_find_generation_done:
    cmp [rax+PN_ENGINE],r15
    jne public_span_fail
    ret

/* RETIRE validates settled SDK state before owned physical mappings retire. */
pump_retire_node:
    PM_SAVE
    mov rbp,rdi
    cmp qword ptr [rbp+PN_OWNERSHIP],3
    jne public_span_fail
    mov rsi,[rbp+PN_GENERATION]
    test rsi,rsi
    jz pump_retire_untracked
    mov edi,8
    xor edx,edx
    xor ecx,ecx
    xor r8d,r8d
    xor r9d,r9d
    call pump_registry
    cmp eax,8
    jne public_span_fail
pump_retire_untracked:
    mov rdi,rbp
    call pump_trace_retired
    lea rbx,[r12+PM_ALL]
pump_unlink_node:
    mov rax,[rbx]
    test rax,rax
    jz public_span_fail
    cmp rax,rbp
    je pump_unlink_found
    lea rbx,[rax+PN_NEXT]
    jmp pump_unlink_node
pump_unlink_found:
    mov rax,[rbp+PN_NEXT]
    mov [rbx],rax
    mov rdi,[rbp+PN_DESCRIPTOR+8]
    mov rsi,[rbp+PN_DESCRIPTOR+16]
    add rsi,4096
    mov eax,11
    syscall
    test rax,rax
    jnz public_span_fail
    mov rdi,[rbp+PN_DESCRIPTOR+32]
    mov rsi,[rbp+PN_DESCRIPTOR+40]
    add rsi,4096
    mov eax,11
    syscall
    test rax,rax
    jnz public_span_fail
    mov rdi,[rbp+PN_INPUT]
    mov rsi,[rbp+PN_INPUT_CAPACITY]
    add rsi,4096
    mov eax,11
    syscall
    test rax,rax
    jnz public_span_fail
    mov rdi,rbp
    mov esi,8192
    mov eax,11
    syscall
    test rax,rax
    jnz public_span_fail
    xor eax,eax
    PM_RETURN

/* Best-effort restoration on an invariant failure. The ordinary close path
 * clears each bit after restoring that same open file description. */
pump_restore_fd_flags:
    test qword ptr [r12+PM_FLAGS_SET],1
    jz pump_restore_output_flags
    xor edi,edi
    mov esi,4
    mov rdx,[r12+PM_IN_FLAGS]
    mov eax,72
    syscall
    and qword ptr [r12+PM_FLAGS_SET],-2
pump_restore_output_flags:
    test qword ptr [r12+PM_FLAGS_SET],2
    jz pump_restore_flags_done
    mov edi,1
    mov esi,4
    mov rdx,[r12+PM_OUT_FLAGS]
    mov eax,72
    syscall
    and qword ptr [r12+PM_FLAGS_SET],-3
pump_restore_flags_done:
    ret

/* Fixed offsets belong to the identity-bound packed capability at slot57. */
.macro PM_PORT_EXPORT name,offset
pump_port_\name:
    mov rax,[rip+grow_fixture_images+57*8]
    add rax,\offset
    jmp rax
.endm
PM_PORT_EXPORT create,359
PM_PORT_EXPORT attach,580
PM_PORT_EXPORT detach,756
PM_PORT_EXPORT service,1481
PM_PORT_EXPORT wake_fd,1598
PM_PORT_EXPORT receive,1668
PM_PORT_EXPORT release,1845
PM_PORT_EXPORT shutdown,2000
PM_PORT_EXPORT destroy,2127
pump_null_path:
    .asciz "/dev/null"
