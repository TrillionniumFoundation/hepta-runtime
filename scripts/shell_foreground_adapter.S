/* Fixed capability bridge; all Shell policy is chosen by the four HIA owners. */
.intel_syntax noprefix
.section .text
.global _start
.type _start,@function
.extern shell_process_entry
.extern shell_io_entry
.extern shell_controller_entry
.extern f0
.equ G_ENV,0
.equ G_PID,8
.equ G_ARG,16
.equ G_DIR,24
.equ G_OUTFD,32
.equ G_ERRFD,40
.equ G_PTRACE,48
.equ G_ITRACE,56
.equ G_CTRACE,64
.equ G_CCTRACE,72
.equ G_IN,80
.equ G_INCAP,88
.equ G_INLEN,96
.equ G_CWORK,104
.equ G_CCAP,112
.equ G_COUT,120
.equ G_PCTX,128
.equ G_PWORK,136
.equ G_PCAP,144
.equ G_ICTX,152
.equ G_IWORK,160
.equ G_ICAP,168
.equ G_OUTBASE,176
.equ G_OUTPTR,184
.equ G_OUTCAP,192
.equ G_OWBASE,200
.equ G_OWPTR,208
.equ G_OWCAP,216
.equ G_PJOB,224
.equ G_IJOB,232
.equ G_NOTIFY,240
.equ G_PWAKE,248
.equ G_QPTR,256
.equ G_QCAP,264
.equ G_QLEN,272
.equ G_QPOS,280
.equ G_HAVE,288
.equ G_NEED,296
.equ G_EOF,304
.equ G_IOERR,312
.equ G_FINISHED,320
.equ G_EXIT,328
.equ G_CSEQ,336
.equ G_CRETX,344
.equ G_CACTION,352
.equ G_CRESULT,360
.equ G_CERROR,368
.equ G_CAUX,376
.equ G_INITIALIZED,384
.equ G_ENVLEN,392
.equ G_JOBSEQ,400
.equ G_PATHBASE,408
.equ G_PATHSTRIDE,416
.equ G_OUTPATH,424
.equ G_ERRPATH,432
.equ G_OUTLEN,440
.equ G_ERRLEN,448
.equ G_STARTSP,456
.equ G_CUSTODY,464
.equ G_ABORTING,472
.equ G_RAWERR,480
.equ G_PUBLISHSEQ,488
.equ G_CSLOT,496
.equ G_READY,592
.equ G_FRAME,656
.equ G_POLL,736
.equ G_TIME,768
.equ G_RECORD,800
.equ G_IOV,928
.equ G_CONTROL,1024
.equ G_LAST_EFFECT,1080
.equ G_TRACE_RECORDS,1088
.equ G_TRACEERR,1096

_start:
    cld
    mov rbp,rsp
    cmp qword ptr [rbp],3
    jne fg_usage
    mov rdi,[rbp+16]
    lea rsi,[rip+fg_option]
    call i_equal_string
    test eax,eax
    jz fg_usage
    mov esi,16384
    call i_allocate
    cmp rax,-4095
    jae fg_allocation_early
    mov r12,rax
    mov [r12+G_STARTSP],rbp
    mov rax,[rbp+24]
    mov [r12+G_ARG],rax
    mov rax,[rbp]
    lea rax,[rbp+rax*8+16]
    mov [r12+G_ENV],rax
    mov eax,39
    syscall
    mov [r12+G_PID],rax
    mov qword ptr [r12+G_DIR],-1
    mov qword ptr [r12+G_OUTFD],-1
    mov qword ptr [r12+G_ERRFD],-1
    mov qword ptr [r12+G_PTRACE],-1
    mov qword ptr [r12+G_ITRACE],-1
    mov qword ptr [r12+G_CTRACE],-1
    mov qword ptr [r12+G_CCTRACE],-1
    mov qword ptr [r12+G_NOTIFY],-1
    mov qword ptr [r12+G_PWAKE],-1
    mov qword ptr [r12+G_CUSTODY],-1
    mov qword ptr [r12+G_NEED],8
    mov esi,8192
    call i_allocate
    cmp rax,-4095
    jae fg_allocation
    mov [r12+G_PCTX],rax
    mov rbx,rax
    mov qword ptr [rbx+p_NULLFD],-1
    mov qword ptr [rbx+p_EXREAD],-1
    mov qword ptr [rbx+p_EXWRITE],-1
    mov qword ptr [rbx+p_PIDFD],-2
    mov qword ptr [rbx+p_CHILD_TOKEN],1
    mov [rbx+p_BRIDGE],r12
    mov rax,[r12+G_ENV]
    mov [rbx+p_ENVIRON],rax
    mov rax,[r12+G_PID]
    mov [rbx+p_SELF_PID],rax
    mov esi,4096
    mov r10d,33
    call p_allocate_flags
    cmp rax,-4095
    jae fg_allocation
    mov [rbx+p_AUDIT],rax
    mov esi,4096
    call i_allocate
    cmp rax,-4095
    jae fg_allocation
    mov [r12+G_ICTX],rax
    mov rbx,rax
    mov qword ptr [rbx+i_READFD],-1
    mov qword ptr [rbx+i_DIRFD],-1
    mov qword ptr [rbx+i_OUTFD],-1
    mov qword ptr [rbx+i_ERRFD],-1
    mov qword ptr [rbx+i_TRACEFD],-1
    mov qword ptr [rbx+i_AUDITFD],-1
    mov [rbx+i_BRIDGE],r12
    mov rax,[r12+G_PID]
    mov [rbx+i_PID],rax

    mov qword ptr [r12+G_TIME],1
    mov edi,13
    lea rsi,[r12+G_TIME]
    xor edx,edx
    mov r10d,8
    mov eax,13
    syscall
    test rax,rax
    js fg_io_failure
    mov qword ptr [r12+G_TIME],0
    call fg_eventfd
    test rax,rax
    js fg_io_failure
    mov [r12+G_NOTIFY],rax
    call fg_eventfd
    test rax,rax
    js fg_io_failure
    mov [r12+G_PWAKE],rax
    mov rbx,[r12+G_PCTX]
    mov [rbx+p_WAKEFD],rax
    mov esi,4096
    call i_allocate
    cmp rax,-4095
    jae fg_allocation
    mov [r12+G_PJOB],rax
    mov [rax+J_GLOBAL],r12
    mov rdx,[r12+G_PCTX]
    mov [rax+J_CONTEXT],rdx
    mov qword ptr [rax+J_KIND],1
    lea rdx,[rip+fg_process_primitive]
    mov [rax+J_FUNCTION],rdx
    mov esi,4096
    call i_allocate
    cmp rax,-4095
    jae fg_allocation
    mov [r12+G_IJOB],rax
    mov [rax+J_GLOBAL],r12
    mov rdx,[r12+G_ICTX]
    mov [rax+J_CONTEXT],rdx
    mov qword ptr [rax+J_KIND],2
    lea rdx,[rip+fg_io_primitive]
    mov [rax+J_FUNCTION],rdx
    mov esi,8192
    call i_allocate
    cmp rax,-4095
    jae fg_allocation
    mov [r12+G_QPTR],rax
    mov qword ptr [r12+G_QCAP],8192
    mov rdi,[r12+G_ARG]
    call i_string_length
    add rax,64
    jc fg_allocation
    mov [r12+G_PATHSTRIDE],rax
    mov rsi,rax
    imul rsi,rsi,6
    jo fg_allocation
    call i_allocate
    cmp rax,-4095
    jae fg_allocation
    mov [r12+G_PATHBASE],rax
    mov rdi,-100
    mov rsi,[r12+G_ARG]
    mov edx,0xb0000
    xor r10d,r10d
    mov eax,257
    syscall
    call i_normalize_fd
    test rax,rax
    js fg_io_failure
    mov [r12+G_DIR],rax
    mov edi,0
    lea rdx,[rip+fg_stdout]
    call fg_path
    mov [r12+G_OUTPATH],rdx
    mov [r12+G_OUTLEN],rax
    mov rsi,rdx
    mov edi,0
    call fg_create_file
    test rax,rax
    js fg_io_failure
    mov [r12+G_OUTFD],rax
    mov edi,1
    lea rdx,[rip+fg_stderr]
    call fg_path
    mov [r12+G_ERRPATH],rdx
    mov [r12+G_ERRLEN],rax
    mov rsi,rdx
    mov edi,0
    call fg_create_file
    test rax,rax
    js fg_io_failure
    mov [r12+G_ERRFD],rax
    mov edi,2
    lea rdx,[rip+fg_ptrace]
    call fg_path
    mov rsi,rdx
    mov edi,1
    call fg_create_file
    test rax,rax
    js fg_io_failure
    mov [r12+G_PTRACE],rax
    mov edi,3
    lea rdx,[rip+fg_itrace]
    call fg_path
    mov rsi,rdx
    mov edi,1
    call fg_create_file
    test rax,rax
    js fg_io_failure
    mov [r12+G_ITRACE],rax
    mov edi,4
    lea rdx,[rip+fg_ctrace]
    call fg_path
    mov rsi,rdx
    mov edi,1
    call fg_create_file
    test rax,rax
    js fg_io_failure
    mov [r12+G_CTRACE],rax
    mov edi,5
    lea rdx,[rip+fg_cctrace]
    call fg_path
    mov rsi,rdx
    mov edi,1
    call fg_create_file
    test rax,rax
    js fg_io_failure
    mov [r12+G_CCTRACE],rax
    mov rbx,[r12+G_PCTX]
    mov rax,[r12+G_DIR]
    mov [rbx+p_DIRECTORY],rax
    mov rax,[r12+G_OUTFD]
    mov [rbx+p_OUTLOG],rax
    mov rax,[r12+G_ERRFD]
    mov [rbx+p_ERRLOG],rax
    mov rax,[r12+G_PTRACE]
    mov [rbx+p_TRACEFD],rax
    mov rbx,[r12+G_ICTX]
    mov rax,[r12+G_DIR]
    mov [rbx+i_DIRFD],rax
    mov rax,[r12+G_OUTFD]
    mov [rbx+i_OUTFD],rax
    mov rax,[r12+G_ERRFD]
    mov [rbx+i_ERRFD],rax
    mov rax,[r12+G_ITRACE]
    mov [rbx+i_TRACEFD],rax
    mov rax,[r12+G_OUTPATH]
    mov [rbx+i_OUTPATH],rax
    mov rax,[r12+G_ERRPATH]
    mov [rbx+i_ERRPATH],rax
    mov rax,[r12+G_OUTLEN]
    mov [rbx+i_OUTLEN],rax
    mov rax,[r12+G_ERRLEN]
    mov [rbx+i_ERRLEN],rax
    mov r13,r12
    mov r12,rbx
    mov rdi,[r13+G_OUTFD]
    xor ebx,ebx
    call i_observe_capture
    mov rax,[r12+i_STATBUF+8]
    mov [r13+G_READY+40],rax
    mov rdi,[r13+G_ERRFD]
    mov ebx,1
    call i_observe_capture
    mov rax,[r12+i_STATBUF+8]
    mov [r13+G_READY+48],rax
    mov r12,r13
    mov rax,[rip+fg_ready_magic]
    mov [r12+G_READY],rax
    mov qword ptr [r12+G_READY+8],1
    mov rax,[r12+G_PID]
    mov [r12+G_READY+16],rax
    mov rax,[r12+G_OUTFD]
    mov [r12+G_READY+24],rax
    mov rax,[r12+G_ERRFD]
    mov [r12+G_READY+32],rax
    mov edi,20
    lea rsi,[r12+G_READY]
    mov edx,64
    xor ecx,ecx
    call fg_trace
    lea rsi,[r12+G_READY]
    mov edx,64
    call fg_enqueue
    mov edi,1
    call p_nonblocking
    test rax,rax
    js fg_io_failure
    call fg_flush
    xor edi,edi
    lea rsi,[r12+G_INLEN]
    mov edx,8
    call i_read_exact
    cmp eax,1
    jne fg_transport_failure

    mov rsi,[r12+G_INLEN]
    test rsi,rsi
    js fg_allocation
    cmp rsi,4096
    jae fg_input_size
    mov esi,4096
fg_input_size:
    add rsi,4095
    jc fg_allocation
    and rsi,-4096
    mov [r12+G_INCAP],rsi
    call i_allocate
    cmp rax,-4095
    jae fg_allocation
    mov [r12+G_IN],rax
    xor edi,edi
    mov rsi,rax
    mov rdx,[r12+G_INLEN]
    call i_read_exact
    cmp eax,1
    jne fg_transport_failure
    mov rsi,[r12+G_INLEN]
    add rsi,8192
    jc fg_allocation
    add rsi,4095
    jc fg_allocation
    and rsi,-4096
    test rsi,rsi
    js fg_allocation
    mov [r12+G_CCAP],rsi
    call i_allocate
    cmp rax,-4095
    jae fg_allocation
    mov [r12+G_CWORK],rax
    mov esi,4096
    call i_allocate
    cmp rax,-4095
    jae fg_allocation
    add rax,16
    mov [r12+G_COUT],rax
    xor edi,edi
    call p_nonblocking
    test rax,rax
    js fg_io_failure

fg_loop:
    cmp qword ptr [r12+G_ABORTING],0
    jne fg_fatal_competing
    mov rax,[r12+G_PCTX]
    cmp qword ptr [rax+p_ROLE],2
    je fg_invoke
    call fg_flush
    cmp qword ptr [r12+G_FINISHED],0
    jne fg_drain
    call fg_pump
fg_invoke:
    mov edi,0
    mov rsi,[r12+G_IN]
    mov rdx,[r12+G_INLEN]
    xor ecx,ecx
    call fg_trace
    mov rdi,[r12+G_COUT]
    mov rax,0x4141414141414141
    mov [rdi-16],rax
    mov [rdi-8],rax
    mov rax,0x4242424242424242
    mov [rdi+64],rax
    mov [rdi+72],rax
    mov rax,0xa7a7a7a7a7a7a7a7
    mov ecx,8
    rep stosq
    mov rdi,[r12+G_IN]
    mov rsi,[r12+G_INLEN]
    mov rdx,[r12+G_COUT]
    mov ecx,64
    mov r8,[r12+G_CWORK]
    mov r9,[r12+G_CCAP]
    call shell_controller_entry
    mov [r12+G_CRETX],rax
    mov rcx,rax
    mov edi,1
    mov rsi,[r12+G_COUT]
    sub rsi,16
    mov edx,96
    call fg_trace
    mov rdi,[r12+G_COUT]
    mov rax,0x4141414141414141
    cmp [rdi-16],rax
    jne fg_contract
    cmp [rdi-8],rax
    jne fg_contract
    mov rax,0x4242424242424242
    cmp [rdi+64],rax
    jne fg_contract
    cmp [rdi+72],rax
    jne fg_contract
    mov edi,2
    call fg_control
    mov rax,[r12+G_CRETX]
    mov rdx,rax
    shr rdx,32
    jnz fg_contract
    cmp eax,0xfffffff0
    je fg_capability
    cmp eax,64
    je fg_publish
    test eax,eax
    je fg_retire
    mov edi,2
    cmp eax,0xffffffff
    je fg_refusal
    mov edi,75
    cmp eax,0xfffffffe
    je fg_refusal
    mov edi,78
    cmp eax,0xfffffff9
    je fg_refusal
    mov edi,74
    cmp eax,0xfffffff8
    je fg_refusal
    jmp fg_contract
fg_refusal:
    mov esi,edi
    mov rdi,r12
    jmp fg_fatal

fg_capability:
    mov rbx,[r12+G_CWORK]
    mov rax,[rip+fg_effect_magic]
    cmp [rbx+256],rax
    jne fg_contract
    mov rax,[r12+G_LAST_EFFECT]
    inc rax
    jz fg_contract
    cmp [rbx+264],rax
    jne fg_contract
    mov [r12+G_LAST_EFFECT],rax
    mov rax,[rbx+304]
    or rax,[rbx+312]
    or rax,[rbx+320]
    or rax,[rbx+328]
    or rax,[rbx+336]
    or rax,[rbx+344]
    jnz fg_contract
    lea rsi,[rbx+256]
    lea rdi,[r12+G_CSLOT]
    mov ecx,12
    rep movsq
    mov rax,[r12+G_CSLOT+16]
    mov [r12+G_CACTION],rax
    cmp rax,1
    jb fg_contract
    cmp rax,13
    ja fg_contract
    mov qword ptr [r12+G_CRESULT],0
    mov qword ptr [r12+G_CERROR],0
    mov qword ptr [r12+G_CAUX],0
    mov edi,2
    lea rsi,[r12+G_CSLOT]
    mov edx,96
    xor ecx,ecx
    call fg_trace
    mov rax,[r12+G_CACTION]
    cmp rax,1
    je fg_init
    cmp rax,2
    je fg_call_process
    cmp rax,3
    je fg_dispatch_process
    cmp rax,4
    je fg_poll_process
    cmp rax,5
    je fg_call_io
    cmp rax,6
    je fg_seed
    cmp rax,7
    je fg_dispatch_io
    cmp rax,8
    je fg_poll_io
    cmp rax,9
    je fg_snapshot
    cmp rax,10
    je fg_call_outcome
    cmp rax,11
    je fg_grow_outcome
    cmp rax,12
    je fg_wait_activity
    cmp rax,13
    je fg_environment_extent
    jmp fg_contract

fg_cap_complete:
    mov rbx,[r12+G_CWORK]
    lea rsi,[rbx+256]
    lea rdi,[r12+G_CSLOT]
    mov ecx,12
    repe cmpsq
    jne fg_contract
    mov rax,[r12+G_CRESULT]
    mov [rbx+312],rax
    mov rax,[r12+G_CERROR]
    mov [rbx+320],rax
    mov qword ptr [rbx+328],0
    mov qword ptr [rbx+336],1
    mov edi,3
    lea rsi,[rbx+256]
    mov edx,96
    mov rcx,[r12+G_CRESULT]
    call fg_trace
    jmp fg_loop

fg_cap_error:
    neg rax
    cmp rax,4095
    ja fg_contract
    test rax,rax
    jz fg_contract
    mov [r12+G_CERROR],rax
    mov qword ptr [r12+G_CRESULT],0
    jmp fg_cap_complete

fg_environment_extent:
    call fg_zero_args
    mov rbx,[r12+G_ENV]
    mov eax,8
fg_environment_next:
    mov rsi,[rbx]
    test rsi,rsi
    jz fg_environment_done
    add rax,9
    jc fg_contract
fg_environment_byte:
    cmp byte ptr [rsi],0
    je fg_environment_advance
    inc rax
    jz fg_contract
    inc rsi
    jmp fg_environment_byte
fg_environment_advance:
    add rbx,8
    jmp fg_environment_next
fg_environment_done:
    mov [r12+G_ENVLEN],rax
    mov [r12+G_CRESULT],rax
    jmp fg_cap_complete

fg_init:
    cmp qword ptr [r12+G_INITIALIZED],0
    jne fg_contract
    cmp qword ptr [r12+G_CSLOT+24],1
    jne fg_contract
    cmp qword ptr [r12+G_CSLOT+40],8192
    jne fg_contract
    mov rsi,[r12+G_CSLOT+32]
    cmp rsi,65536
    jb fg_contract
    test rsi,rsi
    js fg_contract
    mov [r12+G_PCAP],rsi
    call i_allocate
    cmp rax,-4095
    jae fg_cap_error
    mov [r12+G_PWORK],rax
    mov rbx,[r12+G_PJOB]
    mov [rbx+J_WORK],rax
    mov rax,[r12+G_PCAP]
    mov [rbx+J_CAPACITY],rax
    mov rbx,[r12+G_PCTX]
    mov [rbx+p_WORK_CAP],rax
    mov esi,8192
    call i_allocate
    cmp rax,-4095
    jae fg_cap_error
    mov [r12+G_IWORK],rax
    mov rbx,[r12+G_IJOB]
    mov [rbx+J_WORK],rax
    mov qword ptr [rbx+J_CAPACITY],8192
    mov qword ptr [r12+G_ICAP],8192
    mov rbx,[r12+G_ICTX]
    mov qword ptr [rbx+i_WLEN],8192
    mov esi,4128
    call i_allocate
    cmp rax,-4095
    jae fg_cap_error
    mov [r12+G_OUTBASE],rax
    add rax,16
    mov [r12+G_OUTPTR],rax
    mov qword ptr [r12+G_OUTCAP],4096
    mov esi,160
    call i_allocate
    cmp rax,-4095
    jae fg_cap_error
    mov [r12+G_OWBASE],rax
    add rax,16
    mov [r12+G_OWPTR],rax
    mov qword ptr [r12+G_OWCAP],128
    mov rbx,[r12+G_CWORK]
    mov rax,[r12+G_PCAP]
    mov [rbx+640],rax
    mov qword ptr [rbx+648],8192
    mov qword ptr [rbx+656],4096
    mov qword ptr [rbx+664],128
    mov qword ptr [r12+G_INITIALIZED],1
    jmp fg_cap_complete

fg_call_process:
    call fg_initialized
    mov rdi,[r12+G_CSLOT+24]
    mov rsi,[r12+G_CSLOT+32]
    call fg_cspan
    mov r13,rdi
    mov r14,rsi
    mov rdi,[r12+G_CSLOT+40]
    mov esi,96
    call fg_cspan
    mov r15,rdi
    lea rax,[r13+r14]
    cmp rax,r15
    jbe fg_process_disjoint
    lea rax,[r15+96]
    cmp rax,r13
    ja fg_contract
fg_process_disjoint:
    mov al,0xa7
    mov ecx,96
    rep stosb
    mov edi,4
    mov rsi,r13
    mov rdx,r14
    xor ecx,ecx
    call fg_trace
    mov rdi,r13
    mov rsi,r14
    mov rdx,r15
    mov ecx,96
    mov r8,[r12+G_PWORK]
    mov r9,[r12+G_PCAP]
    call shell_process_entry
    mov [r12+G_CRESULT],rax
    mov edi,5
    mov rsi,r15
    mov edx,96
    mov rcx,[r12+G_CRESULT]
    call fg_trace
    mov edi,14
    mov rsi,r13
    mov rdx,r14
    mov rcx,[r12+G_CRESULT]
    call fg_trace
    jmp fg_cap_complete

fg_call_io:
    call fg_initialized
    mov rdi,[r12+G_CSLOT+24]
    mov rsi,[r12+G_CSLOT+32]
    call fg_cspan
    mov r13,rdi
    mov r14,rsi
    mov rdi,[r12+G_CSLOT+40]
    mov esi,64
    call fg_cspan
    mov r15,rdi
    lea rax,[r13+r14]
    cmp rax,r15
    jbe fg_io_disjoint
    lea rax,[r15+64]
    cmp rax,r13
    ja fg_contract
fg_io_disjoint:
    mov al,0xa7
    mov ecx,64
    rep stosb
    mov edi,6
    mov rsi,r13
    mov rdx,r14
    xor ecx,ecx
    call fg_trace
    mov rdi,r13
    mov rsi,r14
    mov rdx,r15
    mov ecx,64
    mov r8,[r12+G_IWORK]
    mov r9,[r12+G_ICAP]
    call shell_io_entry
    mov [r12+G_CRESULT],rax
    mov rbx,[r12+G_ICTX]
    mov rax,[rbx+i_WLEN]
    mov [r12+G_ICAP],rax
    mov rbx,[r12+G_CWORK]
    mov [rbx+648],rax
    mov edi,7
    mov rsi,r15
    mov edx,64
    mov rcx,[r12+G_CRESULT]
    call fg_trace
    mov edi,15
    mov rsi,r13
    mov rdx,r14
    mov rcx,[r12+G_CRESULT]
    call fg_trace
    jmp fg_cap_complete

fg_seed:
    call fg_initialized
    call fg_zero_last
    cmp qword ptr [r12+1104],0
    jne fg_contract
    mov rax,[r12+G_CSLOT+24]
    cmp rax,2
    ja fg_contract
    mov rbx,[r12+G_IJOB]
    cmp qword ptr [rbx+J_STATUS],0
    jne fg_contract
    mov rbx,[r12+G_IWORK]
    cmp qword ptr [rbx+8],1
    jne fg_contract
    cmp qword ptr [rbx+24],1
    jne fg_contract
    cmp qword ptr [rbx+264],1
    jne fg_contract
    cmp qword ptr [rbx+272],1
    jne fg_contract
    cmp qword ptr [rbx+336],0
    jne fg_contract
    mov [rbx+240],rax
    mov qword ptr [r12+1104],1
    jmp fg_cap_complete
fg_snapshot:
    call fg_initialized
    call fg_zero_args
    cmp qword ptr [r12+1104],1
    jne fg_contract
    mov rbx,[r12+G_IJOB]
    cmp qword ptr [rbx+J_STATUS],0
    jne fg_contract
    mov rbx,[r12+G_IWORK]
    mov rax,[rbx+240]
    cmp rax,2
    ja fg_contract
    mov [r12+G_CRESULT],rax
    jmp fg_cap_complete
fg_grow_outcome:
    call fg_initialized
    call fg_zero_last
    mov rbx,[r12+G_CSLOT+24]
    cmp rbx,[r12+G_OUTCAP]
    jbe fg_contract
    mov rdx,rbx
    add rdx,32
    jc fg_contract
    test rdx,rdx
    js fg_contract
    mov rdi,[r12+G_OUTBASE]
    mov rsi,[r12+G_OUTCAP]
    add rsi,32
    mov r10d,1
    xor r8d,r8d
    mov eax,25
    syscall
    cmp rax,-4095
    jae fg_cap_error
    mov [r12+G_OUTBASE],rax
    add rax,16
    mov [r12+G_OUTPTR],rax
    mov [r12+G_OUTCAP],rbx
    mov [r12+G_CRESULT],rbx
    jmp fg_cap_complete

fg_call_outcome:
    call fg_initialized
    cmp qword ptr [r12+G_CSLOT+24],4096
    jne fg_contract
    cmp qword ptr [r12+G_CSLOT+40],704
    jne fg_contract
    mov rbx,[r12+G_IJOB]
    cmp qword ptr [rbx+J_STATUS],0
    jne fg_contract
    mov r14,[r12+G_CSLOT+32]
    cmp r14,112
    jb fg_contract
    mov rax,[r12+G_ICAP]
    sub rax,4096
    cmp r14,rax
    ja fg_contract
    mov r13,[r12+G_IWORK]
    add r13,4096
    mov rdi,[r12+G_OUTBASE]
    mov al,0x41
    mov ecx,16
    rep stosb
    mov al,0xa7
    mov rcx,[r12+G_OUTCAP]
    rep stosb
    mov al,0x42
    mov ecx,16
    rep stosb
    mov rdi,[r12+G_OWBASE]
    mov al,0x51
    mov ecx,16
    rep stosb
    mov al,0xb8
    mov ecx,128
    rep stosb
    mov al,0x52
    mov ecx,16
    rep stosb
    mov edi,8
    mov rsi,r13
    mov rdx,r14
    xor ecx,ecx
    call fg_trace
    mov edi,16
    mov rsi,[r12+G_OUTBASE]
    mov rdx,[r12+G_OUTCAP]
    add rdx,32
    xor ecx,ecx
    call fg_trace
    mov edi,17
    mov rsi,[r12+G_OWBASE]
    mov edx,160
    xor ecx,ecx
    call fg_trace
    mov rdi,r13
    mov rsi,r14
    mov rdx,[r12+G_OUTPTR]
    mov rcx,[r12+G_OUTCAP]
    mov r8,[r12+G_OWPTR]
    mov r9,[r12+G_OWCAP]
    call f0
    mov [r12+G_CRESULT],rax

    mov edi,9
    mov rsi,[r12+G_OUTBASE]
    mov rdx,[r12+G_OUTCAP]
    add rdx,32
    mov rcx,[r12+G_CRESULT]
    call fg_trace
    mov edi,18
    mov rsi,[r12+G_OWBASE]
    mov edx,160
    mov rcx,[r12+G_CRESULT]
    call fg_trace
    mov edi,19
    mov rsi,r13
    mov rdx,r14
    mov rcx,[r12+G_CRESULT]
    call fg_trace
    mov rsi,[r12+G_OUTPTR]
    mov rdi,[r12+G_CWORK]
    add rdi,704
    mov ecx,5
    rep movsq
    mov rdi,[r12+G_OUTPTR]
    mov rsi,[r12+G_OUTCAP]
    mov rax,0x4141414141414141
    mov rdx,0x4242424242424242
    call fg_guards
    mov rdi,[r12+G_OWPTR]
    mov esi,128
    mov rax,0x5151515151515151
    mov rdx,0x5252525252525252
    call fg_guards
    jmp fg_cap_complete

fg_dispatch_process:
    call fg_initialized
    call fg_zero_args
    mov r13,[r12+G_PJOB]
    mov r14,[r12+G_PWORK]
    jmp fg_dispatch_common
fg_dispatch_io:
    call fg_initialized
    call fg_zero_args
    mov r13,[r12+G_IJOB]
    mov r14,[r12+G_IWORK]
fg_dispatch_common:
    cmp qword ptr [r13+J_STATUS],0
    jne fg_contract
    mov rax,[r14+304]
    or rax,[r14+312]
    or rax,[r14+320]
    or rax,[r14+328]
    or rax,[r14+336]
    or rax,[r14+344]
    jnz fg_contract
    mov rax,[r12+G_JOBSEQ]
    inc rax
    jz fg_contract
    mov [r12+G_JOBSEQ],rax
    mov [r13+J_TOKEN],rax
    mov [r13+J_WORK],r14
    lea rsi,[r14+256]
    lea rdi,[r13+J_SHADOW]
    mov ecx,12
    rep movsq
    mov edi,10
    cmp qword ptr [r13+J_KIND],1
    je fg_job_issue
    mov edi,12
fg_job_issue:
    lea rsi,[r13+J_SHADOW]
    mov edx,96
    mov rcx,[r13+J_TOKEN]
    call fg_trace
    mov rax,[r13+J_SHADOW+16]
    cmp qword ptr [r13+J_KIND],2
    je fg_io_job_choice
    mov rbx,[r13+J_CONTEXT]
    cmp qword ptr [rbx+p_ROLE],2
    je fg_job_inline
    cmp rax,13
    je fg_job_thread
    cmp rax,16
    je fg_job_thread
    cmp rax,17
    je fg_job_thread
    jmp fg_job_inline
fg_io_job_choice:
    cmp rax,1
    je fg_job_inline
    cmp rax,7
    je fg_job_inline
    jmp fg_job_thread
fg_job_thread:
    mov rdi,r13
    call fg_start_worker
    test rax,rax
    js fg_cap_error
    cmp qword ptr [r13+240],0
    jne fg_worker_trace_done
    mov qword ptr [r13+240],1
    mov eax,dword ptr [r13+J_TID]
    mov [r13+232],rax
    mov [r12+G_FRAME+8],rax
    mov rax,[r13+J_KIND]
    mov [r12+G_FRAME],rax
    mov edi,23
    lea rsi,[r12+G_FRAME]
    mov edx,16
    xor ecx,ecx
    call fg_trace
fg_worker_trace_done:
    mov qword ptr [r13+J_STATUS],1
    mov rdi,r13
    call fg_wake_job
    jmp fg_job_dispatched

fg_job_inline:
    mov rdi,r13
    call fg_run_job
    cmp qword ptr [r13+J_KIND],2
    je fg_io_grow_result
    cmp qword ptr [r13+J_SHADOW+16],5
    jne fg_job_dispatched
    mov rbx,[r13+J_CONTEXT]
    cmp qword ptr [rbx+p_ROLE],2
    je fg_fork_child_identity
    cmp qword ptr [r13+J_ERROR],0
    jne fg_job_dispatched
    cmp qword ptr [r12+G_CUSTODY],-1
    jne fg_contract
    mov rdi,[rbx+p_CHILD_PID]
    xor esi,esi
    mov eax,434
    syscall
    call i_normalize_fd
    mov [r12+G_RAWERR],rax
    mov edi,21
    xor esi,esi
    xor edx,edx
    mov rcx,rax
    call fg_trace
    mov rax,[r12+G_RAWERR]
    test rax,rax
    js fg_cap_error
    mov [r12+G_CUSTODY],rax
    jmp fg_job_dispatched
fg_fork_child_identity:
    mov eax,39
    syscall
    mov [r12+G_PID],rax
    jmp fg_job_dispatched
fg_io_grow_result:
    mov rax,[r13+J_WORK]
    mov [r12+G_IWORK],rax
    mov rbx,[r13+J_CONTEXT]
    mov rax,[rbx+i_WLEN]
    mov [r12+G_ICAP],rax
    mov [r13+J_CAPACITY],rax
fg_job_dispatched:
    mov rax,[r13+J_TOKEN]
    mov [r12+G_CRESULT],rax
    jmp fg_cap_complete

fg_poll_process:
    call fg_initialized
    call fg_zero_last
    mov r13,[r12+G_PJOB]
    mov r14,[r12+G_PWORK]
    jmp fg_poll_job
fg_poll_io:
    call fg_initialized
    call fg_zero_last
    mov r13,[r12+G_IJOB]
    mov r14,[r12+G_IWORK]
fg_poll_job:
    mov rax,[r12+G_CSLOT+24]
    test rax,rax
    jz fg_contract
    cmp rax,[r13+J_TOKEN]
    jne fg_contract
    mov rax,[r13+J_STATUS]
    cmp rax,3
    je fg_job_ready
    cmp rax,1
    je fg_cap_complete
    cmp rax,2
    je fg_cap_complete
    jmp fg_contract
fg_job_ready:
    cmp r14,[r13+J_WORK]
    jne fg_contract
    lea rsi,[r14+256]
    lea rdi,[r13+J_SHADOW]
    mov ecx,12
    repe cmpsq
    jne fg_contract
    mov rax,[r13+J_RESULT]
    mov [r14+312],rax
    mov rax,[r13+J_ERROR]
    mov [r14+320],rax
    mov rax,[r13+J_AUX]
    mov [r14+328],rax
    mov qword ptr [r14+336],1
    mov qword ptr [r13+J_STATUS],0
    mov edi,11
    cmp qword ptr [r13+J_KIND],1
    je fg_job_join_trace
    mov edi,13
fg_job_join_trace:
    lea rsi,[r14+256]
    mov edx,96
    mov rcx,[r13+J_TOKEN]
    call fg_trace
    mov qword ptr [r12+G_CRESULT],1
    jmp fg_cap_complete

fg_wait_activity:
    call fg_initialized
    cmp qword ptr [r12+G_CSLOT+40],0
    jne fg_contract
    mov rdi,[r12+G_PJOB]
    mov rsi,[r12+G_CSLOT+24]
    call fg_wait_job
    mov r13,rax
    mov rdi,[r12+G_IJOB]
    mov rsi,[r12+G_CSLOT+32]
    call fg_wait_job
    or rax,r13
    jnz fg_cap_complete
    mov rax,[r12+G_CSLOT+24]
    or rax,[r12+G_CSLOT+32]
    jz fg_contract
    call fg_pollfds
    lea rdi,[r12+G_POLL]
    mov esi,3
    xor edx,edx
    xor r10d,r10d
    mov r8d,8
    mov eax,271
    syscall
    cmp rax,-4
    je fg_cap_complete
    test rax,rax
    js fg_cap_error
    call fg_drain_notify
    call fg_flush
    call fg_pump
    jmp fg_cap_complete
fg_wait_job:
    mov rax,[rdi+J_STATUS]
    test rsi,rsi
    jnz fg_wait_live_job
    test rax,rax
    jne fg_contract
    ret
fg_wait_live_job:
    cmp rsi,[rdi+J_TOKEN]
    jne fg_contract
    cmp rax,3
    ja fg_contract
    test rax,rax
    jz fg_contract
    cmp rax,3
    sete al
    movzx eax,al
    ret
fg_pollfds:
    mov dword ptr [r12+G_POLL],0
    mov dword ptr [r12+G_POLL+4],1
    cmp qword ptr [r12+G_EOF],0
    je fg_poll_output
    mov dword ptr [r12+G_POLL],-1
fg_poll_output:
    mov dword ptr [r12+G_POLL+8],-1
    mov dword ptr [r12+G_POLL+12],4
    cmp qword ptr [r12+G_IOERR],0
    jne fg_poll_notify
    mov rax,[r12+G_QLEN]
    cmp rax,[r12+G_QPOS]
    je fg_poll_notify
    mov dword ptr [r12+G_POLL+8],1
fg_poll_notify:
    mov rax,[r12+G_NOTIFY]
    mov [r12+G_POLL+16],eax
    mov dword ptr [r12+G_POLL+20],1
    ret
fg_drain_notify:
    mov rdi,[r12+G_NOTIFY]
    lea rsi,[r12+G_TIME]
    mov edx,8
    xor eax,eax
    syscall
    cmp rax,-4
    je fg_drain_notify
    cmp rax,-11
    je fg_notify_done
    cmp rax,8
    jne fg_io_failure
fg_notify_done:
    ret

fg_control:
    push r13
    mov r13,[r12+G_IN]
    call fg_control_body
    pop r13
    ret
fg_pump:
    push r13
    mov r13,[r12+G_IN]
    call fg_pump_body
    pop r13
    ret
fg_control_body:
    mov rax, 0x3130514746485348 /* HSHFGQ01 */
    mov [r13], rax
    mov [r13 + 8], rdi
    mov qword ptr [r13 + 16], 1
    mov qword ptr [r13 + 24], 0
    mov qword ptr [r13 + 32], 0
    mov qword ptr [r12 + G_INLEN], 40
    ret
fg_pump_body:
    cmp qword ptr [r12 + G_EOF], 0
    jne fg_pump_done
    cmp qword ptr [r12 + G_IOERR], 0
    jne fg_pump_shutdown
fg_pump_read:
    xor edi, edi
    mov rsi, [r12 + G_HAVE]
    lea rsi, [r12 + rsi + G_CONTROL]
    mov rdx, [r12 + G_NEED]
    sub rdx, [r12 + G_HAVE]
    xor eax, eax
    syscall
    cmp rax, -4
    je fg_pump_read
    cmp rax, -11
    je fg_pump_done
    test rax, rax
    js fg_pump_error
    jz fg_pump_eof
    add [r12 + G_HAVE], rax
    mov rax, [r12 + G_HAVE]
    cmp rax, [r12 + G_NEED]
    jb fg_pump_read
    cmp qword ptr [r12 + G_NEED], 8
    jne fg_pump_complete
    cmp qword ptr [r12 + G_CONTROL], 40
    jne fg_pump_malformed
    mov qword ptr [r12 + G_NEED], 48
    jmp fg_pump_read
fg_pump_complete:
    lea rsi, [r12 + G_CONTROL + 8]
    mov rdi, r13
    mov ecx, 5
    rep movsq
    mov qword ptr [r12 + G_INLEN], 40
    mov qword ptr [r12 + G_HAVE], 0
    mov qword ptr [r12 + G_NEED], 8
    call fg_input_observed
fg_pump_done:
    ret
fg_pump_malformed:
    mov qword ptr [r12 + G_IOERR], -71
    jmp fg_pump_shutdown
fg_pump_error:
    mov [r12 + G_IOERR], rax
    jmp fg_pump_shutdown
fg_pump_eof:
    cmp qword ptr [r12 + G_HAVE], 0
    je fg_pump_shutdown
    mov qword ptr [r12 + G_IOERR], -71
fg_pump_shutdown:
    mov qword ptr [r12 + G_EOF], 1
    mov edi, 4
    call fg_control_body
    call fg_input_observed
    ret

fg_flush:
    cmp qword ptr [r12 + G_IOERR], 0
    jne fg_flush_done
fg_flush_more:
    mov rdx, [r12 + G_QLEN]
    sub rdx, [r12 + G_QPOS]
    jz fg_flush_empty
    mov edi, 1
    mov rsi, [r12 + G_QPTR]
    add rsi, [r12 + G_QPOS]
    mov eax, 1
    syscall
    cmp rax, -4
    je fg_flush_more
    cmp rax, -11
    je fg_flush_done
    test rax, rax
    jle fg_flush_error
    add [r12 + G_QPOS], rax
    jmp fg_flush_more
fg_flush_empty:
    mov qword ptr [r12 + G_QLEN], 0
    mov qword ptr [r12 + G_QPOS], 0
fg_flush_done:
    ret
fg_flush_error:
    mov [r12 + G_IOERR], rax
    test rax, rax
    jnz fg_flush_done
    mov qword ptr [r12 + G_IOERR], -5
    ret

fg_input_observed:
    mov edi,22
    mov rsi,[r12+G_IN]
    mov edx,40
    xor ecx,ecx
    call fg_trace
fg_input_wake:
    mov rdi,[r12+G_PWAKE]
    lea rsi,[rip+fg_one]
    mov edx,8
    mov eax,1
    syscall
    cmp rax,-4
    je fg_input_wake
    cmp rax,8
    je fg_input_wake_done
    cmp rax,-11
    jne fg_io_failure
fg_input_wake_done:
    ret

fg_enqueue:
    push rbx
    push rbp
    push r13
    mov rbx,rdx
    mov rbp,rsi
    mov r13,[r12+G_QLEN]
    add r13,rbx
    jc fg_allocation
    cmp r13,[r12+G_QCAP]
    jbe fg_queue_capacity
    mov rdx,r13
    add rdx,4095
    jc fg_allocation
    and rdx,-4096
    test rdx,rdx
    js fg_allocation
    mov rdi,[r12+G_QPTR]
    mov rsi,[r12+G_QCAP]
    mov [r12+G_QCAP],rdx
    mov r10d,1
    xor r8d,r8d
    mov eax,25
    syscall
    cmp rax,-4095
    jae fg_allocation
    mov [r12+G_QPTR],rax
fg_queue_capacity:
    mov rdi,[r12+G_QPTR]
    add rdi,[r12+G_QLEN]
    mov rsi,rbp
    mov rcx,rbx
    rep movsb
    mov [r12+G_QLEN],r13
    pop r13
    pop rbp
    pop rbx
    ret

fg_publish:
    mov rax,[r12+G_PCTX]
    cmp qword ptr [rax+p_ROLE],2
    je fg_contract
    mov rbx,[r12+G_COUT]
    mov rax,[rip+fg_descriptor_magic]
    cmp [rbx],rax
    jne fg_contract
    cmp qword ptr [rbx+16],1
    jne fg_contract
    cmp qword ptr [rbx+56],0
    jne fg_contract
    mov rax,[r12+G_PUBLISHSEQ]
    inc rax
    jz fg_contract
    cmp rax,[rbx+8]
    jne fg_contract
    mov [r12+G_PUBLISHSEQ],rax
    mov r13,[r12+G_CWORK]
    mov rdx,[r12+G_CCAP]
    cmp qword ptr [rbx+24],1
    je fg_loan_source
    cmp qword ptr [rbx+24],2
    jne fg_contract
    mov r13,[r12+G_OUTPTR]
    mov rdx,[r12+G_OUTCAP]
fg_loan_source:
    mov rax,[rbx+32]
    cmp rax,rdx
    ja fg_contract
    sub rdx,rax
    mov r14,[rbx+40]
    cmp r14,rdx
    ja fg_contract
    add r13,rax
    mov qword ptr [r12+G_FRAME],64
    mov rax,r14
    add rax,64
    jc fg_contract
    mov [r12+G_FRAME+8],rax
    lea rdi,[r12+G_FRAME+16]
    mov rsi,rbx
    mov ecx,8
    rep movsq
    lea rsi,[r12+G_FRAME]
    mov edx,80
    call fg_enqueue
    mov rsi,r13
    mov rdx,r14
    call fg_enqueue
    jmp fg_loop

fg_retire:
    mov rbx,[r12+G_PCTX]
    cmp qword ptr [rbx+p_ROLE],2
    je fg_contract
    cmp qword ptr [rbx+p_OWNED],0
    jne fg_contract
    mov rbx,[r12+G_ICTX]
    cmp qword ptr [rbx+i_READFD],-1
    jne fg_contract
    mov rdi,[r12+G_PJOB]
    call fg_stop_job
    mov rdi,[r12+G_IJOB]
    call fg_stop_job
    mov r13,r12
    mov r12,[r13+G_ICTX]
    call i_cleanup
    call i_footer
    cmp qword ptr [r12+i_TRACEERR],0
    jne fg_retire_io_bad
    cmp qword ptr [r12+i_IOERR],0
    jne fg_retire_io_bad
    mov r12,[r13+G_PCTX]
    call p_audit_footer
    cmp qword ptr [r12+p_EXIT_CODE],0
    jne fg_retire_io_bad
    mov r12,r13
    mov rdi,[r12+G_CUSTODY]
    cmp rdi,2
    jle fg_retire_no_pidfd
    mov [r12+G_FRAME],rdi
    mov eax,3
    syscall
    mov qword ptr [r12+G_CUSTODY],-1
    mov edi,25
    lea rsi,[r12+G_FRAME]
    mov edx,8
    mov rcx,rax
    call fg_trace
fg_retire_no_pidfd:
    call fg_final_footer
    mov qword ptr [r12+G_FRAME],0
    mov qword ptr [r12+G_FRAME+8],0
    lea rsi,[r12+G_FRAME]
    mov edx,16
    call fg_enqueue
    mov qword ptr [r12+G_FINISHED],1
    jmp fg_loop
fg_retire_io_bad:
    mov r12,r13
    jmp fg_transport_failure
fg_stop_job:
    push r13
    mov r13,rdi
    cmp qword ptr [r13+J_STATUS],0
    jne fg_contract
    cmp qword ptr [r13+J_THREADED],0
    je fg_stop_done
    mov qword ptr [r13+J_STATUS],4
    call fg_wake_job
fg_join_worker:
    mov edx,dword ptr [r13+J_TID]
    test edx,edx
    jz fg_worker_joined
    lea rdi,[r13+J_TID]
    xor esi,esi
    xor r10d,r10d
    xor r8d,r8d
    xor r9d,r9d
    mov eax,202
    syscall
    cmp rax,0
    je fg_join_worker
    cmp rax,-4
    je fg_join_worker
    cmp rax,-11
    je fg_join_worker
    jmp fg_contract

fg_worker_joined:
    cmp qword ptr [r13+J_STATUS],5
    jne fg_contract
    mov rdi,[r13+J_STACK]
    mov rsi,[r13+J_STACKLEN]
    mov eax,11
    syscall
    test rax,rax
    js fg_io_failure
    mov rax,[r13+J_KIND]
    mov [r12+G_FRAME],rax
    mov rax,[r13+232]
    mov [r12+G_FRAME+8],rax
    mov edi,24
    lea rsi,[r12+G_FRAME]
    mov edx,16
    xor ecx,ecx
    call fg_trace
fg_stop_done:
    pop r13
    ret
fg_drain:
    cmp qword ptr [r12+G_IOERR],0
    jne fg_drain_failed
    mov rax,[r12+G_QLEN]
    cmp rax,[r12+G_QPOS]
    je fg_normal_exit
    mov dword ptr [r12+G_POLL],1
    mov dword ptr [r12+G_POLL+4],4
    lea rdi,[r12+G_POLL]
    mov esi,1
    xor edx,edx
    xor r10d,r10d
    mov r8d,8
    mov eax,271
    syscall
    cmp rax,-4
    je fg_loop
    test rax,rax
    js fg_transport_failure
    jmp fg_loop
fg_drain_failed:
    mov qword ptr [r12+G_EXIT],74
fg_normal_exit:
    mov rdi,[r12+G_EXIT]
    mov eax,231
    syscall
    ud2

fg_initialized:
    cmp qword ptr [r12+G_INITIALIZED],1
    jne fg_contract
    ret
fg_zero_args:
    cmp qword ptr [r12+G_CSLOT+24],0
    jne fg_contract
fg_zero_last:
    mov rax,[r12+G_CSLOT+32]
    or rax,[r12+G_CSLOT+40]
    jnz fg_contract
    ret
fg_cspan:
    cmp rdi,[r12+G_CCAP]
    ja fg_contract
    mov rax,[r12+G_CCAP]
    sub rax,rdi
    cmp rsi,rax
    ja fg_contract
    add rdi,[r12+G_CWORK]
    ret
fg_guards:
    cmp [rdi-16],rax
    jne fg_contract
    cmp [rdi-8],rax
    jne fg_contract
    cmp [rdi+rsi],rdx
    jne fg_contract
    cmp [rdi+rsi+8],rdx
    jne fg_contract
    ret
fg_eventfd:
    xor edi,edi
    mov esi,0x80800
    mov eax,290
    syscall
    jmp i_normalize_fd
fg_path:
    imul rdi,[r12+G_PATHSTRIDE]
    add rdi,[r12+G_PATHBASE]
    mov rsi,[r12+G_ARG]
    call i_make_path
    mov rdx,r8
    ret
fg_create_file:
    shl edi,10
    mov edx,edi
    or edx,0xa00c1
    mov rdi,-100
    mov r10d,384
    mov eax,257
    syscall
    jmp i_normalize_fd

/* HSHFGTR1: seq,type,role,pid,tid,mono,cap-seq,action,return,
 * chunk-size,process-job,io-job,offset,total-size,zero; raw chunk follows. */
fg_trace:
    push rbx
    push rbp
    push r13
    push r14
    push r15
    sub rsp,16
    mov rbx,rdi
    mov rbp,rcx
    mov r13,rsi
    mov r14,rdx
    xor r15d,r15d
    mov rax,[r12+G_PCTX]
    mov rax,[rax+p_ROLE]
    mov [rsp+8],rax
    mov rdx,[r12+G_CTRACE]
    cmp rax,2
    jne fg_trace_fd
    mov rdx,[r12+G_CCTRACE]
fg_trace_fd:
    mov [rsp],rdx
    cmp rdx,2
    jle fg_trace_return
fg_trace_chunk:
    mov edi,1
    lea rsi,[r12+G_TIME]
    mov eax,228
    syscall
    test rax,rax
    js fg_io_failure
    mov rax,[rip+fg_trace_magic]
    mov [r12+G_RECORD],rax
    inc qword ptr [r12+G_CSEQ]
    mov rax,[r12+G_CSEQ]
    mov [r12+G_RECORD+8],rax
    mov [r12+G_RECORD+16],rbx
    mov rax,[rsp+8]
    mov [r12+G_RECORD+24],rax
    mov rax,[r12+G_PID]
    mov [r12+G_RECORD+32],rax
    mov eax,186
    syscall
    mov [r12+G_RECORD+40],rax
    mov rax,[r12+G_TIME]
    imul rax,rax,1000000000
    add rax,[r12+G_TIME+8]
    mov [r12+G_RECORD+48],rax
    xor eax,eax
    mov rdx,[r12+G_CWORK]
    test rdx,rdx
    jz fg_trace_no_controller
    mov rax,[rdx+264]
fg_trace_no_controller:
    mov [r12+G_RECORD+56],rax
    mov rax,[r12+G_CACTION]
    mov [r12+G_RECORD+64],rax
    mov [r12+G_RECORD+72],rbp

    mov rax,r14
    sub rax,r15
    cmp rax,1048576
    jbe fg_trace_chunk_size
    mov eax,1048576
fg_trace_chunk_size:
    mov [r12+G_RECORD+80],rax
    mov rdx,[r12+G_PJOB]
    mov rdx,[rdx+J_TOKEN]
    mov [r12+G_RECORD+88],rdx
    mov rdx,[r12+G_IJOB]
    mov rdx,[rdx+J_TOKEN]
    mov [r12+G_RECORD+96],rdx
    mov [r12+G_RECORD+104],r15
    mov [r12+G_RECORD+112],r14
    mov qword ptr [r12+G_RECORD+120],0
    lea rdx,[r12+G_RECORD]
    mov [r12+G_IOV],rdx
    mov qword ptr [r12+G_IOV+8],128
    lea rdx,[r13+r15]
    mov [r12+G_IOV+16],rdx
    mov [r12+G_IOV+24],rax
fg_trace_write:
    mov rdi,[rsp]
    lea rsi,[r12+G_IOV]
    mov edx,2
    mov eax,20
    syscall
    cmp rax,-4
    je fg_trace_write
    mov rdx,[r12+G_RECORD+80]
    add rdx,128
    cmp rax,rdx
    jne fg_trace_failed
    inc qword ptr [r12+G_TRACE_RECORDS]
    add r15,[r12+G_RECORD+80]
    cmp r15,r14
    jb fg_trace_chunk
fg_trace_return:
    add rsp,16
    pop r15
    pop r14
    pop r13
    pop rbp
    pop rbx
    ret
fg_trace_failed:
    mov [r12+G_TRACEERR],rax
    jmp fg_transport_failure

fg_final_footer:
    lea rdi,[r12+4096]
    xor eax,eax
    mov ecx,16
    rep stosq
    mov rax,[rip+fg_footer_magic]
    mov [r12+4096],rax
    mov rax,[r12+G_PID]
    mov [r12+4104],rax
    mov rax,[r12+G_TRACE_RECORDS]
    inc rax
    mov [r12+4112],rax
    mov rax,[r12+G_LAST_EFFECT]
    mov [r12+4120],rax
    mov rax,[r12+G_PUBLISHSEQ]
    mov [r12+4128],rax
    mov rax,[r12+G_EXIT]
    mov [r12+4136],rax
    mov rax,[r12+G_IOERR]
    mov [r12+4144],rax
    mov rax,[r12+G_CUSTODY]
    mov [r12+4152],rax
    mov rbx,[r12+G_PCTX]
    mov rax,[rbx+p_OWNED]
    mov [r12+4160],rax
    mov rax,[rbx+p_WAIT_CACHED]
    mov [r12+4200],rax
    mov rbx,[r12+G_ICTX]
    mov rax,[rbx+i_READFD]
    mov [r12+4168],rax
    mov rbx,[r12+G_PJOB]
    mov eax,dword ptr [rbx+J_TID]
    mov [r12+4176],rax
    mov rbx,[r12+G_IJOB]
    mov eax,dword ptr [rbx+J_TID]
    mov [r12+4184],rax
    mov rbx,[r12+G_IWORK]
    test rbx,rbx
    jz fg_footer_cache
    mov rax,[rbx+240]
    mov [r12+4192],rax
fg_footer_cache:
    mov edi,255
    lea rsi,[r12+4096]
    mov edx,128
    xor ecx,ecx
    call fg_trace
    ret

fg_io_failure:
    mov [r12+G_RAWERR],rax
fg_transport_failure:
    mov esi,74
    mov rdi,r12
    jmp fg_fatal
fg_contract:
    mov esi,78
    mov rdi,r12
    jmp fg_fatal
fg_allocation:
    mov esi,75
    mov rdi,r12
    jmp fg_fatal
fg_fatal:
    /* Infrastructure only; HIA ABORT_SELF never enters this path. */
    mov r12,rdi
    mov eax,1
    xchg rax,[r12+G_ABORTING]
    test rax,rax
    jnz fg_fatal_competing
    mov [r12+G_EXIT],rsi
    lea rsp,[r12+16368]
    mov rbx,[r12+G_PCTX]
    test rbx,rbx
    jz fg_fatal_record
    cmp qword ptr [rbx+p_ROLE],2
    je fg_fatal_record
    mov rdi,[r12+G_CUSTODY]
    cmp rdi,2
    jle fg_fatal_record
    mov esi,9
    xor edx,edx
    xor r10d,r10d
    mov eax,424
    syscall
    mov [r12+1112],rax
    mov rdi,[rbx+p_CHILD_PID]
    test rdi,rdi
    jle fg_fatal_record
fg_fatal_wait:
    lea rsi,[r12+1128]
    xor edx,edx
    xor r10d,r10d
    mov eax,61
    syscall
    cmp rax,-4
    je fg_fatal_wait
    mov [r12+1120],rax
    cmp rax,[rbx+p_CHILD_PID]
    je fg_fatal_retire
    cmp rax,-10
    jne fg_fatal_record
fg_fatal_retire:
    mov qword ptr [rbx+p_OWNED],0
fg_fatal_record:
    lea rdi,[r12+12288]
    xor eax,eax
    mov ecx,16
    rep stosq
    mov rax,[rip+fg_abort_magic]
    mov [r12+12288],rax
    mov rax,[r12+G_PID]
    mov [r12+12296],rax
    mov rax,[r12+G_EXIT]
    mov [r12+12304],rax
    mov rax,[r12+G_CUSTODY]
    mov [r12+12312],rax
    mov rax,[r12+1112]
    mov [r12+12320],rax
    mov rax,[r12+1120]
    mov [r12+12328],rax
    mov rax,[r12+G_RAWERR]
    mov [r12+12336],rax
    mov rax,[r12+G_CACTION]
    mov [r12+12344],rax
    mov rax,[r12+G_LAST_EFFECT]
    mov [r12+12352],rax
    mov rdi,[r12+G_CTRACE]
    test rbx,rbx
    jz fg_fatal_write
    cmp qword ptr [rbx+p_ROLE],2
    jne fg_fatal_write
    mov rdi,[r12+G_CCTRACE]
fg_fatal_write:
    cmp rdi,2
    jle fg_fatal_exit
    lea rsi,[r12+12288]
    mov edx,128
    mov eax,1
    syscall
fg_fatal_exit:
    mov rdi,[r12+G_EXIT]
    mov eax,231
    syscall
    ud2
fg_fatal_competing:
    mov edi,78
    mov eax,60
    syscall
    ud2
fg_allocation_early:
    mov edi,75
    jmp fg_early_exit
fg_usage:
    mov edi,64
fg_early_exit:
    mov eax,231
    syscall
    ud2

/* Fixed asynchronous syscall workers. No worker invokes HIA or libc. */
.equ J_STATUS,0
.equ J_TOKEN,8
.equ J_CONTEXT,16
.equ J_WORK,24
.equ J_FUNCTION,32
.equ J_GLOBAL,40
.equ J_TID,48
.equ J_STACK,56
.equ J_STACKLEN,64
.equ J_WAKE,72
.equ J_RESULT,80
.equ J_ERROR,88
.equ J_AUX,96
.equ J_THREADED,104
.equ J_CAPACITY,112
.equ J_KIND,120
.equ J_SHADOW,128

fg_process_primitive:
    push rbp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub rsp,8
    mov r12,rdi
    mov r14,rsi
    call p_effect_dispatch
    mov rax,r14
    mov rdx,[r12+p_RESULT]
    mov rcx,[r12+p_ERROR]
    mov r8,[r12+p_AUX]
    add rsp,8
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret

fg_io_primitive:
    push rbp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub rsp,8
    mov r12,rdi
    mov r14,rsi
    call i_effect_pending
    mov rax,r14
    mov rdx,[r12+i_RESULT]
    mov rcx,[r12+i_ERROR]
    xor r8d,r8d
    add rsp,8
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret

/* rdi is a private job, never a frame pointer. */
fg_run_job:
    push r12
    mov r12,rdi
    mov qword ptr [r12+J_STATUS],2
    mov rdi,[r12+J_CONTEXT]
    mov rsi,[r12+J_WORK]
    call qword ptr [r12+J_FUNCTION]
    mov [r12+J_WORK],rax
    mov [r12+J_RESULT],rdx
    mov [r12+J_ERROR],rcx
    mov [r12+J_AUX],r8
    mov qword ptr [r12+J_STATUS],3
    pop r12
    ret

fg_start_worker:
    push rbx
    push r12
    sub rsp,8
    mov r12,rdi
    cmp dword ptr [r12+J_TID],0
    jne fg_worker_already_started
    mov esi,69632
    call i_allocate
    cmp rax,-4095
    jae fg_worker_start_done
    mov [r12+J_STACK],rax
    mov qword ptr [r12+J_STACKLEN],69632
    mov rdi,rax
    mov esi,4096
    xor edx,edx
    mov eax,10
    syscall
    test rax,rax
    js fg_worker_start_done
    mov rsi,[r12+J_STACK]
    add rsi,69616
    mov [rsi],r12
    mov edi,0x350f00 /* VM|FS|FILES|SIGHAND|THREAD|SYSVSEM|PARENT_SETTID|CHILD_CLEARTID */
    lea rdx,[r12+J_TID]
    lea r10,[r12+J_TID]
    xor r8d,r8d
    mov eax,56
    syscall
    test rax,rax
    jz fg_worker_child
    test rax,rax
    js fg_worker_start_done
    mov qword ptr [r12+J_THREADED],1
fg_worker_already_started:
    xor eax,eax
fg_worker_start_done:
    add rsp,8
    pop r12
    pop rbx
    ret

fg_worker_child:
    mov r12,[rsp]
fg_worker_loop:
    mov eax,dword ptr [r12+J_STATUS]
    cmp eax,1
    je fg_worker_run
    cmp eax,4
    je fg_worker_stop
    mov edx,eax
    mov rdi,r12
    mov esi,128 /* FUTEX_WAIT_PRIVATE */
    xor r10d,r10d
    xor r8d,r8d
    xor r9d,r9d
    mov eax,202
    syscall
    jmp fg_worker_loop
fg_worker_run:
    mov rdi,r12
    call fg_run_job
    mov rax,[r12+J_GLOBAL]
    mov rdi,[rax+G_NOTIFY]
    lea rsi,[rip+fg_one]
    mov edx,8
fg_worker_notify:
    mov eax,1
    syscall
    cmp rax,-4
    je fg_worker_notify
    cmp rax,8
    je fg_worker_loop
    cmp rax,-11
    je fg_worker_loop
    mov rdi,[r12+J_GLOBAL]
    mov esi,74
    jmp fg_fatal
fg_worker_stop:
    mov qword ptr [r12+J_STATUS],5
    xor edi,edi
    mov eax,60
    syscall
    ud2

fg_wake_job:
    /* rdi points at the status futex. */
    mov esi,129 /* FUTEX_WAKE_PRIVATE */
    mov edx,1
    xor r10d,r10d
    xor r8d,r8d
    xor r9d,r9d
    mov eax,202
    syscall
    ret

p_child_contract:
    jmp p_boundary_contract

/* Fixed process primitives; HIA selects all lifecycle actions. */
.equ p_EFFECT, 256
.equ p_PLAN, 512
.equ p_PENDING, 0xfffffff0
.equ p_INVALID, 0xffffffff
.equ p_CAPACITY, 0xfffffffe
.equ p_CONTRACT, 0xfffffff9
.equ p_ROLE, 0
.equ p_ENVIRON, 8
.equ p_ADMITTED, 16
.equ p_NULLFD, 24
.equ p_EXREAD, 32
.equ p_EXWRITE, 40
.equ p_CHILD_PID, 48
.equ p_CHILD_TOKEN, 56
.equ p_SEQUENCE, 64
.equ p_FORKED, 72
.equ p_OWNED, 80
.equ p_TRACKED, 88
.equ p_CHILD_STAGE, 96
.equ p_UNUSED_CLOSED, 104
.equ p_HANDSHAKE, 112
.equ p_INPUT_LEN, 120
.equ p_INPUT_CAP, 128
.equ p_WORK_CAP, 136
.equ p_ENV_ARRAY, 144
.equ p_ENV_ARRAY_BYTES, 152
.equ p_PIDFD, 160
.equ p_CONTROL_HAVE, 168
.equ p_CONTROL_NEED, 176
.equ p_EOF_SEEN, 184
.equ p_SETUP_CLOSED, 192
.equ p_DIRECTORY, 200
.equ p_OUTLOG, 208
.equ p_ERRLOG, 216
.equ p_TRACEFD, 224
.equ p_AUDIT, 232
.equ p_ENV_DONE, 240
.equ p_NULL_DONE, 248
.equ p_CHANNEL_DONE, 256
.equ p_ACTION, 264
.equ p_RESULT, 272
.equ p_ERROR, 280
.equ p_AUX, 288
.equ p_QUEUE, 296
.equ p_QUEUE_CAP, 304
.equ p_QUEUE_LEN, 312
.equ p_QUEUE_POS, 320
.equ p_IO_ERROR, 328
.equ p_ABORTING, 336
.equ p_FINISHED, 344
.equ p_SELF_PID, 352
.equ p_EXIT_CODE, 360
.equ p_WAIT_CACHED, 368
.equ p_ENV_NEEDED, 376
.equ p_WAIT_STATUS, 384
.equ p_RAW_AUX, 392
.equ p_TIMESPEC, 400
.equ p_CLOCKBUF, 416
.equ p_SIGACTION, 448
.equ p_POLLFDS, 480
.equ p_PACKET, 512
.equ p_REPLY, 528
.equ p_FDPAIR, 544
.equ p_ARGV, 576
.equ p_TRACE_RECORD, 640
.equ p_EXEC_PATH, 784
.equ p_COMMAND_PTR, 792
.equ p_SCRIPT_PTR, 800
.equ p_ENV_COUNT, 808
.equ p_ENV_TABLE, 816
.equ p_CONTROL_BUFFER, 1024

p_effect_dispatch:
    mov rax, 0x3158465250485348 /* HSHPRFX1 */
    cmp [r14 + p_EFFECT], rax
    jne p_boundary_contract
    mov rax, [r12 + p_SEQUENCE]
    inc rax
    jz p_boundary_contract
    cmp [r14 + p_EFFECT + 8], rax
    jne p_boundary_contract
    mov [r12 + p_SEQUENCE], rax
    mov rax, [r14 + p_EFFECT + 48]
    or rax, [r14 + p_EFFECT + 56]
    or rax, [r14 + p_EFFECT + 64]
    or rax, [r14 + p_EFFECT + 72]
    or rax, [r14 + p_EFFECT + 80]
    or rax, [r14 + p_EFFECT + 88]
    jnz p_boundary_contract
    mov rax, [r14 + p_EFFECT + 16]
    mov [r12 + p_ACTION], rax
    cmp rax, 1
    jb p_boundary_contract
    cmp rax, 19
    ja p_boundary_contract
    mov qword ptr [r12 + p_RESULT], 0
    mov qword ptr [r12 + p_ERROR], 0
    mov qword ptr [r12 + p_AUX], 0
    mov qword ptr [r12 + p_RAW_AUX], 0
    xor edi, edi
    call p_trace_effect
    mov rax, [r12 + p_ACTION]
    cmp rax, 1
    je p_effect_capture
    cmp qword ptr [r12 + p_ADMITTED], 1
    jne p_boundary_contract
    cmp rax, 2
    je p_effect_environment
    cmp rax, 3
    je p_effect_null
    cmp rax, 4
    je p_effect_channel
    cmp rax, 5
    je p_effect_fork
    cmp rax, 6
    je p_effect_close_unused
    cmp rax, 7
    je p_effect_dup_stdio
    cmp rax, 8
    je p_effect_chdir
    cmp rax, 9
    je p_effect_sigpipe
    cmp rax, 10
    je p_effect_setsid
    cmp rax, 11
    je p_effect_exec
    cmp rax, 12
    je p_effect_exec_failure
    cmp rax, 13
    je p_effect_handshake
    cmp rax, 14
    je p_effect_track
    cmp rax, 15
    je p_effect_clock
    cmp rax, 16
    je p_effect_wait
    cmp rax, 17
    je p_effect_wakeup
    cmp rax, 18
    je p_effect_signal
    cmp rax, 19
    je p_effect_close_setup
    jmp p_boundary_contract

p_effect_capture:
    call p_role_before_fork
    cmp qword ptr [r12 + p_ADMITTED], 0
    jne p_boundary_contract
    cmp qword ptr [r14 + p_EFFECT + 24], 1
    jne p_boundary_contract
    call p_zero_arg12
    cmp qword ptr [r12 + p_OUTLOG], 2
    jbe p_boundary_contract
    cmp qword ptr [r12 + p_ERRLOG], 2
    jbe p_boundary_contract
    mov qword ptr [r12 + p_ADMITTED], 1
    jmp p_acknowledge

p_effect_environment:
    call p_role_before_fork
    cmp qword ptr [r12 + p_ENV_DONE], 0
    jne p_boundary_contract
    cmp qword ptr [r14 + p_EFFECT + 40], 0
    jne p_boundary_contract
    mov rdi, [r14 + p_EFFECT + 24]
    mov rsi, [r14 + p_EFFECT + 32]
    call p_check_span
    mov rbx, [r12 + p_ENVIRON]
    xor r8d, r8d
    mov r9d, 8
p_environment_measure:
    mov rsi, [rbx]
    test rsi, rsi
    jz p_environment_measured
    xor edx, edx
p_environment_length:
    cmp byte ptr [rsi + rdx], 0
    je p_environment_record_length
    inc rdx
    jmp p_environment_length
p_environment_record_length:
    add rdx, 9
    jc p_boundary_contract
    add r9, rdx
    jc p_boundary_contract
    inc r8
    add rbx, 8
    jmp p_environment_measure
p_environment_measured:
    mov [r12 + p_ENV_NEEDED], r9
    cmp r9, [r14 + p_EFFECT + 32]
    ja p_environment_capacity
    mov rdi, [r14 + p_EFFECT + 24]
    add rdi, r14
    mov [rdi], r8
    add rdi, 8
    mov rbx, [r12 + p_ENVIRON]
p_environment_copy:
    mov rsi, [rbx]
    test rsi, rsi
    jz p_environment_copied
    xor ecx, ecx
p_environment_copy_length:
    cmp byte ptr [rsi + rcx], 0
    je p_environment_copy_record
    inc rcx
    jmp p_environment_copy_length
p_environment_copy_record:
    mov [rdi], rcx
    add rdi, 8
    inc rcx
    rep movsb
    add rbx, 8
    jmp p_environment_copy
p_environment_copied:
    mov qword ptr [r12 + p_ENV_DONE], 1
    mov rax, [r12 + p_ENV_NEEDED]
    mov [r12 + p_RESULT], rax
    jmp p_acknowledge
p_environment_capacity:
    mov qword ptr [r12 + p_ERROR], 105
    mov rax, [r12 + p_ENV_NEEDED]
    mov [r12 + p_AUX], rax
    jmp p_acknowledge

p_effect_null:
    call p_role_before_fork
    call p_zero_args
    cmp qword ptr [r12 + p_ENV_DONE], 1
    jne p_boundary_contract
    cmp qword ptr [r12 + p_NULL_DONE], 0
    jne p_boundary_contract
    mov rdi, -100
    lea rsi, [rip + p_devnull]
    mov edx, 0x80000
    xor r10d, r10d
    mov eax, 257
    syscall
    mov [r12 + p_RAW_AUX], rax
    call p_normalize_fd
    test rax, rax
    js p_acknowledge_error
    mov [r12 + p_NULLFD], rax
    mov qword ptr [r12 + p_NULL_DONE], 1
    jmp p_acknowledge

p_effect_channel:
    call p_role_before_fork
    call p_zero_args
    cmp qword ptr [r12 + p_NULL_DONE], 1
    jne p_boundary_contract
    cmp qword ptr [r12 + p_CHANNEL_DONE], 0
    jne p_boundary_contract
    mov edi, 1
    mov esi, 0x80005 /* AF_UNIX, SOCK_SEQPACKET|SOCK_CLOEXEC */
    xor edx, edx
    lea r10, [r12 + p_FDPAIR]
    mov eax, 53
    syscall
    mov [r12 + p_RAW_AUX], rax
    test rax, rax
    js p_acknowledge_error
    movsxd rax, dword ptr [r12 + p_FDPAIR]
    call p_normalize_fd
    test rax, rax
    js p_channel_first_failed
    mov [r12 + p_EXREAD], rax
    movsxd rax, dword ptr [r12 + p_FDPAIR + 4]
    call p_normalize_fd
    test rax, rax
    js p_acknowledge_error
    mov [r12 + p_EXWRITE], rax
    mov qword ptr [r12 + p_CHANNEL_DONE], 1
    jmp p_acknowledge
p_channel_first_failed:
    mov rbx, rax
    mov edi, [r12 + p_FDPAIR + 4]
    mov eax, 3
    syscall
    mov rax, rbx
    jmp p_acknowledge_error

p_effect_fork:
    call p_role_before_fork
    call p_zero_args
    cmp qword ptr [r12 + p_CHANNEL_DONE], 1
    jne p_boundary_contract
    cmp qword ptr [r12 + p_FORKED], 0
    jne p_boundary_contract
    mov qword ptr [r12 + p_FORKED], 1
    mov eax, 57
    syscall
    mov [r12 + p_RAW_AUX], rax
    test rax, rax
    js p_acknowledge_error
    jz p_fork_child
    mov qword ptr [r12 + p_ROLE], 1
    mov qword ptr [r12 + p_OWNED], 1
    mov [r12 + p_CHILD_PID], rax
    mov [r12 + p_RESULT], rax
    mov rax, [r12 + p_CHILD_TOKEN]
    mov [r12 + p_AUX], rax
    jmp p_acknowledge
p_fork_child:
    mov qword ptr [r12 + p_ROLE], 2
    mov eax, 39
    syscall
    mov [r12 + p_SELF_PID], rax
    mov [r12 + p_CHILD_PID], rax
    mov rax, [r12 + p_CHILD_TOKEN]
    mov [r12 + p_AUX], rax
    jmp p_acknowledge

p_effect_close_unused:
    call p_zero_arg12
    cmp qword ptr [r12 + p_UNUSED_CLOSED], 0
    jne p_boundary_contract
    mov rax, [r14 + p_EFFECT + 24]
    cmp rax, [r12 + p_ROLE]
    jne p_boundary_contract
    cmp rax, 1
    je p_close_child_endpoint
    cmp rax, 2
    jne p_boundary_contract
    lea rdi, [r12 + p_EXREAD]
    jmp p_close_unused_endpoint
p_close_child_endpoint:
    lea rdi, [r12 + p_EXWRITE]
p_close_unused_endpoint:
    call p_close_slot
    mov qword ptr [r12 + p_UNUSED_CLOSED], 1
    jmp p_acknowledge

p_effect_dup_stdio:
    call p_role_child
    call p_zero_arg12
    cmp qword ptr [r12 + p_UNUSED_CLOSED], 1
    jne p_boundary_contract
    mov rsi, [r14 + p_EFFECT + 24]
    cmp rsi, 2
    ja p_boundary_contract
    cmp rsi, [r12 + p_CHILD_STAGE]
    jne p_boundary_contract
    mov rdi, [r12 + p_NULLFD]
    test rsi, rsi
    jz p_dup_descriptor_ready
    mov rdi, [r12 + p_OUTLOG]
    cmp rsi, 1
    je p_dup_descriptor_ready
    mov rdi, [r12 + p_ERRLOG]
p_dup_descriptor_ready:
    cmp rdi, 2
    jbe p_boundary_contract
    mov eax, 33
    syscall
    mov [r12 + p_RAW_AUX], rax
    test rax, rax
    js p_acknowledge_error
    inc qword ptr [r12 + p_CHILD_STAGE]
    jmp p_acknowledge

p_effect_chdir:
    call p_role_child
    cmp qword ptr [r12 + p_CHILD_STAGE], 3
    jne p_boundary_contract
    cmp qword ptr [r14 + p_EFFECT + 40], 0
    jne p_boundary_contract
    mov rdi, [r14 + p_EFFECT + 24]
    mov rsi, [r14 + p_EFFECT + 32]
    call p_check_cstr
    mov eax, 80
    syscall
    mov [r12 + p_RAW_AUX], rax
    test rax, rax
    js p_acknowledge_error
    mov qword ptr [r12 + p_CHILD_STAGE], 4
    jmp p_acknowledge

p_effect_sigpipe:
    call p_role_child
    call p_zero_args
    cmp qword ptr [r12 + p_CHILD_STAGE], 4
    jne p_boundary_contract
    mov edi, 13
    lea rsi, [r12 + p_SIGACTION]
    xor edx, edx
    mov r10d, 8
    mov eax, 13
    syscall
    mov [r12 + p_RAW_AUX], rax
    test rax, rax
    js p_acknowledge_error
    mov qword ptr [r12 + p_CHILD_STAGE], 5
    jmp p_acknowledge

p_effect_setsid:
    call p_role_child
    call p_zero_args
    cmp qword ptr [r12 + p_CHILD_STAGE], 5
    jne p_boundary_contract
    mov eax, 112
    syscall
    mov [r12 + p_RAW_AUX], rax
    test rax, rax
    js p_acknowledge_error
    mov [r12 + p_RESULT], rax
    mov qword ptr [r12 + p_CHILD_STAGE], 6
    jmp p_acknowledge

p_effect_exec:
    call p_role_child
    cmp qword ptr [r12 + p_CHILD_STAGE], 6
    jne p_boundary_contract
    cmp qword ptr [r14 + p_EFFECT + 40], p_PLAN
    jne p_boundary_contract
    cmp qword ptr [r14 + p_PLAN + 56], 0
    jne p_boundary_contract
    cmp qword ptr [r14 + p_PLAN], 1
    ja p_boundary_contract
    mov rdi, [r14 + p_EFFECT + 24]
    mov rsi, [r14 + p_EFFECT + 32]
    call p_check_cstr
    mov [r12 + p_EXEC_PATH], rdi
    mov rdi, [r14 + p_PLAN + 24]
    mov rsi, [r14 + p_PLAN + 32]
    call p_check_cstr
    mov [r12 + p_COMMAND_PTR], rdi
    cmp qword ptr [r14 + p_PLAN], 0
    je p_exec_script_valid
    mov rdi, [r14 + p_PLAN + 40]
    mov rsi, [r14 + p_PLAN + 48]
    call p_check_cstr
    mov [r12 + p_SCRIPT_PTR], rdi
p_exec_script_valid:
    mov rax, [r14 + p_PLAN + 16]
    mov [r12 + p_ENV_COUNT], rax
    mov rsi, rax
    shl rsi, 5
    shr rsi, 5
    cmp rsi, rax
    jne p_boundary_contract
    shl rsi, 5
    mov rdi, [r14 + p_PLAN + 8]
    call p_check_span
    mov [r12 + p_ENV_TABLE], rdi
    mov rsi, [r12 + p_ENV_COUNT]
    inc rsi
    jz p_boundary_contract
    shl rsi, 3
    cmp rsi, [r12 + p_ENV_ARRAY_BYTES]
    jbe p_exec_array_ready
    mov rbp, rsi
    cmp qword ptr [r12 + p_ENV_ARRAY_BYTES], 0
    jne p_exec_resize_array
    call p_allocate
    jmp p_exec_array_allocated
p_exec_resize_array:
    mov rdi, [r12 + p_ENV_ARRAY]
    mov rdx, rsi
    mov rsi, [r12 + p_ENV_ARRAY_BYTES]
    mov r10d, 1
    xor r8d, r8d
    mov eax, 25
    syscall
p_exec_array_allocated:
    cmp rax, -4095
    jae p_acknowledge_error
    mov [r12 + p_ENV_ARRAY], rax
    mov [r12 + p_ENV_ARRAY_BYTES], rbp
p_exec_array_ready:
    mov rbx, [r12 + p_ENV_TABLE]
    mov rbp, [r12 + p_ENV_ARRAY]
    mov r10, [r12 + p_ENV_COUNT]
p_exec_environment_entry:
    test r10, r10
    jz p_exec_environment_ready
    mov rdi, [rbx]
    mov rsi, [rbx + 8]
    call p_check_cstr
    mov [rbp], rdi
    add rbp, 8
    add rbx, 32
    dec r10
    jmp p_exec_environment_entry
p_exec_environment_ready:
    mov qword ptr [rbp], 0
    lea rax, [rip + p_sh_name]
    mov [r12 + p_ARGV], rax
    lea rax, [rip + p_dash_c]
    mov [r12 + p_ARGV + 8], rax
    mov rax, [r12 + p_COMMAND_PTR]
    mov [r12 + p_ARGV + 16], rax
    mov qword ptr [r12 + p_ARGV + 24], 0
    cmp qword ptr [r14 + p_PLAN], 0
    je p_exec_arguments_ready
    lea rax, [rip + p_bin_sh]
    mov [r12 + p_ARGV], rax
    mov rax, [r12 + p_SCRIPT_PTR]
    mov [r12 + p_ARGV + 8], rax
    lea rax, [rip + p_dash_c]
    mov [r12 + p_ARGV + 16], rax
    mov rax, [r12 + p_COMMAND_PTR]
    mov [r12 + p_ARGV + 24], rax
    mov qword ptr [r12 + p_ARGV + 32], 0
p_exec_arguments_ready:
    mov rdi, [r12 + p_EXEC_PATH]
    lea rsi, [r12 + p_ARGV]
    mov rdx, [r12 + p_ENV_ARRAY]
    mov eax, 59
    syscall
    mov [r12 + p_RAW_AUX], rax
    jmp p_acknowledge_error

p_effect_exec_failure:
    call p_role_child
    call p_zero_arg12
    mov rax, [r14 + p_EFFECT + 24]
    /* A NOEX payload of zero remains distinct from a successful channel EOF. */
    cmp rax, 4095
    ja p_boundary_contract
    bswap eax
    mov [r12 + p_PACKET], eax
    mov dword ptr [r12 + p_PACKET + 4], 0x58454f4e
p_exec_failure_write:
    mov rdi, [r12 + p_EXWRITE]
    cmp rdi, 2
    jbe p_boundary_contract
    lea rsi, [r12 + p_PACKET]
    mov edx, 8
    mov eax, 1
    syscall
    cmp rax, -4
    je p_exec_failure_write
    mov [r12 + p_RAW_AUX], rax
    cmp rax, 8
    jne p_child_contract
    mov edi, 1
    mov eax, 60
    syscall
    ud2

p_effect_handshake:
    call p_role_parent
    call p_zero_args
    cmp qword ptr [r12 + p_UNUSED_CLOSED], 1
    jne p_boundary_contract
    cmp qword ptr [r12 + p_HANDSHAKE], 0
    jne p_boundary_contract
p_handshake_read:
    mov rdi, [r12 + p_EXREAD]
    cmp rdi, 2
    jbe p_boundary_contract
    lea rsi, [r12 + p_PACKET]
    mov edx, 8
    xor eax, eax
    syscall
    mov [r12 + p_RAW_AUX], rax
    cmp rax, -4
    je p_handshake_read
    test rax, rax
    jz p_handshake_success
    cmp rax, 8
    jne p_handshake_contract
    cmp dword ptr [r12 + p_PACKET + 4], 0x58454f4e
    jne p_handshake_contract
    mov eax, [r12 + p_PACKET]
    bswap eax
    mov [r12 + p_ERROR], rax
    mov qword ptr [r12 + p_RESULT], 1
    mov qword ptr [r12 + p_HANDSHAKE], 2
    jmp p_acknowledge
p_handshake_success:
    mov qword ptr [r12 + p_HANDSHAKE], 1
    jmp p_acknowledge
p_handshake_contract:
    /* Rust reaps, then panics on a broken or short CLOEXEC channel. */
p_handshake_contract_reap:
    mov rdi, [r12 + p_CHILD_PID]
    lea rsi, [r12 + p_WAIT_STATUS]
    xor edx, edx
    xor r10d, r10d
    mov eax, 61
    syscall
    cmp rax, -4
    je p_handshake_contract_reap
    cmp rax, [r12 + p_CHILD_PID]
    je p_handshake_retire
    cmp rax, -10
    jne p_boundary_contract
p_handshake_retire:
    mov qword ptr [r12 + p_OWNED], 0
    jmp p_boundary_contract

p_effect_track:
    call p_role_parent
    call p_owned_token
    cmp qword ptr [r14 + p_EFFECT + 40], 0
    jne p_boundary_contract
    cmp qword ptr [r12 + p_HANDSHAKE], 1
    jne p_boundary_contract
    mov rax, [r14 + p_EFFECT + 32]
    cmp rax, 1
    ja p_boundary_contract
    test rax, rax
    jz p_track_record
    cmp qword ptr [r12 + p_OWNED], 1
    jne p_boundary_contract
p_track_record:
    mov [r12 + p_TRACKED], rax
    jmp p_acknowledge

p_effect_clock:
    call p_role_parent
    call p_zero_args
    mov edi, 1
    lea rsi, [r12 + p_CLOCKBUF]
    mov eax, 228
    syscall
    mov [r12 + p_RAW_AUX], rax
    test rax, rax
    js p_acknowledge_error
    mov rax, [r12 + p_CLOCKBUF]
    mov ecx, 1000000000
    mul rcx
    test rdx, rdx
    jnz p_boundary_contract
    add rax, [r12 + p_CLOCKBUF + 8]
    jc p_boundary_contract
    mov [r12 + p_RESULT], rax
    jmp p_acknowledge

p_effect_wait:
    call p_role_parent
    call p_owned_token
    cmp qword ptr [r14 + p_EFFECT + 40], 0
    jne p_boundary_contract
    mov rax, [r14 + p_EFFECT + 32]
    cmp rax, 1
    ja p_boundary_contract
    cmp qword ptr [r12 + p_WAIT_CACHED], 1
    je p_wait_cached
    cmp qword ptr [r12 + p_OWNED], 1
    jne p_wait_lost
    mov edx, 1
    sub edx, eax
    mov rdi, [r12 + p_CHILD_PID]
    lea rsi, [r12 + p_WAIT_STATUS]
    xor r10d, r10d
    mov eax, 61
    syscall
    mov [r12 + p_RAW_AUX], rax
    test rax, rax
    jz p_acknowledge
    js p_wait_error
    cmp rax, [r12 + p_CHILD_PID]
    jne p_boundary_contract
    mov qword ptr [r12 + p_WAIT_CACHED], 1
    mov qword ptr [r12 + p_OWNED], 0
    lea rdi, [r12 + p_PIDFD]
    call p_close_slot
p_wait_cached:
    mov qword ptr [r12 + p_RESULT], 1
    mov eax, [r12 + p_WAIT_STATUS]
    mov [r12 + p_AUX], rax
    jmp p_acknowledge
p_wait_error:
    cmp rax, -10
    jne p_acknowledge_error
    mov qword ptr [r12 + p_OWNED], 0
    mov qword ptr [r12 + p_WAIT_CACHED], 2
    lea rdi, [r12 + p_PIDFD]
    call p_close_slot
p_wait_lost:
    mov rax, -10
    jmp p_acknowledge_error

p_effect_signal:
    call p_role_parent
    call p_owned_token
    cmp qword ptr [r14 + p_EFFECT + 40], 9
    jne p_boundary_contract
    mov rax, [r14 + p_EFFECT + 32]
    cmp rax, 1
    je p_signal_kind_ok
    cmp rax, 2
    jne p_boundary_contract
p_signal_kind_ok:
    cmp qword ptr [r12 + p_OWNED], 1
    jne p_signal_retired
    mov rdi, [r12 + p_CHILD_PID]
    cmp rax, 1
    je p_signal_target_ready
    neg rdi
p_signal_target_ready:
    mov esi, 9
    mov eax, 62
    syscall
    jmp p_acknowledge_syscall
p_signal_retired:
    mov rax, -3
    jmp p_acknowledge_syscall

p_effect_wakeup:
    call p_role_parent
    call p_owned_token
    cmp qword ptr [r14 + p_EFFECT + 40], 0
    jne p_boundary_contract
    cmp qword ptr [r12 + p_OWNED], 1
    jne p_acknowledge
    cmp qword ptr [r12 + p_PIDFD], -2
    jne p_wake_pidfd_ready
    mov rdi, [r12 + p_CHILD_PID]
    mov esi, 2048
    mov eax, 434
    syscall
    test rax, rax
    js p_wake_without_pidfd
    call p_normalize_fd
    test rax, rax
    js p_wake_without_pidfd
    mov [r12 + p_PIDFD], rax
    jmp p_wake_pidfd_ready
p_wake_without_pidfd:
    mov qword ptr [r12 + p_PIDFD], -1
p_wake_pidfd_ready:
    call p_make_pollfds
    mov rax, [r14 + p_EFFECT + 32]
    cmp qword ptr [r12 + p_PIDFD], 0
    jge p_wake_duration_ready
    cmp rax, 10000000
    jbe p_wake_duration_ready
    mov eax, 10000000
p_wake_duration_ready:
    xor ebp, ebp
    cmp rax, -1
    je p_wake_poll
    xor edx, edx
    mov ecx, 1000000000
    div rcx
    mov [r12 + p_TIMESPEC], rax
    mov [r12 + p_TIMESPEC + 8], rdx
    lea rbp, [r12 + p_TIMESPEC]
p_wake_poll:
    lea rdi, [r12 + p_POLLFDS]
    mov esi, 3
    mov rdx, rbp
    xor r10d, r10d
    mov r8d, 8
    mov eax, 271
    syscall
    mov [r12 + p_RAW_AUX], rax
    cmp rax, -4
    je p_wake_received
    test rax, rax
    js p_acknowledge_error
p_wake_received:
    call p_drain_wake
    jmp p_acknowledge

p_effect_close_setup:
    cmp qword ptr [r12 + p_ROLE], 2
    je p_boundary_contract
    call p_zero_args
    lea rdi, [r12 + p_NULLFD]
    call p_close_slot
    lea rdi, [r12 + p_EXREAD]
    call p_close_slot
    lea rdi, [r12 + p_EXWRITE]
    call p_close_slot
    mov qword ptr [r12 + p_SETUP_CLOSED], 1
    jmp p_acknowledge

p_acknowledge_syscall:
    mov [r12 + p_RAW_AUX], rax
    test rax, rax
    js p_acknowledge_error
    mov [r12 + p_RESULT], rax
    jmp p_acknowledge
p_acknowledge_error:
    cmp rax, -4095
    jb p_boundary_contract
    neg rax
    mov [r12 + p_ERROR], rax
p_acknowledge:
    /* Only private results here; main POLL publishes the owner completion. */
    mov edi,1
    call p_trace_effect
    ret

p_role_before_fork:
    cmp qword ptr [r12 + p_ROLE], 0
    jne p_boundary_contract
    ret
p_role_parent:
    cmp qword ptr [r12 + p_ROLE], 1
    jne p_boundary_contract
    ret
p_role_child:
    cmp qword ptr [r12 + p_ROLE], 2
    jne p_boundary_contract
    ret
p_owned_token:
    mov rax, [r14 + p_EFFECT + 24]
    cmp rax, [r12 + p_CHILD_TOKEN]
    jne p_boundary_contract
    cmp qword ptr [r12 + p_FORKED], 1
    jne p_boundary_contract
    ret
p_zero_args:
    cmp qword ptr [r14 + p_EFFECT + 24], 0
    jne p_boundary_contract
p_zero_arg12:
    mov rax, [r14 + p_EFFECT + 32]
    or rax, [r14 + p_EFFECT + 40]
    jnz p_boundary_contract
    ret
p_check_span:
    cmp rdi, 4096
    jb p_boundary_contract
    mov rax, [r12 + p_WORK_CAP]
    cmp rdi, rax
    ja p_boundary_contract
    sub rax, rdi
    cmp rsi, rax
    ja p_boundary_contract
    add rdi, r14
    ret
p_check_cstr:
    inc rsi
    jz p_boundary_contract
    call p_check_span
    dec rsi
    cmp byte ptr [rdi + rsi], 0
    jne p_boundary_contract
    xor ecx, ecx
p_cstr_no_embedded_nul:
    cmp rcx, rsi
    je p_cstr_valid
    cmp byte ptr [rdi + rcx], 0
    je p_boundary_contract
    inc rcx
    jmp p_cstr_no_embedded_nul
p_cstr_valid:
    ret

p_trace_effect:
    mov [r12 + p_TRACE_RECORD + 112], rdi
    mov rax, 0x3152545250485348 /* HSHPRTR1 */
    mov [r12 + p_TRACE_RECORD], rax
    mov rax, [r12 + p_ROLE]
    mov [r12 + p_TRACE_RECORD + 8], rax
    mov rax, [r12 + p_SELF_PID]
    mov [r12 + p_TRACE_RECORD + 16], rax
    mov rax, [r12 + p_CHILD_TOKEN]
    mov [r12 + p_TRACE_RECORD + 24], rax
    mov rax, [r12 + p_SEQUENCE]
    mov [r12 + p_TRACE_RECORD + 32], rax
    mov rax, [r12 + p_ACTION]
    mov [r12 + p_TRACE_RECORD + 40], rax
    mov rax, [r14 + p_EFFECT + 24]
    mov [r12 + p_TRACE_RECORD + 48], rax
    mov rax, [r14 + p_EFFECT + 32]
    mov [r12 + p_TRACE_RECORD + 56], rax
    mov rax, [r14 + p_EFFECT + 40]
    mov [r12 + p_TRACE_RECORD + 64], rax
    mov rax, [r12 + p_RESULT]
    mov [r12 + p_TRACE_RECORD + 72], rax
    mov rax, [r12 + p_ERROR]
    mov [r12 + p_TRACE_RECORD + 80], rax
    mov rax, [r12 + p_AUX]
    mov [r12 + p_TRACE_RECORD + 88], rax
    mov rax, [r12 + p_CHILD_PID]
    mov [r12 + p_TRACE_RECORD + 96], rax
    mov rax, [r12 + p_OWNED]
    mov rdx, [r12 + p_TRACKED]
    shl rdx, 1
    or rax, rdx
    mov rdx, [r12 + p_SETUP_CLOSED]
    shl rdx, 2
    or rax, rdx
    mov rdx, [r12 + p_HANDSHAKE]
    shl rdx, 3
    or rax, rdx
    mov [r12 + p_TRACE_RECORD + 104], rax
    mov rax, [r12 + p_RAW_AUX]
    mov [r12 + p_TRACE_RECORD + 120], rax
    mov r8, [r12 + p_AUDIT]
    cmp qword ptr [r12 + p_ROLE], 2
    jne p_trace_slot_ready
    add r8, 32
p_trace_slot_ready:
    inc qword ptr [r8]
    mov rdi, [r12 + p_TRACEFD]
    lea rsi, [r12 + p_TRACE_RECORD]
    mov edx, 128
    mov eax, 1
    syscall
    mov [r8 + 16], rax
    cmp rax, 128
    je p_trace_done
    mov qword ptr [r8 + 8], 1
p_trace_done:
    ret
p_audit_footer:
    mov rdi, r12
    add rdi, p_TRACE_RECORD
    mov ecx, 16
    xor eax, eax
    rep stosq
    mov rax, 0x3144554150485348 /* HSHPAUD1 */
    mov [r12 + p_TRACE_RECORD], rax
    mov r8, [r12 + p_AUDIT]
    mov rax, [r8]
    mov [r12 + p_TRACE_RECORD + 8], rax
    mov rax, [r8 + 32]
    mov [r12 + p_TRACE_RECORD + 16], rax
    mov rax, [r8 + 8]
    mov [r12 + p_TRACE_RECORD + 24], rax
    mov rax, [r8 + 40]
    mov [r12 + p_TRACE_RECORD + 32], rax
    mov rax, [r8 + 16]
    mov [r12 + p_TRACE_RECORD + 40], rax
    mov rax, [r8 + 48]
    mov [r12 + p_TRACE_RECORD + 48], rax
    mov rax, [r8 + 24]
    mov [r12 + p_TRACE_RECORD + 56], rax
    mov rax, [r8 + 56]
    mov [r12 + p_TRACE_RECORD + 64], rax
    mov rax, [r12 + p_OWNED]
    mov [r12 + p_TRACE_RECORD + 72], rax
    mov rax, [r12 + p_TRACKED]
    mov [r12 + p_TRACE_RECORD + 80], rax
    mov rax, [r12 + p_WAIT_CACHED]
    mov [r12 + p_TRACE_RECORD + 88], rax
    mov rax, [r12 + p_CHILD_PID]
    mov [r12 + p_TRACE_RECORD + 96], rax
    mov rax, [r12 + p_EOF_SEEN]
    mov [r12 + p_TRACE_RECORD + 104], rax
    mov rax, [r12 + p_IO_ERROR]
    mov [r12 + p_TRACE_RECORD + 112], rax
    mov rdi, [r12 + p_TRACEFD]
    lea rsi, [r12 + p_TRACE_RECORD]
    mov edx, 128
    mov eax, 1
    syscall
    cmp rax, 128
    je p_footer_written
    mov qword ptr [r12 + p_EXIT_CODE], 74
p_footer_written:
    mov r8, [r12 + p_AUDIT]
    mov rax, [r8 + 8]
    or rax, [r8 + 40]
    jz p_footer_no_audit_error
    mov qword ptr [r12 + p_EXIT_CODE], 74
p_footer_no_audit_error:
    mov rax, [r8 + 24]
    or rax, [r8 + 56]
    jz p_footer_done
    mov qword ptr [r12 + p_EXIT_CODE], 78
p_footer_done:
    ret

p_normalize_fd:
    test rax, rax
    js p_normalized
    cmp rax, 2
    ja p_normalized
    mov r8, rax
    mov rdi, rax
    mov esi, 1030 /* F_DUPFD_CLOEXEC */
    mov edx, 3
    mov eax, 72
    syscall
    mov r9, rax
    mov rdi, r8
    mov eax, 3
    syscall
    mov rax, r9
p_normalized:
    ret
p_close_slot:
    mov r8, rdi
    mov rdi, [r8]
    mov qword ptr [r8], -1
    test rdi, rdi
    js p_close_finished
    mov eax, 3
    syscall
p_close_finished:
    ret
p_nonblocking:
    mov r8, rdi
    mov esi, 3
    mov eax, 72
    syscall
    test rax, rax
    js p_nonblocking_done
    or eax, 2048
    mov rdx, rax
    mov rdi, r8
    mov esi, 4
    mov eax, 72
    syscall
p_nonblocking_done:
    ret
p_allocate:
    mov r10d, 34
p_allocate_flags:
    xor edi, edi
    mov edx, 3
    mov r8, -1
    xor r9d, r9d
    mov eax, 9
    syscall
    ret
p_devnull: .asciz "/dev/null"
p_sh_name: .asciz "sh"
p_dash_c: .asciz "-c"
p_bin_sh: .asciz "/bin/sh"
.equ p_BRIDGE,2056
.equ p_WAKEFD,2064
p_make_pollfds:
    mov rax,[r12+p_WAKEFD]
    mov [r12+p_POLLFDS],eax
    mov dword ptr [r12+p_POLLFDS+4],1
    mov rax,[r12+p_PIDFD]
    mov [r12+p_POLLFDS+8],eax
    mov dword ptr [r12+p_POLLFDS+12],1
    mov dword ptr [r12+p_POLLFDS+16],-1
    mov dword ptr [r12+p_POLLFDS+20],0
    ret
p_drain_wake:
    test word ptr [r12+p_POLLFDS+6],1
    jz p_drain_done
    mov rdi,[r12+p_WAKEFD]
    lea rsi,[r12+p_PACKET]
    mov edx,8
    xor eax,eax
    syscall
    cmp rax,8
    je p_drain_done
    cmp rax,-11
    je p_drain_done
    cmp rax,-4
    jne p_boundary_contract
p_drain_done:
    ret
p_boundary_contract:
    mov rax,[r12+p_AUDIT]
    test rax,rax
    jz p_contract_no_audit
    cmp qword ptr [r12+p_ROLE],2
    je p_contract_child_flag
    mov qword ptr [rax+24],1
    jmp p_contract_no_audit
p_contract_child_flag:
    mov qword ptr [rax+56],1
p_contract_no_audit:
    mov rdi,[r12+p_BRIDGE]
    mov esi,78
    jmp fg_fatal

/* Fixed IO primitives; HIA selects read loops and result tags. */
.equ i_E,256
.equ i_WLEN,0
.equ i_DIRFD,8
.equ i_OUTFD,16
.equ i_ERRFD,24
.equ i_TRACEFD,32
.equ i_READFD,40
.equ i_HANDLE,48
.equ i_SEQ,56
.equ i_ACTION,64
.equ i_RAW,72
.equ i_ERROR,80
.equ i_RESULT,88
.equ i_AUDITFD,96
.equ i_PAYPTR,104
.equ i_PAYLEN,112
.equ i_PAYKIND,120
.equ i_MODE,128
.equ i_ADMITTED,136
.equ i_SERIAL,152
.equ i_ISSUES,160
.equ i_COMPLETIONS,168
.equ i_TRACEERR,176
.equ i_IOERR,184
.equ i_PID,192
.equ i_RECORDS,200
.equ i_PATHMAP,208
.equ i_OUTPATH,216
.equ i_ERRPATH,224
.equ i_TRACEPATH,232
.equ i_OUTLEN,240
.equ i_ERRLEN,248
.equ i_A0,256
.equ i_A1,264
.equ i_A2,272
.equ i_PHASE,280
.equ i_EXITCODE,288
.equ i_FRAME,304
.equ i_STATBUF,336
.equ i_READY,512
.equ i_GATE,576
.equ i_RECORD,640
.equ i_SIGACT,816
.equ i_FOOTER,896
.equ i_ABORTMASK,1040
.equ i_OLDABORTMASK,1048

i_effect_pending:
    mov rax,[rip+i_effect_magic]
    cmp [r14+i_E],rax
    jne i_contract
    mov rax,[r12+i_SEQ]
    inc rax
    jz i_contract
    cmp [r14+i_E+8],rax
    jne i_contract
    mov [r12+i_SEQ],rax
    mov rax,[r14+i_E+48]
    or rax,[r14+i_E+56]
    or rax,[r14+i_E+64]
    or rax,[r14+i_E+72]
    or rax,[r14+i_E+80]
    or rax,[r14+i_E+88]
    jnz i_contract
    mov rax,[r14+i_E+16]
    cmp rax,1
    jb i_contract
    cmp rax,11
    ja i_contract
    mov [r12+i_ACTION],rax
    mov rax,[r14+i_E+24]
    mov [r12+i_A0],rax
    mov rax,[r14+i_E+32]
    mov [r12+i_A1],rax
    mov rax,[r14+i_E+40]
    mov [r12+i_A2],rax

i_dispatch:
    mov qword ptr [r12+i_RAW],0
    mov qword ptr [r12+i_ERROR],0
    mov qword ptr [r12+i_RESULT],0
    mov qword ptr [r12+i_PAYPTR],0
    mov qword ptr [r12+i_PAYLEN],0
    mov qword ptr [r12+i_PAYKIND],0
    mov rax,[r12+i_READFD]
    mov [r12+i_AUDITFD],rax
    mov rax,[r12+i_ACTION]
    cmp rax,10
    je i_diagnostic_issue
    cmp rax,11
    jne i_not_abort_issue
    mov qword ptr [r12+i_AUDITFD],-1
i_not_abort_issue:
    cmp rax,2
    je i_path_issue
    cmp rax,8
    je i_path_issue
    jmp i_ordinary_issue
i_diagnostic_issue:
    cmp qword ptr [r12+i_A2],0
    jne i_contract
    mov rdi,[r12+i_A0]
    mov rsi,[r12+i_A1]
    test rsi,rsi
    jz i_contract
    cmp rdi,1024
    jb i_contract
    mov rax,rdi
    add rax,rsi
    jc i_contract
    cmp rax,1280
    ja i_contract
    call i_span
    mov rax,[r12+i_A0]
    add rax,r14
    mov [r12+i_PAYPTR],rax
    mov rax,[r12+i_A1]
    mov [r12+i_PAYLEN],rax
    mov qword ptr [r12+i_PAYKIND],4
    mov qword ptr [r12+i_AUDITFD],2
    jmp i_ordinary_issue
i_path_issue:
    call i_capture_path
    mov [r12+i_PAYPTR],rsi
    mov [r12+i_PAYLEN],rdx
    mov qword ptr [r12+i_PAYKIND],1
i_ordinary_issue:
    mov qword ptr [r12+i_PHASE],0
    call i_trace_record
    mov qword ptr [r12+i_PAYPTR],0
    mov qword ptr [r12+i_PAYLEN],0
    mov qword ptr [r12+i_PAYKIND],0
    mov rax,[r12+i_ACTION]
    cmp rax,1
    je i_admit
    cmp qword ptr [r12+i_ADMITTED],1
    jne i_contract
    cmp rax,2
    je i_open_read
    cmp rax,3
    je i_metadata_statx
    cmp rax,4
    je i_metadata_fstat
    cmp rax,5
    je i_read_file
    cmp rax,6
    je i_close_read
    cmp rax,7
    je i_grow_work
    cmp rax,8
    je i_unlink_file
    cmp rax,9
    je i_statx_probe
    cmp rax,10
    je i_diagnostic_write
    cmp rax,11
    je i_abort_self
    jmp i_contract
i_admit:
    cmp qword ptr [r12+i_ADMITTED],0
    jne i_contract
    cmp qword ptr [r12+i_A0],1
    jne i_contract
    call i_zero_last
    mov qword ptr [r12+i_ADMITTED],1
    xor eax,eax
    jmp i_acknowledge
i_open_read:
    cmp qword ptr [r12+i_READFD],-1
    jne i_contract
    call i_capture_path
    mov rdi,-100
    mov edx,0x80000
    xor r10d,r10d
    mov eax,257
    syscall
    mov [r12+i_RAW],rax
    call i_normalize_fd
    test rax,rax
    js i_error_return
    mov [r12+i_READFD],rax
    mov [r12+i_AUDITFD],rax
    inc qword ptr [r12+i_SERIAL]
    jz i_contract
    mov rax,[r12+i_SERIAL]
    mov [r12+i_HANDLE],rax
    mov [r12+i_RESULT],rax
    jmp i_acknowledged
i_metadata_statx:
    call i_owned_handle
    cmp qword ptr [r12+i_A1],384
    jne i_contract
    cmp qword ptr [r12+i_A2],256
    jne i_contract
    lea rdi,[r14+384]
    mov ecx,256
    xor eax,eax
    rep stosb
    mov rdi,[r12+i_READFD]
    lea rsi,[rip+i_empty_path]
    mov edx,0x1000
    mov r10d,0xfff
    lea r8,[r14+384]
    mov eax,332
    syscall
    mov [r12+i_RAW],rax
    test rax,rax
    js i_error_return
    lea rax,[r14+384]
    mov [r12+i_PAYPTR],rax
    mov qword ptr [r12+i_PAYLEN],256
    mov qword ptr [r12+i_PAYKIND],3
    xor eax,eax
    jmp i_acknowledge
i_metadata_fstat:
    call i_owned_handle
    cmp qword ptr [r12+i_A1],640
    jne i_contract
    cmp qword ptr [r12+i_A2],144
    jne i_contract
    mov rdi,[r12+i_READFD]
    lea rsi,[r14+640]
    mov eax,5
    syscall
    mov [r12+i_RAW],rax
    test rax,rax
    js i_error_return
    lea rax,[r14+640]
    mov [r12+i_PAYPTR],rax
    mov qword ptr [r12+i_PAYLEN],144
    mov qword ptr [r12+i_PAYKIND],3
    xor eax,eax
    jmp i_acknowledge
i_statx_probe:
    mov rax,[r12+i_A0]
    or rax,[r12+i_A1]
    or rax,[r12+i_A2]
    jnz i_contract
    xor edi,edi
    xor esi,esi
    xor edx,edx
    mov r10d,0xfff
    xor r8d,r8d
    mov eax,332
    syscall
    mov [r12+i_RAW],rax
    test rax,rax
    js i_error_return
    jmp i_acknowledge
i_read_file:
    call i_owned_handle
    mov rdi,[r12+i_A1]
    mov rsi,[r12+i_A2]
    call i_span
    cmp qword ptr [r12+i_A1],800
    jne i_read_data_span
    cmp qword ptr [r12+i_A2],32
    jne i_contract
    jmp i_read_span_ready
i_read_data_span:
    cmp qword ptr [r12+i_A1],4208
    jb i_contract
i_read_span_ready:
    mov rdi,[r12+i_READFD]
    mov rsi,[r12+i_A1]
    add rsi,r14
    mov rdx,[r12+i_A2]
    test rdx,rdx
    jz i_contract
    xor eax,eax
    syscall
    mov [r12+i_RAW],rax
    test rax,rax
    js i_error_return
    mov [r12+i_RESULT],rax
    mov [r12+i_PAYLEN],rax
    mov rax,[r12+i_A1]
    add rax,r14
    mov [r12+i_PAYPTR],rax
    mov qword ptr [r12+i_PAYKIND],2
    jmp i_acknowledged
i_close_read:
    call i_owned_handle
    call i_zero_last
    mov rdi,[r12+i_READFD]
    mov eax,3
    syscall
    mov [r12+i_RAW],rax
    mov qword ptr [r12+i_READFD],-1
    mov qword ptr [r12+i_HANDLE],0
    test rax,rax
    js i_error_return
    jmp i_acknowledge
i_grow_work:
    call i_zero_last
    mov rdx,[r12+i_A0]
    cmp rdx,[r12+i_WLEN]
    jbe i_contract
    add rdx,4095
    jc i_contract
    and rdx,-4096
    mov rbp,rdx
    mov rdi,r14
    mov rsi,[r12+i_WLEN]
    mov r10d,1
    xor r8d,r8d
    mov eax,25
    syscall
    mov [r12+i_RAW],rax
    cmp rax,-4095
    jae i_error_return
    mov r14,rax
    mov [r12+i_WLEN],rbp
    mov [r12+i_RESULT],rbp
    jmp i_acknowledged
i_unlink_file:
    call i_capture_path
    mov rdi,rsi
    mov eax,87
    syscall
    mov [r12+i_RAW],rax
    test rax,rax
    js i_error_return
    jmp i_acknowledge
i_diagnostic_write:
    mov edi,2
    mov rsi,[r12+i_A0]
    add rsi,r14
    mov rdx,[r12+i_A1]
    mov eax,1
    syscall
    test rax,rax
    js i_error_return
    jmp i_acknowledge
i_abort_self:
    mov rax,[r12+i_A0]
    or rax,[r12+i_A1]
    or rax,[r12+i_A2]
    jnz i_contract
    /* Fixed libc-compatible raise(SIGABRT), then forced-default fallback.
     * This intrinsic does not choose whether a failure is fatal: HIA did. */
    mov qword ptr [r12+i_ABORTMASK],-1
    xor edi,edi
    lea rsi,[r12+i_ABORTMASK]
    lea rdx,[r12+i_OLDABORTMASK]
    mov r10d,8
    mov eax,14
    syscall
    mov eax,186
    syscall
    mov rsi,rax
    mov rdi,[r12+i_PID]
    mov edx,6
    mov eax,234
    syscall
    mov edi,2
    lea rsi,[r12+i_OLDABORTMASK]
    xor edx,edx
    mov r10d,8
    mov eax,14
    syscall
    xor edi,edi
    lea rsi,[r12+i_ABORTMASK]
    xor edx,edx
    mov r10d,8
    mov eax,14
    syscall
    mov qword ptr [r12+i_SIGACT],0
    mov qword ptr [r12+i_SIGACT+8],0
    mov qword ptr [r12+i_SIGACT+16],0
    mov qword ptr [r12+i_SIGACT+24],-1
    mov edi,6
    lea rsi,[r12+i_SIGACT]
    xor edx,edx
    mov r10d,8
    mov eax,13
    syscall
    mov eax,186
    syscall
    mov rsi,rax
    mov rdi,[r12+i_PID]
    mov edx,6
    mov eax,234
    syscall
    mov qword ptr [r12+i_ABORTMASK],32
    mov edi,1
    lea rsi,[r12+i_ABORTMASK]
    xor edx,edx
    mov r10d,8
    mov eax,14
    syscall
    hlt
    mov edi,127
    mov eax,231
    syscall
i_acknowledge:
    mov [r12+i_RAW],rax
    mov [r12+i_RESULT],rax
    jmp i_acknowledged
i_error_return:
    mov [r12+i_RAW],rax
    neg rax
    cmp rax,4095
    ja i_contract
    mov [r12+i_ERROR],rax
    mov qword ptr [r12+i_RESULT],0
i_acknowledged:
    mov qword ptr [r12+i_PHASE],1
    call i_trace_record
    mov rax,r14
    ret

i_owned_handle:
    cmp qword ptr [r12+i_READFD],2
    jbe i_contract
    mov rax,[r12+i_A0]
    test rax,rax
    jz i_contract
    cmp rax,[r12+i_HANDLE]
    jne i_contract
    ret
i_zero_last:
    mov rax,[r12+i_A1]
    or rax,[r12+i_A2]
    jnz i_contract
    ret
i_span:
    cmp rdi,[r12+i_WLEN]
    ja i_contract
    mov rax,[r12+i_WLEN]
    sub rax,rdi
    cmp rsi,rax
    ja i_contract
    ret
i_capture_path:
    cmp qword ptr [r12+i_A0],1
    jne i_contract
    cmp qword ptr [r12+i_A2],0
    jne i_contract
    mov rax,[r12+i_A1]
    cmp rax,1
    ja i_contract
    test rax,rax
    jnz i_path_stderr
    mov rsi,[r12+i_OUTPATH]
    mov rdx,[r12+i_OUTLEN]
    ret
i_path_stderr:
    mov rsi,[r12+i_ERRPATH]
    mov rdx,[r12+i_ERRLEN]
    ret

i_observe_capture:
    mov [r12+i_AUDITFD],rdi
    mov [r12+i_A0],rbx
    mov qword ptr [r12+i_A1],0
    mov qword ptr [r12+i_A2],0
    mov qword ptr [r12+i_ACTION],0
    mov qword ptr [r12+i_PHASE],1
    lea rsi,[r12+i_STATBUF]
    mov eax,5
    syscall
    mov [r12+i_RAW],rax
    test rax,rax
    js i_startup_error
    mov qword ptr [r12+i_ERROR],0
    lea rax,[r12+i_STATBUF]
    mov [r12+i_PAYPTR],rax
    mov qword ptr [r12+i_PAYLEN],144
    mov qword ptr [r12+i_PAYKIND],3
    call i_trace_record
    ret

i_trace_record:
    cmp qword ptr [r12+i_TRACEFD],2
    jbe i_trace_done
    mov rax,[rip+i_trace_magic]
    mov [r12+i_RECORD],rax
    mov rax,[r12+i_SEQ]
    mov [r12+i_RECORD+8],rax
    mov rax,[r12+i_ACTION]
    mov [r12+i_RECORD+16],rax
    mov rax,[r12+i_PHASE]
    mov [r12+i_RECORD+24],rax
    mov rax,[r12+i_PID]
    mov [r12+i_RECORD+32],rax
    mov eax,186
    syscall
    mov [r12+i_RECORD+40],rax
    mov qword ptr [r12+i_RECORD+48],1
    mov rax,[r12+i_AUDITFD]
    mov [r12+i_RECORD+56],rax
    mov rax,[r12+i_A0]
    mov [r12+i_RECORD+64],rax
    mov rax,[r12+i_A1]
    mov [r12+i_RECORD+72],rax
    mov rax,[r12+i_A2]
    mov [r12+i_RECORD+80],rax
    mov rax,[r12+i_RAW]
    mov [r12+i_RECORD+88],rax
    mov rax,[r12+i_ERROR]
    mov [r12+i_RECORD+96],rax
    mov rax,[r12+i_PAYKIND]
    mov [r12+i_RECORD+104],rax
    mov rax,[r12+i_PAYLEN]
    mov [r12+i_RECORD+112],rax
    mov qword ptr [r12+i_RECORD+120],0
    inc qword ptr [r12+i_RECORDS]
    cmp qword ptr [r12+i_ACTION],0
    je i_trace_write
    cmp qword ptr [r12+i_PHASE],0
    jne i_trace_completion
    inc qword ptr [r12+i_ISSUES]
    jmp i_trace_write
i_trace_completion:
    inc qword ptr [r12+i_COMPLETIONS]
i_trace_write:
    mov rdi,[r12+i_TRACEFD]
    lea rsi,[r12+i_RECORD]
    mov edx,128
    call i_write_all
    test rax,rax
    js i_trace_failed
    mov rdi,[r12+i_TRACEFD]
    mov rsi,[r12+i_PAYPTR]
    mov rdx,[r12+i_PAYLEN]
    call i_write_all
    test rax,rax
    js i_trace_failed
i_trace_done:
    ret
i_trace_failed:
    mov [r12+i_TRACEERR],rax
    ret
i_footer:
    cmp qword ptr [r12+i_TRACEFD],2
    jbe i_footer_done
    lea rdi,[r12+i_FOOTER]
    mov ecx,128
    xor eax,eax
    rep stosb
    mov rax,[rip+i_footer_magic]
    mov [r12+i_FOOTER],rax
    mov rax,[r12+i_PID]
    mov [r12+i_FOOTER+8],rax
    mov rax,[r12+i_RECORDS]
    mov [r12+i_FOOTER+16],rax
    mov rax,[r12+i_ISSUES]
    mov [r12+i_FOOTER+24],rax
    mov rax,[r12+i_COMPLETIONS]
    mov [r12+i_FOOTER+32],rax
    mov rax,[r12+i_TRACEERR]
    mov [r12+i_FOOTER+40],rax
    mov rax,[r12+i_IOERR]
    mov [r12+i_FOOTER+48],rax
    mov rax,[r12+i_READFD]
    mov [r12+i_FOOTER+56],rax
    mov rax,[r12+i_OUTFD]
    mov [r12+i_FOOTER+64],rax
    mov rax,[r12+i_ERRFD]
    mov [r12+i_FOOTER+72],rax
    mov rax,[r12+i_EXITCODE]
    mov [r12+i_FOOTER+80],rax
    mov rax,[r12+i_MODE]
    mov [r12+i_FOOTER+88],rax
    mov rdi,[r12+i_TRACEFD]
    lea rsi,[r12+i_FOOTER]
    mov edx,128
    call i_write_all
    test rax,rax
    jns i_footer_done
    mov [r12+i_TRACEERR],rax
i_footer_done:
    ret

i_cleanup:
    mov rdi,[r12+i_READFD]
    call i_close_if_owned
    mov qword ptr [r12+i_READFD],-1
    mov qword ptr [r12+i_HANDLE],0
    mov rdi,[r12+i_OUTFD]
    call i_close_if_owned
    mov qword ptr [r12+i_OUTFD],-1
    mov rdi,[r12+i_ERRFD]
    call i_close_if_owned
    mov qword ptr [r12+i_ERRFD],-1
    mov rdi,[r12+i_DIRFD]
    call i_close_if_owned
    mov qword ptr [r12+i_DIRFD],-1
    ret
i_close_if_owned:
    cmp rdi,2
    jbe i_close_done
    cmp rdi,-1
    je i_close_done
    mov eax,3
    syscall
i_close_done:
    ret
i_allocate:
    xor edi,edi
    mov edx,3
    mov r10d,0x22
    mov r8,-1
    xor r9d,r9d
    mov eax,9
    syscall
    ret
i_create_file:
    mov rdi,-100
    mov edx,0xa00c1
    mov r10d,0x180
    mov eax,257
    syscall
    jmp i_normalize_fd
i_normalize_fd:
    cmp rax,-4095
    jae i_normalized
    cmp rax,2
    ja i_normalized
    mov r8,rax
    mov rdi,rax
    mov esi,1030
    mov edx,3
    mov eax,72
    syscall
    mov r9,rax
    mov rdi,r8
    mov eax,3
    syscall
    mov rax,r9
i_normalized:
    ret
i_read_exact:
    mov r8,rdx
i_read_exact_loop:
    test rdx,rdx
    jz i_read_exact_ok
    xor eax,eax
    syscall
    cmp rax,-4
    je i_read_exact_loop
    test rax,rax
    js i_read_exact_error
    jz i_read_exact_eof
    add rsi,rax
    sub rdx,rax
    jmp i_read_exact_loop
i_read_exact_ok:
    mov eax,1
    ret
i_read_exact_eof:
    cmp rdx,r8
    jne i_read_exact_error
    xor eax,eax
    ret
i_read_exact_error:
    mov eax,-1
    ret
i_write_all:
    test rdx,rdx
    jz i_write_ok
i_write_loop:
    mov eax,1
    syscall
    cmp rax,-4
    je i_write_loop
    test rax,rax
    js i_write_done
    jz i_write_zero
    add rsi,rax
    sub rdx,rax
    jnz i_write_loop
i_write_ok:
    xor eax,eax
i_write_done:
    ret
i_write_zero:
    mov rax,-5
    ret
i_equal_string:
    xor eax,eax
i_string_equal_loop:
    mov cl,[rdi]
    cmp cl,[rsi]
    jne i_string_equal_done
    test cl,cl
    jz i_string_equal_yes
    inc rdi
    inc rsi
    jmp i_string_equal_loop
i_string_equal_yes:
    mov eax,1
i_string_equal_done:
    ret
i_string_length:
    xor eax,eax
i_string_length_loop:
    cmp byte ptr [rdi+rax],0
    je i_string_length_done
    inc rax
    jmp i_string_length_loop
i_string_length_done:
    ret
i_make_path:
    mov r8,rdi
i_make_prefix:
    mov al,[rsi]
    test al,al
    jz i_make_suffix
    mov [rdi],al
    inc rdi
    inc rsi
    jmp i_make_prefix
i_make_suffix:
    mov al,[rdx]
    mov [rdi],al
    inc rdi
    inc rdx
    test al,al
    jnz i_make_suffix
    mov rax,rdi
    sub rax,r8
    ret
i_signal_handler:
    ret
i_signal_return:
    mov eax,15
    syscall

i_empty_path: .byte 0
i_ready_magic: .ascii "HSHOIRD1"
i_gate_magic: .ascii "HSHOIGT1"
i_effect_magic: .ascii "HSHOIFX1"
i_descriptor_magic: .ascii "HSHOID01"
i_trace_magic: .ascii "HSHOITR1"
i_footer_magic: .ascii "HSHOIAU1"
.equ i_BRIDGE,2048
i_contract:
    mov rdi,[r12+i_BRIDGE]
    mov esi,78
    jmp fg_fatal
i_startup_error:
    mov [r12+i_IOERR],rax
    mov rdi,[r12+i_BRIDGE]
    mov esi,74
    jmp fg_fatal


fg_option: .asciz "--foreground-fixture"
fg_stdout: .asciz "/stdout.log"
fg_stderr: .asciz "/stderr.log"
fg_ptrace: .asciz "/process-effects.bin"
fg_itrace: .asciz "/io-effects.bin"
fg_ctrace: .asciz "/controller-effects.bin"
fg_cctrace: .asciz "/controller-child.bin"
fg_ready_magic: .ascii "HSHFGRD1"
fg_descriptor_magic: .ascii "HSHFGD01"
fg_effect_magic: .ascii "HSHFGFX1"
fg_trace_magic: .ascii "HSHFGTR1"
fg_footer_magic: .ascii "HSHFGAU1"
fg_abort_magic: .ascii "HSHFGAB1"
.balign 8,0
fg_one: .quad 1
.balign 16,0
.size _start,.-_start
.section .note.GNU-stack,"",@progbits
