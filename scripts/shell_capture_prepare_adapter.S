/* Fixed Linux capabilities. Every preparation decision remains in HIA. */
.intel_syntax noprefix
.section .text
.global _start
.type _start,@function
.equ DFD,0
.equ TFD,8
.equ EFD,16
.equ PID,24
.equ TID,32
.equ REQUESTS,40
.equ ENTRIES,48
.equ ISSUED,56
.equ COMPLETED,64
.equ KISSUED,72
.equ KCOMPLETED,80
.equ MINTED,88
.equ CLOSED,96
.equ ADOPTED,104
.equ LIVE,112
.equ RECEIVER,120
.equ IOERR,128
.equ BAD,136
.equ LASTRET,144
.equ SEED,152
.equ SEQUENCE,160
.equ ARENAS,168
.equ CHILDMAP,176
.equ CHILDSIZE,184
.equ FIRST,192
.equ ACTIVE,200
.equ PARENTSEQ,208
.equ PHASE,216
.equ ACTION,224
.equ ROLE,232
.equ INOFF,240
.equ INLEN,248
.equ OUTOFF,256
.equ CHILDRET,264
.equ RESULT,272
.equ ERRNO,280
.equ AUX,288
.equ NODE,296
.equ TOKENS,304
.equ NEXTTOKEN,312
.equ HEAD,320
.equ PSLOT,384
.equ LPTR,480
.equ LSLOTLEN,488
.equ PATHPTR,496
.equ PATHLEN,504
.equ NR,512
.equ FDARG,520
.equ FLAGS,528
.equ MODEARG,536
.equ RAW,544
.equ KERRNO,552
.equ HANDLE,560
.equ MODEOUT,568
.equ STATLEN,576
.equ TARGETTOKEN,584
.equ KROLE,592
.equ KSEQ,600
.equ OHEAD,640
.equ KHEAD,832
.equ EHEAD,1024
.equ FOOTER,1216
.equ READY,1472
.equ RESPONSE,1536
.equ TS,1552
.equ GATE,1600
.equ ACK,1696
.equ NODEBASE,1728
.equ CONTEXTS,2560
.equ STATBUF,4096
/* Each context: three actual guarded allocations, then counters/forwarding. */
.equ CIBASE,0
.equ CIPTR,8
.equ CICAP,16
.equ CILEN,24
.equ COBASE,32
.equ COPTR,40
.equ COCAP,48
.equ CWBASE,56
.equ CWPTR,64
.equ CWCAP,72
.equ CRET,80
.equ CCALLS,88
.equ CIMAGE,96
.equ CINOFF,104
.equ COUTOFF,112
.equ CNODE,120
.macro copyq destination,source
    mov rax,[r15+\source]
    mov [r15+\destination],rax
.endm
.macro audit_write fd,offset,length
    mov rdi,[r15+\fd]
    lea rsi,[r15+\offset]
    mov edx,\length
    call write_all
    test eax,eax
    jnz infrastructure
.endm
_start:
    mov rbx,rsp
    and rsp,-16
    sub rsp,16384
    mov r15,rsp
    xor eax,eax
    mov rdi,r15
    mov ecx,2048
    rep stosq
    mov qword ptr [r15+DFD],-1
    mov qword ptr [r15+TFD],-1
    mov qword ptr [r15+EFD],-1
    mov qword ptr [r15+NEXTTOKEN],1
    cmp qword ptr [rbx],3
    jne usage
    mov rdi,[rbx+16]
    lea rsi,[rip+option_name]
    call equal_cstring
    test eax,eax
    jz usage
    mov eax,39
    syscall
    mov [r15+PID],rax
    mov eax,186
    syscall
    mov [r15+TID],rax
    mov rdi,-100
    mov rsi,[rbx+24]
    mov edx,0xb0000
    xor r10d,r10d
    mov eax,257
    syscall
    test rax,rax
    js infrastructure
    mov [r15+DFD],rax
    mov rdi,rax
    lea rsi,[rip+effects_name]
    mov edx,0xa00c1
    mov r10d,384
    mov eax,257
    syscall
    test rax,rax
    js infrastructure
    call normalize_audit_fd
    mov [r15+TFD],rax
    mov rdi,[r15+DFD]
    lea rsi,[rip+entries_name]
    mov edx,0xa00c1
    mov r10d,384
    mov eax,257
    syscall
    test rax,rax
    js infrastructure
    call normalize_audit_fd
    mov [r15+EFD],rax
    mov rdi,[r15+DFD]
    mov eax,3
    syscall
    mov qword ptr [r15+DFD],-1
    mov rax,0x3159445252505348 /* HSPRRDY1 */
    mov [r15+READY],rax
    copyq READY+8,PID
    copyq READY+16,TID
    copyq READY+24,TFD
    copyq READY+32,EFD
    mov qword ptr [r15+READY+40],1
    mov edi,1
    lea rsi,[r15+READY]
    mov edx,64
    call write_all
    test eax,eax
    jnz infrastructure
next_request:
    xor edi,edi
    lea rsi,[r15+HEAD]
    mov edx,32
    call read_exact
    cmp eax,1
    je normal_exit
    test eax,eax
    jnz infrastructure
    lea r12,[r15+CONTEXTS]
    cmp qword ptr [r15+FIRST],0
    je first_request
    mov rax,[r15+HEAD+8]
    cmp rax,[r12+COCAP]
    jne contract
    mov rax,[r15+HEAD+16]
    cmp rax,[r12+CWCAP]
    jne contract
    mov rax,[r15+HEAD+24]
    cmp rax,[r15+SEED]
    jne contract
    mov rdi,[r12+CIBASE]
    mov rsi,[r12+CICAP]
    add rsi,32
    mov eax,11
    syscall
    test rax,rax
    js infrastructure
    jmp input_allocation
first_request:
    mov rax,[r15+HEAD+24]
    mov [r15+SEED],rax
    mov [r15+SEQUENCE],rax
    mov rdi,[r15+HEAD+8]
    mov [r12+COCAP],rdi
    add rdi,32
    jc infrastructure
    call map_rw
    mov [r12+COBASE],rax
    lea rdx,[rax+16]
    mov [r12+COPTR],rdx
    mov rdi,rax
    mov al,0xa5
    mov ecx,16
    rep stosb
    add rdi,[r12+COCAP]
    mov al,0xa6
    mov ecx,16
    rep stosb
    mov rdi,[r15+HEAD+16]
    mov [r12+CWCAP],rdi
    add rdi,32
    jc infrastructure
    call map_rw
    mov [r12+CWBASE],rax
    lea rdx,[rax+16]
    mov [r12+CWPTR],rdx
    mov rdi,rax
    mov al,0x5a
    mov ecx,16
    rep stosb
    add rdi,[r12+CWCAP]
    mov al,0x5b
    mov ecx,16
    rep stosb
    mov qword ptr [r15+FIRST],1
input_allocation:
    mov rdi,[r15+HEAD]
    mov [r12+CICAP],rdi
    mov [r12+CILEN],rdi
    add rdi,32
    jc infrastructure
    call map_rw
    mov [r12+CIBASE],rax
    lea rdx,[rax+16]
    mov [r12+CIPTR],rdx
    mov rdi,rax
    mov al,0xc1
    mov ecx,16
    rep stosb
    add rdi,[r12+CICAP]
    mov al,0xc2
    mov ecx,16
    rep stosb
    xor edi,edi
    mov rsi,[r12+CIPTR]
    mov rdx,[r12+CILEN]
    call read_exact
    test eax,eax
    jnz infrastructure
    mov rdi,[r12+COPTR]
    mov rcx,[r12+COCAP]
    mov al,0xa7
    rep stosb
    inc qword ptr [r15+REQUESTS]
invoke_owner:
    mov qword ptr [r15+ACTIVE],0
    mov qword ptr [r15+PARENTSEQ],0
    call invoke_context
    mov [r15+LASTRET],rax
    cmp eax,0xfffffffd
    je owner_pending
    cmp rax,128
    je owner_result
    cmp eax,0xfffffffe
    je owner_refusal
    cmp eax,0xffffffff
    jne contract
owner_refusal:
    mov [r15+RESPONSE],rax
    mov qword ptr [r15+RESPONSE+8],0
    mov edi,1
    lea rsi,[r15+RESPONSE]
    mov edx,16
    call write_all
    test eax,eax
    jnz infrastructure
    jmp next_request
owner_result:
    lea r12,[r15+CONTEXTS]
    cmp qword ptr [r12+COCAP],128
    jb contract
    mov rdx,[r12+COPTR]
    mov rbx,[rdx+8]
    cmp rbx,128
    jb contract
    cmp rbx,[r12+COCAP]
    ja contract
    mov qword ptr [r15+RESPONSE],128
    mov [r15+RESPONSE+8],rbx
    mov edi,1
    lea rsi,[r15+RESPONSE]
    mov edx,16
    call write_all
    test eax,eax
    jnz infrastructure
    mov edi,1
    mov rsi,[r12+COPTR]
    mov rdx,rbx
    call write_all
    test eax,eax
    jnz infrastructure
    jmp next_request
owner_pending:
    lea r12,[r15+CONTEXTS]
    cmp qword ptr [r12+CWCAP],224
    jb contract
    mov rsi,[r12+CWPTR]
    add rsi,128
    lea rdi,[r15+PSLOT]
    mov ecx,12
    rep movsq
    mov rax,0x3158465050485348 /* HSHPPFX1 */
    cmp [r15+PSLOT],rax
    jne contract
    mov rax,[r15+PSLOT+56]
    or rax,[r15+PSLOT+64]
    or rax,[r15+PSLOT+72]
    or rax,[r15+PSLOT+80]
    or rax,[r15+PSLOT+88]
    jnz contract
    mov rax,[r15+PSLOT+16]
    mov [r15+ACTION],rax
    cmp rax,1
    jb contract
    cmp rax,9
    ja contract
    copyq PARENTSEQ,PSLOT+8
    mov qword ptr [r15+RESULT],0
    mov qword ptr [r15+ERRNO],0
    mov qword ptr [r15+AUX],0
    inc qword ptr [r15+ISSUED]
    mov qword ptr [r15+PHASE],0
    call record_outer
    mov rax,[r15+ACTION]
    cmp eax,1
    je init_arenas
    cmp qword ptr [r15+ARENAS],1
    jne contract
    cmp eax,2
    je call_mkdir
    cmp eax,3
    je dispatch_mkdir
    cmp eax,4
    je observe_sequence
    cmp eax,5
    je call_file
    cmp eax,6
    je dispatch_file
    cmp eax,7
    je adopt_file
    cmp eax,8
    je close_owned
    jmp call_path
complete_outer:
    lea r12,[r15+CONTEXTS]
    mov rdx,[r12+CWPTR]
    add rdx,128
    mov rax,[r15+RESULT]
    mov [rdx+64],rax
    mov rax,[r15+ERRNO]
    mov [rdx+72],rax
    mov rax,[r15+AUX]
    mov [rdx+80],rax
    mov qword ptr [rdx+56],1
    inc qword ptr [r15+COMPLETED]
    mov qword ptr [r15+PHASE],1
    call record_outer
    call effect_gate
    lea r12,[r15+CONTEXTS]
    cmp qword ptr [r12+CILEN],16
    jb contract
    mov rax,[r12+CIPTR]
    mov qword ptr [rax+8],2
    jmp invoke_owner

/* Every module invocation records complete guarded allocations. */
invoke_context:
    sub rsp,8 /* System V alignment before calling an unchanged module entry. */
    mov rax,[r15+ACTIVE]
    shl rax,7
    lea r12,[r15+CONTEXTS+rax]
    inc qword ptr [r15+ENTRIES]
    inc qword ptr [r12+CCALLS]
    mov qword ptr [r15+PHASE],0
    call record_entry
    mov rdi,[r12+CIPTR]
    mov rsi,[r12+CILEN]
    mov rdx,[r12+COPTR]
    mov rcx,[r12+COCAP]
    mov r8,[r12+CWPTR]
    mov r9,[r12+CWCAP]
    lea rax,[rip+module_offset_table]
    mov r10,[r12+CIMAGE]
    mov rax,[rax+r10*8]
    lea r10,[rip+shell_capture_prepare_entry]
    add rax,r10
    call rax
    mov eax,eax
    mov [r12+CRET],rax
    mov qword ptr [r15+PHASE],1
    call record_entry
    mov rax,[r12+CRET]
    add rsp,8
    ret

/* One mapping makes INIT rollback atomic; no FD can yet have been created. */
init_arenas:
    cmp qword ptr [r15+ARENAS],0
    jne contract
    mov rax,[r15+PSLOT+48]
    mov ecx,5
    mul rcx
    test rdx,rdx
    jnz infrastructure
    mov rbx,rax
    mov rax,[r15+PSLOT+40]
    mov ecx,3
    mul rcx
    test rdx,rdx
    jnz infrastructure
    add rbx,rax
    jc infrastructure
    add rbx,[r15+PSLOT+24]
    jc infrastructure
    add rbx,[r15+PSLOT+32]
    jc infrastructure
    add rbx,976 /* guards, fixed outputs/workspace, three owned FD nodes */
    jc infrastructure
    xor edi,edi
    mov rsi,rbx
    mov edx,3
    mov r10d,0x22
    mov r8,-1
    xor r9d,r9d
    mov eax,9
    syscall
    test rax,rax
    jns init_mapped
    cmp rax,-4095
    jl contract
    mov [r15+RESULT],rax
    neg rax
    mov [r15+ERRNO],rax
    jmp complete_outer
init_mapped:
    mov [r15+CHILDMAP],rax
    mov [r15+CHILDSIZE],rbx
    mov r14,rax
    mov r13d,1
init_context_loop:
    mov rax,r13
    shl rax,7
    lea r12,[r15+CONTEXTS+rax]
    mov rax,r13
    cmp eax,3
    jb init_image_ready
    mov eax,3
init_image_ready:
    mov [r12+CIMAGE],rax
    mov rax,[r15+PSLOT+48]
    mov [r12+CICAP],rax
    mov [r12+CIBASE],r14
    lea rdx,[r14+16]
    mov [r12+CIPTR],rdx
    mov rdi,r14
    mov al,0xc1
    mov ecx,16
    rep stosb
    add rdi,[r12+CICAP]
    mov al,0xc2
    mov ecx,16
    rep stosb
    mov r14,rdi
    mov eax,48
    mov edx,3
    cmp r13d,1
    je init_path_caps
    cmp r13d,2
    jne init_file_caps
    mov eax,32
    mov rdx,[r15+PSLOT+32]
    jmp init_caps_ready
init_path_caps:
    mov rax,[r15+PSLOT+24]
    mov edx,128
    jmp init_caps_ready
init_file_caps:
    mov rdx,[r15+PSLOT+40]
init_caps_ready:
    mov [r12+COCAP],rax
    mov [r12+CWCAP],rdx
    mov [r12+COBASE],r14
    lea rdx,[r14+16]
    mov [r12+COPTR],rdx
    mov rdi,r14
    mov al,0xa5
    mov ecx,16
    rep stosb
    add rdi,[r12+COCAP]
    mov al,0xa6
    mov ecx,16
    rep stosb
    mov r14,rdi
    mov [r12+CWBASE],r14
    lea rdx,[r14+16]
    mov [r12+CWPTR],rdx
    mov rdi,r14
    mov al,0x5a
    mov ecx,16
    rep stosb
    add rdi,[r12+CWCAP]
    mov al,0x5b
    mov ecx,16
    rep stosb
    mov r14,rdi
    inc r13d
    cmp r13d,6
    jb init_context_loop
    mov [r15+NODEBASE],r14
    mov r13d,3
init_node_loop:
    mov rax,r13
    shl rax,7
    lea r12,[r15+CONTEXTS+rax]
    mov [r12+CNODE],r14
    add r14,64
    inc r13d
    cmp r13d,6
    jb init_node_loop
    mov rax,[r15+CHILDMAP]
    add rax,[r15+CHILDSIZE]
    cmp r14,rax
    jne contract
    mov qword ptr [r15+ARENAS],1
    jmp complete_outer

call_mkdir:
    cmp qword ptr [r15+PSLOT+24],1024
    jne contract
    cmp qword ptr [r15+PSLOT+40],512
    jne contract
    cmp qword ptr [r15+PSLOT+48],0
    jne contract
    mov qword ptr [r15+ROLE],2
    copyq INOFF,PSLOT+24
    copyq INLEN,PSLOT+32
    copyq OUTOFF,PSLOT+40
    jmp call_child
call_file:
    mov rax,[r15+PSLOT+24]
    cmp rax,3
    jb contract
    cmp rax,5
    ja contract
    mov [r15+ROLE],rax
    cmp qword ptr [r15+PSLOT+32],1024
    jne contract
    cmp qword ptr [r15+PSLOT+48],512
    jne contract
    copyq INOFF,PSLOT+32
    copyq INLEN,PSLOT+40
    copyq OUTOFF,PSLOT+48
    jmp call_child
call_path:
    cmp qword ptr [r15+PSLOT+24],1024
    jne contract
    mov rax,[r15+PSLOT+48]
    cmp rax,[r15+CONTEXTS+128+COCAP]
    jne contract
    mov qword ptr [r15+ROLE],1
    copyq INOFF,PSLOT+24
    copyq INLEN,PSLOT+32
    copyq OUTOFF,PSLOT+40
call_child:
    mov rax,[r15+ROLE]
    mov [r15+ACTIVE],rax
    shl rax,7
    lea r12,[r15+CONTEXTS+rax]
    mov rax,[r15+INLEN]
    cmp rax,[r12+CICAP]
    ja contract
    mov [r12+CILEN],rax
    mov rbx,[r15+CONTEXTS+CWCAP]
    mov rdx,[r15+INOFF]
    cmp rdx,rbx
    ja contract
    sub rbx,rdx
    cmp rax,rbx
    ja contract
    mov [r12+CINOFF],rdx
    mov rbx,[r15+CONTEXTS+CWCAP]
    mov rdx,[r15+OUTOFF]
    cmp rdx,rbx
    ja contract
    sub rbx,rdx
    mov rax,[r12+COCAP]
    cmp qword ptr [r15+ROLE],2
    jne child_output_bound
    add rax,16
child_output_bound:
    cmp rax,rbx
    ja contract
    mov [r12+COUTOFF],rdx
    mov rdi,[r12+CIPTR]
    mov rcx,[r12+CICAP]
    mov al,0xd1
    rep stosb
    mov rdi,[r12+CIPTR]
    mov rsi,[r15+CONTEXTS+CWPTR]
    add rsi,[r15+INOFF]
    mov rcx,[r12+CILEN]
    rep movsb
    mov rdi,[r12+COPTR]
    mov rsi,[r15+CONTEXTS+CWPTR]
    add rsi,[r15+OUTOFF]
    mov rcx,[r12+COCAP]
    rep movsb
    call invoke_context
    mov [r15+RESULT],rax
    mov rdi,[r15+CONTEXTS+CWPTR]
    add rdi,[r15+OUTOFF]
    mov rsi,[r12+COPTR]
    mov rcx,[r12+COCAP]
    rep movsb
    cmp qword ptr [r15+ROLE],2
    jne complete_outer
    xor eax,eax
    mov ecx,16
    rep stosb
    jmp complete_outer

observe_sequence:
    call require_zero_args
    mov eax,1
    lock xadd qword ptr [r15+SEQUENCE],rax
    mov [r15+RESULT],rax
    jmp complete_outer

adopt_file:
    mov rax,[r15+PSLOT+24]
    cmp rax,3
    jb contract
    cmp rax,4
    ja contract
    mov [r15+ROLE],rax
    mov rdx,[r15+PSLOT+40]
    or rdx,[r15+PSLOT+48]
    jnz contract
    shl rax,7
    lea r12,[r15+CONTEXTS+rax]
    cmp qword ptr [r12+CRET],48
    jne contract
    mov rdx,[r12+CWPTR]
    cmp qword ptr [r12+CWCAP],224
    jb contract
    mov rax,0x3130574643485348 /* HSHCFW01 */
    cmp [rdx],rax
    jne contract
    cmp qword ptr [rdx+8],4
    jne contract
    cmp qword ptr [rdx+16],3
    jne contract
    cmp qword ptr [rdx+48],0
    jne contract
    cmp qword ptr [rdx+64],0
    jne contract
    cmp qword ptr [rdx+72],0
    jne contract
    mov rax,[r15+PSLOT+32]
    cmp [rdx+80],rax
    jne contract
    mov rdx,[r12+COPTR]
    mov rcx,0x3130524643485348 /* HSHCFR01 */
    cmp [rdx],rcx
    jne contract
    cmp qword ptr [rdx+8],48
    jne contract
    cmp qword ptr [rdx+16],4
    jne contract
    cmp qword ptr [rdx+24],0
    jne contract
    cmp qword ptr [rdx+32],0
    jne contract
    cmp [rdx+40],rax
    jne contract
    call find_token
    mov rdx,[r15+ROLE]
    cmp [rbx+32],rdx
    jne contract
    mov qword ptr [rbx+32],0
    inc qword ptr [r15+ADOPTED]
    inc qword ptr [r15+RECEIVER]
    jmp complete_outer

require_zero_args:
    mov rax,[r15+PSLOT+24]
    or rax,[r15+PSLOT+32]
    or rax,[r15+PSLOT+40]
    or rax,[r15+PSLOT+48]
    jnz contract
    ret
/* rax opaque token -> rbx actual live descriptor node. */
find_token:
    test rax,rax
    jz contract
    mov rbx,[r15+TOKENS]
find_token_loop:
    test rbx,rbx
    jz contract
    cmp [rbx+8],rax
    je found_token
    mov rbx,[rbx]
    jmp find_token_loop
found_token:
    cmp qword ptr [rbx+24],1
    jne contract
    mov [r15+NODE],rbx
    ret

dispatch_mkdir:
    call require_zero_args
    mov qword ptr [r15+KROLE],2
    lea r12,[r15+CONTEXTS+256]
    mov eax,0xfffffffd
    cmp [r12+CRET],rax
    jne contract
    cmp qword ptr [r12+CWCAP],192
    jb contract
    mov rdx,[r12+CWPTR]
    add rdx,96
    mov [r15+LPTR],rdx
    mov qword ptr [r15+LSLOTLEN],96
    mov rax,0x3158464b4d485348 /* HSHMKFX1 */
    cmp [rdx],rax
    jne contract
    mov rax,[rdx+48]
    or rax,[rdx+56]
    or rax,[rdx+64]
    or rax,[rdx+72]
    or rax,[rdx+80]
    or rax,[rdx+88]
    jnz contract
    mov rax,[rdx+8]
    mov [r15+KSEQ],rax
    call clear_kernel
    mov rdx,[r15+LPTR]
    mov rax,[rdx+16]
    cmp rax,1
    je mkdir_primitive
    cmp rax,2
    je statx_primitive
    cmp rax,3
    je statx_probe
    cmp rax,4
    jne contract
    cmp qword ptr [rdx+40],0
    jne contract
    call borrow_path
    mov qword ptr [r15+NR],262
    mov qword ptr [r15+FDARG],-100
    mov qword ptr [r15+STATLEN],144
    jmp kernel_issue
mkdir_primitive:
    cmp qword ptr [rdx+40],511
    jne contract
    call borrow_path
    mov qword ptr [r15+NR],83
    mov qword ptr [r15+MODEARG],511
    jmp kernel_issue
statx_primitive:
    cmp qword ptr [rdx+40],4095
    jne contract
    call borrow_path
    mov qword ptr [r15+NR],332
    mov qword ptr [r15+FDARG],-100
    mov qword ptr [r15+MODEARG],4095
    mov qword ptr [r15+STATLEN],256
    jmp kernel_issue
statx_probe:
    mov rax,[rdx+24]
    or rax,[rdx+32]
    jnz contract
    cmp qword ptr [rdx+40],4095
    jne contract
    mov qword ptr [r15+NR],332
    mov qword ptr [r15+MODEARG],4095
    jmp kernel_issue

dispatch_file:
    mov rax,[r15+PSLOT+24]
    cmp rax,3
    jb contract
    cmp rax,5
    ja contract
    mov [r15+KROLE],rax
    shl rax,7
    lea r12,[r15+CONTEXTS+rax]
    mov rax,[r15+PSLOT+32]
    or rax,[r15+PSLOT+40]
    or rax,[r15+PSLOT+48]
    jnz contract
    mov eax,0xfffffffd
    cmp [r12+CRET],rax
    jne contract
    cmp qword ptr [r12+CWCAP],224
    jb contract
    mov rdx,[r12+CWPTR]
    add rdx,128
    mov [r15+LPTR],rdx
    mov qword ptr [r15+LSLOTLEN],96
    mov rax,0x3158464643485348 /* HSHCFFX1 */
    cmp [rdx],rax
    jne contract
    mov rax,[rdx+56]
    or rax,[rdx+64]
    or rax,[rdx+72]
    or rax,[rdx+80]
    or rax,[rdx+88]
    jnz contract
    mov rax,[rdx+8]
    mov [r15+KSEQ],rax
    call clear_kernel
    mov rdx,[r15+LPTR]
    mov rax,[rdx+16]
    cmp rax,1
    je open_primitive
    cmp rax,2
    je unlink_primitive
    cmp rax,3
    jne contract
    mov rax,[rdx+32]
    or rax,[rdx+40]
    or rax,[rdx+48]
    jnz contract
    mov rax,[rdx+24]
    mov [r15+TARGETTOKEN],rax
    call find_token
    mov rax,[r15+KROLE]
    cmp [rbx+32],rax
    jne contract
    mov rax,[rbx+16]
    mov [r15+FDARG],rax
    mov qword ptr [r15+NR],3
    jmp kernel_issue
open_primitive:
    cmp qword ptr [rdx+40],0x80241
    jne contract
    cmp qword ptr [rdx+48],438
    jne contract
    mov rbx,[r12+CNODE]
    test rbx,rbx
    jz contract
    cmp qword ptr [rbx+8],0
    jne contract
    mov [r15+NODE],rbx
    call borrow_path
    mov qword ptr [r15+NR],257
    mov qword ptr [r15+FDARG],-100
    mov qword ptr [r15+FLAGS],0x80241
    mov qword ptr [r15+MODEARG],438
    jmp kernel_issue
unlink_primitive:
    mov rax,[rdx+40]
    or rax,[rdx+48]
    jnz contract
    call borrow_path
    mov qword ptr [r15+NR],87
    jmp kernel_issue

close_owned:
    mov rax,[r15+PSLOT+32]
    or rax,[r15+PSLOT+40]
    or rax,[r15+PSLOT+48]
    jnz contract
    mov qword ptr [r15+KROLE],0
    mov qword ptr [r15+KSEQ],0
    mov qword ptr [r15+LPTR],0
    mov qword ptr [r15+LSLOTLEN],0
    call clear_kernel
    mov rax,[r15+PSLOT+24]
    mov [r15+TARGETTOKEN],rax
    call find_token
    cmp qword ptr [rbx+32],0
    jne contract
    mov rax,[rbx+16]
    mov [r15+FDARG],rax
    mov qword ptr [r15+NR],3
    jmp kernel_issue

clear_kernel:
    mov qword ptr [r15+PATHPTR],0
    mov qword ptr [r15+PATHLEN],0
    mov qword ptr [r15+NR],0
    mov qword ptr [r15+FDARG],0
    mov qword ptr [r15+FLAGS],0
    mov qword ptr [r15+MODEARG],0
    mov qword ptr [r15+RAW],0
    mov qword ptr [r15+KERRNO],0
    mov qword ptr [r15+HANDLE],0
    mov qword ptr [r15+MODEOUT],0
    mov qword ptr [r15+STATLEN],0
    mov qword ptr [r15+TARGETTOKEN],0
    lea rdi,[r15+STATBUF]
    xor eax,eax
    mov ecx,32
    rep stosq
    ret

/* Validate the HIA-selected C-string borrow; never choose another path. */
borrow_path:
    mov rdx,[r15+LPTR]
    mov rax,[rdx+24]
    mov rcx,[rdx+32]
    mov rbx,[r12+CWCAP]
    cmp rax,rbx
    ja contract
    sub rbx,rax
    cmp rcx,rbx
    jae contract
    add rax,[r12+CWPTR]
    cmp byte ptr [rax+rcx],0
    jne contract
    mov [r15+PATHPTR],rax
    mov [r15+PATHLEN],rcx
    xor edx,edx
borrow_scan:
    cmp rdx,rcx
    jae borrow_done
    cmp byte ptr [rax+rdx],0
    je contract
    inc rdx
    jmp borrow_scan
borrow_done:
    ret

kernel_issue:
    inc qword ptr [r15+KISSUED]
    mov qword ptr [r15+PHASE],0
    call record_kernel
    mov rax,[r15+NR]
    cmp eax,83
    je do_mkdir
    cmp eax,332
    je do_statx
    cmp eax,262
    je do_fstatat
    cmp eax,257
    je do_openat
    cmp eax,87
    je do_unlink
    cmp eax,3
    jne contract
    mov rdi,[r15+FDARG]
    syscall
    jmp kernel_return
do_mkdir:
    mov rdi,[r15+PATHPTR]
    mov rsi,[r15+MODEARG]
    syscall
    jmp kernel_return
do_statx:
    mov rdi,[r15+FDARG]
    mov rsi,[r15+PATHPTR]
    xor edx,edx
    mov r10,[r15+MODEARG]
    xor r8d,r8d
    cmp qword ptr [r15+STATLEN],0
    je statx_buffer_ready
    lea r8,[r15+STATBUF]
statx_buffer_ready:
    syscall
    jmp kernel_return
do_fstatat:
    mov rdi,-100
    mov rsi,[r15+PATHPTR]
    lea rdx,[r15+STATBUF]
    xor r10d,r10d
    syscall
    jmp kernel_return
do_openat:
    mov rdi,-100
    mov rsi,[r15+PATHPTR]
    mov rdx,[r15+FLAGS]
    mov r10,[r15+MODEARG]
    syscall
    jmp kernel_return
do_unlink:
    mov rdi,[r15+PATHPTR]
    syscall
kernel_return:
    mov [r15+RAW],rax
    test rax,rax
    jns kernel_success
    cmp rax,-4095
    jl contract
    neg rax
    mov [r15+KERRNO],rax
    jmp kernel_custody
kernel_success:
    cmp qword ptr [r15+NR],257
    je mint_token
    test rax,rax
    jnz contract
    cmp qword ptr [r15+STATLEN],0
    je kernel_custody
    cmp qword ptr [r15+NR],332
    jne stat64_mode
    movzx eax,word ptr [r15+STATBUF+28]
    mov [r15+MODEOUT],rax
    jmp kernel_custody
stat64_mode:
    mov eax,[r15+STATBUF+24]
    mov [r15+MODEOUT],rax
    jmp kernel_custody
mint_token:
    cmp rax,0x7fffffff
    ja contract
    mov rbx,[r15+NODE]
    mov rdx,[r15+TOKENS]
    mov [rbx],rdx
    mov rdx,[r15+NEXTTOKEN]
    test rdx,rdx
    jz contract
    mov [rbx+8],rdx
    mov [r15+HANDLE],rdx
    inc qword ptr [r15+NEXTTOKEN]
    mov [rbx+16],rax
    mov qword ptr [rbx+24],1
    mov rdx,[r15+KROLE]
    mov [rbx+32],rdx
    mov rdx,[r15+PARENTSEQ]
    mov [rbx+40],rdx
    mov rdx,[r15+KSEQ]
    mov [rbx+48],rdx
    mov rdx,[r15+REQUESTS]
    mov [rbx+56],rdx
    mov [r15+TOKENS],rbx
    inc qword ptr [r15+MINTED]
    inc qword ptr [r15+LIVE]
kernel_custody:
    cmp qword ptr [r15+NR],3
    jne kernel_completion
    mov rbx,[r15+NODE]
    mov qword ptr [rbx+24],0
    inc qword ptr [r15+CLOSED]
    dec qword ptr [r15+LIVE]
    cmp qword ptr [rbx+32],0
    jne kernel_completion
    dec qword ptr [r15+RECEIVER]
kernel_completion:
    cmp qword ptr [r15+KROLE],0
    je receiver_completion
    mov rdx,[r15+LPTR]
    cmp qword ptr [r15+KROLE],2
    je mkdir_completion
    mov rax,[r15+RAW]
    mov [rdx+64],rax
    mov rax,[r15+KERRNO]
    mov [rdx+72],rax
    mov rax,[r15+HANDLE]
    mov [rdx+80],rax
    mov qword ptr [rdx+56],1
    jmp kernel_record_done
mkdir_completion:
    mov rax,[r15+RAW]
    mov [rdx+56],rax
    mov rax,[r15+KERRNO]
    mov [rdx+64],rax
    mov rax,[r15+MODEOUT]
    mov [rdx+72],rax
    mov qword ptr [rdx+48],1
    jmp kernel_record_done
receiver_completion:
    copyq RESULT,RAW
    copyq ERRNO,KERRNO
kernel_record_done:
    inc qword ptr [r15+KCOMPLETED]
    mov qword ptr [r15+PHASE],1
    call record_kernel
    jmp complete_outer

record_entry:
    mov edi,1
    lea rsi,[r15+TS]
    mov eax,228
    syscall
    test rax,rax
    js infrastructure
    mov rax,0x31304e4552505348 /* HSPREN01 */
    mov [r15+EHEAD],rax
    copyq EHEAD+8,REQUESTS
    copyq EHEAD+16,ENTRIES
    copyq EHEAD+24,ACTIVE
    copyq EHEAD+32,PHASE
    copyq EHEAD+40,PID
    copyq EHEAD+48,TID
    mov rax,[r12+CILEN]
    mov [r15+EHEAD+56],rax
    mov rax,[r12+COCAP]
    mov [r15+EHEAD+64],rax
    mov rax,[r12+CWCAP]
    mov [r15+EHEAD+72],rax
    xor eax,eax
    cmp qword ptr [r15+PHASE],0
    je entry_return_ready
    mov rax,[r12+CRET]
entry_return_ready:
    mov [r15+EHEAD+80],rax
    mov rax,[r15+TS]
    imul rax,1000000000
    add rax,[r15+TS+8]
    mov [r15+EHEAD+88],rax
    copyq EHEAD+96,PARENTSEQ
    copyq EHEAD+104,ISSUED
    copyq EHEAD+112,COMPLETED
    copyq EHEAD+120,KISSUED
    copyq EHEAD+128,KCOMPLETED
    copyq EHEAD+136,MINTED
    copyq EHEAD+144,CLOSED
    copyq EHEAD+152,ADOPTED
    copyq EHEAD+160,LIVE
    copyq EHEAD+168,RECEIVER
    mov rax,[r12+CICAP]
    mov [r15+EHEAD+176],rax
    mov rax,[r12+CCALLS]
    mov [r15+EHEAD+184],rax
    audit_write EFD,EHEAD,192
    mov rdi,[r15+EFD]
    mov rsi,[r12+CIBASE]
    mov rdx,[r12+CICAP]
    add rdx,32
    call write_all
    test eax,eax
    jnz infrastructure
    mov rdi,[r15+EFD]
    mov rsi,[r12+COBASE]
    mov rdx,[r12+COCAP]
    add rdx,32
    call write_all
    test eax,eax
    jnz infrastructure
    mov rdi,[r15+EFD]
    mov rsi,[r12+CWBASE]
    mov rdx,[r12+CWCAP]
    add rdx,32
    call write_all
    test eax,eax
    jnz infrastructure
    ret

record_outer:
    mov rax,0x3130464552505348 /* HSPREF01 */
    mov [r15+OHEAD],rax
    copyq OHEAD+8,REQUESTS
    copyq OHEAD+16,PARENTSEQ
    copyq OHEAD+24,PID
    copyq OHEAD+32,TID
    copyq OHEAD+40,PHASE
    copyq OHEAD+48,ISSUED
    copyq OHEAD+56,COMPLETED
    copyq OHEAD+64,KISSUED
    copyq OHEAD+72,KCOMPLETED
    copyq OHEAD+80,MINTED
    copyq OHEAD+88,CLOSED
    copyq OHEAD+96,ADOPTED
    copyq OHEAD+104,LIVE
    copyq OHEAD+112,RECEIVER
    copyq OHEAD+120,SEED
    copyq OHEAD+128,SEQUENCE
    copyq OHEAD+136,LASTRET
    copyq OHEAD+144,ARENAS
    copyq OHEAD+152,CHILDSIZE
    audit_write TFD,OHEAD,192
    mov rdi,[r15+TFD]
    mov rsi,[r15+CONTEXTS+CWPTR]
    add rsi,128
    mov edx,96
    call write_all
    test eax,eax
    jnz infrastructure
    ret

record_kernel:
    mov rax,0x3130435352505348 /* HSPRSC01 */
    mov [r15+KHEAD],rax
    copyq KHEAD+8,REQUESTS
    copyq KHEAD+16,PARENTSEQ
    copyq KHEAD+24,KROLE
    copyq KHEAD+32,KSEQ
    copyq KHEAD+40,PID
    copyq KHEAD+48,TID
    copyq KHEAD+56,PHASE
    copyq KHEAD+64,NR
    copyq KHEAD+72,FDARG
    copyq KHEAD+80,FLAGS
    copyq KHEAD+88,MODEARG
    copyq KHEAD+96,RAW
    copyq KHEAD+104,KERRNO
    copyq KHEAD+112,HANDLE
    copyq KHEAD+120,MODEOUT
    copyq KHEAD+128,PATHLEN
    copyq KHEAD+136,LSLOTLEN
    copyq KHEAD+144,STATLEN
    copyq KHEAD+152,TARGETTOKEN
    copyq KHEAD+160,MINTED
    copyq KHEAD+168,CLOSED
    copyq KHEAD+176,LIVE
    copyq KHEAD+184,RECEIVER
    audit_write TFD,KHEAD,192
    mov rdi,[r15+TFD]
    mov rsi,[r15+LPTR]
    mov rdx,[r15+LSLOTLEN]
    call write_all
    test eax,eax
    jnz infrastructure
    mov rdi,[r15+TFD]
    mov rsi,[r15+PATHPTR]
    mov rdx,[r15+PATHLEN]
    call write_all
    test eax,eax
    jnz infrastructure
    mov rdi,[r15+TFD]
    lea rsi,[r15+STATBUF]
    mov rdx,[r15+STATLEN]
    call write_all
    test eax,eax
    jnz infrastructure
    ret

/* A gate admits an acknowledgement, never a supplied effect completion. */
effect_gate:
    mov rax,0x3130544752505348 /* HSPRGT01 */
    mov [r15+GATE],rax
    copyq GATE+8,PARENTSEQ
    copyq GATE+16,ACTION
    copyq GATE+24,REQUESTS
    copyq GATE+32,ENTRIES
    copyq GATE+40,KCOMPLETED
    copyq GATE+48,MINTED
    copyq GATE+56,CLOSED
    copyq GATE+64,ADOPTED
    copyq GATE+72,LIVE
    copyq GATE+80,RECEIVER
    copyq GATE+88,SEQUENCE
    mov edi,1
    lea rsi,[r15+GATE]
    mov edx,96
    call write_all
    test eax,eax
    jnz infrastructure
    xor edi,edi
    lea rsi,[r15+ACK]
    mov edx,16
    call read_exact
    test eax,eax
    jnz infrastructure
    mov rax,0x314b434152505348 /* HSPRACK1 */
    cmp [r15+ACK],rax
    jne contract
    mov rax,[r15+PARENTSEQ]
    cmp [r15+ACK+8],rax
    jne contract
    ret

normal_exit:
    mov rax,0x3144554152505348 /* HSPRAUD1 */
    mov [r15+FOOTER],rax
    copyq FOOTER+8,PID
    copyq FOOTER+16,REQUESTS
    copyq FOOTER+24,ENTRIES
    copyq FOOTER+32,ISSUED
    copyq FOOTER+40,COMPLETED
    copyq FOOTER+48,KISSUED
    copyq FOOTER+56,KCOMPLETED
    copyq FOOTER+64,MINTED
    copyq FOOTER+72,CLOSED
    copyq FOOTER+80,ADOPTED
    copyq FOOTER+88,LIVE
    copyq FOOTER+96,RECEIVER
    copyq FOOTER+104,SEED
    copyq FOOTER+112,SEQUENCE
    copyq FOOTER+120,IOERR
    copyq FOOTER+128,BAD
    copyq FOOTER+136,LASTRET
    mov rax,[r15+CONTEXTS+COCAP]
    mov [r15+FOOTER+144],rax
    mov rax,[r15+CONTEXTS+CWCAP]
    mov [r15+FOOTER+152],rax
    copyq FOOTER+160,CHILDSIZE
    copyq FOOTER+168,ARENAS
    copyq FOOTER+176,TFD
    copyq FOOTER+184,EFD
    xor ecx,ecx
footer_calls:
    mov rax,rcx
    shl rax,7
    mov rax,[r15+CONTEXTS+rax+CCALLS]
    mov [r15+FOOTER+192+rcx*8],rax
    inc ecx
    cmp ecx,6
    jb footer_calls
    copyq FOOTER+240,FIRST
    audit_write TFD,FOOTER,256
    audit_write EFD,FOOTER,256
    mov edi,1
    lea rsi,[r15+FOOTER]
    mov edx,256
    call write_all
    test eax,eax
    jnz infrastructure
    xor edi,edi
    jmp exit_group

/* Only transport loops retry EINTR; fixed kernel effects above never retry. */
read_exact:
    mov r8,rdx
read_loop:
    test rdx,rdx
    jz io_ok
    xor eax,eax
    syscall
    cmp rax,-4
    je read_loop
    test rax,rax
    js io_bad
    jz read_eof
    add rsi,rax
    sub rdx,rax
    jmp read_loop
read_eof:
    cmp rdx,r8
    jne io_bad
    mov eax,1
    ret
write_all:
    test rdx,rdx
    jz io_ok
write_loop:
    mov eax,1
    syscall
    cmp rax,-4
    je write_loop
    test rax,rax
    jle io_bad
    add rsi,rax
    sub rdx,rax
    jnz write_loop
io_ok:
    xor eax,eax
    ret
io_bad:
    mov eax,-1
    ret
map_rw:
    mov rsi,rdi
    xor edi,edi
    mov edx,3
    mov r10d,0x22
    mov r8,-1
    xor r9d,r9d
    mov eax,9
    syscall
    test rax,rax
    js infrastructure
    ret
normalize_audit_fd:
    cmp rax,3
    jae normalized
    push rbx
    mov rbx,rax
    mov rdi,rax
    mov esi,1030
    mov edx,3
    mov eax,72
    syscall
    test rax,rax
    js infrastructure
    push rax
    mov rdi,rbx
    mov eax,3
    syscall
    pop rax
    pop rbx
normalized:
    ret
equal_cstring:
    mov al,[rdi]
    cmp al,[rsi]
    jne unequal
    test al,al
    jz equal
    inc rdi
    inc rsi
    jmp equal_cstring
equal:
    mov eax,1
    ret
unequal:
    xor eax,eax
    ret
usage:
    mov edi,64
    jmp exit_group
infrastructure:
    mov qword ptr [r15+IOERR],1
    mov edi,74
    jmp exit_group
contract:
    mov qword ptr [r15+BAD],1
    mov edi,78
exit_group:
    mov eax,231
    syscall
    ud2
option_name: .asciz "--capture-prepare-fixture"
effects_name: .asciz "effects.bin"
entries_name: .asciz "entries.bin"
.balign 8,0
module_offset_table:
    .quad 0,0,0,0
.size _start, .-_start
.balign 16,0
shell_capture_prepare_entry:
    int3

