.intel_syntax noprefix
.text
.equ lcsp_I_SPEC,512
.equ lcsp_I_READ,520
.equ lcsp_I_PATH,528
.equ lcsp_I_MKDIR,536
.equ lcsp_I_WRITE,544
.equ lcsp_I_KEY,552
.equ lcsp_I_CACHE,560
.equ lcsp_FRAME,576
.equ lcsp_FRAMECAP,584
.equ lcsp_FRAMELEN,592
.equ lcsp_WORK,600
.equ lcsp_WORKCAP,608
.equ lcsp_OUT,616
.equ lcsp_OUTCAP,624
.equ lcsp_CURRENT,632
.equ lcsp_CURRENTLEN,640
.equ lcsp_CALLBACK,656
.equ lcsp_CALLBACKCAP,664
.equ lcsp_CHILD,672
.equ lcsp_SEQUENCE,680
.equ lcsp_GENERATION,688
.equ lcsp_CHILDREQ,696
.equ lcsp_CHILDREQLEN,704
.equ lcsp_CHILDRESULT,712
.equ lcsp_CHILDRESULTLEN,720
.equ lcsp_CHILDCODE,728
.equ lcsp_CREATED,736
.equ lcsp_CACHE_INIT,744
.equ lcsp_CACHE,752
.equ lcsp_CACHECAP,760
.equ lcsp_CACHEOUT,768
.equ lcsp_CACHEOUTCAP,776
.equ lcsp_CACHEINPUT,784
.equ lcsp_CACHEINPUTLEN,792
.equ lcsp_SCRATCH,800
.equ lcsp_SCRATCHCAP,808
.equ lcsp_SUBOUT,816
.equ lcsp_SUBOUTCAP,824
.equ lcsp_ACTIVE_KIND,848
.equ lcsp_ASYNCINPUT,856
.equ lcsp_ASYNCWORK,864
.equ lcsp_ASYNCINCAP,872
.equ lcsp_ASYNCWCAP,880
.equ lcsp_MKREQ,888
.equ lcsp_MKREQCAP,896
.equ lcsp_MKWORK,904
.equ lcsp_MKWORKCAP,912
.equ lcsp_MKSEQ,928
.equ lcsp_SECURE,984
.equ lcsp_KEYCTX,2048
.equ lcsp_READCTX,2176
.global local_create_spec_run
.global local_create_spec_release
.global local_create_spec_cancel
.equ lcsp_PUBLIC_CTX,1200
.equ lcsp_RETURN_STACK,1208
.equ lcsp_META_POINTER,1224
.equ lcsp_MAIN_MAGIC,3544428917551221832

local_create_spec_run:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp,24
    mov [rsp],rdi
    mov [rsp+8],rsi
    mov [rsp+16],rdx
    mov r13,rsp
    test rdi,rdi
    jz lcsp_callable_invalid_early
    mov rax,3544385997943032904
    cmp [rdi],rax
    jne lcsp_callable_invalid_early
    cmp qword ptr [rdi+8],160
    jne lcsp_callable_invalid_early
    cmp qword ptr [rdi+16],0
    je lcsp_callable_invalid_early
    cmp qword ptr [rdi+24],0
    je lcsp_callable_invalid_early
    cmp qword ptr [rdi+64],1
    ja lcsp_callable_invalid_early
    cmp qword ptr [rdi+72],1
    ja lcsp_callable_invalid_early
    cmp qword ptr [rdi+152],0
    jne lcsp_callable_invalid_early
    mov ecx,80
lcsp_callable_empty_outputs:
    cmp qword ptr [rdi+rcx],0
    jne lcsp_callable_invalid_early
    add ecx,8
    cmp ecx,136
    jb lcsp_callable_empty_outputs
    mov rax,[rdi+40]
    test rax,rax
    jz lcsp_callable_invalid_early
    test al,7
    jnz lcsp_callable_invalid_early
    cmp qword ptr [rax],1
    ja lcsp_callable_invalid_early
    mov rax,[rdi+136]
    test rax,rax
    jz lcsp_callable_no_wake_check
    test al,7
    jnz lcsp_callable_invalid_early
    cmp qword ptr [rax],1
    ja lcsp_callable_invalid_early
lcsp_callable_no_wake_check:
    mov rax,[rdi+144]
    test rax,rax
    jz lcsp_callable_invalid_early
    cmp byte ptr [rax],2
    ja lcsp_callable_invalid_early
    mov rax,[rdi+16]
    xor ecx,ecx
lcsp_callable_entries_check:
    cmp qword ptr [rax+rcx*8],0
    je lcsp_callable_invalid_early
    inc ecx
    cmp ecx,7
    jb lcsp_callable_entries_check
    xor r15d,r15d
    mov edi,4096
    call lcsp_allocate_guarded
    mov r15,rax
    mov rax,lcsp_MAIN_MAGIC
    mov [r15],rax
    mov rbx,[rsp]
    mov [r15+lcsp_PUBLIC_CTX],rbx
    mov [r15+lcsp_RETURN_STACK],rsp
    mov [rbx+120],r15
    mov rax,[rbx+144]
    mov [r15+lcsp_META_POINTER],rax
    mov rsi,[rbx+16]
    lea rdi,[r15+lcsp_I_SPEC]
    mov ecx,7
    rep movsq
    mov rax,[rbx+64]
    mov [r15+lcsp_SECURE],rax
    mov rax,[rsp+8]
    mov [r15+lcsp_CURRENT],rax
    mov rax,[rsp+16]
    mov [r15+lcsp_CURRENTLEN],rax
    mov edi,4096
    call lcsp_async_map
    mov [r15+320],rax
    mov rbx,rax
    mov qword ptr [rbx],-1
    mov eax,39
    syscall
    mov [rbx+40],rax
    call lcsp_callable_sync_flags
    lea rdi,[r15+lcsp_WORK]
    mov esi,4096
    xor edx,edx
    call lcsp_ensure_region
    mov rbx,[r15+320]
    mov rdx,[rbx+16]
    mov [rax+112],rdx
    lea rdi,[r15+lcsp_OUT]
    mov esi,4096
    xor edx,edx
    call lcsp_ensure_region
    jmp lcsp_full_invoke

/* Only an existing parent poll/WAIT boundary consumes these owned words. */
lcsp_callable_sync_flags:
    mov rax,[r15+lcsp_PUBLIC_CTX]
    mov r10,[r15+320]
    mov r11,[rax+40]
    mov r11,[r11]
    cmp r11,1
    ja lcsp_contract
    or [r10+16],r11
    mov r11,[rax+136]
    test r11,r11
    jz lcsp_callable_sync_done
    xor eax,eax
    xchg rax,[r11]
    cmp rax,1
    ja lcsp_contract
    or dword ptr [r10+120],eax
lcsp_callable_sync_done:
    ret

lcsp_callable_publish:
    push rbp
    mov rbp,rsp
    and rsp,-16
    mov r10,[r15+lcsp_PUBLIC_CTX]
    cmp qword ptr [r10+104],0
    jne lcsp_contract
    mov edx,eax
    cmp rax,rdx
    jne lcsp_contract
    mov [r10+96],rax
    xor edx,edx
    xor ecx,ecx
    cmp eax,0xffff0000
    jae lcsp_callable_publish_fields
    mov rdx,[r15+lcsp_OUT]
    mov rcx,rax
lcsp_callable_publish_fields:
    mov [r10+80],rdx
    mov [r10+88],rcx
    mov qword ptr [r10+104],1
    mov r11,[r10+48]
    test r11,r11
    jz lcsp_callable_publish_done
    mov rdi,[r10+56]
    mov esi,eax
    call r11
lcsp_callable_publish_done:
    mov rsp,rbp
    pop rbp
    ret

lcsp_callable_metadata_publish:
    cmp qword ptr [r15+lcsp_ACTIVE_KIND],3
    jne lcsp_callable_metadata_done
    mov r10,[r15+320]
    cmp qword ptr [r10+136],1
    jne lcsp_callable_metadata_done
    movzx eax,byte ptr [r10+128]
    cmp eax,2
    ja lcsp_contract
    mov r10,[r15+lcsp_META_POINTER]
    mov [r10],al
lcsp_callable_metadata_done:
    ret

lcsp_callable_finish:
    mov r10,[r15+lcsp_PUBLIC_CTX]
    cmp qword ptr [r10+104],1
    jne lcsp_contract
    mov r11,[r15+320]
    test r11,r11
    jz lcsp_callable_finished_drained
    cmp qword ptr [r11],-1
    jne lcsp_contract
    cmp qword ptr [r11+32],0
    jne lcsp_contract
lcsp_callable_finished_drained:
    mov qword ptr [r10+112],1
    mov eax,[r10+96]
    cmp qword ptr [r10+128],0
    je lcsp_callable_return
    mov eax,0xfffffffc
lcsp_callable_return:
    mov rsp,[r15+lcsp_RETURN_STACK]
lcsp_callable_restore:
    add rsp,24
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

lcsp_callable_invalid_early:
    mov eax,0xffffffff
    mov rsp,r13
    jmp lcsp_callable_restore
lcsp_callable_resource_early:
    mov rsp,r13
    mov r10,[rsp]
    mov eax,0xfffffffc
    mov [r10+96],rax
    mov qword ptr [r10+104],1
    mov qword ptr [r10+112],1
    mov qword ptr [r10+128],74
    mov r11,[r10+48]
    test r11,r11
    jz lcsp_callable_resource_early_done
    mov rdi,[r10+56]
    mov esi,0xfffffffc
    xor edx,edx
    xor ecx,ecx
    call r11
lcsp_callable_resource_early_done:
    mov eax,0xfffffffc
    jmp lcsp_callable_restore

/* Public cancellation sets a request bit, never HIA ready or ticket state. */
local_create_spec_cancel:
    test rdi,rdi
    jz lcsp_callable_cancel_invalid
    mov rax,3544385997943032904
    cmp [rdi],rax
    jne lcsp_callable_cancel_invalid
    cmp qword ptr [rdi+8],160
    jne lcsp_callable_cancel_invalid
    mov rax,[rdi+40]
    test rax,rax
    jz lcsp_callable_cancel_invalid
    test al,7
    jnz lcsp_callable_cancel_invalid
    mov qword ptr [rax],1
    mov rax,[rdi+120]
    test rax,rax
    jz lcsp_callable_cancel_done
    cmp qword ptr [rdi+112],0
    jne lcsp_callable_cancel_done
    mov rax,[rax+320]
    test rax,rax
    jz lcsp_callable_cancel_done
    mov qword ptr [rax+16],1
    lock inc dword ptr [rax+24]
    lea rdi,[rax+24]
    mov esi,1
    mov edx,2147483647
    xor r10d,r10d
    xor r8d,r8d
    xor r9d,r9d
    mov eax,202
    syscall
    test rax,rax
    js lcsp_callable_cancel_invalid
lcsp_callable_cancel_done:
    xor eax,eax
    ret
lcsp_callable_cancel_invalid:
    mov eax,0xffffffff
    ret

/* Release is allowed only after all tickets and descriptors are drained. */
local_create_spec_release:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov r12,rdi
    test rdi,rdi
    jz lcsp_callable_release_invalid
    mov rax,3544385997943032904
    cmp [rdi],rax
    jne lcsp_callable_release_invalid
    cmp qword ptr [rdi+8],160
    jne lcsp_callable_release_invalid
    cmp qword ptr [rdi+112],1
    jne lcsp_callable_release_busy
    mov r15,[rdi+120]
    test r15,r15
    jz lcsp_callable_release_done
    mov rax,lcsp_MAIN_MAGIC
    cmp [r15],rax
    jne lcsp_callable_release_invalid
    cmp [r15+lcsp_PUBLIC_CTX],r12
    jne lcsp_callable_release_invalid
    mov rax,[r15+320]
    test rax,rax
    jz lcsp_callable_release_regions
    cmp qword ptr [rax],-1
    jne lcsp_callable_release_busy
    cmp qword ptr [rax+32],0
    jne lcsp_callable_release_busy
lcsp_callable_release_regions:
    lea r13,[rip+lcsp_callable_owned_regions]
    mov r14d,9
lcsp_callable_release_one:
    mov rbx,[r13]
    mov rdi,[r15+rbx]
    test rdi,rdi
    jz lcsp_callable_release_next
    mov rsi,[r15+rbx+8]
    add rsi,4096
    jc lcsp_callable_release_invalid
    mov eax,11
    syscall
    test rax,rax
    jnz lcsp_callable_release_invalid
    mov qword ptr [r15+rbx],0
    mov qword ptr [r15+rbx+8],0
lcsp_callable_release_next:
    add r13,8
    dec r14d
    jnz lcsp_callable_release_one
    mov rdi,[r15+lcsp_ASYNCINPUT]
    mov rsi,[r15+lcsp_ASYNCINCAP]
    call lcsp_callable_release_shared
    mov rdi,[r15+lcsp_ASYNCWORK]
    mov rsi,[r15+lcsp_ASYNCWCAP]
    call lcsp_callable_release_shared
    mov rdi,[r15+320]
    mov esi,4096
    call lcsp_callable_release_shared
    mov rdi,r15
    mov esi,8192
    mov eax,11
    syscall
    test rax,rax
    jnz lcsp_callable_release_invalid
    mov qword ptr [r12+120],0
    mov qword ptr [r12+80],0
    mov qword ptr [r12+88],0
lcsp_callable_release_done:
    xor eax,eax
    jmp lcsp_callable_release_return
lcsp_callable_release_busy:
    mov eax,16
    jmp lcsp_callable_release_return
lcsp_callable_release_invalid:
    mov eax,0xffffffff
lcsp_callable_release_return:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret
lcsp_callable_release_shared:
    test rdi,rdi
    jz lcsp_callable_release_shared_done
    mov eax,11
    syscall
    test rax,rax
    jnz lcsp_callable_release_shared_bad
lcsp_callable_release_shared_done:
    ret
lcsp_callable_release_shared_bad:
    add rsp,8
    jmp lcsp_callable_release_invalid
.balign 8
lcsp_callable_owned_regions:
    .quad lcsp_WORK,lcsp_OUT,lcsp_CALLBACK,lcsp_SCRATCH,lcsp_SUBOUT,lcsp_MKREQ,lcsp_MKWORK,lcsp_KEYCTX+16,lcsp_KEYCTX+32

lcsp_full_invoke:
    mov rdi,[r15+lcsp_OUT]
    mov rsi,[r15+lcsp_OUTCAP]
    call lcsp_make_writable
    mov rdi,[r15+lcsp_CURRENT]
    mov rsi,[r15+lcsp_CURRENTLEN]
    mov rdx,[r15+lcsp_OUT]
    mov rcx,[r15+lcsp_OUTCAP]
    mov r8,[r15+lcsp_WORK]
    mov r9,[r15+lcsp_WORKCAP]
    call qword ptr [r15+lcsp_I_SPEC]
    mov edx,eax
    cmp rax,rdx
    jne lcsp_contract
    cmp eax,0xffffffef
    je lcsp_full_grow_work
    cmp eax,0xffffffee
    je lcsp_full_grow_output
    cmp eax,0xffffffe0
    je lcsp_full_child
    cmp eax,0xfffffff7
    je lcsp_full_publish_scalar
    cmp eax,0xffff0000
    jae lcsp_full_publish_scalar
    cmp eax,32
    jb lcsp_contract
    cmp rax,[r15+lcsp_OUTCAP]
    ja lcsp_contract
    mov rbx,[r15+lcsp_OUT]
    mov rdx,0x3130525053434c48
    cmp [rbx],rdx
    jne lcsp_contract
lcsp_full_publish_scalar:
    call lcsp_callable_publish
lcsp_full_finished:
    jmp lcsp_callable_finish
lcsp_full_grow_work:
    mov rax,[r15+lcsp_WORK]
    mov rsi,[rax+104]
    cmp rsi,[r15+lcsp_WORKCAP]
    jbe lcsp_contract
    lea rdi,[r15+lcsp_WORK]
    mov edx,1
    call lcsp_ensure_region
    jmp lcsp_full_invoke
lcsp_full_grow_output:
    mov rax,[r15+lcsp_WORK]
    mov rsi,[rax+136]
    cmp rsi,[r15+lcsp_OUTCAP]
    jbe lcsp_contract
    lea rdi,[r15+lcsp_OUT]
    xor edx,edx
    call lcsp_ensure_region
    jmp lcsp_full_invoke

lcsp_full_child:
    mov rbx,[r15+lcsp_OUT]
    mov rax,0x3158465053434c48
    cmp [rbx],rax
    jne lcsp_contract
    cmp qword ptr [rbx+56],0
    jne lcsp_contract
    mov rax,[rbx+8]
    cmp rax,[r15+lcsp_OUTCAP]
    ja lcsp_contract
    sub rax,64
    jc lcsp_contract
    cmp [rbx+48],rax
    jne lcsp_contract
    mov [r15+lcsp_CHILDREQLEN],rax
    lea rax,[rbx+64]
    mov [r15+lcsp_CHILDREQ],rax
    mov rdx,[r15+lcsp_WORK]
    mov rax,[rbx+16]
    cmp rax,1
    jb lcsp_contract
    cmp rax,7
    ja lcsp_contract
    cmp [rdx+144],rax
    jne lcsp_contract
    mov [r15+lcsp_CHILD],rax
    mov rax,[rbx+24]
    cmp [rdx+16],rax
    jne lcsp_contract
    mov [r15+lcsp_SEQUENCE],rax
    mov rax,[rbx+32]
    cmp [rdx+24],rax
    jne lcsp_contract
    mov [r15+lcsp_GENERATION],rax
    mov rax,[r15+lcsp_CHILD]
    mov ecx,1
    cmp rax,3
    jne lcsp_not_mkdir_flags
    mov ecx,3
lcsp_not_mkdir_flags:
    cmp rax,4
    jne lcsp_child_flags_ready
    mov ecx,5
lcsp_child_flags_ready:
    cmp [rbx+40],rcx
    jne lcsp_contract
    mov edi,2
    mov rsi,rbx
    mov edx,64
    call lcsp_write_all
    test eax,eax
    jnz lcsp_infrastructure
    mov rdi,[r15+lcsp_OUT]
    mov rsi,[r15+lcsp_OUTCAP]
    call lcsp_make_readonly
    mov rax,[r15+lcsp_CHILD]
    cmp rax,1
    je lcsp_child_read
    cmp rax,2
    je lcsp_child_path
    cmp rax,3
    je lcsp_child_mkdir
    cmp rax,4
    je lcsp_child_write
    cmp rax,5
    je lcsp_child_key
    cmp rax,6
    je lcsp_child_cache
    mov rax,[r15+lcsp_CHILDREQ]
    cmp qword ptr [r15+lcsp_CHILDREQLEN],16
    jne lcsp_contract
    mov rdx,0x313051544d434c48
    cmp [rax],rdx
    jne lcsp_contract
    cmp qword ptr [rax+8],0
    jne lcsp_contract
    mov rax,0x313052544d434c48
    mov [r15+1104],rax
    mov rax,[r15+lcsp_META_POINTER]
    movzx eax,byte ptr [rax]
    cmp eax,2
    ja lcsp_contract
    mov [r15+1112],rax
    lea rax,[r15+1104]
    mov [r15+lcsp_CHILDRESULT],rax
    mov qword ptr [r15+lcsp_CHILDRESULTLEN],16
    mov qword ptr [r15+lcsp_CHILDCODE],16
    jmp lcsp_full_finish_child

lcsp_child_read:
    lea rdi,[r15+lcsp_SCRATCH]
    mov rsi,[r15+lcsp_CHILDREQLEN]
    add rsi,1024
    jc lcsp_infrastructure
    xor edx,edx
    call lcsp_ensure_region
    lea rdi,[r15+lcsp_SUBOUT]
    mov esi,4096
    xor edx,edx
    call lcsp_ensure_region
    lea rdi,[r15+lcsp_READCTX]
    xor eax,eax
    mov ecx,12
    rep stosq
    mov rax,[r15+lcsp_CHILDREQ]
    mov [r15+lcsp_READCTX],rax
    mov rax,[r15+lcsp_CHILDREQLEN]
    mov [r15+lcsp_READCTX+48],rax
    mov rax,[r15+lcsp_SCRATCH]
    mov [r15+lcsp_READCTX+16],rax
    mov rax,[r15+lcsp_SCRATCHCAP]
    mov [r15+lcsp_READCTX+24],rax
    mov rax,[r15+lcsp_SUBOUT]
    mov [r15+lcsp_READCTX+32],rax
    mov rax,[r15+lcsp_SUBOUTCAP]
    mov [r15+lcsp_READCTX+40],rax
    mov rax,[r15+lcsp_META_POINTER]
    mov [r15+lcsp_READCTX+64],rax
    mov [r15+lcsp_READCTX+96],r15
    mov rax,[r15+lcsp_I_READ]
    mov [r15+lcsp_READCTX+80],rax
    lea rdi,[r15+lcsp_READCTX]
    call lcsp_local_read_run
    cmp eax,40
    jne lcsp_contract
    mov [r15+lcsp_CHILDCODE],rax
    mov [r15+lcsp_CHILDRESULTLEN],rax
    mov rax,[r15+lcsp_SUBOUT]
    mov [r15+lcsp_CHILDRESULT],rax
    jmp lcsp_full_finish_child
lcsp_child_path:
    lea rdi,[r15+lcsp_SCRATCH]
    mov esi,4096
    xor edx,edx
    call lcsp_ensure_region
    lea rdi,[r15+lcsp_SUBOUT]
    mov rsi,[r15+lcsp_CHILDREQLEN]
    add rsi,80
    jc lcsp_infrastructure
    xor edx,edx
    call lcsp_ensure_region
    mov rdi,[r15+lcsp_CHILDREQ]
    mov rsi,[r15+lcsp_CHILDREQLEN]
    mov rdx,[r15+lcsp_SUBOUT]
    mov rcx,[r15+lcsp_SUBOUTCAP]
    mov r8,[r15+lcsp_SCRATCH]
    mov r9,[r15+lcsp_SCRATCHCAP]
    call qword ptr [r15+lcsp_I_PATH]
    cmp eax,80
    jne lcsp_contract
    mov [r15+lcsp_CHILDCODE],rax
    mov rdx,[r15+lcsp_SUBOUT]
    mov [r15+lcsp_CHILDRESULT],rdx
    mov rax,[rdx+16]
    cmp rax,[r15+lcsp_SUBOUTCAP]
    ja lcsp_contract
    mov [r15+lcsp_CHILDRESULTLEN],rax
    jmp lcsp_full_finish_child
lcsp_child_key:
    lea rdi,[r15+lcsp_KEYCTX+16]
    mov esi,1056768
    xor edx,edx
    call lcsp_ensure_region
    lea rdi,[r15+lcsp_KEYCTX+32]
    mov esi,4096
    xor edx,edx
    call lcsp_ensure_region
    mov rax,[r15+lcsp_CHILDREQ]
    mov [r15+lcsp_KEYCTX],rax
    mov rax,[r15+lcsp_CHILDREQLEN]
    mov [r15+lcsp_KEYCTX+48],rax
    mov rax,[r15+lcsp_SECURE]
    mov [r15+lcsp_KEYCTX+64],rax
    mov qword ptr [r15+lcsp_KEYCTX+72],-1
    mov qword ptr [r15+lcsp_KEYCTX+80],-1
    mov qword ptr [r15+lcsp_KEYCTX+88],0
    mov rax,[r15+lcsp_I_KEY]
    mov [r15+lcsp_KEYCTX+96],rax
    mov [r15+lcsp_KEYCTX+104],r15
    lea rdi,[r15+lcsp_KEYCTX]
    call lcsp_key_run
    cmp eax,32
    jb lcsp_contract
    cmp eax,0xffff0000
    jae lcsp_contract
    mov [r15+lcsp_CHILDCODE],rax
    mov [r15+lcsp_CHILDRESULTLEN],rax
    mov rax,[r15+lcsp_KEYCTX+32]
    mov [r15+lcsp_CHILDRESULT],rax
    jmp lcsp_full_finish_child
lcsp_child_cache:
    mov rsi,[r15+lcsp_CHILDREQ]
    mov rdx,[r15+lcsp_CHILDREQLEN]
    cmp rdx,48
    jb lcsp_contract
    mov rax,0x3130484341435648
    cmp [rsi],rax
    jne lcsp_contract
    cmp qword ptr [rsi+8],6
    jne lcsp_contract
    mov qword ptr [r15+1168],0
    mov qword ptr [r15+1176],0
    mov r10,[r15+lcsp_PUBLIC_CTX]
    mov rdi,[r10+32]
    lea rcx,[r15+1168]
    call qword ptr [r10+24]
    cmp rax,32
    jne lcsp_contract
    cmp qword ptr [r15+1176],32
    jne lcsp_contract
    mov rdx,[r15+1168]
    test rdx,rdx
    jz lcsp_contract
    mov [r15+lcsp_CHILDCODE],rax
    mov [r15+lcsp_CHILDRESULTLEN],rax
    mov [r15+lcsp_CHILDRESULT],rdx
lcsp_full_finish_child:
    call lcsp_build_callback
    jmp lcsp_full_invoke

lcsp_build_callback:
    lea rdi,[r15+lcsp_CALLBACK]
    mov rsi,[r15+lcsp_CHILDRESULTLEN]
    add rsi,64
    jc lcsp_infrastructure
    xor edx,edx
    call lcsp_ensure_region
    mov rdi,[r15+lcsp_CALLBACK]
    mov rsi,[r15+lcsp_CALLBACKCAP]
    call lcsp_make_writable
    mov rdi,[r15+lcsp_CALLBACK]
    mov rax,0x3130435053434c48
    mov [rdi],rax
    mov qword ptr [rdi+8],2
    mov rax,[r15+lcsp_GENERATION]
    mov [rdi+16],rax
    mov rax,[r15+lcsp_SEQUENCE]
    mov [rdi+24],rax
    mov rax,[r15+lcsp_CHILD]
    mov [rdi+32],rax
    mov rax,[r15+lcsp_CHILDCODE]
    mov [rdi+40],rax
    mov rcx,[r15+lcsp_CHILDRESULTLEN]
    mov [rdi+48],rcx
    mov qword ptr [rdi+56],0
    mov rsi,[r15+lcsp_CHILDRESULT]
    add rdi,64
    rep movsb
    mov rdi,[r15+lcsp_CALLBACK]
    mov rsi,[r15+lcsp_CALLBACKCAP]
    call lcsp_make_readonly
    mov rax,[r15+lcsp_CALLBACK]
    mov [r15+lcsp_CURRENT],rax
    mov rax,[r15+lcsp_CHILDRESULTLEN]
    add rax,64
    mov [r15+lcsp_CURRENTLEN],rax
    ret

lcsp_round_capacity:
    mov rax,rdi
    add rax,4095
    jc lcsp_infrastructure
    and rax,-4096
    test rax,rax
    jnz lcsp_rounded
    mov eax,4096
lcsp_rounded:
    ret
lcsp_allocate_guarded:
    push rbx
    mov rbx,rdi
    mov rsi,rdi
    add rsi,4096
    jc lcsp_infrastructure
    xor edi,edi
    mov edx,3
    mov r10d,0x22
    mov r8,-1
    xor r9d,r9d
    mov eax,9
    syscall
    cmp rax,-4095
    jae lcsp_infrastructure
    push rax
    lea rdi,[rax+rbx]
    mov esi,4096
    xor edx,edx
    mov eax,10
    syscall
    test rax,rax
    jnz lcsp_callable_guard_fail
    pop rax
    pop rbx
    ret
lcsp_callable_guard_fail:
    pop rdi
    lea rsi,[rbx+4096]
    mov eax,11
    syscall
    pop rbx
    jmp lcsp_infrastructure
lcsp_ensure_region:
    push rbx
    push rbp
    push r12
    push r13
    mov rbx,rdi
    mov ebp,edx
    mov rax,[rbx]
    test rax,rax
    jz lcsp_ensure_allocate
    cmp rsi,[rbx+8]
    jbe lcsp_ensure_done
lcsp_ensure_allocate:
    mov rdi,rsi
    call lcsp_round_capacity
    mov r12,rax
    mov rdi,rax
    call lcsp_allocate_guarded
    mov r13,rax
    cmp qword ptr [rbx],0
    je lcsp_ensure_publish
    test ebp,ebp
    jz lcsp_ensure_retire
    mov rdi,r13
    mov rsi,[rbx]
    mov rcx,[rbx+8]
    rep movsb
lcsp_ensure_retire:
    mov rdi,[rbx]
    mov rsi,[rbx+8]
    add rsi,4096
    mov eax,11
    syscall
    test rax,rax
    jnz lcsp_infrastructure
lcsp_ensure_publish:
    mov [rbx],r13
    mov [rbx+8],r12
    mov rax,r13
lcsp_ensure_done:
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret
lcsp_make_readonly:
    mov edx,1
    jmp lcsp_set_protection
lcsp_make_writable:
    mov edx,3
lcsp_set_protection:
    mov eax,10
    syscall
    test rax,rax
    jnz lcsp_infrastructure
    ret
lcsp_protect_input:
    mov rdi,r12
    mov rsi,[r15+8]
    jmp lcsp_make_readonly
lcsp_write_all:
    cmp edi,2
    jne lcsp_contract
    mov rax,[r15+lcsp_PUBLIC_CTX]
    cmp qword ptr [rax+72],0
    je lcsp_io_ok
    test rdx,rdx
    jz lcsp_io_ok
lcsp_write_again:
    mov eax,1
    syscall
    cmp rax,-4
    je lcsp_write_again
    test rax,rax
    jle lcsp_io_bad
    add rsi,rax
    sub rdx,rax
    jnz lcsp_write_again
lcsp_io_ok:
    xor eax,eax
    ret
lcsp_io_bad:
    mov eax,1
    ret
lcsp_local_create_entry:
    mov rax,0x313051414d434c48
    cmp [rdi],rax
    je lcsp_mkdir_await_entry
    jmp qword ptr [r15+lcsp_I_WRITE]
lcsp_mkdir_await_entry:
    jmp qword ptr [r15+lcsp_I_SPEC]
lcsp_contract:
    jmp lcsp_async_contract
lcsp_infrastructure:
    test r15,r15
    jz lcsp_callable_resource_early
    mov rax,lcsp_MAIN_MAGIC
    cmp [r15],rax
    jne lcsp_callable_key_infrastructure
    mov edi,74
    jmp lcsp_callable_abort_with_code
lcsp_callable_key_infrastructure:
    call lcsp_key_cleanup
    mov edi,74
lcsp_fatal_exit:
    mov r15,[r15+104]
lcsp_callable_abort_with_code:
    mov ebx,edi
    cmp qword ptr [r15+320],0
    jne lcsp_async_abort
    jmp lcsp_callable_abort_parent
lcsp_child_write:
    mov qword ptr [r15+lcsp_ACTIVE_KIND],4
    mov r13,[r15+lcsp_CHILDREQLEN]
    mov rdi,r13
    call lcsp_round_capacity
    mov [r15+8],rax
    mov [r15+lcsp_ASYNCINCAP],rax
    mov rdi,rax
    call lcsp_async_map
    mov r12,rax
    mov [r15+lcsp_ASYNCINPUT],rax
    mov rdi,rax
    mov rsi,[r15+lcsp_CHILDREQ]
    mov rcx,r13
    rep movsb
    mov rdi,r13
    add rdi,456
    jc lcsp_infrastructure
    and rdi,-8
    mov [r15+304],rdi
    add rdi,256
    jc lcsp_infrastructure
    mov [r15+16],rdi
    mov [r15+lcsp_ASYNCWCAP],rdi
    call lcsp_async_map
    mov r14,rax
    mov [r15+lcsp_ASYNCWORK],rax
    jmp lcsp_nested_initialize

lcsp_child_mkdir:
    mov rax,[r15+lcsp_META_POINTER]
    movzx eax,byte ptr [rax]
    cmp eax,2
    ja lcsp_contract
    mov r10,[r15+320]
    mov [r10+128],al
    mov qword ptr [r10+136],0
    mov qword ptr [r15+lcsp_ACTIVE_KIND],3
    lea rdi,[r15+lcsp_MKREQ]
    mov rsi,[r15+lcsp_CHILDREQLEN]
    xor edx,edx
    call lcsp_ensure_region
    mov rdi,rax
    mov rsi,[r15+lcsp_CHILDREQ]
    mov rcx,[r15+lcsp_CHILDREQLEN]
    rep movsb
    mov rdi,[r15+lcsp_MKREQ]
    mov rsi,[r15+lcsp_MKREQCAP]
    call lcsp_make_readonly
    mov rax,[r15+lcsp_MKREQ]
    mov rsi,[rax+24]
    inc rsi
    jz lcsp_infrastructure
    mov rax,rsi
    mov ecx,10
    mul rcx
    test rdx,rdx
    jnz lcsp_infrastructure
    mov rsi,rax
    add rsi,512
    jc lcsp_infrastructure
    lea rdi,[r15+lcsp_MKWORK]
    xor edx,edx
    call lcsp_ensure_region
    lea rdi,[r15+lcsp_SUBOUT]
    mov esi,4096
    xor edx,edx
    call lcsp_ensure_region
    mov qword ptr [r15+lcsp_MKSEQ],0
    mov qword ptr [r15+304],0
    mov qword ptr [r15+8],4096
    mov qword ptr [r15+lcsp_ASYNCINCAP],4096
    mov edi,4096
    call lcsp_async_map
    mov r12,rax
    mov [r15+lcsp_ASYNCINPUT],rax
    mov rax,0x313051414d434c48
    mov [r12],rax
    mov qword ptr [r12+8],1
    mov rax,[r15+lcsp_GENERATION]
    mov [r12+32],rax
    mov r13d,64
    mov qword ptr [r15+16],512
    mov qword ptr [r15+lcsp_ASYNCWCAP],512
    mov edi,512
    call lcsp_async_map
    mov r14,rax
    mov [r15+lcsp_ASYNCWORK],rax
lcsp_nested_initialize:
    mov rbx,[r15+320]
    cmp qword ptr [rbx],-1
    jne lcsp_async_contract
    cmp qword ptr [rbx+32],0
    jne lcsp_async_contract
    cmp qword ptr [rbx+8],0
    jne lcsp_async_contract
    mov qword ptr [rbx+48],0
    mov qword ptr [rbx+56],0
    mov qword ptr [rbx+64],0
    mov qword ptr [rbx+72],0
    mov qword ptr [rbx+80],0
    mov qword ptr [rbx+96],0
    mov qword ptr [r15+488],0
    mov qword ptr [r15+496],0
    call lcsp_protect_input
    mov edi,1
    xor esi,esi
    xor edx,edx
    call lcsp_async_call
    cmp eax,128
    jne lcsp_async_contract
    cmp qword ptr [r15+368],10
    jne lcsp_async_contract
    /* The enclosing parent is still inside the same owned poll turn. */
    mov edi,2
    xor esi,esi
    xor edx,edx
    call lcsp_async_call
    jmp lcsp_async_parent_dispatch

lcsp_nested_continue:
    mov edi,8
    xor esi,esi
    call lcsp_async_parent_call
    jmp lcsp_async_parent_dispatch
lcsp_nested_mkdir_result:
    cmp qword ptr [r15+lcsp_ACTIVE_KIND],3
    jne lcsp_async_contract
    mov rbx,[r15+320]
    cmp qword ptr [rbx+32],0
    jne lcsp_async_contract
    cmp qword ptr [rbx],-1
    jne lcsp_async_contract
    mov rax,0x3130524b4d485348
    cmp [r15+352],rax
    jne lcsp_async_contract
    mov eax,32
    jmp lcsp_nested_result
lcsp_nested_write_result:
    cmp qword ptr [r15+lcsp_ACTIVE_KIND],4
    jne lcsp_async_contract
    mov eax,48
lcsp_nested_result:
    mov [r15+lcsp_CHILDCODE],rax
    mov [r15+lcsp_CHILDRESULTLEN],rax
    lea rax,[r15+352]
    mov [r15+lcsp_CHILDRESULT],rax
    call lcsp_build_callback
    call lcsp_retire_nested
    jmp lcsp_full_invoke

/* First publish the real parent cancellation, then drain its owned worker. */
lcsp_nested_publish_cancel:
    mov qword ptr [r15+lcsp_CHILDRESULT],0
    mov qword ptr [r15+lcsp_CHILDRESULTLEN],0
    mov eax,0xfffffff7
    mov [r15+lcsp_CHILDCODE],rax
    call lcsp_build_callback
    mov rdi,[r15+lcsp_OUT]
    mov rsi,[r15+lcsp_OUTCAP]
    call lcsp_make_writable
    mov rdi,[r15+lcsp_CURRENT]
    mov rsi,[r15+lcsp_CURRENTLEN]
    mov rdx,[r15+lcsp_OUT]
    mov rcx,[r15+lcsp_OUTCAP]
    mov r8,[r15+lcsp_WORK]
    mov r9,[r15+lcsp_WORKCAP]
    call qword ptr [r15+lcsp_I_SPEC]
    mov edx,eax
    cmp rax,rdx
    jne lcsp_async_contract
    cmp eax,0xfffffff7
    jne lcsp_async_contract
    call lcsp_callable_publish
    ret
lcsp_nested_canceled:
    call lcsp_retire_nested
    jmp lcsp_full_finished
lcsp_retire_nested:
    mov rdi,[r15+lcsp_ASYNCINPUT]
    mov rsi,[r15+lcsp_ASYNCINCAP]
    mov eax,11
    syscall
    test rax,rax
    jnz lcsp_infrastructure
    mov rdi,[r15+lcsp_ASYNCWORK]
    mov rsi,[r15+lcsp_ASYNCWCAP]
    mov eax,11
    syscall
    test rax,rax
    jnz lcsp_infrastructure
    mov qword ptr [r15+lcsp_ASYNCINPUT],0
    mov qword ptr [r15+lcsp_ASYNCWORK],0
    mov qword ptr [r15+lcsp_ACTIVE_KIND],0
    ret

/* One whole HIA mkdir algorithm runs inside one admitted blocking ticket. */
lcsp_mkdir_child:
    mov rbx,[r15+320]
    mov edi,4
    mov rsi,[rbx+64]
    xor edx,edx
    call lcsp_async_call
    cmp eax,128
    jne lcsp_async_contract
    cmp qword ptr [r15+368],8
    jne lcsp_async_contract
lcsp_mkdir_invoke:
    mov rdi,[r15+lcsp_MKREQ]
    mov rsi,[r15+lcsp_CHILDREQLEN]
    mov rdx,[r15+lcsp_SUBOUT]
    mov rcx,[r15+lcsp_SUBOUTCAP]
    mov r8,[r15+lcsp_MKWORK]
    mov r9,[r15+lcsp_MKWORKCAP]
    call qword ptr [r15+lcsp_I_MKDIR]
    mov edx,eax
    cmp rax,rdx
    jne lcsp_async_contract
    cmp eax,32
    je lcsp_mkdir_complete
    cmp eax,0xfffffffd
    jne lcsp_async_contract
    call lcsp_mkdir_effect
    mov rdi,[r15+lcsp_MKREQ]
    mov rsi,[r15+lcsp_MKREQCAP]
    call lcsp_make_writable
    mov rax,[r15+lcsp_MKREQ]
    mov qword ptr [rax+8],2
    mov qword ptr [rax+16],0
    mov rdi,rax
    mov rsi,[r15+lcsp_MKREQCAP]
    call lcsp_make_readonly
    jmp lcsp_mkdir_invoke
lcsp_mkdir_complete:
    mov rsi,[r15+lcsp_SUBOUT]
    mov rax,0x3130524b4d485348
    cmp [rsi],rax
    jne lcsp_async_contract
    cmp qword ptr [rsi+24],2
    ja lcsp_async_contract
    call lcsp_async_lock
    cmp qword ptr [r14+248],0
    jne lcsp_async_contract
    mov rsi,[r15+lcsp_SUBOUT]
    mov rax,[rsi+24]
    mov byte ptr [rbx+128],al
    mov qword ptr [rbx+136],1
    lea rdi,[r14+256]
    mov ecx,32
    rep movsb
    mov qword ptr [r14+248],1
    call lcsp_async_unlock
    mov edi,5
    mov rsi,[rbx+64]
    xor edx,edx
    call lcsp_async_call
    cmp eax,128
    jne lcsp_async_contract
    cmp qword ptr [r15+368],9
    jne lcsp_async_contract
    jmp lcsp_async_child_ready

lcsp_mkdir_effect:
    push rbp
    push rbx
    sub rsp,272
    mov rbx,[r15+lcsp_MKWORK]
    lea rbp,[rbx+96]
    mov rax,0x3158464b4d485348
    cmp [rbp],rax
    jne lcsp_async_contract
    mov rax,[r15+lcsp_MKSEQ]
    inc rax
    jz lcsp_async_contract
    cmp [rbp+8],rax
    jne lcsp_async_contract
    cmp [rbx+80],rax
    jne lcsp_async_contract
    cmp qword ptr [rbx+72],1
    jne lcsp_async_contract
    mov [r15+lcsp_MKSEQ],rax
    mov rax,[rbp+48]
    or rax,[rbp+56]
    or rax,[rbp+64]
    or rax,[rbp+72]
    or rax,[rbp+80]
    or rax,[rbp+88]
    jnz lcsp_async_contract
    mov rax,[rbp+16]
    cmp [rbx+88],rax
    jne lcsp_async_contract
    cmp rax,1
    jb lcsp_async_contract
    cmp rax,4
    ja lcsp_async_contract
    mov [rsp+256],rax
    cmp rax,3
    je lcsp_mkdir_probe
    mov rcx,[r15+lcsp_MKREQ]
    mov rcx,[rcx+24]
    mov rdx,rcx
    add rcx,513
    jc lcsp_async_contract
    cmp [rbp+24],rcx
    jne lcsp_async_contract
    cmp [rbp+32],rdx
    ja lcsp_async_contract
    cmp rcx,[r15+lcsp_MKWORKCAP]
    jae lcsp_async_contract
    mov rdx,[r15+lcsp_MKWORKCAP]
    sub rdx,rcx
    cmp [rbp+32],rdx
    jae lcsp_async_contract
    lea rsi,[rbx+rcx]
    mov rcx,[rbp+32]
    cmp byte ptr [rsi+rcx],0
    jne lcsp_async_contract
    xor edx,edx
lcsp_mkdir_cstring_check:
    cmp rdx,rcx
    jae lcsp_mkdir_cstring_ready
    cmp byte ptr [rsi+rdx],0
    je lcsp_async_contract
    inc rdx
    jmp lcsp_mkdir_cstring_check
lcsp_mkdir_cstring_ready:
    cmp qword ptr [rsp+256],1
    je lcsp_mkdir_dispatch
    mov rdi,rsp
    xor eax,eax
    mov ecx,32
    rep stosq
    cmp qword ptr [rsp+256],2
    je lcsp_mkdir_statx
    cmp qword ptr [rbp+40],0
    jne lcsp_async_contract
    mov rdi,-100
    mov rdx,rsp
    xor r10d,r10d
    mov eax,262
    syscall
    test rax,rax
    jnz lcsp_mkdir_effect_return
    mov edx,[rsp+24]
    mov [rbp+72],rdx
    jmp lcsp_mkdir_effect_return
lcsp_mkdir_statx:
    cmp qword ptr [rbp+40],4095
    jne lcsp_async_contract
    mov rdi,-100
    xor edx,edx
    mov r10d,4095
    mov r8,rsp
    mov eax,332
    syscall
    test rax,rax
    jnz lcsp_mkdir_effect_return
    movzx edx,word ptr [rsp+28]
    mov [rbp+72],rdx
    jmp lcsp_mkdir_effect_return
lcsp_mkdir_dispatch:
    cmp qword ptr [rbp+40],511
    jne lcsp_async_contract
    mov rdi,rsi
    mov esi,511
    mov eax,83
    syscall
    jmp lcsp_mkdir_effect_return
lcsp_mkdir_probe:
    mov rax,[rbp+24]
    or rax,[rbp+32]
    jnz lcsp_async_contract
    cmp qword ptr [rbp+40],4095
    jne lcsp_async_contract
    xor edi,edi
    xor esi,esi
    xor edx,edx
    mov r10d,4095
    xor r8d,r8d
    mov eax,332
    syscall
lcsp_mkdir_effect_return:
    mov [rbp+56],rax
    test rax,rax
    jz lcsp_mkdir_effect_success
    jns lcsp_async_contract
    cmp rax,-4095
    jl lcsp_async_contract
    neg rax
    mov [rbp+64],rax
lcsp_mkdir_effect_success:
    mov qword ptr [rbp+48],1
    mov edi,2
    mov rsi,rbp
    mov edx,96
    call lcsp_write_all
    test eax,eax
    jnz lcsp_async_infrastructure
    add rsp,272
    pop rbx
    pop rbp
    ret

lcsp_async_parent_dispatch:
    cmp eax,32
    je lcsp_nested_mkdir_result
    cmp eax,48
    je lcsp_async_normal_result
    cmp eax,128
    jne lcsp_async_contract
    mov rax,[r15+368]
    cmp rax,1
    je lcsp_async_queue_child
    cmp rax,2
    je lcsp_async_queue_child
    cmp rax,3
    je lcsp_async_parent_wait
    cmp rax,4
    je lcsp_async_parent_close
    cmp rax,6
    je lcsp_async_cancel_result
    cmp rax,11
    je lcsp_async_parent_reap
    cmp rax,12
    je lcsp_async_queue_child
    cmp rax,10
    je lcsp_nested_continue
    jmp lcsp_async_contract

/* HIA calls are serialized; admitted syscalls execute outside this mutex. */
lcsp_async_call:
    push rbp
    mov rbp,rsp
    and rsp,-16
    mov [r15+336],rdi
    mov [r15+344],rsi
    mov [r15+480],rdx
    call lcsp_async_lock
    mov rdi,r12
    mov rsi,[r15+8]
    mov edx,3
    mov eax,10
    syscall
    test rax,rax
    jnz lcsp_async_infrastructure
    mov rax,[r15+336]
    mov [r12+8],rax
    mov rax,[r15+344]
    mov [r12+40],rax
    mov qword ptr [r12+48],0
    mov rax,[r15+480]
    mov [r12+56],rax
    mov rdi,r12
    mov rsi,[r15+8]
    mov edx,1
    mov eax,10
    syscall
    test rax,rax
    jnz lcsp_async_infrastructure
    mov rdi,r12
    mov rsi,r13
    lea rdx,[r15+352]
    mov ecx,128
    mov r8,r14
    mov r9,[r15+16]
    call lcsp_local_create_entry
    mov edx,eax
    cmp rax,rdx
    jne lcsp_async_contract
    mov [r15+24],rax
    call lcsp_async_unlock
    mov rax,[r15+24]
    cmp eax,128
    jne lcsp_async_call_return
    mov rdx,0x3130525341434c48
    cmp [r15+352],rdx
    jne lcsp_async_contract
    cmp qword ptr [r15+360],128
    jne lcsp_async_contract
    cmp qword ptr [r15+472],0
    jne lcsp_async_contract
    mov rdx,[r12+32]
    cmp [r15+384],rdx
    jne lcsp_async_contract
    mov edi,2
    lea rsi,[r15+352]
    mov edx,128
    call lcsp_write_all
    test eax,eax
    jnz lcsp_async_infrastructure
    mov rax,[r15+24]
lcsp_async_call_return:
    mov rsp,rbp
    pop rbp
    ret
lcsp_async_parent_call:
    call lcsp_callable_sync_flags
    mov rax,[r15+320]
    mov rdx,[rax+16]
    call lcsp_async_call
    ret

lcsp_async_map:
    mov rsi,rdi
    xor edi,edi
    mov edx,3
    mov r10d,0x21
    mov r8,-1
    xor r9d,r9d
    mov eax,9
    syscall
    cmp rax,-4095
    jae lcsp_infrastructure
    ret
lcsp_async_lock:
    mov rbx,[r15+320]
lcsp_async_lock_again:
    xor eax,eax
    mov edx,1
    lock cmpxchg dword ptr [rbx+8],edx
    je lcsp_async_locked
    lea rdi,[rbx+8]
    xor esi,esi
    mov edx,1
    sub rsp,16
    mov qword ptr [rsp],0
    mov qword ptr [rsp+8],10000000
    mov r10,rsp
    xor r8d,r8d
    xor r9d,r9d
    mov eax,202
    syscall
    add rsp,16
    test rax,rax
    jz lcsp_async_lock_again
    cmp rax,-4
    je lcsp_async_lock_again
    cmp rax,-11
    je lcsp_async_lock_again
    cmp rax,-110
    jne lcsp_async_infrastructure
    cmp qword ptr [r15+488],1
    je lcsp_async_lock_again
    mov rdi,[rbx+32]
    test rdi,rdi
    jz lcsp_async_contract
    lea rsi,[r15+296]
    mov edx,1
    xor r10d,r10d
    mov eax,61
    syscall
    cmp rax,-4
    je lcsp_async_lock_again
    test rax,rax
    jz lcsp_async_lock_again
    call lcsp_async_record_reap
    jmp lcsp_async_lock_again
lcsp_async_locked:
    ret
lcsp_async_unlock:
    mov rbx,[r15+320]
    xor eax,eax
    xchg dword ptr [rbx+8],eax
    cmp eax,1
    jne lcsp_async_contract
    lea rdi,[rbx+8]
    mov esi,1
    mov edx,2147483647
    xor r10d,r10d
    xor r8d,r8d
    xor r9d,r9d
    mov eax,202
    syscall
    test rax,rax
    js lcsp_async_infrastructure
    ret
lcsp_async_notify:
    mov rbx,[r15+320]
    lock inc dword ptr [rbx+24]
    lea rdi,[rbx+24]
    mov esi,1
    mov edx,2147483647
    xor r10d,r10d
    xor r8d,r8d
    xor r9d,r9d
    mov eax,202
    syscall
    test rax,rax
    js lcsp_async_infrastructure
    ret

/* A signal never mutates borrowed HIA frames or the policy workspace. */
lcsp_async_queue_child:
    mov rbx,[r15+320]
    cmp qword ptr [rbx+32],0
    jne lcsp_async_contract
    cmp qword ptr [r15+496],0
    jne lcsp_async_contract
    mov rax,[r15+392]
    mov [rbx+64],rax
    mov rax,[r15+368]
    mov [rbx+72],rax
    mov qword ptr [rbx+48],0
    mov qword ptr [rbx+80],0
    inc qword ptr [rbx+88]
    mov edi,0x411 /* CLONE_FILES | SIGCHLD: separate VM, shared FD table. */
    xor esi,esi
    xor edx,edx
    xor r10d,r10d
    xor r8d,r8d
    mov eax,56
    syscall
    test rax,rax
    jz lcsp_async_child
    js lcsp_async_infrastructure
    mov [rbx+32],rax
    mov edi,3
    mov rsi,[rbx+64]
    call lcsp_async_parent_call
    cmp eax,128
    jne lcsp_async_contract
    cmp qword ptr [r15+368],10
    jne lcsp_async_contract
    mov rbx,[r15+320]
    mov qword ptr [rbx+80],1
    lea rdi,[rbx+80]
    mov esi,1
    mov edx,2147483647
    xor r10d,r10d
    xor r8d,r8d
    xor r9d,r9d
    mov eax,202
    syscall
    test rax,rax
    js lcsp_async_infrastructure
    mov edi,8
    xor esi,esi
    call lcsp_async_parent_call
    jmp lcsp_async_parent_dispatch

lcsp_async_child:
    mov qword ptr [r15+488],1
    mov edi,1
    mov esi,9
    xor edx,edx
    xor r10d,r10d
    xor r8d,r8d
    mov eax,157
    syscall
    test rax,rax
    jnz lcsp_async_contract
    mov eax,110
    syscall
    mov rbx,[r15+320]
    cmp rax,[rbx+40]
    jne lcsp_async_contract
    mov qword ptr [r15+256],1
    mov qword ptr [r15+264],0
    mov qword ptr [r15+272],0
    mov qword ptr [r15+280],0
    mov edi,10
    lea rsi,[r15+256]
    xor edx,edx
    mov r10d,8
    mov eax,13
    syscall
    test rax,rax
    jnz lcsp_async_contract
lcsp_async_admission_wait:
    cmp qword ptr [rbx+80],1
    je lcsp_async_child_invoke
    lea rdi,[rbx+80]
    xor esi,esi
    xor edx,edx
    xor r10d,r10d
    xor r8d,r8d
    xor r9d,r9d
    mov eax,202
    syscall
    test rax,rax
    jz lcsp_async_admission_wait
    cmp rax,-4
    je lcsp_async_admission_wait
    cmp rax,-11
    je lcsp_async_admission_wait
    jmp lcsp_async_infrastructure
lcsp_async_child_invoke:
    cmp qword ptr [r15+lcsp_ACTIVE_KIND],3
    je lcsp_mkdir_child
    mov rbx,[r15+320]
    mov edi,4
    mov rsi,[rbx+64]
    xor edx,edx
    call lcsp_async_call
    cmp eax,128
    jne lcsp_async_contract
    cmp qword ptr [r15+368],9
    je lcsp_async_child_ready
    cmp qword ptr [r15+368],8
    jne lcsp_async_contract
    call lcsp_async_effect
    jmp lcsp_async_child_invoke
lcsp_async_child_ready:
    mov rbx,[r15+320]
    mov qword ptr [rbx+48],1
    call lcsp_async_notify
    xor edi,edi
    mov eax,60
    syscall
    ud2

lcsp_async_parent_wait:
    call lcsp_callable_sync_flags
    mov rbx,[r15+320]
    mov eax,[rbx+24]
    mov [r15+504],eax
    cmp qword ptr [rbx+16],0
    jne lcsp_async_parent_cancel
    /* Only an existing HIA WAIT boundary admits an external repoll. The
     * coalescing bit cannot alter ready, ticket, accepted bytes or cancel. */
    xor eax,eax
    xchg eax,dword ptr [rbx+120]
    test eax,eax
    jnz lcsp_async_parent_poll
    cmp qword ptr [rbx+48],1
    je lcsp_async_parent_poll
    mov rdi,[rbx+32]
    test rdi,rdi
    jz lcsp_async_contract
    lea rsi,[r15+296]
    mov edx,1
    xor r10d,r10d
    mov eax,61
    syscall
    cmp rax,-4
    je lcsp_async_parent_wait
    test rax,rax
    js lcsp_async_infrastructure
    jz lcsp_async_parent_sleep
    call lcsp_async_record_reap
    jmp lcsp_async_parent_poll
lcsp_async_parent_sleep:
    sub rsp,16
    mov qword ptr [rsp],0
    mov qword ptr [rsp+8],10000000
    lea rdi,[rbx+24]
    xor esi,esi
    mov edx,[r15+504]
    mov r10,rsp
    xor r8d,r8d
    xor r9d,r9d
    mov eax,202
    syscall
    add rsp,16
    test rax,rax
    jz lcsp_async_parent_wait
    cmp rax,-4
    je lcsp_async_parent_wait
    cmp rax,-11
    je lcsp_async_parent_wait
    cmp rax,-110
    je lcsp_async_parent_wait
    jmp lcsp_async_infrastructure
lcsp_async_parent_poll:
    mov edi,2
    xor esi,esi
    call lcsp_async_parent_call
    jmp lcsp_async_parent_dispatch
lcsp_async_parent_cancel:
    mov edi,6
    xor esi,esi
    call lcsp_async_parent_call
    jmp lcsp_async_parent_dispatch

lcsp_async_parent_reap:
    call lcsp_async_reap_child
    mov rbx,[r15+320]
    mov edi,7
    mov rsi,[rbx+64]
    call lcsp_async_parent_call
    mov qword ptr [r15+496],0
    jmp lcsp_async_parent_dispatch
lcsp_async_reap_child:
    mov rbx,[r15+320]
    cmp qword ptr [rbx+32],0
    jne lcsp_async_reap_again
    cmp qword ptr [r15+496],1
    jne lcsp_async_contract
    ret
lcsp_async_reap_again:
    mov rdi,[rbx+32]
    lea rsi,[r15+296]
    xor edx,edx
    xor r10d,r10d
    mov eax,61
    syscall
    cmp rax,-4
    je lcsp_async_reap_again
    call lcsp_async_record_reap
    ret
lcsp_async_record_reap:
    mov rbx,[r15+320]
    cmp rax,[rbx+32]
    jne lcsp_async_infrastructure
    mov qword ptr [rbx+32],0
    cmp dword ptr [r15+296],0
    jne lcsp_async_contract
    cmp qword ptr [rbx+48],1
    jne lcsp_async_contract
    mov qword ptr [r15+496],1
    call lcsp_callable_metadata_publish
    ret

lcsp_async_parent_close:
    call lcsp_async_effect
    mov rbx,[r15+320]
    mov edi,5
    mov rsi,[rbx+64]
    call lcsp_async_parent_call
    jmp lcsp_async_parent_dispatch

lcsp_async_normal_result:
    mov rbx,[r15+320]
    cmp qword ptr [rbx+32],0
    jne lcsp_async_contract
    cmp qword ptr [rbx],-1
    jne lcsp_async_contract
    mov rax,0x3130524552434c48
    cmp [r15+352],rax
    jne lcsp_async_contract
    cmp qword ptr [r15+360],48
    jne lcsp_async_contract
    cmp qword ptr [r15+368],3
    ja lcsp_async_contract
    cmp qword ptr [r15+392],0
    jne lcsp_async_contract
    jmp lcsp_nested_write_result

lcsp_async_cancel_result:
    mov rbx,[r15+320]
    cmp qword ptr [rbx+96],0
    jne lcsp_async_drain
    call lcsp_nested_publish_cancel
    mov rbx,[r15+320]
    mov qword ptr [rbx+96],1
lcsp_async_drain:
    cmp qword ptr [rbx+32],0
    je lcsp_async_drain_reaped
    call lcsp_async_reap_child
lcsp_async_drain_reaped:
    cmp qword ptr [r15+496],0
    je lcsp_async_drained
    mov rbx,[r15+320]
    mov edi,7
    mov rsi,[rbx+64]
    call lcsp_async_parent_call
    mov qword ptr [r15+496],0
    cmp eax,128
    jne lcsp_async_contract
    cmp qword ptr [r15+368],6
    jne lcsp_async_contract
lcsp_async_drained:
    mov rbx,[r15+320]
    cmp qword ptr [rbx],-1
    jne lcsp_async_contract
    cmp qword ptr [rbx+32],0
    jne lcsp_async_contract
    cmp qword ptr [r15+lcsp_ACTIVE_KIND],3
    je lcsp_nested_canceled
    mov rax,[r15+304]
    cmp qword ptr [r14+rax+144],1
    jne lcsp_async_contract
    jmp lcsp_nested_canceled

/* One independent span/custody check immediately precedes each real syscall.
 * The ticket's old end is immutable even if HIA prepares the next chunk.
 */
lcsp_async_effect:
    push rbp
    sub rsp,64
    call lcsp_async_lock
    mov rbp,[r15+304]
    mov rax,0x3130464552434c48
    cmp [r14+128],rax
    jne lcsp_async_contract
    mov rax,[rbx+56]
    inc rax
    cmp [r14+136],rax
    je lcsp_async_effect_sequence
    /* Drop can replace one already prepared, never queued WRITE with CLOSE.
     * These are HIA issue sequence numbers, not executed syscall counts.
     * Keep the exact single-step rule everywhere else, including normal close.
     */
    cmp qword ptr [r14+144],3
    jne lcsp_async_contract
    cmp qword ptr [r14+rbp+16],4
    jne lcsp_async_contract
    mov rcx,[r14+rbp+136]
    cmp rcx,2
    jb lcsp_async_contract
    cmp rcx,3
    ja lcsp_async_contract
    inc rax
    cmp [r14+136],rax
    jne lcsp_async_contract
lcsp_async_effect_sequence:
    cmp [r14+16],rax
    jne lcsp_async_contract
    mov [rbx+56],rax
    cmp qword ptr [r14+184],0
    jne lcsp_async_contract
    cmp qword ptr [r14+192],0
    jne lcsp_async_contract
    cmp qword ptr [r14+200],0
    jne lcsp_async_contract
    cmp qword ptr [r14+208],0
    jne lcsp_async_contract
    cmp qword ptr [r14+216],0
    jne lcsp_async_contract
    mov rax,[rbx+64]
    cmp [r14+rbp+48],rax
    jne lcsp_async_contract
    mov rax,[r12+32]
    cmp [r14+rbp+8],rax
    jne lcsp_async_contract
    mov rax,[r14+144]
    cmp [r14+8],rax
    jne lcsp_async_contract
    mov [rsp],rax
    cmp rax,1
    je lcsp_async_open_effect
    cmp rax,2
    je lcsp_async_write_effect
    cmp rax,3
    je lcsp_async_close_effect
    jmp lcsp_async_contract
lcsp_async_open_effect:
    cmp qword ptr [r15+488],1
    jne lcsp_async_contract
    cmp qword ptr [r14+rbp+80],3
    jne lcsp_async_contract
    cmp qword ptr [r14+rbp+56],1
    jne lcsp_async_contract
    cmp qword ptr [rbx],-1
    jne lcsp_async_contract
    cmp qword ptr [r14+152],512
    jne lcsp_async_contract
    mov rax,[r12+16]
    cmp [r14+160],rax
    jne lcsp_async_contract
    cmp byte ptr [r14+rax+512],0
    jne lcsp_async_contract
    cmp qword ptr [r14+168],0x800c1
    jne lcsp_async_contract
    cmp qword ptr [r14+176],438
    jne lcsp_async_contract
    mov qword ptr [rsp+8],-100
    lea rax,[r14+512]
    mov [rsp+16],rax
    mov qword ptr [rsp+24],0x800c1
    mov qword ptr [rsp+32],438
    jmp lcsp_async_effect_dispatch
lcsp_async_write_effect:
    cmp qword ptr [r15+488],1
    jne lcsp_async_contract
    cmp qword ptr [r14+rbp+80],3
    jne lcsp_async_contract
    cmp qword ptr [r14+rbp+56],2
    jne lcsp_async_contract
    cmp qword ptr [r14+152],1
    jne lcsp_async_contract
    cmp qword ptr [r14+48],1
    jne lcsp_async_contract
    cmp qword ptr [r14+176],0
    jne lcsp_async_contract
    mov rax,[r14+56]
    cmp rax,[r14+rbp+64]
    jb lcsp_async_contract
    cmp rax,[r14+rbp+72]
    jae lcsp_async_contract
    mov rcx,[r14+rbp+72]
    cmp [r14+64],rcx
    jne lcsp_async_contract
    sub rcx,rax
    mov rdx,[r14+168]
    cmp rdx,rcx
    jne lcsp_async_contract
    test rdx,rdx
    jz lcsp_async_contract
    cmp rdx,2097152
    ja lcsp_async_contract
    add rax,[r12+16]
    jc lcsp_async_contract
    add rax,513
    jc lcsp_async_contract
    cmp [r14+160],rax
    jne lcsp_async_contract
    mov rcx,[r15+16]
    cmp rax,rcx
    ja lcsp_async_contract
    sub rcx,rax
    cmp rdx,rcx
    ja lcsp_async_contract
    add rax,r14
    mov [rsp+16],rax
    mov [rsp+24],rdx
    mov rax,[rbx]
    test rax,rax
    js lcsp_async_contract
    mov [rsp+8],rax
    jmp lcsp_async_effect_dispatch
lcsp_async_close_effect:
    cmp qword ptr [r14+152],1
    jne lcsp_async_contract
    cmp qword ptr [r14+88],1
    jne lcsp_async_contract
    cmp qword ptr [r14+48],0
    jne lcsp_async_contract
    cmp qword ptr [r14+160],0
    jne lcsp_async_contract
    cmp qword ptr [r14+168],0
    jne lcsp_async_contract
    cmp qword ptr [r14+176],0
    jne lcsp_async_contract
    mov rax,[r14+rbp+136]
    cmp qword ptr [r15+488],1
    je lcsp_async_worker_close_check
    cmp qword ptr [r14+rbp+80],4
    jne lcsp_async_contract
    cmp rax,1
    je lcsp_async_close_admitted
    cmp rax,2
    jne lcsp_async_contract
    jmp lcsp_async_close_admitted
lcsp_async_worker_close_check:
    cmp qword ptr [r14+rbp+80],3
    jne lcsp_async_contract
    cmp rax,3
    jne lcsp_async_contract
lcsp_async_close_admitted:
    mov rax,[rbx]
    test rax,rax
    js lcsp_async_contract
    mov [rsp+8],rax
    mov qword ptr [rbx],-1
lcsp_async_effect_dispatch:
    call lcsp_async_unlock
    mov rdi,[rsp+8]
    mov rsi,[rsp+16]
    mov rdx,[rsp+24]
    mov r10,[rsp+32]
    mov rax,[rsp]
    cmp eax,1
    je lcsp_async_open_dispatch
    cmp eax,2
    je lcsp_async_write_dispatch
    mov eax,3
    jmp lcsp_async_kernel_call
lcsp_async_open_dispatch:
    mov eax,257
    jmp lcsp_async_kernel_call
lcsp_async_write_dispatch:
    mov eax,1
lcsp_async_kernel_call:
    syscall
    mov [rsp+40],rax
    mov qword ptr [rsp+48],0
    mov qword ptr [rsp+56],0
    test rax,rax
    jns lcsp_async_effect_success
    cmp rax,-4095
    jl lcsp_async_contract
    neg rax
    mov [rsp+48],rax
    jmp lcsp_async_effect_complete
lcsp_async_effect_success:
    cmp qword ptr [rsp],1
    je lcsp_async_open_success
    cmp qword ptr [rsp],2
    je lcsp_async_write_success
    test rax,rax
    jnz lcsp_async_contract
    jmp lcsp_async_effect_complete
lcsp_async_open_success:
    cmp rax,0x7fffffff
    ja lcsp_async_contract
    mov qword ptr [rsp+56],1
    jmp lcsp_async_effect_complete
lcsp_async_write_success:
    cmp rax,[rsp+24]
    ja lcsp_async_contract
lcsp_async_effect_complete:
    call lcsp_async_lock
    cmp qword ptr [r14+184],0
    jne lcsp_async_contract
    cmp qword ptr [rsp+56],0
    je lcsp_async_effect_fields
    cmp qword ptr [rbx],-1
    jne lcsp_async_contract
    mov rax,[rsp+40]
    mov [rbx],rax
lcsp_async_effect_fields:
    mov rax,[rsp+40]
    mov [r14+192],rax
    mov rax,[rsp+48]
    mov [r14+200],rax
    mov rax,[rsp+56]
    mov [r14+208],rax
    mov qword ptr [r14+184],1
    call lcsp_async_unlock
    mov edi,2
    lea rsi,[r14+128]
    mov edx,96
    call lcsp_write_all
    test eax,eax
    jnz lcsp_async_infrastructure
    add rsp,64
    pop rbp
    ret

lcsp_async_contract:
    mov ebx,70
    jmp lcsp_async_abort
lcsp_async_infrastructure:
    mov ebx,74
lcsp_async_abort:
    cmp qword ptr [r15+488],1
    je lcsp_async_abort_exit
    mov [r15+288],rbx
    mov rbx,[r15+320]
    cmp qword ptr [rbx+32],0
    je lcsp_async_abort_close
    mov rdi,[rbx+32]
    mov esi,9
    mov eax,62
    syscall
lcsp_async_abort_wait:
    mov rdi,[rbx+32]
    lea rsi,[r15+296]
    xor edx,edx
    xor r10d,r10d
    mov eax,61
    syscall
    cmp rax,-4
    je lcsp_async_abort_wait
    mov qword ptr [rbx+32],0
lcsp_async_abort_close:
    cmp qword ptr [rbx],-1
    je lcsp_async_abort_closed
    mov rdi,[rbx]
    mov qword ptr [rbx],-1
    mov eax,3
    syscall
lcsp_async_abort_closed:
    mov rbx,[r15+288]
lcsp_async_abort_exit:
    cmp qword ptr [r15+488],1
    je lcsp_callable_worker_exit
    call lcsp_callable_metadata_publish
lcsp_callable_abort_parent:
    mov r10,[r15+lcsp_PUBLIC_CTX]
    mov [r10+128],rbx
    cmp qword ptr [r10+104],0
    jne lcsp_callable_finish
    mov eax,0xfffffffc
    call lcsp_callable_publish
    jmp lcsp_callable_finish
lcsp_callable_worker_exit:
    mov edi,ebx
    mov eax,60
    syscall
    ud2

lcsp_local_read_run:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp, 520
    mov r15, rdi
    cmp qword ptr [r15 + 72], 0
    jne lcsp_lr_contract_fail
    mov rdi, qword ptr [r15 + 48]
    add rdi, 1024
    jc lcsp_lr_memory_fail
    cmp rdi, qword ptr [r15 + 24]
    jbe lcsp_lr_read_workspace_ready
    mov ebp, 16
    call lcsp_lr_resize_buffer
lcsp_lr_read_workspace_ready:
    mov rdi, qword ptr [r15 + 16]
    xor eax, eax
    mov ecx, 128
    rep stosq
    mov qword ptr [r15 + 88], 0
lcsp_lr_read_invoke:
    mov rdi, qword ptr [r15]
    mov rsi, qword ptr [r15 + 48]
    mov rdx, qword ptr [r15 + 32]
    mov rcx, qword ptr [r15 + 40]
    mov r8, qword ptr [r15 + 16]
    mov r9, qword ptr [r15 + 24]
    call qword ptr [r15 + 80]
    mov edx, eax
    cmp rax, rdx
    jne lcsp_lr_contract_fail
    mov rbx, qword ptr [r15 + 16]
    cmp eax, 0xffffffef
    je lcsp_lr_read_grow
    cmp eax, 0xffffffe8
    je lcsp_lr_read_cache
    cmp eax, 0xfffffff0
    je lcsp_lr_read_effect
    cmp eax, 0xfffffff6
    je lcsp_lr_allocation_abort
    cmp eax, 0xffffffff
    je lcsp_lr_read_refused
    cmp eax, 0xfffffffe
    je lcsp_lr_read_refused
    cmp eax, 0xfffffff9
    je lcsp_lr_contract_fail
    cmp rax, qword ptr [r15 + 40]
    ja lcsp_lr_contract_fail
    cmp eax, 32
    jb lcsp_lr_contract_fail
    cmp qword ptr [rbx], 100
    jne lcsp_lr_contract_fail
    cmp qword ptr [r15 + 72], 0
    jne lcsp_lr_contract_fail
    mov rdx, qword ptr [r15 + 32]
    mov rcx, 0x3130304f524c4648
    cmp qword ptr [rdx], rcx
    jne lcsp_lr_contract_fail
    lea rcx, [rax - 32]
    cmp qword ptr [rdx + 24], rcx
    jne lcsp_lr_contract_fail
    jmp lcsp_lr_read_return
lcsp_lr_read_refused:
    mov dword ptr [rsp + 504], eax
    call lcsp_lr_cleanup
    mov eax, dword ptr [rsp + 504]
lcsp_lr_read_return:
    add rsp, 520
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

lcsp_lr_read_grow:
    cmp qword ptr [rbx], 90
    jne lcsp_lr_contract_fail
    mov rdi, qword ptr [rbx + 200]
    mov rax, qword ptr [rbx + 216]
    cmp rax, 1
    je lcsp_lr_read_grow_work
    cmp rax, 2
    jne lcsp_lr_contract_fail
    cmp qword ptr [rbx + 208], 100
    jne lcsp_lr_contract_fail
    cmp qword ptr [r15 + 72], 0
    jne lcsp_lr_contract_fail
    cmp rdi, 1073741824
    ja lcsp_lr_read_resource
    mov ebp, 32
    jmp lcsp_lr_read_grow_do
lcsp_lr_read_grow_work:
    cmp rdi, 1207959552
    ja lcsp_lr_read_resource
    mov rax, qword ptr [rbx + 208]
    cmp rax, 20
    je lcsp_lr_read_grow_work_valid
    cmp rax, 23
    je lcsp_lr_read_grow_work_valid
    cmp rax, 24
    jne lcsp_lr_contract_fail
lcsp_lr_read_grow_work_valid:
    mov rax, qword ptr [rbx + 56]
    add rax, qword ptr [rbx + 152]
    jc lcsp_lr_contract_fail
    cmp rdi, rax
    jne lcsp_lr_contract_fail
    mov ebp, 16
lcsp_lr_read_grow_do:
    cmp rdi, qword ptr [r15 + rbp + 8]
    jbe lcsp_lr_contract_fail
    call lcsp_lr_resize_buffer
    jmp lcsp_lr_read_invoke
lcsp_lr_read_resource:
    mov eax, 0xfffffffe
    jmp lcsp_lr_read_refused

lcsp_lr_read_cache:
    lea r12, [rbx + 640]
    mov rax, 0x3130304341544d48
    cmp qword ptr [r12], rax
    jne lcsp_lr_contract_fail
    call lcsp_lr_sequence_admit
    mov r13, qword ptr [r12 + 16]
    cmp r13, 1
    ja lcsp_lr_contract_fail
    mov rax, qword ptr [r12 + 32]
    or rax, qword ptr [r12 + 40]
    jnz lcsp_lr_contract_fail
    mov rax, qword ptr [rbx]
    cmp rax, 60
    jb lcsp_lr_contract_fail
    cmp rax, 63
    ja lcsp_lr_contract_fail
    cmp rax, 62
    jb lcsp_lr_read_cache_load
    cmp r13, 1
    jne lcsp_lr_contract_fail
    mov rax, qword ptr [r12 + 24]
    cmp rax, qword ptr [rbx + 104]
    jne lcsp_lr_contract_fail
    cmp rax, 1
    jb lcsp_lr_contract_fail
    cmp rax, 2
    ja lcsp_lr_contract_fail
    mov rdx, qword ptr [r15 + 64]
    mov byte ptr [rdx], al
    xor eax, eax
    jmp lcsp_lr_read_cache_complete
lcsp_lr_read_cache_load:
    test r13, r13
    jnz lcsp_lr_contract_fail
    cmp qword ptr [r12 + 24], 0
    jne lcsp_lr_contract_fail
    mov rdx, qword ptr [r15 + 64]
    movzx eax, byte ptr [rdx]
    cmp eax, 2
    ja lcsp_lr_contract_fail
lcsp_lr_read_cache_complete:
    mov qword ptr [r12 + 56], rax
    mov qword ptr [r12 + 80], 1
    jmp lcsp_lr_read_invoke

lcsp_lr_read_effect:
    lea r12, [rbx + 256]
    mov rax, 0x58464f49524c4648
    cmp qword ptr [r12], rax
    jne lcsp_lr_contract_fail
    call lcsp_lr_sequence_admit
    mov r14, qword ptr [r12 + 16]
    mov rax, qword ptr [rbx]
    cmp r14, 8
    jne lcsp_lr_read_effect_phase
    cmp rax, 21
    je lcsp_lr_read_effect_ready
    cmp rax, 22
    jne lcsp_lr_contract_fail
    jmp lcsp_lr_read_effect_ready
lcsp_lr_read_effect_phase:
    cmp rax, r14
    jne lcsp_lr_contract_fail
lcsp_lr_read_effect_ready:
    mov rdi, rsp
    xor eax, eax
    mov ecx, 32
    rep stosq
    cmp r14, 1
    je lcsp_lr_read_path_statx
    cmp r14, 2
    je lcsp_lr_read_probe_statx
    cmp r14, 3
    je lcsp_lr_read_path_stat
    cmp r14, 4
    je lcsp_lr_read_open
    cmp r14, 5
    je lcsp_lr_read_fd_statx
    cmp r14, 7
    je lcsp_lr_read_fd_stat
    cmp r14, 8
    je lcsp_lr_read_bytes
    cmp r14, 9
    je lcsp_lr_read_close
    cmp r14, 10
    je lcsp_lr_read_path_stat
    cmp r14, 11
    je lcsp_lr_read_fd_statat
    cmp r14, 12
    je lcsp_lr_read_probe_stat
    jmp lcsp_lr_contract_fail
lcsp_lr_read_path_statx:
    call lcsp_lr_path_admit
    mov rsi, rax
    mov rdi, -100
    xor edx, edx
    mov r10d, 4095
    mov r8, rsp
    mov eax, 332
    syscall
    mov ebp, 1
    jmp lcsp_lr_effect_done
lcsp_lr_read_path_stat:
    call lcsp_lr_path_admit
    mov rsi, rax
    mov rdi, -100
    mov rdx, rsp
    xor r10d, r10d
    mov eax, 262
    syscall
    mov ebp, 2
    jmp lcsp_lr_effect_done
lcsp_lr_read_probe_statx:
    call lcsp_lr_zero_arguments
    xor edi, edi
    xor esi, esi
    xor edx, edx
    mov r10d, 4095
    xor r8d, r8d
    mov eax, 332
    syscall
    xor ebp, ebp
    jmp lcsp_lr_effect_done
lcsp_lr_read_probe_stat:
    call lcsp_lr_zero_arguments
    xor edi, edi
    xor esi, esi
    xor edx, edx
    xor r10d, r10d
    mov eax, 262
    syscall
    xor ebp, ebp
    jmp lcsp_lr_effect_done
lcsp_lr_read_open:
    cmp qword ptr [r15 + 72], 0
    jne lcsp_lr_contract_fail
    call lcsp_lr_path_admit
    mov rsi, rax
    mov rdi, -100
    mov edx, 524288
    xor r10d, r10d
    mov eax, 257
    syscall
    mov ebp, 3
    jmp lcsp_lr_effect_done
lcsp_lr_read_fd_statx:
    call lcsp_lr_fd_only
    lea rsi, [rip + lcsp_lr_empty_path]
    mov edx, 4096
    mov r10d, 4095
    mov r8, rsp
    mov eax, 332
    syscall
    mov ebp, 1
    jmp lcsp_lr_effect_done
lcsp_lr_read_fd_statat:
    call lcsp_lr_fd_only
    lea rsi, [rip + lcsp_lr_empty_path]
    mov rdx, rsp
    mov r10d, 4096
    mov eax, 262
    syscall
    mov ebp, 2
    jmp lcsp_lr_effect_done
lcsp_lr_read_fd_stat:
    call lcsp_lr_fd_only
    mov rsi, rsp
    mov eax, 5
    syscall
    mov ebp, 2
    jmp lcsp_lr_effect_done
lcsp_lr_read_bytes:
    cmp qword ptr [r12 + 24], 1
    jne lcsp_lr_contract_fail
    mov rdi, qword ptr [r15 + 72]
    test rdi, rdi
    jz lcsp_lr_contract_fail
    dec rdi
    mov rsi, qword ptr [r12 + 32]
    mov rdx, qword ptr [r12 + 40]
    cmp qword ptr [rbx], 21
    jne lcsp_lr_read_regular
    cmp rsi, 768
    jne lcsp_lr_contract_fail
    cmp rdx, 32
    jne lcsp_lr_contract_fail
    jmp lcsp_lr_read_span_ready
lcsp_lr_read_regular:
    mov rax, qword ptr [rbx + 56]
    cmp rax, 1024
    jb lcsp_lr_contract_fail
    add rax, qword ptr [rbx + 160]
    jc lcsp_lr_contract_fail
    cmp rsi, rax
    jne lcsp_lr_contract_fail
    mov rax, qword ptr [rbx + 152]
    sub rax, qword ptr [rbx + 160]
    jc lcsp_lr_contract_fail
    cmp rax, qword ptr [rbx + 176]
    cmova rax, qword ptr [rbx + 176]
    cmp rdx, rax
    jne lcsp_lr_contract_fail
    test rdx, rdx
    jz lcsp_lr_contract_fail
lcsp_lr_read_span_ready:
    cmp rsi, qword ptr [r15 + 24]
    ja lcsp_lr_contract_fail
    mov rax, qword ptr [r15 + 24]
    sub rax, rsi
    cmp rdx, rax
    ja lcsp_lr_contract_fail
    add rsi, rbx
    xor eax, eax
    syscall
    mov ebp, 4
    jmp lcsp_lr_effect_done
lcsp_lr_read_close:
    call lcsp_lr_fd_only
    mov qword ptr [r15 + 72], 0
    mov eax, 3
    syscall
    xor ebp, ebp
lcsp_lr_effect_done:
    cmp rax, -4095
    jae lcsp_lr_effect_error
    cmp ebp, 1
    jne lcsp_lr_effect_stat64
    test rax, rax
    jnz lcsp_lr_contract_fail
    mov rax, qword ptr [rsp + 40]
    mov qword ptr [r12 + 72], rax
    jmp lcsp_lr_effect_completed
lcsp_lr_effect_stat64:
    cmp ebp, 2
    jne lcsp_lr_effect_opened
    test rax, rax
    jnz lcsp_lr_contract_fail
    mov rax, qword ptr [rsp + 48]
    mov qword ptr [r12 + 72], rax
    jmp lcsp_lr_effect_completed
lcsp_lr_effect_opened:
    cmp ebp, 3
    jne lcsp_lr_effect_read
    inc rax
    jz lcsp_lr_contract_fail
    mov qword ptr [r15 + 72], rax
    mov qword ptr [r12 + 72], 1
    jmp lcsp_lr_effect_completed
lcsp_lr_effect_read:
    cmp ebp, 4
    jne lcsp_lr_effect_unit
    cmp rax, qword ptr [r12 + 40]
    ja lcsp_lr_contract_fail
    mov qword ptr [r12 + 56], rax
    jmp lcsp_lr_effect_completed
lcsp_lr_effect_unit:
    test rax, rax
    jnz lcsp_lr_contract_fail
    jmp lcsp_lr_effect_completed
lcsp_lr_effect_error:
    neg rax
    mov qword ptr [r12 + 64], rax
lcsp_lr_effect_completed:
    mov qword ptr [r12 + 80], 1
    jmp lcsp_lr_read_invoke

lcsp_lr_sequence_admit:
    mov rax, qword ptr [r15 + 88]
    inc rax
    jz lcsp_lr_contract_fail
    cmp qword ptr [r12 + 8], rax
    jne lcsp_lr_contract_fail
    cmp qword ptr [rbx + 72], rax
    jne lcsp_lr_contract_fail
    mov qword ptr [r15 + 88], rax
    mov rax, qword ptr [r12 + 48]
    or rax, qword ptr [r12 + 56]
    or rax, qword ptr [r12 + 64]
    or rax, qword ptr [r12 + 72]
    or rax, qword ptr [r12 + 80]
    or rax, qword ptr [r12 + 88]
    jnz lcsp_lr_contract_fail
    ret
lcsp_lr_path_admit:
    cmp qword ptr [r12 + 24], 1024
    jne lcsp_lr_contract_fail
    mov rcx, qword ptr [rbx + 48]
    cmp qword ptr [r12 + 32], rcx
    jne lcsp_lr_contract_fail
    cmp qword ptr [r12 + 40], 0
    jne lcsp_lr_contract_fail
    mov rax, qword ptr [r15 + 24]
    sub rax, 1024
    jc lcsp_lr_contract_fail
    cmp rcx, rax
    jae lcsp_lr_contract_fail
    lea rax, [rbx + 1024]
    cmp byte ptr [rax + rcx], 0
    jne lcsp_lr_contract_fail
    xor edx, edx
lcsp_lr_path_scan:
    cmp rdx, rcx
    je lcsp_lr_path_done
    cmp byte ptr [rax + rdx], 0
    je lcsp_lr_contract_fail
    inc rdx
    jmp lcsp_lr_path_scan
lcsp_lr_path_done:
    ret
lcsp_lr_zero_arguments:
    mov rax, qword ptr [r12 + 24]
    or rax, qword ptr [r12 + 32]
    or rax, qword ptr [r12 + 40]
    jnz lcsp_lr_contract_fail
    ret
lcsp_lr_fd_only:
    cmp qword ptr [r12 + 24], 1
    jne lcsp_lr_contract_fail
    mov rax, qword ptr [r12 + 32]
    or rax, qword ptr [r12 + 40]
    jnz lcsp_lr_contract_fail
    mov rdi, qword ptr [r15 + 72]
    test rdi, rdi
    jz lcsp_lr_contract_fail
    dec rdi
    ret

# rbp is the fixed context offset of (pointer, capacity), never input data.
lcsp_lr_resize_buffer:
    # Full profile regions are mapped before fork. A request beyond them
    # returns CAPACITY in HIA; no child can publish a child-private relocation.
    jmp lcsp_lr_contract_fail

lcsp_lr_cleanup:
    mov rdi, qword ptr [r15 + 72]
    mov qword ptr [r15 + 72], 0
    test rdi, rdi
    jz lcsp_lr_cleanup_done
    dec rdi
    mov eax, 3
    syscall
lcsp_lr_cleanup_done:
    ret
lcsp_lr_contract_fail:
    call lcsp_lr_cleanup
    mov edi, 70
    jmp lcsp_lr_child_exit
lcsp_lr_memory_fail:
    call lcsp_lr_cleanup
    mov edi, 71
    jmp lcsp_lr_child_exit
lcsp_lr_io_fail:
    call lcsp_lr_cleanup
    mov edi, 74
    jmp lcsp_lr_child_exit
lcsp_lr_allocation_abort:
    call lcsp_lr_cleanup
    mov edi, 134
lcsp_lr_child_exit:
    mov r15,[r15+96]
    jmp lcsp_callable_abort_with_code
lcsp_lr_empty_path:
    .byte 0

lcsp_key_run:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp, 520
    mov r15, rdi
    cmp qword ptr [r15 + 72], -1
    jne lcsp_key_contract_fail
    cmp qword ptr [r15 + 80], -1
    jne lcsp_key_contract_fail
    mov rdi, qword ptr [r15 + 16]
    xor eax, eax
    mov ecx, 128
    rep stosq
    mov rbx, qword ptr [r15 + 16]
    mov rax, qword ptr [r15 + 64]
    mov qword ptr [rbx + 176], rax
    mov qword ptr [r15 + 88], 0
lcsp_key_invoke:
    mov rdi, qword ptr [r15]
    mov rsi, qword ptr [r15 + 48]
    mov rdx, qword ptr [r15 + 32]
    mov rcx, qword ptr [r15 + 40]
    mov r8, qword ptr [r15 + 16]
    mov r9, qword ptr [r15 + 24]
    call qword ptr [r15 + 96]
    mov edx, eax
    cmp rax, rdx
    jne lcsp_key_contract_fail
    mov rbx, qword ptr [r15 + 16]
    cmp eax, 0xffffffef
    je lcsp_key_grow_workspace
    cmp eax, 0xffffffee
    je lcsp_key_grow_output
    cmp eax, 0xfffffff0
    je lcsp_key_admit_effect
    cmp eax, 0xffffffff
    je lcsp_key_refusal
    cmp eax, 0xfffffffe
    je lcsp_key_refusal
    cmp eax, 0xfffffff9
    je lcsp_key_contract_fail
    cmp eax, 32
    jb lcsp_key_contract_fail
    cmp rax, qword ptr [r15 + 40]
    ja lcsp_key_contract_fail
    cmp qword ptr [rbx], 100
    jne lcsp_key_contract_fail
    mov rdx, qword ptr [r15 + 32]
    mov rcx, 0x313030594b4c5248
    cmp qword ptr [rdx], rcx
    jne lcsp_key_contract_fail
    lea rcx, [rax - 32]
    cmp qword ptr [rdx + 16], rcx
    jne lcsp_key_contract_fail
    cmp qword ptr [rdx + 24], 0
    jne lcsp_key_contract_fail
    cmp qword ptr [r15 + 72], -1
    jne lcsp_key_contract_fail
    cmp qword ptr [r15 + 80], -1
    jne lcsp_key_contract_fail
    mov dword ptr [r15 + 56], eax
    jmp lcsp_key_done
lcsp_key_refusal:
    mov dword ptr [r15 + 56], eax
    call lcsp_key_cleanup
    jmp lcsp_key_done

lcsp_key_grow_workspace:
    mov rdi, qword ptr [rbx + 40]
    cmp rdi, qword ptr [rbx + 32]
    jbe lcsp_key_contract_fail
    mov rax, 0x1ffffffffffbfeff
    cmp rdi, rax
    ja lcsp_key_memory_fail
    shl rdi, 2
    add rdi, 1049600
    jc lcsp_key_memory_fail
    call lcsp_round_capacity
    mov r12, rax
    cmp r12, qword ptr [r15 + 24]
    jbe lcsp_key_invoke
    mov rdi, r12
    call lcsp_allocate_guarded
    mov r13, rax
    mov rdi, rax
    mov rsi, qword ptr [r15 + 16]
    mov rcx, qword ptr [r15 + 24]
    rep movsb
    mov rdi, qword ptr [r15 + 16]
    mov rsi, qword ptr [r15 + 24]
    add rsi, 4096
    mov qword ptr [r15 + 16], r13
    mov qword ptr [r15 + 24], r12
    mov eax, 11
    syscall
    test rax, rax
    jnz lcsp_key_io_fail
    jmp lcsp_key_invoke
lcsp_key_grow_output:
    mov rdi, qword ptr [rbx + 48]
    cmp rdi, qword ptr [r15 + 40]
    jbe lcsp_key_contract_fail
    mov rax, 0xffffffef
    cmp rdi, rax
    ja lcsp_key_contract_fail
    call lcsp_round_capacity
    mov r12, rax
    mov rdi, r12
    call lcsp_allocate_guarded
    mov r13, rax
    mov rdi, qword ptr [r15 + 32]
    mov rsi, qword ptr [r15 + 40]
    add rsi, 4096
    mov qword ptr [r15 + 32], r13
    mov qword ptr [r15 + 40], r12
    mov eax, 11
    syscall
    test rax, rax
    jnz lcsp_key_io_fail
    jmp lcsp_key_invoke

lcsp_key_admit_effect:
    mov rax, qword ptr [r15 + 48]
    cmp qword ptr [rbx + 8], rax
    jne lcsp_key_contract_fail
    mov rax, qword ptr [r15 + 40]
    cmp qword ptr [rbx + 16], rax
    jne lcsp_key_contract_fail
    mov rax, qword ptr [r15 + 24]
    cmp qword ptr [rbx + 24], rax
    jne lcsp_key_contract_fail
    mov rax, qword ptr [rbx + 40]
    or rax, qword ptr [rbx + 48]
    jnz lcsp_key_contract_fail
    mov rax, qword ptr [rbx + 32]
    cmp rax, 1024
    jb lcsp_key_contract_fail
    lea rcx, [rax - 1]
    test rcx, rax
    jnz lcsp_key_contract_fail
    cmp qword ptr [rbx + 96], rax
    jae lcsp_key_contract_fail
    mov rcx, 0x1ffffffffffbfeff
    cmp rax, rcx
    ja lcsp_key_contract_fail
    shl rax, 2
    add rax, 1049600
    jc lcsp_key_contract_fail
    cmp rax, qword ptr [r15 + 24]
    ja lcsp_key_contract_fail
    mov rax, 0x584659454b4c4648
    cmp qword ptr [rbx + 512], rax
    jne lcsp_key_contract_fail
    inc qword ptr [r15 + 88]
    jz lcsp_key_contract_fail
    mov rax, qword ptr [r15 + 88]
    cmp qword ptr [rbx + 520], rax
    jne lcsp_key_contract_fail
    cmp qword ptr [rbx + 56], rax
    jne lcsp_key_contract_fail
    mov rax, qword ptr [rbx + 568]
    or rax, qword ptr [rbx + 576]
    or rax, qword ptr [rbx + 584]
    or rax, qword ptr [rbx + 592]
    or rax, qword ptr [rbx + 600]
    or rax, qword ptr [rbx + 608]
    or rax, qword ptr [rbx + 616]
    or rax, qword ptr [rbx + 624]
    or rax, qword ptr [rbx + 632]
    jnz lcsp_key_contract_fail
    mov r14, qword ptr [rbx + 528]
    cmp r14, 1
    je lcsp_key_get_current
    cmp r14, 2
    je lcsp_key_read_link
    cmp r14, 3
    je lcsp_key_access_path
    cmp r14, 4
    je lcsp_key_access_path
    cmp r14, 5
    je lcsp_key_lstat_path
    cmp r14, 6
    je lcsp_key_access_path
    cmp r14, 7
    je lcsp_key_open_parent
    cmp r14, 8
    je lcsp_key_stat_descriptor
    cmp r14, 9
    je lcsp_key_close_descriptor
    cmp r14, 10
    je lcsp_key_get_flags
    cmp r14, 11
    je lcsp_key_set_cloexec
    cmp r14, 12
    je lcsp_key_directory_entries
    cmp r14, 13
    je lcsp_key_rewind_directory
    jmp lcsp_key_contract_fail

lcsp_key_get_current:
    cmp qword ptr [rbx], 10
    jne lcsp_key_contract_fail
    call lcsp_key_resolved_argument
    mov rdx, qword ptr [rbx + 552]
    or rdx, qword ptr [rbx + 560]
    jnz lcsp_key_contract_fail
    mov rsi, qword ptr [rbx + 544]
    cmp rsi, qword ptr [rbx + 152]
    jne lcsp_key_contract_fail
    cmp rsi, 1024
    jb lcsp_key_contract_fail
    cmp rsi, qword ptr [rbx + 32]
    ja lcsp_key_contract_fail
    mov eax, 79
    syscall
    jmp lcsp_key_value_completion

lcsp_key_read_link:
    cmp qword ptr [rbx], 3
    jne lcsp_key_contract_fail
    call lcsp_key_resolved_argument
    mov rcx, qword ptr [rbx + 544]
    cmp rcx, qword ptr [rbx + 96]
    jne lcsp_key_contract_fail
    call lcsp_key_cstring
    mov rax, qword ptr [rbx + 32]
    lea rax, [rax + rax + 1024]
    cmp qword ptr [rbx + 552], rax
    jne lcsp_key_contract_fail
    lea rsi, [rbx + rax]
    mov rdx, qword ptr [rbx + 144]
    cmp rdx, 1024
    jb lcsp_key_contract_fail
    dec rdx
    cmp rdx, qword ptr [rbx + 560]
    jne lcsp_key_contract_fail
    cmp rdx, qword ptr [rbx + 32]
    jae lcsp_key_contract_fail
    mov eax, 89
    syscall
    jmp lcsp_key_value_completion

lcsp_key_access_path:
    cmp qword ptr [rbx], 4
    jne lcsp_key_contract_fail
    call lcsp_key_resolved_argument
    mov rcx, qword ptr [rbx + 96]
    inc rcx
    cmp rcx, qword ptr [rbx + 32]
    jae lcsp_key_contract_fail
    cmp rcx, qword ptr [rbx + 544]
    jne lcsp_key_contract_fail
    call lcsp_key_cstring
    mov rax, qword ptr [rbx + 552]
    or rax, qword ptr [rbx + 560]
    jnz lcsp_key_contract_fail
    mov rsi, rdi
    mov edi, -100
    xor edx, edx
    mov r10d, 512
    mov eax, 439
    cmp r14, 3
    je lcsp_key_access_go
    cmp r14, 4
    jne lcsp_key_stat_access
    cmp qword ptr [r15 + 64], 0
    jne lcsp_key_contract_fail
    mov eax, 269
lcsp_key_access_go:
    syscall
    jmp lcsp_key_zero_completion
lcsp_key_stat_access:
    cmp qword ptr [r15 + 64], 1
    jne lcsp_key_contract_fail
    xor r10d, r10d
    jmp lcsp_key_stat_at

lcsp_key_lstat_path:
    mov rax, qword ptr [rbx]
    cmp rax, 12
    je lcsp_key_lstat_fixed
    cmp rax, 13
    je lcsp_key_lstat_fixed
    cmp rax, 24
    jne lcsp_key_contract_fail
    mov rax, qword ptr [rbx + 32]
    lea rax, [rax * 4 + 1024]
    add rax, qword ptr [rbx + 368]
    jc lcsp_key_contract_fail
    cmp rax, qword ptr [rbx + 536]
    jne lcsp_key_contract_fail
    mov rcx, qword ptr [rbx + 376]
    cmp rcx, qword ptr [rbx + 544]
    jne lcsp_key_contract_fail
    mov rdx, qword ptr [rbx + 552]
    cmp rdx, qword ptr [rbx + 160]
    jne lcsp_key_contract_fail
    jmp lcsp_key_lstat_arguments
lcsp_key_lstat_fixed:
    mov rax, qword ptr [rbx + 32]
    lea rax, [rax + rax + 1024]
    cmp rax, qword ptr [rbx + 536]
    jne lcsp_key_contract_fail
    mov ecx, 1
    cmp qword ptr [rbx + 544], 1
    jne lcsp_key_contract_fail
    cmp qword ptr [rbx + 552], 0
    jne lcsp_key_contract_fail
    xor edx, edx
    cmp qword ptr [rbx], 12
    jne lcsp_key_lstat_root
    cmp byte ptr [rbx + rax], 46
    jne lcsp_key_contract_fail
    jmp lcsp_key_lstat_arguments
lcsp_key_lstat_root:
    cmp byte ptr [rbx + rax], 47
    jne lcsp_key_contract_fail
lcsp_key_lstat_arguments:
    cmp qword ptr [rbx + 560], 0
    jne lcsp_key_contract_fail
    lea rdi, [rbx + rax]
    call lcsp_key_cstring
    mov rsi, rdi
    mov edi, -100
    test rdx, rdx
    jz lcsp_key_lstat_cwd
    call lcsp_key_descriptor
lcsp_key_lstat_cwd:
    mov r10d, 256
lcsp_key_stat_at:
    mov r12, rsi
    mov r13, rdi
    mov rdi, rsp
    xor eax, eax
    mov ecx, 32
    rep stosq
    mov rdi, r13
    mov rsi, r12
    mov rdx, rsp
    mov eax, 262
    syscall
    jmp lcsp_key_stat_completion

lcsp_key_open_parent:
    cmp qword ptr [rbx], 15
    jne lcsp_key_contract_fail
    mov rax, qword ptr [rbx + 552]
    or rax, qword ptr [rbx + 560]
    jnz lcsp_key_contract_fail
    mov r12, qword ptr [rbx + 536]
    cmp r12, 1
    jb lcsp_key_contract_fail
    cmp r12, 2
    ja lcsp_key_contract_fail
    cmp qword ptr [r15 + r12 * 8 + 64], -1
    jne lcsp_key_contract_fail
    mov rdx, qword ptr [rbx + 544]
    cmp rdx, qword ptr [rbx + 160]
    jne lcsp_key_contract_fail
    cmp rdx, r12
    je lcsp_key_contract_fail
    mov edi, -100
    test rdx, rdx
    jz lcsp_key_open_parent_cwd
    call lcsp_key_descriptor
lcsp_key_open_parent_cwd:
    lea rsi, [rip + lcsp_key_parent_name]
    xor edx, edx
    xor r10d, r10d
    mov eax, 257
    syscall
    test rax, rax
    js lcsp_key_error_completion
    cmp rax, 0x7fffffff
    ja lcsp_key_contract_fail
    mov qword ptr [r15 + r12 * 8 + 64], rax
    mov rax, r12
    jmp lcsp_key_value_completion

lcsp_key_stat_descriptor:
    mov rax, qword ptr [rbx]
    cmp rax, 16
    je lcsp_key_stat_descriptor_phase
    cmp rax, 18
    jne lcsp_key_contract_fail
lcsp_key_stat_descriptor_phase:
    call lcsp_key_zero_trailing_args
    mov rdx, qword ptr [rbx + 536]
    cmp rdx, qword ptr [rbx + 168]
    jne lcsp_key_contract_fail
    call lcsp_key_descriptor
    mov r13, rdi
    mov rdi, rsp
    xor eax, eax
    mov ecx, 32
    rep stosq
    mov rdi, r13
    mov rsi, rsp
    mov eax, 5
    syscall
lcsp_key_stat_completion:
    test rax, rax
    js lcsp_key_error_completion
    test rax, rax
    jnz lcsp_key_contract_fail
    mov rax, qword ptr [rsp]
    mov qword ptr [rbx + 584], rax
    mov rax, qword ptr [rsp + 8]
    mov qword ptr [rbx + 592], rax
    mov eax, dword ptr [rsp + 24]
    mov qword ptr [rbx + 600], rax
    mov rax, qword ptr [rsp + 56]
    mov qword ptr [rbx + 616], rax
    jmp lcsp_key_acknowledge

lcsp_key_close_descriptor:
    mov rax, qword ptr [rbx]
    cmp rax, 17
    je lcsp_key_close_phase
    cmp rax, 27
    je lcsp_key_close_phase
    cmp rax, 29
    jne lcsp_key_contract_fail
lcsp_key_close_phase:
    call lcsp_key_zero_trailing_args
    mov rdx, qword ptr [rbx + 536]
    call lcsp_key_descriptor
    mov qword ptr [r15 + rdx * 8 + 64], -1
    mov eax, 3
    syscall
    jmp lcsp_key_zero_completion

lcsp_key_get_flags:
    cmp qword ptr [rbx], 19
    jne lcsp_key_contract_fail
    call lcsp_key_zero_trailing_args
    mov rdx, qword ptr [rbx + 536]
    cmp rdx, qword ptr [rbx + 168]
    jne lcsp_key_contract_fail
    call lcsp_key_descriptor
    mov esi, 3
    xor edx, edx
    mov eax, 72
    syscall
    jmp lcsp_key_value_completion
lcsp_key_set_cloexec:
    cmp qword ptr [rbx], 20
    jne lcsp_key_contract_fail
    call lcsp_key_zero_trailing_args
    mov rdx, qword ptr [rbx + 536]
    cmp rdx, qword ptr [rbx + 168]
    jne lcsp_key_contract_fail
    call lcsp_key_descriptor
    mov esi, 2
    mov edx, 1
    mov eax, 72
    syscall
    jmp lcsp_key_zero_completion

lcsp_key_directory_entries:
    cmp qword ptr [rbx], 22
    jne lcsp_key_contract_fail
    cmp qword ptr [rbx + 560], 0
    jne lcsp_key_contract_fail
    mov rax, qword ptr [rbx + 32]
    lea rax, [rax * 4 + 1024]
    cmp rax, qword ptr [rbx + 544]
    jne lcsp_key_contract_fail
    mov r12, qword ptr [rbx + 552]
    cmp r12, 32768
    jb lcsp_key_contract_fail
    cmp r12, 1048576
    ja lcsp_key_contract_fail
    cmp r12, qword ptr [rbx + 336]
    jne lcsp_key_contract_fail
    lea rsi, [rbx + rax]
    mov rdx, qword ptr [rbx + 536]
    cmp rdx, qword ptr [rbx + 160]
    jne lcsp_key_contract_fail
    call lcsp_key_descriptor
    mov rdx, r12
    mov eax, 217
    syscall
    jmp lcsp_key_value_completion
lcsp_key_rewind_directory:
    cmp qword ptr [rbx], 23
    jne lcsp_key_contract_fail
    call lcsp_key_zero_trailing_args
    mov rdx, qword ptr [rbx + 536]
    cmp rdx, qword ptr [rbx + 160]
    jne lcsp_key_contract_fail
    call lcsp_key_descriptor
    xor esi, esi
    xor edx, edx
    mov eax, 8
    syscall
    jmp lcsp_key_value_completion

lcsp_key_resolved_argument:
    mov rax, qword ptr [rbx + 32]
    add rax, 1024
    cmp qword ptr [rbx + 536], rax
    jne lcsp_key_contract_fail
    lea rdi, [rbx + rax]
    ret
lcsp_key_zero_trailing_args:
    mov rax, qword ptr [rbx + 544]
    or rax, qword ptr [rbx + 552]
    or rax, qword ptr [rbx + 560]
    jnz lcsp_key_contract_fail
    ret
# logical slot in rdx -> real lcsp_key_descriptor in rdi, preserving other arguments.
lcsp_key_descriptor:
    cmp rdx, 1
    jb lcsp_key_contract_fail
    cmp rdx, 2
    ja lcsp_key_contract_fail
    mov rdi, qword ptr [r15 + rdx * 8 + 64]
    test rdi, rdi
    js lcsp_key_contract_fail
    ret
# Exact span containment and unique final NUL.  rdx is preserved for dirfd.
lcsp_key_cstring:
    mov rax, rdi
    sub rax, rbx
    jc lcsp_key_contract_fail
    cmp rax, qword ptr [r15 + 24]
    jae lcsp_key_contract_fail
    mov r11, qword ptr [r15 + 24]
    sub r11, rax
    cmp rcx, r11
    jae lcsp_key_contract_fail
    cmp byte ptr [rdi + rcx], 0
    jne lcsp_key_contract_fail
    xor eax, eax
lcsp_key_cstring_loop:
    cmp rax, rcx
    je lcsp_key_cstring_done
    cmp byte ptr [rdi + rax], 0
    je lcsp_key_contract_fail
    inc rax
    jmp lcsp_key_cstring_loop
lcsp_key_cstring_done:
    ret
lcsp_key_value_completion:
    test rax, rax
    js lcsp_key_error_completion
    mov qword ptr [rbx + 568], rax
    jmp lcsp_key_acknowledge
lcsp_key_zero_completion:
    test rax, rax
    js lcsp_key_error_completion
    test rax, rax
    jnz lcsp_key_contract_fail
    jmp lcsp_key_acknowledge
lcsp_key_error_completion:
    neg rax
    cmp rax, 4095
    ja lcsp_key_contract_fail
    mov qword ptr [rbx + 576], rax
lcsp_key_acknowledge:
    mov qword ptr [rbx + 608], 1
    jmp lcsp_key_invoke

lcsp_key_cleanup:
    mov rdi, qword ptr [r15 + 72]
    mov qword ptr [r15 + 72], -1
    test rdi, rdi
    js lcsp_key_cleanup_second
    mov eax, 3
    syscall
lcsp_key_cleanup_second:
    mov rdi, qword ptr [r15 + 80]
    mov qword ptr [r15 + 80], -1
    test rdi, rdi
    js lcsp_key_cleanup_done
    mov eax, 3
    syscall
lcsp_key_cleanup_done:
    ret
lcsp_key_done:
    mov eax, dword ptr [r15 + 56]
    add rsp, 520
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret
lcsp_key_contract_fail:
    call lcsp_key_cleanup
    mov edi, 70
    jmp lcsp_fatal_exit
lcsp_key_memory_fail:
    call lcsp_key_cleanup
    mov edi, 71
    jmp lcsp_fatal_exit
lcsp_key_io_fail:
    call lcsp_key_cleanup
    mov edi, 74
    jmp lcsp_fatal_exit
lcsp_key_parent_name:
    .asciz ".."

.balign 16
