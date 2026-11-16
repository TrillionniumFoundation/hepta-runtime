.intel_syntax noprefix
.text
.equ lel_INPUT,0
.equ lel_INCAP,8
.equ lel_INLEN,16
.equ lel_CALLBACK,24
.equ lel_CBCAP,32
.equ lel_CURRENT,40
.equ lel_CURLEN,48
.equ lel_CHILD,56
.equ lel_SEQUENCE,64
.equ lel_GENERATION,72
.equ lel_HINTS,80
.equ lel_HINTCAP,88
.equ lel_HINTLEN,96
.equ lel_HINTCOUNT,104
.equ lel_CHILDREQ,112
.equ lel_CHILDREQLEN,120
.equ lel_CHILDOUT,128
.equ lel_CHILDCODE,136
.equ lel_OBS_PHASE,144
.equ lel_SECURE,152
.equ lel_SLOTS,256
.equ lel_READCTX,2048
.equ lel_KEYCTX,2176
.equ lel_ATOMICCTX,2304
.equ lel_META_BYTE,2432
.equ lel_MKREQ,1536
.equ lel_MKREQCAP,1544
.equ lel_MKLEN,1552
.equ lel_MKSEQ,1560
.equ lel_CHILDEXTENT,1568
.equ lel_MKWORK,1584
.equ lel_MKWORKCAP,1592
.global local_extract_lines_run
.global local_extract_lines_resume
.global local_extract_lines_cancel_wait
.global local_extract_lines_release
.equ lel_PUBLIC_CTX,1280
.equ lel_RETURN_STACK,1288
.equ lel_META_POINTER,1296
.equ lel_RESULT_PAIR,1304
.equ lel_WAIT_FLAG,1320
.equ lel_ABORTING,1328
.equ lel_CLEAN_FRAME,1344
.equ lel_CLEAN_OUTPUT,1408
.equ lel_MAIN_TAG,192
.equ lel_MAIN_MAGIC,0x31304d4354584548
.equ lel_CONTEXT_MAGIC,0x3130494354584548

local_extract_lines_run:
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
    jz lel_callable_invalid_early
    mov rax,lel_CONTEXT_MAGIC
    cmp [rdi],rax
    jne lel_callable_invalid_early
    cmp qword ptr [rdi+8],192
    jne lel_callable_invalid_early
    cmp qword ptr [rdi+16],0
    je lel_callable_invalid_early
    cmp qword ptr [rdi+24],0
    je lel_callable_invalid_early
    cmp qword ptr [rdi+40],0
    je lel_callable_invalid_early
    cmp qword ptr [rdi+72],0
    je lel_callable_invalid_early
    cmp qword ptr [rdi+96],1
    ja lel_callable_invalid_early
    cmp qword ptr [rdi+104],0
    jne lel_callable_invalid_early
    mov ecx,112
lel_callable_empty_fields:
    cmp qword ptr [rdi+rcx],0
    jne lel_callable_invalid_early
    add ecx,8
    cmp ecx,192
    jb lel_callable_empty_fields
    mov rax,[rdi+88]
    test rax,rax
    jz lel_callable_invalid_early
    cmp byte ptr [rax],2
    ja lel_callable_invalid_early
    mov rax,[rdi+16]
    xor ecx,ecx
lel_callable_check_entries:
    cmp qword ptr [rax+rcx*8],0
    je lel_callable_invalid_early
    inc ecx
    cmp ecx,14
    jb lel_callable_check_entries
    mov ebx,3
lel_callable_check_shared:
    mov rdx,[rdi+56]
    cmp ebx,3
    je lel_callable_check_record
    mov rdx,[rdi+64]
lel_callable_check_record:
    test rdx,rdx
    jz lel_callable_invalid_early
    test dl,7
    jnz lel_callable_invalid_early
    mov rcx,[rax+rbx*8]
    cmp [rdx],rcx
    jne lel_callable_invalid_early
    cmp qword ptr [rdx+8],0
    je lel_callable_invalid_early
    cmp qword ptr [rdx+16],4096
    jb lel_callable_invalid_early
    cmp qword ptr [rdx+16],268435456
    ja lel_callable_invalid_early
    test qword ptr [rdx+16],4095
    jnz lel_callable_invalid_early
    cmp qword ptr [rdx+24],0
    je lel_callable_invalid_early
    cmp qword ptr [rdx+32],4096
    jb lel_callable_invalid_early
    cmp qword ptr [rdx+32],134217728
    ja lel_callable_invalid_early
    test qword ptr [rdx+32],4095
    jnz lel_callable_invalid_early
    mov rcx,[rdx+48]
    or rcx,[rdx+56]
    jnz lel_callable_invalid_early
    cmp ebx,3
    jne lel_callable_admitted
    mov ebx,6
    jmp lel_callable_check_shared
lel_callable_admitted:
    cmp qword ptr [rsp+16],134217728
    ja lel_callable_capacity_early
    xor r15d,r15d
    mov edi,4096
    call lel_allocate_guarded
    mov r15,rax
    mov rax,lel_MAIN_MAGIC
    mov [r15+lel_MAIN_TAG],rax
    mov rbx,[rsp]
    mov [r15+lel_PUBLIC_CTX],rbx
    mov [r15+lel_RETURN_STACK],rsp
    mov [rbx+152],r15
    mov rax,[rbx+88]
    mov [r15+lel_META_POINTER],rax
    mov rax,[rbx+96]
    mov [r15+lel_SECURE],rax
    mov qword ptr [r15+lel_ATOMICCTX+80],-1
    mov rsi,[rbx+16]
    xor ecx,ecx
lel_callable_install_entries:
    mov rax,[rsi+rcx*8]
    mov rdi,rcx
    shl rdi,6
    mov [r15+lel_SLOTS+rdi],rax
    inc ecx
    cmp ecx,14
    jb lel_callable_install_entries
    lea rdi,[r15+lel_INPUT]
    mov rsi,[rsp+16]
    xor edx,edx
    call lel_ensure_region
    mov rdi,[r15+lel_INPUT]
    mov rsi,[rsp+8]
    mov rcx,[rsp+16]
    mov [r15+lel_INLEN],rcx
    rep movsb
    mov rdi,[r15+lel_INPUT]
    mov rsi,[r15+lel_INCAP]
    mov edx,1
    call lel_protection
    mov rax,[r15+lel_INPUT]
    mov [r15+lel_CURRENT],rax
    mov rax,[r15+lel_INLEN]
    mov [r15+lel_CURLEN],rax
    cmp rax,128
    jb lel_body_invoke
    mov rax,[r15+lel_INPUT]
    mov rax,[rax+24]
    mov [r15+lel_GENERATION],rax
    jmp lel_body_invoke
lel_callable_invalid_early:
    mov eax,0xffffffff
    jmp lel_callable_return_early
lel_callable_capacity_early:
    mov eax,0xfffffffe
lel_callable_return_early:
    mov rsp,r13
lel_callable_restore:
    add rsp,24
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

/* The exposed suspension is the unchanged HIA file-lock WAIT. */
local_extract_lines_resume:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp,24
    mov [rsp],rdi
    mov r13,rsp
    call lel_callable_check_wait
    test eax,eax
    jnz lel_callable_invalid_early
    mov [r15+lel_RETURN_STACK],rsp
    mov qword ptr [r15+lel_WAIT_FLAG],0
    mov rbx,[r15+lel_PUBLIC_CTX]
    mov qword ptr [rbx+112],0
    mov qword ptr [rbx+120],0
    mov qword ptr [rbx+128],0
    lea rdi,[r15+lel_CALLBACK]
    mov esi,48
    xor edx,edx
    call lel_ensure_region
    mov rdi,[r15+lel_CALLBACK]
    mov rsi,[r15+lel_CBCAP]
    mov edx,3
    call lel_protection
    mov rbx,[r15+lel_CALLBACK]
    mov rax,0x31304b5742544c48
    mov [rbx],rax
    mov rdx,[r15+lel_SLOTS+8]
    mov rax,[rdx+16]
    mov [rbx+8],rax
    mov rax,[rdx+40]
    mov [rbx+16],rax
    mov rax,[rdx+168]
    mov [rbx+24],rax
    mov qword ptr [rbx+32],0
    mov qword ptr [rbx+40],0
    mov rdi,rbx
    mov rsi,[r15+lel_CBCAP]
    mov edx,1
    call lel_protection
    mov [r15+lel_CURRENT],rbx
    mov qword ptr [r15+lel_CURLEN],48
    jmp lel_body_invoke

lel_callable_check_wait:
    test rdi,rdi
    jz lel_callable_wait_bad
    mov rax,lel_CONTEXT_MAGIC
    cmp [rdi],rax
    jne lel_callable_wait_bad
    cmp qword ptr [rdi+8],192
    jne lel_callable_wait_bad
    cmp qword ptr [rdi+136],0
    jne lel_callable_wait_bad
    cmp qword ptr [rdi+144],0
    jne lel_callable_wait_bad
    mov r15,[rdi+152]
    test r15,r15
    jz lel_callable_wait_bad
    mov rax,lel_MAIN_MAGIC
    cmp [r15+lel_MAIN_TAG],rax
    jne lel_callable_wait_bad
    cmp [r15+lel_PUBLIC_CTX],rdi
    jne lel_callable_wait_bad
    cmp qword ptr [r15+lel_WAIT_FLAG],1
    jne lel_callable_wait_bad
    mov rax,[r15+lel_SLOTS+8]
    cmp qword ptr [rax+8],14
    jne lel_callable_wait_bad
    cmp qword ptr [rax+48],0
    jne lel_callable_wait_bad
    cmp qword ptr [rax+168],0
    je lel_callable_wait_bad
    cmp qword ptr [rax+176],0
    jne lel_callable_wait_bad
    xor eax,eax
    ret
lel_callable_wait_bad:
    mov eax,0xffffffff
    ret

/* Only a returned WAIT may be dropped; this cancels no in-flight I/O. */
local_extract_lines_cancel_wait:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp,24
    mov [rsp],rdi
    mov r13,rsp
    call lel_callable_check_wait
    test eax,eax
    jnz lel_callable_invalid_early
    mov [r15+lel_RETURN_STACK],rsp
    call lel_callable_drop_lease
    test eax,eax
    jnz lel_contract
    mov qword ptr [r15+lel_WAIT_FLAG],0
    mov eax,0xfffffff7
    jmp lel_callable_complete

lel_callable_wait:
    mov r10,[r15+lel_PUBLIC_CTX]
    mov rax,[r15+lel_SLOTS+24]
    mov [r10+112],rax
    mov qword ptr [r10+120],48
    mov eax,0xffffffdf
    mov [r10+128],rax
    mov qword ptr [r15+lel_WAIT_FLAG],1
    mov eax,0xffffffdf
    jmp lel_callable_return

lel_callable_complete:
    mov r10,[r15+lel_PUBLIC_CTX]
    cmp qword ptr [r10+136],0
    jne lel_contract
    mov [r10+128],rax
    mov qword ptr [r10+112],0
    mov qword ptr [r10+120],0
    cmp eax,0xffff0000
    jae lel_callable_complete_fields
    mov rcx,[r15+lel_SLOTS+24]
    mov [r10+112],rcx
    mov [r10+120],rax
lel_callable_complete_fields:
    mov qword ptr [r10+136],1
    mov qword ptr [r10+144],1
lel_callable_return:
    mov rsp,[r15+lel_RETURN_STACK]
    jmp lel_callable_restore

lel_callable_shared_growth:
    push rbp
    mov rbp,rsp
    and rsp,-16
    mov rdx,rsi
    mov rcx,rdi
    sub rsp,16
    mov [rsp],rdx
    mov [rsp+8],rcx
    mov r10,[r15+lel_PUBLIC_CTX]
    mov rdi,[r10+80]
    mov rsi,r14
    call qword ptr [r10+72]
    test eax,eax
    jnz lel_resource
    mov rax,[rsp]
    cmp [rbx+16],rax
    jb lel_contract
    mov rax,[rsp+8]
    cmp [rbx+32],rax
    jb lel_contract
    mov rax,r14
    shl rax,6
    mov rax,[r15+lel_SLOTS+rax]
    cmp [rbx],rax
    jne lel_contract
    mov rax,[rbx+48]
    or rax,[rbx+56]
    jnz lel_contract
    cmp qword ptr [rbx+8],0
    je lel_contract
    cmp qword ptr [rbx+24],0
    je lel_contract
    cmp qword ptr [rbx+16],268435456
    ja lel_contract
    cmp qword ptr [rbx+32],134217728
    ja lel_contract
    test qword ptr [rbx+16],4095
    jnz lel_contract
    test qword ptr [rbx+32],4095
    jnz lel_contract
    mov rsp,rbp
    pop rbp
    ret

lel_callable_cache:
    mov r10,[r15+lel_PUBLIC_CTX]
    mov r11,[r10+24]
    mov rdi,[r10+32]
    jmp lel_callable_external
lel_callable_hint:
    mov r10,[r15+lel_PUBLIC_CTX]
    mov r11,[r10+40]
    mov rdi,[r10+48]
lel_callable_external:
    mov qword ptr [r15+lel_RESULT_PAIR],0
    mov qword ptr [r15+lel_RESULT_PAIR+8],0
    mov rsi,[r15+lel_CHILDREQ]
    mov rdx,[r15+lel_CHILDREQLEN]
    lea rcx,[r15+lel_RESULT_PAIR]
    call r11
    cmp rax,32
    jne lel_contract
    cmp qword ptr [r15+lel_RESULT_PAIR+8],32
    jne lel_contract
    mov rcx,[r15+lel_RESULT_PAIR]
    test rcx,rcx
    jz lel_contract
    mov [r15+lel_CHILDOUT],rcx
    jmp lel_child_completed

/* Failure drains owned capabilities without inventing a semantic result. */
lel_callable_abort:
    test r15,r15
    jz lel_callable_fault_early
    mov rsp,[r15+lel_RETURN_STACK]
    cmp qword ptr [r15+lel_ABORTING],0
    jne lel_callable_uncertain
    mov [r15+lel_ABORTING],rdi
    mov rbx,[r15+lel_PUBLIC_CTX]
    mov [rbx+160],rdi
    cmp qword ptr [r15+lel_READCTX+80],0
    je lel_callable_abort_key
    push r15
    lea r15,[r15+lel_READCTX]
    call lel_lr_cleanup
    pop r15
    mov rax,[r15+lel_READCTX+16]
    mov [r15+lel_SLOTS+64+8],rax
    mov rax,[r15+lel_READCTX+24]
    mov [r15+lel_SLOTS+64+16],rax
    mov rax,[r15+lel_READCTX+32]
    mov [r15+lel_SLOTS+64+24],rax
    mov rax,[r15+lel_READCTX+40]
    mov [r15+lel_SLOTS+64+32],rax
lel_callable_abort_key:
    cmp qword ptr [r15+lel_KEYCTX+96],0
    je lel_callable_abort_atomic
    push r15
    lea r15,[r15+lel_KEYCTX]
    call lel_key_cleanup
    pop r15
    mov rax,[r15+lel_KEYCTX+16]
    mov [r15+lel_SLOTS+128+8],rax
    mov rax,[r15+lel_KEYCTX+24]
    mov [r15+lel_SLOTS+128+16],rax
    mov rax,[r15+lel_KEYCTX+32]
    mov [r15+lel_SLOTS+128+24],rax
    mov rax,[r15+lel_KEYCTX+40]
    mov [r15+lel_SLOTS+128+32],rax
lel_callable_abort_atomic:
    mov rdi,[r15+lel_ATOMICCTX+80]
    mov qword ptr [r15+lel_ATOMICCTX+80],-1
    test rdi,rdi
    js lel_callable_abort_lease
    mov eax,3
    syscall
lel_callable_abort_lease:
    call lel_callable_drop_lease
    test eax,eax
    jnz lel_callable_uncertain
    mov eax,0xfffffffc
    jmp lel_callable_complete
lel_callable_uncertain:
    mov r10,[r15+lel_PUBLIC_CTX]
    mov eax,0xfffffffc
    mov [r10+128],rax
    mov qword ptr [r10+136],1
    mov qword ptr [r10+144],0
    mov qword ptr [r10+112],0
    mov qword ptr [r10+120],0
    mov eax,0xfffffffc
    jmp lel_callable_return

lel_callable_drop_lease:
    push rbx
    mov rax,[r15+lel_SLOTS+8]
    test rax,rax
    jz lel_callable_drop_done
    mov rbx,[rax+168]
    test rbx,rbx
    jz lel_callable_drop_done
    lea rdi,[r15+lel_CLEAN_FRAME]
    xor eax,eax
    mov ecx,8
    rep stosq
    mov rax,0x314b434f4c465248
    mov [r15+lel_CLEAN_FRAME],rax
    mov qword ptr [r15+lel_CLEAN_FRAME+8],6
    mov [r15+lel_CLEAN_FRAME+16],rbx
    mov r10,[r15+lel_PUBLIC_CTX]
    mov r10,[r10+56]
    lea rdi,[r15+lel_CLEAN_FRAME]
    mov esi,64
    lea rdx,[r15+lel_CLEAN_OUTPUT]
    mov ecx,64
    mov r8,[r10+8]
    mov r9,[r10+16]
    call qword ptr [r10]
    cmp rax,64
    jne lel_callable_drop_bad
    mov rax,0x3130524b4c465248
    cmp [r15+lel_CLEAN_OUTPUT],rax
    jne lel_callable_drop_bad
    cmp qword ptr [r15+lel_CLEAN_OUTPUT+8],6
    jne lel_callable_drop_bad
    cmp qword ptr [r15+lel_CLEAN_OUTPUT+16],0
    jne lel_callable_drop_bad
    cmp [r15+lel_CLEAN_OUTPUT+24],rbx
    jne lel_callable_drop_bad
lel_callable_drop_done:
    xor eax,eax
    jmp lel_callable_drop_return
lel_callable_drop_bad:
    mov eax,0xffffffff
lel_callable_drop_return:
    pop rbx
    ret

lel_callable_fault_early:
    mov rsp,r13
    mov r10,[rsp]
    mov [r10+160],rdi
    mov eax,0xfffffffc
    mov [r10+128],rax
    mov qword ptr [r10+136],1
    mov qword ptr [r10+144],1
    mov eax,0xfffffffc
    jmp lel_callable_restore

/* Release never frees borrowed records, callbacks, or the parent statx byte. */
local_extract_lines_release:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov r12,rdi
    test rdi,rdi
    jz lel_callable_release_invalid
    mov rax,lel_CONTEXT_MAGIC
    cmp [rdi],rax
    jne lel_callable_release_invalid
    cmp qword ptr [rdi+8],192
    jne lel_callable_release_invalid
    cmp qword ptr [rdi+136],1
    jne lel_callable_release_busy
    cmp qword ptr [rdi+144],1
    jne lel_callable_release_busy
    mov r15,[rdi+152]
    test r15,r15
    jz lel_callable_release_done
    mov rax,lel_MAIN_MAGIC
    cmp [r15+lel_MAIN_TAG],rax
    jne lel_callable_release_invalid
    cmp [r15+lel_PUBLIC_CTX],r12
    jne lel_callable_release_invalid
    lea r13,[rip+lel_callable_owned_regions]
    mov r14d,27
lel_callable_release_region:
    mov rbx,[r13]
    mov rdi,[r15+rbx]
    test rdi,rdi
    jz lel_callable_release_next
    mov rsi,[r15+rbx+8]
    add rsi,4096
    jc lel_callable_release_invalid
    mov eax,11
    syscall
    test rax,rax
    jnz lel_callable_release_invalid
    mov qword ptr [r15+rbx],0
    mov qword ptr [r15+rbx+8],0
lel_callable_release_next:
    add r13,8
    dec r14d
    jnz lel_callable_release_region
    mov rdi,r15
    mov esi,8192
    mov eax,11
    syscall
    test rax,rax
    jnz lel_callable_release_invalid
    mov qword ptr [r12+152],0
    mov qword ptr [r12+112],0
    mov qword ptr [r12+120],0
lel_callable_release_done:
    xor eax,eax
    jmp lel_callable_release_return
lel_callable_release_busy:
    mov eax,16
    jmp lel_callable_release_return
lel_callable_release_invalid:
    mov eax,0xffffffff
lel_callable_release_return:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret
.balign 8,0
lel_callable_owned_regions:
    .quad lel_INPUT,lel_CALLBACK,160
    .quad lel_SLOTS+8,lel_SLOTS+24,lel_SLOTS+64+8,lel_SLOTS+64+24
    .quad lel_SLOTS+128+8,lel_SLOTS+128+24,lel_SLOTS+256+8,lel_SLOTS+256+24
    .quad lel_SLOTS+320+8,lel_SLOTS+320+24,lel_SLOTS+448+8,lel_SLOTS+448+24
    .quad lel_SLOTS+576+8,lel_SLOTS+576+24,lel_SLOTS+640+8,lel_SLOTS+640+24
    .quad lel_SLOTS+704+8,lel_SLOTS+704+24
    .quad lel_SLOTS+768+8,lel_SLOTS+768+24,lel_SLOTS+832+8,lel_SLOTS+832+24
    .quad lel_MKREQ,lel_MKWORK

lel_body_invoke:
    xor edi,edi
    mov rsi,[r15+lel_CURRENT]
    mov rdx,[r15+lel_CURLEN]
    call lel_pure_invoke
    cmp eax,0xffffffe0
    je lel_body_call
    cmp eax,0xffffffdf
    je lel_callable_wait
    cmp eax,0xffff0000
    jae lel_callable_owner_refusal
    cmp eax,32
    jb lel_contract
    mov rdx,[r15+lel_SLOTS+8]
    cmp qword ptr [rdx+8],100
    jne lel_contract
    mov rcx,[rdx+48]
    or rcx,[rdx+168]
    or rcx,[rdx+176]
    jnz lel_contract
    jmp lel_callable_complete
lel_callable_owner_refusal:
    mov rdx,[r15+lel_SLOTS+8]
    cmp qword ptr [rdx],0
    jne lel_contract
    jmp lel_callable_complete
lel_body_call:
    mov rbx,[r15+lel_SLOTS+24]
    mov rax,0x314c414342544c48
    cmp [rbx],rax
    jne lel_contract
    mov rax,[rbx+8]
    cmp rax,[r15+lel_SLOTS+32]
    ja lel_contract
    cmp rax,64
    jb lel_contract
    sub rax,64
    cmp [rbx+48],rax
    jne lel_contract
    cmp qword ptr [rbx+40],1
    jne lel_contract
    cmp qword ptr [rbx+56],0
    jne lel_contract
    mov rcx,[rbx+16]
    test rcx,rcx
    jz lel_contract
    cmp rcx,14
    ja lel_contract
    mov [r15+lel_CHILD],rcx
    mov [r15+lel_CHILDREQLEN],rax
    lea rax,[rbx+64]
    mov [r15+lel_CHILDREQ],rax
    mov rax,[rbx+24]
    mov [r15+lel_SEQUENCE],rax
    mov rax,[rbx+32]
    cmp rax,[r15+lel_GENERATION]
    jne lel_contract
    mov rdi,rbx
    mov rsi,[r15+lel_SLOTS+32]
    mov edx,1
    call lel_protection
    mov rax,[r15+lel_CHILD]
    cmp eax,1
    je lel_child_read
    cmp eax,2
    je lel_child_key
    cmp eax,7
    je lel_child_atomic
    cmp eax,8
    je lel_callable_cache
    cmp eax,10
    je lel_callable_hint
    cmp eax,11
    je lel_child_mkdir
    cmp eax,12
    je lel_child_error
    cmp eax,13
    je lel_child_endpoint
    cmp eax,14
    je lel_child_verify
    mov rdi,rax
    mov rsi,[r15+lel_CHILDREQ]
    mov rdx,[r15+lel_CHILDREQLEN]
    call lel_pure_invoke
    mov [r15+lel_CHILDOUT],rsi
    jmp lel_child_completed
lel_child_endpoint:
    mov edi,12
    jmp lel_child_pure_selected
lel_child_verify:
    mov edi,13
    jmp lel_child_pure_selected
lel_child_error:
    mov edi,11
lel_child_pure_selected:
    mov rsi,[r15+lel_CHILDREQ]
    mov rdx,[r15+lel_CHILDREQLEN]
    call lel_pure_invoke
    mov [r15+lel_CHILDOUT],rsi
lel_child_completed:
    mov edx,eax
    cmp rax,rdx
    jne lel_contract
    cmp eax,0xffff0000
    jae lel_contract
    mov [r15+lel_CHILDCODE],rax
    mov [r15+lel_CHILDEXTENT],rax
    cmp qword ptr [r15+lel_CHILD],9
    je lel_parent_extent
    cmp qword ptr [r15+lel_CHILD],13
    je lel_endpoint_extent
    jmp lel_extent_ready
lel_parent_extent:
    cmp eax,80
    jne lel_contract
    mov rdx,[r15+lel_CHILDOUT]
    mov rcx,[rdx+16]
    cmp rcx,80
    jb lel_contract
    cmp rcx,[r15+lel_SLOTS+576+32]
    ja lel_contract
    mov [r15+lel_CHILDEXTENT],rcx
    jmp lel_extent_ready
lel_endpoint_extent:
    cmp eax,32
    jne lel_contract
    mov rdx,[r15+lel_CHILDOUT]
    mov ecx,32
    cmp qword ptr [rdx+8],0
    jne lel_endpoint_extent_checked
    add rcx,[rdx+24]
    jc lel_contract
lel_endpoint_extent_checked:
    cmp rcx,[r15+lel_SLOTS+768+32]
    ja lel_contract
    mov [r15+lel_CHILDEXTENT],rcx
lel_extent_ready:
    mov rdi,[r15+lel_SLOTS+24]
    mov rsi,[r15+lel_SLOTS+32]
    mov edx,3
    call lel_protection
    lea rdi,[r15+lel_CALLBACK]
    mov rsi,[r15+lel_CHILDEXTENT]
    add rsi,64
    jc lel_resource
    xor edx,edx
    call lel_ensure_region
    mov rdi,[r15+lel_CALLBACK]
    mov rsi,[r15+lel_CBCAP]
    mov edx,3
    call lel_protection
    mov rbx,[r15+lel_CALLBACK]
    mov rax,0x3130514342544c48
    mov [rbx],rax
    mov qword ptr [rbx+8],2
    mov rax,[r15+lel_GENERATION]
    mov [rbx+16],rax
    mov rax,[r15+lel_SEQUENCE]
    mov [rbx+24],rax
    mov rax,[r15+lel_CHILD]
    mov [rbx+32],rax
    mov rcx,[r15+lel_CHILDCODE]
    mov [rbx+40],rcx
    mov rcx,[r15+lel_CHILDEXTENT]
    mov [rbx+48],rcx
    mov qword ptr [rbx+56],0
    lea rdi,[rbx+64]
    mov rsi,[r15+lel_CHILDOUT]
    rep movsb
    mov rdi,rbx
    mov rsi,[r15+lel_CBCAP]
    mov edx,1
    call lel_protection
    mov [r15+lel_CURRENT],rbx
    mov rax,[r15+lel_CHILDEXTENT]
    add rax,64
    mov [r15+lel_CURLEN],rax
    jmp lel_body_invoke

lel_lock_initial:
    .quad 0x314b434f4c465248,0,0,0,0,0,0,0
lel_hint_response:
    .quad 0x3130504842544c48,0,0,0

/* Pure HIA calls retain one arena per fixed image. Growth replays only an
   admitted lel_resource refusal; semantic completion is returned to the caller. */
lel_pure_invoke:
    push rbp
    push rbx
    push r12
    push r13
    push r14
    mov r14,rdi
    cmp r14,13
    ja lel_contract
    mov r12,rsi
    mov r13,rdx
    cmp r13,134217728
    ja lel_resource
    mov rbx,r14
    shl rbx,6
    lea rbx,[r15+lel_SLOTS+rbx]
    cmp r14,3
    je lel_callable_lock_record
    cmp r14,6
    je lel_callable_history_record
    jmp lel_callable_private_record
lel_callable_lock_record:
    mov rbx,[r15+lel_PUBLIC_CTX]
    mov rbx,[rbx+56]
    jmp lel_pure_again
lel_callable_history_record:
    mov rbx,[r15+lel_PUBLIC_CTX]
    mov rbx,[rbx+64]
    jmp lel_pure_again
lel_callable_private_record:
    lea rdi,[rbx+8]
    mov esi,4096
    mov edx,1
    call lel_ensure_region
    lea rdi,[rbx+24]
    mov esi,4096
    xor edx,edx
    call lel_ensure_region
lel_pure_again:
    mov rdi,r12
    mov rsi,r13
    mov rdx,[rbx+24]
    mov rcx,[rbx+32]
    mov r8,[rbx+8]
    mov r9,[rbx+16]
    call qword ptr [rbx]
    mov edx,eax
    cmp rax,rdx
    jne lel_contract
    cmp eax,0xffffffd0
    je lel_pure_data_growth
    cmp eax,0xffffffef
    je lel_pure_work_need
    cmp eax,0xffffffee
    je lel_pure_output_need
    cmp eax,0xfffffffe
    je lel_pure_capacity
    cmp eax,0xffff0000
    jae lel_pure_return
    cmp rax,[rbx+32]
    ja lel_contract
    cmp r14,3
    jne lel_pure_return
    cmp eax,64
    jne lel_pure_return
    mov rcx,[rbx+24]
    cmp qword ptr [rcx+16],2
    jne lel_pure_return
    mov rsi,[rcx+32]
    jmp lel_pure_grow_work
lel_pure_data_growth:
    cmp r14,5
    jne lel_contract
    cmp qword ptr [rbx+32],32
    jb lel_contract
    mov rax,[rbx+24]
    mov rcx,0x3230305357524748
    cmp [rax],rcx
    jne lel_contract
    cmp qword ptr [rax+24],0
    jne lel_contract
    mov rsi,[rax+16]
    cmp qword ptr [rax+8],1
    je lel_pure_grow_work
    cmp qword ptr [rax+8],2
    jne lel_contract
    jmp lel_pure_grow_output
lel_pure_work_need:
    cmp r14,0
    je lel_pure_work_pointer
    jmp lel_contract
lel_pure_work_pointer:
    mov rax,[rbx+8]
    mov rsi,[rax+144]
lel_pure_grow_work:
    cmp rsi,[rbx+16]
    jbe lel_contract
    cmp rsi,268435456
    ja lel_resource
    cmp r14,3
    jne lel_callable_private_work_growth
    mov rdi,[rbx+32]
    call lel_callable_shared_growth
    jmp lel_pure_again
lel_callable_private_work_growth:
    lea rdi,[rbx+8]
    mov edx,1
    call lel_ensure_region
    jmp lel_pure_again
lel_pure_output_need:
    cmp r14,0
    je lel_pure_output_pointer
    jmp lel_contract
lel_pure_output_pointer:
    mov rax,[rbx+8]
    mov rsi,[rax+152]
lel_pure_grow_output:
    cmp rsi,[rbx+32]
    jbe lel_contract
    cmp rsi,134217728
    ja lel_resource
    lea rdi,[rbx+24]
    xor edx,edx
    call lel_ensure_region
    jmp lel_pure_again
lel_pure_capacity:
    cmp r14,6
    jne lel_callable_private_capacity
    mov rsi,[rbx+16]
    shl rsi,1
    jc lel_resource
    cmp rsi,268435456
    ja lel_resource
    mov rdi,[rbx+32]
    shl rdi,1
    jc lel_resource
    cmp rdi,134217728
    ja lel_resource
    call lel_callable_shared_growth
    jmp lel_pure_again
lel_callable_private_capacity:
    cmp r14,4
    je lel_pure_capacity_grow
    cmp r14,6
    je lel_pure_capacity_grow
    cmp r14,8
    je lel_pure_capacity_grow
    cmp r14,9
    je lel_pure_capacity_grow
    cmp r14,12
    je lel_pure_capacity_grow
    cmp r14,13
    jne lel_resource
lel_pure_capacity_grow:
    mov rsi,[rbx+16]
    shl rsi,1
    jc lel_resource
    cmp rsi,268435456
    ja lel_resource
    lea rdi,[rbx+8]
    mov edx,1
    call lel_ensure_region
    mov rsi,[rbx+32]
    shl rsi,1
    jc lel_resource
    cmp rsi,134217728
    ja lel_resource
    lea rdi,[rbx+24]
    xor edx,edx
    call lel_ensure_region
    jmp lel_pure_again
lel_pure_return:
    mov [rbx+40],rax
    mov rsi,[rbx+24]
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret

lel_child_read:
    lea rbx,[r15+lel_SLOTS+64]
    lea rdi,[rbx+8]
    mov esi,4096
    mov edx,1
    call lel_ensure_region
    lea rdi,[rbx+24]
    mov esi,4096
    xor edx,edx
    call lel_ensure_region
    mov rax,[r15+lel_CHILDREQ]
    mov [r15+lel_READCTX],rax
    mov rax,[r15+lel_CHILDREQLEN]
    mov [r15+lel_READCTX+48],rax
    mov rax,[rbx+8]
    mov [r15+lel_READCTX+16],rax
    mov rax,[rbx+16]
    mov [r15+lel_READCTX+24],rax
    mov rax,[rbx+24]
    mov [r15+lel_READCTX+32],rax
    mov rax,[rbx+32]
    mov [r15+lel_READCTX+40],rax
    mov rax,[r15+lel_META_POINTER]
    mov [r15+lel_READCTX+64],rax
    mov [r15+lel_READCTX+96],r15
    mov rax,[rbx]
    mov [r15+lel_READCTX+80],rax
    lea rdi,[r15+lel_READCTX]
    call lel_local_read_run
    mov rcx,[r15+lel_READCTX+16]
    mov [rbx+8],rcx
    mov rcx,[r15+lel_READCTX+24]
    mov [rbx+16],rcx
    mov rcx,[r15+lel_READCTX+32]
    mov [rbx+24],rcx
    mov [r15+lel_CHILDOUT],rcx
    mov rcx,[r15+lel_READCTX+40]
    mov [rbx+32],rcx
    jmp lel_child_completed

lel_child_key:
    lea rbx,[r15+lel_SLOTS+128]
    lea rdi,[rbx+8]
    mov esi,1056768
    mov edx,1
    call lel_ensure_region
    lea rdi,[rbx+24]
    mov esi,4096
    xor edx,edx
    call lel_ensure_region
    mov rax,[r15+lel_CHILDREQ]
    mov [r15+lel_KEYCTX],rax
    mov rax,[r15+lel_CHILDREQLEN]
    mov [r15+lel_KEYCTX+48],rax
    mov rax,[rbx+8]
    mov [r15+lel_KEYCTX+16],rax
    mov rax,[rbx+16]
    mov [r15+lel_KEYCTX+24],rax
    mov rax,[rbx+24]
    mov [r15+lel_KEYCTX+32],rax
    mov rax,[rbx+32]
    mov [r15+lel_KEYCTX+40],rax
    mov rax,[r15+lel_SECURE]
    mov [r15+lel_KEYCTX+64],rax
    mov qword ptr [r15+lel_KEYCTX+72],-1
    mov qword ptr [r15+lel_KEYCTX+80],-1
    mov rax,[rbx]
    mov [r15+lel_KEYCTX+96],rax
    mov [r15+lel_KEYCTX+104],r15
    lea rdi,[r15+lel_KEYCTX]
    call lel_key_run
    mov rcx,[r15+lel_KEYCTX+16]
    mov [rbx+8],rcx
    mov rcx,[r15+lel_KEYCTX+24]
    mov [rbx+16],rcx
    mov rcx,[r15+lel_KEYCTX+32]
    mov [rbx+24],rcx
    mov [r15+lel_CHILDOUT],rcx
    mov rcx,[r15+lel_KEYCTX+40]
    mov [rbx+32],rcx
    jmp lel_child_completed

lel_child_atomic:
    lea rbx,[r15+lel_SLOTS+448]
    mov rax,[r15+lel_CHILDREQ]
    cmp qword ptr [r15+lel_CHILDREQLEN],64
    jb lel_contract
    mov rbp,[rax+16]
    mov rsi,rbp
    imul rsi,rsi,5
    jo lel_resource
    add rsi,4096
    jc lel_resource
    lea rdi,[rbx+8]
    mov edx,1
    call lel_ensure_region
    mov rsi,rbp
    imul rsi,rsi,3
    jo lel_resource
    add rsi,512
    jc lel_resource
    lea rdi,[rbx+24]
    xor edx,edx
    call lel_ensure_region
    call lel_atomic_run
    mov rcx,[rbx+24]
    mov [r15+lel_CHILDOUT],rcx
    jmp lel_child_completed

lel_atomic_run:
    push rbp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub rsp,280
    lea rbp,[r15+lel_ATOMICCTX]
    mov [rbp],rbx
    mov [rbp+72],rsp
    mov rax,[r15+lel_CHILDREQ]
    mov [rbp+16],rax
    mov rax,[r15+lel_CHILDREQLEN]
    mov [rbp+24],rax
    mov r12,[rbx+8]
    mov r13,-1
    mov [rbp+80],r13
    mov rax,[rbx+16]
    mov [rbp+40],rax
    mov rdi,r12
    xor eax,eax
    mov ecx,128
    rep stosq
    mov rax,[r15+lel_META_POINTER]
    movzx eax,byte ptr [rax]
    cmp eax,2
    ja lel_atomic_worker_contract
    mov [r12+8],rax
    xor ebx,ebx
lel_atomic_invoke_policy:
    mov qword ptr [r12+136],0
    mov rax,[rbp]
    mov rdi,[rbp+16]
    mov rsi,[rbp+24]
    mov rdx,[rax+24]
    mov rcx,[rax+32]
    mov r8,r12
    mov r9,[rbp+40]
    call qword ptr [rax]
    mov edx,eax
    cmp rax,rdx
    jne lel_atomic_worker_contract
    cmp eax,0xfffffff0
    jne lel_atomic_policy_done
    mov rax,0x3158465441414948
    cmp [r12+256],rax
    jne lel_atomic_worker_contract
    inc rbx
    jz lel_atomic_worker_contract
    cmp [r12+264],rbx
    jne lel_atomic_worker_contract
    cmp [r12+144],rbx
    jne lel_atomic_worker_contract
    mov r14,[r12+272]
    cmp [r12],r14
    jne lel_atomic_worker_contract
    cmp r14,1
    jb lel_atomic_worker_contract
    cmp r14,11
    ja lel_atomic_worker_contract
    mov rax,[r12+304]
    or rax,[r12+312]
    or rax,[r12+320]
    or rax,[r12+328]
    or rax,[r12+336]
    or rax,[r12+344]
    jnz lel_atomic_worker_contract
    cmp qword ptr [r12+56],1024
    jne lel_atomic_worker_contract
    mov rax,[rbp+24]
    sub rax,64
    cmp [r12+40],rax
    ja lel_atomic_worker_contract
    mov rax,[r12+40]
    add rax,1025
    jc lel_atomic_worker_contract
    cmp rax,[r12+64]
    jne lel_atomic_worker_contract
    add rax,[r12+72]
    jc lel_atomic_worker_contract
    cmp rax,[rbp+40]
    jae lel_atomic_worker_contract
    cmp byte ptr [r12+rax],0
    jne lel_atomic_worker_contract
    mov rax,[r12+40]
    cmp byte ptr [r12+rax+1024],0
    jne lel_atomic_worker_contract
    cmp r14,1
    je lel_atomic_stat_path
    cmp r14,2
    je lel_atomic_stat_probe
    cmp r14,3
    je lel_atomic_stat_path
    cmp r14,10
    je lel_atomic_stat_path
    cmp r14,11
    je lel_atomic_stat_probe_fallback
    cmp r14,4
    je lel_atomic_open_temp
    cmp r14,5
    je lel_atomic_write_temp
    cmp r14,6
    je lel_atomic_close_temp
    cmp r14,7
    je lel_atomic_chmod_temp
    cmp r14,8
    je lel_atomic_rename_temp
    jmp lel_atomic_unlink_temp
lel_atomic_policy_done:
    cmp r13,-1
    jne lel_atomic_worker_contract
    mov rcx,[r12+8]
    cmp rcx,2
    ja lel_atomic_worker_contract
    mov rdx,[r15+lel_META_POINTER]
    mov [rdx],cl
    add rsp,280
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret
lel_atomic_worker_contract:
    mov rsp,[rbp+72]
    mov rdi,r13
    mov r13,-1
    mov [rbp+80],r13
    test rdi,rdi
    js lel_contract
    mov eax,3
    syscall
    jmp lel_contract

/* The existing file owner chooses NUL admission and the one remove_file
   attempt. This fixed adapter owns only its admitted private unlink effect. */
lel_child_mkdir:
    mov rbx,[r15+lel_CHILDREQ]
    cmp qword ptr [r15+lel_CHILDREQLEN],64
    jb lel_contract
    mov rax,0x3130514b4d485348
    cmp [rbx],rax
    jne lel_contract
    cmp qword ptr [rbx+8],1
    jne lel_contract
    cmp qword ptr [rbx+16],0
    jne lel_contract
    mov rcx,[r15+lel_CHILDREQLEN]
    sub rcx,64
    cmp [rbx+24],rcx
    jne lel_contract
    mov rax,[rbx+32]
    or rax,[rbx+40]
    or rax,[rbx+48]
    or rax,[rbx+56]
    jnz lel_contract
    lea rdi,[r15+lel_MKREQ]
    mov rsi,[r15+lel_CHILDREQLEN]
    xor edx,edx
    call lel_ensure_region
    mov rdi,[r15+lel_MKREQ]
    mov rsi,[r15+lel_MKREQCAP]
    mov edx,3
    call lel_protection
    mov rdi,[r15+lel_MKREQ]
    mov rsi,[r15+lel_CHILDREQ]
    mov rcx,[r15+lel_CHILDREQLEN]
    mov [r15+lel_MKLEN],rcx
    rep movsb
    mov rax,[r15+lel_META_POINTER]
    movzx eax,byte ptr [rax]
    cmp eax,2
    ja lel_contract
    mov rbx,[r15+lel_MKREQ]
    mov [rbx+16],rax
    mov rax,[rbx+24]
    inc rax
    jz lel_resource
    mov ecx,10
    mul rcx
    test rdx,rdx
    jnz lel_resource
    add rax,512
    jc lel_resource
    cmp rax,268435456
    ja lel_resource
    lea rdi,[r15+lel_MKWORK]
    mov rsi,rax
    xor edx,edx
    call lel_ensure_region
    mov rdi,[r15+lel_MKWORK]
    mov rcx,[r15+lel_MKWORKCAP]
    xor eax,eax
    rep stosb
    lea rdi,[r15+lel_SLOTS+640+24]
    mov esi,4096
    xor edx,edx
    call lel_ensure_region
    mov qword ptr [r15+lel_MKSEQ],0
lel_mkdir_invoke:
    mov rdi,[r15+lel_MKREQ]
    mov rsi,[r15+lel_MKREQCAP]
    mov edx,1
    call lel_protection
    mov rdi,[r15+lel_MKREQ]
    mov rsi,[r15+lel_MKLEN]
    mov rdx,[r15+lel_SLOTS+640+24]
    mov rcx,[r15+lel_SLOTS+640+32]
    mov r8,[r15+lel_MKWORK]
    mov r9,[r15+lel_MKWORKCAP]
    call qword ptr [r15+lel_SLOTS+640]
    mov edx,eax
    cmp rax,rdx
    jne lel_contract
    cmp eax,32
    je lel_mkdir_complete
    cmp eax,0xfffffffd
    jne lel_contract
    call lel_mkdir_effect
    mov rdi,[r15+lel_MKREQ]
    mov rsi,[r15+lel_MKREQCAP]
    mov edx,3
    call lel_protection
    mov rax,[r15+lel_MKREQ]
    mov qword ptr [rax+8],2
    mov qword ptr [rax+16],0
    jmp lel_mkdir_invoke
lel_mkdir_complete:
    mov rsi,[r15+lel_SLOTS+640+24]
    mov rax,0x3130524b4d485348
    cmp [rsi],rax
    jne lel_contract
    cmp qword ptr [rsi+24],2
    ja lel_contract
    mov rax,[rsi+24]
    mov rdx,[r15+lel_META_POINTER]
    mov [rdx],al
    mov [r15+lel_CHILDOUT],rsi
    mov eax,32
    jmp lel_child_completed
lel_round_capacity:
    mov rax,rdi
    add rax,4095
    jc lel_resource
    and rax,-4096
    test rax,rax
    jnz lel_rounded
    mov eax,4096
lel_rounded:
    ret
lel_allocate_guarded:
    push rbx
    mov rbx,rdi
    mov rsi,rdi
    add rsi,4096
    jc lel_resource
    xor edi,edi
    mov edx,3
    mov r10d,0x22
    mov r8,-1
    xor r9d,r9d
    mov eax,9
    syscall
    cmp rax,-4095
    jae lel_resource
    push rax
    lea rdi,[rax+rbx]
    mov esi,4096
    xor edx,edx
    mov eax,10
    syscall
    test rax,rax
    jnz lel_callable_guard_failed
    pop rax
    pop rbx
    ret
lel_callable_guard_failed:
    pop rdi
    lea rsi,[rbx+4096]
    mov eax,11
    syscall
    pop rbx
    jmp lel_infrastructure
lel_ensure_region:
    push rbx
    push rbp
    push r12
    push r13
    mov rbx,rdi
    mov ebp,edx
    mov rax,[rbx]
    test rax,rax
    jz lel_ensure_allocate
    cmp rsi,[rbx+8]
    jbe lel_ensure_done
lel_ensure_allocate:
    mov rdi,rsi
    call lel_round_capacity
    mov r12,rax
    mov rdi,rax
    call lel_allocate_guarded
    mov r13,rax
    cmp qword ptr [rbx],0
    je lel_ensure_publish
    test ebp,ebp
    jz lel_ensure_retire
    mov rdi,r13
    mov rsi,[rbx]
    mov rcx,[rbx+8]
    rep movsb
lel_ensure_retire:
    mov rdi,[rbx]
    mov rsi,[rbx+8]
    add rsi,4096
    mov eax,11
    syscall
    test rax,rax
    jnz lel_infrastructure
lel_ensure_publish:
    mov [rbx],r13
    mov [rbx+8],r12
    mov rax,r13
lel_ensure_done:
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret
lel_protection:
    mov eax,10
    syscall
    test rax,rax
    jnz lel_infrastructure
    ret
lel_contract:
    mov edi,70
    jmp lel_callable_abort
lel_resource:
    mov edi,71
    jmp lel_callable_abort
lel_infrastructure:
    mov edi,74
    jmp lel_callable_abort
lel_fatal_exit:
    mov r15,[r15+104]
    jmp lel_callable_abort
lel_atomic_stat_path:
    cmp r13, -1
    jne lel_atomic_worker_contract
    cmp qword ptr [r12 + 256 + 24], 1024
    jne lel_atomic_worker_contract
    mov rax, qword ptr [r12 + 40]
    cmp qword ptr [r12 + 256 + 32], rax
    jne lel_atomic_worker_contract
    cmp qword ptr [r12 + 256 + 40], 0
    jne lel_atomic_worker_contract
    lea rdi, [r12 + 1024]
    mov rcx, rax
    call lel_atomic_exact_cstring
    mov rdi, rsp
    xor eax, eax
    mov ecx, 32
    rep stosq
    mov edi, -100
    lea rsi, [r12 + 1024]
    cmp r14, 1
    jne lel_atomic_stat_fallback
    xor edx, edx
    mov r10d, 0xfff
    mov r8, rsp
    mov eax, 332
    syscall
    test rax, rax
    js lel_atomic_effect_error
    movzx eax, word ptr [rsp + 28]
    mov qword ptr [r12 + 256 + 72], rax
    jmp lel_atomic_acknowledge
lel_atomic_stat_fallback:
    mov rdx, rsp
    xor r10d, r10d
    mov eax, 262
    syscall
    test rax, rax
    js lel_atomic_effect_error
    mov eax, dword ptr [rsp + 24]
    mov qword ptr [r12 + 256 + 72], rax
    jmp lel_atomic_acknowledge

lel_atomic_stat_probe:
    cmp r13, -1
    jne lel_atomic_worker_contract
    mov rax, qword ptr [r12 + 256 + 24]
    or rax, qword ptr [r12 + 256 + 32]
    or rax, qword ptr [r12 + 256 + 40]
    jnz lel_atomic_worker_contract
    xor edi, edi
    xor esi, esi
    xor edx, edx
    mov r10d, 0xfff
    xor r8d, r8d
    mov eax, 332
    syscall
    test rax, rax
    js lel_atomic_effect_error
    jmp lel_atomic_acknowledge

lel_atomic_stat_probe_fallback:
    cmp r13, -1
    jne lel_atomic_worker_contract
    mov rax, qword ptr [r12 + 256 + 24]
    or rax, qword ptr [r12 + 256 + 32]
    or rax, qword ptr [r12 + 256 + 40]
    jnz lel_atomic_worker_contract
    xor edi, edi
    xor esi, esi
    mov rdx, rsp
    xor r10d, r10d
    mov eax, 262
    syscall
    test rax, rax
    js lel_atomic_effect_error
    jmp lel_atomic_worker_contract

lel_atomic_temp_arguments:
    mov rax, qword ptr [r12 + 64]
    cmp qword ptr [r12 + 256 + 24], rax
    jne lel_atomic_worker_contract
    mov rcx, qword ptr [r12 + 72]
    cmp qword ptr [r12 + 256 + 32], rcx
    jne lel_atomic_worker_contract
    lea rdi, [r12 + rax]
    call lel_atomic_exact_cstring
    mov rax, qword ptr [r12 + 64]
    lea rdi, [r12 + rax]
    ret
lel_atomic_open_temp:
    cmp r13, -1
    jne lel_atomic_worker_contract
    cmp qword ptr [r12 + 256 + 40], 0
    jne lel_atomic_worker_contract
    call lel_atomic_temp_arguments
    mov rsi, rdi
    mov edi, -100
    mov edx, 0x80241
    mov r10d, 0666
    mov eax, 257
    syscall
    test rax, rax
    js lel_atomic_effect_error
    cmp rax, 0x7fffffff
    ja lel_atomic_worker_contract
    mov r13, rax
    mov [rbp+80],r13
    mov qword ptr [r12 + 256 + 72], 1
    jmp lel_atomic_acknowledge

lel_atomic_write_temp:
    cmp r13, 0
    jl lel_atomic_worker_contract
    cmp qword ptr [r12 + 256 + 24], 1
    jne lel_atomic_worker_contract
    mov rax, qword ptr [r12 + 40]
    add rax, 64
    add rax, qword ptr [r12 + 112]
    jc lel_atomic_worker_contract
    cmp rax, qword ptr [r12 + 256 + 32]
    jne lel_atomic_worker_contract
    cmp rax, [rbp + 24]
    jae lel_atomic_worker_contract
    mov rdx, [rbp + 24]
    sub rdx, rax
    cmp rdx, qword ptr [r12 + 256 + 40]
    jne lel_atomic_worker_contract
    mov rsi, [rbp + 16]
    add rsi, rax
    mov rdi, r13
    mov eax, 1
    syscall
    test rax, rax
    js lel_atomic_effect_error
    mov qword ptr [r12 + 256 + 56], rax
    jmp lel_atomic_acknowledge

lel_atomic_close_temp:
    cmp r13, 0
    jl lel_atomic_worker_contract
    cmp qword ptr [r12 + 256 + 24], 1
    jne lel_atomic_worker_contract
    mov rax, qword ptr [r12 + 256 + 32]
    or rax, qword ptr [r12 + 256 + 40]
    jnz lel_atomic_worker_contract
    mov rdi, r13
    mov r13, -1
    mov [rbp+80],r13
    mov eax, 3
    syscall
    test rax, rax
    js lel_atomic_effect_error
    jmp lel_atomic_acknowledge

lel_atomic_chmod_temp:
    cmp r13, -1
    jne lel_atomic_worker_contract
    mov rax, qword ptr [r12 + 80]
    mov ecx, 0xffffffff
    cmp rax, rcx
    ja lel_atomic_worker_contract
    cmp qword ptr [r12 + 256 + 40], rax
    jne lel_atomic_worker_contract
    call lel_atomic_temp_arguments
    mov esi, dword ptr [r12 + 80]
    mov eax, 90
    syscall
    test rax, rax
    js lel_atomic_effect_error
    jmp lel_atomic_acknowledge

lel_atomic_rename_temp:
    cmp r13, -1
    jne lel_atomic_worker_contract
    mov rax, qword ptr [r12 + 64]
    cmp qword ptr [r12 + 256 + 24], rax
    jne lel_atomic_worker_contract
    cmp qword ptr [r12 + 256 + 32], 1024
    jne lel_atomic_worker_contract
    cmp qword ptr [r12 + 256 + 40], 0
    jne lel_atomic_worker_contract
    lea rdi, [r12 + rax]
    mov rcx, qword ptr [r12 + 72]
    call lel_atomic_exact_cstring
    lea rdi, [r12 + 1024]
    mov rcx, qword ptr [r12 + 40]
    call lel_atomic_exact_cstring
    mov rax, qword ptr [r12 + 64]
    lea rdi, [r12 + rax]
    lea rsi, [r12 + 1024]
    mov eax, 82
    syscall
    test rax, rax
    js lel_atomic_effect_error
    jmp lel_atomic_acknowledge

lel_atomic_unlink_temp:
    cmp r13, -1
    jne lel_atomic_worker_contract
    cmp qword ptr [r12 + 256 + 40], 0
    jne lel_atomic_worker_contract
    call lel_atomic_temp_arguments
    mov eax, 87
    syscall
    test rax, rax
    js lel_atomic_effect_error
    jmp lel_atomic_acknowledge

lel_atomic_effect_error:
    cmp rax, -4095
    jb lel_atomic_worker_contract
    neg rax
    mov qword ptr [r12 + 256 + 64], rax
lel_atomic_acknowledge:
    mov qword ptr [r12 + 256 + 80], 1
    jmp lel_atomic_invoke_policy

lel_atomic_exact_cstring:
    xor eax, eax
    test rcx, rcx
    jz lel_atomic_exact_end
    repne scasb
    je lel_atomic_worker_contract
lel_atomic_exact_end:
    cmp byte ptr [rdi], 0
    jne lel_atomic_worker_contract
    ret


lel_local_read_run:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp, 520
    mov r15, rdi
    cmp qword ptr [r15 + 72], 0
    jne lel_lr_contract_fail
    mov rdi, qword ptr [r15 + 48]
    add rdi, 1024
    jc lel_lr_memory_fail
    cmp rdi, qword ptr [r15 + 24]
    jbe lel_lr_read_workspace_ready
    mov ebp, 16
    call lel_lr_resize_buffer
lel_lr_read_workspace_ready:
    mov rdi, qword ptr [r15 + 16]
    xor eax, eax
    mov ecx, 128
    rep stosq
    mov qword ptr [r15 + 88], 0
lel_lr_read_invoke:
    mov rdi, qword ptr [r15]
    mov rsi, qword ptr [r15 + 48]
    mov rdx, qword ptr [r15 + 32]
    mov rcx, qword ptr [r15 + 40]
    mov r8, qword ptr [r15 + 16]
    mov r9, qword ptr [r15 + 24]
    call qword ptr [r15 + 80]
    mov edx, eax
    cmp rax, rdx
    jne lel_lr_contract_fail
    mov rbx, qword ptr [r15 + 16]
    cmp eax, 0xffffffef
    je lel_lr_read_grow
    cmp eax, 0xffffffe8
    je lel_lr_read_cache
    cmp eax, 0xfffffff0
    je lel_lr_read_effect
    cmp eax, 0xfffffff6
    je lel_lr_allocation_abort
    cmp eax, 0xffffffff
    je lel_lr_read_refused
    cmp eax, 0xfffffffe
    je lel_lr_read_refused
    cmp eax, 0xfffffff9
    je lel_lr_contract_fail
    cmp rax, qword ptr [r15 + 40]
    ja lel_lr_contract_fail
    cmp eax, 32
    jb lel_lr_contract_fail
    cmp qword ptr [rbx], 100
    jne lel_lr_contract_fail
    cmp qword ptr [r15 + 72], 0
    jne lel_lr_contract_fail
    mov rdx, qword ptr [r15 + 32]
    mov rcx, 0x3130304f524c4648
    cmp qword ptr [rdx], rcx
    jne lel_lr_contract_fail
    lea rcx, [rax - 32]
    cmp qword ptr [rdx + 24], rcx
    jne lel_lr_contract_fail
    jmp lel_lr_read_return
lel_lr_read_refused:
    mov dword ptr [rsp + 504], eax
    call lel_lr_cleanup
    mov eax, dword ptr [rsp + 504]
lel_lr_read_return:
    add rsp, 520
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

lel_lr_read_grow:
    cmp qword ptr [rbx], 90
    jne lel_lr_contract_fail
    mov rdi, qword ptr [rbx + 200]
    mov rax, qword ptr [rbx + 216]
    cmp rax, 1
    je lel_lr_read_grow_work
    cmp rax, 2
    jne lel_lr_contract_fail
    cmp qword ptr [rbx + 208], 100
    jne lel_lr_contract_fail
    cmp qword ptr [r15 + 72], 0
    jne lel_lr_contract_fail
    cmp rdi, 1073741824
    ja lel_lr_read_resource
    mov ebp, 32
    jmp lel_lr_read_grow_do
lel_lr_read_grow_work:
    cmp rdi, 1207959552
    ja lel_lr_read_resource
    mov rax, qword ptr [rbx + 208]
    cmp rax, 20
    je lel_lr_read_grow_work_valid
    cmp rax, 23
    je lel_lr_read_grow_work_valid
    cmp rax, 24
    jne lel_lr_contract_fail
lel_lr_read_grow_work_valid:
    mov rax, qword ptr [rbx + 56]
    add rax, qword ptr [rbx + 152]
    jc lel_lr_contract_fail
    cmp rdi, rax
    jne lel_lr_contract_fail
    mov ebp, 16
lel_lr_read_grow_do:
    cmp rdi, qword ptr [r15 + rbp + 8]
    jbe lel_lr_contract_fail
    call lel_lr_resize_buffer
    jmp lel_lr_read_invoke
lel_lr_read_resource:
    mov eax, 0xfffffffe
    jmp lel_lr_read_refused

lel_lr_read_cache:
    lea r12, [rbx + 640]
    mov rax, 0x3130304341544d48
    cmp qword ptr [r12], rax
    jne lel_lr_contract_fail
    call lel_lr_sequence_admit
    mov r13, qword ptr [r12 + 16]
    cmp r13, 1
    ja lel_lr_contract_fail
    mov rax, qword ptr [r12 + 32]
    or rax, qword ptr [r12 + 40]
    jnz lel_lr_contract_fail
    mov rax, qword ptr [rbx]
    cmp rax, 60
    jb lel_lr_contract_fail
    cmp rax, 63
    ja lel_lr_contract_fail
    cmp rax, 62
    jb lel_lr_read_cache_load
    cmp r13, 1
    jne lel_lr_contract_fail
    mov rax, qword ptr [r12 + 24]
    cmp rax, qword ptr [rbx + 104]
    jne lel_lr_contract_fail
    cmp rax, 1
    jb lel_lr_contract_fail
    cmp rax, 2
    ja lel_lr_contract_fail
    mov rdx, qword ptr [r15 + 64]
    mov byte ptr [rdx], al
    xor eax, eax
    jmp lel_lr_read_cache_complete
lel_lr_read_cache_load:
    test r13, r13
    jnz lel_lr_contract_fail
    cmp qword ptr [r12 + 24], 0
    jne lel_lr_contract_fail
    mov rdx, qword ptr [r15 + 64]
    movzx eax, byte ptr [rdx]
    cmp eax, 2
    ja lel_lr_contract_fail
lel_lr_read_cache_complete:
    mov qword ptr [r12 + 56], rax
    mov qword ptr [r12 + 80], 1
    jmp lel_lr_read_invoke

lel_lr_read_effect:
    lea r12, [rbx + 256]
    mov rax, 0x58464f49524c4648
    cmp qword ptr [r12], rax
    jne lel_lr_contract_fail
    call lel_lr_sequence_admit
    mov r14, qword ptr [r12 + 16]
    mov rax, qword ptr [rbx]
    cmp r14, 8
    jne lel_lr_read_effect_phase
    cmp rax, 21
    je lel_lr_read_effect_ready
    cmp rax, 22
    jne lel_lr_contract_fail
    jmp lel_lr_read_effect_ready
lel_lr_read_effect_phase:
    cmp rax, r14
    jne lel_lr_contract_fail
lel_lr_read_effect_ready:
    mov rdi, rsp
    xor eax, eax
    mov ecx, 32
    rep stosq
    cmp r14, 1
    je lel_lr_read_path_statx
    cmp r14, 2
    je lel_lr_read_probe_statx
    cmp r14, 3
    je lel_lr_read_path_stat
    cmp r14, 4
    je lel_lr_read_open
    cmp r14, 5
    je lel_lr_read_fd_statx
    cmp r14, 7
    je lel_lr_read_fd_stat
    cmp r14, 8
    je lel_lr_read_bytes
    cmp r14, 9
    je lel_lr_read_close
    cmp r14, 10
    je lel_lr_read_path_stat
    cmp r14, 11
    je lel_lr_read_fd_statat
    cmp r14, 12
    je lel_lr_read_probe_stat
    jmp lel_lr_contract_fail
lel_lr_read_path_statx:
    call lel_lr_path_admit
    mov rsi, rax
    mov rdi, -100
    xor edx, edx
    mov r10d, 4095
    mov r8, rsp
    mov eax, 332
    syscall
    mov ebp, 1
    jmp lel_lr_effect_done
lel_lr_read_path_stat:
    call lel_lr_path_admit
    mov rsi, rax
    mov rdi, -100
    mov rdx, rsp
    xor r10d, r10d
    mov eax, 262
    syscall
    mov ebp, 2
    jmp lel_lr_effect_done
lel_lr_read_probe_statx:
    call lel_lr_zero_arguments
    xor edi, edi
    xor esi, esi
    xor edx, edx
    mov r10d, 4095
    xor r8d, r8d
    mov eax, 332
    syscall
    xor ebp, ebp
    jmp lel_lr_effect_done
lel_lr_read_probe_stat:
    call lel_lr_zero_arguments
    xor edi, edi
    xor esi, esi
    xor edx, edx
    xor r10d, r10d
    mov eax, 262
    syscall
    xor ebp, ebp
    jmp lel_lr_effect_done
lel_lr_read_open:
    cmp qword ptr [r15 + 72], 0
    jne lel_lr_contract_fail
    call lel_lr_path_admit
    mov rsi, rax
    mov rdi, -100
    mov edx, 524288
    xor r10d, r10d
    mov eax, 257
    syscall
    mov ebp, 3
    jmp lel_lr_effect_done
lel_lr_read_fd_statx:
    call lel_lr_fd_only
    lea rsi, [rip + lel_lr_empty_path]
    mov edx, 4096
    mov r10d, 4095
    mov r8, rsp
    mov eax, 332
    syscall
    mov ebp, 1
    jmp lel_lr_effect_done
lel_lr_read_fd_statat:
    call lel_lr_fd_only
    lea rsi, [rip + lel_lr_empty_path]
    mov rdx, rsp
    mov r10d, 4096
    mov eax, 262
    syscall
    mov ebp, 2
    jmp lel_lr_effect_done
lel_lr_read_fd_stat:
    call lel_lr_fd_only
    mov rsi, rsp
    mov eax, 5
    syscall
    mov ebp, 2
    jmp lel_lr_effect_done
lel_lr_read_bytes:
    cmp qword ptr [r12 + 24], 1
    jne lel_lr_contract_fail
    mov rdi, qword ptr [r15 + 72]
    test rdi, rdi
    jz lel_lr_contract_fail
    dec rdi
    mov rsi, qword ptr [r12 + 32]
    mov rdx, qword ptr [r12 + 40]
    cmp qword ptr [rbx], 21
    jne lel_lr_read_regular
    cmp rsi, 768
    jne lel_lr_contract_fail
    cmp rdx, 32
    jne lel_lr_contract_fail
    jmp lel_lr_read_span_ready
lel_lr_read_regular:
    mov rax, qword ptr [rbx + 56]
    cmp rax, 1024
    jb lel_lr_contract_fail
    add rax, qword ptr [rbx + 160]
    jc lel_lr_contract_fail
    cmp rsi, rax
    jne lel_lr_contract_fail
    mov rax, qword ptr [rbx + 152]
    sub rax, qword ptr [rbx + 160]
    jc lel_lr_contract_fail
    cmp rax, qword ptr [rbx + 176]
    cmova rax, qword ptr [rbx + 176]
    cmp rdx, rax
    jne lel_lr_contract_fail
    test rdx, rdx
    jz lel_lr_contract_fail
lel_lr_read_span_ready:
    cmp rsi, qword ptr [r15 + 24]
    ja lel_lr_contract_fail
    mov rax, qword ptr [r15 + 24]
    sub rax, rsi
    cmp rdx, rax
    ja lel_lr_contract_fail
    add rsi, rbx
    xor eax, eax
    syscall
    mov ebp, 4
    jmp lel_lr_effect_done
lel_lr_read_close:
    call lel_lr_fd_only
    mov qword ptr [r15 + 72], 0
    mov eax, 3
    syscall
    xor ebp, ebp
lel_lr_effect_done:
    cmp rax, -4095
    jae lel_lr_effect_error
    cmp ebp, 1
    jne lel_lr_effect_stat64
    test rax, rax
    jnz lel_lr_contract_fail
    mov rax, qword ptr [rsp + 40]
    mov qword ptr [r12 + 72], rax
    cmp qword ptr [rbx + 16], 3
    jne lel_lr_effect_completed
    movzx eax, word ptr [rsp + 28]
    mov qword ptr [r12 + 88], rax
    jmp lel_lr_effect_completed
lel_lr_effect_stat64:
    cmp ebp, 2
    jne lel_lr_effect_opened
    test rax, rax
    jnz lel_lr_contract_fail
    mov rax, qword ptr [rsp + 48]
    mov qword ptr [r12 + 72], rax
    cmp qword ptr [rbx + 16], 3
    jne lel_lr_effect_completed
    mov eax, dword ptr [rsp + 24]
    mov qword ptr [r12 + 88], rax
    jmp lel_lr_effect_completed
lel_lr_effect_opened:
    cmp ebp, 3
    jne lel_lr_effect_read
    inc rax
    jz lel_lr_contract_fail
    mov qword ptr [r15 + 72], rax
    mov qword ptr [r12 + 72], 1
    jmp lel_lr_effect_completed
lel_lr_effect_read:
    cmp ebp, 4
    jne lel_lr_effect_unit
    cmp rax, qword ptr [r12 + 40]
    ja lel_lr_contract_fail
    mov qword ptr [r12 + 56], rax
    jmp lel_lr_effect_completed
lel_lr_effect_unit:
    test rax, rax
    jnz lel_lr_contract_fail
    jmp lel_lr_effect_completed
lel_lr_effect_error:
    neg rax
    mov qword ptr [r12 + 64], rax
lel_lr_effect_completed:
    mov qword ptr [r12 + 80], 1
    jmp lel_lr_read_invoke

lel_lr_sequence_admit:
    mov rax, qword ptr [r15 + 88]
    inc rax
    jz lel_lr_contract_fail
    cmp qword ptr [r12 + 8], rax
    jne lel_lr_contract_fail
    cmp qword ptr [rbx + 72], rax
    jne lel_lr_contract_fail
    mov qword ptr [r15 + 88], rax
    mov rax, qword ptr [r12 + 48]
    or rax, qword ptr [r12 + 56]
    or rax, qword ptr [r12 + 64]
    or rax, qword ptr [r12 + 72]
    or rax, qword ptr [r12 + 80]
    or rax, qword ptr [r12 + 88]
    jnz lel_lr_contract_fail
    ret
lel_lr_path_admit:
    cmp qword ptr [r12 + 24], 1024
    jne lel_lr_contract_fail
    mov rcx, qword ptr [rbx + 48]
    cmp qword ptr [r12 + 32], rcx
    jne lel_lr_contract_fail
    cmp qword ptr [r12 + 40], 0
    jne lel_lr_contract_fail
    mov rax, qword ptr [r15 + 24]
    sub rax, 1024
    jc lel_lr_contract_fail
    cmp rcx, rax
    jae lel_lr_contract_fail
    lea rax, [rbx + 1024]
    cmp byte ptr [rax + rcx], 0
    jne lel_lr_contract_fail
    xor edx, edx
lel_lr_path_scan:
    cmp rdx, rcx
    je lel_lr_path_done
    cmp byte ptr [rax + rdx], 0
    je lel_lr_contract_fail
    inc rdx
    jmp lel_lr_path_scan
lel_lr_path_done:
    ret
lel_lr_zero_arguments:
    mov rax, qword ptr [r12 + 24]
    or rax, qword ptr [r12 + 32]
    or rax, qword ptr [r12 + 40]
    jnz lel_lr_contract_fail
    ret
lel_lr_fd_only:
    cmp qword ptr [r12 + 24], 1
    jne lel_lr_contract_fail
    mov rax, qword ptr [r12 + 32]
    or rax, qword ptr [r12 + 40]
    jnz lel_lr_contract_fail
    mov rdi, qword ptr [r15 + 72]
    test rdi, rdi
    jz lel_lr_contract_fail
    dec rdi
    ret

# rbp is the fixed context offset of (pointer, capacity), never input data.
lel_lr_resize_buffer:
    push r15
    mov rsi,rdi
    lea rdi,[r15+rbp]
    mov edx,1
    mov r15,[r15+96]
    call lel_ensure_region
    pop r15
    ret

lel_lr_cleanup:
    mov rdi, qword ptr [r15 + 72]
    mov qword ptr [r15 + 72], 0
    test rdi, rdi
    jz lel_lr_cleanup_done
    dec rdi
    mov eax, 3
    syscall
lel_lr_cleanup_done:
    ret
lel_lr_contract_fail:
    call lel_lr_cleanup
    mov edi, 70
    jmp lel_lr_child_exit
lel_lr_memory_fail:
    call lel_lr_cleanup
    mov edi, 71
    jmp lel_lr_child_exit
lel_lr_io_fail:
    call lel_lr_cleanup
    mov edi, 74
    jmp lel_lr_child_exit
lel_lr_allocation_abort:
    call lel_lr_cleanup
    mov edi, 134
lel_lr_child_exit:
    mov r15,[r15+96]
    jmp lel_callable_abort
lel_lr_empty_path:
    .byte 0

lel_key_run:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp, 520
    mov r15, rdi
    cmp qword ptr [r15 + 72], -1
    jne lel_key_contract_fail
    cmp qword ptr [r15 + 80], -1
    jne lel_key_contract_fail
    mov rdi, qword ptr [r15 + 16]
    xor eax, eax
    mov ecx, 128
    rep stosq
    mov rbx, qword ptr [r15 + 16]
    mov rax, qword ptr [r15 + 64]
    mov qword ptr [rbx + 176], rax
    mov qword ptr [r15 + 88], 0
lel_key_invoke:
    mov rdi, qword ptr [r15]
    mov rsi, qword ptr [r15 + 48]
    mov rdx, qword ptr [r15 + 32]
    mov rcx, qword ptr [r15 + 40]
    mov r8, qword ptr [r15 + 16]
    mov r9, qword ptr [r15 + 24]
    call qword ptr [r15 + 96]
    mov edx, eax
    cmp rax, rdx
    jne lel_key_contract_fail
    mov rbx, qword ptr [r15 + 16]
    cmp eax, 0xffffffef
    je lel_key_grow_workspace
    cmp eax, 0xffffffee
    je lel_key_grow_output
    cmp eax, 0xfffffff0
    je lel_key_admit_effect
    cmp eax, 0xffffffff
    je lel_key_refusal
    cmp eax, 0xfffffffe
    je lel_key_refusal
    cmp eax, 0xfffffff9
    je lel_key_contract_fail
    cmp eax, 32
    jb lel_key_contract_fail
    cmp rax, qword ptr [r15 + 40]
    ja lel_key_contract_fail
    cmp qword ptr [rbx], 100
    jne lel_key_contract_fail
    mov rdx, qword ptr [r15 + 32]
    mov rcx, 0x313030594b4c5248
    cmp qword ptr [rdx], rcx
    jne lel_key_contract_fail
    lea rcx, [rax - 32]
    cmp qword ptr [rdx + 16], rcx
    jne lel_key_contract_fail
    cmp qword ptr [rdx + 24], 0
    jne lel_key_contract_fail
    cmp qword ptr [r15 + 72], -1
    jne lel_key_contract_fail
    cmp qword ptr [r15 + 80], -1
    jne lel_key_contract_fail
    mov dword ptr [r15 + 56], eax
    jmp lel_key_done
lel_key_refusal:
    mov dword ptr [r15 + 56], eax
    call lel_key_cleanup
    jmp lel_key_done

lel_key_grow_workspace:
    mov rdi, qword ptr [rbx + 40]
    cmp rdi, qword ptr [rbx + 32]
    jbe lel_key_contract_fail
    mov rax, 0x1ffffffffffbfeff
    cmp rdi, rax
    ja lel_key_memory_fail
    shl rdi, 2
    add rdi, 1049600
    jc lel_key_memory_fail
    call lel_callable_key_round
    mov r12, rax
    cmp r12, qword ptr [r15 + 24]
    jbe lel_key_invoke
    mov rdi, r12
    call lel_callable_key_allocate
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
    jnz lel_key_io_fail
    jmp lel_key_invoke
lel_key_grow_output:
    mov rdi, qword ptr [rbx + 48]
    cmp rdi, qword ptr [r15 + 40]
    jbe lel_key_contract_fail
    mov rax, 0xffffffef
    cmp rdi, rax
    ja lel_key_contract_fail
    call lel_callable_key_round
    mov r12, rax
    mov rdi, r12
    call lel_callable_key_allocate
    mov r13, rax
    mov rdi, qword ptr [r15 + 32]
    mov rsi, qword ptr [r15 + 40]
    add rsi, 4096
    mov qword ptr [r15 + 32], r13
    mov qword ptr [r15 + 40], r12
    mov eax, 11
    syscall
    test rax, rax
    jnz lel_key_io_fail
    jmp lel_key_invoke

lel_key_admit_effect:
    mov rax, qword ptr [r15 + 48]
    cmp qword ptr [rbx + 8], rax
    jne lel_key_contract_fail
    mov rax, qword ptr [r15 + 40]
    cmp qword ptr [rbx + 16], rax
    jne lel_key_contract_fail
    mov rax, qword ptr [r15 + 24]
    cmp qword ptr [rbx + 24], rax
    jne lel_key_contract_fail
    mov rax, qword ptr [rbx + 40]
    or rax, qword ptr [rbx + 48]
    jnz lel_key_contract_fail
    mov rax, qword ptr [rbx + 32]
    cmp rax, 1024
    jb lel_key_contract_fail
    lea rcx, [rax - 1]
    test rcx, rax
    jnz lel_key_contract_fail
    cmp qword ptr [rbx + 96], rax
    jae lel_key_contract_fail
    mov rcx, 0x1ffffffffffbfeff
    cmp rax, rcx
    ja lel_key_contract_fail
    shl rax, 2
    add rax, 1049600
    jc lel_key_contract_fail
    cmp rax, qword ptr [r15 + 24]
    ja lel_key_contract_fail
    mov rax, 0x584659454b4c4648
    cmp qword ptr [rbx + 512], rax
    jne lel_key_contract_fail
    inc qword ptr [r15 + 88]
    jz lel_key_contract_fail
    mov rax, qword ptr [r15 + 88]
    cmp qword ptr [rbx + 520], rax
    jne lel_key_contract_fail
    cmp qword ptr [rbx + 56], rax
    jne lel_key_contract_fail
    mov rax, qword ptr [rbx + 568]
    or rax, qword ptr [rbx + 576]
    or rax, qword ptr [rbx + 584]
    or rax, qword ptr [rbx + 592]
    or rax, qword ptr [rbx + 600]
    or rax, qword ptr [rbx + 608]
    or rax, qword ptr [rbx + 616]
    or rax, qword ptr [rbx + 624]
    or rax, qword ptr [rbx + 632]
    jnz lel_key_contract_fail
    mov r14, qword ptr [rbx + 528]
    cmp r14, 1
    je lel_key_get_current
    cmp r14, 2
    je lel_key_read_link
    cmp r14, 3
    je lel_key_access_path
    cmp r14, 4
    je lel_key_access_path
    cmp r14, 5
    je lel_key_lstat_path
    cmp r14, 6
    je lel_key_access_path
    cmp r14, 7
    je lel_key_open_parent
    cmp r14, 8
    je lel_key_stat_descriptor
    cmp r14, 9
    je lel_key_close_descriptor
    cmp r14, 10
    je lel_key_get_flags
    cmp r14, 11
    je lel_key_set_cloexec
    cmp r14, 12
    je lel_key_directory_entries
    cmp r14, 13
    je lel_key_rewind_directory
    jmp lel_key_contract_fail

lel_key_get_current:
    cmp qword ptr [rbx], 10
    jne lel_key_contract_fail
    call lel_key_resolved_argument
    mov rdx, qword ptr [rbx + 552]
    or rdx, qword ptr [rbx + 560]
    jnz lel_key_contract_fail
    mov rsi, qword ptr [rbx + 544]
    cmp rsi, qword ptr [rbx + 152]
    jne lel_key_contract_fail
    cmp rsi, 1024
    jb lel_key_contract_fail
    cmp rsi, qword ptr [rbx + 32]
    ja lel_key_contract_fail
    mov eax, 79
    syscall
    jmp lel_key_value_completion

lel_key_read_link:
    cmp qword ptr [rbx], 3
    jne lel_key_contract_fail
    call lel_key_resolved_argument
    mov rcx, qword ptr [rbx + 544]
    cmp rcx, qword ptr [rbx + 96]
    jne lel_key_contract_fail
    call lel_key_cstring
    mov rax, qword ptr [rbx + 32]
    lea rax, [rax + rax + 1024]
    cmp qword ptr [rbx + 552], rax
    jne lel_key_contract_fail
    lea rsi, [rbx + rax]
    mov rdx, qword ptr [rbx + 144]
    cmp rdx, 1024
    jb lel_key_contract_fail
    dec rdx
    cmp rdx, qword ptr [rbx + 560]
    jne lel_key_contract_fail
    cmp rdx, qword ptr [rbx + 32]
    jae lel_key_contract_fail
    mov eax, 89
    syscall
    jmp lel_key_value_completion

lel_key_access_path:
    cmp qword ptr [rbx], 4
    jne lel_key_contract_fail
    call lel_key_resolved_argument
    mov rcx, qword ptr [rbx + 96]
    inc rcx
    cmp rcx, qword ptr [rbx + 32]
    jae lel_key_contract_fail
    cmp rcx, qword ptr [rbx + 544]
    jne lel_key_contract_fail
    call lel_key_cstring
    mov rax, qword ptr [rbx + 552]
    or rax, qword ptr [rbx + 560]
    jnz lel_key_contract_fail
    mov rsi, rdi
    mov edi, -100
    xor edx, edx
    mov r10d, 512
    mov eax, 439
    cmp r14, 3
    je lel_key_access_go
    cmp r14, 4
    jne lel_key_stat_access
    cmp qword ptr [r15 + 64], 0
    jne lel_key_contract_fail
    mov eax, 269
lel_key_access_go:
    syscall
    jmp lel_key_zero_completion
lel_key_stat_access:
    cmp qword ptr [r15 + 64], 1
    jne lel_key_contract_fail
    xor r10d, r10d
    jmp lel_key_stat_at

lel_key_lstat_path:
    mov rax, qword ptr [rbx]
    cmp rax, 12
    je lel_key_lstat_fixed
    cmp rax, 13
    je lel_key_lstat_fixed
    cmp rax, 24
    jne lel_key_contract_fail
    mov rax, qword ptr [rbx + 32]
    lea rax, [rax * 4 + 1024]
    add rax, qword ptr [rbx + 368]
    jc lel_key_contract_fail
    cmp rax, qword ptr [rbx + 536]
    jne lel_key_contract_fail
    mov rcx, qword ptr [rbx + 376]
    cmp rcx, qword ptr [rbx + 544]
    jne lel_key_contract_fail
    mov rdx, qword ptr [rbx + 552]
    cmp rdx, qword ptr [rbx + 160]
    jne lel_key_contract_fail
    jmp lel_key_lstat_arguments
lel_key_lstat_fixed:
    mov rax, qword ptr [rbx + 32]
    lea rax, [rax + rax + 1024]
    cmp rax, qword ptr [rbx + 536]
    jne lel_key_contract_fail
    mov ecx, 1
    cmp qword ptr [rbx + 544], 1
    jne lel_key_contract_fail
    cmp qword ptr [rbx + 552], 0
    jne lel_key_contract_fail
    xor edx, edx
    cmp qword ptr [rbx], 12
    jne lel_key_lstat_root
    cmp byte ptr [rbx + rax], 46
    jne lel_key_contract_fail
    jmp lel_key_lstat_arguments
lel_key_lstat_root:
    cmp byte ptr [rbx + rax], 47
    jne lel_key_contract_fail
lel_key_lstat_arguments:
    cmp qword ptr [rbx + 560], 0
    jne lel_key_contract_fail
    lea rdi, [rbx + rax]
    call lel_key_cstring
    mov rsi, rdi
    mov edi, -100
    test rdx, rdx
    jz lel_key_lstat_cwd
    call lel_key_descriptor
lel_key_lstat_cwd:
    mov r10d, 256
lel_key_stat_at:
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
    jmp lel_key_stat_completion

lel_key_open_parent:
    cmp qword ptr [rbx], 15
    jne lel_key_contract_fail
    mov rax, qword ptr [rbx + 552]
    or rax, qword ptr [rbx + 560]
    jnz lel_key_contract_fail
    mov r12, qword ptr [rbx + 536]
    cmp r12, 1
    jb lel_key_contract_fail
    cmp r12, 2
    ja lel_key_contract_fail
    cmp qword ptr [r15 + r12 * 8 + 64], -1
    jne lel_key_contract_fail
    mov rdx, qword ptr [rbx + 544]
    cmp rdx, qword ptr [rbx + 160]
    jne lel_key_contract_fail
    cmp rdx, r12
    je lel_key_contract_fail
    mov edi, -100
    test rdx, rdx
    jz lel_key_open_parent_cwd
    call lel_key_descriptor
lel_key_open_parent_cwd:
    lea rsi, [rip + lel_key_parent_name]
    xor edx, edx
    xor r10d, r10d
    mov eax, 257
    syscall
    test rax, rax
    js lel_key_error_completion
    cmp rax, 0x7fffffff
    ja lel_key_contract_fail
    mov qword ptr [r15 + r12 * 8 + 64], rax
    mov rax, r12
    jmp lel_key_value_completion

lel_key_stat_descriptor:
    mov rax, qword ptr [rbx]
    cmp rax, 16
    je lel_key_stat_descriptor_phase
    cmp rax, 18
    jne lel_key_contract_fail
lel_key_stat_descriptor_phase:
    call lel_key_zero_trailing_args
    mov rdx, qword ptr [rbx + 536]
    cmp rdx, qword ptr [rbx + 168]
    jne lel_key_contract_fail
    call lel_key_descriptor
    mov r13, rdi
    mov rdi, rsp
    xor eax, eax
    mov ecx, 32
    rep stosq
    mov rdi, r13
    mov rsi, rsp
    mov eax, 5
    syscall
lel_key_stat_completion:
    test rax, rax
    js lel_key_error_completion
    test rax, rax
    jnz lel_key_contract_fail
    mov rax, qword ptr [rsp]
    mov qword ptr [rbx + 584], rax
    mov rax, qword ptr [rsp + 8]
    mov qword ptr [rbx + 592], rax
    mov eax, dword ptr [rsp + 24]
    mov qword ptr [rbx + 600], rax
    mov rax, qword ptr [rsp + 56]
    mov qword ptr [rbx + 616], rax
    jmp lel_key_acknowledge

lel_key_close_descriptor:
    mov rax, qword ptr [rbx]
    cmp rax, 17
    je lel_key_close_phase
    cmp rax, 27
    je lel_key_close_phase
    cmp rax, 29
    jne lel_key_contract_fail
lel_key_close_phase:
    call lel_key_zero_trailing_args
    mov rdx, qword ptr [rbx + 536]
    call lel_key_descriptor
    mov qword ptr [r15 + rdx * 8 + 64], -1
    mov eax, 3
    syscall
    jmp lel_key_zero_completion

lel_key_get_flags:
    cmp qword ptr [rbx], 19
    jne lel_key_contract_fail
    call lel_key_zero_trailing_args
    mov rdx, qword ptr [rbx + 536]
    cmp rdx, qword ptr [rbx + 168]
    jne lel_key_contract_fail
    call lel_key_descriptor
    mov esi, 3
    xor edx, edx
    mov eax, 72
    syscall
    jmp lel_key_value_completion
lel_key_set_cloexec:
    cmp qword ptr [rbx], 20
    jne lel_key_contract_fail
    call lel_key_zero_trailing_args
    mov rdx, qword ptr [rbx + 536]
    cmp rdx, qword ptr [rbx + 168]
    jne lel_key_contract_fail
    call lel_key_descriptor
    mov esi, 2
    mov edx, 1
    mov eax, 72
    syscall
    jmp lel_key_zero_completion

lel_key_directory_entries:
    cmp qword ptr [rbx], 22
    jne lel_key_contract_fail
    cmp qword ptr [rbx + 560], 0
    jne lel_key_contract_fail
    mov rax, qword ptr [rbx + 32]
    lea rax, [rax * 4 + 1024]
    cmp rax, qword ptr [rbx + 544]
    jne lel_key_contract_fail
    mov r12, qword ptr [rbx + 552]
    cmp r12, 32768
    jb lel_key_contract_fail
    cmp r12, 1048576
    ja lel_key_contract_fail
    cmp r12, qword ptr [rbx + 336]
    jne lel_key_contract_fail
    lea rsi, [rbx + rax]
    mov rdx, qword ptr [rbx + 536]
    cmp rdx, qword ptr [rbx + 160]
    jne lel_key_contract_fail
    call lel_key_descriptor
    mov rdx, r12
    mov eax, 217
    syscall
    jmp lel_key_value_completion
lel_key_rewind_directory:
    cmp qword ptr [rbx], 23
    jne lel_key_contract_fail
    call lel_key_zero_trailing_args
    mov rdx, qword ptr [rbx + 536]
    cmp rdx, qword ptr [rbx + 160]
    jne lel_key_contract_fail
    call lel_key_descriptor
    xor esi, esi
    xor edx, edx
    mov eax, 8
    syscall
    jmp lel_key_value_completion

lel_key_resolved_argument:
    mov rax, qword ptr [rbx + 32]
    add rax, 1024
    cmp qword ptr [rbx + 536], rax
    jne lel_key_contract_fail
    lea rdi, [rbx + rax]
    ret
lel_key_zero_trailing_args:
    mov rax, qword ptr [rbx + 544]
    or rax, qword ptr [rbx + 552]
    or rax, qword ptr [rbx + 560]
    jnz lel_key_contract_fail
    ret
# logical slot in rdx -> real lel_key_descriptor in rdi, preserving other arguments.
lel_key_descriptor:
    cmp rdx, 1
    jb lel_key_contract_fail
    cmp rdx, 2
    ja lel_key_contract_fail
    mov rdi, qword ptr [r15 + rdx * 8 + 64]
    test rdi, rdi
    js lel_key_contract_fail
    ret
# Exact span containment and unique final NUL.  rdx is preserved for dirfd.
lel_key_cstring:
    mov rax, rdi
    sub rax, rbx
    jc lel_key_contract_fail
    cmp rax, qword ptr [r15 + 24]
    jae lel_key_contract_fail
    mov r11, qword ptr [r15 + 24]
    sub r11, rax
    cmp rcx, r11
    jae lel_key_contract_fail
    cmp byte ptr [rdi + rcx], 0
    jne lel_key_contract_fail
    xor eax, eax
lel_key_cstring_loop:
    cmp rax, rcx
    je lel_key_cstring_done
    cmp byte ptr [rdi + rax], 0
    je lel_key_contract_fail
    inc rax
    jmp lel_key_cstring_loop
lel_key_cstring_done:
    ret
lel_key_value_completion:
    test rax, rax
    js lel_key_error_completion
    mov qword ptr [rbx + 568], rax
    jmp lel_key_acknowledge
lel_key_zero_completion:
    test rax, rax
    js lel_key_error_completion
    test rax, rax
    jnz lel_key_contract_fail
    jmp lel_key_acknowledge
lel_key_error_completion:
    neg rax
    cmp rax, 4095
    ja lel_key_contract_fail
    mov qword ptr [rbx + 576], rax
lel_key_acknowledge:
    mov qword ptr [rbx + 608], 1
    jmp lel_key_invoke

lel_key_cleanup:
    mov rdi, qword ptr [r15 + 72]
    mov qword ptr [r15 + 72], -1
    test rdi, rdi
    js lel_key_cleanup_second
    mov eax, 3
    syscall
lel_key_cleanup_second:
    mov rdi, qword ptr [r15 + 80]
    mov qword ptr [r15 + 80], -1
    test rdi, rdi
    js lel_key_cleanup_done
    mov eax, 3
    syscall
lel_key_cleanup_done:
    ret
lel_key_done:
    mov eax, dword ptr [r15 + 56]
    add rsp, 520
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret
lel_key_contract_fail:
    call lel_key_cleanup
    mov edi, 70
    jmp lel_fatal_exit
lel_key_memory_fail:
    call lel_key_cleanup
    mov edi, 71
    jmp lel_fatal_exit
lel_key_io_fail:
    call lel_key_cleanup
    mov edi, 74
    jmp lel_fatal_exit
lel_key_parent_name:
    .asciz ".."

lel_callable_key_round:
    push r15
    mov r15,[r15+104]
    call lel_round_capacity
    pop r15
    ret
lel_callable_key_allocate:
    push r15
    mov r15,[r15+104]
    call lel_allocate_guarded
    pop r15
    ret

/* Same admitted mkdir/statx/stat effect, without fixture journaling. */
lel_mkdir_effect:
    push rbp
    push rbx
    sub rsp,272
    mov rbx,[r15+lel_MKWORK]
    lea rbp,[rbx+96]
    mov rax,0x3158464b4d485348
    cmp [rbp],rax
    jne lel_contract
    mov rax,[r15+lel_MKSEQ]
    inc rax
    jz lel_contract
    cmp [rbp+8],rax
    jne lel_contract
    cmp [rbx+80],rax
    jne lel_contract
    cmp qword ptr [rbx+72],1
    jne lel_contract
    mov [r15+lel_MKSEQ],rax
    mov rax,[rbp+48]
    or rax,[rbp+56]
    or rax,[rbp+64]
    or rax,[rbp+72]
    or rax,[rbp+80]
    or rax,[rbp+88]
    jnz lel_contract
    mov rax,[rbp+16]
    cmp [rbx+88],rax
    jne lel_contract
    cmp rax,1
    jb lel_contract
    cmp rax,4
    ja lel_contract
    mov [rsp+256],rax
    cmp rax,3
    je lel_mkdir_probe
    mov rcx,[r15+lel_MKREQ]
    mov rcx,[rcx+24]
    mov rdx,rcx
    add rcx,513
    jc lel_contract
    cmp [rbp+24],rcx
    jne lel_contract
    cmp [rbp+32],rdx
    ja lel_contract
    cmp rcx,[r15+lel_MKWORKCAP]
    jae lel_contract
    mov rdx,[r15+lel_MKWORKCAP]
    sub rdx,rcx
    cmp [rbp+32],rdx
    jae lel_contract
    lea rsi,[rbx+rcx]
    mov rcx,[rbp+32]
    cmp byte ptr [rsi+rcx],0
    jne lel_contract
    xor edx,edx
lel_mkdir_cstring_check:
    cmp rdx,rcx
    jae lel_mkdir_cstring_ready
    cmp byte ptr [rsi+rdx],0
    je lel_contract
    inc rdx
    jmp lel_mkdir_cstring_check
lel_mkdir_cstring_ready:
    cmp qword ptr [rsp+256],1
    je lel_mkdir_dispatch
    mov rdi,rsp
    xor eax,eax
    mov ecx,32
    rep stosq
    cmp qword ptr [rsp+256],2
    je lel_mkdir_statx
    cmp qword ptr [rbp+40],0
    jne lel_contract
    mov rdi,-100
    mov rdx,rsp
    xor r10d,r10d
    mov eax,262
    syscall
    test rax,rax
    jnz lel_mkdir_effect_return
    mov edx,[rsp+24]
    mov [rbp+72],rdx
    jmp lel_mkdir_effect_return
lel_mkdir_statx:
    cmp qword ptr [rbp+40],4095
    jne lel_contract
    mov rdi,-100
    xor edx,edx
    mov r10d,4095
    mov r8,rsp
    mov eax,332
    syscall
    test rax,rax
    jnz lel_mkdir_effect_return
    movzx edx,word ptr [rsp+28]
    mov [rbp+72],rdx
    jmp lel_mkdir_effect_return
lel_mkdir_dispatch:
    cmp qword ptr [rbp+40],511
    jne lel_contract
    mov rdi,rsi
    mov esi,511
    mov eax,83
    syscall
    jmp lel_mkdir_effect_return
lel_mkdir_probe:
    mov rax,[rbp+24]
    or rax,[rbp+32]
    jnz lel_contract
    cmp qword ptr [rbp+40],4095
    jne lel_contract
    xor edi,edi
    xor esi,esi
    xor edx,edx
    mov r10d,4095
    xor r8d,r8d
    mov eax,332
    syscall
lel_mkdir_effect_return:
    mov [rbp+56],rax
    test rax,rax
    jz lel_mkdir_effect_success
    jns lel_contract
    cmp rax,-4095
    jl lel_contract
    neg rax
    mov [rbp+64],rax
lel_mkdir_effect_success:
    mov qword ptr [rbp+48],1
    add rsp,272
    pop rbx
    pop rbp
    ret

