/* Fixed transport for unchanged Batch owners; no filesystem policy here. */
.equ ltb_NESTED_TARGET,3072
.equ ltb_NESTED_INPUT,3080
.equ ltb_NESTED_LENGTH,3088
.equ ltb_NESTED_SEQUENCE,3096
.equ ltb_NESTED_FOOTER,3104
.equ ltb_NESTED_KIND,3112
.equ ltb_LOCK_SEQUENCE,3120

local_text_body_resume:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp,24
    mov [rsp],rdi
    mov r13,rsp
    call ltb_callable_check_wait
    test eax,eax
    jnz ltb_callable_invalid_early
    mov [r15+ltb_RETURN_STACK],rsp
    mov rax,[r15+ltb_SLOTS+8]
    mov qword ptr [rax+328],1
    jmp ltb_callable_resume_admitted
local_text_body_cancel_wait:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp,24
    mov [rsp],rdi
    mov r13,rsp
    call ltb_callable_check_wait
    test eax,eax
    jnz ltb_callable_invalid_early
    mov [r15+ltb_RETURN_STACK],rsp
    mov rax,[r15+ltb_SLOTS+8]
    mov qword ptr [rax+112],1
    mov qword ptr [rax+328],1
ltb_callable_resume_admitted:
    mov qword ptr [r15+ltb_WAIT_FLAG],0
    mov rax,[r15+ltb_PUBLIC_CTX]
    mov qword ptr [rax+112],0
    mov qword ptr [rax+120],0
    mov qword ptr [rax+128],0
    jmp ltb_body_invoke
ltb_callable_check_wait:
    test rdi,rdi
    jz ltb_callable_wait_bad
    mov rax,ltb_CONTEXT_MAGIC
    cmp [rdi],rax
    jne ltb_callable_wait_bad
    cmp qword ptr [rdi+8],192
    jne ltb_callable_wait_bad
    cmp qword ptr [rdi+136],0
    jne ltb_callable_wait_bad
    cmp qword ptr [rdi+144],0
    jne ltb_callable_wait_bad
    mov r15,[rdi+152]
    test r15,r15
    jz ltb_callable_wait_bad
    mov rax,ltb_MAIN_MAGIC
    cmp [r15+ltb_MAIN_TAG],rax
    jne ltb_callable_wait_bad
    cmp [r15+ltb_PUBLIC_CTX],rdi
    jne ltb_callable_wait_bad
    cmp qword ptr [r15+ltb_WAIT_FLAG],1
    jne ltb_callable_wait_bad
    mov rax,[r15+ltb_SLOTS+8]
    cmp qword ptr [rax],240
    jne ltb_callable_wait_bad
    cmp qword ptr [rax+40],0
    je ltb_callable_wait_bad
    cmp qword ptr [rax+48],0
    jne ltb_callable_wait_bad
    mov rcx,[r15+ltb_SEQUENCE]
    cmp [rax+264],rcx
    jne ltb_callable_wait_bad
    cmp qword ptr [rax+328],0
    jne ltb_callable_wait_bad
    xor eax,eax
    ret
ltb_callable_wait_bad:
    mov eax,0xffffffff
    ret

ltb_body_invoke:
    xor edi,edi
    mov rsi,[r15+ltb_INPUT]
    mov rdx,[r15+ltb_INLEN]
    call ltb_pure_invoke
    cmp eax,0xffffffe0
    je ltb_body_call
    cmp eax,0xffffffe1
    je ltb_callable_wait
    mov rdx,[r15+ltb_SLOTS+8]
    cmp qword ptr [rdx+40],0
    jne ltb_contract
    cmp qword ptr [rdx+48],0
    jne ltb_contract
    cmp eax,0xffff0000
    jae ltb_callable_complete
    cmp eax,32
    jb ltb_contract
    cmp qword ptr [rdx],201
    jne ltb_contract
    mov rsi,[r15+ltb_SLOTS+24]
    mov rdx,0x3130305257424648
    cmp [rsi],rdx
    jne ltb_contract
    cmp qword ptr [rsi+8],1
    ja ltb_contract
    lea rdx,[rax-32]
    cmp [rsi+16],rdx
    jne ltb_contract
    cmp qword ptr [rsi+24],0
    jne ltb_contract
    jmp ltb_callable_complete
ltb_admit_effect_sequence:
    mov rdx,0x4c4c414354424648
    cmp [rbx+256],rdx
    jne ltb_contract
    mov rdx,[r15+ltb_SEQUENCE]
    inc rdx
    jz ltb_contract
    cmp [rbx+264],rdx
    jne ltb_contract
    cmp [rbx+56],rdx
    jne ltb_contract
    mov [r15+ltb_SEQUENCE],rdx
    xor ecx,ecx
    mov edx,312
ltb_admit_effect_zeros:
    or rcx,[rbx+rdx]
    add edx,8
    cmp edx,384
    jb ltb_admit_effect_zeros
    test rcx,rcx
    jnz ltb_contract
    ret
ltb_callable_wait:
    mov rbx,[r15+ltb_SLOTS+8]
    call ltb_admit_effect_sequence
    cmp qword ptr [rbx],240
    jne ltb_contract
    mov rax,[rbx+272]
    or rax,[rbx+280]
    or rax,[rbx+288]
    or rax,[rbx+296]
    or rax,[rbx+304]
    jnz ltb_contract
    cmp qword ptr [rbx+40],0
    je ltb_contract
    cmp qword ptr [rbx+48],0
    jne ltb_contract
    mov r10,[r15+ltb_PUBLIC_CTX]
    lea rax,[rbx+256]
    mov [r10+112],rax
    mov qword ptr [r10+120],128
    mov eax,0xffffffe1
    mov [r10+128],rax
    mov qword ptr [r15+ltb_WAIT_FLAG],1
    jmp ltb_callable_return
ltb_body_call:
    mov rbx,[r15+ltb_SLOTS+8]
    call ltb_admit_effect_sequence
    mov rax,[rbx+272]
    cmp rax,1
    jb ltb_contract
    cmp rax,13
    ja ltb_contract
    cmp rax,7
    je ltb_contract
    cmp rax,10
    je ltb_contract
    cmp rax,11
    je ltb_contract
    cmp [rbx+104],rax
    jne ltb_contract
    mov [r15+ltb_CHILD],rax
    mov rdx,[rbx+280]
    mov rcx,[rbx+288]
    cmp rdx,4096
    jae ltb_body_input_region
    /* The owner's cleanup phases use its dedicated metadata-free pair. */
    cmp qword ptr [r15+ltb_CHILD],1
    jne ltb_contract
    cmp rdx,1024
    jne ltb_contract
    cmp rcx,64
    jne ltb_contract
    cmp qword ptr [rbx+296],1088
    jne ltb_contract
    cmp qword ptr [rbx+304],64
    jne ltb_contract
    cmp qword ptr [rbx],181
    je ltb_body_input_region
    cmp qword ptr [rbx],191
    jne ltb_contract
ltb_body_input_region:
    cmp rdx,[r15+ltb_SLOTS+16]
    ja ltb_contract
    mov rax,[r15+ltb_SLOTS+16]
    sub rax,rdx
    cmp rcx,rax
    ja ltb_contract
    lea rax,[rbx+rdx]
    mov [r15+ltb_CHILDREQ],rax
    mov [r15+ltb_CHILDREQLEN],rcx
    mov r8,[rbx+296]
    cmp rdx,1024
    je ltb_body_output_region
    cmp r8,4096
    jb ltb_contract
ltb_body_output_region:
    mov r9,[rbx+304]
    mov rax,2147483648
    cmp r9,rax
    ja ltb_contract
    add rax,1073741824
    cmp r8,rax
    ja ltb_contract
    sub rax,r8
    cmp r9,rax
    ja ltb_contract
    mov rax,rdx
    add rax,rcx
    cmp rax,r8
    jbe ltb_body_disjoint
    lea rax,[r8+r9]
    cmp rax,rdx
    ja ltb_contract
ltb_body_disjoint:
    mov rax,[r15+ltb_CHILD]
    cmp eax,1
    je ltb_body_lock
    cmp eax,2
    je ltb_body_key
    cmp eax,4
    je ltb_body_atomic
    cmp eax,5
    je ltb_callable_cache
    cmp eax,6
    je ltb_body_read
    cmp eax,9
    je ltb_body_nested
    cmp eax,12
    je ltb_body_nested
    mov rdi,rax
    mov rsi,[r15+ltb_CHILDREQ]
    mov rdx,[r15+ltb_CHILDREQLEN]
    call ltb_pure_invoke
    jmp ltb_child_completed
ltb_body_lock:
    call ltb_lock_run
    jmp ltb_child_completed
ltb_body_key:
    call ltb_child_key
    mov rsi,[r15+ltb_CHILDOUT]
    jmp ltb_child_completed
ltb_body_atomic:
    call ltb_child_atomic
    mov rsi,[r15+ltb_CHILDOUT]
    jmp ltb_child_completed
ltb_body_read:
    call ltb_child_read
    mov rsi,[r15+ltb_CHILDOUT]
    jmp ltb_child_completed
ltb_body_nested:
    call ltb_nested_run
    jmp ltb_child_completed
ltb_callable_cache:
    mov qword ptr [r15+ltb_RESULT_PAIR],0
    mov qword ptr [r15+ltb_RESULT_PAIR+8],0
    mov r10,[r15+ltb_PUBLIC_CTX]
    mov rdi,[r10+32]
    mov rsi,[r15+ltb_CHILDREQ]
    mov rdx,[r15+ltb_CHILDREQLEN]
    lea rcx,[r15+ltb_RESULT_PAIR]
    call qword ptr [r10+24]
    cmp rax,32
    jb ltb_contract
    cmp rax,1073741824
    ja ltb_contract
    cmp [r15+ltb_RESULT_PAIR+8],rax
    jne ltb_contract
    mov rsi,[r15+ltb_RESULT_PAIR]
    test rsi,rsi
    jz ltb_contract
    /* Copy the complete borrowed Get before the next callback. */
ltb_child_completed:
    mov edx,eax
    cmp rax,rdx
    jne ltb_contract
    mov [r15+ltb_CHILDCODE],rax
    mov [r15+ltb_CHILDOUT],rsi
    mov rbx,[r15+ltb_SLOTS+8]
    cmp eax,0xffff0000
    jae ltb_child_error_completion
    cmp rax,[rbx+304]
    ja ltb_contract
    mov rsi,[rbx+296]
    add rsi,rax
    jc ltb_contract
    cmp rsi,[r15+ltb_SLOTS+16]
    jbe ltb_child_output_ready
    mov rax,3221225472
    cmp rsi,rax
    ja ltb_resource
    lea rdi,[r15+ltb_SLOTS+8]
    mov edx,1
    call ltb_ensure_region
    mov rbx,[r15+ltb_SLOTS+8]
ltb_child_output_ready:
    mov rdi,[rbx+296]
    add rdi,rbx
    mov rsi,[r15+ltb_CHILDOUT]
    mov rcx,[r15+ltb_CHILDCODE]
    rep movsb
    mov rax,[r15+ltb_CHILDCODE]
    mov [rbx+320],rax
    jmp ltb_child_acknowledge
ltb_child_error_completion:
    mov qword ptr [rbx+320],0
ltb_child_acknowledge:
    mov rax,[r15+ltb_CHILDCODE]
    mov [rbx+312],rax
    mov qword ptr [rbx+328],1
    jmp ltb_body_invoke

/* Shared lock/history records are borrowed; other arenas are private. */
ltb_pure_invoke:
    push rbp
    push rbx
    push r12
    push r13
    push r14
    mov r14,rdi
    cmp r14,13
    ja ltb_contract
    mov r12,rsi
    mov r13,rdx
    cmp r13,536870912
    ja ltb_resource
    mov rbx,r14
    shl rbx,6
    lea rbx,[r15+ltb_SLOTS+rbx]
    cmp r14,7
    je ltb_callable_lock_record
    cmp r14,3
    je ltb_callable_history_record
    lea rdi,[rbx+8]
    mov esi,8192
    mov edx,1
    call ltb_ensure_region
    lea rdi,[rbx+24]
    mov esi,4096
    xor edx,edx
    call ltb_ensure_region
    jmp ltb_pure_again
ltb_callable_lock_record:
    mov rbx,[r15+ltb_PUBLIC_CTX]
    mov rbx,[rbx+56]
    jmp ltb_pure_again
ltb_callable_history_record:
    mov rbx,[r15+ltb_PUBLIC_CTX]
    mov rbx,[rbx+64]
ltb_pure_again:
    mov rdi,r12
    mov rsi,r13
    mov rdx,[rbx+24]
    mov rcx,[rbx+32]
    mov r8,[rbx+8]
    mov r9,[rbx+16]
    call qword ptr [rbx]
    mov edx,eax
    cmp rax,rdx
    jne ltb_contract
    cmp eax,0xffffffef
    je ltb_pure_work_need
    cmp eax,0xffffffee
    je ltb_pure_output_need
    cmp eax,0xfffffffe
    je ltb_pure_capacity
    cmp eax,0xffff0000
    jae ltb_pure_return
    cmp rax,[rbx+32]
    ja ltb_contract
    cmp r14,7
    jne ltb_pure_return
    cmp eax,64
    jne ltb_pure_return
    mov rcx,[rbx+24]
    cmp qword ptr [rcx+16],2
    jne ltb_pure_return
    mov rsi,[rcx+32]
    jmp ltb_pure_grow_work
ltb_pure_work_need:
    test r14,r14
    jnz ltb_contract
    mov rax,[rbx+8]
    mov rsi,[rax+120]
ltb_pure_grow_work:
    cmp rsi,[rbx+16]
    jbe ltb_contract
    call ltb_check_work_limit
    cmp r14,7
    jne ltb_private_work_growth
    mov rdi,[rbx+32]
    call ltb_callable_shared_growth
    jmp ltb_pure_again
ltb_private_work_growth:
    lea rdi,[rbx+8]
    mov edx,1
    call ltb_ensure_region
    jmp ltb_pure_again
ltb_pure_output_need:
    test r14,r14
    jnz ltb_contract
    mov rax,[rbx+8]
    mov rsi,[rax+120]
    cmp rsi,[rbx+32]
    jbe ltb_contract
    call ltb_check_output_limit
    lea rdi,[rbx+24]
    xor edx,edx
    call ltb_ensure_region
    jmp ltb_pure_again
ltb_pure_capacity:
    mov rsi,[rbx+16]
    shl rsi,1
    jc ltb_resource
    call ltb_check_work_limit
    mov rdi,[rbx+32]
    shl rdi,1
    jc ltb_resource
    push rsi
    mov rsi,rdi
    call ltb_check_output_limit
    pop rsi
    cmp r14,3
    je ltb_pure_shared_capacity
    cmp r14,7
    je ltb_pure_shared_capacity
    push rdi
    lea rdi,[rbx+8]
    mov edx,1
    call ltb_ensure_region
    pop rsi
    lea rdi,[rbx+24]
    xor edx,edx
    call ltb_ensure_region
    jmp ltb_pure_again
ltb_pure_shared_capacity:
    call ltb_callable_shared_growth
    jmp ltb_pure_again
ltb_pure_return:
    mov [rbx+40],rax
    mov rsi,[rbx+24]
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret
ltb_check_work_limit:
    mov eax,1207959552
    test r14,r14
    jz ltb_work_big
    cmp r14,13
    jne ltb_work_bound
ltb_work_big:
    mov eax,3221225472
ltb_work_bound:
    cmp rsi,rax
    ja ltb_resource
    ret
ltb_check_output_limit:
    mov eax,1073741824
    test r14,r14
    jz ltb_output_big
    cmp r14,13
    jne ltb_output_bound
ltb_output_big:
    mov eax,2147483648
ltb_output_bound:
    cmp rsi,rax
    ja ltb_resource
    ret

/* Canonical lock service retains its independent nested effect sequence. */
ltb_lock_run:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    lea r14,[r15+ltb_SLOTS+64]
    mov r12,[r15+ltb_CHILDREQ]
    mov r13,[r15+ltb_CHILDREQLEN]
    mov rsi,r13
    add rsi,512
    jc ltb_resource
    cmp rsi,131072
    jae ltb_lock_work_size
    mov esi,131072
ltb_lock_work_size:
    cmp rsi,1207959552
    ja ltb_resource
    lea rdi,[r14+8]
    xor edx,edx
    call ltb_ensure_region
    lea rdi,[r14+24]
    mov esi,4096
    xor edx,edx
    call ltb_ensure_region
    mov rdi,[r14+8]
    mov rcx,[r14+16]
    xor eax,eax
    rep stosb
    /* The unchanged controller uses fixed key=1 and state=2 sequences.
       Non-acquire requests enter the state phase directly. */
    mov qword ptr [r15+ltb_LOCK_SEQUENCE],0
    cmp qword ptr [r12+8],1
    je ltb_lock_again
    mov qword ptr [r15+ltb_LOCK_SEQUENCE],1
ltb_lock_again:
    mov rdi,r12
    mov rsi,r13
    mov rdx,[r14+24]
    mov rcx,[r14+32]
    mov r8,[r14+8]
    mov r9,[r14+16]
    call qword ptr [r14]
    cmp eax,0xfffffff0
    jne ltb_lock_done
    mov rbp,[r14+8]
    mov rax,0x4c41434b434c4648
    cmp [rbp+64],rax
    jne ltb_contract
    mov rax,[r15+ltb_LOCK_SEQUENCE]
    inc rax
    jz ltb_contract
    cmp [rbp+72],rax
    jne ltb_contract
    cmp [rbp+16],rax
    jne ltb_contract
    mov [r15+ltb_LOCK_SEQUENCE],rax
    mov rax,[rbp+120]
    or rax,[rbp+128]
    or rax,[rbp+136]
    or rax,[rbp+144]
    or rax,[rbp+152]
    or rax,[rbp+160]
    or rax,[rbp+168]
    or rax,[rbp+176]
    or rax,[rbp+184]
    jnz ltb_contract
    mov rdx,[rbp+88]
    mov rcx,[rbp+96]
    cmp rdx,[r14+16]
    ja ltb_contract
    mov rax,[r14+16]
    sub rax,rdx
    cmp rcx,rax
    ja ltb_contract
    lea rsi,[rbp+rdx]
    mov [r15+ltb_CHILDREQ],rsi
    mov [r15+ltb_CHILDREQLEN],rcx
    mov rdx,rcx
    cmp qword ptr [rbp+80],1
    je ltb_lock_key
    cmp qword ptr [rbp+80],2
    jne ltb_contract
    mov edi,7
    call ltb_pure_invoke
    jmp ltb_lock_completion
ltb_lock_key:
    /* Key's syscall shim clobbers rbx/rbp/r12/r13/r14 internally. */
    push rbp
    push r12
    push r13
    push r14
    call ltb_child_key
    pop r14
    pop r13
    pop r12
    pop rbp
    mov rsi,[r15+ltb_CHILDOUT]
ltb_lock_completion:
    cmp rax,32
    jb ltb_contract
    cmp rax,[rbp+112]
    ja ltb_contract
    mov rdx,[rbp+104]
    cmp rdx,[r14+16]
    ja ltb_contract
    mov rcx,[r14+16]
    sub rcx,rdx
    cmp rax,rcx
    ja ltb_contract
    mov [rbp+120],rax
    mov [rbp+128],rax
    mov rcx,rax
    lea rdi,[rbp+rdx]
    rep movsb
    mov qword ptr [rbp+136],1
    jmp ltb_lock_again
ltb_lock_done:
    cmp rax,64
    jne ltb_contract
    mov rsi,[r14+24]
    mov [r14+40],rax
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

/* Pure nested owners use the published footer and a checked private arena. */
ltb_nested_run:
    push rbp
    push rbx
    push r12
    push r13
    push r14
    mov r14,[r15+ltb_CHILD]
    mov [r15+ltb_NESTED_TARGET],r14
    mov r12,[r15+ltb_CHILDREQ]
    mov r13,[r15+ltb_CHILDREQLEN]
    mov rbx,r14
    shl rbx,6
    lea rbx,[r15+ltb_SLOTS+rbx]
    lea rdi,[rbx+24]
    mov esi,4096
    xor edx,edx
    call ltb_ensure_region
ltb_nested_prepare:
    cmp r14,9
    jne ltb_apply_work_size
    mov rsi,r13
    shl rsi,1
    jc ltb_resource
    add rsi,[rbx+32]
    jc ltb_resource
    add rsi,32768
    jc ltb_resource
    mov qword ptr [r15+ltb_NESTED_KIND],1
    jmp ltb_nested_work_size
ltb_apply_work_size:
    cmp r14,12
    jne ltb_contract
    mov rsi,r13
    shl rsi,2
    jc ltb_resource
    mov rax,[rbx+32]
    imul rax,rax,3
    jo ltb_resource
    add rsi,rax
    jc ltb_resource
    add rsi,32768
    jc ltb_resource
    mov qword ptr [r15+ltb_NESTED_KIND],4
ltb_nested_work_size:
    cmp rsi,1207959552
    ja ltb_resource
    lea rdi,[rbx+8]
    xor edx,edx
    call ltb_ensure_region
    mov rbp,[rbx+8]
    mov qword ptr [rbp],0
    add rbp,[rbx+16]
    sub rbp,256
    mov [r15+ltb_NESTED_FOOTER],rbp
    mov rdi,rbp
    xor eax,eax
    mov ecx,32
    rep stosq
    mov qword ptr [rbp+120],3
    mov rax,[r15+ltb_NESTED_KIND]
    mov [rbp+128],rax
    mov qword ptr [rbp+136],1
    mov qword ptr [r15+ltb_NESTED_SEQUENCE],0
ltb_nested_again:
    mov rdi,r12
    mov rsi,r13
    mov rdx,[rbx+24]
    mov rcx,[rbx+32]
    mov r8,[rbx+8]
    mov r9,[rbx+16]
    call qword ptr [rbx]
    mov edx,eax
    cmp rax,rdx
    jne ltb_contract
    cmp eax,0xffffffe0
    je ltb_nested_effect
    cmp eax,0xfffffffe
    je ltb_nested_capacity
    cmp eax,0xffff0000
    jae ltb_nested_done
    cmp rax,[rbx+32]
    ja ltb_contract
    jmp ltb_nested_done
ltb_nested_capacity:
    mov rsi,[rbx+32]
    shl rsi,1
    jc ltb_resource
    cmp rsi,1073741824
    ja ltb_resource
    lea rdi,[rbx+24]
    xor edx,edx
    call ltb_ensure_region
    jmp ltb_nested_prepare
ltb_nested_effect:
    mov rax,0x31304c4143414948
    cmp [rbp],rax
    jne ltb_contract
    mov rax,[r15+ltb_NESTED_SEQUENCE]
    inc rax
    jz ltb_contract
    cmp [rbp+8],rax
    jne ltb_contract
    mov [r15+ltb_NESTED_SEQUENCE],rax
    cmp qword ptr [rbp+24],2
    jne ltb_contract
    cmp qword ptr [rbp+48],2
    jne ltb_contract
    cmp qword ptr [rbp+120],3
    jne ltb_contract
    mov rax,[r15+ltb_NESTED_KIND]
    cmp [rbp+128],rax
    jne ltb_contract
    cmp qword ptr [rbp+136],1
    jne ltb_contract
    mov rax,[rbp+72]
    or rax,[rbp+80]
    or rax,[rbp+88]
    or rax,[rbp+96]
    or rax,[rbp+104]
    jnz ltb_contract
    mov r8,[rbx+16]
    sub r8,256
    mov rax,[rbp+32]
    cmp rax,r8
    ja ltb_contract
    mov rcx,r8
    sub rcx,rax
    cmp [rbp+40],rcx
    ja ltb_contract
    mov rdx,[rbp+56]
    cmp rdx,r8
    ja ltb_contract
    sub r8,rdx
    cmp [rbp+64],r8
    ja ltb_contract
    mov rcx,rax
    add rcx,[rbp+40]
    cmp rcx,rdx
    jbe ltb_nested_disjoint
    add rdx,[rbp+64]
    cmp rdx,rax
    ja ltb_contract
ltb_nested_disjoint:
    mov rdi,[rbp+16]
    cmp r14,9
    jne ltb_nested_editable
    cmp rdi,2
    je ltb_nested_endpoint
    cmp rdi,3
    jne ltb_contract
    mov edi,11
    jmp ltb_nested_target_ready
ltb_nested_endpoint:
    mov edi,10
    jmp ltb_nested_target_ready
ltb_nested_editable:
    cmp rdi,5
    jne ltb_contract
    mov edi,8
ltb_nested_target_ready:
    mov rsi,[rbp+32]
    add rsi,[rbx+8]
    mov rdx,[rbp+40]
    call ltb_pure_invoke
    cmp eax,0xffff0000
    jae ltb_nested_leaf_refusal
    cmp rax,[rbp+64]
    ja ltb_nested_leaf_capacity
    mov rcx,rax
    mov rdi,[rbp+56]
    add rdi,[rbx+8]
    rep movsb
    jmp ltb_nested_leaf_refusal
ltb_nested_leaf_capacity:
    mov eax,0xfffffffe
ltb_nested_leaf_refusal:
    mov [rbp+80],rax
    mov rcx,[rbp+8]
    mov [rbp+88],rcx
    mov qword ptr [rbp+96],1
    jmp ltb_nested_again
ltb_nested_done:
    mov [rbx+40],rax
    mov rsi,[rbx+24]
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret
