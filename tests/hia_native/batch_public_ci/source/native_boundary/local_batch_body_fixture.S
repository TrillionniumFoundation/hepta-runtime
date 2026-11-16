.intel_syntax noprefix
.section .text
.global _start
.equ INPUT,0
.equ INCAP,8
.equ INLEN,16
.equ CALLBACK,24
.equ CBCAP,32
.equ CURRENT,40
.equ CURLEN,48
.equ CHILD,56
.equ SEQUENCE,64
.equ GENERATION,72
.equ HINTS,80
.equ HINTCAP,88
.equ HINTLEN,96
.equ HINTCOUNT,104
.equ CHILDREQ,112
.equ CHILDREQLEN,120
.equ CHILDOUT,128
.equ CHILDCODE,136
.equ OBS_PHASE,144
.equ SECURE,152
.equ SLOTS,256
.equ READCTX,2048
.equ KEYCTX,2176
.equ ATOMICCTX,2304
.equ META_BYTE,2432

_start:
    cmp qword ptr [rsp],1
    jne usage
    xor r14d,r14d
    lea rsi,[rsp+24]
environment_end:
    cmp qword ptr [rsi],0
    lea rsi,[rsi+8]
    jne environment_end
find_secure:
    mov rax,[rsi]
    test rax,rax
    jz secure_done
    cmp rax,23
    jne secure_next
    mov r14,[rsi+8]
secure_next:
    add rsi,16
    jmp find_secure
secure_done:
    and rsp,-16
    mov edi,4096
    call allocate_guarded
    mov r15,rax
    mov [r15+SECURE],r14
    lea rax,[rip+images]
    lea rsi,[rip+image_table]
    xor ecx,ecx
install_images:
    mov rdx,[rsi+rcx*8]
    test rdx,rdx
    jz contract
    cmp rdx,1048576
    ja contract
    mov rdi,rcx
    shl rdi,6
    mov [r15+SLOTS+rdi],rax
    add rax,rdx
    jc contract
    inc ecx
    cmp ecx,14
    jb install_images
    mov edi,7
    lea rsi,[rip+lock_initial]
    mov edx,64
    call pure_invoke
    cmp eax,64
    jne contract

next_frame:
    xor edi,edi
    lea rsi,[r15+INLEN]
    mov edx,8
    call read_header
    test eax,eax
    jz success
    cmp qword ptr [r15+INLEN],536870912
    ja resource
    lea rdi,[r15+INPUT]
    mov rsi,[r15+INLEN]
    xor edx,edx
    call ensure_region
    mov rdi,[r15+INPUT]
    mov rsi,[r15+INCAP]
    mov edx,3
    call protection
    xor edi,edi
    mov rsi,[r15+INPUT]
    mov rdx,[r15+INLEN]
    call read_exact
    mov rdi,[r15+INPUT]
    mov rsi,[r15+INCAP]
    mov edx,1
    call protection
    mov rbx,[r15+INPUT]
    cmp qword ptr [r15+INLEN],8
    jb frame_refused
    mov rax,0x3130484341435648
    cmp [rbx],rax
    je fixture_cache
    mov rax,0x3130515453494848
    cmp [rbx],rax
    je fixture_history
    mov rax,0x3130305457424648
    cmp [rbx],rax
    jne frame_refused
    cmp qword ptr [r15+INLEN],64
    jb frame_refused
    inc qword ptr [r15+GENERATION]
    jz contract
    call fixture_bind_context
    xor edi,edi
    call observe_states
    lea rdi,[r15+1280]
    mov rsi,[r15+INPUT]
    mov rdx,[r15+INLEN]
    call local_batch_body_run
    cmp eax,0xffffffe1
    je pending_unimplemented
    cmp eax,0xffff0000
    jae frame_code
    cmp qword ptr [r15+1416],1
    jne contract
    cmp qword ptr [r15+1424],1
    jne contract
    cmp qword ptr [r15+1440],0
    jne contract
    cmp [r15+1400],rax
    jne contract
    mov [r15+CHILDCODE],rax
    mov rax,[r15+1392]
    mov [r15+CHILDOUT],rax
    mov edi,1
    call observe_states
    jmp publish_result
fixture_cache:
    mov edi,5
    jmp fixture_call
fixture_history:
    mov edi,3
fixture_call:
    mov rsi,[r15+INPUT]
    mov rdx,[r15+INLEN]
    call pure_invoke
    cmp eax,0xffff0000
    jae frame_code
    mov [r15+CHILDCODE],rax
    mov [r15+CHILDOUT],rsi
publish_result:
    mov edi,1
    lea rsi,[r15+CHILDCODE]
    mov edx,8
    call write_all
    mov edi,1
    mov rsi,[r15+CHILDOUT]
    mov rdx,[r15+CHILDCODE]
    call write_all
    jmp fixture_release_result
frame_refused:
    mov eax,0xffffffff
frame_code:
    mov [r15+CHILDCODE],rax
    mov edi,1
    lea rsi,[r15+CHILDCODE]
    mov edx,8
    call write_all
    jmp fixture_release_result

fixture_release_result:
    cmp qword ptr [r15+1416],0
    je next_frame
    lea rdi,[r15+1280]
    call local_batch_body_release
    test eax,eax
    jnz contract
    mov qword ptr [r15+1416],0
    jmp next_frame
lock_initial:
    .quad 0x314b434f4c465248,0,0,0,0,0,0,0
hint_response:
    .quad 0x3130504842544c48,0,0,0

/* Pure HIA calls retain one arena per fixed image. Growth replays only an
   admitted resource refusal; semantic completion is returned to the caller. */
pure_invoke:
    push rbp
    push rbx
    push r12
    push r13
    push r14
    mov r14,rdi
    cmp r14,3
    je pure_admitted
    cmp r14,5
    je pure_admitted
    cmp r14,7
    jne contract
pure_admitted:
    mov r12,rsi
    mov r13,rdx
    cmp r13,536870912
    ja resource
    mov rbx,r14
    shl rbx,6
    lea rbx,[r15+SLOTS+rbx]
    lea rdi,[rbx+8]
    mov esi,4096
    mov edx,1
    call ensure_region
    lea rdi,[rbx+24]
    mov esi,4096
    xor edx,edx
    call ensure_region
pure_again:
    mov rdi,r12
    mov rsi,r13
    mov rdx,[rbx+24]
    mov rcx,[rbx+32]
    mov r8,[rbx+8]
    mov r9,[rbx+16]
    call qword ptr [rbx]
    mov edx,eax
    cmp rax,rdx
    jne contract
    cmp eax,0xfffffffe
    je pure_capacity
    cmp eax,0xffff0000
    jae pure_return
    cmp rax,[rbx+32]
    ja contract
    cmp r14,7
    jne pure_return
    cmp eax,64
    jne pure_return
    mov rcx,[rbx+24]
    cmp qword ptr [rcx+16],2
    jne pure_return
    mov rsi,[rcx+32]
    cmp rsi,[rbx+16]
    jbe contract
    cmp rsi,1207959552
    ja resource
    lea rdi,[rbx+8]
    mov edx,1
    call ensure_region
    jmp pure_again
pure_capacity:
    cmp r14,7
    je resource
    mov rsi,[rbx+16]
    shl rsi,1
    jc resource
    cmp rsi,1207959552
    ja resource
    lea rdi,[rbx+8]
    mov edx,1
    call ensure_region
    mov rsi,[rbx+32]
    shl rsi,1
    jc resource
    cmp rsi,1073741824
    ja resource
    lea rdi,[rbx+24]
    xor edx,edx
    call ensure_region
    jmp pure_again
pure_return:
    mov [rbx+40],rax
    mov rsi,[rbx+24]
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret

observe_states:
    push rbx
    push rbp
    push r12
    push r13
    sub rsp,64
    mov [r15+OBS_PHASE],rdi
    mov ebx,7
observe_one:
    mov rbp,rbx
    shl rbp,6
    lea rbp,[r15+SLOTS+rbp]
    mov rdi,rsp
    xor eax,eax
    mov ecx,8
    rep stosq
    mov rax,0x3130414e42424c48
    mov [rsp],rax
    mov rdx,[rbp+16]
    mov rax,rdx
    add rax,64
    jc resource
    mov [rsp+8],rax
    mov rax,[r15+OBS_PHASE]
    mov [rsp+16],rax
    mov rax,[r15+GENERATION]
    mov [rsp+24],rax
    mov [rsp+32],rbx
    mov [rsp+40],rdx
    mov edi,2
    mov rsi,rsp
    mov edx,64
    call write_all
    mov edi,2
    mov rsi,[rbp+8]
    mov rdx,[rbp+16]
    call write_all
    cmp ebx,7
    jne observe_second
    mov ebx,3
    jmp observe_one
observe_second:
    cmp ebx,3
    jne observe_done
    mov ebx,5
    jmp observe_one
observe_done:
    add rsp,64
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

round_capacity:
    mov rax,rdi
    add rax,4095
    jc resource
    and rax,-4096
    test rax,rax
    jnz rounded
    mov eax,4096
rounded:
    ret
allocate_guarded:
    push rbx
    mov rbx,rdi
    mov rsi,rdi
    add rsi,4096
    jc resource
    xor edi,edi
    mov edx,3
    mov r10d,0x22
    mov r8,-1
    xor r9d,r9d
    mov eax,9
    syscall
    cmp rax,-4095
    jae resource
    push rax
    lea rdi,[rax+rbx]
    mov esi,4096
    xor edx,edx
    mov eax,10
    syscall
    test rax,rax
    jnz infrastructure
    pop rax
    pop rbx
    ret
ensure_region:
    push rbx
    push rbp
    push r12
    push r13
    mov rbx,rdi
    mov ebp,edx
    mov rax,[rbx]
    test rax,rax
    jz ensure_allocate
    cmp rsi,[rbx+8]
    jbe ensure_done
ensure_allocate:
    mov rdi,rsi
    call round_capacity
    mov r12,rax
    mov rdi,rax
    call allocate_guarded
    mov r13,rax
    cmp qword ptr [rbx],0
    je ensure_publish
    test ebp,ebp
    jz ensure_retire
    mov rdi,r13
    mov rsi,[rbx]
    mov rcx,[rbx+8]
    rep movsb
ensure_retire:
    mov rdi,[rbx]
    mov rsi,[rbx+8]
    add rsi,4096
    mov eax,11
    syscall
    test rax,rax
    jnz infrastructure
ensure_publish:
    mov [rbx],r13
    mov [rbx+8],r12
    mov rax,r13
ensure_done:
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret
protection:
    mov eax,10
    syscall
    test rax,rax
    jnz infrastructure
    ret
read_header:
    mov r8,rdx
read_header_again:
    xor eax,eax
    syscall
    cmp rax,-4
    je read_header_again
    test rax,rax
    js infrastructure
    jz read_header_eof
    add rsi,rax
    sub rdx,rax
    jnz read_header_again
    mov eax,1
    ret
read_header_eof:
    cmp rdx,r8
    jne infrastructure
    xor eax,eax
    ret
read_exact:
    test rdx,rdx
    jz read_done
read_exact_again:
    xor eax,eax
    syscall
    cmp rax,-4
    je read_exact_again
    test rax,rax
    jle infrastructure
    add rsi,rax
    sub rdx,rax
    jnz read_exact_again
read_done:
    ret
write_all:
    test rdx,rdx
    jz write_done
write_again:
    mov eax,1
    syscall
    cmp rax,-4
    je write_again
    test rax,rax
    jle infrastructure
    add rsi,rax
    sub rdx,rax
    jnz write_again
write_done:
    ret
pending_unimplemented:
    mov edi,78
    jmp fatal_exit
contract:
    mov edi,70
    jmp fatal_exit
resource:
    mov edi,71
    jmp fatal_exit
infrastructure:
    mov edi,74
    jmp fatal_exit
usage:
    mov edi,64
    jmp fatal_exit
success:
    xor edi,edi
fatal_exit:
    mov eax,60
    syscall
    ud2


/* Fixture capabilities use the actual retained HIA cache/history/lock images. */
fixture_bind_context:
    lea rdi,[r15+1280]
    xor eax,eax
    mov ecx,24
    rep stosq
    mov rax,0x3130494342424c48
    mov [r15+1280],rax
    mov qword ptr [r15+1288],192
    lea rax,[r15+1536]
    mov [r15+1296],rax
    xor ecx,ecx
fixture_copy_entries:
    mov rdx,rcx
    shl rdx,6
    mov rax,[r15+SLOTS+rdx]
    mov [r15+1536+rcx*8],rax
    inc ecx
    cmp ecx,14
    jb fixture_copy_entries
    lea rax,[rip+fixture_cache_callback]
    mov [r15+1304],rax
    mov [r15+1312],r15
    lea rax,[rip+fixture_hint_callback]
    mov [r15+1320],rax
    mov [r15+1328],r15
    lea rax,[r15+SLOTS+448]
    mov [r15+1336],rax
    lea rax,[r15+SLOTS+192]
    mov [r15+1344],rax
    lea rax,[rip+fixture_shared_growth]
    mov [r15+1352],rax
    mov [r15+1360],r15
    lea rax,[r15+META_BYTE]
    mov [r15+1368],rax
    mov rax,[r15+SECURE]
    mov [r15+1376],rax
    ret

fixture_cache_callback:
    push r15
    push rbx
    push r12
    mov r15,rdi
    mov r12,rcx
    mov edi,5
    call pure_invoke
    mov [r12],rsi
    mov [r12+8],rax
    pop r12
    pop rbx
    pop r15
    ret

fixture_shared_growth:
    push r15
    push rbx
    push r12
    push r13
    push rbp
    mov r15,rdi
    mov r12,rdx
    mov r13,rcx
    cmp esi,7
    je fixture_shared_selected
    cmp esi,3
    jne contract
fixture_shared_selected:
    shl rsi,6
    lea rbx,[r15+SLOTS+rsi]
    cmp r12,[rbx+16]
    jb contract
    cmp r13,[rbx+32]
    jb contract
    cmp r12,1207959552
    ja resource
    cmp r13,1073741824
    ja resource
    lea rdi,[rbx+8]
    mov rsi,r12
    mov edx,1
    call ensure_region
    lea rdi,[rbx+24]
    mov rsi,r13
    xor edx,edx
    call ensure_region
    xor eax,eax
    pop rbp
    pop r13
    pop r12
    pop rbx
    pop r15
    ret

fixture_hint_callback:
    mov eax,0xffffffff
    ret

.intel_syntax noprefix
.text
.equ lbb_INPUT,0
.equ lbb_INCAP,8
.equ lbb_INLEN,16
.equ lbb_CALLBACK,24
.equ lbb_CBCAP,32
.equ lbb_CURRENT,40
.equ lbb_CURLEN,48
.equ lbb_CHILD,56
.equ lbb_SEQUENCE,64
.equ lbb_GENERATION,72
.equ lbb_HINTS,80
.equ lbb_HINTCAP,88
.equ lbb_HINTLEN,96
.equ lbb_HINTCOUNT,104
.equ lbb_CHILDREQ,112
.equ lbb_CHILDREQLEN,120
.equ lbb_CHILDOUT,128
.equ lbb_CHILDCODE,136
.equ lbb_OBS_PHASE,144
.equ lbb_SECURE,152
.equ lbb_SLOTS,256
.equ lbb_READCTX,2048
.equ lbb_KEYCTX,2176
.equ lbb_ATOMICCTX,2304
.equ lbb_META_BYTE,2432
.global local_batch_body_run
.global local_batch_body_resume
.global local_batch_body_cancel_wait
.global local_batch_body_release
.equ lbb_PUBLIC_CTX,1280
.equ lbb_RETURN_STACK,1288
.equ lbb_META_POINTER,1296
.equ lbb_RESULT_PAIR,1304
.equ lbb_WAIT_FLAG,1320
.equ lbb_ABORTING,1328
.equ lbb_CLEAN_FRAME,1344
.equ lbb_CLEAN_OUTPUT,1408
.equ lbb_MAIN_TAG,192
.equ lbb_MAIN_MAGIC,0x3130434d42424c48
.equ lbb_CONTEXT_MAGIC,0x3130494342424c48

local_batch_body_run:
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
    jz lbb_callable_invalid_early
    mov rax,lbb_CONTEXT_MAGIC
    cmp [rdi],rax
    jne lbb_callable_invalid_early
    cmp qword ptr [rdi+8],192
    jne lbb_callable_invalid_early
    cmp qword ptr [rdi+16],0
    je lbb_callable_invalid_early
    cmp qword ptr [rdi+24],0
    je lbb_callable_invalid_early
    cmp qword ptr [rdi+40],0
    je lbb_callable_invalid_early
    cmp qword ptr [rdi+72],0
    je lbb_callable_invalid_early
    cmp qword ptr [rdi+96],1
    ja lbb_callable_invalid_early
    cmp qword ptr [rdi+104],0
    jne lbb_callable_invalid_early
    mov ecx,112
lbb_callable_empty_fields:
    cmp qword ptr [rdi+rcx],0
    jne lbb_callable_invalid_early
    add ecx,8
    cmp ecx,192
    jb lbb_callable_empty_fields
    mov rax,[rdi+88]
    test rax,rax
    jz lbb_callable_invalid_early
    cmp byte ptr [rax],2
    ja lbb_callable_invalid_early
    mov rax,[rdi+16]
    xor ecx,ecx
lbb_callable_check_entries:
    cmp qword ptr [rax+rcx*8],0
    je lbb_callable_invalid_early
    inc ecx
    cmp ecx,14
    jb lbb_callable_check_entries
    mov ebx,7
lbb_callable_check_shared:
    mov rdx,[rdi+56]
    cmp ebx,7
    je lbb_callable_check_record
    mov rdx,[rdi+64]
lbb_callable_check_record:
    test rdx,rdx
    jz lbb_callable_invalid_early
    test dl,7
    jnz lbb_callable_invalid_early
    mov rcx,[rax+rbx*8]
    cmp [rdx],rcx
    jne lbb_callable_invalid_early
    cmp qword ptr [rdx+8],0
    je lbb_callable_invalid_early
    cmp qword ptr [rdx+16],4096
    jb lbb_callable_invalid_early
    cmp qword ptr [rdx+16],1207959552
    ja lbb_callable_invalid_early
    test qword ptr [rdx+16],4095
    jnz lbb_callable_invalid_early
    cmp qword ptr [rdx+24],0
    je lbb_callable_invalid_early
    cmp qword ptr [rdx+32],4096
    jb lbb_callable_invalid_early
    cmp qword ptr [rdx+32],1073741824
    ja lbb_callable_invalid_early
    test qword ptr [rdx+32],4095
    jnz lbb_callable_invalid_early
    mov rcx,[rdx+48]
    or rcx,[rdx+56]
    jnz lbb_callable_invalid_early
    cmp ebx,7
    jne lbb_callable_admitted
    mov ebx,3
    jmp lbb_callable_check_shared
lbb_callable_admitted:
    cmp qword ptr [rsp+16],536870912
    ja lbb_callable_capacity_early
    xor r15d,r15d
    mov edi,4096
    call lbb_allocate_guarded
    mov r15,rax
    mov rax,lbb_MAIN_MAGIC
    mov [r15+lbb_MAIN_TAG],rax
    mov rbx,[rsp]
    mov [r15+lbb_PUBLIC_CTX],rbx
    mov [r15+lbb_RETURN_STACK],rsp
    mov [rbx+152],r15
    mov rax,[rbx+88]
    mov [r15+lbb_META_POINTER],rax
    mov rax,[rbx+96]
    mov [r15+lbb_SECURE],rax
    mov qword ptr [r15+lbb_ATOMICCTX+80],-1
    mov rsi,[rbx+16]
    xor ecx,ecx
lbb_callable_install_entries:
    mov rax,[rsi+rcx*8]
    mov rdi,rcx
    shl rdi,6
    mov [r15+lbb_SLOTS+rdi],rax
    inc ecx
    cmp ecx,14
    jb lbb_callable_install_entries
    lea rdi,[r15+lbb_INPUT]
    mov rsi,[rsp+16]
    xor edx,edx
    call lbb_ensure_region
    mov rdi,[r15+lbb_INPUT]
    mov rsi,[rsp+8]
    mov rcx,[rsp+16]
    mov [r15+lbb_INLEN],rcx
    rep movsb
    mov rdi,[r15+lbb_INPUT]
    mov rsi,[r15+lbb_INCAP]
    mov edx,1
    call lbb_protection
    mov rax,[r15+lbb_INPUT]
    mov [r15+lbb_CURRENT],rax
    mov rax,[r15+lbb_INLEN]
    mov [r15+lbb_CURLEN],rax
    jmp lbb_body_invoke
lbb_callable_invalid_early:
    mov eax,0xffffffff
    jmp lbb_callable_return_early
lbb_callable_capacity_early:
    mov eax,0xfffffffe
lbb_callable_return_early:
    mov rsp,r13
lbb_callable_restore:
    add rsp,24
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

/* Fixed transport for unchanged Batch owners; no filesystem policy here. */
.equ lbb_NESTED_TARGET,3072
.equ lbb_NESTED_INPUT,3080
.equ lbb_NESTED_LENGTH,3088
.equ lbb_NESTED_SEQUENCE,3096
.equ lbb_NESTED_FOOTER,3104
.equ lbb_NESTED_KIND,3112
.equ lbb_LOCK_SEQUENCE,3120

local_batch_body_resume:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp,24
    mov [rsp],rdi
    mov r13,rsp
    call lbb_callable_check_wait
    test eax,eax
    jnz lbb_callable_invalid_early
    mov [r15+lbb_RETURN_STACK],rsp
    mov rax,[r15+lbb_SLOTS+8]
    mov qword ptr [rax+328],1
    jmp lbb_callable_resume_admitted
local_batch_body_cancel_wait:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp,24
    mov [rsp],rdi
    mov r13,rsp
    call lbb_callable_check_wait
    test eax,eax
    jnz lbb_callable_invalid_early
    mov [r15+lbb_RETURN_STACK],rsp
    mov rax,[r15+lbb_SLOTS+8]
    mov qword ptr [rax+112],1
    mov qword ptr [rax+328],1
lbb_callable_resume_admitted:
    mov qword ptr [r15+lbb_WAIT_FLAG],0
    mov rax,[r15+lbb_PUBLIC_CTX]
    mov qword ptr [rax+112],0
    mov qword ptr [rax+120],0
    mov qword ptr [rax+128],0
    jmp lbb_body_invoke
lbb_callable_check_wait:
    test rdi,rdi
    jz lbb_callable_wait_bad
    mov rax,lbb_CONTEXT_MAGIC
    cmp [rdi],rax
    jne lbb_callable_wait_bad
    cmp qword ptr [rdi+8],192
    jne lbb_callable_wait_bad
    cmp qword ptr [rdi+136],0
    jne lbb_callable_wait_bad
    cmp qword ptr [rdi+144],0
    jne lbb_callable_wait_bad
    mov r15,[rdi+152]
    test r15,r15
    jz lbb_callable_wait_bad
    mov rax,lbb_MAIN_MAGIC
    cmp [r15+lbb_MAIN_TAG],rax
    jne lbb_callable_wait_bad
    cmp [r15+lbb_PUBLIC_CTX],rdi
    jne lbb_callable_wait_bad
    cmp qword ptr [r15+lbb_WAIT_FLAG],1
    jne lbb_callable_wait_bad
    mov rax,[r15+lbb_SLOTS+8]
    cmp qword ptr [rax],240
    jne lbb_callable_wait_bad
    cmp qword ptr [rax+40],0
    je lbb_callable_wait_bad
    cmp qword ptr [rax+48],0
    jne lbb_callable_wait_bad
    mov rcx,[r15+lbb_SEQUENCE]
    cmp [rax+264],rcx
    jne lbb_callable_wait_bad
    cmp qword ptr [rax+328],0
    jne lbb_callable_wait_bad
    xor eax,eax
    ret
lbb_callable_wait_bad:
    mov eax,0xffffffff
    ret

lbb_body_invoke:
    xor edi,edi
    mov rsi,[r15+lbb_INPUT]
    mov rdx,[r15+lbb_INLEN]
    call lbb_pure_invoke
    cmp eax,0xffffffe0
    je lbb_body_call
    cmp eax,0xffffffe1
    je lbb_callable_wait
    mov rdx,[r15+lbb_SLOTS+8]
    cmp qword ptr [rdx+40],0
    jne lbb_contract
    cmp qword ptr [rdx+48],0
    jne lbb_contract
    cmp eax,0xffff0000
    jae lbb_callable_complete
    cmp eax,32
    jb lbb_contract
    cmp qword ptr [rdx],201
    jne lbb_contract
    mov rsi,[r15+lbb_SLOTS+24]
    mov rdx,0x3130305257424648
    cmp [rsi],rdx
    jne lbb_contract
    cmp qword ptr [rsi+8],1
    ja lbb_contract
    lea rdx,[rax-32]
    cmp [rsi+16],rdx
    jne lbb_contract
    cmp qword ptr [rsi+24],0
    jne lbb_contract
    jmp lbb_callable_complete
lbb_admit_effect_sequence:
    mov rdx,0x4c4c414354424648
    cmp [rbx+256],rdx
    jne lbb_contract
    mov rdx,[r15+lbb_SEQUENCE]
    inc rdx
    jz lbb_contract
    cmp [rbx+264],rdx
    jne lbb_contract
    cmp [rbx+56],rdx
    jne lbb_contract
    mov [r15+lbb_SEQUENCE],rdx
    xor ecx,ecx
    mov edx,312
lbb_admit_effect_zeros:
    or rcx,[rbx+rdx]
    add edx,8
    cmp edx,384
    jb lbb_admit_effect_zeros
    test rcx,rcx
    jnz lbb_contract
    ret
lbb_callable_wait:
    mov rbx,[r15+lbb_SLOTS+8]
    call lbb_admit_effect_sequence
    cmp qword ptr [rbx],240
    jne lbb_contract
    mov rax,[rbx+272]
    or rax,[rbx+280]
    or rax,[rbx+288]
    or rax,[rbx+296]
    or rax,[rbx+304]
    jnz lbb_contract
    cmp qword ptr [rbx+40],0
    je lbb_contract
    cmp qword ptr [rbx+48],0
    jne lbb_contract
    mov r10,[r15+lbb_PUBLIC_CTX]
    lea rax,[rbx+256]
    mov [r10+112],rax
    mov qword ptr [r10+120],128
    mov eax,0xffffffe1
    mov [r10+128],rax
    mov qword ptr [r15+lbb_WAIT_FLAG],1
    jmp lbb_callable_return
lbb_body_call:
    mov rbx,[r15+lbb_SLOTS+8]
    call lbb_admit_effect_sequence
    mov rax,[rbx+272]
    cmp rax,1
    jb lbb_contract
    cmp rax,13
    ja lbb_contract
    cmp rax,7
    je lbb_contract
    cmp rax,10
    je lbb_contract
    cmp rax,11
    je lbb_contract
    cmp [rbx+104],rax
    jne lbb_contract
    mov [r15+lbb_CHILD],rax
    mov rdx,[rbx+280]
    mov rcx,[rbx+288]
    cmp rdx,4096
    jae lbb_body_input_region
    /* The owner's cleanup phases use its dedicated metadata-free pair. */
    cmp qword ptr [r15+lbb_CHILD],1
    jne lbb_contract
    cmp rdx,1024
    jne lbb_contract
    cmp rcx,64
    jne lbb_contract
    cmp qword ptr [rbx+296],1088
    jne lbb_contract
    cmp qword ptr [rbx+304],64
    jne lbb_contract
    cmp qword ptr [rbx],181
    je lbb_body_input_region
    cmp qword ptr [rbx],191
    jne lbb_contract
lbb_body_input_region:
    cmp rdx,[r15+lbb_SLOTS+16]
    ja lbb_contract
    mov rax,[r15+lbb_SLOTS+16]
    sub rax,rdx
    cmp rcx,rax
    ja lbb_contract
    lea rax,[rbx+rdx]
    mov [r15+lbb_CHILDREQ],rax
    mov [r15+lbb_CHILDREQLEN],rcx
    mov r8,[rbx+296]
    cmp rdx,1024
    je lbb_body_output_region
    cmp r8,4096
    jb lbb_contract
lbb_body_output_region:
    mov r9,[rbx+304]
    mov rax,2147483648
    cmp r9,rax
    ja lbb_contract
    add rax,1073741824
    cmp r8,rax
    ja lbb_contract
    sub rax,r8
    cmp r9,rax
    ja lbb_contract
    mov rax,rdx
    add rax,rcx
    cmp rax,r8
    jbe lbb_body_disjoint
    lea rax,[r8+r9]
    cmp rax,rdx
    ja lbb_contract
lbb_body_disjoint:
    mov rax,[r15+lbb_CHILD]
    cmp eax,1
    je lbb_body_lock
    cmp eax,2
    je lbb_body_key
    cmp eax,4
    je lbb_body_atomic
    cmp eax,5
    je lbb_callable_cache
    cmp eax,6
    je lbb_body_read
    cmp eax,9
    je lbb_body_nested
    cmp eax,12
    je lbb_body_nested
    mov rdi,rax
    mov rsi,[r15+lbb_CHILDREQ]
    mov rdx,[r15+lbb_CHILDREQLEN]
    call lbb_pure_invoke
    jmp lbb_child_completed
lbb_body_lock:
    call lbb_lock_run
    jmp lbb_child_completed
lbb_body_key:
    call lbb_child_key
    mov rsi,[r15+lbb_CHILDOUT]
    jmp lbb_child_completed
lbb_body_atomic:
    call lbb_child_atomic
    mov rsi,[r15+lbb_CHILDOUT]
    jmp lbb_child_completed
lbb_body_read:
    call lbb_child_read
    mov rsi,[r15+lbb_CHILDOUT]
    jmp lbb_child_completed
lbb_body_nested:
    call lbb_nested_run
    jmp lbb_child_completed
lbb_callable_cache:
    mov qword ptr [r15+lbb_RESULT_PAIR],0
    mov qword ptr [r15+lbb_RESULT_PAIR+8],0
    mov r10,[r15+lbb_PUBLIC_CTX]
    mov rdi,[r10+32]
    mov rsi,[r15+lbb_CHILDREQ]
    mov rdx,[r15+lbb_CHILDREQLEN]
    lea rcx,[r15+lbb_RESULT_PAIR]
    call qword ptr [r10+24]
    cmp rax,32
    jb lbb_contract
    cmp rax,1073741824
    ja lbb_contract
    cmp [r15+lbb_RESULT_PAIR+8],rax
    jne lbb_contract
    mov rsi,[r15+lbb_RESULT_PAIR]
    test rsi,rsi
    jz lbb_contract
    /* Copy the complete borrowed Get before the next callback. */
lbb_child_completed:
    mov edx,eax
    cmp rax,rdx
    jne lbb_contract
    mov [r15+lbb_CHILDCODE],rax
    mov [r15+lbb_CHILDOUT],rsi
    mov rbx,[r15+lbb_SLOTS+8]
    cmp eax,0xffff0000
    jae lbb_child_error_completion
    cmp rax,[rbx+304]
    ja lbb_contract
    mov rsi,[rbx+296]
    add rsi,rax
    jc lbb_contract
    cmp rsi,[r15+lbb_SLOTS+16]
    jbe lbb_child_output_ready
    mov rax,3221225472
    cmp rsi,rax
    ja lbb_resource
    lea rdi,[r15+lbb_SLOTS+8]
    mov edx,1
    call lbb_ensure_region
    mov rbx,[r15+lbb_SLOTS+8]
lbb_child_output_ready:
    mov rdi,[rbx+296]
    add rdi,rbx
    mov rsi,[r15+lbb_CHILDOUT]
    mov rcx,[r15+lbb_CHILDCODE]
    rep movsb
    mov rax,[r15+lbb_CHILDCODE]
    mov [rbx+320],rax
    jmp lbb_child_acknowledge
lbb_child_error_completion:
    mov qword ptr [rbx+320],0
lbb_child_acknowledge:
    mov rax,[r15+lbb_CHILDCODE]
    mov [rbx+312],rax
    mov qword ptr [rbx+328],1
    jmp lbb_body_invoke

/* Shared lock/history records are borrowed; other arenas are private. */
lbb_pure_invoke:
    push rbp
    push rbx
    push r12
    push r13
    push r14
    mov r14,rdi
    cmp r14,13
    ja lbb_contract
    mov r12,rsi
    mov r13,rdx
    cmp r13,536870912
    ja lbb_resource
    mov rbx,r14
    shl rbx,6
    lea rbx,[r15+lbb_SLOTS+rbx]
    cmp r14,7
    je lbb_callable_lock_record
    cmp r14,3
    je lbb_callable_history_record
    lea rdi,[rbx+8]
    mov esi,8192
    mov edx,1
    call lbb_ensure_region
    lea rdi,[rbx+24]
    mov esi,4096
    xor edx,edx
    call lbb_ensure_region
    jmp lbb_pure_again
lbb_callable_lock_record:
    mov rbx,[r15+lbb_PUBLIC_CTX]
    mov rbx,[rbx+56]
    jmp lbb_pure_again
lbb_callable_history_record:
    mov rbx,[r15+lbb_PUBLIC_CTX]
    mov rbx,[rbx+64]
lbb_pure_again:
    mov rdi,r12
    mov rsi,r13
    mov rdx,[rbx+24]
    mov rcx,[rbx+32]
    mov r8,[rbx+8]
    mov r9,[rbx+16]
    call qword ptr [rbx]
    mov edx,eax
    cmp rax,rdx
    jne lbb_contract
    cmp eax,0xffffffef
    je lbb_pure_work_need
    cmp eax,0xffffffee
    je lbb_pure_output_need
    cmp eax,0xfffffffe
    je lbb_pure_capacity
    cmp eax,0xffff0000
    jae lbb_pure_return
    cmp rax,[rbx+32]
    ja lbb_contract
    cmp r14,7
    jne lbb_pure_return
    cmp eax,64
    jne lbb_pure_return
    mov rcx,[rbx+24]
    cmp qword ptr [rcx+16],2
    jne lbb_pure_return
    mov rsi,[rcx+32]
    jmp lbb_pure_grow_work
lbb_pure_work_need:
    test r14,r14
    jnz lbb_contract
    mov rax,[rbx+8]
    mov rsi,[rax+120]
lbb_pure_grow_work:
    cmp rsi,[rbx+16]
    jbe lbb_contract
    call lbb_check_work_limit
    cmp r14,7
    jne lbb_private_work_growth
    mov rdi,[rbx+32]
    call lbb_callable_shared_growth
    jmp lbb_pure_again
lbb_private_work_growth:
    lea rdi,[rbx+8]
    mov edx,1
    call lbb_ensure_region
    jmp lbb_pure_again
lbb_pure_output_need:
    test r14,r14
    jnz lbb_contract
    mov rax,[rbx+8]
    mov rsi,[rax+120]
    cmp rsi,[rbx+32]
    jbe lbb_contract
    call lbb_check_output_limit
    lea rdi,[rbx+24]
    xor edx,edx
    call lbb_ensure_region
    jmp lbb_pure_again
lbb_pure_capacity:
    mov rsi,[rbx+16]
    shl rsi,1
    jc lbb_resource
    call lbb_check_work_limit
    mov rdi,[rbx+32]
    shl rdi,1
    jc lbb_resource
    push rsi
    mov rsi,rdi
    call lbb_check_output_limit
    pop rsi
    cmp r14,3
    je lbb_pure_shared_capacity
    cmp r14,7
    je lbb_pure_shared_capacity
    push rdi
    lea rdi,[rbx+8]
    mov edx,1
    call lbb_ensure_region
    pop rsi
    lea rdi,[rbx+24]
    xor edx,edx
    call lbb_ensure_region
    jmp lbb_pure_again
lbb_pure_shared_capacity:
    call lbb_callable_shared_growth
    jmp lbb_pure_again
lbb_pure_return:
    mov [rbx+40],rax
    mov rsi,[rbx+24]
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret
lbb_check_work_limit:
    mov eax,1207959552
    test r14,r14
    jz lbb_work_big
    cmp r14,13
    jne lbb_work_bound
lbb_work_big:
    mov eax,3221225472
lbb_work_bound:
    cmp rsi,rax
    ja lbb_resource
    ret
lbb_check_output_limit:
    mov eax,1073741824
    test r14,r14
    jz lbb_output_big
    cmp r14,13
    jne lbb_output_bound
lbb_output_big:
    mov eax,2147483648
lbb_output_bound:
    cmp rsi,rax
    ja lbb_resource
    ret

/* Canonical lock service retains its independent nested effect sequence. */
lbb_lock_run:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    lea r14,[r15+lbb_SLOTS+64]
    mov r12,[r15+lbb_CHILDREQ]
    mov r13,[r15+lbb_CHILDREQLEN]
    mov rsi,r13
    add rsi,512
    jc lbb_resource
    cmp rsi,131072
    jae lbb_lock_work_size
    mov esi,131072
lbb_lock_work_size:
    cmp rsi,1207959552
    ja lbb_resource
    lea rdi,[r14+8]
    xor edx,edx
    call lbb_ensure_region
    lea rdi,[r14+24]
    mov esi,4096
    xor edx,edx
    call lbb_ensure_region
    mov rdi,[r14+8]
    mov rcx,[r14+16]
    xor eax,eax
    rep stosb
    /* The unchanged controller uses fixed key=1 and state=2 sequences.
       Non-acquire requests enter the state phase directly. */
    mov qword ptr [r15+lbb_LOCK_SEQUENCE],0
    cmp qword ptr [r12+8],1
    je lbb_lock_again
    mov qword ptr [r15+lbb_LOCK_SEQUENCE],1
lbb_lock_again:
    mov rdi,r12
    mov rsi,r13
    mov rdx,[r14+24]
    mov rcx,[r14+32]
    mov r8,[r14+8]
    mov r9,[r14+16]
    call qword ptr [r14]
    cmp eax,0xfffffff0
    jne lbb_lock_done
    mov rbp,[r14+8]
    mov rax,0x4c41434b434c4648
    cmp [rbp+64],rax
    jne lbb_contract
    mov rax,[r15+lbb_LOCK_SEQUENCE]
    inc rax
    jz lbb_contract
    cmp [rbp+72],rax
    jne lbb_contract
    cmp [rbp+16],rax
    jne lbb_contract
    mov [r15+lbb_LOCK_SEQUENCE],rax
    mov rax,[rbp+120]
    or rax,[rbp+128]
    or rax,[rbp+136]
    or rax,[rbp+144]
    or rax,[rbp+152]
    or rax,[rbp+160]
    or rax,[rbp+168]
    or rax,[rbp+176]
    or rax,[rbp+184]
    jnz lbb_contract
    mov rdx,[rbp+88]
    mov rcx,[rbp+96]
    cmp rdx,[r14+16]
    ja lbb_contract
    mov rax,[r14+16]
    sub rax,rdx
    cmp rcx,rax
    ja lbb_contract
    lea rsi,[rbp+rdx]
    mov [r15+lbb_CHILDREQ],rsi
    mov [r15+lbb_CHILDREQLEN],rcx
    mov rdx,rcx
    cmp qword ptr [rbp+80],1
    je lbb_lock_key
    cmp qword ptr [rbp+80],2
    jne lbb_contract
    mov edi,7
    call lbb_pure_invoke
    jmp lbb_lock_completion
lbb_lock_key:
    /* Key's syscall shim clobbers rbx/rbp/r12/r13/r14 internally. */
    push rbp
    push r12
    push r13
    push r14
    call lbb_child_key
    pop r14
    pop r13
    pop r12
    pop rbp
    mov rsi,[r15+lbb_CHILDOUT]
lbb_lock_completion:
    cmp rax,32
    jb lbb_contract
    cmp rax,[rbp+112]
    ja lbb_contract
    mov rdx,[rbp+104]
    cmp rdx,[r14+16]
    ja lbb_contract
    mov rcx,[r14+16]
    sub rcx,rdx
    cmp rax,rcx
    ja lbb_contract
    mov [rbp+120],rax
    mov [rbp+128],rax
    mov rcx,rax
    lea rdi,[rbp+rdx]
    rep movsb
    mov qword ptr [rbp+136],1
    jmp lbb_lock_again
lbb_lock_done:
    cmp rax,64
    jne lbb_contract
    mov rsi,[r14+24]
    mov [r14+40],rax
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

/* Pure nested owners use the published footer and a checked private arena. */
lbb_nested_run:
    push rbp
    push rbx
    push r12
    push r13
    push r14
    mov r14,[r15+lbb_CHILD]
    mov [r15+lbb_NESTED_TARGET],r14
    mov r12,[r15+lbb_CHILDREQ]
    mov r13,[r15+lbb_CHILDREQLEN]
    mov rbx,r14
    shl rbx,6
    lea rbx,[r15+lbb_SLOTS+rbx]
    lea rdi,[rbx+24]
    mov esi,4096
    xor edx,edx
    call lbb_ensure_region
lbb_nested_prepare:
    cmp r14,9
    jne lbb_apply_work_size
    mov rsi,r13
    shl rsi,1
    jc lbb_resource
    add rsi,[rbx+32]
    jc lbb_resource
    add rsi,32768
    jc lbb_resource
    mov qword ptr [r15+lbb_NESTED_KIND],1
    jmp lbb_nested_work_size
lbb_apply_work_size:
    cmp r14,12
    jne lbb_contract
    mov rsi,r13
    shl rsi,2
    jc lbb_resource
    mov rax,[rbx+32]
    imul rax,rax,3
    jo lbb_resource
    add rsi,rax
    jc lbb_resource
    add rsi,32768
    jc lbb_resource
    mov qword ptr [r15+lbb_NESTED_KIND],4
lbb_nested_work_size:
    cmp rsi,1207959552
    ja lbb_resource
    lea rdi,[rbx+8]
    xor edx,edx
    call lbb_ensure_region
    mov rbp,[rbx+8]
    mov qword ptr [rbp],0
    add rbp,[rbx+16]
    sub rbp,256
    mov [r15+lbb_NESTED_FOOTER],rbp
    mov rdi,rbp
    xor eax,eax
    mov ecx,32
    rep stosq
    mov qword ptr [rbp+120],3
    mov rax,[r15+lbb_NESTED_KIND]
    mov [rbp+128],rax
    mov qword ptr [rbp+136],1
    mov qword ptr [r15+lbb_NESTED_SEQUENCE],0
lbb_nested_again:
    mov rdi,r12
    mov rsi,r13
    mov rdx,[rbx+24]
    mov rcx,[rbx+32]
    mov r8,[rbx+8]
    mov r9,[rbx+16]
    call qword ptr [rbx]
    mov edx,eax
    cmp rax,rdx
    jne lbb_contract
    cmp eax,0xffffffe0
    je lbb_nested_effect
    cmp eax,0xfffffffe
    je lbb_nested_capacity
    cmp eax,0xffff0000
    jae lbb_nested_done
    cmp rax,[rbx+32]
    ja lbb_contract
    jmp lbb_nested_done
lbb_nested_capacity:
    mov rsi,[rbx+32]
    shl rsi,1
    jc lbb_resource
    cmp rsi,1073741824
    ja lbb_resource
    lea rdi,[rbx+24]
    xor edx,edx
    call lbb_ensure_region
    jmp lbb_nested_prepare
lbb_nested_effect:
    mov rax,0x31304c4143414948
    cmp [rbp],rax
    jne lbb_contract
    mov rax,[r15+lbb_NESTED_SEQUENCE]
    inc rax
    jz lbb_contract
    cmp [rbp+8],rax
    jne lbb_contract
    mov [r15+lbb_NESTED_SEQUENCE],rax
    cmp qword ptr [rbp+24],2
    jne lbb_contract
    cmp qword ptr [rbp+48],2
    jne lbb_contract
    cmp qword ptr [rbp+120],3
    jne lbb_contract
    mov rax,[r15+lbb_NESTED_KIND]
    cmp [rbp+128],rax
    jne lbb_contract
    cmp qword ptr [rbp+136],1
    jne lbb_contract
    mov rax,[rbp+72]
    or rax,[rbp+80]
    or rax,[rbp+88]
    or rax,[rbp+96]
    or rax,[rbp+104]
    jnz lbb_contract
    mov r8,[rbx+16]
    sub r8,256
    mov rax,[rbp+32]
    cmp rax,r8
    ja lbb_contract
    mov rcx,r8
    sub rcx,rax
    cmp [rbp+40],rcx
    ja lbb_contract
    mov rdx,[rbp+56]
    cmp rdx,r8
    ja lbb_contract
    sub r8,rdx
    cmp [rbp+64],r8
    ja lbb_contract
    mov rcx,rax
    add rcx,[rbp+40]
    cmp rcx,rdx
    jbe lbb_nested_disjoint
    add rdx,[rbp+64]
    cmp rdx,rax
    ja lbb_contract
lbb_nested_disjoint:
    mov rdi,[rbp+16]
    cmp r14,9
    jne lbb_nested_editable
    cmp rdi,2
    je lbb_nested_endpoint
    cmp rdi,3
    jne lbb_contract
    mov edi,11
    jmp lbb_nested_target_ready
lbb_nested_endpoint:
    mov edi,10
    jmp lbb_nested_target_ready
lbb_nested_editable:
    cmp rdi,5
    jne lbb_contract
    mov edi,8
lbb_nested_target_ready:
    mov rsi,[rbp+32]
    add rsi,[rbx+8]
    mov rdx,[rbp+40]
    call lbb_pure_invoke
    cmp eax,0xffff0000
    jae lbb_nested_leaf_refusal
    cmp rax,[rbp+64]
    ja lbb_nested_leaf_capacity
    mov rcx,rax
    mov rdi,[rbp+56]
    add rdi,[rbx+8]
    rep movsb
    jmp lbb_nested_leaf_refusal
lbb_nested_leaf_capacity:
    mov eax,0xfffffffe
lbb_nested_leaf_refusal:
    mov [rbp+80],rax
    mov rcx,[rbp+8]
    mov [rbp+88],rcx
    mov qword ptr [rbp+96],1
    jmp lbb_nested_again
lbb_nested_done:
    mov [rbx+40],rax
    mov rsi,[rbx+24]
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret
lbb_callable_complete:
    mov r10,[r15+lbb_PUBLIC_CTX]
    cmp qword ptr [r10+136],0
    jne lbb_contract
    mov [r10+128],rax
    mov qword ptr [r10+112],0
    mov qword ptr [r10+120],0
    cmp eax,0xffff0000
    jae lbb_callable_complete_fields
    mov rcx,[r15+lbb_SLOTS+24]
    mov [r10+112],rcx
    mov [r10+120],rax
lbb_callable_complete_fields:
    mov qword ptr [r10+136],1
    mov qword ptr [r10+144],1
lbb_callable_return:
    mov rsp,[r15+lbb_RETURN_STACK]
    jmp lbb_callable_restore

lbb_callable_shared_growth:
    push rbp
    mov rbp,rsp
    and rsp,-16
    mov rdx,rsi
    mov rcx,rdi
    sub rsp,16
    mov [rsp],rdx
    mov [rsp+8],rcx
    mov r10,[r15+lbb_PUBLIC_CTX]
    mov rdi,[r10+80]
    mov rsi,r14
    call qword ptr [r10+72]
    test eax,eax
    jnz lbb_resource
    mov rax,[rsp]
    cmp [rbx+16],rax
    jb lbb_contract
    mov rax,[rsp+8]
    cmp [rbx+32],rax
    jb lbb_contract
    mov rax,r14
    shl rax,6
    mov rax,[r15+lbb_SLOTS+rax]
    cmp [rbx],rax
    jne lbb_contract
    mov rax,[rbx+48]
    or rax,[rbx+56]
    jnz lbb_contract
    cmp qword ptr [rbx+8],0
    je lbb_contract
    cmp qword ptr [rbx+24],0
    je lbb_contract
    cmp qword ptr [rbx+16],1207959552
    ja lbb_contract
    cmp qword ptr [rbx+32],1073741824
    ja lbb_contract
    test qword ptr [rbx+16],4095
    jnz lbb_contract
    test qword ptr [rbx+32],4095
    jnz lbb_contract
    mov rsp,rbp
    pop rbp
    ret

/* Failure drains owned capabilities without inventing a semantic result. */
lbb_callable_abort:
    test r15,r15
    jz lbb_callable_fault_early
    mov rsp,[r15+lbb_RETURN_STACK]
    cmp qword ptr [r15+lbb_ABORTING],0
    jne lbb_callable_uncertain
    mov [r15+lbb_ABORTING],rdi
    mov rbx,[r15+lbb_PUBLIC_CTX]
    mov [rbx+160],rdi
    cmp qword ptr [r15+lbb_READCTX+80],0
    je lbb_callable_abort_key
    push r15
    lea r15,[r15+lbb_READCTX]
    call lbb_lr_cleanup
    pop r15
    mov rax,[r15+lbb_READCTX+16]
    mov [r15+lbb_SLOTS+384+8],rax
    mov rax,[r15+lbb_READCTX+24]
    mov [r15+lbb_SLOTS+384+16],rax
    mov rax,[r15+lbb_READCTX+32]
    mov [r15+lbb_SLOTS+384+24],rax
    mov rax,[r15+lbb_READCTX+40]
    mov [r15+lbb_SLOTS+384+32],rax
lbb_callable_abort_key:
    cmp qword ptr [r15+lbb_KEYCTX+96],0
    je lbb_callable_abort_atomic
    push r15
    lea r15,[r15+lbb_KEYCTX]
    call lbb_key_cleanup
    pop r15
    mov rax,[r15+lbb_KEYCTX+16]
    mov [r15+lbb_SLOTS+128+8],rax
    mov rax,[r15+lbb_KEYCTX+24]
    mov [r15+lbb_SLOTS+128+16],rax
    mov rax,[r15+lbb_KEYCTX+32]
    mov [r15+lbb_SLOTS+128+24],rax
    mov rax,[r15+lbb_KEYCTX+40]
    mov [r15+lbb_SLOTS+128+32],rax
lbb_callable_abort_atomic:
    mov rdi,[r15+lbb_ATOMICCTX+80]
    mov qword ptr [r15+lbb_ATOMICCTX+80],-1
    test rdi,rdi
    js lbb_callable_abort_lease
    mov eax,3
    syscall
lbb_callable_abort_lease:
    call lbb_callable_drop_lease
    test eax,eax
    jnz lbb_callable_uncertain
    mov eax,0xfffffffc
    jmp lbb_callable_complete
lbb_callable_uncertain:
    mov r10,[r15+lbb_PUBLIC_CTX]
    mov eax,0xfffffffc
    mov [r10+128],rax
    mov qword ptr [r10+136],1
    mov qword ptr [r10+144],0
    mov qword ptr [r10+112],0
    mov qword ptr [r10+120],0
    mov eax,0xfffffffc
    jmp lbb_callable_return

lbb_callable_drop_lease:
    push rbx
    mov rax,[r15+lbb_SLOTS+8]
    test rax,rax
    jz lbb_callable_drop_done
    mov rbx,[rax+40]
    test rbx,rbx
    jz lbb_callable_drop_done
    lea rdi,[r15+lbb_CLEAN_FRAME]
    xor eax,eax
    mov ecx,8
    rep stosq
    mov rax,0x314b434f4c465248
    mov [r15+lbb_CLEAN_FRAME],rax
    mov qword ptr [r15+lbb_CLEAN_FRAME+8],6
    mov [r15+lbb_CLEAN_FRAME+16],rbx
    mov r10,[r15+lbb_PUBLIC_CTX]
    mov r10,[r10+56]
    lea rdi,[r15+lbb_CLEAN_FRAME]
    mov esi,64
    lea rdx,[r15+lbb_CLEAN_OUTPUT]
    mov ecx,64
    mov r8,[r10+8]
    mov r9,[r10+16]
    call qword ptr [r10]
    cmp rax,64
    jne lbb_callable_drop_bad
    mov rax,0x3130524b4c465248
    cmp [r15+lbb_CLEAN_OUTPUT],rax
    jne lbb_callable_drop_bad
    cmp qword ptr [r15+lbb_CLEAN_OUTPUT+8],6
    jne lbb_callable_drop_bad
    cmp qword ptr [r15+lbb_CLEAN_OUTPUT+16],0
    jne lbb_callable_drop_bad
    cmp [r15+lbb_CLEAN_OUTPUT+24],rbx
    jne lbb_callable_drop_bad
lbb_callable_drop_done:
    xor eax,eax
    jmp lbb_callable_drop_return
lbb_callable_drop_bad:
    mov eax,0xffffffff
lbb_callable_drop_return:
    pop rbx
    ret

lbb_callable_fault_early:
    mov rsp,r13
    mov r10,[rsp]
    mov [r10+160],rdi
    mov eax,0xfffffffc
    mov [r10+128],rax
    mov qword ptr [r10+136],1
    mov qword ptr [r10+144],1
    mov eax,0xfffffffc
    jmp lbb_callable_restore

/* Release never frees borrowed records, callbacks, or the parent statx byte. */
local_batch_body_release:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov r12,rdi
    test rdi,rdi
    jz lbb_callable_release_invalid
    mov rax,lbb_CONTEXT_MAGIC
    cmp [rdi],rax
    jne lbb_callable_release_invalid
    cmp qword ptr [rdi+8],192
    jne lbb_callable_release_invalid
    cmp qword ptr [rdi+136],1
    jne lbb_callable_release_busy
    cmp qword ptr [rdi+144],1
    jne lbb_callable_release_busy
    mov r15,[rdi+152]
    test r15,r15
    jz lbb_callable_release_done
    mov rax,lbb_MAIN_MAGIC
    cmp [r15+lbb_MAIN_TAG],rax
    jne lbb_callable_release_invalid
    cmp [r15+lbb_PUBLIC_CTX],r12
    jne lbb_callable_release_invalid
    lea r13,[rip+lbb_callable_owned_regions]
    mov r14d,26
lbb_callable_release_region:
    mov rbx,[r13]
    mov rdi,[r15+rbx]
    test rdi,rdi
    jz lbb_callable_release_next
    mov rsi,[r15+rbx+8]
    add rsi,4096
    jc lbb_callable_release_invalid
    mov eax,11
    syscall
    test rax,rax
    jnz lbb_callable_release_invalid
    mov qword ptr [r15+rbx],0
    mov qword ptr [r15+rbx+8],0
lbb_callable_release_next:
    add r13,8
    dec r14d
    jnz lbb_callable_release_region
    mov rdi,r15
    mov esi,8192
    mov eax,11
    syscall
    test rax,rax
    jnz lbb_callable_release_invalid
    mov qword ptr [r12+152],0
    mov qword ptr [r12+112],0
    mov qword ptr [r12+120],0
lbb_callable_release_done:
    xor eax,eax
    jmp lbb_callable_release_return
lbb_callable_release_busy:
    mov eax,16
    jmp lbb_callable_release_return
lbb_callable_release_invalid:
    mov eax,0xffffffff
lbb_callable_release_return:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret
.balign 8,0
lbb_callable_owned_regions:
    .quad lbb_INPUT,lbb_CALLBACK,lbb_SLOTS+0+8,lbb_SLOTS+0+24,lbb_SLOTS+64+8,lbb_SLOTS+64+24,lbb_SLOTS+128+8,lbb_SLOTS+128+24,lbb_SLOTS+256+8,lbb_SLOTS+256+24,lbb_SLOTS+320+8,lbb_SLOTS+320+24,lbb_SLOTS+384+8,lbb_SLOTS+384+24,lbb_SLOTS+512+8,lbb_SLOTS+512+24,lbb_SLOTS+576+8,lbb_SLOTS+576+24,lbb_SLOTS+640+8,lbb_SLOTS+640+24,lbb_SLOTS+704+8,lbb_SLOTS+704+24,lbb_SLOTS+768+8,lbb_SLOTS+768+24,lbb_SLOTS+832+8,lbb_SLOTS+832+24

lbb_child_read:
    push rbp
    lea rbx,[r15+lbb_SLOTS+384]
    lea rdi,[rbx+8]
    mov esi,4096
    mov edx,1
    call lbb_ensure_region
    lea rdi,[rbx+24]
    mov esi,4096
    xor edx,edx
    call lbb_ensure_region
    mov rax,[r15+lbb_CHILDREQ]
    mov [r15+lbb_READCTX],rax
    mov rax,[r15+lbb_CHILDREQLEN]
    mov [r15+lbb_READCTX+48],rax
    mov rax,[rbx+8]
    mov [r15+lbb_READCTX+16],rax
    mov rax,[rbx+16]
    mov [r15+lbb_READCTX+24],rax
    mov rax,[rbx+24]
    mov [r15+lbb_READCTX+32],rax
    mov rax,[rbx+32]
    mov [r15+lbb_READCTX+40],rax
    mov rax,[r15+lbb_META_POINTER]
    mov [r15+lbb_READCTX+64],rax
    mov [r15+lbb_READCTX+96],r15
    mov rax,[rbx]
    mov [r15+lbb_READCTX+80],rax
    lea rdi,[r15+lbb_READCTX]
    call lbb_local_read_run
    mov rcx,[r15+lbb_READCTX+16]
    mov [rbx+8],rcx
    mov rcx,[r15+lbb_READCTX+24]
    mov [rbx+16],rcx
    mov rcx,[r15+lbb_READCTX+32]
    mov [rbx+24],rcx
    mov [r15+lbb_CHILDOUT],rcx
    mov rcx,[r15+lbb_READCTX+40]
    mov [rbx+32],rcx
    pop rbp
    ret

lbb_child_key:
    push rbp
    lea rbx,[r15+lbb_SLOTS+128]
    lea rdi,[rbx+8]
    mov esi,1056768
    mov edx,1
    call lbb_ensure_region
    lea rdi,[rbx+24]
    mov esi,4096
    xor edx,edx
    call lbb_ensure_region
    mov rax,[r15+lbb_CHILDREQ]
    mov [r15+lbb_KEYCTX],rax
    mov rax,[r15+lbb_CHILDREQLEN]
    mov [r15+lbb_KEYCTX+48],rax
    mov rax,[rbx+8]
    mov [r15+lbb_KEYCTX+16],rax
    mov rax,[rbx+16]
    mov [r15+lbb_KEYCTX+24],rax
    mov rax,[rbx+24]
    mov [r15+lbb_KEYCTX+32],rax
    mov rax,[rbx+32]
    mov [r15+lbb_KEYCTX+40],rax
    mov rax,[r15+lbb_SECURE]
    mov [r15+lbb_KEYCTX+64],rax
    mov qword ptr [r15+lbb_KEYCTX+72],-1
    mov qword ptr [r15+lbb_KEYCTX+80],-1
    mov rax,[rbx]
    mov [r15+lbb_KEYCTX+96],rax
    mov [r15+lbb_KEYCTX+104],r15
    lea rdi,[r15+lbb_KEYCTX]
    call lbb_key_run
    mov rcx,[r15+lbb_KEYCTX+16]
    mov [rbx+8],rcx
    mov rcx,[r15+lbb_KEYCTX+24]
    mov [rbx+16],rcx
    mov rcx,[r15+lbb_KEYCTX+32]
    mov [rbx+24],rcx
    mov [r15+lbb_CHILDOUT],rcx
    mov rcx,[r15+lbb_KEYCTX+40]
    mov [rbx+32],rcx
    pop rbp
    ret

lbb_child_atomic:
    push rbp
    lea rbx,[r15+lbb_SLOTS+256]
    mov rax,[r15+lbb_CHILDREQ]
    cmp qword ptr [r15+lbb_CHILDREQLEN],64
    jb lbb_contract
    mov rbp,[rax+16]
    mov rsi,rbp
    imul rsi,rsi,5
    jo lbb_resource
    add rsi,4096
    jc lbb_resource
    lea rdi,[rbx+8]
    mov edx,1
    call lbb_ensure_region
    mov rsi,rbp
    imul rsi,rsi,3
    jo lbb_resource
    add rsi,512
    jc lbb_resource
    lea rdi,[rbx+24]
    xor edx,edx
    call lbb_ensure_region
    call lbb_atomic_run
    mov rcx,[rbx+24]
    mov [r15+lbb_CHILDOUT],rcx
    pop rbp
    ret

lbb_atomic_run:
    push rbp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub rsp,280
    lea rbp,[r15+lbb_ATOMICCTX]
    mov [rbp],rbx
    mov [rbp+72],rsp
    mov rax,[r15+lbb_CHILDREQ]
    mov [rbp+16],rax
    mov rax,[r15+lbb_CHILDREQLEN]
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
    mov rax,[r15+lbb_META_POINTER]
    movzx eax,byte ptr [rax]
    cmp eax,2
    ja lbb_atomic_worker_contract
    mov [r12+8],rax
    xor ebx,ebx
lbb_atomic_invoke_policy:
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
    jne lbb_atomic_worker_contract
    cmp eax,0xfffffff0
    jne lbb_atomic_policy_done
    mov rax,0x3158465441414948
    cmp [r12+256],rax
    jne lbb_atomic_worker_contract
    inc rbx
    jz lbb_atomic_worker_contract
    cmp [r12+264],rbx
    jne lbb_atomic_worker_contract
    cmp [r12+144],rbx
    jne lbb_atomic_worker_contract
    mov r14,[r12+272]
    cmp [r12],r14
    jne lbb_atomic_worker_contract
    cmp r14,1
    jb lbb_atomic_worker_contract
    cmp r14,11
    ja lbb_atomic_worker_contract
    mov rax,[r12+304]
    or rax,[r12+312]
    or rax,[r12+320]
    or rax,[r12+328]
    or rax,[r12+336]
    or rax,[r12+344]
    jnz lbb_atomic_worker_contract
    cmp qword ptr [r12+56],1024
    jne lbb_atomic_worker_contract
    mov rax,[rbp+24]
    sub rax,64
    cmp [r12+40],rax
    ja lbb_atomic_worker_contract
    mov rax,[r12+40]
    add rax,1025
    jc lbb_atomic_worker_contract
    cmp rax,[r12+64]
    jne lbb_atomic_worker_contract
    add rax,[r12+72]
    jc lbb_atomic_worker_contract
    cmp rax,[rbp+40]
    jae lbb_atomic_worker_contract
    cmp byte ptr [r12+rax],0
    jne lbb_atomic_worker_contract
    mov rax,[r12+40]
    cmp byte ptr [r12+rax+1024],0
    jne lbb_atomic_worker_contract
    cmp r14,1
    je lbb_atomic_stat_path
    cmp r14,2
    je lbb_atomic_stat_probe
    cmp r14,3
    je lbb_atomic_stat_path
    cmp r14,10
    je lbb_atomic_stat_path
    cmp r14,11
    je lbb_atomic_stat_probe_fallback
    cmp r14,4
    je lbb_atomic_open_temp
    cmp r14,5
    je lbb_atomic_write_temp
    cmp r14,6
    je lbb_atomic_close_temp
    cmp r14,7
    je lbb_atomic_chmod_temp
    cmp r14,8
    je lbb_atomic_rename_temp
    jmp lbb_atomic_unlink_temp
lbb_atomic_policy_done:
    cmp r13,-1
    jne lbb_atomic_worker_contract
    mov rcx,[r12+8]
    cmp rcx,2
    ja lbb_atomic_worker_contract
    mov rdx,[r15+lbb_META_POINTER]
    mov [rdx],cl
    add rsp,280
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret
lbb_atomic_worker_contract:
    mov rsp,[rbp+72]
    mov rdi,r13
    mov r13,-1
    mov [rbp+80],r13
    test rdi,rdi
    js lbb_contract
    mov eax,3
    syscall
    jmp lbb_contract

/* These complete observations belong only to the qualification fixture. */
lbb_round_capacity:
    mov rax,rdi
    add rax,4095
    jc lbb_resource
    and rax,-4096
    test rax,rax
    jnz lbb_rounded
    mov eax,4096
lbb_rounded:
    ret
lbb_allocate_guarded:
    push rbx
    mov rbx,rdi
    mov rsi,rdi
    add rsi,4096
    jc lbb_resource
    xor edi,edi
    mov edx,3
    mov r10d,0x22
    mov r8,-1
    xor r9d,r9d
    mov eax,9
    syscall
    cmp rax,-4095
    jae lbb_resource
    push rax
    lea rdi,[rax+rbx]
    mov esi,4096
    xor edx,edx
    mov eax,10
    syscall
    test rax,rax
    jnz lbb_callable_guard_failed
    pop rax
    pop rbx
    ret
lbb_callable_guard_failed:
    pop rdi
    lea rsi,[rbx+4096]
    mov eax,11
    syscall
    pop rbx
    jmp lbb_infrastructure
lbb_ensure_region:
    push rbx
    push rbp
    push r12
    push r13
    mov rbx,rdi
    mov ebp,edx
    mov rax,[rbx]
    test rax,rax
    jz lbb_ensure_allocate
    cmp rsi,[rbx+8]
    jbe lbb_ensure_done
lbb_ensure_allocate:
    mov rdi,rsi
    call lbb_round_capacity
    mov r12,rax
    mov rdi,rax
    call lbb_allocate_guarded
    mov r13,rax
    cmp qword ptr [rbx],0
    je lbb_ensure_publish
    test ebp,ebp
    jz lbb_ensure_retire
    mov rdi,r13
    mov rsi,[rbx]
    mov rcx,[rbx+8]
    rep movsb
lbb_ensure_retire:
    mov rdi,[rbx]
    mov rsi,[rbx+8]
    add rsi,4096
    mov eax,11
    syscall
    test rax,rax
    jnz lbb_infrastructure
lbb_ensure_publish:
    mov [rbx],r13
    mov [rbx+8],r12
    mov rax,r13
lbb_ensure_done:
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret
lbb_protection:
    mov eax,10
    syscall
    test rax,rax
    jnz lbb_infrastructure
    ret
lbb_contract:
    mov edi,70
    jmp lbb_callable_abort
lbb_resource:
    mov edi,71
    jmp lbb_callable_abort
lbb_infrastructure:
    mov edi,74
    jmp lbb_callable_abort
lbb_fatal_exit:
    mov r15,[r15+104]
    jmp lbb_callable_abort
lbb_atomic_stat_path:
    cmp r13, -1
    jne lbb_atomic_worker_contract
    cmp qword ptr [r12 + 256 + 24], 1024
    jne lbb_atomic_worker_contract
    mov rax, qword ptr [r12 + 40]
    cmp qword ptr [r12 + 256 + 32], rax
    jne lbb_atomic_worker_contract
    cmp qword ptr [r12 + 256 + 40], 0
    jne lbb_atomic_worker_contract
    lea rdi, [r12 + 1024]
    mov rcx, rax
    call lbb_atomic_exact_cstring
    mov rdi, rsp
    xor eax, eax
    mov ecx, 32
    rep stosq
    mov edi, -100
    lea rsi, [r12 + 1024]
    cmp r14, 1
    jne lbb_atomic_stat_fallback
    xor edx, edx
    mov r10d, 0xfff
    mov r8, rsp
    mov eax, 332
    syscall
    test rax, rax
    js lbb_atomic_effect_error
    movzx eax, word ptr [rsp + 28]
    mov qword ptr [r12 + 256 + 72], rax
    jmp lbb_atomic_acknowledge
lbb_atomic_stat_fallback:
    mov rdx, rsp
    xor r10d, r10d
    mov eax, 262
    syscall
    test rax, rax
    js lbb_atomic_effect_error
    mov eax, dword ptr [rsp + 24]
    mov qword ptr [r12 + 256 + 72], rax
    jmp lbb_atomic_acknowledge

lbb_atomic_stat_probe:
    cmp r13, -1
    jne lbb_atomic_worker_contract
    mov rax, qword ptr [r12 + 256 + 24]
    or rax, qword ptr [r12 + 256 + 32]
    or rax, qword ptr [r12 + 256 + 40]
    jnz lbb_atomic_worker_contract
    xor edi, edi
    xor esi, esi
    xor edx, edx
    mov r10d, 0xfff
    xor r8d, r8d
    mov eax, 332
    syscall
    test rax, rax
    js lbb_atomic_effect_error
    jmp lbb_atomic_acknowledge

lbb_atomic_stat_probe_fallback:
    cmp r13, -1
    jne lbb_atomic_worker_contract
    mov rax, qword ptr [r12 + 256 + 24]
    or rax, qword ptr [r12 + 256 + 32]
    or rax, qword ptr [r12 + 256 + 40]
    jnz lbb_atomic_worker_contract
    xor edi, edi
    xor esi, esi
    mov rdx, rsp
    xor r10d, r10d
    mov eax, 262
    syscall
    test rax, rax
    js lbb_atomic_effect_error
    jmp lbb_atomic_worker_contract

lbb_atomic_temp_arguments:
    mov rax, qword ptr [r12 + 64]
    cmp qword ptr [r12 + 256 + 24], rax
    jne lbb_atomic_worker_contract
    mov rcx, qword ptr [r12 + 72]
    cmp qword ptr [r12 + 256 + 32], rcx
    jne lbb_atomic_worker_contract
    lea rdi, [r12 + rax]
    call lbb_atomic_exact_cstring
    mov rax, qword ptr [r12 + 64]
    lea rdi, [r12 + rax]
    ret
lbb_atomic_open_temp:
    cmp r13, -1
    jne lbb_atomic_worker_contract
    cmp qword ptr [r12 + 256 + 40], 0
    jne lbb_atomic_worker_contract
    call lbb_atomic_temp_arguments
    mov rsi, rdi
    mov edi, -100
    mov edx, 0x80241
    mov r10d, 0666
    mov eax, 257
    syscall
    test rax, rax
    js lbb_atomic_effect_error
    cmp rax, 0x7fffffff
    ja lbb_atomic_worker_contract
    mov r13, rax
    mov [rbp+80],r13
    mov qword ptr [r12 + 256 + 72], 1
    jmp lbb_atomic_acknowledge

lbb_atomic_write_temp:
    cmp r13, 0
    jl lbb_atomic_worker_contract
    cmp qword ptr [r12 + 256 + 24], 1
    jne lbb_atomic_worker_contract
    mov rax, qword ptr [r12 + 40]
    add rax, 64
    add rax, qword ptr [r12 + 112]
    jc lbb_atomic_worker_contract
    cmp rax, qword ptr [r12 + 256 + 32]
    jne lbb_atomic_worker_contract
    cmp rax, [rbp + 24]
    jae lbb_atomic_worker_contract
    mov rdx, [rbp + 24]
    sub rdx, rax
    cmp rdx, qword ptr [r12 + 256 + 40]
    jne lbb_atomic_worker_contract
    mov rsi, [rbp + 16]
    add rsi, rax
    mov rdi, r13
    mov eax, 1
    syscall
    test rax, rax
    js lbb_atomic_effect_error
    mov qword ptr [r12 + 256 + 56], rax
    jmp lbb_atomic_acknowledge

lbb_atomic_close_temp:
    cmp r13, 0
    jl lbb_atomic_worker_contract
    cmp qword ptr [r12 + 256 + 24], 1
    jne lbb_atomic_worker_contract
    mov rax, qword ptr [r12 + 256 + 32]
    or rax, qword ptr [r12 + 256 + 40]
    jnz lbb_atomic_worker_contract
    mov rdi, r13
    mov r13, -1
    mov [rbp+80],r13
    mov eax, 3
    syscall
    test rax, rax
    js lbb_atomic_effect_error
    jmp lbb_atomic_acknowledge

lbb_atomic_chmod_temp:
    cmp r13, -1
    jne lbb_atomic_worker_contract
    mov rax, qword ptr [r12 + 80]
    mov ecx, 0xffffffff
    cmp rax, rcx
    ja lbb_atomic_worker_contract
    cmp qword ptr [r12 + 256 + 40], rax
    jne lbb_atomic_worker_contract
    call lbb_atomic_temp_arguments
    mov esi, dword ptr [r12 + 80]
    mov eax, 90
    syscall
    test rax, rax
    js lbb_atomic_effect_error
    jmp lbb_atomic_acknowledge

lbb_atomic_rename_temp:
    cmp r13, -1
    jne lbb_atomic_worker_contract
    mov rax, qword ptr [r12 + 64]
    cmp qword ptr [r12 + 256 + 24], rax
    jne lbb_atomic_worker_contract
    cmp qword ptr [r12 + 256 + 32], 1024
    jne lbb_atomic_worker_contract
    cmp qword ptr [r12 + 256 + 40], 0
    jne lbb_atomic_worker_contract
    lea rdi, [r12 + rax]
    mov rcx, qword ptr [r12 + 72]
    call lbb_atomic_exact_cstring
    lea rdi, [r12 + 1024]
    mov rcx, qword ptr [r12 + 40]
    call lbb_atomic_exact_cstring
    mov rax, qword ptr [r12 + 64]
    lea rdi, [r12 + rax]
    lea rsi, [r12 + 1024]
    mov eax, 82
    syscall
    test rax, rax
    js lbb_atomic_effect_error
    jmp lbb_atomic_acknowledge

lbb_atomic_unlink_temp:
    cmp r13, -1
    jne lbb_atomic_worker_contract
    cmp qword ptr [r12 + 256 + 40], 0
    jne lbb_atomic_worker_contract
    call lbb_atomic_temp_arguments
    mov eax, 87
    syscall
    test rax, rax
    js lbb_atomic_effect_error
    jmp lbb_atomic_acknowledge

lbb_atomic_effect_error:
    cmp rax, -4095
    jb lbb_atomic_worker_contract
    neg rax
    mov qword ptr [r12 + 256 + 64], rax
lbb_atomic_acknowledge:
    mov qword ptr [r12 + 256 + 80], 1
    jmp lbb_atomic_invoke_policy

lbb_atomic_exact_cstring:
    xor eax, eax
    test rcx, rcx
    jz lbb_atomic_exact_end
    repne scasb
    je lbb_atomic_worker_contract
lbb_atomic_exact_end:
    cmp byte ptr [rdi], 0
    jne lbb_atomic_worker_contract
    ret


lbb_local_read_run:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp, 520
    mov r15, rdi
    cmp qword ptr [r15 + 72], 0
    jne lbb_lr_contract_fail
    mov rdi, qword ptr [r15 + 48]
    add rdi, 1024
    jc lbb_lr_memory_fail
    cmp rdi, qword ptr [r15 + 24]
    jbe lbb_lr_read_workspace_ready
    mov ebp, 16
    call lbb_lr_resize_buffer
lbb_lr_read_workspace_ready:
    mov rdi, qword ptr [r15 + 16]
    xor eax, eax
    mov ecx, 128
    rep stosq
    mov qword ptr [r15 + 88], 0
lbb_lr_read_invoke:
    mov rdi, qword ptr [r15]
    mov rsi, qword ptr [r15 + 48]
    mov rdx, qword ptr [r15 + 32]
    mov rcx, qword ptr [r15 + 40]
    mov r8, qword ptr [r15 + 16]
    mov r9, qword ptr [r15 + 24]
    call qword ptr [r15 + 80]
    mov edx, eax
    cmp rax, rdx
    jne lbb_lr_contract_fail
    mov rbx, qword ptr [r15 + 16]
    cmp eax, 0xffffffef
    je lbb_lr_read_grow
    cmp eax, 0xffffffe8
    je lbb_lr_read_cache
    cmp eax, 0xfffffff0
    je lbb_lr_read_effect
    cmp eax, 0xfffffff6
    je lbb_lr_allocation_abort
    cmp eax, 0xffffffff
    je lbb_lr_read_refused
    cmp eax, 0xfffffffe
    je lbb_lr_read_refused
    cmp eax, 0xfffffff9
    je lbb_lr_contract_fail
    cmp rax, qword ptr [r15 + 40]
    ja lbb_lr_contract_fail
    cmp eax, 32
    jb lbb_lr_contract_fail
    cmp qword ptr [rbx], 100
    jne lbb_lr_contract_fail
    cmp qword ptr [r15 + 72], 0
    jne lbb_lr_contract_fail
    mov rdx, qword ptr [r15 + 32]
    mov rcx, 0x3130304f524c4648
    cmp qword ptr [rdx], rcx
    jne lbb_lr_contract_fail
    lea rcx, [rax - 32]
    cmp qword ptr [rdx + 24], rcx
    jne lbb_lr_contract_fail
    jmp lbb_lr_read_return
lbb_lr_read_refused:
    mov dword ptr [rsp + 504], eax
    call lbb_lr_cleanup
    mov eax, dword ptr [rsp + 504]
lbb_lr_read_return:
    add rsp, 520
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

lbb_lr_read_grow:
    cmp qword ptr [rbx], 90
    jne lbb_lr_contract_fail
    mov rdi, qword ptr [rbx + 200]
    mov rax, qword ptr [rbx + 216]
    cmp rax, 1
    je lbb_lr_read_grow_work
    cmp rax, 2
    jne lbb_lr_contract_fail
    cmp qword ptr [rbx + 208], 100
    jne lbb_lr_contract_fail
    cmp qword ptr [r15 + 72], 0
    jne lbb_lr_contract_fail
    cmp rdi, 1073741824
    ja lbb_lr_read_resource
    mov ebp, 32
    jmp lbb_lr_read_grow_do
lbb_lr_read_grow_work:
    cmp rdi, 1207959552
    ja lbb_lr_read_resource
    mov rax, qword ptr [rbx + 208]
    cmp rax, 20
    je lbb_lr_read_grow_work_valid
    cmp rax, 23
    je lbb_lr_read_grow_work_valid
    cmp rax, 24
    jne lbb_lr_contract_fail
lbb_lr_read_grow_work_valid:
    mov rax, qword ptr [rbx + 56]
    add rax, qword ptr [rbx + 152]
    jc lbb_lr_contract_fail
    cmp rdi, rax
    jne lbb_lr_contract_fail
    mov ebp, 16
lbb_lr_read_grow_do:
    cmp rdi, qword ptr [r15 + rbp + 8]
    jbe lbb_lr_contract_fail
    call lbb_lr_resize_buffer
    jmp lbb_lr_read_invoke
lbb_lr_read_resource:
    mov eax, 0xfffffffe
    jmp lbb_lr_read_refused

lbb_lr_read_cache:
    lea r12, [rbx + 640]
    mov rax, 0x3130304341544d48
    cmp qword ptr [r12], rax
    jne lbb_lr_contract_fail
    call lbb_lr_sequence_admit
    mov r13, qword ptr [r12 + 16]
    cmp r13, 1
    ja lbb_lr_contract_fail
    mov rax, qword ptr [r12 + 32]
    or rax, qword ptr [r12 + 40]
    jnz lbb_lr_contract_fail
    mov rax, qword ptr [rbx]
    cmp rax, 60
    jb lbb_lr_contract_fail
    cmp rax, 63
    ja lbb_lr_contract_fail
    cmp rax, 62
    jb lbb_lr_read_cache_load
    cmp r13, 1
    jne lbb_lr_contract_fail
    mov rax, qword ptr [r12 + 24]
    cmp rax, qword ptr [rbx + 104]
    jne lbb_lr_contract_fail
    cmp rax, 1
    jb lbb_lr_contract_fail
    cmp rax, 2
    ja lbb_lr_contract_fail
    mov rdx, qword ptr [r15 + 64]
    mov byte ptr [rdx], al
    xor eax, eax
    jmp lbb_lr_read_cache_complete
lbb_lr_read_cache_load:
    test r13, r13
    jnz lbb_lr_contract_fail
    cmp qword ptr [r12 + 24], 0
    jne lbb_lr_contract_fail
    mov rdx, qword ptr [r15 + 64]
    movzx eax, byte ptr [rdx]
    cmp eax, 2
    ja lbb_lr_contract_fail
lbb_lr_read_cache_complete:
    mov qword ptr [r12 + 56], rax
    mov qword ptr [r12 + 80], 1
    jmp lbb_lr_read_invoke

lbb_lr_read_effect:
    lea r12, [rbx + 256]
    mov rax, 0x58464f49524c4648
    cmp qword ptr [r12], rax
    jne lbb_lr_contract_fail
    call lbb_lr_sequence_admit
    mov r14, qword ptr [r12 + 16]
    mov rax, qword ptr [rbx]
    cmp r14, 8
    jne lbb_lr_read_effect_phase
    cmp rax, 21
    je lbb_lr_read_effect_ready
    cmp rax, 22
    jne lbb_lr_contract_fail
    jmp lbb_lr_read_effect_ready
lbb_lr_read_effect_phase:
    cmp rax, r14
    jne lbb_lr_contract_fail
lbb_lr_read_effect_ready:
    mov rdi, rsp
    xor eax, eax
    mov ecx, 32
    rep stosq
    cmp r14, 1
    je lbb_lr_read_path_statx
    cmp r14, 2
    je lbb_lr_read_probe_statx
    cmp r14, 3
    je lbb_lr_read_path_stat
    cmp r14, 4
    je lbb_lr_read_open
    cmp r14, 5
    je lbb_lr_read_fd_statx
    cmp r14, 7
    je lbb_lr_read_fd_stat
    cmp r14, 8
    je lbb_lr_read_bytes
    cmp r14, 9
    je lbb_lr_read_close
    cmp r14, 10
    je lbb_lr_read_path_stat
    cmp r14, 11
    je lbb_lr_read_fd_statat
    cmp r14, 12
    je lbb_lr_read_probe_stat
    jmp lbb_lr_contract_fail
lbb_lr_read_path_statx:
    call lbb_lr_path_admit
    mov rsi, rax
    mov rdi, -100
    xor edx, edx
    mov r10d, 4095
    mov r8, rsp
    mov eax, 332
    syscall
    mov ebp, 1
    jmp lbb_lr_effect_done
lbb_lr_read_path_stat:
    call lbb_lr_path_admit
    mov rsi, rax
    mov rdi, -100
    mov rdx, rsp
    xor r10d, r10d
    mov eax, 262
    syscall
    mov ebp, 2
    jmp lbb_lr_effect_done
lbb_lr_read_probe_statx:
    call lbb_lr_zero_arguments
    xor edi, edi
    xor esi, esi
    xor edx, edx
    mov r10d, 4095
    xor r8d, r8d
    mov eax, 332
    syscall
    xor ebp, ebp
    jmp lbb_lr_effect_done
lbb_lr_read_probe_stat:
    call lbb_lr_zero_arguments
    xor edi, edi
    xor esi, esi
    xor edx, edx
    xor r10d, r10d
    mov eax, 262
    syscall
    xor ebp, ebp
    jmp lbb_lr_effect_done
lbb_lr_read_open:
    cmp qword ptr [r15 + 72], 0
    jne lbb_lr_contract_fail
    call lbb_lr_path_admit
    mov rsi, rax
    mov rdi, -100
    mov edx, 524288
    xor r10d, r10d
    mov eax, 257
    syscall
    mov ebp, 3
    jmp lbb_lr_effect_done
lbb_lr_read_fd_statx:
    call lbb_lr_fd_only
    lea rsi, [rip + lbb_lr_empty_path]
    mov edx, 4096
    mov r10d, 4095
    mov r8, rsp
    mov eax, 332
    syscall
    mov ebp, 1
    jmp lbb_lr_effect_done
lbb_lr_read_fd_statat:
    call lbb_lr_fd_only
    lea rsi, [rip + lbb_lr_empty_path]
    mov rdx, rsp
    mov r10d, 4096
    mov eax, 262
    syscall
    mov ebp, 2
    jmp lbb_lr_effect_done
lbb_lr_read_fd_stat:
    call lbb_lr_fd_only
    mov rsi, rsp
    mov eax, 5
    syscall
    mov ebp, 2
    jmp lbb_lr_effect_done
lbb_lr_read_bytes:
    cmp qword ptr [r12 + 24], 1
    jne lbb_lr_contract_fail
    mov rdi, qword ptr [r15 + 72]
    test rdi, rdi
    jz lbb_lr_contract_fail
    dec rdi
    mov rsi, qword ptr [r12 + 32]
    mov rdx, qword ptr [r12 + 40]
    cmp qword ptr [rbx], 21
    jne lbb_lr_read_regular
    cmp rsi, 768
    jne lbb_lr_contract_fail
    cmp rdx, 32
    jne lbb_lr_contract_fail
    jmp lbb_lr_read_span_ready
lbb_lr_read_regular:
    mov rax, qword ptr [rbx + 56]
    cmp rax, 1024
    jb lbb_lr_contract_fail
    add rax, qword ptr [rbx + 160]
    jc lbb_lr_contract_fail
    cmp rsi, rax
    jne lbb_lr_contract_fail
    mov rax, qword ptr [rbx + 152]
    sub rax, qword ptr [rbx + 160]
    jc lbb_lr_contract_fail
    cmp rax, qword ptr [rbx + 176]
    cmova rax, qword ptr [rbx + 176]
    cmp rdx, rax
    jne lbb_lr_contract_fail
    test rdx, rdx
    jz lbb_lr_contract_fail
lbb_lr_read_span_ready:
    cmp rsi, qword ptr [r15 + 24]
    ja lbb_lr_contract_fail
    mov rax, qword ptr [r15 + 24]
    sub rax, rsi
    cmp rdx, rax
    ja lbb_lr_contract_fail
    add rsi, rbx
    xor eax, eax
    syscall
    mov ebp, 4
    jmp lbb_lr_effect_done
lbb_lr_read_close:
    call lbb_lr_fd_only
    mov qword ptr [r15 + 72], 0
    mov eax, 3
    syscall
    xor ebp, ebp
lbb_lr_effect_done:
    cmp rax, -4095
    jae lbb_lr_effect_error
    cmp ebp, 1
    jne lbb_lr_effect_stat64
    test rax, rax
    jnz lbb_lr_contract_fail
    mov rax, qword ptr [rsp + 40]
    mov qword ptr [r12 + 72], rax
    cmp qword ptr [rbx + 16], 3
    jne lbb_lr_effect_completed
    movzx eax, word ptr [rsp + 28]
    mov qword ptr [r12 + 88], rax
    jmp lbb_lr_effect_completed
lbb_lr_effect_stat64:
    cmp ebp, 2
    jne lbb_lr_effect_opened
    test rax, rax
    jnz lbb_lr_contract_fail
    mov rax, qword ptr [rsp + 48]
    mov qword ptr [r12 + 72], rax
    cmp qword ptr [rbx + 16], 3
    jne lbb_lr_effect_completed
    mov eax, dword ptr [rsp + 24]
    mov qword ptr [r12 + 88], rax
    jmp lbb_lr_effect_completed
lbb_lr_effect_opened:
    cmp ebp, 3
    jne lbb_lr_effect_read
    inc rax
    jz lbb_lr_contract_fail
    mov qword ptr [r15 + 72], rax
    mov qword ptr [r12 + 72], 1
    jmp lbb_lr_effect_completed
lbb_lr_effect_read:
    cmp ebp, 4
    jne lbb_lr_effect_unit
    cmp rax, qword ptr [r12 + 40]
    ja lbb_lr_contract_fail
    mov qword ptr [r12 + 56], rax
    jmp lbb_lr_effect_completed
lbb_lr_effect_unit:
    test rax, rax
    jnz lbb_lr_contract_fail
    jmp lbb_lr_effect_completed
lbb_lr_effect_error:
    neg rax
    mov qword ptr [r12 + 64], rax
lbb_lr_effect_completed:
    mov qword ptr [r12 + 80], 1
    jmp lbb_lr_read_invoke

lbb_lr_sequence_admit:
    mov rax, qword ptr [r15 + 88]
    inc rax
    jz lbb_lr_contract_fail
    cmp qword ptr [r12 + 8], rax
    jne lbb_lr_contract_fail
    cmp qword ptr [rbx + 72], rax
    jne lbb_lr_contract_fail
    mov qword ptr [r15 + 88], rax
    mov rax, qword ptr [r12 + 48]
    or rax, qword ptr [r12 + 56]
    or rax, qword ptr [r12 + 64]
    or rax, qword ptr [r12 + 72]
    or rax, qword ptr [r12 + 80]
    or rax, qword ptr [r12 + 88]
    jnz lbb_lr_contract_fail
    ret
lbb_lr_path_admit:
    cmp qword ptr [r12 + 24], 1024
    jne lbb_lr_contract_fail
    mov rcx, qword ptr [rbx + 48]
    cmp qword ptr [r12 + 32], rcx
    jne lbb_lr_contract_fail
    cmp qword ptr [r12 + 40], 0
    jne lbb_lr_contract_fail
    mov rax, qword ptr [r15 + 24]
    sub rax, 1024
    jc lbb_lr_contract_fail
    cmp rcx, rax
    jae lbb_lr_contract_fail
    lea rax, [rbx + 1024]
    cmp byte ptr [rax + rcx], 0
    jne lbb_lr_contract_fail
    xor edx, edx
lbb_lr_path_scan:
    cmp rdx, rcx
    je lbb_lr_path_done
    cmp byte ptr [rax + rdx], 0
    je lbb_lr_contract_fail
    inc rdx
    jmp lbb_lr_path_scan
lbb_lr_path_done:
    ret
lbb_lr_zero_arguments:
    mov rax, qword ptr [r12 + 24]
    or rax, qword ptr [r12 + 32]
    or rax, qword ptr [r12 + 40]
    jnz lbb_lr_contract_fail
    ret
lbb_lr_fd_only:
    cmp qword ptr [r12 + 24], 1
    jne lbb_lr_contract_fail
    mov rax, qword ptr [r12 + 32]
    or rax, qword ptr [r12 + 40]
    jnz lbb_lr_contract_fail
    mov rdi, qword ptr [r15 + 72]
    test rdi, rdi
    jz lbb_lr_contract_fail
    dec rdi
    ret

# rbp is the fixed context offset of (pointer, capacity), never input data.
lbb_lr_resize_buffer:
    push r15
    mov rsi,rdi
    lea rdi,[r15+rbp]
    mov edx,1
    mov r15,[r15+96]
    call lbb_ensure_region
    pop r15
    ret

lbb_lr_cleanup:
    mov rdi, qword ptr [r15 + 72]
    mov qword ptr [r15 + 72], 0
    test rdi, rdi
    jz lbb_lr_cleanup_done
    dec rdi
    mov eax, 3
    syscall
lbb_lr_cleanup_done:
    ret
lbb_lr_contract_fail:
    call lbb_lr_cleanup
    mov edi, 70
    jmp lbb_lr_child_exit
lbb_lr_memory_fail:
    call lbb_lr_cleanup
    mov edi, 71
    jmp lbb_lr_child_exit
lbb_lr_io_fail:
    call lbb_lr_cleanup
    mov edi, 74
    jmp lbb_lr_child_exit
lbb_lr_allocation_abort:
    call lbb_lr_cleanup
    mov edi, 134
lbb_lr_child_exit:
    mov r15,[r15+96]
    jmp lbb_callable_abort
lbb_lr_empty_path:
    .byte 0

lbb_key_run:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp, 520
    mov r15, rdi
    cmp qword ptr [r15 + 72], -1
    jne lbb_key_contract_fail
    cmp qword ptr [r15 + 80], -1
    jne lbb_key_contract_fail
    mov rdi, qword ptr [r15 + 16]
    xor eax, eax
    mov ecx, 128
    rep stosq
    mov rbx, qword ptr [r15 + 16]
    mov rax, qword ptr [r15 + 64]
    mov qword ptr [rbx + 176], rax
    mov qword ptr [r15 + 88], 0
lbb_key_invoke:
    mov rdi, qword ptr [r15]
    mov rsi, qword ptr [r15 + 48]
    mov rdx, qword ptr [r15 + 32]
    mov rcx, qword ptr [r15 + 40]
    mov r8, qword ptr [r15 + 16]
    mov r9, qword ptr [r15 + 24]
    call qword ptr [r15 + 96]
    mov edx, eax
    cmp rax, rdx
    jne lbb_key_contract_fail
    mov rbx, qword ptr [r15 + 16]
    cmp eax, 0xffffffef
    je lbb_key_grow_workspace
    cmp eax, 0xffffffee
    je lbb_key_grow_output
    cmp eax, 0xfffffff0
    je lbb_key_admit_effect
    cmp eax, 0xffffffff
    je lbb_key_refusal
    cmp eax, 0xfffffffe
    je lbb_key_refusal
    cmp eax, 0xfffffff9
    je lbb_key_contract_fail
    cmp eax, 32
    jb lbb_key_contract_fail
    cmp rax, qword ptr [r15 + 40]
    ja lbb_key_contract_fail
    cmp qword ptr [rbx], 100
    jne lbb_key_contract_fail
    mov rdx, qword ptr [r15 + 32]
    mov rcx, 0x313030594b4c5248
    cmp qword ptr [rdx], rcx
    jne lbb_key_contract_fail
    lea rcx, [rax - 32]
    cmp qword ptr [rdx + 16], rcx
    jne lbb_key_contract_fail
    cmp qword ptr [rdx + 24], 0
    jne lbb_key_contract_fail
    cmp qword ptr [r15 + 72], -1
    jne lbb_key_contract_fail
    cmp qword ptr [r15 + 80], -1
    jne lbb_key_contract_fail
    mov dword ptr [r15 + 56], eax
    jmp lbb_key_done
lbb_key_refusal:
    mov dword ptr [r15 + 56], eax
    call lbb_key_cleanup
    jmp lbb_key_done

lbb_key_grow_workspace:
    mov rdi, qword ptr [rbx + 40]
    cmp rdi, qword ptr [rbx + 32]
    jbe lbb_key_contract_fail
    mov rax, 0x1ffffffffffbfeff
    cmp rdi, rax
    ja lbb_key_memory_fail
    shl rdi, 2
    add rdi, 1049600
    jc lbb_key_memory_fail
    call lbb_callable_key_round
    mov r12, rax
    cmp r12, qword ptr [r15 + 24]
    jbe lbb_key_invoke
    mov rdi, r12
    call lbb_callable_key_allocate
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
    jnz lbb_key_io_fail
    jmp lbb_key_invoke
lbb_key_grow_output:
    mov rdi, qword ptr [rbx + 48]
    cmp rdi, qword ptr [r15 + 40]
    jbe lbb_key_contract_fail
    mov rax, 0xffffffef
    cmp rdi, rax
    ja lbb_key_contract_fail
    call lbb_callable_key_round
    mov r12, rax
    mov rdi, r12
    call lbb_callable_key_allocate
    mov r13, rax
    mov rdi, qword ptr [r15 + 32]
    mov rsi, qword ptr [r15 + 40]
    add rsi, 4096
    mov qword ptr [r15 + 32], r13
    mov qword ptr [r15 + 40], r12
    mov eax, 11
    syscall
    test rax, rax
    jnz lbb_key_io_fail
    jmp lbb_key_invoke

lbb_key_admit_effect:
    mov rax, qword ptr [r15 + 48]
    cmp qword ptr [rbx + 8], rax
    jne lbb_key_contract_fail
    mov rax, qword ptr [r15 + 40]
    cmp qword ptr [rbx + 16], rax
    jne lbb_key_contract_fail
    mov rax, qword ptr [r15 + 24]
    cmp qword ptr [rbx + 24], rax
    jne lbb_key_contract_fail
    mov rax, qword ptr [rbx + 40]
    or rax, qword ptr [rbx + 48]
    jnz lbb_key_contract_fail
    mov rax, qword ptr [rbx + 32]
    cmp rax, 1024
    jb lbb_key_contract_fail
    lea rcx, [rax - 1]
    test rcx, rax
    jnz lbb_key_contract_fail
    cmp qword ptr [rbx + 96], rax
    jae lbb_key_contract_fail
    mov rcx, 0x1ffffffffffbfeff
    cmp rax, rcx
    ja lbb_key_contract_fail
    shl rax, 2
    add rax, 1049600
    jc lbb_key_contract_fail
    cmp rax, qword ptr [r15 + 24]
    ja lbb_key_contract_fail
    mov rax, 0x584659454b4c4648
    cmp qword ptr [rbx + 512], rax
    jne lbb_key_contract_fail
    inc qword ptr [r15 + 88]
    jz lbb_key_contract_fail
    mov rax, qword ptr [r15 + 88]
    cmp qword ptr [rbx + 520], rax
    jne lbb_key_contract_fail
    cmp qword ptr [rbx + 56], rax
    jne lbb_key_contract_fail
    mov rax, qword ptr [rbx + 568]
    or rax, qword ptr [rbx + 576]
    or rax, qword ptr [rbx + 584]
    or rax, qword ptr [rbx + 592]
    or rax, qword ptr [rbx + 600]
    or rax, qword ptr [rbx + 608]
    or rax, qword ptr [rbx + 616]
    or rax, qword ptr [rbx + 624]
    or rax, qword ptr [rbx + 632]
    jnz lbb_key_contract_fail
    mov r14, qword ptr [rbx + 528]
    cmp r14, 1
    je lbb_key_get_current
    cmp r14, 2
    je lbb_key_read_link
    cmp r14, 3
    je lbb_key_access_path
    cmp r14, 4
    je lbb_key_access_path
    cmp r14, 5
    je lbb_key_lstat_path
    cmp r14, 6
    je lbb_key_access_path
    cmp r14, 7
    je lbb_key_open_parent
    cmp r14, 8
    je lbb_key_stat_descriptor
    cmp r14, 9
    je lbb_key_close_descriptor
    cmp r14, 10
    je lbb_key_get_flags
    cmp r14, 11
    je lbb_key_set_cloexec
    cmp r14, 12
    je lbb_key_directory_entries
    cmp r14, 13
    je lbb_key_rewind_directory
    jmp lbb_key_contract_fail

lbb_key_get_current:
    cmp qword ptr [rbx], 10
    jne lbb_key_contract_fail
    call lbb_key_resolved_argument
    mov rdx, qword ptr [rbx + 552]
    or rdx, qword ptr [rbx + 560]
    jnz lbb_key_contract_fail
    mov rsi, qword ptr [rbx + 544]
    cmp rsi, qword ptr [rbx + 152]
    jne lbb_key_contract_fail
    cmp rsi, 1024
    jb lbb_key_contract_fail
    cmp rsi, qword ptr [rbx + 32]
    ja lbb_key_contract_fail
    mov eax, 79
    syscall
    jmp lbb_key_value_completion

lbb_key_read_link:
    cmp qword ptr [rbx], 3
    jne lbb_key_contract_fail
    call lbb_key_resolved_argument
    mov rcx, qword ptr [rbx + 544]
    cmp rcx, qword ptr [rbx + 96]
    jne lbb_key_contract_fail
    call lbb_key_cstring
    mov rax, qword ptr [rbx + 32]
    lea rax, [rax + rax + 1024]
    cmp qword ptr [rbx + 552], rax
    jne lbb_key_contract_fail
    lea rsi, [rbx + rax]
    mov rdx, qword ptr [rbx + 144]
    cmp rdx, 1024
    jb lbb_key_contract_fail
    dec rdx
    cmp rdx, qword ptr [rbx + 560]
    jne lbb_key_contract_fail
    cmp rdx, qword ptr [rbx + 32]
    jae lbb_key_contract_fail
    mov eax, 89
    syscall
    jmp lbb_key_value_completion

lbb_key_access_path:
    cmp qword ptr [rbx], 4
    jne lbb_key_contract_fail
    call lbb_key_resolved_argument
    mov rcx, qword ptr [rbx + 96]
    inc rcx
    cmp rcx, qword ptr [rbx + 32]
    jae lbb_key_contract_fail
    cmp rcx, qword ptr [rbx + 544]
    jne lbb_key_contract_fail
    call lbb_key_cstring
    mov rax, qword ptr [rbx + 552]
    or rax, qword ptr [rbx + 560]
    jnz lbb_key_contract_fail
    mov rsi, rdi
    mov edi, -100
    xor edx, edx
    mov r10d, 512
    mov eax, 439
    cmp r14, 3
    je lbb_key_access_go
    cmp r14, 4
    jne lbb_key_stat_access
    cmp qword ptr [r15 + 64], 0
    jne lbb_key_contract_fail
    mov eax, 269
lbb_key_access_go:
    syscall
    jmp lbb_key_zero_completion
lbb_key_stat_access:
    cmp qword ptr [r15 + 64], 1
    jne lbb_key_contract_fail
    xor r10d, r10d
    jmp lbb_key_stat_at

lbb_key_lstat_path:
    mov rax, qword ptr [rbx]
    cmp rax, 12
    je lbb_key_lstat_fixed
    cmp rax, 13
    je lbb_key_lstat_fixed
    cmp rax, 24
    jne lbb_key_contract_fail
    mov rax, qword ptr [rbx + 32]
    lea rax, [rax * 4 + 1024]
    add rax, qword ptr [rbx + 368]
    jc lbb_key_contract_fail
    cmp rax, qword ptr [rbx + 536]
    jne lbb_key_contract_fail
    mov rcx, qword ptr [rbx + 376]
    cmp rcx, qword ptr [rbx + 544]
    jne lbb_key_contract_fail
    mov rdx, qword ptr [rbx + 552]
    cmp rdx, qword ptr [rbx + 160]
    jne lbb_key_contract_fail
    jmp lbb_key_lstat_arguments
lbb_key_lstat_fixed:
    mov rax, qword ptr [rbx + 32]
    lea rax, [rax + rax + 1024]
    cmp rax, qword ptr [rbx + 536]
    jne lbb_key_contract_fail
    mov ecx, 1
    cmp qword ptr [rbx + 544], 1
    jne lbb_key_contract_fail
    cmp qword ptr [rbx + 552], 0
    jne lbb_key_contract_fail
    xor edx, edx
    cmp qword ptr [rbx], 12
    jne lbb_key_lstat_root
    cmp byte ptr [rbx + rax], 46
    jne lbb_key_contract_fail
    jmp lbb_key_lstat_arguments
lbb_key_lstat_root:
    cmp byte ptr [rbx + rax], 47
    jne lbb_key_contract_fail
lbb_key_lstat_arguments:
    cmp qword ptr [rbx + 560], 0
    jne lbb_key_contract_fail
    lea rdi, [rbx + rax]
    call lbb_key_cstring
    mov rsi, rdi
    mov edi, -100
    test rdx, rdx
    jz lbb_key_lstat_cwd
    call lbb_key_descriptor
lbb_key_lstat_cwd:
    mov r10d, 256
lbb_key_stat_at:
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
    jmp lbb_key_stat_completion

lbb_key_open_parent:
    cmp qword ptr [rbx], 15
    jne lbb_key_contract_fail
    mov rax, qword ptr [rbx + 552]
    or rax, qword ptr [rbx + 560]
    jnz lbb_key_contract_fail
    mov r12, qword ptr [rbx + 536]
    cmp r12, 1
    jb lbb_key_contract_fail
    cmp r12, 2
    ja lbb_key_contract_fail
    cmp qword ptr [r15 + r12 * 8 + 64], -1
    jne lbb_key_contract_fail
    mov rdx, qword ptr [rbx + 544]
    cmp rdx, qword ptr [rbx + 160]
    jne lbb_key_contract_fail
    cmp rdx, r12
    je lbb_key_contract_fail
    mov edi, -100
    test rdx, rdx
    jz lbb_key_open_parent_cwd
    call lbb_key_descriptor
lbb_key_open_parent_cwd:
    lea rsi, [rip + lbb_key_parent_name]
    xor edx, edx
    xor r10d, r10d
    mov eax, 257
    syscall
    test rax, rax
    js lbb_key_error_completion
    cmp rax, 0x7fffffff
    ja lbb_key_contract_fail
    mov qword ptr [r15 + r12 * 8 + 64], rax
    mov rax, r12
    jmp lbb_key_value_completion

lbb_key_stat_descriptor:
    mov rax, qword ptr [rbx]
    cmp rax, 16
    je lbb_key_stat_descriptor_phase
    cmp rax, 18
    jne lbb_key_contract_fail
lbb_key_stat_descriptor_phase:
    call lbb_key_zero_trailing_args
    mov rdx, qword ptr [rbx + 536]
    cmp rdx, qword ptr [rbx + 168]
    jne lbb_key_contract_fail
    call lbb_key_descriptor
    mov r13, rdi
    mov rdi, rsp
    xor eax, eax
    mov ecx, 32
    rep stosq
    mov rdi, r13
    mov rsi, rsp
    mov eax, 5
    syscall
lbb_key_stat_completion:
    test rax, rax
    js lbb_key_error_completion
    test rax, rax
    jnz lbb_key_contract_fail
    mov rax, qword ptr [rsp]
    mov qword ptr [rbx + 584], rax
    mov rax, qword ptr [rsp + 8]
    mov qword ptr [rbx + 592], rax
    mov eax, dword ptr [rsp + 24]
    mov qword ptr [rbx + 600], rax
    mov rax, qword ptr [rsp + 56]
    mov qword ptr [rbx + 616], rax
    jmp lbb_key_acknowledge

lbb_key_close_descriptor:
    mov rax, qword ptr [rbx]
    cmp rax, 17
    je lbb_key_close_phase
    cmp rax, 27
    je lbb_key_close_phase
    cmp rax, 29
    jne lbb_key_contract_fail
lbb_key_close_phase:
    call lbb_key_zero_trailing_args
    mov rdx, qword ptr [rbx + 536]
    call lbb_key_descriptor
    mov qword ptr [r15 + rdx * 8 + 64], -1
    mov eax, 3
    syscall
    jmp lbb_key_zero_completion

lbb_key_get_flags:
    cmp qword ptr [rbx], 19
    jne lbb_key_contract_fail
    call lbb_key_zero_trailing_args
    mov rdx, qword ptr [rbx + 536]
    cmp rdx, qword ptr [rbx + 168]
    jne lbb_key_contract_fail
    call lbb_key_descriptor
    mov esi, 3
    xor edx, edx
    mov eax, 72
    syscall
    jmp lbb_key_value_completion
lbb_key_set_cloexec:
    cmp qword ptr [rbx], 20
    jne lbb_key_contract_fail
    call lbb_key_zero_trailing_args
    mov rdx, qword ptr [rbx + 536]
    cmp rdx, qword ptr [rbx + 168]
    jne lbb_key_contract_fail
    call lbb_key_descriptor
    mov esi, 2
    mov edx, 1
    mov eax, 72
    syscall
    jmp lbb_key_zero_completion

lbb_key_directory_entries:
    cmp qword ptr [rbx], 22
    jne lbb_key_contract_fail
    cmp qword ptr [rbx + 560], 0
    jne lbb_key_contract_fail
    mov rax, qword ptr [rbx + 32]
    lea rax, [rax * 4 + 1024]
    cmp rax, qword ptr [rbx + 544]
    jne lbb_key_contract_fail
    mov r12, qword ptr [rbx + 552]
    cmp r12, 32768
    jb lbb_key_contract_fail
    cmp r12, 1048576
    ja lbb_key_contract_fail
    cmp r12, qword ptr [rbx + 336]
    jne lbb_key_contract_fail
    lea rsi, [rbx + rax]
    mov rdx, qword ptr [rbx + 536]
    cmp rdx, qword ptr [rbx + 160]
    jne lbb_key_contract_fail
    call lbb_key_descriptor
    mov rdx, r12
    mov eax, 217
    syscall
    jmp lbb_key_value_completion
lbb_key_rewind_directory:
    cmp qword ptr [rbx], 23
    jne lbb_key_contract_fail
    call lbb_key_zero_trailing_args
    mov rdx, qword ptr [rbx + 536]
    cmp rdx, qword ptr [rbx + 160]
    jne lbb_key_contract_fail
    call lbb_key_descriptor
    xor esi, esi
    xor edx, edx
    mov eax, 8
    syscall
    jmp lbb_key_value_completion

lbb_key_resolved_argument:
    mov rax, qword ptr [rbx + 32]
    add rax, 1024
    cmp qword ptr [rbx + 536], rax
    jne lbb_key_contract_fail
    lea rdi, [rbx + rax]
    ret
lbb_key_zero_trailing_args:
    mov rax, qword ptr [rbx + 544]
    or rax, qword ptr [rbx + 552]
    or rax, qword ptr [rbx + 560]
    jnz lbb_key_contract_fail
    ret
# logical slot in rdx -> real lbb_key_descriptor in rdi, preserving other arguments.
lbb_key_descriptor:
    cmp rdx, 1
    jb lbb_key_contract_fail
    cmp rdx, 2
    ja lbb_key_contract_fail
    mov rdi, qword ptr [r15 + rdx * 8 + 64]
    test rdi, rdi
    js lbb_key_contract_fail
    ret
# Exact span containment and unique final NUL.  rdx is preserved for dirfd.
lbb_key_cstring:
    mov rax, rdi
    sub rax, rbx
    jc lbb_key_contract_fail
    cmp rax, qword ptr [r15 + 24]
    jae lbb_key_contract_fail
    mov r11, qword ptr [r15 + 24]
    sub r11, rax
    cmp rcx, r11
    jae lbb_key_contract_fail
    cmp byte ptr [rdi + rcx], 0
    jne lbb_key_contract_fail
    xor eax, eax
lbb_key_cstring_loop:
    cmp rax, rcx
    je lbb_key_cstring_done
    cmp byte ptr [rdi + rax], 0
    je lbb_key_contract_fail
    inc rax
    jmp lbb_key_cstring_loop
lbb_key_cstring_done:
    ret
lbb_key_value_completion:
    test rax, rax
    js lbb_key_error_completion
    mov qword ptr [rbx + 568], rax
    jmp lbb_key_acknowledge
lbb_key_zero_completion:
    test rax, rax
    js lbb_key_error_completion
    test rax, rax
    jnz lbb_key_contract_fail
    jmp lbb_key_acknowledge
lbb_key_error_completion:
    neg rax
    cmp rax, 4095
    ja lbb_key_contract_fail
    mov qword ptr [rbx + 576], rax
lbb_key_acknowledge:
    mov qword ptr [rbx + 608], 1
    jmp lbb_key_invoke

lbb_key_cleanup:
    mov rdi, qword ptr [r15 + 72]
    mov qword ptr [r15 + 72], -1
    test rdi, rdi
    js lbb_key_cleanup_second
    mov eax, 3
    syscall
lbb_key_cleanup_second:
    mov rdi, qword ptr [r15 + 80]
    mov qword ptr [r15 + 80], -1
    test rdi, rdi
    js lbb_key_cleanup_done
    mov eax, 3
    syscall
lbb_key_cleanup_done:
    ret
lbb_key_done:
    mov eax, dword ptr [r15 + 56]
    add rsp, 520
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret
lbb_key_contract_fail:
    call lbb_key_cleanup
    mov edi, 70
    jmp lbb_fatal_exit
lbb_key_memory_fail:
    call lbb_key_cleanup
    mov edi, 71
    jmp lbb_fatal_exit
lbb_key_io_fail:
    call lbb_key_cleanup
    mov edi, 74
    jmp lbb_fatal_exit
lbb_key_parent_name:
    .asciz ".."

lbb_callable_key_round:
    push r15
    mov r15,[r15+104]
    call lbb_round_capacity
    pop r15
    ret
lbb_callable_key_allocate:
    push r15
    mov r15,[r15+104]
    call lbb_allocate_guarded
    pop r15
    ret

.balign 16,0
image_table:
.quad 0,0,0,0,0,0,0,0,0,0,0,0,0,0
.balign 16,0
images:
