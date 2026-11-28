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
    cmp ecx,12
    jb install_images
    mov edi,3
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
    cmp qword ptr [r15+INLEN],134217728
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
    mov rax,0x3130515242544c48
    cmp [rbx],rax
    jne frame_refused
    cmp qword ptr [r15+INLEN],80
    jb frame_refused
    mov rax,[rbx+56]
    mov [r15+GENERATION],rax
    mov qword ptr [r15+HINTLEN],0
    mov qword ptr [r15+HINTCOUNT],0
    call fixture_bind_context
    xor edi,edi
    call observe_states
    lea rdi,[r15+1280]
    mov rsi,[r15+INPUT]
    mov rdx,[r15+INLEN]
    call local_text_body_run
    cmp eax,0xffffffdf
    je pending_unimplemented
    cmp eax,0xffff0000
    jae frame_code
    cmp qword ptr [r15+1416],1
    jne contract
    cmp qword ptr [r15+1424],1
    jne contract
    cmp [r15+1400],rax
    jne contract
    mov [r15+CHILDCODE],rax
    mov rax,[r15+1392]
    mov [r15+CHILDOUT],rax
    call observe_hints
    mov edi,1
    call observe_states
    jmp publish_result
fixture_cache:
    mov edi,8
    jmp fixture_call
fixture_history:
    mov edi,6
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
    call local_text_body_release
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
    cmp r14,11
    ja contract
    mov r12,rsi
    mov r13,rdx
    cmp r13,134217728
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
    cmp eax,0xffffffef
    je pure_work_need
    cmp eax,0xffffffee
    je pure_output_need
    cmp eax,0xfffffffe
    je pure_capacity
    cmp eax,0xffff0000
    jae pure_return
    cmp rax,[rbx+32]
    ja contract
    cmp r14,3
    jne pure_return
    cmp eax,64
    jne pure_return
    mov rcx,[rbx+24]
    cmp qword ptr [rcx+16],2
    jne pure_return
    mov rsi,[rcx+32]
    jmp pure_grow_work
pure_work_need:
    cmp r14,0
    je pure_work_pointer
    cmp r14,5
    je pure_work_pointer
    cmp r14,9
    jne contract
pure_work_pointer:
    mov rax,[rbx+8]
    mov rsi,[rax+144]
pure_grow_work:
    cmp rsi,[rbx+16]
    jbe contract
    cmp rsi,268435456
    ja resource
    lea rdi,[rbx+8]
    mov edx,1
    call ensure_region
    jmp pure_again
pure_output_need:
    cmp r14,0
    je pure_output_pointer
    cmp r14,5
    je pure_output_pointer
    cmp r14,9
    jne contract
pure_output_pointer:
    mov rax,[rbx+8]
    mov rsi,[rax+152]
    cmp rsi,[rbx+32]
    jbe contract
    cmp rsi,134217728
    ja resource
    lea rdi,[rbx+24]
    xor edx,edx
    call ensure_region
    jmp pure_again
pure_capacity:
    cmp r14,4
    je pure_capacity_grow
    cmp r14,6
    je pure_capacity_grow
    cmp r14,8
    jne resource
pure_capacity_grow:
    mov rsi,[rbx+16]
    shl rsi,1
    jc resource
    cmp rsi,268435456
    ja resource
    lea rdi,[rbx+8]
    mov edx,1
    call ensure_region
    mov rsi,[rbx+32]
    shl rsi,1
    jc resource
    cmp rsi,134217728
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
    mov ebx,3
observe_one:
    mov rbp,rbx
    shl rbp,6
    lea rbp,[r15+SLOTS+rbp]
    mov rdi,rsp
    xor eax,eax
    mov ecx,8
    rep stosq
    mov rax,0x3130414e42544c48
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
    cmp ebx,3
    jne observe_second
    mov ebx,6
    jmp observe_one
observe_second:
    cmp ebx,6
    jne observe_done
    mov ebx,8
    jmp observe_one
observe_done:
    add rsp,64
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

observe_hints:
    push rbx
    sub rsp,48
    mov rax,0x3130544842544c48
    mov [rsp],rax
    mov rax,[r15+HINTLEN]
    add rax,48
    jc resource
    mov [rsp+8],rax
    mov rax,[r15+GENERATION]
    mov [rsp+16],rax
    mov rax,[r15+INPUT]
    mov rax,[rax+8]
    mov [rsp+24],rax
    mov rax,[r15+CHILDOUT]
    mov rax,[rax+16]
    mov [rsp+32],rax
    mov rax,[r15+HINTCOUNT]
    mov [rsp+40],rax
    mov edi,2
    mov rsi,rsp
    mov edx,48
    call write_all
    mov edi,2
    mov rsi,[r15+HINTS]
    mov rdx,[r15+HINTLEN]
    call write_all
    add rsp,48
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
    mov rax,0x3130494342544c48
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
    cmp ecx,12
    jb fixture_copy_entries
    lea rax,[rip+fixture_cache_callback]
    mov [r15+1304],rax
    mov [r15+1312],r15
    lea rax,[rip+fixture_hint_callback]
    mov [r15+1320],rax
    mov [r15+1328],r15
    lea rax,[r15+SLOTS+192]
    mov [r15+1336],rax
    lea rax,[r15+SLOTS+384]
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
    mov edi,8
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
    cmp esi,3
    je fixture_shared_selected
    cmp esi,6
    jne contract
fixture_shared_selected:
    shl rsi,6
    lea rbx,[r15+SLOTS+rsi]
    cmp r12,[rbx+16]
    jb contract
    cmp r13,[rbx+32]
    jb contract
    cmp r12,268435456
    ja resource
    cmp r13,134217728
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
    push r15
    push rbx
    push r12
    mov r15,rdi
    mov rbx,rsi
    mov r12,rcx
    mov rcx,rdx
    cmp rcx,32
    jb contract
    sub rcx,32
    cmp [rbx+16],rcx
    jne contract
    mov rax,0x3130514842544c48
    cmp [rbx],rax
    jne contract
    cmp qword ptr [rbx+24],0
    jne contract
    cmp qword ptr [rbx+8],2
    je fixture_hint_done
    cmp qword ptr [rbx+8],1
    jne contract
    mov rsi,[r15+HINTLEN]
    add rsi,8
    jc resource
    add rsi,rcx
    jc resource
    lea rdi,[r15+HINTS]
    mov edx,1
    call ensure_region
    mov rdi,[r15+HINTS]
    add rdi,[r15+HINTLEN]
    mov rcx,[rbx+16]
    mov [rdi],rcx
    add rdi,8
    lea rsi,[rbx+32]
    add [r15+HINTLEN],rcx
    add qword ptr [r15+HINTLEN],8
    inc qword ptr [r15+HINTCOUNT]
    jz resource
    rep movsb
fixture_hint_done:
    lea rax,[rip+hint_response]
    mov [r12],rax
    mov qword ptr [r12+8],32
    mov eax,32
    pop r12
    pop rbx
    pop r15
    ret

.intel_syntax noprefix
.text
.equ ltb_INPUT,0
.equ ltb_INCAP,8
.equ ltb_INLEN,16
.equ ltb_CALLBACK,24
.equ ltb_CBCAP,32
.equ ltb_CURRENT,40
.equ ltb_CURLEN,48
.equ ltb_CHILD,56
.equ ltb_SEQUENCE,64
.equ ltb_GENERATION,72
.equ ltb_HINTS,80
.equ ltb_HINTCAP,88
.equ ltb_HINTLEN,96
.equ ltb_HINTCOUNT,104
.equ ltb_CHILDREQ,112
.equ ltb_CHILDREQLEN,120
.equ ltb_CHILDOUT,128
.equ ltb_CHILDCODE,136
.equ ltb_OBS_PHASE,144
.equ ltb_SECURE,152
.equ ltb_SLOTS,256
.equ ltb_READCTX,2048
.equ ltb_KEYCTX,2176
.equ ltb_ATOMICCTX,2304
.equ ltb_META_BYTE,2432
.global local_text_body_run
.global local_text_body_resume
.global local_text_body_cancel_wait
.global local_text_body_release
.equ ltb_PUBLIC_CTX,1024
.equ ltb_RETURN_STACK,1032
.equ ltb_META_POINTER,1040
.equ ltb_RESULT_PAIR,1048
.equ ltb_WAIT_FLAG,1064
.equ ltb_ABORTING,1072
.equ ltb_CLEAN_FRAME,1088
.equ ltb_CLEAN_OUTPUT,1152
.equ ltb_MAIN_TAG,192
.equ ltb_MAIN_MAGIC,0x31304d4242544c48
.equ ltb_CONTEXT_MAGIC,0x3130494342544c48

local_text_body_run:
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
    jz ltb_callable_invalid_early
    mov rax,ltb_CONTEXT_MAGIC
    cmp [rdi],rax
    jne ltb_callable_invalid_early
    cmp qword ptr [rdi+8],192
    jne ltb_callable_invalid_early
    cmp qword ptr [rdi+16],0
    je ltb_callable_invalid_early
    cmp qword ptr [rdi+24],0
    je ltb_callable_invalid_early
    cmp qword ptr [rdi+40],0
    je ltb_callable_invalid_early
    cmp qword ptr [rdi+72],0
    je ltb_callable_invalid_early
    cmp qword ptr [rdi+96],1
    ja ltb_callable_invalid_early
    cmp qword ptr [rdi+104],0
    jne ltb_callable_invalid_early
    mov ecx,112
ltb_callable_empty_fields:
    cmp qword ptr [rdi+rcx],0
    jne ltb_callable_invalid_early
    add ecx,8
    cmp ecx,192
    jb ltb_callable_empty_fields
    mov rax,[rdi+88]
    test rax,rax
    jz ltb_callable_invalid_early
    cmp byte ptr [rax],2
    ja ltb_callable_invalid_early
    mov rax,[rdi+16]
    xor ecx,ecx
ltb_callable_check_entries:
    cmp qword ptr [rax+rcx*8],0
    je ltb_callable_invalid_early
    inc ecx
    cmp ecx,12
    jb ltb_callable_check_entries
    mov ebx,3
ltb_callable_check_shared:
    mov rdx,[rdi+56]
    cmp ebx,3
    je ltb_callable_check_record
    mov rdx,[rdi+64]
ltb_callable_check_record:
    test rdx,rdx
    jz ltb_callable_invalid_early
    test dl,7
    jnz ltb_callable_invalid_early
    mov rcx,[rax+rbx*8]
    cmp [rdx],rcx
    jne ltb_callable_invalid_early
    cmp qword ptr [rdx+8],0
    je ltb_callable_invalid_early
    cmp qword ptr [rdx+16],4096
    jb ltb_callable_invalid_early
    cmp qword ptr [rdx+16],268435456
    ja ltb_callable_invalid_early
    test qword ptr [rdx+16],4095
    jnz ltb_callable_invalid_early
    cmp qword ptr [rdx+24],0
    je ltb_callable_invalid_early
    cmp qword ptr [rdx+32],4096
    jb ltb_callable_invalid_early
    cmp qword ptr [rdx+32],134217728
    ja ltb_callable_invalid_early
    test qword ptr [rdx+32],4095
    jnz ltb_callable_invalid_early
    mov rcx,[rdx+48]
    or rcx,[rdx+56]
    jnz ltb_callable_invalid_early
    cmp ebx,3
    jne ltb_callable_admitted
    mov ebx,6
    jmp ltb_callable_check_shared
ltb_callable_admitted:
    cmp qword ptr [rsp+16],134217728
    ja ltb_callable_capacity_early
    xor r15d,r15d
    mov edi,4096
    call ltb_allocate_guarded
    mov r15,rax
    mov rax,ltb_MAIN_MAGIC
    mov [r15+ltb_MAIN_TAG],rax
    mov rbx,[rsp]
    mov [r15+ltb_PUBLIC_CTX],rbx
    mov [r15+ltb_RETURN_STACK],rsp
    mov [rbx+152],r15
    mov rax,[rbx+88]
    mov [r15+ltb_META_POINTER],rax
    mov rax,[rbx+96]
    mov [r15+ltb_SECURE],rax
    mov qword ptr [r15+ltb_ATOMICCTX+80],-1
    mov rsi,[rbx+16]
    xor ecx,ecx
ltb_callable_install_entries:
    mov rax,[rsi+rcx*8]
    mov rdi,rcx
    shl rdi,6
    mov [r15+ltb_SLOTS+rdi],rax
    inc ecx
    cmp ecx,12
    jb ltb_callable_install_entries
    lea rdi,[r15+ltb_INPUT]
    mov rsi,[rsp+16]
    xor edx,edx
    call ltb_ensure_region
    mov rdi,[r15+ltb_INPUT]
    mov rsi,[rsp+8]
    mov rcx,[rsp+16]
    mov [r15+ltb_INLEN],rcx
    rep movsb
    mov rdi,[r15+ltb_INPUT]
    mov rsi,[r15+ltb_INCAP]
    mov edx,1
    call ltb_protection
    mov rax,[r15+ltb_INPUT]
    mov [r15+ltb_CURRENT],rax
    mov rax,[r15+ltb_INLEN]
    mov [r15+ltb_CURLEN],rax
    cmp rax,80
    jb ltb_body_invoke
    mov rax,[r15+ltb_INPUT]
    mov rax,[rax+56]
    mov [r15+ltb_GENERATION],rax
    jmp ltb_body_invoke
ltb_callable_invalid_early:
    mov eax,0xffffffff
    jmp ltb_callable_return_early
ltb_callable_capacity_early:
    mov eax,0xfffffffe
ltb_callable_return_early:
    mov rsp,r13
ltb_callable_restore:
    add rsp,24
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

/* The exposed suspension is the unchanged HIA file-lock WAIT. */
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
    mov qword ptr [r15+ltb_WAIT_FLAG],0
    mov rbx,[r15+ltb_PUBLIC_CTX]
    mov qword ptr [rbx+112],0
    mov qword ptr [rbx+120],0
    mov qword ptr [rbx+128],0
    lea rdi,[r15+ltb_CALLBACK]
    mov esi,48
    xor edx,edx
    call ltb_ensure_region
    mov rdi,[r15+ltb_CALLBACK]
    mov rsi,[r15+ltb_CBCAP]
    mov edx,3
    call ltb_protection
    mov rbx,[r15+ltb_CALLBACK]
    mov rax,0x31304b5742544c48
    mov [rbx],rax
    mov rdx,[r15+ltb_SLOTS+8]
    mov rax,[rdx+16]
    mov [rbx+8],rax
    mov rax,[rdx+40]
    mov [rbx+16],rax
    mov rax,[rdx+168]
    mov [rbx+24],rax
    mov qword ptr [rbx+32],0
    mov qword ptr [rbx+40],0
    mov rdi,rbx
    mov rsi,[r15+ltb_CBCAP]
    mov edx,1
    call ltb_protection
    mov [r15+ltb_CURRENT],rbx
    mov qword ptr [r15+ltb_CURLEN],48
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
    cmp qword ptr [rax+8],14
    jne ltb_callable_wait_bad
    cmp qword ptr [rax+48],0
    jne ltb_callable_wait_bad
    cmp qword ptr [rax+168],0
    je ltb_callable_wait_bad
    cmp qword ptr [rax+176],0
    jne ltb_callable_wait_bad
    xor eax,eax
    ret
ltb_callable_wait_bad:
    mov eax,0xffffffff
    ret

/* Only a returned WAIT may be dropped; this cancels no in-flight I/O. */
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
    call ltb_callable_drop_lease
    test eax,eax
    jnz ltb_contract
    mov qword ptr [r15+ltb_WAIT_FLAG],0
    mov eax,0xfffffff7
    jmp ltb_callable_complete

ltb_callable_wait:
    mov r10,[r15+ltb_PUBLIC_CTX]
    mov rax,[r15+ltb_SLOTS+24]
    mov [r10+112],rax
    mov qword ptr [r10+120],48
    mov eax,0xffffffdf
    mov [r10+128],rax
    mov qword ptr [r15+ltb_WAIT_FLAG],1
    mov eax,0xffffffdf
    jmp ltb_callable_return

ltb_callable_complete:
    mov r10,[r15+ltb_PUBLIC_CTX]
    cmp qword ptr [r10+136],0
    jne ltb_contract
    mov [r10+128],rax
    mov qword ptr [r10+112],0
    mov qword ptr [r10+120],0
    cmp eax,0xffff0000
    jae ltb_callable_complete_fields
    mov rcx,[r15+ltb_SLOTS+24]
    mov [r10+112],rcx
    mov [r10+120],rax
ltb_callable_complete_fields:
    mov qword ptr [r10+136],1
    mov qword ptr [r10+144],1
ltb_callable_return:
    mov rsp,[r15+ltb_RETURN_STACK]
    jmp ltb_callable_restore

ltb_callable_shared_growth:
    push rbp
    mov rbp,rsp
    and rsp,-16
    mov rdx,rsi
    mov rcx,rdi
    sub rsp,16
    mov [rsp],rdx
    mov [rsp+8],rcx
    mov r10,[r15+ltb_PUBLIC_CTX]
    mov rdi,[r10+80]
    mov rsi,r14
    call qword ptr [r10+72]
    test eax,eax
    jnz ltb_resource
    mov rax,[rsp]
    cmp [rbx+16],rax
    jb ltb_contract
    mov rax,[rsp+8]
    cmp [rbx+32],rax
    jb ltb_contract
    mov rax,r14
    shl rax,6
    mov rax,[r15+ltb_SLOTS+rax]
    cmp [rbx],rax
    jne ltb_contract
    mov rax,[rbx+48]
    or rax,[rbx+56]
    jnz ltb_contract
    cmp qword ptr [rbx+8],0
    je ltb_contract
    cmp qword ptr [rbx+24],0
    je ltb_contract
    cmp qword ptr [rbx+16],268435456
    ja ltb_contract
    cmp qword ptr [rbx+32],134217728
    ja ltb_contract
    test qword ptr [rbx+16],4095
    jnz ltb_contract
    test qword ptr [rbx+32],4095
    jnz ltb_contract
    mov rsp,rbp
    pop rbp
    ret

ltb_callable_cache:
    mov r10,[r15+ltb_PUBLIC_CTX]
    mov r11,[r10+24]
    mov rdi,[r10+32]
    jmp ltb_callable_external
ltb_callable_hint:
    mov r10,[r15+ltb_PUBLIC_CTX]
    mov r11,[r10+40]
    mov rdi,[r10+48]
ltb_callable_external:
    mov qword ptr [r15+ltb_RESULT_PAIR],0
    mov qword ptr [r15+ltb_RESULT_PAIR+8],0
    mov rsi,[r15+ltb_CHILDREQ]
    mov rdx,[r15+ltb_CHILDREQLEN]
    lea rcx,[r15+ltb_RESULT_PAIR]
    call r11
    cmp rax,32
    jne ltb_contract
    cmp qword ptr [r15+ltb_RESULT_PAIR+8],32
    jne ltb_contract
    mov rcx,[r15+ltb_RESULT_PAIR]
    test rcx,rcx
    jz ltb_contract
    mov [r15+ltb_CHILDOUT],rcx
    jmp ltb_child_completed

/* Failure drains owned capabilities without inventing a semantic result. */
ltb_callable_abort:
    test r15,r15
    jz ltb_callable_fault_early
    mov rsp,[r15+ltb_RETURN_STACK]
    cmp qword ptr [r15+ltb_ABORTING],0
    jne ltb_callable_uncertain
    mov [r15+ltb_ABORTING],rdi
    mov rbx,[r15+ltb_PUBLIC_CTX]
    mov [rbx+160],rdi
    cmp qword ptr [r15+ltb_READCTX+80],0
    je ltb_callable_abort_key
    push r15
    lea r15,[r15+ltb_READCTX]
    call ltb_lr_cleanup
    pop r15
    mov rax,[r15+ltb_READCTX+16]
    mov [r15+ltb_SLOTS+64+8],rax
    mov rax,[r15+ltb_READCTX+24]
    mov [r15+ltb_SLOTS+64+16],rax
    mov rax,[r15+ltb_READCTX+32]
    mov [r15+ltb_SLOTS+64+24],rax
    mov rax,[r15+ltb_READCTX+40]
    mov [r15+ltb_SLOTS+64+32],rax
ltb_callable_abort_key:
    cmp qword ptr [r15+ltb_KEYCTX+96],0
    je ltb_callable_abort_atomic
    push r15
    lea r15,[r15+ltb_KEYCTX]
    call ltb_key_cleanup
    pop r15
    mov rax,[r15+ltb_KEYCTX+16]
    mov [r15+ltb_SLOTS+128+8],rax
    mov rax,[r15+ltb_KEYCTX+24]
    mov [r15+ltb_SLOTS+128+16],rax
    mov rax,[r15+ltb_KEYCTX+32]
    mov [r15+ltb_SLOTS+128+24],rax
    mov rax,[r15+ltb_KEYCTX+40]
    mov [r15+ltb_SLOTS+128+32],rax
ltb_callable_abort_atomic:
    mov rdi,[r15+ltb_ATOMICCTX+80]
    mov qword ptr [r15+ltb_ATOMICCTX+80],-1
    test rdi,rdi
    js ltb_callable_abort_lease
    mov eax,3
    syscall
ltb_callable_abort_lease:
    call ltb_callable_drop_lease
    test eax,eax
    jnz ltb_callable_uncertain
    mov eax,0xfffffffc
    jmp ltb_callable_complete
ltb_callable_uncertain:
    mov r10,[r15+ltb_PUBLIC_CTX]
    mov eax,0xfffffffc
    mov [r10+128],rax
    mov qword ptr [r10+136],1
    mov qword ptr [r10+144],0
    mov qword ptr [r10+112],0
    mov qword ptr [r10+120],0
    mov eax,0xfffffffc
    jmp ltb_callable_return

ltb_callable_drop_lease:
    push rbx
    mov rax,[r15+ltb_SLOTS+8]
    test rax,rax
    jz ltb_callable_drop_done
    mov rbx,[rax+168]
    test rbx,rbx
    jz ltb_callable_drop_done
    lea rdi,[r15+ltb_CLEAN_FRAME]
    xor eax,eax
    mov ecx,8
    rep stosq
    mov rax,0x314b434f4c465248
    mov [r15+ltb_CLEAN_FRAME],rax
    mov qword ptr [r15+ltb_CLEAN_FRAME+8],6
    mov [r15+ltb_CLEAN_FRAME+16],rbx
    mov r10,[r15+ltb_PUBLIC_CTX]
    mov r10,[r10+56]
    lea rdi,[r15+ltb_CLEAN_FRAME]
    mov esi,64
    lea rdx,[r15+ltb_CLEAN_OUTPUT]
    mov ecx,64
    mov r8,[r10+8]
    mov r9,[r10+16]
    call qword ptr [r10]
    cmp rax,64
    jne ltb_callable_drop_bad
    mov rax,0x3130524b4c465248
    cmp [r15+ltb_CLEAN_OUTPUT],rax
    jne ltb_callable_drop_bad
    cmp qword ptr [r15+ltb_CLEAN_OUTPUT+8],6
    jne ltb_callable_drop_bad
    cmp qword ptr [r15+ltb_CLEAN_OUTPUT+16],0
    jne ltb_callable_drop_bad
    cmp [r15+ltb_CLEAN_OUTPUT+24],rbx
    jne ltb_callable_drop_bad
ltb_callable_drop_done:
    xor eax,eax
    jmp ltb_callable_drop_return
ltb_callable_drop_bad:
    mov eax,0xffffffff
ltb_callable_drop_return:
    pop rbx
    ret

ltb_callable_fault_early:
    mov rsp,r13
    mov r10,[rsp]
    mov [r10+160],rdi
    mov eax,0xfffffffc
    mov [r10+128],rax
    mov qword ptr [r10+136],1
    mov qword ptr [r10+144],1
    mov eax,0xfffffffc
    jmp ltb_callable_restore

/* Release never frees borrowed records, callbacks, or the parent statx byte. */
local_text_body_release:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov r12,rdi
    test rdi,rdi
    jz ltb_callable_release_invalid
    mov rax,ltb_CONTEXT_MAGIC
    cmp [rdi],rax
    jne ltb_callable_release_invalid
    cmp qword ptr [rdi+8],192
    jne ltb_callable_release_invalid
    cmp qword ptr [rdi+136],1
    jne ltb_callable_release_busy
    cmp qword ptr [rdi+144],1
    jne ltb_callable_release_busy
    mov r15,[rdi+152]
    test r15,r15
    jz ltb_callable_release_done
    mov rax,ltb_MAIN_MAGIC
    cmp [r15+ltb_MAIN_TAG],rax
    jne ltb_callable_release_invalid
    cmp [r15+ltb_PUBLIC_CTX],r12
    jne ltb_callable_release_invalid
    lea r13,[rip+ltb_callable_owned_regions]
    mov r14d,21
ltb_callable_release_region:
    mov rbx,[r13]
    mov rdi,[r15+rbx]
    test rdi,rdi
    jz ltb_callable_release_next
    mov rsi,[r15+rbx+8]
    add rsi,4096
    jc ltb_callable_release_invalid
    mov eax,11
    syscall
    test rax,rax
    jnz ltb_callable_release_invalid
    mov qword ptr [r15+rbx],0
    mov qword ptr [r15+rbx+8],0
ltb_callable_release_next:
    add r13,8
    dec r14d
    jnz ltb_callable_release_region
    mov rdi,r15
    mov esi,8192
    mov eax,11
    syscall
    test rax,rax
    jnz ltb_callable_release_invalid
    mov qword ptr [r12+152],0
    mov qword ptr [r12+112],0
    mov qword ptr [r12+120],0
ltb_callable_release_done:
    xor eax,eax
    jmp ltb_callable_release_return
ltb_callable_release_busy:
    mov eax,16
    jmp ltb_callable_release_return
ltb_callable_release_invalid:
    mov eax,0xffffffff
ltb_callable_release_return:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret
.balign 8,0
ltb_callable_owned_regions:
    .quad ltb_INPUT,ltb_CALLBACK,160
    .quad ltb_SLOTS+8,ltb_SLOTS+24,ltb_SLOTS+64+8,ltb_SLOTS+64+24
    .quad ltb_SLOTS+128+8,ltb_SLOTS+128+24,ltb_SLOTS+256+8,ltb_SLOTS+256+24
    .quad ltb_SLOTS+320+8,ltb_SLOTS+320+24,ltb_SLOTS+448+8,ltb_SLOTS+448+24
    .quad ltb_SLOTS+576+8,ltb_SLOTS+576+24,ltb_SLOTS+640+8,ltb_SLOTS+640+24
    .quad ltb_SLOTS+704+8,ltb_SLOTS+704+24

ltb_body_invoke:
    xor edi,edi
    mov rsi,[r15+ltb_CURRENT]
    mov rdx,[r15+ltb_CURLEN]
    call ltb_pure_invoke
    cmp eax,0xffffffe0
    je ltb_body_call
    cmp eax,0xffffffdf
    je ltb_callable_wait
    cmp eax,0xffff0000
    jae ltb_callable_owner_refusal
    cmp eax,32
    jb ltb_contract
    mov rdx,[r15+ltb_SLOTS+8]
    cmp qword ptr [rdx+8],100
    jne ltb_contract
    mov rcx,[rdx+48]
    or rcx,[rdx+168]
    or rcx,[rdx+176]
    jnz ltb_contract
    jmp ltb_callable_complete
ltb_callable_owner_refusal:
    mov rdx,[r15+ltb_SLOTS+8]
    cmp qword ptr [rdx],0
    jne ltb_contract
    jmp ltb_callable_complete
ltb_body_call:
    mov rbx,[r15+ltb_SLOTS+24]
    mov rax,0x314c414342544c48
    cmp [rbx],rax
    jne ltb_contract
    mov rax,[rbx+8]
    cmp rax,[r15+ltb_SLOTS+32]
    ja ltb_contract
    cmp rax,64
    jb ltb_contract
    sub rax,64
    cmp [rbx+48],rax
    jne ltb_contract
    cmp qword ptr [rbx+40],1
    jne ltb_contract
    cmp qword ptr [rbx+56],0
    jne ltb_contract
    mov rcx,[rbx+16]
    test rcx,rcx
    jz ltb_contract
    cmp rcx,12
    ja ltb_contract
    mov [r15+ltb_CHILD],rcx
    mov [r15+ltb_CHILDREQLEN],rax
    lea rax,[rbx+64]
    mov [r15+ltb_CHILDREQ],rax
    mov rax,[rbx+24]
    mov [r15+ltb_SEQUENCE],rax
    mov rax,[rbx+32]
    cmp rax,[r15+ltb_GENERATION]
    jne ltb_contract
    mov rdi,rbx
    mov rsi,[r15+ltb_SLOTS+32]
    mov edx,1
    call ltb_protection
    mov rax,[r15+ltb_CHILD]
    cmp eax,1
    je ltb_child_read
    cmp eax,2
    je ltb_child_key
    cmp eax,7
    je ltb_child_atomic
    cmp eax,8
    je ltb_callable_cache
    cmp eax,10
    je ltb_callable_hint
    cmp eax,11
    je ltb_child_unlink
    cmp eax,12
    je ltb_child_error
    mov rdi,rax
    mov rsi,[r15+ltb_CHILDREQ]
    mov rdx,[r15+ltb_CHILDREQLEN]
    call ltb_pure_invoke
    mov [r15+ltb_CHILDOUT],rsi
    jmp ltb_child_completed
ltb_child_error:
    mov edi,11
    mov rsi,[r15+ltb_CHILDREQ]
    mov rdx,[r15+ltb_CHILDREQLEN]
    call ltb_pure_invoke
    mov [r15+ltb_CHILDOUT],rsi
ltb_child_completed:
    mov edx,eax
    cmp rax,rdx
    jne ltb_contract
    cmp eax,0xffff0000
    jae ltb_contract
    mov [r15+ltb_CHILDCODE],rax
    mov rdi,[r15+ltb_SLOTS+24]
    mov rsi,[r15+ltb_SLOTS+32]
    mov edx,3
    call ltb_protection
    lea rdi,[r15+ltb_CALLBACK]
    mov rsi,[r15+ltb_CHILDCODE]
    add rsi,64
    jc ltb_resource
    xor edx,edx
    call ltb_ensure_region
    mov rdi,[r15+ltb_CALLBACK]
    mov rsi,[r15+ltb_CBCAP]
    mov edx,3
    call ltb_protection
    mov rbx,[r15+ltb_CALLBACK]
    mov rax,0x3130514342544c48
    mov [rbx],rax
    mov qword ptr [rbx+8],2
    mov rax,[r15+ltb_GENERATION]
    mov [rbx+16],rax
    mov rax,[r15+ltb_SEQUENCE]
    mov [rbx+24],rax
    mov rax,[r15+ltb_CHILD]
    mov [rbx+32],rax
    mov rcx,[r15+ltb_CHILDCODE]
    mov [rbx+40],rcx
    mov [rbx+48],rcx
    mov qword ptr [rbx+56],0
    lea rdi,[rbx+64]
    mov rsi,[r15+ltb_CHILDOUT]
    rep movsb
    mov rdi,rbx
    mov rsi,[r15+ltb_CBCAP]
    mov edx,1
    call ltb_protection
    mov [r15+ltb_CURRENT],rbx
    mov rax,[r15+ltb_CHILDCODE]
    add rax,64
    mov [r15+ltb_CURLEN],rax
    jmp ltb_body_invoke

ltb_lock_initial:
    .quad 0x314b434f4c465248,0,0,0,0,0,0,0
ltb_hint_response:
    .quad 0x3130504842544c48,0,0,0

/* Pure HIA calls retain one arena per fixed image. Growth replays only an
   admitted ltb_resource refusal; semantic completion is returned to the caller. */
ltb_pure_invoke:
    push rbp
    push rbx
    push r12
    push r13
    push r14
    mov r14,rdi
    cmp r14,11
    ja ltb_contract
    mov r12,rsi
    mov r13,rdx
    cmp r13,134217728
    ja ltb_resource
    mov rbx,r14
    shl rbx,6
    lea rbx,[r15+ltb_SLOTS+rbx]
    cmp r14,3
    je ltb_callable_lock_record
    cmp r14,6
    je ltb_callable_history_record
    jmp ltb_callable_private_record
ltb_callable_lock_record:
    mov rbx,[r15+ltb_PUBLIC_CTX]
    mov rbx,[rbx+56]
    jmp ltb_pure_again
ltb_callable_history_record:
    mov rbx,[r15+ltb_PUBLIC_CTX]
    mov rbx,[rbx+64]
    jmp ltb_pure_again
ltb_callable_private_record:
    lea rdi,[rbx+8]
    mov esi,4096
    mov edx,1
    call ltb_ensure_region
    lea rdi,[rbx+24]
    mov esi,4096
    xor edx,edx
    call ltb_ensure_region
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
    cmp r14,3
    jne ltb_pure_return
    cmp eax,64
    jne ltb_pure_return
    mov rcx,[rbx+24]
    cmp qword ptr [rcx+16],2
    jne ltb_pure_return
    mov rsi,[rcx+32]
    jmp ltb_pure_grow_work
ltb_pure_work_need:
    cmp r14,0
    je ltb_pure_work_pointer
    cmp r14,5
    je ltb_pure_work_pointer
    cmp r14,9
    jne ltb_contract
ltb_pure_work_pointer:
    mov rax,[rbx+8]
    mov rsi,[rax+144]
ltb_pure_grow_work:
    cmp rsi,[rbx+16]
    jbe ltb_contract
    cmp rsi,268435456
    ja ltb_resource
    cmp r14,3
    jne ltb_callable_private_work_growth
    mov rdi,[rbx+32]
    call ltb_callable_shared_growth
    jmp ltb_pure_again
ltb_callable_private_work_growth:
    lea rdi,[rbx+8]
    mov edx,1
    call ltb_ensure_region
    jmp ltb_pure_again
ltb_pure_output_need:
    cmp r14,0
    je ltb_pure_output_pointer
    cmp r14,5
    je ltb_pure_output_pointer
    cmp r14,9
    jne ltb_contract
ltb_pure_output_pointer:
    mov rax,[rbx+8]
    mov rsi,[rax+152]
    cmp rsi,[rbx+32]
    jbe ltb_contract
    cmp rsi,134217728
    ja ltb_resource
    lea rdi,[rbx+24]
    xor edx,edx
    call ltb_ensure_region
    jmp ltb_pure_again
ltb_pure_capacity:
    cmp r14,6
    jne ltb_callable_private_capacity
    mov rsi,[rbx+16]
    shl rsi,1
    jc ltb_resource
    cmp rsi,268435456
    ja ltb_resource
    mov rdi,[rbx+32]
    shl rdi,1
    jc ltb_resource
    cmp rdi,134217728
    ja ltb_resource
    call ltb_callable_shared_growth
    jmp ltb_pure_again
ltb_callable_private_capacity:
    cmp r14,4
    je ltb_pure_capacity_grow
    cmp r14,6
    je ltb_pure_capacity_grow
    cmp r14,8
    jne ltb_resource
ltb_pure_capacity_grow:
    mov rsi,[rbx+16]
    shl rsi,1
    jc ltb_resource
    cmp rsi,268435456
    ja ltb_resource
    lea rdi,[rbx+8]
    mov edx,1
    call ltb_ensure_region
    mov rsi,[rbx+32]
    shl rsi,1
    jc ltb_resource
    cmp rsi,134217728
    ja ltb_resource
    lea rdi,[rbx+24]
    xor edx,edx
    call ltb_ensure_region
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

ltb_child_read:
    lea rbx,[r15+ltb_SLOTS+64]
    lea rdi,[rbx+8]
    mov esi,4096
    mov edx,1
    call ltb_ensure_region
    lea rdi,[rbx+24]
    mov esi,4096
    xor edx,edx
    call ltb_ensure_region
    mov rax,[r15+ltb_CHILDREQ]
    mov [r15+ltb_READCTX],rax
    mov rax,[r15+ltb_CHILDREQLEN]
    mov [r15+ltb_READCTX+48],rax
    mov rax,[rbx+8]
    mov [r15+ltb_READCTX+16],rax
    mov rax,[rbx+16]
    mov [r15+ltb_READCTX+24],rax
    mov rax,[rbx+24]
    mov [r15+ltb_READCTX+32],rax
    mov rax,[rbx+32]
    mov [r15+ltb_READCTX+40],rax
    mov rax,[r15+ltb_META_POINTER]
    mov [r15+ltb_READCTX+64],rax
    mov [r15+ltb_READCTX+96],r15
    mov rax,[rbx]
    mov [r15+ltb_READCTX+80],rax
    lea rdi,[r15+ltb_READCTX]
    call ltb_local_read_run
    mov rcx,[r15+ltb_READCTX+16]
    mov [rbx+8],rcx
    mov rcx,[r15+ltb_READCTX+24]
    mov [rbx+16],rcx
    mov rcx,[r15+ltb_READCTX+32]
    mov [rbx+24],rcx
    mov [r15+ltb_CHILDOUT],rcx
    mov rcx,[r15+ltb_READCTX+40]
    mov [rbx+32],rcx
    jmp ltb_child_completed

ltb_child_key:
    lea rbx,[r15+ltb_SLOTS+128]
    lea rdi,[rbx+8]
    mov esi,1056768
    mov edx,1
    call ltb_ensure_region
    lea rdi,[rbx+24]
    mov esi,4096
    xor edx,edx
    call ltb_ensure_region
    mov rax,[r15+ltb_CHILDREQ]
    mov [r15+ltb_KEYCTX],rax
    mov rax,[r15+ltb_CHILDREQLEN]
    mov [r15+ltb_KEYCTX+48],rax
    mov rax,[rbx+8]
    mov [r15+ltb_KEYCTX+16],rax
    mov rax,[rbx+16]
    mov [r15+ltb_KEYCTX+24],rax
    mov rax,[rbx+24]
    mov [r15+ltb_KEYCTX+32],rax
    mov rax,[rbx+32]
    mov [r15+ltb_KEYCTX+40],rax
    mov rax,[r15+ltb_SECURE]
    mov [r15+ltb_KEYCTX+64],rax
    mov qword ptr [r15+ltb_KEYCTX+72],-1
    mov qword ptr [r15+ltb_KEYCTX+80],-1
    mov rax,[rbx]
    mov [r15+ltb_KEYCTX+96],rax
    mov [r15+ltb_KEYCTX+104],r15
    lea rdi,[r15+ltb_KEYCTX]
    call ltb_key_run
    mov rcx,[r15+ltb_KEYCTX+16]
    mov [rbx+8],rcx
    mov rcx,[r15+ltb_KEYCTX+24]
    mov [rbx+16],rcx
    mov rcx,[r15+ltb_KEYCTX+32]
    mov [rbx+24],rcx
    mov [r15+ltb_CHILDOUT],rcx
    mov rcx,[r15+ltb_KEYCTX+40]
    mov [rbx+32],rcx
    jmp ltb_child_completed

ltb_child_atomic:
    lea rbx,[r15+ltb_SLOTS+448]
    mov rax,[r15+ltb_CHILDREQ]
    cmp qword ptr [r15+ltb_CHILDREQLEN],64
    jb ltb_contract
    mov rbp,[rax+16]
    mov rsi,rbp
    imul rsi,rsi,5
    jo ltb_resource
    add rsi,4096
    jc ltb_resource
    lea rdi,[rbx+8]
    mov edx,1
    call ltb_ensure_region
    mov rsi,rbp
    imul rsi,rsi,3
    jo ltb_resource
    add rsi,512
    jc ltb_resource
    lea rdi,[rbx+24]
    xor edx,edx
    call ltb_ensure_region
    call ltb_atomic_run
    mov rcx,[rbx+24]
    mov [r15+ltb_CHILDOUT],rcx
    jmp ltb_child_completed

ltb_atomic_run:
    push rbp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub rsp,280
    lea rbp,[r15+ltb_ATOMICCTX]
    mov [rbp],rbx
    mov [rbp+72],rsp
    mov rax,[r15+ltb_CHILDREQ]
    mov [rbp+16],rax
    mov rax,[r15+ltb_CHILDREQLEN]
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
    mov rax,[r15+ltb_META_POINTER]
    movzx eax,byte ptr [rax]
    cmp eax,2
    ja ltb_atomic_worker_contract
    mov [r12+8],rax
    xor ebx,ebx
ltb_atomic_invoke_policy:
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
    jne ltb_atomic_worker_contract
    cmp eax,0xfffffff0
    jne ltb_atomic_policy_done
    mov rax,0x3158465441414948
    cmp [r12+256],rax
    jne ltb_atomic_worker_contract
    inc rbx
    jz ltb_atomic_worker_contract
    cmp [r12+264],rbx
    jne ltb_atomic_worker_contract
    cmp [r12+144],rbx
    jne ltb_atomic_worker_contract
    mov r14,[r12+272]
    cmp [r12],r14
    jne ltb_atomic_worker_contract
    cmp r14,1
    jb ltb_atomic_worker_contract
    cmp r14,11
    ja ltb_atomic_worker_contract
    mov rax,[r12+304]
    or rax,[r12+312]
    or rax,[r12+320]
    or rax,[r12+328]
    or rax,[r12+336]
    or rax,[r12+344]
    jnz ltb_atomic_worker_contract
    cmp qword ptr [r12+56],1024
    jne ltb_atomic_worker_contract
    mov rax,[rbp+24]
    sub rax,64
    cmp [r12+40],rax
    ja ltb_atomic_worker_contract
    mov rax,[r12+40]
    add rax,1025
    jc ltb_atomic_worker_contract
    cmp rax,[r12+64]
    jne ltb_atomic_worker_contract
    add rax,[r12+72]
    jc ltb_atomic_worker_contract
    cmp rax,[rbp+40]
    jae ltb_atomic_worker_contract
    cmp byte ptr [r12+rax],0
    jne ltb_atomic_worker_contract
    mov rax,[r12+40]
    cmp byte ptr [r12+rax+1024],0
    jne ltb_atomic_worker_contract
    cmp r14,1
    je ltb_atomic_stat_path
    cmp r14,2
    je ltb_atomic_stat_probe
    cmp r14,3
    je ltb_atomic_stat_path
    cmp r14,10
    je ltb_atomic_stat_path
    cmp r14,11
    je ltb_atomic_stat_probe_fallback
    cmp r14,4
    je ltb_atomic_open_temp
    cmp r14,5
    je ltb_atomic_write_temp
    cmp r14,6
    je ltb_atomic_close_temp
    cmp r14,7
    je ltb_atomic_chmod_temp
    cmp r14,8
    je ltb_atomic_rename_temp
    jmp ltb_atomic_unlink_temp
ltb_atomic_policy_done:
    cmp r13,-1
    jne ltb_atomic_worker_contract
    mov rcx,[r12+8]
    cmp rcx,2
    ja ltb_atomic_worker_contract
    mov rdx,[r15+ltb_META_POINTER]
    mov [rdx],cl
    add rsp,280
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret
ltb_atomic_worker_contract:
    mov rsp,[rbp+72]
    mov rdi,r13
    mov r13,-1
    mov [rbp+80],r13
    test rdi,rdi
    js ltb_contract
    mov eax,3
    syscall
    jmp ltb_contract

/* The existing file owner chooses NUL admission and the one remove_file
   attempt. This fixed adapter owns only its admitted private unlink effect. */
ltb_child_unlink:
    lea rbx,[r15+ltb_SLOTS+640]
    mov rax,[r15+ltb_CHILDREQ]
    cmp qword ptr [r15+ltb_CHILDREQLEN],64
    jb ltb_contract
    mov rsi,[rax+24]
    add rsi,513
    jc ltb_resource
    lea rdi,[rbx+8]
    xor edx,edx
    call ltb_ensure_region
    lea rdi,[rbx+24]
    mov esi,4096
    xor edx,edx
    call ltb_ensure_region
    lea rdi,[r15+160]
    mov rsi,[r15+ltb_CHILDREQLEN]
    xor edx,edx
    call ltb_ensure_region
    mov rdi,[r15+160]
    mov rsi,[r15+168]
    mov edx,3
    call ltb_protection
    mov rdi,[r15+160]
    mov rsi,[r15+ltb_CHILDREQ]
    mov rcx,[r15+ltb_CHILDREQLEN]
    rep movsb
    mov rdi,[rbx+8]
    xor eax,eax
    mov ecx,64
    rep stosq
    mov qword ptr [r15+176],0
ltb_unlink_invoke:
    mov rdi,[r15+160]
    mov rsi,[r15+168]
    mov edx,1
    call ltb_protection
    mov rdi,[r15+160]
    mov rsi,[r15+ltb_CHILDREQLEN]
    mov rdx,[rbx+24]
    mov rcx,[rbx+32]
    mov r8,[rbx+8]
    mov r9,[rbx+16]
    call qword ptr [rbx]
    mov edx,eax
    cmp rax,rdx
    jne ltb_contract
    cmp eax,0xfffffffd
    jne ltb_unlink_result
    mov r12,[rbx+8]
    lea rbp,[r12+128]
    mov rax,0x3158464643485348
    cmp [rbp],rax
    jne ltb_contract
    inc qword ptr [r15+176]
    jz ltb_contract
    mov rax,[r15+176]
    cmp [rbp+8],rax
    jne ltb_contract
    cmp [r12+24],rax
    jne ltb_contract
    cmp qword ptr [r12+8],2
    jne ltb_contract
    cmp qword ptr [r12+16],1
    jne ltb_contract
    cmp qword ptr [rbp+16],2
    jne ltb_contract
    cmp qword ptr [rbp+24],512
    jne ltb_contract
    mov rcx,[r12+32]
    cmp [rbp+32],rcx
    jne ltb_contract
    mov rax,[rbp+40]
    or rax,[rbp+48]
    or rax,[rbp+56]
    or rax,[rbp+64]
    or rax,[rbp+72]
    or rax,[rbp+80]
    or rax,[rbp+88]
    jnz ltb_contract
    mov rax,[rbx+16]
    sub rax,513
    jc ltb_contract
    cmp rcx,rax
    ja ltb_contract
    lea rdi,[r12+512]
    xor eax,eax
    test rcx,rcx
    jz ltb_unlink_terminator
    repne scasb
    je ltb_contract
ltb_unlink_terminator:
    cmp byte ptr [rdi],0
    jne ltb_contract
    lea rdi,[r12+512]
    mov eax,87
    syscall
    mov [rbp+64],rax
    cmp rax,-4095
    jae ltb_unlink_error
    test rax,rax
    jnz ltb_contract
    jmp ltb_unlink_acknowledge
ltb_unlink_error:
    neg rax
    mov [rbp+72],rax
ltb_unlink_acknowledge:
    mov qword ptr [rbp+56],1
    mov rdi,[r15+160]
    mov rsi,[r15+168]
    mov edx,3
    call ltb_protection
    mov rax,[r15+160]
    mov qword ptr [rax+8],2
    jmp ltb_unlink_invoke
ltb_unlink_result:
    cmp eax,48
    jne ltb_contract
    mov r12,[rbx+8]
    cmp qword ptr [r12+16],3
    jne ltb_contract
    cmp qword ptr [r12+48],0
    jne ltb_contract
    mov rcx,[rbx+24]
    mov [r15+ltb_CHILDOUT],rcx
    jmp ltb_child_completed

/* These complete observations belong only to the qualification fixture. */
ltb_round_capacity:
    mov rax,rdi
    add rax,4095
    jc ltb_resource
    and rax,-4096
    test rax,rax
    jnz ltb_rounded
    mov eax,4096
ltb_rounded:
    ret
ltb_allocate_guarded:
    push rbx
    mov rbx,rdi
    mov rsi,rdi
    add rsi,4096
    jc ltb_resource
    xor edi,edi
    mov edx,3
    mov r10d,0x22
    mov r8,-1
    xor r9d,r9d
    mov eax,9
    syscall
    cmp rax,-4095
    jae ltb_resource
    push rax
    lea rdi,[rax+rbx]
    mov esi,4096
    xor edx,edx
    mov eax,10
    syscall
    test rax,rax
    jnz ltb_callable_guard_failed
    pop rax
    pop rbx
    ret
ltb_callable_guard_failed:
    pop rdi
    lea rsi,[rbx+4096]
    mov eax,11
    syscall
    pop rbx
    jmp ltb_infrastructure
ltb_ensure_region:
    push rbx
    push rbp
    push r12
    push r13
    mov rbx,rdi
    mov ebp,edx
    mov rax,[rbx]
    test rax,rax
    jz ltb_ensure_allocate
    cmp rsi,[rbx+8]
    jbe ltb_ensure_done
ltb_ensure_allocate:
    mov rdi,rsi
    call ltb_round_capacity
    mov r12,rax
    mov rdi,rax
    call ltb_allocate_guarded
    mov r13,rax
    cmp qword ptr [rbx],0
    je ltb_ensure_publish
    test ebp,ebp
    jz ltb_ensure_retire
    mov rdi,r13
    mov rsi,[rbx]
    mov rcx,[rbx+8]
    rep movsb
ltb_ensure_retire:
    mov rdi,[rbx]
    mov rsi,[rbx+8]
    add rsi,4096
    mov eax,11
    syscall
    test rax,rax
    jnz ltb_infrastructure
ltb_ensure_publish:
    mov [rbx],r13
    mov [rbx+8],r12
    mov rax,r13
ltb_ensure_done:
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret
ltb_protection:
    mov eax,10
    syscall
    test rax,rax
    jnz ltb_infrastructure
    ret
ltb_contract:
    mov edi,70
    jmp ltb_callable_abort
ltb_resource:
    mov edi,71
    jmp ltb_callable_abort
ltb_infrastructure:
    mov edi,74
    jmp ltb_callable_abort
ltb_fatal_exit:
    mov r15,[r15+104]
    jmp ltb_callable_abort
ltb_atomic_stat_path:
    cmp r13, -1
    jne ltb_atomic_worker_contract
    cmp qword ptr [r12 + 256 + 24], 1024
    jne ltb_atomic_worker_contract
    mov rax, qword ptr [r12 + 40]
    cmp qword ptr [r12 + 256 + 32], rax
    jne ltb_atomic_worker_contract
    cmp qword ptr [r12 + 256 + 40], 0
    jne ltb_atomic_worker_contract
    lea rdi, [r12 + 1024]
    mov rcx, rax
    call ltb_atomic_exact_cstring
    mov rdi, rsp
    xor eax, eax
    mov ecx, 32
    rep stosq
    mov edi, -100
    lea rsi, [r12 + 1024]
    cmp r14, 1
    jne ltb_atomic_stat_fallback
    xor edx, edx
    mov r10d, 0xfff
    mov r8, rsp
    mov eax, 332
    syscall
    test rax, rax
    js ltb_atomic_effect_error
    movzx eax, word ptr [rsp + 28]
    mov qword ptr [r12 + 256 + 72], rax
    jmp ltb_atomic_acknowledge
ltb_atomic_stat_fallback:
    mov rdx, rsp
    xor r10d, r10d
    mov eax, 262
    syscall
    test rax, rax
    js ltb_atomic_effect_error
    mov eax, dword ptr [rsp + 24]
    mov qword ptr [r12 + 256 + 72], rax
    jmp ltb_atomic_acknowledge

ltb_atomic_stat_probe:
    cmp r13, -1
    jne ltb_atomic_worker_contract
    mov rax, qword ptr [r12 + 256 + 24]
    or rax, qword ptr [r12 + 256 + 32]
    or rax, qword ptr [r12 + 256 + 40]
    jnz ltb_atomic_worker_contract
    xor edi, edi
    xor esi, esi
    xor edx, edx
    mov r10d, 0xfff
    xor r8d, r8d
    mov eax, 332
    syscall
    test rax, rax
    js ltb_atomic_effect_error
    jmp ltb_atomic_acknowledge

ltb_atomic_stat_probe_fallback:
    cmp r13, -1
    jne ltb_atomic_worker_contract
    mov rax, qword ptr [r12 + 256 + 24]
    or rax, qword ptr [r12 + 256 + 32]
    or rax, qword ptr [r12 + 256 + 40]
    jnz ltb_atomic_worker_contract
    xor edi, edi
    xor esi, esi
    mov rdx, rsp
    xor r10d, r10d
    mov eax, 262
    syscall
    test rax, rax
    js ltb_atomic_effect_error
    jmp ltb_atomic_worker_contract

ltb_atomic_temp_arguments:
    mov rax, qword ptr [r12 + 64]
    cmp qword ptr [r12 + 256 + 24], rax
    jne ltb_atomic_worker_contract
    mov rcx, qword ptr [r12 + 72]
    cmp qword ptr [r12 + 256 + 32], rcx
    jne ltb_atomic_worker_contract
    lea rdi, [r12 + rax]
    call ltb_atomic_exact_cstring
    mov rax, qword ptr [r12 + 64]
    lea rdi, [r12 + rax]
    ret
ltb_atomic_open_temp:
    cmp r13, -1
    jne ltb_atomic_worker_contract
    cmp qword ptr [r12 + 256 + 40], 0
    jne ltb_atomic_worker_contract
    call ltb_atomic_temp_arguments
    mov rsi, rdi
    mov edi, -100
    mov edx, 0x80241
    mov r10d, 0666
    mov eax, 257
    syscall
    test rax, rax
    js ltb_atomic_effect_error
    cmp rax, 0x7fffffff
    ja ltb_atomic_worker_contract
    mov r13, rax
    mov [rbp+80],r13
    mov qword ptr [r12 + 256 + 72], 1
    jmp ltb_atomic_acknowledge

ltb_atomic_write_temp:
    cmp r13, 0
    jl ltb_atomic_worker_contract
    cmp qword ptr [r12 + 256 + 24], 1
    jne ltb_atomic_worker_contract
    mov rax, qword ptr [r12 + 40]
    add rax, 64
    add rax, qword ptr [r12 + 112]
    jc ltb_atomic_worker_contract
    cmp rax, qword ptr [r12 + 256 + 32]
    jne ltb_atomic_worker_contract
    cmp rax, [rbp + 24]
    jae ltb_atomic_worker_contract
    mov rdx, [rbp + 24]
    sub rdx, rax
    cmp rdx, qword ptr [r12 + 256 + 40]
    jne ltb_atomic_worker_contract
    mov rsi, [rbp + 16]
    add rsi, rax
    mov rdi, r13
    mov eax, 1
    syscall
    test rax, rax
    js ltb_atomic_effect_error
    mov qword ptr [r12 + 256 + 56], rax
    jmp ltb_atomic_acknowledge

ltb_atomic_close_temp:
    cmp r13, 0
    jl ltb_atomic_worker_contract
    cmp qword ptr [r12 + 256 + 24], 1
    jne ltb_atomic_worker_contract
    mov rax, qword ptr [r12 + 256 + 32]
    or rax, qword ptr [r12 + 256 + 40]
    jnz ltb_atomic_worker_contract
    mov rdi, r13
    mov r13, -1
    mov [rbp+80],r13
    mov eax, 3
    syscall
    test rax, rax
    js ltb_atomic_effect_error
    jmp ltb_atomic_acknowledge

ltb_atomic_chmod_temp:
    cmp r13, -1
    jne ltb_atomic_worker_contract
    mov rax, qword ptr [r12 + 80]
    mov ecx, 0xffffffff
    cmp rax, rcx
    ja ltb_atomic_worker_contract
    cmp qword ptr [r12 + 256 + 40], rax
    jne ltb_atomic_worker_contract
    call ltb_atomic_temp_arguments
    mov esi, dword ptr [r12 + 80]
    mov eax, 90
    syscall
    test rax, rax
    js ltb_atomic_effect_error
    jmp ltb_atomic_acknowledge

ltb_atomic_rename_temp:
    cmp r13, -1
    jne ltb_atomic_worker_contract
    mov rax, qword ptr [r12 + 64]
    cmp qword ptr [r12 + 256 + 24], rax
    jne ltb_atomic_worker_contract
    cmp qword ptr [r12 + 256 + 32], 1024
    jne ltb_atomic_worker_contract
    cmp qword ptr [r12 + 256 + 40], 0
    jne ltb_atomic_worker_contract
    lea rdi, [r12 + rax]
    mov rcx, qword ptr [r12 + 72]
    call ltb_atomic_exact_cstring
    lea rdi, [r12 + 1024]
    mov rcx, qword ptr [r12 + 40]
    call ltb_atomic_exact_cstring
    mov rax, qword ptr [r12 + 64]
    lea rdi, [r12 + rax]
    lea rsi, [r12 + 1024]
    mov eax, 82
    syscall
    test rax, rax
    js ltb_atomic_effect_error
    jmp ltb_atomic_acknowledge

ltb_atomic_unlink_temp:
    cmp r13, -1
    jne ltb_atomic_worker_contract
    cmp qword ptr [r12 + 256 + 40], 0
    jne ltb_atomic_worker_contract
    call ltb_atomic_temp_arguments
    mov eax, 87
    syscall
    test rax, rax
    js ltb_atomic_effect_error
    jmp ltb_atomic_acknowledge

ltb_atomic_effect_error:
    cmp rax, -4095
    jb ltb_atomic_worker_contract
    neg rax
    mov qword ptr [r12 + 256 + 64], rax
ltb_atomic_acknowledge:
    mov qword ptr [r12 + 256 + 80], 1
    jmp ltb_atomic_invoke_policy

ltb_atomic_exact_cstring:
    xor eax, eax
    test rcx, rcx
    jz ltb_atomic_exact_end
    repne scasb
    je ltb_atomic_worker_contract
ltb_atomic_exact_end:
    cmp byte ptr [rdi], 0
    jne ltb_atomic_worker_contract
    ret


ltb_local_read_run:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp, 520
    mov r15, rdi
    cmp qword ptr [r15 + 72], 0
    jne ltb_lr_contract_fail
    mov rdi, qword ptr [r15 + 48]
    add rdi, 1024
    jc ltb_lr_memory_fail
    cmp rdi, qword ptr [r15 + 24]
    jbe ltb_lr_read_workspace_ready
    mov ebp, 16
    call ltb_lr_resize_buffer
ltb_lr_read_workspace_ready:
    mov rdi, qword ptr [r15 + 16]
    xor eax, eax
    mov ecx, 128
    rep stosq
    mov qword ptr [r15 + 88], 0
ltb_lr_read_invoke:
    mov rdi, qword ptr [r15]
    mov rsi, qword ptr [r15 + 48]
    mov rdx, qword ptr [r15 + 32]
    mov rcx, qword ptr [r15 + 40]
    mov r8, qword ptr [r15 + 16]
    mov r9, qword ptr [r15 + 24]
    call qword ptr [r15 + 80]
    mov edx, eax
    cmp rax, rdx
    jne ltb_lr_contract_fail
    mov rbx, qword ptr [r15 + 16]
    cmp eax, 0xffffffef
    je ltb_lr_read_grow
    cmp eax, 0xffffffe8
    je ltb_lr_read_cache
    cmp eax, 0xfffffff0
    je ltb_lr_read_effect
    cmp eax, 0xfffffff6
    je ltb_lr_allocation_abort
    cmp eax, 0xffffffff
    je ltb_lr_read_refused
    cmp eax, 0xfffffffe
    je ltb_lr_read_refused
    cmp eax, 0xfffffff9
    je ltb_lr_contract_fail
    cmp rax, qword ptr [r15 + 40]
    ja ltb_lr_contract_fail
    cmp eax, 32
    jb ltb_lr_contract_fail
    cmp qword ptr [rbx], 100
    jne ltb_lr_contract_fail
    cmp qword ptr [r15 + 72], 0
    jne ltb_lr_contract_fail
    mov rdx, qword ptr [r15 + 32]
    mov rcx, 0x3130304f524c4648
    cmp qword ptr [rdx], rcx
    jne ltb_lr_contract_fail
    lea rcx, [rax - 32]
    cmp qword ptr [rdx + 24], rcx
    jne ltb_lr_contract_fail
    jmp ltb_lr_read_return
ltb_lr_read_refused:
    mov dword ptr [rsp + 504], eax
    call ltb_lr_cleanup
    mov eax, dword ptr [rsp + 504]
ltb_lr_read_return:
    add rsp, 520
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

ltb_lr_read_grow:
    cmp qword ptr [rbx], 90
    jne ltb_lr_contract_fail
    mov rdi, qword ptr [rbx + 200]
    mov rax, qword ptr [rbx + 216]
    cmp rax, 1
    je ltb_lr_read_grow_work
    cmp rax, 2
    jne ltb_lr_contract_fail
    cmp qword ptr [rbx + 208], 100
    jne ltb_lr_contract_fail
    cmp qword ptr [r15 + 72], 0
    jne ltb_lr_contract_fail
    cmp rdi, 1073741824
    ja ltb_lr_read_resource
    mov ebp, 32
    jmp ltb_lr_read_grow_do
ltb_lr_read_grow_work:
    cmp rdi, 1207959552
    ja ltb_lr_read_resource
    mov rax, qword ptr [rbx + 208]
    cmp rax, 20
    je ltb_lr_read_grow_work_valid
    cmp rax, 23
    je ltb_lr_read_grow_work_valid
    cmp rax, 24
    jne ltb_lr_contract_fail
ltb_lr_read_grow_work_valid:
    mov rax, qword ptr [rbx + 56]
    add rax, qword ptr [rbx + 152]
    jc ltb_lr_contract_fail
    cmp rdi, rax
    jne ltb_lr_contract_fail
    mov ebp, 16
ltb_lr_read_grow_do:
    cmp rdi, qword ptr [r15 + rbp + 8]
    jbe ltb_lr_contract_fail
    call ltb_lr_resize_buffer
    jmp ltb_lr_read_invoke
ltb_lr_read_resource:
    mov eax, 0xfffffffe
    jmp ltb_lr_read_refused

ltb_lr_read_cache:
    lea r12, [rbx + 640]
    mov rax, 0x3130304341544d48
    cmp qword ptr [r12], rax
    jne ltb_lr_contract_fail
    call ltb_lr_sequence_admit
    mov r13, qword ptr [r12 + 16]
    cmp r13, 1
    ja ltb_lr_contract_fail
    mov rax, qword ptr [r12 + 32]
    or rax, qword ptr [r12 + 40]
    jnz ltb_lr_contract_fail
    mov rax, qword ptr [rbx]
    cmp rax, 60
    jb ltb_lr_contract_fail
    cmp rax, 63
    ja ltb_lr_contract_fail
    cmp rax, 62
    jb ltb_lr_read_cache_load
    cmp r13, 1
    jne ltb_lr_contract_fail
    mov rax, qword ptr [r12 + 24]
    cmp rax, qword ptr [rbx + 104]
    jne ltb_lr_contract_fail
    cmp rax, 1
    jb ltb_lr_contract_fail
    cmp rax, 2
    ja ltb_lr_contract_fail
    mov rdx, qword ptr [r15 + 64]
    mov byte ptr [rdx], al
    xor eax, eax
    jmp ltb_lr_read_cache_complete
ltb_lr_read_cache_load:
    test r13, r13
    jnz ltb_lr_contract_fail
    cmp qword ptr [r12 + 24], 0
    jne ltb_lr_contract_fail
    mov rdx, qword ptr [r15 + 64]
    movzx eax, byte ptr [rdx]
    cmp eax, 2
    ja ltb_lr_contract_fail
ltb_lr_read_cache_complete:
    mov qword ptr [r12 + 56], rax
    mov qword ptr [r12 + 80], 1
    jmp ltb_lr_read_invoke

ltb_lr_read_effect:
    lea r12, [rbx + 256]
    mov rax, 0x58464f49524c4648
    cmp qword ptr [r12], rax
    jne ltb_lr_contract_fail
    call ltb_lr_sequence_admit
    mov r14, qword ptr [r12 + 16]
    mov rax, qword ptr [rbx]
    cmp r14, 8
    jne ltb_lr_read_effect_phase
    cmp rax, 21
    je ltb_lr_read_effect_ready
    cmp rax, 22
    jne ltb_lr_contract_fail
    jmp ltb_lr_read_effect_ready
ltb_lr_read_effect_phase:
    cmp rax, r14
    jne ltb_lr_contract_fail
ltb_lr_read_effect_ready:
    mov rdi, rsp
    xor eax, eax
    mov ecx, 32
    rep stosq
    cmp r14, 1
    je ltb_lr_read_path_statx
    cmp r14, 2
    je ltb_lr_read_probe_statx
    cmp r14, 3
    je ltb_lr_read_path_stat
    cmp r14, 4
    je ltb_lr_read_open
    cmp r14, 5
    je ltb_lr_read_fd_statx
    cmp r14, 7
    je ltb_lr_read_fd_stat
    cmp r14, 8
    je ltb_lr_read_bytes
    cmp r14, 9
    je ltb_lr_read_close
    cmp r14, 10
    je ltb_lr_read_path_stat
    cmp r14, 11
    je ltb_lr_read_fd_statat
    cmp r14, 12
    je ltb_lr_read_probe_stat
    jmp ltb_lr_contract_fail
ltb_lr_read_path_statx:
    call ltb_lr_path_admit
    mov rsi, rax
    mov rdi, -100
    xor edx, edx
    mov r10d, 4095
    mov r8, rsp
    mov eax, 332
    syscall
    mov ebp, 1
    jmp ltb_lr_effect_done
ltb_lr_read_path_stat:
    call ltb_lr_path_admit
    mov rsi, rax
    mov rdi, -100
    mov rdx, rsp
    xor r10d, r10d
    mov eax, 262
    syscall
    mov ebp, 2
    jmp ltb_lr_effect_done
ltb_lr_read_probe_statx:
    call ltb_lr_zero_arguments
    xor edi, edi
    xor esi, esi
    xor edx, edx
    mov r10d, 4095
    xor r8d, r8d
    mov eax, 332
    syscall
    xor ebp, ebp
    jmp ltb_lr_effect_done
ltb_lr_read_probe_stat:
    call ltb_lr_zero_arguments
    xor edi, edi
    xor esi, esi
    xor edx, edx
    xor r10d, r10d
    mov eax, 262
    syscall
    xor ebp, ebp
    jmp ltb_lr_effect_done
ltb_lr_read_open:
    cmp qword ptr [r15 + 72], 0
    jne ltb_lr_contract_fail
    call ltb_lr_path_admit
    mov rsi, rax
    mov rdi, -100
    mov edx, 524288
    xor r10d, r10d
    mov eax, 257
    syscall
    mov ebp, 3
    jmp ltb_lr_effect_done
ltb_lr_read_fd_statx:
    call ltb_lr_fd_only
    lea rsi, [rip + ltb_lr_empty_path]
    mov edx, 4096
    mov r10d, 4095
    mov r8, rsp
    mov eax, 332
    syscall
    mov ebp, 1
    jmp ltb_lr_effect_done
ltb_lr_read_fd_statat:
    call ltb_lr_fd_only
    lea rsi, [rip + ltb_lr_empty_path]
    mov rdx, rsp
    mov r10d, 4096
    mov eax, 262
    syscall
    mov ebp, 2
    jmp ltb_lr_effect_done
ltb_lr_read_fd_stat:
    call ltb_lr_fd_only
    mov rsi, rsp
    mov eax, 5
    syscall
    mov ebp, 2
    jmp ltb_lr_effect_done
ltb_lr_read_bytes:
    cmp qword ptr [r12 + 24], 1
    jne ltb_lr_contract_fail
    mov rdi, qword ptr [r15 + 72]
    test rdi, rdi
    jz ltb_lr_contract_fail
    dec rdi
    mov rsi, qword ptr [r12 + 32]
    mov rdx, qword ptr [r12 + 40]
    cmp qword ptr [rbx], 21
    jne ltb_lr_read_regular
    cmp rsi, 768
    jne ltb_lr_contract_fail
    cmp rdx, 32
    jne ltb_lr_contract_fail
    jmp ltb_lr_read_span_ready
ltb_lr_read_regular:
    mov rax, qword ptr [rbx + 56]
    cmp rax, 1024
    jb ltb_lr_contract_fail
    add rax, qword ptr [rbx + 160]
    jc ltb_lr_contract_fail
    cmp rsi, rax
    jne ltb_lr_contract_fail
    mov rax, qword ptr [rbx + 152]
    sub rax, qword ptr [rbx + 160]
    jc ltb_lr_contract_fail
    cmp rax, qword ptr [rbx + 176]
    cmova rax, qword ptr [rbx + 176]
    cmp rdx, rax
    jne ltb_lr_contract_fail
    test rdx, rdx
    jz ltb_lr_contract_fail
ltb_lr_read_span_ready:
    cmp rsi, qword ptr [r15 + 24]
    ja ltb_lr_contract_fail
    mov rax, qword ptr [r15 + 24]
    sub rax, rsi
    cmp rdx, rax
    ja ltb_lr_contract_fail
    add rsi, rbx
    xor eax, eax
    syscall
    mov ebp, 4
    jmp ltb_lr_effect_done
ltb_lr_read_close:
    call ltb_lr_fd_only
    mov qword ptr [r15 + 72], 0
    mov eax, 3
    syscall
    xor ebp, ebp
ltb_lr_effect_done:
    cmp rax, -4095
    jae ltb_lr_effect_error
    cmp ebp, 1
    jne ltb_lr_effect_stat64
    test rax, rax
    jnz ltb_lr_contract_fail
    mov rax, qword ptr [rsp + 40]
    mov qword ptr [r12 + 72], rax
    cmp qword ptr [rbx + 16], 3
    jne ltb_lr_effect_completed
    movzx eax, word ptr [rsp + 28]
    mov qword ptr [r12 + 88], rax
    jmp ltb_lr_effect_completed
ltb_lr_effect_stat64:
    cmp ebp, 2
    jne ltb_lr_effect_opened
    test rax, rax
    jnz ltb_lr_contract_fail
    mov rax, qword ptr [rsp + 48]
    mov qword ptr [r12 + 72], rax
    cmp qword ptr [rbx + 16], 3
    jne ltb_lr_effect_completed
    mov eax, dword ptr [rsp + 24]
    mov qword ptr [r12 + 88], rax
    jmp ltb_lr_effect_completed
ltb_lr_effect_opened:
    cmp ebp, 3
    jne ltb_lr_effect_read
    inc rax
    jz ltb_lr_contract_fail
    mov qword ptr [r15 + 72], rax
    mov qword ptr [r12 + 72], 1
    jmp ltb_lr_effect_completed
ltb_lr_effect_read:
    cmp ebp, 4
    jne ltb_lr_effect_unit
    cmp rax, qword ptr [r12 + 40]
    ja ltb_lr_contract_fail
    mov qword ptr [r12 + 56], rax
    jmp ltb_lr_effect_completed
ltb_lr_effect_unit:
    test rax, rax
    jnz ltb_lr_contract_fail
    jmp ltb_lr_effect_completed
ltb_lr_effect_error:
    neg rax
    mov qword ptr [r12 + 64], rax
ltb_lr_effect_completed:
    mov qword ptr [r12 + 80], 1
    jmp ltb_lr_read_invoke

ltb_lr_sequence_admit:
    mov rax, qword ptr [r15 + 88]
    inc rax
    jz ltb_lr_contract_fail
    cmp qword ptr [r12 + 8], rax
    jne ltb_lr_contract_fail
    cmp qword ptr [rbx + 72], rax
    jne ltb_lr_contract_fail
    mov qword ptr [r15 + 88], rax
    mov rax, qword ptr [r12 + 48]
    or rax, qword ptr [r12 + 56]
    or rax, qword ptr [r12 + 64]
    or rax, qword ptr [r12 + 72]
    or rax, qword ptr [r12 + 80]
    or rax, qword ptr [r12 + 88]
    jnz ltb_lr_contract_fail
    ret
ltb_lr_path_admit:
    cmp qword ptr [r12 + 24], 1024
    jne ltb_lr_contract_fail
    mov rcx, qword ptr [rbx + 48]
    cmp qword ptr [r12 + 32], rcx
    jne ltb_lr_contract_fail
    cmp qword ptr [r12 + 40], 0
    jne ltb_lr_contract_fail
    mov rax, qword ptr [r15 + 24]
    sub rax, 1024
    jc ltb_lr_contract_fail
    cmp rcx, rax
    jae ltb_lr_contract_fail
    lea rax, [rbx + 1024]
    cmp byte ptr [rax + rcx], 0
    jne ltb_lr_contract_fail
    xor edx, edx
ltb_lr_path_scan:
    cmp rdx, rcx
    je ltb_lr_path_done
    cmp byte ptr [rax + rdx], 0
    je ltb_lr_contract_fail
    inc rdx
    jmp ltb_lr_path_scan
ltb_lr_path_done:
    ret
ltb_lr_zero_arguments:
    mov rax, qword ptr [r12 + 24]
    or rax, qword ptr [r12 + 32]
    or rax, qword ptr [r12 + 40]
    jnz ltb_lr_contract_fail
    ret
ltb_lr_fd_only:
    cmp qword ptr [r12 + 24], 1
    jne ltb_lr_contract_fail
    mov rax, qword ptr [r12 + 32]
    or rax, qword ptr [r12 + 40]
    jnz ltb_lr_contract_fail
    mov rdi, qword ptr [r15 + 72]
    test rdi, rdi
    jz ltb_lr_contract_fail
    dec rdi
    ret

# rbp is the fixed context offset of (pointer, capacity), never input data.
ltb_lr_resize_buffer:
    push r15
    mov rsi,rdi
    lea rdi,[r15+rbp]
    mov edx,1
    mov r15,[r15+96]
    call ltb_ensure_region
    pop r15
    ret

ltb_lr_cleanup:
    mov rdi, qword ptr [r15 + 72]
    mov qword ptr [r15 + 72], 0
    test rdi, rdi
    jz ltb_lr_cleanup_done
    dec rdi
    mov eax, 3
    syscall
ltb_lr_cleanup_done:
    ret
ltb_lr_contract_fail:
    call ltb_lr_cleanup
    mov edi, 70
    jmp ltb_lr_child_exit
ltb_lr_memory_fail:
    call ltb_lr_cleanup
    mov edi, 71
    jmp ltb_lr_child_exit
ltb_lr_io_fail:
    call ltb_lr_cleanup
    mov edi, 74
    jmp ltb_lr_child_exit
ltb_lr_allocation_abort:
    call ltb_lr_cleanup
    mov edi, 134
ltb_lr_child_exit:
    mov r15,[r15+96]
    jmp ltb_callable_abort
ltb_lr_empty_path:
    .byte 0

ltb_key_run:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp, 520
    mov r15, rdi
    cmp qword ptr [r15 + 72], -1
    jne ltb_key_contract_fail
    cmp qword ptr [r15 + 80], -1
    jne ltb_key_contract_fail
    mov rdi, qword ptr [r15 + 16]
    xor eax, eax
    mov ecx, 128
    rep stosq
    mov rbx, qword ptr [r15 + 16]
    mov rax, qword ptr [r15 + 64]
    mov qword ptr [rbx + 176], rax
    mov qword ptr [r15 + 88], 0
ltb_key_invoke:
    mov rdi, qword ptr [r15]
    mov rsi, qword ptr [r15 + 48]
    mov rdx, qword ptr [r15 + 32]
    mov rcx, qword ptr [r15 + 40]
    mov r8, qword ptr [r15 + 16]
    mov r9, qword ptr [r15 + 24]
    call qword ptr [r15 + 96]
    mov edx, eax
    cmp rax, rdx
    jne ltb_key_contract_fail
    mov rbx, qword ptr [r15 + 16]
    cmp eax, 0xffffffef
    je ltb_key_grow_workspace
    cmp eax, 0xffffffee
    je ltb_key_grow_output
    cmp eax, 0xfffffff0
    je ltb_key_admit_effect
    cmp eax, 0xffffffff
    je ltb_key_refusal
    cmp eax, 0xfffffffe
    je ltb_key_refusal
    cmp eax, 0xfffffff9
    je ltb_key_contract_fail
    cmp eax, 32
    jb ltb_key_contract_fail
    cmp rax, qword ptr [r15 + 40]
    ja ltb_key_contract_fail
    cmp qword ptr [rbx], 100
    jne ltb_key_contract_fail
    mov rdx, qword ptr [r15 + 32]
    mov rcx, 0x313030594b4c5248
    cmp qword ptr [rdx], rcx
    jne ltb_key_contract_fail
    lea rcx, [rax - 32]
    cmp qword ptr [rdx + 16], rcx
    jne ltb_key_contract_fail
    cmp qword ptr [rdx + 24], 0
    jne ltb_key_contract_fail
    cmp qword ptr [r15 + 72], -1
    jne ltb_key_contract_fail
    cmp qword ptr [r15 + 80], -1
    jne ltb_key_contract_fail
    mov dword ptr [r15 + 56], eax
    jmp ltb_key_done
ltb_key_refusal:
    mov dword ptr [r15 + 56], eax
    call ltb_key_cleanup
    jmp ltb_key_done

ltb_key_grow_workspace:
    mov rdi, qword ptr [rbx + 40]
    cmp rdi, qword ptr [rbx + 32]
    jbe ltb_key_contract_fail
    mov rax, 0x1ffffffffffbfeff
    cmp rdi, rax
    ja ltb_key_memory_fail
    shl rdi, 2
    add rdi, 1049600
    jc ltb_key_memory_fail
    call ltb_callable_key_round
    mov r12, rax
    cmp r12, qword ptr [r15 + 24]
    jbe ltb_key_invoke
    mov rdi, r12
    call ltb_callable_key_allocate
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
    jnz ltb_key_io_fail
    jmp ltb_key_invoke
ltb_key_grow_output:
    mov rdi, qword ptr [rbx + 48]
    cmp rdi, qword ptr [r15 + 40]
    jbe ltb_key_contract_fail
    mov rax, 0xffffffef
    cmp rdi, rax
    ja ltb_key_contract_fail
    call ltb_callable_key_round
    mov r12, rax
    mov rdi, r12
    call ltb_callable_key_allocate
    mov r13, rax
    mov rdi, qword ptr [r15 + 32]
    mov rsi, qword ptr [r15 + 40]
    add rsi, 4096
    mov qword ptr [r15 + 32], r13
    mov qword ptr [r15 + 40], r12
    mov eax, 11
    syscall
    test rax, rax
    jnz ltb_key_io_fail
    jmp ltb_key_invoke

ltb_key_admit_effect:
    mov rax, qword ptr [r15 + 48]
    cmp qword ptr [rbx + 8], rax
    jne ltb_key_contract_fail
    mov rax, qword ptr [r15 + 40]
    cmp qword ptr [rbx + 16], rax
    jne ltb_key_contract_fail
    mov rax, qword ptr [r15 + 24]
    cmp qword ptr [rbx + 24], rax
    jne ltb_key_contract_fail
    mov rax, qword ptr [rbx + 40]
    or rax, qword ptr [rbx + 48]
    jnz ltb_key_contract_fail
    mov rax, qword ptr [rbx + 32]
    cmp rax, 1024
    jb ltb_key_contract_fail
    lea rcx, [rax - 1]
    test rcx, rax
    jnz ltb_key_contract_fail
    cmp qword ptr [rbx + 96], rax
    jae ltb_key_contract_fail
    mov rcx, 0x1ffffffffffbfeff
    cmp rax, rcx
    ja ltb_key_contract_fail
    shl rax, 2
    add rax, 1049600
    jc ltb_key_contract_fail
    cmp rax, qword ptr [r15 + 24]
    ja ltb_key_contract_fail
    mov rax, 0x584659454b4c4648
    cmp qword ptr [rbx + 512], rax
    jne ltb_key_contract_fail
    inc qword ptr [r15 + 88]
    jz ltb_key_contract_fail
    mov rax, qword ptr [r15 + 88]
    cmp qword ptr [rbx + 520], rax
    jne ltb_key_contract_fail
    cmp qword ptr [rbx + 56], rax
    jne ltb_key_contract_fail
    mov rax, qword ptr [rbx + 568]
    or rax, qword ptr [rbx + 576]
    or rax, qword ptr [rbx + 584]
    or rax, qword ptr [rbx + 592]
    or rax, qword ptr [rbx + 600]
    or rax, qword ptr [rbx + 608]
    or rax, qword ptr [rbx + 616]
    or rax, qword ptr [rbx + 624]
    or rax, qword ptr [rbx + 632]
    jnz ltb_key_contract_fail
    mov r14, qword ptr [rbx + 528]
    cmp r14, 1
    je ltb_key_get_current
    cmp r14, 2
    je ltb_key_read_link
    cmp r14, 3
    je ltb_key_access_path
    cmp r14, 4
    je ltb_key_access_path
    cmp r14, 5
    je ltb_key_lstat_path
    cmp r14, 6
    je ltb_key_access_path
    cmp r14, 7
    je ltb_key_open_parent
    cmp r14, 8
    je ltb_key_stat_descriptor
    cmp r14, 9
    je ltb_key_close_descriptor
    cmp r14, 10
    je ltb_key_get_flags
    cmp r14, 11
    je ltb_key_set_cloexec
    cmp r14, 12
    je ltb_key_directory_entries
    cmp r14, 13
    je ltb_key_rewind_directory
    jmp ltb_key_contract_fail

ltb_key_get_current:
    cmp qword ptr [rbx], 10
    jne ltb_key_contract_fail
    call ltb_key_resolved_argument
    mov rdx, qword ptr [rbx + 552]
    or rdx, qword ptr [rbx + 560]
    jnz ltb_key_contract_fail
    mov rsi, qword ptr [rbx + 544]
    cmp rsi, qword ptr [rbx + 152]
    jne ltb_key_contract_fail
    cmp rsi, 1024
    jb ltb_key_contract_fail
    cmp rsi, qword ptr [rbx + 32]
    ja ltb_key_contract_fail
    mov eax, 79
    syscall
    jmp ltb_key_value_completion

ltb_key_read_link:
    cmp qword ptr [rbx], 3
    jne ltb_key_contract_fail
    call ltb_key_resolved_argument
    mov rcx, qword ptr [rbx + 544]
    cmp rcx, qword ptr [rbx + 96]
    jne ltb_key_contract_fail
    call ltb_key_cstring
    mov rax, qword ptr [rbx + 32]
    lea rax, [rax + rax + 1024]
    cmp qword ptr [rbx + 552], rax
    jne ltb_key_contract_fail
    lea rsi, [rbx + rax]
    mov rdx, qword ptr [rbx + 144]
    cmp rdx, 1024
    jb ltb_key_contract_fail
    dec rdx
    cmp rdx, qword ptr [rbx + 560]
    jne ltb_key_contract_fail
    cmp rdx, qword ptr [rbx + 32]
    jae ltb_key_contract_fail
    mov eax, 89
    syscall
    jmp ltb_key_value_completion

ltb_key_access_path:
    cmp qword ptr [rbx], 4
    jne ltb_key_contract_fail
    call ltb_key_resolved_argument
    mov rcx, qword ptr [rbx + 96]
    inc rcx
    cmp rcx, qword ptr [rbx + 32]
    jae ltb_key_contract_fail
    cmp rcx, qword ptr [rbx + 544]
    jne ltb_key_contract_fail
    call ltb_key_cstring
    mov rax, qword ptr [rbx + 552]
    or rax, qword ptr [rbx + 560]
    jnz ltb_key_contract_fail
    mov rsi, rdi
    mov edi, -100
    xor edx, edx
    mov r10d, 512
    mov eax, 439
    cmp r14, 3
    je ltb_key_access_go
    cmp r14, 4
    jne ltb_key_stat_access
    cmp qword ptr [r15 + 64], 0
    jne ltb_key_contract_fail
    mov eax, 269
ltb_key_access_go:
    syscall
    jmp ltb_key_zero_completion
ltb_key_stat_access:
    cmp qword ptr [r15 + 64], 1
    jne ltb_key_contract_fail
    xor r10d, r10d
    jmp ltb_key_stat_at

ltb_key_lstat_path:
    mov rax, qword ptr [rbx]
    cmp rax, 12
    je ltb_key_lstat_fixed
    cmp rax, 13
    je ltb_key_lstat_fixed
    cmp rax, 24
    jne ltb_key_contract_fail
    mov rax, qword ptr [rbx + 32]
    lea rax, [rax * 4 + 1024]
    add rax, qword ptr [rbx + 368]
    jc ltb_key_contract_fail
    cmp rax, qword ptr [rbx + 536]
    jne ltb_key_contract_fail
    mov rcx, qword ptr [rbx + 376]
    cmp rcx, qword ptr [rbx + 544]
    jne ltb_key_contract_fail
    mov rdx, qword ptr [rbx + 552]
    cmp rdx, qword ptr [rbx + 160]
    jne ltb_key_contract_fail
    jmp ltb_key_lstat_arguments
ltb_key_lstat_fixed:
    mov rax, qword ptr [rbx + 32]
    lea rax, [rax + rax + 1024]
    cmp rax, qword ptr [rbx + 536]
    jne ltb_key_contract_fail
    mov ecx, 1
    cmp qword ptr [rbx + 544], 1
    jne ltb_key_contract_fail
    cmp qword ptr [rbx + 552], 0
    jne ltb_key_contract_fail
    xor edx, edx
    cmp qword ptr [rbx], 12
    jne ltb_key_lstat_root
    cmp byte ptr [rbx + rax], 46
    jne ltb_key_contract_fail
    jmp ltb_key_lstat_arguments
ltb_key_lstat_root:
    cmp byte ptr [rbx + rax], 47
    jne ltb_key_contract_fail
ltb_key_lstat_arguments:
    cmp qword ptr [rbx + 560], 0
    jne ltb_key_contract_fail
    lea rdi, [rbx + rax]
    call ltb_key_cstring
    mov rsi, rdi
    mov edi, -100
    test rdx, rdx
    jz ltb_key_lstat_cwd
    call ltb_key_descriptor
ltb_key_lstat_cwd:
    mov r10d, 256
ltb_key_stat_at:
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
    jmp ltb_key_stat_completion

ltb_key_open_parent:
    cmp qword ptr [rbx], 15
    jne ltb_key_contract_fail
    mov rax, qword ptr [rbx + 552]
    or rax, qword ptr [rbx + 560]
    jnz ltb_key_contract_fail
    mov r12, qword ptr [rbx + 536]
    cmp r12, 1
    jb ltb_key_contract_fail
    cmp r12, 2
    ja ltb_key_contract_fail
    cmp qword ptr [r15 + r12 * 8 + 64], -1
    jne ltb_key_contract_fail
    mov rdx, qword ptr [rbx + 544]
    cmp rdx, qword ptr [rbx + 160]
    jne ltb_key_contract_fail
    cmp rdx, r12
    je ltb_key_contract_fail
    mov edi, -100
    test rdx, rdx
    jz ltb_key_open_parent_cwd
    call ltb_key_descriptor
ltb_key_open_parent_cwd:
    lea rsi, [rip + ltb_key_parent_name]
    xor edx, edx
    xor r10d, r10d
    mov eax, 257
    syscall
    test rax, rax
    js ltb_key_error_completion
    cmp rax, 0x7fffffff
    ja ltb_key_contract_fail
    mov qword ptr [r15 + r12 * 8 + 64], rax
    mov rax, r12
    jmp ltb_key_value_completion

ltb_key_stat_descriptor:
    mov rax, qword ptr [rbx]
    cmp rax, 16
    je ltb_key_stat_descriptor_phase
    cmp rax, 18
    jne ltb_key_contract_fail
ltb_key_stat_descriptor_phase:
    call ltb_key_zero_trailing_args
    mov rdx, qword ptr [rbx + 536]
    cmp rdx, qword ptr [rbx + 168]
    jne ltb_key_contract_fail
    call ltb_key_descriptor
    mov r13, rdi
    mov rdi, rsp
    xor eax, eax
    mov ecx, 32
    rep stosq
    mov rdi, r13
    mov rsi, rsp
    mov eax, 5
    syscall
ltb_key_stat_completion:
    test rax, rax
    js ltb_key_error_completion
    test rax, rax
    jnz ltb_key_contract_fail
    mov rax, qword ptr [rsp]
    mov qword ptr [rbx + 584], rax
    mov rax, qword ptr [rsp + 8]
    mov qword ptr [rbx + 592], rax
    mov eax, dword ptr [rsp + 24]
    mov qword ptr [rbx + 600], rax
    mov rax, qword ptr [rsp + 56]
    mov qword ptr [rbx + 616], rax
    jmp ltb_key_acknowledge

ltb_key_close_descriptor:
    mov rax, qword ptr [rbx]
    cmp rax, 17
    je ltb_key_close_phase
    cmp rax, 27
    je ltb_key_close_phase
    cmp rax, 29
    jne ltb_key_contract_fail
ltb_key_close_phase:
    call ltb_key_zero_trailing_args
    mov rdx, qword ptr [rbx + 536]
    call ltb_key_descriptor
    mov qword ptr [r15 + rdx * 8 + 64], -1
    mov eax, 3
    syscall
    jmp ltb_key_zero_completion

ltb_key_get_flags:
    cmp qword ptr [rbx], 19
    jne ltb_key_contract_fail
    call ltb_key_zero_trailing_args
    mov rdx, qword ptr [rbx + 536]
    cmp rdx, qword ptr [rbx + 168]
    jne ltb_key_contract_fail
    call ltb_key_descriptor
    mov esi, 3
    xor edx, edx
    mov eax, 72
    syscall
    jmp ltb_key_value_completion
ltb_key_set_cloexec:
    cmp qword ptr [rbx], 20
    jne ltb_key_contract_fail
    call ltb_key_zero_trailing_args
    mov rdx, qword ptr [rbx + 536]
    cmp rdx, qword ptr [rbx + 168]
    jne ltb_key_contract_fail
    call ltb_key_descriptor
    mov esi, 2
    mov edx, 1
    mov eax, 72
    syscall
    jmp ltb_key_zero_completion

ltb_key_directory_entries:
    cmp qword ptr [rbx], 22
    jne ltb_key_contract_fail
    cmp qword ptr [rbx + 560], 0
    jne ltb_key_contract_fail
    mov rax, qword ptr [rbx + 32]
    lea rax, [rax * 4 + 1024]
    cmp rax, qword ptr [rbx + 544]
    jne ltb_key_contract_fail
    mov r12, qword ptr [rbx + 552]
    cmp r12, 32768
    jb ltb_key_contract_fail
    cmp r12, 1048576
    ja ltb_key_contract_fail
    cmp r12, qword ptr [rbx + 336]
    jne ltb_key_contract_fail
    lea rsi, [rbx + rax]
    mov rdx, qword ptr [rbx + 536]
    cmp rdx, qword ptr [rbx + 160]
    jne ltb_key_contract_fail
    call ltb_key_descriptor
    mov rdx, r12
    mov eax, 217
    syscall
    jmp ltb_key_value_completion
ltb_key_rewind_directory:
    cmp qword ptr [rbx], 23
    jne ltb_key_contract_fail
    call ltb_key_zero_trailing_args
    mov rdx, qword ptr [rbx + 536]
    cmp rdx, qword ptr [rbx + 160]
    jne ltb_key_contract_fail
    call ltb_key_descriptor
    xor esi, esi
    xor edx, edx
    mov eax, 8
    syscall
    jmp ltb_key_value_completion

ltb_key_resolved_argument:
    mov rax, qword ptr [rbx + 32]
    add rax, 1024
    cmp qword ptr [rbx + 536], rax
    jne ltb_key_contract_fail
    lea rdi, [rbx + rax]
    ret
ltb_key_zero_trailing_args:
    mov rax, qword ptr [rbx + 544]
    or rax, qword ptr [rbx + 552]
    or rax, qword ptr [rbx + 560]
    jnz ltb_key_contract_fail
    ret
# logical slot in rdx -> real ltb_key_descriptor in rdi, preserving other arguments.
ltb_key_descriptor:
    cmp rdx, 1
    jb ltb_key_contract_fail
    cmp rdx, 2
    ja ltb_key_contract_fail
    mov rdi, qword ptr [r15 + rdx * 8 + 64]
    test rdi, rdi
    js ltb_key_contract_fail
    ret
# Exact span containment and unique final NUL.  rdx is preserved for dirfd.
ltb_key_cstring:
    mov rax, rdi
    sub rax, rbx
    jc ltb_key_contract_fail
    cmp rax, qword ptr [r15 + 24]
    jae ltb_key_contract_fail
    mov r11, qword ptr [r15 + 24]
    sub r11, rax
    cmp rcx, r11
    jae ltb_key_contract_fail
    cmp byte ptr [rdi + rcx], 0
    jne ltb_key_contract_fail
    xor eax, eax
ltb_key_cstring_loop:
    cmp rax, rcx
    je ltb_key_cstring_done
    cmp byte ptr [rdi + rax], 0
    je ltb_key_contract_fail
    inc rax
    jmp ltb_key_cstring_loop
ltb_key_cstring_done:
    ret
ltb_key_value_completion:
    test rax, rax
    js ltb_key_error_completion
    mov qword ptr [rbx + 568], rax
    jmp ltb_key_acknowledge
ltb_key_zero_completion:
    test rax, rax
    js ltb_key_error_completion
    test rax, rax
    jnz ltb_key_contract_fail
    jmp ltb_key_acknowledge
ltb_key_error_completion:
    neg rax
    cmp rax, 4095
    ja ltb_key_contract_fail
    mov qword ptr [rbx + 576], rax
ltb_key_acknowledge:
    mov qword ptr [rbx + 608], 1
    jmp ltb_key_invoke

ltb_key_cleanup:
    mov rdi, qword ptr [r15 + 72]
    mov qword ptr [r15 + 72], -1
    test rdi, rdi
    js ltb_key_cleanup_second
    mov eax, 3
    syscall
ltb_key_cleanup_second:
    mov rdi, qword ptr [r15 + 80]
    mov qword ptr [r15 + 80], -1
    test rdi, rdi
    js ltb_key_cleanup_done
    mov eax, 3
    syscall
ltb_key_cleanup_done:
    ret
ltb_key_done:
    mov eax, dword ptr [r15 + 56]
    add rsp, 520
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret
ltb_key_contract_fail:
    call ltb_key_cleanup
    mov edi, 70
    jmp ltb_fatal_exit
ltb_key_memory_fail:
    call ltb_key_cleanup
    mov edi, 71
    jmp ltb_fatal_exit
ltb_key_io_fail:
    call ltb_key_cleanup
    mov edi, 74
    jmp ltb_fatal_exit
ltb_key_parent_name:
    .asciz ".."

ltb_callable_key_round:
    push r15
    mov r15,[r15+104]
    call ltb_round_capacity
    pop r15
    ret
ltb_callable_key_allocate:
    push r15
    mov r15,[r15+104]
    call ltb_allocate_guarded
    pop r15
    ret

.balign 16,0
image_table:
.quad 0,0,0,0,0,0,0,0,0,0,0,0
.balign 16,0
images:
