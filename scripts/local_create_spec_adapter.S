/* Fixed private Local Create composition. HIA owns all semantic decisions. */
.intel_syntax noprefix
.section .text
.global _start
.equ I_SPEC,512
.equ I_READ,520
.equ I_PATH,528
.equ I_MKDIR,536
.equ I_WRITE,544
.equ I_KEY,552
.equ I_CACHE,560
.equ FRAME,576
.equ FRAMECAP,584
.equ FRAMELEN,592
.equ WORK,600
.equ WORKCAP,608
.equ OUT,616
.equ OUTCAP,624
.equ CURRENT,632
.equ CURRENTLEN,640
.equ CALLBACK,656
.equ CALLBACKCAP,664
.equ CHILD,672
.equ SEQUENCE,680
.equ GENERATION,688
.equ CHILDREQ,696
.equ CHILDREQLEN,704
.equ CHILDRESULT,712
.equ CHILDRESULTLEN,720
.equ CHILDCODE,728
.equ CREATED,736
.equ CACHE_INIT,744
.equ CACHE,752
.equ CACHECAP,760
.equ CACHEOUT,768
.equ CACHEOUTCAP,776
.equ CACHEINPUT,784
.equ CACHEINPUTLEN,792
.equ SCRATCH,800
.equ SCRATCHCAP,808
.equ SUBOUT,816
.equ SUBOUTCAP,824
.equ ACTIVE_KIND,848
.equ ASYNCINPUT,856
.equ ASYNCWORK,864
.equ ASYNCINCAP,872
.equ ASYNCWCAP,880
.equ MKREQ,888
.equ MKREQCAP,896
.equ MKWORK,904
.equ MKWORKCAP,912
.equ MKSEQ,928
.equ SECURE,984
.equ KEYCTX,2048
.equ READCTX,2176

_start:
    xor r15d,r15d
    cmp qword ptr [rsp],1
    jne usage
    xor r14d,r14d
    lea rsi,[rsp+24]
find_environment_end:
    cmp qword ptr [rsi],0
    lea rsi,[rsi+8]
    jne find_environment_end
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
image_addresses:
    mov rdx,[rsi+rcx*8]
    test rdx,rdx
    jz contract
    cmp rdx,1048576
    ja contract
    mov [r15+I_SPEC+rcx*8],rax
    add rax,rdx
    jc contract
    inc ecx
    cmp ecx,7
    jb image_addresses
    mov rax,0x314d495350434c48
    cmp [rsi+56],rax
    jne contract
    mov edi,4096
    call async_map
    mov [r15+320],rax
    mov rbx,rax
    mov qword ptr [rbx],-1
    mov [rbx+112],rbx
    mov eax,39
    syscall
    mov [rbx+40],rax
    mov edi,0x1001
    mov rsi,rbx
    mov eax,158
    syscall
    test rax,rax
    jnz infrastructure
    lea rax,[rip+async_cancel_handler]
    mov [r15+256],rax
    mov qword ptr [r15+264],0x4000000
    lea rax,[rip+async_sigreturn]
    mov [r15+272],rax
    mov qword ptr [r15+280],0
    mov edi,10
    lea rsi,[r15+256]
    xor edx,edx
    mov r10d,8
    mov eax,13
    syscall
    test rax,rax
    jnz infrastructure
    lea rax,[rip+async_wake_handler]
    mov [r15+256],rax
    mov edi,12
    lea rsi,[r15+256]
    xor edx,edx
    mov r10d,8
    mov eax,13
    syscall
    test rax,rax
    jnz infrastructure
    mov qword ptr [r15+256],1
    mov edi,13
    lea rsi,[r15+256]
    xor edx,edx
    mov r10d,8
    mov eax,13
    syscall
    test rax,rax
    jnz infrastructure

next_frame:
    xor edi,edi
    lea rsi,[r15+FRAMELEN]
    mov edx,8
    call read_header
    test eax,eax
    jz success
    mov rsi,[r15+FRAMELEN]
    mov eax,0xffff0000
    cmp rsi,rax
    jae infrastructure
    lea rdi,[r15+FRAME]
    xor edx,edx
    call ensure_region
    mov rdi,[r15+FRAME]
    mov rsi,[r15+FRAMECAP]
    call make_writable
    xor edi,edi
    mov rsi,[r15+FRAME]
    mov rdx,[r15+FRAMELEN]
    call read_exact
    test eax,eax
    jnz infrastructure
    mov rdi,[r15+FRAME]
    mov rsi,[r15+FRAMECAP]
    call make_readonly
    cmp qword ptr [r15+FRAMELEN],8
    jb frame_refusal
    mov rbx,[r15+FRAME]
    mov rax,0x3130484341435648
    cmp [rbx],rax
    je fixture_cache
    mov rax,0x3130515053434c48
    cmp [rbx],rax
    jne frame_refusal
    cmp qword ptr [r15+CREATED],0
    jne frame_refusal
    cmp qword ptr [r15+CACHE_INIT],1
    jne frame_refusal
    mov qword ptr [r15+CREATED],1
    xor edi,edi
    call observe_cache
    mov rax,[r15+FRAME]
    mov [r15+CURRENT],rax
    mov rax,[r15+FRAMELEN]
    mov [r15+CURRENTLEN],rax
    lea rdi,[r15+WORK]
    mov esi,4096
    xor edx,edx
    call ensure_region
    mov rbx,[r15+320]
    mov rdx,[rbx+16]
    mov [rax+112],rdx
    lea rdi,[r15+OUT]
    mov esi,4096
    xor edx,edx
    call ensure_region
    jmp full_invoke

fixture_cache:
    cmp qword ptr [r15+FRAMELEN],48
    jb frame_refusal
    cmp qword ptr [rbx+16],0
    jne frame_refusal
    cmp qword ptr [r15+CACHE_INIT],0
    jne fixture_cache_active
    cmp qword ptr [r15+FRAMELEN],48
    jne frame_refusal
    mov rax,[rbx+8]
    or rax,[rbx+24]
    or rax,[rbx+32]
    or rax,[rbx+40]
    jnz frame_refusal
    mov qword ptr [r15+CACHE_INIT],1
    jmp fixture_cache_call
fixture_cache_active:
    mov rax,[rbx+8]
    cmp rax,1
    je fixture_cache_call
    cmp qword ptr [r15+CREATED],0
    jne frame_refusal
    cmp rax,2
    je fixture_cache_call
    cmp rax,9
    jne frame_refusal
fixture_cache_call:
    mov [r15+CACHEINPUT],rbx
    mov rax,[r15+FRAMELEN]
    mov [r15+CACHEINPUTLEN],rax
    call cache_run
    mov [r15+1000],rax
    mov edi,1
    lea rsi,[r15+1000]
    mov edx,8
    call write_all
    test eax,eax
    jnz infrastructure
    mov rdx,[r15+1000]
    cmp edx,0xffff0000
    jae next_frame
    mov edi,1
    mov rsi,[r15+CACHEOUT]
    call write_all
    test eax,eax
    jnz infrastructure
    jmp next_frame
frame_refusal:
    mov eax,0xffffffff
    mov [r15+1000],rax
    mov edi,1
    lea rsi,[r15+1000]
    mov edx,8
    call write_all
    test eax,eax
    jnz infrastructure
    jmp next_frame

full_invoke:
    mov rdi,[r15+OUT]
    mov rsi,[r15+OUTCAP]
    call make_writable
    mov rdi,[r15+CURRENT]
    mov rsi,[r15+CURRENTLEN]
    mov rdx,[r15+OUT]
    mov rcx,[r15+OUTCAP]
    mov r8,[r15+WORK]
    mov r9,[r15+WORKCAP]
    call qword ptr [r15+I_SPEC]
    mov edx,eax
    cmp rax,rdx
    jne contract
    cmp eax,0xffffffef
    je full_grow_work
    cmp eax,0xffffffee
    je full_grow_output
    cmp eax,0xffffffe0
    je full_child
    cmp eax,0xfffffff7
    je full_publish_scalar
    cmp eax,0xffff0000
    jae full_publish_scalar
    cmp eax,32
    jb contract
    cmp rax,[r15+OUTCAP]
    ja contract
    mov rbx,[r15+OUT]
    mov rdx,0x3130525053434c48
    cmp [rbx],rdx
    jne contract
full_publish_scalar:
    mov [r15+1000],rax
    mov edi,1
    lea rsi,[r15+1000]
    mov edx,8
    call write_all
    test eax,eax
    jnz infrastructure
    mov rdx,[r15+1000]
    cmp edx,0xffff0000
    jae full_finished
    mov edi,1
    mov rsi,[r15+OUT]
    call write_all
    test eax,eax
    jnz infrastructure
full_finished:
    mov edi,1
    call observe_cache
    jmp next_frame
full_grow_work:
    mov rax,[r15+WORK]
    mov rsi,[rax+104]
    cmp rsi,[r15+WORKCAP]
    jbe contract
    lea rdi,[r15+WORK]
    mov edx,1
    call ensure_region
    jmp full_invoke
full_grow_output:
    mov rax,[r15+WORK]
    mov rsi,[rax+136]
    cmp rsi,[r15+OUTCAP]
    jbe contract
    lea rdi,[r15+OUT]
    xor edx,edx
    call ensure_region
    jmp full_invoke

full_child:
    mov rbx,[r15+OUT]
    mov rax,0x3158465053434c48
    cmp [rbx],rax
    jne contract
    cmp qword ptr [rbx+56],0
    jne contract
    mov rax,[rbx+8]
    cmp rax,[r15+OUTCAP]
    ja contract
    sub rax,64
    jc contract
    cmp [rbx+48],rax
    jne contract
    mov [r15+CHILDREQLEN],rax
    lea rax,[rbx+64]
    mov [r15+CHILDREQ],rax
    mov rdx,[r15+WORK]
    mov rax,[rbx+16]
    cmp rax,1
    jb contract
    cmp rax,7
    ja contract
    cmp [rdx+144],rax
    jne contract
    mov [r15+CHILD],rax
    mov rax,[rbx+24]
    cmp [rdx+16],rax
    jne contract
    mov [r15+SEQUENCE],rax
    mov rax,[rbx+32]
    cmp [rdx+24],rax
    jne contract
    mov [r15+GENERATION],rax
    mov rax,[r15+CHILD]
    mov ecx,1
    cmp rax,3
    jne not_mkdir_flags
    mov ecx,3
not_mkdir_flags:
    cmp rax,4
    jne child_flags_ready
    mov ecx,5
child_flags_ready:
    cmp [rbx+40],rcx
    jne contract
    mov edi,2
    mov rsi,rbx
    mov edx,64
    call write_all
    test eax,eax
    jnz infrastructure
    mov rdi,[r15+OUT]
    mov rsi,[r15+OUTCAP]
    call make_readonly
    mov rax,[r15+CHILD]
    cmp rax,1
    je child_read
    cmp rax,2
    je child_path
    cmp rax,3
    je child_mkdir
    cmp rax,4
    je child_write
    cmp rax,5
    je child_key
    cmp rax,6
    je child_cache
    mov rax,[r15+CHILDREQ]
    cmp qword ptr [r15+CHILDREQLEN],16
    jne contract
    mov rdx,0x313051544d434c48
    cmp [rax],rdx
    jne contract
    cmp qword ptr [rax+8],0
    jne contract
    mov rax,0x313052544d434c48
    mov [r15+1104],rax
    mov rax,[r15+320]
    movzx eax,byte ptr [rax+128]
    cmp eax,2
    ja contract
    mov [r15+1112],rax
    lea rax,[r15+1104]
    mov [r15+CHILDRESULT],rax
    mov qword ptr [r15+CHILDRESULTLEN],16
    mov qword ptr [r15+CHILDCODE],16
    jmp full_finish_child

child_read:
    lea rdi,[r15+SCRATCH]
    mov rsi,[r15+CHILDREQLEN]
    add rsi,1024
    jc infrastructure
    xor edx,edx
    call ensure_region
    lea rdi,[r15+SUBOUT]
    mov esi,4096
    xor edx,edx
    call ensure_region
    lea rdi,[r15+READCTX]
    xor eax,eax
    mov ecx,12
    rep stosq
    mov rax,[r15+CHILDREQ]
    mov [r15+READCTX],rax
    mov rax,[r15+CHILDREQLEN]
    mov [r15+READCTX+48],rax
    mov rax,[r15+SCRATCH]
    mov [r15+READCTX+16],rax
    mov rax,[r15+SCRATCHCAP]
    mov [r15+READCTX+24],rax
    mov rax,[r15+SUBOUT]
    mov [r15+READCTX+32],rax
    mov rax,[r15+SUBOUTCAP]
    mov [r15+READCTX+40],rax
    mov rax,[r15+320]
    add rax,128
    mov [r15+READCTX+64],rax
    mov rax,[r15+I_READ]
    mov [r15+READCTX+80],rax
    lea rdi,[r15+READCTX]
    call local_read_run
    cmp eax,40
    jne contract
    mov [r15+CHILDCODE],rax
    mov [r15+CHILDRESULTLEN],rax
    mov rax,[r15+SUBOUT]
    mov [r15+CHILDRESULT],rax
    jmp full_finish_child
child_path:
    lea rdi,[r15+SCRATCH]
    mov esi,4096
    xor edx,edx
    call ensure_region
    lea rdi,[r15+SUBOUT]
    mov rsi,[r15+CHILDREQLEN]
    add rsi,80
    jc infrastructure
    xor edx,edx
    call ensure_region
    mov rdi,[r15+CHILDREQ]
    mov rsi,[r15+CHILDREQLEN]
    mov rdx,[r15+SUBOUT]
    mov rcx,[r15+SUBOUTCAP]
    mov r8,[r15+SCRATCH]
    mov r9,[r15+SCRATCHCAP]
    call qword ptr [r15+I_PATH]
    cmp eax,80
    jne contract
    mov [r15+CHILDCODE],rax
    mov rdx,[r15+SUBOUT]
    mov [r15+CHILDRESULT],rdx
    mov rax,[rdx+16]
    cmp rax,[r15+SUBOUTCAP]
    ja contract
    mov [r15+CHILDRESULTLEN],rax
    jmp full_finish_child
child_key:
    lea rdi,[r15+KEYCTX+16]
    mov esi,1056768
    xor edx,edx
    call ensure_region
    lea rdi,[r15+KEYCTX+32]
    mov esi,4096
    xor edx,edx
    call ensure_region
    mov rax,[r15+CHILDREQ]
    mov [r15+KEYCTX],rax
    mov rax,[r15+CHILDREQLEN]
    mov [r15+KEYCTX+48],rax
    mov rax,[r15+SECURE]
    mov [r15+KEYCTX+64],rax
    mov qword ptr [r15+KEYCTX+72],-1
    mov qword ptr [r15+KEYCTX+80],-1
    mov qword ptr [r15+KEYCTX+88],0
    mov rax,[r15+I_KEY]
    mov [r15+KEYCTX+96],rax
    lea rdi,[r15+KEYCTX]
    call key_run
    cmp eax,32
    jb contract
    cmp eax,0xffff0000
    jae contract
    mov [r15+CHILDCODE],rax
    mov [r15+CHILDRESULTLEN],rax
    mov rax,[r15+KEYCTX+32]
    mov [r15+CHILDRESULT],rax
    jmp full_finish_child
child_cache:
    mov rax,[r15+CHILDREQ]
    mov [r15+CACHEINPUT],rax
    mov rax,[r15+CHILDREQLEN]
    mov [r15+CACHEINPUTLEN],rax
    call cache_run
    cmp eax,32
    jne contract
    mov [r15+CHILDCODE],rax
    mov [r15+CHILDRESULTLEN],rax
    mov rax,[r15+CACHEOUT]
    mov [r15+CHILDRESULT],rax
full_finish_child:
    call build_callback
    jmp full_invoke

build_callback:
    lea rdi,[r15+CALLBACK]
    mov rsi,[r15+CHILDRESULTLEN]
    add rsi,64
    jc infrastructure
    xor edx,edx
    call ensure_region
    mov rdi,[r15+CALLBACK]
    mov rsi,[r15+CALLBACKCAP]
    call make_writable
    mov rdi,[r15+CALLBACK]
    mov rax,0x3130435053434c48
    mov [rdi],rax
    mov qword ptr [rdi+8],2
    mov rax,[r15+GENERATION]
    mov [rdi+16],rax
    mov rax,[r15+SEQUENCE]
    mov [rdi+24],rax
    mov rax,[r15+CHILD]
    mov [rdi+32],rax
    mov rax,[r15+CHILDCODE]
    mov [rdi+40],rax
    mov rcx,[r15+CHILDRESULTLEN]
    mov [rdi+48],rcx
    mov qword ptr [rdi+56],0
    mov rsi,[r15+CHILDRESULT]
    add rdi,64
    rep movsb
    mov rdi,[r15+CALLBACK]
    mov rsi,[r15+CALLBACKCAP]
    call make_readonly
    mov rax,[r15+CALLBACK]
    mov [r15+CURRENT],rax
    mov rax,[r15+CHILDRESULTLEN]
    add rax,64
    mov [r15+CURRENTLEN],rax
    ret

cache_run:
    push rbx
    mov rbx,[r15+CACHEINPUT]
    mov esi,4096
    cmp qword ptr [r15+CACHE],0
    je cache_need_key
    mov rax,[r15+CACHE]
    mov rsi,[rax+16]
cache_need_key:
    cmp qword ptr [r15+CACHEINPUTLEN],48
    jb cache_no_reserve
    mov rdx,[rbx+24]
    cmp rdx,[r15+CACHEINPUTLEN]
    ja cache_no_reserve
    add rsi,rdx
    jc infrastructure
    mov rdx,[rbx+32]
    cmp rdx,1048576
    jbe cache_value_bound
    mov edx,1048576
cache_value_bound:
    add rsi,rdx
    jc infrastructure
cache_no_value:
    add rsi,128
    jc infrastructure
cache_no_reserve:
    lea rdi,[r15+CACHE]
    mov edx,1
    call ensure_region
    lea rdi,[r15+CACHEOUT]
    mov esi,1048608
    xor edx,edx
    call ensure_region
    mov rdi,[r15+CACHEINPUT]
    mov rsi,[r15+CACHEINPUTLEN]
    mov rdx,[r15+CACHEOUT]
    mov rcx,[r15+CACHEOUTCAP]
    mov r8,[r15+CACHE]
    mov r9,[r15+CACHECAP]
    call qword ptr [r15+I_CACHE]
    mov edx,eax
    cmp rax,rdx
    jne contract
    cmp eax,0xffff0000
    jae cache_return
    cmp eax,32
    jb contract
    cmp rax,[r15+CACHEOUTCAP]
    ja contract
cache_return:
    pop rbx
    ret

/* Qualification observer only: complete owned arena, never accepted as input. */
observe_cache:
    mov [r15+1136],rdi
    mov rax,0x3130414e53434c48
    mov [r15+1120],rax
    mov rax,[r15+CACHECAP]
    mov [r15+1144],rax
    add rax,48
    jc infrastructure
    mov [r15+1128],rax
    mov rax,[r15+CACHE]
    mov rax,[rax+16]
    cmp rax,[r15+CACHECAP]
    ja contract
    mov [r15+1152],rax
    mov qword ptr [r15+1160],0
    mov edi,2
    lea rsi,[r15+1120]
    mov edx,48
    call write_all
    test eax,eax
    jnz infrastructure
    mov edi,2
    mov rsi,[r15+CACHE]
    mov rdx,[r15+CACHECAP]
    call write_all
    test eax,eax
    jnz infrastructure
    ret

/* Fixed memory/transport primitives; no filesystem policy. */
round_capacity:
    mov rax,rdi
    add rax,4095
    jc infrastructure
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
    jc infrastructure
    xor edi,edi
    mov edx,3
    mov r10d,0x22
    mov r8,-1
    xor r9d,r9d
    mov eax,9
    syscall
    cmp rax,-4095
    jae infrastructure
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
make_readonly:
    mov edx,1
    jmp set_protection
make_writable:
    mov edx,3
set_protection:
    mov eax,10
    syscall
    test rax,rax
    jnz infrastructure
    ret
protect_input:
    mov rdi,r12
    mov rsi,[r15+8]
    jmp make_readonly
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
    jz io_ok
read_again:
    xor eax,eax
    syscall
    cmp rax,-4
    je read_again
    test rax,rax
    jle io_bad
    add rsi,rax
    sub rdx,rax
    jnz read_again
    jmp io_ok
write_all:
    test rdx,rdx
    jz io_ok
write_again:
    mov eax,1
    syscall
    cmp rax,-4
    je write_again
    test rax,rax
    jle io_bad
    add rsi,rax
    sub rdx,rax
    jnz write_again
io_ok:
    xor eax,eax
    ret
io_bad:
    mov eax,1
    ret
local_create_entry:
    mov rax,0x313051414d434c48
    cmp [rdi],rax
    je mkdir_await_entry
    jmp qword ptr [r15+I_WRITE]
mkdir_await_entry:
    jmp qword ptr [r15+I_SPEC]
success:
    xor edi,edi
    jmp fatal_exit
usage:
    mov edi,64
    jmp fatal_exit
contract:
    jmp async_contract
infrastructure:
    test r15,r15
    jz bare_infrastructure
    cmp qword ptr [r15+320],0
    jne async_infrastructure
bare_infrastructure:
    mov edi,74
fatal_exit:
    mov eax,60
    syscall
    ud2

/* Bind an already admitted HIA child call to one real worker mechanism. */
child_write:
    mov qword ptr [r15+ACTIVE_KIND],4
    mov r13,[r15+CHILDREQLEN]
    mov rdi,r13
    call round_capacity
    mov [r15+8],rax
    mov [r15+ASYNCINCAP],rax
    mov rdi,rax
    call async_map
    mov r12,rax
    mov [r15+ASYNCINPUT],rax
    mov rdi,rax
    mov rsi,[r15+CHILDREQ]
    mov rcx,r13
    rep movsb
    mov rdi,r13
    add rdi,456
    jc infrastructure
    and rdi,-8
    mov [r15+304],rdi
    add rdi,256
    jc infrastructure
    mov [r15+16],rdi
    mov [r15+ASYNCWCAP],rdi
    call async_map
    mov r14,rax
    mov [r15+ASYNCWORK],rax
    jmp nested_initialize

child_mkdir:
    mov qword ptr [r15+ACTIVE_KIND],3
    lea rdi,[r15+MKREQ]
    mov rsi,[r15+CHILDREQLEN]
    xor edx,edx
    call ensure_region
    mov rdi,rax
    mov rsi,[r15+CHILDREQ]
    mov rcx,[r15+CHILDREQLEN]
    rep movsb
    mov rdi,[r15+MKREQ]
    mov rsi,[r15+MKREQCAP]
    call make_readonly
    mov rax,[r15+MKREQ]
    mov rsi,[rax+24]
    inc rsi
    jz infrastructure
    mov rax,rsi
    mov ecx,10
    mul rcx
    test rdx,rdx
    jnz infrastructure
    mov rsi,rax
    add rsi,512
    jc infrastructure
    lea rdi,[r15+MKWORK]
    xor edx,edx
    call ensure_region
    lea rdi,[r15+SUBOUT]
    mov esi,4096
    xor edx,edx
    call ensure_region
    mov qword ptr [r15+MKSEQ],0
    mov qword ptr [r15+304],0
    mov qword ptr [r15+8],4096
    mov qword ptr [r15+ASYNCINCAP],4096
    mov edi,4096
    call async_map
    mov r12,rax
    mov [r15+ASYNCINPUT],rax
    mov rax,0x313051414d434c48
    mov [r12],rax
    mov qword ptr [r12+8],1
    mov rax,[r15+GENERATION]
    mov [r12+32],rax
    mov r13d,64
    mov qword ptr [r15+16],512
    mov qword ptr [r15+ASYNCWCAP],512
    mov edi,512
    call async_map
    mov r14,rax
    mov [r15+ASYNCWORK],rax
nested_initialize:
    mov rbx,[r15+320]
    cmp qword ptr [rbx],-1
    jne async_contract
    cmp qword ptr [rbx+32],0
    jne async_contract
    cmp qword ptr [rbx+8],0
    jne async_contract
    mov qword ptr [rbx+48],0
    mov qword ptr [rbx+56],0
    mov qword ptr [rbx+64],0
    mov qword ptr [rbx+72],0
    mov qword ptr [rbx+80],0
    mov qword ptr [rbx+96],0
    mov qword ptr [r15+488],0
    mov qword ptr [r15+496],0
    call protect_input
    mov edi,1
    xor esi,esi
    xor edx,edx
    call async_call
    cmp eax,128
    jne async_contract
    cmp qword ptr [r15+368],10
    jne async_contract
    /* The enclosing parent is still inside the same owned poll turn. */
    mov edi,2
    xor esi,esi
    xor edx,edx
    call async_call
    jmp async_parent_dispatch

nested_continue:
    mov edi,8
    xor esi,esi
    call async_parent_call
    jmp async_parent_dispatch
nested_mkdir_result:
    cmp qword ptr [r15+ACTIVE_KIND],3
    jne async_contract
    mov rbx,[r15+320]
    cmp qword ptr [rbx+32],0
    jne async_contract
    cmp qword ptr [rbx],-1
    jne async_contract
    mov rax,0x3130524b4d485348
    cmp [r15+352],rax
    jne async_contract
    mov eax,32
    jmp nested_result
nested_write_result:
    cmp qword ptr [r15+ACTIVE_KIND],4
    jne async_contract
    mov eax,48
nested_result:
    mov [r15+CHILDCODE],rax
    mov [r15+CHILDRESULTLEN],rax
    lea rax,[r15+352]
    mov [r15+CHILDRESULT],rax
    call build_callback
    call retire_nested
    jmp full_invoke

/* First publish the real parent cancellation, then drain its owned worker. */
nested_publish_cancel:
    mov qword ptr [r15+CHILDRESULT],0
    mov qword ptr [r15+CHILDRESULTLEN],0
    mov eax,0xfffffff7
    mov [r15+CHILDCODE],rax
    call build_callback
    mov rdi,[r15+OUT]
    mov rsi,[r15+OUTCAP]
    call make_writable
    mov rdi,[r15+CURRENT]
    mov rsi,[r15+CURRENTLEN]
    mov rdx,[r15+OUT]
    mov rcx,[r15+OUTCAP]
    mov r8,[r15+WORK]
    mov r9,[r15+WORKCAP]
    call qword ptr [r15+I_SPEC]
    mov edx,eax
    cmp rax,rdx
    jne async_contract
    cmp eax,0xfffffff7
    jne async_contract
    mov [r15+1000],rax
    mov edi,1
    lea rsi,[r15+1000]
    mov edx,8
    call write_all
    test eax,eax
    jnz async_infrastructure
    ret
nested_canceled:
    call retire_nested
    jmp full_finished
retire_nested:
    mov rdi,[r15+ASYNCINPUT]
    mov rsi,[r15+ASYNCINCAP]
    mov eax,11
    syscall
    test rax,rax
    jnz infrastructure
    mov rdi,[r15+ASYNCWORK]
    mov rsi,[r15+ASYNCWCAP]
    mov eax,11
    syscall
    test rax,rax
    jnz infrastructure
    mov qword ptr [r15+ASYNCINPUT],0
    mov qword ptr [r15+ASYNCWORK],0
    mov qword ptr [r15+ACTIVE_KIND],0
    ret

/* One whole HIA mkdir algorithm runs inside one admitted blocking ticket. */
mkdir_child:
    mov rbx,[r15+320]
    mov edi,4
    mov rsi,[rbx+64]
    xor edx,edx
    call async_call
    cmp eax,128
    jne async_contract
    cmp qword ptr [r15+368],8
    jne async_contract
mkdir_invoke:
    mov rdi,[r15+MKREQ]
    mov rsi,[r15+CHILDREQLEN]
    mov rdx,[r15+SUBOUT]
    mov rcx,[r15+SUBOUTCAP]
    mov r8,[r15+MKWORK]
    mov r9,[r15+MKWORKCAP]
    call qword ptr [r15+I_MKDIR]
    mov edx,eax
    cmp rax,rdx
    jne async_contract
    cmp eax,32
    je mkdir_complete
    cmp eax,0xfffffffd
    jne async_contract
    call mkdir_effect
    mov rdi,[r15+MKREQ]
    mov rsi,[r15+MKREQCAP]
    call make_writable
    mov rax,[r15+MKREQ]
    mov qword ptr [rax+8],2
    mov qword ptr [rax+16],0
    mov rdi,rax
    mov rsi,[r15+MKREQCAP]
    call make_readonly
    jmp mkdir_invoke
mkdir_complete:
    mov rsi,[r15+SUBOUT]
    mov rax,0x3130524b4d485348
    cmp [rsi],rax
    jne async_contract
    cmp qword ptr [rsi+24],2
    ja async_contract
    call async_lock
    cmp qword ptr [r14+248],0
    jne async_contract
    mov rsi,[r15+SUBOUT]
    mov rax,[rsi+24]
    mov byte ptr [rbx+128],al
    lea rdi,[r14+256]
    mov ecx,32
    rep movsb
    mov qword ptr [r14+248],1
    call async_unlock
    mov edi,5
    mov rsi,[rbx+64]
    xor edx,edx
    call async_call
    cmp eax,128
    jne async_contract
    cmp qword ptr [r15+368],9
    jne async_contract
    jmp async_child_ready

mkdir_effect:
    push rbp
    push rbx
    sub rsp,272
    mov rbx,[r15+MKWORK]
    lea rbp,[rbx+96]
    mov rax,0x3158464b4d485348
    cmp [rbp],rax
    jne async_contract
    mov rax,[r15+MKSEQ]
    inc rax
    jz async_contract
    cmp [rbp+8],rax
    jne async_contract
    cmp [rbx+80],rax
    jne async_contract
    cmp qword ptr [rbx+72],1
    jne async_contract
    mov [r15+MKSEQ],rax
    mov rax,[rbp+48]
    or rax,[rbp+56]
    or rax,[rbp+64]
    or rax,[rbp+72]
    or rax,[rbp+80]
    or rax,[rbp+88]
    jnz async_contract
    mov rax,[rbp+16]
    cmp [rbx+88],rax
    jne async_contract
    cmp rax,1
    jb async_contract
    cmp rax,4
    ja async_contract
    mov [rsp+256],rax
    cmp rax,3
    je mkdir_probe
    mov rcx,[r15+MKREQ]
    mov rcx,[rcx+24]
    mov rdx,rcx
    add rcx,513
    jc async_contract
    cmp [rbp+24],rcx
    jne async_contract
    cmp [rbp+32],rdx
    ja async_contract
    cmp rcx,[r15+MKWORKCAP]
    jae async_contract
    mov rdx,[r15+MKWORKCAP]
    sub rdx,rcx
    cmp [rbp+32],rdx
    jae async_contract
    lea rsi,[rbx+rcx]
    mov rcx,[rbp+32]
    cmp byte ptr [rsi+rcx],0
    jne async_contract
    xor edx,edx
mkdir_cstring_check:
    cmp rdx,rcx
    jae mkdir_cstring_ready
    cmp byte ptr [rsi+rdx],0
    je async_contract
    inc rdx
    jmp mkdir_cstring_check
mkdir_cstring_ready:
    cmp qword ptr [rsp+256],1
    je mkdir_dispatch
    mov rdi,rsp
    xor eax,eax
    mov ecx,32
    rep stosq
    cmp qword ptr [rsp+256],2
    je mkdir_statx
    cmp qword ptr [rbp+40],0
    jne async_contract
    mov rdi,-100
    mov rdx,rsp
    xor r10d,r10d
    mov eax,262
    syscall
    test rax,rax
    jnz mkdir_effect_return
    mov edx,[rsp+24]
    mov [rbp+72],rdx
    jmp mkdir_effect_return
mkdir_statx:
    cmp qword ptr [rbp+40],4095
    jne async_contract
    mov rdi,-100
    xor edx,edx
    mov r10d,4095
    mov r8,rsp
    mov eax,332
    syscall
    test rax,rax
    jnz mkdir_effect_return
    movzx edx,word ptr [rsp+28]
    mov [rbp+72],rdx
    jmp mkdir_effect_return
mkdir_dispatch:
    cmp qword ptr [rbp+40],511
    jne async_contract
    mov rdi,rsi
    mov esi,511
    mov eax,83
    syscall
    jmp mkdir_effect_return
mkdir_probe:
    mov rax,[rbp+24]
    or rax,[rbp+32]
    jnz async_contract
    cmp qword ptr [rbp+40],4095
    jne async_contract
    xor edi,edi
    xor esi,esi
    xor edx,edx
    mov r10d,4095
    xor r8d,r8d
    mov eax,332
    syscall
mkdir_effect_return:
    mov [rbp+56],rax
    test rax,rax
    jz mkdir_effect_success
    jns async_contract
    cmp rax,-4095
    jl async_contract
    neg rax
    mov [rbp+64],rax
mkdir_effect_success:
    mov qword ptr [rbp+48],1
    mov edi,2
    mov rsi,rbp
    mov edx,96
    call write_all
    test eax,eax
    jnz async_infrastructure
    add rsp,272
    pop rbx
    pop rbp
    ret

async_parent_dispatch:
    cmp eax,32
    je nested_mkdir_result
    cmp eax,48
    je async_normal_result
    cmp eax,128
    jne async_contract
    mov rax,[r15+368]
    cmp rax,1
    je async_queue_child
    cmp rax,2
    je async_queue_child
    cmp rax,3
    je async_parent_wait
    cmp rax,4
    je async_parent_close
    cmp rax,6
    je async_cancel_result
    cmp rax,11
    je async_parent_reap
    cmp rax,12
    je async_queue_child
    cmp rax,10
    je nested_continue
    jmp async_contract

/* HIA calls are serialized; admitted syscalls execute outside this mutex. */
async_call:
    push rbp
    mov rbp,rsp
    and rsp,-16
    mov [r15+336],rdi
    mov [r15+344],rsi
    mov [r15+480],rdx
    call async_lock
    mov rdi,r12
    mov rsi,[r15+8]
    mov edx,3
    mov eax,10
    syscall
    test rax,rax
    jnz async_infrastructure
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
    jnz async_infrastructure
    mov rdi,r12
    mov rsi,r13
    lea rdx,[r15+352]
    mov ecx,128
    mov r8,r14
    mov r9,[r15+16]
    call local_create_entry
    mov edx,eax
    cmp rax,rdx
    jne async_contract
    mov [r15+24],rax
    call async_unlock
    mov rax,[r15+24]
    cmp eax,128
    jne async_call_return
    mov rdx,0x3130525341434c48
    cmp [r15+352],rdx
    jne async_contract
    cmp qword ptr [r15+360],128
    jne async_contract
    cmp qword ptr [r15+472],0
    jne async_contract
    mov rdx,[r12+32]
    cmp [r15+384],rdx
    jne async_contract
    mov edi,2
    lea rsi,[r15+352]
    mov edx,128
    call write_all
    test eax,eax
    jnz async_infrastructure
    mov rax,[r15+24]
async_call_return:
    mov rsp,rbp
    pop rbp
    ret
async_parent_call:
    mov rax,[r15+320]
    mov rdx,[rax+16]
    call async_call
    ret

async_map:
    mov rsi,rdi
    xor edi,edi
    mov edx,3
    mov r10d,0x21
    mov r8,-1
    xor r9d,r9d
    mov eax,9
    syscall
    cmp rax,-4095
    jae infrastructure
    ret
async_lock:
    mov rbx,[r15+320]
async_lock_again:
    xor eax,eax
    mov edx,1
    lock cmpxchg dword ptr [rbx+8],edx
    je async_locked
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
    jz async_lock_again
    cmp rax,-4
    je async_lock_again
    cmp rax,-11
    je async_lock_again
    cmp rax,-110
    jne async_infrastructure
    cmp qword ptr [r15+488],1
    je async_lock_again
    mov rdi,[rbx+32]
    test rdi,rdi
    jz async_contract
    lea rsi,[r15+296]
    mov edx,1
    xor r10d,r10d
    mov eax,61
    syscall
    cmp rax,-4
    je async_lock_again
    test rax,rax
    jz async_lock_again
    call async_record_reap
    jmp async_lock_again
async_locked:
    ret
async_unlock:
    mov rbx,[r15+320]
    xor eax,eax
    xchg dword ptr [rbx+8],eax
    cmp eax,1
    jne async_contract
    lea rdi,[rbx+8]
    mov esi,1
    mov edx,2147483647
    xor r10d,r10d
    xor r8d,r8d
    xor r9d,r9d
    mov eax,202
    syscall
    test rax,rax
    js async_infrastructure
    ret
async_notify:
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
    js async_infrastructure
    ret

/* A signal never mutates borrowed HIA frames or the policy workspace. */
async_wake_handler:
    mov dword ptr gs:[120],1
    jmp async_signal_notify
async_cancel_handler:
    mov qword ptr gs:[16],1
async_signal_notify:
    lock inc dword ptr gs:[24]
    mov rdi,qword ptr gs:[112]
    add rdi,24
    mov esi,1
    mov edx,2147483647
    xor r10d,r10d
    xor r8d,r8d
    xor r9d,r9d
    mov eax,202
    syscall
    ret
async_sigreturn:
    mov eax,15
    syscall
    ud2

async_queue_child:
    mov rbx,[r15+320]
    cmp qword ptr [rbx+32],0
    jne async_contract
    cmp qword ptr [r15+496],0
    jne async_contract
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
    jz async_child
    js async_infrastructure
    mov [rbx+32],rax
    mov edi,3
    mov rsi,[rbx+64]
    call async_parent_call
    cmp eax,128
    jne async_contract
    cmp qword ptr [r15+368],10
    jne async_contract
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
    js async_infrastructure
    mov edi,8
    xor esi,esi
    call async_parent_call
    jmp async_parent_dispatch

async_child:
    mov qword ptr [r15+488],1
    mov edi,1
    mov esi,9
    xor edx,edx
    xor r10d,r10d
    xor r8d,r8d
    mov eax,157
    syscall
    test rax,rax
    jnz async_contract
    mov eax,110
    syscall
    mov rbx,[r15+320]
    cmp rax,[rbx+40]
    jne async_contract
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
    jnz async_contract
async_admission_wait:
    cmp qword ptr [rbx+80],1
    je async_child_invoke
    lea rdi,[rbx+80]
    xor esi,esi
    xor edx,edx
    xor r10d,r10d
    xor r8d,r8d
    xor r9d,r9d
    mov eax,202
    syscall
    test rax,rax
    jz async_admission_wait
    cmp rax,-4
    je async_admission_wait
    cmp rax,-11
    je async_admission_wait
    jmp async_infrastructure
async_child_invoke:
    cmp qword ptr [r15+ACTIVE_KIND],3
    je mkdir_child
    mov rbx,[r15+320]
    mov edi,4
    mov rsi,[rbx+64]
    xor edx,edx
    call async_call
    cmp eax,128
    jne async_contract
    cmp qword ptr [r15+368],9
    je async_child_ready
    cmp qword ptr [r15+368],8
    jne async_contract
    call async_effect
    jmp async_child_invoke
async_child_ready:
    mov rbx,[r15+320]
    mov qword ptr [rbx+48],1
    call async_notify
    xor edi,edi
    mov eax,60
    syscall
    ud2

async_parent_wait:
    mov rbx,[r15+320]
    mov eax,[rbx+24]
    mov [r15+504],eax
    cmp qword ptr [rbx+16],0
    jne async_parent_cancel
    /* Only an existing HIA WAIT boundary admits an external repoll. The
     * coalescing bit cannot alter ready, ticket, accepted bytes or cancel. */
    xor eax,eax
    xchg eax,dword ptr [rbx+120]
    test eax,eax
    jnz async_parent_poll
    cmp qword ptr [rbx+48],1
    je async_parent_poll
    mov rdi,[rbx+32]
    test rdi,rdi
    jz async_contract
    lea rsi,[r15+296]
    mov edx,1
    xor r10d,r10d
    mov eax,61
    syscall
    cmp rax,-4
    je async_parent_wait
    test rax,rax
    js async_infrastructure
    jz async_parent_sleep
    call async_record_reap
    jmp async_parent_poll
async_parent_sleep:
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
    jz async_parent_wait
    cmp rax,-4
    je async_parent_wait
    cmp rax,-11
    je async_parent_wait
    cmp rax,-110
    je async_parent_wait
    jmp async_infrastructure
async_parent_poll:
    mov edi,2
    xor esi,esi
    call async_parent_call
    jmp async_parent_dispatch
async_parent_cancel:
    mov edi,6
    xor esi,esi
    call async_parent_call
    jmp async_parent_dispatch

async_parent_reap:
    call async_reap_child
    mov rbx,[r15+320]
    mov edi,7
    mov rsi,[rbx+64]
    call async_parent_call
    mov qword ptr [r15+496],0
    jmp async_parent_dispatch
async_reap_child:
    mov rbx,[r15+320]
    cmp qword ptr [rbx+32],0
    jne async_reap_again
    cmp qword ptr [r15+496],1
    jne async_contract
    ret
async_reap_again:
    mov rdi,[rbx+32]
    lea rsi,[r15+296]
    xor edx,edx
    xor r10d,r10d
    mov eax,61
    syscall
    cmp rax,-4
    je async_reap_again
    call async_record_reap
    ret
async_record_reap:
    mov rbx,[r15+320]
    cmp rax,[rbx+32]
    jne async_infrastructure
    mov qword ptr [rbx+32],0
    cmp dword ptr [r15+296],0
    jne async_contract
    cmp qword ptr [rbx+48],1
    jne async_contract
    mov qword ptr [r15+496],1
    ret

async_parent_close:
    call async_effect
    mov rbx,[r15+320]
    mov edi,5
    mov rsi,[rbx+64]
    call async_parent_call
    jmp async_parent_dispatch

async_normal_result:
    mov rbx,[r15+320]
    cmp qword ptr [rbx+32],0
    jne async_contract
    cmp qword ptr [rbx],-1
    jne async_contract
    mov rax,0x3130524552434c48
    cmp [r15+352],rax
    jne async_contract
    cmp qword ptr [r15+360],48
    jne async_contract
    cmp qword ptr [r15+368],3
    ja async_contract
    cmp qword ptr [r15+392],0
    jne async_contract
    jmp nested_write_result

async_cancel_result:
    mov rbx,[r15+320]
    cmp qword ptr [rbx+96],0
    jne async_drain
    call nested_publish_cancel
    mov rbx,[r15+320]
    mov qword ptr [rbx+96],1
async_drain:
    cmp qword ptr [rbx+32],0
    je async_drain_reaped
    call async_reap_child
async_drain_reaped:
    cmp qword ptr [r15+496],0
    je async_drained
    mov rbx,[r15+320]
    mov edi,7
    mov rsi,[rbx+64]
    call async_parent_call
    mov qword ptr [r15+496],0
    cmp eax,128
    jne async_contract
    cmp qword ptr [r15+368],6
    jne async_contract
async_drained:
    mov rbx,[r15+320]
    cmp qword ptr [rbx],-1
    jne async_contract
    cmp qword ptr [rbx+32],0
    jne async_contract
    cmp qword ptr [r15+ACTIVE_KIND],3
    je nested_canceled
    mov rax,[r15+304]
    cmp qword ptr [r14+rax+144],1
    jne async_contract
    jmp nested_canceled

/* One independent span/custody check immediately precedes each real syscall.
 * The ticket's old end is immutable even if HIA prepares the next chunk.
 */
async_effect:
    push rbp
    sub rsp,64
    call async_lock
    mov rbp,[r15+304]
    mov rax,0x3130464552434c48
    cmp [r14+128],rax
    jne async_contract
    mov rax,[rbx+56]
    inc rax
    cmp [r14+136],rax
    je async_effect_sequence
    /* Drop can replace one already prepared, never queued WRITE with CLOSE.
     * These are HIA issue sequence numbers, not executed syscall counts.
     * Keep the exact single-step rule everywhere else, including normal close.
     */
    cmp qword ptr [r14+144],3
    jne async_contract
    cmp qword ptr [r14+rbp+16],4
    jne async_contract
    mov rcx,[r14+rbp+136]
    cmp rcx,2
    jb async_contract
    cmp rcx,3
    ja async_contract
    inc rax
    cmp [r14+136],rax
    jne async_contract
async_effect_sequence:
    cmp [r14+16],rax
    jne async_contract
    mov [rbx+56],rax
    cmp qword ptr [r14+184],0
    jne async_contract
    cmp qword ptr [r14+192],0
    jne async_contract
    cmp qword ptr [r14+200],0
    jne async_contract
    cmp qword ptr [r14+208],0
    jne async_contract
    cmp qword ptr [r14+216],0
    jne async_contract
    mov rax,[rbx+64]
    cmp [r14+rbp+48],rax
    jne async_contract
    mov rax,[r12+32]
    cmp [r14+rbp+8],rax
    jne async_contract
    mov rax,[r14+144]
    cmp [r14+8],rax
    jne async_contract
    mov [rsp],rax
    cmp rax,1
    je async_open_effect
    cmp rax,2
    je async_write_effect
    cmp rax,3
    je async_close_effect
    jmp async_contract
async_open_effect:
    cmp qword ptr [r15+488],1
    jne async_contract
    cmp qword ptr [r14+rbp+80],3
    jne async_contract
    cmp qword ptr [r14+rbp+56],1
    jne async_contract
    cmp qword ptr [rbx],-1
    jne async_contract
    cmp qword ptr [r14+152],512
    jne async_contract
    mov rax,[r12+16]
    cmp [r14+160],rax
    jne async_contract
    cmp byte ptr [r14+rax+512],0
    jne async_contract
    cmp qword ptr [r14+168],0x800c1
    jne async_contract
    cmp qword ptr [r14+176],438
    jne async_contract
    mov qword ptr [rsp+8],-100
    lea rax,[r14+512]
    mov [rsp+16],rax
    mov qword ptr [rsp+24],0x800c1
    mov qword ptr [rsp+32],438
    jmp async_effect_dispatch
async_write_effect:
    cmp qword ptr [r15+488],1
    jne async_contract
    cmp qword ptr [r14+rbp+80],3
    jne async_contract
    cmp qword ptr [r14+rbp+56],2
    jne async_contract
    cmp qword ptr [r14+152],1
    jne async_contract
    cmp qword ptr [r14+48],1
    jne async_contract
    cmp qword ptr [r14+176],0
    jne async_contract
    mov rax,[r14+56]
    cmp rax,[r14+rbp+64]
    jb async_contract
    cmp rax,[r14+rbp+72]
    jae async_contract
    mov rcx,[r14+rbp+72]
    cmp [r14+64],rcx
    jne async_contract
    sub rcx,rax
    mov rdx,[r14+168]
    cmp rdx,rcx
    jne async_contract
    test rdx,rdx
    jz async_contract
    cmp rdx,2097152
    ja async_contract
    add rax,[r12+16]
    jc async_contract
    add rax,513
    jc async_contract
    cmp [r14+160],rax
    jne async_contract
    mov rcx,[r15+16]
    cmp rax,rcx
    ja async_contract
    sub rcx,rax
    cmp rdx,rcx
    ja async_contract
    add rax,r14
    mov [rsp+16],rax
    mov [rsp+24],rdx
    mov rax,[rbx]
    test rax,rax
    js async_contract
    mov [rsp+8],rax
    jmp async_effect_dispatch
async_close_effect:
    cmp qword ptr [r14+152],1
    jne async_contract
    cmp qword ptr [r14+88],1
    jne async_contract
    cmp qword ptr [r14+48],0
    jne async_contract
    cmp qword ptr [r14+160],0
    jne async_contract
    cmp qword ptr [r14+168],0
    jne async_contract
    cmp qword ptr [r14+176],0
    jne async_contract
    mov rax,[r14+rbp+136]
    cmp qword ptr [r15+488],1
    je async_worker_close_check
    cmp qword ptr [r14+rbp+80],4
    jne async_contract
    cmp rax,1
    je async_close_admitted
    cmp rax,2
    jne async_contract
    jmp async_close_admitted
async_worker_close_check:
    cmp qword ptr [r14+rbp+80],3
    jne async_contract
    cmp rax,3
    jne async_contract
async_close_admitted:
    mov rax,[rbx]
    test rax,rax
    js async_contract
    mov [rsp+8],rax
    mov qword ptr [rbx],-1
async_effect_dispatch:
    call async_unlock
    mov rdi,[rsp+8]
    mov rsi,[rsp+16]
    mov rdx,[rsp+24]
    mov r10,[rsp+32]
    mov rax,[rsp]
    cmp eax,1
    je async_open_dispatch
    cmp eax,2
    je async_write_dispatch
    mov eax,3
    jmp async_kernel_call
async_open_dispatch:
    mov eax,257
    jmp async_kernel_call
async_write_dispatch:
    mov eax,1
async_kernel_call:
    syscall
    mov [rsp+40],rax
    mov qword ptr [rsp+48],0
    mov qword ptr [rsp+56],0
    test rax,rax
    jns async_effect_success
    cmp rax,-4095
    jl async_contract
    neg rax
    mov [rsp+48],rax
    jmp async_effect_complete
async_effect_success:
    cmp qword ptr [rsp],1
    je async_open_success
    cmp qword ptr [rsp],2
    je async_write_success
    test rax,rax
    jnz async_contract
    jmp async_effect_complete
async_open_success:
    cmp rax,0x7fffffff
    ja async_contract
    mov qword ptr [rsp+56],1
    jmp async_effect_complete
async_write_success:
    cmp rax,[rsp+24]
    ja async_contract
async_effect_complete:
    call async_lock
    cmp qword ptr [r14+184],0
    jne async_contract
    cmp qword ptr [rsp+56],0
    je async_effect_fields
    cmp qword ptr [rbx],-1
    jne async_contract
    mov rax,[rsp+40]
    mov [rbx],rax
async_effect_fields:
    mov rax,[rsp+40]
    mov [r14+192],rax
    mov rax,[rsp+48]
    mov [r14+200],rax
    mov rax,[rsp+56]
    mov [r14+208],rax
    mov qword ptr [r14+184],1
    call async_unlock
    mov edi,2
    lea rsi,[r14+128]
    mov edx,96
    call write_all
    test eax,eax
    jnz async_infrastructure
    add rsp,64
    pop rbp
    ret

async_contract:
    mov ebx,70
    jmp async_abort
async_infrastructure:
    mov ebx,74
async_abort:
    cmp qword ptr [r15+488],1
    je async_abort_exit
    mov [r15+288],rbx
    mov rbx,[r15+320]
    cmp qword ptr [rbx+32],0
    je async_abort_close
    mov rdi,[rbx+32]
    mov esi,9
    mov eax,62
    syscall
async_abort_wait:
    mov rdi,[rbx+32]
    lea rsi,[r15+296]
    xor edx,edx
    xor r10d,r10d
    mov eax,61
    syscall
    cmp rax,-4
    je async_abort_wait
    mov qword ptr [rbx+32],0
async_abort_close:
    cmp qword ptr [rbx],-1
    je async_abort_closed
    mov rdi,[rbx]
    mov qword ptr [rbx],-1
    mov eax,3
    syscall
async_abort_closed:
    mov rbx,[r15+288]
async_abort_exit:
    mov edi,ebx
    mov eax,60
    syscall
    ud2

local_read_run:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp, 520
    mov r15, rdi
    cmp qword ptr [r15 + 72], 0
    jne lr_contract_fail
    mov rdi, qword ptr [r15 + 48]
    add rdi, 1024
    jc lr_memory_fail
    cmp rdi, qword ptr [r15 + 24]
    jbe lr_read_workspace_ready
    mov ebp, 16
    call lr_resize_buffer
lr_read_workspace_ready:
    mov rdi, qword ptr [r15 + 16]
    xor eax, eax
    mov ecx, 128
    rep stosq
    mov qword ptr [r15 + 88], 0
lr_read_invoke:
    mov rdi, qword ptr [r15]
    mov rsi, qword ptr [r15 + 48]
    mov rdx, qword ptr [r15 + 32]
    mov rcx, qword ptr [r15 + 40]
    mov r8, qword ptr [r15 + 16]
    mov r9, qword ptr [r15 + 24]
    call qword ptr [r15 + 80]
    mov edx, eax
    cmp rax, rdx
    jne lr_contract_fail
    mov rbx, qword ptr [r15 + 16]
    cmp eax, 0xffffffef
    je lr_read_grow
    cmp eax, 0xffffffe8
    je lr_read_cache
    cmp eax, 0xfffffff0
    je lr_read_effect
    cmp eax, 0xfffffff6
    je lr_allocation_abort
    cmp eax, 0xffffffff
    je lr_read_refused
    cmp eax, 0xfffffffe
    je lr_read_refused
    cmp eax, 0xfffffff9
    je lr_contract_fail
    cmp rax, qword ptr [r15 + 40]
    ja lr_contract_fail
    cmp eax, 32
    jb lr_contract_fail
    cmp qword ptr [rbx], 100
    jne lr_contract_fail
    cmp qword ptr [r15 + 72], 0
    jne lr_contract_fail
    mov rdx, qword ptr [r15 + 32]
    mov rcx, 0x3130304f524c4648
    cmp qword ptr [rdx], rcx
    jne lr_contract_fail
    lea rcx, [rax - 32]
    cmp qword ptr [rdx + 24], rcx
    jne lr_contract_fail
    jmp lr_read_return
lr_read_refused:
    mov dword ptr [rsp + 504], eax
    call lr_cleanup
    mov eax, dword ptr [rsp + 504]
lr_read_return:
    add rsp, 520
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

lr_read_grow:
    cmp qword ptr [rbx], 90
    jne lr_contract_fail
    mov rdi, qword ptr [rbx + 200]
    mov rax, qword ptr [rbx + 216]
    cmp rax, 1
    je lr_read_grow_work
    cmp rax, 2
    jne lr_contract_fail
    cmp qword ptr [rbx + 208], 100
    jne lr_contract_fail
    cmp qword ptr [r15 + 72], 0
    jne lr_contract_fail
    cmp rdi, 1073741824
    ja lr_read_resource
    mov ebp, 32
    jmp lr_read_grow_do
lr_read_grow_work:
    cmp rdi, 1207959552
    ja lr_read_resource
    mov rax, qword ptr [rbx + 208]
    cmp rax, 20
    je lr_read_grow_work_valid
    cmp rax, 23
    je lr_read_grow_work_valid
    cmp rax, 24
    jne lr_contract_fail
lr_read_grow_work_valid:
    mov rax, qword ptr [rbx + 56]
    add rax, qword ptr [rbx + 152]
    jc lr_contract_fail
    cmp rdi, rax
    jne lr_contract_fail
    mov ebp, 16
lr_read_grow_do:
    cmp rdi, qword ptr [r15 + rbp + 8]
    jbe lr_contract_fail
    call lr_resize_buffer
    jmp lr_read_invoke
lr_read_resource:
    mov eax, 0xfffffffe
    jmp lr_read_refused

lr_read_cache:
    lea r12, [rbx + 640]
    mov rax, 0x3130304341544d48
    cmp qword ptr [r12], rax
    jne lr_contract_fail
    call lr_sequence_admit
    mov r13, qword ptr [r12 + 16]
    cmp r13, 1
    ja lr_contract_fail
    mov rax, qword ptr [r12 + 32]
    or rax, qword ptr [r12 + 40]
    jnz lr_contract_fail
    mov rax, qword ptr [rbx]
    cmp rax, 60
    jb lr_contract_fail
    cmp rax, 63
    ja lr_contract_fail
    cmp rax, 62
    jb lr_read_cache_load
    cmp r13, 1
    jne lr_contract_fail
    mov rax, qword ptr [r12 + 24]
    cmp rax, qword ptr [rbx + 104]
    jne lr_contract_fail
    cmp rax, 1
    jb lr_contract_fail
    cmp rax, 2
    ja lr_contract_fail
    mov rdx, qword ptr [r15 + 64]
    mov byte ptr [rdx], al
    xor eax, eax
    jmp lr_read_cache_complete
lr_read_cache_load:
    test r13, r13
    jnz lr_contract_fail
    cmp qword ptr [r12 + 24], 0
    jne lr_contract_fail
    mov rdx, qword ptr [r15 + 64]
    movzx eax, byte ptr [rdx]
    cmp eax, 2
    ja lr_contract_fail
lr_read_cache_complete:
    mov qword ptr [r12 + 56], rax
    mov qword ptr [r12 + 80], 1
    jmp lr_read_invoke

lr_read_effect:
    lea r12, [rbx + 256]
    mov rax, 0x58464f49524c4648
    cmp qword ptr [r12], rax
    jne lr_contract_fail
    call lr_sequence_admit
    mov r14, qword ptr [r12 + 16]
    mov rax, qword ptr [rbx]
    cmp r14, 8
    jne lr_read_effect_phase
    cmp rax, 21
    je lr_read_effect_ready
    cmp rax, 22
    jne lr_contract_fail
    jmp lr_read_effect_ready
lr_read_effect_phase:
    cmp rax, r14
    jne lr_contract_fail
lr_read_effect_ready:
    mov rdi, rsp
    xor eax, eax
    mov ecx, 32
    rep stosq
    cmp r14, 1
    je lr_read_path_statx
    cmp r14, 2
    je lr_read_probe_statx
    cmp r14, 3
    je lr_read_path_stat
    cmp r14, 4
    je lr_read_open
    cmp r14, 5
    je lr_read_fd_statx
    cmp r14, 7
    je lr_read_fd_stat
    cmp r14, 8
    je lr_read_bytes
    cmp r14, 9
    je lr_read_close
    cmp r14, 10
    je lr_read_path_stat
    cmp r14, 11
    je lr_read_fd_statat
    cmp r14, 12
    je lr_read_probe_stat
    jmp lr_contract_fail
lr_read_path_statx:
    call lr_path_admit
    mov rsi, rax
    mov rdi, -100
    xor edx, edx
    mov r10d, 4095
    mov r8, rsp
    mov eax, 332
    syscall
    mov ebp, 1
    jmp lr_effect_done
lr_read_path_stat:
    call lr_path_admit
    mov rsi, rax
    mov rdi, -100
    mov rdx, rsp
    xor r10d, r10d
    mov eax, 262
    syscall
    mov ebp, 2
    jmp lr_effect_done
lr_read_probe_statx:
    call lr_zero_arguments
    xor edi, edi
    xor esi, esi
    xor edx, edx
    mov r10d, 4095
    xor r8d, r8d
    mov eax, 332
    syscall
    xor ebp, ebp
    jmp lr_effect_done
lr_read_probe_stat:
    call lr_zero_arguments
    xor edi, edi
    xor esi, esi
    xor edx, edx
    xor r10d, r10d
    mov eax, 262
    syscall
    xor ebp, ebp
    jmp lr_effect_done
lr_read_open:
    cmp qword ptr [r15 + 72], 0
    jne lr_contract_fail
    call lr_path_admit
    mov rsi, rax
    mov rdi, -100
    mov edx, 524288
    xor r10d, r10d
    mov eax, 257
    syscall
    mov ebp, 3
    jmp lr_effect_done
lr_read_fd_statx:
    call lr_fd_only
    lea rsi, [rip + lr_empty_path]
    mov edx, 4096
    mov r10d, 4095
    mov r8, rsp
    mov eax, 332
    syscall
    mov ebp, 1
    jmp lr_effect_done
lr_read_fd_statat:
    call lr_fd_only
    lea rsi, [rip + lr_empty_path]
    mov rdx, rsp
    mov r10d, 4096
    mov eax, 262
    syscall
    mov ebp, 2
    jmp lr_effect_done
lr_read_fd_stat:
    call lr_fd_only
    mov rsi, rsp
    mov eax, 5
    syscall
    mov ebp, 2
    jmp lr_effect_done
lr_read_bytes:
    cmp qword ptr [r12 + 24], 1
    jne lr_contract_fail
    mov rdi, qword ptr [r15 + 72]
    test rdi, rdi
    jz lr_contract_fail
    dec rdi
    mov rsi, qword ptr [r12 + 32]
    mov rdx, qword ptr [r12 + 40]
    cmp qword ptr [rbx], 21
    jne lr_read_regular
    cmp rsi, 768
    jne lr_contract_fail
    cmp rdx, 32
    jne lr_contract_fail
    jmp lr_read_span_ready
lr_read_regular:
    mov rax, qword ptr [rbx + 56]
    cmp rax, 1024
    jb lr_contract_fail
    add rax, qword ptr [rbx + 160]
    jc lr_contract_fail
    cmp rsi, rax
    jne lr_contract_fail
    mov rax, qword ptr [rbx + 152]
    sub rax, qword ptr [rbx + 160]
    jc lr_contract_fail
    cmp rax, qword ptr [rbx + 176]
    cmova rax, qword ptr [rbx + 176]
    cmp rdx, rax
    jne lr_contract_fail
    test rdx, rdx
    jz lr_contract_fail
lr_read_span_ready:
    cmp rsi, qword ptr [r15 + 24]
    ja lr_contract_fail
    mov rax, qword ptr [r15 + 24]
    sub rax, rsi
    cmp rdx, rax
    ja lr_contract_fail
    add rsi, rbx
    xor eax, eax
    syscall
    mov ebp, 4
    jmp lr_effect_done
lr_read_close:
    call lr_fd_only
    mov qword ptr [r15 + 72], 0
    mov eax, 3
    syscall
    xor ebp, ebp
lr_effect_done:
    cmp rax, -4095
    jae lr_effect_error
    cmp ebp, 1
    jne lr_effect_stat64
    test rax, rax
    jnz lr_contract_fail
    mov rax, qword ptr [rsp + 40]
    mov qword ptr [r12 + 72], rax
    jmp lr_effect_completed
lr_effect_stat64:
    cmp ebp, 2
    jne lr_effect_opened
    test rax, rax
    jnz lr_contract_fail
    mov rax, qword ptr [rsp + 48]
    mov qword ptr [r12 + 72], rax
    jmp lr_effect_completed
lr_effect_opened:
    cmp ebp, 3
    jne lr_effect_read
    inc rax
    jz lr_contract_fail
    mov qword ptr [r15 + 72], rax
    mov qword ptr [r12 + 72], 1
    jmp lr_effect_completed
lr_effect_read:
    cmp ebp, 4
    jne lr_effect_unit
    cmp rax, qword ptr [r12 + 40]
    ja lr_contract_fail
    mov qword ptr [r12 + 56], rax
    jmp lr_effect_completed
lr_effect_unit:
    test rax, rax
    jnz lr_contract_fail
    jmp lr_effect_completed
lr_effect_error:
    neg rax
    mov qword ptr [r12 + 64], rax
lr_effect_completed:
    mov qword ptr [r12 + 80], 1
    jmp lr_read_invoke

lr_sequence_admit:
    mov rax, qword ptr [r15 + 88]
    inc rax
    jz lr_contract_fail
    cmp qword ptr [r12 + 8], rax
    jne lr_contract_fail
    cmp qword ptr [rbx + 72], rax
    jne lr_contract_fail
    mov qword ptr [r15 + 88], rax
    mov rax, qword ptr [r12 + 48]
    or rax, qword ptr [r12 + 56]
    or rax, qword ptr [r12 + 64]
    or rax, qword ptr [r12 + 72]
    or rax, qword ptr [r12 + 80]
    or rax, qword ptr [r12 + 88]
    jnz lr_contract_fail
    ret
lr_path_admit:
    cmp qword ptr [r12 + 24], 1024
    jne lr_contract_fail
    mov rcx, qword ptr [rbx + 48]
    cmp qword ptr [r12 + 32], rcx
    jne lr_contract_fail
    cmp qword ptr [r12 + 40], 0
    jne lr_contract_fail
    mov rax, qword ptr [r15 + 24]
    sub rax, 1024
    jc lr_contract_fail
    cmp rcx, rax
    jae lr_contract_fail
    lea rax, [rbx + 1024]
    cmp byte ptr [rax + rcx], 0
    jne lr_contract_fail
    xor edx, edx
lr_path_scan:
    cmp rdx, rcx
    je lr_path_done
    cmp byte ptr [rax + rdx], 0
    je lr_contract_fail
    inc rdx
    jmp lr_path_scan
lr_path_done:
    ret
lr_zero_arguments:
    mov rax, qword ptr [r12 + 24]
    or rax, qword ptr [r12 + 32]
    or rax, qword ptr [r12 + 40]
    jnz lr_contract_fail
    ret
lr_fd_only:
    cmp qword ptr [r12 + 24], 1
    jne lr_contract_fail
    mov rax, qword ptr [r12 + 32]
    or rax, qword ptr [r12 + 40]
    jnz lr_contract_fail
    mov rdi, qword ptr [r15 + 72]
    test rdi, rdi
    jz lr_contract_fail
    dec rdi
    ret

# rbp is the fixed context offset of (pointer, capacity), never input data.
lr_resize_buffer:
    # Full profile regions are mapped before fork. A request beyond them
    # returns CAPACITY in HIA; no child can publish a child-private relocation.
    jmp lr_contract_fail

lr_cleanup:
    mov rdi, qword ptr [r15 + 72]
    mov qword ptr [r15 + 72], 0
    test rdi, rdi
    jz lr_cleanup_done
    dec rdi
    mov eax, 3
    syscall
lr_cleanup_done:
    ret
lr_contract_fail:
    call lr_cleanup
    mov edi, 70
    jmp lr_child_exit
lr_memory_fail:
    call lr_cleanup
    mov edi, 71
    jmp lr_child_exit
lr_io_fail:
    call lr_cleanup
    mov edi, 74
    jmp lr_child_exit
lr_allocation_abort:
    call lr_cleanup
    mov edi, 134
lr_child_exit:
    mov eax, 60
    syscall
    ud2
lr_empty_path:
    .byte 0

key_run:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp, 520
    mov r15, rdi
    cmp qword ptr [r15 + 72], -1
    jne key_contract_fail
    cmp qword ptr [r15 + 80], -1
    jne key_contract_fail
    mov rdi, qword ptr [r15 + 16]
    xor eax, eax
    mov ecx, 128
    rep stosq
    mov rbx, qword ptr [r15 + 16]
    mov rax, qword ptr [r15 + 64]
    mov qword ptr [rbx + 176], rax
    mov qword ptr [r15 + 88], 0
key_invoke:
    mov rdi, qword ptr [r15]
    mov rsi, qword ptr [r15 + 48]
    mov rdx, qword ptr [r15 + 32]
    mov rcx, qword ptr [r15 + 40]
    mov r8, qword ptr [r15 + 16]
    mov r9, qword ptr [r15 + 24]
    call qword ptr [r15 + 96]
    mov edx, eax
    cmp rax, rdx
    jne key_contract_fail
    mov rbx, qword ptr [r15 + 16]
    cmp eax, 0xffffffef
    je key_grow_workspace
    cmp eax, 0xffffffee
    je key_grow_output
    cmp eax, 0xfffffff0
    je key_admit_effect
    cmp eax, 0xffffffff
    je key_refusal
    cmp eax, 0xfffffffe
    je key_refusal
    cmp eax, 0xfffffff9
    je key_contract_fail
    cmp eax, 32
    jb key_contract_fail
    cmp rax, qword ptr [r15 + 40]
    ja key_contract_fail
    cmp qword ptr [rbx], 100
    jne key_contract_fail
    mov rdx, qword ptr [r15 + 32]
    mov rcx, 0x313030594b4c5248
    cmp qword ptr [rdx], rcx
    jne key_contract_fail
    lea rcx, [rax - 32]
    cmp qword ptr [rdx + 16], rcx
    jne key_contract_fail
    cmp qword ptr [rdx + 24], 0
    jne key_contract_fail
    cmp qword ptr [r15 + 72], -1
    jne key_contract_fail
    cmp qword ptr [r15 + 80], -1
    jne key_contract_fail
    mov dword ptr [r15 + 56], eax
    jmp key_done
key_refusal:
    mov dword ptr [r15 + 56], eax
    call key_cleanup
    jmp key_done

key_grow_workspace:
    mov rdi, qword ptr [rbx + 40]
    cmp rdi, qword ptr [rbx + 32]
    jbe key_contract_fail
    mov rax, 0x1ffffffffffbfeff
    cmp rdi, rax
    ja key_memory_fail
    shl rdi, 2
    add rdi, 1049600
    jc key_memory_fail
    call round_capacity
    mov r12, rax
    cmp r12, qword ptr [r15 + 24]
    jbe key_invoke
    mov rdi, r12
    call allocate_guarded
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
    jnz key_io_fail
    jmp key_invoke
key_grow_output:
    mov rdi, qword ptr [rbx + 48]
    cmp rdi, qword ptr [r15 + 40]
    jbe key_contract_fail
    mov rax, 0xffffffef
    cmp rdi, rax
    ja key_contract_fail
    call round_capacity
    mov r12, rax
    mov rdi, r12
    call allocate_guarded
    mov r13, rax
    mov rdi, qword ptr [r15 + 32]
    mov rsi, qword ptr [r15 + 40]
    add rsi, 4096
    mov qword ptr [r15 + 32], r13
    mov qword ptr [r15 + 40], r12
    mov eax, 11
    syscall
    test rax, rax
    jnz key_io_fail
    jmp key_invoke

key_admit_effect:
    mov rax, qword ptr [r15 + 48]
    cmp qword ptr [rbx + 8], rax
    jne key_contract_fail
    mov rax, qword ptr [r15 + 40]
    cmp qword ptr [rbx + 16], rax
    jne key_contract_fail
    mov rax, qword ptr [r15 + 24]
    cmp qword ptr [rbx + 24], rax
    jne key_contract_fail
    mov rax, qword ptr [rbx + 40]
    or rax, qword ptr [rbx + 48]
    jnz key_contract_fail
    mov rax, qword ptr [rbx + 32]
    cmp rax, 1024
    jb key_contract_fail
    lea rcx, [rax - 1]
    test rcx, rax
    jnz key_contract_fail
    cmp qword ptr [rbx + 96], rax
    jae key_contract_fail
    mov rcx, 0x1ffffffffffbfeff
    cmp rax, rcx
    ja key_contract_fail
    shl rax, 2
    add rax, 1049600
    jc key_contract_fail
    cmp rax, qword ptr [r15 + 24]
    ja key_contract_fail
    mov rax, 0x584659454b4c4648
    cmp qword ptr [rbx + 512], rax
    jne key_contract_fail
    inc qword ptr [r15 + 88]
    jz key_contract_fail
    mov rax, qword ptr [r15 + 88]
    cmp qword ptr [rbx + 520], rax
    jne key_contract_fail
    cmp qword ptr [rbx + 56], rax
    jne key_contract_fail
    mov rax, qword ptr [rbx + 568]
    or rax, qword ptr [rbx + 576]
    or rax, qword ptr [rbx + 584]
    or rax, qword ptr [rbx + 592]
    or rax, qword ptr [rbx + 600]
    or rax, qword ptr [rbx + 608]
    or rax, qword ptr [rbx + 616]
    or rax, qword ptr [rbx + 624]
    or rax, qword ptr [rbx + 632]
    jnz key_contract_fail
    mov r14, qword ptr [rbx + 528]
    cmp r14, 1
    je key_get_current
    cmp r14, 2
    je key_read_link
    cmp r14, 3
    je key_access_path
    cmp r14, 4
    je key_access_path
    cmp r14, 5
    je key_lstat_path
    cmp r14, 6
    je key_access_path
    cmp r14, 7
    je key_open_parent
    cmp r14, 8
    je key_stat_descriptor
    cmp r14, 9
    je key_close_descriptor
    cmp r14, 10
    je key_get_flags
    cmp r14, 11
    je key_set_cloexec
    cmp r14, 12
    je key_directory_entries
    cmp r14, 13
    je key_rewind_directory
    jmp key_contract_fail

key_get_current:
    cmp qword ptr [rbx], 10
    jne key_contract_fail
    call key_resolved_argument
    mov rdx, qword ptr [rbx + 552]
    or rdx, qword ptr [rbx + 560]
    jnz key_contract_fail
    mov rsi, qword ptr [rbx + 544]
    cmp rsi, qword ptr [rbx + 152]
    jne key_contract_fail
    cmp rsi, 1024
    jb key_contract_fail
    cmp rsi, qword ptr [rbx + 32]
    ja key_contract_fail
    mov eax, 79
    syscall
    jmp key_value_completion

key_read_link:
    cmp qword ptr [rbx], 3
    jne key_contract_fail
    call key_resolved_argument
    mov rcx, qword ptr [rbx + 544]
    cmp rcx, qword ptr [rbx + 96]
    jne key_contract_fail
    call key_cstring
    mov rax, qword ptr [rbx + 32]
    lea rax, [rax + rax + 1024]
    cmp qword ptr [rbx + 552], rax
    jne key_contract_fail
    lea rsi, [rbx + rax]
    mov rdx, qword ptr [rbx + 144]
    cmp rdx, 1024
    jb key_contract_fail
    dec rdx
    cmp rdx, qword ptr [rbx + 560]
    jne key_contract_fail
    cmp rdx, qword ptr [rbx + 32]
    jae key_contract_fail
    mov eax, 89
    syscall
    jmp key_value_completion

key_access_path:
    cmp qword ptr [rbx], 4
    jne key_contract_fail
    call key_resolved_argument
    mov rcx, qword ptr [rbx + 96]
    inc rcx
    cmp rcx, qword ptr [rbx + 32]
    jae key_contract_fail
    cmp rcx, qword ptr [rbx + 544]
    jne key_contract_fail
    call key_cstring
    mov rax, qword ptr [rbx + 552]
    or rax, qword ptr [rbx + 560]
    jnz key_contract_fail
    mov rsi, rdi
    mov edi, -100
    xor edx, edx
    mov r10d, 512
    mov eax, 439
    cmp r14, 3
    je key_access_go
    cmp r14, 4
    jne key_stat_access
    cmp qword ptr [r15 + 64], 0
    jne key_contract_fail
    mov eax, 269
key_access_go:
    syscall
    jmp key_zero_completion
key_stat_access:
    cmp qword ptr [r15 + 64], 1
    jne key_contract_fail
    xor r10d, r10d
    jmp key_stat_at

key_lstat_path:
    mov rax, qword ptr [rbx]
    cmp rax, 12
    je key_lstat_fixed
    cmp rax, 13
    je key_lstat_fixed
    cmp rax, 24
    jne key_contract_fail
    mov rax, qword ptr [rbx + 32]
    lea rax, [rax * 4 + 1024]
    add rax, qword ptr [rbx + 368]
    jc key_contract_fail
    cmp rax, qword ptr [rbx + 536]
    jne key_contract_fail
    mov rcx, qword ptr [rbx + 376]
    cmp rcx, qword ptr [rbx + 544]
    jne key_contract_fail
    mov rdx, qword ptr [rbx + 552]
    cmp rdx, qword ptr [rbx + 160]
    jne key_contract_fail
    jmp key_lstat_arguments
key_lstat_fixed:
    mov rax, qword ptr [rbx + 32]
    lea rax, [rax + rax + 1024]
    cmp rax, qword ptr [rbx + 536]
    jne key_contract_fail
    mov ecx, 1
    cmp qword ptr [rbx + 544], 1
    jne key_contract_fail
    cmp qword ptr [rbx + 552], 0
    jne key_contract_fail
    xor edx, edx
    cmp qword ptr [rbx], 12
    jne key_lstat_root
    cmp byte ptr [rbx + rax], 46
    jne key_contract_fail
    jmp key_lstat_arguments
key_lstat_root:
    cmp byte ptr [rbx + rax], 47
    jne key_contract_fail
key_lstat_arguments:
    cmp qword ptr [rbx + 560], 0
    jne key_contract_fail
    lea rdi, [rbx + rax]
    call key_cstring
    mov rsi, rdi
    mov edi, -100
    test rdx, rdx
    jz key_lstat_cwd
    call key_descriptor
key_lstat_cwd:
    mov r10d, 256
key_stat_at:
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
    jmp key_stat_completion

key_open_parent:
    cmp qword ptr [rbx], 15
    jne key_contract_fail
    mov rax, qword ptr [rbx + 552]
    or rax, qword ptr [rbx + 560]
    jnz key_contract_fail
    mov r12, qword ptr [rbx + 536]
    cmp r12, 1
    jb key_contract_fail
    cmp r12, 2
    ja key_contract_fail
    cmp qword ptr [r15 + r12 * 8 + 64], -1
    jne key_contract_fail
    mov rdx, qword ptr [rbx + 544]
    cmp rdx, qword ptr [rbx + 160]
    jne key_contract_fail
    cmp rdx, r12
    je key_contract_fail
    mov edi, -100
    test rdx, rdx
    jz key_open_parent_cwd
    call key_descriptor
key_open_parent_cwd:
    lea rsi, [rip + key_parent_name]
    xor edx, edx
    xor r10d, r10d
    mov eax, 257
    syscall
    test rax, rax
    js key_error_completion
    cmp rax, 0x7fffffff
    ja key_contract_fail
    mov qword ptr [r15 + r12 * 8 + 64], rax
    mov rax, r12
    jmp key_value_completion

key_stat_descriptor:
    mov rax, qword ptr [rbx]
    cmp rax, 16
    je key_stat_descriptor_phase
    cmp rax, 18
    jne key_contract_fail
key_stat_descriptor_phase:
    call key_zero_trailing_args
    mov rdx, qword ptr [rbx + 536]
    cmp rdx, qword ptr [rbx + 168]
    jne key_contract_fail
    call key_descriptor
    mov r13, rdi
    mov rdi, rsp
    xor eax, eax
    mov ecx, 32
    rep stosq
    mov rdi, r13
    mov rsi, rsp
    mov eax, 5
    syscall
key_stat_completion:
    test rax, rax
    js key_error_completion
    test rax, rax
    jnz key_contract_fail
    mov rax, qword ptr [rsp]
    mov qword ptr [rbx + 584], rax
    mov rax, qword ptr [rsp + 8]
    mov qword ptr [rbx + 592], rax
    mov eax, dword ptr [rsp + 24]
    mov qword ptr [rbx + 600], rax
    mov rax, qword ptr [rsp + 56]
    mov qword ptr [rbx + 616], rax
    jmp key_acknowledge

key_close_descriptor:
    mov rax, qword ptr [rbx]
    cmp rax, 17
    je key_close_phase
    cmp rax, 27
    je key_close_phase
    cmp rax, 29
    jne key_contract_fail
key_close_phase:
    call key_zero_trailing_args
    mov rdx, qword ptr [rbx + 536]
    call key_descriptor
    mov qword ptr [r15 + rdx * 8 + 64], -1
    mov eax, 3
    syscall
    jmp key_zero_completion

key_get_flags:
    cmp qword ptr [rbx], 19
    jne key_contract_fail
    call key_zero_trailing_args
    mov rdx, qword ptr [rbx + 536]
    cmp rdx, qword ptr [rbx + 168]
    jne key_contract_fail
    call key_descriptor
    mov esi, 3
    xor edx, edx
    mov eax, 72
    syscall
    jmp key_value_completion
key_set_cloexec:
    cmp qword ptr [rbx], 20
    jne key_contract_fail
    call key_zero_trailing_args
    mov rdx, qword ptr [rbx + 536]
    cmp rdx, qword ptr [rbx + 168]
    jne key_contract_fail
    call key_descriptor
    mov esi, 2
    mov edx, 1
    mov eax, 72
    syscall
    jmp key_zero_completion

key_directory_entries:
    cmp qword ptr [rbx], 22
    jne key_contract_fail
    cmp qword ptr [rbx + 560], 0
    jne key_contract_fail
    mov rax, qword ptr [rbx + 32]
    lea rax, [rax * 4 + 1024]
    cmp rax, qword ptr [rbx + 544]
    jne key_contract_fail
    mov r12, qword ptr [rbx + 552]
    cmp r12, 32768
    jb key_contract_fail
    cmp r12, 1048576
    ja key_contract_fail
    cmp r12, qword ptr [rbx + 336]
    jne key_contract_fail
    lea rsi, [rbx + rax]
    mov rdx, qword ptr [rbx + 536]
    cmp rdx, qword ptr [rbx + 160]
    jne key_contract_fail
    call key_descriptor
    mov rdx, r12
    mov eax, 217
    syscall
    jmp key_value_completion
key_rewind_directory:
    cmp qword ptr [rbx], 23
    jne key_contract_fail
    call key_zero_trailing_args
    mov rdx, qword ptr [rbx + 536]
    cmp rdx, qword ptr [rbx + 160]
    jne key_contract_fail
    call key_descriptor
    xor esi, esi
    xor edx, edx
    mov eax, 8
    syscall
    jmp key_value_completion

key_resolved_argument:
    mov rax, qword ptr [rbx + 32]
    add rax, 1024
    cmp qword ptr [rbx + 536], rax
    jne key_contract_fail
    lea rdi, [rbx + rax]
    ret
key_zero_trailing_args:
    mov rax, qword ptr [rbx + 544]
    or rax, qword ptr [rbx + 552]
    or rax, qword ptr [rbx + 560]
    jnz key_contract_fail
    ret
# logical slot in rdx -> real key_descriptor in rdi, preserving other arguments.
key_descriptor:
    cmp rdx, 1
    jb key_contract_fail
    cmp rdx, 2
    ja key_contract_fail
    mov rdi, qword ptr [r15 + rdx * 8 + 64]
    test rdi, rdi
    js key_contract_fail
    ret
# Exact span containment and unique final NUL.  rdx is preserved for dirfd.
key_cstring:
    mov rax, rdi
    sub rax, rbx
    jc key_contract_fail
    cmp rax, qword ptr [r15 + 24]
    jae key_contract_fail
    mov r11, qword ptr [r15 + 24]
    sub r11, rax
    cmp rcx, r11
    jae key_contract_fail
    cmp byte ptr [rdi + rcx], 0
    jne key_contract_fail
    xor eax, eax
key_cstring_loop:
    cmp rax, rcx
    je key_cstring_done
    cmp byte ptr [rdi + rax], 0
    je key_contract_fail
    inc rax
    jmp key_cstring_loop
key_cstring_done:
    ret
key_value_completion:
    test rax, rax
    js key_error_completion
    mov qword ptr [rbx + 568], rax
    jmp key_acknowledge
key_zero_completion:
    test rax, rax
    js key_error_completion
    test rax, rax
    jnz key_contract_fail
    jmp key_acknowledge
key_error_completion:
    neg rax
    cmp rax, 4095
    ja key_contract_fail
    mov qword ptr [rbx + 576], rax
key_acknowledge:
    mov qword ptr [rbx + 608], 1
    jmp key_invoke

key_cleanup:
    mov rdi, qword ptr [r15 + 72]
    mov qword ptr [r15 + 72], -1
    test rdi, rdi
    js key_cleanup_second
    mov eax, 3
    syscall
key_cleanup_second:
    mov rdi, qword ptr [r15 + 80]
    mov qword ptr [r15 + 80], -1
    test rdi, rdi
    js key_cleanup_done
    mov eax, 3
    syscall
key_cleanup_done:
    ret
key_done:
    mov eax, dword ptr [r15 + 56]
    add rsp, 520
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret
key_contract_fail:
    call key_cleanup
    mov edi, 70
    jmp fatal_exit
key_memory_fail:
    call key_cleanup
    mov edi, 71
    jmp fatal_exit
key_io_fail:
    call key_cleanup
    mov edi, 74
    jmp fatal_exit
key_parent_name:
    .asciz ".."

.balign 16
image_table:
    .quad 0,0,0,0,0,0,0,0x314d495350434c48
.balign 16
images:
