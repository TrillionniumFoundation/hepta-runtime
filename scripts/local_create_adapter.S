/* Private Linux x86-64 syscall bridge. HIA alone chooses file policy and retries. */
.intel_syntax noprefix
.section .text
.global _start
.type _start,@function
_start:
    cmp qword ptr [rsp],1
    jne usage
    and rsp,-16
    sub rsp,512
    mov r15,rsp
    xor eax,eax
    mov rdi,r15
    mov ecx,64
    rep stosq
    mov qword ptr [r15],-1
    /* Ignore SIGPIPE so transport failure retires any actually owned FD. */
    mov qword ptr [r15+256],1
    mov edi,13
    lea rsi,[r15+256]
    xor edx,edx
    mov r10d,8
    mov eax,13
    syscall
    test rax,rax
    js infrastructure
    xor edi,edi
    lea rsi,[r15+64]
    mov edx,8
    call read_exact
    test eax,eax
    jnz infrastructure
    mov r13,[r15+64]
    mov rdi,r13
    add rdi,4095
    jc infrastructure
    and rdi,-4096
    test rdi,rdi
    jnz input_extent
    mov edi,4096
input_extent:
    mov [r15+8],rdi
    call map_rw
    mov r12,rax
    xor edi,edi
    mov rsi,r12
    mov rdx,r13
    call read_exact
    test eax,eax
    jnz infrastructure
    cmp r13,8
    jb legacy_request
    mov rax,0x3130515241434c48
    cmp [r12],rax
    jne legacy_request
    cmp r13,64
    jb async_header_refused
    cmp qword ptr [r12+8],1
    jne async_header_refused
    cmp qword ptr [r12+40],0
    jne async_header_refused
    cmp qword ptr [r12+48],0
    jne async_header_refused
    cmp qword ptr [r12+56],0
    jne async_header_refused
    jmp async_start
async_header_refused:
    mov eax,0xffffffff
    jmp refusal
legacy_request:
    mov rdi,r13
    add rdi,449
    jc infrastructure
    cmp rdi,512
    jae workspace_extent
    mov edi,512
workspace_extent:
    mov [r15+16],rdi
    call map_rw
    mov r14,rax
    call protect_input
invoke:
    mov rdi,r12
    mov rsi,r13
    lea rdx,[r15+80]
    mov ecx,64
    mov r8,r14
    mov r9,[r15+16]
    call local_create_entry
    mov edx,eax
    cmp rax,rdx
    jne contract
    mov [r15+24],rax
    cmp eax,0xfffffffd
    je effect
    cmp qword ptr [r15],-1
    jne contract
    cmp eax,48
    je successful
    cmp eax,0xffffffff
    je refusal
    cmp eax,0xfffffffe
    jne contract
refusal:
    mov [r15+144],rax
    mov edi,1
    lea rsi,[r15+144]
    mov edx,8
    call write_all
    test eax,eax
    jnz infrastructure
    jmp success
successful:
    mov rax,0x3130524552434c48 /* HLCRER01 */
    cmp [r15+80],rax
    jne contract
    cmp qword ptr [r15+88],48
    jne contract
    cmp qword ptr [r15+96],3
    ja contract
    cmp qword ptr [r15+120],0
    jne contract
    mov qword ptr [r15+144],48
    lea rsi,[r15+80]
    lea rdi,[r15+152]
    mov ecx,48
    rep movsb
    mov edi,1
    lea rsi,[r15+144]
    mov edx,56
    call write_all
    test eax,eax
    jnz infrastructure
    jmp success
effect:
    cmp r13,64
    jb contract
    mov rax,0x3130464552434c48 /* HLCREF01 */
    cmp [r14+128],rax
    jne contract
    mov rax,[r15+32]
    inc rax
    cmp [r14+136],rax
    jne contract
    cmp [r14+16],rax
    jne contract
    mov [r15+32],rax
    cmp qword ptr [r14+184],0
    jne contract
    cmp qword ptr [r14+192],0
    jne contract
    cmp qword ptr [r14+200],0
    jne contract
    cmp qword ptr [r14+208],0
    jne contract
    cmp qword ptr [r14+216],0
    jne contract
    mov rax,[r14+144]
    cmp [r14+8],rax
    jne contract
    cmp rax,1
    je open_effect
    cmp rax,2
    je write_effect
    cmp rax,3
    jne contract
    jmp close_effect
open_effect:
    cmp qword ptr [r15],-1
    jne contract
    cmp qword ptr [r14+152],512
    jne contract
    mov rax,[r14+160]
    cmp [r12+16],rax
    jne contract
    mov rcx,[r15+16]
    sub rcx,513
    cmp rax,rcx
    ja contract
    cmp byte ptr [r14+rax+512],0
    jne contract
    cmp qword ptr [r14+168],0x800c1
    jne contract
    cmp qword ptr [r14+176],438
    jne contract
    mov rdi,-100
    lea rsi,[r14+512]
    mov rdx,[r14+168]
    mov r10,[r14+176]
    mov eax,257
    syscall
    test rax,rax
    js completed_error
    cmp rax,0x7fffffff
    ja contract
    mov [r15],rax
    mov qword ptr [r14+208],1
    jmp completed
write_effect:
    cmp qword ptr [r15],-1
    je contract
    cmp qword ptr [r14+152],1
    jne contract
    cmp qword ptr [r14+48],1
    jne contract
    cmp qword ptr [r14+176],0
    jne contract
    mov rax,[r14+160]
    mov rcx,[r15+16]
    cmp rax,rcx
    ja contract
    sub rcx,rax
    mov rdx,[r14+168]
    cmp rdx,rcx
    ja contract
    test rdx,rdx
    jz contract
    cmp rdx,2097152
    ja contract
    lea rsi,[r14+rax]
    mov rdi,[r15]
    mov eax,1
    syscall
    test rax,rax
    js completed_error
    cmp rax,[r14+168]
    ja contract
    jmp completed
close_effect:
    cmp qword ptr [r15],-1
    je contract
    cmp qword ptr [r14+152],1
    jne contract
    cmp qword ptr [r14+88],1
    jne contract
    cmp qword ptr [r14+48],0
    jne contract
    cmp qword ptr [r14+160],0
    jne contract
    cmp qword ptr [r14+168],0
    jne contract
    cmp qword ptr [r14+176],0
    jne contract
    mov rdi,[r15]
    mov qword ptr [r15],-1
    mov eax,3
    syscall
    test rax,rax
    js completed_error
    test rax,rax
    jnz contract
    jmp completed
completed_error:
    cmp rax,-4095
    jl contract
    mov rdx,rax
    neg rdx
    mov [r14+200],rdx
completed:
    mov [r14+192],rax
    mov qword ptr [r14+184],1
    /* One full observation record per real syscall, never a fabricated effect. */
    mov edi,2
    lea rsi,[r14+128]
    mov edx,96
    call write_all
    test eax,eax
    jnz infrastructure
    cmp qword ptr [r15+40],0
    jne invoke
    mov rdi,r12
    mov rsi,[r15+8]
    mov edx,3
    mov eax,10
    syscall
    test rax,rax
    js infrastructure
    mov qword ptr [r12+8],2
    mov qword ptr [r15+40],1
    call protect_input
    jmp invoke
protect_input:
    mov rdi,r12
    mov rsi,[r15+8]
    mov edx,1
    mov eax,10
    syscall
    test rax,rax
    js infrastructure
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
    cmp rax,-4095
    jae infrastructure
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
success:
    xor edi,edi
    jmp exit
contract:
    mov ebx,70
    jmp cleanup
infrastructure:
    mov ebx,74
cleanup:
    cmp qword ptr [r15],-1
    je cleaned
    mov rdi,[r15]
    mov qword ptr [r15],-1
    mov eax,3
    syscall
cleaned:
    mov edi,ebx
    jmp exit
usage:
    mov edi,64
exit:
    mov eax,60
    syscall
    ud2
/* Same-owner asynchronous mechanism. HIA owns every policy transition.
 * The bridge owns a shared FD table, one child ticket, a call mutex,
 * immutable request storage, actual wait/reap and a supervisor cancel bit.
 */
async_start:
    mov rdi,[r15+8]
    call async_map
    mov [r15+312],rax
    mov rdi,rax
    mov rsi,r12
    mov rcx,r13
    rep movsb
    mov rdi,r12
    mov rsi,[r15+8]
    mov eax,11
    syscall
    test rax,rax
    jnz infrastructure
    mov r12,[r15+312]
    mov rdi,r13
    add rdi,456
    jc infrastructure
    and rdi,-8
    mov [r15+304],rdi
    add rdi,256
    jc infrastructure
    mov [r15+16],rdi
    call async_map
    mov r14,rax
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
    jnz async_infrastructure
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
    jnz async_infrastructure
    /* External wake is a mechanical request to repoll the existing future. */
    lea rax,[rip+async_wake_handler]
    mov [r15+256],rax
    mov edi,12
    lea rsi,[r15+256]
    xor edx,edx
    mov r10d,8
    mov eax,13
    syscall
    test rax,rax
    jnz async_infrastructure
    call protect_input
    mov edi,1
    xor esi,esi
    xor edx,edx
    call async_call
    cmp eax,128
    jne async_initial_refusal
    cmp qword ptr [r15+368],10
    jne async_contract
    mov edi,2
    xor esi,esi
    call async_parent_call
async_parent_dispatch:
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
    mov qword ptr [r15+144],48
    lea rsi,[r15+352]
    lea rdi,[r15+152]
    mov ecx,48
    rep movsb
    mov edi,1
    lea rsi,[r15+144]
    mov edx,56
    call write_all
    test eax,eax
    jnz async_infrastructure
    jmp success

async_cancel_result:
    mov rbx,[r15+320]
    cmp qword ptr [rbx+96],0
    jne async_drain
    mov qword ptr [r15+144],128
    lea rsi,[r15+352]
    lea rdi,[r15+152]
    mov ecx,128
    rep movsb
    mov edi,1
    lea rsi,[r15+144]
    mov edx,136
    call write_all
    test eax,eax
    jnz async_infrastructure
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
    mov rax,[r15+304]
    cmp qword ptr [r14+rax+144],1
    jne async_contract
    jmp success

async_initial_refusal:
    cmp eax,0xffffffff
    je async_refused
    cmp eax,0xfffffffe
    jne async_contract
async_refused:
    mov [r15+144],rax
    mov edi,1
    lea rsi,[r15+144]
    mov edx,8
    call write_all
    test eax,eax
    jnz async_infrastructure
    jmp success

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

.p2align 4,0
local_create_entry:
    .byte 0xcc
.section .note.GNU-stack,"",@progbits
