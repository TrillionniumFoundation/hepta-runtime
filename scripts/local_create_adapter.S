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
.p2align 4,0
local_create_entry:
    .byte 0xcc
.section .note.GNU-stack,"",@progbits
