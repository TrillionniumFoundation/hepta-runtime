/* Fixed Linux x86-64 carrier for the HIA file entry guard.
 * HIA owns whole-image pin admission, child selection, sealing and execution.
 * The adapter translates bounded private spans and the six closed syscalls.
 */
.intel_syntax noprefix
.text
.global _start, entry_policy_call_hole, entry_image_size_hole
.equ WORK_BYTES,65536
_start:
    mov rbx,rsp
    cmp QWORD PTR [rbx],5
    jne usage
    sub rsp,192
    mov eax,9
    xor edi,edi
    mov esi,WORK_BYTES+4096
    mov edx,3
    mov r10d,0x22
    mov r8,-1
    xor r9d,r9d
    syscall
    cmp rax,-4095
    jae io_error
    mov r15,rax
    lea r14,[rax+WORK_BYTES]
    lea r12,[rip+_start-176]
    mov r13,QWORD PTR [rip+entry_image_size_hole]
    mov QWORD PTR [r15+8288],5
    mov rsi,[rbx+16]
    lea rdi,[r15+8448]
    mov ecx,63
    call capture_string
    mov [r15+8304],rax
    mov rsi,[rbx+24]
    lea rdi,[r15+8512]
    mov ecx,64
    call capture_string
    mov [r15+8312],rax
    mov rsi,[rbx+32]
    lea rdi,[r15+8576]
    mov ecx,63
    call capture_string
    mov [r15+8320],rax
    mov rsi,[rbx+40]
    lea rdi,[r15+16384]
    mov ecx,4095
    call capture_string
    mov [r15+8328],rax
advance:
    mov rdi,r12
    mov rsi,r13
    mov rdx,r14
    mov ecx,128
    mov r8,r15
    mov r9d,WORK_BYTES
    .byte 0xe8
entry_policy_call_hole: .long 0
    cmp eax,1
    je syscall_action
    cmp eax,2
    je relocate_action
    jmp invalid
syscall_action:
    mov rax,[r14]
    cmp rax,319
    je allowed
    cmp rax,1
    je allowed
    cmp rax,72
    je allowed
    cmp rax,322
    je allowed
    cmp rax,60
    jne invalid
allowed:
    xor ebx,ebx
    mov rbp,[r14+56]
argument:
    mov rax,[r14+8+rbx*8]
    mov rcx,rbp
    and ecx,3
    shr rbp,2
    test ecx,ecx
    jz argument_ready
    cmp ecx,1
    jne other_pointer
    cmp rax,r13
    jae invalid
    add rax,r12
    jmp argument_ready
other_pointer:
    cmp ecx,3
    jne invalid
    cmp rax,WORK_BYTES
    jae invalid
    add rax,r15
argument_ready:
    mov [rsp+rbx*8],rax
    inc ebx
    cmp ebx,6
    jb argument
    test rbp,rbp
    jne invalid
    mov rax,[r14]
    mov rdi,[rsp]
    mov rsi,[rsp+8]
    mov rdx,[rsp+16]
    mov r10,[rsp+24]
    mov r8,[rsp+32]
    mov r9,[rsp+40]
    syscall
    mov [r15+8200],rax
    jmp advance
relocate_action:
    cmp QWORD PTR [r14],24704
    jne invalid
    cmp QWORD PTR [r14+8],4
    jne invalid
    cmp QWORD PTR [r14+16],24832
    jne invalid
    xor ebx,ebx
relocate_word:
    mov rax,[r15+24704+rbx*8]
    cmp rax,-1
    je null_word
    cmp rax,WORK_BYTES
    jae invalid
    add rax,r15
    jmp store_word
null_word:
    xor eax,eax
store_word:
    mov [r15+24832+rbx*8],rax
    inc ebx
    cmp ebx,4
    jb relocate_word
    mov QWORD PTR [r15+8200],0
    jmp advance
capture_string:
    xor eax,eax
copy_character:
    mov dl,[rsi+rax]
    mov [rdi+rax],dl
    test dl,dl
    jz copied
    cmp rax,rcx
    jae usage
    inc rax
    jmp copy_character
copied:
    ret
usage:
    mov edi,64
    jmp terminate
invalid:
    mov edi,65
    jmp terminate
io_error:
    mov edi,74
terminate:
    mov eax,60
    syscall
    ud2
.balign 8
entry_image_size_hole: .quad 0
