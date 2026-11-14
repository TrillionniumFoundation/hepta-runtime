/* Explicit 200 ms test probe; production guard retains its fixed 30 seconds.
 * The owned worker performs a real blocking read on an empty pipe. */
.intel_syntax noprefix
.text
.global _start
_start:
 sub rsp,512
 mov r12,rsp
 mov rdi,r12
 xor eax,eax
 mov ecx,64
 rep stosq
 mov edi,17
 lea rsi,[r12+64]
 xor edx,edx
 mov r10d,8
 mov eax,13
 syscall
 test rax,rax
 js failed
 xor edi,edi
 mov esi,4096
 mov edx,3
 mov r10d,0x21
 mov r8,-1
 xor r9d,r9d
 mov eax,9
 syscall
 cmp rax,-4095
 jae failed
 mov r13,rax
 mov rdi,r12
 mov esi,0x80000
 mov eax,293
 syscall
 test rax,rax
 js failed
 lea rdi,[r12+8]
 mov esi,0x80800
 mov eax,293
 syscall
 test rax,rax
 js failed
 mov eax,39
 syscall
 mov r15,rax
 mov edi,1
 lea rsi,[r12+96]
 mov eax,228
 syscall
 test rax,rax
 js failed
 mov eax,57
 syscall
 test rax,rax
 js failed
 jz worker
 mov r14,rax
 mov edi,[r12]
 mov eax,3
 syscall
 mov edi,[r12+12]
 mov eax,3
 syscall
 mov [r12+208],r14
 mov edi,1
 lea rsi,[r12+208]
 mov edx,8
 mov eax,1
 syscall
 cmp eax,8
 jne cancel_failed
 mov eax,[r12+8]
 mov [r12+128],eax
 mov WORD PTR [r12+132],1
 mov QWORD PTR [r12+144],0
 mov QWORD PTR [r12+152],200000000
 lea rdi,[r12+128]
 mov esi,1
 lea rdx,[r12+144]
 xor r10d,r10d
 mov r8d,8
 mov eax,271
 syscall
 test rax,rax
 jnz cancel_failed
 cmp QWORD PTR [r13],1
 jne cancel_failed
 mov rdi,r14
 mov esi,9
 mov eax,62
 syscall
 mov [r12+200],rax
 test rax,rax
 jnz failed
 mov ebx,100
reap:
 mov rdi,r14
 lea rsi,[r12+192]
 mov edx,1
 xor r10d,r10d
 mov eax,61
 syscall
 cmp rax,r14
 je reaped
 test rax,rax
 jnz failed
 dec ebx
 jz failed
 mov QWORD PTR [r12+160],0
 mov QWORD PTR [r12+168],1000000
 lea rdi,[r12+160]
 xor esi,esi
 mov eax,35
 syscall
 jmp reap
reaped:
 mov eax,[r12+192]
 and eax,127
 cmp eax,9
 jne failed
 mov edi,1
 lea rsi,[r12+112]
 mov eax,228
 syscall
 test rax,rax
 js failed
 mov rax,[r12+112]
 sub rax,[r12+96]
 imul rax,rax,1000000000
 add rax,[r12+120]
 sub rax,[r12+104]
 mov QWORD PTR [r12+224],110
 mov [r12+232],rax
 mov [r12+240],r14
 mov rax,[r12+200]
 mov [r12+248],rax
 mov eax,[r12+192]
 mov [r12+256],rax
 mov rax,[r13]
 mov [r12+264],rax
 mov edi,1
 lea rsi,[r12+224]
 mov edx,48
 mov eax,1
 syscall
 cmp eax,48
 jne failed
 xor edi,edi
 jmp exit
cancel_failed:
 mov rdi,r14
 mov esi,9
 mov eax,62
 syscall
 jmp failed
worker:
 mov edi,1
 mov esi,9
 xor edx,edx
 xor r10d,r10d
 xor r8d,r8d
 mov eax,157
 syscall
 test rax,rax
 js failed
 mov eax,110
 syscall
 cmp rax,r15
 jne failed
 xor edi,edi
 mov eax,3
 syscall
 mov edi,1
 mov eax,3
 syscall
 mov edi,2
 mov eax,3
 syscall
 mov edi,[r12+4]
 mov eax,3
 syscall
 mov edi,[r12+8]
 mov eax,3
 syscall
 mov QWORD PTR [r13],1
 mov edi,[r12]
 lea rsi,[r13+128]
 mov edx,1
 xor eax,eax
 syscall
 mov QWORD PTR [r13],2
 mov edi,[r12+12]
 lea rsi,[r13]
 mov edx,1
 mov eax,1
 syscall
failed:
 mov edi,1
exit:
 mov eax,60
 syscall
 ud2
