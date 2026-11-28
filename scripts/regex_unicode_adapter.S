/* Fixed internal Unicode-query profile: HIA owner 10 calls only HIA data 11.
 * Length-prefixed bytes in; u64 status,u64 length,payload out. No libc or JSON.
 */
.intel_syntax noprefix
.section .text
.global _start
.global query_call_displacement
.global data_call_displacement
.equ INPUT, 4096
.equ OUTPUT, 8392704
.equ QUERY_WORK, 8458240
.equ DATA_WORK, 9506816
.equ MAP_BYTES, 9572352
.equ FOOTER, 1048320
.equ DATA_BYTES, 171683

_start:
    cld
    xor edi, edi
    mov esi, MAP_BYTES
    mov edx, 3
    mov r10d, 34
    mov r8, -1
    xor r9d, r9d
    mov eax, 9
    syscall
    cmp rax, -4095
    jae failed
    mov r15, rax

next_frame:
    lea rsi, [r15]
    mov edx, 8
    call read_exact
    cmp eax, 1
    je complete
    test eax, eax
    jnz failed
    mov rdx, [r15]
    cmp rdx, 8388608
    ja failed
    test rdx, rdx
    jz query_resume
    lea rsi, [r15 + INPUT]
    call read_exact
    test eax, eax
    jnz failed

query_resume:
    lea rdi, [r15 + INPUT]
    mov rsi, [r15]
    lea rdx, [r15 + OUTPUT]
    mov ecx, 65536
    lea r8, [r15 + QUERY_WORK]
    mov r9d, 1048576
    .byte 0xe8
query_call_displacement:
    .long 0
    mov eax, eax
    cmp eax, 0xffffffe0
    je child_call
    xor edx, edx
    cmp eax, 0xffff0000
    jae domain_result
    cmp eax, 65536
    ja failed
    mov rdx, rax
    xor eax, eax
domain_result:
    mov [r15 + 8], rax
    mov [r15 + 16], rdx
    lea rsi, [r15 + 8]
    mov edx, 16
    call write_exact
    mov rdx, [r15 + 16]
    lea rsi, [r15 + OUTPUT]
    call write_exact
    jmp next_frame

child_call:
    cmp qword ptr [r15 + 24], 0
    jne failed
    lea r14, [r15 + QUERY_WORK + FOOTER]
    mov rax, 0x31304c4143414948
    cmp [r14], rax
    jne failed
    cmp qword ptr [r14 + 8], 1
    jne failed
    cmp qword ptr [r14 + 16], 11
    jne failed
    cmp qword ptr [r14 + 24], 2
    jne failed
    cmp qword ptr [r14 + 32], 256
    jne failed
    cmp qword ptr [r14 + 40], 8
    jne failed
    cmp qword ptr [r14 + 48], 2
    jne failed
    cmp qword ptr [r14 + 56], 8192
    jne failed
    cmp qword ptr [r14 + 64], DATA_BYTES
    jne failed
    xor ecx, ecx
child_zero_fields:
    cmp qword ptr [r14 + rcx*8 + 72], 0
    jne failed
    inc ecx
    cmp ecx, 6
    jb child_zero_fields
    lea rdi, [r15 + QUERY_WORK + 256]
    mov esi, 8
    lea rdx, [r15 + QUERY_WORK + 8192]
    mov ecx, DATA_BYTES
    lea r8, [r15 + DATA_WORK]
    mov r9d, 65536
    .byte 0xe8
data_call_displacement:
    .long 0
    cmp eax, DATA_BYTES
    jne failed
    mov qword ptr [r14 + 80], DATA_BYTES
    mov qword ptr [r14 + 88], 1
    mov qword ptr [r14 + 96], 1
    mov qword ptr [r14 + 104], 0
    mov qword ptr [r15 + 24], 1
    jmp query_resume

read_exact:
    xor r8d, r8d
read_loop:
    xor edi, edi
    xor eax, eax
    syscall
    cmp rax, -4
    je read_loop
    test rax, rax
    js failed
    jz read_eof
    add r8, rax
    add rsi, rax
    sub rdx, rax
    jnz read_loop
    xor eax, eax
    ret
read_eof:
    test r8, r8
    jnz failed
    mov eax, 1
    ret

write_exact:
    test rdx, rdx
    jz write_done
write_loop:
    mov edi, 1
    mov eax, 1
    syscall
    cmp rax, -4
    je write_loop
    test rax, rax
    jle failed
    add rsi, rax
    sub rdx, rax
    jnz write_loop
write_done:
    ret

complete:
    xor edi, edi
    mov eax, 60
    syscall
failed:
    mov edi, 74
    mov eax, 60
    syscall
