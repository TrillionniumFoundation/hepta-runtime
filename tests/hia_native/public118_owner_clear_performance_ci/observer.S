.intel_syntax noprefix
.section .text
.global _start
_start:
    sub rsp, 176
    xor edi, edi
    mov rsi, rsp
    mov edx, 72
    call read_all
    mov rax, 0x3130304c4c414348
    cmp [rsp], rax
    jne fail
    mov r8, [rsp + 8]
    mov rsi, [rsp + 16]
    mov edx, 5
    mov r10d, 2
    call map_fd
    mov [rsp + 80], rax
    mov r8, [rsp + 24]
    mov rsi, [rsp + 32]
    mov edx, 1
    mov r10d, 1
    call map_fd
    mov [rsp + 88], rax
    mov r8, [rsp + 40]
    mov rsi, [rsp + 48]
    mov edx, 3
    mov r10d, 1
    call map_fd
    mov [rsp + 96], rax
    mov r8, [rsp + 56]
    mov rsi, [rsp + 64]
    mov edx, 3
    mov r10d, 1
    call map_fd
    mov [rsp + 104], rax
    mov eax, 228
    mov edi, 1
    lea rsi, [rsp + 112]
    syscall
    test rax, rax
    jnz fail
    mov rdi, [rsp + 88]
    mov rsi, [rsp + 32]
    mov rdx, [rsp + 96]
    mov rcx, [rsp + 48]
    mov r8, [rsp + 104]
    mov r9, [rsp + 64]
    call [rsp + 80]
    mov [rsp + 152], rax
    mov eax, 228
    mov edi, 1
    lea rsi, [rsp + 128]
    syscall
    test rax, rax
    jnz fail
    mov rax, 0x3130305250434848
    mov [rsp + 144], rax
    mov edi, 1
    lea rsi, [rsp + 144]
    mov edx, 16
    call write_all
    mov edi, 1
    lea rsi, [rsp + 112]
    mov edx, 32
    call write_all
    xor edi, edi
    mov eax, 60
    syscall
map_fd:
    xor edi, edi
    test rsi, rsi
    jnz map_size
    mov esi, 1
map_size:
    xor r9d, r9d
    mov eax, 9
    syscall
    cmp rax, -4095
    jae fail
    ret
read_all:
    mov r12, rsi
    mov r13, rdx
read_loop:
    xor eax, eax
    mov rsi, r12
    mov rdx, r13
    syscall
    cmp rax, -4
    je read_loop
    test rax, rax
    jle fail
    add r12, rax
    sub r13, rax
    jnz read_loop
    ret
write_all:
    mov r12, rsi
    mov r13, rdx
write_loop:
    mov eax, 1
    mov rsi, r12
    mov rdx, r13
    syscall
    cmp rax, -4
    je write_loop
    test rax, rax
    jle fail
    add r12, rax
    sub r13, rax
    jnz write_loop
    ret
fail:
    mov edi, 121
    mov eax, 60
    syscall
.section .note.GNU-stack,"",@progbits
