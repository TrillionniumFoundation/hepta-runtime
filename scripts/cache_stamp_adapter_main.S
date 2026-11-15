.intel_syntax noprefix
.section .text
.global _start
.global cache_call_displacement
.equ CACHE_INPUT, 4096
.equ CACHE_OUTPUT, 1052672
.equ CACHE_WORK, 2097152
.equ STAMP_BASE, 10485760
.equ CACHE_GUARD, 23068672
.equ CACHE_MAP, 23072768

_start:
    cld
    cmp qword ptr [rsp], 18
    jne main_usage
    lea rbx, [rsp + 16]
    xor edi, edi
    mov esi, CACHE_MAP
    mov edx, 3
    mov r10d, 34
    mov r8, -1
    xor r9d, r9d
    mov eax, 9
    syscall
    cmp rax, -4095
    jae main_bare_fail
    mov r15, rax
    mov r13, rax
    lea rdi, [r15 + 128]
    mov ecx, 17
    mov rax, -1
    rep stosq
    mov qword ptr [r15 + STAMP_BASE + 128], -1
    lea rdi, [r15 + STAMP_BASE + 2097152 + 16384]
    mov ecx, 33794
    rep stosq
    mov qword ptr [r15 + 512], 1
    mov edi, 13
    lea rsi, [r15 + 512]
    xor edx, edx
    mov r10d, 8
    mov eax, 13
    syscall
    test rax, rax
    jnz main_io_fail
    lea rdi, [r15 + CACHE_GUARD]
    mov esi, 4096
    xor edx, edx
    mov eax, 10
    syscall
    test rax, rax
    jnz main_io_fail
    xor ebp, ebp
main_open_fixture:
    mov edi, -100
    mov rsi, [rbx + rbp*8]
    mov edx, 0xa0800
    xor r10d, r10d
    mov eax, 257
    syscall
    test rax, rax
    js main_io_fail
    mov [r15 + rbp*8 + 128], rax
    inc ebp
    cmp ebp, 17
    jb main_open_fixture
    lea r12, [r15 + CACHE_WORK]
main_next_frame:
    lea rdi, [r15 + CACHE_INPUT]
    mov esi, 1048576
    mov edx, 3
    mov eax, 10
    syscall
    test rax, rax
    jnz main_io_fail
    lea rsi, [r15 + 24]
    mov edx, 8
    mov r8d, 1
    call main_read_exact
    test eax, eax
    jz main_success
    mov rdx, [r15 + 24]
    cmp rdx, 1048576
    ja main_contract_fail
    lea rsi, [r15 + CACHE_INPUT]
    xor r8d, r8d
    call main_read_exact
    lea rdi, [r15 + CACHE_INPUT]
    mov esi, 1048576
    mov edx, 1
    mov eax, 10
    syscall
    test rax, rax
    jnz main_io_fail
main_resume:
    lea rdi, [r15 + CACHE_INPUT]
    mov rsi, [r15 + 24]
    lea rdx, [r15 + CACHE_OUTPUT]
    mov ecx, 266432
    mov r8, r12
    mov r9d, 8388608
    .byte 0xe8
cache_call_displacement:
    .long 0
    mov ecx, eax
    cmp rax, rcx
    jne main_contract_fail
    cmp eax, 0xfffffff0
    jne main_result
    lea r14, [r12 + 256]
    mov rax, 0x3130304143415248
    cmp [r14], rax
    jne main_contract_fail
    mov rax, [r15 + 16]
    inc rax
    jz main_contract_fail
    cmp [r14 + 8], rax
    jne main_contract_fail
    cmp [r12 + 16], rax
    jne main_contract_fail
    mov [r15 + 16], rax
    mov rax, [r14 + 64]
    or rax, [r14 + 72]
    or rax, [r14 + 80]
    or rax, [r14 + 88]
    jnz main_contract_fail
    cmp qword ptr [r12 + 8], 1
    jne main_contract_fail
    cmp qword ptr [r14 + 16], 100
    jne main_contract_fail
    cmp qword ptr [r14 + 24], 0
    jne main_contract_fail
    cmp qword ptr [r14 + 32], 8192
    jne main_contract_fail
    cmp qword ptr [r14 + 40], 8
    jne main_contract_fail
    cmp qword ptr [r14 + 48], 524288
    jne main_contract_fail
    cmp qword ptr [r14 + 56], 266288
    jne main_contract_fail
    mov rax, [r12 + 8192]
    cmp rax, 1
    jb main_contract_fail
    cmp rax, 17
    ja main_contract_fail
    mov rdi, [r15 + rax*8 + 120]
    test rdi, rdi
    js main_contract_fail
    call stamp_entry
    mov [r14 + 72], rax
    mov rax, [r14 + 8]
    mov [r14 + 64], rax
    jmp main_resume
main_result:
    cmp qword ptr [r12 + 8], 0
    jne main_contract_fail
    mov [r15 + 32], eax
    cmp eax, 266432
    ja main_special_result
    cmp eax, 64
    jb main_contract_fail
    jmp main_result_header
main_special_result:
    cmp eax, 0xffffffff
    je main_result_header
    cmp eax, 0xfffffffe
    je main_result_header
    cmp eax, 0xfffffff9
    jne main_contract_fail
main_result_header:
    lea rsi, [r15 + 32]
    mov edx, 4
    call main_write_exact
    mov edx, [r15 + 32]
    cmp edx, 266432
    ja main_next_frame
    lea rsi, [r15 + CACHE_OUTPUT]
    call main_write_exact
    jmp main_next_frame
main_success:
    xor ebp, ebp
    jmp main_cleanup
main_contract_fail:
    mov ebp, 2
    jmp main_cleanup
main_io_fail:
    mov ebp, 74
main_cleanup:
    mov r15, r13
    mov qword ptr [r15 + STAMP_BASE + 128], -1
    add r15, STAMP_BASE + 2097152
    mov qword ptr [r15 + 16384], -1
    mov ebx, 33793
main_namespace_cleanup_loop:
    mov rdi, [r15 + rbx*8 + 16384]
    mov qword ptr [r15 + rbx*8 + 16384], -1
    test rdi, rdi
    js main_namespace_cleanup_next
    call s_ns_raw_descriptor_referenced
    test eax, eax
    jnz main_namespace_cleanup_next
    mov eax, 3
    syscall
main_namespace_cleanup_next:
    dec ebx
    jns main_namespace_cleanup_loop
    mov r15, r13
    mov ebx, 16
main_fixture_cleanup_loop:
    mov rdi, [r15 + rbx*8 + 128]
    mov qword ptr [r15 + rbx*8 + 128], -1
    test rdi, rdi
    js main_fixture_cleanup_next
    mov eax, 3
    syscall
main_fixture_cleanup_next:
    dec ebx
    jns main_fixture_cleanup_loop
    mov rdi, r15
    mov esi, CACHE_MAP
    mov eax, 11
    syscall
    mov edi, ebp
    jmp main_exit
main_bare_fail:
    mov edi, 74
    jmp main_exit
main_usage:
    mov edi, 64
main_exit:
    mov eax, 60
    syscall
    ud2
