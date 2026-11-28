.intel_syntax noprefix
.section .text
.global _start

# Closed Linux x86-64 effects for the HIA raw canonicalize owner.  There are two
# private directory slots, never caller-selected file descriptors.  Every
# path is an exact NUL-terminated span admitted below.  No libc or resolver
# runs outside the HIA image.
_start:
    xor r15d, r15d
    cmp qword ptr [rsp], 1
    jne usage
    lea rsi, [rsp + 24]
environment:
    cmp qword ptr [rsi], 0
    lea rsi, [rsi + 8]
    jne environment
    xor ebp, ebp
auxiliary_vector:
    mov rax, qword ptr [rsi]
    test rax, rax
    jz auxiliary_done
    cmp rax, 23
    jne auxiliary_next
    cmp qword ptr [rsi + 8], 0
    setne bpl
auxiliary_next:
    add rsi, 16
    jmp auxiliary_vector
auxiliary_done:
    sub rsp, 512
    xor edi, edi
    mov esi, 4096
    mov edx, 3
    mov r10d, 0x22
    mov r8, -1
    xor r9d, r9d
    mov eax, 9
    syscall
    cmp rax, -4095
    jae memory_fail
    mov r15, rax
    mov qword ptr [r15 + 64], rbp
    mov qword ptr [r15 + 72], -1
    mov qword ptr [r15 + 80], -1
    mov edi, 4096
    call allocate_guarded
    mov qword ptr [r15], rax
    mov qword ptr [r15 + 8], 4096
    mov edi, 1056768
    call allocate_guarded
    mov qword ptr [r15 + 16], rax
    mov qword ptr [r15 + 24], 1056768
    mov edi, 4096
    call allocate_guarded
    mov qword ptr [r15 + 32], rax
    mov qword ptr [r15 + 40], 4096
    mov qword ptr [rsp], 1
    mov qword ptr [rsp + 8], 0
    mov qword ptr [rsp + 16], 0
    mov qword ptr [rsp + 24], 0
    mov edi, 13
    mov rsi, rsp
    xor edx, edx
    mov r10d, 8
    mov eax, 13
    syscall
    test rax, rax
    jnz io_fail

next_frame:
    cmp qword ptr [r15 + 72], -1
    jne contract_fail
    cmp qword ptr [r15 + 80], -1
    jne contract_fail
    lea rsi, [r15 + 56]
    mov edx, 8
    mov r14d, 1
    call read_exact
    test eax, eax
    jz success
    mov rax, qword ptr [r15 + 56]
    mov qword ptr [r15 + 48], rax
    cmp rax, qword ptr [r15 + 8]
    jbe input_ready
    mov rdi, rax
    call round_capacity
    mov r12, rax
    mov rdi, r12
    call allocate_guarded
    mov r13, rax
    mov rdi, qword ptr [r15]
    mov rsi, qword ptr [r15 + 8]
    add rsi, 4096
    mov qword ptr [r15], r13
    mov qword ptr [r15 + 8], r12
    mov eax, 11
    syscall
    test rax, rax
    jnz io_fail
input_ready:
    mov rdi, qword ptr [r15]
    mov rsi, qword ptr [r15 + 8]
    mov edx, 3
    mov eax, 10
    syscall
    test rax, rax
    jnz io_fail
    mov rsi, qword ptr [r15]
    mov rdx, qword ptr [r15 + 48]
    xor r14d, r14d
    call read_exact
    mov rdi, qword ptr [r15]
    mov rsi, qword ptr [r15 + 8]
    mov edx, 1
    mov eax, 10
    syscall
    test rax, rax
    jnz io_fail
    mov rdi, qword ptr [r15 + 16]
    xor eax, eax
    mov ecx, 128
    rep stosq
    mov rbx, qword ptr [r15 + 16]
    mov rax, qword ptr [r15 + 64]
    mov qword ptr [rbx + 176], rax
    mov qword ptr [r15 + 88], 0
invoke:
    mov rdi, qword ptr [r15]
    mov rsi, qword ptr [r15 + 48]
    mov rdx, qword ptr [r15 + 32]
    mov rcx, qword ptr [r15 + 40]
    mov r8, qword ptr [r15 + 16]
    mov r9, qword ptr [r15 + 24]
    call policy_image
    mov edx, eax
    cmp rax, rdx
    jne contract_fail
    mov rbx, qword ptr [r15 + 16]
    cmp eax, 0xffffffef
    je grow_workspace
    cmp eax, 0xffffffee
    je grow_output
    cmp eax, 0xfffffff0
    je admit_effect
    cmp eax, 0xffffffff
    je refusal
    cmp eax, 0xfffffffe
    je refusal
    cmp eax, 0xfffffff9
    je contract_fail
    cmp eax, 32
    jb contract_fail
    cmp rax, qword ptr [r15 + 40]
    ja contract_fail
    cmp qword ptr [rbx], 100
    jne contract_fail
    mov rdx, qword ptr [r15 + 32]
    mov rcx, 0x3130524c4e435248
    cmp qword ptr [rdx], rcx
    jne contract_fail
    lea rcx, [rax - 32]
    cmp qword ptr [rdx + 16], rcx
    jne contract_fail
    cmp qword ptr [rdx + 8], 0
    je result_success
    cmp qword ptr [rdx + 8], 1
    jne contract_fail
    mov rcx, qword ptr [rdx + 24]
    test rcx, rcx
    jz contract_fail
    cmp rcx, 65536
    je result_status_valid
    cmp rcx, 4095
    ja contract_fail
    jmp result_status_valid
result_success:
    cmp qword ptr [rdx + 24], 0
    jne contract_fail
result_status_valid:
    cmp qword ptr [r15 + 72], -1
    jne contract_fail
    cmp qword ptr [r15 + 80], -1
    jne contract_fail
    mov dword ptr [r15 + 56], eax
    lea rsi, [r15 + 56]
    mov edx, 4
    call write_exact
    mov edx, dword ptr [r15 + 56]
    mov rsi, qword ptr [r15 + 32]
    call write_exact
    jmp next_frame
refusal:
    mov dword ptr [r15 + 56], eax
    call cleanup
    lea rsi, [r15 + 56]
    mov edx, 4
    call write_exact
    jmp next_frame

grow_workspace:
    mov rdi, qword ptr [rbx + 40]
    cmp rdi, qword ptr [rbx + 32]
    jbe contract_fail
    mov rax, 0x1ffffffffffbfeff
    cmp rdi, rax
    ja memory_fail
    shl rdi, 2
    add rdi, 1049600
    jc memory_fail
    call round_capacity
    mov r12, rax
    cmp r12, qword ptr [r15 + 24]
    jbe invoke
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
    jnz io_fail
    jmp invoke
grow_output:
    mov rdi, qword ptr [rbx + 48]
    cmp rdi, qword ptr [r15 + 40]
    jbe contract_fail
    mov rax, 0xffffffef
    cmp rdi, rax
    ja contract_fail
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
    jnz io_fail
    jmp invoke

admit_effect:
    mov rax, qword ptr [r15 + 48]
    cmp qword ptr [rbx + 8], rax
    jne contract_fail
    mov rax, qword ptr [r15 + 40]
    cmp qword ptr [rbx + 16], rax
    jne contract_fail
    mov rax, qword ptr [r15 + 24]
    cmp qword ptr [rbx + 24], rax
    jne contract_fail
    mov rax, qword ptr [rbx + 40]
    or rax, qword ptr [rbx + 48]
    jnz contract_fail
    mov rax, qword ptr [rbx + 32]
    cmp rax, 1024
    jb contract_fail
    lea rcx, [rax - 1]
    test rcx, rax
    jnz contract_fail
    cmp qword ptr [rbx + 96], rax
    jae contract_fail
    mov rcx, 0x1ffffffffffbfeff
    cmp rax, rcx
    ja contract_fail
    shl rax, 2
    add rax, 1049600
    jc contract_fail
    cmp rax, qword ptr [r15 + 24]
    ja contract_fail
    mov rax, 0x584659454b4c4648
    cmp qword ptr [rbx + 512], rax
    jne contract_fail
    inc qword ptr [r15 + 88]
    jz contract_fail
    mov rax, qword ptr [r15 + 88]
    cmp qword ptr [rbx + 520], rax
    jne contract_fail
    cmp qword ptr [rbx + 56], rax
    jne contract_fail
    mov rax, qword ptr [rbx + 568]
    or rax, qword ptr [rbx + 576]
    or rax, qword ptr [rbx + 584]
    or rax, qword ptr [rbx + 592]
    or rax, qword ptr [rbx + 600]
    or rax, qword ptr [rbx + 608]
    or rax, qword ptr [rbx + 616]
    or rax, qword ptr [rbx + 624]
    or rax, qword ptr [rbx + 632]
    jnz contract_fail
    mov r14, qword ptr [rbx + 528]
    cmp r14, 1
    je get_current
    cmp r14, 2
    je read_link
    cmp r14, 3
    je access_path
    cmp r14, 4
    je access_path
    cmp r14, 5
    je lstat_path
    cmp r14, 6
    je access_path
    cmp r14, 7
    je open_parent
    cmp r14, 8
    je stat_descriptor
    cmp r14, 9
    je close_descriptor
    cmp r14, 10
    je get_flags
    cmp r14, 11
    je set_cloexec
    cmp r14, 12
    je directory_entries
    cmp r14, 13
    je rewind_directory
    jmp contract_fail

get_current:
    cmp qword ptr [rbx], 10
    jne contract_fail
    call resolved_argument
    mov rdx, qword ptr [rbx + 552]
    or rdx, qword ptr [rbx + 560]
    jnz contract_fail
    mov rsi, qword ptr [rbx + 544]
    cmp rsi, qword ptr [rbx + 152]
    jne contract_fail
    cmp rsi, 1024
    jb contract_fail
    cmp rsi, qword ptr [rbx + 32]
    ja contract_fail
    mov eax, 79
    syscall
    jmp value_completion

read_link:
    cmp qword ptr [rbx], 3
    jne contract_fail
    call resolved_argument
    mov rcx, qword ptr [rbx + 544]
    cmp rcx, qword ptr [rbx + 96]
    jne contract_fail
    call cstring
    mov rax, qword ptr [rbx + 32]
    lea rax, [rax + rax + 1024]
    cmp qword ptr [rbx + 552], rax
    jne contract_fail
    lea rsi, [rbx + rax]
    mov rdx, qword ptr [rbx + 144]
    cmp rdx, 1024
    jb contract_fail
    dec rdx
    cmp rdx, qword ptr [rbx + 560]
    jne contract_fail
    cmp rdx, qword ptr [rbx + 32]
    jae contract_fail
    mov eax, 89
    syscall
    jmp value_completion

access_path:
    cmp qword ptr [rbx], 4
    jne contract_fail
    call resolved_argument
    mov rcx, qword ptr [rbx + 96]
    inc rcx
    cmp rcx, qword ptr [rbx + 32]
    jae contract_fail
    cmp rcx, qword ptr [rbx + 544]
    jne contract_fail
    call cstring
    mov rax, qword ptr [rbx + 552]
    or rax, qword ptr [rbx + 560]
    jnz contract_fail
    mov rsi, rdi
    mov edi, -100
    xor edx, edx
    mov r10d, 512
    mov eax, 439
    cmp r14, 3
    je access_go
    cmp r14, 4
    jne stat_access
    cmp qword ptr [r15 + 64], 0
    jne contract_fail
    mov eax, 269
access_go:
    syscall
    jmp zero_completion
stat_access:
    cmp qword ptr [r15 + 64], 1
    jne contract_fail
    xor r10d, r10d
    jmp stat_at

lstat_path:
    mov rax, qword ptr [rbx]
    cmp rax, 12
    je lstat_fixed
    cmp rax, 13
    je lstat_fixed
    cmp rax, 24
    jne contract_fail
    mov rax, qword ptr [rbx + 32]
    lea rax, [rax * 4 + 1024]
    add rax, qword ptr [rbx + 368]
    jc contract_fail
    cmp rax, qword ptr [rbx + 536]
    jne contract_fail
    mov rcx, qword ptr [rbx + 376]
    cmp rcx, qword ptr [rbx + 544]
    jne contract_fail
    mov rdx, qword ptr [rbx + 552]
    cmp rdx, qword ptr [rbx + 160]
    jne contract_fail
    jmp lstat_arguments
lstat_fixed:
    mov rax, qword ptr [rbx + 32]
    lea rax, [rax + rax + 1024]
    cmp rax, qword ptr [rbx + 536]
    jne contract_fail
    mov ecx, 1
    cmp qword ptr [rbx + 544], 1
    jne contract_fail
    cmp qword ptr [rbx + 552], 0
    jne contract_fail
    xor edx, edx
    cmp qword ptr [rbx], 12
    jne lstat_root
    cmp byte ptr [rbx + rax], 46
    jne contract_fail
    jmp lstat_arguments
lstat_root:
    cmp byte ptr [rbx + rax], 47
    jne contract_fail
lstat_arguments:
    cmp qword ptr [rbx + 560], 0
    jne contract_fail
    lea rdi, [rbx + rax]
    call cstring
    mov rsi, rdi
    mov edi, -100
    test rdx, rdx
    jz lstat_cwd
    call descriptor
lstat_cwd:
    mov r10d, 256
stat_at:
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
    jmp stat_completion

open_parent:
    cmp qword ptr [rbx], 15
    jne contract_fail
    mov rax, qword ptr [rbx + 552]
    or rax, qword ptr [rbx + 560]
    jnz contract_fail
    mov r12, qword ptr [rbx + 536]
    cmp r12, 1
    jb contract_fail
    cmp r12, 2
    ja contract_fail
    cmp qword ptr [r15 + r12 * 8 + 64], -1
    jne contract_fail
    mov rdx, qword ptr [rbx + 544]
    cmp rdx, qword ptr [rbx + 160]
    jne contract_fail
    cmp rdx, r12
    je contract_fail
    mov edi, -100
    test rdx, rdx
    jz open_parent_cwd
    call descriptor
open_parent_cwd:
    lea rsi, [rip + parent_name]
    xor edx, edx
    xor r10d, r10d
    mov eax, 257
    syscall
    test rax, rax
    js error_completion
    cmp rax, 0x7fffffff
    ja contract_fail
    mov qword ptr [r15 + r12 * 8 + 64], rax
    mov rax, r12
    jmp value_completion

stat_descriptor:
    mov rax, qword ptr [rbx]
    cmp rax, 16
    je stat_descriptor_phase
    cmp rax, 18
    jne contract_fail
stat_descriptor_phase:
    call zero_trailing_args
    mov rdx, qword ptr [rbx + 536]
    cmp rdx, qword ptr [rbx + 168]
    jne contract_fail
    call descriptor
    mov r13, rdi
    mov rdi, rsp
    xor eax, eax
    mov ecx, 32
    rep stosq
    mov rdi, r13
    mov rsi, rsp
    mov eax, 5
    syscall
stat_completion:
    test rax, rax
    js error_completion
    test rax, rax
    jnz contract_fail
    mov rax, qword ptr [rsp]
    mov qword ptr [rbx + 584], rax
    mov rax, qword ptr [rsp + 8]
    mov qword ptr [rbx + 592], rax
    mov eax, dword ptr [rsp + 24]
    mov qword ptr [rbx + 600], rax
    mov rax, qword ptr [rsp + 56]
    mov qword ptr [rbx + 616], rax
    jmp acknowledge

close_descriptor:
    mov rax, qword ptr [rbx]
    cmp rax, 17
    je close_phase
    cmp rax, 27
    je close_phase
    cmp rax, 29
    jne contract_fail
close_phase:
    call zero_trailing_args
    mov rdx, qword ptr [rbx + 536]
    call descriptor
    mov qword ptr [r15 + rdx * 8 + 64], -1
    mov eax, 3
    syscall
    jmp zero_completion

get_flags:
    cmp qword ptr [rbx], 19
    jne contract_fail
    call zero_trailing_args
    mov rdx, qword ptr [rbx + 536]
    cmp rdx, qword ptr [rbx + 168]
    jne contract_fail
    call descriptor
    mov esi, 3
    xor edx, edx
    mov eax, 72
    syscall
    jmp value_completion
set_cloexec:
    cmp qword ptr [rbx], 20
    jne contract_fail
    call zero_trailing_args
    mov rdx, qword ptr [rbx + 536]
    cmp rdx, qword ptr [rbx + 168]
    jne contract_fail
    call descriptor
    mov esi, 2
    mov edx, 1
    mov eax, 72
    syscall
    jmp zero_completion

directory_entries:
    cmp qword ptr [rbx], 22
    jne contract_fail
    cmp qword ptr [rbx + 560], 0
    jne contract_fail
    mov rax, qword ptr [rbx + 32]
    lea rax, [rax * 4 + 1024]
    cmp rax, qword ptr [rbx + 544]
    jne contract_fail
    mov r12, qword ptr [rbx + 552]
    cmp r12, 32768
    jb contract_fail
    cmp r12, 1048576
    ja contract_fail
    cmp r12, qword ptr [rbx + 336]
    jne contract_fail
    lea rsi, [rbx + rax]
    mov rdx, qword ptr [rbx + 536]
    cmp rdx, qword ptr [rbx + 160]
    jne contract_fail
    call descriptor
    mov rdx, r12
    mov eax, 217
    syscall
    jmp value_completion
rewind_directory:
    cmp qword ptr [rbx], 23
    jne contract_fail
    call zero_trailing_args
    mov rdx, qword ptr [rbx + 536]
    cmp rdx, qword ptr [rbx + 160]
    jne contract_fail
    call descriptor
    xor esi, esi
    xor edx, edx
    mov eax, 8
    syscall
    jmp value_completion

resolved_argument:
    mov rax, qword ptr [rbx + 32]
    add rax, 1024
    cmp qword ptr [rbx + 536], rax
    jne contract_fail
    lea rdi, [rbx + rax]
    ret
zero_trailing_args:
    mov rax, qword ptr [rbx + 544]
    or rax, qword ptr [rbx + 552]
    or rax, qword ptr [rbx + 560]
    jnz contract_fail
    ret
# logical slot in rdx -> real descriptor in rdi, preserving other arguments.
descriptor:
    cmp rdx, 1
    jb contract_fail
    cmp rdx, 2
    ja contract_fail
    mov rdi, qword ptr [r15 + rdx * 8 + 64]
    test rdi, rdi
    js contract_fail
    ret
# Exact span containment and unique final NUL.  rdx is preserved for dirfd.
cstring:
    mov rax, rdi
    sub rax, rbx
    jc contract_fail
    cmp rax, qword ptr [r15 + 24]
    jae contract_fail
    mov r11, qword ptr [r15 + 24]
    sub r11, rax
    cmp rcx, r11
    jae contract_fail
    cmp byte ptr [rdi + rcx], 0
    jne contract_fail
    xor eax, eax
cstring_loop:
    cmp rax, rcx
    je cstring_done
    cmp byte ptr [rdi + rax], 0
    je contract_fail
    inc rax
    jmp cstring_loop
cstring_done:
    ret
value_completion:
    test rax, rax
    js error_completion
    mov qword ptr [rbx + 568], rax
    jmp acknowledge
zero_completion:
    test rax, rax
    js error_completion
    test rax, rax
    jnz contract_fail
    jmp acknowledge
error_completion:
    neg rax
    cmp rax, 4095
    ja contract_fail
    mov qword ptr [rbx + 576], rax
acknowledge:
    mov qword ptr [rbx + 608], 1
    jmp invoke

round_capacity:
    mov rax, rdi
    add rax, 4095
    jc memory_fail
    and rax, -4096
    test rax, rax
    jz memory_fail
    mov rdx, 0x7ffffffffffff000
    cmp rax, rdx
    jae memory_fail
    ret
allocate_guarded:
    push rbx
    mov rbx, rdi
    lea rsi, [rdi + 4096]
    xor edi, edi
    mov edx, 3
    mov r10d, 0x22
    mov r8, -1
    xor r9d, r9d
    mov eax, 9
    syscall
    cmp rax, -4095
    jae memory_fail
    push rax
    lea rdi, [rax + rbx]
    mov esi, 4096
    xor edx, edx
    mov eax, 10
    syscall
    test rax, rax
    jnz memory_fail
    pop rax
    pop rbx
    ret
read_exact:
    test rdx, rdx
    jz read_done
read_loop:
    xor edi, edi
    xor eax, eax
    syscall
    cmp rax, -4
    je read_loop
    test rax, rax
    js io_fail
    jz read_eof
    xor r14d, r14d
    add rsi, rax
    sub rdx, rax
    jnz read_loop
read_done:
    mov eax, 1
    ret
read_eof:
    test r14, r14
    jz io_fail
    xor eax, eax
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
    jle io_fail
    add rsi, rax
    sub rdx, rax
    jnz write_loop
write_done:
    ret
cleanup:
    mov rdi, qword ptr [r15 + 72]
    mov qword ptr [r15 + 72], -1
    test rdi, rdi
    js cleanup_second
    mov eax, 3
    syscall
cleanup_second:
    mov rdi, qword ptr [r15 + 80]
    mov qword ptr [r15 + 80], -1
    test rdi, rdi
    js cleanup_done
    mov eax, 3
    syscall
cleanup_done:
    ret
success:
    xor edi, edi
    jmp exit
usage:
    mov edi, 64
    jmp exit
contract_fail:
    call cleanup
    mov edi, 70
    jmp exit
memory_fail:
    test r15, r15
    jz memory_exit
    call cleanup
memory_exit:
    mov edi, 71
    jmp exit
io_fail:
    call cleanup
    mov edi, 74
exit:
    mov eax, 231
    syscall
    ud2
parent_name:
    .asciz ".."
.balign 16
policy_image:
