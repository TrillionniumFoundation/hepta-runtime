/* Closed Linux ordinary-file boundary. HIA owns generation, sequencing,
 * UTF-8, EOF, cancellation and snapshot lifetime. This is a component fixture,
 * not public MCP dispatch. No descriptor/flag comes from a public frame. */
.intel_syntax noprefix
.section .text
.global _start
.global owner_call_displacement
_start:
    cmp qword ptr [rsp], 1
    jne usage
    xor r12d, r12d
    mov esi, 4096
    call allocate
    cmp rax, -4095
    jae resource_failure
    mov r12, rax
    mov qword ptr [r12], -1
    mov esi, 4096
    call allocate
    cmp rax, -4095
    jae resource_failure
    mov [r12 + 40], rax
    mov qword ptr [r12 + 32], 4096
    mov esi, 131072
    call allocate
    cmp rax, -4095
    jae resource_failure
    mov r14, rax
    mov r15d, 131072
    mov qword ptr [r12 + 128], 1
    mov edi, 13
    lea rsi, [r12 + 128]
    xor edx, edx
    mov r10d, 8
    mov eax, 13
    syscall
    test rax, rax
    js io_failure
frame_next:
    xor edi, edi
    lea rsi, [r12 + 24]
    mov edx, 8
    call read_exact
    test eax, eax
    jz success
    cmp eax, 1
    jne io_failure
    mov rax, [r12 + 24]
    cmp rax, 64
    jb invalid
    test rax, rax
    js resource_failure
    cmp rax, [r12 + 32]
    jbe read_frame
    mov rdx, [r12 + 32]
input_grow:
    cmp rdx, rax
    jae input_grow_ready
    shl rdx, 1
    jc resource_failure
    test rdx, rdx
    js resource_failure
    jmp input_grow
input_grow_ready:
    mov [r12 + 48], rdx
    mov rdi, [r12 + 40]
    mov rsi, [r12 + 32]
    mov r10d, 1
    mov eax, 25
    syscall
    cmp rax, -4095
    jae resource_failure
    mov [r12 + 40], rax
    mov rax, [r12 + 48]
    mov [r12 + 32], rax
read_frame:
    xor edi, edi
    mov rsi, [r12 + 40]
    mov rdx, [r12 + 24]
    call read_exact
    cmp eax, 1
    jne io_failure
invoke:
    mov rdi, [r12 + 40]
    mov rsi, [r12 + 24]
    lea rdx, [r12 + 256]
    mov ecx, 80
    mov r8, r14
    mov r9, r15
    .byte 0xe8
owner_call_displacement:
    .long 0
    mov rdx, rax
    shr rdx, 32
    jnz invalid
    cmp eax, 0xffffffd0
    je grow_workspace
    cmp eax, 0xfffffff0
    je dispatch
    mov [r12 + 512], rax
    mov qword ptr [r12 + 520], 0
    cmp rax, 80
    jne reply
    cmp qword ptr [r12], -1
    jne invalid
    mov rax, 0x3130305244525648
    cmp [r12 + 256], rax
    jne invalid
    mov rdx, [r12 + 320]
    mov rax, [r12 + 312]
    cmp rax, r15
    ja invalid
    mov rcx, r15
    sub rcx, rax
    cmp rdx, rcx
    ja invalid
    add rdx, 80
    jc resource_failure
    mov [r12 + 520], rdx
reply:
    mov edi, 1
    lea rsi, [r12 + 512]
    mov edx, 16
    call write_exact
    cmp qword ptr [r12 + 520], 0
    je frame_next
    mov edi, 1
    lea rsi, [r12 + 256]
    mov edx, 80
    call write_exact
    mov rdx, [r12 + 320]
    test rdx, rdx
    jz frame_next
    mov edi, 1
    mov rsi, [r12 + 312]
    add rsi, r14
    call write_exact
    jmp frame_next

grow_workspace:
    mov rax, 0x3130304744525648
    cmp [r14 + 640], rax
    jne invalid
    mov rax, [r12 + 16]
    inc rax
    jz resource_failure
    cmp [r14 + 648], rax
    jne invalid
    cmp [r14 + 136], rax
    jne invalid
    mov [r12 + 16], rax
    mov rax, [r14 + 656]
    cmp rax, r15
    jbe invalid
    test rax, rax
    js resource_failure
    mov rdx, r15
workspace_grow:
    cmp rdx, rax
    jae workspace_grow_ready
    shl rdx, 1
    jc resource_failure
    test rdx, rdx
    js resource_failure
    jmp workspace_grow
workspace_grow_ready:
    mov [r12 + 48], rdx
    mov rdi, r14
    mov rsi, r15
    mov r10d, 1
    mov eax, 25
    syscall
    cmp rax, -4095
    jae resource_failure
    mov r14, rax
    mov r15, [r12 + 48]
    jmp invoke

dispatch:
    cmp qword ptr [r14 + 16], 1
    jne invalid
    mov rax, 0x3130584644525648
    cmp [r14 + 512], rax
    jne invalid
    mov rax, [r12 + 8]
    inc rax
    jz resource_failure
    cmp [r14 + 520], rax
    jne invalid
    cmp [r14 + 32], rax
    jne invalid
    mov [r12 + 8], rax
    mov rax, [r14 + 8]
    test rax, rax
    jz invalid
    cmp [r14 + 528], rax
    jne invalid
    lea rsi, [r14 + 576]
    mov ecx, 8
check_completion_zero:
    cmp qword ptr [rsi], 0
    jne invalid
    add rsi, 8
    loop check_completion_zero
    mov rax, [r12]
    mov [r12 + 64], rax
    mov rax, [r14 + 536]
    cmp rax, 1
    je stat_effect
    cmp rax, 2
    je open_effect
    cmp rax, 3
    je read_effect
    cmp rax, 4
    je close_effect
    jmp invalid
check_path:
    cmp qword ptr [r14 + 544], 4096
    jne invalid
    mov rax, [r14 + 552]
    cmp [r14 + 40], rax
    jne invalid
    mov rcx, r15
    sub rcx, 4097
    cmp rax, rcx
    ja invalid
    cmp byte ptr [r14 + rax + 4096], 0
    jne invalid
    ret
stat_effect:
    cmp qword ptr [r14 + 120], 11
    jne invalid
    cmp qword ptr [r12], -1
    jne invalid
    call check_path
    cmp qword ptr [r14 + 560], 1024
    jne invalid
    cmp qword ptr [r14 + 568], 144
    jne invalid
    mov rdi, -100
    lea rsi, [r14 + 4096]
    lea rdx, [r14 + 1024]
    xor r10d, r10d
    mov eax, 262
    syscall
    mov [r12 + 72], rax
    test rax, rax
    js effect_error
    jnz invalid
    mov eax, dword ptr [r14 + 1048]
    mov [r14 + 608], rax
    mov rax, [r14 + 1072]
    mov [r14 + 616], rax
    xor eax, eax
    jmp effect_complete
open_effect:
    cmp qword ptr [r14 + 120], 21
    jne invalid
    cmp qword ptr [r12], -1
    jne invalid
    call check_path
    cmp qword ptr [r14 + 560], 524288
    jne invalid
    cmp qword ptr [r14 + 568], 0
    jne invalid
    mov rdi, -100
    lea rsi, [r14 + 4096]
    mov edx, 524288
    xor r10d, r10d
    mov eax, 257
    syscall
    mov [r12 + 72], rax
    test rax, rax
    js effect_error
    mov [r12], rax
    xor eax, eax
    jmp effect_complete
read_effect:
    cmp qword ptr [r14 + 120], 31
    jne invalid
    cmp qword ptr [r14 + 104], 1
    jne invalid
    cmp qword ptr [r14 + 544], 0
    jne invalid
    cmp qword ptr [r14 + 560], 65536
    jne invalid
    cmp qword ptr [r14 + 568], 0
    jne invalid
    mov rsi, [r14 + 48]
    add rsi, [r14 + 56]
    jc invalid
    cmp [r14 + 552], rsi
    jne invalid
    mov rax, r15
    sub rax, 65536
    cmp rsi, rax
    ja invalid
    add rsi, r14
    mov rdi, [r12]
    test rdi, rdi
    js invalid
    mov edx, 65536
    xor eax, eax
    syscall
    mov [r12 + 72], rax
    test rax, rax
    js effect_error
    cmp rax, 65536
    ja invalid
    jmp effect_complete
close_effect:
    cmp qword ptr [r14 + 120], 41
    jne invalid
    cmp qword ptr [r14 + 104], 1
    jne invalid
    lea rsi, [r14 + 544]
    mov ecx, 4
check_close_args:
    cmp qword ptr [rsi], 0
    jne invalid
    add rsi, 8
    loop check_close_args
    mov rdi, [r12]
    test rdi, rdi
    js invalid
    mov qword ptr [r12], -1
    mov eax, 3
    syscall
    mov [r12 + 72], rax
    test rax, rax
    js effect_error
    jnz invalid
    jmp effect_complete
effect_error:
    cmp rax, -4095
    jb invalid
    mov rdx, rax
    neg rdx
    mov [r14 + 600], rdx
effect_complete:
    mov [r14 + 592], rax
    mov rax, [r14 + 520]
    mov [r14 + 576], rax
    mov rax, [r14 + 528]
    mov [r14 + 584], rax
    call receipt
    jmp invoke

receipt:
    lea rdi, [r12 + 768]
    mov rax, 0x314b434144525648
    mov [rdi], rax
    lea rsi, [r14 + 520]
    add rdi, 8
    mov ecx, 7
    cld
    rep movsq
    mov rax, [r12 + 72]
    mov [r12 + 832], rax
    lea rsi, [r14 + 592]
    lea rdi, [r12 + 840]
    mov ecx, 4
    rep movsq
    mov rax, [r12 + 64]
    mov [r12 + 872], rax
    mov rax, [r12]
    mov [r12 + 880], rax
    mov rax, [r14 + 520]
    mov [r12 + 888], rax
    mov edi, 2
    lea rsi, [r12 + 768]
    mov edx, 128
    call write_exact
    ret

allocate:
    xor edi, edi
    mov edx, 3
    mov r10d, 34
    mov r8, -1
    xor r9d, r9d
    mov eax, 9
    syscall
    ret
read_exact:
    mov r8, rdx
read_more:
    xor eax, eax
    syscall
    cmp rax, -4
    je read_more
    test rax, rax
    js io_failure
    jz read_eof
    add rsi, rax
    sub rdx, rax
    jnz read_more
    mov eax, 1
    ret
read_eof:
    cmp rdx, r8
    jne io_failure
    xor eax, eax
    ret
write_exact:
    test rdx, rdx
    jz write_done
write_more:
    mov eax, 1
    syscall
    cmp rax, -4
    je write_more
    cmp rax, -11
    je write_poll
    test rax, rax
    jle io_failure
    add rsi, rax
    sub rdx, rax
    jnz write_more
write_done:
    ret
write_poll:
    push rdi
    push rsi
    push rdx
    sub rsp, 16
    mov [rsp], edi
    mov dword ptr [rsp + 4], 4
poll_again:
    mov rdi, rsp
    mov esi, 1
    mov rdx, -1
    mov eax, 7
    syscall
    cmp rax, -4
    je poll_again
    cmp rax, 1
    jne io_failure
    add rsp, 16
    pop rdx
    pop rsi
    pop rdi
    jmp write_more
success:
    xor edi, edi
    jmp cleanup
usage:
    mov edi, 64
    jmp exit
invalid:
    mov edi, 70
    jmp cleanup
resource_failure:
    mov edi, 71
    jmp cleanup
io_failure:
    mov edi, 74
cleanup:
    mov ebp, edi
    test r12, r12
    jz cleanup_done
    mov rdi, [r12]
    test rdi, rdi
    js cleanup_done
    mov qword ptr [r12], -1
    mov eax, 3
    syscall
cleanup_done:
    mov edi, ebp
exit:
    mov eax, 60
    syscall
    ud2
