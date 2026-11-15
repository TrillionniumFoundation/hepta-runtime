/* Closed scalar call bridge. Only HIA owns regex parsing, admission and match.
 * Edges: 3->15; 15->{10,12,13,14}; {10,12,14}->11. No OS effect continuations.
 * The mapping is private/lazy. Input/output and every image workspace disjoint.
 */
.intel_syntax noprefix
.section .text
.global _start
.global image3_call_displacement
.global image15_call_displacement
.global image10_call_displacement
.global image12_call_displacement
.global image13_call_displacement
.global image14_call_displacement
.global image11_call_displacement
.equ INPUT, 4096
.equ OUTPUT, 134221824
.equ CONTROLLER_WORK, 536875008
.equ SYNTAX_WORK, 805310464
.equ HIR_WORK, 1073745920
.equ NFA_WORK, 1342181376
.equ MATCH_WORK, 1610616832
.equ DATA_WORK, 1644171264
.equ MAP_BYTES, 1644236800
.equ VALIDATION_WORK, 268439552
.equ CONTEXTS, 512
.equ SEQUENCES, 2048

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
    cmp rdx, 134217728
    ja failed
    test rdx, rdx
    jz root_context
    lea rsi, [r15 + INPUT]
    call read_exact
    test eax, eax
    jnz failed
root_context:
    xor r12d, r12d
    lea r14, [r15 + CONTEXTS]
    mov qword ptr [r14], 3
    lea rax, [r15 + INPUT]
    mov [r14 + 8], rax
    mov rax, [r15]
    mov [r14 + 16], rax
    lea rax, [r15 + OUTPUT]
    mov [r14 + 24], rax
    mov qword ptr [r14 + 32], 134217728
    lea rax, [r15 + VALIDATION_WORK]
    mov [r14 + 40], rax
    mov qword ptr [r14 + 48], 268435456

invoke:
    mov rax, r12
    shl rax, 6
    lea r14, [r15 + rax + CONTEXTS]
    mov rdi, [r14 + 8]
    mov rsi, [r14 + 16]
    mov rdx, [r14 + 24]
    mov rcx, [r14 + 32]
    mov r8, [r14 + 40]
    mov r9, [r14 + 48]
    mov rax, [r14]
    cmp eax, 3
    je invoke3
    cmp eax, 15
    je invoke15
    cmp eax, 10
    je invoke10
    cmp eax, 12
    je invoke12
    cmp eax, 13
    je invoke13
    cmp eax, 14
    je invoke14
    cmp eax, 11
    jne failed
    .byte 0xe8
image11_call_displacement:
    .long 0
    jmp returned
invoke3:
    .byte 0xe8
image3_call_displacement:
    .long 0
    jmp returned
invoke15:
    .byte 0xe8
image15_call_displacement:
    .long 0
    jmp returned
invoke10:
    .byte 0xe8
image10_call_displacement:
    .long 0
    jmp returned
invoke12:
    .byte 0xe8
image12_call_displacement:
    .long 0
    jmp returned
invoke13:
    .byte 0xe8
image13_call_displacement:
    .long 0
    jmp returned
invoke14:
    .byte 0xe8
image14_call_displacement:
    .long 0
returned:
    mov eax, eax
    cmp eax, 0xffffffe0
    je child_call
    cmp eax, 0xffff0000
    jae completed_child
    cmp rax, [r14 + 32]
    ja failed
completed_child:
    test r12, r12
    jz root_result
    dec r12
    sub r14, 64
    mov rbx, [r14 + 40]
    add rbx, [r14 + 48]
    sub rbx, 256
    mov [rbx + 80], rax
    mov rcx, [rbx + 8]
    mov [rbx + 88], rcx
    mov qword ptr [rbx + 96], 1
    mov qword ptr [rbx + 104], 0
    jmp invoke
root_result:
    xor edx, edx
    cmp eax, 0xffff0000
    jae domain_result
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
    cmp r12, 3
    jae failed
    mov rbx, [r14 + 40]
    mov rcx, [r14 + 48]
    lea rbx, [rbx + rcx - 256]
    mov rax, 0x31304c4143414948
    cmp [rbx], rax
    jne failed
    mov r10, [r14]
    mov r11, [rbx + 16]
    cmp r10, 3
    je validation_edge
    cmp r10, 15
    je root_edge
    cmp r10, 10
    je data_edge
    cmp r10, 12
    je data_edge
    cmp r10, 14
    jne failed
data_edge:
    cmp r11, 11
    jne failed
    jmp edge_admitted
validation_edge:
    cmp r11, 15
    jne failed
    jmp edge_admitted
root_edge:
    cmp r11, 10
    jb failed
    cmp r11, 14
    ja failed
    cmp r11, 11
    je failed
edge_admitted:
    cmp qword ptr [rbx + 24], 2
    jne failed
    cmp qword ptr [rbx + 48], 2
    jne failed
    xor ecx, ecx
zero_fields:
    cmp qword ptr [rbx + rcx*8 + 72], 0
    jne failed
    inc ecx
    cmp ecx, 6
    jb zero_fields
    mov rax, [r15 + r10*8 + SEQUENCES]
    inc rax
    jz failed
    cmp rax, [rbx + 8]
    jne failed
    mov rdx, [r14 + 48]
    sub rdx, 256
    mov rsi, [rbx + 32]
    cmp rsi, rdx
    ja failed
    sub rdx, rsi
    mov rdi, [rbx + 40]
    cmp rdi, rdx
    ja failed
    mov rcx, [rbx + 56]
    mov rdx, [r14 + 48]
    sub rdx, 256
    cmp rcx, rdx
    ja failed
    sub rdx, rcx
    mov r8, [rbx + 64]
    cmp r8, rdx
    ja failed
    test rdi, rdi
    jz spans_admitted
    test r8, r8
    jz spans_admitted
    lea rdx, [rsi + rdi]
    cmp rdx, rcx
    jbe spans_admitted
    lea rdx, [rcx + r8]
    cmp rdx, rsi
    ja failed
spans_admitted:
    cmp rdi, 134217728
    ja failed
    cmp r8, 134217728
    ja failed
    cmp r11, 14
    jne maybe_data
    cmp r8, 8
    ja failed
maybe_data:
    cmp r11, 11
    jne profile_admitted
    cmp rdi, 8
    ja failed
    cmp r8, 171683
    ja failed
profile_admitted:
    mov [r15 + r10*8 + SEQUENCES], rax
    add rsi, [r14 + 40]
    add rcx, [r14 + 40]
    inc r12
    add r14, 64
    mov [r14], r11
    mov [r14 + 8], rsi
    mov [r14 + 16], rdi
    mov [r14 + 24], rcx
    mov [r14 + 32], r8
    mov edx, 268435456
    mov eax, CONTROLLER_WORK
    cmp r11, 15
    je set_workspace
    mov eax, SYNTAX_WORK
    cmp r11, 10
    je set_workspace
    mov eax, HIR_WORK
    cmp r11, 12
    je set_workspace
    mov eax, NFA_WORK
    cmp r11, 13
    je set_workspace
    mov eax, MATCH_WORK
    mov edx, 33554432
    cmp r11, 14
    je set_workspace
    mov eax, DATA_WORK
    mov edx, 65536
set_workspace:
    add rax, r15
    mov [r14 + 40], rax
    mov [r14 + 48], rdx
    jmp invoke

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
