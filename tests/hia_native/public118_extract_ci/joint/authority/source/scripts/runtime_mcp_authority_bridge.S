/* Serial, private stdio authority capability. The nine fixed HIA owners decide
 * startup, entropy policy, first-call binding, crypto and result projection.
 * This boundary supplies memory, exact continuation delivery and fixed OS I/O.
 * No JSON byte, protocol peer or public tool name selects this capability. */
.intel_syntax noprefix
.section .text
.global runtime_authority_create
.global runtime_authority_release
.global runtime_authority_owned
.equ RA_INVALID, 0xffffffff
.equ RA_FATAL, 0xffffffe8
.equ RA_CALL, 0xffffffe0
.equ RA_EFFECT, 0xfffffff0
.equ RA_SLOT, 56
.equ RA_BYTES, 24928256

/* rdi is this session's fixed public engine. All nine workspaces start zero. */
runtime_authority_create:
    push rbp
    push rbx
    push r12
    push r13
    sub rsp, 8
    mov rbp, rdi
    cmp qword ptr [rbp + 432], 0
    jne ra_create_invalid
    mov edi, RA_BYTES
    call view_allocate
    cmp rax, -4095
    jae ra_create_done
    mov rbx, rax
    mov rax, 0x3130544341555248 /* HRUACT01 */
    mov [rbx], rax
    mov qword ptr [rbx + 40], 1 /* Trusted session lifecycle ticket. */
    mov qword ptr [rbx + 48], 1 /* Only native stdio is installed here. */
    mov qword ptr [rbx + 56], -1
    mov qword ptr [rbx + 72], -1
    mov qword ptr [rbx + 80], -1
    xor r12d, r12d
    lea r13, [rbx + 256]
ra_create_member:
    lea rdx, [rip + runtime_authority_images]
    mov rax, [rdx + r12 * 8]
    test rax, rax
    jz ra_create_mapping_fail
    mov [r13], rax
    imul rdx, r12, 48
    lea rcx, [rip + runtime_authority_caps]
    add rdx, rcx
    mov rax, [rdx + 40]
    add rax, rbx
    mov [r13 + 8], rax
    mov rax, [rdx]
    mov [r13 + 16], rax
    mov rax, [rdx + 8]
    mov [r13 + 24], rax
    mov rax, [rdx + 16]
    mov [r13 + 32], rax
    mov rax, [rdx + 24]
    mov [r13 + 40], rax
    mov rax, [rdx + 32]
    mov [r13 + 48], rax
    add r13, 64
    inc r12d
    cmp r12d, 9
    jb ra_create_member
    lea rdi, [rbx + 1280]
    xor esi, esi
    lea rdx, [rbx + 1024]
    mov ecx, 256
    xor r8d, r8d
    mov r9, rbx
    call ra_enter
    test rax, rax
    jnz ra_create_mapping_fail
    mov qword ptr [rbx + 8], 1
    mov qword ptr [rbx + 32], 1
    mov [rbp + 432], rbx
    xor eax, eax
    jmp ra_create_done
ra_create_mapping_fail:
    mov rdi, rbx
    call ra_drop_mapping
    mov rax, -22
    jmp ra_create_done
ra_create_invalid:
    mov rax, -22
ra_create_done:
    add rsp, 8
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret

/* r15 is the exact public session. The current successful output is borrowed
 * until the parent delivery completes; another call cannot overlap that borrow. */
runtime_authority_owned:
    push rbp
    push rbx
    push r12
    push r13
    push r14
    sub rsp, 16
    mov r12, rdi
    mov r13, rsi
    mov r14, [r15 + 432]
    mov rbx, [r15 + 8]
    add rbx, RA_SLOT * 64
    lea rbp, [r15 + 512 + RA_SLOT * 64]
    cmp qword ptr [rbp], 0
    jne ra_owned_invalid
    cmp qword ptr [rbp + 8], 0
    jne ra_owned_invalid
    test r14, r14
    jz ra_owned_invalid
    cmp qword ptr [r14 + 8], 1
    jne ra_owned_invalid
    cmp r13, 64
    jne ra_owned_invalid
    lea rdx, [rip + runtime_authority_request]
    xor ecx, ecx
ra_owned_request:
    mov al, [r12 + rcx]
    cmp al, [rdx + rcx]
    jne ra_owned_invalid
    inc ecx
    cmp ecx, 64
    jb ra_owned_request
    mov qword ptr [rbp], 1
    mov qword ptr [rbx + 48], 0
    mov qword ptr [rbx + 56], 0
    mov rax, [r14 + 256 + 8]
    mov [rbx + 8], rax
    mov qword ptr [rbx + 16], 16777216
    lea rdx, [r14 + 1024]
    mov [rbx + 32], rdx
    mov qword ptr [rbx + 40], 256
    inc qword ptr [r14 + 88]
    mov rdi, r12
    mov rsi, r13
    mov ecx, 256
    xor r8d, r8d
    mov r9, r14
    call ra_enter
    mov [rbx + 48], rax
    cmp eax, 0xffff0000
    jae ra_owned_return
    cmp rax, 256
    ja ra_owned_invalid_active
    mov [rbx + 56], rax
ra_owned_return:
    mov qword ptr [rbp], 0
    jmp ra_owned_done
ra_owned_invalid_active:
    mov qword ptr [rbp], 0
ra_owned_invalid:
    mov eax, RA_INVALID
    mov [rbx + 48], rax
    mov qword ptr [rbx + 56], 0
ra_owned_done:
    add rsp, 16
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret

/* Trusted final release after every public CALL has completed its delivery. */
runtime_authority_release:
    push rbx
    push r12
    sub rsp, 8
    mov rbx, [r15 + 432]
    test rbx, rbx
    jz ra_release_empty
    cmp qword ptr [r15 + 512 + RA_SLOT * 64], 0
    jne ra_release_invalid
    cmp qword ptr [r15 + 520 + RA_SLOT * 64], 0
    jne ra_release_invalid
    cmp qword ptr [rbx + 16], 0
    jne ra_release_invalid
    cmp qword ptr [rbx + 24], 0
    jne ra_release_invalid
    mov qword ptr [rbx + 32], 2
    lea rdi, [rbx + 1280]
    xor esi, esi
    lea rdx, [rbx + 1024]
    mov ecx, 256
    xor r8d, r8d
    mov r9, rbx
    call ra_enter
    test rax, rax
    jnz ra_release_invalid
    mov rdi, rbx
    call ra_drop_mapping
    test rax, rax
    jnz ra_release_done
    mov qword ptr [r15 + 432], 0
    mov rdi, [r15 + 8]
    add rdi, RA_SLOT * 64
    mov ecx, 8
    xor eax, eax
    rep stosq
ra_release_empty:
    xor eax, eax
    jmp ra_release_done
ra_release_invalid:
    mov rax, -22
ra_release_done:
    add rsp, 8
    pop r12
    pop rbx
    ret

/* rdi context; retire all real FDs, wipe the complete owned allocation, unmap. */
ra_drop_mapping:
    push rbx
    push rbp
    sub rsp, 8
    mov rbx, rdi
    xor ebp, ebp
ra_drop_fd:
    lea rdx, [rip + ra_descriptor_offsets]
    mov edx, [rdx + rbp * 4]
    mov rdi, [rbx + rdx]
    mov qword ptr [rbx + rdx], -1
    test rdi, rdi
    js ra_drop_next_fd
    mov eax, 3
    syscall
ra_drop_next_fd:
    inc ebp
    cmp ebp, 3
    jb ra_drop_fd
    mov rdi, rbx
    mov ecx, RA_BYTES
    xor eax, eax
    rep stosb
    mov rdi, rbx
    mov esi, RA_BYTES + 4096
    mov eax, 11
    syscall
    add rsp, 8
    pop rbp
    pop rbx
    ret

/* rdi/rsi input, rdx/rcx destination, r8 fixed local owner, r9 context.
 * Child input/output are exact bounded spans requested by the source footer. */
ra_enter:
    push rbp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub rsp, 136
    mov [rsp], rdi
    mov [rsp + 8], rsi
    mov [rsp + 16], rdx
    mov [rsp + 24], rcx
    mov r14, r8
    mov r15, r9
    cmp r14, 9
    jae ra_enter_invalid
    mov rax, 0x3130544341555248
    cmp [r15], rax
    jne ra_enter_invalid
    bt [r15 + 16], r14
    jc ra_enter_invalid
    mov rax, [r15 + 24]
    cmp rax, 8
    jae ra_enter_invalid
    mov [rsp + 32], rax
    mov rbx, r14
    shl rbx, 6
    lea rbx, [r15 + rbx + 256]
    cmp rsi, [rbx + 24]
    ja ra_enter_invalid
    cmp rcx, [rbx + 32]
    ja ra_enter_invalid
    mov r12, [rbx + 8]
    mov r13, [rbx + 16]
    bts [r15 + 16], r14
    inc qword ptr [r15 + 24]
    mov rbp, r12
    add rbp, r13
    sub rbp, 256
ra_enter_resume:
    cmp qword ptr [rbx + 40], 1
    je ra_enter_footer
    cmp qword ptr [rbx + 40], 8
    jne ra_enter_native
ra_enter_footer:
    mov eax, 3
    test r14, r14
    jnz ra_enter_child_footer
    mov rax, [r15 + 32]
ra_enter_child_footer:
    mov [rbp + 120], rax
    mov [rbp + 128], r14
    mov rax, [rsp + 32]
    mov [rbp + 136], rax
    test r14, r14
    jnz ra_enter_loader_footer
    mov rax, [r15 + 48]
    mov [rbp + 160], rax
    mov rax, [r15 + 40]
    mov [rbp + 168], rax
ra_enter_loader_footer:
    cmp r14, 8
    jne ra_enter_native
    mov rax, [r15 + 32]
    test rax, rax
    jnz ra_enter_fatal
    cmp qword ptr [rsp + 32], 1
    jne ra_enter_fatal
    mov [rbp + 144], rax
    mov qword ptr [rbp + 152], 0
    mov rax, [r15 + 48]
    mov [rbp + 160], rax
    mov rax, [r15 + 40]
    mov [rbp + 168], rax
ra_enter_native:
    mov rdi, [rsp]
    mov rsi, [rsp + 8]
    mov rdx, [rsp + 16]
    mov rcx, [rsp + 24]
    mov r8, r12
    mov r9, r13
    inc qword ptr [r15 + 96]
    call [rbx]
    mov edx, eax
    cmp rax, rdx
    jne ra_enter_fatal
    cmp eax, RA_CALL
    je ra_enter_child
    cmp eax, RA_EFFECT
    je ra_enter_effect
    cmp eax, 0xffff0000
    jae ra_enter_return
    cmp rax, [rsp + 24]
    ja ra_enter_fatal
    jmp ra_enter_return
ra_enter_child:
    cmp qword ptr [rbx + 40], 1
    jne ra_enter_fatal
    mov rax, 0x31304c4143414948 /* HIACAL01 */
    cmp [rbp], rax
    jne ra_enter_fatal
    mov rax, [rbx + 56]
    inc rax
    jz ra_enter_fatal
    cmp [rbp + 8], rax
    jne ra_enter_fatal
    mov [rsp + 40], rax
    mov r8, [rbp + 16]
    cmp r8, 9
    jae ra_enter_fatal
    bt [rbx + 48], r8
    jnc ra_enter_fatal
    bt [r15 + 16], r8
    jc ra_enter_fatal
    cmp r8, 8
    jne ra_enter_entropy_edge
    test r14, r14
    jnz ra_enter_fatal
    cmp qword ptr [r15 + 32], 0
    jne ra_enter_fatal
ra_enter_entropy_edge:
    cmp r8, 7
    jne ra_enter_child_shape
    cmp r14, 6
    je ra_enter_child_shape
    test r14, r14
    jnz ra_enter_fatal
    cmp qword ptr [r15 + 32], 0
    jne ra_enter_fatal
ra_enter_child_shape:
    mov rax, [rbp + 72]
    or rax, [rbp + 80]
    or rax, [rbp + 88]
    or rax, [rbp + 96]
    or rax, [rbp + 104]
    jnz ra_enter_fatal
    cmp qword ptr [rbp + 48], 2
    jne ra_enter_fatal
    mov rdi, r12
    mov rsi, r13
    sub rsi, 256
    mov rax, [rbp + 24]
    cmp rax, 2
    je ra_enter_child_input
    test rax, rax
    jnz ra_enter_fatal
    mov rdi, [rsp]
    mov rsi, [rsp + 8]
ra_enter_child_input:
    mov rax, [rbp + 32]
    cmp rax, rsi
    ja ra_enter_fatal
    sub rsi, rax
    cmp [rbp + 40], rsi
    ja ra_enter_fatal
    add rdi, rax
    jc ra_enter_fatal
    mov rsi, [rbp + 40]
    mov rdx, [rbp + 56]
    mov rcx, r13
    sub rcx, 256
    cmp rdx, rcx
    ja ra_enter_fatal
    sub rcx, rdx
    cmp [rbp + 64], rcx
    ja ra_enter_fatal
    add rdx, r12
    jc ra_enter_fatal
    mov rcx, [rbp + 64]
    test rsi, rsi
    jz ra_enter_child_disjoint
    test rcx, rcx
    jz ra_enter_child_disjoint
    mov rax, rdi
    add rax, rsi
    jc ra_enter_fatal
    cmp rax, rdx
    jbe ra_enter_child_disjoint
    mov rax, rdx
    add rax, rcx
    jc ra_enter_fatal
    cmp rax, rdi
    ja ra_enter_fatal
ra_enter_child_disjoint:
    mov rax, [rsp + 40]
    mov [rbx + 56], rax
    mov r9, r15
    inc qword ptr [r15 + 104]
    call ra_enter
    mov [rbp + 80], rax
    mov rdx, [rsp + 40]
    mov [rbp + 88], rdx
    mov qword ptr [rbp + 96], 1
    mov qword ptr [rbp + 104], 0
    jmp ra_enter_resume
ra_enter_effect:
    cmp r14, 8
    je ra_enter_loader
    cmp r14, 7
    jne ra_enter_fatal
    call ra_entropy_effect
    test rax, rax
    jnz ra_enter_fatal
    jmp ra_enter_resume
ra_enter_loader:
    call ra_loader_effect
    test rax, rax
    jnz ra_enter_fatal
    jmp ra_enter_resume
ra_enter_fatal:
    mov eax, RA_FATAL
ra_enter_return:
    btr [r15 + 16], r14
    dec qword ptr [r15 + 24]
    jmp ra_enter_done
ra_enter_invalid:
    mov eax, RA_INVALID
ra_enter_done:
    add rsp, 136
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret

/* Both effect owners publish the same ten-word shape at workspace+256.
 * r12 workspace/r15 context, rdi expected magic, rsi private last-sequence. */
ra_effect_admit:
    cmp [r12 + 256], rdi
    jne ra_effect_invalid
    mov rax, [r15 + rsi]
    inc rax
    jz ra_effect_invalid
    cmp [r12 + 264], rax
    jne ra_effect_invalid
    mov rcx, [r12 + 288]
    or rcx, [r12 + 304]
    or rcx, [r12 + 312]
    or rcx, [r12 + 320]
    or rcx, [r12 + 328]
    jnz ra_effect_invalid
    mov [r15 + rsi], rax
    inc qword ptr [r15 + 112]
    xor eax, eax
    ret
ra_effect_invalid:
    mov eax, RA_FATAL
    ret
ra_effect_complete:
    xor edx, edx
    test rax, rax
    jns ra_effect_result
    neg rax
    mov rdx, rax
    xor eax, eax
ra_effect_result:
    mov [r12 + 304], rax
    mov [r12 + 312], rdx
    mov rax, [r12 + 264]
    mov [r12 + 320], rax
    mov qword ptr [r12 + 328], 1
    xor eax, eax
    ret

/* The stdio loader can only open its source-selected fixed owner device. */
ra_loader_effect:
    sub rsp, 8
    mov rdi, 0x3130444f4c414948 /* HIALOD01 */
    mov esi, 64
    call ra_effect_admit
    test rax, rax
    jnz ra_loader_done
    mov rax, [r12 + 296]
    cmp rax, 7
    je ra_loader_open
    cmp rax, 4
    je ra_loader_read
    cmp rax, 6
    je ra_loader_close
    jmp ra_loader_invalid
ra_loader_open:
    mov rax, [r12 + 272]
    or rax, [r12 + 280]
    jnz ra_loader_invalid
    cmp qword ptr [r15 + 56], -1
    jne ra_loader_invalid
    mov edi, -100
    lea rsi, [rip + ra_urandom_path]
    mov edx, 0x80000
    xor r10d, r10d
    mov eax, 257
    syscall
    test rax, rax
    js ra_loader_complete
    mov [r15 + 56], rax
    xor eax, eax
    jmp ra_loader_complete
ra_loader_read:
    mov rsi, [r12 + 272]
    mov rdx, [r12 + 280]
    cmp rsi, 135168
    jb ra_loader_invalid
    cmp rsi, 139266
    jae ra_loader_invalid
    mov rcx, 139266
    sub rcx, rsi
    test rdx, rdx
    jz ra_loader_invalid
    cmp rdx, rcx
    ja ra_loader_invalid
    mov rdi, [r15 + 56]
    test rdi, rdi
    js ra_loader_invalid
    add rsi, r12
    xor eax, eax
    syscall
    jmp ra_loader_complete
ra_loader_close:
    mov rax, [r12 + 272]
    or rax, [r12 + 280]
    jnz ra_loader_invalid
    mov rdi, [r15 + 56]
    test rdi, rdi
    js ra_loader_invalid
    mov qword ptr [r15 + 56], -1
    mov eax, 3
    syscall
ra_loader_complete:
    call ra_effect_complete
    jmp ra_loader_done
ra_loader_invalid:
    mov eax, RA_FATAL
ra_loader_done:
    add rsp, 8
    ret

/* Original SystemEntropy's direct/fallback policy remains entirely in HIA. */
ra_entropy_effect:
    sub rsp, 24
    mov rdi, 0x3230544e45414948 /* HIAENT02 */
    mov esi, 120
    call ra_effect_admit
    test rax, rax
    jnz ra_entropy_done
    mov rax, [r12 + 296]
    cmp rax, 1
    je ra_entropy_probe
    cmp rax, 2
    je ra_entropy_data
    cmp rax, 7
    je ra_entropy_data
    mov rdx, [r12 + 272]
    or rdx, [r12 + 280]
    jnz ra_entropy_invalid
    cmp rax, 3
    je ra_entropy_open_random
    cmp rax, 4
    je ra_entropy_poll
    cmp rax, 5
    je ra_entropy_close_random
    cmp rax, 6
    je ra_entropy_open_urandom
    jmp ra_entropy_invalid
ra_entropy_probe:
    cmp qword ptr [r12 + 272], 512
    jne ra_entropy_invalid
    cmp qword ptr [r12 + 280], 0
    jne ra_entropy_invalid
    lea rdi, [r12 + 512]
    xor esi, esi
    xor edx, edx
    mov eax, 318
    syscall
    jmp ra_entropy_complete
ra_entropy_data:
    mov rsi, [r12 + 272]
    mov rdx, [r12 + 280]
    cmp rsi, 512
    jb ra_entropy_invalid
    cmp rsi, 640
    jae ra_entropy_invalid
    mov rcx, 640
    sub rcx, rsi
    test rdx, rdx
    jz ra_entropy_invalid
    cmp rdx, rcx
    ja ra_entropy_invalid
    add rsi, r12
    cmp rax, 2
    jne ra_entropy_read
    mov rdi, rsi
    mov rsi, rdx
    xor edx, edx
    mov eax, 318
    syscall
    jmp ra_entropy_complete
ra_entropy_read:
    mov rdi, [r15 + 72]
    test rdi, rdi
    js ra_entropy_invalid
    xor eax, eax
    syscall
    jmp ra_entropy_complete
ra_entropy_open_random:
    cmp qword ptr [r15 + 80], -1
    jne ra_entropy_invalid
    lea rsi, [rip + ra_random_path]
    mov qword ptr [rsp + 8], 80
    jmp ra_entropy_open
ra_entropy_open_urandom:
    cmp qword ptr [r15 + 72], -1
    jne ra_entropy_invalid
    lea rsi, [rip + ra_urandom_path]
    mov qword ptr [rsp + 8], 72
ra_entropy_open:
    mov edi, -100
    mov edx, 0x80000
    xor r10d, r10d
    mov eax, 257
    syscall
    test rax, rax
    js ra_entropy_complete
    mov rcx, [rsp + 8]
    mov [r15 + rcx], rax
    xor eax, eax
    jmp ra_entropy_complete
ra_entropy_poll:
    mov rax, [r15 + 80]
    test rax, rax
    js ra_entropy_invalid
    mov [rsp], eax
    mov dword ptr [rsp + 4], 1
    mov rdi, rsp
    mov esi, 1
    mov rdx, -1
    mov eax, 7
    syscall
    jmp ra_entropy_complete
ra_entropy_close_random:
    mov rdi, [r15 + 80]
    test rdi, rdi
    js ra_entropy_invalid
    mov qword ptr [r15 + 80], -1
    mov eax, 3
    syscall
ra_entropy_complete:
    call ra_effect_complete
    jmp ra_entropy_done
ra_entropy_invalid:
    mov eax, RA_FATAL
ra_entropy_done:
    add rsp, 24
    ret

.balign 8
runtime_authority_images:
    .zero 72
/* workspace, input, output, flags, child mask, private allocation offset. */
runtime_authority_caps:
    .quad 16777216, 8388608, 8388608, 1, 456, 4096
    .quad 3145728, 8388608, 2097152, 1, 28, 16781312
    .quad 2048, 8388608, 128, 0, 0, 19927040
    .quad 1184, 8388608, 128, 0, 0, 19931136
    .quad 512, 8388608, 1048640, 0, 0, 19935232
    .quad 1576960, 164, 64, 0, 0, 19939328
    .quad 3145728, 8388608, 2097152, 1, 166, 21516288
    .quad 1024, 24, 128, 4, 0, 24662016
    .quad 262144, 131095, 4096, 8, 0, 24666112
ra_descriptor_offsets:
    .long 56, 72, 80
runtime_authority_request:
    .ascii "4852415554523031030000000000000000000000000000000000000000000000"
ra_random_path:
    .asciz "/dev/random"
ra_urandom_path:
    .asciz "/dev/urandom"
