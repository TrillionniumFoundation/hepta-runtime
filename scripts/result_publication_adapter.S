/* Fixed Linux borrowed-byte boundary. All construction, UTF-8 admission,
 * escaping, generation checks and ACK semantics execute in the HIA image.
 * These explicit fixture modes are not production MCP handlers. */
.intel_syntax noprefix
.section .text
.global _start
.equ SRC, 4096
.equ DST, 73728
.equ WINDOW, 65600
.equ GROW, 0xffffffd0
.equ RESOURCE, 0xfffffffc
_start:
    cmp qword ptr [rsp], 2
    jne usage
    mov rbx, [rsp + 16]
    mov rdi, rbx
    lea rsi, [rip + owner_option]
    call equal_string
    test eax, eax
    jnz owner_mode
    mov rdi, rbx
    lea rsi, [rip + publish_option]
    call equal_string
    test eax, eax
    jz usage
    mov ebp, 1
    jmp setup
owner_mode:
    xor ebp, ebp
setup:
    mov esi, 262144
    call allocate
    cmp rax, -4095
    jae io_failure
    mov r12, rax
    mov [r12], rbp
    mov esi, 131072
    call allocate
    cmp rax, -4095
    jae io_failure
    mov r14, rax
    mov r15d, 131072
    mov qword ptr [r12 + 256], 1
    mov edi, 13
    lea rsi, [r12 + 256]
    xor edx, edx
    mov r10d, 8
    mov eax, 13
    syscall
    test rax, rax
    js io_failure
frame_next:
    xor edi, edi
    lea rsi, [r12 + 8]
    mov edx, 8
    call read_exact
    test eax, eax
    jz input_done
    cmp eax, 1
    jne invalid
    mov rdx, [r12 + 8]
    cmp rdx, 64
    jb invalid
    cmp rdx, WINDOW
    ja invalid
    xor edi, edi
    lea rsi, [r12 + SRC]
    call read_exact
    cmp eax, 1
    jne invalid
    cmp qword ptr [r12], 0
    je invoke_frame
    mov rax, [r12 + SRC + 8]
    cmp rax, 7
    jbe invoke_frame
    cmp rax, 13
    jne invalid
invoke_frame:
    call invoke
    mov [r12 + 16], rax
    cmp qword ptr [r12], 0
    jne construction_result
    mov qword ptr [r12 + 24], 0
    cmp rax, WINDOW
    ja owner_reply
    mov [r12 + 24], rax
owner_reply:
    mov edi, 1
    lea rsi, [r12 + 16]
    mov edx, 16
    call write_exact
    mov rdx, [r12 + 24]
    test rdx, rdx
    jz frame_next
    mov edi, 1
    lea rsi, [r12 + DST]
    call write_exact
    jmp frame_next
construction_result:
    cmp rax, 64
    je frame_next
    cmp eax, RESOURCE
    je resource_failure
    jmp invalid
input_done:
    cmp qword ptr [r12], 0
    je success
    mov edi, 8
    call make_request
    call invoke
    cmp rax, 64
    jne invalid
publish_next:
    mov edi, 9
    call make_request
    call invoke
    cmp rax, 64
    jb invalid
    cmp rax, WINDOW
    ja invalid
    sub rax, 64
    mov [r12 + 64], rax
    test rax, rax
    jz publication_done
    mov rax, [r12 + DST + 32]
    mov [r12 + 48], rax
    mov rax, [r12 + DST + 40]
    mov [r12 + 56], rax
write_attempt:
    mov edi, 1
    lea rsi, [r12 + DST + 64]
    mov rdx, [r12 + 64]
    mov eax, 1
    syscall
    mov [r12 + 72], rax
    test rax, rax
    jle write_wait_or_fail
    mov edi, 10
    call make_request
    mov rax, [r12 + 48]
    mov [r12 + SRC + 24], rax
    mov rax, [r12 + 56]
    mov [r12 + SRC + 32], rax
    mov rax, [r12 + 72]
    mov [r12 + SRC + 40], rax
    call invoke
    mov [r12 + 88], rax
    call write_receipt
    cmp qword ptr [r12 + 88], 64
    jne invalid
    jmp publish_next
write_wait_or_fail:
    mov qword ptr [r12 + 88], -1
    call write_receipt
    mov rax, [r12 + 72]
    cmp rax, -4
    je write_attempt
    cmp rax, -11
    jne io_failure
    mov dword ptr [r12 + 128], 1
    mov dword ptr [r12 + 132], 4
wait_writable:
    lea rdi, [r12 + 128]
    mov esi, 1
    mov rdx, -1
    mov eax, 7
    syscall
    cmp rax, -4
    je wait_writable
    cmp rax, 1
    jne io_failure
    jmp write_attempt
publication_done:
    cmp qword ptr [r12 + DST + 24], 4
    jne invalid
    mov edi, 12
    call make_request
    call invoke
    cmp rax, 64
    jne invalid
    jmp success

/* Private mapping growth is only between image invocations. Source and output
 * are in the disjoint fixed transport mapping; no old arena pointer survives. */
invoke:
    lea rdi, [r12 + SRC]
    mov rsi, [r12 + 8]
    lea rdx, [r12 + DST]
    mov ecx, WINDOW
    mov r8, r14
    mov r9, r15
    sub rsp, 8
    call .Lowner_image
    add rsp, 8
    mov rdx, rax
    shr rdx, 32
    jnz invalid
    cmp eax, GROW
    je grow_arena
    cmp rax, 64
    jne invoke_return
    cmp qword ptr [r12 + SRC + 8], 1
    jne invoke_return
    mov qword ptr [r12 + 32], 0
invoke_return:
    ret
grow_arena:
    mov rax, 0x31304f5247505248
    cmp [r14 + 512], rax
    jne invalid
    mov rax, [r12 + 32]
    inc rax
    jz invalid
    cmp [r14 + 520], rax
    jne invalid
    cmp [r14 + 240], rax
    jne invalid
    mov [r12 + 32], rax
    mov rdx, [r14 + 528]
    cmp rdx, r15
    jbe invalid
    test rdx, rdx
    js resource_return
    mov [r12 + 96], rdx
    mov rdi, r14
    mov rsi, r15
    mov r10d, 1
    xor r8d, r8d
    mov eax, 25
    syscall
    cmp rax, -4095
    jae resource_return
    mov r14, rax
    mov r15, [r12 + 96]
    jmp invoke
resource_return:
    mov eax, RESOURCE
    ret

make_request:
    push rdi
    lea rdi, [r12 + SRC]
    mov ecx, 8
    xor eax, eax
    rep stosq
    pop rdi
    mov rax, 0x3130303051505248
    mov [r12 + SRC], rax
    mov [r12 + SRC + 8], rdi
    mov rax, [r14 + 8]
    mov [r12 + SRC + 16], rax
    mov qword ptr [r12 + 8], 64
    ret
write_receipt:
    mov rax, 0x314b434157505248
    mov [r12 + 1024], rax
    mov rax, [r14 + 8]
    mov [r12 + 1032], rax
    mov rax, [r12 + 48]
    mov [r12 + 1040], rax
    mov rax, [r12 + 56]
    mov [r12 + 1048], rax
    mov rax, [r12 + 64]
    mov [r12 + 1056], rax
    mov rax, [r12 + 72]
    mov [r12 + 1064], rax
    mov rax, [r14 + 144]
    mov [r12 + 1072], rax
    mov rax, [r12 + 88]
    mov [r12 + 1080], rax
    mov edi, 2
    lea rsi, [r12 + 1024]
    mov edx, 64
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
    xor r8d, r8d
read_again:
    xor eax, eax
    syscall
    cmp rax, -4
    je read_again
    test rax, rax
    js read_error
    jz read_eof
    add r8, rax
    add rsi, rax
    sub rdx, rax
    jnz read_again
    mov eax, 1
    ret
read_eof:
    test r8, r8
    jnz read_error
    xor eax, eax
    ret
read_error:
    mov eax, 2
    ret
write_exact:
    mov eax, 1
    syscall
    cmp rax, -4
    je write_exact
    test rax, rax
    jle io_failure
    add rsi, rax
    sub rdx, rax
    jnz write_exact
    ret
equal_string:
    mov al, [rdi]
    cmp al, [rsi]
    jne different
    inc rdi
    inc rsi
    test al, al
    jnz equal_string
    mov eax, 1
    ret
different:
    xor eax, eax
    ret
success:
    xor edi, edi
    jmp finish
invalid:
    mov edi, 2
    jmp finish
resource_failure:
    mov edi, 75
    jmp finish
io_failure:
    mov edi, 74
    jmp finish
usage:
    mov edi, 64
finish:
    mov eax, 60
    syscall
    ud2
owner_option: .asciz "--owner-fixture"
publish_option: .asciz "--publish-fixture"
.balign 16, 0
.Lowner_image:
    .byte 0
