/* Diagnostic CI prefix only. All registers and callable result are preserved. */
.section .text
extract_diagnostic_terminal:
    push rax
    push rcx
    push rdx
    push rdi
    push rsi
    push r8
    push r9
    push r10
    push r11
    lea rsi, [rip + extract_diagnostic_header]
    mov edx, 80
    call extract_diagnostic_span
    mov rsi, r12
    mov edx, 192
    call extract_diagnostic_span
    lea rsi, [r12 + 256]
    mov edx, 256
    call extract_diagnostic_span
    mov rax, [r15 + 8]
    mov rsi, [rax + 61*64 + 8]
    mov edx, 512
    call extract_diagnostic_span
    mov rax, [r15 + 16]
    mov rax, [rax + 8]
    mov rsi, [rax + 6*64 + 24]
    mov edx, 64
    call extract_diagnostic_span
    mov rax, [r15 + 16]
    mov rax, [rax + 8]
    mov rsi, [rax + 6*64 + 8]
    mov edx, 256
    call extract_diagnostic_span
    mov rax, [r15 + 400]
    mov rsi, [rax + 64 + 8]
    mov edx, 256
    call extract_diagnostic_span
    mov rax, [r15 + 400]
    mov rsi, [rax + 128 + 8]
    mov edx, 256
    call extract_diagnostic_span
    mov rsi, [r12 + 152]
    mov edx, 2048
    call extract_diagnostic_span
    mov rax, [r12 + 152]
    xor esi, esi
    test rax, rax
    jz extract_diagnostic_no_owner
    mov rsi, [rax + 264]
extract_diagnostic_no_owner:
    mov edx, 512
    call extract_diagnostic_span
    pop r11
    pop r10
    pop r9
    pop r8
    pop rsi
    pop rdi
    pop rdx
    pop rcx
    pop rax
    ret
extract_diagnostic_span:
    test rsi, rsi
    jnz extract_diagnostic_span_ready
    lea rsi, [rip + extract_diagnostic_absent]
extract_diagnostic_span_ready:
    mov edi, 2
    jmp view_write_all
.balign 8
extract_diagnostic_header:
    .ascii "RXDIAG01"
    .quad 192,256,512,64,256,256,256,2048,512
extract_diagnostic_absent:
    .zero 2048
