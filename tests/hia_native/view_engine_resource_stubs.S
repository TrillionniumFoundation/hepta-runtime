/* Test-only callable wrappers. These are not native HIA implementations. */
.intel_syntax noprefix
.section .text
.global resource_initialization_stub
.global resource_unexpected_stub
.global resource_destroy_fixture
.global view_read_invoke
.global view_key_invoke
.global view_scope_invoke
resource_initialization_stub:
    cmp rsi, 16
    jne resource_unexpected_stub
    mov rax, 0x313030494c435648
    cmp [rdi], rax
    jne resource_unexpected_stub
    cmp qword ptr [rdi + 8], 1
    jne resource_unexpected_stub
    cmp rcx, 16777216
    jne resource_unexpected_stub
    cmp r9, 131072
    jne resource_unexpected_stub
    inc qword ptr [rip + resource_stub_initializations]
    mov eax, 32
    ret
view_read_invoke:
view_key_invoke:
view_scope_invoke:
resource_unexpected_stub:
    inc qword ptr [rip + resource_stub_unexpected]
    mov eax, 0xffffffff
    ret
resource_destroy_fixture:
    push r15
    mov r15, rdi
    call view_engine_destroy
    pop r15
    ret
.section .bss
.balign 8
.global resource_stub_initializations
.global resource_stub_unexpected
resource_stub_initializations:
    .quad 0
resource_stub_unexpected:
    .quad 0
.section .note.GNU-stack,"",@progbits
