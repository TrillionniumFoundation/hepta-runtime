/* Test-only entry bridge. The real engine, allocator and fixed consumers are retained. */
.intel_syntax noprefix
.section .text
.global _start
_start:
    mov edi,71
    mov eax,231
    syscall
    ud2
.global fixture_invoke
fixture_invoke:
    push r15
    mov r15,rdi
    mov r8,rsi
    mov rdi,rdx
    mov rsi,rcx
    call runtime_grow_owned
    pop r15
    ret
.global fixture_destroy
fixture_destroy:
    push r15
    mov r15,rdi
    call runtime_grow_destroy
    pop r15
    ret
.global fixture_detach
fixture_detach:
    push r15
    mov r15,rdi
    mov rdi,rsi
    call pump_detach_frontend
    pop r15
    ret
.global fixture_restore
fixture_restore:
    push r15
    mov r15,rdi
    mov rdi,rsi
    call pump_restore_frontend
    pop r15
    ret
/* These independently qualified capabilities are outside this storage fixture.
 * No application capability receives a synthetic successful implementation. */
.global runtime_authority_create
.global runtime_authority_release
.global pump_trace_detached
.global pump_trace_restored
runtime_authority_create:
runtime_authority_release:
pump_trace_detached:
pump_trace_restored:
    xor eax,eax
    ret
.section .note.GNU-stack,"",@progbits
