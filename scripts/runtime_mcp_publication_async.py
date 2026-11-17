"""Retain the qualified publisher across an actual nonblocking EAGAIN.

The existing HIA CREATE/import/START/PULL/write/ACK/DROP sequence is retained.
No buffer is acknowledged before the actual positive write result. The private
context is host-owned storage, never a public input or externally chosen pointer.
"""


def combine_async(text):
    def replace(before, after):
        nonlocal text
        if text.count(before) != 1:
            raise ValueError('async publication anchor differs: ' + before[:100])
        text = text.replace(before, after, 1)

    replace('pub_restore:\n    mov rsp, rbx\n',
        'pub_restore:\n    cmp qword ptr [rbx + 48], 2\n'
        '    je pub_async_finished\n    mov rsp, rbx\n')
    replace('pub_fail_io:\n    mov ebp, 74\n',
        'pub_fail_io:\n    cmp qword ptr [rbx + 48], 2\n'
        '    je pub_async_cancel_io\n    mov ebp, 74\n')
    replace('    cmp rax, -11\n    jne pub_fail_io\n    mov dword ptr [r12 + 128], 1\n',
        '    cmp rax, -11\n    jne pub_fail_io\n'
        '    cmp qword ptr [rbx + 48], 2\n    je pub_async_suspend\n'
        '    mov dword ptr [r12 + 128], 1\n')
    return text + '\n' + ASYNC


ASYNC = r'''
/* Private 128-byte context. First 64 bytes retain the original publisher
 * argument/return layout. 64=magic,72=transport,80=work,88=capacity,
 * 96=phase(0 fresh/1 suspended/2 settled),104/112 reserved,120=entry stack.
 * The stack is retained only during one synchronous invocation, never while
 * suspended. No pointer to a suspended native stack escapes this function. */
.global runtime_publication_async_start
.global runtime_publication_async_resume
.global runtime_publication_async_abort
.macro PUB_ASYNC_SAVE
    push r15
    push r14
    push r13
    push r12
    push rbx
    push rbp
    sub rsp, 8
    mov rbx, rdi
    mov [rbx + 120], rsp
.endm
runtime_publication_async_start:
    PUB_ASYNC_SAVE
    mov rax, 0x3130434155505248 /* HRPUAC01 */
    cmp [rbx + 64], rax
    jne pub_async_bad
    cmp qword ptr [rbx + 96], 0
    jne pub_async_bad
    mov rax, [rbx + 72]
    or rax, [rbx + 80]
    or rax, [rbx + 88]
    or rax, [rbx + 104]
    or rax, [rbx + 112]
    jnz pub_async_bad
    cmp qword ptr [rbx + 32], 1
    ja pub_async_bad
    cmp qword ptr [rbx + 48], 2
    jne pub_async_bad
    mov rax, [rbx + 56]
    test rax, rax
    jz pub_async_start_ready
    cmp rax, 3
    jne pub_async_bad
pub_async_start_ready:
    jmp pub_begin
runtime_publication_async_resume:
    PUB_ASYNC_SAVE
    call pub_async_load
    test eax, eax
    jnz pub_async_restore
    jmp pub_write_attempt
runtime_publication_async_abort:
    PUB_ASYNC_SAVE
    call pub_async_load
    test eax, eax
    jnz pub_async_restore
    jmp pub_async_cancel_io
pub_async_load:
    mov rax, 0x3130434155505248
    cmp [rbx + 64], rax
    jne pub_async_load_bad
    cmp qword ptr [rbx + 48], 2
    jne pub_async_load_bad
    cmp qword ptr [rbx + 96], 1
    jne pub_async_load_bad
    mov r12, [rbx + 72]
    mov r14, [rbx + 80]
    mov r15, [rbx + 88]
    test r12, r12
    jz pub_async_load_bad
    test r14, r14
    jz pub_async_load_bad
    cmp r15, 131072
    jb pub_async_load_bad
    xor eax, eax
    ret
pub_async_load_bad:
    mov eax, 2
    ret
pub_async_suspend:
    mov [rbx + 72], r12
    mov [rbx + 80], r14
    mov [rbx + 88], r15
    mov qword ptr [rbx + 96], 1
    mov eax, 1
    jmp pub_async_restore
pub_async_cancel_io:
    /* A write syscall has returned, so no OS borrow remains. The HIA owner
     * receives actual cancellation before the physical storage is retired. */
    test r12, r12
    jz pub_async_io_release
    test r14, r14
    jz pub_async_io_release
    cmp qword ptr [r14 + 8], 0
    je pub_async_io_release
    /* CANCEL11 and DROP12 are alternative terminal operations. The actual
     * owner reaches phase5 after CANCEL; a second DROP is correctly refused.
     * Preserve the genuine I/O failure after one accepted terminal effect. */
    mov edi, 11
    call pub_make_request
    call pub_invoke
    cmp rax, 64
    jne pub_fail_invalid
pub_async_io_release:
    mov ebp, 74
    jmp pub_release
pub_async_finished:
    mov qword ptr [rbx + 72], 0
    mov qword ptr [rbx + 80], 0
    mov qword ptr [rbx + 88], 0
    mov qword ptr [rbx + 96], 2
    mov eax, [rbx + 40]
    jmp pub_async_restore
pub_async_bad:
    mov eax, 2
pub_async_restore:
    mov rsp, [rbx + 120]
    mov qword ptr [rbx + 120], 0
    add rsp, 8
    pop rbp
    pop rbx
    pop r12
    pop r13
    pop r14
    pop r15
    ret
'''
