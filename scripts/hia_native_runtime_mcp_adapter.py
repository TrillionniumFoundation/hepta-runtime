"""Trusted callable borrows into the exact config and publication dispatcher.

HIA retains config semantics, child calls, and the entire publisher lifecycle.
The public entry takes no external selectors. Old entries remain available.
"""
import hashlib

BASE_SHA='f6bd57471e25621547786f76da2e076f37d0e375d2d25bd009e5575b17d8ba54'

def replace(text,old,new):
    if text.count(old)!=1:raise ValueError('public bridge anchor differs: '+old[:100])
    return text.replace(old,new,1)

def combine(adapter,transport):
    if hashlib.sha256(adapter.encode()).hexdigest()!=BASE_SHA:
        raise ValueError('qualified configuration boundary differs')
    adapter=replace(adapter,'_start:\n    cld\n','.type _start, @function\n_start:\n    add rsp, 8 /* Actual HIA linker entry call. */\n    cld\n')
    adapter=replace(adapter,'    cmp qword ptr [rbx], 3\n    jne argv_fatal\n',
        '    call grow_config_auxv\n    cmp qword ptr [rbx], 1\n    je grow_config_absent\n    cmp qword ptr [rbx], 3\n    jne argv_fatal\n')
    adapter=replace(adapter,'    cmp qword ptr [r14 + FOOTER + 120], 0\n    je startup_completed\n',
        '    cmp qword ptr [r14 + FOOTER + 120], 0\n    je startup_completed\n    cmp qword ptr [r14 + FOOTER + 120], 4\n    je startup_completed\n')
    adapter=replace(adapter,'startup_completed:\n    test eax, eax\n    jz frame_next\n',
        'startup_completed:\n    test eax, eax\n    jz public_span_start\n')
    adapter=replace(adapter,'mcp_owner_completed:\n',
        'mcp_owner_completed:\n    cmp qword ptr [r15 + 784], 3\n    je runtime_config_query_return\n')
    adapter=replace(adapter,'    mov rbx, rsp\n    mov rax, 0x3130425550505248\n',
        '    mov rbx, rsp\n    mov qword ptr [rbx + 48], 0\n    mov rax, 0x3130425550505248\n')
    adapter=replace(adapter,'    mov [rbx + 32], rax\n    xor r12d, r12d\n',
        '    mov [rbx + 32], rax\npub_begin:\n    xor r12d, r12d\n')
    adapter=replace(adapter,'    mov eax, [rbx + 40]\n    add rsp, 64\n',
        '    mov eax, [rbx + 40]\n    mov edx, [rbx + 48]\n    add rsp, 64\n')
    adapter=replace(adapter,'    pop r15\n    test eax, eax\n    jnz pub_return_failure\n',
        '    pop r15\n    test edx, edx\n    jnz runtime_publication_span_return\n    test eax, eax\n    jnz pub_return_failure\n')
    adapter=replace(adapter,'    mov qword ptr [r15 + 872], 0\nmcp_value_completed:\n',
        '    mov qword ptr [r15 + 872], 0\n    cmp qword ptr [r15 + 912], 1\n    je runtime_execution_completed\nmcp_value_completed:\n')
    return adapter+'\n'+CALLABLE+'\n'+transport+'\n'+HELPERS

CALLABLE=r'''
.global runtime_config_query
.global runtime_publication_span
/* HIA entry ABI, r15=extra engine. The installed owner keeps its own state;
 * the existing dispatcher executes its actual child calls and effects. */
runtime_config_query:
    push rbp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub rsp, 8
    mov r15, [r15 + 24]
    test r15, r15
    jz runtime_config_query_bad
    cmp qword ptr [r15 + 784], 0
    jne runtime_config_query_bad
    cmp qword ptr [r15 + 872], 0
    jne runtime_config_query_bad
    mov [r15 + 832], rdi
    mov [r15 + 840], rsi
    mov [r15 + 848], rdx
    mov [r15 + 856], rcx
    mov qword ptr [r15 + 784], 3
    mov qword ptr [r15 + ROOT_WORK + FOOTER + 120], 1
    jmp owner_resume
runtime_config_query_return:
    mov qword ptr [r15 + 784], 0
    jmp runtime_config_query_restore
runtime_config_query_bad:
    mov eax, 0xffffffff
runtime_config_query_restore:
    add rsp, 8
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret

/* Trusted spans are inside the admitted frontend output descriptor.
 * Both are fully imported before HIA START. No frontend pointer is used by
 * PULL/write/ACK. Return 0/2/74/75; the caller appends framing LF. */
runtime_publication_span:
    cmp r8, 1
    ja runtime_publication_span_invalid
    mov rax, rdi
    add rax, rsi
    jc runtime_publication_span_invalid
    mov rax, rdx
    add rax, rcx
    jc runtime_publication_span_invalid
    push r15
    push r14
    push r13
    push r12
    push rbx
    push rbp
    sub rsp, 64
    mov rbx, rsp
    mov [rbx], rdi
    mov [rbx + 8], rsi
    mov [rbx + 16], rdx
    mov [rbx + 24], rcx
    mov [rbx + 32], r8
    mov qword ptr [rbx + 48], 1
    jmp pub_begin
runtime_publication_span_invalid:
    mov eax, 2
runtime_publication_span_return:
    ret
'''

HELPERS = '\n/* The absent configuration is initialized by owner kind4, never synthesized. */\ngrow_config_absent:\n    mov qword ptr [r15 + 24], 0\n    mov qword ptr [r15 + ROOT_WORK + FOOTER + 120], 4\n    jmp owner_resume\n\n/* Observe actual process AT_SECURE for the shared native I/O bridge. */\ngrow_config_auxv:\n    mov rcx, [rbx]\n    lea rcx, [rbx + rcx * 8 + 16]\ngrow_config_environment_end:\n    mov rax, [rcx]\n    add rcx, 8\n    test rax, rax\n    jnz grow_config_environment_end\ngrow_config_auxv_next:\n    mov rax, [rcx]\n    test rax, rax\n    jz grow_config_auxv_done\n    cmp rax, 23\n    jne grow_config_auxv_advance\n    mov rax, [rcx + 8]\n    mov [r15 + 904], rax\ngrow_config_auxv_advance:\n    add rcx, 16\n    jmp grow_config_auxv_next\ngrow_config_auxv_done:\n    ret\n'
