"""Trusted callable borrows into the exact config and publication dispatcher.

HIA retains config semantics, child calls, and the entire publisher lifecycle.
The public entry takes no external selectors. Old entries remain available.
"""
import hashlib

BASE_SHA='c4b99fafb1ff25f5b88093a07a29e0a601043db02d947b1e8aebfd4c5493b06f'

def replace(text,old,new):
    if text.count(old)!=1:raise ValueError('public bridge anchor differs: '+old[:100])
    return text.replace(old,new,1)

def combine(adapter,transport):
    if hashlib.sha256(adapter.encode()).hexdigest()!=BASE_SHA:
        raise ValueError('qualified configuration boundary differs')
    adapter=replace(adapter,'_start:\n    cld\n','.type _start, @function\n_start:\n    add rsp, 8 /* Actual HIA linker entry call. */\n    cld\n')
    adapter=replace(adapter,'    cmp qword ptr [rbx], 3\n    jne argv_fatal\n',
        '    call grow_config_auxv\n    cmp qword ptr [rbx], 1\n    je grow_config_absent\n    cmp qword ptr [rbx], 3\n    jne argv_fatal\n')
    adapter=replace(adapter,'    cmp qword ptr [rdx + 120], 0\n    je startup_completed\n',
        '    cmp qword ptr [rdx + 120], 0\n    je startup_completed\n    cmp qword ptr [rdx + 120], 4\n    je startup_completed\n')
    adapter=replace(adapter,'startup_completed:\n    test eax, eax\n    jz frame_next\n',
        'startup_completed:\n    test eax, eax\n    jz public_span_start\n')
    adapter=replace(adapter,'mcp_owner_completed:\n',
        'mcp_owner_completed:\n    cmp qword ptr [r15 + 784], 3\n    je runtime_config_query_return\n')
    adapter=replace(adapter,'    cmp qword ptr [r15 + 784], 0\n    jne cfg_resource /* Legacy MCP5 still owns its distinct output borrow. */\n',
        '    cmp qword ptr [r15 + 784], 3\n    je runtime_config_query_growth_return\n    cmp qword ptr [r15 + 784], 0\n    jne cfg_resource /* Legacy MCP5 still owns its distinct output borrow. */\n')
    adapter=replace(adapter,'    mov rbx, rsp\n    mov rax, 0x3130425550505248\n',
        '    mov rbx, rsp\n    mov qword ptr [rbx + 48], 0\n    mov qword ptr [rbx + 56], 3\n    mov rax, 0x3130425550505248\n')
    adapter=replace(adapter,'    mov [rbx + 32], rax\n    xor r12d, r12d\n',
        '    mov [rbx + 32], rax\npub_begin:\n    xor r12d, r12d\n')
    adapter=replace(adapter,'    mov eax, [rbx + 40]\n    add rsp, 64\n',
        '    mov eax, [rbx + 40]\n    mov edx, [rbx + 48]\n    add rsp, 64\n')
    adapter=replace(adapter,'    pop r15\n    test eax, eax\n    jnz pub_return_failure\n',
        '    pop r15\n    test edx, edx\n    jnz runtime_publication_span_return\n    test eax, eax\n    jnz pub_return_failure\n')
    adapter=replace(adapter,'    mov qword ptr [r15 + 872], 0\nmcp_value_completed:\n',
        '    mov qword ptr [r15 + 872], 0\n    cmp qword ptr [r15 + 912], 1\n    je runtime_execution_completed\nmcp_value_completed:\n')
    adapter=replace(adapter,"    mov qword ptr [r12 + PUB_SRC + 32], 3\n","    mov rax, [rbx + 56]\n    mov [r12 + PUB_SRC + 32], rax\n")
    adapter=replace(adapter,"    mov rsi, [rbx]\n    mov rcx, [rbx + 8]\n    mov edi, 13\n    call pub_import\n","    cmp qword ptr [rbx + 56], 3\n    jne pub_skip_trusted_prefix\n    mov rsi, [rbx]\n    mov rcx, [rbx + 8]\n    mov edi, 13\n    call pub_import\npub_skip_trusted_prefix:\n")
    adapter=replace(adapter,'finish_ok:\n    xor ebp, ebp\n','finish_ok:\n    mov ebp, dword ptr [r15 + CG_PUBLIC_EOF_EXIT]\n')
    return adapter+'\n'+CALLABLE+'\n'+transport+'\n'+HELPERS

CALLABLE=r'''
.global runtime_config_query
.global runtime_publication_span
.global runtime_publication_raw_span
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
    mov rax, [r15 + CG_OWNER]
    mov r9, [r15 + CG_OWNER + 8]
    test rax, rax
    jz runtime_config_query_bad
    cmp r9, 256
    jb runtime_config_query_bad
    mov [r15 + 832], rdi
    mov [r15 + 840], rsi
    mov [r15 + 848], rdx
    mov [r15 + 856], rcx
    mov qword ptr [r15 + 784], 3
    lea rax, [rax + r9 - 256]
    mov qword ptr [rax + 120], 1
    jmp owner_resume
runtime_config_query_return:
    cmp eax, 0xffff0000
    jae runtime_config_query_end
    mov qword ptr [r15 + CG_DELIVERY], 0
    jmp runtime_config_query_end
runtime_config_query_growth_return:
    /* Keep the completed child and HIA relocation state. The extra engine
     * owns this output mapping and retries the same request after growth. */
    mov eax, 0xffffffd0
runtime_config_query_end:
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
runtime_publication_raw_span:
    mov rdx, rdi
    mov rcx, rsi
    xor edi, edi
    xor esi, esi
    xor r8d, r8d
    xor r9d, r9d
    jmp runtime_publication_common
runtime_publication_span:
    mov r9d, 3
runtime_publication_common:
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
    mov [rbx + 56], r9
    jmp pub_begin
runtime_publication_span_invalid:
    mov eax, 2
runtime_publication_span_return:
    ret
'''

HELPERS = '\n/* The absent configuration is initialized by owner kind4, never synthesized. */\ngrow_config_absent:\n    mov qword ptr [r15 + 24], 0\n    mov rax, [r15 + CG_OWNER]\n    add rax, [r15 + CG_OWNER + 8]\n    sub rax, 256\n    mov qword ptr [rax + 120], 4\n    jmp owner_resume\n\n/* Observe actual process AT_SECURE for the shared native I/O bridge. */\ngrow_config_auxv:\n    mov rcx, [rbx]\n    lea rcx, [rbx + rcx * 8 + 16]\ngrow_config_environment_end:\n    mov rax, [rcx]\n    add rcx, 8\n    test rax, rax\n    jnz grow_config_environment_end\ngrow_config_auxv_next:\n    mov rax, [rcx]\n    test rax, rax\n    jz grow_config_auxv_done\n    cmp rax, 23\n    jne grow_config_auxv_advance\n    mov rax, [rcx + 8]\n    mov [r15 + 904], rax\ngrow_config_auxv_advance:\n    add rcx, 16\n    jmp grow_config_auxv_next\ngrow_config_auxv_done:\n    ret\n'
