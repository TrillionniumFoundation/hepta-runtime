"""Private fixture entry after the actual frozen configuration lifecycle."""

def replace(source,old,new):
    if source.count(old)!=1:raise ValueError('config fixture source anchor: '+old[:80])
    return source.replace(old,new,1)

def combine(adapter,fixture):
    adapter=replace(adapter,'_start:\n    cld\n','.type _start, @function\n_start:\n    add rsp, 8 /* HIA linker entry call. */\n    cld\n')
    adapter=replace(adapter,'    cmp qword ptr [rbx], 3\n    jne argv_fatal\n',
        '    call grow_config_auxv\n    cmp qword ptr [rbx], 1\n    je grow_config_absent\n    cmp qword ptr [rbx], 3\n    jne argv_fatal\n')
    adapter=replace(adapter,'    cmp qword ptr [rdx + 120], 0\n    je startup_completed\n',
        '    cmp qword ptr [rdx + 120], 0\n    je startup_completed\n    cmp qword ptr [rdx + 120], 4\n    je startup_completed\n')
    adapter=replace(adapter,'startup_completed:\n    test eax, eax\n    jz frame_next\n',
        'startup_completed:\n    test eax, eax\n    jz grow_fixture_start\n')
    fixture=replace(fixture,'.global _start\n.type _start, @function\n_start:\n    add rsp, 8\n',
        '.type grow_fixture_start, @function\ngrow_fixture_start:\n')
    fixture=replace(fixture,'    mov r12, rsp\n','    mov r12, rsp\n    mov [r12 + 248], r15 /* Actual installed config control. */\n')
    fixture=replace(fixture,'    xor esi, esi\n    call runtime_grow_create\n','    mov rsi, r15\n    call runtime_grow_create\n')
    fixture=replace(fixture,'grow_fixture_success:\n    xor edi, edi\n    mov eax, 60\n    syscall\n    ud2\n',
        'grow_fixture_success:\n    mov r15, [r12 + 248]\n    jmp frame_eof /* Actual HIA release of config filesystem leases. */\n')
    return adapter+'\n'+fixture+'\n'+HELPERS

HELPERS='''
/* The absent configuration is initialized by owner kind4, never synthesized. */
grow_config_absent:
    mov qword ptr [r15 + 24], 0
    mov rax, [r15 + 1024]
    add rax, [r15 + 1032]
    mov qword ptr [rax - 136], 4
    jmp owner_resume

/* Observe actual process AT_SECURE for the shared native I/O bridge. */
grow_config_auxv:
    mov qword ptr [r15 + 1144], 1
    mov rcx, [rbx]
    lea rcx, [rbx + rcx * 8 + 16]
grow_config_environment_end:
    mov rax, [rcx]
    add rcx, 8
    test rax, rax
    jnz grow_config_environment_end
grow_config_auxv_next:
    mov rax, [rcx]
    test rax, rax
    jz grow_config_auxv_done
    cmp rax, 23
    jne grow_config_auxv_advance
    mov rax, [rcx + 8]
    mov [r15 + 904], rax
grow_config_auxv_advance:
    add rcx, 16
    jmp grow_config_auxv_next
grow_config_auxv_done:
    ret
'''
