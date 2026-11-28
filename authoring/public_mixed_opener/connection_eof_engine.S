runtime_grow_connection_result:
    cmp qword ptr [rsp + 8],24
    jne runtime_grow_connection_regular
    mov rdx,[rsp]
    cmp qword ptr [rdx + 8],3
    jne runtime_grow_connection_regular
    cmp eax,32
    jb runtime_grow_bad
    mov rdx,0x3130464f45435248 /* HRCEOF01 fixed private EOF result. */
    cmp [r13],rdx
    jne runtime_grow_bad
    cmp qword ptr [r13 + 8],1
    ja runtime_grow_bad
    mov rdx,[r13 + 24]
    add rdx,32
    jc runtime_grow_bad
    cmp rax,rdx
    jne runtime_grow_bad
    cmp qword ptr [r13 + 8],0
    jne runtime_grow_connection_eof_error
    mov rdx,[r13 + 16]
    or rdx,[r13 + 24]
    jnz runtime_grow_bad
    jmp runtime_grow_extent_ready
runtime_grow_connection_eof_error:
    cmp qword ptr [r13 + 16],32
    jne runtime_grow_bad
    cmp qword ptr [r13 + 24],0
    je runtime_grow_bad
    jmp runtime_grow_extent_ready
runtime_grow_connection_regular:
