/* Actual FileLockState completions wake retained extract futures. The shared
 * HIA owner supplies the lease; this boundary neither polls nor creates a
 * completion. Host-private links live until actual terminal drain. The one
 * public event loop serializes every invocation of the shared HIA state. */
.intel_syntax noprefix
.section .text
.global runtime_lock_wake_record
.global runtime_extract_wait_link
.global runtime_extract_wait_unlink
.equ XW_HUB_HEAD,192
.equ XW_HUB_SEQUENCE,200
.equ XW_HUB_COUNT,208
.equ XW_LINKED,512
.equ XW_LEASE,520
.equ XW_READY,528
.equ XW_NEXT,536
.equ XW_NODE,544
.equ XW_WAKE_SEQUENCE,552
.equ XW_WAKE_OPERATION,560

/* rdi hub; rsi complete actual HRFLKR01. Only actual completed
 * cancel/unlock/drop transitions publish the HIA owner's reserved lease. */
runtime_lock_wake_record:
    test rdi,rdi
    jz xw_invalid
    mov rax,0x3142554842544c48
    cmp [rdi],rax
    jne xw_invalid
    test rsi,rsi
    jz xw_invalid
    mov rax,0x3130524b4c465248
    cmp [rsi],rax
    jne xw_invalid
    cmp qword ptr [rsi+16],0
    jne xw_success
    mov rdx,[rsi+56]
    test rdx,rdx
    jz xw_success
    mov rax,[rsi+8]
    cmp rax,4
    jb xw_invalid
    cmp rax,6
    ja xw_invalid
    inc qword ptr [rdi+XW_HUB_SEQUENCE]
    jz xw_invalid
    mov rcx,[rdi+XW_HUB_HEAD]
    mov r10,[rdi+XW_HUB_COUNT]
    xor r8d,r8d
xw_wake_next:
    test rcx,rcx
    jz xw_wake_complete
    test r10,r10
    jz xw_invalid
    dec r10
    cmp qword ptr [rcx+XW_LINKED],1
    jne xw_invalid
    cmp [rcx+80],rdi
    jne xw_invalid
    cmp [rcx+XW_LEASE],rdx
    jne xw_wake_advance
    test r8,r8
    jnz xw_invalid
    mov r8,rcx
    cmp qword ptr [rcx+XW_READY],0
    jne xw_invalid
    mov qword ptr [rcx+XW_READY],1
    mov r9,[rdi+XW_HUB_SEQUENCE]
    mov [rcx+XW_WAKE_SEQUENCE],r9
    mov [rcx+XW_WAKE_OPERATION],rax
xw_wake_advance:
    mov rcx,[rcx+XW_NEXT]
    jmp xw_wake_next
xw_wake_complete:
    test r10,r10
    jnz xw_invalid
    jmp xw_success

/* rdi actual callable context after its unchanged HIA lock WAIT. */
runtime_extract_wait_link:
    test rdi,rdi
    jz xw_invalid
    mov rax,0x3130494354584548
    cmp [rdi],rax
    jne xw_invalid
    cmp qword ptr [rdi+8],192
    jne xw_invalid
    mov eax,0xffffffdf
    cmp [rdi+128],rax
    jne xw_invalid
    mov rax,[rdi+136]
    or rax,[rdi+144]
    or rax,[rdi+160]
    jnz xw_invalid
    mov rcx,[rdi+152]
    test rcx,rcx
    jz xw_invalid
    mov rax,0x31304d4354584548
    cmp [rcx+192],rax
    jne xw_invalid
    cmp [rcx+1280],rdi
    jne xw_invalid
    cmp qword ptr [rcx+1320],1
    jne xw_invalid
    mov rcx,[rcx+256+8]
    test rcx,rcx
    jz xw_invalid
    cmp qword ptr [rcx+8],14
    jne xw_invalid
    mov rax,[rcx+48]
    or rax,[rcx+176]
    jnz xw_invalid
    mov rdx,[rcx+168]
    test rdx,rdx
    jz xw_invalid
    mov rsi,[rdi+80]
    test rsi,rsi
    jz xw_invalid
    mov rax,0x3142554842544c48
    cmp [rsi],rax
    jne xw_invalid
    cmp qword ptr [rdi+XW_LINKED],0
    je xw_link_new
    cmp qword ptr [rdi+XW_LINKED],1
    jne xw_invalid
    cmp [rdi+XW_LEASE],rdx
    jne xw_invalid
    cmp qword ptr [rdi+XW_READY],0
    jne xw_invalid
    jmp xw_success
xw_link_new:
    mov rax,[rdi+XW_LEASE]
    or rax,[rdi+XW_READY]
    or rax,[rdi+XW_NEXT]
    jnz xw_invalid
    mov rax,[rsi+XW_HUB_COUNT]
    inc rax
    jz xw_invalid
    mov [rsi+XW_HUB_COUNT],rax
    mov [rdi+XW_LEASE],rdx
    mov rax,[rsi+XW_HUB_HEAD]
    mov [rdi+XW_NEXT],rax
    mov [rsi+XW_HUB_HEAD],rdi
    mov qword ptr [rdi+XW_LINKED],1
    jmp xw_success

/* Only an actually drained terminal future may leave the wake list. */
runtime_extract_wait_unlink:
    test rdi,rdi
    jz xw_invalid
    cmp qword ptr [rdi+XW_LINKED],0
    je xw_unlinked
    cmp qword ptr [rdi+XW_LINKED],1
    jne xw_invalid
    cmp qword ptr [rdi+136],1
    jne xw_invalid
    cmp qword ptr [rdi+144],1
    jne xw_invalid
    cmp qword ptr [rdi+160],0
    jne xw_invalid
    mov rsi,[rdi+80]
    test rsi,rsi
    jz xw_invalid
    mov rax,0x3142554842544c48
    cmp [rsi],rax
    jne xw_invalid
    mov r8,rsi
    mov r9,[rsi+XW_HUB_COUNT]
    test r9,r9
    jz xw_invalid
    add rsi,XW_HUB_HEAD
xw_unlink_find:
    test r9,r9
    jz xw_invalid
    dec r9
    mov rcx,[rsi]
    test rcx,rcx
    jz xw_invalid
    cmp rcx,rdi
    je xw_unlink_found
    cmp qword ptr [rcx+XW_LINKED],1
    jne xw_invalid
    lea rsi,[rcx+XW_NEXT]
    jmp xw_unlink_find
xw_unlink_found:
    dec qword ptr [r8+XW_HUB_COUNT]
    mov rax,[rdi+XW_NEXT]
    mov [rsi],rax
    mov qword ptr [rdi+XW_LINKED],0
    mov qword ptr [rdi+XW_LEASE],0
    mov qword ptr [rdi+XW_READY],0
    mov qword ptr [rdi+XW_NEXT],0
    mov qword ptr [rdi+XW_NODE],0
xw_unlinked:
    mov rax,[rdi+XW_LEASE]
    or rax,[rdi+XW_READY]
    or rax,[rdi+XW_NEXT]
    jnz xw_invalid
xw_success:
    xor eax,eax
    ret
xw_invalid:
    mov eax,0xffffffff
    ret
