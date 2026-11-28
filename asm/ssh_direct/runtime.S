/* Runtime extensions to the unchanged five HIA policies and retained owner.
 * No caller-selected PID, executable, thread, final Entry or result is accepted.
 * Only the process event-loop may install notifications or destroy the instance.
 */
.intel_syntax noprefix
.section .text
.equ C_RUNTIME_WAKE, 912
.equ C_RUNTIME_ERROR, 920
.equ C_RUNTIME_DESTROY_ERROR, 928

/* Existing whole method bodies are retained under explicit inner labels.
 * The only added effect is a wake after the real terminal publication. */
ssh_finish_request:
    push r12
    mov r12,rdi
    call ssh_finish_request_runtime_inner
    mov rdi,[r12+R_CTX]
    call ssh_runtime_owner_notify
    pop r12
    ret
ssh_quarantine:
    push r12
    mov r12,rdi
    call ssh_quarantine_runtime_inner
    mov rdi,[r12+R_CTX]
    call ssh_runtime_owner_notify
    pop r12
    ret
ssh_join_notify:
    push r12
    mov r12,rdi
    call ssh_join_notify_runtime_inner
    mov rdi,r12
    call ssh_runtime_owner_notify
    pop r12
    ret

ssh_direct_owner_set_wake:
    push r12
    push r13
    sub rsp,8
    mov r12,rdi
    mov r13,rsi
    call ssh_identity
    test rax,rax
    js .Lruntime_set_return
    cmp r13,3
    jb .Lruntime_set_bad
    cmp r13,2147483647
    ja .Lruntime_set_bad
    cmp qword ptr [r12+C_RUNTIME_WAKE],0
    jne .Lruntime_set_bad
    cmp qword ptr [r12+C_ALLOCATED],0
    jne .Lruntime_set_bad
    cmp qword ptr [r12+C_FROZEN],0
    jne .Lruntime_set_bad
    inc r13
    mov [r12+C_RUNTIME_WAKE],r13
    xor eax,eax
    jmp .Lruntime_set_return
.Lruntime_set_bad:
    mov rax,-22
.Lruntime_set_return:
    add rsp,8
    pop r13
    pop r12
    ret

ssh_runtime_owner_notify:
    push r12
    sub rsp,16
    mov r12,rdi
    mov rax,[r12+C_RUNTIME_WAKE]
    test rax,rax
    jz .Lruntime_notify_return
    dec rax
    mov [rsp+8],rax
    mov qword ptr [rsp],1
.Lruntime_notify_write:
    mov rdi,[rsp+8]
    mov rsi,rsp
    mov edx,8
    mov eax,1
    syscall
    cmp rax,-4
    je .Lruntime_notify_write
    cmp rax,8
    je .Lruntime_notify_return
    cmp rax,-11
    je .Lruntime_notify_return
    mov qword ptr [r12+C_RUNTIME_ERROR],5
.Lruntime_notify_return:
    add rsp,16
    pop r12
    ret

/* Nonblocking final destruction. Caller first performs the original persistent
 * shutdown; a pending real join returns 1. Unknown/failed joins retain all
 * custody. The serialized outer API supplies the final borrow exclusion. */
ssh_direct_owner_destroy:
    push r12
    push r13
    sub rsp,8
    mov r12,rdi
    call ssh_identity
    test rax,rax
    js .Lruntime_destroy_return
    mov rax,[r12+C_RUNTIME_DESTROY_ERROR]
    test rax,rax
    jnz .Lruntime_destroy_return
    cmp qword ptr [r12+C_FROZEN],1
    jne .Lruntime_destroy_busy
    cmp qword ptr [r12+C_JOIN_START],1
    jne .Lruntime_destroy_busy
    call ssh_direct_join_result
    test rax,rax
    jnz .Lruntime_destroy_return
    cmp dword ptr [r12+C_TID],0
    jne .Lruntime_destroy_busy
    cmp dword ptr [r12+C_JOIN_TID],0
    jne .Lruntime_destroy_busy
    cmp qword ptr [r12+C_OWNER_DONE],1
    jne .Lruntime_destroy_invalid
    mov rax,[r12+C_ERROR]
    or rax,[r12+C_JOIN_ERROR]
    or rax,[r12+C_RUNTIME_ERROR]
    or rax,[r12+C_QUEUE_HEAD]
    or rax,[r12+C_QUEUE_TAIL]
    or rax,[r12+C_ACTIVE]
    or rax,[r12+C_DRAIN]
    or rax,[r12+C_QUARANTINED]
    or rax,[r12+C_STACK]
    or rax,[r12+C_STACK_CAP]
    or rax,[r12+C_CORE+64]
    or rax,[r12+C_CORE+72]
    or rax,[r12+C_CORE+80]
    jnz .Lruntime_destroy_invalid
    cmp dword ptr [r12+C_CORE+4],0
    jne .Lruntime_destroy_busy
    cmp dword ptr [r12+C_CORE],0
    jne .Lruntime_destroy_busy
    cmp dword ptr [r12+C_QUEUE_LOCK],0
    jne .Lruntime_destroy_busy
    mov rax,[r12+C_ALLOCATED]
    cmp rax,[r12+C_FREED]
    jne .Lruntime_destroy_busy
    mov rdi,[r12+C_WAKE]
    mov qword ptr [r12+C_WAKE],-1
    mov eax,3
    syscall
    test rax,rax
    jnz .Lruntime_destroy_failed
    mov qword ptr [r12+C_RUNTIME_WAKE],0
    mov rdi,[r12+C_JOIN_STACK]
    mov rsi,[r12+C_JOIN_CAP]
    call ssh_free
    test rax,rax
    jnz .Lruntime_destroy_failed
    mov qword ptr [r12+C_JOIN_STACK],0
    mov qword ptr [r12+C_JOIN_CAP],0
    mov rdi,[r12+C_CORE+24]
    mov rsi,[r12+C_CORE+32]
    call ssh_free
    test rax,rax
    jnz .Lruntime_destroy_failed
    mov qword ptr [r12+C_CORE+24],0
    mov qword ptr [r12+C_CORE+32],0
    mov rdi,r12
    mov esi,4096
    call ssh_free
    jmp .Lruntime_destroy_return
.Lruntime_destroy_failed:
    mov [r12+C_RUNTIME_DESTROY_ERROR],rax
    jmp .Lruntime_destroy_return
.Lruntime_destroy_invalid:
    mov rax,-71
    jmp .Lruntime_destroy_return
.Lruntime_destroy_busy:
    mov eax,1
.Lruntime_destroy_return:
    add rsp,8
    pop r13
    pop r12
    ret

/* Immutable image table patched by the actually executed HIA image packer. */
ssh_hia_child:
    jmp qword ptr [rip+runtime_ssh_images]
ssh_hia_admission:
    jmp qword ptr [rip+runtime_ssh_images+8]
ssh_hia_core:
    jmp qword ptr [rip+runtime_ssh_images+16]
ssh_hia_io:
    jmp qword ptr [rip+runtime_ssh_images+24]
ssh_hia_future:
    jmp qword ptr [rip+runtime_ssh_images+32]
