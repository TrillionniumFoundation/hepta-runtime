/* Fixed private process fence hub. The installed configuration control block
 * is borrowed only through its existing owner; no config offsets are claimed.
 * A session binds this hub during trusted startup, never through protocol JSON.
 * HIA slot27 owns admission order and tokens; slot28 only executes the original
 * five-image lifecycle and lends its current output until the parent copies it. */
.intel_syntax noprefix
.section .text
.global runtime_filesystem_hub_create
.global runtime_filesystem_hub_bind
.global runtime_filesystem_hub_destroy
.global runtime_filesystem_install_fence
.global runtime_grow_fence_owned
.global runtime_grow_fence_release

/* rdi is the original kernel environment vector. */
runtime_filesystem_hub_create:
    push rbp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub rsp, 24
    mov r12, rdi
    mov edi, 4096
    call view_allocate
    cmp rax, -4095
    jae fs_hub_create_done
    mov r13, rax
    mov rax, 0x3230425548534648 /* HFSHUB02 */
    mov [r13], rax
    xor r14d, r14d
    lea rdi, [rip + fs_fence_env_root]
    mov rsi, r12
    call fs_fence_environment
    mov [r13 + 128], rax
    mov [r13 + 136], rdx
    test rax, rax
    jz fs_hub_env_owner
    or r14d, 1
fs_hub_env_owner:
    lea rdi, [rip + fs_fence_env_owner]
    mov rsi, r12
    call fs_fence_environment
    mov [r13 + 144], rax
    mov [r13 + 152], rdx
    test rax, rax
    jz fs_hub_env_required
    or r14d, 2
fs_hub_env_required:
    lea rdi, [rip + fs_fence_env_required]
    mov rsi, r12
    call fs_fence_environment
    mov [r13 + 160], rax
    mov [r13 + 168], rdx
    test rax, rax
    jz fs_hub_env_sized
    or r14d, 4
fs_hub_env_sized:
    mov rax, 48
    add rax, [r13 + 136]
    jc fs_hub_create_overflow
    add rax, [r13 + 152]
    jc fs_hub_create_overflow
    add rax, [r13 + 168]
    jc fs_hub_create_overflow
    mov [r13 + 24], rax
    add rax, 4095
    jc fs_hub_create_overflow
    and rax, -4096
    test rax, rax
    jle fs_hub_create_overflow
    mov [r13 + 32], rax
    mov rdi, rax
    call view_allocate
    cmp rax, -4095
    jae fs_hub_create_failed
    mov [r13 + 16], rax
    mov rdi, rax
    mov rax, 0x32304e4946534648 /* HFSFIN02 */
    mov [rdi], rax
    mov [rdi + 8], r14
    mov rax, [r13 + 136]
    mov [rdi + 16], rax
    mov rax, [r13 + 152]
    mov [rdi + 24], rax
    mov rax, [r13 + 168]
    mov [rdi + 32], rax
    mov qword ptr [rdi + 40], 0
    add rdi, 48
    mov rsi, [r13 + 128]
    mov rcx, [r13 + 136]
    rep movsb
    mov rsi, [r13 + 144]
    mov rcx, [r13 + 152]
    rep movsb
    mov rsi, [r13 + 160]
    mov rcx, [r13 + 168]
    rep movsb
    lea rdi, [r13 + 128]
    xor eax, eax
    mov ecx, 6
    rep stosq
    mov rax, r13
    jmp fs_hub_create_done
fs_hub_create_overflow:
    mov rax, -12
fs_hub_create_failed:
    mov r14, rax
    mov rdi, r13
    mov esi, 8192
    mov eax, 11
    syscall
    mov rax, r14
fs_hub_create_done:
    add rsp, 24
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret

/* Byte capture, without required/UTF-8/owner semantic interpretation. */
fs_fence_environment:
    mov r8, rsi
    mov r9, rdi
fs_fence_env_next:
    mov rsi, [r8]
    test rsi, rsi
    jz fs_fence_env_absent
    xor ecx, ecx
fs_fence_env_compare:
    mov al, [r9 + rcx]
    test al, al
    jz fs_fence_env_equals
    cmp al, [rsi + rcx]
    jne fs_fence_env_advance
    inc rcx
    jmp fs_fence_env_compare
fs_fence_env_equals:
    cmp byte ptr [rsi + rcx], 61
    jne fs_fence_env_advance
    lea rax, [rsi + rcx + 1]
    xor edx, edx
fs_fence_env_length:
    cmp byte ptr [rax + rdx], 0
    je fs_fence_env_return
    inc rdx
    jmp fs_fence_env_length
fs_fence_env_advance:
    add r8, 8
    jmp fs_fence_env_next
fs_fence_env_absent:
    xor eax, eax
    xor edx, edx
fs_fence_env_return:
    ret

/* r15 fixed session engine, rdi fixed hub. Installed config must be identical. */
runtime_filesystem_hub_bind:
    mov rax, 0x3230425548534648
    cmp [rdi], rax
    jne fs_hub_invalid
    cmp qword ptr [rdi + 56], 0
    jne fs_hub_invalid
    cmp qword ptr [r15 + 224], 0
    jne fs_hub_invalid
    cmp qword ptr [rdi + 40], -1
    je fs_hub_invalid
    mov rax, [r15 + 24]
    cmp qword ptr [rdi + 40], 0
    je fs_hub_bind_first
    cmp [rdi + 64], rax
    jne fs_hub_invalid
    jmp fs_hub_bind_admitted
fs_hub_bind_first:
    mov [rdi + 64], rax
fs_hub_bind_admitted:
    inc qword ptr [rdi + 40]
    mov [r15 + 224], rdi
    xor eax, eax
    ret
fs_hub_invalid:
    mov eax, 0xffffffff
    ret

/* All session references have ended before the process owner destroys hub. */
runtime_filesystem_hub_destroy:
    push rbx
    mov rax, 0x3230425548534648
    cmp [rdi], rax
    jne fs_hub_destroy_invalid
    mov rax, [rdi + 8]
    or rax, [rdi + 40]
    jnz fs_hub_destroy_invalid
    mov rbx, rdi
    mov rdi, [rbx + 16]
    mov rsi, [rbx + 32]
    add rsi, 4096
    mov eax, 11
    syscall
    test rax, rax
    jnz fs_hub_destroy_done
    mov rdi, rbx
    mov esi, 8192
    mov eax, 11
    syscall
    jmp fs_hub_destroy_done
fs_hub_destroy_invalid:
    mov eax, 0xffffffff
fs_hub_destroy_done:
    pop rbx
    ret

/* This runs on slot27's ordinary retry loop, so a real INIT growth result is
 * handled by the same allocation/retry boundary as a request growth result. */
runtime_filesystem_install_fence:
    push r12
    sub rsp, 16
    mov r12, [r15 + 224]
    test r12, r12
    jz fs_install_fence_invalid
    mov rax, 0x3230425548534648
    cmp [r12], rax
    jne fs_install_fence_invalid
    cmp qword ptr [r12 + 40], 0
    je fs_install_fence_invalid
    mov rdi, [r12 + 16]
    mov rsi, [r12 + 24]
    mov rdx, [rbx + 32]
    mov rcx, [rbx + 40]
    mov r8, [rbx + 8]
    mov r9, [rbx + 16]
    inc qword ptr [r15 + 128]
    call qword ptr [rbx]
    mov edi, 1
    call runtime_grow_trace
    cmp rax, 48
    jne fs_install_fence_done
    mov rdx, [rbx + 32]
    mov rax, 0x3230524546534648 /* HFSFER02 */
    cmp [rdx], rax
    jne fs_install_fence_invalid
    cmp qword ptr [rdx + 8], 3
    jne fs_install_fence_invalid
    mov rax, [rdx + 16]
    or rax, [rdx + 24]
    or rax, [rdx + 32]
    or rax, [rdx + 40]
    jnz fs_install_fence_invalid
    mov qword ptr [r15 + 232], 1
    xor eax, eax
    jmp fs_install_fence_done
fs_install_fence_invalid:
    mov eax, 0xffffffff
fs_install_fence_done:
    add rsp, 16
    pop r12
    ret

/* No application decision is made here: complete private native frames only. */
runtime_grow_fence_owned:
    push rbp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub rsp, 56
    mov r12, rdi
    mov r13, rsi
    mov r14, r15
    mov rbx, [r15 + 8]
    add rbx, 28 * 64
    mov ebp, 28
    lea rdx, [r15 + 512 + 28 * 64]
    cmp qword ptr [rdx], 0
    jne fs_fence_early_invalid
    cmp qword ptr [rdx + 8], 0
    jne fs_fence_early_invalid
    mov qword ptr [rdx], 1
    mov [rsp + 8], rdx
    mov qword ptr [rsp + 16], 0
    mov qword ptr [rsp + 24], 0
    mov qword ptr [rbx + 48], 0
    mov qword ptr [rbx + 56], 0
    mov rdx, [r14 + 224]
    test rdx, rdx
    jz fs_fence_invalid
    mov rax, 0x3230425548534648
    cmp [rdx], rax
    jne fs_fence_invalid
    mov [rsp], rdx
    cmp r13, 8
    jb fs_fence_invalid
    mov rax, 0x3130474643464648 /* HFFCFG01 */
    cmp [r12], rax
    je fs_fence_configure
    mov rax, 0x3130595341464648 /* HFFASY01 */
    cmp [r12], rax
    jne fs_fence_invalid
    mov r15, [r14 + 208]
    test r15, r15
    jz fs_fence_invalid
    cmp [rdx + 8], r15
    jne fs_fence_invalid
    mov rax, [r15 + RF_NATIVE_CALLS]
    mov [rsp + 16], rax
    mov rax, [r15 + RF_NATIVE_EFFECTS]
    mov [rsp + 24], rax
    mov rdi, r12
    mov rsi, r13
    call runtime_fence_native_invoke
    cmp rax, 64
    je fs_fence_native_result
    cmp rax, 80
    jne fs_fence_invalid
fs_fence_native_result:
    mov [rbx + 48], rax
    mov [rbx + 56], rax
    jmp fs_fence_alias
fs_fence_configure:
    cmp qword ptr [r14 + 208], 0
    jne fs_fence_invalid
    mov r15, [rdx + 8]
    test r15, r15
    jz fs_fence_create_native
    mov rax, RF_PRIVATE_VALUE
    cmp [r15 + RF_PRIVATE_MAGIC], rax
    jne fs_fence_invalid
    cmp [r15 + RF_CONFIG_LENGTH], r13
    jne fs_fence_invalid
    mov rdi, [r15 + RF_CONFIG_BYTES]
    mov rsi, r12
    mov rcx, r13
    repe cmpsb
    jne fs_fence_invalid
    cmp qword ptr [r15 + RF_REFERENCES], -1
    je fs_fence_resource
    inc qword ptr [r15 + RF_REFERENCES]
    mov rax, [r15 + RF_NATIVE_CALLS]
    mov [rsp + 16], rax
    mov rax, [r15 + RF_NATIVE_EFFECTS]
    mov [rsp + 24], rax
    jmp fs_fence_attach_native
fs_fence_create_native:
    mov r15, r14
    mov rdi, r12
    mov rsi, r13
    call runtime_fence_native_create
    cmp rax, -4095
    jae fs_fence_resource
    mov r15, rax
    mov rdx, [rsp]
    mov [rdx + 8], r15
fs_fence_attach_native:
    mov [r14 + 208], r15
    mov qword ptr [rbx + 48], 0
    mov qword ptr [rbx + 56], 0
fs_fence_alias:
    mov [rbx + 8], r15
    mov qword ptr [rbx + 16], RF_MAP_BYTES
    lea rax, [r15 + RF_OUTPUT]
    mov [rbx + 32], rax
    mov qword ptr [rbx + 40], 80
    mov rax, [r15 + RF_NATIVE_CALLS]
    sub rax, [rsp + 16]
    jc fs_fence_invalid
    add [r14 + 128], rax
    add [r14 + 240], rax
    mov rax, [r15 + RF_NATIVE_EFFECTS]
    sub rax, [rsp + 24]
    jc fs_fence_invalid
    add [r14 + 248], rax
    mov r15, r14
    mov rax, [rbx + 48]
    mov edi, 1
    call runtime_grow_trace
    jmp fs_fence_done
fs_fence_resource:
    mov eax, 0xfffffffc
    jmp fs_fence_error
fs_fence_invalid:
    mov eax, 0xffffffff
fs_fence_error:
    mov [rbx + 48], rax
    mov qword ptr [rbx + 56], 0
fs_fence_done:
    mov rdx, [rsp + 8]
    mov qword ptr [rdx], 0
    mov rax, [rbx + 48]
    jmp fs_fence_return
fs_fence_early_invalid:
    mov eax, 0xffffffff
fs_fence_return:
    add rsp, 56
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret

/* Terminal session release, after the HIA gateway released its admitted call.
 * It cannot discard an active caller-owned permit in another session. */
runtime_grow_fence_release:
    push rbx
    push r12
    push r13
    push r14
    sub rsp, 8
    mov r14, r15
    mov r12, [r14 + 224]
    test r12, r12
    jz fs_fence_release_empty
    mov rax, 0x3230425548534648
    cmp [r12], rax
    jne fs_fence_release_invalid
    cmp qword ptr [r12 + 40], 0
    je fs_fence_release_invalid
    cmp qword ptr [r14 + 512 + 27 * 64], 0
    jne fs_fence_release_invalid
    cmp qword ptr [r14 + 520 + 27 * 64], 0
    jne fs_fence_release_invalid
    cmp qword ptr [r14 + 512 + 28 * 64], 0
    jne fs_fence_release_invalid
    cmp qword ptr [r14 + 520 + 28 * 64], 0
    jne fs_fence_release_invalid
    mov rbx, [r14 + 8]
    mov rdx, [rbx + 27 * 64 + 8]
    test rdx, rdx
    jz fs_fence_release_attached
    mov rax, [rdx + 8]
    or rax, [rdx + 112]
    jnz fs_fence_release_invalid
fs_fence_release_attached:
    mov r15, [r14 + 208]
    test r15, r15
    jz fs_fence_detach_hub
    cmp [r12 + 8], r15
    jne fs_fence_release_invalid
    mov rax, [r15 + RF_REFERENCES]
    cmp rax, 1
    jb fs_fence_release_invalid
    jne fs_fence_release_reference
    call runtime_fence_native_close
    test rax, rax
    jnz fs_fence_release_done
    mov qword ptr [r12 + 8], 0
    jmp fs_fence_release_clear
fs_fence_release_reference:
    dec qword ptr [r15 + RF_REFERENCES]
fs_fence_release_clear:
    mov qword ptr [r14 + 208], 0
    lea rdi, [rbx + 28 * 64 + 8]
    xor eax, eax
    mov ecx, 7
    rep stosq
fs_fence_detach_hub:
    dec qword ptr [r12 + 40]
    mov qword ptr [r14 + 224], 0
    mov qword ptr [r14 + 232], 0
fs_fence_release_empty:
    xor eax, eax
    jmp fs_fence_release_done
fs_fence_release_invalid:
    mov eax, 0xffffffff
fs_fence_release_done:
    mov r15, r14
    add rsp, 8
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

fs_fence_env_root:
    .asciz "HEPTA_EFFECT_OWNER_FENCE_DIR"
fs_fence_env_owner:
    .asciz "HEPTA_EFFECT_OWNER_SELF"
fs_fence_env_required:
    .asciz "HEPTA_EFFECT_OWNER_FENCE_REQUIRED"
