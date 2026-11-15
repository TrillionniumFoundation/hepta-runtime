/* Private fixed batch graph. No batch decision is implemented by this boundary. */
.intel_syntax noprefix
.section .text
.global batch_engine_create
batch_engine_create:
    push rbp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub rsp, 24
    mov [rsp + 8], rdi
    mov [rsp + 16], rsi
    mov qword ptr [rsp], 0
    mov edi, 4096
    call view_allocate
    cmp rax, -4095
    jae batch_create_cleanup
    mov r15, rax
    mov [rsp], rax
    mov rax, [rsp + 8]
    mov [r15], rax
    mov rax, [rsp + 16]
    mov [r15 + 16], rax
    mov edi, 4096
    call view_allocate
    cmp rax, -4095
    jae batch_create_cleanup
    mov [r15 + 8], rax
    mov r14, rax
    xor ebp, ebp
batch_create_slot:
    mov rax, [rsp + 8]
    mov rax, [rax + rbp * 8]
    mov [r14], rax
    lea rbx, [rip + batch_initial_capacities]
    mov rax, rbp
    shl rax, 4
    add rbx, rax
    mov rdi, [rbx]
    mov [r14 + 16], rdi
    call view_allocate
    cmp rax, -4095
    jae batch_create_cleanup
    mov [r14 + 8], rax
    mov rdi, [rbx + 8]
    mov [r14 + 32], rdi
    call view_allocate
    cmp rax, -4095
    jae batch_create_cleanup
    mov [r14 + 24], rax
    add r14, 64
    inc rbp
    cmp rbp, 22
    jb batch_create_slot
    lea rdi, [rip + batch_history_init]
    mov esi, 64
    mov edx, 17
    call batch_dispatch
    cmp eax, 64
    jne batch_create_invalid
    lea rdi, [rip + batch_locks_init]
    mov esi, 64
    mov edx, 18
    call batch_dispatch
    cmp eax, 64
    jne batch_create_invalid
    lea rdi, [rip + batch_lease_init]
    mov esi, 64
    mov edx, 7
    call batch_dispatch
    cmp eax, 64
    jne batch_create_invalid
    mov rbx, [r15 + 8]
    mov rax, [rbx + 7 * 64 + 24]
    mov rcx, 0x313030524c435248
    cmp [rax], rcx
    jne batch_create_invalid
    mov rcx, [rax + 8]
    mov [r15 + 112], rcx
    mov rdx, [rax + 16]
    mov [r15 + 120], rdx
    lea rdi, [r15 + 256]
    mov rax, 0x3230494e49434248
    mov [rdi], rax
    mov qword ptr [rdi + 8], 1
    mov [rdi + 16], rcx
    mov [rdi + 24], rdx
    mov qword ptr [rdi + 32], 10
    mov qword ptr [rdi + 40], 7
    mov qword ptr [rdi + 48], 0
    mov qword ptr [rdi + 56], 0
    mov esi, 64
    xor edx, edx
    call batch_dispatch
    cmp eax, 64
    jne batch_create_invalid
    mov rax, r15
    jmp batch_create_return
batch_create_invalid:
    mov rax, -22
batch_create_cleanup:
    mov r13, rax
    mov r15, [rsp]
    test r15, r15
    jz batch_create_cleaned
    call batch_engine_free_maps
batch_create_cleaned:
    mov rax, r13
batch_create_return:
    add rsp, 24
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret

/* r15 engine, edx fixed slot, rdi/rsi immutable frame. */
.global batch_dispatch
batch_dispatch:
    cmp edx, 22
    jae batch_dispatch_invalid
    cmp edx, 1
    jb batch_pure_invoke
    cmp edx, 3
    jbe view_read_invoke
    cmp edx, 5
    je view_key_invoke
    cmp edx, 6
    je batch_shared_scope_invoke
    cmp edx, 7
    je batch_shared_scope_invoke
    cmp edx, 8
    je batch_shared_scope_invoke
    cmp edx, 17
    je batch_dispatch_global
    cmp edx, 18
    je batch_dispatch_global
    cmp edx, 13
    je batch_tree_invoke
    cmp edx, 14
    je batch_tree_invoke
    cmp edx, 19
    je batch_atomic_invoke
    jmp batch_pure_invoke
batch_dispatch_global:
    cmp qword ptr [r15 + 800], 0
    jne batch_shared_global_invoke
    jmp batch_pure_invoke
batch_dispatch_invalid:
    mov eax, 0xffffffff
    ret

/* Grow one owned descriptor allocation. No borrowed mapping moves here.
 * rdi descriptor, esi 1=workspace/2=output, rdx minimum. Return errno or zero. */
batch_grow:
    push rbx
    push rbp
    push r12
    mov rbx, rdi
    mov ebp, esi
    test rdx, rdx
    js batch_grow_overflow
    cmp ebp, 1
    jne batch_grow_out
    mov rsi, [rbx + 16]
    mov rdi, [rbx + 8]
    jmp batch_grow_admit
batch_grow_out:
    cmp ebp, 2
    jne batch_grow_overflow
    mov rsi, [rbx + 32]
    mov rdi, [rbx + 24]
batch_grow_admit:
    cmp rdx, rsi
    jbe batch_grow_done
    mov r12, rsi
batch_grow_loop:
    cmp r12, rdx
    jae batch_grow_ready
    shl r12, 1
    jc batch_grow_overflow
    test r12, r12
    js batch_grow_overflow
    jmp batch_grow_loop
batch_grow_ready:
    mov rdx, r12
    call view_resize
    cmp rax, -4095
    jae batch_grow_return
    cmp ebp, 1
    jne batch_grow_store_out
    mov [rbx + 8], rax
    mov [rbx + 16], r12
    jmp batch_grow_done
batch_grow_store_out:
    mov [rbx + 24], rax
    mov [rbx + 32], r12
batch_grow_done:
    xor eax, eax
    jmp batch_grow_return
batch_grow_overflow:
    mov rax, -12
batch_grow_return:
    pop r12
    pop rbp
    pop rbx
    ret

batch_pure_invoke:
    push rbx
    push r12
    push r13
    push r14
    sub rsp, 8
    mov r12, rdi
    mov r13, rsi
    mov r14d, edx
    mov ebx, edx
    shl rbx, 6
    add rbx, [r15 + 8]
    cmp r14d, 12
    jne batch_pure_not_input_bridge
    /* Capacity hint only: HBPI still validates every byte and reports its
     * exact requirement. Avoid rescanning a large typed object just because
     * the freshly installed output starts at 4 KiB. Never impose a quota. */
    mov rdx, r13
    add rdx, 8192
    jc batch_pure_resource
    mov rdi, rbx
    mov esi, 2
    call batch_grow
    test rax, rax
    jnz batch_pure_resource
    jmp batch_pure_retry
batch_pure_not_input_bridge:
    cmp r14d, 15
    jne batch_pure_retry
    mov rdx, r13
    shl rdx, 2
    jc batch_pure_resource
    add rdx, 4096
    jc batch_pure_resource
    mov rdi, rbx
    mov esi, 1
    call batch_grow
    test rax, rax
    jnz batch_pure_resource
    /* The admitted HEDIT001 frame bounds every retained normalized byte:
     * four input-sized arrays plus the header already fit above. A short
     * output must never double those sufficient arrays on every retry. */
    mov rdx, r13
    shl rdx, 1
    jc batch_pure_resource
    add rdx, 4096
    jc batch_pure_resource
    mov rdi, rbx
    mov esi, 2
    call batch_grow
    test rax, rax
    jnz batch_pure_resource
batch_pure_retry:
    mov rdi, r12
    mov rsi, r13
    mov rdx, [rbx + 24]
    mov rcx, [rbx + 32]
    mov r8, [rbx + 8]
    mov r9, [rbx + 16]
    call qword ptr [rbx]
    mov edx, eax
    cmp rax, rdx
    jne batch_pure_contract
    cmp eax, 0xfffffffe
    je batch_pure_capacity
    cmp r14d, 18
    je batch_pure_lock
    cmp r14d, 0
    je batch_pure_controller
    cmp r14d, 12
    je batch_pure_wide
    cmp r14d, 16
    je batch_pure_wide
    cmp r14d, 20
    je batch_pure_wide
    jmp batch_pure_done
batch_pure_controller:
    cmp eax, 64
    jne batch_pure_done
    mov rcx, [rbx + 24]
    mov rdx, 0x3230305241434248
    cmp [rcx], rdx
    jne batch_pure_contract
    cmp qword ptr [rcx + 8], 5
    jne batch_pure_done
    mov rsi, [rcx + 32]
    mov rdx, [rcx + 48]
    jmp batch_pure_grow_exact
batch_pure_wide:
    cmp eax, 64
    jne batch_pure_done
    mov rcx, [rbx + 24]
    mov rsi, [rcx + 8]
    cmp rsi, 2
    je batch_pure_wide_growth
    cmp rsi, 3
    jne batch_pure_done
batch_pure_wide_growth:
    dec rsi
    mov rdx, [rcx + 48]
    cmp r14d, 12
    jne batch_pure_grow_exact
    mov rdx, [rcx + 40]
    jmp batch_pure_grow_exact
batch_pure_lock:
    cmp eax, 64
    jne batch_pure_done
    mov rcx, [rbx + 24]
    mov rdx, 0x3130524b4c465248
    cmp [rcx], rdx
    jne batch_pure_contract
    cmp qword ptr [rcx + 16], 2
    jne batch_pure_done
    mov rdx, [rcx + 32]
    mov esi, 1
    jmp batch_pure_grow_exact
batch_pure_capacity:
    cmp r14d, 8
    je batch_pure_grow_work
    cmp r14d, 17
    je batch_pure_grow_work
    cmp r14d, 15
    jne batch_pure_done
    mov rdx, [rbx + 32]
    shl rdx, 1
    jc batch_pure_resource
    mov rdi, rbx
    mov esi, 2
    call batch_grow
    test rax, rax
    jnz batch_pure_resource
    jmp batch_pure_retry
batch_pure_grow_work:
    mov rdx, [rbx + 16]
    shl rdx, 1
    jc batch_pure_resource
    mov esi, 1
batch_pure_grow_exact:
    cmp esi, 1
    je batch_pure_check_work_growth
    cmp esi, 2
    jne batch_pure_contract
    cmp rdx, [rbx + 32]
    jbe batch_pure_contract
    jmp batch_pure_growth_ready
batch_pure_check_work_growth:
    cmp rdx, [rbx + 16]
    jbe batch_pure_contract
batch_pure_growth_ready:
    mov rdi, rbx
    call batch_grow
    test rax, rax
    jnz batch_pure_resource
    jmp batch_pure_retry
batch_pure_contract:
    mov eax, 0xfffffff8
    jmp batch_pure_done
batch_pure_resource:
    mov eax, 0xfffffffc
batch_pure_done:
    mov [rbx + 40], rax
    add rsp, 8
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

.global batch_engine_free_maps
batch_engine_free_maps:
    push rbx
    push r12
    push r13
    mov r12, [r15 + 8]
    test r12, r12
    jz batch_free_engine
    cmp qword ptr [r15 + 808], 0
    je batch_free_owned_slots
    mov rax, [r15 + 1024]
    mov [r12 + 7 * 64 + 8], rax
    mov rax, [r15 + 1032]
    mov [r12 + 7 * 64 + 16], rax
    mov rax, [r15 + 1040]
    mov [r12 + 8 * 64 + 8], rax
    mov rax, [r15 + 1048]
    mov [r12 + 8 * 64 + 16], rax
batch_free_owned_slots:
    xor ebx, ebx
batch_free_slot:
    mov rdi, [r12 + 8]
    mov rsi, [r12 + 16]
    call batch_unmap
    mov rdi, [r12 + 24]
    mov rsi, [r12 + 32]
    call batch_unmap
    cmp ebx, 1
    jb batch_free_next
    cmp ebx, 3
    jbe batch_free_control
    cmp ebx, 5
    je batch_free_control
    cmp ebx, 19
    jne batch_free_next
batch_free_control:
    mov rdi, [r12 + 48]
    mov esi, 4096
    call batch_unmap
batch_free_next:
    add r12, 64
    inc ebx
    cmp ebx, 22
    jb batch_free_slot
    mov rdi, [r15 + 8]
    mov esi, 4096
    call batch_unmap
batch_free_engine:
    mov rdi, [r15 + 656]
    mov rsi, [r15 + 664]
    call batch_unmap
    mov rdi, [r15 + 712]
    mov rsi, [r15 + 720]
    call batch_unmap
    mov rdi, [r15 + 128]
    mov rsi, [r15 + 136]
    call batch_unmap
    mov rdi, [r15 + 160]
    mov rsi, [r15 + 168]
    call batch_unmap
    mov rdi, [r15 + 224]
    mov rsi, [r15 + 232]
    call batch_unmap
    mov rdi, r15
    mov esi, 4096
    call batch_unmap
    pop r13
    pop r12
    pop rbx
    ret
batch_unmap:
    test rdi, rdi
    jz batch_unmap_done
    add rsi, 4096
    mov eax, 11
    syscall
batch_unmap_done:
    ret

.balign 8
batch_history_init:
    .ascii "HHISTQ01"
    .zero 56
batch_locks_init:
    .ascii "HRFLOCK1"
    .zero 56
batch_lease_init:
    .ascii "HRCLQ001"
    .quad 1, 0, 0, 8, 0, 0, 0
batch_initial_capacities:
    .quad 4096, 4096
    .quad 131072, 4096
    .quad 131072, 4096
    .quad 131072, 4096
    .quad 4096, 4096
    .quad 1056768, 4096
    .quad 33554432, 8388608
    .quad 33554432, 8388608
    .quad 4096, 1052672
    .quad 4096, 4096
    .quad 33554432, 8388608
    .quad 4096, 4096
    .quad 65536, 4096
    .quad 131072, 4096
    .quad 131072, 4096
    .quad 65536, 4096
    .quad 65536, 4096
    .quad 4096, 4096
    .quad 4096, 4096
    .quad 4096, 4096
    .quad 65536, 4096
    .quad 65536, 4096
