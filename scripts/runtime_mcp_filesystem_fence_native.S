/* Source-owned private callable adaptation of the published five-image lifecycle. */
.equ RF_WORKER_LIMIT, 512
/* Four fixed HIA images: owner, descriptor policy, typed JSON and SHA. */
.intel_syntax noprefix
.section .text
.global rf_owner_call_displacement
.global rf_fs_call_displacement
.global rf_json_call_displacement
.global rf_sha_call_displacement
.equ RF_INPUT, 4096
.equ RF_OUTPUT, 8392704
.equ RF_WORK, 16781312
.equ RF_ROOT_WORK, 50335744
.equ RF_JSON_WORK, 83890176
.equ RF_SHA_WORK, 88084480
.equ RF_MAP_BYTES, 88088576
.equ RF_CAP, 8388608
.equ RF_WCAP, 33554432
.equ RF_FOOTER, 33554176
.equ RF_ACTION, 256
.equ RF_STAT, 512
.equ RF_NAME, 4096
.equ RF_READ_AREA, 8192


.global runtime_fence_native_create
.global runtime_fence_native_invoke
.global runtime_fence_native_close
.equ RF_SAVED_RSP, 1104
.equ RF_CALL_MODE, 1112
.equ RF_BUSY, 1128
.equ RF_OLD_FS, 1136
.equ RF_OLD_SIGILL, 1144
.equ RF_REFERENCES, 1184
.equ RF_CONFIG_LENGTH, 1200
.equ RF_PRIVATE_MAGIC, 1208
.equ RF_CONFIG_BYTES, 1216
.equ RF_CONFIG_CAPACITY, 1224
.equ RF_NATIVE_CALLS, 1232
.equ RF_NATIVE_EFFECTS, 1240
.equ RF_PRIVATE_VALUE, 0x32304c4346465248 /* HRFFCL02 */

/* Trusted configuration frame from the HIA admission wrapper. */
runtime_fence_native_create:
    push rbp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub rsp, 24
    mov r13, rdi
    mov r12, rsi
    cmp rsi, 48
    jb rf_create_invalid
    cmp rsi, RF_CAP
    ja rf_create_invalid
    mov esi, RF_MAP_BYTES
    call rf_allocate_rw
    cmp rax, -4095
    jae rf_create_return
    mov r15, rax
    mov [r15 + RF_SAVED_RSP], rsp
    mov qword ptr [r15 + RF_CALL_MODE], 1
    mov qword ptr [r15 + RF_BUSY], 1
    mov qword ptr [r15 + RF_G_CACHE_FD], -1
    mov qword ptr [r15 + RF_G_EVENT_FD], -1
    lea rax, [r15 + RF_ROOT_WORK + RF_CACHE_BASE]
    mov [r15 + 704], rax
    mov [r15 + RF_C_GLOBAL], r15
    mov [r15 + RF_C_SELF], r15
    mov [r15 + RF_CONFIG_LENGTH], r12
    mov rsi, r12
    add rsi, 4095
    and rsi, -4096
    mov [r15 + RF_CONFIG_CAPACITY], rsi
    call rf_allocate_rw
    cmp rax, -4095
    jae rf_create_free_root
    mov [r15 + RF_CONFIG_BYTES], rax
    mov rdi, rax
    mov rsi, r13
    mov rcx, r12
    rep movsb
    mov rdi, [r15 + RF_CONFIG_BYTES]
    mov rsi, [r15 + RF_CONFIG_CAPACITY]
    mov edx, 1
    mov eax, 10
    syscall
    test rax, rax
    jnz rf_create_free_config
    lea rdi, [r15 + RF_INPUT]
    mov rsi, r13
    mov rcx, r12
    rep movsb
    mov [r15 + 24], r12
    mov qword ptr [r15 + RF_ROOT_WORK + RF_FOOTER + 120], 0
    jmp rf_owner_resume
rf_create_free_config:
    mov r14, rax
    mov rdi, [r15 + RF_CONFIG_BYTES]
    mov rsi, [r15 + RF_CONFIG_CAPACITY]
    mov eax, 11
    syscall
    mov rax, r14
rf_create_free_root:
    mov r14, rax
    mov rdi, r15
    mov esi, RF_MAP_BYTES
    mov eax, 11
    syscall
    mov rax, r14
    jmp rf_create_return
rf_create_invalid:
    mov rax, -22
rf_create_return:
    add rsp, 24
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret

/* r15 is the fixed private engine. The borrowed input ends at this return. */
runtime_fence_native_invoke:
    push rbp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub rsp, 24
    mov rax, RF_PRIVATE_VALUE
    cmp [r15 + RF_PRIVATE_MAGIC], rax
    jne rf_invoke_invalid
    cmp qword ptr [r15 + RF_BUSY], 0
    jne rf_invoke_invalid
    cmp qword ptr [r15 + RF_G_EOF], 0
    jne rf_invoke_invalid
    cmp qword ptr [r15 + RF_G_FRAME], 0
    jne rf_invoke_invalid
    cmp rsi, 64
    jb rf_invoke_invalid
    cmp rsi, RF_CAP
    ja rf_invoke_invalid
    mov [r15 + RF_SAVED_RSP], rsp
    mov qword ptr [r15 + RF_CALL_MODE], 2
    mov qword ptr [r15 + RF_BUSY], 1
    mov [r15 + 24], rsi
    mov rcx, rsi
    mov rsi, rdi
    lea rdi, [r15 + RF_INPUT]
    rep movsb
    mov qword ptr [r15 + RF_G_FRAME], 1
    mov rax, [r15 + RF_G_MANAGER]
    mov qword ptr [rax + RF_M_EVENT + 8], 1
    jmp rf_manager_resume
rf_invoke_invalid:
    mov eax, 0xffffffff
    jmp rf_create_return

/* Final process owner release. The real manager cancels and joins work before
 * the last arena or trap handler is retired. It never kills a live worker. */
runtime_fence_native_close:
    push rbp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub rsp, 24
    mov rax, RF_PRIVATE_VALUE
    cmp [r15 + RF_PRIVATE_MAGIC], rax
    jne rf_invoke_invalid
    cmp qword ptr [r15 + RF_BUSY], 0
    jne rf_invoke_invalid
    cmp qword ptr [r15 + RF_G_FRAME], 0
    jne rf_invoke_invalid
    mov [r15 + RF_SAVED_RSP], rsp
    mov qword ptr [r15 + RF_CALL_MODE], 3
    mov qword ptr [r15 + RF_BUSY], 1
    mov qword ptr [r15 + RF_G_EOF], 1
    mov qword ptr [r15 + 24], 0
    mov rax, [r15 + RF_G_MANAGER]
    mov qword ptr [rax + RF_M_EVENT + 8], 3
    jmp rf_manager_resume

rf_callable_return:
    mov rsp, [r15 + RF_SAVED_RSP]
    mov qword ptr [r15 + RF_BUSY], 0
    jmp rf_create_return

rf_owner_resume:
    mov rax, [r15 + RF_C_GLOBAL]
    lock inc qword ptr [rax + RF_NATIVE_CALLS]
    mov qword ptr [r15 + 80], 0
    lea r13, [r15 + RF_INPUT]
    lea r12, [r15 + RF_OUTPUT]
    lea r14, [r15 + RF_ROOT_WORK]
    mov rdi, r13
    mov rsi, [r15 + 24]
    mov rdx, r12
    mov ecx, RF_CAP
    mov r8, r14
    mov r9d, RF_WCAP
    .byte 0xe8
rf_owner_call_displacement:
rf_local_owner_call_displacement:
    .long 0
    jmp rf_native_return
rf_native_resume:
    mov rax, [r15 + RF_C_GLOBAL]
    lock inc qword ptr [rax + RF_NATIVE_CALLS]
    cmp qword ptr [r15 + 80], 1
    jne rf_fatal
    mov rdi, r13
    mov rsi, [r15 + 96]
    mov rdx, r12
    mov rcx, [r15 + 104]
    mov r8, r14
    mov r9d, RF_WCAP
    .byte 0xe8
rf_fs_call_displacement:
    .long 0
    jmp rf_native_return
rf_json_resume:
    mov rax, [r15 + RF_C_GLOBAL]
    lock inc qword ptr [rax + RF_NATIVE_CALLS]
    lea r14, [r15 + RF_JSON_WORK]
    mov rdi, r13
    mov rsi, [r15 + 96]
    mov rdx, r12
    mov rcx, [r15 + 104]
    mov r8, r14
    mov r9d, 4194304
    .byte 0xe8
rf_json_call_displacement:
    .long 0
    jmp rf_native_return
rf_sha_resume:
    mov rax, [r15 + RF_C_GLOBAL]
    lock inc qword ptr [rax + RF_NATIVE_CALLS]
    lea r14, [r15 + RF_SHA_WORK]
    mov rdi, r13
    mov rsi, [r15 + 96]
    mov rdx, r12
    mov rcx, [r15 + 104]
    mov r8, r14
    mov r9d, 4096
    .byte 0xe8
rf_sha_call_displacement:
    .long 0
rf_native_return:
    mov edx, eax
    cmp rax, rdx
    jne rf_fatal
    mov edx, 0xffffffe0
    cmp rax, rdx
    je rf_call_dispatch
    mov edx, 0xfffffff0
    cmp rax, rdx
    je rf_effect_dispatch_checked
    cmp qword ptr [r15 + 80], 0
    jne rf_child_completed
    cmp rax, RF_CAP
    ja rf_fatal
    cmp qword ptr [r14 + RF_FOOTER + 120], 0
    je rf_startup_completed
    cmp qword ptr [r15 + RF_C_WORKER], 1
    jne rf_fatal
    cmp qword ptr [r15 + RF_C_MODE], 2
    je rf_drop_completed
    cmp qword ptr [r15 + RF_C_MODE], 3
    je rf_inline_completed
    cmp qword ptr [r15 + RF_C_MODE], 1
    jne rf_fatal
    jmp rf_worker_completed
rf_effect_dispatch_checked:
    cmp qword ptr [r15 + 80], 1
    jne rf_fatal
    jmp rf_effect_dispatch

rf_child_completed:
    mov edx, 0xffff0000
    cmp rax, rdx
    jae rf_child_result_ok
    cmp rax, [r15 + 104]
    ja rf_fatal
rf_child_result_ok:
    lea rdx, [r15 + RF_ROOT_WORK + RF_FOOTER]
    mov [rdx + 80], rax
    mov rax, [r15 + 88]
    mov [rdx + 88], rax
    mov qword ptr [rdx + 96], 1
    jmp rf_owner_resume

rf_call_dispatch:
    cmp qword ptr [r15 + RF_C_MODE], 3
    je rf_fatal
    cmp qword ptr [r15 + 80], 0
    jne rf_fatal
    lea rdx, [r15 + RF_ROOT_WORK + RF_FOOTER]
    mov rax, 0x31304c4143414948 /* HIACAL01 */
    cmp [rdx], rax
    jne rf_fatal
    mov rax, [r15 + 88]
    inc rax
    jz rf_fatal
    cmp [rdx + 8], rax
    jne rf_fatal
    mov [r15 + 88], rax
    mov rax, [rdx + 72]
    or rax, [rdx + 80]
    or rax, [rdx + 88]
    or rax, [rdx + 96]
    or rax, [rdx + 104]
    jnz rf_fatal
    mov rax, [rdx + 16]
    cmp rax, 1
    jb rf_fatal
    cmp rax, 3
    ja rf_fatal
    mov [r15 + 80], rax
    cmp qword ptr [rdx + 24], 2
    jne rf_fatal
    cmp qword ptr [rdx + 48], 2
    jne rf_fatal
    mov rax, [rdx + 32]
    cmp rax, RF_FOOTER
    ja rf_fatal
    mov rcx, RF_FOOTER
    sub rcx, rax
    mov r8, [rdx + 40]
    cmp r8, rcx
    ja rf_fatal
    cmp r8, RF_CAP
    ja rf_fatal
    mov [r15 + 96], r8
    lea r13, [r15 + RF_ROOT_WORK]
    add r13, rax
    mov rax, [rdx + 56]
    cmp rax, RF_FOOTER
    ja rf_fatal
    mov rcx, RF_FOOTER
    sub rcx, rax
    mov r9, [rdx + 64]
    cmp r9, rcx
    ja rf_fatal
    cmp r9, RF_CAP
    ja rf_fatal
    mov [r15 + 104], r9
    lea r12, [r15 + RF_ROOT_WORK]
    add r12, rax
    test r8, r8
    jz rf_spans_disjoint
    test r9, r9
    jz rf_spans_disjoint
    lea rax, [r13 + r8]
    cmp r12, rax
    jae rf_spans_disjoint
    lea rax, [r12 + r9]
    cmp r13, rax
    jb rf_fatal
rf_spans_disjoint:
    cmp qword ptr [r15 + 80], 1
    je rf_start_fs
    cmp qword ptr [r15 + 80], 2
    jne rf_sha_resume
    cmp qword ptr [r15 + 96], 1048600
    ja rf_fatal
    jmp rf_json_resume
rf_start_fs:
    lea r14, [r15 + RF_WORK]
    jmp rf_native_resume
/* Native lifecycle boundary. The HIA manager owns future/permit policy.
 * This file supplies fixed private allocations, threads and event transport.
 * No input frame chooses an image, code address, syscall or administrator path.
 */
.equ RF_CACHE_BASE, 23658496
.equ RF_CACHE_BYTES, 4456448
.equ RF_MANAGER_INITIAL, 10485760
.equ RF_STACK_BYTES, 1118208
.equ RF_STACK_TOP, 1052672
.equ RF_G_CACHE_FD, 712
.equ RF_G_JOBS, 752
.equ RF_G_MANAGER, 760
.equ RF_G_MANAGER_BYTES, 768
.equ RF_G_MANAGER_SEQ, 776
.equ RF_G_EVENT_FD, 784
.equ RF_G_READ_STAGE, 808
.equ RF_G_READ_SIZE, 816
.equ RF_G_READ_HAVE, 824
.equ RF_G_FRAME, 832
.equ RF_G_WRITE_SIZE, 840
.equ RF_G_WRITE_HAVE, 848
.equ RF_G_WAIT, 864
.equ RF_G_EOF, 872
.equ RF_G_POLLFDS, 896
.equ RF_G_EVENT_WORD, 920
.equ RF_G_NODE, 936
.equ RF_G_DROP_NODE, 944
.equ RF_G_LAST_ID, 952
.equ RF_G_RUNNING, 960
.equ RF_G_LIMIT, 968
.equ RF_G_WIRE, 2048
.equ RF_M_ACTION, 256
.equ RF_M_RESULT, 512
.equ RF_M_EVENT, 2048
.equ RF_C_GLOBAL, 720
.equ RF_C_HELD, 728
.equ RF_C_SELF, 736
.equ RF_C_WORKER, 744
.equ RF_C_NODE, 752
.equ RF_C_BOUNDARY, 760
.equ RF_C_MODE, 776
.equ RF_C_NOTIFY, 800
.global rf_manager_call_displacement

rf_startup_completed:
    test eax, eax
    jnz rf_fatal
    cmp qword ptr [r15 + RF_C_WORKER], 0
    jne rf_fatal
    mov [r15 + RF_C_SELF], r15
    mov edi, 0x1003
    lea rsi, [r15 + RF_OLD_FS]
    mov eax, 158
    syscall
    test rax, rax
    jnz rf_fatal
    mov edi, 0x1002 /* ARCH_SET_FS: private native TLS, no libc runtime. */
    mov rsi, r15
    mov eax, 158
    syscall
    test rax, rax
    jnz rf_fatal
    lea rax, [rip + rf_native_trap_handler]
    mov [r15 + 1024], rax
    mov qword ptr [r15 + 1032], 0x0c000004
    lea rax, [rip + rf_native_signal_restorer]
    mov [r15 + 1040], rax
    mov qword ptr [r15 + 1048], 0
    mov edi, 4
    lea rsi, [r15 + 1024]
    lea rdx, [r15 + RF_OLD_SIGILL]
    mov r10d, 8
    mov eax, 13
    syscall
    test rax, rax
    jnz rf_fatal
    /* The caller retains exclusive ownership of stdin/stdout. */
    lea rdi, [rip + rf_cache_name]
    mov esi, 3
    mov eax, 319
    syscall
    cmp rax, -4095
    jae rf_fatal
    mov [r15 + RF_G_CACHE_FD], rax
    mov rdi, rax
    mov esi, RF_CACHE_BYTES
    mov eax, 77
    syscall
    test rax, rax
    jnz rf_fatal
    mov rdi, [r15 + RF_G_CACHE_FD]
    mov esi, 1033
    mov edx, 7
    mov eax, 72
    syscall
    test rax, rax
    jnz rf_fatal
    mov rdi, [r15 + RF_G_CACHE_FD]
    mov esi, 1034
    mov eax, 72
    syscall
    and eax, 7
    cmp eax, 7
    jne rf_fatal
    lea rdi, [r15 + RF_ROOT_WORK + RF_CACHE_BASE]
    mov [r15 + 704], rdi
    mov esi, RF_CACHE_BYTES
    mov edx, 3
    mov r10d, 17
    mov r8, [r15 + RF_G_CACHE_FD]
    xor r9d, r9d
    mov eax, 9
    syscall
    cmp rax, [r15 + 704]
    jne rf_fatal
    xor edi, edi
    mov esi, 0x80800
    mov eax, 290
    syscall
    cmp rax, -4095
    jae rf_fatal
    mov [r15 + RF_G_EVENT_FD], rax
    xor edi, edi
    mov esi, RF_MANAGER_INITIAL
    call rf_allocate_rw
    cmp rax, -4095
    jae rf_fatal
    mov [r15 + RF_G_MANAGER], rax
    mov qword ptr [r15 + RF_G_MANAGER_BYTES], RF_MANAGER_INITIAL
    mov qword ptr [r15 + RF_G_LIMIT], RF_WORKER_LIMIT
    mov rdx, 0x3130545645464648 /* HFFEVT01 */
    mov [rax + RF_M_EVENT], rdx
    mov qword ptr [rax + RF_M_EVENT + 8], 0
    mov qword ptr [rax + RF_M_EVENT + 16], RF_WORKER_LIMIT
    mov rdx, [r15 + RF_ROOT_WORK + 32]
    mov [rax + RF_M_EVENT + 24], rdx
    mov rdx, [r15 + RF_ROOT_WORK + 56]
    mov [rax + RF_M_EVENT + 32], rdx
    mov qword ptr [r15 + 24], 0
    jmp rf_manager_resume

rf_manager_resume:
    mov rax, [r15 + RF_C_GLOBAL]
    lock inc qword ptr [rax + RF_NATIVE_CALLS]
    lea rdi, [r15 + RF_INPUT]
    mov rsi, [r15 + 24]
    lea rdx, [r15 + RF_OUTPUT]
    mov ecx, 80
    mov r8, [r15 + RF_G_MANAGER]
    mov r9, [r15 + RF_G_MANAGER_BYTES]
    .byte 0xe8
rf_manager_call_displacement:
rf_local_manager_call_displacement:
    .long 0
    mov edx, eax
    cmp rax, rdx
    jne rf_fatal
    mov edx, 0xffffffd0
    cmp rax, rdx
    je rf_manager_effect
    mov edx, 0xffffffd1
    cmp rax, rdx
    je rf_manager_idle
    mov edx, 0xffffffd2
    cmp rax, rdx
    je rf_manager_wait
    mov edx, 0xffffffd3
    cmp rax, rdx
    je rf_manager_done
    cmp rax, 64
    je rf_manager_response
    cmp rax, 80
    jne rf_fatal

rf_manager_response:
    cmp qword ptr [r15 + RF_CALL_MODE], 2
    jne rf_fatal
    cmp qword ptr [r15 + RF_G_FRAME], 1
    jne rf_fatal
    mov qword ptr [r15 + RF_G_FRAME], 0
    mov qword ptr [r15 + RF_G_WAIT], 0
    mov qword ptr [r15 + 24], 0
    jmp rf_callable_return
rf_manager_idle:
    cmp qword ptr [r15 + RF_CALL_MODE], 1
    jne rf_fatal
    mov qword ptr [r15 + RF_G_WAIT], 0
    mov rax, RF_PRIVATE_VALUE
    mov [r15 + RF_PRIVATE_MAGIC], rax
    mov qword ptr [r15 + RF_REFERENCES], 1
    mov rax, r15
    jmp rf_callable_return
rf_manager_wait:
    mov qword ptr [r15 + RF_G_WAIT], 1
rf_callable_event_read:
    mov rdi, [r15 + RF_G_EVENT_FD]
    lea rsi, [r15 + RF_G_EVENT_WORD]
    mov edx, 8
    xor eax, eax
    syscall
    cmp rax, -4
    je rf_callable_event_read
    cmp rax, -11
    je rf_callable_event_poll
    cmp rax, 8
    jne rf_fatal
    mov rax, [r15 + RF_G_MANAGER]
    mov qword ptr [rax + RF_M_EVENT + 8], 2
    jmp rf_manager_resume
rf_callable_event_poll:
    lea rdi, [r15 + RF_G_POLLFDS]
    mov rax, [r15 + RF_G_EVENT_FD]
    mov [rdi], eax
    mov dword ptr [rdi + 4], 1
    mov esi, 1
    mov edx, -1
    mov eax, 7
    syscall
    cmp rax, -4
    je rf_callable_event_read
    test rax, rax
    jle rf_fatal
    jmp rf_callable_event_read
rf_manager_done:
    cmp qword ptr [r15 + RF_CALL_MODE], 3
    jne rf_fatal
    cmp qword ptr [r15 + RF_G_EOF], 1
    jne rf_fatal
    mov rax, [r15 + RF_G_JOBS]
    or rax, [r15 + RF_G_RUNNING]
    jnz rf_fatal
    mov rdi, [r15 + RF_G_EVENT_FD]
    mov eax, 3
    syscall
    mov rdi, [r15 + RF_G_CACHE_FD]
    mov eax, 3
    syscall
    mov rdi, [r15 + RF_G_MANAGER]
    mov rsi, [r15 + RF_G_MANAGER_BYTES]
    mov eax, 11
    syscall
    test rax, rax
    jnz rf_fatal
    mov edi, 4
    lea rsi, [r15 + RF_OLD_SIGILL]
    xor edx, edx
    mov r10d, 8
    mov eax, 13
    syscall
    test rax, rax
    jnz rf_fatal
    mov edi, 0x1002
    mov rsi, [r15 + RF_OLD_FS]
    mov eax, 158
    syscall
    test rax, rax
    jnz rf_fatal
    mov rdi, [r15 + RF_CONFIG_BYTES]
    mov rsi, [r15 + RF_CONFIG_CAPACITY]
    mov eax, 11
    syscall
    test rax, rax
    jnz rf_fatal
    mov rsp, [r15 + RF_SAVED_RSP]
    mov rdi, r15
    mov esi, RF_MAP_BYTES
    mov eax, 11
    syscall
    test rax, rax
    jnz rf_bare_fatal
    xor eax, eax
    jmp rf_create_return

rf_allocate_rw:
    xor edi, edi
    mov edx, 3
    mov r10d, 34
    mov r8, -1
    xor r9d, r9d
    mov eax, 9
    syscall
    ret

rf_cache_name:
    .asciz "hia-effect-replay-cache"

rf_manager_effect:
    mov r14, [r15 + RF_G_MANAGER]
    lea r14, [r14 + RF_M_ACTION]
    mov rax, 0x315443414d464648 /* HFFMACT1 */
    cmp [r14], rax
    jne rf_fatal
    mov rax, [r15 + RF_G_MANAGER_SEQ]
    inc rax
    jz rf_fatal
    cmp [r14 + 8], rax
    jne rf_fatal
    mov [r15 + RF_G_MANAGER_SEQ], rax
    mov rax, [r14 + 56]
    or rax, [r14 + 64]
    or rax, [r14 + 72]
    or rax, [r14 + 80]
    or rax, [r14 + 88]
    or rax, [r14 + 96]
    or rax, [r14 + 104]
    or rax, [r14 + 112]
    or rax, [r14 + 120]
    jnz rf_fatal
    mov rax, [r14 + 16]
    cmp rax, 1
    je rf_manager_allocate
    call rf_manager_zero_span
    cmp qword ptr [r14 + 16], 6
    je rf_manager_grow
    cmp qword ptr [r14 + 32], 0
    jne rf_fatal
    mov rdi, [r14 + 24]
    call rf_job_lookup
    mov [r15 + RF_G_NODE], rax
    cmp qword ptr [r14 + 16], 2
    je rf_manager_start
    cmp qword ptr [r14 + 16], 7
    je rf_manager_start
    cmp qword ptr [r14 + 16], 3
    je rf_manager_inspect
    cmp qword ptr [r14 + 16], 4
    je rf_manager_retire
    cmp qword ptr [r14 + 16], 5
    je rf_manager_drop
    jmp rf_fatal

rf_manager_zero_span:
    mov rax, [r14 + 40]
    or rax, [r14 + 48]
    jnz rf_fatal
    ret

rf_job_lookup:
    test rdi, rdi
    jz rf_fatal
    mov rax, [r15 + RF_G_JOBS]
rf_job_lookup_next:
    test rax, rax
    jz rf_fatal
    cmp [rax + 8], rdi
    je rf_job_lookup_found
    mov rax, [rax]
    jmp rf_job_lookup_next
rf_job_lookup_found:
    ret

rf_manager_allocate:
    mov rax, [r15 + RF_G_LAST_ID]
    inc rax
    jz rf_fatal
    cmp [r14 + 24], rax
    jne rf_fatal
    cmp qword ptr [r14 + 40], 4096
    jne rf_fatal
    mov rax, [r14 + 48]
    cmp rax, 40
    jb rf_fatal
    cmp rax, RF_CAP
    ja rf_fatal
    mov qword ptr [r15 + 984], 0
    mov rdi, [r14 + 32]
    test rdi, rdi
    jz rf_manager_alloc_node
    call rf_job_lookup
    cmp qword ptr [rax + 192], 1
    jne rf_fatal
    cmp qword ptr [rax + 80], 1
    jne rf_fatal
    mov rdx, [rax + 48]
    test rdx, rdx
    jz rf_fatal
    cmp qword ptr [rdx + RF_ROOT_WORK + 152], 1
    jne rf_fatal
    cmp qword ptr [rax + 16], 0
    jne rf_fatal
    mov [r15 + 984], rax
rf_manager_alloc_node:
    mov esi, 4096
    call rf_allocate_rw
    cmp rax, -4095
    jae rf_manager_ack
    mov [r15 + RF_G_NODE], rax
    mov rdx, [r15 + 984]
    mov [rax + 16], rdx
    mov rdx, [r14 + 24]
    mov [rax + 8], rdx
    mov rdx, [r14 + 48]
    mov [rax + 32], rdx
    add rdx, 4095
    and rdx, -4096
    mov [rax + 40], rdx
    mov rsi, rdx
    call rf_allocate_rw
    cmp rax, -4095
    jae rf_manager_alloc_failed
    mov rbx, [r15 + RF_G_NODE]
    mov [rbx + 24], rax
    mov rdi, rax
    mov rsi, [r15 + RF_G_MANAGER]
    add rsi, 4096
    mov rcx, [rbx + 32]
    rep movsb
    mov rdi, [rbx + 24]
    mov rsi, [rbx + 40]
    mov edx, 1
    mov eax, 10
    syscall
    test rax, rax
    jnz rf_manager_alloc_failed
    mov rdx, [r15 + RF_G_JOBS]
    mov [rbx], rdx
    mov [r15 + RF_G_JOBS], rbx
    mov rax, [rbx + 8]
    mov [r15 + RF_G_LAST_ID], rax
    jmp rf_manager_ack
rf_manager_alloc_failed:
    mov [r15 + 1000], rax
    mov rbx, [r15 + RF_G_NODE]
    mov rdi, [rbx + 24]
    test rdi, rdi
    jz rf_manager_alloc_node_free
    mov rsi, [rbx + 40]
    mov eax, 11
    syscall
rf_manager_alloc_node_free:
    mov rdi, rbx
    mov esi, 4096
    mov eax, 11
    syscall
    mov rax, [r15 + 1000]
    jmp rf_manager_ack

rf_manager_grow:
    cmp qword ptr [r14 + 24], 0
    jne rf_fatal
    mov rdx, [r15 + RF_G_MANAGER_BYTES]
    add rdx, 1048576
    jc rf_fatal
    cmp [r14 + 32], rdx
    jne rf_fatal
    mov rdi, [r15 + RF_G_MANAGER]
    mov rsi, [r15 + RF_G_MANAGER_BYTES]
    mov r10d, 1
    xor r8d, r8d
    mov eax, 25
    syscall
    cmp rax, -4095
    jae rf_manager_ack
    mov [r15 + RF_G_MANAGER], rax
    add qword ptr [r15 + RF_G_MANAGER_BYTES], 1048576
    mov rax, [r15 + RF_G_MANAGER_BYTES]
    jmp rf_manager_ack

rf_manager_inspect:
    mov rbx, [r15 + RF_G_NODE]
    cmp qword ptr [rbx + 96], 1
    jne rf_fatal
    cmp qword ptr [rbx + 80], 0
    jne rf_manager_join
    xor eax, eax
    jmp rf_manager_ack
rf_manager_join:
    mov edx, [rbx + 72]
    test edx, edx
    jz rf_manager_joined
    lea rdi, [rbx + 72]
    xor esi, esi
    xor r10d, r10d
    xor r8d, r8d
    xor r9d, r9d
    mov eax, 202
    syscall
    cmp rax, -4
    je rf_manager_join
    cmp rax, -11
    je rf_manager_join
    test rax, rax
    jnz rf_fatal
    jmp rf_manager_join
rf_manager_joined:
    mfence
    cmp qword ptr [rbx + 192], 0
    jne rf_manager_join_recorded
    cmp qword ptr [r15 + RF_G_RUNNING], 0
    je rf_fatal
    dec qword ptr [r15 + RF_G_RUNNING]
    mov qword ptr [rbx + 192], 1
rf_manager_join_recorded:
    mov rax, [rbx + 80]
    cmp rax, 2
    je rf_manager_ack
    cmp rax, 1
    jne rf_fatal
    lea rsi, [rbx + 120]
    mov rdi, [r15 + RF_G_MANAGER]
    add rdi, RF_M_RESULT
    mov ecx, 40
    rep movsb
    mov eax, 1
    jmp rf_manager_ack

rf_manager_drop:
    mov rbx, [r15 + RF_G_NODE]
    cmp qword ptr [rbx + 192], 1
    jne rf_fatal
    cmp qword ptr [rbx + 80], 1
    jne rf_fatal
    cmp qword ptr [rbx + 16], 0
    jne rf_fatal
    mov rax, [rbx + 48]
    test rax, rax
    jz rf_fatal
    cmp qword ptr [rax + RF_ROOT_WORK + 152], 1
    jne rf_fatal
    /* A still-live borrower prevents descriptor transfer/release. */
    mov rdx, [r15 + RF_G_JOBS]
rf_drop_check_borrowers:
    test rdx, rdx
    jz rf_drop_borrowers_clear
    cmp [rdx + 16], rbx
    jne rf_drop_next_borrower
    cmp qword ptr [rdx + 192], 1
    jne rf_fatal
rf_drop_next_borrower:
    mov rdx, [rdx]
    jmp rf_drop_check_borrowers
rf_drop_borrowers_clear:
    mov [r15 + RF_G_DROP_NODE], rbx
    mov r15, rax
    mov qword ptr [r15 + RF_C_MODE], 2
    lea rdi, [r15 + RF_INPUT]
    mov rax, 0x3130444d43464648 /* HFFCMD01 */
    mov [rdi], rax
    mov qword ptr [rdi + 8], 4
    mov qword ptr [rdi + 16], 0
    mov qword ptr [rdi + 24], 0
    mov qword ptr [rdi + 32], 0
    mov qword ptr [r15 + 24], 40
    mov qword ptr [r15 + RF_ROOT_WORK + RF_FOOTER + 120], 1
    jmp rf_owner_resume
rf_drop_completed:
    cmp rax, 40
    jne rf_fatal
    lea rdx, [r15 + RF_OUTPUT]
    mov rax, 0x3130534552464648 /* HFFRES01 */
    cmp [rdx], rax
    jne rf_fatal
    mov rax, [rdx + 8]
    or rax, [rdx + 16]
    or rax, [rdx + 24]
    or rax, [rdx + 32]
    or rax, [r15]
    or rax, [r15 + RF_C_HELD]
    jnz rf_fatal
    mov qword ptr [r15 + RF_C_MODE], 0
    mov r15, [r15 + RF_C_GLOBAL]
    xor eax, eax
    jmp rf_manager_ack

rf_manager_retire:
    mov rbx, [r15 + RF_G_NODE]
    cmp dword ptr [rbx + 72], 0
    jne rf_fatal
    cmp qword ptr [rbx + 96], 0
    je rf_retire_not_started
    cmp qword ptr [rbx + 192], 1
    jne rf_fatal
rf_retire_not_started:
    mov rdi, [rbx + 48]
    test rdi, rdi
    jz rf_retire_no_context
    mov rax, [rdi]
    cmp rax, [rdi + RF_C_BOUNDARY]
    jne rf_fatal
    cmp qword ptr [rdi + RF_C_HELD], 0
    jne rf_fatal
    mov esi, RF_MAP_BYTES
    mov eax, 11
    syscall
    test rax, rax
    jnz rf_fatal
rf_retire_no_context:
    mov rdi, [rbx + 56]
    test rdi, rdi
    jz rf_retire_no_stack
    mov esi, RF_STACK_BYTES
    mov eax, 11
    syscall
    test rax, rax
    jnz rf_fatal
rf_retire_no_stack:
    mov rdi, [rbx + 24]
    mov rsi, [rbx + 40]
    mov eax, 11
    syscall
    test rax, rax
    jnz rf_fatal
    lea r8, [r15 + RF_G_JOBS]
rf_retire_find_job:
    mov rax, [r8]
    test rax, rax
    jz rf_fatal
    cmp rax, rbx
    je rf_retire_job_found
    mov r8, rax
    jmp rf_retire_find_job
rf_retire_job_found:
    mov rax, [rbx]
    mov [r8], rax
    mov rdi, rbx
    mov esi, 4096
    mov eax, 11
    syscall
    test rax, rax
    jnz rf_fatal
    xor eax, eax
    jmp rf_manager_ack

rf_manager_ack:
    mov r14, [r15 + RF_G_MANAGER]
    add r14, RF_M_ACTION
    xor edx, edx
    cmp rax, -4095
    jb rf_manager_ack_value
    neg rax
    mov rdx, rax
    xor eax, eax
rf_manager_ack_value:
    mov [r14 + 72], rdx
    mov [r14 + 80], rax
    mov rax, [r15 + RF_G_MANAGER_SEQ]
    mov [r14 + 64], rax
    jmp rf_manager_resume

rf_manager_start:
    mov rbx, [r15 + RF_G_NODE]
    mov rax, [rbx + 48]
    or rax, [rbx + 56]
    or rax, [rbx + 72]
    or rax, [rbx + 80]
    or rax, [rbx + 96]
    jnz rf_fatal
    cmp qword ptr [r14 + 16], 7
    je rf_start_capacity_ready
    mov rax, [r15 + RF_G_RUNNING]
    cmp rax, [r15 + RF_G_LIMIT]
    jae rf_fatal
rf_start_capacity_ready:
    mov esi, RF_MAP_BYTES
    call rf_allocate_rw
    cmp rax, -4095
    jae rf_start_no_context_failed
    mov [rbx + 48], rax
    mov rdx, [rbx + 16]
    mov rsi, r15
    test rdx, rdx
    jz rf_start_copy_owner
    cmp qword ptr [rdx + 192], 1
    jne rf_fatal
    mov rsi, [rdx + 48]
    test rsi, rsi
    jz rf_fatal
    cmp qword ptr [rsi + RF_ROOT_WORK + 152], 1
    jne rf_fatal
    mov rcx, [rsi]
    mov [rax], rcx
    mov [rax + RF_C_BOUNDARY], rcx
    mov rcx, [rsi + 8]
    mov [rax + 8], rcx
rf_start_copy_owner:
    lea rdi, [rax + RF_ROOT_WORK]
    add rsi, RF_ROOT_WORK
    /* Copy only admitted fields, immutable configuration and the optional path.
     * The two scan-name arrays and temporary JSON arena stay private and empty.
     */
    mov ecx, 270336
    rep movsb
    mov rax, [rbx + 16]
    test rax, rax
    jz rf_start_private_copied
    mov rsi, [rax + 48]
    add rsi, RF_ROOT_WORK + 4263936
    mov rdi, [rbx + 48]
    add rdi, RF_ROOT_WORK + 4263936
    mov ecx, 4096
    rep movsb
rf_start_private_copied:
    mov rdx, [rbx + 48]
    mov rax, [rdx + RF_ROOT_WORK + 16]
    mov [rdx + 88], rax
    mov [rdx + RF_C_GLOBAL], r15
    mov [rdx + RF_C_SELF], rdx
    mov qword ptr [rdx + RF_C_WORKER], 1
    mov [rdx + RF_C_NODE], rbx
    mov qword ptr [rdx + RF_C_MODE], 1
    mov rax, [rbx + 32]
    mov [rdx + 24], rax
    lea rdi, [rdx + RF_INPUT]
    mov rsi, [rbx + 24]
    mov rcx, rax
    rep movsb
    mov rdx, [rbx + 48]
    mov qword ptr [rdx + RF_ROOT_WORK + RF_FOOTER + 120], 1
    lea rdi, [rdx + RF_ROOT_WORK + RF_CACHE_BASE]
    mov esi, RF_CACHE_BYTES
    mov edx, 3
    mov r10d, 17
    mov r8, [r15 + RF_G_CACHE_FD]
    xor r9d, r9d
    mov eax, 9
    syscall
    mov rdx, [rbx + 48]
    lea rdx, [rdx + RF_ROOT_WORK + RF_CACHE_BASE]
    cmp rax, rdx
    jne rf_start_map_failed
    cmp qword ptr [r14 + 16], 7
    je rf_start_inline
    mov esi, RF_STACK_BYTES
    call rf_allocate_rw
    cmp rax, -4095
    jae rf_start_failed
    mov [rbx + 56], rax
    mov qword ptr [rbx + 64], RF_STACK_BYTES
    mov rdi, rax
    mov esi, 4096
    xor edx, edx
    mov eax, 10
    syscall
    test rax, rax
    jnz rf_start_failed
    mov rsi, [rbx + 56]
    add rsi, RF_STACK_TOP - 16
    mov rax, [rbx + 48]
    mov [rsi], rax
    mov [rsi + 8], rbx
    mov qword ptr [rbx + 96], 1
    mov edi, 0x3d0f00 /* Shared process plus private FS-base for trap custody. */
    lea rdx, [rbx + 72]
    mov r10, rdx
    mov r8, [rbx + 48]
    mov eax, 56
    syscall
    test rax, rax
    jz rf_worker_entry
    cmp rax, -4095
    jae rf_start_failed
    inc qword ptr [r15 + RF_G_RUNNING]
    xor eax, eax
    jmp rf_manager_ack
rf_start_inline:
    mov qword ptr [rbx + 96], 1
    mov qword ptr [rbx + 192], 1
    mov r15, [rbx + 48]
    mov qword ptr [r15 + RF_C_MODE], 3
    jmp rf_owner_resume
rf_start_map_failed:
    cmp rax, -4095
    jae rf_start_failed
    mov rax, -5
rf_start_failed:
    mov [r15 + 1000], rax
    /* No worker was published: no filesystem descriptor was acquired. */
    mov rdi, [rbx + 56]
    test rdi, rdi
    jz rf_start_free_context
    mov esi, RF_STACK_BYTES
    mov eax, 11
    syscall
    mov qword ptr [rbx + 56], 0
rf_start_free_context:
    mov rdi, [rbx + 48]
    mov esi, RF_MAP_BYTES
    mov eax, 11
    syscall
    mov qword ptr [rbx + 48], 0
    mov qword ptr [rbx + 192], 1
    mov rax, [r15 + 1000]
    jmp rf_manager_ack
rf_start_no_context_failed:
    mov qword ptr [rbx + 192], 1
    jmp rf_manager_ack

rf_worker_entry:
    mov r15, [rsp]
    add rsp, 16
    cld
    mov rbx, [r15 + RF_C_NODE]
    mov rax, [rbx + 56]
    add rax, RF_STACK_TOP
    mov [r15 + 832], rax
    mov qword ptr [r15 + 840], 0
    mov qword ptr [r15 + 848], 65536
    lea rdi, [r15 + 832]
    xor esi, esi
    mov eax, 131
    syscall
    test rax, rax
    jnz rf_worker_failed
    /* A caller may have blocked SIGILL before exec. Only this worker's native
     * trap signal is unblocked; every other inherited signal bit is retained.
     */
    mov qword ptr [r15 + 864], 8
    mov edi, 1
    lea rsi, [r15 + 864]
    xor edx, edx
    mov r10d, 8
    mov eax, 14
    syscall
    test rax, rax
    jnz rf_worker_failed
    jmp rf_owner_resume

rf_worker_completed:
    cmp rax, 40
    jne rf_fatal
    mov rbx, [r15 + RF_C_NODE]
    cmp [rbx + 48], r15
    jne rf_fatal
    cmp qword ptr [r15 + RF_C_HELD], 0
    jne rf_fatal
    cmp qword ptr [r15 + RF_ROOT_WORK + 8], 0
    jne rf_fatal
    cmp qword ptr [r15 + RF_WORK + 8], 0
    jne rf_fatal
    lea rsi, [r15 + RF_OUTPUT]
    lea rdi, [rbx + 120]
    mov ecx, 40
    rep movsb
    mov qword ptr [rbx + 88], 40
    mov eax, 1
    xchg [rbx + 80], rax
    test rax, rax
    jnz rf_fatal
    jmp rf_worker_notify

rf_inline_completed:
    cmp rax, 40
    jne rf_fatal
    cmp qword ptr [r15 + RF_C_HELD], 0
    jne rf_fatal
    mov rbx, [r15 + RF_C_NODE]
    lea rsi, [r15 + RF_OUTPUT]
    lea rdi, [rbx + 120]
    mov ecx, 40
    rep movsb
    mov qword ptr [rbx + 80], 1
    mov qword ptr [rbx + 88], 40
    mov qword ptr [r15 + RF_C_MODE], 0
    mov r15, [r15 + RF_C_GLOBAL]
    lea rsi, [rbx + 120]
    mov rdi, [r15 + RF_G_MANAGER]
    add rdi, RF_M_RESULT
    mov ecx, 40
    rep movsb
    xor eax, eax
    jmp rf_manager_ack

/* An abnormal component completion is a worker failure, never a permit.
 * Descriptor ownership is removed before close. Borrowed handles are retained.
 */
rf_worker_failed:
    cmp qword ptr [r15 + RF_C_HELD], 0
    je rf_worker_cleanup
    mov qword ptr [r15 + RF_C_HELD], 0
    mov rax, [r15 + RF_C_GLOBAL]
    mov rdi, [rax + 704]
    mov qword ptr [rdi + 8], 1
    mov dword ptr [rdi], 0
    mov esi, 129
    mov edx, 1
    xor r10d, r10d
    xor r8d, r8d
    xor r9d, r9d
    mov eax, 202
    syscall
rf_worker_cleanup:
    mov rbx, [r15]
    cmp rbx, [r15 + RF_C_BOUNDARY]
    je rf_worker_cleanup_done
    test rbx, rbx
    jz rf_worker_global_fatal
    mov rax, [rbx]
    mov [r15], rax
    mov rdi, [rbx + 16]
    mov eax, 3
    syscall
    mov rdi, rbx
    mov esi, 4096
    mov eax, 11
    syscall
    jmp rf_worker_cleanup
rf_worker_cleanup_done:
    mov rbx, [r15 + RF_C_NODE]
    mov qword ptr [rbx + 88], 0
    mov eax, 2
    xchg [rbx + 80], rax
rf_worker_notify:
    mov qword ptr [r15 + RF_C_NOTIFY], 1
    mov rax, [r15 + RF_C_GLOBAL]
    mov rdi, [rax + RF_G_EVENT_FD]
    lea rsi, [r15 + RF_C_NOTIFY]
    mov edx, 8
rf_worker_notify_retry:
    mov eax, 1
    syscall
    cmp rax, -4
    je rf_worker_notify_retry
    cmp rax, -11
    je rf_worker_exit
    cmp rax, 8
    jne rf_worker_global_fatal
rf_worker_exit:
    xor edi, edi
    mov eax, 60
    syscall
    ud2
rf_worker_global_fatal:
    mov edi, 111
    jmp rf_process_exit_group

/* Only an actual positive-code SIGILL at a pinned worker HIA instruction is
 * recovered. External signals and faults in the manager/adapter stay fatal.
 * The signal frame redirects onto the worker's original stack; no arena or
 * stack can be retired until its CHILD_CLEARTID word has become zero.
 */
rf_native_trap_handler:
    cmp edi, 4
    jne rf_signal_process_fatal
    cmp dword ptr [rsi + 8], 0
    jle rf_signal_process_fatal
    mov rax, qword ptr fs:[RF_C_SELF]
    cmp qword ptr [rax + RF_C_WORKER], 1
    jne rf_signal_process_fatal
    cmp qword ptr [rax + RF_C_MODE], 1
    jne rf_signal_process_fatal
    mov rcx, [rdx + 168] /* ucontext x86-64 REG_RIP */
    lea r8, [rip + rf_local_owner_call_displacement]
    movsxd r9, dword ptr [r8]
    lea r8, [r8 + r9 + 4]
    cmp rcx, r8
    jb rf_signal_process_fatal
    lea r8, [rip + rf_local_manager_call_displacement]
    movsxd r9, dword ptr [r8]
    lea r8, [r8 + r9 + 4]
    cmp rcx, r8
    jae rf_signal_process_fatal
    mov [rdx + 96], rax /* REG_R15 = this registered worker context */
    mov r8, [rax + RF_C_NODE]
    mov r8, [r8 + 56]
    add r8, RF_STACK_TOP - 16
    mov [rdx + 160], r8 /* REG_RSP */
    lea r8, [rip + rf_worker_signal_failure]
    mov [rdx + 168], r8
    ret
rf_native_signal_restorer:
    mov eax, 15
    syscall
    ud2
rf_worker_signal_failure:
    cld
    mov rbx, [r15 + RF_C_NODE]
    mov qword ptr [rbx + 104], 4
    jmp rf_worker_failed
rf_signal_process_fatal:
    mov edi, 111
    jmp rf_process_exit_group

rf_fatal:
    cmp qword ptr [r15 + RF_C_WORKER], 1
    jne rf_main_fatal
    cmp qword ptr [r15 + RF_C_MODE], 1
    je rf_worker_failed
rf_main_fatal:
    mov edi, 111
    jmp rf_process_exit_group
rf_bare_fatal:
    mov edi, 112
    jmp rf_process_exit_group
rf_argv_fatal:
    mov edi, 64
rf_process_exit_group:
    mov eax, 231
    syscall
    ud2

rf_effect_dispatch:
    mov rax, 0x3154434153464648 /* HFFSACT1 */
    cmp [r14 + RF_ACTION], rax
    jne rf_fatal
    mov rax, [r15 + 16]
    inc rax
    jz rf_fatal
    cmp [r14 + RF_ACTION + 8], rax
    jne rf_fatal
    mov [r15 + 16], rax
    mov rax, [r14 + RF_ACTION + 56]
    or rax, [r14 + RF_ACTION + 64]
    or rax, [r14 + RF_ACTION + 72]
    or rax, [r14 + RF_ACTION + 80]
    or rax, [r14 + RF_ACTION + 88]
    or rax, [r14 + RF_ACTION + 96]
    or rax, [r14 + RF_ACTION + 104]
    or rax, [r14 + RF_ACTION + 112]
    or rax, [r14 + RF_ACTION + 120]
    or rax, [r14 + RF_ACTION + 32]
    jnz rf_fatal
    mov rax, [r14 + RF_ACTION + 16]
    mov [r15 + 48], rax
    cmp rax, 1
    je rf_effect_root
    cmp rax, 2
    je rf_effect_open
    cmp rax, 3
    je rf_effect_open
    cmp rax, 4
    je rf_effect_open
    cmp rax, 5
    je rf_effect_stat
    cmp rax, 6
    je rf_effect_read
    cmp rax, 7
    je rf_effect_lock
    cmp rax, 8
    je rf_effect_close
    cmp rax, 9
    je rf_effect_clock
    cmp rax, 10
    je rf_effect_proc
    cmp rax, 11
    je rf_effect_dents
    cmp rax, 12
    je rf_effect_uid
    cmp rax, 13
    je rf_effect_cache_lock
    cmp rax, 14
    je rf_effect_cache_unlock
    jmp rf_fatal

/* The zero-span actions cannot turn a workspace word into a pointer. */
rf_zero_span:
    mov rax, [r14 + RF_ACTION + 40]
    or rax, [r14 + RF_ACTION + 48]
    jnz rf_fatal
    ret
rf_no_handle:
    cmp qword ptr [r14 + RF_ACTION + 24], 0
    jne rf_fatal
    ret
rf_effect_root:
    call rf_zero_span
    call rf_no_handle
rf_root_retry:
    mov rdi, -100
    lea rsi, [rip + rf_slash]
    mov edx, 0x80000
    xor r10d, r10d
    mov eax, 257
    syscall
    cmp rax, -4
    je rf_root_retry
    jmp rf_register_result
rf_effect_open:
    cmp qword ptr [r14 + RF_ACTION + 40], RF_NAME
    jne rf_fatal
    mov rcx, [r14 + RF_ACTION + 48]
    cmp rcx, RF_CAP
    ja rf_fatal
    lea rsi, [r14 + RF_NAME]
    cmp byte ptr [rsi + rcx], 0
    jne rf_fatal
    xor edx, edx
rf_open_no_nul:
    cmp rdx, rcx
    je rf_open_nul_checked
    cmp byte ptr [rsi + rdx], 0
    je rf_fatal
    inc rdx
    jmp rf_open_no_nul
rf_open_nul_checked:
    mov rdi, [r14 + RF_ACTION + 24]
    call rf_lookup
    mov rdi, rdx
    lea rsi, [r14 + RF_NAME]
    mov edx, 0xa0800
    cmp qword ptr [r15 + 48], 2
    jne rf_open_record_flags
    mov edx, 0xb0000
    jmp rf_open_ready
rf_open_record_flags:
    cmp qword ptr [r15 + 48], 4
    jne rf_open_ready
    add edx, 2
rf_open_ready:
    xor r10d, r10d
    mov eax, 257
    syscall
    jmp rf_register_result
rf_effect_stat:
    call rf_zero_span
    mov rdi, [r14 + RF_ACTION + 24]
    call rf_lookup
    mov rdi, rdx
    lea rsi, [r14 + RF_STAT]
    mov eax, 5
    syscall
    jmp rf_acknowledge
rf_effect_read:
    cmp qword ptr [r14 + RF_ACTION + 40], RF_READ_AREA
    jne rf_fatal
    cmp qword ptr [r14 + RF_ACTION + 48], 1048577
    ja rf_fatal
    mov rdi, [r14 + RF_ACTION + 24]
    call rf_lookup
    mov rdi, rdx
    lea rsi, [r14 + RF_READ_AREA]
    mov rdx, [r14 + RF_ACTION + 48]
    xor eax, eax
    syscall
    jmp rf_acknowledge
rf_effect_lock:
    call rf_zero_span
    mov rdi, [r14 + RF_ACTION + 24]
    call rf_lookup
    mov rdi, rdx
    mov esi, 1
    mov eax, 73
    syscall
    jmp rf_acknowledge
rf_effect_close:
    call rf_zero_span
    mov rdi, [r14 + RF_ACTION + 24]
    call rf_retire_close
    jmp rf_acknowledge
rf_effect_clock:
    call rf_zero_span
    call rf_no_handle
    mov edi, 1
    lea rsi, [r14 + RF_STAT]
    mov eax, 228
    syscall
    jmp rf_acknowledge
rf_effect_proc:
    call rf_zero_span
    mov rdi, [r14 + RF_ACTION + 24]
    call rf_lookup
    mov rax, rdx
    call rf_proc_path
    mov rdi, -100
    mov edx, 0x90800
    xor r10d, r10d
    mov eax, 257
    syscall
    jmp rf_register_result
rf_effect_dents:
    cmp qword ptr [r14 + RF_ACTION + 40], RF_READ_AREA
    jne rf_fatal
    cmp qword ptr [r14 + RF_ACTION + 48], 32768
    jne rf_fatal
    mov rdi, [r14 + RF_ACTION + 24]
    call rf_lookup
    mov rdi, rdx
    lea rsi, [r14 + RF_READ_AREA]
    mov edx, 32768
    mov eax, 217
    syscall
    jmp rf_acknowledge
rf_effect_uid:
    call rf_zero_span
    call rf_no_handle
    mov eax, 107
    syscall
    jmp rf_acknowledge

/* One canonical address is used for all shared-workspace aliases. */
rf_effect_cache_lock:
    call rf_zero_span
    call rf_no_handle
    cmp qword ptr [r15 + 728], 0
    jne rf_fatal
    mov rax, [r15 + 720]
    test rax, rax
    jz rf_fatal
    mov rbx, [rax + 704]
    test rbx, rbx
    jz rf_fatal
rf_cache_lock_retry:
    xor eax, eax
    mov edx, 1
    lock cmpxchg dword ptr [rbx], edx
    jz rf_cache_lock_held
    mov rdi, rbx
    mov esi, 128
    mov edx, 1
    xor r10d, r10d
    xor r8d, r8d
    xor r9d, r9d
    mov eax, 202
    syscall
    cmp rax, -4
    je rf_cache_lock_retry
    cmp rax, -11
    je rf_cache_lock_retry
    test rax, rax
    jnz rf_fatal
    jmp rf_cache_lock_retry
rf_cache_lock_held:
    mov qword ptr [r15 + 728], 1
    xor eax, eax
    jmp rf_acknowledge
rf_effect_cache_unlock:
    call rf_zero_span
    call rf_no_handle
    cmp qword ptr [r15 + 728], 1
    jne rf_fatal
    mov qword ptr [r15 + 728], 0
    mov rax, [r15 + 720]
    mov rdi, [rax + 704]
    mov dword ptr [rdi], 0
    mov esi, 129
    mov edx, 1
    xor r10d, r10d
    xor r8d, r8d
    xor r9d, r9d
    mov eax, 202
    syscall
    cmp rax, -4095
    jae rf_fatal
    xor eax, eax
    jmp rf_acknowledge

rf_register_result:
    cmp rax, -4095
    jae rf_acknowledge
    call rf_register_fd
rf_acknowledge:
    mov rdx, [r15 + RF_C_GLOBAL]
    lock inc qword ptr [rdx + RF_NATIVE_EFFECTS]
    xor edx, edx
    cmp rax, -4095
    jb rf_ack_value
    neg rax
    mov rdx, rax
    xor eax, eax
rf_ack_value:
    mov [r14 + RF_ACTION + 72], rdx
    mov [r14 + RF_ACTION + 80], rax
    mov rax, [r15 + 16]
    mov [r14 + RF_ACTION + 64], rax
    jmp rf_native_resume

/* rf_lookup(id) -> host-owned node and raw fd. No caller pointer is used. */
rf_lookup:
    test rdi, rdi
    jz rf_fatal
    mov rax, [r15]
rf_lookup_next:
    test rax, rax
    jz rf_fatal
    cmp [rax + 8], rdi
    je rf_lookup_found
    mov rax, [rax]
    jmp rf_lookup_next
rf_lookup_found:
    mov rdx, [rax + 16]
    ret

rf_register_fd:
    push rax
    cmp qword ptr [r15 + 8], -1
    je rf_register_overflow
    xor edi, edi
    mov esi, 4096
    mov edx, 3
    mov r10d, 34
    mov r8, -1
    xor r9d, r9d
    mov eax, 9
    syscall
    cmp rax, -4095
    jae rf_register_failed
    mov rcx, [r15]
    mov [rax], rcx
    mov rcx, [r15 + 8]
    inc rcx
    mov [r15 + 8], rcx
    mov [rax + 8], rcx
    pop rdx
    mov [rax + 16], rdx
    mov [r15], rax
    mov rax, rcx
    ret
rf_register_overflow:
    mov rax, -75
rf_register_failed:
    pop rdi
    push rax
    mov eax, 3
    syscall
    pop rax
    ret

rf_retire_close:
    lea r8, [r15]
    mov rax, [r8]
rf_retire_next:
    cmp rax, [r15 + 760]
    je rf_fatal
    test rax, rax
    jz rf_fatal
    cmp [rax + 8], rdi
    je rf_retire_found
    mov r8, rax
    mov rax, [rax]
    jmp rf_retire_next
rf_retire_found:
    mov rcx, [rax]
    mov [r8], rcx
    push qword ptr [rax + 16]
    mov rdi, rax
    mov esi, 4096
    mov eax, 11
    syscall
    pop rdi
    mov eax, 3
    syscall
    ret

rf_proc_path:
    lea r8, [r15 + 192]
    mov byte ptr [r8], 0
    mov r9, r8
    mov r10d, 10
rf_decimal_next:
    xor edx, edx
    div r10
    add dl, 48
    dec r8
    mov [r8], dl
    test rax, rax
    jnz rf_decimal_next
    lea rsi, [rip + rf_proc_prefix]
    lea rdi, [r15 + 128]
    mov ecx, 14
    rep movsb
    mov rsi, r8
    mov rcx, r9
    sub rcx, r8
    inc rcx
    rep movsb
    lea rsi, [r15 + 128]
    ret


rf_slash:
    .asciz "/"
rf_proc_prefix:
    .ascii "/proc/self/fd/"
