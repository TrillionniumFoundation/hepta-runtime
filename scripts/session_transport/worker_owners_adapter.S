.intel_syntax noprefix
.section .text
    jmp on_standalone
# Serialized scheduler-thread owner. Waker callbacks are fixed link-time symbols.
.equ CDF_CONTEXT_MAGIC, 0x3130435446444348
.equ CDF_REQUEST_MAGIC, 0x3130514644435248
.equ CDF_REPLY_MAGIC, 0x3130524644435248
.equ CDF_WORK_MAGIC, 0x3130574644435248
.equ CDF_ACTION_MAGIC, 0x3130414644435248
.equ CDF_COMPLETE_MAGIC, 0x31304f4344435248
.macro cdf_enter
    push rbp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub rsp, 72
.endm
.macro cdf_leave
    add rsp, 72
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret
.endm

# create(hook_owner, never-reused positive generation) -> context or zero.
cooperative_defer_create:
    cdf_enter
    mov r14, rdi
    mov r13, rsi
    test r14, r14
    jz cdf_create_failed
    test r13, r13
    jz cdf_create_failed
    mov edi, 4096
    call cdf_allocate
    test rax, rax
    jz cdf_create_failed
    mov r12, rax
    mov edi, 536
    call cdf_allocate
    test rax, rax
    jz cdf_create_free
    mov [r12 + 16], rax
    mov qword ptr [r12 + 24], 536
    mov [r12 + 8], r13
    mov [r12 + 40], r14
    mov eax, 186
    syscall
    test rax, rax
    jle cdf_fatal
    mov [r12 + 32], rax
    movabs rax, CDF_CONTEXT_MAGIC
    mov [r12], rax
    mov rdi, rsp
    xor eax, eax
    mov ecx, 8
    rep stosq
    movabs rax, CDF_REQUEST_MAGIC
    mov [rsp], rax
    mov [rsp + 16], r13
    mov rdi, r12
    mov rsi, rsp
    mov edx, 64
    lea rcx, [r12 + 128]
    mov r8d, 64
    call cooperative_defer_call
    cmp rax, 64
    jne cdf_fatal
    mov rax, r12
    cdf_leave
cdf_create_free:
    mov rdi, r12
    mov esi, 4096
    call cdf_unmap
cdf_create_failed:
    xor eax, eax
    cdf_leave

# call(context, borrowed request64, length, reply64, capacity) -> unchanged HIA code.
# The callback owner is borrowed until destroy returns. Calls stay on creator TID.
cooperative_defer_call:
    cdf_enter
    mov r12, rdi
    mov r13, rsi
    mov r14, rcx
    cmp r8, 64
    jb cdf_call_capacity
    cmp rdx, 64
    jne cdf_call_invalid
    test r12, r12
    jz cdf_call_invalid
    test r13, r13
    jz cdf_call_invalid
    test r14, r14
    jz cdf_call_invalid
    movabs rax, CDF_CONTEXT_MAGIC
    cmp [r12], rax
    jne cdf_call_invalid
    mov eax, 186
    syscall
    cmp [r12 + 32], rax
    jne cdf_call_invalid
    cmp qword ptr [r12 + 48], 0
    jne cdf_call_invalid
    mov rax, [r13 + 16]
    cmp rax, [r12 + 8]
    jne cdf_call_invalid
    mov rdi, rsp
    mov rsi, r13
    mov ecx, 8
    cld
    rep movsq
    mov qword ptr [r12 + 48], 1
cdf_call_again:
    mov rdi, rsp
    mov esi, 64
    lea rdx, [r12 + 128]
    mov ecx, 64
    mov r8, [r12 + 16]
    mov r9, [r12 + 24]
    call cdf_invoke
    add qword ptr [r12 + 56], 1
    jc cdf_fatal
    mov edx, eax
    cmp rax, rdx
    jne cdf_fatal
    cmp eax, 0xfffffff0
    je cdf_call_effect
    cmp eax, 0xfffffffd
    je cdf_call_grow
    cmp eax, 64
    je cdf_call_success
    cmp eax, 0xffffffff
    je cdf_call_return_code
    cmp eax, 0xfffffffe
    jne cdf_fatal
cdf_call_return_code:
    mov qword ptr [r12 + 48], 0
    cdf_leave
cdf_call_success:
    movabs rax, CDF_REPLY_MAGIC
    cmp [r12 + 128], rax
    jne cdf_fatal
    mov rax, [r12 + 136]
    cmp rax, [r12 + 8]
    jne cdf_fatal
    mov rax, [r12 + 144]
    cmp rax, [rsp + 8]
    jne cdf_fatal
    cmp qword ptr [r12 + 184], 0
    jne cdf_fatal
    mov rdi, r14
    lea rsi, [r12 + 128]
    mov ecx, 8
    rep movsq
    mov eax, 64
    jmp cdf_call_return_code
cdf_call_capacity:
    mov eax, 0xfffffffe
    cdf_leave
cdf_call_invalid:
    mov eax, 0xffffffff
    cdf_leave

cdf_call_effect:
    mov r15, [r12 + 16]
    movabs rax, CDF_ACTION_MAGIC
    cmp [r15 + 256], rax
    jne cdf_fatal
    mov rax, [r15 + 264]
    cmp rax, [r15 + 24]
    jne cdf_fatal
    mov rax, [r15 + 272]
    cmp rax, [r12 + 8]
    jne cdf_fatal
    mov rax, [r15 + 280]
    cmp rax, 1
    jb cdf_fatal
    cmp rax, 3
    ja cdf_fatal
    cmp qword ptr [r15 + 312], 0
    jne cdf_fatal
    lea rdi, [r15 + 128]
    mov rsi, rsp
    mov ecx, 8
    repe cmpsq
    jne cdf_fatal
    lea rdi, [r12 + 192]
    lea rsi, [r15 + 256]
    mov ecx, 8
    rep movsq
    mov qword ptr [r12 + 256], 0
    mov qword ptr [r12 + 264], 0
    mov qword ptr [r12 + 272], 0
    mov rdi, [r12 + 40]
    mov rsi, [r12 + 224]
    mov rdx, [r12 + 232]
    mov rcx, [r12 + 240]
    cmp qword ptr [r12 + 216], 1
    je cdf_effect_clone
    cmp qword ptr [r12 + 216], 2
    je cdf_effect_wake
    call cooperative_waker_drop
    jmp cdf_effect_return
cdf_effect_clone:
    lea r8, [r12 + 256]
    call cooperative_waker_clone
    jmp cdf_effect_return
cdf_effect_wake:
    call cooperative_waker_wake
cdf_effect_return:
    test rax, rax
    jnz cdf_fatal
    add qword ptr [r12 + 72], 1
    jc cdf_fatal
    lea rdi, [r12 + 192]
    lea rsi, [r15 + 256]
    mov ecx, 8
    repe cmpsq
    jne cdf_fatal
    lea rdi, [r15 + 320]
    xor eax, eax
    mov ecx, 8
    rep stosq
    movabs rax, CDF_COMPLETE_MAGIC
    mov [r15 + 320], rax
    mov rax, [r12 + 200]
    mov [r15 + 328], rax
    mov rax, [r12 + 8]
    mov [r15 + 336], rax
    mov rax, [r12 + 216]
    mov [r15 + 344], rax
    cmp rax, 1
    jne cdf_call_again
    cmp qword ptr [r12 + 264], 0
    je cdf_fatal
    cmp qword ptr [r12 + 272], 0
    je cdf_fatal
    lea rdi, [r15 + 352]
    lea rsi, [r12 + 256]
    mov ecx, 3
    rep movsq
    jmp cdf_call_again

cdf_call_grow:
    mov rbx, [r12 + 24]
    lea rbp, [rbx + rbx]
    mov edx, 0xffffffff
    cmp rbp, rdx
    jae cdf_fatal
    mov r15, [r12 + 16]
    mov rdi, rbp
    call cdf_allocate
    test rax, rax
    jz cdf_fatal
    mov [r12 + 16], rax
    mov [r12 + 24], rbp
    mov rdi, rax
    mov rsi, r15
    mov rcx, rbx
    rep movsb
    mov rdi, r15
    mov rsi, rbx
    call cdf_unmap
    add qword ptr [r12 + 64], 1
    jc cdf_fatal
    jmp cdf_call_again

# destroy requires the same owning thread, with all external callers stopped.
# All remaining owned Wakers are dropped by the unchanged HIA before unmapping.
cooperative_defer_destroy:
    cdf_enter
    mov r12, rdi
    test r12, r12
    jz cdf_call_invalid
    movabs rax, CDF_CONTEXT_MAGIC
    cmp [r12], rax
    jne cdf_call_invalid
    mov eax, 186
    syscall
    cmp [r12 + 32], rax
    jne cdf_call_invalid
    cmp qword ptr [r12 + 48], 0
    jne cdf_call_invalid
    mov rbx, [r12 + 16]
    cmp qword ptr [rbx], 0
    je cdf_destroy_closed
    movabs rax, CDF_WORK_MAGIC
    cmp [rbx], rax
    jne cdf_fatal
    mov rdi, rsp
    xor eax, eax
    mov ecx, 8
    rep stosq
    movabs rax, CDF_REQUEST_MAGIC
    mov [rsp], rax
    mov qword ptr [rsp + 8], 4
    mov rax, [r12 + 8]
    mov [rsp + 16], rax
    mov rdi, r12
    mov rsi, rsp
    mov edx, 64
    lea rcx, [r12 + 128]
    mov r8d, 64
    call cooperative_defer_call
    cmp rax, 64
    jne cdf_fatal
    mov rbx, [r12 + 16]
cdf_destroy_closed:
    mov rax, [rbx]
    or rax, [rbx + 16]
    or rax, [rbx + 32]
    or rax, [rbx + 40]
    jnz cdf_fatal
    mov rax, [rbx + 8]
    cmp rax, [r12 + 8]
    jne cdf_fatal
    mov qword ptr [r12], 0
    mov rdi, rbx
    mov rsi, [r12 + 24]
    mov qword ptr [r12 + 16], 0
    call cdf_unmap
    mov rdi, r12
    mov esi, 4096
    call cdf_unmap
    xor eax, eax
    cdf_leave

# Guarded anonymous mappings; no Rust/libc/Python dependency in these functions.
cdf_allocate:
    push rbx
    push r12
    push r13
    lea r12, [rdi + 4095]
    and r12, -4096
    lea r13, [r12 + 4096]
    xor edi, edi
    mov rsi, r13
    mov edx, 3
    mov r10d, 0x22
    mov r8, -1
    xor r9d, r9d
    mov eax, 9
    syscall
    cmp rax, -4095
    jae cdf_allocate_failed
    mov rbx, rax
    lea rdi, [rbx + r12]
    mov esi, 4096
    xor edx, edx
    mov eax, 10
    syscall
    test rax, rax
    jnz cdf_allocate_release
    mov rax, rbx
    jmp cdf_allocate_done
cdf_allocate_release:
    mov rdi, rbx
    mov rsi, r13
    mov eax, 11
    syscall
cdf_allocate_failed:
    xor eax, eax
cdf_allocate_done:
    pop r13
    pop r12
    pop rbx
    ret
cdf_unmap:
    add rsi, 4095
    and rsi, -4096
    add rsi, 4096
    mov eax, 11
    syscall
    test rax, rax
    jnz cdf_fatal
    ret
cdf_invoke:
    .byte 0xe8
defer_policy_call_displacement:
    .long 0
    ret
cdf_fatal:
    mov edi, 70
    mov eax, 231
    syscall
    ud2

# Exact borrowed HIA budget owner. This boundary only owns private memory.
.equ CBG_MAGIC, 0x3130544342435248
.equ CBG_REQUEST, 0x3130305142435248
.equ CBG_REPLY, 0x3130305242435248
.macro cbg_enter
    push rbp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub rsp, 72
.endm
.macro cbg_leave
    add rsp, 72
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret
.endm

# create(positive generation) -> context or zero; no TLS replacement.
cooperative_budget_create:
    cbg_enter
    mov r13, rdi
    test r13, r13
    jz cbg_create_failed
    mov edi, 4096
    call cdf_allocate
    test rax, rax
    jz cbg_create_failed
    mov r12, rax
    mov edi, 320
    call cdf_allocate
    test rax, rax
    jz cbg_create_free
    mov [r12 + 16], rax
    mov qword ptr [r12 + 24], 320
    mov [r12 + 8], r13
    mov eax, 186
    syscall
    test rax, rax
    jle cdf_fatal
    mov [r12 + 32], rax
    movabs rax, CBG_MAGIC
    mov [r12], rax
    mov rdi, rsp
    xor eax, eax
    mov ecx, 8
    rep stosq
    movabs rax, CBG_REQUEST
    mov [rsp], rax
    mov [rsp + 16], r13
    mov rdi, r12
    mov rsi, rsp
    mov edx, 64
    lea rcx, [r12 + 192]
    mov r8d, 80
    call cooperative_budget_call
    cmp rax, 80
    jne cdf_fatal
    mov rax, r12
    cbg_leave
cbg_create_free:
    mov rdi, r12
    mov esi, 4096
    call cdf_unmap
cbg_create_failed:
    xor eax, eax
    cbg_leave

# call(context, request64, length, output80, capacity) -> HIA result.
# Input is copied before entry; caller storage is never used as scratch.
cooperative_budget_call:
    cbg_enter
    mov r12, rdi
    mov r13, rsi
    mov r14, rcx
    cmp r8, 80
    jb cbg_capacity
    cmp rdx, 64
    jne cbg_invalid
    test r12, r12
    jz cbg_invalid
    test r13, r13
    jz cbg_invalid
    test r14, r14
    jz cbg_invalid
    movabs rax, CBG_MAGIC
    cmp [r12], rax
    jne cbg_invalid
    mov eax, 186
    syscall
    cmp [r12 + 32], rax
    jne cbg_invalid
    cmp qword ptr [r12 + 40], 0
    jne cbg_invalid
    mov rax, [r13 + 16]
    cmp rax, [r12 + 8]
    jne cbg_invalid
    mov rdi, rsp
    mov rsi, r13
    mov ecx, 8
    cld
    rep movsq
    mov qword ptr [r12 + 40], 1
cbg_again:
    mov rdi, rsp
    mov esi, 64
    lea rdx, [r12 + 192]
    mov ecx, 80
    mov r8, [r12 + 16]
    mov r9, [r12 + 24]
    call cbg_invoke
    add qword ptr [r12 + 48], 1
    jc cdf_fatal
    mov edx, eax
    cmp rax, rdx
    jne cdf_fatal
    cmp eax, 0xfffffffd
    je cbg_grow
    cmp eax, 80
    je cbg_success
    cmp eax, 0xffffffff
    je cbg_return
    cmp eax, 0xfffffffe
    jne cdf_fatal
cbg_return:
    mov qword ptr [r12 + 40], 0
    cbg_leave
cbg_success:
    movabs rax, CBG_REPLY
    cmp [r12 + 192], rax
    jne cdf_fatal
    cmp qword ptr [r12 + 200], 1
    ja cdf_fatal
    mov rax, [r12 + 208]
    cmp rax, [r12 + 8]
    jne cdf_fatal
    mov rax, [r12 + 256]
    or rax, [r12 + 264]
    jnz cdf_fatal
    mov rdi, r14
    lea rsi, [r12 + 192]
    mov ecx, 10
    rep movsq
    mov eax, 80
    jmp cbg_return
cbg_capacity:
    mov eax, 0xfffffffe
    cbg_leave
cbg_invalid:
    mov eax, 0xffffffff
    cbg_leave
cbg_grow:
    mov r15, [r12 + 24]
    cmp r15, 0x7fffffff
    ja cdf_fatal
    mov rdi, r15
    shl rdi, 1
    call cdf_allocate
    test rax, rax
    jz cdf_fatal
    mov rbx, rax
    mov rdi, rax
    mov rsi, [r12 + 16]
    mov rcx, r15
    rep movsb
    mov rdi, [r12 + 16]
    mov rsi, r15
    mov [r12 + 16], rbx
    shl r15, 1
    mov [r12 + 24], r15
    call cdf_unmap
    add qword ptr [r12 + 56], 1
    jc cdf_fatal
    jmp cbg_again

# Requires all actual scopes and RestoreOnPending guards already dropped.
cooperative_budget_destroy:
    cbg_enter
    mov r12, rdi
    test r12, r12
    jz cbg_destroy_invalid
    movabs rax, CBG_MAGIC
    cmp [r12], rax
    jne cbg_destroy_invalid
    mov eax, 186
    syscall
    cmp [r12 + 32], rax
    jne cbg_destroy_invalid
    cmp qword ptr [r12 + 40], 0
    jne cbg_destroy_invalid
    mov rdi, rsp
    xor eax, eax
    mov ecx, 8
    rep stosq
    movabs rax, CBG_REQUEST
    mov [rsp], rax
    mov qword ptr [rsp + 8], 9
    mov rax, [r12 + 8]
    mov [rsp + 16], rax
    mov rdi, r12
    mov rsi, rsp
    mov edx, 64
    lea rcx, [r12 + 192]
    mov r8d, 80
    call cooperative_budget_call
    cmp rax, 80
    jne cbg_destroy_done
    mov rdi, [r12 + 16]
    mov rsi, [r12 + 24]
    mov qword ptr [r12 + 16], 0
    call cdf_unmap
    mov qword ptr [r12], 0
    mov rdi, r12
    mov esi, 4096
    call cdf_unmap
    xor eax, eax
cbg_destroy_done:
    cbg_leave
cbg_destroy_invalid:
    mov eax, 0xffffffff
    cbg_leave
cbg_invoke:
    .byte 0xe8
budget_policy_call_displacement:
    .long 0
    ret

# One physical scheduler-thread execution context; no TLS replacement.
.equ SCS_MAGIC, 0x3130544353435248
.equ SCS_REQUEST, 0x3130305153435248
.equ SCS_REPLY, 0x3130305253435248
.equ SCS_CELL_MAGIC, 0x3130304b57535248
.macro scs_request operation
    lea rdi, [r12 + 128]
    xor eax, eax
    mov ecx, 8
    rep stosq
    movabs rax, SCS_REQUEST
    mov [r12 + 128], rax
    mov qword ptr [r12 + 136], \operation
    mov rax, [r12 + 8]
    mov [r12 + 144], rax
.endm
.macro scs_budget_request operation
    lea rdi, [r12 + 288]
    xor eax, eax
    mov ecx, 8
    rep stosq
    movabs rax, CBG_REQUEST
    mov [r12 + 288], rax
    mov qword ptr [r12 + 296], \operation
    mov rax, [r12 + 8]
    mov [r12 + 304], rax
.endm
.macro scs_defer_request operation
    lea rdi, [r12 + 432]
    xor eax, eax
    mov ecx, 8
    rep stosq
    movabs rax, CDF_REQUEST_MAGIC
    mov [r12 + 432], rax
    mov qword ptr [r12 + 440], \operation
    mov rax, [r12 + 8]
    mov [r12 + 448], rax
.endm

# create(generation, mode 1 current-thread / 2 one multi-thread local worker).
cooperative_scheduler_create:
    cbg_enter
    mov r13, rdi
    mov r14, rsi
    test r13, r13
    jz scs_create_failed
    sub rsi, 1
    cmp rsi, 1
    ja scs_create_failed
    mov edi, 4096
    call cdf_allocate
    test rax, rax
    jz scs_create_failed
    mov r12, rax
    mov [r12 + 8], r13
    mov [r12 + 112], r14
    mov qword ptr [r12 + 104], -1
    movabs rax, SCS_MAGIC
    mov [r12], rax
    mov eax, 186
    syscall
    test rax, rax
    jle cdf_fatal
    mov [r12 + 32], rax
    mov edi, 576
    call cdf_allocate
    test rax, rax
    jz cdf_fatal
    mov [r12 + 16], rax
    mov qword ptr [r12 + 24], 576
    mov rdi, r13
    call cooperative_budget_create
    test rax, rax
    jz cdf_fatal
    mov [r12 + 48], rax
    mov rdi, r12
    mov rsi, r13
    call cooperative_defer_create
    test rax, rax
    jz cdf_fatal
    mov [r12 + 56], rax
    xor edi, edi
    mov esi, 0x80800
    mov eax, 290
    syscall
    test rax, rax
    js cdf_fatal
    mov [r12 + 104], rax
    scs_request 0
    mov [r12 + 160], r14
    call scs_policy
    mov rax, r12
    cbg_leave
scs_create_failed:
    xor eax, eax
    cbg_leave

scs_validate:
    test rdi, rdi
    jz cdf_fatal
    movabs rax, SCS_MAGIC
    cmp [rdi], rax
    jne cdf_fatal
    mov eax, 186
    syscall
    cmp rax, [rdi + 32]
    jne cdf_fatal
    ret

# Internal exact frame; all policy runs stay on the creator thread.
scs_policy:
    cbg_enter
    mov rdi, r12
    call scs_validate
    cmp qword ptr [r12 + 40], 0
    jne cdf_fatal
    mov qword ptr [r12 + 40], 1
    mov rdi, rsp
    lea rsi, [r12 + 128]
    mov ecx, 8
    rep movsq
scs_policy_again:
    mov rdi, rsp
    mov esi, 64
    lea rdx, [r12 + 192]
    mov ecx, 96
    mov r8, [r12 + 16]
    mov r9, [r12 + 24]
    call scs_invoke
    add qword ptr [r12 + 120], 1
    jc cdf_fatal
    cmp eax, 0xfffffffd
    je scs_policy_grow
    cmp rax, 96
    jne cdf_fatal
    movabs rax, SCS_REPLY
    cmp [r12 + 192], rax
    jne cdf_fatal
    mov rax, [r12 + 208]
    cmp [r12 + 8], rax
    jne cdf_fatal
    mov qword ptr [r12 + 40], 0
    mov eax, 96
    cbg_leave
scs_policy_grow:
    mov r15, [r12 + 24]
    cmp r15, 0x7fffffff
    ja cdf_fatal
    mov rdi, r15
    shl rdi, 1
    call cdf_allocate
    test rax, rax
    jz cdf_fatal
    mov rbx, rax
    mov rdi, rax
    mov rsi, [r12 + 16]
    mov rcx, r15
    rep movsb
    mov rdi, [r12 + 16]
    mov rsi, r15
    mov [r12 + 16], rbx
    shl r15, 1
    mov [r12 + 24], r15
    call cdf_unmap
    jmp scs_policy_again

scs_budget:
    sub rsp, 8
    mov rdi, [r12 + 48]
    lea rsi, [r12 + 288]
    mov edx, 64
    lea rcx, [r12 + 352]
    mov r8d, 80
    call cooperative_budget_call
    cmp rax, 80
    jne cdf_fatal
    add rsp, 8
    ret
scs_defer:
    sub rsp, 8
    mov rdi, [r12 + 56]
    lea rsi, [r12 + 432]
    mov edx, 64
    lea rcx, [r12 + 496]
    mov r8d, 64
    call cooperative_defer_call
    cmp rax, 64
    jne cdf_fatal
    add rsp, 8
    ret

# register(context, borrowed task cookie, local wake bool) -> owned Waker cell.
cooperative_scheduler_register:
    cbg_enter
    mov r12, rdi
    mov r13, rsi
    mov r14, rdx
    call scs_validate
    test r13, r13
    jz cdf_fatal
    cmp r14, 1
    ja cdf_fatal
    mov edi, 4096
    call cdf_allocate
    test rax, rax
    jz cdf_fatal
    mov r15, rax
    movabs rax, SCS_CELL_MAGIC
    mov [r15], rax
    mov [r15 + 8], r12
    mov [r15 + 24], r13
    mov qword ptr [r15 + 32], 1
    mov rax, [r12 + 80]
    mov [r15 + 48], rax
    test rax, rax
    jz scs_register_link
    mov [rax + 40], r15
scs_register_link:
    mov [r12 + 80], r15
    add qword ptr [r12 + 88], 1
    jc cdf_fatal
    scs_request 1
    mov [r12 + 152], r15
    mov [r12 + 160], r14
    call scs_policy
    cmp [r12 + 224], r15
    jne cdf_fatal
    mov rax, [r12 + 216]
    test rax, rax
    jz cdf_fatal
    mov [r15 + 16], rax
    mov rax, r15
    cbg_leave

# next(context) -> cell or zero; rdx = 0 selected, 1 idle, 2 batch end.
# Repeated LIFO polls retain the same real Budget scope token.
cooperative_scheduler_next:
    cbg_enter
    mov r12, rdi
    call scs_validate
    cmp qword ptr [r12 + 96], 0
    jne cdf_fatal
    cmp qword ptr [r12 + 64], 0
    je scs_next_begin
    scs_budget_request 7
    call scs_budget
    mov r13, [r12 + 384]
    cmp r13, 1
    ja cdf_fatal
    scs_request 5
    mov [r12 + 160], r13
    jmp scs_next_policy
scs_next_begin:
    scs_request 3
scs_next_policy:
    call scs_policy
    mov r13, [r12 + 200]
    cmp r13, 2
    ja cdf_fatal
    mov r14, [r12 + 224]
    cmp qword ptr [r12 + 232], 0
    je scs_next_check_end
    cmp qword ptr [r12 + 232], 1
    jne cdf_fatal
    cmp qword ptr [r12 + 64], 0
    jne cdf_fatal
    test r13, r13
    jnz cdf_fatal
    scs_budget_request 1
    call scs_budget
    mov rax, [r12 + 376]
    test rax, rax
    jz cdf_fatal
    mov [r12 + 64], rax
scs_next_check_end:
    cmp qword ptr [r12 + 240], 0
    je scs_next_selected
    cmp qword ptr [r12 + 240], 1
    jne cdf_fatal
    cmp r13, 2
    jne cdf_fatal
    mov r15, [r12 + 64]
    test r15, r15
    jz cdf_fatal
    scs_budget_request 3
    mov [r12 + 312], r15
    call scs_budget
    mov qword ptr [r12 + 64], 0
scs_next_selected:
    test r13, r13
    jnz scs_next_empty
    test r14, r14
    jz cdf_fatal
    mov rdi, r14
    call scs_cell_validate
    cmp [r14 + 8], r12
    jne cdf_fatal
    cmp qword ptr [r14 + 56], 0
    jne cdf_fatal
    cmp qword ptr [r12 + 64], 0
    je cdf_fatal
    mov [r12 + 96], r14
    mov rax, r14
    xor edx, edx
    cbg_leave
scs_next_empty:
    test r14, r14
    jnz cdf_fatal
    mov rdx, r13
    xor eax, eax
    cbg_leave

# finish(context, current cell, actual callback Ready bool).
cooperative_scheduler_finish:
    cbg_enter
    mov r12, rdi
    mov r13, rsi
    mov r14, rdx
    call scs_validate
    mov rdi, r13
    call scs_cell_validate
    cmp r14, 1
    ja cdf_fatal
    cmp [r12 + 96], r13
    jne cdf_fatal
    cmp [r13 + 8], r12
    jne cdf_fatal
    scs_request 4
    mov rax, [r13 + 16]
    mov [r12 + 152], rax
    mov [r12 + 160], r14
    call scs_policy
    mov qword ptr [r12 + 96], 0
    xor eax, eax
    cbg_leave

# proceed(context,current cell) -> Restore guard, or zero Pending.
# Pending registers the exact task Waker with the real Defer owner.
cooperative_scheduler_proceed:
    cbg_enter
    mov r12, rdi
    mov r13, rsi
    call scs_validate
    cmp [r12 + 96], r13
    jne cdf_fatal
    test r13, r13
    jz cdf_fatal
    scs_budget_request 4
    mov [r12 + 328], r13
    call scs_budget
    cmp qword ptr [r12 + 360], 0
    je scs_proceed_ready
    cmp qword ptr [r12 + 360], 1
    jne cdf_fatal
    cmp [r12 + 408], r13
    jne cdf_fatal
    scs_defer_request 1
    mov [r12 + 456], r13
    lea rax, [rip + scheduler_waker_table]
    mov [r12 + 464], rax
    mov [r12 + 472], r13
    call scs_defer
    xor eax, eax
    cbg_leave
scs_proceed_ready:
    mov rax, [r12 + 376]
    test rax, rax
    jz cdf_fatal
    cbg_leave

# Successful work marks progress before dropping its Restore guard.
cooperative_scheduler_progress:
    cbg_enter
    mov r12, rdi
    mov r13, rsi
    call scs_validate
    test r13, r13
    jz cdf_fatal
    scs_budget_request 5
    mov [r12 + 312], r13
    call scs_budget
    scs_budget_request 6
    mov [r12 + 312], r13
    call scs_budget
    xor eax, eax
    cbg_leave
cooperative_scheduler_restore:
    cbg_enter
    mov r12, rdi
    mov r13, rsi
    call scs_validate
    test r13, r13
    jz cdf_fatal
    scs_budget_request 6
    mov [r12 + 312], r13
    call scs_budget
    xor eax, eax
    cbg_leave

# Caller first performs the real driver park/yield. No synthetic park receipt.
cooperative_scheduler_after_park:
    cbg_enter
    mov r12, rdi
    call scs_validate
    mov rax, [r12 + 64]
    or rax, [r12 + 96]
    jnz cdf_fatal
    scs_defer_request 3
    call scs_defer
    xor eax, eax
    cbg_leave

# Retire only after actual task completion; cloned Wakers keep their own cell.
cooperative_scheduler_retire:
    cbg_enter
    mov r13, rdi
    call scs_cell_validate
    mov r12, [r13 + 8]
    mov rdi, r12
    call scs_validate
    cmp [r12 + 96], r13
    je cdf_fatal
    cmp qword ptr [r13 + 56], 0
    jne cdf_fatal
    scs_request 7
    mov rax, [r13 + 16]
    mov [r12 + 152], rax
    call scs_policy
    mov qword ptr [r13 + 24], 0
    mov qword ptr [r13 + 56], 1
    mov rdi, r13
    call scs_cell_release
    xor eax, eax
    cbg_leave

cooperative_scheduler_destroy:
    cbg_enter
    mov r12, rdi
    call scs_validate
    mov rax, [r12 + 608]
    or rax, [r12 + 616]
    or rax, [r12 + 624]
    jnz cdf_fatal
    mov rax, [r12 + 64]
    or rax, [r12 + 96]
    jnz cdf_fatal
    scs_request 8
    call scs_policy
    mov rdi, [r12 + 56]
    call cooperative_defer_destroy
    test rax, rax
    jnz cdf_fatal
    mov qword ptr [r12 + 56], 0
    mov rax, [r12 + 80]
    or rax, [r12 + 88]
    jnz cdf_fatal
    mov rdi, [r12 + 48]
    call cooperative_budget_destroy
    test rax, rax
    jnz cdf_fatal
    mov qword ptr [r12 + 48], 0
    mov rdi, [r12 + 104]
    mov qword ptr [r12 + 104], -1
    mov eax, 3
    syscall
    mov rdi, [r12 + 16]
    mov rsi, [r12 + 24]
    mov qword ptr [r12 + 16], 0
    call cdf_unmap
    mov qword ptr [r12], 0
    mov rdi, r12
    mov esi, 4096
    call cdf_unmap
    xor eax, eax
    cbg_leave
scs_invoke:
    .byte 0xe8
scheduler_policy_call_displacement:
    .long 0
    ret

# Batch qualification adds optional observations after the actual Defer hooks.
# Scheduler/Waker operations and all HIA semantic images are unchanged.
# Actual owned task Wakers. Cells remain live after their task stack retires.
# This first callable is confined to its physical worker's creator thread.
scs_cell_validate:
    push rbx
    mov rbx, rdi
    test rbx, rbx
    jz cdf_fatal
    movabs rax, SCS_CELL_MAGIC
    cmp [rbx], rax
    jne cdf_fatal
    cmp qword ptr [rbx + 32], 0
    je cdf_fatal
    mov rdi, [rbx + 8]
    call scs_validate
    mov rdi, rbx
    pop rbx
    ret

cooperative_scheduler_retain:
    sub rsp, 8
    call scs_cell_validate
    lock add qword ptr [rdi + 32], 1
    jc cdf_fatal
    mov rax, rdi
    add rsp, 8
    ret

cooperative_scheduler_release:
    jmp scs_cell_release
scs_cell_release:
    cbg_enter
    mov r13, rdi
    call scs_cell_validate
    mov r12, [r13 + 8]
    lock sub qword ptr [r13 + 32], 1
    jc cdf_fatal
    jnz scs_cell_release_done
    cmp qword ptr [r13 + 56], 1
    jne cdf_fatal
    cmp qword ptr [r13 + 24], 0
    jne cdf_fatal
    mov rax, [r13 + 40]
    mov rdx, [r13 + 48]
    test rax, rax
    jz scs_cell_release_head
    cmp [rax + 48], r13
    jne cdf_fatal
    mov [rax + 48], rdx
    jmp scs_cell_release_next
scs_cell_release_head:
    cmp [r12 + 80], r13
    jne cdf_fatal
    mov [r12 + 80], rdx
scs_cell_release_next:
    test rdx, rdx
    jz scs_cell_release_count
    cmp [rdx + 40], r13
    jne cdf_fatal
    mov [rdx + 40], rax
scs_cell_release_count:
    sub qword ptr [r12 + 88], 1
    jc cdf_fatal
    mov qword ptr [r13], 0
    mov rdi, r13
    mov esi, 4096
    call cdf_unmap
scs_cell_release_done:
    xor eax, eax
    cbg_leave

# notify(cell, yield bool, local bool); state/queue decisions are all HIA.
cooperative_scheduler_notify:
    cbg_enter
    mov r13, rdi
    mov r14, rsi
    mov r15, rdx
    call scs_cell_validate
    cmp r14, 1
    ja cdf_fatal
    cmp r15, 1
    ja cdf_fatal
    mov r12, [r13 + 8]
    scs_request 2
    mov rax, [r13 + 16]
    mov [r12 + 152], rax
    mov [r12 + 160], r14
    mov [r12 + 168], r15
    call scs_policy
    cmp qword ptr [r12 + 232], 0
    je scs_notify_done
    cmp qword ptr [r12 + 232], 1
    jne cdf_fatal
    mov qword ptr [rsp], 1
scs_notify_signal:
    mov rdi, [r12 + 104]
    mov rsi, rsp
    mov edx, 8
    mov eax, 1
    syscall
    cmp rax, -4
    je scs_notify_signal
    cmp rax, -11
    je scs_notify_done
    cmp rax, 8
    jne cdf_fatal
scs_notify_done:
    xor eax, eax
    cbg_leave

# Defer uses fixed clone/wake/drop hooks, with real cell references.
cooperative_waker_clone:
    cbg_enter
    mov r12, rdi
    mov r13, rsi
    mov r14, rdx
    mov r15, rcx
    mov rbx, r8
    mov rdi, r13
    call scs_cell_validate
    cmp [r13 + 8], r12
    jne cdf_fatal
    cmp r15, r13
    jne cdf_fatal
    lea rax, [rip + scheduler_waker_table]
    cmp r14, rax
    jne cdf_fatal
    test rbx, rbx
    jz cdf_fatal
    mov rdi, r13
    call cooperative_scheduler_retain
    mov [rbx], r13
    mov [rbx + 8], r14
    mov [rbx + 16], r13
    add qword ptr [r12 + 568], 1
    jc cdf_fatal
    mov rdi, [r12 + 632]
    mov esi, 1
    mov rdx, r13
    call oneshot_observe
    xor eax, eax
    cbg_leave
cooperative_waker_wake:
    cbg_enter
    mov r12, rdi
    mov r13, rsi
    mov r14, rdx
    mov r15, rcx
    mov rdi, r13
    call scs_cell_validate
    cmp [r13 + 8], r12
    jne cdf_fatal
    cmp r15, r13
    jne cdf_fatal
    lea rax, [rip + scheduler_waker_table]
    cmp r14, rax
    jne cdf_fatal
    mov rdi, r13
    xor esi, esi
    mov edx, 1
    call cooperative_scheduler_notify
    add qword ptr [r12 + 576], 1
    jc cdf_fatal
    mov rdi, r13
    call scs_cell_release
    mov rdi, [r12 + 632]
    mov esi, 4
    mov rdx, r13
    call oneshot_observe
    xor eax, eax
    cbg_leave
cooperative_waker_drop:
    cbg_enter
    mov r12, rdi
    mov r13, rsi
    mov r14, rdx
    mov r15, rcx
    mov rdi, r13
    call scs_cell_validate
    cmp [r13 + 8], r12
    jne cdf_fatal
    cmp r15, r13
    jne cdf_fatal
    lea rax, [rip + scheduler_waker_table]
    cmp r14, rax
    jne cdf_fatal
    add qword ptr [r12 + 584], 1
    jc cdf_fatal
    mov rdi, r13
    call scs_cell_release
    mov rdi, [r12 + 632]
    mov esi, 2
    mov rdx, r13
    call oneshot_observe
    xor eax, eax
    cbg_leave
.balign 8
scheduler_waker_table:
    .quad 0x3130545657435348

# Unique typed-value custody. Typed destruction decisions stay in the HIA entry.
# Shared ABI: VALUE-LEASE-ABI-v1.md. Requires cdf_allocate/cdf_unmap/cbg_enter.
.equ VL_MAGIC, 0x313030534c565248

# create(bytes, length, positive generation, admitted typed drop entry, cookie).
value_lease_create:
    cbg_enter
    mov r13, rdi
    mov r14, rsi
    mov r15, rdx
    mov rbp, rcx
    mov [rsp], r8
    test r15, r15
    jz vl_create_invalid
    test rbp, rbp
    jz vl_create_invalid
    test r8, r8
    jz vl_create_invalid
    movabs rax, 0x7fffffffffffd000
    cmp r14, rax
    ja vl_create_invalid
    test r14, r14
    jz vl_create_allocate
    test r13, r13
    jz vl_create_invalid
vl_create_allocate:
    mov edi, 4096
    call cdf_allocate
    test rax, rax
    jz vl_create_invalid
    mov r12, rax
    mov [r12 + 8], r15
    mov [r12 + 24], r14
    mov [r12 + 32], rbp
    mov rax, [rsp]
    mov [r12 + 40], rax
    mov qword ptr [r12 + 64], 4096
    mov rdi, r14
    test rdi, rdi
    jnz vl_create_payload
    mov edi, 1
vl_create_payload:
    mov [r12 + 48], rdi
    call cdf_allocate
    test rax, rax
    jz vl_create_free_descriptor
    mov [r12 + 16], rax
    mov rdi, rax
    mov rsi, r13
    mov rcx, r14
    cld
    rep movsb
    mov rdi, [r12 + 16]
    mov rsi, [r12 + 48]
    mov edx, 1
    mov eax, 10
    syscall
    test rax, rax
    jnz vl_create_free_payload
    mov eax, 186
    syscall
    test rax, rax
    jle cdf_fatal
    mov [r12 + 56], rax
    movabs rax, VL_MAGIC
    mov [r12], rax
    mov rdi, r12
    mov esi, 4096
    mov edx, 1
    mov eax, 10
    syscall
    test rax, rax
    jnz vl_create_free_payload
    mov rax, r12
    cbg_leave
vl_create_free_payload:
    mov rdi, [r12 + 16]
    mov rsi, [r12 + 48]
    call cdf_unmap
vl_create_free_descriptor:
    mov rdi, r12
    mov esi, 4096
    call cdf_unmap
vl_create_invalid:
    xor eax, eax
    cbg_leave

# Unsafe internal handle validation. RDI remains the borrowed descriptor.
vl_validate:
    test rdi, rdi
    jz cdf_fatal
    movabs rax, VL_MAGIC
    cmp [rdi], rax
    jne cdf_fatal
    cmp qword ptr [rdi + 8], 0
    je cdf_fatal
    cmp qword ptr [rdi + 16], 0
    je cdf_fatal
    cmp qword ptr [rdi + 32], 0
    je cdf_fatal
    cmp qword ptr [rdi + 40], 0
    je cdf_fatal
    movabs rax, 0x7fffffffffffd000
    cmp [rdi + 24], rax
    ja cdf_fatal
    mov rax, [rdi + 24]
    test rax, rax
    jnz vl_validate_size
    mov eax, 1
vl_validate_size:
    cmp [rdi + 48], rax
    jne cdf_fatal
    cmp qword ptr [rdi + 64], 4096
    jne cdf_fatal
    cmp qword ptr [rdi + 72], 0
    jne cdf_fatal
    mov eax, 186
    syscall
    cmp [rdi + 56], rax
    jne cdf_fatal
    ret

value_lease_span:
    sub rsp, 8
    call vl_validate
    mov rax, [rdi + 16]
    mov rdx, [rdi + 24]
    add rsp, 8
    ret

# Consume only after an HIA owner requests typed destruction.
value_lease_drop:
    cbg_enter
    mov r12, rdi
    call vl_validate
    mov rdi, [r12 + 40]
    mov rsi, [r12 + 16]
    mov rdx, [r12 + 24]
    mov rcx, [r12 + 8]
    mov r8, r12
    call qword ptr [r12 + 32]
    test rax, rax
    jnz cdf_fatal
    mov rdi, [r12 + 16]
    mov rsi, [r12 + 48]
    call cdf_unmap
    mov rdi, r12
    mov esi, 4096
    call cdf_unmap
    xor eax, eax
    cbg_leave

# Fixed callable ABI, private mappings and real callbacks; no channel policy.
.equ ON_CONTEXT, 0x313030434e4f5248
.equ ON_REQUEST, 0x313030514e4f5248
.equ ON_RESPONSE, 0x313030524e4f5248
.equ ON_ACTION, 0x313030414e4f5248
.equ ON_STATS, 0x313030534e4f5248
.equ ON_OBSERVER, 0x31303053424f5248

# create(scheduler, positive generation, optional observer) -> context or zero.
oneshot_create:
    cbg_enter
    mov r13, rdi
    mov r14, rsi
    mov r15, rdx
    call scs_validate
    test r14, r14
    jz on_create_failed
    mov edi, 4096
    call cdf_allocate
    test rax, rax
    jz on_create_failed
    mov r12, rax
    mov [r12 + 8], r14
    mov [r12 + 48], r13
    mov [r12 + 104], r15
    mov edi, 2048
    call cdf_allocate
    test rax, rax
    jz on_create_free
    mov [r12 + 16], rax
    mov qword ptr [r12 + 24], 2048
    mov eax, 186
    syscall
    test rax, rax
    jle cdf_fatal
    mov [r12 + 32], rax
    movabs rax, ON_CONTEXT
    mov [r12], rax
    movabs rax, ON_REQUEST
    mov [r12 + 384], rax
    mov qword ptr [r12 + 392], 1
    mov [r12 + 400], r14
    mov rdi, r12
    lea rsi, [r12 + 384]
    mov edx, 80
    lea rcx, [r12 + 256]
    mov r8d, 80
    call oneshot_call
    cmp rax, 80
    jne cdf_fatal
    mov rax, r12
    cbg_leave
on_create_free:
    mov rdi, r12
    mov esi, 4096
    call cdf_unmap
on_create_failed:
    xor eax, eax
    cbg_leave

# Unsafe internal context validation: no global address registry.
on_validate:
    test rdi, rdi
    jz cdf_fatal
    movabs rax, ON_CONTEXT
    cmp [rdi], rax
    jne cdf_fatal
    mov eax, 186
    syscall
    cmp [rdi + 32], rax
    jne cdf_fatal
    cmp qword ptr [rdi + 24], 2048
    jne cdf_fatal
    ret

# call(context, borrowed request, bytes, borrowed output, capacity) -> u32.
oneshot_call:
    cbg_enter
    mov r12, rdi
    mov r13, rsi
    mov r14, rcx
    cmp r8, 80
    jb on_capacity
    cmp rdx, 80
    jne on_invalid
    test r12, r12
    jz on_invalid
    test r13, r13
    jz on_invalid
    test r14, r14
    jz on_invalid
    movabs rax, ON_CONTEXT
    cmp [r12], rax
    jne on_invalid
    mov eax, 186
    syscall
    cmp [r12 + 32], rax
    jne on_invalid
    cmp qword ptr [r12 + 40], 0
    jne on_invalid
    mov rax, [r13 + 16]
    cmp [r12 + 8], rax
    jne on_invalid
    mov edi, 80
    call cdf_allocate
    test rax, rax
    jz cdf_fatal
    mov [r12 + 56], rax
    mov rdi, rax
    mov rsi, r13
    mov ecx, 10
    cld
    rep movsq
    mov rdi, [r12 + 56]
    mov esi, 80
    mov edx, 1
    mov eax, 10
    syscall
    test rax, rax
    jnz cdf_fatal
    mov qword ptr [r12 + 40], 1
on_call_again:
    mov rdi, [r12 + 56]
    mov esi, 80
    lea rdx, [r12 + 256]
    mov ecx, 80
    mov r8, [r12 + 16]
    mov r9, [r12 + 24]
    call on_invoke
    add qword ptr [r12 + 72], 1
    jc cdf_fatal
    mov edx, eax
    cmp rdx, rax
    jne cdf_fatal
    cmp eax, 0xfffffff0
    je on_call_effect
    mov r15, rax
    cmp eax, 80
    je on_call_success
    cmp eax, 0xffffffff
    je on_call_return
    cmp eax, 0xfffffffe
    jne cdf_fatal
    jmp on_call_return
on_call_effect:
    mov rdi, r12
    call on_effect
    jmp on_call_again
on_call_success:
    movabs rax, ON_RESPONSE
    cmp [r12 + 256], rax
    jne cdf_fatal
    cmp qword ptr [r12 + 264], 10
    ja cdf_fatal
    mov rax, [r12 + 272]
    cmp [r12 + 8], rax
    jne cdf_fatal
    cmp qword ptr [r12 + 296], 31
    ja cdf_fatal
    cmp qword ptr [r12 + 304], 1
    ja cdf_fatal
    mov rax, [r12 + 312]
    or rax, [r12 + 320]
    or rax, [r12 + 328]
    jnz cdf_fatal
    mov rdi, r14
    lea rsi, [r12 + 256]
    mov ecx, 10
    cld
    rep movsq
on_call_return:
    cmp qword ptr [r12 + 112], 0
    jne cdf_fatal
    mov rbx, [r12 + 16]
    cmp qword ptr [rbx + 80], 0
    jne cdf_fatal
    mov rdi, [r12 + 56]
    mov esi, 80
    call cdf_unmap
    mov qword ptr [r12 + 56], 0
    mov qword ptr [r12 + 40], 0
    mov rax, r15
    cbg_leave
on_invalid:
    mov eax, 0xffffffff
    cbg_leave
on_capacity:
    mov eax, 0xfffffffe
    cbg_leave

# Snapshot and execute one exact HIA-requested physical effect.
on_effect:
    cbg_enter
    mov r12, rdi
    call on_validate
    mov rbx, [r12 + 16]
    movabs rax, ON_ACTION
    cmp [rbx + 512], rax
    jne cdf_fatal
    mov r14, [rbx + 520]
    lea rax, [r14 - 1]
    cmp rax, 6
    ja cdf_fatal
    mov rax, [r12 + 88]
    add rax, 1
    jc cdf_fatal
    cmp [rbx + 528], rax
    jne cdf_fatal
    mov rax, [r12 + 8]
    cmp [rbx + 536], rax
    jne cdf_fatal
    mov r13, [rbx + 544]
    test r13, r13
    jz cdf_fatal
    mov rax, [rbx + 552]
    or rax, [rbx + 560]
    or rax, [rbx + 568]
    or rax, [rbx + 576]
    or rax, [rbx + 600]
    or rax, [rbx + 608]
    or rax, [rbx + 616]
    or rax, [rbx + 624]
    or rax, [rbx + 632]
    jnz cdf_fatal
    cmp qword ptr [rbx + 584], 1024
    jne cdf_fatal
    cmp qword ptr [rbx + 592], 32
    jne cdf_fatal
    lea rdi, [r12 + 128]
    lea rsi, [rbx + 512]
    mov ecx, 16
    cld
    rep movsq
    cmp r14, 1
    je on_effect_budget
    cmp r14, 2
    je on_effect_progress
    cmp r14, 3
    je on_effect_restore
    cmp r14, 7
    je on_effect_drop_value
    mov rdi, r13
    call scs_cell_validate
    mov rax, [r12 + 48]
    cmp [r13 + 8], rax
    jne cdf_fatal
    cmp r14, 4
    je on_effect_retain
    cmp r14, 5
    je on_effect_wake
    cmp qword ptr [r12 + 64], 0
    je cdf_fatal
    mov rdi, r13
    call cooperative_scheduler_release
    test rax, rax
    jnz cdf_fatal
    sub qword ptr [r12 + 64], 1
    jc cdf_fatal
    mov esi, 2
    jmp on_effect_observe
on_effect_retain:
    mov rdi, r13
    call cooperative_scheduler_retain
    cmp rax, r13
    jne cdf_fatal
    add qword ptr [r12 + 64], 1
    jc cdf_fatal
    mov esi, 1
    jmp on_effect_observe
on_effect_wake:
    mov rax, [r12 + 48]
    mov rdx, [rax + 64]
    or rdx, [rax + 616]
    setne dl
    movzx edx, dl
    xor esi, esi
    mov rdi, r13
    call cooperative_scheduler_notify
    test rax, rax
    jnz cdf_fatal
    mov esi, 3
on_effect_observe:
    mov rdi, [r12 + 104]
    mov rdx, r13
    call oneshot_observe
    jmp on_effect_complete
on_effect_budget:
    cmp qword ptr [r12 + 112], 0
    jne cdf_fatal
    mov rdi, [r12 + 48]
    mov rsi, r13
    call cooperative_scheduler_proceed
    mov [r12 + 112], rax
    mov [rbx + 1024], rax
    jmp on_effect_complete
on_effect_progress:
    cmp [r12 + 112], r13
    jne cdf_fatal
    mov rdi, [r12 + 48]
    mov rsi, r13
    call cooperative_scheduler_progress
    jmp on_effect_guard_done
on_effect_restore:
    cmp [r12 + 112], r13
    jne cdf_fatal
    mov rdi, [r12 + 48]
    mov rsi, r13
    call cooperative_scheduler_restore
on_effect_guard_done:
    test rax, rax
    jnz cdf_fatal
    mov qword ptr [r12 + 112], 0
    jmp on_effect_complete
on_effect_drop_value:
    mov rdi, r13
    call value_lease_drop
    test rax, rax
    jnz cdf_fatal
    add qword ptr [r12 + 96], 1
    jc cdf_fatal
on_effect_complete:
    lea rdi, [r12 + 128]
    lea rsi, [rbx + 512]
    mov ecx, 16
    cld
    repe cmpsq
    jne cdf_fatal
    mov qword ptr [rbx + 600], 1
    cmp r14, 1
    jne on_effect_record
    mov qword ptr [rbx + 616], 8
on_effect_record:
    mov rax, [r12 + 144]
    mov [r12 + 88], rax
    add qword ptr [r12 + 80], 1
    jc cdf_fatal
    xor eax, eax
    cbg_leave

# Observe completed real callbacks only. Optional borrowed observer descriptor:
# magic, writable record pointer, record capacity, completed record count.
oneshot_observe:
    test rdi, rdi
    jz on_observe_done
    movabs rax, ON_OBSERVER
    cmp [rdi], rax
    jne cdf_fatal
    mov rax, [rdi + 24]
    cmp rax, [rdi + 16]
    jae cdf_fatal
    mov r9, [rdi + 8]
    test r9, r9
    jz cdf_fatal
    mov r10, rax
    shl r10, 4
    jc cdf_fatal
    mov [r9 + r10], rsi
    mov [r9 + r10 + 8], rdx
    add rax, 1
    jc cdf_fatal
    mov [rdi + 24], rax
on_observe_done:
    xor eax, eax
    ret

# stats(context, output80, capacity) -> zero; physical counts only.
oneshot_stats:
    cbg_enter
    mov r12, rdi
    mov r13, rsi
    cmp rdx, 80
    jb on_capacity
    test r13, r13
    jz on_invalid
    call on_validate
    movabs rax, ON_STATS
    mov [r13], rax
    mov rax, [r12 + 8]
    mov [r13 + 8], rax
    mov rax, [r12 + 64]
    mov [r13 + 16], rax
    mov rax, [r12 + 72]
    mov [r13 + 24], rax
    mov rax, [r12 + 80]
    mov [r13 + 32], rax
    mov rax, [r12 + 88]
    mov [r13 + 40], rax
    mov rax, [r12 + 96]
    mov [r13 + 48], rax
    mov rax, [r12 + 112]
    mov [r13 + 56], rax
    mov rax, [r12 + 40]
    mov [r13 + 64], rax
    mov qword ptr [r13 + 72], 0
    xor eax, eax
    cbg_leave

# HIA retire must have run after both endpoints and all leases were consumed.
oneshot_destroy:
    cbg_enter
    mov r12, rdi
    call on_validate
    mov rax, [r12 + 40]
    or rax, [r12 + 56]
    or rax, [r12 + 64]
    or rax, [r12 + 112]
    jnz on_invalid
    mov rbx, [r12 + 16]
    cmp qword ptr [rbx], 0
    jne on_invalid
    mov rax, [r12 + 8]
    cmp [rbx + 8], rax
    jne on_invalid
    mov ecx, 16
on_destroy_check:
    cmp qword ptr [rbx + rcx], 0
    jne on_invalid
    add rcx, 8
    cmp rcx, 2048
    jb on_destroy_check
    mov rdi, rbx
    mov esi, 2048
    call cdf_unmap
    mov qword ptr [r12], 0
    mov rdi, r12
    mov esi, 4096
    call cdf_unmap
    xor eax, eax
    cbg_leave

on_invoke:
    .byte 0xe8
oneshot_policy_call_displacement:
    .long 0
    ret

# Qualification-only adapter to an actual typed HIA destructor entry.
.equ OP_CONTEXT, 0x3130304350565248
.equ OP_RESPONSE, 0x3130305244565248

# create(optional physical-callback observer) -> private typed context.
probe_create:
    cbg_enter
    mov r13, rdi
    mov edi, 4096
    call cdf_allocate
    test rax, rax
    jz cdf_fatal
    mov r12, rax
    mov edi, 65568
    call cdf_allocate
    test rax, rax
    jz cdf_fatal
    mov [r12 + 8], rax
    mov qword ptr [r12 + 16], 65568
    mov [r12 + 32], r13
    mov eax, 186
    syscall
    test rax, rax
    jle cdf_fatal
    mov [r12 + 24], rax
    movabs rax, OP_CONTEXT
    mov [r12], rax
    mov rax, r12
    cbg_leave

probe_validate:
    test rdi, rdi
    jz cdf_fatal
    movabs rax, OP_CONTEXT
    cmp [rdi], rax
    jne cdf_fatal
    mov eax, 186
    syscall
    cmp [rdi + 24], rax
    jne cdf_fatal
    cmp qword ptr [rdi + 16], 65568
    jne cdf_fatal
    ret

# Typed destructor(cookie, bytes, length, generation, live value lease).
probe_drop_entry:
    cbg_enter
    mov r12, rdi
    mov r13, rsi
    mov r14, rdx
    mov r15, rcx
    mov rbx, r8
    call probe_validate
    cmp qword ptr [r12 + 40], 0
    jne cdf_fatal
    mov rdi, rbx
    call vl_validate
    cmp [rbx + 8], r15
    jne cdf_fatal
    cmp [rbx + 16], r13
    jne cdf_fatal
    cmp [rbx + 24], r14
    jne cdf_fatal
    lea rax, [rip + probe_drop_entry]
    cmp [rbx + 32], rax
    jne cdf_fatal
    cmp [rbx + 40], r12
    jne cdf_fatal
    mov qword ptr [r12 + 40], 1
    mov rdi, r13
    mov rsi, r14
    lea rdx, [r12 + 128]
    mov ecx, 64
    mov r8, [r12 + 8]
    mov r9, [r12 + 16]
    call probe_invoke
    add qword ptr [r12 + 48], 1
    jc cdf_fatal
    cmp rax, 64
    jne cdf_fatal
    movabs rax, OP_RESPONSE
    cmp [r12 + 128], rax
    jne cdf_fatal
    mov rax, [r13 + 8]
    cmp [r12 + 136], rax
    jne cdf_fatal
    mov rax, [r12 + 8]
    mov rax, [rax + 8]
    cmp [r12 + 144], rax
    jne cdf_fatal
    mov rdi, [r12 + 32]
    mov esi, 5
    mov rdx, rbx
    call oneshot_observe
    mov qword ptr [r12 + 40], 0
    xor eax, eax
    cbg_leave

# Caller has already consumed all values borrowing this typed context.
probe_destroy:
    cbg_enter
    mov r12, rdi
    call probe_validate
    cmp qword ptr [r12 + 40], 0
    jne cdf_fatal
    mov rdi, [r12 + 8]
    mov rsi, [r12 + 16]
    call cdf_unmap
    mov qword ptr [r12], 0
    mov rdi, r12
    mov esi, 4096
    call cdf_unmap
    xor eax, eax
    cbg_leave

probe_invoke:
    .byte 0xe8
probe_policy_call_displacement:
    .long 0
    ret

# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
# Physical custody for the HIA YieldNow state and read-only batch observations.
.equ YNC_MAGIC, 0x313030434e595248
.equ YNC_REQUEST, 0x313030514e595248
.equ YNC_RESPONSE, 0x313030524e595248
.equ YNC_ACTION, 0x313030414e595248
# create(generation, scheduler) -> context. All future decisions reside in HIA.
yield_now_create:
    cbg_enter
    mov r13, rdi
    mov r14, rsi
    test r13, r13
    jz cdf_fatal
    mov rdi, r14
    call scs_validate
    mov edi, 4096
    call cdf_allocate
    test rax, rax
    jz cdf_fatal
    mov r12, rax
    movabs rax, YNC_MAGIC
    mov [r12], rax
    mov [r12 + 8], r13
    mov [r12 + 40], r14
    mov eax, 186
    syscall
    mov [r12 + 24], rax
    mov edi, 256
    call cdf_allocate
    test rax, rax
    jz cdf_fatal
    mov [r12 + 16], rax
    movabs rax, YNC_REQUEST
    mov [r12 + 128], rax
    mov [r12 + 144], r13
    call ync_invoke_private
    cmp eax, 32
    jne cdf_fatal
    cmp qword ptr [r12 + 72], 0
    jne cdf_fatal
    mov rax, r12
    cbg_leave
ync_validate:
    test rdi, rdi
    jz cdf_fatal
    movabs rax, YNC_MAGIC
    cmp [rdi], rax
    jne cdf_fatal
    mov eax, 186
    syscall
    cmp [rdi + 24], rax
    jne cdf_fatal
    ret
ync_invoke_private:
    sub rsp, 8
    lea rdi, [r12 + 128]
    mov esi, 64
    lea rdx, [r12 + 64]
    mov ecx, 32
    mov r8, [r12 + 16]
    mov r9d, 256
    call ync_invoke
    add qword ptr [r12 + 48], 1
    jc cdf_fatal
    cmp eax, 0xfffffff0
    je ync_invoke_return
    cmp rax, 32
    jne cdf_fatal
    movabs rdx, YNC_RESPONSE
    cmp [r12 + 64], rdx
    jne cdf_fatal
    cmp qword ptr [r12 + 72], 1
    ja cdf_fatal
    mov rdx, [r12 + 8]
    cmp [r12 + 80], rdx
    jne cdf_fatal
    cmp qword ptr [r12 + 88], 0
    jne cdf_fatal
ync_invoke_return:
    add rsp, 8
    ret
# poll(context,current task cell) -> 0 Ready / 1 Pending, from actual HIA response.
yield_now_poll:
    cbg_enter
    mov r12, rdi
    mov r13, rsi
    call ync_validate
    cmp qword ptr [r12 + 32], 0
    jne cdf_fatal
    mov r14, [r12 + 40]
    mov rdi, r14
    call scs_validate
    cmp [r14 + 96], r13
    jne cdf_fatal
    mov rdi, r13
    call scs_cell_validate
    cmp [r13 + 8], r14
    jne cdf_fatal
    mov qword ptr [r12 + 32], 1
    mov qword ptr [r12 + 136], 1
    mov [r12 + 152], r13
    call ync_invoke_private
    cmp eax, 32
    je ync_poll_return
    mov rbx, [r12 + 16]
    movabs rax, YNC_ACTION
    cmp [rbx + 128], rax
    jne cdf_fatal
    cmp qword ptr [rbx + 136], 1
    jne cdf_fatal
    mov rax, [r12 + 8]
    cmp [rbx + 144], rax
    jne cdf_fatal
    cmp [rbx + 152], r13
    jne cdf_fatal
    mov rax, [rbx + 160]
    or rax, [rbx + 168]
    or rax, [rbx + 176]
    or rax, [rbx + 184]
    jnz cdf_fatal
    mov rdi, rsp
    lea rsi, [rbx + 128]
    mov ecx, 8
    rep movsq
    mov rdi, r14
    mov rsi, r13
    call cooperative_scheduler_defer_current
    test rax, rax
    jnz cdf_fatal
    mov rdi, rsp
    lea rsi, [rbx + 128]
    mov ecx, 8
    repe cmpsq
    jne cdf_fatal
    mov qword ptr [rbx + 160], 1
    add qword ptr [r12 + 56], 1
    jc cdf_fatal
    call ync_invoke_private
    cmp eax, 32
    jne cdf_fatal
    cmp qword ptr [r12 + 72], 1
    jne cdf_fatal
ync_poll_return:
    mov qword ptr [r12 + 32], 0
    mov rax, [r12 + 72]
    cbg_leave
yield_now_destroy:
    cbg_enter
    mov r12, rdi
    call ync_validate
    cmp qword ptr [r12 + 32], 0
    jne cdf_fatal
    mov rdi, [r12 + 16]
    cmp qword ptr [rdi + 24], 0
    jne cdf_fatal
    mov esi, 256
    call cdf_unmap
    mov qword ptr [r12], 0
    mov rdi, r12
    mov esi, 4096
    call cdf_unmap
    xor eax, eax
    cbg_leave
ync_invoke:
    .byte 0xe8
yield_policy_call_displacement:
    .long 0
    ret

# This helper is exactly the existing actual scheduler/Defer registration path.
cooperative_scheduler_defer_current:
    cbg_enter
    mov r12, rdi
    mov r13, rsi
    call scs_validate
    cmp [r12 + 96], r13
    jne cdf_fatal
    test r13, r13
    jz cdf_fatal
    scs_defer_request 1
    mov [r12 + 456], r13
    lea rax, [rip + scheduler_waker_table]
    mov [r12 + 464], rax
    mov [r12 + 472], r13
    call scs_defer
    xor eax, eax
    cbg_leave

# Optional borrowed observation memory; no scheduler policy or Waker registry.
batch_observer_attach:
    cbg_enter
    mov r12, rdi
    mov r13, rsi
    call scs_validate
    cmp qword ptr [r12 + 96], 0
    jne cdf_fatal
    test r13, r13
    jz batch_attach_store
    movabs rax, ON_OBSERVER
    cmp [r13], rax
    jne cdf_fatal
batch_attach_store:
    mov [r12 + 632], r13
    xor eax, eax
    cbg_leave
# Return the actual HIA Budget.has_budget_remaining observation; no budget write.
batch_budget_remaining:
    cbg_enter
    mov r12, rdi
    call scs_validate
    scs_budget_request 7
    call scs_budget
    mov rax, [r12 + 384]
    cmp rax, 1
    ja cdf_fatal
    cbg_leave

# The batch fixture owns a real canonical Waker reference in addition to the
# task cell's baseline owner. Its actual release is observed before owner retire.
batch_anchor_drop:
    cbg_enter
    mov r13, rdi
    call scs_cell_validate
    mov r12, [r13 + 8]
    cmp qword ptr [r12 + 96], 0
    jne cdf_fatal
    cmp qword ptr [r13 + 32], 2
    jb cdf_fatal
    mov rdi, r13
    call cooperative_scheduler_release
    test rax, rax
    jnz cdf_fatal
    mov rdi, [r12 + 632]
    mov esi, 2
    mov rdx, r13
    call oneshot_observe
    xor eax, eax
    cbg_leave

# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
# Private invocation memory and fixed physical typed-drop effects only.
# Each recursive destructor receives its own arena. No shared channel lock is held.
.equ TD_REQUEST, 0x3130305144545248
.equ TD_RESPONSE, 0x3130305244545248
.equ TD_ACTION, 0x3130304144545248
.equ TD_OBSERVER, 0x3130304f44545248

owned_oneshot_handle_drop_entry:
    mov r9d, 1
    jmp td_drop_entry
session_event_drop_entry:
    mov r9d, 2
    jmp td_drop_entry

# Existing ValueLease callback ABI:
# cookie SC, actual RO payload, length, lease generation, own descriptor.
td_drop_entry:
    cbg_enter
    mov [rsp], rdi
    mov [rsp + 8], rsi
    mov [rsp + 16], rdx
    mov [rsp + 24], rcx
    mov [rsp + 32], r8
    mov [rsp + 40], r9
    mov rdi, r8
    call vl_validate
    mov rbx, [rsp + 32]
    mov rax, [rsp + 8]
    cmp [rbx + 16], rax
    jne cdf_fatal
    mov rax, [rsp + 16]
    cmp rax, 128
    ja cdf_fatal
    cmp [rbx + 24], rax
    jne cdf_fatal
    mov rax, [rsp + 24]
    cmp [rbx + 8], rax
    jne cdf_fatal
    mov rdi, [rsp]
    cmp [rbx + 40], rdi
    jne cdf_fatal
    call scs_validate
    lea rax, [rip + owned_oneshot_handle_drop_entry]
    cmp qword ptr [rsp + 40], 1
    je td_entry_identity
    cmp qword ptr [rsp + 40], 2
    jne cdf_fatal
    lea rax, [rip + session_event_drop_entry]
td_entry_identity:
    cmp [rbx + 32], rax
    jne cdf_fatal
    mov edi, 4096
    call cdf_allocate
    test rax, rax
    jz cdf_fatal
    mov r12, rax
    mov rax, [rsp + 32]
    mov [r12], rax
    mov [r12 + 72], rax
    mov rax, [rsp]
    mov [r12 + 8], rax
    mov [r12 + 88], rax
    mov rax, [rsp + 24]
    mov [r12 + 16], rax
    mov [r12 + 80], rax
    mov rax, [rsp + 40]
    mov [r12 + 24], rax
    mov rax, [rsp + 16]
    mov [r12 + 96], rax
    add rax, 64
    mov [r12 + 56], rax
    movabs rax, TD_REQUEST
    mov [r12 + 64], rax
    lea rdi, [r12 + 128]
    mov rsi, [rsp + 8]
    mov rcx, [rsp + 16]
    cld
    rep movsb
    mov esi, 1
    call td_observe
td_again:
    lea rdi, [r12 + 64]
    mov rsi, [r12 + 56]
    lea rdx, [r12 + 256]
    mov ecx, 80
    lea r8, [r12 + 1024]
    mov r9d, 2048
    cmp qword ptr [r12 + 24], 1
    jne td_event_invoke
    call td_handle_invoke
    jmp td_invoked
td_event_invoke:
    call td_event_policy_invoke
td_invoked:
    add qword ptr [r12 + 32], 1
    jc cdf_fatal
    mov edx, eax
    cmp rax, rdx
    jne cdf_fatal
    cmp eax, 0xfffffff0
    je td_effect
    cmp eax, 80
    jne cdf_fatal
    movabs rax, TD_RESPONSE
    cmp [r12 + 256], rax
    jne cdf_fatal
    cmp qword ptr [r12 + 264], 0
    jne cdf_fatal
    mov rax, [r12 + 16]
    cmp [r12 + 272], rax
    jne cdf_fatal
    mov rax, [r12]
    cmp [r12 + 280], rax
    jne cdf_fatal
    mov rax, [r12 + 24]
    cmp [r12 + 288], rax
    jne cdf_fatal
    mov rax, [r12 + 40]
    cmp [r12 + 296], rax
    jne cdf_fatal
    cmp qword ptr [r12 + 304], 1
    ja cdf_fatal
    mov rax, [r12 + 312]
    or rax, [r12 + 320]
    or rax, [r12 + 328]
    jnz cdf_fatal
    cmp qword ptr [r12 + 1056], 0
    jne cdf_fatal
    cmp qword ptr [r12 + 1080], 1
    jne cdf_fatal
    mov esi, 2
    call td_observe
    mov rdi, r12
    mov esi, 4096
    call cdf_unmap
    xor eax, eax
    cbg_leave

td_effect:
    lea rbx, [r12 + 1024]
    movabs rax, TD_ACTION
    cmp [rbx + 512], rax
    jne cdf_fatal
    mov r13, [rbx + 520]
    sub r13, 1
    cmp r13, 2
    ja cdf_fatal
    add r13, 1
    mov rax, [r12 + 40]
    add rax, 1
    jc cdf_fatal
    cmp [rbx + 528], rax
    jne cdf_fatal
    mov rax, [r12 + 16]
    cmp [rbx + 536], rax
    jne cdf_fatal
    mov r14, [rbx + 544]
    test r14, r14
    jz cdf_fatal
    cmp [r12], r14
    je cdf_fatal
    cmp qword ptr [rbx + 584], 1024
    jne cdf_fatal
    cmp qword ptr [rbx + 592], 80
    jne cdf_fatal
    mov rax, [rbx + 600]
    or rax, [rbx + 608]
    or rax, [rbx + 616]
    or rax, [rbx + 624]
    or rax, [rbx + 632]
    jnz cdf_fatal
    lea rdi, [r12 + 512]
    lea rsi, [rbx + 512]
    mov ecx, 16
    rep movsq
    cmp r13, 1
    je td_value_drop
    mov rdi, r14
    call on_validate
    mov rax, [r12 + 8]
    cmp [r14 + 48], rax
    jne cdf_fatal
    cmp r13, 3
    je td_channel_destroy
    lea rdi, [r12 + 384]
    xor eax, eax
    mov ecx, 10
    rep stosq
    movabs rax, ON_REQUEST
    mov [r12 + 384], rax
    mov rax, [rbx + 552]
    mov [r12 + 392], rax
    mov rax, [rbx + 560]
    mov [r12 + 400], rax
    mov rax, [rbx + 568]
    mov [r12 + 408], rax
    mov rax, [rbx + 576]
    mov [r12 + 416], rax
    mov rdi, r14
    lea rsi, [r12 + 384]
    mov edx, 80
    lea rcx, [rbx + 1024]
    mov r8d, 80
    call oneshot_call
    cmp rax, 80
    jne cdf_fatal
    jmp td_effect_done
td_value_drop:
    mov rdi, r14
    call value_lease_drop
    test rax, rax
    jnz cdf_fatal
    jmp td_effect_done
td_channel_destroy:
    mov rdi, r14
    call oneshot_destroy
    test rax, rax
    jnz cdf_fatal
td_effect_done:
    lea rdi, [r12 + 512]
    lea rsi, [rbx + 512]
    mov ecx, 16
    repe cmpsq
    jne cdf_fatal
    mov qword ptr [rbx + 600], 1
    cmp r13, 2
    jne td_receipt_done
    mov qword ptr [rbx + 616], 80
td_receipt_done:
    add qword ptr [r12 + 40], 1
    jc cdf_fatal
    jmp td_again

td_handle_invoke:
    .byte 0xe8
handle_drop_policy_call_displacement:
    .long 0
    ret
td_event_policy_invoke:
    .byte 0xe8
event_drop_policy_call_displacement:
    .long 0
    ret

# Optional borrowed physical entry/return evidence. Rows contain:
# stage, type tag, actual root descriptor, private arena, HIA entries, effects.
typed_drop_observer_attach:
    cbg_enter
    mov r12, rdi
    mov r13, rsi
    call scs_validate
    cmp qword ptr [r12 + 96], 0
    jne cdf_fatal
    test r13, r13
    jz td_attach_store
    movabs rax, TD_OBSERVER
    cmp [r13], rax
    jne cdf_fatal
td_attach_store:
    mov [r12 + 640], r13
    xor eax, eax
    cbg_leave
td_observe:
    mov rdi, [r12 + 8]
    mov rdi, [rdi + 640]
    test rdi, rdi
    jz td_observe_done
    movabs rax, TD_OBSERVER
    cmp [rdi], rax
    jne cdf_fatal
    mov rax, [rdi + 24]
    cmp rax, [rdi + 16]
    jae cdf_fatal
    mov rcx, rax
    imul rcx, 48
    jo cdf_fatal
    mov r8, [rdi + 8]
    test r8, r8
    jz cdf_fatal
    add r8, rcx
    jc cdf_fatal
    mov [r8], rsi
    mov rdx, [r12 + 24]
    mov [r8 + 8], rdx
    mov rdx, [r12]
    mov [r8 + 16], rdx
    mov [r8 + 24], r12
    mov rdx, [r12 + 32]
    mov [r8 + 32], rdx
    mov rdx, [r12 + 40]
    mov [r8 + 40], rdx
    add rax, 1
    jc cdf_fatal
    mov [rdi + 24], rax
td_observe_done:
    ret

# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
# Fixed ABI effects for HIA-owned send-by-value and storage consumption.
.equ OS_REQUEST, 0x3130514e534f5248
.equ OS_RESPONSE, 0x3130524e534f5248
.equ OS_ACTION, 0x3130414e534f5248

# owned_oneshot_send(sender ValueLease, value ValueLease, output80, capacity).
owned_oneshot_send:
    cbg_enter
    mov [rsp], rdi
    mov [rsp + 8], rsi
    mov [rsp + 16], rdx
    mov [rsp + 24], rcx
    cmp rcx, 80
    jb os_capacity
    test rdx, rdx
    jz os_invalid
    call vl_validate
    mov rbx, [rsp]
    cmp qword ptr [rbx + 24], 32
    jne os_invalid
    lea rax, [rip + owned_oneshot_handle_drop_entry]
    cmp [rbx + 32], rax
    jne os_invalid
    mov rdi, [rbx + 40]
    call scs_validate
    mov rdi, [rsp + 8]
    call vl_validate
    mov edi, 4096
    call cdf_allocate
    test rax, rax
    jz cdf_fatal
    mov r12, rax
    mov rbx, [rsp]
    mov [r12], rbx
    mov [r12 + 72], rbx
    mov rax, [rbx + 40]
    mov [r12 + 8], rax
    mov [r12 + 88], rax
    mov rax, [rbx + 8]
    mov [r12 + 16], rax
    mov [r12 + 80], rax
    mov qword ptr [r12 + 24], 3
    mov rax, [rsp + 16]
    mov [r12 + 48], rax
    mov qword ptr [r12 + 56], 128
    movabs rax, OS_REQUEST
    mov [r12 + 64], rax
    mov rsi, [rbx + 16]
    mov rax, [rsi + 16]
    mov [r12 + 96], rax
    mov rax, [rsi + 24]
    mov [r12 + 104], rax
    mov rax, [rsp + 8]
    mov [r12 + 112], rax
    lea rdi, [r12 + 160]
    mov ecx, 4
    cld
    rep movsq
    mov esi, 1
    call td_observe
os_again:
    lea rdi, [r12 + 64]
    mov esi, 128
    lea rdx, [r12 + 256]
    mov ecx, 80
    lea r8, [r12 + 1024]
    mov r9d, 2048
    call os_policy_invoke
    add qword ptr [r12 + 32], 1
    jc cdf_fatal
    mov edx, eax
    cmp rax, rdx
    jne cdf_fatal
    cmp eax, 0xfffffff0
    je os_effect
    cmp eax, 0xffffffff
    je os_rejected
    cmp eax, 0xfffffffe
    je os_rejected
    cmp eax, 80
    jne cdf_fatal
    movabs rax, OS_RESPONSE
    cmp [r12 + 256], rax
    jne cdf_fatal
    mov rax, [r12 + 264]
    sub rax, 1
    cmp rax, 1
    ja cdf_fatal
    mov rax, [r12 + 16]
    cmp [r12 + 272], rax
    jne cdf_fatal
    cmp qword ptr [r12 + 288], 1
    ja cdf_fatal
    mov rax, [r12 + 40]
    cmp [r12 + 296], rax
    jne cdf_fatal
    mov rax, [r12 + 304]
    or rax, [r12 + 312]
    or rax, [r12 + 320]
    or rax, [r12 + 328]
    jnz cdf_fatal
    cmp qword ptr [r12 + 1056], 0
    jne cdf_fatal
    cmp qword ptr [r12 + 1080], 1
    jne cdf_fatal
    mov rdi, [r12 + 48]
    lea rsi, [r12 + 256]
    mov ecx, 10
    rep movsq
    mov r15d, 80
    jmp os_return
os_rejected:
    cmp qword ptr [r12 + 40], 0
    jne cdf_fatal
    mov r15d, eax
os_return:
    mov esi, 2
    call td_observe
    mov rdi, r12
    mov esi, 4096
    call cdf_unmap
    mov rax, r15
    cbg_leave
os_capacity:
    mov eax, 0xfffffffe
    cbg_leave
os_invalid:
    mov eax, 0xffffffff
    cbg_leave

os_effect:
    lea rbx, [r12 + 1024]
    movabs rax, OS_ACTION
    cmp [rbx + 512], rax
    jne cdf_fatal
    mov r13, [rbx + 520]
    sub r13, 2
    cmp r13, 2
    ja cdf_fatal
    add r13, 2
    mov rax, [r12 + 40]
    add rax, 1
    jc cdf_fatal
    cmp [rbx + 528], rax
    jne cdf_fatal
    mov rax, [r12 + 16]
    cmp [rbx + 536], rax
    jne cdf_fatal
    mov r14, [rbx + 544]
    test r14, r14
    jz cdf_fatal
    cmp qword ptr [rbx + 584], 1024
    jne cdf_fatal
    cmp qword ptr [rbx + 592], 80
    jne cdf_fatal
    mov rax, [rbx + 600]
    or rax, [rbx + 608]
    or rax, [rbx + 616]
    or rax, [rbx + 624]
    or rax, [rbx + 632]
    jnz cdf_fatal
    lea rdi, [r12 + 512]
    lea rsi, [rbx + 512]
    mov ecx, 16
    rep movsq
    cmp r13, 4
    je os_forget_storage
    cmp r14, [r12 + 96]
    jne cdf_fatal
    mov rdi, r14
    call on_validate
    mov rax, [r12 + 8]
    cmp [r14 + 48], rax
    jne cdf_fatal
    cmp r13, 3
    je os_channel_destroy
    lea rdi, [r12 + 384]
    xor eax, eax
    mov ecx, 10
    rep stosq
    movabs rax, ON_REQUEST
    mov [r12 + 384], rax
    mov rax, [rbx + 552]
    mov [r12 + 392], rax
    mov rax, [rbx + 560]
    mov [r12 + 400], rax
    mov rax, [rbx + 568]
    mov [r12 + 408], rax
    mov rax, [rbx + 576]
    mov [r12 + 416], rax
    mov rdi, r14
    lea rsi, [r12 + 384]
    mov edx, 80
    lea rcx, [rbx + 1024]
    mov r8d, 80
    call oneshot_call
    cmp rax, 80
    jne cdf_fatal
    jmp os_effect_done
os_channel_destroy:
    mov rdi, r14
    call oneshot_destroy
    test rax, rax
    jnz cdf_fatal
    jmp os_effect_done
os_forget_storage:
    cmp r14, [r12]
    jne cdf_fatal
    mov rdi, r14
    call vl_validate
    mov rax, [r12 + 16]
    cmp [r14 + 8], rax
    jne cdf_fatal
    cmp qword ptr [r14 + 24], 32
    jne cdf_fatal
    lea rax, [rip + owned_oneshot_handle_drop_entry]
    cmp [r14 + 32], rax
    jne cdf_fatal
    mov rax, [r12 + 8]
    cmp [r14 + 40], rax
    jne cdf_fatal
    lea rsi, [r12 + 160]
    mov rdi, [r14 + 16]
    mov ecx, 4
    repe cmpsq
    jne cdf_fatal
    # HIA issued storage consumption after the actual send completed.
    # No second Sender::drop is invoked for this consumed endpoint.
    mov rdi, [r14 + 16]
    mov rsi, [r14 + 48]
    call cdf_unmap
    mov rdi, r14
    mov esi, 4096
    call cdf_unmap
os_effect_done:
    lea rdi, [r12 + 512]
    lea rsi, [rbx + 512]
    mov ecx, 16
    repe cmpsq
    jne cdf_fatal
    mov qword ptr [rbx + 600], 1
    cmp r13, 2
    jne os_receipt_done
    mov qword ptr [rbx + 616], 80
os_receipt_done:
    add qword ptr [r12 + 40], 1
    jc cdf_fatal
    jmp os_again
os_policy_invoke:
    .byte 0xe8
owned_send_policy_call_displacement:
    .long 0
    ret

on_standalone:
    mov eax, 60
    mov edi, 64
    syscall
    ud2

# Fixed custody for the HIA batch semaphore. No queue/permit decision here.
.equ SEM_CONTEXT_MAGIC, 0x313030434d535248
.equ SEM_REQUEST_MAGIC, 0x313051504d535248
.equ SEM_REPLY_MAGIC, 0x313052504d535248
.equ SEM_ACTION_MAGIC, 0x313030414d535248
.equ SEM_VTABLE_MAGIC, 0x313054564d535248
.equ SEM_BUDGET_REPLY, 0x313047424d535248

# create(Scheduler, generation, initial permits, link-time Waker table or 0,
#        borrowed callback owner) -> context or 0.
batch_semaphore_create:
    cbg_enter
    mov [rsp], rdi
    mov [rsp + 8], rsi
    mov [rsp + 16], rdx
    mov [rsp + 24], rcx
    mov [rsp + 32], r8
    call scs_validate
    cmp qword ptr [rsp + 8], 0
    je sem_create_failed
    movabs rax, 2305843009213693951
    cmp [rsp + 16], rax
    ja sem_create_failed
    mov edi, 4096
    call cdf_allocate
    test rax, rax
    jz sem_create_failed
    mov r12, rax
    mov rax, [rsp + 8]
    mov [r12 + 8], rax
    mov rax, [rsp]
    mov [r12 + 40], rax
    mov rax, [rsp + 24]
    test rax, rax
    jnz sem_create_table
    lea rax, [rip + sem_default_waker_table]
    mov rdx, [rsp]
    mov [rsp + 32], rdx
sem_create_table:
    movabs rdx, SEM_VTABLE_MAGIC
    cmp [rax], rdx
    jne cdf_fatal
    mov [r12 + 64], rax
    mov rax, [rsp + 32]
    mov [r12 + 72], rax
    mov eax, 186
    syscall
    mov [r12 + 32], rax
    mov edi, 1024
    call cdf_allocate
    test rax, rax
    jz sem_create_cleanup
    mov [r12 + 16], rax
    mov qword ptr [r12 + 24], 1024
    movabs rax, SEM_CONTEXT_MAGIC
    mov [r12], rax
    lea rdi, [r12 + 128]
    xor eax, eax
    mov ecx, 12
    rep stosq
    movabs rax, SEM_REQUEST_MAGIC
    mov [r12 + 128], rax
    mov qword ptr [r12 + 136], 1
    mov rax, [r12 + 8]
    mov [r12 + 144], rax
    mov rax, [rsp + 16]
    mov [r12 + 160], rax
    mov rdi, r12
    lea rsi, [r12 + 128]
    mov edx, 96
    lea rcx, [r12 + 256]
    mov r8d, 128
    call batch_semaphore_call
    cmp eax, 128
    jne cdf_fatal
    mov rax, r12
    cbg_leave
sem_create_cleanup:
    mov rdi, r12
    mov esi, 4096
    call cdf_unmap
sem_create_failed:
    xor eax, eax
    cbg_leave

# call(context, borrowed request96, length, reply128, capacity).
# A separate guarded RO mapping holds the same request through every effect.
batch_semaphore_call:
    cbg_enter
    mov r12, rdi
    mov r13, rsi
    mov r14, rcx
    cmp r8, 128
    jb sem_capacity
    cmp rdx, 96
    jne sem_invalid
    test r12, r12
    jz sem_invalid
    test r13, r13
    jz sem_invalid
    test r14, r14
    jz sem_invalid
    movabs rax, SEM_CONTEXT_MAGIC
    cmp [r12], rax
    jne sem_invalid
    mov eax, 186
    syscall
    cmp rax, [r12 + 32]
    jne sem_invalid
    cmp qword ptr [r12 + 48], 0
    jne sem_invalid
    mov rax, [r13 + 16]
    cmp rax, [r12 + 8]
    jne sem_invalid
    mov edi, 96
    call cdf_allocate
    test rax, rax
    jz cdf_fatal
    mov r15, rax
    mov rdi, rax
    mov rsi, r13
    mov ecx, 12
    rep movsq
    mov rdi, r15
    mov esi, 4096
    mov edx, 1
    mov eax, 10
    syscall
    test rax, rax
    jnz cdf_fatal
    mov [r12 + 120], r15
    mov qword ptr [r12 + 48], 1
sem_again:
    mov rbx, [r12 + 16]
    mov rdi, r15
    mov esi, 96
    lea rdx, [r12 + 256]
    mov ecx, 128
    mov r8, rbx
    mov r9, [r12 + 24]
    call sem_invoke
    add qword ptr [r12 + 80], 1
    jc cdf_fatal
    mov edx, eax
    cmp rax, rdx
    jne cdf_fatal
    cmp eax, 0xfffffffd
    je sem_grow
    cmp eax, 0xfffffff0
    je sem_effect
    cmp eax, 128
    je sem_success
    cmp eax, 0xffffffff
    je sem_return
    cmp eax, 0xfffffffe
    jne cdf_fatal
sem_return:
    mov ebp, eax
    cmp qword ptr [r12 + 56], 0
    jne cdf_fatal
    mov rdi, r15
    mov esi, 96
    call cdf_unmap
    mov qword ptr [r12 + 120], 0
    mov qword ptr [r12 + 48], 0
    mov eax, ebp
    cbg_leave
sem_success:
    movabs rax, SEM_REPLY_MAGIC
    cmp [r12 + 256], rax
    jne cdf_fatal
    mov rax, [r12 + 272]
    cmp rax, [r12 + 8]
    jne cdf_fatal
    mov rax, [r12 + 280]
    cmp rax, [r15 + 8]
    jne cdf_fatal
    mov rax, [r12 + 368]
    or rax, [r12 + 376]
    jnz cdf_fatal
    mov rdi, r14
    lea rsi, [r12 + 256]
    mov ecx, 16
    rep movsq
    mov eax, 128
    jmp sem_return
sem_capacity:
    mov eax, 0xfffffffe
    cbg_leave
sem_invalid:
    mov eax, 0xffffffff
    cbg_leave
sem_grow:
    cmp qword ptr [r12 + 56], 0
    jne cdf_fatal
    cmp qword ptr [rbx + 120], 0
    jne cdf_fatal
    mov rbp, [r12 + 24]
    cmp rbp, 0x7fffffff
    ja cdf_fatal
    lea rdi, [rbp + rbp]
    call cdf_allocate
    test rax, rax
    jz cdf_fatal
    mov [rsp], rax
    mov rdi, rax
    mov rsi, rbx
    mov rcx, rbp
    rep movsb
    mov rdi, rbx
    mov rsi, rbp
    call cdf_unmap
    mov rax, [rsp]
    mov [r12 + 16], rax
    shl rbp, 1
    mov [r12 + 24], rbp
    add qword ptr [r12 + 88], 1
    jc cdf_fatal
    jmp sem_again

# destroy requires all borrowed users stopped and all Acquire futures dropped.
batch_semaphore_destroy:
    cbg_enter
    mov r12, rdi
    movabs rax, SEM_CONTEXT_MAGIC
    cmp [r12], rax
    jne cdf_fatal
    mov eax, 186
    syscall
    cmp rax, [r12 + 32]
    jne cdf_fatal
    mov rax, [r12 + 48]
    or rax, [r12 + 56]
    or rax, [r12 + 120]
    jnz cdf_fatal
    mov rbx, [r12 + 16]
    cmp qword ptr [rbx], 0
    je sem_destroy_done
    lea rdi, [r12 + 128]
    xor eax, eax
    mov ecx, 12
    rep stosq
    movabs rax, SEM_REQUEST_MAGIC
    mov [r12 + 128], rax
    mov qword ptr [r12 + 136], 9
    mov rax, [r12 + 8]
    mov [r12 + 144], rax
    mov rdi, r12
    lea rsi, [r12 + 128]
    mov edx, 96
    lea rcx, [r12 + 256]
    mov r8d, 128
    call batch_semaphore_call
    cmp eax, 128
    jne cdf_fatal
    mov rbx, [r12 + 16]
sem_destroy_done:
    cmp qword ptr [rbx], 0
    jne cdf_fatal
    mov qword ptr [r12], 0
    mov rdi, rbx
    mov rsi, [r12 + 24]
    call cdf_unmap
    mov rdi, r12
    mov esi, 4096
    call cdf_unmap
    xor eax, eax
    cbg_leave
sem_invoke:
    .byte 0xe8
semaphore_policy_call_displacement:
    .long 0
    ret


sem_effect:
    movabs rax, SEM_ACTION_MAGIC
    cmp [rbx + 384], rax
    jne cdf_fatal
    mov rbp, [rbx + 392]
    lea rax, [rbp - 1]
    cmp rax, 7
    ja cdf_fatal
    mov rax, [r12 + 96]
    add rax, 1
    jc cdf_fatal
    cmp rax, [rbx + 400]
    jne cdf_fatal
    mov [r12 + 96], rax
    mov rax, [r12 + 8]
    cmp rax, [rbx + 408]
    jne cdf_fatal
    mov rax, [rbx + 424]
    or rax, [rbx + 432]
    or rax, [rbx + 456]
    or rax, [rbx + 464]
    or rax, [rbx + 472]
    or rax, [rbx + 480]
    or rax, [rbx + 488]
    or rax, [rbx + 496]
    or rax, [rbx + 504]
    jnz cdf_fatal
    cmp rbp, 6
    je sem_effect_budget_span
    mov rax, [rbx + 440]
    or rax, [rbx + 448]
    jnz cdf_fatal
    jmp sem_effect_copy
sem_effect_budget_span:
    cmp qword ptr [rbx + 440], 896
    jne cdf_fatal
    cmp qword ptr [rbx + 448], 16
    jne cdf_fatal
sem_effect_copy:
    lea rdi, [r12 + 512]
    lea rsi, [rbx + 384]
    mov ecx, 16
    rep movsq
    cmp rbp, 1
    je sem_lock
    cmp rbp, 2
    je sem_unlock
    cmp rbp, 5
    jbe sem_waker
    cmp rbp, 6
    je sem_budget_proceed
    cmp rbp, 7
    je sem_budget_progress
    jmp sem_budget_restore
sem_lock:
    cmp qword ptr [rbx + 416], 0
    jne cdf_fatal
    xor eax, eax
    mov edx, 1
    lock cmpxchg [r12 + 56], rdx
    jne cdf_fatal
    jmp sem_effect_complete
sem_unlock:
    cmp qword ptr [rbx + 416], 0
    jne cdf_fatal
    xor eax, eax
    xchg rax, [r12 + 56]
    cmp rax, 1
    jne cdf_fatal
    jmp sem_effect_complete
sem_waker:
    mov rax, [r12 + 64]
    mov rcx, rbp
    sub rcx, 2
    mov rdx, [rax + rcx * 8]
    add rax, rdx
    mov rdi, [r12 + 72]
    mov rsi, [rbx + 416]
    test rsi, rsi
    jz cdf_fatal
    call rax
    test rax, rax
    jnz cdf_fatal
    jmp sem_effect_complete
sem_budget_proceed:
    mov rdi, [r12 + 40]
    mov rsi, [rdi + 96]
    test rsi, rsi
    jz cdf_fatal
    call cooperative_scheduler_proceed
    mov [rbx + 904], rax
    movabs rax, SEM_BUDGET_REPLY
    mov [rbx + 896], rax
    jmp sem_effect_complete
sem_budget_progress:
    mov rdi, [r12 + 40]
    mov rsi, [rbx + 416]
    call cooperative_scheduler_progress
    test rax, rax
    jnz cdf_fatal
    jmp sem_effect_complete
sem_budget_restore:
    mov rdi, [r12 + 40]
    mov rsi, [rbx + 416]
    call cooperative_scheduler_restore
    test rax, rax
    jnz cdf_fatal
sem_effect_complete:
    lea rsi, [rbx + 384]
    lea rdi, [r12 + 512]
    mov ecx, 16
    repe cmpsq
    jne cdf_fatal
    mov qword ptr [rbx + 472], 1
    mov qword ptr [rbx + 480], 0
    xor eax, eax
    cmp rbp, 6
    jne sem_effect_length
    mov eax, 16
sem_effect_length:
    mov [rbx + 488], rax
    jmp sem_again

# Default hooks own actual Scheduler Waker references. No wire pointer selects them.
sem_default_clone:
    cbg_enter
    mov r12, rdi
    mov r13, rsi
    mov rdi, r13
    call scs_cell_validate
    cmp [r13 + 8], r12
    jne cdf_fatal
    mov rdi, r13
    call cooperative_scheduler_retain
    cmp rax, r13
    jne cdf_fatal
    xor eax, eax
    cbg_leave
sem_default_drop:
    cbg_enter
    mov r12, rdi
    mov r13, rsi
    mov rdi, r13
    call scs_cell_validate
    cmp [r13 + 8], r12
    jne cdf_fatal
    mov rdi, r13
    call cooperative_scheduler_release
    xor eax, eax
    cbg_leave
sem_default_wake:
    cbg_enter
    mov r12, rdi
    mov r13, rsi
    mov rdi, r13
    call scs_cell_validate
    cmp [r13 + 8], r12
    jne cdf_fatal
    mov rdx, [r12 + 96]
    or rdx, [r12 + 616]
    setnz dl
    movzx edx, dl
    xor esi, esi
    mov rdi, r13
    call cooperative_scheduler_notify
    mov rdi, r13
    call cooperative_scheduler_release
    xor eax, eax
    cbg_leave
.balign 8
sem_default_waker_table:
    .quad SEM_VTABLE_MAGIC
    .quad sem_default_clone - sem_default_waker_table
    .quad sem_default_drop - sem_default_waker_table
    .quad sem_default_wake - sem_default_waker_table


# Fixed private-call custody for the HIA bounded-mpsc controller.
# Every call owns an independent continuation; shared metadata is only borrowed
# while its short gate is held. Typed Drop runs outside all channel gates.
.equ MNC_MAGIC, 0x3130304e4d435248
.equ MNC_REQUEST, 0x313051554d435248
.equ MNC_REPLY, 0x313052554d435248
.equ MNC_ACTION, 0x313041434d435248
.equ MNC_BUDGET_REPLY, 0x31304742434d5248
.equ MNC_PRIVATE_BYTES, 16384

# create(Scheduler, fresh generation, positive capacity,
#        link-time semaphore-compatible Waker table or 0, borrowed hook owner).
bounded_mpsc_create:
    cbg_enter
    mov [rsp], rdi
    mov [rsp + 8], rsi
    mov [rsp + 16], rdx
    mov [rsp + 24], rcx
    mov [rsp + 32], r8
    call scs_validate
    cmp qword ptr [rsp + 8], 0
    je mnc_create_failed
    cmp qword ptr [rsp + 16], 0
    je mnc_create_failed
    movabs rax, 2305843009213693951
    cmp [rsp + 16], rax
    ja mnc_create_failed
    mov edi, 4096
    call cdf_allocate
    test rax, rax
    jz mnc_create_failed
    mov r12, rax
    mov rax, [rsp + 8]
    mov [r12 + 8], rax
    mov rax, [rsp]
    mov [r12 + 40], rax
    mov eax, 186
    syscall
    mov [r12 + 32], rax
    mov edi, 1024
    call cdf_allocate
    test rax, rax
    jz mnc_create_free_context
    mov [r12 + 16], rax
    mov qword ptr [r12 + 24], 1024
    mov rdi, [rsp]
    mov rsi, [rsp + 8]
    mov rdx, [rsp + 16]
    mov rcx, [rsp + 24]
    mov r8, [rsp + 32]
    call batch_semaphore_create
    test rax, rax
    jz mnc_create_free_arena
    mov [r12 + 80], rax
    mov rdx, [rax + 64]
    mov [r12 + 64], rdx
    mov rdx, [rax + 72]
    mov [r12 + 72], rdx
    movabs rax, MNC_MAGIC
    mov [r12], rax
    lea rdi, [r12 + 128]
    xor eax, eax
    mov ecx, 12
    rep stosq
    movabs rax, MNC_REQUEST
    mov [r12 + 128], rax
    mov qword ptr [r12 + 136], 1
    mov rax, [r12 + 8]
    mov [r12 + 144], rax
    mov rax, [rsp + 16]
    mov [r12 + 160], rax
    mov rdi, r12
    lea rsi, [r12 + 128]
    mov edx, 96
    lea rcx, [r12 + 256]
    mov r8d, 128
    call bounded_mpsc_call
    cmp eax, 128
    jne cdf_fatal
    mov rax, r12
    cbg_leave
mnc_create_free_arena:
    mov rdi, [r12 + 16]
    mov rsi, [r12 + 24]
    call cdf_unmap
mnc_create_free_context:
    mov rdi, r12
    mov esi, 4096
    call cdf_unmap
mnc_create_failed:
    xor eax, eax
    cbg_leave

# call(context, borrowed request96, length, reply128, capacity).
# The private continuation + output never aliases another nested invocation.
bounded_mpsc_call:
    cbg_enter
    mov r12, rdi
    mov r13, rsi
    mov r14, rcx
    cmp r8, 128
    jb mnc_capacity
    cmp rdx, 96
    jne mnc_invalid
    test r12, r12
    jz mnc_invalid
    test r13, r13
    jz mnc_invalid
    test r14, r14
    jz mnc_invalid
    movabs rax, MNC_MAGIC
    cmp [r12], rax
    jne mnc_invalid
    mov eax, 186
    syscall
    cmp rax, [r12 + 32]
    jne mnc_invalid
    mov rax, [r13 + 16]
    cmp rax, [r12 + 8]
    jne mnc_invalid
    cmp qword ptr [r12 + 112], 0
    jne mnc_invalid
    add qword ptr [r12 + 48], 1
    jc cdf_fatal
    mov edi, MNC_PRIVATE_BYTES
    call cdf_allocate
    test rax, rax
    jz cdf_fatal
    mov rbx, rax
    lea r15, [rbx + 8192]
    mov rdi, r15
    mov rsi, r13
    mov ecx, 12
    rep movsq
    mov rdi, r15
    mov esi, 4096
    mov edx, 1
    mov eax, 10
    syscall
    test rax, rax
    jnz cdf_fatal
mnc_again:
    mov rdi, r15
    mov esi, 96
    lea rdx, [rbx + 12288]
    mov ecx, 128
    mov r8, rbx
    mov r9d, 8192
    call mnc_controller_invoke
    add qword ptr [r12 + 104], 1
    jc cdf_fatal
    mov edx, eax
    cmp rax, rdx
    jne cdf_fatal
    cmp eax, 0xfffffff0
    je mnc_effect
    cmp eax, 128
    je mnc_success
    cmp eax, 0xffffffff
    je mnc_return
    cmp eax, 0xfffffffe
    jne cdf_fatal
mnc_return:
    mov [rsp], rax
    cmp qword ptr [rbx + 12704], 0
    jne cdf_fatal
    cmp qword ptr [r12 + 56], 0
    jne cdf_fatal
    mov rdi, rbx
    mov esi, MNC_PRIVATE_BYTES
    call cdf_unmap
    sub qword ptr [r12 + 48], 1
    jc cdf_fatal
    jnz mnc_return_live
    cmp qword ptr [r12 + 112], 0
    je mnc_return_live
    mov rdi, r12
    call bounded_mpsc_destroy
    test rax, rax
    jnz cdf_fatal
mnc_return_live:
    mov rax, [rsp]
    cbg_leave
mnc_success:
    movabs rax, MNC_REPLY
    cmp [rbx + 12288], rax
    jne cdf_fatal
    mov rax, [rbx + 12304]
    cmp rax, [r12 + 8]
    jne cdf_fatal
    mov rax, [rbx + 12312]
    cmp rax, [r15 + 8]
    jne cdf_fatal
    mov rax, [rbx + 12400]
    or rax, [rbx + 12408]
    jnz cdf_fatal
    mov rdi, r14
    lea rsi, [rbx + 12288]
    mov ecx, 16
    rep movsq
    mov eax, 128
    jmp mnc_return
mnc_capacity:
    mov eax, 0xfffffffe
    cbg_leave
mnc_invalid:
    mov eax, 0xffffffff
    cbg_leave

# All endpoint/future/value owners must be retired before destroy.
# An outstanding invocation prevents physical teardown, including callback reentry.
bounded_mpsc_destroy:
    cbg_enter
    mov r12, rdi
    test r12, r12
    jz mnc_invalid
    movabs rax, MNC_MAGIC
    cmp [r12], rax
    jne mnc_invalid
    mov eax, 186
    syscall
    cmp [r12 + 32], rax
    jne mnc_invalid
    mov rax, [r12 + 48]
    or rax, [r12 + 56]
    jnz mnc_invalid
    mov rax, [r12 + 16]
    cmp qword ptr [rax], 0
    je mnc_destroy_retired
    lea rdi, [r12 + 128]
    xor eax, eax
    mov ecx, 12
    rep stosq
    movabs rax, MNC_REQUEST
    mov [r12 + 128], rax
    mov qword ptr [r12 + 136], 13
    mov rax, [r12 + 8]
    mov [r12 + 144], rax
    mov rdi, r12
    lea rsi, [r12 + 128]
    mov edx, 96
    lea rcx, [r12 + 256]
    mov r8d, 128
    call bounded_mpsc_call
    cmp eax, 0xffffffff
    je mnc_destroy_return
    cmp eax, 128
    jne cdf_fatal
mnc_destroy_retired:
    mov rdi, [r12 + 80]
    call batch_semaphore_destroy
    test rax, rax
    jnz cdf_fatal
    mov qword ptr [r12 + 80], 0
    mov qword ptr [r12], 0
    mov rdi, [r12 + 16]
    mov rsi, [r12 + 24]
    call cdf_unmap
    mov rdi, r12
    mov esi, 4096
    call cdf_unmap
    xor eax, eax
mnc_destroy_return:
    cbg_leave
mnc_controller_invoke:
    .byte 0xe8
mpsc_controller_policy_call_displacement:
    .long 0
    ret
mnc_state_invoke:
    .byte 0xe8
mpsc_state_policy_call_displacement:
    .long 0
    ret

# Closed effect catalogue. No channel policy is implemented in this boundary.
mnc_effect:
    movabs rax, MNC_ACTION
    cmp [rbx + 512], rax
    jne cdf_fatal
    mov rbp, [rbx + 520]
    lea rax, [rbp - 1]
    cmp rax, 10
    ja cdf_fatal
    mov rax, [rbx + 12672]
    add rax, 1
    jc cdf_fatal
    cmp rax, [rbx + 528]
    jne cdf_fatal
    mov [rbx + 12672], rax
    mov rax, [r12 + 8]
    cmp rax, [rbx + 536]
    jne cdf_fatal
    mov rax, [rbx + 584]
    or rax, [rbx + 592]
    or rax, [rbx + 600]
    or rax, [rbx + 608]
    or rax, [rbx + 616]
    or rax, [rbx + 624]
    or rax, [rbx + 632]
    jnz cdf_fatal
    cmp rbp, 1
    je mnc_state_span
    cmp rbp, 2
    je mnc_semaphore_span
    mov rax, [rbx + 552]
    or rax, [rbx + 560]
    jnz cdf_fatal
    cmp rbp, 6
    je mnc_budget_span
    mov rax, [rbx + 568]
    or rax, [rbx + 576]
    jnz cdf_fatal
    jmp mnc_effect_copy
mnc_state_span:
    cmp qword ptr [rbx + 552], 1024
    jne cdf_fatal
    cmp qword ptr [rbx + 560], 96
    jne cdf_fatal
    cmp qword ptr [rbx + 568], 1152
    jne cdf_fatal
    cmp qword ptr [rbx + 576], 256
    jne cdf_fatal
    jmp mnc_effect_copy
mnc_semaphore_span:
    cmp qword ptr [rbx + 552], 1536
    jne cdf_fatal
    cmp qword ptr [rbx + 560], 96
    jne cdf_fatal
    cmp qword ptr [rbx + 568], 1664
    jne cdf_fatal
    cmp qword ptr [rbx + 576], 128
    jne cdf_fatal
    jmp mnc_effect_copy
mnc_budget_span:
    cmp qword ptr [rbx + 568], 1856
    jne cdf_fatal
    cmp qword ptr [rbx + 576], 16
    jne cdf_fatal
mnc_effect_copy:
    lea rdi, [rbx + 12544]
    lea rsi, [rbx + 512]
    mov ecx, 16
    rep movsq
    mov [rbx + 12680], rbp
    mov qword ptr [rbx + 12688], 0
    mov qword ptr [rbx + 12696], 0
    cmp rbp, 1
    je mnc_state_call
    cmp rbp, 2
    je mnc_semaphore_call
    cmp rbp, 5
    jbe mnc_waker
    cmp rbp, 6
    je mnc_budget_proceed
    cmp rbp, 7
    je mnc_budget_progress
    cmp rbp, 8
    je mnc_budget_restore
    cmp rbp, 9
    je mnc_gate_lock
    cmp rbp, 10
    je mnc_gate_unlock
    cmp qword ptr [rbx + 12704], 0
    jne cdf_fatal
    cmp qword ptr [r12 + 56], 0
    jne cdf_fatal
    mov rdi, [rbx + 544]
    test rdi, rdi
    jz cdf_fatal
    call value_lease_drop
    test rax, rax
    jnz cdf_fatal
    jmp mnc_effect_complete
mnc_gate_lock:
    cmp qword ptr [rbx + 544], 0
    jne cdf_fatal
    cmp qword ptr [rbx + 12704], 0
    jne cdf_fatal
    xor eax, eax
    mov edx, 1
    lock cmpxchg [r12 + 56], rdx
    jne cdf_fatal
    mov qword ptr [rbx + 12704], 1
    jmp mnc_effect_complete
mnc_gate_unlock:
    cmp qword ptr [rbx + 544], 0
    jne cdf_fatal
    cmp qword ptr [rbx + 12704], 1
    jne cdf_fatal
    xor eax, eax
    xchg rax, [r12 + 56]
    cmp rax, 1
    jne cdf_fatal
    mov qword ptr [rbx + 12704], 0
    jmp mnc_effect_complete
mnc_state_call:
    cmp qword ptr [rbx + 544], 0
    jne cdf_fatal
    cmp qword ptr [rbx + 12704], 1
    jne cdf_fatal
    cmp qword ptr [r12 + 56], 1
    jne cdf_fatal
mnc_state_again:
    lea rdi, [rbx + 1024]
    mov esi, 96
    lea rdx, [rbx + 1152]
    mov ecx, 256
    mov r8, [r12 + 16]
    mov r9, [r12 + 24]
    call mnc_state_invoke
    add qword ptr [r12 + 88], 1
    jc cdf_fatal
    mov edx, eax
    cmp rax, rdx
    jne cdf_fatal
    cmp eax, 0xfffffffd
    je mnc_state_grow
    cmp eax, 0xffffffff
    je mnc_state_invalid
    cmp eax, 256
    jne cdf_fatal
    mov qword ptr [rbx + 12696], 256
mnc_state_invalid:
    mov [rbx + 12688], rax
    jmp mnc_effect_complete
mnc_state_grow:
    mov rbp, [r12 + 24]
    cmp rbp, 0x7fffffff
    ja cdf_fatal
    lea rdi, [rbp + rbp]
    call cdf_allocate
    test rax, rax
    jz cdf_fatal
    mov [rsp + 8], rax
    mov rdi, rax
    mov rsi, [r12 + 16]
    mov rcx, rbp
    rep movsb
    mov rdi, [r12 + 16]
    mov rsi, rbp
    call cdf_unmap
    mov rax, [rsp + 8]
    mov [r12 + 16], rax
    shl rbp, 1
    mov [r12 + 24], rbp
    add qword ptr [r12 + 96], 1
    jc cdf_fatal
    jmp mnc_state_again
mnc_semaphore_call:
    cmp qword ptr [rbx + 544], 0
    jne cdf_fatal
    cmp qword ptr [rbx + 12704], 0
    jne cdf_fatal
    cmp qword ptr [r12 + 56], 0
    jne cdf_fatal
    mov rdi, [r12 + 80]
    lea rsi, [rbx + 1536]
    mov edx, 96
    lea rcx, [rbx + 1664]
    mov r8d, 128
    call batch_semaphore_call
    cmp eax, 128
    jne cdf_fatal
    mov qword ptr [rbx + 12688], 128
    mov qword ptr [rbx + 12696], 128
    jmp mnc_effect_complete
mnc_waker:
    mov rax, [r12 + 64]
    mov rcx, [rbx + 12680]
    sub rcx, 2
    mov rdx, [rax + rcx * 8]
    add rax, rdx
    mov rdi, [r12 + 72]
    mov rsi, [rbx + 544]
    test rsi, rsi
    jz cdf_fatal
    call rax
    test rax, rax
    jnz cdf_fatal
    jmp mnc_effect_complete
mnc_budget_proceed:
    mov rdi, [r12 + 40]
    mov rsi, [rdi + 96]
    test rsi, rsi
    jz cdf_fatal
    call cooperative_scheduler_proceed
    mov [rbx + 1864], rax
    movabs rax, MNC_BUDGET_REPLY
    mov [rbx + 1856], rax
    mov qword ptr [rbx + 12696], 16
    jmp mnc_effect_complete
mnc_budget_progress:
    mov rdi, [r12 + 40]
    mov rsi, [rbx + 544]
    call cooperative_scheduler_progress
    test rax, rax
    jnz cdf_fatal
    jmp mnc_effect_complete
mnc_budget_restore:
    mov rdi, [r12 + 40]
    mov rsi, [rbx + 544]
    call cooperative_scheduler_restore
    test rax, rax
    jnz cdf_fatal
mnc_effect_complete:
    lea rdi, [rbx + 12544]
    lea rsi, [rbx + 512]
    mov ecx, 16
    repe cmpsq
    jne cdf_fatal
    mov qword ptr [rbx + 600], 1
    mov rax, [rbx + 12688]
    mov [rbx + 608], rax
    mov rax, [rbx + 12696]
    mov [rbx + 616], rax
    jmp mnc_again

# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
# Private invocation memory and fixed physical typed-drop effects only.
# Each recursive destructor receives its own arena. No shared channel lock is held.
.equ MD_REQUEST, 0x3130305144545248
.equ MD_RESPONSE, 0x3130305244545248
.equ MD_ACTION, 0x31303041444d5248
.equ MD_OBSERVER, 0x3130304f44545248

owned_mpsc_handle_drop_entry:
    mov r9d, 4
    jmp md_drop_entry
streamable_http_receiver_drop_entry:
    mov r9d, 5
    jmp md_drop_entry

# Existing ValueLease callback ABI:
# cookie SC, actual RO payload, length, lease generation, own descriptor.
md_drop_entry:
    cbg_enter
    mov [rsp], rdi
    mov [rsp + 8], rsi
    mov [rsp + 16], rdx
    mov [rsp + 24], rcx
    mov [rsp + 32], r8
    mov [rsp + 40], r9
    mov rdi, r8
    call vl_validate
    mov rbx, [rsp + 32]
    mov rax, [rsp + 8]
    cmp [rbx + 16], rax
    jne cdf_fatal
    mov rax, [rsp + 16]
    cmp rax, 40
    ja cdf_fatal
    cmp [rbx + 24], rax
    jne cdf_fatal
    mov rax, [rsp + 24]
    cmp [rbx + 8], rax
    jne cdf_fatal
    mov rdi, [rsp]
    cmp [rbx + 40], rdi
    jne cdf_fatal
    call scs_validate
    lea rax, [rip + owned_mpsc_handle_drop_entry]
    cmp qword ptr [rsp + 40], 4
    je md_entry_identity
    cmp qword ptr [rsp + 40], 5
    jne cdf_fatal
    lea rax, [rip + streamable_http_receiver_drop_entry]
md_entry_identity:
    cmp [rbx + 32], rax
    jne cdf_fatal
    mov edi, 4096
    call cdf_allocate
    test rax, rax
    jz cdf_fatal
    mov r12, rax
    mov rax, [rsp + 32]
    mov [r12], rax
    mov [r12 + 72], rax
    mov rax, [rsp]
    mov [r12 + 8], rax
    mov [r12 + 88], rax
    mov rax, [rsp + 24]
    mov [r12 + 16], rax
    mov [r12 + 80], rax
    mov rax, [rsp + 40]
    mov [r12 + 24], rax
    mov rax, [rsp + 16]
    mov [r12 + 96], rax
    add rax, 64
    mov [r12 + 56], rax
    movabs rax, MD_REQUEST
    mov [r12 + 64], rax
    lea rdi, [r12 + 128]
    mov rsi, [rsp + 8]
    mov rcx, [rsp + 16]
    cld
    rep movsb
    mov esi, 1
    call md_observe
md_again:
    lea rdi, [r12 + 64]
    mov rsi, [r12 + 56]
    lea rdx, [r12 + 256]
    mov ecx, 80
    lea r8, [r12 + 1024]
    mov r9d, 2048
    call md_policy_invoke
md_invoked:
    add qword ptr [r12 + 32], 1
    jc cdf_fatal
    mov edx, eax
    cmp rax, rdx
    jne cdf_fatal
    cmp eax, 0xfffffff0
    je md_effect
    cmp eax, 80
    jne cdf_fatal
    movabs rax, MD_RESPONSE
    cmp [r12 + 256], rax
    jne cdf_fatal
    cmp qword ptr [r12 + 264], 0
    jne cdf_fatal
    mov rax, [r12 + 16]
    cmp [r12 + 272], rax
    jne cdf_fatal
    mov rax, [r12]
    cmp [r12 + 280], rax
    jne cdf_fatal
    mov rax, [r12 + 24]
    cmp [r12 + 288], rax
    jne cdf_fatal
    mov rax, [r12 + 40]
    cmp [r12 + 296], rax
    jne cdf_fatal
    cmp qword ptr [r12 + 304], 1
    ja cdf_fatal
    mov rax, [r12 + 312]
    or rax, [r12 + 320]
    or rax, [r12 + 328]
    jnz cdf_fatal
    cmp qword ptr [r12 + 1056], 0
    jne cdf_fatal
    cmp qword ptr [r12 + 1080], 1
    jne cdf_fatal
    mov esi, 2
    call md_observe
    mov rdi, r12
    mov esi, 4096
    call cdf_unmap
    xor eax, eax
    cbg_leave

md_effect:
    lea rbx, [r12 + 1024]
    movabs rax, MD_ACTION
    cmp [rbx + 512], rax
    jne cdf_fatal
    mov r13, [rbx + 520]
    sub r13, 1
    cmp r13, 2
    ja cdf_fatal
    add r13, 1
    mov rax, [r12 + 40]
    add rax, 1
    jc cdf_fatal
    cmp [rbx + 528], rax
    jne cdf_fatal
    mov rax, [r12 + 16]
    cmp [rbx + 536], rax
    jne cdf_fatal
    mov r14, [rbx + 544]
    test r14, r14
    jz cdf_fatal
    cmp [r12], r14
    je cdf_fatal
    cmp qword ptr [rbx + 584], 1024
    jne cdf_fatal
    cmp qword ptr [rbx + 592], 128
    jne cdf_fatal
    mov rax, [rbx + 600]
    or rax, [rbx + 608]
    or rax, [rbx + 616]
    or rax, [rbx + 624]
    or rax, [rbx + 632]
    jnz cdf_fatal
    lea rdi, [r12 + 512]
    lea rsi, [rbx + 512]
    mov ecx, 16
    rep movsq
    cmp r13, 1
    je md_value_drop
    movabs rax, MNC_MAGIC
    cmp [r14], rax
    jne cdf_fatal
    mov rax, [r12 + 8]
    cmp [r14 + 40], rax
    jne cdf_fatal
    mov eax, 186
    syscall
    cmp [r14 + 32], rax
    jne cdf_fatal
    cmp r13, 3
    je md_channel_destroy
    lea rdi, [r12 + 384]
    xor eax, eax
    mov ecx, 12
    rep stosq
    movabs rax, MNC_REQUEST
    mov [r12 + 384], rax
    mov rax, [rbx + 552]
    mov [r12 + 392], rax
    mov rax, [rbx + 560]
    mov [r12 + 400], rax
    mov rax, [rbx + 568]
    mov [r12 + 408], rax
    mov rax, [rbx + 576]
    mov [r12 + 416], rax
    mov rdi, r14
    lea rsi, [r12 + 384]
    mov edx, 96
    lea rcx, [rbx + 1024]
    mov r8d, 128
    call bounded_mpsc_call
    cmp rax, 128
    jne cdf_fatal
    jmp md_effect_done
md_value_drop:
    mov rdi, r14
    call value_lease_drop
    test rax, rax
    jnz cdf_fatal
    jmp md_effect_done
md_channel_destroy:
    mov rdi, r14
    call bounded_mpsc_retire_owned
    test rax, rax
    jnz cdf_fatal
md_effect_done:
    lea rdi, [r12 + 512]
    lea rsi, [rbx + 512]
    mov ecx, 16
    repe cmpsq
    jne cdf_fatal
    mov qword ptr [rbx + 600], 1
    cmp r13, 2
    jne md_receipt_done
    mov qword ptr [rbx + 616], 128
md_receipt_done:
    add qword ptr [r12 + 40], 1
    jc cdf_fatal
    jmp md_again

md_policy_invoke:
    .byte 0xe8
owned_mpsc_drop_policy_call_displacement:
    .long 0
    ret

# Physical retirement after a successful actual HIA op13.
# A live nested invocation owns the mapping until its call boundary returns.
bounded_mpsc_retire_owned:
    cbg_enter
    mov r12, rdi
    test r12, r12
    jz mnc_invalid
    movabs rax, MNC_MAGIC
    cmp [r12], rax
    jne mnc_invalid
    mov eax, 186
    syscall
    cmp [r12 + 32], rax
    jne mnc_invalid
    cmp qword ptr [r12 + 56], 0
    jne mnc_invalid
    cmp qword ptr [r12 + 112], 0
    jne mnc_invalid
    mov rax, [r12 + 16]
    cmp qword ptr [rax], 0
    jne mnc_invalid
    mov qword ptr [r12 + 112], 1
    cmp qword ptr [r12 + 48], 0
    jne md_retire_deferred
    mov rdi, r12
    call bounded_mpsc_destroy
    test rax, rax
    jnz cdf_fatal
md_retire_deferred:
    xor eax, eax
    cbg_leave

# Observer number alone changes for combined EventTake/Result images.
# HIA reply type remains 4; it is restored immediately after the borrowed observer.
md_observe:
    cmp qword ptr [r12 + 24], 4
    jne md_observe_direct
    mov qword ptr [r12 + 24], 6
    sub rsp, 8
    call td_observe
    add rsp, 8
    mov qword ptr [r12 + 24], 4
    ret
md_observe_direct:
    jmp td_observe

# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
# Fixed storage consumption after HIA transfers SessionEvent's owned fields.
.equ TK_RESPONSE, 0x3130524656535248
.equ TK_ACTION, 0x3130415456535248

# session_event_take(owned Event ValueLease, output160, capacity).
session_event_take:
    cbg_enter
    mov [rsp], rdi
    mov [rsp + 8], rsi
    mov [rsp + 16], rdx
    cmp rdx, 160
    jb tk_capacity
    test rsi, rsi
    jz tk_invalid
    call vl_validate
    mov rbx, [rsp]
    cmp qword ptr [rbx + 24], 128
    jne tk_invalid
    lea rax, [rip + session_event_drop_entry]
    cmp [rbx + 32], rax
    jne tk_invalid
    mov rdi, [rbx + 40]
    call scs_validate
    mov edi, 4096
    call cdf_allocate
    test rax, rax
    jz cdf_fatal
    mov r12, rax
    mov rbx, [rsp]
    mov [r12], rbx
    mov [r12 + 72], rbx
    mov rax, [rbx + 40]
    mov [r12 + 8], rax
    mov [r12 + 88], rax
    mov rax, [rbx + 8]
    mov [r12 + 16], rax
    mov [r12 + 80], rax
    mov qword ptr [r12 + 24], 4
    mov rax, [rsp + 8]
    mov [r12 + 48], rax
    mov qword ptr [r12 + 56], 192
    movabs rax, TD_REQUEST
    mov [r12 + 64], rax
    mov qword ptr [r12 + 96], 128
    lea rdi, [r12 + 128]
    mov rsi, [rbx + 16]
    mov ecx, 16
    cld
    rep movsq
    mov esi, 1
    call td_observe
tk_again:
    lea rdi, [r12 + 64]
    mov esi, 192
    lea rdx, [r12 + 256]
    mov ecx, 160
    lea r8, [r12 + 1024]
    mov r9d, 2048
    call tk_policy_invoke
    add qword ptr [r12 + 32], 1
    jc cdf_fatal
    mov edx, eax
    cmp rax, rdx
    jne cdf_fatal
    cmp eax, 0xfffffff0
    je tk_effect
    cmp eax, 0xffffffff
    je tk_rejected
    cmp eax, 0xfffffffe
    je tk_rejected
    cmp eax, 160
    jne cdf_fatal
    movabs rax, TK_RESPONSE
    cmp [r12 + 256], rax
    jne cdf_fatal
    mov rax, [r12 + 16]
    cmp [r12 + 264], rax
    jne cdf_fatal
    mov rax, [r12]
    cmp [r12 + 272], rax
    jne cdf_fatal
    cmp qword ptr [r12 + 280], 128
    jne cdf_fatal
    lea rdi, [r12 + 288]
    lea rsi, [r12 + 128]
    mov ecx, 16
    repe cmpsq
    jne cdf_fatal
    cmp qword ptr [r12 + 32], 2
    jne cdf_fatal
    cmp qword ptr [r12 + 40], 1
    jne cdf_fatal
    cmp qword ptr [r12 + 1056], 0
    jne cdf_fatal
    cmp qword ptr [r12 + 1080], 1
    jne cdf_fatal
    mov rdi, [r12 + 48]
    lea rsi, [r12 + 256]
    mov ecx, 20
    rep movsq
    mov r15d, 160
    jmp tk_return
tk_rejected:
    cmp qword ptr [r12 + 40], 0
    jne cdf_fatal
    mov r15d, eax
tk_return:
    mov esi, 2
    call td_observe
    mov rdi, r12
    mov esi, 4096
    call cdf_unmap
    mov rax, r15
    cbg_leave
tk_capacity:
    mov eax, 0xfffffffe
    cbg_leave
tk_invalid:
    mov eax, 0xffffffff
    cbg_leave

tk_effect:
    lea rbx, [r12 + 1024]
    movabs rax, TK_ACTION
    cmp [rbx + 512], rax
    jne cdf_fatal
    cmp qword ptr [rbx + 520], 4
    jne cdf_fatal
    cmp qword ptr [rbx + 528], 1
    jne cdf_fatal
    cmp qword ptr [r12 + 40], 0
    jne cdf_fatal
    mov rax, [r12 + 16]
    cmp [rbx + 536], rax
    jne cdf_fatal
    mov r14, [rbx + 544]
    cmp r14, [r12]
    jne cdf_fatal
    mov rax, [rbx + 552]
    or rax, [rbx + 560]
    or rax, [rbx + 568]
    or rax, [rbx + 576]
    jnz cdf_fatal
    cmp qword ptr [rbx + 584], 1024
    jne cdf_fatal
    cmp qword ptr [rbx + 592], 80
    jne cdf_fatal
    mov rax, [rbx + 600]
    or rax, [rbx + 608]
    or rax, [rbx + 616]
    or rax, [rbx + 624]
    or rax, [rbx + 632]
    jnz cdf_fatal
    lea rdi, [r12 + 512]
    lea rsi, [rbx + 512]
    mov ecx, 16
    rep movsq
    mov rdi, r14
    call vl_validate
    mov rax, [r12 + 16]
    cmp [r14 + 8], rax
    jne cdf_fatal
    cmp qword ptr [r14 + 24], 128
    jne cdf_fatal
    lea rax, [rip + session_event_drop_entry]
    cmp [r14 + 32], rax
    jne cdf_fatal
    mov rax, [r12 + 8]
    cmp [r14 + 40], rax
    jne cdf_fatal
    mov rdi, [r14 + 16]
    lea rsi, [r12 + 128]
    mov ecx, 16
    repe cmpsq
    jne cdf_fatal
    # Consume the enclosing Event storage only. Its fields remain uniquely owned.
    mov rdi, [r14 + 16]
    mov rsi, [r14 + 48]
    call cdf_unmap
    mov rdi, r14
    mov esi, 4096
    call cdf_unmap
    lea rdi, [r12 + 512]
    lea rsi, [rbx + 512]
    mov ecx, 16
    repe cmpsq
    jne cdf_fatal
    mov qword ptr [rbx + 600], 1
    mov qword ptr [r12 + 40], 1
    jmp tk_again
tk_policy_invoke:
    .byte 0xe8
event_take_policy_call_displacement:
    .long 0
    ret

# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
# Fixed Result typed Drop. One private continuation, actual child ValueLease Drop.
.equ RSD_REQUEST, 0x3130305144545248
.equ RSD_RESPONSE, 0x3130305244545248
.equ RSD_ACTION, 0x3130304144535248

session_result_drop_entry:
    cbg_enter
    mov [rsp], rdi
    mov [rsp + 8], rsi
    mov [rsp + 16], rdx
    mov [rsp + 24], rcx
    mov [rsp + 32], r8
    mov rdi, r8
    call vl_validate
    mov rbx, [rsp + 32]
    mov rax, [rsp + 8]
    cmp [rbx + 16], rax
    jne cdf_fatal
    cmp qword ptr [rsp + 16], 32
    jne cdf_fatal
    cmp qword ptr [rbx + 24], 32
    jne cdf_fatal
    mov rax, [rsp + 24]
    cmp [rbx + 8], rax
    jne cdf_fatal
    lea rax, [rip + session_result_drop_entry]
    cmp [rbx + 32], rax
    jne cdf_fatal
    mov rdi, [rsp]
    cmp [rbx + 40], rdi
    jne cdf_fatal
    call scs_validate
    mov edi, 4096
    call cdf_allocate
    test rax, rax
    jz cdf_fatal
    mov r12, rax
    mov rax, [rsp + 32]
    mov [r12], rax
    mov [r12 + 72], rax
    mov rax, [rsp]
    mov [r12 + 8], rax
    mov [r12 + 88], rax
    mov rax, [rsp + 24]
    mov [r12 + 16], rax
    mov [r12 + 80], rax
    mov qword ptr [r12 + 24], 7
    mov qword ptr [r12 + 96], 32
    mov qword ptr [r12 + 56], 96
    movabs rax, RSD_REQUEST
    mov [r12 + 64], rax
    lea rdi, [r12 + 128]
    mov rsi, [rsp + 8]
    mov ecx, 4
    cld
    rep movsq
    mov esi, 1
    call td_observe
rsd_again:
    lea rdi, [r12 + 64]
    mov esi, 96
    lea rdx, [r12 + 256]
    mov ecx, 80
    lea r8, [r12 + 1024]
    mov r9d, 2048
    call rsd_policy_invoke
    add qword ptr [r12 + 32], 1
    jc cdf_fatal
    mov edx, eax
    cmp rax, rdx
    jne cdf_fatal
    cmp eax, 0xfffffff0
    je rsd_effect
    cmp eax, 80
    jne cdf_fatal
    movabs rax, RSD_RESPONSE
    cmp [r12 + 256], rax
    jne cdf_fatal
    cmp qword ptr [r12 + 264], 0
    jne cdf_fatal
    mov rax, [r12 + 16]
    cmp [r12 + 272], rax
    jne cdf_fatal
    mov rax, [r12]
    cmp [r12 + 280], rax
    jne cdf_fatal
    cmp qword ptr [r12 + 288], 7
    jne cdf_fatal
    mov rax, [r12 + 40]
    cmp [r12 + 296], rax
    jne cdf_fatal
    add rax, 1
    cmp [r12 + 32], rax
    jne cdf_fatal
    mov rax, [r12 + 304]
    or rax, [r12 + 312]
    or rax, [r12 + 320]
    or rax, [r12 + 328]
    jnz cdf_fatal
    cmp qword ptr [r12 + 1056], 0
    jne cdf_fatal
    cmp qword ptr [r12 + 1080], 1
    jne cdf_fatal
    mov esi, 2
    call td_observe
    mov rdi, r12
    mov esi, 4096
    call cdf_unmap
    xor eax, eax
    cbg_leave
rsd_effect:
    lea rbx, [r12 + 1024]
    movabs rax, RSD_ACTION
    cmp [rbx + 512], rax
    jne cdf_fatal
    cmp qword ptr [rbx + 520], 1
    jne cdf_fatal
    cmp qword ptr [rbx + 528], 1
    jne cdf_fatal
    cmp qword ptr [r12 + 40], 0
    jne cdf_fatal
    mov rax, [r12 + 16]
    cmp [rbx + 536], rax
    jne cdf_fatal
    mov r14, [rbx + 544]
    test r14, r14
    jz cdf_fatal
    cmp [r12 + 152], r14
    jne cdf_fatal
    cmp [r12], r14
    je cdf_fatal
    mov rax, [rbx + 552]
    or rax, [rbx + 560]
    or rax, [rbx + 568]
    or rax, [rbx + 576]
    jnz cdf_fatal
    cmp qword ptr [rbx + 584], 1024
    jne cdf_fatal
    cmp qword ptr [rbx + 592], 128
    jne cdf_fatal
    mov rax, [rbx + 600]
    or rax, [rbx + 608]
    or rax, [rbx + 616]
    or rax, [rbx + 624]
    or rax, [rbx + 632]
    jnz cdf_fatal
    lea rdi, [r12 + 512]
    lea rsi, [rbx + 512]
    mov ecx, 16
    rep movsq
    mov rdi, r14
    call vl_validate
    mov rax, [r12 + 8]
    cmp [r14 + 40], rax
    jne cdf_fatal
    mov rdi, r14
    call value_lease_drop
    test rax, rax
    jnz cdf_fatal
    lea rdi, [r12 + 512]
    lea rsi, [rbx + 512]
    mov ecx, 16
    repe cmpsq
    jne cdf_fatal
    mov qword ptr [rbx + 600], 1
    mov qword ptr [r12 + 40], 1
    jmp rsd_again
rsd_policy_invoke:
    .byte 0xe8
session_result_drop_policy_call_displacement:
    .long 0
    ret

# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
# Fixed storage consumption after HIA transfers Result's owned fields.
.equ SRT_RESPONSE, 0x3130524652535248
.equ SRT_ACTION, 0x3130304152535248

# session_result_take(owned Result ValueLease, output64, capacity).
session_result_take:
    cbg_enter
    mov [rsp], rdi
    mov [rsp + 8], rsi
    mov [rsp + 16], rdx
    cmp rdx, 64
    jb srt_capacity
    test rsi, rsi
    jz srt_invalid
    call vl_validate
    mov rbx, [rsp]
    cmp qword ptr [rbx + 24], 32
    jne srt_invalid
    lea rax, [rip + session_result_drop_entry]
    cmp [rbx + 32], rax
    jne srt_invalid
    mov rdi, [rbx + 40]
    call scs_validate
    mov edi, 4096
    call cdf_allocate
    test rax, rax
    jz cdf_fatal
    mov r12, rax
    mov rbx, [rsp]
    mov [r12], rbx
    mov [r12 + 72], rbx
    mov rax, [rbx + 40]
    mov [r12 + 8], rax
    mov [r12 + 88], rax
    mov rax, [rbx + 8]
    mov [r12 + 16], rax
    mov [r12 + 80], rax
    mov qword ptr [r12 + 24], 9
    mov rax, [rsp + 8]
    mov [r12 + 48], rax
    mov qword ptr [r12 + 56], 96
    movabs rax, TD_REQUEST
    mov [r12 + 64], rax
    mov qword ptr [r12 + 96], 32
    lea rdi, [r12 + 128]
    mov rsi, [rbx + 16]
    mov ecx, 4
    cld
    rep movsq
    mov esi, 1
    call td_observe
srt_again:
    lea rdi, [r12 + 64]
    mov esi, 96
    lea rdx, [r12 + 256]
    mov ecx, 64
    lea r8, [r12 + 1024]
    mov r9d, 2048
    call srt_policy_invoke
    add qword ptr [r12 + 32], 1
    jc cdf_fatal
    mov edx, eax
    cmp rax, rdx
    jne cdf_fatal
    cmp eax, 0xfffffff0
    je srt_effect
    cmp eax, 0xffffffff
    je srt_rejected
    cmp eax, 0xfffffffe
    je srt_rejected
    cmp eax, 64
    jne cdf_fatal
    movabs rax, SRT_RESPONSE
    cmp [r12 + 256], rax
    jne cdf_fatal
    mov rax, [r12 + 16]
    cmp [r12 + 264], rax
    jne cdf_fatal
    mov rax, [r12]
    cmp [r12 + 272], rax
    jne cdf_fatal
    cmp qword ptr [r12 + 280], 32
    jne cdf_fatal
    lea rdi, [r12 + 288]
    lea rsi, [r12 + 128]
    mov ecx, 4
    repe cmpsq
    jne cdf_fatal
    cmp qword ptr [r12 + 32], 2
    jne cdf_fatal
    cmp qword ptr [r12 + 40], 1
    jne cdf_fatal
    cmp qword ptr [r12 + 1056], 0
    jne cdf_fatal
    cmp qword ptr [r12 + 1080], 1
    jne cdf_fatal
    mov rdi, [r12 + 48]
    lea rsi, [r12 + 256]
    mov ecx, 8
    rep movsq
    mov r15d, 64
    jmp srt_return
srt_rejected:
    cmp qword ptr [r12 + 40], 0
    jne cdf_fatal
    mov r15d, eax
srt_return:
    mov esi, 2
    call td_observe
    mov rdi, r12
    mov esi, 4096
    call cdf_unmap
    mov rax, r15
    cbg_leave
srt_capacity:
    mov eax, 0xfffffffe
    cbg_leave
srt_invalid:
    mov eax, 0xffffffff
    cbg_leave

srt_effect:
    lea rbx, [r12 + 1024]
    movabs rax, SRT_ACTION
    cmp [rbx + 512], rax
    jne cdf_fatal
    cmp qword ptr [rbx + 520], 4
    jne cdf_fatal
    cmp qword ptr [rbx + 528], 1
    jne cdf_fatal
    cmp qword ptr [r12 + 40], 0
    jne cdf_fatal
    mov rax, [r12 + 16]
    cmp [rbx + 536], rax
    jne cdf_fatal
    mov r14, [rbx + 544]
    cmp r14, [r12]
    jne cdf_fatal
    mov rax, [rbx + 552]
    or rax, [rbx + 560]
    or rax, [rbx + 568]
    or rax, [rbx + 576]
    jnz cdf_fatal
    cmp qword ptr [rbx + 584], 1024
    jne cdf_fatal
    cmp qword ptr [rbx + 592], 80
    jne cdf_fatal
    mov rax, [rbx + 600]
    or rax, [rbx + 608]
    or rax, [rbx + 616]
    or rax, [rbx + 624]
    or rax, [rbx + 632]
    jnz cdf_fatal
    lea rdi, [r12 + 512]
    lea rsi, [rbx + 512]
    mov ecx, 16
    rep movsq
    mov rdi, r14
    call vl_validate
    mov rax, [r12 + 16]
    cmp [r14 + 8], rax
    jne cdf_fatal
    cmp qword ptr [r14 + 24], 32
    jne cdf_fatal
    lea rax, [rip + session_result_drop_entry]
    cmp [r14 + 32], rax
    jne cdf_fatal
    mov rax, [r12 + 8]
    cmp [r14 + 40], rax
    jne cdf_fatal
    mov rdi, [r14 + 16]
    lea rsi, [r12 + 128]
    mov ecx, 4
    repe cmpsq
    jne cdf_fatal
    # Consume the enclosing Result storage only. Its fields remain uniquely owned.
    mov rdi, [r14 + 16]
    mov rsi, [r14 + 48]
    call cdf_unmap
    mov rdi, r14
    mov esi, 4096
    call cdf_unmap
    lea rdi, [r12 + 512]
    lea rsi, [rbx + 512]
    mov ecx, 16
    repe cmpsq
    jne cdf_fatal
    mov qword ptr [rbx + 600], 1
    mov qword ptr [r12 + 40], 1
    jmp srt_again
srt_policy_invoke:
    .byte 0xe8
session_result_take_policy_call_displacement:
    .long 0
    ret

# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
# Fixed private arenas, HIA child invocation and owned-value custody.
# HIA owns formatting, source-chain checks and error ownership decisions.
.equ SE_ACTION, 0x3130304145535248
.equ SE_DROP_REQUEST, 0x3130304445535248

# session_error_call(frame, bytes, output, capacity, optional counts32)
session_error_call:
    cbg_enter
    mov [rsp], rdi
    mov [rsp + 8], rsi
    mov [rsp + 16], rdx
    mov [rsp + 24], rcx
    mov [rsp + 32], r8
    test rdi, rdi
    jz se_invalid_early
    test rdx, rdx
    jz se_invalid_early
    cmp rsi, 8388800
    ja se_invalid_early
    cmp rcx, 67108864
    ja se_invalid_early
    mov rax, rdi
    add rax, rsi
    jc se_invalid_early
    mov rax, rdx
    add rax, rcx
    jc se_invalid_early
    mov edi, 4096
    call cdf_allocate
    test rax, rax
    jz cdf_fatal
    mov r12, rax
    mov rdi, r12
    mov rsi, rsp
    mov ecx, 5
    cld
    rep movsq
    mov edi, 268435456
    call cdf_allocate
    test rax, rax
    jz cdf_fatal
    mov r13, rax
se_again:
    mov rdi, [r12]
    mov rsi, [r12 + 8]
    mov rdx, [r12 + 16]
    mov rcx, [r12 + 24]
    mov r8, r13
    mov r9d, 268435456
    call se_policy_invoke
    add qword ptr [r12 + 40], 1
    jc cdf_fatal
    mov edx, eax
    cmp rax, rdx
    jne cdf_fatal
    cmp eax, 0xfffffff0
    je se_effect
    cmp eax, 0xffffffff
    je se_return
    cmp eax, 0xfffffffe
    je se_return
    cmp rax, [r12 + 24]
    ja cdf_fatal
se_return:
    mov [r12 + 88], rax
    mov rdi, [r12 + 32]
    test rdi, rdi
    jz se_no_counts
    lea rsi, [r12 + 40]
    mov ecx, 4
    rep movsq
se_no_counts:
    mov rdi, [r12 + 80]
    test rdi, rdi
    jz se_no_child_arena
    mov esi, 268435456
    call cdf_unmap
se_no_child_arena:
    mov rdi, r13
    mov esi, 268435456
    call cdf_unmap
    mov rax, [r12 + 88]
    mov [rsp + 40], rax
    mov rdi, r12
    mov esi, 4096
    call cdf_unmap
    mov rax, [rsp + 40]
    cbg_leave
se_invalid_early:
    mov eax, 0xffffffff
    cbg_leave

se_effect:
    lea rbx, [r13 + 512]
    movabs rax, SE_ACTION
    cmp [rbx], rax
    jne cdf_fatal
    mov r15, [rbx + 8]
    cmp r15, 1
    jb cdf_fatal
    cmp r15, 3
    ja cdf_fatal
    cmp r15, [rbx + 16]
    jne cdf_fatal
    cmp r15, [r12 + 72]
    jbe cdf_fatal
    cmp qword ptr [r12 + 72], 0
    jne se_not_first
    cmp r15, 1
    jne cdf_fatal
se_not_first:
    mov [r12 + 72], r15
    mov rax, [rbx + 24]
    cmp rax, 268435456
    ja cdf_fatal
    mov rcx, [rbx + 32]
    add rcx, rax
    jc cdf_fatal
    cmp rcx, 268435456
    ja cdf_fatal
    mov rax, [rbx + 40]
    cmp rax, 268435456
    ja cdf_fatal
    mov rcx, [rbx + 48]
    add rcx, rax
    jc cdf_fatal
    cmp rcx, 268435456
    ja cdf_fatal
    mov rax, [rbx + 80]
    or rax, [rbx + 88]
    or rax, [rbx + 96]
    or rax, [rbx + 104]
    or rax, [rbx + 112]
    or rax, [rbx + 120]
    jnz cdf_fatal
    lea rdi, [r12 + 128]
    mov rsi, rbx
    mov ecx, 16
    rep movsq
    cmp r15, 3
    je se_create
    cmp r15, 2
    je se_view
    cmp qword ptr [rbx + 24], 9437184
    jne cdf_fatal
    cmp qword ptr [rbx + 40], 18874368
    jne cdf_fatal
    cmp qword ptr [rbx + 48], 67108864
    jne cdf_fatal
    cmp qword ptr [rbx + 56], 268435456
    jne cdf_fatal
    mov rax, [rbx + 64]
    or rax, [rbx + 72]
    jnz cdf_fatal
    mov r14, [r12 + 80]
    test r14, r14
    jnz se_child_ready
    mov edi, 268435456
    call cdf_allocate
    test rax, rax
    jz cdf_fatal
    mov r14, rax
    mov [r12 + 80], rax
se_child_ready:
    mov rdi, [rbx + 24]
    add rdi, r13
    mov rsi, [rbx + 32]
    mov rdx, [rbx + 40]
    add rdx, r13
    mov rcx, [rbx + 48]
    mov r8, r14
    mov r9d, 268435456
    call se_sdk_policy_invoke
    add qword ptr [r12 + 48], 1
    jc cdf_fatal
    mov edx, eax
    cmp rax, rdx
    jne cdf_fatal
    mov [rsp + 48], rax
    xor edx, edx
    cmp eax, 0xffffffff
    je se_receipt
    cmp eax, 0xfffffffe
    je se_receipt
    cmp rax, [rbx + 48]
    ja cdf_fatal
    mov rdx, rax
    jmp se_receipt

# Fixed immutable ValueLease span copy; source text and chain comparison are HIA.
se_view:
    cmp qword ptr [rbx + 24], 9437184
    jne cdf_fatal
    cmp qword ptr [rbx + 32], 16
    jne cdf_fatal
    cmp qword ptr [rbx + 40], 85983232
    jne cdf_fatal
    cmp qword ptr [rbx + 48], 67108896
    jne cdf_fatal
    mov rax, [rbx + 56]
    or rax, [rbx + 64]
    or rax, [rbx + 72]
    jnz cdf_fatal
    mov rdi, [r13 + 9437184]
    call vl_validate
    mov rax, [r13 + 9437192]
    cmp [rdi + 40], rax
    jne cdf_fatal
    lea rax, [rip + session_error_drop_entry]
    cmp [rdi + 32], rax
    jne cdf_fatal
    call value_lease_span
    add qword ptr [r12 + 56], 1
    jc cdf_fatal
    cmp rdx, [rbx + 48]
    ja se_view_capacity
    mov rsi, rax
    mov rcx, rdx
    mov rdi, [rbx + 40]
    add rdi, r13
    cld
    rep movsb
    mov [rsp + 48], rdx
    jmp se_receipt
se_view_capacity:
    mov eax, 0xfffffffe
    mov [rsp + 48], rax
    xor edx, edx
    jmp se_receipt

se_create:
    cmp qword ptr [rbx + 24], 153092128
    jne cdf_fatal
    cmp qword ptr [rbx + 32], 1248
    jb cdf_fatal
    cmp qword ptr [rbx + 32], 67108896
    ja cdf_fatal
    cmp qword ptr [rbx + 40], 1024
    jne cdf_fatal
    cmp qword ptr [rbx + 48], 16
    jne cdf_fatal
    cmp qword ptr [rbx + 56], 0
    jne cdf_fatal
    cmp qword ptr [rbx + 64], 0
    je cdf_fatal
    mov rdi, [rbx + 72]
    call scs_validate
    mov rdi, [r13 + 153092136]
    test rdi, rdi
    jz se_create_admitted
    call vl_validate
    mov rax, [rbx + 72]
    cmp [rdi + 40], rax
    jne cdf_fatal
se_create_admitted:
    lea rdi, [r13 + 153092128]
    mov rsi, [rbx + 32]
    mov rdx, [rbx + 64]
    lea rcx, [rip + session_error_drop_entry]
    mov r8, [rbx + 72]
    call value_lease_create
    test rax, rax
    jz cdf_fatal
    mov [r13 + 1024], rax
    mov rax, [rbx + 64]
    mov [r13 + 1032], rax
    add qword ptr [r12 + 64], 1
    jc cdf_fatal
    mov qword ptr [rsp + 48], 0
    mov edx, 16
se_receipt:
    mov [rsp + 56], rdx
    lea rdi, [r12 + 128]
    mov rsi, rbx
    mov ecx, 16
    repe cmpsq
    jne cdf_fatal
    mov qword ptr [rbx + 80], 1
    mov rax, [rsp + 48]
    mov [rbx + 88], rax
    mov rax, [rsp + 56]
    mov [rbx + 96], rax
    jmp se_again

se_policy_invoke:
    .byte 0xe8
session_error_owner_policy_call_displacement:
    .long 0
    ret
se_sdk_policy_invoke:
    .byte 0xe8
session_error_project_policy_call_displacement:
    .long 0
    ret
# Error action 2 borrows an actual immutable source value.

# ValueLease typed callback. The HIA frame borrows only the fixed ownership
# prefix, retaining the complete immutable projection in its real value.
session_error_drop_entry:
    cbg_enter
    mov [rsp], rdi
    mov [rsp + 8], rsi
    mov [rsp + 16], rdx
    mov [rsp + 24], rcx
    mov [rsp + 32], r8
    mov rdi, r8
    call vl_validate
    mov rbx, [rsp + 32]
    mov rax, [rsp + 8]
    cmp [rbx + 16], rax
    jne cdf_fatal
    mov rax, [rsp + 16]
    cmp rax, 1248
    jb cdf_fatal
    cmp rax, 67108896
    ja cdf_fatal
    cmp [rbx + 24], rax
    jne cdf_fatal
    mov rax, [rsp + 24]
    cmp [rbx + 8], rax
    jne cdf_fatal
    mov rdi, [rsp]
    cmp [rbx + 40], rdi
    jne cdf_fatal
    call scs_validate
    lea rax, [rip + session_error_drop_entry]
    cmp [rbx + 32], rax
    jne cdf_fatal
    mov edi, 4096
    call cdf_allocate
    test rax, rax
    jz cdf_fatal
    mov r12, rax
    mov rax, [rsp + 32]
    mov [r12], rax
    mov [r12 + 72], rax
    mov rax, [rsp]
    mov [r12 + 8], rax
    mov [r12 + 88], rax
    mov rax, [rsp + 24]
    mov [r12 + 16], rax
    mov [r12 + 80], rax
    mov qword ptr [r12 + 24], 8
    mov rax, [rsp + 16]
    mov [r12 + 96], rax
    mov qword ptr [r12 + 56], 96
    movabs rax, SE_DROP_REQUEST
    mov [r12 + 64], rax
    lea rdi, [r12 + 128]
    mov rsi, [rsp + 8]
    mov ecx, 4
    cld
    rep movsq
    mov esi, 1
    call td_observe
setd_again:
    lea rdi, [r12 + 64]
    mov esi, 96
    lea rdx, [r12 + 256]
    mov ecx, 80
    lea r8, [r12 + 1024]
    mov r9d, 2048
    call setd_policy_invoke
    add qword ptr [r12 + 32], 1
    jc cdf_fatal
    mov edx, eax
    cmp rax, rdx
    jne cdf_fatal
    cmp eax, 0xfffffff0
    je setd_effect
    cmp eax, 80
    jne cdf_fatal
    movabs rax, TD_RESPONSE
    cmp [r12 + 256], rax
    jne cdf_fatal
    cmp qword ptr [r12 + 264], 0
    jne cdf_fatal
    mov rax, [r12 + 16]
    cmp [r12 + 272], rax
    jne cdf_fatal
    mov rax, [r12]
    cmp [r12 + 280], rax
    jne cdf_fatal
    cmp qword ptr [r12 + 288], 8
    jne cdf_fatal
    mov rax, [r12 + 40]
    cmp [r12 + 296], rax
    jne cdf_fatal
    mov rax, [r12 + 304]
    or rax, [r12 + 312]
    or rax, [r12 + 320]
    or rax, [r12 + 328]
    jnz cdf_fatal
    cmp qword ptr [r12 + 1056], 0
    jne cdf_fatal
    cmp qword ptr [r12 + 1080], 1
    jne cdf_fatal
    mov esi, 2
    call td_observe
    mov rdi, r12
    mov esi, 4096
    call cdf_unmap
    xor eax, eax
    cbg_leave
setd_effect:
    lea rbx, [r12 + 1024]
    movabs rax, TD_ACTION
    cmp [rbx + 512], rax
    jne cdf_fatal
    cmp qword ptr [rbx + 520], 1
    jne cdf_fatal
    cmp qword ptr [rbx + 528], 1
    jne cdf_fatal
    cmp qword ptr [r12 + 40], 0
    jne cdf_fatal
    mov rax, [r12 + 16]
    cmp [rbx + 536], rax
    jne cdf_fatal
    mov r14, [rbx + 544]
    test r14, r14
    jz cdf_fatal
    cmp [r12], r14
    je cdf_fatal
    mov rax, [rbx + 552]
    or rax, [rbx + 560]
    or rax, [rbx + 568]
    or rax, [rbx + 576]
    jnz cdf_fatal
    cmp qword ptr [rbx + 584], 1024
    jne cdf_fatal
    cmp qword ptr [rbx + 592], 80
    jne cdf_fatal
    mov rax, [rbx + 600]
    or rax, [rbx + 608]
    or rax, [rbx + 616]
    or rax, [rbx + 624]
    or rax, [rbx + 632]
    jnz cdf_fatal
    lea rdi, [r12 + 512]
    lea rsi, [rbx + 512]
    mov ecx, 16
    rep movsq
    mov rdi, r14
    call vl_validate
    mov rax, [r12 + 8]
    cmp [rdi + 40], rax
    jne cdf_fatal
    call value_lease_drop
    test rax, rax
    jnz cdf_fatal
    lea rdi, [r12 + 512]
    lea rsi, [rbx + 512]
    mov ecx, 16
    repe cmpsq
    jne cdf_fatal
    mov qword ptr [rbx + 600], 1
    mov qword ptr [r12 + 40], 1
    jmp setd_again
setd_policy_invoke:
    .byte 0xe8
session_error_drop_policy_call_displacement:
    .long 0
    ret

# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
# Fixed memory and ValueLease custody. HIA decides IO construction, move or drop.
.equ SCI_ACTION, 0x3130414945535248

# session_error_into_io(frame64, length, output64, capacity, optional counts40)
session_error_into_io:
    cbg_enter
    mov [rsp], rdi
    mov [rsp + 8], rsi
    mov [rsp + 16], rdx
    mov [rsp + 24], rcx
    mov [rsp + 32], r8
    test rdi, rdi
    jz sci_invalid
    test rdx, rdx
    jz sci_invalid
    cmp rsi, 64
    jne sci_invalid
    cmp rcx, 67108864
    ja sci_invalid
    mov rax, rdi
    add rax, rsi
    jc sci_invalid
    mov rax, rdx
    add rax, rcx
    jc sci_invalid
    mov edi, 4096
    call cdf_allocate
    test rax, rax
    jz cdf_fatal
    mov r12, rax
    mov rdi, r12
    mov rsi, rsp
    mov ecx, 5
    cld
    rep movsq
    mov edi, 268435456
    call cdf_allocate
    test rax, rax
    jz cdf_fatal
    mov r13, rax
sci_again:
    mov rdi, [r12]
    mov rsi, [r12 + 8]
    mov rdx, [r12 + 16]
    mov rcx, [r12 + 24]
    mov r8, r13
    mov r9d, 268435456
    call sci_policy_invoke
    add qword ptr [r12 + 40], 1
    jc cdf_fatal
    mov edx, eax
    cmp rax, rdx
    jne cdf_fatal
    cmp eax, 0xfffffff0
    je sci_effect
    cmp eax, 0xffffffff
    je sci_return
    cmp eax, 0xfffffffe
    je sci_return
    cmp rax, [r12 + 24]
    ja cdf_fatal
sci_return:
    mov [r12 + 88], rax
    mov rdi, [r12 + 32]
    test rdi, rdi
    jz sci_no_counts
    lea rsi, [r12 + 40]
    mov ecx, 5
    cld
    rep movsq
sci_no_counts:
    mov rdi, r13
    mov esi, 268435456
    call cdf_unmap
    mov rax, [r12 + 88]
    mov [rsp + 40], rax
    mov rdi, r12
    mov esi, 4096
    call cdf_unmap
    mov rax, [rsp + 40]
    cbg_leave
sci_invalid:
    mov eax, 0xffffffff
    cbg_leave

sci_effect:
    lea rbx, [r13 + 512]
    movabs rax, SCI_ACTION
    cmp [rbx], rax
    jne cdf_fatal
    mov r15, [rbx + 8]
    cmp r15, 1
    jb cdf_fatal
    cmp r15, 4
    ja cdf_fatal
    mov rax, r15
    cmp r15, 4
    jne sci_sequence
    mov eax, 3
sci_sequence:
    cmp [rbx + 16], rax
    jne cdf_fatal
    mov rdx, [r12 + 80]
    inc rdx
    cmp rax, rdx
    jne cdf_fatal
    mov [r12 + 80], rax
    mov rax, [rbx + 24]
    cmp rax, 268435456
    ja cdf_fatal
    mov rcx, [rbx + 32]
    add rcx, rax
    jc cdf_fatal
    cmp rcx, 268435456
    ja cdf_fatal
    mov rax, [rbx + 40]
    cmp rax, 268435456
    ja cdf_fatal
    mov rcx, [rbx + 48]
    add rcx, rax
    jc cdf_fatal
    cmp rcx, 268435456
    ja cdf_fatal
    mov rax, [rbx + 80]
    or rax, [rbx + 88]
    or rax, [rbx + 96]
    or rax, [rbx + 104]
    or rax, [rbx + 112]
    or rax, [rbx + 120]
    jnz cdf_fatal
    lea rdi, [r12 + 128]
    mov rsi, rbx
    mov ecx, 16
    cld
    rep movsq
    cmp r15, 1
    je sci_view
    cmp r15, 2
    je sci_create
    jmp sci_owned_action

sci_view:
    cmp qword ptr [rbx + 24], 8192
    jne cdf_fatal
    cmp qword ptr [rbx + 32], 16
    jne cdf_fatal
    cmp qword ptr [rbx + 40], 65536
    jne cdf_fatal
    cmp qword ptr [rbx + 48], 67108896
    jne cdf_fatal
    mov rax, [rbx + 56]
    or rax, [rbx + 64]
    or rax, [rbx + 72]
    jnz cdf_fatal
    mov rdi, [r13 + 8192]
    call vl_validate
    mov rax, [r13 + 8200]
    cmp [rdi + 40], rax
    jne cdf_fatal
    lea rax, [rip + session_error_drop_entry]
    cmp [rdi + 32], rax
    jne sci_view_invalid
    mov rsi, rdi
    lea rdi, [r12 + 256]
    mov ecx, 10
    rep movsq
    mov rdi, [r13 + 8192]
    call value_lease_span
    add qword ptr [r12 + 48], 1
    jc cdf_fatal
    cmp rdx, [rbx + 48]
    ja sci_view_capacity
    mov rsi, rax
    mov rcx, rdx
    lea rdi, [r13 + 65536]
    rep movsb
    mov [rsp + 48], rdx
    jmp sci_receipt
sci_view_capacity:
    mov eax, 0xfffffffe
    mov [rsp + 48], rax
    xor edx, edx
    jmp sci_receipt
sci_view_invalid:
    mov eax, 0xffffffff
    mov [rsp + 48], rax
    xor edx, edx
    jmp sci_receipt

sci_create:
    cmp qword ptr [rbx + 24], 75497472
    jne cdf_fatal
    cmp qword ptr [rbx + 32], 1248
    jb cdf_fatal
    cmp qword ptr [rbx + 32], 67108896
    ja cdf_fatal
    cmp qword ptr [rbx + 40], 2048
    jne cdf_fatal
    cmp qword ptr [rbx + 48], 16
    jne cdf_fatal
    cmp qword ptr [rbx + 56], 0
    jne cdf_fatal
    cmp qword ptr [rbx + 64], 0
    je cdf_fatal
    mov rdi, [rbx + 72]
    call scs_validate
    mov rdi, [r13 + 75497480]
    test rdi, rdi
    jz sci_create_admitted
    call vl_validate
    mov rax, [rbx + 72]
    cmp [rdi + 40], rax
    jne cdf_fatal
    lea rax, [rip + session_error_drop_entry]
    cmp [rdi + 32], rax
    jne cdf_fatal
sci_create_admitted:
    lea rdi, [r13 + 75497472]
    mov rsi, [rbx + 32]
    mov rdx, [rbx + 64]
    lea rcx, [rip + session_error_drop_entry]
    mov r8, [rbx + 72]
    call value_lease_create
    test rax, rax
    jz cdf_fatal
    mov [r13 + 2048], rax
    mov rax, [rbx + 64]
    mov [r13 + 2056], rax
    add qword ptr [r12 + 56], 1
    jc cdf_fatal
    mov qword ptr [rsp + 48], 0
    mov edx, 16
    jmp sci_receipt

sci_owned_action:
    cmp qword ptr [rbx + 24], 8192
    jne cdf_fatal
    cmp qword ptr [rbx + 32], 16
    jne cdf_fatal
    cmp qword ptr [rbx + 40], 3072
    jne cdf_fatal
    mov rax, [rbx + 48]
    or rax, [rbx + 56]
    or rax, [rbx + 64]
    or rax, [rbx + 72]
    jnz cdf_fatal
    mov r14, [r13 + 8192]
    mov rdi, r14
    call vl_validate
    lea rsi, [r12 + 256]
    mov ecx, 10
    repe cmpsq
    jne cdf_fatal
    mov rax, [r13 + 8200]
    cmp [r14 + 40], rax
    jne cdf_fatal
    mov rdi, [r14 + 16]
    lea rsi, [r13 + 65536]
    mov rcx, [r14 + 24]
    cmp rcx, 67108896
    ja cdf_fatal
    repe cmpsb
    jne cdf_fatal
    cmp r15, 4
    je sci_drop
    # The admitted HIA continuation transfers fields before consuming storage.
    mov rdi, [r14 + 16]
    mov rsi, [r14 + 48]
    call cdf_unmap
    mov rdi, r14
    mov esi, 4096
    call cdf_unmap
    add qword ptr [r12 + 64], 1
    jc cdf_fatal
    jmp sci_owned_done
sci_drop:
    mov rdi, r14
    call value_lease_drop
    test rax, rax
    jnz cdf_fatal
    add qword ptr [r12 + 72], 1
    jc cdf_fatal
sci_owned_done:
    mov qword ptr [rsp + 48], 0
    xor edx, edx
sci_receipt:
    mov [rsp + 56], rdx
    lea rdi, [r12 + 128]
    mov rsi, rbx
    mov ecx, 16
    repe cmpsq
    jne cdf_fatal
    mov qword ptr [rbx + 80], 1
    mov rax, [rsp + 48]
    mov [rbx + 88], rax
    mov rax, [rsp + 56]
    mov [rbx + 96], rax
    jmp sci_again

sci_policy_invoke:
    .byte 0xe8
session_error_into_io_policy_call_displacement:
    .long 0
    ret

# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
# Fixed ABI, mappings, typed child calls and physical receipts. All future policy is HIA.
.equ LHF_CONTEXT, 0x3130304348535248
.equ LHF_ACTION, 0x3130414948535248
.equ LHF_TRACE, 0x3130305448535248

# create(frame, length, output, capacity, counters64, optional_trace) -> context or zero.
session_handle_future_create:
    cbg_enter
    cmp rsi, 128
    jne lhf_create_zero
    mov [rsp], rdi
    mov [rsp + 8], rdx
    mov [rsp + 16], rcx
    mov [rsp + 24], r8
    mov [rsp + 32], r9
    mov edi, 4096
    call cdf_allocate
    test rax, rax
    jz lhf_create_zero
    mov r12, rax
    mov edi, 16384
    call cdf_allocate
    test rax, rax
    jz cdf_fatal
    mov [r12 + 8], rax
    mov rsi, [rsp]
    lea rdi, [r12 + 64]
    mov ecx, 16
    cld
    rep movsq
    mov rax, [rsp + 8]
    mov [r12 + 200], rax
    mov rax, [rsp + 16]
    mov [r12 + 208], rax
    mov rax, [rsp + 24]
    mov [r12 + 216], rax
    mov rax, [rsp + 32]
    mov [r12 + 48], rax
    mov rax, [r12 + 96]
    mov [r12 + 16], rax
    mov rdi, r12
    call lhf_drive
    cmp rax, 64
    jne lhf_create_free
    mov rdi, [r12 + 16]
    call scs_validate
    mov eax, 186
    syscall
    mov [r12 + 24], rax
    movabs rax, LHF_CONTEXT
    mov [r12], rax
    mov rax, r12
    cbg_leave
lhf_create_free:
    mov rdi, [r12 + 8]
    mov esi, 16384
    call cdf_unmap
    mov rdi, r12
    mov esi, 4096
    call cdf_unmap
lhf_create_zero:
    xor eax, eax
    cbg_leave

# call(context, operation, actual_waker, output, capacity, counters64) -> HIA result.
# A successful operation 3 destroys the future context after HIA requested all drops.
session_handle_future_call:
    cbg_enter
    mov r12, rdi
    mov [rsp], rsi
    mov [rsp + 8], rdx
    mov [rsp + 16], rcx
    mov [rsp + 24], r8
    mov [rsp + 32], r9
    test r12, r12
    jz cdf_fatal
    movabs rax, LHF_CONTEXT
    cmp [r12], rax
    jne cdf_fatal
    mov eax, 186
    syscall
    cmp [r12 + 24], rax
    jne cdf_fatal
    cmp qword ptr [r12 + 32], 0
    jne cdf_fatal
    mov qword ptr [r12 + 32], 1
    mov rdi, [r12 + 16]
    call scs_validate
    mov rax, [rsp]
    mov [r12 + 72], rax
    mov rax, [rsp + 8]
    mov [r12 + 168], rax
    mov rax, [rsp + 16]
    mov [r12 + 200], rax
    mov rax, [rsp + 24]
    mov [r12 + 208], rax
    mov rax, [rsp + 32]
    mov [r12 + 216], rax
    mov rdi, r12
    call lhf_drive
    mov [rsp + 40], rax
    mov qword ptr [r12 + 32], 0
    cmp rax, 64
    jne lhf_call_return
    mov rdi, [r12 + 200]
    cmp qword ptr [rdi + 8], 3
    jne lhf_call_return
    mov rdi, [r12 + 8]
    mov esi, 16384
    call cdf_unmap
    mov rdi, r12
    mov esi, 4096
    call cdf_unmap
lhf_call_return:
    mov rax, [rsp + 40]
    cbg_leave

lhf_drive:
    cbg_enter
    mov r12, rdi
    mov r13, [r12 + 8]
    lea rdi, [r12 + 512]
    xor eax, eax
    mov ecx, 8
    cld
    rep stosq
lhf_again:
    lea rdi, [r12 + 64]
    mov esi, 128
    mov rdx, [r12 + 200]
    mov rcx, [r12 + 208]
    mov r8, r13
    mov r9d, 16384
    call lhf_policy_invoke
    add qword ptr [r12 + 512], 1
    jc cdf_fatal
    mov edx, eax
    cmp rax, rdx
    jne cdf_fatal
    cmp eax, 0xfffffff0
    je lhf_effect
    cmp eax, 0xffffffff
    je lhf_done
    cmp eax, 0xfffffffe
    je lhf_done
    cmp rax, 64
    jne cdf_fatal
lhf_done:
    mov [r12 + 224], rax
    mov rdi, [r12 + 216]
    test rdi, rdi
    jz lhf_no_counts
    lea rsi, [r12 + 512]
    mov ecx, 8
    rep movsq
lhf_no_counts:
    mov rax, [r12 + 224]
    cbg_leave

lhf_effect:
    lea rbx, [r13 + 512]
    movabs rax, LHF_ACTION
    cmp [rbx], rax
    jne cdf_fatal
    mov r15, [rbx + 8]
    cmp r15, 1
    jb cdf_fatal
    cmp r15, 7
    ja cdf_fatal
    mov rax, [r12 + 232]
    add rax, 1
    jc cdf_fatal
    cmp [rbx + 16], rax
    jne cdf_fatal
    mov [r12 + 232], rax
    cmp qword ptr [rbx + 32], 2048
    jne cdf_fatal
    cmp qword ptr [rbx + 40], 512
    ja cdf_fatal
    cmp qword ptr [rbx + 48], 4096
    jne cdf_fatal
    cmp qword ptr [rbx + 56], 512
    ja cdf_fatal
    mov rax, [rbx + 80]
    cmp rax, [r12 + 16]
    jne cdf_fatal
    mov rax, [rbx + 88]
    or rax, [rbx + 96]
    or rax, [rbx + 104]
    or rax, [rbx + 112]
    or rax, [rbx + 120]
    jnz cdf_fatal
    lea rdi, [r12 + 768]
    mov rsi, rbx
    mov ecx, 16
    rep movsq
    mov rdi, r12
    mov esi, 1
    call lhf_trace
    add qword ptr [r12 + 512 + r15 * 8], 1
    jc cdf_fatal
    cmp r15, 1
    je lhf_view
    cmp r15, 2
    je lhf_oneshot_create
    cmp r15, 3
    je lhf_value_create
    cmp r15, 4
    je lhf_mpsc
    cmp r15, 5
    je lhf_oneshot
    cmp r15, 6
    je lhf_drop
    lea rdi, [r13 + 2048]
    mov rsi, [rbx + 40]
    lea rdx, [r13 + 4096]
    mov rcx, [rbx + 56]
    lea r8, [r12 + 896]
    call session_error_call
    jmp lhf_child_return

lhf_view:
    cmp qword ptr [rbx + 40], 8
    jne cdf_fatal
    mov rdi, [r13 + 2048]
    call vl_validate
    mov rax, [r12 + 16]
    cmp [rdi + 40], rax
    jne cdf_fatal
    lea rax, [rip + owned_mpsc_handle_drop_entry]
    cmp qword ptr [rbx + 64], 1
    je lhf_view_entry
    cmp qword ptr [rbx + 64], 2
    jne cdf_fatal
    lea rax, [rip + session_result_drop_entry]
lhf_view_entry:
    cmp [rdi + 32], rax
    jne cdf_fatal
    call value_lease_span
    cmp rdx, [rbx + 56]
    ja cdf_fatal
    mov rsi, rax
    lea rdi, [r13 + 4096]
    mov rcx, rdx
    rep movsb
    mov rax, rdx
    jmp lhf_child_return

lhf_oneshot_create:
    cmp qword ptr [rbx + 40], 16
    jne cdf_fatal
    cmp qword ptr [rbx + 56], 16
    jne cdf_fatal
    mov rdi, [r13 + 2048]
    mov rsi, [r13 + 2056]
    xor edx, edx
    call oneshot_create
    test rax, rax
    jz cdf_fatal
    mov [r13 + 4096], rax
    mov rax, [r13 + 2056]
    mov [r13 + 4104], rax
    xor eax, eax
    mov edx, 16
    jmp lhf_receipt

lhf_value_create:
    cmp qword ptr [rbx + 56], 16
    jne cdf_fatal
    lea rcx, [rip + owned_oneshot_handle_drop_entry]
    cmp qword ptr [rbx + 64], 1
    je lhf_create_entry
    lea rcx, [rip + session_event_drop_entry]
    cmp qword ptr [rbx + 64], 2
    je lhf_create_entry
    lea rcx, [rip + session_result_drop_entry]
    cmp qword ptr [rbx + 64], 3
    jne cdf_fatal
lhf_create_entry:
    lea rdi, [r13 + 2048]
    mov rsi, [rbx + 40]
    mov rdx, [rbx + 72]
    mov r8, [rbx + 80]
    call value_lease_create
    test rax, rax
    jz cdf_fatal
    mov [r13 + 4096], rax
    mov rax, [rbx + 72]
    mov [r13 + 4104], rax
    xor eax, eax
    mov edx, 16
    jmp lhf_receipt

lhf_mpsc:
    mov rdi, [rbx + 64]
    lea rsi, [r13 + 2048]
    mov rdx, [rbx + 40]
    lea rcx, [r13 + 4096]
    mov r8, [rbx + 56]
    call bounded_mpsc_call
    jmp lhf_child_return
lhf_oneshot:
    mov rdi, [rbx + 64]
    lea rsi, [r13 + 2048]
    mov rdx, [rbx + 40]
    lea rcx, [r13 + 4096]
    mov r8, [rbx + 56]
    call oneshot_call
    jmp lhf_child_return
lhf_drop:
    cmp qword ptr [rbx + 40], 8
    jne cdf_fatal
    cmp qword ptr [rbx + 56], 0
    jne cdf_fatal
    mov rdi, [r13 + 2048]
    call vl_validate
    mov rax, [r12 + 16]
    cmp [rdi + 40], rax
    jne cdf_fatal
    call value_lease_drop
    test rax, rax
    jnz cdf_fatal
lhf_child_return:
    cmp rax, [rbx + 56]
    ja cdf_fatal
    mov rdx, rax
lhf_receipt:
    mov [r12 + 240], rax
    mov [r12 + 248], rdx
    lea rdi, [r12 + 768]
    mov rsi, rbx
    mov ecx, 16
    repe cmpsq
    jne cdf_fatal
    mov rdi, r12
    mov esi, 2
    call lhf_trace
    mov qword ptr [rbx + 88], 1
    mov rax, [r12 + 240]
    mov [rbx + 96], rax
    mov rax, [r12 + 248]
    mov [rbx + 104], rax
    jmp lhf_again

# Optional raw physical evidence. No branches implement protocol outcomes here.
# 2048-byte rows preserve action, all private input/output bytes and actual descriptor.
lhf_trace:
    cbg_enter
    mov r12, rdi
    mov r13, rsi
    mov r15, [r12 + 48]
    test r15, r15
    jz lhf_trace_done
    movabs rax, LHF_TRACE
    cmp [r15], rax
    jne cdf_fatal
    mov rax, [r15 + 24]
    cmp rax, [r15 + 16]
    jae cdf_fatal
    mov r14, rax
    shl r14, 11
    shr r14, 11
    cmp rax, r14
    jne cdf_fatal
    shl r14, 11
    add r14, [r15 + 8]
    jc cdf_fatal
    mov rdi, r14
    xor eax, eax
    mov ecx, 256
    cld
    rep stosq
    mov [r14], r13
    mov rbx, [r12 + 8]
    mov rax, [rbx + 520]
    mov [r14 + 8], rax
    mov rax, [rbx + 528]
    mov [r14 + 16], rax
    mov rax, [rbx + 536]
    mov [r14 + 24], rax
    mov [r14 + 48], r12
    mov [r14 + 56], rbx
    lea rdi, [r14 + 64]
    lea rsi, [rbx + 512]
    mov ecx, 16
    rep movsq
    lea rdi, [r14 + 192]
    lea rsi, [rbx + 2048]
    mov ecx, 64
    rep movsq
    lea rdi, [r14 + 704]
    lea rsi, [rbx + 4096]
    mov ecx, 64
    rep movsq
    lea rdi, [r14 + 1344]
    lea rsi, [r12 + 512]
    mov ecx, 8
    rep movsq
    cmp r13, 2
    jne lhf_trace_recorded
    mov rax, [r12 + 240]
    mov [r14 + 32], rax
    mov rax, [r12 + 248]
    mov [r14 + 40], rax
    mov rax, [r14 + 8]
    cmp rax, 1
    je lhf_trace_view
    cmp rax, 2
    je lhf_trace_channel
    cmp rax, 3
    jne lhf_trace_recorded
    mov rsi, [rbx + 4096]
    mov ecx, 10
    jmp lhf_trace_extra
lhf_trace_view:
    mov rsi, [rbx + 2048]
    mov ecx, 10
    jmp lhf_trace_extra
lhf_trace_channel:
    mov rsi, [rbx + 4096]
    mov ecx, 16
lhf_trace_extra:
    lea rdi, [r14 + 1216]
    rep movsq
lhf_trace_recorded:
    add qword ptr [r15 + 24], 1
    jc cdf_fatal
lhf_trace_done:
    cbg_leave

lhf_policy_invoke:
    .byte 0xe8
session_handle_future_policy_call_displacement:
    .long 0
    ret

# One physical scheduler thread; all callback owners outlive this timer context.
.equ TM_MAGIC, 0x31305443544d5248
.equ TM_REQUEST, 0x313030514d545248
.equ TM_REPLY, 0x313030524d545248
.macro tm_enter
    push rbp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub rsp, 120
.endm
.macro tm_leave
    add rsp, 120
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret
.endm

# create(generation, fixed_hook_owner, borrowed_eventfd_or_minus_one) -> context/0.
timer_owner_create:
    tm_enter
    mov r13, rdi
    mov r14, rsi
    mov r15, rdx
    test r13, r13
    jz tm_create_failed
    test r14, r14
    jz tm_create_failed
    cmp r15, -1
    jl tm_create_failed
    cmp r15, 0x7fffffff
    jg tm_create_failed
    mov edi, 4096
    call tm_allocate
    test rax, rax
    jz tm_create_failed
    mov r12, rax
    mov qword ptr [r12 + 48], -1
    mov qword ptr [r12 + 56], -1
    mov edi, 8192
    call tm_allocate
    test rax, rax
    jz tm_create_free_context
    mov [r12 + 16], rax
    mov qword ptr [r12 + 32], 8192
    mov [r12 + 8], r13
    mov [r12 + 64], r14
    mov eax, 186
    syscall
    test rax, rax
    jle tm_fatal
    mov [r12 + 24], rax
    mov edi, 1
    mov esi, 0x80800
    mov eax, 283
    syscall
    test rax, rax
    js tm_create_free_work
    mov [r12 + 48], rax
    cmp r15, -1
    jne tm_create_borrow_wake
    xor edi, edi
    mov esi, 0x80800
    mov eax, 290
    syscall
    test rax, rax
    js tm_create_close_timer
    mov [r12 + 56], rax
    mov qword ptr [r12 + 96], 1
    jmp tm_create_ready
tm_create_borrow_wake:
    mov [r12 + 56], r15
tm_create_ready:
    movabs rax, TM_MAGIC
    mov [r12], rax
    call tm_clock
    xor eax, eax
    xor edx, edx
    mov rdi, rsp
    call tm_frame
    mov rax, [r12 + 912]
    mov [rsp + 32], rax
    mov rax, [r12 + 920]
    mov [rsp + 40], rax
    mov rdi, r12
    mov rsi, rsp
    mov edx, 96
    lea rcx, [r12 + 256]
    mov r8d, 640
    call timer_owner_call
    cmp rax, 640
    jne tm_fatal
    cmp qword ptr [r12 + 264], 0
    jne tm_fatal
    mov rax, r12
    tm_leave
tm_create_close_timer:
    mov rdi, [r12 + 48]
    mov qword ptr [r12 + 48], -1
    mov eax, 3
    syscall
tm_create_free_work:
    mov rdi, [r12 + 16]
    mov esi, 8192
    call tm_unmap
tm_create_free_context:
    mov rdi, r12
    mov esi, 4096
    call tm_unmap
tm_create_failed:
    xor eax, eax
    tm_leave

# Validate only this owned context and its creator thread, never a global TLS slot.
tm_validate:
    test r12, r12
    jz tm_fatal
    movabs rax, TM_MAGIC
    cmp [r12], rax
    jne tm_fatal
    mov eax, 186
    syscall
    cmp [r12 + 24], rax
    jne tm_fatal
    ret

# Build a private input: r12=context, rax=operation, rdx=token, rdi=96-byte slot.
tm_frame:
    mov r8, rdi
    mov r10, rax
    mov r11, rdx
    xor eax, eax
    mov ecx, 12
    cld
    rep stosq
    movabs rax, TM_REQUEST
    mov [r8], rax
    mov [r8 + 8], r10
    mov rax, [r12 + 8]
    mov [r8 + 16], rax
    mov [r8 + 24], r11
    ret

tm_allocate:
    push rbx
    push r12
    push r13
    add rdi, 4095
    jc tm_allocate_failed
    mov r12, rdi
    and r12, -4096
    mov r13, r12
    add r13, 4096
    jc tm_allocate_failed
    xor edi, edi
    mov rsi, r13
    mov edx, 3
    mov r10d, 0x22
    mov r8, -1
    xor r9d, r9d
    mov eax, 9
    syscall
    cmp rax, -4095
    jae tm_allocate_failed
    mov rbx, rax
    lea rdi, [rbx + r12]
    mov esi, 4096
    xor edx, edx
    mov eax, 10
    syscall
    test rax, rax
    jnz tm_allocate_release
    mov rax, rbx
    jmp tm_allocate_done
tm_allocate_release:
    mov rdi, rbx
    mov rsi, r13
    mov eax, 11
    syscall
tm_allocate_failed:
    xor eax, eax
tm_allocate_done:
    pop r13
    pop r12
    pop rbx
    ret
tm_unmap:
    add rsi, 4095
    and rsi, -4096
    add rsi, 4096
    mov eax, 11
    syscall
    test rax, rax
    jnz tm_fatal
    ret
tm_fatal:
    mov edi, 70
    mov eax, 231
    syscall
    ud2

# call(context, input96, length, output640, capacity) -> original HIA u32 result.
# All policy (including time arithmetic and wheel ordering) remains inside HIA.
timer_owner_call:
    tm_enter
    mov r12, rdi
    mov r13, rsi
    mov r14, rcx
    cmp rdx, 96
    jne tm_call_invalid
    cmp r8, 640
    jb tm_call_capacity
    test r12, r12
    jz tm_call_invalid
    test r13, r13
    jz tm_call_invalid
    test r14, r14
    jz tm_call_invalid
    movabs rax, TM_MAGIC
    cmp [r12], rax
    jne tm_call_invalid
    mov eax, 186
    syscall
    cmp [r12 + 24], rax
    jne tm_call_invalid
    cmp qword ptr [r12 + 40], 0
    jne tm_call_invalid
    mov rax, [r13 + 16]
    cmp rax, [r12 + 8]
    jne tm_call_invalid
    mov rdi, rsp
    mov rsi, r13
    mov ecx, 12
    cld
    rep movsq
    mov qword ptr [r12 + 40], 1
tm_call_again:
    mov rdi, rsp
    mov esi, 96
    lea rdx, [r12 + 256]
    mov ecx, 640
    mov r8, [r12 + 16]
    mov r9, [r12 + 32]
    call tm_invoke
    add qword ptr [r12 + 104], 1
    jc tm_fatal
    mov edx, eax
    cmp rax, rdx
    jne tm_fatal
    cmp eax, 0xfffffffd
    je tm_call_grow
    cmp eax, 640
    je tm_call_success
    cmp eax, 0xffffffff
    je tm_call_return
    cmp eax, 0xfffffffe
    jne tm_fatal
tm_call_return:
    mov qword ptr [r12 + 40], 0
    tm_leave
tm_call_success:
    movabs rax, TM_REPLY
    cmp [r12 + 256], rax
    jne tm_fatal
    mov rax, [r12 + 272]
    cmp rax, [r12 + 8]
    jne tm_fatal
    cmp qword ptr [r12 + 264], 3
    ja tm_fatal
    cmp qword ptr [r12 + 352], 32
    ja tm_fatal
    cmp qword ptr [r12 + 360], 1
    ja tm_fatal
    cmp qword ptr [r12 + 368], 1
    ja tm_fatal
    cmp qword ptr [r12 + 376], 0
    jne tm_fatal
    xor ebx, ebx
tm_call_events:
    cmp rbx, [r12 + 352]
    jae tm_call_unpark
    mov rbp, rbx
    shl rbp, 4
    mov rax, [r12 + rbp + 384]
    mov rdi, [r12 + 64]
    mov rsi, [r12 + rbp + 392]
    test rsi, rsi
    jz tm_fatal
    cmp rax, 1
    je tm_call_clone
    cmp rax, 2
    je tm_call_wake
    cmp rax, 3
    jne tm_fatal
    call timer_waker_drop
    add qword ptr [r12 + 128], 1
    jc tm_fatal
    jmp tm_call_event_done
tm_call_clone:
    call timer_waker_clone
    add qword ptr [r12 + 112], 1
    jc tm_fatal
    jmp tm_call_event_done
tm_call_wake:
    call timer_waker_wake
    add qword ptr [r12 + 120], 1
    jc tm_fatal
tm_call_event_done:
    test rax, rax
    jnz tm_fatal
    inc rbx
    jmp tm_call_events
tm_call_unpark:
    cmp qword ptr [r12 + 368], 0
    je tm_call_copy
    mov qword ptr [rsp + 104], 1
tm_call_unpark_retry:
    mov rdi, [r12 + 56]
    lea rsi, [rsp + 104]
    mov edx, 8
    mov eax, 1
    syscall
    cmp rax, -4
    je tm_call_unpark_retry
    cmp rax, -11
    je tm_call_copy
    cmp rax, 8
    jne tm_fatal
tm_call_copy:
    mov rdi, r14
    lea rsi, [r12 + 256]
    mov ecx, 80
    rep movsq
    mov eax, 640
    jmp tm_call_return
tm_call_invalid:
    mov eax, 0xffffffff
    tm_leave
tm_call_capacity:
    mov eax, 0xfffffffe
    tm_leave
tm_call_grow:
    mov rbx, [r12 + 32]
    mov rbp, rbx
    add rbp, rbx
    jc tm_fatal
    mov rdi, rbp
    call tm_allocate
    test rax, rax
    jz tm_fatal
    mov r15, rax
    mov rdi, rax
    mov rsi, [r12 + 16]
    mov rcx, rbx
    rep movsb
    mov rdi, [r12 + 16]
    mov rsi, rbx
    mov [r12 + 16], r15
    mov [r12 + 32], rbp
    call tm_unmap
    jmp tm_call_again
tm_invoke:
    .byte 0xe8
timer_policy_call_displacement:
    .long 0
    ret

# new_relative(context, duration_seconds, nanoseconds, output640, capacity).
# HIA selects checked_add versus far_future; only the overflow path reads the
# second real Instant used by Tokio Instant::far_future(). No clock is simulated.
timer_sleep_new_relative:
    tm_enter
    mov r12, rdi
    mov r13, rsi
    mov r14, rdx
    mov r15, rcx
    cmp r8, 640
    jb tm_sleep_capacity
    test r15, r15
    jz tm_sleep_invalid
    call tm_validate
    call tm_clock
    mov eax, 1
    xor edx, edx
    mov rdi, rsp
    call tm_frame
    mov [rsp + 32], r13
    mov [rsp + 40], r14
    mov rax, [r12 + 912]
    mov [rsp + 48], rax
    mov rax, [r12 + 920]
    mov [rsp + 56], rax
tm_sleep_relative_call:
    mov rdi, r12
    mov rsi, rsp
    mov edx, 96
    lea rcx, [r12 + 256]
    mov r8d, 640
    call timer_owner_call
    cmp rax, 640
    jne tm_sleep_return
    cmp qword ptr [r12 + 264], 3
    jne tm_sleep_relative_publish
    cmp qword ptr [rsp + 80], 0
    jne tm_fatal
    call tm_clock
    mov rax, [r12 + 912]
    mov [rsp + 64], rax
    mov rax, [r12 + 920]
    mov [rsp + 72], rax
    mov qword ptr [rsp + 80], 1
    jmp tm_sleep_relative_call
tm_sleep_relative_publish:
    mov rdi, r15
    lea rsi, [r12 + 256]
    mov ecx, 80
    rep movsq
    mov eax, 640
tm_sleep_return:
    tm_leave
tm_sleep_capacity:
    mov eax, 0xfffffffe
    tm_leave
tm_sleep_invalid:
    mov eax, 0xffffffff
    tm_leave

# Driver shutdown fires pending timers using the original process_at_time(MAX)
# path. Sleep handles and their final registered Wakers remain owned until Drop.
timer_owner_shutdown:
    tm_enter
    mov r12, rdi
    call tm_validate
    mov eax, 11
    xor edx, edx
    mov rdi, rsp
    call tm_frame
tm_shutdown_call:
    mov rdi, r12
    mov rsi, rsp
    mov edx, 96
    lea rcx, [r12 + 256]
    mov r8d, 640
    call timer_owner_call
    cmp rax, 640
    jne tm_fatal
    cmp qword ptr [r12 + 264], 0
    jne tm_fatal
    cmp qword ptr [r12 + 360], 0
    je tm_shutdown_done
    mov eax, 9
    xor edx, edx
    mov rdi, rsp
    call tm_frame
    jmp tm_shutdown_call
tm_shutdown_done:
    xor eax, eax
    tm_leave

# destroy requires no live Sleep, no borrowed callback, and no in-flight call.
# It never retires a borrowed scheduler notification descriptor.
timer_owner_destroy:
    tm_enter
    mov r12, rdi
    call tm_validate
    cmp qword ptr [r12 + 40], 0
    jne tm_destroy_invalid
    mov rbx, [r12 + 16]
    cmp qword ptr [rbx + 40], 0
    jne tm_destroy_invalid
    mov eax, 13
    xor edx, edx
    mov rdi, rsp
    call tm_frame
    mov rdi, r12
    mov rsi, rsp
    mov edx, 96
    lea rcx, [r12 + 256]
    mov r8d, 640
    call timer_owner_call
    cmp rax, 640
    jne tm_fatal
    mov rdi, [r12 + 48]
    mov qword ptr [r12 + 48], -1
    mov eax, 3
    syscall
    cmp qword ptr [r12 + 96], 0
    je tm_destroy_unmap
    mov rdi, [r12 + 56]
    mov qword ptr [r12 + 56], -1
    mov eax, 3
    syscall
tm_destroy_unmap:
    mov qword ptr [r12], 0
    mov rdi, [r12 + 16]
    mov rsi, [r12 + 32]
    mov qword ptr [r12 + 16], 0
    call tm_unmap
    mov rdi, r12
    mov esi, 4096
    call tm_unmap
    xor eax, eax
    tm_leave
tm_destroy_invalid:
    mov eax, 0xffffffff
    tm_leave

# Real CLOCK_MONOTONIC observations. This layer never advances or replaces time.
tm_clock:
    mov edi, 1
    lea rsi, [r12 + 912]
    mov eax, 228
    syscall
    test rax, rax
    jnz tm_fatal
    cmp qword ptr [r12 + 920], 1000000000
    jae tm_fatal
    ret

# prepare(context, limit_present, seconds, nanoseconds) -> poll timeout 0/-1.
# Caller may append the owned timerfd to its existing physical I/O wait set.
# The private HIA park decision alone determines the duration and zero timeout.
timer_owner_prepare:
    tm_enter
    mov r12, rdi
    mov r13, rsi
    mov r14, rdx
    mov r15, rcx
    call tm_validate
    call tm_clock
    mov eax, 10
    xor edx, edx
    mov rdi, rsp
    call tm_frame
    mov rax, [r12 + 912]
    mov [rsp + 32], rax
    mov rax, [r12 + 920]
    mov [rsp + 40], rax
    mov [rsp + 48], r13
    mov [rsp + 56], r14
    mov [rsp + 64], r15
    mov rdi, r12
    mov rsi, rsp
    mov edx, 96
    lea rcx, [r12 + 256]
    mov r8d, 640
    call timer_owner_call
    cmp rax, 640
    jne tm_fatal
    mov rax, [r12 + 264]
    cmp rax, 1
    ja tm_fatal
    mov qword ptr [r12 + 928], 0
    mov qword ptr [r12 + 936], 0
    mov qword ptr [r12 + 944], 0
    mov qword ptr [r12 + 952], 0
    mov r13, -1
    test rax, rax
    jnz tm_prepare_arm
    mov rax, [r12 + 320]
    mov rdx, [r12 + 328]
    mov [r12 + 944], rax
    mov [r12 + 952], rdx
    or rax, rdx
    jnz tm_prepare_arm
    xor r13d, r13d
tm_prepare_arm:
    mov rdi, [r12 + 48]
    xor esi, esi
    lea rdx, [r12 + 928]
    xor r10d, r10d
    mov eax, 286
    syscall
    test rax, rax
    jnz tm_fatal
    mov [r12 + 144], r13
    mov rax, r13
    tm_leave

# Drain only the timerfd. The shared scheduler eventfd remains caller-owned.
timer_owner_after_park:
    tm_enter
    mov r12, rdi
    call tm_validate
tm_after_drain_timer:
    mov rdi, [r12 + 48]
    lea rsi, [r12 + 960]
    mov edx, 8
    xor eax, eax
    syscall
    cmp rax, -4
    je tm_after_drain_timer
    cmp rax, -11
    je tm_after_clock
    cmp rax, 8
    jne tm_fatal
tm_after_clock:
    call tm_clock
    mov eax, 8
    xor edx, edx
    mov rdi, rsp
    call tm_frame
    mov rax, [r12 + 912]
    mov [rsp + 32], rax
    mov rax, [r12 + 920]
    mov [rsp + 40], rax
tm_after_process:
    mov rdi, r12
    mov rsi, rsp
    mov edx, 96
    lea rcx, [r12 + 256]
    mov r8d, 640
    call timer_owner_call
    cmp rax, 640
    jne tm_fatal
    cmp qword ptr [r12 + 264], 0
    jne tm_fatal
    cmp qword ptr [r12 + 360], 0
    je tm_after_done
    mov eax, 9
    xor edx, edx
    mov rdi, rsp
    call tm_frame
    jmp tm_after_process
tm_after_done:
    xor eax, eax
    tm_leave

# Owned standalone wait helper. Shared scheduler integration uses prepare and
# after_park around its single existing I/O polling operation instead.
timer_owner_park_once:
    tm_enter
    mov r12, rdi
    call timer_owner_prepare
    mov r13, rax
    mov rax, [r12 + 48]
    mov [rsp], eax
    mov dword ptr [rsp + 4], 1
    mov rax, [r12 + 56]
    mov [rsp + 8], eax
    mov dword ptr [rsp + 12], 1
tm_park_poll:
    mov rdi, rsp
    mov esi, 2
    mov rdx, r13
    mov eax, 7
    syscall
    cmp rax, -4
    je tm_park_poll
    test rax, rax
    js tm_fatal
    movzx eax, word ptr [rsp + 6]
    movzx edx, word ptr [rsp + 14]
    or eax, edx
    test eax, 0x38
    jnz tm_fatal
    cmp qword ptr [r12 + 96], 0
    je tm_park_after
tm_park_drain_owned_wake:
    mov rdi, [r12 + 56]
    lea rsi, [r12 + 960]
    mov edx, 8
    xor eax, eax
    syscall
    cmp rax, -4
    je tm_park_drain_owned_wake
    cmp rax, -11
    je tm_park_after
    cmp rax, 8
    jne tm_fatal
tm_park_after:
    mov rdi, r12
    call timer_owner_after_park
    tm_leave

timer_owner_notification_fd:
    push r12
    mov r12, rdi
    call tm_validate
    mov rax, [r12 + 48]
    pop r12
    ret

# One timer owner inside one real physical scheduler context. The core marker
# records actual driver ownership, not whether a task happens to be polling.
.equ STM_TIMER, 608
.equ STM_CORE, 616
.equ STM_DRIVER, 624
.equ STM_CLONES, 1408
.equ STM_WAKES, 664
.equ STM_DROPS, 648
.equ STM_REQUEST, 672
.equ STM_REPLY, 768
.macro stm_request operation
    lea rdi, [r12 + STM_REQUEST]
    xor eax, eax
    mov ecx, 12
    rep stosq
    movabs rax, TM_REQUEST
    mov [r12 + STM_REQUEST], rax
    mov qword ptr [r12 + STM_REQUEST + 8], \operation
    mov rax, [r12 + 8]
    mov [r12 + STM_REQUEST + 16], rax
.endm

scheduler_timer_install:
    tm_enter
    mov r12, rdi
    call scs_validate
    mov rax, [r12 + STM_TIMER]
    or rax, [r12 + STM_CORE]
    or rax, [r12 + STM_DRIVER]
    jnz cdf_fatal
    mov rdi, [r12 + 8]
    mov rsi, r12
    mov rdx, [r12 + 104]
    call timer_owner_create
    test rax, rax
    jz cdf_fatal
    mov [r12 + STM_TIMER], rax
    xor eax, eax
    tm_leave

stm_validate:
    sub rsp, 8
    mov rdi, r12
    call scs_validate
    cmp qword ptr [r12 + STM_TIMER], 0
    je cdf_fatal
    add rsp, 8
    ret

stm_call:
    sub rsp, 8
    mov rdi, [r12 + STM_TIMER]
    lea rsi, [r12 + STM_REQUEST]
    mov edx, 96
    lea rcx, [r12 + STM_REPLY]
    mov r8d, 640
    call timer_owner_call
    cmp rax, 640
    jne cdf_fatal
    mov rax, [r12 + STM_REPLY + 8]
    cmp rax, 2
    ja cdf_fatal
    add rsp, 8
    ret

# create relative(SC, duration seconds, nanoseconds) -> owned Sleep token.
scheduler_sleep_relative:
    tm_enter
    mov r12, rdi
    mov r13, rsi
    mov r14, rdx
    call stm_validate
    mov rdi, [r12 + STM_TIMER]
    mov rsi, r13
    mov rdx, r14
    lea rcx, [r12 + STM_REPLY]
    mov r8d, 640
    call timer_sleep_new_relative
    cmp rax, 640
    jne cdf_fatal
    cmp qword ptr [r12 + STM_REPLY + 8], 0
    jne cdf_fatal
    mov rax, [r12 + STM_REPLY + 24]
    tm_leave

# create until(SC, actual absolute CLOCK_MONOTONIC seconds, nanoseconds).
scheduler_sleep_until:
    tm_enter
    mov r12, rdi
    mov r13, rsi
    mov r14, rdx
    call stm_validate
    stm_request 2
    mov [r12 + STM_REQUEST + 32], r13
    mov [r12 + STM_REQUEST + 40], r14
    call stm_call
    test rax, rax
    jnz cdf_fatal
    mov rax, [r12 + STM_REPLY + 24]
    tm_leave

scheduler_sleep_reset:
    tm_enter
    mov r12, rdi
    mov r13, rsi
    mov r14, rdx
    mov r15, rcx
    call stm_validate
    stm_request 3
    mov [r12 + STM_REQUEST + 24], r13
    mov [r12 + STM_REQUEST + 32], r14
    mov [r12 + STM_REQUEST + 40], r15
    call stm_call
    tm_leave

# poll(SC, Sleep token, exact current task Waker) -> Ready0/Pending1/panic2.
# Only the existing outer task/LIFO scope owns the 128-operation Budget. A
# budget Pending does not initialize or poll the Sleep and defers its task.
scheduler_sleep_poll:
    tm_enter
    mov r12, rdi
    mov r13, rsi
    mov r14, rdx
    call stm_validate
    cmp [r12 + 96], r14
    jne cdf_fatal
    test r14, r14
    jz cdf_fatal
    mov rdi, r12
    mov rsi, r14
    call cooperative_scheduler_proceed
    test rax, rax
    jz stm_poll_budget_pending
    mov r15, rax
    stm_request 4
    mov [r12 + STM_REQUEST + 24], r13
    mov [r12 + STM_REQUEST + 32], r14
    call stm_call
    mov rbx, rax
    mov rdi, r12
    mov rsi, r15
    test rbx, rbx
    jnz stm_poll_restore
    call cooperative_scheduler_progress
    jmp stm_poll_return
stm_poll_restore:
    call cooperative_scheduler_restore
stm_poll_return:
    mov rax, rbx
    tm_leave
stm_poll_budget_pending:
    mov eax, 1
    tm_leave

scheduler_sleep_drop:
    tm_enter
    mov r12, rdi
    mov r13, rsi
    call stm_validate
    stm_request 7
    mov [r12 + STM_REQUEST + 24], r13
    call stm_call
    test rax, rax
    jnz cdf_fatal
    tm_leave

scheduler_timer_uninstall:
    tm_enter
    mov r12, rdi
    call stm_validate
    mov rax, [r12 + STM_CORE]
    or rax, [r12 + STM_DRIVER]
    or rax, [r12 + 64]
    or rax, [r12 + 96]
    jnz cdf_fatal
    mov rdi, [r12 + STM_TIMER]
    call timer_owner_destroy
    test rax, rax
    jnz stm_uninstall_return
    mov qword ptr [r12 + STM_TIMER], 0
stm_uninstall_return:
    tm_leave

# RawWaker custody is exactly the existing scheduler cell owner. The timer
# consumes a clone on wake, while reset/drop releases the same retained clone.
timer_waker_clone:
    tm_enter
    mov r12, rdi
    mov r13, rsi
    mov rdi, r13
    call scs_cell_validate
    cmp [r13 + 8], r12
    jne cdf_fatal
    mov rdi, r13
    call cooperative_scheduler_retain
    add qword ptr [r12 + STM_CLONES], 1
    jc cdf_fatal
    xor eax, eax
    tm_leave

timer_waker_wake:
    tm_enter
    mov r12, rdi
    mov r13, rsi
    mov rdi, r13
    call scs_cell_validate
    cmp [r13 + 8], r12
    jne cdf_fatal
    mov rax, [r12 + STM_CORE]
    cmp rax, 1
    ja cdf_fatal
    or rax, [r12 + 96]
    xor edx, edx
    test rax, rax
    setne dl
    mov rdi, r13
    xor esi, esi
    call cooperative_scheduler_notify
    add qword ptr [r12 + STM_WAKES], 1
    jc cdf_fatal
    mov rdi, r13
    call cooperative_scheduler_release
    xor eax, eax
    tm_leave

timer_waker_drop:
    tm_enter
    mov r12, rdi
    mov r13, rsi
    mov rdi, r13
    call scs_cell_validate
    cmp [r13 + 8], r12
    jne cdf_fatal
    add qword ptr [r12 + STM_DROPS], 1
    jc cdf_fatal
    mov rdi, r13
    call cooperative_scheduler_release
    xor eax, eax
    tm_leave

# The actual physical driver enters with the same worker core still owned.
# I/O readiness is delivered first by the caller; timer wakes follow, then Defer.
# No task is selected and no cooperative Budget scope is reset by these calls.
scheduler_timer_prepare:
    tm_enter
    mov r12, rdi
    mov r13, rsi
    mov r14, rdx
    mov r15, rcx
    call stm_validate
    mov rax, [r12 + STM_CORE]
    or rax, [r12 + STM_DRIVER]
    or rax, [r12 + 64]
    or rax, [r12 + 96]
    jnz cdf_fatal
    mov qword ptr [r12 + STM_CORE], 1
    mov qword ptr [r12 + STM_DRIVER], 1
    scs_defer_request 2
    call scs_defer
    cmp qword ptr [r12 + 528], 1
    je stm_prepare_limit
    cmp qword ptr [r12 + 528], 0
    jne cdf_fatal
    mov r13d, 1
    xor r14d, r14d
    xor r15d, r15d
stm_prepare_limit:
    mov rdi, [r12 + STM_TIMER]
    mov rsi, r13
    mov rdx, r14
    mov rcx, r15
    call timer_owner_prepare
    tm_leave

scheduler_timer_notification_fd:
    tm_enter
    mov r12, rdi
    call stm_validate
    mov rdi, [r12 + STM_TIMER]
    call timer_owner_notification_fd
    tm_leave

scheduler_timer_after_io:
    tm_enter
    mov r12, rdi
    call stm_validate
    cmp qword ptr [r12 + STM_CORE], 1
    jne cdf_fatal
    cmp qword ptr [r12 + STM_DRIVER], 1
    jne cdf_fatal
    mov rax, [r12 + 64]
    or rax, [r12 + 96]
    jnz cdf_fatal
    mov rdi, [r12 + STM_TIMER]
    call timer_owner_after_park
    test rax, rax
    jnz cdf_fatal
    mov rdi, r12
    call cooperative_scheduler_after_park
    test rax, rax
    jnz cdf_fatal
    mov qword ptr [r12 + STM_DRIVER], 0
    mov qword ptr [r12 + STM_CORE], 0
    xor eax, eax
    tm_leave

# Timer-only callable: one real poll waits on timerfd plus the scheduler wakefd.
# A production I/O dispatcher uses prepare/notification_fd/after_io around its
# same physical poll, so no second event loop or blocking pool is introduced.
scheduler_timer_park_once:
    tm_enter
    mov r12, rdi
    call scheduler_timer_prepare
    mov r13, rax
    mov rax, [r12 + STM_TIMER]
    mov rax, [rax + 48]
    mov [rsp], eax
    mov dword ptr [rsp + 4], 1
    mov rax, [r12 + 104]
    mov [rsp + 8], eax
    mov dword ptr [rsp + 12], 1
stm_driver_poll:
    add qword ptr [r12 + 656], 1
    jc cdf_fatal
    mov rdi, rsp
    mov esi, 2
    mov rdx, r13
    mov eax, 7
    syscall
    cmp rax, -4
    je stm_driver_poll
    test rax, rax
    js cdf_fatal
    movzx eax, word ptr [rsp + 6]
    movzx edx, word ptr [rsp + 14]
    or eax, edx
    test eax, 0x38
    jnz cdf_fatal
stm_driver_wake_drain:
    mov rdi, [r12 + 104]
    lea rsi, [rsp + 16]
    mov edx, 8
    xor eax, eax
    syscall
    cmp rax, -4
    je stm_driver_wake_drain
    cmp rax, -11
    je stm_driver_after_io
    cmp rax, 8
    jne cdf_fatal
stm_driver_after_io:
    mov rdi, r12
    call scheduler_timer_after_io
    tm_leave

# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
# Fixed ABI, mapped storage and scheduler RawWaker custody only.
.equ CTC_MAGIC, 0x3130304354435248
.equ CTC_REQUEST, 0x3130305154435248
.equ CTC_RESPONSE, 0x3130305254435248

# create(shared scheduler, positive generation) -> owned context or zero.
cancellation_token_create:
    cbg_enter
    mov r12, rdi
    mov r13, rdi
    mov r14, rsi
    test r14, r14
    jz ctc_create_failed
    call scs_validate
    mov edi, 4096
    call cdf_allocate
    test rax, rax
    jz ctc_create_failed
    mov r12, rax
    mov [r12 + 8], r14
    mov [r12 + 32], r13
    mov eax, 186
    syscall
    mov [r12 + 40], rax
    mov edi, 8192
    call cdf_allocate
    test rax, rax
    jz ctc_create_free_context
    mov [r12 + 16], rax
    mov qword ptr [r12 + 24], 8192
    mov edi, 4096
    call cdf_allocate
    test rax, rax
    jz ctc_create_free_workspace
    mov [r12 + 96], rax
    mov qword ptr [r12 + 104], 4096
    movabs rax, CTC_MAGIC
    mov [r12], rax
    movabs rax, CTC_REQUEST
    mov [r12 + 128], rax
    mov rax, [r12 + 8]
    mov [r12 + 144], rax
    mov rdi, r12
    lea rsi, [r12 + 128]
    mov edx, 80
    lea rcx, [r12 + 256]
    mov r8d, 128
    call cancellation_token_call
    cmp rax, 128
    jne cdf_fatal
    mov rax, r12
    cbg_leave
ctc_create_free_workspace:
    mov rdi, [r12 + 16]
    mov rsi, [r12 + 24]
    call cdf_unmap
ctc_create_free_context:
    mov rdi, r12
    mov esi, 4096
    call cdf_unmap
ctc_create_failed:
    xor eax, eax
    cbg_leave

# call(context, borrowed input80, length, output128, capacity) -> 128/error.
# HIA returns all concrete Waker effects. The adapter only binds them to the
# actual scheduler cell retain/notify/release primitives and observer ABI.
cancellation_token_call:
    cbg_enter
    mov r12, rdi
    mov r13, rsi
    mov r14, rcx
    cmp rdx, 80
    jne ctc_invalid
    cmp r8, 128
    jb ctc_capacity
    test r12, r12
    jz ctc_invalid
    test r13, r13
    jz ctc_invalid
    test r14, r14
    jz ctc_invalid
    movabs rax, CTC_MAGIC
    cmp [r12], rax
    jne ctc_invalid
    mov eax, 186
    syscall
    cmp [r12 + 40], rax
    jne ctc_invalid
    cmp qword ptr [r12 + 48], 0
    jne ctc_invalid
    mov rax, [r13 + 16]
    cmp [r12 + 8], rax
    jne ctc_invalid
    lea rdi, [r12 + 128]
    mov rsi, r13
    mov ecx, 10
    cld
    rep movsq
    mov qword ptr [r12 + 48], 1
ctc_call_again:
    lea rdi, [r12 + 128]
    mov esi, 80
    mov rdx, [r12 + 96]
    mov rcx, [r12 + 104]
    mov r8, [r12 + 16]
    mov r9, [r12 + 24]
    call ctc_invoke
    add qword ptr [r12 + 56], 1
    jc cdf_fatal
    mov edx, eax
    cmp rax, rdx
    jne cdf_fatal
    cmp eax, 0xfffffffd
    je ctc_grow_workspace
    cmp eax, 0xfffffffe
    je ctc_grow_output
    cmp eax, 0xffffffff
    je ctc_call_return
    cmp rax, 128
    jb cdf_fatal
    cmp rax, [r12 + 104]
    ja cdf_fatal
    mov [r12 + 120], rax
    mov r15, [r12 + 96]
    movabs rdx, CTC_RESPONSE
    cmp [r15], rdx
    jne cdf_fatal
    mov rdx, [r12 + 8]
    cmp [r15 + 16], rdx
    jne cdf_fatal
    mov rdx, [r12 + 136]
    cmp [r15 + 24], rdx
    jne cdf_fatal
    mov rdx, [r15 + 104]
    cmp rdx, 524280
    ja cdf_fatal
    shl rdx, 4
    add rdx, 128
    cmp rax, rdx
    jne cdf_fatal
    xor ebx, ebx
ctc_effect_loop:
    cmp rbx, [r15 + 104]
    jae ctc_copy_result
    mov rbp, rbx
    shl rbp, 4
    mov r13, [r15 + rbp + 136]
    mov rdi, r13
    call scs_cell_validate
    mov rax, [r12 + 32]
    cmp [r13 + 8], rax
    jne cdf_fatal
    mov rax, [r15 + rbp + 128]
    cmp rax, 1
    je ctc_clone
    cmp rax, 2
    je ctc_drop
    cmp rax, 4
    jne cdf_fatal
    mov rax, [r12 + 32]
    mov rdx, [rax + 96]
    or rdx, [rax + 616]
    setnz dl
    movzx edx, dl
    mov rdi, r13
    xor esi, esi
    call cooperative_scheduler_notify
    test rax, rax
    jnz cdf_fatal
    mov rdi, r13
    call cooperative_scheduler_release
    test rax, rax
    jnz cdf_fatal
    add qword ptr [r12 + 80], 1
    jc cdf_fatal
    jmp ctc_observe
ctc_clone:
    mov rdi, r13
    call cooperative_scheduler_retain
    cmp rax, r13
    jne cdf_fatal
    add qword ptr [r12 + 64], 1
    jc cdf_fatal
    jmp ctc_observe
ctc_drop:
    mov rdi, r13
    call cooperative_scheduler_release
    test rax, rax
    jnz cdf_fatal
    add qword ptr [r12 + 72], 1
    jc cdf_fatal
ctc_observe:
    mov rdi, [r12 + 32]
    mov rdi, [rdi + 632]
    mov rsi, [r15 + rbp + 128]
    mov rdx, r13
    call oneshot_observe
    inc rbx
    jmp ctc_effect_loop
ctc_copy_result:
    mov rdi, r14
    mov rsi, r15
    mov ecx, 16
    rep movsq
    mov eax, 128
ctc_call_return:
    mov qword ptr [r12 + 48], 0
    cbg_leave
ctc_invalid:
    mov eax, 0xffffffff
    cbg_leave
ctc_capacity:
    mov eax, 0xfffffffe
    cbg_leave
ctc_grow_workspace:
    mov rbx, [r12 + 24]
    cmp rbx, 33554432
    jae ctc_call_return
    lea rdi, [rbx + rbx]
    call cdf_allocate
    test rax, rax
    jz cdf_fatal
    mov rbp, rax
    mov rdi, rax
    mov rsi, [r12 + 16]
    mov rcx, rbx
    rep movsb
    mov rdi, [r12 + 16]
    mov rsi, rbx
    mov [r12 + 16], rbp
    shl rbx, 1
    mov [r12 + 24], rbx
    call cdf_unmap
    add qword ptr [r12 + 88], 1
    jc cdf_fatal
    jmp ctc_call_again
ctc_grow_output:
    mov rbx, [r12 + 104]
    cmp rbx, 8388608
    jae ctc_call_return
    lea rdi, [rbx + rbx]
    call cdf_allocate
    test rax, rax
    jz cdf_fatal
    mov rbp, rax
    mov rdi, [r12 + 96]
    mov rsi, rbx
    mov [r12 + 96], rbp
    shl rbx, 1
    mov [r12 + 104], rbx
    call cdf_unmap
    add qword ptr [r12 + 112], 1
    jc cdf_fatal
    jmp ctc_call_again
ctc_invoke:
    .byte 0xe8
cancellation_policy_call_displacement:
    .long 0
    ret

# Destroy only after HIA verifies that every token, waiter and guard is gone.
cancellation_token_destroy:
    cbg_enter
    mov r12, rdi
    test r12, r12
    jz ctc_invalid
    movabs rax, CTC_MAGIC
    cmp [r12], rax
    jne ctc_invalid
    mov eax, 186
    syscall
    cmp [r12 + 40], rax
    jne ctc_invalid
    cmp qword ptr [r12 + 48], 0
    jne ctc_invalid
    lea rdi, [r12 + 128]
    xor eax, eax
    mov ecx, 10
    rep stosq
    movabs rax, CTC_REQUEST
    mov [r12 + 128], rax
    mov qword ptr [r12 + 136], 16
    mov rax, [r12 + 8]
    mov [r12 + 144], rax
    mov rdi, r12
    lea rsi, [r12 + 128]
    mov edx, 80
    lea rcx, [r12 + 256]
    mov r8d, 128
    call cancellation_token_call
    cmp rax, 128
    jne ctc_destroy_return
    mov rdi, [r12 + 96]
    mov rsi, [r12 + 104]
    call cdf_unmap
    mov rdi, [r12 + 16]
    mov rsi, [r12 + 24]
    call cdf_unmap
    mov rdi, r12
    mov esi, 4096
    call cdf_unmap
    xor eax, eax
ctc_destroy_return:
    cbg_leave

# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
# Fixed private arenas and real ValueLease custody. Typed choices and wire are HIA.
.equ SM_ACTION, 0x313030414d535348
.equ SM_TYPED_ACTION, 0x3130304356535348
.equ SM_PARSE_REPLY, 0x3130525056535348
.equ SM_DROP_REQUEST, 0x313030444d535348

# server_message_call(frame, bytes, output, capacity, optional counts48)
server_message_call:
    cbg_enter
    mov [rsp], rdi
    mov [rsp + 8], rsi
    mov [rsp + 16], rdx
    mov [rsp + 24], rcx
    mov [rsp + 32], r8
    test rdi, rdi
    jz sm_invalid_early
    test rdx, rdx
    jz sm_invalid_early
    cmp rsi, 16777216
    ja sm_invalid_early
    cmp rcx, 67108864
    ja sm_invalid_early
    mov rax, rdi
    add rax, rsi
    jc sm_invalid_early
    mov rax, rdx
    add rax, rcx
    jc sm_invalid_early
    mov edi, 4096
    call cdf_allocate
    test rax, rax
    jz cdf_fatal
    mov r12, rax
    mov rdi, r12
    mov rsi, rsp
    mov ecx, 5
    cld
    rep movsq
    mov edi, 268435456
    call cdf_allocate
    test rax, rax
    jz cdf_fatal
    mov r13, rax
sm_again:
    mov rdi, [r12]
    mov rsi, [r12 + 8]
    mov rdx, [r12 + 16]
    mov rcx, [r12 + 24]
    mov r8, r13
    mov r9d, 268435456
    call sm_owner_policy_invoke
    add qword ptr [r12 + 40], 1
    jc cdf_fatal
    mov edx, eax
    cmp rax, rdx
    jne cdf_fatal
    cmp eax, 0xfffffff0
    je sm_effect
    cmp eax, 0xffffffff
    je sm_return
    cmp eax, 0xfffffffe
    je sm_return
    cmp rax, [r12 + 24]
    ja cdf_fatal
sm_return:
    mov [r12 + 104], rax
    mov rdi, [r12 + 32]
    test rdi, rdi
    jz sm_no_counts
    lea rsi, [r12 + 40]
    mov ecx, 6
    rep movsq
sm_no_counts:
    mov rdi, [r12 + 96]
    test rdi, rdi
    jz sm_no_child_arena
    mov esi, 268435456
    call cdf_unmap
sm_no_child_arena:
    mov rdi, r13
    mov esi, 268435456
    call cdf_unmap
    mov rax, [r12 + 104]
    mov [rsp + 40], rax
    mov rdi, r12
    mov esi, 4096
    call cdf_unmap
    mov rax, [rsp + 40]
    cbg_leave
sm_invalid_early:
    mov eax, 0xffffffff
    cbg_leave

sm_effect:
    lea rbx, [r13 + 512]
    movabs rax, SM_ACTION
    cmp [rbx], rax
    jne cdf_fatal
    mov r15, [rbx + 8]
    cmp r15, 1
    jb cdf_fatal
    cmp r15, 3
    ja cdf_fatal
    cmp r15, [rbx + 16]
    jne cdf_fatal
    cmp r15, [r12 + 88]
    jbe cdf_fatal
    cmp qword ptr [r12 + 88], 0
    jne sm_not_first
    cmp r15, 1
    jne cdf_fatal
sm_not_first:
    mov [r12 + 88], r15
    mov rax, [rbx + 24]
    cmp rax, 268435456
    ja cdf_fatal
    mov rcx, [rbx + 32]
    add rcx, rax
    jc cdf_fatal
    cmp rcx, 268435456
    ja cdf_fatal
    mov rax, [rbx + 40]
    cmp rax, 268435456
    ja cdf_fatal
    mov rcx, [rbx + 48]
    add rcx, rax
    jc cdf_fatal
    cmp rcx, 268435456
    ja cdf_fatal
    mov rax, [rbx + 80]
    or rax, [rbx + 88]
    or rax, [rbx + 96]
    or rax, [rbx + 104]
    or rax, [rbx + 112]
    or rax, [rbx + 120]
    jnz cdf_fatal
    lea rdi, [r12 + 128]
    mov rsi, rbx
    mov ecx, 16
    rep movsq
    cmp r15, 3
    je sm_create
    cmp qword ptr [rbx + 24], 17825792
    jne cdf_fatal
    cmp qword ptr [rbx + 32], 40
    jb cdf_fatal
    cmp qword ptr [rbx + 32], 8388648
    ja cdf_fatal
    cmp qword ptr [rbx + 56], 268435456
    jne cdf_fatal
    mov rax, [rbx + 64]
    or rax, [rbx + 72]
    jnz cdf_fatal
    mov eax, 27262976
    mov ecx, 67108864
    cmp r15, 1
    je sm_reply_span
    mov eax, 94371840
    mov ecx, 16777216
sm_reply_span:
    cmp [rbx + 40], rax
    jne cdf_fatal
    cmp [rbx + 48], rcx
    jne cdf_fatal
    mov r14, [r12 + 96]
    test r14, r14
    jnz sm_child_ready
    mov edi, 268435456
    call cdf_allocate
    test rax, rax
    jz cdf_fatal
    mov r14, rax
    mov [r12 + 96], rax
sm_child_ready:
    mov rax, [rbx + 24]
    add rax, r13
    mov [r12 + 256], rax
    mov rax, [rbx + 32]
    mov [r12 + 264], rax
    mov rax, [rbx + 40]
    add rax, r13
    mov [r12 + 272], rax
    mov rax, [rbx + 48]
    mov [r12 + 280], rax
    call sm_typed_drive
    mov edx, eax
    cmp rax, rdx
    jne cdf_fatal
    mov [rsp + 48], rax
    xor edx, edx
    cmp eax, 0xffffffff
    je sm_receipt
    cmp eax, 0xfffffffe
    je sm_receipt
    cmp rax, [rbx + 48]
    ja cdf_fatal
    mov rdx, rax
    jmp sm_receipt

sm_create:
    cmp qword ptr [rbx + 24], 111149056
    jne cdf_fatal
    cmp qword ptr [rbx + 32], 162
    jb cdf_fatal
    cmp qword ptr [rbx + 32], 67108896
    ja cdf_fatal
    cmp qword ptr [rbx + 40], 1024
    jne cdf_fatal
    cmp qword ptr [rbx + 48], 16
    jne cdf_fatal
    cmp qword ptr [rbx + 56], 0
    jne cdf_fatal
    cmp qword ptr [rbx + 64], 0
    je cdf_fatal
    mov rdi, [rbx + 72]
    call scs_validate
    lea rdi, [r13 + 111149056]
    mov rsi, [rbx + 32]
    mov rdx, [rbx + 64]
    lea rcx, [rip + server_message_drop_entry]
    mov r8, [rbx + 72]
    call value_lease_create
    test rax, rax
    jz cdf_fatal
    mov [r13 + 1024], rax
    mov rax, [rbx + 64]
    mov [r13 + 1032], rax
    add qword ptr [r12 + 72], 1
    jc cdf_fatal
    mov qword ptr [rsp + 48], 0
    mov edx, 16
sm_receipt:
    mov [rsp + 56], rdx
    lea rdi, [r12 + 128]
    mov rsi, rbx
    mov ecx, 16
    repe cmpsq
    jne cdf_fatal
    mov qword ptr [rbx + 80], 1
    mov rax, [rsp + 48]
    mov [rbx + 88], rax
    mov rax, [rsp + 56]
    mov [rbx + 96], rax
    jmp sm_again

# Same query and private child W through controller -> parser -> controller
# -> emitter -> controller. No JSON parsing is performed by the broker.
sm_typed_arguments:
    mov rdi, [r12 + 256]
    mov rsi, [r12 + 264]
    mov rdx, [r12 + 272]
    mov rcx, [r12 + 280]
    mov r8, r14
    mov r9d, 268435456
    ret
sm_typed_drive:
    sub rsp, 8
    call sm_typed_arguments
    call sm_typed_controller_invoke
    add qword ptr [r12 + 48], 1
    jc cdf_fatal
    cmp eax, 64
    jne cdf_fatal
    cmp rax, 64
    jne cdf_fatal
    mov qword ptr [r12 + 400], 1
    call sm_typed_action_check
    mov rdi, [r12 + 256]
    mov rsi, [r12 + 264]
    lea rdx, [r12 + 512]
    mov ecx, 32
    mov r8, r14
    mov r9d, 268435456
    call sm_typed_parser_invoke
    add qword ptr [r12 + 56], 1
    jc cdf_fatal
    cmp rax, 32
    jne cdf_fatal
    movabs rax, SM_PARSE_REPLY
    cmp [r12 + 512], rax
    jne cdf_fatal
    lea rdi, [r12 + 320]
    mov rsi, [r12 + 272]
    mov ecx, 8
    repe cmpsq
    jne cdf_fatal
    call sm_typed_arguments
    call sm_typed_controller_invoke
    add qword ptr [r12 + 48], 1
    jc cdf_fatal
    mov edx, eax
    cmp rax, rdx
    jne cdf_fatal
    cmp eax, 0xffffffff
    je sm_typed_done
    cmp eax, 0xfffffffe
    je sm_typed_done
    cmp rax, 64
    jne cdf_fatal
    mov qword ptr [r12 + 400], 2
    call sm_typed_action_check
    call sm_typed_arguments
    call sm_typed_emitter_invoke
    add qword ptr [r12 + 64], 1
    jc cdf_fatal
    mov edx, eax
    cmp rax, rdx
    jne cdf_fatal
    mov [r12 + 392], rax
    call sm_typed_arguments
    call sm_typed_controller_invoke
    add qword ptr [r12 + 48], 1
    jc cdf_fatal
    cmp rax, [r12 + 392]
    jne cdf_fatal
sm_typed_done:
    add rsp, 8
    ret
sm_typed_action_check:
    mov rdx, [r12 + 272]
    movabs rax, SM_TYPED_ACTION
    cmp [rdx], rax
    jne cdf_fatal
    mov rax, [r12 + 400]
    cmp [rdx + 8], rax
    jne cdf_fatal
    cmp [rdx + 16], rax
    jne cdf_fatal
    cmp [rdx + 24], rax
    jne cdf_fatal
    mov rcx, [r12 + 264]
    cmp [rdx + 32], rcx
    jne cdf_fatal
    cmp qword ptr [rdx + 56], 0
    jne cdf_fatal
    cmp rax, 1
    jne sm_typed_emission_action
    cmp qword ptr [rdx + 40], 32
    jne cdf_fatal
    mov rax, [rdx + 48]
    mov [r12 + 384], rax
    jmp sm_typed_action_snapshot
sm_typed_emission_action:
    mov rax, [r12 + 280]
    cmp [rdx + 40], rax
    jne cdf_fatal
    mov rax, [r12 + 384]
    cmp [rdx + 48], rax
    jne cdf_fatal
sm_typed_action_snapshot:
    lea rdi, [r12 + 320]
    mov rsi, rdx
    mov ecx, 8
    rep movsq
    ret
sm_owner_policy_invoke:
    .byte 0xe8
server_message_owner_policy_call_displacement:
    .long 0
    ret
sm_typed_controller_invoke:
    .byte 0xe8
server_message_typed_policy_call_displacement:
    .long 0
    ret
sm_typed_parser_invoke:
    .byte 0xe8
server_message_schema_policy_call_displacement:
    .long 0
    ret
sm_typed_emitter_invoke:
    .byte 0xe8
server_message_emitter_policy_call_displacement:
    .long 0
    ret

# Real ValueLease callback. The complete payload remains immutable and mapped
# until this typed callback has returned to the existing ValueLease owner.
server_message_drop_entry:
    cbg_enter
    mov [rsp], rdi
    mov [rsp + 8], rsi
    mov [rsp + 16], rdx
    mov [rsp + 24], rcx
    mov [rsp + 32], r8
    mov rdi, r8
    call vl_validate
    mov rbx, [rsp + 32]
    mov rax, [rsp + 8]
    cmp [rbx + 16], rax
    jne cdf_fatal
    mov rax, [rsp + 16]
    cmp rax, 162
    jb cdf_fatal
    cmp rax, 67108896
    ja cdf_fatal
    cmp [rbx + 24], rax
    jne cdf_fatal
    mov rax, [rsp + 24]
    cmp [rbx + 8], rax
    jne cdf_fatal
    mov rdi, [rsp]
    cmp [rbx + 40], rdi
    jne cdf_fatal
    call scs_validate
    lea rax, [rip + server_message_drop_entry]
    cmp [rbx + 32], rax
    jne cdf_fatal
    mov edi, 4096
    call cdf_allocate
    test rax, rax
    jz cdf_fatal
    mov r12, rax
    mov rax, [rsp + 32]
    mov [r12], rax
    mov [r12 + 72], rax
    mov rax, [rsp]
    mov [r12 + 8], rax
    mov [r12 + 88], rax
    mov rax, [rsp + 24]
    mov [r12 + 16], rax
    mov [r12 + 80], rax
    mov qword ptr [r12 + 24], 12
    mov rax, [rsp + 16]
    mov [r12 + 96], rax
    mov qword ptr [r12 + 56], 96
    movabs rax, SM_DROP_REQUEST
    mov [r12 + 64], rax
    lea rdi, [r12 + 128]
    mov rsi, [rsp + 8]
    mov ecx, 4
    cld
    rep movsq
    mov esi, 1
    call td_observe
    lea rdi, [r12 + 64]
    mov esi, 96
    lea rdx, [r12 + 256]
    mov ecx, 80
    lea r8, [r12 + 1024]
    mov r9d, 2048
    call sm_drop_policy_invoke
    add qword ptr [r12 + 32], 1
    jc cdf_fatal
    cmp rax, 80
    jne cdf_fatal
    movabs rax, TD_RESPONSE
    cmp [r12 + 256], rax
    jne cdf_fatal
    cmp qword ptr [r12 + 264], 0
    jne cdf_fatal
    mov rax, [r12 + 16]
    cmp [r12 + 272], rax
    jne cdf_fatal
    mov rax, [r12]
    cmp [r12 + 280], rax
    jne cdf_fatal
    cmp qword ptr [r12 + 288], 12
    jne cdf_fatal
    mov rax, [r12 + 296]
    or rax, [r12 + 304]
    or rax, [r12 + 312]
    or rax, [r12 + 320]
    or rax, [r12 + 328]
    jnz cdf_fatal
    cmp qword ptr [r12 + 1056], 0
    jne cdf_fatal
    cmp qword ptr [r12 + 1080], 1
    jne cdf_fatal
    mov esi, 2
    call td_observe
    mov rdi, r12
    mov esi, 4096
    call cdf_unmap
    xor eax, eax
    cbg_leave
sm_drop_policy_invoke:
    .byte 0xe8
server_message_drop_policy_call_displacement:
    .long 0
    ret

# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
# Fixed storage, descriptor custody and HIA-requested actual child ValueLease Drop.
# Worker request field order and admission are decided by its HIA owner policy.
worker_send_request_drop_entry:
    cbg_enter
    mov [rsp], rdi
    mov [rsp + 8], rsi
    mov [rsp + 16], rdx
    mov [rsp + 24], rcx
    mov [rsp + 32], r8
    mov rdi, r8
    call vl_validate
    mov rbx, [rsp + 32]
    mov rax, [rsp + 8]
    cmp [rbx + 16], rax
    jne cdf_fatal
    cmp qword ptr [rsp + 16], 48
    jne cdf_fatal
    cmp qword ptr [rbx + 24], 48
    jne cdf_fatal
    mov rax, [rsp + 24]
    cmp [rbx + 8], rax
    jne cdf_fatal
    mov rdi, [rsp]
    cmp [rbx + 40], rdi
    jne cdf_fatal
    call scs_validate
    lea rax, [rip + worker_send_request_drop_entry]
    cmp [rbx + 32], rax
    jne cdf_fatal
    mov edi, 4096
    call cdf_allocate
    test rax, rax
    jz cdf_fatal
    mov r12, rax
    mov rax, [rsp + 32]
    mov [r12], rax
    mov [r12 + 72], rax
    mov rax, [rsp]
    mov [r12 + 8], rax
    mov [r12 + 88], rax
    mov rax, [rsp + 24]
    mov [r12 + 16], rax
    mov [r12 + 80], rax
    mov qword ptr [r12 + 24], 11
    mov qword ptr [r12 + 56], 112
    mov qword ptr [r12 + 96], 48
    movabs rax, TD_REQUEST
    mov [r12 + 64], rax
    lea rdi, [r12 + 128]
    mov rsi, [rsp + 8]
    mov ecx, 6
    cld
    rep movsq
    mov esi, 1
    call td_observe
wsd_again:
    lea rdi, [r12 + 64]
    mov esi, 112
    lea rdx, [r12 + 256]
    mov ecx, 80
    lea r8, [r12 + 1024]
    mov r9d, 2048
    call wsd_policy_invoke
    add qword ptr [r12 + 32], 1
    jc cdf_fatal
    mov edx, eax
    cmp rax, rdx
    jne cdf_fatal
    cmp eax, 0xfffffff0
    je wsd_effect
    cmp eax, 80
    jne cdf_fatal
    movabs rax, TD_RESPONSE
    cmp [r12 + 256], rax
    jne cdf_fatal
    cmp qword ptr [r12 + 264], 0
    jne cdf_fatal
    mov rax, [r12 + 16]
    cmp [r12 + 272], rax
    jne cdf_fatal
    mov rax, [r12]
    cmp [r12 + 280], rax
    jne cdf_fatal
    cmp qword ptr [r12 + 288], 11
    jne cdf_fatal
    cmp qword ptr [r12 + 296], 2
    jne cdf_fatal
    mov rax, [r12 + 304]
    or rax, [r12 + 312]
    or rax, [r12 + 320]
    or rax, [r12 + 328]
    jnz cdf_fatal
    cmp qword ptr [r12 + 32], 3
    jne cdf_fatal
    cmp qword ptr [r12 + 40], 2
    jne cdf_fatal
    cmp qword ptr [r12 + 1056], 0
    jne cdf_fatal
    cmp qword ptr [r12 + 1080], 1
    jne cdf_fatal
    mov esi, 2
    call td_observe
    mov rdi, r12
    mov esi, 4096
    call cdf_unmap
    xor eax, eax
    cbg_leave
wsd_effect:
    lea rbx, [r12 + 1024]
    movabs rax, TD_ACTION
    cmp [rbx + 512], rax
    jne cdf_fatal
    cmp qword ptr [rbx + 520], 1
    jne cdf_fatal
    mov rax, [r12 + 40]
    add rax, 1
    jc cdf_fatal
    cmp rax, 2
    ja cdf_fatal
    cmp [rbx + 528], rax
    jne cdf_fatal
    mov rax, [r12 + 16]
    cmp [rbx + 536], rax
    jne cdf_fatal
    mov r14, [rbx + 544]
    test r14, r14
    jz cdf_fatal
    cmp [r12], r14
    je cdf_fatal
    mov rax, [rbx + 552]
    or rax, [rbx + 560]
    or rax, [rbx + 568]
    or rax, [rbx + 576]
    jnz cdf_fatal
    cmp qword ptr [rbx + 584], 1024
    jne cdf_fatal
    cmp qword ptr [rbx + 592], 80
    jne cdf_fatal
    mov rax, [rbx + 600]
    or rax, [rbx + 608]
    or rax, [rbx + 616]
    or rax, [rbx + 624]
    or rax, [rbx + 632]
    jnz cdf_fatal
    lea rdi, [r12 + 512]
    lea rsi, [rbx + 512]
    mov ecx, 16
    rep movsq
    mov rdi, r14
    call vl_validate
    mov rax, [r12 + 8]
    cmp [r14 + 40], rax
    jne cdf_fatal
    mov rdi, r14
    call value_lease_drop
    test rax, rax
    jnz cdf_fatal
    lea rdi, [r12 + 512]
    lea rsi, [rbx + 512]
    mov ecx, 16
    repe cmpsq
    jne cdf_fatal
    mov qword ptr [rbx + 600], 1
    add qword ptr [r12 + 40], 1
    jc cdf_fatal
    jmp wsd_again
wsd_policy_invoke:
    .byte 0xe8
worker_request_drop_policy_call_displacement:
    .long 0
    ret

# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
# Fixed storage consumption after HIA transfers LocalSessionWorker request's owned fields.
.equ WST_RESPONSE, 0x3130524657535248
.equ WST_ACTION, 0x3130415453575248

# worker_send_request_take(owned WorkerSendRequest ValueLease, output80, capacity).
worker_send_request_take:
    cbg_enter
    mov [rsp], rdi
    mov [rsp + 8], rsi
    mov [rsp + 16], rdx
    cmp rdx, 80
    jb wst_capacity
    test rsi, rsi
    jz wst_invalid
    call vl_validate
    mov rbx, [rsp]
    cmp qword ptr [rbx + 24], 48
    jne wst_invalid
    lea rax, [rip + worker_send_request_drop_entry]
    cmp [rbx + 32], rax
    jne wst_invalid
    mov rdi, [rbx + 40]
    call scs_validate
    mov edi, 4096
    call cdf_allocate
    test rax, rax
    jz cdf_fatal
    mov r12, rax
    mov rbx, [rsp]
    mov [r12], rbx
    mov [r12 + 72], rbx
    mov rax, [rbx + 40]
    mov [r12 + 8], rax
    mov [r12 + 88], rax
    mov rax, [rbx + 8]
    mov [r12 + 16], rax
    mov [r12 + 80], rax
    mov qword ptr [r12 + 24], 13
    mov rax, [rsp + 8]
    mov [r12 + 48], rax
    mov qword ptr [r12 + 56], 112
    movabs rax, TD_REQUEST
    mov [r12 + 64], rax
    mov qword ptr [r12 + 96], 48
    lea rdi, [r12 + 128]
    mov rsi, [rbx + 16]
    mov ecx, 6
    cld
    rep movsq
    mov esi, 1
    call td_observe
wst_again:
    lea rdi, [r12 + 64]
    mov esi, 112
    lea rdx, [r12 + 256]
    mov ecx, 80
    lea r8, [r12 + 1024]
    mov r9d, 2048
    call wst_policy_invoke
    add qword ptr [r12 + 32], 1
    jc cdf_fatal
    mov edx, eax
    cmp rax, rdx
    jne cdf_fatal
    cmp eax, 0xfffffff0
    je wst_effect
    cmp eax, 0xffffffff
    je wst_rejected
    cmp eax, 0xfffffffe
    je wst_rejected
    cmp eax, 80
    jne cdf_fatal
    movabs rax, WST_RESPONSE
    cmp [r12 + 256], rax
    jne cdf_fatal
    mov rax, [r12 + 16]
    cmp [r12 + 264], rax
    jne cdf_fatal
    mov rax, [r12]
    cmp [r12 + 272], rax
    jne cdf_fatal
    cmp qword ptr [r12 + 280], 48
    jne cdf_fatal
    lea rdi, [r12 + 288]
    lea rsi, [r12 + 128]
    mov ecx, 6
    repe cmpsq
    jne cdf_fatal
    cmp qword ptr [r12 + 32], 2
    jne cdf_fatal
    cmp qword ptr [r12 + 40], 1
    jne cdf_fatal
    cmp qword ptr [r12 + 1056], 0
    jne cdf_fatal
    cmp qword ptr [r12 + 1080], 1
    jne cdf_fatal
    mov rdi, [r12 + 48]
    lea rsi, [r12 + 256]
    mov ecx, 10
    rep movsq
    mov r15d, 80
    jmp wst_return
wst_rejected:
    cmp qword ptr [r12 + 40], 0
    jne cdf_fatal
    mov r15d, eax
wst_return:
    mov esi, 2
    call td_observe
    mov rdi, r12
    mov esi, 4096
    call cdf_unmap
    mov rax, r15
    cbg_leave
wst_capacity:
    mov eax, 0xfffffffe
    cbg_leave
wst_invalid:
    mov eax, 0xffffffff
    cbg_leave

wst_effect:
    lea rbx, [r12 + 1024]
    movabs rax, WST_ACTION
    cmp [rbx + 512], rax
    jne cdf_fatal
    cmp qword ptr [rbx + 520], 4
    jne cdf_fatal
    cmp qword ptr [rbx + 528], 1
    jne cdf_fatal
    cmp qword ptr [r12 + 40], 0
    jne cdf_fatal
    mov rax, [r12 + 16]
    cmp [rbx + 536], rax
    jne cdf_fatal
    mov r14, [rbx + 544]
    cmp r14, [r12]
    jne cdf_fatal
    mov rax, [rbx + 552]
    or rax, [rbx + 560]
    or rax, [rbx + 568]
    or rax, [rbx + 576]
    jnz cdf_fatal
    cmp qword ptr [rbx + 584], 1024
    jne cdf_fatal
    cmp qword ptr [rbx + 592], 80
    jne cdf_fatal
    mov rax, [rbx + 600]
    or rax, [rbx + 608]
    or rax, [rbx + 616]
    or rax, [rbx + 624]
    or rax, [rbx + 632]
    jnz cdf_fatal
    lea rdi, [r12 + 512]
    lea rsi, [rbx + 512]
    mov ecx, 16
    rep movsq
    mov rdi, r14
    call vl_validate
    mov rax, [r12 + 16]
    cmp [r14 + 8], rax
    jne cdf_fatal
    cmp qword ptr [r14 + 24], 48
    jne cdf_fatal
    lea rax, [rip + worker_send_request_drop_entry]
    cmp [r14 + 32], rax
    jne cdf_fatal
    mov rax, [r12 + 8]
    cmp [r14 + 40], rax
    jne cdf_fatal
    mov rdi, [r14 + 16]
    lea rsi, [r12 + 128]
    mov ecx, 6
    repe cmpsq
    jne cdf_fatal
    # Consume the enclosing WorkerSendRequest storage only. Its fields remain uniquely owned.
    mov rdi, [r14 + 16]
    mov rsi, [r14 + 48]
    call cdf_unmap
    mov rdi, r14
    mov esi, 4096
    call cdf_unmap
    lea rdi, [r12 + 512]
    lea rsi, [rbx + 512]
    mov ecx, 16
    repe cmpsq
    jne cdf_fatal
    mov qword ptr [rbx + 600], 1
    mov qword ptr [r12 + 40], 1
    jmp wst_again
wst_policy_invoke:
    .byte 0xe8
worker_request_take_policy_call_displacement:
    .long 0
    ret

# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
# Fixed Worker Result typed Drop. One private continuation, actual child ValueLease Drop.
.equ WRD_REQUEST, 0x3130305144545248
.equ WRD_RESPONSE, 0x3130305244545248
.equ WRD_ACTION, 0x3130304144545248

worker_result_drop_entry:
    cbg_enter
    mov [rsp], rdi
    mov [rsp + 8], rsi
    mov [rsp + 16], rdx
    mov [rsp + 24], rcx
    mov [rsp + 32], r8
    mov rdi, r8
    call vl_validate
    mov rbx, [rsp + 32]
    mov rax, [rsp + 8]
    cmp [rbx + 16], rax
    jne cdf_fatal
    cmp qword ptr [rsp + 16], 32
    jne cdf_fatal
    cmp qword ptr [rbx + 24], 32
    jne cdf_fatal
    mov rax, [rsp + 24]
    cmp [rbx + 8], rax
    jne cdf_fatal
    lea rax, [rip + worker_result_drop_entry]
    cmp [rbx + 32], rax
    jne cdf_fatal
    mov rdi, [rsp]
    cmp [rbx + 40], rdi
    jne cdf_fatal
    call scs_validate
    mov edi, 4096
    call cdf_allocate
    test rax, rax
    jz cdf_fatal
    mov r12, rax
    mov rax, [rsp + 32]
    mov [r12], rax
    mov [r12 + 72], rax
    mov rax, [rsp]
    mov [r12 + 8], rax
    mov [r12 + 88], rax
    mov rax, [rsp + 24]
    mov [r12 + 16], rax
    mov [r12 + 80], rax
    mov qword ptr [r12 + 24], 14
    mov qword ptr [r12 + 96], 32
    mov qword ptr [r12 + 56], 96
    movabs rax, WRD_REQUEST
    mov [r12 + 64], rax
    lea rdi, [r12 + 128]
    mov rsi, [rsp + 8]
    mov ecx, 4
    cld
    rep movsq
    mov esi, 1
    call td_observe
wrd_again:
    lea rdi, [r12 + 64]
    mov esi, 96
    lea rdx, [r12 + 256]
    mov ecx, 80
    lea r8, [r12 + 1024]
    mov r9d, 2048
    call wrd_policy_invoke
    add qword ptr [r12 + 32], 1
    jc cdf_fatal
    mov edx, eax
    cmp rax, rdx
    jne cdf_fatal
    cmp eax, 0xfffffff0
    je wrd_effect
    cmp eax, 80
    jne cdf_fatal
    movabs rax, WRD_RESPONSE
    cmp [r12 + 256], rax
    jne cdf_fatal
    cmp qword ptr [r12 + 264], 0
    jne cdf_fatal
    mov rax, [r12 + 16]
    cmp [r12 + 272], rax
    jne cdf_fatal
    mov rax, [r12]
    cmp [r12 + 280], rax
    jne cdf_fatal
    cmp qword ptr [r12 + 288], 14
    jne cdf_fatal
    mov rax, [r12 + 40]
    cmp [r12 + 296], rax
    jne cdf_fatal
    add rax, 1
    cmp [r12 + 32], rax
    jne cdf_fatal
    mov rax, [r12 + 304]
    or rax, [r12 + 312]
    or rax, [r12 + 320]
    or rax, [r12 + 328]
    jnz cdf_fatal
    cmp qword ptr [r12 + 1056], 0
    jne cdf_fatal
    cmp qword ptr [r12 + 1080], 1
    jne cdf_fatal
    mov esi, 2
    call td_observe
    mov rdi, r12
    mov esi, 4096
    call cdf_unmap
    xor eax, eax
    cbg_leave
wrd_effect:
    lea rbx, [r12 + 1024]
    movabs rax, WRD_ACTION
    cmp [rbx + 512], rax
    jne cdf_fatal
    cmp qword ptr [rbx + 520], 1
    jne cdf_fatal
    cmp qword ptr [rbx + 528], 1
    jne cdf_fatal
    cmp qword ptr [r12 + 40], 0
    jne cdf_fatal
    mov rax, [r12 + 16]
    cmp [rbx + 536], rax
    jne cdf_fatal
    mov r14, [rbx + 544]
    test r14, r14
    jz cdf_fatal
    cmp [r12 + 152], r14
    jne cdf_fatal
    cmp [r12], r14
    je cdf_fatal
    mov rax, [rbx + 552]
    or rax, [rbx + 560]
    or rax, [rbx + 568]
    or rax, [rbx + 576]
    jnz cdf_fatal
    cmp qword ptr [rbx + 584], 1024
    jne cdf_fatal
    cmp qword ptr [rbx + 592], 80
    jne cdf_fatal
    mov rax, [rbx + 600]
    or rax, [rbx + 608]
    or rax, [rbx + 616]
    or rax, [rbx + 624]
    or rax, [rbx + 632]
    jnz cdf_fatal
    lea rdi, [r12 + 512]
    lea rsi, [rbx + 512]
    mov ecx, 16
    rep movsq
    mov rdi, r14
    call vl_validate
    mov rax, [r12 + 8]
    cmp [r14 + 40], rax
    jne cdf_fatal
    mov rdi, r14
    call value_lease_drop
    test rax, rax
    jnz cdf_fatal
    lea rdi, [r12 + 512]
    lea rsi, [rbx + 512]
    mov ecx, 16
    repe cmpsq
    jne cdf_fatal
    mov qword ptr [rbx + 600], 1
    mov qword ptr [r12 + 40], 1
    jmp wrd_again
wrd_policy_invoke:
    .byte 0xe8
worker_result_drop_policy_call_displacement:
    .long 0
    ret

# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
# Fixed storage consumption after HIA transfers Worker Result's owned fields.
.equ WRT_RESPONSE, 0x3130524652575248
.equ WRT_ACTION, 0x3130415452575248

# worker_result_take(owned Result ValueLease, output64, capacity).
worker_result_take:
    cbg_enter
    mov [rsp], rdi
    mov [rsp + 8], rsi
    mov [rsp + 16], rdx
    cmp rdx, 64
    jb wrt_capacity
    test rsi, rsi
    jz wrt_invalid
    call vl_validate
    mov rbx, [rsp]
    cmp qword ptr [rbx + 24], 32
    jne wrt_invalid
    lea rax, [rip + worker_result_drop_entry]
    cmp [rbx + 32], rax
    jne wrt_invalid
    mov rdi, [rbx + 40]
    call scs_validate
    mov edi, 4096
    call cdf_allocate
    test rax, rax
    jz cdf_fatal
    mov r12, rax
    mov rbx, [rsp]
    mov [r12], rbx
    mov [r12 + 72], rbx
    mov rax, [rbx + 40]
    mov [r12 + 8], rax
    mov [r12 + 88], rax
    mov rax, [rbx + 8]
    mov [r12 + 16], rax
    mov [r12 + 80], rax
    mov qword ptr [r12 + 24], 15
    mov rax, [rsp + 8]
    mov [r12 + 48], rax
    mov qword ptr [r12 + 56], 96
    movabs rax, TD_REQUEST
    mov [r12 + 64], rax
    mov qword ptr [r12 + 96], 32
    lea rdi, [r12 + 128]
    mov rsi, [rbx + 16]
    mov ecx, 4
    cld
    rep movsq
    mov esi, 1
    call td_observe
wrt_again:
    lea rdi, [r12 + 64]
    mov esi, 96
    lea rdx, [r12 + 256]
    mov ecx, 64
    lea r8, [r12 + 1024]
    mov r9d, 2048
    call wrt_policy_invoke
    add qword ptr [r12 + 32], 1
    jc cdf_fatal
    mov edx, eax
    cmp rax, rdx
    jne cdf_fatal
    cmp eax, 0xfffffff0
    je wrt_effect
    cmp eax, 0xffffffff
    je wrt_rejected
    cmp eax, 0xfffffffe
    je wrt_rejected
    cmp eax, 64
    jne cdf_fatal
    movabs rax, WRT_RESPONSE
    cmp [r12 + 256], rax
    jne cdf_fatal
    mov rax, [r12 + 16]
    cmp [r12 + 264], rax
    jne cdf_fatal
    mov rax, [r12]
    cmp [r12 + 272], rax
    jne cdf_fatal
    cmp qword ptr [r12 + 280], 32
    jne cdf_fatal
    lea rdi, [r12 + 288]
    lea rsi, [r12 + 128]
    mov ecx, 4
    repe cmpsq
    jne cdf_fatal
    cmp qword ptr [r12 + 32], 2
    jne cdf_fatal
    cmp qword ptr [r12 + 40], 1
    jne cdf_fatal
    cmp qword ptr [r12 + 1056], 0
    jne cdf_fatal
    cmp qword ptr [r12 + 1080], 1
    jne cdf_fatal
    mov rdi, [r12 + 48]
    lea rsi, [r12 + 256]
    mov ecx, 8
    rep movsq
    mov r15d, 64
    jmp wrt_return
wrt_rejected:
    cmp qword ptr [r12 + 40], 0
    jne cdf_fatal
    mov r15d, eax
wrt_return:
    mov esi, 2
    call td_observe
    mov rdi, r12
    mov esi, 4096
    call cdf_unmap
    mov rax, r15
    cbg_leave
wrt_capacity:
    mov eax, 0xfffffffe
    cbg_leave
wrt_invalid:
    mov eax, 0xffffffff
    cbg_leave

wrt_effect:
    lea rbx, [r12 + 1024]
    movabs rax, WRT_ACTION
    cmp [rbx + 512], rax
    jne cdf_fatal
    cmp qword ptr [rbx + 520], 4
    jne cdf_fatal
    cmp qword ptr [rbx + 528], 1
    jne cdf_fatal
    cmp qword ptr [r12 + 40], 0
    jne cdf_fatal
    mov rax, [r12 + 16]
    cmp [rbx + 536], rax
    jne cdf_fatal
    mov r14, [rbx + 544]
    cmp r14, [r12]
    jne cdf_fatal
    mov rax, [rbx + 552]
    or rax, [rbx + 560]
    or rax, [rbx + 568]
    or rax, [rbx + 576]
    jnz cdf_fatal
    cmp qword ptr [rbx + 584], 1024
    jne cdf_fatal
    cmp qword ptr [rbx + 592], 80
    jne cdf_fatal
    mov rax, [rbx + 600]
    or rax, [rbx + 608]
    or rax, [rbx + 616]
    or rax, [rbx + 624]
    or rax, [rbx + 632]
    jnz cdf_fatal
    lea rdi, [r12 + 512]
    lea rsi, [rbx + 512]
    mov ecx, 16
    rep movsq
    mov rdi, r14
    call vl_validate
    mov rax, [r12 + 16]
    cmp [r14 + 8], rax
    jne cdf_fatal
    cmp qword ptr [r14 + 24], 32
    jne cdf_fatal
    lea rax, [rip + worker_result_drop_entry]
    cmp [r14 + 32], rax
    jne cdf_fatal
    mov rax, [r12 + 8]
    cmp [r14 + 40], rax
    jne cdf_fatal
    mov rdi, [r14 + 16]
    lea rsi, [r12 + 128]
    mov ecx, 4
    repe cmpsq
    jne cdf_fatal
    # Consume the enclosing Result storage only. Its fields remain uniquely owned.
    mov rdi, [r14 + 16]
    mov rsi, [r14 + 48]
    call cdf_unmap
    mov rdi, r14
    mov esi, 4096
    call cdf_unmap
    lea rdi, [r12 + 512]
    lea rsi, [rbx + 512]
    mov ecx, 16
    repe cmpsq
    jne cdf_fatal
    mov qword ptr [rbx + 600], 1
    mov qword ptr [r12 + 40], 1
    jmp wrt_again
wrt_policy_invoke:
    .byte 0xe8
worker_result_take_policy_call_displacement:
    .long 0
    ret

# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
# Optional fixed observer for the existing actual semaphore/MPSC Waker hooks.
# The original hook completes before any row is appended. No business decision.
channel_waker_observer_table:
    lea rax, [rip + channel_observed_waker_table]
    ret
channel_observed_clone:
    cbg_enter
    mov r12, rdi
    mov r13, rsi
    call sem_default_clone
    test rax, rax
    jnz cdf_fatal
    mov rdi, [r12 + 632]
    mov esi, 1
    mov rdx, r13
    call oneshot_observe
    xor eax, eax
    cbg_leave
channel_observed_drop:
    cbg_enter
    mov r12, rdi
    mov r13, rsi
    call sem_default_drop
    test rax, rax
    jnz cdf_fatal
    mov rdi, [r12 + 632]
    mov esi, 2
    mov rdx, r13
    call oneshot_observe
    xor eax, eax
    cbg_leave
channel_observed_wake:
    cbg_enter
    mov r12, rdi
    mov r13, rsi
    call sem_default_wake
    test rax, rax
    jnz cdf_fatal
    mov rdi, [r12 + 632]
    mov esi, 4
    mov rdx, r13
    call oneshot_observe
    xor eax, eax
    cbg_leave
.balign 8
channel_observed_waker_table:
    .quad SEM_VTABLE_MAGIC
    .quad channel_observed_clone - channel_observed_waker_table
    .quad channel_observed_drop - channel_observed_waker_table
    .quad channel_observed_wake - channel_observed_waker_table
