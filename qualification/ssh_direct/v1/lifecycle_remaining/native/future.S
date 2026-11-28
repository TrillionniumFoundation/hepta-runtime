# Outer caller future: original timeout, post-reply active check and exactly
# one CancelOnDrop. This is separate from the independent owner's result.
.equ R_CALLER_DONE, 488
.equ R_FUTURE, 800
.equ R_CALLER_RESULT, 1024
.equ R_FUTURE_WORK, 1152
.equ R_FUTURE_OUT, 1280

# request, operation. Every observed readiness/error/stop/token is actual.
ssh_future:
    push r12
    sub rsp, 320
    mov r12, rdi
    mov rax, 0x3130305146535348
    mov QWORD PTR [rsp], rax
    mov QWORD PTR [rsp+8], rsi
    mov QWORD PTR [rsp+16], r12
    mov rax, QWORD PTR [r12+R_GENERATION]
    mov QWORD PTR [rsp+24], rax
    lea rdi, [rsp+32]
    mov esi, 96
    call ssh_zero
    cmp QWORD PTR [rsp+8], 0
    je .Lfuture_init_clock
    mov rax, QWORD PTR [r12+R_DONE]
    mov QWORD PTR [rsp+32], rax
    mov rax, QWORD PTR [r12+R_KIND]
    mov QWORD PTR [rsp+40], rax
    mov rax, QWORD PTR [r12+R_CTX]
    mov rax, QWORD PTR [rax+C_FROZEN]
    mov QWORD PTR [rsp+48], rax
    mov rax, QWORD PTR [r12+R_ADM_WORK+32]
    mov QWORD PTR [rsp+72], rax
    call ssh_now
    cmp rdx, -1
    je .Lfuture_clock_failed
    mov QWORD PTR [rsp+56], rax
    mov QWORD PTR [rsp+64], rdx
    jmp .Lfuture_invoke
.Lfuture_init_clock:
    mov rax, QWORD PTR [r12+R_DEADLINE_LO]
    mov QWORD PTR [rsp+56], rax
    mov rax, QWORD PTR [r12+R_DEADLINE_HI]
    mov QWORD PTR [rsp+64], rax
.Lfuture_invoke:
    lea rdi, [rsp+128]
    mov esi, 192
    call ssh_zero
    mov rdi, QWORD PTR [r12+R_CTX]
    lea rsi, [r12+R_FUTURE]
    mov rdx, rsp
    mov ecx, 128
    lea r8, [rsp+128]
    call ssh_invoke
    mov rdx, QWORD PTR [rsp+152]
.Lfuture_return:
    add rsp, 320
    pop r12
    ret
.Lfuture_clock_failed:
    mov rax, -5
    jmp .Lfuture_return

# request, 96-byte result. Each original caller polls this future serially.
# 1 = pending; 0 = a stable result borrowed until caller release.
.global ssh_direct_capture_result
ssh_direct_capture_result:
    push rbx
    push r12
    push r13
    mov r12, rdi
    mov r13, rsi
    cmp QWORD PTR [r12+R_CALLER_DONE], 1
    je .Lcapture_cached
    cmp QWORD PTR [r12+R_FUTURE_WORK], 0
    je .Lcapture_early_owner
    mov esi, 1
    call ssh_future
    cmp eax, 192
    jne .Lcapture_protocol
    test rdx, rdx
    jz .Lcapture_pending
    mov rbx, rdx
    cmp rbx, 3
    je .Lcapture_deadline
    mov rdi, r12
    lea rsi, [r12+R_CALLER_RESULT]
    call ssh_direct_result
    test rax, rax
    jnz .Lcapture_protocol
    cmp rbx, 4
    jne .Lcapture_recorded
    mov QWORD PTR [r12+R_CALLER_RESULT+16], 1
    mov QWORD PTR [r12+R_CALLER_RESULT+24], 704
    mov QWORD PTR [r12+R_CALLER_RESULT+32], 0
    jmp .Lcapture_recorded
.Lcapture_early_owner:
    mov rdi, r12
    lea rsi, [r12+R_CALLER_RESULT]
    call ssh_direct_result
    test rax, rax
    jnz .Lcapture_protocol
    jmp .Lcapture_recorded
.Lcapture_deadline:
    lea rdi, [r12+R_CALLER_RESULT]
    mov esi, 96
    call ssh_zero
    mov rax, 0x3130534552535348
    mov QWORD PTR [r12+R_CALLER_RESULT], rax
    mov QWORD PTR [r12+R_CALLER_RESULT+8], 96
    mov QWORD PTR [r12+R_CALLER_RESULT+16], 1
    mov QWORD PTR [r12+R_CALLER_RESULT+24], 703
    mov rax, QWORD PTR [r12+R_GENERATION]
    mov QWORD PTR [r12+R_CALLER_RESULT+80], rax
.Lcapture_recorded:
    cmp QWORD PTR [r12+R_CALLER_RESULT+16], 0
    je .Lcapture_publish
    # An Err does not expose partially captured Output bytes.
    mov QWORD PTR [r12+R_CALLER_RESULT+40], 0
    mov QWORD PTR [r12+R_CALLER_RESULT+48], 0
    mov QWORD PTR [r12+R_CALLER_RESULT+56], 0
    mov QWORD PTR [r12+R_CALLER_RESULT+64], 0
    mov QWORD PTR [r12+R_CALLER_RESULT+72], 0
.Lcapture_publish:
    mov QWORD PTR [r12+R_CALLER_DONE], 1
    cmp QWORD PTR [r12+R_ADM_WORK], 0
    je .Lcapture_cached
    mov rdi, r12
    call ssh_direct_cancel
.Lcapture_cached:
    mov rdi, r13
    lea rsi, [r12+R_CALLER_RESULT]
    mov edx, 96
    call ssh_copy
    xor eax, eax
    jmp .Lcapture_return
.Lcapture_pending:
    mov eax, 1
    jmp .Lcapture_return
.Lcapture_protocol:
    mov rax, -71
.Lcapture_return:
    pop r13
    pop r12
    pop rbx
    ret
