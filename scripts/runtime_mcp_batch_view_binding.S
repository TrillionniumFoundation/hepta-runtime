/* Trusted Batch/View installation. Both native owners remain authoritative.
 * A private record owns the original Batch arenas and the actual cloned lease;
 * no protocol value selects this record or either descriptor table.
 * Record: magic,phase,batch,view,own_lease,own_lease_cap,own_cache,own_cache_cap,
 * own_lease_private48/56,clone_epoch,clone_ticket,initial_epoch,initial_ticket.
 * Phases 0/1/2/3/4/5 = initial/dropped/released/cloned/installed/retired.
 * Phase 6 quarantines an impossible successful-but-invalid native receipt.
 * It is never 'cleaned' by guessing whether an ownership effect occurred. */
.intel_syntax noprefix
.section .text
.global runtime_batch_view_install
.global runtime_batch_view_refresh
.global runtime_batch_view_store
.global runtime_batch_view_retire

/* rdi=zeroed 4096-byte record, rsi=fresh Batch, rdx=this Session's View. */
runtime_batch_view_install:
    push rbp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub rsp, 72
    mov r12, rdi
    mov r14, rsi
    mov r13, rdx
    cmp qword ptr [r12], 0
    jne batch_view_install_invalid
    cmp qword ptr [r14 + 808], 0
    jne batch_view_install_invalid
    cmp qword ptr [r14 + 840], 0
    jne batch_view_install_invalid
    cmp qword ptr [r14 + 648], 0
    jne batch_view_install_invalid
    mov rbx, [r14 + 8]
    mov rbp, [r13 + 8]
    mov rax, [rbx + 7 * 64]
    cmp [rbp + 7 * 64], rax
    jne batch_view_install_invalid
    mov rax, [rbx + 8 * 64]
    cmp [rbp + 8 * 64], rax
    jne batch_view_install_invalid
    mov rax, [rbx + 8]
    cmp qword ptr [rax + 8], 0
    jne batch_view_install_invalid
    cmp qword ptr [rax + 16], 0
    jne batch_view_install_invalid
    mov rax, [rbp + 8]
    cmp qword ptr [rax + 16], 1
    jne batch_view_install_invalid
    cmp qword ptr [rax + 24], 1
    jne batch_view_install_invalid
    cmp qword ptr [rax + 56], 0
    jne batch_view_install_invalid
    mov rcx, [rax + 40]
    test rcx, rcx
    jz batch_view_install_invalid
    mov rdx, [rax + 48]
    test rdx, rdx
    jz batch_view_install_invalid
    mov rax, 0x3230304250564248 /* HBVPB002 */
    mov [r12], rax
    mov [r12 + 16], r14
    mov [r12 + 24], r13
    mov [r12 + 80], rcx
    mov [rsp + 64], rdx
    mov rax, [rbx + 7 * 64 + 8]
    mov [r12 + 32], rax
    mov rax, [rbx + 7 * 64 + 16]
    mov [r12 + 40], rax
    mov rax, [rbx + 8 * 64 + 8]
    mov [r12 + 48], rax
    mov rax, [rbx + 8 * 64 + 16]
    mov [r12 + 56], rax
    mov rax, [rbx + 7 * 64 + 48]
    mov [r12 + 64], rax
    mov rax, [rbx + 7 * 64 + 56]
    mov [r12 + 72], rax
    mov rax, [r14 + 112]
    mov [r12 + 96], rax
    mov rax, [r14 + 120]
    mov [r12 + 104], rax
    mov r15, r14
    mov rdi, rsp
    call batch_view_zero_frame
    mov rax, 0x3230514c41434248 /* HBCALQ02 DROP */
    mov [rsp], rax
    mov qword ptr [rsp + 8], 6
    mov rdi, rsp
    mov esi, 64
    xor edx, edx
    call batch_dispatch
    cmp eax, 64
    jne batch_view_install_return_code
    mov qword ptr [r12 + 8], 6
    mov rdi, [rbx + 24]
    call batch_view_unit_receipt
    test eax, eax
    jnz batch_view_install_return_code
    mov qword ptr [r12 + 8], 1
    mov rdi, rsp
    call batch_view_zero_frame
    mov rax, 0x313030514c435248 /* HRCLQ001 RELEASE */
    mov [rsp], rax
    mov qword ptr [rsp + 8], 3
    mov rax, [r12 + 96]
    mov [rsp + 16], rax
    mov rax, [r12 + 104]
    mov [rsp + 24], rax
    mov rdi, rsp
    mov esi, 64
    mov edx, 7
    call batch_dispatch
    cmp eax, 64
    jne batch_view_install_return_code
    mov qword ptr [r12 + 8], 6
    mov rdi, [rbx + 7 * 64 + 24]
    call batch_view_lease_receipt
    test eax, eax
    jnz batch_view_install_return_code
    mov rax, [r12 + 96]
    cmp [rdi + 8], rax
    jne batch_view_install_invalid
    mov rax, [r12 + 104]
    cmp [rdi + 16], rax
    jne batch_view_install_invalid
    mov rax, [rdi + 24]
    or rax, [rdi + 32]
    jnz batch_view_install_invalid
    mov qword ptr [r12 + 8], 2
    mov rdi, r12
    call runtime_batch_view_refresh
    test eax, eax
    jnz batch_view_install_return_code
    mov rdi, rsp
    call batch_view_zero_frame
    mov rax, 0x313030514c435248
    mov [rsp], rax
    mov qword ptr [rsp + 8], 2
    mov rax, [r12 + 80]
    mov [rsp + 16], rax
    mov rax, [rsp + 64]
    mov [rsp + 24], rax
    mov rdi, rsp
    mov esi, 64
    mov edx, 7
    call batch_dispatch
    mov rbp, rax
    mov rdi, r12
    call runtime_batch_view_store
    test eax, eax
    jnz batch_view_install_return_code
    mov rax, rbp
    cmp eax, 64
    jne batch_view_install_return_code
    mov qword ptr [r12 + 8], 6
    mov rdi, [rbx + 7 * 64 + 24]
    call batch_view_lease_receipt
    test eax, eax
    jnz batch_view_install_return_code
    mov rax, [r12 + 80]
    cmp [rdi + 8], rax
    jne batch_view_install_invalid
    cmp qword ptr [rdi + 16], 0
    je batch_view_install_invalid
    cmp qword ptr [rdi + 24], 2
    jb batch_view_install_invalid
    cmp qword ptr [rdi + 32], 1
    jne batch_view_install_invalid
    mov [r15 + 112], rax
    mov rax, [rdi + 16]
    mov [r12 + 88], rax
    mov [r15 + 120], rax
    mov qword ptr [r12 + 8], 3
    mov rdi, rsp
    call batch_view_install_frame
    mov rdi, rsp
    mov esi, 64
    xor edx, edx
    call batch_dispatch
    cmp eax, 64
    jne batch_view_install_return_code
    mov qword ptr [r12 + 8], 6
    mov rdi, [rbx + 24]
    call batch_view_unit_receipt
    test eax, eax
    jnz batch_view_install_return_code
    mov qword ptr [r12 + 8], 4
    xor eax, eax
    jmp batch_view_install_done
batch_view_install_invalid:
    mov eax, 0xfffffff8
batch_view_install_return_code:
    mov edx, eax
    cmp rax, rdx
    jne batch_view_install_invalid
    cmp eax, 0xffff0000
    jb batch_view_install_invalid
batch_view_install_done:
    add rsp, 72
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret

/* Only workspace borrows move; every engine keeps its own output mappings. */
runtime_batch_view_refresh:
    mov rax, 0x3230304250564248
    cmp [rdi], rax
    jne batch_view_copy_invalid
    mov rax, [rdi + 24]
    mov rax, [rax + 8]
    mov rcx, [rdi + 16]
    mov rcx, [rcx + 8]
    jmp batch_view_copy_work
runtime_batch_view_store:
    mov rax, 0x3230304250564248
    cmp [rdi], rax
    jne batch_view_copy_invalid
    mov rax, [rdi + 16]
    mov rax, [rax + 8]
    mov rcx, [rdi + 24]
    mov rcx, [rcx + 8]
batch_view_copy_work:
    mov rdx, [rax + 7 * 64 + 8]
    mov [rcx + 7 * 64 + 8], rdx
    mov rdx, [rax + 7 * 64 + 16]
    mov [rcx + 7 * 64 + 16], rdx
    mov rdx, [rax + 7 * 64 + 48]
    mov [rcx + 7 * 64 + 48], rdx
    mov rdx, [rax + 7 * 64 + 56]
    mov [rcx + 7 * 64 + 56], rdx
    mov rdx, [rax + 8 * 64 + 8]
    mov [rcx + 8 * 64 + 8], rdx
    mov rdx, [rax + 8 * 64 + 16]
    mov [rcx + 8 * 64 + 16], rdx
    xor eax, eax
    ret
batch_view_copy_invalid:
    mov eax, 0xfffffff8
    ret

/* rdi=private record. A failed install is retired through actual HIA calls.
 * No arena is unmapped until the native owner has consumed its live lease.
 * A quarantined receipt or live worker is retained and reported as failure. */
runtime_batch_view_retire:
    push rbp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub rsp, 72
    mov r12, rdi
    mov rax, 0x3230304250564248
    cmp [r12], rax
    jne batch_view_retire_invalid
    cmp qword ptr [r12 + 8], 5
    jae batch_view_retire_invalid
    mov r15, [r12 + 16]
    cmp qword ptr [r15 + 648], 0
    jne batch_view_retire_invalid
    mov rbx, [r15 + 8]
    mov rbp, [r12 + 8]
    cmp rbp, 3
    jae batch_view_retire_borrow
    call batch_view_restore_owned
    cmp rbp, 2
    jne batch_view_retire_own_ticket
    /* RELEASE completed, CLONE did not. Re-create only the empty private
     * cache to give the original engine retirement its actual live ticket. */
    mov rdi, rsp
    call batch_view_zero_frame
    mov rax, 0x313030514c435248
    mov [rsp], rax
    mov qword ptr [rsp + 8], 1
    mov qword ptr [rsp + 32], 8
    mov rdi, rsp
    mov esi, 64
    mov edx, 7
    call batch_dispatch
    cmp eax, 64
    jne batch_view_retire_invalid
    mov rdi, [rbx + 7 * 64 + 24]
    call batch_view_lease_receipt
    test eax, eax
    jnz batch_view_retire_invalid
    cmp qword ptr [rdi + 24], 1
    jne batch_view_retire_invalid
    cmp qword ptr [rdi + 32], 1
    jne batch_view_retire_invalid
    mov rax, [rdi + 8]
    mov [r12 + 96], rax
    mov rax, [rdi + 16]
    mov [r12 + 104], rax
    mov qword ptr [r12 + 8], 1
batch_view_retire_own_ticket:
    mov rax, [r12 + 96]
    mov [r15 + 112], rax
    mov rax, [r12 + 104]
    mov [r15 + 120], rax
    test rbp, rbp
    jz batch_view_retire_call
    jmp batch_view_retire_install
batch_view_retire_borrow:
    mov rdi, r12
    call runtime_batch_view_refresh
    test eax, eax
    jnz batch_view_retire_invalid
    cmp rbp, 4
    je batch_view_retire_call
batch_view_retire_install:
    mov rdi, rsp
    call batch_view_install_frame
    mov rdi, rsp
    mov esi, 64
    xor edx, edx
    call batch_dispatch
    cmp eax, 64
    jne batch_view_retire_invalid
    mov rdi, [rbx + 24]
    call batch_view_unit_receipt
    test eax, eax
    jnz batch_view_retire_invalid
batch_view_retire_call:
    call batch_engine_retire
    mov r13, rax
    cmp rbp, 3
    jb batch_view_retire_check
    mov rdi, r12
    call runtime_batch_view_store
    test eax, eax
    jnz batch_view_retire_invalid
batch_view_retire_check:
    test r13, r13
    jnz batch_view_retire_invalid
    call batch_view_restore_owned
    mov qword ptr [r12 + 8], 5
    call batch_engine_free_maps
    mov qword ptr [r12 + 16], 0
    xor eax, eax
    jmp batch_view_retire_done
batch_view_retire_invalid:
    mov eax, 0xfffffff8
batch_view_retire_done:
    add rsp, 72
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret

/* Internal helpers preserve all callee-saved registers. */
batch_view_restore_owned:
    mov rax, [r12 + 32]
    mov [rbx + 7 * 64 + 8], rax
    mov rax, [r12 + 40]
    mov [rbx + 7 * 64 + 16], rax
    mov rax, [r12 + 48]
    mov [rbx + 8 * 64 + 8], rax
    mov rax, [r12 + 56]
    mov [rbx + 8 * 64 + 16], rax
    mov rax, [r12 + 64]
    mov [rbx + 7 * 64 + 48], rax
    mov rax, [r12 + 72]
    mov [rbx + 7 * 64 + 56], rax
    ret
batch_view_zero_frame:
    push rdi
    xor eax, eax
    mov ecx, 8
    cld
    rep stosq
    pop rdi
    ret
batch_view_install_frame:
    sub rsp, 8
    call batch_view_zero_frame
    add rsp, 8
    mov rax, 0x3230494e49434248
    mov [rdi], rax
    mov qword ptr [rdi + 8], 1
    mov rax, [r15 + 112]
    mov [rdi + 16], rax
    mov rax, [r15 + 120]
    mov [rdi + 24], rax
    mov qword ptr [rdi + 32], 10
    mov qword ptr [rdi + 40], 7
    ret
batch_view_unit_receipt:
    mov rax, 0x3230305241434248
    cmp [rdi], rax
    jne batch_view_copy_invalid
    cmp qword ptr [rdi + 8], 7
    jne batch_view_copy_invalid
    mov rax, [rdi + 16]
    or rax, [rdi + 24]
    or rax, [rdi + 32]
    or rax, [rdi + 40]
    or rax, [rdi + 48]
    or rax, [rdi + 56]
    jnz batch_view_copy_invalid
    ret
batch_view_lease_receipt:
    mov rax, 0x313030524c435248
    cmp [rdi], rax
    jne batch_view_copy_invalid
    cmp qword ptr [rdi + 8], 0
    je batch_view_copy_invalid
    cmp qword ptr [rdi + 16], 0
    je batch_view_copy_invalid
    mov rax, [rdi + 40]
    or rax, [rdi + 48]
    or rax, [rdi + 56]
    jnz batch_view_copy_invalid
    ret
