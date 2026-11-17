/* Fixed private Local TextEditor attachment. Application dispatch and wire
 * conversion live in text_editor_local_body HIA; all edit semantics remain
 * in the twelve HIA owners. This boundary only binds and retains capabilities.
 * Extra engine+400 borrows the one process hub; +408 owns its call context.
 * The fixture executes serially. No public async/cancellation claim is made. */
.intel_syntax noprefix
.section .text
.global runtime_text_body_hub_create
.global runtime_text_body_hub_destroy
.global runtime_text_body_owned
.global runtime_text_body_release
.global runtime_text_body_shared_grow
.global runtime_text_body_hint

/* Allocate one pair of persistent owners before either session is made. */
runtime_text_body_hub_create:
    push rbx
    push rbp
    push r12
    sub rsp, 64
    mov edi, 4096
    call view_allocate
    cmp rax, -4095
    jae rtbh_create_return
    mov r12, rax
    mov rax, 0x3142554842544c48 /* HLTBHUB1 */
    mov [r12], rax
    lea rax, [rip + runtime_text_body_images]
    mov rdx, [rax + 3*8]
    mov [r12 + 64], rdx
    mov rdx, [rax + 6*8]
    mov [r12 + 128], rdx
    xor ebp, ebp
rtbh_create_slot:
    mov rbx, rbp
    shl rbx, 6
    lea rbx, [r12 + rbx + 64]
    mov edi, 4096
    call view_allocate
    cmp rax, -4095
    jae rtbh_create_failed
    mov [rbx + 8], rax
    mov qword ptr [rbx + 16], 4096
    mov edi, 4096
    call view_allocate
    cmp rax, -4095
    jae rtbh_create_failed
    mov [rbx + 24], rax
    mov qword ptr [rbx + 32], 4096
    lea rdi, [rsp]
    xor eax, eax
    mov ecx, 8
    rep stosq
    mov rax, 0x314b434f4c465248 /* HRFLOCK1 */
    test ebp, ebp
    jz rtbh_create_request
    mov rax, 0x3130515453494848 /* HHISTQ01 */
rtbh_create_request:
    mov [rsp], rax
    mov rdi, rsp
    mov esi, 64
    mov rdx, [rbx + 24]
    mov rcx, [rbx + 32]
    mov r8, [rbx + 8]
    mov r9, [rbx + 16]
    call qword ptr [rbx]
    mov [rbx + 40], rax
    cmp rax, 64
    jne rtbh_create_failed
    inc ebp
    cmp ebp, 2
    jb rtbh_create_slot
    mov rax, r12
    jmp rtbh_create_return
rtbh_create_failed:
    mov rdi, r12
    call runtime_text_body_hub_destroy
    mov rax, -12
rtbh_create_return:
    add rsp, 64
    pop r12
    pop rbp
    pop rbx
    ret

/* Both session contexts have already drained and released their borrows. */
runtime_text_body_hub_destroy:
    push rbx
    push rbp
    push r12
    mov r12, rdi
    mov rax, 0x3142554842544c48
    cmp [r12], rax
    jne rtbh_destroy_invalid
.ifdef RUNTIME_LOCK_WAKE_HOOK
    mov rax,[r12+XW_HUB_HEAD]
    or rax,[r12+XW_HUB_COUNT]
    jnz rtbh_destroy_invalid
.endif
    xor ebp, ebp
rtbh_destroy_slot:
    mov rbx, rbp
    shl rbx, 6
    lea rbx, [r12 + rbx + 64]
    mov rdi, [rbx + 8]
    test rdi, rdi
    jz rtbh_destroy_output
    mov rsi, [rbx + 16]
    add rsi, 4096
    mov eax, 11
    syscall
    test rax, rax
    jnz rtbh_destroy_done
    mov qword ptr [rbx + 8], 0
    mov qword ptr [rbx + 16], 0
rtbh_destroy_output:
    mov rdi, [rbx + 24]
    test rdi, rdi
    jz rtbh_destroy_next
    mov rsi, [rbx + 32]
    add rsi, 4096
    mov eax, 11
    syscall
    test rax, rax
    jnz rtbh_destroy_done
    mov qword ptr [rbx + 24], 0
    mov qword ptr [rbx + 32], 0
rtbh_destroy_next:
    inc ebp
    cmp ebp, 2
    jb rtbh_destroy_slot
    mov rdi, r12
    mov esi, 8192
    mov eax, 11
    syscall
    jmp rtbh_destroy_done
rtbh_destroy_invalid:
    mov rax, -22
rtbh_destroy_done:
    pop r12
    pop rbp
    pop rbx
    ret

/* ABI: rdi hub, rsi owner3/6, rdx needed work, rcx needed output. */
runtime_text_body_shared_grow:
    push rbx
    push r12
    push r13
    push r14
    sub rsp, 8
    mov r12, rdi
    mov r13, rdx
    mov r14, rcx
    mov rax, 0x3142554842544c48
    cmp [r12], rax
    jne rtbh_grow_invalid
    lea rbx, [r12 + 64]
    cmp esi, 3
    je rtbh_grow_selected
    cmp esi, 6
    jne rtbh_grow_invalid
    add rbx, 64
rtbh_grow_selected:
    cmp r13, [rbx + 16]
    jb rtbh_grow_invalid
    cmp r14, [rbx + 32]
    jb rtbh_grow_invalid
    cmp r13, 268435456
    ja rtbh_grow_resource
    cmp r14, 134217728
    ja rtbh_grow_resource
    add r13, 4095
    and r13, -4096
    add r14, 4095
    and r14, -4096
    cmp r13, [rbx + 16]
    je rtbh_grow_output
    mov rdi, [rbx + 8]
    mov rsi, [rbx + 16]
    mov rdx, r13
    call view_resize
    cmp rax, -4095
    jae rtbh_grow_resource
    mov [rbx + 8], rax
    mov [rbx + 16], r13
rtbh_grow_output:
    cmp r14, [rbx + 32]
    je rtbh_grow_success
    mov rdi, [rbx + 24]
    mov rsi, [rbx + 32]
    mov rdx, r14
    call view_resize
    cmp rax, -4095
    jae rtbh_grow_resource
    mov [rbx + 24], rax
    mov [rbx + 32], r14
rtbh_grow_success:
    xor eax, eax
    jmp rtbh_grow_done
rtbh_grow_resource:
    mov eax, 0xfffffffc
    jmp rtbh_grow_done
rtbh_grow_invalid:
    mov eax, 0xffffffff
rtbh_grow_done:
    add rsp, 8
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

/* Fixed native slot40, owned result retained until parent delivery completes. */
runtime_text_body_owned:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    sub rsp, 32
    mov [rsp], rdi
    mov [rsp + 8], rsi
    mov rbx, [r15 + 8]
    add rbx, 40*64
    lea rbp, [r15 + 512 + 40*64]
    cmp qword ptr [rbp], 0
    jne rtb_invalid
    cmp qword ptr [rbp + 8], 0
    jne rtb_invalid
    mov qword ptr [rbp], 1
    mov qword ptr [rbx + 48], 0
    mov qword ptr [rbx + 56], 0
    mov r14, [r15 + 400]
    test r14, r14
    jz rtb_invalid_active
    mov rax, 0x3142554842544c48
    cmp [r14], rax
    jne rtb_invalid_active
    mov r12, [r15 + 408]
    test r12, r12
    jnz rtb_existing
    mov edi, 4096
    call view_allocate
    cmp rax, -4095
    jae rtb_resource_active
    mov r12, rax
    mov [r15 + 408], rax
    mov [r12 + 256 + 168], r15
    jmp rtb_context_ready
rtb_existing:
    cmp qword ptr [r12 + 152], 0
    je rtb_context_ready
    mov rdi, r12
    call local_text_body_release
    test eax, eax
    jnz rtb_invalid_active
rtb_context_ready:
    mov rdi, r12
    xor eax, eax
    mov ecx, 24
    rep stosq
    mov rax, 0x3130494342544c48 /* HLTBCI01 */
    mov [r12], rax
    mov qword ptr [r12 + 8], 192
    lea rax, [rip + runtime_text_body_images]
    mov [r12 + 16], rax
    lea rax, [rip + runtime_text_create_cache]
    mov [r12 + 24], rax
    lea rax, [r12 + 256]
    mov [r12 + 32], rax
    mov [r12 + 48], rax
    lea rax, [rip + runtime_text_body_hint]
    mov [r12 + 40], rax
    lea rax, [r14 + 64]
    mov [r12 + 56], rax
    lea rax, [r14 + 128]
    mov [r12 + 64], rax
    lea rax, [rip + runtime_text_body_shared_grow]
    mov [r12 + 72], rax
    mov [r12 + 80], r14
    lea rax, [r14 + 8]
    mov [r12 + 88], rax
    mov rax, [r15 + 32]
    mov [r12 + 96], rax
    mov rdi, r12
    mov rsi, [rsp]
    mov rdx, [rsp + 8]
    inc qword ptr [r15 + 128]
    call local_text_body_run
    mov edx, eax
    cmp rax, rdx
    jne rtb_invalid_active
    cmp [r12 + 128], rax
    jne rtb_invalid_active
    /* A scheduling WAIT remains distinct; this serial fixture has no waiter
     * executor. Never spin, fabricate a wake, or release an undrained owner. */
    cmp eax, 0xffffffdf
    je rtb_undrained
    cmp qword ptr [r12 + 136], 1
    jne rtb_invalid_active
    cmp qword ptr [r12 + 144], 1
    jne rtb_invalid_active
    cmp qword ptr [r12 + 160], 0
    jne rtb_invalid_active
    mov [rbx + 48], rax
    mov rcx, [r12 + 112]
    mov [rbx + 32], rcx
    mov rcx, [r12 + 120]
    mov [rbx + 40], rcx
    mov [rbx + 56], rcx
    cmp eax, 0xffff0000
    jae rtb_private
    cmp rax, rcx
    jne rtb_invalid_active
    jmp rtb_complete
rtb_private:
    test rcx, rcx
    jnz rtb_invalid_active
    jmp rtb_complete
rtb_resource_active:
    mov eax, 0xfffffffc
    jmp rtb_error
rtb_invalid_active:
    mov eax, 0xffffffff
rtb_error:
    mov [rbx + 48], rax
    mov qword ptr [rbx + 56], 0
rtb_complete:
    mov qword ptr [rbp], 0
    jmp rtb_done
rtb_undrained:
    mov [rbx + 48], rax
    mov qword ptr [rbx + 56], 0
    jmp rtb_done
rtb_invalid:
    mov eax, 0xffffffff
rtb_done:
    add rsp, 32
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

/* Same request Scope receives each actual HIA hint before caller DRAIN. */
runtime_text_body_hint:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp, 72
    mov r12, rdi
    mov [rsp], rsi
    mov [rsp + 8], rdx
    mov [rsp + 16], rcx
    cmp rdx, 32
    jb rtbh_hint_invalid
    mov rax, 0x3130514842544c48 /* HLTBHQ01 */
    cmp [rsi], rax
    jne rtbh_hint_invalid
    cmp qword ptr [rsi + 8], 1
    jne rtbh_hint_invalid
    cmp qword ptr [rsi + 24], 0
    jne rtbh_hint_invalid
    sub rdx, 32
    cmp [rsi + 16], rdx
    jne rtbh_hint_invalid
    mov r14, [r12 + 168]
    test r14, r14
    jz rtbh_hint_invalid
    mov rbx, [r14 + 8]
    mov rbx, [rbx + 35*64 + 8]
    test rbx, rbx
    jz rtbh_hint_invalid
    cmp qword ptr [rbx + 416], 1
    jne rtbh_hint_invalid
    mov rax, [rbx + 112]
    test rax, rax
    jz rtbh_hint_invalid
    mov [rsp + 24], rax
    mov rax, [rbx + 120]
    test rax, rax
    jz rtbh_hint_invalid
    mov [rsp + 32], rax
    add rdx, 64
    jc rtbh_hint_resource
    cmp rdx, [r12 + 192]
    jbe rtbh_hint_frame
    add rdx, 4095
    jc rtbh_hint_resource
    and rdx, -4096
    test rdx, rdx
    jle rtbh_hint_resource
    mov r13, rdx
    mov rdi, [r12 + 184]
    test rdi, rdi
    jz rtbh_hint_allocate
    mov rsi, [r12 + 192]
    call view_resize
    jmp rtbh_hint_allocated
rtbh_hint_allocate:
    mov rdi, r13
    call view_allocate
rtbh_hint_allocated:
    cmp rax, -4095
    jae rtbh_hint_resource
    mov [r12 + 184], rax
    mov [r12 + 192], r13
rtbh_hint_frame:
    mov rbp, [r12 + 184]
    mov rdi, rbp
    xor eax, eax
    mov ecx, 8
    rep stosq
    mov rax, 0x3130305143535248 /* HRSCQ001 */
    mov [rbp], rax
    mov qword ptr [rbp + 8], 3
    mov rax, [rsp + 24]
    mov [rbp + 16], rax
    mov rax, [rsp + 32]
    mov [rbp + 24], rax
    mov rcx, [rsp + 8]
    sub rcx, 32
    mov [rbp + 48], rcx
    lea rdi, [rbp + 64]
    mov rsi, [rsp]
    add rsi, 32
    rep movsb
    mov r15, [r14 + 16]
    test r15, r15
    jz rtbh_hint_invalid
    mov r13, [r15 + 8]
    add r13, 6*64
    mov rax, [r13 + 32]
    cmp rax, 64
    jb rtbh_hint_invalid
    mov [rsp + 40], rax
    mov qword ptr [r13 + 32], 64
    mov rdi, rbp
    mov rsi, [rsp + 8]
    add rsi, 32
    mov edx, 6
    call view_scope_invoke
    mov rdx, [rsp + 40]
    mov [r13 + 32], rdx
    cmp rax, 64
    jne rtbh_hint_invalid
    mov rdx, [r13 + 24]
    mov rax, 0x3130305243535248 /* HRSCR001 */
    cmp [rdx], rax
    jne rtbh_hint_invalid
    mov rax, [rsp + 24]
    cmp [rdx + 8], rax
    jne rtbh_hint_invalid
    mov rax, [rsp + 32]
    cmp [rdx + 16], rax
    jne rtbh_hint_invalid
    cmp qword ptr [rdx + 24], 1
    jne rtbh_hint_invalid
    mov rax, [rdx + 32]
    or rax, [rdx + 56]
    jnz rtbh_hint_invalid
    mov rax, [rbx + 96]
    cmp [rdx + 40], rax
    jne rtbh_hint_invalid
    mov rax, [rbx + 128]
    cmp [rdx + 48], rax
    jne rtbh_hint_invalid
    mov rcx, [rsp + 16]
    lea rax, [rip + rtbh_hint_reply]
    mov [rcx], rax
    mov qword ptr [rcx + 8], 32
    mov eax, 32
    jmp rtbh_hint_done
rtbh_hint_resource:
    mov eax, 0xfffffffc
    jmp rtbh_hint_done
rtbh_hint_invalid:
    mov eax, 0xffffffff
rtbh_hint_done:
    add rsp, 72
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

runtime_text_body_release:
    push rbx
    mov rbx, [r15 + 408]
    test rbx, rbx
    jz rtbh_release_success
    cmp qword ptr [rbx + 152], 0
    je rtbh_release_frame
    mov rdi, rbx
    call local_text_body_release
    test eax, eax
    jnz rtbh_release_done
rtbh_release_frame:
    mov rdi, [rbx + 256 + 184]
    test rdi, rdi
    jz rtbh_release_control
    mov rsi, [rbx + 256 + 192]
    add rsi, 4096
    mov eax, 11
    syscall
    test rax, rax
    jnz rtbh_release_done
    mov qword ptr [rbx + 256 + 184], 0
    mov qword ptr [rbx + 256 + 192], 0
rtbh_release_control:
    mov rdi, rbx
    mov esi, 8192
    mov eax, 11
    syscall
    test rax, rax
    jnz rtbh_release_done
    mov qword ptr [r15 + 408], 0
rtbh_release_success:
    xor eax, eax
rtbh_release_done:
    pop rbx
    ret
.balign 8
rtbh_hint_reply:
    .ascii "HLTBHP01"
    .zero 24
runtime_text_body_images:
    .zero 96
