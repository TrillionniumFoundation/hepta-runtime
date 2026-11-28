/* Private Linux x86-64 mutex and owned memory for the single process SSH registry.
 * The installed HIA entry owns every transition. There is no admission policy here.
 * invoke takes only a fixed HSSGRQ01 frame and serializes one HIA transition.
 * The controller retains the root lease until all borrowers and waiters are gone.
 * create/invoke/destroy are fixed private entries, never public JSON resources.
 */
.intel_syntax noprefix
.section .text
.global ssh_direct_registry_engine
ssh_direct_registry_engine:
    .byte 0xe9
    .long create - . - 4
    .byte 0xe9
    .long invoke - . - 4
    .byte 0xe9
    .long destroy - . - 4

.equ MAGIC, 0x3130584c47535348
.equ INVALID, 0xffffffff
.equ CAPACITY, 0xfffffffe
.equ RESOURCE, 0xfffffffc
.equ CONTRACT, 0xfffffff9
.equ GROW, 0xffffffd0
.equ ENTRY, 8
.equ WORK, 16
.equ CAP, 24
.equ LOCK, 32
.equ BORROWS, 36
.equ GENERATION, 40
.equ REQUEST, 128
.equ OUTPUT, 256

.macro ENTER
    cld
    push rbp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub rsp, 8
.endm
.macro LEAVE
    add rsp, 8
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret
.endm

/* create(installer_owned_hia_entry, nonzero_instance_generation) -> ctx or -errno */
create:
    ENTER
    test rdi, rdi
    jz create_bad
    test rsi, rsi
    jz create_bad
    mov r13, rdi
    mov r14, rsi
    mov esi, 4096
    call allocate
    test rax, rax
    js create_done
    mov r12, rax
    movabs rcx, MAGIC
    mov [r12], rcx
    mov [r12 + ENTRY], r13
    mov [r12 + GENERATION], r14
    mov esi, 4096
    call allocate
    test rax, rax
    js create_free_context
    mov [r12 + WORK], rax
    mov qword ptr [r12 + CAP], 4096
    movabs rax, 0x3130515247535348 /* HSSGRQ01 */
    mov [r12 + REQUEST], rax
    mov qword ptr [r12 + REQUEST + 8], 1
    mov [r12 + REQUEST + 16], r14
    call enter_hia
    cmp eax, 128
    jne create_free_work
    cmp qword ptr [r12 + OUTPUT + 8], 0
    jne create_free_work
    movabs rax, 0x3130525247535348 /* HSSGRR01 */
    cmp [r12 + OUTPUT], rax
    jne create_free_work
    cmp [r12 + OUTPUT + 16], r14
    jne create_free_work
    mov rax, r12
    jmp create_done
create_free_work:
    mov rdi, [r12 + WORK]
    mov rsi, [r12 + CAP]
    mov eax, 11
    syscall
    mov rax, -22
create_free_context:
    mov rbx, rax
    mov rdi, r12
    mov esi, 4096
    mov eax, 11
    syscall
    mov rax, rbx
    jmp create_done
create_bad:
    mov rax, -22
create_done:
    LEAVE

/* invoke(ctx, captured_request, exact_96, output, output_capacity)
 * Caller must retain its actual context lease throughout this synchronous call.
 */
invoke:
    ENTER
    mov ebx, INVALID
    test rdi, rdi
    jz invoke_done
    mov r12, rdi
    movabs rax, MAGIC
    cmp [r12], rax
    jne invoke_done
    test rsi, rsi
    jz invoke_done
    test rcx, rcx
    jz invoke_done
    cmp rdx, 96
    jne invoke_done
    mov ebx, CAPACITY
    cmp r8, 128
    jb invoke_done
    mov ebx, INVALID
    mov r13, rsi
    mov r14, rcx
    /* No pointer may alias the registry control page, or each other. */
    mov rdi, r13
    mov esi, 96
    mov rdx, r12
    mov ecx, 4096
    call disjoint
    test eax, eax
    jz invoke_done
    mov rdi, r14
    mov esi, 128
    mov rdx, r12
    mov ecx, 4096
    call disjoint
    test eax, eax
    jz invoke_done
    mov rdi, r13
    mov esi, 96
    mov rdx, r14
    mov ecx, 128
    call disjoint
    test eax, eax
    jz invoke_done
    lock inc dword ptr [r12 + BORROWS]
    call acquire
    test rax, rax
    js invoke_lock_failed
    /* The workspace pointer and extent are read only under this mutex. */
    mov rdi, r13
    mov esi, 96
    mov rdx, [r12 + WORK]
    mov rcx, [r12 + CAP]
    call disjoint
    test eax, eax
    jz invoke_unlock
    mov rdi, r14
    mov esi, 128
    mov rdx, [r12 + WORK]
    mov rcx, [r12 + CAP]
    call disjoint
    test eax, eax
    jz invoke_unlock
    lea rdi, [r12 + REQUEST]
    mov rsi, r13
    mov ecx, 12
    rep movsq
invoke_call:
    call enter_hia
    mov ebx, eax
    cmp eax, GROW
    jne invoke_terminal
    movabs rax, 0x3230305357524748 /* HGRWS002 */
    cmp [r12 + OUTPUT], rax
    jne invoke_contract
    cmp qword ptr [r12 + OUTPUT + 8], 1
    jne invoke_contract
    cmp qword ptr [r12 + OUTPUT + 24], 0
    jne invoke_contract
    mov r15, [r12 + OUTPUT + 16]
    cmp r15, [r12 + CAP]
    jbe invoke_contract
    mov rax, r15
    add rax, 4095
    jc invoke_resource
    shr rax, 47
    jnz invoke_resource
    mov rsi, r15
    call allocate
    test rax, rax
    js invoke_resource
    mov rbp, rax
    mov rdi, rbp
    mov rsi, [r12 + WORK]
    mov rcx, [r12 + CAP]
    rep movsb
    mov rdi, [r12 + WORK]
    mov rsi, [r12 + CAP]
    mov eax, 11
    syscall
    test rax, rax
    js invoke_free_new
    mov [r12 + WORK], rbp
    mov [r12 + CAP], r15
    jmp invoke_call
invoke_free_new:
    mov rdi, rbp
    mov rsi, r15
    mov eax, 11
    syscall
invoke_resource:
    mov ebx, RESOURCE
    jmp invoke_terminal
invoke_contract:
    mov ebx, CONTRACT
invoke_terminal:
    /* A changed supplied request never gets a successful completion. The HIA
       state already ran only the captured copy; observed mutation is sticky. */
    lea rsi, [r12 + REQUEST]
    mov rdi, r13
    mov ecx, 96
    repe cmpsb
    jne invoke_changed
    cmp ebx, 128
    jne invoke_unlock
    movabs rax, 0x3130525247535348
    cmp [r12 + OUTPUT], rax
    jne invoke_bad_frame
    mov rax, [r12 + GENERATION]
    cmp [r12 + OUTPUT + 16], rax
    jne invoke_bad_frame
    lea rsi, [r12 + OUTPUT]
    mov rdi, r14
    mov ecx, 16
    rep movsq
    jmp invoke_unlock
invoke_bad_frame:
    mov ebx, CONTRACT
    jmp invoke_unlock
invoke_changed:
    lea rdi, [r12 + REQUEST]
    xor eax, eax
    mov ecx, 12
    rep stosq
    movabs rax, 0x3130515247535348
    mov [r12 + REQUEST], rax
    mov qword ptr [r12 + REQUEST + 8], 14
    mov rax, [r12 + GENERATION]
    mov [r12 + REQUEST + 16], rax
    mov qword ptr [r12 + REQUEST + 48], 11
    call enter_hia
    mov ebx, CONTRACT
invoke_unlock:
    call release
    lock dec dword ptr [r12 + BORROWS]
    jmp invoke_done
invoke_lock_failed:
    lock dec dword ptr [r12 + BORROWS]
    mov ebx, RESOURCE
invoke_done:
    mov eax, ebx
    LEAVE

/* destroy only after all external leases were joined, and HIA clean frozen
 * shutdown. Failed/quarantined owners remain addressable for reconciliation.
 */
destroy:
    ENTER
    mov rbx, -22
    test rdi, rdi
    jz destroy_done
    mov r12, rdi
    movabs rax, MAGIC
    cmp [r12], rax
    jne destroy_done
    lock inc dword ptr [r12 + BORROWS]
    call acquire
    test rax, rax
    js destroy_lock_failed
    mov rbx, -16
    cmp dword ptr [r12 + BORROWS], 1
    jne destroy_unlock
    lea rdi, [r12 + REQUEST]
    xor eax, eax
    mov ecx, 12
    rep stosq
    movabs rax, 0x3130515247535348
    mov [r12 + REQUEST], rax
    mov qword ptr [r12 + REQUEST + 8], 15
    mov rax, [r12 + GENERATION]
    mov [r12 + REQUEST + 16], rax
    call enter_hia
    cmp eax, 128
    jne destroy_unlock
    cmp qword ptr [r12 + OUTPUT + 120], 1
    jne destroy_unlock
    mov rdi, [r12 + WORK]
    mov rsi, [r12 + CAP]
    mov eax, 11
    syscall
    test rax, rax
    js destroy_unmap_failed
    mov qword ptr [r12], 0
    mov rdi, r12
    mov esi, 4096
    mov eax, 11
    syscall
    mov rbx, rax
    jmp destroy_done
destroy_unmap_failed:
    mov rbx, rax
destroy_unlock:
    call release
    lock dec dword ptr [r12 + BORROWS]
    jmp destroy_done
destroy_lock_failed:
    lock dec dword ptr [r12 + BORROWS]
    mov rbx, rax
destroy_done:
    mov rax, rbx
    LEAVE

/* Internal leaves. No cross-module relocation and no libc imports. */
enter_hia:
    lea rdi, [r12 + REQUEST]
    mov esi, 96
    lea rdx, [r12 + OUTPUT]
    mov ecx, 128
    mov r8, [r12 + WORK]
    mov r9, [r12 + CAP]
    jmp qword ptr [r12 + ENTRY]
allocate:
    xor edi, edi
    mov edx, 3
    mov r10d, 0x22
    mov r8, -1
    xor r9d, r9d
    mov eax, 9
    syscall
    ret
disjoint:
    mov rax, rdi
    add rax, rsi
    jc disjoint_no
    mov r8, rdx
    add r8, rcx
    jc disjoint_no
    cmp rax, rdx
    jbe disjoint_yes
    cmp r8, rdi
    jbe disjoint_yes
disjoint_no:
    xor eax, eax
    ret
disjoint_yes:
    mov eax, 1
    ret
acquire:
    mov eax, 1
    xchg eax, dword ptr [r12 + LOCK]
    test eax, eax
    jz acquire_ok
    lea rdi, [r12 + LOCK]
    mov esi, 128 /* FUTEX_WAIT_PRIVATE */
    mov edx, 1
    xor r10d, r10d
    xor r8d, r8d
    xor r9d, r9d
    mov eax, 202
    syscall
    test rax, rax
    jz acquire
    cmp rax, -4
    je acquire
    cmp rax, -11
    je acquire
    ret
acquire_ok:
    xor eax, eax
    ret
release:
    mov dword ptr [r12 + LOCK], 0
    lea rdi, [r12 + LOCK]
    mov esi, 129 /* FUTEX_WAKE_PRIVATE */
    mov edx, 1
    mov eax, 202
    syscall
    ret
