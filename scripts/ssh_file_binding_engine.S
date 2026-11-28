/* Private file-read binding between the one instance HIA registry and the
 * already qualified direct-SSH descriptor engine. Only the original unit
 * final-entry profile for foreground file reads is implemented here.
 * Job effects require a separate typed entry capability and cannot use it.
 * All lifecycle decisions remain HIA transitions; this forwards real results.
 * No public frame supplies these private function pointers, fd, PID or lease.
 */
.intel_syntax noprefix
.section .text
.global ssh_file_binding_engine
ssh_file_binding_engine:
    .byte 0xe9
    .long create - . - 4
    .byte 0xe9
    .long step - . - 4
    .byte 0xe9
    .long notify - . - 4
    .byte 0xe9
    .long rebind - . - 4
    .byte 0xe9
    .long finish - . - 4
    .byte 0xe9
    .long destroy - . - 4

.equ MAGIC, 0x3130544342535348 /* HSSBCT01 */
.equ TABLE, 0x3130444e42535348 /* HSSBND01 */
.equ REGBASE, 8
.equ REGCTX, 16
.equ CAPBASE, 24
.equ CAPCTX, 32
.equ TOKEN, 40
.equ GENERATION, 48
.equ BUSY, 56
.equ BROKEN, 60
.equ SEQUENCE, 64
.equ DEADLINE, 80
.equ FLAGS, 96
.equ UNCERTAIN, 104
.equ FINISHED, 112
.equ REAP_RECORDED, 120
.equ CONTRACT, 0xfffffff9
.equ WAITING, 2

.macro ENTER
    cld
    push rbp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub rsp, 280
    mov r13, rsp
.endm
.macro LEAVE
    add rsp, 280
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret
.endm

/* create(installed_private_table64, fresh_transport_context)
 * table: HSSBND01,version1,registry_code,registry_ctx,transport_code,
 * generation,foreground_unit_entry_profile1,zero.
 * The same registry must already contain this request's exact queued token.
 */
create:
    ENTER
    mov rbx, -22
    test rdi, rdi
    jz create_done
    test rsi, rsi
    jz create_done
    mov r15, rdi
    mov r14, rsi
    mov rax, rdi
    add rax, 64
    jc create_done
    lea rdi, [r13]
    mov rsi, r15
    mov ecx, 8
    rep movsq
    movabs rax, TABLE
    cmp [r13], rax
    jne create_done
    cmp qword ptr [r13 + 8], 1
    jne create_done
    cmp qword ptr [r13 + 48], 1
    jne create_done
    cmp qword ptr [r13 + 56], 0
    jne create_done
    cmp qword ptr [r13 + 16], 0
    je create_done
    cmp qword ptr [r13 + 24], 0
    je create_done
    cmp qword ptr [r13 + 32], 0
    je create_done
    cmp qword ptr [r13 + 40], 0
    je create_done
    movabs rax, 0x3130544348535348 /* HSSHCT01 */
    cmp [r14], rax
    jne create_done
    cmp qword ptr [r14 + 456], 1
    jne create_done
    cmp qword ptr [r14 + 40], 0
    jne create_done
    cmp qword ptr [r14 + 48], 0
    jne create_done
    cmp qword ptr [r14 + 64], 0
    jne create_done
    cmp qword ptr [r14 + 472], 0
    jne create_done
    cmp qword ptr [r14 + 488], 0
    jne create_done
    mov rdx, [r14 + 8]
    test rdx, rdx
    jz create_done
    cmp qword ptr [rdx + 8], 1
    jne create_done
    cmp qword ptr [rdx + 16], 1
    jne create_done
    mov rax, [r13 + 40]
    cmp [rdx + 184], rax
    jne create_done
    cmp [r14 + 448], rax
    jne create_done
    mov rax, [rdx + 24]
    test rax, rax
    jz create_done
    cmp [r14 + 56], rax
    jne create_done
    /* The owner already captured and admitted the complete file plan. */
    mov rcx, [rdx + 1024]
    cmp rcx, [r14 + 16]
    jae create_done
    mov rax, [r14 + 16]
    sub rax, rcx
    cmp rax, 128
    jb create_done
    add rcx, rdx
    movabs rax, 0x3330504853424648 /* HFBSHP03 */
    cmp [rcx], rax
    jne create_done
    cmp qword ptr [rcx + 16], 1
    jb create_done
    cmp qword ptr [rcx + 16], 2
    ja create_done
    mov esi, 4096
    call allocate
    test rax, rax
    js create_sys_error
    mov r12, rax
    movabs rcx, MAGIC
    mov [r12], rcx
    mov rax, [r13 + 16]
    mov [r12 + REGBASE], rax
    mov rax, [r13 + 24]
    mov [r12 + REGCTX], rax
    mov rax, [r13 + 32]
    mov [r12 + CAPBASE], rax
    mov [r12 + CAPCTX], r14
    mov rdx, [r14 + 8]
    mov rax, [rdx + 24]
    mov [r12 + TOKEN], rax
    mov rax, [rdx + 184]
    mov [r12 + GENERATION], rax
    mov rax, [rdx + 32]
    mov [r12 + DEADLINE], rax
    /* Compare the supplied installation table before any HIA mutation. */
    mov rsi, r13
    mov rdi, r15
    mov ecx, 64
    repe cmpsb
    jne create_free
    mov edi, 15
    xor esi, esi
    xor edx, edx
    xor ecx, ecx
    call registry
    test eax, eax
    jnz create_free
    cmp qword ptr [r13 + 128 + 32], 1
    jne create_free
    mov rax, [r12 + DEADLINE]
    cmp [r13 + 128 + 48], rax
    jne create_free
    cmp qword ptr [r13 + 128 + 72], 0
    jne create_free
    cmp qword ptr [r13 + 128 + 80], 0
    jne create_free
    cmp qword ptr [r13 + 128 + 88], 0
    jne create_free
    /* HIA one-time binding prevents two transport owners claiming a token. */
    mov edi, 17
    xor esi, esi
    xor edx, edx
    xor ecx, ecx
    call registry
    test eax, eax
    jnz create_free
    mov rbx, r12
    jmp create_done
create_free:
    mov rdi, r12
    mov esi, 4096
    mov eax, 11
    syscall
    mov rbx, -22
    jmp create_done
create_sys_error:
    mov rbx, rax
create_done:
    mov rax, rbx
    LEAVE

/* step: 0 exact physical completion; 2 known registry serialization wait.
 * Waiting never acknowledges the owner or repeats an unknown syscall.
 */
step:
    ENTER
    mov r12, rdi
    call check
    test eax, eax
    jz step_bad
    mov eax, 1
    xchg eax, dword ptr [r12 + BUSY]
    test eax, eax
    jnz step_busy
    cmp dword ptr [r12 + BROKEN], 0
    jne step_broken
    cmp qword ptr [r12 + FINISHED], 0
    jne step_bad_unlock
    mov r14, [r12 + CAPCTX]
    mov rbp, [r14 + 8]
    mov rax, [rbp + 16]
    mov rcx, [r12 + SEQUENCE]
    inc rcx
    jz step_bad_unlock
    cmp rax, rcx
    jne step_bad_unlock
    mov r15, [rbp + 256 + 16]
    /* Observe the same global instance before performing the next effect. */
    mov edi, 15
    xor esi, esi
    xor edx, edx
    xor ecx, ecx
    call registry
    test eax, eax
    jnz step_fail
    xor ebx, ebx
    cmp qword ptr [r13 + 128 + 56], 0
    je step_check_frozen
    or ebx, 1
step_check_frozen:
    cmp qword ptr [r13 + 128 + 64], 0
    je step_notify
    or ebx, 2
step_notify:
    mov rax, [r12 + FLAGS]
    not rax
    and rbx, rax
    jz step_dispatch
    mov rdi, r14
    mov rsi, rbx
    mov rax, [r12 + CAPBASE]
    add rax, 15
    call rax
    test rax, rax
    jnz step_fail
    or [r12 + FLAGS], rbx
step_dispatch:
    cmp r15, 2
    je step_commit
    cmp r15, 13
    je step_release
    mov rdi, r14
    mov rax, [r12 + CAPBASE]
    add rax, 5
    call rax
    test rax, rax
    jnz step_fail
    cmp r15, 3
    je step_spawn_observed
    cmp r15, 8
    je step_wait_observed
    jmp step_success
step_commit:
    call clock
    test rax, rax
    js step_fail
    mov rsi, rax
    mov edi, 3
    xor edx, edx
    xor ecx, ecx
    call registry
    cmp eax, 2
    je step_waiting
    cmp eax, 1
    je step_commit_refused
    test eax, eax
    jnz step_fail
    /* Original foreground run_capture_until has an infallible unit entry. */
    mov edi, 4
    xor esi, esi
    mov edx, 1
    xor ecx, ecx
    call registry
    test eax, eax
    jnz step_fail
    mov rdi, r14
    mov rax, [r12 + CAPBASE]
    add rax, 5
    call rax
    cmp eax, 1
    jne step_fail
    mov rdi, r14
    mov esi, 1
    xor edx, edx
    xor ecx, ecx
    mov rax, [r12 + CAPBASE]
    add rax, 10
    call rax
    test eax, eax
    jnz step_fail
    jmp step_success
step_commit_refused:
    mov rdi, r14
    mov rax, [r12 + CAPBASE]
    add rax, 5
    call rax
    cmp eax, 1
    jne step_fail
    mov rdi, r14
    xor esi, esi
    mov edx, 125 /* known ECANCELED admission, no child */
    xor ecx, ecx
    mov rax, [r12 + CAPBASE]
    add rax, 10
    call rax
    test eax, eax
    jnz step_fail
    jmp step_success
step_spawn_observed:
    mov edi, 5
    xor esi, esi
    mov rcx, [r14 + 272] /* actual errno, not caller data */
    test rcx, rcx
    jnz step_spawn_failed
    mov rdx, [r14 + 64] /* exact original child PID */
    cmp rdx, [r14 + 280]
    jne step_fail
    call registry
    test eax, eax
    jnz step_fail
    jmp step_success
step_spawn_failed:
    xor edx, edx
    call registry
    cmp eax, 1
    jne step_fail
    jmp step_success
step_wait_observed:
    cmp qword ptr [r14 + 152], 0 /* actual wait uncertainty */
    jne step_quarantine
    cmp qword ptr [r14 + 264], 0
    je step_success
    cmp qword ptr [r14 + 264], 1
    jne step_fail
    cmp qword ptr [r12 + REAP_RECORDED], 1
    je step_success
    mov edi, 6
    xor esi, esi
    mov rdx, [r14 + 280]
    xor ecx, ecx
    call registry
    test eax, eax
    jnz step_fail
    mov qword ptr [r12 + REAP_RECORDED], 1
    jmp step_success
step_quarantine:
    cmp qword ptr [r12 + UNCERTAIN], 1
    je step_success
    mov edi, 9
    xor esi, esi
    mov edx, 6
    xor ecx, ecx
    call registry
    cmp eax, 3
    jne step_fail
    mov qword ptr [r12 + UNCERTAIN], 1
    jmp step_success
step_release:
    mov edi, 10
    xor esi, esi
    xor edx, edx
    xor ecx, ecx
    call registry
    cmp eax, 2
    je step_waiting
    test eax, eax
    jnz step_fail
    mov rdi, r14
    mov rax, [r12 + CAPBASE]
    add rax, 5
    call rax
    cmp eax, 1
    jne step_fail
    /* Drop the original unit entry only after the HIA admitted known reap. */
    mov edi, 11
    xor esi, esi
    xor edx, edx
    xor ecx, ecx
    call registry
    test eax, eax
    jnz step_fail
    mov rdi, r14
    xor esi, esi
    xor edx, edx
    xor ecx, ecx
    mov rax, [r12 + CAPBASE]
    add rax, 10
    call rax
    test eax, eax
    jnz step_fail
step_success:
    mov rax, [rbp + 16]
    mov [r12 + SEQUENCE], rax
    xor ebx, ebx
    jmp step_unlock
step_waiting:
    mov ebx, WAITING
    jmp step_unlock
step_fail:
    call mark_broken
step_broken:
    mov ebx, CONTRACT
    jmp step_unlock
step_bad_unlock:
    mov ebx, CONTRACT
step_unlock:
    mov dword ptr [r12 + BUSY], 0
    mov eax, ebx
    jmp step_done
step_busy:
    mov rax, -16
    jmp step_done
step_bad:
    mov eax, CONTRACT
step_done:
    LEAVE

/* notify records cancellation/freeze in the shared HIA instance before waking
 * the actual child owner. Caller loss never releases an entry or child lease.
 */
notify:
    ENTER
    mov r12, rdi
    mov r14, rsi
    call check
    test eax, eax
    jz notify_bad
    test r14, r14
    jz notify_bad
    cmp r14, 3
    ja notify_bad
    test r14, 1
    jz notify_freeze
    mov edi, 7
    xor esi, esi
    xor edx, edx
    xor ecx, ecx
    call registry
    test eax, eax
    jnz notify_bad
notify_freeze:
    test r14, 2
    jz notify_cap
    mov edi, 8
    xor esi, esi
    xor edx, edx
    xor ecx, ecx
    call registry
    test eax, eax
    jnz notify_bad
notify_cap:
    mov rdi, [r12 + CAPCTX]
    mov rsi, r14
    mov rax, [r12 + CAPBASE]
    add rax, 15
    call rax
    jmp notify_done
notify_bad:
    mov rax, -22
notify_done:
    LEAVE

/* rebind forwards the original byte-for-byte growth check under owner exclusion. */
rebind:
    ENTER
    mov r12, rdi
    mov r14, rsi
    mov r15, rdx
    call check
    test eax, eax
    jz rebind_bad
    mov eax, 1
    xchg eax, dword ptr [r12 + BUSY]
    test eax, eax
    jnz rebind_busy
    mov rdi, [r12 + CAPCTX]
    mov rsi, r14
    mov rdx, r15
    mov rax, [r12 + CAPBASE]
    add rax, 20
    call rax
    mov dword ptr [r12 + BUSY], 0
    jmp rebind_done
rebind_bad:
    mov rax, -22
    jmp rebind_done
rebind_busy:
    mov rax, -16
rebind_done:
    LEAVE

/* finish only after the actual HIA owner emitted its terminal HSSHRR01.
 * A pre-entry terminal has no child or lease. A quarantined owner is retained.
 */
finish:
    ENTER
    mov r12, rdi
    call check
    test eax, eax
    jz finish_bad
    mov eax, 1
    xchg eax, dword ptr [r12 + BUSY]
    test eax, eax
    jnz finish_busy
    cmp dword ptr [r12 + BROKEN], 0
    jne finish_hold
    cmp qword ptr [r12 + FINISHED], 0
    jne finish_hold
    cmp qword ptr [r12 + UNCERTAIN], 0
    jne finish_hold
    mov r14, [r12 + CAPCTX]
    mov rbp, [r14 + 8]
    cmp qword ptr [rbp + 8], 27
    jne finish_hold
    mov edi, 15
    xor esi, esi
    xor edx, edx
    xor ecx, ecx
    call registry
    test eax, eax
    jnz finish_hold
    cmp qword ptr [r13 + 128 + 32], 7
    je finish_detach
    cmp qword ptr [r13 + 128 + 32], 1
    jne finish_hold
    cmp qword ptr [rbp + 224], 0
    jne finish_hold
    cmp qword ptr [rbp + 168], 0
    jne finish_hold
    mov rdx, [rbp + 144]
    test rdx, rdx
    jz finish_hold
    mov edi, 18
    xor esi, esi
    xor ecx, ecx
    call registry
    test eax, eax
    jnz finish_hold
finish_detach:
    mov edi, 13
    xor esi, esi
    xor edx, edx
    xor ecx, ecx
    call registry
    test eax, eax
    jnz finish_hold
    mov qword ptr [r12 + FINISHED], 1
    xor ebx, ebx
    jmp finish_unlock
finish_hold:
    mov rbx, -16
finish_unlock:
    mov dword ptr [r12 + BUSY], 0
    mov rax, rbx
    jmp finish_done
finish_bad:
    mov rax, -22
    jmp finish_done
finish_busy:
    mov rax, -16
finish_done:
    LEAVE

/* destroy never abandons a live or uncertain transport. All outer borrows must
 * have been joined by the same root owner before this final call.
 */
destroy:
    ENTER
    mov r12, rdi
    call check
    test eax, eax
    jz destroy_bad
    mov eax, 1
    xchg eax, dword ptr [r12 + BUSY]
    test eax, eax
    jnz destroy_busy
    cmp qword ptr [r12 + FINISHED], 1
    jne destroy_hold
    cmp dword ptr [r12 + BROKEN], 0
    jne destroy_hold
    mov rdi, [r12 + CAPCTX]
    mov rax, [r12 + CAPBASE]
    add rax, 25
    call rax
    test rax, rax
    jnz destroy_unlock
    mov qword ptr [r12], 0
    mov rdi, r12
    mov esi, 4096
    mov eax, 11
    syscall
    jmp destroy_done
destroy_hold:
    mov rax, -16
destroy_unlock:
    mov dword ptr [r12 + BUSY], 0
    jmp destroy_done
destroy_bad:
    mov rax, -22
    jmp destroy_done
destroy_busy:
    mov rax, -16
destroy_done:
    LEAVE

/* registry(op,now,x,y) returns the HIA status and retains the complete actual
 * response in this invocation's private stack. No notify/step shared scratch.
 */
registry:
    mov [r13 + 8], rdi
    mov [r13 + 32], rsi
    mov [r13 + 48], rdx
    mov [r13 + 56], rcx
    movabs rax, 0x3130515247535348 /* HSSGRQ01 */
    mov [r13], rax
    mov rax, [r12 + GENERATION]
    mov [r13 + 16], rax
    mov rax, [r12 + TOKEN]
    cmp edi, 8
    je registry_global
    cmp edi, 12
    je registry_global
    cmp edi, 14
    jne registry_token
registry_global:
    xor eax, eax
registry_token:
    mov [r13 + 24], rax
    mov qword ptr [r13 + 40], 0
    mov qword ptr [r13 + 64], 0
    mov qword ptr [r13 + 72], 0
    mov qword ptr [r13 + 80], 0
    mov qword ptr [r13 + 88], 0
    mov rdi, [r12 + REGCTX]
    mov rsi, r13
    mov edx, 96
    lea rcx, [r13 + 128]
    mov r8d, 128
    mov rax, [r12 + REGBASE]
    add rax, 5
    sub rsp, 8
    call rax
    add rsp, 8
    cmp eax, 128
    jne registry_contract
    movabs rax, 0x3130525247535348
    cmp [r13 + 128], rax
    jne registry_contract
    mov rax, [r12 + GENERATION]
    cmp [r13 + 128 + 16], rax
    jne registry_contract
    mov rax, [r13 + 24]
    cmp [r13 + 128 + 24], rax
    jne registry_contract
    mov rax, [r13 + 128 + 8]
    cmp rax, 3
    ja registry_contract
    ret
registry_contract:
    mov eax, CONTRACT
    ret
mark_broken:
    mov dword ptr [r12 + BROKEN], 1
    mov edi, 14
    xor esi, esi
    mov edx, 12
    xor ecx, ecx
    jmp registry
check:
    xor eax, eax
    test r12, r12
    jz check_done
    movabs rcx, MAGIC
    cmp [r12], rcx
    jne check_done
    mov rdx, [r12 + CAPCTX]
    test rdx, rdx
    jz check_done
    movabs rcx, 0x3130544348535348
    cmp [rdx], rcx
    jne check_done
    mov rcx, [r12 + TOKEN]
    cmp [rdx + 56], rcx
    jne check_done
    mov rcx, [r12 + GENERATION]
    cmp [rdx + 448], rcx
    jne check_done
    mov eax, 1
check_done:
    ret
clock:
    mov edi, 1
    lea rsi, [r13 + 256]
    mov eax, 228
    syscall
    test rax, rax
    js clock_done
    mov rax, [r13 + 256]
    mov ecx, 1000000000
    mul rcx
    test rdx, rdx
    jnz clock_overflow
    add rax, [r13 + 264]
    jc clock_overflow
clock_done:
    ret
clock_overflow:
    mov rax, -75
    ret
allocate:
    xor edi, edi
    mov edx, 3
    mov r10d, 0x22
    mov r8, -1
    xor r9d, r9d
    mov eax, 9
    syscall
    ret
