/* Fixed private Bellman port. HIA caller/decoders and the exact packed worker
 * own all typed, numerical, commitment, error and permit decisions. This file
 * owns mappings, immutable call turns, exact FIFO copies and private tags. */
.intel_syntax noprefix
.section .text
.equ BP_INVALID, 0xffffffff
.equ BP_RESOURCE, 0xfffffffc
.equ BP_BUSY, 0xfffffff8
.equ BP_CALL, 0xfffffff0
.equ BP_GROW, 0xffffffd0
.equ BP_DELIVERY, 0xffffffcd
.equ BP_SLOT, 57
.equ BP_CTX_BYTES, 4096
.equ BP_ROW_BYTES, 4096
.equ BC_WORKER, 8
.equ BC_PID, 16
.equ BC_TAG, 24
.equ BC_PHASE, 32
.equ BC_LOCK, 40
.equ BC_ROWS, 48
.equ BC_ROW_COUNT, 56
.equ BC_READY_HEAD, 64
.equ BC_READY_TAIL, 72
.equ BC_WAKE_FD, 80
.equ BC_JOURNAL_FD, 88
.equ BC_ENGINES, 96
.equ BC_TOKEN, 104
.equ BC_BORROW, 112
.equ BC_RECEIVE, 128
.equ BC_OUTPUT, 192
.equ BR_NEXT, 8
.equ BR_ENGINE, 16
.equ BR_TAG, 24
.equ BR_STATE, 32
.equ BR_STATUS, 40
.equ BR_INPUT, 48
.equ BR_INPUT_CAP, 56
.equ BR_INPUT_LEN, 64
.equ BR_WORK, 72
.equ BR_WORK_CAP, 80
.equ BR_OUTPUT, 88
.equ BR_OUTPUT_CAP, 96
.equ BR_SEQUENCE, 104
.equ BR_TARGET, 112
.equ BR_CHILD_INPUT, 120
.equ BR_CHILD_INPUT_LEN, 128
.equ BR_REPLY, 136
.equ BR_REPLY_LEN, 144
.equ BR_CHILD_WORK, 152
.equ BR_CHILD_WORK_CAP, 160
.equ BR_CHILD_OUTPUT, 168
.equ BR_CHILD_OUTPUT_CAP, 176

.macro BP_SAVE
    push rbp
    mov rbp,rsp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub rsp,200
    mov [rbp-48],rdi
    mov [rbp-56],rsi
    mov [rbp-64],rdx
    mov [rbp-72],rcx
    mov [rbp-80],r8
    mov [rbp-88],r9
.endm
.macro BP_RESTORE
    add rsp,200
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret
.endm
.macro BP_ENTER
    BP_SAVE
    mov r14,rdi
    call bp_enter
    test rax,rax
    jnz bp_return
.endm
.macro BP_NO_BORROW
    cmp qword ptr [r14+BC_BORROW],0
    jne bp_locked_invalid
.endm
.macro BP_WORKER name
    mov rdi,[r14+BC_WORKER]
    lea rax,[rip+runtime_bellman_worker_image+BWX_\name]
    call rax
.endm

/* Allocate and zero anonymous storage. The caller checks syscall failures. */
bp_map:
    mov rsi,rdi
    xor edi,edi
    mov edx,3
    mov r10d,0x22
    mov r8,-1
    xor r9d,r9d
    mov eax,9
    syscall
    ret
bp_unmap:
    test rdi,rdi
    jz bp_unmap_empty
    mov eax,11
    syscall
    test rax,rax
    jnz bp_fatal
bp_unmap_empty:
    xor eax,eax
    ret
bp_fatal:
    /* Runtime failure is not a Rust business refusal. Actual worker parent-
     * death ownership handles process teardown; no caller cancellation kills. */
    mov edi,70
    mov eax,231
    syscall
    ud2
bp_enter:
    test r14,r14
    jz bp_enter_invalid
    mov rax,0x3130544350425248 /* HRBPCT01 */
    cmp [r14],rax
    jne bp_enter_invalid
    mov eax,39
    syscall
    cmp rax,[r14+BC_PID]
    jne bp_enter_invalid
    xor eax,eax
    mov ecx,1
    lock cmpxchg [r14+BC_LOCK],rcx
    jnz bp_enter_busy
    xor eax,eax
    ret
bp_enter_busy:
    mov eax,0xfffffff9
    ret
bp_enter_invalid:
    mov eax,BP_INVALID
    ret
bp_locked_invalid:
    mov eax,BP_INVALID
    jmp bp_unlock_return
bp_locked_busy:
    mov eax,BP_BUSY
bp_unlock_return:
    mov qword ptr [r14+BC_LOCK],0
bp_return:
    BP_RESTORE

.global runtime_bellman_create
runtime_bellman_create:
    BP_SAVE
    cmp rdi,2
    jb bp_create_invalid
    mov edi,BP_CTX_BYTES
    call bp_map
    cmp rax,-4095
    jae bp_create_resource
    mov r14,rax
    mov rax,0x3130544350425248
    mov [r14],rax
    mov rdi,[rbp-48]
    mov [r14+BC_JOURNAL_FD],rdi
    lea rax,[rip+runtime_bellman_worker_image+BWX_init]
    call rax
    mov edx,0xffffffff
    cmp rax,rdx
    je bp_create_worker_invalid
    test rax,rax
    jz bp_fatal
    mov [r14+BC_WORKER],rax
    mov eax,39
    syscall
    mov [r14+BC_PID],rax
    mov qword ptr [r14+BC_PHASE],1
    BP_WORKER wake_fd
    cmp rax,0x7fffffff
    ja bp_fatal
    mov [r14+BC_WAKE_FD],rax
    mov rax,r14
    jmp bp_return
bp_create_worker_invalid:
    mov rdi,r14
    mov esi,BP_CTX_BYTES
    call bp_unmap
bp_create_invalid:
    mov eax,BP_INVALID
    jmp bp_return
bp_create_resource:
    mov eax,BP_RESOURCE
    jmp bp_return

.global runtime_bellman_attach
runtime_bellman_attach:
    BP_ENTER
    BP_NO_BORROW
    cmp qword ptr [r14+BC_PHASE],1
    jne bp_locked_invalid
    mov r15,[rbp-56]
    test r15,r15
    jz bp_locked_invalid
    mov rax,0x3230474e45475248 /* HRGENG02 */
    cmp [r15+40],rax
    jne bp_locked_invalid
    mov rax,[r15+440]
    or rax,[r15+448]
    jnz bp_locked_invalid
    cmp qword ptr [r14+BC_ENGINES],-1
    je bp_locked_busy
    mov [r15+440],r14
    mov qword ptr [r15+448],1
    inc qword ptr [r14+BC_ENGINES]
    xor eax,eax
    jmp bp_unlock_return

.global runtime_bellman_detach
runtime_bellman_detach:
    BP_ENTER
    BP_NO_BORROW
    mov r15,[rbp-56]
    cmp [r15+440],r14
    jne bp_locked_invalid
    cmp qword ptr [r15+448],1
    jne bp_locked_invalid
    mov rax,[r15+512+BP_SLOT*64]
    or rax,[r15+520+BP_SLOT*64]
    jnz bp_locked_busy
    mov rbx,[r14+BC_ROWS]
bp_detach_find:
    test rbx,rbx
    jz bp_detach_clear
    cmp [rbx+BR_ENGINE],r15
    je bp_locked_busy
    mov rbx,[rbx+BR_NEXT]
    jmp bp_detach_find
bp_detach_clear:
    cmp qword ptr [r14+BC_ENGINES],0
    je bp_fatal
    dec qword ptr [r14+BC_ENGINES]
    mov qword ptr [r15+440],0
    mov qword ptr [r15+448],0
    mov rdi,[r15+8]
    add rdi,BP_SLOT*64
    xor eax,eax
    mov ecx,8
    cld
    rep stosq
    jmp bp_unlock_return

/* r14 context, rdi expected caller row or zero for READY-only service.
 * Copy every complete event before releasing its exact worker borrow. */
bp_drain:
    push rbx
    push r12
    push r13
    sub rsp,16
    mov r12,rdi
    mov qword ptr [rsp],0
bp_drain_next:
    lea rsi,[r14+BC_RECEIVE]
    mov edx,32
    BP_WORKER receive
    test rax,rax
    jz bp_drain_done
    cmp rax,32
    jne bp_fatal
    mov rax,0x3130575242574248
    cmp [r14+BC_RECEIVE],rax
    jne bp_fatal
    mov r13,[r14+BC_RECEIVE+8]
    mov rbx,[r14+BC_RECEIVE+16]
    cmp rbx,192
    jb bp_fatal
    mov rax,0x313052534d504248
    cmp [r13],rax
    jne bp_fatal
    cmp [r13+8],rbx
    jne bp_fatal
    cmp qword ptr [r13+56],0
    jne bp_fatal
    mov rax,[r13+48]
    add rax,192
    jc bp_fatal
    cmp rax,rbx
    jne bp_fatal
    mov rsi,r13
    mov rdx,rbx
    call bp_trace_event
    cmp qword ptr [r13+16],2
    je bp_drain_ready
    cmp qword ptr [r13+16],1
    jne bp_fatal
    test r12,r12
    jz bp_fatal
    cmp qword ptr [rsp],0
    jne bp_fatal
    mov rax,[r12+BR_TAG]
    cmp [r13+24],rax
    jne bp_fatal
    mov rax,[r12+BR_CHILD_INPUT]
    cmp qword ptr [rax+8],1
    je bp_drain_submit_job
    mov rax,[rax+24]
    cmp [r13+32],rax
    jne bp_fatal
    jmp bp_drain_control_job_ready
bp_drain_submit_job:
    mov rax,[r13+32]
    mov [r12+184],rax
bp_drain_control_job_ready:
    cmp qword ptr [r12+BR_REPLY],0
    jne bp_fatal
    mov rdi,rbx
    call bp_map
    cmp rax,-4095
    jae bp_fatal
    mov [r12+BR_REPLY],rax
    mov [r12+BR_REPLY_LEN],rbx
    mov rdi,rax
    mov rsi,r13
    mov rcx,rbx
    cld
    rep movsb
    mov qword ptr [rsp],1
    jmp bp_drain_release
bp_drain_ready:
    cmp rbx,192
    jne bp_fatal
    mov edi,4096
    call bp_map
    cmp rax,-4095
    jae bp_fatal
    mov [rsp+8],rax
    mov qword ptr [rax+8],192
    lea rdi,[rax+32]
    mov rsi,r13
    mov ecx,192
    cld
    rep movsb
    mov rax,[rsp+8]
    mov rdx,[r14+BC_READY_TAIL]
    test rdx,rdx
    jz bp_drain_ready_first
    mov [rdx],rax
    jmp bp_drain_ready_tail
bp_drain_ready_first:
    mov [r14+BC_READY_HEAD],rax
bp_drain_ready_tail:
    mov [r14+BC_READY_TAIL],rax
bp_drain_release:
    mov rsi,[r14+BC_RECEIVE+24]
    BP_WORKER release
    test rax,rax
    jnz bp_fatal
    jmp bp_drain_next
bp_drain_done:
    test r12,r12
    jz bp_drain_return
    cmp qword ptr [rsp],1
    jne bp_fatal
bp_drain_return:
    xor eax,eax
    add rsp,16
    pop r13
    pop r12
    pop rbx
    ret

.global runtime_bellman_service
runtime_bellman_service:
    BP_ENTER
    BP_NO_BORROW
    BP_WORKER poll
    cmp rax,1
    ja bp_fatal
    xor edi,edi
    call bp_drain
    xor eax,eax
    cmp qword ptr [r14+BC_READY_HEAD],0
    setne al
    jmp bp_unlock_return

.global runtime_bellman_wake_fd
runtime_bellman_wake_fd:
    BP_ENTER
    mov rax,[r14+BC_WAKE_FD]
    jmp bp_unlock_return

.global runtime_bellman_ready_receive
runtime_bellman_ready_receive:
    BP_ENTER
    BP_NO_BORROW
    cmp qword ptr [rbp-64],32
    jb bp_receive_capacity
    mov rbx,[r14+BC_READY_HEAD]
    test rbx,rbx
    jz bp_receive_empty
    mov rax,[r14+BC_TOKEN]
    cmp rax,-1
    je bp_receive_capacity
    inc rax
    mov [r14+BC_TOKEN],rax
    mov [rbx+16],rax
    mov [r14+BC_BORROW],rbx
    mov rdi,[rbp-56]
    mov rdx,0x3130524250524248 /* HBRPBR01 */
    mov [rdi],rdx
    lea rdx,[rbx+32]
    mov [rdi+8],rdx
    mov rdx,[rbx+8]
    mov [rdi+16],rdx
    mov [rdi+24],rax
    mov eax,32
    jmp bp_unlock_return
bp_receive_empty:
    xor eax,eax
    jmp bp_unlock_return
bp_receive_capacity:
    mov eax,0xfffffffe
    jmp bp_unlock_return

.global runtime_bellman_ready_release
runtime_bellman_ready_release:
    BP_ENTER
    mov rbx,[r14+BC_BORROW]
    test rbx,rbx
    jz bp_locked_invalid
    cmp [r14+BC_READY_HEAD],rbx
    jne bp_fatal
    mov rax,[rbp-56]
    test rax,rax
    jz bp_locked_invalid
    cmp [rbx+16],rax
    jne bp_locked_invalid
    mov rax,[rbx]
    mov [r14+BC_READY_HEAD],rax
    test rax,rax
    jnz bp_ready_release_node
    mov qword ptr [r14+BC_READY_TAIL],0
bp_ready_release_node:
    mov qword ptr [r14+BC_BORROW],0
    mov rdi,rbx
    mov esi,4096
    call bp_unmap
    xor eax,eax
    jmp bp_unlock_return

.global runtime_bellman_shutdown
runtime_bellman_shutdown:
    BP_ENTER
    BP_NO_BORROW
    cmp qword ptr [r14+BC_PHASE],2
    je bp_shutdown_done
    cmp qword ptr [r14+BC_PHASE],1
    jne bp_locked_invalid
    BP_WORKER shutdown
    test rax,rax
    jnz bp_fatal
    mov qword ptr [r14+BC_PHASE],2
bp_shutdown_done:
    xor eax,eax
    jmp bp_unlock_return

.global runtime_bellman_destroy
runtime_bellman_destroy:
    BP_ENTER
    BP_NO_BORROW
    cmp qword ptr [r14+BC_PHASE],2
    jne bp_locked_busy
    mov rax,[r14+BC_ENGINES]
    or rax,[r14+BC_ROW_COUNT]
    or rax,[r14+BC_ROWS]
    or rax,[r14+BC_READY_HEAD]
    or rax,[r14+BC_READY_TAIL]
    jnz bp_locked_busy
    BP_WORKER destroy
    test rax,rax
    jnz bp_unlock_return
    mov rdi,r14
    mov esi,BP_CTX_BYTES
    call bp_unmap
    xor eax,eax
    jmp bp_return

/* rdi owned pointer/capacity pair; rsi required bytes; rdx preserve. */
bp_ensure_pair:
    cmp rsi,[rdi+8]
    jbe bp_ensure_done
    push rbx
    push r12
    push r13
    sub rsp,16
    mov rbx,rdi
    mov r12,rsi
    mov r13,rdx
    test r12,r12
    jz bp_fatal
    mov rdi,r12
    call bp_map
    cmp rax,-4095
    jae bp_fatal
    mov [rsp],rax
    test r13,r13
    jz bp_ensure_retire_old
    mov rdi,rax
    mov rsi,[rbx]
    mov rcx,[rbx+8]
    cld
    rep movsb
bp_ensure_retire_old:
    mov rdi,[rbx]
    mov rsi,[rbx+8]
    call bp_unmap
    mov rax,[rsp]
    mov [rbx],rax
    mov [rbx+8],r12
    add rsp,16
    pop r13
    pop r12
    pop rbx
bp_ensure_done:
    ret
bp_drop_pair:
    push rbx
    mov rbx,rdi
    mov rsi,[rbx+8]
    mov rdi,[rbx]
    call bp_unmap
    mov qword ptr [rbx],0
    mov qword ptr [rbx+8],0
    pop rbx
    ret

/* r14 context, r15 engine, rax private tag. */
bp_find_row:
    mov rbx,[r14+BC_ROWS]
bp_find_row_next:
    test rbx,rbx
    jz bp_find_row_return
    cmp [rbx+BR_TAG],rax
    jne bp_find_row_advance
    cmp [rbx+BR_ENGINE],r15
    jne bp_find_row_absent
    ret
bp_find_row_advance:
    mov rbx,[rbx+BR_NEXT]
    jmp bp_find_row_next
bp_find_row_absent:
    xor ebx,ebx
bp_find_row_return:
    ret

/* SysV fixture wrapper; production enters owned with fixed r15 engine. */
.global runtime_bellman_invoke
runtime_bellman_invoke:
    push r15
    mov r15,rdi
    mov rdi,rsi
    mov rsi,rdx
    call runtime_bellman_owned
    pop r15
    ret

.global runtime_bellman_owned
runtime_bellman_owned:
    BP_SAVE
    mov r14,[r15+440]
    call bp_enter
    test rax,rax
    jnz bp_return
    BP_NO_BORROW
    cmp qword ptr [r15+448],1
    jne bp_locked_invalid
    mov rax,[r15+8]
    add rax,BP_SLOT*64
    mov [rbp-104],rax
    mov rax,[r15+512+BP_SLOT*64]
    or rax,[r15+520+BP_SLOT*64]
    jnz bp_locked_busy
    mov qword ptr [r15+512+BP_SLOT*64],1
    cmp qword ptr [rbp-56],64
    jb bp_owned_invalid
    cmp qword ptr [rbp-56],16777216
    ja bp_owned_resource
    mov r12,[rbp-48]
    mov rax,[r12]
    mov rdx,0x31304741544c4248 /* HBLTAG01 */
    cmp rax,rdx
    je bp_owned_allocate
    mov rdx,0x31305445524c4248 /* HBLRET01 */
    cmp rax,rdx
    je bp_owned_retire
    mov rdx,0x3130514c434c4248 /* HBLCLQ01 */
    cmp rax,rdx
    jne bp_owned_invalid
    mov rax,[r12+8]
    dec rax
    cmp rax,2
    ja bp_owned_invalid
    mov rax,[r12+32]
    or rax,[r12+40]
    or rax,[r12+48]
    or rax,[r12+56]
    jnz bp_owned_invalid
    mov rax,[rbp-56]
    sub rax,64
    cmp [r12+24],rax
    jne bp_owned_invalid
    cmp qword ptr [r12+8],1
    je bp_owned_find_caller
    test rax,rax
    jnz bp_owned_invalid
bp_owned_find_caller:
    mov rax,[r12+16]
    test rax,rax
    jz bp_owned_invalid
    call bp_find_row
    test rbx,rbx
    jz bp_owned_invalid
    cmp qword ptr [r12+8],1
    jne bp_owned_existing_turn
    cmp qword ptr [r14+BC_PHASE],1
    jne bp_owned_invalid
    cmp qword ptr [rbx+BR_STATE],0
    jne bp_owned_invalid
    mov qword ptr [rbx+BR_STATE],1
    jmp bp_owned_prepare_turn
bp_owned_existing_turn:
    cmp qword ptr [rbx+BR_STATE],1
    jne bp_owned_invalid
    cmp qword ptr [rbx+BR_STATUS],3
    jne bp_owned_invalid
bp_owned_prepare_turn:
    lea rdi,[rbx+BR_INPUT]
    mov rsi,[rbp-56]
    xor edx,edx
    call bp_ensure_pair
    mov rdi,[rbx+BR_INPUT]
    mov rsi,[rbp-48]
    mov rcx,[rbp-56]
    mov [rbx+BR_INPUT_LEN],rcx
    cld
    rep movsb
    lea rdi,[rbx+BR_WORK]
    mov esi,4096
    mov edx,1
    call bp_ensure_pair
    lea rdi,[rbx+BR_OUTPUT]
    mov esi,64
    mov edx,1
    call bp_ensure_pair
    jmp bp_caller_enter

bp_owned_allocate:
    cmp qword ptr [r14+BC_PHASE],1
    jne bp_owned_invalid
    cmp qword ptr [rbp-56],64
    jne bp_owned_invalid
    cmp qword ptr [r12+8],1
    jne bp_owned_invalid
    mov rax,[r12+16]
    or rax,[r12+24]
    or rax,[r12+32]
    or rax,[r12+40]
    or rax,[r12+48]
    or rax,[r12+56]
    jnz bp_owned_invalid
    cmp qword ptr [r14+BC_TAG],-1
    je bp_owned_resource
    mov edi,BP_ROW_BYTES
    call bp_map
    cmp rax,-4095
    jae bp_owned_resource
    mov rbx,rax
    mov rax,0x3130574f524c4248 /* HBLROW01 */
    mov [rbx],rax
    mov [rbx+BR_ENGINE],r15
    inc qword ptr [r14+BC_TAG]
    mov rax,[r14+BC_TAG]
    mov [rbx+BR_TAG],rax
    mov rcx,[r14+BC_ROWS]
    mov [rbx+BR_NEXT],rcx
    mov [r14+BC_ROWS],rbx
    inc qword ptr [r14+BC_ROW_COUNT]
    lea r13,[r14+BC_OUTPUT]
    mov rdx,0x31305247544c4248 /* HBLTGR01 */
    mov [r13],rdx
    mov [r13+8],rax
    mov qword ptr [r13+16],0
    mov qword ptr [r13+24],0
    jmp bp_owned_small_result

bp_owned_retire:
    cmp qword ptr [rbp-56],64
    jne bp_owned_invalid
    cmp qword ptr [r12+8],1
    jne bp_owned_invalid
    mov rax,[r12+24]
    or rax,[r12+32]
    or rax,[r12+40]
    or rax,[r12+48]
    or rax,[r12+56]
    jnz bp_owned_invalid
    mov rax,[r12+16]
    call bp_find_row
    test rbx,rbx
    jz bp_owned_invalid
    cmp qword ptr [rbx+BR_STATE],1
    je bp_owned_busy
    mov rax,[rbx+BR_TAG]
    mov [rbp-112],rax
    lea rdi,[r14+BC_ROWS]
bp_retire_find_link:
    mov rax,[rdi]
    test rax,rax
    jz bp_fatal
    cmp rax,rbx
    je bp_retire_unlink
    lea rdi,[rax+BR_NEXT]
    jmp bp_retire_find_link
bp_retire_unlink:
    mov rax,[rbx+BR_NEXT]
    mov [rdi],rax
    dec qword ptr [r14+BC_ROW_COUNT]
    call bp_drop_row
    lea r13,[r14+BC_OUTPUT]
    mov rax,0x31305254524c4248 /* HBLRTR01 */
    mov [r13],rax
    mov rax,[rbp-112]
    mov [r13+8],rax
    mov qword ptr [r13+16],0
    mov qword ptr [r13+24],0
bp_owned_small_result:
    mov rdx,[rbp-104]
    mov qword ptr [rdx+8],0
    mov qword ptr [rdx+16],0
    mov [rdx+32],r13
    mov qword ptr [rdx+40],64
    mov qword ptr [rdx+48],32
    mov qword ptr [rdx+56],32
    mov eax,32
    jmp bp_owned_finish
bp_owned_invalid:
    mov eax,BP_INVALID
    jmp bp_owned_error
bp_owned_busy:
    mov eax,BP_BUSY
    jmp bp_owned_error
bp_owned_resource:
    mov eax,BP_RESOURCE
bp_owned_error:
    mov rdx,[rbp-104]
    mov [rdx+48],rax
    mov qword ptr [rdx+56],0
bp_owned_finish:
    mov qword ptr [r15+512+BP_SLOT*64],0
    jmp bp_unlock_return

/* Retire this caller's mappings only. The shared worker remains untouched. */
bp_drop_row:
    push rbx
    lea rdi,[rbx+BR_INPUT]
    call bp_drop_pair
    lea rdi,[rbx+BR_WORK]
    call bp_drop_pair
    lea rdi,[rbx+BR_OUTPUT]
    call bp_drop_pair
    lea rdi,[rbx+BR_CHILD_INPUT]
    call bp_drop_pair
    lea rdi,[rbx+BR_REPLY]
    call bp_drop_pair
    lea rdi,[rbx+BR_CHILD_WORK]
    call bp_drop_pair
    lea rdi,[rbx+BR_CHILD_OUTPUT]
    call bp_drop_pair
    mov rdi,rbx
    mov esi,BP_ROW_BYTES
    call bp_unmap
    pop rbx
    ret

bp_caller_enter:
    mov rdi,[rbx+BR_INPUT]
    mov rsi,[rbx+BR_INPUT_LEN]
    mov rdx,[rbx+BR_OUTPUT]
    mov rcx,[rbx+BR_OUTPUT_CAP]
    mov r8,[rbx+BR_WORK]
    mov r9,[rbx+BR_WORK_CAP]
    lea rax,[rip+runtime_bellman_caller_image]
    call rax
    mov edx,eax
    cmp rax,rdx
    jne bp_fatal
    cmp eax,BP_GROW
    je bp_caller_grow
    cmp eax,BP_CALL
    je bp_caller_action
    cmp eax,64
    jne bp_fatal
    mov r13,[rbx+BR_OUTPUT]
    mov rax,0x3130524c434c4248 /* HBLCLR01 */
    cmp [r13],rax
    jne bp_fatal
    mov rax,[rbx+BR_TAG]
    cmp [r13+16],rax
    jne bp_fatal
    mov rax,[r13+40]
    or rax,[r13+48]
    or rax,[r13+56]
    jnz bp_fatal
    mov rax,[r13+8]
    cmp rax,4
    ja bp_fatal
    mov [rbx+BR_STATUS],rax
    cmp rax,3
    je bp_caller_pending
    mov qword ptr [rbx+BR_STATE],2
bp_caller_pending:
    mov rax,[r13+32]
    add rax,64
    jc bp_fatal
    cmp rax,[rbx+BR_OUTPUT_CAP]
    ja bp_fatal
    mov rdx,[rbp-104]
    mov [rdx+56],rax
    mov rax,[rbx+BR_WORK]
    mov [rdx+8],rax
    mov rax,[rbx+BR_WORK_CAP]
    mov [rdx+16],rax
    mov [rdx+32],r13
    mov rax,[rbx+BR_OUTPUT_CAP]
    mov [rdx+40],rax
    mov qword ptr [rdx+48],64
    mov eax,64
    jmp bp_owned_finish

bp_caller_grow:
    mov r13,[rbx+BR_OUTPUT]
    mov rax,0x3230305357524748 /* HGRWS002 */
    cmp [r13],rax
    jne bp_fatal
    cmp qword ptr [r13+24],0
    jne bp_fatal
    mov rsi,[r13+16]
    cmp qword ptr [r13+8],1
    je bp_caller_grow_work
    cmp qword ptr [r13+8],2
    jne bp_fatal
    cmp rsi,67108864
    ja bp_fatal
    lea rdi,[rbx+BR_OUTPUT]
    jmp bp_caller_grow_admit
bp_caller_grow_work:
    cmp rsi,268435456
    ja bp_fatal
    lea rdi,[rbx+BR_WORK]
bp_caller_grow_admit:
    cmp rsi,[rdi+8]
    jbe bp_fatal
    mov edx,1
    call bp_ensure_pair
    jmp bp_caller_enter

bp_caller_action:
    mov r13,[rbx+BR_WORK]
    add r13,256
    mov rax,0x31304341434c4248 /* HBLCAC01 */
    cmp [r13],rax
    jne bp_fatal
    cmp qword ptr [r13+8],0
    je bp_fatal
    cmp qword ptr [r13+16],2
    ja bp_fatal
    cmp qword ptr [r13+24],1
    ja bp_fatal
    mov rax,[r13+64]
    or rax,[r13+72]
    or rax,[r13+80]
    or rax,[r13+88]
    or rax,[r13+96]
    or rax,[r13+104]
    jnz bp_fatal
    mov rax,[r13+32]
    cmp rax,4096
    jb bp_fatal
    cmp rax,[rbx+BR_WORK_CAP]
    ja bp_fatal
    mov rdx,[rbx+BR_WORK_CAP]
    sub rdx,rax
    cmp [r13+40],rdx
    ja bp_fatal
    cmp qword ptr [r13+40],64
    jb bp_fatal
    cmp qword ptr [r13+40],16777216
    ja bp_fatal
    mov rax,[r13+48]
    cmp rax,4096
    jb bp_fatal
    cmp rax,[rbx+BR_WORK_CAP]
    ja bp_fatal
    mov rdx,[rbx+BR_WORK_CAP]
    sub rdx,rax
    cmp [r13+56],rdx
    ja bp_fatal
    mov rax,0x3130304341504248 /* HBPAC001: full returned continuation. */
    call bp_trace_action
    cmp qword ptr [r13+24],1
    je bp_action_redeliver
    mov rax,[r13+8]
    cmp rax,[rbx+BR_SEQUENCE]
    jbe bp_fatal
    lea rdi,[rbx+BR_CHILD_INPUT]
    call bp_drop_pair
    lea rdi,[rbx+BR_REPLY]
    call bp_drop_pair
    lea rdi,[rbx+BR_CHILD_INPUT]
    mov rsi,[r13+40]
    xor edx,edx
    call bp_ensure_pair
    mov rdi,[rbx+BR_CHILD_INPUT]
    mov rsi,[rbx+BR_WORK]
    add rsi,[r13+32]
    mov rcx,[r13+40]
    cld
    rep movsb
    mov rax,[r13+8]
    mov [rbx+BR_SEQUENCE],rax
    mov rax,[r13+16]
    mov [rbx+BR_TARGET],rax
    cmp rax,2
    je bp_child_worker
    jmp bp_child_pure
bp_action_redeliver:
    mov rax,[r13+8]
    cmp rax,[rbx+BR_SEQUENCE]
    jne bp_fatal
    mov rax,[r13+16]
    cmp rax,[rbx+BR_TARGET]
    jne bp_fatal
    mov rcx,[r13+40]
    cmp rcx,[rbx+BR_CHILD_INPUT_LEN]
    jne bp_fatal
    mov rsi,[rbx+BR_CHILD_INPUT]
    mov rdi,[rbx+BR_WORK]
    add rdi,[r13+32]
    cld
    repe cmpsb
    jne bp_fatal
    cmp qword ptr [rbx+BR_REPLY],0
    je bp_fatal
    jmp bp_action_deliver

bp_child_worker:
    mov rsi,[rbx+BR_CHILD_INPUT]
    mov rax,0x313051524b574248 /* HBWKRQ01 */
    cmp [rsi],rax
    jne bp_fatal
    mov rax,[rsi+8]
    dec rax
    cmp rax,3
    ja bp_fatal
    mov rax,[rsi+32]
    or rax,[rsi+48]
    or rax,[rsi+56]
    jnz bp_fatal
    mov rax,[rbx+BR_TAG]
    cmp [rsi+16],rax
    jne bp_fatal
    mov rdx,[rbx+BR_CHILD_INPUT_LEN]
    mov rax,rdx
    sub rax,64
    cmp [rsi+40],rax
    jne bp_fatal
    cmp qword ptr [rsi+8],1
    je bp_child_submit_job
    mov rax,[rbx+184] /* Private admitted job, zero until submit. */
    test rax,rax
    jz bp_fatal
    cmp [rsi+24],rax
    jne bp_fatal
    jmp bp_child_worker_admitted
bp_child_submit_job:
    cmp qword ptr [rsi+24],0
    jne bp_fatal
    cmp qword ptr [rbx+184],0
    jne bp_fatal
bp_child_worker_admitted:
    /* One writev is one complete owned input observation. The two spans are
     * immutable until the actual worker control turn returns. */
    mov rax,0x31304e4957504248 /* HBPWIN01 */
    mov [rbp-240],rax
    lea rax,[rdx+16]
    mov [rbp-232],rax
    lea rax,[rbp-240]
    mov [rbp-224],rax
    mov qword ptr [rbp-216],16
    mov [rbp-208],rsi
    mov [rbp-200],rdx
bp_trace_input_retry:
    mov rdi,[r14+BC_JOURNAL_FD]
    lea rsi,[rbp-224]
    mov edx,2
    mov eax,20
    syscall
    cmp rax,-4
    je bp_trace_input_retry
    cmp rax,[rbp-232]
    jne bp_fatal
    mov rsi,[rbx+BR_CHILD_INPUT]
    mov rdx,[rbx+BR_CHILD_INPUT_LEN]
    BP_WORKER control
    test rax,rax
    jnz bp_fatal
    mov rdi,rbx
    call bp_drain
    jmp bp_action_deliver

/* Both fixed adapters are pure; every retry receives fresh zero work/output,
 * as in their qualified independent borrowed-buffer transport. */
bp_child_pure:
    mov qword ptr [rbp-120],65536
    mov qword ptr [rbp-128],64
    cmp qword ptr [rbx+BR_TARGET],0
    jne bp_child_pure_attempt
    mov qword ptr [rbp-128],128
bp_child_pure_attempt:
    lea rdi,[rbx+BR_CHILD_WORK]
    call bp_drop_pair
    lea rdi,[rbx+BR_CHILD_OUTPUT]
    call bp_drop_pair
    lea rdi,[rbx+BR_CHILD_WORK]
    mov rsi,[rbp-120]
    xor edx,edx
    call bp_ensure_pair
    lea rdi,[rbx+BR_CHILD_OUTPUT]
    mov rsi,[rbp-128]
    xor edx,edx
    call bp_ensure_pair
    mov rdi,[rbx+BR_CHILD_INPUT]
    mov rsi,[rbx+BR_CHILD_INPUT_LEN]
    mov rdx,[rbx+BR_CHILD_OUTPUT]
    mov rcx,[rbx+BR_CHILD_OUTPUT_CAP]
    mov r8,[rbx+BR_CHILD_WORK]
    mov r9,[rbx+BR_CHILD_WORK_CAP]
    lea rax,[rip+runtime_bellman_params_image]
    cmp qword ptr [rbx+BR_TARGET],0
    je bp_child_pure_call
    lea rax,[rip+runtime_bellman_diagnostic_image]
bp_child_pure_call:
    call rax
    mov edx,eax
    cmp rax,rdx
    jne bp_fatal
    cmp eax,BP_GROW
    je bp_child_pure_grow
    cmp eax,0xffff0000
    jae bp_fatal
    test rax,rax
    jz bp_fatal
    cmp rax,[rbx+BR_CHILD_OUTPUT_CAP]
    ja bp_fatal
    mov [rbx+BR_REPLY_LEN],rax
    mov rdi,rax
    call bp_map
    cmp rax,-4095
    jae bp_fatal
    mov [rbx+BR_REPLY],rax
    mov rdi,rax
    mov rsi,[rbx+BR_CHILD_OUTPUT]
    mov rcx,[rbx+BR_REPLY_LEN]
    cld
    rep movsb
    jmp bp_action_deliver
bp_child_pure_grow:
    mov r12,[rbx+BR_CHILD_OUTPUT]
    mov rax,0x3230305357524748
    cmp [r12],rax
    jne bp_fatal
    cmp qword ptr [r12+24],0
    jne bp_fatal
    mov rax,[r12+16]
    cmp qword ptr [r12+8],1
    je bp_child_pure_grow_work
    cmp qword ptr [r12+8],2
    jne bp_fatal
    cmp rax,[rbp-128]
    jbe bp_fatal
    cmp rax,67108864
    ja bp_fatal
    mov [rbp-128],rax
    jmp bp_child_pure_attempt
bp_child_pure_grow_work:
    cmp rax,[rbp-120]
    jbe bp_fatal
    cmp rax,268435456
    ja bp_fatal
    mov [rbp-120],rax
    jmp bp_child_pure_attempt

bp_action_deliver:
    /* Re-read the current arena; no pointer survives caller workspace growth. */
    mov r13,[rbx+BR_WORK]
    add r13,256
    mov rax,[rbx+BR_SEQUENCE]
    cmp [r13+8],rax
    jne bp_fatal
    mov [r13+64],rax
    mov rcx,[rbx+BR_REPLY_LEN]
    mov [r13+96],rcx
    mov eax,BP_DELIVERY
    cmp rcx,[r13+56]
    ja bp_action_acknowledge
    mov rsi,[rbx+BR_REPLY]
    mov rdi,[rbx+BR_WORK]
    add rdi,[r13+48]
    mov rax,rcx
    cld
    rep movsb
bp_action_acknowledge:
    mov [r13+72],rax
    mov rax,0x3130304141504248 /* HBPAA001: full acknowledged continuation. */
    call bp_trace_action
    jmp bp_caller_enter

/* One immutable 32-byte observation header and the complete live 112-byte
 * HIA continuation are written together. This does not decide or replay it. */
bp_trace_action:
    sub rsp,64
    mov [rsp],rax
    mov qword ptr [rsp+8],144
    mov rax,[rbx+BR_TAG]
    mov [rsp+16],rax
    mov rax,[rbx+184]
    mov [rsp+24],rax
    mov [rsp+32],rsp
    mov qword ptr [rsp+40],32
    mov [rsp+48],r13
    mov qword ptr [rsp+56],112
bp_trace_action_retry:
    mov rdi,[r14+BC_JOURNAL_FD]
    lea rsi,[rsp+32]
    mov edx,2
    mov eax,20
    syscall
    cmp rax,-4
    je bp_trace_action_retry
    cmp rax,144
    jne bp_fatal
    add rsp,64
    ret

/* Complete regular-file / null-device event write; a short transport write
 * is a retained resource failure, never a successful partial observation. */
bp_trace_event:
    mov rdi,[r14+BC_JOURNAL_FD]
    mov eax,1
    syscall
    cmp rax,-4
    je bp_trace_event
    cmp rax,rdx
    jne bp_fatal
    ret
