.intel_syntax noprefix
.section .text
.global _start
.global stamp_call_displacement
.equ MAIN_INPUT, 4096
.equ MAIN_OUTPUT, 8192
.equ MAIN_OWNER, 1048576
.equ NAMESPACE_BASE, 2097152
.equ FINAL_GUARD, 12582912
.equ TOTAL_MAP, 12587008
.equ M_ACTION, 256
.equ M_STAT, 1024
.equ M_STATX, 3072
.equ M_REQUEST, 8192
.equ M_REPLY, 12288

_start:
    cld
    cmp qword ptr [rsp], 2
    jne main_usage
    mov rbx, [rsp + 16]
    xor edi, edi
    mov esi, TOTAL_MAP
    mov edx, 3
    mov r10d, 34
    mov r8, -1
    xor r9d, r9d
    mov eax, 9
    syscall
    cmp rax, -4095
    jae main_bare_fail
    mov r15, rax
    mov r13, rax
    lea rdi, [r15 + 128]
    mov ecx, 1
    mov rax, -1
    rep stosq
    lea rdi, [r15 + NAMESPACE_BASE + 16384]
    mov ecx, 33794
    rep stosq
    mov qword ptr [r15 + 256], 1
    mov edi, 13
    lea rsi, [r15 + 256]
    xor edx, edx
    mov r10d, 8
    mov eax, 13
    syscall
    test rax, rax
    jnz main_io_fail
    lea rdi, [r15 + FINAL_GUARD]
    mov esi, 4096
    xor edx, edx
    mov eax, 10
    syscall
    test rax, rax
    jnz main_io_fail
    mov edi, -100
    mov rsi, rbx
    mov edx, 0xa0800
    xor r10d, r10d
    mov eax, 257
    syscall
    test rax, rax
    js main_io_fail
    mov [r15 + 128], rax
    lea r12, [r15 + MAIN_OWNER]
main_next_frame:
    lea rdi, [r15 + MAIN_INPUT]
    mov esi, 4096
    mov edx, 3
    mov eax, 10
    syscall
    test rax, rax
    jnz main_io_fail
    lea rsi, [r15 + 24]
    mov edx, 8
    mov r8d, 1
    call main_read_exact
    test eax, eax
    jz main_success
    mov rdx, [r15 + 24]
    cmp rdx, 4096
    ja main_contract_fail
    lea rsi, [r15 + MAIN_INPUT]
    xor r8d, r8d
    call main_read_exact
    lea rdi, [r15 + MAIN_INPUT]
    mov esi, 4096
    mov edx, 1
    mov eax, 10
    syscall
    test rax, rax
    jnz main_io_fail
main_resume:
    lea rdi, [r15 + MAIN_INPUT]
    mov rsi, [r15 + 24]
    lea rdx, [r15 + MAIN_OUTPUT]
    mov ecx, 4096
    mov r8, r12
    mov r9d, 1048576
    .byte 0xe8
stamp_call_displacement:
    .long 0
    mov ecx, eax
    cmp rax, rcx
    jne main_contract_fail
    cmp eax, 0xfffffff0
    jne main_result
    lea r14, [r12 + M_ACTION]
    mov rax, 0x3130304153415248
    cmp [r14], rax
    jne main_contract_fail
    mov rax, [r15 + 16]
    inc rax
    jz main_contract_fail
    cmp [r14 + 8], rax
    jne main_contract_fail
    cmp [r12 + 16], rax
    jne main_contract_fail
    mov [r15 + 16], rax
    mov rax, [r14 + 64]
    or rax, [r14 + 72]
    or rax, [r14 + 80]
    or rax, [r14 + 88]
    jnz main_contract_fail
    mov rax, [r14 + 16]
    cmp rax, 100
    jae main_child
    cmp qword ptr [r14 + 56], 0
    jne main_contract_fail
    cmp rax, 2
    je main_fstat
    cmp rax, 5
    je main_uid
    cmp rax, 8
    je main_statx
    cmp rax, 9
    je main_statx_probe
    cmp rax, 10
    je main_statat
    cmp rax, 11
    je main_statat_probe
    jmp main_contract_fail
main_zero_span:
    mov rax, [r14 + 32]
    or rax, [r14 + 40]
    or rax, [r14 + 48]
    jnz main_contract_fail
    ret
main_slot_live:
    cmp qword ptr [r14 + 24], 0
    jne main_contract_fail
    mov rdi, [r15 + 128]
    test rdi, rdi
    js main_contract_fail
    ret
main_uid:
    cmp qword ptr [r12 + 8], 8
    jne main_contract_fail
    cmp qword ptr [r14 + 24], 0
    jne main_contract_fail
    cmp qword ptr [r14 + 32], M_STAT + 144
    jne main_contract_fail
    cmp qword ptr [r14 + 40], 8
    jne main_contract_fail
    cmp qword ptr [r14 + 48], 0
    jne main_contract_fail
    mov eax, 107
    syscall
    mov [r12 + M_STAT + 144], rax
    jmp main_ack
main_metadata_live:
    mov rcx, [r14 + 24]
    cmp rcx, 1
    ja main_contract_fail
    cmp rcx, [r12 + 128]
    jne main_contract_fail
    cmp qword ptr [r14 + 48], 0
    jne main_contract_fail
    call main_slot_live
    ret
main_stat_span:
    cmp qword ptr [r14 + 32], M_STAT
    jne main_contract_fail
    cmp qword ptr [r14 + 40], 144
    jne main_contract_fail
    lea rsi, [r12 + M_STAT]
    ret
main_fstat:
    cmp qword ptr [r12 + 8], 50
    jne main_contract_fail
    call main_metadata_live
    call main_stat_span
    mov eax, 5
    syscall
    jmp main_zero
main_statx:
    cmp qword ptr [r12 + 8], 51
    jne main_contract_fail
    call main_metadata_live
    cmp qword ptr [r14 + 32], M_STATX
    jne main_contract_fail
    cmp qword ptr [r14 + 40], 256
    jne main_contract_fail
    lea rsi, [r15 + 512]
    mov edx, 4096
    mov r10d, 4095
    lea r8, [r12 + M_STATX]
    mov eax, 332
    syscall
    jmp main_zero
main_statat:
    cmp qword ptr [r12 + 8], 52
    jne main_contract_fail
    call main_metadata_live
    call main_stat_span
    lea rsi, [r15 + 512]
    lea rdx, [r12 + M_STAT]
    mov r10d, 4096
    mov eax, 262
    syscall
    jmp main_zero
main_probe_admit:
    cmp qword ptr [r14 + 24], 0
    jne main_contract_fail
    call main_zero_span
    xor edi, edi
    xor esi, esi
    xor edx, edx
    ret
main_statx_probe:
    cmp qword ptr [r12 + 8], 53
    jne main_contract_fail
    call main_probe_admit
    mov r10d, 4095
    xor r8d, r8d
    mov eax, 332
    syscall
    jmp main_zero
main_statat_probe:
    cmp qword ptr [r12 + 8], 54
    jne main_contract_fail
    call main_probe_admit
    lea rdx, [r12 + M_STAT]
    xor r10d, r10d
    mov eax, 262
    syscall
    jmp main_zero
main_child:
    cmp rax, 101
    jne main_contract_fail
    cmp qword ptr [r14 + 24], 0
    jne main_contract_fail
    cmp qword ptr [r14 + 32], M_REQUEST
    jne main_contract_fail
    cmp qword ptr [r14 + 40], 32
    jne main_contract_fail
    cmp qword ptr [r14 + 48], M_REPLY
    jne main_contract_fail
    cmp qword ptr [r14 + 56], 72
    jne main_contract_fail
    cmp qword ptr [r12 + 8], 9
    jne main_contract_fail
    cmp qword ptr [r12 + M_REQUEST + 8], 1
    jne main_contract_fail
    cmp qword ptr [r12 + M_REQUEST + 16], 0
    jne main_contract_fail
    call namespace_entry
main_child_return:
    mov [r14 + 72], rax
    jmp main_ack
main_zero:
    test rax, rax
    js main_error
    jnz main_contract_fail
    jmp main_ack
main_value:
    test rax, rax
    js main_error
    mov [r14 + 72], rax
    jmp main_ack
main_error:
    cmp rax, -4095
    jb main_contract_fail
    neg rax
    mov [r14 + 80], rax
main_ack:
    mov rax, [r14 + 8]
    mov [r14 + 64], rax
    jmp main_resume
main_result:
    cmp qword ptr [r12 + 8], 0
    jne main_contract_fail
    mov [r15 + 32], eax
    cmp eax, 48
    je main_result_header
    cmp eax, 160
    je main_result_header
    cmp eax, 0xffffffff
    je main_result_header
    cmp eax, 0xfffffffe
    jne main_contract_fail
main_result_header:
    lea rsi, [r15 + 32]
    mov edx, 4
    call main_write_exact
    mov edx, [r15 + 32]
    cmp edx, 4096
    ja main_next_frame
    lea rsi, [r15 + MAIN_OUTPUT]
    call main_write_exact
    jmp main_next_frame
main_read_exact:
    test rdx, rdx
    jz main_read_done
main_read_retry:
    xor edi, edi
    xor eax, eax
    syscall
    cmp rax, -4
    je main_read_retry
    test rax, rax
    js main_io_fail
    jz main_read_eof
    xor r8d, r8d
    add rsi, rax
    sub rdx, rax
    jnz main_read_retry
main_read_done:
    mov eax, 1
    ret
main_read_eof:
    test r8d, r8d
    jz main_contract_fail
    xor eax, eax
    ret
main_write_exact:
    test rdx, rdx
    jz main_write_done
main_write_retry:
    mov edi, 1
    mov eax, 1
    syscall
    cmp rax, -4
    je main_write_retry
    test rax, rax
    jle main_io_fail
    add rsi, rax
    sub rdx, rax
    jnz main_write_retry
main_write_done:
    ret
main_success:
    xor ebp, ebp
    jmp main_cleanup
main_contract_fail:
    mov ebp, 2
    jmp main_cleanup
main_io_fail:
    mov ebp, 74
main_cleanup:
    mov r15, r13
    mov qword ptr [r15 + NAMESPACE_BASE + 16384], -1
    add r15, NAMESPACE_BASE
    mov ebx, 33793
main_namespace_cleanup_loop:
    mov rdi, [r15 + rbx*8 + 16384]
    mov qword ptr [r15 + rbx*8 + 16384], -1
    test rdi, rdi
    js main_namespace_cleanup_next
    call ns_raw_descriptor_referenced
    test eax, eax
    jnz main_namespace_cleanup_next
    mov eax, 3
    syscall
main_namespace_cleanup_next:
    dec ebx
    jns main_namespace_cleanup_loop
    mov r15, r13
    mov rdi, [r15 + 128]
    mov qword ptr [r15 + 128], -1
    test rdi, rdi
    js main_unmap
    mov eax, 3
    syscall
main_unmap:
    mov rdi, r15
    mov esi, TOTAL_MAP
    mov eax, 11
    syscall
    mov edi, ebp
    jmp main_exit
main_bare_fail:
    mov edi, 74
    jmp main_exit
main_usage:
    mov edi, 64
main_exit:
    mov eax, 60
    syscall
    ud2

.equ ns_INPUT, 4096
.equ ns_OUTPUT, 8192
.equ ns_FDS, 16384
.equ ns_OWNER, 1048576
.equ ns_GUARD, 9437184
.equ ns_MAP_SIZE, 9441280
.equ ns_FDS_COUNT, 33794
.equ ns_SET_SLOT, 4880
.equ ns_SET_TABLE, 2097152
.equ ns_SET_STRIDE, 16640
.equ ns_PHASE, 4104
.equ ns_SEQUENCE, 4112
.equ ns_OPERATION, 4136
.equ ns_DIRECTORY, 4144
.equ ns_WATCHER, 4152
.equ ns_SCAN_LIVE, 4288
.equ ns_SCAN_CAPACITY, 4304
.equ ns_CANDIDATE, 4328
.equ ns_ACTION, 4352
.equ ns_STAT, 6144
.equ ns_STATX, 6400
.equ ns_NAME, 7040
.equ ns_EVENTS, 65536
.equ ns_DIRENTS, 131072
.global ns_namespace_call_displacement
namespace_entry:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp, 8
    lea r15, [r13 + NAMESPACE_BASE]
    lea r12, [r15 + 1048576]
    lea rdi, [r15 + 4096]
    mov esi, 4096
    mov edx, 3
    mov eax, 10
    syscall
    test rax, rax
    jnz main_io_fail
    lea rdi, [r15 + 4096]
    lea rsi, [r13 + MAIN_OWNER + M_REQUEST]
    mov ecx, 32
    rep movsb
    mov qword ptr [r15 + 24], 32
    lea rdi, [r15 + 4096]
    mov esi, 4096
    mov edx, 1
    mov eax, 10
    syscall
    test rax, rax
    jnz main_io_fail
    cmp qword ptr [r15 + 16384], -1
    jne main_contract_fail
    mov rax, [r13 + 128]
    test rax, rax
    js main_contract_fail
    mov [r15 + 16384], rax
ns_resume_namespace:
    lea rdi, [r15 + ns_INPUT]
    mov rsi, [r15 + 24]
    lea rdx, [r15 + ns_OUTPUT]
    mov ecx, 4096
    mov r8, r12
    mov r9d, 8388608
    .byte 0xe8
ns_namespace_call_displacement:
    .long 0
    mov ecx, eax
    cmp rax, rcx
    jne main_contract_fail
    cmp eax, 0xfffffff0
    jne ns_owner_result
    lea r14, [r12 + ns_ACTION]
    mov rax, 0x3130304156534e48
    cmp [r14], rax
    jne main_contract_fail
    mov rax, [r15 + 16]
    inc rax
    jz main_contract_fail
    cmp [r14 + 8], rax
    jne main_contract_fail
    cmp [r12 + ns_SEQUENCE], rax
    jne main_contract_fail
    mov [r15 + 16], rax
    mov rax, [r14 + 56]
    or rax, [r14 + 64]
    or rax, [r14 + 72]
    or rax, [r14 + 80]
    or rax, [r14 + 88]
    jnz main_contract_fail
    mov rax, [r14 + 16]
    cmp rax, 1
    je ns_bind_effect
    cmp rax, 2
    je ns_old_stat_effect
    cmp rax, 3
    je ns_statx_effect
    cmp rax, 4
    je ns_statat_effect
    cmp rax, 5
    je ns_statx_probe_effect
    cmp rax, 6
    je ns_statat_probe_effect
    cmp rax, 7
    je ns_init_effect
    cmp rax, 8
    je ns_events_effect
    cmp rax, 9
    je ns_duplicate_effect
    cmp rax, 10
    je ns_add_watch_effect
    cmp rax, 11
    je ns_remove_watch_effect
    cmp rax, 12
    je ns_close_pin_effect
    cmp rax, 13
    je ns_scan_open_effect
    cmp rax, 14
    je ns_flags_effect
    cmp rax, 15
    je ns_scan_stat_effect
    cmp rax, 16
    je ns_directory_effect
    cmp rax, 17
    je ns_close_scan_effect
    cmp rax, 18
    je ns_close_borrow_effect
    cmp rax, 19
    je ns_retain_borrow_effect
    cmp rax, 20
    je ns_close_set_event_effect
    jmp main_contract_fail
ns_zero_span:
    mov rax, [r14 + 32]
    or rax, [r14 + 40]
    or rax, [r14 + 48]
    jnz main_contract_fail
    ret
ns_borrow_index:
    mov rcx, [r14 + 24]
    cmp rcx, 258
    ja main_contract_fail
    cmp rcx, [r12 + ns_DIRECTORY]
    jne main_contract_fail
    ret
ns_borrow_live:
    call ns_borrow_index
    mov rdi, [r15 + rcx*8 + ns_FDS]
    test rdi, rdi
    js main_contract_fail
    ret
ns_set_admit:
    mov rax, [r12 + ns_SET_SLOT]
    cmp rax, 128
    jae main_contract_fail
    imul rax, ns_SET_STRIDE
    add rax, ns_SET_TABLE
    cmp rax, [r12 + ns_WATCHER]
    jne main_contract_fail
    mov rax, [r12 + ns_OPERATION]
    cmp rax, 5
    jb main_contract_fail
    cmp rax, 7
    ja main_contract_fail
    ret
ns_event_index:
    mov ecx, 259
    cmp qword ptr [r12 + ns_WATCHER], 8192
    je ns_event_normal
    cmp qword ptr [r12 + ns_WATCHER], 24576
    jne ns_event_set
    inc ecx
    cmp qword ptr [r12 + ns_OPERATION], 2
    jne main_contract_fail
    jmp ns_event_index_ok
ns_event_normal:
    cmp qword ptr [r12 + ns_OPERATION], 1
    jne main_contract_fail
    jmp ns_event_index_ok
ns_event_set:
    call ns_set_admit
    mov rcx, [r12 + ns_SET_SLOT]
    add rcx, 262
ns_event_index_ok:
    cmp rcx, [r14 + 24]
    jne main_contract_fail
    ret
ns_event_live:
    call ns_event_index
    mov rdi, [r15 + rcx*8 + ns_FDS]
    test rdi, rdi
    js main_contract_fail
    ret
ns_pin_index:
    call ns_pin_bounds
    mov rcx, [r14 + 24]
    cmp rcx, rdx
    jb main_contract_fail
    cmp rcx, r8
    jae main_contract_fail
    ret
ns_pin_bounds:
    mov edx, 512
    cmp qword ptr [r12 + ns_WATCHER], 8192
    je ns_pin_pool
    cmp qword ptr [r12 + ns_WATCHER], 24576
    jne ns_pin_set
    mov edx, 641
ns_pin_pool:
    lea r8, [rdx + 129]
    ret
ns_pin_set:
    call ns_set_admit
    mov rdx, [r12 + ns_SET_SLOT]
    imul rdx, 258
    add rdx, 770
    lea r8, [rdx + 258]
    ret
ns_scan_live:
    cmp qword ptr [r14 + 24], 261
    jne main_contract_fail
    mov rdi, [r15 + ns_FDS + 261*8]
    test rdi, rdi
    js main_contract_fail
    ret
ns_bind_effect:
    cmp qword ptr [r12 + ns_PHASE], 1
    jne main_contract_fail
    call ns_borrow_index
    cmp qword ptr [r14 + 32], ns_NAME
    jne main_contract_fail
    cmp qword ptr [r14 + 48], 0
    jne main_contract_fail
    test rcx, rcx
    jnz ns_bind_name
    cmp qword ptr [r14 + 40], 1
    jne main_contract_fail
    cmp qword ptr [r12 + ns_NAME], 46
    jne main_contract_fail
    jmp ns_bind_ready
ns_bind_name:
    cmp qword ptr [r14 + 40], 4
    jne main_contract_fail
    cmp byte ptr [r12 + ns_NAME], 100
    jne main_contract_fail
    cmp dword ptr [r12 + ns_NAME + 4], 0
    jne main_contract_fail
    mov eax, ecx
    xor edx, edx
    mov ebx, 100
    div ebx
    add eax, 48
    cmp al, [r12 + ns_NAME + 1]
    jne main_contract_fail
    mov eax, edx
    xor edx, edx
    mov ebx, 10
    div ebx
    add eax, 48
    add edx, 48
    cmp al, [r12 + ns_NAME + 2]
    jne main_contract_fail
    cmp dl, [r12 + ns_NAME + 3]
    jne main_contract_fail
ns_bind_ready:
    cmp qword ptr [r15 + rcx*8 + ns_FDS], -1
    jne ns_bind_existing
    mov rdi, [r15 + ns_FDS]
    lea rsi, [r12 + ns_NAME]
    mov edx, 0x80000
    xor r10d, r10d
    mov eax, 257
    syscall
    jmp ns_install_descriptor
ns_bind_existing:
    mov [r14 + 72], rcx
    jmp ns_acknowledge
ns_stat_span:
    cmp qword ptr [r14 + 32], ns_STAT
    jne main_contract_fail
    cmp qword ptr [r14 + 40], 144
    jne main_contract_fail
    cmp qword ptr [r14 + 48], 0
    jne main_contract_fail
    lea rsi, [r12 + ns_STAT]
    ret
ns_old_stat_effect:
    cmp qword ptr [r12 + ns_PHASE], 50
    jne main_contract_fail
    call ns_borrow_live
    call ns_stat_span
    mov eax, 5
    syscall
    jmp ns_zero_effect
ns_statx_effect:
    cmp qword ptr [r12 + ns_PHASE], 51
    jne main_contract_fail
    call ns_borrow_live
    cmp qword ptr [r14 + 32], ns_STATX
    jne main_contract_fail
    cmp qword ptr [r14 + 40], 256
    jne main_contract_fail
    cmp qword ptr [r14 + 48], 0
    jne main_contract_fail
    mov byte ptr [r15 + 512], 0
    lea rsi, [r15 + 512]
    mov edx, 4096
    mov r10d, 4095
    lea r8, [r12 + ns_STATX]
    mov eax, 332
    syscall
    jmp ns_zero_effect
ns_statat_effect:
    cmp qword ptr [r12 + ns_PHASE], 52
    jne main_contract_fail
    call ns_borrow_live
    call ns_stat_span
    mov byte ptr [r15 + 512], 0
    lea rsi, [r15 + 512]
    lea rdx, [r12 + ns_STAT]
    mov r10d, 4096
    mov eax, 262
    syscall
    jmp ns_zero_effect
ns_probe_admit:
    cmp qword ptr [r14 + 24], 0
    jne main_contract_fail
    call ns_zero_span
    xor edi, edi
    xor esi, esi
    xor edx, edx
    ret
ns_statx_probe_effect:
    cmp qword ptr [r12 + ns_PHASE], 53
    jne main_contract_fail
    call ns_probe_admit
    mov r10d, 4095
    xor r8d, r8d
    mov eax, 332
    syscall
    jmp ns_zero_effect
ns_statat_probe_effect:
    cmp qword ptr [r12 + ns_PHASE], 54
    jne main_contract_fail
    call ns_probe_admit
    lea rdx, [r12 + ns_STAT]
    xor r10d, r10d
    mov eax, 262
    syscall
    jmp ns_zero_effect
ns_init_effect:
    cmp qword ptr [r12 + ns_PHASE], 10
    jne main_contract_fail
    call ns_zero_span
    call ns_event_index
    cmp qword ptr [r15 + rcx*8 + ns_FDS], -1
    jne main_contract_fail
    mov edi, 0x80800
    mov eax, 294
    syscall
    jmp ns_install_descriptor
ns_events_effect:
    cmp qword ptr [r12 + ns_PHASE], 11
    jne main_contract_fail
    call ns_event_live
    cmp qword ptr [r14 + 32], ns_EVENTS
    jne main_contract_fail
    cmp qword ptr [r14 + 40], 16384
    jne main_contract_fail
    cmp qword ptr [r14 + 48], 0
    jne main_contract_fail
    lea rsi, [r12 + ns_EVENTS]
    mov edx, 16384
    xor eax, eax
    syscall
    jmp ns_value_effect
ns_duplicate_effect:
    cmp qword ptr [r12 + ns_PHASE], 15
    jne main_contract_fail
    call ns_pin_index
    cmp qword ptr [r15 + rcx*8 + ns_FDS], -1
    jne main_contract_fail
    mov rax, [r14 + 32]
    or rax, [r14 + 40]
    jnz main_contract_fail
    mov rax, [r14 + 48]
    cmp rax, [r12 + ns_DIRECTORY]
    jne main_contract_fail
    cmp rax, 258
    ja main_contract_fail
    mov rdi, [r15 + rax*8 + ns_FDS]
    test rdi, rdi
    js main_contract_fail
    mov esi, 1030
    mov edx, 3 /* Rust File::try_clone preserves standard descriptor slots. */
    mov eax, 72
    syscall
    jmp ns_install_descriptor
ns_add_watch_effect:
    cmp qword ptr [r12 + ns_PHASE], 16
    jne main_contract_fail
    call ns_event_live
    cmp qword ptr [r14 + 32], 0
    jne main_contract_fail
    mov ebx, 16781248
    cmp qword ptr [r12 + ns_OPERATION], 1
    je ns_watch_flags_ok
    or ebx, 14
ns_watch_flags_ok:
    cmp rbx, [r14 + 40]
    jne main_contract_fail
    push rdi
    call ns_pin_bounds
    pop rdi
    mov rax, [r14 + 48]
    cmp rax, rdx
    jb main_contract_fail
    cmp rax, r8
    jae main_contract_fail
    mov rax, [r15 + rax*8 + ns_FDS]
    test rax, rax
    js main_contract_fail
    lea r8, [r15 + 640]
    mov byte ptr [r8], 0
    mov r9d, 10
ns_fd_digits:
    xor edx, edx
    div r9
    add dl, 48
    dec r8
    mov [r8], dl
    test rax, rax
    jnz ns_fd_digits
    mov rax, 0x65732f636f72702f
    mov [r15 + 576], rax
    mov dword ptr [r15 + 584], 0x662f666c
    mov word ptr [r15 + 588], 0x2f64
    lea rsi, [r15 + 576]
    lea rdx, [r15 + 590]
ns_copy_digits:
    mov al, [r8]
    mov [rdx], al
    inc r8
    inc rdx
    test al, al
    jnz ns_copy_digits
    mov edx, ebx
    mov eax, 254
    syscall
    jmp ns_value_effect
ns_remove_watch_effect:
    mov rax, [r12 + ns_PHASE]
    cmp rax, 13
    je ns_remove_admit
    cmp rax, 17
    jne main_contract_fail
ns_remove_admit:
    call ns_event_live
    mov rax, [r14 + 32]
    or rax, [r14 + 40]
    jnz main_contract_fail
    mov rsi, [r14 + 48]
    cmp rsi, 2147483647
    ja main_contract_fail
    mov eax, 255
    syscall
    jmp ns_zero_effect
ns_close_pin_effect:
    mov rax, [r12 + ns_PHASE]
    cmp rax, 14
    je ns_close_pin_admit
    cmp rax, 18
    je ns_close_pin_admit
    cmp rax, 19
    je ns_close_pin_admit
    cmp rax, 202
    jne main_contract_fail
ns_close_pin_admit:
    call ns_zero_span
    call ns_pin_index
    jmp ns_close_slot
ns_scan_open_effect:
    cmp qword ptr [r12 + ns_PHASE], 100
    jne main_contract_fail
    cmp qword ptr [r14 + 24], 261
    jne main_contract_fail
    cmp qword ptr [r15 + ns_FDS + 261*8], -1
    jne main_contract_fail
    cmp qword ptr [r14 + 32], ns_NAME
    jne main_contract_fail
    cmp qword ptr [r14 + 40], 1
    jne main_contract_fail
    cmp qword ptr [r12 + ns_NAME], 46
    jne main_contract_fail
    mov rax, [r14 + 48]
    cmp rax, [r12 + ns_DIRECTORY]
    jne main_contract_fail
    cmp rax, 258
    ja main_contract_fail
    mov rdi, [r15 + rax*8 + ns_FDS]
    test rdi, rdi
    js main_contract_fail
    lea rsi, [r12 + ns_NAME]
    mov edx, 0x90000
    xor r10d, r10d
    mov eax, 257
    syscall
    jmp ns_install_descriptor
ns_flags_effect:
    cmp qword ptr [r12 + ns_PHASE], 101
    jne main_contract_fail
    call ns_zero_span
    call ns_scan_live
    mov esi, 3
    xor edx, edx
    mov eax, 72
    syscall
    jmp ns_value_effect
ns_scan_stat_effect:
    cmp qword ptr [r12 + ns_PHASE], 102
    jne main_contract_fail
    call ns_scan_live
    call ns_stat_span
    mov eax, 5
    syscall
    jmp ns_zero_effect
ns_directory_effect:
    cmp qword ptr [r12 + ns_PHASE], 103
    jne main_contract_fail
    call ns_scan_live
    cmp qword ptr [r14 + 32], ns_DIRENTS
    jne main_contract_fail
    cmp qword ptr [r14 + 48], 0
    jne main_contract_fail
    mov rdx, [r14 + 40]
    cmp rdx, 32768
    jb main_contract_fail
    cmp rdx, 1048576
    ja main_contract_fail
    cmp rdx, [r12 + ns_SCAN_CAPACITY]
    jne main_contract_fail
    lea rsi, [r12 + ns_DIRENTS]
    mov eax, 217
    syscall
    jmp ns_value_effect
ns_close_scan_effect:
    mov rax, [r12 + ns_PHASE]
    cmp rax, 104
    je ns_close_scan_admit
    cmp rax, 105
    jne main_contract_fail
ns_close_scan_admit:
    call ns_zero_span
    call ns_scan_live
    mov ecx, 261
    jmp ns_close_slot
ns_close_borrow_effect:
    cmp qword ptr [r12 + ns_PHASE], 2
    jne main_contract_fail
    call ns_zero_span
    call ns_borrow_index
    test rcx, rcx
    jz main_contract_fail
    cmp qword ptr [r15 + rcx*8 + ns_FDS], -1
    je ns_acknowledge
ns_close_slot:
    mov rdi, [r15 + rcx*8 + ns_FDS]
    test rdi, rdi
    js main_contract_fail
    mov qword ptr [r15 + rcx*8 + ns_FDS], -1
    call ns_raw_descriptor_referenced
    test eax, eax
    jnz ns_acknowledge
    mov eax, 3
    syscall
    jmp ns_zero_effect
ns_raw_descriptor_referenced:
    xor ecx, ecx
ns_raw_reference_next:
    cmp [r15 + rcx*8 + ns_FDS], rdi
    je ns_raw_reference_yes
    inc ecx
    cmp ecx, ns_FDS_COUNT
    jb ns_raw_reference_next
    xor eax, eax
    ret
ns_raw_reference_yes:
    mov eax, 1
    ret
ns_retain_borrow_effect:
    cmp qword ptr [r12 + ns_PHASE], 15
    jne main_contract_fail
    cmp qword ptr [r12 + ns_OPERATION], 5
    jne main_contract_fail
    call ns_set_admit
    call ns_pin_index
    cmp qword ptr [r15 + rcx*8 + ns_FDS], -1
    jne main_contract_fail
    mov rax, [r14 + 32]
    or rax, [r14 + 40]
    jnz main_contract_fail
    mov rax, [r14 + 48]
    cmp rax, 258
    ja main_contract_fail
    cmp rax, [r12 + ns_DIRECTORY]
    jne main_contract_fail
    mov rax, [r15 + rax*8 + ns_FDS]
    test rax, rax
    js main_contract_fail
    mov [r15 + rcx*8 + ns_FDS], rax
    mov [r14 + 72], rcx
    jmp ns_acknowledge
ns_close_set_event_effect:
    cmp qword ptr [r12 + ns_PHASE], 201
    jne main_contract_fail
    call ns_zero_span
    call ns_set_admit
    call ns_event_live
    jmp ns_close_slot
ns_install_descriptor:
    test rax, rax
    js ns_effect_error
    cmp rax, 2147483647
    ja main_contract_fail
    mov rcx, [r14 + 24]
    cmp rcx, ns_FDS_COUNT
    jae main_contract_fail
    cmp qword ptr [r15 + rcx*8 + ns_FDS], -1
    jne main_contract_fail
    mov [r15 + rcx*8 + ns_FDS], rax
    mov [r14 + 72], rcx
    jmp ns_acknowledge
ns_zero_effect:
    test rax, rax
    js ns_effect_error
    jnz main_contract_fail
    jmp ns_acknowledge
ns_value_effect:
    test rax, rax
    js ns_effect_error
    mov [r14 + 72], rax
    jmp ns_acknowledge
ns_effect_error:
    cmp rax, -4095
    jb main_contract_fail
    neg rax
    mov [r14 + 80], rax
ns_acknowledge:
    mov rax, [r14 + 8]
    mov [r14 + 64], rax
    jmp ns_resume_namespace
ns_owner_result:
    cmp qword ptr [r12 + 4104], 0
    jne main_contract_fail
    cmp qword ptr [r12 + 4288], 0
    jne main_contract_fail
    cmp qword ptr [r12 + 4328], 0
    jne main_contract_fail
    cmp qword ptr [r15 + 16384 + 261*8], -1
    jne main_contract_fail
    cmp eax, 72
    jne main_contract_fail
    mov qword ptr [r15 + 16384], -1
    lea rdi, [r13 + MAIN_OWNER + M_REPLY]
    lea rsi, [r15 + 8192]
    mov ecx, eax
    rep movsb
    add rsp, 8
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret
