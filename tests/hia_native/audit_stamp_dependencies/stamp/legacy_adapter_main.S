.intel_syntax noprefix
.section .text
.global _start
.global legacy_call_displacement
.equ MAIN_INPUT, 4096
.equ MAIN_OUTPUT, 8192
.equ MAIN_OWNER, 1048576
.equ ANCHOR_BASE, 2097152
.equ NAMESPACE_BASE, 5242880
.equ ENTROPY_WORK, 15728640
.equ FINAL_GUARD, 16777216
.equ TOTAL_MAP, 16781312
.equ M_ACTION, 256
.equ M_STAT, 1024
.equ M_STATX, 3072
.equ M_TEMP, 4096
.equ M_LEGACY, 4352
.equ M_ANCHOR, 4608
.equ M_JSON, 6144
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
    mov ecx, 5
    mov rax, -1
    rep stosq
    mov qword ptr [r15 + ANCHOR_BASE + 128], -1
    mov qword ptr [r15 + ANCHOR_BASE + 136], -1
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
    mov edx, 0xb0000
    xor r10d, r10d
    mov eax, 257
    syscall
    test rax, rax
    js main_io_fail
    mov [r15 + 128], rax
    mov [r15 + ANCHOR_BASE + 128], rax
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
legacy_call_displacement:
    .long 0
    mov ecx, eax
    cmp rax, rcx
    jne main_contract_fail
    cmp eax, 0xfffffff0
    jne main_result
    lea r14, [r12 + M_ACTION]
    mov rax, 0x313030414c415248
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
    cmp rax, 1
    je main_open
    cmp rax, 2
    je main_fstat
    cmp rax, 3
    je main_mkdir
    cmp rax, 4
    je main_sync
    cmp rax, 5
    je main_uid
    cmp rax, 6
    je main_temp_open
    cmp rax, 7
    je main_close
    cmp rax, 8
    je main_statx
    cmp rax, 9
    je main_statx_probe
    cmp rax, 10
    je main_statat
    cmp rax, 11
    je main_statat_probe
    cmp rax, 12
    je main_write
    cmp rax, 13
    je main_link
    cmp rax, 14
    je main_unlink
    jmp main_contract_fail
main_zero_span:
    mov rax, [r14 + 32]
    or rax, [r14 + 40]
    or rax, [r14 + 48]
    jnz main_contract_fail
    ret
main_slot_live:
    mov rcx, [r14 + 24]
    cmp rcx, 2
    ja main_contract_fail
    mov rdi, [r15 + rcx*8 + 128]
    test rdi, rdi
    js main_contract_fail
    ret
main_legacy_name:
    cmp qword ptr [r14 + 32], M_LEGACY
    jne main_contract_fail
    cmp qword ptr [r14 + 40], 19
    jne main_contract_fail
    lea rsi, [r12 + M_LEGACY]
    mov rax, 0x2d74736575716572
    cmp [rsi], rax
    jne main_contract_fail
    mov rax, 0x2d65766968637261
    cmp [rsi + 8], rax
    jne main_contract_fail
    cmp dword ptr [rsi + 16], 0x00313176
    jne main_contract_fail
    ret
main_temp_name:
    cmp qword ptr [r14 + 32], M_TEMP
    jne main_contract_fail
    cmp qword ptr [r14 + 40], 84
    jne main_contract_fail
    lea rsi, [r12 + M_TEMP]
    mov rax, 0x657669686372612e
    cmp [rsi], rax
    jne main_contract_fail
    mov rax, 0x2d726f68636e612d
    cmp [rsi + 8], rax
    jne main_contract_fail
    mov ecx, 16
main_temp_digit:
    mov al, [rsi + rcx]
    cmp al, 48
    jb main_contract_fail
    cmp al, 57
    jbe main_temp_digit_ok
    cmp al, 97
    jb main_contract_fail
    cmp al, 102
    ja main_contract_fail
main_temp_digit_ok:
    inc ecx
    cmp ecx, 80
    jb main_temp_digit
    cmp dword ptr [rsi + 80], 0x706d742e
    jne main_contract_fail
    cmp byte ptr [rsi + 84], 0
    jne main_contract_fail
    ret
main_open:
    mov rax, [r12 + 8]
    cmp rax, 3
    je main_open_phase
    cmp rax, 6
    jne main_contract_fail
main_open_phase:
    cmp qword ptr [r14 + 24], 1
    jne main_contract_fail
    cmp qword ptr [r14 + 48], 0
    jne main_contract_fail
    cmp qword ptr [r15 + 136], -1
    jne main_contract_fail
    call main_legacy_name
    mov rdi, [r15 + 128]
    mov edx, 0xb0000
    xor r10d, r10d
    mov eax, 257
    syscall
    test rax, rax
    js main_error
    mov [r15 + 136], rax
    mov qword ptr [r14 + 72], 1
    jmp main_ack
main_mkdir:
    cmp qword ptr [r12 + 8], 4
    jne main_contract_fail
    cmp qword ptr [r14 + 24], 0
    jne main_contract_fail
    cmp qword ptr [r14 + 48], 448
    jne main_contract_fail
    call main_legacy_name
    mov rdi, [r15 + 128]
    mov edx, 448
    mov eax, 258
    syscall
    jmp main_zero
main_sync:
    call main_zero_span
    mov rax, [r12 + 8]
    cmp rax, 5
    je main_root_sync
    cmp rax, 16
    je main_root_sync
    cmp rax, 13
    jne main_contract_fail
    cmp qword ptr [r14 + 24], 2
    jne main_contract_fail
    jmp main_sync_live
main_root_sync:
    cmp qword ptr [r14 + 24], 0
    jne main_contract_fail
main_sync_live:
    call main_slot_live
    mov eax, 74
    syscall
    jmp main_zero
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
main_temp_open:
    cmp qword ptr [r12 + 8], 11
    jne main_contract_fail
    cmp qword ptr [r14 + 24], 2
    jne main_contract_fail
    cmp qword ptr [r14 + 48], 384
    jne main_contract_fail
    cmp qword ptr [r15 + 144], -1
    jne main_contract_fail
    call main_temp_name
    mov rdi, [r15 + 128]
    mov edx, 0xa00c1
    mov r10d, 384
    mov eax, 257
    syscall
    test rax, rax
    js main_error
    mov [r15 + 144], rax
    mov qword ptr [r14 + 72], 2
    jmp main_ack
main_close:
    call main_zero_span
    mov rax, [r12 + 8]
    cmp rax, 302
    je main_legacy_close
    cmp rax, 16
    je main_temp_close
    cmp rax, 301
    jne main_contract_fail
main_temp_close:
    cmp qword ptr [r14 + 24], 2
    jne main_contract_fail
    jmp main_close_live
main_legacy_close:
    cmp qword ptr [r14 + 24], 1
    jne main_contract_fail
main_close_live:
    call main_slot_live
    mov qword ptr [r15 + rcx*8 + 128], -1
    mov eax, 3
    syscall
    jmp main_zero
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
main_write:
    cmp qword ptr [r12 + 8], 12
    jne main_contract_fail
    cmp qword ptr [r14 + 24], 2
    jne main_contract_fail
    cmp qword ptr [r14 + 48], 0
    jne main_contract_fail
    mov rax, [r12 + 88]
    mov rdx, [r12 + 96]
    cmp rdx, 256
    ja main_contract_fail
    cmp rax, rdx
    jae main_contract_fail
    sub rdx, rax
    cmp rdx, [r14 + 40]
    jne main_contract_fail
    lea rsi, [rax + M_JSON]
    cmp rsi, [r14 + 32]
    jne main_contract_fail
    add rsi, r12
    mov rdi, [r15 + 144]
    test rdi, rdi
    js main_contract_fail
    mov eax, 1
    syscall
    jmp main_value
main_link:
    cmp qword ptr [r12 + 8], 14
    jne main_contract_fail
    cmp qword ptr [r14 + 24], 0
    jne main_contract_fail
    cmp qword ptr [r14 + 48], M_ANCHOR
    jne main_contract_fail
    call main_temp_name
    lea r10, [r12 + M_ANCHOR]
    mov rax, 0x747365757165722e
    cmp [r10], rax
    jne main_contract_fail
    mov rax, 0x657669686372612d
    cmp [r10 + 8], rax
    jne main_contract_fail
    mov rax, 0x636e612d3131762d
    cmp [r10 + 16], rax
    jne main_contract_fail
    mov rax, 0x6e6f736a2e726f68
    cmp [r10 + 24], rax
    jne main_contract_fail
    cmp byte ptr [r10 + 32], 0
    jne main_contract_fail
    mov rdi, [r15 + 128]
    mov rdx, rdi
    xor r8d, r8d
    mov eax, 265
    syscall
    jmp main_zero
main_unlink:
    mov rax, [r12 + 8]
    cmp rax, 15
    je main_unlink_phase
    cmp rax, 300
    jne main_contract_fail
main_unlink_phase:
    cmp qword ptr [r14 + 24], 0
    jne main_contract_fail
    cmp qword ptr [r14 + 48], 0
    jne main_contract_fail
    call main_temp_name
    mov rdi, [r15 + 128]
    xor edx, edx
    mov eax, 263
    syscall
    jmp main_zero
main_child:
    cmp qword ptr [r14 + 24], 0
    jne main_contract_fail
    cmp qword ptr [r14 + 32], M_REQUEST
    jne main_contract_fail
    cmp qword ptr [r14 + 48], M_REPLY
    jne main_contract_fail
    cmp rax, 100
    je main_anchor_call
    cmp rax, 101
    je main_namespace_call
    cmp rax, 102
    jne main_contract_fail
    cmp qword ptr [r12 + 8], 10
    jne main_contract_fail
    cmp qword ptr [r14 + 40], 24
    jne main_contract_fail
    cmp qword ptr [r14 + 56], 32
    jne main_contract_fail
    call entropy_entry
    jmp main_child_return
main_anchor_call:
    cmp qword ptr [r14 + 40], 32
    jne main_contract_fail
    cmp qword ptr [r14 + 56], 4096
    jne main_contract_fail
    mov rax, [r12 + 8]
    cmp rax, 2
    je main_anchor_phase
    cmp rax, 17
    je main_anchor_phase
    cmp rax, 303
    jne main_contract_fail
main_anchor_phase:
    call anchor_entry
    jmp main_child_return
main_namespace_call:
    cmp qword ptr [r12 + 8], 9
    jne main_contract_fail
    cmp qword ptr [r14 + 40], 32
    jne main_contract_fail
    cmp qword ptr [r14 + 56], 72
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
    cmp eax, 4096
    jbe main_normal_result
    cmp eax, 0xffffffff
    je main_result_header
    cmp eax, 0xfffffffe
    jne main_contract_fail
    jmp main_result_header
main_normal_result:
    cmp eax, 64
    jb main_contract_fail
    cmp qword ptr [r15 + 144], -1
    jne main_contract_fail
    cmp qword ptr [r12 + 144], 0
    jne main_contract_fail
    cmp qword ptr [r12 + 48], 0
    jne main_result_live
    cmp qword ptr [r15 + 136], -1
    jne main_contract_fail
    cmp qword ptr [r15 + ANCHOR_BASE + 136], -1
    jne main_contract_fail
    jmp main_result_header
main_result_live:
    cmp qword ptr [r12 + 48], 1
    jne main_contract_fail
    cmp qword ptr [r15 + 136], -1
    je main_contract_fail
    cmp qword ptr [r15 + ANCHOR_BASE + 136], -1
    je main_contract_fail
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
    mov ebx, 2
main_close_owned:
    mov rdi, [r15 + rbx*8 + 128]
    mov qword ptr [r15 + rbx*8 + 128], -1
    test rdi, rdi
    js main_close_next
    mov eax, 3
    syscall
main_close_next:
    dec ebx
    cmp ebx, 0
    jg main_close_owned
    mov rdi, [r15 + ANCHOR_BASE + 136]
    mov qword ptr [r15 + ANCHOR_BASE + 136], -1
    test rdi, rdi
    js main_close_entropy
    mov eax, 3
    syscall
main_close_entropy:
    mov ebx, 4
main_entropy_cleanup_loop:
    mov rdi, [r15 + rbx*8 + 128]
    mov qword ptr [r15 + rbx*8 + 128], -1
    test rdi, rdi
    js main_entropy_cleanup_next
    mov eax, 3
    syscall
main_entropy_cleanup_next:
    dec ebx
    cmp ebx, 3
    jge main_entropy_cleanup_loop
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
    lea rdi, [r15 + ENTROPY_WORK]
    xor eax, eax
    mov ecx, 128
    rep stosq
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
