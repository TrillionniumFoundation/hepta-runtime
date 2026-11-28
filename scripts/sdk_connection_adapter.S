/* Copyright 2026 Muvon Un Limited
 * Copyright 2026 TrillionniumFoundation
 * SPDX-License-Identifier: Apache-2.0
 * Fixed three-image transport fixture. Public protocol decisions stay in HIA.
 * The third image is an explicit SDK-default test handler, never production.
 */
.intel_syntax noprefix
.section .text
.global _start
.global message_call_displacement
.global connection_call_displacement
.global fixture_call_displacement
.equ RAW_CAP, 8388610
.equ LINE_CAP, 8388608
.equ PROJECT_CAP, 67108864
.equ ADMISSION_CAP, 134217728
.equ WIRE_CAP, 134217728
.equ OWNER_WORK_CAP, 268435456
.equ RAW, 4096
.equ MESSAGE_INPUT, 8396800
.equ PROJECTION, 16789504
.equ ADMISSION, 83902464
.equ WIRE, 218120192
.equ MESSAGE_WORK, 352337920
.equ CONNECTION_WORK, 620773376
.equ FIXTURE_WORK, 889208832
.equ MAP_BYTES, 889274368

/* Private fixed offsets: used0, scan8, consumed16, eof24, next32,
 * close40, wire pointer48, remaining56, projection length64, admission72. */
_start:
    cld
    cmp qword ptr [rsp], 1
    jne usage
    xor edi, edi
    mov esi, MAP_BYTES
    mov edx, 3
    mov r10d, 34
    mov r8, -1
    xor r9d, r9d
    mov eax, 9
    syscall
    cmp rax, -4095
    jae io_failure
    mov r15, rax
    mov byte ptr [r15 + 128], 10
read_more:
    mov rdx, RAW_CAP
    sub rdx, [r15]
    jz capacity_failure
    mov rsi, [r15]
    lea rsi, [r15 + rsi + RAW]
    xor edi, edi
    xor eax, eax
    syscall
    cmp rax, -4
    je read_more
    test rax, rax
    js io_failure
    jz at_eof
    add [r15], rax
scan:
    mov rax, [r15 + 8]
    cmp rax, [r15]
    jae compact
    cmp byte ptr [r15 + rax + RAW], 10
    je found_line
    inc qword ptr [r15 + 8]
    jmp scan
found_line:
    lea rdx, [rax + 1]
    mov [r15 + 32], rdx
    jmp prepare_line
at_eof:
    mov qword ptr [r15 + 24], 1
    mov rax, [r15]
    mov [r15 + 32], rax
    cmp rax, [r15 + 16]
    je close_owner
prepare_line:
    mov rsi, [r15 + 16]
    mov rcx, rax
    sub rcx, rsi
    lea rsi, [r15 + rsi + RAW]
    test rcx, rcx
    jz next_line
    cmp byte ptr [rsi + rcx - 1], 13
    jne line_ready
    dec rcx
line_ready:
    test rcx, rcx
    jz next_line
    cmp rcx, LINE_CAP
    ja capacity_failure
    mov [r15 + 80], rcx
    lea rdi, [r15 + MESSAGE_INPUT + 24]
    rep movsb
    lea rdi, [r15 + MESSAGE_INPUT]
    mov rax, 0x313030514a435248 /* HRCJQ001 */
    mov [rdi], rax
    mov qword ptr [rdi + 8], 1
    mov rsi, [r15 + 80]
    mov [rdi + 16], rsi
    add rsi, 24
    lea rdx, [r15 + PROJECTION + 24]
    mov ecx, PROJECT_CAP
    lea r8, [r15 + MESSAGE_WORK]
    mov r9d, OWNER_WORK_CAP
    .byte 0xe8
message_call_displacement: .long 0
    cmp eax, 0xfffffffe
    je capacity_failure
    cmp eax, 256
    jb native_failure
    cmp eax, PROJECT_CAP
    ja native_failure
    mov [r15 + 64], rax
    lea rdi, [r15 + PROJECTION]
    mov rdx, 0x313030514e435248 /* HRCNQ001 */
    mov [rdi], rdx
    mov qword ptr [rdi + 8], 1
    mov [rdi + 16], rax
    lea rsi, [rax + 24]
    jmp invoke_connection
close_owner:
    lea rdi, [r15 + PROJECTION]
    mov rax, 0x313030514e435248
    mov [rdi], rax
    mov qword ptr [rdi + 8], 2
    mov qword ptr [rdi + 16], 0
    mov esi, 24
invoke_connection:
    lea rdx, [r15 + ADMISSION]
    mov ecx, ADMISSION_CAP
    lea r8, [r15 + CONNECTION_WORK]
    mov r9d, OWNER_WORK_CAP
    .byte 0xe8
connection_call_displacement: .long 0
    cmp eax, 0xfffffffe
    je capacity_failure
    cmp eax, 256
    jb native_failure
    cmp eax, ADMISSION_CAP
    ja native_failure
    mov [r15 + 72], rax
    lea rbx, [r15 + ADMISSION]
    mov rdx, 0x313030534e435248 /* HRCNS001 */
    cmp [rbx], rdx
    jne native_failure
    mov rdx, [rbx + 16]
    cmp rdx, 1
    ja native_failure
    mov [r15 + 40], rdx
    mov rdx, [rbx + 8]
    cmp rdx, 6
    je success
    test rdx, rdx
    jz next_line
    cmp rdx, 1
    je direct_response
    cmp rdx, 5
    ja native_failure
    mov rdi, rbx
    mov rsi, rax
    lea rdx, [r15 + WIRE]
    mov ecx, WIRE_CAP
    lea r8, [r15 + FIXTURE_WORK]
    mov r9d, 65536
    .byte 0xe8
fixture_call_displacement: .long 0
    cmp eax, 0xfffffffe
    je capacity_failure
    cmp eax, WIRE_CAP
    ja native_failure
    mov [r15 + 56], rax
    lea rax, [r15 + WIRE]
    mov [r15 + 48], rax
    jmp write_response
direct_response:
    mov rdx, [rbx + 64]
    mov rcx, [rbx + 72]
    cmp rdx, 256
    jb native_failure
    cmp rdx, rax
    ja native_failure
    sub rax, rdx
    cmp rcx, rax
    ja native_failure
    lea rax, [rbx + rdx]
    mov [r15 + 48], rax
    mov [r15 + 56], rcx
write_response:
    cmp qword ptr [r15 + 56], 0
    je response_done
write_body:
    mov eax, 1
    mov edi, 1
    mov rsi, [r15 + 48]
    mov rdx, [r15 + 56]
    syscall
    cmp rax, -4
    je write_body
    test rax, rax
    jle io_failure
    add [r15 + 48], rax
    sub [r15 + 56], rax
    jne write_body
write_newline:
    mov eax, 1
    mov edi, 1
    lea rsi, [r15 + 128]
    mov edx, 1
    syscall
    cmp rax, -4
    je write_newline
    cmp rax, 1
    jne io_failure
response_done:
    cmp qword ptr [r15 + 40], 0
    jne success
next_line:
    mov rax, [r15 + 32]
    mov [r15 + 8], rax
    mov [r15 + 16], rax
    cmp qword ptr [r15 + 24], 0
    jne close_owner
    jmp scan
compact:
    mov rax, [r15 + 16]
    sub [r15], rax
    mov rcx, [r15]
    cmp rcx, RAW_CAP
    jae capacity_failure
    lea rdi, [r15 + RAW]
    lea rsi, [r15 + rax + RAW]
    rep movsb
    mov rax, [r15]
    mov [r15 + 8], rax
    mov qword ptr [r15 + 16], 0
    jmp read_more
success:
    xor edi, edi
    jmp terminate
native_failure:
    mov edi, 2
    jmp terminate
capacity_failure:
    mov edi, 3
    jmp terminate
io_failure:
    mov edi, 4
    jmp terminate
usage:
    mov edi, 64
terminate:
    mov eax, 60
    syscall
    ud2
