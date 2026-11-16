/* Copyright 2026 Muvon Un Limited
 * Copyright 2026 TrillionniumFoundation
 * SPDX-License-Identifier: Apache-2.0
 * Seventeen fixed HIA images. Immutable startup and SDK admission precede
 * three real configured routes. Global audit/result durability is separate.
 */
.intel_syntax noprefix
.section .text
.equ ROOT_INPUT_CAP, 16777216
.equ ROOT_OUTPUT_CAP, 134217728
.equ ROOT_WCAP, 268435456
.equ VALIDATION_WORK, 721424384
.equ LINK, 16908288
.equ INPUT, 4096
.equ OUTPUT, 16781312
.equ WORK, 150999040
.equ ROOT_WORK, 184553472
.equ JSON_WORK, 452988928
.equ SHA_WORK, 989859840
.equ MCP_WORK, 1258295296
.equ VALUE_WORK, 1526730752
.equ EXECUTION_WORK, 1795166208
.equ EXECUTION_JSON_WORK, 2063601664
.equ EXECUTION_CORE_WORK, 2332037120
.equ REGEX_CONTROLLER_WORK, 2600472576
.equ REGEX_SYNTAX_WORK, 2868908032
.equ REGEX_HIR_WORK, 3137343488
.equ REGEX_NFA_WORK, 3405778944
.equ REGEX_MATCH_WORK, 3674214400
.equ REGEX_DATA_WORK, 3707768832
.equ MESSAGE_INPUT, 3707834368
.equ PROJECTION, 3724615680
.equ ADMISSION, 3791728640
.equ CONNECTION_WORK, 3925946368
.equ MAP_BYTES, 4194381824
.equ REGEX_CONTEXTS, 2048
.equ REGEX_SEQUENCES, 2560
.equ CAP, 8388608
.equ WCAP, 33554432
.equ FOOTER, 268435200
.equ ACTION, 512
.equ STAT, 1024
.equ NAME, 8454144
.equ READ_AREA, 65536


_start:
    cld
    mov rbx, rsp
    xor edi, edi
    mov esi, MAP_BYTES
    mov edx, 3
    mov r10d, 34
    mov r8, -1
    xor r9d, r9d
    mov eax, 9
    syscall
    cmp rax, -4095
    jae bare_fatal
    mov r15, rax
    lea rax, [r15 + 1168]
    mov [r15 + 1176], rax
    cmp qword ptr [rbx], 3
    jne argv_fatal
    mov rdi, [rbx + 16]
    lea rsi, [rip + state_option]
    call cstr_equal
    test eax, eax
    jz argv_fatal
    mov rdi, [rbx + 24]
    mov [r15 + 704], rdi
    call cstr_length
    mov [r15 + 712], rax
    lea rax, [rbx + 40]
    mov [r15 + 648], rax
    lea rdi, [rip + env_state]
    call find_environment
    mov [r15 + 720], rax
    mov [r15 + 728], rdx
    test rax, rax
    jz environment_xdg
    or qword ptr [r15 + 640], 1
environment_xdg:
    lea rdi, [rip + env_xdg]
    call find_environment
    mov [r15 + 736], rax
    mov [r15 + 744], rdx
    test rax, rax
    jz environment_home
    or qword ptr [r15 + 640], 2
environment_home:
    lea rdi, [rip + env_home]
    call find_environment
    mov [r15 + 752], rax
    mov [r15 + 760], rdx
    test rax, rax
    jz environment_temp
    or qword ptr [r15 + 640], 4
environment_temp:
    lea rdi, [rip + env_temp]
    call find_environment
    mov [r15 + 768], rax
    mov [r15 + 776], rdx
    test rax, rax
    jz config_frame
    or qword ptr [r15 + 640], 8
config_frame:
    lea rdi, [r15 + INPUT]
    mov rax, 0x3130434746435248 /* HRCFGC01 */
    mov [rdi], rax
    mov rax, [r15 + 640]
    mov [rdi + 8], rax
    xor ebx, ebx
config_lengths:
    mov rax, rbx
    shl rax, 4
    mov rax, [r15 + rax + 712]
    mov [rdi + rbx*8 + 16], rax
    inc rbx
    cmp rbx, 5
    jne config_lengths
    mov qword ptr [rdi + 56], 0
    add rdi, 64
    xor ebx, ebx
config_bytes:
    mov rax, rbx
    shl rax, 4
    mov rsi, [r15 + rax + 704]
    mov rcx, [r15 + rax + 712]
    rep movsb
    inc rbx
    cmp rbx, 5
    jne config_bytes
    lea rax, [r15 + INPUT]
    sub rdi, rax
    mov [r15 + 24], rdi
    lea rax, [r15 + ROOT_WORK + FOOTER]
    mov qword ptr [rax + 120], 0
    jmp owner_resume

/* Framing is fixed; the two HIA owners make all public protocol decisions. */
frame_next:
    mov rcx, [r15 + 816]
    test rcx, rcx
    jz frame_scan
    mov rdx, [r15 + 800]
    cmp rcx, rdx
    ja fatal
    sub rdx, rcx
    lea rdi, [r15 + INPUT]
    lea rsi, [rdi + rcx]
    mov rcx, rdx
    rep movsb
    mov [r15 + 800], rdx
    mov qword ptr [r15 + 808], 0
    mov qword ptr [r15 + 816], 0
frame_scan:
    mov rcx, [r15 + 808]
    mov rdx, [r15 + 800]
    lea rsi, [r15 + INPUT]
frame_scan_byte:
    cmp rcx, rdx
    jae frame_need_input
    cmp byte ptr [rsi + rcx], 10
    je frame_found
    inc rcx
    jmp frame_scan_byte
frame_found:
    lea rax, [rcx + 1]
    mov [r15 + 816], rax
    jmp prepare_line
frame_need_input:
    mov [r15 + 808], rcx
    cmp qword ptr [r15 + 824], 0
    jne frame_final_line
    cmp rdx, 8388610
    jae fatal
    mov ecx, 8388610
    sub rcx, rdx
    cmp rcx, 65536
    jbe frame_read_bounded
    mov ecx, 65536
frame_read_bounded:
    add rsi, rdx
    mov rdx, rcx
    xor edi, edi
    xor eax, eax
    syscall
    cmp rax, -4
    je frame_scan
    cmp rax, -4095
    jae fatal
    test rax, rax
    jz frame_input_eof
    add [r15 + 800], rax
    jmp frame_scan
frame_input_eof:
    mov qword ptr [r15 + 824], 1
    jmp frame_scan
frame_final_line:
    test rdx, rdx
    jz frame_eof
    mov [r15 + 816], rdx
    mov rcx, rdx
prepare_line:
    test rcx, rcx
    jz frame_next
    lea rsi, [r15 + INPUT]
    cmp byte ptr [rsi + rcx - 1], 13
    jne line_ready
    dec rcx
line_ready:
    test rcx, rcx
    jz frame_next
    cmp rcx, 8388608
    ja fatal
    mov [r15 + 24], rcx
    mov edi, MESSAGE_INPUT + 24
    add rdi, r15
    rep movsb
    mov edi, MESSAGE_INPUT
    add rdi, r15
    mov rax, 0x313030514a435248 /* HRCJQ001 */
    mov [rdi], rax
    mov qword ptr [rdi + 8], 1
    mov rsi, [r15 + 24]
    mov [rdi + 16], rsi
    add rsi, 24
    mov edx, PROJECTION + 24
    add rdx, r15
    mov ecx, 67108864
    lea r8, [r15 + VALUE_WORK]
    mov r9d, ROOT_WCAP
    call qword ptr [rip + pub_image_message]
    cmp eax, 256
    jb fatal
    cmp eax, 67108864
    ja fatal
    mov edi, PROJECTION
    add rdi, r15
    mov rdx, 0x313030514e435248 /* HRCNQ001 */
    mov [rdi], rdx
    mov qword ptr [rdi + 8], 1
    mov [rdi + 16], rax
    lea rsi, [rax + 24]
    jmp invoke_connection
frame_eof:
    mov edi, PROJECTION
    add rdi, r15
    mov rax, 0x313030514e435248
    mov [rdi], rax
    mov qword ptr [rdi + 8], 2
    mov qword ptr [rdi + 16], 0
    mov esi, 24
invoke_connection:
    mov edx, ADMISSION
    add rdx, r15
    mov ecx, 134217728
    mov r8d, CONNECTION_WORK
    add r8, r15
    mov r9d, ROOT_WCAP
    call qword ptr [rip + pub_image_connection]
    cmp eax, 256
    jb fatal
    cmp eax, 134217728
    ja fatal
    mov [r15 + 904], rax
    mov ebx, ADMISSION
    add rbx, r15
    mov rdx, 0x313030534e435248
    cmp [rbx], rdx
    jne fatal
    mov rdx, [rbx + 16]
    cmp rdx, 1
    ja fatal
    mov [r15 + 912], rdx
    mov rdx, [rbx + 8]
    cmp rdx, 6
    je config_eof
    test rdx, rdx
    jz frame_next
    cmp rdx, 1
    je direct_response
    cmp rdx, 5
    ja fatal
    jmp mcp_resume
direct_response:
    mov rdx, [rbx + 64]
    mov rcx, [rbx + 72]
    cmp rdx, 256
    jb fatal
    cmp rdx, rax
    ja fatal
    sub rax, rdx
    cmp rcx, rax
    ja fatal
    lea rsi, [rbx + rdx]
    mov rdx, rcx
    jmp public_write
config_eof:
    jmp ex_shutdown
config_eof_original:
    mov qword ptr [r15 + 24], 0
    lea rax, [r15 + ROOT_WORK + FOOTER]
    mov qword ptr [rax + 120], 2
    jmp owner_resume

owner_resume:
    mov qword ptr [r15 + 80], 0
    lea r13, [r15 + INPUT]
    lea r12, [r15 + OUTPUT]
    mov rsi, [r15 + 24]
    mov ecx, ROOT_OUTPUT_CAP
    cmp qword ptr [r15 + 784], 0
    je owner_context_ready
    mov r13, [r15 + 832]
    mov rsi, [r15 + 840]
    mov r12, [r15 + 848]
    mov rcx, [r15 + 856]
owner_context_ready:
    lea r14, [r15 + ROOT_WORK]
    mov rdi, r13
    mov rdx, r12
    mov r8, r14
    mov r9d, ROOT_WCAP
    call qword ptr [rip + pub_image_owner]
    jmp native_return
mcp_resume:
    mov qword ptr [r15 + 80], 5
    mov r13d, ADMISSION
    add r13, r15
    lea r12, [r15 + OUTPUT]
    lea r14, [r15 + MCP_WORK]
    mov rdi, r13
    mov rsi, [r15 + 904]
    mov rdx, r12
    mov ecx, ROOT_OUTPUT_CAP
    mov r8, r14
    mov r9d, ROOT_WCAP
    call qword ptr [rip + pub_image_mcp]
    jmp native_return
native_resume:
    cmp qword ptr [r15 + 80], 1
    jne fatal
    mov rdi, r13
    mov rsi, [r15 + 96]
    mov rdx, r12
    mov rcx, [r15 + 104]
    mov r8, r14
    mov r9d, WCAP
    call qword ptr [rip + pub_image_fs]
    jmp native_return
json_resume:
    lea r14, [r15 + JSON_WORK]
    mov rdi, r13
    mov rsi, [r15 + 96]
    mov rdx, r12
    mov rcx, [r15 + 104]
    mov r8, r14
    mov r9d, ROOT_WCAP
    call qword ptr [rip + pub_image_json]
    jmp native_return
identity_resume:
    lea r14, [r15 + SHA_WORK]
    mov rdi, r13
    mov rsi, [r15 + 96]
    mov rdx, r12
    mov rcx, [r15 + 104]
    mov r8, r14
    mov r9d, ROOT_WCAP
    call qword ptr [rip + pub_image_identity]
    jmp native_return
validation_resume:
    lea r14, [r15 + REGEX_CONTEXTS]
    mov qword ptr [r14], 3
    mov [r14 + 8], r13
    mov rax, [r15 + 96]
    mov [r14 + 16], rax
    mov [r14 + 24], r12
    mov rax, [r15 + 104]
    mov [r14 + 32], rax
    lea rax, [r15 + VALIDATION_WORK]
    mov [r14 + 40], rax
    mov qword ptr [r14 + 48], ROOT_WCAP
    xor r12d, r12d
    jmp regex_invoke
native_return:
    mov edx, eax
    cmp rax, rdx
    jne fatal
    mov edx, 0xffffffe0
    cmp rax, rdx
    je call_dispatch
    mov edx, 0xfffffff0
    cmp rax, rdx
    je effect_dispatch_checked
    cmp qword ptr [r15 + 80], 5
    je mcp_completed
    cmp qword ptr [r15 + 80], 6
    je execution_completed
    cmp qword ptr [r15 + 80], 7
    je execution_child_completed
    cmp qword ptr [r15 + 80], 8
    je execution_child_completed
    cmp qword ptr [r15 + 80], 0
    jne child_completed
    cmp qword ptr [r15 + 784], 0
    jne mcp_owner_completed
    cmp rax, ROOT_OUTPUT_CAP
    ja fatal
    cmp qword ptr [r14 + FOOTER + 120], 2
    je shutdown_completed
    cmp qword ptr [r14 + FOOTER + 120], 0
    je startup_completed
    jmp fatal /* No external binary-query production path. */
mcp_completed:
    cmp rax, ROOT_OUTPUT_CAP
    ja fatal
    cmp eax, 8
    jb ex_mcp_untyped
    mov rdx, 0x3153455243505248
    cmp [r15 + OUTPUT], rdx
    je ex_wire
ex_mcp_untyped:
    mov rdx, rax
    lea rsi, [r15 + OUTPUT]
public_write:
    test rdx, rdx
    jz public_written
    mov edi, 1
    call write_exact
    test eax, eax
    jnz fatal
    mov edi, 1
    lea rsi, [rip + newline]
    mov edx, 1
    call write_exact
    test eax, eax
    jnz fatal
public_written:
    cmp qword ptr [r15 + 912], 0
    jne config_eof
    jmp frame_next
mcp_owner_completed:
    cmp qword ptr [r15 + 784], 3
    je ex_config_return
    cmp rax, [r15 + 856]
    ja fatal
    cmp qword ptr [r15 + 784], 2
    je execution_owner_completed
    lea rdx, [r15 + MCP_WORK + FOOTER]
    mov [rdx + 80], rax
    mov rax, [r15 + 792]
    mov [rdx + 88], rax
    mov qword ptr [rdx + 96], 1
    mov qword ptr [r15 + 784], 0
    jmp mcp_resume
startup_completed:
    test eax, eax
    jz ex_initialize
    cmp rax, 32
    jb fatal
    lea rsi, [r15 + OUTPUT]
    mov rdx, 0x31304d4746435248 /* HRCFGM01 */
    cmp [rsi], rdx
    jne fatal
    sub rax, 32
    cmp [rsi + 24], rax
    jne fatal
    mov rdx, rax
    add rsi, 32
    mov edi, 2
    call write_exact
    mov edi, 2
    lea rsi, [rip + newline]
    mov edx, 1
    call write_exact
    mov ebp, 78
    jmp cleanup_all
shutdown_completed:
    test eax, eax
    jnz fatal
    jmp finish_ok
effect_dispatch_checked:
    cmp qword ptr [r15 + 80], 1
    jne fatal
    jmp effect_dispatch

child_completed:
    mov edx, 0xffff0000
    cmp rax, rdx
    jae child_result_ok
    cmp rax, [r15 + 104]
    ja fatal
child_result_ok:
    lea rdx, [r15 + ROOT_WORK + FOOTER]
    mov [rdx + 80], rax
    mov rax, [r15 + 88]
    mov [rdx + 88], rax
    mov qword ptr [rdx + 96], 1
    jmp owner_resume

/* Closed calls from registry5 to installed config0 and execution6.
 * Execution6 can call only JSON7, config0/op4 and core8. No caller-supplied
 * table, code address, configuration event, file descriptor or syscall. */
mcp_call_dispatch:
    cmp qword ptr [r15 + 784], 0
    jne fatal
    cmp qword ptr [r15 + 872], 0
    jne fatal
    lea rdx, [r15 + MCP_WORK + FOOTER]
    mov rax, 0x31304c4143414948
    cmp [rdx], rax
    jne fatal
    mov rax, [r15 + 792]
    inc rax
    jz fatal
    cmp [rdx + 8], rax
    jne fatal
    mov [r15 + 792], rax
    cmp qword ptr [rdx + 24], 2
    jne fatal
    cmp qword ptr [rdx + 48], 2
    jne fatal
    cmp qword ptr [rdx + 64], 67108864
    jne fatal
    mov rax, [rdx + 72]
    or rax, [rdx + 80]
    or rax, [rdx + 88]
    or rax, [rdx + 96]
    or rax, [rdx + 104]
    jnz fatal
    mov rax, [rdx + 16]
    cmp qword ptr [rdx + 56], 100667392
    jne fatal
    cmp rax, 6
    je mcp_execution_call
    test rax, rax
    jnz fatal
    cmp qword ptr [rdx + 32], 33550336
    jne fatal
    cmp qword ptr [rdx + 40], 24
    jne fatal
    lea rax, [r15 + MCP_WORK + 33550336]
    mov rdx, 0x3130514746435248
    cmp [rax], rdx
    jne fatal
    cmp qword ptr [rax + 8], 1
    jb fatal
    cmp qword ptr [rax + 8], 2
    ja fatal
    cmp qword ptr [rax + 16], 0
    jne fatal
    mov [r15 + 832], rax
    mov qword ptr [r15 + 840], 24
    lea rax, [r15 + MCP_WORK + 100667392]
    mov [r15 + 848], rax
    mov qword ptr [r15 + 856], 67108864
    mov qword ptr [r15 + 784], 1
    lea rax, [r15 + ROOT_WORK + FOOTER]
    mov qword ptr [rax + 120], 1
    jmp owner_resume

mcp_execution_call:
    cmp qword ptr [rdx + 32], 33554432
    jne fatal
    mov rsi, [rdx + 40]
    cmp rsi, 26
    jb fatal
    cmp rsi, 67108864
    ja fatal
    lea r13, [r15 + MCP_WORK + 33554432]
    mov rax, 0x3130514552535848
    cmp [r13], rax
    jne fatal
    cmp qword ptr [r13 + 8], 1
    jb fatal
    cmp qword ptr [r13 + 8], 3
    ja fatal
    mov rax, rsi
    sub rax, 24
    cmp [r13 + 16], rax
    jne fatal
    mov [r15 + 880], rsi
    jmp ex_begin
execution_resume:
    cmp qword ptr [r15 + 872], 1
    jne fatal
    mov qword ptr [r15 + 80], 6
    lea r13, [r15 + MCP_WORK + 33554432]
    lea r12, [r15 + MCP_WORK + 100667392]
    mov r14d, EXECUTION_WORK
    add r14, r15
    mov rdi, r13
    mov rsi, [r15 + 880]
    mov rdx, r12
    mov ecx, 67108864
    mov r8, r14
    mov r9d, ROOT_WCAP
    call qword ptr [rip + pub_image_execution]
    jmp native_return

execution_call_dispatch:
    cmp qword ptr [r15 + 872], 1
    jne fatal
    cmp qword ptr [r15 + 784], 0
    jne fatal
    mov edx, EXECUTION_WORK + FOOTER
    add rdx, r15
    mov rax, 0x31304c4143414948
    cmp [rdx], rax
    jne fatal
    mov rax, [r15 + 864]
    inc rax
    jz fatal
    cmp [rdx + 8], rax
    jne fatal
    mov [r15 + 864], rax
    cmp qword ptr [rdx + 24], 2
    jne fatal
    cmp qword ptr [rdx + 48], 2
    jne fatal
    cmp qword ptr [rdx + 64], 67108864
    jne fatal
    mov rax, [rdx + 72]
    or rax, [rdx + 80]
    or rax, [rdx + 88]
    or rax, [rdx + 96]
    or rax, [rdx + 104]
    jnz fatal
    mov rcx, [rdx + 40]
    cmp rcx, 67108864
    ja fatal
    mov [r15 + 888], rcx
    mov rax, [rdx + 16]
    cmp rax, 7
    je execution_json_call
    cmp qword ptr [rdx + 56], 134234112
    jne fatal
    cmp rax, 8
    je execution_core_call
    test rax, rax
    jnz fatal
    cmp qword ptr [rdx + 32], 4096
    jne fatal
    cmp rcx, 24
    jb fatal
    mov eax, EXECUTION_WORK + 4096
    add rax, r15
    mov rdx, 0x3130514746435248
    cmp [rax], rdx
    jne fatal
    cmp qword ptr [rax + 8], 4
    jne fatal
    sub rcx, 24
    cmp [rax + 16], rcx
    jne fatal
    mov [r15 + 832], rax
    add rcx, 24
    mov [r15 + 840], rcx
    mov eax, EXECUTION_WORK + 134234112
    add rax, r15
    mov [r15 + 848], rax
    mov qword ptr [r15 + 856], 67108864
    mov qword ptr [r15 + 784], 2
    lea rax, [r15 + ROOT_WORK + FOOTER]
    mov qword ptr [rax + 120], 1
    jmp owner_resume

execution_json_call:
    cmp qword ptr [rdx + 32], 4096
    jne fatal
    cmp qword ptr [rdx + 56], 67117056
    jne fatal
    mov r13d, EXECUTION_WORK + 4096
    add r13, r15
    mov r12d, EXECUTION_WORK + 67117056
    add r12, r15
    mov r14d, EXECUTION_JSON_WORK
    add r14, r15
    mov qword ptr [r15 + 80], 7
    mov rdi, r13
    mov rsi, [r15 + 888]
    mov rdx, r12
    mov ecx, 67108864
    mov r8, r14
    mov r9d, ROOT_WCAP
    call qword ptr [rip + pub_image_execution_json]
    jmp native_return

execution_core_call:
    cmp qword ptr [rdx + 32], 67117056
    jne fatal
    mov r13d, EXECUTION_WORK + 67117056
    add r13, r15
    mov r12d, EXECUTION_WORK + 134234112
    add r12, r15
    mov r14d, EXECUTION_CORE_WORK
    add r14, r15
    mov qword ptr [r15 + 80], 8
    mov rdi, r13
    mov rsi, [r15 + 888]
    mov rdx, r12
    mov ecx, 67108864
    mov r8, r14
    mov r9d, ROOT_WCAP
    call qword ptr [rip + pub_image_execution_core]
    jmp native_return

execution_owner_completed:
    cmp qword ptr [r15 + 872], 1
    jne fatal
    mov qword ptr [r15 + 784], 0
execution_child_completed:
    cmp qword ptr [r15 + 872], 1
    jne fatal
    mov edx, 0xfffffffe
    cmp rax, rdx
    jae execution_child_status
    cmp rax, 67108864
    ja fatal
execution_child_status:
    mov edx, EXECUTION_WORK + FOOTER
    add rdx, r15
    mov [rdx + 80], rax
    mov rax, [r15 + 864]
    mov [rdx + 88], rax
    mov qword ptr [rdx + 96], 1
    jmp execution_resume

execution_completed:
    cmp qword ptr [r15 + 872], 1
    jne fatal
    mov qword ptr [r15 + 872], 0
    jmp ex_execution_completed
mcp_child_completed:
    mov edx, 0xfffffffe
    cmp rax, rdx
    jae mcp_child_status
    cmp rax, 67108864
    ja fatal
mcp_child_status:
    lea rdx, [r15 + MCP_WORK + FOOTER]
    mov [rdx + 80], rax
    mov rax, [r15 + 792]
    mov [rdx + 88], rax
    mov qword ptr [rdx + 96], 1
    jmp mcp_resume

call_dispatch:
    cmp qword ptr [r15 + 80], 6
    je execution_call_dispatch
    cmp qword ptr [r15 + 80], 5
    je mcp_call_dispatch
    cmp qword ptr [r15 + 80], 0
    jne fatal
    lea rdx, [r15 + ROOT_WORK + FOOTER]
    mov rax, 0x31304c4143414948 /* HIACAL01 */
    cmp [rdx], rax
    jne fatal
    mov rax, [r15 + 88]
    inc rax
    jz fatal
    cmp [rdx + 8], rax
    jne fatal
    mov [r15 + 88], rax
    mov rax, [rdx + 72]
    or rax, [rdx + 80]
    or rax, [rdx + 88]
    or rax, [rdx + 96]
    or rax, [rdx + 104]
    jnz fatal
    mov rax, [rdx + 16]
    cmp rax, 1
    jb fatal
    cmp rax, 4
    ja fatal
    mov [r15 + 80], rax
    cmp qword ptr [rdx + 24], 2
    jne fatal
    cmp qword ptr [rdx + 48], 2
    jne fatal
    mov rax, [rdx + 32]
    cmp rax, FOOTER
    ja fatal
    mov rcx, FOOTER
    sub rcx, rax
    mov r8, [rdx + 40]
    cmp r8, rcx
    ja fatal
    cmp r8, ROOT_OUTPUT_CAP
    ja fatal
    mov [r15 + 96], r8
    lea r13, [r15 + ROOT_WORK]
    add r13, rax
    mov rax, [rdx + 56]
    cmp rax, FOOTER
    ja fatal
    mov rcx, FOOTER
    sub rcx, rax
    mov r9, [rdx + 64]
    cmp r9, rcx
    ja fatal
    cmp r9, ROOT_OUTPUT_CAP
    ja fatal
    mov [r15 + 104], r9
    lea r12, [r15 + ROOT_WORK]
    add r12, rax
    test r8, r8
    jz spans_disjoint
    test r9, r9
    jz spans_disjoint
    lea rax, [r13 + r8]
    cmp r12, rax
    jae spans_disjoint
    lea rax, [r12 + r9]
    cmp r13, rax
    jb fatal
spans_disjoint:
    cmp qword ptr [r15 + 80], 1
    je start_fs
    cmp qword ptr [r15 + 80], 2
    je start_json
    cmp qword ptr [r15 + 80], 3
    je validation_resume
    jmp identity_resume
start_fs:
    cmp qword ptr [r15 + 96], CAP
    ja fatal
    cmp qword ptr [r15 + 104], CAP
    ja fatal
    lea r14, [r15 + WORK]
    jmp native_resume
start_json:
    cmp qword ptr [r15 + 96], 16777216
    ja fatal
    cmp qword ptr [r15 + 104], 67108864
    ja fatal
    jmp json_resume

/* Startup reads only the original process argv/environment. No frame can
 * select, reload or overwrite these lifecycle inputs. */
cstr_equal:
    xor ecx, ecx
cstr_equal_next:
    mov al, [rdi + rcx]
    cmp al, [rsi + rcx]
    jne cstr_not_equal
    test al, al
    jz cstr_is_equal
    inc rcx
    jmp cstr_equal_next
cstr_not_equal:
    xor eax, eax
    ret
cstr_is_equal:
    mov eax, 1
    ret
cstr_length:
    xor eax, eax
cstr_length_next:
    cmp byte ptr [rdi + rax], 0
    je cstr_length_done
    inc rax
    cmp rax, 131071
    ja argv_fatal
    jmp cstr_length_next
cstr_length_done:
    ret
find_environment:
    mov r9, rdi
    mov r8, [r15 + 648]
environment_next:
    mov rdi, [r8]
    test rdi, rdi
    jz environment_absent
    xor ecx, ecx
environment_compare:
    mov al, [r9 + rcx]
    test al, al
    jz environment_equals
    cmp al, [rdi + rcx]
    jne environment_advance
    inc rcx
    jmp environment_compare
environment_equals:
    cmp byte ptr [rdi + rcx], 61
    jne environment_advance
    lea r10, [rdi + rcx + 1]
    mov rdi, r10
    call cstr_length
    mov rdx, rax
    mov rax, r10
    ret
environment_advance:
    add r8, 8
    jmp environment_next
environment_absent:
    xor eax, eax
    xor edx, edx
    ret
argv_fatal:
    mov ebp, 64
    jmp cleanup_all

state_option:
    .asciz "--runtime-config"
env_state:
    .asciz "HEPTA_RUNTIME_STATE_DIR"
env_xdg:
    .asciz "XDG_STATE_HOME"
env_home:
    .asciz "HOME"
env_temp:
    .asciz "TMPDIR"
newline:
    .byte 10

/* Only fixed configuration-installation effects are admitted here. HIA owns
 * their ordering, pathname construction, metadata checks and cleanup policy. */
effect_dispatch:
    mov rax, 0x3130415346435248 /* HRCFSA01 */
    cmp [r14 + ACTION], rax
    jne fatal
    mov rax, [r15 + 16]
    inc rax
    jz fatal
    cmp [r14 + ACTION + 8], rax
    jne fatal
    mov [r15 + 16], rax
    mov rax, [r14 + ACTION + 56]
    or rax, [r14 + ACTION + 64]
    or rax, [r14 + ACTION + 72]
    or rax, [r14 + ACTION + 80]
    or rax, [r14 + ACTION + 88]
    or rax, [r14 + ACTION + 96]
    or rax, [r14 + ACTION + 104]
    or rax, [r14 + ACTION + 112]
    or rax, [r14 + ACTION + 120]
    jnz fatal
    mov rax, [r14 + ACTION + 16]
    mov [r15 + 48], rax
    cmp rax, 1
    je effect_mkdir
    cmp qword ptr [r14 + ACTION + 32], 0
    jne fatal
    cmp rax, 2
    je effect_stat_path
    cmp rax, 3
    je effect_stat_path
    cmp rax, 4
    je effect_readlink
    cmp rax, 5
    je effect_open_lock
    cmp rax, 6
    je effect_stat_fd
    cmp rax, 7
    je effect_uid
    cmp rax, 8
    je effect_chmod_fd
    cmp rax, 9
    je effect_try_lock
    cmp rax, 10
    je effect_chmod_path
    cmp rax, 11
    je effect_close
    cmp rax, 12
    je effect_open_read
    cmp rax, 13
    je effect_read
    jmp fatal

zero_span:
    mov rax, [r14 + ACTION + 40]
    or rax, [r14 + ACTION + 48]
    jnz fatal
    ret
no_handle:
    cmp qword ptr [r14 + ACTION + 24], 0
    jne fatal
    ret
path_span:
    call no_handle
    cmp qword ptr [r14 + ACTION + 40], NAME
    jne fatal
    mov rcx, [r14 + ACTION + 48]
    cmp rcx, CAP
    jae fatal
    lea rsi, [r14 + NAME]
    cmp byte ptr [rsi + rcx], 0
    jne fatal
    xor edx, edx
path_no_nul:
    cmp rdx, rcx
    je path_nul_checked
    cmp byte ptr [rsi + rdx], 0
    je fatal
    inc rdx
    jmp path_no_nul
path_nul_checked:
    ret

effect_mkdir:
    mov rax, [r14 + ACTION + 32]
    cmp rax, 448
    je mkdir_mode_checked
    cmp rax, 511
    jne fatal
mkdir_mode_checked:
    call path_span
    mov rdi, -100
    mov rdx, [r14 + ACTION + 32]
    mov eax, 258
    syscall
    jmp acknowledge
effect_stat_path:
    call path_span
    mov rdi, -100
    lea rdx, [r14 + STAT]
    xor r10d, r10d
    cmp qword ptr [r15 + 48], 3
    jne stat_path_ready
    mov r10d, 256
stat_path_ready:
    mov eax, 262
    syscall
    jmp acknowledge
effect_readlink:
    call path_span
    mov rdi, -100
    lea rdx, [r14 + LINK]
    mov r10d, 1048576
    mov eax, 267
    syscall
    jmp acknowledge
effect_open_lock:
    call path_span
open_lock_retry:
    mov rdi, -100
    mov edx, 0xa0842 /* RDWR|CREAT|NOFOLLOW|CLOEXEC|NONBLOCK, never truncate. */
    mov r10d, 384
    mov eax, 257
    syscall
    cmp rax, -4
    je open_lock_retry
    jmp register_result
effect_open_read:
    call path_span
open_read_retry:
    mov rdi, -100
    mov edx, 0x80000 /* RDONLY|CLOEXEC; std::fs::read follows paths. */
    xor r10d, r10d
    mov eax, 257
    syscall
    cmp rax, -4
    je open_read_retry
    jmp register_result
effect_read:
    mov rax, [r14 + ACTION + 40]
    cmp rax, 65536
    jb fatal
    cmp rax, 8454080
    ja fatal
    mov rdx, [r14 + ACTION + 48]
    test rdx, rdx
    jz fatal
    cmp rdx, 65536
    ja fatal
    add rax, rdx
    cmp rax, 8454081
    ja fatal
    mov rdi, [r14 + ACTION + 24]
    call lookup
    mov rdi, rdx
    mov rsi, [r14 + ACTION + 40]
    add rsi, r14
    mov rdx, [r14 + ACTION + 48]
    xor eax, eax
    syscall
    jmp acknowledge
effect_stat_fd:
    call zero_span
    mov rdi, [r14 + ACTION + 24]
    call lookup
    mov rdi, rdx
    lea rsi, [r14 + STAT]
    mov rdx, [r15 + EX_META_ADDRESS]
    test rdx, rdx
    jz fatal
    call tk_intent_file_metadata
    jmp acknowledge
effect_uid:
    call zero_span
    call no_handle
    mov eax, 107
    syscall
    jmp acknowledge
effect_chmod_fd:
    call zero_span
    mov rdi, [r14 + ACTION + 24]
    call lookup
    mov rdi, rdx
    mov esi, 384
    mov eax, 91
    syscall
    jmp acknowledge
effect_try_lock:
    call zero_span
    mov rdi, [r14 + ACTION + 24]
    call lookup
    mov rdi, rdx
    mov esi, 6 /* LOCK_EX|LOCK_NB */
    mov eax, 73
    syscall
    jmp acknowledge
effect_chmod_path:
    call path_span
    mov rdi, -100
    mov edx, 448
    mov eax, 268
    syscall
    jmp acknowledge
effect_close:
    call zero_span
    mov rdi, [r14 + ACTION + 24]
    call retire_close
    jmp acknowledge

register_result:
    cmp rax, -4095
    jae acknowledge
    call register_fd
acknowledge:
    xor edx, edx
    cmp rax, -4095
    jb ack_value
    neg rax
    mov rdx, rax
    xor eax, eax
ack_value:
    mov [r14 + ACTION + 72], rdx
    mov [r14 + ACTION + 80], rax
    mov rax, [r15 + 16]
    mov [r14 + ACTION + 64], rax
    jmp native_resume

/* lookup(id) -> host-owned node and raw fd. No caller pointer is used. */
lookup:
    test rdi, rdi
    jz fatal
    mov rax, [r15]
lookup_next:
    test rax, rax
    jz fatal
    cmp [rax + 8], rdi
    je lookup_found
    mov rax, [rax]
    jmp lookup_next
lookup_found:
    mov rdx, [rax + 16]
    ret

register_fd:
    push rax
    cmp qword ptr [r15 + 8], -1
    je register_overflow
    xor edi, edi
    mov esi, 4096
    mov edx, 3
    mov r10d, 34
    mov r8, -1
    xor r9d, r9d
    mov eax, 9
    syscall
    cmp rax, -4095
    jae register_failed
    mov rcx, [r15]
    mov [rax], rcx
    mov rcx, [r15 + 8]
    inc rcx
    mov [r15 + 8], rcx
    mov [rax + 8], rcx
    pop rdx
    mov [rax + 16], rdx
    mov [r15], rax
    mov rax, rcx
    ret
register_overflow:
    mov rax, -75
register_failed:
    pop rdi
    push rax
    mov eax, 3
    syscall
    pop rax
    ret

retire_close:
    lea r8, [r15]
    mov rax, [r8]
retire_next:
    test rax, rax
    jz fatal
    cmp [rax + 8], rdi
    je retire_found
    mov r8, rax
    mov rax, [rax]
    jmp retire_next
retire_found:
    mov rcx, [rax]
    mov [r8], rcx
    push qword ptr [rax + 16]
    mov rdi, rax
    mov esi, 4096
    mov eax, 11
    syscall
    pop rdi
    mov eax, 3
    syscall
    ret

/* 0 complete; 1 EOF before bytes; 2 truncated/error. */
read_exact:
    mov r8, rdx
read_again:
    test rdx, rdx
    jz exact_ok
    xor eax, eax
    syscall
    cmp rax, -4
    je read_again
    test rax, rax
    js exact_error
    jz exact_eof
    add rsi, rax
    sub rdx, rax
    jmp read_again
exact_eof:
    mov eax, 1
    cmp rdx, r8
    je exact_return
exact_error:
    mov eax, 2
exact_return:
    ret
exact_ok:
    xor eax, eax
    ret
write_exact:
    test rdx, rdx
    jz exact_ok
write_again:
    mov eax, 1
    syscall
    cmp rax, -4
    je write_again
    test rax, rax
    jle exact_error
    add rsi, rax
    sub rdx, rax
    jnz write_again
    jmp exact_ok

finish_ok:
    xor ebp, ebp
    jmp cleanup_all
fatal:
    mov ebp, 111
cleanup_all:
    mov rbx, [r15]
    test rbx, rbx
    jz process_exit
    mov rax, [rbx]
    mov [r15], rax
    mov rdi, [rbx + 16]
    mov eax, 3
    syscall
    mov rdi, rbx
    mov esi, 4096
    mov eax, 11
    syscall
    jmp cleanup_all
process_exit:
    mov edi, ebp
    mov eax, 231
    syscall
bare_fatal:
    mov edi, 112
    mov eax, 231
    syscall

/* HIA regex-only child subtree; no descriptor or effect capability. */
regex_invoke:
    mov rax, r12
    shl rax, 6
    lea r14, [r15 + rax + REGEX_CONTEXTS]
    mov rdi, [r14 + 8]
    mov rsi, [r14 + 16]
    mov rdx, [r14 + 24]
    mov rcx, [r14 + 32]
    mov r8, [r14 + 40]
    mov r9, [r14 + 48]
    mov rax, [r14]
    cmp eax, 3
    je regex_invoke3
    cmp eax, 15
    je regex_invoke15
    cmp eax, 10
    je regex_invoke10
    cmp eax, 12
    je regex_invoke12
    cmp eax, 13
    je regex_invoke13
    cmp eax, 14
    je regex_invoke14
    cmp eax, 11
    jne fatal
    call qword ptr [rip + pub_image_regex_unicode_data]
    jmp regex_returned
regex_invoke3:
    call qword ptr [rip + pub_image_validation]
    jmp regex_returned
regex_invoke15:
    call qword ptr [rip + pub_image_regex_controller]
    jmp regex_returned
regex_invoke10:
    call qword ptr [rip + pub_image_regex_syntax]
    jmp regex_returned
regex_invoke12:
    call qword ptr [rip + pub_image_regex_hir]
    jmp regex_returned
regex_invoke13:
    call qword ptr [rip + pub_image_regex_nfa]
    jmp regex_returned
regex_invoke14:
    call qword ptr [rip + pub_image_regex_match]
regex_returned:
    mov edx, eax
    cmp rax, rdx
    jne fatal
    cmp eax, 0xffffffe0
    je regex_child_call
    cmp eax, 0xffff0000
    jae regex_completed_child
    cmp rax, [r14 + 32]
    ja fatal
regex_completed_child:
    test r12, r12
    jz regex_root_result
    dec r12
    sub r14, 64
    mov rbx, [r14 + 40]
    add rbx, [r14 + 48]
    sub rbx, 256
    mov [rbx + 80], rax
    mov rcx, [rbx + 8]
    mov [rbx + 88], rcx
    mov qword ptr [rbx + 96], 1
    mov qword ptr [rbx + 104], 0
    jmp regex_invoke
regex_root_result:
    mov r13, [r14 + 8]
    mov r12, [r14 + 24]
    mov r14, [r14 + 40]
    jmp native_return

regex_child_call:
    cmp r12, 3
    jae fatal
    mov rbx, [r14 + 40]
    mov rcx, [r14 + 48]
    lea rbx, [rbx + rcx - 256]
    mov rax, 0x31304c4143414948
    cmp [rbx], rax
    jne fatal
    mov r10, [r14]
    mov r11, [rbx + 16]
    cmp r10, 3
    je regex_validation_edge
    cmp r10, 15
    je regex_root_edge
    cmp r10, 10
    je regex_data_edge
    cmp r10, 12
    je regex_data_edge
    cmp r10, 14
    jne fatal
regex_data_edge:
    cmp r11, 11
    jne fatal
    jmp regex_edge_admitted
regex_validation_edge:
    cmp r11, 15
    jne fatal
    jmp regex_edge_admitted
regex_root_edge:
    cmp r11, 10
    jb fatal
    cmp r11, 14
    ja fatal
    cmp r11, 11
    je fatal
regex_edge_admitted:
    cmp qword ptr [rbx + 24], 2
    jne fatal
    cmp qword ptr [rbx + 48], 2
    jne fatal
    xor ecx, ecx
regex_zero_fields:
    cmp qword ptr [rbx + rcx*8 + 72], 0
    jne fatal
    inc ecx
    cmp ecx, 6
    jb regex_zero_fields
    mov rax, [r15 + r10*8 + REGEX_SEQUENCES]
    inc rax
    jz fatal
    cmp rax, [rbx + 8]
    jne fatal
    mov rdx, [r14 + 48]
    sub rdx, 256
    mov rsi, [rbx + 32]
    cmp rsi, rdx
    ja fatal
    sub rdx, rsi
    mov rdi, [rbx + 40]
    cmp rdi, rdx
    ja fatal
    mov rcx, [rbx + 56]
    mov rdx, [r14 + 48]
    sub rdx, 256
    cmp rcx, rdx
    ja fatal
    sub rdx, rcx
    mov r8, [rbx + 64]
    cmp r8, rdx
    ja fatal
    test rdi, rdi
    jz regex_spans_admitted
    test r8, r8
    jz regex_spans_admitted
    lea rdx, [rsi + rdi]
    cmp rdx, rcx
    jbe regex_spans_admitted
    lea rdx, [rcx + r8]
    cmp rdx, rsi
    ja fatal
regex_spans_admitted:
    cmp rdi, 134217728
    ja fatal
    cmp r8, 134217728
    ja fatal
    cmp r11, 14
    jne regex_maybe_data
    cmp r8, 8
    ja fatal
regex_maybe_data:
    cmp r11, 11
    jne regex_profile_admitted
    cmp rdi, 8
    ja fatal
    cmp r8, 171683
    ja fatal
regex_profile_admitted:
    mov [r15 + r10*8 + REGEX_SEQUENCES], rax
    add rsi, [r14 + 40]
    add rcx, [r14 + 40]
    inc r12
    add r14, 64
    mov [r14], r11
    mov [r14 + 8], rsi
    mov [r14 + 16], rdi
    mov [r14 + 24], rcx
    mov [r14 + 32], r8
    mov edx, 268435456
    mov eax, REGEX_CONTROLLER_WORK
    cmp r11, 15
    je regex_set_workspace
    mov eax, REGEX_SYNTAX_WORK
    cmp r11, 10
    je regex_set_workspace
    mov eax, REGEX_HIR_WORK
    cmp r11, 12
    je regex_set_workspace
    mov eax, REGEX_NFA_WORK
    cmp r11, 13
    je regex_set_workspace
    mov eax, REGEX_MATCH_WORK
    mov edx, 33554432
    cmp r11, 14
    je regex_set_workspace
    mov eax, REGEX_DATA_WORK
    mov edx, 65536
regex_set_workspace:
    add rax, r15
    mov [r14 + 40], rax
    mov [r14 + 48], rdx
    jmp regex_invoke


# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
# Closed execution_shadow_admit lifecycle. Public arguments cannot select
# configuration, caller identity, storage roots, callbacks, or cancellation.
.equ EX_CONTROL_SLOT, 3072
.equ EX_INPUT, 4096
.equ EX_OUT, 67112960
.equ EX_WORK, 134221824
.equ EX_MAP_OUT, 402657280
.equ EX_MAP_WORK, 469766144
.equ EX_WIRE_IN, 738201600
.equ EX_WIRE_WORK, 872419328
.equ EX_MAP_BYTES, 872484864
.equ EX_PART, 67092480
.equ EX_CHILD_REQUEST, 134250496
.equ EX_CHILD_REPLY, 201342976
.equ EX_M_REQUEST, 67174400
.equ EX_M_REPLY, 134283264
.equ EX_CAP, 67108864
.equ EX_AUTH_BYTES, 50331648

ex_allocate:
    mov rsi, rdi
    xor edi, edi
    mov edx, 3
    mov r10d, 34
    mov r8, -1
    xor r9d, r9d
    mov eax, 9
    syscall
    cmp rax, -4095
    jae fatal
    ret

ex_initialize:
    cmp qword ptr [r15 + EX_CONTROL_SLOT], 0
    jne fatal
    mov edi, EX_MAP_BYTES
    call ex_allocate
    mov [r15 + EX_CONTROL_SLOT], rax
    mov rbx, rax
    mov [rbx], r15
    lea rdi, [rbx + 256]
    mov rax, 0x3130514746435248
    mov [rdi], rax
    mov qword ptr [rdi + 8], 11
    mov qword ptr [rdi + 16], 0
    mov esi, 24
    lea rdx, [rbx + EX_WIRE_IN]
    mov ecx, ROOT_OUTPUT_CAP
    call ex_config_projection
    cmp eax, 40
    jb fatal
    cmp eax, ROOT_OUTPUT_CAP
    ja fatal
    lea rdx, [rbx + EX_WIRE_IN]
    mov rcx, 0x3131504346435248
    cmp [rdx], rcx
    jne fatal
    mov rcx, [rdx + 8]
    cmp rcx, 1
    ja fatal
    mov [rbx + 24], rcx
    mov rcx, [rdx + 16]
    cmp rcx, 1
    ja fatal
    mov [rbx + 32], rcx
    sub eax, 40
    cmp [rdx + 24], rax
    jne fatal
    cmp qword ptr [rdx + 32], 0
    jne fatal
    mov [rbx + 48], rax
    cmp qword ptr [rbx + 24], 0
    je ex_initialize_disabled
    test rax, rax
    jz fatal
    lea rdi, [rax + 4096]
    and rdi, -4096
    mov [rbx + 176], rdi
    call ex_allocate
    mov [rbx + 40], rax
    mov rdi, rax
    lea rsi, [rbx + EX_WIRE_IN + 40]
    mov rcx, [rbx + 48]
    rep movsb
    mov byte ptr [rdi], 0
    mov rdi, [rbx + 40]
    mov rsi, [rbx + 176]
    mov edx, 1
    mov eax, 10
    syscall
    test rax, rax
    jnz fatal
    jmp ex_initialize_authority
ex_initialize_disabled:
    mov rax, [rbx + 32]
    or rax, [rbx + 48]
    jnz fatal
ex_initialize_authority:
    mov edi, EX_AUTH_BYTES
    call ex_allocate
    mov [rbx + 8], rax
    mov [rax], r15
    push r15
    sub rsp, 8
    mov r15, rax
    call au_authority_prepare
    xor edi, edi
    call au_authority_lifecycle
    add rsp, 8
    pop r15
    test eax, eax
    jnz fatal
    cmp qword ptr [rbx + 24], 0
    je frame_next
    mov rdi, [rbx + 40]
    mov rsi, [rbx + 48]
    call tk_service_create
    test rax, rax
    jz fatal
    mov [rbx + 16], rax
    call ex_bind_intent
    jmp frame_next

# Projection is a trusted private query against the installed config arena.
ex_begin:
    mov rbx, [r15 + EX_CONTROL_SLOT]
    test rbx, rbx
    jz fatal
    cmp [rbx], r15
    jne fatal
    mov rax, [rbx + 128]
    or rax, [rbx + 136]
    or rax, [rbx + 184]
    jnz fatal
    mov qword ptr [rbx + 128], 1
    mov qword ptr [rbx + 152], 0
    mov qword ptr [rbx + 88], 0
    mov [rbx + 72], r13
    mov [rbx + 80], rsi
    jmp ex_mapper_resume

ex_outer_resume:
    mov rbx, [r15 + EX_CONTROL_SLOT]
    lea rdi, [rbx + EX_INPUT]
    mov rsi, [rbx + 56]
    lea rdx, [rbx + EX_OUT]
    mov ecx, EX_CAP
    lea r8, [rbx + EX_WORK]
    mov r9d, ROOT_WCAP
    call qword ptr [rip + ex_image_outer]
    mov edx, eax
    cmp rax, rdx
    jne fatal
    cmp eax, 0xfffffff0
    je ex_outer_action
    cmp eax, 65
    jb fatal
    cmp eax, EX_CAP
    ja fatal
    mov [rbx + 64], rax
    mov [rbx + 80], rax
    lea rax, [rbx + EX_OUT]
    mov [rbx + 72], rax
    mov qword ptr [rbx + 88], 2
    jmp ex_mapper_resume
ex_outer_action:
    lea r14, [rbx + EX_WORK + 256]
    mov rax, 0x313030414f435248
    cmp [r14], rax
    jne fatal
    mov rax, [rbx + 96]
    inc rax
    jz fatal
    cmp [r14 + 8], rax
    jne fatal
    mov [rbx + 96], rax
    cmp qword ptr [r14 + 32], EX_CHILD_REQUEST
    jne fatal
    cmp qword ptr [r14 + 48], EX_CHILD_REPLY
    jne fatal
    cmp qword ptr [r14 + 56], EX_PART
    jne fatal
    mov rax, [r14 + 64]
    or rax, [r14 + 72]
    or rax, [r14 + 80]
    or rax, [r14 + 88]
    jnz fatal
    mov rax, [r14 + 40]
    cmp rax, 128
    jb fatal
    cmp rax, EX_PART
    ja fatal
    mov [rbx + 80], rax
    lea rax, [rbx + EX_WORK + EX_CHILD_REQUEST]
    mov [rbx + 72], rax
    mov qword ptr [rbx + 88], 1
    jmp ex_mapper_resume

ex_mapper_resume:
    mov rbx, [r15 + EX_CONTROL_SLOT]
    mov rdi, [rbx + 72]
    mov rsi, [rbx + 80]
    lea rdx, [rbx + EX_MAP_OUT]
    mov ecx, EX_CAP
    lea r8, [rbx + EX_MAP_WORK]
    mov r9d, ROOT_WCAP
    call qword ptr [rip + ex_image_mapper]
    mov edx, eax
    cmp rax, rdx
    jne fatal
    cmp eax, 0xfffffff0
    je ex_mapper_action
    cmp eax, 32
    jb fatal
    cmp eax, EX_CAP
    ja fatal
    mov [rbx + 144], rax
    mov rdx, [rbx + 88]
    test rdx, rdx
    jz ex_mapper_initial
    cmp rdx, 1
    je ex_mapper_child
    cmp rdx, 2
    jne fatal
    mov qword ptr [rbx + 128], 0
    mov rdi, r15
    add rdi, MCP_WORK + 100667392
    lea rsi, [rbx + EX_MAP_OUT]
    mov rcx, rax
    rep movsb
    mov rax, [rbx + 144]
    jmp mcp_child_completed
ex_mapper_initial:
    mov [rbx + 56], rax
    lea rdi, [rbx + EX_INPUT]
    lea rsi, [rbx + EX_MAP_OUT]
    mov rcx, rax
    rep movsb
    jmp ex_outer_resume
ex_mapper_child:
    cmp eax, EX_PART
    ja fatal
    lea rdi, [rbx + EX_WORK + EX_CHILD_REPLY]
    lea rsi, [rbx + EX_MAP_OUT]
    mov rcx, rax
    rep movsb
    lea r14, [rbx + EX_WORK + 256]
    mov rax, [rbx + 144]
    mov [r14 + 72], rax
    mov rax, [rbx + 96]
    mov [r14 + 64], rax
    jmp ex_outer_resume

ex_mapper_action:
    cmp qword ptr [rbx + 88], 1
    jne fatal
    lea r14, [rbx + EX_MAP_WORK + 256]
    mov rax, 0x3130304145435248
    cmp [r14], rax
    jne fatal
    mov rax, [rbx + 104]
    inc rax
    jz fatal
    cmp [r14 + 8], rax
    jne fatal
    mov [rbx + 104], rax
    cmp qword ptr [r14 + 24], EX_M_REQUEST
    jne fatal
    cmp qword ptr [r14 + 40], EX_M_REPLY
    jne fatal
    cmp qword ptr [r14 + 48], EX_CAP
    jne fatal
    mov rax, [r14 + 56]
    or rax, [r14 + 64]
    or rax, [r14 + 72]
    or rax, [r14 + 80]
    or rax, [r14 + 88]
    jnz fatal
    mov rsi, [r14 + 32]
    cmp rsi, EX_CAP
    ja fatal
    lea rdi, [rbx + EX_MAP_WORK + EX_M_REQUEST]
    lea rdx, [rbx + EX_MAP_WORK + EX_M_REPLY]
    mov ecx, EX_CAP
    mov rax, [r14 + 16]
    cmp rax, 1
    je ex_map_config
    cmp rax, 2
    je ex_map_authority
    cmp rax, 3
    je ex_map_ticket
    cmp rax, 4
    je ex_map_execution
    cmp rax, 5
    je ex_map_cancellation
    cmp rax, 6
    je ex_map_intent
    cmp rax, 7
    je ex_map_metadata
    jmp fatal
ex_map_config:
    cmp rsi, 24
    jne fatal
    call ex_config_projection
    jmp ex_mapper_ack
ex_map_authority:
    cmp rsi, 16
    jne fatal
    mov rax, [rbx + 8]
    test rax, rax
    jz fatal
    mov rsi, rdi
    lea rdi, [rax + 65536]
    mov ecx, 16
    rep movsb
    push r15
    sub rsp, 8
    mov r15, rax
    lea rdi, [r15 + 65536]
    mov esi, 16
    lea rdx, [r15 + 9437184]
    mov ecx, 96
    call au_authority_request
    add rsp, 8
    pop r15
    cmp eax, 32
    jb fatal
    cmp eax, 96
    ja fatal
    mov [rbx + 144], rax
    mov rsi, [rbx + 8]
    add rsi, 9437184
    lea rdi, [rbx + EX_MAP_WORK + EX_M_REPLY]
    mov ecx, eax
    rep movsb
    mov rax, [rbx + 144]
    jmp ex_mapper_ack
ex_map_ticket:
    cmp rsi, 8388608
    ja fatal
    mov r8, rcx
    mov rcx, rdx
    mov rdx, rsi
    mov rsi, rdi
    mov rdi, [rbx + 16]
    test rdi, rdi
    jz fatal
    call tk_service_call
    jmp ex_mapper_ack
ex_map_execution:
    cmp rsi, 26
    jb fatal
    cmp qword ptr [rbx + 136], 0
    jne fatal
    mov [r15 + 880], rsi
    mov rcx, rsi
    mov rsi, rdi
    lea rdi, [r15 + MCP_WORK + 33554432]
    rep movsb
    mov qword ptr [rbx + 136], 1
    mov qword ptr [r15 + 872], 1
    jmp execution_resume
ex_map_cancellation:
    cmp rsi, 16
    jne fatal
    mov rax, 0x3130535443435248
    mov [rdx], rax
    mov rax, [rbx + 152]
    cmp rax, 1
    ja fatal
    mov [rdx + 8], rax
    mov eax, 16
    jmp ex_mapper_ack
ex_execution_completed:
    mov rbx, [r15 + EX_CONTROL_SLOT]
    cmp qword ptr [rbx + 128], 1
    jne fatal
    cmp qword ptr [rbx + 136], 1
    jne fatal
    mov qword ptr [rbx + 136], 0
    cmp eax, EX_CAP
    ja fatal
    mov [rbx + 144], rax
    lea rsi, [r15 + MCP_WORK + 100667392]
    lea rdi, [rbx + EX_MAP_WORK + EX_M_REPLY]
    mov rcx, rax
    rep movsb
    mov rax, [rbx + 144]
ex_mapper_ack:
    mov rbx, [r15 + EX_CONTROL_SLOT]
    mov edx, eax
    cmp rax, rdx
    jne fatal
    cmp eax, EX_CAP
    ja fatal
    lea r14, [rbx + EX_MAP_WORK + 256]
    mov [r14 + 64], rax
    mov [r14 + 72], rax
    mov rax, [rbx + 104]
    mov [r14 + 56], rax
    jmp ex_mapper_resume

# HIA typed dispatcher supplies the full canonical typed body before wire order.
ex_wire:
    mov rbx, [r15 + EX_CONTROL_SLOT]
    test rbx, rbx
    jz fatal
    cmp rax, ROOT_OUTPUT_CAP
    ja fatal
    mov [rbx + 144], rax
    lea rdi, [rbx + EX_WIRE_IN]
    lea rsi, [r15 + OUTPUT]
    mov rcx, rax
    rep movsb
    lea rdi, [rbx + EX_WIRE_IN]
    mov rsi, [rbx + 144]
    lea rdx, [r15 + OUTPUT]
    mov ecx, ROOT_OUTPUT_CAP
    lea r8, [rbx + EX_WIRE_WORK]
    mov r9d, 65536
    call qword ptr [rip + ex_image_wire]
    mov edx, eax
    cmp rax, rdx
    jne fatal
    cmp eax, ROOT_OUTPUT_CAP
    ja fatal
    mov rdx, rax
    lea rsi, [r15 + OUTPUT]
    jmp public_write

ex_shutdown:
    mov rbx, [r15 + EX_CONTROL_SLOT]
    test rbx, rbx
    jz ex_shutdown_done
    cmp [rbx], r15
    jne fatal
    mov rax, [rbx + 128]
    or rax, [rbx + 136]
    or rax, [rbx + 184]
    jnz fatal
    mov qword ptr [rbx + 184], 1
    mov rdi, [rbx + 16]
    test rdi, rdi
    jz ex_shutdown_authority
    call tk_service_drop
    test rax, rax
    jnz fatal
    mov qword ptr [rbx + 16], 0
ex_shutdown_authority:
    mov rax, [rbx + 8]
    test rax, rax
    jz fatal
    push r15
    sub rsp, 8
    mov r15, rax
    mov edi, 2
    call au_authority_lifecycle
    test eax, eax
    jnz au_authority_contract_fail
    call au_authority_cleanup
    add rsp, 8
    pop r15
    mov rdi, [rbx + 8]
    mov qword ptr [rbx + 8], 0
    mov esi, EX_AUTH_BYTES
    mov eax, 11
    syscall
    test rax, rax
    jnz fatal
    mov rdi, [rbx + 40]
    test rdi, rdi
    jz ex_shutdown_mapping
    mov rsi, [rbx + 176]
    mov qword ptr [rbx + 40], 0
    mov eax, 11
    syscall
    test rax, rax
    jnz fatal
ex_shutdown_mapping:
    mov qword ptr [r15 + EX_CONTROL_SLOT], 0
    mov rdi, rbx
    mov esi, EX_MAP_BYTES
    mov eax, 11
    syscall
    test rax, rax
    jnz fatal
ex_shutdown_done:
    jmp config_eof_original
public_authority_fatal:
    mov r15, [r15]
    jmp fatal

.include "public_lifecycle_metadata.S"


.equ au_AUTH_CONTROL,4096
.equ au_AUTH_WORK_BEGIN,16777216
.equ au_AUTH_WORK_END,41701376
.equ au_MAP_BYTES,50331648
/* Copyright 2026 Muvon Un Limited
 * Copyright 2026 TrillionniumFoundation
 * SPDX-License-Identifier: Apache-2.0
 * Closed nine-image authority subtree. Logical IDs and private state never
 * come from public JSON. au_AUTH_CONTROL and each work offset are fixed at build.
 * r15 is the encompassing mapping; all exported helpers preserve callee-saved
 * registers. Only the two declared entropy owners can request an OS effect.
 */
.intel_syntax noprefix

au_authority_prepare:
    mov r10d, au_AUTH_CONTROL
    add r10, r15
    mov qword ptr [r10 + 272], -1
    mov qword ptr [r10 + 280], -1
    mov qword ptr [r10 + 288], -1
    ret

/* edi is trusted startup(0) or shutdown(2). No public frame selects it. */
au_authority_lifecycle:
    mov r10d, au_AUTH_CONTROL
    add r10, r15
    mov [r10], rdi
    lea rdi, [r10 + 64]
    xor esi, esi
    lea rdx, [r10 + 128]
    mov ecx, 96
    xor r8d, r8d
    jmp au_authority_invoke

/* The caller supplies only the fixed private query and disjoint result span. */
au_authority_request:
    mov r10d, au_AUTH_CONTROL
    add r10, r15
    mov qword ptr [r10], 5
    xor r8d, r8d
    jmp au_authority_invoke

/* Retire descriptors before close; preserve the caller's exit/status value. */
au_authority_cleanup:
    push rbx
    mov ebx, au_AUTH_CONTROL
    add rbx, r15
    mov r10d, 272
au_authority_cleanup_fd:
    mov rdi, [rbx + r10]
    mov qword ptr [rbx + r10], -1
    test rdi, rdi
    js au_authority_cleanup_next
    mov eax, 3
    syscall
au_authority_cleanup_next:
    add r10, 8
    cmp r10, 296
    jne au_authority_cleanup_fd
    mov edi, au_AUTH_WORK_BEGIN
    add rdi, r15
    mov ecx, au_AUTH_WORK_END - au_AUTH_WORK_BEGIN
    xor eax, eax
    rep stosb
    pop rbx
    ret

/* rdi/rsi input; rdx/rcx output; r8 logical ID. The function graph is fixed. */
au_authority_invoke:
    push rbp
    push rbx
    push r12
    push r13
    push r14
    sub rsp, 96
    mov [rsp], rdi
    mov [rsp + 8], rsi
    mov [rsp + 16], rdx
    mov [rsp + 24], rcx
    mov [rsp + 32], r8
    mov rbp, r8
    cmp rbp, 9
    jae au_authority_contract_fail
    mov ebx, au_AUTH_CONTROL
    add rbx, r15
    cmp qword ptr [rbx + 40], 8
    jae au_authority_contract_fail
    mov eax, 1
    mov ecx, ebp
    shl rax, cl
    test [rbx + 48], rax
    jnz au_authority_contract_fail
    or [rbx + 48], rax
    inc qword ptr [rbx + 40]
    lea rax, [rbp + rbp*2]
    shl rax, 4
    lea r10, [rip + au_authority_table]
    add r10, rax
    mov r12, [r10]
    add r12, r15
    mov r13, [r10 + 8]
    mov [rsp + 40], r10
    mov rax, [rsp + 8]
    cmp rax, [r10 + 16]
    ja au_authority_contract_fail
    mov rax, [rsp + 24]
    cmp rax, [r10 + 24]
    ja au_authority_contract_fail
    mov rax, [rsp]
    sub rax, r15
    jc au_authority_contract_fail
    mov edx, au_MAP_BYTES
    cmp rax, rdx
    ja au_authority_contract_fail
    sub rdx, rax
    cmp [rsp + 8], rdx
    ja au_authority_contract_fail
    mov rax, [rsp + 16]
    sub rax, r15
    jc au_authority_contract_fail
    mov edx, au_MAP_BYTES
    cmp rax, rdx
    ja au_authority_contract_fail
    sub rdx, rax
    cmp [rsp + 24], rdx
    ja au_authority_contract_fail
    cmp qword ptr [rsp + 8], 0
    je au_authority_spans_valid
    cmp qword ptr [rsp + 24], 0
    je au_authority_spans_valid
    mov rax, [rsp]
    add rax, [rsp + 8]
    cmp rax, [rsp + 16]
    jbe au_authority_spans_valid
    mov rax, [rsp + 16]
    add rax, [rsp + 24]
    cmp rax, [rsp]
    ja au_authority_contract_fail
au_authority_spans_valid:
    xor r14d, r14d
    cmp qword ptr [r10 + 32], 1
    je au_authority_footer
    cmp qword ptr [r10 + 32], 8
    jne au_authority_private_loader_checked
au_authority_footer:
    lea r14, [r12 + r13 - 256]
    mov qword ptr [r14 + 120], 3
    test rbp, rbp
    jnz au_authority_footer_kind
    mov rax, [rbx]
    mov [r14 + 120], rax
    mov qword ptr [r14 + 160], 1
    mov qword ptr [r14 + 168], 1
    mov rax, 0x31504143574f5248 /* HROWCAP1 */
    mov [r14 + 176], rax
au_authority_footer_kind:
    mov [r14 + 128], rbp
    mov rax, [rbx + 40]
    dec rax
    mov [r14 + 136], rax
au_authority_private_loader_checked:
    cmp ebp, 8
    jne au_authority_enter
    cmp qword ptr [rbx], 0
    jne au_authority_contract_fail
    cmp qword ptr [rbx + 40], 2
    jne au_authority_contract_fail
    cmp qword ptr [rbx + 48], 257
    jne au_authority_contract_fail
    cmp qword ptr [rsp + 8], 24
    jne au_authority_contract_fail
    mov rdi, [rsp]
    mov rax, 0x313044414f4c5248 /* HRLOAD01 */
    cmp [rdi], rax
    jne au_authority_contract_fail
    cmp qword ptr [rdi + 8], 2
    jne au_authority_contract_fail
    cmp qword ptr [rdi + 16], 0
    jne au_authority_contract_fail
    mov qword ptr [r14 + 144], 0
    mov qword ptr [r14 + 152], 0
    mov qword ptr [r14 + 160], 1
    mov qword ptr [r14 + 168], 1
au_authority_enter:
    mov rdi, [rsp]
    mov rsi, [rsp + 8]
    mov rdx, [rsp + 16]
    mov rcx, [rsp + 24]
    mov r8, r12
    mov r9, r13
    cmp ebp, 0
    je au_authority_native_0
    cmp ebp, 1
    je au_authority_native_1
    cmp ebp, 2
    je au_authority_native_2
    cmp ebp, 3
    je au_authority_native_3
    cmp ebp, 4
    je au_authority_native_4
    cmp ebp, 5
    je au_authority_native_5
    cmp ebp, 6
    je au_authority_native_6
    cmp ebp, 7
    je au_authority_native_7
    cmp ebp, 8
    je au_authority_native_8
    jmp au_authority_contract_fail
/* The authoring step inserts nine fixed direct-call relocation holes here. */
au_authority_native_0:
    call qword ptr [rip + au_authority_image_0]
    jmp au_authority_native_return
au_authority_native_1:
    call qword ptr [rip + au_authority_image_1]
    jmp au_authority_native_return
au_authority_native_2:
    call qword ptr [rip + au_authority_image_2]
    jmp au_authority_native_return
au_authority_native_3:
    call qword ptr [rip + au_authority_image_3]
    jmp au_authority_native_return
au_authority_native_4:
    call qword ptr [rip + au_authority_image_4]
    jmp au_authority_native_return
au_authority_native_5:
    call qword ptr [rip + au_authority_image_5]
    jmp au_authority_native_return
au_authority_native_6:
    call qword ptr [rip + au_authority_image_6]
    jmp au_authority_native_return
au_authority_native_7:
    call qword ptr [rip + au_authority_image_7]
    jmp au_authority_native_return
au_authority_native_8:
    call qword ptr [rip + au_authority_image_8]
    jmp au_authority_native_return

au_authority_native_return:
    mov edx, eax
    cmp rax, rdx
    jne au_authority_contract_fail
    cmp eax, 0xffffffe0
    je au_authority_child_call
    cmp eax, 0xfffffff0
    je au_authority_effect
    cmp eax, 0xffff0000
    jae au_authority_done
    cmp rax, [rsp + 24]
    ja au_authority_contract_fail
au_authority_done:
    mov [rsp + 72], rax
    mov eax, 1
    mov ecx, ebp
    shl rax, cl
    not rax
    and [rbx + 48], rax
    dec qword ptr [rbx + 40]
    mov rax, [rsp + 72]
    add rsp, 96
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret

au_authority_child_call:
    mov r10, [rsp + 40]
    cmp qword ptr [r10 + 32], 1
    jne au_authority_contract_fail
    mov rax, 0x31304c4143414948 /* HIACAL01 */
    cmp [r14], rax
    jne au_authority_contract_fail
    mov rax, [r14 + 8]
    test rax, rax
    jz au_authority_contract_fail
    mov rdx, [rbx + rbp*8 + 512]
    inc rdx
    jz au_authority_contract_fail
    cmp rax, rdx
    jne au_authority_contract_fail
    mov [rsp + 80], rax
    mov rax, [r14 + 72]
    or rax, [r14 + 80]
    or rax, [r14 + 88]
    or rax, [r14 + 96]
    or rax, [r14 + 104]
    jnz au_authority_contract_fail
    mov r8, [r14 + 16]
    cmp r8, 9
    jae au_authority_contract_fail
    bt [r10 + 40], r8
    jnc au_authority_contract_fail
    cmp r8, 7
    jne au_authority_child_target
    cmp ebp, 6
    je au_authority_child_target
    test ebp, ebp
    jnz au_authority_contract_fail
    cmp qword ptr [rbx], 0
    jne au_authority_contract_fail
au_authority_child_target:
    mov rax, [r14 + 24]
    test rax, rax
    jz au_authority_source_input
    cmp rax, 2
    jne au_authority_contract_fail
    mov rdi, r12
    lea rdx, [r13 - 256]
    jmp au_authority_source_span
au_authority_source_input:
    mov rdi, [rsp]
    mov rdx, [rsp + 8]
au_authority_source_span:
    mov rax, [r14 + 32]
    cmp rax, rdx
    ja au_authority_contract_fail
    sub rdx, rax
    mov rsi, [r14 + 40]
    cmp rsi, rdx
    ja au_authority_contract_fail
    add rdi, rax
    cmp qword ptr [r14 + 48], 2
    jne au_authority_contract_fail
    lea rdx, [r13 - 256]
    mov rax, [r14 + 56]
    cmp rax, rdx
    ja au_authority_contract_fail
    sub rdx, rax
    mov rcx, [r14 + 64]
    cmp rcx, rdx
    ja au_authority_contract_fail
    lea rdx, [r12 + rax]
    mov rax, [rsp + 80]
    mov [rbx + rbp*8 + 512], rax
    call au_authority_invoke
    mov [r14 + 80], rax
    mov rax, [rsp + 80]
    mov [r14 + 88], rax
    mov qword ptr [r14 + 96], 1
    mov qword ptr [r14 + 104], 0
    jmp au_authority_enter

au_authority_effect:
    cmp ebp, 7
    je au_authority_entropy_effect
    cmp ebp, 8
    je au_authority_loader_effect
    jmp au_authority_contract_fail

au_authority_contract_fail:
    jmp public_authority_fatal

au_authority_entropy_effect:
    mov r10, [rsp + 40]
    cmp qword ptr [r10 + 32], 4
    jne au_authority_contract_fail
    mov r10, 0x3230544e45414948 /* HIAENT02 */
    mov r11d, 256
    jmp au_authority_effect_check
au_authority_loader_effect:
    mov r10, [rsp + 40]
    cmp qword ptr [r10 + 32], 8
    jne au_authority_contract_fail
    mov r10, 0x3130444f4c414948 /* HIALOD01 */
    mov r11d, 264
au_authority_effect_check:
    cmp [r12 + 256], r10
    jne au_authority_contract_fail
    mov rax, [r12 + 264]
    test rax, rax
    jz au_authority_contract_fail
    mov rdx, [rbx + r11]
    inc rdx
    jz au_authority_contract_fail
    cmp rax, rdx
    jne au_authority_contract_fail
    mov [rbx + r11], rax
    mov rax, [r12 + 288]
    or rax, [r12 + 304]
    or rax, [r12 + 312]
    or rax, [r12 + 320]
    or rax, [r12 + 328]
    jnz au_authority_contract_fail
    cmp ebp, 8
    je au_authority_loader_action
    mov rax, [r12 + 296]
    cmp rax, 1
    je au_authority_entropy_probe
    cmp rax, 2
    je au_authority_entropy_fill
    cmp rax, 3
    je au_authority_entropy_open_random
    cmp rax, 4
    je au_authority_entropy_poll
    cmp rax, 5
    je au_authority_entropy_close_random
    cmp rax, 6
    je au_authority_entropy_open_urandom
    cmp rax, 7
    je au_authority_entropy_read
    jmp au_authority_contract_fail

au_authority_effect_zero_span:
    mov rax, [r12 + 272]
    or rax, [r12 + 280]
    jnz au_authority_contract_fail
    ret
au_authority_entropy_span:
    mov rax, [r12 + 272]
    cmp rax, 512
    jb au_authority_contract_fail
    cmp rax, 640
    jae au_authority_contract_fail
    mov edx, 640
    sub rdx, rax
    mov rsi, [r12 + 280]
    test rsi, rsi
    jz au_authority_contract_fail
    cmp rsi, rdx
    ja au_authority_contract_fail
    lea rdi, [r12 + rax]
    ret
au_authority_entropy_probe:
    cmp qword ptr [r12 + 272], 512
    jne au_authority_contract_fail
    cmp qword ptr [r12 + 280], 0
    jne au_authority_contract_fail
    lea rdi, [r12 + 512]
    xor esi, esi
    xor edx, edx
    mov eax, 318
    syscall
    jmp au_authority_effect_ack
au_authority_entropy_fill:
    call au_authority_entropy_span
    xor edx, edx
    mov eax, 318
    syscall
    jmp au_authority_effect_ack
au_authority_entropy_open_random:
    call au_authority_effect_zero_span
    cmp qword ptr [rbx + 272], -1
    jne au_authority_contract_fail
    mov rdi, -100
    lea rsi, [rip + au_authority_random_path]
    mov edx, 524288
    xor r10d, r10d
    mov eax, 257
    syscall
    cmp rax, -4095
    jae au_authority_effect_ack
    mov [rbx + 272], rax
    xor eax, eax
    jmp au_authority_effect_ack
au_authority_entropy_poll:
    call au_authority_effect_zero_span
    mov rax, [rbx + 272]
    test rax, rax
    js au_authority_contract_fail
    mov [rbx + 320], eax
    mov word ptr [rbx + 324], 1
    mov word ptr [rbx + 326], 0
    lea rdi, [rbx + 320]
    mov esi, 1
    mov rdx, -1
    mov eax, 7
    syscall
    jmp au_authority_effect_ack
au_authority_entropy_close_random:
    call au_authority_effect_zero_span
    mov rdi, [rbx + 272]
    test rdi, rdi
    js au_authority_contract_fail
    mov qword ptr [rbx + 272], -1
    mov eax, 3
    syscall
    jmp au_authority_effect_ack
au_authority_entropy_open_urandom:
    call au_authority_effect_zero_span
    cmp qword ptr [rbx + 280], -1
    jne au_authority_contract_fail
    mov rdi, -100
    lea rsi, [rip + au_authority_urandom_path]
    mov edx, 524288
    xor r10d, r10d
    mov eax, 257
    syscall
    cmp rax, -4095
    jae au_authority_effect_ack
    mov [rbx + 280], rax
    xor eax, eax
    jmp au_authority_effect_ack
au_authority_entropy_read:
    call au_authority_entropy_span
    mov rdx, rsi
    mov rsi, rdi
    mov rdi, [rbx + 280]
    test rdi, rdi
    js au_authority_contract_fail
    xor eax, eax
    syscall
    jmp au_authority_effect_ack

/* Stdio-only loader: exactly op2, fixed owner device, read_exact(32), Drop. */
au_authority_loader_action:
    mov rax, [r12 + 296]
    cmp rax, 7
    je au_authority_owner_open
    cmp rax, 4
    je au_authority_owner_read
    cmp rax, 6
    je au_authority_owner_close
    jmp au_authority_contract_fail
au_authority_owner_open:
    call au_authority_effect_zero_span
    cmp qword ptr [rbx + 288], -1
    jne au_authority_contract_fail
    mov rdi, -100
    lea rsi, [rip + au_authority_urandom_path]
    mov edx, 524288
    xor r10d, r10d
    mov eax, 257
    syscall
    cmp rax, -4095
    jae au_authority_effect_ack
    mov [rbx + 288], rax
    xor eax, eax
    jmp au_authority_effect_ack
au_authority_owner_read:
    mov rax, [r12 + 272]
    cmp rax, 135168
    jb au_authority_contract_fail
    cmp rax, 135200
    jae au_authority_contract_fail
    mov edx, 135200
    sub rdx, rax
    mov rcx, [r12 + 280]
    test rcx, rcx
    jz au_authority_contract_fail
    cmp rcx, rdx
    ja au_authority_contract_fail
    lea rsi, [r12 + rax]
    mov rdx, rcx
    mov rdi, [rbx + 288]
    test rdi, rdi
    js au_authority_contract_fail
    xor eax, eax
    syscall
    jmp au_authority_effect_ack
au_authority_owner_close:
    call au_authority_effect_zero_span
    mov rdi, [rbx + 288]
    test rdi, rdi
    js au_authority_contract_fail
    mov qword ptr [rbx + 288], -1
    mov eax, 3
    syscall
au_authority_effect_ack:
    xor edx, edx
    cmp rax, -4095
    jb au_authority_effect_success
    neg rax
    mov rdx, rax
    xor eax, eax
au_authority_effect_success:
    mov [r12 + 304], rax
    mov [r12 + 312], rdx
    mov rax, [r12 + 264]
    mov [r12 + 320], rax
    mov qword ptr [r12 + 328], 1
    jmp au_authority_enter

au_authority_random_path:
    .asciz "/dev/random"
au_authority_urandom_path:
    .asciz "/dev/urandom"
/* Immutable table: work offset, work size, maximum input/output, flags, mask. */
.balign 8
au_authority_table:
    .quad 16777216,16777216,8388608,8388608,1,456
    .quad 33554432,3145728,8388608,2097152,1,28
    .quad 36700160,2048,8388608,128,0,0
    .quad 36704256,1184,8388608,128,0,0
    .quad 36708352,512,8388608,1048640,0,0
    .quad 36712448,1576960,164,64,0,0
    .quad 38289408,3145728,8388608,2097152,1,166
    .quad 41435136,1024,24,128,4,0
    .quad 41439232,262144,131095,4096,8,0

.balign 8
au_authority_image_0:
    .quad 0
au_authority_image_1:
    .quad 0
au_authority_image_2:
    .quad 0
au_authority_image_3:
    .quad 0
au_authority_image_4:
    .quad 0
au_authority_image_5:
    .quad 0
au_authority_image_6:
    .quad 0
au_authority_image_7:
    .quad 0
au_authority_image_8:
    .quad 0

# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
# Fixed service transport. CLI roots are retained raw strings, never opened here.
.intel_syntax noprefix
.section .text
.equ tk_GLOBAL_LOCK, 4096
.equ tk_GLOBAL_ACTIVITY, 8192
.equ tk_GLOBAL_ENTROPY, 12288
.equ tk_CONTEXT_BYTES, 32768
.equ tk_LEAF_WORK, 4096
.equ tk_CLOCK_WORK, 12288
.equ tk_LOCK_CONTEXT, 16384
.equ tk_FRAME_INPUT, 20480
.equ tk_FRAME_OUTPUT, 24576
.equ tk_CLEANUP_REQUEST, 28672
.equ tk_CLEANUP_REPLY, 28800
.equ tk_TICKET_WORK_BYTES, 2097152
.equ tk_TICKET_MAP_BYTES, 2105344
.equ tk_TICKET_INPUT, 2097152
.equ tk_TICKET_OUTPUT, 2101248
.equ tk_SERVICE_ROOT_BYTES, 65536
.equ tk_SERVICE_WORK, 256
.equ tk_SERVICE_CAP, 264
.equ tk_SERVICE_MAPPING, 272
.equ tk_SERVICE_TABLE, 280
.equ tk_SERVICE_SLOTS, 288
.equ tk_SERVICE_TABLE_MAPPING, 296
.equ tk_SERVICE_IO, 304
.equ tk_SERVICE_SEQUENCE, 312
.equ tk_SERVICE_INPUT_LENGTH, 320
.equ tk_SERVICE_EVENT, 328
.equ tk_STORAGE_GLOBAL, 24576
.equ tk_ROOT_COUNT, 32768
.equ tk_ROOT_PATHS, 32776
.equ tk_MAX_PUBLIC_INPUT, 8388608
.equ tk_SERVICE_IO_BYTES, 8396800
.equ tk_SERVICE_OUTPUT, 8392704
.equ tk_S_ACTION, 256
.equ tk_S_REQUEST, 4096
.equ tk_S_REPLY, 12288

# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
# Fixed callable form of the qualified dynamic Ticket service.
# Root pathname is borrowed from one immutable installed-config allocation.
tk_service_create:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp, 24
    mov [rsp], rdi
    mov [rsp + 8], rsi
    test rdi, rdi
    jz tk_contract_fail
    test rsi, rsi
    jz tk_contract_fail
    mov edi, tk_SERVICE_ROOT_BYTES
    call tk_allocate_guarded
    mov r15, rax
    mov [r15], r15
    mov qword ptr [r15 + tk_ROOT_COUNT], 1
    mov rax, [rsp]
    mov [r15 + tk_ROOT_PATHS], rax
    mov rax, [rsp + 8]
    mov [r15 + tk_ROOT_PATHS + 8], rax
    mov edi, tk_SERVICE_IO_BYTES
    call tk_allocate_guarded
    mov [r15 + tk_SERVICE_IO], rax
    mov edi, 20480
    call tk_allocate_guarded
    mov [r15 + tk_SERVICE_WORK], rax
    mov qword ptr [r15 + tk_SERVICE_CAP], 16896
    mov qword ptr [r15 + tk_SERVICE_MAPPING], 20480
    mov edi, 4096
    call tk_allocate_guarded
    mov [r15 + tk_SERVICE_TABLE], rax
    mov qword ptr [r15 + tk_SERVICE_SLOTS], 8
    mov qword ptr [r15 + tk_SERVICE_TABLE_MAPPING], 4096
    mov edi, 4096
    call tk_allocate_guarded
    mov [r15 + tk_GLOBAL_LOCK + 8], rax
    mov qword ptr [r15 + tk_GLOBAL_LOCK + 16], 256
    mov rax, [rip + tk_image_table + 80]
    mov [r15 + tk_GLOBAL_LOCK + 24], rax
    mov edi, 4096
    call tk_allocate_guarded
    mov [r15 + tk_GLOBAL_ACTIVITY + 8], rax
    mov qword ptr [r15 + tk_GLOBAL_ACTIVITY + 16], 256
    mov rax, [rip + tk_image_table + 32]
    mov [r15 + tk_GLOBAL_ACTIVITY + 24], rax
    mov rax, [rip + tk_image_table + 64]
    mov [r15 + tk_GLOBAL_ENTROPY + 24], rax
    mov qword ptr [r15 + tk_GLOBAL_ENTROPY + 152], -1
    mov qword ptr [r15 + tk_GLOBAL_ENTROPY + 160], -1
    lea rdi, [r15 + tk_GLOBAL_LOCK + 512]
    mov rax, 0x313030514c415248
    mov [rdi], rax
    mov esi, 128
    lea rdx, [r15 + tk_GLOBAL_LOCK + 640]
    lea rcx, [r15 + tk_GLOBAL_LOCK]
    call tk_lock_policy_run
    cmp qword ptr [r15 + tk_GLOBAL_LOCK + 656], 0
    jne tk_contract_fail
    mov qword ptr [r15 + 1024], 1
    mov edi, 13
    lea rsi, [r15 + 1024]
    xor edx, edx
    mov r10d, 8
    mov eax, 13
    syscall
    test rax, rax
    jnz tk_io_fail

    mov rax, r15
    add rsp, 24
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

# root, inner HRATWQ01 bytes, byte count, result, result capacity.
tk_service_call:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp, 24
    mov r15, rdi
    mov [rsp], rcx
    mov [rsp + 8], r8
    cmp r8, 608
    jb tk_callable_capacity
    cmp rdx, tk_MAX_PUBLIC_INPUT
    ja tk_callable_invalid
    cmp [r15], r15
    jne tk_contract_fail
    cmp qword ptr [r15 + tk_ROOT_COUNT], 1
    jne tk_contract_fail
    mov rbp, rdx
    mov rdi, [r15 + tk_SERVICE_IO]
    add rdi, 32
    mov rcx, rbp
    rep movsb
    mov rdi, [r15 + tk_SERVICE_IO]
    mov rax, 0x3151435354415248
    mov [rdi], rax
    mov qword ptr [rdi + 8], 0
    mov qword ptr [rdi + 16], 1
    mov [rdi + 24], rbp
    add rbp, 32
    mov [r15 + tk_SERVICE_INPUT_LENGTH], rbp
    mov qword ptr [r15 + tk_SERVICE_EVENT], 0
    call tk_service_drive
    cmp eax, 608
    ja tk_callable_return
    mov ebp, eax
    mov rdi, [rsp]
    mov rsi, [r15 + tk_SERVICE_IO]
    add rsi, tk_SERVICE_OUTPUT
    mov ecx, eax
    rep movsb
    mov eax, ebp
    jmp tk_callable_return
tk_callable_capacity:
    mov eax, 0xfffffffe
    jmp tk_callable_return
tk_callable_invalid:
    mov eax, 0xffffffff
tk_callable_return:
    add rsp, 24
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

# EOF invokes the original per-Ticket Drop in ascending live-handle order.
# Native mappings are retired only after HIA confirms no surviving contexts.
tk_service_drop:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp, 24
    mov r15, rdi
    cmp [r15], r15
    jne tk_contract_fail
    mov rdi, r15
    mov esi, 1
    call tk_intent_global_drop
    mov qword ptr [r15 + tk_SERVICE_INPUT_LENGTH], 32
    mov qword ptr [r15 + tk_SERVICE_EVENT], 1
    mov rdi, [r15 + tk_SERVICE_IO]
    mov rax, 0x3151435354415248
    mov [rdi], rax
    mov qword ptr [rdi + 8], 1
    mov qword ptr [rdi + 16], 1
    mov qword ptr [rdi + 24], 0
    call tk_service_drive
    cmp eax, 32
    jne tk_contract_fail
    mov rax, [r15 + tk_SERVICE_IO]
    add rax, tk_SERVICE_OUTPUT
    mov rdx, 0x444e455354415248
    cmp [rax], rdx
    jne tk_contract_fail
    mov rdx, [rax + 16]
    or rdx, [rax + 24]
    jnz tk_contract_fail
    mov rdi, r15
    xor esi, esi
    call tk_intent_global_drop
    call tk_service_shutdown
    mov rdi, [r15 + tk_GLOBAL_LOCK + 8]
    mov rsi, [r15 + tk_GLOBAL_LOCK + 16]
    add rsi, 4095
    and rsi, -4096
    add rsi, 4096
    mov qword ptr [r15 + tk_GLOBAL_LOCK + 8], 0
    call tk_callable_unmap
    mov rdi, [r15 + tk_GLOBAL_ACTIVITY + 8]
    mov rsi, [r15 + tk_GLOBAL_ACTIVITY + 16]
    add rsi, 4095
    and rsi, -4096
    add rsi, 4096
    mov qword ptr [r15 + tk_GLOBAL_ACTIVITY + 8], 0
    call tk_callable_unmap
    mov rdi, [r15 + tk_SERVICE_TABLE]
    mov rsi, [r15 + tk_SERVICE_TABLE_MAPPING]
    add rsi, 4096
    mov qword ptr [r15 + tk_SERVICE_TABLE], 0
    call tk_callable_unmap
    mov rdi, [r15 + tk_SERVICE_WORK]
    mov rsi, [r15 + tk_SERVICE_MAPPING]
    add rsi, 4096
    mov qword ptr [r15 + tk_SERVICE_WORK], 0
    call tk_callable_unmap
    mov rdi, [r15 + tk_SERVICE_IO]
    mov esi, tk_SERVICE_IO_BYTES + 4096
    mov qword ptr [r15 + tk_SERVICE_IO], 0
    call tk_callable_unmap
    mov rdi, r15
    mov esi, tk_SERVICE_ROOT_BYTES + 4096
    call tk_callable_unmap
    xor eax, eax
    jmp tk_callable_return
tk_callable_unmap:
    test rdi, rdi
    jz tk_contract_fail
    mov eax, 11
    syscall
    test rax, rax
    jnz tk_io_fail
    ret

tk_service_next:
tk_service_regular_frame:
tk_service_emit_result:
tk_service_eof:
tk_service_enter:
tk_service_stopped:
    jmp tk_contract_fail

# Caller rootcap lookup: no descriptor creation, normalization, or UTF-8 conversion.
tk_ticket_root_path:
    mov rax, [rdi]
    test rsi, rsi
    jz tk_ticket_root_missing
    cmp rsi, [rax + tk_ROOT_COUNT]
    ja tk_ticket_root_missing
    dec rsi
    shl rsi, 4
    mov rdx, [rax + tk_ROOT_PATHS + rsi + 8]
    mov rax, [rax + tk_ROOT_PATHS + rsi]
    ret
tk_ticket_root_missing:
    xor eax, eax
    xor edx, edx
    ret

# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
# HIA decides admission, handles, growth and consumption; this boundary owns bytes.
tk_service_drive:
    push rbx
    push rbp
    push r12
    push r13
    push r14
tk_service_resume:
    mov r12, [r15 + tk_SERVICE_WORK]
    mov rdi, [r15 + tk_SERVICE_IO]
    mov rsi, [r15 + tk_SERVICE_INPUT_LENGTH]
    lea rdx, [rdi + tk_SERVICE_OUTPUT]
    mov ecx, 608
    mov r8, r12
    mov r9, [r15 + tk_SERVICE_CAP]
    call qword ptr [rip + tk_image_table + 96]
    mov edx, eax
    cmp rax, rdx
    jne tk_contract_fail
    cmp eax, 0xfffffff7
    je tk_service_grow
    cmp eax, 0xfffffff0
    jne tk_service_return
    lea r14, [r12 + tk_S_ACTION]
    mov rax, 0x3130415354415248
    cmp [r14], rax
    jne tk_contract_fail
    mov rax, [r15 + tk_SERVICE_SEQUENCE]
    inc rax
    jz tk_contract_fail
    cmp [r14 + 8], rax
    jne tk_contract_fail
    cmp [r12 + 16], rax
    jne tk_contract_fail
    mov [r15 + tk_SERVICE_SEQUENCE], rax
    mov rax, [r14 + 16]
    cmp rax, 1
    jb tk_contract_fail
    cmp rax, 4
    ja tk_contract_fail
    cmp [r12 + 8], rax
    jne tk_contract_fail
    mov rdx, [r14 + 24]
    cmp [r12 + 80], rdx
    jne tk_contract_fail
    mov rdx, [r14 + 80]
    cmp [r12 + 88], rdx
    jne tk_contract_fail
    cmp qword ptr [r14 + 32], tk_S_REQUEST
    jne tk_contract_fail
    cmp qword ptr [r14 + 48], tk_S_REPLY
    jne tk_contract_fail
    cmp qword ptr [r14 + 56], 608
    jne tk_contract_fail
    mov rdx, [r14 + 64]
    or rdx, [r14 + 72]
    or rdx, [r14 + 88]
    jnz tk_contract_fail
    mov rcx, [r14 + 40]
    cmp rcx, [r12 + 136]
    jne tk_contract_fail
    cmp rcx, 2048
    ja tk_contract_fail
    test rcx, rcx
    jz tk_service_request_equal
    lea rsi, [r12 + tk_S_REQUEST]
    lea rdi, [r12 + 8192]
    repe cmpsb
    jne tk_contract_fail
tk_service_request_equal:
    cmp rax, 1
    je tk_service_allocate
    cmp rax, 2
    je tk_service_invoke_ticket
    cmp rax, 3
    je tk_service_dispose
    jmp tk_service_invoke_activity
tk_service_return:
    cmp eax, 608
    jbe tk_service_regular_return
    cmp eax, 0xffffffff
    je tk_service_done
    cmp eax, 0xfffffffe
    je tk_service_done
    cmp eax, 0xfffffff9
    jne tk_contract_fail
    jmp tk_service_done
tk_service_regular_return:
    cmp eax, 32
    jb tk_contract_fail
    cmp qword ptr [r12 + 8], 0
    jne tk_contract_fail
tk_service_done:
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

tk_service_grow:
    cmp qword ptr [r12 + 8], 0
    jne tk_contract_fail
    mov rbp, [r15 + tk_SERVICE_CAP]
    mov rax, [r12 + 32]
    add rax, 64
    jc tk_contract_fail
    cmp [r12 + 72], rax
    jne tk_contract_fail
    cmp rax, rbp
    jbe tk_contract_fail
tk_service_grow_size:
    shl rbp, 1
    jc tk_memory_fail
    cmp rbp, 33554432
    ja tk_memory_fail
    cmp rbp, rax
    jb tk_service_grow_size
    lea rdi, [rbp + 4095]
    and rdi, -4096
    mov r13, rdi
    call tk_allocate_guarded
    mov rbx, rax
    mov rdi, rax
    mov rsi, r12
    mov rcx, [r15 + tk_SERVICE_CAP]
    rep movsb
    mov rsi, [r15 + tk_SERVICE_MAPPING]
    add rsi, 4096
    mov [r15 + tk_SERVICE_WORK], rbx
    mov [r15 + tk_SERVICE_CAP], rbp
    mov [r15 + tk_SERVICE_MAPPING], r13
    mov rdi, r12
    mov eax, 11
    syscall
    test rax, rax
    jnz tk_io_fail
    jmp tk_service_resume

# r13 is the native entry selected by the HIA-owned aligned node offset.
tk_service_context_slot:
    mov rax, [r14 + 80]
    cmp rax, 16384
    jb tk_contract_fail
    cmp rax, [r12 + 32]
    jae tk_contract_fail
    mov rdx, rax
    sub rdx, 16384
    test rdx, 63
    jnz tk_contract_fail
    shr rdx, 6
    cmp rdx, [r15 + tk_SERVICE_SLOTS]
    jae tk_contract_fail
    cmp qword ptr [r12 + rax + 40], 1
    jne tk_service_slot_unallocated
    jmp tk_service_slot_node_ready
tk_service_slot_unallocated:
    cmp qword ptr [r14 + 16], 1
    jne tk_contract_fail
    cmp qword ptr [r12 + rax], 1
    jne tk_contract_fail
tk_service_slot_node_ready:
    mov rcx, [r14 + 24]
    test rcx, rcx
    jz tk_contract_fail
    cmp [r12 + rax + 8], rcx
    jne tk_contract_fail
    shl rdx, 4
    mov r13, [r15 + tk_SERVICE_TABLE]
    add r13, rdx
    ret

tk_service_allocate:
    cmp qword ptr [r14 + 40], 0
    jne tk_contract_fail
    mov rax, [r14 + 80]
    cmp rax, 16384
    jb tk_contract_fail
    sub rax, 16384
    test rax, 63
    jnz tk_contract_fail
    shr rax, 6
    mov rbp, [r15 + tk_SERVICE_SLOTS]
    cmp rax, rbp
    jb tk_service_table_ready
tk_service_table_size:
    shl rbp, 1
    jc tk_memory_fail
    cmp rax, rbp
    jae tk_service_table_size
    mov rdi, rbp
    shl rdi, 4
    jc tk_memory_fail
    add rdi, 4095
    jc tk_memory_fail
    and rdi, -4096
    mov r13, rdi
    call tk_allocate_guarded
    mov rbx, rax
    mov rdi, rax
    mov rsi, [r15 + tk_SERVICE_TABLE]
    mov rcx, [r15 + tk_SERVICE_SLOTS]
    shl rcx, 4
    rep movsb
    mov rdi, [r15 + tk_SERVICE_TABLE]
    mov rsi, [r15 + tk_SERVICE_TABLE_MAPPING]
    add rsi, 4096
    mov [r15 + tk_SERVICE_TABLE], rbx
    mov [r15 + tk_SERVICE_SLOTS], rbp
    mov [r15 + tk_SERVICE_TABLE_MAPPING], r13
    mov eax, 11
    syscall
    test rax, rax
    jnz tk_io_fail
tk_service_table_ready:
    call tk_service_context_slot
    mov rax, [r13]
    or rax, [r13 + 8]
    jnz tk_contract_fail
    mov edi, tk_CONTEXT_BYTES
    call tk_allocate_guarded
    mov rbx, rax
    mov [rbx], r15
    mov rax, [r14 + 24]
    mov [rbx + 256], rax
    lea rdx, [r15 + tk_GLOBAL_LOCK]
    mov [rbx + tk_LOCK_CONTEXT + 64], rdx
    mov [r13], rax
    mov [r13 + 8], rbx
    jmp tk_service_context_ack

tk_service_existing_context:
    call tk_service_context_slot
    mov rax, [r14 + 24]
    cmp [r13], rax
    jne tk_contract_fail
    mov rbx, [r13 + 8]
    test rbx, rbx
    jz tk_contract_fail
    cmp [rbx], r15
    jne tk_contract_fail
    cmp [rbx + 256], rax
    jne tk_contract_fail
    ret

tk_service_dispose:
    cmp qword ptr [r14 + 40], 0
    jne tk_contract_fail
    call tk_service_existing_context
    mov rax, [rbx + 72]
    test rax, rax
    jz tk_service_dispose_leaves
    cmp qword ptr [rax + 8], 0
    jne tk_contract_fail
    cmp qword ptr [rax + 128], 0
    jne tk_contract_fail
tk_service_dispose_leaves:
    cmp dword ptr [rbx + 96], 0
    jne tk_contract_fail
    cmp qword ptr [rbx + 104], 0
    jne tk_contract_fail
    mov rax, [rbx + tk_LEAF_WORK + 64]
    or rax, [rbx + tk_LEAF_WORK + 72]
    or rax, [rbx + tk_LEAF_WORK + 88]
    jnz tk_contract_fail
    mov rdi, rbx
    call tk_leaf_retire
    mov rdi, rbx
    call tk_ticket_storage_retire
    test rax, rax
    jnz tk_contract_fail
    cmp qword ptr [rbx + 248], 0
    jne tk_contract_fail
    mov qword ptr [r13], 0
    mov qword ptr [r13 + 8], 0
    mov rdi, [rbx + 72]
    test rdi, rdi
    jz tk_service_dispose_context
    mov esi, tk_TICKET_MAP_BYTES + 4096
    mov eax, 11
    syscall
    test rax, rax
    jnz tk_io_fail
tk_service_dispose_context:
    mov rdi, rbx
    mov esi, tk_CONTEXT_BYTES + 4096
    mov eax, 11
    syscall
    test rax, rax
    jnz tk_io_fail
tk_service_context_ack:
    lea rdi, [r12 + tk_S_REPLY]
    mov rax, 0x4b43415354415248
    mov [rdi], rax
    mov rax, [r14 + 24]
    mov [rdi + 8], rax
    mov rax, [r14 + 80]
    mov [rdi + 16], rax
    mov qword ptr [rdi + 24], 0
    mov eax, 32
    jmp tk_service_ack

tk_service_invoke_ticket:
    call tk_service_existing_context
    mov rcx, [r14 + 40]
    mov [rbx + 192], rcx
    lea rdi, [rbx + tk_FRAME_INPUT]
    lea rsi, [r12 + tk_S_REQUEST]
    rep movsb
    mov rdi, rbx
    call tk_ticket_call
tk_service_ticket_result:
    cmp eax, 0xfffffff0
    jne tk_service_ticket_complete
    cmp qword ptr [rbx + 104], 1
    jne tk_contract_fail
    mov rbp, [rbx + 72]
    test rbp, rbp
    jz tk_contract_fail
    mov rdi, rbx
    lea rsi, [rbp + 256]
    lea rdx, [rbp + 400000]
    mov rcx, [rbp + 296]
    cmp rcx, 270000
    ja tk_contract_fail
    lea r8, [rbp + 1200000]
    mov r9d, 270000
    call tk_ticket_storage_callback
    mov edx, eax
    cmp rax, rdx
    jne tk_contract_fail
    cmp eax, 48
    jb tk_contract_fail
    cmp eax, 270000
    ja tk_contract_fail
    lea rdi, [rbp + 1199968]
    mov rdx, 0x31304b4341545248
    mov [rdi], rdx
    mov rdx, [rbp + 264]
    mov [rdi + 8], rdx
    mov [rdi + 16], rax
    mov qword ptr [rdi + 24], 0
    add rax, 32
    mov [rbx + 192], rax
    mov rdi, rbx
    call tk_ticket_resume_call
    jmp tk_service_ticket_result
tk_service_ticket_complete:
    lea rsi, [rbx + tk_FRAME_OUTPUT]
    jmp tk_service_inner_reply
tk_service_invoke_activity:
    mov rax, [r14 + 24]
    or rax, [r14 + 80]
    jnz tk_contract_fail
    lea rdi, [r12 + tk_S_REQUEST]
    mov rsi, [r14 + 40]
    lea rdx, [r12 + tk_S_REPLY + 16]
    lea rcx, [r15 + tk_GLOBAL_ACTIVITY]
    call tk_public_active_policy_run
    lea rsi, [r12 + tk_S_REPLY + 16]
tk_service_inner_reply:
    mov edx, eax
    cmp rax, rdx
    jne tk_contract_fail
    mov rbp, rax
    cmp eax, 576
    jbe tk_service_inner_copy
    cmp eax, 0xffffffff
    je tk_service_inner_no_payload
    cmp eax, 0xfffffffe
    je tk_service_inner_no_payload
    cmp eax, 0xfffffff9
    jne tk_contract_fail
tk_service_inner_no_payload:
    xor ecx, ecx
    jmp tk_service_inner_header
tk_service_inner_copy:
    mov rcx, rax
    lea rdi, [r12 + tk_S_REPLY + 16]
    rep movsb
    mov rcx, rbp
tk_service_inner_header:
    mov rax, 0x3130495354415248
    mov [r12 + tk_S_REPLY], rax
    mov [r12 + tk_S_REPLY + 8], rbp
    lea rax, [rcx + 16]
tk_service_ack:
    mov [r14 + 72], rax
    mov rax, [r14 + 8]
    mov [r14 + 64], rax
    jmp tk_service_resume

tk_service_shutdown:
    mov rax, [r15 + tk_SERVICE_WORK]
    cmp qword ptr [rax + 8], 0
    jne tk_contract_fail
    cmp qword ptr [rax + 64], 0
    jne tk_contract_fail
    mov rdi, [r15 + tk_SERVICE_TABLE]
    mov rcx, [r15 + tk_SERVICE_SLOTS]
    shl rcx, 1
    xor eax, eax
    repe scasq
    jne tk_contract_fail
    mov rdi, r15
    call tk_ticket_storage_global_drop
    test rax, rax
    jnz tk_contract_fail
    lea rdi, [r15 + tk_GLOBAL_LOCK + 512]
    xor eax, eax
    mov ecx, 16
    rep stosq
    lea rdi, [r15 + tk_GLOBAL_LOCK + 512]
    mov rax, 0x313030514c415248
    mov [rdi], rax
    mov qword ptr [rdi + 8], 9
    mov esi, 128
    lea rdx, [r15 + tk_GLOBAL_LOCK + 640]
    lea rcx, [r15 + tk_GLOBAL_LOCK]
    call tk_lock_policy_run
    cmp qword ptr [r15 + tk_GLOBAL_LOCK + 656], 0
    jne tk_contract_fail
    mov rdi, [r15 + tk_GLOBAL_ENTROPY + 152]
    test rdi, rdi
    js tk_service_entropy_closed
    mov qword ptr [r15 + tk_GLOBAL_ENTROPY + 152], -1
    mov eax, 3
    syscall
tk_service_entropy_closed:
    cmp qword ptr [r15 + tk_GLOBAL_ENTROPY + 160], -1
    jne tk_contract_fail
    ret

# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
# Fixed native buffers and capability custody for the HIA StorageMapper.
.equ tk_TS_INPUT, 4096
.equ tk_TS_INPUT_CAP, 1052672
.equ tk_TS_OUTPUT, 1056768
.equ tk_TS_WORK, 2097152
.equ tk_TS_MAP_BYTES, 10485760
.equ tk_TS_ACTION, 256
.equ tk_TS_REQUEST, 4096
.equ tk_TS_REPLY, 2101248

# Original service callback ABI: context, action96, args, len, reply, capacity.
tk_ticket_storage_callback:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp, 24
    mov r13, rdi
    mov r14, rsi
    mov rbp, rdx
    mov rbx, rcx
    mov [rsp], r8
    mov [rsp + 8], r9
    cmp r9, 270000
    jne tk_contract_fail
    cmp rbx, 8
    jb tk_contract_fail
    cmp rbx, 270000
    ja tk_contract_fail
    mov rax, [r13 + 72]
    test rax, rax
    jz tk_contract_fail
    lea rdx, [rax + 256]
    cmp r14, rdx
    jne tk_contract_fail
    lea rdx, [rax + 400000]
    cmp rbp, rdx
    jne tk_contract_fail
    lea rdx, [rax + 1200000]
    cmp r8, rdx
    jne tk_contract_fail
    cmp [r14 + 40], rbx
    jne tk_contract_fail
    mov rax, 0x3130304154415248
    cmp [r14], rax
    jne tk_contract_fail
    mov rax, [r13 + 112]
    cmp [r14 + 8], rax
    jne tk_contract_fail
    mov rax, [r14 + 64]
    or rax, [r14 + 72]
    or rax, [r14 + 80]
    or rax, [r14 + 88]
    jnz tk_contract_fail
    mov r15, [r13 + 248]
    test r15, r15
    jnz tk_ts_have_context
    cmp qword ptr [r14 + 16], 101
    jne tk_contract_fail
    mov r12, [r13]
    mov rax, [r12 + 24576]
    test rax, rax
    jnz tk_ts_have_global
    mov edi, 4096
    call tk_allocate_guarded
    mov rdx, 0x3130475354415248
    mov [rax], rdx
    mov [rax + 8], r12
    mov [r12 + 24576], rax
    mov rdi, rax
    call tk_ticket_backend_create
    test rax, rax
    jz tk_contract_fail
    mov rdx, [r12 + 24576]
    mov [rdx + 16], rax
    mov rax, rdx
tk_ts_have_global:
    mov [rsp + 16], rax
    mov edi, tk_TS_MAP_BYTES
    call tk_allocate_guarded
    mov r15, rax
    mov rdx, 0x3130435354415248
    mov [r15], rdx
    mov [r15 + 8], r13
    mov rax, [rsp + 16]
    mov [r15 + 16], rax
    mov rcx, [rax + 40]
    mov [r15 + 24], rcx
    test rcx, rcx
    jz tk_ts_link_head
    cmp qword ptr [rcx + 32], 0
    jne tk_contract_fail
    mov [rcx + 32], r15
tk_ts_link_head:
    mov [rax + 40], r15
    mov [r13 + 248], r15
    call tk_ticket_directory_create
    mov [r15 + 80], rax
tk_ts_have_context:
    mov rax, 0x3130435354415248
    cmp [r15], rax
    jne tk_contract_fail
    cmp [r15 + 8], r13
    jne tk_contract_fail
    cmp qword ptr [r15 + 64], 0
    jne tk_contract_fail
    mov rdx, [r15 + 16]
    mov rax, 0x3130475354415248
    cmp [rdx], rax
    jne tk_contract_fail
    mov rax, [r13]
    cmp [rdx + 8], rax
    jne tk_contract_fail
    cmp qword ptr [rdx + 56], 0
    jne tk_contract_fail
    mov qword ptr [rdx + 56], 1
    mov qword ptr [r15 + 64], 1
    mov rax, [rsp]
    mov [r15 + 40], rax
    mov [r15 + 72], r14
    mov [r15 + 88], rbp
    mov [r15 + 96], rbx
    mov rax, [rsp + 8]
    mov [r15 + 104], rax
    lea rdi, [r15 + 256]
    mov rsi, r14
    mov ecx, 12
    rep movsq
    mov qword ptr [r15 + 128], 0
    mov qword ptr [r15 + 136], 0
    cmp qword ptr [r14 + 16], 101
    jne tk_ts_path_ready
    cmp rbx, 8
    jne tk_contract_fail
    mov rdi, r13
    mov rsi, [rbp]
    call tk_ticket_root_path
    test rax, rax
    jz tk_contract_fail
    cmp rdx, 1048528
    ja tk_contract_fail
    mov [r15 + 128], rax
    mov [r15 + 136], rdx
tk_ts_path_ready:
    lea r12, [r15 + tk_TS_WORK]
    cmp qword ptr [r12 + 8], 0
    jne tk_contract_fail
    lea rdi, [r15 + tk_TS_INPUT]
    mov esi, tk_TS_INPUT_CAP
    mov edx, 3
    mov eax, 10
    syscall
    test rax, rax
    jnz tk_io_fail
    lea rdi, [r15 + tk_TS_INPUT]
    mov rax, 0x3130515354415248
    mov [rdi], rax
    mov rax, [r14 + 16]
    mov [rdi + 8], rax
    mov rax, [r14 + 24]
    mov [rdi + 16], rax
    mov [rdi + 24], rbx
    mov rax, [r15 + 136]
    mov [rdi + 32], rax
    mov qword ptr [rdi + 40], 0
    add rdi, 48
    mov rsi, rbp
    mov rcx, rbx
    rep movsb
    mov rsi, [r15 + 128]
    mov rcx, [r15 + 136]
    rep movsb
    mov rax, [r15 + 136]
    lea rax, [rax + rbx + 48]
    cmp rax, 1048584
    ja tk_contract_fail
    mov [r15 + 48], rax
    lea rdi, [r15 + tk_TS_INPUT]
    mov esi, tk_TS_INPUT_CAP
    mov edx, 1
    mov eax, 10
    syscall
    test rax, rax
    jnz tk_io_fail
tk_ts_resume:
    lea rdi, [r15 + tk_TS_INPUT]
    mov rsi, [r15 + 48]
    lea rdx, [r15 + tk_TS_OUTPUT]
    mov ecx, 270000
    mov r8, r12
    mov r9d, 8388608
    call qword ptr [rip + tk_ticket_storage_image]
    mov edx, eax
    cmp rax, rdx
    jne tk_contract_fail
    cmp eax, 0xfffffff0
    jne tk_ts_result
    lea r14, [r12 + tk_TS_ACTION]
    mov rax, 0x3130415354415248
    cmp [r14], rax
    jne tk_contract_fail
    mov rax, [r15 + 56]
    inc rax
    jz tk_contract_fail
    cmp [r14 + 8], rax
    jne tk_contract_fail
    cmp [r12 + 16], rax
    jne tk_contract_fail
    mov [r15 + 56], rax
    cmp qword ptr [r14 + 32], tk_TS_REQUEST
    jne tk_contract_fail
    cmp qword ptr [r14 + 48], tk_TS_REPLY
    jne tk_contract_fail
    cmp qword ptr [r14 + 56], 270000
    jne tk_contract_fail
    mov rcx, [r14 + 40]
    cmp rcx, 16
    jb tk_contract_fail
    cmp rcx, 1048576
    ja tk_contract_fail
    lea rsi, [r12 + tk_TS_REQUEST]
    lea rdi, [r12 + 1052672]
    repe cmpsb
    jne tk_contract_fail
    lea rsi, [r14 + 16]
    lea rdi, [r12 + 384]
    mov ecx, 6
    repe cmpsq
    jne tk_contract_fail
    mov rsi, r12
    lea rdi, [r12 + 512]
    mov ecx, 30
    repe cmpsq
    jne tk_contract_fail
    mov rax, [r14 + 64]
    or rax, [r14 + 72]
    or rax, [r14 + 80]
    or rax, [r14 + 88]
    jnz tk_contract_fail
    mov rax, [r14 + 16]
    cmp rax, 1
    je tk_ts_hot_directory
    cmp rax, 2
    je tk_ts_base_directory
    cmp rax, 7
    je tk_ts_raw_write
    cmp rax, 3
    jb tk_contract_fail
    cmp rax, 8
    ja tk_contract_fail
    mov rdi, [r15 + 16]
    mov rsi, r14
    lea rdx, [r12 + tk_TS_REQUEST]
    mov rcx, [r14 + 40]
    lea r8, [r12 + tk_TS_REPLY]
    mov r9, [r15 + 80]
    call tk_ticket_backend_call
    jmp tk_ts_ack
tk_ts_hot_directory:
    mov rdi, [r15 + 80]
    jmp tk_ts_directory_invoke
tk_ts_base_directory:
    mov rbx, [r15 + 16]
    mov rdi, [rbx + 24]
    test rdi, rdi
    jnz tk_ts_directory_invoke
    call tk_ticket_directory_create
    mov [rbx + 24], rax
    mov rdi, rax
tk_ts_directory_invoke:
    lea rsi, [r12 + tk_TS_REQUEST]
    mov rdx, [r14 + 40]
    lea rcx, [r12 + tk_TS_REPLY]
    call tk_ticket_directory_call
    jmp tk_ts_ack
tk_ts_raw_write:
    mov rbx, [r15 + 16]
    mov rax, [rbx + 32]
    test rax, rax
    jnz tk_ts_writer_ready
    call tk_ticket_raw_write_create
    mov [rbx + 32], rax
tk_ts_writer_ready:
    mov rdi, [r15 + 80]
    mov rsi, [r14 + 24]
    cmp rsi, [r12 + 80]
    jne tk_contract_fail
    call tk_ticket_directory_borrow
    mov r8, rax
    mov rdi, [rbx + 32]
    lea rsi, [r12 + tk_TS_REQUEST]
    mov rdx, [r14 + 40]
    lea rcx, [r12 + tk_TS_REPLY]
    call tk_ticket_raw_write_call
tk_ts_ack:
    mov edx, eax
    cmp rax, rdx
    jne tk_contract_fail
    cmp rax, 270000
    ja tk_contract_fail
    mov [r14 + 72], rax
    mov rax, [r14 + 8]
    mov [r14 + 64], rax
    jmp tk_ts_resume
tk_ts_result:
    cmp eax, 48
    jb tk_contract_fail
    cmp eax, 270000
    ja tk_contract_fail
    cmp qword ptr [r12 + 8], 0
    jne tk_contract_fail
    mov ebx, eax
    mov rsi, [r15 + 72]
    lea rdi, [r15 + 256]
    mov ecx, 12
    repe cmpsq
    jne tk_contract_fail
    mov rsi, [r15 + 88]
    lea rdi, [r15 + tk_TS_INPUT + 48]
    mov rcx, [r15 + 96]
    repe cmpsb
    jne tk_contract_fail
    cmp rbx, [r15 + 104]
    ja tk_contract_fail
    mov rdi, [r15 + 40]
    lea rsi, [r15 + tk_TS_OUTPUT]
    mov rcx, rbx
    rep movsb
    mov qword ptr [r15 + 40], 0
    mov qword ptr [r15 + 72], 0
    mov qword ptr [r15 + 88], 0
    mov qword ptr [r15 + 96], 0
    mov qword ptr [r15 + 104], 0
    mov qword ptr [r15 + 64], 0
    mov rdx, [r15 + 16]
    cmp qword ptr [rdx + 56], 1
    jne tk_contract_fail
    mov qword ptr [rdx + 56], 0
    mov eax, ebx
    add rsp, 24
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

tk_ticket_storage_retire:
    push rbx
    push r12
    push r13
    mov r13, rdi
    mov rbx, [rdi + 248]
    test rbx, rbx
    jz tk_ts_retired
    mov rax, 0x3130435354415248
    cmp [rbx], rax
    jne tk_contract_fail
    cmp [rbx + 8], r13
    jne tk_contract_fail
    mov r12, [rbx + 16]
    mov rax, [rbx + 64]
    or rax, [rbx + tk_TS_WORK + 8]
    or rax, [rbx + tk_TS_WORK + 80]
    or rax, [rbx + tk_TS_WORK + 88]
    or rax, [rbx + tk_TS_WORK + 96]
    or rax, [r12 + 56]
    jnz tk_contract_fail
    mov rdi, [rbx + 80]
    call tk_ticket_directory_drop
    mov qword ptr [rbx + 80], 0
    mov rax, [rbx + 24]
    mov rdx, [rbx + 32]
    test rax, rax
    jz tk_ts_unlink_previous
    cmp [rax + 32], rbx
    jne tk_contract_fail
    mov [rax + 32], rdx
tk_ts_unlink_previous:
    test rdx, rdx
    jz tk_ts_unlink_head
    cmp [rdx + 24], rbx
    jne tk_contract_fail
    mov [rdx + 24], rax
    jmp tk_ts_unlinked
tk_ts_unlink_head:
    cmp [r12 + 40], rbx
    jne tk_contract_fail
    mov [r12 + 40], rax
tk_ts_unlinked:
    mov qword ptr [r13 + 248], 0
    mov rdi, rbx
    mov esi, tk_TS_MAP_BYTES + 4096
    mov eax, 11
    syscall
    test rax, rax
    jnz tk_io_fail
tk_ts_retired:
    xor eax, eax
    pop r13
    pop r12
    pop rbx
    ret

# Called after the service has driven original Drop on every live Ticket.
tk_ticket_storage_global_drop:
    push rbx
    push r12
    sub rsp, 8
    mov r12, rdi
    mov rbx, [rdi + 24576]
    test rbx, rbx
    jz tk_ts_global_retired
    mov rax, 0x3130475354415248
    cmp [rbx], rax
    jne tk_contract_fail
    cmp [rbx + 8], r12
    jne tk_contract_fail
    mov rax, [rbx + 40]
    or rax, [rbx + 56]
    jnz tk_contract_fail
    mov rdi, rbx
    call tk_ticket_backend_drop
    mov rdi, [rbx + 32]
    call tk_ticket_raw_write_drop
    mov rdi, [rbx + 24]
    call tk_ticket_directory_drop
    mov qword ptr [r12 + 24576], 0
    mov rdi, rbx
    mov esi, 8192
    mov eax, 11
    syscall
    test rax, rax
    jnz tk_io_fail
tk_ts_global_retired:
    xor eax, eax
    add rsp, 8
    pop r12
    pop rbx
    ret

.intel_syntax noprefix
.section .text
.equ tk_td_INPUT, 4096
.equ tk_td_INPUT_CAP, 1048576
.equ tk_td_OUTPUT, 1056768
.equ tk_td_OUTPUT_CAP, 64
.equ tk_td_IO_WORK, 2097152
.equ tk_td_MAP_SIZE, 6295552
.equ tk_td_ACTION, 256
.equ tk_td_STAT, 8192
.equ tk_td_NAME, 65536
tk_td_resume_io:
    lea rdi, [r15 + tk_td_INPUT]
    mov rsi, [r15 + 24]
    lea rdx, [r15 + tk_td_OUTPUT]
    mov ecx, tk_td_OUTPUT_CAP
    mov r8, r12
    mov r9d, 4194304
    call qword ptr [rip + tk_ticket_directory_image]
    cmp eax, 0xfffffff0
    jne tk_td_io_result
    lea r14, [r12 + tk_td_ACTION]
    mov rax, 0x3130304144415248
    cmp [r14], rax
    jne tk_contract_fail
    mov rax, [r15 + 8]
    inc rax
    jz tk_contract_fail
    cmp [r14 + 8], rax
    jne tk_contract_fail
    cmp [r12 + 16], rax
    jne tk_contract_fail
    mov [r15 + 8], rax
    mov rax, [r14 + 56]
    or rax, [r14 + 64]
    or rax, [r14 + 72]
    or rax, [r14 + 80]
    or rax, [r14 + 88]
    jnz tk_contract_fail
    mov rax, [r14 + 16]
    cmp rax, 1
    je tk_td_open_slash
    cmp rax, 2
    je tk_td_open_component
    cmp rax, 3
    je tk_td_stat_effect
    cmp rax, 4
    je tk_td_mkdir_effect
    cmp rax, 5
    je tk_td_sync_effect
    cmp rax, 6
    je tk_td_close_effect
    cmp rax, 7
    je tk_td_transfer_effect
    cmp rax, 8
    je tk_td_open_component
    jmp tk_contract_fail

tk_td_vacant_slot:
    mov rbx, [r14 + 24]
    cmp rbx, 1
    jb tk_contract_fail
    cmp rbx, 2
    ja tk_contract_fail
    cmp qword ptr [r15 + rbx*8 + 120], -1
    jne tk_contract_fail
    ret
tk_td_live_slot:
    mov rcx, [r14 + 24]
    cmp rcx, 1
    jb tk_contract_fail
    cmp rcx, 3
    ja tk_contract_fail
    mov rdi, [r15 + rcx*8 + 120]
    test rdi, rdi
    js tk_contract_fail
    ret
tk_td_name_span:
    cmp qword ptr [r14 + 32], tk_td_NAME
    jne tk_contract_fail
    mov rcx, [r14 + 40]
    test rcx, rcx
    jz tk_contract_fail
    cmp rcx, 1048528
    ja tk_contract_fail
    lea rdi, [r12 + tk_td_NAME]
    xor eax, eax
    repne scasb
    je tk_contract_fail
    cmp byte ptr [rdi], 0
    jne tk_contract_fail
    ret
tk_td_store_checked:
    call tk_td_name_span
    cmp qword ptr [r14 + 40], 13
    jne tk_contract_fail
    lea rsi, [rip + tk_td_store_literal]
    lea rdi, [r12 + tk_td_NAME]
    mov ecx, 13
    repe cmpsb
    jne tk_contract_fail
    ret
tk_td_parent_slot:
    mov rcx, [r14 + 48]
    cmp rcx, 1
    jb tk_contract_fail
    cmp rcx, 2
    ja tk_contract_fail
    mov rdi, [r15 + rcx*8 + 120]
    test rdi, rdi
    js tk_contract_fail
    ret
tk_td_open_slash:
    call tk_td_vacant_slot
    call tk_td_name_span
    cmp qword ptr [r14 + 48], 0
    jne tk_contract_fail
    cmp qword ptr [r14 + 40], 1
    jne tk_contract_fail
    cmp byte ptr [r12 + tk_td_NAME], 47
    jne tk_contract_fail
    mov edi, -100
    mov edx, 0x2b0000
    jmp tk_td_open_syscall
tk_td_open_component:
    call tk_td_vacant_slot
    cmp qword ptr [r12 + 8], 14
    je tk_td_open_store
    cmp qword ptr [r12 + 8], 2
    jne tk_contract_fail
    call tk_td_name_span
    mov rdx, [r12 + 96]
    cmp rdx, [r15 + 24]
    ja tk_contract_fail
    mov rcx, [r14 + 40]
    sub rdx, rcx
    jc tk_contract_fail
    cmp rdx, 48
    jb tk_contract_fail
    lea rsi, [r15 + rdx + tk_td_INPUT]
    lea rdi, [r12 + tk_td_NAME]
    repe cmpsb
    jne tk_contract_fail
    jmp tk_td_component_checked
tk_td_open_store:
    call tk_td_store_checked
tk_td_component_checked:
    call tk_td_parent_slot
    mov edx, 0xb0000
    cmp qword ptr [r14 + 16], 8
    jne tk_td_open_syscall
    mov edx, 0x2b0000
tk_td_open_syscall:
    lea rsi, [r12 + tk_td_NAME]
    xor r10d, r10d
    mov eax, 257
    syscall
    test rax, rax
    js tk_td_effect_error
    mov [r15 + rbx*8 + 120], rax
    mov [r14 + 72], rbx
    jmp tk_td_acknowledge
tk_td_stat_effect:
    call tk_td_live_slot
    cmp qword ptr [r14 + 32], tk_td_STAT
    jne tk_contract_fail
    cmp qword ptr [r14 + 40], 152
    jne tk_contract_fail
    cmp qword ptr [r14 + 48], 1
    ja tk_contract_fail
    lea rsi, [r12 + tk_td_STAT]
    mov eax, 5
    syscall
    test rax, rax
    js tk_td_effect_error
    cmp qword ptr [r14 + 48], 1
    je tk_td_acknowledge
    mov eax, 107
    syscall
    mov [r12 + tk_td_STAT + 144], rax
    jmp tk_td_acknowledge
tk_td_mkdir_effect:
    call tk_td_store_checked
    call tk_td_live_slot
    cmp qword ptr [r14 + 48], 448
    jne tk_contract_fail
    lea rsi, [r12 + tk_td_NAME]
    mov edx, 448
    mov eax, 258
    syscall
    test rax, rax
    js tk_td_effect_error
    jmp tk_td_acknowledge
tk_td_zero_span:
    mov rax, [r14 + 32]
    or rax, [r14 + 40]
    or rax, [r14 + 48]
    jnz tk_contract_fail
    ret
tk_td_sync_effect:
    call tk_td_zero_span
    call tk_td_live_slot
    mov eax, 74
    syscall
    test rax, rax
    js tk_td_effect_error
    jmp tk_td_acknowledge
tk_td_close_effect:
    call tk_td_zero_span
    call tk_td_live_slot
    mov qword ptr [r15 + rcx*8 + 120], -1
    mov eax, 3
    syscall
    jmp tk_td_acknowledge
tk_td_transfer_effect:
    call tk_td_live_slot
    cmp rcx, 2
    ja tk_contract_fail
    mov rax, [r14 + 32]
    or rax, [r14 + 40]
    jnz tk_contract_fail
    cmp qword ptr [r14 + 48], 3
    jne tk_contract_fail
    cmp qword ptr [r15 + 144], -1
    jne tk_contract_fail
    mov [r15 + 144], rdi
    mov qword ptr [r15 + rcx*8 + 120], -1
    mov qword ptr [r14 + 72], 3
    jmp tk_td_acknowledge
tk_td_effect_error:
    neg rax
    cmp rax, 4095
    ja tk_contract_fail
    mov [r14 + 80], rax
tk_td_acknowledge:
    mov rax, [r14 + 8]
    mov [r14 + 64], rax
    jmp tk_td_resume_io
tk_td_io_result:
    jmp tk_td_return
tk_td_store_literal:
    .ascii "request-audit"

.equ tk_tw_INPUT, 4096
.equ tk_tw_INPUT_CAP, 1048576
.equ tk_tw_OUTPUT, 1056768
.equ tk_tw_OUTPUT_CAP, 512
.equ tk_tw_OWNER, 6291456
.equ tk_tw_WRITE_OWNER, 2097152
.equ tk_tw_W_STAT, 8192
.equ tk_tw_W_FILENAME, 65536
.equ tk_tw_W_TEMPORARY, 73728
.equ tk_tw_W_NEW_BYTES, 32768
.equ tk_tw_W_CHILD_REQUEST, 1048576
.equ tk_tw_W_CHILD_REPLY, 16384
.equ tk_tw_JSON_WORK, 10485760
.equ tk_tw_MAP_SIZE, 11538432
.equ tk_tw_ACTION, 256
.equ tk_tw_STAT, 1024
.equ tk_tw_FILENAME, 4096
.equ tk_tw_TEMPORARY, 4224
.equ tk_tw_CLEAN_NAME, 4480
.equ tk_tw_CLEAN_TARGET, 4800
.equ tk_tw_DOT, 4928
.equ tk_tw_CHILD_REQUEST, 8192
.equ tk_tw_CHILD_REPLY, 12288
.equ tk_tw_READ_BYTES, 24576
.equ tk_tw_DIR_BYTES, 65536
tk_tw_resume_owner:
    lea rdi, [r13 + tk_tw_W_CHILD_REQUEST]
    mov rsi, [r13 + tk_tw_ACTION + 40]
    lea rdx, [r13 + tk_tw_W_CHILD_REPLY]
    mov ecx, tk_tw_OUTPUT_CAP
    mov r8, r12
    mov r9d, 4194304
    call qword ptr [rip + tk_ticket_raw_read_image]
    cmp eax, 0xfffffff0
    jne tk_tw_owner_result
    lea r14, [r12 + tk_tw_ACTION]
    mov rax, 0x3130304152415248
    cmp [r14], rax
    jne tk_contract_fail
    mov rax, [r15 + 16]
    inc rax
    jz tk_contract_fail
    cmp [r14 + 8], rax
    jne tk_contract_fail
    cmp [r12 + 16], rax
    jne tk_contract_fail
    mov [r15 + 16], rax
    mov rax, [r14 + 64]
    or rax, [r14 + 72]
    or rax, [r14 + 80]
    or rax, [r14 + 88]
    jnz tk_contract_fail
    mov rax, [r14 + 16]
    cmp rax, 100
    je tk_tw_json_effect
    cmp qword ptr [r14 + 56], 0
    jne tk_contract_fail
    cmp rax, 1
    je tk_tw_stat_effect
    cmp rax, 2
    je tk_tw_open_effect
    cmp rax, 3
    je tk_tw_read_effect
    cmp rax, 5
    je tk_tw_sync_effect
    cmp rax, 8
    je tk_tw_unlink_effect
    cmp rax, 9
    je tk_tw_close_effect
    cmp rax, 10
    je tk_tw_scan_open_effect
    cmp rax, 11
    je tk_tw_duplicate_effect
    cmp rax, 12
    je tk_tw_flags_effect
    cmp rax, 13
    je tk_tw_directory_effect
    jmp tk_contract_fail
tk_tw_json_effect:
    cmp qword ptr [r14 + 24], 0
    jne tk_contract_fail
    cmp qword ptr [r14 + 32], tk_tw_CHILD_REQUEST
    jne tk_contract_fail
    cmp qword ptr [r14 + 40], 24
    jb tk_contract_fail
    cmp qword ptr [r14 + 40], 2072
    ja tk_contract_fail
    cmp qword ptr [r14 + 48], tk_tw_CHILD_REPLY
    jne tk_contract_fail
    cmp qword ptr [r14 + 56], 4096
    jne tk_contract_fail
    lea rdi, [r12 + tk_tw_CHILD_REQUEST]
    mov rsi, [r14 + 40]
    lea rdx, [r12 + tk_tw_CHILD_REPLY]
    mov ecx, 4096
    lea r8, [r15 + tk_tw_JSON_WORK]
    mov r9d, 1048576
    call qword ptr [rip + tk_ticket_json_image]
    mov [r12 + tk_tw_ACTION + 72], rax
    jmp tk_tw_acknowledge
tk_tw_live_slot:
    mov rcx, [r14 + 24]
    cmp rcx, 6
    ja tk_contract_fail
    mov rdi, [r15 + rcx*8 + 128]
    test rdi, rdi
    js tk_contract_fail
    ret
tk_tw_zero_span:
    mov rax, [r14 + 32]
    or rax, [r14 + 40]
    or rax, [r14 + 48]
    jnz tk_contract_fail
    ret
tk_tw_stat_effect:
    call tk_tw_live_slot
    test rcx, rcx
    jz tk_contract_fail
    cmp qword ptr [r14 + 32], tk_tw_STAT
    jne tk_contract_fail
    cmp qword ptr [r14 + 40], 152
    jne tk_contract_fail
    cmp qword ptr [r14 + 48], 1
    ja tk_contract_fail
    lea rsi, [r12 + tk_tw_STAT]
    mov eax, 5
    syscall
    test rax, rax
    js tk_tw_effect_error
    cmp qword ptr [r14 + 48], 1
    je tk_tw_acknowledge
    mov eax, 107
    syscall
    mov [r12 + tk_tw_STAT + 144], rax
    jmp tk_tw_acknowledge
tk_tw_name_span:
    mov rax, [r14 + 32]
    mov rdx, [r14 + 40]
    cmp rax, tk_tw_FILENAME
    je tk_tw_record_name
    cmp rax, tk_tw_CLEAN_TARGET
    je tk_tw_record_name
    cmp rax, tk_tw_TEMPORARY
    je tk_tw_staging_name
    cmp rax, tk_tw_CLEAN_NAME
    jne tk_contract_fail
tk_tw_staging_name:
    cmp rdx, 134
    jne tk_contract_fail
    lea rsi, [r12 + rax]
    cmp byte ptr [rsi], 46
    jne tk_contract_fail
    cmp byte ptr [rsi + 65], 45
    jne tk_contract_fail
    cmp dword ptr [rsi + 130], 0x706d742e
    jne tk_contract_fail
    cmp byte ptr [rsi + 134], 0
    jne tk_contract_fail
    inc rsi
    call tk_tw_hex64
    add rsi, 65
    call tk_tw_hex64
    sub rsi, 66
    ret
tk_tw_record_name:
    cmp rdx, 69
    jne tk_contract_fail
    lea rsi, [r12 + rax]
    call tk_tw_hex64
    cmp dword ptr [rsi + 64], 0x6f736a2e
    jne tk_contract_fail
    cmp byte ptr [rsi + 68], 110
    jne tk_contract_fail
    cmp byte ptr [rsi + 69], 0
    jne tk_contract_fail
    ret
tk_tw_hex64:
    xor r8d, r8d
tk_tw_hex_loop:
    mov dl, [rsi + r8]
    cmp dl, 48
    jb tk_contract_fail
    cmp dl, 57
    jbe tk_tw_hex_good
    cmp dl, 97
    jb tk_contract_fail
    cmp dl, 102
    ja tk_contract_fail
tk_tw_hex_good:
    inc r8d
    cmp r8d, 64
    jne tk_tw_hex_loop
    ret
tk_tw_open_effect:
    cmp qword ptr [r14 + 48], 0
    jne tk_contract_fail
    mov rcx, [r14 + 24]
    cmp rcx, 1
    je tk_tw_open_slot_ok
    cmp rcx, 2
    je tk_tw_open_slot_ok
    cmp rcx, 5
    je tk_tw_open_slot_ok
    cmp rcx, 6
    jne tk_contract_fail
tk_tw_open_slot_ok:
    cmp qword ptr [r15 + rcx*8 + 128], -1
    jne tk_contract_fail
    call tk_tw_name_span
    mov rdi, [r15 + 128]
    mov edx, 0xa0800
    xor r10d, r10d
    jmp tk_tw_issue_open
tk_tw_scan_open_effect:
    cmp qword ptr [r14 + 24], 3
    jne tk_contract_fail
    cmp qword ptr [r15 + 152], -1
    jne tk_contract_fail
    cmp qword ptr [r14 + 32], tk_tw_DOT
    jne tk_contract_fail
    cmp qword ptr [r14 + 40], 1
    jne tk_contract_fail
    cmp qword ptr [r14 + 48], 0
    jne tk_contract_fail
    cmp qword ptr [r12 + tk_tw_DOT], 46
    jne tk_contract_fail
    mov rdi, [r15 + 128]
    lea rsi, [r12 + tk_tw_DOT]
    mov edx, 0xb0000
    xor r10d, r10d
tk_tw_issue_open:
    mov eax, 257
    syscall
    test rax, rax
    js tk_tw_effect_error
    cmp rax, 0x7fffffff
    ja tk_contract_fail
    mov rcx, [r14 + 24]
    mov [r15 + rcx*8 + 128], rax
    mov [r14 + 72], rcx
    jmp tk_tw_acknowledge
tk_tw_read_effect:
    call tk_tw_live_slot
    cmp rcx, 1
    jne tk_contract_fail
    cmp qword ptr [r14 + 48], 0
    jne tk_contract_fail
    mov rax, [r12 + 88]
    cmp rax, 2048
    ja tk_contract_fail
    lea rsi, [rax + tk_tw_READ_BYTES]
    cmp rsi, [r14 + 32]
    jne tk_contract_fail
    mov edx, 2049
    sub rdx, rax
    cmp rdx, [r14 + 40]
    jne tk_contract_fail
    add rsi, r12
    xor eax, eax
    syscall
    jmp tk_tw_value_effect
tk_tw_sync_effect:
    call tk_tw_zero_span
    call tk_tw_live_slot
    test rcx, rcx
    jnz tk_contract_fail
    mov eax, 74
    syscall
    test rax, rax
    js tk_tw_effect_error
    jmp tk_tw_acknowledge
tk_tw_unlink_effect:
    cmp qword ptr [r14 + 24], 0
    jne tk_contract_fail
    cmp qword ptr [r14 + 32], tk_tw_CLEAN_NAME
    jne tk_contract_fail
    cmp qword ptr [r14 + 48], 0
    jne tk_contract_fail
    call tk_tw_name_span
    mov rdi, [r15 + 128]
    xor edx, edx
    mov eax, 263
    syscall
    test rax, rax
    js tk_tw_effect_error
    jmp tk_tw_acknowledge
tk_tw_close_effect:
    call tk_tw_zero_span
    call tk_tw_live_slot
    test rcx, rcx
    jz tk_contract_fail
    mov qword ptr [r15 + rcx*8 + 128], -1
    mov eax, 3
    syscall
    test rax, rax
    js tk_tw_effect_error
    jmp tk_tw_acknowledge
tk_tw_duplicate_effect:
    cmp qword ptr [r14 + 24], 4
    jne tk_contract_fail
    cmp qword ptr [r14 + 32], 0
    jne tk_contract_fail
    cmp qword ptr [r14 + 40], 0
    jne tk_contract_fail
    cmp qword ptr [r14 + 48], 3
    jne tk_contract_fail
    cmp qword ptr [r15 + 160], -1
    jne tk_contract_fail
    mov rdi, [r15 + 152]
    test rdi, rdi
    js tk_contract_fail
    mov esi, 1030
    xor edx, edx
    mov eax, 72
    syscall
    test rax, rax
    js tk_tw_effect_error
    mov [r15 + 160], rax
    mov qword ptr [r14 + 72], 4
    jmp tk_tw_acknowledge
tk_tw_flags_effect:
    call tk_tw_zero_span
    call tk_tw_live_slot
    cmp rcx, 4
    jne tk_contract_fail
    mov esi, 3
    xor edx, edx
    mov eax, 72
    syscall
    jmp tk_tw_value_effect
tk_tw_directory_effect:
    call tk_tw_live_slot
    cmp rcx, 4
    jne tk_contract_fail
    cmp qword ptr [r14 + 32], tk_tw_DIR_BYTES
    jne tk_contract_fail
    cmp qword ptr [r14 + 48], 0
    jne tk_contract_fail
    mov rdx, [r14 + 40]
    cmp rdx, 32768
    jb tk_contract_fail
    cmp rdx, 1048576
    ja tk_contract_fail
    cmp rdx, [r12 + 136]
    jne tk_contract_fail
    lea rsi, [r12 + tk_tw_DIR_BYTES]
    mov eax, 217
    syscall
tk_tw_value_effect:
    test rax, rax
    js tk_tw_effect_error
    mov [r14 + 72], rax
    jmp tk_tw_acknowledge
tk_tw_effect_error:
    cmp rax, -4095
    jb tk_contract_fail
    neg rax
    mov [r14 + 80], rax
tk_tw_acknowledge:
    mov rax, [r12 + tk_tw_ACTION + 8]
    mov [r12 + tk_tw_ACTION + 64], rax
    jmp tk_tw_resume_owner
tk_tw_owner_result:
    mov ecx, 1
tk_tw_check_slots:
    cmp qword ptr [r15 + rcx*8 + 128], -1
    jne tk_contract_fail
    inc ecx
    cmp ecx, 7
    jne tk_tw_check_slots
    cmp qword ptr [r12 + 8], 0
    jne tk_contract_fail
    mov [r13 + tk_tw_ACTION + 72], rax
    mov rax, [r13 + tk_tw_ACTION + 8]
    mov [r13 + tk_tw_ACTION + 64], rax
    jmp tk_tw_resume_write
tk_tw_resume_write:
    lea rdi, [r15 + tk_tw_INPUT]
    mov rsi, [r15 + 24]
    lea rdx, [r15 + tk_tw_OUTPUT]
    mov ecx, tk_tw_OUTPUT_CAP
    mov r8, r13
    mov r9d, 4194304
    call qword ptr [rip + tk_ticket_raw_write_image]
    cmp eax, 0xfffffff0
    jne tk_tw_write_result
    lea r14, [r13 + tk_tw_ACTION]
    mov rax, 0x3130304157415248
    cmp [r14], rax
    jne tk_contract_fail
    mov rax, [r15 + 8]
    inc rax
    jz tk_contract_fail
    cmp [r14 + 8], rax
    jne tk_contract_fail
    cmp [r13 + 16], rax
    jne tk_contract_fail
    mov [r15 + 8], rax
    mov rax, [r14 + 64]
    or rax, [r14 + 72]
    or rax, [r14 + 80]
    or rax, [r14 + 88]
    jnz tk_contract_fail
    mov rax, [r14 + 16]
    cmp rax, 100
    je tk_tw_w_read_start
    cmp qword ptr [r14 + 56], 0
    jne tk_contract_fail
    cmp rax, 1
    je tk_tw_w_stat
    cmp rax, 2
    je tk_tw_w_open
    cmp rax, 4
    je tk_tw_w_write
    cmp rax, 5
    je tk_tw_w_sync
    cmp rax, 6
    je tk_tw_w_link
    cmp rax, 7
    je tk_tw_w_rename
    cmp rax, 8
    je tk_tw_w_unlink
    cmp rax, 9
    je tk_tw_w_close
    jmp tk_contract_fail
tk_tw_w_read_start:
    cmp qword ptr [r14 + 24], 0
    jne tk_contract_fail
    cmp qword ptr [r14 + 32], tk_tw_W_CHILD_REQUEST
    jne tk_contract_fail
    cmp qword ptr [r14 + 40], 29
    jb tk_contract_fail
    cmp qword ptr [r14 + 40], tk_tw_INPUT_CAP
    ja tk_contract_fail
    cmp qword ptr [r14 + 48], tk_tw_W_CHILD_REPLY
    jne tk_contract_fail
    cmp qword ptr [r14 + 56], 512
    jne tk_contract_fail
    cmp qword ptr [r15 + 192], -1
    jne tk_contract_fail
    jmp tk_tw_resume_owner
tk_tw_w_live:
    mov rcx, [r14 + 24]
    cmp rcx, 1
    ja tk_contract_fail
    mov rdi, [r15 + 128]
    test rcx, rcx
    jz tk_tw_w_live_check
    mov rdi, [r15 + 192]
tk_tw_w_live_check:
    test rdi, rdi
    js tk_contract_fail
    ret
tk_tw_w_stat:
    call tk_tw_w_live
    cmp qword ptr [r14 + 32], tk_tw_W_STAT
    jne tk_contract_fail
    cmp qword ptr [r14 + 40], 152
    jne tk_contract_fail
    cmp qword ptr [r14 + 48], 0
    jne tk_contract_fail
    lea rsi, [r13 + tk_tw_W_STAT]
    mov eax, 5
    syscall
    test rax, rax
    js tk_tw_w_error
    mov eax, 107
    syscall
    mov [r13 + tk_tw_W_STAT + 144], rax
    jmp tk_tw_w_acknowledge
tk_tw_w_names:
    cmp qword ptr [r15 + 24], 288
    jb tk_contract_fail
    mov rbx, [r15 + tk_tw_INPUT + 104]
    cmp rbx, 2048
    ja tk_contract_fail
    mov rsi, [r15 + tk_tw_INPUT + 96]
    cmp rsi, 256
    jne tk_contract_fail
    lea rsi, [r15 + tk_tw_INPUT + 288]
    lea rdi, [r13 + tk_tw_W_FILENAME]
    mov rcx, rbx
    # A zero-length comparison preserves flags; make equality explicit.
    cmp rcx, rcx
    repe cmpsb
    jne tk_contract_fail
    mov rax, 0x6e6f736a2e
    cmp [rdi], rax
    jne tk_contract_fail
    lea rax, [rbx + 5]
    cmp [r13 + 120], rax
    jne tk_contract_fail
    cmp byte ptr [r13 + tk_tw_W_TEMPORARY], 46
    jne tk_contract_fail
    lea rsi, [r15 + tk_tw_INPUT + 288]
    lea rdi, [r13 + tk_tw_W_TEMPORARY + 1]
    mov rcx, rbx
    # A zero-length comparison preserves flags; make equality explicit.
    cmp rcx, rcx
    repe cmpsb
    jne tk_contract_fail
    cmp byte ptr [rdi], 45
    jne tk_contract_fail
    inc rdi
    lea rsi, [r15 + tk_tw_INPUT + 288]
    mov rcx, rbx
    # A zero-length comparison preserves flags; make equality explicit.
    cmp rcx, rcx
    repe cmpsb
    jne tk_contract_fail
    cmp qword ptr [rdi], 0x706d742e
    jne tk_contract_fail
    lea rax, [rbx*2 + 6]
    cmp [r13 + 128], rax
    jne tk_contract_fail
    xor ecx, ecx
tk_tw_w_name_no_nul:
    cmp rcx, rbx
    je tk_tw_w_names_ok
    cmp byte ptr [r15 + tk_tw_INPUT + 288 + rcx], 0
    je tk_contract_fail
    inc rcx
    jmp tk_tw_w_name_no_nul
tk_tw_w_names_ok:
    ret
tk_tw_w_temporary_span:
    call tk_tw_w_names
    cmp qword ptr [r14 + 32], tk_tw_W_TEMPORARY
    jne tk_contract_fail
    mov rax, [r13 + 128]
    cmp rax, [r14 + 40]
    jne tk_contract_fail
    lea rsi, [r13 + tk_tw_W_TEMPORARY]
    ret
tk_tw_w_open:
    cmp qword ptr [r14 + 24], 1
    jne tk_contract_fail
    cmp qword ptr [r15 + 192], -1
    jne tk_contract_fail
    cmp qword ptr [r14 + 48], 1
    jne tk_contract_fail
    call tk_tw_w_temporary_span
    mov rdi, [r15 + 128]
    mov edx, 0xa00c1
    mov r10d, 0600
    mov eax, 257
    syscall
    test rax, rax
    js tk_tw_w_error
    cmp rax, 0x7fffffff
    ja tk_contract_fail
    mov [r15 + 192], rax
    mov qword ptr [r14 + 72], 1
    jmp tk_tw_w_acknowledge
tk_tw_w_write:
    call tk_tw_w_live
    cmp rcx, 1
    jne tk_contract_fail
    cmp qword ptr [r14 + 48], 0
    jne tk_contract_fail
    mov rdx, [r13 + 96]
    cmp rdx, 2048
    ja tk_contract_fail
    mov rax, [r13 + 104]
    cmp rax, rdx
    jae tk_contract_fail
    lea rsi, [rax + tk_tw_W_NEW_BYTES]
    cmp rsi, [r14 + 32]
    jne tk_contract_fail
    sub rdx, rax
    cmp rdx, [r14 + 40]
    jne tk_contract_fail
    add rsi, r13
    mov eax, 1
    syscall
    test rax, rax
    js tk_tw_w_error
    mov [r14 + 72], rax
    jmp tk_tw_w_acknowledge
tk_tw_w_sync:
    call tk_tw_zero_span
    call tk_tw_w_live
    mov eax, 74
    syscall
    test rax, rax
    js tk_tw_w_error
    jmp tk_tw_w_acknowledge
tk_tw_w_publication:
    cmp qword ptr [r14 + 24], 0
    jne tk_contract_fail
    cmp qword ptr [r15 + 192], -1
    jne tk_contract_fail
    cmp qword ptr [r14 + 48], tk_tw_W_FILENAME
    jne tk_contract_fail
    call tk_tw_w_temporary_span
    mov rdi, [r15 + 128]
    mov rdx, rdi
    lea r10, [r13 + tk_tw_W_FILENAME]
    ret
tk_tw_w_link:
    call tk_tw_w_publication
    xor r8d, r8d
    mov eax, 265
    syscall
    test rax, rax
    js tk_tw_w_error
    jmp tk_tw_w_acknowledge
tk_tw_w_rename:
    call tk_tw_w_publication
    mov eax, 264
    syscall
    test rax, rax
    js tk_tw_w_error
    jmp tk_tw_w_acknowledge
tk_tw_w_unlink:
    cmp qword ptr [r14 + 24], 0
    jne tk_contract_fail
    cmp qword ptr [r14 + 48], 0
    jne tk_contract_fail
    call tk_tw_w_temporary_span
    mov rdi, [r15 + 128]
    xor edx, edx
    mov eax, 263
    syscall
    test rax, rax
    js tk_tw_w_error
    jmp tk_tw_w_acknowledge
tk_tw_w_close:
    call tk_tw_zero_span
    call tk_tw_w_live
    cmp rcx, 1
    jne tk_contract_fail
    mov qword ptr [r15 + 192], -1
    mov eax, 3
    syscall
    test rax, rax
    js tk_tw_w_error
    jmp tk_tw_w_acknowledge
tk_tw_w_error:
    cmp rax, -4095
    jb tk_contract_fail
    neg rax
    mov [r14 + 80], rax
tk_tw_w_acknowledge:
    mov rax, [r13 + tk_tw_ACTION + 8]
    mov [r13 + tk_tw_ACTION + 64], rax
    jmp tk_tw_resume_write
tk_tw_write_result:
    jmp tk_tw_return

# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
# Callable transport/custody wrappers; every filesystem decision remains HIA.

tk_ticket_directory_create:
    sub rsp, 8
    mov edi, 6291456
    call tk_allocate_guarded
    add rsp, 8
    mov rdx, 0x3130434454415248
    mov [rax], rdx
    mov qword ptr [rax + 128], -1
    mov qword ptr [rax + 136], -1
    mov qword ptr [rax + 144], -1
    ret

# rdi=context, rsi=request, rdx=length, rcx=reply64
tk_ticket_directory_call:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp, 8
    mov r15, rdi
    mov rbx, rsi
    mov rbp, rdx
    mov rax, 0x3130434454415248
    cmp [r15], rax
    jne tk_contract_fail
    cmp qword ptr [r15 + 48], 0
    jne tk_contract_fail
    mov qword ptr [r15 + 48], 1
    mov [r15 + 40], rcx
    cmp rbp, 48
    jb tk_contract_fail
    cmp rbp, tk_td_INPUT_CAP
    ja tk_contract_fail
    mov [r15 + 24], rbp
    lea r12, [r15 + tk_td_IO_WORK]
    cmp qword ptr [r12 + 8], 0
    jne tk_contract_fail
    lea rdi, [r15 + tk_td_INPUT]
    mov esi, tk_td_INPUT_CAP
    mov edx, 3
    mov eax, 10
    syscall
    test rax, rax
    jnz tk_io_fail
    lea rdi, [r15 + tk_td_INPUT]
    mov rsi, rbx
    mov rcx, rbp
    rep movsb
    lea rdi, [r15 + tk_td_INPUT]
    mov esi, tk_td_INPUT_CAP
    mov edx, 1
    mov eax, 10
    syscall
    test rax, rax
    jnz tk_io_fail
    jmp tk_td_resume_io
tk_td_return:
    mov edx, eax
    cmp rax, rdx
    jne tk_contract_fail
    cmp qword ptr [r15 + 128], -1
    jne tk_contract_fail
    cmp qword ptr [r15 + 136], -1
    jne tk_contract_fail
    cmp qword ptr [r12 + 8], 0
    jne tk_contract_fail
    mov ebx, eax
    cmp eax, 64
    je tk_td_copy_result
    cmp eax, 0xffffffff
    je tk_td_return_done
    cmp eax, 0xfffffffe
    jne tk_contract_fail
    jmp tk_td_return_done
tk_td_copy_result:
    mov rdi, [r15 + 40]
    lea rsi, [r15 + tk_td_OUTPUT]
    mov ecx, 8
    rep movsq
tk_td_return_done:
    mov qword ptr [r15 + 40], 0
    mov qword ptr [r15 + 48], 0
    mov eax, ebx
    add rsp, 8
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

# Borrow requires the exact, live Directory lease and a completed owner phase.
# rdi=context, rsi=lease -> rax=held descriptor
tk_ticket_directory_borrow:
    test rdi, rdi
    jz tk_contract_fail
    mov rax, 0x3130434454415248
    cmp [rdi], rax
    jne tk_contract_fail
    cmp qword ptr [rdi + 48], 0
    jne tk_contract_fail
    lea rdx, [rdi + tk_td_IO_WORK]
    mov rax, 0x3130305744415248
    cmp [rdx], rax
    jne tk_contract_fail
    cmp qword ptr [rdx + 8], 0
    jne tk_contract_fail
    cmp qword ptr [rdx + 64], 4
    jne tk_contract_fail
    test rsi, rsi
    jz tk_contract_fail
    cmp [rdx + 72], rsi
    jne tk_contract_fail
    cmp qword ptr [rdi + 128], -1
    jne tk_contract_fail
    cmp qword ptr [rdi + 136], -1
    jne tk_contract_fail
    mov rax, [rdi + 144]
    test rax, rax
    js tk_contract_fail
    ret

tk_ticket_directory_drop:
    test rdi, rdi
    jz tk_td_drop_done
    mov rax, 0x3130434454415248
    cmp [rdi], rax
    jne tk_contract_fail
    mov rax, [rdi + 48]
    or rax, [rdi + tk_td_IO_WORK + 8]
    or rax, [rdi + tk_td_IO_WORK + 64]
    or rax, [rdi + tk_td_IO_WORK + 72]
    jnz tk_contract_fail
    cmp qword ptr [rdi + 128], -1
    jne tk_contract_fail
    cmp qword ptr [rdi + 136], -1
    jne tk_contract_fail
    cmp qword ptr [rdi + 144], -1
    jne tk_contract_fail
    mov esi, tk_td_MAP_SIZE
    mov eax, 11
    syscall
    test rax, rax
    jnz tk_io_fail
tk_td_drop_done:
    ret

tk_ticket_raw_write_create:
    sub rsp, 8
    mov edi, 11534336
    call tk_allocate_guarded
    add rsp, 8
    mov rdx, 0x3130435754415248
    mov [rax], rdx
    xor ecx, ecx
tk_tw_initialize_fd:
    mov qword ptr [rax + rcx*8 + 128], -1
    inc ecx
    cmp ecx, 7
    jne tk_tw_initialize_fd
    mov qword ptr [rax + 192], -1
    ret

# rdi=context, rsi=request, rdx=length, rcx=reply32, r8=borrowed hot FD
tk_ticket_raw_write_call:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp, 8
    mov r15, rdi
    mov rbx, rsi
    mov rbp, rdx
    mov rax, 0x3130435754415248
    cmp [r15], rax
    jne tk_contract_fail
    cmp qword ptr [r15 + 48], 0
    jne tk_contract_fail
    mov qword ptr [r15 + 48], 1
    mov [r15 + 40], rcx
    cmp rbp, 288
    jb tk_contract_fail
    cmp rbp, 544
    ja tk_contract_fail
    cmp qword ptr [r15 + 128], -1
    jne tk_contract_fail
    test r8, r8
    js tk_contract_fail
    mov [r15 + 128], r8
    mov [r15 + 24], rbp
    lea r12, [r15 + tk_tw_OWNER]
    lea r13, [r15 + tk_tw_WRITE_OWNER]
    mov rax, [r12 + 8]
    or rax, [r13 + 8]
    jnz tk_contract_fail
    lea rdi, [r15 + tk_tw_INPUT]
    mov esi, tk_tw_INPUT_CAP
    mov edx, 3
    mov eax, 10
    syscall
    test rax, rax
    jnz tk_io_fail
    lea rdi, [r15 + tk_tw_INPUT]
    mov rsi, rbx
    mov rcx, rbp
    rep movsb
    lea rdi, [r15 + tk_tw_INPUT]
    mov esi, tk_tw_INPUT_CAP
    mov edx, 1
    mov eax, 10
    syscall
    test rax, rax
    jnz tk_io_fail
    jmp tk_tw_resume_write
tk_tw_return:
    mov edx, eax
    cmp rax, rdx
    jne tk_contract_fail
    mov ebx, eax
    cmp qword ptr [r15 + 192], -1
    jne tk_contract_fail
    mov rax, [r12 + 8]
    or rax, [r13 + 8]
    jnz tk_contract_fail
    mov ecx, 1
tk_tw_return_fd:
    cmp qword ptr [r15 + rcx*8 + 128], -1
    jne tk_contract_fail
    inc ecx
    cmp ecx, 7
    jne tk_tw_return_fd
    mov qword ptr [r15 + 128], -1
    cmp ebx, 32
    je tk_tw_copy_result
    cmp ebx, 0xffffffff
    je tk_tw_return_done
    cmp ebx, 0xfffffffe
    jne tk_contract_fail
    jmp tk_tw_return_done
tk_tw_copy_result:
    mov rdi, [r15 + 40]
    lea rsi, [r15 + tk_tw_OUTPUT]
    mov ecx, 4
    rep movsq
tk_tw_return_done:
    mov qword ptr [r15 + 40], 0
    mov qword ptr [r15 + 48], 0
    mov eax, ebx
    add rsp, 8
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

tk_ticket_raw_write_drop:
    test rdi, rdi
    jz tk_tw_drop_done
    mov rax, 0x3130435754415248
    cmp [rdi], rax
    jne tk_contract_fail
    mov rax, [rdi + 48]
    or rax, [rdi + tk_tw_OWNER + 8]
    or rax, [rdi + tk_tw_WRITE_OWNER + 8]
    jnz tk_contract_fail
    xor ecx, ecx
tk_tw_drop_fd:
    cmp qword ptr [rdi + rcx*8 + 128], -1
    jne tk_contract_fail
    inc ecx
    cmp ecx, 7
    jne tk_tw_drop_fd
    cmp qword ptr [rdi + 192], -1
    jne tk_contract_fail
    mov esi, tk_tw_MAP_SIZE
    mov eax, 11
    syscall
    test rax, rax
    jnz tk_io_fail
tk_tw_drop_done:
    ret

.intel_syntax noprefix
.section .text
.intel_syntax noprefix
.section .text
.equ tk_tb_G_WORK, 48
.equ tk_tb_G_WORK_BYTES, 56
.equ tk_tb_G_INSTANCES, 64
.equ tk_tb_G_GENERATION, 72
.equ tk_tb_G_ROOT_COUNT, 80
.equ tk_tb_G_NAMESPACE, 88
.equ tk_tb_G_ENTROPY, 96
.equ tk_tb_G_ROOT_FDS, 128
.equ tk_tb_G_INPUT, 4096
.equ tk_tb_G_INPUT_BYTES, 8388608
.equ tk_tb_G_OUTPUT, 8392704
.equ tk_tb_G_BYTES, 8404992
.equ tk_tb_G_INITIAL_WORK, 16846848
.equ tk_tb_G_NAMESPACE_BYTES, 9441280
.equ tk_tb_G_ENTROPY_BYTES, 24576
.equ tk_tb_I_GLOBAL, 3968
.equ tk_tb_I_TOKEN, 3976
.equ tk_tb_I_NEXT, 3984
.equ tk_tb_I_PREVIOUS, 3992

.equ tk_tb_G_SAVE, 104
.equ tk_tb_G_WRITE, 120
.equ tk_tb_S_INPUT, 4096
.equ tk_tb_S_INPUT_CAP, 8388608
.equ tk_tb_S_OUTPUT, 8392704
.equ tk_tb_S_OWNER, 8400896
.equ tk_tb_S_BYTES, 8470528
.equ tk_tb_RW_BYTES, 11538432

tk_tb_save_allocate:
    xor edi, edi
    mov esi, tk_tb_S_BYTES
    mov edx, 3
    mov r10d, 34
    mov r8, -1
    xor r9d, r9d
    mov eax, 9
    syscall
    cmp rax, -4095
    jae tk_tb_global_io_fail
    mov [r15 + tk_tb_G_SAVE], rax
    mov [rax + 4000], r15
    lea rdi, [rax + tk_tb_S_BYTES - 4096]
    mov esi, 4096
    xor edx, edx
    mov eax, 10
    syscall
    test rax, rax
    jnz tk_tb_global_io_fail
    xor edi, edi
    mov esi, tk_tb_RW_BYTES
    mov edx, 3
    mov r10d, 34
    mov r8, -1
    xor r9d, r9d
    mov eax, 9
    syscall
    cmp rax, -4095
    jae tk_tb_global_io_fail
    mov [r15 + tk_tb_G_WRITE], rax
    mov [rax + 4000], r15
    lea rdi, [rax + 128]
    mov ecx, 7
    mov rax, -1
    rep stosq
    mov rax, [r15 + tk_tb_G_WRITE]
    mov qword ptr [rax + 192], -1
    lea rdi, [rax + tk_tb_RW_BYTES - 4096]
    mov esi, 4096
    xor edx, edx
    mov eax, 10
    syscall
    test rax, rax
    jnz tk_tb_global_io_fail
    ret

tk_tb_save_entry:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    mov r15, [r15 + tk_tb_G_SAVE]
    lea r12, [r15 + tk_tb_S_OWNER]
tk_tb_save_resume:
    lea rdi, [r15 + tk_tb_S_INPUT]
    mov rsi, [r15 + 24]
    lea rdx, [r15 + tk_tb_S_OUTPUT]
    mov ecx, 8192
    mov r8, r12
    mov r9d, 65536
    call qword ptr [rip + tk_ticket_backend_save_image]
    mov ecx, eax
    cmp rax, rcx
    jne tk_tb_global_contract_fail
    cmp eax, 0xfffffff0
    jne tk_tb_save_return
    lea r14, [r12 + 256]
    mov rax, 0x3130415653415248
    cmp [r14], rax
    jne tk_tb_global_contract_fail
    mov rax, [r15 + 16]
    inc rax
    jz tk_tb_global_contract_fail
    cmp [r14 + 8], rax
    jne tk_tb_global_contract_fail
    cmp [r12 + 16], rax
    jne tk_tb_global_contract_fail
    mov [r15 + 16], rax
    mov rax, [r14 + 64]
    or rax, [r14 + 72]
    or rax, [r14 + 80]
    or rax, [r14 + 88]
    jnz tk_tb_global_contract_fail
    cmp qword ptr [r14 + 32], 8192
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 48], 16384
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 56], 8192
    jne tk_tb_global_contract_fail
    mov rsi, [r14 + 40]
    cmp rsi, 64
    jb tk_tb_global_contract_fail
    cmp rsi, 4096
    ja tk_tb_global_contract_fail
    lea rdi, [r12 + 8192]
    lea rdx, [r12 + 16384]
    cmp qword ptr [r14 + 16], 100
    je tk_tb_save_archive_effect
    cmp qword ptr [r14 + 16], 101
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 24], 0
    je tk_tb_global_contract_fail
    call tk_tb_raw_record_write_entry
    jmp tk_tb_save_child_return
tk_tb_save_archive_effect:
    cmp qword ptr [r14 + 24], 0
    jne tk_tb_global_contract_fail
    mov ecx, 1
    call tk_tb_registry_entry
tk_tb_save_child_return:
    mov ecx, eax
    cmp rax, rcx
    jne tk_tb_global_contract_fail
    mov [r14 + 72], rax
    mov rax, [r14 + 8]
    mov [r14 + 64], rax
    jmp tk_tb_save_resume
tk_tb_save_return:
    cmp eax, 0xffffffff
    je tk_tb_save_restore
    cmp eax, 0xfffffffe
    je tk_tb_save_restore
    cmp eax, 64
    jb tk_tb_global_contract_fail
    cmp eax, 8192
    ja tk_tb_global_contract_fail
    cmp qword ptr [r12 + 8], 0
    jne tk_tb_global_contract_fail
tk_tb_save_restore:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

tk_tb_cleanup_save_descriptors:
    mov rax, [r15 + tk_tb_G_WRITE]
    test rax, rax
    jz tk_tb_cleanup_save_done
    mov qword ptr [rax + 128], -1
    lea rbx, [rax + 136]
    mov r13d, 6
    call tk_tb_cleanup_table
    mov rax, [r15 + tk_tb_G_WRITE]
    lea rbx, [rax + 192]
    mov r13d, 1
    call tk_tb_cleanup_table
tk_tb_cleanup_save_done:
    ret

tk_tb_registry_entry:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp, 32
    mov [rsp], rdi
    mov [rsp + 8], rdx
    mov [rsp + 16], rsi
    mov [rsp + 24], rcx
    mov r15, [r15 + 4000]
    mov r15, [r15 + tk_tb_I_GLOBAL]
    cmp rsi, tk_tb_G_INPUT_BYTES
    ja tk_tb_registry_entry_invalid
    cmp rcx, 1
    jne tk_tb_registry_entry_copy
    cmp rsi, 64
    jb tk_tb_registry_entry_invalid
    mov rax, 0x313030514f415248
    cmp [rdi], rax
    jne tk_tb_registry_entry_invalid
    cmp qword ptr [rdi + 48], 0
    jne tk_tb_registry_entry_invalid
tk_tb_registry_entry_copy:
    lea rdi, [r15 + tk_tb_G_INPUT]
    mov esi, tk_tb_G_INPUT_BYTES
    mov edx, 3
    mov eax, 10
    syscall
    test rax, rax
    jnz tk_tb_global_io_fail
    lea rdi, [r15 + tk_tb_G_INPUT]
    mov rsi, [rsp]
    mov rcx, [rsp + 16]
    mov [r15 + 16], rcx
    rep movsb
    cmp qword ptr [rsp + 24], 1
    jne tk_tb_registry_entry_event
    mov rax, 0x3130305751415248
    mov [r15 + tk_tb_G_INPUT], rax
    cmp qword ptr [r15 + tk_tb_G_INPUT + 8], 1
    jne tk_tb_registry_entry_event
    mov qword ptr [r15 + tk_tb_G_INPUT + 48], 1
tk_tb_registry_entry_event:
    mov r12, [r15 + tk_tb_G_WORK]
    mov qword ptr [r12 + 352], 1
    cmp qword ptr [rsp + 24], 2
    jne tk_tb_registry_entry_protect
    mov qword ptr [r12 + 352], 2
tk_tb_registry_entry_protect:
    lea rdi, [r15 + tk_tb_G_INPUT]
    mov esi, tk_tb_G_INPUT_BYTES
    mov edx, 1
    mov eax, 10
    syscall
    test rax, rax
    jnz tk_tb_global_io_fail
tk_tb_registry_resume:
    mov r12, [r15 + tk_tb_G_WORK]
    lea rdi, [r15 + tk_tb_G_INPUT]
    mov rsi, [r15 + 16]
    lea rdx, [r15 + tk_tb_G_OUTPUT]
    mov ecx, 8192
    mov r8, r12
    mov r9, [r15 + tk_tb_G_WORK_BYTES]
    call qword ptr [rip + tk_ticket_backend_registry_image]
    mov ecx, eax
    cmp rax, rcx
    jne tk_tb_global_contract_fail
    cmp eax, 0xfffffff0
    jne tk_tb_registry_result
    lea r14, [r12 + 256]
    mov rax, 0x3130584651415248
    cmp [r14], rax
    jne tk_tb_global_contract_fail
    mov rax, [r15 + 8]
    inc rax
    jz tk_tb_global_contract_fail
    cmp [r14 + 8], rax
    jne tk_tb_global_contract_fail
    cmp [r12 + 16], rax
    jne tk_tb_global_contract_fail
    mov [r15 + 8], rax
    mov rax, [r14 + 64]
    or rax, [r14 + 72]
    or rax, [r14 + 80]
    or rax, [r14 + 88]
    jnz tk_tb_global_contract_fail
    mov rax, [r14 + 16]
    cmp rax, 1
    je tk_tb_registry_create
    cmp rax, 2
    je tk_tb_registry_invoke
    cmp rax, 3
    je tk_tb_registry_destroy
    cmp rax, 4
    je tk_tb_registry_grow
    jmp tk_tb_global_contract_fail
tk_tb_registry_ack:
    mov rax, [r14 + 8]
    mov [r14 + 64], rax
    jmp tk_tb_registry_resume
tk_tb_registry_result:
    mov ebx, eax
    cmp eax, 0xffffffff
    je tk_tb_registry_entry_restore
    cmp eax, 0xfffffffe
    je tk_tb_registry_entry_restore
    cmp eax, 64
    jb tk_tb_global_contract_fail
    cmp eax, 8192
    ja tk_tb_global_contract_fail
    cmp qword ptr [r12 + 8], 0
    jne tk_tb_global_contract_fail
    mov rax, 0x3130525751415248
    cmp [r15 + tk_tb_G_OUTPUT], rax
    jne tk_tb_global_contract_fail
    mov rdi, [rsp + 8]
    lea rsi, [r15 + tk_tb_G_OUTPUT]
    mov ecx, ebx
    rep movsb
    cmp qword ptr [rsp + 24], 1
    jne tk_tb_registry_entry_restore
    mov rdi, [rsp + 8]
    mov rax, 0x313030524f415248
    mov [rdi], rax
    jmp tk_tb_registry_entry_restore
tk_tb_registry_entry_invalid:
    mov ebx, 0xffffffff
tk_tb_registry_entry_restore:
    mov eax, ebx
    add rsp, 32
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret
.equ tk_tb_R_INPUT, 4096
.equ tk_tb_R_INPUT_CAP, 8388608
.equ tk_tb_R_OUTPUT, 8392704
.equ tk_tb_R_OWNER, 8400896
.equ tk_tb_R_WORK, 33554432
.equ tk_tb_L_BASE, 44040192
.equ tk_tb_N_BASE, 49283072
.equ tk_tb_M_BASE, 67108864
.equ tk_tb_W_BASE, 75497472
.equ tk_tb_A_BASE, 104857600
.equ tk_tb_E_BASE, 117440512
.equ tk_tb_V_BASE, 119537664
.equ tk_tb_MAP_BYTES, 134217728
.equ tk_tb_ROOT_FDS, 128
tk_tb_registry_zero_spans:
    mov rax, [r14 + 32]
    or rax, [r14 + 40]
    or rax, [r14 + 48]
    or rax, [r14 + 56]
    jnz tk_tb_global_contract_fail
    ret
tk_tb_registry_root_capability:
    test rcx, rcx
    jz tk_tb_global_contract_fail
    cmp rcx, [r15 + tk_tb_G_ROOT_COUNT]
    ja tk_tb_global_contract_fail
    mov r9, [r15 + tk_tb_G_ROOT_FDS - 8 + rcx*8]
    test r9, r9
    js tk_tb_global_contract_fail
    ret
tk_tb_registry_find_instance:
    mov r8, [r15 + tk_tb_G_INSTANCES]
tk_tb_registry_find_next:
    test r8, r8
    jz tk_tb_global_contract_fail
    cmp [r8 + tk_tb_I_GLOBAL], r15
    jne tk_tb_global_contract_fail
    cmp [r8 + tk_tb_I_TOKEN], rcx
    je tk_tb_registry_found_instance
    mov r8, [r8 + tk_tb_I_NEXT]
    jmp tk_tb_registry_find_next
tk_tb_registry_found_instance:
    ret
tk_tb_registry_create:
    call tk_tb_registry_zero_spans
    mov rcx, [r14 + 24]
    call tk_tb_registry_root_capability
    mov rbx, r9
    mov rbp, [r15 + tk_tb_G_GENERATION]
    inc rbp
    jz tk_tb_global_contract_fail
    xor edi, edi
    mov esi, tk_tb_MAP_BYTES
    mov edx, 3
    mov r10d, 34
    mov r8, -1
    xor r9d, r9d
    mov eax, 9
    syscall
    cmp rax, -4095
    jae tk_tb_global_io_fail
    mov r13, rax
    mov [r13 + tk_tb_I_GLOBAL], r15
    mov [r13 + tk_tb_I_TOKEN], rbp
    mov [r13 + 4000], r13
    mov [r13 + tk_tb_L_BASE + 4000], r13
    mov [r13 + tk_tb_L_BASE + 2097152 + 4000], r13
    mov [r13 + tk_tb_M_BASE + 4000], r13
    mov [r13 + tk_tb_W_BASE + 4000], r13
    mov [r13 + tk_tb_W_BASE + 18874368 + 4000], r13
    mov [r13 + tk_tb_A_BASE + 4000], r13
    mov [r13 + tk_tb_V_BASE + 4000], r13
    mov rax, -1
    lea rdi, [r13 + tk_tb_ROOT_FDS]
    mov ecx, 267
    rep stosq
    lea rdi, [r13 + tk_tb_L_BASE + 128]
    mov ecx, 5
    rep stosq
    lea rdi, [r13 + tk_tb_L_BASE + 2097152 + 128]
    mov ecx, 2
    rep stosq
    lea rdi, [r13 + tk_tb_M_BASE + 128]
    mov ecx, 6
    rep stosq
    lea rdi, [r13 + tk_tb_W_BASE + 128]
    mov ecx, 5
    rep stosq
    lea rdi, [r13 + tk_tb_W_BASE + 18874368 + 128]
    mov ecx, 6
    rep stosq
    lea rdi, [r13 + tk_tb_A_BASE + 128]
    mov ecx, 7
    rep stosq
    mov qword ptr [r13 + tk_tb_ROOT_FDS], -1
    lea rdi, [r13 + tk_tb_MAP_BYTES - 4096]
    mov esi, 4096
    xor edx, edx
    mov eax, 10
    syscall
    test rax, rax
    jnz tk_tb_global_io_fail
    mov rax, [r15 + tk_tb_G_INSTANCES]
    mov [r13 + tk_tb_I_NEXT], rax
    test rax, rax
    jz tk_tb_registry_install_head
    mov [rax + tk_tb_I_PREVIOUS], r13
tk_tb_registry_install_head:
    mov [r15 + tk_tb_G_INSTANCES], r13
    mov [r15 + tk_tb_G_GENERATION], rbp
    mov [r14 + 72], rbp
    jmp tk_tb_registry_ack
tk_tb_registry_invoke:
    cmp qword ptr [r14 + 32], 8404992
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 56], 8192
    jne tk_tb_global_contract_fail
    mov rsi, [r14 + 40]
    cmp rsi, 64
    jb tk_tb_global_contract_fail
    cmp rsi, 8388608
    ja tk_tb_global_contract_fail
    mov rcx, [r14 + 24]
    call tk_tb_registry_find_instance
    cmp qword ptr [r14 + 48], 1
    jne tk_tb_global_contract_fail
    mov r9, [r8 + tk_tb_ROOT_FDS + 8]
    test r9, r9
    jns tk_tb_registry_invocation_root_ready
    mov ecx, 1
    call tk_tb_registry_root_capability
tk_tb_registry_invocation_root_ready:
    lea rdi, [r12 + 8404992]
    lea rdx, [r12 + 16793600]
    call tk_tb_registry_inner_entry
    mov ecx, eax
    cmp rax, rcx
    jne tk_tb_global_contract_fail
    mov [r14 + 72], rax
    jmp tk_tb_registry_ack
tk_tb_registry_destroy:
    call tk_tb_registry_zero_spans
    mov rcx, [r14 + 24]
    call tk_tb_registry_find_instance
    mov rax, [r8 + tk_tb_R_OWNER + 8]
    or rax, [r8 + tk_tb_R_OWNER + 80]
    or rax, [r8 + tk_tb_R_OWNER + 88]
    or rax, [r8 + tk_tb_R_OWNER + 96]
    or rax, [r8 + tk_tb_R_OWNER + 104]
    or rax, [r8 + tk_tb_R_OWNER + 112]
    or rax, [r8 + tk_tb_R_OWNER + 128]
    or rax, [r8 + tk_tb_R_OWNER + 136]
    or rax, [r8 + tk_tb_R_OWNER + 144]
    or rax, [r8 + tk_tb_R_OWNER + 440]
    jnz tk_tb_global_contract_fail
    lea rdi, [r8 + tk_tb_ROOT_FDS + 8]
    mov ecx, 266
    call tk_tb_registry_assert_closed
    lea rdi, [r8 + tk_tb_L_BASE + 128]
    mov ecx, 5
    call tk_tb_registry_assert_closed
    lea rdi, [r8 + tk_tb_L_BASE + 2097152 + 128]
    mov ecx, 2
    call tk_tb_registry_assert_closed
    lea rdi, [r8 + tk_tb_M_BASE + 128]
    mov ecx, 6
    call tk_tb_registry_assert_closed
    lea rdi, [r8 + tk_tb_W_BASE + 128]
    mov ecx, 5
    call tk_tb_registry_assert_closed
    lea rdi, [r8 + tk_tb_W_BASE + 18874368 + 128]
    mov ecx, 6
    call tk_tb_registry_assert_closed
    lea rdi, [r8 + tk_tb_A_BASE + 128]
    mov ecx, 7
    call tk_tb_registry_assert_closed
    mov qword ptr [r8 + tk_tb_ROOT_FDS], -1
    mov rax, [r8 + tk_tb_I_PREVIOUS]
    mov rdx, [r8 + tk_tb_I_NEXT]
    test rax, rax
    jz tk_tb_registry_remove_head
    cmp [rax + tk_tb_I_NEXT], r8
    jne tk_tb_global_contract_fail
    mov [rax + tk_tb_I_NEXT], rdx
    jmp tk_tb_registry_remove_following
tk_tb_registry_remove_head:
    cmp [r15 + tk_tb_G_INSTANCES], r8
    jne tk_tb_global_contract_fail
    mov [r15 + tk_tb_G_INSTANCES], rdx
tk_tb_registry_remove_following:
    test rdx, rdx
    jz tk_tb_registry_unmap_instance
    cmp [rdx + tk_tb_I_PREVIOUS], r8
    jne tk_tb_global_contract_fail
    mov [rdx + tk_tb_I_PREVIOUS], rax
tk_tb_registry_unmap_instance:
    mov rdi, r8
    mov esi, tk_tb_MAP_BYTES
    mov eax, 11
    syscall
    test rax, rax
    jnz tk_tb_global_io_fail
    jmp tk_tb_registry_ack
tk_tb_registry_assert_closed:
    cmp qword ptr [rdi], -1
    jne tk_tb_global_contract_fail
    add rdi, 8
    dec ecx
    jnz tk_tb_registry_assert_closed
    ret
tk_tb_registry_grow:
    mov rax, [r14 + 24]
    or rax, [r14 + 32]
    or rax, [r14 + 48]
    or rax, [r14 + 56]
    jnz tk_tb_global_contract_fail
    mov rbp, [r15 + tk_tb_G_WORK_BYTES]
    mov r13, rbp
    shl r13, 1
    jc tk_tb_global_contract_fail
    cmp r13, [r14 + 40]
    jne tk_tb_global_contract_fail
    mov rax, 0x7fffffffffffefff
    cmp r13, rax
    ja tk_tb_global_contract_fail
    mov rbx, [r15 + tk_tb_G_WORK]
    xor edi, edi
    lea rsi, [r13 + 4096]
    mov edx, 3
    mov r10d, 34
    mov r8, -1
    xor r9d, r9d
    mov eax, 9
    syscall
    cmp rax, -4095
    jae tk_tb_global_io_fail
    mov [r15 + 112], rax
    lea rdi, [rax + r13]
    mov esi, 4096
    xor edx, edx
    mov eax, 10
    syscall
    test rax, rax
    jnz tk_tb_global_io_fail
    mov rdi, [r15 + 112]
    mov rsi, rbx
    mov rcx, rbp
    rep movsb
    mov r12, [r15 + 112]
    mov [r15 + tk_tb_G_WORK], r12
    mov [r15 + tk_tb_G_WORK_BYTES], r13
    mov qword ptr [r15 + 112], 0
    lea r14, [r12 + 256]
    mov rdi, rbx
    lea rsi, [rbp + 4096]
    mov eax, 11
    syscall
    test rax, rax
    jnz tk_tb_global_io_fail
    mov [r14 + 72], r13
    jmp tk_tb_registry_ack

tk_tb_registry_inner_entry:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp, 24
    mov [rsp], rdi
    mov [rsp + 8], rdx
    mov [rsp + 16], rsi
    mov r15, r8
    cmp qword ptr [r15 + tk_tb_ROOT_FDS], -1
    jne tk_tb_global_contract_fail
    mov [r15 + tk_tb_ROOT_FDS], r9
    mov r13, r15
    lea r12, [r15 + tk_tb_R_OWNER]
    lea rdi, [r15 + tk_tb_R_INPUT]
    mov esi, tk_tb_R_INPUT_CAP
    mov edx, 3
    mov eax, 10
    syscall
    test rax, rax
    jnz tk_tb_global_io_fail
    lea rdi, [r15 + tk_tb_R_INPUT]
    mov rsi, [rsp]
    mov rcx, [rsp + 16]
    mov [r15 + 24], rcx
    rep movsb
    lea rdi, [r15 + tk_tb_R_INPUT]
    mov esi, tk_tb_R_INPUT_CAP
    mov edx, 1
    mov eax, 10
    syscall
    test rax, rax
    jnz tk_tb_global_io_fail
tk_tb_resume_archive:
    lea rdi, [r15 + tk_tb_R_INPUT]
    mov rsi, [r15 + 24]
    lea rdx, [r15 + tk_tb_R_OUTPUT]
    mov ecx, 8192
    mov r8, r12
    mov r9d, tk_tb_R_WORK
    call qword ptr [rip + tk_ticket_backend_archive_image]
    mov ecx, eax
    cmp rax, rcx
    jne tk_tb_global_contract_fail
    cmp eax, 0xfffffff0
    jne tk_tb_archive_result
    lea r14, [r12 + 256]
    mov rax, 0x313030414f415248
    cmp [r14], rax
    jne tk_tb_global_contract_fail
    mov rax, [r15 + 16]
    inc rax
    jz tk_tb_global_contract_fail
    cmp [r14 + 8], rax
    jne tk_tb_global_contract_fail
    cmp [r12 + 16], rax
    jne tk_tb_global_contract_fail
    mov [r15 + 16], rax
    mov rax, [r14 + 64]
    or rax, [r14 + 72]
    or rax, [r14 + 80]
    or rax, [r14 + 88]
    jnz tk_tb_global_contract_fail
    mov rax, [r14 + 16]
    cmp rax, 100
    jae tk_tb_root_child
    cmp qword ptr [r14 + 56], 0
    jne tk_tb_global_contract_fail
    cmp rax, 1
    je tk_tb_root_open
    cmp rax, 2
    je tk_tb_root_stat
    cmp rax, 3
    je tk_tb_root_mkdir
    cmp rax, 5
    je tk_tb_root_uid
    cmp rax, 6
    je tk_tb_root_duplicate
    cmp rax, 7
    je tk_tb_root_named
    cmp rax, 8
    je tk_tb_root_statx
    cmp rax, 9
    je tk_tb_root_statx_probe
    cmp rax, 10
    je tk_tb_root_statat
    cmp rax, 11
    je tk_tb_root_statat_probe
    cmp rax, 12
    je tk_tb_root_close
    cmp rax, 13
    je tk_tb_root_sync
    cmp rax, 14
    je tk_tb_root_unlink
    cmp rax, 15
    je tk_tb_root_scan_open
    cmp rax, 16
    je tk_tb_root_flags
    cmp rax, 17
    je tk_tb_root_directory
    jmp tk_tb_global_contract_fail
tk_tb_root_live:
    mov rcx, [r14 + 24]
    cmp rcx, 266
    ja tk_tb_global_contract_fail
    mov rdi, [r15 + tk_tb_ROOT_FDS + rcx*8]
    test rdi, rdi
    js tk_tb_global_contract_fail
    ret
tk_tb_root_empty:
    mov rcx, [r14 + 24]
    cmp rcx, 1
    jb tk_tb_global_contract_fail
    cmp rcx, 266
    ja tk_tb_global_contract_fail
    cmp qword ptr [r15 + tk_tb_ROOT_FDS + rcx*8], -1
    jne tk_tb_global_contract_fail
    mov rbx, rcx
    ret
tk_tb_root_parent:
    mov rcx, [r14 + 48]
    cmp rcx, 266
    ja tk_tb_global_contract_fail
    mov rdi, [r15 + tk_tb_ROOT_FDS + rcx*8]
    test rdi, rdi
    js tk_tb_global_contract_fail
    ret
tk_tb_root_zero_span:
    mov rax, [r14 + 32]
    or rax, [r14 + 40]
    or rax, [r14 + 48]
    jnz tk_tb_global_contract_fail
    ret
tk_tb_root_name:
    mov rax, [r14 + 32]
    mov rdx, [r14 + 40]
    cmp rax, 12416
    je tk_tb_root_pair_name
    cmp rax, 12288
    je tk_tb_root_record_name
    cmp rax, 81920
    je tk_tb_root_walk_name
    cmp rax, 12432
    je tk_tb_root_layout_name
    cmp rax, 12512
    je tk_tb_root_anchor_name
    cmp rax, 12608
    je tk_tb_root_intent_name
    cmp rax, 12720
    je tk_tb_root_legacy_name
    jmp tk_tb_global_contract_fail
tk_tb_root_layout_name:
    lea rsi, [rip + tk_tb_literal_layout]
    mov ecx, 19
    jmp tk_tb_root_compare_name
tk_tb_root_anchor_name:
    lea rsi, [rip + tk_tb_literal_anchor]
    mov ecx, 32
    jmp tk_tb_root_compare_name
tk_tb_root_intent_name:
    lea rsi, [rip + tk_tb_literal_intent]
    mov ecx, 30
    jmp tk_tb_root_compare_name
tk_tb_root_legacy_name:
    lea rsi, [rip + tk_tb_literal_legacy]
    mov ecx, 19
tk_tb_root_compare_name:
    cmp rdx, rcx
    jne tk_tb_global_contract_fail
    lea rbp, [r12 + rax]
    inc ecx
tk_tb_root_compare_byte:
    mov al, [rsi]
    cmp [rbp], al
    jne tk_tb_global_contract_fail
    inc rsi
    inc rbp
    dec ecx
    jnz tk_tb_root_compare_byte
    mov rsi, [r14 + 32]
    add rsi, r12
    ret
tk_tb_root_pair_name:
    cmp rdx, 2
    jne tk_tb_global_contract_fail
    mov ecx, 2
    jmp tk_tb_root_hex_name
tk_tb_root_walk_name:
    cmp qword ptr [r14 + 16], 7
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 24], 2
    jne tk_tb_global_contract_fail
    cmp qword ptr [r12 + 48], 13
    je tk_tb_root_record_name
    cmp qword ptr [r12 + 48], 14
    jne tk_tb_global_contract_fail
tk_tb_root_record_name:
    cmp rdx, 69
    jne tk_tb_global_contract_fail
    mov ecx, 64
tk_tb_root_hex_name:
    lea rsi, [r12 + rax]
    xor edx, edx
tk_tb_root_hex_byte:
    movzx eax, byte ptr [rsi + rdx]
    cmp eax, 48
    jb tk_tb_global_contract_fail
    cmp eax, 57
    jbe tk_tb_root_hex_ok
    cmp eax, 97
    jb tk_tb_global_contract_fail
    cmp eax, 102
    ja tk_tb_global_contract_fail
tk_tb_root_hex_ok:
    inc edx
    cmp edx, ecx
    jb tk_tb_root_hex_byte
    cmp ecx, 2
    je tk_tb_root_hex_end
    cmp dword ptr [rsi + 64], 0x6f736a2e
    jne tk_tb_global_contract_fail
    cmp word ptr [rsi + 68], 0x006e
    jne tk_tb_global_contract_fail
    ret
tk_tb_root_hex_end:
    cmp byte ptr [rsi + 2], 0
    jne tk_tb_global_contract_fail
    ret
tk_tb_root_open:
    call tk_tb_root_empty
    call tk_tb_root_name
    cmp rbx, 260
    je tk_tb_root_open_anchor
    cmp rbx, 3
    je tk_tb_root_open_layout
    cmp rbx, 261
    je tk_tb_root_open_layout
    cmp rbx, 4
    jb tk_tb_global_contract_fail
    cmp rbx, 262
    ja tk_tb_global_contract_fail
    cmp qword ptr [r14 + 32], 12416
    jne tk_tb_global_contract_fail
    cmp rbx, 262
    je tk_tb_root_open_transient
    cmp rbx, 259
    ja tk_tb_global_contract_fail
    cmp qword ptr [r14 + 48], 3
    jne tk_tb_global_contract_fail
    jmp tk_tb_root_open_directory
tk_tb_root_open_transient:
    cmp qword ptr [r14 + 48], 261
    jne tk_tb_global_contract_fail
    jmp tk_tb_root_open_directory
tk_tb_root_open_layout:
    cmp qword ptr [r14 + 32], 12432
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 48], 1
    jne tk_tb_global_contract_fail
tk_tb_root_open_directory:
    mov edx, 0xb0000
    jmp tk_tb_root_issue_open
tk_tb_root_open_anchor:
    cmp qword ptr [r14 + 32], 12512
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 48], 1
    jne tk_tb_global_contract_fail
    mov edx, 0xa0800
tk_tb_root_issue_open:
    push rdx
    call tk_tb_root_parent
    pop rdx
    xor r10d, r10d
    mov eax, 257
    syscall
    test rax, rax
    js tk_tb_root_error
    mov [r15 + tk_tb_ROOT_FDS + rbx*8], rax
    mov rax, rbx
    jmp tk_tb_root_value
tk_tb_root_scan_open:
    call tk_tb_root_empty
    cmp rbx, 263
    je tk_tb_root_scan_slot
    cmp rbx, 265
    jne tk_tb_global_contract_fail
tk_tb_root_scan_slot:
    cmp qword ptr [r14 + 32], 12704
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 40], 1
    jne tk_tb_global_contract_fail
    cmp word ptr [r12 + 12704], 46
    jne tk_tb_global_contract_fail
    lea rsi, [r12 + 12704]
    mov edx, 0xb0000
    jmp tk_tb_root_issue_open
tk_tb_root_stat:
    call tk_tb_root_live
    call tk_tb_root_stat_span
    cmp qword ptr [r14 + 48], 0
    jne tk_tb_global_contract_fail
    mov eax, 5
    syscall
    jmp tk_tb_root_zero
tk_tb_root_stat_span:
    cmp qword ptr [r14 + 32], 1024
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 40], 144
    jne tk_tb_global_contract_fail
    lea rsi, [r12 + 1024]
    ret
tk_tb_root_statx:
    call tk_tb_root_live
    cmp qword ptr [r14 + 32], 3072
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 40], 256
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 48], 0
    jne tk_tb_global_contract_fail
    lea rsi, [rip + tk_tb_literal_empty]
    mov edx, 4096
    mov r10d, 4095
    lea r8, [r12 + 3072]
    mov eax, 332
    syscall
    jmp tk_tb_root_zero
tk_tb_root_statat:
    call tk_tb_root_live
    call tk_tb_root_stat_span
    cmp qword ptr [r14 + 48], 0
    jne tk_tb_global_contract_fail
    lea rsi, [rip + tk_tb_literal_empty]
    lea rdx, [r12 + 1024]
    mov r10d, 4096
    mov eax, 262
    syscall
    jmp tk_tb_root_zero
tk_tb_root_probe:
    cmp qword ptr [r14 + 24], 0
    jne tk_tb_global_contract_fail
    call tk_tb_root_zero_span
    xor edi, edi
    xor esi, esi
    xor edx, edx
    ret
tk_tb_root_statx_probe:
    call tk_tb_root_probe
    mov r10d, 4095
    xor r8d, r8d
    mov eax, 332
    syscall
    jmp tk_tb_root_zero
tk_tb_root_statat_probe:
    call tk_tb_root_probe
    lea rdx, [r12 + 1024]
    xor r10d, r10d
    mov eax, 262
    syscall
    jmp tk_tb_root_zero
tk_tb_root_named:
    call tk_tb_root_name
    call tk_tb_root_live
    cmp qword ptr [r14 + 48], 1024
    jne tk_tb_global_contract_fail
    lea rdx, [r12 + 1024]
    mov r10d, 256
    mov eax, 262
    syscall
    jmp tk_tb_root_zero
tk_tb_root_uid:
    cmp qword ptr [r14 + 24], 0
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 32], 2048
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 40], 8
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 48], 0
    jne tk_tb_global_contract_fail
    mov eax, 107
    syscall
    mov [r12 + 2048], rax
    xor eax, eax
    jmp tk_tb_root_zero
tk_tb_root_duplicate:
    call tk_tb_root_empty
    mov rax, [r14 + 32]
    or rax, [r14 + 40]
    jnz tk_tb_global_contract_fail
    cmp rbx, 1
    je tk_tb_root_clone_inner
    cmp rbx, 264
    je tk_tb_root_clone_stream
    cmp rbx, 266
    jne tk_tb_global_contract_fail
tk_tb_root_clone_stream:
    lea rax, [rbx - 1]
    cmp [r14 + 48], rax
    jne tk_tb_global_contract_fail
    jmp tk_tb_root_duplicate_do
tk_tb_root_clone_inner:
    cmp qword ptr [r14 + 48], 0
    jne tk_tb_global_contract_fail
tk_tb_root_duplicate_do:
    call tk_tb_root_parent
    mov esi, 1030
    mov edx, 3
    mov eax, 72
    syscall
    test rax, rax
    js tk_tb_root_error
    mov [r15 + tk_tb_ROOT_FDS + rbx*8], rax
    mov rax, rbx
    jmp tk_tb_root_value
tk_tb_root_mkdir:
    call tk_tb_root_name
    call tk_tb_root_live
    cmp qword ptr [r14 + 48], 448
    jne tk_tb_global_contract_fail
    cmp rcx, 1
    je tk_tb_root_mkdir_root
    cmp rcx, 261
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 32], 12416
    jne tk_tb_global_contract_fail
    jmp tk_tb_root_mkdir_do
tk_tb_root_mkdir_root:
    cmp qword ptr [r14 + 32], 12432
    jne tk_tb_global_contract_fail
tk_tb_root_mkdir_do:
    mov edx, 448
    mov eax, 258
    syscall
    jmp tk_tb_root_zero
tk_tb_root_sync:
    call tk_tb_root_zero_span
    call tk_tb_root_live
    mov eax, 74
    syscall
    jmp tk_tb_root_zero
tk_tb_root_unlink:
    call tk_tb_root_name
    call tk_tb_root_live
    cmp rcx, 1
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 32], 12608
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 48], 0
    jne tk_tb_global_contract_fail
    xor edx, edx
    mov eax, 263
    syscall
    jmp tk_tb_root_zero
tk_tb_root_close:
    call tk_tb_root_zero_span
    call tk_tb_root_live
    test rcx, rcx
    jz tk_tb_global_contract_fail
    cmp rcx, 2
    je tk_tb_global_contract_fail
    cmp byte ptr [r12 + rcx + 56320], 0
    jne tk_tb_global_contract_fail
    mov qword ptr [r15 + tk_tb_ROOT_FDS + rcx*8], -1
    cmp rcx, 1
    jne tk_tb_root_close_alias_retired
    mov qword ptr [r15 + tk_tb_ROOT_FDS], -1
tk_tb_root_close_alias_retired:
    call tk_tb_shared_close
    jmp tk_tb_root_zero
tk_tb_root_flags:
    call tk_tb_root_zero_span
    call tk_tb_root_live
    cmp rcx, 264
    je tk_tb_root_flags_do
    cmp rcx, 266
    jne tk_tb_global_contract_fail
tk_tb_root_flags_do:
    mov esi, 3
    xor edx, edx
    mov eax, 72
    syscall
    jmp tk_tb_root_value
tk_tb_root_directory:
    call tk_tb_root_live
    cmp rcx, 264
    je tk_tb_root_directory_outer
    cmp rcx, 266
    jne tk_tb_global_contract_fail
    mov esi, 2097152
    jmp tk_tb_root_directory_span
tk_tb_root_directory_outer:
    mov esi, 1048576
tk_tb_root_directory_span:
    cmp [r14 + 32], rsi
    jne tk_tb_global_contract_fail
    add rsi, r12
    mov rdx, [r14 + 40]
    cmp rdx, 32768
    jb tk_tb_global_contract_fail
    cmp rdx, 1048576
    ja tk_tb_global_contract_fail
    cmp qword ptr [r14 + 48], 0
    jne tk_tb_global_contract_fail
    mov eax, 217
    syscall
    jmp tk_tb_root_value
tk_tb_root_zero:
    test rax, rax
    js tk_tb_root_error
    jnz tk_tb_global_contract_fail
    jmp tk_tb_root_ack
tk_tb_root_value:
    test rax, rax
    js tk_tb_root_error
    mov [r14 + 72], rax
    jmp tk_tb_root_ack
tk_tb_root_error:
    cmp rax, -4095
    jb tk_tb_global_contract_fail
    neg rax
    mov [r14 + 80], rax
tk_tb_root_ack:
    mov rax, [r14 + 8]
    mov [r14 + 64], rax
    jmp tk_tb_resume_archive
tk_tb_archive_result:
    mov [r15 + 32], eax
    cmp eax, 8192
    ja tk_tb_registry_inner_refusal
    cmp eax, 64
    jb tk_tb_global_contract_fail
    cmp qword ptr [r12 + 8], 0
    jne tk_tb_global_contract_fail
    mov ebx, eax
    mov rdi, [rsp + 8]
    lea rsi, [r15 + tk_tb_R_OUTPUT]
    mov ecx, eax
    rep movsb
    mov eax, ebx
    mov qword ptr [r15 + tk_tb_ROOT_FDS], -1
    add rsp, 24
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret
tk_tb_registry_inner_refusal:
    cmp eax, 0xffffffff
    je tk_tb_registry_inner_restore
    cmp eax, 0xfffffffe
    jne tk_tb_global_contract_fail
tk_tb_registry_inner_restore:
    mov qword ptr [r15 + tk_tb_ROOT_FDS], -1
    add rsp, 24
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret
tk_tb_literal_empty:
    .byte 0
tk_tb_literal_layout:
    .asciz "request-archive-v12"
tk_tb_literal_legacy:
    .asciz "request-archive-v11"
tk_tb_literal_anchor:
    .asciz ".request-archive-v12-anchor.json"
tk_tb_literal_intent:
    .asciz ".request-archive-v12-init.json"

tk_tb_root_child:
    cmp qword ptr [r14 + 32], 16384
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 48], 32768
    jne tk_tb_global_contract_fail
    cmp rax, 100
    je tk_tb_call_legacy
    cmp rax, 101
    je tk_tb_call_metadata
    cmp rax, 102
    je tk_tb_call_writer
    cmp rax, 103
    je tk_tb_call_namespace
    cmp rax, 105
    je tk_tb_call_visitor
    cmp rax, 104
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 40], 93
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 56], 512
    jne tk_tb_global_contract_fail
    mov rcx, [r14 + 24]
    cmp rcx, 2
    je tk_tb_call_record_ready
    cmp rcx, 4
    jb tk_tb_global_contract_fail
    cmp rcx, 259
    ja tk_tb_global_contract_fail
tk_tb_call_record_ready:
    lea rdi, [r12 + 16384]
    mov esi, 93
    lea rdx, [r12 + 32768]
    call tk_tb_record_entry
    jmp tk_tb_root_child_return
tk_tb_call_legacy:
    cmp qword ptr [r14 + 24], 1
    ja tk_tb_global_contract_fail
    cmp qword ptr [r14 + 40], 32
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 56], 4096
    jne tk_tb_global_contract_fail
    lea rdi, [r12 + 16384]
    mov esi, 32
    lea rdx, [r12 + 32768]
    call tk_tb_legacy_entry
    jmp tk_tb_root_child_return
tk_tb_call_metadata:
    cmp qword ptr [r14 + 24], 1
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 40], 32
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 56], 4480
    jne tk_tb_global_contract_fail
    lea rdi, [r12 + 16384]
    mov esi, 32
    lea rdx, [r12 + 32768]
    call tk_tb_metadata_entry
    jmp tk_tb_root_child_return
tk_tb_call_writer:
    cmp qword ptr [r14 + 24], 1
    jne tk_tb_global_contract_fail
    mov rsi, [r14 + 40]
    cmp rsi, 128
    jb tk_tb_global_contract_fail
    cmp rsi, 4224
    ja tk_tb_global_contract_fail
    cmp qword ptr [r14 + 56], 64
    jne tk_tb_global_contract_fail
    lea rdi, [r12 + 16384]
    lea rdx, [r12 + 32768]
    call tk_tb_writer_entry
    jmp tk_tb_root_child_return
tk_tb_call_namespace:
    cmp qword ptr [r14 + 24], 0
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 56], 72
    jne tk_tb_global_contract_fail
    mov rsi, [r14 + 40]
    cmp rsi, 32
    je tk_tb_call_namespace_ready
    cmp rsi, 2096
    jne tk_tb_global_contract_fail
tk_tb_call_namespace_ready:
    lea rdi, [r12 + 16384]
    lea rdx, [r12 + 32768]
    call tk_tb_shared_namespace_entry
    jmp tk_tb_root_child_return
tk_tb_call_visitor:
    cmp qword ptr [r14 + 56], 64
    jne tk_tb_global_contract_fail
    mov rsi, [r14 + 40]
    cmp rsi, 64
    jb tk_tb_global_contract_fail
    cmp rsi, 319
    ja tk_tb_global_contract_fail
    lea rdi, [r12 + 16384]
    mov rax, 0x313030564f415248
    cmp [rdi], rax
    jne tk_tb_global_contract_fail
    mov rax, [rdi + 32]
    add rax, 64
    cmp rax, rsi
    jne tk_tb_global_contract_fail
    mov rcx, [r14 + 24]
    cmp rcx, [rdi + 16]
    jne tk_tb_global_contract_fail
    cmp qword ptr [rdi + 8], 2
    je tk_tb_visitor_finish
    cmp qword ptr [rdi + 8], 1
    jne tk_tb_global_contract_fail
    cmp rcx, 2
    je tk_tb_visitor_slot
    cmp rcx, 4
    jb tk_tb_global_contract_fail
    cmp rcx, 259
    ja tk_tb_global_contract_fail
tk_tb_visitor_slot:
    cmp qword ptr [r15 + tk_tb_ROOT_FDS + rcx*8], 0
    jl tk_tb_global_contract_fail
    jmp tk_tb_visitor_ready
tk_tb_visitor_finish:
    test rcx, rcx
    jnz tk_tb_global_contract_fail
    cmp rsi, 64
    jne tk_tb_global_contract_fail
tk_tb_visitor_ready:
    lea rdx, [r12 + 32768]
    call tk_tb_visitor_entry
tk_tb_root_child_return:
    mov ecx, eax
    cmp rax, rcx
    jne tk_tb_global_contract_fail
    mov [r14 + 72], rax
    jmp tk_tb_root_ack

/* Every borrowed alias is registered before the descriptor may be retained. */
# Only owning slots participate in last-reference detection. Borrowed root,
# hot, writer/read and Namespace input slots never prolong File lifetimes.
tk_tb_shared_referenced:
    push r8
    push r9
    push r10
    push r11
    mov r11, [r15 + 4000]
    mov r11, [r11 + tk_tb_I_GLOBAL]
    mov r10, [r11 + tk_tb_G_INSTANCES]
tk_tb_shared_instance_next:
    test r10, r10
    jz tk_tb_shared_save_start
    cmp [r10 + tk_tb_I_GLOBAL], r11
    jne tk_tb_global_contract_fail
    mov ecx, 1
tk_tb_shared_root_next:
    cmp [r10 + tk_tb_ROOT_FDS + rcx*8], rdi
    je tk_tb_shared_yes
    inc ecx
    cmp ecx, 267
    jb tk_tb_shared_root_next
    cmp [r10 + tk_tb_L_BASE + 136], rdi
    je tk_tb_shared_yes
    cmp [r10 + tk_tb_L_BASE + 2097152 + 136], rdi
    je tk_tb_shared_yes
    mov r10, [r10 + tk_tb_I_NEXT]
    jmp tk_tb_shared_instance_next
tk_tb_shared_save_start:
    mov r10, [r11 + tk_tb_G_WRITE]
    test r10, r10
    jz tk_tb_shared_entries_start
    mov ecx, 1
tk_tb_shared_save_next:
    cmp [r10 + 128 + rcx*8], rdi
    je tk_tb_shared_yes
    inc ecx
    cmp ecx, 7
    jb tk_tb_shared_save_next
    cmp [r10 + 192], rdi
    je tk_tb_shared_yes
tk_tb_shared_entries_start:
    mov r10, [r11 + tk_tb_G_ENTRIES]
    test r10, r10
    jz tk_tb_shared_remove_start
    mov ecx, 1
tk_tb_shared_entries_next:
    cmp [r10 + 128 + rcx*8], rdi
    je tk_tb_shared_yes
    inc ecx
    cmp ecx, 7
    jb tk_tb_shared_entries_next
tk_tb_shared_remove_start:
    mov r10, [r11 + tk_tb_G_REMOVE]
    test r10, r10
    jz tk_tb_shared_namespace_start
    mov ecx, 1
tk_tb_shared_remove_next:
    cmp [r10 + 128 + rcx*8], rdi
    je tk_tb_shared_yes
    inc ecx
    cmp ecx, 7
    jb tk_tb_shared_remove_next
tk_tb_shared_namespace_start:
    mov r10, [r11 + tk_tb_G_NAMESPACE]
    test r10, r10
    jz tk_tb_shared_external_start
    mov ecx, 259
tk_tb_shared_namespace_next:
    cmp [r10 + 16384 + rcx*8], rdi
    je tk_tb_shared_yes
    inc ecx
    cmp ecx, 33794
    jb tk_tb_shared_namespace_next
tk_tb_shared_external_start:
    mov r9, [r11 + tk_tb_G_SG]
    mov rax, 0x3130475354415248
    cmp [r9], rax
    jne tk_tb_global_contract_fail
    mov r10, [r9 + 24]
    test r10, r10
    jz tk_tb_shared_external_write
    call tk_tb_shared_directory_owned
    test eax, eax
    jnz tk_tb_shared_yes
tk_tb_shared_external_write:
    mov r10, [r9 + 32]
    test r10, r10
    jz tk_tb_shared_external_tickets
    mov rax, 0x3130435754415248
    cmp [r10], rax
    jne tk_tb_global_contract_fail
    mov ecx, 1
tk_tb_shared_external_write_next:
    cmp [r10 + 128 + rcx*8], rdi
    je tk_tb_shared_yes
    inc ecx
    cmp ecx, 7
    jb tk_tb_shared_external_write_next
    cmp [r10 + 192], rdi
    je tk_tb_shared_yes
tk_tb_shared_external_tickets:
    mov r8, [r9 + 40]
    xor r10d, r10d
tk_tb_shared_ticket_next:
    test r8, r8
    jz tk_tb_shared_no
    cmp [r8 + 16], r9
    jne tk_tb_global_contract_fail
    cmp [r8 + 32], r10
    jne tk_tb_global_contract_fail
    cmp qword ptr [r8 + 8], 0
    je tk_tb_global_contract_fail
    mov r10, [r8 + 80]
    test r10, r10
    jz tk_tb_shared_ticket_following
    call tk_tb_shared_directory_owned
    test eax, eax
    jnz tk_tb_shared_yes
tk_tb_shared_ticket_following:
    mov r10, r8
    mov r8, [r8 + 24]
    jmp tk_tb_shared_ticket_next
tk_tb_shared_directory_owned:
    mov rax, 0x3130434454415248
    cmp [r10], rax
    jne tk_tb_global_contract_fail
    cmp [r10 + 128], rdi
    je tk_tb_shared_directory_yes
    cmp [r10 + 136], rdi
    je tk_tb_shared_directory_yes
    cmp [r10 + 144], rdi
    je tk_tb_shared_directory_yes
    xor eax, eax
    ret
tk_tb_shared_directory_yes:
    mov eax, 1
    ret
tk_tb_shared_no:
    xor eax, eax
    jmp tk_tb_shared_restore
tk_tb_shared_yes:
    mov eax, 1
tk_tb_shared_restore:
    pop r11
    pop r10
    pop r9
    pop r8
    ret

tk_tb_shared_close:
    call tk_tb_shared_referenced
    test eax, eax
    jnz tk_tb_shared_close_deferred
    mov eax, 3
    syscall
    ret
tk_tb_shared_close_deferred:
    xor eax, eax
    ret

tk_tb_cleanup_all_descriptors:
    mov qword ptr [r15 + tk_tb_ROOT_FDS], -1
    mov qword ptr [r15 + tk_tb_L_BASE + 128], -1
    mov qword ptr [r15 + tk_tb_L_BASE + 2097152 + 128], -1
    mov qword ptr [r15 + tk_tb_M_BASE + 128], -1
    mov qword ptr [r15 + tk_tb_W_BASE + 128], -1
    mov qword ptr [r15 + tk_tb_W_BASE + 18874368 + 128], -1
    mov qword ptr [r15 + tk_tb_A_BASE + 128], -1
    lea rbx, [r15 + tk_tb_ROOT_FDS + 8]
    mov r13d, 266
    call tk_tb_cleanup_table
    lea rbx, [r15 + tk_tb_L_BASE + 136]
    mov r13d, 4
    call tk_tb_cleanup_table
    lea rbx, [r15 + tk_tb_L_BASE + 2097152 + 136]
    mov r13d, 1
    call tk_tb_cleanup_table
    lea rbx, [r15 + tk_tb_M_BASE + 136]
    mov r13d, 5
    call tk_tb_cleanup_table
    lea rbx, [r15 + tk_tb_W_BASE + 136]
    mov r13d, 4
    call tk_tb_cleanup_table
    lea rbx, [r15 + tk_tb_W_BASE + 18874368 + 136]
    mov r13d, 5
    call tk_tb_cleanup_table
    lea rbx, [r15 + tk_tb_A_BASE + 136]
    mov r13d, 6
    call tk_tb_cleanup_table
    ret
tk_tb_cleanup_table:
    test r13, r13
    jz tk_tb_cleanup_table_done
    mov rdi, [rbx]
    mov qword ptr [rbx], -1
    test rdi, rdi
    js tk_tb_cleanup_table_next
    call tk_tb_shared_close
tk_tb_cleanup_table_next:
    add rbx, 8
    dec r13
    jmp tk_tb_cleanup_table
tk_tb_cleanup_table_done:
    ret

tk_tb_global_contract_fail:
    jmp tk_contract_fail
tk_tb_global_io_fail:
    jmp tk_io_fail

tk_tb_legacy_entry:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp, 24
    mov [rsp], rdi
    mov [rsp + 8], rdx
    mov [rsp + 16], rsi
    mov rax, [r15 + 4000]
    lea r15, [rax + tk_tb_L_BASE]
    mov r13, r15
    lea r12, [r15 + 1048576]
    lea rdi, [r15 + 4096]
    mov esi, 4096
    mov edx, 3
    mov eax, 10
    syscall
    test rax, rax
    jnz tk_tb_global_io_fail
    lea rdi, [r15 + 4096]
    mov rsi, [rsp]
    mov rcx, [rsp + 16]
    mov [r15 + 24], rcx
    rep movsb
    lea rdi, [r15 + 4096]
    mov esi, 4096
    mov edx, 1
    mov eax, 10
    syscall
    test rax, rax
    jnz tk_tb_global_io_fail
    mov rax, [r15 + 4000]
    cmp qword ptr [r15 + 4096 + 8], 2
    je tk_tb_legacy_no_root_borrow
    cmp qword ptr [r15 + 4096 + 8], 5
    je tk_tb_legacy_no_root_borrow
    mov rcx, [r14 + 24]
    cmp rcx, 266
    ja tk_tb_global_contract_fail
    mov rax, [rax + tk_tb_ROOT_FDS + rcx*8]
    test rax, rax
    js tk_tb_global_contract_fail
    jmp tk_tb_legacy_borrow_ready
tk_tb_legacy_no_root_borrow:
    mov rax, -1
tk_tb_legacy_borrow_ready:
    mov [r15 + 128], rax
    mov [r15 + 2097152 + 128], rax
    cmp qword ptr [r15 + 4096 + 8], 2
    je tk_tb_legacy_release
    cmp qword ptr [r15 + 4096 + 8], 5
    jne tk_tb_legacy_enter
tk_tb_legacy_release:
    mov rax, [r15 + 4000]
    cmp byte ptr [rax + tk_tb_R_OWNER + 56322], 0
    jne tk_tb_global_contract_fail
    mov qword ptr [rax + tk_tb_ROOT_FDS + 16], -1
tk_tb_legacy_enter:
    jmp tk_tb_l_main_resume
.equ tk_tb_l_MAIN_INPUT, 4096
.equ tk_tb_l_MAIN_OUTPUT, 8192
.equ tk_tb_l_MAIN_OWNER, 1048576
.equ tk_tb_l_ANCHOR_BASE, 2097152
.equ tk_tb_l_NAMESPACE_BASE, 5242880
.equ tk_tb_l_ENTROPY_WORK, 15728640
.equ tk_tb_l_FINAL_GUARD, 16777216
.equ tk_tb_l_TOTAL_MAP, 16781312
.equ tk_tb_l_M_ACTION, 256
.equ tk_tb_l_M_STAT, 1024
.equ tk_tb_l_M_STATX, 3072
.equ tk_tb_l_M_TEMP, 4096
.equ tk_tb_l_M_LEGACY, 4352
.equ tk_tb_l_M_ANCHOR, 4608
.equ tk_tb_l_M_JSON, 6144
.equ tk_tb_l_M_REQUEST, 8192
.equ tk_tb_l_M_REPLY, 12288
tk_tb_l_main_resume:
    lea rdi, [r15 + tk_tb_l_MAIN_INPUT]
    mov rsi, [r15 + 24]
    lea rdx, [r15 + tk_tb_l_MAIN_OUTPUT]
    mov ecx, 4096
    mov r8, r12
    mov r9d, 1048576
    call qword ptr [rip + tk_ticket_backend_legacy_image]
    mov ecx, eax
    cmp rax, rcx
    jne tk_tb_global_contract_fail
    cmp eax, 0xfffffff0
    jne tk_tb_l_main_result
    lea r14, [r12 + tk_tb_l_M_ACTION]
    mov rax, 0x313030414c415248
    cmp [r14], rax
    jne tk_tb_global_contract_fail
    mov rax, [r15 + 16]
    inc rax
    jz tk_tb_global_contract_fail
    cmp [r14 + 8], rax
    jne tk_tb_global_contract_fail
    cmp [r12 + 16], rax
    jne tk_tb_global_contract_fail
    mov [r15 + 16], rax
    mov rax, [r14 + 64]
    or rax, [r14 + 72]
    or rax, [r14 + 80]
    or rax, [r14 + 88]
    jnz tk_tb_global_contract_fail
    mov rax, [r14 + 16]
    cmp rax, 100
    jae tk_tb_l_main_child
    cmp qword ptr [r14 + 56], 0
    jne tk_tb_global_contract_fail
    cmp rax, 1
    je tk_tb_l_main_open
    cmp rax, 2
    je tk_tb_l_main_fstat
    cmp rax, 3
    je tk_tb_l_main_mkdir
    cmp rax, 4
    je tk_tb_l_main_sync
    cmp rax, 5
    je tk_tb_l_main_uid
    cmp rax, 6
    je tk_tb_l_main_temp_open
    cmp rax, 7
    je tk_tb_l_main_close
    cmp rax, 8
    je tk_tb_l_main_statx
    cmp rax, 9
    je tk_tb_l_main_statx_probe
    cmp rax, 10
    je tk_tb_l_main_statat
    cmp rax, 11
    je tk_tb_l_main_statat_probe
    cmp rax, 12
    je tk_tb_l_main_write
    cmp rax, 13
    je tk_tb_l_main_link
    cmp rax, 14
    je tk_tb_l_main_unlink
    jmp tk_tb_global_contract_fail
tk_tb_l_main_zero_span:
    mov rax, [r14 + 32]
    or rax, [r14 + 40]
    or rax, [r14 + 48]
    jnz tk_tb_global_contract_fail
    ret
tk_tb_l_main_slot_live:
    mov rcx, [r14 + 24]
    cmp rcx, 2
    ja tk_tb_global_contract_fail
    mov rdi, [r15 + rcx*8 + 128]
    test rdi, rdi
    js tk_tb_global_contract_fail
    ret
tk_tb_l_main_legacy_name:
    cmp qword ptr [r14 + 32], tk_tb_l_M_LEGACY
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 40], 19
    jne tk_tb_global_contract_fail
    lea rsi, [r12 + tk_tb_l_M_LEGACY]
    mov rax, 0x2d74736575716572
    cmp [rsi], rax
    jne tk_tb_global_contract_fail
    mov rax, 0x2d65766968637261
    cmp [rsi + 8], rax
    jne tk_tb_global_contract_fail
    cmp dword ptr [rsi + 16], 0x00313176
    jne tk_tb_global_contract_fail
    ret
tk_tb_l_main_temp_name:
    cmp qword ptr [r14 + 32], tk_tb_l_M_TEMP
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 40], 84
    jne tk_tb_global_contract_fail
    lea rsi, [r12 + tk_tb_l_M_TEMP]
    mov rax, 0x657669686372612e
    cmp [rsi], rax
    jne tk_tb_global_contract_fail
    mov rax, 0x2d726f68636e612d
    cmp [rsi + 8], rax
    jne tk_tb_global_contract_fail
    mov ecx, 16
tk_tb_l_main_temp_digit:
    mov al, [rsi + rcx]
    cmp al, 48
    jb tk_tb_global_contract_fail
    cmp al, 57
    jbe tk_tb_l_main_temp_digit_ok
    cmp al, 97
    jb tk_tb_global_contract_fail
    cmp al, 102
    ja tk_tb_global_contract_fail
tk_tb_l_main_temp_digit_ok:
    inc ecx
    cmp ecx, 80
    jb tk_tb_l_main_temp_digit
    cmp dword ptr [rsi + 80], 0x706d742e
    jne tk_tb_global_contract_fail
    cmp byte ptr [rsi + 84], 0
    jne tk_tb_global_contract_fail
    ret
tk_tb_l_main_open:
    mov rax, [r12 + 8]
    cmp rax, 3
    je tk_tb_l_main_open_phase
    cmp rax, 6
    jne tk_tb_global_contract_fail
tk_tb_l_main_open_phase:
    cmp qword ptr [r14 + 24], 1
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 48], 0
    jne tk_tb_global_contract_fail
    cmp qword ptr [r15 + 136], -1
    jne tk_tb_global_contract_fail
    call tk_tb_l_main_legacy_name
    mov rdi, [r15 + 128]
    mov edx, 0xb0000
    xor r10d, r10d
    mov eax, 257
    syscall
    test rax, rax
    js tk_tb_l_main_error
    mov [r15 + 136], rax
    mov qword ptr [r14 + 72], 1
    jmp tk_tb_l_main_ack
tk_tb_l_main_mkdir:
    cmp qword ptr [r12 + 8], 4
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 24], 0
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 48], 448
    jne tk_tb_global_contract_fail
    call tk_tb_l_main_legacy_name
    mov rdi, [r15 + 128]
    mov edx, 448
    mov eax, 258
    syscall
    jmp tk_tb_l_main_zero
tk_tb_l_main_sync:
    call tk_tb_l_main_zero_span
    mov rax, [r12 + 8]
    cmp rax, 5
    je tk_tb_l_main_root_sync
    cmp rax, 16
    je tk_tb_l_main_root_sync
    cmp rax, 13
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 24], 2
    jne tk_tb_global_contract_fail
    jmp tk_tb_l_main_sync_live
tk_tb_l_main_root_sync:
    cmp qword ptr [r14 + 24], 0
    jne tk_tb_global_contract_fail
tk_tb_l_main_sync_live:
    call tk_tb_l_main_slot_live
    mov eax, 74
    syscall
    jmp tk_tb_l_main_zero
tk_tb_l_main_uid:
    cmp qword ptr [r12 + 8], 8
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 24], 0
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 32], tk_tb_l_M_STAT + 144
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 40], 8
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 48], 0
    jne tk_tb_global_contract_fail
    mov eax, 107
    syscall
    mov [r12 + tk_tb_l_M_STAT + 144], rax
    jmp tk_tb_l_main_ack
tk_tb_l_main_temp_open:
    cmp qword ptr [r12 + 8], 11
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 24], 2
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 48], 384
    jne tk_tb_global_contract_fail
    cmp qword ptr [r15 + 144], -1
    jne tk_tb_global_contract_fail
    call tk_tb_l_main_temp_name
    mov rdi, [r15 + 128]
    mov edx, 0xa00c1
    mov r10d, 384
    mov eax, 257
    syscall
    test rax, rax
    js tk_tb_l_main_error
    mov [r15 + 144], rax
    mov qword ptr [r14 + 72], 2
    jmp tk_tb_l_main_ack
tk_tb_l_main_close:
    call tk_tb_l_main_zero_span
    mov rax, [r12 + 8]
    cmp rax, 302
    je tk_tb_l_main_legacy_close
    cmp rax, 16
    je tk_tb_l_main_temp_close
    cmp rax, 301
    jne tk_tb_global_contract_fail
tk_tb_l_main_temp_close:
    cmp qword ptr [r14 + 24], 2
    jne tk_tb_global_contract_fail
    jmp tk_tb_l_main_close_live
tk_tb_l_main_legacy_close:
    cmp qword ptr [r14 + 24], 1
    jne tk_tb_global_contract_fail
tk_tb_l_main_close_live:
    call tk_tb_l_main_slot_live
    mov qword ptr [r15 + rcx*8 + 128], -1
    call tk_tb_shared_close
    jmp tk_tb_l_main_zero
tk_tb_l_main_metadata_live:
    mov rcx, [r14 + 24]
    cmp rcx, 1
    ja tk_tb_global_contract_fail
    cmp rcx, [r12 + 128]
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 48], 0
    jne tk_tb_global_contract_fail
    call tk_tb_l_main_slot_live
    ret
tk_tb_l_main_stat_span:
    cmp qword ptr [r14 + 32], tk_tb_l_M_STAT
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 40], 144
    jne tk_tb_global_contract_fail
    lea rsi, [r12 + tk_tb_l_M_STAT]
    ret
tk_tb_l_main_fstat:
    cmp qword ptr [r12 + 8], 50
    jne tk_tb_global_contract_fail
    call tk_tb_l_main_metadata_live
    call tk_tb_l_main_stat_span
    mov eax, 5
    syscall
    jmp tk_tb_l_main_zero
tk_tb_l_main_statx:
    cmp qword ptr [r12 + 8], 51
    jne tk_tb_global_contract_fail
    call tk_tb_l_main_metadata_live
    cmp qword ptr [r14 + 32], tk_tb_l_M_STATX
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 40], 256
    jne tk_tb_global_contract_fail
    lea rsi, [r15 + 512]
    mov edx, 4096
    mov r10d, 4095
    lea r8, [r12 + tk_tb_l_M_STATX]
    mov eax, 332
    syscall
    jmp tk_tb_l_main_zero
tk_tb_l_main_statat:
    cmp qword ptr [r12 + 8], 52
    jne tk_tb_global_contract_fail
    call tk_tb_l_main_metadata_live
    call tk_tb_l_main_stat_span
    lea rsi, [r15 + 512]
    lea rdx, [r12 + tk_tb_l_M_STAT]
    mov r10d, 4096
    mov eax, 262
    syscall
    jmp tk_tb_l_main_zero
tk_tb_l_main_probe_admit:
    cmp qword ptr [r14 + 24], 0
    jne tk_tb_global_contract_fail
    call tk_tb_l_main_zero_span
    xor edi, edi
    xor esi, esi
    xor edx, edx
    ret
tk_tb_l_main_statx_probe:
    cmp qword ptr [r12 + 8], 53
    jne tk_tb_global_contract_fail
    call tk_tb_l_main_probe_admit
    mov r10d, 4095
    xor r8d, r8d
    mov eax, 332
    syscall
    jmp tk_tb_l_main_zero
tk_tb_l_main_statat_probe:
    cmp qword ptr [r12 + 8], 54
    jne tk_tb_global_contract_fail
    call tk_tb_l_main_probe_admit
    lea rdx, [r12 + tk_tb_l_M_STAT]
    xor r10d, r10d
    mov eax, 262
    syscall
    jmp tk_tb_l_main_zero
tk_tb_l_main_write:
    cmp qword ptr [r12 + 8], 12
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 24], 2
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 48], 0
    jne tk_tb_global_contract_fail
    mov rax, [r12 + 88]
    mov rdx, [r12 + 96]
    cmp rdx, 256
    ja tk_tb_global_contract_fail
    cmp rax, rdx
    jae tk_tb_global_contract_fail
    sub rdx, rax
    cmp rdx, [r14 + 40]
    jne tk_tb_global_contract_fail
    lea rsi, [rax + tk_tb_l_M_JSON]
    cmp rsi, [r14 + 32]
    jne tk_tb_global_contract_fail
    add rsi, r12
    mov rdi, [r15 + 144]
    test rdi, rdi
    js tk_tb_global_contract_fail
    mov eax, 1
    syscall
    jmp tk_tb_l_main_value
tk_tb_l_main_link:
    cmp qword ptr [r12 + 8], 14
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 24], 0
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 48], tk_tb_l_M_ANCHOR
    jne tk_tb_global_contract_fail
    call tk_tb_l_main_temp_name
    lea r10, [r12 + tk_tb_l_M_ANCHOR]
    mov rax, 0x747365757165722e
    cmp [r10], rax
    jne tk_tb_global_contract_fail
    mov rax, 0x657669686372612d
    cmp [r10 + 8], rax
    jne tk_tb_global_contract_fail
    mov rax, 0x636e612d3131762d
    cmp [r10 + 16], rax
    jne tk_tb_global_contract_fail
    mov rax, 0x6e6f736a2e726f68
    cmp [r10 + 24], rax
    jne tk_tb_global_contract_fail
    cmp byte ptr [r10 + 32], 0
    jne tk_tb_global_contract_fail
    mov rdi, [r15 + 128]
    mov rdx, rdi
    xor r8d, r8d
    mov eax, 265
    syscall
    jmp tk_tb_l_main_zero
tk_tb_l_main_unlink:
    mov rax, [r12 + 8]
    cmp rax, 15
    je tk_tb_l_main_unlink_phase
    cmp rax, 300
    jne tk_tb_global_contract_fail
tk_tb_l_main_unlink_phase:
    cmp qword ptr [r14 + 24], 0
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 48], 0
    jne tk_tb_global_contract_fail
    call tk_tb_l_main_temp_name
    mov rdi, [r15 + 128]
    xor edx, edx
    mov eax, 263
    syscall
    jmp tk_tb_l_main_zero
tk_tb_l_main_child:
    cmp qword ptr [r14 + 24], 0
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 32], tk_tb_l_M_REQUEST
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 48], tk_tb_l_M_REPLY
    jne tk_tb_global_contract_fail
    cmp rax, 100
    je tk_tb_l_main_anchor_call
    cmp rax, 101
    je tk_tb_l_main_namespace_call
    cmp rax, 102
    jne tk_tb_global_contract_fail
    cmp qword ptr [r12 + 8], 10
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 40], 24
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 56], 32
    jne tk_tb_global_contract_fail
    lea rdi, [r12 + tk_tb_l_M_REQUEST]
    lea rdx, [r12 + tk_tb_l_M_REPLY]
    mov esi, 24
    call tk_tb_shared_entropy_entry
    jmp tk_tb_l_main_child_return
tk_tb_l_main_anchor_call:
    cmp qword ptr [r14 + 40], 32
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 56], 4096
    jne tk_tb_global_contract_fail
    mov rax, [r12 + 8]
    cmp rax, 2
    je tk_tb_l_main_anchor_phase
    cmp rax, 17
    je tk_tb_l_main_anchor_phase
    cmp rax, 303
    je tk_tb_l_main_anchor_phase
    cmp rax, 400
    jne tk_tb_global_contract_fail
tk_tb_l_main_anchor_phase:
    call tk_tb_l_anchor_entry
    jmp tk_tb_l_main_child_return
tk_tb_l_main_namespace_call:
    cmp qword ptr [r12 + 8], 9
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 40], 32
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 56], 72
    jne tk_tb_global_contract_fail
    cmp qword ptr [r12 + tk_tb_l_M_REQUEST + 8], 1
    jne tk_tb_global_contract_fail
    cmp qword ptr [r12 + tk_tb_l_M_REQUEST + 16], 0
    jne tk_tb_global_contract_fail
    lea rdi, [r12 + tk_tb_l_M_REQUEST]
    lea rdx, [r12 + tk_tb_l_M_REPLY]
    mov esi, 32
    call tk_tb_shared_namespace_entry
tk_tb_l_main_child_return:
    mov [r14 + 72], rax
    jmp tk_tb_l_main_ack
tk_tb_l_main_zero:
    test rax, rax
    js tk_tb_l_main_error
    jnz tk_tb_global_contract_fail
    jmp tk_tb_l_main_ack
tk_tb_l_main_value:
    test rax, rax
    js tk_tb_l_main_error
    mov [r14 + 72], rax
    jmp tk_tb_l_main_ack
tk_tb_l_main_error:
    cmp rax, -4095
    jb tk_tb_global_contract_fail
    neg rax
    mov [r14 + 80], rax
tk_tb_l_main_ack:
    mov rax, [r14 + 8]
    mov [r14 + 64], rax
    jmp tk_tb_l_main_resume
tk_tb_l_main_result:
    cmp qword ptr [r12 + 8], 0
    jne tk_tb_global_contract_fail
    mov [r15 + 32], eax
    cmp eax, 4096
    jbe tk_tb_l_main_normal_result
    cmp eax, 0xffffffff
    je tk_tb_l_main_result_header
    cmp eax, 0xfffffffe
    jne tk_tb_global_contract_fail
    jmp tk_tb_l_main_result_header
tk_tb_l_main_normal_result:
    cmp eax, 64
    jb tk_tb_global_contract_fail
    cmp qword ptr [r15 + 144], -1
    jne tk_tb_global_contract_fail
    cmp qword ptr [r12 + 144], 0
    jne tk_tb_global_contract_fail
    cmp qword ptr [r12 + 48], 0
    jne tk_tb_l_main_result_live
    cmp qword ptr [r15 + 136], -1
    jne tk_tb_global_contract_fail
    cmp qword ptr [r15 + tk_tb_l_ANCHOR_BASE + 136], -1
    jne tk_tb_global_contract_fail
    jmp tk_tb_l_main_result_header
tk_tb_l_main_result_live:
    cmp qword ptr [r12 + 48], 1
    jne tk_tb_global_contract_fail
    cmp qword ptr [r15 + 136], -1
    je tk_tb_global_contract_fail
    cmp qword ptr [r15 + tk_tb_l_ANCHOR_BASE + 136], -1
    je tk_tb_global_contract_fail
tk_tb_l_main_result_header:
    mov rax, [r15 + 4000]
    mov rdx, [r15 + 136]
    mov [rax + tk_tb_ROOT_FDS + 16], rdx
    mov qword ptr [r15 + 128], -1
    mov qword ptr [r15 + tk_tb_l_ANCHOR_BASE + 128], -1
    mov eax, [r15 + 32]
    cmp eax, 64
    jb tk_tb_global_contract_fail
    cmp eax, 2368
    ja tk_tb_global_contract_fail
    mov ebx, eax
    mov rdi, [rsp + 8]
    lea rsi, [r15 + tk_tb_l_MAIN_OUTPUT]
    mov ecx, eax
    rep movsb
    mov eax, ebx
    add rsp, 24
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret
.equ tk_tb_l_a_INPUT, 4096
.equ tk_tb_l_a_OUTPUT, 8192
.equ tk_tb_l_a_OWNER, 65536
.equ tk_tb_l_a_JSON_WORK, 1114112
.equ tk_tb_l_a_GUARD, 2162688
.equ tk_tb_l_a_MAP_SIZE, 2166784
.equ tk_tb_l_a_ACTION, 256
.equ tk_tb_l_a_STAT, 1024
.equ tk_tb_l_a_NAME, 2048
.equ tk_tb_l_a_STATX, 3072
.equ tk_tb_l_a_READ_BYTES, 8192
.equ tk_tb_l_a_CHILD_REQUEST, 12288
.equ tk_tb_l_a_CHILD_REPLY, 16384
tk_tb_l_anchor_entry:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp, 8
    lea r15, [r13 + tk_tb_l_ANCHOR_BASE]
    lea r12, [r15 + 65536]
    lea rdi, [r15 + 4096]
    mov esi, 4096
    mov edx, 3
    mov eax, 10
    syscall
    test rax, rax
    jnz tk_tb_global_io_fail
    lea rdi, [r15 + 4096]
    lea rsi, [r13 + tk_tb_l_MAIN_OWNER + tk_tb_l_M_REQUEST]
    mov ecx, 32
    rep movsb
    mov qword ptr [r15 + 24], 32
    lea rdi, [r15 + 4096]
    mov esi, 4096
    mov edx, 1
    mov eax, 10
    syscall
    test rax, rax
    jnz tk_tb_global_io_fail
    mov rax, [r13 + 128]
    cmp [r15 + 128], rax
    jne tk_tb_global_contract_fail
tk_tb_l_a_resume_anchor:
    lea rdi, [r15 + tk_tb_l_a_INPUT]
    mov rsi, [r15 + 24]
    lea rdx, [r15 + tk_tb_l_a_OUTPUT]
    mov ecx, 4096
    mov r8, r12
    mov r9d, 1048576
    call qword ptr [rip + tk_ticket_backend_anchor_image]
    mov ecx, eax
    cmp rax, rcx
    jne tk_tb_global_contract_fail
    cmp eax, 0xfffffff0
    jne tk_tb_l_a_owner_result
    lea r14, [r12 + tk_tb_l_a_ACTION]
    mov rax, 0x3130304141415248
    cmp [r14], rax
    jne tk_tb_global_contract_fail
    mov rax, [r15 + 16]
    inc rax
    jz tk_tb_global_contract_fail
    cmp [r14 + 8], rax
    jne tk_tb_global_contract_fail
    cmp [r12 + 16], rax
    jne tk_tb_global_contract_fail
    mov [r15 + 16], rax
    mov rax, [r14 + 64]
    or rax, [r14 + 72]
    or rax, [r14 + 80]
    or rax, [r14 + 88]
    jnz tk_tb_global_contract_fail
    mov rax, [r14 + 16]
    cmp rax, 100
    je tk_tb_l_a_json_effect
    cmp qword ptr [r14 + 56], 0
    jne tk_tb_global_contract_fail
    cmp rax, 1
    je tk_tb_l_a_open_effect
    cmp rax, 2
    je tk_tb_l_a_held_effect
    cmp rax, 3
    je tk_tb_l_a_named_effect
    cmp rax, 4
    je tk_tb_l_a_read_effect
    cmp rax, 5
    je tk_tb_l_a_uid_effect
    cmp rax, 6
    je tk_tb_l_a_pread_effect
    cmp rax, 7
    je tk_tb_l_a_close_effect
    cmp rax, 8
    je tk_tb_l_a_statx_effect
    cmp rax, 9
    je tk_tb_l_a_statx_probe_effect
    cmp rax, 10
    je tk_tb_l_a_statat_effect
    cmp rax, 11
    je tk_tb_l_a_statat_probe_effect
    jmp tk_tb_global_contract_fail
tk_tb_l_a_anchor_live:
    cmp qword ptr [r14 + 24], 1
    jne tk_tb_global_contract_fail
    mov rdi, [r15 + 136]
    test rdi, rdi
    js tk_tb_global_contract_fail
    ret
tk_tb_l_a_fixed_name:
    cmp qword ptr [r14 + 32], tk_tb_l_a_NAME
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 40], 32
    jne tk_tb_global_contract_fail
    lea rsi, [r12 + tk_tb_l_a_NAME]
    mov rax, 0x747365757165722e
    cmp [rsi], rax
    jne tk_tb_global_contract_fail
    mov rax, 0x657669686372612d
    cmp [rsi + 8], rax
    jne tk_tb_global_contract_fail
    mov rax, 0x636e612d3131762d
    cmp [rsi + 16], rax
    jne tk_tb_global_contract_fail
    mov rax, 0x6e6f736a2e726f68
    cmp [rsi + 24], rax
    jne tk_tb_global_contract_fail
    cmp byte ptr [rsi + 32], 0
    jne tk_tb_global_contract_fail
    ret
tk_tb_l_a_open_effect:
    cmp qword ptr [r12 + 8], 1
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 24], 1
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 48], 0
    jne tk_tb_global_contract_fail
    cmp qword ptr [r15 + 136], -1
    jne tk_tb_global_contract_fail
    call tk_tb_l_a_fixed_name
    mov rdi, [r15 + 128]
    mov edx, 0xa0800
    xor r10d, r10d
    mov eax, 257
    syscall
    test rax, rax
    js tk_tb_l_a_effect_error
    mov [r15 + 136], rax
    mov qword ptr [r14 + 72], 1
    jmp tk_tb_l_a_acknowledge
tk_tb_l_a_held_effect:
    cmp qword ptr [r12 + 8], 50
    jne tk_tb_global_contract_fail
    call tk_tb_l_a_anchor_live
    cmp qword ptr [r14 + 32], tk_tb_l_a_STAT
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 40], 144
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 48], 0
    jne tk_tb_global_contract_fail
    lea rsi, [r12 + tk_tb_l_a_STAT]
    mov eax, 5
    syscall
    test rax, rax
    js tk_tb_l_a_effect_error
    jmp tk_tb_l_a_acknowledge
tk_tb_l_a_statx_effect:
    cmp qword ptr [r12 + 8], 51
    jne tk_tb_global_contract_fail
    call tk_tb_l_a_anchor_live
    cmp qword ptr [r14 + 32], tk_tb_l_a_STATX
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 40], 256
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 48], 0
    jne tk_tb_global_contract_fail
    cmp byte ptr [r12 + tk_tb_l_a_NAME + 32], 0
    jne tk_tb_global_contract_fail
    lea rsi, [r12 + tk_tb_l_a_NAME + 32]
    mov edx, 4096
    mov r10d, 4095
    lea r8, [r12 + tk_tb_l_a_STATX]
    mov eax, 332
    syscall
    test rax, rax
    js tk_tb_l_a_effect_error
    jmp tk_tb_l_a_acknowledge
tk_tb_l_a_statat_effect:
    cmp qword ptr [r12 + 8], 52
    jne tk_tb_global_contract_fail
    call tk_tb_l_a_anchor_live
    cmp qword ptr [r14 + 32], tk_tb_l_a_STAT
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 40], 144
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 48], 0
    jne tk_tb_global_contract_fail
    cmp byte ptr [r12 + tk_tb_l_a_NAME + 32], 0
    jne tk_tb_global_contract_fail
    lea rsi, [r12 + tk_tb_l_a_NAME + 32]
    lea rdx, [r12 + tk_tb_l_a_STAT]
    mov r10d, 4096
    mov eax, 262
    syscall
    test rax, rax
    js tk_tb_l_a_effect_error
    jmp tk_tb_l_a_acknowledge
tk_tb_l_a_metadata_probe_admit:
    mov rax, [r14 + 24]
    or rax, [r14 + 32]
    or rax, [r14 + 40]
    or rax, [r14 + 48]
    jnz tk_tb_global_contract_fail
    xor edi, edi
    xor esi, esi
    xor edx, edx
    ret
tk_tb_l_a_statx_probe_effect:
    cmp qword ptr [r12 + 8], 53
    jne tk_tb_global_contract_fail
    call tk_tb_l_a_metadata_probe_admit
    mov r10d, 4095
    xor r8d, r8d
    mov eax, 332
    syscall
    test rax, rax
    js tk_tb_l_a_effect_error
    jmp tk_tb_l_a_acknowledge
tk_tb_l_a_statat_probe_effect:
    cmp qword ptr [r12 + 8], 54
    jne tk_tb_global_contract_fail
    call tk_tb_l_a_metadata_probe_admit
    lea rdx, [r12 + tk_tb_l_a_STAT]
    xor r10d, r10d
    mov eax, 262
    syscall
    test rax, rax
    js tk_tb_l_a_effect_error
    jmp tk_tb_l_a_acknowledge
tk_tb_l_a_named_effect:
    cmp qword ptr [r14 + 24], 0
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 48], tk_tb_l_a_STAT
    jne tk_tb_global_contract_fail
    call tk_tb_l_a_fixed_name
    mov rdi, [r15 + 128]
    lea rdx, [r12 + tk_tb_l_a_STAT]
    mov r10d, 256
    mov eax, 262
    syscall
    test rax, rax
    js tk_tb_l_a_effect_error
    jmp tk_tb_l_a_acknowledge
tk_tb_l_a_uid_effect:
    cmp qword ptr [r14 + 24], 0
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 32], tk_tb_l_a_STAT + 144
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 40], 8
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 48], 0
    jne tk_tb_global_contract_fail
    mov eax, 107
    syscall
    mov [r12 + tk_tb_l_a_STAT + 144], rax
    jmp tk_tb_l_a_acknowledge
tk_tb_l_a_read_effect:
    call tk_tb_l_a_anchor_live
    cmp qword ptr [r12 + 8], 5
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 48], 0
    jne tk_tb_global_contract_fail
    mov rax, [r12 + 88]
    cmp rax, 2048
    ja tk_tb_global_contract_fail
    lea rsi, [rax + tk_tb_l_a_READ_BYTES]
    cmp rsi, [r14 + 32]
    jne tk_tb_global_contract_fail
    mov edx, 2049
    sub rdx, rax
    cmp rdx, [r14 + 40]
    jne tk_tb_global_contract_fail
    add rsi, r12
    xor eax, eax
    syscall
    jmp tk_tb_l_a_value_effect
tk_tb_l_a_pread_effect:
    call tk_tb_l_a_anchor_live
    cmp qword ptr [r12 + 8], 14
    jne tk_tb_global_contract_fail
    mov r10, [r12 + 88]
    mov rdx, [r12 + 96]
    cmp rdx, 2048
    ja tk_tb_global_contract_fail
    cmp r10, rdx
    jae tk_tb_global_contract_fail
    sub rdx, r10
    cmp rdx, [r14 + 40]
    jne tk_tb_global_contract_fail
    cmp r10, [r14 + 48]
    jne tk_tb_global_contract_fail
    lea rsi, [r10 + tk_tb_l_a_READ_BYTES]
    cmp rsi, [r14 + 32]
    jne tk_tb_global_contract_fail
    add rsi, r12
    mov eax, 17
    syscall
    jmp tk_tb_l_a_value_effect
tk_tb_l_a_close_effect:
    call tk_tb_l_a_anchor_live
    mov rax, [r14 + 32]
    or rax, [r14 + 40]
    or rax, [r14 + 48]
    jnz tk_tb_global_contract_fail
    mov qword ptr [r15 + 136], -1
    mov eax, 3
    syscall
    test rax, rax
    js tk_tb_l_a_effect_error
    jmp tk_tb_l_a_acknowledge
tk_tb_l_a_json_effect:
    cmp qword ptr [r12 + 8], 8
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 24], 0
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 32], tk_tb_l_a_CHILD_REQUEST
    jne tk_tb_global_contract_fail
    mov rsi, [r14 + 40]
    cmp rsi, 24
    jb tk_tb_global_contract_fail
    cmp rsi, 2072
    ja tk_tb_global_contract_fail
    cmp qword ptr [r14 + 48], tk_tb_l_a_CHILD_REPLY
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 56], 256
    jne tk_tb_global_contract_fail
    lea rdi, [r12 + tk_tb_l_a_CHILD_REQUEST]
    lea rdx, [r12 + tk_tb_l_a_CHILD_REPLY]
    mov ecx, 256
    lea r8, [r15 + tk_tb_l_a_JSON_WORK]
    mov r9d, 1048576
    call qword ptr [rip + tk_ticket_backend_json_image]
    mov ecx, eax
    cmp rax, rcx
    jne tk_tb_global_contract_fail
    mov [r14 + 72], rax
    jmp tk_tb_l_a_acknowledge
tk_tb_l_a_value_effect:
    test rax, rax
    js tk_tb_l_a_effect_error
    mov [r14 + 72], rax
    jmp tk_tb_l_a_acknowledge
tk_tb_l_a_effect_error:
    cmp rax, -4095
    jb tk_tb_global_contract_fail
    neg rax
    mov [r14 + 80], rax
tk_tb_l_a_acknowledge:
    mov rax, [r14 + 8]
    mov [r14 + 64], rax
    jmp tk_tb_l_a_resume_anchor
tk_tb_l_a_owner_result:
    cmp qword ptr [r12 + 8], 0
    jne tk_tb_global_contract_fail
    mov rcx, [r12 + 48]
    cmp rcx, 1
    ja tk_tb_global_contract_fail
    test rcx, rcx
    jz tk_tb_l_a_no_anchor
    cmp qword ptr [r15 + 136], -1
    je tk_tb_global_contract_fail
    jmp tk_tb_l_a_slots_ok
tk_tb_l_a_no_anchor:
    cmp qword ptr [r15 + 136], -1
    jne tk_tb_global_contract_fail
tk_tb_l_a_slots_ok:
    cmp eax, 64
    jb tk_tb_global_contract_fail
    cmp eax, 2368
    ja tk_tb_global_contract_fail
    lea rdi, [r13 + tk_tb_l_MAIN_OWNER + tk_tb_l_M_REPLY]
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

tk_tb_shared_namespace_entry:
    mov rax, [r15 + 4000]
    mov rax, [rax + tk_tb_I_GLOBAL]
    mov rax, [rax + tk_tb_G_NAMESPACE]
    mov qword ptr [rax + 4008], -1
    jmp tk_tb_shared_namespace_borrow_ready
tk_tb_borrowed_hot_namespace_entry:
    cmp rsi, 32
    jne tk_tb_global_contract_fail
    cmp qword ptr [rdi + 8], 1
    jne tk_tb_global_contract_fail
    cmp qword ptr [rdi + 16], 0
    jne tk_tb_global_contract_fail
    test rcx, rcx
    js tk_tb_global_contract_fail
    mov rax, [r15 + 4000]
    cmp [rax + tk_tb_I_GLOBAL], rax
    jne tk_tb_global_contract_fail
    xor r8d, r8d
tk_tb_shared_namespace_hot_owner:
    cmp [rax + tk_tb_G_HOT_FDS + r8*8], rcx
    je tk_tb_shared_namespace_hot_owned
    inc r8d
    cmp r8d, 17
    jb tk_tb_shared_namespace_hot_owner
    jmp tk_tb_global_contract_fail
tk_tb_shared_namespace_hot_owned:
    mov rax, [rax + tk_tb_G_NAMESPACE]
    mov [rax + 4008], rcx
tk_tb_shared_namespace_borrow_ready:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp, 24
    mov [rsp], rdi
    mov [rsp + 8], rdx
    mov [rsp + 16], rsi
    mov rax, [r15 + 4000]
    mov r15, [rax + tk_tb_I_GLOBAL]
    mov r15, [r15 + tk_tb_G_NAMESPACE]
    mov [r15 + 4000], rax
    mov r13, r15
    lea r12, [r15 + 1048576]
    lea rdi, [r15 + 4096]
    mov esi, 4096
    mov edx, 3
    mov eax, 10
    syscall
    test rax, rax
    jnz tk_tb_global_io_fail
    lea rdi, [r15 + 4096]
    mov rsi, [rsp]
    mov rcx, [rsp + 16]
    mov [r15 + 24], rcx
    rep movsb
    lea rdi, [r15 + 4096]
    mov esi, 4096
    mov edx, 1
    mov eax, 10
    syscall
    test rax, rax
    jnz tk_tb_global_io_fail
    cmp qword ptr [r15 + 24], 32
    je tk_tb_ns_frame_size_ok
    cmp qword ptr [r15 + 24], 2096
    jne tk_tb_global_contract_fail
tk_tb_ns_frame_size_ok:
    mov rbx, [r15 + 4000]
    mov rax, [r15 + 4104]
    cmp rax, 1
    je tk_tb_ns_flat_borrow
    cmp rax, 2
    je tk_tb_ns_flat_borrow
    cmp rax, 5
    je tk_tb_ns_layout_borrow
    cmp rax, 6
    je tk_tb_ns_enter
    cmp rax, 7
    jne tk_tb_global_contract_fail
    jmp tk_tb_ns_enter
tk_tb_ns_flat_borrow:
    cmp qword ptr [r15 + 4112], 0
    jne tk_tb_global_contract_fail
    cmp qword ptr [r15 + tk_tb_ns_FDS], -1
    jne tk_tb_global_contract_fail
    mov rax, [r15 + 4008]
    test rax, rax
    jns tk_tb_ns_flat_root_ready
    mov rax, [rbx + tk_tb_L_BASE + 136]
tk_tb_ns_flat_root_ready:
    test rax, rax
    js tk_tb_global_contract_fail
    mov [r15 + tk_tb_ns_FDS], rax
    jmp tk_tb_ns_enter
tk_tb_ns_layout_borrow:
    cmp qword ptr [r15 + 4112], 258
    jne tk_tb_global_contract_fail
    mov ecx, 1
tk_tb_ns_bind_layout_next:
    cmp [r15 + 4096 + 24 + rcx*8], rcx
    jne tk_tb_global_contract_fail
    cmp qword ptr [r15 + tk_tb_ns_FDS + rcx*8], -1
    jne tk_tb_global_contract_fail
    mov rax, [rbx + tk_tb_ROOT_FDS + 8 + rcx*8]
    test rax, rax
    js tk_tb_global_contract_fail
    mov [r15 + tk_tb_ns_FDS + rcx*8], rax
    inc ecx
    cmp ecx, 259
    jb tk_tb_ns_bind_layout_next
tk_tb_ns_enter:
    jmp tk_tb_ns_resume_namespace
.equ tk_tb_ns_INPUT, 4096
.equ tk_tb_ns_OUTPUT, 8192
.equ tk_tb_ns_FDS, 16384
.equ tk_tb_ns_OWNER, 1048576
.equ tk_tb_ns_GUARD, 9437184
.equ tk_tb_ns_MAP_SIZE, 9441280
.equ tk_tb_ns_FDS_COUNT, 33794
.equ tk_tb_ns_SET_SLOT, 4880
.equ tk_tb_ns_SET_TABLE, 2097152
.equ tk_tb_ns_SET_STRIDE, 16640
.equ tk_tb_ns_PHASE, 4104
.equ tk_tb_ns_SEQUENCE, 4112
.equ tk_tb_ns_OPERATION, 4136
.equ tk_tb_ns_DIRECTORY, 4144
.equ tk_tb_ns_WATCHER, 4152
.equ tk_tb_ns_SCAN_LIVE, 4288
.equ tk_tb_ns_SCAN_CAPACITY, 4304
.equ tk_tb_ns_CANDIDATE, 4328
.equ tk_tb_ns_ACTION, 4352
.equ tk_tb_ns_STAT, 6144
.equ tk_tb_ns_STATX, 6400
.equ tk_tb_ns_NAME, 7040
.equ tk_tb_ns_EVENTS, 65536
.equ tk_tb_ns_DIRENTS, 131072
tk_tb_ns_resume_namespace:
    lea rdi, [r15 + tk_tb_ns_INPUT]
    mov rsi, [r15 + 24]
    lea rdx, [r15 + tk_tb_ns_OUTPUT]
    mov ecx, 4096
    mov r8, r12
    mov r9d, 8388608
    call qword ptr [rip + tk_ticket_backend_namespace_image]
    mov ecx, eax
    cmp rax, rcx
    jne tk_tb_global_contract_fail
    cmp eax, 0xfffffff0
    jne tk_tb_ns_owner_result
    lea r14, [r12 + tk_tb_ns_ACTION]
    mov rax, 0x3130304156534e48
    cmp [r14], rax
    jne tk_tb_global_contract_fail
    mov rax, [r15 + 16]
    inc rax
    jz tk_tb_global_contract_fail
    cmp [r14 + 8], rax
    jne tk_tb_global_contract_fail
    cmp [r12 + tk_tb_ns_SEQUENCE], rax
    jne tk_tb_global_contract_fail
    mov [r15 + 16], rax
    mov rax, [r14 + 56]
    or rax, [r14 + 64]
    or rax, [r14 + 72]
    or rax, [r14 + 80]
    or rax, [r14 + 88]
    jnz tk_tb_global_contract_fail
    mov rax, [r14 + 16]
    cmp rax, 1
    je tk_tb_ns_bind_effect
    cmp rax, 2
    je tk_tb_ns_old_stat_effect
    cmp rax, 3
    je tk_tb_ns_statx_effect
    cmp rax, 4
    je tk_tb_ns_statat_effect
    cmp rax, 5
    je tk_tb_ns_statx_probe_effect
    cmp rax, 6
    je tk_tb_ns_statat_probe_effect
    cmp rax, 7
    je tk_tb_ns_init_effect
    cmp rax, 8
    je tk_tb_ns_events_effect
    cmp rax, 9
    je tk_tb_ns_duplicate_effect
    cmp rax, 10
    je tk_tb_ns_add_watch_effect
    cmp rax, 11
    je tk_tb_ns_remove_watch_effect
    cmp rax, 12
    je tk_tb_ns_close_pin_effect
    cmp rax, 13
    je tk_tb_ns_scan_open_effect
    cmp rax, 14
    je tk_tb_ns_flags_effect
    cmp rax, 15
    je tk_tb_ns_scan_stat_effect
    cmp rax, 16
    je tk_tb_ns_directory_effect
    cmp rax, 17
    je tk_tb_ns_close_scan_effect
    cmp rax, 18
    je tk_tb_ns_close_borrow_effect
    cmp rax, 19
    je tk_tb_ns_retain_borrow_effect
    cmp rax, 20
    je tk_tb_ns_close_set_event_effect
    jmp tk_tb_global_contract_fail
tk_tb_ns_zero_span:
    mov rax, [r14 + 32]
    or rax, [r14 + 40]
    or rax, [r14 + 48]
    jnz tk_tb_global_contract_fail
    ret
tk_tb_ns_borrow_index:
    mov rcx, [r14 + 24]
    cmp rcx, 258
    ja tk_tb_global_contract_fail
    cmp rcx, [r12 + tk_tb_ns_DIRECTORY]
    jne tk_tb_global_contract_fail
    ret
tk_tb_ns_borrow_live:
    call tk_tb_ns_borrow_index
    mov rdi, [r15 + rcx*8 + tk_tb_ns_FDS]
    test rdi, rdi
    js tk_tb_global_contract_fail
    ret
tk_tb_ns_set_admit:
    mov rax, [r12 + tk_tb_ns_SET_SLOT]
    cmp rax, 128
    jae tk_tb_global_contract_fail
    imul rax, tk_tb_ns_SET_STRIDE
    add rax, tk_tb_ns_SET_TABLE
    cmp rax, [r12 + tk_tb_ns_WATCHER]
    jne tk_tb_global_contract_fail
    mov rax, [r12 + tk_tb_ns_OPERATION]
    cmp rax, 5
    jb tk_tb_global_contract_fail
    cmp rax, 7
    ja tk_tb_global_contract_fail
    ret
tk_tb_ns_event_index:
    mov ecx, 259
    cmp qword ptr [r12 + tk_tb_ns_WATCHER], 8192
    je tk_tb_ns_event_normal
    cmp qword ptr [r12 + tk_tb_ns_WATCHER], 24576
    jne tk_tb_ns_event_set
    inc ecx
    cmp qword ptr [r12 + tk_tb_ns_OPERATION], 2
    jne tk_tb_global_contract_fail
    jmp tk_tb_ns_event_index_ok
tk_tb_ns_event_normal:
    cmp qword ptr [r12 + tk_tb_ns_OPERATION], 1
    jne tk_tb_global_contract_fail
    jmp tk_tb_ns_event_index_ok
tk_tb_ns_event_set:
    call tk_tb_ns_set_admit
    mov rcx, [r12 + tk_tb_ns_SET_SLOT]
    add rcx, 262
tk_tb_ns_event_index_ok:
    cmp rcx, [r14 + 24]
    jne tk_tb_global_contract_fail
    ret
tk_tb_ns_event_live:
    call tk_tb_ns_event_index
    mov rdi, [r15 + rcx*8 + tk_tb_ns_FDS]
    test rdi, rdi
    js tk_tb_global_contract_fail
    ret
tk_tb_ns_pin_index:
    call tk_tb_ns_pin_bounds
    mov rcx, [r14 + 24]
    cmp rcx, rdx
    jb tk_tb_global_contract_fail
    cmp rcx, r8
    jae tk_tb_global_contract_fail
    ret
tk_tb_ns_pin_bounds:
    mov edx, 512
    cmp qword ptr [r12 + tk_tb_ns_WATCHER], 8192
    je tk_tb_ns_pin_pool
    cmp qword ptr [r12 + tk_tb_ns_WATCHER], 24576
    jne tk_tb_ns_pin_set
    mov edx, 641
tk_tb_ns_pin_pool:
    lea r8, [rdx + 129]
    ret
tk_tb_ns_pin_set:
    call tk_tb_ns_set_admit
    mov rdx, [r12 + tk_tb_ns_SET_SLOT]
    imul rdx, 258
    add rdx, 770
    lea r8, [rdx + 258]
    ret
tk_tb_ns_scan_live:
    cmp qword ptr [r14 + 24], 261
    jne tk_tb_global_contract_fail
    mov rdi, [r15 + tk_tb_ns_FDS + 261*8]
    test rdi, rdi
    js tk_tb_global_contract_fail
    ret
tk_tb_ns_bind_effect:
    cmp qword ptr [r12 + tk_tb_ns_PHASE], 1
    jne tk_tb_global_contract_fail
    call tk_tb_ns_borrow_index
    cmp qword ptr [r14 + 32], tk_tb_ns_NAME
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 48], 0
    jne tk_tb_global_contract_fail
    test rcx, rcx
    jnz tk_tb_ns_bind_name
    cmp qword ptr [r14 + 40], 1
    jne tk_tb_global_contract_fail
    cmp qword ptr [r12 + tk_tb_ns_NAME], 46
    jne tk_tb_global_contract_fail
    jmp tk_tb_ns_bind_ready
tk_tb_ns_bind_name:
    cmp qword ptr [r14 + 40], 4
    jne tk_tb_global_contract_fail
    cmp byte ptr [r12 + tk_tb_ns_NAME], 100
    jne tk_tb_global_contract_fail
    cmp dword ptr [r12 + tk_tb_ns_NAME + 4], 0
    jne tk_tb_global_contract_fail
    mov eax, ecx
    xor edx, edx
    mov ebx, 100
    div ebx
    add eax, 48
    cmp al, [r12 + tk_tb_ns_NAME + 1]
    jne tk_tb_global_contract_fail
    mov eax, edx
    xor edx, edx
    mov ebx, 10
    div ebx
    add eax, 48
    add edx, 48
    cmp al, [r12 + tk_tb_ns_NAME + 2]
    jne tk_tb_global_contract_fail
    cmp dl, [r12 + tk_tb_ns_NAME + 3]
    jne tk_tb_global_contract_fail
tk_tb_ns_bind_ready:
    cmp qword ptr [r15 + rcx*8 + tk_tb_ns_FDS], -1
    jne tk_tb_ns_bind_existing
    jmp tk_tb_global_contract_fail
tk_tb_ns_bind_existing:
    mov [r14 + 72], rcx
    jmp tk_tb_ns_acknowledge
tk_tb_ns_stat_span:
    cmp qword ptr [r14 + 32], tk_tb_ns_STAT
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 40], 144
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 48], 0
    jne tk_tb_global_contract_fail
    lea rsi, [r12 + tk_tb_ns_STAT]
    ret
tk_tb_ns_old_stat_effect:
    cmp qword ptr [r12 + tk_tb_ns_PHASE], 50
    jne tk_tb_global_contract_fail
    call tk_tb_ns_borrow_live
    call tk_tb_ns_stat_span
    mov eax, 5
    syscall
    jmp tk_tb_ns_zero_effect
tk_tb_ns_statx_effect:
    cmp qword ptr [r12 + tk_tb_ns_PHASE], 51
    jne tk_tb_global_contract_fail
    call tk_tb_ns_borrow_live
    cmp qword ptr [r14 + 32], tk_tb_ns_STATX
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 40], 256
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 48], 0
    jne tk_tb_global_contract_fail
    mov byte ptr [r15 + 512], 0
    lea rsi, [r15 + 512]
    mov edx, 4096
    mov r10d, 4095
    lea r8, [r12 + tk_tb_ns_STATX]
    mov eax, 332
    syscall
    jmp tk_tb_ns_zero_effect
tk_tb_ns_statat_effect:
    cmp qword ptr [r12 + tk_tb_ns_PHASE], 52
    jne tk_tb_global_contract_fail
    call tk_tb_ns_borrow_live
    call tk_tb_ns_stat_span
    mov byte ptr [r15 + 512], 0
    lea rsi, [r15 + 512]
    lea rdx, [r12 + tk_tb_ns_STAT]
    mov r10d, 4096
    mov eax, 262
    syscall
    jmp tk_tb_ns_zero_effect
tk_tb_ns_probe_admit:
    cmp qword ptr [r14 + 24], 0
    jne tk_tb_global_contract_fail
    call tk_tb_ns_zero_span
    xor edi, edi
    xor esi, esi
    xor edx, edx
    ret
tk_tb_ns_statx_probe_effect:
    cmp qword ptr [r12 + tk_tb_ns_PHASE], 53
    jne tk_tb_global_contract_fail
    call tk_tb_ns_probe_admit
    mov r10d, 4095
    xor r8d, r8d
    mov eax, 332
    syscall
    jmp tk_tb_ns_zero_effect
tk_tb_ns_statat_probe_effect:
    cmp qword ptr [r12 + tk_tb_ns_PHASE], 54
    jne tk_tb_global_contract_fail
    call tk_tb_ns_probe_admit
    lea rdx, [r12 + tk_tb_ns_STAT]
    xor r10d, r10d
    mov eax, 262
    syscall
    jmp tk_tb_ns_zero_effect
tk_tb_ns_init_effect:
    cmp qword ptr [r12 + tk_tb_ns_PHASE], 10
    jne tk_tb_global_contract_fail
    call tk_tb_ns_zero_span
    call tk_tb_ns_event_index
    cmp qword ptr [r15 + rcx*8 + tk_tb_ns_FDS], -1
    jne tk_tb_global_contract_fail
    mov edi, 0x80800
    mov eax, 294
    syscall
    jmp tk_tb_ns_install_descriptor
tk_tb_ns_events_effect:
    cmp qword ptr [r12 + tk_tb_ns_PHASE], 11
    jne tk_tb_global_contract_fail
    call tk_tb_ns_event_live
    cmp qword ptr [r14 + 32], tk_tb_ns_EVENTS
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 40], 16384
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 48], 0
    jne tk_tb_global_contract_fail
    lea rsi, [r12 + tk_tb_ns_EVENTS]
    mov edx, 16384
    xor eax, eax
    syscall
    jmp tk_tb_ns_value_effect
tk_tb_ns_duplicate_effect:
    cmp qword ptr [r12 + tk_tb_ns_PHASE], 15
    jne tk_tb_global_contract_fail
    call tk_tb_ns_pin_index
    cmp qword ptr [r15 + rcx*8 + tk_tb_ns_FDS], -1
    jne tk_tb_global_contract_fail
    mov rax, [r14 + 32]
    or rax, [r14 + 40]
    jnz tk_tb_global_contract_fail
    mov rax, [r14 + 48]
    cmp rax, [r12 + tk_tb_ns_DIRECTORY]
    jne tk_tb_global_contract_fail
    cmp rax, 258
    ja tk_tb_global_contract_fail
    mov rdi, [r15 + rax*8 + tk_tb_ns_FDS]
    test rdi, rdi
    js tk_tb_global_contract_fail
    mov esi, 1030
    mov edx, 3 /* Rust File::try_clone preserves standard descriptor slots. */
    mov eax, 72
    syscall
    jmp tk_tb_ns_install_descriptor
tk_tb_ns_add_watch_effect:
    cmp qword ptr [r12 + tk_tb_ns_PHASE], 16
    jne tk_tb_global_contract_fail
    call tk_tb_ns_event_live
    cmp qword ptr [r14 + 32], 0
    jne tk_tb_global_contract_fail
    mov ebx, 16781248
    cmp qword ptr [r12 + tk_tb_ns_OPERATION], 1
    je tk_tb_ns_watch_flags_ok
    or ebx, 14
tk_tb_ns_watch_flags_ok:
    cmp rbx, [r14 + 40]
    jne tk_tb_global_contract_fail
    push rdi
    call tk_tb_ns_pin_bounds
    pop rdi
    mov rax, [r14 + 48]
    cmp rax, rdx
    jb tk_tb_global_contract_fail
    cmp rax, r8
    jae tk_tb_global_contract_fail
    mov rax, [r15 + rax*8 + tk_tb_ns_FDS]
    test rax, rax
    js tk_tb_global_contract_fail
    lea r8, [r15 + 640]
    mov byte ptr [r8], 0
    mov r9d, 10
tk_tb_ns_fd_digits:
    xor edx, edx
    div r9
    add dl, 48
    dec r8
    mov [r8], dl
    test rax, rax
    jnz tk_tb_ns_fd_digits
    mov rax, 0x65732f636f72702f
    mov [r15 + 576], rax
    mov dword ptr [r15 + 584], 0x662f666c
    mov word ptr [r15 + 588], 0x2f64
    lea rsi, [r15 + 576]
    lea rdx, [r15 + 590]
tk_tb_ns_copy_digits:
    mov al, [r8]
    mov [rdx], al
    inc r8
    inc rdx
    test al, al
    jnz tk_tb_ns_copy_digits
    mov edx, ebx
    mov eax, 254
    syscall
    jmp tk_tb_ns_value_effect
tk_tb_ns_remove_watch_effect:
    mov rax, [r12 + tk_tb_ns_PHASE]
    cmp rax, 13
    je tk_tb_ns_remove_admit
    cmp rax, 17
    jne tk_tb_global_contract_fail
tk_tb_ns_remove_admit:
    call tk_tb_ns_event_live
    mov rax, [r14 + 32]
    or rax, [r14 + 40]
    jnz tk_tb_global_contract_fail
    mov rsi, [r14 + 48]
    cmp rsi, 2147483647
    ja tk_tb_global_contract_fail
    mov eax, 255
    syscall
    jmp tk_tb_ns_zero_effect
tk_tb_ns_close_pin_effect:
    mov rax, [r12 + tk_tb_ns_PHASE]
    cmp rax, 14
    je tk_tb_ns_close_pin_admit
    cmp rax, 18
    je tk_tb_ns_close_pin_admit
    cmp rax, 19
    je tk_tb_ns_close_pin_admit
    cmp rax, 202
    jne tk_tb_global_contract_fail
tk_tb_ns_close_pin_admit:
    call tk_tb_ns_zero_span
    call tk_tb_ns_pin_index
    jmp tk_tb_ns_close_slot
tk_tb_ns_scan_open_effect:
    cmp qword ptr [r12 + tk_tb_ns_PHASE], 100
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 24], 261
    jne tk_tb_global_contract_fail
    cmp qword ptr [r15 + tk_tb_ns_FDS + 261*8], -1
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 32], tk_tb_ns_NAME
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 40], 1
    jne tk_tb_global_contract_fail
    cmp qword ptr [r12 + tk_tb_ns_NAME], 46
    jne tk_tb_global_contract_fail
    mov rax, [r14 + 48]
    cmp rax, [r12 + tk_tb_ns_DIRECTORY]
    jne tk_tb_global_contract_fail
    cmp rax, 258
    ja tk_tb_global_contract_fail
    mov rdi, [r15 + rax*8 + tk_tb_ns_FDS]
    test rdi, rdi
    js tk_tb_global_contract_fail
    lea rsi, [r12 + tk_tb_ns_NAME]
    mov edx, 0x90000
    xor r10d, r10d
    mov eax, 257
    syscall
    jmp tk_tb_ns_install_descriptor
tk_tb_ns_flags_effect:
    cmp qword ptr [r12 + tk_tb_ns_PHASE], 101
    jne tk_tb_global_contract_fail
    call tk_tb_ns_zero_span
    call tk_tb_ns_scan_live
    mov esi, 3
    xor edx, edx
    mov eax, 72
    syscall
    jmp tk_tb_ns_value_effect
tk_tb_ns_scan_stat_effect:
    cmp qword ptr [r12 + tk_tb_ns_PHASE], 102
    jne tk_tb_global_contract_fail
    call tk_tb_ns_scan_live
    call tk_tb_ns_stat_span
    mov eax, 5
    syscall
    jmp tk_tb_ns_zero_effect
tk_tb_ns_directory_effect:
    cmp qword ptr [r12 + tk_tb_ns_PHASE], 103
    jne tk_tb_global_contract_fail
    call tk_tb_ns_scan_live
    cmp qword ptr [r14 + 32], tk_tb_ns_DIRENTS
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 48], 0
    jne tk_tb_global_contract_fail
    mov rdx, [r14 + 40]
    cmp rdx, 32768
    jb tk_tb_global_contract_fail
    cmp rdx, 1048576
    ja tk_tb_global_contract_fail
    cmp rdx, [r12 + tk_tb_ns_SCAN_CAPACITY]
    jne tk_tb_global_contract_fail
    lea rsi, [r12 + tk_tb_ns_DIRENTS]
    mov eax, 217
    syscall
    jmp tk_tb_ns_value_effect
tk_tb_ns_close_scan_effect:
    mov rax, [r12 + tk_tb_ns_PHASE]
    cmp rax, 104
    je tk_tb_ns_close_scan_admit
    cmp rax, 105
    jne tk_tb_global_contract_fail
tk_tb_ns_close_scan_admit:
    call tk_tb_ns_zero_span
    call tk_tb_ns_scan_live
    mov ecx, 261
    jmp tk_tb_ns_close_slot
tk_tb_ns_close_borrow_effect:
    cmp qword ptr [r12 + tk_tb_ns_PHASE], 2
    jne tk_tb_global_contract_fail
    call tk_tb_ns_zero_span
    call tk_tb_ns_borrow_index
    test rcx, rcx
    jz tk_tb_global_contract_fail
    cmp qword ptr [r15 + rcx*8 + tk_tb_ns_FDS], -1
    je tk_tb_ns_acknowledge
tk_tb_ns_close_slot:
    mov rdi, [r15 + rcx*8 + tk_tb_ns_FDS]
    test rdi, rdi
    js tk_tb_global_contract_fail
    mov qword ptr [r15 + rcx*8 + tk_tb_ns_FDS], -1
    call tk_tb_ns_raw_descriptor_referenced
    test eax, eax
    jnz tk_tb_ns_acknowledge
    mov eax, 3
    syscall
    jmp tk_tb_ns_zero_effect
tk_tb_ns_raw_descriptor_referenced:
    jmp tk_tb_shared_referenced
tk_tb_ns_retain_borrow_effect:
    cmp qword ptr [r12 + tk_tb_ns_PHASE], 15
    jne tk_tb_global_contract_fail
    cmp qword ptr [r12 + tk_tb_ns_OPERATION], 5
    jne tk_tb_global_contract_fail
    call tk_tb_ns_set_admit
    call tk_tb_ns_pin_index
    cmp qword ptr [r15 + rcx*8 + tk_tb_ns_FDS], -1
    jne tk_tb_global_contract_fail
    mov rax, [r14 + 32]
    or rax, [r14 + 40]
    jnz tk_tb_global_contract_fail
    mov rax, [r14 + 48]
    cmp rax, 258
    ja tk_tb_global_contract_fail
    cmp rax, [r12 + tk_tb_ns_DIRECTORY]
    jne tk_tb_global_contract_fail
    mov rax, [r15 + rax*8 + tk_tb_ns_FDS]
    test rax, rax
    js tk_tb_global_contract_fail
    mov [r15 + rcx*8 + tk_tb_ns_FDS], rax
    mov [r14 + 72], rcx
    jmp tk_tb_ns_acknowledge
tk_tb_ns_close_set_event_effect:
    cmp qword ptr [r12 + tk_tb_ns_PHASE], 201
    jne tk_tb_global_contract_fail
    call tk_tb_ns_zero_span
    call tk_tb_ns_set_admit
    call tk_tb_ns_event_live
    jmp tk_tb_ns_close_slot
tk_tb_ns_install_descriptor:
    test rax, rax
    js tk_tb_ns_effect_error
    cmp rax, 2147483647
    ja tk_tb_global_contract_fail
    mov rcx, [r14 + 24]
    cmp rcx, tk_tb_ns_FDS_COUNT
    jae tk_tb_global_contract_fail
    cmp qword ptr [r15 + rcx*8 + tk_tb_ns_FDS], -1
    jne tk_tb_global_contract_fail
    mov [r15 + rcx*8 + tk_tb_ns_FDS], rax
    mov [r14 + 72], rcx
    jmp tk_tb_ns_acknowledge
tk_tb_ns_zero_effect:
    test rax, rax
    js tk_tb_ns_effect_error
    jnz tk_tb_global_contract_fail
    jmp tk_tb_ns_acknowledge
tk_tb_ns_value_effect:
    test rax, rax
    js tk_tb_ns_effect_error
    mov [r14 + 72], rax
    jmp tk_tb_ns_acknowledge
tk_tb_ns_effect_error:
    cmp rax, -4095
    jb tk_tb_global_contract_fail
    neg rax
    mov [r14 + 80], rax
tk_tb_ns_acknowledge:
    mov rax, [r14 + 8]
    mov [r14 + 64], rax
    jmp tk_tb_ns_resume_namespace
tk_tb_ns_owner_result:
    cmp eax, 72
    jne tk_tb_global_contract_fail
    cmp qword ptr [r12 + 4104], 0
    jne tk_tb_global_contract_fail
    cmp qword ptr [r12 + 4288], 0
    jne tk_tb_global_contract_fail
    cmp qword ptr [r12 + 4328], 0
    jne tk_tb_global_contract_fail
    cmp qword ptr [r15 + tk_tb_ns_FDS + 261*8], -1
    jne tk_tb_global_contract_fail
    mov ebx, eax
    lea rdi, [r15 + tk_tb_ns_FDS]
    mov ecx, 259
    mov rax, -1
    rep stosq
    mov eax, ebx
    mov ebx, eax
    mov rdi, [rsp + 8]
    lea rsi, [r15 + 8192]
    mov ecx, eax
    rep movsb
    mov eax, ebx
    add rsp, 24
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

tk_tb_metadata_entry:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp, 24
    mov [rsp], rdi
    mov [rsp + 8], rdx
    mov [rsp + 16], rsi
    mov rax, [r15 + 4000]
    lea r15, [rax + tk_tb_M_BASE]
    mov r13, r15
    lea r12, [r15 + 65536]
    lea rdi, [r15 + 4096]
    mov esi, 4096
    mov edx, 3
    mov eax, 10
    syscall
    test rax, rax
    jnz tk_tb_global_io_fail
    lea rdi, [r15 + 4096]
    mov rsi, [rsp]
    mov rcx, [rsp + 16]
    mov [r15 + 24], rcx
    rep movsb
    lea rdi, [r15 + 4096]
    mov esi, 4096
    mov edx, 1
    mov eax, 10
    syscall
    test rax, rax
    jnz tk_tb_global_io_fail
    mov rax, [r15 + 4000]
    mov rcx, [r14 + 24]
    cmp rcx, 266
    ja tk_tb_global_contract_fail
    mov rax, [rax + tk_tb_ROOT_FDS + rcx*8]
    test rax, rax
    js tk_tb_global_contract_fail
    mov [r15 + 128], rax
    jmp tk_tb_m_resume_owner
.equ tk_tb_m_INPUT, 4096
.equ tk_tb_m_OUTPUT, 8192
.equ tk_tb_m_OWNER, 65536
.equ tk_tb_m_JSON_WORK, 3211264
.equ tk_tb_m_GUARD, 4259840
.equ tk_tb_m_MAP_SIZE, 4263936
.equ tk_tb_m_ACTION, 256
.equ tk_tb_m_STAT, 1024
.equ tk_tb_m_STATX, 3072
.equ tk_tb_m_NAME, 4096
.equ tk_tb_m_LEGACY_NAME, 4160
.equ tk_tb_m_DOT, 4224
.equ tk_tb_m_CANDIDATE, 4352
.equ tk_tb_m_MAIN_REQUEST, 8192
.equ tk_tb_m_LEGACY_REQUEST, 73760
.equ tk_tb_m_CHILD_REPLY, 77824
.equ tk_tb_m_DIRENTS, 1048576
tk_tb_m_resume_owner:
    lea rdi, [r15 + tk_tb_m_INPUT]
    mov rsi, [r15 + 24]
    lea rdx, [r15 + tk_tb_m_OUTPUT]
    mov ecx, 8192
    mov r8, r12
    mov r9d, 3145728
    call qword ptr [rip + tk_ticket_backend_metadata_image]
    mov ecx, eax
    cmp rax, rcx
    jne tk_tb_global_contract_fail
    cmp eax, 0xfffffff0
    jne tk_tb_m_return
    lea r14, [r12 + tk_tb_m_ACTION]
    mov rax, 0x313030414d415248
    cmp [r14], rax
    jne tk_tb_global_contract_fail
    mov rax, [r15 + 16]
    inc rax
    jz tk_tb_global_contract_fail
    cmp [r14 + 8], rax
    jne tk_tb_global_contract_fail
    cmp [r12 + 16], rax
    jne tk_tb_global_contract_fail
    mov [r15 + 16], rax
    mov rax, [r14 + 64]
    or rax, [r14 + 72]
    or rax, [r14 + 80]
    or rax, [r14 + 88]
    jnz tk_tb_global_contract_fail
    mov rax, [r14 + 16]
    cmp rax, 100
    je tk_tb_m_json_effect
    cmp qword ptr [r14 + 56], 0
    jne tk_tb_global_contract_fail
    cmp rax, 1
    je tk_tb_m_open_effect
    cmp rax, 2
    je tk_tb_m_held_effect
    cmp rax, 4
    je tk_tb_m_read_effect
    cmp rax, 5
    je tk_tb_m_uid_effect
    cmp rax, 7
    je tk_tb_m_close_effect
    cmp rax, 8
    je tk_tb_m_statx_effect
    cmp rax, 9
    je tk_tb_m_statx_probe_effect
    cmp rax, 10
    je tk_tb_m_statat_effect
    cmp rax, 11
    je tk_tb_m_statat_probe_effect
    cmp rax, 12
    je tk_tb_m_scan_open_effect
    cmp rax, 13
    je tk_tb_m_duplicate_effect
    cmp rax, 14
    je tk_tb_m_flags_effect
    cmp rax, 15
    je tk_tb_m_directory_effect
    cmp rax, 16
    je tk_tb_m_candidate_open_effect
    cmp rax, 17
    je tk_tb_m_unlink_effect
    cmp rax, 18
    je tk_tb_m_sync_effect
    jmp tk_tb_global_contract_fail

tk_tb_m_live_slot:
    mov rcx, [r14 + 24]
    cmp rcx, 5
    ja tk_tb_global_contract_fail
    mov rdi, [r15 + rcx*8 + 128]
    test rdi, rdi
    js tk_tb_global_contract_fail
    ret
tk_tb_m_empty_slot:
    mov rcx, [r14 + 24]
    test rcx, rcx
    jz tk_tb_global_contract_fail
    cmp rcx, 5
    ja tk_tb_global_contract_fail
    cmp qword ptr [r15 + rcx*8 + 128], -1
    jne tk_tb_global_contract_fail
    ret
tk_tb_m_zero_span:
    mov rax, [r14 + 32]
    or rax, [r14 + 40]
    or rax, [r14 + 48]
    jnz tk_tb_global_contract_fail
    ret
tk_tb_m_root_name:
    cmp qword ptr [r14 + 48], 0
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 32], tk_tb_m_NAME
    jne tk_tb_global_contract_fail
    lea rdi, [r12 + tk_tb_m_NAME]
    cmp qword ptr [r12 + 40], 1
    je tk_tb_m_anchor_name
    cmp qword ptr [r12 + 40], 2
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 40], 30
    jne tk_tb_global_contract_fail
    lea rsi, [rip + tk_tb_m_intent_literal]
    mov ecx, 31
    jmp tk_tb_m_compare_name
tk_tb_m_anchor_name:
    cmp qword ptr [r14 + 40], 32
    jne tk_tb_global_contract_fail
    lea rsi, [rip + tk_tb_m_anchor_literal]
    mov ecx, 33
tk_tb_m_compare_name:
    repe cmpsb
    jne tk_tb_global_contract_fail
    ret
tk_tb_m_legacy_name:
    cmp qword ptr [r14 + 48], 0
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 32], tk_tb_m_LEGACY_NAME
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 40], 32
    jne tk_tb_global_contract_fail
    lea rdi, [r12 + tk_tb_m_LEGACY_NAME]
    lea rsi, [rip + tk_tb_m_legacy_literal]
    mov ecx, 33
    repe cmpsb
    jne tk_tb_global_contract_fail
    ret
tk_tb_m_open_effect:
    call tk_tb_m_empty_slot
    cmp qword ptr [r12 + 8], 1
    je tk_tb_m_open_main
    cmp qword ptr [r12 + 8], 10
    jne tk_tb_global_contract_fail
    cmp rcx, 2
    jne tk_tb_global_contract_fail
    call tk_tb_m_legacy_name
    lea rsi, [r12 + tk_tb_m_LEGACY_NAME]
    jmp tk_tb_m_open_readonly
tk_tb_m_open_main:
    cmp rcx, 1
    jne tk_tb_global_contract_fail
    call tk_tb_m_root_name
    lea rsi, [r12 + tk_tb_m_NAME]
tk_tb_m_open_readonly:
    mov rdi, [r15 + 128]
    mov edx, 0xa0800
    xor r10d, r10d
tk_tb_m_issue_open:
    mov eax, 257
    syscall
    test rax, rax
    js tk_tb_m_effect_error
    cmp rax, 0x7fffffff
    ja tk_tb_global_contract_fail
    mov rcx, [r14 + 24]
    mov [r15 + rcx*8 + 128], rax
    mov [r14 + 72], rcx
    jmp tk_tb_m_acknowledge
tk_tb_m_metadata_slot:
    call tk_tb_m_live_slot
    cmp rcx, [r12 + 128]
    jne tk_tb_global_contract_fail
    mov rax, [r12 + 136]
    cmp rax, 16
    je tk_tb_m_metadata_root
    cmp rax, 11
    je tk_tb_m_metadata_legacy
    cmp rax, 61
    je tk_tb_m_metadata_candidate
    cmp rax, 2
    je tk_tb_m_metadata_main
    cmp rax, 5
    je tk_tb_m_metadata_main
    cmp rax, 20
    je tk_tb_m_metadata_main
    cmp rax, 30
    jne tk_tb_global_contract_fail
tk_tb_m_metadata_main:
    cmp rcx, 1
    jne tk_tb_global_contract_fail
    ret
tk_tb_m_metadata_root:
    test rcx, rcx
    jnz tk_tb_global_contract_fail
    ret
tk_tb_m_metadata_legacy:
    cmp rcx, 2
    jne tk_tb_global_contract_fail
    ret
tk_tb_m_metadata_candidate:
    cmp rcx, 5
    jne tk_tb_global_contract_fail
    ret
tk_tb_m_stat_span:
    cmp qword ptr [r14 + 32], tk_tb_m_STAT
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 40], 144
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 48], 0
    jne tk_tb_global_contract_fail
    ret
tk_tb_m_held_effect:
    cmp qword ptr [r12 + 8], 43
    je tk_tb_m_stream_stat
    cmp qword ptr [r12 + 8], 50
    jne tk_tb_global_contract_fail
    call tk_tb_m_metadata_slot
    jmp tk_tb_m_held_issued
tk_tb_m_stream_stat:
    call tk_tb_m_live_slot
    cmp rcx, 4
    jne tk_tb_global_contract_fail
tk_tb_m_held_issued:
    call tk_tb_m_stat_span
    lea rsi, [r12 + tk_tb_m_STAT]
    mov eax, 5
    syscall
    jmp tk_tb_m_zero_effect
tk_tb_m_statx_effect:
    cmp qword ptr [r12 + 8], 51
    jne tk_tb_global_contract_fail
    call tk_tb_m_metadata_slot
    cmp qword ptr [r14 + 32], tk_tb_m_STATX
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 40], 256
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 48], 0
    jne tk_tb_global_contract_fail
    lea rsi, [rip + tk_tb_m_empty_literal]
    mov edx, 4096
    mov r10d, 4095
    lea r8, [r12 + tk_tb_m_STATX]
    mov eax, 332
    syscall
    jmp tk_tb_m_zero_effect
tk_tb_m_statat_effect:
    cmp qword ptr [r12 + 8], 52
    jne tk_tb_global_contract_fail
    call tk_tb_m_metadata_slot
    call tk_tb_m_stat_span
    lea rsi, [rip + tk_tb_m_empty_literal]
    lea rdx, [r12 + tk_tb_m_STAT]
    mov r10d, 4096
    mov eax, 262
    syscall
    jmp tk_tb_m_zero_effect
tk_tb_m_probe_admit:
    cmp qword ptr [r14 + 24], 0
    jne tk_tb_global_contract_fail
    call tk_tb_m_zero_span
    xor edi, edi
    xor esi, esi
    xor edx, edx
    ret
tk_tb_m_statx_probe_effect:
    cmp qword ptr [r12 + 8], 53
    jne tk_tb_global_contract_fail
    call tk_tb_m_probe_admit
    mov r10d, 4095
    xor r8d, r8d
    mov eax, 332
    syscall
    jmp tk_tb_m_zero_effect
tk_tb_m_statat_probe_effect:
    cmp qword ptr [r12 + 8], 54
    jne tk_tb_global_contract_fail
    call tk_tb_m_probe_admit
    lea rdx, [r12 + tk_tb_m_STAT]
    xor r10d, r10d
    mov eax, 262
    syscall
    jmp tk_tb_m_zero_effect
tk_tb_m_uid_effect:
    mov rax, [r12 + 8]
    cmp rax, 3
    je tk_tb_m_uid_admit
    cmp rax, 12
    je tk_tb_m_uid_admit
    cmp rax, 21
    jne tk_tb_global_contract_fail
tk_tb_m_uid_admit:
    cmp qword ptr [r14 + 24], 0
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 32], 544
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 40], 8
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 48], 0
    jne tk_tb_global_contract_fail
    mov eax, 107
    syscall
    mov [r12 + 544], rax
    jmp tk_tb_m_acknowledge
tk_tb_m_read_effect:
    call tk_tb_m_live_slot
    cmp qword ptr [r14 + 48], 0
    jne tk_tb_global_contract_fail
    cmp qword ptr [r12 + 8], 4
    je tk_tb_m_main_read
    cmp qword ptr [r12 + 8], 13
    jne tk_tb_global_contract_fail
    cmp rcx, 2
    jne tk_tb_global_contract_fail
    mov eax, tk_tb_m_LEGACY_REQUEST + 24
    mov edx, 2049
    jmp tk_tb_m_admit_read
tk_tb_m_main_read:
    cmp rcx, 1
    jne tk_tb_global_contract_fail
    mov eax, tk_tb_m_MAIN_REQUEST + 24
    mov edx, 65537
tk_tb_m_admit_read:
    mov rcx, [r12 + 72]
    cmp rcx, rdx
    jae tk_tb_global_contract_fail
    add rax, rcx
    sub rdx, rcx
    cmp rax, [r14 + 32]
    jne tk_tb_global_contract_fail
    cmp rdx, [r14 + 40]
    jne tk_tb_global_contract_fail
    lea rsi, [r12 + rax]
    xor eax, eax
    syscall
    jmp tk_tb_m_value_effect
tk_tb_m_close_effect:
    call tk_tb_m_zero_span
    call tk_tb_m_live_slot
    test rcx, rcx
    jz tk_tb_global_contract_fail
    mov rax, [r12 + 8]
    cmp rax, 300
    je tk_tb_m_close_issue
    cmp rax, 15
    je tk_tb_m_close_legacy
    cmp rax, 45
    je tk_tb_m_close_stream
    cmp rax, 48
    je tk_tb_m_close_stream
    cmp rax, 46
    je tk_tb_m_close_scan
    cmp rax, 62
    jne tk_tb_global_contract_fail
    cmp rcx, 5
    jne tk_tb_global_contract_fail
    jmp tk_tb_m_close_issue
tk_tb_m_close_legacy:
    cmp rcx, 2
    jne tk_tb_global_contract_fail
    jmp tk_tb_m_close_issue
tk_tb_m_close_stream:
    cmp rcx, 4
    jne tk_tb_global_contract_fail
    jmp tk_tb_m_close_issue
tk_tb_m_close_scan:
    cmp rcx, 3
    jne tk_tb_global_contract_fail
tk_tb_m_close_issue:
    mov qword ptr [r15 + rcx*8 + 128], -1
    mov eax, 3
    syscall
    jmp tk_tb_m_zero_effect
tk_tb_m_scan_open_effect:
    cmp qword ptr [r12 + 8], 40
    jne tk_tb_global_contract_fail
    call tk_tb_m_empty_slot
    cmp rcx, 3
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 32], tk_tb_m_DOT
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 40], 1
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 48], 0
    jne tk_tb_global_contract_fail
    cmp qword ptr [r12 + tk_tb_m_DOT], 46
    jne tk_tb_global_contract_fail
    lea rsi, [r12 + tk_tb_m_DOT]
    mov rdi, [r15 + 128]
    mov edx, 0xb0000
    xor r10d, r10d
    jmp tk_tb_m_issue_open
tk_tb_m_duplicate_effect:
    cmp qword ptr [r12 + 8], 41
    jne tk_tb_global_contract_fail
    call tk_tb_m_empty_slot
    cmp rcx, 4
    jne tk_tb_global_contract_fail
    mov rax, [r14 + 32]
    or rax, [r14 + 40]
    jnz tk_tb_global_contract_fail
    cmp qword ptr [r14 + 48], 3
    jne tk_tb_global_contract_fail
    mov rdi, [r15 + 152]
    test rdi, rdi
    js tk_tb_global_contract_fail
    mov esi, 1030
    xor edx, edx
    mov eax, 72
    syscall
    test rax, rax
    js tk_tb_m_effect_error
    mov [r15 + 160], rax
    mov qword ptr [r14 + 72], 4
    jmp tk_tb_m_acknowledge
tk_tb_m_flags_effect:
    cmp qword ptr [r12 + 8], 42
    jne tk_tb_global_contract_fail
    call tk_tb_m_zero_span
    call tk_tb_m_live_slot
    cmp rcx, 4
    jne tk_tb_global_contract_fail
    mov esi, 3
    xor edx, edx
    mov eax, 72
    syscall
    jmp tk_tb_m_value_effect
tk_tb_m_directory_effect:
    cmp qword ptr [r12 + 8], 44
    jne tk_tb_global_contract_fail
    call tk_tb_m_live_slot
    cmp rcx, 4
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 32], tk_tb_m_DIRENTS
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 48], 0
    jne tk_tb_global_contract_fail
    mov rdx, [r14 + 40]
    cmp rdx, 32768
    jb tk_tb_global_contract_fail
    cmp rdx, 1048576
    ja tk_tb_global_contract_fail
    cmp rdx, [r12 + 232]
    jne tk_tb_global_contract_fail
    lea rsi, [r12 + tk_tb_m_DIRENTS]
    mov eax, 217
    syscall
    jmp tk_tb_m_value_effect
tk_tb_m_candidate_name:
    cmp qword ptr [r14 + 32], tk_tb_m_CANDIDATE
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 48], 0
    jne tk_tb_global_contract_fail
    mov rax, [r12 + 240]
    cmp [r14 + 40], rax
    jne tk_tb_global_contract_fail
    lea rdi, [r12 + tk_tb_m_CANDIDATE]
    cmp qword ptr [r12 + 40], 1
    je tk_tb_m_candidate_anchor
    cmp qword ptr [r12 + 40], 2
    jne tk_tb_global_contract_fail
    cmp rax, 86
    jne tk_tb_global_contract_fail
    lea rsi, [rip + tk_tb_m_intent_prefix]
    mov ecx, 18
    jmp tk_tb_m_candidate_prefix
tk_tb_m_candidate_anchor:
    cmp rax, 88
    jne tk_tb_global_contract_fail
    lea rsi, [rip + tk_tb_m_anchor_prefix]
    mov ecx, 20
tk_tb_m_candidate_prefix:
    repe cmpsb
    jne tk_tb_global_contract_fail
    mov ecx, 64
tk_tb_m_candidate_digit:
    movzx eax, byte ptr [rdi]
    sub eax, 48
    cmp eax, 9
    jbe tk_tb_m_candidate_digit_ok
    add eax, 48
    sub eax, 97
    cmp eax, 5
    ja tk_tb_global_contract_fail
tk_tb_m_candidate_digit_ok:
    inc rdi
    dec ecx
    jnz tk_tb_m_candidate_digit
    cmp dword ptr [rdi], 0x706d742e
    jne tk_tb_global_contract_fail
    cmp byte ptr [rdi + 4], 0
    jne tk_tb_global_contract_fail
    ret
tk_tb_m_candidate_open_effect:
    cmp qword ptr [r12 + 8], 60
    jne tk_tb_global_contract_fail
    call tk_tb_m_empty_slot
    cmp rcx, 5
    jne tk_tb_global_contract_fail
    call tk_tb_m_candidate_name
    mov rdi, [r15 + 128]
    lea rsi, [r12 + tk_tb_m_CANDIDATE]
    mov edx, 0xa0800
    xor r10d, r10d
    jmp tk_tb_m_issue_open
tk_tb_m_unlink_effect:
    cmp qword ptr [r12 + 8], 63
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 24], 0
    jne tk_tb_global_contract_fail
    cmp qword ptr [r15 + 168], -1
    je tk_tb_global_contract_fail
    call tk_tb_m_candidate_name
    mov rdi, [r15 + 128]
    lea rsi, [r12 + tk_tb_m_CANDIDATE]
    xor edx, edx
    mov eax, 263
    syscall
    jmp tk_tb_m_zero_effect
tk_tb_m_sync_effect:
    cmp qword ptr [r12 + 8], 47
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 24], 0
    jne tk_tb_global_contract_fail
    call tk_tb_m_zero_span
    mov rdi, [r15 + 128]
    mov eax, 74
    syscall
    jmp tk_tb_m_zero_effect
tk_tb_m_json_effect:
    cmp qword ptr [r14 + 24], 0
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 48], tk_tb_m_CHILD_REPLY
    jne tk_tb_global_contract_fail
    cmp qword ptr [r12 + 8], 6
    je tk_tb_m_json_main
    cmp qword ptr [r12 + 8], 14
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 32], tk_tb_m_LEGACY_REQUEST
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 56], 256
    jne tk_tb_global_contract_fail
    cmp qword ptr [r12 + tk_tb_m_LEGACY_REQUEST + 8], 2
    jne tk_tb_global_contract_fail
    lea rdi, [r12 + tk_tb_m_LEGACY_REQUEST]
    mov eax, 2048
    jmp tk_tb_m_json_admit
tk_tb_m_json_main:
    cmp qword ptr [r14 + 32], tk_tb_m_MAIN_REQUEST
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 56], 262400
    jne tk_tb_global_contract_fail
    mov rax, [r12 + 40]
    add rax, 2
    cmp [r12 + tk_tb_m_MAIN_REQUEST + 8], rax
    jne tk_tb_global_contract_fail
    lea rdi, [r12 + tk_tb_m_MAIN_REQUEST]
    mov eax, 65536
tk_tb_m_json_admit:
    mov rsi, [rdi + 16]
    cmp rsi, rax
    ja tk_tb_global_contract_fail
    add rsi, 24
    cmp rsi, [r14 + 40]
    jne tk_tb_global_contract_fail
    mov rax, 0x313030514a415248
    cmp [rdi], rax
    jne tk_tb_global_contract_fail
    lea rdx, [r12 + tk_tb_m_CHILD_REPLY]
    mov rcx, [r14 + 56]
    lea r8, [r15 + tk_tb_m_JSON_WORK]
    mov r9d, 1048576
    call qword ptr [rip + tk_ticket_backend_json_image]
    mov ecx, eax
    cmp rax, rcx
    jne tk_tb_global_contract_fail
    mov [r14 + 72], rax
    jmp tk_tb_m_acknowledge
tk_tb_m_zero_effect:
    test rax, rax
    js tk_tb_m_effect_error
    test rax, rax
    jnz tk_tb_global_contract_fail
    jmp tk_tb_m_acknowledge
tk_tb_m_value_effect:
    test rax, rax
    js tk_tb_m_effect_error
    mov [r14 + 72], rax
    jmp tk_tb_m_acknowledge
tk_tb_m_effect_error:
    cmp rax, -4095
    jb tk_tb_global_contract_fail
    neg rax
    mov [r14 + 80], rax
tk_tb_m_acknowledge:
    mov rax, [r14 + 8]
    mov [r14 + 64], rax
    jmp tk_tb_m_resume_owner
tk_tb_m_anchor_literal:
    .asciz ".request-archive-v12-anchor.json"
tk_tb_m_intent_literal:
    .asciz ".request-archive-v12-init.json"
tk_tb_m_legacy_literal:
    .asciz ".request-archive-v11-anchor.json"
tk_tb_m_anchor_prefix:
    .ascii ".archive-v12-anchor-"
tk_tb_m_intent_prefix:
    .ascii ".archive-v12-init-"
tk_tb_m_empty_literal:
    .byte 0
tk_tb_m_return:
    cmp eax, 128
    jb tk_tb_global_contract_fail
    cmp eax, 4480
    ja tk_tb_global_contract_fail
    cmp qword ptr [r12 + 8], 0
    jne tk_tb_global_contract_fail
    cmp qword ptr [r12 + 48], 0
    jne tk_tb_global_contract_fail
    mov ecx, 1
tk_tb_m_closed:
    cmp qword ptr [r15 + 128 + rcx*8], -1
    jne tk_tb_global_contract_fail
    inc ecx
    cmp ecx, 6
    jne tk_tb_m_closed
    mov qword ptr [r15 + 128], -1
    mov ebx, eax
    mov rdi, [rsp + 8]
    lea rsi, [r15 + 8192]
    mov ecx, eax
    rep movsb
    mov eax, ebx
    add rsp, 24
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

tk_tb_writer_entry:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp, 24
    mov [rsp], rdi
    mov [rsp + 8], rdx
    mov [rsp + 16], rsi
    mov rax, [r15 + 4000]
    lea r15, [rax + tk_tb_W_BASE]
    mov r13, r15
    lea r12, [r15 + 8396800]
    lea rdi, [r15 + 4096]
    mov esi, 8388608
    mov edx, 3
    mov eax, 10
    syscall
    test rax, rax
    jnz tk_tb_global_io_fail
    lea rdi, [r15 + 4096]
    mov rsi, [rsp]
    mov rcx, [rsp + 16]
    mov [r15 + 24], rcx
    rep movsb
    lea rdi, [r15 + 4096]
    mov esi, 8388608
    mov edx, 1
    mov eax, 10
    syscall
    test rax, rax
    jnz tk_tb_global_io_fail
    mov rax, [r15 + 4000]
    mov rcx, [r14 + 24]
    cmp rcx, 266
    ja tk_tb_global_contract_fail
    mov rax, [rax + tk_tb_ROOT_FDS + rcx*8]
    test rax, rax
    js tk_tb_global_contract_fail
    mov [r15 + 128], rax
    mov [r15 + 18874368 + 128], rax
    jmp tk_tb_w_main_resume
.equ tk_tb_w_MAIN_INPUT, 4096
.equ tk_tb_w_MAIN_OUTPUT, 8392704
.equ tk_tb_w_MAIN_OWNER, 8396800
.equ tk_tb_w_ENTROPY_WORK, 17838080
.equ tk_tb_w_METADATA_BASE, 18874368
.equ tk_tb_w_FINAL_GUARD, 23142400
.equ tk_tb_w_TOTAL_MAP, 23146496
.equ tk_tb_w_M_ACTION, 256
.equ tk_tb_w_M_TEMP, 4096
.equ tk_tb_w_M_TARGET, 4352
.equ tk_tb_w_M_REQUEST, 8192
.equ tk_tb_w_M_REPLY, 16384
.equ tk_tb_w_M_JSON, 65536
tk_tb_w_main_resume:
    lea rdi, [r15 + tk_tb_w_MAIN_INPUT]
    mov rsi, [r15 + 24]
    lea rdx, [r15 + tk_tb_w_MAIN_OUTPUT]
    mov ecx, 64
    mov r8, r12
    mov r9d, 9437184
    call qword ptr [rip + tk_ticket_backend_writer_image]
    mov ecx, eax
    cmp rax, rcx
    jne tk_tb_global_contract_fail
    cmp eax, 0xfffffff0
    jne tk_tb_w_main_result
    lea r14, [r12 + tk_tb_w_M_ACTION]
    mov rax, 0x31303041574d5248
    cmp [r14], rax
    jne tk_tb_global_contract_fail
    mov rax, [r15 + 16]
    inc rax
    jz tk_tb_global_contract_fail
    cmp [r14 + 8], rax
    jne tk_tb_global_contract_fail
    cmp [r12 + 16], rax
    jne tk_tb_global_contract_fail
    mov [r15 + 16], rax
    mov rax, [r14 + 64]
    or rax, [r14 + 72]
    or rax, [r14 + 80]
    or rax, [r14 + 88]
    jnz tk_tb_global_contract_fail
    mov rax, [r14 + 16]
    cmp rax, 100
    je tk_tb_w_main_entropy
    cmp rax, 101
    je tk_tb_w_main_metadata
    cmp qword ptr [r14 + 56], 0
    jne tk_tb_global_contract_fail
    cmp rax, 1
    je tk_tb_w_main_open
    cmp rax, 2
    je tk_tb_w_main_write
    cmp rax, 3
    je tk_tb_w_main_sync
    cmp rax, 4
    je tk_tb_w_main_link
    cmp rax, 5
    je tk_tb_w_main_unlink
    cmp rax, 6
    je tk_tb_w_main_rename
    cmp rax, 7
    je tk_tb_w_main_close
    jmp tk_tb_global_contract_fail
tk_tb_w_main_metadata:
    cmp qword ptr [r12 + 8], 1
    jne tk_tb_global_contract_fail
    cmp qword ptr [r12 + 40], 3
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 24], 0
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 32], tk_tb_w_M_REQUEST
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 40], 32
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 48], tk_tb_w_M_REPLY
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 56], 4480
    jne tk_tb_global_contract_fail
    mov rax, 0x323030514d415248
    cmp [r12 + tk_tb_w_M_REQUEST], rax
    jne tk_tb_global_contract_fail
    cmp qword ptr [r12 + tk_tb_w_M_REQUEST + 8], 2
    jne tk_tb_global_contract_fail
    cmp qword ptr [r12 + tk_tb_w_M_REQUEST + 16], 0
    jne tk_tb_global_contract_fail
    call tk_tb_w_metadata_entry
    mov [r14 + 72], rax
    jmp tk_tb_w_main_ack
tk_tb_w_main_zero_span:
    mov rax, [r14 + 32]
    or rax, [r14 + 40]
    or rax, [r14 + 48]
    jnz tk_tb_global_contract_fail
    ret
tk_tb_w_main_root_slot:
    cmp qword ptr [r14 + 24], 0
    jne tk_tb_global_contract_fail
    mov rdi, [r15 + 128]
    test rdi, rdi
    js tk_tb_global_contract_fail
    ret
tk_tb_w_main_temp_slot:
    cmp qword ptr [r14 + 24], 1
    jne tk_tb_global_contract_fail
    mov rdi, [r15 + 136]
    test rdi, rdi
    js tk_tb_global_contract_fail
    ret
tk_tb_w_main_temp_name:
    cmp qword ptr [r14 + 32], tk_tb_w_M_TEMP
    jne tk_tb_global_contract_fail
    lea rsi, [r12 + tk_tb_w_M_TEMP]
    mov rax, [r12 + 40]
    cmp rax, 1
    je tk_tb_w_main_anchor_prefix
    cmp rax, 2
    je tk_tb_w_main_intent_prefix
    cmp rax, 3
    jne tk_tb_global_contract_fail
tk_tb_w_main_intent_prefix:
    lea rdi, [rip + tk_tb_w_fixed_intent_prefix]
    mov ecx, 18
    mov edx, 86
    jmp tk_tb_w_main_prefix_compare
tk_tb_w_main_anchor_prefix:
    lea rdi, [rip + tk_tb_w_fixed_anchor_prefix]
    mov ecx, 20
    mov edx, 88
tk_tb_w_main_prefix_compare:
    cmp [r14 + 40], rdx
    jne tk_tb_global_contract_fail
    cmp [r12 + 96], rdx
    jne tk_tb_global_contract_fail
    xor r8d, r8d
tk_tb_w_main_prefix_byte:
    mov al, [rsi + r8]
    cmp al, [rdi + r8]
    jne tk_tb_global_contract_fail
    inc r8
    cmp r8, rcx
    jb tk_tb_w_main_prefix_byte
    add ecx, 64
tk_tb_w_main_temp_hex:
    mov al, [rsi + r8]
    cmp al, 48
    jb tk_tb_global_contract_fail
    cmp al, 57
    jbe tk_tb_w_main_hex_ok
    cmp al, 97
    jb tk_tb_global_contract_fail
    cmp al, 102
    ja tk_tb_global_contract_fail
tk_tb_w_main_hex_ok:
    inc r8
    cmp r8, rcx
    jb tk_tb_w_main_temp_hex
    cmp dword ptr [rsi + r8], 0x706d742e
    jne tk_tb_global_contract_fail
    cmp byte ptr [rsi + r8 + 4], 0
    jne tk_tb_global_contract_fail
    ret
tk_tb_w_main_target_name:
    cmp qword ptr [r14 + 48], tk_tb_w_M_TARGET
    jne tk_tb_global_contract_fail
    lea r10, [r12 + tk_tb_w_M_TARGET]
    cmp qword ptr [r12 + 40], 1
    je tk_tb_w_main_anchor_target
    lea rdi, [rip + tk_tb_w_fixed_intent_target]
    mov ecx, 31
    jmp tk_tb_w_main_target_compare
tk_tb_w_main_anchor_target:
    lea rdi, [rip + tk_tb_w_fixed_anchor_target]
    mov ecx, 33
tk_tb_w_main_target_compare:
    xor edx, edx
tk_tb_w_main_target_byte:
    mov al, [r10 + rdx]
    cmp al, [rdi + rdx]
    jne tk_tb_global_contract_fail
    inc edx
    cmp edx, ecx
    jb tk_tb_w_main_target_byte
    ret
tk_tb_w_main_open:
    cmp qword ptr [r12 + 8], 3
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 24], 1
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 48], 384
    jne tk_tb_global_contract_fail
    cmp qword ptr [r15 + 136], -1
    jne tk_tb_global_contract_fail
    call tk_tb_w_main_temp_name
    mov rdi, [r15 + 128]
    mov edx, 0xa00c1
    mov r10d, 384
    mov eax, 257
    syscall
    test rax, rax
    js tk_tb_w_main_error
    mov [r15 + 136], rax
    mov qword ptr [r14 + 72], 1
    jmp tk_tb_w_main_ack
tk_tb_w_main_write:
    cmp qword ptr [r12 + 8], 4
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 48], 0
    jne tk_tb_global_contract_fail
    call tk_tb_w_main_temp_slot
    mov rax, [r12 + 88]
    mov rdx, [r12 + 80]
    cmp rdx, 65536
    ja tk_tb_global_contract_fail
    cmp rax, rdx
    jae tk_tb_global_contract_fail
    sub rdx, rax
    cmp [r14 + 40], rdx
    jne tk_tb_global_contract_fail
    lea rsi, [rax + tk_tb_w_M_JSON]
    cmp [r14 + 32], rsi
    jne tk_tb_global_contract_fail
    add rsi, r12
    mov eax, 1
    syscall
    jmp tk_tb_w_main_value
tk_tb_w_main_sync:
    call tk_tb_w_main_zero_span
    cmp qword ptr [r12 + 8], 5
    je tk_tb_w_main_file_sync
    cmp qword ptr [r12 + 8], 9
    jne tk_tb_global_contract_fail
    call tk_tb_w_main_root_slot
    jmp tk_tb_w_main_sync_live
tk_tb_w_main_file_sync:
    call tk_tb_w_main_temp_slot
tk_tb_w_main_sync_live:
    mov eax, 74
    syscall
    jmp tk_tb_w_main_zero
tk_tb_w_main_link:
    cmp qword ptr [r12 + 8], 6
    jne tk_tb_global_contract_fail
    cmp qword ptr [r12 + 40], 3
    je tk_tb_global_contract_fail
    call tk_tb_w_main_temp_name
    call tk_tb_w_main_target_name
    call tk_tb_w_main_root_slot
    mov rdx, rdi
    xor r8d, r8d
    mov eax, 265
    syscall
    jmp tk_tb_w_main_zero
tk_tb_w_main_unlink:
    cmp qword ptr [r14 + 48], 0
    jne tk_tb_global_contract_fail
    mov rax, [r12 + 8]
    cmp rax, 7
    je tk_tb_w_main_unlink_ready
    cmp rax, 300
    jne tk_tb_global_contract_fail
tk_tb_w_main_unlink_ready:
    call tk_tb_w_main_temp_name
    call tk_tb_w_main_root_slot
    xor edx, edx
    mov eax, 263
    syscall
    jmp tk_tb_w_main_zero
tk_tb_w_main_rename:
    cmp qword ptr [r12 + 8], 8
    jne tk_tb_global_contract_fail
    cmp qword ptr [r12 + 40], 3
    jne tk_tb_global_contract_fail
    call tk_tb_w_main_temp_name
    call tk_tb_w_main_target_name
    call tk_tb_w_main_root_slot
    mov rdx, rdi
    mov eax, 264
    syscall
    jmp tk_tb_w_main_zero
tk_tb_w_main_close:
    call tk_tb_w_main_zero_span
    mov rax, [r12 + 8]
    cmp rax, 10
    je tk_tb_w_main_close_ready
    cmp rax, 301
    jne tk_tb_global_contract_fail
tk_tb_w_main_close_ready:
    call tk_tb_w_main_temp_slot
    mov qword ptr [r15 + 136], -1
    mov eax, 3
    syscall
    jmp tk_tb_w_main_zero
tk_tb_w_main_entropy:
    cmp qword ptr [r12 + 8], 2
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 24], 0
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 32], tk_tb_w_M_REQUEST
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 40], 24
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 48], tk_tb_w_M_REPLY
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 56], 32
    jne tk_tb_global_contract_fail
    lea rdi, [r12 + tk_tb_w_M_REQUEST]
    lea rdx, [r12 + tk_tb_w_M_REPLY]
    mov esi, 24
    call tk_tb_shared_entropy_entry
    mov [r14 + 72], rax
    jmp tk_tb_w_main_ack
tk_tb_w_main_zero:
    test rax, rax
    js tk_tb_w_main_error
    jnz tk_tb_global_contract_fail
    jmp tk_tb_w_main_ack
tk_tb_w_main_value:
    test rax, rax
    js tk_tb_w_main_error
    mov [r14 + 72], rax
    jmp tk_tb_w_main_ack
tk_tb_w_main_error:
    cmp rax, -4095
    jb tk_tb_global_contract_fail
    neg rax
    mov [r14 + 80], rax
tk_tb_w_main_ack:
    mov rax, [r14 + 8]
    mov [r14 + 64], rax
    jmp tk_tb_w_main_resume
tk_tb_w_main_result:
    cmp qword ptr [r12 + 8], 0
    jne tk_tb_global_contract_fail
    cmp qword ptr [r15 + 136], -1
    jne tk_tb_global_contract_fail
    cmp qword ptr [r12 + 56], 0
    jne tk_tb_global_contract_fail
    mov [r15 + 32], eax
    cmp eax, 64
    je tk_tb_w_main_result_header
    cmp eax, 0xffffffff
    je tk_tb_w_main_result_header
    cmp eax, 0xfffffffe
    jne tk_tb_global_contract_fail
tk_tb_w_main_result_header:
    mov eax, [r15 + 32]
    cmp eax, 64
    jne tk_tb_global_contract_fail
    mov qword ptr [r15 + 128], -1
    mov qword ptr [r15 + tk_tb_w_METADATA_BASE + 128], -1
    mov ebx, eax
    mov rdi, [rsp + 8]
    lea rsi, [r15 + tk_tb_w_MAIN_OUTPUT]
    mov ecx, eax
    rep movsb
    mov eax, ebx
    add rsp, 24
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret
tk_tb_w_fixed_anchor_prefix:
    .ascii ".archive-v12-anchor-"
tk_tb_w_fixed_intent_prefix:
    .ascii ".archive-v12-init-"
tk_tb_w_fixed_anchor_target:
    .asciz ".request-archive-v12-anchor.json"
tk_tb_w_fixed_intent_target:
    .asciz ".request-archive-v12-init.json"

tk_tb_w_metadata_entry:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp, 8
    lea r15, [r13 + tk_tb_w_METADATA_BASE]
    lea r12, [r15 + tk_tb_w_md_OWNER]
    lea rdi, [r15 + tk_tb_w_md_INPUT]
    mov esi, 4096
    mov edx, 3
    mov eax, 10
    syscall
    test rax, rax
    jnz tk_tb_global_io_fail
    lea rdi, [r15 + tk_tb_w_md_INPUT]
    lea rsi, [r13 + tk_tb_w_MAIN_OWNER + tk_tb_w_M_REQUEST]
    mov ecx, 32
    rep movsb
    mov qword ptr [r15 + 24], 32
    lea rdi, [r15 + tk_tb_w_md_INPUT]
    mov esi, 4096
    mov edx, 1
    mov eax, 10
    syscall
    test rax, rax
    jnz tk_tb_global_io_fail
    mov rax, [r13 + 128]
    test rax, rax
    js tk_tb_global_contract_fail
    cmp [r15 + 128], rax
    jne tk_tb_global_contract_fail
    jmp tk_tb_w_md_resume_owner
tk_tb_w_md_owner_result:
    cmp eax, 128
    jb tk_tb_global_contract_fail
    cmp eax, 4480
    ja tk_tb_global_contract_fail
    cmp qword ptr [r12 + 8], 0
    jne tk_tb_global_contract_fail
    cmp qword ptr [r12 + 48], 0
    jne tk_tb_global_contract_fail
    mov ebx, eax
    mov ecx, 1
tk_tb_w_md_check_closed:
    cmp qword ptr [r15 + rcx*8 + 128], -1
    jne tk_tb_global_contract_fail
    inc ecx
    cmp ecx, 6
    jne tk_tb_w_md_check_closed
    lea rsi, [r15 + tk_tb_w_md_OUTPUT]
    lea rdi, [r13 + tk_tb_w_MAIN_OWNER + tk_tb_w_M_REPLY]
    mov ecx, ebx
    rep movsb
    mov eax, ebx
    add rsp, 8
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret
.equ tk_tb_w_md_INPUT, 4096
.equ tk_tb_w_md_OUTPUT, 8192
.equ tk_tb_w_md_OWNER, 65536
.equ tk_tb_w_md_JSON_WORK, 3211264
.equ tk_tb_w_md_GUARD, 4259840
.equ tk_tb_w_md_MAP_SIZE, 4263936
.equ tk_tb_w_md_ACTION, 256
.equ tk_tb_w_md_STAT, 1024
.equ tk_tb_w_md_STATX, 3072
.equ tk_tb_w_md_NAME, 4096
.equ tk_tb_w_md_LEGACY_NAME, 4160
.equ tk_tb_w_md_DOT, 4224
.equ tk_tb_w_md_CANDIDATE, 4352
.equ tk_tb_w_md_MAIN_REQUEST, 8192
.equ tk_tb_w_md_LEGACY_REQUEST, 73760
.equ tk_tb_w_md_CHILD_REPLY, 77824
.equ tk_tb_w_md_DIRENTS, 1048576
tk_tb_w_md_resume_owner:
    lea rdi, [r15 + tk_tb_w_md_INPUT]
    mov rsi, [r15 + 24]
    lea rdx, [r15 + tk_tb_w_md_OUTPUT]
    mov ecx, 8192
    mov r8, r12
    mov r9d, 3145728
    call qword ptr [rip + tk_ticket_backend_metadata_image]
    mov ecx, eax
    cmp rax, rcx
    jne tk_tb_global_contract_fail
    cmp eax, 0xfffffff0
    jne tk_tb_w_md_owner_result
    lea r14, [r12 + tk_tb_w_md_ACTION]
    mov rax, 0x313030414d415248
    cmp [r14], rax
    jne tk_tb_global_contract_fail
    mov rax, [r15 + 16]
    inc rax
    jz tk_tb_global_contract_fail
    cmp [r14 + 8], rax
    jne tk_tb_global_contract_fail
    cmp [r12 + 16], rax
    jne tk_tb_global_contract_fail
    mov [r15 + 16], rax
    mov rax, [r14 + 64]
    or rax, [r14 + 72]
    or rax, [r14 + 80]
    or rax, [r14 + 88]
    jnz tk_tb_global_contract_fail
    mov rax, [r14 + 16]
    cmp rax, 100
    je tk_tb_w_md_json_effect
    cmp qword ptr [r14 + 56], 0
    jne tk_tb_global_contract_fail
    cmp rax, 1
    je tk_tb_w_md_open_effect
    cmp rax, 2
    je tk_tb_w_md_held_effect
    cmp rax, 4
    je tk_tb_w_md_read_effect
    cmp rax, 5
    je tk_tb_w_md_uid_effect
    cmp rax, 7
    je tk_tb_w_md_close_effect
    cmp rax, 8
    je tk_tb_w_md_statx_effect
    cmp rax, 9
    je tk_tb_w_md_statx_probe_effect
    cmp rax, 10
    je tk_tb_w_md_statat_effect
    cmp rax, 11
    je tk_tb_w_md_statat_probe_effect
    cmp rax, 12
    je tk_tb_w_md_scan_open_effect
    cmp rax, 13
    je tk_tb_w_md_duplicate_effect
    cmp rax, 14
    je tk_tb_w_md_flags_effect
    cmp rax, 15
    je tk_tb_w_md_directory_effect
    cmp rax, 16
    je tk_tb_w_md_candidate_open_effect
    cmp rax, 17
    je tk_tb_w_md_unlink_effect
    cmp rax, 18
    je tk_tb_w_md_sync_effect
    jmp tk_tb_global_contract_fail

tk_tb_w_md_live_slot:
    mov rcx, [r14 + 24]
    cmp rcx, 5
    ja tk_tb_global_contract_fail
    mov rdi, [r15 + rcx*8 + 128]
    test rdi, rdi
    js tk_tb_global_contract_fail
    ret
tk_tb_w_md_empty_slot:
    mov rcx, [r14 + 24]
    test rcx, rcx
    jz tk_tb_global_contract_fail
    cmp rcx, 5
    ja tk_tb_global_contract_fail
    cmp qword ptr [r15 + rcx*8 + 128], -1
    jne tk_tb_global_contract_fail
    ret
tk_tb_w_md_zero_span:
    mov rax, [r14 + 32]
    or rax, [r14 + 40]
    or rax, [r14 + 48]
    jnz tk_tb_global_contract_fail
    ret
tk_tb_w_md_root_name:
    cmp qword ptr [r14 + 48], 0
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 32], tk_tb_w_md_NAME
    jne tk_tb_global_contract_fail
    lea rdi, [r12 + tk_tb_w_md_NAME]
    cmp qword ptr [r12 + 40], 1
    je tk_tb_w_md_anchor_name
    cmp qword ptr [r12 + 40], 2
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 40], 30
    jne tk_tb_global_contract_fail
    lea rsi, [rip + tk_tb_w_md_intent_literal]
    mov ecx, 31
    jmp tk_tb_w_md_compare_name
tk_tb_w_md_anchor_name:
    cmp qword ptr [r14 + 40], 32
    jne tk_tb_global_contract_fail
    lea rsi, [rip + tk_tb_w_md_anchor_literal]
    mov ecx, 33
tk_tb_w_md_compare_name:
    repe cmpsb
    jne tk_tb_global_contract_fail
    ret
tk_tb_w_md_legacy_name:
    cmp qword ptr [r14 + 48], 0
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 32], tk_tb_w_md_LEGACY_NAME
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 40], 32
    jne tk_tb_global_contract_fail
    lea rdi, [r12 + tk_tb_w_md_LEGACY_NAME]
    lea rsi, [rip + tk_tb_w_md_legacy_literal]
    mov ecx, 33
    repe cmpsb
    jne tk_tb_global_contract_fail
    ret
tk_tb_w_md_open_effect:
    call tk_tb_w_md_empty_slot
    cmp qword ptr [r12 + 8], 1
    je tk_tb_w_md_open_main
    cmp qword ptr [r12 + 8], 10
    jne tk_tb_global_contract_fail
    cmp rcx, 2
    jne tk_tb_global_contract_fail
    call tk_tb_w_md_legacy_name
    lea rsi, [r12 + tk_tb_w_md_LEGACY_NAME]
    jmp tk_tb_w_md_open_readonly
tk_tb_w_md_open_main:
    cmp rcx, 1
    jne tk_tb_global_contract_fail
    call tk_tb_w_md_root_name
    lea rsi, [r12 + tk_tb_w_md_NAME]
tk_tb_w_md_open_readonly:
    mov rdi, [r15 + 128]
    mov edx, 0xa0800
    xor r10d, r10d
tk_tb_w_md_issue_open:
    mov eax, 257
    syscall
    test rax, rax
    js tk_tb_w_md_effect_error
    cmp rax, 0x7fffffff
    ja tk_tb_global_contract_fail
    mov rcx, [r14 + 24]
    mov [r15 + rcx*8 + 128], rax
    mov [r14 + 72], rcx
    jmp tk_tb_w_md_acknowledge
tk_tb_w_md_metadata_slot:
    call tk_tb_w_md_live_slot
    cmp rcx, [r12 + 128]
    jne tk_tb_global_contract_fail
    mov rax, [r12 + 136]
    cmp rax, 16
    je tk_tb_w_md_metadata_root
    cmp rax, 11
    je tk_tb_w_md_metadata_legacy
    cmp rax, 61
    je tk_tb_w_md_metadata_candidate
    cmp rax, 2
    je tk_tb_w_md_metadata_main
    cmp rax, 5
    je tk_tb_w_md_metadata_main
    cmp rax, 20
    je tk_tb_w_md_metadata_main
    cmp rax, 30
    jne tk_tb_global_contract_fail
tk_tb_w_md_metadata_main:
    cmp rcx, 1
    jne tk_tb_global_contract_fail
    ret
tk_tb_w_md_metadata_root:
    test rcx, rcx
    jnz tk_tb_global_contract_fail
    ret
tk_tb_w_md_metadata_legacy:
    cmp rcx, 2
    jne tk_tb_global_contract_fail
    ret
tk_tb_w_md_metadata_candidate:
    cmp rcx, 5
    jne tk_tb_global_contract_fail
    ret
tk_tb_w_md_stat_span:
    cmp qword ptr [r14 + 32], tk_tb_w_md_STAT
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 40], 144
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 48], 0
    jne tk_tb_global_contract_fail
    ret
tk_tb_w_md_held_effect:
    cmp qword ptr [r12 + 8], 43
    je tk_tb_w_md_stream_stat
    cmp qword ptr [r12 + 8], 50
    jne tk_tb_global_contract_fail
    call tk_tb_w_md_metadata_slot
    jmp tk_tb_w_md_held_issued
tk_tb_w_md_stream_stat:
    call tk_tb_w_md_live_slot
    cmp rcx, 4
    jne tk_tb_global_contract_fail
tk_tb_w_md_held_issued:
    call tk_tb_w_md_stat_span
    lea rsi, [r12 + tk_tb_w_md_STAT]
    mov eax, 5
    syscall
    jmp tk_tb_w_md_zero_effect
tk_tb_w_md_statx_effect:
    cmp qword ptr [r12 + 8], 51
    jne tk_tb_global_contract_fail
    call tk_tb_w_md_metadata_slot
    cmp qword ptr [r14 + 32], tk_tb_w_md_STATX
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 40], 256
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 48], 0
    jne tk_tb_global_contract_fail
    lea rsi, [rip + tk_tb_w_md_empty_literal]
    mov edx, 4096
    mov r10d, 4095
    lea r8, [r12 + tk_tb_w_md_STATX]
    mov eax, 332
    syscall
    jmp tk_tb_w_md_zero_effect
tk_tb_w_md_statat_effect:
    cmp qword ptr [r12 + 8], 52
    jne tk_tb_global_contract_fail
    call tk_tb_w_md_metadata_slot
    call tk_tb_w_md_stat_span
    lea rsi, [rip + tk_tb_w_md_empty_literal]
    lea rdx, [r12 + tk_tb_w_md_STAT]
    mov r10d, 4096
    mov eax, 262
    syscall
    jmp tk_tb_w_md_zero_effect
tk_tb_w_md_probe_admit:
    cmp qword ptr [r14 + 24], 0
    jne tk_tb_global_contract_fail
    call tk_tb_w_md_zero_span
    xor edi, edi
    xor esi, esi
    xor edx, edx
    ret
tk_tb_w_md_statx_probe_effect:
    cmp qword ptr [r12 + 8], 53
    jne tk_tb_global_contract_fail
    call tk_tb_w_md_probe_admit
    mov r10d, 4095
    xor r8d, r8d
    mov eax, 332
    syscall
    jmp tk_tb_w_md_zero_effect
tk_tb_w_md_statat_probe_effect:
    cmp qword ptr [r12 + 8], 54
    jne tk_tb_global_contract_fail
    call tk_tb_w_md_probe_admit
    lea rdx, [r12 + tk_tb_w_md_STAT]
    xor r10d, r10d
    mov eax, 262
    syscall
    jmp tk_tb_w_md_zero_effect
tk_tb_w_md_uid_effect:
    mov rax, [r12 + 8]
    cmp rax, 3
    je tk_tb_w_md_uid_admit
    cmp rax, 12
    je tk_tb_w_md_uid_admit
    cmp rax, 21
    jne tk_tb_global_contract_fail
tk_tb_w_md_uid_admit:
    cmp qword ptr [r14 + 24], 0
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 32], 544
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 40], 8
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 48], 0
    jne tk_tb_global_contract_fail
    mov eax, 107
    syscall
    mov [r12 + 544], rax
    jmp tk_tb_w_md_acknowledge
tk_tb_w_md_read_effect:
    call tk_tb_w_md_live_slot
    cmp qword ptr [r14 + 48], 0
    jne tk_tb_global_contract_fail
    cmp qword ptr [r12 + 8], 4
    je tk_tb_w_md_main_read
    cmp qword ptr [r12 + 8], 13
    jne tk_tb_global_contract_fail
    cmp rcx, 2
    jne tk_tb_global_contract_fail
    mov eax, tk_tb_w_md_LEGACY_REQUEST + 24
    mov edx, 2049
    jmp tk_tb_w_md_admit_read
tk_tb_w_md_main_read:
    cmp rcx, 1
    jne tk_tb_global_contract_fail
    mov eax, tk_tb_w_md_MAIN_REQUEST + 24
    mov edx, 65537
tk_tb_w_md_admit_read:
    mov rcx, [r12 + 72]
    cmp rcx, rdx
    jae tk_tb_global_contract_fail
    add rax, rcx
    sub rdx, rcx
    cmp rax, [r14 + 32]
    jne tk_tb_global_contract_fail
    cmp rdx, [r14 + 40]
    jne tk_tb_global_contract_fail
    lea rsi, [r12 + rax]
    xor eax, eax
    syscall
    jmp tk_tb_w_md_value_effect
tk_tb_w_md_close_effect:
    call tk_tb_w_md_zero_span
    call tk_tb_w_md_live_slot
    test rcx, rcx
    jz tk_tb_global_contract_fail
    mov rax, [r12 + 8]
    cmp rax, 300
    je tk_tb_w_md_close_issue
    cmp rax, 15
    je tk_tb_w_md_close_legacy
    cmp rax, 45
    je tk_tb_w_md_close_stream
    cmp rax, 48
    je tk_tb_w_md_close_stream
    cmp rax, 46
    je tk_tb_w_md_close_scan
    cmp rax, 62
    jne tk_tb_global_contract_fail
    cmp rcx, 5
    jne tk_tb_global_contract_fail
    jmp tk_tb_w_md_close_issue
tk_tb_w_md_close_legacy:
    cmp rcx, 2
    jne tk_tb_global_contract_fail
    jmp tk_tb_w_md_close_issue
tk_tb_w_md_close_stream:
    cmp rcx, 4
    jne tk_tb_global_contract_fail
    jmp tk_tb_w_md_close_issue
tk_tb_w_md_close_scan:
    cmp rcx, 3
    jne tk_tb_global_contract_fail
tk_tb_w_md_close_issue:
    mov qword ptr [r15 + rcx*8 + 128], -1
    mov eax, 3
    syscall
    jmp tk_tb_w_md_zero_effect
tk_tb_w_md_scan_open_effect:
    cmp qword ptr [r12 + 8], 40
    jne tk_tb_global_contract_fail
    call tk_tb_w_md_empty_slot
    cmp rcx, 3
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 32], tk_tb_w_md_DOT
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 40], 1
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 48], 0
    jne tk_tb_global_contract_fail
    cmp qword ptr [r12 + tk_tb_w_md_DOT], 46
    jne tk_tb_global_contract_fail
    lea rsi, [r12 + tk_tb_w_md_DOT]
    mov rdi, [r15 + 128]
    mov edx, 0xb0000
    xor r10d, r10d
    jmp tk_tb_w_md_issue_open
tk_tb_w_md_duplicate_effect:
    cmp qword ptr [r12 + 8], 41
    jne tk_tb_global_contract_fail
    call tk_tb_w_md_empty_slot
    cmp rcx, 4
    jne tk_tb_global_contract_fail
    mov rax, [r14 + 32]
    or rax, [r14 + 40]
    jnz tk_tb_global_contract_fail
    cmp qword ptr [r14 + 48], 3
    jne tk_tb_global_contract_fail
    mov rdi, [r15 + 152]
    test rdi, rdi
    js tk_tb_global_contract_fail
    mov esi, 1030
    xor edx, edx
    mov eax, 72
    syscall
    test rax, rax
    js tk_tb_w_md_effect_error
    mov [r15 + 160], rax
    mov qword ptr [r14 + 72], 4
    jmp tk_tb_w_md_acknowledge
tk_tb_w_md_flags_effect:
    cmp qword ptr [r12 + 8], 42
    jne tk_tb_global_contract_fail
    call tk_tb_w_md_zero_span
    call tk_tb_w_md_live_slot
    cmp rcx, 4
    jne tk_tb_global_contract_fail
    mov esi, 3
    xor edx, edx
    mov eax, 72
    syscall
    jmp tk_tb_w_md_value_effect
tk_tb_w_md_directory_effect:
    cmp qword ptr [r12 + 8], 44
    jne tk_tb_global_contract_fail
    call tk_tb_w_md_live_slot
    cmp rcx, 4
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 32], tk_tb_w_md_DIRENTS
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 48], 0
    jne tk_tb_global_contract_fail
    mov rdx, [r14 + 40]
    cmp rdx, 32768
    jb tk_tb_global_contract_fail
    cmp rdx, 1048576
    ja tk_tb_global_contract_fail
    cmp rdx, [r12 + 232]
    jne tk_tb_global_contract_fail
    lea rsi, [r12 + tk_tb_w_md_DIRENTS]
    mov eax, 217
    syscall
    jmp tk_tb_w_md_value_effect
tk_tb_w_md_candidate_name:
    cmp qword ptr [r14 + 32], tk_tb_w_md_CANDIDATE
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 48], 0
    jne tk_tb_global_contract_fail
    mov rax, [r12 + 240]
    cmp [r14 + 40], rax
    jne tk_tb_global_contract_fail
    lea rdi, [r12 + tk_tb_w_md_CANDIDATE]
    cmp qword ptr [r12 + 40], 1
    je tk_tb_w_md_candidate_anchor
    cmp qword ptr [r12 + 40], 2
    jne tk_tb_global_contract_fail
    cmp rax, 86
    jne tk_tb_global_contract_fail
    lea rsi, [rip + tk_tb_w_md_intent_prefix]
    mov ecx, 18
    jmp tk_tb_w_md_candidate_prefix
tk_tb_w_md_candidate_anchor:
    cmp rax, 88
    jne tk_tb_global_contract_fail
    lea rsi, [rip + tk_tb_w_md_anchor_prefix]
    mov ecx, 20
tk_tb_w_md_candidate_prefix:
    repe cmpsb
    jne tk_tb_global_contract_fail
    mov ecx, 64
tk_tb_w_md_candidate_digit:
    movzx eax, byte ptr [rdi]
    sub eax, 48
    cmp eax, 9
    jbe tk_tb_w_md_candidate_digit_ok
    add eax, 48
    sub eax, 97
    cmp eax, 5
    ja tk_tb_global_contract_fail
tk_tb_w_md_candidate_digit_ok:
    inc rdi
    dec ecx
    jnz tk_tb_w_md_candidate_digit
    cmp dword ptr [rdi], 0x706d742e
    jne tk_tb_global_contract_fail
    cmp byte ptr [rdi + 4], 0
    jne tk_tb_global_contract_fail
    ret
tk_tb_w_md_candidate_open_effect:
    cmp qword ptr [r12 + 8], 60
    jne tk_tb_global_contract_fail
    call tk_tb_w_md_empty_slot
    cmp rcx, 5
    jne tk_tb_global_contract_fail
    call tk_tb_w_md_candidate_name
    mov rdi, [r15 + 128]
    lea rsi, [r12 + tk_tb_w_md_CANDIDATE]
    mov edx, 0xa0800
    xor r10d, r10d
    jmp tk_tb_w_md_issue_open
tk_tb_w_md_unlink_effect:
    cmp qword ptr [r12 + 8], 63
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 24], 0
    jne tk_tb_global_contract_fail
    cmp qword ptr [r15 + 168], -1
    je tk_tb_global_contract_fail
    call tk_tb_w_md_candidate_name
    mov rdi, [r15 + 128]
    lea rsi, [r12 + tk_tb_w_md_CANDIDATE]
    xor edx, edx
    mov eax, 263
    syscall
    jmp tk_tb_w_md_zero_effect
tk_tb_w_md_sync_effect:
    cmp qword ptr [r12 + 8], 47
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 24], 0
    jne tk_tb_global_contract_fail
    call tk_tb_w_md_zero_span
    mov rdi, [r15 + 128]
    mov eax, 74
    syscall
    jmp tk_tb_w_md_zero_effect
tk_tb_w_md_json_effect:
    cmp qword ptr [r14 + 24], 0
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 48], tk_tb_w_md_CHILD_REPLY
    jne tk_tb_global_contract_fail
    cmp qword ptr [r12 + 8], 6
    je tk_tb_w_md_json_main
    cmp qword ptr [r12 + 8], 14
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 32], tk_tb_w_md_LEGACY_REQUEST
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 56], 256
    jne tk_tb_global_contract_fail
    cmp qword ptr [r12 + tk_tb_w_md_LEGACY_REQUEST + 8], 2
    jne tk_tb_global_contract_fail
    lea rdi, [r12 + tk_tb_w_md_LEGACY_REQUEST]
    mov eax, 2048
    jmp tk_tb_w_md_json_admit
tk_tb_w_md_json_main:
    cmp qword ptr [r14 + 32], tk_tb_w_md_MAIN_REQUEST
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 56], 262400
    jne tk_tb_global_contract_fail
    mov rax, [r12 + 40]
    add rax, 2
    cmp [r12 + tk_tb_w_md_MAIN_REQUEST + 8], rax
    jne tk_tb_global_contract_fail
    lea rdi, [r12 + tk_tb_w_md_MAIN_REQUEST]
    mov eax, 65536
tk_tb_w_md_json_admit:
    mov rsi, [rdi + 16]
    cmp rsi, rax
    ja tk_tb_global_contract_fail
    add rsi, 24
    cmp rsi, [r14 + 40]
    jne tk_tb_global_contract_fail
    mov rax, 0x313030514a415248
    cmp [rdi], rax
    jne tk_tb_global_contract_fail
    lea rdx, [r12 + tk_tb_w_md_CHILD_REPLY]
    mov rcx, [r14 + 56]
    lea r8, [r15 + tk_tb_w_md_JSON_WORK]
    mov r9d, 1048576
    call qword ptr [rip + tk_ticket_backend_json_image]
    mov ecx, eax
    cmp rax, rcx
    jne tk_tb_global_contract_fail
    mov [r14 + 72], rax
    jmp tk_tb_w_md_acknowledge
tk_tb_w_md_zero_effect:
    test rax, rax
    js tk_tb_w_md_effect_error
    test rax, rax
    jnz tk_tb_global_contract_fail
    jmp tk_tb_w_md_acknowledge
tk_tb_w_md_value_effect:
    test rax, rax
    js tk_tb_w_md_effect_error
    mov [r14 + 72], rax
    jmp tk_tb_w_md_acknowledge
tk_tb_w_md_effect_error:
    cmp rax, -4095
    jb tk_tb_global_contract_fail
    neg rax
    mov [r14 + 80], rax
tk_tb_w_md_acknowledge:
    mov rax, [r14 + 8]
    mov [r14 + 64], rax
    jmp tk_tb_w_md_resume_owner
tk_tb_w_md_anchor_literal:
    .asciz ".request-archive-v12-anchor.json"
tk_tb_w_md_intent_literal:
    .asciz ".request-archive-v12-init.json"
tk_tb_w_md_legacy_literal:
    .asciz ".request-archive-v11-anchor.json"
tk_tb_w_md_anchor_prefix:
    .ascii ".archive-v12-anchor-"
tk_tb_w_md_intent_prefix:
    .ascii ".archive-v12-init-"
tk_tb_w_md_empty_literal:
    .byte 0

tk_tb_record_entry:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp, 24
    mov [rsp], rdi
    mov [rsp + 8], rdx
    mov [rsp + 16], rsi
    mov rax, [r15 + 4000]
    lea r15, [rax + tk_tb_A_BASE]
    mov r13, r15
    lea r12, [r15 + 2097152]
    lea rdi, [r15 + 4096]
    mov esi, 1048576
    mov edx, 3
    mov eax, 10
    syscall
    test rax, rax
    jnz tk_tb_global_io_fail
    lea rdi, [r15 + 4096]
    mov rsi, [rsp]
    mov rcx, [rsp + 16]
    mov [r15 + 24], rcx
    rep movsb
    lea rdi, [r15 + 4096]
    mov esi, 1048576
    mov edx, 1
    mov eax, 10
    syscall
    test rax, rax
    jnz tk_tb_global_io_fail
    mov rax, [r15 + 4000]
    mov rcx, [r14 + 24]
    cmp rcx, 266
    ja tk_tb_global_contract_fail
    mov rax, [rax + tk_tb_ROOT_FDS + rcx*8]
    test rax, rax
    js tk_tb_global_contract_fail
    mov [r15 + 128], rax
    jmp tk_tb_a_resume_owner
.equ tk_tb_a_INPUT, 4096
.equ tk_tb_a_INPUT_CAP, 1048576
.equ tk_tb_a_OUTPUT, 1056768
.equ tk_tb_a_OUTPUT_CAP, 512
.equ tk_tb_a_OWNER, 2097152
.equ tk_tb_a_JSON_WORK, 6291456
.equ tk_tb_a_MAP_SIZE, 7344128
.equ tk_tb_a_ACTION, 256
.equ tk_tb_a_STAT, 1024
.equ tk_tb_a_FILENAME, 4096
.equ tk_tb_a_TEMPORARY, 4224
.equ tk_tb_a_CLEAN_NAME, 4480
.equ tk_tb_a_CLEAN_TARGET, 4800
.equ tk_tb_a_DOT, 4928
.equ tk_tb_a_CHILD_REQUEST, 8192
.equ tk_tb_a_CHILD_REPLY, 12288
.equ tk_tb_a_READ_BYTES, 24576
.equ tk_tb_a_DIR_BYTES, 65536
tk_tb_a_resume_owner:
    lea rdi, [r15 + tk_tb_a_INPUT]
    mov rsi, [r15 + 24]
    lea rdx, [r15 + tk_tb_a_OUTPUT]
    mov ecx, tk_tb_a_OUTPUT_CAP
    mov r8, r12
    mov r9d, 4194304
    call qword ptr [rip + tk_ticket_backend_record_image]
    cmp eax, 0xfffffff0
    jne tk_tb_a_owner_result
    lea r14, [r12 + tk_tb_a_ACTION]
    mov rax, 0x3130304152415248
    cmp [r14], rax
    jne tk_tb_global_contract_fail
    mov rax, [r15 + 8]
    inc rax
    jz tk_tb_global_contract_fail
    cmp [r14 + 8], rax
    jne tk_tb_global_contract_fail
    cmp [r12 + 16], rax
    jne tk_tb_global_contract_fail
    mov [r15 + 8], rax
    mov rax, [r14 + 64]
    or rax, [r14 + 72]
    or rax, [r14 + 80]
    or rax, [r14 + 88]
    jnz tk_tb_global_contract_fail
    mov rax, [r14 + 16]
    cmp rax, 100
    je tk_tb_a_json_effect
    cmp qword ptr [r14 + 56], 0
    jne tk_tb_global_contract_fail
    cmp rax, 1
    je tk_tb_a_stat_effect
    cmp rax, 2
    je tk_tb_a_open_effect
    cmp rax, 3
    je tk_tb_a_read_effect
    cmp rax, 5
    je tk_tb_a_sync_effect
    cmp rax, 8
    je tk_tb_a_unlink_effect
    cmp rax, 9
    je tk_tb_a_close_effect
    cmp rax, 10
    je tk_tb_a_scan_open_effect
    cmp rax, 11
    je tk_tb_a_duplicate_effect
    cmp rax, 12
    je tk_tb_a_flags_effect
    cmp rax, 13
    je tk_tb_a_directory_effect
    jmp tk_tb_global_contract_fail
tk_tb_a_json_effect:
    cmp qword ptr [r14 + 24], 0
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 32], tk_tb_a_CHILD_REQUEST
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 40], 24
    jb tk_tb_global_contract_fail
    cmp qword ptr [r14 + 40], 2072
    ja tk_tb_global_contract_fail
    cmp qword ptr [r14 + 48], tk_tb_a_CHILD_REPLY
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 56], 4096
    jne tk_tb_global_contract_fail
    lea rdi, [r12 + tk_tb_a_CHILD_REQUEST]
    mov rsi, [r14 + 40]
    lea rdx, [r12 + tk_tb_a_CHILD_REPLY]
    mov ecx, 4096
    lea r8, [r15 + tk_tb_a_JSON_WORK]
    mov r9d, 1048576
    call qword ptr [rip + tk_ticket_backend_json_image]
    mov [r12 + tk_tb_a_ACTION + 72], rax
    jmp tk_tb_a_acknowledge
tk_tb_a_live_slot:
    mov rcx, [r14 + 24]
    cmp rcx, 6
    ja tk_tb_global_contract_fail
    mov rdi, [r15 + rcx*8 + 128]
    test rdi, rdi
    js tk_tb_global_contract_fail
    ret
tk_tb_a_zero_span:
    mov rax, [r14 + 32]
    or rax, [r14 + 40]
    or rax, [r14 + 48]
    jnz tk_tb_global_contract_fail
    ret
tk_tb_a_stat_effect:
    call tk_tb_a_live_slot
    test rcx, rcx
    jz tk_tb_global_contract_fail
    cmp qword ptr [r14 + 32], tk_tb_a_STAT
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 40], 152
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 48], 1
    ja tk_tb_global_contract_fail
    lea rsi, [r12 + tk_tb_a_STAT]
    mov eax, 5
    syscall
    test rax, rax
    js tk_tb_a_effect_error
    cmp qword ptr [r14 + 48], 1
    je tk_tb_a_acknowledge
    mov eax, 107
    syscall
    mov [r12 + tk_tb_a_STAT + 144], rax
    jmp tk_tb_a_acknowledge
tk_tb_a_name_span:
    mov rax, [r14 + 32]
    mov rdx, [r14 + 40]
    cmp rax, tk_tb_a_FILENAME
    je tk_tb_a_record_name
    cmp rax, tk_tb_a_CLEAN_TARGET
    je tk_tb_a_record_name
    cmp rax, tk_tb_a_TEMPORARY
    je tk_tb_a_staging_name
    cmp rax, tk_tb_a_CLEAN_NAME
    jne tk_tb_global_contract_fail
tk_tb_a_staging_name:
    cmp rdx, 134
    jne tk_tb_global_contract_fail
    lea rsi, [r12 + rax]
    cmp byte ptr [rsi], 46
    jne tk_tb_global_contract_fail
    cmp byte ptr [rsi + 65], 45
    jne tk_tb_global_contract_fail
    cmp dword ptr [rsi + 130], 0x706d742e
    jne tk_tb_global_contract_fail
    cmp byte ptr [rsi + 134], 0
    jne tk_tb_global_contract_fail
    inc rsi
    call tk_tb_a_hex64
    add rsi, 65
    call tk_tb_a_hex64
    sub rsi, 66
    ret
tk_tb_a_record_name:
    cmp rdx, 69
    jne tk_tb_global_contract_fail
    lea rsi, [r12 + rax]
    call tk_tb_a_hex64
    cmp dword ptr [rsi + 64], 0x6f736a2e
    jne tk_tb_global_contract_fail
    cmp byte ptr [rsi + 68], 110
    jne tk_tb_global_contract_fail
    cmp byte ptr [rsi + 69], 0
    jne tk_tb_global_contract_fail
    ret
tk_tb_a_hex64:
    xor r8d, r8d
tk_tb_a_hex_loop:
    mov dl, [rsi + r8]
    cmp dl, 48
    jb tk_tb_global_contract_fail
    cmp dl, 57
    jbe tk_tb_a_hex_good
    cmp dl, 97
    jb tk_tb_global_contract_fail
    cmp dl, 102
    ja tk_tb_global_contract_fail
tk_tb_a_hex_good:
    inc r8d
    cmp r8d, 64
    jne tk_tb_a_hex_loop
    ret
tk_tb_a_open_effect:
    cmp qword ptr [r14 + 48], 0
    jne tk_tb_global_contract_fail
    mov rcx, [r14 + 24]
    cmp rcx, 1
    je tk_tb_a_open_slot_ok
    cmp rcx, 2
    je tk_tb_a_open_slot_ok
    cmp rcx, 5
    je tk_tb_a_open_slot_ok
    cmp rcx, 6
    jne tk_tb_global_contract_fail
tk_tb_a_open_slot_ok:
    cmp qword ptr [r15 + rcx*8 + 128], -1
    jne tk_tb_global_contract_fail
    call tk_tb_a_name_span
    mov rdi, [r15 + 128]
    mov edx, 0xa0800
    xor r10d, r10d
    jmp tk_tb_a_issue_open
tk_tb_a_scan_open_effect:
    cmp qword ptr [r14 + 24], 3
    jne tk_tb_global_contract_fail
    cmp qword ptr [r15 + 152], -1
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 32], tk_tb_a_DOT
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 40], 1
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 48], 0
    jne tk_tb_global_contract_fail
    cmp qword ptr [r12 + tk_tb_a_DOT], 46
    jne tk_tb_global_contract_fail
    mov rdi, [r15 + 128]
    lea rsi, [r12 + tk_tb_a_DOT]
    mov edx, 0xb0000
    xor r10d, r10d
tk_tb_a_issue_open:
    mov eax, 257
    syscall
    test rax, rax
    js tk_tb_a_effect_error
    cmp rax, 0x7fffffff
    ja tk_tb_global_contract_fail
    mov rcx, [r14 + 24]
    mov [r15 + rcx*8 + 128], rax
    mov [r14 + 72], rcx
    jmp tk_tb_a_acknowledge
tk_tb_a_read_effect:
    call tk_tb_a_live_slot
    cmp rcx, 1
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 48], 0
    jne tk_tb_global_contract_fail
    mov rax, [r12 + 88]
    cmp rax, 2048
    ja tk_tb_global_contract_fail
    lea rsi, [rax + tk_tb_a_READ_BYTES]
    cmp rsi, [r14 + 32]
    jne tk_tb_global_contract_fail
    mov edx, 2049
    sub rdx, rax
    cmp rdx, [r14 + 40]
    jne tk_tb_global_contract_fail
    add rsi, r12
    xor eax, eax
    syscall
    jmp tk_tb_a_value_effect
tk_tb_a_sync_effect:
    call tk_tb_a_zero_span
    call tk_tb_a_live_slot
    test rcx, rcx
    jnz tk_tb_global_contract_fail
    mov eax, 74
    syscall
    test rax, rax
    js tk_tb_a_effect_error
    jmp tk_tb_a_acknowledge
tk_tb_a_unlink_effect:
    cmp qword ptr [r14 + 24], 0
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 32], tk_tb_a_CLEAN_NAME
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 48], 0
    jne tk_tb_global_contract_fail
    call tk_tb_a_name_span
    mov rdi, [r15 + 128]
    xor edx, edx
    mov eax, 263
    syscall
    test rax, rax
    js tk_tb_a_effect_error
    jmp tk_tb_a_acknowledge
tk_tb_a_close_effect:
    call tk_tb_a_zero_span
    call tk_tb_a_live_slot
    test rcx, rcx
    jz tk_tb_global_contract_fail
    mov qword ptr [r15 + rcx*8 + 128], -1
    mov eax, 3
    syscall
    test rax, rax
    js tk_tb_a_effect_error
    jmp tk_tb_a_acknowledge
tk_tb_a_duplicate_effect:
    cmp qword ptr [r14 + 24], 4
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 32], 0
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 40], 0
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 48], 3
    jne tk_tb_global_contract_fail
    cmp qword ptr [r15 + 160], -1
    jne tk_tb_global_contract_fail
    mov rdi, [r15 + 152]
    test rdi, rdi
    js tk_tb_global_contract_fail
    mov esi, 1030
    xor edx, edx
    mov eax, 72
    syscall
    test rax, rax
    js tk_tb_a_effect_error
    mov [r15 + 160], rax
    mov qword ptr [r14 + 72], 4
    jmp tk_tb_a_acknowledge
tk_tb_a_flags_effect:
    call tk_tb_a_zero_span
    call tk_tb_a_live_slot
    cmp rcx, 4
    jne tk_tb_global_contract_fail
    mov esi, 3
    xor edx, edx
    mov eax, 72
    syscall
    jmp tk_tb_a_value_effect
tk_tb_a_directory_effect:
    call tk_tb_a_live_slot
    cmp rcx, 4
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 32], tk_tb_a_DIR_BYTES
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 48], 0
    jne tk_tb_global_contract_fail
    mov rdx, [r14 + 40]
    cmp rdx, 32768
    jb tk_tb_global_contract_fail
    cmp rdx, 1048576
    ja tk_tb_global_contract_fail
    cmp rdx, [r12 + 136]
    jne tk_tb_global_contract_fail
    lea rsi, [r12 + tk_tb_a_DIR_BYTES]
    mov eax, 217
    syscall
tk_tb_a_value_effect:
    test rax, rax
    js tk_tb_a_effect_error
    mov [r14 + 72], rax
    jmp tk_tb_a_acknowledge
tk_tb_a_effect_error:
    cmp rax, -4095
    jb tk_tb_global_contract_fail
    neg rax
    mov [r14 + 80], rax
tk_tb_a_acknowledge:
    mov rax, [r12 + tk_tb_a_ACTION + 8]
    mov [r12 + tk_tb_a_ACTION + 64], rax
    jmp tk_tb_a_resume_owner
tk_tb_a_owner_result:
    mov ecx, 1
tk_tb_a_check_slots:
    cmp qword ptr [r15 + rcx*8 + 128], -1
    jne tk_tb_global_contract_fail
    inc ecx
    cmp ecx, 7
    jne tk_tb_a_check_slots
    cmp qword ptr [r12 + 8], 0
    jne tk_tb_global_contract_fail
    mov [r15 + 32], eax
    cmp eax, tk_tb_a_OUTPUT_CAP
    jbe tk_tb_a_normal_result
    cmp eax, 0xffffffff
    je tk_tb_a_result_header
    cmp eax, 0xfffffffe
    jne tk_tb_global_contract_fail
    jmp tk_tb_a_result_header
tk_tb_a_normal_result:
    cmp eax, 32
    jb tk_tb_global_contract_fail
tk_tb_a_result_header:
    mov eax, [r15 + 32]
    cmp eax, 32
    jb tk_tb_global_contract_fail
    cmp eax, 512
    ja tk_tb_global_contract_fail
    mov qword ptr [r15 + 128], -1
    mov ebx, eax
    mov rdi, [rsp + 8]
    lea rsi, [r15 + tk_tb_a_OUTPUT]
    mov ecx, eax
    rep movsb
    mov eax, ebx
    add rsp, 24
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

tk_tb_shared_entropy_entry:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp, 24
    mov [rsp], rdi
    mov [rsp + 8], rdx
    mov [rsp + 16], rsi
    mov rax, [r15 + 4000]
    mov r15, [rax + tk_tb_I_GLOBAL]
    mov r15, [r15 + tk_tb_G_ENTROPY]
    mov [r15 + 4000], rax
    mov r13, r15
    lea r12, [r15 + 16384]
    lea rdi, [r15 + 4096]
    mov esi, 4096
    mov edx, 3
    mov eax, 10
    syscall
    test rax, rax
    jnz tk_tb_global_io_fail
    lea rdi, [r15 + 4096]
    mov rsi, [rsp]
    mov rcx, [rsp + 16]
    mov [r15 + 24], rcx
    rep movsb
    lea rdi, [r15 + 4096]
    mov esi, 4096
    mov edx, 1
    mov eax, 10
    syscall
    test rax, rax
    jnz tk_tb_global_io_fail
tk_tb_entropy_resume:
    lea rdi, [r15 + 4096]
    mov esi, 24
    lea rdx, [r15 + 8192]
    mov ecx, 32
    mov r8, r12
    mov r9d, 1024
    call qword ptr [rip + tk_ticket_backend_entropy_image]
    mov ecx, eax
    cmp rax, rcx
    jne tk_tb_global_contract_fail
    cmp eax, 0xfffffff0
    jne tk_tb_entropy_result
    lea r14, [r12 + 256]
    mov rax, 0x3230544e45414948
    cmp [r14], rax
    jne tk_tb_global_contract_fail
    mov rax, [r15 + 64]
    inc rax
    jz tk_tb_global_contract_fail
    cmp [r14 + 8], rax
    jne tk_tb_global_contract_fail
    cmp [r12 + 24], rax
    jne tk_tb_global_contract_fail
    mov [r15 + 64], rax
    mov rax, [r14 + 32]
    or rax, [r14 + 48]
    or rax, [r14 + 56]
    or rax, [r14 + 64]
    or rax, [r14 + 72]
    jnz tk_tb_global_contract_fail
    cmp qword ptr [r12 + 8], 32
    jne tk_tb_global_contract_fail
    mov rax, [r14 + 40]
    cmp rax, [r12]
    jne tk_tb_global_contract_fail
    cmp rax, 1
    je tk_tb_entropy_probe
    cmp rax, 2
    je tk_tb_entropy_direct
    cmp rax, 7
    je tk_tb_entropy_read
    mov rcx, [r14 + 16]
    or rcx, [r14 + 24]
    jnz tk_tb_global_contract_fail
    cmp rax, 3
    je tk_tb_entropy_random_open
    cmp rax, 4
    je tk_tb_entropy_poll
    cmp rax, 5
    je tk_tb_entropy_random_close
    cmp rax, 6
    je tk_tb_entropy_urandom_open
    jmp tk_tb_global_contract_fail
tk_tb_entropy_probe:
    cmp qword ptr [r14 + 16], 512
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 24], 0
    jne tk_tb_global_contract_fail
    lea rdi, [r12 + 512]
    xor esi, esi
    xor edx, edx
    mov eax, 318
    syscall
    jmp tk_tb_entropy_value
tk_tb_entropy_span:
    mov rcx, [r12 + 16]
    cmp rcx, 32
    jae tk_tb_global_contract_fail
    lea rsi, [rcx + 512]
    cmp rsi, [r14 + 16]
    jne tk_tb_global_contract_fail
    mov edx, 32
    sub rdx, rcx
    cmp rdx, [r14 + 24]
    jne tk_tb_global_contract_fail
    add rsi, r12
    ret
tk_tb_entropy_direct:
    call tk_tb_entropy_span
    mov rdi, rsi
    mov rsi, rdx
    xor edx, edx
    mov eax, 318
    syscall
    jmp tk_tb_entropy_value
tk_tb_entropy_read:
    call tk_tb_entropy_span
    mov rdi, [r15 + 152]
    test rdi, rdi
    js tk_tb_global_contract_fail
    xor eax, eax
    syscall
    jmp tk_tb_entropy_value
tk_tb_entropy_random_open:
    cmp qword ptr [r15 + 160], -1
    jne tk_tb_global_contract_fail
    lea rsi, [rip + tk_tb_entropy_random_path]
    mov edi, -100
    mov edx, 0x80000
    xor r10d, r10d
    mov eax, 257
    syscall
    test rax, rax
    js tk_tb_entropy_error
    mov [r15 + 160], rax
    jmp tk_tb_entropy_ack
tk_tb_entropy_urandom_open:
    cmp qword ptr [r15 + 152], -1
    jne tk_tb_global_contract_fail
    lea rsi, [rip + tk_tb_entropy_urandom_path]
    mov edi, -100
    mov edx, 0x80000
    xor r10d, r10d
    mov eax, 257
    syscall
    test rax, rax
    js tk_tb_entropy_error
    mov [r15 + 152], rax
    jmp tk_tb_entropy_ack
tk_tb_entropy_poll:
    mov rax, [r15 + 160]
    test rax, rax
    js tk_tb_global_contract_fail
    mov [r15 + 768], eax
    mov dword ptr [r15 + 772], 1
    lea rdi, [r15 + 768]
    mov esi, 1
    mov rdx, -1
    mov eax, 7
    syscall
    jmp tk_tb_entropy_value
tk_tb_entropy_random_close:
    mov rdi, [r15 + 160]
    test rdi, rdi
    js tk_tb_global_contract_fail
    mov qword ptr [r15 + 160], -1
    mov eax, 3
    syscall
    jmp tk_tb_entropy_value
tk_tb_entropy_value:
    test rax, rax
    js tk_tb_entropy_error
    mov [r14 + 48], rax
    jmp tk_tb_entropy_ack
tk_tb_entropy_error:
    cmp rax, -4095
    jb tk_tb_global_contract_fail
    neg rax
    mov [r14 + 56], rax
tk_tb_entropy_ack:
    mov rax, [r14 + 8]
    mov [r14 + 64], rax
    mov qword ptr [r14 + 72], 1
    jmp tk_tb_entropy_resume
tk_tb_entropy_result:
    cmp eax, 32
    je tk_tb_entropy_result_code
    cmp eax, 0xfffffffd
    je tk_tb_entropy_result_code
    cmp eax, 0xfffffffc
    jne tk_tb_global_contract_fail
tk_tb_entropy_result_code:
    cmp qword ptr [r15 + 160], -1
    jne tk_tb_global_contract_fail
    cmp qword ptr [r12 + 48], 0
    jne tk_tb_global_contract_fail
    cmp qword ptr [r12 + 40], 0
    jne tk_tb_entropy_cached
    cmp qword ptr [r15 + 152], -1
    jne tk_tb_global_contract_fail
    jmp tk_tb_entropy_restore
tk_tb_entropy_cached:
    cmp qword ptr [r12 + 40], 1
    jne tk_tb_global_contract_fail
    cmp qword ptr [r15 + 152], -1
    je tk_tb_global_contract_fail
tk_tb_entropy_restore:
    mov ebx, eax
    mov rdi, [rsp + 8]
    lea rsi, [r15 + 8192]
    xor ecx, ecx
    cmp eax, 32
    jne tk_tb_entropy_copy_ready
    mov ecx, 32
tk_tb_entropy_copy_ready:
    rep movsb
    mov eax, ebx
    add rsp, 24
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret
tk_tb_entropy_random_path:
    .asciz "/dev/random"
tk_tb_entropy_urandom_path:
    .asciz "/dev/urandom"

tk_tb_visitor_entry:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp, 24
    mov [rsp], rdi
    mov [rsp + 8], rdx
    mov [rsp + 16], rsi
    mov rax, [r15 + 4000]
    lea r15, [rax + tk_tb_V_BASE]
    mov r13, r15
    lea r12, [r15 + 12288]
    lea rdi, [r15 + 4096]
    mov esi, 4096
    mov edx, 3
    mov eax, 10
    syscall
    test rax, rax
    jnz tk_tb_global_io_fail
    lea rdi, [r15 + 4096]
    mov rsi, [rsp]
    mov rcx, [rsp + 16]
    mov [r15 + 24], rcx
    rep movsb
    lea rdi, [r15 + 4096]
    mov esi, 4096
    mov edx, 1
    mov eax, 10
    syscall
    test rax, rax
    jnz tk_tb_global_io_fail
    jmp tk_tb_visitor_body
tk_tb_visitor_body:
    # This stderr stream is the declared qualification callback observation.
    mov rax, [r15 + 24]
    mov [r15 + 40], rax
    lea rsi, [r15 + 40]
    mov edx, 8
    call tk_tb_visitor_trace
    lea rsi, [r15 + 4096]
    mov rdx, [r15 + 24]
    call tk_tb_visitor_trace
    lea rdi, [r15 + 4096]
    mov rsi, [r15 + 24]
    lea rdx, [r15 + 8192]
    mov ecx, 64
    mov r8, r12
    mov r9d, 4096
    call qword ptr [rip + tk_ticket_backend_visitor_image]
    cmp rax, 64
    jne tk_tb_global_contract_fail
    jmp tk_tb_visitor_return
tk_tb_visitor_trace:
    test rdx, rdx
    jz tk_tb_visitor_trace_done
    mov edi, 2
    mov eax, 1
    syscall
    cmp rax, -4
    je tk_tb_visitor_trace
    test rax, rax
    jle tk_tb_global_io_fail
    add rsi, rax
    sub rdx, rax
    jmp tk_tb_visitor_trace
tk_tb_visitor_trace_done:
    ret

tk_tb_visitor_return:
    mov ebx, eax
    mov rdi, [rsp + 8]
    lea rsi, [r15 + 8192]
    mov ecx, eax
    rep movsb
    mov eax, ebx
    add rsp, 24
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

/* Resolve only HIA-created live lease and directory tokens. Never raw input FDs. */
tk_tb_save_checked_node:
    cmp rax, 16842752
    jb tk_tb_global_contract_fail
    mov r10, [r11 + 144]
    cmp r10, 16842752
    jb tk_tb_global_contract_fail
    cmp r10, [r13 + tk_tb_G_WORK_BYTES]
    ja tk_tb_global_contract_fail
    cmp rax, r10
    jae tk_tb_global_contract_fail
    sub r10, rax
    cmp r10, 96
    jb tk_tb_global_contract_fail
    mov rdi, rax
    push rcx
    push rdx
    sub rax, 16842752
    xor edx, edx
    mov ecx, 96
    div rcx
    test rdx, rdx
    jnz tk_tb_global_contract_fail
    pop rdx
    pop rcx
    lea rax, [r11 + rdi]
    ret
tk_tb_save_find_id:
    test rdx, rdx
    jz tk_tb_global_contract_fail
    mov r9, [r11 + 144]
    cmp r9, 16842752
    jb tk_tb_global_contract_fail
    sub r9, 16842752
tk_tb_save_find_id_next:
    test rcx, rcx
    jz tk_tb_global_contract_fail
    cmp r9, 96
    jb tk_tb_global_contract_fail
    mov rax, rcx
    call tk_tb_save_checked_node
    cmp [rax], r8
    jne tk_tb_global_contract_fail
    cmp [rax + 8], rdx
    je tk_tb_save_find_id_return
    mov rcx, [rax + 16]
    sub r9, 96
    jmp tk_tb_save_find_id_next
tk_tb_save_find_id_return:
    ret

tk_tb_raw_record_write_entry:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp, 40
    mov [rsp], rdi
    mov [rsp + 8], rdx
    mov [rsp + 16], rsi
    mov r13, [r15 + 4000]
    cmp [r13 + tk_tb_I_GLOBAL], r13
    jne tk_tb_global_contract_fail
    mov r11, [r13 + tk_tb_G_WORK]
    cmp qword ptr [r11 + 8], 0
    jne tk_tb_global_contract_fail
    mov rax, 0x3130545351415248
    cmp [r11], rax
    jne tk_tb_global_contract_fail
    mov rcx, [r11 + 168]
    mov rdx, [r15 + tk_tb_S_OWNER + 56]
    mov r8d, 2
    call tk_tb_save_find_id
    mov rax, [rax + 24]
    mov [rsp + 24], rax
    call tk_tb_save_checked_node
    cmp qword ptr [rax], 1
    jne tk_tb_global_contract_fail
    cmp qword ptr [rax + 24], 0
    je tk_tb_global_contract_fail
    cmp qword ptr [rax + 32], 0
    je tk_tb_global_contract_fail
    cmp qword ptr [rax + 72], 1
    jne tk_tb_global_contract_fail
    cmp qword ptr [rax + 88], 0
    je tk_tb_global_contract_fail
    mov rbx, rax
    mov rcx, [r11 + 176]
    mov rdx, [r14 + 24]
    mov r8d, 3
    call tk_tb_save_find_id
    mov rcx, [rsp + 24]
    cmp [rax + 24], rcx
    jne tk_tb_global_contract_fail
    mov rax, [rax + 32]
    mov [rsp + 32], rax
    mov rcx, [rbx + 32]
    mov r15, r13
    call tk_tb_registry_find_instance
    mov rbp, r8
    cmp qword ptr [rbp + tk_tb_R_OWNER + 8], 0
    jne tk_tb_global_contract_fail
    mov rdx, [rbx + 88]
    xor ecx, ecx
tk_tb_rw_find_lease:
    cmp [rbp + tk_tb_R_OWNER + 65536 + rcx*8], rdx
    je tk_tb_rw_lease_found
    inc ecx
    cmp ecx, 1024
    jb tk_tb_rw_find_lease
    jmp tk_tb_global_contract_fail
tk_tb_rw_lease_found:
    mov rdx, [rsp + 32]
    test rdx, rdx
    jz tk_tb_global_contract_fail
    mov ecx, 2
tk_tb_rw_find_directory:
    cmp [rbp + tk_tb_R_OWNER + 73728 + rcx*8], rdx
    je tk_tb_rw_directory_found
    inc ecx
    cmp ecx, 3
    jne tk_tb_rw_directory_continue
    inc ecx
tk_tb_rw_directory_continue:
    cmp ecx, 260
    jb tk_tb_rw_find_directory
    jmp tk_tb_global_contract_fail
tk_tb_rw_directory_found:
    cmp byte ptr [rbp + tk_tb_R_OWNER + 56320 + rcx], 1
    jne tk_tb_global_contract_fail
    mov rbx, [rbp + tk_tb_ROOT_FDS + rcx*8]
    test rbx, rbx
    js tk_tb_global_contract_fail
    mov r15, [r13 + tk_tb_G_WRITE]
    cmp qword ptr [r15 + 128], -1
    jne tk_tb_global_contract_fail
    mov [r15 + 128], rbx
    lea rdi, [r15 + 4096]
    mov esi, 1048576
    mov edx, 3
    mov eax, 10
    syscall
    test rax, rax
    jnz tk_tb_global_io_fail
    lea rdi, [r15 + 4096]
    mov rsi, [rsp]
    mov rcx, [rsp + 16]
    cmp rcx, 1048576
    ja tk_tb_global_contract_fail
    mov [r15 + 24], rcx
    rep movsb
    lea rdi, [r15 + 4096]
    mov esi, 1048576
    mov edx, 1
    mov eax, 10
    syscall
    test rax, rax
    jnz tk_tb_global_io_fail
    lea r12, [r15 + 6291456]
    lea r13, [r15 + 2097152]
    jmp tk_tb_rw_resume_write

.equ tk_tb_rw_INPUT, 4096
.equ tk_tb_rw_INPUT_CAP, 1048576
.equ tk_tb_rw_OUTPUT, 1056768
.equ tk_tb_rw_OUTPUT_CAP, 512
.equ tk_tb_rw_OWNER, 6291456
.equ tk_tb_rw_WRITE_OWNER, 2097152
.equ tk_tb_rw_W_STAT, 8192
.equ tk_tb_rw_W_FILENAME, 65536
.equ tk_tb_rw_W_TEMPORARY, 73728
.equ tk_tb_rw_W_NEW_BYTES, 32768
.equ tk_tb_rw_W_CHILD_REQUEST, 1048576
.equ tk_tb_rw_W_CHILD_REPLY, 16384
.equ tk_tb_rw_JSON_WORK, 10485760
.equ tk_tb_rw_MAP_SIZE, 11538432
.equ tk_tb_rw_ACTION, 256
.equ tk_tb_rw_STAT, 1024
.equ tk_tb_rw_FILENAME, 4096
.equ tk_tb_rw_TEMPORARY, 4224
.equ tk_tb_rw_CLEAN_NAME, 4480
.equ tk_tb_rw_CLEAN_TARGET, 4800
.equ tk_tb_rw_DOT, 4928
.equ tk_tb_rw_CHILD_REQUEST, 8192
.equ tk_tb_rw_CHILD_REPLY, 12288
.equ tk_tb_rw_READ_BYTES, 24576
.equ tk_tb_rw_DIR_BYTES, 65536
tk_tb_rw_resume_owner:
    lea rdi, [r13 + tk_tb_rw_W_CHILD_REQUEST]
    mov rsi, [r13 + tk_tb_rw_ACTION + 40]
    lea rdx, [r13 + tk_tb_rw_W_CHILD_REPLY]
    mov ecx, tk_tb_rw_OUTPUT_CAP
    mov r8, r12
    mov r9d, 4194304
    call qword ptr [rip + tk_ticket_backend_record_image]
    cmp eax, 0xfffffff0
    jne tk_tb_rw_owner_result
    lea r14, [r12 + tk_tb_rw_ACTION]
    mov rax, 0x3130304152415248
    cmp [r14], rax
    jne tk_tb_global_contract_fail
    mov rax, [r15 + 16]
    inc rax
    jz tk_tb_global_contract_fail
    cmp [r14 + 8], rax
    jne tk_tb_global_contract_fail
    cmp [r12 + 16], rax
    jne tk_tb_global_contract_fail
    mov [r15 + 16], rax
    mov rax, [r14 + 64]
    or rax, [r14 + 72]
    or rax, [r14 + 80]
    or rax, [r14 + 88]
    jnz tk_tb_global_contract_fail
    mov rax, [r14 + 16]
    cmp rax, 100
    je tk_tb_rw_json_effect
    cmp qword ptr [r14 + 56], 0
    jne tk_tb_global_contract_fail
    cmp rax, 1
    je tk_tb_rw_stat_effect
    cmp rax, 2
    je tk_tb_rw_open_effect
    cmp rax, 3
    je tk_tb_rw_read_effect
    cmp rax, 5
    je tk_tb_rw_sync_effect
    cmp rax, 8
    je tk_tb_rw_unlink_effect
    cmp rax, 9
    je tk_tb_rw_close_effect
    cmp rax, 10
    je tk_tb_rw_scan_open_effect
    cmp rax, 11
    je tk_tb_rw_duplicate_effect
    cmp rax, 12
    je tk_tb_rw_flags_effect
    cmp rax, 13
    je tk_tb_rw_directory_effect
    jmp tk_tb_global_contract_fail
tk_tb_rw_json_effect:
    cmp qword ptr [r14 + 24], 0
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 32], tk_tb_rw_CHILD_REQUEST
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 40], 24
    jb tk_tb_global_contract_fail
    cmp qword ptr [r14 + 40], 2072
    ja tk_tb_global_contract_fail
    cmp qword ptr [r14 + 48], tk_tb_rw_CHILD_REPLY
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 56], 4096
    jne tk_tb_global_contract_fail
    lea rdi, [r12 + tk_tb_rw_CHILD_REQUEST]
    mov rsi, [r14 + 40]
    lea rdx, [r12 + tk_tb_rw_CHILD_REPLY]
    mov ecx, 4096
    lea r8, [r15 + tk_tb_rw_JSON_WORK]
    mov r9d, 1048576
    call qword ptr [rip + tk_ticket_backend_json_image]
    mov [r12 + tk_tb_rw_ACTION + 72], rax
    jmp tk_tb_rw_acknowledge
tk_tb_rw_live_slot:
    mov rcx, [r14 + 24]
    cmp rcx, 6
    ja tk_tb_global_contract_fail
    mov rdi, [r15 + rcx*8 + 128]
    test rdi, rdi
    js tk_tb_global_contract_fail
    ret
tk_tb_rw_zero_span:
    mov rax, [r14 + 32]
    or rax, [r14 + 40]
    or rax, [r14 + 48]
    jnz tk_tb_global_contract_fail
    ret
tk_tb_rw_stat_effect:
    call tk_tb_rw_live_slot
    test rcx, rcx
    jz tk_tb_global_contract_fail
    cmp qword ptr [r14 + 32], tk_tb_rw_STAT
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 40], 152
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 48], 1
    ja tk_tb_global_contract_fail
    lea rsi, [r12 + tk_tb_rw_STAT]
    mov eax, 5
    syscall
    test rax, rax
    js tk_tb_rw_effect_error
    cmp qword ptr [r14 + 48], 1
    je tk_tb_rw_acknowledge
    mov eax, 107
    syscall
    mov [r12 + tk_tb_rw_STAT + 144], rax
    jmp tk_tb_rw_acknowledge
tk_tb_rw_name_span:
    mov rax, [r14 + 32]
    mov rdx, [r14 + 40]
    cmp rax, tk_tb_rw_FILENAME
    je tk_tb_rw_record_name
    cmp rax, tk_tb_rw_CLEAN_TARGET
    je tk_tb_rw_record_name
    cmp rax, tk_tb_rw_TEMPORARY
    je tk_tb_rw_staging_name
    cmp rax, tk_tb_rw_CLEAN_NAME
    jne tk_tb_global_contract_fail
tk_tb_rw_staging_name:
    cmp rdx, 134
    jne tk_tb_global_contract_fail
    lea rsi, [r12 + rax]
    cmp byte ptr [rsi], 46
    jne tk_tb_global_contract_fail
    cmp byte ptr [rsi + 65], 45
    jne tk_tb_global_contract_fail
    cmp dword ptr [rsi + 130], 0x706d742e
    jne tk_tb_global_contract_fail
    cmp byte ptr [rsi + 134], 0
    jne tk_tb_global_contract_fail
    inc rsi
    call tk_tb_rw_hex64
    add rsi, 65
    call tk_tb_rw_hex64
    sub rsi, 66
    ret
tk_tb_rw_record_name:
    cmp rdx, 69
    jne tk_tb_global_contract_fail
    lea rsi, [r12 + rax]
    call tk_tb_rw_hex64
    cmp dword ptr [rsi + 64], 0x6f736a2e
    jne tk_tb_global_contract_fail
    cmp byte ptr [rsi + 68], 110
    jne tk_tb_global_contract_fail
    cmp byte ptr [rsi + 69], 0
    jne tk_tb_global_contract_fail
    ret
tk_tb_rw_hex64:
    xor r8d, r8d
tk_tb_rw_hex_loop:
    mov dl, [rsi + r8]
    cmp dl, 48
    jb tk_tb_global_contract_fail
    cmp dl, 57
    jbe tk_tb_rw_hex_good
    cmp dl, 97
    jb tk_tb_global_contract_fail
    cmp dl, 102
    ja tk_tb_global_contract_fail
tk_tb_rw_hex_good:
    inc r8d
    cmp r8d, 64
    jne tk_tb_rw_hex_loop
    ret
tk_tb_rw_open_effect:
    cmp qword ptr [r14 + 48], 0
    jne tk_tb_global_contract_fail
    mov rcx, [r14 + 24]
    cmp rcx, 1
    je tk_tb_rw_open_slot_ok
    cmp rcx, 2
    je tk_tb_rw_open_slot_ok
    cmp rcx, 5
    je tk_tb_rw_open_slot_ok
    cmp rcx, 6
    jne tk_tb_global_contract_fail
tk_tb_rw_open_slot_ok:
    cmp qword ptr [r15 + rcx*8 + 128], -1
    jne tk_tb_global_contract_fail
    call tk_tb_rw_name_span
    mov rdi, [r15 + 128]
    mov edx, 0xa0800
    xor r10d, r10d
    jmp tk_tb_rw_issue_open
tk_tb_rw_scan_open_effect:
    cmp qword ptr [r14 + 24], 3
    jne tk_tb_global_contract_fail
    cmp qword ptr [r15 + 152], -1
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 32], tk_tb_rw_DOT
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 40], 1
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 48], 0
    jne tk_tb_global_contract_fail
    cmp qword ptr [r12 + tk_tb_rw_DOT], 46
    jne tk_tb_global_contract_fail
    mov rdi, [r15 + 128]
    lea rsi, [r12 + tk_tb_rw_DOT]
    mov edx, 0xb0000
    xor r10d, r10d
tk_tb_rw_issue_open:
    mov eax, 257
    syscall
    test rax, rax
    js tk_tb_rw_effect_error
    cmp rax, 0x7fffffff
    ja tk_tb_global_contract_fail
    mov rcx, [r14 + 24]
    mov [r15 + rcx*8 + 128], rax
    mov [r14 + 72], rcx
    jmp tk_tb_rw_acknowledge
tk_tb_rw_read_effect:
    call tk_tb_rw_live_slot
    cmp rcx, 1
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 48], 0
    jne tk_tb_global_contract_fail
    mov rax, [r12 + 88]
    cmp rax, 2048
    ja tk_tb_global_contract_fail
    lea rsi, [rax + tk_tb_rw_READ_BYTES]
    cmp rsi, [r14 + 32]
    jne tk_tb_global_contract_fail
    mov edx, 2049
    sub rdx, rax
    cmp rdx, [r14 + 40]
    jne tk_tb_global_contract_fail
    add rsi, r12
    xor eax, eax
    syscall
    jmp tk_tb_rw_value_effect
tk_tb_rw_sync_effect:
    call tk_tb_rw_zero_span
    call tk_tb_rw_live_slot
    test rcx, rcx
    jnz tk_tb_global_contract_fail
    mov eax, 74
    syscall
    test rax, rax
    js tk_tb_rw_effect_error
    jmp tk_tb_rw_acknowledge
tk_tb_rw_unlink_effect:
    cmp qword ptr [r14 + 24], 0
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 32], tk_tb_rw_CLEAN_NAME
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 48], 0
    jne tk_tb_global_contract_fail
    call tk_tb_rw_name_span
    mov rdi, [r15 + 128]
    xor edx, edx
    mov eax, 263
    syscall
    test rax, rax
    js tk_tb_rw_effect_error
    jmp tk_tb_rw_acknowledge
tk_tb_rw_close_effect:
    call tk_tb_rw_zero_span
    call tk_tb_rw_live_slot
    test rcx, rcx
    jz tk_tb_global_contract_fail
    mov qword ptr [r15 + rcx*8 + 128], -1
    mov eax, 3
    syscall
    test rax, rax
    js tk_tb_rw_effect_error
    jmp tk_tb_rw_acknowledge
tk_tb_rw_duplicate_effect:
    cmp qword ptr [r14 + 24], 4
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 32], 0
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 40], 0
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 48], 3
    jne tk_tb_global_contract_fail
    cmp qword ptr [r15 + 160], -1
    jne tk_tb_global_contract_fail
    mov rdi, [r15 + 152]
    test rdi, rdi
    js tk_tb_global_contract_fail
    mov esi, 1030
    xor edx, edx
    mov eax, 72
    syscall
    test rax, rax
    js tk_tb_rw_effect_error
    mov [r15 + 160], rax
    mov qword ptr [r14 + 72], 4
    jmp tk_tb_rw_acknowledge
tk_tb_rw_flags_effect:
    call tk_tb_rw_zero_span
    call tk_tb_rw_live_slot
    cmp rcx, 4
    jne tk_tb_global_contract_fail
    mov esi, 3
    xor edx, edx
    mov eax, 72
    syscall
    jmp tk_tb_rw_value_effect
tk_tb_rw_directory_effect:
    call tk_tb_rw_live_slot
    cmp rcx, 4
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 32], tk_tb_rw_DIR_BYTES
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 48], 0
    jne tk_tb_global_contract_fail
    mov rdx, [r14 + 40]
    cmp rdx, 32768
    jb tk_tb_global_contract_fail
    cmp rdx, 1048576
    ja tk_tb_global_contract_fail
    cmp rdx, [r12 + 136]
    jne tk_tb_global_contract_fail
    lea rsi, [r12 + tk_tb_rw_DIR_BYTES]
    mov eax, 217
    syscall
tk_tb_rw_value_effect:
    test rax, rax
    js tk_tb_rw_effect_error
    mov [r14 + 72], rax
    jmp tk_tb_rw_acknowledge
tk_tb_rw_effect_error:
    cmp rax, -4095
    jb tk_tb_global_contract_fail
    neg rax
    mov [r14 + 80], rax
tk_tb_rw_acknowledge:
    mov rax, [r12 + tk_tb_rw_ACTION + 8]
    mov [r12 + tk_tb_rw_ACTION + 64], rax
    jmp tk_tb_rw_resume_owner
tk_tb_rw_owner_result:
    mov ecx, 1
tk_tb_rw_check_slots:
    cmp qword ptr [r15 + rcx*8 + 128], -1
    jne tk_tb_global_contract_fail
    inc ecx
    cmp ecx, 7
    jne tk_tb_rw_check_slots
    cmp qword ptr [r12 + 8], 0
    jne tk_tb_global_contract_fail
    mov [r13 + tk_tb_rw_ACTION + 72], rax
    mov rax, [r13 + tk_tb_rw_ACTION + 8]
    mov [r13 + tk_tb_rw_ACTION + 64], rax
    jmp tk_tb_rw_resume_write
tk_tb_rw_resume_write:
    lea rdi, [r15 + tk_tb_rw_INPUT]
    mov rsi, [r15 + 24]
    lea rdx, [r15 + tk_tb_rw_OUTPUT]
    mov ecx, tk_tb_rw_OUTPUT_CAP
    mov r8, r13
    mov r9d, 4194304
    call qword ptr [rip + tk_ticket_backend_raw_write_image]
    cmp eax, 0xfffffff0
    jne tk_tb_rw_write_result
    lea r14, [r13 + tk_tb_rw_ACTION]
    mov rax, 0x3130304157415248
    cmp [r14], rax
    jne tk_tb_global_contract_fail
    mov rax, [r15 + 8]
    inc rax
    jz tk_tb_global_contract_fail
    cmp [r14 + 8], rax
    jne tk_tb_global_contract_fail
    cmp [r13 + 16], rax
    jne tk_tb_global_contract_fail
    mov [r15 + 8], rax
    mov rax, [r14 + 64]
    or rax, [r14 + 72]
    or rax, [r14 + 80]
    or rax, [r14 + 88]
    jnz tk_tb_global_contract_fail
    mov rax, [r14 + 16]
    cmp rax, 100
    je tk_tb_rw_w_read_start
    cmp qword ptr [r14 + 56], 0
    jne tk_tb_global_contract_fail
    cmp rax, 1
    je tk_tb_rw_w_stat
    cmp rax, 2
    je tk_tb_rw_w_open
    cmp rax, 4
    je tk_tb_rw_w_write
    cmp rax, 5
    je tk_tb_rw_w_sync
    cmp rax, 6
    je tk_tb_rw_w_link
    cmp rax, 7
    je tk_tb_rw_w_rename
    cmp rax, 8
    je tk_tb_rw_w_unlink
    cmp rax, 9
    je tk_tb_rw_w_close
    jmp tk_tb_global_contract_fail
tk_tb_rw_w_read_start:
    cmp qword ptr [r14 + 24], 0
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 32], tk_tb_rw_W_CHILD_REQUEST
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 40], 29
    jb tk_tb_global_contract_fail
    cmp qword ptr [r14 + 40], tk_tb_rw_INPUT_CAP
    ja tk_tb_global_contract_fail
    cmp qword ptr [r14 + 48], tk_tb_rw_W_CHILD_REPLY
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 56], 512
    jne tk_tb_global_contract_fail
    cmp qword ptr [r15 + 192], -1
    jne tk_tb_global_contract_fail
    jmp tk_tb_rw_resume_owner
tk_tb_rw_w_live:
    mov rcx, [r14 + 24]
    cmp rcx, 1
    ja tk_tb_global_contract_fail
    mov rdi, [r15 + 128]
    test rcx, rcx
    jz tk_tb_rw_w_live_check
    mov rdi, [r15 + 192]
tk_tb_rw_w_live_check:
    test rdi, rdi
    js tk_tb_global_contract_fail
    ret
tk_tb_rw_w_stat:
    call tk_tb_rw_w_live
    cmp qword ptr [r14 + 32], tk_tb_rw_W_STAT
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 40], 152
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 48], 0
    jne tk_tb_global_contract_fail
    lea rsi, [r13 + tk_tb_rw_W_STAT]
    mov eax, 5
    syscall
    test rax, rax
    js tk_tb_rw_w_error
    mov eax, 107
    syscall
    mov [r13 + tk_tb_rw_W_STAT + 144], rax
    jmp tk_tb_rw_w_acknowledge
tk_tb_rw_w_names:
    cmp qword ptr [r15 + 24], 288
    jb tk_tb_global_contract_fail
    mov rbx, [r15 + tk_tb_rw_INPUT + 104]
    cmp rbx, 2048
    ja tk_tb_global_contract_fail
    mov rsi, [r15 + tk_tb_rw_INPUT + 96]
    cmp rsi, 256
    jne tk_tb_global_contract_fail
    lea rsi, [r15 + tk_tb_rw_INPUT + 288]
    lea rdi, [r13 + tk_tb_rw_W_FILENAME]
    mov rcx, rbx
    # A zero-length comparison preserves flags; make equality explicit.
    cmp rcx, rcx
    repe cmpsb
    jne tk_tb_global_contract_fail
    mov rax, 0x6e6f736a2e
    cmp [rdi], rax
    jne tk_tb_global_contract_fail
    lea rax, [rbx + 5]
    cmp [r13 + 120], rax
    jne tk_tb_global_contract_fail
    cmp byte ptr [r13 + tk_tb_rw_W_TEMPORARY], 46
    jne tk_tb_global_contract_fail
    lea rsi, [r15 + tk_tb_rw_INPUT + 288]
    lea rdi, [r13 + tk_tb_rw_W_TEMPORARY + 1]
    mov rcx, rbx
    # A zero-length comparison preserves flags; make equality explicit.
    cmp rcx, rcx
    repe cmpsb
    jne tk_tb_global_contract_fail
    cmp byte ptr [rdi], 45
    jne tk_tb_global_contract_fail
    inc rdi
    lea rsi, [r15 + tk_tb_rw_INPUT + 288]
    mov rcx, rbx
    # A zero-length comparison preserves flags; make equality explicit.
    cmp rcx, rcx
    repe cmpsb
    jne tk_tb_global_contract_fail
    cmp qword ptr [rdi], 0x706d742e
    jne tk_tb_global_contract_fail
    lea rax, [rbx*2 + 6]
    cmp [r13 + 128], rax
    jne tk_tb_global_contract_fail
    xor ecx, ecx
tk_tb_rw_w_name_no_nul:
    cmp rcx, rbx
    je tk_tb_rw_w_names_ok
    cmp byte ptr [r15 + tk_tb_rw_INPUT + 288 + rcx], 0
    je tk_tb_global_contract_fail
    inc rcx
    jmp tk_tb_rw_w_name_no_nul
tk_tb_rw_w_names_ok:
    ret
tk_tb_rw_w_temporary_span:
    call tk_tb_rw_w_names
    cmp qword ptr [r14 + 32], tk_tb_rw_W_TEMPORARY
    jne tk_tb_global_contract_fail
    mov rax, [r13 + 128]
    cmp rax, [r14 + 40]
    jne tk_tb_global_contract_fail
    lea rsi, [r13 + tk_tb_rw_W_TEMPORARY]
    ret
tk_tb_rw_w_open:
    cmp qword ptr [r14 + 24], 1
    jne tk_tb_global_contract_fail
    cmp qword ptr [r15 + 192], -1
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 48], 1
    jne tk_tb_global_contract_fail
    call tk_tb_rw_w_temporary_span
    mov rdi, [r15 + 128]
    mov edx, 0xa00c1
    mov r10d, 0600
    mov eax, 257
    syscall
    test rax, rax
    js tk_tb_rw_w_error
    cmp rax, 0x7fffffff
    ja tk_tb_global_contract_fail
    mov [r15 + 192], rax
    mov qword ptr [r14 + 72], 1
    jmp tk_tb_rw_w_acknowledge
tk_tb_rw_w_write:
    call tk_tb_rw_w_live
    cmp rcx, 1
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 48], 0
    jne tk_tb_global_contract_fail
    mov rdx, [r13 + 96]
    cmp rdx, 2048
    ja tk_tb_global_contract_fail
    mov rax, [r13 + 104]
    cmp rax, rdx
    jae tk_tb_global_contract_fail
    lea rsi, [rax + tk_tb_rw_W_NEW_BYTES]
    cmp rsi, [r14 + 32]
    jne tk_tb_global_contract_fail
    sub rdx, rax
    cmp rdx, [r14 + 40]
    jne tk_tb_global_contract_fail
    add rsi, r13
    mov eax, 1
    syscall
    test rax, rax
    js tk_tb_rw_w_error
    mov [r14 + 72], rax
    jmp tk_tb_rw_w_acknowledge
tk_tb_rw_w_sync:
    call tk_tb_rw_zero_span
    call tk_tb_rw_w_live
    mov eax, 74
    syscall
    test rax, rax
    js tk_tb_rw_w_error
    jmp tk_tb_rw_w_acknowledge
tk_tb_rw_w_publication:
    cmp qword ptr [r14 + 24], 0
    jne tk_tb_global_contract_fail
    cmp qword ptr [r15 + 192], -1
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 48], tk_tb_rw_W_FILENAME
    jne tk_tb_global_contract_fail
    call tk_tb_rw_w_temporary_span
    mov rdi, [r15 + 128]
    mov rdx, rdi
    lea r10, [r13 + tk_tb_rw_W_FILENAME]
    ret
tk_tb_rw_w_link:
    call tk_tb_rw_w_publication
    xor r8d, r8d
    mov eax, 265
    syscall
    test rax, rax
    js tk_tb_rw_w_error
    jmp tk_tb_rw_w_acknowledge
tk_tb_rw_w_rename:
    call tk_tb_rw_w_publication
    mov eax, 264
    syscall
    test rax, rax
    js tk_tb_rw_w_error
    jmp tk_tb_rw_w_acknowledge
tk_tb_rw_w_unlink:
    cmp qword ptr [r14 + 24], 0
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 48], 0
    jne tk_tb_global_contract_fail
    call tk_tb_rw_w_temporary_span
    mov rdi, [r15 + 128]
    xor edx, edx
    mov eax, 263
    syscall
    test rax, rax
    js tk_tb_rw_w_error
    jmp tk_tb_rw_w_acknowledge
tk_tb_rw_w_close:
    call tk_tb_rw_zero_span
    call tk_tb_rw_w_live
    cmp rcx, 1
    jne tk_tb_global_contract_fail
    mov qword ptr [r15 + 192], -1
    mov eax, 3
    syscall
    test rax, rax
    js tk_tb_rw_w_error
    jmp tk_tb_rw_w_acknowledge
tk_tb_rw_w_error:
    cmp rax, -4095
    jb tk_tb_global_contract_fail
    neg rax
    mov [r14 + 80], rax
tk_tb_rw_w_acknowledge:
    mov rax, [r13 + tk_tb_rw_ACTION + 8]
    mov [r13 + tk_tb_rw_ACTION + 64], rax
    jmp tk_tb_rw_resume_write
tk_tb_rw_write_result:
    mov ecx, eax
    cmp rax, rcx
    jne tk_tb_global_contract_fail
    mov ebx, eax
    cmp qword ptr [r15 + 192], -1
    jne tk_tb_global_contract_fail
    cmp qword ptr [r13 + 8], 0
    jne tk_tb_global_contract_fail
    mov ecx, 1
tk_tb_rw_write_final_slots:
    cmp qword ptr [r15 + 128 + rcx*8], -1
    jne tk_tb_global_contract_fail
    inc ecx
    cmp ecx, 7
    jb tk_tb_rw_write_final_slots
    mov qword ptr [r15 + 128], -1
    cmp ebx, 0xffffffff
    je tk_tb_rw_write_restore
    cmp ebx, 0xfffffffe
    je tk_tb_rw_write_restore
    cmp ebx, 32
    jne tk_tb_global_contract_fail
    mov rdi, [rsp + 8]
    lea rsi, [r15 + tk_tb_rw_OUTPUT]
    mov ecx, ebx
    rep movsb
tk_tb_rw_write_restore:
    mov eax, ebx
    add rsp, 40
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

/* Private fixed composition. No request supplies a raw descriptor or pointer. */
.equ tk_tb_G_COLD, 640
.equ tk_tb_G_STAMP, 648
.equ tk_tb_G_ENTRIES, 656
.equ tk_tb_G_HOT_FDS, 672
.equ tk_tb_G_HOT_ARGV, 816
.equ tk_tb_C_INPUT, 4096
.equ tk_tb_C_OUTPUT, 1052672
.equ tk_tb_C_OWNER, 2097152
.equ tk_tb_C_WORK, 12582912
.equ tk_tb_C_BYTES, 14684160
.equ tk_tb_CS_BYTES, 2101248
.equ tk_tb_CE_BYTES, 12587008
.equ tk_tb_B_ACTION, 8388864
.equ tk_tb_B_REQUEST, 8392704
.equ tk_tb_B_REPLY, 10489856
.equ tk_tb_B_SEQUENCE, 8388624
.equ tk_tb_B_PHASE, 8388616

tk_tb_cold_allocate:
    xor edi, edi
    mov esi, tk_tb_C_BYTES
    mov edx, 3
    mov r10d, 34
    mov r8, -1
    xor r9d, r9d
    mov eax, 9
    syscall
    cmp rax, -4095
    jae tk_tb_global_io_fail
    mov [r15 + tk_tb_G_COLD], rax
    mov [rax + 4000], r15
    lea rdi, [rax + tk_tb_C_BYTES - 4096]
    mov esi, 4096
    xor edx, edx
    mov eax, 10
    syscall
    test rax, rax
    jnz tk_tb_global_io_fail
    xor edi, edi
    mov esi, tk_tb_CS_BYTES
    mov edx, 3
    mov r10d, 34
    mov r8, -1
    xor r9d, r9d
    mov eax, 9
    syscall
    cmp rax, -4095
    jae tk_tb_global_io_fail
    mov [r15 + tk_tb_G_STAMP], rax
    mov [rax + 4000], r15
    mov qword ptr [rax + 128], -1
    lea rdi, [rax + tk_tb_CS_BYTES - 4096]
    mov esi, 4096
    xor edx, edx
    mov eax, 10
    syscall
    test rax, rax
    jnz tk_tb_global_io_fail
    xor edi, edi
    mov esi, tk_tb_CE_BYTES
    mov edx, 3
    mov r10d, 34
    mov r8, -1
    xor r9d, r9d
    mov eax, 9
    syscall
    cmp rax, -4095
    jae tk_tb_global_io_fail
    mov [r15 + tk_tb_G_ENTRIES], rax
    mov [rax + 4000], r15
    lea rdi, [rax + 128]
    mov rax, -1
    mov ecx, 7
    rep stosq
    mov rax, [r15 + tk_tb_G_ENTRIES]
    lea rdi, [rax + tk_tb_CE_BYTES - 4096]
    mov esi, 4096
    xor edx, edx
    mov eax, 10
    syscall
    test rax, rax
    jnz tk_tb_global_io_fail
    ret

tk_tb_cold_preflight:
    cmp qword ptr [r15 + 24], 64
    jb tk_tb_cold_resume
    mov rax, 0x3130305143415248
    cmp [r15 + tk_tb_C_INPUT], rax
    jne tk_tb_cold_resume
    mov rax, [r15 + tk_tb_C_INPUT + 8]
    cmp rax, 1
    jb tk_tb_cold_resume
    cmp rax, 4
    ja tk_tb_cold_resume
    mov rdx, [r15 + 4000]
    mov rdx, [rdx + tk_tb_G_WORK]
    cmp qword ptr [rdx], 0
    je tk_tb_cold_capability_refusal
    mov rcx, 0x3130545351415248
    cmp [rdx], rcx
    jne tk_tb_global_contract_fail
    cmp qword ptr [rdx + 8], 0
    jne tk_tb_global_contract_fail
    cmp rax, 3
    jne tk_tb_cold_resume
    mov rdx, [r15 + tk_tb_C_INPUT + 24]
    call tk_tb_cold_live_lease
    test eax, eax
    jnz tk_tb_cold_resume
tk_tb_cold_capability_refusal:
    mov eax, 0xffffffff
    jmp tk_tb_cold_result

/* Lookup is bounded by the HIA-owned arena; no failed lookup changes state. */
tk_tb_cold_live_lease:
    push r13
    mov r13, [r15 + 4000]
    mov r11, [r13 + tk_tb_G_WORK]
    test rdx, rdx
    jz tk_tb_cold_lease_missing
    mov r9, [r11 + 144]
    cmp r9, 16842752
    jb tk_tb_global_contract_fail
    cmp r9, [r13 + tk_tb_G_WORK_BYTES]
    ja tk_tb_global_contract_fail
    sub r9, 16842752
    mov rcx, [r11 + 168]
tk_tb_cold_lease_next:
    test rcx, rcx
    jz tk_tb_cold_lease_missing
    cmp r9, 96
    jb tk_tb_global_contract_fail
    mov rax, rcx
    call tk_tb_save_checked_node
    cmp qword ptr [rax], 2
    jne tk_tb_global_contract_fail
    cmp [rax + 8], rdx
    je tk_tb_cold_lease_found
    mov rcx, [rax + 16]
    sub r9, 96
    jmp tk_tb_cold_lease_next
tk_tb_cold_lease_found:
    mov rax, [rax + 24]
    call tk_tb_save_checked_node
    cmp qword ptr [rax], 1
    jne tk_tb_global_contract_fail
    cmp qword ptr [rax + 24], 0
    je tk_tb_global_contract_fail
    cmp qword ptr [rax + 32], 0
    je tk_tb_global_contract_fail
    cmp qword ptr [rax + 72], 1
    jne tk_tb_global_contract_fail
    cmp qword ptr [rax + 88], 0
    je tk_tb_global_contract_fail
    mov eax, 1
    pop r13
    ret
tk_tb_cold_lease_missing:
    xor eax, eax
    pop r13
    ret

tk_tb_cold_resume:
    lea rdi, [r15 + tk_tb_C_INPUT]
    mov rsi, [r15 + 24]
    lea rdx, [r15 + tk_tb_C_OUTPUT]
    mov ecx, 266432
    mov r8, r12
    mov r9d, tk_tb_C_WORK
    call qword ptr [rip + tk_ticket_backend_cold_image]
    mov ecx, eax
    cmp rax, rcx
    jne tk_tb_global_contract_fail
    cmp eax, 0xfffffff0
    jne tk_tb_cold_result
    lea r14, [r12 + tk_tb_B_ACTION]
    mov rax, 0x3130414743415248
    cmp [r14], rax
    jne tk_tb_global_contract_fail
    mov rax, [r15 + 16]
    inc rax
    jz tk_tb_global_contract_fail
    cmp [r14 + 8], rax
    jne tk_tb_global_contract_fail
    cmp [r12 + tk_tb_B_SEQUENCE], rax
    jne tk_tb_global_contract_fail
    mov [r15 + 16], rax
    mov rax, [r14 + 64]
    or rax, [r14 + 72]
    or rax, [r14 + 80]
    or rax, [r14 + 88]
    jnz tk_tb_global_contract_fail
    cmp qword ptr [r14 + 32], tk_tb_B_REQUEST
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 48], tk_tb_B_REPLY
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 56], 266304
    jne tk_tb_global_contract_fail
    mov rax, [r14 + 16]
    cmp rax, 100
    je tk_tb_cold_stamp_effect
    cmp rax, 101
    je tk_tb_cold_entries_effect
    cmp rax, 102
    je tk_tb_cold_save_effect
    cmp rax, 103
    jne tk_tb_global_contract_fail
tk_tb_cold_save_effect:
    cmp qword ptr [r14 + 24], 0
    jne tk_tb_global_contract_fail
    mov rsi, [r14 + 40]
    cmp rsi, 64
    jb tk_tb_global_contract_fail
    cmp rsi, 4096
    ja tk_tb_global_contract_fail
    lea rdi, [r12 + tk_tb_B_REQUEST]
    lea rdx, [r12 + tk_tb_B_REPLY]
    call tk_tb_cold_save_entry
    jmp tk_tb_cold_child_return
tk_tb_cold_hot_descriptor:
    cmp qword ptr [r14 + 40], 16
    jne tk_tb_global_contract_fail
    mov rcx, [r14 + 24]
    cmp rcx, 1
    jb tk_tb_global_contract_fail
    cmp rcx, 17
    ja tk_tb_global_contract_fail
    mov rax, [r15 + 4000]
    mov rcx, [rax + tk_tb_G_HOT_FDS - 8 + rcx*8]
    test rcx, rcx
    js tk_tb_global_contract_fail
    ret
tk_tb_cold_stamp_effect:
    call tk_tb_cold_hot_descriptor
    lea rdi, [r12 + tk_tb_B_REQUEST]
    mov esi, 16
    lea rdx, [r12 + tk_tb_B_REPLY]
    call tk_tb_cold_stamp_entry
    jmp tk_tb_cold_child_return
tk_tb_cold_entries_effect:
    call tk_tb_cold_hot_descriptor
    lea rdi, [r12 + tk_tb_B_REQUEST]
    mov esi, 16
    lea rdx, [r12 + tk_tb_B_REPLY]
    call tk_tb_cold_entries_entry
tk_tb_cold_child_return:
    mov ecx, eax
    cmp rax, rcx
    jne tk_tb_global_contract_fail
    mov [r14 + 72], rax
    mov rax, [r14 + 8]
    mov [r14 + 64], rax
    jmp tk_tb_cold_resume

tk_tb_cold_result:
    mov ecx, eax
    cmp rax, rcx
    jne tk_tb_global_contract_fail
    mov [r15 + 32], eax
    cmp eax, 266432
    ja tk_tb_cold_special_result
    cmp eax, 64
    jb tk_tb_global_contract_fail
    cmp qword ptr [r12 + tk_tb_B_PHASE], 0
    jne tk_tb_global_contract_fail
    jmp tk_tb_cold_result_header
tk_tb_cold_special_result:
    cmp eax, 0xffffffff
    je tk_tb_cold_result_header
    cmp eax, 0xfffffffe
    je tk_tb_cold_result_header
    cmp eax, 0xfffffff9
    jne tk_tb_global_contract_fail
tk_tb_cold_result_header:
    ret

tk_tb_cold_save_entry:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp, 24
    mov [rsp], rdi
    mov [rsp + 8], rdx
    mov [rsp + 16], rsi
    mov r15, [r15 + 4000]
    cmp [r15 + tk_tb_I_GLOBAL], r15
    jne tk_tb_global_contract_fail
    mov rbx, [r15 + tk_tb_G_SAVE]
    lea rdi, [rbx + tk_tb_S_INPUT]
    mov esi, tk_tb_S_INPUT_CAP
    mov edx, 3
    mov eax, 10
    syscall
    test rax, rax
    jnz tk_tb_global_io_fail
    mov rcx, [rsp + 16]
    cmp rcx, 64
    jb tk_tb_global_contract_fail
    cmp rcx, 4096
    ja tk_tb_global_contract_fail
    mov [rbx + 24], rcx
    lea rdi, [rbx + tk_tb_S_INPUT]
    mov rsi, [rsp]
    rep movsb
    lea rdi, [rbx + tk_tb_S_INPUT]
    mov esi, tk_tb_S_INPUT_CAP
    mov edx, 1
    mov eax, 10
    syscall
    test rax, rax
    jnz tk_tb_global_io_fail
    call tk_tb_save_entry
    mov ecx, eax
    cmp rax, rcx
    jne tk_tb_global_contract_fail
    mov ebp, eax
    cmp eax, 0xffffffff
    je tk_tb_cold_save_restore
    cmp eax, 0xfffffffe
    je tk_tb_cold_save_restore
    cmp eax, 64
    jb tk_tb_global_contract_fail
    cmp eax, 8192
    ja tk_tb_global_contract_fail
    mov rdi, [rsp + 8]
    lea rsi, [rbx + tk_tb_S_OUTPUT]
    mov ecx, eax
    rep movsb
tk_tb_cold_save_restore:
    mov eax, ebp
    add rsp, 24
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

tk_tb_cleanup_cold_descriptors:
    mov rax, [r15 + tk_tb_G_STAMP]
    test rax, rax
    jz tk_tb_cleanup_cold_entries_borrow
    mov qword ptr [rax + 128], -1
tk_tb_cleanup_cold_entries_borrow:
    mov rax, [r15 + tk_tb_G_ENTRIES]
    test rax, rax
    jz tk_tb_cleanup_cold_namespace_borrow
    mov qword ptr [rax + 128], -1
tk_tb_cleanup_cold_namespace_borrow:
    mov rax, [r15 + tk_tb_G_NAMESPACE]
    test rax, rax
    jz tk_tb_cleanup_cold_transient
    lea rdi, [rax + 16384]
    mov rax, -1
    mov ecx, 259
    rep stosq
tk_tb_cleanup_cold_transient:
    mov rax, [r15 + tk_tb_G_ENTRIES]
    test rax, rax
    jz tk_tb_cleanup_cold_hot
    lea rbx, [rax + 136]
    mov r13d, 6
    call tk_tb_cleanup_table
tk_tb_cleanup_cold_hot:
    lea rbx, [r15 + tk_tb_G_HOT_FDS]
    mov r13d, 17
    call tk_tb_cleanup_table
    ret

tk_tb_cold_stamp_entry:
    cmp rsi, 16
    jne tk_tb_global_contract_fail
    mov rax, [r15 + 4000]
    mov rax, [rax + tk_tb_G_STAMP]
    mov [rax + 4008], rcx
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp, 24
    mov [rsp], rdi
    mov [rsp + 8], rdx
    mov [rsp + 16], rsi
    mov rax, [r15 + 4000]
    mov r15, [rax + tk_tb_G_STAMP]
    mov r13, r15
    lea r12, [r15 + 1048576]
    lea rdi, [r15 + 4096]
    mov esi, 4096
    mov edx, 3
    mov eax, 10
    syscall
    test rax, rax
    jnz tk_tb_global_io_fail
    lea rdi, [r15 + 4096]
    mov rsi, [rsp]
    mov rcx, [rsp + 16]
    mov [r15 + 24], rcx
    rep movsb
    mov rax, [r15 + 4000]
    mov rax, [rax + tk_tb_G_WORK]
    mov rdx, 0x3130545351415248
    cmp [rax], rdx
    jne tk_tb_global_contract_fail
    cmp qword ptr [rax + 8], 0
    jne tk_tb_global_contract_fail
    mov rax, [rax + 80]
    cmp rax, 2
    ja tk_tb_global_contract_fail
    mov [r15 + 4096 + 16], rax
    mov qword ptr [r15 + 4096 + 24], 0
    mov qword ptr [r15 + 24], 32
    lea rdi, [r15 + 4096]
    mov esi, 4096
    mov edx, 1
    mov eax, 10
    syscall
    test rax, rax
    jnz tk_tb_global_io_fail
    cmp qword ptr [r15 + 128], -1
    jne tk_tb_global_contract_fail
    mov rax, [r15 + 4008]
    mov [r15 + 128], rax
    jmp tk_tb_cs_main_resume
.equ tk_tb_cs_MAIN_INPUT, 4096
.equ tk_tb_cs_MAIN_OUTPUT, 8192
.equ tk_tb_cs_MAIN_OWNER, 1048576
.equ tk_tb_cs_NAMESPACE_BASE, 2097152
.equ tk_tb_cs_FINAL_GUARD, 12582912
.equ tk_tb_cs_TOTAL_MAP, 12587008
.equ tk_tb_cs_M_ACTION, 256
.equ tk_tb_cs_M_STAT, 1024
.equ tk_tb_cs_M_STATX, 3072
.equ tk_tb_cs_M_REQUEST, 8192
.equ tk_tb_cs_M_REPLY, 12288
.equ tk_tb_cs_ns_INPUT, 4096
.equ tk_tb_cs_ns_OUTPUT, 8192
.equ tk_tb_cs_ns_FDS, 16384
.equ tk_tb_cs_ns_OWNER, 1048576
.equ tk_tb_cs_ns_GUARD, 9437184
.equ tk_tb_cs_ns_MAP_SIZE, 9441280
.equ tk_tb_cs_ns_FDS_COUNT, 33794
.equ tk_tb_cs_ns_SET_SLOT, 4880
.equ tk_tb_cs_ns_SET_TABLE, 2097152
.equ tk_tb_cs_ns_SET_STRIDE, 16640
.equ tk_tb_cs_ns_PHASE, 4104
.equ tk_tb_cs_ns_SEQUENCE, 4112
.equ tk_tb_cs_ns_OPERATION, 4136
.equ tk_tb_cs_ns_DIRECTORY, 4144
.equ tk_tb_cs_ns_WATCHER, 4152
.equ tk_tb_cs_ns_SCAN_LIVE, 4288
.equ tk_tb_cs_ns_SCAN_CAPACITY, 4304
.equ tk_tb_cs_ns_CANDIDATE, 4328
.equ tk_tb_cs_ns_ACTION, 4352
.equ tk_tb_cs_ns_STAT, 6144
.equ tk_tb_cs_ns_STATX, 6400
.equ tk_tb_cs_ns_NAME, 7040
.equ tk_tb_cs_ns_EVENTS, 65536
.equ tk_tb_cs_ns_DIRENTS, 131072
tk_tb_cs_main_resume:
    lea rdi, [r15 + tk_tb_cs_MAIN_INPUT]
    mov rsi, [r15 + 24]
    lea rdx, [r15 + tk_tb_cs_MAIN_OUTPUT]
    mov ecx, 4096
    mov r8, r12
    mov r9d, 1048576
    call qword ptr [rip + tk_ticket_backend_stamp_image]
    mov ecx, eax
    cmp rax, rcx
    jne tk_tb_global_contract_fail
    cmp eax, 0xfffffff0
    jne tk_tb_cs_main_result
    lea r14, [r12 + tk_tb_cs_M_ACTION]
    mov rax, 0x3130304153415248
    cmp [r14], rax
    jne tk_tb_global_contract_fail
    mov rax, [r15 + 16]
    inc rax
    jz tk_tb_global_contract_fail
    cmp [r14 + 8], rax
    jne tk_tb_global_contract_fail
    cmp [r12 + 16], rax
    jne tk_tb_global_contract_fail
    mov [r15 + 16], rax
    mov rax, [r14 + 64]
    or rax, [r14 + 72]
    or rax, [r14 + 80]
    or rax, [r14 + 88]
    jnz tk_tb_global_contract_fail
    mov rax, [r14 + 16]
    cmp rax, 100
    jae tk_tb_cs_main_child
    cmp qword ptr [r14 + 56], 0
    jne tk_tb_global_contract_fail
    cmp rax, 2
    je tk_tb_cs_main_fstat
    cmp rax, 5
    je tk_tb_cs_main_uid
    cmp rax, 8
    je tk_tb_cs_main_statx
    cmp rax, 9
    je tk_tb_cs_main_statx_probe
    cmp rax, 10
    je tk_tb_cs_main_statat
    cmp rax, 11
    je tk_tb_cs_main_statat_probe
    jmp tk_tb_global_contract_fail
tk_tb_cs_main_zero_span:
    mov rax, [r14 + 32]
    or rax, [r14 + 40]
    or rax, [r14 + 48]
    jnz tk_tb_global_contract_fail
    ret
tk_tb_cs_main_slot_live:
    cmp qword ptr [r14 + 24], 0
    jne tk_tb_global_contract_fail
    mov rdi, [r15 + 128]
    test rdi, rdi
    js tk_tb_global_contract_fail
    ret
tk_tb_cs_main_uid:
    cmp qword ptr [r12 + 8], 8
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 24], 0
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 32], tk_tb_cs_M_STAT + 144
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 40], 8
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 48], 0
    jne tk_tb_global_contract_fail
    mov eax, 107
    syscall
    mov [r12 + tk_tb_cs_M_STAT + 144], rax
    jmp tk_tb_cs_main_ack
tk_tb_cs_main_metadata_live:
    mov rcx, [r14 + 24]
    cmp rcx, 1
    ja tk_tb_global_contract_fail
    cmp rcx, [r12 + 128]
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 48], 0
    jne tk_tb_global_contract_fail
    call tk_tb_cs_main_slot_live
    ret
tk_tb_cs_main_stat_span:
    cmp qword ptr [r14 + 32], tk_tb_cs_M_STAT
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 40], 144
    jne tk_tb_global_contract_fail
    lea rsi, [r12 + tk_tb_cs_M_STAT]
    ret
tk_tb_cs_main_fstat:
    cmp qword ptr [r12 + 8], 50
    jne tk_tb_global_contract_fail
    call tk_tb_cs_main_metadata_live
    call tk_tb_cs_main_stat_span
    mov eax, 5
    syscall
    jmp tk_tb_cs_main_zero
tk_tb_cs_main_statx:
    cmp qword ptr [r12 + 8], 51
    jne tk_tb_global_contract_fail
    call tk_tb_cs_main_metadata_live
    cmp qword ptr [r14 + 32], tk_tb_cs_M_STATX
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 40], 256
    jne tk_tb_global_contract_fail
    lea rsi, [r15 + 512]
    mov edx, 4096
    mov r10d, 4095
    lea r8, [r12 + tk_tb_cs_M_STATX]
    mov eax, 332
    syscall
    jmp tk_tb_cs_main_zero
tk_tb_cs_main_statat:
    cmp qword ptr [r12 + 8], 52
    jne tk_tb_global_contract_fail
    call tk_tb_cs_main_metadata_live
    call tk_tb_cs_main_stat_span
    lea rsi, [r15 + 512]
    lea rdx, [r12 + tk_tb_cs_M_STAT]
    mov r10d, 4096
    mov eax, 262
    syscall
    jmp tk_tb_cs_main_zero
tk_tb_cs_main_probe_admit:
    cmp qword ptr [r14 + 24], 0
    jne tk_tb_global_contract_fail
    call tk_tb_cs_main_zero_span
    xor edi, edi
    xor esi, esi
    xor edx, edx
    ret
tk_tb_cs_main_statx_probe:
    cmp qword ptr [r12 + 8], 53
    jne tk_tb_global_contract_fail
    call tk_tb_cs_main_probe_admit
    mov r10d, 4095
    xor r8d, r8d
    mov eax, 332
    syscall
    jmp tk_tb_cs_main_zero
tk_tb_cs_main_statat_probe:
    cmp qword ptr [r12 + 8], 54
    jne tk_tb_global_contract_fail
    call tk_tb_cs_main_probe_admit
    lea rdx, [r12 + tk_tb_cs_M_STAT]
    xor r10d, r10d
    mov eax, 262
    syscall
    jmp tk_tb_cs_main_zero
tk_tb_cs_main_child:
    cmp rax, 101
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 24], 0
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 32], tk_tb_cs_M_REQUEST
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 40], 32
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 48], tk_tb_cs_M_REPLY
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 56], 72
    jne tk_tb_global_contract_fail
    cmp qword ptr [r12 + 8], 9
    jne tk_tb_global_contract_fail
    cmp qword ptr [r12 + tk_tb_cs_M_REQUEST + 8], 1
    jne tk_tb_global_contract_fail
    cmp qword ptr [r12 + tk_tb_cs_M_REQUEST + 16], 0
    jne tk_tb_global_contract_fail
    call tk_tb_cs_namespace_entry
tk_tb_cs_main_child_return:
    mov [r14 + 72], rax
    jmp tk_tb_cs_main_ack
tk_tb_cs_main_zero:
    test rax, rax
    js tk_tb_cs_main_error
    jnz tk_tb_global_contract_fail
    jmp tk_tb_cs_main_ack
tk_tb_cs_main_value:
    test rax, rax
    js tk_tb_cs_main_error
    mov [r14 + 72], rax
    jmp tk_tb_cs_main_ack
tk_tb_cs_main_error:
    cmp rax, -4095
    jb tk_tb_global_contract_fail
    neg rax
    mov [r14 + 80], rax
tk_tb_cs_main_ack:
    mov rax, [r14 + 8]
    mov [r14 + 64], rax
    jmp tk_tb_cs_main_resume
tk_tb_cs_main_result:
    mov ecx, eax
    cmp rax, rcx
    jne tk_tb_global_contract_fail
    cmp qword ptr [r12 + 8], 0
    jne tk_tb_global_contract_fail
    cmp eax, 48
    je tk_tb_cold_stamp_result_ready
    cmp eax, 160
    jne tk_tb_global_contract_fail
tk_tb_cold_stamp_result_ready:
    mov rdx, [r15 + 4000]
    mov rdx, [rdx + tk_tb_G_WORK]
    cmp qword ptr [rdx + 8], 0
    jne tk_tb_global_contract_fail
    mov rcx, [r12 + 120]
    cmp rcx, 2
    ja tk_tb_global_contract_fail
    mov [rdx + 80], rcx
    mov qword ptr [r15 + 128], -1
    mov ebx, eax
    cmp eax, 0xffffffff
    je tk_tb_cold_stamp_no_copy
    cmp eax, 0xfffffffe
    je tk_tb_cold_stamp_no_copy
    cmp eax, 48
    jb tk_tb_global_contract_fail
    cmp eax, 160
    ja tk_tb_global_contract_fail
    mov rdi, [rsp + 8]
    lea rsi, [r15 + tk_tb_cs_MAIN_OUTPUT]
    mov ecx, eax
    rep movsb
tk_tb_cold_stamp_no_copy:
    mov eax, ebx
    add rsp, 24
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret
tk_tb_cs_namespace_entry:
    lea rdi, [r12 + tk_tb_cs_M_REQUEST]
    mov esi, 32
    lea rdx, [r12 + tk_tb_cs_M_REPLY]
    mov rcx, [r15 + 128]
    jmp tk_tb_borrowed_hot_namespace_entry

tk_tb_cold_entries_entry:
    cmp rsi, 16
    jne tk_tb_global_contract_fail
    mov rax, [r15 + 4000]
    mov rax, [rax + tk_tb_G_ENTRIES]
    mov [rax + 4008], rcx
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp, 24
    mov [rsp], rdi
    mov [rsp + 8], rdx
    mov [rsp + 16], rsi
    mov rax, [r15 + 4000]
    mov r15, [rax + tk_tb_G_ENTRIES]
    mov r13, r15
    lea r12, [r15 + 7340032]
    lea rdi, [r15 + 4096]
    mov esi, 1048576
    mov edx, 3
    mov eax, 10
    syscall
    test rax, rax
    jnz tk_tb_global_io_fail
    lea rdi, [r15 + 4096]
    mov rsi, [rsp]
    mov rcx, [rsp + 16]
    mov [r15 + 24], rcx
    rep movsb
    lea rdi, [r15 + 4096]
    mov esi, 1048576
    mov edx, 1
    mov eax, 10
    syscall
    test rax, rax
    jnz tk_tb_global_io_fail
    cmp qword ptr [r15 + 128], -1
    jne tk_tb_global_contract_fail
    mov rax, [r15 + 4008]
    mov [r15 + 128], rax
    lea r13, [r15 + 3145728]
    jmp tk_tb_ce_resume_entries
.equ tk_tb_ce_INPUT, 4096
.equ tk_tb_ce_INPUT_CAP, 1048576
.equ tk_tb_ce_OUTPUT, 1056768
.equ tk_tb_ce_OUTPUT_CAP, 1048576
.equ tk_tb_ce_OWNER, 7340032
.equ tk_tb_ce_ENTRIES_OWNER, 3145728
.equ tk_tb_ce_X_CHILD_REQUEST, 1179648
.equ tk_tb_ce_X_CHILD_REPLY, 16384
.equ tk_tb_ce_JSON_WORK, 11534336
.equ tk_tb_ce_MAP_SIZE, 12587008
.equ tk_tb_ce_ACTION, 256
.equ tk_tb_ce_STAT, 1024
.equ tk_tb_ce_FILENAME, 4096
.equ tk_tb_ce_TEMPORARY, 4224
.equ tk_tb_ce_CLEAN_NAME, 4480
.equ tk_tb_ce_CLEAN_TARGET, 4800
.equ tk_tb_ce_DOT, 4928
.equ tk_tb_ce_CHILD_REQUEST, 8192
.equ tk_tb_ce_CHILD_REPLY, 12288
.equ tk_tb_ce_READ_BYTES, 24576
.equ tk_tb_ce_DIR_BYTES, 65536
tk_tb_ce_resume_owner:
    lea rdi, [r13 + tk_tb_ce_X_CHILD_REQUEST]
    mov rsi, [r13 + tk_tb_ce_ACTION + 40]
    lea rdx, [r13 + tk_tb_ce_X_CHILD_REPLY]
    mov ecx, 512
    mov r8, r12
    mov r9d, 4194304
    call qword ptr [rip + tk_ticket_backend_record_image]
    cmp eax, 0xfffffff0
    jne tk_tb_ce_owner_result
    lea r14, [r12 + tk_tb_ce_ACTION]
    mov rax, 0x3130304152415248
    cmp [r14], rax
    jne tk_tb_global_contract_fail
    mov rax, [r15 + 16]
    inc rax
    jz tk_tb_global_contract_fail
    cmp [r14 + 8], rax
    jne tk_tb_global_contract_fail
    cmp [r12 + 16], rax
    jne tk_tb_global_contract_fail
    mov [r15 + 16], rax
    mov rax, [r14 + 64]
    or rax, [r14 + 72]
    or rax, [r14 + 80]
    or rax, [r14 + 88]
    jnz tk_tb_global_contract_fail
    mov rax, [r14 + 16]
    cmp rax, 100
    je tk_tb_ce_json_effect
    cmp qword ptr [r14 + 56], 0
    jne tk_tb_global_contract_fail
    cmp rax, 1
    je tk_tb_ce_stat_effect
    cmp rax, 2
    je tk_tb_ce_open_effect
    cmp rax, 3
    je tk_tb_ce_read_effect
    cmp rax, 5
    je tk_tb_ce_sync_effect
    cmp rax, 8
    je tk_tb_ce_unlink_effect
    cmp rax, 9
    je tk_tb_ce_close_effect
    cmp rax, 10
    je tk_tb_ce_scan_open_effect
    cmp rax, 11
    je tk_tb_ce_duplicate_effect
    cmp rax, 12
    je tk_tb_ce_flags_effect
    cmp rax, 13
    je tk_tb_ce_directory_effect
    jmp tk_tb_global_contract_fail
tk_tb_ce_json_effect:
    cmp qword ptr [r14 + 24], 0
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 32], tk_tb_ce_CHILD_REQUEST
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 40], 24
    jb tk_tb_global_contract_fail
    cmp qword ptr [r14 + 40], 2072
    ja tk_tb_global_contract_fail
    cmp qword ptr [r14 + 48], tk_tb_ce_CHILD_REPLY
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 56], 4096
    jne tk_tb_global_contract_fail
    lea rdi, [r12 + tk_tb_ce_CHILD_REQUEST]
    mov rsi, [r14 + 40]
    lea rdx, [r12 + tk_tb_ce_CHILD_REPLY]
    mov ecx, 4096
    lea r8, [r15 + tk_tb_ce_JSON_WORK]
    mov r9d, 1048576
    call qword ptr [rip + tk_ticket_backend_json_image]
    mov [r12 + tk_tb_ce_ACTION + 72], rax
    jmp tk_tb_ce_acknowledge
tk_tb_ce_live_slot:
    mov rcx, [r14 + 24]
    cmp rcx, 6
    ja tk_tb_global_contract_fail
    mov rdi, [r15 + rcx*8 + 128]
    test rdi, rdi
    js tk_tb_global_contract_fail
    ret
tk_tb_ce_zero_span:
    mov rax, [r14 + 32]
    or rax, [r14 + 40]
    or rax, [r14 + 48]
    jnz tk_tb_global_contract_fail
    ret
tk_tb_ce_stat_effect:
    call tk_tb_ce_live_slot
    test rcx, rcx
    jz tk_tb_global_contract_fail
    cmp qword ptr [r14 + 32], tk_tb_ce_STAT
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 40], 152
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 48], 1
    ja tk_tb_global_contract_fail
    lea rsi, [r12 + tk_tb_ce_STAT]
    mov eax, 5
    syscall
    test rax, rax
    js tk_tb_ce_effect_error
    cmp qword ptr [r14 + 48], 1
    je tk_tb_ce_acknowledge
    mov eax, 107
    syscall
    mov [r12 + tk_tb_ce_STAT + 144], rax
    jmp tk_tb_ce_acknowledge
tk_tb_ce_name_span:
    mov rax, [r14 + 32]
    mov rdx, [r14 + 40]
    cmp rax, tk_tb_ce_FILENAME
    je tk_tb_ce_record_name
    cmp rax, tk_tb_ce_CLEAN_TARGET
    je tk_tb_ce_record_name
    cmp rax, tk_tb_ce_TEMPORARY
    je tk_tb_ce_staging_name
    cmp rax, tk_tb_ce_CLEAN_NAME
    jne tk_tb_global_contract_fail
tk_tb_ce_staging_name:
    cmp rdx, 134
    jne tk_tb_global_contract_fail
    lea rsi, [r12 + rax]
    cmp byte ptr [rsi], 46
    jne tk_tb_global_contract_fail
    cmp byte ptr [rsi + 65], 45
    jne tk_tb_global_contract_fail
    cmp dword ptr [rsi + 130], 0x706d742e
    jne tk_tb_global_contract_fail
    cmp byte ptr [rsi + 134], 0
    jne tk_tb_global_contract_fail
    inc rsi
    call tk_tb_ce_hex64
    add rsi, 65
    call tk_tb_ce_hex64
    sub rsi, 66
    ret
tk_tb_ce_record_name:
    cmp rdx, 69
    jne tk_tb_global_contract_fail
    lea rsi, [r12 + rax]
    call tk_tb_ce_hex64
    cmp dword ptr [rsi + 64], 0x6f736a2e
    jne tk_tb_global_contract_fail
    cmp byte ptr [rsi + 68], 110
    jne tk_tb_global_contract_fail
    cmp byte ptr [rsi + 69], 0
    jne tk_tb_global_contract_fail
    ret
tk_tb_ce_hex64:
    xor r8d, r8d
tk_tb_ce_hex_loop:
    mov dl, [rsi + r8]
    cmp dl, 48
    jb tk_tb_global_contract_fail
    cmp dl, 57
    jbe tk_tb_ce_hex_good
    cmp dl, 97
    jb tk_tb_global_contract_fail
    cmp dl, 102
    ja tk_tb_global_contract_fail
tk_tb_ce_hex_good:
    inc r8d
    cmp r8d, 64
    jne tk_tb_ce_hex_loop
    ret
tk_tb_ce_open_effect:
    cmp qword ptr [r14 + 48], 0
    jne tk_tb_global_contract_fail
    mov rcx, [r14 + 24]
    cmp rcx, 1
    je tk_tb_ce_open_slot_ok
    cmp rcx, 2
    je tk_tb_ce_open_slot_ok
    cmp rcx, 5
    je tk_tb_ce_open_slot_ok
    cmp rcx, 6
    jne tk_tb_global_contract_fail
tk_tb_ce_open_slot_ok:
    cmp qword ptr [r15 + rcx*8 + 128], -1
    jne tk_tb_global_contract_fail
    call tk_tb_ce_name_span
    mov rdi, [r15 + 128]
    mov edx, 0xa0800
    xor r10d, r10d
    jmp tk_tb_ce_issue_open
tk_tb_ce_scan_open_effect:
    cmp qword ptr [r14 + 24], 3
    jne tk_tb_global_contract_fail
    cmp qword ptr [r15 + 152], -1
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 32], tk_tb_ce_DOT
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 40], 1
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 48], 0
    jne tk_tb_global_contract_fail
    cmp qword ptr [r12 + tk_tb_ce_DOT], 46
    jne tk_tb_global_contract_fail
    mov rdi, [r15 + 128]
    lea rsi, [r12 + tk_tb_ce_DOT]
    mov edx, 0xb0000
    xor r10d, r10d
tk_tb_ce_issue_open:
    mov eax, 257
    syscall
    test rax, rax
    js tk_tb_ce_effect_error
    cmp rax, 0x7fffffff
    ja tk_tb_global_contract_fail
    mov rcx, [r14 + 24]
    mov [r15 + rcx*8 + 128], rax
    mov [r14 + 72], rcx
    jmp tk_tb_ce_acknowledge
tk_tb_ce_read_effect:
    call tk_tb_ce_live_slot
    cmp rcx, 1
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 48], 0
    jne tk_tb_global_contract_fail
    mov rax, [r12 + 88]
    cmp rax, 2048
    ja tk_tb_global_contract_fail
    lea rsi, [rax + tk_tb_ce_READ_BYTES]
    cmp rsi, [r14 + 32]
    jne tk_tb_global_contract_fail
    mov edx, 2049
    sub rdx, rax
    cmp rdx, [r14 + 40]
    jne tk_tb_global_contract_fail
    add rsi, r12
    xor eax, eax
    syscall
    jmp tk_tb_ce_value_effect
tk_tb_ce_sync_effect:
    call tk_tb_ce_zero_span
    call tk_tb_ce_live_slot
    test rcx, rcx
    jnz tk_tb_global_contract_fail
    mov eax, 74
    syscall
    test rax, rax
    js tk_tb_ce_effect_error
    jmp tk_tb_ce_acknowledge
tk_tb_ce_unlink_effect:
    cmp qword ptr [r14 + 24], 0
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 32], tk_tb_ce_CLEAN_NAME
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 48], 0
    jne tk_tb_global_contract_fail
    call tk_tb_ce_name_span
    mov rdi, [r15 + 128]
    xor edx, edx
    mov eax, 263
    syscall
    test rax, rax
    js tk_tb_ce_effect_error
    jmp tk_tb_ce_acknowledge
tk_tb_ce_close_effect:
    call tk_tb_ce_zero_span
    call tk_tb_ce_live_slot
    test rcx, rcx
    jz tk_tb_global_contract_fail
    mov qword ptr [r15 + rcx*8 + 128], -1
    mov eax, 3
    syscall
    test rax, rax
    js tk_tb_ce_effect_error
    jmp tk_tb_ce_acknowledge
tk_tb_ce_duplicate_effect:
    cmp qword ptr [r14 + 24], 4
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 32], 0
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 40], 0
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 48], 3
    jne tk_tb_global_contract_fail
    cmp qword ptr [r15 + 160], -1
    jne tk_tb_global_contract_fail
    mov rdi, [r15 + 152]
    test rdi, rdi
    js tk_tb_global_contract_fail
    mov esi, 1030
    xor edx, edx
    mov eax, 72
    syscall
    test rax, rax
    js tk_tb_ce_effect_error
    mov [r15 + 160], rax
    mov qword ptr [r14 + 72], 4
    jmp tk_tb_ce_acknowledge
tk_tb_ce_flags_effect:
    call tk_tb_ce_zero_span
    call tk_tb_ce_live_slot
    cmp rcx, 4
    jne tk_tb_global_contract_fail
    mov esi, 3
    xor edx, edx
    mov eax, 72
    syscall
    jmp tk_tb_ce_value_effect
tk_tb_ce_directory_effect:
    call tk_tb_ce_live_slot
    cmp rcx, 4
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 32], tk_tb_ce_DIR_BYTES
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 48], 0
    jne tk_tb_global_contract_fail
    mov rdx, [r14 + 40]
    cmp rdx, 32768
    jb tk_tb_global_contract_fail
    cmp rdx, 1048576
    ja tk_tb_global_contract_fail
    cmp rdx, [r12 + 136]
    jne tk_tb_global_contract_fail
    lea rsi, [r12 + tk_tb_ce_DIR_BYTES]
    mov eax, 217
    syscall
tk_tb_ce_value_effect:
    test rax, rax
    js tk_tb_ce_effect_error
    mov [r14 + 72], rax
    jmp tk_tb_ce_acknowledge
tk_tb_ce_effect_error:
    cmp rax, -4095
    jb tk_tb_global_contract_fail
    neg rax
    mov [r14 + 80], rax
tk_tb_ce_acknowledge:
    mov rax, [r12 + tk_tb_ce_ACTION + 8]
    mov [r12 + tk_tb_ce_ACTION + 64], rax
    cmp qword ptr [r15 + 72], 1
    je tk_tb_ce_resume_entries
    jmp tk_tb_ce_resume_owner
tk_tb_ce_owner_result:
    mov ecx, 1
tk_tb_ce_check_slots:
    cmp qword ptr [r15 + rcx*8 + 128], -1
    jne tk_tb_global_contract_fail
    inc ecx
    cmp ecx, 7
    jne tk_tb_ce_check_slots
    cmp qword ptr [r12 + 8], 0
    jne tk_tb_global_contract_fail
    mov [r13 + tk_tb_ce_ACTION + 72], rax
    mov rax, [r13 + tk_tb_ce_ACTION + 8]
    mov [r13 + tk_tb_ce_ACTION + 64], rax
    jmp tk_tb_ce_resume_entries
tk_tb_ce_resume_entries:
    lea r12, [r15 + tk_tb_ce_OWNER]
    lea rdi, [r15 + tk_tb_ce_INPUT]
    mov rsi, [r15 + 24]
    lea rdx, [r15 + tk_tb_ce_OUTPUT]
    mov ecx, tk_tb_ce_OUTPUT_CAP
    mov r8, r13
    mov r9d, 4194304
    call qword ptr [rip + tk_ticket_backend_entries_image]
    cmp eax, 0xfffffff0
    jne tk_tb_ce_entries_result
    lea r14, [r13 + tk_tb_ce_ACTION]
    mov rax, 0x3130304145415248
    cmp [r14], rax
    jne tk_tb_global_contract_fail
    mov rax, [r15 + 8]
    inc rax
    jz tk_tb_global_contract_fail
    cmp [r14 + 8], rax
    jne tk_tb_global_contract_fail
    cmp [r13 + 16], rax
    jne tk_tb_global_contract_fail
    mov [r15 + 8], rax
    mov rax, [r14 + 64]
    or rax, [r14 + 72]
    or rax, [r14 + 80]
    or rax, [r14 + 88]
    jnz tk_tb_global_contract_fail
    mov rax, [r14 + 16]
    cmp rax, 100
    je tk_tb_ce_x_read_start
    cmp qword ptr [r14 + 56], 0
    jne tk_tb_global_contract_fail
    mov qword ptr [r15 + 72], 1
    mov r12, r13
    cmp rax, 10
    je tk_tb_ce_scan_open_effect
    cmp rax, 11
    je tk_tb_ce_duplicate_effect
    cmp rax, 12
    je tk_tb_ce_flags_effect
    cmp rax, 13
    je tk_tb_ce_directory_effect
    cmp rax, 1
    je tk_tb_ce_x_scan_stat
    cmp rax, 9
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 24], 3
    je tk_tb_ce_close_effect
    cmp qword ptr [r14 + 24], 4
    je tk_tb_ce_close_effect
    jmp tk_tb_global_contract_fail
tk_tb_ce_x_scan_stat:
    cmp qword ptr [r14 + 24], 4
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 48], 1
    jne tk_tb_global_contract_fail
    jmp tk_tb_ce_stat_effect
tk_tb_ce_x_read_start:
    cmp qword ptr [r14 + 24], 0
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 32], tk_tb_ce_X_CHILD_REQUEST
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 40], 24
    jb tk_tb_global_contract_fail
    cmp qword ptr [r14 + 40], 279
    ja tk_tb_global_contract_fail
    cmp qword ptr [r14 + 48], tk_tb_ce_X_CHILD_REPLY
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 56], 512
    jne tk_tb_global_contract_fail
    cmp qword ptr [r13 + 56], 0
    jne tk_tb_global_contract_fail
    mov ecx, 1
tk_tb_ce_x_check_child_slots:
    cmp qword ptr [r15 + rcx*8 + 128], -1
    jne tk_tb_global_contract_fail
    inc ecx
    cmp ecx, 7
    jne tk_tb_ce_x_check_child_slots
    mov qword ptr [r15 + 72], 0
    jmp tk_tb_ce_resume_owner
tk_tb_ce_entries_result:
    cmp qword ptr [r13 + 8], 0
    jne tk_tb_global_contract_fail
    cmp qword ptr [r13 + 56], 0
    jne tk_tb_global_contract_fail
    mov ecx, 1
tk_tb_ce_x_check_result_slots:
    cmp qword ptr [r15 + rcx*8 + 128], -1
    jne tk_tb_global_contract_fail
    inc ecx
    cmp ecx, 7
    jne tk_tb_ce_x_check_result_slots
    mov ecx, eax
    cmp rax, rcx
    jne tk_tb_global_contract_fail
    mov qword ptr [r15 + 128], -1
    mov ebx, eax
    cmp eax, 0xffffffff
    je tk_tb_cold_entries_no_copy
    cmp eax, 0xfffffffe
    je tk_tb_cold_entries_no_copy
    cmp eax, 32
    jb tk_tb_global_contract_fail
    cmp eax, 266272
    ja tk_tb_global_contract_fail
    mov rdi, [rsp + 8]
    lea rsi, [r15 + tk_tb_ce_OUTPUT]
    mov ecx, eax
    rep movsb
tk_tb_cold_entries_no_copy:
    mov eax, ebx
    add rsp, 24
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

tk_tb_cold_roots_option:
    .asciz "--archive-roots"

.equ tk_tb_kr_INPUT, 4096
.equ tk_tb_kr_INPUT_CAP, 1048576
.equ tk_tb_kr_OUTPUT, 1056768
.equ tk_tb_kr_OUTPUT_CAP, 512
.equ tk_tb_kr_OWNER, 6291456
.equ tk_tb_kr_REMOVE_OWNER, 2097152
.equ tk_tb_kr_X_FILENAME, 65536
.equ tk_tb_kr_X_CHILD_REQUEST, 1048576
.equ tk_tb_kr_X_CHILD_REPLY, 16384
.equ tk_tb_kr_JSON_WORK, 10485760
.equ tk_tb_kr_MAP_SIZE, 11538432
.equ tk_tb_kr_ACTION, 256
.equ tk_tb_kr_STAT, 1024
.equ tk_tb_kr_FILENAME, 4096
.equ tk_tb_kr_TEMPORARY, 4224
.equ tk_tb_kr_CLEAN_NAME, 4480
.equ tk_tb_kr_CLEAN_TARGET, 4800
.equ tk_tb_kr_DOT, 4928
.equ tk_tb_kr_CHILD_REQUEST, 8192
.equ tk_tb_kr_CHILD_REPLY, 12288
.equ tk_tb_kr_READ_BYTES, 24576
.equ tk_tb_kr_DIR_BYTES, 65536
tk_tb_kr_resume_owner:
    cmp qword ptr [r15 + 4016], 1
    jne tk_tb_read_for_removal
    lea rdi, [r15 + tk_tb_kr_INPUT]
    mov rsi, [r15 + 24]
    lea rdx, [r15 + tk_tb_kr_OUTPUT]
    jmp tk_tb_read_transport_ready
tk_tb_read_for_removal:
    lea rdi, [r13 + tk_tb_kr_X_CHILD_REQUEST]
    mov rsi, [r13 + tk_tb_kr_ACTION + 40]
    lea rdx, [r13 + tk_tb_kr_X_CHILD_REPLY]
tk_tb_read_transport_ready:
    mov ecx, tk_tb_kr_OUTPUT_CAP
    mov r8, r12
    mov r9d, 4194304
    call qword ptr [rip + tk_ticket_backend_record_image]
    cmp eax, 0xfffffff0
    jne tk_tb_kr_owner_result
    lea r14, [r12 + tk_tb_kr_ACTION]
    mov rax, 0x3130304152415248
    cmp [r14], rax
    jne tk_tb_global_contract_fail
    mov rax, [r15 + 16]
    inc rax
    jz tk_tb_global_contract_fail
    cmp [r14 + 8], rax
    jne tk_tb_global_contract_fail
    cmp [r12 + 16], rax
    jne tk_tb_global_contract_fail
    mov [r15 + 16], rax
    mov rax, [r14 + 64]
    or rax, [r14 + 72]
    or rax, [r14 + 80]
    or rax, [r14 + 88]
    jnz tk_tb_global_contract_fail
    mov rax, [r14 + 16]
    cmp rax, 100
    je tk_tb_kr_json_effect
    cmp qword ptr [r14 + 56], 0
    jne tk_tb_global_contract_fail
    cmp rax, 1
    je tk_tb_kr_stat_effect
    cmp rax, 2
    je tk_tb_kr_open_effect
    cmp rax, 3
    je tk_tb_kr_read_effect
    cmp rax, 5
    je tk_tb_kr_sync_effect
    cmp rax, 8
    je tk_tb_kr_unlink_effect
    cmp rax, 9
    je tk_tb_kr_close_effect
    cmp rax, 10
    je tk_tb_kr_scan_open_effect
    cmp rax, 11
    je tk_tb_kr_duplicate_effect
    cmp rax, 12
    je tk_tb_kr_flags_effect
    cmp rax, 13
    je tk_tb_kr_directory_effect
    jmp tk_tb_global_contract_fail
tk_tb_kr_json_effect:
    cmp qword ptr [r14 + 24], 0
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 32], tk_tb_kr_CHILD_REQUEST
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 40], 24
    jb tk_tb_global_contract_fail
    cmp qword ptr [r14 + 40], 2072
    ja tk_tb_global_contract_fail
    cmp qword ptr [r14 + 48], tk_tb_kr_CHILD_REPLY
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 56], 4096
    jne tk_tb_global_contract_fail
    lea rdi, [r12 + tk_tb_kr_CHILD_REQUEST]
    mov rsi, [r14 + 40]
    lea rdx, [r12 + tk_tb_kr_CHILD_REPLY]
    mov ecx, 4096
    lea r8, [r15 + tk_tb_kr_JSON_WORK]
    mov r9d, 1048576
    call qword ptr [rip + tk_ticket_backend_json_image]
    mov [r12 + tk_tb_kr_ACTION + 72], rax
    jmp tk_tb_kr_acknowledge
tk_tb_kr_live_slot:
    mov rcx, [r14 + 24]
    cmp rcx, 6
    ja tk_tb_global_contract_fail
    mov rdi, [r15 + rcx*8 + 128]
    test rdi, rdi
    js tk_tb_global_contract_fail
    ret
tk_tb_kr_zero_span:
    mov rax, [r14 + 32]
    or rax, [r14 + 40]
    or rax, [r14 + 48]
    jnz tk_tb_global_contract_fail
    ret
tk_tb_kr_stat_effect:
    call tk_tb_kr_live_slot
    test rcx, rcx
    jz tk_tb_global_contract_fail
    cmp qword ptr [r14 + 32], tk_tb_kr_STAT
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 40], 152
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 48], 1
    ja tk_tb_global_contract_fail
    lea rsi, [r12 + tk_tb_kr_STAT]
    mov eax, 5
    syscall
    test rax, rax
    js tk_tb_kr_effect_error
    cmp qword ptr [r14 + 48], 1
    je tk_tb_kr_acknowledge
    mov eax, 107
    syscall
    mov [r12 + tk_tb_kr_STAT + 144], rax
    jmp tk_tb_kr_acknowledge
tk_tb_kr_name_span:
    mov rax, [r14 + 32]
    mov rdx, [r14 + 40]
    cmp rax, tk_tb_kr_FILENAME
    je tk_tb_kr_record_name
    cmp rax, tk_tb_kr_CLEAN_TARGET
    je tk_tb_kr_record_name
    cmp rax, tk_tb_kr_TEMPORARY
    je tk_tb_kr_staging_name
    cmp rax, tk_tb_kr_CLEAN_NAME
    jne tk_tb_global_contract_fail
tk_tb_kr_staging_name:
    cmp rdx, 134
    jne tk_tb_global_contract_fail
    lea rsi, [r12 + rax]
    cmp byte ptr [rsi], 46
    jne tk_tb_global_contract_fail
    cmp byte ptr [rsi + 65], 45
    jne tk_tb_global_contract_fail
    cmp dword ptr [rsi + 130], 0x706d742e
    jne tk_tb_global_contract_fail
    cmp byte ptr [rsi + 134], 0
    jne tk_tb_global_contract_fail
    inc rsi
    call tk_tb_kr_hex64
    add rsi, 65
    call tk_tb_kr_hex64
    sub rsi, 66
    ret
tk_tb_kr_record_name:
    cmp rdx, 69
    jne tk_tb_global_contract_fail
    lea rsi, [r12 + rax]
    call tk_tb_kr_hex64
    cmp dword ptr [rsi + 64], 0x6f736a2e
    jne tk_tb_global_contract_fail
    cmp byte ptr [rsi + 68], 110
    jne tk_tb_global_contract_fail
    cmp byte ptr [rsi + 69], 0
    jne tk_tb_global_contract_fail
    ret
tk_tb_kr_hex64:
    xor r8d, r8d
tk_tb_kr_hex_loop:
    mov dl, [rsi + r8]
    cmp dl, 48
    jb tk_tb_global_contract_fail
    cmp dl, 57
    jbe tk_tb_kr_hex_good
    cmp dl, 97
    jb tk_tb_global_contract_fail
    cmp dl, 102
    ja tk_tb_global_contract_fail
tk_tb_kr_hex_good:
    inc r8d
    cmp r8d, 64
    jne tk_tb_kr_hex_loop
    ret
tk_tb_kr_open_effect:
    cmp qword ptr [r14 + 48], 0
    jne tk_tb_global_contract_fail
    mov rcx, [r14 + 24]
    cmp rcx, 1
    je tk_tb_kr_open_slot_ok
    cmp rcx, 2
    je tk_tb_kr_open_slot_ok
    cmp rcx, 5
    je tk_tb_kr_open_slot_ok
    cmp rcx, 6
    jne tk_tb_global_contract_fail
tk_tb_kr_open_slot_ok:
    cmp qword ptr [r15 + rcx*8 + 128], -1
    jne tk_tb_global_contract_fail
    call tk_tb_kr_name_span
    mov rdi, [r15 + 128]
    mov edx, 0xa0800
    xor r10d, r10d
    jmp tk_tb_kr_issue_open
tk_tb_kr_scan_open_effect:
    cmp qword ptr [r14 + 24], 3
    jne tk_tb_global_contract_fail
    cmp qword ptr [r15 + 152], -1
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 32], tk_tb_kr_DOT
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 40], 1
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 48], 0
    jne tk_tb_global_contract_fail
    cmp qword ptr [r12 + tk_tb_kr_DOT], 46
    jne tk_tb_global_contract_fail
    mov rdi, [r15 + 128]
    lea rsi, [r12 + tk_tb_kr_DOT]
    mov edx, 0xb0000
    xor r10d, r10d
tk_tb_kr_issue_open:
    mov eax, 257
    syscall
    test rax, rax
    js tk_tb_kr_effect_error
    cmp rax, 0x7fffffff
    ja tk_tb_global_contract_fail
    mov rcx, [r14 + 24]
    mov [r15 + rcx*8 + 128], rax
    mov [r14 + 72], rcx
    jmp tk_tb_kr_acknowledge
tk_tb_kr_read_effect:
    call tk_tb_kr_live_slot
    cmp rcx, 1
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 48], 0
    jne tk_tb_global_contract_fail
    mov rax, [r12 + 88]
    cmp rax, 2048
    ja tk_tb_global_contract_fail
    lea rsi, [rax + tk_tb_kr_READ_BYTES]
    cmp rsi, [r14 + 32]
    jne tk_tb_global_contract_fail
    mov edx, 2049
    sub rdx, rax
    cmp rdx, [r14 + 40]
    jne tk_tb_global_contract_fail
    add rsi, r12
    xor eax, eax
    syscall
    jmp tk_tb_kr_value_effect
tk_tb_kr_sync_effect:
    call tk_tb_kr_zero_span
    call tk_tb_kr_live_slot
    test rcx, rcx
    jnz tk_tb_global_contract_fail
    mov eax, 74
    syscall
    test rax, rax
    js tk_tb_kr_effect_error
    jmp tk_tb_kr_acknowledge
tk_tb_kr_unlink_effect:
    cmp qword ptr [r14 + 24], 0
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 32], tk_tb_kr_CLEAN_NAME
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 48], 0
    jne tk_tb_global_contract_fail
    call tk_tb_kr_name_span
    mov rdi, [r15 + 128]
    xor edx, edx
    mov eax, 263
    syscall
    test rax, rax
    js tk_tb_kr_effect_error
    jmp tk_tb_kr_acknowledge
tk_tb_kr_close_effect:
    call tk_tb_kr_zero_span
    call tk_tb_kr_live_slot
    test rcx, rcx
    jz tk_tb_global_contract_fail
    mov qword ptr [r15 + rcx*8 + 128], -1
    mov eax, 3
    syscall
    test rax, rax
    js tk_tb_kr_effect_error
    jmp tk_tb_kr_acknowledge
tk_tb_kr_duplicate_effect:
    cmp qword ptr [r14 + 24], 4
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 32], 0
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 40], 0
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 48], 3
    jne tk_tb_global_contract_fail
    cmp qword ptr [r15 + 160], -1
    jne tk_tb_global_contract_fail
    mov rdi, [r15 + 152]
    test rdi, rdi
    js tk_tb_global_contract_fail
    mov esi, 1030
    xor edx, edx
    mov eax, 72
    syscall
    test rax, rax
    js tk_tb_kr_effect_error
    mov [r15 + 160], rax
    mov qword ptr [r14 + 72], 4
    jmp tk_tb_kr_acknowledge
tk_tb_kr_flags_effect:
    call tk_tb_kr_zero_span
    call tk_tb_kr_live_slot
    cmp rcx, 4
    jne tk_tb_global_contract_fail
    mov esi, 3
    xor edx, edx
    mov eax, 72
    syscall
    jmp tk_tb_kr_value_effect
tk_tb_kr_directory_effect:
    call tk_tb_kr_live_slot
    cmp rcx, 4
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 32], tk_tb_kr_DIR_BYTES
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 48], 0
    jne tk_tb_global_contract_fail
    mov rdx, [r14 + 40]
    cmp rdx, 32768
    jb tk_tb_global_contract_fail
    cmp rdx, 1048576
    ja tk_tb_global_contract_fail
    cmp rdx, [r12 + 136]
    jne tk_tb_global_contract_fail
    lea rsi, [r12 + tk_tb_kr_DIR_BYTES]
    mov eax, 217
    syscall
tk_tb_kr_value_effect:
    test rax, rax
    js tk_tb_kr_effect_error
    mov [r14 + 72], rax
    jmp tk_tb_kr_acknowledge
tk_tb_kr_effect_error:
    cmp rax, -4095
    jb tk_tb_global_contract_fail
    neg rax
    mov [r14 + 80], rax
tk_tb_kr_acknowledge:
    mov rax, [r12 + tk_tb_kr_ACTION + 8]
    mov [r12 + tk_tb_kr_ACTION + 64], rax
    jmp tk_tb_kr_resume_owner
tk_tb_kr_owner_result:
    mov ecx, 1
tk_tb_kr_check_slots:
    cmp qword ptr [r15 + rcx*8 + 128], -1
    jne tk_tb_global_contract_fail
    inc ecx
    cmp ecx, 7
    jne tk_tb_kr_check_slots
    cmp qword ptr [r12 + 8], 0
    jne tk_tb_global_contract_fail
    cmp qword ptr [r15 + 4016], 1
    je tk_tb_retention_hot_read_result
    mov [r13 + tk_tb_kr_ACTION + 72], rax
    mov rax, [r13 + tk_tb_kr_ACTION + 8]
    mov [r13 + tk_tb_kr_ACTION + 64], rax
    jmp tk_tb_kr_resume_remove
tk_tb_kr_resume_remove:
    lea rdi, [r15 + tk_tb_kr_INPUT]
    mov rsi, [r15 + 24]
    lea rdx, [r15 + tk_tb_kr_OUTPUT]
    mov ecx, tk_tb_kr_OUTPUT_CAP
    mov r8, r13
    mov r9d, 4194304
    call qword ptr [rip + tk_ticket_backend_remove_image]
    cmp eax, 0xfffffff0
    jne tk_tb_kr_remove_result
    lea r14, [r13 + tk_tb_kr_ACTION]
    mov rax, 0x3130304158415248
    cmp [r14], rax
    jne tk_tb_global_contract_fail
    mov rax, [r15 + 8]
    inc rax
    jz tk_tb_global_contract_fail
    cmp [r14 + 8], rax
    jne tk_tb_global_contract_fail
    cmp [r13 + 16], rax
    jne tk_tb_global_contract_fail
    mov [r15 + 8], rax
    mov rax, [r14 + 64]
    or rax, [r14 + 72]
    or rax, [r14 + 80]
    or rax, [r14 + 88]
    jnz tk_tb_global_contract_fail
    mov rax, [r14 + 16]
    cmp rax, 100
    je tk_tb_kr_x_read_start
    cmp qword ptr [r14 + 56], 0
    jne tk_tb_global_contract_fail
    cmp rax, 5
    je tk_tb_kr_x_sync
    cmp rax, 8
    je tk_tb_kr_x_unlink
    jmp tk_tb_global_contract_fail
tk_tb_kr_x_read_start:
    cmp qword ptr [r14 + 24], 0
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 32], tk_tb_kr_X_CHILD_REQUEST
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 40], 29
    jb tk_tb_global_contract_fail
    cmp qword ptr [r14 + 40], tk_tb_kr_INPUT_CAP
    ja tk_tb_global_contract_fail
    cmp qword ptr [r14 + 48], tk_tb_kr_X_CHILD_REPLY
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 56], 512
    jne tk_tb_global_contract_fail
    jmp tk_tb_kr_resume_owner
tk_tb_kr_x_root:
    cmp qword ptr [r14 + 24], 0
    jne tk_tb_global_contract_fail
    mov rdi, [r15 + 128]
    test rdi, rdi
    js tk_tb_global_contract_fail
    ret
tk_tb_kr_x_sync:
    call tk_tb_kr_zero_span
    call tk_tb_kr_x_root
    mov eax, 74
    syscall
    test rax, rax
    js tk_tb_kr_x_error
    jmp tk_tb_kr_x_acknowledge
tk_tb_kr_x_unlink:
    call tk_tb_kr_x_root
    cmp qword ptr [r14 + 32], tk_tb_kr_X_FILENAME
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 40], 69
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 48], 0
    jne tk_tb_global_contract_fail
    cmp qword ptr [r15 + 24], 344
    jb tk_tb_global_contract_fail
    cmp qword ptr [r15 + tk_tb_kr_INPUT + 88], 256
    jne tk_tb_global_contract_fail
    cmp qword ptr [r15 + tk_tb_kr_INPUT + 96], 64
    jne tk_tb_global_contract_fail
    lea rsi, [r13 + tk_tb_kr_X_FILENAME]
    call tk_tb_kr_hex64
    lea rsi, [r15 + tk_tb_kr_INPUT + 280]
    lea rdi, [r13 + tk_tb_kr_X_FILENAME]
    mov ecx, 64
    repe cmpsb
    jne tk_tb_global_contract_fail
    mov rax, 0x6e6f736a2e
    cmp [rdi], rax
    jne tk_tb_global_contract_fail
    mov rdi, [r15 + 128]
    lea rsi, [r13 + tk_tb_kr_X_FILENAME]
    xor edx, edx
    mov eax, 263
    syscall
    test rax, rax
    js tk_tb_kr_x_error
    jmp tk_tb_kr_x_acknowledge
tk_tb_kr_x_error:
    cmp rax, -4095
    jb tk_tb_global_contract_fail
    neg rax
    mov [r14 + 80], rax
tk_tb_kr_x_acknowledge:
    mov rax, [r13 + tk_tb_kr_ACTION + 8]
    mov [r13 + tk_tb_kr_ACTION + 64], rax
    jmp tk_tb_kr_resume_remove
tk_tb_kr_remove_result:
    cmp qword ptr [r13 + 8], 0
    jne tk_tb_global_contract_fail
    mov qword ptr [r15 + 128], -1
    mov ebx, eax
    cmp eax, 0xffffffff
    je tk_tb_retention_remove_no_copy
    cmp eax, 0xfffffffe
    je tk_tb_retention_remove_no_copy
    cmp eax, 32
    jb tk_tb_global_contract_fail
    cmp eax, 32
    ja tk_tb_global_contract_fail
    mov rdi, [rsp + 8]
    lea rsi, [r15 + tk_tb_kr_OUTPUT]
    mov ecx, eax
    rep movsb
tk_tb_retention_remove_no_copy:
    mov eax, ebx
    add rsp, 24
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret
tk_tb_retention_hot_read_result:
    mov qword ptr [r15 + 128], -1
    mov ebx, eax
    cmp eax, 0xffffffff
    je tk_tb_retention_read_no_copy
    cmp eax, 0xfffffffe
    je tk_tb_retention_read_no_copy
    cmp eax, 32
    jb tk_tb_global_contract_fail
    cmp eax, 544
    ja tk_tb_global_contract_fail
    mov rdi, [rsp + 8]
    lea rsi, [r15 + tk_tb_kr_OUTPUT]
    mov ecx, eax
    rep movsb
tk_tb_retention_read_no_copy:
    mov eax, ebx
    add rsp, 24
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret
tk_tb_retention_read_entry:
    mov rax, [r15 + 4000]
    mov rax, [rax + tk_tb_G_REMOVE]
    mov [rax + 4008], rcx
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp, 24
    mov [rsp], rdi
    mov [rsp + 8], rdx
    mov [rsp + 16], rsi
    mov rax, [r15 + 4000]
    mov r15, [rax + tk_tb_G_REMOVE]
    mov r13, r15
    lea r12, [r15 + tk_tb_kr_OWNER]
    lea rdi, [r15 + tk_tb_kr_INPUT]
    mov esi, 1048576
    mov edx, 3
    mov eax, 10
    syscall
    test rax, rax
    jnz tk_tb_global_io_fail
    lea rdi, [r15 + tk_tb_kr_INPUT]
    mov rsi, [rsp]
    mov rcx, [rsp + 16]
    mov [r15 + 24], rcx
    rep movsb
    lea rdi, [r15 + tk_tb_kr_INPUT]
    mov esi, 1048576
    mov edx, 1
    mov eax, 10
    syscall
    test rax, rax
    jnz tk_tb_global_io_fail
    cmp qword ptr [r15 + 128], -1
    jne tk_tb_global_contract_fail
    mov rax, [r15 + 4008]
    test rax, rax
    js tk_tb_global_contract_fail
    mov [r15 + 128], rax
    mov qword ptr [r15 + 4016], 1
    lea r12, [r15 + tk_tb_kr_OWNER]
    lea r13, [r15 + tk_tb_kr_REMOVE_OWNER]
    jmp tk_tb_kr_resume_owner
tk_tb_retention_remove_entry:
    mov rax, [r15 + 4000]
    mov rax, [rax + tk_tb_G_REMOVE]
    mov [rax + 4008], rcx
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp, 24
    mov [rsp], rdi
    mov [rsp + 8], rdx
    mov [rsp + 16], rsi
    mov rax, [r15 + 4000]
    mov r15, [rax + tk_tb_G_REMOVE]
    mov r13, r15
    lea r12, [r15 + tk_tb_kr_REMOVE_OWNER]
    lea rdi, [r15 + tk_tb_kr_INPUT]
    mov esi, 1048576
    mov edx, 3
    mov eax, 10
    syscall
    test rax, rax
    jnz tk_tb_global_io_fail
    lea rdi, [r15 + tk_tb_kr_INPUT]
    mov rsi, [rsp]
    mov rcx, [rsp + 16]
    mov [r15 + 24], rcx
    rep movsb
    lea rdi, [r15 + tk_tb_kr_INPUT]
    mov esi, 1048576
    mov edx, 1
    mov eax, 10
    syscall
    test rax, rax
    jnz tk_tb_global_io_fail
    cmp qword ptr [r15 + 128], -1
    jne tk_tb_global_contract_fail
    mov rax, [r15 + 4008]
    test rax, rax
    js tk_tb_global_contract_fail
    mov [r15 + 128], rax
    mov qword ptr [r15 + 4016], 0
    lea r12, [r15 + tk_tb_kr_OWNER]
    lea r13, [r15 + tk_tb_kr_REMOVE_OWNER]
    jmp tk_tb_kr_resume_remove

.equ tk_tb_K_INPUT, 4096
.equ tk_tb_K_OUTPUT, 1052672
.equ tk_tb_K_OWNER, 2097152
.equ tk_tb_K_WORK, 8388608
.equ tk_tb_K_BYTES, 10489856
.equ tk_tb_KB_ACTION, 4194560
.equ tk_tb_KB_REQUEST, 4198400
.equ tk_tb_KB_REPLY, 4206592
.equ tk_tb_KB_SEQUENCE, 4194320
.equ tk_tb_KB_PHASE, 4194312
.equ tk_tb_KB_HOT, 4194368
.equ tk_tb_KB_ARCHIVE, 4194376

# r15 is the private Retention mapping; the original HIA context frame owns
# selection of its Arc. Native fields 40/48 bind that context to Directory.
tk_tb_retention_admission:
    lea r12, [r15 + tk_tb_K_OWNER]
    mov rax, 0x313051544b415248
    cmp [r15 + tk_tb_K_INPUT], rax
    je tk_tb_retention_context
    mov rax, 0x313030514b415248
    cmp [r15 + tk_tb_K_INPUT], rax
    jne tk_tb_global_contract_fail
    mov rax, [r15 + 4000]
    mov rcx, [rax + tk_tb_G_DIRECTORY]
    cmp [r15 + 40], rcx
    jne tk_tb_global_contract_fail
    mov rcx, [rax + tk_tb_G_ACTION]
    mov rcx, [rcx + 24]
    cmp [r15 + 48], rcx
    jne tk_tb_global_contract_fail
    mov rdx, [r12 + tk_tb_KB_ARCHIVE]
    call tk_tb_cold_live_lease
    test eax, eax
    jz tk_tb_global_contract_fail
    jmp tk_tb_retention_resume
tk_tb_retention_context:
    cmp qword ptr [r15 + 24], 32
    jne tk_tb_global_contract_fail
    cmp qword ptr [r15 + tk_tb_K_INPUT + 8], 1
    jne tk_tb_global_contract_fail
    cmp qword ptr [r15 + tk_tb_K_INPUT + 24], 0
    jne tk_tb_global_contract_fail
    mov rdx, [r15 + tk_tb_K_INPUT + 16]
    call tk_tb_cold_live_lease
    test eax, eax
    jz tk_tb_global_contract_fail
tk_tb_retention_resume:
    lea rdi, [r15 + tk_tb_K_INPUT]
    mov rsi, [r15 + 24]
    lea rdx, [r15 + tk_tb_K_OUTPUT]
    mov ecx, 266432
    mov r8, r12
    mov r9d, tk_tb_K_WORK
    call qword ptr [rip + tk_ticket_backend_retention_image]
    mov ecx, eax
    cmp rax, rcx
    jne tk_tb_global_contract_fail
    cmp eax, 0xfffffff0
    jne tk_tb_retention_result
    lea r14, [r12 + tk_tb_KB_ACTION]
    mov rax, 0x313041474b415248
    cmp [r14], rax
    jne tk_tb_global_contract_fail
    mov rax, [r15 + 16]
    inc rax
    jz tk_tb_global_contract_fail
    cmp [r14 + 8], rax
    jne tk_tb_global_contract_fail
    cmp [r12 + tk_tb_KB_SEQUENCE], rax
    jne tk_tb_global_contract_fail
    mov [r15 + 16], rax
    mov rax, [r14 + 64]
    or rax, [r14 + 72]
    or rax, [r14 + 80]
    or rax, [r14 + 88]
    jnz tk_tb_global_contract_fail
    cmp qword ptr [r14 + 32], tk_tb_KB_REQUEST
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 48], tk_tb_KB_REPLY
    jne tk_tb_global_contract_fail
    cmp qword ptr [r14 + 56], 8192
    jne tk_tb_global_contract_fail
    mov rsi, [r14 + 40]
    cmp rsi, 24
    jb tk_tb_global_contract_fail
    cmp rsi, 576
    ja tk_tb_global_contract_fail
    lea rdi, [r12 + tk_tb_KB_REQUEST]
    lea rdx, [r12 + tk_tb_KB_REPLY]
    mov rax, [r14 + 16]
    cmp rax, 100
    je tk_tb_retention_read_effect
    cmp rax, 101
    je tk_tb_retention_archive_effect
    cmp rax, 102
    je tk_tb_retention_activity_effect
    cmp rax, 103
    jne tk_tb_global_contract_fail
    call tk_tb_retention_hot_descriptor
    call tk_tb_retention_remove_entry
    jmp tk_tb_retention_child_return
tk_tb_retention_read_effect:
    call tk_tb_retention_hot_descriptor
    call tk_tb_retention_read_entry
    jmp tk_tb_retention_child_return
tk_tb_retention_archive_effect:
    cmp qword ptr [r14 + 24], 0
    jne tk_tb_global_contract_fail
    call tk_tb_cold_save_entry
    jmp tk_tb_retention_child_return
tk_tb_retention_activity_effect:
    cmp qword ptr [r14 + 24], 0
    jne tk_tb_global_contract_fail
    mov rcx, [r15 + 4000]
    mov rcx, [rcx + tk_tb_G_SG]
    mov rcx, [rcx + 8]
    add rcx, 8192
    call tk_active_policy_run
    cmp eax, 64
    jne tk_tb_global_contract_fail
tk_tb_retention_child_return:
    mov ecx, eax
    cmp rax, rcx
    jne tk_tb_global_contract_fail
    mov [r14 + 72], rax
    mov rax, [r14 + 8]
    mov [r14 + 64], rax
    jmp tk_tb_retention_resume
tk_tb_retention_hot_descriptor:
    cmp qword ptr [r14 + 24], 1
    jne tk_tb_global_contract_fail
    mov rcx, [r15 + 4000]
    mov rcx, [rcx + tk_tb_G_HOT_FDS]
    test rcx, rcx
    js tk_tb_global_contract_fail
    ret
tk_tb_retention_result:
    cmp eax, 0xffffffff
    je tk_tb_retention_result_return
    cmp eax, 0xfffffffe
    je tk_tb_retention_result_return
    cmp eax, 32
    jb tk_tb_global_contract_fail
    cmp eax, 266432
    ja tk_tb_global_contract_fail
    cmp qword ptr [r12 + tk_tb_KB_PHASE], 0
    jne tk_tb_global_contract_fail
    cmp qword ptr [r12 + 8], 0
    jne tk_tb_global_contract_fail
    cmp eax, 32
    jne tk_tb_retention_result_return
    mov rcx, 0x313052544b415248
    cmp [r15 + tk_tb_K_OUTPUT], rcx
    jne tk_tb_global_contract_fail
    mov rdx, [r15 + 4000]
    mov rcx, [rdx + tk_tb_G_DIRECTORY]
    mov [r15 + 40], rcx
    mov rcx, [rdx + tk_tb_G_ACTION]
    mov rcx, [rcx + 24]
    mov [r15 + 48], rcx
tk_tb_retention_result_return:
    ret

# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
.equ tk_tb_G_SG, 832
.equ tk_tb_G_BUSY, 840
.equ tk_tb_G_ACTION, 848
.equ tk_tb_G_REQUEST, 856
.equ tk_tb_G_LENGTH, 864
.equ tk_tb_G_REPLY, 872
.equ tk_tb_G_DIRECTORY, 880
.equ tk_tb_G_RESULT, 896
.equ tk_tb_G_RETENTION, 904
.equ tk_tb_G_REMOVE, 912
.equ tk_tb_G_SCRATCH, 2048

# edi is the complete mapping size, including its final guard page.
tk_tb_backend_allocate:
    push rbx
    push r12
    sub rsp, 8
    mov ebx, edi
    test ebx, 4095
    jnz tk_tb_global_contract_fail
    cmp ebx, 8192
    jb tk_tb_global_contract_fail
    xor edi, edi
    mov esi, ebx
    mov edx, 3
    mov r10d, 34
    mov r8, -1
    xor r9d, r9d
    mov eax, 9
    syscall
    cmp rax, -4095
    jae tk_tb_global_io_fail
    mov r12, rax
    lea rdi, [rax + rbx - 4096]
    mov esi, 4096
    xor edx, edx
    mov eax, 10
    syscall
    test rax, rax
    jnz tk_tb_global_io_fail
    mov rax, r12
    add rsp, 8
    pop r12
    pop rbx
    ret

tk_ticket_backend_create:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp, 8
    cld
    mov r12, rdi
    test r12, r12
    jz tk_contract_fail
    mov rax, 0x3130475354415248
    cmp [r12], rax
    jne tk_contract_fail
    cmp qword ptr [r12 + 8], 0
    je tk_contract_fail
    cmp qword ptr [r12 + 16], 0
    jne tk_contract_fail
    mov edi, tk_tb_G_BYTES
    call tk_tb_backend_allocate
    mov r15, rax
    mov rdx, 0x31304b4254415248
    mov [r15], rdx
    mov [r15 + tk_tb_I_GLOBAL], r15
    mov [r15 + 4000], r15
    mov [r15 + tk_tb_G_SG], r12
    mov [r12 + 16], r15
    mov qword ptr [r15 + tk_tb_G_ROOT_COUNT], 1
    lea rdi, [r15 + tk_tb_G_ROOT_FDS]
    mov ecx, 64
    mov rax, -1
    rep stosq
    lea rdi, [r15 + tk_tb_G_HOT_FDS]
    mov ecx, 17
    rep stosq
    mov edi, tk_tb_G_INITIAL_WORK + 4096
    call tk_tb_backend_allocate
    mov [r15 + tk_tb_G_WORK], rax
    mov qword ptr [r15 + tk_tb_G_WORK_BYTES], tk_tb_G_INITIAL_WORK
    mov qword ptr [rax + 136], 1
    mov edi, tk_tb_G_NAMESPACE_BYTES
    call tk_tb_backend_allocate
    mov [r15 + tk_tb_G_NAMESPACE], rax
    mov [rax + 4000], r15
    mov qword ptr [rax + 4008], -1
    lea rdi, [rax + 16384]
    mov ecx, 33794
    mov rax, -1
    rep stosq
    mov edi, tk_tb_G_ENTROPY_BYTES
    call tk_tb_backend_allocate
    mov [r15 + tk_tb_G_ENTROPY], rax
    mov [rax + 4000], r15
    mov qword ptr [rax + 152], -1
    mov qword ptr [rax + 160], -1
    call tk_tb_save_allocate
    call tk_tb_cold_allocate
    mov edi, tk_tb_K_BYTES
    call tk_tb_backend_allocate
    mov [r15 + tk_tb_G_RETENTION], rax
    mov [rax + 4000], r15
    mov edi, tk_tb_kr_MAP_SIZE
    call tk_tb_backend_allocate
    mov [r15 + tk_tb_G_REMOVE], rax
    mov [rax + 4000], r15
    lea rdi, [rax + 128]
    mov ecx, 7
    mov rax, -1
    rep stosq
    mov rax, r15
    add rsp, 8
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

# The Directory pointer must be an actual member of the service's live
# Storage list. Its exact HIA lease is then checked by the original callable.
tk_tb_backend_hot_borrow:
    push rbx
    push rbp
    sub rsp, 8
    mov rbx, [r15 + tk_tb_G_SG]
    mov rbp, [r15 + tk_tb_G_DIRECTORY]
    test rbp, rbp
    jz tk_tb_global_contract_fail
    mov rdx, [rbx + 40]
    xor ecx, ecx
tk_tb_backend_hot_next:
    test rdx, rdx
    jz tk_tb_global_contract_fail
    cmp [rdx + 16], rbx
    jne tk_tb_global_contract_fail
    cmp [rdx + 32], rcx
    jne tk_tb_global_contract_fail
    cmp qword ptr [rdx + 8], 0
    je tk_tb_global_contract_fail
    cmp [rdx + 80], rbp
    je tk_tb_backend_hot_found
    mov rcx, rdx
    mov rdx, [rdx + 24]
    jmp tk_tb_backend_hot_next
tk_tb_backend_hot_found:
    mov rdi, rbp
    mov rsi, [r15 + tk_tb_G_ACTION]
    mov rsi, [rsi + 24]
    call tk_ticket_directory_borrow
    test rax, rax
    js tk_tb_global_contract_fail
    mov [r15 + tk_tb_G_HOT_FDS], rax
    add rsp, 8
    pop rbp
    pop rbx
    ret

# rdi=SG, rsi=actual action96, rdx=request, rcx=length, r8=reply,
# r9=owned Directory context. No JSON/serialized authority enters this ABI.
tk_ticket_backend_call:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp, 8
    cld
    mov rax, 0x3130475354415248
    cmp [rdi], rax
    jne tk_contract_fail
    mov r15, [rdi + 16]
    test r15, r15
    jz tk_contract_fail
    mov rax, 0x31304b4254415248
    cmp [r15], rax
    jne tk_contract_fail
    cmp [r15 + tk_tb_G_SG], rdi
    jne tk_contract_fail
    cmp [r15 + tk_tb_I_GLOBAL], r15
    jne tk_contract_fail
    cmp [r15 + 4000], r15
    jne tk_contract_fail
    cmp qword ptr [r15 + tk_tb_G_BUSY], 0
    jne tk_contract_fail
    cmp qword ptr [r15 + tk_tb_G_ROOT_FDS], -1
    jne tk_contract_fail
    cmp qword ptr [r15 + tk_tb_G_HOT_FDS], -1
    jne tk_contract_fail
    mov rax, 0x3130415354415248
    cmp [rsi], rax
    jne tk_contract_fail
    cmp qword ptr [rsi + 8], 0
    je tk_contract_fail
    cmp qword ptr [rsi + 32], 4096
    jne tk_contract_fail
    cmp [rsi + 40], rcx
    jne tk_contract_fail
    cmp rcx, 16
    jb tk_contract_fail
    cmp rcx, 1048576
    ja tk_contract_fail
    cmp qword ptr [rsi + 48], 2101248
    jne tk_contract_fail
    cmp qword ptr [rsi + 56], 270000
    jne tk_contract_fail
    mov rax, [rsi + 64]
    or rax, [rsi + 72]
    or rax, [rsi + 80]
    or rax, [rsi + 88]
    jnz tk_contract_fail
    lea rax, [rsi + 3840]
    cmp rax, rdx
    jne tk_contract_fail
    lea rax, [rsi + 2100992]
    cmp rax, r8
    jne tk_contract_fail
    mov [r15 + tk_tb_G_ACTION], rsi
    mov [r15 + tk_tb_G_REQUEST], rdx
    mov [r15 + tk_tb_G_LENGTH], rcx
    mov [r15 + tk_tb_G_REPLY], r8
    mov [r15 + tk_tb_G_DIRECTORY], r9
    mov qword ptr [r15 + tk_tb_G_BUSY], 1
    mov rax, [rsi + 16]
    cmp rax, 3
    je tk_tb_backend_archive
    cmp rax, 4
    je tk_tb_backend_cold
    cmp rax, 5
    je tk_tb_backend_retention
    cmp rax, 6
    je tk_tb_backend_read
    cmp rax, 8
    je tk_tb_backend_stamp
    jmp tk_tb_global_contract_fail

tk_tb_backend_archive:
    cmp qword ptr [r15 + tk_tb_G_LENGTH], 64
    jb tk_tb_global_contract_fail
    cmp qword ptr [r15 + tk_tb_G_LENGTH], 4096
    ja tk_tb_global_contract_fail
    mov rbx, [r15 + tk_tb_G_REQUEST]
    mov rax, 0x313030514f415248
    cmp [rbx], rax
    je tk_tb_backend_archive_operation
    mov rax, 0x3130515653415248
    cmp [rbx], rax
    jne tk_tb_global_contract_fail
    cmp qword ptr [rbx + 8], 1
    jne tk_tb_global_contract_fail
    jmp tk_tb_backend_archive_lease
tk_tb_backend_archive_operation:
    cmp qword ptr [rbx + 8], 1
    jne tk_tb_backend_archive_lease
    cmp qword ptr [rbx + 16], 0
    jne tk_tb_global_contract_fail
    mov rdi, [r15 + tk_tb_G_SG]
    mov rdi, [rdi + 24]
    mov rsi, [r15 + tk_tb_G_ACTION]
    mov rsi, [rsi + 24]
    call tk_ticket_directory_borrow
    mov [r15 + tk_tb_G_ROOT_FDS], rax
    jmp tk_tb_backend_archive_ready
tk_tb_backend_archive_lease:
    mov rdx, [rbx + 16]
    mov rax, [r15 + tk_tb_G_ACTION]
    cmp [rax + 24], rdx
    jne tk_tb_global_contract_fail
    call tk_tb_cold_live_lease
    test eax, eax
    jz tk_tb_global_contract_fail
tk_tb_backend_archive_ready:
    mov rdi, [r15 + tk_tb_G_REQUEST]
    mov rsi, [r15 + tk_tb_G_LENGTH]
    mov rdx, [r15 + tk_tb_G_REPLY]
    call tk_tb_cold_save_entry
    jmp tk_tb_backend_return

tk_tb_backend_cold:
    call tk_tb_backend_hot_borrow
    mov rbx, [r15 + tk_tb_G_COLD]
    mov qword ptr [r15 + tk_tb_G_RESULT], tk_tb_C_OUTPUT
    jmp tk_tb_backend_copy_owner_input
tk_tb_backend_retention:
    call tk_tb_backend_hot_borrow
    mov rbx, [r15 + tk_tb_G_RETENTION]
    mov qword ptr [r15 + tk_tb_G_RESULT], tk_tb_K_OUTPUT
tk_tb_backend_copy_owner_input:
    lea rdi, [rbx + 4096]
    mov esi, 1048576
    mov edx, 3
    mov eax, 10
    syscall
    test rax, rax
    jnz tk_tb_global_io_fail
    lea rdi, [rbx + 4096]
    mov rsi, [r15 + tk_tb_G_REQUEST]
    mov rcx, [r15 + tk_tb_G_LENGTH]
    mov [rbx + 24], rcx
    rep movsb
    lea rdi, [rbx + 4096]
    mov esi, 1048576
    mov edx, 1
    mov eax, 10
    syscall
    test rax, rax
    jnz tk_tb_global_io_fail
    mov rax, [r15 + tk_tb_G_ACTION]
    cmp qword ptr [rax + 16], 5
    je tk_tb_backend_retention_run
    mov r15, rbx
    lea r12, [r15 + tk_tb_C_OWNER]
    call tk_tb_cold_preflight
    jmp tk_tb_backend_copy_owner_result
tk_tb_backend_retention_run:
    mov r15, rbx
    call tk_tb_retention_admission
tk_tb_backend_copy_owner_result:
    mov ecx, eax
    cmp rax, rcx
    jne tk_tb_global_contract_fail
    mov ebp, eax
    mov rdx, [r15 + 4000]
    cmp eax, 266432
    ja tk_tb_backend_owner_refusal
    cmp eax, 32
    jb tk_tb_global_contract_fail
    mov rdi, [rdx + tk_tb_G_REPLY]
    mov rsi, [rdx + tk_tb_G_RESULT]
    add rsi, r15
    mov ecx, eax
    rep movsb
    jmp tk_tb_backend_owner_complete
tk_tb_backend_owner_refusal:
    cmp eax, 0xfffffff9
    je tk_tb_backend_owner_complete
    cmp eax, 0xfffffffe
    jb tk_tb_global_contract_fail
tk_tb_backend_owner_complete:
    mov r15, rdx
    mov eax, ebp
    jmp tk_tb_backend_return
tk_tb_backend_read:
    call tk_tb_backend_hot_borrow
    mov rcx, rax
    mov rdi, [r15 + tk_tb_G_REQUEST]
    mov rsi, [r15 + tk_tb_G_LENGTH]
    cmp rsi, 93
    jne tk_tb_global_contract_fail
    mov rdx, [r15 + tk_tb_G_REPLY]
    call tk_tb_retention_read_entry
    jmp tk_tb_backend_return
tk_tb_backend_stamp:
    call tk_tb_backend_hot_borrow
    mov rcx, rax
    mov rdi, [r15 + tk_tb_G_REQUEST]
    mov rsi, [r15 + tk_tb_G_LENGTH]
    cmp rsi, 16
    jne tk_tb_global_contract_fail
    mov rdx, [r15 + tk_tb_G_REPLY]
    call tk_tb_cold_stamp_entry
tk_tb_backend_return:
    mov edx, eax
    cmp rax, rdx
    jne tk_tb_global_contract_fail
    mov ebx, eax
    mov qword ptr [r15 + tk_tb_G_ROOT_FDS], -1
    mov qword ptr [r15 + tk_tb_G_HOT_FDS], -1
    mov qword ptr [r15 + tk_tb_G_ACTION], 0
    mov qword ptr [r15 + tk_tb_G_REQUEST], 0
    mov qword ptr [r15 + tk_tb_G_LENGTH], 0
    mov qword ptr [r15 + tk_tb_G_REPLY], 0
    mov qword ptr [r15 + tk_tb_G_DIRECTORY], 0
    mov qword ptr [r15 + tk_tb_G_RESULT], 0
    mov qword ptr [r15 + tk_tb_G_BUSY], 0
    mov eax, ebx
    add rsp, 8
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

# Finish all actual Arc lifetimes through Registry HIA before retiring its
# remaining caches. Directory, RawWrite and Activity belong to the service.
tk_ticket_backend_drop:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp, 8
    mov rax, 0x3130475354415248
    cmp [rdi], rax
    jne tk_contract_fail
    mov r15, [rdi + 16]
    test r15, r15
    jz tk_tb_backend_drop_done
    mov rax, 0x31304b4254415248
    cmp [r15], rax
    jne tk_contract_fail
    cmp [r15 + tk_tb_G_SG], rdi
    jne tk_contract_fail
    cmp qword ptr [r15 + tk_tb_G_BUSY], 0
    jne tk_contract_fail
    cmp qword ptr [r15 + tk_tb_G_ROOT_FDS], -1
    jne tk_contract_fail
    cmp qword ptr [r15 + tk_tb_G_HOT_FDS], -1
    jne tk_contract_fail
    cmp qword ptr [r15 + 112], 0
    jne tk_contract_fail
    mov qword ptr [r15 + tk_tb_G_BUSY], 1
    mov r12, [r15 + tk_tb_G_WORK]
    cmp qword ptr [r12 + 8], 0
    jne tk_contract_fail
    cmp qword ptr [r12], 0
    je tk_tb_backend_drop_instances_done
    lea rdi, [r15 + tk_tb_G_SCRATCH]
    xor eax, eax
    mov ecx, 8
    rep stosq
    mov rax, 0x3130305751415248
    mov [r15 + tk_tb_G_SCRATCH], rax
    mov qword ptr [r15 + tk_tb_G_SCRATCH + 8], 16
    lea rdi, [r15 + tk_tb_G_SCRATCH]
    mov esi, 64
    lea rdx, [r15 + tk_tb_G_SCRATCH + 128]
    mov ecx, 2
    call tk_tb_registry_entry
    cmp eax, 64
    jne tk_contract_fail
    cmp qword ptr [r15 + tk_tb_G_SCRATCH + 136], 0
    jne tk_contract_fail
tk_tb_backend_drop_instances_done:
    cmp qword ptr [r15 + tk_tb_G_INSTANCES], 0
    jne tk_contract_fail
    mov rax, [r15 + tk_tb_G_RETENTION]
    cmp qword ptr [rax + tk_tb_K_OWNER + 8], 0
    jne tk_contract_fail
    cmp qword ptr [rax + tk_tb_K_OWNER + tk_tb_KB_PHASE], 0
    jne tk_contract_fail
    mov rax, [r15 + tk_tb_G_COLD]
    cmp qword ptr [rax + tk_tb_C_OWNER + 8], 0
    jne tk_contract_fail
    cmp qword ptr [rax + tk_tb_C_OWNER + tk_tb_B_PHASE], 0
    jne tk_contract_fail
    call tk_tb_cleanup_save_descriptors
    call tk_tb_cleanup_cold_descriptors
    mov rax, [r15 + tk_tb_G_REMOVE]
    mov qword ptr [rax + 128], -1
    lea rbx, [rax + 136]
    mov r13d, 6
    call tk_tb_cleanup_table
    mov rax, [r15 + tk_tb_G_NAMESPACE]
    mov [rax + 4000], r15
    lea rdi, [rax + 16384]
    mov ecx, 259
    mov rax, -1
    rep stosq
    mov rax, [r15 + tk_tb_G_NAMESPACE]
    lea rbx, [rax + 16384 + 259*8]
    mov r13d, 33535
    call tk_tb_cleanup_table
    mov rax, [r15 + tk_tb_G_ENTROPY]
    lea rbx, [rax + 152]
    mov r13d, 2
    call tk_tb_cleanup_table
    # Release each disjoint mapping only after its descriptor scan completes.
    mov edi, tk_tb_G_RETENTION
    mov esi, tk_tb_K_BYTES
    call tk_tb_backend_unmap_slot
    mov edi, tk_tb_G_REMOVE
    mov esi, tk_tb_kr_MAP_SIZE
    call tk_tb_backend_unmap_slot
    mov edi, tk_tb_G_COLD
    mov esi, tk_tb_C_BYTES
    call tk_tb_backend_unmap_slot
    mov edi, tk_tb_G_STAMP
    mov esi, tk_tb_CS_BYTES
    call tk_tb_backend_unmap_slot
    mov edi, tk_tb_G_ENTRIES
    mov esi, tk_tb_CE_BYTES
    call tk_tb_backend_unmap_slot
    mov edi, tk_tb_G_SAVE
    mov esi, tk_tb_S_BYTES
    call tk_tb_backend_unmap_slot
    mov edi, tk_tb_G_WRITE
    mov esi, tk_tb_RW_BYTES
    call tk_tb_backend_unmap_slot
    mov edi, tk_tb_G_NAMESPACE
    mov esi, tk_tb_G_NAMESPACE_BYTES
    call tk_tb_backend_unmap_slot
    mov edi, tk_tb_G_ENTROPY
    mov esi, tk_tb_G_ENTROPY_BYTES
    call tk_tb_backend_unmap_slot
    mov edi, tk_tb_G_WORK
    mov rsi, [r15 + tk_tb_G_WORK_BYTES]
    add rsi, 4096
    jc tk_contract_fail
    call tk_tb_backend_unmap_slot
    mov rax, [r15 + tk_tb_G_SG]
    cmp [rax + 16], r15
    jne tk_contract_fail
    mov qword ptr [rax + 16], 0
    mov rdi, r15
    mov esi, tk_tb_G_BYTES
    mov eax, 11
    syscall
    test rax, rax
    jnz tk_io_fail
tk_tb_backend_drop_done:
    add rsp, 8
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

tk_tb_backend_unmap_slot:
    lea rdx, [r15 + rdi]
    mov rdi, [rdx]
    test rdi, rdi
    jz tk_contract_fail
    mov qword ptr [rdx], 0
    mov eax, 11
    syscall
    test rax, rax
    jnz tk_io_fail
    ret

# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
# Callable HIA broker: input/length/output plus a private, single-caller context.
tk_leaf_call:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp, 8
    mov r15, rcx
    xor eax, eax
    mov r8d, 1
    lock cmpxchg dword ptr [r15 + 96], r8d
    jne tk_contract_fail
    mov [r15 + 32], rdi
    mov [r15 + 40], rdx
    mov [r15 + 48], rsi
    lea r12, [r15 + tk_LEAF_WORK]
tk_leaf_resume:
    mov rdi, [r15 + 32]
    mov rsi, [r15 + 48]
    mov rdx, [r15 + 40]
    mov ecx, 128
    mov r8, r12
    mov r9d, 8192
    call qword ptr [rip + tk_image_table]
    mov edx, eax
    cmp rax, rdx
    jne tk_contract_fail
    cmp eax, 0xfffffff0
    jne tk_leaf_return
    cmp qword ptr [r12 + 8], 1
    jne tk_contract_fail
    lea r14, [r12 + 256]
    mov rax, 0x3130414c54415248
    cmp [r14], rax
    jne tk_contract_fail
    mov rax, [r15 + 56]
    inc rax
    jz tk_contract_fail
    cmp [r14 + 8], rax
    jne tk_contract_fail
    cmp [r12 + 16], rax
    jne tk_contract_fail
    mov [r15 + 56], rax
    cmp qword ptr [r14 + 32], 1024
    jne tk_contract_fail
    cmp qword ptr [r14 + 48], 2048
    jne tk_contract_fail
    cmp qword ptr [r14 + 56], 128
    jne tk_contract_fail
    mov rax, [r14 + 24]
    or rax, [r14 + 64]
    or rax, [r14 + 72]
    or rax, [r14 + 80]
    or rax, [r14 + 88]
    jnz tk_contract_fail
    mov rcx, [r14 + 40]
    cmp rcx, [r12 + 120]
    jne tk_contract_fail
    cmp rcx, 128
    ja tk_contract_fail
    lea rsi, [r12 + 1024]
    lea rdi, [r12 + 3072]
    repe cmpsb
    jne tk_contract_fail
    mov rax, [r14 + 16]
    cmp rax, [r12 + 112]
    jne tk_contract_fail
    cmp rax, 1
    je tk_leaf_lock
    cmp rax, 2
    je tk_leaf_active
    cmp rax, 3
    je tk_leaf_clock
    cmp rax, 4
    je tk_leaf_identity
    jmp tk_contract_fail
tk_leaf_lock:
    cmp qword ptr [r14 + 40], 64
    jne tk_contract_fail
    lea rdi, [r15 + tk_LOCK_CONTEXT + 256]
    lea rsi, [r12 + 1024]
    mov ecx, 8
    rep movsq
    lea rdi, [r15 + tk_LOCK_CONTEXT]
    call tk_lock_run_command
    lea rdi, [r12 + 2048]
    lea rsi, [r15 + tk_LOCK_CONTEXT + 640]
    mov ecx, 10
    rep movsq
    mov rax, [r15 + tk_LOCK_CONTEXT + 152]
    mov [r12 + 2048 + 80], rax
    mov eax, 88
    jmp tk_leaf_ack
tk_leaf_active:
    lea rdi, [r12 + 1024]
    mov rsi, [r14 + 40]
    lea rdx, [r12 + 2048]
    mov rcx, [r15]
    add rcx, tk_GLOBAL_ACTIVITY
    call tk_active_policy_run
    jmp tk_leaf_ack
tk_leaf_clock:
    cmp qword ptr [r14 + 40], 32
    jne tk_contract_fail
    mov rdi, r15
    call tk_clock_entry
    jmp tk_leaf_ack
tk_leaf_identity:
    cmp qword ptr [r14 + 40], 24
    jne tk_contract_fail
    lea rdi, [r12 + 1024]
    lea rsi, [r12 + 2048]
    mov rdx, [r15]
    add rdx, tk_GLOBAL_ENTROPY
    call tk_identity_entry
tk_leaf_ack:
    mov edx, eax
    cmp rax, rdx
    jne tk_contract_fail
    cmp eax, 128
    ja tk_contract_fail
    mov [r14 + 72], rax
    mov rax, [r14 + 8]
    mov [r14 + 64], rax
    jmp tk_leaf_resume
tk_leaf_return:
    mov ebx, eax
    xor eax, eax
    xchg [r15 + 96], eax
    cmp eax, 1
    jne tk_contract_fail
    mov eax, ebx
    add rsp, 8
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

# Read-only activity lookup uses the same arena and gate as every live Ticket.
tk_activity_lookup:
    cmp rsi, 128
    jne tk_contract_fail
    mov rax, 0x3130305141415248
    cmp [rdi], rax
    jne tk_contract_fail
    mov rax, [rdi + 8]
    cmp rax, 6
    je tk_activity_lookup_kind
    cmp rax, 7
    jne tk_contract_fail
tk_activity_lookup_kind:
    cmp qword ptr [rdi + 16], 0
    jne tk_contract_fail
    cmp qword ptr [rdi + 24], 64
    jne tk_contract_fail
    mov rax, [rdi + 32]
    or rax, [rdi + 40]
    or rax, [rdi + 48]
    or rax, [rdi + 56]
    jnz tk_contract_fail
    mov rcx, [rcx]
    add rcx, tk_GLOBAL_ACTIVITY
    jmp tk_active_policy_run

# EOF/drop disposal still traverses the broker and the actual child owners.
tk_leaf_retire:
    push rbx
    push r12
    push r15
    mov r15, rdi
    mov ebx, 4
tk_leaf_retire_resource:
    lea r12, [r15 + tk_LEAF_WORK]
    mov rax, [r12 + 88]
    cmp ebx, 4
    je tk_leaf_retire_found
    mov rax, [r12 + 72]
    cmp ebx, 3
    je tk_leaf_retire_found
    mov rax, [r12 + 64]
tk_leaf_retire_found:
    test rax, rax
    jz tk_leaf_retire_next
    lea rdi, [r15 + tk_CLEANUP_REQUEST]
    mov r12, rax
    xor eax, eax
    mov ecx, 8
    rep stosq
    lea rdi, [r15 + tk_CLEANUP_REQUEST]
    mov rax, 0x3130514c54415248
    mov [rdi], rax
    mov qword ptr [rdi + 8], 122
    mov [rdi + 16], rbx
    mov qword ptr [rdi + 24], 8
    mov [rdi + 48], r12
    mov esi, 56
    lea rdx, [r15 + tk_CLEANUP_REPLY]
    mov rcx, r15
    call tk_leaf_call
    cmp eax, 48
    jne tk_contract_fail
    cmp qword ptr [r15 + tk_CLEANUP_REPLY + 8], 0
    jne tk_contract_fail
tk_leaf_retire_next:
    cmp ebx, 4
    jne tk_leaf_retire_was_pin
    mov ebx, 3
    jmp tk_leaf_retire_resource
tk_leaf_retire_was_pin:
    cmp ebx, 3
    jne tk_leaf_retire_timer
    mov ebx, 5
    jmp tk_leaf_retire_resource
tk_leaf_retire_timer:
    cmp qword ptr [r15 + tk_LEAF_WORK + 104], 0
    je tk_leaf_retire_done
    lea rdi, [r15 + tk_CLEANUP_REQUEST]
    xor eax, eax
    mov ecx, 6
    rep stosq
    lea rdi, [r15 + tk_CLEANUP_REQUEST]
    mov rax, 0x3130514c54415248
    mov [rdi], rax
    mov qword ptr [rdi + 8], 123
    mov esi, 48
    lea rdx, [r15 + tk_CLEANUP_REPLY]
    mov rcx, r15
    call tk_leaf_call
    cmp eax, 48
    jne tk_contract_fail
    cmp qword ptr [r15 + tk_CLEANUP_REPLY + 8], 0
    jne tk_contract_fail
tk_leaf_retire_done:
    pop r15
    pop r12
    pop rbx
    ret

# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
# Drive the unchanged Ticket policy through actual leaves. Storage stays borrowed.
tk_ticket_call:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp, 8
    mov r15, rdi
    cmp qword ptr [r15 + 104], 0
    jne tk_contract_fail
    mov r12, [r15 + 72]
    test r12, r12
    jnz tk_ticket_have_arena
    mov rax, [r15 + tk_LEAF_WORK + 64]
    or rax, [r15 + tk_LEAF_WORK + 72]
    or rax, [r15 + tk_LEAF_WORK + 88]
    or rax, [r15 + tk_LEAF_WORK + 104]
    jnz tk_contract_fail
    mov edi, tk_TICKET_MAP_BYTES
    call tk_allocate_guarded
    mov r12, rax
    mov [r15 + 72], rax
    mov qword ptr [r15 + 232], 1
tk_ticket_have_arena:
    cmp qword ptr [r12 + 8], 0
    jne tk_contract_fail
    mov rcx, [r15 + 192]
    cmp rcx, 2048
    ja tk_contract_fail
    mov [r15 + 80], rcx
    lea rdi, [r12 + tk_TICKET_INPUT]
    lea rsi, [r15 + tk_FRAME_INPUT]
    rep movsb
    jmp tk_ticket_drive

tk_ticket_resume_call:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp, 8
    mov r15, rdi
    cmp qword ptr [r15 + 104], 1
    jne tk_contract_fail
    mov r12, [r15 + 72]
    test r12, r12
    jz tk_contract_fail
    lea r13, [r12 + 1199968]
    mov rax, 0x31304b4341545248
    cmp [r13], rax
    jne tk_contract_fail
    mov rax, [r13 + 8]
    cmp rax, [r12 + 264]
    jne tk_contract_fail
    cmp rax, [r15 + 112]
    jne tk_contract_fail
    cmp qword ptr [r13 + 24], 0
    jne tk_contract_fail
    mov rcx, [r13 + 16]
    cmp rcx, 48
    jb tk_contract_fail
    cmp rcx, 270000
    ja tk_contract_fail
    lea rdx, [rcx + 32]
    cmp rdx, [r15 + 192]
    jne tk_contract_fail
    mov [r12 + 320], rax
    mov [r12 + 328], rcx
    mov qword ptr [r15 + 104], 0
tk_ticket_drive:
    lea rdi, [r12 + tk_TICKET_INPUT]
    mov rsi, [r15 + 80]
    lea rdx, [r12 + tk_TICKET_OUTPUT]
    mov ecx, 576
    mov r8, r12
    mov r9d, tk_TICKET_WORK_BYTES
    call qword ptr [rip + tk_image_table + 16]
    mov edx, eax
    cmp rax, rdx
    jne tk_contract_fail
    cmp eax, 0xfffffff0
    jne tk_ticket_result
    lea r14, [r12 + 256]
    mov rax, 0x3130304154415248
    cmp [r14], rax
    jne tk_contract_fail
    mov rax, [r15 + 112]
    inc rax
    jz tk_contract_fail
    cmp [r14 + 8], rax
    jne tk_contract_fail
    cmp [r12 + 16], rax
    jne tk_contract_fail
    cmp qword ptr [r14 + 32], 400000
    jne tk_contract_fail
    cmp qword ptr [r14 + 48], 1200000
    jne tk_contract_fail
    cmp qword ptr [r14 + 56], 270000
    jne tk_contract_fail
    mov rcx, [r14 + 40]
    cmp rcx, 270000
    ja tk_contract_fail
    test rcx, rcx
    jz tk_ticket_argument_equal
    lea rsi, [r12 + 400000]
    lea rdi, [r12 + 800000]
    repe cmpsb
    jne tk_contract_fail
tk_ticket_argument_equal:
    mov rcx, [r14 + 64]
    or rcx, [r14 + 72]
    or rcx, [r14 + 80]
    or rcx, [r14 + 88]
    jnz tk_contract_fail
    mov [r15 + 112], rax
    mov rbx, [r14 + 16]
    cmp rbx, 100
    jb tk_contract_fail
    cmp rbx, 122
    ja tk_contract_fail
    cmp rbx, 122
    jne tk_ticket_regular_phase
    cmp qword ptr [r12 + 8], 200
    jne tk_contract_fail
    cmp qword ptr [r14 + 24], 3
    jb tk_ticket_storage
    cmp qword ptr [r14 + 24], 5
    ja tk_contract_fail
    jmp tk_ticket_resource
tk_ticket_regular_phase:
    cmp [r12 + 8], rbx
    jne tk_contract_fail
    cmp rbx, 100
    je tk_ticket_resource
    cmp rbx, 104
    jb tk_ticket_storage
    cmp rbx, 108
    jbe tk_ticket_middle_resource
    cmp rbx, 112
    jb tk_ticket_storage
    cmp rbx, 116
    jbe tk_ticket_resource
    jmp tk_ticket_storage
tk_ticket_middle_resource:
    cmp rbx, 106
    je tk_ticket_storage
tk_ticket_resource:
    mov rcx, [r14 + 40]
    cmp rcx, 72
    ja tk_contract_fail
    lea rdi, [r15 + tk_CLEANUP_REQUEST]
    mov rax, 0x3130514c54415248
    mov [rdi], rax
    mov [rdi + 8], rbx
    mov rax, [r14 + 24]
    mov [rdi + 16], rax
    mov [rdi + 24], rcx
    mov qword ptr [rdi + 32], 0
    mov qword ptr [rdi + 40], 0
    add rdi, 48
    lea rsi, [r12 + 400000]
    rep movsb
    lea rdi, [r15 + tk_CLEANUP_REQUEST]
    mov rsi, [r14 + 40]
    add rsi, 48
    lea rdx, [r15 + tk_CLEANUP_REPLY]
    mov rcx, r15
    call tk_leaf_call
    cmp eax, 48
    jb tk_contract_fail
    cmp eax, 112
    ja tk_contract_fail
    mov [r14 + 72], rax
    mov rcx, rax
    lea rdi, [r12 + 1200000]
    lea rsi, [r15 + tk_CLEANUP_REPLY]
    rep movsb
    mov rax, [r14 + 8]
    mov [r14 + 64], rax
    inc qword ptr [r15 + 240]
    jz tk_contract_fail
    jmp tk_ticket_drive
tk_ticket_storage:
    mov qword ptr [r15 + 104], 1
    mov eax, 0xfffffff0
    jmp tk_ticket_return
tk_ticket_result:
    mov ebx, eax
    cmp qword ptr [r12 + 8], 0
    jne tk_contract_fail
    cmp eax, 576
    ja tk_ticket_return
    cmp eax, 64
    jb tk_contract_fail
    mov rax, 0x3130305254415248
    cmp [r12 + tk_TICKET_OUTPUT], rax
    jne tk_contract_fail
    cmp qword ptr [r12 + 128], 0
    jne tk_ticket_copy_result
    mov rax, [r15 + tk_LEAF_WORK + 64]
    or rax, [r15 + tk_LEAF_WORK + 72]
    or rax, [r15 + tk_LEAF_WORK + 88]
    jnz tk_contract_fail
    mov rdi, r15
    call tk_leaf_retire
tk_ticket_copy_result:
    lea rsi, [r12 + tk_TICKET_OUTPUT]
    lea rdi, [r15 + tk_FRAME_OUTPUT]
    mov ecx, ebx
    rep movsb
    mov eax, ebx
tk_ticket_return:
    add rsp, 8
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

# Each real worker retains its own non-transferable guard token across commands.
tk_lock_run_command:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp, 24
    mov r15, rdi
    mov rbx, [r15 + 64]
    mov r12, [r15 + 280]
    mov rax, [r15 + 272]
    cmp rax, [r15 + 144]
    jne tk_contract_fail
    cmp qword ptr [r15 + 304], 0
    jne tk_contract_fail
    lea rdi, [r15 + 384]
    xor eax, eax
    mov ecx, 16
    rep stosq
    mov rax, 0x313030514c415248
    mov [r15 + 384], rax
    cmp r12, 1
    je tk_lock_command_acquire
    cmp r12, 2
    je tk_lock_command_acquire
    cmp r12, 3
    jb tk_contract_fail
    cmp r12, 5
    jbe tk_lock_command_release
    cmp r12, 6
    je tk_lock_command_snapshot
    cmp r12, 7
    je tk_lock_command_queue_poison
    cmp r12, 8
    je tk_lock_command_inner_poison
    cmp r12, 9
    je tk_lock_command_notify
    cmp r12, 10
    je tk_lock_command_raw_acquire
    cmp r12, 11
    je tk_lock_command_raw_release
    cmp r12, 12
    je tk_lock_command_raw_panic
    cmp r12, 14
    je tk_lock_command_hold_queue
    cmp r12, 15
    je tk_lock_command_release_queue
    cmp r12, 16
    je tk_lock_command_fixture_counter
    cmp r12, 17
    je tk_lock_command_fixture_counter
    jmp tk_contract_fail
tk_lock_command_acquire:
    cmp qword ptr [r15 + 152], 0
    jne tk_contract_fail
    cmp qword ptr [r15 + 208], 0
    jne tk_contract_fail
    mov [r15 + 392], r12
    mov r13, [r15 + 288]
    cmp r13, 2
    ja tk_contract_fail
    test r13, r13
    jnz tk_lock_deadline_present
    cmp r12, 2
    je tk_contract_fail
    cmp qword ptr [r15 + 296], 0
    jne tk_contract_fail
    mov qword ptr [r15 + 168], 0
    mov qword ptr [r15 + 176], 0
    mov qword ptr [r15 + 184], 0
    jmp tk_lock_acquisition_call
tk_lock_deadline_present:
    mov edi, 1
    lea rsi, [r15 + 768]
    mov eax, 228
    syscall
    test rax, rax
    jnz tk_io_fail
    mov rax, [r15 + 768]
    mov [r15 + 176], rax
    mov rax, [r15 + 776]
    mov [r15 + 184], rax
    mov qword ptr [r15 + 168], 1
    cmp r13, 2
    je tk_lock_deadline_ready
    mov rax, [r15 + 296]
    mov rcx, 3600000000000
    cmp rax, rcx
    ja tk_contract_fail
    xor edx, edx
    mov ecx, 1000000000
    div rcx
    add [r15 + 176], rax
    jc tk_contract_fail
    add rdx, [r15 + 184]
    cmp rdx, rcx
    jb tk_lock_deadline_nanos
    sub rdx, rcx
    inc qword ptr [r15 + 176]
    jz tk_contract_fail
tk_lock_deadline_nanos:
    mov [r15 + 184], rdx
tk_lock_deadline_ready:
    mov qword ptr [r15 + 408], 1
    mov rax, [r15 + 176]
    mov [r15 + 416], rax
    mov rax, [r15 + 184]
    mov [r15 + 424], rax
tk_lock_acquisition_call:
    call tk_lock_core_call
    jmp tk_lock_decision
tk_lock_command_release:
    mov rax, [r15 + 152]
    test rax, rax
    jz tk_contract_fail
    mov [r15 + 400], rax
    cmp r12, 3
    je tk_lock_command_finish_shared
    mov qword ptr [r15 + 392], 12
    mov rax, [r15 + 160]
    mov [r15 + 408], rax
    cmp r12, 5
    jne tk_lock_release_call
    mov qword ptr [r15 + 416], 1
    jmp tk_lock_release_call
tk_lock_command_finish_shared:
    cmp qword ptr [r15 + 160], 2
    jne tk_contract_fail
    mov qword ptr [r15 + 392], 6
tk_lock_release_call:
    call tk_lock_core_call
    jmp tk_lock_decision
tk_lock_command_snapshot:
    mov qword ptr [r15 + 392], 8
    call tk_lock_core_call
    jmp tk_lock_decision
tk_lock_command_queue_poison:
    mov qword ptr [r15 + 392], 10
    mov qword ptr [r15 + 408], 1
    call tk_lock_core_call
    jmp tk_lock_decision
tk_lock_command_inner_poison:
    mov dword ptr [rbx + 112], 1
    mov qword ptr [r15 + 392], 10
    mov qword ptr [r15 + 408], 2
    call tk_lock_core_call
    jmp tk_lock_decision
tk_lock_command_notify:
    mov qword ptr [r15 + 392], 11
    call tk_lock_core_call
    jmp tk_lock_decision
tk_lock_command_raw_acquire:
    cmp qword ptr [r15 + 216], 0
    jne tk_contract_fail
    xor eax, eax
    mov edx, 1
    lock cmpxchg [rbx + 124], edx
    jne tk_contract_fail
    mov qword ptr [r15 + 216], 1
    mov qword ptr [r15 + 528], 0
    jmp tk_lock_command_response
tk_lock_command_raw_panic:
    mov dword ptr [rbx + 112], 1
    cmp qword ptr [r15 + 216], 1
    jne tk_contract_fail
    mov qword ptr [r15 + 392], 10
    mov qword ptr [r15 + 408], 2
    call tk_lock_core_call
    cmp qword ptr [r15 + 528], 0
    jne tk_contract_fail
tk_lock_command_raw_release:
    cmp qword ptr [r15 + 216], 1
    jne tk_contract_fail
    xor eax, eax
    xchg [rbx + 124], eax
    cmp eax, 1
    jne tk_contract_fail
    mov qword ptr [r15 + 216], 0
    mov qword ptr [r15 + 528], 0
    jmp tk_lock_command_response
tk_lock_decision:
    mov rax, [r15 + 528]
    cmp rax, 1
    je tk_lock_wait_turn
    cmp rax, 3
    je tk_lock_check_turn
    cmp rax, 4
    je tk_lock_try_inner
    cmp rax, 8
    je tk_lock_release_inner
    cmp rax, 5
    je tk_lock_acquired
    test rax, rax
    jz tk_lock_completed
    cmp rax, 6
    je tk_lock_refused
    cmp rax, 7
    je tk_lock_refused
    jmp tk_contract_fail
tk_lock_wait_turn:
    cmp r12, 2
    ja tk_contract_fail
    mov rax, [r15 + 536]
    mov [r15 + 152], rax
    lea rdi, [rbx + 120]
    mov esi, 137
    mov edx, [r15 + 568]
    xor r10d, r10d
    cmp qword ptr [r15 + 168], 0
    je tk_lock_wait_time_ready
    lea r10, [r15 + 176]
tk_lock_wait_time_ready:
    xor r8d, r8d
    mov r9d, 0xffffffff
    mov eax, 202
    syscall
    test rax, rax
    jz tk_lock_poll_again
    cmp rax, -11
    je tk_lock_poll_again
    cmp rax, -4
    je tk_lock_poll_again
    cmp rax, -110
    jne tk_contract_fail
tk_lock_poll_again:
    call tk_lock_clear_initial
    mov qword ptr [r15 + 392], 3
    call tk_lock_core_call
    jmp tk_lock_decision
tk_lock_check_turn:
    cmp r12, 2
    ja tk_contract_fail
    mov rax, [r15 + 536]
    mov [r15 + 152], rax
    call tk_lock_clear_initial
    mov qword ptr [r15 + 392], 4
    mov [r15 + 408], r12
    call tk_lock_guard_clock_fields
    call tk_lock_core_call
    jmp tk_lock_decision
tk_lock_try_inner:
    cmp r12, 1
    jne tk_contract_fail
    cmp qword ptr [r15 + 208], 0
    jne tk_contract_fail
    call tk_lock_clear_initial
    mov qword ptr [r15 + 392], 5
    call tk_lock_guard_clock_fields
    xor eax, eax
    mov edx, 1
    lock cmpxchg [rbx + 124], edx
    jne tk_lock_inner_busy
    mov qword ptr [r15 + 208], 1
    jmp tk_lock_inner_result
tk_lock_inner_busy:
    mov qword ptr [r15 + 408], 2
tk_lock_inner_result:
    call tk_lock_core_call
    jmp tk_lock_decision
tk_lock_release_inner:
    mov qword ptr [r15 + 232], 0
    mov rax, [r15 + 544]
    mov [r15 + 240], rax
    jmp tk_lock_dispose_guard
tk_lock_dispose_guard:
    cmp qword ptr [r15 + 208], 0
    je tk_lock_disposed_inner
    cmp qword ptr [r15 + 240], 0
    je tk_lock_release_inner_word
    mov dword ptr [rbx + 112], 1
tk_lock_release_inner_word:
    xor eax, eax
    xchg [rbx + 124], eax
    cmp eax, 1
    jne tk_contract_fail
    mov qword ptr [r15 + 208], 0
tk_lock_disposed_inner:
    call tk_lock_clear_initial
    mov qword ptr [r15 + 392], 7
    mov rax, [r15 + 232]
    mov [r15 + 416], rax
    mov rax, [r15 + 240]
    mov [r15 + 408], rax
    call tk_lock_core_call
    jmp tk_lock_decision
tk_lock_acquired:
    cmp r12, 2
    ja tk_contract_fail
    mov rax, [r15 + 536]
    cmp rax, [r15 + 152]
    jne tk_contract_fail
    mov [r15 + 160], r12
    jmp tk_lock_command_response
tk_lock_completed:
    cmp r12, 3
    jb tk_contract_fail
    cmp r12, 5
    ja tk_lock_command_response
    cmp qword ptr [r15 + 392], 12
    je tk_lock_release_inner
    jmp tk_lock_forget_guard
tk_lock_refused:
    cmp r12, 3
    ja tk_contract_fail
    cmp qword ptr [r15 + 392], 4
    je tk_lock_dispose_failed_acquisition
    cmp qword ptr [r15 + 392], 5
    jne tk_lock_forget_guard
tk_lock_dispose_failed_acquisition:
    mov rax, [r15 + 528]
    mov [r15 + 232], rax
    mov qword ptr [r15 + 240], 0
    jmp tk_lock_dispose_guard
tk_lock_forget_guard:
    cmp qword ptr [r15 + 208], 0
    jne tk_contract_fail
    mov qword ptr [r15 + 152], 0
    mov qword ptr [r15 + 160], 0
    mov qword ptr [r15 + 168], 0
tk_lock_command_response:
    lea rdi, [r15 + 640]
    xor eax, eax
    mov ecx, 10
    rep stosq
    mov rax, 0x3130304f4c415248
    mov [r15 + 640], rax
    mov rax, [r15 + 264]
    mov [r15 + 648], rax
    mov rax, [r15 + 144]
    mov [r15 + 656], rax
    mov [r15 + 664], r12
    mov rax, [r15 + 528]
    mov [r15 + 672], rax
    cmp r12, 6
    jne tk_lock_command_done
    mov rax, [r15 + 536]
    mov [r15 + 680], rax
    mov rax, [r15 + 544]
    mov [r15 + 688], rax
    mov rax, [r15 + 552]
    mov [r15 + 696], rax
    mov rax, [r15 + 560]
    mov [r15 + 704], rax
tk_lock_command_done:
    add rsp, 24
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret
tk_lock_clear_initial:
    mov rax, [r15 + 152]
    mov [r15 + 400], rax
    mov qword ptr [r15 + 408], 0
    mov qword ptr [r15 + 416], 0
    mov qword ptr [r15 + 424], 0
    mov qword ptr [r15 + 488], 0
    ret
tk_lock_guard_clock_fields:
    mov rax, [r15 + 168]
    mov [r15 + 488], rax
    mov rax, [r15 + 176]
    mov [r15 + 416], rax
    mov rax, [r15 + 184]
    mov [r15 + 424], rax
    ret
tk_lock_core_call:
    lea rdi, [r15 + 384]
    mov esi, 128
    lea rdx, [r15 + 512]
    mov rcx, [r15 + 64]
    jmp tk_lock_policy_run

tk_lock_command_hold_queue:
    cmp qword ptr [r15 + 200], 0
    jne tk_contract_fail
    mov rdi, rbx
    call tk_mutex_lock
    mov qword ptr [r15 + 200], 1
    mov qword ptr [r15 + 528], 0
    jmp tk_lock_command_response
tk_lock_command_release_queue:
    cmp qword ptr [r15 + 200], 1
    jne tk_contract_fail
    mov qword ptr [r15 + 200], 0
    mov rdi, rbx
    call tk_mutex_unlock
    mov qword ptr [r15 + 528], 0
    jmp tk_lock_command_response

# Qualification-only state faults; actual queue custody protects both writes.
tk_lock_command_fixture_counter:
    cmp qword ptr [r15 + 200], 0
    jne tk_contract_fail
    mov rdi, rbx
    call tk_mutex_lock
    mov rdx, [rbx + 8]
    mov rax, [r15 + 288]
    cmp r12, 16
    jne tk_lock_fixture_readers
    cmp qword ptr [rdx + 104], 0
    jne tk_contract_fail
    mov [rdx + 48], rax
    jmp tk_lock_fixture_counter_done
tk_lock_fixture_readers:
    mov [rdx + 64], rax
tk_lock_fixture_counter_done:
    mov rdi, rbx
    call tk_mutex_unlock
    mov qword ptr [r15 + 528], 0
    jmp tk_lock_command_response

# Queue decisions are HIA; this boundary owns clock, mutex, growth and wake.
tk_lock_policy_run:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp, 312
    mov r12, rdi
    mov r13, rsi
    mov r14, rdx
    mov r15, rcx
    cmp r13, 128
    jne tk_contract_fail
    mov edi, 1
    lea rsi, [rsp + 288]
    mov eax, 228
    syscall
    test rax, rax
    jnz tk_io_fail
    mov rax, [rsp + 288]
    mov [r12 + 48], rax
    mov rax, [rsp + 296]
    mov [r12 + 56], rax
    mov rax, [rsp + 288]
    mov [r12 + 64], rax
    mov rax, [rsp + 296]
    mov [r12 + 72], rax
    mov eax, [r15 + 112]
    mov [r12 + 96], rax
    mov rax, [r12 + 8]
    cmp rax, 4
    je tk_lock_policy_private
    cmp rax, 5
    je tk_lock_policy_private
    cmp rax, 12
    je tk_lock_policy_private
    cmp rax, 1
    je tk_lock_policy_preflight
    cmp rax, 2
    jne tk_lock_policy_lock
tk_lock_policy_preflight:
    cmp qword ptr [r12 + 16], 0
    jne tk_contract_fail
    mov [rsp + 8], rax
    mov [r12 + 16], rax
    mov qword ptr [r12 + 8], 13
    mov rdi, r12
    mov esi, 128
    mov rdx, r14
    mov ecx, 64
    lea r8, [rsp + 32]
    mov r9d, 256
    call qword ptr [r15 + 24]
    cmp eax, 64
    jne tk_contract_fail
    mov rax, [rsp + 8]
    mov [r12 + 8], rax
    mov qword ptr [r12 + 16], 0
    cmp qword ptr [r14 + 16], 0
    je tk_lock_policy_lock
    cmp qword ptr [r14 + 16], 6
    jne tk_contract_fail
    mov eax, 64
    jmp tk_lock_policy_return
tk_lock_policy_lock:
    mov rdi, r15
    call tk_mutex_lock
    inc qword ptr [r15 + 40]
    cmp qword ptr [r15 + 40], 1
    jne tk_contract_fail
    mov edi, 1
    lea rsi, [rsp + 288]
    mov eax, 228
    syscall
    test rax, rax
    jnz tk_io_fail
    mov rax, [rsp + 288]
    mov [r12 + 64], rax
    mov rax, [rsp + 296]
    mov [r12 + 72], rax
    mov eax, [r15 + 112]
    mov [r12 + 96], rax
tk_lock_policy_invoke:
    mov edi, 1
    lea rsi, [rsp + 288]
    mov eax, 228
    syscall
    test rax, rax
    jnz tk_io_fail
    mov rax, [rsp + 288]
    mov [r12 + 80], rax
    mov rax, [rsp + 296]
    mov [r12 + 88], rax
    inc qword ptr [r15 + 32]
    jz tk_contract_fail
    mov rdi, r12
    mov rsi, r13
    mov rdx, r14
    mov ecx, 64
    mov r8, qword ptr [r15 + 8]
    mov r9, qword ptr [r15 + 16]
    call qword ptr [r15 + 24]
    mov edx, eax
    cmp rax, rdx
    jne tk_contract_fail
    cmp eax, 64
    jne tk_contract_fail
    mov rax, 0x313030524c415248
    cmp qword ptr [r14], rax
    jne tk_contract_fail
    cmp qword ptr [r14 + 16], 2
    jne tk_lock_policy_success
    mov rax, qword ptr [r14 + 8]
    cmp rax, 1
    je tk_lock_policy_growth
    cmp rax, 2
    jne tk_contract_fail
tk_lock_policy_growth:
    cmp r13, 128
    jb tk_contract_fail
    cmp qword ptr [r12 + 8], rax
    jne tk_contract_fail
    cmp qword ptr [r14 + 24], 0
    jne tk_contract_fail
    mov rdi, qword ptr [r14 + 32]
    cmp rdi, qword ptr [r15 + 16]
    jbe tk_contract_fail
    mov rax, qword ptr [r15 + 16]
    add rax, rax
    jc tk_memory_fail
    cmp rdi, rax
    cmovb rdi, rax
    call tk_round_capacity
    mov rbp, rax
    mov rdi, rax
    call tk_allocate_guarded
    mov rbx, rax
    mov rdi, rax
    mov rsi, qword ptr [r15 + 8]
    mov rcx, qword ptr [r15 + 16]
    rep movsb
    mov rdi, qword ptr [r15 + 8]
    mov rsi, qword ptr [r15 + 16]
    add rsi, 4096
    mov qword ptr [r15 + 8], rbx
    mov qword ptr [r15 + 16], rbp
    mov eax, 11
    syscall
    test rax, rax
    jnz tk_io_fail
    jmp tk_lock_policy_invoke
tk_lock_policy_success:
    mov qword ptr [rsp + 24], 0
    mov eax, [r14 + 56]
    cmp [r15 + 120], eax
    je tk_lock_policy_no_notification
    mov [r15 + 120], eax
    mov qword ptr [rsp + 24], 1
tk_lock_policy_no_notification:
    dec qword ptr [r15 + 40]
    jnz tk_contract_fail
    mov rdi, r15
    call tk_mutex_unlock
    cmp qword ptr [rsp + 24], 0
    je tk_lock_policy_done
    lea rdi, [r15 + 120]
    call tk_lock_wake_all
tk_lock_policy_done:
    mov eax, 64
tk_lock_policy_return:
    add rsp, 312
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret
tk_lock_wake_all:
    mov esi, 129
    mov edx, 0x7fffffff
    xor r10d, r10d
    xor r8d, r8d
    xor r9d, r9d
    mov eax, 202
    syscall
    test rax, rax
    js tk_contract_fail
    ret

tk_lock_policy_private:
    mov rdi, r12
    mov esi, 128
    mov rdx, r14
    mov ecx, 64
    lea r8, [rsp + 32]
    mov r9d, 256
    call qword ptr [r15 + 24]
    cmp eax, 64
    jne tk_contract_fail
    jmp tk_lock_policy_return

# One native custody gate serializes every lease, registry and arena mutation.
# The HIA owner implements all lifetime, key, pruning and poison decisions.
tk_active_policy_run:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp, 24
    mov r12, rdi
    mov r13, rsi
    mov r14, rdx
    mov r15, rcx
    mov rdi, r15
    call tk_mutex_lock
tk_active_policy_invoke:
    mov rdi, r12
    mov rsi, r13
    mov rdx, r14
    mov ecx, 64
    mov r8, [r15 + 8]
    mov r9, [r15 + 16]
    call qword ptr [r15 + 24]
    cmp rax, 64
    jne tk_contract_fail
    mov rax, 0x3130305241415248
    cmp [r14], rax
    jne tk_contract_fail
    cmp qword ptr [r14 + 8], 2
    jne tk_active_policy_return
    cmp qword ptr [r14 + 24], 0
    jne tk_contract_fail
    mov rdi, [r14 + 16]
    cmp rdi, [r15 + 16]
    jbe tk_contract_fail
    mov rax, [r15 + 16]
    add rax, rax
    jc tk_memory_fail
    cmp rdi, rax
    cmovb rdi, rax
    call tk_round_capacity
    mov rbp, rax
    mov rdi, rax
    call tk_allocate_guarded
    mov rbx, rax
    mov rdi, rax
    mov rsi, [r15 + 8]
    mov rcx, [r15 + 16]
    rep movsb
    mov rdi, [r15 + 8]
    mov rsi, [r15 + 16]
    add rsi, 4096
    mov [r15 + 8], rbx
    mov [r15 + 16], rbp
    mov eax, 11
    syscall
    test rax, rax
    jnz tk_io_fail
    jmp tk_active_policy_invoke
tk_active_policy_return:
    mov rdi, r15
    call tk_mutex_unlock
    mov eax, 64
    add rsp, 24
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

# One native custody gate serializes every lease, registry and arena mutation.
# The HIA owner implements all lifetime, key, pruning and poison decisions.
tk_public_active_policy_run:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp, 24
    mov r12, rdi
    mov r13, rsi
    mov r14, rdx
    mov r15, rcx
    mov rdi, r15
    call tk_mutex_lock
tk_public_active_policy_invoke:
    mov rdi, r12
    mov rsi, r13
    mov rdx, r14
    mov ecx, 64
    mov r8, [r15 + 8]
    mov r9, [r15 + 16]
    call qword ptr [r15 + 24]
    mov edx, eax
    cmp rax, rdx
    jne tk_contract_fail
    mov [rsp + 16], eax
    cmp eax, 64
    je tk_public_active_normal_reply
    cmp eax, 0xffffffff
    je tk_public_active_policy_return
    cmp eax, 0xfffffffe
    je tk_public_active_policy_return
    cmp eax, 0xfffffff9
    je tk_public_active_policy_return
    jmp tk_contract_fail
tk_public_active_normal_reply:
    mov rax, 0x3130305241415248
    cmp [r14], rax
    jne tk_contract_fail
    cmp qword ptr [r14 + 8], 2
    jne tk_public_active_policy_return
    cmp qword ptr [r14 + 24], 0
    jne tk_contract_fail
    mov rdi, [r14 + 16]
    cmp rdi, [r15 + 16]
    jbe tk_contract_fail
    mov rax, [r15 + 16]
    add rax, rax
    jc tk_memory_fail
    cmp rdi, rax
    cmovb rdi, rax
    call tk_round_capacity
    mov rbp, rax
    mov rdi, rax
    call tk_allocate_guarded
    mov rbx, rax
    mov rdi, rax
    mov rsi, [r15 + 8]
    mov rcx, [r15 + 16]
    rep movsb
    mov rdi, [r15 + 8]
    mov rsi, [r15 + 16]
    add rsi, 4096
    mov [r15 + 8], rbx
    mov [r15 + 16], rbp
    mov eax, 11
    syscall
    test rax, rax
    jnz tk_io_fail
    jmp tk_public_active_policy_invoke
tk_public_active_policy_return:
    mov rdi, r15
    call tk_mutex_unlock
    mov eax, [rsp + 16]
    add rsp, 24
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
# One actual clock owner belongs to each private Ticket context.
tk_clock_entry:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp, 8
    mov r15, rdi
    lea r12, [r15 + tk_CLOCK_WORK]
tk_clock_resume:
    lea rdi, [r15 + tk_LEAF_WORK + 1024]
    mov esi, 32
    lea rdx, [r15 + tk_LEAF_WORK + 2048]
    mov ecx, 128
    mov r8, r12
    mov r9d, 1024
    call qword ptr [rip + tk_image_table + 48]
    mov edx, eax
    cmp rax, rdx
    jne tk_contract_fail
    cmp eax, 0xfffffff0
    jne tk_clock_result
    cmp qword ptr [r12 + 8], 1
    jne tk_contract_fail
    lea r14, [r12 + 256]
    mov rax, 0x3130414c43415248
    cmp [r14], rax
    jne tk_contract_fail
    mov rax, [r15 + 64]
    inc rax
    jz tk_contract_fail
    cmp [r14 + 8], rax
    jne tk_contract_fail
    cmp [r12 + 16], rax
    jne tk_contract_fail
    mov [r15 + 64], rax
    cmp qword ptr [r14 + 16], 1
    jne tk_contract_fail
    cmp qword ptr [r14 + 32], 512
    jne tk_contract_fail
    cmp qword ptr [r14 + 40], 16
    jne tk_contract_fail
    mov rax, [r14 + 48]
    or rax, [r14 + 56]
    or rax, [r14 + 64]
    or rax, [r14 + 72]
    or rax, [r14 + 80]
    or rax, [r14 + 88]
    jnz tk_contract_fail
    mov rdi, [r14 + 24]
    cmp rdi, 1
    ja tk_contract_fail
    xor eax, eax
    cmp qword ptr [r12 + 40], 1
    setne al
    cmp rdi, rax
    jne tk_contract_fail
    lea rsi, [r12 + 512]
    mov eax, 228
    syscall
    test rax, rax
    jz tk_clock_ack
    cmp rax, -4095
    jb tk_contract_fail
    neg rax
    mov [r14 + 72], rax
tk_clock_ack:
    mov rax, [r14 + 8]
    mov [r14 + 80], rax
    mov qword ptr [r14 + 88], 1
    jmp tk_clock_resume
tk_clock_result:
    cmp eax, 48
    je tk_clock_restore
    cmp eax, 64
    je tk_clock_restore
    cmp eax, 72
    jne tk_contract_fail
tk_clock_restore:
    add rsp, 8
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
# All Tickets borrow the same gated entropy workspace and cached device FD.
tk_identity_entry:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp, 8
    mov r13, rdi
    mov rbp, rsi
    mov r15, rdx
    mov rdi, r15
    call tk_mutex_lock
    mov [r15 + 32], r13
    mov [r15 + 40], rbp
    lea r12, [r15 + 4096]
    jmp tk_entropy_resume
tk_entropy_result:
    cmp eax, 48
    je tk_entropy_result_code
    cmp eax, 112
    jne tk_contract_fail
tk_entropy_result_code:
    mov ebx, eax
    cmp qword ptr [r15 + 160], -1
    jne tk_contract_fail
    cmp qword ptr [r12 + 48], 0
    jne tk_contract_fail
    cmp qword ptr [r12 + 40], 0
    jne tk_entropy_cached
    cmp qword ptr [r15 + 152], -1
    jne tk_contract_fail
    jmp tk_entropy_restore
tk_entropy_cached:
    cmp qword ptr [r12 + 40], 1
    jne tk_contract_fail
    cmp qword ptr [r15 + 152], -1
    je tk_contract_fail
tk_entropy_restore:
    mov qword ptr [r15 + 32], 0
    mov qword ptr [r15 + 40], 0
    mov rdi, r15
    call tk_mutex_unlock
    mov eax, ebx
    add rsp, 8
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret
tk_entropy_random_path:
    .asciz "/dev/random"
tk_entropy_urandom_path:
    .asciz "/dev/urandom"

tk_entropy_resume:
    mov rdi, [r15 + 32]
    mov esi, 24
    mov rdx, [r15 + 40]
    mov ecx, 128
    mov r8, r12
    mov r9d, 1024
    call qword ptr [r15 + 24]
    mov ecx, eax
    cmp rax, rcx
    jne tk_contract_fail
    cmp eax, 0xfffffff0
    jne tk_entropy_result
    lea r14, [r12 + 256]
    mov rax, 0x3230544e45414948
    cmp [r14], rax
    jne tk_contract_fail
    mov rax, [r15 + 64]
    inc rax
    jz tk_contract_fail
    cmp [r14 + 8], rax
    jne tk_contract_fail
    cmp [r12 + 24], rax
    jne tk_contract_fail
    mov [r15 + 64], rax
    mov rax, [r14 + 32]
    or rax, [r14 + 48]
    or rax, [r14 + 56]
    or rax, [r14 + 64]
    or rax, [r14 + 72]
    jnz tk_contract_fail
    cmp qword ptr [r12 + 8], 32
    jne tk_contract_fail
    mov rax, [r14 + 40]
    cmp rax, [r12]
    jne tk_contract_fail
    cmp rax, 1
    je tk_entropy_probe
    cmp rax, 2
    je tk_entropy_direct
    cmp rax, 7
    je tk_entropy_read
    mov rcx, [r14 + 16]
    or rcx, [r14 + 24]
    jnz tk_contract_fail
    cmp rax, 3
    je tk_entropy_random_open
    cmp rax, 4
    je tk_entropy_poll
    cmp rax, 5
    je tk_entropy_random_close
    cmp rax, 6
    je tk_entropy_urandom_open
    jmp tk_contract_fail
tk_entropy_probe:
    cmp qword ptr [r14 + 16], 512
    jne tk_contract_fail
    cmp qword ptr [r14 + 24], 0
    jne tk_contract_fail
    lea rdi, [r12 + 512]
    xor esi, esi
    xor edx, edx
    mov eax, 318
    syscall
    jmp tk_entropy_value
tk_entropy_span:
    mov rcx, [r12 + 16]
    cmp rcx, 32
    jae tk_contract_fail
    lea rsi, [rcx + 512]
    cmp rsi, [r14 + 16]
    jne tk_contract_fail
    mov edx, 32
    sub rdx, rcx
    cmp rdx, [r14 + 24]
    jne tk_contract_fail
    add rsi, r12
    ret
tk_entropy_direct:
    call tk_entropy_span
    mov rdi, rsi
    mov rsi, rdx
    xor edx, edx
    mov eax, 318
    syscall
    jmp tk_entropy_value
tk_entropy_read:
    call tk_entropy_span
    mov rdi, [r15 + 152]
    test rdi, rdi
    js tk_contract_fail
    xor eax, eax
    syscall
    jmp tk_entropy_value
tk_entropy_random_open:
    cmp qword ptr [r15 + 160], -1
    jne tk_contract_fail
    lea rsi, [rip + tk_entropy_random_path]
    mov edi, -100
    mov edx, 0x80000
    xor r10d, r10d
    mov eax, 257
    syscall
    test rax, rax
    js tk_entropy_error
    mov [r15 + 160], rax
    jmp tk_entropy_ack
tk_entropy_urandom_open:
    cmp qword ptr [r15 + 152], -1
    jne tk_contract_fail
    lea rsi, [rip + tk_entropy_urandom_path]
    mov edi, -100
    mov edx, 0x80000
    xor r10d, r10d
    mov eax, 257
    syscall
    test rax, rax
    js tk_entropy_error
    mov [r15 + 152], rax
    jmp tk_entropy_ack
tk_entropy_poll:
    mov rax, [r15 + 160]
    test rax, rax
    js tk_contract_fail
    mov [r15 + 768], eax
    mov dword ptr [r15 + 772], 1
    lea rdi, [r15 + 768]
    mov esi, 1
    mov rdx, -1
    mov eax, 7
    syscall
    jmp tk_entropy_value
tk_entropy_random_close:
    mov rdi, [r15 + 160]
    test rdi, rdi
    js tk_contract_fail
    mov qword ptr [r15 + 160], -1
    mov eax, 3
    syscall
    jmp tk_entropy_value
tk_entropy_value:
    test rax, rax
    js tk_entropy_error
    mov [r14 + 48], rax
    jmp tk_entropy_ack
tk_entropy_error:
    cmp rax, -4095
    jb tk_contract_fail
    neg rax
    mov [r14 + 56], rax
tk_entropy_ack:
    mov rax, [r14 + 8]
    mov [r14 + 64], rax
    mov qword ptr [r14 + 72], 1
    jmp tk_entropy_resume

tk_mutex_lock:
    push rbx
    mov rbx, rdi
tk_mutex_retry:
    xor eax, eax
    mov edx, 1
    lock cmpxchg dword ptr [rbx], edx
    je tk_mutex_locked
    mov rdi, rbx
    mov esi, 128
    mov edx, 1
    xor r10d, r10d
    xor r8d, r8d
    xor r9d, r9d
    mov eax, 202
    syscall
    test rax, rax
    jz tk_mutex_retry
    cmp rax, -11
    je tk_mutex_retry
    cmp rax, -4
    je tk_mutex_retry
    jmp tk_contract_fail
tk_mutex_locked:
    pop rbx
    ret
tk_mutex_unlock:
    xor eax, eax
    xchg dword ptr [rdi], eax
    cmp eax, 1
    jne tk_contract_fail
tk_wake_one:
    mov esi, 129
    mov edx, 1
    xor r10d, r10d
    xor r8d, r8d
    xor r9d, r9d
    mov eax, 202
    syscall
    test rax, rax
    js tk_contract_fail
    ret

tk_round_capacity:
    mov rax, rdi
    add rax, 4095
    jc tk_memory_fail
    and rax, -4096
    test rax, rax
    jz tk_memory_fail
    mov rdx, 0x7ffffffffffff000
    cmp rax, rdx
    jae tk_memory_fail
    ret
tk_allocate_guarded:
    push rbx
    mov rbx, rdi
    lea rsi, [rdi + 4096]
    xor edi, edi
    mov edx, 3
    mov r10d, 0x22
    mov r8, -1
    xor r9d, r9d
    mov eax, 9
    syscall
    cmp rax, -4095
    jae tk_memory_fail
    push rax
    lea rdi, [rax + rbx]
    mov esi, 4096
    xor edx, edx
    mov eax, 10
    syscall
    test rax, rax
    jnz tk_memory_fail
    pop rax
    pop rbx
    ret
tk_read_exact:
    test rdx, rdx
    jz tk_read_done
tk_read_loop:
    xor edi, edi
    xor eax, eax
    syscall
    cmp rax, -4
    je tk_read_loop
    test rax, rax
    js tk_io_fail
    jz tk_read_eof
    xor r14d, r14d
    add rsi, rax
    sub rdx, rax
    jnz tk_read_loop
tk_read_done:
    mov eax, 1
    ret
tk_read_eof:
    test r14, r14
    jz tk_io_fail
    xor eax, eax
    ret
tk_write_exact:
    test rdx, rdx
    jz tk_write_done
tk_write_loop:
    mov edi, 1
    mov eax, 1
    syscall
    cmp rax, -4
    je tk_write_loop
    test rax, rax
    jle tk_io_fail
    add rsi, rax
    sub rdx, rax
    jnz tk_write_loop
tk_write_done:
    ret
tk_usage:
    mov edi, 64
    jmp tk_fatal_exit
tk_contract_fail:
    mov edi, 70
    jmp tk_fatal_exit
tk_memory_fail:
    mov edi, 71
    jmp tk_fatal_exit
tk_io_fail:
    mov edi, 74
tk_fatal_exit:
    mov eax, 231
    syscall
    ud2

.balign 16
tk_image_table:
    .zero 112
tk_ticket_storage_image:
    .quad 0
tk_ticket_directory_image:
    .quad 0
tk_ticket_raw_write_image:
    .quad 0
tk_ticket_raw_read_image:
    .quad 0
tk_ticket_json_image:
    .quad 0
tk_ticket_backend_cold_image:
    .quad 0
tk_ticket_backend_save_image:
    .quad 0
tk_ticket_backend_registry_image:
    .quad 0
tk_ticket_backend_archive_image:
    .quad 0
tk_ticket_backend_legacy_image:
    .quad 0
tk_ticket_backend_anchor_image:
    .quad 0
tk_ticket_backend_namespace_image:
    .quad 0
tk_ticket_backend_metadata_image:
    .quad 0
tk_ticket_backend_writer_image:
    .quad 0
tk_ticket_backend_record_image:
    .quad 0
tk_ticket_backend_json_image:
    .quad 0
tk_ticket_backend_entropy_image:
    .quad 0
tk_ticket_backend_visitor_image:
    .quad 0
tk_ticket_backend_raw_write_image:
    .quad 0
tk_ticket_backend_stamp_image:
    .quad 0
tk_ticket_backend_entries_image:
    .quad 0
tk_ticket_backend_retention_image:
    .quad 0
tk_ticket_backend_remove_image:
    .quad 0
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
# Fixed bytes/lease boundary; all semantic transitions are HIA.
.equ tk_OV_INPUT, 4096
.equ tk_OV_INPUT_CAP, 9437184
.equ tk_OV_OUTPUT, 9441280
.equ tk_OV_WORK, 9445376
.equ tk_OV_WORK_BYTES, 16777216
.equ tk_OV_MAP_BYTES, 26222592

# SysV: root, trusted rootcap, query, length, reply, capacity -> u32.
tk_audit_observation_call:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp, 104
    mov [rsp], rdi
    mov [rsp + 8], rsi
    mov [rsp + 16], rdx
    mov [rsp + 24], rcx
    mov [rsp + 32], r8
    mov [rsp + 40], r9
    cmp r9, 320
    jb tk_ov_capacity
    cmp rcx, 96
    jb tk_ov_invalid
    cmp rcx, 8388608
    ja tk_ov_invalid
    test rdi, rdi
    jz tk_contract_fail
    cmp [rdi], rdi
    jne tk_contract_fail
    test rsi, rsi
    jz tk_ov_invalid
    cmp rsi, [rdi + tk_ROOT_COUNT]
    ja tk_ov_invalid
    cmp [rdx + 16], rsi
    jne tk_ov_invalid
    mov rax, 0x313051564f415248
    cmp [rdx], rax
    jne tk_ov_invalid
    mov r15, rdi
    mov rax, rsi
    dec rax
    shl rax, 4
    mov rbx, [r15 + tk_ROOT_PATHS + rax]
    mov rbp, [r15 + tk_ROOT_PATHS + rax + 8]
    cmp rbp, 1048528
    ja tk_ov_capacity
    mov [rsp + 64], rbx
    mov [rsp + 72], rbp
    mov edi, tk_CONTEXT_BYTES
    call tk_allocate_guarded
    mov r13, rax
    mov [rsp + 48], rax
    mov [rax], r15
    lea rdx, [r15 + tk_GLOBAL_LOCK]
    mov [rax + tk_LOCK_CONTEXT + 64], rdx
    mov edi, tk_OV_MAP_BYTES
    call tk_allocate_guarded
    mov r12, rax
    mov [rsp + 56], rax
    mov rdx, 0x3130435354415248
    mov [r12], rdx
    mov [r12 + 8], r13
    mov [r13 + 248], r12
    lea rdi, [r12 + tk_OV_INPUT]
    mov rax, 0x31304e454f415248
    mov [rdi], rax
    mov rax, [rsp + 72]
    mov [rdi + 8], rax
    mov rax, [rsp + 24]
    mov [rdi + 16], rax
    mov qword ptr [rdi + 24], 0
    add rdi, 32
    mov rsi, [rsp + 64]
    mov rcx, [rsp + 72]
    rep movsb
    mov rsi, [rsp + 16]
    mov rcx, [rsp + 24]
    rep movsb
    mov rax, [rsp + 24]
    add rax, [rsp + 72]
    add rax, 32
    cmp rax, 9437168
    ja tk_contract_fail
    mov [r12 + 48], rax
    lea rdi, [r12 + tk_OV_INPUT]
    mov esi, tk_OV_INPUT_CAP
    mov edx, 1
    mov eax, 10
    syscall
    test rax, rax
    jnz tk_io_fail
    lea rbp, [r12 + tk_OV_WORK]
tk_ov_resume:
    lea rdi, [r12 + tk_OV_INPUT]
    mov rsi, [r12 + 48]
    lea rdx, [r12 + tk_OV_OUTPUT]
    mov ecx, 320
    mov r8, rbp
    mov r9d, tk_OV_WORK_BYTES
    call qword ptr [rip + tk_audit_observation_image]
    mov edx, eax
    cmp rax, rdx
    jne tk_contract_fail
    cmp eax, 0xfffffff0
    jne tk_ov_result
    lea r14, [rbp + 256]
    mov rax, 0x3130415354415248
    cmp [r14], rax
    jne tk_contract_fail
    mov rax, [r12 + 56]
    inc rax
    jz tk_contract_fail
    cmp [r14 + 8], rax
    jne tk_contract_fail
    cmp [rbp + 16], rax
    jne tk_contract_fail
    mov [r12 + 56], rax
    cmp qword ptr [r14 + 32], 4096
    jne tk_contract_fail
    cmp qword ptr [r14 + 48], 2101248
    jne tk_contract_fail
    cmp qword ptr [r14 + 56], 270000
    jne tk_contract_fail
    mov rcx, [r14 + 40]
    cmp rcx, 48
    jb tk_contract_fail
    cmp rcx, 1048576
    ja tk_contract_fail
    lea rsi, [rbp + 4096]
    lea rdi, [rbp + 1052672]
    repe cmpsb
    jne tk_contract_fail
    lea rsi, [r14 + 16]
    lea rdi, [rbp + 384]
    mov ecx, 6
    repe cmpsq
    jne tk_contract_fail
    mov rsi, rbp
    lea rdi, [rbp + 512]
    mov ecx, 30
    repe cmpsq
    jne tk_contract_fail
    mov rax, [r14 + 64]
    or rax, [r14 + 72]
    or rax, [r14 + 80]
    or rax, [r14 + 88]
    jnz tk_contract_fail
    mov rax, [r14 + 16]
    cmp rax, 9
    je tk_ov_lock
    cmp rax, 10
    je tk_ov_activity
    cmp rax, 1
    je tk_ov_storage
    cmp rax, 2
    je tk_ov_storage
    cmp rax, 3
    je tk_ov_storage
    cmp rax, 6
    jne tk_contract_fail
tk_ov_storage:
    call tk_ov_storage_admit
    mov rax, [r14 + 16]
    cmp rax, 1
    je tk_ov_hot_directory
    cmp rax, 2
    je tk_ov_base_directory
    mov rdi, [r12 + 16]
    mov rsi, r14
    lea rdx, [rbp + 4096]
    mov rcx, [r14 + 40]
    lea r8, [rbp + 2101248]
    mov r9, [r12 + 80]
    call tk_ticket_backend_call
    jmp tk_ov_ack
tk_ov_hot_directory:
    mov rdi, [r12 + 80]
    jmp tk_ov_directory
tk_ov_base_directory:
    mov rbx, [r12 + 16]
    mov rdi, [rbx + 24]
    test rdi, rdi
    jnz tk_ov_directory
    call tk_ticket_directory_create
    mov [rbx + 24], rax
    mov rdi, rax
tk_ov_directory:
    lea rsi, [rbp + 4096]
    mov rdx, [r14 + 40]
    lea rcx, [rbp + 2101248]
    call tk_ticket_directory_call
    jmp tk_ov_ack
tk_ov_lock:
    lea rdi, [rbp + 4096]
    mov rax, 0x3130514c54415248
    cmp [rdi], rax
    jne tk_contract_fail
    mov rax, [rdi + 32]
    or rax, [rdi + 40]
    jnz tk_contract_fail
    cmp qword ptr [rbp + 8], 10
    je tk_ov_lock_acquire
    cmp qword ptr [rbp + 8], 83
    jne tk_contract_fail
    cmp qword ptr [r14 + 40], 56
    jne tk_contract_fail
    cmp qword ptr [rdi + 8], 122
    jne tk_contract_fail
    cmp qword ptr [rdi + 16], 5
    jne tk_contract_fail
    cmp qword ptr [rdi + 24], 8
    jne tk_contract_fail
    mov rax, [rbp + 64]
    test rax, rax
    jz tk_contract_fail
    cmp [rdi + 48], rax
    jne tk_contract_fail
    cmp [r14 + 24], rax
    jne tk_contract_fail
    # Remove per-call registrations while the original STORE_LOCK is still held.
    call tk_ov_storage_unlink
    jmp tk_ov_lock_invoke
tk_ov_lock_acquire:
    cmp qword ptr [r14 + 40], 48
    jne tk_contract_fail
    cmp qword ptr [rdi + 8], 100
    jne tk_contract_fail
    mov rax, [rdi + 16]
    or rax, [rdi + 24]
    or rax, [r14 + 24]
    or rax, [rbp + 64]
    jnz tk_contract_fail
tk_ov_lock_invoke:
    lea rdi, [rbp + 4096]
    mov rsi, [r14 + 40]
    lea rdx, [rbp + 2101248]
    mov rcx, r13
    call tk_leaf_call
    jmp tk_ov_ack
tk_ov_activity:
    cmp qword ptr [rbp + 8], 40
    jne tk_contract_fail
    cmp qword ptr [r14 + 40], 128
    jne tk_contract_fail
    cmp qword ptr [r14 + 24], 0
    jne tk_contract_fail
    lea rdi, [rbp + 4096]
    mov esi, 128
    lea rdx, [rbp + 2101248]
    mov rcx, r13
    call tk_activity_lookup
tk_ov_ack:
    mov edx, eax
    cmp rax, rdx
    jne tk_contract_fail
    cmp eax, 270000
    ja tk_contract_fail
    mov [r14 + 72], rax
    mov rax, [r14 + 8]
    mov [r14 + 64], rax
    jmp tk_ov_resume
tk_ov_result:
    mov [rsp + 80], eax
    mov rax, [rbp + 8]
    or rax, [rbp + 64]
    or rax, [rbp + 80]
    or rax, [rbp + 88]
    or rax, [rbp + 96]
    or rax, [r12 + 16]
    or rax, [r12 + 24]
    or rax, [r12 + 32]
    or rax, [r12 + 80]
    jnz tk_contract_fail
    mov rax, [r13 + tk_LEAF_WORK + 64]
    or rax, [r13 + tk_LEAF_WORK + 72]
    or rax, [r13 + tk_LEAF_WORK + 88]
    or rax, [r13 + tk_LEAF_WORK + 104]
    or rax, [r13 + tk_LOCK_CONTEXT + 152]
    or rax, [r13 + tk_LOCK_CONTEXT + 208]
    jnz tk_contract_fail
    mov eax, [rsp + 80]
    cmp eax, 320
    jbe tk_ov_copy_result
    cmp eax, 0xffffffff
    je tk_ov_retire
    cmp eax, 0xfffffffe
    je tk_ov_retire
    cmp eax, 0xfffffff9
    jne tk_contract_fail
    jmp tk_ov_retire
tk_ov_copy_result:
    cmp eax, 128
    jb tk_contract_fail
    mov ecx, eax
    mov rdi, [rsp + 32]
    lea rsi, [r12 + tk_OV_OUTPUT]
    rep movsb
tk_ov_retire:
    mov qword ptr [r13 + 248], 0
    mov rdi, r12
    mov esi, tk_OV_MAP_BYTES + 4096
    mov eax, 11
    syscall
    test rax, rax
    jnz tk_io_fail
    mov rdi, r13
    mov esi, tk_CONTEXT_BYTES + 4096
    mov eax, 11
    syscall
    test rax, rax
    jnz tk_io_fail
    mov eax, [rsp + 80]
    jmp tk_ov_done
tk_ov_invalid:
    mov eax, 0xffffffff
    jmp tk_ov_done
tk_ov_capacity:
    mov eax, 0xfffffffe
tk_ov_done:
    add rsp, 104
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

# Called only after the same actual exclusive guard has been acquired.
tk_ov_storage_admit:
    push rbx
    sub rsp, 16
    cmp qword ptr [r13 + tk_LOCK_CONTEXT + 208], 1
    jne tk_contract_fail
    mov rax, [r13 + tk_LEAF_WORK + 64]
    test rax, rax
    jz tk_contract_fail
    cmp [rbp + 64], rax
    jne tk_contract_fail
    mov rbx, [r12 + 16]
    test rbx, rbx
    jnz tk_ov_storage_exists
    cmp qword ptr [r14 + 16], 1
    jne tk_contract_fail
    cmp qword ptr [rbp + 8], 20
    jne tk_contract_fail
    mov rbx, [r15 + tk_STORAGE_GLOBAL]
    test rbx, rbx
    jnz tk_ov_global_ready
    mov edi, 4096
    call tk_allocate_guarded
    mov rbx, rax
    mov rdx, 0x3130475354415248
    mov [rbx], rdx
    mov [rbx + 8], r15
    mov [r15 + tk_STORAGE_GLOBAL], rbx
    mov rdi, rbx
    call tk_ticket_backend_create
    test rax, rax
    jz tk_contract_fail
    mov [rbx + 16], rax
tk_ov_global_ready:
    mov rax, 0x3130475354415248
    cmp [rbx], rax
    jne tk_contract_fail
    cmp [rbx + 8], r15
    jne tk_contract_fail
    cmp qword ptr [rbx + 56], 0
    jne tk_contract_fail
    mov qword ptr [rbx + 56], 1
    mov [r12 + 16], rbx
    mov rax, [rbx + 40]
    mov [r12 + 24], rax
    test rax, rax
    jz tk_ov_link_head
    cmp qword ptr [rax + 32], 0
    jne tk_contract_fail
    mov [rax + 32], r12
tk_ov_link_head:
    mov [rbx + 40], r12
    call tk_ticket_directory_create
    mov [r12 + 80], rax
tk_ov_storage_exists:
    mov rax, 0x3130475354415248
    cmp [rbx], rax
    jne tk_contract_fail
    cmp [rbx + 8], r15
    jne tk_contract_fail
    cmp qword ptr [rbx + 56], 1
    jne tk_contract_fail
    add rsp, 16
    pop rbx
    ret

tk_ov_storage_unlink:
    push rbx
    sub rsp, 16
    mov rax, [rbp + 80]
    or rax, [rbp + 88]
    or rax, [rbp + 96]
    jnz tk_contract_fail
    mov rbx, [r12 + 16]
    test rbx, rbx
    jz tk_ov_unlink_done
    cmp qword ptr [rbx + 56], 1
    jne tk_contract_fail
    mov rdi, [r12 + 80]
    call tk_ticket_directory_drop
    mov qword ptr [r12 + 80], 0
    mov rax, [r12 + 24]
    mov rdx, [r12 + 32]
    test rax, rax
    jz tk_ov_unlink_previous
    cmp [rax + 32], r12
    jne tk_contract_fail
    mov [rax + 32], rdx
tk_ov_unlink_previous:
    test rdx, rdx
    jz tk_ov_unlink_head
    cmp [rdx + 24], r12
    jne tk_contract_fail
    mov [rdx + 24], rax
    jmp tk_ov_unlinked
tk_ov_unlink_head:
    cmp [rbx + 40], r12
    jne tk_contract_fail
    mov [rbx + 40], rax
tk_ov_unlinked:
    mov qword ptr [rbx + 56], 0
    mov qword ptr [r12 + 16], 0
    mov qword ptr [r12 + 24], 0
    mov qword ptr [r12 + 32], 0
tk_ov_unlink_done:
    add rsp, 16
    pop rbx
    ret

# Private qualification transport keeps all old HRATWQ01 commands unchanged.
# Observation frames choose a rootcap already installed by trusted startup argv.
tk_observation_service_frame:
    mov rsi, [r15 + tk_SERVICE_IO]
    add rsi, 32
    mov rax, [r15 + 1088]
    cmp rax, 96
    jb tk_observation_service_regular
    mov rdx, 0x313051564f415248
    cmp [rsi], rdx
    jne tk_observation_service_regular
    mov rcx, rax
    mov rdx, rsi
    mov rsi, [rsi + 16]
    mov rdi, r15
    mov r8, [r15 + tk_SERVICE_IO]
    add r8, tk_SERVICE_OUTPUT
    mov r9d, 320
    call tk_audit_observation_call
    jmp tk_service_emit_result
tk_observation_service_regular:
    mov rax, [r15 + 1088]
    jmp tk_service_regular_frame

.balign 8
tk_audit_observation_image:
    .quad 0

# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
.equ tk_IP_BYTES, 0x1c01000
.equ tk_IR_BYTES, 0x1001000
.equ tk_IP_GLOBAL, 0x300
.equ tk_IP_REPLY, 0x308
.equ tk_IP_BUSY, 0x310
.equ tk_IG_SERVICE, 8
.equ tk_IG_LOCKS, 16
.equ tk_IG_CACHE_COUNT, 64
.equ tk_IG_CACHE_HEAD, 72
.equ tk_IG_META_LOCAL, 96
.equ tk_IG_STORE_GUARD, 2048
.equ tk_IG_CACHE, 8192
.equ tk_IG_CACHE_BYTES, 73728
# rdi=IG; one Archive and two independent Directory contexts.
tk_intent_prepare_create:
    push rbx
    push r12
    sub rsp, 8
    mov rbx, rdi
    xor edi, edi
    mov esi, tk_IP_BYTES
    mov edx, 3
    mov r10d, 34
    mov r8, -1
    xor r9d, r9d
    mov eax, 9
    syscall
    cmp rax, -4095
    jae tk_intent_resource_failure
    mov r12, rax
    mov [rax + tk_IP_GLOBAL], rbx
    lea rdi, [rax + 0x80]
    mov ecx, 7
    mov rax, -1
    rep stosq
    lea rdi, [r12 + 0xc0]
    mov ecx, 6
    rep stosq
    lea rdi, [r12 + tk_IP_BYTES - 4096]
    mov esi, 4096
    xor edx, edx
    mov eax, 10
    syscall
    test rax, rax
    jnz tk_intent_resource_failure
    mov rax, r12
    add rsp, 8
    pop r12
    pop rbx
    ret
# rdi=map,rsi=0 Archive/4 Directory0/5 Directory1,rdx=input,rcx=len,r8=reply64.
tk_intent_prepare_call:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp, 8
    mov r15, rdi
    mov rbx, rdx
    mov rbp, rcx
    cmp qword ptr [r15 + tk_IP_BUSY], 0
    jne tk_intent_contract_failure
    cmp rcx, 48
    jb tk_intent_contract_failure
    cmp rcx, 1048576
    ja tk_intent_contract_failure
    test rsi, rsi
    jz tk_intent_prepare_tag_ok
    cmp rsi, 4
    je tk_intent_prepare_tag_ok
    cmp rsi, 5
    jne tk_intent_contract_failure
tk_intent_prepare_tag_ok:
    mov [r15 + 32], rsi
    mov [r15 + tk_IP_REPLY], r8
    mov qword ptr [r15 + tk_IP_BUSY], 1
    mov [r15 + 0x1000128], rbp
    lea rdi, [r15 + 0x1110000]
    mov esi, 1048576
    mov edx, 3
    mov eax, 10
    syscall
    test rax, rax
    jnz tk_intent_resource_failure
    lea rdi, [r15 + 0x1110000]
    mov rsi, rbx
    mov rcx, rbp
    rep movsb
    lea rdi, [r15 + 0x1110000]
    mov esi, 1048576
    mov edx, 1
    mov eax, 10
    syscall
    test rax, rax
    jnz tk_intent_resource_failure
    # Parsed anchor cache is shared; child continuation/sequence stays local.
    mov rbx, [r15 + tk_IP_GLOBAL]
    mov rax, [rbx + tk_IG_CACHE_COUNT]
    cmp rax, 16
    ja tk_intent_contract_failure
    mov [r15 + 0xa00060], rax
    mov rax, [rbx + tk_IG_CACHE_HEAD]
    mov [r15 + 0xa00068], rax
    lea rsi, [rbx + tk_IG_CACHE]
    lea rdi, [r15 + 0xa40000]
    mov ecx, tk_IG_CACHE_BYTES / 8
    rep movsq
    jmp tk_intent_prepare_dispatch
tk_intent_prepare_complete:
    mov edx, eax
    cmp rax, rdx
    jne tk_intent_contract_failure
    mov ebp, eax
    cmp eax, 64
    je tk_intent_prepare_copy_result
    cmp eax, 0xfffffffe
    jb tk_intent_contract_failure
    jmp tk_intent_prepare_publish_cache
tk_intent_prepare_copy_result:
    mov rdi, [r15 + tk_IP_REPLY]
    lea rsi, [r15 + 0x1210000]
    mov ecx, 8
    rep movsq
tk_intent_prepare_publish_cache:
    mov rbx, [r15 + tk_IP_GLOBAL]
    mov rax, [r15 + 0xa00060]
    cmp rax, 16
    ja tk_intent_contract_failure
    mov [rbx + tk_IG_CACHE_COUNT], rax
    mov rax, [r15 + 0xa00068]
    mov [rbx + tk_IG_CACHE_HEAD], rax
    lea rdi, [rbx + tk_IG_CACHE]
    lea rsi, [r15 + 0xa40000]
    mov ecx, tk_IG_CACHE_BYTES / 8
    rep movsq
    cmp qword ptr [r15 + 0xb8], 0
    jne tk_intent_contract_failure
    mov qword ptr [r15 + tk_IP_REPLY], 0
    mov qword ptr [r15 + tk_IP_BUSY], 0
    mov eax, ebp
    add rsp, 8
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

tk_intent_prepare_metadata:
    push rdi
    mov rdi, [r15 + tk_IP_GLOBAL]
    call tk_intent_metadata_address
    pop rdi
    lea rsi, [r12 + 8192]
    call tk_intent_file_metadata
    test rax, rax
    js tk_intent_prepare_errno
    mov eax, 107
    syscall
    mov [r12 + 8336], rax
    jmp tk_intent_prepare_ack
tk_intent_prepare_store_lock:
    cmp qword ptr [r15 + 0xb8], 0
    jne tk_intent_contract_failure
    mov rbx, [r15 + tk_IP_GLOBAL]
    lea rdi, [rbx + tk_IG_STORE_GUARD]
    xor eax, eax
    mov ecx, 64
    rep stosq
    mov rdi, [rbx + tk_IG_LOCKS]
    lea rsi, [rbx + tk_IG_STORE_GUARD]
    call tk_result_locks_store_lock
    test eax, eax
    jnz tk_intent_store_unavailable
    mov qword ptr [r15 + 0xb8], 1
    mov qword ptr [r14 + 72], 1
    jmp tk_intent_prepare_ack
tk_intent_store_unavailable:
    # The frozen Store owner phase 2 maps a missing acquired guard to its
    # original fixed 'store unavailable' diagnostic 30, without errno.
    cmp eax, 2
    jne tk_intent_contract_failure
    mov qword ptr [r14 + 72], 0
    jmp tk_intent_prepare_ack
tk_intent_prepare_store_drop:
    cmp qword ptr [r15 + 0xb8], 1
    jne tk_intent_contract_failure
    mov rdi, [r15 + tk_IP_GLOBAL]
    add rdi, tk_IG_STORE_GUARD
    call tk_result_locks_drop
    test eax, eax
    jnz tk_intent_contract_failure
    mov qword ptr [r15 + 0xb8], 0
    jmp tk_intent_prepare_ack
# rdi=IG -> rdx=current shared metadata cache, never retained across calls.
tk_intent_metadata_address:
    mov rax, [rdi + tk_IG_SERVICE]
    test rax, rax
    jz tk_intent_metadata_local
    mov rax, [rax + 24576]
    test rax, rax
    jz tk_intent_contract_failure
    cmp qword ptr [rax + 56], 0
    jne tk_intent_contract_failure
    mov rax, [rax + 16]
    test rax, rax
    jz tk_intent_contract_failure
    cmp qword ptr [rax + 56], 88
    jb tk_intent_contract_failure
    mov rdx, [rax + 48]
    test rdx, rdx
    jz tk_intent_contract_failure
    add rdx, 80
    ret
tk_intent_metadata_local:
    lea rdx, [rdi + tk_IG_META_LOCAL]
    ret
# rdi=IG. Record IO never owns its caller's directory descriptor.
tk_intent_record_create:
    push rbx
    push r12
    sub rsp, 8
    mov rbx, rdi
    xor edi, edi
    mov esi, tk_IR_BYTES
    mov edx, 3
    mov r10d, 34
    mov r8, -1
    xor r9d, r9d
    mov eax, 9
    syscall
    cmp rax, -4095
    jae tk_intent_resource_failure
    mov r12, rax
    mov [rax + tk_IP_GLOBAL], rbx
    mov qword ptr [rax + 128], -1
    mov qword ptr [rax + 136], -1
    mov qword ptr [rax + 144], -1
    lea rdi, [rax + tk_IR_BYTES - 4096]
    mov esi, 4096
    xor edx, edx
    mov eax, 10
    syscall
    test rax, rax
    jnz tk_intent_resource_failure
    mov rax, r12
    add rsp, 8
    pop r12
    pop rbx
    ret
# rdi=map,rsi=checked directory FD,rdx=input,rcx=len,r8=reply262144.
tk_intent_record_call:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp, 8
    mov r15, rdi
    mov rbx, rdx
    mov rbp, rcx
    cmp qword ptr [r15 + tk_IP_BUSY], 0
    jne tk_intent_contract_failure
    cmp qword ptr [r15 + 128], -1
    jne tk_intent_contract_failure
    cmp qword ptr [r15 + 136], -1
    jne tk_intent_contract_failure
    cmp qword ptr [r15 + 144], -1
    jne tk_intent_contract_failure
    cmp rsi, 0x7fffffff
    ja tk_intent_contract_failure
    cmp rcx, 117
    jb tk_intent_contract_failure
    cmp rcx, 1048576
    ja tk_intent_contract_failure
    mov [r15 + 128], rsi
    mov [r15 + 24], rbp
    mov [r15 + tk_IP_REPLY], r8
    mov qword ptr [r15 + tk_IP_BUSY], 1
    lea rdi, [r15 + 4096]
    mov esi, 1048576
    mov edx, 3
    mov eax, 10
    syscall
    test rax, rax
    jnz tk_intent_resource_failure
    lea rdi, [r15 + 4096]
    mov rsi, rbx
    mov rcx, rbp
    rep movsb
    lea rdi, [r15 + 4096]
    mov esi, 1048576
    mov edx, 1
    mov eax, 10
    syscall
    test rax, rax
    jnz tk_intent_resource_failure
    lea r12, [r15 + 0x200000]
    lea r13, [r15 + 0xa00000]
    jmp tk_intent_record_dispatch
tk_intent_record_complete:
    mov ebp, [r15 + 32]
    cmp ebp, 262144
    ja tk_intent_record_no_copy
    mov rdi, [r15 + tk_IP_REPLY]
    lea rsi, [r15 + 0x102000]
    mov ecx, ebp
    rep movsb
tk_intent_record_no_copy:
    mov qword ptr [r15 + 128], -1
    mov qword ptr [r15 + tk_IP_REPLY], 0
    mov qword ptr [r15 + tk_IP_BUSY], 0
    mov eax, ebp
    add rsp, 8
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret
tk_intent_record_metadata:
    push rdi
    mov rdi, [r15 + tk_IP_GLOBAL]
    call tk_intent_metadata_address
    pop rdi
    lea rsi, [r12 + 8192]
    call tk_intent_file_metadata
    test rax, rax
    js tk_intent_record_errno
    mov eax, 107
    syscall
    mov [r12 + 8336], rax
    jmp tk_intent_record_ack

# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
# rdi checked FD, rsi stat64[144], rdx shared original metadata-cache u64*.
# Derived from the frozen Spool statx/glibc/std provider, now full stat64.
# Returns 0 or negative errno; no metadata retry and no business validation.
tk_intent_file_metadata:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp, 280
    mov r12, rdi
    mov r13, rsi
    mov r14, rdx
    mov rax, [r14]
    cmp rax, 2
    ja tk_intent_contract_failure
    je tk_intent_meta_fstat
    mov rdi, rsp
    xor eax, eax
    mov ecx, 32
    rep stosq
    mov rdi, r12
    lea rsi, [rip + tk_intent_empty]
    mov edx, 4096
    mov r10d, 4095
    mov r8, rsp
    mov eax, 332
    syscall
    cmp rax, -38
    je tk_intent_meta_fallback
tk_intent_meta_statx_result:
    test rax, rax
    jz tk_intent_meta_statx_success
    jns tk_intent_contract_failure
    cmp rax, -4095
    jb tk_intent_contract_failure
    cmp qword ptr [r14], 1
    je tk_intent_meta_return
    mov [rsp + 256], rax
    xor edi, edi
    xor esi, esi
    xor edx, edx
    mov r10d, 4095
    xor r8d, r8d
    mov eax, 332
    syscall
    cmp rax, -38
    jne tk_intent_meta_probe_result
    xor edi, edi
    xor esi, esi
    mov rdx, rsp
    xor r10d, r10d
    mov eax, 262
    syscall
    test rax, rax
    jz tk_intent_meta_impossible_null
tk_intent_meta_probe_result:
    cmp rax, -14
    jne tk_intent_meta_unavailable
    mov qword ptr [r14], 1
    mov rax, [rsp + 256]
    jmp tk_intent_meta_return
tk_intent_meta_impossible_null:
    xor eax, eax
    mov [rax], rax
    ud2
tk_intent_meta_unavailable:
    mov qword ptr [r14], 2
tk_intent_meta_fstat:
    mov rdi, r13
    xor eax, eax
    mov ecx, 18
    rep stosq
    mov rdi, r12
    mov rsi, r13
    mov eax, 5
    syscall
    test rax, rax
    js tk_intent_meta_return
    jnz tk_intent_contract_failure
    jmp tk_intent_meta_return
tk_intent_meta_fallback:
    mov rdi, r13
    xor eax, eax
    mov ecx, 18
    rep stosq
    mov rdi, r12
    lea rsi, [rip + tk_intent_empty]
    mov rdx, r13
    mov r10d, 4096
    mov eax, 262
    syscall
    test rax, rax
    jnz tk_intent_meta_statx_result
    mov qword ptr [r14], 1
    # stat64 -> glibc statx -> Rust stat64 narrows these fields.
    mov eax, [r13 + 16]
    mov [r13 + 16], rax
    movzx eax, word ptr [r13 + 24]
    mov [r13 + 24], eax
    mov eax, [r13 + 56]
    mov [r13 + 56], rax
    mov eax, [r13 + 80]
    mov [r13 + 80], rax
    mov eax, [r13 + 96]
    mov [r13 + 96], rax
    mov eax, [r13 + 112]
    mov [r13 + 112], rax
    xor eax, eax
    jmp tk_intent_meta_return
tk_intent_meta_statx_success:
    mov qword ptr [r14], 1
    mov rdi, r13
    xor eax, eax
    mov ecx, 18
    rep stosq
    mov eax, [rsp + 136]
    mov edx, [rsp + 140]
    call tk_intent_device_number
    mov [r13], rax
    mov rax, [rsp + 32]
    mov [r13 + 8], rax
    mov eax, [rsp + 16]
    mov [r13 + 16], rax
    movzx eax, word ptr [rsp + 28]
    mov [r13 + 24], eax
    mov eax, [rsp + 20]
    mov [r13 + 28], eax
    mov eax, [rsp + 24]
    mov [r13 + 32], eax
    mov eax, [rsp + 128]
    mov edx, [rsp + 132]
    call tk_intent_device_number
    mov [r13 + 40], rax
    mov rax, [rsp + 40]
    mov [r13 + 48], rax
    mov eax, [rsp + 4]
    mov [r13 + 56], rax
    mov rax, [rsp + 48]
    mov [r13 + 64], rax
    mov rax, [rsp + 64]
    mov [r13 + 72], rax
    mov eax, [rsp + 72]
    mov [r13 + 80], rax
    mov rax, [rsp + 112]
    mov [r13 + 88], rax
    mov eax, [rsp + 120]
    mov [r13 + 96], rax
    mov rax, [rsp + 96]
    mov [r13 + 104], rax
    mov eax, [rsp + 104]
    mov [r13 + 112], rax
    xor eax, eax
tk_intent_meta_return:
    add rsp, 280
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret
tk_intent_device_number:
    mov ecx, eax
    and ecx, 0xfffff000
    shl rcx, 32
    and eax, 4095
    shl rax, 8
    or rcx, rax
    mov eax, edx
    and edx, 0xffffff00
    shl rdx, 12
    and eax, 255
    or rcx, rdx
    or rax, rcx
    ret
tk_intent_sync_all:
    mov eax, 74
    syscall
    cmp rax, -4
    je tk_intent_sync_all
    ret
tk_intent_empty:
    .byte 0

# Retained prefix: c6d755bc8adca58987f6b4dde48feb264bf546ad2aa1c629a4b6090e5b3dd7d1
tk_intent_prepare_prefix:
    .byte 0x7f,0x45,0x4c,0x46,0x2,0x1,0x1,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x2,0x0,0x3e,0x0,0x1,0x0,0x0,0x0
    .byte 0xb0,0x0,0x40,0x0,0x0,0x0,0x0,0x0,0x40,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0
    .byte 0x0,0x0,0x0,0x0,0x40,0x0,0x38,0x0,0x2,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x1,0x0,0x0,0x0,0x5,0x0,0x0,0x0
    .byte 0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x40,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x40,0x0,0x0,0x0,0x0,0x0
    .byte 0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x10,0x0,0x0,0x0,0x0,0x0,0x0
    .byte 0x51,0xe5,0x74,0x64,0x6,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0
    .byte 0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0
    .byte 0x10,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0xfc,0x48,0x83,0x3c,0x24,0x1,0xf,0x85,0xb8,0x16,0x0,0x0,0x31,0xff,0xbe,0x0
    .byte 0x10,0xc0,0x1,0xba,0x3,0x0,0x0,0x0,0x41,0xba,0x22,0x0,0x0,0x0,0x49,0xc7,0xc0,0xff,0xff,0xff,0xff,0x45,0x31,0xc9
    .byte 0xb8,0x9,0x0,0x0,0x0,0xf,0x5,0x48,0x3d,0x1,0xf0,0xff,0xff,0xf,0x83,0x90,0x16,0x0,0x0,0x49,0x89,0xc7,0x49,0xc7
    .byte 0x87,0x80,0x0,0x0,0x0,0xff,0xff,0xff,0xff,0x49,0xc7,0x87,0x88,0x0,0x0,0x0,0xff,0xff,0xff,0xff,0x49,0xc7,0x87,0x90
    .byte 0x0,0x0,0x0,0xff,0xff,0xff,0xff,0x49,0xc7,0x87,0x98,0x0,0x0,0x0,0xff,0xff,0xff,0xff,0x49,0xc7,0x87,0xa0,0x0,0x0
    .byte 0x0,0xff,0xff,0xff,0xff,0x49,0xc7,0x87,0xa8,0x0,0x0,0x0,0xff,0xff,0xff,0xff,0x49,0xc7,0x87,0xb0,0x0,0x0,0x0,0xff
    .byte 0xff,0xff,0xff,0x49,0xc7,0x87,0xc0,0x0,0x0,0x0,0xff,0xff,0xff,0xff,0x49,0xc7,0x87,0xc8,0x0,0x0,0x0,0xff,0xff,0xff
    .byte 0xff,0x49,0xc7,0x87,0xd0,0x0,0x0,0x0,0xff,0xff,0xff,0xff,0x49,0xc7,0x87,0xd8,0x0,0x0,0x0,0xff,0xff,0xff,0xff,0x49
    .byte 0xc7,0x87,0xe0,0x0,0x0,0x0,0xff,0xff,0xff,0xff,0x49,0xc7,0x87,0xe8,0x0,0x0,0x0,0xff,0xff,0xff,0xff,0x49,0x8d,0xbf
    .byte 0x0,0x0,0xc0,0x1,0xbe,0x0,0x10,0x0,0x0,0x31,0xd2,0xb8,0xa,0x0,0x0,0x0,0xf,0x5,0x48,0x85,0xc0,0xf,0x85,0x7b
    .byte 0x15,0x0,0x0,0x49,0xc7,0x47,0x20,0x3,0x0,0x0,0x0,0x4d,0x8d,0xa7,0x0,0x0,0x0,0x1,0x49,0x8d,0xbf,0x0,0x10,0x0
    .byte 0x0,0xbe,0x0,0x0,0x10,0x0,0xba,0x3,0x0,0x0,0x0,0xb8,0xa,0x0,0x0,0x0,0xf,0x5,0x48,0x85,0xc0,0xf,0x85,0x4b
    .byte 0x15,0x0,0x0,0x49,0x8d,0x77,0x30,0xba,0x8,0x0,0x0,0x0,0x41,0xb8,0x1,0x0,0x0,0x0,0xe8,0xd6,0x14,0x0,0x0,0x85
    .byte 0xc0,0xf,0x84,0x24,0x15,0x0,0x0,0x49,0x8b,0x57,0x30,0x48,0x81,0xfa,0x0,0x0,0x10,0x0,0xf,0x87,0x1e,0x15,0x0,0x0
    .byte 0x49,0x8d,0xb7,0x0,0x10,0x0,0x0,0x45,0x31,0xc0,0xe8,0xae,0x14,0x0,0x0,0x49,0x8d,0xbf,0x0,0x10,0x0,0x0,0xbe,0x0
    .byte 0x0,0x10,0x0,0xba,0x1,0x0,0x0,0x0,0xb8,0xa,0x0,0x0,0x0,0xf,0x5,0x48,0x85,0xc0,0xf,0x85,0xee,0x14,0x0,0x0
    .byte 0x49,0x8b,0x47,0x20,0x48,0x83,0xf8,0x1,0x74,0x6e,0x48,0x83,0xf8,0x2,0xf,0x84,0xd6,0x0,0x0,0x0,0x48,0x83,0xf8,0x3
    .byte 0xf,0x84,0xcf,0x2,0x0,0x0,0x48,0x83,0xf8,0x4,0xf,0x84,0xff,0x2,0x0,0x0,0x48,0x83,0xf8,0x5,0xf,0x84,0xf5,0x2
    .byte 0x0,0x0,0x48,0x85,0xc0,0xf,0x85,0xac,0x14,0x0,0x0,0x4d,0x8d,0xa7,0x0,0x0,0x20,0x0,0x49,0x8d,0xbf,0x0,0x0,0x11
    .byte 0x1,0x49,0x8b,0xb7,0x28,0x1,0x0,0x1,0x49,0x8d,0x97,0x0,0x0,0x21,0x1,0xb9,0x0,0x0,0x4,0x0,0x4d,0x89,0xe0,0x41
    .byte 0xb9,0x0,0x0,0x40,0x0,0xe8
    .long tk_intent_image_result_store - . - 4
    .byte 0x83,0xf8,0xf0,0xf,0x85,0x37,0x13,0x0,0x0,0xe9,0xa,0x1,0x0,0x0,0x4d,0x8d,0xa7,0x0,0x0,0x60,0x0,0x49,0x8d,0xbf
    .byte 0x0,0x0,0x40,0x0,0x49,0x8b,0xb7,0x28,0x1,0x20,0x0,0x49,0x8d,0x97,0x0,0x0,0x42,0x0,0xb9,0x0,0x0,0x4,0x0,0x4d
    .byte 0x89,0xe0,0x41,0xb9,0x0,0x0,0x40,0x0,0xe8
    .long tk_intent_image_result_publish - . - 4
    .byte 0x83,0xf8,0xf0,0xf,0x84,0xd2,0x0,0x0,0x0,0x49,0x83,0x7c,0x24,0x8,0x0,0xf,0x85,0x2b,0x14,0x0,0x0,0x49,0x83,0xbf
    .byte 0xa8,0x0,0x0,0x0,0xff,0xf,0x85,0x1d,0x14,0x0,0x0,0x49,0xc7,0x47,0x20,0x0,0x0,0x0,0x0,0x4d,0x8d,0xa7,0x0,0x0
    .byte 0x20,0x0,0x4d,0x8d,0xb4,0x24,0x0,0x1,0x0,0x0,0x49,0x89,0x46,0x48,0xe9,0x8b,0xf,0x0,0x0,0x49,0x8d,0xbf,0x0,0x0
    .byte 0x40,0x0,0x49,0x8d,0x97,0x0,0x0,0x42,0x0,0x49,0x83,0x7f,0x28,0x0,0x74,0x19,0x49,0x83,0x7f,0x28,0x1,0xf,0x85,0xdd
    .byte 0x13,0x0,0x0,0x49,0x8d,0xbf,0x0,0x0,0x80,0x0,0x49,0x8d,0x97,0x0,0x0,0x82,0x0,0x4d,0x8d,0xa7,0x0,0x0,0xa0,0x0
    .byte 0xbe,0x18,0x0,0x0,0x0,0xb9,0x0,0x0,0x4,0x0,0x4d,0x89,0xe0,0x41,0xb9,0x0,0x0,0x40,0x0,0xe8
    .long tk_intent_image_result_metadata - . - 4
    .byte 0x83,0xf8,0xf0,0x74,0x46,0x49,0x83,0x7c,0x24,0x8,0x0,0xf,0x85,0x9f,0x13,0x0,0x0,0x49,0x83,0xbf,0xb0,0x0,0x0,0x0
    .byte 0xff,0xf,0x85,0x91,0x13,0x0,0x0,0x49,0x8b,0x4f,0x28,0x49,0x89,0x4f,0x20,0x4d,0x8d,0xa7,0x0,0x0,0x20,0x0,0x48,0x85
    .byte 0xc9,0x74,0x7,0x4d,0x8d,0xa7,0x0,0x0,0x60,0x0,0x4d,0x8d,0xb4,0x24,0x0,0x1,0x0,0x0,0x49,0x89,0x46,0x48,0xe9,0xf3
    .byte 0xe,0x0,0x0,0x4d,0x8d,0xb4,0x24,0x0,0x1,0x0,0x0,0x49,0x8b,0x4f,0x20,0x48,0xb8,0x48,0x52,0x41,0x53,0x41,0x30,0x30
    .byte 0x31,0x48,0x85,0xc9,0x74,0x44,0x48,0xb8,0x48,0x52,0x41,0x50,0x41,0x30,0x30,0x31,0x48,0x83,0xf9,0x1,0x74,0x34,0x48,0xb8
    .byte 0x48,0x52,0x41,0x4d,0x41,0x30,0x30,0x31,0x48,0x83,0xf9,0x2,0x74,0x24,0x48,0xb8,0x48,0x52,0x53,0x50,0x41,0x30,0x30,0x31
    .byte 0x48,0x83,0xf9,0x3,0x74,0x14,0x48,0xb8,0x48,0x52,0x44,0x41,0x41,0x30,0x30,0x31,0x48,0x83,0xf9,0x5,0xf,0x87,0x6,0x13
    .byte 0x0,0x0,0x49,0x39,0x6,0xf,0x85,0xfd,0x12,0x0,0x0,0x49,0x8d,0x7c,0xcf,0x8,0x48,0x83,0xf9,0x2,0x76,0x5,0x49,0x8d
    .byte 0x7c,0xcf,0x38,0x48,0x8b,0x7,0x48,0xff,0xc0,0xf,0x84,0xe1,0x12,0x0,0x0,0x49,0x39,0x46,0x8,0xf,0x85,0xd7,0x12,0x0
    .byte 0x0,0x49,0x39,0x44,0x24,0x10,0xf,0x85,0xcc,0x12,0x0,0x0,0x48,0x89,0x7,0x49,0x8b,0x46,0x40,0x49,0xb,0x46,0x48,0x49
    .byte 0xb,0x46,0x50,0x49,0xb,0x46,0x58,0xf,0x85,0xb3,0x12,0x0,0x0,0x49,0x8b,0x46,0x10,0x48,0x85,0xc9,0xf,0x84,0xe0,0x3
    .byte 0x0,0x0,0x48,0x83,0xf9,0x3,0xf,0x84,0xfa,0x1,0x0,0x0,0xf,0x87,0xb5,0x2,0x0,0x0,0x48,0x83,0xf8,0x66,0xf,0x84
    .byte 0x5d,0x8,0x0,0x0,0x48,0x83,0xf8,0x64,0xf,0x84,0xa7,0x7,0x0,0x0,0x48,0x83,0xf8,0x65,0xf,0x84,0x9d,0x7,0x0,0x0
    .byte 0x49,0x83,0x7e,0x38,0x0,0xf,0x85,0x6d,0x12,0x0,0x0,0x48,0x83,0xf8,0x1,0xf,0x84,0x5d,0xd,0x0,0x0,0x48,0x83,0xf8
    .byte 0x2,0xf,0x84,0x8a,0x9,0x0,0x0,0x48,0x83,0xf8,0x3,0xf,0x84,0x42,0xb,0x0,0x0,0x48,0x83,0xf8,0x4,0xf,0x84,0xa8
    .byte 0xb,0x0,0x0,0x48,0x83,0xf8,0x5,0xf,0x84,0x0,0xc,0x0,0x0,0x48,0x83,0xf8,0x6,0xf,0x84,0x1d,0xc,0x0,0x0,0x48
    .byte 0x83,0xf8,0x8,0xf,0x84,0x82,0xc,0x0,0x0,0x48,0x83,0xf8,0x9,0xf,0x84,0x73,0xd,0x0,0x0,0x48,0x83,0xf8,0xa,0xf
    .byte 0x84,0x64,0xa,0x0,0x0,0x48,0x83,0xf8,0xb,0xf,0x84,0x9f,0xc,0x0,0x0,0x48,0x83,0xf8,0xc,0xf,0x84,0xcc,0xc,0x0
    .byte 0x0,0xe9,0xfa,0x11,0x0,0x0,0x4d,0x8d,0xa7,0x0,0x0,0x0,0x1,0x49,0x8d,0xbf,0x0,0x10,0x0,0x0,0x49,0x8b,0x77,0x30
    .byte 0x49,0x8d,0x97,0x0,0x20,0x10,0x0,0xb9,0x0,0x0,0x4,0x0,0x4d,0x89,0xe0,0x41,0xb9,0x0,0x0,0x40,0x0,0xe8
    .long tk_intent_unreachable_prepare - . - 4
    .byte 0x83,0xf8,0xf0,0xf,0x85,0x49,0x2,0x0,0x0,0xe9,0x5b,0xfe,0xff,0xff,0x4d,0x8d,0xa7,0x0,0x0,0x40,0x1,0x49,0x83,0x7f
    .byte 0x20,0x4,0x74,0x12,0x49,0x83,0x7f,0x20,0x5,0xf,0x85,0xa7,0x11,0x0,0x0,0x4d,0x8d,0xa7,0x0,0x0,0x80,0x1,0x49,0x8d
    .byte 0xbf,0x0,0x0,0x11,0x1,0x49,0x8b,0xb7,0x28,0x1,0x0,0x1,0x49,0x8d,0x97,0x0,0x0,0x21,0x1,0xb9,0x0,0x0,0x4,0x0
    .byte 0x4d,0x89,0xe0,0x41,0xb9,0x0,0x0,0x40,0x0,0xe8
    .long tk_intent_image_result_directory - . - 4
    .byte 0x83,0xf8,0xf0,0xf,0x84,0xa,0xfe,0xff,0xff,0x89,0xc5,0x49,0x83,0x7c,0x24,0x8,0x0,0xf,0x85,0x61,0x11,0x0,0x0,0xe8
    .byte 0x99,0x0,0x0,0x0,0x49,0x83,0x7d,0x0,0xff,0xf,0x85,0x51,0x11,0x0,0x0,0x49,0x83,0x7d,0x8,0xff,0xf,0x85,0x46,0x11
    .byte 0x0,0x0,0x49,0x83,0x7c,0x24,0x40,0x0,0x74,0x25,0x49,0x83,0x7c,0x24,0x40,0x4,0xf,0x85,0x32,0x11,0x0,0x0,0x49,0x83
    .byte 0x7c,0x24,0x48,0x0,0xf,0x84,0x26,0x11,0x0,0x0,0x49,0x83,0x7d,0x10,0x0,0xf,0x8c,0x1b,0x11,0x0,0x0,0xeb,0x17,0x49
    .byte 0x83,0x7c,0x24,0x48,0x0,0xf,0x85,0xd,0x11,0x0,0x0,0x49,0x83,0x7d,0x10,0xff,0xf,0x85,0x2,0x11,0x0,0x0,0x49,0x8b
    .byte 0x45,0x10,0x49,0x83,0x7f,0x20,0x4,0x75,0x9,0x49,0x89,0x87,0x88,0x0,0x0,0x0,0xeb,0x7,0x49,0x89,0x87,0x80,0x0,0x0
    .byte 0x0,0x89,0xe8
    .byte 0xe9
    .long tk_intent_prepare_complete - . - 4
    .byte 0x90
    .byte 0x90
    .byte 0x90
    .byte 0x90
    .byte 0x90
    .byte 0x4d,0x8d,0xa7,0x0,0x0,0x0,0x1,0x4d,0x8d,0xb4,0x24,0x0,0x1,0x0,0x0,0x49,0x89,0x46,0x48,0xe9,0x51,0xc,0x0,0x0
    .byte 0x4d,0x8d,0xaf,0xc0,0x0,0x0,0x0,0x49,0x83,0x7f,0x20,0x4,0x74,0x12,0x49,0x83,0x7f,0x20,0x5,0xf,0x85,0xaa,0x10,0x0
    .byte 0x0,0x4d,0x8d,0xaf,0xd8,0x0,0x0,0x0,0xc3,0x49,0x81,0x7e,0x20,0x0,0x0,0x11,0x0,0xf,0x85,0x94,0x10,0x0,0x0,0x49
    .byte 0x83,0x7e,0x28,0x30,0xf,0x82,0x89,0x10,0x0,0x0,0x49,0x81,0x7e,0x28,0x0,0x0,0x10,0x0,0xf,0x87,0x7b,0x10,0x0,0x0
    .byte 0x49,0x81,0x7e,0x30,0x0,0x0,0x21,0x0,0xf,0x85,0x6d,0x10,0x0,0x0,0x49,0x81,0x7e,0x38,0x0,0x0,0x4,0x0,0xf,0x85
    .byte 0x5f,0x10,0x0,0x0,0x48,0x83,0xf8,0x65,0x74,0x3d,0x48,0x83,0xf8,0x64,0xf,0x85,0x4f,0x10,0x0,0x0,0x49,0x8b,0x4e,0x18
    .byte 0x48,0x83,0xf9,0x1,0xf,0x87,0x41,0x10,0x0,0x0,0x48,0xb8,0x48,0x52,0x44,0x41,0x51,0x30,0x30,0x31,0x49,0x39,0x84,0x24
    .byte 0x0,0x0,0x11,0x0,0xf,0x85,0x29,0x10,0x0,0x0,0x48,0x83,0xc1,0x4,0x49,0x89,0x4f,0x20,0xe9,0x35,0xfb,0xff,0xff,0x49
    .byte 0x83,0x7e,0x18,0x0,0xf,0x85,0x11,0x10,0x0,0x0,0x49,0x83,0x7e,0x28,0x30,0xf,0x85,0x6,0x10,0x0,0x0,0x48,0xb8,0x48
    .byte 0x52,0x41,0x53,0x51,0x30,0x30,0x31,0x49,0x39,0x84,0x24,0x0,0x0,0x11,0x0,0xf,0x85,0xee,0xf,0x0,0x0,0x49,0xc7,0x47
    .byte 0x20,0x0,0x0,0x0,0x0,0xe9,0xfa,0xfa,0xff,0xff,0xe8,0x19,0xff,0xff,0xff,0x49,0x83,0x7e,0x38,0x0,0xf,0x85,0xd1,0xf
    .byte 0x0,0x0,0x48,0x83,0xf8,0x1,0xf,0x84,0x46,0xc,0x0,0x0,0x48,0x83,0xf8,0x2,0xf,0x84,0x7a,0xc,0x0,0x0,0x48,0x83
    .byte 0xf8,0x3,0xf,0x84,0x46,0xd,0x0,0x0,0x48,0x83,0xf8,0x4,0xf,0x84,0x94,0xd,0x0,0x0,0x48,0x83,0xf8,0x5,0xf,0x84
    .byte 0xd7,0xd,0x0,0x0,0x48,0x83,0xf8,0x6,0xf,0x84,0xec,0xd,0x0,0x0,0x48,0x83,0xf8,0x7,0xf,0x84,0x1,0xe,0x0,0x0
    .byte 0x48,0x83,0xf8,0x8,0xf,0x84,0xb0,0xc,0x0,0x0,0xe9,0x7c,0xf,0x0,0x0,0x41,0x89,0x47,0x48,0x49,0x83,0x7f,0x20,0x3
    .byte 0xf,0x85,0x6d,0xf,0x0,0x0,0x49,0x83,0xbf,0xb8,0x0,0x0,0x0,0x0,0xf,0x85,0x5f,0xf,0x0,0x0,0x49,0x83,0x7c,0x24
    .byte 0x8,0x0,0xf,0x85,0x53,0xf,0x0,0x0,0x49,0x8b,0x44,0x24,0x30,0x49,0xb,0x44,0x24,0x38,0x49,0xb,0x44,0x24,0x40,0xf
    .byte 0x85,0x3e,0xf,0x0,0x0,0xbb,0x6,0x0,0x0,0x0,0x49,0x83,0xbc,0xdf,0x80,0x0,0x0,0x0,0xff,0xf,0x85,0x2a,0xf,0x0
    .byte 0x0,0xff,0xcb,0x79,0xed,0xbb,0x5,0x0,0x0,0x0,0x49,0x83,0xbc,0xdf,0xc0,0x0,0x0,0x0,0xff,0xf,0x85,0x12,0xf,0x0
    .byte 0x0,0xff,0xcb,0x79,0xed,0x41,0x83,0x7f,0x48,0x20,0x74,0x12,0x41,0x83,0x7f,0x48,0xff,0x74,0xb,0x41,0x83,0x7f,0x48,0xfe
    .byte 0xf,0x85,0xf5,0xe,0x0,0x0,0x49,0x8d,0x77,0x48,0xba,0x4,0x0,0x0,0x0,0xe8,0xbe,0xe,0x0,0x0,0x41,0x83,0x7f,0x48
    .byte 0x20,0xf,0x85,0x77,0xf9,0xff,0xff,0x49,0x8d,0xb7,0x0,0x20,0x10,0x0,0xba,0x20,0x0,0x0,0x0,0xe8,0xa2,0xe,0x0,0x0
    .byte 0xe9,0x61,0xf9,0xff,0xff,0x48,0x83,0xf8,0x64,0x74,0x66,0x48,0x83,0xf8,0x65,0x74,0x60,0x49,0x83,0x7e,0x38,0x0,0xf,0x85
    .byte 0xaf,0xe,0x0,0x0,0x48,0x83,0xf8,0x2,0xf,0x84,0x76,0x2,0x0,0x0,0x48,0x83,0xf8,0x3,0xf,0x84,0x21,0x3,0x0,0x0
    .byte 0x48,0x83,0xf8,0x4,0xf,0x84,0xe0,0x2,0x0,0x0,0x48,0x83,0xf8,0x5,0xf,0x84,0x65,0x3,0x0,0x0,0x48,0x83,0xf8,0x6
    .byte 0xf,0x84,0x71,0x3,0x0,0x0,0x48,0x83,0xf8,0x8,0xf,0x84,0x44,0x2,0x0,0x0,0x48,0x83,0xf8,0xb,0xf,0x84,0xff,0x8
    .byte 0x0,0x0,0x48,0x83,0xf8,0xc,0xf,0x84,0x2c,0x9,0x0,0x0,0xe9,0x5a,0xe,0x0,0x0,0x49,0x83,0x7e,0x18,0x1,0xf,0x87
    .byte 0x4f,0xe,0x0,0x0,0x49,0x81,0x7e,0x20,0x0,0x0,0x20,0x0,0xf,0x85,0x41,0xe,0x0,0x0,0x49,0x81,0x7e,0x30,0x0,0x0
    .byte 0x22,0x0,0xf,0x85,0x33,0xe,0x0,0x0,0x49,0x81,0x7e,0x38,0x0,0x0,0x4,0x0,0xf,0x85,0x25,0xe,0x0,0x0,0x49,0x8b
    .byte 0x8c,0x24,0x8,0x0,0x20,0x0,0x48,0xff,0xc9,0x49,0x3b,0x4e,0x18,0xf,0x85,0x10,0xe,0x0,0x0,0x49,0x83,0x7e,0x10,0x65
    .byte 0x74,0x59,0x49,0x83,0x7e,0x28,0x18,0xf,0x85,0xfe,0xd,0x0,0x0,0x48,0xb8,0x48,0x52,0x41,0x4d,0x51,0x30,0x30,0x31,0x49
    .byte 0x39,0x84,0x24,0x0,0x0,0x20,0x0,0xf,0x85,0xe6,0xd,0x0,0x0,0x49,0x83,0xbc,0x24,0x10,0x0,0x20,0x0,0x0,0xf,0x85
    .byte 0xd7,0xd,0x0,0x0,0x49,0x83,0xbf,0xb0,0x0,0x0,0x0,0xff,0xf,0x85,0xc9,0xd,0x0,0x0,0x49,0x89,0x4f,0x38,0x49,0xc7
    .byte 0x47,0x28,0x0,0x0,0x0,0x0,0x49,0xc7,0x47,0x20,0x2,0x0,0x0,0x0,0xe9,0xc9,0xf8,0xff,0xff,0x49,0x83,0x7e,0x28,0x18
    .byte 0xf,0x82,0xa5,0xd,0x0,0x0,0x49,0x81,0x7e,0x28,0x18,0x80,0x1,0x0,0xf,0x87,0x97,0xd,0x0,0x0,0x48,0xb8,0x48,0x52
    .byte 0x41,0x50,0x51,0x30,0x30,0x31,0x49,0x39,0x84,0x24,0x0,0x0,0x20,0x0,0xf,0x85,0x7f,0xd,0x0,0x0,0x49,0x83,0xbf,0xa8
    .byte 0x0,0x0,0x0,0xff,0xf,0x85,0x71,0xd,0x0,0x0,0x49,0x89,0x4f,0x40,0x49,0xc7,0x47,0x20,0x1,0x0,0x0,0x0,0xe9,0x79
    .byte 0xf8,0xff,0xff,0x49,0x8b,0x4e,0x18,0x48,0x83,0xf9,0x4,0xf,0x87,0x52,0xd,0x0,0x0,0x49,0x8b,0xbc,0xcf,0x80,0x0,0x0
    .byte 0x0,0x48,0x85,0xff,0xf,0x88,0x41,0xd,0x0,0x0,0xc3,0x49,0x8b,0x46,0x20,0x48,0x3d,0x0,0xb0,0x1,0x0,0xf,0x84,0x8e
    .byte 0x0,0x0,0x0,0x48,0x3d,0x80,0xb0,0x1,0x0,0xf,0x84,0xba,0x0,0x0,0x0,0x48,0x3d,0x0,0xb1,0x1,0x0,0xf,0x85,0x18
    .byte 0xd,0x0,0x0,0x49,0x83,0x7e,0x28,0x2,0xf,0x85,0xd,0xd,0x0,0x0,0x41,0x80,0xbc,0x24,0x2,0xb1,0x1,0x0,0x0,0xf
    .byte 0x85,0xfe,0xc,0x0,0x0,0x49,0x8b,0x44,0x24,0x58,0x48,0x3d,0xff,0x0,0x0,0x0,0xf,0x87,0xed,0xc,0x0,0x0,0x48,0x89
    .byte 0xc2,0x48,0xc1,0xe8,0x4,0xe8,0x32,0x0,0x0,0x0,0x41,0x38,0x84,0x24,0x0,0xb1,0x1,0x0,0xf,0x85,0xd3,0xc,0x0,0x0
    .byte 0x48,0x89,0xd0,0x83,0xe0,0xf,0xe8,0x19,0x0,0x0,0x0,0x41,0x38,0x84,0x24,0x1,0xb1,0x1,0x0,0xf,0x85,0xba,0xc,0x0
    .byte 0x0,0xbd,0x3,0x0,0x0,0x0,0xbb,0x4,0x0,0x0,0x0,0xc3,0x83,0xf8,0xa,0x72,0x4,0x83,0xc0,0x57,0xc3,0x83,0xc0,0x30
    .byte 0xc3,0x49,0x83,0x7e,0x28,0x12,0xf,0x85,0x97,0xc,0x0,0x0,0x48,0x8d,0x35,0x5d,0xd,0x0,0x0,0x49,0x8d,0xbc,0x24,0x0
    .byte 0xb0,0x1,0x0,0xb9,0x12,0x0,0x0,0x0,0xf3,0xa6,0xf,0x85,0x7b,0xc,0x0,0x0,0x80,0x3f,0x0,0xf,0x85,0x72,0xc,0x0
    .byte 0x0,0x31,0xed,0xbb,0x2,0x0,0x0,0x0,0xc3,0x49,0x83,0x7e,0x28,0x7,0xf,0x85,0x5f,0xc,0x0,0x0,0x48,0x8d,0x35,0x37
    .byte 0xd,0x0,0x0,0x49,0x8d,0xbc,0x24,0x80,0xb0,0x1,0x0,0xb9,0x7,0x0,0x0,0x0,0xf3,0xa6,0xf,0x85,0x43,0xc,0x0,0x0
    .byte 0x80,0x3f,0x0,0xf,0x85,0x3a,0xc,0x0,0x0,0xbd,0x2,0x0,0x0,0x0,0xbb,0x3,0x0,0x0,0x0,0xc3,0xe8,0xea,0xfe,0xff
    .byte 0xff,0x49,0x39,0x5e,0x18,0xf,0x85,0x20,0xc,0x0,0x0,0x49,0x39,0x6e,0x30,0xf,0x85,0x16,0xc,0x0,0x0,0x49,0x83,0xbc
    .byte 0xdf,0x80,0x0,0x0,0x0,0xff,0xf,0x85,0x7,0xc,0x0,0x0,0x49,0x8b,0xbc,0xef,0x80,0x0,0x0,0x0,0x48,0x85,0xff,0xf
    .byte 0x88,0xf6,0xb,0x0,0x0,0x49,0x8b,0x76,0x20,0x4c,0x1,0xe6,0xba,0x0,0x0,0xb,0x0,0x49,0x83,0x7e,0x10,0x8,0x75,0xe
    .byte 0x83,0xfb,0x2,0xf,0x85,0xda,0xb,0x0,0x0,0xba,0x0,0x8,0xa,0x0,0x45,0x31,0xd2,0xb8,0x1,0x1,0x0,0x0,0xf,0x5
    .byte 0x48,0x85,0xc0,0xf,0x88,0x3d,0x7,0x0,0x0,0x49,0x89,0x84,0xdf,0x80,0x0,0x0,0x0,0x49,0x89,0x5e,0x48,0xe9,0x3f,0x7
    .byte 0x0,0x0,0xe8,0x6c,0xfe,0xff,0xff,0x49,0x39,0x6e,0x18,0xf,0x85,0xa2,0xb,0x0,0x0,0x49,0x83,0x7e,0x30,0x0,0xf,0x85
    .byte 0x97,0xb,0x0,0x0,0xe8,0x32,0xfe,0xff,0xff,0x49,0x8b,0x76,0x20,0x4c,0x1,0xe6,0xba,0xc0,0x1,0x0,0x0,0xb8,0x2,0x1
    .byte 0x0,0x0,0xf,0x5,0xe9,0xea,0x6,0x0,0x0,0xe8,0x15,0xfe,0xff,0xff,0x49,0x81,0x7e,0x20,0x0,0x20,0x0,0x0,0xf,0x85
    .byte 0x67,0xb,0x0,0x0,0x49,0x81,0x7e,0x28,0x98,0x0,0x0,0x0,0xf,0x85,0x59,0xb,0x0,0x0,0x49,0x83,0x7e,0x30,0x0,0xf
    .byte 0x85,0x4e,0xb,0x0,0x0
    .byte 0xe9
    .long tk_intent_prepare_metadata - . - 4
    .byte 0x90
    .byte 0x90
    .byte 0x90
    .byte 0x90
    .byte 0x90
    .byte 0x90
    .byte 0x90
    .byte 0x90
    .byte 0x90
    .byte 0x90
    .byte 0x90
    .byte 0x90
    .byte 0x90
    .byte 0x90
    .byte 0x90
    .byte 0x90
    .byte 0x90
    .byte 0x90
    .byte 0x90
    .byte 0x90
    .byte 0x90
    .byte 0x90
    .byte 0x90
    .byte 0x90
    .byte 0x90
    .byte 0x90
    .byte 0x90
    .byte 0x90
    .byte 0x90
    .byte 0x90
    .byte 0x90
    .byte 0x90
    .byte 0x90
    .byte 0x90
    .byte 0xe9,0xb0,0x6,0x0,0x0,0xe8,0xbd,0xfd,0xff,0xff,0xe8,0x36,0x2,0x0,0x0
    .byte 0xe8
    .long tk_intent_sync_all - . - 4
    .byte 0x90,0x90
    .byte 0xe9,0x7c,0x6,0x0,0x0,0x49,0x83,0x7e,0x18,0x2,0xf,0x82,0x1,0xb,0x0,0x0,0xe8,0x9c,0xfd,0xff,0xff,0xe8,0x15,0x2
    .byte 0x0,0x0,0x49,0x8b,0x4e,0x18,0x49,0xc7,0x84,0xcf,0x80,0x0,0x0,0x0,0xff,0xff,0xff,0xff,0xb8,0x3,0x0,0x0,0x0,0xf
    .byte 0x5,0xe9,0x69,0x6,0x0,0x0,0x49,0x83,0x7e,0x18,0x0,0xf,0x85,0xd0,0xa,0x0,0x0,0x49,0x83,0x7e,0x28,0x18,0xf,0x82
    .byte 0xc5,0xa,0x0,0x0,0x49,0x81,0x7e,0x28,0x18,0x80,0x1,0x0,0xf,0x87,0xb7,0xa,0x0,0x0,0x49,0x81,0x7e,0x38,0x0,0x0
    .byte 0x4,0x0,0xf,0x85,0xa9,0xa,0x0,0x0,0xb8,0x0,0x0,0x11,0x0,0xba,0x0,0x0,0x21,0x0,0x49,0x83,0x7f,0x20,0x2,0x74
    .byte 0x15,0x49,0x83,0x7e,0x10,0x64,0xf,0x85,0x8d,0xa,0x0,0x0,0xb8,0x0,0x0,0x20,0x0,0xba,0x0,0x0,0x22,0x0,0x49,0x39
    .byte 0x46,0x20,0xf,0x85,0x79,0xa,0x0,0x0,0x49,0x39,0x56,0x30,0xf,0x85,0x6f,0xa,0x0,0x0,0x49,0x8d,0x3c,0x4,0x49,0x8b
    .byte 0x76,0x28,0x4c,0x1,0xe2,0xb9,0x0,0x0,0x4,0x0,0x41,0xb9,0x0,0x0,0x10,0x0,0x49,0x83,0x7e,0x10,0x64,0x74,0xe,0x4d
    .byte 0x8d,0x87,0x0,0x0,0xf0,0x0,0xe8
    .long tk_intent_image_binary_codec - . - 4
    .byte 0xeb,0xc,0x4d,0x8d,0x87,0x0,0x0,0xe0,0x0,0xe8
    .long tk_intent_image_storage_json - . - 4
    .byte 0x49,0x89,0x46,0x48,0xe9,0xbd,0x5,0x0,0x0,0xe8,0xa1,0x0,0x0,0x0,0x49,0x83,0x7e,0x18,0x0,0xf,0x85,0x1f,0xa,0x0
    .byte 0x0,0x49,0x81,0x7e,0x20,0x0,0x0,0x20,0x0,0xf,0x85,0x11,0xa,0x0,0x0,0x49,0x83,0x7e,0x28,0x18,0xf,0x85,0x6,0xa
    .byte 0x0,0x0,0x49,0x81,0x7e,0x30,0x0,0x0,0x22,0x0,0xf,0x85,0xf8,0x9,0x0,0x0,0x49,0x81,0x7e,0x38,0x0,0x0,0x4,0x0
    .byte 0xf,0x85,0xea,0x9,0x0,0x0,0x48,0xb8,0x48,0x52,0x41,0x4d,0x51,0x30,0x30,0x31,0x49,0x39,0x84,0x24,0x0,0x0,0x20,0x0
    .byte 0xf,0x85,0xd2,0x9,0x0,0x0,0x49,0x83,0xbc,0x24,0x8,0x0,0x20,0x0,0x2,0xf,0x85,0xc3,0x9,0x0,0x0,0x49,0x83,0xbc
    .byte 0x24,0x10,0x0,0x20,0x0,0x0,0xf,0x85,0xb4,0x9,0x0,0x0,0x49,0x83,0xbf,0xb0,0x0,0x0,0x0,0xff,0xf,0x85,0xa6,0x9
    .byte 0x0,0x0,0x49,0x8b,0x47,0x40,0x49,0x89,0x47,0x38,0x49,0xc7,0x47,0x28,0x1,0x0,0x0,0x0,0x49,0xc7,0x47,0x20,0x2,0x0
    .byte 0x0,0x0,0xe9,0xa2,0xf4,0xff,0xff,0x49,0x83,0x7f,0x20,0x1,0xf,0x85,0x7e,0x9,0x0,0x0,0xc3,0x49,0x8b,0x5f,0x20,0x48
    .byte 0x83,0xfb,0x1,0xf,0x82,0x6f,0x9,0x0,0x0,0x48,0x83,0xfb,0x2,0xf,0x87,0x65,0x9,0x0,0x0,0x49,0x8d,0x9c,0xdf,0xa0
    .byte 0x0,0x0,0x0,0xc3,0x49,0x83,0x7e,0x18,0x1,0xf,0x85,0x51,0x9,0x0,0x0,0xe8,0xcf,0xff,0xff,0xff,0x48,0x8b,0x3b,0x48
    .byte 0x85,0xff,0xf,0x88,0x40,0x9,0x0,0x0,0xc3,0x49,0x83,0x7e,0x18,0x1,0xf,0x85,0x34,0x9,0x0,0x0,0xe8,0xb2,0xff,0xff
    .byte 0xff,0x48,0x83,0x3b,0xff,0xf,0x85,0x25,0x9,0x0,0x0,0xc3,0x49,0x8b,0x4f,0x40,0x49,0x83,0x7f,0x20,0x1,0x74,0xf,0x49
    .byte 0x83,0x7f,0x20,0x2,0xf,0x85,0xe,0x9,0x0,0x0,0x49,0x8b,0x4f,0x38,0x48,0x83,0xf9,0x1,0xf,0x87,0x0,0x9,0x0,0x0
    .byte 0x49,0x8b,0xbc,0xcf,0x80,0x0,0x0,0x0,0x48,0x85,0xff,0xf,0x88,0xef,0x8,0x0,0x0,0xc3,0x49,0x83,0x7f,0x20,0x1,0xf
    .byte 0x87,0xe3,0x8,0x0,0x0,0xc3,0x49,0x8b,0x46,0x20,0x49,0xb,0x46,0x28,0x49,0xb,0x46,0x30,0xf,0x85,0xd0,0x8,0x0,0x0
    .byte 0xc3,0xe8,0x8b,0xff,0xff,0xff,0x49,0x83,0x7f,0x20,0x1,0x74,0x7a,0x49,0x81,0x7e,0x20,0x0,0x10,0x0,0x0,0xf,0x85,0xb5
    .byte 0x8,0x0,0x0,0x49,0x83,0x7e,0x30,0x0,0xf,0x85,0xaa,0x8,0x0,0x0,0x48,0x8d,0x35,0x3c,0x9,0x0,0x0,0xb9,0x18,0x0
    .byte 0x0,0x0,0x49,0x83,0x7c,0x24,0x30,0x2,0x74,0x18,0x49,0x83,0x7c,0x24,0x30,0x1,0xf,0x85,0x8a,0x8,0x0,0x0,0x48,0x8d
    .byte 0x35,0xfd,0x8,0x0,0x0,0xb9,0x1f,0x0,0x0,0x0,0x49,0x39,0x4e,0x28,0xf,0x85,0x74,0x8,0x0,0x0,0x49,0x8d,0xbc,0x24
    .byte 0x0,0x10,0x0,0x0,0xf3,0xa6,0xf,0x85,0x64,0x8,0x0,0x0,0x80,0x3f,0x0,0xf,0x85,0x5b,0x8,0x0,0x0,0x49,0x8d,0xb4
    .byte 0x24,0x0,0x10,0x0,0x0,0xba,0x0,0x8,0xa,0x0,0x45,0x31,0xd2,0xeb,0x75,0x49,0x83,0x7e,0x30,0x1,0xf,0x85,0x3e,0x8
    .byte 0x0,0x0,0x49,0x81,0x7e,0x20,0x0,0xb0,0x1,0x0,0x74,0x48,0x49,0x81,0x7e,0x20,0xc0,0xb0,0x1,0x0,0xf,0x85,0x26,0x8
    .byte 0x0,0x0,0x49,0x83,0x7e,0x28,0x18,0xf,0x85,0x1b,0x8,0x0,0x0,0x49,0x8d,0xbc,0x24,0xc0,0xb0,0x1,0x0,0x48,0x8d,0x35
    .byte 0xa5,0x8,0x0,0x0,0xb9,0x18,0x0,0x0,0x0,0xf3,0xa6,0xf,0x85,0xff,0x7,0x0,0x0,0x80,0x3f,0x0,0xf,0x85,0xf6,0x7
    .byte 0x0,0x0,0x49,0x8d,0xb4,0x24,0xc0,0xb0,0x1,0x0,0xeb,0xd,0xe8,0x64,0x0,0x0,0x0,0x49,0x8d,0xb4,0x24,0x0,0xb0,0x1
    .byte 0x0,0xba,0xc1,0x0,0xa,0x0,0x41,0xba,0x80,0x1,0x0,0x0,0xe8,0xab,0xfe,0xff,0xff,0xb8,0x1,0x1,0x0,0x0,0xf,0x5
    .byte 0x48,0x85,0xc0,0xf,0x88,0x3a,0x3,0x0,0x0,0x48,0x89,0x3,0x49,0xc7,0x46,0x48,0x1,0x0,0x0,0x0,0xe9,0x3d,0x3,0x0
    .byte 0x0,0xe8,0x21,0xfe,0xff,0xff,0xe8,0x66,0xfe,0xff,0xff,0xe8,0xbe,0xfe,0xff,0xff,0xbf,0x9c,0xff,0xff,0xff,0x48,0x8d,0x35
    .byte 0x45,0x8,0x0,0x0,0xba,0x0,0x0,0x8,0x0,0x45,0x31,0xd2,0xb8,0x1,0x1,0x0,0x0,0xf,0x5,0xeb,0xbb,0x49,0x81,0x7e
    .byte 0x20,0x0,0xb0,0x1,0x0,0xf,0x85,0x75,0x7,0x0,0x0,0x49,0x83,0x7e,0x28,0x53,0xf,0x85,0x6a,0x7,0x0,0x0,0x49,0x8d
    .byte 0xbc,0x24,0x0,0xb0,0x1,0x0,0x48,0x8d,0x35,0x19,0x8,0x0,0x0,0xb9,0xf,0x0,0x0,0x0,0xf3,0xa6,0xf,0x85,0x4e,0x7
    .byte 0x0,0x0,0xb9,0x40,0x0,0x0,0x0,0x8a,0x7,0x3c,0x30,0xf,0x82,0x3f,0x7,0x0,0x0,0x3c,0x39,0x76,0x10,0x3c,0x61,0xf
    .byte 0x82,0x33,0x7,0x0,0x0,0x3c,0x66,0xf,0x87,0x2b,0x7,0x0,0x0,0x48,0xff,0xc7,0xff,0xc9,0x75,0xdb,0x81,0x3f,0x2e,0x74
    .byte 0x6d,0x70,0xf,0x85,0x18,0x7,0x0,0x0,0x80,0x7f,0x4,0x0,0xf,0x85,0xe,0x7,0x0,0x0,0xc3,0xe8,0xac,0xfd,0xff,0xff
    .byte 0x49,0x83,0x7e,0x30,0x0,0xf,0x85,0xfd,0x6,0x0,0x0,0x49,0x8b,0x44,0x24,0x40,0x48,0x89,0xc1,0x49,0x83,0x7f,0x20,0x1
    .byte 0x74,0x1b,0x48,0x81,0xc1,0x0,0x0,0x1,0x0,0xba,0x1,0x80,0x1,0x0,0x49,0x83,0x7c,0x24,0x30,0x1,0x74,0x13,0xba,0x1
    .byte 0x4,0x0,0x0,0xeb,0xc,0x48,0x81,0xc1,0x0,0xb1,0x1,0x0,0xba,0x20,0x0,0x0,0x0,0x49,0x3b,0x4e,0x20,0xf,0x85,0xbd
    .byte 0x6,0x0,0x0,0x48,0x29,0xc2,0xf,0x86,0xb4,0x6,0x0,0x0,0x49,0x3b,0x56,0x28,0xf,0x85,0xaa,0x6,0x0,0x0,0x49,0x8d
    .byte 0x34,0xc,0x31,0xc0,0xf,0x5,0xe9,0xd,0x2,0x0,0x0,0xe8,0xf,0xfd,0xff,0xff,0xe8,0x37,0xfd,0xff,0xff,0x49,0x83,0x7e
    .byte 0x30,0x0,0xf,0x85,0x88,0x6,0x0,0x0,0x49,0x8b,0x44,0x24,0x50,0x49,0x8b,0x54,0x24,0x48,0x48,0x81,0xfa,0x0,0x80,0x1
    .byte 0x0,0xf,0x87,0x71,0x6,0x0,0x0,0x48,0x39,0xd0,0xf,0x83,0x68,0x6,0x0,0x0,0x48,0x29,0xc2,0x49,0x39,0x56,0x28,0xf
    .byte 0x85,0x5b,0x6,0x0,0x0,0x48,0x5,0x0,0x0,0x8,0x0,0x49,0x39,0x46,0x20,0xf,0x85,0x4b,0x6,0x0,0x0,0x49,0x8d,0x34
    .byte 0x4,0xb8,0x1,0x0,0x0,0x0,0xf,0x5,0xe9,0xab,0x1,0x0,0x0,0xe8,0xad,0xfc,0xff,0xff,0xe8,0x4f,0xfd,0xff,0xff,0xe8
    .byte 0x8,0xfd,0xff,0xff,0x49,0x83,0x7e,0x18,0x0,0x74,0x5,0xe8,0xc4,0xfc,0xff,0xff
    .byte 0xe8
    .long tk_intent_sync_all - . - 4
    .byte 0x90,0x90
    .byte 0xe9,0x84,0x1,0x0,0x0,0xe8,0x86,0xfc,0xff,0xff,0x49,0x83,0x7e,0x18,0x0,0xf,0x85,0x4,0x6,0x0,0x0,0xe8,0x7c,0xfe
    .byte 0xff,0xff,0x49,0x81,0x7e,0x30,0x80,0xb0,0x1,0x0,0xf,0x85,0xf1,0x5,0x0,0x0,0x49,0x8d,0xbc,0x24,0x80,0xb0,0x1,0x0
    .byte 0x48,0x8d,0x35,0x5c,0x6,0x0,0x0,0xb9,0x1f,0x0,0x0,0x0,0xf3,0xa6,0xf,0x85,0xd5,0x5,0x0,0x0,0x80,0x3f,0x0,0xf
    .byte 0x85,0xcc,0x5,0x0,0x0,0xe8,0xa3,0xfc,0xff,0xff,0x49,0x8d,0xb4,0x24,0x0,0xb0,0x1,0x0,0x48,0x89,0xfa,0x4d,0x8d,0x94
    .byte 0x24,0x80,0xb0,0x1,0x0,0x45,0x31,0xc0,0xb8,0x9,0x1,0x0,0x0,0xf,0x5,0xe9,0x15,0x1,0x0,0x0,0xe8,0x17,0xfc,0xff
    .byte 0xff,0x49,0x83,0x7e,0x18,0x0,0xf,0x85,0x95,0x5,0x0,0x0,0x49,0x83,0x7e,0x30,0x0,0xf,0x85,0x8a,0x5,0x0,0x0,0xe8
    .byte 0x2,0xfe,0xff,0xff,0xe8,0x5c,0xfc,0xff,0xff,0x49,0x8d,0xb4,0x24,0x0,0xb0,0x1,0x0,0x31,0xd2,0xb8,0x7,0x1,0x0,0x0
    .byte 0xf,0x5,0xe9,0xda,0x0,0x0,0x0,0xe8,0x77,0xfc,0xff,0xff,0xe8,0x7e,0xfc,0xff,0xff,0x49,0x83,0x7e,0x18,0x0,0xf,0x85
    .byte 0x55,0x5,0x0,0x0
    .byte 0xe9
    .long tk_intent_prepare_store_lock - . - 4
    .byte 0x90
    .byte 0x90
    .byte 0x90
    .byte 0x90
    .byte 0x90
    .byte 0x90
    .byte 0x90
    .byte 0x90
    .byte 0x90
    .byte 0x90
    .byte 0x90
    .byte 0x90
    .byte 0x90
    .byte 0x90
    .byte 0x90
    .byte 0x90
    .byte 0x90
    .byte 0x90
    .byte 0x90
    .byte 0x90
    .byte 0x90
    .byte 0x90
    .byte 0x90
    .byte 0x90
    .byte 0xe9,0xc1,0x0,0x0,0x0,0xe8,0x40,0xfc,0xff,0xff,0xe8,0x47,0xfc,0xff,0xff,0x49,0x83,0x7e,0x18,0x0,0xf,0x85,0x1e,0x5
    .byte 0x0,0x0
    .byte 0xe9
    .long tk_intent_prepare_store_drop - . - 4
    .byte 0x90
    .byte 0x90
    .byte 0x90
    .byte 0x90
    .byte 0x90
    .byte 0x90
    .byte 0x90
    .byte 0x90
    .byte 0x90
    .byte 0x90
    .byte 0x90
    .byte 0x90
    .byte 0x90
    .byte 0x90
    .byte 0xe9,0x94,0x0,0x0,0x0,0x49,0x83,0x7f,0x20,0x2,0xf,0x85,0xfb,0x4,0x0,0x0,0xe8,0x9a,0xfb,0xff,0xff,0x49,0x81,0x7e
    .byte 0x20,0x0,0x20,0x0,0x0,0xf,0x85,0xe8,0x4,0x0,0x0,0x49,0x81,0x7e,0x28,0x98,0x0,0x0,0x0,0xf,0x85,0xda,0x4,0x0
    .byte 0x0,0x49,0x83,0x7e,0x30,0x0,0xf,0x85,0xcf,0x4,0x0,0x0
    .byte 0xe9
    .long tk_intent_prepare_metadata - . - 4
    .byte 0x90
    .byte 0x90
    .byte 0x90
    .byte 0x90
    .byte 0x90
    .byte 0x90
    .byte 0x90
    .byte 0x90
    .byte 0x90
    .byte 0x90
    .byte 0x90
    .byte 0x90
    .byte 0x90
    .byte 0x90
    .byte 0x90
    .byte 0x90
    .byte 0x90
    .byte 0x90
    .byte 0x90
    .byte 0x90
    .byte 0x90
    .byte 0x90
    .byte 0x90
    .byte 0x90
    .byte 0x90
    .byte 0x90
    .byte 0x90
    .byte 0x90
    .byte 0x90
    .byte 0x90
    .byte 0xeb,0x38,0xe8,0x49,0xfb,0xff,0xff,0xe8,0xbe,0xfb,0xff,0xff,0x48,0xc7,0x3,0xff,0xff,0xff,0xff,0xb8,0x3,0x0,0x0,0x0
    .byte 0xf,0x5,0xeb,0x1e,0x48,0x85,0xc0,0x78,0x6,0x49,0x89,0x46,0x48,0xeb,0x13,0x48,0xf7,0xd8,0x48,0x3d,0xff,0xf,0x0,0x0
    .byte 0xf,0x87,0x76,0x4,0x0,0x0,0x49,0x89,0x46,0x50,0x49,0x8b,0x46,0x8,0x49,0x89,0x46,0x40,0xe9,0x7e,0xef,0xff,0xff,0x49
    .byte 0x8b,0x5e,0x18,0x48,0x83,0xfb,0x1,0xf,0x82,0x57,0x4,0x0,0x0,0x48,0x83,0xfb,0x2,0xf,0x87,0x4d,0x4,0x0,0x0,0x49
    .byte 0x83,0x7c,0xdd,0xf8,0xff,0xf,0x85,0x41,0x4,0x0,0x0,0xc3,0x49,0x8b,0x4e,0x18,0x48,0x83,0xf9,0x1,0xf,0x82,0x32,0x4
    .byte 0x0,0x0,0x48,0x83,0xf9,0x3,0xf,0x87,0x28,0x4,0x0,0x0,0x49,0x8b,0x7c,0xcd,0xf8,0x48,0x85,0xff,0xf,0x88,0x1a,0x4
    .byte 0x0,0x0,0xc3,0x49,0x81,0x7e,0x20,0x0,0x0,0x1,0x0,0xf,0x85,0xb,0x4,0x0,0x0,0x49,0x8b,0x4e,0x28,0x48,0x85,0xc9
    .byte 0xf,0x84,0xfe,0x3,0x0,0x0,0x48,0x81,0xf9,0xd0,0xff,0xf,0x0,0xf,0x87,0xf1,0x3,0x0,0x0,0x49,0x8d,0xbc,0x24,0x0
    .byte 0x0,0x1,0x0,0x31,0xc0,0xf2,0xae,0xf,0x84,0xdf,0x3,0x0,0x0,0x80,0x3f,0x0,0xf,0x85,0xd6,0x3,0x0,0x0,0xc3,0xe8
    .byte 0xb7,0xff,0xff,0xff,0x49,0x83,0x7e,0x28,0xf,0xf,0x85,0xc5,0x3,0x0,0x0,0x48,0x8d,0x35,0xa4,0x4,0x0,0x0,0x49,0x8d
    .byte 0xbc,0x24,0x0,0x0,0x1,0x0,0xb9,0xf,0x0,0x0,0x0,0xf3,0xa6,0xf,0x85,0xa9,0x3,0x0,0x0,0xc3,0x49,0x8b,0x4e,0x30
    .byte 0x48,0x83,0xf9,0x1,0xf,0x82,0x9a,0x3,0x0,0x0,0x48,0x83,0xf9,0x2,0xf,0x87,0x90,0x3,0x0,0x0,0x49,0x8b,0x7c,0xcd
    .byte 0xf8,0x48,0x85,0xff,0xf,0x88,0x82,0x3,0x0,0x0,0xc3,0xe8,0x17,0xff,0xff,0xff,0xe8,0x5e,0xff,0xff,0xff,0x49,0x83,0x7e
    .byte 0x30,0x0,0xf,0x85,0x6c,0x3,0x0,0x0,0x49,0x83,0x7e,0x28,0x1,0xf,0x85,0x61,0x3,0x0,0x0,0x41,0x80,0xbc,0x24,0x0
    .byte 0x0,0x1,0x0,0x2f,0xf,0x85,0x52,0x3,0x0,0x0,0xbf,0x9c,0xff,0xff,0xff,0xba,0x0,0x0,0xb,0x0,0xe9,0xad,0x0,0x0
    .byte 0x0,0xe8,0xd9,0xfe,0xff,0xff,0x49,0x83,0x7c,0x24,0x8,0xe,0x74,0x54,0x49,0x83,0x7c,0x24,0x8,0x2,0xf,0x85,0x2a,0x3
    .byte 0x0,0x0,0xe8,0xc,0xff,0xff,0xff,0x49,0x8b,0x54,0x24,0x60,0x49,0x3b,0x97,0x28,0x1,0x0,0x1,0xf,0x87,0x13,0x3,0x0
    .byte 0x0,0x49,0x8b,0x4e,0x28,0x48,0x29,0xca,0xf,0x82,0x6,0x3,0x0,0x0,0x48,0x83,0xfa,0x30,0xf,0x82,0xfc,0x2,0x0,0x0
    .byte 0x49,0x8d,0xb4,0x17,0x0,0x0,0x11,0x1,0x49,0x8d,0xbc,0x24,0x0,0x0,0x1,0x0,0xf3,0xa6,0xf,0x85,0xe4,0x2,0x0,0x0
    .byte 0xeb,0x5,0xe8,0x8,0xff,0xff,0xff,0xe8,0x30,0xff,0xff,0xff,0xba,0x0,0x0,0xb,0x0,0xeb,0x3b,0xe8,0x67,0xfe,0xff,0xff
    .byte 0xe8,0xae,0xfe,0xff,0xff,0x49,0x83,0x7e,0x28,0x1f,0xf,0x85,0xbc,0x2,0x0,0x0,0x48,0x8d,0x35,0x2f,0x3,0x0,0x0,0x49
    .byte 0x8d,0xbc,0x24,0x0,0x0,0x1,0x0,0xb9,0x1f,0x0,0x0,0x0,0xf3,0xa6,0xf,0x85,0xa0,0x2,0x0,0x0,0xe8,0xf3,0xfe,0xff
    .byte 0xff,0xba,0x0,0x8,0xa,0x0,0x49,0x8d,0xb4,0x24,0x0,0x0,0x1,0x0,0x45,0x31,0xd2,0xb8,0x1,0x1,0x0,0x0,0xf,0x5
    .byte 0x48,0x85,0xc0,0xf,0x88,0xf6,0xfd,0xff,0xff,0x49,0x89,0x44,0xdd,0xf8,0x49,0x89,0x5e,0x48,0xe9,0xfb,0xfd,0xff,0xff,0xe8
    .byte 0x28,0xfe,0xff,0xff,0x49,0x81,0x7e,0x20,0x0,0x20,0x0,0x0,0xf,0x85,0x5a,0x2,0x0,0x0,0x49,0x81,0x7e,0x28,0x98,0x0
    .byte 0x0,0x0,0xf,0x85,0x4c,0x2,0x0,0x0,0x49,0x83,0x7e,0x30,0x0,0xf,0x85,0x41,0x2,0x0,0x0
    .byte 0xe9
    .long tk_intent_prepare_metadata - . - 4
    .byte 0x90
    .byte 0x90
    .byte 0x90
    .byte 0x90
    .byte 0x90
    .byte 0x90
    .byte 0x90
    .byte 0x90
    .byte 0x90
    .byte 0x90
    .byte 0x90
    .byte 0x90
    .byte 0x90
    .byte 0x90
    .byte 0x90
    .byte 0x90
    .byte 0x90
    .byte 0x90
    .byte 0x90
    .byte 0x90
    .byte 0x90
    .byte 0x90
    .byte 0x90
    .byte 0x90
    .byte 0x90
    .byte 0x90
    .byte 0x90
    .byte 0x90
    .byte 0x90
    .byte 0x90
    .byte 0x90
    .byte 0x90
    .byte 0x90
    .byte 0x90
    .byte 0xe9,0xa3,0xfd,0xff,0xff,0xe8,0x3b,0xfe,0xff,0xff,0xe8,0xcb,0xfd,0xff,0xff,0x49,0x81,0x7e,0x30,0xc0,0x1,0x0,0x0,0xf
    .byte 0x85,0xfd,0x1,0x0,0x0,0x49,0x8d,0xb4,0x24,0x0,0x0,0x1,0x0,0xba,0xc0,0x1,0x0,0x0,0xb8,0x2,0x1,0x0,0x0,0xf
    .byte 0x5,0x48,0x85,0xc0,0xf,0x88,0x5b,0xfd,0xff,0xff,0xe9,0x69,0xfd,0xff,0xff,0x49,0x8b,0x46,0x20,0x49,0xb,0x46,0x28,0x49
    .byte 0xb,0x46,0x30,0xf,0x85,0xc9,0x1,0x0,0x0,0xc3,0xe8,0xe8,0xff,0xff,0xff,0xe8,0x7e,0xfd,0xff,0xff
    .byte 0xe8
    .long tk_intent_sync_all - . - 4
    .byte 0x90,0x90
    .byte 0x48,0x85,0xc0,0xf,0x88,0x29,0xfd,0xff,0xff,0xe9,0x37,0xfd,0xff,0xff,0xe8,0xc9,0xff,0xff,0xff,0xe8,0x5f,0xfd,0xff,0xff
    .byte 0x49,0xc7,0x44,0xcd,0xf8,0xff,0xff,0xff,0xff,0xb8,0x3,0x0,0x0,0x0,0xf,0x5,0xe9,0x18,0xfd,0xff,0xff,0xe8,0x45,0xfd
    .byte 0xff,0xff,0x48,0x83,0xf9,0x2,0xf,0x87,0x7b,0x1,0x0,0x0,0x49,0x8b,0x46,0x20,0x49,0xb,0x46,0x28,0xf,0x85,0x6d,0x1
    .byte 0x0,0x0,0x49,0x83,0x7e,0x30,0x3,0xf,0x85,0x62,0x1,0x0,0x0,0x49,0x83,0x7d,0x10,0xff,0xf,0x85,0x57,0x1,0x0,0x0
    .byte 0x49,0x89,0x7d,0x10,0x49,0xc7,0x44,0xcd,0xf8,0xff,0xff,0xff,0xff,0x49,0xc7,0x46,0x48,0x3,0x0,0x0,0x0,0xe9,0xcb,0xfc
    .byte 0xff,0xff,0x41,0x89,0x47,0x48,0x49,0x83,0x7f,0x20,0x0,0xf,0x85,0x2e,0x1,0x0,0x0,0x49,0x83,0xbf,0xb8,0x0,0x0,0x0
    .byte 0x0,0xf,0x85,0x20,0x1,0x0,0x0,0x49,0x83,0xbf,0x90,0x0,0x0,0x0,0xff,0xf,0x85,0x12,0x1,0x0,0x0,0x49,0x83,0xbf
    .byte 0xa8,0x0,0x0,0x0,0xff,0xf,0x85,0x4,0x1,0x0,0x0,0x49,0x83,0xbf,0xb0,0x0,0x0,0x0,0xff,0xf,0x85,0xf6,0x0,0x0
    .byte 0x0,0x49,0x83,0x7c,0x24,0x8,0x0,0xf,0x85,0xea,0x0,0x0,0x0,0x49,0x83,0x7c,0x24,0x48,0x0,0xf,0x85,0xde,0x0,0x0
    .byte 0x0,0x49,0x8b,0x44,0x24,0x40,0x48,0x83,0xe0,0xf9,0xf,0x85,0xcf,0x0,0x0,0x0,0xbb,0x2,0x0,0x0,0x0,0xbd,0x78,0x0
    .byte 0x0,0x0,0xba,0x98,0x0,0x0,0x0,0xe8,0x36,0x0,0x0,0x0,0xbb,0x4,0x0,0x0,0x0,0xbd,0x88,0x0,0x0,0x0,0xba,0xa0
    .byte 0x0,0x0,0x0,0xe8,0x22,0x0,0x0,0x0,0x41,0x83,0x7f,0x48,0x40,0x74,0x12,0x41,0x83,0x7f,0x48,0xff,0x74,0xb,0x41,0x83
    .byte 0x7f,0x48,0xfe,0xf,0x85,0x8e,0x0,0x0,0x0,0x41,0x8b,0x47,0x48,0xe9,0xa0,0xef,0xff,0xff,0x49,0x8b,0x44,0x24,0x40,0x48
    .byte 0x21,0xd8,0x48,0x85,0xc0,0x74,0xf,0x49,0x83,0x3c,0x2c,0x0,0x74,0x71,0x49,0x83,0x3c,0x17,0x0,0x7c,0x6a,0xc3,0x49,0x83
    .byte 0x3c,0x2c,0x0,0x75,0x62,0x49,0x83,0x3c,0x17,0xff,0x75,0x5b,0xc3,0x48,0x85,0xd2,0x74,0x1e,0x31,0xff,0x31,0xc0,0xf,0x5
    .byte 0x48,0x83,0xf8,0xfc,0x74,0xf4,0x48,0x85,0xc0,0x78,0x4b,0x74,0x11,0x45,0x31,0xc0,0x48,0x1,0xc6,0x48,0x29,0xc2,0x75,0xe2
    .byte 0xb8,0x1,0x0,0x0,0x0,0xc3,0x45,0x85,0xc0,0x74,0x33,0x31,0xc0,0xc3,0x48,0x85,0xd2,0x74,0x1f,0xbf,0x1,0x0,0x0,0x0
    .byte 0xb8,0x1,0x0,0x0,0x0,0xf,0x5,0x48,0x83,0xf8,0xfc,0x74,0xee,0x48,0x85,0xc0,0x7e,0x14,0x48,0x1,0xc6,0x48,0x29,0xc2
    .byte 0x75,0xe1,0xc3,0x31,0xed,0xeb,0xc
    .byte 0xe9
    .long tk_intent_contract_failure - . - 4
    .byte 0x90
    .byte 0x90
    .byte 0xe9
    .long tk_intent_resource_failure - . - 4
    .byte 0xbb,0x6,0x0,0x0,0x0,0x49,0x8b,0xbc,0xdf,0x80,0x0,0x0,0x0,0x48,0x85,0xff,0x78,0x13,0x49,0xc7,0x84,0xdf,0x80,0x0
    .byte 0x0,0x0,0xff,0xff,0xff,0xff,0xb8,0x3,0x0,0x0,0x0,0xf,0x5,0xff,0xcb,0x83,0xfb,0x2,0x7d,0xd9,0xbb,0x5,0x0,0x0
    .byte 0x0,0x49,0x8b,0xbc,0xdf,0xc0,0x0,0x0,0x0,0x48,0x85,0xff,0x78,0x13,0x49,0xc7,0x84,0xdf,0xc0,0x0,0x0,0x0,0xff,0xff
    .byte 0xff,0xff,0xb8,0x3,0x0,0x0,0x0,0xf,0x5,0xff,0xcb,0x79,0xdc,0x89,0xef,0xeb,0xc,0xbf,0x40,0x0,0x0,0x0,0xeb,0x5
    .byte 0xbf,0x4a,0x0,0x0,0x0,0xb8,0x3c,0x0,0x0,0x0,0xf,0x5,0xf,0xb,0x2e,0x72,0x65,0x71,0x75,0x65,0x73,0x74,0x2d,0x72
    .byte 0x65,0x73,0x75,0x6c,0x74,0x73,0x2d,0x76,0x32,0x2d,0x61,0x6e,0x63,0x68,0x6f,0x72,0x2e,0x6a,0x73,0x6f,0x6e,0x2e,0x72,0x65
    .byte 0x71,0x75,0x65,0x73,0x74,0x2d,0x72,0x65,0x73,0x75,0x6c,0x74,0x73,0x2d,0x76,0x32,0x2e,0x6a,0x73,0x6f,0x6e,0x2f,0x64,0x65
    .byte 0x76,0x2f,0x75,0x72,0x61,0x6e,0x64,0x6f,0x6d,0x0,0x2e,0x72,0x65,0x73,0x75,0x6c,0x74,0x2d,0x61,0x6e,0x63,0x68,0x6f,0x72
    .byte 0x2d,0x72,0x65,0x71,0x75,0x65,0x73,0x74,0x2d,0x72,0x65,0x73,0x75,0x6c,0x74,0x73,0x2d,0x76,0x32,0x61,0x72,0x63,0x68,0x69
    .byte 0x76,0x65,0x72,0x65,0x71,0x75,0x65,0x73,0x74,0x2d,0x72,0x65,0x73,0x75,0x6c,0x74,0x73
.equ tk_intent_prepare_dispatch, tk_intent_prepare_prefix + 552
.equ tk_intent_prepare_ack, tk_intent_prepare_prefix + 4765
.equ tk_intent_prepare_errno, tk_intent_prepare_prefix + 4746
.equ tk_intent_prepare_directory, tk_intent_prepare_prefix + 1359
.equ tk_intent_prepare_store, tk_intent_prepare_prefix + 611

# Retained prefix: 205cd92fc5f457212abf5286b5be403aa232adf5de9f5e97fc3fe88a3a98e5a6
tk_intent_record_prefix:
    .byte 0x7f,0x45,0x4c,0x46,0x2,0x1,0x1,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x2,0x0,0x3e,0x0,0x1,0x0,0x0,0x0
    .byte 0xb0,0x0,0x40,0x0,0x0,0x0,0x0,0x0,0x40,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0
    .byte 0x0,0x0,0x0,0x0,0x40,0x0,0x38,0x0,0x2,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x1,0x0,0x0,0x0,0x5,0x0,0x0,0x0
    .byte 0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x40,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x40,0x0,0x0,0x0,0x0,0x0
    .byte 0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x10,0x0,0x0,0x0,0x0,0x0,0x0
    .byte 0x51,0xe5,0x74,0x64,0x6,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0
    .byte 0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0
    .byte 0x10,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0xfc,0x48,0x83,0x3c,0x24,0x2,0xf,0x85,0xa3,0x9,0x0,0x0,0x48,0x8b,0x5c,0x24
    .byte 0x10,0x31,0xff,0xbe,0x0,0x10,0x0,0x1,0xba,0x3,0x0,0x0,0x0,0x41,0xba,0x22,0x0,0x0,0x0,0x49,0xc7,0xc0,0xff,0xff
    .byte 0xff,0xff,0x45,0x31,0xc9,0xb8,0x9,0x0,0x0,0x0,0xf,0x5,0x48,0x3d,0x1,0xf0,0xff,0xff,0xf,0x83,0x76,0x9,0x0,0x0
    .byte 0x49,0x89,0xc7,0x49,0xc7,0x87,0x80,0x0,0x0,0x0,0xff,0xff,0xff,0xff,0x49,0xc7,0x87,0x88,0x0,0x0,0x0,0xff,0xff,0xff
    .byte 0xff,0x49,0xc7,0x87,0x90,0x0,0x0,0x0,0xff,0xff,0xff,0xff,0x49,0x8d,0xbf,0x0,0x0,0x0,0x1,0xbe,0x0,0x10,0x0,0x0
    .byte 0x31,0xd2,0xb8,0xa,0x0,0x0,0x0,0xf,0x5,0x48,0x85,0xc0,0xf,0x85,0xfb,0x8,0x0,0x0,0xbf,0x9c,0xff,0xff,0xff,0x48
    .byte 0x89,0xde,0xba,0x0,0x0,0xb,0x0,0x45,0x31,0xd2,0xb8,0x1,0x1,0x0,0x0,0xf,0x5,0x48,0x85,0xc0,0xf,0x88,0xdb,0x8
    .byte 0x0,0x0,0x49,0x89,0x87,0x80,0x0,0x0,0x0,0x4d,0x8d,0xa7,0x0,0x0,0x20,0x0,0x4d,0x8d,0xaf,0x0,0x0,0xa0,0x0,0x49
    .byte 0x8d,0xbf,0x0,0x10,0x0,0x0,0xbe,0x0,0x0,0x10,0x0,0xba,0x3,0x0,0x0,0x0,0xb8,0xa,0x0,0x0,0x0,0xf,0x5,0x48
    .byte 0x85,0xc0,0xf,0x85,0xa5,0x8,0x0,0x0,0x49,0x8d,0x77,0x18,0xba,0x8,0x0,0x0,0x0,0x41,0xb8,0x1,0x0,0x0,0x0,0xe8
    .byte 0x30,0x8,0x0,0x0,0x85,0xc0,0xf,0x84,0x7e,0x8,0x0,0x0,0x49,0x8b,0x57,0x18,0x48,0x81,0xfa,0x0,0x0,0x10,0x0,0xf
    .byte 0x87,0x78,0x8,0x0,0x0,0x49,0x8d,0xb7,0x0,0x10,0x0,0x0,0x45,0x31,0xc0,0xe8,0x8,0x8,0x0,0x0,0x49,0x8d,0xbf,0x0
    .byte 0x10,0x0,0x0,0xbe,0x0,0x0,0x10,0x0,0xba,0x1,0x0,0x0,0x0,0xb8,0xa,0x0,0x0,0x0,0xf,0x5,0x48,0x85,0xc0,0xf
    .byte 0x85,0x48,0x8,0x0,0x0,0x49,0x8d,0xbf,0x0,0x10,0x0,0x0,0x49,0x8b,0x77,0x18,0x49,0x8d,0x97,0x0,0x20,0x10,0x0,0xb9
    .byte 0x0,0x0,0x4,0x0,0x4d,0x89,0xe0,0x41,0xb9,0x0,0x0,0x80,0x0,0xe8
    .long tk_intent_image_record_io - . - 4
    .byte 0x83,0xf8,0xf0,0xf,0x85,0x3d,0x7,0x0,0x0,0x4d,0x8d,0xb4,0x24,0x0,0x1,0x0,0x0,0x48,0xb8,0x48,0x52,0x46,0x53,0x41
    .byte 0x30,0x30,0x31,0x49,0x39,0x6,0xf,0x85,0xf8,0x7,0x0,0x0,0x49,0x8b,0x47,0x8,0x48,0xff,0xc0,0xf,0x84,0xeb,0x7,0x0
    .byte 0x0,0x49,0x39,0x46,0x8,0xf,0x85,0xe1,0x7,0x0,0x0,0x49,0x39,0x44,0x24,0x10,0xf,0x85,0xd6,0x7,0x0,0x0,0x49,0x89
    .byte 0x47,0x8,0x49,0x8b,0x46,0x40,0x49,0xb,0x46,0x48,0x49,0xb,0x46,0x50,0x49,0xb,0x46,0x58,0xf,0x85,0xbc,0x7,0x0,0x0
    .byte 0x49,0x83,0x7e,0x10,0x64,0x74,0x73,0xe8,0xfc,0x1,0x0,0x0,0x49,0x83,0x7e,0x38,0x0,0xf,0x85,0xa5,0x7,0x0,0x0,0x49
    .byte 0x8b,0x46,0x10,0x48,0x83,0xf8,0x1,0xf,0x84,0xf6,0x2,0x0,0x0,0x48,0x83,0xf8,0x2,0xf,0x84,0x44,0x3,0x0,0x0,0x48
    .byte 0x83,0xf8,0x3,0xf,0x84,0x22,0x4,0x0,0x0,0x48,0x83,0xf8,0x4,0xf,0x84,0x8d,0x4,0x0,0x0,0x48,0x83,0xf8,0x5,0xf
    .byte 0x84,0x8,0x5,0x0,0x0,0x48,0x83,0xf8,0x6,0xf,0x84,0xa6,0x5,0x0,0x0,0x48,0x83,0xf8,0x7,0xf,0x84,0xb9,0x5,0x0
    .byte 0x0,0x48,0x83,0xf8,0x8,0xf,0x84,0xc9,0x5,0x0,0x0,0x48,0x83,0xf8,0x9,0xf,0x84,0x10,0x6,0x0,0x0,0xe9,0x42,0x7
    .byte 0x0,0x0,0x49,0x83,0x7e,0x18,0x0,0xf,0x85,0x37,0x7,0x0,0x0,0x49,0x81,0x7e,0x20,0x0,0x0,0x21,0x0,0xf,0x85,0x29
    .byte 0x7,0x0,0x0,0x49,0x83,0x7e,0x28,0x5d,0xf,0x82,0x1e,0x7,0x0,0x0,0x49,0x81,0x7e,0x28,0x5d,0x80,0x1,0x0,0xf,0x87
    .byte 0x10,0x7,0x0,0x0,0x49,0x81,0x7e,0x30,0x0,0x0,0x31,0x0,0xf,0x85,0x2,0x7,0x0,0x0,0x49,0x81,0x7e,0x38,0x0,0x0
    .byte 0x4,0x0,0xf,0x85,0xf4,0x6,0x0,0x0,0x49,0x8d,0xbc,0x24,0x0,0x0,0x21,0x0,0x49,0x8b,0xb4,0x24,0x28,0x1,0x0,0x0
    .byte 0x49,0x8d,0x94,0x24,0x0,0x0,0x31,0x0,0xb9,0x0,0x0,0x4,0x0,0x4d,0x89,0xe8,0x41,0xb9,0x0,0x0,0x40,0x0,0xe8
    .long tk_intent_image_record_validation - . - 4
    .byte 0x83,0xf8,0xf0,0xf,0x85,0xff,0x0,0x0,0x0,0x4d,0x8d,0xb5,0x0,0x1,0x0,0x0,0x48,0xb8,0x48,0x52,0x56,0x4c,0x41,0x30
    .byte 0x30,0x31,0x49,0x39,0x6,0xf,0x85,0xa6,0x6,0x0,0x0,0x49,0x8b,0x47,0x10,0x48,0xff,0xc0,0xf,0x84,0x99,0x6,0x0,0x0
    .byte 0x49,0x39,0x46,0x8,0xf,0x85,0x8f,0x6,0x0,0x0,0x49,0x39,0x45,0x10,0xf,0x85,0x85,0x6,0x0,0x0,0x49,0x89,0x47,0x10
    .byte 0x49,0x8b,0x46,0x18,0x49,0xb,0x46,0x40,0x49,0xb,0x46,0x48,0x49,0xb,0x46,0x50,0x49,0xb,0x46,0x58,0xf,0x85,0x67,0x6
    .byte 0x0,0x0,0x49,0x81,0x7e,0x20,0x0,0x0,0x11,0x0,0xf,0x85,0x59,0x6,0x0,0x0,0x49,0x83,0x7e,0x28,0x18,0xf,0x82,0x4e
    .byte 0x6,0x0,0x0,0x49,0x81,0x7e,0x28,0x18,0x80,0x1,0x0,0xf,0x87,0x40,0x6,0x0,0x0,0x49,0x81,0x7e,0x30,0x0,0x0,0x21
    .byte 0x0,0xf,0x85,0x32,0x6,0x0,0x0,0x49,0x81,0x7e,0x38,0x0,0x0,0x10,0x0,0xf,0x85,0x24,0x6,0x0,0x0,0x49,0x8d,0xbd
    .byte 0x0,0x0,0x11,0x0,0x49,0x8b,0x76,0x28,0x49,0x8d,0x95,0x0,0x0,0x21,0x0,0xb9,0x0,0x0,0x10,0x0,0x41,0xb9,0x0,0x0
    .byte 0x10,0x0,0x49,0x83,0x7e,0x10,0x1,0x74,0x19,0x49,0x83,0x7e,0x10,0x2,0xf,0x85,0xf5,0x5,0x0,0x0,0x4d,0x8d,0x87,0x0
    .byte 0x0,0xf0,0x0,0xe8
    .long tk_intent_image_binary_codec - . - 4
    .byte 0xeb,0xc,0x4d,0x8d,0x87,0x0,0x0,0xe0,0x0,0xe8
    .long tk_intent_image_storage_json - . - 4
    .byte 0x49,0x89,0x85,0x48,0x1,0x0,0x0,0x49,0x8b,0x85,0x8,0x1,0x0,0x0,0x49,0x89,0x85,0x40,0x1,0x0,0x0,0xe9,0xcd,0xfe
    .byte 0xff,0xff,0x49,0x89,0x84,0x24,0x48,0x1,0x0,0x0,0xe9,0xc9,0x4,0x0,0x0,0x49,0x83,0x7f,0x18,0x75,0xf,0x82,0xa9,0x5
    .byte 0x0,0x0,0x49,0x8d,0xb7,0x30,0x10,0x0,0x0,0x49,0x8d,0xbc,0x24,0x0,0x10,0x0,0x0,0xb9,0x45,0x0,0x0,0x0,0xf3,0xa6
    .byte 0xf,0x85,0x8d,0x5,0x0,0x0,0x41,0x80,0xbc,0x24,0x45,0x10,0x0,0x0,0x0,0xf,0x85,0x7e,0x5,0x0,0x0,0x41,0x81,0xbc
    .byte 0x24,0x40,0x10,0x0,0x0,0x2e,0x6a,0x73,0x6f,0xf,0x85,0x6c,0x5,0x0,0x0,0x41,0x80,0xbc,0x24,0x44,0x10,0x0,0x0,0x6e
    .byte 0xf,0x85,0x5d,0x5,0x0,0x0,0x31,0xc9,0x41,0x8a,0x84,0xc,0x0,0x10,0x0,0x0,0x3c,0x30,0xf,0x82,0x4b,0x5,0x0,0x0
    .byte 0x3c,0x39,0x76,0x10,0x3c,0x61,0xf,0x82,0x3f,0x5,0x0,0x0,0x3c,0x66,0xf,0x87,0x37,0x5,0x0,0x0,0x41,0x3a,0x84,0xc
    .byte 0x81,0x10,0x0,0x0,0xf,0x85,0x29,0x5,0x0,0x0,0x41,0x3a,0x84,0xc,0xc2,0x10,0x0,0x0,0xf,0x85,0x1b,0x5,0x0,0x0
    .byte 0xff,0xc1,0x83,0xf9,0x40,0x75,0xb9,0x41,0x80,0xbc,0x24,0x80,0x10,0x0,0x0,0x2e,0xf,0x85,0x5,0x5,0x0,0x0,0x41,0x80
    .byte 0xbc,0x24,0xc1,0x10,0x0,0x0,0x2d,0xf,0x85,0xf6,0x4,0x0,0x0,0x41,0x81,0xbc,0x24,0x2,0x11,0x0,0x0,0x2e,0x74,0x6d
    .byte 0x70,0xf,0x85,0xe4,0x4,0x0,0x0,0x41,0x80,0xbc,0x24,0x6,0x11,0x0,0x0,0x0,0xf,0x85,0xd5,0x4,0x0,0x0,0xc3,0x49
    .byte 0x8b,0x4e,0x18,0x48,0x83,0xf9,0x2,0xf,0x87,0xc6,0x4,0x0,0x0,0x49,0x8b,0xbc,0xcf,0x80,0x0,0x0,0x0,0x48,0x85,0xff
    .byte 0xf,0x88,0xb5,0x4,0x0,0x0,0xc3,0x49,0x8b,0x46,0x20,0x49,0xb,0x46,0x28,0x49,0xb,0x46,0x30,0xf,0x85,0xa2,0x4,0x0
    .byte 0x0,0xc3,0xe8,0xc8,0xff,0xff,0xff,0x49,0x81,0x7e,0x20,0x0,0x20,0x0,0x0,0xf,0x85,0x8e,0x4,0x0,0x0,0x49,0x81,0x7e
    .byte 0x28,0x98,0x0,0x0,0x0,0xf,0x85,0x80,0x4,0x0,0x0,0x49,0x83,0x7e,0x30,0x0,0xf,0x85,0x75,0x4,0x0,0x0
    .byte 0xe9
    .long tk_intent_record_metadata - . - 4
    .byte 0x90
    .byte 0x90
    .byte 0x90
    .byte 0x90
    .byte 0x90
    .byte 0x90
    .byte 0x90
    .byte 0x90
    .byte 0x90
    .byte 0x90
    .byte 0x90
    .byte 0x90
    .byte 0x90
    .byte 0x90
    .byte 0x90
    .byte 0x90
    .byte 0x90
    .byte 0x90
    .byte 0x90
    .byte 0x90
    .byte 0x90
    .byte 0x90
    .byte 0x90
    .byte 0x90
    .byte 0x90
    .byte 0x90
    .byte 0x90
    .byte 0x90
    .byte 0x90
    .byte 0x90
    .byte 0x90
    .byte 0x90
    .byte 0x90
    .byte 0x90
    .byte 0xe9,0x5e,0x3,0x0,0x0,0x49,0x8b,0x4e,0x18,0x48,0x83,0xf9,0x1,0xf,0x82,0x3b,0x4,0x0,0x0,0x48,0x83,0xf9,0x2,0xf
    .byte 0x87,0x31,0x4,0x0,0x0,0x49,0x83,0xbc,0xcf,0x80,0x0,0x0,0x0,0xff,0xf,0x85,0x22,0x4,0x0,0x0,0x49,0x8b,0x46,0x20
    .byte 0x48,0x3d,0x0,0x10,0x0,0x0,0x74,0x1c,0x48,0x3d,0x80,0x10,0x0,0x0,0xf,0x85,0xa,0x4,0x0,0x0,0x49,0x81,0x7e,0x28
    .byte 0x86,0x0,0x0,0x0,0xf,0x85,0xfc,0x3,0x0,0x0,0xeb,0x16,0x49,0x83,0x7e,0x28,0x45,0xf,0x85,0xef,0x3,0x0,0x0,0x49
    .byte 0x83,0x7e,0x30,0x0,0xf,0x85,0xe4,0x3,0x0,0x0,0x49,0x8d,0x34,0x4,0xba,0x0,0x8,0xa,0x0,0x45,0x31,0xd2,0x49,0x83
    .byte 0x7e,0x30,0x0,0x74,0x2c,0x49,0x83,0x7e,0x30,0x1,0xf,0x85,0xc6,0x3,0x0,0x0,0x48,0x83,0xf9,0x1,0xf,0x85,0xbc,0x3
    .byte 0x0,0x0,0x48,0x3d,0x80,0x10,0x0,0x0,0xf,0x85,0xb0,0x3,0x0,0x0,0xba,0xc1,0x0,0xa,0x0,0x41,0xba,0x80,0x1,0x0
    .byte 0x0,0x49,0x8b,0xbf,0x80,0x0,0x0,0x0,0xb8,0x1,0x1,0x0,0x0,0xf,0x5,0x48,0x85,0xc0,0xf,0x88,0x90,0x2,0x0,0x0
    .byte 0x48,0x3d,0xff,0xff,0xff,0x7f,0xf,0x87,0x82,0x3,0x0,0x0,0x49,0x8b,0x4e,0x18,0x49,0x89,0x84,0xcf,0x80,0x0,0x0,0x0
    .byte 0x49,0x8b,0x46,0x30,0x49,0x89,0x84,0xcf,0xa0,0x0,0x0,0x0,0x49,0x89,0x4e,0x48,0xe9,0x76,0x2,0x0,0x0,0xe8,0x88,0xfe
    .byte 0xff,0xff,0x48,0x83,0xf9,0x1,0xf,0x85,0x52,0x3,0x0,0x0,0x49,0x83,0xbf,0xa8,0x0,0x0,0x0,0x0,0xf,0x85,0x44,0x3
    .byte 0x0,0x0,0x49,0x83,0x7e,0x30,0x0,0xf,0x85,0x39,0x3,0x0,0x0,0x49,0x8b,0x44,0x24,0x40,0x48,0x3d,0x0,0x80,0x1,0x0
    .byte 0xf,0x87,0x28,0x3,0x0,0x0,0x48,0x8d,0xb0,0x0,0x0,0x1,0x0,0x49,0x3b,0x76,0x20,0xf,0x85,0x17,0x3,0x0,0x0,0xba
    .byte 0x1,0x80,0x1,0x0,0x48,0x29,0xc2,0x49,0x3b,0x56,0x28,0xf,0x85,0x5,0x3,0x0,0x0,0x4c,0x1,0xe6,0x31,0xc0,0xf,0x5
    .byte 0x48,0x85,0xc0,0xf,0x88,0xf7,0x1,0x0,0x0,0x49,0x89,0x46,0x48,0xe9,0x1,0x2,0x0,0x0,0xe8,0x13,0xfe,0xff,0xff,0x48
    .byte 0x83,0xf9,0x1,0xf,0x85,0xdd,0x2,0x0,0x0,0x49,0x83,0xbf,0xa8,0x0,0x0,0x0,0x1,0xf,0x85,0xcf,0x2,0x0,0x0,0x49
    .byte 0x83,0x7e,0x30,0x0,0xf,0x85,0xc4,0x2,0x0,0x0,0x49,0x8b,0x54,0x24,0x38,0x48,0x81,0xfa,0x0,0x80,0x1,0x0,0xf,0x87
    .byte 0xb2,0x2,0x0,0x0,0x49,0x8b,0x84,0x24,0x80,0x0,0x0,0x0,0x48,0x39,0xd0,0xf,0x83,0xa1,0x2,0x0,0x0,0x48,0x8d,0xb0
    .byte 0x0,0x0,0xc,0x0,0x49,0x3b,0x76,0x20,0xf,0x85,0x90,0x2,0x0,0x0,0x48,0x29,0xc2,0x49,0x3b,0x56,0x28,0xf,0x85,0x83
    .byte 0x2,0x0,0x0,0x4c,0x1,0xe6,0xb8,0x1,0x0,0x0,0x0,0xf,0x5,0x48,0x85,0xc0,0xf,0x88,0x72,0x1,0x0,0x0,0x49,0x89
    .byte 0x46,0x48,0xe9,0x7c,0x1,0x0,0x0,0xe8,0xae,0xfd,0xff,0xff,0xe8,0x89,0xfd,0xff,0xff,0x48,0x83,0xf9,0x1,0xf,0x87,0x53
    .byte 0x2,0x0,0x0,0x48,0x85,0xc9,0x74,0xe,0x49,0x83,0xbf,0xa8,0x0,0x0,0x0,0x1,0xf,0x85,0x40,0x2,0x0,0x0
    .byte 0xe8
    .long tk_intent_sync_all - . - 4
    .byte 0x90,0x90
    .byte 0x48,0x85,0xc0,0xf,0x88,0x32,0x1,0x0,0x0,0xe9,0x40,0x1,0x0,0x0,0x49,0x83,0x7e,0x18,0x0,0xf,0x85,0x20,0x2,0x0
    .byte 0x0,0x49,0x81,0x7e,0x20,0x80,0x10,0x0,0x0,0xf,0x85,0x12,0x2,0x0,0x0,0x49,0x81,0x7e,0x28,0x86,0x0,0x0,0x0,0xf
    .byte 0x85,0x4,0x2,0x0,0x0,0x49,0x81,0x7e,0x30,0x0,0x10,0x0,0x0,0xf,0x85,0xf6,0x1,0x0,0x0,0x49,0x83,0xbf,0x88,0x0
    .byte 0x0,0x0,0xff,0xf,0x85,0xe8,0x1,0x0,0x0,0x49,0x83,0xbf,0x90,0x0,0x0,0x0,0xff,0xf,0x85,0xda,0x1,0x0,0x0,0x49
    .byte 0x8b,0xbf,0x80,0x0,0x0,0x0,0x48,0x89,0xfa,0x49,0x8d,0xb4,0x24,0x80,0x10,0x0,0x0,0x4d,0x8d,0x94,0x24,0x0,0x10,0x0
    .byte 0x0,0xc3,0xe8,0x8f,0xff,0xff,0xff,0x45,0x31,0xc0,0xb8,0x9,0x1,0x0,0x0,0xf,0x5,0x48,0x85,0xc0,0xf,0x88,0xa9,0x0
    .byte 0x0,0x0,0xe9,0xb7,0x0,0x0,0x0,0xe8,0x72,0xff,0xff,0xff,0xb8,0x8,0x1,0x0,0x0,0xf,0x5,0x48,0x85,0xc0,0xf,0x88
    .byte 0x8f,0x0,0x0,0x0,0xe9,0x9d,0x0,0x0,0x0,0x49,0x83,0x7e,0x18,0x0,0xf,0x85,0x7d,0x1,0x0,0x0,0x49,0x81,0x7e,0x20
    .byte 0x80,0x10,0x0,0x0,0xf,0x85,0x6f,0x1,0x0,0x0,0x49,0x81,0x7e,0x28,0x86,0x0,0x0,0x0,0xf,0x85,0x61,0x1,0x0,0x0
    .byte 0x49,0x83,0x7e,0x30,0x0,0xf,0x85,0x56,0x1,0x0,0x0,0x49,0x8b,0xbf,0x80,0x0,0x0,0x0,0x49,0x8d,0xb4,0x24,0x80,0x10
    .byte 0x0,0x0,0x31,0xd2,0xb8,0x7,0x1,0x0,0x0,0xf,0x5,0x48,0x85,0xc0,0x78,0x3b,0xeb,0x4c,0xe8,0x7e,0xfc,0xff,0xff,0xe8
    .byte 0x59,0xfc,0xff,0xff,0x48,0x85,0xc9,0xf,0x84,0x24,0x1,0x0,0x0,0x49,0xc7,0x84,0xcf,0x80,0x0,0x0,0x0,0xff,0xff,0xff
    .byte 0xff,0x49,0xc7,0x84,0xcf,0xa0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0xb8,0x3,0x0,0x0,0x0,0xf,0x5,0x48,0x85,0xc0,0x78
    .byte 0x2,0xeb,0x13,0x48,0x3d,0x1,0xf0,0xff,0xff,0xf,0x82,0xf2,0x0,0x0,0x0,0x48,0xf7,0xd8,0x49,0x89,0x46,0x50,0x49,0x8b
    .byte 0x84,0x24,0x8,0x1,0x0,0x0,0x49,0x89,0x84,0x24,0x40,0x1,0x0,0x0,0xe9,0x95,0xf8,0xff,0xff,0x49,0x83,0xbf,0x88,0x0
    .byte 0x0,0x0,0xff,0xf,0x85,0xc8,0x0,0x0,0x0,0x49,0x83,0xbf,0x90,0x0,0x0,0x0,0xff,0xf,0x85,0xba,0x0,0x0,0x0,0x49
    .byte 0x83,0x7c,0x24,0x8,0x0,0xf,0x85,0xae,0x0,0x0,0x0,0x41,0x89,0x47,0x20,0x3d,0x0,0x0,0x4,0x0,0x76,0x10,0x83,0xf8
    .byte 0xff,0x74,0x14,0x83,0xf8,0xfe,0xf,0x85,0x95,0x0,0x0,0x0,0xeb,0x9,0x83,0xf8,0x30,0xf,0x82,0x8a,0x0,0x0,0x0
    .byte 0xe9
    .long tk_intent_record_complete - . - 4
    .byte 0x90
    .byte 0x90
    .byte 0x90
    .byte 0x90
    .byte 0xe8,0x53,0x0,0x0,0x0,0x41,0x8b,0x47,0x20,0x3d,0x0,0x0,0x4,0x0,0xf,0x87,0xae,0xf7,0xff,0xff,0x89,0xc2,0x49,0x8d
    .byte 0xb7,0x0,0x20,0x10,0x0,0xe8,0x36,0x0,0x0,0x0,0xe9,0x9b,0xf7,0xff,0xff,0x48,0x85,0xd2,0x74,0x1e,0x31,0xff,0x31,0xc0
    .byte 0xf,0x5,0x48,0x83,0xf8,0xfc,0x74,0xf4,0x48,0x85,0xc0,0x78,0x4b,0x74,0x11,0x45,0x31,0xc0,0x48,0x1,0xc6,0x48,0x29,0xc2
    .byte 0x75,0xe2,0xb8,0x1,0x0,0x0,0x0,0xc3,0x45,0x85,0xc0,0x74,0x33,0x31,0xc0,0xc3,0x48,0x85,0xd2,0x74,0x1f,0xbf,0x1,0x0
    .byte 0x0,0x0,0xb8,0x1,0x0,0x0,0x0,0xf,0x5,0x48,0x83,0xf8,0xfc,0x74,0xee,0x48,0x85,0xc0,0x7e,0x14,0x48,0x1,0xc6,0x48
    .byte 0x29,0xc2,0x75,0xe1,0xc3,0x31,0xed,0xeb,0xc
    .byte 0xe9
    .long tk_intent_contract_failure - . - 4
    .byte 0x90
    .byte 0x90
    .byte 0xe9
    .long tk_intent_resource_failure - . - 4
    .byte 0xbb,0x2,0x0,0x0,0x0,0x49,0x8b,0xbc,0xdf,0x80,0x0,0x0,0x0,0x48,0x85,0xff,0x78,0x13,0x49,0xc7,0x84,0xdf,0x80,0x0
    .byte 0x0,0x0,0xff,0xff,0xff,0xff,0xb8,0x3,0x0,0x0,0x0,0xf,0x5,0xff,0xcb,0x79,0xdc,0x89,0xef,0xeb,0xc,0xbf,0x40,0x0
    .byte 0x0,0x0,0xeb,0x5,0xbf,0x4a,0x0,0x0,0x0,0xb8,0x3c,0x0,0x0,0x0,0xf,0x5,0xf,0xb
.equ tk_intent_record_dispatch, tk_intent_record_prefix + 485
.equ tk_intent_record_ack, tk_intent_record_prefix + 2363
.equ tk_intent_record_errno, tk_intent_record_prefix + 2344

# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
# One real Intent, same Ticket/AuditObservation service and actual result children.
.equ tk_INTENT_GLOBAL_SLOT, 24608
.equ tk_IC_WORK, 2097152
.equ tk_IC_WORK_BYTES, 41943040
.equ tk_IC_INPUT, 45088768
.equ tk_IC_INPUT_BYTES, 9437184
.equ tk_IC_BYTES, 54525952
.equ tk_IC_REPLY, 4096
.equ tk_IC_ACTION_COPY, 1024
.equ tk_IC_SCRATCH, 16384
.equ tk_IC_CHILD_REQUEST, 12582912
.equ tk_IC_CHILD_REPLY, 23068672
.equ tk_IC_CHILD_CAP, 262144

# rdi = existing real service Root. No filesystem access at allocation.
tk_intent_global_create:
    push rbx
    push r12
    push r13
    mov r12, rdi
    cmp [r12], r12
    jne tk_intent_contract_failure
    cmp qword ptr [r12 + tk_INTENT_GLOBAL_SLOT], 0
    jne tk_intent_contract_failure
    mov rbx, [r12 + tk_STORAGE_GLOBAL]
    test rbx, rbx
    jnz tk_intent_global_storage_ready
    mov edi, 4096
    call tk_allocate_guarded
    mov rbx, rax
    mov rdx, 0x3130475354415248
    mov [rbx], rdx
    mov [rbx + 8], r12
    mov [r12 + tk_STORAGE_GLOBAL], rbx
    mov rdi, rbx
    call tk_ticket_backend_create
    test rax, rax
    jz tk_intent_contract_failure
    mov [rbx + 16], rax
tk_intent_global_storage_ready:
    mov rax, 0x3130475354415248
    cmp [rbx], rax
    jne tk_intent_contract_failure
    cmp [rbx + 8], r12
    jne tk_intent_contract_failure
    cmp qword ptr [rbx + 56], 0
    jne tk_intent_contract_failure
    mov edi, 131072
    call tk_allocate_guarded
    mov r13, rax
    mov rdx, 0x3130474954495248
    mov [r13], rdx
    mov [r13 + tk_IG_SERVICE], r12
    mov [r12 + tk_INTENT_GLOBAL_SLOT], r13
    call tk_result_locks_create
    mov [r13 + tk_IG_LOCKS], rax
    mov rdi, r13
    call tk_intent_prepare_create
    mov [r13 + 24], rax
    mov rdi, r13
    call tk_intent_prepare_create
    mov [r13 + 32], rax
    mov rdi, r13
    call tk_intent_record_create
    mov [r13 + 40], rax
    mov edi, tk_IC_BYTES
    call tk_allocate_guarded
    mov [r13 + 56], rax
    mov [rax + 8], r13
    mov rdx, 0x3130434954495248
    mov [rax], rdx
    mov rax, r13
    pop r13
    pop r12
    pop rbx
    ret

# rdi = IG, rsi = private request, rdx = length, rcx = output80.
tk_intent_owner_call:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp, 8
    mov r12, rdi
    mov rbx, rsi
    mov r13, rdx
    mov r15, [r12 + 56]
    cmp [r15 + 8], r12
    jne tk_intent_contract_failure
    cmp qword ptr [r12 + 80], 0
    jne tk_intent_contract_failure
    cmp qword ptr [r15 + 32], 0
    jne tk_intent_contract_failure
    cmp rdx, 8388704
    ja tk_intent_owner_invalid
    mov [r15 + 16], rdx
    mov [r15 + 24], rcx
    mov qword ptr [r15 + 32], 1
    mov qword ptr [r12 + 80], 1
    lea rdi, [r15 + tk_IC_INPUT]
    mov esi, tk_IC_INPUT_BYTES
    mov edx, 3
    mov eax, 10
    syscall
    test rax, rax
    jnz tk_intent_resource_failure
    lea rdi, [r15 + tk_IC_INPUT]
    mov rsi, rbx
    mov rcx, r13
    rep movsb
    lea rdi, [r15 + tk_IC_INPUT]
    mov esi, tk_IC_INPUT_BYTES
    mov edx, 1
    mov eax, 10
    syscall
    test rax, rax
    jnz tk_intent_resource_failure
    lea rbp, [r15 + tk_IC_WORK]
tk_intent_owner_resume:
    lea rdi, [r15 + tk_IC_INPUT]
    mov rsi, [r15 + 16]
    lea rdx, [r15 + tk_IC_REPLY]
    mov ecx, 80
    mov r8, rbp
    mov r9d, tk_IC_WORK_BYTES
    call tk_intent_image_intent
    mov edx, eax
    cmp rax, rdx
    jne tk_intent_contract_failure
    cmp eax, 0xfffffff0
    jne tk_intent_owner_result
    lea r14, [rbp + 4096]
    mov rax, 0x3130304149525248
    cmp [r14], rax
    jne tk_intent_contract_failure
    mov rax, [r15 + 40]
    inc rax
    jz tk_intent_contract_failure
    cmp [r14 + 8], rax
    jne tk_intent_contract_failure
    cmp [rbp + 16], rax
    jne tk_intent_contract_failure
    mov [r15 + 40], rax
    cmp qword ptr [r14 + 32], tk_IC_CHILD_REQUEST
    jne tk_intent_contract_failure
    cmp qword ptr [r14 + 48], tk_IC_CHILD_REPLY
    jne tk_intent_contract_failure
    cmp qword ptr [r14 + 56], tk_IC_CHILD_CAP
    jne tk_intent_contract_failure
    mov rcx, [r14 + 40]
    cmp rcx, 16
    jb tk_intent_contract_failure
    cmp rcx, 9437184
    ja tk_intent_contract_failure
    mov rax, [r14 + 64]
    or rax, [r14 + 72]
    or rax, [r14 + 80]
    or rax, [r14 + 88]
    jnz tk_intent_contract_failure
    mov rsi, r14
    lea rdi, [r15 + tk_IC_ACTION_COPY]
    mov ecx, 12
    rep movsq
    lea r13, [rbp + tk_IC_CHILD_REQUEST]
    mov rax, [r14 + 16]
    cmp rax, 1
    je tk_intent_child_lock
    cmp rax, 2
    je tk_intent_child_directory
    cmp rax, 3
    je tk_intent_child_audit
    cmp rax, 4
    je tk_intent_child_archive
    cmp rax, 5
    je tk_intent_child_record
    cmp rax, 6
    je tk_intent_child_conversion
    cmp rax, 7
    je tk_intent_child_metadata
    jmp tk_intent_contract_failure

tk_intent_child_lock:
    cmp qword ptr [r14 + 24], 0
    jne tk_intent_contract_failure
    mov rax, 0x313030514c525248
    cmp [r13], rax
    jne tk_intent_contract_failure
    mov rax, [r13 + 8]
    cmp rax, 1
    je tk_intent_child_lock_acquire
    cmp rax, 2
    jne tk_intent_contract_failure
    cmp qword ptr [r14 + 40], 64
    jne tk_intent_contract_failure
    cmp qword ptr [r15 + 112], 1
    jne tk_intent_contract_failure
    mov rax, [r13 + 16]
    cmp [r12 + 1024 + 88], rax
    jne tk_intent_contract_failure
    lea rdi, [r12 + 1024]
    call tk_result_locks_drop
    test eax, eax
    jnz tk_intent_contract_failure
    mov qword ptr [r15 + 112], 0
    jmp tk_intent_child_lock_reply
tk_intent_child_lock_acquire:
    cmp qword ptr [r14 + 40], 128
    jne tk_intent_contract_failure
    cmp qword ptr [r13 + 32], 64
    jne tk_intent_contract_failure
    cmp qword ptr [r15 + 112], 0
    jne tk_intent_contract_failure
    lea rdi, [r12 + 1024]
    xor eax, eax
    mov ecx, 64
    rep stosq
    mov rdi, [r12 + tk_IG_LOCKS]
    lea rsi, [r12 + 1024]
    lea rdx, [r13 + 64]
    mov ecx, 64
    call tk_result_locks_record_lock
    test eax, eax
    jz tk_intent_child_lock_held
    cmp eax, 2
    jne tk_intent_contract_failure
    jmp tk_intent_child_lock_reply
tk_intent_child_lock_held:
    mov qword ptr [r15 + 112], 1
tk_intent_child_lock_reply:
    lea rsi, [r12 + 1024 + 256]
    lea rdi, [rbp + tk_IC_CHILD_REPLY]
    mov ecx, 8
    rep movsq
    cmp qword ptr [r15 + 112], 0
    jne tk_intent_child_lock_done
    lea rdi, [r12 + 1024]
    xor eax, eax
    mov ecx, 64
    rep stosq
tk_intent_child_lock_done:
    mov eax, 64
    jmp tk_intent_child_complete

tk_intent_child_directory:
    mov rax, [r14 + 24]
    cmp rax, 2
    ja tk_intent_contract_failure
    mov rbx, [r12 + 24]
    cmp rax, 1
    je tk_intent_child_directory_b
    cmp rax, 2
    jne tk_intent_child_directory_selected
    cmp qword ptr [rbp + 40], 2
    jne tk_intent_child_directory_selected
tk_intent_child_directory_b:
    mov rbx, [r12 + 32]
tk_intent_child_directory_selected:
    cmp qword ptr [r13 + 8], 4
    je tk_intent_child_directory_drop
    mov rdi, [r12 + tk_IG_SERVICE]
    lea rsi, [r13 + 48]
    mov rdx, [r13 + 32]
    mov rax, [r14 + 40]
    sub rax, 48
    jc tk_intent_contract_failure
    cmp rax, rdx
    jne tk_intent_contract_failure
    call tk_intent_root_cap
    test rax, rax
    jz tk_intent_contract_failure
tk_intent_child_directory_drop:
    mov rdi, rbx
    mov esi, 4
    cmp qword ptr [r14 + 24], 2
    jne tk_intent_child_directory_call
    mov esi, 5
tk_intent_child_directory_call:
    mov rdx, r13
    mov rcx, [r14 + 40]
    lea r8, [rbp + tk_IC_CHILD_REPLY]
    call tk_intent_prepare_call
    jmp tk_intent_child_complete

tk_intent_child_archive:
    mov rax, [r14 + 24]
    cmp rax, 1
    ja tk_intent_contract_failure
    mov rdi, [r12 + 24 + rax*8]
    xor esi, esi
    mov rdx, r13
    mov rcx, [r14 + 40]
    lea r8, [rbp + tk_IC_CHILD_REPLY]
    call tk_intent_prepare_call
    jmp tk_intent_child_complete

tk_intent_child_record:
    mov rax, [r14 + 24]
    cmp rax, 1
    ja tk_intent_contract_failure
    mov rbx, [r12 + 24]
    test rax, rax
    jnz tk_intent_child_record_shard
    cmp qword ptr [rbx + 0x1400048], 0
    je tk_intent_contract_failure
    mov rsi, [rbx + 208]
    jmp tk_intent_child_record_call
tk_intent_child_record_shard:
    cmp qword ptr [rbx + 0x200088], 0
    je tk_intent_contract_failure
    mov rsi, [rbx + 160]
tk_intent_child_record_call:
    mov rdi, [r12 + 40]
    mov rdx, r13
    mov rcx, [r14 + 40]
    lea r8, [rbp + tk_IC_CHILD_REPLY]
    call tk_intent_record_call
    jmp tk_intent_child_complete

tk_intent_child_conversion:
    cmp qword ptr [r14 + 24], 0
    jne tk_intent_contract_failure
    mov rdi, r12
    mov rsi, r13
    mov rdx, [r14 + 40]
    lea rcx, [rbp + tk_IC_CHILD_REPLY]
    call tk_intent_conversion_call
    jmp tk_intent_child_complete

tk_intent_child_metadata:
    mov rax, [r14 + 24]
    cmp rax, 1
    ja tk_intent_contract_failure
    cmp qword ptr [r14 + 40], 16
    jne tk_intent_contract_failure
    cmp [r13 + 8], rax
    jne tk_intent_contract_failure
    mov rdx, 0x3130514d49525248
    cmp [r13], rdx
    jne tk_intent_contract_failure
    mov rbx, [r12 + 24 + rax*8]
    cmp qword ptr [rbx + 0x1400048], 0
    je tk_intent_contract_failure
    mov rdi, r12
    call tk_intent_metadata_address
    mov rdi, [rbx + 208]
    cmp rdi, 0x7fffffff
    ja tk_intent_contract_failure
    lea rsi, [r15 + 8192]
    call tk_intent_file_metadata
    lea rdi, [rbp + tk_IC_CHILD_REPLY]
    mov rdx, 0x3130524d49525248
    mov [rdi], rdx
    mov qword ptr [rdi + 8], 0
    mov qword ptr [rdi + 16], 0
    mov qword ptr [rdi + 24], 0
    test rax, rax
    js tk_intent_child_metadata_error
    mov rax, [r15 + 8192]
    mov [rdi + 16], rax
    mov rax, [r15 + 8200]
    mov [rdi + 24], rax
    jmp tk_intent_child_metadata_done
tk_intent_child_metadata_error:
    neg rax
    cmp rax, 4095
    ja tk_intent_contract_failure
    mov [rdi + 8], rax
tk_intent_child_metadata_done:
    mov eax, 32
    jmp tk_intent_child_complete

tk_intent_child_audit:
    cmp qword ptr [r14 + 24], 0
    jne tk_intent_contract_failure
    cmp qword ptr [r14 + 40], 192
    jb tk_intent_contract_failure
    mov rax, 0x3130515649415248
    cmp [r13], rax
    jne tk_intent_contract_failure
    cmp qword ptr [r13 + 40], 64
    jne tk_intent_contract_failure
    cmp qword ptr [r13 + 48], 64
    jne tk_intent_contract_failure
    cmp qword ptr [r13 + 56], 0
    jne tk_intent_contract_failure
    mov rbx, [r13 + 16]
    cmp rbx, 16
    ja tk_intent_contract_failure
    mov rdx, [r13 + 8]
    cmp rdx, 1048528
    ja tk_intent_contract_failure
    lea rax, [rdx + rbx + 192]
    cmp [r14 + 40], rax
    jne tk_intent_contract_failure
    mov rdi, [r12 + tk_IG_SERVICE]
    lea rsi, [r13 + 64]
    call tk_intent_root_cap
    test rax, rax
    jz tk_intent_contract_failure
    mov [r15 + 96], rax
    lea rdi, [r15 + tk_IC_SCRATCH]
    xor eax, eax
    mov ecx, 12
    rep stosq
    mov rax, 0x313051564f415248
    mov [r15 + tk_IC_SCRATCH], rax
    mov qword ptr [r15 + tk_IC_SCRATCH + 8], 3
    mov rax, [r15 + 96]
    mov [r15 + tk_IC_SCRATCH + 16], rax
    mov qword ptr [r15 + tk_IC_SCRATCH + 24], 64
    mov qword ptr [r15 + tk_IC_SCRATCH + 32], 64
    mov [r15 + tk_IC_SCRATCH + 40], rbx
    mov rax, [r13 + 24]
    mov [r15 + tk_IC_SCRATCH + 48], rax
    mov rax, [r13 + 32]
    mov [r15 + tk_IC_SCRATCH + 56], rax
    mov rax, [r13 + 8]
    lea rdx, [r13 + rax + 64]
    lea rdi, [r15 + tk_IC_SCRATCH + 96]
    lea rsi, [rdx + rbx + 64]
    mov ecx, 64
    rep movsb
    lea rsi, [rdx + rbx]
    mov ecx, 64
    rep movsb
    mov rsi, rdx
    mov rcx, rbx
    rep movsb
    mov rdi, [r12 + tk_IG_SERVICE]
    mov rsi, [r15 + 96]
    lea rdx, [r15 + tk_IC_SCRATCH]
    lea rcx, [rbx + 224]
    lea r8, [r15 + 32768]
    mov r9d, 320
    call tk_audit_observation_call
    cmp rax, 128
    jne tk_intent_contract_failure
    mov rax, 0x313052564f415248
    cmp [r15 + 32768], rax
    jne tk_intent_contract_failure
    cmp qword ptr [r15 + 32776], 3
    jne tk_intent_contract_failure
    lea rdi, [rbp + tk_IC_CHILD_REPLY]
    mov rax, 0x3130525649415248
    mov [rdi], rax
    mov rax, [r15 + 32784]
    mov [rdi + 8], rax
    mov rax, [r15 + 32792]
    mov [rdi + 16], rax
    mov qword ptr [rdi + 24], 0
    mov eax, 32
    jmp tk_intent_child_complete

tk_intent_child_complete:
    mov edx, eax
    cmp rax, rdx
    jne tk_intent_contract_failure
    cmp eax, tk_IC_CHILD_CAP
    ja tk_intent_contract_failure
    mov ebx, eax
    mov rsi, r14
    lea rdi, [r15 + tk_IC_ACTION_COPY]
    mov ecx, 8
    repe cmpsq
    jne tk_intent_contract_failure
    mov rax, [r14 + 64]
    or rax, [r14 + 72]
    or rax, [r14 + 80]
    or rax, [r14 + 88]
    jnz tk_intent_contract_failure
    mov [r14 + 72], rbx
    mov rax, [r14 + 8]
    mov [r14 + 64], rax
    jmp tk_intent_owner_resume

tk_intent_owner_result:
    mov ebx, eax
    cmp eax, 80
    jne tk_intent_owner_refusal
    cmp qword ptr [rbp + 8], 0
    jne tk_intent_contract_failure
    cmp qword ptr [r15 + 112], 0
    jne tk_intent_contract_failure
    mov rax, 0x3130305249525248
    cmp [r15 + tk_IC_REPLY], rax
    jne tk_intent_contract_failure
    mov rax, [r15 + tk_IC_REPLY + 24]
    cmp [rbp + 32], rax
    jne tk_intent_contract_failure
    mov [r15 + 104], rax
    lea rsi, [r15 + tk_IC_REPLY]
    mov rdi, [r15 + 24]
    mov ecx, 10
    rep movsq
    jmp tk_intent_owner_retire
tk_intent_owner_refusal:
    cmp eax, 0xfffffffd
    jb tk_intent_contract_failure
tk_intent_owner_retire:
    mov qword ptr [r15 + 24], 0
    mov qword ptr [r15 + 32], 0
    mov qword ptr [r12 + 80], 0
    mov eax, ebx
    jmp tk_intent_owner_done
tk_intent_owner_invalid:
    mov eax, 0xffffffff
tk_intent_owner_done:
    add rsp, 8
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

# Exact raw argv root lookup, not an owner hash or a serialized authority flag.
# rdi=Root,rsi=bytes,rdx=length -> rax=one-based cap or zero.
tk_intent_root_cap:
    push rbx
    mov r8, rsi
    mov r9, rdx
    mov r10, rdi
    mov r11, [r10 + tk_ROOT_COUNT]
    cmp r11, 1
    jb tk_intent_contract_failure
    cmp r11, 64
    ja tk_intent_contract_failure
    xor ebx, ebx
tk_intent_root_cap_next:
    mov rax, rbx
    shl rax, 4
    cmp [r10 + tk_ROOT_PATHS + rax + 8], r9
    jne tk_intent_root_cap_skip
    mov rdi, [r10 + tk_ROOT_PATHS + rax]
    mov rsi, r8
    mov rcx, r9
    repe cmpsb
    je tk_intent_root_cap_found
tk_intent_root_cap_skip:
    inc rbx
    cmp rbx, r11
    jb tk_intent_root_cap_next
    xor eax, eax
    pop rbx
    ret
tk_intent_root_cap_found:
    lea rax, [rbx + 1]
    pop rbx
    ret

# The fixed transport has one Intent. Old Ticket/Observation commands remain.
tk_intent_service_frame:
    mov rsi, [r15 + tk_SERVICE_IO]
    add rsi, 32
    mov rdx, [r15 + 1088]
    cmp rdx, 8
    jb tk_intent_service_regular
    mov rax, 0x3130305149525248
    cmp [rsi], rax
    jne tk_intent_service_regular
    mov rdi, [r15 + tk_INTENT_GLOBAL_SLOT]
    test rdi, rdi
    jnz tk_intent_service_ready
    mov rdi, r15
    call tk_intent_global_create
    mov rdi, rax
tk_intent_service_ready:
    mov rsi, [r15 + tk_SERVICE_IO]
    add rsi, 32
    mov rdx, [r15 + 1088]
    mov rcx, [r15 + tk_SERVICE_IO]
    add rcx, tk_SERVICE_OUTPUT
    call tk_intent_owner_call
    jmp tk_service_emit_result
tk_intent_service_regular:
    cmp qword ptr [r15 + 1088], tk_MAX_PUBLIC_INPUT
    ja tk_intent_contract_failure
    jmp tk_observation_service_frame

tk_intent_contract_failure:
tk_result_locks_contract_failure:
    jmp tk_contract_fail
tk_intent_resource_failure:
tk_result_locks_resource_failure:
    jmp tk_io_fail
tk_intent_unreachable_prepare:
    jmp tk_intent_contract_failure

# The consumed Intent's real fields retire before the shared Ticket storage.
tk_intent_global_drop:
    push rbx
    push r12
    push r13
    sub rsp, 16
    mov [rsp], rsi
    mov r12, rdi
    mov r13, [r12 + tk_INTENT_GLOBAL_SLOT]
    test r13, r13
    jz tk_intent_global_drop_done
    cmp [r13 + tk_IG_SERVICE], r12
    jne tk_intent_contract_failure
    cmp qword ptr [r13 + 80], 0
    jne tk_intent_contract_failure
    mov rbx, [r13 + 56]
    cmp qword ptr [rbx + 112], 0
    jne tk_intent_contract_failure
    cmp qword ptr [rbx + 104], 0
    je tk_intent_global_drop_empty
    cmp qword ptr [rbx + 104], 1
    jne tk_intent_contract_failure
    lea rdi, [rbx + 65536]
    xor eax, eax
    mov ecx, 12
    rep stosq
    mov rax, 0x3130305149525248
    mov [rbx + 65536], rax
    mov qword ptr [rbx + 65544], 3
    mov rdi, r13
    lea rsi, [rbx + 65536]
    mov edx, 96
    lea rcx, [rbx + 65792]
    call tk_intent_owner_call
    cmp eax, 80
    jne tk_intent_contract_failure
    mov rax, [rbx + 65800]
    or rax, [rbx + 65816]
    or rax, [rbx + 104]
    jnz tk_intent_contract_failure
tk_intent_global_drop_empty:
    cmp qword ptr [rsp], 1
    je tk_intent_global_drop_done
    cmp qword ptr [rsp], 0
    jne tk_intent_contract_failure
    mov rdi, [r13 + 24]
    call tk_intent_prepare_cleanup
    mov qword ptr [r13 + 24], 0
    mov rdi, [r13 + 32]
    call tk_intent_prepare_cleanup
    mov qword ptr [r13 + 32], 0
    mov rdi, [r13 + 40]
    cmp qword ptr [rdi + 128], -1
    jne tk_intent_contract_failure
    cmp qword ptr [rdi + 136], -1
    jne tk_intent_contract_failure
    cmp qword ptr [rdi + 144], -1
    jne tk_intent_contract_failure
    mov qword ptr [r13 + 40], 0
    mov esi, tk_IR_BYTES
    mov eax, 11
    syscall
    test rax, rax
    jnz tk_intent_resource_failure
    mov rdi, r13
    call tk_intent_conversion_drop
    mov rdi, rbx
    mov esi, tk_IC_BYTES + 4096
    mov qword ptr [r13 + 56], 0
    mov eax, 11
    syscall
    test rax, rax
    jnz tk_intent_resource_failure
    mov rdi, [r13 + tk_IG_LOCKS]
    call tk_result_locks_close
    test eax, eax
    jnz tk_intent_contract_failure
    mov qword ptr [r13 + tk_IG_LOCKS], 0
    mov qword ptr [r12 + tk_INTENT_GLOBAL_SLOT], 0
    mov rdi, r13
    mov esi, 135168
    mov eax, 11
    syscall
    test rax, rax
    jnz tk_intent_resource_failure
tk_intent_global_drop_done:
    add rsp, 16
    pop r13
    pop r12
    pop rbx
    ret

# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
# Exact retained-result HIA with its real pure children. Scratch is per call.
.equ tk_CV_INPUT, 4096
.equ tk_CV_INPUT_CAP, 9437184
.equ tk_CV_OUTPUT, 9441280
.equ tk_CV_WORK, 12582912
.equ tk_CV_DTO_WORK, 281018368
.equ tk_CV_PURE_WORK, 549453824
.equ tk_CV_BYTES, 817889280
.equ tk_CV_REQUEST, 167837696
.equ tk_CV_REPLY, 184614912
.equ tk_CV_REPLY_CAP, 67108864
# rdi=IG,rsi=request,rdx=len,rcx=reply (at least 98336 bytes).
tk_intent_conversion_call:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp, 24
    mov r13, rdi
    mov [rsp], rsi
    mov [rsp + 8], rdx
    mov [rsp + 16], rcx
    cmp rdx, tk_CV_INPUT_CAP
    ja tk_intent_contract_failure
    mov r15, [r13 + 48]
    test r15, r15
    jnz tk_intent_conversion_existing
    mov edi, tk_CV_BYTES
    call tk_allocate_guarded
    mov r15, rax
    mov [r13 + 48], rax
    mov [r15 + 8], r13
tk_intent_conversion_existing:
    cmp [r15 + 8], r13
    jne tk_intent_contract_failure
    cmp qword ptr [r15 + 32], 0
    jne tk_intent_contract_failure
    mov qword ptr [r15 + 32], 1
    mov qword ptr [r15 + 40], 0
    mov rax, [rsp + 8]
    mov [r15 + 16], rax
    mov rax, [rsp + 16]
    mov [r15 + 24], rax
    lea rdi, [r15 + tk_CV_INPUT]
    mov esi, tk_CV_INPUT_CAP
    mov edx, 3
    mov eax, 10
    syscall
    test rax, rax
    jnz tk_intent_resource_failure
    lea rdi, [r15 + tk_CV_INPUT]
    mov rsi, [rsp]
    mov rcx, [rsp + 8]
    rep movsb
    lea rdi, [r15 + tk_CV_INPUT]
    mov esi, tk_CV_INPUT_CAP
    mov edx, 1
    mov eax, 10
    syscall
    test rax, rax
    jnz tk_intent_resource_failure
    lea rbp, [r15 + tk_CV_WORK]
    mov rdi, rbp
    mov esi, 268435456
    mov edx, 4
    mov eax, 28
    syscall
    test rax, rax
    jnz tk_intent_resource_failure
tk_intent_conversion_resume:
    lea rdi, [r15 + tk_CV_INPUT]
    mov rsi, [r15 + 16]
    lea rdx, [r15 + tk_CV_OUTPUT]
    mov ecx, 98336
    mov r8, rbp
    mov r9d, 268435456
    call tk_intent_image_retention
    mov edx, eax
    cmp rax, rdx
    jne tk_intent_contract_failure
    cmp eax, 0xfffffff0
    jne tk_intent_conversion_result
    lea r14, [rbp + 256]
    mov rax, 0x3130304154525248
    cmp [r14], rax
    jne tk_intent_contract_failure

    mov rax, [r15 + 40]
    inc rax
    jz tk_intent_contract_failure
    cmp [r14 + 8], rax
    jne tk_intent_contract_failure
    mov [r15 + 40], rax
    mov rax, [r14 + 24]
    or rax, [r14 + 64]
    or rax, [r14 + 72]
    or rax, [r14 + 80]
    or rax, [r14 + 88]
    jnz tk_intent_contract_failure
    cmp qword ptr [r14 + 32], tk_CV_REQUEST
    jne tk_intent_contract_failure
    cmp qword ptr [r14 + 48], tk_CV_REPLY
    jne tk_intent_contract_failure
    cmp qword ptr [r14 + 56], tk_CV_REPLY_CAP
    jne tk_intent_contract_failure
    cmp qword ptr [r14 + 40], 16777216
    ja tk_intent_contract_failure
    mov rsi, r14
    lea rdi, [r15 + 512]
    mov ecx, 12
    rep movsq
    mov rsi, [r14 + 16]
    cmp rsi, 4
    je tk_intent_conversion_dto
    cmp rsi, 3
    je tk_intent_conversion_metadata
    mov rdi, r15
    lea rdx, [rbp + tk_CV_REQUEST]
    mov rcx, [r14 + 40]
    lea r8, [rbp + tk_CV_REPLY]
    mov r9d, tk_CV_REPLY_CAP
    call tk_intent_pure_run
    jmp tk_intent_conversion_ack
tk_intent_conversion_metadata:
    mov rdi, r15
    lea rsi, [rbp + tk_CV_REQUEST]
    mov rdx, [r14 + 40]
    lea rcx, [rbp + tk_CV_REPLY]
    mov r8d, tk_CV_REPLY_CAP
    call tk_intent_result_metadata_call
    jmp tk_intent_conversion_ack
tk_intent_conversion_dto:
    mov rdi, r15
    lea rsi, [rbp + tk_CV_REQUEST]
    mov rdx, [r14 + 40]
    lea rcx, [rbp + tk_CV_REPLY]
    mov r8d, tk_CV_REPLY_CAP
    call tk_intent_dto_call
tk_intent_conversion_ack:
    mov edx, eax
    cmp rax, rdx
    jne tk_intent_contract_failure
    mov ebx, eax
    mov rsi, r14
    lea rdi, [r15 + 512]
    mov ecx, 12
    repe cmpsq
    jne tk_intent_contract_failure
    mov [r14 + 72], rbx
    mov rax, [r14 + 8]
    mov [r14 + 64], rax
    jmp tk_intent_conversion_resume
tk_intent_conversion_result:
    mov ebx, eax
    cmp eax, 98336
    ja tk_intent_conversion_refusal
    cmp eax, 32
    jb tk_intent_contract_failure
    mov rdi, [r15 + 24]
    lea rsi, [r15 + tk_CV_OUTPUT]
    mov ecx, ebx
    rep movsb
    jmp tk_intent_conversion_release
tk_intent_conversion_refusal:
    cmp eax, 0xfffffffe
    jb tk_intent_contract_failure
tk_intent_conversion_release:
    mov qword ptr [r15 + 32], 0
    mov qword ptr [r15 + 24], 0
    mov eax, ebx
    add rsp, 24
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

# Only plain pure children use this cleared scratch; suspended DTO has its own.
# CV, plain role1/2/5, request, length, reply, capacity.
tk_intent_pure_run:
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub rsp, 16
    mov r15, rdi
    mov ebx, esi
    mov r12, rdx
    mov r13, rcx
    mov r14, r8
    mov [rsp], r9
    lea rdi, [r15 + tk_CV_PURE_WORK]
    mov esi, 268435456
    mov edx, 4
    mov eax, 28
    syscall
    test rax, rax
    jnz tk_intent_resource_failure
    mov rdi, r12
    mov rsi, r13
    mov rdx, r14
    mov rcx, [rsp]
    lea r8, [r15 + tk_CV_PURE_WORK]
    mov r9d, 268435456
    cmp ebx, 1
    je tk_intent_pure_value
    cmp ebx, 2
    je tk_intent_pure_typed
    cmp ebx, 5
    jne tk_intent_contract_failure
    mov r9d, 33554432
    call tk_intent_image_binary_codec
    jmp tk_intent_pure_done
tk_intent_pure_value:
    call tk_intent_image_value
    jmp tk_intent_pure_done
tk_intent_pure_typed:
    call tk_intent_image_typed
    jmp tk_intent_pure_done
tk_intent_pure_done:
    add rsp, 16
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

# CV, DTO request, length, output, capacity; independent suspended DTO workspace.
tk_intent_dto_call:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp, 8
    mov r15, rdi
    cmp qword ptr [r15 + 144], 0
    jne tk_intent_contract_failure
    mov [r15 + 56], rsi
    mov [r15 + 64], rdx
    mov [r15 + 72], rcx
    mov [r15 + 80], r8
    mov qword ptr [r15 + 48], 0
    lea rbp, [r15 + tk_CV_DTO_WORK]
    mov rdi, rbp
    mov esi, 268435456
    mov edx, 4
    mov eax, 28
    syscall
    test rax, rax
    jnz tk_intent_resource_failure
tk_intent_dto_resume:
    mov rdi, [r15 + 56]
    mov rsi, [r15 + 64]
    mov rdx, [r15 + 72]
    mov rcx, [r15 + 80]
    mov r8, rbp
    mov r9d, 268435456
    call tk_intent_image_safe_dto
    mov edx, eax
    cmp rax, rdx
    jne tk_intent_contract_failure
    cmp eax, 0xfffffff0
    jne tk_intent_dto_result
    lea r14, [rbp + 256]
    mov rax, 0x3130304144535248
    cmp [r14], rax
    jne tk_intent_contract_failure
    mov rax, [r15 + 48]
    inc rax
    jz tk_intent_contract_failure
    cmp [r14 + 8], rax
    jne tk_intent_contract_failure
    mov [r15 + 48], rax
    mov rax, [r14 + 24]
    or rax, [r14 + 64]
    or rax, [r14 + 72]
    or rax, [r14 + 80]
    or rax, [r14 + 88]
    jnz tk_intent_contract_failure
    cmp qword ptr [r14 + 32], tk_CV_REQUEST
    jne tk_intent_contract_failure
    cmp qword ptr [r14 + 48], tk_CV_REPLY
    jne tk_intent_contract_failure
    cmp qword ptr [r14 + 56], tk_CV_REPLY_CAP
    jne tk_intent_contract_failure
    cmp qword ptr [r14 + 40], 16777216
    ja tk_intent_contract_failure
    mov rsi, r14
    lea rdi, [r15 + 640]
    mov ecx, 12
    rep movsq
    cmp qword ptr [r14 + 16], 2
    je tk_intent_dto_config
    cmp qword ptr [r14 + 16], 1
    jne tk_intent_contract_failure
    mov rdi, r15
    mov esi, 1
    lea rdx, [rbp + tk_CV_REQUEST]
    mov rcx, [r14 + 40]
    lea r8, [rbp + tk_CV_REPLY]
    mov r9d, tk_CV_REPLY_CAP
    call tk_intent_pure_run
    jmp tk_intent_dto_ack
tk_intent_dto_config:
    mov rdi, [r15 + 8]
    lea rsi, [rbp + tk_CV_REQUEST]
    mov rdx, [r14 + 40]
    lea rcx, [rbp + tk_CV_REPLY]
    mov r8d, tk_CV_REPLY_CAP
    call tk_intent_config_call
tk_intent_dto_ack:
    mov edx, eax
    cmp rax, rdx
    jne tk_intent_contract_failure
    mov ebx, eax
    mov rsi, r14
    lea rdi, [r15 + 640]
    mov ecx, 12
    repe cmpsq
    jne tk_intent_contract_failure
    mov [r14 + 72], rbx
    mov rax, [r14 + 8]
    mov [r14 + 64], rax
    jmp tk_intent_dto_resume
tk_intent_dto_result:
    cmp eax, 32
    je tk_intent_dto_done
    cmp eax, 0xfffffffe
    jb tk_intent_contract_failure
tk_intent_dto_done:
    mov qword ptr [r15 + 56], 0
    mov qword ptr [r15 + 64], 0
    mov qword ptr [r15 + 72], 0
    mov qword ptr [r15 + 80], 0
    add rsp, 8
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

# rdi=IG, after all synchronous callers completed.
tk_intent_conversion_drop:
    push rbx
    mov rbx, rdi
    mov rdi, [rbx + 48]
    test rdi, rdi
    jz tk_intent_conversion_drop_done
    cmp qword ptr [rdi + 32], 0
    jne tk_intent_contract_failure
    mov qword ptr [rbx + 48], 0
    mov esi, tk_CV_BYTES + 4096
    mov eax, 11
    syscall
    test rax, rax
    jnz tk_intent_resource_failure
tk_intent_conversion_drop_done:
    mov rdi, rbx
    call tk_intent_config_drop
    pop rbx
    ret

# The metadata annotator is a continuation owner with real Value/typed children.
# Its lifetime precedes DTO; they reuse the second private workspace serially.
.equ tk_CM_REQUEST, 16785408
.equ tk_CM_REPLY, 33570816
.equ tk_CM_REPLY_CAP, 67108864
tk_intent_result_metadata_call:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp, 8
    mov r15, rdi
    cmp qword ptr [r15 + 144], 0
    jne tk_intent_contract_failure
    cmp qword ptr [r15 + 56], 0
    jne tk_intent_contract_failure
    mov qword ptr [r15 + 144], 1
    mov [r15 + 96], rsi
    mov [r15 + 104], rdx
    mov [r15 + 112], rcx
    mov [r15 + 120], r8
    mov qword ptr [r15 + 136], 0
    lea rbp, [r15 + tk_CV_DTO_WORK]
    mov rdi, rbp
    mov esi, 268435456
    mov edx, 4
    mov eax, 28
    syscall
    test rax, rax
    jnz tk_intent_resource_failure
tk_intent_result_metadata_resume:
    mov rdi, [r15 + 96]
    mov rsi, [r15 + 104]
    mov rdx, [r15 + 112]
    mov rcx, [r15 + 120]
    mov r8, rbp
    mov r9d, 268435456
    call tk_intent_image_request
    mov edx, eax
    cmp rax, rdx
    jne tk_intent_contract_failure
    cmp eax, 0xfffffff0
    jne tk_intent_result_metadata_result
    lea r14, [rbp + 256]
    mov rax, 0x3130304152505248
    cmp [r14], rax
    jne tk_intent_contract_failure
    mov rax, [r15 + 136]
    inc rax
    jz tk_intent_contract_failure
    cmp [r14 + 8], rax
    jne tk_intent_contract_failure
    cmp [rbp + 16], rax
    jne tk_intent_contract_failure
    mov [r15 + 136], rax
    mov rax, [r14 + 24]
    or rax, [r14 + 64]
    or rax, [r14 + 72]
    or rax, [r14 + 80]
    or rax, [r14 + 88]
    jnz tk_intent_contract_failure
    cmp qword ptr [r14 + 32], tk_CM_REQUEST
    jne tk_intent_contract_failure
    cmp qword ptr [r14 + 48], tk_CM_REPLY
    jne tk_intent_contract_failure
    cmp qword ptr [r14 + 56], tk_CM_REPLY_CAP
    jne tk_intent_contract_failure
    cmp qword ptr [r14 + 40], 16777216
    ja tk_intent_contract_failure
    mov r12, [r14 + 16]
    cmp r12, 1
    jb tk_intent_contract_failure
    cmp r12, 2
    ja tk_intent_contract_failure
    mov rsi, r14
    lea rdi, [r15 + 768]
    mov ecx, 12
    rep movsq
    mov rdi, r15
    mov rsi, r12
    lea rdx, [rbp + tk_CM_REQUEST]
    mov rcx, [r14 + 40]
    lea r8, [rbp + tk_CM_REPLY]
    mov r9d, tk_CM_REPLY_CAP
    call tk_intent_pure_run
    mov edx, eax
    cmp rax, rdx
    jne tk_intent_contract_failure
    mov ebx, eax
    mov rsi, r14
    lea rdi, [r15 + 768]
    mov ecx, 12
    repe cmpsq
    jne tk_intent_contract_failure
    mov [r14 + 72], rbx
    mov rax, [r14 + 8]
    mov [r14 + 64], rax
    jmp tk_intent_result_metadata_resume
tk_intent_result_metadata_result:
    cmp eax, tk_CM_REPLY_CAP
    ja tk_intent_result_metadata_refusal
    cmp eax, 64
    jb tk_intent_contract_failure
    cmp qword ptr [rbp + 8], 0
    jne tk_intent_contract_failure
    jmp tk_intent_result_metadata_done
tk_intent_result_metadata_refusal:
    cmp eax, 0xfffffffe
    jb tk_intent_contract_failure
tk_intent_result_metadata_done:
    mov qword ptr [r15 + 96], 0
    mov qword ptr [r15 + 104], 0
    mov qword ptr [r15 + 112], 0
    mov qword ptr [r15 + 120], 0
    mov qword ptr [r15 + 144], 0
    add rsp, 8
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

# Normal carrier retirement uses actual HIA child drop entries before retiring their carriers.
tk_intent_prepare_cleanup:
    push rbx
    push rbp
    sub rsp, 120
    mov rbx, rdi
    xor ebp, ebp
tk_intent_prepare_cleanup_next:
    lea rdi, [rsp]
    xor eax, eax
    mov ecx, 6
    rep stosq
    cmp ebp, 0
    jne tk_intent_prepare_cleanup_archive
    mov rcx, [rbx + 0x200088]
    mov edx, 4
    jmp tk_intent_prepare_cleanup_store
tk_intent_prepare_cleanup_archive:
    cmp ebp, 1
    jne tk_intent_prepare_cleanup_dirs
    mov rcx, [rbx + 0x200078]
    mov edx, 5
tk_intent_prepare_cleanup_store:
    test rcx, rcx
    jz tk_intent_prepare_cleanup_advance
    mov rax, 0x3130305153415248
    mov [rsp], rax
    mov [rsp + 8], rdx
    mov [rsp + 24], rcx
    xor esi, esi
    jmp tk_intent_prepare_cleanup_call
tk_intent_prepare_cleanup_dirs:
    cmp ebp, 2
    jne tk_intent_prepare_cleanup_dir1
    mov rcx, [rbx + 0x1400048]
    mov esi, 4
    jmp tk_intent_prepare_cleanup_dir
tk_intent_prepare_cleanup_dir1:
    mov rcx, [rbx + 0x1800048]
    mov esi, 5
tk_intent_prepare_cleanup_dir:
    test rcx, rcx
    jz tk_intent_prepare_cleanup_advance
    mov rax, 0x3130305141445248
    mov [rsp], rax
    mov qword ptr [rsp + 8], 4
    mov [rsp + 24], rcx
tk_intent_prepare_cleanup_call:
    mov rdi, rbx
    mov rdx, rsp
    mov ecx, 48
    lea r8, [rsp + 48]
    call tk_intent_prepare_call
    cmp eax, 64
    jne tk_intent_contract_failure
    cmp qword ptr [rsp + 56], 0
    jne tk_intent_contract_failure
tk_intent_prepare_cleanup_advance:
    inc ebp
    cmp ebp, 4
    jb tk_intent_prepare_cleanup_next
    cmp qword ptr [rbx + 0xb8], 0
    jne tk_intent_contract_failure
    lea rdi, [rbx + 0x80]
    mov ecx, 7
tk_intent_prepare_cleanup_slots:
    cmp qword ptr [rdi], -1
    jne tk_intent_contract_failure
    add rdi, 8
    dec ecx
    jnz tk_intent_prepare_cleanup_slots
    lea rdi, [rbx + 0xc0]
    mov ecx, 6
tk_intent_prepare_cleanup_dirslots:
    cmp qword ptr [rdi], -1
    jne tk_intent_contract_failure
    add rdi, 8
    dec ecx
    jnz tk_intent_prepare_cleanup_dirslots
    mov rdi, rbx
    mov esi, 0x1c01000
    mov eax, 11
    syscall
    test rax, rax
    jnz tk_intent_resource_failure
    add rsp, 120
    pop rbp
    pop rbx
    ret

.equ tk_icfg_ROOT_INPUT_CAP, 67108864
.equ tk_icfg_ROOT_OUTPUT_CAP, 134217728
.equ tk_icfg_ROOT_WCAP, 268435456
.equ tk_icfg_VALIDATION_WORK, 771756032
.equ tk_icfg_LINK, 16908288
.equ tk_icfg_INPUT, 4096
.equ tk_icfg_OUTPUT, 67112960
.equ tk_icfg_WORK, 201330688
.equ tk_icfg_ROOT_WORK, 234885120
.equ tk_icfg_JSON_WORK, 503320576
.equ tk_icfg_SHA_WORK, 1040191488
.equ tk_icfg_REGEX_CONTROLLER_WORK, 1308626944
.equ tk_icfg_REGEX_SYNTAX_WORK, 1577062400
.equ tk_icfg_REGEX_HIR_WORK, 1845497856
.equ tk_icfg_REGEX_NFA_WORK, 2113933312
.equ tk_icfg_REGEX_MATCH_WORK, 2382368768
.equ tk_icfg_REGEX_DATA_WORK, 2415923200
.equ tk_icfg_MAP_BYTES, 2415988736
.equ tk_icfg_REGEX_CONTEXTS, 2048
.equ tk_icfg_REGEX_SEQUENCES, 2560
.equ tk_icfg_CAP, 8388608
.equ tk_icfg_WCAP, 33554432
.equ tk_icfg_FOOTER, 268435200
.equ tk_icfg_ACTION, 512
.equ tk_icfg_STAT, 1024
.equ tk_icfg_NAME, 8454144
.equ tk_icfg_READ_AREA, 65536
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
.equ tk_IG_CONFIG, 128
.equ tk_CFG_IG, 1120
.equ tk_CFG_BUSY, 1128
.equ tk_CFG_REPLY, 1136
.equ tk_CFG_CAPACITY, 1144
.equ tk_CFG_KIND, 1152
.equ tk_CFG_CODE, 1160

# Only the trusted process startup supplies path/envp.
# rdi=IG, rsi=raw argv path or zero, rdx=original envp.
tk_intent_config_create:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp, 8
    mov r12, rdi
    mov r13, rsi
    mov r14, rdx
    cmp qword ptr [r12 + tk_IG_CONFIG], 0
    jne tk_intent_contract_failure
    mov edi, tk_icfg_MAP_BYTES
    call tk_allocate_guarded
    mov r15, rax
    mov [r12 + tk_IG_CONFIG], rax
    mov [r15 + tk_CFG_IG], r12
    mov [r15 + 648], r14
    mov qword ptr [r15 + tk_CFG_BUSY], 1
    mov qword ptr [r15 + tk_CFG_CAPACITY], tk_icfg_ROOT_OUTPUT_CAP
    test r13, r13
    jz tk_intent_config_uninstalled
    mov [r15 + 704], r13
    mov rdi, r13
    call tk_icfg_cstr_length
    mov [r15 + 712], rax
    jmp tk_icfg_build_start
tk_intent_config_uninstalled:
    mov qword ptr [r15 + 24], 0
    lea rax, [r15 + tk_icfg_ROOT_WORK + tk_icfg_FOOTER]
    mov qword ptr [rax + 120], 4
tk_intent_config_start_enter:
    call tk_intent_config_seal_input
    call tk_intent_config_run
    test eax, eax
    jnz tk_intent_config_start_failed
    mov qword ptr [r15 + tk_CFG_BUSY], 0
    mov rax, r15
    jmp tk_intent_config_return
tk_intent_config_start_failed:
    cmp eax, 32
    jb tk_intent_contract_failure
    lea rsi, [r15 + tk_icfg_OUTPUT]
    mov rdx, 0x31304d4746435248
    cmp [rsi], rdx
    jne tk_intent_contract_failure
    sub rax, 32
    cmp [rsi + 24], rax
    jne tk_intent_contract_failure
    mov rdx, rax
    add rsi, 32
    mov edi, 2
    call tk_icfg_write_exact
    mov edi, 2
    lea rsi, [rip + tk_icfg_newline]
    mov edx, 1
    call tk_icfg_write_exact
tk_intent_config_failed_cleanup:
    mov rax, [r15]
    test rax, rax
    jz tk_intent_config_failed_exit
    mov rdi, [rax + 8]
    call tk_icfg_retire_close
    jmp tk_intent_config_failed_cleanup
tk_intent_config_failed_exit:
    mov edi, 78
    mov eax, 231
    syscall
    ud2

tk_intent_config_seal_input:
    lea rdi, [r15 + tk_icfg_INPUT]
    mov esi, tk_icfg_ROOT_INPUT_CAP
    mov edx, 1
    mov eax, 10
    syscall
    test rax, rax
    jnz tk_intent_resource_failure
    ret

# rdi=IG, rsi=request, rdx=length, rcx=reply, r8=reply capacity.
# There is no frame-accessible installation or reinitialization route.
tk_intent_config_call:
    jmp ex_intent_config_call
tk_intent_config_return:
    add rsp, 8
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

# rdi=IG; all synchronous private queries have returned.
tk_intent_config_drop:
    jmp ex_intent_config_drop

tk_intent_config_run:
    sub rsp, 8
    jmp tk_icfg_owner_resume

tk_icfg_build_start:
    lea rdi, [rip + tk_icfg_env_state]
    call tk_icfg_find_environment
    mov [r15 + 720], rax
    mov [r15 + 728], rdx
    test rax, rax
    jz tk_icfg_environment_xdg
    or qword ptr [r15 + 640], 1
tk_icfg_environment_xdg:
    lea rdi, [rip + tk_icfg_env_xdg]
    call tk_icfg_find_environment
    mov [r15 + 736], rax
    mov [r15 + 744], rdx
    test rax, rax
    jz tk_icfg_environment_home
    or qword ptr [r15 + 640], 2
tk_icfg_environment_home:
    lea rdi, [rip + tk_icfg_env_home]
    call tk_icfg_find_environment
    mov [r15 + 752], rax
    mov [r15 + 760], rdx
    test rax, rax
    jz tk_icfg_environment_temp
    or qword ptr [r15 + 640], 4
tk_icfg_environment_temp:
    lea rdi, [rip + tk_icfg_env_temp]
    call tk_icfg_find_environment
    mov [r15 + 768], rax
    mov [r15 + 776], rdx
    test rax, rax
    jz tk_icfg_config_frame
    or qword ptr [r15 + 640], 8
tk_icfg_config_frame:
    lea rdi, [r15 + tk_icfg_INPUT]
    mov rax, 0x3130434746435248 /* HRCFGC01 */
    mov [rdi], rax
    mov rax, [r15 + 640]
    mov [rdi + 8], rax
    xor ebx, ebx
tk_icfg_config_lengths:
    mov rax, rbx
    shl rax, 4
    mov rax, [r15 + rax + 712]
    mov [rdi + rbx*8 + 16], rax
    inc rbx
    cmp rbx, 5
    jne tk_icfg_config_lengths
    mov qword ptr [rdi + 56], 0
    add rdi, 64
    xor ebx, ebx
tk_icfg_config_bytes:
    mov rax, rbx
    shl rax, 4
    mov rsi, [r15 + rax + 704]
    mov rcx, [r15 + rax + 712]
    rep movsb
    inc rbx
    cmp rbx, 5
    jne tk_icfg_config_bytes
    lea rax, [r15 + tk_icfg_INPUT]
    sub rdi, rax
    mov [r15 + 24], rdi
    lea rax, [r15 + tk_icfg_ROOT_WORK + tk_icfg_FOOTER]
    mov qword ptr [rax + 120], 0
    jmp tk_intent_config_start_enter

tk_icfg_owner_resume:
    mov qword ptr [r15 + 80], 0
    lea r13, [r15 + tk_icfg_INPUT]
    lea r12, [r15 + tk_icfg_OUTPUT]
    lea r14, [r15 + tk_icfg_ROOT_WORK]
    mov rdi, r13
    mov rsi, [r15 + 24]
    mov rdx, r12
    mov rcx, [r15 + tk_CFG_CAPACITY]
    mov r8, r14
    mov r9d, tk_icfg_ROOT_WCAP
    call tk_intent_image_config_owner
    jmp tk_icfg_native_return
tk_icfg_native_resume:
    cmp qword ptr [r15 + 80], 1
    jne tk_icfg_fatal
    mov rdi, r13
    mov rsi, [r15 + 96]
    mov rdx, r12
    mov rcx, [r15 + 104]
    mov r8, r14
    mov r9d, tk_icfg_WCAP
    call tk_intent_image_config_fs
    jmp tk_icfg_native_return
tk_icfg_json_resume:
    lea r14, [r15 + tk_icfg_JSON_WORK]
    mov rdi, r13
    mov rsi, [r15 + 96]
    mov rdx, r12
    mov rcx, [r15 + 104]
    mov r8, r14
    mov r9d, tk_icfg_ROOT_WCAP
    call tk_intent_image_config_json
    jmp tk_icfg_native_return
tk_icfg_identity_resume:
    lea r14, [r15 + tk_icfg_SHA_WORK]
    mov rdi, r13
    mov rsi, [r15 + 96]
    mov rdx, r12
    mov rcx, [r15 + 104]
    mov r8, r14
    mov r9d, tk_icfg_ROOT_WCAP
    call tk_intent_image_config_identity
    jmp tk_icfg_native_return
tk_icfg_validation_resume:
    lea r14, [r15 + tk_icfg_REGEX_CONTEXTS]
    mov qword ptr [r14], 3
    mov [r14 + 8], r13
    mov rax, [r15 + 96]
    mov [r14 + 16], rax
    mov [r14 + 24], r12
    mov rax, [r15 + 104]
    mov [r14 + 32], rax
    lea rax, [r15 + tk_icfg_VALIDATION_WORK]
    mov [r14 + 40], rax
    mov qword ptr [r14 + 48], tk_icfg_ROOT_WCAP
    xor r12d, r12d
    jmp tk_icfg_regex_invoke
tk_icfg_native_return:
    mov edx, eax
    cmp rax, rdx
    jne tk_icfg_fatal
    mov edx, 0xffffffe0
    cmp rax, rdx
    je tk_icfg_call_dispatch
    mov edx, 0xfffffff0
    cmp rax, rdx
    je tk_icfg_effect_dispatch_checked
    cmp qword ptr [r15 + 80], 0
    jne tk_icfg_child_completed
    cmp rax, [r15 + tk_CFG_CAPACITY]
    ja tk_icfg_fatal
    add rsp, 8
    ret

tk_icfg_effect_dispatch_checked:
    cmp qword ptr [r15 + 80], 1
    jne tk_icfg_fatal
    jmp tk_icfg_effect_dispatch

tk_icfg_child_completed:
    mov edx, 0xffff0000
    cmp rax, rdx
    jae tk_icfg_child_result_ok
    cmp rax, [r15 + 104]
    ja tk_icfg_fatal
tk_icfg_child_result_ok:
    lea rdx, [r15 + tk_icfg_ROOT_WORK + tk_icfg_FOOTER]
    mov [rdx + 80], rax
    mov rax, [r15 + 88]
    mov [rdx + 88], rax
    mov qword ptr [rdx + 96], 1
    jmp tk_icfg_owner_resume

tk_icfg_call_dispatch:
    cmp qword ptr [r15 + 80], 0
    jne tk_icfg_fatal
    lea rdx, [r15 + tk_icfg_ROOT_WORK + tk_icfg_FOOTER]
    mov rax, 0x31304c4143414948 /* HIACAL01 */
    cmp [rdx], rax
    jne tk_icfg_fatal
    mov rax, [r15 + 88]
    inc rax
    jz tk_icfg_fatal
    cmp [rdx + 8], rax
    jne tk_icfg_fatal
    mov [r15 + 88], rax
    mov rax, [rdx + 72]
    or rax, [rdx + 80]
    or rax, [rdx + 88]
    or rax, [rdx + 96]
    or rax, [rdx + 104]
    jnz tk_icfg_fatal
    mov rax, [rdx + 16]
    cmp rax, 1
    jb tk_icfg_fatal
    cmp rax, 4
    ja tk_icfg_fatal
    mov [r15 + 80], rax
    cmp qword ptr [rdx + 24], 2
    jne tk_icfg_fatal
    cmp qword ptr [rdx + 48], 2
    jne tk_icfg_fatal
    mov rax, [rdx + 32]
    cmp rax, tk_icfg_FOOTER
    ja tk_icfg_fatal
    mov rcx, tk_icfg_FOOTER
    sub rcx, rax
    mov r8, [rdx + 40]
    cmp r8, rcx
    ja tk_icfg_fatal
    cmp r8, tk_icfg_ROOT_OUTPUT_CAP
    ja tk_icfg_fatal
    mov [r15 + 96], r8
    lea r13, [r15 + tk_icfg_ROOT_WORK]
    add r13, rax
    mov rax, [rdx + 56]
    cmp rax, tk_icfg_FOOTER
    ja tk_icfg_fatal
    mov rcx, tk_icfg_FOOTER
    sub rcx, rax
    mov r9, [rdx + 64]
    cmp r9, rcx
    ja tk_icfg_fatal
    cmp r9, tk_icfg_ROOT_OUTPUT_CAP
    ja tk_icfg_fatal
    mov [r15 + 104], r9
    lea r12, [r15 + tk_icfg_ROOT_WORK]
    add r12, rax
    test r8, r8
    jz tk_icfg_spans_disjoint
    test r9, r9
    jz tk_icfg_spans_disjoint
    lea rax, [r13 + r8]
    cmp r12, rax
    jae tk_icfg_spans_disjoint
    lea rax, [r12 + r9]
    cmp r13, rax
    jb tk_icfg_fatal
tk_icfg_spans_disjoint:
    cmp qword ptr [r15 + 80], 1
    je tk_icfg_start_fs
    cmp qword ptr [r15 + 80], 2
    je tk_icfg_start_json
    cmp qword ptr [r15 + 80], 3
    je tk_icfg_validation_resume
    jmp tk_icfg_identity_resume
tk_icfg_start_fs:
    cmp qword ptr [r15 + 96], tk_icfg_CAP
    ja tk_icfg_fatal
    cmp qword ptr [r15 + 104], tk_icfg_CAP
    ja tk_icfg_fatal
    lea r14, [r15 + tk_icfg_WORK]
    jmp tk_icfg_native_resume
tk_icfg_start_json:
    cmp qword ptr [r15 + 96], 16777216
    ja tk_icfg_fatal
    cmp qword ptr [r15 + 104], 67108864
    ja tk_icfg_fatal
    jmp tk_icfg_json_resume

tk_icfg_cstr_equal:
    xor ecx, ecx
tk_icfg_cstr_equal_next:
    mov al, [rdi + rcx]
    cmp al, [rsi + rcx]
    jne tk_icfg_cstr_not_equal
    test al, al
    jz tk_icfg_cstr_is_equal
    inc rcx
    jmp tk_icfg_cstr_equal_next
tk_icfg_cstr_not_equal:
    xor eax, eax
    ret
tk_icfg_cstr_is_equal:
    mov eax, 1
    ret
tk_icfg_cstr_length:
    xor eax, eax
tk_icfg_cstr_length_next:
    cmp byte ptr [rdi + rax], 0
    je tk_icfg_cstr_length_done
    inc rax
    cmp rax, 131071
    ja tk_icfg_argv_fatal
    jmp tk_icfg_cstr_length_next
tk_icfg_cstr_length_done:
    ret
tk_icfg_find_environment:
    mov r9, rdi
    mov r8, [r15 + 648]
tk_icfg_environment_next:
    mov rdi, [r8]
    test rdi, rdi
    jz tk_icfg_environment_absent
    xor ecx, ecx
tk_icfg_environment_compare:
    mov al, [r9 + rcx]
    test al, al
    jz tk_icfg_environment_equals
    cmp al, [rdi + rcx]
    jne tk_icfg_environment_advance
    inc rcx
    jmp tk_icfg_environment_compare
tk_icfg_environment_equals:
    cmp byte ptr [rdi + rcx], 61
    jne tk_icfg_environment_advance
    lea r10, [rdi + rcx + 1]
    mov rdi, r10
    call tk_icfg_cstr_length
    mov rdx, rax
    mov rax, r10
    ret
tk_icfg_environment_advance:
    add r8, 8
    jmp tk_icfg_environment_next
tk_icfg_environment_absent:
    xor eax, eax
    xor edx, edx
    ret
tk_icfg_argv_fatal:
    jmp tk_intent_contract_failure

tk_icfg_state_option:
    .asciz "--runtime-config"
tk_icfg_env_state:
    .asciz "HEPTA_RUNTIME_STATE_DIR"
tk_icfg_env_xdg:
    .asciz "XDG_STATE_HOME"
tk_icfg_env_home:
    .asciz "HOME"
tk_icfg_env_temp:
    .asciz "TMPDIR"
tk_icfg_newline:
    .byte 10

tk_icfg_effect_dispatch:
    mov rax, 0x3130415346435248 /* HRCFSA01 */
    cmp [r14 + tk_icfg_ACTION], rax
    jne tk_icfg_fatal
    mov rax, [r15 + 16]
    inc rax
    jz tk_icfg_fatal
    cmp [r14 + tk_icfg_ACTION + 8], rax
    jne tk_icfg_fatal
    mov [r15 + 16], rax
    mov rax, [r14 + tk_icfg_ACTION + 56]
    or rax, [r14 + tk_icfg_ACTION + 64]
    or rax, [r14 + tk_icfg_ACTION + 72]
    or rax, [r14 + tk_icfg_ACTION + 80]
    or rax, [r14 + tk_icfg_ACTION + 88]
    or rax, [r14 + tk_icfg_ACTION + 96]
    or rax, [r14 + tk_icfg_ACTION + 104]
    or rax, [r14 + tk_icfg_ACTION + 112]
    or rax, [r14 + tk_icfg_ACTION + 120]
    jnz tk_icfg_fatal
    mov rax, [r14 + tk_icfg_ACTION + 16]
    mov [r15 + 48], rax
    cmp rax, 1
    je tk_icfg_effect_mkdir
    cmp qword ptr [r14 + tk_icfg_ACTION + 32], 0
    jne tk_icfg_fatal
    cmp rax, 2
    je tk_icfg_effect_stat_path
    cmp rax, 3
    je tk_icfg_effect_stat_path
    cmp rax, 4
    je tk_icfg_effect_readlink
    cmp rax, 5
    je tk_icfg_effect_open_lock
    cmp rax, 6
    je tk_icfg_effect_stat_fd
    cmp rax, 7
    je tk_icfg_effect_uid
    cmp rax, 8
    je tk_icfg_effect_chmod_fd
    cmp rax, 9
    je tk_icfg_effect_try_lock
    cmp rax, 10
    je tk_icfg_effect_chmod_path
    cmp rax, 11
    je tk_icfg_effect_close
    cmp rax, 12
    je tk_icfg_effect_open_read
    cmp rax, 13
    je tk_icfg_effect_read
    jmp tk_icfg_fatal

tk_icfg_zero_span:
    mov rax, [r14 + tk_icfg_ACTION + 40]
    or rax, [r14 + tk_icfg_ACTION + 48]
    jnz tk_icfg_fatal
    ret
tk_icfg_no_handle:
    cmp qword ptr [r14 + tk_icfg_ACTION + 24], 0
    jne tk_icfg_fatal
    ret
tk_icfg_path_span:
    call tk_icfg_no_handle
    cmp qword ptr [r14 + tk_icfg_ACTION + 40], tk_icfg_NAME
    jne tk_icfg_fatal
    mov rcx, [r14 + tk_icfg_ACTION + 48]
    cmp rcx, tk_icfg_CAP
    jae tk_icfg_fatal
    lea rsi, [r14 + tk_icfg_NAME]
    cmp byte ptr [rsi + rcx], 0
    jne tk_icfg_fatal
    xor edx, edx
tk_icfg_path_no_nul:
    cmp rdx, rcx
    je tk_icfg_path_nul_checked
    cmp byte ptr [rsi + rdx], 0
    je tk_icfg_fatal
    inc rdx
    jmp tk_icfg_path_no_nul
tk_icfg_path_nul_checked:
    ret

tk_icfg_effect_mkdir:
    mov rax, [r14 + tk_icfg_ACTION + 32]
    cmp rax, 448
    je tk_icfg_mkdir_mode_checked
    cmp rax, 511
    jne tk_icfg_fatal
tk_icfg_mkdir_mode_checked:
    call tk_icfg_path_span
    mov rdi, -100
    mov rdx, [r14 + tk_icfg_ACTION + 32]
    mov eax, 258
    syscall
    jmp tk_icfg_acknowledge
tk_icfg_effect_stat_path:
    call tk_icfg_path_span
    mov rdi, -100
    lea rdx, [r14 + tk_icfg_STAT]
    xor r10d, r10d
    cmp qword ptr [r15 + 48], 3
    jne tk_icfg_stat_path_ready
    mov r10d, 256
tk_icfg_stat_path_ready:
    mov eax, 262
    syscall
    jmp tk_icfg_acknowledge
tk_icfg_effect_readlink:
    call tk_icfg_path_span
    mov rdi, -100
    lea rdx, [r14 + tk_icfg_LINK]
    mov r10d, 1048576
    mov eax, 267
    syscall
    jmp tk_icfg_acknowledge
tk_icfg_effect_open_lock:
    call tk_icfg_path_span
tk_icfg_open_lock_retry:
    mov rdi, -100
    mov edx, 0xa0842 /* RDWR|CREAT|NOFOLLOW|CLOEXEC|NONBLOCK, never truncate. */
    mov r10d, 384
    mov eax, 257
    syscall
    cmp rax, -4
    je tk_icfg_open_lock_retry
    jmp tk_icfg_register_result
tk_icfg_effect_open_read:
    call tk_icfg_path_span
tk_icfg_open_read_retry:
    mov rdi, -100
    mov edx, 0x80000 /* RDONLY|CLOEXEC; std::fs::read follows paths. */
    xor r10d, r10d
    mov eax, 257
    syscall
    cmp rax, -4
    je tk_icfg_open_read_retry
    jmp tk_icfg_register_result
tk_icfg_effect_read:
    mov rax, [r14 + tk_icfg_ACTION + 40]
    cmp rax, 65536
    jb tk_icfg_fatal
    cmp rax, 8454080
    ja tk_icfg_fatal
    mov rdx, [r14 + tk_icfg_ACTION + 48]
    test rdx, rdx
    jz tk_icfg_fatal
    cmp rdx, 65536
    ja tk_icfg_fatal
    add rax, rdx
    cmp rax, 8454081
    ja tk_icfg_fatal
    mov rdi, [r14 + tk_icfg_ACTION + 24]
    call tk_icfg_lookup
    mov rdi, rdx
    mov rsi, [r14 + tk_icfg_ACTION + 40]
    add rsi, r14
    mov rdx, [r14 + tk_icfg_ACTION + 48]
    xor eax, eax
    syscall
    jmp tk_icfg_acknowledge
tk_icfg_effect_stat_fd:
    call tk_icfg_zero_span
    mov rdi, [r14 + tk_icfg_ACTION + 24]
    call tk_icfg_lookup
    sub rsp, 16
    mov [rsp], rdx
    mov rdi, [r15 + tk_CFG_IG]
    call tk_intent_metadata_address
    # The checked shared-cache address is returned in RDX, not RAX.
    mov rdi, [rsp]
    add rsp, 16
    lea rsi, [r14 + tk_icfg_STAT]
    call tk_intent_file_metadata
    jmp tk_icfg_acknowledge
tk_icfg_effect_uid:
    call tk_icfg_zero_span
    call tk_icfg_no_handle
    mov eax, 107
    syscall
    jmp tk_icfg_acknowledge
tk_icfg_effect_chmod_fd:
    call tk_icfg_zero_span
    mov rdi, [r14 + tk_icfg_ACTION + 24]
    call tk_icfg_lookup
    mov rdi, rdx
    mov esi, 384
    mov eax, 91
    syscall
    jmp tk_icfg_acknowledge
tk_icfg_effect_try_lock:
    call tk_icfg_zero_span
    mov rdi, [r14 + tk_icfg_ACTION + 24]
    call tk_icfg_lookup
    mov rdi, rdx
    mov esi, 6 /* LOCK_EX|LOCK_NB */
    mov eax, 73
    syscall
    jmp tk_icfg_acknowledge
tk_icfg_effect_chmod_path:
    call tk_icfg_path_span
    mov rdi, -100
    mov edx, 448
    mov eax, 268
    syscall
    jmp tk_icfg_acknowledge
tk_icfg_effect_close:
    call tk_icfg_zero_span
    mov rdi, [r14 + tk_icfg_ACTION + 24]
    call tk_icfg_retire_close
    jmp tk_icfg_acknowledge

tk_icfg_register_result:
    cmp rax, -4095
    jae tk_icfg_acknowledge
    call tk_icfg_register_fd
tk_icfg_acknowledge:
    xor edx, edx
    cmp rax, -4095
    jb tk_icfg_ack_value
    neg rax
    mov rdx, rax
    xor eax, eax
tk_icfg_ack_value:
    mov [r14 + tk_icfg_ACTION + 72], rdx
    mov [r14 + tk_icfg_ACTION + 80], rax
    mov rax, [r15 + 16]
    mov [r14 + tk_icfg_ACTION + 64], rax
    jmp tk_icfg_native_resume

/* tk_icfg_lookup(id) -> host-owned node and raw fd. No caller pointer is used. */
tk_icfg_lookup:
    test rdi, rdi
    jz tk_icfg_fatal
    mov rax, [r15]
tk_icfg_lookup_next:
    test rax, rax
    jz tk_icfg_fatal
    cmp [rax + 8], rdi
    je tk_icfg_lookup_found
    mov rax, [rax]
    jmp tk_icfg_lookup_next
tk_icfg_lookup_found:
    mov rdx, [rax + 16]
    ret

tk_icfg_register_fd:
    push rax
    cmp qword ptr [r15 + 8], -1
    je tk_icfg_register_overflow
    xor edi, edi
    mov esi, 4096
    mov edx, 3
    mov r10d, 34
    mov r8, -1
    xor r9d, r9d
    mov eax, 9
    syscall
    cmp rax, -4095
    jae tk_icfg_register_failed
    mov rcx, [r15]
    mov [rax], rcx
    mov rcx, [r15 + 8]
    inc rcx
    mov [r15 + 8], rcx
    mov [rax + 8], rcx
    pop rdx
    mov [rax + 16], rdx
    mov [r15], rax
    mov rax, rcx
    ret
tk_icfg_register_overflow:
    mov rax, -75
tk_icfg_register_failed:
    pop rdi
    push rax
    mov eax, 3
    syscall
    pop rax
    ret

tk_icfg_retire_close:
    lea r8, [r15]
    mov rax, [r8]
tk_icfg_retire_next:
    test rax, rax
    jz tk_icfg_fatal
    cmp [rax + 8], rdi
    je tk_icfg_retire_found
    mov r8, rax
    mov rax, [rax]
    jmp tk_icfg_retire_next
tk_icfg_retire_found:
    mov rcx, [rax]
    mov [r8], rcx
    push qword ptr [rax + 16]
    mov rdi, rax
    mov esi, 4096
    mov eax, 11
    syscall
    pop rdi
    mov eax, 3
    syscall
    ret

/* 0 complete; 1 EOF before bytes; 2 truncated/error. */
tk_icfg_read_exact:
    mov r8, rdx
tk_icfg_read_again:
    test rdx, rdx
    jz tk_icfg_exact_ok
    xor eax, eax
    syscall
    cmp rax, -4
    je tk_icfg_read_again
    test rax, rax
    js tk_icfg_exact_error
    jz tk_icfg_exact_eof
    add rsi, rax
    sub rdx, rax
    jmp tk_icfg_read_again
tk_icfg_exact_eof:
    mov eax, 1
    cmp rdx, r8
    je tk_icfg_exact_return
tk_icfg_exact_error:
    mov eax, 2
tk_icfg_exact_return:
    ret
tk_icfg_exact_ok:
    xor eax, eax
    ret
tk_icfg_write_exact:
    test rdx, rdx
    jz tk_icfg_exact_ok
tk_icfg_write_again:
    mov eax, 1
    syscall
    cmp rax, -4
    je tk_icfg_write_again
    test rax, rax
    jle tk_icfg_exact_error
    add rsi, rax
    sub rdx, rax
    jnz tk_icfg_write_again
    jmp tk_icfg_exact_ok

/* HIA regex-only child subtree; no descriptor or effect capability. */
tk_icfg_regex_invoke:
    mov rax, r12
    shl rax, 6
    lea r14, [r15 + rax + tk_icfg_REGEX_CONTEXTS]
    mov rdi, [r14 + 8]
    mov rsi, [r14 + 16]
    mov rdx, [r14 + 24]
    mov rcx, [r14 + 32]
    mov r8, [r14 + 40]
    mov r9, [r14 + 48]
    mov rax, [r14]
    cmp eax, 3
    je tk_icfg_regex_invoke3
    cmp eax, 15
    je tk_icfg_regex_invoke15
    cmp eax, 10
    je tk_icfg_regex_invoke10
    cmp eax, 12
    je tk_icfg_regex_invoke12
    cmp eax, 13
    je tk_icfg_regex_invoke13
    cmp eax, 14
    je tk_icfg_regex_invoke14
    cmp eax, 11
    jne tk_icfg_fatal
    call tk_intent_image_config_regex_unicode_data
    jmp tk_icfg_regex_returned
tk_icfg_regex_invoke3:
    call tk_intent_image_config_validation
    jmp tk_icfg_regex_returned
tk_icfg_regex_invoke15:
    call tk_intent_image_config_regex_controller
    jmp tk_icfg_regex_returned
tk_icfg_regex_invoke10:
    call tk_intent_image_config_regex_syntax
    jmp tk_icfg_regex_returned
tk_icfg_regex_invoke12:
    call tk_intent_image_config_regex_hir
    jmp tk_icfg_regex_returned
tk_icfg_regex_invoke13:
    call tk_intent_image_config_regex_nfa
    jmp tk_icfg_regex_returned
tk_icfg_regex_invoke14:
    call tk_intent_image_config_regex_match
tk_icfg_regex_returned:
    mov edx, eax
    cmp rax, rdx
    jne tk_icfg_fatal
    cmp eax, 0xffffffe0
    je tk_icfg_regex_child_call
    cmp eax, 0xffff0000
    jae tk_icfg_regex_completed_child
    cmp rax, [r14 + 32]
    ja tk_icfg_fatal
tk_icfg_regex_completed_child:
    test r12, r12
    jz tk_icfg_regex_root_result
    dec r12
    sub r14, 64
    mov rbx, [r14 + 40]
    add rbx, [r14 + 48]
    sub rbx, 256
    mov [rbx + 80], rax
    mov rcx, [rbx + 8]
    mov [rbx + 88], rcx
    mov qword ptr [rbx + 96], 1
    mov qword ptr [rbx + 104], 0
    jmp tk_icfg_regex_invoke
tk_icfg_regex_root_result:
    mov r13, [r14 + 8]
    mov r12, [r14 + 24]
    mov r14, [r14 + 40]
    jmp tk_icfg_native_return

tk_icfg_regex_child_call:
    cmp r12, 3
    jae tk_icfg_fatal
    mov rbx, [r14 + 40]
    mov rcx, [r14 + 48]
    lea rbx, [rbx + rcx - 256]
    mov rax, 0x31304c4143414948
    cmp [rbx], rax
    jne tk_icfg_fatal
    mov r10, [r14]
    mov r11, [rbx + 16]
    cmp r10, 3
    je tk_icfg_regex_validation_edge
    cmp r10, 15
    je tk_icfg_regex_root_edge
    cmp r10, 10
    je tk_icfg_regex_data_edge
    cmp r10, 12
    je tk_icfg_regex_data_edge
    cmp r10, 14
    jne tk_icfg_fatal
tk_icfg_regex_data_edge:
    cmp r11, 11
    jne tk_icfg_fatal
    jmp tk_icfg_regex_edge_admitted
tk_icfg_regex_validation_edge:
    cmp r11, 15
    jne tk_icfg_fatal
    jmp tk_icfg_regex_edge_admitted
tk_icfg_regex_root_edge:
    cmp r11, 10
    jb tk_icfg_fatal
    cmp r11, 14
    ja tk_icfg_fatal
    cmp r11, 11
    je tk_icfg_fatal
tk_icfg_regex_edge_admitted:
    cmp qword ptr [rbx + 24], 2
    jne tk_icfg_fatal
    cmp qword ptr [rbx + 48], 2
    jne tk_icfg_fatal
    xor ecx, ecx
tk_icfg_regex_zero_fields:
    cmp qword ptr [rbx + rcx*8 + 72], 0
    jne tk_icfg_fatal
    inc ecx
    cmp ecx, 6
    jb tk_icfg_regex_zero_fields
    mov rax, [r15 + r10*8 + tk_icfg_REGEX_SEQUENCES]
    inc rax
    jz tk_icfg_fatal
    cmp rax, [rbx + 8]
    jne tk_icfg_fatal
    mov rdx, [r14 + 48]
    sub rdx, 256
    mov rsi, [rbx + 32]
    cmp rsi, rdx
    ja tk_icfg_fatal
    sub rdx, rsi
    mov rdi, [rbx + 40]
    cmp rdi, rdx
    ja tk_icfg_fatal
    mov rcx, [rbx + 56]
    mov rdx, [r14 + 48]
    sub rdx, 256
    cmp rcx, rdx
    ja tk_icfg_fatal
    sub rdx, rcx
    mov r8, [rbx + 64]
    cmp r8, rdx
    ja tk_icfg_fatal
    test rdi, rdi
    jz tk_icfg_regex_spans_admitted
    test r8, r8
    jz tk_icfg_regex_spans_admitted
    lea rdx, [rsi + rdi]
    cmp rdx, rcx
    jbe tk_icfg_regex_spans_admitted
    lea rdx, [rcx + r8]
    cmp rdx, rsi
    ja tk_icfg_fatal
tk_icfg_regex_spans_admitted:
    cmp rdi, 134217728
    ja tk_icfg_fatal
    cmp r8, 134217728
    ja tk_icfg_fatal
    cmp r11, 14
    jne tk_icfg_regex_maybe_data
    cmp r8, 8
    ja tk_icfg_fatal
tk_icfg_regex_maybe_data:
    cmp r11, 11
    jne tk_icfg_regex_profile_admitted
    cmp rdi, 8
    ja tk_icfg_fatal
    cmp r8, 171683
    ja tk_icfg_fatal
tk_icfg_regex_profile_admitted:
    mov [r15 + r10*8 + tk_icfg_REGEX_SEQUENCES], rax
    add rsi, [r14 + 40]
    add rcx, [r14 + 40]
    inc r12
    add r14, 64
    mov [r14], r11
    mov [r14 + 8], rsi
    mov [r14 + 16], rdi
    mov [r14 + 24], rcx
    mov [r14 + 32], r8
    mov edx, 268435456
    mov eax, tk_icfg_REGEX_CONTROLLER_WORK
    cmp r11, 15
    je tk_icfg_regex_set_workspace
    mov eax, tk_icfg_REGEX_SYNTAX_WORK
    cmp r11, 10
    je tk_icfg_regex_set_workspace
    mov eax, tk_icfg_REGEX_HIR_WORK
    cmp r11, 12
    je tk_icfg_regex_set_workspace
    mov eax, tk_icfg_REGEX_NFA_WORK
    cmp r11, 13
    je tk_icfg_regex_set_workspace
    mov eax, tk_icfg_REGEX_MATCH_WORK
    mov edx, 33554432
    cmp r11, 14
    je tk_icfg_regex_set_workspace
    mov eax, tk_icfg_REGEX_DATA_WORK
    mov edx, 65536
tk_icfg_regex_set_workspace:
    add rax, r15
    mov [r14 + 40], rax
    mov [r14 + 48], rdx
    jmp tk_icfg_regex_invoke


tk_icfg_fatal:
    jmp tk_intent_contract_failure

.intel_syntax noprefix
.section .text
.equ tk_rlk_G_LOCK, 0
.equ tk_rlk_G_STORE, 4
.equ tk_rlk_G_CHANGED, 8
.equ tk_rlk_G_CLOSING, 12
.equ tk_rlk_G_ARENA, 16
.equ tk_rlk_G_CAPACITY, 24
.equ tk_rlk_G_HEAD, 32
.equ tk_rlk_G_COUNT, 40
.equ tk_rlk_G_LAST, 48
.equ tk_rlk_G_STACK, 64
.equ tk_rlk_G_INPUT, 72
.equ tk_rlk_G_LENGTH, 80
.equ tk_rlk_G_EXIT, 88
.equ tk_rlk_G_NOTIFY, 96
.equ tk_rlk_G_GROWS, 104
.equ tk_rlk_G_REQUEST, 512
.equ tk_rlk_G_OUTPUT, 576
.equ tk_rlk_G_REPLY, 1024
.equ tk_rlk_INPUT_CAP, 8388672
.equ tk_rlk_INPUT_MAP, 8392704
.equ tk_rlk_A_MAGIC, 0
.equ tk_rlk_A_NEXT, 8
.equ tk_rlk_A_GLOBAL, 16
.equ tk_rlk_A_ID, 24
.equ tk_rlk_A_INPUT, 40
.equ tk_rlk_A_LENGTH, 48
.equ tk_rlk_A_STATE, 56
.equ tk_rlk_A_COMMAND, 64
.equ tk_rlk_A_TID, 72
.equ tk_rlk_A_ACTUAL_TID, 80
.equ tk_rlk_A_RECORD, 88
.equ tk_rlk_A_STORE, 96
.equ tk_rlk_A_DIAG, 104
.equ tk_rlk_A_MODE, 112
.equ tk_rlk_A_PANIC, 120
.equ tk_rlk_A_EXPECTED, 128
.equ tk_rlk_A_ATTEMPTS, 136
.equ tk_rlk_A_DROPS, 144
.equ tk_rlk_A_SIGNALS, 152
.equ tk_rlk_A_HELD_GATE, 168
.equ tk_rlk_A_REQUEST, 192
.equ tk_rlk_A_OUTPUT, 256
.equ tk_rlk_A_READY, 384
.equ tk_rlk_A_ALTSTACK, 400
.equ tk_rlk_A_MASK, 448
.equ tk_rlk_ACTOR_MAP, 1126400
.equ tk_rlk_ALT_START, 4096
.equ tk_rlk_ALT_BYTES, 65536
.equ tk_rlk_STACK_GUARD, 69632
.equ tk_rlk_STACK_START, 73728
.equ tk_rlk_STACK_END, 1122304
.equ tk_rlk_ACTOR_MAGIC, 0x315443414c525248

# Fixed trusted callable. Guard memory is private, 512 bytes, kept live by caller.
.equ tk_rlk_G_ROOT_MAGIC, 176
.equ tk_rlk_G_BORROWS, 184
.equ tk_rlk_ROOT_MAGIC, 0x3130544f4f524c52
.equ tk_rlk_GUARD_MAGIC, 0x31304447524c5248
.equ tk_rlk_A_RECORD_GUARD, 512
.equ tk_rlk_A_STORE_GUARD, 1024

# No signal or TLS state is changed by create/acquire/normal drop/close.
tk_result_locks_create:
    push rbx
    push r13
    sub rsp, 8
    xor edi, edi
    mov esi, 4096
    mov edx, 3
    mov r10d, 34
    mov r8, -1
    xor r9d, r9d
    mov eax, 9
    syscall
    cmp rax, -4095
    jae tk_result_locks_resource_failure
    mov r13, rax
    mov rdx, tk_rlk_ROOT_MAGIC
    mov [r13 + tk_rlk_G_ROOT_MAGIC], rdx
    xor edi, edi
    mov esi, 8192
    mov edx, 3
    mov r10d, 34
    mov r8, -1
    xor r9d, r9d
    mov eax, 9
    syscall
    cmp rax, -4095
    jae tk_result_locks_resource_failure
    mov [r13 + tk_rlk_G_ARENA], rax
    mov qword ptr [r13 + tk_rlk_G_CAPACITY], 8192
    lea rdi, [r13 + tk_rlk_G_REQUEST]
    xor esi, esi
    xor edx, edx
    xor ecx, ecx
    call tk_rlk_prepare_request
    lea rdi, [r13 + tk_rlk_G_REQUEST]
    mov esi, 64
    lea rdx, [r13 + tk_rlk_G_OUTPUT]
    call tk_rlk_policy_locked
    cmp eax, 64
    jne tk_result_locks_contract_failure
    cmp qword ptr [r13 + tk_rlk_G_OUTPUT + 8], 0
    jne tk_result_locks_contract_failure
    cmp qword ptr [r13 + tk_rlk_G_OUTPUT + 16], 0
    jne tk_result_locks_contract_failure
    mov rax, r13
    add rsp, 8
    pop r13
    pop rbx
    ret

# rdi root, rsi guard512 (all zero), rdx id bytes, rcx length.
tk_result_locks_record_lock:
    mov r8d, 1
    jmp tk_rlk_callable_lock
# rdi root, rsi guard512 (all zero).
tk_result_locks_store_lock:
    xor edx, edx
    xor ecx, ecx
    mov r8d, 2
tk_rlk_callable_lock:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp, 40
    mov r13, rdi
    mov r15, rsi
    mov [rsp], rdx
    mov [rsp + 8], rcx
    mov [rsp + 16], r8
    cmp rcx, 8388608
    ja tk_rlk_callable_invalid
    mov rax, tk_rlk_ROOT_MAGIC
    cmp [r13 + tk_rlk_G_ROOT_MAGIC], rax
    jne tk_result_locks_contract_failure
    mov rdi, r15
    mov ecx, 64
    xor eax, eax
tk_rlk_callable_check_zero:
    or rax, [rdi]
    add rdi, 8
    dec ecx
    jnz tk_rlk_callable_check_zero
    test rax, rax
    jnz tk_result_locks_contract_failure
    mov rax, tk_rlk_GUARD_MAGIC
    mov [r15 + tk_rlk_A_MAGIC], rax
    mov [r15 + tk_rlk_A_GLOBAL], r13
    mov rax, [rsp + 16]
    mov [r15 + tk_rlk_A_MODE], rax
    mov eax, 186
    syscall
    test rax, rax
    jle tk_result_locks_contract_failure
    mov [r15 + tk_rlk_A_ACTUAL_TID], rax
    mov r12, [rsp + 8]
    add r12, 64
    mov [r15 + tk_rlk_A_LENGTH], r12
    add r12, 4095
    and r12, -4096
    xor edi, edi
    mov rsi, r12
    mov edx, 3
    mov r10d, 34
    mov r8, -1
    xor r9d, r9d
    mov eax, 9
    syscall
    cmp rax, -4095
    jae tk_result_locks_resource_failure
    mov [r15 + tk_rlk_A_INPUT], rax
    mov rdi, rax
    mov esi, 1
    cmp qword ptr [r15 + tk_rlk_A_MODE], 2
    jne tk_rlk_callable_request_op
    mov esi, 3
tk_rlk_callable_request_op:
    xor edx, edx
    xor ecx, ecx
    call tk_rlk_prepare_request
    mov rdi, [r15 + tk_rlk_A_INPUT]
    mov rcx, [rsp + 8]
    mov [rdi + 32], rcx
    add rdi, 64
    mov rsi, [rsp]
    rep movsb
    mov rdi, [r15 + tk_rlk_A_INPUT]
    mov rsi, r12
    mov edx, 1
    mov eax, 10
    syscall
    test rax, rax
    jnz tk_result_locks_resource_failure
    lea rdi, [r13 + tk_rlk_G_LOCK]
    call tk_rlk_mutex_lock
    add qword ptr [r13 + tk_rlk_G_BORROWS], 1
    jc tk_result_locks_contract_failure
    cmp qword ptr [r15 + tk_rlk_A_MODE], 2
    je tk_rlk_callable_begin_store
tk_rlk_callable_record_try_locked:
    add qword ptr [r15 + tk_rlk_A_ATTEMPTS], 1
    mov rdi, [r15 + tk_rlk_A_INPUT]
    mov rsi, [r15 + tk_rlk_A_LENGTH]
    lea rdx, [r15 + tk_rlk_A_OUTPUT]
    call tk_rlk_policy_locked
    cmp eax, 64
    jne tk_rlk_callable_invalid_locked
    cmp qword ptr [r15 + tk_rlk_A_OUTPUT + 8], 1
    je tk_rlk_callable_record_wait
    cmp qword ptr [r15 + tk_rlk_A_OUTPUT + 8], 0
    jne tk_result_locks_contract_failure
    mov ebx, [r15 + tk_rlk_A_OUTPUT + 16]
    test ebx, ebx
    jnz tk_rlk_callable_failure_locked
    mov rax, [r15 + tk_rlk_A_OUTPUT + 24]
    test rax, rax
    jz tk_result_locks_contract_failure
    mov [r15 + tk_rlk_A_RECORD], rax
    jmp tk_rlk_callable_acquired_locked
tk_rlk_callable_record_wait:
    mov edx, [r13 + tk_rlk_G_CHANGED]
    mov [r15 + tk_rlk_A_EXPECTED], rdx
    lea rdi, [r13 + tk_rlk_G_LOCK]
    call tk_rlk_mutex_unlock
    lea rdi, [r13 + tk_rlk_G_CHANGED]
    mov edx, [r15 + tk_rlk_A_EXPECTED]
    call tk_rlk_wait_value
    lea rdi, [r13 + tk_rlk_G_LOCK]
    call tk_rlk_mutex_lock
    jmp tk_rlk_callable_record_try_locked
tk_rlk_callable_begin_store:
    lea rdi, [r13 + tk_rlk_G_LOCK]
    call tk_rlk_mutex_unlock
    lea rdi, [r13 + tk_rlk_G_STORE]
    call tk_rlk_mutex_lock
    lea rdi, [r13 + tk_rlk_G_LOCK]
    call tk_rlk_mutex_lock
    mov rdi, [r15 + tk_rlk_A_INPUT]
    mov esi, 64
    lea rdx, [r15 + tk_rlk_A_OUTPUT]
    call tk_rlk_policy_locked
    cmp eax, 64
    jne tk_result_locks_contract_failure
    cmp qword ptr [r15 + tk_rlk_A_OUTPUT + 8], 0
    jne tk_result_locks_contract_failure
    mov ebx, [r15 + tk_rlk_A_OUTPUT + 16]
    test ebx, ebx
    jnz tk_rlk_callable_store_failed
    mov rax, [r15 + tk_rlk_A_OUTPUT + 24]
    test rax, rax
    jz tk_result_locks_contract_failure
    mov [r15 + tk_rlk_A_STORE], rax
tk_rlk_callable_acquired_locked:
    mov dword ptr [r15 + tk_rlk_A_STATE], 4
    lea rdi, [r13 + tk_rlk_G_LOCK]
    call tk_rlk_mutex_unlock
    xor eax, eax
    jmp tk_rlk_callable_return
tk_rlk_callable_store_failed:
    lea rdi, [r13 + tk_rlk_G_LOCK]
    call tk_rlk_mutex_unlock
    lea rdi, [r13 + tk_rlk_G_STORE]
    call tk_rlk_mutex_unlock
    lea rdi, [r13 + tk_rlk_G_LOCK]
    call tk_rlk_mutex_lock
    jmp tk_rlk_callable_failure_locked
tk_rlk_callable_invalid_locked:
    cmp eax, 0xffffffff
    jne tk_result_locks_contract_failure
    mov ebx, 3
tk_rlk_callable_failure_locked:
    cmp qword ptr [r13 + tk_rlk_G_BORROWS], 0
    je tk_result_locks_contract_failure
    sub qword ptr [r13 + tk_rlk_G_BORROWS], 1
    lea rdi, [r13 + tk_rlk_G_LOCK]
    call tk_rlk_mutex_unlock
    mov [r15 + tk_rlk_A_DIAG], rbx
    mov dword ptr [r15 + tk_rlk_A_STATE], 6
    call tk_rlk_callable_retire_input
    mov eax, ebx
    jmp tk_rlk_callable_return
tk_rlk_callable_invalid:
    mov eax, 0xffffffff
tk_rlk_callable_return:
    add rsp, 40
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

tk_rlk_callable_retire_input:
    mov rdi, [r15 + tk_rlk_A_INPUT]
    mov rsi, [r15 + tk_rlk_A_LENGTH]
    add rsi, 4095
    and rsi, -4096
    mov qword ptr [r15 + tk_rlk_A_INPUT], 0
    mov qword ptr [r15 + tk_rlk_A_MAGIC], 0
    mov eax, 11
    syscall
    test rax, rax
    jnz tk_result_locks_resource_failure
    ret
# Normal native caller entry: no serialized panicking flag exists.
tk_result_locks_drop:
    xor r8d, r8d
    jmp tk_rlk_callable_drop
tk_rlk_callable_drop:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp, 8
    mov ebx, r8d
    mov r15, rdi
    mov rax, tk_rlk_GUARD_MAGIC
    cmp [r15 + tk_rlk_A_MAGIC], rax
    jne tk_result_locks_contract_failure
    cmp dword ptr [r15 + tk_rlk_A_STATE], 4
    jne tk_result_locks_contract_failure
    mov r13, [r15 + tk_rlk_A_GLOBAL]
    mov rax, tk_rlk_ROOT_MAGIC
    cmp [r13 + tk_rlk_G_ROOT_MAGIC], rax
    jne tk_result_locks_contract_failure
    cmp qword ptr [r15 + tk_rlk_A_MODE], 1
    je tk_rlk_callable_drop_record
    cmp qword ptr [r15 + tk_rlk_A_MODE], 2
    jne tk_result_locks_contract_failure
    mov eax, 186
    syscall
    cmp [r15 + tk_rlk_A_ACTUAL_TID], rax
    jne tk_result_locks_contract_failure
    cmp qword ptr [r15 + tk_rlk_A_RECORD], 0
    jne tk_result_locks_contract_failure
    mov r12, [r15 + tk_rlk_A_STORE]
    mov r14d, 4
    jmp tk_rlk_callable_drop_locked
tk_rlk_callable_drop_record:
    cmp qword ptr [r15 + tk_rlk_A_STORE], 0
    jne tk_result_locks_contract_failure
    mov r12, [r15 + tk_rlk_A_RECORD]
    mov r14d, 2
tk_rlk_callable_drop_locked:
    test r12, r12
    jz tk_result_locks_contract_failure
    lea rdi, [r13 + tk_rlk_G_LOCK]
    call tk_rlk_mutex_lock
    lea rdi, [r15 + tk_rlk_A_REQUEST]
    mov rsi, r14
    mov rdx, r12
    mov rcx, rbx
    call tk_rlk_prepare_request
    lea rdi, [r15 + tk_rlk_A_REQUEST]
    mov esi, 64
    lea rdx, [r15 + tk_rlk_A_OUTPUT]
    call tk_rlk_policy_locked
    cmp eax, 64
    jne tk_result_locks_contract_failure
    cmp qword ptr [r15 + tk_rlk_A_OUTPUT + 8], 0
    jne tk_result_locks_contract_failure
    cmp qword ptr [r15 + tk_rlk_A_OUTPUT + 16], 0
    jne tk_result_locks_contract_failure
    mov qword ptr [r15 + tk_rlk_A_RECORD], 0
    mov qword ptr [r15 + tk_rlk_A_STORE], 0
    cmp qword ptr [r13 + tk_rlk_G_BORROWS], 0
    je tk_result_locks_contract_failure
    sub qword ptr [r13 + tk_rlk_G_BORROWS], 1
    mov eax, 5
    test ebx, ebx
    jz tk_rlk_callable_drop_state
    mov eax, 7
tk_rlk_callable_drop_state:
    mov [r15 + tk_rlk_A_STATE], eax
    lea rdi, [r13 + tk_rlk_G_LOCK]
    call tk_rlk_mutex_unlock
    cmp r14d, 4
    jne tk_rlk_callable_drop_notify
    lea rdi, [r13 + tk_rlk_G_STORE]
    call tk_rlk_mutex_unlock
    jmp tk_rlk_callable_drop_retire
tk_rlk_callable_drop_notify:
    call tk_rlk_changed_notify_all
tk_rlk_callable_drop_retire:
    call tk_rlk_callable_retire_input
    xor eax, eax
    add rsp, 8
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

# The lifetime owner must first join all possible callers; never concurrent destroy.
# Busy is returned without freeing any mapping. No poison is reset for reuse.
tk_result_locks_close:
    push rbx
    push r12
    push r13
    mov r13, rdi
    mov rax, tk_rlk_ROOT_MAGIC
    cmp [r13 + tk_rlk_G_ROOT_MAGIC], rax
    jne tk_result_locks_contract_failure
    lea rdi, [r13 + tk_rlk_G_LOCK]
    call tk_rlk_mutex_lock
    mov rax, [r13 + tk_rlk_G_BORROWS]
    or rax, [r13 + tk_rlk_G_COUNT]
    or rax, [r13 + tk_rlk_G_HEAD]
    jnz tk_rlk_callable_close_busy
    lea rdi, [r13 + tk_rlk_G_REQUEST]
    mov esi, 7
    xor edx, edx
    xor ecx, ecx
    call tk_rlk_prepare_request
    lea rdi, [r13 + tk_rlk_G_REQUEST]
    mov esi, 64
    lea rdx, [r13 + tk_rlk_G_OUTPUT]
    call tk_rlk_policy_locked
    cmp eax, 64
    jne tk_result_locks_contract_failure
    mov rax, [r13 + tk_rlk_G_OUTPUT + 8]
    or rax, [r13 + tk_rlk_G_OUTPUT + 16]
    or rax, [r13 + tk_rlk_G_OUTPUT + 32]
    or rax, [r13 + tk_rlk_G_OUTPUT + 48]
    jnz tk_result_locks_contract_failure
    cmp dword ptr [r13 + tk_rlk_G_STORE], 0
    jne tk_result_locks_contract_failure
    mov qword ptr [r13 + tk_rlk_G_ROOT_MAGIC], 0
    lea rdi, [r13 + tk_rlk_G_LOCK]
    call tk_rlk_mutex_unlock
    mov rdi, [r13 + tk_rlk_G_ARENA]
    mov rsi, [r13 + tk_rlk_G_CAPACITY]
    mov eax, 11
    syscall
    test rax, rax
    jnz tk_result_locks_resource_failure
    mov rdi, r13
    mov esi, 4096
    mov eax, 11
    syscall
    test rax, rax
    jnz tk_result_locks_resource_failure
    xor eax, eax
    jmp tk_rlk_callable_close_return
tk_rlk_callable_close_busy:
    lea rdi, [r13 + tk_rlk_G_LOCK]
    call tk_rlk_mutex_unlock
    mov eax, 0xfffffffd
tk_rlk_callable_close_return:
    pop r13
    pop r12
    pop rbx
    ret


# Original Rust 1.95 wait semantics: WAIT_BITSET|PRIVATE, full mask, EINTR retry.
tk_rlk_mutex_lock:
    xor eax, eax
    mov edx, 1
    lock cmpxchg dword ptr [rdi], edx
    jz tk_rlk_mutex_acquired
tk_rlk_mutex_contended:
    mov eax, 2
    xchg eax, dword ptr [rdi]
    test eax, eax
    jz tk_rlk_mutex_acquired
    mov edx, 2
    sub rsp, 8
    call tk_rlk_wait_value
    add rsp, 8
    jmp tk_rlk_mutex_contended
tk_rlk_mutex_acquired:
    ret
tk_rlk_mutex_unlock:
    xor eax, eax
    xchg eax, dword ptr [rdi]
    cmp eax, 2
    jne tk_rlk_mutex_unlocked
    mov esi, 129
    mov edx, 1
    xor r10d, r10d
    xor r8d, r8d
    xor r9d, r9d
    mov eax, 202
    syscall
tk_rlk_mutex_unlocked:
    ret
tk_rlk_changed_notify_all:
    lock add dword ptr [r13 + tk_rlk_G_CHANGED], 1
    lock add qword ptr [r13 + tk_rlk_G_NOTIFY], 1
    lea rdi, [r13 + tk_rlk_G_CHANGED]
    mov esi, 129
    mov edx, 0x7fffffff
    xor r10d, r10d
    xor r8d, r8d
    xor r9d, r9d
    mov eax, 202
    syscall
    ret
tk_rlk_wait_value:
    cmp dword ptr [rdi], edx
    jne tk_rlk_wait_value_done
    mov esi, 137
    xor r10d, r10d
    xor r8d, r8d
    mov r9d, -1
    mov eax, 202
    syscall
    cmp rax, -4
    je tk_rlk_wait_value
tk_rlk_wait_value_done:
    ret
tk_rlk_wait_private_zero:
    cmp dword ptr [rdi], 0
    jne tk_rlk_private_wait_done
    xor edx, edx
    sub rsp, 8
    call tk_rlk_wait_value
    add rsp, 8
    jmp tk_rlk_wait_private_zero
tk_rlk_private_wait_done:
    ret
tk_rlk_wake_private_all:
    mov esi, 129
    mov edx, 0x7fffffff
    xor r10d, r10d
    xor r8d, r8d
    xor r9d, r9d
    mov eax, 202
    syscall
    ret


# Global short-operation gate must be held. No arena pointer escapes a call.
tk_rlk_policy_locked:
    push rdi
    push rsi
    push rdx
tk_rlk_policy_retry:
    mov rdi, [rsp + 16]
    mov rsi, [rsp + 8]
    mov rdx, [rsp]
    mov ecx, 64
    mov r8, [r13 + tk_rlk_G_ARENA]
    mov r9, [r13 + tk_rlk_G_CAPACITY]
    .byte 0xe8
tk_result_locks_policy_call_displacement:
    .long tk_intent_image_result_locks - . - 4
    mov ecx, eax
    cmp rax, rcx
    jne tk_result_locks_contract_failure
    cmp eax, 64
    jne tk_rlk_policy_return
    mov rdx, [rsp]
    mov rax, 0x313030524c525248
    cmp [rdx], rax
    jne tk_result_locks_contract_failure
    cmp qword ptr [rdx + 8], 2
    jne tk_rlk_policy_done
    cmp qword ptr [rdx + 16], 0
    jne tk_result_locks_contract_failure
    mov rsi, [rdx + 24]
    cmp rsi, [r13 + tk_rlk_G_CAPACITY]
    jbe tk_result_locks_contract_failure
    mov rax, 0x7ffffffffffff000
    cmp rsi, rax
    ja tk_result_locks_contract_failure
    add rsi, 4095
    and rsi, -4096
    mov rdx, rsi
    mov rdi, [r13 + tk_rlk_G_ARENA]
    mov rsi, [r13 + tk_rlk_G_CAPACITY]
    mov r10d, 1
    xor r8d, r8d
    mov eax, 25
    syscall
    cmp rax, -4095
    jae tk_result_locks_resource_failure
    mov [r13 + tk_rlk_G_ARENA], rax
    mov [r13 + tk_rlk_G_CAPACITY], rdx
    add qword ptr [r13 + tk_rlk_G_GROWS], 1
    jmp tk_rlk_policy_retry
tk_rlk_policy_done:
    mov eax, 64
tk_rlk_policy_return:
    add rsp, 24
    ret

tk_rlk_prepare_request:
    mov rax, 0x313030514c525248
    mov [rdi], rax
    mov [rdi + 8], rsi
    mov [rdi + 16], rdx
    mov [rdi + 24], rcx
    mov qword ptr [rdi + 32], 0
    mov qword ptr [rdi + 40], 0
    mov qword ptr [rdi + 48], 0
    mov qword ptr [rdi + 56], 0
    ret


tk_intent_image_result_locks:
    jmp qword ptr [rip + tk_intent_image_slot_result_locks]

tk_intent_image_result_store:
    jmp qword ptr [rip + tk_intent_image_slot_result_store]

tk_intent_image_result_publish:
    jmp qword ptr [rip + tk_intent_image_slot_result_publish]

tk_intent_image_result_metadata:
    jmp qword ptr [rip + tk_intent_image_slot_result_metadata]

tk_intent_image_result_directory:
    jmp qword ptr [rip + tk_intent_image_slot_result_directory]

tk_intent_image_storage_json:
    jmp qword ptr [rip + tk_intent_image_slot_storage_json]

tk_intent_image_binary_codec:
    jmp qword ptr [rip + tk_intent_image_slot_binary_codec]

tk_intent_image_record_io:
    jmp qword ptr [rip + tk_intent_image_slot_record_io]

tk_intent_image_record_validation:
    jmp qword ptr [rip + tk_intent_image_slot_record_validation]

tk_intent_image_retention:
    jmp qword ptr [rip + tk_intent_image_slot_retention]

tk_intent_image_value:
    jmp qword ptr [rip + tk_intent_image_slot_value]

tk_intent_image_typed:
    jmp qword ptr [rip + tk_intent_image_slot_typed]

tk_intent_image_request:
    jmp qword ptr [rip + tk_intent_image_slot_request]

tk_intent_image_safe_dto:
    jmp qword ptr [rip + tk_intent_image_slot_safe_dto]

tk_intent_image_intent:
    jmp qword ptr [rip + tk_intent_image_slot_intent]

tk_intent_image_config_owner:
    jmp qword ptr [rip + tk_intent_image_slot_config_owner]

tk_intent_image_config_fs:
    jmp qword ptr [rip + tk_intent_image_slot_config_fs]

tk_intent_image_config_json:
    jmp qword ptr [rip + tk_intent_image_slot_config_json]

tk_intent_image_config_validation:
    jmp qword ptr [rip + tk_intent_image_slot_config_validation]

tk_intent_image_config_identity:
    jmp qword ptr [rip + tk_intent_image_slot_config_identity]

tk_intent_image_config_regex_syntax:
    jmp qword ptr [rip + tk_intent_image_slot_config_regex_syntax]

tk_intent_image_config_regex_unicode_data:
    jmp qword ptr [rip + tk_intent_image_slot_config_regex_unicode_data]

tk_intent_image_config_regex_hir:
    jmp qword ptr [rip + tk_intent_image_slot_config_regex_hir]

tk_intent_image_config_regex_nfa:
    jmp qword ptr [rip + tk_intent_image_slot_config_regex_nfa]

tk_intent_image_config_regex_match:
    jmp qword ptr [rip + tk_intent_image_slot_config_regex_match]

tk_intent_image_config_regex_controller:
    jmp qword ptr [rip + tk_intent_image_slot_config_regex_controller]

.balign 8
tk_intent_image_slot_result_locks:
    .quad 0
tk_intent_image_slot_result_store:
    .quad 0
tk_intent_image_slot_result_publish:
    .quad 0
tk_intent_image_slot_result_metadata:
    .quad 0
tk_intent_image_slot_result_directory:
    .quad 0
tk_intent_image_slot_storage_json:
    .quad 0
tk_intent_image_slot_binary_codec:
    .quad 0
tk_intent_image_slot_record_io:
    .quad 0
tk_intent_image_slot_record_validation:
    .quad 0
tk_intent_image_slot_retention:
    .quad 0
tk_intent_image_slot_value:
    .quad 0
tk_intent_image_slot_typed:
    .quad 0
tk_intent_image_slot_request:
    .quad 0
tk_intent_image_slot_safe_dto:
    .quad 0
tk_intent_image_slot_intent:
    .quad 0
tk_intent_image_slot_config_owner:
    .quad 0
tk_intent_image_slot_config_fs:
    .quad 0
tk_intent_image_slot_config_json:
    .quad 0
tk_intent_image_slot_config_validation:
    .quad 0
tk_intent_image_slot_config_identity:
    .quad 0
tk_intent_image_slot_config_regex_syntax:
    .quad 0
tk_intent_image_slot_config_regex_unicode_data:
    .quad 0
tk_intent_image_slot_config_regex_hir:
    .quad 0
tk_intent_image_slot_config_regex_nfa:
    .quad 0
tk_intent_image_slot_config_regex_match:
    .quad 0
tk_intent_image_slot_config_regex_controller:
    .quad 0

.balign 8
pub_image_owner:
    .quad 0
pub_image_fs:
    .quad 0
pub_image_json:
    .quad 0
pub_image_validation:
    .quad 0
pub_image_identity:
    .quad 0
pub_image_mcp:
    .quad 0
pub_image_execution:
    .quad 0
pub_image_execution_json:
    .quad 0
pub_image_execution_core:
    .quad 0
pub_image_message:
    .quad 0
pub_image_regex_syntax:
    .quad 0
pub_image_regex_unicode_data:
    .quad 0
pub_image_regex_hir:
    .quad 0
pub_image_regex_nfa:
    .quad 0
pub_image_regex_match:
    .quad 0
pub_image_regex_controller:
    .quad 0
pub_image_connection:
    .quad 0
ex_image_outer:
    .quad 0
ex_image_mapper:
    .quad 0
ex_image_wire:
    .quad 0
images:
