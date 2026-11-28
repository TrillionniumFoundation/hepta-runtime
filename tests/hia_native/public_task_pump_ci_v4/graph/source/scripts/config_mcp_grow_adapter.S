/* Seventeen fixed HIA images. Administrator startup is followed by newline MCP.
 * Image 10 owns text publication; six regex images use their private local selectors. */
.intel_syntax noprefix
.section .text
.global _start
.global regex_controller_call_displacement
.global regex_match_call_displacement
.global regex_nfa_call_displacement
.global regex_hir_call_displacement
.global regex_unicode_data_call_displacement
.global regex_syntax_call_displacement
.global value_call_displacement
.global execution_call_displacement
.global execution_json_call_displacement
.global execution_core_call_displacement
.global mcp_call_displacement
.global owner_call_displacement
.global fs_call_displacement
.global json_call_displacement
.global identity_call_displacement
.global validation_call_displacement
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
.equ MAP_BYTES, 3707834368
.equ REGEX_CONTEXTS, 2048
.equ REGEX_SEQUENCES, 2560
.equ CAP, 8388608
.equ WCAP, 33554432
.equ FOOTER, 268435200
.equ ACTION, 512

.equ CG_OWNER, 1024
.equ CG_FS, 1040
.equ CG_JSON, 1056
.equ CG_CHILDOUT, 1072
.equ CG_ROOTOUT, 1088
.equ CG_VALIDATION, 1104
.equ CG_DELIVERY, 1120
.equ CG_EXTENT, 1128
.equ CG_TRACE, 1144
.equ CG_SEQUENCE, 1152
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
    call cfg_initialize_borrows
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
    mov rax, [r15 + CG_OWNER]
    add rax, [r15 + CG_OWNER + 8]
    sub rax, 256
    mov qword ptr [rax + 120], 0
    jmp owner_resume

/* Only line framing occurs here. All JSON and tools stay in HIA. */
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
    cmp rcx, 8388608
    ja fatal
    mov [r15 + 24], rcx
    inc rcx
    mov [r15 + 816], rcx
    jmp mcp_resume
frame_need_input:
    mov [r15 + 808], rcx
    cmp qword ptr [r15 + 824], 0
    jne frame_final_line
    cmp rdx, 8388609
    jae fatal
    mov ecx, 8388609
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
    cmp rdx, 8388608
    ja fatal
    mov [r15 + 24], rdx
    mov [r15 + 816], rdx
    jmp mcp_resume
frame_eof:
    mov qword ptr [r15 + 24], 0
    mov rax, [r15 + CG_OWNER]
    add rax, [r15 + CG_OWNER + 8]
    sub rax, 256
    mov qword ptr [rax + 120], 2
owner_resume:
    mov qword ptr [r15 + 80], 0
    lea r13, [r15 + INPUT]
    mov r12, [r15 + CG_ROOTOUT]
    mov rsi, [r15 + 24]
    mov rcx, [r15 + CG_ROOTOUT + 8]
    cmp qword ptr [r15 + 784], 0
    je owner_context_ready
    mov r13, [r15 + 832]
    mov rsi, [r15 + 840]
    mov r12, [r15 + 848]
    mov rcx, [r15 + 856]
owner_context_ready:
    cmp qword ptr [r15 + CG_DELIVERY], 0
    je cfg_owner_input_ready
    mov r13, [r15 + CG_CHILDOUT]
    mov rsi, [r15 + CG_EXTENT]
cfg_owner_input_ready:
    mov r14, [r15 + CG_OWNER]
    mov rdi, r13
    mov rdx, r12
    mov r8, r14
    mov r9, [r15 + CG_OWNER + 8]
    .byte 0xe8
owner_call_displacement:
    .long 0
    jmp native_return
mcp_resume:
    mov qword ptr [r15 + 80], 5
    lea r13, [r15 + INPUT]
    lea r12, [r15 + OUTPUT]
    lea r14, [r15 + MCP_WORK]
    mov rdi, r13
    mov rsi, [r15 + 24]
    mov rdx, r12
    mov ecx, ROOT_OUTPUT_CAP
    mov r8, r14
    mov r9d, ROOT_WCAP
    .byte 0xe8
mcp_call_displacement:
    .long 0
    jmp native_return
native_resume:
    cmp qword ptr [r15 + 80], 1
    jne fatal
    mov r14, [r15 + CG_FS]
    mov rdi, r13
    mov rsi, [r15 + 96]
    mov r12, [r15 + CG_CHILDOUT]
    mov rdx, r12
    mov rcx, [r15 + CG_CHILDOUT + 8]
    mov [r15 + 104], rcx
    mov r8, r14
    mov r9, [r15 + CG_FS + 8]
    .byte 0xe8
fs_call_displacement:
    .long 0
    jmp native_return
json_resume:
    mov r14, [r15 + CG_JSON]
    mov rdi, r13
    mov rsi, [r15 + 96]
    mov r12, [r15 + CG_CHILDOUT]
    mov rdx, r12
    mov rcx, [r15 + CG_CHILDOUT + 8]
    mov [r15 + 104], rcx
    mov r8, r14
    mov r9, [r15 + CG_JSON + 8]
    .byte 0xe8
json_call_displacement:
    .long 0
    jmp native_return
identity_resume:
    lea r14, [r15 + SHA_WORK]
    mov rdi, r13
    mov rsi, [r15 + 96]
    mov rdx, r12
    mov rcx, [r15 + 104]
    mov r8, r14
    mov r9d, ROOT_WCAP
    .byte 0xe8
identity_call_displacement:
    .long 0
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
    mov rax, [r15 + CG_VALIDATION]
    mov [r14 + 40], rax
    mov rax, [r15 + CG_VALIDATION + 8]
    mov [r14 + 48], rax
    xor r12d, r12d
    jmp regex_invoke
native_return:
    mov edx, eax
    cmp rax, rdx
    jne fatal
    cmp eax, 0xffffffd0
    je cfg_native_growth
    mov edx, 0xffffffe0
    cmp rax, rdx
    je call_dispatch
    mov edx, 0xfffffff0
    cmp rax, rdx
    je effect_dispatch_checked
    cmp qword ptr [r15 + 80], 5
    je mcp_completed
    cmp qword ptr [r15 + 80], 9
    je mcp_value_completed
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
    mov qword ptr [r15 + CG_DELIVERY], 0
    cmp rax, [r15 + CG_ROOTOUT + 8]
    ja fatal
    mov rcx, [r15 + CG_OWNER + 8]
    lea rdx, [r14 + rcx - 256]
    cmp qword ptr [rdx + 120], 2
    je shutdown_completed
    cmp qword ptr [rdx + 120], 0
    je startup_completed
    jmp fatal /* No external binary-query production path. */
mcp_completed:
    cmp eax, 0xffffffd1
    je mcp_publication
    cmp rax, ROOT_OUTPUT_CAP
    ja fatal
    test rax, rax
    jz frame_next
    mov rdx, rax
    mov edi, 1
    lea rsi, [r15 + OUTPUT]
    call write_exact
    test eax, eax
    jnz fatal
    mov edi, 1
    lea rsi, [rip + newline]
    mov edx, 1
    call write_exact
    test eax, eax
    jnz fatal
    jmp frame_next
mcp_owner_completed:
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
    jz frame_next
    cmp rax, 32
    jb fatal
    mov rsi, [r15 + CG_ROOTOUT]
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
    xor ecx, ecx
    mov edx, 0xffff0000
    cmp rax, rdx
    jae child_result_ok
    cmp rax, [r15 + CG_CHILDOUT + 8]
    ja fatal
    mov rcx, rax
child_result_ok:
    mov [r15 + CG_EXTENT], rcx
    mov qword ptr [r15 + CG_DELIVERY], 1
    mov rdx, [r15 + CG_OWNER]
    add rdx, [r15 + CG_OWNER + 8]
    sub rdx, 256
    mov [rdx + 80], rax
    mov [rdx + 128], rcx
    mov rax, [r15 + 88]
    mov [rdx + 88], rax
    mov qword ptr [rdx + 96], 1
    mov qword ptr [rdx + 112], 1
    jmp owner_resume

/* Closed calls from MCP5 to installed config0, execution6 and Value9.
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
    cmp rax, 9
    je mcp_value_call
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
    mov rax, [r15 + CG_OWNER]
    add rax, [r15 + CG_OWNER + 8]
    sub rax, 256
    mov qword ptr [rax + 120], 1
    jmp owner_resume

mcp_value_call:
    cmp qword ptr [rdx + 32], 167780352
    jne fatal
    cmp qword ptr [rdx + 56], 33554456
    jne fatal
    mov rsi, [rdx + 40]
    cmp rsi, 24
    jb fatal
    cmp rsi, 8388632
    ja fatal
    lea r13, [r15 + MCP_WORK + 167780352]
    mov rax, 0x31304c41564a5348
    cmp [r13], rax
    jne fatal
    cmp qword ptr [r13 + 8], 1
    jne fatal
    mov rax, rsi
    sub rax, 24
    cmp [r13 + 16], rax
    jne fatal
    mov qword ptr [r15 + 80], 9
    lea r12, [r15 + MCP_WORK + 33554456]
    lea r14, [r15 + VALUE_WORK]
    mov rdi, r13
    mov rdx, r12
    mov ecx, 67108864
    mov r8, r14
    mov r9d, ROOT_WCAP
    .byte 0xe8
value_call_displacement:
    .long 0
    jmp native_return

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
    jne fatal
    mov rax, rsi
    sub rax, 24
    cmp [r13 + 16], rax
    jne fatal
    mov [r15 + 880], rsi
    mov qword ptr [r15 + 872], 1
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
    .byte 0xe8
execution_call_displacement:
    .long 0
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
    mov rax, [r15 + CG_OWNER]
    add rax, [r15 + CG_OWNER + 8]
    sub rax, 256
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
    .byte 0xe8
execution_json_call_displacement:
    .long 0
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
    .byte 0xe8
execution_core_call_displacement:
    .long 0
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
mcp_value_completed:
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
    mov qword ptr [r15 + CG_DELIVERY], 0
    mov rdx, [r15 + CG_OWNER]
    mov rcx, [r15 + CG_OWNER + 8]
    lea rdx, [rdx + rcx - 256]
    mov rax, 0x31304c4143414948
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
    or rax, [rdx + 112]
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
    mov rcx, [r15 + CG_OWNER + 8]
    sub rcx, 256
    mov rax, [rdx + 32]
    cmp rax, rcx
    ja fatal
    sub rcx, rax
    mov r8, [rdx + 40]
    cmp r8, rcx
    ja fatal
    mov [r15 + 96], r8
    mov r13, [r15 + CG_OWNER]
    add r13, rax
    mov rax, [rdx + 56]
    mov rcx, [r15 + CG_OWNER + 8]
    sub rcx, 256
    cmp rax, rcx
    ja fatal
    sub rcx, rax
    mov rsi, [rdx + 64]
    cmp rsi, rcx
    ja fatal
    lea rdi, [r15 + CG_CHILDOUT]
    call cfg_resize
    cmp rax, -4095
    jae cfg_resource
    mov r12, rax
    mov rax, [r15 + CG_CHILDOUT + 8]
    mov [r15 + 104], rax
    cmp qword ptr [r15 + 80], 1
    je start_fs
    cmp qword ptr [r15 + 80], 2
    je start_json
    cmp qword ptr [r15 + 80], 3
    je validation_resume
    jmp identity_resume
start_fs:
    jmp native_resume
start_json:
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
    cmp rax, 33554432
    jb fatal
    cmp rax, [r15 + CG_FS + 8]
    ja fatal
    mov rdx, [r14 + ACTION + 48]
    test rdx, rdx
    jz fatal
    cmp rdx, 65536
    ja fatal
    add rax, rdx
    jc fatal
    cmp rax, [r15 + CG_FS + 8]
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
    mov eax, 5
    syscall
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
    call cfg_destroy_borrows
    mov edi, ebp
    mov eax, 60
    syscall
bare_fatal:
    mov edi, 112
    mov eax, 60
    syscall


/* Only config_mcp's typed text-result handoff can enter this publisher. */
.global publication_call_displacement
.equ PUB_SRC, 4096
.equ PUB_DST, 73728
.equ PUB_WINDOW, 65600
.equ PUB_GROW, 0xffffffd0
.equ PUB_RESOURCE, 0xfffffffc
mcp_publication:
    push r15
    push r14
    push r13
    push r12
    push rbx
    push rbp
    sub rsp, 64
    mov rbx, rsp
    mov rax, 0x3130425550505248
    cmp [r14 + FOOTER + 160], rax
    jne pub_early_invalid
    cmp qword ptr [r14 + FOOTER + 168], 100667424
    jne pub_early_invalid
    cmp qword ptr [r14 + FOOTER + 176], 67108832
    ja pub_early_invalid
    cmp qword ptr [r14 + FOOTER + 184], ROOT_OUTPUT_CAP
    ja pub_early_invalid
    cmp qword ptr [r14 + FOOTER + 192], 1
    ja pub_early_invalid
    cmp qword ptr [r14 + FOOTER + 200], 1
    jne pub_early_invalid
    lea rax, [r15 + OUTPUT]
    mov [rbx], rax
    mov rax, [r14 + FOOTER + 184]
    mov [rbx + 8], rax
    lea rax, [r14 + 100667424]
    mov [rbx + 16], rax
    mov rax, [r14 + FOOTER + 176]
    mov [rbx + 24], rax
    mov rax, [r14 + FOOTER + 192]
    mov [rbx + 32], rax
    xor r12d, r12d
    xor r14d, r14d
    xor r15d, r15d
    mov esi, 262144
    call pub_allocate
    cmp rax, -4095
    jae pub_fail_resource
    mov r12, rax
    mov esi, 131072
    call pub_allocate
    cmp rax, -4095
    jae pub_fail_resource
    mov r14, rax
    mov r15d, 131072
    mov qword ptr [r12 + 256], 1
    mov edi, 13
    lea rsi, [r12 + 256]
    xor edx, edx
    mov r10d, 8
    mov eax, 13
    syscall
    test rax, rax
    js pub_fail_io
    mov edi, 1
    call pub_make_request
    mov qword ptr [r12 + PUB_SRC + 32], 3
    mov rax, [rbx + 32]
    mov [r12 + PUB_SRC + 40], rax
    call pub_invoke
    cmp rax, 64
    jne pub_fail_invalid
    mov rsi, [rbx]
    mov rcx, [rbx + 8]
    mov edi, 13
    call pub_import
    mov rsi, [rbx + 16]
    mov rcx, [rbx + 24]
    mov edi, 2
    call pub_import
    mov edi, 3
    call pub_make_request
    call pub_invoke
    cmp rax, 64
    jne pub_fail_invalid
    mov edi, 7
    call pub_make_request
    call pub_invoke
    cmp rax, 64
    jne pub_fail_invalid
    mov edi, 8
    call pub_make_request
    call pub_invoke
    cmp rax, 64
    jne pub_fail_invalid
    jmp pub_publish_next
pub_import:
    push rbp
    mov [r12 + 160], rsi
    mov [r12 + 168], rcx
    mov [r12 + 176], rdi
pub_import_next:
    cmp qword ptr [r12 + 168], 0
    je pub_import_done
    mov rdi, [r12 + 176]
    call pub_make_request
    mov rcx, [r12 + 168]
    cmp rcx, 65536
    jbe pub_import_size
    mov ecx, 65536
pub_import_size:
    mov [r12 + PUB_SRC + 48], rcx
    lea rax, [rcx + 64]
    mov [r12 + 8], rax
    sub [r12 + 168], rcx
    mov rsi, [r12 + 160]
    add [r12 + 160], rcx
    lea rdi, [r12 + PUB_SRC + 64]
    rep movsb
    call pub_invoke
    cmp eax, PUB_RESOURCE
    je pub_import_resource
    cmp rax, 64
    jne pub_import_invalid
    jmp pub_import_next
pub_import_resource:
    pop rbp
    jmp pub_fail_resource
pub_import_invalid:
    pop rbp
    jmp pub_fail_invalid
pub_import_done:
    pop rbp
    ret
pub_write_receipt:
    /* Production stderr remains unchanged. The exact shared write/ACK loop
     * has a retaining fixture; MCP tests capture complete actual wire bytes. */
    ret
pub_success:
    xor ebp, ebp
    jmp pub_release
pub_fail_invalid:
    mov ebp, 2
    jmp pub_release
pub_fail_io:
    mov ebp, 74
    jmp pub_release
pub_fail_resource:
    mov ebp, 75
pub_release:
    mov [rbx + 40], rbp
    test r14, r14
    jz pub_release_transport
    mov rdi, r14
    mov rsi, r15
    mov eax, 11
    syscall
pub_release_transport:
    test r12, r12
    jz pub_restore
    mov rdi, r12
    mov esi, 262144
    mov eax, 11
    syscall
pub_restore:
    mov rsp, rbx
    mov eax, [rbx + 40]
    add rsp, 64
    pop rbp
    pop rbx
    pop r12
    pop r13
    pop r14
    pop r15
    test eax, eax
    jnz pub_return_failure
    mov edi, 1
    lea rsi, [rip + newline]
    mov edx, 1
    call write_exact
    test eax, eax
    jnz fatal
    jmp frame_next
pub_return_failure:
    mov ebp, eax
    jmp cleanup_all
pub_early_invalid:
    add rsp, 64
    pop rbp
    pop rbx
    pop r12
    pop r13
    pop r14
    pop r15
    jmp fatal

pub_publish_next:
    mov edi, 9
    call pub_make_request
    call pub_invoke
    cmp rax, 64
    jb pub_fail_invalid
    cmp rax, PUB_WINDOW
    ja pub_fail_invalid
    sub rax, 64
    mov [r12 + 64], rax
    test rax, rax
    jz pub_publication_done
    mov rax, [r12 + PUB_DST + 32]
    mov [r12 + 48], rax
    mov rax, [r12 + PUB_DST + 40]
    mov [r12 + 56], rax
pub_write_attempt:
    mov edi, 1
    lea rsi, [r12 + PUB_DST + 64]
    mov rdx, [r12 + 64]
    mov eax, 1
    syscall
    mov [r12 + 72], rax
    test rax, rax
    jle pub_write_wait_or_fail
    mov edi, 10
    call pub_make_request
    mov rax, [r12 + 48]
    mov [r12 + PUB_SRC + 24], rax
    mov rax, [r12 + 56]
    mov [r12 + PUB_SRC + 32], rax
    mov rax, [r12 + 72]
    mov [r12 + PUB_SRC + 40], rax
    call pub_invoke
    mov [r12 + 88], rax
    call pub_write_receipt
    cmp qword ptr [r12 + 88], 64
    jne pub_fail_invalid
    jmp pub_publish_next
pub_write_wait_or_fail:
    mov qword ptr [r12 + 88], -1
    call pub_write_receipt
    mov rax, [r12 + 72]
    cmp rax, -4
    je pub_write_attempt
    cmp rax, -11
    jne pub_fail_io
    mov dword ptr [r12 + 128], 1
    mov dword ptr [r12 + 132], 4
pub_wait_writable:
    lea rdi, [r12 + 128]
    mov esi, 1
    mov rdx, -1
    mov eax, 7
    syscall
    cmp rax, -4
    je pub_wait_writable
    cmp rax, 1
    jne pub_fail_io
    jmp pub_write_attempt
pub_publication_done:
    cmp qword ptr [r12 + PUB_DST + 24], 4
    jne pub_fail_invalid
    mov edi, 12
    call pub_make_request
    call pub_invoke
    cmp rax, 64
    jne pub_fail_invalid
    jmp pub_success

/* Private mapping growth is only between image invocations. Source and output
 * are in the disjoint fixed transport mapping; no old arena pointer survives. */
pub_invoke:
    lea rdi, [r12 + PUB_SRC]
    mov rsi, [r12 + 8]
    lea rdx, [r12 + PUB_DST]
    mov ecx, PUB_WINDOW
    mov r8, r14
    mov r9, r15
    sub rsp, 8
    .byte 0xe8
publication_call_displacement:
    .long 0
    add rsp, 8
    mov rdx, rax
    shr rdx, 32
    jnz pub_fail_invalid
    cmp eax, PUB_GROW
    je pub_grow_arena
    cmp rax, 64
    jne pub_invoke_return
    cmp qword ptr [r12 + PUB_SRC + 8], 1
    jne pub_invoke_return
    mov qword ptr [r12 + 32], 0
pub_invoke_return:
    ret
pub_grow_arena:
    mov rax, 0x31304f5247505248
    cmp [r14 + 512], rax
    jne pub_fail_invalid
    mov rax, [r12 + 32]
    inc rax
    jz pub_fail_invalid
    cmp [r14 + 520], rax
    jne pub_fail_invalid
    cmp [r14 + 240], rax
    jne pub_fail_invalid
    mov [r12 + 32], rax
    mov rdx, [r14 + 528]
    cmp rdx, r15
    jbe pub_fail_invalid
    test rdx, rdx
    js pub_resource_return
    mov [r12 + 96], rdx
    mov rdi, r14
    mov rsi, r15
    mov r10d, 1
    xor r8d, r8d
    mov eax, 25
    syscall
    cmp rax, -4095
    jae pub_resource_return
    mov r14, rax
    mov r15, [r12 + 96]
    jmp pub_invoke
pub_resource_return:
    mov eax, PUB_RESOURCE
    ret

pub_make_request:
    push rdi
    lea rdi, [r12 + PUB_SRC]
    mov ecx, 8
    xor eax, eax
    rep stosq
    pop rdi
    mov rax, 0x3130303051505248
    mov [r12 + PUB_SRC], rax
    mov [r12 + PUB_SRC + 8], rdi
    mov rax, [r14 + 8]
    mov [r12 + PUB_SRC + 16], rax
    mov qword ptr [r12 + 8], 64
    ret
pub_allocate:
    xor edi, edi
    mov edx, 3
    mov r10d, 34
    mov r8, -1
    xor r9d, r9d
    mov eax, 9
    syscall
    ret

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
    .byte 0xe8
regex_unicode_data_call_displacement:
    .long 0
    jmp regex_returned
regex_invoke3:
    .byte 0xe8
validation_call_displacement:
    .long 0
    jmp regex_returned
regex_invoke15:
    .byte 0xe8
regex_controller_call_displacement:
    .long 0
    jmp regex_returned
regex_invoke10:
    .byte 0xe8
regex_syntax_call_displacement:
    .long 0
    jmp regex_returned
regex_invoke12:
    .byte 0xe8
regex_hir_call_displacement:
    .long 0
    jmp regex_returned
regex_invoke13:
    .byte 0xe8
regex_nfa_call_displacement:
    .long 0
    jmp regex_returned
regex_invoke14:
    .byte 0xe8
regex_match_call_displacement:
    .long 0
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


/* Configuration-only owned mappings. The HIA growth record supplies the
 * required extent. Linux mremap may move a mapping only between f0 calls. */
cfg_initialize_borrows:
    push rbx
    lea rdi, [r15 + CG_OWNER]
    mov esi, 8388864
    call cfg_resize
    cmp rax, -4095
    jae cfg_initialize_failed
    lea rdi, [r15 + CG_FS]
    mov esi, 33554432
    call cfg_resize
    cmp rax, -4095
    jae cfg_initialize_failed
    lea rdi, [r15 + CG_JSON]
    mov esi, 65536
    call cfg_resize
    cmp rax, -4095
    jae cfg_initialize_failed
    lea rdi, [r15 + CG_CHILDOUT]
    mov esi, 65536
    call cfg_resize
    cmp rax, -4095
    jae cfg_initialize_failed
    lea rdi, [r15 + CG_ROOTOUT]
    mov esi, 65536
    call cfg_resize
    cmp rax, -4095
    jae cfg_initialize_failed
    lea rdi, [r15 + CG_VALIDATION]
    mov esi, 262144
    call cfg_resize
    cmp rax, -4095
    jae cfg_initialize_failed
    pop rbx
    ret
cfg_initialize_failed:
    pop rbx
    jmp cfg_resource

cfg_native_growth:
    mov rax, 0x3230305357524748
    cmp [r12], rax
    jne fatal
    cmp qword ptr [r12 + 24], 0
    jne fatal
    mov rax, [r12 + 8]
    cmp rax, 3
    je cfg_resource
    mov rsi, [r12 + 16]
    test rsi, rsi
    jz fatal
    cmp rax, 1
    je cfg_native_work_growth
    cmp rax, 2
    jne fatal
    lea rdi, [r15 + CG_CHILDOUT]
    cmp qword ptr [r15 + 80], 0
    jne cfg_native_growth_apply
    cmp qword ptr [r15 + 784], 0
    jne cfg_resource /* Legacy MCP5 still owns its distinct output borrow. */
    lea rdi, [r15 + CG_ROOTOUT]
    jmp cfg_native_growth_apply
cfg_native_work_growth:
    lea rdi, [r15 + CG_OWNER]
    cmp qword ptr [r15 + 80], 0
    je cfg_native_growth_apply
    lea rdi, [r15 + CG_FS]
    cmp qword ptr [r15 + 80], 1
    je cfg_native_growth_apply
    lea rdi, [r15 + CG_JSON]
    cmp qword ptr [r15 + 80], 2
    je cfg_native_growth_apply
    lea rdi, [r15 + CG_VALIDATION]
    cmp qword ptr [r15 + 80], 3
    jne fatal
cfg_native_growth_apply:
    cmp rsi, [rdi + 8]
    jbe fatal
    call cfg_resize
    cmp rax, -4095
    jae cfg_resource
    cmp qword ptr [r15 + 80], 0
    je owner_resume
    cmp qword ptr [r15 + 80], 1
    je native_resume
    cmp qword ptr [r15 + 80], 2
    je json_resume
    cmp qword ptr [r15 + 80], 3
    jne fatal
    mov r12, [r15 + CG_CHILDOUT]
    mov rax, [r15 + CG_CHILDOUT + 8]
    mov [r15 + 104], rax
    jmp validation_resume

/* rdi -> {owned pointer, capacity}; rsi required. Preserve all callee-saved
 * registers and publish a new descriptor only after a successful syscall. */
cfg_resize:
    push rbx
    push rbp
    push r12
    push r13
    sub rsp, 16
    mov rbx, rdi
    mov r12, rsi
    mov rbp, [rbx + 8]
    mov r13, [rbx]
    cmp r12, rbp
    jbe cfg_resize_already
    mov rsi, rbp
    cmp rsi, 4096
    jae cfg_resize_double
    mov esi, 4096
cfg_resize_double:
    cmp rsi, r12
    jae cfg_resize_ready
    test rsi, rsi
    js cfg_resize_overflow
    shl rsi, 1
    jc cfg_resize_overflow
    jmp cfg_resize_double
cfg_resize_ready:
    test rsi, rsi
    js cfg_resize_overflow
    mov [rsp], rsi
    test r13, r13
    jz cfg_resize_first
    mov rdi, r13
    mov rdx, rsi
    mov rsi, rbp
    mov r10d, 1
    xor r8d, r8d
    mov eax, 25
    syscall
    jmp cfg_resize_observed
cfg_resize_first:
    xor edi, edi
    mov edx, 3
    mov r10d, 34
    mov r8, -1
    xor r9d, r9d
    mov eax, 9
    syscall
cfg_resize_observed:
    mov [rsp + 8], rax
    cmp rax, -4095
    jae cfg_resize_trace
    mov [rbx], rax
    mov rcx, [rsp]
    mov [rbx + 8], rcx
cfg_resize_trace:
    cmp qword ptr [r15 + CG_TRACE], 1
    jne cfg_resize_return_result
    call cfg_resize_receipt
cfg_resize_return_result:
    mov rax, [rsp + 8]
    jmp cfg_resize_return
cfg_resize_already:
    mov rax, r13
    jmp cfg_resize_return
cfg_resize_overflow:
    mov rax, -75
cfg_resize_return:
    add rsp, 16
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

/* Private fixture trace; production leaves CG_TRACE zero. Full 80-byte
 * records bind actual requested/old/new extents and raw Linux results. */
cfg_resize_receipt:
    sub rsp, 80
    mov rax, 0x32304f5247435248 /* HRCGRO02 */
    mov [rsp], rax
    inc qword ptr [r15 + CG_SEQUENCE]
    jz fatal
    mov rax, [r15 + CG_SEQUENCE]
    mov [rsp + 8], rax
    mov rax, rbx
    sub rax, r15
    sub rax, CG_OWNER
    shr rax, 4
    mov [rsp + 16], rax
    mov rax, [r15 + 80]
    mov [rsp + 24], rax
    mov [rsp + 32], rbp
    mov [rsp + 40], r12
    mov rax, [rbx + 8]
    mov [rsp + 48], rax
    mov rax, [rsp + 96]
    mov [rsp + 56], rax
    mov [rsp + 64], r13
    mov rax, [rbx]
    mov [rsp + 72], rax
    mov edi, 2
    mov rsi, rsp
    mov edx, 80
    call write_exact
    test eax, eax
    jnz fatal
    add rsp, 80
    ret

cfg_destroy_borrows:
    push rbx
    lea rbx, [r15 + CG_OWNER]
cfg_destroy_next:
    mov rdi, [rbx]
    test rdi, rdi
    jz cfg_destroy_advance
    mov rsi, [rbx + 8]
    mov eax, 11
    syscall
    cmp rax, -4095
    jae cfg_destroy_failed
    mov qword ptr [rbx], 0
    mov qword ptr [rbx + 8], 0
cfg_destroy_advance:
    add rbx, 16
    lea rax, [r15 + CG_DELIVERY]
    cmp rbx, rax
    jb cfg_destroy_next
    pop rbx
    ret
cfg_destroy_failed:
    mov ebp, 75
    jmp cfg_destroy_advance
cfg_resource:
    mov ebp, 75
    jmp cleanup_all
