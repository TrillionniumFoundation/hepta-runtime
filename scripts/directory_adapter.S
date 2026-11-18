/* Fixed private controller storage. None of these pointers are wire inputs. */
.equ D_POLICY_PARENT, 1000
.equ D_CHILD_LEN, 1008
.equ D_CURRENT, 1016
.equ D_HEAD, 1024
.equ D_LAST_ID, 1032
.equ D_CLOSING, 1040
.equ D_INPUT_STAGE, 1048
.equ D_INPUT_USED, 1056
.equ D_INPUT_LEN, 1064
.equ D_WAKE_R, 1072
.equ D_WAKE_W, 1080
.equ D_FENCE_IN, 1088
.equ D_FENCE_OUT, 1096
.equ D_FENCE_PID, 1104
.equ D_MEMFD, 1112
.equ D_PARENT_PID, 1120
.equ D_USER_PTR, 1128
.equ D_USER_LEN, 1136
.equ D_USER_PRESENT, 1144
.equ D_ENVP, 1152
.equ D_STARTUP_MODE, 1160
.equ D_STATE_PTR, 1168
.equ D_STATE_LEN, 1176
.equ D_ENTRY_PTR, 1184
.equ D_ENTRY_LEN, 1192
.equ D_ENTRY_KIND, 1200
.equ D_ERR_R, 1208
.equ D_ERR_W, 1216
.equ D_IN_R, 1224
.equ D_OUT_W, 1232
.equ D_SCAN, 1240
.equ D_SCAN_NEXT, 1248
.equ D_JOB_SEQUENCE, 1256
.equ D_PATH_WORK, 1264
.equ D_ERRNO_WORK, 1272
.equ D_FENCE_CLOSED, 1280
.equ D_BLOB_SIZE, 1288
.equ D_CONTROL_ID, 1296
.equ D_CONTROL_CMD, 1304
.equ D_RESULT_CODE, 1312
.equ D_PIPES, 1344
.equ D_ARGV, 1408
.equ D_DUP_FDS, 1472
.equ D_SIGNAL_ACTION, 1536
.equ D_SIGNAL_MASK, 1568
.equ D_POLL, 1600
.equ D_FRAME_HEADER, 1664
.equ D_REPLY, 1728
.equ D_EXEC_ERROR, 1856
.equ D_WSTATUS, 1872
.equ D_NOTICE, 1880
.equ D_JOB_R, 1896
.equ D_JOB_W, 1904
.equ D_EMIT_EVENT, 1912
.equ D_EMIT_ID, 1920
.equ D_EMIT_CODE, 1928
.equ D_EMIT_PTR, 1936
.equ D_EMIT_LEN, 1944
.equ D_SNAPSHOT_FD, 1952
.equ D_SNAPSHOT, 1960
.equ D_START_STAT, 2048
.equ D_SNAPSHOT_BYTES, 8392704
.equ D_TASK_BYTES, 402657280
.equ T_NEXT, 0
.equ T_ID, 8
.equ T_WORK, 16
.equ T_OUTPUT, 24
.equ T_PID, 32
.equ T_FD, 40
.equ T_JOB, 48
.equ T_STATUS, 56
.equ T_SEQUENCE, 64
.equ T_GOT, 72
.equ T_WSTATUS, 80
.equ T_PIPE_EOF, 88
.equ T_PIPE_FAIL, 96
.equ T_DROP_SENT, 104
.equ T_RESPONSE, 256
.global caller_call_displacement
.global path_call_displacement
.global errno_call_displacement
.global mkdir_call_displacement
.global fence_blob_displacement
.global fence_blob_length

/* Five fixed HIA images: installed config, FS, typed JSON, validation/projection and identity. */
.intel_syntax noprefix
.section .text
.global _start
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
.equ MAP_BYTES, 3489730624
.equ CLIENT_WORK, 2113933376
.global client_call_displacement
.equ CONTEXT_WORK, 1828720640
.equ SESSION_WORK, 2097156096
.equ SESSION_WCAP, 16777280
.global context_call_displacement
.global state_call_displacement
.global value_call_displacement
.equ POLICY_WORK, 1258295296
.equ CANON_WORK, 1526730752
.equ POLICY_INPUT, 1795166208
.equ CAN_PATH_CAP, 67108864
.equ CAN_NORM, 4096
.equ CAN_CANON, 67117056
.equ CAN_LINK, 201342976
.equ CAN_LINK_CAP, 1048576
.global policy_call_displacement
.global canonical_call_displacement
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
    mov rax, [rbx]
    lea rax, [rbx + rax*8 + 16]
    mov [r15 + D_ENVP], rax
    mov [r15 + 648], rax
    mov qword ptr [r15 + D_WAKE_R], -1
    mov qword ptr [r15 + D_WAKE_W], -1
    mov qword ptr [r15 + D_FENCE_IN], -1
    mov qword ptr [r15 + D_FENCE_OUT], -1
    mov qword ptr [r15 + D_MEMFD], -1
    mov qword ptr [r15 + D_ERR_R], -1
    mov qword ptr [r15 + D_ERR_W], -1
    mov qword ptr [r15 + D_IN_R], -1
    mov qword ptr [r15 + D_OUT_W], -1
    mov qword ptr [r15 + D_JOB_R], -1
    mov qword ptr [r15 + D_JOB_W], -1
    mov qword ptr [r15 + D_SNAPSHOT_FD], 4
    call d_read_startup_snapshot
    cmp qword ptr [rbx], 3
    je context_unconfigured_argv
    cmp qword ptr [rbx], 5
    jne argv_fatal
    mov rdi, [rbx + 32]
    lea rsi, [rip + session_option]
    call cstr_equal
    test eax, eax
    jz argv_fatal
    mov rdi, [rbx + 40]
    mov [r15 + 864], rdi
    call cstr_length
    mov [r15 + 872], rax
    mov qword ptr [r15 + 936], 1
    mov rdi, [rbx + 16]
    lea rsi, [rip + state_option]
    call cstr_equal
    test eax, eax
    jz argv_fatal
    mov rdi, [rbx + 24]
    mov [r15 + 704], rdi
    call cstr_length
    mov [r15 + 712], rax
    lea rax, [rbx + 56]
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

frame_next:
    jmp d_main
frame_eof:
    cmp qword ptr [r15 + 936], 0
    je finish_ok
    mov qword ptr [r15 + 800], 0
    mov qword ptr [r15 + 24], 0
    lea rax, [r15 + ROOT_WORK + FOOTER]
    mov qword ptr [rax + 120], 2
owner_resume:
    mov qword ptr [r15 + 80], 0
    lea r13, [r15 + INPUT]
    lea r12, [r15 + OUTPUT]
    lea r14, [r15 + ROOT_WORK]
    mov rsi, [r15 + 24]
    cmp qword ptr [r15 + 800], 0
    je owner_input_selected
    cmp qword ptr [r15 + 800], 2
    je d_owner_query_buffers
    cmp qword ptr [r15 + 800], 3
    je owner_input_selected
    cmp qword ptr [r15 + 800], 1
    jne fatal
    lea r13, [r15 + POLICY_WORK + 4096]
    lea r12, [r15 + POLICY_WORK + 67117056]
    mov rsi, [r15 + 808]
    jmp owner_input_selected
d_owner_query_buffers:
    mov rax, [r15 + D_CURRENT]
    mov rax, [rax + T_WORK]
    lea r13, [rax + 4096]
    lea r12, [rax + 67117056]
    mov rsi, [r15 + D_CHILD_LEN]
owner_input_selected:
    mov rdi, r13
    mov rdx, r12
    mov ecx, ROOT_OUTPUT_CAP
    mov r8, r14
    mov r9d, ROOT_WCAP
    .byte 0xe8
owner_call_displacement:
    .long 0
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
    .byte 0xe8
fs_call_displacement:
    .long 0
    jmp native_return
json_resume:
    lea r14, [r15 + JSON_WORK]
    mov rdi, r13
    mov rsi, [r15 + 96]
    mov rdx, r12
    mov rcx, [r15 + 104]
    mov r8, r14
    mov r9d, ROOT_WCAP
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
    lea rax, [r15 + VALIDATION_WORK]
    mov [r14 + 40], rax
    mov qword ptr [r14 + 48], ROOT_WCAP
    xor r12d, r12d
    jmp regex_invoke
native_return:
    mov edx, eax
    cmp rax, rdx
    jne fatal
    cmp qword ptr [r15 + 80], 7
    je context_return
    cmp qword ptr [r15 + 80], 8
    je session_return
    cmp qword ptr [r15 + 80], 9
    je client_value_completed
    cmp qword ptr [r15 + 80], 10
    je client_return
    cmp qword ptr [r15 + 80], 5
    je policy_return
    cmp qword ptr [r15 + 80], 6
    je canonical_return
    mov edx, 0xffffffe0
    cmp rax, rdx
    je call_dispatch
    mov edx, 0xfffffff0
    cmp rax, rdx
    je effect_dispatch_checked
    cmp qword ptr [r15 + 80], 0
    jne child_completed
    cmp qword ptr [r15 + 800], 1
    je policy_child_completed
    cmp qword ptr [r15 + 800], 2
    je d_child_completed
    cmp qword ptr [r15 + 800], 3
    je d_startup_config_result
    cmp rax, ROOT_OUTPUT_CAP
    ja fatal
    cmp qword ptr [r14 + FOOTER + 120], 2
    je shutdown_completed
    cmp qword ptr [r14 + FOOTER + 120], 0
    je startup_completed
    cmp qword ptr [r14 + FOOTER + 120], 4
    je startup_completed
    mov [r15 + 32], rax
    mov edi, 1
    lea rsi, [r15 + 32]
    mov edx, 8
    call write_exact
    test eax, eax
    jnz fatal
    mov edi, 1
    lea rsi, [r15 + OUTPUT]
    mov rdx, [r15 + 32]
    call write_exact
    test eax, eax
    jnz fatal
    jmp frame_next
startup_completed:
    test eax, eax
    jz session_initialize
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

call_dispatch:
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
    call d_cleanup
base_cleanup_all:
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
    jmp base_cleanup_all
process_exit:
    mov edi, ebp
    mov eax, 60
    syscall
bare_fatal:
    mov edi, 112
    mov eax, 60
    syscall

/* Private policy calls are the only post-startup input route in this profile. */
policy_resume:
    mov qword ptr [r15 + 80], 5
    lea r13, [r15 + CONTEXT_WORK + 4096]
    lea r12, [r15 + CONTEXT_WORK + 67117056]
    mov rsi, [r15 + 896]
    cmp qword ptr [r15 + D_POLICY_PARENT], 0
    je d_policy_buffers_ready
    cmp qword ptr [r15 + D_POLICY_PARENT], 1
    jne fatal
    mov rax, [r15 + D_CURRENT]
    mov rax, [rax + T_WORK]
    lea r13, [rax + 4096]
    lea r12, [rax + 67117056]
    mov rsi, [r15 + D_CHILD_LEN]
d_policy_buffers_ready:
    lea r14, [r15 + POLICY_WORK]
    mov rdi, r13
    mov rdx, r12
    mov ecx, ROOT_OUTPUT_CAP
    mov r8, r14
    mov r9d, ROOT_WCAP
    .byte 0xe8
policy_call_displacement:
    .long 0
    jmp native_return

policy_return:
    cmp eax, 0xfffffff0
    je policy_dispatch
    cmp qword ptr [r15 + D_POLICY_PARENT], 0
    je context_child_completed
    cmp qword ptr [r15 + D_POLICY_PARENT], 1
    jne fatal
    jmp d_child_completed

policy_dispatch:
    lea r14, [r15 + POLICY_WORK]
    lea rdx, [r14 + 256]
    movabs rax, 0x3130304143504c48 /* HLPCA001 */
    cmp [rdx], rax
    jne fatal
    mov rax, [r15 + 816]
    inc rax
    jz fatal
    cmp [rdx + 8], rax
    jne fatal
    cmp [r14 + 16], rax
    jne fatal
    mov [r15 + 816], rax
    mov rax, [rdx + 24]
    or rax, [rdx + 64]
    or rax, [rdx + 72]
    or rax, [rdx + 80]
    or rax, [rdx + 88]
    jnz fatal
    cmp qword ptr [rdx + 32], 4096
    jne fatal
    cmp qword ptr [rdx + 48], 67117056
    jne fatal
    cmp qword ptr [rdx + 56], ROOT_OUTPUT_CAP
    jne fatal
    mov rax, [rdx + 40]
    cmp rax, 24
    jb fatal
    cmp rax, 67112960
    ja fatal
    mov [r15 + 808], rax
    mov rcx, [r14 + 4096 + 16]
    add rcx, 24
    jc fatal
    cmp rcx, rax
    jne fatal
    cmp qword ptr [rdx + 16], 1
    je policy_config
    cmp qword ptr [rdx + 16], 2
    jne fatal
    movabs rcx, 0x3130514e41435248 /* HRCANQ01 */
    cmp [r14 + 4096], rcx
    jne fatal
    cmp qword ptr [r14 + 8], 2
    je policy_candidate
    cmp qword ptr [r14 + 8], 4
    jne fatal
    cmp qword ptr [r14 + 4096 + 8], 2
    jne fatal
    jmp canonical_resume
policy_candidate:
    cmp rax, 33554432
    ja fatal
    cmp qword ptr [r14 + 4096 + 8], 1
    jne fatal
    jmp canonical_resume
policy_config:
    movabs rcx, 0x3130514746435248 /* HRCFGQ01 */
    cmp [r14 + 4096], rcx
    jne fatal
    cmp qword ptr [r14 + 4096 + 8], 7
    jne fatal
    cmp qword ptr [r14 + 8], 1
    je policy_count
    cmp qword ptr [r14 + 8], 3
    jne fatal
    cmp rax, 32
    jne fatal
    mov rcx, [r14 + 40]
    cmp [r14 + 4096 + 24], rcx
    jne fatal
    jmp policy_config_start
policy_count:
    cmp rax, 24
    jne fatal
policy_config_start:
    mov qword ptr [r15 + 800], 1
    lea rax, [r15 + ROOT_WORK + FOOTER]
    mov qword ptr [rax + 120], 1
    jmp owner_resume

canonical_resume:
    mov qword ptr [r15 + 80], 6
    lea r13, [r15 + POLICY_WORK + 4096]
    lea r12, [r15 + POLICY_WORK + 67117056]
    mov rsi, [r15 + 808]
    cmp qword ptr [r15 + 920], 0
    je context_canonical_input_selected
    cmp qword ptr [r15 + 920], 1
    jne fatal
    lea r13, [r15 + CONTEXT_WORK + 4096]
    lea r12, [r15 + CONTEXT_WORK + 67117056]
    mov rsi, [r15 + 896]
context_canonical_input_selected:
    lea r14, [r15 + CANON_WORK]
    mov rdi, r13
    mov rdx, r12
    mov ecx, ROOT_OUTPUT_CAP
    mov r8, r14
    mov r9d, ROOT_WCAP
    .byte 0xe8
canonical_call_displacement:
    .long 0
    jmp native_return

canonical_return:
    cmp eax, 0xfffffff0
    je context_canonical_effect
    cmp qword ptr [r15 + 920], 0
    je policy_child_completed
    cmp qword ptr [r15 + 920], 1
    jne fatal
    jmp context_child_completed
context_canonical_effect:
    lea r12, [r15 + CANON_WORK]
    lea r13, [r12 + 256]
    jmp canon_handle_effect

policy_child_completed:
    cmp eax, ROOT_OUTPUT_CAP
    jbe policy_child_result_valid
    cmp eax, 0xffffffff
    je policy_child_result_valid
    cmp eax, 0xfffffffe
    jne fatal
policy_child_result_valid:
    lea rdx, [r15 + POLICY_WORK + 256]
    mov [rdx + 72], rax
    mov rax, [r15 + 816]
    mov [rdx + 64], rax
    mov qword ptr [r15 + 800], 0
    jmp policy_resume

canon_handle_effect:
    movabs rax, 0x3130574e41435248
    cmp qword ptr [r12], rax
    jne fatal
    movabs rax, 0x3130414e41435248
    cmp qword ptr [r13], rax
    jne fatal
    mov rax, qword ptr [r15+848]
    inc rax
    jz fatal
    cmp qword ptr [r13+8], rax
    jne fatal
    cmp qword ptr [r12+16], rax
    jne fatal
    mov qword ptr [r15+848], rax
    mov rax, qword ptr [r13+24]
    or rax, qword ptr [r13+48]
    or rax, qword ptr [r13+56]
    or rax, qword ptr [r13+64]
    or rax, qword ptr [r13+72]
    or rax, qword ptr [r13+80]
    or rax, qword ptr [r13+88]
    jnz fatal
    mov r14, qword ptr [r13+16]
    cmp r14, 1
    jb fatal
    cmp r14, 7
    ja fatal
    cmp r14, 4
    je canon_canonical_readlink
    cmp r14, 5
    je canon_canonical_stat
    cmp qword ptr [r12+8], r14
    jne fatal
    cmp r14, 2
    je canon_stat_probe
    cmp r14, 7
    je canon_stat_probe_fallback
    cmp qword ptr [r13+32], CAN_NORM
    jne fatal
    mov rax, qword ptr [r12+48]
    cmp qword ptr [r13+40], rax
    jne fatal
    call canon_exact_path
    cmp r14, 1
    je canon_statx_path
    jmp canon_legacy_stat

canon_exact_path:
    mov rcx, qword ptr [r13+40]
    test rcx, rcx
    jz fatal
    cmp rcx, CAN_PATH_CAP
    jae fatal
    mov rsi, qword ptr [r13+32]
    add rsi, r12
    cmp byte ptr [rsi], 47
    jne fatal
    cmp byte ptr [rsi+rcx], 0
    jne fatal
    xor edx, edx
canon_path_scan:
    cmp byte ptr [rsi+rdx], 0
    je fatal
    inc rdx
    cmp rdx, rcx
    jb canon_path_scan
    ret

canon_statx_path:
    mov edi, -100
    xor edx, edx
    mov r10d, 0xfff
    lea r8, [r12+512]
    mov eax, 332
    syscall
    jmp canon_zero_result
canon_legacy_stat:
    mov edi, -100
    lea rdx, [r12+512]
    xor r10d, r10d
    mov eax, 262
    syscall
    jmp canon_zero_result
canon_stat_probe:
    mov rax, qword ptr [r13+32]
    or rax, qword ptr [r13+40]
    jnz fatal
    xor edi, edi
    xor esi, esi
    xor edx, edx
    mov r10d, 0xfff
    xor r8d, r8d
    mov eax, 332
    syscall
    jmp canon_zero_result
canon_stat_probe_fallback:
    mov rax, qword ptr [r13+32]
    or rax, qword ptr [r13+40]
    jnz fatal
    xor edi, edi
    xor esi, esi
    lea rdx, [r12+512]
    xor r10d, r10d
    mov eax, 262
    syscall
    jmp canon_zero_result

canon_canonical_path:
    cmp qword ptr [r13+32], CAN_CANON
    jne fatal
    mov rax, qword ptr [r12+64]
    cmp qword ptr [r13+40], rax
    jne fatal
    jmp canon_exact_path
canon_canonical_readlink:
    cmp qword ptr [r12+8], 20
    jne fatal
    call canon_canonical_path
    mov edi, -100
    lea rdx, [r12+CAN_LINK]
    mov r10d, CAN_LINK_CAP
    mov eax, 267
    syscall
    cmp rax, -4095
    jae canon_effect_error
    cmp rax, CAN_LINK_CAP
    ja fatal
    mov qword ptr [r13+80], rax
    jmp canon_acknowledge
canon_canonical_stat:
    cmp qword ptr [r12+8], 21
    jne fatal
    call canon_canonical_path
    jmp canon_legacy_stat
canon_zero_result:
    cmp rax, -4095
    jae canon_effect_error
    test rax, rax
    jnz fatal
    jmp canon_acknowledge
canon_effect_error:
    neg rax
    mov qword ptr [r13+72], rax
canon_acknowledge:
    mov rax, qword ptr [r13+8]
    mov qword ptr [r13+64], rax
    jmp canonical_resume


/* The parent owns startup, one private session, and a closed child call graph. */
session_option:
    .asciz "--session-root"
context_unconfigured_argv:
    mov rdi, [rbx + 16]
    lea rsi, [rip + session_option]
    call cstr_equal
    test eax, eax
    jz argv_fatal
    mov rdi, [rbx + 24]
    mov [r15 + 864], rdi
    call cstr_length
    mov [r15 + 872], rax
    /* The HIA configuration owner initializes its own absent state. */
    mov qword ptr [r15 + 24], 0
    lea rax, [r15 + ROOT_WORK + FOOTER]
    mov qword ptr [rax + 120], 4
    jmp owner_resume

session_initialize:
    lea r13, [r15 + INPUT]
    movabs rax, 0x3130305157535248 /* HRSWQ001 */
    mov [r13], rax
    mov qword ptr [r13 + 8], 1
    mov rax, [r15 + 872]
    mov [r13 + 16], rax
    mov qword ptr [r13 + 24], 0
    mov rsi, [r15 + 864]
    lea rdi, [r13 + 32]
    mov rcx, rax
    rep movsb
    add rax, 32
    mov [r15 + 896], rax
    mov qword ptr [r15 + 904], 32
    mov qword ptr [r15 + 912], 0
    jmp session_resume

context_resume:
    mov qword ptr [r15 + 80], 7
    mov rax, [r15 + D_CURRENT]
    mov rax, [rax + T_WORK]
    lea r13, [rax + 4096]
    lea r12, [rax + 67117056]
    lea r14, [r15 + CONTEXT_WORK]
    mov rdi, r13
    mov rsi, [r15 + D_CHILD_LEN]
    mov rdx, r12
    mov ecx, 32
    mov r8, r14
    mov r9d, ROOT_WCAP
    .byte 0xe8
context_call_displacement:
    .long 0
    jmp native_return

context_return:
    cmp eax, 0xfffffff0
    je context_dispatch
    jmp d_child_completed

context_dispatch:
    lea r14, [r15 + CONTEXT_WORK]
    lea rdx, [r14 + 256]
    movabs rax, 0x3130415043535248 /* HRSCPA01 */
    cmp [rdx], rax
    jne fatal
    mov rax, [r15 + 880]
    inc rax
    jz fatal
    cmp [rdx + 8], rax
    jne fatal
    cmp [r14 + 16], rax
    jne fatal
    mov [r15 + 880], rax
    mov rax, [rdx + 24]
    or rax, [rdx + 64]
    or rax, [rdx + 72]
    or rax, [rdx + 80]
    or rax, [rdx + 88]
    jnz fatal
    cmp qword ptr [rdx + 32], 4096
    jne fatal
    cmp qword ptr [rdx + 48], 67117056
    jne fatal
    mov rax, [rdx + 40]
    cmp rax, 24
    jb fatal
    cmp rax, 16777256
    ja fatal
    mov [r15 + 896], rax
    mov rcx, [rdx + 56]
    mov [r15 + 904], rcx
    cmp qword ptr [rdx + 16], 1
    je context_session
    cmp qword ptr [rdx + 16], 2
    je context_value
    cmp rcx, ROOT_OUTPUT_CAP
    jne fatal
    mov rcx, [r14 + 4096 + 16]
    add rcx, 24
    jc fatal
    cmp rcx, rax
    jne fatal
    cmp qword ptr [rdx + 16], 3
    je context_policy
    cmp qword ptr [rdx + 16], 4
    jne fatal
    cmp qword ptr [r14 + 8], 4
    jne fatal
    movabs rcx, 0x3130514e41435248 /* HRCANQ01 */
    cmp [r14 + 4096], rcx
    jne fatal
    cmp qword ptr [r14 + 4096 + 8], 3
    jne fatal
    mov qword ptr [r15 + 920], 1
    jmp canonical_resume
context_policy:
    mov qword ptr [r15 + D_POLICY_PARENT], 0
    cmp qword ptr [r14 + 8], 3
    jne fatal
    movabs rcx, 0x31305143504c5248 /* HRLPCQ01 */
    cmp [r14 + 4096], rcx
    jne fatal
    cmp qword ptr [r14 + 4096 + 8], 1
    jne fatal
    mov qword ptr [r15 + 920], 0
    jmp policy_resume
context_session:
    cmp rcx, 32
    jne fatal
    cmp rax, 32
    jb fatal
    movabs rcx, 0x3130305157535248
    cmp [r14 + 4096], rcx
    jne fatal
    cmp qword ptr [r14 + 4096 + 24], 0
    jne fatal
    mov rcx, [r14 + 4096 + 16]
    add rcx, 32
    jc fatal
    cmp rcx, rax
    jne fatal
    cmp qword ptr [r14 + 8], 1
    je context_latch
    cmp qword ptr [r14 + 8], 5
    jne fatal
    cmp qword ptr [r14 + 4096 + 8], 3
    jne fatal
    jmp context_state_ready
context_latch:
    cmp rax, 32
    jne fatal
    cmp qword ptr [r14 + 4096 + 8], 5
    jne fatal
context_state_ready:
    mov qword ptr [r15 + 912], 1
    jmp session_resume
/* Child 2 is the HIA client-capability resolver; only its Value child can recurse. */
context_value:
    cmp rcx, 67108896
    jne fatal
    cmp qword ptr [r14 + 8], 2
    jne fatal
    cmp rax, 40
    jb fatal
    movabs rcx, 0x313051434d435248 /* HRCMCQ01 */
    cmp [r14 + 4096], rcx
    jne fatal
    cmp qword ptr [r14 + 4096 + 8], 1
    ja fatal
    cmp qword ptr [r14 + 4096 + 16], 1
    ja fatal
    mov rcx, [r14 + 4096 + 24]
    mov rdx, [r14 + 4096 + 32]
    cmp rcx, 8388608
    ja fatal
    cmp rdx, 8388608
    ja fatal
    cmp qword ptr [r14 + 4096 + 16], 0
    jne client_legacy_extent_ready
    test rdx, rdx
    jnz fatal
client_legacy_extent_ready:
    add rcx, rdx
    add rcx, 40
    cmp rcx, rax
    jne fatal
client_resume:
    mov qword ptr [r15 + 80], 10
    lea r13, [r15 + CONTEXT_WORK + 4096]
    lea r12, [r15 + CONTEXT_WORK + 67117056]
    lea r14, [r15 + CLIENT_WORK]
    mov rdi, r13
    mov rsi, [r15 + 896]
    mov rdx, r12
    mov ecx, 67108896
    mov r8, r14
    mov r9d, ROOT_WCAP
    .byte 0xe8
client_call_displacement:
    .long 0
    jmp native_return
client_return:
    cmp eax, 0xfffffff0
    jne context_child_completed
    lea r14, [r15 + CLIENT_WORK]
    lea rdx, [r14 + 256]
    movabs rax, 0x313041434d435248 /* HRCMCA01 */
    cmp [rdx], rax
    jne fatal
    mov rax, [r15 + 944]
    inc rax
    jz fatal
    cmp [rdx + 8], rax
    jne fatal
    cmp [r14 + 16], rax
    jne fatal
    mov [r15 + 944], rax
    cmp qword ptr [rdx + 16], 1
    jne fatal
    mov rax, [rdx + 24]
    or rax, [rdx + 64]
    or rax, [rdx + 72]
    or rax, [rdx + 80]
    or rax, [rdx + 88]
    jnz fatal
    cmp qword ptr [rdx + 32], 4096
    jne fatal
    cmp qword ptr [rdx + 48], 67117056
    jne fatal
    cmp qword ptr [rdx + 56], 67108864
    jne fatal
    mov rax, [rdx + 40]
    cmp rax, 24
    jb fatal
    cmp rax, 8388632
    ja fatal
    mov [r15 + 952], rax
    lea r13, [r14 + 4096]
    lea r12, [r14 + 67117056]
    movabs rcx, 0x31304c41564a5348 /* HSJVAL01 */
    cmp [r13], rcx
    jne fatal
    cmp qword ptr [r13 + 8], 1
    jne fatal
    mov rcx, [r13 + 16]
    add rcx, 24
    jc fatal
    cmp rcx, rax
    jne fatal
    mov qword ptr [r15 + 80], 9
    lea r14, [r15 + JSON_WORK]
    mov rdi, r13
    mov rsi, [r15 + 952]
    mov rdx, r12
    mov ecx, 67108864
    mov r8, r14
    mov r9d, ROOT_WCAP
    .byte 0xe8
value_call_displacement:
    .long 0
    jmp native_return
client_value_completed:
    cmp eax, 67108864
    jbe client_value_valid
    cmp eax, 0xffffffff
    je client_value_valid
    cmp eax, 0xfffffffe
    jne fatal
client_value_valid:
    lea rdx, [r15 + CLIENT_WORK]
    add rdx, 256
    mov [rdx + 72], rax
    mov rax, [r15 + 944]
    mov [rdx + 64], rax
    jmp client_resume

session_resume:
    mov qword ptr [r15 + 80], 8
    lea r13, [r15 + INPUT]
    lea r12, [r15 + OUTPUT]
    cmp qword ptr [r15 + 912], 3
    je d_session_query_buffers
    cmp qword ptr [r15 + 912], 1
    jne session_buffers_selected
    lea r13, [r15 + CONTEXT_WORK + 4096]
    lea r12, [r15 + CONTEXT_WORK + 67117056]
    jmp session_buffers_selected
d_session_query_buffers:
    mov rax, [r15 + D_CURRENT]
    mov rax, [rax + T_WORK]
    lea r13, [rax + 4096]
    lea r12, [rax + 67117056]
session_buffers_selected:
    lea r14, [r15 + SESSION_WORK]
    mov rdi, r13
    mov rsi, [r15 + 896]
    mov rdx, r12
    mov rcx, [r15 + 904]
    mov r8, r14
    mov r9d, SESSION_WCAP
    .byte 0xe8
state_call_displacement:
    .long 0
    jmp native_return
session_return:
    cmp qword ptr [r15 + 912], 3
    je d_child_completed
    cmp qword ptr [r15 + 912], 1
    je context_child_completed
    cmp rax, [r15 + 904]
    ja fatal
    cmp rax, 32
    jb fatal
    lea rdx, [r15 + OUTPUT]
    movabs rcx, 0x3130305257535248 /* HRSWR001 */
    cmp [rdx], rcx
    jne fatal
    cmp qword ptr [r15 + 912], 2
    je context_observed
    cmp rax, 32
    jne fatal
    mov rcx, [rdx + 8]
    or rcx, [rdx + 16]
    or rcx, [rdx + 24]
    jnz fatal
    jmp d_startup
context_observed:
    cmp qword ptr [rdx + 8], 1
    jne fatal
    cmp qword ptr [rdx + 16], 0
    jne fatal
    mov rcx, rax
    sub rcx, 32
    cmp [rdx + 24], rcx
    jne fatal
    jmp context_write
context_child_completed:
    cmp rax, [r15 + 904]
    jbe context_child_valid
    cmp eax, 0xffffffff
    je context_child_valid
    cmp eax, 0xfffffffe
    jne fatal
context_child_valid:
    lea rdx, [r15 + CONTEXT_WORK + 256]
    mov [rdx + 72], rax
    mov rax, [r15 + 880]
    mov [rdx + 64], rax
    jmp context_resume
context_write:
    mov [r15 + 32], rax
    mov edi, 1
    lea rsi, [r15 + 32]
    mov edx, 8
    call write_exact
    test eax, eax
    jnz fatal
    mov rdx, [r15 + 32]
    cmp rdx, 8388640
    ja frame_next
    mov edi, 1
    lea rsi, [r15 + OUTPUT]
    call write_exact
    test eax, eax
    jnz fatal
    jmp frame_next

/* A distinct inherited read-only pipe is the trusted connection snapshot. */
d_read_startup_snapshot:
    mov edi, 4
    mov esi, 3
    mov eax, 72
    syscall
    cmp rax, -4095
    jae fatal
    and eax, 3
    jnz fatal
    mov edi, 4
    lea rsi, [r15 + D_START_STAT]
    mov eax, 5
    syscall
    test rax, rax
    jnz fatal
    mov eax, [r15 + D_START_STAT + 24]
    and eax, 0xf000
    cmp eax, 0x1000
    jne fatal
    mov esi, D_SNAPSHOT_BYTES
    call d_allocate
    mov [r15 + D_SNAPSHOT], rax
    mov rsi, rax
    mov edi, 4
    mov edx, 32
    call read_exact
    test eax, eax
    jnz fatal
    mov r12, [r15 + D_SNAPSHOT]
    movabs rax, 0x3154494e49444d48 /* HMDINIT1 */
    cmp [r12], rax
    jne fatal
    cmp qword ptr [r12 + 8], 1
    ja fatal
    cmp qword ptr [r12 + 16], 1
    ja fatal
    mov rdx, [r12 + 24]
    cmp rdx, 8388608
    ja fatal
    cmp qword ptr [r12 + 16], 0
    jne d_snapshot_length_valid
    test rdx, rdx
    jnz fatal
d_snapshot_length_valid:
    mov edi, 4
    lea rsi, [r12 + 32]
    call read_exact
    test eax, eax
    jnz fatal
    mov edi, 4
    lea rsi, [r15 + D_NOTICE]
    mov edx, 1
    call read_exact
    cmp eax, 1
    jne fatal
    lea rdi, [r15 + D_SNAPSHOT_FD]
    call d_close_slot
    mov rdi, [r15 + D_SNAPSHOT]
    mov esi, D_SNAPSHOT_BYTES
    mov edx, 1
    mov eax, 10
    syscall
    test rax, rax
    jnz fatal
    ret

d_startup:
    mov rax, [r15 + D_ENVP]
    mov [r15 + 648], rax
    lea rdi, [rip + d_env_user]
    call find_environment
    mov [r15 + D_USER_PTR], rax
    mov [r15 + D_USER_LEN], rdx
    test rax, rax
    setnz al
    movzx eax, al
    mov [r15 + D_USER_PRESENT], rax
    mov eax, 39
    syscall
    test rax, rax
    jle fatal
    mov [r15 + D_PARENT_PID], rax
    lea rdi, [r15 + INPUT]
    movabs rax, 0x3130514746435248
    mov [rdi], rax
    mov qword ptr [rdi + 8], 6
    mov qword ptr [rdi + 16], 0
    mov qword ptr [r15 + 24], 24
    mov qword ptr [r15 + 800], 3
    lea rax, [r15 + ROOT_WORK + FOOTER]
    mov qword ptr [rax + 120], 1
    jmp owner_resume

d_startup_config_result:
    cmp rax, 32
    jb fatal
    cmp rax, 131103
    ja fatal
    lea rdx, [r15 + OUTPUT]
    movabs rcx, 0x31304d4746435248
    cmp [rdx], rcx
    jne fatal
    sub rax, 32
    cmp [rdx + 24], rax
    jne fatal
    cmp qword ptr [rdx + 8], 0
    je d_startup_present
    cmp qword ptr [rdx + 8], 1
    jne fatal
    cmp qword ptr [rdx + 16], 9
    jne fatal
    cmp rax, 62
    jne fatal
    lea rdi, [rdx + 32]
    lea rsi, [rip + d_disabled_text]
    mov ecx, 62
    repe cmpsb
    jne fatal
    mov qword ptr [r15 + D_STARTUP_MODE], 0
    jmp d_startup_effects
d_startup_present:
    cmp qword ptr [rdx + 16], 0
    jne fatal
    test rax, rax
    jz fatal
    cmp byte ptr [rdx + 32], 47
    jne fatal
    lea rsi, [rdx + 32]
    lea rdi, [r15 + POLICY_INPUT]
    mov [r15 + D_STATE_PTR], rdi
    mov [r15 + D_STATE_LEN], rax
    mov rcx, rax
d_state_copy:
    lodsb
    test al, al
    jz fatal
    stosb
    loop d_state_copy
    mov byte ptr [rdi], 0
    mov qword ptr [r15 + D_STARTUP_MODE], 1
d_startup_effects:
    mov qword ptr [r15 + 800], 0
    /* Private TLS lets the signal handler find only its own fixed wake pipe. */
    mov edi, 0x1002
    mov rsi, r15
    mov eax, 158
    syscall
    test rax, rax
    jnz fatal
    lea rdi, [r15 + D_PIPES]
    mov esi, 0x80800
    mov eax, 293
    syscall
    test rax, rax
    jnz fatal
    mov eax, [r15 + D_PIPES]
    mov [r15 + D_WAKE_R], rax
    mov eax, [r15 + D_PIPES + 4]
    mov [r15 + D_WAKE_W], rax
    lea rax, [rip + d_sigchld]
    mov [r15 + D_SIGNAL_ACTION], rax
    mov qword ptr [r15 + D_SIGNAL_ACTION + 8], 0x14000000
    lea rax, [rip + d_signal_return]
    mov [r15 + D_SIGNAL_ACTION + 16], rax
    mov qword ptr [r15 + D_SIGNAL_ACTION + 24], 0
    mov edi, 17
    lea rsi, [r15 + D_SIGNAL_ACTION]
    xor edx, edx
    mov r10d, 8
    mov eax, 13
    syscall
    test rax, rax
    jnz fatal
    mov qword ptr [r15 + D_SIGNAL_MASK], 65536
    mov edi, 1 /* SIG_UNBLOCK */
    lea rsi, [r15 + D_SIGNAL_MASK]
    xor edx, edx
    mov r10d, 8
    mov eax, 14
    syscall
    test rax, rax
    jnz fatal
    mov qword ptr [r15 + D_SIGNAL_ACTION], 1 /* SIG_IGN */
    mov edi, 13 /* SIGPIPE */
    lea rsi, [r15 + D_SIGNAL_ACTION]
    xor edx, edx
    mov r10d, 8
    mov eax, 13
    syscall
    test rax, rax
    jnz fatal
    call d_launch_fence
    xor edi, edi
    mov esi, 3
    mov eax, 72
    syscall
    cmp rax, -4095
    jae fatal
    or eax, 2048
    mov edx, eax
    mov esi, 4
    mov eax, 72
    syscall
    test rax, rax
    jnz fatal
    mov esi, 268435456
    call d_allocate
    mov [r15 + D_PATH_WORK], rax
    mov esi, 4096
    call d_allocate
    mov [r15 + D_ERRNO_WORK], rax
    jmp d_main

d_allocate:
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

d_launch_fence:
    lea rdi, [rip + d_fence_name]
    mov esi, 3
    mov eax, 319
    syscall
    cmp rax, -4095
    jae fatal
    mov [r15 + D_MEMFD], rax
    mov rdi, rax
    /* The HIA linker binds both this RIP target and the exact embedded ELF. */
    .byte 0x48,0x8d,0x35
fence_blob_displacement:
    .long 0
    .byte 0xba
fence_blob_length:
    .long 0
    mov [r15 + D_BLOB_SIZE], rdx
    call write_exact
    test eax, eax
    jnz fatal
    mov rdi, [r15 + D_MEMFD]
    mov esi, 448
    mov eax, 91
    syscall
    test rax, rax
    jnz fatal
    mov rdi, [r15 + D_MEMFD]
    mov esi, 1033
    mov edx, 15
    mov eax, 72
    syscall
    test rax, rax
    jnz fatal
    mov esi, 1034
    mov eax, 72
    syscall
    and eax, 15
    cmp eax, 15
    jne fatal
    lea rdi, [r15 + D_PIPES]
    mov esi, 0x80000
    mov eax, 293
    syscall
    test rax, rax
    jnz fatal
    mov eax, [r15 + D_PIPES]
    mov [r15 + D_IN_R], rax
    mov eax, [r15 + D_PIPES + 4]
    mov [r15 + D_FENCE_IN], rax
    lea rdi, [r15 + D_PIPES]
    mov esi, 0x80000
    mov eax, 293
    syscall
    test rax, rax
    jnz fatal
    mov eax, [r15 + D_PIPES]
    mov [r15 + D_FENCE_OUT], rax
    mov eax, [r15 + D_PIPES + 4]
    mov [r15 + D_OUT_W], rax
    lea rdi, [r15 + D_PIPES]
    mov esi, 0x80000
    mov eax, 293
    syscall
    test rax, rax
    jnz fatal
    mov eax, [r15 + D_PIPES]
    mov [r15 + D_ERR_R], rax
    mov eax, [r15 + D_PIPES + 4]
    mov [r15 + D_ERR_W], rax
    lea rax, [rip + d_fence_name]
    mov [r15 + D_ARGV], rax
    lea rax, [rip + d_fence_absent]
    mov [r15 + D_ARGV + 8], rax
    mov qword ptr [r15 + D_ARGV + 16], 0
    mov qword ptr [r15 + D_ARGV + 24], 0
    cmp qword ptr [r15 + D_STARTUP_MODE], 0
    je d_fence_argv_ready
    lea rax, [rip + d_fence_option]
    mov [r15 + D_ARGV + 8], rax
    mov rax, [r15 + D_STATE_PTR]
    mov [r15 + D_ARGV + 16], rax
d_fence_argv_ready:
    mov eax, 57
    syscall
    cmp rax, -4095
    jae fatal
    test rax, rax
    jz d_fence_child
    mov [r15 + D_FENCE_PID], rax
    lea rdi, [r15 + D_IN_R]
    call d_close_slot
    lea rdi, [r15 + D_OUT_W]
    call d_close_slot
    lea rdi, [r15 + D_ERR_W]
    call d_close_slot
    mov rdi, [r15 + D_ERR_R]
    lea rsi, [r15 + D_EXEC_ERROR]
    mov edx, 8
    call read_exact
    cmp eax, 1
    jne fatal
    lea rdi, [r15 + D_ERR_R]
    call d_close_slot
    lea rdi, [r15 + D_MEMFD]
    call d_close_slot
    ret

d_fence_child:
    mov edi, 1
    mov esi, 9
    mov eax, 157
    syscall
    test rax, rax
    jnz d_fence_child_error
    mov eax, 110
    syscall
    cmp rax, [r15 + D_PARENT_PID]
    jne d_fence_child_parent_gone
    mov rax, [r15 + D_IN_R]
    mov [r15 + D_DUP_FDS], rax
    mov rax, [r15 + D_OUT_W]
    mov [r15 + D_DUP_FDS + 8], rax
    mov rax, [r15 + D_WAKE_W]
    mov [r15 + D_DUP_FDS + 16], rax
    mov rax, [r15 + D_MEMFD]
    mov [r15 + D_DUP_FDS + 24], rax
    mov rax, [r15 + D_ERR_W]
    mov [r15 + D_DUP_FDS + 32], rax
    xor ebx, ebx
d_fence_preserve_fds:
    mov rdi, [r15 + rbx*8 + D_DUP_FDS]
    mov esi, 1030
    mov edx, 16
    mov eax, 72
    syscall
    cmp rax, -4
    je d_fence_preserve_fds
    cmp rax, 16
    jb d_fence_child_error
    cmp rax, -4095
    jae d_fence_child_error
    mov [r15 + rbx*8 + D_DUP_FDS], rax
    inc ebx
    cmp ebx, 5
    jb d_fence_preserve_fds
    xor ebx, ebx
d_fence_normalize_fds:
    mov rdi, [r15 + rbx*8 + D_DUP_FDS]
    mov esi, ebx
    cmp ebx, 2
    jb d_fence_target_ready
    inc esi
d_fence_target_ready:
    xor edx, edx
    cmp ebx, 3
    jb d_fence_dup_ready
    mov edx, 0x80000
d_fence_dup_ready:
    mov eax, 292
    syscall
    cmp rax, -4
    je d_fence_normalize_fds
    cmp rax, -4095
    jae d_fence_child_error
    inc ebx
    cmp ebx, 5
    jb d_fence_normalize_fds
    mov qword ptr [r15 + D_ERR_W], 5
    mov edi, 2
    mov eax, 3
    syscall
    mov edi, 6
    mov esi, -1
    xor edx, edx
    mov eax, 436
    syscall
    test rax, rax
    jnz d_fence_child_error
    mov edi, 4
    lea rsi, [rip + d_empty]
    lea rdx, [r15 + D_ARGV]
    mov r10, [r15 + D_ENVP]
    mov r8d, 4096
    mov eax, 322
    syscall
d_fence_child_error:
    neg rax
    test rax, rax
    jnz d_fence_error_ready
    mov eax, 5
d_fence_error_ready:
    mov [r15 + D_EXEC_ERROR], rax
    mov rdi, [r15 + D_ERR_W]
    lea rsi, [r15 + D_EXEC_ERROR]
    mov edx, 8
    call write_exact
d_fence_child_parent_gone:
    mov edi, 113
    mov eax, 60
    syscall

d_close_slot:
    mov rax, [rdi]
    test rax, rax
    js d_close_done
    mov qword ptr [rdi], -1
    mov rdi, rax
    mov eax, 3
    syscall
d_close_done:
    ret

d_sigchld:
    mov edi, dword ptr fs:D_WAKE_W
    sub rsp, 8
    mov byte ptr [rsp], 1
    mov rsi, rsp
    mov edx, 1
    mov eax, 1
    syscall
    add rsp, 8
    ret
d_signal_return:
    mov eax, 15
    syscall

d_env_user:
    .asciz "USER="
d_disabled_text:
    .ascii "runtime tools are disabled; start with --runtime-config <file>"
d_fence_name:
    .asciz "hia-directory-shared-fence"
d_fence_option:
    .asciz "--state-root"
d_fence_absent:
    .asciz "--runtime-disabled"
d_empty:
    .byte 0

d_call_caller:
    mov rax, [r15 + D_CURRENT]
    mov r8, [rax + T_WORK]
    mov rdx, [rax + T_OUTPUT]
    mov rcx, [r15 + D_ENTRY_KIND]
    mov [r8 + FOOTER + 120], rcx
    mov rdi, [r15 + D_ENTRY_PTR]
    mov rsi, [r15 + D_ENTRY_LEN]
    mov ecx, ROOT_OUTPUT_CAP
    mov r9d, ROOT_WCAP
    .byte 0xe8
caller_call_displacement:
    .long 0
    mov edx, eax
    cmp rax, rdx
    jne fatal
    ret

d_drive:
    call d_call_caller
    cmp eax, 0xfffffff0
    je d_dispatch
    cmp eax, 0xffffffd2
    je d_pause
    cmp eax, 0xffffffd3
    je d_pause
    mov rbx, [r15 + D_CURRENT]
    mov rdx, [rbx + T_WORK]
    mov rcx, [rdx + 24]
    or rcx, [rdx + 32]
    or rcx, [rdx + 40]
    or rcx, [rdx + 48]
    or rcx, [rdx + 8]
    or rcx, [rbx + T_PID]
    jnz fatal
    cmp eax, ROOT_OUTPUT_CAP
    jbe d_complete_task
    cmp eax, 0xffffffff
    je d_complete_task
    cmp eax, 0xfffffffe
    je d_complete_task
    jmp fatal
d_pause:
    ret

d_dispatch:
    mov rbx, [r15 + D_CURRENT]
    mov r14, [rbx + T_WORK]
    lea r13, [r14 + 256]
    movabs rax, 0x3130414343444d48 /* HMDCCA01 */
    cmp [r13], rax
    jne fatal
    mov rax, [rbx + T_SEQUENCE]
    inc rax
    jz fatal
    cmp [r13 + 8], rax
    jne fatal
    cmp [r14 + 16], rax
    jne fatal
    mov [rbx + T_SEQUENCE], rax
    mov rax, [r13 + 24]
    or rax, [r13 + 64]
    or rax, [r13 + 72]
    or rax, [r13 + 80]
    or rax, [r13 + 88]
    jnz fatal
    cmp qword ptr [r13 + 32], 4096
    jne fatal
    cmp qword ptr [r13 + 48], 67117056
    jne fatal
    mov rax, [r13 + 40]
    cmp rax, 67108864
    ja fatal
    mov [r15 + D_CHILD_LEN], rax
    cmp qword ptr [r13 + 56], ROOT_OUTPUT_CAP
    ja fatal
    mov rcx, [r13 + 16]
    cmp rcx, 1
    je d_fence_request
    cmp rcx, 2
    je d_context_request
    cmp rcx, 3
    je d_session_request
    cmp rcx, 4
    je d_config_request
    cmp rcx, 5
    je d_path_request
    cmp rcx, 6
    je d_policy_request
    cmp rcx, 7
    je d_mkdir_request
    cmp rcx, 8
    je d_errno_request
    jmp fatal

d_child_completed:
    mov edx, eax
    cmp rax, rdx
    jne fatal
    mov rbx, [r15 + D_CURRENT]
    mov r14, [rbx + T_WORK]
    cmp rax, [r14 + 256 + 56]
    jbe d_child_bound
    cmp eax, 0xffffffff
    je d_child_bound
    cmp eax, 0xfffffffe
    jne fatal
d_child_bound:
    mov [r14 + 256 + 72], rax
    mov rax, [rbx + T_SEQUENCE]
    cmp [r14 + 256 + 8], rax
    jne fatal
    mov [r14 + 256 + 64], rax
    mov qword ptr [r15 + D_ENTRY_KIND], 2
    mov qword ptr [r15 + D_ENTRY_LEN], 0
    lea rax, [rip + d_empty]
    mov [r15 + D_ENTRY_PTR], rax
    jmp d_drive

d_fence_request:
    cmp rax, 64
    jne fatal
    cmp qword ptr [r13 + 56], 64
    jne fatal
    lea r12, [r14 + 4096]
    movabs rcx, 0x3130595341464648
    cmp [r12], rcx
    jne fatal
    mov rcx, [r12 + 32]
    or rcx, [r12 + 40]
    or rcx, [r12 + 48]
    or rcx, [r12 + 56]
    jnz fatal
    cmp qword ptr [r14 + 8], 1
    je d_fence_create
    cmp qword ptr [r12 + 24], 0
    jne fatal
    cmp qword ptr [r14 + 8], 2
    je d_fence_poll
    cmp qword ptr [r14 + 8], 90
    je d_fence_release
    cmp qword ptr [r14 + 8], 92
    jne fatal
    cmp qword ptr [r12 + 8], 3
    jne fatal
    jmp d_fence_retire_id
d_fence_release:
    cmp qword ptr [r12 + 8], 5
    jne fatal
d_fence_retire_id:
    mov rcx, [r14 + 168]
    cmp [r12 + 16], rcx
    jne fatal
    jmp d_fence_ipc
d_fence_create:
    cmp qword ptr [r12 + 8], 1
    jne fatal
    cmp qword ptr [r12 + 16], 0
    jne fatal
    cmp qword ptr [r12 + 24], 1
    jne fatal
    jmp d_fence_ipc
d_fence_poll:
    cmp qword ptr [r12 + 8], 8
    jne fatal
    mov rcx, [r14 + 32]
    cmp [r12 + 16], rcx
    jne fatal
d_fence_ipc:
    cmp qword ptr [r15 + D_FENCE_CLOSED], 0
    jne fatal
    mov qword ptr [r15 + D_REPLY], 64
    mov rdi, [r15 + D_FENCE_IN]
    lea rsi, [r15 + D_REPLY]
    mov edx, 8
    call write_exact
    test eax, eax
    jnz fatal
    mov rdi, [r15 + D_FENCE_IN]
    mov rsi, r12
    mov edx, 64
    call write_exact
    test eax, eax
    jnz fatal
    mov rdi, [r15 + D_FENCE_OUT]
    lea rsi, [r15 + D_REPLY]
    mov edx, 8
    call read_exact
    test eax, eax
    jnz fatal
    cmp qword ptr [r15 + D_REPLY], 64
    jne fatal
    mov rdi, [r15 + D_FENCE_OUT]
    lea rsi, [r14 + 67117056]
    mov edx, 64
    call read_exact
    test eax, eax
    jnz fatal
    mov eax, 64
    jmp d_child_completed

d_context_request:
    cmp qword ptr [r14 + 8], 3
    jne fatal
    cmp qword ptr [r13 + 56], 32
    jne fatal
    cmp rax, 40
    jb fatal
    cmp rax, 16777256
    ja fatal
    movabs rcx, 0x3130514343535248 /* HRSCCQ01 */
    cmp [r14 + 4096], rcx
    jne fatal
    mov qword ptr [r15 + D_POLICY_PARENT], 0
    jmp context_resume
d_session_request:
    cmp qword ptr [r14 + 8], 4
    jne fatal
    cmp rax, 32
    jne fatal
    cmp qword ptr [r13 + 56], 16777216
    jne fatal
    movabs rcx, 0x3130305157535248
    cmp [r14 + 4096], rcx
    jne fatal
    cmp qword ptr [r14 + 4104], 2
    jne fatal
    mov rcx, [r14 + 4112]
    or rcx, [r14 + 4120]
    jnz fatal
    mov qword ptr [r15 + 912], 3
    mov qword ptr [r15 + 896], 32
    mov qword ptr [r15 + 904], 16777216
    jmp session_resume
d_config_request:
    cmp qword ptr [r13 + 56], ROOT_OUTPUT_CAP
    jne fatal
    movabs rcx, 0x3130514746435248
    cmp [r14 + 4096], rcx
    jne fatal
    cmp qword ptr [r14 + 8], 5
    je d_config_state_query
    cmp qword ptr [r14 + 8], 8
    jne fatal
    cmp qword ptr [r14 + 4104], 8
    jne fatal
    cmp rax, 64
    jb fatal
    cmp qword ptr [r14 + 4096 + 40], 1
    jne fatal
    jmp d_config_query_ready
d_config_state_query:
    cmp qword ptr [r14 + 4104], 6
    jne fatal
    cmp rax, 24
    jne fatal
d_config_query_ready:
    mov rcx, [r14 + 4112]
    add rcx, 24
    jc fatal
    cmp rcx, rax
    jne fatal
    mov qword ptr [r15 + 800], 2
    lea rax, [r15 + ROOT_WORK + FOOTER]
    mov qword ptr [rax + 120], 1
    jmp owner_resume

d_path_request:
    cmp qword ptr [r14 + 8], 6
    jne fatal
    cmp qword ptr [r13 + 56], 33554432
    jne fatal
    cmp rax, 56
    jb fatal
    cmp rax, 33554432
    ja fatal
    movabs rcx, 0x3130514c4f535248 /* HRSOLQ01 */
    cmp [r14 + 4096], rcx
    jne fatal
    cmp qword ptr [r14 + 4104], 2
    jne fatal
    lea rdi, [r14 + 4096]
    mov rsi, rax
    lea rdx, [r14 + 67117056]
    mov ecx, 33554432
    mov r8, [r15 + D_PATH_WORK]
    mov r9d, ROOT_WCAP
    .byte 0xe8
path_call_displacement:
    .long 0
    jmp d_child_completed

d_policy_request:
    cmp qword ptr [r14 + 8], 7
    je d_local_policy_phase
    cmp qword ptr [r14 + 8], 9
    jne fatal
d_local_policy_phase:
    cmp qword ptr [r13 + 56], ROOT_OUTPUT_CAP
    jne fatal
    cmp rax, 24
    jb fatal
    cmp rax, 33554456
    ja fatal
    movabs rcx, 0x31305143504c5248 /* HRLPCQ01 */
    cmp [r14 + 4096], rcx
    jne fatal
    cmp qword ptr [r14 + 4104], 1
    jne fatal
    mov rcx, [r14 + 4112]
    add rcx, 24
    jc fatal
    cmp rax, rcx
    jne fatal
    mov qword ptr [r15 + D_POLICY_PARENT], 1
    /* A preceding context may have used canonical's is_dir route. This new
       call belongs to policy, including every resumed canonical effect. */
    mov qword ptr [r15 + 920], 0
    jmp policy_resume

d_mkdir_request:
    cmp qword ptr [r14 + 8], 10
    jne fatal
    cmp qword ptr [r13 + 56], 32
    jne fatal
    cmp rax, 24
    jb fatal
    cmp rax, 33554456
    ja fatal
    movabs rcx, 0x3130515249444d48 /* HMDIRQ01 */
    cmp [r14 + 4096], rcx
    jne fatal
    cmp qword ptr [r14 + 4104], 1
    jne fatal
    mov rcx, [r14 + 4112]
    add rcx, 24
    jc fatal
    cmp rax, rcx
    jne fatal
    mov rcx, [rbx + T_PID]
    or rcx, [rbx + T_JOB]
    jnz fatal
    call d_launch_mkdir
    mov rbx, [r15 + D_CURRENT]
    mov r14, [rbx + T_WORK]
    lea rdx, [r14 + 67117056]
    movabs rcx, 0x313053524a444d48 /* HMDJRS01 */
    mov [rdx], rcx
    mov qword ptr [rdx + 8], 0
    mov rcx, [rbx + T_JOB]
    mov [rdx + 16], rcx
    mov [rdx + 24], rax
    test rax, rax
    jz d_mkdir_start_ready
    cmp rax, 4095
    ja fatal
    test rcx, rcx
    jnz fatal
    mov qword ptr [rdx + 8], 1
d_mkdir_start_ready:
    mov eax, 32
    jmp d_child_completed

d_errno_request:
    cmp qword ptr [r14 + 8], 11
    jne fatal
    cmp rax, 16
    jne fatal
    cmp qword ptr [r13 + 56], 4096
    jne fatal
    movabs rcx, 0x3130515245444d48 /* HMDERQ01 */
    cmp [r14 + 4096], rcx
    jne fatal
    lea rdi, [r14 + 4096]
    mov esi, 16
    lea rdx, [r14 + 67117056]
    mov ecx, 4096
    mov r8, [r15 + D_ERRNO_WORK]
    mov r9d, 4096
    .byte 0xe8
errno_call_displacement:
    .long 0
    jmp d_child_completed

/* Private lifecycle frames schedule real owners; they carry no authority. */
d_main:
    call d_scan_tasks
    call d_reap_fence
    cmp qword ptr [r15 + D_CLOSING], 0
    jne d_closing_loop
    call d_read_input
    test eax, eax
    jnz d_main
    jmp d_wait_events
d_closing_loop:
    call d_close_fence_when_unused
    cmp qword ptr [r15 + D_HEAD], 0
    jne d_wait_events
    cmp qword ptr [r15 + D_FENCE_PID], 0
    jne d_wait_events
    jmp frame_eof

d_wait_events:
    mov dword ptr [r15 + D_POLL], 0
    mov word ptr [r15 + D_POLL + 4], 1
    mov word ptr [r15 + D_POLL + 6], 0
    cmp qword ptr [r15 + D_CLOSING], 0
    je d_poll_stdin_ready
    mov dword ptr [r15 + D_POLL], -1
d_poll_stdin_ready:
    mov eax, [r15 + D_WAKE_R]
    mov [r15 + D_POLL + 8], eax
    mov word ptr [r15 + D_POLL + 12], 1
    mov word ptr [r15 + D_POLL + 14], 0
    lea rdi, [r15 + D_POLL]
    mov esi, 2
    mov edx, -1
    mov eax, 7
    syscall
    cmp rax, -4
    je d_main
    test rax, rax
    jle fatal
    test word ptr [r15 + D_POLL + 6], 0x28
    jnz fatal
    test word ptr [r15 + D_POLL + 14], 0x38
    jnz fatal
d_drain_notices:
    mov rdi, [r15 + D_WAKE_R]
    lea rsi, [r15 + D_NOTICE]
    mov edx, 8
    xor eax, eax
    syscall
    cmp rax, -4
    je d_drain_notices
    cmp rax, -11
    je d_main
    test rax, rax
    jle fatal
    jmp d_drain_notices

/* Returns one when a complete frame or EOF was consumed, zero on EAGAIN. */
d_read_input:
    cmp qword ptr [r15 + D_INPUT_STAGE], 0
    jne d_read_body
    lea rsi, [r15 + D_FRAME_HEADER]
    mov edx, 8
    jmp d_read_selected
d_read_body:
    lea rsi, [r15 + POLICY_INPUT]
    mov rdx, [r15 + D_INPUT_LEN]
d_read_selected:
    mov rcx, [r15 + D_INPUT_USED]
    add rsi, rcx
    sub rdx, rcx
    jz fatal
    xor edi, edi
    xor eax, eax
    syscall
    cmp rax, -4
    je d_read_input
    cmp rax, -11
    je d_read_would_block
    test rax, rax
    js fatal
    jz d_input_eof
    add [r15 + D_INPUT_USED], rax
    cmp qword ptr [r15 + D_INPUT_STAGE], 0
    jne d_body_progress
    cmp qword ptr [r15 + D_INPUT_USED], 8
    jb d_read_input
    jne fatal
    mov rax, [r15 + D_FRAME_HEADER]
    cmp rax, 32
    jb fatal
    cmp rax, 16777288
    ja fatal
    mov [r15 + D_INPUT_LEN], rax
    mov qword ptr [r15 + D_INPUT_STAGE], 1
    mov qword ptr [r15 + D_INPUT_USED], 0
    jmp d_read_input
d_body_progress:
    mov rax, [r15 + D_INPUT_USED]
    cmp rax, [r15 + D_INPUT_LEN]
    jb d_read_input
    jne fatal
    call d_control
    mov qword ptr [r15 + D_INPUT_STAGE], 0
    mov qword ptr [r15 + D_INPUT_USED], 0
    mov qword ptr [r15 + D_INPUT_LEN], 0
    mov eax, 1
    ret
d_read_would_block:
    xor eax, eax
    ret
d_input_eof:
    cmp qword ptr [r15 + D_INPUT_STAGE], 0
    jne fatal
    cmp qword ptr [r15 + D_INPUT_USED], 0
    jne fatal
    mov qword ptr [r15 + D_CLOSING], 1
    mov eax, 1
    ret

d_control:
    lea r12, [r15 + POLICY_INPUT]
    movabs rax, 0x31304c5443444d48 /* HMDCTL01 */
    cmp [r12], rax
    jne fatal
    mov rax, [r15 + D_INPUT_LEN]
    sub rax, 32
    cmp [r12 + 24], rax
    jne fatal
    mov rcx, [r12 + 8]
    mov [r15 + D_CONTROL_CMD], rcx
    mov rdx, [r12 + 16]
    test rdx, rdx
    jz fatal
    mov [r15 + D_CONTROL_ID], rdx
    cmp rcx, 1
    je d_begin_control
    test rax, rax
    jnz fatal
    cmp rcx, 2
    je d_cancel_control
    cmp rcx, 3
    jne fatal
d_cancel_control:
    mov rbx, [r15 + D_HEAD]
d_find_control:
    test rbx, rbx
    jz d_control_missing
    cmp [rbx + T_ID], rdx
    je d_cancel_found
    mov rbx, [rbx + T_NEXT]
    jmp d_find_control
d_cancel_found:
    mov [r15 + D_CURRENT], rbx
    mov rax, [r15 + D_CONTROL_CMD]
    inc rax /* soft cancellation is event 3, outer drop is event 4 */
    mov [r15 + D_ENTRY_KIND], rax
    mov qword ptr [r15 + D_ENTRY_LEN], 0
    lea rax, [rip + d_empty]
    mov [r15 + D_ENTRY_PTR], rax
    call d_drive
    xor edx, edx
    jmp d_emit_control_ack
d_control_missing:
    mov edx, 1
d_emit_control_ack:
    mov rax, [r15 + D_CONTROL_CMD]
    inc rax
    mov [r15 + D_EMIT_EVENT], rax
    mov rax, [r15 + D_CONTROL_ID]
    mov [r15 + D_EMIT_ID], rax
    mov [r15 + D_EMIT_CODE], rdx
    mov qword ptr [r15 + D_EMIT_LEN], 0
    call d_emit
    ret

d_begin_control:
    cmp rdx, [r15 + D_LAST_ID]
    jbe fatal
    mov [r15 + D_LAST_ID], rdx
    mov esi, D_TASK_BYTES
    call d_allocate
    mov rbx, rax
    mov rdx, [r15 + D_HEAD]
    mov [rbx + T_NEXT], rdx
    mov [r15 + D_HEAD], rbx
    mov [r15 + D_CURRENT], rbx
    mov rdx, [r15 + D_CONTROL_ID]
    mov [rbx + T_ID], rdx
    lea rax, [rbx + 4096]
    mov [rbx + T_WORK], rax
    lea rax, [rbx + 268439552]
    mov [rbx + T_OUTPUT], rax
    mov qword ptr [rbx + T_FD], -1
    mov qword ptr [rbx + T_STATUS], 1
    mov rdi, [rbx + T_WORK]
    add rdi, 4096
    mov [r15 + D_ENTRY_PTR], rdi
    movabs rax, 0x3230464343444d48 /* HMDCCF02 */
    mov [rdi], rax
    mov rax, [r15 + D_USER_PRESENT]
    mov [rdi + 8], rax
    mov rcx, [r15 + D_USER_LEN]
    mov [rdi + 16], rcx
    mov r12, [r15 + D_SNAPSHOT]
    mov rax, [r12 + 8]
    mov [rdi + 24], rax
    mov rax, [r12 + 16]
    mov [rdi + 32], rax
    mov rdx, [r12 + 24]
    mov [rdi + 40], rdx
    mov qword ptr [rdi + 48], 0
    lea rax, [rcx + rdx + 56]
    mov [r15 + D_ENTRY_LEN], rax
    mov rsi, [r15 + D_USER_PTR]
    add rdi, 56
    rep movsb
    lea rsi, [r12 + 32]
    mov rcx, [r12 + 24]
    rep movsb
    mov qword ptr [r15 + D_ENTRY_KIND], 0
    call d_call_caller
    test rax, rax
    jnz fatal
    mov qword ptr [r15 + D_EMIT_EVENT], 1
    mov rax, [r15 + D_CONTROL_ID]
    mov [r15 + D_EMIT_ID], rax
    mov qword ptr [r15 + D_EMIT_CODE], 0
    mov qword ptr [r15 + D_EMIT_LEN], 0
    call d_emit
    lea rax, [r15 + POLICY_INPUT + 32]
    mov [r15 + D_ENTRY_PTR], rax
    mov rax, [r15 + D_INPUT_LEN]
    sub rax, 32
    mov [r15 + D_ENTRY_LEN], rax
    mov qword ptr [r15 + D_ENTRY_KIND], 1
    call d_drive
    ret

d_emit:
    mov rax, [r15 + D_EMIT_LEN]
    cmp rax, ROOT_OUTPUT_CAP
    ja fatal
    add rax, 40
    mov [r15 + D_REPLY], rax
    movabs rax, 0x3130525443444d48 /* HMDCTR01 */
    mov [r15 + D_REPLY + 8], rax
    mov rax, [r15 + D_EMIT_EVENT]
    mov [r15 + D_REPLY + 16], rax
    mov rax, [r15 + D_EMIT_ID]
    mov [r15 + D_REPLY + 24], rax
    mov rax, [r15 + D_EMIT_CODE]
    mov [r15 + D_REPLY + 32], rax
    mov rax, [r15 + D_EMIT_LEN]
    mov [r15 + D_REPLY + 40], rax
    mov edi, 1
    lea rsi, [r15 + D_REPLY]
    mov edx, 48
    call write_exact
    test eax, eax
    jnz fatal
    mov edi, 1
    mov rsi, [r15 + D_EMIT_PTR]
    mov rdx, [r15 + D_EMIT_LEN]
    call write_exact
    test eax, eax
    jnz fatal
    ret

d_complete_task:
    mov [r15 + D_RESULT_CODE], rax
    mov qword ptr [r15 + D_EMIT_EVENT], 2
    mov rax, [rbx + T_ID]
    mov [r15 + D_EMIT_ID], rax
    mov rax, [r15 + D_RESULT_CODE]
    mov [r15 + D_EMIT_CODE], rax
    mov qword ptr [r15 + D_EMIT_LEN], 0
    cmp rax, ROOT_OUTPUT_CAP
    ja d_complete_payload_ready
    mov [r15 + D_EMIT_LEN], rax
    mov rax, [rbx + T_OUTPUT]
    mov [r15 + D_EMIT_PTR], rax
d_complete_payload_ready:
    call d_emit
    mov rbx, [r15 + D_CURRENT]
    cmp qword ptr [rbx + T_PID], 0
    jne fatal
    cmp qword ptr [rbx + T_FD], -1
    jne fatal
    lea rdi, [r15 + D_HEAD]
d_unlink_task:
    mov rax, [rdi]
    test rax, rax
    jz fatal
    cmp rax, rbx
    je d_unlink_found
    lea rdi, [rax + T_NEXT]
    jmp d_unlink_task
d_unlink_found:
    mov rax, [rbx + T_NEXT]
    mov [rdi], rax
    mov qword ptr [r15 + D_CURRENT], 0
    mov rdi, rbx
    mov esi, D_TASK_BYTES
    mov eax, 11
    syscall
    test rax, rax
    jnz fatal
    ret

d_scan_tasks:
    mov rax, [r15 + D_HEAD]
    mov [r15 + D_SCAN], rax
d_scan_next:
    mov rbx, [r15 + D_SCAN]
    test rbx, rbx
    jz d_scan_done
    mov [r15 + D_CURRENT], rbx
    mov rax, [rbx + T_NEXT]
    mov [r15 + D_SCAN_NEXT], rax
    cmp qword ptr [r15 + D_CLOSING], 0
    je d_scan_job
    cmp qword ptr [rbx + T_DROP_SENT], 0
    jne d_scan_job
    mov qword ptr [rbx + T_DROP_SENT], 1
    mov qword ptr [r15 + D_ENTRY_KIND], 4
    mov qword ptr [r15 + D_ENTRY_LEN], 0
    lea rax, [rip + d_empty]
    mov [r15 + D_ENTRY_PTR], rax
    call d_drive
    mov rbx, [r15 + D_CURRENT]
    test rbx, rbx
    jz d_scan_advance
d_scan_job:
    cmp qword ptr [rbx + T_PID], 0
    je d_scan_future
    call d_job_progress
    jmp d_scan_advance
d_scan_future:
    mov rdx, [rbx + T_WORK]
    cmp qword ptr [rdx + 32], 0
    je d_scan_advance
    cmp qword ptr [rdx + 64], 0
    jne fatal
    mov qword ptr [r15 + D_ENTRY_KIND], 6
    mov qword ptr [r15 + D_ENTRY_LEN], 0
    lea rax, [rip + d_empty]
    mov [r15 + D_ENTRY_PTR], rax
    call d_drive
d_scan_advance:
    mov rax, [r15 + D_SCAN_NEXT]
    mov [r15 + D_SCAN], rax
    jmp d_scan_next
d_scan_done:
    mov qword ptr [r15 + D_CURRENT], 0
    ret

/* Only waitpid success can turn a submitted task into a HIA completion. */
d_job_progress:
    call d_job_drain
    mov rbx, [r15 + D_CURRENT]
d_job_wait:
    mov rdi, [rbx + T_PID]
    lea rsi, [rbx + T_WSTATUS]
    mov edx, 1 /* WNOHANG */
    xor r10d, r10d
    mov eax, 61
    syscall
    cmp rax, -4
    je d_job_wait
    test rax, rax
    jz d_job_pending
    cmp rax, [rbx + T_PID]
    jne fatal
    mov qword ptr [rbx + T_PID], 0
    call d_job_drain
    mov rbx, [r15 + D_CURRENT]
    lea rdi, [rbx + T_FD]
    call d_close_slot
    mov r14, [rbx + T_WORK]
    mov rax, [rbx + T_JOB]
    test rax, rax
    jz fatal
    cmp [r14 + 48], rax
    jne fatal
    mov [r14 + FOOTER + 128], rax
    mov qword ptr [rbx + T_JOB], 0
    mov qword ptr [r15 + D_ENTRY_KIND], 7
    mov qword ptr [r15 + D_ENTRY_LEN], 0
    lea rax, [rip + d_empty]
    mov [r15 + D_ENTRY_PTR], rax
    mov qword ptr [r14 + FOOTER + 136], 1
    cmp qword ptr [rbx + T_WSTATUS], 0
    jne d_job_deliver
    cmp qword ptr [rbx + T_GOT], 40
    jne d_job_deliver
    cmp qword ptr [rbx + T_PIPE_EOF], 1
    jne d_job_deliver
    cmp qword ptr [rbx + T_PIPE_FAIL], 0
    jne d_job_deliver
    mov qword ptr [r14 + FOOTER + 136], 0
    lea rax, [rbx + T_RESPONSE]
    mov [r15 + D_ENTRY_PTR], rax
    mov qword ptr [r15 + D_ENTRY_LEN], 40
d_job_deliver:
    call d_drive
d_job_pending:
    ret

d_job_drain:
    mov rbx, [r15 + D_CURRENT]
    cmp qword ptr [rbx + T_FD], -1
    je d_job_drain_done
    cmp qword ptr [rbx + T_PIPE_EOF], 0
    jne d_job_drain_done
    mov rcx, [rbx + T_GOT]
    cmp rcx, 40
    ja d_job_drain_done
    mov edx, 41
    sub rdx, rcx
    lea rsi, [rbx + T_RESPONSE]
    add rsi, rcx
    mov rdi, [rbx + T_FD]
    xor eax, eax
    syscall
    cmp rax, -4
    je d_job_drain
    cmp rax, -11
    je d_job_drain_done
    test rax, rax
    js d_job_read_error
    jz d_job_read_eof
    add [rbx + T_GOT], rax
    cmp qword ptr [rbx + T_GOT], 40
    ja d_job_read_error
    jmp d_job_drain
d_job_read_eof:
    mov qword ptr [rbx + T_PIPE_EOF], 1
    ret
d_job_read_error:
    mov qword ptr [rbx + T_PIPE_FAIL], 1
    lea rdi, [rbx + T_FD]
    call d_close_slot
d_job_drain_done:
    ret

d_reap_fence:
    cmp qword ptr [r15 + D_FENCE_PID], 0
    je d_fence_reap_done
d_fence_wait:
    mov rdi, [r15 + D_FENCE_PID]
    lea rsi, [r15 + D_WSTATUS]
    mov edx, 1
    xor r10d, r10d
    mov eax, 61
    syscall
    cmp rax, -4
    je d_fence_wait
    test rax, rax
    jz d_fence_reap_done
    cmp rax, [r15 + D_FENCE_PID]
    jne fatal
    mov qword ptr [r15 + D_FENCE_PID], 0
    cmp qword ptr [r15 + D_FENCE_CLOSED], 1
    jne fatal
    cmp dword ptr [r15 + D_WSTATUS], 0
    jne fatal
    lea rdi, [r15 + D_FENCE_OUT]
    call d_close_slot
d_fence_reap_done:
    ret

d_close_fence_when_unused:
    cmp qword ptr [r15 + D_FENCE_CLOSED], 0
    jne d_fence_close_done
    mov rbx, [r15 + D_HEAD]
d_find_live_permit:
    test rbx, rbx
    jz d_fence_close
    mov rdx, [rbx + T_WORK]
    mov rax, [rdx + 32]
    or rax, [rdx + 40]
    jnz d_fence_close_done
    mov rbx, [rbx + T_NEXT]
    jmp d_find_live_permit
d_fence_close:
    mov qword ptr [r15 + D_FENCE_CLOSED], 1
    lea rdi, [r15 + D_FENCE_IN]
    call d_close_slot
d_fence_close_done:
    ret

/* Fatal paths retire channels and reap only this parent's registered children. */
d_cleanup:
    push rbp
    mov rax, [r15 + D_HEAD]
    mov [r15 + D_SCAN], rax
d_cleanup_kill_tasks:
    mov rbx, [r15 + D_SCAN]
    test rbx, rbx
    jz d_cleanup_kill_fence
    mov rax, [rbx + T_NEXT]
    mov [r15 + D_SCAN], rax
    mov rdi, [rbx + T_PID]
    test rdi, rdi
    jz d_cleanup_kill_tasks
    mov esi, 9
    mov eax, 62
    syscall
    jmp d_cleanup_kill_tasks
d_cleanup_kill_fence:
    mov rdi, [r15 + D_FENCE_PID]
    test rdi, rdi
    jz d_cleanup_join_tasks
    mov esi, 9
    mov eax, 62
    syscall
d_cleanup_join_tasks:
    mov rbx, [r15 + D_HEAD]
    test rbx, rbx
    jz d_cleanup_join_fence
    cmp qword ptr [rbx + T_PID], 0
    je d_cleanup_task_joined
d_cleanup_task_wait:
    mov rdi, [rbx + T_PID]
    lea rsi, [rbx + T_WSTATUS]
    xor edx, edx
    xor r10d, r10d
    mov eax, 61
    syscall
    cmp rax, -4
    je d_cleanup_task_wait
    mov qword ptr [rbx + T_PID], 0
d_cleanup_task_joined:
    lea rdi, [rbx + T_FD]
    call d_close_slot
    mov rax, [rbx + T_NEXT]
    mov [r15 + D_HEAD], rax
    mov rdi, rbx
    mov esi, D_TASK_BYTES
    mov eax, 11
    syscall
    jmp d_cleanup_join_tasks
d_cleanup_join_fence:
    cmp qword ptr [r15 + D_FENCE_PID], 0
    je d_cleanup_channels
d_cleanup_fence_wait:
    mov rdi, [r15 + D_FENCE_PID]
    lea rsi, [r15 + D_WSTATUS]
    xor edx, edx
    xor r10d, r10d
    mov eax, 61
    syscall
    cmp rax, -4
    je d_cleanup_fence_wait
    mov qword ptr [r15 + D_FENCE_PID], 0
d_cleanup_channels:
    lea rdi, [r15 + D_FENCE_IN]
    call d_close_slot
    lea rdi, [r15 + D_FENCE_OUT]
    call d_close_slot
    lea rdi, [r15 + D_MEMFD]
    call d_close_slot
    lea rdi, [r15 + D_ERR_R]
    call d_close_slot
    lea rdi, [r15 + D_ERR_W]
    call d_close_slot
    lea rdi, [r15 + D_IN_R]
    call d_close_slot
    lea rdi, [r15 + D_OUT_W]
    call d_close_slot
    lea rdi, [r15 + D_JOB_R]
    call d_close_slot
    lea rdi, [r15 + D_JOB_W]
    call d_close_slot
    lea rdi, [r15 + D_WAKE_R]
    call d_close_slot
    lea rdi, [r15 + D_WAKE_W]
    call d_close_slot
    mov rdi, [r15 + D_PATH_WORK]
    test rdi, rdi
    jz d_cleanup_errno
    mov esi, ROOT_WCAP
    mov eax, 11
    syscall
d_cleanup_errno:
    mov rdi, [r15 + D_ERRNO_WORK]
    test rdi, rdi
    jz d_cleanup_snapshot
    mov esi, 4096
    mov eax, 11
    syscall
d_cleanup_snapshot:
    lea rdi, [r15 + D_SNAPSHOT_FD]
    call d_close_slot
    mov rdi, [r15 + D_SNAPSHOT]
    test rdi, rdi
    jz d_cleanup_done
    mov esi, D_SNAPSHOT_BYTES
    mov eax, 11
    syscall
d_cleanup_done:
    pop rbp
    ret

/* Each submitted mkdir task owns its process, path snapshot and two FD slots. */
d_launch_mkdir:
    cmp qword ptr [r15 + D_JOB_SEQUENCE], -1
    je d_job_counter_full
    lea rdi, [r15 + D_PIPES]
    mov esi, 0x80800
    mov eax, 293
    syscall
    cmp rax, -4095
    jae d_job_start_errno
    mov eax, [r15 + D_PIPES]
    mov [r15 + D_JOB_R], rax
    mov eax, [r15 + D_PIPES + 4]
    mov [r15 + D_JOB_W], rax
    mov eax, 57
    syscall
    cmp rax, -4095
    jae d_job_fork_error
    test rax, rax
    jz d_mkdir_child
    mov rbx, [r15 + D_CURRENT]
    mov [rbx + T_PID], rax
    mov rax, [r15 + D_JOB_R]
    mov [rbx + T_FD], rax
    mov qword ptr [r15 + D_JOB_R], -1
    mov rax, [r15 + D_JOB_SEQUENCE]
    inc rax
    mov [r15 + D_JOB_SEQUENCE], rax
    mov [rbx + T_JOB], rax
    mov qword ptr [rbx + T_GOT], 0
    mov qword ptr [rbx + T_WSTATUS], 0
    mov qword ptr [rbx + T_PIPE_EOF], 0
    mov qword ptr [rbx + T_PIPE_FAIL], 0
    lea rdi, [r15 + D_JOB_W]
    call d_close_slot
    xor eax, eax
    ret
d_job_fork_error:
    neg rax
    mov [r15 + D_EXEC_ERROR], rax
    lea rdi, [r15 + D_JOB_R]
    call d_close_slot
    lea rdi, [r15 + D_JOB_W]
    call d_close_slot
    mov rax, [r15 + D_EXEC_ERROR]
    ret
d_job_start_errno:
    neg rax
    ret
d_job_counter_full:
    mov eax, 75
    ret

d_mkdir_child:
    mov edi, 1
    mov esi, 9
    mov eax, 157
    syscall
    test rax, rax
    jnz d_worker_bare_fatal
    mov eax, 110
    syscall
    cmp rax, [r15 + D_PARENT_PID]
    jne d_worker_bare_fatal
    mov rbx, [r15 + D_CURRENT]
    mov r12, [rbx + T_WORK]
    add r12, 4096
    mov r13, [r15 + D_CHILD_LEN]
d_worker_preserve_fd:
    mov rdi, [r15 + D_JOB_W]
    mov esi, 1030
    mov edx, 16
    mov eax, 72
    syscall
    cmp rax, -4
    je d_worker_preserve_fd
    cmp rax, -4095
    jae d_worker_bare_fatal
    cmp rax, 16
    jb d_worker_bare_fatal
    mov rdi, rax
d_worker_install_fd:
    mov esi, 3
    mov edx, 0x80000
    mov eax, 292
    syscall
    cmp rax, -4
    je d_worker_install_fd
    cmp rax, 3
    jne d_worker_bare_fatal
    mov edi, 4
    mov esi, -1
    xor edx, edx
    mov eax, 436
    syscall
    test rax, rax
    jnz d_worker_bare_fatal
    xor edi, edi
    mov eax, 3
    syscall
    mov edi, 1
    mov eax, 3
    syscall
    mov edi, 2
    mov eax, 3
    syscall
    xor edi, edi
    mov esi, 33558528
    mov edx, 3
    mov r10d, 34
    mov r8, -1
    xor r9d, r9d
    mov eax, 9
    syscall
    cmp rax, -4095
    jae d_worker_bare_fatal
    mov r15, rax
    mov [r15 + 64], r12
    mov [r15 + 72], r13
d_worker_invoke:
    mov rdi, [r15 + 64]
    mov rsi, [r15 + 72]
    lea rdx, [r15 + 256]
    mov ecx, 40
    lea r8, [r15 + 4096]
    mov r9d, 33554432
    .byte 0xe8
mkdir_call_displacement:
    .long 0
    mov edx, eax
    cmp rax, rdx
    jne d_worker_fatal
    cmp eax, 0xfffffff0
    je d_worker_handle_effect
    cmp eax, 40
    jne d_worker_fatal
    mov rax, [r15 + 24]
    or rax, [r15 + 40]
    jnz d_worker_fatal
    mov edi, 3
    lea rsi, [r15 + 256]
    mov edx, 40
    call write_exact
    test eax, eax
    jnz d_worker_fatal
    mov edi, 3
    mov eax, 3
    syscall
    xor edi, edi
    mov eax, 60
    syscall
d_worker_fatal:
    cmp qword ptr [r15 + 24], 0
    je d_worker_close_second
    mov qword ptr [r15 + 24], 0
    mov rdi, [r15 + 32]
    mov eax, 3
    syscall
d_worker_close_second:
    cmp qword ptr [r15 + 40], 0
    je d_worker_bare_fatal
    mov qword ptr [r15 + 40], 0
    mov rdi, [r15 + 48]
    mov eax, 3
    syscall
d_worker_bare_fatal:
    mov edi, 114
    mov eax, 60
    syscall
d_worker_root_name:
    .asciz "/"

d_worker_handle_effect:
    lea r12, [r15+4096]
    lea r13, [r12+256]
    movabs rax, 0x3130575249444d48
    cmp qword ptr [r12], rax
    jne d_worker_fatal
    movabs rax, 0x3130415249444d48
    cmp qword ptr [r13], rax
    jne d_worker_fatal
    mov rax, qword ptr [r15+8]
    add rax, 1
    jc d_worker_fatal
    cmp qword ptr [r13+8], rax
    jne d_worker_fatal
    cmp qword ptr [r12+16], rax
    jne d_worker_fatal
    mov qword ptr [r15+8], rax
    mov rax, qword ptr [r13+56]
    or rax, qword ptr [r13+64]
    or rax, qword ptr [r13+72]
    or rax, qword ptr [r13+80]
    or rax, qword ptr [r13+88]
    jnz d_worker_fatal
    mov rax, qword ptr [r13+16]
    cmp rax, 1
    je d_worker_effect_root
    cmp rax, 2
    je d_worker_effect_open
    cmp rax, 3
    je d_worker_effect_mkdir
    cmp rax, 4
    je d_worker_effect_close
    jmp d_worker_fatal

d_worker_can_open:
    cmp qword ptr [r15+16], -1
    je d_worker_fatal
    cmp qword ptr [r15+24], 0
    je d_worker_can_open_return
    cmp qword ptr [r15+40], 0
    jne d_worker_fatal
d_worker_can_open_return:
    ret

d_worker_lookup_handle:
    test rdi, rdi
    jz d_worker_fatal
    cmp qword ptr [r15+24], rdi
    je d_worker_found_first
    cmp qword ptr [r15+40], rdi
    jne d_worker_fatal
    lea r14, [r15+40]
    mov rdi, qword ptr [r15+48]
    ret
d_worker_found_first:
    lea r14, [r15+24]
    mov rdi, qword ptr [r15+32]
    ret

d_worker_validate_name:
    cmp qword ptr [r13+32], 4096
    jne d_worker_fatal
    mov rcx, qword ptr [r13+40]
    test rcx, rcx
    jz d_worker_fatal
    cmp rcx, 33554432-4097
    ja d_worker_fatal
    cmp qword ptr [r12+80], rcx
    jne d_worker_fatal
    lea rsi, [r12+4096]
    cmp byte ptr [rsi+rcx], 0
    jne d_worker_fatal
    cmp rcx, 1
    jne d_worker_check_dotdot
    cmp byte ptr [rsi], 46
    je d_worker_fatal
d_worker_check_dotdot:
    cmp rcx, 2
    jne d_worker_scan_name
    cmp word ptr [rsi], 0x2e2e
    je d_worker_fatal
d_worker_scan_name:
    xor edx, edx
d_worker_scan_name_loop:
    cmp byte ptr [rsi+rdx], 0
    je d_worker_fatal
    cmp byte ptr [rsi+rdx], 47
    je d_worker_fatal
    inc rdx
    cmp rdx, rcx
    jb d_worker_scan_name_loop
    mov rdi, qword ptr [r13+24]
    cmp rdi, qword ptr [r12+40]
    jne d_worker_fatal
    call d_worker_lookup_handle
    ret

d_worker_effect_root:
    cmp qword ptr [r12+8], 1
    jne d_worker_fatal
    mov rax, qword ptr [r13+24]
    or rax, qword ptr [r13+32]
    or rax, qword ptr [r13+40]
    or rax, qword ptr [r13+48]
    or rax, qword ptr [r15+24]
    or rax, qword ptr [r15+40]
    jnz d_worker_fatal
    call d_worker_can_open
    mov eax, 257
    mov rdi, -100
    lea rsi, [rip+d_worker_root_name]
    mov edx, 0x2b0000
    xor r10d, r10d
    syscall
    jmp d_worker_opened

d_worker_effect_open:
    cmp qword ptr [r12+8], 2
    je d_worker_open_phase_valid
    cmp qword ptr [r12+8], 5
    jne d_worker_fatal
d_worker_open_phase_valid:
    cmp qword ptr [r13+48], 0
    jne d_worker_fatal
    call d_worker_can_open
    call d_worker_validate_name
    mov eax, 257
    mov edx, 0x2b0000
    xor r10d, r10d
    syscall
d_worker_opened:
    cmp rax, -4095
    jae d_worker_effect_errno
    mov rdx, qword ptr [r15+16]
    inc rdx
    mov qword ptr [r15+16], rdx
    cmp qword ptr [r15+24], 0
    jne d_worker_install_second
    mov qword ptr [r15+24], rdx
    mov qword ptr [r15+32], rax
    jmp d_worker_installed
d_worker_install_second:
    mov qword ptr [r15+40], rdx
    mov qword ptr [r15+48], rax
d_worker_installed:
    mov qword ptr [r13+80], rdx
    jmp d_worker_acknowledge

d_worker_effect_mkdir:
    cmp qword ptr [r12+8], 4
    jne d_worker_fatal
    cmp qword ptr [r13+48], 448
    jne d_worker_fatal
    call d_worker_validate_name
    mov eax, 258
    mov edx, 448
    syscall
    cmp rax, -4095
    jae d_worker_effect_errno
    test rax, rax
    jnz d_worker_fatal
    jmp d_worker_acknowledge

d_worker_effect_close:
    cmp qword ptr [r12+8], 3
    je d_worker_close_phase_valid
    cmp qword ptr [r12+8], 90
    jne d_worker_fatal
d_worker_close_phase_valid:
    mov rax, qword ptr [r13+32]
    or rax, qword ptr [r13+40]
    or rax, qword ptr [r13+48]
    jnz d_worker_fatal
    mov rdi, qword ptr [r13+24]
    cmp rdi, qword ptr [r12+40]
    je d_worker_fatal
    cmp rdi, qword ptr [r12+48]
    je d_worker_fatal
    call d_worker_lookup_handle
    mov qword ptr [r14], 0
    mov eax, 3
    syscall
    cmp rax, -4095
    jae d_worker_effect_errno
    test rax, rax
    jnz d_worker_fatal
    jmp d_worker_acknowledge

d_worker_effect_errno:
    neg rax
    mov qword ptr [r13+72], rax
d_worker_acknowledge:
    mov rax, qword ptr [r13+8]
    mov qword ptr [r13+64], rax
    jmp d_worker_invoke

/* Regex logical IDs stay separate from parent physical member IDs. */
.equ REGEX_CONTEXTS, 3072
.equ REGEX_SEQUENCES, 3584
.equ REGEX_CONTROLLER_WORK, 2382368832
.equ REGEX_SYNTAX_WORK, 2650804288
.equ REGEX_HIR_WORK, 2919239744
.equ REGEX_NFA_WORK, 3187675200
.equ REGEX_MATCH_WORK, 3456110656
.equ REGEX_DATA_WORK, 3489665088
.global regex_syntax_call_displacement
.global regex_unicode_data_call_displacement
.global regex_hir_call_displacement
.global regex_nfa_call_displacement
.global regex_match_call_displacement
.global regex_controller_call_displacement

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

