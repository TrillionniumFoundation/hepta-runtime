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
    mov [r15 + WD_STACK], rbx
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
    xor edi, edi
    lea rsi, [r15 + 32]
    mov edx, 8
    call read_exact
    cmp eax, 1
    je frame_eof
    test eax, eax
    jnz fatal
    mov rax, [r15 + 32]
    cmp rax, 16777256
    ja fatal
    mov [r15 + WD_LENGTH], rax
    xor edi, edi
    mov rsi, [r15 + WD_INPUT]
    mov rdx, rax
    call read_exact
    test eax, eax
    jnz fatal
    jmp wd_resume
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
    je owner_input_selected
    cmp qword ptr [r15 + 800], 1
    jne fatal
    lea r13, [r15 + POLICY_WORK + 4096]
    lea r12, [r15 + POLICY_WORK + 67117056]
    mov rsi, [r15 + 808]
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
    cmp qword ptr [r15 + 80], 13
    je wd_params_value_completed
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
    je wd_config_completed
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
    lea r14, [r15 + POLICY_WORK]
    mov rdi, r13
    mov rsi, [r15 + 896]
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
    jmp context_child_completed

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
    cmp r14, 8
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
    cmp r14, 8
    je canon_lstat
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
canon_lstat:
    mov edi, -100
    lea rdx, [r12+512]
    mov r10d, 0x100
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
    lea r13, [r15 + POLICY_INPUT]
    lea r12, [r15 + OUTPUT]
    lea r14, [r15 + CONTEXT_WORK]
    mov rdi, r13
    mov rsi, [r15 + 888]
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
    cmp qword ptr [r15 + WD_CHILD], 2
    je wd_context_completed
    cmp eax, 0xffffffff
    je context_write
    cmp eax, 0xfffffffe
    je context_write
    cmp eax, 32
    jne fatal
    lea rdx, [r15 + OUTPUT]
    movabs rcx, 0x3130525043535248 /* HRSCPR01 */
    cmp [rdx], rcx
    jne fatal
    mov rcx, [rdx + 8]
    or rcx, [rdx + 16]
    or rcx, [rdx + 24]
    jnz fatal
    /* Observe the same private state only after the complete context call. */
    lea r13, [r15 + INPUT]
    movabs rax, 0x3130305157535248
    mov [r13], rax
    mov qword ptr [r13 + 8], 2
    mov qword ptr [r13 + 16], 0
    mov qword ptr [r13 + 24], 0
    mov qword ptr [r15 + 896], 32
    mov qword ptr [r15 + 904], 8388640
    mov qword ptr [r15 + 912], 2
    jmp session_resume

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
shared_value_call:
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
    cmp qword ptr [r15 + 912], 1
    jne session_buffers_selected
    lea r13, [r15 + CONTEXT_WORK + 4096]
    lea r12, [r15 + CONTEXT_WORK + 67117056]
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
    je wd_session_completed
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
    jmp wd_initialize
context_observed:
    cmp qword ptr [rdx + 8], 1
    jne fatal
    cmp qword ptr [rdx + 16], 0
    jne fatal
    mov rcx, rax
    sub rcx, 32
    cmp [rdx + 24], rcx
    jne fatal
    jmp wd_publish
context_child_completed:
    cmp qword ptr [r15 + WD_CHILD], 6
    je wd_policy_completed
    cmp qword ptr [r15 + WD_CHILD], 8
    je wd_policy_completed
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

/* Private, fixed-image byte and syscall dispatch.  All path and tool choices
 * belong to HIA.  The output wrapper observes the same session after a call. */
.global caller_call_displacement
.global params_call_displacement
.global path_call_displacement
.global raw_canonical_call_displacement
.equ WD_CALLER, 960
.equ WD_PARAMS, 968
.equ WD_PATH, 976
.equ WD_RAW, 984
.equ WD_INPUT, 992
.equ WD_LENGTH, 1000
.equ WD_SEQUENCE, 1008
.equ WD_CHILD, 1016
.equ WD_CHILD_LENGTH, 1024
.equ WD_CHILD_CAP, 1032
.equ WD_PARAMS_SEQUENCE, 1040
.equ WD_VALUE_LENGTH, 1048
.equ WD_READY, 1056
.equ WD_START_LENGTH, 1064
.equ WD_STACK, 1072
.equ WD_USER, 1080
.equ WD_USER_LENGTH, 1088
.equ WD_USER_PRESENT, 1096
.equ WD_RESULT_LENGTH, 1104
.equ WD_SNAPSHOT, 1120
.equ WD_OBSERVATION, 1160

wd_mmap:
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

wd_initialize:
    mov edi, ROOT_WCAP
    call wd_mmap
    mov [r15 + WD_CALLER], rax
    mov edi, ROOT_WCAP
    call wd_mmap
    mov [r15 + WD_PARAMS], rax
    mov edi, ROOT_WCAP
    call wd_mmap
    mov [r15 + WD_PATH], rax
    mov edi, 4096
    call wd_mmap
    mov [r15 + WD_RAW], rax
    mov qword ptr [rax + 72], -1
    mov qword ptr [rax + 80], -1
    mov edi, 16781312
    call wd_mmap
    mov [r15 + WD_INPUT], rax
    mov rbx, [r15 + WD_STACK]
    mov rax, [rbx]
    lea rsi, [rbx + rax*8 + 16]
    mov [r15 + 648], rsi
wd_environment_end:
    cmp qword ptr [rsi], 0
    lea rsi, [rsi + 8]
    jne wd_environment_end
wd_auxiliary:
    mov rax, [rsi]
    test rax, rax
    jz wd_auxiliary_done
    cmp rax, 23
    jne wd_auxiliary_next
    xor eax, eax
    cmp qword ptr [rsi + 8], 0
    setne al
    mov rdx, [r15 + WD_RAW]
    mov [rdx + 64], rax
wd_auxiliary_next:
    add rsi, 16
    jmp wd_auxiliary
wd_auxiliary_done:
    lea rdi, [rip + wd_user_name]
    call find_environment
    mov [r15 + WD_USER], rax
    mov [r15 + WD_USER_LENGTH], rdx
    cmp rdx, 131071
    ja fatal
    test rax, rax
    setne al
    movzx eax, al
    mov [r15 + WD_USER_PRESENT], rax
    mov edi, 4
    lea rsi, [r15 + WD_SNAPSHOT]
    mov edx, 32
    call read_exact
    test eax, eax
    jnz fatal
    movabs rax, 0x3154494e49574d48 /* HMWINIT1 */
    cmp [r15 + WD_SNAPSHOT], rax
    jne fatal
    cmp qword ptr [r15 + WD_SNAPSHOT + 8], 1
    ja fatal
    cmp qword ptr [r15 + WD_SNAPSHOT + 16], 1
    ja fatal
    cmp qword ptr [r15 + WD_SNAPSHOT + 24], 8388608
    ja fatal
    lea rdi, [r15 + INPUT]
    movabs rax, 0x3130464344574d48 /* HMWDCF01 */
    mov [rdi], rax
    mov rax, [r15 + WD_USER_PRESENT]
    mov [rdi + 8], rax
    mov rax, [r15 + WD_USER_LENGTH]
    mov [rdi + 16], rax
    mov rax, [r15 + WD_SNAPSHOT + 8]
    mov [rdi + 24], rax
    mov rax, [r15 + WD_SNAPSHOT + 16]
    mov [rdi + 32], rax
    mov rax, [r15 + WD_SNAPSHOT + 24]
    mov [rdi + 40], rax
    mov qword ptr [rdi + 48], 0
    add rdi, 56
    mov rsi, [r15 + WD_USER]
    mov rcx, [r15 + WD_USER_LENGTH]
    rep movsb
    mov rsi, rdi
    mov edi, 4
    mov rdx, [r15 + WD_SNAPSHOT + 24]
    call read_exact
    test eax, eax
    jnz fatal
    mov edi, 4
    lea rsi, [r15 + WD_OBSERVATION]
    mov edx, 1
    call read_exact
    cmp eax, 1
    jne fatal
    mov edi, 4
    mov eax, 3
    syscall
    test rax, rax
    jnz fatal
    mov rax, [r15 + WD_USER_LENGTH]
    add rax, [r15 + WD_SNAPSHOT + 24]
    add rax, 56
    mov [r15 + WD_START_LENGTH], rax
    jmp wd_resume

wd_resume:
    mov rdi, [r15 + WD_INPUT]
    mov rsi, [r15 + WD_LENGTH]
    cmp qword ptr [r15 + WD_READY], 1
    je wd_input_selected
    lea rdi, [r15 + INPUT]
    mov rsi, [r15 + WD_START_LENGTH]
wd_input_selected:
    lea rdx, [r15 + OUTPUT]
    mov ecx, ROOT_OUTPUT_CAP
    mov r8, [r15 + WD_CALLER]
    mov r9d, ROOT_WCAP
    .byte 0xe8
caller_call_displacement:
    .long 0
    mov edx, eax
    cmp rax, rdx
    jne fatal
    cmp qword ptr [r15 + WD_READY], 1
    je wd_return
    test eax, eax
    jnz fatal
    mov qword ptr [r15 + WD_READY], 1
    jmp frame_next
wd_return:
    cmp eax, 0xfffffff0
    je wd_dispatch
    cmp eax, ROOT_OUTPUT_CAP
    ja wd_refusal
    cmp eax, 32
    jb fatal
    mov [r15 + WD_RESULT_LENGTH], rax
    mov rdi, [r15 + WD_CALLER]
    add rdi, 67117056
    lea rsi, [r15 + OUTPUT]
    mov rcx, rax
    rep movsb
    lea r13, [r15 + INPUT]
    movabs rax, 0x3130305157535248
    mov [r13], rax
    mov qword ptr [r13 + 8], 2
    mov qword ptr [r13 + 16], 0
    mov qword ptr [r13 + 24], 0
    mov qword ptr [r15 + 896], 32
    mov qword ptr [r15 + 904], 8388640
    mov qword ptr [r15 + 912], 2
    jmp session_resume
wd_refusal:
    cmp eax, 0xffffffff
    je wd_refusal_valid
    cmp eax, 0xfffffffe
    je wd_refusal_valid
    cmp eax, 0xffffffd0
    jne fatal
wd_refusal_valid:
    mov [r15 + 32], rax
    mov edi, 1
    lea rsi, [r15 + 32]
    mov edx, 8
    call write_exact
    test eax, eax
    jnz fatal
    jmp frame_next

wd_publish:
    mov [r15 + 32], rax
    add rax, [r15 + WD_RESULT_LENGTH]
    add rax, 32
    mov [r15 + WD_OBSERVATION], rax
    movabs rax, 0x3130424f44574d48 /* HMWDOB01 */
    mov [r15 + WD_OBSERVATION + 8], rax
    mov rax, [r15 + WD_RESULT_LENGTH]
    mov [r15 + WD_OBSERVATION + 16], rax
    mov rax, [r15 + SESSION_WORK + 40]
    mov [r15 + WD_OBSERVATION + 24], rax
    mov rax, [r15 + 32]
    mov [r15 + WD_OBSERVATION + 32], rax
    mov edi, 1
    lea rsi, [r15 + WD_OBSERVATION]
    mov edx, 40
    call write_exact
    test eax, eax
    jnz fatal
    mov edi, 1
    mov rsi, [r15 + WD_CALLER]
    add rsi, 67117056
    mov rdx, [r15 + WD_RESULT_LENGTH]
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

wd_dispatch:
    mov r14, [r15 + WD_CALLER]
    lea rdx, [r14 + 256]
    movabs rax, 0x3130414344574d48 /* HMWDCA01 */
    cmp [rdx], rax
    jne fatal
    mov rax, [r15 + WD_SEQUENCE]
    inc rax
    jz fatal
    cmp [rdx + 8], rax
    jne fatal
    cmp [r14 + 16], rax
    jne fatal
    mov [r15 + WD_SEQUENCE], rax
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
    cmp rax, 67108864
    ja fatal
    mov [r15 + WD_CHILD_LENGTH], rax
    mov rax, [rdx + 56]
    cmp rax, ROOT_OUTPUT_CAP
    ja fatal
    mov [r15 + WD_CHILD_CAP], rax
    mov rax, [rdx + 16]
    mov [r15 + WD_CHILD], rax
    cmp rax, 1
    je wd_params_resume
    cmp rax, 2
    je wd_context
    cmp rax, 3
    je wd_session
    cmp rax, 4
    je wd_config
    cmp rax, 5
    je wd_path
    cmp rax, 6
    je wd_policy
    cmp rax, 7
    je wd_raw
    cmp rax, 8
    je wd_directory
    jmp fatal

wd_params_resume:
    mov r13, [r15 + WD_CALLER]
    lea rdi, [r13 + 4096]
    mov rsi, [r15 + WD_CHILD_LENGTH]
    lea rdx, [r13 + 67117056]
    mov ecx, ROOT_OUTPUT_CAP
    mov r8, [r15 + WD_PARAMS]
    mov r9d, ROOT_WCAP
    .byte 0xe8
params_call_displacement:
    .long 0
    cmp eax, 0xfffffff0
    jne wd_child_complete
    mov r14, [r15 + WD_PARAMS]
    lea rdx, [r14 + 256]
    movabs rax, 0x3130415044574d48 /* HMWDPA01 */
    cmp [rdx], rax
    jne fatal
    mov rax, [r15 + WD_PARAMS_SEQUENCE]
    inc rax
    jz fatal
    cmp [rdx + 8], rax
    jne fatal
    cmp [r14 + 16], rax
    jne fatal
    mov [r15 + WD_PARAMS_SEQUENCE], rax
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
    mov rsi, [rdx + 40]
    cmp rsi, 24
    jb fatal
    cmp rsi, 8388632
    ja fatal
    lea rdi, [r14 + 4096]
    movabs rax, 0x31304c41564a5348 /* HSJVAL01 */
    cmp [rdi], rax
    jne fatal
    cmp qword ptr [rdi + 8], 1
    jne fatal
    mov rax, [rdi + 16]
    add rax, 24
    cmp rax, rsi
    jne fatal
    lea rdx, [r14 + 67117056]
    mov ecx, 67108864
    lea r8, [r15 + JSON_WORK]
    mov r9d, ROOT_WCAP
    mov qword ptr [r15 + 80], 13
    jmp shared_value_call
wd_params_value_completed:
    cmp eax, 67108864
    jbe wd_params_value_valid
    cmp eax, 0xffffffff
    je wd_params_value_valid
    cmp eax, 0xfffffffe
    jne fatal
wd_params_value_valid:
    mov rdx, [r15 + WD_PARAMS]
    mov [rdx + 256 + 72], rax
    mov rax, [r15 + WD_PARAMS_SEQUENCE]
    mov [rdx + 256 + 64], rax
    jmp wd_params_resume

wd_context:
    cmp qword ptr [r15 + WD_CHILD_CAP], 32
    jne fatal
    mov rcx, [r15 + WD_CHILD_LENGTH]
    cmp rcx, 16777256
    ja fatal
    mov [r15 + 888], rcx
    lea rsi, [r14 + 4096]
    lea rdi, [r15 + POLICY_INPUT]
    rep movsb
    jmp context_resume
wd_context_completed:
    lea rsi, [r15 + OUTPUT]
    jmp wd_child_copy

wd_session:
    mov rcx, [r15 + WD_CHILD_LENGTH]
    cmp rcx, 8388640
    ja fatal
    mov [r15 + 896], rcx
    mov rax, [r15 + WD_CHILD_CAP]
    mov [r15 + 904], rax
    lea rsi, [r14 + 4096]
    lea rdi, [r15 + INPUT]
    rep movsb
    mov qword ptr [r15 + 912], 3
    jmp session_resume
wd_session_completed:
    lea rsi, [r15 + OUTPUT]
    jmp wd_child_copy

wd_config:
    cmp qword ptr [r15 + WD_CHILD_CAP], ROOT_OUTPUT_CAP
    jne fatal
    mov rcx, [r15 + WD_CHILD_LENGTH]
    cmp rcx, ROOT_INPUT_CAP
    ja fatal
    mov [r15 + 24], rcx
    lea rsi, [r14 + 4096]
    lea rdi, [r15 + INPUT]
    rep movsb
    mov qword ptr [r15 + 800], 2
    lea rax, [r15 + ROOT_WORK + FOOTER]
    mov qword ptr [rax + 120], 1
    jmp owner_resume
wd_config_completed:
    mov qword ptr [r15 + 800], 0
    lea rsi, [r15 + OUTPUT]
    jmp wd_child_copy

wd_path:
    cmp qword ptr [r15 + WD_CHILD_CAP], 33554432
    jne fatal
    lea rdi, [r14 + 4096]
    mov rsi, [r15 + WD_CHILD_LENGTH]
    lea rdx, [r14 + 67117056]
    mov ecx, 33554432
    mov r8, [r15 + WD_PATH]
    mov r9d, ROOT_WCAP
    .byte 0xe8
path_call_displacement:
    .long 0
    jmp wd_child_complete

wd_policy:
    cmp qword ptr [r15 + WD_CHILD_CAP], ROOT_OUTPUT_CAP
    jne fatal
    mov rcx, [r15 + WD_CHILD_LENGTH]
    mov [r15 + 896], rcx
    mov qword ptr [r15 + 904], ROOT_OUTPUT_CAP
    lea rsi, [r14 + 4096]
    lea rdi, [r15 + CONTEXT_WORK + 4096]
    rep movsb
    mov qword ptr [r15 + 920], 0
    jmp policy_resume
wd_directory:
    cmp qword ptr [r15 + WD_CHILD_CAP], ROOT_OUTPUT_CAP
    jne fatal
    mov rcx, [r15 + WD_CHILD_LENGTH]
    mov [r15 + 896], rcx
    mov qword ptr [r15 + 904], ROOT_OUTPUT_CAP
    lea rsi, [r14 + 4096]
    lea rdi, [r15 + CONTEXT_WORK + 4096]
    rep movsb
    mov qword ptr [r15 + 920], 1
    jmp canonical_resume
wd_policy_completed:
    lea rsi, [r15 + CONTEXT_WORK + 67117056]
    jmp wd_child_copy

wd_raw:
    cmp qword ptr [r15 + WD_CHILD_CAP], ROOT_OUTPUT_CAP
    jne fatal
    lea rdi, [r14 + 4096]
    mov rsi, [r15 + WD_CHILD_LENGTH]
    lea rdx, [r14 + 67117056]
    mov ecx, ROOT_OUTPUT_CAP
    mov r8, [r15 + WD_RAW]
    call wd_raw_run
    jmp wd_child_complete

wd_child_copy:
    cmp eax, 0xffffffff
    je wd_child_complete
    cmp eax, 0xfffffffe
    je wd_child_complete
    cmp rax, [r15 + WD_CHILD_CAP]
    ja fatal
    mov rdi, [r15 + WD_CALLER]
    add rdi, 67117056
    mov rcx, rax
    rep movsb
wd_child_complete:
    mov edx, eax
    cmp rax, rdx
    jne fatal
    cmp rax, [r15 + WD_CHILD_CAP]
    jbe wd_child_valid
    cmp eax, 0xffffffff
    je wd_child_valid
    cmp eax, 0xfffffffe
    jne fatal
wd_child_valid:
    mov rdx, [r15 + WD_CALLER]
    mov [rdx + 256 + 72], rax
    mov rax, [r15 + WD_SEQUENCE]
    mov [rdx + 256 + 64], rax
    jmp wd_resume

wd_user_name:
    .asciz "USER"


wd_raw_run:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp, 520
    mov r15, r8
    cmp qword ptr [r15 + 72], -1
    jne wd_raw_contract_fail
    cmp qword ptr [r15 + 80], -1
    jne wd_raw_contract_fail
    mov [r15], rdi
    mov [r15 + 48], rsi
    mov [r15 + 32], rdx
    mov [r15 + 40], rcx
    cmp qword ptr [r15 + 16], 0
    jne wd_raw_workspace_ready
    mov edi, 1056768
    call wd_raw_allocate_guarded
    mov [r15 + 16], rax
    mov qword ptr [r15 + 24], 1056768
wd_raw_workspace_ready:
    mov rdi, [r15 + 16]
    xor eax, eax
    mov ecx, 128
    rep stosq
    mov rbx, [r15 + 16]
    mov rax, [r15 + 64]
    mov [rbx + 176], rax
    mov qword ptr [r15 + 88], 0
    jmp wd_raw_invoke
wd_raw_invoke:
    mov rdi, qword ptr [r15]
    mov rsi, qword ptr [r15 + 48]
    mov rdx, qword ptr [r15 + 32]
    mov rcx, qword ptr [r15 + 40]
    mov r8, qword ptr [r15 + 16]
    mov r9, qword ptr [r15 + 24]
    .byte 0xe8
raw_canonical_call_displacement:
    .long 0
    mov edx, eax
    cmp rax, rdx
    jne wd_raw_contract_fail
    mov rbx, qword ptr [r15 + 16]
    cmp eax, 0xffffffef
    je wd_raw_grow_workspace
    cmp eax, 0xffffffee
    je wd_raw_grow_output
    cmp eax, 0xfffffff0
    je wd_raw_admit_effect
    cmp eax, 0xffffffff
    je wd_raw_refusal
    cmp eax, 0xfffffffe
    je wd_raw_refusal
    cmp eax, 0xfffffff9
    je wd_raw_contract_fail
    cmp eax, 32
    jb wd_raw_contract_fail
    cmp rax, qword ptr [r15 + 40]
    ja wd_raw_contract_fail
    cmp qword ptr [rbx], 100
    jne wd_raw_contract_fail
    mov rdx, qword ptr [r15 + 32]
    mov rcx, 0x3130524c4e435248
    cmp qword ptr [rdx], rcx
    jne wd_raw_contract_fail
    lea rcx, [rax - 32]
    cmp qword ptr [rdx + 16], rcx
    jne wd_raw_contract_fail
    cmp qword ptr [rdx + 8], 0
    je wd_raw_result_success
    cmp qword ptr [rdx + 8], 1
    jne wd_raw_contract_fail
    mov rcx, qword ptr [rdx + 24]
    test rcx, rcx
    jz wd_raw_contract_fail
    cmp rcx, 65536
    je wd_raw_result_status_valid
    cmp rcx, 4095
    ja wd_raw_contract_fail
    jmp wd_raw_result_status_valid
wd_raw_result_success:
    cmp qword ptr [rdx + 24], 0
    jne wd_raw_contract_fail
wd_raw_result_status_valid:
    cmp qword ptr [r15 + 72], -1
    jne wd_raw_contract_fail
    cmp qword ptr [r15 + 80], -1
    jne wd_raw_contract_fail
    jmp wd_raw_raw_return
wd_raw_refusal:
    mov [rsp + 256], rax
    call wd_raw_cleanup
    mov rax, [rsp + 256]
    jmp wd_raw_raw_return

wd_raw_grow_workspace:
    mov rdi, qword ptr [rbx + 40]
    cmp rdi, qword ptr [rbx + 32]
    jbe wd_raw_contract_fail
    mov rax, 0x1ffffffffffbfeff
    cmp rdi, rax
    ja wd_raw_memory_fail
    shl rdi, 2
    add rdi, 1049600
    jc wd_raw_memory_fail
    call wd_raw_round_capacity
    mov r12, rax
    cmp r12, qword ptr [r15 + 24]
    jbe wd_raw_invoke
    mov rdi, r12
    call wd_raw_allocate_guarded
    mov r13, rax
    mov rdi, rax
    mov rsi, qword ptr [r15 + 16]
    mov rcx, qword ptr [r15 + 24]
    rep movsb
    mov rdi, qword ptr [r15 + 16]
    mov rsi, qword ptr [r15 + 24]
    add rsi, 4096
    mov qword ptr [r15 + 16], r13
    mov qword ptr [r15 + 24], r12
    mov eax, 11
    syscall
    test rax, rax
    jnz wd_raw_io_fail
    jmp wd_raw_invoke
wd_raw_grow_output:
    mov eax, 0xfffffffe
    jmp wd_raw_refusal

wd_raw_admit_effect:
    mov rax, qword ptr [r15 + 48]
    cmp qword ptr [rbx + 8], rax
    jne wd_raw_contract_fail
    mov rax, qword ptr [r15 + 40]
    cmp qword ptr [rbx + 16], rax
    jne wd_raw_contract_fail
    mov rax, qword ptr [r15 + 24]
    cmp qword ptr [rbx + 24], rax
    jne wd_raw_contract_fail
    mov rax, qword ptr [rbx + 40]
    or rax, qword ptr [rbx + 48]
    jnz wd_raw_contract_fail
    mov rax, qword ptr [rbx + 32]
    cmp rax, 1024
    jb wd_raw_contract_fail
    lea rcx, [rax - 1]
    test rcx, rax
    jnz wd_raw_contract_fail
    cmp qword ptr [rbx + 96], rax
    jae wd_raw_contract_fail
    mov rcx, 0x1ffffffffffbfeff
    cmp rax, rcx
    ja wd_raw_contract_fail
    shl rax, 2
    add rax, 1049600
    jc wd_raw_contract_fail
    cmp rax, qword ptr [r15 + 24]
    ja wd_raw_contract_fail
    mov rax, 0x584659454b4c4648
    cmp qword ptr [rbx + 512], rax
    jne wd_raw_contract_fail
    inc qword ptr [r15 + 88]
    jz wd_raw_contract_fail
    mov rax, qword ptr [r15 + 88]
    cmp qword ptr [rbx + 520], rax
    jne wd_raw_contract_fail
    cmp qword ptr [rbx + 56], rax
    jne wd_raw_contract_fail
    mov rax, qword ptr [rbx + 568]
    or rax, qword ptr [rbx + 576]
    or rax, qword ptr [rbx + 584]
    or rax, qword ptr [rbx + 592]
    or rax, qword ptr [rbx + 600]
    or rax, qword ptr [rbx + 608]
    or rax, qword ptr [rbx + 616]
    or rax, qword ptr [rbx + 624]
    or rax, qword ptr [rbx + 632]
    jnz wd_raw_contract_fail
    mov r14, qword ptr [rbx + 528]
    cmp r14, 1
    je wd_raw_get_current
    cmp r14, 2
    je wd_raw_read_link
    cmp r14, 3
    je wd_raw_access_path
    cmp r14, 4
    je wd_raw_access_path
    cmp r14, 5
    je wd_raw_lstat_path
    cmp r14, 6
    je wd_raw_access_path
    cmp r14, 7
    je wd_raw_open_parent
    cmp r14, 8
    je wd_raw_stat_descriptor
    cmp r14, 9
    je wd_raw_close_descriptor
    cmp r14, 10
    je wd_raw_get_flags
    cmp r14, 11
    je wd_raw_set_cloexec
    cmp r14, 12
    je wd_raw_directory_entries
    cmp r14, 13
    je wd_raw_rewind_directory
    jmp wd_raw_contract_fail

wd_raw_get_current:
    cmp qword ptr [rbx], 10
    jne wd_raw_contract_fail
    call wd_raw_resolved_argument
    mov rdx, qword ptr [rbx + 552]
    or rdx, qword ptr [rbx + 560]
    jnz wd_raw_contract_fail
    mov rsi, qword ptr [rbx + 544]
    cmp rsi, qword ptr [rbx + 152]
    jne wd_raw_contract_fail
    cmp rsi, 1024
    jb wd_raw_contract_fail
    cmp rsi, qword ptr [rbx + 32]
    ja wd_raw_contract_fail
    mov eax, 79
    syscall
    jmp wd_raw_value_completion

wd_raw_read_link:
    cmp qword ptr [rbx], 3
    jne wd_raw_contract_fail
    call wd_raw_resolved_argument
    mov rcx, qword ptr [rbx + 544]
    cmp rcx, qword ptr [rbx + 96]
    jne wd_raw_contract_fail
    call wd_raw_cstring
    mov rax, qword ptr [rbx + 32]
    lea rax, [rax + rax + 1024]
    cmp qword ptr [rbx + 552], rax
    jne wd_raw_contract_fail
    lea rsi, [rbx + rax]
    mov rdx, qword ptr [rbx + 144]
    cmp rdx, 1024
    jb wd_raw_contract_fail
    dec rdx
    cmp rdx, qword ptr [rbx + 560]
    jne wd_raw_contract_fail
    cmp rdx, qword ptr [rbx + 32]
    jae wd_raw_contract_fail
    mov eax, 89
    syscall
    jmp wd_raw_value_completion

wd_raw_access_path:
    cmp qword ptr [rbx], 4
    jne wd_raw_contract_fail
    call wd_raw_resolved_argument
    mov rcx, qword ptr [rbx + 96]
    inc rcx
    cmp rcx, qword ptr [rbx + 32]
    jae wd_raw_contract_fail
    cmp rcx, qword ptr [rbx + 544]
    jne wd_raw_contract_fail
    call wd_raw_cstring
    mov rax, qword ptr [rbx + 552]
    or rax, qword ptr [rbx + 560]
    jnz wd_raw_contract_fail
    mov rsi, rdi
    mov edi, -100
    xor edx, edx
    mov r10d, 512
    mov eax, 439
    cmp r14, 3
    je wd_raw_access_go
    cmp r14, 4
    jne wd_raw_stat_access
    cmp qword ptr [r15 + 64], 0
    jne wd_raw_contract_fail
    mov eax, 269
wd_raw_access_go:
    syscall
    jmp wd_raw_zero_completion
wd_raw_stat_access:
    cmp qword ptr [r15 + 64], 1
    jne wd_raw_contract_fail
    xor r10d, r10d
    jmp wd_raw_stat_at

wd_raw_lstat_path:
    mov rax, qword ptr [rbx]
    cmp rax, 12
    je wd_raw_lstat_fixed
    cmp rax, 13
    je wd_raw_lstat_fixed
    cmp rax, 24
    jne wd_raw_contract_fail
    mov rax, qword ptr [rbx + 32]
    lea rax, [rax * 4 + 1024]
    add rax, qword ptr [rbx + 368]
    jc wd_raw_contract_fail
    cmp rax, qword ptr [rbx + 536]
    jne wd_raw_contract_fail
    mov rcx, qword ptr [rbx + 376]
    cmp rcx, qword ptr [rbx + 544]
    jne wd_raw_contract_fail
    mov rdx, qword ptr [rbx + 552]
    cmp rdx, qword ptr [rbx + 160]
    jne wd_raw_contract_fail
    jmp wd_raw_lstat_arguments
wd_raw_lstat_fixed:
    mov rax, qword ptr [rbx + 32]
    lea rax, [rax + rax + 1024]
    cmp rax, qword ptr [rbx + 536]
    jne wd_raw_contract_fail
    mov ecx, 1
    cmp qword ptr [rbx + 544], 1
    jne wd_raw_contract_fail
    cmp qword ptr [rbx + 552], 0
    jne wd_raw_contract_fail
    xor edx, edx
    cmp qword ptr [rbx], 12
    jne wd_raw_lstat_root
    cmp byte ptr [rbx + rax], 46
    jne wd_raw_contract_fail
    jmp wd_raw_lstat_arguments
wd_raw_lstat_root:
    cmp byte ptr [rbx + rax], 47
    jne wd_raw_contract_fail
wd_raw_lstat_arguments:
    cmp qword ptr [rbx + 560], 0
    jne wd_raw_contract_fail
    lea rdi, [rbx + rax]
    call wd_raw_cstring
    mov rsi, rdi
    mov edi, -100
    test rdx, rdx
    jz wd_raw_lstat_cwd
    call wd_raw_descriptor
wd_raw_lstat_cwd:
    mov r10d, 256
wd_raw_stat_at:
    mov r12, rsi
    mov r13, rdi
    mov rdi, rsp
    xor eax, eax
    mov ecx, 32
    rep stosq
    mov rdi, r13
    mov rsi, r12
    mov rdx, rsp
    mov eax, 262
    syscall
    jmp wd_raw_stat_completion

wd_raw_open_parent:
    cmp qword ptr [rbx], 15
    jne wd_raw_contract_fail
    mov rax, qword ptr [rbx + 552]
    or rax, qword ptr [rbx + 560]
    jnz wd_raw_contract_fail
    mov r12, qword ptr [rbx + 536]
    cmp r12, 1
    jb wd_raw_contract_fail
    cmp r12, 2
    ja wd_raw_contract_fail
    cmp qword ptr [r15 + r12 * 8 + 64], -1
    jne wd_raw_contract_fail
    mov rdx, qword ptr [rbx + 544]
    cmp rdx, qword ptr [rbx + 160]
    jne wd_raw_contract_fail
    cmp rdx, r12
    je wd_raw_contract_fail
    mov edi, -100
    test rdx, rdx
    jz wd_raw_open_parent_cwd
    call wd_raw_descriptor
wd_raw_open_parent_cwd:
    lea rsi, [rip + wd_raw_parent_name]
    xor edx, edx
    xor r10d, r10d
    mov eax, 257
    syscall
    test rax, rax
    js wd_raw_error_completion
    cmp rax, 0x7fffffff
    ja wd_raw_contract_fail
    mov qword ptr [r15 + r12 * 8 + 64], rax
    mov rax, r12
    jmp wd_raw_value_completion

wd_raw_stat_descriptor:
    mov rax, qword ptr [rbx]
    cmp rax, 16
    je wd_raw_stat_descriptor_phase
    cmp rax, 18
    jne wd_raw_contract_fail
wd_raw_stat_descriptor_phase:
    call wd_raw_zero_trailing_args
    mov rdx, qword ptr [rbx + 536]
    cmp rdx, qword ptr [rbx + 168]
    jne wd_raw_contract_fail
    call wd_raw_descriptor
    mov r13, rdi
    mov rdi, rsp
    xor eax, eax
    mov ecx, 32
    rep stosq
    mov rdi, r13
    mov rsi, rsp
    mov eax, 5
    syscall
wd_raw_stat_completion:
    test rax, rax
    js wd_raw_error_completion
    test rax, rax
    jnz wd_raw_contract_fail
    mov rax, qword ptr [rsp]
    mov qword ptr [rbx + 584], rax
    mov rax, qword ptr [rsp + 8]
    mov qword ptr [rbx + 592], rax
    mov eax, dword ptr [rsp + 24]
    mov qword ptr [rbx + 600], rax
    mov rax, qword ptr [rsp + 56]
    mov qword ptr [rbx + 616], rax
    jmp wd_raw_acknowledge

wd_raw_close_descriptor:
    mov rax, qword ptr [rbx]
    cmp rax, 17
    je wd_raw_close_phase
    cmp rax, 27
    je wd_raw_close_phase
    cmp rax, 29
    jne wd_raw_contract_fail
wd_raw_close_phase:
    call wd_raw_zero_trailing_args
    mov rdx, qword ptr [rbx + 536]
    call wd_raw_descriptor
    mov qword ptr [r15 + rdx * 8 + 64], -1
    mov eax, 3
    syscall
    jmp wd_raw_zero_completion

wd_raw_get_flags:
    cmp qword ptr [rbx], 19
    jne wd_raw_contract_fail
    call wd_raw_zero_trailing_args
    mov rdx, qword ptr [rbx + 536]
    cmp rdx, qword ptr [rbx + 168]
    jne wd_raw_contract_fail
    call wd_raw_descriptor
    mov esi, 3
    xor edx, edx
    mov eax, 72
    syscall
    jmp wd_raw_value_completion
wd_raw_set_cloexec:
    cmp qword ptr [rbx], 20
    jne wd_raw_contract_fail
    call wd_raw_zero_trailing_args
    mov rdx, qword ptr [rbx + 536]
    cmp rdx, qword ptr [rbx + 168]
    jne wd_raw_contract_fail
    call wd_raw_descriptor
    mov esi, 2
    mov edx, 1
    mov eax, 72
    syscall
    jmp wd_raw_zero_completion

wd_raw_directory_entries:
    cmp qword ptr [rbx], 22
    jne wd_raw_contract_fail
    cmp qword ptr [rbx + 560], 0
    jne wd_raw_contract_fail
    mov rax, qword ptr [rbx + 32]
    lea rax, [rax * 4 + 1024]
    cmp rax, qword ptr [rbx + 544]
    jne wd_raw_contract_fail
    mov r12, qword ptr [rbx + 552]
    cmp r12, 32768
    jb wd_raw_contract_fail
    cmp r12, 1048576
    ja wd_raw_contract_fail
    cmp r12, qword ptr [rbx + 336]
    jne wd_raw_contract_fail
    lea rsi, [rbx + rax]
    mov rdx, qword ptr [rbx + 536]
    cmp rdx, qword ptr [rbx + 160]
    jne wd_raw_contract_fail
    call wd_raw_descriptor
    mov rdx, r12
    mov eax, 217
    syscall
    jmp wd_raw_value_completion
wd_raw_rewind_directory:
    cmp qword ptr [rbx], 23
    jne wd_raw_contract_fail
    call wd_raw_zero_trailing_args
    mov rdx, qword ptr [rbx + 536]
    cmp rdx, qword ptr [rbx + 160]
    jne wd_raw_contract_fail
    call wd_raw_descriptor
    xor esi, esi
    xor edx, edx
    mov eax, 8
    syscall
    jmp wd_raw_value_completion

wd_raw_resolved_argument:
    mov rax, qword ptr [rbx + 32]
    add rax, 1024
    cmp qword ptr [rbx + 536], rax
    jne wd_raw_contract_fail
    lea rdi, [rbx + rax]
    ret
wd_raw_zero_trailing_args:
    mov rax, qword ptr [rbx + 544]
    or rax, qword ptr [rbx + 552]
    or rax, qword ptr [rbx + 560]
    jnz wd_raw_contract_fail
    ret
# logical slot in rdx -> real wd_raw_descriptor in rdi, preserving other arguments.
wd_raw_descriptor:
    cmp rdx, 1
    jb wd_raw_contract_fail
    cmp rdx, 2
    ja wd_raw_contract_fail
    mov rdi, qword ptr [r15 + rdx * 8 + 64]
    test rdi, rdi
    js wd_raw_contract_fail
    ret
# Exact span containment and unique final NUL.  rdx is preserved for dirfd.
wd_raw_cstring:
    mov rax, rdi
    sub rax, rbx
    jc wd_raw_contract_fail
    cmp rax, qword ptr [r15 + 24]
    jae wd_raw_contract_fail
    mov r11, qword ptr [r15 + 24]
    sub r11, rax
    cmp rcx, r11
    jae wd_raw_contract_fail
    cmp byte ptr [rdi + rcx], 0
    jne wd_raw_contract_fail
    xor eax, eax
wd_raw_cstring_loop:
    cmp rax, rcx
    je wd_raw_cstring_done
    cmp byte ptr [rdi + rax], 0
    je wd_raw_contract_fail
    inc rax
    jmp wd_raw_cstring_loop
wd_raw_cstring_done:
    ret
wd_raw_value_completion:
    test rax, rax
    js wd_raw_error_completion
    mov qword ptr [rbx + 568], rax
    jmp wd_raw_acknowledge
wd_raw_zero_completion:
    test rax, rax
    js wd_raw_error_completion
    test rax, rax
    jnz wd_raw_contract_fail
    jmp wd_raw_acknowledge
wd_raw_error_completion:
    neg rax
    cmp rax, 4095
    ja wd_raw_contract_fail
    mov qword ptr [rbx + 576], rax
wd_raw_acknowledge:
    mov qword ptr [rbx + 608], 1
    jmp wd_raw_invoke

wd_raw_round_capacity:
    mov rax, rdi
    add rax, 4095
    jc wd_raw_memory_fail
    and rax, -4096
    test rax, rax
    jz wd_raw_memory_fail
    mov rdx, 0x7ffffffffffff000
    cmp rax, rdx
    jae wd_raw_memory_fail
    ret
wd_raw_allocate_guarded:
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
    jae wd_raw_memory_fail
    push rax
    lea rdi, [rax + rbx]
    mov esi, 4096
    xor edx, edx
    mov eax, 10
    syscall
    test rax, rax
    jnz wd_raw_memory_fail
    pop rax
    pop rbx
    ret
wd_raw_cleanup:
    mov rdi, qword ptr [r15 + 72]
    mov qword ptr [r15 + 72], -1
    test rdi, rdi
    js wd_raw_cleanup_second
    mov eax, 3
    syscall
wd_raw_cleanup_second:
    mov rdi, qword ptr [r15 + 80]
    mov qword ptr [r15 + 80], -1
    test rdi, rdi
    js wd_raw_cleanup_done
    mov eax, 3
    syscall
wd_raw_cleanup_done:
    ret

wd_raw_raw_return:
    add rsp, 520
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret
wd_raw_contract_fail:
    call wd_raw_cleanup
    mov edi, 70
    mov eax, 231
    syscall
    ud2
wd_raw_memory_fail:
    call wd_raw_cleanup
    mov edi, 71
    mov eax, 231
    syscall
    ud2
wd_raw_io_fail:
    call wd_raw_cleanup
    mov edi, 74
    mov eax, 231
    syscall
    ud2
wd_raw_parent_name:
    .asciz ".."

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

