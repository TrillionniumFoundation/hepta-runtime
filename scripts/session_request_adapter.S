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
.equ MAP_BYTES, 2382368832
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
    mov [r15 + 888], rax
    xor edi, edi
    lea rsi, [r15 + POLICY_INPUT]
    mov rdx, rax
    call read_exact
    test eax, eax
    jnz fatal
    jmp context_resume
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
    lea r14, [r15 + VALIDATION_WORK]
    mov rdi, r13
    mov rsi, [r15 + 96]
    mov rdx, r12
    mov rcx, [r15 + 104]
    mov r8, r14
    mov r9d, ROOT_WCAP
    .byte 0xe8
validation_call_displacement:
    .long 0
    jmp native_return
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
    jmp frame_next
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
