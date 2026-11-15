.intel_syntax noprefix
.section .text
.global _start
.global namespace_call_displacement
.equ INPUT, 4096
.equ OUTPUT, 8192
.equ FDS, 16384
.equ OWNER, 1048576
.equ GUARD, 9437184
.equ MAP_SIZE, 9441280
.equ FDS_COUNT, 33794
.equ SET_SLOT, 4880
.equ SET_TABLE, 2097152
.equ SET_STRIDE, 16640
.equ PHASE, 4104
.equ SEQUENCE, 4112
.equ OPERATION, 4136
.equ DIRECTORY, 4144
.equ WATCHER, 4152
.equ SCAN_LIVE, 4288
.equ SCAN_CAPACITY, 4304
.equ CANDIDATE, 4328
.equ ACTION, 4352
.equ STAT, 6144
.equ STATX, 6400
.equ NAME, 7040
.equ EVENTS, 65536
.equ DIRENTS, 131072

_start:
    cld
    cmp qword ptr [rsp], 2
    jne usage
    mov rbx, [rsp + 16]
    xor edi, edi
    mov esi, MAP_SIZE
    mov edx, 3
    mov r10d, 34
    mov r8, -1
    xor r9d, r9d
    mov eax, 9
    syscall
    cmp rax, -4095
    jae bare_fail
    mov r15, rax
    lea rdi, [r15 + FDS]
    mov ecx, FDS_COUNT
    mov rax, -1
    rep stosq
    mov qword ptr [r15 + 256], 1
    mov edi, 13
    lea rsi, [r15 + 256]
    xor edx, edx
    mov r10d, 8
    mov eax, 13
    syscall
    test rax, rax
    jnz io_fail
    lea rdi, [r15 + GUARD]
    mov esi, 4096
    xor edx, edx
    mov eax, 10
    syscall
    test rax, rax
    jnz io_fail
    mov edi, -100
    mov rsi, rbx
    mov edx, 0x90000
    xor r10d, r10d
    mov eax, 257
    syscall
    test rax, rax
    js io_fail
    mov [r15 + FDS], rax
    lea r12, [r15 + OWNER]
next_frame:
    lea rdi, [r15 + INPUT]
    mov esi, 4096
    mov edx, 3
    mov eax, 10
    syscall
    test rax, rax
    jnz io_fail
    lea rsi, [r15 + 24]
    mov edx, 8
    mov r8d, 1
    call read_exact
    test eax, eax
    jz success
    mov rdx, [r15 + 24]
    cmp rdx, 4096
    ja contract_fail
    lea rsi, [r15 + INPUT]
    xor r8d, r8d
    call read_exact
    lea rdi, [r15 + INPUT]
    mov esi, 4096
    mov edx, 1
    mov eax, 10
    syscall
    test rax, rax
    jnz io_fail
resume_namespace:
    lea rdi, [r15 + INPUT]
    mov rsi, [r15 + 24]
    lea rdx, [r15 + OUTPUT]
    mov ecx, 4096
    mov r8, r12
    mov r9d, 8388608
    .byte 0xe8
namespace_call_displacement:
    .long 0
    mov ecx, eax
    cmp rax, rcx
    jne contract_fail
    cmp eax, 0xfffffff0
    jne owner_result
    lea r14, [r12 + ACTION]
    mov rax, 0x3130304156534e48
    cmp [r14], rax
    jne contract_fail
    mov rax, [r15 + 16]
    inc rax
    jz contract_fail
    cmp [r14 + 8], rax
    jne contract_fail
    cmp [r12 + SEQUENCE], rax
    jne contract_fail
    mov [r15 + 16], rax
    mov rax, [r14 + 56]
    or rax, [r14 + 64]
    or rax, [r14 + 72]
    or rax, [r14 + 80]
    or rax, [r14 + 88]
    jnz contract_fail
    mov rax, [r14 + 16]
    cmp rax, 1
    je bind_effect
    cmp rax, 2
    je old_stat_effect
    cmp rax, 3
    je statx_effect
    cmp rax, 4
    je statat_effect
    cmp rax, 5
    je statx_probe_effect
    cmp rax, 6
    je statat_probe_effect
    cmp rax, 7
    je init_effect
    cmp rax, 8
    je events_effect
    cmp rax, 9
    je duplicate_effect
    cmp rax, 10
    je add_watch_effect
    cmp rax, 11
    je remove_watch_effect
    cmp rax, 12
    je close_pin_effect
    cmp rax, 13
    je scan_open_effect
    cmp rax, 14
    je flags_effect
    cmp rax, 15
    je scan_stat_effect
    cmp rax, 16
    je directory_effect
    cmp rax, 17
    je close_scan_effect
    cmp rax, 18
    je close_borrow_effect
    cmp rax, 19
    je retain_borrow_effect
    cmp rax, 20
    je close_set_event_effect
    jmp contract_fail
zero_span:
    mov rax, [r14 + 32]
    or rax, [r14 + 40]
    or rax, [r14 + 48]
    jnz contract_fail
    ret
borrow_index:
    mov rcx, [r14 + 24]
    cmp rcx, 258
    ja contract_fail
    cmp rcx, [r12 + DIRECTORY]
    jne contract_fail
    ret
borrow_live:
    call borrow_index
    mov rdi, [r15 + rcx*8 + FDS]
    test rdi, rdi
    js contract_fail
    ret
set_admit:
    mov rax, [r12 + SET_SLOT]
    cmp rax, 128
    jae contract_fail
    imul rax, SET_STRIDE
    add rax, SET_TABLE
    cmp rax, [r12 + WATCHER]
    jne contract_fail
    mov rax, [r12 + OPERATION]
    cmp rax, 5
    jb contract_fail
    cmp rax, 7
    ja contract_fail
    ret
event_index:
    mov ecx, 259
    cmp qword ptr [r12 + WATCHER], 8192
    je event_normal
    cmp qword ptr [r12 + WATCHER], 24576
    jne event_set
    inc ecx
    cmp qword ptr [r12 + OPERATION], 2
    jne contract_fail
    jmp event_index_ok
event_normal:
    cmp qword ptr [r12 + OPERATION], 1
    jne contract_fail
    jmp event_index_ok
event_set:
    call set_admit
    mov rcx, [r12 + SET_SLOT]
    add rcx, 262
event_index_ok:
    cmp rcx, [r14 + 24]
    jne contract_fail
    ret
event_live:
    call event_index
    mov rdi, [r15 + rcx*8 + FDS]
    test rdi, rdi
    js contract_fail
    ret
pin_index:
    call pin_bounds
    mov rcx, [r14 + 24]
    cmp rcx, rdx
    jb contract_fail
    cmp rcx, r8
    jae contract_fail
    ret
pin_bounds:
    mov edx, 512
    cmp qword ptr [r12 + WATCHER], 8192
    je pin_pool
    cmp qword ptr [r12 + WATCHER], 24576
    jne pin_set
    mov edx, 641
pin_pool:
    lea r8, [rdx + 129]
    ret
pin_set:
    call set_admit
    mov rdx, [r12 + SET_SLOT]
    imul rdx, 258
    add rdx, 770
    lea r8, [rdx + 258]
    ret
scan_live:
    cmp qword ptr [r14 + 24], 261
    jne contract_fail
    mov rdi, [r15 + FDS + 261*8]
    test rdi, rdi
    js contract_fail
    ret
bind_effect:
    cmp qword ptr [r12 + PHASE], 1
    jne contract_fail
    call borrow_index
    cmp qword ptr [r14 + 32], NAME
    jne contract_fail
    cmp qword ptr [r14 + 48], 0
    jne contract_fail
    test rcx, rcx
    jnz bind_name
    cmp qword ptr [r14 + 40], 1
    jne contract_fail
    cmp qword ptr [r12 + NAME], 46
    jne contract_fail
    jmp bind_ready
bind_name:
    cmp qword ptr [r14 + 40], 4
    jne contract_fail
    cmp byte ptr [r12 + NAME], 100
    jne contract_fail
    cmp dword ptr [r12 + NAME + 4], 0
    jne contract_fail
    mov eax, ecx
    xor edx, edx
    mov ebx, 100
    div ebx
    add eax, 48
    cmp al, [r12 + NAME + 1]
    jne contract_fail
    mov eax, edx
    xor edx, edx
    mov ebx, 10
    div ebx
    add eax, 48
    add edx, 48
    cmp al, [r12 + NAME + 2]
    jne contract_fail
    cmp dl, [r12 + NAME + 3]
    jne contract_fail
bind_ready:
    cmp qword ptr [r15 + rcx*8 + FDS], -1
    jne bind_existing
    mov rdi, [r15 + FDS]
    lea rsi, [r12 + NAME]
    mov edx, 0x80000
    xor r10d, r10d
    mov eax, 257
    syscall
    jmp install_descriptor
bind_existing:
    mov [r14 + 72], rcx
    jmp acknowledge
stat_span:
    cmp qword ptr [r14 + 32], STAT
    jne contract_fail
    cmp qword ptr [r14 + 40], 144
    jne contract_fail
    cmp qword ptr [r14 + 48], 0
    jne contract_fail
    lea rsi, [r12 + STAT]
    ret
old_stat_effect:
    cmp qword ptr [r12 + PHASE], 50
    jne contract_fail
    call borrow_live
    call stat_span
    mov eax, 5
    syscall
    jmp zero_effect
statx_effect:
    cmp qword ptr [r12 + PHASE], 51
    jne contract_fail
    call borrow_live
    cmp qword ptr [r14 + 32], STATX
    jne contract_fail
    cmp qword ptr [r14 + 40], 256
    jne contract_fail
    cmp qword ptr [r14 + 48], 0
    jne contract_fail
    mov byte ptr [r15 + 512], 0
    lea rsi, [r15 + 512]
    mov edx, 4096
    mov r10d, 4095
    lea r8, [r12 + STATX]
    mov eax, 332
    syscall
    jmp zero_effect
statat_effect:
    cmp qword ptr [r12 + PHASE], 52
    jne contract_fail
    call borrow_live
    call stat_span
    mov byte ptr [r15 + 512], 0
    lea rsi, [r15 + 512]
    lea rdx, [r12 + STAT]
    mov r10d, 4096
    mov eax, 262
    syscall
    jmp zero_effect
probe_admit:
    cmp qword ptr [r14 + 24], 0
    jne contract_fail
    call zero_span
    xor edi, edi
    xor esi, esi
    xor edx, edx
    ret
statx_probe_effect:
    cmp qword ptr [r12 + PHASE], 53
    jne contract_fail
    call probe_admit
    mov r10d, 4095
    xor r8d, r8d
    mov eax, 332
    syscall
    jmp zero_effect
statat_probe_effect:
    cmp qword ptr [r12 + PHASE], 54
    jne contract_fail
    call probe_admit
    lea rdx, [r12 + STAT]
    xor r10d, r10d
    mov eax, 262
    syscall
    jmp zero_effect
init_effect:
    cmp qword ptr [r12 + PHASE], 10
    jne contract_fail
    call zero_span
    call event_index
    cmp qword ptr [r15 + rcx*8 + FDS], -1
    jne contract_fail
    mov edi, 0x80800
    mov eax, 294
    syscall
    jmp install_descriptor
events_effect:
    cmp qword ptr [r12 + PHASE], 11
    jne contract_fail
    call event_live
    cmp qword ptr [r14 + 32], EVENTS
    jne contract_fail
    cmp qword ptr [r14 + 40], 16384
    jne contract_fail
    cmp qword ptr [r14 + 48], 0
    jne contract_fail
    lea rsi, [r12 + EVENTS]
    mov edx, 16384
    xor eax, eax
    syscall
    jmp value_effect
duplicate_effect:
    cmp qword ptr [r12 + PHASE], 15
    jne contract_fail
    call pin_index
    cmp qword ptr [r15 + rcx*8 + FDS], -1
    jne contract_fail
    mov rax, [r14 + 32]
    or rax, [r14 + 40]
    jnz contract_fail
    mov rax, [r14 + 48]
    cmp rax, [r12 + DIRECTORY]
    jne contract_fail
    cmp rax, 258
    ja contract_fail
    mov rdi, [r15 + rax*8 + FDS]
    test rdi, rdi
    js contract_fail
    mov esi, 1030
    mov edx, 3 /* Rust File::try_clone preserves standard descriptor slots. */
    mov eax, 72
    syscall
    jmp install_descriptor
add_watch_effect:
    cmp qword ptr [r12 + PHASE], 16
    jne contract_fail
    call event_live
    cmp qword ptr [r14 + 32], 0
    jne contract_fail
    mov ebx, 16781248
    cmp qword ptr [r12 + OPERATION], 1
    je watch_flags_ok
    or ebx, 14
watch_flags_ok:
    cmp rbx, [r14 + 40]
    jne contract_fail
    push rdi
    call pin_bounds
    pop rdi
    mov rax, [r14 + 48]
    cmp rax, rdx
    jb contract_fail
    cmp rax, r8
    jae contract_fail
    mov rax, [r15 + rax*8 + FDS]
    test rax, rax
    js contract_fail
    lea r8, [r15 + 640]
    mov byte ptr [r8], 0
    mov r9d, 10
fd_digits:
    xor edx, edx
    div r9
    add dl, 48
    dec r8
    mov [r8], dl
    test rax, rax
    jnz fd_digits
    mov rax, 0x65732f636f72702f
    mov [r15 + 576], rax
    mov dword ptr [r15 + 584], 0x662f666c
    mov word ptr [r15 + 588], 0x2f64
    lea rsi, [r15 + 576]
    lea rdx, [r15 + 590]
copy_digits:
    mov al, [r8]
    mov [rdx], al
    inc r8
    inc rdx
    test al, al
    jnz copy_digits
    mov edx, ebx
    mov eax, 254
    syscall
    jmp value_effect
remove_watch_effect:
    mov rax, [r12 + PHASE]
    cmp rax, 13
    je remove_admit
    cmp rax, 17
    jne contract_fail
remove_admit:
    call event_live
    mov rax, [r14 + 32]
    or rax, [r14 + 40]
    jnz contract_fail
    mov rsi, [r14 + 48]
    cmp rsi, 2147483647
    ja contract_fail
    mov eax, 255
    syscall
    jmp zero_effect
close_pin_effect:
    mov rax, [r12 + PHASE]
    cmp rax, 14
    je close_pin_admit
    cmp rax, 18
    je close_pin_admit
    cmp rax, 19
    je close_pin_admit
    cmp rax, 202
    jne contract_fail
close_pin_admit:
    call zero_span
    call pin_index
    jmp close_slot
scan_open_effect:
    cmp qword ptr [r12 + PHASE], 100
    jne contract_fail
    cmp qword ptr [r14 + 24], 261
    jne contract_fail
    cmp qword ptr [r15 + FDS + 261*8], -1
    jne contract_fail
    cmp qword ptr [r14 + 32], NAME
    jne contract_fail
    cmp qword ptr [r14 + 40], 1
    jne contract_fail
    cmp qword ptr [r12 + NAME], 46
    jne contract_fail
    mov rax, [r14 + 48]
    cmp rax, [r12 + DIRECTORY]
    jne contract_fail
    cmp rax, 258
    ja contract_fail
    mov rdi, [r15 + rax*8 + FDS]
    test rdi, rdi
    js contract_fail
    lea rsi, [r12 + NAME]
    mov edx, 0x90000
    xor r10d, r10d
    mov eax, 257
    syscall
    jmp install_descriptor
flags_effect:
    cmp qword ptr [r12 + PHASE], 101
    jne contract_fail
    call zero_span
    call scan_live
    mov esi, 3
    xor edx, edx
    mov eax, 72
    syscall
    jmp value_effect
scan_stat_effect:
    cmp qword ptr [r12 + PHASE], 102
    jne contract_fail
    call scan_live
    call stat_span
    mov eax, 5
    syscall
    jmp zero_effect
directory_effect:
    cmp qword ptr [r12 + PHASE], 103
    jne contract_fail
    call scan_live
    cmp qword ptr [r14 + 32], DIRENTS
    jne contract_fail
    cmp qword ptr [r14 + 48], 0
    jne contract_fail
    mov rdx, [r14 + 40]
    cmp rdx, 32768
    jb contract_fail
    cmp rdx, 1048576
    ja contract_fail
    cmp rdx, [r12 + SCAN_CAPACITY]
    jne contract_fail
    lea rsi, [r12 + DIRENTS]
    mov eax, 217
    syscall
    jmp value_effect
close_scan_effect:
    mov rax, [r12 + PHASE]
    cmp rax, 104
    je close_scan_admit
    cmp rax, 105
    jne contract_fail
close_scan_admit:
    call zero_span
    call scan_live
    mov ecx, 261
    jmp close_slot
close_borrow_effect:
    cmp qword ptr [r12 + PHASE], 2
    jne contract_fail
    call zero_span
    call borrow_index
    test rcx, rcx
    jz contract_fail
    cmp qword ptr [r15 + rcx*8 + FDS], -1
    je acknowledge
close_slot:
    mov rdi, [r15 + rcx*8 + FDS]
    test rdi, rdi
    js contract_fail
    mov qword ptr [r15 + rcx*8 + FDS], -1
    call raw_descriptor_referenced
    test eax, eax
    jnz acknowledge
    mov eax, 3
    syscall
    jmp zero_effect
raw_descriptor_referenced:
    xor ecx, ecx
raw_reference_next:
    cmp [r15 + rcx*8 + FDS], rdi
    je raw_reference_yes
    inc ecx
    cmp ecx, FDS_COUNT
    jb raw_reference_next
    xor eax, eax
    ret
raw_reference_yes:
    mov eax, 1
    ret
retain_borrow_effect:
    cmp qword ptr [r12 + PHASE], 15
    jne contract_fail
    cmp qword ptr [r12 + OPERATION], 5
    jne contract_fail
    call set_admit
    call pin_index
    cmp qword ptr [r15 + rcx*8 + FDS], -1
    jne contract_fail
    mov rax, [r14 + 32]
    or rax, [r14 + 40]
    jnz contract_fail
    mov rax, [r14 + 48]
    cmp rax, 258
    ja contract_fail
    cmp rax, [r12 + DIRECTORY]
    jne contract_fail
    mov rax, [r15 + rax*8 + FDS]
    test rax, rax
    js contract_fail
    mov [r15 + rcx*8 + FDS], rax
    mov [r14 + 72], rcx
    jmp acknowledge
close_set_event_effect:
    cmp qword ptr [r12 + PHASE], 201
    jne contract_fail
    call zero_span
    call set_admit
    call event_live
    jmp close_slot
install_descriptor:
    test rax, rax
    js effect_error
    cmp rax, 2147483647
    ja contract_fail
    mov rcx, [r14 + 24]
    cmp rcx, FDS_COUNT
    jae contract_fail
    cmp qword ptr [r15 + rcx*8 + FDS], -1
    jne contract_fail
    mov [r15 + rcx*8 + FDS], rax
    mov [r14 + 72], rcx
    jmp acknowledge
zero_effect:
    test rax, rax
    js effect_error
    jnz contract_fail
    jmp acknowledge
value_effect:
    test rax, rax
    js effect_error
    mov [r14 + 72], rax
    jmp acknowledge
effect_error:
    cmp rax, -4095
    jb contract_fail
    neg rax
    mov [r14 + 80], rax
acknowledge:
    mov rax, [r14 + 8]
    mov [r14 + 64], rax
    jmp resume_namespace
owner_result:
    cmp qword ptr [r12 + PHASE], 0
    jne contract_fail
    cmp qword ptr [r12 + SCAN_LIVE], 0
    jne contract_fail
    cmp qword ptr [r12 + CANDIDATE], 0
    jne contract_fail
    cmp qword ptr [r15 + FDS + 261*8], -1
    jne contract_fail
    mov [r15 + 32], eax
    cmp eax, 64
    je result_header
    cmp eax, 0xffffffff
    je result_header
    cmp eax, 0xfffffffe
    jne contract_fail
result_header:
    lea rsi, [r15 + 32]
    mov edx, 4
    call write_exact
    cmp dword ptr [r15 + 32], 64
    jne next_frame
    lea rsi, [r15 + OUTPUT]
    mov edx, 64
    call write_exact
    jmp next_frame
read_exact:
    test rdx, rdx
    jz read_done
read_retry:
    xor edi, edi
    xor eax, eax
    syscall
    cmp rax, -4
    je read_retry
    test rax, rax
    js io_fail
    jz read_eof
    xor r8d, r8d
    add rsi, rax
    sub rdx, rax
    jnz read_retry
read_done:
    mov eax, 1
    ret
read_eof:
    test r8d, r8d
    jz contract_fail
    xor eax, eax
    ret
write_exact:
    test rdx, rdx
    jz write_done
write_retry:
    mov edi, 1
    mov eax, 1
    syscall
    cmp rax, -4
    je write_retry
    test rax, rax
    jle io_fail
    add rsi, rax
    sub rdx, rax
    jnz write_retry
write_done:
    ret
success:
    xor ebp, ebp
    jmp cleanup_exit
contract_fail:
    mov ebp, 2
    jmp cleanup_exit
io_fail:
    mov ebp, 74
cleanup_exit:
    mov ebx, FDS_COUNT - 1
cleanup_loop:
    mov rdi, [r15 + rbx*8 + FDS]
    mov qword ptr [r15 + rbx*8 + FDS], -1
    test rdi, rdi
    js cleanup_next
    call raw_descriptor_referenced
    test eax, eax
    jnz cleanup_next
    mov eax, 3
    syscall
cleanup_next:
    dec ebx
    jns cleanup_loop
    mov rdi, r15
    mov esi, MAP_SIZE
    mov eax, 11
    syscall
    mov edi, ebp
    jmp exit
bare_fail:
    mov edi, 74
    jmp exit
usage:
    mov edi, 64
exit:
    mov eax, 60
    syscall
    ud2
