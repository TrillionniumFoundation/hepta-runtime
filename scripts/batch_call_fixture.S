/* Qualification transport only. The exported engine contains all real calls. */
.intel_syntax noprefix
.section .text
.global _start
_start:
    mov rax, [rsp]
    xor r12d, r12d
    xor r13d, r13d
    cmp rax, 1
    je batch_fixture_args_done
    cmp rax, 2
    jne batch_fixture_usage
    mov rdi, [rsp + 16]
    cmp dword ptr [rdi], 0x73612d2d
    je batch_fixture_async_args
    cmp dword ptr [rdi], 0x79732d2d
    jne batch_fixture_usage
    cmp word ptr [rdi + 4], 0x636e
    jne batch_fixture_usage
    cmp byte ptr [rdi + 6], 0
    jne batch_fixture_usage
    mov r12d, 1
    jmp batch_fixture_args_done
batch_fixture_async_args:
    cmp dword ptr [rdi + 4], 0x00636e79
    jne batch_fixture_usage
    mov r13d, 1
batch_fixture_args_done:
    lea rsi, [rsp + rax * 8 + 16]
batch_fixture_env:
    cmp qword ptr [rsi], 0
    lea rsi, [rsi + 8]
    jne batch_fixture_env
    xor ebp, ebp
batch_fixture_aux:
    mov rax, [rsi]
    test rax, rax
    jz batch_fixture_install
    cmp rax, 23
    jne batch_fixture_aux_next
    cmp qword ptr [rsi + 8], 0
    setne bpl
batch_fixture_aux_next:
    add rsi, 16
    jmp batch_fixture_aux
batch_fixture_install:
    lea rdi, [rip + batch_image_table]
    mov rsi, rbp
    call batch_engine_create
    cmp rax, -4095
    jae batch_fixture_resource
    mov r15, rax
    mov [r15 + 24], r12
    mov [r15 + 640], r13
    mov [r15 + 1080], r15
    mov [r15 + 1088], r15
    sub rsp, 64
batch_fixture_next:
    xor edi, edi
    mov rsi, rsp
    mov edx, 8
    call view_read_all
    test rax, rax
    je batch_fixture_eof
    cmp rax, 1
    jne batch_fixture_io
    mov r12, [rsp]
    mov edx, 224
    call batch_buffer
    test rax, rax
    js batch_fixture_resource
    xor edi, edi
    mov rsi, [r15 + 224]
    mov rdx, r12
    call view_read_all
    cmp rax, 1
    jne batch_fixture_io
    mov rdi, [r15 + 224]
    mov rsi, r12
    cmp r12, 32
    jb batch_fixture_not_control
    mov rax, 0x3230515846434248
    cmp [rdi], rax
    jne batch_fixture_not_control
    call batch_fixture_control
    test rax, rax
    js batch_fixture_contract
    jmp batch_fixture_next
batch_fixture_not_control:
    cmp r12, 16
    jne batch_fixture_call
    mov rax, 0x32304c4553434248
    cmp [rdi], rax
    je batch_fixture_choose
    mov rax, 0x324c544341434248
    cmp [rdi], rax
    jne batch_fixture_call
    cmp qword ptr [r15 + 640], 1
    jne batch_fixture_contract
    cmp qword ptr [rdi + 8], 4
    je batch_fixture_wake
    cmp qword ptr [rdi + 8], 5
    je batch_fixture_retire_wait
    cmp qword ptr [rdi + 8], 2
    je batch_fixture_cancel
    cmp qword ptr [rdi + 8], 1
    je batch_fixture_poll
    cmp qword ptr [rdi + 8], 3
    jne batch_fixture_contract
    mov esi, 1
    jmp batch_fixture_resume
batch_fixture_poll:
    xor esi, esi
batch_fixture_resume:
    call batch_call_resume
    jmp batch_fixture_result
batch_fixture_cancel:
    call batch_call_cancel
    jmp batch_fixture_result
batch_fixture_wake:
    call batch_call_wake
    jmp batch_fixture_result
batch_fixture_retire_wait:
    call batch_call_retire_wait
    jmp batch_fixture_result
batch_fixture_choose:
    mov r13, [rdi + 8]
    mov rdi, r13
    call batch_fixture_select
    cmp rax, -4095
    jae batch_fixture_contract
    mov r15, rax
    mov qword ptr [rsp], 6
    mov qword ptr [rsp + 8], 16
    mov rax, 0x3230524c53434248
    mov [rsp + 16], rax
    mov [rsp + 24], r13
    mov edi, 1
    mov rsi, rsp
    mov edx, 32
    call view_write_all
    test rax, rax
    js batch_fixture_io
    jmp batch_fixture_next
batch_fixture_call:
    call batch_call_run
batch_fixture_result:
    mov [rsp + 16], rax
    mov rbx, [r15 + 8]
    mov qword ptr [rsp], 2
    mov qword ptr [rsp + 8], 8
    cmp eax, 0xfffffff0
    jne batch_fixture_ordinary
    mov qword ptr [rsp], 3
    mov eax, 64
batch_fixture_ordinary:
    cmp eax, 0xffff0000
    jae batch_fixture_header
    cmp eax, 64
    jne batch_fixture_contract
    mov rax, [rbx + 24]
    mov rcx, [rax + 40]
    add rcx, 64
    jc batch_fixture_contract
    cmp rcx, [rbx + 32]
    ja batch_fixture_contract
    mov [rsp + 24], rcx
    add rcx, 8
    jc batch_fixture_contract
    mov [rsp + 8], rcx
batch_fixture_header:
    mov edi, 1
    mov rsi, rsp
    mov edx, 24
    call view_write_all
    test rax, rax
    js batch_fixture_io
    mov eax, 0xffff0000
    cmp dword ptr [rsp + 16], 0xfffffff0
    je batch_fixture_write_body
    cmp [rsp + 16], rax
    jae batch_fixture_next
batch_fixture_write_body:
    mov edi, 1
    mov rsi, [rbx + 24]
    mov rdx, [rsp + 24]
    call view_write_all
    test rax, rax
    js batch_fixture_io
    jmp batch_fixture_next
batch_fixture_eof:
    call batch_fixture_retire_all
    test rax, rax
    jnz batch_fixture_contract
    xor edi, edi
    jmp batch_fixture_exit
batch_fixture_usage:
    mov edi, 64
    jmp batch_fixture_exit
batch_fixture_contract:
    mov edi, 70
    jmp batch_fixture_exit
batch_fixture_resource:
    mov edi, 71
    jmp batch_fixture_exit
batch_fixture_io:
    mov edi, 74
batch_fixture_exit:
    mov eax, 60
    syscall
    ud2
.balign 8
.global batch_image_table
batch_image_table:
    .zero 176
