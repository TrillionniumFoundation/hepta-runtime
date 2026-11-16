# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
# Fixed serial callbacks. The installed Config arena and Ticket storage are shared.
.equ EX_META_LOCAL, 1168
.equ EX_META_ADDRESS, 1176
.equ EX_CONFIG_IG, 1184

# Same borrowed query ABI as the former leaf projection. This drives continuation.
ex_config_projection:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    cmp qword ptr [r15 + 784], 0
    jne fatal
    cmp rsi, 24
    jb fatal
    cmp rsi, ROOT_INPUT_CAP
    ja fatal
    cmp rcx, 32
    jb fatal
    cmp rcx, ROOT_OUTPUT_CAP
    ja fatal
    mov rax, 0x3130514746435248
    cmp [rdi], rax
    jne fatal
    cmp qword ptr [rdi + 8], 1
    jb fatal
    cmp qword ptr [rdi + 8], 12
    ja fatal
    mov [r15 + 832], rdi
    mov [r15 + 840], rsi
    mov [r15 + 848], rdx
    mov [r15 + 856], rcx
    mov qword ptr [r15 + 784], 3
    lea rax, [r15 + ROOT_WORK + FOOTER]
    mov qword ptr [rax + 120], 1
    jmp owner_resume
ex_config_return:
    cmp qword ptr [r15 + 784], 3
    jne fatal
    cmp rax, [r15 + 856]
    ja fatal
    mov qword ptr [r15 + 784], 0
    mov qword ptr [r15 + 832], 0
    mov qword ptr [r15 + 840], 0
    mov qword ptr [r15 + 848], 0
    mov qword ptr [r15 + 856], 0
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

# IG, request, bytes, reply, capacity -> complete HRCFGM01.
ex_intent_config_call:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp, 8
    mov r12, rdi
    mov r15, [r12 + 128]
    test r15, r15
    jz tk_intent_contract_failure
    cmp [r15 + EX_CONFIG_IG], r12
    jne fatal
    mov rax, [r15 + EX_CONTROL_SLOT]
    test rax, rax
    jz fatal
    mov rax, [rax + 16]
    cmp [r12 + 8], rax
    jne fatal
    mov rdi, rsi
    mov rsi, rdx
    mov rdx, rcx
    mov rcx, r8
    call ex_config_projection
    add rsp, 8
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

# IG remains alive here. Transfer the unique cache word before backend retirement.
# Config is borrowed; its actual EOF destruction belongs to the public root.
ex_intent_config_drop:
    push rbx
    push r12
    sub rsp, 8
    mov r12, rdi
    mov rbx, [r12 + 128]
    test rbx, rbx
    jz ex_intent_config_drop_done
    cmp [rbx + EX_CONFIG_IG], r12
    jne tk_intent_contract_failure
    cmp qword ptr [rbx + 784], 0
    jne tk_intent_contract_failure
    call tk_intent_metadata_address
    cmp [rbx + EX_META_ADDRESS], rdx
    jne tk_intent_contract_failure
    mov rax, [rdx]
    cmp rax, 2
    ja tk_intent_contract_failure
    mov [rbx + EX_META_LOCAL], rax
    lea rax, [rbx + EX_META_LOCAL]
    mov [rbx + EX_META_ADDRESS], rax
    mov qword ptr [rbx + EX_CONFIG_IG], 0
    mov qword ptr [r12 + 128], 0
ex_intent_config_drop_done:
    xor eax, eax
    add rsp, 8
    pop r12
    pop rbx
    ret

# Called after the fixed Ticket root was constructed, before any request.
ex_bind_intent:
    push rbx
    mov rdi, [rbx + 16]
    call tk_intent_global_create
    test rax, rax
    jz fatal
    cmp qword ptr [rax + 128], 0
    jne fatal
    cmp qword ptr [r15 + EX_CONFIG_IG], 0
    jne fatal
    mov [rax + 128], r15
    mov [r15 + EX_CONFIG_IG], rax
    mov rdi, rax
    call tk_intent_metadata_address
    cmp qword ptr [rdx], 0
    jne fatal
    mov rax, [r15 + EX_META_LOCAL]
    cmp rax, 2
    ja fatal
    mov [rdx], rax
    mov [r15 + EX_META_ADDRESS], rdx
    mov qword ptr [r15 + EX_META_LOCAL], 0
    pop rbx
    ret

ex_map_intent:
    cmp rsi, 96
    jb fatal
    cmp rsi, 8388704
    ja fatal
    mov rcx, rdx
    mov rdx, rsi
    mov rsi, rdi
    mov rdi, [r15 + EX_CONFIG_IG]
    test rdi, rdi
    jz fatal
    call tk_intent_owner_call
    cmp eax, 80
    jne fatal
    jmp ex_mapper_ack

ex_map_metadata:
    cmp rsi, 96
    jb fatal
    cmp rsi, 16777216
    ja fatal
    call ex_metadata_call
    jmp ex_mapper_ack

# request, bytes, reply, capacity. The DTO and metadata calls are serial.
ex_metadata_call:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp, 40
    mov [rsp], rdi
    mov [rsp + 8], rsi
    mov [rsp + 16], rdx
    mov [rsp + 24], rcx
    mov r13, [r15 + EX_CONFIG_IG]
    test r13, r13
    jz fatal
    cmp [r13 + 128], r15
    jne fatal
    mov r12, [r13 + 48]
    test r12, r12
    jnz ex_metadata_existing
    mov edi, OFFSET FLAT:tk_CV_BYTES
    call tk_allocate_guarded
    mov r12, rax
    mov [r13 + 48], r12
    mov [r12 + 8], r13
ex_metadata_existing:
    cmp [r12 + 8], r13
    jne fatal
    mov rax, [r12 + 32]
    or rax, [r12 + 56]
    or rax, [r12 + 144]
    jnz fatal
    mov rdi, r12
    mov rsi, [rsp]
    mov rdx, [rsp + 8]
    mov rcx, [rsp + 16]
    mov r8, [rsp + 24]
    call tk_intent_result_metadata_call
    add rsp, 40
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret
