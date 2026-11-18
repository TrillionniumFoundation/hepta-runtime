# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
# Fixed serial callbacks. The installed Config arena and Ticket storage are shared.
.equ EX_META_LOCAL, 1168
.equ EX_META_ADDRESS, 1176
.equ EX_CONFIG_IG, 1184

# Same borrowed query ABI as the former leaf projection. This drives continuation.
ex_config_projection:
    jmp pf_config_query
pf_config_owned:
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
    cmp qword ptr [rdi + 8], 13
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

# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
# Stable public Config metadata provider; no shared arena pointer across IO.
ex_public_file_metadata:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp, 136
    mov r12, rdi
    mov r13, rsi
    mov r14, [r15 + EX_CONFIG_IG]
    xor ebx, ebx
    test r14, r14
    jnz ex_public_file_metadata_shared
    mov rbx, rsp
    mov rdi, rbx
    xor eax, eax
    mov ecx, 16
    rep stosq
    mov rax, 0x3130474954495248
    mov [rbx], rax
    mov rax, [r15 + EX_META_LOCAL]
    cmp rax, 2
    ja fatal
    mov [rbx + 96], rax
    mov r14, rbx
    jmp ex_public_file_metadata_call
ex_public_file_metadata_shared:
    cmp [r14 + 128], r15
    jne fatal
ex_public_file_metadata_call:
    mov rdi, r12
    mov rsi, r13
    mov rdx, r14
    call tk_intent_file_metadata
    test rbx, rbx
    jz ex_public_file_metadata_done
    mov rcx, [rbx + 96]
    cmp rcx, 2
    ja fatal
    mov [r15 + EX_META_LOCAL], rcx
ex_public_file_metadata_done:
    add rsp, 136
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

# The IG and SG remain alive. All Read workers joined before this callback.
# Config is borrowed; its destruction remains with the public root.
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
    mov rdi, r12
    call tk_intent_provider_cache_load
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

# Bind the original Config and its startup cache before admitting any request.
# Exactly one IG and one Read boundary share the existing Ticket service.
ex_bind_intent:
    push rbx
    push r12
    sub rsp, 8
    mov rdi, [rbx + 16]
    call tk_intent_global_create
    test rax, rax
    jz fatal
    mov r12, rax
    cmp qword ptr [r12 + 128], 0
    jne fatal
    cmp qword ptr [r15 + EX_CONFIG_IG], 0
    jne fatal
    mov [r12 + 128], r15
    mov [r15 + EX_CONFIG_IG], r12
    mov rdi, r12
    call tk_intent_provider_cache_load
    test rax, rax
    jnz fatal
    mov rsi, [r15 + EX_META_LOCAL]
    cmp rsi, 2
    ja fatal
    mov rdi, r12
    call tk_intent_provider_cache_publish
    test rax, rax
    jnz fatal
    mov [r15 + EX_META_ADDRESS], r12
    mov qword ptr [r15 + EX_META_LOCAL], 0
    mov rdi, [rbx + 16]
    call tk_read_boundary_create
    test rax, rax
    jz fatal
    mov rdi, [rbx + 16]
    mov rsi, r12
    call tk_async_global_create
    test rax, rax
    jz fatal
    mov rdi, [rbx + 16]
    call tk_metadata_boundary_create
    test rax, rax
    jz fatal
    add rsp, 8
    pop r12
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
    mov rdi, [r15 + PIC_ROOT_SLOT]
    test rdi, rdi
    jz pic_map_intent_canonical
    call intent_caller_call
    jmp pic_map_intent_done
pic_map_intent_canonical:
    mov rdi, [r15 + EX_CONFIG_IG]
    test rdi, rdi
    jz fatal
    call tk_intent_owner_call
pic_map_intent_done:
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
    jmp pic_public_metadata
pf_metadata_owned:
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
