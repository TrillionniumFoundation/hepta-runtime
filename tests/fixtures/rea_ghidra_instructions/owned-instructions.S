# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
# x86-64 owned fixture source only. Qualification must compile and hash a fresh ELF.
# The analysis provider must never execute that ELF.
.section .text
.balign 16
.global hepta_instruction_leaf
.type hepta_instruction_leaf, @function
hepta_instruction_leaf:
    .byte 0xb8, 0x11, 0x00, 0x00, 0x00
    .byte 0x83, 0xc0, 0x07
    .byte 0xc3
.size hepta_instruction_leaf, .-hepta_instruction_leaf

.balign 16
.global hepta_instruction_row_budget
.type hepta_instruction_row_budget, @function
hepta_instruction_row_budget:
    .rept 4096
    .byte 0x90
    .endr
    .byte 0xc3
.size hepta_instruction_row_budget, .-hepta_instruction_row_budget

.balign 16
.global _start
.type _start, @function
_start:
    call hepta_instruction_leaf
    call hepta_instruction_row_budget
    xor %edi, %edi
    mov $60, %eax
    syscall
.size _start, .-_start
.section .note.GNU-stack,"",@progbits
