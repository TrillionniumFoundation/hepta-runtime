# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
# Successful file_info handoff only. Enter by JMP with the original guard frame.
# The retained worker has published its result and notified the ready pipe.
# Own-PID WNOHANG reaping must finish before the next request can begin.
# Every retry is charged to the existing absolute CLOCK_MONOTONIC deadline.
.intel_syntax noprefix
.section .text
.global guard_ready_reap
.equ guard_cancel, 0x4014c0
.equ guard_reap, 0x401483
.equ guard_remaining, 0x4013e5
.equ guard_failure, 0x40145e
.equ guard_resume, 0x40181f
guard_ready_reap:
    call guard_cancel
    test rax, rax
    js guard_failure
    cmp QWORD PTR [rbp], 0
    je guard_resume
.Lwait_owned:
    call guard_remaining
    test rax, rax
    js guard_failure
    cmp QWORD PTR [rbp+0x120], 0
    jne .Lcap
    cmp QWORD PTR [rbp+0x128], 1000000
    jbe .Lsleep
.Lcap:
    mov QWORD PTR [rbp+0x120], 0
    mov QWORD PTR [rbp+0x128], 1000000
.Lsleep:
    xor edi, edi
    xor esi, esi
    lea rdx, [rbp+0x120]
    xor r10d, r10d
    push r8
    mov r8d, 8
    mov eax, 271
    syscall
    pop r8
    cmp rax, -4
    je .Lreap
    test rax, rax
    js guard_failure
.Lreap:
    call guard_reap
    test rax, rax
    js guard_failure
    cmp QWORD PTR [rbp], 0
    jne .Lwait_owned
    jmp guard_resume
.section .note.GNU-stack,"",@progbits
