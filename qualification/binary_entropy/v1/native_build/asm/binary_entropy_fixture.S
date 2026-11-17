.intel_syntax noprefix
.section .text
.global _start
.type _start, @function
_start:
    xor eax, eax
    ret
.section .note.GNU-stack,"",@progbits
