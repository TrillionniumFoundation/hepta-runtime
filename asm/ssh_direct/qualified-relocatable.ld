/* Preserve the originally qualified relocatable section order across GNU ld
 * versions. Both the complete .o and complete linked ELF retain their exact
 * original SHA256 checks. This changes no section bytes or runtime code. */
SECTIONS
{
  .text 0 : { *(.text) }
  .rodata 0 : { *(.rodata) }
  .data 0 : { *(.data) }
  .bss 0 : { *(.bss) }
  .note.GNU-stack 0 : { *(.note.GNU-stack) }
}
