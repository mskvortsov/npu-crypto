OUTPUT_ARCH(riscv)
ENTRY(_start)
SECTIONS {
  . = 0x80000000;
  .text : { *(.text.init) *(.text .text.*) }
  .rodata : { *(.rodata .rodata.*) *(.srodata .srodata.*) }
  .data : { *(.data .data.*) *(.sdata .sdata.*) }
  __global_pointer$ = . + 0x800;
  .bss : { *(.bss .bss.*) *(.sbss .sbss.*) *(COMMON) }
}
