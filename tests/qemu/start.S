.section .text.init, "ax"
.globl _start
_start:
	csrr t0, mhartid
	li t1, 8
	bgeu t0, t1, 2f
	.option push
	.option norelax
	la gp, __global_pointer$
	.option pop
	la sp, stacks
	addi t1, t0, 1
	slli t1, t1, 14
	add sp, sp, t1
	mv a0, t0
	bnez t0, 1f
	call test_main
1:
	mv a0, t0
	call qemu_hart_entry
2:
	wfi
	j 2b
.section .bss
.balign 16
stacks:
	.space 131072
