/* SPDX-License-Identifier: GPL-2.0-only */
.section .text.init, "ax", @progbits
.globl _start
.type _start, @function
_start:
	.rept 8
	nop
	.endr
	fence.i
	fence
	csrrci t0, mstatus, 8
	csrr t0, mhartid
	li t1, 8
	bgeu t0, t1, .Lpark
	.option push
	.option norelax
	la gp, __global_pointer$
	.option pop
	la sp, __stack0
	li t1, 0x4000
	mul t1, t0, t1
	add sp, sp, t1
	bnez t0, .Lrun
	la t0, __bss_start
	la t1, __bss_end
	addi t1, t1, 4
.Lzero:
	bgeu t0, t1, .Lrun
	sw zero, 0(t0)
	addi t0, t0, 4
	j .Lzero
.Lrun:
	csrr a0, mhartid
	call crypto_service
.Lpark:
	wfi
	j .Lpark
.size _start, . - _start
