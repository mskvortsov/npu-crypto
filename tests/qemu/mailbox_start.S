.section .text.init, "ax"
.globl _start
_start:
 csrr t0, mhartid
 .option push
 .option norelax
 la gp, __global_pointer$
 .option pop
 la sp, stacks
 addi t1, t0, 1
 slli t1, t1, 14
 add sp, sp, t1
 mv a0, t0
 li t1, 8
 beq t0, t1, 1f
 call crypto_service
1:
 call mailbox_test_main
2:
 wfi
 j 2b
.section .bss
.balign 16
stacks:
 .space 147456
