/* Reserve enough executable capacity for EVERY aligned function permutation. */
.section .fgspace,"ax",@progbits
.space 131072,0xcc
.section .note.GNU-stack,"",@progbits
