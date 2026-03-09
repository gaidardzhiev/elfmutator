.syntax unified
.arch armv7-a
.text
.globl _start
.type _start, %function
_start:
mov r7, #4
mov r0, #1
adr r1, msg
mov r2, #34
svc 0
b .
msg:
.asciz "Malicious ARM32 payload executed!\n"
