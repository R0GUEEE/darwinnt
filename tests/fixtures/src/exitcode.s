.text
.globl _start
_start:
    mov x0, #42
    mov x16, #1
    svc #0x80
