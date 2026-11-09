.text
.globl _start
_start:
    mov x0, #1
    adrp x1, msg@PAGE
    add  x1, x1, msg@PAGEOFF
    mov x2, #6
    mov x16, #4          // write
    svc #0x80
    mov x0, #0
    mov x16, #1          // exit
    svc #0x80
.data
msg:
    .ascii "hello\n"
