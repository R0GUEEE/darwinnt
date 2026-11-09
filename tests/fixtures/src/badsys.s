.text
.globl _start
_start:
    mov x16, #2          // fork
    svc #0x80
    // x0 now holds the errno (78 = ENOSYS) on failure; exit with it
    mov x16, #1
    svc #0x80
