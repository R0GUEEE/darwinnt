#!/bin/sh
# Builds real Darwin arm64 executables with the cross toolchain, for tests.
#
# These are not hand-crafted byte blobs: clang emits arm64 Mach-O objects and
# ld64.lld links them into executables that a Mac could run. Using the real
# toolchain is what caught __PAGEZERO (an unrejected guard segment) -- a
# synthetic fixture would never have had one.
set -eu

OUT="${1:-tests/fixtures}"
mkdir -p "$OUT"
SRC="$OUT/src"
mkdir -p "$SRC"

TARGET=arm64-apple-macos11

link() {
    ld64.lld -arch arm64 -platform_version macos 11.0 11.0 -e "$2" "$1" -o "$3" 2>/dev/null
}

# ---- 1. hello: write(1, "hello\n", 6) then exit(0) ----
cat > "$SRC/hello.s" <<'EOF'
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
EOF

# ---- 2. exitcode: exit(42) ----
cat > "$SRC/exitcode.s" <<'EOF'
.text
.globl _start
_start:
    mov x0, #42
    mov x16, #1
    svc #0x80
EOF

# ---- 3. badsys: an unimplemented syscall, then exit(0) ----
# Uses fork (2), which the shim deliberately does not implement: the guest must
# observe ENOSYS rather than a fabricated success.
cat > "$SRC/badsys.s" <<'EOF'
.text
.globl _start
_start:
    mov x16, #2          // fork
    svc #0x80
    // x0 now holds the errno (78 = ENOSYS) on failure; exit with it
    mov x16, #1
    svc #0x80
EOF

for name in hello exitcode badsys; do
    clang --target=$TARGET -c "$SRC/$name.s" -o "$OUT/$name.o"
    link "$OUT/$name.o" _start "$OUT/$name.macho"
    rm -f "$OUT/$name.o"
    printf 'built %s.macho (%s bytes)\n' "$name" "$(wc -c < "$OUT/$name.macho")"
done
