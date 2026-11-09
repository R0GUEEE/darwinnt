# Host build (Linux/macOS). The Windows target is built in CI with MinGW.
CC      ?= gcc
CFLAGS  ?= -std=c11 -Wall -Wextra -Wpedantic -O2
CFLAGS  += -Iinclude -Isrc
LDFLAGS ?=
# SAN=1 enables ASan/UBSan where the toolchain ships the runtime.
ifeq ($(SAN),1)
SANFLAGS = -g -fsanitize=address,undefined
else
SANFLAGS = -g
endif

SRC_COMMON = src/dnt_macho.c src/dnt_path.c src/dnt_syscall.c src/dnt_vfs.c \
             src/dnt_port_posix.c
SRC_HOST   = src/main.c $(SRC_COMMON)

all: build/darwinnt

src/generated/syscalls.h: spec/master.txt tools/gen_syscalls.py
	python3 tools/gen_syscalls.py spec/master.txt $@

build:
	mkdir -p build

build/darwinnt: $(SRC_HOST) src/generated/syscalls.h | build
	$(CC) $(CFLAGS) $(SRC_HOST) -o $@ $(LDFLAGS)

build/test_macho: tests/test_macho.c tests/fixture.c src/dnt_macho.c src/generated/syscalls.h | build
	$(CC) $(CFLAGS) $(SANFLAGS) $^ -o $@

build/test_path: tests/test_path.c src/dnt_path.c | build
	$(CC) $(CFLAGS) $(SANFLAGS) $^ -o $@

build/test_syscall: tests/test_syscall.c src/dnt_syscall.c src/generated/syscalls.h | build
	$(CC) $(CFLAGS) $(SANFLAGS) tests/test_syscall.c src/dnt_syscall.c src/dnt_vfs.c \
	  src/dnt_path.c src/dnt_port_posix.c -o $@

build/test_vfs: tests/test_vfs.c src/dnt_vfs.c src/dnt_path.c src/dnt_port_posix.c | build
	$(CC) $(CFLAGS) $(SANFLAGS) $^ -o $@

build/test_syscalls_fs: tests/test_syscalls_fs.c src/dnt_syscall.c src/dnt_vfs.c \
                        src/dnt_path.c src/dnt_port_posix.c src/generated/syscalls.h | build
	$(CC) $(CFLAGS) $(SANFLAGS) tests/test_syscalls_fs.c src/dnt_syscall.c src/dnt_vfs.c \
	  src/dnt_path.c src/dnt_port_posix.c -o $@

check: build/test_macho build/test_path build/test_syscall build/test_vfs build/test_syscalls_fs
	./build/test_macho && ./build/test_path && ./build/test_syscall \
	  && ./build/test_vfs && ./build/test_syscalls_fs

clean:
	rm -rf build

.PHONY: all check clean
