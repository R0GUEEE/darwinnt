#ifndef DNT_SYSCALL_H
#define DNT_SYSCALL_H
#include <stdint.h>
#include <stddef.h>
#include "dnt_abi.h"

/* Host services the syscall layer needs. Supplied by the Windows runtime;
 * every call is optional and its absence is reported, not guessed at. */
typedef struct {
    void (*exit)(int code);
    void (*gettimeofday)(dnt_timeval *tv);
    void (*unimplemented)(uint32_t nr, const char *name); /* logging hook */
} dnt_host_ops;

void dnt_syscall_init(const dnt_host_ops *ops);
const dnt_host_ops *dnt_host(void);

/* Entry point from the generated per-number stubs.
 *
 * Darwin's return convention is two registers' worth of information: the
 * result in x0 and "did it fail" in the carry flag. Returning errno as a
 * positive value alone loses the distinction between a failed call returning
 * errno 2 and a successful call returning 2 (e.g. read() of 2 bytes), so the
 * failure bit is reported out of band through *is_error. */
uint64_t dnt_syscall_ex(uint32_t nr, uint64_t a0, uint64_t a1, uint64_t a2,
                        uint64_t a3, uint64_t a4, uint64_t a5, int *is_error);

typedef struct { uint64_t v; int err; } dnt_result;
dnt_result dnt_syscall_r(uint32_t nr, uint64_t a0, uint64_t a1, uint64_t a2,
                         uint64_t a3, uint64_t a4, uint64_t a5);

uint64_t dnt_syscall(uint32_t nr, uint64_t a0, uint64_t a1, uint64_t a2,
                     uint64_t a3, uint64_t a4, uint64_t a5);
const char *dnt_syscall_name(uint32_t nr);

/* Guest memory helpers. */
int dnt_u_strcpy(uint64_t guest_addr, char *host_dst, size_t host_cap, size_t *out_len);
size_t dnt_u_read(uint64_t guest_addr, void *dst, size_t n);
void dnt_u_write(uint64_t guest_addr, const void *src, size_t n);

/* Guest memory registration, called by the executor. */
void dnt_guest_register(uint64_t base, uint64_t size);
void dnt_guest_clear(void);
int  dnt_guest_range_ok(uint64_t addr, uint64_t n);

#endif
