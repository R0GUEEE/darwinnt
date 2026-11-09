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

/* Entry point from the generated per-number stubs. */
uint64_t dnt_syscall(uint32_t nr, uint64_t a0, uint64_t a1, uint64_t a2,
                     uint64_t a3, uint64_t a4, uint64_t a5);
const char *dnt_syscall_name(uint32_t nr);

/* Guest memory helpers. */
int dnt_u_strcpy(uint64_t guest_addr, char *host_dst, size_t host_cap, size_t *out_len);
size_t dnt_u_read(uint64_t guest_addr, void *dst, size_t n);
void dnt_u_write(uint64_t guest_addr, const void *src, size_t n);

#endif
