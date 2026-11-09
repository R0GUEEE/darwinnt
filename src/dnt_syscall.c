/* Syscall dispatch.
 *
 * The guest's `svc` trap lands in one of the generated stubs, which calls
 * dnt_syscall(nr, a0..a5). Each handler returns 0 or a Darwin errno; the
 * trampoline converts that into the two return conventions Darwin uses:
 *
 *   - most calls:   x0 = result, on error carry flag set and x0 = errno
 *   - exit:         does not return
 *
 * The host side is deliberately thin. Anything that touches the guest address
 * space goes through dnt_u<...> accessors, because a guest pointer is not a
 * valid host pointer until the page has been mapped.
 */
#include "dnt_syscall.h"
#include "dnt_abi.h"
#include "dnt_errno.h"
#include "dnt_path.h"
#include "generated/syscalls.h"

#include <stdio.h>
#include <string.h>

/* ---- guest address space access ---- */

/* Copy a NUL-terminated guest string into host memory, bounded by
 * `host_cap`. Returns 0 or DNT_EFAULT. Mirrors copyinstr(): a string with no
 * terminator inside the cap is ENAMETOOLONG, not EFAULT. */
/* Both are supplied by the host VM layer. They are weak here so that the
 * parser tests and tooling can link without a guest address space. */
__attribute__((weak)) size_t dnt_u_read(uint64_t guest_addr, void *dst, size_t n)
{
    (void)guest_addr; (void)dst; (void)n;
    return 0; /* no VM attached: every guest access faults */
}

__attribute__((weak)) void dnt_u_write(uint64_t guest_addr, const void *src, size_t n)
{
    (void)guest_addr; (void)src; (void)n;
}

int dnt_u_strcpy(uint64_t guest_addr, char *host_dst, size_t host_cap,
                 size_t *out_len)
{
    size_t got = dnt_u_read(guest_addr, host_dst, host_cap);
    if (got == 0)
        return DNT_EFAULT;
    void *nul = memchr(host_dst, 0, got);
    if (!nul)
        return DNT_ENAMETOOLONG;
    if (out_len)
        *out_len = (size_t)((char *)nul - host_dst);
    return 0;
}

/* ---- process-wide state ---- */
static dnt_host_ops g_ops;
static int g_initialised;

void dnt_syscall_init(const dnt_host_ops *ops)
{
    if (ops)
        g_ops = *ops;
    g_initialised = 1;
}

const dnt_host_ops *dnt_host(void)
{
    return &g_ops;
}

/* ---- generic handlers ---- */
static uint64_t sys_exit_call(uint64_t code)
{
    /* proc_exit takes the full int; the 8-bit truncation Darwin is famous for
     * happens when the parent reads the wait status (WEXITSTATUS), not here. */
    if (g_ops.exit)
        g_ops.exit((int)code);
    return 0;
}

static uint64_t sys_getpid(void)  { return 42; }
static uint64_t sys_getppid(void) { return 1; }
static uint64_t sys_getuid(void)  { return 501; }   /* first normal Darwin uid */
static uint64_t sys_getgid(void)  { return 20; }    /* staff */
static uint64_t sys_geteuid(void) { return 501; }
static uint64_t sys_getegid(void) { return 20; }

static uint64_t sys_gettimeofday(uint64_t tv_addr, uint64_t tz, uint64_t mach)
{
    (void)tz; (void)mach;
    if (!tv_addr)
        return DNT_EFAULT;
    dnt_timeval tv;
    if (g_ops.gettimeofday) {
        g_ops.gettimeofday(&tv);
        dnt_u_write(tv_addr, &tv, sizeof(tv));
        return 0;
    }
    return DNT_ENOSYS;
}

uint64_t dnt_syscall(uint32_t nr, uint64_t a0, uint64_t a1, uint64_t a2,
                     uint64_t a3, uint64_t a4, uint64_t a5)
{
    (void)g_initialised; (void)a3; (void)a4; (void)a5;
    if (nr > DSYS_MAX_SYSCALL)
        return (uint64_t)DNT_ENOSYS;

    switch (nr) {
    case DSYS_EXIT:              return sys_exit_call(a0);
    case DSYS_GETPID:            return sys_getpid();
    case DSYS_GETPPID:           return sys_getppid();
    case DSYS_GETUID:            return sys_getuid();
    case DSYS_GETGID:            return sys_getgid();
    case DSYS_GETEUID:           return sys_geteuid();
    case DSYS_GETEGID:           return sys_getegid();
    case DSYS_GETTIMEOFDAY:      return sys_gettimeofday(a0, a1, a2);
    default:
        if (g_ops.unimplemented)
            g_ops.unimplemented(nr,
                nr <= DSYS_MAX_SYSCALL ? dsys_table_name[nr] : "?");
        return (uint64_t)DNT_ENOSYS;
    }
}

const char *dnt_syscall_name(uint32_t nr)
{
    if (nr > DSYS_MAX_SYSCALL)
        return "out-of-range";
    return dsys_table_name[nr] ? dsys_table_name[nr] : "nosys";
}
