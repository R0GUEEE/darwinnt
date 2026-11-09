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
#include "dnt_vfs.h"
#include "dnt_port.h"
#include "generated/syscalls.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

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


/* ---- filesystem handlers ---- */

/* Read a guest path into host memory. Returns 0 or a Darwin errno. */
static int getpath(uint64_t guest_addr, char *buf, size_t cap)
{
    if (!guest_addr)
        return DNT_EFAULT;
    return dnt_u_strcpy(guest_addr, buf, cap, NULL);
}

static uint64_t sys_open(uint64_t path_addr, int flags, int mode)
{
    char path[DNT_MAXPATHLEN];
    int rc = getpath(path_addr, path, sizeof(path));
    if (rc)
        return (uint64_t)rc;
    int fd = dnt_vfs_open(path, flags, mode);
    return fd < 0 ? (uint64_t)(-fd) : (uint64_t)fd;
}

static uint64_t sys_close(uint64_t fd)
{
    int rc = dnt_vfs_close((int)fd);
    return rc ? (uint64_t)rc : 0;
}

static uint64_t sys_read(uint64_t fd, uint64_t buf_addr, uint64_t nbyte)
{
    /* Bound the transfer: a guest asking for 4 GB is not a request we honour
     * by allocating it. Chunked reads let the caller loop, as read() allows. */
    const uint64_t chunk = 1u << 20;
    if (nbyte > chunk)
        nbyte = chunk;
    char *tmp = malloc((size_t)nbyte ? (size_t)nbyte : 1);
    if (!tmp)
        return DNT_ENOMEM;
    int err = 0;
    int64_t r = dnt_vfs_read((int)fd, tmp, nbyte, &err);
    if (r > 0)
        dnt_u_write(buf_addr, tmp, (size_t)r);
    free(tmp);
    if (r < 0)
        return (uint64_t)err;
    return (uint64_t)r;
}

static uint64_t sys_write(uint64_t fd, uint64_t buf_addr, uint64_t nbyte)
{
    const uint64_t chunk = 1u << 20;
    if (nbyte > chunk)
        nbyte = chunk;
    char *tmp = malloc((size_t)nbyte ? (size_t)nbyte : 1);
    if (!tmp)
        return DNT_ENOMEM;
    size_t got = dnt_u_read(buf_addr, tmp, (size_t)nbyte);
    if (got != (size_t)nbyte) {
        free(tmp);
        return DNT_EFAULT;
    }
    int err = 0;
    int64_t r = dnt_vfs_write((int)fd, tmp, nbyte, &err);
    free(tmp);
    if (r < 0)
        return (uint64_t)err;
    return (uint64_t)r;
}

static uint64_t sys_lseek(uint64_t fd, int64_t off, int whence)
{
    int err = 0;
    int64_t r = dnt_vfs_lseek((int)fd, off, whence, &err);
    return r < 0 ? (uint64_t)err : (uint64_t)r;
}

static uint64_t sys_stat_common(uint64_t path_addr, uint64_t ub, int follow)
{
    char path[DNT_MAXPATHLEN];
    int rc = getpath(path_addr, path, sizeof(path));
    if (rc)
        return (uint64_t)rc;
    if (!ub)
        return DNT_EFAULT;
    dnt_stat st;
    rc = dnt_vfs_stat(path, &st, follow);
    if (rc)
        return (uint64_t)rc;
    dnt_u_write(ub, &st, sizeof(st));
    return 0;
}

static uint64_t sys_fstat(uint64_t fd, uint64_t ub)
{
    if (!ub)
        return DNT_EFAULT;
    dnt_stat st;
    int rc = dnt_vfs_fstat((int)fd, &st);
    if (rc)
        return (uint64_t)rc;
    dnt_u_write(ub, &st, sizeof(st));
    return 0;
}

static uint64_t sys_getdirentries64(uint64_t fd, uint64_t buf_addr,
                                   uint64_t bufsize, uint64_t base_addr)
{
    if (bufsize > (1u << 20))
        return DNT_EINVAL;
    char *tmp = malloc((size_t)bufsize ? (size_t)bufsize : 1);
    if (!tmp)
        return DNT_ENOMEM;
    int64_t base = 0;
    int64_t r = dnt_vfs_getdirentries64((int)fd, tmp, bufsize, &base);
    if (r >= 0) {
        dnt_u_write(buf_addr, tmp, (size_t)r);
        if (base_addr)
            dnt_u_write(base_addr, &base, sizeof(base));
    }
    free(tmp);
    return r < 0 ? (uint64_t)(-r) : (uint64_t)r;
}

static uint64_t sys_chdir(uint64_t path_addr)
{
    char path[DNT_MAXPATHLEN];
    int rc = getpath(path_addr, path, sizeof(path));
    if (rc)
        return (uint64_t)rc;
    return (uint64_t)dnt_vfs_chdir(path);
}

static uint64_t sys_unlink(uint64_t path_addr)
{
    char path[DNT_MAXPATHLEN];
    int rc = getpath(path_addr, path, sizeof(path));
    if (rc)
        return (uint64_t)rc;
    return (uint64_t)dnt_vfs_unlink(path);
}

static uint64_t sys_mkdir(uint64_t path_addr, int mode)
{
    char path[DNT_MAXPATHLEN];
    int rc = getpath(path_addr, path, sizeof(path));
    if (rc)
        return (uint64_t)rc;
    return (uint64_t)dnt_vfs_mkdir(path, mode);
}

static uint64_t sys_rmdir(uint64_t path_addr)
{
    char path[DNT_MAXPATHLEN];
    int rc = getpath(path_addr, path, sizeof(path));
    if (rc)
        return (uint64_t)rc;
    return (uint64_t)dnt_vfs_rmdir(path);
}

static uint64_t sys_rename(uint64_t from_addr, uint64_t to_addr)
{
    char a[DNT_MAXPATHLEN], b[DNT_MAXPATHLEN];
    int rc = getpath(from_addr, a, sizeof(a));
    if (rc) return (uint64_t)rc;
    rc = getpath(to_addr, b, sizeof(b));
    if (rc) return (uint64_t)rc;
    return (uint64_t)dnt_vfs_rename(a, b);
}

static uint64_t sys_ftruncate(uint64_t fd, int64_t length)
{
    if (length < 0)
        return DNT_EINVAL;
    return (uint64_t)dnt_vfs_ftruncate((int)fd, (uint64_t)length);
}

static uint64_t sys_access(uint64_t path_addr, int mode)
{
    (void)mode;
    char path[DNT_MAXPATHLEN];
    int rc = getpath(path_addr, path, sizeof(path));
    if (rc)
        return (uint64_t)rc;
    dnt_stat st;
    rc = dnt_vfs_stat(path, &st, 1);
    return rc ? (uint64_t)rc : 0;
}

static uint64_t sys_fsync(uint64_t fd)
{
    /* Host backends flush on close; report success for a valid descriptor
     * rather than pretending to have called FlushFileBuffers. */
    return dnt_vfs_get((int)fd) ? 0 : DNT_EBADF;
}

static uint64_t sys_dup2(uint64_t from, uint64_t to)
{
    (void)from; (void)to;
    return DNT_ENOSYS;
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
    case DSYS_OPEN:              return sys_open(a0, (int)a1, (int)a2);
    case DSYS_OPEN_EXTENDED:     return sys_open(a0, (int)a1, (int)a4);
    case DSYS_SYS_CLOSE:         return sys_close(a0);
    case DSYS_READ:              return sys_read(a0, a1, a2);
    case DSYS_WRITE:             return sys_write(a0, a1, a2);
    case DSYS_LSEEK:             return sys_lseek(a0, (int64_t)a1, (int)a2);
    case DSYS_STAT64:            return sys_stat_common(a0, a1, 1);
    case DSYS_LSTAT64:           return sys_stat_common(a0, a1, 0);
    case DSYS_SYS_FSTAT64:       return sys_fstat(a0, a1);
    case DSYS_STAT:              return sys_stat_common(a0, a1, 1);
    case DSYS_LSTAT:             return sys_stat_common(a0, a1, 0);
    case DSYS_SYS_FSTAT:         return sys_fstat(a0, a1);
    case DSYS_GETDIRENTRIES64:   return sys_getdirentries64(a0, a1, a2, a3);
    case DSYS_SYS_CHDIR:         return sys_chdir(a0);
    case DSYS_SYS_FCHDIR:        return DNT_ENOSYS;
    case DSYS_UNLINK:            return sys_unlink(a0);
    case DSYS_MKDIR:             return sys_mkdir(a0, (int)a1);
    case DSYS_RMDIR:             return sys_rmdir(a0);
    case DSYS_RENAME:            return sys_rename(a0, a1);
    case DSYS_FTRUNCATE:         return sys_ftruncate(a0, (int64_t)a1);
    case DSYS_ACCESS:            return sys_access(a0, (int)a1);
    case DSYS_FSYNC:             return sys_fsync(a0);
    case DSYS_SYS_DUP2:          return sys_dup2(a0, a1);

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
