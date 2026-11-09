/* End-to-end: syscall number in, Darwin-visible effect out.
 *
 * A fake guest address space stands in for the Windows one, so this exercises
 * the same path a real guest takes: dnt_syscall() -> copyin path -> VFS ->
 * port -> disk, and back through copyout into guest memory.
 */
#include "dnt_syscall.h"
#include "dnt_vfs.h"
#include "dnt_abi.h"
#include "dnt_errno.h"
#include "generated/syscalls.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int failures;
#define CHECK(cond, ...) do { \
    if (!(cond)) { printf("FAIL: "); printf(__VA_ARGS__); printf("\n"); failures++; } \
    else { printf("ok: "); printf(__VA_ARGS__); printf("\n"); } \
} while (0)

/* ---- simulated guest memory ---- */
#define GUEST_BASE 0x0000000100000000ull
#define GUEST_SIZE (1u << 16)
static uint8_t g_guest[GUEST_SIZE] __attribute__((aligned(4096)));

static uint64_t g2h(uint64_t addr) { return (uint64_t)(uintptr_t)(g_guest + (addr - GUEST_BASE)); }

size_t dnt_u_read(uint64_t addr, void *dst, size_t n)
{
    if (addr < GUEST_BASE || addr + n > GUEST_BASE + GUEST_SIZE)
        return 0;
    memcpy(dst, (void *)(uintptr_t)g2h(addr), n);
    return n;
}

void dnt_u_write(uint64_t addr, const void *src, size_t n)
{
    if (addr < GUEST_BASE || addr + n > GUEST_BASE + GUEST_SIZE)
        return;
    memcpy((void *)(uintptr_t)g2h(addr), src, n);
}

static uint64_t put_string(const char *s)
{
    static uint64_t off = 0x100;
    uint64_t addr = GUEST_BASE + off;
    size_t n = strlen(s) + 1;
    if (off + n >= GUEST_SIZE)
        abort();
    memcpy(g_guest + off, s, n);
    off += n;
    return addr;
}

static int exits;
static void on_exit(int c) { (void)c; exits++; }
static void on_unimpl(uint32_t nr, const char *name) { (void)nr; (void)name; }

/* Darwin syscalls that fail set the carry flag and return errno in x0. At the
 * C level dnt_syscall returns the errno as a positive value; the trampoline
 * decides how to present it. Tests assert on that raw value. */
static uint64_t call1(uint32_t nr, uint64_t a0)
{
    return dnt_syscall(nr, a0, 0, 0, 0, 0, 0);
}

int main(void)
{
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "rm -rf /tmp/dnt_e2e && mkdir -p /tmp/dnt_e2e/usr/share");
    if (system(cmd) != 0) return 2;

    FILE *f = fopen("/tmp/dnt_e2e/usr/share/hello.txt", "wb");
    if (!f) return 2;
    fwrite("darwin", 1, 6, f);
    fclose(f);

    if (dnt_vfs_init("/tmp/dnt_e2e") != 0) return 2;
    dnt_host_ops ops = { on_exit, NULL, on_unimpl };
    dnt_syscall_init(&ops);

    /* open via syscall 5, read via 3, close via 6 */
    uint64_t path = put_string("/usr/share/hello.txt");
    uint64_t r = call1(DSYS_OPEN, path);
    CHECK(r >= 3 && r < 64, "open() syscall returned fd %llu", (unsigned long long)r);
    int fd = (int)r;

    uint64_t buf = GUEST_BASE + 0x1000;
    r = dnt_syscall(DSYS_READ, (uint64_t)fd, buf, 16, 0, 0, 0);
    CHECK(r == 6, "read() returned 6 bytes (got %llu)", (unsigned long long)r);
    CHECK(memcmp(g_guest + 0x1000, "darwin", 6) == 0, "bytes landed in guest memory");

    r = call1(DSYS_SYS_CLOSE, (uint64_t)fd);
    CHECK(r == 0, "close() returned 0");

    /* stat64 -> struct written into guest memory */
    uint64_t st_addr = GUEST_BASE + 0x2000;
    r = dnt_syscall(DSYS_STAT64, path, st_addr, 0, 0, 0, 0);
    CHECK(r == 0, "stat64() succeeded");
    dnt_stat gst;
    memcpy(&gst, g_guest + 0x2000, sizeof(gst));
    CHECK(gst.st_size == 6, "guest sees st_size 6 (got %lld)", (long long)gst.st_size);
    CHECK((gst.st_mode & DNT_S_IFMT) == DNT_S_IFREG, "guest sees S_IFREG");

    /* missing file must surface ENOENT through the syscall layer */
    uint64_t miss = put_string("/usr/share/nope");
    r = call1(DSYS_OPEN, miss);
    CHECK(r == DNT_ENOENT, "open(missing) -> ENOENT (got %llu)", (unsigned long long)r);

    /* path pointer outside guest memory must be EFAULT, not a host crash */
    r = call1(DSYS_OPEN, 0xDEADBEEF000ull);
    CHECK(r == DNT_EFAULT, "open(bad pointer) -> EFAULT (got %llu)", (unsigned long long)r);

    /* getdirentries64 through the dispatcher */
    uint64_t dirp = put_string("/usr");
    r = call1(DSYS_OPEN, dirp);
    CHECK(r >= 3, "open(/usr) -> fd");
    int dfd = (int)r;
    uint64_t dbuf = GUEST_BASE + 0x3000;
    uint64_t base_addr = GUEST_BASE + 0x3800;
    r = dnt_syscall(DSYS_GETDIRENTRIES64, (uint64_t)dfd, dbuf, 2048, base_addr, 0, 0);
    CHECK((int64_t)r > 0, "getdirentries64() returned %lld bytes", (long long)r);
    int found = 0;
    int64_t off = 0;
    while (off < (int64_t)r) {
        dnt_dirent de;
        memcpy(&de, g_guest + 0x3000 + off, offsetof(dnt_dirent, d_name) + 260);
        if (strcmp(de.d_name, "share") == 0) found = 1;
        if (de.d_reclen == 0) break;
        off += de.d_reclen;
    }
    CHECK(found, "guest listing contains 'share'");
    call1(DSYS_SYS_CLOSE, (uint64_t)dfd);

    /* mkdir + rename + unlink through the dispatcher */
    uint64_t nd = put_string("/newdir");
    CHECK(call1(DSYS_MKDIR, nd) == 0, "mkdir()");
    struct stat hs;
    CHECK(stat("/tmp/dnt_e2e/newdir", &hs) == 0 && S_ISDIR(hs.st_mode),
          "directory exists on disk");
    uint64_t from = put_string("/newdir");
    uint64_t to = put_string("/renamed");
    CHECK(dnt_syscall(DSYS_RENAME, from, to, 0, 0, 0, 0) == 0, "rename()");
    CHECK(call1(DSYS_RMDIR, to) == 0, "rmdir()");

    /* unimplemented syscalls must still report ENOSYS */
    r = call1(DSYS_FORK, 0);
    CHECK(r == DNT_ENOSYS, "unimplemented syscall -> ENOSYS");

    printf("\n%s (%d failure%s)\n", failures ? "FAILED" : "PASSED",
           failures, failures == 1 ? "" : "s");
    return failures ? 1 : 0;
}
