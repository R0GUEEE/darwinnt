/* Dispatcher tests. The critical property is that the numbers we dispatch on
 * match XNU's table, and that unimplemented calls are *reported* rather than
 * returning a plausible zero. */
#include "dnt_syscall.h"
#include "dnt_errno.h"
#include "generated/syscalls.h"

#include <stdio.h>
#include <string.h>

static int failures;
static int exits, exit_code;
static uint32_t last_unimpl;
static int unimpl_count;

static void on_exit(int code) { exits++; exit_code = code; }
static void on_unimpl(uint32_t nr, const char *name)
{
    (void)name;
    last_unimpl = nr;
    unimpl_count++;
}

#define CHECK(cond, ...) do { \
    if (!(cond)) { printf("FAIL: "); printf(__VA_ARGS__); printf("\n"); failures++; } \
    else { printf("ok: "); printf(__VA_ARGS__); printf("\n"); } \
} while (0)

int main(void)
{
    dnt_host_ops ops = { on_exit, NULL, on_unimpl };
    dnt_syscall_init(&ops);

    /* Numbers must equal the XNU master table, not "whatever libSystem had". */
    CHECK(DSYS_EXIT == 1, "exit == 1");
    CHECK(DSYS_FORK == 2, "fork == 2");
    CHECK(DSYS_READ == 3, "read == 3");
    CHECK(DSYS_WRITE == 4, "write == 4");
    CHECK(DSYS_OPEN == 5, "open == 5");
    CHECK(DSYS_GETPID == 20, "getpid == 20");
    CHECK(DSYS_SIGACTION == 46, "sigaction == 46");
    CHECK(DSYS_SYSCTL == 202, "sysctl == 202");

    CHECK(strcmp(dnt_syscall_name(DSYS_WRITE), "write") == 0, "name(write)");
    CHECK(strcmp(dnt_syscall_name(0), "nosys") == 0, "name(0) == nosys");
    CHECK(strcmp(dnt_syscall_name(99999), "out-of-range") == 0, "name(oob)");

    CHECK(dnt_syscall(DSYS_GETPID, 0,0,0,0,0,0) == 42, "getpid returns a pid");
    CHECK(dnt_syscall(DSYS_GETUID, 0,0,0,0,0,0) == 501, "getuid returns 501");

    /* exit must reach the host, and report the low 8 bits like Darwin */
    exits = 0;
    dnt_syscall(DSYS_EXIT, 300, 0,0,0,0,0);
    CHECK(exits == 1 && exit_code == 300, "exit(300) delivered");
    exits = 0;
    dnt_syscall(DSYS_EXIT, 0x1FF, 0,0,0,0,0);
    CHECK(exits == 1 && exit_code == 0x1FF, "exit(511) delivered unmasked");

    /* an unimplemented call must be logged and return ENOSYS, never 0 */
    unimpl_count = 0;
    uint64_t r = dnt_syscall(DSYS_FORK, 0,0,0,0,0,0);
    CHECK(r == DNT_ENOSYS, "fork -> ENOSYS (%llu)", (unsigned long long)r);
    CHECK(unimpl_count == 1 && last_unimpl == DSYS_FORK, "fork reported to host");

    /* gettimeofday with no host clock must not fabricate a time */
    r = dnt_syscall(DSYS_GETTIMEOFDAY, 0x1000, 0, 0, 0,0,0);
    CHECK(r == DNT_ENOSYS, "gettimeofday without host clock -> ENOSYS");

    /* out-of-range numbers */
    r = dnt_syscall(DSYS_MAX_SYSCALL + 1, 0,0,0,0,0,0);
    CHECK(r == DNT_ENOSYS, "out-of-range number -> ENOSYS");

    printf("\n%s (%d failure%s)\n", failures ? "FAILED" : "PASSED",
           failures, failures == 1 ? "" : "s");
    return failures ? 1 : 0;
}
