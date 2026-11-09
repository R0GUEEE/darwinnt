/* Executes the real linked Darwin binaries in tests/fixtures.
 *
 * These were produced by clang + ld64.lld, not hand-assembled bytes, so they
 * are the same kind of file a Mac would run. If this suite passes, a guest
 * program can call write() and exit() through the trap path.
 */
#include "dnt_exec.h"
#include "dnt_cpu.h"
#include "dnt_syscall.h"
#include "dnt_vfs.h"
#include "dnt_abi.h"
#include "dnt_errno.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

static int failures;
#define CHECK(cond, ...) do { \
    if (!(cond)) { printf("FAIL: "); printf(__VA_ARGS__); printf("\n"); failures++; } \
    else { printf("ok: "); printf(__VA_ARGS__); printf("\n"); } \
} while (0)

static int g_exited;
static int g_exit_code;
static void on_exit(int c) { g_exited = 1; g_exit_code = c; }
static void on_unimpl(uint32_t nr, const char *name) { (void)nr; (void)name; }
static const dnt_host_ops *host(void)
{
    static dnt_host_ops ops = { on_exit, NULL, on_unimpl };
    return &ops;
}

/* Guest memory lives at its own addresses here, so register nothing: the
 * weak accessors in dnt_syscall.c check the region table, and the executor
 * registers the image and stack itself. */

static uint8_t *load(const char *path, size_t *len)
{
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    fseek(f, 0, SEEK_SET);
    uint8_t *b = malloc((size_t)n);
    if (b && fread(b, 1, (size_t)n, f) != (size_t)n) { free(b); b = NULL; }
    fclose(f);
    *len = (size_t)n;
    return b;
}

static dnt_exec_result run_fixture(const char *name)
{
    char path[512];
    snprintf(path, sizeof(path), "%s", name);
    size_t len = 0;
    uint8_t *data = load(path, &len);
    dnt_exec_result r;
    memset(&r, 0, sizeof(r));
    if (!data) {
        snprintf(r.detail, sizeof(r.detail), "cannot read %s", path);
        r.error = -999;
        return r;
    }
    dnt_syscall_init(host());
    dnt_exec_image(data, len, "/tmp/dnt_exec_root", 0, &r);
    free(data);
    return r;
}

static int run_and_capture(const char *path, const char *want,
                           int want_exit, int *captured)
{
    /* Redirect stdout to a file so the suite can assert on what the guest
     * printed, not just on its exit code. */
    char tmp[256];
    snprintf(tmp, sizeof(tmp), "/tmp/dnt_capture_%d.txt", (int)getpid());
    FILE *save = stdout;
    (void)save;
    fflush(stdout);
    int saved_fd = dup(1);
    FILE *cap = freopen(tmp, "w", stdout);
    if (!cap) return -1;

    dnt_exec_result r = run_fixture(path);

    fflush(stdout);
    dup2(saved_fd, 1);
    close(saved_fd);

    char buf[512] = {0};
    FILE *in = fopen(tmp, "r");
    if (in) {
        size_t n = fread(buf, 1, sizeof(buf) - 1, in);
        buf[n] = 0;
        fclose(in);
    }
    unlink(tmp);

    int ok = (r.error == 0 || r.halt == DNT_HALT_EXIT);
    printf("  %s: halt=%d exit=%d detail='%s'\n", path, r.halt, r.exit_code, r.detail);
    if (want && strcmp(buf, want) != 0) {
        printf("FAIL: stdout was '%s', want '%s'\n", buf, want);
        failures++;
    }
    if (want_exit >= 0 && r.exit_code != want_exit) {
        printf("FAIL: exit %d, want %d\n", r.exit_code, want_exit);
        failures++;
    }
    if (captured) *captured = ok;
    return ok ? 0 : -1;
}

int main(void)
{
    system("rm -rf /tmp/dnt_exec_root && mkdir -p /tmp/dnt_exec_root");

    /* hello.macho: write(1, "hello\n", 6); exit(0) */
    CHECK(run_and_capture("tests/fixtures/hello.macho", "hello\n", 0, NULL) == 0,
          "hello.macho prints 'hello' and exits 0");

    /* exitcode.macho: exit(42) */
    CHECK(run_and_capture("tests/fixtures/exitcode.macho", "", 42, NULL) == 0,
          "exitcode.macho exits 42");

    /* badsys.macho: fork() -> ENOSYS, then exit(errno) */
    CHECK(run_and_capture("tests/fixtures/badsys.macho", "", 78, NULL) == 0,
          "badsys.macho observes ENOSYS(78) from fork");

    /* A truncated image must be refused, not executed. */
    size_t len = 0;
    uint8_t *data = load("tests/fixtures/hello.macho", &len);
    if (data) {
        dnt_exec_result r;
        dnt_exec_image(data, 200, "/tmp/dnt_exec_root", 0, &r);
        CHECK(r.error != 0, "truncated image refused (%s)", r.detail);
        free(data);
    }

    printf("\n%s (%d failure%s)\n", failures ? "FAILED" : "PASSED",
           failures, failures == 1 ? "" : "s");
    return failures ? 1 : 0;
}
