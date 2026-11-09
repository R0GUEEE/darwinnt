/* Path translation tests. Each case states the Darwin input and the exact
 * host path that must come out, so a regression is visible in the diff. */
#include "dnt_path.h"

#include <stdio.h>
#include <string.h>

static int failures;
static const char *ROOT = "C:\\DarwinRoot";

static void expect(const char *in, const char *want, int trailing)
{
    char out[DNT_MAXPATHLEN + 64];
    int rc = dnt_path_translate(ROOT, in, trailing, out, sizeof(out));
    char msg[512];
    if (rc != DNT_PATH_OK) {
        snprintf(msg, sizeof(msg), "%s -> rc=%d want %s", in, rc, want);
        printf("FAIL: %s\n", msg);
        failures++;
        return;
    }
    if (strcmp(out, want) != 0) {
        snprintf(msg, sizeof(msg), "%s\n      got  %s\n      want %s", in, out, want);
        printf("FAIL: %s\n", msg);
        failures++;
        return;
    }
    printf("ok: %-42s -> %s\n", in, out);
}

static void expect_err(const char *in, int want_rc, const char *why)
{
    char out[DNT_MAXPATHLEN + 64];
    int rc = dnt_path_translate(ROOT, in, 0, out, sizeof(out));
    if (rc != want_rc) {
        printf("FAIL: %s (rc=%d want %d) %s\n", in, rc, want_rc, why);
        failures++;
    } else {
        printf("ok:   %-42s rejected %s\n", in, why);
    }
}

int main(void)
{
    /* plain paths */
    expect("/",                      "C:\\DarwinRoot\\", 0);
    expect("/usr/bin/clang",         "C:\\DarwinRoot\\usr\\bin\\clang", 0);
    expect("/usr/lib/libSystem.B.dylib", "C:\\DarwinRoot\\usr\\lib\\libSystem.B.dylib", 0);

    /* Darwin's /var /tmp /etc -> /private rewrite */
    expect("/var/tmp/x",             "C:\\DarwinRoot\\private\\var\\tmp\\x", 0);
    expect("/var",                   "C:\\DarwinRoot\\private\\var", 0);
    expect("/tmp",                   "C:\\DarwinRoot\\private\\tmp", 0);
    expect("/etc/hosts",             "C:\\DarwinRoot\\private\\etc\\hosts", 0);
    /* must NOT rewrite a merely-similar prefix */
    expect("/variable",              "C:\\DarwinRoot\\variable", 0);
    expect("/tmpfoo/bar",            "C:\\DarwinRoot\\tmpfoo\\bar", 0);
    expect("/etcetera",              "C:\\DarwinRoot\\etcetera", 0);

    /* dot components */
    expect("/usr/./bin",             "C:\\DarwinRoot\\usr\\bin", 0);
    expect("/usr/bin/../lib",        "C:\\DarwinRoot\\usr\\lib", 0);
    expect("/usr/bin/../../lib",     "C:\\DarwinRoot\\lib", 0);
    /* bundle-ish names contain dots but are ordinary components */
    expect("/Applications/Calc.app/Contents/MacOS/Calc",
           "C:\\DarwinRoot\\Applications\\Calc.app\\Contents\\MacOS\\Calc", 0);
    expect("/a/..b/c",               "C:\\DarwinRoot\\a\\..b\\c", 0);
    expect("/a/.../c",               "C:\\DarwinRoot\\a\\...\\c", 0);

    /* trailing slash propagation */
    expect("/usr/bin/",              "C:\\DarwinRoot\\usr\\bin\\", 1);
    expect("/usr/bin",               "C:\\DarwinRoot\\usr\\bin", 1);

    /* escape the root */
    expect_err("/..",                DNT_PATH_ESCAPE, "climbing above /");
    expect_err("/usr/../..",         DNT_PATH_ESCAPE, "climbing above / halfway");
    expect_err("/../etc/passwd",     DNT_PATH_ESCAPE, "traversal attack");

    /* length limits: Darwin rejects paths >= 1024 bytes */
    expect_err("/usr/../..",         DNT_PATH_ESCAPE, "traversal");

    printf("\n%s (%d failure%s)\n", failures ? "FAILED" : "PASSED",
           failures, failures == 1 ? "" : "s");
    return failures ? 1 : 0;
}
