/* Windows runtime host services for the Darwin syscall layer.
 *
 * Everything Windows-specific lives behind dnt_host_ops, so the Darwin side
 * (parser, translator, dispatcher) compiles and tests identically on any host.
 */
#ifdef _WIN32

#include "dnt_win.h"
#include "dnt_syscall.h"
#include "dnt_abi.h"
#include "dnt_errno.h"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>

static DWORD g_exit_code = 0;
static volatile LONG g_exiting = 0;
static FILE *g_verbose;

static void win_exit(int code)
{
    /* A guest exit must unwind through Windows' own teardown so atexit-style
     * finalisers the host owns (log flush, handle close) still run. */
    g_exit_code = (DWORD)code;
    InterlockedExchange(&g_exiting, 1);
    if (g_verbose)
        fflush(g_verbose);
    ExitProcess((UINT)code);
}

static void win_gettimeofday(dnt_timeval *tv)
{
    /* Darwin's clock is Unix epoch; Windows FILETIME counts 100ns ticks from
     * 1601-01-01. The 11644473600 second offset is the whole conversion. */
    FILETIME ft;
    GetSystemTimePreciseAsFileTime(&ft);
    ULARGE_INTEGER u;
    u.LowPart = ft.dwLowDateTime;
    u.HighPart = ft.dwHighDateTime;
    uint64_t ticks = u.QuadPart;                 /* 100ns since 1601 */
    uint64_t unix_100ns = ticks - 116444736000000000ull;
    tv->tv_sec = (dnt_time_t)(unix_100ns / 10000000ull);
    tv->tv_usec = (dnt_suseconds_t)((unix_100ns % 10000000ull) / 10ull);
}

static void win_unimplemented(uint32_t nr, const char *name)
{
    static uint8_t seen[1024];
    if (nr < sizeof(seen) && !seen[nr]) {
        seen[nr] = 1;
        fprintf(stderr, "[dnt] syscall %u (%s) not implemented -> ENOSYS\n",
                nr, name ? name : "?");
    }
}

const dnt_host_ops *dnt_win_host_ops(void)
{
    static dnt_host_ops ops = { win_exit, win_gettimeofday, win_unimplemented };
    return &ops;
}

void dnt_win_set_verbose(FILE *f) { g_verbose = f; }
int dnt_win_is_exiting(void) { return g_exiting != 0; }
DWORD dnt_win_exit_code(void) { return g_exit_code; }

#endif /* _WIN32 */
