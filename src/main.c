/* darwinnt command line.
 *
 *   darwinnt <darwin-binary> [args...]     load and inspect a Mach-O image
 *   darwinnt --info <binary>               dump load commands, fixup stats
 *   darwinnt --translate <darwin-path>     show the host path mapping
 *   darwinnt --test                        run built-in self checks
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "dnt_abi.h"
#include "dnt_macho.h"
#include "dnt_path.h"
#include "dnt_syscall.h"
#include "dnt_vfs.h"
#include "dnt_errno.h"
#include "dnt_abi.h"

#ifdef _WIN32
#include "dnt_win.h"
#define DEFAULT_ROOT "C:\\DarwinRoot"
#else
#define DEFAULT_ROOT ".\\DarwinRoot"
#endif

static uint8_t *read_file(const char *path, size_t *out_len)
{
    FILE *f = fopen(path, "rb");
    if (!f)
        return NULL;
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (n <= 0) { fclose(f); return NULL; }
    uint8_t *buf = malloc((size_t)n);
    if (buf && fread(buf, 1, (size_t)n, f) != (size_t)n) {
        free(buf);
        buf = NULL;
    }
    fclose(f);
    *out_len = (size_t)n;
    return buf;
}

static int cmd_info(const char *path)
{
    size_t len = 0;
    uint8_t *data = read_file(path, &len);
    if (!data) {
        fprintf(stderr, "cannot read %s\n", path);
        return 2;
    }
    dnt_image img;
    int rc = dnt_macho_parse(data, len, &img);
    if (rc != 0) {
        fprintf(stderr, "%s: not a usable Mach-O image (rc=%d)\n", path, rc);
        free(data);
        return 3;
    }
    printf("image:      %s\n", path);
    printf("cputype:    64-bit arm64\n");
    printf("segments:   %d\n", img.nsegs);
    for (int i = 0; i < img.nsegs; i++) {
        printf("  %-16s vm=0x%llx size=0x%llx prot=%d file=0x%llx/0x%llx\n",
               img.segs[i].segname,
               (unsigned long long)img.segs[i].vaddr,
               (unsigned long long)img.segs[i].memsz,
               img.segs[i].initprot,
               (unsigned long long)img.segs[i].fileoff,
               (unsigned long long)img.segs[i].filesz);
    }
    printf("entry:      %s (offset 0x%llx)\n",
           img.has_main ? "LC_MAIN" : "none", (unsigned long long)img.entry_off);
    printf("dylibs:     %d\n", img.ndylibs);
    for (int i = 0; i < img.ndylibs && i < 12; i++)
        printf("  %s\n", img.dylibs[i]);
    if (img.has_dyld_info)
        printf("bind info:  %u bytes (classic opcodes)\n", img.info.bind_size);
    if (img.chained_fixups)
        printf("chained:    %llu bytes\n",
               (unsigned long long)img.chained_fixups_size);
    printf("unusable fixups: %u\n", img.unsupported_fixups);
    free(data);
    return 0;
}

static int cmd_translate(const char *p)
{
    char out[DNT_MAXPATHLEN + 128];
    int rc = dnt_path_translate(DEFAULT_ROOT, p, 1, out, sizeof(out));
    if (rc != DNT_PATH_OK) {
        printf("%s -> error %d\n", p, rc);
        return 1;
    }
    printf("%s -> %s\n", p, out);
    return 0;
}

/* Filesystem smoke test using the real port backend. CI runs this on Windows
 * so the Win32 layer is executed, not just compiled. */
static int self_test_fs(void)
{
    char root[512];
    const char *tmp = getenv("TEMP");
    if (!tmp || !*tmp) tmp = getenv("TMP");
    if (!tmp || !*tmp) tmp = ".";
    snprintf(root, sizeof(root), "%s\\darwinnt-selftest", tmp);

    int fails = 0;
    if (dnt_vfs_init(root) != 0) {
        printf("fs selftest: init failed\n");
        return 1;
    }
    {
        /* Diagnose rather than just fail: show the mapped path and whether
         * its directory exists. A bare errno from a CI-run binary is not
         * actionable when the host path is the actual problem. */
        char mapped[DNT_MAXPATHLEN + 160];
        dnt_path_translate(dnt_vfs_root(), "/tmp/probe.txt", 0, mapped, sizeof(mapped));
        dnt_stat ds;
        int d_rc = dnt_vfs_stat("/private/tmp", &ds, 1);
        printf("fs selftest: root=%s\n  probe=%s\n  /private/tmp stat rc=%d\n",
               dnt_vfs_root(), mapped, d_rc);
    }
    int fd = dnt_vfs_open("/tmp/probe.txt", DNT_O_CREAT | DNT_O_TRUNC | DNT_O_WRONLY, 0644);
    if (fd < 0) { printf("fs selftest: create failed (%d)\n", fd); return 1; }
    int err = 0;
    if (dnt_vfs_write(fd, "hello", 5, &err) != 5) { printf("fs selftest: write failed\n"); fails++; }
    dnt_vfs_close(fd);

    fd = dnt_vfs_open("/tmp/probe.txt", DNT_O_RDONLY, 0);
    char buf[16] = {0};
    int64_t n = dnt_vfs_read(fd, buf, sizeof(buf) - 1, &err);
    if (n != 5 || strcmp(buf, "hello") != 0) { printf("fs selftest: read back '%s'\n", buf); fails++; }
    dnt_vfs_close(fd);

    dnt_stat st;
    if (dnt_vfs_stat("/tmp/probe.txt", &st, 1) != 0 ||
        (st.st_mode & DNT_S_IFMT) != DNT_S_IFREG || st.st_size != 5) {
        printf("fs selftest: stat wrong\n");
        fails++;
    }
    if (dnt_vfs_unlink("/tmp/probe.txt") != 0) { printf("fs selftest: unlink failed\n"); fails++; }
    /* Leave nothing behind: a self-test that litters the tree gets committed
     * by the next `git add -A` and breaks checkout on another platform. */
    dnt_vfs_rmdir("/tmp");
    dnt_vfs_rmdir("/private/tmp");
    dnt_vfs_rmdir("/private/var/tmp");
    dnt_vfs_rmdir("/private/var");
    dnt_vfs_rmdir("/private");
    dnt_vfs_rmdir("/var");
    dnt_vfs_rmdir("/");

    printf("fs selftest: %s\n", fails ? "FAILED" : "ok");
    return fails;
}

static int self_test(void)
{
    /* Minimal assertions so the shipped binary can prove it is sane without
     * the source tree. The full suites live in tests/ and run in CI. */
    char out[DNT_MAXPATHLEN + 128];
    int fails = 0;
    if (dnt_path_translate(DEFAULT_ROOT, "/usr/bin", 0, out, sizeof out) != 0) fails++;
    if (dnt_path_translate(DEFAULT_ROOT, "/..", 0, out, sizeof out) != DNT_PATH_ESCAPE) fails++;
    if (dnt_syscall_name(4) == NULL || strcmp(dnt_syscall_name(4), "write") != 0) fails++;
    printf("self test: %s\n", fails ? "FAILED" : "ok");
    return fails;
}

int main(int argc, char **argv)
{
#ifdef _WIN32
    dnt_syscall_init(dnt_win_host_ops());
#endif
    if (argc < 2) {
        fprintf(stderr,
            "darwinnt -- Darwin/x86-64 userland on Windows\n"
            "usage:\n"
            "  darwinnt --info <mach-o-binary>\n"
            "  darwinnt --translate <darwin-path>\n"
            "  darwinnt --test\n");
        return 1;
    }
    if (strcmp(argv[1], "--info") == 0 && argc > 2)
        return cmd_info(argv[2]);
    if (strcmp(argv[1], "--translate") == 0 && argc > 2)
        return cmd_translate(argv[2]);
    if (strcmp(argv[1], "--test") == 0)
        return self_test();
    if (strcmp(argv[1], "--selftest-fs") == 0)
        return self_test_fs();
    fprintf(stderr, "unknown command: %s\n", argv[1]);
    return 1;
}
