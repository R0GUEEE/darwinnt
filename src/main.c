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
    fprintf(stderr, "unknown command: %s\n", argv[1]);
    return 1;
}
