/* Tests that the Mach-O parser and both fixup decoders find the correct slot
 * and the correct symbol name in structurally valid Darwin images. */
#include "dnt_macho.h"
#include "dnt_fixture.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static int failures;

#define CHECK(cond, msg) do { \
    if (!(cond)) { printf("FAIL: %s\n", msg); failures++; } \
    else printf("ok: %s\n", msg); \
} while (0)

typedef struct { uint64_t slot; char sym[128]; int hits; } hitrec;

static void on_bind(void *user, uint64_t slot, const char *sym, int64_t addend)
{
    hitrec *h = user;
    (void)addend;
    h->slot = slot;
    snprintf(h->sym, sizeof(h->sym), "%s", sym ? sym : "(null)");
    h->hits++;
}

static void test_chained(const char *sym)
{
    dnt_fixture fx;
    char msg[160];
    if (dnt_fixture_chained(&fx, sym) != 0) { printf("FAIL: fixture alloc\n"); failures++; return; }

    dnt_macho_header_out ho;
    int rc = dnt_macho_header(fx.data, fx.len, &ho);
    snprintf(msg, sizeof(msg), "chained: header accepted (arm64 execute) rc=%d", rc);
    CHECK(rc == 0 && ho.cputype == DNT_CPU_TYPE_ARM64, msg);

    dnt_image img;
    rc = dnt_macho_parse(fx.data, fx.len, &img);
    snprintf(msg, sizeof(msg), "chained: parse rc=%d nsegs=%d (want 2)", rc, img.nsegs);
    CHECK(rc == 0 && img.nsegs == 2, msg);
    CHECK(img.chained_fixups != NULL, "chained: fixups blob located");

    /* The slot lives at __DATA vaddr 0x100001000; image_at_base == __TEXT. */
    uint8_t *image = fx.data; /* reuse file bytes as the "mapped" image */
    hitrec h; memset(&h, 0, sizeof(h));
    int n = dnt_macho_apply_fixups(&img, image + 0 /* __TEXT at fileoff 0 */,
                                   on_bind, &h);
    snprintf(msg, sizeof(msg), "chained: apply rc=%d hits=%d", n, h.hits);
    CHECK(n == 0 && h.hits == 1, msg);
    snprintf(msg, sizeof(msg), "chained: symbol == '%s' (got '%s')", sym, h.sym);
    CHECK(strcmp(h.sym, sym) == 0, msg);
    /* slot address must equal image_base + 0x1000 exactly */
    snprintf(msg, sizeof(msg), "chained: slot addr exact (got 0x%llx want 0x%llx)",
             (unsigned long long)h.slot,
             (unsigned long long)((uintptr_t)image + 0x1000));
    CHECK(h.slot == (uint64_t)(uintptr_t)(image + 0x1000), msg);

    dnt_fixture_free(&fx);
}

static void test_opcodes(const char *sym)
{
    dnt_fixture fx;
    char msg[160];
    if (dnt_fixture_bind_opcodes(&fx, sym) != 0) { printf("FAIL: fixture alloc\n"); failures++; return; }

    dnt_image img;
    int rc = dnt_macho_parse(fx.data, fx.len, &img);
    CHECK(rc == 0, "opcodes: parse ok");
    CHECK(img.has_dyld_info && img.info.bind_size > 0, "opcodes: bind stream present");

    hitrec h; memset(&h, 0, sizeof(h));
    int n = dnt_macho_apply_fixups(&img, fx.data, on_bind, &h);
    snprintf(msg, sizeof(msg), "opcodes: apply rc=%d hits=%d", n, h.hits);
    CHECK(n == 0 && h.hits == 1, msg);
    snprintf(msg, sizeof(msg), "opcodes: symbol == '%s' (got '%s')", sym, h.sym);
    CHECK(strcmp(h.sym, sym) == 0, msg);
    CHECK(h.slot == (uint64_t)(uintptr_t)(fx.data + 0x1000), "opcodes: slot addr exact");

    dnt_fixture_free(&fx);
}

static void test_rejects(void)
{
    uint8_t junk[64];
    memset(junk, 0xAB, sizeof(junk));
    dnt_macho_header_out ho;
    CHECK(dnt_macho_header(junk, sizeof(junk), &ho) == DNT_E_NOTMACHO,
          "reject: garbage is not Mach-O");

    /* Valid magic but sizeofcmds beyond EOF must be caught, not walked. */
    dnt_mach_header_64 mh;
    memset(&mh, 0, sizeof(mh));
    mh.magic = 0xfeedfacf;
    mh.cputype = DNT_CPU_TYPE_ARM64;
    mh.filetype = DNT_MH_EXECUTE;
    mh.ncmds = 1000;
    mh.sizeofcmds = 0x7FFFFFF0;
    CHECK(dnt_macho_header(&mh, sizeof(mh), &ho) == DNT_E_TRUNCATED,
          "reject: oversized sizeofcmds is truncated");

    CHECK(dnt_macho_header(&mh, 7, &ho) == DNT_E_NOTMACHO,
          "reject: short buffer");
}

int main(void)
{
    test_chained("_write");
    test_chained("_malloc");
    test_opcodes("_exit");
    test_opcodes("_objc_msgSend");
    test_rejects();
    printf("\n%s (%d failure%s)\n", failures ? "FAILED" : "PASSED",
           failures, failures == 1 ? "" : "s");
    return failures ? 1 : 0;
}
