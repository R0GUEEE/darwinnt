/* Symbol binding: turns a Darwin import into a callable guest address.
 *
 * A dynamically linked Darwin binary does not call into libSystem directly.
 * The stub at the call site is:
 *
 *     adrp x16, GOT@PAGE
 *     ldr  x16, [x16, GOT@PAGEOFF]
 *     br   x16
 *
 * and the GOT slot initially points at dyld_stub_binder. The first call lands
 * in the binder, which looks the name up, writes the resolved address into the
 * slot, and jumps there. Every later call goes straight through.
 *
 * The resolved address is not a Mach-O address: it points into the
 * interpreter's trampoline page, and the trampoline converts an AAPCS64 call
 * into a Darwin syscall.
 */
#include "dnt_bind.h"
#include "dnt_cpu.h"
#include "dnt_syscall.h"
#include "dnt_abi.h"
#include "dnt_errno.h"
#include "generated/syscalls.h"

#include <stdio.h>
#include <string.h>

typedef struct {
    const char *name;
    uint32_t    syscall;
} dnt_sym;

/* The libSystem surface actually provided. Anything not listed is reported as
 * missing rather than silently returning zero. */
static const dnt_sym g_syms[] = {
    { "write",            DSYS_WRITE },
    { "read",             DSYS_READ },
    { "open",             DSYS_OPEN },
    { "close",            DSYS_SYS_CLOSE },
    { "lseek",            DSYS_LSEEK },
    { "stat",             DSYS_STAT64 },
    { "lstat",            DSYS_LSTAT64 },
    { "fstat",            DSYS_SYS_FSTAT64 },
    { "stat64",           DSYS_STAT64 },
    { "lstat64",          DSYS_LSTAT64 },
    { "fstat64",          DSYS_SYS_FSTAT64 },
    { "unlink",           DSYS_UNLINK },
    { "mkdir",            DSYS_MKDIR },
    { "rmdir",            DSYS_RMDIR },
    { "rename",           DSYS_RENAME },
    { "chdir",            DSYS_SYS_CHDIR },
    { "ftruncate",        DSYS_FTRUNCATE },
    { "access",           DSYS_ACCESS },
    { "fsync",            DSYS_FSYNC },
    { "getdirentries64",  DSYS_GETDIRENTRIES64 },
    { "exit",             DSYS_EXIT },
    { "getpid",           DSYS_GETPID },
    { "getppid",          DSYS_GETPPID },
    { "getuid",           DSYS_GETUID },
    { "geteuid",          DSYS_GETEUID },
    { "getgid",           DSYS_GETGID },
    { "getegid",          DSYS_GETEGID },
};

void dnt_bind_reset(dnt_bind *b)
{
    if (!b)
        return;
    memset(b, 0, sizeof(*b));
    b->ntramps = 0;
}

int dnt_bind_count(dnt_bind *b) { return b ? b->ntramps : 0; }

const char *dnt_bind_name(dnt_bind *b, int idx)
{
    if (!b || idx < 0 || idx >= b->ntramps)
        return NULL;
    return b->names[idx];
}

uint32_t dnt_bind_syscall(dnt_bind *b, int idx)
{
    if (!b || idx < 0 || idx >= b->ntramps)
        return 0;
    return b->nr[idx];
}

/* Install a symbol and return its trampoline address. Idempotent: the same
 * name always maps to the same slot, so two GOT slots importing one function
 * share a trampoline. */
uint64_t dnt_bind_install(dnt_bind *b, const char *name, uint32_t syscall_nr)
{
    for (int i = 0; i < b->ntramps; i++) {
        if (strcmp(b->names[i], name) == 0)
            return b->trampoline_base + (uint64_t)i * DNT_TRAMPOLINE_STRIDE;
    }
    if (b->ntramps >= DNT_MAX_TRAMPS)
        return 0;
    int idx = b->ntramps;
    snprintf(b->names[idx], sizeof(b->names[idx]), "%s", name);
    b->nr[idx] = syscall_nr;
    b->ntramps++;
    return b->trampoline_base + (uint64_t)idx * DNT_TRAMPOLINE_STRIDE;
}

uint64_t dnt_bind_lookup(dnt_bind *b, const char *name)
{
    if (strcmp(name, "dyld_stub_binder") == 0)
        return b->binder_addr;

    for (size_t i = 0; i < sizeof(g_syms) / sizeof(g_syms[0]); i++) {
        if (strcmp(g_syms[i].name, name) == 0)
            return dnt_bind_install(b, name, g_syms[i].syscall);
    }
    return 0;
}

int dnt_bind_trampoline_index(dnt_bind *b, uint64_t addr)
{
    if (!b || b->ntramps == 0 || addr < b->trampoline_base)
        return -1;
    uint64_t off = addr - b->trampoline_base;
    if (off % DNT_TRAMPOLINE_STRIDE)
        return -1;
    uint64_t idx = off / DNT_TRAMPOLINE_STRIDE;
    if (idx >= (uint64_t)b->ntramps)
        return -1;
    return (int)idx;
}

/* Fixup callback: for every import slot the parser found, write the resolved
 * address into the guest slot. Missing symbols are recorded, not ignored. */
typedef struct {
    dnt_bind         *b;
    uint8_t          *mem;
    uint64_t          image_base;
    dnt_bind_report  *rep;
} bind_ctx_t;

static void fixup_cb(void *user, uint64_t slot_addr, const char *sym, int64_t addend)
{
    bind_ctx_t *c = user;
    (void)addend;
    /* Only import slots carry a symbol name; rebases are handled below. */

    /* slot_addr is a host address (the parser was handed the mapped image).
     *
     * The weak/lazy binder slot imports dyld_stub_binder itself; that slot must
     * keep pointing at our binder entry. Every other import resolves to its
     * trampoline, which is what the lazy stub will jump through on the first
     * call. */
    uint64_t resolved = dnt_bind_lookup(c->b, sym);
    if (strcmp(sym, "dyld_stub_binder") == 0)
        resolved = c->b->binder_addr;
    if (!resolved) {
        if (c->rep->nmissing < DNT_MAX_MISSING) {
            snprintf(c->rep->missing[c->rep->nmissing],
                     sizeof(c->rep->missing[0]), "%s", sym);
            c->rep->nmissing++;
        }
        resolved = c->b->binder_addr;   /* leave it pointing at the binder */
    }
    memcpy((void *)(uintptr_t)slot_addr, &resolved, sizeof(resolved));
    c->rep->nbound++;
}

/* Rebase: a pointer stored in the image that points into the image's own
 * file-linked address range must be slid by (mapped_base - link_base). The
 * lazy GOT slots are exactly this: they hold the link-time address of the
 * binder stub, and without the slide they point outside the mapping. */
static void rebase_pass(dnt_image *img, uint8_t *mem, uint64_t mapped_base,
                        uint8_t *mem_end)
{
    uint64_t link_base = img->base_vaddr;
    uint64_t link_end = link_base + img->max_mapped;
    int64_t  slide = (int64_t)(mapped_base - link_base);
    if (slide == 0)
        return;

    for (int s = 0; s < img->nsegs; s++) {
        dnt_seg *seg = &img->segs[s];
        if (seg->filesz < 8)
            continue;
        uint64_t off = seg->vaddr - link_base;
        if (off + seg->filesz > img->max_mapped)
            continue;
        uint8_t *p = mem + off;
        uint8_t *end = p + seg->filesz;
        if (end > mem_end)
            end = mem_end;
        for (; p + 8 <= end; p += 8) {
            uint64_t v;
            memcpy(&v, p, 8);
            if (v >= link_base && v < link_end) {
                v = (uint64_t)((int64_t)v + slide);
                memcpy(p, &v, 8);
            }
        }
    }
}

int dnt_bind_apply(dnt_image *img, uint8_t *mem, dnt_bind *b,
                   dnt_bind_report *rep)
{
    memset(rep, 0, sizeof(*rep));
    bind_ctx_t ctx;
    ctx.b = b;
    ctx.mem = mem;
    ctx.image_base = img->base_vaddr;
    ctx.rep = rep;

    /* Slide self-references first: the GOT slots that hold link-time
     * addresses must be corrected before the binder checks rely on them. */
    rebase_pass(img, mem, (uint64_t)(uintptr_t)mem, mem + img->max_mapped);

    int rc = dnt_macho_apply_fixups(img, mem, fixup_cb, &ctx);
    if (rc != 0)
        rep->unsupported = 1;
    return rc;
}
