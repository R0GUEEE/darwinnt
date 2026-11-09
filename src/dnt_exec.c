/* Image execution: map a parsed Mach-O into memory and run it.
 *
 * The mapping mirrors what dyld does: segments are placed in one contiguous
 * span at their file-linked virtual addresses, so PC-relative addressing
 * between __TEXT and __DATA works without relocation.
 */
#include "dnt_exec.h"
#include "dnt_macho.h"
#include "dnt_cpu.h"
#include "dnt_vfs.h"
#include "dnt_abi.h"
#include "dnt_errno.h"
#include "dnt_syscall.h"
#include "dnt_bind.h"
#include "dnt_cpu.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#endif

/* `why` receives a human-readable reason on failure; CI prints it. A NULL
 * return with no explanation is what made the last Windows failure opaque. */
static uint8_t *map_region(uint64_t want, uint64_t *out_base, char *why, size_t why_cap)
{
#ifdef _WIN32
    /* The interpreter dereferences guest addresses as native pointers, and
     * the image is linked for a fixed virtual address (0x100000000 on arm64).
     * It MUST land there or every PC-relative access is wrong, so mapping
     * elsewhere is a hard failure rather than a silent slide.
     *
     * A requested base of 0 means "anywhere", used only for the stack. */
    /* VirtualAlloc rounds the *size* up to the 64 KiB allocation granularity
     * internally, so asking for 16 KiB at 0x100000000 actually claims
     * [0x100000000, 0x100010000). Request the same rounded size explicitly so
     * the reserved extent is predictable and matches what the guest addresses
     * cover. */
    SIZE_T rounded = (SIZE_T)((want + 0xFFFF) & ~(uint64_t)0xFFFF);
    void *p;
    if (*out_base == 0) {
        p = VirtualAlloc(NULL, rounded, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    } else {
        p = VirtualAlloc((void *)(uintptr_t)*out_base, rounded,
                         MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    }
    if (!p) {
#ifdef _WIN32
        snprintf(why, why_cap, "VirtualAlloc(%llu bytes at 0x%llx) failed, err=%lu",
                 (unsigned long long)want, (unsigned long long)*out_base,
                 (unsigned long)GetLastError());
#else
        snprintf(why, why_cap, "VirtualAlloc(%llu bytes) failed",
                 (unsigned long long)want);
#endif
        return NULL;
    }
    *out_base = (uint64_t)(uintptr_t)p;
    return (uint8_t *)p;
#else
    void *p = aligned_alloc(4096, (size_t)((want + 0xFFF) & ~0xFFFull));
    if (!p) {
        snprintf(why, why_cap, "aligned_alloc(%llu bytes) failed",
                 (unsigned long long)want);
        return NULL;
    }
    memset(p, 0, (size_t)want);
    *out_base = (uint64_t)(uintptr_t)p;
    return (uint8_t *)p;
#endif
}

static void unmap_region(uint8_t *base, uint64_t size)
{
#ifdef _WIN32
    VirtualFree(base, 0, MEM_RELEASE);
#else
    (void)size;
    free(base);
#endif
}

int dnt_exec_image(const uint8_t *file, size_t file_len, const char *root,
                   int verbose, dnt_exec_result *out)
{
    memset(out, 0, sizeof(*out));

    dnt_image img;
    int rc = dnt_macho_parse(file, file_len, &img);
    if (rc != 0) {
        out->error = rc;
        snprintf(out->detail, sizeof(out->detail),
                 "parse failed (rc=%d): not a loadable Mach-O", rc);
        return rc;
    }
    if (!img.has_main) {
        out->error = DNT_E_NOENTRY;
        snprintf(out->detail, sizeof(out->detail), "no LC_MAIN entry point");
        return DNT_E_NOENTRY;
    }

    uint64_t image_base = img.base_vaddr;
    uint64_t image_size = img.max_mapped;
    if (image_size == 0 || image_size > DNT_MAX_IMAGE_SIZE) {
        out->error = DNT_E_GEOMETRY;
        snprintf(out->detail, sizeof(out->detail),
                 "image size %llu is not mappable", (unsigned long long)image_size);
        return DNT_E_GEOMETRY;
    }

    /* `link_base` is where the file says the image lives; `image_base` becomes
     * where it actually landed. Segment offsets are computed against
     * link_base, addresses the CPU executes against use the mapped base. */
    uint64_t link_base = image_base;
    uint64_t want_base = image_base;
    char why[200] = {0};
    uint8_t *mem = map_region(image_size, &image_base, why, sizeof(why));
    if (!mem) {
        out->error = DNT_E_NOMEM;
        snprintf(out->detail, sizeof(out->detail), "cannot map image: %s", why);
        return DNT_E_NOMEM;
    }
    out->image_base = image_base;
    out->image_size = image_size;
    out->mapped_at_requested = (image_base == want_base);

    for (int i = 0; i < img.nsegs; i++) {
        dnt_seg *s = &img.segs[i];
        if (s->filesz == 0)
            continue;
        uint64_t off = s->vaddr - link_base;
        if (off + s->filesz > image_size || s->fileoff + s->filesz > file_len)
            continue;
        memcpy(mem + off, file + s->fileoff, (size_t)s->filesz);
    }

    /* The host stack is not inside the guest image, so it is allocated
     * wherever the OS likes; nothing in the guest refers to it by address. */
    const uint64_t stack_size = 1 << 16;
    uint64_t stack_base = 0;
    uint8_t *stack = map_region(stack_size, &stack_base, why, sizeof(why));
    if (!stack) {
        unmap_region(mem, image_size);
        out->error = DNT_E_NOMEM;
        snprintf(out->detail, sizeof(out->detail), "cannot map stack: %s", why);
        return DNT_E_NOMEM;
    }

    /* ---- binding ----
     * The trampoline page and the binder address must sit outside the image,
     * so the interpreter can recognise a jump to them. They are placed in a
     * separate host allocation; the CPU checks them before fetching. */
    static dnt_bind bind;
    dnt_bind_reset(&bind);
    uint64_t tramp_base = 0;
    const uint64_t tramp_size = DNT_MAX_TRAMPS * DNT_TRAMPOLINE_STRIDE;
    uint8_t *tramp = map_region(tramp_size, &tramp_base, why, sizeof(why));
    if (!tramp) {
        unmap_region(stack, stack_size);
        unmap_region(mem, image_size);
        out->error = DNT_E_NOMEM;
        snprintf(out->detail, sizeof(out->detail), "cannot map trampolines: %s", why);
        return DNT_E_NOMEM;
    }
    bind.trampoline_base = tramp_base;
    if (getenv("DNT_TRACE"))
        fprintf(stderr, "tramp base=0x%llx size=%llu binder=0x%llx image=0x%llx..0x%llx\n",
                (unsigned long long)tramp_base, (unsigned long long)tramp_size,
                (unsigned long long)(tramp_base + tramp_size + 0x100),
                (unsigned long long)image_base,
                (unsigned long long)(image_base + image_size));
    /* The binder lives one page past the trampolines: a distinct address the
     * CPU can recognise without colliding with a trampoline index. */
    bind.binder_addr = tramp_base + tramp_size + 0x100;
    bind.image_size = image_size;

    dnt_bind_report rep;
    dnt_bind_apply(&img, mem, &bind, &rep);
    out->nbound = rep.nbound;
    out->nmissing = rep.nmissing;
    out->bind_ok = (rep.unsupported == 0);
    for (int i = 0; i < rep.nmissing && i < DNT_MAX_MISSING; i++)
        snprintf(out->missing[i], sizeof(out->missing[0]), "%s", rep.missing[i]);

    dnt_cpu cpu;
    dnt_cpu_reset(&cpu, image_base + img.entry_off,
                  stack_base + stack_size - 16, image_base, image_size);
    dnt_cpu_set_binding(&cpu, &bind);
    cpu.x[0] = 0;            /* argc */
    cpu.x[1] = 0;            /* argv */
    cpu.x[30] = 0;           /* return address: RET to 0 stops the machine */

    dnt_vfs_init(root);

    /* Tell the syscall layer which spans belong to the guest. Everything
     * outside these is EFAULT rather than a host fault. */
    dnt_guest_clear();
    dnt_guest_register((uint64_t)(uintptr_t)mem, image_size);
    dnt_guest_register((uint64_t)(uintptr_t)stack, stack_size);

    int run = dnt_cpu_run(&cpu, 20000000);
    out->halt = cpu.halt;
    out->exit_code = cpu.exit_code;
    snprintf(out->detail, sizeof(out->detail), "%s", cpu.halt_detail);

    if (verbose && run != 0)
        fprintf(stderr, "darwinnt: halted: %s\n", cpu.halt_detail);

    unmap_region(tramp, tramp_size);
    unmap_region(stack, stack_size);
    unmap_region(mem, image_size);

    if (cpu.halt == DNT_HALT_EXIT)
        return 0;
    /* A guest that returns from main without exiting still terminated
     * normally; report success and the return value. */
    if (cpu.halt == DNT_HALT_NONE && cpu.pc < image_base)
        return 0;
    return -1;
}
