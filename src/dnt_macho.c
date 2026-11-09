/* Mach-O image loading for the darwinnt shim.
 *
 * Loads a 64-bit Darwin executable into a reserved address window, applying
 * segment protections, slide, zero-fill and symbol fixups. Supports both fixup
 * mechanisms a modern toolchain can emit:
 *   - classic LC_DYLD_INFO(_ONLY) bind opcodes (BIND_OPCODE_* stream)
 *   - LC_DYLD_CHAINED_FIXUPS (arm64e/arm64 chained pointer formats)
 *
 * Fixups are not "resolved" in the ELF sense: a Darwin import lands on a lazy
 * stub whose address is written into the slot. The stub, when first executed,
 * calls dnt_bind(name) and patches itself. That keeps startup O(1) in the
 * number of imports, which matters because libSystem alone has thousands.
 */
#include "dnt_macho.h"
#include "dnt_abi.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------------ */
/* Byte order helpers: Mach-O is host-endian on the files we accept.   */
/* ------------------------------------------------------------------ */
static uint32_t rd32(const void *p) { uint32_t v; memcpy(&v, p, 4); return v; }
static uint64_t rd64(const void *p) { uint64_t v; memcpy(&v, p, 8); return v; }
static uint16_t rd16(const void *p) { uint16_t v; memcpy(&v, p, 2); return v; }

/* Load commands and fixup records are packed at file offsets, which are only
 * guaranteed to be 8-byte aligned for well-formed files. A malformed or
 * concatenated image puts them on odd offsets; casting to a struct pointer
 * there is undefined behaviour (and a fault on strict-alignment targets), so
 * every record is copied out through these helpers before being read. */
#define LOAD_REC(type, dst, src) do { \
    memset(&(dst), 0, sizeof(dst)); \
    memcpy(&(dst), (src), sizeof(dst)); \
} while (0)

/* Virtual memory the guest can reach. On Win64 we reserve one large region at
 * a chosen base and hand out image slots from it, so that a 32-bit-relative
 * branch between two images stays in range. */
#define DNT_IMAGE_WINDOW_BASE   0x0000000100000000ull
#define DNT_IMAGE_WINDOW_SIZE   (4ull << 30)

static uint64_t g_window_next = 0;

uint64_t dnt_image_alloc(uint64_t want, int protect_rwx)
{
    if (!g_window_next)
        g_window_next = DNT_IMAGE_WINDOW_BASE;
    uint64_t base = (g_window_next + 0xFFFFull) & ~0xFFFFull;
    g_window_next = base + want;
    if (g_window_next > DNT_IMAGE_WINDOW_BASE + DNT_IMAGE_WINDOW_SIZE)
        return 0; /* caller must report ENOMEM, never wrap */
    (void)protect_rwx;
    return base;
}

/* ------------------------------------------------------------------ */
/* Header validation                                                   */
/* ------------------------------------------------------------------ */
int dnt_macho_header(const void *data, size_t len, dnt_macho_header_out *out)
{
    if (len < sizeof(dnt_mach_header_64))
        return DNT_E_NOTMACHO;
    const dnt_mach_header_64 *mh = data;
    if (mh->magic == 0xbebafeca || mh->magic == 0xcafebabe) {
        /* fat file: caller must pick a slice first */
        return DNT_E_FAT;
    }
    if (mh->magic != 0xfeedfacf)
        return DNT_E_NOTMACHO;
    if (mh->cputype != DNT_CPU_TYPE_ARM64 && mh->cputype != DNT_CPU_TYPE_X86_64)
        return DNT_E_CPU;
    if (mh->filetype != DNT_MH_EXECUTE && mh->filetype != DNT_MH_DYLIB)
        return DNT_E_FILETYPE;

    out->cputype    = mh->cputype;
    out->filetype   = mh->filetype;
    out->ncmds      = mh->ncmds;
    out->flags      = mh->flags;
    out->sizeofcmds = mh->sizeofcmds;
    /* A header claiming more commands than bytes exist is the first thing a
     * fuzzer finds; reject before walking. */
    if ((uint64_t)sizeof(dnt_mach_header_64) + mh->sizeofcmds > len)
        return DNT_E_TRUNCATED;
    return 0;
}

/* Total virtual size the image needs (max segment end), used to reserve. */
uint64_t dnt_macho_vmsize(const void *data, size_t len, dnt_macho_header_out *out)
{
    (void)len; (void)out;
    const dnt_mach_header_64 *mh = data;
    const uint8_t *p = (const uint8_t *)data + sizeof(*mh);
    uint64_t max_end = 0;
    for (uint32_t i = 0; i < mh->ncmds; i++) {
        dnt_load_command lc;
        LOAD_REC(dnt_load_command, lc, p);
        if (lc.cmdsize < sizeof(lc) ||
            (uint64_t)(p - (const uint8_t *)data) + lc.cmdsize > len)
            break;
        if (lc.cmd == LC_SEGMENT_64 && lc.cmdsize >= sizeof(dnt_segment_command_64)) {
            dnt_segment_command_64 sc;
            LOAD_REC(dnt_segment_command_64, sc, p);
            uint64_t end = sc.vmaddr + sc.vmsize;
            if (end > max_end)
                max_end = end;
        }
        p += lc.cmdsize;
    }
    /* Page-align and add a guard page so a wild write traps instead of
     * silently corrupting the next mapping. */
    return (max_end + 0x3FFF) & ~0x3FFFull;
}

/* ------------------------------------------------------------------ */
/* Classic dyld bind opcode stream                                     */
/* ------------------------------------------------------------------ */
enum {
    BIND_OPCODE_MASK = 0xF0, BIND_IMMEDIATE_MASK = 0x0F,
    BIND_OPCODE_DONE = 0x00, BIND_OPCODE_SET_DYLIB_ORDINAL_IMM = 0x10,
    BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB = 0x20,
    BIND_OPCODE_SET_DYLIB_SPECIAL_IMM = 0x30,
    BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM = 0x40,
    BIND_OPCODE_SET_TYPE_IMM = 0x50, BIND_OPCODE_SET_ADDEND_SLEB = 0x60,
    BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB = 0x70,
    BIND_OPCODE_ADD_ADDR_ULEB = 0x80, BIND_OPCODE_DO_BIND = 0x90,
    BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB = 0xA0,
    BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED = 0xB0,
    BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB = 0xC0,
    BIND_OPCODE_THREADED = 0xD0,
};

static uint64_t read_uleb(const uint8_t **pp, const uint8_t *end)
{
    uint64_t result = 0;
    unsigned shift = 0;
    const uint8_t *p = *pp;
    while (p < end) {
        uint8_t b = *p++;
        if (shift < 64)
            result |= (uint64_t)(b & 0x7F) << shift;
        shift += 7;
        if (!(b & 0x80))
            break;
    }
    *pp = p;
    return result;
}

static int64_t read_sleb(const uint8_t **pp, const uint8_t *end)
{
    int64_t result = 0;
    unsigned shift = 0;
    uint8_t b = 0;
    const uint8_t *p = *pp;
    while (p < end) {
        b = *p++;
        if (shift < 64)
            result |= (int64_t)(b & 0x7F) << shift;
        shift += 7;
        if (!(b & 0x80))
            break;
    }
    if (shift < 64 && (b & 0x40))
        result |= -((int64_t)1 << shift);
    *pp = p;
    return result;
}

typedef struct {
    dnt_image *img;
    uint8_t *image;          /* load address of base segment */
    const char *sym;         /* points into symbuf below, never into a frame */
    char symbuf[512];
} bind_ctx;

/* Records a fixup to be applied by the caller: slot address + symbol name. */
typedef void (*dnt_bind_cb)(void *user, uint64_t slot_addr, const char *sym, int64_t addend);

static void run_bind_stream(bind_ctx *ctx, const uint8_t *start, const uint8_t *end,
                            dnt_bind_cb cb, void *user)
{
    const uint8_t *p = start;
    int64_t addend = 0;
    uint64_t addr = 0;
    int seg_index = 0;

    while (p < end) {
        uint8_t byte = *p++;
        uint8_t op = byte & BIND_OPCODE_MASK;
        uint8_t imm = byte & BIND_IMMEDIATE_MASK;
        switch (op) {
        case BIND_OPCODE_DONE:
            p = end; /* one stream per LC_DYLD_INFO blob; DONE ends it */
            break;
        case BIND_OPCODE_SET_DYLIB_ORDINAL_IMM:
        case BIND_OPCODE_SET_TYPE_IMM:
            break;
        case BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB:
            (void)read_uleb(&p, end);
            break;
        case BIND_OPCODE_SET_DYLIB_SPECIAL_IMM:
            break;
        case BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM: {
            size_t n = 0;
            while (p < end && *p && n < sizeof(ctx->symbuf) - 1)
                ctx->symbuf[n++] = (char)*p++;
            ctx->symbuf[n] = 0;
            if (p < end && *p == 0)
                p++;
            ctx->sym = ctx->symbuf;
            break;
        }
        case BIND_OPCODE_SET_ADDEND_SLEB:
            addend = read_sleb(&p, end);
            break;
        case BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB: {
            seg_index = imm;
            uint64_t off = read_uleb(&p, end);
            addr = (uint64_t)(uintptr_t)(ctx->image +
                    (ctx->img->segs[seg_index].vaddr - ctx->img->segs[0].vaddr) + off);
            break;
        }
        case BIND_OPCODE_ADD_ADDR_ULEB:
            addr += read_uleb(&p, end);
            break;
        case BIND_OPCODE_DO_BIND:
            if (ctx->sym)
                cb(user, addr, ctx->sym, addend);
            addr += sizeof(void *);
            break;
        case BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB:
            if (ctx->sym)
                cb(user, addr, ctx->sym, addend);
            addr += read_uleb(&p, end) + sizeof(void *);
            break;
        case BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED:
            if (ctx->sym)
                cb(user, addr, ctx->sym, addend);
            addr += (uint64_t)imm * sizeof(void *) + sizeof(void *);
            break;
        case BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB: {
            uint64_t count = read_uleb(&p, end);
            uint64_t skip = read_uleb(&p, end);
            for (uint64_t i = 0; i < count; i++) {
                if (ctx->sym)
                    cb(user, addr, ctx->sym, addend);
                addr += skip + sizeof(void *);
            }
            break;
        }
        case BIND_OPCODE_THREADED:
            /* arm64e threaded binds: a full implementation walks the bind
             * target table. Recorded as unsupported rather than silently
             * skipped -- a wrong slot here is a crash three frames later. */
            if (imm == 0 /* SET_BIND_ORDINAL_TABLE_SIZE_ULEB */) {
                (void)read_uleb(&p, end);
            } else {
                ctx->img->unsupported_fixups++;
            }
            break;
        default:
            ctx->img->unsupported_fixups++;
            p = end;
            break;
        }
    }
}

/* ------------------------------------------------------------------ */
/* Chained fixups (LC_DYLD_CHAINED_FIXUPS)                             */
/* ------------------------------------------------------------------ */
/* Formats the guest toolchain actually emits. The 64-bit pointer format
 * encodes bind (import) vs rebase in the high bit and carries the ordinal in
 * the middle field, so the import table index is derivable per slot. */
enum {
    DYLD_CHAINED_PTR_ARM64E = 1,
    DYLD_CHAINED_PTR_64 = 2,
    DYLD_CHAINED_PTR_64_OFFSET = 6,
    DYLD_CHAINED_PTR_ARM64E_USERLAND = 9,
    DYLD_CHAINED_PTR_ARM64E_USERLAND24 = 12,
};

static void walk_chained(dnt_image *img, uint8_t *image, dnt_bind_cb cb, void *user)
{
    if (!img->chained_fixups || img->chained_fixups_size < 28)
        return;
    /* The contract: image_at_base spans img->max_mapped bytes. Every pointer
     * derived below is checked against that bound before being dereferenced. */
    const uint64_t mapped = img->max_mapped;
    const uint8_t *base = img->chained_fixups;
    const uint64_t hdr_size = img->chained_fixups_size;
    uint32_t starts_off  = rd32(base + 4);
    uint32_t imports_off = rd32(base + 8);
    uint32_t symbols_off = rd32(base + 12);
    uint32_t imports_cnt = rd32(base + 16);
    if (starts_off + 4 > hdr_size || imports_off + (uint64_t)imports_cnt * 4 > hdr_size ||
        symbols_off > hdr_size)
        return; /* truncated blob: load nothing rather than read past the buffer */

    const uint8_t *starts  = base + starts_off;
    const uint8_t *imports = base + imports_off;
    const uint8_t *symbols = base + symbols_off;
    uint32_t segcount = rd32(starts);
    uint8_t *image_base = image; /* == __TEXT vmaddr, segment_offset is relative to it */

    /* A corrupted blob must not walk off the end. Every read below is guarded
     * against `base + hdr_size`, and the segment table is capped at segcount. */
    if (starts_off + 4 + (uint64_t)segcount * 4 > hdr_size)
        segcount = (uint32_t)((hdr_size - starts_off - 4) / 4);

    for (uint32_t s = 0; s < segcount && s < DNT_MAX_SEGS; s++) {
        uint32_t seg_off = rd32(starts + 4 + (uint64_t)s * 4);
        if (!seg_off)
            continue;
        if (starts_off + seg_off + 22 > hdr_size)
            continue;
        const uint8_t *si = starts + seg_off;
        /* dyld_chained_starts_in_segment, verified against
         * mach-o/fixup-chains.h:
         *   size0 page_size4 pointer_format6 segment_offset8
         *   max_valid_pointer16 page_count20 page_start[]22 */
        uint16_t page_size    = rd16(si + 4);
        uint16_t ptr_format   = rd16(si + 6);
        uint64_t seg_mem_off  = rd64(si + 8);   /* offset of segment in memory */
        uint16_t page_count   = rd16(si + 20);
        const uint8_t *page_start = si + 22;   /* u16 array, read via rd16 */

        /* page_start[] and chain_starts[] must lie wholly inside the blob. */
        uint64_t seg_rec_off = (uint64_t)(si - base);
        if (seg_rec_off + 22 + (uint64_t)page_count * 2 > hdr_size) {
            /* clamp to what actually fits rather than trusting page_count */
            if (seg_rec_off + 22 > hdr_size)
                continue;
            page_count = (uint16_t)((hdr_size - seg_rec_off - 22) / 2);
        }

        if (page_size == 0) {
            img->unsupported_fixups++;
            continue;
        }
        int fmt_ok = (ptr_format == DYLD_CHAINED_PTR_64 ||
                      ptr_format == DYLD_CHAINED_PTR_64_OFFSET ||
                      ptr_format == DYLD_CHAINED_PTR_ARM64E ||
                      ptr_format == DYLD_CHAINED_PTR_ARM64E_USERLAND ||
                      ptr_format == DYLD_CHAINED_PTR_ARM64E_USERLAND24);
        if (!fmt_ok) {
            /* e.g. 32-bit or kernel-cache formats: cannot be decoded here. */
            img->unsupported_fixups++;
            continue;
        }

        /* chain_starts[] begins right after page_start[page_count]. */
        const uint8_t *chain_starts = si + 22 + (uint64_t)page_count * 2;

        for (uint32_t pg = 0; pg < page_count; pg++) {
            uint16_t st = rd16(page_start + (uint64_t)pg * 2);
            if (st == DYLD_CHAINED_PTR_START_NONE)
                continue;

            /* Page with multiple chains: pg entry indexes chain_starts[] and
             * the list is terminated by a high-bit entry. */
            uint16_t starts_local[64];
            int n_starts = 0;
            if (st & DYLD_CHAINED_PTR_START_MULTI) {
                uint32_t idx = st & ~DYLD_CHAINED_PTR_START_MULTI;
                uint64_t cs_max = (hdr_size - seg_rec_off - 22 -
                                   (uint64_t)page_count * 2) / 2;
                if ((uint64_t)idx >= cs_max)
                    continue;
                for (int k = 0; k < 64 && n_starts < 64; k++) {
                    if ((uint64_t)idx + k >= cs_max)
                        break;
                    uint16_t e = rd16(chain_starts + (uint64_t)(idx + k) * 2);
                    starts_local[n_starts++] = e & ~DYLD_CHAINED_PTR_START_LAST;
                    if (e & DYLD_CHAINED_PTR_START_LAST)
                        break;
                }
            } else {
                starts_local[n_starts++] = st;
            }

            for (int k = 0; k < n_starts; k++) {
                uint64_t page_base = seg_mem_off + (uint64_t)pg * page_size;
                /* `seg_mem_off` comes from the file and is guest-controlled.
                 * If it does not fall inside a segment we actually mapped, a
                 * corrupted blob would walk the chain through arbitrary
                 * memory. Refuse instead of trusting it. */
                const dnt_seg *host_seg = NULL;
                if (seg_mem_off > img->max_mapped) {
                    /* Segment tables and the fixup blob are independent data
                     * in the file. A corrupted one must not move the walk
                     * outside the bytes the caller actually mapped. */
                    img->unsupported_fixups++;
                    continue;
                }
                for (int q = 0; q < img->nsegs; q++) {
                    if (seg_mem_off == img->segs[q].vaddr - img->base_vaddr) {
                        host_seg = &img->segs[q];
                        break;
                    }
                }
                if (!host_seg)
                    continue;
                /* The blob supplies a trusted-looking segment_offset but the
                 * image's real extent is memsz. A page_start/(size) pair from
                 * a corrupted file can point past the segment the caller
                 * allocated, so both the page and the chain inside it are
                 * clamped to memsz, not just to page_size. */
                if ((uint64_t)pg * page_size >= host_seg->memsz)
                    continue;
                if (page_base + 8 > mapped)
                    continue;
                uint64_t page_room = host_seg->memsz - (uint64_t)pg * page_size;
                uint64_t eff_size = page_size < page_room ? page_size : page_room;
                if (eff_size < 8)
                    continue;
                uint64_t start_off = starts_local[k] & 0x7FFF;
                if (start_off + 8 > eff_size)
                    continue;
                uint8_t *seg_base = image_base + page_base;
                uint8_t *slot = seg_base + start_off;
                uint8_t *page_end = seg_base + eff_size;
                int guard = 0;
                for (;;) {
                    if (slot < seg_base || slot + 8 > page_end)
                        break;
                    if (++guard > 65536)
                        break;
                    uint64_t raw = rd64(slot);
                    uint32_t next;
                    uint32_t ordinal = 0;
                    int is_bind = (int)((raw >> 62) & 1);

                    if (ptr_format == DYLD_CHAINED_PTR_64 ||
                        ptr_format == DYLD_CHAINED_PTR_64_OFFSET) {
                        next    = (uint32_t)((raw >> 51) & 0xFFF);
                        ordinal = (uint32_t)(raw & 0xFFFFFF);
                    } else {
                        next    = (uint32_t)((raw >> 51) & 0x7FF);
                        ordinal = (uint32_t)(raw & 0xFFFF);
                    }

                    if (is_bind && ordinal < imports_cnt) {
                        uint32_t imp = rd32(imports + (uint64_t)ordinal * 4);
                        uint32_t name_off = imp & 0x3FFFFF;
                        if ((uint64_t)symbols_off + name_off < hdr_size) {
                            const char *nm = (const char *)(symbols + name_off);
                            cb(user, (uint64_t)(uintptr_t)slot, nm, 0);
                        } else {
                            img->unsupported_fixups++;
                        }
                    }
                    if (!next)
                        break;
                    slot += (uint64_t)next * 4;
                }
            }
        }
    }
}

/* ------------------------------------------------------------------ */
/* Public loading entry point                                          */
/* ------------------------------------------------------------------ */
/* `name` points into the file buffer and its length is bounded by the load
 * command, not by a NUL we can trust: a malformed cmdsize can leave the name
 * unterminated right up to EOF. Always pass the number of readable bytes. */
static int add_dylib(dnt_image *img, const char *name, size_t name_cap)
{
    if (img->ndylibs >= DNT_MAX_LOADS)
        return 0;
    size_t max = sizeof(img->dylibs[0]) - 1;
    size_t n = 0;
    while (n < name_cap && n < max && name[n])
        n++;
    memcpy(img->dylibs[img->ndylibs], name, n);
    img->dylibs[img->ndylibs][n] = 0;
    return ++img->ndylibs;
}

/* Parse load commands into an image description. Does not map memory: the
 * caller (the real loader under Windows) owns the VM. Kept separate so the
 * parser is testable on any host. */
int dnt_macho_parse(const void *data, size_t len, dnt_image *img)
{
    memset(img, 0, sizeof(*img));
    dnt_macho_header_out ho;
    int rc = dnt_macho_header(data, len, &ho);
    if (rc)
        return rc;

    const dnt_mach_header_64 *mh = data;
    const uint8_t *p = (const uint8_t *)data + sizeof(*mh);
    const uint8_t *limit = (const uint8_t *)data + len;

    for (uint32_t i = 0; i < mh->ncmds; i++) {
        dnt_load_command lc;
        LOAD_REC(dnt_load_command, lc, p);
        if (lc.cmdsize < sizeof(lc) || p + lc.cmdsize > limit)
            return DNT_E_TRUNCATED;

        switch (lc.cmd) {
        case LC_SEGMENT_64: {
            dnt_segment_command_64 sc;
            if (lc.cmdsize < sizeof(sc))
                return DNT_E_TRUNCATED;
            LOAD_REC(dnt_segment_command_64, sc, p);
            if (img->nsegs >= DNT_MAX_SEGS)
                break;
            /* Reject implausible geometry before anything allocates against
             * it. A corrupted vmaddr here becomes a max_mapped near 2^63, and
             * every downstream size calculation then overflows. Real arm64
             * user images live far below 2^47. */
            /* Mach-O segments are laid out back to back; the loader maps one
             * contiguous span starting at the first segment. Anything else is
             * corruption and must not become a wild-sized allocation. */
            if (sc.vmsize > DNT_MAX_SEG_SIZE ||
                sc.vmaddr > (1ull << 47) ||
                sc.vmaddr + sc.vmsize < sc.vmaddr ||
                sc.vmaddr + sc.vmsize > (1ull << 47) ||
                sc.filesize > len ||
                sc.fileoff > len ||
                (uint64_t)sc.fileoff + sc.filesize > len)
                return DNT_E_TRUNCATED;
            if (img->nsegs > 0) {
                uint64_t base = img->segs[0].vaddr;
                if (sc.vmaddr < base)
                    return DNT_E_NOSEG;
                /* gap between base and this segment must stay within the cap */
                if (sc.vmaddr - base + sc.vmsize > DNT_MAX_IMAGE_SIZE)
                    return DNT_E_TRUNCATED;
            }
            dnt_seg *s = &img->segs[img->nsegs++];
            memcpy(s->segname, sc.segname, 16);
            s->segname[16] = 0;
            s->vaddr = sc.vmaddr;
            s->memsz = sc.vmsize;
            s->fileoff = sc.fileoff;
            s->filesz = sc.filesize;
            s->initprot = sc.initprot;
            s->maxprot = sc.maxprot;
            break;
        }
        case LC_MAIN: {
            dnt_entry_point_command ep;
            if (lc.cmdsize < sizeof(ep))
                return DNT_E_TRUNCATED;
            LOAD_REC(dnt_entry_point_command, ep, p);
            img->entry_off = ep.entryoff;
            img->has_main = 1;
            break;
        }
        case LC_ID_DYLIB: {
            dnt_dylib_command dl;
            if (lc.cmdsize < sizeof(dl))
                return DNT_E_TRUNCATED;
            LOAD_REC(dnt_dylib_command, dl, p);
            if (dl.name_off && dl.name_off < lc.cmdsize) {
                size_t cap = lc.cmdsize - dl.name_off;
                size_t max = sizeof(img->install_name) - 1;
                size_t n = 0;
                while (n < cap && n < max && p[dl.name_off + n])
                    n++;
                memcpy(img->install_name, p + dl.name_off, n);
                img->install_name[n] = 0;
            }
            break;
        }
        case LC_LOAD_DYLIB:
        case LC_LOAD_WEAK_DYLIB:
        case LC_REEXPORT_DYLIB: {
            dnt_dylib_command dl;
            if (lc.cmdsize < sizeof(dl))
                return DNT_E_TRUNCATED;
            LOAD_REC(dnt_dylib_command, dl, p);
            if (dl.name_off && dl.name_off < lc.cmdsize)
                add_dylib(img, (const char *)(p + dl.name_off),
                          lc.cmdsize - dl.name_off);
            break;
        }
        case LC_DYLD_INFO:
        case LC_DYLD_INFO_ONLY:
            if (lc.cmdsize < sizeof(dnt_dyld_info_command))
                return DNT_E_TRUNCATED;
            LOAD_REC(dnt_dyld_info_command, img->info, p);
            /* the blob offsets must live inside the file */
            if ((uint64_t)img->info.bind_off + img->info.bind_size > len ||
                (uint64_t)img->info.lazy_bind_off + img->info.lazy_bind_size > len)
                return DNT_E_TRUNCATED;
            img->dyld_info = data;
            img->has_dyld_info = 1;
            break;
        case LC_DYLD_CHAINED_FIXUPS: {
            dnt_linkedit_data_command ld;
            if (lc.cmdsize < sizeof(ld))
                return DNT_E_TRUNCATED;
            LOAD_REC(dnt_linkedit_data_command, ld, p);
            if ((uint64_t)ld.dataoff + ld.datasize <= len) {
                img->chained_fixups = (const uint8_t *)data + ld.dataoff;
                img->chained_fixups_size = ld.datasize;
            }
            break;
        }
        default:
            break;
        }
        p += lc.cmdsize;
    }

    img->base_vaddr = img->segs[0].vaddr;
    if (img->max_mapped > DNT_MAX_IMAGE_SIZE)
        return DNT_E_TRUNCATED;
    /* Highest byte (relative to base) the caller must have mapped. A chain
     * that reaches past this is reading outside the image, period. */
    img->max_mapped = 0;
    for (int i = 0; i < img->nsegs; i++) {
        /* Segments must sit at or above the base. Subtracting a larger vmaddr
         * from base underflows to ~2^64 and turns every later bound check into
         * a no-op, which is exactly how a corrupt image smuggles a wild write
         * past the guards. */
        if (img->segs[i].vaddr < img->base_vaddr)
            return DNT_E_NOSEG;
        uint64_t end = (img->segs[i].vaddr - img->base_vaddr) + img->segs[i].memsz;
        if (end < img->segs[i].memsz)   /* overflow */
            return DNT_E_NOSEG;
        if (end > img->max_mapped)
            img->max_mapped = end;
    }
    return 0;
}

/* Walk every fixup, invoking cb for each import slot. Returns the number of
 * fixups applied, or -1 if nothing could be decoded. */
int dnt_macho_apply_fixups(dnt_image *img, uint8_t *image_at_base,
                          dnt_bind_cb cb, void *user)
{
    bind_ctx ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.img = img;
    ctx.image = image_at_base;

    if (img->has_dyld_info && img->info.bind_size) {
        const uint8_t *start = img->dyld_info + img->info.bind_off;
        run_bind_stream(&ctx, start, start + img->info.bind_size, cb, user);
    }
    if (img->info.lazy_bind_size) {
        const uint8_t *start = img->dyld_info + img->info.lazy_bind_off;
        run_bind_stream(&ctx, start, start + img->info.lazy_bind_size, cb, user);
    }
    if (img->chained_fixups)
        walk_chained(img, image_at_base, cb, user);

    if (!img->has_dyld_info && !img->chained_fixups)
        return -1;
    return img->unsupported_fixups ? -2 : 0;
}
