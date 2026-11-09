/* Builders for the two bind mechanisms. Layout is deliberately Apple-shaped:
 *
 *   [mach_header_64][LC_SEGMENT_64 __TEXT][LC_SEGMENT_64 __DATA]
 *   [LC_DYLD_INFO_ONLY or LC_DYLD_CHAINED_FIXUPS]
 *   ... __TEXT contents ... __DATA contents ... linkedit payload ...
 *
 * Chained fixups blob:
 *   dyld_chained_fixups_header        (28 bytes)  starts_off/imports_off/
 *                                                 symbols_off/imports_count
 *   dyld_chained_starts_in_image      segcount + seg_info_offset[]
 *   dyld_chained_starts_in_segment    size/page_size/pointer_format/
 *                                     segment_offset/max_valid/page_count/
 *                                     page_start[]
 *   imports[]                         4-byte packed {lib_ordinal, weak, name_off}
 *   symbols[]                         NUL-terminated names
 */
#include "dnt_fixture.h"
#include "dnt_macho.h"

#include <stdlib.h>
#include <string.h>

#define PAGE 0x1000

static void w16(uint8_t *p, uint16_t v) { memcpy(p, &v, 2); }
static void w32(uint8_t *p, uint32_t v) { memcpy(p, &v, 4); }
static void w64(uint8_t *p, uint64_t v) { memcpy(p, &v, 8); }

#define TEXT_OFF 0x000
#define DATA_OFF 0x1000
#define LINKEDIT_OFF 0x2000

static void put_header(uint8_t *buf, const dnt_mach_header_64 *mh)
{
    memcpy(buf, mh, sizeof(*mh));
}

static size_t put_segment(uint8_t *buf, size_t off, const char *name,
                          uint64_t vmaddr, uint64_t vmsize, uint64_t fileoff,
                          uint64_t filesize, int prot)
{
    dnt_segment_command_64 sc;
    memset(&sc, 0, sizeof(sc));
    sc.cmd = LC_SEGMENT_64;
    sc.cmdsize = sizeof(sc);
    strncpy(sc.segname, name, 16);
    sc.vmaddr = vmaddr;
    sc.vmsize = vmsize;
    sc.fileoff = fileoff;
    sc.filesize = filesize;
    sc.maxprot = prot;
    sc.initprot = prot;
    memcpy(buf + off, &sc, sizeof(sc));
    return off + sizeof(sc);
}

int dnt_fixture_chained(dnt_fixture *fx, const char *import_name)
{
    memset(fx, 0, sizeof(*fx));
    size_t len = 0x3000;
    uint8_t *buf = calloc(1, len);
    if (!buf)
        return -1;

    dnt_mach_header_64 mh;
    memset(&mh, 0, sizeof(mh));
    mh.magic = 0xfeedfacf;
    mh.cputype = DNT_CPU_TYPE_ARM64;
    mh.filetype = DNT_MH_EXECUTE;
    mh.ncmds = 3;
    mh.flags = 0x00200085;
    put_header(buf, &mh);

    size_t p = sizeof(mh);
    p = put_segment(buf, p, "__TEXT", 0x100000000ull, PAGE, TEXT_OFF, PAGE, 5);
    p = put_segment(buf, p, "__DATA", 0x100001000ull, PAGE, DATA_OFF, PAGE, 3);

    /* linkedit_data_command for chained fixups */
    dnt_linkedit_data_command ldc;
    memset(&ldc, 0, sizeof(ldc));
    ldc.cmd = LC_DYLD_CHAINED_FIXUPS;
    ldc.cmdsize = sizeof(ldc);

    /* Build the fixups blob with explicit, named offsets. */
    uint8_t blob[512];
    memset(blob, 0, sizeof(blob));

    /* --- dyld_chained_fixups_header (28 bytes) --- */
    enum { OFF_VERSION=0, OFF_STARTS=4, OFF_IMPORTS=8, OFF_SYMBOLS=12,
           OFF_COUNT=16, OFF_FMT=20, OFF_SYMFMT=24 };
    w32(blob + OFF_VERSION, 0);
    w32(blob + OFF_FMT, 1);          /* DYLD_CHAINED_IMPORT */
    w32(blob + OFF_SYMFMT, 0);       /* UNCOMPRESSED */

    /* --- dyld_chained_starts_in_image --- */
    size_t starts_off = 28;
    w32(blob + OFF_STARTS, (uint32_t)starts_off);
    w32(blob + starts_off + 0, 2);   /* segcount */
    w32(blob + starts_off + 4, 0);   /* seg_info_offset[0]: __TEXT none */
    size_t off1_pos = starts_off + 8;
    w32(blob + off1_pos, 0);         /* seg_info_offset[1]: patched below */

    /* --- dyld_chained_starts_in_segment (__DATA) --- */
    size_t si = starts_off + 12;
    w32(blob + si + 0, 24);          /* size */
    w16(blob + si + 4, PAGE);        /* page_size */
    w16(blob + si + 6, 2);           /* pointer_format = DYLD_CHAINED_PTR_64 */
    w64(blob + si + 8, DATA_OFF);    /* segment_offset */
    w32(blob + si + 16, 0);          /* max_valid_pointer */
    w16(blob + si + 20, 1);          /* page_count */
    w16(blob + si + 22, 0);          /* page_start[0] = 0 (first slot) */
    w32(blob + off1_pos, (uint32_t)(si - starts_off));

    /* --- imports + symbols --- */
    size_t imports_off = si + 24;
    size_t symbols_off = imports_off + 4;
    size_t nlen = strlen(import_name) + 1;
    memcpy(blob + symbols_off, import_name, nlen);
    /* packed import: name_offset bits [0:22], lib_ordinal [22:30] */
    w32(blob + imports_off, 0u /* name_offset */ | (1u << 22) /* lib ordinal */);
    w32(blob + OFF_IMPORTS, (uint32_t)imports_off);
    w32(blob + OFF_SYMBOLS, (uint32_t)symbols_off);
    w32(blob + OFF_COUNT, 1);
    size_t blob_size = symbols_off + nlen;

    ldc.dataoff = LINKEDIT_OFF;
    ldc.datasize = (uint32_t)blob_size;
    memcpy(buf + p, &ldc, sizeof(ldc));
    memcpy(buf + LINKEDIT_OFF, blob, blob_size);

    /* The bind slot: PTR_64 bind encoding, next=0, ordinal=0, bind=1. */
    uint64_t slot = (1ull << 63) /* auth? no: bit63 unused for PTR_64 */;
    slot = 0;
    slot |= (0ull);              /* ordinal 24 bits = 0 */
    slot |= (0ull << 51);        /* next 12 bits = 0 */
    slot |= (1ull << 62);        /* bind = 1 */
    w64(buf + DATA_OFF, slot);

    fx->data = buf;
    fx->len = len;
    fx->bind_slot_vaddr = 0x100001000ull;
    fx->image_vmsize = 0x2000;
    return 0;
}

int dnt_fixture_bind_opcodes(dnt_fixture *fx, const char *import_name)
{
    memset(fx, 0, sizeof(*fx));
    size_t len = 0x3000;
    uint8_t *buf = calloc(1, len);
    if (!buf)
        return -1;

    dnt_mach_header_64 mh;
    memset(&mh, 0, sizeof(mh));
    mh.magic = 0xfeedfacf;
    mh.cputype = DNT_CPU_TYPE_ARM64;
    mh.filetype = DNT_MH_EXECUTE;
    mh.ncmds = 3;
    put_header(buf, &mh);

    size_t p = sizeof(mh);
    p = put_segment(buf, p, "__TEXT", 0x100000000ull, PAGE, TEXT_OFF, PAGE, 5);
    p = put_segment(buf, p, "__DATA", 0x100001000ull, PAGE, DATA_OFF, PAGE, 3);

    /* bind opcode stream:
     *   SET_DYLIB_ORDINAL_IMM 1
     *   SET_SYMBOL_TRAILING_FLAGS_IMM 0, "name", 0
     *   SET_TYPE_IMM 1
     *   SET_SEGMENT_AND_OFFSET_ULEB seg 1, offset 0
     *   DO_BIND
     *   DONE
     */
    uint8_t ops[256];
    size_t o = 0;
    ops[o++] = 0x11;                       /* SET_DYLIB_ORDINAL_IMM | 1 */
    ops[o++] = 0x40;                       /* SET_SYMBOL_TRAILING_FLAGS_IMM | 0 */
    size_t nlen = strlen(import_name);
    memcpy(ops + o, import_name, nlen + 1);
    o += nlen + 1;
    ops[o++] = 0x51;                       /* SET_TYPE_IMM | 1 (pointer) */
    ops[o++] = 0x71;                       /* SET_SEGMENT_AND_OFFSET_ULEB | seg 1 */
    ops[o++] = 0x00;                       /* uleb offset 0 */
    ops[o++] = 0x90;                       /* DO_BIND */
    ops[o++] = 0x00;                       /* DONE */

    dnt_dyld_info_command info;
    memset(&info, 0, sizeof(info));
    info.cmd = LC_DYLD_INFO_ONLY;
    info.cmdsize = sizeof(info);
    info.bind_off = LINKEDIT_OFF;
    info.bind_size = (uint32_t)o;
    memcpy(buf + p, &info, sizeof(info));
    memcpy(buf + LINKEDIT_OFF, ops, o);

    fx->data = buf;
    fx->len = len;
    fx->bind_slot_vaddr = 0x100001000ull;
    fx->image_vmsize = 0x2000;
    return 0;
}

void dnt_fixture_free(dnt_fixture *fx)
{
    if (fx && fx->data) {
        free(fx->data);
        fx->data = NULL;
        fx->len = 0;
    }
}
