#ifndef DNT_MACHO_H
#define DNT_MACHO_H
#include <stdint.h>
#include <stddef.h>
#include "dnt_abi.h"

/* ---- Mach-O constants (values from xnu EXTERNAL_HEADERS/mach-o/loader.h) ---- */
#define DNT_MH_EXECUTE   0x2
#define DNT_MH_DYLIB     0x6
#define DNT_MH_DYLINKER  0x7
#define DNT_CPU_TYPE_X86_64  0x01000007
#define DNT_CPU_TYPE_ARM64   0x0100000C
#define DNT_LC_REQ_DYLD      0x80000000u

#define LC_SEGMENT_64       0x19
#define LC_LOAD_DYLIB       0xC
#define LC_ID_DYLIB         0xD
#define LC_LOAD_WEAK_DYLIB  (0x18 | DNT_LC_REQ_DYLD)
#define LC_REEXPORT_DYLIB   (0x1F | DNT_LC_REQ_DYLD)
#define LC_MAIN             (0x28 | DNT_LC_REQ_DYLD)
#define LC_UNIXTHREAD       0x5
#define LC_DYLD_INFO        0x22
#define LC_DYLD_INFO_ONLY   (0x22 | DNT_LC_REQ_DYLD)
#define LC_DYLD_CHAINED_FIXUPS (0x34 | DNT_LC_REQ_DYLD)
#define LC_DYLD_EXPORTS_TRIE   (0x33 | DNT_LC_REQ_DYLD)
#define LC_CODE_SIGNATURE   0x1D
#define LC_UUID             0x1B
#define LC_RPATH            (0x1C | DNT_LC_REQ_DYLD)

#define DNT_MAX_SEGS 32
#define DNT_MAX_LOADS 128

typedef struct {
    uint32_t magic;
    int32_t  cputype;
    int32_t  cpusubtype;
    uint32_t filetype;
    uint32_t ncmds;
    uint32_t sizeofcmds;
    uint32_t flags;
    uint32_t reserved;
} dnt_mach_header_64;

typedef struct {
    uint32_t cmd;
    uint32_t cmdsize;
} dnt_load_command;

typedef struct {
    uint32_t cmd;
    uint32_t cmdsize;
    char segname[16];
    uint64_t vmaddr;
    uint64_t vmsize;
    uint64_t fileoff;
    uint64_t filesize;
    int32_t  maxprot;
    int32_t  initprot;
    uint32_t nsects;
    uint32_t flags;
} dnt_segment_command_64;

typedef struct {
    uint32_t cmd;
    uint32_t cmdsize;
    uint32_t name_off; /* offset from load command start */
    uint32_t timestamp;
    uint32_t current_version;
    uint32_t compatibility_version;
} dnt_dylib_command;

typedef struct {
    uint32_t cmd;
    uint32_t cmdsize;
    uint64_t entryoff;
    uint64_t stacksize;
} dnt_entry_point_command;

typedef struct {
    uint32_t cmd;
    uint32_t cmdsize;
    uint32_t dataoff;
    uint32_t datasize;
} dnt_linkedit_data_command;

typedef struct {
    uint32_t cmd;
    uint32_t cmdsize;
    uint32_t bind_off, bind_size;
    uint32_t weak_bind_off, weak_bind_size;
    uint32_t lazy_bind_off, lazy_bind_size;
    uint32_t export_off, export_size;
} dnt_dyld_info_command;

/* ---- Error codes returned by the loader ---- */
#define DNT_E_NOTMACHO   (-1)
#define DNT_E_FAT        (-2)
#define DNT_E_CPU        (-3)
#define DNT_E_FILETYPE   (-4)
#define DNT_E_TRUNCATED  (-5)
#define DNT_E_NOMEM      (-6)
#define DNT_E_NOSEG      (-7)

typedef struct {
    uint32_t cputype, filetype, ncmds, flags, sizeofcmds;
} dnt_macho_header_out;

typedef struct {
    char     segname[17];
    uint64_t vaddr, memsz, fileoff, filesz;
    int32_t  initprot, maxprot;
} dnt_seg;

typedef struct dnt_image {
    dnt_seg  segs[DNT_MAX_SEGS];
    int      nsegs;
    uint64_t base_vaddr;       /* vmaddr of segment 0 (usually __TEXT) */
    uint64_t entry_off;        /* from LC_MAIN, relative to __TEXT */
    int      has_main;
    char     install_name[512];
    char     dylibs[DNT_MAX_LOADS][512];
    int      ndylibs;

    const uint8_t *dyld_info;  /* whole file, for bind opcode decoding */
    dnt_dyld_info_command info;
    int      has_dyld_info;

    const uint8_t *chained_fixups;
    uint64_t chained_fixups_size;

    int      npages;             /* __PAGEZERO segments seen (skipped when mapping) */
    uint64_t pagesize_size;      /* size of the guard region, for host setup */
    uint64_t max_mapped;         /* bytes the caller must map from base_vaddr */
    uint32_t unsupported_fixups;
} dnt_image;

/* A single Darwin image is never larger than this; used to reject corrupt
 * segment tables before any size arithmetic. */
#define DNT_MAX_IMAGE_SIZE (1ull << 34)   /* 16 GiB: generous for a userland image */
#define DNT_MAX_SEG_SIZE   (1ull << 31)   /* 2 GiB: no userland segment is bigger */

#define DYLD_CHAINED_PTR_START_NONE  0xFFFF
#define DYLD_CHAINED_PTR_START_MULTI 0x8000
#define DYLD_CHAINED_PTR_START_LAST  0x8000

int  dnt_macho_header(const void *data, size_t len, dnt_macho_header_out *out);
uint64_t dnt_macho_vmsize(const void *data, size_t len, dnt_macho_header_out *out);
int dnt_macho_parse(const void *data, size_t len, dnt_image *img);
uint64_t dnt_image_alloc(uint64_t want, int protect_rwx);

#endif

/* bind callback signature shared with dnt_macho.c */
int dnt_macho_parse(const void *data, size_t len, dnt_image *img);
int dnt_macho_apply_fixups(dnt_image *img, uint8_t *image_at_base,
                          void (*cb)(void *, uint64_t, const char *, int64_t),
                          void *user);
