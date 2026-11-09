/* 64-bit Darwin stub binaries, emitted here so the loader can be exercised
 * without a Mac. These are structurally valid Mach-O files: real header,
 * LC_SEGMENT_64s and (optionally) an LC_DYLD_CHAINED_FIXUPS blob whose import
 * table points at real C strings. They are not runnable on Darwin -- they exist
 * to prove the parser reads what dyld would read.
 */
#ifndef DNT_FIXTURE_H
#define DNT_FIXTURE_H
#include <stdint.h>
#include <stddef.h>

typedef struct {
    uint8_t *data;
    size_t   len;
    /* where things ended up, so a test can assert on specific slots */
    uint64_t bind_slot_vaddr; /* virtual address of the single bind slot */
    uint64_t image_vmsize;
} dnt_fixture;

/* Emits: __TEXT (4K, file-backed) + __DATA (4K, with one chained bind to
 * _write). Returns 0 on success. Caller frees fx->data. */
int dnt_fixture_chained(dnt_fixture *fx, const char *import_name);

/* Same, using classic LC_DYLD_INFO bind opcodes. */
int dnt_fixture_bind_opcodes(dnt_fixture *fx, const char *import_name);

void dnt_fixture_free(dnt_fixture *fx);

#endif
