/* Binary plist reader — just enough to read top-level string values.
 *
 * Real IPAs ship `bplist00`, not XML (Apple's tooling always emits binary).
 * The format:
 *
 *   "bplist00"                                  8-byte magic
 *   <object table>                              variable
 *   <offset table>                              num_objects * offset_size
 *   <trailer, 32 bytes>
 *
 * Trailer layout (from its END):
 *   [0]  unused x6
 *   [6]  offset_size      [7]  object_ref_size
 *   [8]  num_objects (u64) [16] top_object (u64)
 *   [24] offset_table_offset (u64)
 *
 * A dict object is a marker byte (0xD0 | log2(count)) followed by count key
 * refs and count value refs. Strings are 0x50|len (ASCII) or 0x60|len (UTF-16).
 * Objects whose length will not fit in the nibble use marker 0x_ F followed by
 * an int object holding the real length.
 */
#include "dnt_plist.h"

#include <string.h>

static uint64_t rd_be(const uint8_t *p, int n)
{
    uint64_t v = 0;
    for (int i = 0; i < n; i++)
        v = (v << 8) | p[i];
    return v;
}

typedef struct {
    const uint8_t *d;
    size_t         len;
    int            off_size;
    int            ref_size;
    uint64_t       n_obj;
    uint64_t       top;
    uint64_t       off_tab;
} bpl;

static uint64_t obj_offset(const bpl *p, uint64_t idx)
{
    if (idx >= p->n_obj)
        return 0;
    uint64_t o = p->off_tab + idx * (uint64_t)p->off_size;
    if (o + p->off_size > p->len)
        return 0;
    return rd_be(p->d + o, p->off_size);
}

/* Decode the length of a variable-length object at `marker`. */
static uint64_t obj_count(const uint8_t *obj, size_t *hdr)
{
    uint8_t m = obj[0];
    uint8_t lo = m & 0x0F;
    if (lo != 0x0F) {
        *hdr = 1;
        return lo;
    }
    /* length follows as an int object */
    if (obj[1] != 0x10 && obj[1] != 0x11 && obj[1] != 0x12 && obj[1] != 0x13) {
        *hdr = 1;
        return 0;
    }
    int nb = 1 << (obj[1] & 0x0F);
    *hdr = 2 + (size_t)nb;
    return rd_be(obj + 2, nb);
}

/* Copy a string object into out. Returns 0 on success. */
static int obj_string(const bpl *p, uint64_t idx, char *out, size_t cap)
{
    uint64_t off = obj_offset(p, idx);
    if (!off || off >= p->len)
        return -1;
    const uint8_t *obj = p->d + off;
    uint8_t m = obj[0];
    if ((m & 0xF0) != 0x50 && (m & 0xF0) != 0x60)
        return -1;

    size_t hdr = 0;
    uint64_t count = obj_count(obj, &hdr);
    const uint8_t *s = obj + hdr;
    if ((uint64_t)(s - p->d) + count > p->len)
        return -1;

    if ((m & 0xF0) == 0x50) {          /* ASCII */
        size_t n = count < cap - 1 ? (size_t)count : cap - 1;
        memcpy(out, s, n);
        out[n] = 0;
        return 0;
    }
    /* UTF-16BE -> ASCII-ish: keep the low byte of each code unit, which is
     * correct for the Latin bundle identifiers and version strings we read. */
    size_t n = 0;
    for (uint64_t i = 0; i < count && n + 1 < cap; i++) {
        uint16_t c = (uint16_t)((s[i*2] << 8) | s[i*2 + 1]);
        out[n++] = (char)(c < 0x80 ? c : '?');
    }
    out[n] = 0;
    return 0;
}

int dnt_plist_bin_lookup(const uint8_t *data, size_t len,
                         const char *key, char *out, size_t cap)
{
    if (len < 40 || memcmp(data, "bplist00", 8) != 0)
        return -1;

    const uint8_t *tr = data + len - 32;
    bpl p;
    p.d = data;
    p.len = len;
    p.off_size = tr[6];
    p.ref_size = tr[7];
    p.n_obj = rd_be(tr + 8, 8);
    p.top = rd_be(tr + 16, 8);
    p.off_tab = rd_be(tr + 24, 8);

    if (p.off_size < 1 || p.off_size > 8 || p.ref_size < 1 || p.ref_size > 8)
        return -1;
    if (p.n_obj == 0 || p.off_tab >= len)
        return -1;

    /* Walk only the top-level dictionary. Nested values are not needed. */
    uint64_t off = obj_offset(&p, p.top);
    if (!off || off >= len)
        return -1;
    const uint8_t *obj = data + off;
    if ((obj[0] & 0xF0) != 0xD0)
        return -1;

    size_t hdr = 0;
    uint64_t count = obj_count(obj, &hdr);
    const uint8_t *keys = obj + hdr;
    const uint8_t *vals = keys + (uint64_t)count * p.ref_size;
    if ((uint64_t)(vals - data) + (uint64_t)count * p.ref_size > len)
        return -1;

    for (uint64_t i = 0; i < count; i++) {
        uint64_t kref = rd_be(keys + i * p.ref_size, p.ref_size);
        char kbuf[256];
        if (obj_string(&p, kref, kbuf, sizeof(kbuf)) != 0)
            continue;
        if (strcmp(kbuf, key) != 0)
            continue;
        uint64_t vref = rd_be(vals + i * p.ref_size, p.ref_size);
        return obj_string(&p, vref, out, cap);
    }
    return -1;
}
