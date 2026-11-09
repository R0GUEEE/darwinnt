#ifndef DNT_EXEC_H
#define DNT_EXEC_H
#include <stdint.h>
#include <stddef.h>

enum {
    DNT_E_NOENTRY = -100,
    DNT_E_GEOMETRY = -101,
};

typedef struct {
    int      error;
    int      halt;
    int      exit_code;
    uint64_t image_base;
    uint64_t image_size;
    int      mapped_at_requested;  /* 0 when the image slid to another base */
    char     detail[160];
    int      nbound;            /* import slots resolved */
    int      nmissing;
    int      bind_ok;           /* 0 when a fixup mechanism was unsupported */
    char     missing[32][64];   /* symbols we do not provide */
} dnt_exec_result;

/* Map `file` and run it from its LC_MAIN entry with `root` as the Darwin
 * filesystem root. Returns 0 if the guest exited, negative otherwise. */
int dnt_exec_image(const uint8_t *file, size_t file_len, const char *root,
                   int verbose, dnt_exec_result *out);

#endif
