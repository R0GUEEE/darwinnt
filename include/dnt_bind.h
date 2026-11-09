#ifndef DNT_BIND_H
#define DNT_BIND_H
#include <stdint.h>
#include <stddef.h>
#include "dnt_macho.h"

#define DNT_MAX_TRAMPS        256
#define DNT_TRAMPOLINE_STRIDE 16
#define DNT_MAX_MISSING       32

/* A guest calling a bound symbol jumps to trampoline_base + idx*stride; the
 * interpreter recognises that address and dispatches rather than executing
 * the bytes there. */
typedef struct {
    uint64_t trampoline_base;
    uint64_t image_size;           /* needed to spot in-image slots */
    uint64_t binder_addr;          /* where GOT slots point before resolution */
    int      ntramps;
    char     names[DNT_MAX_TRAMPS][64];
    uint32_t nr[DNT_MAX_TRAMPS];   /* Darwin syscall number per trampoline */
} dnt_bind;

typedef struct {
    int nbound;
    int unsupported;
    int nmissing;
    char missing[DNT_MAX_MISSING][64];
} dnt_bind_report;

void     dnt_bind_reset(dnt_bind *b);
uint64_t dnt_bind_lookup(dnt_bind *b, const char *name);
uint64_t dnt_bind_install(dnt_bind *b, const char *name, uint32_t syscall_nr);
int      dnt_bind_trampoline_index(dnt_bind *b, uint64_t addr);
int      dnt_bind_count(dnt_bind *b);
const char *dnt_bind_name(dnt_bind *b, int idx);
uint32_t dnt_bind_syscall(dnt_bind *b, int idx);

int dnt_bind_apply(dnt_image *img, uint8_t *mem, dnt_bind *b,
                   dnt_bind_report *rep);

#endif
