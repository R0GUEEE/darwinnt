#ifndef DNT_PLIST_H
#define DNT_PLIST_H
#include <stdint.h>
#include <stddef.h>
/* Read a top-level string value from a binary plist (bplist00).
 * Returns 0 on success, -1 if absent or unreadable. */
int dnt_plist_bin_lookup(const uint8_t *data, size_t len,
                         const char *key, char *out, size_t cap);
#endif
