#ifndef DNT_PATH_H
#define DNT_PATH_H
#include <stddef.h>
#include <stdint.h>

#define DNT_MAXPATHLEN 1024   /* Darwin PATH_MAX; XNU allocates namei bufs at this */
#define DNT_MAX_PATH_COMPONENTS 256

enum {
    DNT_PATH_OK = 0,
    DNT_PATH_EINVAL = -1,
    DNT_PATH_ENAMETOOLONG = -2,
    DNT_PATH_ESCAPE = -3,   /* ".." tried to climb above the Darwin root */
};

/* Translate a guest path into a host path under `root`.
 * Returns DNT_PATH_OK and NUL-terminated host path in `out`.
 * If preserve_trailing_slash, a trailing separator in the guest path is
 * carried through (the caller turns that into ENOTDIR when the target is not
 * a directory). */
int dnt_path_translate(const char *root, const char *darwin_path,
                       int preserve_trailing_slash, char *out, size_t out_cap);

#endif
