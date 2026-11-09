/* Darwin path -> Windows path translation.
 *
 * The guest believes in a POSIX tree rooted at "/". Windows has drive letters
 * and no root. The mapping is:
 *
 *   Darwin              Windows (root = DNT_ROOT, default C:\DarwinRoot)
 *   /                   <root>\
 *   /usr/bin/cc         <root>\usr\bin\cc
 *   /var/tmp            <root>\private\var\tmp   (Darwin's /var is a symlink
 *                                                 into /private/var)
 *
 * Two Darwin rules matter and are easy to get wrong:
 *
 * 1. Bundle components. In "Foo.app/Contents/MacOS/bar" there is no ".." to
 *    worry about, but a component that merely *contains* dots must never be
 *    read as a parent reference: Darwin's namei only acts on ".." when it is
 *    the entire component.
 * 2. Trailing slashes imply "must be a directory" -- the caller needs to know
 *    so it can return ENOTDIR instead of opening a regular file.
 */
#include "dnt_path.h"

#include <string.h>

int dnt_path_translate(const char *root, const char *darwin_path,
                       int preserve_trailing_slash, char *out, size_t out_cap)
{
    if (!root || !darwin_path || !out || out_cap == 0)
        return DNT_PATH_EINVAL;

    size_t plen = strlen(darwin_path);
    if (plen >= DNT_MAXPATHLEN)
        return DNT_PATH_ENAMETOOLONG;

    size_t rlen = strlen(root);
    while (rlen > 0 && (root[rlen - 1] == '\\' || root[rlen - 1] == '/'))
        rlen--;
    if (rlen + plen + 16 >= out_cap)
        return DNT_PATH_ENAMETOOLONG;

    int root_components = 1;
    for (size_t i = 1; i < rlen; i++)
        if (root[i] == '\\' || root[i] == '/')
            root_components++;
    size_t o = 0;
    memcpy(out, root, rlen);
    o = rlen;

    /* Separator handling differs by host shape. A Windows root ("C:\\x" or a
     * UNC path) uses backslashes; a POSIX root ("/tmp/x") must keep forward
     * slashes and its leading one, or every translated path becomes relative. */
    const int posix_root = (root[0] == '/');
    const char sep = posix_root ? '/' : '\\';
    if (!posix_root) {
        for (size_t i = 0; i < o; i++)
            if (out[i] == '/')
                out[i] = '\\';
    }

    /* Darwin canonicalises these three vnodes into /private. Guests stat()
     * /var/tmp and open() /var/tmp and must land on one inode, so rewrite the
     * prefix exactly like the kernel's root vnode link does. */
    const char *p = darwin_path;
    static const char *const froms[] = { "/var", "/tmp", "/etc" };
    static const char *const tos[]   = { "/private/var", "/private/tmp", "/private/etc" };
    size_t nrew = 3;
    for (size_t i = 0; i < nrew; i++) {
        size_t fl = strlen(froms[i]);
        if (strncmp(darwin_path, froms[i], fl) == 0 &&
            (darwin_path[fl] == '/' || darwin_path[fl] == 0)) {
            /* Emit the replacement using the host's separator. */
            const char *t = tos[i];
            for (; *t; t++)
                out[o++] = (*t == '/') ? sep : *t;
            p = darwin_path + fl;
            break;
        }
    }

    size_t rest = strlen(p);
    memmove(out + o, p, rest + 1);
    o += rest;

    int had_trailing = o > 0 && (out[o - 1] == '/');


    /* Collapse "." and ".." components. walk separates "<root>" from the
     * guest part so a ".." that would climb above / is detected even when the
     * root is a multi-component host path like C:\DarwinRoot. */
    size_t w = 0, r = 0;
    int depth = 0;              /* components below root */
    int escaped_root = 0;
    int comp = 0;               /* 0 = still copying root prefix */
    /* A POSIX absolute root keeps its leading separator; Windows roots are
     * "C:" or UNC and must not gain one. */
    if (posix_root) {
        out[w++] = sep;
        while (r < o && (out[r] == '\\' || out[r] == '/'))
            r++;
    }
    while (r < o) {
        while (r < o && (out[r] == '\\' || out[r] == '/'))
            r++;
        if (r >= o)
            break;
        size_t cs = r;
        while (r < o && out[r] != '\\' && out[r] != '/')
            r++;
        size_t cl = r - cs;

        int in_root = comp < root_components;
        comp++;

        int is_dot    = (cl == 1 && out[cs] == '.');
        int is_dotdot = (cl == 2 && out[cs] == '.' && out[cs + 1] == '.');
        if (!in_root && is_dot)
            continue;
        if (!in_root && is_dotdot) {
            if (depth == 0) { escaped_root = 1; continue; }
            depth--;
            while (w > 0 && out[w - 1] != '\\' && out[w - 1] != '/')
                w--;
            if (w > 0)
                w--;
            continue;
        }
        if (w > 0 && out[w - 1] != sep)
            out[w++] = sep;
        if (w != cs)
            memmove(out + w, out + cs, cl);
        w += cl;
        if (!in_root)
            depth++;
    }
    out[w] = 0;

    if (escaped_root)
        return DNT_PATH_ESCAPE;

    if (preserve_trailing_slash && had_trailing && w + 1 < out_cap) {
        out[w++] = sep;
        out[w] = 0;
    }
    /* Darwin root itself maps to "<root>\" so joins behave. */
    if (w == 0 || (w == rlen && depth == 0 && o > rlen)) {
        out[w++] = sep;
        out[w] = 0;
    }
    return DNT_PATH_OK;
}
