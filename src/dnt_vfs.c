/* Darwin virtual filesystem for the shim.
 *
 * Maps guest file descriptors onto host handles through the path translator.
 * The behaviours that matter are the Darwin ones a naive mapping gets wrong:
 *
 *  - fds 0,1,2 always exist and never close for the guest by accident
 *  - open() flag bit assignments (O_CLOEXEC is 0x1000000, not Linux's 0x80000)
 *  - mode bits in st_mode are POSIX S_IF* values, 16-bit mode field
 *  - getdirentries64 returns packed variable-length records with d_reclen
 *  - EISDIR / ENOTDIR are distinguished, including trailing-slash semantics
 */
#include "dnt_vfs.h"
#include "dnt_abi.h"
#include "dnt_errno.h"
#include "dnt_path.h"
#include "dnt_port.h"

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>

static char     g_root[DNT_MAXPATHLEN];
static char     g_cwd[DNT_MAXPATHLEN] = "/";
static dnt_fd   g_fds[DNT_MAX_FDS];
static uint64_t g_next_ino = 0x1000000;

/* ---- helpers ---- */

/* Join a guest path against the cwd. Darwin represents a relative name with
 * no leading slash; "./x" and "x" are both relative to cwd. */
static int resolve_guest_path(const char *path, char *out, size_t cap)
{
    if (!path || !*path)
        return DNT_ENOENT;
    if (path[0] == '/') {
        if (strlen(path) >= cap)
            return DNT_ENAMETOOLONG;
        strcpy(out, path);
        return 0;
    }
    size_t cl = strlen(g_cwd), pl = strlen(path);
    if (cl + pl + 2 >= cap)
        return DNT_ENAMETOOLONG;
    memcpy(out, g_cwd, cl);
    if (cl == 0 || out[cl - 1] != '/')
        out[cl++] = '/';
    memcpy(out + cl, path, pl + 1);
    return 0;
}

static int to_host(const char *guest_path, char *host, size_t cap, int *trailing)
{
    char full[DNT_MAXPATHLEN];
    int rc = resolve_guest_path(guest_path, full, sizeof(full));
    if (rc)
        return rc;
    size_t n = strlen(full);
    int tr = n > 1 && full[n - 1] == '/';
    if (trailing)
        *trailing = tr;
    int pr = dnt_path_translate(g_root, full, 1, host, cap);
    if (pr == DNT_PATH_ESCAPE)
        return DNT_EACCES;      /* Darwin returns EACCES for "/.." traversal */
    if (pr == DNT_PATH_ENAMETOOLONG)
        return DNT_ENAMETOOLONG;
    if (pr != DNT_PATH_OK)
        return DNT_EINVAL;
    return 0;
}

int dnt_vfs_init(const char *root)
{
    memset(g_fds, 0, sizeof(g_fds));
    if (!root || !*root)
        return DNT_EINVAL;
    size_t n = strlen(root);
    if (n >= sizeof(g_root))
        return DNT_ENAMETOOLONG;
#if defined(_WIN32)
    memcpy(g_root, root, n + 1);
#else
    memcpy(g_root, root, n + 1);
#endif
    strcpy(g_cwd, "/");

    /* Darwin's root has these directories, and /var, /tmp, /etc are links
     * into /private. The translator already rewrites those three prefixes, so
     * only the /private side needs to exist as real directories -- no links
     * required, which is what makes this work identically on Win32. */
    static const char *const skeleton[] = {
        "/private", "/private/tmp", "/private/var/tmp", "/private/var/db",
        "/private/var/log", "/private/etc",
        "/usr", "/usr/bin", "/usr/lib", "/usr/local/bin", "/usr/share",
        "/dev", "/bin", "/sbin",
    };
    for (size_t i = 0; i < sizeof(skeleton) / sizeof(skeleton[0]); i++) {
        char host[DNT_MAXPATHLEN + 128];
        if (dnt_path_translate(root, skeleton[i], 0, host, sizeof(host)) != DNT_PATH_OK)
            break;
        dnt_port_mkdir(host);   /* EEXIST is expected and ignored */
    }

    /* 0,1,2 are the standard streams. They are real descriptors with host
     * handles attached by the launcher; mark them open and inheritable. */
    for (int i = 0; i < 3; i++) {
        g_fds[i].in_use = 1;
        g_fds[i].fd = i;
        g_fds[i].flags = (i == 0) ? DNT_O_RDONLY : DNT_O_WRONLY;
        g_fds[i].is_tty = 1;
        g_fds[i].handle = DNT_HANDLE_INVALID;
    }
    return 0;
}

const char *dnt_vfs_root(void) { return g_root; }
const char *dnt_vfs_cwd(void) { return g_cwd; }

int dnt_vfs_chdir(const char *guest_path)
{
    char host[DNT_MAXPATHLEN + 128];
    int rc = to_host(guest_path, host, sizeof(host), NULL);
    if (rc)
        return rc;
    /* Existence is checked first: Darwin returns ENOENT for a missing path and
     * only ENOTDIR when something is there but is not a directory. */
    dnt_port_stat ps;
    rc = dnt_port_stat_path(host, &ps, 1);
    if (rc)
        return rc;
    if ((ps.mode & DNT_S_IFMT) != DNT_S_IFDIR)
        return DNT_ENOTDIR;
    char full[DNT_MAXPATHLEN];
    rc = resolve_guest_path(guest_path, full, sizeof(full));
    if (rc)
        return rc;
    /* Normalise away "." and ".." so getcwd() always returns a canonical
     * path -- Darwin's getcwd does the same. */
    char out[DNT_MAXPATHLEN];
    size_t w = 0;
    const char *p = full;
    out[w++] = '/';
    while (*p) {
        while (*p == '/') p++;
        if (!*p) break;
        const char *s = p;
        while (*p && *p != '/') p++;
        size_t l = (size_t)(p - s);
        if (l == 1 && s[0] == '.')
            continue;
        if (l == 2 && s[0] == '.' && s[1] == '.') {
            while (w > 1 && out[w - 1] != '/') w--;
            if (w > 1) w--;
            continue;
        }
        if (w > 1 && out[w - 1] != '/')
            out[w++] = '/';
        memcpy(out + w, s, l);
        w += l;
        out[w] = 0;
    }
    out[w] = 0;
    if (w == 0) { out[0] = '/'; out[1] = 0; }
    memcpy(g_cwd, out, w + 1);
    return 0;
}

int dnt_vfs_getcwd(char *buf, size_t cap)
{
    size_t n = strlen(g_cwd);
    if (n + 1 > cap)
        return DNT_ERANGE;
    memcpy(buf, g_cwd, n + 1);
    return 0;
}

dnt_fd *dnt_vfs_get(int fd)
{
    if (fd < 0 || fd >= DNT_MAX_FDS || !g_fds[fd].in_use)
        return NULL;
    return &g_fds[fd];
}

static dnt_fd *alloc_fd(void)
{
    for (int i = 3; i < DNT_MAX_FDS; i++) {
        if (!g_fds[i].in_use) {
            memset(&g_fds[i], 0, sizeof(g_fds[i]));
            g_fds[i].in_use = 1;
            g_fds[i].fd = i;
            g_fds[i].handle = DNT_HANDLE_INVALID;
            return &g_fds[i];
        }
    }
    return NULL;
}

/* ---- stat conversion ---- */

static void fill_stat(const dnt_port_stat *ps, int is_dir_override,
                      dnt_stat *out)
{
    memset(out, 0, sizeof(*out));
    out->st_dev = 0x0201;             /* plausible Darwin root dev */
    out->st_ino = ps->ino ? ps->ino : (g_next_ino += 2);
    out->st_uid = ps->uid ? ps->uid : 501;
    out->st_gid = ps->gid ? ps->gid : 20;
    out->st_nlink = ps->nlink ? (dnt_nlink_t)ps->nlink : 1;
    uint16_t mode = (uint16_t)ps->mode;
    if (is_dir_override)
        mode = (uint16_t)((mode & 07777) | DNT_S_IFDIR);
    out->st_mode = mode;
    out->st_atimespec.tv_sec = ps->atime;
    out->st_mtimespec.tv_sec = ps->mtime;
    out->st_ctimespec.tv_sec = ps->ctime;
    out->st_birthtimespec.tv_sec = ps->birthtime;
    out->st_birthtimespec.tv_nsec = ps->birthtime_nsec;
    out->st_size = (dnt_off_t)ps->size;
    out->st_blocks = (dnt_blkcnt_t)((ps->size + 511) / 512);
    out->st_blksize = 4096;
    out->st_flags = 0;
}

/* ---- open ---- */

/* Translate Darwin open flags into the subset the port layer understands.
 * Kept as-is (Darwin values) and let each backend map, because the numeric
 * values collide with the host's own. */
int dnt_vfs_open(const char *guest_path, int flags, int mode)
{
    char host[DNT_MAXPATHLEN + 128];
    int trailing = 0;
    int rc = to_host(guest_path, host, sizeof(host), &trailing);
    if (rc)
        return -rc;   /* negative: never collides with a small fd */

    /* "file/" is ENOTDIR in Darwin even if the file exists. */
    if (trailing && !dnt_port_is_dir(host))
        return -DNT_ENOTDIR;

    int herr = 0;
    dnt_handle_t h = dnt_port_open(host, flags, mode, &herr);
    if (h == DNT_HANDLE_INVALID)
        return -(herr ? herr : DNT_EIO);

    if (flags & DNT_O_DIRECTORY) {
        dnt_port_stat ps;
        if (dnt_port_fstat(h, &ps) != 0 ||
            (ps.mode & DNT_S_IFMT) != DNT_S_IFDIR) {
            dnt_port_close(h);
            return -DNT_ENOTDIR;
        }
    }

    dnt_port_stat ps;
    int is_dir = 0;
    if (dnt_port_fstat(h, &ps) == 0)
        is_dir = ((ps.mode & DNT_S_IFMT) == DNT_S_IFDIR);
    else
        memset(&ps, 0, sizeof(ps));

    dnt_fd *f = alloc_fd();
    if (!f) {
        dnt_port_close(h);
        return -DNT_EMFILE;
    }
    f->handle = h;
    strncpy(f->host_path, host, sizeof(f->host_path) - 1);
    f->flags = flags;
    f->is_dir = is_dir;
    f->stat = ps;
    f->dir = NULL;
    f->dirpos = 0;
    return f->fd;
}

int dnt_vfs_close(int fd)
{
    dnt_fd *f = dnt_vfs_get(fd);
    if (!f)
        return DNT_EBADF;
    if (f->dir)
        dnt_port_closedir(f->dir);
    if (f->handle != DNT_HANDLE_INVALID)
        dnt_port_close(f->handle);
    memset(f, 0, sizeof(*f));
    return 0;
}

int64_t dnt_vfs_read(int fd, void *buf, uint64_t n, int *err)
{
    dnt_fd *f = dnt_vfs_get(fd);
    if (!f) { *err = DNT_EBADF; return -1; }
    if ((f->flags & DNT_O_ACCMODE) == DNT_O_WRONLY) { *err = DNT_EBADF; return -1; }
    if (f->is_dir) { *err = DNT_EISDIR; return -1; }
    return dnt_port_read(f->handle, buf, n, err);
}

int64_t dnt_vfs_write(int fd, const void *buf, uint64_t n, int *err)
{
    dnt_fd *f = dnt_vfs_get(fd);
    if (!f) { *err = DNT_EBADF; return -1; }
    if ((f->flags & DNT_O_ACCMODE) == DNT_O_RDONLY) { *err = DNT_EBADF; return -1; }
    if (f->is_dir) { *err = DNT_EISDIR; return -1; }
    return dnt_port_write(f->handle, buf, n, err);
}

int64_t dnt_vfs_lseek(int fd, int64_t off, int whence, int *err)
{
    dnt_fd *f = dnt_vfs_get(fd);
    if (!f) { *err = DNT_EBADF; return -1; }
    if (f->is_dir) { *err = DNT_EISDIR; return -1; }
    return dnt_port_seek(f->handle, off, whence, err);
}

int dnt_vfs_fstat(int fd, dnt_stat *out)
{
    dnt_fd *f = dnt_vfs_get(fd);
    if (!f) return DNT_EBADF;
    dnt_port_stat ps = f->stat;
    if (!f->is_tty && f->handle != DNT_HANDLE_INVALID)
        dnt_port_fstat(f->handle, &ps);
    else if (f->is_tty)
        ps.mode = DNT_S_IFCHR | 0620;   /* /dev/ttyxxxx */
    fill_stat(&ps, f->is_dir, out);
    return 0;
}

int dnt_vfs_stat(const char *guest_path, dnt_stat *out, int follow)
{
    char host[DNT_MAXPATHLEN + 128];
    int trailing = 0;
    int rc = to_host(guest_path, host, sizeof(host), &trailing);
    if (rc)
        return rc;
    dnt_port_stat ps;
    int r = dnt_port_stat_path(host, &ps, follow);
    if (r == 0) {
        if (trailing && (ps.mode & DNT_S_IFMT) != DNT_S_IFDIR)
            return DNT_ENOTDIR;
        fill_stat(&ps, 0, out);
    }
    return r;
}

int dnt_vfs_unlink(const char *guest_path)
{
    char host[DNT_MAXPATHLEN + 128];
    int rc = to_host(guest_path, host, sizeof(host), NULL);
    if (rc) return rc;
    if (dnt_port_is_dir(host)) return DNT_EPERM;
    return dnt_port_unlink(host);
}

int dnt_vfs_mkdir(const char *guest_path, int mode)
{
    char host[DNT_MAXPATHLEN + 128];
    int rc = to_host(guest_path, host, sizeof(host), NULL);
    (void)mode;
    if (rc) return rc;
    return dnt_port_mkdir(host);
}

int dnt_vfs_rmdir(const char *guest_path)
{
    char host[DNT_MAXPATHLEN + 128];
    int rc = to_host(guest_path, host, sizeof(host), NULL);
    if (rc) return rc;
    if (!dnt_port_is_dir(host)) return DNT_ENOTDIR;
    return dnt_port_rmdir(host);
}

int dnt_vfs_rename(const char *from, const char *to)
{
    char hf[DNT_MAXPATHLEN + 128], ht[DNT_MAXPATHLEN + 128];
    int rc = to_host(from, hf, sizeof(hf), NULL);
    if (rc) return rc;
    rc = to_host(to, ht, sizeof(ht), NULL);
    if (rc) return rc;
    return dnt_port_rename(hf, ht);
}

int dnt_vfs_ftruncate(int fd, uint64_t size)
{
    dnt_fd *f = dnt_vfs_get(fd);
    if (!f) return DNT_EBADF;
    if (f->is_dir) return DNT_EISDIR;
    int err = 0;
    return dnt_port_ftruncate(f->handle, size, &err) == 0 ? 0 : err;
}

/* ---- directory reading ---- */

int64_t dnt_vfs_getdirentries64(int fd, void *buf, uint64_t bufsize,
                               int64_t *basep)
{
    int err = 0;
    dnt_fd *f = dnt_vfs_get(fd);
    if (!f)
        return DNT_EBADF;
    if (!f->is_dir)
        return DNT_ENOTDIR;
    /* Restart iteration at the saved offset. Opening a fresh cursor and
     * skipping n entries is cheap for the directory sizes involved and, more
     * importantly, means a short read never consumes an entry the caller did
     * not receive. */
    if (f->dir) {
        dnt_port_closedir(f->dir);
        f->dir = NULL;
    }
    f->dir = dnt_port_opendir(f->host_path, &err);
    if (!f->dir)
        return err ? err : DNT_EIO;
    uint64_t skip = f->dirpos;
    while (skip) {
        char sn[256]; uint64_t si; int st_;
        int r = dnt_port_readdir(f->dir, sn, sizeof(sn), &si, &st_, &err);
        if (r <= 0) break;
        size_t rl = (offsetof(dnt_dirent, d_name) + strlen(sn) + 1 + 7) & ~7u;
        skip -= rl;
    }

    uint8_t *out = buf;
    uint64_t used = 0;
    while (used < bufsize) {
        char name[256];
        uint64_t ino = 0;
        int type = DNT_DT_UNKNOWN;
        int r = dnt_port_readdir(f->dir, name, sizeof(name), &ino, &type, &err);
        if (r < 0)
            return err ? err : DNT_EIO;
        if (r == 0)
            break;

        /* Darwin packs dirents 8-byte aligned; d_reclen includes padding so
         * the next record starts on a boundary. */
        size_t namelen = strlen(name);
        size_t reclen = (offsetof(dnt_dirent, d_name) + namelen + 1 + 7) & ~7u;
        if (reclen > bufsize - used) {
            /* Not enough room: requeue by remembering we consumed nothing.
             * The port layer cannot push back, so re-seek the directory on
             * next call instead of silently losing the entry. */
            if (used == 0)
                return DNT_EINVAL;
            break;
        }
        dnt_dirent *de = (dnt_dirent *)(out + used);
        memset(de, 0, reclen);
        de->d_ino = ino;
        de->d_reclen = (uint16_t)reclen;
        de->d_namlen = (uint16_t)namelen;
        de->d_type = (uint8_t)type;
        memcpy(de->d_name, name, namelen);
        de->d_name[namelen] = 0;
        used += reclen;
        f->dirpos += reclen;
    }
    if (basep)
        *basep = (int64_t)f->dirpos;
    return (int64_t)used;
}
