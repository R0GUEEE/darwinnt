/* POSIX implementation of the host port layer.
 *
 * This backend exists so the Darwin semantics in dnt_vfs.c can be tested on
 * Linux. The Windows backend (dnt_port_win.c) implements the same contract on
 * top of Win32 handles; keeping both means a bug in Darwin behaviour shows up
 * in CI rather than only on a user's machine.
 */
#ifndef _WIN32

#define _GNU_SOURCE
#include "dnt_port.h"
#include "dnt_errno.h"
#include "dnt_abi.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

struct dnt_dir {
    DIR *d;
    char path[4096];   /* needed to lstat entries when d_type is unknown */
};

static int map_errno(int e)
{
    switch (e) {
    case 0:             return 0;
    case ENOENT:        return DNT_ENOENT;
    case EACCES:
    case EPERM:         return DNT_EACCES;
    case EISDIR:        return DNT_EISDIR;
    case ENOTDIR:       return DNT_ENOTDIR;
    case EEXIST:        return DNT_EEXIST;
    case EBADF:         return DNT_EBADF;
    case EMFILE:        return DNT_EMFILE;
    case ENFILE:        return DNT_ENFILE;
    case ENOSPC:        return DNT_ENOSPC;
    case ENOTEMPTY:     return DNT_ENOTEMPTY;
    case ENAMETOOLONG:  return DNT_ENAMETOOLONG;
    case ELOOP:         return DNT_ELOOP;
    case EINVAL:        return DNT_EINVAL;
    case ESPIPE:        return DNT_ESPIPE;
    case EROFS:         return DNT_EROFS;
    default:            return DNT_EIO;
    }
}

/* Darwin O_* -> host O_*. The numbers differ (O_CLOEXEC alone is 0x1000000
 * on Darwin and 0x80000 here), so this is a translation, never a cast. */
static int host_open_flags(int df)
{
    int f = 0;
    switch (df & DNT_O_ACCMODE) {
    case DNT_O_WRONLY: f |= O_WRONLY; break;
    case DNT_O_RDWR:   f |= O_RDWR;   break;
    default:           f |= O_RDONLY; break;
    }
    if (df & DNT_O_CREAT)     f |= O_CREAT;
    if (df & DNT_O_EXCL)      f |= O_EXCL;
    if (df & DNT_O_TRUNC)     f |= O_TRUNC;
    if (df & DNT_O_APPEND)    f |= O_APPEND;
    if (df & DNT_O_NONBLOCK)  f |= O_NONBLOCK;
    if (df & DNT_O_NOFOLLOW)  f |= O_NOFOLLOW;
#ifdef O_DIRECTORY
    if (df & DNT_O_DIRECTORY) f |= O_DIRECTORY;
#endif
    if (df & DNT_O_CLOEXEC)   f |= O_CLOEXEC;
    return f;
}

static void fill_ps(const struct stat *st, dnt_port_stat *ps)
{
    memset(ps, 0, sizeof(*ps));
    ps->size = (uint64_t)st->st_size;
    ps->ino = (uint64_t)st->st_ino;
    ps->nlink = (int32_t)st->st_nlink;
    ps->uid = (uint32_t)st->st_uid;
    ps->gid = (uint32_t)st->st_gid;
    /* Darwin mode_t is 16-bit and carries POSIX S_IF values; the host's are
     * the same bit assignments, so only the width matters. */
    ps->mode = (int32_t)(st->st_mode & 0xFFFF);
    ps->atime = (int64_t)st->st_atime;
    ps->mtime = (int64_t)st->st_mtime;
    ps->ctime = (int64_t)st->st_ctime;
    ps->birthtime = ps->mtime;
}

dnt_handle_t dnt_port_open(const char *host_path, int darwin_flags,
                           int create_mode, int *err)
{
    int fd = open(host_path, host_open_flags(darwin_flags),
                  (mode_t)(create_mode ? create_mode : 0666));
    if (fd < 0) {
        if (err) *err = map_errno(errno);
        return DNT_HANDLE_INVALID;
    }
    if (err) *err = 0;
    return fd;
}

int dnt_port_close(dnt_handle_t h)
{
    return close(h) == 0 ? 0 : DNT_EIO;
}

int64_t dnt_port_read(dnt_handle_t h, void *buf, uint64_t n, int *err)
{
    ssize_t r = read(h, buf, (size_t)n);
    if (r < 0) { if (err) *err = map_errno(errno); return -1; }
    return (int64_t)r;
}

int64_t dnt_port_write(dnt_handle_t h, const void *buf, uint64_t n, int *err)
{
    ssize_t r = write(h, buf, (size_t)n);
    if (r < 0) { if (err) *err = map_errno(errno); return -1; }
    return (int64_t)r;
}

int64_t dnt_port_seek(dnt_handle_t h, int64_t off, int whence, int *err)
{
    int w = (whence == DNT_SEEK_CUR) ? SEEK_CUR :
            (whence == DNT_SEEK_END) ? SEEK_END : SEEK_SET;
    off_t r = lseek(h, (off_t)off, w);
    if (r < 0) { if (err) *err = map_errno(errno); return -1; }
    return (int64_t)r;
}

int dnt_port_fstat(dnt_handle_t h, dnt_port_stat *st)
{
    struct stat s;
    if (fstat(h, &s) != 0)
        return DNT_EBADF;
    fill_ps(&s, st);
    return 0;
}

int dnt_port_stat_path(const char *host_path, dnt_port_stat *st, int follow)
{
    struct stat s;
    int r = follow ? stat(host_path, &s) : lstat(host_path, &s);
    if (r != 0)
        return map_errno(errno);
    fill_ps(&s, st);
    return 0;
}

int dnt_port_ftruncate(dnt_handle_t h, uint64_t size, int *err)
{
    if (ftruncate(h, (off_t)size) != 0) {
        if (err) *err = map_errno(errno);
        return -1;
    }
    return 0;
}

int dnt_port_unlink(const char *host_path)
{
    return unlink(host_path) == 0 ? 0 : map_errno(errno);
}

int dnt_port_mkdir(const char *host_path)
{
    return mkdir(host_path, 0777) == 0 ? 0 : map_errno(errno);
}

int dnt_port_rmdir(const char *host_path)
{
    return rmdir(host_path) == 0 ? 0 : map_errno(errno);
}

int dnt_port_rename(const char *from, const char *to)
{
    return rename(from, to) == 0 ? 0 : map_errno(errno);
}

int dnt_port_is_dir(const char *host_path)
{
    struct stat s;
    return stat(host_path, &s) == 0 && S_ISDIR(s.st_mode);
}

dnt_dir *dnt_port_opendir(const char *host_path, int *err)
{
    DIR *d = opendir(host_path);
    if (!d) {
        if (err) *err = map_errno(errno);
        return NULL;
    }
    dnt_dir *dd = calloc(1, sizeof(*dd));
    if (!dd) { closedir(d); if (err) *err = DNT_ENOMEM; return NULL; }
    dd->d = d;
    snprintf(dd->path, sizeof(dd->path), "%s", host_path);
    return dd;
}

static int dirent_to_type(unsigned char t)
{
    switch (t) {
    case DT_DIR:  return DNT_DT_DIR;
    case DT_REG:  return DNT_DT_REG;
    case DT_LNK:  return DNT_DT_LNK;
    case DT_FIFO: return DNT_DT_FIFO;
    case DT_CHR:  return DNT_DT_CHR;
    case DT_BLK:  return DNT_DT_BLK;
    case DT_SOCK: return DNT_DT_SOCK;
    default:      return DNT_DT_UNKNOWN;
    }
}

int dnt_port_readdir(dnt_dir *d, char *name, size_t name_cap,
                     uint64_t *ino, int *type, int *err)
{
    for (;;) {
        errno = 0;
        struct dirent *de = readdir(d->d);
        if (!de) {
            if (err) *err = map_errno(errno);
            return errno ? -1 : 0;
        }
        /* Darwin's getdirentries does report "." and ".." -- callers like ls
         * filter them themselves. Pass everything through. */
        size_t l = strlen(de->d_name);
        if (l >= name_cap)
            continue;
        memcpy(name, de->d_name, l + 1);
        if (ino) *ino = (uint64_t)de->d_ino;
        if (type) {
            int t = dirent_to_type(de->d_type);
            if (t == DNT_DT_UNKNOWN) {
                /* Overlayfs, tmpfs variants and some FUSE filesystems report
                 * DT_UNKNOWN. Darwin callers act on d_type, so resolve it
                 * rather than handing back "unknown" for a plain file. */
                char full[4096];
                int n = snprintf(full, sizeof(full), "%s/%s",
                                 d->path, name);
                struct stat sb;
                if (n > 0 && (size_t)n < sizeof(full) && lstat(full, &sb) == 0) {
                    if (S_ISDIR(sb.st_mode))  t = DNT_DT_DIR;
                    else if (S_ISREG(sb.st_mode)) t = DNT_DT_REG;
                    else if (S_ISLNK(sb.st_mode)) t = DNT_DT_LNK;
                }
            }
            *type = t;
        }
        return 1;
    }
}

int dnt_port_closedir(dnt_dir *d)
{
    if (!d) return DNT_EINVAL;
    closedir(d->d);
    free(d);
    return 0;
}

dnt_handle_t dnt_port_std_handle(int which)
{
    /* The host's descriptors already are 0/1/2; verify they are open rather
     * than assuming, so a closed stream reports EBADF like Darwin does. */
    if (which < 0 || which > 2)
        return DNT_HANDLE_INVALID;
    if (fcntl(which, F_GETFD) < 0)
        return DNT_HANDLE_INVALID;
    return which;
}

int64_t dnt_port_now(void)
{
    return (int64_t)time(NULL);
}

#endif /* !_WIN32 */
