#ifndef DNT_PORT_H
#define DNT_PORT_H
/* Minimal host file API the VFS is written against.
 *
 * Deliberately not "just use CRTs": the Darwin layer needs handle-based
 * operations (fstat without reopening, truncate by handle, delete-on-close)
 * and the tests need to run on Linux. One narrow interface, two backends:
 * dnt_port_win.c and dnt_port_posix.c.
 */
#include <stdint.h>
#include <stddef.h>

#ifdef _WIN32
typedef void *dnt_handle_t;
#define DNT_HANDLE_INVALID ((void *)(intptr_t)-1)
#else
#include <sys/types.h>
typedef int dnt_handle_t;
#define DNT_HANDLE_INVALID (-1)
#endif

typedef struct {
    uint64_t size;
    uint64_t ino;
    int32_t  mode;        /* POSIX st_mode bits (DNT_S_IF* + permissions) */
    int32_t  nlink;
    uint32_t uid, gid;
    int64_t  atime, mtime, ctime, birthtime;  /* Unix seconds */
    int64_t  birthtime_nsec;
} dnt_port_stat;

enum {
    DNT_SEEK_SET = 0,
    DNT_SEEK_CUR = 1,
    DNT_SEEK_END = 2,
};

/* Returns DNT_HANDLE_INVALID on failure and sets *err to a Darwin errno. */
dnt_handle_t dnt_port_open(const char *host_path, int darwin_flags,
                           int create_mode, int *err);
int  dnt_port_close(dnt_handle_t h);
int64_t dnt_port_read(dnt_handle_t h, void *buf, uint64_t n, int *err);
int64_t dnt_port_write(dnt_handle_t h, const void *buf, uint64_t n, int *err);
int64_t dnt_port_seek(dnt_handle_t h, int64_t off, int whence, int *err);
int  dnt_port_fstat(dnt_handle_t h, dnt_port_stat *st);
int  dnt_port_stat_path(const char *host_path, dnt_port_stat *st, int follow);
int  dnt_port_ftruncate(dnt_handle_t h, uint64_t size, int *err);
int  dnt_port_unlink(const char *host_path);
int  dnt_port_mkdir(const char *host_path);
int  dnt_port_rmdir(const char *host_path);
int  dnt_port_rename(const char *from, const char *to);
int  dnt_port_is_dir(const char *host_path);

/* Directory iteration. `cookie` is an opaque host value; returns 1 on entry,
 * 0 at end, negative Darwin errno on failure. */
typedef struct dnt_dir dnt_dir;
dnt_dir *dnt_port_opendir(const char *host_path, int *err);
int      dnt_port_readdir(dnt_dir *d, char *name, size_t name_cap,
                          uint64_t *ino, int *type, int *err);
int      dnt_port_closedir(dnt_dir *d);

/* Host handle for guest fd 0/1/2. Returns DNT_HANDLE_INVALID if the stream
 * is closed, so writes to it fail with EBADF exactly as on Darwin. */
dnt_handle_t dnt_port_std_handle(int which);

/* Pre-1970-clamped current time in Unix seconds. */
int64_t dnt_port_now(void);

#endif
