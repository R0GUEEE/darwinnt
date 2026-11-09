#ifndef DNT_VFS_H
#define DNT_VFS_H
#include <stdint.h>
#include <stddef.h>
#include "dnt_abi.h"
#include "dnt_port.h"

#define DNT_MAX_FDS 256


typedef struct {
    int          in_use;
    int          fd;
    int          flags;          /* Darwin O_* as passed to open */
    int          is_dir;
    int          is_tty;
    int64_t      dirpos;         /* byte offset for getdirentries64 */
    dnt_handle_t handle;
    dnt_dir     *dir;
    dnt_port_stat stat;
    char         host_path[1088];
} dnt_fd;

int  dnt_vfs_init(const char *root);
const char *dnt_vfs_root(void);
const char *dnt_vfs_cwd(void);
dnt_fd *dnt_vfs_get(int fd);

int  dnt_vfs_open(const char *guest_path, int flags, int mode);
int  dnt_vfs_close(int fd);
int64_t dnt_vfs_read(int fd, void *buf, uint64_t n, int *err);
int64_t dnt_vfs_write(int fd, const void *buf, uint64_t n, int *err);
int64_t dnt_vfs_lseek(int fd, int64_t off, int whence, int *err);
int  dnt_vfs_fstat(int fd, dnt_stat *out);
int  dnt_vfs_stat(const char *guest_path, dnt_stat *out, int follow);
int  dnt_vfs_unlink(const char *guest_path);
int  dnt_vfs_mkdir(const char *guest_path, int mode);
int  dnt_vfs_rmdir(const char *guest_path);
int  dnt_vfs_rename(const char *from, const char *to);
int  dnt_vfs_ftruncate(int fd, uint64_t size);
int  dnt_vfs_chdir(const char *guest_path);
int  dnt_vfs_getcwd(char *buf, size_t cap);
int64_t dnt_vfs_getdirentries64(int fd, void *buf, uint64_t bufsize, int64_t *basep);

#endif
