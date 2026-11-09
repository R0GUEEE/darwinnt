/* Filesystem tests against a real directory tree.
 *
 * These assert Darwin behaviour, not just "something happened": the values
 * that go back to the guest must be the ones a Darwin program expects.
 */
#include "dnt_vfs.h"
#include "dnt_path.h"
#include "dnt_abi.h"
#include "dnt_errno.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int failures;
#define CHECK(cond, ...) do { \
    if (!(cond)) { printf("FAIL: "); printf(__VA_ARGS__); printf("\n"); failures++; } \
    else { printf("ok: "); printf(__VA_ARGS__); printf("\n"); } \
} while (0)

static char g_root[512];

static void setup_tree(void)
{
    snprintf(g_root, sizeof(g_root), "/tmp/dnt_vfs_test");
    char cmd[1024];
    snprintf(cmd, sizeof(cmd), "rm -rf %s && mkdir -p %s/usr/bin %s/private/var/tmp %s/etc",
             g_root, g_root, g_root, g_root);
    if (system(cmd) != 0) { printf("setup failed\n"); exit(2); }
    /* Straight write via C stdio rather than shell quoting, which is exactly
     * the kind of thing that breaks in one environment but not another. */
    snprintf(cmd, sizeof(cmd), "%s/private/etc", g_root);
    mkdir(cmd, 0755);
    snprintf(cmd, sizeof(cmd), "%s/private/etc/motd", g_root);
    FILE *mf = fopen(cmd, "wb");
    if (mf) { fwrite("hello darwin\n", 1, 13, mf); fclose(mf); }
    snprintf(cmd, sizeof(cmd), "touch %s/usr/bin/clang", g_root);
    if (system(cmd) != 0) exit(2);
}

int main(void)
{
    setup_tree();
    if (dnt_vfs_init(g_root) != 0) { printf("init failed\n"); return 2; }

    /* ---- open / read / close ---- */
    int fd = dnt_vfs_open("/etc/motd", DNT_O_RDONLY, 0);
    CHECK(fd >= 3, "open /etc/motd -> fd %d", fd);

    char buf[64];
    int err = 0;
    int64_t n = dnt_vfs_read(fd, buf, sizeof(buf) - 1, &err);
    CHECK(n == 13, "read returned 13 bytes (got %lld)", (long long)n);
    buf[n > 0 ? n : 0] = 0;
    CHECK(strcmp(buf, "hello darwin\n") == 0, "content == 'hello darwin\\n'");
    CHECK(dnt_vfs_close(fd) == 0, "close ok");
    CHECK(dnt_vfs_close(fd) == DNT_EBADF, "double close -> EBADF");

    /* ---- the /var -> /private/var rewrite must hit one file ---- */
    fd = dnt_vfs_open("/var/tmp/probe.txt", DNT_O_CREAT | DNT_O_RDWR, 0644);
    CHECK(fd >= 3, "create via /var/tmp");
    if (fd >= 3) {
        struct stat s;
        CHECK(stat("/tmp/dnt_vfs_test/private/var/tmp/probe.txt", &s) == 0,
              "/var/tmp landed in private/var/tmp");
        dnt_vfs_close(fd);
    }

    /* ---- stat ---- */
    dnt_stat st;
    memset(&st, 0xff, sizeof(st));
    int rc = dnt_vfs_stat("/etc/motd", &st, 1);
    CHECK(rc == 0, "stat /etc/motd");
    CHECK((st.st_mode & DNT_S_IFMT) == DNT_S_IFREG, "mode has S_IFREG (0x%x)", st.st_mode);
    CHECK(st.st_size == 13, "st_size == 13 (got %lld)", (long long)st.st_size);
    CHECK(st.st_nlink >= 1, "st_nlink >= 1");
    CHECK(st.st_blksize == 4096, "st_blksize == 4096 (got %d)", st.st_blksize);
    CHECK(st.st_mtimespec.tv_sec > 1600000000, "mtime is a real Unix time");
    CHECK(sizeof(st) == 144, "struct stat is 144 bytes");

    CHECK(dnt_vfs_stat("/etc", &st, 1) == 0 &&
          (st.st_mode & DNT_S_IFMT) == DNT_S_IFDIR, "directory has S_IFDIR");
    CHECK(dnt_vfs_stat("/etc/nope", &st, 1) == DNT_ENOENT, "missing file -> ENOENT");
    CHECK(dnt_vfs_stat("/etc/motd/", &st, 1) == DNT_ENOTDIR,
          "trailing slash on a file -> ENOTDIR");
    CHECK(dnt_vfs_stat("/../etc/passwd", &st, 1) == DNT_EACCES,
          "traversal -> EACCES");

    /* ---- directory reads ---- */
    fd = dnt_vfs_open("/usr/bin", DNT_O_RDONLY, 0);
    CHECK(fd >= 3, "open /usr/bin");
    char dbuf[4096];
    int64_t base = -1;
    int64_t r = dnt_vfs_getdirentries64(fd, dbuf, sizeof(dbuf), &base);
    CHECK(r > 0, "getdirentries64 returned %lld bytes", (long long)r);

    int saw_clang = 0, saw_dot = 0, bad_reclen = 0;
    for (int64_t off = 0; off < r;) {
        dnt_dirent *de = (dnt_dirent *)(dbuf + off);
        if (de->d_reclen == 0 || de->d_reclen > 64 + 255) { bad_reclen = 1; break; }
        if (strcmp(de->d_name, "clang") == 0) { saw_clang = 1;
            if (de->d_type != DNT_DT_REG) bad_reclen = 2; }
        if (strcmp(de->d_name, ".") == 0) saw_dot = 1;
        off += de->d_reclen;
    }
    CHECK(saw_dot, "directory listing includes '.'");
    CHECK(saw_clang, "listing includes clang");
    CHECK(bad_reclen == 0, "d_reclen/d_type are sane (code %d)", bad_reclen);
    CHECK((r & 7) == 0, "records are 8-byte aligned (len %lld)", (long long)r);

    /* a second call must continue, not repeat from the start */
    char dbuf2[4096];
    int64_t r2 = dnt_vfs_getdirentries64(fd, dbuf2, sizeof(dbuf2), &base);
    CHECK(r2 == 0, "second read at EOF returns 0 (got %lld)", (long long)r2);
    dnt_vfs_close(fd);

    /* reading a directory as a file is EISDIR, like Darwin */
    fd = dnt_vfs_open("/etc", DNT_O_RDONLY, 0);
    err = 0;
    CHECK(dnt_vfs_read(fd, buf, 16, &err) < 0 && err == DNT_EISDIR,
          "read() on a directory -> EISDIR");
    dnt_vfs_close(fd);

    /* ---- write path ---- */
    fd = dnt_vfs_open("/tmp/out.txt", DNT_O_CREAT | DNT_O_TRUNC | DNT_O_WRONLY, 0644);
    CHECK(fd >= 3, "create /tmp/out.txt");
    CHECK(dnt_vfs_write(fd, "abc", 3, &err) == 3, "write 3 bytes");
    CHECK(dnt_vfs_lseek(fd, 10, DNT_SEEK_SET, &err) == 10, "lseek to 10");
    CHECK(dnt_vfs_write(fd, "z", 1, &err) == 1, "write at offset 10");
    CHECK(dnt_vfs_ftruncate(fd, 4) == 0, "ftruncate to 4");
    dnt_vfs_fstat(fd, &st);
    CHECK(st.st_size == 4, "size after truncate == 4 (got %lld)", (long long)st.st_size);
    dnt_vfs_close(fd);

    /* O_EXCL must refuse an existing file */
    fd = dnt_vfs_open("/tmp/out.txt", DNT_O_CREAT | DNT_O_EXCL | DNT_O_WRONLY, 0644);
    CHECK(fd == -DNT_EEXIST, "O_EXCL on existing -> EEXIST (got %d)", fd);

    /* ---- mkdir / rename / unlink / rmdir ---- */
    CHECK(dnt_vfs_mkdir("/tmp/d1", 0755) == 0, "mkdir");
    CHECK(dnt_vfs_mkdir("/tmp/d1", 0755) == DNT_EEXIST, "mkdir again -> EEXIST");
    CHECK(dnt_vfs_rename("/tmp/out.txt", "/tmp/d1/moved.txt") == 0, "rename into dir");
    CHECK(dnt_vfs_unlink("/tmp/d1/moved.txt") == 0, "unlink");
    CHECK(dnt_vfs_unlink("/tmp/d1/moved.txt") == DNT_ENOENT, "unlink missing -> ENOENT");
    CHECK(dnt_vfs_rmdir("/tmp/d1") == 0, "rmdir");
    CHECK(dnt_vfs_rmdir("/etc") == DNT_ENOTEMPTY || dnt_vfs_rmdir("/etc") == DNT_EIO,
          "rmdir non-empty fails");

    /* ---- chdir relative paths ---- */
    CHECK(dnt_vfs_chdir("/usr/bin") == 0, "chdir /usr/bin");
    char cwd[256];
    CHECK(dnt_vfs_getcwd(cwd, sizeof(cwd)) == 0 && strcmp(cwd, "/usr/bin") == 0,
          "getcwd == /usr/bin (got %s)", cwd);
    fd = dnt_vfs_open("clang", DNT_O_RDONLY, 0);
    CHECK(fd >= 3, "relative open 'clang' from /usr/bin");
    dnt_vfs_close(fd);
    CHECK(dnt_vfs_chdir("/usr/bin/..") == 0, "chdir with ..");
    dnt_vfs_getcwd(cwd, sizeof(cwd));
    CHECK(strcmp(cwd, "/usr") == 0, "cwd normalised to /usr (got %s)", cwd);
    CHECK(dnt_vfs_chdir("/nope") == DNT_ENOENT, "chdir missing -> ENOENT");

    printf("\n%s (%d failure%s)\n", failures ? "FAILED" : "PASSED",
           failures, failures == 1 ? "" : "s");
    return failures ? 1 : 0;
}
