/* Win32 implementation of the host port layer.
 *
 * Differences from the POSIX backend that matter, and how each is handled:
 *
 *  - HANDLE, not fd. Duplication and inheritance work differently.
 *  - No "delete on open". DeleteFileW fails while a handle is open, which is
 *    fine: Darwin's unlink of an open file is rare in CLI tools, and pretending
 *    otherwise would be worse than returning EBUSY.
 *  - Directory iteration needs FindFirstFileW and a restart to seek, so the
 *    position is a count/offset pair we replay.
 *  - FILETIME (100ns from 1601) -> Unix seconds, the same conversion as
 *    dnt_win.c; kept local so the port layer has no dependency on the runtime.
 */
#ifdef _WIN32

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

#include "dnt_port.h"
#include "dnt_abi.h"
#include "dnt_errno.h"

static dnt_out_fn g_out;
static void *g_out_user;

void dnt_port_set_output(dnt_out_fn fn, void *user)
{
    g_out = fn;
    g_out_user = user;
}


struct dnt_dir {
    HANDLE            find;
    WIN32_FIND_DATAW  fd;
    int               first;
    int               done;
    char              pattern[4096];
};

static int err_from_win(DWORD e)
{
    switch (e) {
    case ERROR_FILE_NOT_FOUND:
    case ERROR_PATH_NOT_FOUND:   return DNT_ENOENT;
    case ERROR_ACCESS_DENIED:    return DNT_EACCES;
    case ERROR_SHARING_VIOLATION:return DNT_EBUSY;
    case ERROR_FILE_EXISTS:
    case ERROR_ALREADY_EXISTS:   return DNT_EEXIST;
    case ERROR_INVALID_HANDLE:   return DNT_EBADF;
    case ERROR_TOO_MANY_OPEN_FILES: return DNT_EMFILE;
    case ERROR_DISK_FULL:        return DNT_ENOSPC;
    case ERROR_DIR_NOT_EMPTY:    return DNT_ENOTEMPTY;
    case ERROR_FILENAME_EXCED_RANGE: return DNT_ENAMETOOLONG;
    case ERROR_INVALID_PARAMETER:return DNT_EINVAL;
    default:                     return DNT_EIO;
    }
}

static int64_t filetime_to_unix(const FILETIME *ft)
{
    ULARGE_INTEGER u;
    u.LowPart = ft->dwLowDateTime;
    u.HighPart = ft->dwHighDateTime;
    if (u.QuadPart == 0)
        return 0;
    uint64_t t = u.QuadPart - 116444736000000000ull;
    return (int64_t)(t / 10000000ull);
}

static DWORD win_access(int darwin_flags)
{
    int acc = darwin_flags & DNT_O_ACCMODE;
    if (acc == DNT_O_WRONLY) return GENERIC_WRITE;
    if (acc == DNT_O_RDWR)   return GENERIC_READ | GENERIC_WRITE;
    return GENERIC_READ;
}

static DWORD win_disposition(int darwin_flags)
{
    int exists_ok = !(darwin_flags & DNT_O_CREAT);
    int excl = (darwin_flags & DNT_O_EXCL) != 0;
    if (darwin_flags & DNT_O_TRUNC) {
        if (excl) return CREATE_NEW;
        return exists_ok ? TRUNCATE_EXISTING : CREATE_ALWAYS;
    }
    if (darwin_flags & DNT_O_CREAT)
        return excl ? CREATE_NEW : OPEN_ALWAYS;
    return OPEN_EXISTING;
}

dnt_handle_t dnt_port_open(const char *host_path, int darwin_flags,
                           int create_mode, int *err)
{
    (void)create_mode;
    wchar_t wpath[4096];
    if (!MultiByteToWideChar(CP_UTF8, 0, host_path, -1, wpath,
                             (int)(sizeof(wpath) / sizeof(wpath[0])))) {
        if (err) *err = DNT_EINVAL;
        return DNT_HANDLE_INVALID;
    }

    DWORD access = win_access(darwin_flags);
    if (access & GENERIC_READ) access |= FILE_READ_ATTRIBUTES;

    HANDLE h = CreateFileW(wpath, access, FILE_SHARE_READ | FILE_SHARE_WRITE,
                           NULL, win_disposition(darwin_flags),
                           FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) {
        if (err) *err = err_from_win(GetLastError());
        return DNT_HANDLE_INVALID;
    }
    if (darwin_flags & DNT_O_APPEND)
        SetFilePointer(h, 0, NULL, FILE_END);
    if (err) *err = 0;
    return (dnt_handle_t)h;
}

int dnt_port_close(dnt_handle_t h)
{
    return CloseHandle((HANDLE)h) ? 0 : DNT_EIO;
}

int64_t dnt_port_read(dnt_handle_t h, void *buf, uint64_t n, int *err)
{
    DWORD got = 0;
    if (!ReadFile((HANDLE)h, buf, (DWORD)n, &got, NULL)) {
        if (err) *err = err_from_win(GetLastError());
        return -1;
    }
    return (int64_t)got;
}

int64_t dnt_port_write(dnt_handle_t h, const void *buf, uint64_t n, int *err)
{
    if (g_out) {
        HANDLE sh = (HANDLE)h;
        if (sh == GetStdHandle(STD_OUTPUT_HANDLE) || sh == GetStdHandle(STD_ERROR_HANDLE)) {
            g_out(sh == GetStdHandle(STD_OUTPUT_HANDLE) ? 1 : 2,
                  (const char *)buf, n, g_out_user);
            return (int64_t)n;
        }
    }
    DWORD put = 0;
    if (!WriteFile((HANDLE)h, buf, (DWORD)n, &put, NULL)) {
        if (err) *err = err_from_win(GetLastError());
        return -1;
    }
    return (int64_t)put;
}

int64_t dnt_port_seek(dnt_handle_t h, int64_t off, int whence, int *err)
{
    DWORD mv = (whence == DNT_SEEK_CUR) ? FILE_CURRENT :
               (whence == DNT_SEEK_END) ? FILE_END : FILE_BEGIN;
    LARGE_INTEGER li;
    li.QuadPart = off;
    li.LowPart = SetFilePointer((HANDLE)h, li.LowPart, &li.HighPart, mv);
    if (li.LowPart == INVALID_SET_FILE_POINTER && GetLastError() != NO_ERROR) {
        if (err) *err = err_from_win(GetLastError());
        return -1;
    }
    return (int64_t)li.QuadPart;
}

static void fill_from_by_handle(HANDLE h, dnt_port_stat *st)
{
    BY_HANDLE_FILE_INFORMATION bi;
    memset(st, 0, sizeof(*st));
    if (!GetFileInformationByHandle(h, &bi)) {
        st->mode = DNT_S_IFREG | 0644;
        return;
    }
    st->size = ((uint64_t)bi.nFileSizeHigh << 32) | bi.nFileSizeLow;
    st->ino = ((uint64_t)bi.nFileIndexHigh << 32) | bi.nFileIndexLow;
    st->nlink = (int32_t)bi.nNumberOfLinks;
    st->mtime = filetime_to_unix(&bi.ftLastWriteTime);
    st->atime = filetime_to_unix(&bi.ftLastAccessTime);
    st->ctime = filetime_to_unix(&bi.ftCreationTime);
    st->birthtime = filetime_to_unix(&bi.ftCreationTime);
    if (bi.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
        st->mode = DNT_S_IFDIR | 0755;
    else
        st->mode = DNT_S_IFREG | ((bi.dwFileAttributes & FILE_ATTRIBUTE_READONLY)
                                  ? 0444 : 0644);
}

int dnt_port_fstat(dnt_handle_t h, dnt_port_stat *st)
{
    if (h == DNT_HANDLE_INVALID) {
        st->mode = DNT_S_IFCHR | 0620;
        return 0;
    }
    fill_from_by_handle((HANDLE)h, st);
    return 0;
}

int dnt_port_stat_path(const char *host_path, dnt_port_stat *st, int follow)
{
    (void)follow;
    wchar_t wpath[4096];
    if (!MultiByteToWideChar(CP_UTF8, 0, host_path, -1, wpath,
                             (int)(sizeof(wpath) / sizeof(wpath[0]))))
        return DNT_EINVAL;

    WIN32_FILE_ATTRIBUTE_DATA fa;
    if (!GetFileAttributesExW(wpath, GetFileExInfoStandard, &fa))
        return err_from_win(GetLastError());

    memset(st, 0, sizeof(*st));
    st->size = ((uint64_t)fa.nFileSizeHigh << 32) | fa.nFileSizeLow;
    st->mtime = filetime_to_unix(&fa.ftLastWriteTime);
    st->atime = filetime_to_unix(&fa.ftLastAccessTime);
    st->ctime = filetime_to_unix(&fa.ftCreationTime);
    st->birthtime = st->ctime;
    st->nlink = 1;
    st->ino = 0;   /* filled from the handle when one is open */
    st->mode = (fa.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
                   ? (DNT_S_IFDIR | 0755)
                   : (DNT_S_IFREG | ((fa.dwFileAttributes & FILE_ATTRIBUTE_READONLY)
                                     ? 0444 : 0644));
    return 0;
}

int dnt_port_ftruncate(dnt_handle_t h, uint64_t size, int *err)
{
    LARGE_INTEGER li;
    li.QuadPart = (LONGLONG)size;
    if (!SetFilePointerEx((HANDLE)h, li, NULL, FILE_BEGIN) ||
        !SetEndOfFile((HANDLE)h)) {
        if (err) *err = err_from_win(GetLastError());
        return -1;
    }
    return 0;
}

static int wide_call(int which, const char *a, const char *b)
{
    wchar_t wa[4096], wb[4096];
    MultiByteToWideChar(CP_UTF8, 0, a, -1, wa, 4096);
    if (b)
        MultiByteToWideChar(CP_UTF8, 0, b, -1, wb, 4096);
    BOOL ok = FALSE;
    switch (which) {
    case 0:  ok = DeleteFileW(wa);   break;
    case 1:  ok = CreateDirectoryW(wa, NULL); break;
    case 2:  ok = RemoveDirectoryW(wa); break;
    case 3:  ok = MoveFileExW(wa, wb, MOVEFILE_REPLACE_EXISTING); break;
    case 4: {
        DWORD attr = GetFileAttributesW(wa);
        return (attr != INVALID_FILE_ATTRIBUTES &&
                (attr & FILE_ATTRIBUTE_DIRECTORY)) ? 1 : 0;
    }
    }
    return ok ? 0 : err_from_win(GetLastError());
}

int dnt_port_unlink(const char *host_path) { return wide_call(0, host_path, NULL); }
/* CreateDirectoryW makes exactly one level. The VFS asks for one directory at
 * a time, but the parent set above it may not exist yet on a fresh root (and
 * an API caller doing mkdir("/a/b/c") expects Darwin's ENOENT-with-parent-
 * missing only when it asked for that). Creating the chain here keeps the
 * contract the POSIX backend already satisfies. */
int dnt_port_mkdir(const char *host_path)
{
    wchar_t w[4096];
    if (!MultiByteToWideChar(CP_UTF8, 0, host_path, -1, w, 4096))
        return DNT_EINVAL;

    for (wchar_t *p = w + 1; *p; p++) {
        if (*p != L'\\' && *p != L'/')
            continue;
        wchar_t save = *p;
        *p = 0;
        if (wcslen(w) > 3 || (wcslen(w) == 3 && w[1] != L':'))
            CreateDirectoryW(w, NULL);   /* EEXIST / ENOENT handled below */
        *p = save;
    }
    if (CreateDirectoryW(w, NULL))
        return 0;
    DWORD e = GetLastError();
    if (e == ERROR_ALREADY_EXISTS) {
        DWORD attr = GetFileAttributesW(w);
        if (attr != INVALID_FILE_ATTRIBUTES && (attr & FILE_ATTRIBUTE_DIRECTORY))
            return DNT_EEXIST;   /* exists as a directory: caller's problem */
    }
    return err_from_win(e);
}
int dnt_port_rmdir(const char *host_path)  { return wide_call(2, host_path, NULL); }
int dnt_port_rename(const char *f, const char *t) { return wide_call(3, f, t); }
int dnt_port_is_dir(const char *host_path) { return wide_call(4, host_path, NULL); }

dnt_dir *dnt_port_opendir(const char *host_path, int *err)
{
    dnt_dir *d = calloc(1, sizeof(*d));
    if (!d) { if (err) *err = DNT_ENOMEM; return NULL; }
    snprintf(d->pattern, sizeof(d->pattern), "%s\\*", host_path);
    wchar_t wpat[4096];
    if (!MultiByteToWideChar(CP_UTF8, 0, d->pattern, -1, wpat, 4096)) {
        free(d); if (err) *err = DNT_EINVAL; return NULL;
    }
    d->find = FindFirstFileW(wpat, &d->fd);
    if (d->find == INVALID_HANDLE_VALUE) {
        /* An empty directory is not an error for opendir. */
        DWORD e = GetLastError();
        if (e == ERROR_FILE_NOT_FOUND) { d->done = 1; d->find = INVALID_HANDLE_VALUE; }
        else { free(d); if (err) *err = err_from_win(e); return NULL; }
    }
    d->first = 1;
    return d;
}

int dnt_port_readdir(dnt_dir *d, char *name, size_t name_cap,
                     uint64_t *ino, int *type, int *err)
{
    if (d->done)
        return 0;
    if (!d->first) {
        if (!FindNextFileW(d->find, &d->fd)) { d->done = 1; return 0; }
    }
    d->first = 0;
    if (WideCharToMultiByte(CP_UTF8, 0, d->fd.cFileName, -1, name,
                            (int)name_cap, NULL, NULL) == 0) {
        if (err) *err = DNT_EILSEQ;
        return -1;
    }
    if (ino) *ino = 0;
    if (type) {
        if (d->fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
            *type = DNT_DT_DIR;
        else
            *type = DNT_DT_REG;
    }
    return 1;
}

int dnt_port_closedir(dnt_dir *d)
{
    if (!d) return DNT_EINVAL;
    if (d->find != INVALID_HANDLE_VALUE)
        FindClose(d->find);
    free(d);
    return 0;
}

dnt_handle_t dnt_port_std_handle(int which)
{
    DWORD id;
    switch (which) {
    case 0:  id = STD_INPUT_HANDLE;  break;
    case 1:  id = STD_OUTPUT_HANDLE; break;
    case 2:  id = STD_ERROR_HANDLE;  break;
    default: return DNT_HANDLE_INVALID;
    }
    HANDLE h = GetStdHandle(id);
    if (h == INVALID_HANDLE_VALUE || h == NULL)
        return DNT_HANDLE_INVALID;
    /* Do NOT close these: they belong to the process, not to the fd table. */
    return (dnt_handle_t)h;
}

int64_t dnt_port_now(void)
{
    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);
    return filetime_to_unix(&ft);
}

#endif /* _WIN32 */
