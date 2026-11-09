/* Core ABI definitions for Darwin binaries running under darwinnt.
 *
 * All types here are the *guest* types as laid out by a 64-bit Darwin
 * (inode64, LP64, little-endian). They must never be replaced by the
 * Windows equivalents: the whole point of the layer is to hand the guest
 * bytes in exactly the shape its libSystem expects.
 */
#ifndef DNT_ABI_H
#define DNT_ABI_H

#include <stdint.h>
#include <stddef.h>

#ifdef _WIN32
#define DNT_EXPORT __declspec(dllexport)
#else
#define DNT_EXPORT __attribute__((visibility("default")))
#endif

/* ---- Darwin scalar types (LP64, sizes verified against xnu bsd/sys/_types.h) ----
 * dev_t=int32 mode_t=uint16 nlink_t=uint16 ino64_t=uint64 uid/gid=uint32
 * blkcnt_t=int64 blksize_t=int32 off_t=int64
 * mode_t being 16-bit (not 32) is the classic porting trap here: it pulls
 * st_nlink up to offset 6 and st_ino to 8.
 */
typedef int64_t dnt_off_t;
typedef int32_t dnt_pid_t;
typedef uint32_t dnt_uid_t;
typedef uint32_t dnt_gid_t;
typedef uint16_t dnt_mode_t;
typedef uint16_t dnt_nlink_t;
typedef uint64_t dnt_ino_t;
typedef int32_t dnt_dev_t;
typedef int64_t dnt_blkcnt_t;
typedef int32_t dnt_blksize_t;
typedef uint64_t dnt_user_addr_t;
typedef uint64_t dnt_user_size_t;
typedef uint64_t dnt_size_t;
typedef int64_t dnt_ssize_t;
typedef int32_t dnt_sigset_word;

/* Darwin time_t is int64 even on ILP32; suseconds_t is int32. */
typedef int64_t dnt_time_t;
typedef int32_t dnt_suseconds_t;

typedef struct {
    dnt_time_t tv_sec;
    dnt_suseconds_t tv_usec;
} dnt_timeval;

typedef struct {
    dnt_time_t tv_sec;
    int64_t tv_nsec;
} dnt_timespec;

/* ---- struct stat (__DARWIN_STRUCT_STAT64, 144 bytes) ----
 * Offsets: dev0 mode4 nlink6 ino8 uid16 gid20 rdev24 atime32 mtime48
 * ctime64 birthtime80 size96 blocks104 blksize112 flags116 gen120.
 */
typedef struct {
    dnt_dev_t st_dev;          /* 0  */
    dnt_mode_t st_mode;        /* 4  */
    dnt_nlink_t st_nlink;      /* 6  */
    dnt_ino_t st_ino;          /* 8  */
    dnt_uid_t st_uid;          /* 16 */
    dnt_gid_t st_gid;          /* 20 */
    dnt_dev_t st_rdev;         /* 24 */
    uint32_t _st_pad0;         /* 28 */
    dnt_timespec st_atimespec; /* 32 */
    dnt_timespec st_mtimespec; /* 48 */
    dnt_timespec st_ctimespec; /* 64 */
    dnt_timespec st_birthtimespec; /* 80 */
    dnt_off_t st_size;         /* 96 */
    dnt_blkcnt_t st_blocks;    /* 104 */
    dnt_blksize_t st_blksize;  /* 112 */
    uint32_t st_flags;         /* 116 */
    uint32_t st_gen;           /* 120 */
    int32_t st_lspare;         /* 124 */
    int64_t st_qspare[2];      /* 128 */
} dnt_stat;

_Static_assert(sizeof(dnt_stat) == 144, "dnt_stat must be 144 bytes");
_Static_assert(offsetof(dnt_stat, st_ino) == 8, "st_ino offset");
_Static_assert(offsetof(dnt_stat, st_atimespec) == 32, "st_atimespec offset");
_Static_assert(offsetof(dnt_stat, st_size) == 96, "st_size offset");
_Static_assert(offsetof(dnt_stat, st_blksize) == 112, "st_blksize offset");

/* ---- struct dirent (64-bit ino variant, 1048 bytes) ---- */
#define DNT_MAXPATHLEN 1024
#define DNT_MAXNAMLEN  255

typedef struct {
    dnt_ino_t d_ino;
    uint64_t d_seekoff;
    uint16_t d_reclen;
    uint16_t d_namlen;
    uint8_t d_type;
    char d_name[DNT_MAXPATHLEN];
} dnt_dirent;

_Static_assert(offsetof(dnt_dirent, d_name) == 21, "d_name offset");

/* ---- iovec ---- */
typedef struct {
    void *iov_base;
    dnt_size_t iov_len;
} dnt_iovec;

/* ---- open flags (Darwin values, not Windows/glibc) ---- */
#define DNT_O_RDONLY   0x0000
#define DNT_O_WRONLY   0x0001
#define DNT_O_RDWR     0x0002
#define DNT_O_ACCMODE  0x0003
#define DNT_O_NONBLOCK 0x0004
#define DNT_O_APPEND   0x0008
#define DNT_O_SHLOCK   0x0010
#define DNT_O_EXLOCK   0x0020
#define DNT_O_ASYNC    0x0040
#define DNT_O_SYNC     0x0080
#define DNT_O_NOFOLLOW 0x0100
#define DNT_O_CREAT    0x0200
#define DNT_O_TRUNC    0x0400
#define DNT_O_EXCL     0x0800
#define DNT_O_EVTONLY  0x8000
#define DNT_O_CLOEXEC  0x1000000

/* ---- mmap flags ---- */
#define DNT_PROT_NONE  0x00
#define DNT_PROT_READ  0x01
#define DNT_PROT_WRITE 0x02
#define DNT_PROT_EXEC  0x04
#define DNT_MAP_SHARED    0x0001
#define DNT_MAP_PRIVATE   0x0002
#define DNT_MAP_FIXED     0x0010
#define DNT_MAP_ANON      0x1000
#define DNT_MAP_FD        0x2000
#define DNT_MAP_FAILED    ((void *)-1)

/* ---- file type bits (st_mode) ---- */
#define DNT_S_IFMT   0170000
#define DNT_S_IFIFO  0010000
#define DNT_S_IFCHR  0020000
#define DNT_S_IFDIR  0040000
#define DNT_S_IFBLK  0060000
#define DNT_S_IFREG  0100000
#define DNT_S_IFLNK  0120000
#define DNT_S_IFSOCK 0140000

/* ---- dirent d_type ---- */
#define DNT_DT_UNKNOWN 0
#define DNT_DT_FIFO    1
#define DNT_DT_CHR     2
#define DNT_DT_DIR     4
#define DNT_DT_BLK     6
#define DNT_DT_REG     8
#define DNT_DT_LNK     10
#define DNT_DT_SOCK    12
#define DNT_DT_WHT     14

/* Darwin diagnostic strings allocated on the guest heap by errno shims. */
#define DNT_MACH_ERR_MAX 108

#endif /* DNT_ABI_H */
