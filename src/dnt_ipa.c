/* IPA inspection.
 *
 * An .ipa is a ZIP holding Payload/<Name>.app/. This answers the questions
 * that matter before anyone tries to run one:
 *
 *   1. What is it?         bundle id, version, minimum OS, executable name
 *   2. Is it runnable?     architecture, encryption state, required frameworks
 *   3. What would it need? the private frameworks the loader lacks
 *
 * It does not pretend to load or run an app. Everything reported comes from
 * the file itself: Info.plist, the Mach-O header, and the load commands.
 */
#include "dnt_ipa.h"
#include "dnt_abi.h"
#include "dnt_plist.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#endif

/* zlib is available on both targets (MinGW ships it via -lz). */
#ifdef DNT_NO_ZLIB
#define DNT_INFLATE_STUB 1
#else
#include <zlib.h>
#endif

static uint32_t rd32(const uint8_t *p) { uint32_t v; memcpy(&v, p, 4); return v; }
static uint16_t rd16(const uint8_t *p) { uint16_t v; memcpy(&v, p, 2); return v; }


static int find_eocd(const uint8_t *d, size_t n, size_t *out)
{
    if (n < 22)
        return -1;
    size_t start = n > (0xFFFFu + 22) ? n - (0xFFFFu + 22) : 0;
    for (size_t i = n - 22; ; i--) {
        if (d[i] == 'P' && d[i+1] == 'K' && d[i+2] == 5 && d[i+3] == 6) {
            *out = i;
            return 0;
        }
        if (i == start)
            break;
    }
    return -1;
}

/* Extract one central-directory entry by exact name into a malloc'd buffer.
 * Returns 0 on success. */
int dnt_ipa_extract(dnt_ipa *ipa, const char *name, uint8_t **out, size_t *out_len)
{
    const uint8_t *d = ipa->data;
    size_t n = ipa->len;
    size_t p = ipa->cd_off;
    size_t want = strlen(name);

    for (uint16_t i = 0; i < ipa->n_entries && p + 46 <= n; i++) {
        if (rd32(d + p) != 0x02014b50)
            break;
        uint16_t name_len = rd16(d + p + 28);
        uint16_t extra_len = rd16(d + p + 30);
        uint16_t comment_len = rd16(d + p + 32);
        uint16_t method = rd16(d + p + 10);
        uint32_t csize = rd32(d + p + 20);
        uint32_t usize = rd32(d + p + 24);
        uint32_t lho = rd32(d + p + 42);

        if (name_len == want && memcmp(d + p + 46, name, want) == 0) {
            if ((uint64_t)lho + 30 > n)
                return -1;
            uint16_t ln = rd16(d + lho + 26);
            uint16_t le = rd16(d + lho + 28);
            uint64_t data_off = (uint64_t)lho + 30 + ln + le;
            if (data_off + csize > n)
                return -1;

            if (method == 0) {
                uint8_t *buf = malloc(usize ? usize : 1);
                if (!buf)
                    return -1;
                memcpy(buf, d + data_off, usize);
                *out = buf;
                *out_len = usize;
                return 0;
            }
#ifndef DNT_NO_ZLIB
            if (method == 8) {
                uint8_t *buf = malloc(usize ? usize : 1);
                if (!buf)
                    return -1;
                z_stream zs;
                memset(&zs, 0, sizeof(zs));
                if (inflateInit2(&zs, -MAX_WBITS) != Z_OK) { free(buf); return -1; }
                zs.next_in = (Bytef *)(d + data_off);
                zs.avail_in = csize;
                zs.next_out = buf;
                zs.avail_out = usize;
                int r = inflate(&zs, Z_FINISH);
                inflateEnd(&zs);
                if (r != Z_STREAM_END) { free(buf); return -1; }
                *out = buf;
                *out_len = usize;
                return 0;
            }
#endif
            return -1;   /* unsupported compression: reported, not guessed */
        }
        p += 46 + name_len + extra_len + comment_len;
    }
    return -1;
}

/* Portable substring search. memmem() is a GNU extension and is absent on
 * MinGW, so the engine carries its own rather than depending on the platform. */
static const char *find_bytes(const char *hay, size_t hay_len,
                              const char *needle, size_t needle_len)
{
    if (needle_len == 0 || hay_len < needle_len)
        return NULL;
    const char *last = hay + hay_len - needle_len;
    for (const char *p = hay; p <= last; p++) {
        if (*p == needle[0] && memcmp(p, needle, needle_len) == 0)
            return p;
    }
    return NULL;
}

/* --- Info.plist: pull a handful of <key>x</key><string>y</string> pairs --- */
static void plist_str(const char *xml, size_t len, const char *key,
                      char *out, size_t cap)
{
    out[0] = 0;
    char pat[128];
    snprintf(pat, sizeof(pat), "<key>%s</key>", key);
    const char *p = find_bytes(xml, len, pat, strlen(pat));
    if (!p)
        return;
    p += strlen(pat);
    const char *end = xml + len;
    while (p < end && (*p == ' ' || *p == '\n' || *p == '\r' || *p == '\t'))
        p++;
    const char *open = find_bytes(p, (size_t)(end - p), "<string>", 8);
    if (!open)
        return;
    open += 8;
    const char *close = find_bytes(open, (size_t)(end - open), "</string>", 9);
    if (!close)
        return;
    size_t n = (size_t)(close - open);
    if (n >= cap)
        n = cap - 1;
    memcpy(out, open, n);
    out[n] = 0;
}

/* --- Mach-O analysis of the app executable --- */
static void analyse_macho(dnt_ipa *ipa, const uint8_t *m, size_t len)
{
    if (len < 32 || rd32(m) != 0xfeedfacf) {
        snprintf(ipa->error, sizeof(ipa->error), "executable is not Mach-O 64");
        return;
    }
    ipa->cpu = (int32_t)rd32(m + 4);
    ipa->is_arm64 = (ipa->cpu == 0x0100000C);
    ipa->filetype = rd32(m + 12);
    ipa->ncmds = rd32(m + 16);

    size_t off = 32;
    for (uint32_t i = 0; i < ipa->ncmds && off + 8 <= len; i++) {
        uint32_t cmd = rd32(m + off);
        uint32_t size = rd32(m + off + 4);
        if (size < 8 || off + size > len)
            break;

        switch (cmd) {
        case 0x2C: {   /* LC_ENCRYPTION_INFO_64 */
            if (size >= 20) {
                ipa->crypt_id = rd32(m + off + 16);
                ipa->crypt_size = rd32(m + off + 12);
                ipa->has_encryption_info = 1;
            }
            break;
        }
        case 0xC:      /* LC_LOAD_DYLIB */
        case 0x18:     /* LC_LOAD_WEAK_DYLIB */
        case 0x8000001F: /* LC_REEXPORT_DYLIB */
        case 0x80000018: {
            if (size >= 24) {
                uint32_t nameoff = rd32(m + off + 8);
                if (nameoff < size) {
                    const char *nm = (const char *)(m + off + nameoff);
                    size_t maxn = size - nameoff;
                    size_t n = 0;
                    while (n < maxn && nm[n])
                        n++;
                    if (ipa->n_dylibs < DNT_IPA_MAX_DYLIBS) {
                        size_t c = n < sizeof(ipa->dylibs[0]) - 1
                                       ? n : sizeof(ipa->dylibs[0]) - 1;
                        memcpy(ipa->dylibs[ipa->n_dylibs], nm, c);
                        ipa->dylibs[ipa->n_dylibs][c] = 0;
                        ipa->n_dylibs++;
                    }
                }
            }
            break;
        }
        case 0x80000028:   /* LC_MAIN */
        case 0x5:          /* LC_UNIXTHREAD */
            ipa->has_entry = 1;
            break;
        case 0x1D:         /* LC_CODE_SIGNATURE */
            ipa->is_signed = 1;
            break;
        default:
            break;
        }
        off += size;
    }
}

int dnt_ipa_open(dnt_ipa *ipa, const uint8_t *data, size_t len)
{
    memset(ipa, 0, sizeof(*ipa));
    ipa->data = data;
    ipa->len = len;

    size_t eocd;
    if (find_eocd(data, len, &eocd) != 0) {
        snprintf(ipa->error, sizeof(ipa->error), "not a ZIP archive");
        return -1;
    }
    ipa->n_entries = rd16(data + eocd + 10);
    ipa->cd_off = rd32(data + eocd + 16);
    ipa->cd_size = rd32(data + eocd + 12);
    if ((uint64_t)ipa->cd_off + ipa->cd_size > len) {
        snprintf(ipa->error, sizeof(ipa->error), "central directory outside file");
        return -1;
    }

    /* Find the app bundle directory. */
    size_t p = ipa->cd_off;
    for (uint16_t i = 0; i < ipa->n_entries && p + 46 <= len; i++) {
        if (rd32(data + p) != 0x02014b50)
            break;
        uint16_t name_len = rd16(data + p + 28);
        uint16_t extra_len = rd16(data + p + 30);
        uint16_t comment_len = rd16(data + p + 32);
        if (name_len < 512) {
            char buf[512];
            memcpy(buf, data + p + 46, name_len);
            buf[name_len] = 0;
            if (!ipa->app_dir[0] && strncmp(buf, "Payload/", 8) == 0 &&
                name_len > 9 && buf[name_len - 1] == '/') {
                /* first "Payload/<X>/" wins */
                const char *slash = strchr(buf + 8, '/');
                if (slash) {
                    size_t dlen = (size_t)(slash - buf) + 1;
                    if (dlen < sizeof(ipa->app_dir)) {
                        memcpy(ipa->app_dir, buf, dlen);
                        ipa->app_dir[dlen] = 0;
                    }
                }
            }
        }
        p += 46 + name_len + extra_len + comment_len;
    }
    if (!ipa->app_dir[0]) {
        snprintf(ipa->error, sizeof(ipa->error),
                 "no Payload/*.app/ - not an iOS app bundle");
        return -1;
    }

    /* Info.plist */
    char plist_path[512];
    snprintf(plist_path, sizeof(plist_path), "%sInfo.plist", ipa->app_dir);
    uint8_t *plist = NULL;
    size_t plist_len = 0;
    if (dnt_ipa_extract(ipa, plist_path, &plist, &plist_len) == 0) {
        /* Real IPAs ship binary plists; accept XML too, since sideload tooling
         * sometimes rewrites them. */
        int binary = (plist_len > 8 && memcmp(plist, "bplist00", 8) == 0);
        struct { const char *key; char *dst; size_t cap; } fields[] = {
            { "CFBundleIdentifier",         ipa->bundle_id,   sizeof(ipa->bundle_id) },
            { "CFBundleExecutable",         ipa->executable,  sizeof(ipa->executable) },
            { "CFBundleShortVersionString", ipa->version,     sizeof(ipa->version) },
            { "MinimumOSVersion",           ipa->min_os,      sizeof(ipa->min_os) },
            { "CFBundleDisplayName",        ipa->display_name,sizeof(ipa->display_name) },
        };
        ipa->plist_binary = binary;
        for (size_t f = 0; f < sizeof(fields)/sizeof(fields[0]); f++) {
            if (binary)
                dnt_plist_bin_lookup(plist, plist_len, fields[f].key,
                                     fields[f].dst, fields[f].cap);
            else
                plist_str((const char *)plist, plist_len, fields[f].key,
                          fields[f].dst, fields[f].cap);
        }
        free(plist);
    }
    if (!ipa->executable[0]) {
        snprintf(ipa->error, sizeof(ipa->error),
                 "Info.plist has no CFBundleExecutable");
        return -1;
    }

    /* The executable itself. */
    char exe_path[512];
    snprintf(exe_path, sizeof(exe_path), "%s%s", ipa->app_dir, ipa->executable);
    uint8_t *exe = NULL;
    size_t exe_len = 0;
    if (dnt_ipa_extract(ipa, exe_path, &exe, &exe_len) == 0) {
        ipa->exec_size = exe_len;
        analyse_macho(ipa, exe, exe_len);
        free(exe);
        ipa->analysis_ok = 1;
    } else {
        snprintf(ipa->error, sizeof(ipa->error),
                 "cannot extract %.200s", exe_path);
    }

    /* Count bundled frameworks for the report. */
    p = ipa->cd_off;
    for (uint16_t i = 0; i < ipa->n_entries && p + 46 <= len; i++) {
        if (rd32(data + p) != 0x02014b50)
            break;
        uint16_t name_len = rd16(data + p + 28);
        uint16_t extra_len = rd16(data + p + 30);
        uint16_t comment_len = rd16(data + p + 32);
        if (name_len < 512) {
            char buf[512];
            memcpy(buf, data + p + 46, name_len);
            buf[name_len] = 0;
            if (strstr(buf, ".framework/") && strstr(buf, ".framework/") == strrchr(buf, '.'))
                ipa->n_frameworks++;
        }
        p += 46 + name_len + extra_len + comment_len;
    }
    return 0;
}

/* The verdict, stated in one sentence. */
const char *dnt_ipa_verdict(const dnt_ipa *ipa, char *buf, size_t cap)
{
    if (!ipa->analysis_ok) {
        snprintf(buf, cap, "unreadable: %s", ipa->error);
        return buf;
    }
    if (!ipa->is_arm64) {
        snprintf(buf, cap, "not arm64 (cpu %#x) - cannot execute", ipa->cpu);
        return buf;
    }
    if (ipa->has_encryption_info && ipa->crypt_id != 0) {
        snprintf(buf, cap,
                 "App Store encrypted binary (cryptid %u). Its __TEXT is "
                 "ciphertext tied to the device key; it cannot be loaded.",
                 ipa->crypt_id);
        return buf;
    }
    if (ipa->n_dylibs > 0) {
        snprintf(buf, cap,
                 "needs %d private frameworks (UIKit, Foundation, ...). "
                 "darwinnt provides %d libSystem symbols and no frameworks, "
                 "so this is an app, not a runnable program.",
                 ipa->n_dylibs, 27);
        return buf;
    }
    snprintf(buf, cap, "no dynamic dependencies - a candidate for execution");
    return buf;
}
