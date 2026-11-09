#ifndef DNT_IPA_H
#define DNT_IPA_H
#include <stdint.h>
#include <stddef.h>

#define DNT_IPA_MAX_DYLIBS 512

typedef struct {
    const uint8_t *data;
    size_t         len;
    uint32_t       n_entries;
    uint32_t       cd_off;
    uint32_t       cd_size;

    char           app_dir[256];      /* "Payload/Foo.app/" */
    char           bundle_id[256];
    char           executable[256];
    char           version[64];
    char           min_os[32];
    char           display_name[128];

    /* Mach-O facts */
    int32_t        cpu;
    int            is_arm64;
    uint32_t       filetype;
    uint32_t       ncmds;
    int            has_entry;
    int            is_signed;
    int            has_encryption_info;
    uint32_t       crypt_id;
    uint32_t       crypt_size;
    uint64_t       exec_size;

    int            n_dylibs;
    char           dylibs[DNT_IPA_MAX_DYLIBS][192];
    int            n_frameworks;      /* bundled .framework dirs */

    int            plist_binary;
    int            analysis_ok;
    char           error[256];
} dnt_ipa;

int dnt_ipa_open(dnt_ipa *ipa, const uint8_t *data, size_t len);
int dnt_ipa_extract(dnt_ipa *ipa, const char *name, uint8_t **out, size_t *out_len);
const char *dnt_ipa_verdict(const dnt_ipa *ipa, char *buf, size_t cap);

#endif
