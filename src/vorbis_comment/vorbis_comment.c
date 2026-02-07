/*
 * vorbis_comment.c – Vorbis Comment parsing and serialization
 */

#include "vorbis_comment.h"
#include "../util/string_util.h"

#include <stdlib.h>
#include <string.h>
#include <ctype.h>

/* ── Little-endian helpers ───────────────────────────────────────────── */

static uint32_t read_le32(const uint8_t *p)
{
    return (uint32_t)p[0]
         | (uint32_t)p[1] << 8
         | (uint32_t)p[2] << 16
         | (uint32_t)p[3] << 24;
}

/* ── Name mapping table ──────────────────────────────────────────────── */

typedef struct { const char *canonical; const char *vc; } name_map_t;

static const name_map_t name_map[] = {
    { "TRACK_NUMBER",      "TRACKNUMBER"      },
    { "DISC_NUMBER",       "DISCNUMBER"       },
    { "DATE_RELEASED",     "DATE"             },
    { "ALBUM_ARTIST",      "ALBUMARTIST"      },
    { "ENCODED_BY",        "ENCODED-BY"       },
    { "SORT_TITLE",        "TITLESORT"        },
    { "SORT_ARTIST",       "ARTISTSORT"       },
    { "SORT_ALBUM",        "ALBUMSORT"        },
    { "SORT_ALBUM_ARTIST", "ALBUMARTISTSORT"  },
    { "ORIGINAL_DATE",     "ORIGINALDATE"     },
    { "PUBLISHER",         "ORGANIZATION"     },
    { NULL, NULL }
};

const char *vc_name_to_canonical(const char *vc_name)
{
    for (const name_map_t *m = name_map; m->canonical; m++)
        if (str_casecmp(vc_name, m->vc) == 0)
            return m->canonical;
    return vc_name;
}

const char *vc_name_from_canonical(const char *canonical)
{
    for (const name_map_t *m = name_map; m->canonical; m++)
        if (str_casecmp(canonical, m->canonical) == 0)
            return m->vc;
    return canonical;
}

/* ── Parse ───────────────────────────────────────────────────────────── */

int vc_parse(const uint8_t *data, size_t size, vorbis_comment_t *vc)
{
    memset(vc, 0, sizeof(*vc));
    const uint8_t *p   = data;
    const uint8_t *end = data + size;

    /* Vendor string */
    if (p + 4 > end) return -1;
    uint32_t vendor_len = read_le32(p); p += 4;
    if (p + vendor_len > end) return -1;
    vc->vendor = (char *)malloc(vendor_len + 1);
    if (!vc->vendor) return -1;
    memcpy(vc->vendor, p, vendor_len);
    vc->vendor[vendor_len] = '\0';
    p += vendor_len;

    /* Comment count */
    if (p + 4 > end) { free(vc->vendor); vc->vendor = NULL; return -1; }
    uint32_t count = read_le32(p); p += 4;

    vc->keys   = (char **)calloc(count, sizeof(char *));
    vc->values = (char **)calloc(count, sizeof(char *));
    if (count && (!vc->keys || !vc->values)) { vc_free(vc); return -1; }

    for (uint32_t i = 0; i < count; i++) {
        if (p + 4 > end) { vc_free(vc); return -1; }
        uint32_t len = read_le32(p); p += 4;
        if (p + len > end) { vc_free(vc); return -1; }

        /* Find '=' separator */
        const uint8_t *eq = (const uint8_t *)memchr(p, '=', len);
        if (!eq) {
            /* Malformed – store whole string as key with empty value */
            vc->keys[i]   = (char *)malloc(len + 1);
            if (vc->keys[i]) { memcpy(vc->keys[i], p, len); vc->keys[i][len] = '\0'; }
            vc->values[i] = str_dup("");
        } else {
            size_t klen = (size_t)(eq - p);
            size_t vlen = len - klen - 1;
            vc->keys[i]   = (char *)malloc(klen + 1);
            vc->values[i] = (char *)malloc(vlen + 1);
            if (vc->keys[i])   { memcpy(vc->keys[i], p, klen);       vc->keys[i][klen]   = '\0'; }
            if (vc->values[i]) { memcpy(vc->values[i], eq + 1, vlen); vc->values[i][vlen] = '\0'; }
        }

        /* Uppercase the key */
        if (vc->keys[i]) {
            for (char *c = vc->keys[i]; *c; c++)
                *c = (char)toupper((unsigned char)*c);
        }

        vc->count++;
        p += len;
    }
    return 0;
}

/* ── Serialize ───────────────────────────────────────────────────────── */

int vc_serialize(const vorbis_comment_t *vc, dyn_buffer_t *buf)
{
    const char *vendor = vc->vendor ? vc->vendor : "liboggtag";
    uint32_t vendor_len = (uint32_t)strlen(vendor);
    if (buf_append_le32(buf, vendor_len) < 0) return -1;
    if (buf_append(buf, vendor, vendor_len) < 0) return -1;

    if (buf_append_le32(buf, (uint32_t)vc->count) < 0) return -1;

    for (size_t i = 0; i < vc->count; i++) {
        const char *key = vc->keys[i] ? vc->keys[i] : "";
        const char *val = vc->values[i] ? vc->values[i] : "";
        uint32_t klen = (uint32_t)strlen(key);
        uint32_t vlen = (uint32_t)strlen(val);
        uint32_t total = klen + 1 + vlen;  /* KEY=VALUE */
        if (buf_append_le32(buf, total) < 0) return -1;
        if (buf_append(buf, key, klen) < 0) return -1;
        if (buf_append_u8(buf, '=') < 0) return -1;
        if (buf_append(buf, val, vlen) < 0) return -1;
    }
    return 0;
}

/* ── Free ────────────────────────────────────────────────────────────── */

void vc_free(vorbis_comment_t *vc)
{
    free(vc->vendor);
    for (size_t i = 0; i < vc->count; i++) {
        free(vc->keys[i]);
        free(vc->values[i]);
    }
    free(vc->keys);
    free(vc->values);
    memset(vc, 0, sizeof(*vc));
}
