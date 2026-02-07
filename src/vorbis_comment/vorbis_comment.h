/*
 * vorbis_comment.h – Parse and serialize Vorbis Comments
 *
 * Handles the raw Vorbis Comment data (vendor string + key=value list).
 * Does NOT include codec-specific framing (Vorbis 0x03 header, OpusTags
 * prefix, etc.) – callers strip/add those.
 */

#ifndef VORBIS_COMMENT_H
#define VORBIS_COMMENT_H

#include "../util/buffer.h"
#include <stddef.h>
#include <stdint.h>

typedef struct {
    char   *vendor;
    size_t  count;
    char  **keys;     /* Vorbis Comment field names (uppercase) */
    char  **values;
} vorbis_comment_t;

/* Parse raw VC data (starting at vendor-length field). */
int  vc_parse(const uint8_t *data, size_t size, vorbis_comment_t *vc);

/* Serialize to a buffer (starting at vendor-length field). */
int  vc_serialize(const vorbis_comment_t *vc, dyn_buffer_t *buf);

void vc_free(vorbis_comment_t *vc);

/* ── Tag-name mapping ────────────────────────────────────────────────
 * Translates between the canonical names shared by libmkvtag/libmp3tag
 * (e.g. TRACK_NUMBER) and Vorbis Comment field names (TRACKNUMBER).
 * Returns the input pointer unchanged if no mapping exists.
 */
const char *vc_name_to_canonical(const char *vc_name);
const char *vc_name_from_canonical(const char *canonical);

#endif /* VORBIS_COMMENT_H */
