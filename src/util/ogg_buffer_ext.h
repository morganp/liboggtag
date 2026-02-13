/*
 * ogg_buffer_ext.h – Little-endian buffer append helpers for Ogg/FLAC
 */

#ifndef OGG_BUFFER_EXT_H
#define OGG_BUFFER_EXT_H

#include <tag_common/buffer.h>

static inline int buffer_append_le32(dyn_buffer_t *b, uint32_t val)
{
    uint8_t tmp[4] = {
        (uint8_t)(val),
        (uint8_t)(val >> 8),
        (uint8_t)(val >> 16),
        (uint8_t)(val >> 24)
    };
    return buffer_append(b, tmp, 4);
}

#endif /* OGG_BUFFER_EXT_H */
