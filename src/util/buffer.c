/*
 * buffer.c – Dynamic byte buffer
 */

#include "buffer.h"

#include <stdlib.h>
#include <string.h>

void buf_init(dyn_buffer_t *b)
{
    b->data     = NULL;
    b->size     = 0;
    b->capacity = 0;
}

void buf_free(dyn_buffer_t *b)
{
    free(b->data);
    b->data     = NULL;
    b->size     = 0;
    b->capacity = 0;
}

int buf_reserve(dyn_buffer_t *b, size_t extra)
{
    size_t need = b->size + extra;
    if (need <= b->capacity) return 0;
    size_t cap = b->capacity ? b->capacity : 256;
    while (cap < need) cap *= 2;
    uint8_t *p = (uint8_t *)realloc(b->data, cap);
    if (!p) return -1;
    b->data     = p;
    b->capacity = cap;
    return 0;
}

int buf_append(dyn_buffer_t *b, const void *data, size_t len)
{
    if (buf_reserve(b, len) < 0) return -1;
    memcpy(b->data + b->size, data, len);
    b->size += len;
    return 0;
}

int buf_append_u8(dyn_buffer_t *b, uint8_t val)
{
    return buf_append(b, &val, 1);
}

int buf_append_le32(dyn_buffer_t *b, uint32_t val)
{
    uint8_t tmp[4] = {
        (uint8_t)(val),
        (uint8_t)(val >> 8),
        (uint8_t)(val >> 16),
        (uint8_t)(val >> 24)
    };
    return buf_append(b, tmp, 4);
}

int buf_append_zeros(dyn_buffer_t *b, size_t count)
{
    if (buf_reserve(b, count) < 0) return -1;
    memset(b->data + b->size, 0, count);
    b->size += count;
    return 0;
}
