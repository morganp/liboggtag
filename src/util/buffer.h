/*
 * buffer.h – Dynamic byte buffer
 */

#ifndef BUFFER_H
#define BUFFER_H

#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint8_t *data;
    size_t   size;
    size_t   capacity;
} dyn_buffer_t;

void   buf_init(dyn_buffer_t *b);
void   buf_free(dyn_buffer_t *b);
int    buf_reserve(dyn_buffer_t *b, size_t extra);
int    buf_append(dyn_buffer_t *b, const void *data, size_t len);
int    buf_append_u8(dyn_buffer_t *b, uint8_t val);
int    buf_append_le32(dyn_buffer_t *b, uint32_t val);
int    buf_append_zeros(dyn_buffer_t *b, size_t count);

#endif /* BUFFER_H */
