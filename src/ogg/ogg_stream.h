/*
 * ogg_stream.h – Ogg page reading, writing, and packet extraction
 */

#ifndef OGG_STREAM_H
#define OGG_STREAM_H

#include "../io/file_io.h"
#include "../util/buffer.h"
#include <stddef.h>
#include <stdint.h>

#define OGG_PAGE_HEADER_SIZE 27
#define OGG_MAX_SEGMENTS     255

/* Header type flags */
#define OGG_FLAG_CONTINUED   0x01
#define OGG_FLAG_BOS         0x02
#define OGG_FLAG_EOS         0x04

typedef struct {
    uint8_t  header_type;
    int64_t  granule_pos;
    uint32_t serial;
    uint32_t page_seq;
    uint32_t crc;
    uint8_t  num_segments;
    uint8_t  segments[OGG_MAX_SEGMENTS];
    uint8_t *data;
    size_t   data_size;
} ogg_page_t;

/* Read the next Ogg page from the file. Allocates page->data. */
int  ogg_page_read(file_io_t *fio, ogg_page_t *page);

/* Write an Ogg page (recomputes CRC). */
int  ogg_page_write(int fd, const ogg_page_t *page);

void ogg_page_free(ogg_page_t *page);

/* Build page(s) from a single packet, writing to fd.
 * header_type: base flags (BOS, etc). serial/page_seq are assigned.
 * granule: granule_position for the last page of the packet.
 * Returns 0 on success, number of pages written via *pages_out. */
int  ogg_write_packet_pages(int fd, const uint8_t *pkt, size_t pkt_len,
                            uint8_t header_type, int64_t granule,
                            uint32_t serial, uint32_t *page_seq,
                            int *pages_out);

/* Detect codec from the first page's data.
 * Returns 'V' for Vorbis, 'O' for Opus, 'F' for FLAC, 0 for unknown. */
int  ogg_detect_codec(const uint8_t *data, size_t size);

#endif /* OGG_STREAM_H */
