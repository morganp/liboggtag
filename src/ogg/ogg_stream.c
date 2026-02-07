/*
 * ogg_stream.c – Ogg page reading, writing, and packet building
 */

#include "ogg_stream.h"
#include "ogg_crc.h"

#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* ── Read a single Ogg page ──────────────────────────────────────────── */

int ogg_page_read(file_io_t *fio, ogg_page_t *page)
{
    memset(page, 0, sizeof(*page));

    uint8_t hdr[OGG_PAGE_HEADER_SIZE];
    if (fio_read(fio, hdr, OGG_PAGE_HEADER_SIZE) < 0)
        return -1;

    /* Capture pattern "OggS" */
    if (memcmp(hdr, "OggS", 4) != 0) return -1;
    if (hdr[4] != 0) return -1; /* version must be 0 */

    page->header_type = hdr[5];
    page->granule_pos = (int64_t)(
        (uint64_t)hdr[6]        | (uint64_t)hdr[7]  << 8  |
        (uint64_t)hdr[8]  << 16 | (uint64_t)hdr[9]  << 24 |
        (uint64_t)hdr[10] << 32 | (uint64_t)hdr[11] << 40 |
        (uint64_t)hdr[12] << 48 | (uint64_t)hdr[13] << 56);
    page->serial   = (uint32_t)hdr[14] | (uint32_t)hdr[15] << 8 |
                     (uint32_t)hdr[16] << 16 | (uint32_t)hdr[17] << 24;
    page->page_seq = (uint32_t)hdr[18] | (uint32_t)hdr[19] << 8 |
                     (uint32_t)hdr[20] << 16 | (uint32_t)hdr[21] << 24;
    page->crc      = (uint32_t)hdr[22] | (uint32_t)hdr[23] << 8 |
                     (uint32_t)hdr[24] << 16 | (uint32_t)hdr[25] << 24;
    page->num_segments = hdr[26];

    /* Read segment table */
    if (page->num_segments > 0) {
        if (fio_read(fio, page->segments, page->num_segments) < 0)
            return -1;
    }

    /* Calculate total data size */
    page->data_size = 0;
    for (int i = 0; i < page->num_segments; i++)
        page->data_size += page->segments[i];

    /* Read data */
    if (page->data_size > 0) {
        page->data = (uint8_t *)malloc(page->data_size);
        if (!page->data) return -1;
        if (fio_read(fio, page->data, page->data_size) < 0) {
            free(page->data); page->data = NULL;
            return -1;
        }
    }
    return 0;
}

/* ── Serialize and write a page ──────────────────────────────────────── */

static void page_serialize_header(const ogg_page_t *page, uint8_t *hdr)
{
    memcpy(hdr, "OggS", 4);
    hdr[4] = 0; /* version */
    hdr[5] = page->header_type;

    uint64_t g = (uint64_t)page->granule_pos;
    for (int i = 0; i < 8; i++) hdr[6 + i] = (uint8_t)(g >> (i * 8));

    uint32_t s = page->serial;
    hdr[14] = (uint8_t)s; hdr[15] = (uint8_t)(s >> 8);
    hdr[16] = (uint8_t)(s >> 16); hdr[17] = (uint8_t)(s >> 24);

    s = page->page_seq;
    hdr[18] = (uint8_t)s; hdr[19] = (uint8_t)(s >> 8);
    hdr[20] = (uint8_t)(s >> 16); hdr[21] = (uint8_t)(s >> 24);

    /* CRC set to 0 for computation */
    hdr[22] = hdr[23] = hdr[24] = hdr[25] = 0;

    hdr[26] = page->num_segments;
}

int ogg_page_write(int fd, const ogg_page_t *page)
{
    uint8_t hdr[OGG_PAGE_HEADER_SIZE];
    page_serialize_header(page, hdr);

    /* Compute CRC over header + segment table + data */
    uint32_t crc = 0;
    crc = ogg_crc_update(crc, hdr, OGG_PAGE_HEADER_SIZE);
    crc = ogg_crc_update(crc, page->segments, page->num_segments);
    if (page->data_size > 0)
        crc = ogg_crc_update(crc, page->data, page->data_size);

    /* Patch CRC into header */
    hdr[22] = (uint8_t)crc; hdr[23] = (uint8_t)(crc >> 8);
    hdr[24] = (uint8_t)(crc >> 16); hdr[25] = (uint8_t)(crc >> 24);

    /* Write header */
    if (write(fd, hdr, OGG_PAGE_HEADER_SIZE) != OGG_PAGE_HEADER_SIZE) return -1;
    /* Segment table */
    if (page->num_segments > 0)
        if (write(fd, page->segments, page->num_segments) != page->num_segments) return -1;
    /* Data */
    if (page->data_size > 0) {
        ssize_t w = write(fd, page->data, page->data_size);
        if (w < 0 || (size_t)w != page->data_size) return -1;
    }
    return 0;
}

void ogg_page_free(ogg_page_t *page)
{
    free(page->data);
    page->data = NULL;
    page->data_size = 0;
}

/* ── Write packet as one or more pages ───────────────────────────────── */

int ogg_write_packet_pages(int fd, const uint8_t *pkt, size_t pkt_len,
                           uint8_t header_type, int64_t granule,
                           uint32_t serial, uint32_t *page_seq,
                           int *pages_out)
{
    int count = 0;
    size_t offset = 0;

    while (offset < pkt_len || (offset == 0 && pkt_len == 0)) {
        ogg_page_t pg;
        memset(&pg, 0, sizeof(pg));

        pg.serial = serial;
        pg.page_seq = (*page_seq)++;

        /* First page of packet gets the caller's flags;
         * continuation pages get CONTINUED flag */
        if (offset == 0)
            pg.header_type = header_type;
        else
            pg.header_type = OGG_FLAG_CONTINUED;

        /* Build segment table for this page */
        size_t remaining = pkt_len - offset;
        size_t page_data = 0;
        pg.num_segments = 0;

        while (remaining > 0 && pg.num_segments < OGG_MAX_SEGMENTS) {
            if (remaining >= 255) {
                pg.segments[pg.num_segments++] = 255;
                page_data += 255;
                remaining -= 255;
            } else {
                pg.segments[pg.num_segments++] = (uint8_t)remaining;
                page_data += remaining;
                remaining = 0;
            }
        }

        /* If packet ends exactly on a 255 boundary and we have room,
         * add a zero-length terminator segment */
        if (remaining == 0 && page_data > 0 &&
            (page_data + offset == pkt_len) &&
            pg.segments[pg.num_segments - 1] == 255 &&
            pg.num_segments < OGG_MAX_SEGMENTS) {
            pg.segments[pg.num_segments++] = 0;
        }

        /* Granule position: -1 for all pages except the last */
        if (offset + page_data >= pkt_len)
            pg.granule_pos = granule;
        else
            pg.granule_pos = -1;

        pg.data = (uint8_t *)(pkt + offset);
        pg.data_size = page_data;

        if (ogg_page_write(fd, &pg) < 0) return -1;

        offset += page_data;
        count++;

        if (pkt_len == 0) break; /* empty packet */
    }

    if (pages_out) *pages_out = count;
    return 0;
}

/* ── Codec detection from first packet data ──────────────────────────── */

int ogg_detect_codec(const uint8_t *data, size_t size)
{
    if (size >= 7 && data[0] == 0x01 && memcmp(data + 1, "vorbis", 6) == 0)
        return 'V';
    if (size >= 8 && memcmp(data, "OpusHead", 8) == 0)
        return 'O';
    if (size >= 5 && data[0] == 0x7F && memcmp(data + 1, "FLAC", 4) == 0)
        return 'F';
    return 0;
}
