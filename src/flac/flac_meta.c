/*
 * flac_meta.c – FLAC metadata block handling
 *
 * Supports in-place writing by consuming adjacent PADDING blocks.
 * Falls back to full rewrite when space is insufficient.
 */

#include "flac_meta.h"

#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>

/* ── Helpers ─────────────────────────────────────────────────────────── */

static int read_block_header(file_io_t *fio, flac_block_header_t *bh)
{
    uint8_t raw[4];
    if (fio_read(fio, raw, 4) < 0) return -1;
    bh->is_last = (raw[0] >> 7) & 1;
    bh->type    = raw[0] & 0x7F;
    bh->length  = (uint32_t)raw[1] << 16 | (uint32_t)raw[2] << 8 | raw[3];
    return 0;
}

static void encode_block_header(uint8_t *out, int is_last, uint8_t type,
                                uint32_t length)
{
    out[0] = (is_last ? 0x80 : 0) | (type & 0x7F);
    out[1] = (uint8_t)(length >> 16);
    out[2] = (uint8_t)(length >> 8);
    out[3] = (uint8_t)(length);
}

/* ── Scan ────────────────────────────────────────────────────────────── */

int flac_scan_metadata(file_io_t *fio, flac_layout_t *layout)
{
    memset(layout, 0, sizeof(*layout));
    fio_seek(fio, 0);

    /* Verify "fLaC" marker */
    uint8_t marker[4];
    if (fio_read(fio, marker, 4) < 0) return -1;
    if (memcmp(marker, "fLaC", 4) != 0) return -1;

    off_t prev_vc_end = 0;

    while (1) {
        off_t block_offset = fio_tell(fio);
        flac_block_header_t bh;
        if (read_block_header(fio, &bh) < 0) return -1;

        if (bh.type == FLAC_BLOCK_VORBIS_COMMENT) {
            layout->vc_offset   = block_offset;
            layout->vc_data_len = bh.length;
            layout->vc_is_last  = bh.is_last;
            prev_vc_end = block_offset + 4 + bh.length;
        } else if (bh.type == FLAC_BLOCK_PADDING) {
            layout->pad_offset   = block_offset;
            layout->pad_data_len = bh.length;
            layout->pad_is_last  = bh.is_last;
            if (prev_vc_end == block_offset)
                layout->pad_follows_vc = 1;
        }

        /* Skip block data */
        fio_seek(fio, fio_tell(fio) + bh.length);

        if (bh.is_last) {
            layout->audio_offset = fio_tell(fio);
            break;
        }
    }
    return 0;
}

/* ── Read ────────────────────────────────────────────────────────────── */

int flac_read_vc_data(file_io_t *fio, const flac_layout_t *layout,
                      uint8_t **data, size_t *size)
{
    if (layout->vc_offset == 0 && layout->vc_data_len == 0)
        return -1; /* no VC block found */

    *size = layout->vc_data_len;
    *data = (uint8_t *)malloc(*size);
    if (!*data) return -1;

    fio_seek(fio, layout->vc_offset + 4); /* skip block header */
    if (fio_read(fio, *data, *size) < 0) {
        free(*data); *data = NULL;
        return -1;
    }
    return 0;
}

/* ── Write (in-place or rewrite) ─────────────────────────────────────── */

#define FLAC_DEFAULT_PADDING 4096

/* Try to write in-place using VC block + adjacent padding. */
static int try_inplace(file_io_t *fio, flac_layout_t *layout,
                       const uint8_t *vc_data, size_t vc_len)
{
    /* Total space available: VC header + VC data [+ PAD header + PAD data] */
    size_t avail = 4 + layout->vc_data_len;
    int have_pad = (layout->pad_follows_vc && layout->pad_offset > 0);
    if (have_pad) avail += 4 + layout->pad_data_len;

    /* We need: VC header + new VC data [+ PAD header + remaining padding] */
    size_t need = 4 + vc_len;
    if (need > avail) return -1; /* doesn't fit */

    size_t leftover = avail - need;

    /* Determine last-block flag */
    int is_last_block;
    if (have_pad)
        is_last_block = layout->pad_is_last;
    else
        is_last_block = layout->vc_is_last;

    fio_seek(fio, layout->vc_offset);

    if (leftover >= 4) {
        /* Write VC block (not last) + PADDING block */
        uint8_t hdr[4];
        encode_block_header(hdr, 0, FLAC_BLOCK_VORBIS_COMMENT, (uint32_t)vc_len);
        if (fio_write(fio, hdr, 4) < 0) return -1;
        if (fio_write(fio, vc_data, vc_len) < 0) return -1;

        uint32_t pad_len = (uint32_t)(leftover - 4);
        encode_block_header(hdr, is_last_block, FLAC_BLOCK_PADDING, pad_len);
        if (fio_write(fio, hdr, 4) < 0) return -1;

        /* Zero-fill padding */
        uint8_t zeros[512];
        memset(zeros, 0, sizeof(zeros));
        size_t rem = pad_len;
        while (rem > 0) {
            size_t n = rem < sizeof(zeros) ? rem : sizeof(zeros);
            if (fio_write(fio, zeros, n) < 0) return -1;
            rem -= n;
        }

        layout->vc_data_len = (uint32_t)vc_len;
        layout->pad_offset  = layout->vc_offset + 4 + (off_t)vc_len;
        layout->pad_data_len = pad_len;
    } else {
        /* No room for a padding block – write VC using all space */
        /* Pad the VC data to fill the entire available area */
        size_t padded_len = avail - 4;
        uint8_t hdr[4];
        encode_block_header(hdr, is_last_block, FLAC_BLOCK_VORBIS_COMMENT,
                            (uint32_t)padded_len);
        if (fio_write(fio, hdr, 4) < 0) return -1;
        if (fio_write(fio, vc_data, vc_len) < 0) return -1;

        /* Zero-fill remaining */
        uint8_t zeros[4];
        memset(zeros, 0, sizeof(zeros));
        size_t rem = padded_len - vc_len;
        while (rem > 0) {
            size_t n = rem < sizeof(zeros) ? rem : sizeof(zeros);
            if (fio_write(fio, zeros, n) < 0) return -1;
            rem -= n;
        }

        layout->vc_data_len = (uint32_t)padded_len;
        layout->pad_offset  = 0;
        layout->pad_data_len = 0;
        layout->pad_follows_vc = 0;
    }

    return 0;
}

/* Full rewrite to temp file. */
static int rewrite_file(file_io_t *fio, const char *path,
                        flac_layout_t *layout,
                        const uint8_t *vc_data, size_t vc_len)
{
    /* Build temp path */
    size_t plen = strlen(path);
    char *tmp_path = (char *)malloc(plen + 8);
    if (!tmp_path) return -1;
    snprintf(tmp_path, plen + 8, "%s.tmp", path);

    int tmp_fd = open(tmp_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (tmp_fd < 0) { free(tmp_path); return -1; }

    off_t file_size = fio_size(fio);
    fio_seek(fio, 0);

    /* Copy everything before the VC block */
    {
        size_t copy_len = (size_t)layout->vc_offset;
        uint8_t buf[8192];
        size_t rem = copy_len;
        while (rem > 0) {
            size_t n = rem < sizeof(buf) ? rem : sizeof(buf);
            if (fio_read(fio, buf, n) < 0) goto fail;
            if (write(tmp_fd, buf, n) != (ssize_t)n) goto fail;
            rem -= n;
        }
    }

    /* Write new VC block (not last) */
    {
        uint8_t hdr[4];
        encode_block_header(hdr, 0, FLAC_BLOCK_VORBIS_COMMENT, (uint32_t)vc_len);
        if (write(tmp_fd, hdr, 4) != 4) goto fail;
        if (vc_len > 0) {
            ssize_t w = write(tmp_fd, vc_data, vc_len);
            if (w < 0 || (size_t)w != vc_len) goto fail;
        }
    }

    /* Write PADDING block (last = depends on what follows) */
    {
        /* Determine what follows the VC+pad region */
        off_t skip_end = layout->vc_offset + 4 + layout->vc_data_len;
        if (layout->pad_follows_vc && layout->pad_offset > 0)
            skip_end = layout->pad_offset + 4 + layout->pad_data_len;

        int pad_is_last = (skip_end >= layout->audio_offset);

        /* If not last, check if there are more metadata blocks */
        if (!pad_is_last) {
            /* More metadata blocks follow – write padding as not-last */
        }

        uint8_t hdr[4];
        encode_block_header(hdr, pad_is_last, FLAC_BLOCK_PADDING,
                            FLAC_DEFAULT_PADDING);
        if (write(tmp_fd, hdr, 4) != 4) goto fail;
        uint8_t zeros[512];
        memset(zeros, 0, sizeof(zeros));
        size_t rem = FLAC_DEFAULT_PADDING;
        while (rem > 0) {
            size_t n = rem < sizeof(zeros) ? rem : sizeof(zeros);
            if (write(tmp_fd, zeros, n) != (ssize_t)n) goto fail;
            rem -= n;
        }

        /* Skip past old VC + padding in source */
        fio_seek(fio, skip_end);

        /* Copy remaining metadata blocks (if any) before audio */
        if (skip_end < layout->audio_offset) {
            /* We need to adjust: the padding we wrote is not-last,
             * remaining blocks are copied as-is */
            hdr[0] &= ~0x80; /* clear is_last on padding */
            lseek(tmp_fd, -(off_t)(4 + FLAC_DEFAULT_PADDING), SEEK_CUR);
            encode_block_header(hdr, 0, FLAC_BLOCK_PADDING, FLAC_DEFAULT_PADDING);
            if (write(tmp_fd, hdr, 4) != 4) goto fail;
            lseek(tmp_fd, FLAC_DEFAULT_PADDING, SEEK_CUR);

            size_t meta_rem = (size_t)(layout->audio_offset - skip_end);
            uint8_t buf[8192];
            while (meta_rem > 0) {
                size_t n = meta_rem < sizeof(buf) ? meta_rem : sizeof(buf);
                if (fio_read(fio, buf, n) < 0) goto fail;
                if (write(tmp_fd, buf, n) != (ssize_t)n) goto fail;
                meta_rem -= n;
            }
        }
    }

    /* Copy audio data */
    {
        fio_seek(fio, layout->audio_offset);
        size_t audio_len = (size_t)(file_size - layout->audio_offset);
        uint8_t buf[8192];
        while (audio_len > 0) {
            size_t n = audio_len < sizeof(buf) ? audio_len : sizeof(buf);
            if (fio_read(fio, buf, n) < 0) goto fail;
            if (write(tmp_fd, buf, n) != (ssize_t)n) goto fail;
            audio_len -= n;
        }
    }

    close(tmp_fd);
    fio_close(fio);

    if (rename(tmp_path, path) != 0) {
        free(tmp_path);
        return -1;
    }
    free(tmp_path);

    /* Reopen the file */
    if (fio_open(fio, path, 1) < 0) return -1;

    /* Rescan layout */
    return flac_scan_metadata(fio, layout);

fail:
    close(tmp_fd);
    unlink(tmp_path);
    free(tmp_path);
    return -1;
}

int flac_write_vc_data(file_io_t *fio, const char *path,
                       flac_layout_t *layout,
                       const uint8_t *vc_data, size_t vc_len)
{
    if (try_inplace(fio, layout, vc_data, vc_len) == 0)
        return 0;
    return rewrite_file(fio, path, layout, vc_data, vc_len);
}
