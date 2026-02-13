/*
 * flac_meta.h – FLAC metadata block reading and writing
 */

#ifndef FLAC_META_H
#define FLAC_META_H

#include "../io/file_io.h"
#include <stddef.h>
#include <stdint.h>

/* Metadata block types */
#define FLAC_BLOCK_STREAMINFO     0
#define FLAC_BLOCK_PADDING        1
#define FLAC_BLOCK_APPLICATION    2
#define FLAC_BLOCK_SEEKTABLE      3
#define FLAC_BLOCK_VORBIS_COMMENT 4
#define FLAC_BLOCK_CUESHEET       5
#define FLAC_BLOCK_PICTURE        6

/* Metadata block header (4 bytes on disk) */
typedef struct {
    int      is_last;
    uint8_t  type;
    uint32_t length;  /* data length (not including 4-byte header) */
} flac_block_header_t;

/* Info about metadata layout needed for tag writing */
typedef struct {
    off_t    vc_offset;       /* file offset of VC block header */
    uint32_t vc_data_len;     /* length of VC block data */
    off_t    pad_offset;      /* file offset of PADDING block header (0 = none) */
    uint32_t pad_data_len;    /* length of PADDING block data */
    int      vc_is_last;      /* was the VC block marked as last? */
    int      pad_is_last;     /* was the PADDING block marked as last? */
    int      pad_follows_vc;  /* does PADDING immediately follow VC? */
    off_t    audio_offset;    /* file offset where audio frames begin */
} flac_layout_t;

/* Scan metadata blocks and populate layout. */
int  flac_scan_metadata(file_io_t *fio, flac_layout_t *layout);

/* Read raw Vorbis Comment data from the VC block. Caller frees *data. */
int  flac_read_vc_data(file_io_t *fio, const flac_layout_t *layout,
                       uint8_t **data, size_t *size);

/* Write VC data, using in-place + padding if possible, else rewrite. */
int  flac_write_vc_data(file_io_t *fio, const char *path,
                        flac_layout_t *layout,
                        const uint8_t *vc_data, size_t vc_len);

#endif /* FLAC_META_H */
