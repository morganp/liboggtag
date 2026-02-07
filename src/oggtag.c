/*
 * oggtag.c – Main API implementation for liboggtag
 *
 * Supports Ogg Vorbis (.ogg/.oga), Ogg Opus (.opus), and native FLAC (.flac).
 * All formats use Vorbis Comments for tagging.
 */

#include "oggtag/oggtag.h"
#include "vorbis_comment/vorbis_comment.h"
#include "ogg/ogg_stream.h"
#include "flac/flac_meta.h"
#include "io/file_io.h"
#include "util/buffer.h"
#include "util/string_util.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* ── Format identifiers ──────────────────────────────────────────────── */

enum oggtag_format {
    FMT_UNKNOWN = 0,
    FMT_OGG_VORBIS,
    FMT_OGG_OPUS,
    FMT_OGG_FLAC,
    FMT_NATIVE_FLAC
};

/* ── Context ─────────────────────────────────────────────────────────── */

struct oggtag_context {
    /* Allocator */
    oggtag_allocator_t alloc;
    int has_alloc;

    /* File */
    file_io_t fio;
    char *path;
    int is_open;
    int read_write;

    /* Detected format */
    enum oggtag_format format;

    /* Ogg stream state */
    uint32_t ogg_serial;

    /* FLAC layout */
    flac_layout_t flac_layout;

    /* Cached tags */
    oggtag_collection_t *cached_tags;
    char *vendor_string;
};

/* ── Allocator wrappers ──────────────────────────────────────────────── */

static void *ctx_alloc(oggtag_context_t *ctx, size_t size)
{
    if (ctx->has_alloc)
        return ctx->alloc.alloc(size, ctx->alloc.user_data);
    return malloc(size);
}

static void ctx_free(oggtag_context_t *ctx, void *ptr)
{
    if (ctx->has_alloc)
        ctx->alloc.free(ptr, ctx->alloc.user_data);
    else
        free(ptr);
}

/* ── Forward declarations ────────────────────────────────────────────── */

static void free_simple_tags(oggtag_context_t *ctx, oggtag_simple_tag_t *st);
static void free_tag(oggtag_context_t *ctx, oggtag_tag_t *tag);

/* ── Version / Error ─────────────────────────────────────────────────── */

const char *oggtag_version(void) { return "1.0.0"; }

const char *oggtag_strerror(int error)
{
    switch (error) {
    case OGGTAG_OK:                 return "Success";
    case OGGTAG_ERR_INVALID_ARG:    return "Invalid argument";
    case OGGTAG_ERR_NO_MEMORY:      return "Out of memory";
    case OGGTAG_ERR_IO:             return "I/O error";
    case OGGTAG_ERR_NOT_OPEN:       return "File not open";
    case OGGTAG_ERR_ALREADY_OPEN:   return "File already open";
    case OGGTAG_ERR_READ_ONLY:      return "File opened read-only";
    case OGGTAG_ERR_NOT_OGG:        return "Not an Ogg/FLAC file";
    case OGGTAG_ERR_BAD_HEADER:     return "Bad header";
    case OGGTAG_ERR_CORRUPT:        return "Corrupt data";
    case OGGTAG_ERR_TRUNCATED:      return "Truncated data";
    case OGGTAG_ERR_UNSUPPORTED:    return "Unsupported format";
    case OGGTAG_ERR_BAD_CRC:        return "CRC mismatch";
    case OGGTAG_ERR_NO_TAGS:        return "No tags found";
    case OGGTAG_ERR_TAG_NOT_FOUND:  return "Tag not found";
    case OGGTAG_ERR_TAG_TOO_LARGE:  return "Tag too large";
    case OGGTAG_ERR_NO_SPACE:       return "No space for tags";
    case OGGTAG_ERR_WRITE_FAILED:   return "Write failed";
    case OGGTAG_ERR_SEEK_FAILED:    return "Seek failed";
    case OGGTAG_ERR_RENAME_FAILED:  return "Rename failed";
    default:                        return "Unknown error";
    }
}

/* ── Context lifecycle ───────────────────────────────────────────────── */

oggtag_context_t *oggtag_create(const oggtag_allocator_t *allocator)
{
    oggtag_context_t *ctx;
    if (allocator)
        ctx = (oggtag_context_t *)allocator->alloc(sizeof(*ctx),
                                                   allocator->user_data);
    else
        ctx = (oggtag_context_t *)calloc(1, sizeof(*ctx));
    if (!ctx) return NULL;
    memset(ctx, 0, sizeof(*ctx));
    ctx->fio.fd = -1;
    if (allocator) {
        ctx->alloc = *allocator;
        ctx->has_alloc = 1;
    }
    return ctx;
}

void oggtag_destroy(oggtag_context_t *ctx)
{
    if (!ctx) return;
    oggtag_close(ctx);
    if (ctx->has_alloc)
        ctx->alloc.free(ctx, ctx->alloc.user_data);
    else
        free(ctx);
}

/* ── Format probing ──────────────────────────────────────────────────── */

static int probe_format(oggtag_context_t *ctx)
{
    uint8_t magic[4];
    fio_seek(&ctx->fio, 0);
    if (fio_read(&ctx->fio, magic, 4) < 0) return OGGTAG_ERR_IO;

    if (memcmp(magic, "fLaC", 4) == 0) {
        ctx->format = FMT_NATIVE_FLAC;
        int rc = flac_scan_metadata(&ctx->fio, &ctx->flac_layout);
        return rc < 0 ? OGGTAG_ERR_CORRUPT : OGGTAG_OK;
    }

    if (memcmp(magic, "OggS", 4) == 0) {
        fio_seek(&ctx->fio, 0);
        ogg_page_t page;
        if (ogg_page_read(&ctx->fio, &page) < 0) return OGGTAG_ERR_NOT_OGG;
        ctx->ogg_serial = page.serial;
        int codec = ogg_detect_codec(page.data, page.data_size);
        ogg_page_free(&page);
        switch (codec) {
        case 'V': ctx->format = FMT_OGG_VORBIS; return OGGTAG_OK;
        case 'O': ctx->format = FMT_OGG_OPUS;   return OGGTAG_OK;
        case 'F': ctx->format = FMT_OGG_FLAC;   return OGGTAG_OK;
        default:  return OGGTAG_ERR_UNSUPPORTED;
        }
    }

    return OGGTAG_ERR_NOT_OGG;
}

int oggtag_open(oggtag_context_t *ctx, const char *path)
{
    if (!ctx || !path) return OGGTAG_ERR_INVALID_ARG;
    if (ctx->is_open) return OGGTAG_ERR_ALREADY_OPEN;
    if (fio_open(&ctx->fio, path, 0) < 0) return OGGTAG_ERR_IO;
    ctx->path = str_dup(path);
    ctx->is_open = 1;
    ctx->read_write = 0;
    int rc = probe_format(ctx);
    if (rc != OGGTAG_OK) { oggtag_close(ctx); return rc; }
    return OGGTAG_OK;
}

int oggtag_open_rw(oggtag_context_t *ctx, const char *path)
{
    if (!ctx || !path) return OGGTAG_ERR_INVALID_ARG;
    if (ctx->is_open) return OGGTAG_ERR_ALREADY_OPEN;
    if (fio_open(&ctx->fio, path, 1) < 0) return OGGTAG_ERR_IO;
    ctx->path = str_dup(path);
    ctx->is_open = 1;
    ctx->read_write = 1;
    int rc = probe_format(ctx);
    if (rc != OGGTAG_OK) { oggtag_close(ctx); return rc; }
    return OGGTAG_OK;
}

void oggtag_close(oggtag_context_t *ctx)
{
    if (!ctx) return;
    fio_close(&ctx->fio);
    if (ctx->cached_tags) {
        oggtag_collection_free(ctx, ctx->cached_tags);
        ctx->cached_tags = NULL;
    }
    free(ctx->vendor_string);
    ctx->vendor_string = NULL;
    free(ctx->path);
    ctx->path = NULL;
    ctx->is_open = 0;
    ctx->format = FMT_UNKNOWN;
}

int oggtag_is_open(const oggtag_context_t *ctx)
{
    return ctx && ctx->is_open;
}

/* ── Ogg: extract comment packet ─────────────────────────────────────── */

/*
 * Read all header pages of the logical bitstream, assemble packets,
 * return the raw comment packet data. For Vorbis the prefix is
 * 0x03 "vorbis" (7 bytes) + trailing framing bit. For Opus: "OpusTags" (8).
 * For Ogg FLAC: 0x84 + 3-byte length + VC data (the 2nd metadata block).
 */
static int ogg_read_comment_packet(oggtag_context_t *ctx,
                                   uint8_t **vc_data, size_t *vc_len)
{
    fio_seek(&ctx->fio, 0);

    dyn_buffer_t pkt;
    buf_init(&pkt);

    int packet_num = 0;   /* count complete packets */
    int found = 0;

    while (!found) {
        ogg_page_t pg;
        if (ogg_page_read(&ctx->fio, &pg) < 0) {
            buf_free(&pkt);
            return OGGTAG_ERR_TRUNCATED;
        }

        /* Only process pages from our serial */
        if (pg.serial != ctx->ogg_serial) {
            ogg_page_free(&pg);
            continue;
        }

        /* Walk segments */
        size_t data_off = 0;
        for (int i = 0; i < pg.num_segments; i++) {
            uint8_t seg = pg.segments[i];
            buf_append(&pkt, pg.data + data_off, seg);
            data_off += seg;

            if (seg < 255) {
                /* Packet boundary */
                if (packet_num == 1) {
                    /* This is the comment packet */
                    found = 1;
                    break;
                }
                packet_num++;
                buf_free(&pkt);
                buf_init(&pkt);
            }
        }
        ogg_page_free(&pg);

        /* Safety: if we've passed many pages without finding it, bail */
        if (packet_num > 3 && !found) {
            buf_free(&pkt);
            return OGGTAG_ERR_NO_TAGS;
        }
    }

    /* Strip codec prefix to get raw VC data */
    size_t prefix_len = 0;
    if (ctx->format == FMT_OGG_VORBIS) {
        /* 0x03 "vorbis" = 7 bytes prefix, 1 byte framing at end */
        if (pkt.size < 8) { buf_free(&pkt); return OGGTAG_ERR_CORRUPT; }
        prefix_len = 7;
        *vc_len = pkt.size - 7 - 1; /* strip prefix and framing byte */
    } else if (ctx->format == FMT_OGG_OPUS) {
        /* "OpusTags" = 8 bytes prefix, no framing */
        if (pkt.size < 8) { buf_free(&pkt); return OGGTAG_ERR_CORRUPT; }
        prefix_len = 8;
        *vc_len = pkt.size - 8;
    } else if (ctx->format == FMT_OGG_FLAC) {
        /* Second packet in Ogg FLAC is the VC metadata block.
         * It starts with a 4-byte metadata block header. */
        if (pkt.size < 4) { buf_free(&pkt); return OGGTAG_ERR_CORRUPT; }
        prefix_len = 4;
        *vc_len = pkt.size - 4;
    } else {
        buf_free(&pkt);
        return OGGTAG_ERR_UNSUPPORTED;
    }

    *vc_data = (uint8_t *)malloc(*vc_len);
    if (!*vc_data) { buf_free(&pkt); return OGGTAG_ERR_NO_MEMORY; }
    memcpy(*vc_data, pkt.data + prefix_len, *vc_len);
    buf_free(&pkt);
    return OGGTAG_OK;
}

/* ── Convert VC → collection ─────────────────────────────────────────── */

static oggtag_collection_t *vc_to_collection(oggtag_context_t *ctx,
                                             const vorbis_comment_t *vc)
{
    oggtag_collection_t *coll = oggtag_collection_create(ctx);
    if (!coll) return NULL;

    oggtag_tag_t *tag = oggtag_collection_add_tag(ctx, coll,
                                                  OGGTAG_TARGET_ALBUM);
    if (!tag) { oggtag_collection_free(ctx, coll); return NULL; }

    for (size_t i = 0; i < vc->count; i++) {
        const char *canonical = vc_name_to_canonical(vc->keys[i]);
        oggtag_tag_add_simple(ctx, tag, canonical, vc->values[i]);
    }

    free(ctx->vendor_string);
    ctx->vendor_string = str_dup(vc->vendor);

    return coll;
}

/* ── Convert collection → VC ─────────────────────────────────────────── */

static int collection_to_vc(const oggtag_collection_t *coll,
                            const char *vendor,
                            vorbis_comment_t *vc)
{
    memset(vc, 0, sizeof(*vc));
    vc->vendor = str_dup(vendor ? vendor : "liboggtag");

    /* Count total simple tags */
    size_t total = 0;
    for (const oggtag_tag_t *t = coll->tags; t; t = t->next)
        for (const oggtag_simple_tag_t *s = t->simple_tags; s; s = s->next)
            total++;

    vc->keys   = (char **)calloc(total ? total : 1, sizeof(char *));
    vc->values = (char **)calloc(total ? total : 1, sizeof(char *));
    if (!vc->keys || !vc->values) { vc_free(vc); return -1; }

    size_t idx = 0;
    for (const oggtag_tag_t *t = coll->tags; t; t = t->next) {
        for (const oggtag_simple_tag_t *s = t->simple_tags; s; s = s->next) {
            const char *vc_name = vc_name_from_canonical(s->name);
            vc->keys[idx]   = str_dup(vc_name);
            vc->values[idx] = str_dup(s->value ? s->value : "");
            idx++;
        }
    }
    vc->count = total;
    return 0;
}

/* ── Read tags ───────────────────────────────────────────────────────── */

int oggtag_read_tags(oggtag_context_t *ctx, oggtag_collection_t **tags)
{
    if (!ctx || !tags) return OGGTAG_ERR_INVALID_ARG;
    if (!ctx->is_open) return OGGTAG_ERR_NOT_OPEN;

    if (ctx->cached_tags) {
        *tags = ctx->cached_tags;
        return OGGTAG_OK;
    }

    uint8_t *raw = NULL;
    size_t raw_len = 0;
    int rc;

    if (ctx->format == FMT_NATIVE_FLAC) {
        rc = flac_read_vc_data(&ctx->fio, &ctx->flac_layout, &raw, &raw_len);
        if (rc < 0) return OGGTAG_ERR_NO_TAGS;
    } else {
        rc = ogg_read_comment_packet(ctx, &raw, &raw_len);
        if (rc != OGGTAG_OK) return rc;
    }

    vorbis_comment_t vc;
    if (vc_parse(raw, raw_len, &vc) < 0) {
        free(raw);
        return OGGTAG_ERR_CORRUPT;
    }
    free(raw);

    oggtag_collection_t *coll = vc_to_collection(ctx, &vc);
    vc_free(&vc);
    if (!coll) return OGGTAG_ERR_NO_MEMORY;

    ctx->cached_tags = coll;
    *tags = coll;
    return OGGTAG_OK;
}

int oggtag_read_tag_string(oggtag_context_t *ctx, const char *name,
                           char *value, size_t size)
{
    if (!ctx || !name || !value || !size) return OGGTAG_ERR_INVALID_ARG;

    oggtag_collection_t *coll = NULL;
    int rc = oggtag_read_tags(ctx, &coll);
    if (rc != OGGTAG_OK) return rc;

    for (const oggtag_tag_t *t = coll->tags; t; t = t->next) {
        for (const oggtag_simple_tag_t *s = t->simple_tags; s; s = s->next) {
            if (str_casecmp(s->name, name) == 0 && s->value) {
                str_copy(value, size, s->value);
                return OGGTAG_OK;
            }
        }
    }
    return OGGTAG_ERR_TAG_NOT_FOUND;
}

/* ── Ogg write: rewrite file with new comment packet ─────────────────── */

static int ogg_write_tags(oggtag_context_t *ctx,
                          const uint8_t *vc_raw, size_t vc_raw_len)
{
    /* Build the full comment packet with codec prefix */
    dyn_buffer_t pkt;
    buf_init(&pkt);

    if (ctx->format == FMT_OGG_VORBIS) {
        uint8_t prefix[7] = { 0x03, 'v','o','r','b','i','s' };
        buf_append(&pkt, prefix, 7);
        buf_append(&pkt, vc_raw, vc_raw_len);
        buf_append_u8(&pkt, 0x01); /* framing bit */
    } else if (ctx->format == FMT_OGG_OPUS) {
        buf_append(&pkt, "OpusTags", 8);
        buf_append(&pkt, vc_raw, vc_raw_len);
    } else if (ctx->format == FMT_OGG_FLAC) {
        /* Metadata block header for VORBIS_COMMENT (type 4) */
        uint8_t bh[4];
        bh[0] = FLAC_BLOCK_VORBIS_COMMENT; /* not-last */
        bh[1] = (uint8_t)(vc_raw_len >> 16);
        bh[2] = (uint8_t)(vc_raw_len >> 8);
        bh[3] = (uint8_t)(vc_raw_len);
        buf_append(&pkt, bh, 4);
        buf_append(&pkt, vc_raw, vc_raw_len);
    } else {
        return OGGTAG_ERR_UNSUPPORTED;
    }

    /* Rewrite strategy:
     * 1. Read all header packets from the original file
     * 2. Replace the comment packet (packet index 1)
     * 3. Write to temp file: header pages + copy remaining audio pages
     */

    fio_seek(&ctx->fio, 0);

    /* Collect header packets */
    int num_header_packets;
    if (ctx->format == FMT_OGG_VORBIS)
        num_header_packets = 3; /* ID, comment, setup */
    else
        num_header_packets = 2; /* head, tags */

    dyn_buffer_t packets[3];
    for (int i = 0; i < 3; i++) buf_init(&packets[i]);

    int pkt_idx = 0;
    off_t audio_start = 0;
    int done_headers = 0;

    while (!done_headers) {
        ogg_page_t pg;
        if (ogg_page_read(&ctx->fio, &pg) < 0) break;

        if (pg.serial != ctx->ogg_serial) {
            ogg_page_free(&pg);
            continue;
        }

        size_t data_off = 0;
        for (int i = 0; i < pg.num_segments && !done_headers; i++) {
            uint8_t seg = pg.segments[i];
            if (pkt_idx < num_header_packets)
                buf_append(&packets[pkt_idx], pg.data + data_off, seg);
            data_off += seg;

            if (seg < 255) {
                pkt_idx++;
                if (pkt_idx >= num_header_packets) {
                    /* Any remaining data on this page belongs to the
                     * first audio packet — we'll handle it via full copy */
                    done_headers = 1;
                }
            }
        }

        if (done_headers) {
            /* audio_start = position after this page in the original file */
            audio_start = fio_tell(&ctx->fio);

            /* But we may have consumed data from this page that belongs
             * to the next packet. We need to back up to include this page
             * in the audio copy if it has remaining data. Actually, for
             * simplicity, let's track remaining segment data. */

            /* Check if there are unconsumed segments on this page that
             * represent audio data. If so, we need to include them. */
            size_t consumed = data_off;
            if (consumed < pg.data_size) {
                /* There's leftover data - this is the start of the first
                 * audio packet. We need to rewind to before this page. */
                audio_start = fio_tell(&ctx->fio) -
                    (off_t)(OGG_PAGE_HEADER_SIZE + pg.num_segments + pg.data_size);
            }
        } else {
            audio_start = fio_tell(&ctx->fio);
        }
        ogg_page_free(&pg);
    }

    /* Replace comment packet (index 1) with our new one */
    buf_free(&packets[1]);
    packets[1] = pkt; /* transfer ownership */

    /* Write to temp file */
    size_t pathlen = strlen(ctx->path);
    char *tmp_path = (char *)malloc(pathlen + 8);
    if (!tmp_path) {
        for (int i = 0; i < num_header_packets; i++) buf_free(&packets[i]);
        return OGGTAG_ERR_NO_MEMORY;
    }
    snprintf(tmp_path, pathlen + 8, "%s.tmp", ctx->path);

    int tmp_fd = open(tmp_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (tmp_fd < 0) {
        free(tmp_path);
        for (int i = 0; i < num_header_packets; i++) buf_free(&packets[i]);
        return OGGTAG_ERR_IO;
    }

    uint32_t page_seq = 0;

    /* Write header packets as pages */
    for (int i = 0; i < num_header_packets; i++) {
        uint8_t flags = 0;
        int64_t granule = 0;

        if (i == 0) {
            flags = OGG_FLAG_BOS;
            granule = 0;
        } else {
            flags = 0;
            granule = 0; /* header pages have granule 0 */
        }

        int pages_written = 0;
        if (ogg_write_packet_pages(tmp_fd, packets[i].data, packets[i].size,
                                   flags, granule, ctx->ogg_serial, &page_seq,
                                   &pages_written) < 0) {
            close(tmp_fd); unlink(tmp_path); free(tmp_path);
            for (int j = 0; j < num_header_packets; j++) buf_free(&packets[j]);
            return OGGTAG_ERR_WRITE_FAILED;
        }
        buf_free(&packets[i]);
    }

    /* Copy remaining pages from original file, adjusting page_seq */
    fio_seek(&ctx->fio, audio_start);
    off_t file_size = fio_size(&ctx->fio);

    while (fio_tell(&ctx->fio) < file_size) {
        ogg_page_t pg;
        if (ogg_page_read(&ctx->fio, &pg) < 0) break;

        if (pg.serial == ctx->ogg_serial) {
            pg.page_seq = page_seq++;
        }

        if (ogg_page_write(tmp_fd, &pg) < 0) {
            ogg_page_free(&pg);
            close(tmp_fd); unlink(tmp_path); free(tmp_path);
            return OGGTAG_ERR_WRITE_FAILED;
        }
        ogg_page_free(&pg);
    }

    close(tmp_fd);
    fio_close(&ctx->fio);

    if (rename(tmp_path, ctx->path) != 0) {
        unlink(tmp_path);
        free(tmp_path);
        return OGGTAG_ERR_RENAME_FAILED;
    }
    free(tmp_path);

    /* Reopen */
    if (fio_open(&ctx->fio, ctx->path, ctx->read_write) < 0)
        return OGGTAG_ERR_IO;

    /* Re-probe to update serial etc. */
    return probe_format(ctx);
}

/* ── Write tags ──────────────────────────────────────────────────────── */

int oggtag_write_tags(oggtag_context_t *ctx, const oggtag_collection_t *tags)
{
    if (!ctx || !tags) return OGGTAG_ERR_INVALID_ARG;
    if (!ctx->is_open) return OGGTAG_ERR_NOT_OPEN;
    if (!ctx->read_write) return OGGTAG_ERR_READ_ONLY;

    /* Serialize collection to VC */
    vorbis_comment_t vc;
    if (collection_to_vc(tags, ctx->vendor_string, &vc) < 0)
        return OGGTAG_ERR_NO_MEMORY;

    dyn_buffer_t buf;
    buf_init(&buf);
    if (vc_serialize(&vc, &buf) < 0) {
        vc_free(&vc); buf_free(&buf);
        return OGGTAG_ERR_NO_MEMORY;
    }
    vc_free(&vc);

    int rc;
    if (ctx->format == FMT_NATIVE_FLAC) {
        rc = flac_write_vc_data(&ctx->fio, ctx->path, &ctx->flac_layout,
                                buf.data, buf.size);
        rc = (rc < 0) ? OGGTAG_ERR_WRITE_FAILED : OGGTAG_OK;
    } else {
        rc = ogg_write_tags(ctx, buf.data, buf.size);
    }
    buf_free(&buf);

    /* Invalidate cache */
    if (ctx->cached_tags) {
        oggtag_collection_free(ctx, ctx->cached_tags);
        ctx->cached_tags = NULL;
    }

    return rc;
}

int oggtag_set_tag_string(oggtag_context_t *ctx,
                          const char *name, const char *value)
{
    if (!ctx || !name) return OGGTAG_ERR_INVALID_ARG;
    if (!ctx->is_open) return OGGTAG_ERR_NOT_OPEN;
    if (!ctx->read_write) return OGGTAG_ERR_READ_ONLY;

    /* Read existing tags (or start fresh) */
    oggtag_collection_t *existing = NULL;
    oggtag_read_tags(ctx, &existing);

    /* Build new collection */
    oggtag_collection_t *coll = oggtag_collection_create(ctx);
    if (!coll) return OGGTAG_ERR_NO_MEMORY;

    oggtag_tag_t *tag = oggtag_collection_add_tag(ctx, coll,
                                                  OGGTAG_TARGET_ALBUM);

    /* Copy existing tags except the one we're setting */
    if (existing) {
        for (const oggtag_tag_t *t = existing->tags; t; t = t->next)
            for (const oggtag_simple_tag_t *s = t->simple_tags; s; s = s->next)
                if (str_casecmp(s->name, name) != 0)
                    oggtag_tag_add_simple(ctx, tag, s->name, s->value);
    }

    /* Add the new tag (unless value is NULL → remove) */
    if (value)
        oggtag_tag_add_simple(ctx, tag, name, value);

    int rc = oggtag_write_tags(ctx, coll);
    oggtag_collection_free(ctx, coll);
    return rc;
}

int oggtag_remove_tag(oggtag_context_t *ctx, const char *name)
{
    return oggtag_set_tag_string(ctx, name, NULL);
}

/* ── Collection building ─────────────────────────────────────────────── */

oggtag_collection_t *oggtag_collection_create(oggtag_context_t *ctx)
{
    if (!ctx) return NULL;
    oggtag_collection_t *c = (oggtag_collection_t *)ctx_alloc(ctx, sizeof(*c));
    if (c) memset(c, 0, sizeof(*c));
    return c;
}

static void free_simple_tags(oggtag_context_t *ctx, oggtag_simple_tag_t *st)
{
    while (st) {
        oggtag_simple_tag_t *next = st->next;
        free_simple_tags(ctx, st->nested);
        free(st->name);
        free(st->value);
        free(st->binary);
        free(st->language);
        ctx_free(ctx, st);
        st = next;
    }
}

static void free_tag(oggtag_context_t *ctx, oggtag_tag_t *tag)
{
    free_simple_tags(ctx, tag->simple_tags);
    free(tag->target_type_str);
    free(tag->track_uids);
    free(tag->edition_uids);
    free(tag->chapter_uids);
    free(tag->attachment_uids);
    ctx_free(ctx, tag);
}

void oggtag_collection_free(oggtag_context_t *ctx, oggtag_collection_t *coll)
{
    if (!ctx || !coll) return;
    oggtag_tag_t *t = coll->tags;
    while (t) {
        oggtag_tag_t *next = t->next;
        free_tag(ctx, t);
        t = next;
    }
    ctx_free(ctx, coll);
}

oggtag_tag_t *oggtag_collection_add_tag(oggtag_context_t *ctx,
                                        oggtag_collection_t *coll,
                                        oggtag_target_type_t type)
{
    if (!ctx || !coll) return NULL;
    oggtag_tag_t *tag = (oggtag_tag_t *)ctx_alloc(ctx, sizeof(*tag));
    if (!tag) return NULL;
    memset(tag, 0, sizeof(*tag));
    tag->target_type = type;

    /* Append to list */
    if (!coll->tags) {
        coll->tags = tag;
    } else {
        oggtag_tag_t *t = coll->tags;
        while (t->next) t = t->next;
        t->next = tag;
    }
    coll->count++;
    return tag;
}

oggtag_simple_tag_t *oggtag_tag_add_simple(oggtag_context_t *ctx,
                                           oggtag_tag_t *tag,
                                           const char *name,
                                           const char *value)
{
    if (!ctx || !tag || !name) return NULL;
    oggtag_simple_tag_t *st = (oggtag_simple_tag_t *)ctx_alloc(ctx, sizeof(*st));
    if (!st) return NULL;
    memset(st, 0, sizeof(*st));
    st->name  = str_dup(name);
    st->value = str_dup(value);
    st->is_default = 1;

    /* Append */
    if (!tag->simple_tags) {
        tag->simple_tags = st;
    } else {
        oggtag_simple_tag_t *s = tag->simple_tags;
        while (s->next) s = s->next;
        s->next = st;
    }
    return st;
}

oggtag_simple_tag_t *oggtag_simple_tag_add_nested(oggtag_context_t *ctx,
                                                  oggtag_simple_tag_t *parent,
                                                  const char *name,
                                                  const char *value)
{
    if (!ctx || !parent || !name) return NULL;
    oggtag_simple_tag_t *st = (oggtag_simple_tag_t *)ctx_alloc(ctx, sizeof(*st));
    if (!st) return NULL;
    memset(st, 0, sizeof(*st));
    st->name  = str_dup(name);
    st->value = str_dup(value);
    st->is_default = 1;

    if (!parent->nested) {
        parent->nested = st;
    } else {
        oggtag_simple_tag_t *s = parent->nested;
        while (s->next) s = s->next;
        s->next = st;
    }
    return st;
}

int oggtag_simple_tag_set_language(oggtag_context_t *ctx,
                                  oggtag_simple_tag_t *simple_tag,
                                  const char *language)
{
    if (!ctx || !simple_tag) return OGGTAG_ERR_INVALID_ARG;
    free(simple_tag->language);
    simple_tag->language = str_dup(language);
    return OGGTAG_OK;
}

int oggtag_tag_add_track_uid(oggtag_context_t *ctx,
                             oggtag_tag_t *tag, uint64_t uid)
{
    if (!ctx || !tag) return OGGTAG_ERR_INVALID_ARG;
    uint64_t *new_uids = (uint64_t *)realloc(tag->track_uids,
        (tag->track_uid_count + 1) * sizeof(uint64_t));
    if (!new_uids) return OGGTAG_ERR_NO_MEMORY;
    new_uids[tag->track_uid_count++] = uid;
    tag->track_uids = new_uids;
    return OGGTAG_OK;
}
