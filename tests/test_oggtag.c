/*
 * test_oggtag.c – Test suite for liboggtag
 *
 * Generates minimal Ogg Vorbis, Ogg Opus, and FLAC test files,
 * then exercises the tag read/write API on each.
 */

#include <oggtag/oggtag.h>

#include "ogg/ogg_stream.h"
#include "ogg/ogg_crc.h"
#include <tag_common/buffer.h>
#include "util/ogg_buffer_ext.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

/* ── Test harness ────────────────────────────────────────────────────── */

static int g_pass = 0, g_fail = 0;

#define CHECK(cond, msg) do { \
    if (cond) { g_pass++; } \
    else { g_fail++; printf("  FAIL: %s (line %d)\n", msg, __LINE__); } \
} while (0)

#define CHECK_RC(rc, msg) CHECK((rc) == OGGTAG_OK, msg)

/* ── Helper: write LE32 ──────────────────────────────────────────────── */

static void put_le32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
}

/* ── Create minimal Ogg Vorbis file ──────────────────────────────────── */

static void create_ogg_vorbis(const char *path)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);

    uint32_t serial = 0x12345678;
    uint32_t page_seq = 0;

    /* Packet 0: Vorbis identification header (30 bytes) */
    uint8_t id_pkt[30];
    memset(id_pkt, 0, sizeof(id_pkt));
    id_pkt[0] = 0x01; /* packet type */
    memcpy(id_pkt + 1, "vorbis", 6);
    /* version = 0 (4 bytes at offset 7) */
    id_pkt[11] = 1; /* channels = 1 */
    put_le32(id_pkt + 12, 44100); /* sample rate */
    /* bitrate max/nominal/min = 0 */
    id_pkt[28] = 0x88; /* blocksize 0=256, 1=256 */
    id_pkt[29] = 0x01; /* framing */

    ogg_write_packet_pages(fd, id_pkt, sizeof(id_pkt),
                           OGG_FLAG_BOS, 0, serial, &page_seq, NULL);

    /* Packet 1: Vorbis comment header */
    dyn_buffer_t comment_pkt;
    buffer_init(&comment_pkt);
    uint8_t vc_prefix[7] = { 0x03, 'v','o','r','b','i','s' };
    buffer_append(&comment_pkt, vc_prefix, 7);
    /* Vendor string */
    const char *vendor = "test";
    buffer_append_le32(&comment_pkt, (uint32_t)strlen(vendor));
    buffer_append(&comment_pkt, vendor, strlen(vendor));
    /* 0 comments */
    buffer_append_le32(&comment_pkt, 0);
    /* Framing bit */
    buffer_append_byte(&comment_pkt, 0x01);

    /* Packet 2: Minimal setup header (just needs to exist) */
    dyn_buffer_t setup_pkt;
    buffer_init(&setup_pkt);
    uint8_t setup_prefix[7] = { 0x05, 'v','o','r','b','i','s' };
    buffer_append(&setup_pkt, setup_prefix, 7);
    /* Minimal codebook data - just enough for structure */
    buffer_append_zeros(&setup_pkt, 20);

    /* Write comment + setup as a single page (as Vorbis spec recommends) */
    /* Actually, write them as separate pages for simplicity */
    ogg_write_packet_pages(fd, comment_pkt.data, comment_pkt.size,
                           0, 0, serial, &page_seq, NULL);
    ogg_write_packet_pages(fd, setup_pkt.data, setup_pkt.size,
                           0, 0, serial, &page_seq, NULL);

    buffer_free(&comment_pkt);
    buffer_free(&setup_pkt);

    /* One audio page with a tiny fake packet */
    uint8_t audio[10] = {0};
    ogg_write_packet_pages(fd, audio, sizeof(audio),
                           OGG_FLAG_EOS, 4096, serial, &page_seq, NULL);

    close(fd);
}

/* ── Create minimal Ogg Opus file ────────────────────────────────────── */

static void create_ogg_opus(const char *path)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);

    uint32_t serial = 0xABCDEF01;
    uint32_t page_seq = 0;

    /* Packet 0: OpusHead (19 bytes) */
    uint8_t head[19];
    memset(head, 0, sizeof(head));
    memcpy(head, "OpusHead", 8);
    head[8]  = 1;   /* version */
    head[9]  = 1;   /* channels */
    /* pre-skip = 0 (2 bytes LE) */
    put_le32(head + 12, 48000); /* sample rate */
    /* output gain = 0, mapping family = 0 */

    ogg_write_packet_pages(fd, head, sizeof(head),
                           OGG_FLAG_BOS, 0, serial, &page_seq, NULL);

    /* Packet 1: OpusTags */
    dyn_buffer_t tags_pkt;
    buffer_init(&tags_pkt);
    buffer_append(&tags_pkt, "OpusTags", 8);
    const char *vendor = "test";
    buffer_append_le32(&tags_pkt, (uint32_t)strlen(vendor));
    buffer_append(&tags_pkt, vendor, strlen(vendor));
    buffer_append_le32(&tags_pkt, 0); /* 0 comments */

    ogg_write_packet_pages(fd, tags_pkt.data, tags_pkt.size,
                           0, 0, serial, &page_seq, NULL);
    buffer_free(&tags_pkt);

    /* Audio page */
    uint8_t audio[10] = {0};
    ogg_write_packet_pages(fd, audio, sizeof(audio),
                           OGG_FLAG_EOS, 960, serial, &page_seq, NULL);

    close(fd);
}

/* ── Create minimal FLAC file ────────────────────────────────────────── */

static void create_flac(const char *path)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);

    /* fLaC marker */
    write(fd, "fLaC", 4);

    /* STREAMINFO block (type 0, 34 bytes data) */
    uint8_t si_hdr[4] = { 0x00, 0x00, 0x00, 34 }; /* not-last, type 0 */
    write(fd, si_hdr, 4);
    uint8_t si_data[34];
    memset(si_data, 0, sizeof(si_data));
    /* min/max block size = 4096 */
    si_data[0] = 0x10; si_data[1] = 0x00; /* min block size */
    si_data[2] = 0x10; si_data[3] = 0x00; /* max block size */
    /* sample rate = 44100 (20 bits), channels-1 = 0 (3 bits), bps-1 = 15 (5 bits) */
    si_data[10] = 0xAC; si_data[11] = 0x44; si_data[12] = 0xF0;
    write(fd, si_data, 34);

    /* VORBIS_COMMENT block (type 4) */
    const char *vendor = "test";
    uint32_t vendor_len = (uint32_t)strlen(vendor);
    uint32_t vc_data_len = 4 + vendor_len + 4; /* vendor_len + vendor + count */
    uint8_t vc_hdr[4] = {
        0x04, /* not-last, type 4 */
        (uint8_t)(vc_data_len >> 16),
        (uint8_t)(vc_data_len >> 8),
        (uint8_t)(vc_data_len)
    };
    write(fd, vc_hdr, 4);
    uint8_t tmp[4];
    put_le32(tmp, vendor_len);
    write(fd, tmp, 4);
    write(fd, vendor, vendor_len);
    put_le32(tmp, 0); /* 0 comments */
    write(fd, tmp, 4);

    /* PADDING block (last, type 1, 4096 bytes) */
    uint8_t pad_hdr[4] = { 0x81, 0x00, 0x10, 0x00 }; /* last, type 1, 4096 */
    write(fd, pad_hdr, 4);
    uint8_t zeros[512];
    memset(zeros, 0, sizeof(zeros));
    for (int i = 0; i < 8; i++) write(fd, zeros, 512);

    /* Fake audio frame */
    uint8_t frame[8] = { 0xFF, 0xF8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    write(fd, frame, sizeof(frame));

    close(fd);
}

/* ── Run tests on a format ───────────────────────────────────────────── */

static void test_format(const char *path, const char *label)
{
    printf("Testing %s ...\n", label);

    oggtag_context_t *ctx;
    int rc;
    char buf[256];

    /* Open read-write */
    ctx = oggtag_create(NULL);
    CHECK(ctx != NULL, "create context");
    rc = oggtag_open_rw(ctx, path);
    CHECK_RC(rc, "open_rw");

    /* Initially no user tags */
    rc = oggtag_read_tag_string(ctx, "TITLE", buf, sizeof(buf));
    CHECK(rc == OGGTAG_ERR_TAG_NOT_FOUND, "no TITLE initially");

    /* Write some tags */
    rc = oggtag_set_tag_string(ctx, "TITLE", "Test Title");
    CHECK_RC(rc, "set TITLE");
    rc = oggtag_set_tag_string(ctx, "ARTIST", "Test Artist");
    CHECK_RC(rc, "set ARTIST");
    rc = oggtag_set_tag_string(ctx, "ALBUM", "Test Album");
    CHECK_RC(rc, "set ALBUM");
    rc = oggtag_set_tag_string(ctx, "TRACK_NUMBER", "7");
    CHECK_RC(rc, "set TRACK_NUMBER");

    /* Read them back */
    rc = oggtag_read_tag_string(ctx, "TITLE", buf, sizeof(buf));
    CHECK_RC(rc, "read TITLE");
    CHECK(strcmp(buf, "Test Title") == 0, "TITLE value");

    rc = oggtag_read_tag_string(ctx, "ARTIST", buf, sizeof(buf));
    CHECK_RC(rc, "read ARTIST");
    CHECK(strcmp(buf, "Test Artist") == 0, "ARTIST value");

    rc = oggtag_read_tag_string(ctx, "ALBUM", buf, sizeof(buf));
    CHECK_RC(rc, "read ALBUM");
    CHECK(strcmp(buf, "Test Album") == 0, "ALBUM value");

    rc = oggtag_read_tag_string(ctx, "TRACK_NUMBER", buf, sizeof(buf));
    CHECK_RC(rc, "read TRACK_NUMBER");
    CHECK(strcmp(buf, "7") == 0, "TRACK_NUMBER value");

    /* Update a tag (in-place for FLAC, rewrite for Ogg) */
    rc = oggtag_set_tag_string(ctx, "TITLE", "Updated Title");
    CHECK_RC(rc, "update TITLE");
    rc = oggtag_read_tag_string(ctx, "TITLE", buf, sizeof(buf));
    CHECK_RC(rc, "read updated TITLE");
    CHECK(strcmp(buf, "Updated Title") == 0, "updated TITLE value");

    /* Remove a tag */
    rc = oggtag_remove_tag(ctx, "TRACK_NUMBER");
    CHECK_RC(rc, "remove TRACK_NUMBER");
    rc = oggtag_read_tag_string(ctx, "TRACK_NUMBER", buf, sizeof(buf));
    CHECK(rc == OGGTAG_ERR_TAG_NOT_FOUND, "TRACK_NUMBER removed");

    oggtag_destroy(ctx);

    /* Reopen read-only and verify persistence */
    ctx = oggtag_create(NULL);
    rc = oggtag_open(ctx, path);
    CHECK_RC(rc, "reopen read-only");

    rc = oggtag_read_tag_string(ctx, "TITLE", buf, sizeof(buf));
    CHECK_RC(rc, "persistent TITLE");
    CHECK(strcmp(buf, "Updated Title") == 0, "persistent TITLE value");

    rc = oggtag_read_tag_string(ctx, "ARTIST", buf, sizeof(buf));
    CHECK_RC(rc, "persistent ARTIST");
    CHECK(strcmp(buf, "Test Artist") == 0, "persistent ARTIST value");

    rc = oggtag_read_tag_string(ctx, "TRACK_NUMBER", buf, sizeof(buf));
    CHECK(rc == OGGTAG_ERR_TAG_NOT_FOUND, "TRACK_NUMBER still removed");

    /* Test collection API */
    oggtag_collection_t *coll = NULL;
    rc = oggtag_read_tags(ctx, &coll);
    CHECK_RC(rc, "read_tags collection");
    CHECK(coll != NULL, "collection not NULL");
    if (coll && coll->tags) {
        int count = 0;
        for (oggtag_simple_tag_t *s = coll->tags->simple_tags; s; s = s->next)
            count++;
        CHECK(count == 3, "collection has 3 tags (TITLE, ARTIST, ALBUM)");
    }

    oggtag_destroy(ctx);

    /* Test collection write API */
    ctx = oggtag_create(NULL);
    rc = oggtag_open_rw(ctx, path);
    CHECK_RC(rc, "reopen rw for collection write");

    coll = oggtag_collection_create(ctx);
    CHECK(coll != NULL, "create collection");
    oggtag_tag_t *tag = oggtag_collection_add_tag(ctx, coll, OGGTAG_TARGET_ALBUM);
    CHECK(tag != NULL, "add tag to collection");
    oggtag_tag_add_simple(ctx, tag, "TITLE", "Collection Title");
    oggtag_tag_add_simple(ctx, tag, "ARTIST", "Collection Artist");
    oggtag_tag_add_simple(ctx, tag, "DATE_RELEASED", "2025");

    rc = oggtag_write_tags(ctx, coll);
    CHECK_RC(rc, "write collection");
    oggtag_collection_free(ctx, coll);

    /* Verify */
    rc = oggtag_read_tag_string(ctx, "TITLE", buf, sizeof(buf));
    CHECK_RC(rc, "read collection TITLE");
    CHECK(strcmp(buf, "Collection Title") == 0, "collection TITLE value");

    rc = oggtag_read_tag_string(ctx, "DATE_RELEASED", buf, sizeof(buf));
    CHECK_RC(rc, "read DATE_RELEASED");
    CHECK(strcmp(buf, "2025") == 0, "DATE_RELEASED value");

    oggtag_destroy(ctx);
    printf("\n");
}

/* ── Main ────────────────────────────────────────────────────────────── */

int main(void)
{
    printf("liboggtag test suite (v%s)\n\n", oggtag_version());

    const char *vorbis_path = "/tmp/test_oggtag_vorbis.ogg";
    const char *opus_path   = "/tmp/test_oggtag_opus.opus";
    const char *flac_path   = "/tmp/test_oggtag.flac";

    create_ogg_vorbis(vorbis_path);
    test_format(vorbis_path, "Ogg Vorbis (.ogg)");

    create_ogg_opus(opus_path);
    test_format(opus_path, "Ogg Opus (.opus)");

    create_flac(flac_path);
    test_format(flac_path, "FLAC (.flac)");

    /* Cleanup */
    remove(vorbis_path);
    remove(opus_path);
    remove(flac_path);

    printf("Results: %d passed, %d failed\n", g_pass, g_fail);
    return g_fail > 0 ? 1 : 0;
}
