/*
 * oggtag.h – Public API for liboggtag
 *
 * Read and write Vorbis Comments in Ogg Vorbis, Ogg Opus, and FLAC files.
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef OGGTAG_H
#define OGGTAG_H

#include "oggtag_types.h"
#include "oggtag_error.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ── Version ─────────────────────────────────────────────────────────── */

const char *oggtag_version(void);

/* ── Error description ───────────────────────────────────────────────── */

const char *oggtag_strerror(int error);

/* ── Context lifecycle ───────────────────────────────────────────────── */

oggtag_context_t *oggtag_create(const oggtag_allocator_t *allocator);
void              oggtag_destroy(oggtag_context_t *ctx);

int  oggtag_open(oggtag_context_t *ctx, const char *path);
int  oggtag_open_rw(oggtag_context_t *ctx, const char *path);
void oggtag_close(oggtag_context_t *ctx);
int  oggtag_is_open(const oggtag_context_t *ctx);

/* ── Tag reading ─────────────────────────────────────────────────────── */

int oggtag_read_tags(oggtag_context_t *ctx, oggtag_collection_t **tags);

int oggtag_read_tag_string(oggtag_context_t *ctx, const char *name,
                           char *value, size_t size);

/* ── Tag writing ─────────────────────────────────────────────────────── */

int oggtag_write_tags(oggtag_context_t *ctx, const oggtag_collection_t *tags);

int oggtag_set_tag_string(oggtag_context_t *ctx,
                          const char *name, const char *value);

int oggtag_remove_tag(oggtag_context_t *ctx, const char *name);

/* ── Collection building ─────────────────────────────────────────────── */

oggtag_collection_t *oggtag_collection_create(oggtag_context_t *ctx);

void oggtag_collection_free(oggtag_context_t *ctx,
                            oggtag_collection_t *coll);

oggtag_tag_t *oggtag_collection_add_tag(oggtag_context_t *ctx,
                                        oggtag_collection_t *coll,
                                        oggtag_target_type_t type);

oggtag_simple_tag_t *oggtag_tag_add_simple(oggtag_context_t *ctx,
                                           oggtag_tag_t *tag,
                                           const char *name,
                                           const char *value);

oggtag_simple_tag_t *oggtag_simple_tag_add_nested(oggtag_context_t *ctx,
                                                  oggtag_simple_tag_t *parent,
                                                  const char *name,
                                                  const char *value);

int oggtag_simple_tag_set_language(oggtag_context_t *ctx,
                                  oggtag_simple_tag_t *simple_tag,
                                  const char *language);

int oggtag_tag_add_track_uid(oggtag_context_t *ctx,
                             oggtag_tag_t *tag, uint64_t uid);

#ifdef __cplusplus
}
#endif

#endif /* OGGTAG_H */
