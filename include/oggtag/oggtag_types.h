/*
 * oggtag_types.h – Public type definitions for liboggtag
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef OGGTAG_TYPES_H
#define OGGTAG_TYPES_H

#include <stddef.h>
#include <stdint.h>

/* Opaque context */
typedef struct oggtag_context oggtag_context_t;

/* Target type values – compatible with libmkvtag / libmp3tag */
typedef enum {
    OGGTAG_TARGET_COLLECTION = 70,
    OGGTAG_TARGET_EDITION    = 60,
    OGGTAG_TARGET_ALBUM      = 50,
    OGGTAG_TARGET_PART       = 40,
    OGGTAG_TARGET_TRACK      = 30,
    OGGTAG_TARGET_SUBTRACK   = 20,
    OGGTAG_TARGET_SHOT       = 10
} oggtag_target_type_t;

/* A single name/value tag (singly-linked list) */
typedef struct oggtag_simple_tag {
    char    *name;
    char    *value;
    uint8_t *binary;
    size_t   binary_size;
    char    *language;
    int      is_default;
    struct oggtag_simple_tag *nested;
    struct oggtag_simple_tag *next;
} oggtag_simple_tag_t;

/* A tag with target scope and list of simple tags */
typedef struct oggtag_tag {
    oggtag_target_type_t  target_type;
    char                 *target_type_str;
    uint64_t *track_uids;      size_t track_uid_count;
    uint64_t *edition_uids;    size_t edition_uid_count;
    uint64_t *chapter_uids;    size_t chapter_uid_count;
    uint64_t *attachment_uids; size_t attachment_uid_count;
    oggtag_simple_tag_t  *simple_tags;
    struct oggtag_tag    *next;
} oggtag_tag_t;

/* Collection of tags */
typedef struct {
    oggtag_tag_t *tags;
    size_t        count;
} oggtag_collection_t;

/* Custom allocator */
typedef struct {
    void *(*alloc)(size_t size, void *user_data);
    void *(*realloc)(void *ptr, size_t size, void *user_data);
    void  (*free)(void *ptr, void *user_data);
    void  *user_data;
} oggtag_allocator_t;

#endif /* OGGTAG_TYPES_H */
