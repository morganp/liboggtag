# liboggtag

A lightweight, zero-dependency C11 library for reading and writing Vorbis Comment tags in Ogg Vorbis, Ogg Opus, and FLAC files.

Designed as a companion to [libmkvtag](https://github.com/morganp/libmkvtag) and [libmp3tag](https://github.com/morganp/libmp3tag), sharing the same API pattern for easy integration.

## Features

- Read and write Vorbis Comments in `.ogg`, `.oga`, `.opus`, and `.flac` files
- In-place editing for FLAC (reuses padding blocks)
- Simple one-call API for common operations
- Full collection API for advanced tag manipulation
- Canonical tag names compatible with libmkvtag and libmp3tag
- Pure C11, no external dependencies (POSIX only)
- Builds as static library, XCFramework for Apple platforms, or CMake target

## Supported Formats

| Extension | Container | Codec | Tag Format |
|-----------|-----------|-------|------------|
| `.ogg` | Ogg | Vorbis | Vorbis Comment |
| `.oga` | Ogg | Vorbis/FLAC | Vorbis Comment |
| `.opus` | Ogg | Opus | Vorbis Comment (OpusTags) |
| `.flac` | Native FLAC | FLAC | Vorbis Comment |

## Quick Start

### Read a tag

```c
oggtag_context_t *ctx = oggtag_create(NULL);
oggtag_open(ctx, "song.ogg");

char title[256];
if (oggtag_read_tag_string(ctx, "TITLE", title, sizeof(title)) == OGGTAG_OK)
    printf("Title: %s\n", title);

oggtag_destroy(ctx);
```

### Write a tag

```c
oggtag_context_t *ctx = oggtag_create(NULL);
oggtag_open_rw(ctx, "song.flac");
oggtag_set_tag_string(ctx, "TITLE", "New Title");
oggtag_destroy(ctx);
```

### Collection API

```c
oggtag_context_t *ctx = oggtag_create(NULL);
oggtag_open_rw(ctx, "song.opus");

oggtag_collection_t *coll = oggtag_collection_create(ctx);
oggtag_tag_t *tag = oggtag_collection_add_tag(ctx, coll, OGGTAG_TARGET_ALBUM);
oggtag_tag_add_simple(ctx, tag, "TITLE", "My Album");
oggtag_tag_add_simple(ctx, tag, "ARTIST", "Artist Name");
oggtag_tag_add_simple(ctx, tag, "DATE_RELEASED", "2025");

oggtag_write_tags(ctx, coll);
oggtag_collection_free(ctx, coll);
oggtag_destroy(ctx);
```

## Tag Name Mapping

Tag names are normalized to canonical names shared across libmkvtag, libmp3tag, and liboggtag:

| Canonical Name | Vorbis Comment Field |
|----------------|---------------------|
| `TITLE` | `TITLE` |
| `ARTIST` | `ARTIST` |
| `ALBUM` | `ALBUM` |
| `ALBUM_ARTIST` | `ALBUMARTIST` |
| `TRACK_NUMBER` | `TRACKNUMBER` |
| `DISC_NUMBER` | `DISCNUMBER` |
| `DATE_RELEASED` | `DATE` |
| `GENRE` | `GENRE` |
| `COMPOSER` | `COMPOSER` |
| `COMMENT` | `COMMENT` |
| `SORT_TITLE` | `TITLESORT` |
| `SORT_ARTIST` | `ARTISTSORT` |
| `SORT_ALBUM` | `ALBUMSORT` |
| `ORIGINAL_DATE` | `ORIGINALDATE` |
| `PUBLISHER` | `ORGANIZATION` |

Fields without a mapping are passed through unchanged.

## Building

### CMake

```sh
cmake -B build -DOGGTAG_BUILD_TESTS=ON
cmake --build build
ctest --test-dir build
```

### Manual

```sh
xcrun clang -c -std=c11 -Wall -Wextra -Wpedantic -I include -I src \
    src/oggtag.c src/vorbis_comment/vorbis_comment.c \
    src/ogg/ogg_stream.c src/ogg/ogg_crc.c \
    src/flac/flac_meta.c src/io/file_io.c \
    src/util/buffer.c src/util/string_util.c
xcrun ar rcs liboggtag.a *.o
```

### XCFramework (macOS + iOS)

```sh
chmod +x build_xcframework.sh
./build_xcframework.sh
# Output: build/xcframework/oggtag.xcframework
```

## License

MIT
