# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build Commands

Build library and tests:
```sh
cd build && xcrun clang -c -std=c11 -Wall -Wextra -Wpedantic -Wno-unused-parameter -I ../include -I ../src \
    ../src/oggtag.c ../src/vorbis_comment/vorbis_comment.c \
    ../src/ogg/ogg_stream.c ../src/ogg/ogg_crc.c \
    ../src/flac/flac_meta.c ../src/io/file_io.c \
    ../src/util/buffer.c ../src/util/string_util.c \
    && xcrun ar rcs liboggtag.a oggtag.o vorbis_comment.o ogg_stream.o ogg_crc.o flac_meta.o file_io.o buffer.o string_util.o
```

Build and run tests:
```sh
cd build && xcrun clang -std=c11 -Wall -Wextra -Wpedantic -Wno-unused-parameter -I ../include -I ../src \
    -o test_oggtag ../tests/test_oggtag.c -L. -loggtag && ./test_oggtag
```

Build XCFramework (macOS + iOS):
```sh
./build_xcframework.sh
```

## Testing

Run `build/test_oggtag` — generates minimal test files for each format, exercises read/write/update/remove/persist/collection APIs (111 checks across 3 formats).

## Architecture

Pure C11 static library for reading/writing Vorbis Comment tags. No external dependencies (POSIX only). API is compatible with [libmkvtag](https://github.com/morganp/libmkvtag) and [libmp3tag](https://github.com/morganp/libmp3tag).

### Layers

- **Public API** (`include/oggtag/`) — `oggtag.h` (functions), `oggtag_types.h` (structs/enums), `oggtag_error.h` (error codes), `module.modulemap` (Swift/Clang)
- **Main implementation** (`src/oggtag.c`) — Context lifecycle, format probing, tag read/write orchestration, collection building
- **Vorbis Comment** (`src/vorbis_comment/`) — Parse/serialize Vorbis Comment key=value data; tag name mapping between canonical names (e.g. `TRACK_NUMBER`) and VC field names (e.g. `TRACKNUMBER`)
- **Ogg** (`src/ogg/`) — Page reader/writer, CRC-32 (polynomial 0x04C11DB7), packet extraction, page rebuilding
- **FLAC** (`src/flac/`) — Metadata block scanning, in-place VC writing with padding block reuse, full rewrite fallback
- **I/O** (`src/io/`) — Buffered POSIX file I/O (8KB read buffer, lazy seek)
- **Util** (`src/util/`) — Dynamic byte buffer (`dyn_buffer_t`), string helpers

### Supported Formats

| Format | Detection | Comment Packet |
|--------|-----------|---------------|
| Ogg Vorbis | `OggS` + `0x01 "vorbis"` | Packet 1: `0x03 "vorbis"` + VC data + framing byte |
| Ogg Opus | `OggS` + `"OpusHead"` | Packet 1: `"OpusTags"` + VC data |
| Ogg FLAC | `OggS` + `0x7F "FLAC"` | Packet 1: metadata block header + VC data |
| Native FLAC | `"fLaC"` marker | Metadata block type 4 (VORBIS_COMMENT) |

### Write Strategies

- **FLAC in-place**: If new VC data fits within existing VC block + adjacent PADDING block, writes in-place and adjusts padding. Falls back to full rewrite with 4KB padding.
- **Ogg rewrite**: Extracts header packets, replaces comment packet, writes to temp file with new header pages + copied audio pages (renumbered page_seq, recalculated CRC), atomic rename.

### Tag Name Mapping

The library normalizes between canonical names (shared with libmkvtag/libmp3tag) and Vorbis Comment field names. Key mappings: `TRACK_NUMBER`↔`TRACKNUMBER`, `DATE_RELEASED`↔`DATE`, `ALBUM_ARTIST`↔`ALBUMARTIST`, `DISC_NUMBER`↔`DISCNUMBER`. Unmapped names pass through unchanged.
