#!/bin/bash
set -euo pipefail

PROJECT_NAME="oggtag"
HEADER_DIR="include/oggtag"
SOURCES=(
    src/oggtag.c
    src/vorbis_comment/vorbis_comment.c
    src/ogg/ogg_stream.c
    src/ogg/ogg_crc.c
    src/flac/flac_meta.c
    src/io/file_io.c
)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TAG_COMMON_DIR="${SCRIPT_DIR}/deps/libtag_common"
CFLAGS="-std=c11 -Wall -Wextra -Wpedantic -Wno-unused-parameter -O2 -I include -I src -I ${TAG_COMMON_DIR}/include"

OUTPUT_DIR="build/xcframework"
rm -rf "$OUTPUT_DIR"
mkdir -p "$OUTPUT_DIR"

build_platform() {
    local platform=$1 arch=$2 sdk=$3 min_ver_flag=$4
    local build_dir="$OUTPUT_DIR/$platform-$arch"
    mkdir -p "$build_dir"

    local objects=()
    for src in "${SOURCES[@]}"; do
        local obj="$build_dir/$(basename "$src" .c).o"
        xcrun --sdk "$sdk" clang -c $CFLAGS \
            -arch "$arch" $min_ver_flag \
            -o "$obj" "$src"
        objects+=("$obj")
    done

    xcrun --sdk "$sdk" ar rcs "$build_dir/lib${PROJECT_NAME}.a" "${objects[@]}"
}

echo "Building macOS (arm64 + x86_64)..."
build_platform macos arm64 macosx "-mmacosx-version-min=10.15"
build_platform macos x86_64 macosx "-mmacosx-version-min=10.15"
mkdir -p "$OUTPUT_DIR/macos-universal"
lipo -create \
    "$OUTPUT_DIR/macos-arm64/lib${PROJECT_NAME}.a" \
    "$OUTPUT_DIR/macos-x86_64/lib${PROJECT_NAME}.a" \
    -output "$OUTPUT_DIR/macos-universal/lib${PROJECT_NAME}.a"

echo "Building iOS (arm64)..."
build_platform ios arm64 iphoneos "-mios-version-min=13.0"

echo "Building iOS Simulator (arm64 + x86_64)..."
build_platform iossim arm64 iphonesimulator "-mios-simulator-version-min=13.0"
build_platform iossim x86_64 iphonesimulator "-mios-simulator-version-min=13.0"
mkdir -p "$OUTPUT_DIR/iossim-universal"
lipo -create \
    "$OUTPUT_DIR/iossim-arm64/lib${PROJECT_NAME}.a" \
    "$OUTPUT_DIR/iossim-x86_64/lib${PROJECT_NAME}.a" \
    -output "$OUTPUT_DIR/iossim-universal/lib${PROJECT_NAME}.a"

# Create .framework bundles
create_framework() {
    local platform=$1 lib_dir=$2
    local fw_dir="$OUTPUT_DIR/$platform/${PROJECT_NAME}.framework"
    mkdir -p "$fw_dir/Headers"
    cp "$lib_dir/lib${PROJECT_NAME}.a" "$fw_dir/${PROJECT_NAME}"
    cp "$HEADER_DIR"/*.h "$fw_dir/Headers/"
    cp "$HEADER_DIR/module.modulemap" "$fw_dir/"
    # Umbrella header
    cat > "$fw_dir/Headers/${PROJECT_NAME}.h" <<'UMBRELLA'
#include "oggtag.h"
#include "oggtag_types.h"
#include "oggtag_error.h"
UMBRELLA
}

create_framework macos-fw "$OUTPUT_DIR/macos-universal"
create_framework ios-fw "$OUTPUT_DIR/ios-arm64"
create_framework iossim-fw "$OUTPUT_DIR/iossim-universal"

echo "Creating XCFramework..."
xcodebuild -create-xcframework \
    -framework "$OUTPUT_DIR/macos-fw/${PROJECT_NAME}.framework" \
    -framework "$OUTPUT_DIR/ios-fw/${PROJECT_NAME}.framework" \
    -framework "$OUTPUT_DIR/iossim-fw/${PROJECT_NAME}.framework" \
    -output "$OUTPUT_DIR/${PROJECT_NAME}.xcframework"

echo "Done: $OUTPUT_DIR/${PROJECT_NAME}.xcframework"
